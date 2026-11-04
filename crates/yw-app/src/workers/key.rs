//! The key worker thread `yw-key` (spec/04 §1.2): sole owner of the `Vault` and of meta writes.
//! Argon2-bound calls never run on the UI thread. `Lock` is processed before any other queued job
//! and cancels the rest with `KeyJobError::Locked`.

use std::path::{Path, PathBuf};

use yw_core::bip32::path::AccountIndex;
use yw_core::bip32::preview_evm_address;
use yw_core::btc::address::script_pubkey;
use yw_core::btc::{BtcAccountId, BtcMeta, BtcNetwork};
use yw_core::error::{KeyError, VaultError};
use yw_core::keyimport::{ImportChain, ImportKey, ImportPreview, ImportSpec};
use yw_core::password::{Bip39Passphrase, VaultPassword};
use yw_core::secret::{SecretString, Zeroizing};
use yw_core::slip10::SolKeySource;
use yw_core::sol::SolAddress;
use yw_core::vault::{
    EvmKeySource, FileKind, ImportedKeys, RecordId, Vault, VaultStatus, VaultStorage,
};

use crate::errors::ErrorCode;
use crate::events::{
    ImportedAccount, KeyJob, KeyOutcome, KeyQueue, KeyResult, LockSignal, MetaLoaded, RevealWhat,
};
use crate::logging::{self, Field};
use crate::meta::{self, Account, EvmAccountPref, Meta, RawAccount, SolRawAccount, Tab};
use crate::store::{FileStorage, LockedSlotBox};
use crate::workers::journal::{JournalState, SolSignTimes};

struct PendingImport {
    phrase: Zeroizing<Vec<u8>>,
    passphrase: Option<Zeroizing<Vec<u8>>>,
}

/// The key of "개인키로 시작하기" between the preview and the commit.
struct PendingKeyStart {
    spec: ImportSpec,
    key: Zeroizing<Vec<u8>>,
}

/// Worker state.
pub struct KeyWorker {
    dir: PathBuf,
    vault: Option<Vault>,
    pending_password: Option<Zeroizing<Vec<u8>>>,
    pending: Option<PendingImport>,
    pending_key: Option<PendingKeyStart>,
    journal: JournalState,
    /// The inserted `YubiKey`s (PC/SC; the emulator in tests, spec/10 §12.1).
    cards: Box<dyn crate::yubikey::CardSource>,
}

impl core::fmt::Debug for KeyWorker {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyWorker")
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn ascii(bytes: &[u8]) -> Result<&str, KeyError> {
    core::str::from_utf8(bytes).map_err(|_| KeyError::MnemonicFormat)
}

fn new_slot() -> Result<Box<LockedSlotBox>, VaultError> {
    LockedSlotBox::new()
        .map(Box::new)
        .map_err(|_| VaultError::OutOfMemory)
}

fn password(bytes: &[u8]) -> Result<VaultPassword, VaultError> {
    VaultPassword::new(bytes).map_err(VaultError::Key)
}

fn passphrase(bytes: &[u8]) -> Result<Bip39Passphrase, KeyError> {
    Bip39Passphrase::new(core::str::from_utf8(bytes).map_err(|_| KeyError::PassphraseInvalidChar)?)
}

/// The format error of a chain's key text (non-UTF-8 input).
const fn format_error(spec: ImportSpec) -> KeyError {
    match spec {
        ImportSpec::Evm => KeyError::InvalidPrivateKey,
        ImportSpec::Sol => KeyError::SolKeyFormat,
        ImportSpec::Btc(_) => KeyError::WifFormat,
    }
}

/// Parses key text for `spec` (the text buffer stays with the caller and is wiped by it).
fn parse_key(spec: ImportSpec, bytes: &[u8]) -> Result<ImportKey, KeyError> {
    let text = core::str::from_utf8(bytes).map_err(|_| format_error(spec))?;
    ImportKey::parse(spec, text)
}

/// The `YubiKey` EVM account index of an approval (`EvmKeySource::Hardware`).
fn card_index(approved: &yw_core::approval::Approved) -> Option<AccountIndex> {
    match approved.signer() {
        yw_core::approval::Signer::Evm(EvmKeySource::Hardware(index)) => Some(index),
        _ => None,
    }
}

/// Reconciles the imported Bitcoin accounts of meta `btc_accounts` with the vault's tag-4
/// records (spec/08 §3.5, spec/02 §5.3): a record without its single-key account (an older
/// vault, or a meta write that failed after the vault write) gets one on its network; an
/// account whose record is gone, or whose key, type or network differs from the record, is
/// dropped (and re-added from the record). Returns whether anything changed.
fn reconcile_btc_accounts(document: &mut Meta, keys: &ImportedKeys) -> bool {
    let mut changed = false;
    let mut expected = Vec::with_capacity(keys.btc.len());
    for (id, info) in &keys.btc {
        match info.account_key(*id.as_bytes()) {
            Ok(key) => expected.push((info.network, key)),
            // A parsed record always gives an account (uncompressed keys are P2PKH only).
            Err(_) => logging::warn("key", "btc.imported_account_invalid", &[]),
        }
    }
    let stale: Vec<(BtcNetwork, BtcAccountId)> = document
        .btc_accounts
        .accounts
        .iter()
        .filter(|meta| meta.account().is_imported())
        .filter(|meta| {
            !expected
                .iter()
                .any(|(network, key)| *network == meta.network() && key == meta.account())
        })
        .map(|meta| (meta.network(), meta.id()))
        .collect();
    for (network, id) in stale {
        let has_primary = document
            .btc
            .as_deref()
            .is_some_and(|primary| primary.network() == network);
        changed |= document
            .btc_accounts
            .remove(network, id, has_primary)
            .is_some();
    }
    for (network, key) in expected {
        if document.btc_accounts.get(network, key.id()).is_none() {
            match document
                .btc_accounts
                .upsert(BtcMeta::with_key(network, key))
            {
                Ok(()) => changed = true,
                Err(_) => logging::warn("key", "btc.accounts_full", &[]),
            }
        }
    }
    changed
}

/// Reconciles the meta imported-key lists with the vault (labels kept by record id, address
/// caches recomputed; Bitcoin keys as accounts of `btc_accounts`); returns whether anything
/// changed.
fn reconcile_imported(document: &mut Meta, keys: &ImportedKeys) -> bool {
    let mut changed = false;
    let mut evm: Vec<RawAccount> = Vec::with_capacity(keys.evm.len());
    for (id, address) in &keys.evm {
        let text = address.to_lower_hex();
        let existing = document
            .evm_raw_accounts
            .iter()
            .find(|raw| raw.record_id == *id.as_bytes());
        if existing.is_none_or(|raw| raw.address != text) {
            changed = true;
        }
        evm.push(RawAccount {
            record_id: *id.as_bytes(),
            label: existing.map_or_else(
                || {
                    let labels = document.evm_raw_accounts.iter().chain(&evm);
                    meta::next_imported_label(
                        meta::EVM_IMPORTED_PREFIX,
                        labels.map(|raw| raw.label.as_str()),
                    )
                },
                |raw| raw.label.clone(),
            ),
            address: text,
        });
    }
    let mut sol: Vec<SolRawAccount> = Vec::with_capacity(keys.sol.len());
    for (id, public) in &keys.sol {
        let text = SolAddress::from_bytes(*public).to_base58();
        let existing = document
            .sol_raw_accounts
            .iter()
            .find(|raw| raw.record_id == *id.as_bytes());
        if existing.is_none_or(|raw| raw.address != text) {
            changed = true;
        }
        sol.push(SolRawAccount {
            record_id: *id.as_bytes(),
            label: existing.map_or_else(
                || {
                    let labels = document.sol_raw_accounts.iter().chain(&sol);
                    meta::next_imported_label(
                        meta::SOL_IMPORTED_PREFIX,
                        labels.map(|raw| raw.label.as_str()),
                    )
                },
                |raw| raw.label.clone(),
            ),
            address: text,
        });
    }
    changed |= evm.len() != document.evm_raw_accounts.len()
        || sol.len() != document.sol_raw_accounts.len();
    document.evm_raw_accounts = evm;
    document.sol_raw_accounts = sol;
    changed |= reconcile_btc_accounts(document, keys);
    if let Some(selected) = document.sol_raw_selected
        && !document
            .sol_raw_accounts
            .iter()
            .any(|raw| raw.record_id == selected)
    {
        document.sol_raw_selected = None;
        changed = true;
    }
    changed
}

impl KeyWorker {
    /// A worker for the data folder `dir`.
    #[must_use]
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            vault: None,
            pending_password: None,
            pending: None,
            pending_key: None,
            journal: JournalState::default(),
            cards: Box::new(crate::yubikey::PcscSource),
        }
    }

    /// Replaces the card source (tests use the APDU emulator).
    #[must_use]
    pub fn with_card_source(mut self, cards: Box<dyn crate::yubikey::CardSource>) -> Self {
        self.cards = cards;
        self
    }

    /// The slot maps of the enrolled `YubiKey`s.
    fn hardware_records(
        vault: &Vault,
    ) -> Result<Vec<yw_core::yubikey::record::HwKeyRecord>, VaultError> {
        Ok(vault
            .hardware_keys()?
            .into_iter()
            .map(|key| key.record)
            .collect())
    }

    /// `EnrolYubiKey` (spec/10 §7): parse the mnemonic, derive, enrol the inserted card, then
    /// add the record (public data only) to the vault.
    fn enrol_yubikey(
        &mut self,
        phrase: &[u8],
        passphrase: Option<&[u8]>,
        slots: &[yw_core::yubikey::plan::PlannedSlot],
        admin_pin: &[u8],
        management_key: &[u8],
    ) -> Result<(RecordId, yw_core::yubikey::enrol::Enrolled), crate::events::YubiKeyJobError> {
        use crate::events::YubiKeyJobError;
        let mnemonic =
            yw_core::bip39::Mnemonic::parse(ascii(phrase).map_err(YubiKeyJobError::Key)?)
                .map_err(YubiKeyJobError::Key)?;
        let passphrase = match passphrase {
            Some(bytes) => self::passphrase(bytes).map_err(YubiKeyJobError::Key)?,
            None => Bip39Passphrase::empty(),
        };
        let seed = mnemonic
            .to_seed(&passphrase)
            .map_err(YubiKeyJobError::Key)?;
        let vault = self
            .vault
            .as_mut()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let records = Self::hardware_records(vault).map_err(YubiKeyJobError::Vault)?;
        let secrets = crate::yubikey::EnrolSecrets {
            admin_pin,
            management_key,
        };
        let enrolled = crate::yubikey::enrol_first_card(
            self.cards.as_mut(),
            seed.expose(),
            slots,
            &records,
            &secrets,
        )
        .map_err(YubiKeyJobError::Card)?;
        let id = vault
            .add_hardware_key(enrolled.record.clone(), now_unix())
            .map_err(YubiKeyJobError::Vault)?;
        logging::info(
            "key",
            "yubikey.enrolled",
            &[(
                "slots",
                Field::Num(u64::try_from(enrolled.record.slots.len()).unwrap_or(0)),
            )],
        );
        Ok((id, enrolled))
    }

    /// `SignEvmCard` (spec/10 §9.2): the journal's signing step with the card signer.
    fn sign_evm_card(
        &mut self,
        ticket: crate::events::SignTicket,
        approved: Box<yw_core::approval::Approved>,
        info: &crate::events::SignInfo,
        pin: &[u8],
        alt: bool,
    ) -> Vec<KeyOutcome> {
        use crate::events::SignFailure;
        let Some(vault) = self.vault.as_mut() else {
            return vec![KeyOutcome::SignedEvm(crate::events::EvmSigned {
                ticket,
                result: Err(SignFailure::JournalWrite(VaultError::InvalidState)),
            })];
        };
        let records = match Self::hardware_records(vault) {
            Ok(records) => records,
            Err(error) => {
                return vec![KeyOutcome::SignedEvm(crate::events::EvmSigned {
                    ticket,
                    result: Err(SignFailure::JournalWrite(error)),
                })];
            }
        };
        let cards = self.cards.as_mut();
        self.journal
            .sign_with(vault, ticket, approved, info, alt, &mut |_, approved| {
                let index = card_index(&approved).ok_or(SignFailure::Sign(
                    yw_core::evm::sign::SignError::KindMismatch,
                ))?;
                let mut card_failure = None;
                let mut card = |digest: [u8; 32]| {
                    crate::yubikey::sign_evm_digest(cards, &records, index, pin, digest).map_err(
                        |error| {
                            card_failure = Some(error);
                            yw_core::yubikey::CardError::Internal
                        },
                    )
                };
                let result =
                    yw_core::evm::sign::sign_transaction_card(*Box::new(approved), &mut card);
                result.map_err(|error| match (card_failure, error) {
                    (Some(failure), _) => SignFailure::Card(failure),
                    (None, yw_core::evm::sign::CardSignError::Sign(error)) => {
                        SignFailure::Sign(error)
                    }
                    (None, yw_core::evm::sign::CardSignError::Card(error)) => {
                        SignFailure::Card(crate::yubikey::CardJobError::Card(error))
                    }
                })
            })
    }

    /// `SignMessageCard` (spec/10 §9.2).
    fn sign_message_card(
        &mut self,
        approved: yw_core::approval::Approved,
        typed: bool,
        pin: &[u8],
    ) -> Result<[u8; 65], crate::events::MessageSignFailure> {
        use crate::events::MessageSignFailure;
        let vault = self.vault.as_ref().ok_or(MessageSignFailure::Sign(
            yw_core::evm::sign::SignError::Vault(VaultError::InvalidState),
        ))?;
        let records = Self::hardware_records(vault).map_err(|error| {
            MessageSignFailure::Sign(yw_core::evm::sign::SignError::Vault(error))
        })?;
        let index = card_index(&approved).ok_or(MessageSignFailure::Sign(
            yw_core::evm::sign::SignError::KindMismatch,
        ))?;
        let cards = self.cards.as_mut();
        let mut card_failure = None;
        let mut card = |digest: [u8; 32]| {
            crate::yubikey::sign_evm_digest(cards, &records, index, pin, digest).map_err(|error| {
                card_failure = Some(error);
                yw_core::yubikey::CardError::Internal
            })
        };
        let result = if typed {
            yw_core::evm::sign::sign_typed_data_card(approved, &mut card)
        } else {
            yw_core::evm::sign::sign_personal_card(approved, &mut card)
        };
        result.map_err(|error| match (card_failure, error) {
            (Some(failure), _) => MessageSignFailure::Card(failure),
            (None, yw_core::evm::sign::CardSignError::Sign(error)) => {
                MessageSignFailure::Sign(error)
            }
            (None, yw_core::evm::sign::CardSignError::Card(error)) => {
                MessageSignFailure::Card(crate::yubikey::CardJobError::Card(error))
            }
        })
    }

    fn vault(&mut self) -> Result<&mut Vault, VaultError> {
        self.vault.as_mut().ok_or(VaultError::InvalidState)
    }

    fn is_alt(&self) -> bool {
        matches!(
            self.vault.as_ref().map(Vault::status),
            Some(VaultStatus::Unlocked {
                alt_passphrase: true
            })
        )
    }

    /// Locks the vault and wipes held import buffers.
    pub fn lock(&mut self) {
        self.pending = None;
        self.pending_key = None;
        self.pending_password = None;
        self.journal.clear();
        if let Some(vault) = self.vault.as_mut() {
            vault.lock();
        }
    }

    fn load(&mut self) -> KeyOutcome {
        let storage = match FileStorage::open(&self.dir) {
            Ok(storage) => storage,
            Err(error) => {
                return KeyOutcome::Status(Err(VaultError::Storage(error)));
            }
        };
        let leftover =
            storage.any_present(FileKind::Meta) || storage.any_present(FileKind::Journal);
        match Vault::load(Box::new(storage)) {
            Ok(vault) => {
                let status = vault.status();
                self.vault = Some(vault);
                KeyOutcome::Loaded {
                    status,
                    leftover: leftover && status == VaultStatus::NoVault,
                }
            }
            Err(error) => KeyOutcome::Status(Err(error)),
        }
    }

    fn write_default_meta(vault: &mut Vault, address: &yw_core::evm::address::Address) {
        let mut document = Meta::default();
        if let Some(first) = document.evm_accounts.first_mut() {
            first.address = address.to_lower_hex();
        }
        if let Err(error) = vault.save_sidecar(FileKind::Meta, &document.to_json()) {
            logging::warn(
                "key",
                "meta.write_failed",
                &[("code", Field::Code(crate::errors::vault_code(error)))],
            );
        }
    }

    fn create(
        &mut self,
        password_bytes: &[u8],
    ) -> Result<(SecretString, yw_core::evm::address::Address), VaultError> {
        let password = password(password_bytes)?;
        let slot = new_slot()?;
        let vault = self.vault()?;
        let phrase = vault.create_wallet(&password, slot, now_unix())?;
        let address = vault.evm_address(EvmKeySource::Derived(AccountIndex::ZERO))?;
        Self::write_default_meta(vault, &address);
        Ok((phrase, address))
    }

    fn preview(
        &mut self,
        pending: PendingImport,
    ) -> Result<yw_core::evm::address::Address, KeyError> {
        let result = (|| {
            let phrase = ascii(&pending.phrase)?;
            let passphrase = pending
                .passphrase
                .as_deref()
                .map(|bytes| passphrase(bytes))
                .transpose()?;
            preview_evm_address(phrase, passphrase.as_ref(), AccountIndex::ZERO)
        })();
        if result.is_ok() {
            self.pending = Some(pending);
        }
        result
    }

    fn commit_import(&mut self) -> Result<(), VaultError> {
        let pending = self.pending.take().ok_or(VaultError::InvalidState)?;
        let held = self
            .pending_password
            .take()
            .ok_or(VaultError::InvalidState)?;
        let password = password(&held)?;
        let phrase = ascii(&pending.phrase).map_err(VaultError::Key)?;
        let passphrase = pending
            .passphrase
            .as_deref()
            .map(|bytes| passphrase(bytes))
            .transpose()
            .map_err(VaultError::Key)?;
        let slot = new_slot()?;
        let vault = self.vault()?;
        vault.import_mnemonic(&password, phrase, passphrase, slot, now_unix())?;
        let address = vault.evm_address(EvmKeySource::Derived(AccountIndex::ZERO))?;
        Self::write_default_meta(vault, &address);
        Ok(())
    }

    fn preview_key_start(&mut self, pending: PendingKeyStart) -> Result<ImportPreview, KeyError> {
        let preview = parse_key(pending.spec, &pending.key)?.preview()?;
        self.pending_key = Some(pending);
        Ok(preview)
    }

    /// The default meta of a new key-only wallet: no derived account, the imported key in its
    /// list (a Bitcoin key as the single-key account of its network in `btc_accounts`, selected),
    /// its chain tab selected.
    fn write_key_only_meta(vault: &mut Vault, chain: ImportChain) -> Result<(), VaultError> {
        let keys = vault.imported_keys()?;
        let mut document = Meta::key_only();
        reconcile_imported(&mut document, &keys);
        if let Some(raw) = document.evm_raw_accounts.first() {
            document.prefs.evm_account = EvmAccountPref::Record(raw.record_id);
        }
        document.sol_raw_selected = document.sol_raw_accounts.first().map(|raw| raw.record_id);
        document.btc_accounts.selected = document.btc_accounts.accounts.first().map(BtcMeta::id);
        document.prefs.tab = match chain {
            ImportChain::Evm => Tab::Evm,
            ImportChain::Sol => Tab::Sol,
            ImportChain::Btc => Tab::Btc,
        };
        if let Err(error) = vault.save_sidecar(FileKind::Meta, &document.to_json()) {
            logging::warn(
                "key",
                "meta.write_failed",
                &[("code", Field::Code(crate::errors::vault_code(error)))],
            );
        }
        Ok(())
    }

    fn commit_key_start(&mut self) -> Result<(), VaultError> {
        let pending = self.pending_key.take().ok_or(VaultError::InvalidState)?;
        let held = self
            .pending_password
            .take()
            .ok_or(VaultError::InvalidState)?;
        let password = password(&held)?;
        let key = parse_key(pending.spec, &pending.key)?;
        let slot = new_slot()?;
        let vault = self.vault()?;
        vault.create_with_key(&password, key, slot, now_unix())?;
        Self::write_key_only_meta(vault, pending.spec.chain())
    }

    fn import_chain_key(
        &mut self,
        spec: ImportSpec,
        bytes: &[u8],
    ) -> Result<ImportedAccount, VaultError> {
        let key = parse_key(spec, bytes)?;
        let preview = key.preview()?;
        if let ImportPreview::Btc(info) = &preview {
            // Its address must not already belong to an account (an HD address in the scanned
            // range, another imported key): E-VLT-011 (spec/08 §3.5).
            let vault = self.vault.as_ref().ok_or(VaultError::InvalidState)?;
            if self
                .journal
                .btc_address_taken(vault, info.network, &script_pubkey(&info.kind))
            {
                return Err(VaultError::DuplicateKey);
            }
        }
        let id = self.vault()?.import_key(key, now_unix())?;
        Ok(match preview {
            ImportPreview::Evm(address) => ImportedAccount::Evm(id, address),
            ImportPreview::Sol(address) => ImportedAccount::Sol(id, address),
            ImportPreview::Btc(info) => ImportedAccount::Btc(id, info),
        })
    }

    /// `삭제` of an imported key (spec/04 §2.18): refused while an imported Bitcoin key's account
    /// has an in-flight record (`ImportedKeyBusy`); otherwise the password check and the vault
    /// removal, then — for a Bitcoin key — its account leaves meta `btc_accounts`.
    fn remove_imported(&mut self, password_bytes: &[u8], id: RecordId) -> Vec<KeyOutcome> {
        let alt = self.is_alt();
        if let Some(vault) = self.vault.as_ref()
            && self
                .journal
                .btc_imported_busy(vault, *id.as_bytes(), now_unix())
        {
            return vec![KeyOutcome::ImportedKeyBusy(id)];
        }
        let result = (|| {
            let password = password(password_bytes).map_err(|_| VaultError::UnlockFailed)?;
            let chain = self.vault()?.remove_imported_key(&password, id)?;
            Ok((id, chain))
        })();
        let btc_removed = matches!(result, Ok((_, ImportChain::Btc)));
        let mut out = vec![KeyOutcome::ImportedKeyRemoved(result)];
        if btc_removed && let Some(vault) = self.vault.as_mut() {
            out.extend(self.journal.btc_remove_imported(vault, *id.as_bytes(), alt));
        }
        out
    }

    /// `.prev` recovery; when it moved `vault.ywv` aside, the quarantined file name is reported
    /// first so the UI can name it (spec/04 §2.15, docs/recovery-guide.ko.md).
    fn recover_from_prev(&mut self, bytes: &[u8]) -> Vec<KeyOutcome> {
        let now = now_unix();
        let result = (|| {
            let password = password(bytes).map_err(|_| VaultError::UnlockFailed)?;
            let slot = new_slot()?;
            self.vault()?.recover_from_prev(&password, slot, now)
        })();
        let mut out = Vec::with_capacity(2);
        if result.is_ok()
            && let Some(at) = self.vault.as_ref().and_then(Vault::quarantined_at)
            && at == now
        {
            out.push(KeyOutcome::Quarantined(format!("vault.ywv.corrupt-{at}")));
        }
        out.push(KeyOutcome::Status(result));
        out
    }

    fn reveal(
        &mut self,
        password_bytes: &[u8],
        what: RevealWhat,
    ) -> Result<
        (
            RevealWhat,
            SecretString,
            Option<yw_core::evm::address::Address>,
        ),
        VaultError,
    > {
        let password = password(password_bytes).map_err(|_| VaultError::UnlockFailed)?;
        let vault = self.vault()?;
        match what {
            RevealWhat::Mnemonic => {
                let phrase = vault.reveal_mnemonic(&password)?;
                let address = vault.evm_address(EvmKeySource::Derived(AccountIndex::ZERO))?;
                Ok((what, phrase, Some(address)))
            }
            RevealWhat::PrivateKey(source) => {
                let hex = vault.reveal_evm_private_key(&password, source)?;
                Ok((what, hex, None))
            }
            RevealWhat::ImportedKey(id) => {
                let (_, text) = vault.reveal_imported_key(&password, id)?;
                Ok((what, text, None))
            }
            RevealWhat::BtcEvmShared { evm_index, network } => {
                let index = AccountIndex::new(evm_index).map_err(VaultError::Key)?;
                let wif = vault.reveal_evm_shared_wif(&password, index, network)?;
                Ok((what, wif, None))
            }
        }
    }

    fn load_meta(&mut self) -> Result<MetaLoaded, VaultError> {
        let alt = self.is_alt();
        let vault = self.vault()?;
        let (mut document, prefs_reset) = if alt {
            (Meta::default(), false)
        } else {
            match vault.open_sidecar(FileKind::Meta)? {
                None => (Meta::default(), false),
                Some((_, plaintext)) => {
                    let parsed = meta::parse(plaintext.expose())
                        .map_err(|_| VaultError::SidecarCorrupt(FileKind::Meta))?;
                    (parsed.meta, parsed.prefs_reset)
                }
            }
        };
        let keys = vault.imported_keys()?;
        let mut mismatch = false;
        if !keys.has_mnemonic {
            // A key-only wallet has no derived accounts (spec/02 §5.3).
            mismatch |= !document.evm_accounts.is_empty() || !document.sol_accounts.is_empty();
            document.evm_accounts.clear();
            document.sol_accounts.clear();
        } else if document.evm_accounts.is_empty() {
            // A mnemonic wallet always lists account 0.
            mismatch = true;
            document.evm_accounts = Meta::default().evm_accounts;
        }
        let indices: Vec<AccountIndex> = document
            .evm_accounts
            .iter()
            .filter_map(|account| AccountIndex::new(account.index).ok())
            .collect();
        let addresses = vault.evm_addresses(&indices)?;
        for (account, address) in document.evm_accounts.iter_mut().zip(addresses) {
            let text = address.to_lower_hex();
            if account.address != text {
                mismatch = true;
                account.address = text;
            }
        }
        mismatch |= reconcile_imported(&mut document, &keys);
        let sol_sources: Vec<SolKeySource> = document
            .sol_accounts
            .iter()
            .filter_map(|account| AccountIndex::new(account.index).ok())
            .map(SolKeySource::Standard)
            .collect();
        let sol_keys = vault.sol_public_keys(&sol_sources)?;
        for (account, key) in document.sol_accounts.iter_mut().zip(sol_keys) {
            let text = SolAddress::from_bytes(key).to_base58();
            if account.address != text {
                mismatch = true;
                account.address = text;
            }
        }
        if mismatch {
            logging::warn("key", "MetaAddressMismatch", &[]);
            if !alt {
                vault.save_sidecar(FileKind::Meta, &document.to_json())?;
            }
        }
        self.journal.set_btc_meta(
            document.btc.as_deref().cloned(),
            document.btc_accounts.clone(),
        );
        Ok(MetaLoaded {
            meta: Box::new(document),
            mismatch,
            prefs_reset,
            has_mnemonic: keys.has_mnemonic,
        })
    }

    fn resolve_sidecar(&mut self, kind: FileKind, use_prev: bool) -> Result<(), ErrorCode> {
        let mut storage = FileStorage::open(&self.dir).map_err(|_| ErrorCode::Vlt006)?;
        let now = now_unix();
        if use_prev {
            storage
                .restore_prev(kind, now)
                .map_err(|_| ErrorCode::Vlt006)
        } else {
            storage.quarantine(kind, now).map_err(|_| ErrorCode::Vlt006)
        }
    }

    /// Runs one non-control job; journal jobs can report several outcomes (signing result,
    /// journal view, moved activity).
    #[expect(clippy::too_many_lines, reason = "one arm per multi-outcome job")]
    pub fn handle(&mut self, job: KeyJob) -> Vec<KeyOutcome> {
        let alt = self.is_alt();
        match job {
            KeyJob::LoadJournal => match self.vault.as_mut() {
                Some(vault) => match self.journal.load(vault) {
                    Ok(view) => {
                        let mut out = self.journal.btc_startup(vault, now_unix(), alt);
                        if !out
                            .iter()
                            .any(|outcome| matches!(outcome, KeyOutcome::Journal(Ok(_))))
                        {
                            out.push(KeyOutcome::Journal(Ok(view)));
                        }
                        out
                    }
                    Err(error) => vec![KeyOutcome::Journal(Err(error))],
                },
                None => vec![KeyOutcome::Journal(Err(VaultError::InvalidState))],
            },
            KeyJob::BtcMeta { op } => match self.vault.as_mut() {
                Some(vault) => self.journal.btc_meta_op(vault, op, alt),
                None => vec![KeyOutcome::BtcMeta(Err(
                    crate::workers::journal::btc::BtcKeyError::Vault(VaultError::InvalidState),
                ))],
            },
            KeyJob::SignBtc {
                approved,
                plan,
                tip_height,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => {
                    self.journal
                        .sign_btc(vault, approved, &plan, tip_height, now_unix_ms, alt)
                }
                None => vec![KeyOutcome::SignedBtc(Err(
                    crate::workers::journal::btc::BtcSignFailure::JournalWrite(
                        VaultError::InvalidState,
                    ),
                ))],
            },
            KeyJob::BtcJournal { op, now_unix_ms } => match self.vault.as_mut() {
                Some(vault) => self.journal.btc_journal(vault, op, now_unix_ms, alt),
                None => vec![KeyOutcome::BtcJournal(Err(
                    crate::workers::journal::btc::BtcKeyError::Vault(VaultError::InvalidState),
                ))],
            },
            KeyJob::SignEvmCard {
                ticket,
                approved,
                info,
                pin,
            } => self.sign_evm_card(ticket, approved, &info, &pin, alt),
            KeyJob::SignEvm {
                ticket,
                approved,
                info,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.sign(vault, ticket, approved, &info, alt),
                None => vec![KeyOutcome::SignedEvm(crate::events::EvmSigned {
                    ticket,
                    result: Err(crate::events::SignFailure::JournalWrite(
                        VaultError::InvalidState,
                    )),
                })],
            },
            KeyJob::JournalApply {
                transitions,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.apply(vault, &transitions, now_unix_ms, alt),
                None => vec![KeyOutcome::Journal(Err(VaultError::InvalidState))],
            },
            KeyJob::SignSol {
                approved,
                consumed_at_ms,
                blockhash,
                last_valid_block_height,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.sign_sol(
                    vault,
                    approved,
                    SolSignTimes {
                        consumed_at_ms,
                        blockhash,
                        last_valid_block_height,
                        now_unix_ms,
                    },
                    alt,
                ),
                None => vec![KeyOutcome::SignedSol(Err(
                    crate::events::SolSignFailure::JournalWrite(VaultError::InvalidState),
                ))],
            },
            KeyJob::SolApply {
                transition,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.apply_sol(vault, &transition, now_unix_ms, alt),
                None => vec![KeyOutcome::Journal(Err(VaultError::InvalidState))],
            },
            KeyJob::RemoveImportedKey { password, id } => self.remove_imported(&password, id),
            KeyJob::RecoverFromPrev { password: bytes } => self.recover_from_prev(&bytes),
            other => vec![self.handle_single(other)],
        }
    }

    #[expect(clippy::too_many_lines, reason = "one arm per job kind")]
    fn handle_single(&mut self, job: KeyJob) -> KeyOutcome {
        match job {
            KeyJob::Load => self.load(),
            KeyJob::CreateWallet { password } => KeyOutcome::Created(self.create(&password)),
            KeyJob::PreviewImport {
                password,
                phrase,
                passphrase,
            } => {
                if let Some(password) = password {
                    self.pending_password = Some(password);
                }
                KeyOutcome::Preview(self.preview(PendingImport { phrase, passphrase }))
            }
            KeyJob::DiscardImport { keep_password } => {
                self.pending = None;
                if !keep_password {
                    self.pending_password = None;
                }
                KeyOutcome::Imported(Err(VaultError::InvalidState))
            }
            KeyJob::CommitImport => KeyOutcome::Imported(self.commit_import()),
            KeyJob::Unlock { password: bytes } => KeyOutcome::Status((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                let slot = new_slot()?;
                self.vault()?.unlock(&password, slot)
            })()),
            KeyJob::EnterPassphrase { passphrase: bytes } => KeyOutcome::Status((|| {
                let passphrase = passphrase(&bytes).map_err(VaultError::Key)?;
                self.vault()?.enter_passphrase(passphrase)
            })()),
            KeyJob::RetryPassphrase => {
                KeyOutcome::Status(self.vault().and_then(Vault::retry_passphrase))
            }
            KeyJob::AcceptMismatch => {
                KeyOutcome::Status(self.vault().and_then(Vault::accept_mismatched_passphrase))
            }
            KeyJob::BackupChallenge => {
                KeyOutcome::Challenge(self.vault().and_then(Vault::backup_challenge))
            }
            KeyJob::ConfirmBackup { id, words } => KeyOutcome::BackupConfirmed((|| {
                let texts: Vec<&str> = words
                    .iter()
                    .map(|word| core::str::from_utf8(word).unwrap_or(""))
                    .collect();
                let answers = [
                    texts.first().copied().unwrap_or(""),
                    texts.get(1).copied().unwrap_or(""),
                    texts.get(2).copied().unwrap_or(""),
                    texts.get(3).copied().unwrap_or(""),
                ];
                self.vault()?.confirm_backup(id, answers)
            })()),
            KeyJob::Reveal { password, what } => KeyOutcome::Revealed(self.reveal(&password, what)),
            KeyJob::ChangePassword { old, new } => KeyOutcome::PasswordChanged((|| {
                let old = password(&old).map_err(|_| VaultError::UnlockFailed)?;
                let new = password(&new)?;
                self.vault()?.change_password(&old, &new)
            })()),
            KeyJob::ImportPrivateKey { hex } => KeyOutcome::RawKeyImported((|| {
                let text = core::str::from_utf8(&hex)
                    .map_err(|_| VaultError::Key(KeyError::InvalidPrivateKey))?;
                let vault = self.vault()?;
                let id = vault.import_evm_private_key(text, now_unix())?;
                let address = vault.evm_address(EvmKeySource::Raw(id))?;
                Ok((id, address))
            })()),
            KeyJob::RemoveRawKey {
                password: bytes,
                id,
            } => KeyOutcome::RawKeyRemoved((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                self.vault()?.remove_evm_raw_key(&password, id)?;
                Ok(id)
            })()),
            KeyJob::PreviewKeyStart {
                password,
                spec,
                key,
            } => {
                if let Some(password) = password {
                    self.pending_password = Some(password);
                }
                KeyOutcome::KeyStartPreview(self.preview_key_start(PendingKeyStart { spec, key }))
            }
            KeyJob::DiscardKeyStart { keep_password } => {
                self.pending_key = None;
                if !keep_password {
                    self.pending_password = None;
                }
                KeyOutcome::KeyStartCommitted(Err(VaultError::InvalidState))
            }
            KeyJob::CommitKeyStart => KeyOutcome::KeyStartCommitted(self.commit_key_start()),
            KeyJob::ImportKey { spec, key } => {
                KeyOutcome::KeyImported(self.import_chain_key(spec, &key))
            }
            KeyJob::LoadMeta => KeyOutcome::Meta(self.load_meta()),
            KeyJob::SaveMeta { meta } => KeyOutcome::MetaSaved((|| {
                if self.is_alt() {
                    return Ok(());
                }
                let mut document = *meta;
                let vault = self.vault.as_mut().ok_or(VaultError::InvalidState)?;
                self.journal.merge_overlay(vault, &mut document);
                vault
                    .save_sidecar(FileKind::Meta, &document.to_json())
                    .map(|_| ())
            })()),
            KeyJob::ResolveSidecar { kind, use_prev } => {
                KeyOutcome::SidecarResolved(self.resolve_sidecar(kind, use_prev))
            }
            KeyJob::DeriveAddresses { indices } => KeyOutcome::Addresses((|| {
                let parsed: Vec<AccountIndex> = indices
                    .iter()
                    .map(|index| AccountIndex::new(*index))
                    .collect::<Result<_, _>>()
                    .map_err(VaultError::Key)?;
                let addresses = self.vault()?.evm_addresses(&parsed)?;
                Ok(indices.into_iter().zip(addresses).collect())
            })()),
            KeyJob::SignMessage {
                ticket,
                approved,
                typed,
            } => KeyOutcome::SignedMessage(crate::events::MessageSigned {
                ticket,
                result: match self.vault.as_ref() {
                    Some(vault) if typed => yw_core::evm::sign::sign_typed_data(vault, *approved),
                    Some(vault) => yw_core::evm::sign::sign_personal(vault, *approved),
                    None => Err(yw_core::evm::sign::SignError::Vault(
                        VaultError::InvalidState,
                    )),
                }
                .map_err(crate::events::MessageSignFailure::Sign),
            }),
            KeyJob::SignMessageCard {
                ticket,
                approved,
                typed,
                pin,
            } => KeyOutcome::SignedMessage(crate::events::MessageSigned {
                ticket,
                result: self.sign_message_card(*approved, typed, &pin),
            }),
            KeyJob::EnrolYubiKey {
                phrase,
                passphrase,
                slots,
                admin_pin,
                management_key,
            } => KeyOutcome::YubiKeyEnrolled(self.enrol_yubikey(
                &phrase,
                passphrase.as_deref().map(Vec::as_slice),
                &slots,
                &admin_pin,
                &management_key,
            )),
            KeyJob::HardwareKeys => {
                KeyOutcome::HardwareKeys(self.vault().and_then(|vault| vault.hardware_keys()))
            }
            KeyJob::SignChainMessage { ticket, approved } => {
                KeyOutcome::SignedChainMessage(crate::events::ChainMessageSigned {
                    ticket,
                    result: match self.vault.as_ref() {
                        Some(vault)
                            if approved.kind() == yw_core::approval::ApprovalKind::BtcMessage =>
                        {
                            yw_core::btc::msgsign::sign_message(vault, *approved)
                                .map(crate::events::ChainSignature::Btc)
                                .map_err(|_| false)
                        }
                        Some(vault) => yw_core::sol::msgsign::sign_message(vault, *approved)
                            .map(crate::events::ChainSignature::Sol)
                            .map_err(|_| false),
                        None => Err(false),
                    },
                })
            }
            KeyJob::SolKeys { purpose, sources } => KeyOutcome::SolKeys(
                purpose,
                self.vault().and_then(|vault| {
                    let keys = vault.sol_public_keys(&sources)?;
                    Ok(sources
                        .into_iter()
                        .zip(keys)
                        .map(|(source, key)| (source, SolAddress::from_bytes(key)))
                        .collect())
                }),
            ),
            KeyJob::LoadJournal
            | KeyJob::SignEvm { .. }
            | KeyJob::SignEvmCard { .. }
            | KeyJob::JournalApply { .. }
            | KeyJob::SignSol { .. }
            | KeyJob::SolApply { .. }
            | KeyJob::BtcMeta { .. }
            | KeyJob::SignBtc { .. }
            | KeyJob::BtcJournal { .. }
            | KeyJob::RemoveImportedKey { .. }
            | KeyJob::RecoverFromPrev { .. } => KeyOutcome::Journal(Err(VaultError::InvalidState)),
            KeyJob::Lock | KeyJob::Shutdown => {
                self.lock();
                KeyOutcome::LockDone
            }
        }
    }
}

/// A default account entry for `계정 추가`.
#[must_use]
pub fn new_account(index: u32, address: &yw_core::evm::address::Address) -> Account {
    Account {
        index,
        label: format!("계정 {}", index.saturating_add(1)),
        address: address.to_lower_hex(),
        hidden: false,
    }
}

/// Runs one popped job; `false` after `Shutdown` (the loop ends).
pub fn step(
    worker: &mut KeyWorker,
    queue: &KeyQueue,
    (epoch, job): (u64, KeyJob),
    sink: &dyn Fn(KeyResult),
    lock_signal: &LockSignal,
) -> bool {
    match job {
        KeyJob::Shutdown => {
            worker.lock();
            lock_signal.signal();
            false
        }
        KeyJob::Lock => {
            worker.lock();
            for (cancelled_epoch, cancelled) in queue.cancel_pending() {
                sink(KeyResult {
                    epoch: cancelled_epoch,
                    outcome: cancelled.cancelled_outcome(),
                });
            }
            lock_signal.signal();
            sink(KeyResult {
                epoch,
                outcome: KeyOutcome::LockDone,
            });
            true
        }
        other => {
            for outcome in worker.handle(other) {
                sink(KeyResult { epoch, outcome });
            }
            true
        }
    }
}

/// The worker loop: runs until `Shutdown`.
pub fn run(
    mut worker: KeyWorker,
    queue: &KeyQueue,
    sink: &dyn Fn(KeyResult),
    lock_signal: &LockSignal,
) {
    while let Some(entry) = queue.pop() {
        if !step(&mut worker, queue, entry, sink, lock_signal) {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{KeyWorker, run};
    use crate::events::{
        KeyJob, KeyJobError, KeyOutcome, KeyQueue, KeyResult, LockSignal, accept_result,
    };

    #[test]
    fn lk2_lock_jumps_the_queue_and_cancels_pending_jobs() {
        let dir = std::env::temp_dir().join(format!(
            "yw-app-lk2-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        let queue = KeyQueue::default();
        queue.push(1, KeyJob::Load);
        queue.push(1, KeyJob::BackupChallenge);
        queue.push(2, KeyJob::Lock);
        queue.push(2, KeyJob::Shutdown);
        let results: Mutex<Vec<KeyResult>> = Mutex::new(Vec::new());
        let signal = LockSignal::default();
        let before = signal.count();
        run(
            KeyWorker::new(&dir),
            &queue,
            &|result| results.lock().unwrap().push(result),
            &signal,
        );
        let results = results.into_inner().unwrap();
        let names: Vec<String> = results
            .iter()
            .map(|result| match &result.outcome {
                KeyOutcome::Cancelled(name, KeyJobError::Locked) => {
                    format!("cancelled:{name}:{}", result.epoch)
                }
                KeyOutcome::LockDone => format!("lockdone:{}", result.epoch),
                _ => "other".to_owned(),
            })
            .collect();
        // `Load` is a control job: it survives the lock (spec/04 §5.3 reloads after locking).
        assert_eq!(
            names,
            ["cancelled:BackupChallenge:1", "lockdone:2", "other"]
        );
        assert!(signal.count() >= before + 2);
        // A result from before the lock (epoch 1) is dropped once the UI is at epoch 2.
        let stale = KeyResult {
            epoch: 1,
            outcome: KeyOutcome::Preview(Err(yw_core::error::KeyError::MnemonicChecksum)),
        };
        assert!(!accept_result(&stale, 2));
        assert!(accept_result(&results[1], 7));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// spec/10 §13 minimal EVM end to end on the key worker, with the APDU emulator as the card:
    /// import a wallet, enrol a `YubiKey` (SIG = EVM 0, AUT = EVM 1) from the mnemonic, then sign
    /// an approved Sepolia transfer and a `personal_sign` of the `YubiKey` account on the card —
    /// post-sign verification and the `Signed` journal commit included. Card failures (wrong PIN,
    /// no card, another card) come back as `SignFailure::Card` with nothing journaled.
    #[test]
    #[allow(
        clippy::too_many_lines,
        clippy::indexing_slicing,
        reason = "one end-to-end scenario"
    )]
    fn yubikey_evm_end_to_end_with_the_emulator() {
        use std::sync::{Arc, Mutex};

        use yw_core::approval::{ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore};
        use yw_core::bip32::path::AccountIndex;
        use yw_core::evm::amount::U256;
        use yw_core::evm::decode::{DecodedTx, decode_call};
        use yw_core::evm::simulate::SimResult;
        use yw_core::evm::tx::{Eip1559Tx, decode_signed};
        use yw_core::journal::evm::Role;
        use yw_core::secret::Zeroizing;
        use yw_core::vault::EvmKeySource;
        use yw_core::yubikey::mock::MockCard;
        use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PlannedSlot};

        use crate::events::{EvmSigned, MessageSignFailure, SignFailure, SignInfo, SignTicket};
        use crate::yubikey::{CardJobError, MockSource};

        // The public `abandon`×11 `about` test mnemonic, built at run time (the privacy scan
        // allows word sequences only in `tests.rs` files).
        let about = format!("{} about", ["abandon"; 11].join(" "));
        let dir = std::env::temp_dir().join(format!(
            "yw-app-yubikey-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        let cards = Arc::new(Mutex::new(vec![MockCard::new(7_700_001)]));
        let mut worker = KeyWorker::new(&dir).with_card_source(Box::new(MockSource {
            cards: Arc::clone(&cards),
        }));
        let bytes = |text: &str| Zeroizing::new(text.as_bytes().to_vec());
        worker.handle(KeyJob::Load);
        worker.handle(KeyJob::PreviewImport {
            password: Some(bytes("yubikey test password")),
            phrase: bytes(&about),
            passphrase: None,
        });
        assert!(matches!(
            worker.handle(KeyJob::CommitImport).first(),
            Some(KeyOutcome::Imported(Ok(())))
        ));

        // Enrol: SIG = EVM 0, AUT = EVM 1.
        let evm = |index| KeyRole::Evm {
            index: AccountIndex::new(index).unwrap(),
            btc: None,
        };
        let slots = vec![
            PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Sig), evm(0)),
            PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Aut), evm(1)),
        ];
        let enrolled = match worker
            .handle(KeyJob::EnrolYubiKey {
                phrase: bytes(&about),
                passphrase: None,
                slots,
                admin_pin: bytes("12345678"),
                management_key: Zeroizing::new(Vec::new()),
            })
            .pop()
        {
            Some(KeyOutcome::YubiKeyEnrolled(Ok((_, enrolled)))) => enrolled,
            other => unreachable!("enrolment failed: {other:?}"),
        };
        assert_eq!(enrolled.record.serial, 7_700_001);
        assert!(enrolled.defaults.openpgp_admin);
        let Some(KeyOutcome::HardwareKeys(Ok(keys))) = worker.handle(KeyJob::HardwareKeys).pop()
        else {
            unreachable!("hardware keys");
        };
        assert_eq!(keys.len(), 1);
        let source = EvmKeySource::Hardware(AccountIndex::new(1).unwrap());
        let account = worker.vault.as_ref().unwrap().evm_address(source).unwrap();
        // EVM account 1 of the `abandon` mnemonic.
        assert_eq!(
            account.to_checksum(),
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"
        );

        // An approved transfer of the YubiKey account.
        let chain = yw_core::evm::chain::sepolia();
        let tx = Eip1559Tx {
            chain_id: 11_155_111,
            nonce: 0,
            max_priority_fee_per_gas: U256::from_u64(1_000_000_000),
            max_fee_per_gas: U256::from_u64(2_000_000_000),
            gas_limit: 21_000,
            to: yw_core::evm::address::parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
                .unwrap(),
            value: U256::from_u64(1_000),
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let mut store = ApprovalStore::new();
        let mut approve = |kind, draft: yw_core::approval::ApprovalDraft| {
            assert_eq!(draft.kind, kind);
            let request = store.issue(draft, 0, 1_790_000_000_000).unwrap();
            store.consume(request.id, request.digest, 1).unwrap()
        };
        let tx_approval = |approve: &mut dyn FnMut(
            ApprovalKind,
            yw_core::approval::ApprovalDraft,
        ) -> yw_core::approval::Approved| {
            let decoded = DecodedTx {
                call: decode_call(&chain, &tx.to, &tx.data),
                tx: tx.clone(),
            };
            approve(
                ApprovalKind::EvmTransaction,
                yw_core::approval::build_evm_tx_request(
                    ApprovalId::random().unwrap(),
                    ApprovalOrigin::App,
                    source,
                    account,
                    ApprovalKind::EvmTransaction,
                    &chain,
                    &decoded,
                    &SimResult::skipped(),
                    &yw_core::approval::ChainFacts::default(),
                    Vec::new(),
                    1_790_000_000_000,
                )
                .unwrap(),
            )
        };
        let info = SignInfo {
            origin: "yw-app".to_owned(),
            label: "YubiKey test".to_owned(),
            role: Role::Original,
            now_unix_ms: 1_790_000_000_000,
        };
        let sign_tx = |worker: &mut KeyWorker, approved, pin: &str| {
            worker
                .handle(KeyJob::SignEvmCard {
                    ticket: SignTicket(9),
                    approved: Box::new(approved),
                    info: info.clone(),
                    pin: bytes(pin),
                })
                .into_iter()
                .find_map(|outcome| match outcome {
                    KeyOutcome::SignedEvm(EvmSigned { ticket, result }) => {
                        assert_eq!(ticket, SignTicket(9));
                        Some(result)
                    }
                    _ => None,
                })
                .unwrap()
        };

        // Wrong PIN: the card error comes back, nothing is journaled.
        cards.lock().unwrap()[0].high_s = true;
        cards.lock().unwrap()[0].log.clear();
        assert_eq!(
            sign_tx(&mut worker, tx_approval(&mut approve), "000000"),
            Err(SignFailure::Card(CardJobError::Card(
                yw_core::yubikey::CardError::WrongPin { retries: 2 }
            )))
        );
        let summary = sign_tx(&mut worker, tx_approval(&mut approve), "123456").unwrap();
        assert_eq!(summary.account, account);
        let decoded = decode_signed(&summary.raw).unwrap();
        assert_eq!(decoded.tx, tx);
        let mut compact = [0_u8; 64];
        compact[..32].copy_from_slice(&decoded.r);
        compact[32..].copy_from_slice(&decoded.s);
        assert_eq!(
            yw_core::evm::sign::recover_address(tx.signing_hash(), decoded.y_parity, &compact),
            Some(account)
        );
        assert!(compact[32] < 0x80, "low-s");
        assert!(
            !cards.lock().unwrap()[0].saw_write(),
            "signing sends no write instruction"
        );

        // personal_sign on the card.
        let message = |approve: &mut dyn FnMut(
            ApprovalKind,
            yw_core::approval::ApprovalDraft,
        ) -> yw_core::approval::Approved| {
            approve(
                ApprovalKind::EvmPersonalSign,
                yw_core::approval::build_personal_request(
                    ApprovalId::random().unwrap(),
                    ApprovalOrigin::Site(
                        yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
                    ),
                    source,
                    account,
                    ApprovalKind::EvmPersonalSign,
                    &chain,
                    &yw_core::evm::eip191::decode_personal_message(b"YubiKey".to_vec()),
                    1_790_000_000_000,
                )
                .unwrap(),
            )
        };
        let signed = worker.handle(KeyJob::SignMessageCard {
            ticket: SignTicket(10),
            approved: Box::new(message(&mut approve)),
            typed: false,
            pin: bytes("123456"),
        });
        let Some(KeyOutcome::SignedMessage(signed)) = signed.into_iter().next() else {
            unreachable!("message outcome");
        };
        let signature = signed.result.unwrap();
        assert_eq!(
            yw_core::evm::sign::recover_message_signer(
                yw_core::evm::eip191::personal_digest(b"YubiKey"),
                &signature
            ),
            Some(account)
        );
        // The vault path refuses a YubiKey approval (no PC key).
        let refused = worker.handle(KeyJob::SignMessage {
            ticket: SignTicket(11),
            approved: Box::new(message(&mut approve)),
            typed: false,
        });
        assert!(matches!(
            refused.first(),
            Some(KeyOutcome::SignedMessage(crate::events::MessageSigned {
                result: Err(MessageSignFailure::Sign(_)),
                ..
            }))
        ));
        // Another card (not enrolled) and no card at all.
        cards.lock().unwrap()[0] = MockCard::new(7_700_002);
        assert_eq!(
            sign_tx(&mut worker, tx_approval(&mut approve), "123456"),
            Err(SignFailure::Card(CardJobError::Card(
                yw_core::yubikey::CardError::WrongCard
            )))
        );
        cards.lock().unwrap().clear();
        assert_eq!(
            sign_tx(&mut worker, tx_approval(&mut approve), "123456"),
            Err(SignFailure::Card(CardJobError::Card(
                yw_core::yubikey::CardError::Transport(yw_core::yubikey::TransportFault::NoCard)
            )))
        );
        drop(worker);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
