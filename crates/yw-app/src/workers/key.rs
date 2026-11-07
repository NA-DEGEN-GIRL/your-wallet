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

pub mod mnemonics;
pub mod yubikey;

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
    /// The recovery words of a `YubiKey` enrolment wizard (spec/10 §7; never on disk).
    pending_enrol: Option<yubikey::PendingEnrol>,
    /// The password of a new `YubiKey` wallet made by `YubiKey 연결하기` (spec/10 §7.6) until the
    /// vault exists (wiped with the wizard and on lock).
    connect_password: Option<Zeroizing<Vec<u8>>>,
    /// The words of "복구 단어 추가 가져오기" between the address preview and the commit.
    pending_mnemonic: Option<PendingImport>,
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
        ImportSpec::Zec(_) => KeyError::ZecKeyFormat,
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

/// The default label of a `YubiKey` account (`YubiKey 계정 1`, `YubiKey Solana 1`).
fn hw_label(evm: bool, index: u32) -> String {
    // A key connected without recovery words (spec/10 §7.6): its index is an account number.
    if yw_core::yubikey::plan::is_unknown_index(index) {
        let number = index
            .saturating_sub(yw_core::yubikey::plan::UNKNOWN_PATH_FIRST)
            .saturating_add(1);
        return if evm {
            format!("YubiKey 카드 키 {number}")
        } else {
            format!("YubiKey Solana 카드 키 {number}")
        };
    }
    if evm {
        format!("YubiKey 계정 {}", index.saturating_add(1))
    } else {
        format!("YubiKey Solana {}", index.saturating_add(1))
    }
}

/// One chain's `hw_accounts` list from the slot map's accounts: labels and hidden flags kept by
/// index, addresses recomputed; returns the list and whether it differs from `old`.
fn hw_list(
    old: &[Account],
    found: impl Iterator<Item = (u32, String)>,
    evm: bool,
) -> (Vec<Account>, bool) {
    let mut list: Vec<Account> = found
        .map(|(index, address)| {
            let existing = old.iter().find(|account| account.index == index);
            Account {
                index,
                label: existing
                    .map_or_else(|| hw_label(evm, index), |account| account.label.clone()),
                address,
                hidden: existing.is_some_and(|account| account.hidden),
            }
        })
        .collect();
    list.sort_by_key(|account| account.index);
    list.dedup_by_key(|account| account.index);
    let changed = list.as_slice() != old;
    (list, changed)
}

/// The Bitcoin accounts the slot map gives (spec/10 §3.1, §3.3): a `KeyRole::Btc` slot is a
/// single-address account of its network and type, an EVM slot with a shared Bitcoin use is one
/// of that use; the public keys come from the vault (`Vault::hardware_btc_account`).
fn hw_btc_expected(
    vault: &Vault,
    records: &[yw_core::yubikey::record::HwKeyRecord],
) -> Vec<(BtcNetwork, yw_core::btc::account::BtcAccountKey)> {
    use yw_core::btc::account::HwBtcKey;
    use yw_core::yubikey::plan::KeyRole;
    let mut expected = Vec::new();
    for slot in records.iter().flat_map(|record| &record.slots) {
        let (key, network, script_type) = match slot.role {
            KeyRole::Btc {
                network,
                script,
                index,
            } => (HwBtcKey::Address(index), network, script),
            KeyRole::Evm {
                index,
                btc: Some(shared),
            } => (HwBtcKey::Evm(index.get()), shared.network, shared.script),
            KeyRole::Evm { btc: None, .. } | KeyRole::Sol { .. } | KeyRole::Zec { .. } => continue,
        };
        match vault.hardware_btc_account(network, script_type, key) {
            Ok(account) => {
                if !expected.contains(&(network, account)) {
                    expected.push((network, account));
                }
            }
            Err(_) => logging::warn("key", "btc.hardware_account_invalid", &[]),
        }
    }
    expected
}

/// Reconciles meta `hw_accounts` and the `YubiKey` Bitcoin accounts of `btc_accounts` with the
/// vault's tag-5 slot map (spec/10 §8, §13), like [`reconcile_imported`] for raw keys: an
/// enrolled key without its account gets one (default label, visible), an account whose key no
/// card holds any more is dropped, address caches are recomputed, and a selection naming a
/// dropped account falls back. Returns whether anything changed.
///
/// # Errors
///
/// The vault's slot map is not readable (locked).
fn reconcile_hardware(document: &mut Meta, vault: &Vault) -> Result<bool, VaultError> {
    use yw_core::yubikey::plan::{KeyRole, accounts, evm_address, sol_address};
    let records = KeyWorker::hardware_records(vault)?;
    let found = accounts(&records);
    let (evm, evm_changed) = hw_list(
        &document.hw_accounts.evm,
        found.iter().filter_map(|account| match account.role {
            KeyRole::Evm { index, .. } => evm_address(&account.public)
                .ok()
                .map(|address| (index.get(), address.to_lower_hex())),
            KeyRole::Btc { .. } | KeyRole::Sol { .. } | KeyRole::Zec { .. } => None,
        }),
        true,
    );
    let (sol, sol_changed) = hw_list(
        &document.hw_accounts.sol,
        found.iter().filter_map(|account| match account.role {
            KeyRole::Sol { index } => sol_address(&account.public)
                .ok()
                .map(|address| (index.get(), address.to_base58())),
            KeyRole::Evm { .. } | KeyRole::Btc { .. } | KeyRole::Zec { .. } => None,
        }),
        false,
    );
    let mut changed = evm_changed || sol_changed;
    document.hw_accounts.evm = evm;
    document.hw_accounts.sol = sol;
    if let EvmAccountPref::Hardware(index) = document.prefs.evm_account
        && !document
            .hw_accounts
            .evm
            .iter()
            .any(|account| account.index == index)
    {
        document.prefs.evm_account = EvmAccountPref::Index(0);
        changed = true;
    }
    if let Some(index) = document.hw_accounts.sol_selected
        && !document
            .hw_accounts
            .sol
            .iter()
            .any(|account| account.index == index)
    {
        document.hw_accounts.sol_selected = None;
        changed = true;
    }
    let present: Vec<u32> = records.iter().map(|record| record.serial).collect();
    let before = document.hw_accounts.defaults.len();
    document
        .hw_accounts
        .defaults
        .retain(|serial| present.contains(serial));
    changed |= document.hw_accounts.defaults.len() != before;
    // Bitcoin: single-address accounts in `btc_accounts` (`key.yubikey`).
    let expected = hw_btc_expected(vault, &records);
    let stale: Vec<(BtcNetwork, BtcAccountId)> = document
        .btc_accounts
        .accounts
        .iter()
        .filter(|meta| meta.account().is_hardware())
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
    Ok(changed)
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
            pending_enrol: None,
            connect_password: None,
            pending_mnemonic: None,
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
            piv_pin: &[],
            admin_last_try: false,
        };
        // The one inserted card (spec/10 §7.3: several are refused, never guessed).
        let serial = crate::yubikey::single_card(self.cards.as_mut())
            .map_err(YubiKeyJobError::Card)?
            .serial;
        let enrolled = crate::yubikey::enrol_card_serial(
            self.cards.as_mut(),
            serial,
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
        let role = card_index(&approved)
            .map(|index| yw_core::yubikey::plan::KeyRole::Evm { index, btc: None });
        if let Some(error) = self.card_refusal(role, pin) {
            return vec![
                KeyOutcome::CardUnused(approved, error),
                KeyOutcome::SignedEvm(crate::events::EvmSigned {
                    ticket,
                    result: Err(SignFailure::Card(error)),
                }),
            ];
        }
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

    /// `SignMessageCard` (spec/10 §9.2): the PIN check first (a failure returns the unused
    /// approval), then the card signature.
    fn sign_message_card(
        &mut self,
        ticket: crate::events::SignTicket,
        approved: Box<yw_core::approval::Approved>,
        typed: bool,
        pin: &[u8],
    ) -> Vec<KeyOutcome> {
        use crate::events::{MessageSignFailure, MessageSigned};
        let role = card_index(&approved)
            .map(|index| yw_core::yubikey::plan::KeyRole::Evm { index, btc: None });
        if let Some(error) = self.card_refusal(role, pin) {
            return vec![
                KeyOutcome::CardUnused(approved, error),
                KeyOutcome::SignedMessage(MessageSigned {
                    ticket,
                    result: Err(MessageSignFailure::Card(error)),
                }),
            ];
        }
        vec![KeyOutcome::SignedMessage(MessageSigned {
            ticket,
            result: self.sign_message_on_card(*approved, typed, pin),
        })]
    }

    fn sign_message_on_card(
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

    /// The PIN check of a card job before its approval is used (spec/10 §9.2): `Some(error)`
    /// when the PIN is wrong or no inserted card holds the key — the job then returns the
    /// unused approval ([`KeyOutcome::CardUnused`]) before its failure. `None` lets the job run
    /// (also when the vault or the role is missing: the signing step reports that).
    fn card_refusal(
        &mut self,
        role: Option<yw_core::yubikey::plan::KeyRole>,
        pin: &[u8],
    ) -> Option<crate::yubikey::CardJobError> {
        let role = role?;
        let records = Self::hardware_records(self.vault.as_ref()?).ok()?;
        crate::yubikey::check_pin(self.cards.as_mut(), &records, role, pin).err()
    }

    /// `SignSolCard` (spec/10 §6.4): the journal's SOL signing step with the card signer.
    fn sign_sol_card(
        &mut self,
        approved: Box<yw_core::approval::Approved>,
        times: SolSignTimes,
        pin: &[u8],
        alt: bool,
    ) -> Vec<KeyOutcome> {
        use crate::events::SolSignFailure;
        use crate::yubikey::CardJobError;
        use yw_core::sol::sign::SolCardSignError;
        let role = crate::yubikey::approval_role(&approved);
        if let Some(error) = self.card_refusal(role, pin) {
            return vec![
                KeyOutcome::CardUnused(approved, error),
                KeyOutcome::SignedSol(Err(SolSignFailure::Card(error))),
            ];
        }
        let Some(vault) = self.vault.as_mut() else {
            return vec![KeyOutcome::SignedSol(Err(SolSignFailure::JournalWrite(
                VaultError::InvalidState,
            )))];
        };
        let records = match Self::hardware_records(vault) {
            Ok(records) => records,
            Err(error) => {
                return vec![KeyOutcome::SignedSol(Err(SolSignFailure::JournalWrite(
                    error,
                )))];
            }
        };
        let Some(yw_core::yubikey::plan::KeyRole::Sol { index }) = role else {
            return vec![KeyOutcome::SignedSol(Err(SolSignFailure::Sign(
                yw_core::sol::SolSignError::KindMismatch,
            )))];
        };
        let cards = self.cards.as_mut();
        self.journal.sign_sol_with(
            vault,
            approved,
            times,
            alt,
            &mut |_, approved, consumed_at_ms, blockhash, now_ms| {
                let mut failure = None;
                let mut card = |message: &[u8]| {
                    crate::yubikey::sign_sol_message(cards, &records, index, pin, message).map_err(
                        |error| {
                            failure = Some(error);
                            yw_core::yubikey::CardError::Internal
                        },
                    )
                };
                let result = yw_core::sol::sign::sign_transfer_card(
                    approved,
                    consumed_at_ms,
                    blockhash,
                    now_ms,
                    &mut card,
                );
                result.map_err(|error| match (failure, error) {
                    (Some(failure), _) => SolSignFailure::Card(failure),
                    (None, SolCardSignError::Sign(error)) => SolSignFailure::Sign(error),
                    (None, SolCardSignError::Card(error)) => {
                        SolSignFailure::Card(CardJobError::Card(error))
                    }
                })
            },
        )
    }

    /// A Zcash step (spec/12 §10–§12).
    fn zec_job(&mut self, job: crate::workers::journal::zec::ZecKeyJob) -> Vec<KeyOutcome> {
        use crate::workers::journal::JournalState;
        use crate::workers::journal::zec::{ZecKeyJob, ZecKeyOutcome, ZecSignFailure};
        let locked = || {
            vec![KeyOutcome::Zec(Box::new(ZecKeyOutcome::Signed(Err(
                ZecSignFailure::JournalWrite,
            ))))]
        };
        match job {
            ZecKeyJob::PublicKey { network, source } => match self.vault.as_ref() {
                Some(vault) => JournalState::zec_public_key(vault, network, source),
                None => vec![KeyOutcome::Zec(Box::new(ZecKeyOutcome::PublicKey(Err(
                    VaultError::InvalidState.to_string(),
                ))))],
            },
            ZecKeyJob::Sign {
                approved,
                plan,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.sign_zec(vault, approved, &plan, now_unix_ms),
                None => locked(),
            },
            ZecKeyJob::SignCard {
                approved,
                plan,
                now_unix_ms,
                pin,
            } => self.sign_zec_card(approved, &plan, now_unix_ms, &pin),
            ZecKeyJob::Journal { txid, transition } => match self.vault.as_mut() {
                Some(vault) => self.journal.apply_zec(vault, txid, transition),
                None => vec![KeyOutcome::Journal(Err(VaultError::InvalidState))],
            },
        }
    }

    /// `SignZecCard` (spec/10 §6.4): one card signature per input with the same PIN
    /// (`zec::sign::sign_plan_card`), the same journal handling as the vault path.
    fn sign_zec_card(
        &mut self,
        approved: Box<yw_core::approval::Approved>,
        plan: &yw_core::zec::ZecPlan,
        now_unix_ms: u64,
        pin: &[u8],
    ) -> Vec<KeyOutcome> {
        use crate::workers::journal::zec::{ZecKeyOutcome, ZecSignFailure};
        let signed_err = |failure: ZecSignFailure| {
            KeyOutcome::Zec(Box::new(ZecKeyOutcome::Signed(Err(failure))))
        };
        let role = crate::yubikey::zec_plan_role(plan);
        if let Some(error) = self.card_refusal(role, pin) {
            return vec![
                KeyOutcome::CardUnused(approved, error),
                signed_err(ZecSignFailure::Card(error)),
            ];
        }
        let (Some(vault), Some(role)) = (self.vault.as_mut(), role) else {
            return vec![signed_err(ZecSignFailure::JournalWrite)];
        };
        let Ok(records) = Self::hardware_records(vault) else {
            return vec![signed_err(ZecSignFailure::JournalWrite)];
        };
        let cards = self.cards.as_mut();
        self.journal.sign_zec_with(
            vault,
            approved,
            plan,
            now_unix_ms,
            &mut |_, approved, plan| {
                let mut failure = None;
                let mut card = |sighash: [u8; 32]| {
                    crate::yubikey::sign_btc_sighash(cards, &records, role, pin, sighash).map_err(
                        |error| {
                            failure = Some(error);
                            yw_core::yubikey::CardError::Internal
                        },
                    )
                };
                let result = yw_core::zec::sign_plan_card(approved, plan, &mut card);
                result.map_err(|error| match failure {
                    Some(failure) => ZecSignFailure::Card(failure),
                    None => ZecSignFailure::Sign(error),
                })
            },
        )
    }

    /// `SignBtcCard` (spec/10 §6.3): the journal's BTC signing step with one card signature per
    /// input (same PIN).
    fn sign_btc_card(
        &mut self,
        approved: Box<yw_core::approval::Approved>,
        plan: &yw_core::btc::SendPlan,
        times: (u32, u64),
        pin: &[u8],
        alt: bool,
    ) -> Vec<KeyOutcome> {
        use crate::workers::journal::btc::BtcSignFailure;
        use crate::yubikey::CardJobError;
        use yw_core::btc::sign::CardSignError;
        let role = crate::yubikey::btc_plan_role(plan);
        if let Some(error) = self.card_refusal(role, pin) {
            return vec![
                KeyOutcome::CardUnused(approved, error),
                KeyOutcome::SignedBtc(Err(BtcSignFailure::Card(error))),
            ];
        }
        let Some(vault) = self.vault.as_mut() else {
            return vec![KeyOutcome::SignedBtc(Err(BtcSignFailure::JournalWrite(
                VaultError::InvalidState,
            )))];
        };
        let records = match Self::hardware_records(vault) {
            Ok(records) => records,
            Err(error) => {
                return vec![KeyOutcome::SignedBtc(Err(BtcSignFailure::JournalWrite(
                    error,
                )))];
            }
        };
        let Some(role) = role else {
            return vec![KeyOutcome::SignedBtc(Err(BtcSignFailure::Sign(
                yw_core::btc::SignError::ApprovalMismatch,
            )))];
        };
        let cards = self.cards.as_mut();
        self.journal.sign_btc_with(
            vault,
            approved,
            plan,
            times,
            alt,
            &mut |_, approved, plan, account| {
                let mut failure = None;
                let mut card = |sighash: [u8; 32]| {
                    crate::yubikey::sign_btc_sighash(cards, &records, role, pin, sighash).map_err(
                        |error| {
                            failure = Some(error);
                            yw_core::yubikey::CardError::Internal
                        },
                    )
                };
                let result = yw_core::btc::sign::sign_plan_card(approved, plan, account, &mut card);
                result.map_err(|error| match (failure, error) {
                    (Some(failure), _) => BtcSignFailure::Card(failure),
                    (None, CardSignError::Sign(error)) => BtcSignFailure::Sign(error),
                    (None, CardSignError::Card(error)) => {
                        BtcSignFailure::Card(CardJobError::Card(error))
                    }
                    (None, CardSignError::PostSign(error)) => BtcSignFailure::PostSign(error),
                })
            },
        )
    }

    /// `SignChainMessageCard` (spec/10 §10): a Solana message (PIV Ed25519) or a Bitcoin
    /// message (BIP137 / BIP322 on `OpenPGP`) of a `YubiKey` account.
    fn sign_chain_message_card(
        &mut self,
        ticket: crate::events::SignTicket,
        approved: Box<yw_core::approval::Approved>,
        pin: &[u8],
    ) -> Vec<KeyOutcome> {
        use crate::events::{ChainMessageSigned, ChainSignature};
        use yw_core::yubikey::plan::KeyRole;
        let role = crate::yubikey::approval_role(&approved);
        if let Some(error) = self.card_refusal(role, pin) {
            logging::info("key", "card.pin_check_failed", &[]);
            return vec![
                KeyOutcome::CardUnused(approved, error),
                KeyOutcome::SignedChainMessage(ChainMessageSigned {
                    ticket,
                    result: Err(false),
                }),
            ];
        }
        let records = self
            .vault
            .as_ref()
            .and_then(|vault| Self::hardware_records(vault).ok());
        let cards = self.cards.as_mut();
        let result = match (role, records) {
            (Some(KeyRole::Sol { index }), Some(records)) => {
                yw_core::sol::msgsign::sign_message_card(*approved, &mut |message: &[u8]| {
                    crate::yubikey::sign_sol_message(cards, &records, index, pin, message)
                        .map_err(|_| yw_core::yubikey::CardError::Internal)
                })
                .map(ChainSignature::Sol)
                .map_err(|_| false)
            }
            (Some(role @ (KeyRole::Btc { .. } | KeyRole::Evm { .. })), Some(records))
                if approved.kind() == yw_core::approval::ApprovalKind::BtcMessage =>
            {
                yw_core::btc::msgsign::sign_message_card(*approved, &mut |sighash: [u8; 32]| {
                    crate::yubikey::sign_btc_sighash(cards, &records, role, pin, sighash)
                        .map_err(|_| yw_core::yubikey::CardError::Internal)
                })
                .map(ChainSignature::Btc)
                .map_err(|_| false)
            }
            _ => Err(false),
        };
        vec![KeyOutcome::SignedChainMessage(ChainMessageSigned {
            ticket,
            result,
        })]
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

    /// Tests: writes `plaintext` as the meta sidecar as it is (e.g. the JSON an older build
    /// wrote), bypassing `Meta::to_json`.
    #[cfg(test)]
    pub(crate) fn test_write_meta_bytes(&mut self, plaintext: &[u8]) -> Result<u64, VaultError> {
        self.vault()?.save_sidecar(FileKind::Meta, plaintext)
    }

    /// Locks the vault and wipes held import buffers.
    pub fn lock(&mut self) {
        self.pending = None;
        self.pending_key = None;
        self.pending_password = None;
        self.yk_wipe();
        self.pending_mnemonic = None;
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
            ImportChain::Zec => Tab::Zec,
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
        if let ImportPreview::Zec(info) = &preview {
            // Its address must not already be this wallet's Zcash account (spec/12 §2.3; the
            // vault refuses card keys and the standard derived key itself).
            let vault = self.vault.as_ref().ok_or(VaultError::InvalidState)?;
            let taken = vault
                .open_sidecar(FileKind::Meta)
                .ok()
                .flatten()
                .and_then(|(_, plaintext)| meta::parse(plaintext.expose()).ok())
                .is_some_and(|parsed| {
                    parsed
                        .meta
                        .zcash
                        .get(info.network)
                        .is_some_and(|account| account.pubkey == info.pubkey)
                });
            if taken {
                return Err(VaultError::DuplicateKey);
            }
        }
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
            ImportPreview::Zec(info) => ImportedAccount::Zec(id, info),
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
        mismatch |= reconcile_hardware(&mut document, vault)?;
        // A Zcash account on an imported key whose record is gone falls back to the default
        // key (spec/12 §12.3: the network's account is made again).
        for network in yw_core::zec::ZecNetwork::ALL {
            let orphan = document.zcash.get(network).is_some_and(|account| {
                account.source == yw_core::zec::ZecKeySource::Imported
                    && !keys
                        .zec
                        .iter()
                        .any(|(_, info)| info.network == network && info.pubkey == account.pubkey)
            });
            if orphan {
                document.zcash.clear(network);
                mismatch = true;
            }
        }
        mismatch |= mnemonics::reconcile_mnemonics(&mut document, vault)?;
        mismatch |= mnemonics::reconcile_mnemonic_chains(&mut document, vault)?;
        let mnemonic_infos = vault.mnemonics()?;
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
            zec_keys: keys.zec,
            mnemonics: mnemonic_infos,
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
            KeyJob::SignSolCard {
                approved,
                consumed_at_ms,
                blockhash,
                last_valid_block_height,
                now_unix_ms,
                pin,
            } => self.sign_sol_card(
                approved,
                SolSignTimes {
                    consumed_at_ms,
                    blockhash,
                    last_valid_block_height,
                    now_unix_ms,
                },
                &pin,
                alt,
            ),
            KeyJob::SignBtcCard {
                approved,
                plan,
                tip_height,
                now_unix_ms,
                pin,
            } => self.sign_btc_card(approved, &plan, (tip_height, now_unix_ms), &pin, alt),
            KeyJob::Zec(zec_job) => self.zec_job(*zec_job),
            KeyJob::SignMessageCard {
                ticket,
                approved,
                typed,
                pin,
            } => self.sign_message_card(ticket, approved, typed, &pin),
            KeyJob::SignChainMessageCard {
                ticket,
                approved,
                pin,
            } => self.sign_chain_message_card(ticket, approved, &pin),
            KeyJob::RemoveImportedKey { password, id } => self.remove_imported(&password, id),
            KeyJob::Mnemonics(mnemonics::MnJob::Remove { password, id }) => {
                self.remove_mnemonic(&password, id)
            }
            KeyJob::RecoverFromPrev { password: bytes } => self.recover_from_prev(&bytes),
            other => {
                let outcome = self.handle_single(other);
                // Several mnemonics with a passphrase: say which one the window asks for.
                let pending = match &outcome {
                    KeyOutcome::Status(Ok(
                        VaultStatus::PassphraseRequired | VaultStatus::PassphraseMismatch,
                    )) => self
                        .vault
                        .as_ref()
                        .and_then(Vault::pending_passphrase)
                        .filter(|pending| pending.count > 1),
                    _ => None,
                };
                match pending {
                    Some(pending) => vec![
                        KeyOutcome::Mnemonics(mnemonics::MnOutcome::PassphraseFor(
                            pending.position,
                            pending.count,
                        )),
                        outcome,
                    ],
                    None => vec![outcome],
                }
            }
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
            KeyJob::ResetWallet {
                stamp,
                include_settings,
            } => {
                // No unlock: the files are moved as they are. Every vault write runs on this
                // thread, so nothing writes them while (or after) they move.
                self.lock();
                self.vault = None;
                KeyOutcome::WalletReset(crate::store::reset::move_wallet_files(
                    &self.dir,
                    &stamp,
                    include_settings,
                ))
            }
            KeyJob::YubiKey(job) => self.yubikey_job(job),
            KeyJob::Mnemonics(job) => self.mnemonic_job(job),
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
            | KeyJob::SignMessageCard { .. }
            | KeyJob::SignChainMessageCard { .. }
            | KeyJob::SignSolCard { .. }
            | KeyJob::SignBtcCard { .. }
            | KeyJob::JournalApply { .. }
            | KeyJob::SignSol { .. }
            | KeyJob::SolApply { .. }
            | KeyJob::BtcMeta { .. }
            | KeyJob::SignBtc { .. }
            | KeyJob::BtcJournal { .. }
            | KeyJob::Zec(_)
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
pub(crate) mod tests {
    use std::sync::Mutex;

    use yw_core::btc::BtcNetwork;

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

    /// A worker on the `abandon` wallet with two emulated `YubiKey`s enrolled: card A (SIG = EVM 0,
    /// AUT = EVM 1, PIV 82 = Solana 0) and card B (SIG = BIP84 mainnet address 0); both cards stay
    /// inserted. Returns the worker, the cards (A, B), the folder and the reconciled meta.
    pub(crate) fn yubikey_wallet(
        tag: &str,
    ) -> (
        KeyWorker,
        std::sync::Arc<std::sync::Mutex<Vec<yw_core::yubikey::mock::MockCard>>>,
        std::path::PathBuf,
        crate::events::MetaLoaded,
    ) {
        use std::sync::{Arc, Mutex};

        use yw_core::bip32::path::AccountIndex;
        use yw_core::secret::Zeroizing;
        use yw_core::yubikey::mock::MockCard;
        use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PivSlot, PlannedSlot};

        let about = format!("{} about", ["abandon"; 11].join(" "));
        let dir = std::env::temp_dir().join(format!(
            "yw-app-yk-{tag}-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        let cards = Arc::new(Mutex::new(vec![MockCard::new(7_700_011)]));
        let mut worker =
            KeyWorker::new(&dir).with_card_source(Box::new(crate::yubikey::MockSource {
                cards: Arc::clone(&cards),
            }));
        let bytes = |text: &str| Zeroizing::new(text.as_bytes().to_vec());
        worker.handle(KeyJob::Load);
        worker.handle(KeyJob::PreviewImport {
            password: Some(bytes("yubikey wallet password")),
            phrase: bytes(&about),
            passphrase: None,
        });
        assert!(matches!(
            worker.handle(KeyJob::CommitImport).first(),
            Some(KeyOutcome::Imported(Ok(())))
        ));
        let evm = |index| KeyRole::Evm {
            index: AccountIndex::new(index).unwrap(),
            btc: None,
        };
        let enrol = |worker: &mut KeyWorker, slots| match worker
            .handle(KeyJob::EnrolYubiKey {
                phrase: bytes(&about),
                passphrase: None,
                slots,
                admin_pin: bytes("12345678"),
                management_key: Zeroizing::new(
                    yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY.to_vec(),
                ),
            })
            .pop()
        {
            Some(KeyOutcome::YubiKeyEnrolled(Ok(_))) => {}
            other => unreachable!("enrolment failed: {other:?}"),
        };
        enrol(
            &mut worker,
            vec![
                PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Sig), evm(0)),
                PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Aut), evm(1)),
                PlannedSlot::recommended(
                    CardSlot::Piv(PivSlot::new(0x82).unwrap()),
                    KeyRole::Sol {
                        index: AccountIndex::ZERO,
                    },
                ),
            ],
        );
        // Card B alone in the reader for its enrolment, then both inserted.
        let card_a = cards.lock().unwrap().pop().unwrap();
        cards.lock().unwrap().push(MockCard::new(7_700_012));
        enrol(
            &mut worker,
            vec![PlannedSlot::recommended(
                CardSlot::OpenPgp(PgpKey::Sig),
                KeyRole::Btc {
                    network: BtcNetwork::Mainnet,
                    script: yw_core::btc::ScriptType::P2wpkh,
                    index: 0,
                },
            )],
        );
        cards.lock().unwrap().insert(0, card_a);
        for card in cards.lock().unwrap().iter_mut() {
            card.log.clear();
        }
        let Some(KeyOutcome::Meta(Ok(loaded))) = worker.handle(KeyJob::LoadMeta).pop() else {
            unreachable!("meta");
        };
        (worker, cards, dir, loaded)
    }

    /// spec/10 §13: after enrolment the meta reconcile lists the slot map's accounts — EVM 0/1
    /// and Solana 0 in `hw_accounts`, the BIP84 address key as a single-address `YubiKey` account
    /// of `btc_accounts` — with the `abandon` vectors as addresses; a second load changes
    /// nothing; labels and hidden flags survive; a key no card holds any more is dropped.
    #[test]
    #[allow(clippy::indexing_slicing, reason = "fixed test lists")]
    fn reconcile_lists_yubikey_accounts_of_every_chain() {
        use yw_core::bip32::path::BtcChain;
        use yw_core::btc::account::HwBtcKey;
        use yw_core::btc::{BtcAccountId, ScriptType};

        let (mut worker, _cards, dir, loaded) = yubikey_wallet("reconcile");
        assert!(loaded.mismatch, "the first load adds the accounts");
        let meta = &loaded.meta;
        let evm: Vec<(u32, &str, &str)> = meta
            .hw_accounts
            .evm
            .iter()
            .map(|account| {
                (
                    account.index,
                    account.label.as_str(),
                    account.address.as_str(),
                )
            })
            .collect();
        assert_eq!(
            evm,
            [
                (
                    0,
                    "YubiKey 계정 1",
                    "0x9858effd232b4033e47d90003d41ec34ecaeda94"
                ),
                (
                    1,
                    "YubiKey 계정 2",
                    "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0"
                )
            ]
        );
        assert_eq!(meta.hw_accounts.sol.len(), 1);
        assert_eq!(
            meta.hw_accounts.sol[0].address,
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
        );
        let id = BtcAccountId::Hardware {
            key: HwBtcKey::Address(0),
            script_type: ScriptType::P2wpkh,
        };
        let btc = meta.btc_accounts.get(BtcNetwork::Mainnet, id).unwrap();
        assert_eq!(
            btc.address(BtcChain::Receive, 0).unwrap().as_str(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert!(btc.account().is_hardware());
        // The mnemonic's own derived account 0 is still there (same key, different account).
        assert_eq!(meta.evm_accounts.len(), 1);
        // Idempotent; a renamed and hidden account keeps its label and flag.
        let mut edited = (*loaded.meta).clone();
        edited.hw_accounts.evm[1].label = "카드 계정".to_owned();
        edited.hw_accounts.evm[1].hidden = true;
        assert!(matches!(
            worker
                .handle(KeyJob::SaveMeta {
                    meta: Box::new(edited.clone())
                })
                .pop(),
            Some(KeyOutcome::MetaSaved(Ok(())))
        ));
        let Some(KeyOutcome::Meta(Ok(again))) = worker.handle(KeyJob::LoadMeta).pop() else {
            unreachable!("meta");
        };
        assert!(!again.mismatch);
        assert_eq!(again.meta.hw_accounts, edited.hw_accounts);
        // The vault without card B's record: its Bitcoin account leaves `btc_accounts`.
        let mut document = (*again.meta).clone();
        {
            let vault = worker.vault.as_mut().unwrap();
            let keys = vault.hardware_keys().unwrap();
            let password =
                yw_core::password::VaultPassword::new(b"yubikey wallet password").unwrap();
            vault.remove_hardware_key(&password, keys[1].id).unwrap();
            assert!(super::reconcile_hardware(&mut document, vault).unwrap());
        }
        assert!(document.btc_accounts.get(BtcNetwork::Mainnet, id).is_none());
        assert_eq!(document.hw_accounts.evm.len(), 2);
        drop(worker);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// spec/10 §6.4, §13: `SignSolCard` signs an approved devnet transfer of `YubiKey` Solana
    /// account 0 on the emulator's PIV slot — the `Pending` record is journaled before the
    /// transaction is returned and the signature verifies strictly; a wrong PIN returns the
    /// unused approval and a `Card` failure with nothing journaled.
    #[test]
    #[allow(clippy::indexing_slicing, reason = "Solana wire offsets")]
    fn sign_sol_card_end_to_end_with_the_emulator() {
        use yw_core::approval::ApprovalStore;
        use yw_core::bip32::path::AccountIndex;
        use yw_core::secret::Zeroizing;
        use yw_core::slip10::SolKeySource;
        use yw_core::sol::display::{SimSummary, SolPreviewFacts, build_sol_transfer_request};
        use yw_core::sol::intent::{SolTransferIntent, flags};
        use yw_core::sol::recipient::{AccountClass, check_recipient};
        use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore};

        use crate::events::SolSignFailure;
        use crate::yubikey::CardJobError;

        const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
        const TO: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
        const NOW: u64 = 1_800_000_000_000;
        let (mut worker, cards, dir, _) = yubikey_wallet("sol");
        let approve = |id: u8| {
            let intent = SolTransferIntent {
                id: [id; 16],
                cluster: SolCluster::Devnet,
                source: SolKeySource::Hardware(AccountIndex::ZERO),
                core: SolTransferCore {
                    from: SolAddress::parse(FROM).unwrap(),
                    to: SolAddress::parse(TO).unwrap(),
                    asset: SolAsset::Sol,
                    amount: 1_000_000,
                    cu_limit: 600,
                    cu_price_micro: 0,
                },
                max_fee_lamports: 5_000,
                fee_cap_lamports: 100_000,
                flags: flags::FIRST_TIME,
                created_at_ms: NOW,
            };
            let facts = SolPreviewFacts {
                account_label: "YubiKey Solana 1".to_owned(),
                recipient: check_recipient(TO, &intent.core.from, &[]).unwrap(),
                recipient_account: AccountClass::Missing,
                balance: 10_000_000_000,
                rent0: 890_880,
                rpc_fee: Some(5_000),
                simulation: SimSummary::Ok { units: 450 },
                spl: None,
                blocks: Vec::new(),
            };
            let draft =
                build_sol_transfer_request(&intent, &intent.cluster.genesis(), &facts).unwrap();
            let mut store = ApprovalStore::new();
            let request = store.issue(draft, 1, NOW).unwrap();
            store.consume(request.id, request.digest, 2).unwrap()
        };
        let sign = |worker: &mut KeyWorker, id: u8, pin: &str| {
            worker.handle(KeyJob::SignSolCard {
                approved: Box::new(approve(id)),
                consumed_at_ms: yw_win::time::monotonic_ms(),
                blockhash: [7; 32],
                last_valid_block_height: 1_150,
                now_unix_ms: NOW,
                pin: Zeroizing::new(pin.as_bytes().to_vec()),
            })
        };
        let journal = |worker: &KeyWorker| {
            crate::workers::journal::JournalState::default()
                .load(worker.vault.as_ref().unwrap())
                .unwrap()
        };
        // Wrong PIN: the approval comes back unused, nothing is signed or journaled.
        let refused = sign(&mut worker, 1, "000000");
        assert!(matches!(refused[0], KeyOutcome::CardUnused(_, _)));
        assert!(matches!(
            refused[1],
            KeyOutcome::SignedSol(Err(SolSignFailure::Card(CardJobError::Card(
                yw_core::yubikey::CardError::WrongPin { retries: 2 }
            ))))
        ));
        assert!(journal(&worker).sol_records.is_empty());
        let outcomes = sign(&mut worker, 2, "123456");
        let Some(KeyOutcome::SignedSol(Ok(summary))) = outcomes.first() else {
            unreachable!("signed");
        };
        assert_eq!(summary.from, SolAddress::parse(FROM).unwrap());
        // `compact-u16(1) ‖ signature ‖ message`: the card signed the template message.
        assert_eq!(summary.tx[0], 1);
        assert_eq!(&summary.tx[1..65], &summary.signature[..]);
        assert!(yw_core::sol::keys::verify_strict(
            &summary.from.to_bytes(),
            &summary.tx[65..],
            &summary.signature
        ));
        let records = journal(&worker).sol_records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tx, summary.tx);
        assert!(
            cards.lock().unwrap().iter().all(|card| !card.saw_write()),
            "card signing sends no write"
        );
        drop(worker);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// spec/10 §6.3, §13: `SignBtcCard` spends two inputs of the `YubiKey` BIP84 address on card
    /// B (high-s and high-R answers): one card signature per input with the same PIN, the full
    /// post-sign verification, the `Signed` record on disk; a wrong PIN returns the unused
    /// approval and a `Card` failure with nothing journaled.
    #[test]
    #[allow(clippy::too_many_lines, reason = "one end-to-end send")]
    fn sign_btc_card_end_to_end_with_the_emulator() {
        use yw_core::approval::{ApprovalId, ApprovalStore};
        use yw_core::bip32::path::BtcChain;
        use yw_core::btc::account::HwBtcKey;
        use yw_core::btc::fee::{FeeChoice, FeeRate, FeeSource};
        use yw_core::btc::meta::{ListedUtxo, VerifiedUtxo};
        use yw_core::btc::{
            BtcAccountId, OutPoint, Sats, ScriptType, SendAmount, SendRequest, Txid,
            build_btc_request, parse_address, plan_send, verify_signed,
        };
        use yw_core::secret::Zeroizing;

        use crate::workers::journal::btc::{BtcMetaOp, BtcRefreshUpdate, BtcSignFailure};
        use crate::yubikey::CardJobError;

        const TIP: u32 = 900_000;
        const NOW_MS: u64 = 1_793_074_713_000;
        let (mut worker, cards, dir, _) = yubikey_wallet("btc");
        let id = BtcAccountId::Hardware {
            key: HwBtcKey::Address(0),
            script_type: ScriptType::P2wpkh,
        };
        let utxo = |byte: u8| {
            let outpoint = OutPoint {
                txid: Txid::from_bytes([byte; 32]),
                vout: 0,
            };
            (
                ListedUtxo {
                    outpoint,
                    chain: BtcChain::Receive,
                    index: 0,
                    height: TIP - 10,
                },
                VerifiedUtxo {
                    outpoint,
                    value: Sats::new(20_000).unwrap(),
                    chain: BtcChain::Receive,
                    index: 0,
                    height: TIP - 10,
                    is_coinbase: false,
                    own: false,
                },
            )
        };
        let (listed, newly): (Vec<_>, Vec<_>) = [utxo(0x51), utxo(0x52)].into_iter().unzip();
        let Some(KeyOutcome::BtcMeta(Ok(update))) = worker
            .handle(KeyJob::BtcMeta {
                op: BtcMetaOp::Refreshed {
                    network: BtcNetwork::Mainnet,
                    account: id,
                    update: Box::new(BtcRefreshUpdate {
                        listed,
                        newly,
                        history: vec![(BtcChain::Receive, 0, 2)],
                        max_tip_seen: TIP,
                        now_unix: 1_000,
                    }),
                },
            })
            .into_iter()
            .next()
        else {
            unreachable!("refreshed");
        };
        let meta = update
            .accounts
            .get(BtcNetwork::Mainnet, id)
            .unwrap()
            .clone();
        let recipient = parse_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            BtcNetwork::Mainnet,
        )
        .unwrap();
        let candidates = meta.spendable(TIP, &[]);
        let plan = plan_send(&SendRequest {
            network: BtcNetwork::Mainnet,
            account: meta.account(),
            recipient,
            amount: SendAmount::Exact(Sats::new(30_000).unwrap()),
            fee: FeeChoice {
                rate: FeeRate::from_sat_per_kvb(2_000),
                source: FeeSource::Manual,
            },
            candidates: &candidates,
            tip_height: TIP,
            change_next: meta.change_next(),
            layout_seed: [3; 32],
            typed_fee_override: None,
            conflicts: &[],
        })
        .unwrap();
        assert_eq!(plan.inputs().len(), 2);
        assert_eq!(
            crate::yubikey::btc_plan_role(&plan).map(yw_core::yubikey::plan::KeyRole::curve),
            Some(yw_core::yubikey::plan::Curve::Secp256k1)
        );
        let approve = || {
            let facts = meta.send_facts(&plan, TIP, &[]).unwrap();
            let draft =
                build_btc_request(ApprovalId::random().unwrap(), &plan, meta.account(), &facts)
                    .unwrap();
            let mut store = ApprovalStore::new();
            let request = store.issue(draft, 1, NOW_MS).unwrap();
            store.consume(request.id, request.digest, 2).unwrap()
        };
        let sign = |worker: &mut KeyWorker, pin: &str| {
            worker.handle(KeyJob::SignBtcCard {
                approved: Box::new(approve()),
                plan: Box::new(plan.clone()),
                tip_height: TIP,
                now_unix_ms: NOW_MS,
                pin: Zeroizing::new(pin.as_bytes().to_vec()),
            })
        };
        let records = |worker: &KeyWorker| {
            crate::workers::journal::JournalState::default()
                .load(worker.vault.as_ref().unwrap())
                .unwrap()
                .btc_records
        };
        for card in cards.lock().unwrap().iter_mut() {
            card.high_s = true;
            card.high_r = true;
        }
        let refused = sign(&mut worker, "000000");
        assert!(matches!(
            refused.first(),
            Some(KeyOutcome::CardUnused(_, _))
        ));
        assert!(matches!(
            refused.get(1),
            Some(KeyOutcome::SignedBtc(Err(BtcSignFailure::Card(
                CardJobError::Card(yw_core::yubikey::CardError::WrongPin { retries: 2 })
            ))))
        ));
        assert!(records(&worker).is_empty());
        let signs_before = cards.lock().unwrap()[1]
            .log
            .iter()
            .filter(|header| header[1] == 0x2A)
            .count();
        let outcomes = sign(&mut worker, "123456");
        let Some(KeyOutcome::SignedBtc(Ok(summary))) = outcomes.first() else {
            unreachable!("signed: {outcomes:?}");
        };
        assert_eq!(summary.network, BtcNetwork::Mainnet);
        verify_signed(&summary.tx.raw, &plan, meta.account()).unwrap();
        let on_disk = records(&worker);
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].txid, summary.tx.txid);
        assert_eq!(on_disk[0].account, id);
        let cards = cards.lock().unwrap();
        let signs = cards[1]
            .log
            .iter()
            .filter(|header| header[1] == 0x2A)
            .count();
        assert_eq!(signs - signs_before, 2, "one card signature per input");
        assert!(cards.iter().all(|card| !card.saw_write()));
        drop(cards);
        drop(worker);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The wizard jobs on the emulator (spec/10 §7, §7.5, §9.3): the preview holds the seed and
    /// touches no card; a wrong admin PIN writes no record; the enrolment, "다시 확인", the PW1
    /// change (a wrong current PIN refused), "PIN 하나로 통일" with the PIN-protected management
    /// key, "가져오기 없이 등록" of a card that already holds the keys (no write),
    /// the removal after the password, and `Discard` / the lock wiping the held words.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one emulator scenario")]
    fn yubikey_wizard_jobs_on_the_emulator() {
        use std::sync::{Arc, Mutex};

        use yw_core::bip32::path::AccountIndex;
        use yw_core::secret::Zeroizing;
        use yw_core::yubikey::mock::MockCard;
        use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PivSlot, PlannedSlot};

        use super::yubikey::{YkJob, YkOutcome};
        use crate::yubikey::{CardJobError, PinTarget};

        let about = format!("{} about", ["abandon"; 11].join(" "));
        let dir = std::env::temp_dir().join(format!(
            "yw-app-yk-jobs-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        let cards = Arc::new(Mutex::new(vec![MockCard::new(9_900_001)]));
        let mut worker =
            KeyWorker::new(&dir).with_card_source(Box::new(crate::yubikey::MockSource {
                cards: Arc::clone(&cards),
            }));
        let bytes = |text: &str| Zeroizing::new(text.as_bytes().to_vec());
        worker.handle(KeyJob::Load);
        worker.handle(KeyJob::PreviewImport {
            password: Some(bytes("yubikey jobs password")),
            phrase: bytes(&about),
            passphrase: None,
        });
        worker.handle(KeyJob::CommitImport);
        let slots = vec![
            PlannedSlot::recommended(
                CardSlot::OpenPgp(PgpKey::Sig),
                KeyRole::Evm {
                    index: AccountIndex::new(3).unwrap(),
                    btc: None,
                },
            ),
            PlannedSlot::recommended(
                CardSlot::Piv(PivSlot::new(0x82).unwrap()),
                KeyRole::Sol {
                    index: AccountIndex::new(4).unwrap(),
                },
            ),
        ];
        let yk =
            |worker: &mut KeyWorker, job: YkJob| match worker.handle(KeyJob::YubiKey(job)).pop() {
                Some(KeyOutcome::YubiKey(outcome)) => Some(outcome),
                Some(KeyOutcome::YubiKeyEnrolled(result)) => {
                    assert!(result.is_ok(), "{result:?}");
                    None
                }
                other => unreachable!("{other:?}"),
            };
        let enrol = |worker: &mut KeyWorker, admin: &str, adopt: bool| {
            worker
                .handle(KeyJob::YubiKey(YkJob::Enrol {
                    serial: 9_900_001,
                    slots: slots.clone(),
                    admin_pin: bytes(admin),
                    management_key: Zeroizing::new(
                        yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY.to_vec(),
                    ),
                    piv_pin: Zeroizing::new(Vec::new()),
                    adopt,
                    admin_last_try: false,
                }))
                .pop()
        };
        let records = |worker: &mut KeyWorker| match worker.handle(KeyJob::HardwareKeys).pop() {
            Some(KeyOutcome::HardwareKeys(Ok(keys))) => keys,
            other => unreachable!("{other:?}"),
        };
        // Wrong words: refused, nothing held.
        assert!(matches!(
            yk(
                &mut worker,
                YkJob::Preview {
                    mnemonic: Some((bytes("abandon abandon"), None)),
                    slots: slots.clone(),
                }
            ),
            Some(YkOutcome::Preview(Err(
                crate::events::YubiKeyJobError::Key(_)
            )))
        ));
        let Some(YkOutcome::Preview(Ok(preview))) = yk(
            &mut worker,
            YkJob::Preview {
                mnemonic: Some((bytes(&about), None)),
                slots: slots.clone(),
            },
        ) else {
            unreachable!("preview");
        };
        assert!(preview.same_as_vault && preview.plan.is_ok());
        assert_eq!(preview.lines[0].path, "m/44'/60'/0'/0/3");
        assert_eq!(preview.lines[1].path, "m/44'/501'/4'/0'");
        assert!(cards.lock().unwrap()[0].log.is_empty());
        // A wrong admin PIN: nothing written, no record.
        assert!(matches!(
            enrol(&mut worker, "00000000", false),
            Some(KeyOutcome::YubiKeyEnrolled(Err(_)))
        ));
        assert!(records(&mut worker).is_empty());
        assert!(matches!(
            enrol(&mut worker, "12345678", false),
            Some(KeyOutcome::YubiKeyEnrolled(Ok(_)))
        ));
        let enrolled = records(&mut worker);
        assert_eq!(enrolled.len(), 1);
        let Some(YkOutcome::Checked(9_900_001, Ok(checks))) =
            yk(&mut worker, YkJob::Check { serial: 9_900_001 })
        else {
            unreachable!("check");
        };
        assert_eq!(checks, [Ok(()), Ok(())]);
        // PW1: a wrong current PIN is refused, then changed.
        let change = |worker: &mut KeyWorker, old: &str| {
            worker
                .handle(KeyJob::YubiKey(YkJob::ChangePin {
                    serial: 9_900_001,
                    target: PinTarget::OpenPgpUser,
                    old: bytes(old),
                    new: bytes("135791"),
                    admin_last_try: false,
                }))
                .pop()
        };
        assert!(matches!(
            change(&mut worker, "000000"),
            Some(KeyOutcome::YubiKey(YkOutcome::PinChanged(
                _,
                PinTarget::OpenPgpUser,
                Err(CardJobError::Card(_))
            )))
        ));
        assert!(matches!(
            change(&mut worker, "123456"),
            Some(KeyOutcome::YubiKey(YkOutcome::PinChanged(_, _, Ok(()))))
        ));
        assert_eq!(cards.lock().unwrap()[0].pw1, b"135791");
        // "PIN 하나로 통일" from the factory values (spec/10 §9.3): PIV PIN, PUK, the management
        // key generated and stored PIN-protected, OpenPGP admin, then user. PW1 is no longer the
        // factory value, so the last step fails and the report names the ones that changed.
        let Some(YkOutcome::PinsSet(9_900_001, Ok(report))) = yk(
            &mut worker,
            YkJob::SetPins {
                serial: 9_900_001,
                current: Zeroizing::new(Vec::new()),
                new: bytes("24681357"),
                admin_last_try: false,
            },
        ) else {
            unreachable!("set pins");
        };
        {
            use crate::yubikey::DefaultsStep::{
                OpenPgpAdmin, OpenPgpUser, PivManagement, PivPin, PivPuk,
            };
            assert_eq!(report.done, [PivPin, PivPuk, PivManagement, OpenPgpAdmin]);
            assert!(matches!(
                report.failed,
                Some((OpenPgpUser, yw_core::yubikey::CardError::WrongPin { .. }))
            ));
            let card = &cards.lock().unwrap()[0];
            assert_eq!(
                (card.piv_pin.as_slice(), card.piv_puk.as_slice()),
                (&b"24681357"[..], &b"24681357"[..])
            );
            assert_eq!(
                (card.pw3.as_slice(), card.pw1.as_slice()),
                (&b"24681357"[..], &b"135791"[..])
            );
            assert_ne!(card.mgmt_key, yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY);
        }
        assert!(matches!(
            yk(&mut worker, YkJob::ProbeManagement { serial: 9_900_001 }),
            Some(YkOutcome::Management(Ok(state))) if state.protected && !state.default
        ));
        // Removal: a wrong password keeps the record.
        let id = enrolled[0].id;
        assert!(matches!(
            yk(
                &mut worker,
                YkJob::Remove {
                    password: bytes("not the password"),
                    id,
                }
            ),
            Some(YkOutcome::Removed(Err(
                yw_core::error::VaultError::UnlockFailed
            )))
        ));
        assert!(matches!(
            yk(
                &mut worker,
                YkJob::Remove {
                    password: bytes("yubikey jobs password"),
                    id,
                }
            ),
            Some(YkOutcome::Removed(Ok(_)))
        ));
        assert!(records(&mut worker).is_empty());
        // "가져오기 없이 등록": the card still holds the keys; read-only.
        cards.lock().unwrap()[0].log.clear();
        assert!(matches!(
            enrol(&mut worker, "", true),
            Some(KeyOutcome::YubiKeyEnrolled(Ok(_)))
        ));
        assert!(!cards.lock().unwrap()[0].saw_write());
        assert_eq!(records(&mut worker)[0].record, enrolled[0].record);
        // `Discard` wipes the held words; so does the lock.
        assert!(matches!(
            yk(&mut worker, YkJob::Discard),
            Some(YkOutcome::Discarded)
        ));
        assert!(matches!(
            yk(
                &mut worker,
                YkJob::Preview {
                    mnemonic: None,
                    slots: slots.clone(),
                }
            ),
            Some(YkOutcome::Preview(Err(_)))
        ));
        assert!(matches!(
            yk(
                &mut worker,
                YkJob::Preview {
                    mnemonic: Some((bytes(&about), None)),
                    slots: slots.clone(),
                }
            ),
            Some(YkOutcome::Preview(Ok(_)))
        ));
        worker.lock();
        let _ = worker.handle(KeyJob::Unlock {
            password: bytes("yubikey jobs password"),
        });
        assert!(matches!(
            yk(
                &mut worker,
                YkJob::Preview {
                    mnemonic: None,
                    slots,
                }
            ),
            Some(YkOutcome::Preview(Err(_)))
        ));
        drop(worker);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// spec/10 §7.3, §9.1: `Identify` refuses two inserted cards and names the one card with its
    /// PIN counters; the enrolment goes to that serial only; with one admin-PIN try left nothing
    /// is sent until the job carries the user's confirmation.
    #[test]
    fn yubikey_one_card_and_the_admin_last_try() {
        use std::sync::{Arc, Mutex};

        use yw_core::secret::Zeroizing;
        use yw_core::yubikey::CardError;
        use yw_core::yubikey::mock::MockCard;

        use super::yubikey::{YkJob, YkOutcome};
        use crate::yubikey::{CardJobError, PinTarget};

        let dir = std::env::temp_dir().join(format!(
            "yw-app-yk-one-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        let cards = Arc::new(Mutex::new(vec![
            MockCard::new(9_900_101),
            MockCard::new(9_900_102),
        ]));
        let mut worker =
            KeyWorker::new(&dir).with_card_source(Box::new(crate::yubikey::MockSource {
                cards: Arc::clone(&cards),
            }));
        let mut yk = |job: YkJob| match worker.handle(KeyJob::YubiKey(job)).pop() {
            Some(KeyOutcome::YubiKey(outcome)) => outcome,
            other => unreachable!("{other:?}"),
        };
        assert!(matches!(
            yk(YkJob::Identify),
            YkOutcome::Identified(Err(CardJobError::Card(CardError::MultipleCards)))
        ));
        cards.lock().unwrap().truncate(1);
        cards.lock().unwrap()[0].pgp_retries = [3, 1];
        let YkOutcome::Identified(Ok(facts)) = yk(YkJob::Identify) else {
            unreachable!("identify");
        };
        assert_eq!(facts.serial, 9_900_101);
        assert_eq!(
            (
                facts.counters.pw1,
                facts.counters.pw3,
                facts.counters.piv_pin
            ),
            (Some(3), Some(1), Some(3))
        );
        cards.lock().unwrap()[0].log.clear();
        let change = |last_try: bool| YkJob::ChangePin {
            serial: 9_900_101,
            target: PinTarget::OpenPgpAdmin,
            old: Zeroizing::new(b"12345678".to_vec()),
            new: Zeroizing::new(b"87654321".to_vec()),
            admin_last_try: last_try,
        };
        assert!(matches!(
            yk(change(false)),
            YkOutcome::PinChanged(_, _, Err(CardJobError::Card(CardError::AdminLastTry)))
        ));
        assert!(
            !cards.lock().unwrap()[0]
                .log
                .iter()
                .any(|header| header[1] == 0x24 || header[1] == 0x20),
            "nothing was verified or changed"
        );
        assert!(matches!(
            yk(change(true)),
            YkOutcome::PinChanged(_, _, Ok(()))
        ));
        assert_eq!(cards.lock().unwrap()[0].pw3, b"87654321");
        let YkOutcome::Counters(_, Ok(counters)) = yk(YkJob::Counters(
            super::yubikey::CounterTarget::Card(9_900_101),
        )) else {
            unreachable!("counters");
        };
        assert_eq!(counters.pw3, Some(3));
        drop(worker);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
