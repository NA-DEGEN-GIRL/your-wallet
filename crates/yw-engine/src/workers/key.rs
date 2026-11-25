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
use yw_core::vault::{EvmKeySource, FileKind, ImportedKeys, RecordId, Vault, VaultStatus};
use yw_platform::Clock;

use crate::errors::ErrorCode;
use crate::events::{
    ImportedAccount, KeyJob, KeyOutcome, KeyQueue, KeyResult, LockSignal, MetaLoaded, RevealWhat,
    SidecarMoves, SidecarRefusal,
};
use crate::logging::{self, Field};
use crate::meta::{self, Account, EvmAccountPref, Meta, RawAccount, SolRawAccount, Tab};
use crate::workers::journal::{JournalState, SolSignTimes};
use platform::{KdfPass, KdfRuns, KeyDeps, KeyPlatform};

pub mod mnemonics;
pub mod platform;
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
    /// Wallet file storage, the resident slot and the reset moves (2026-11-17, spec/15 §11.4
    /// S2; Windows: `store::WinKeyPlatform`).
    platform: Box<dyn KeyPlatform>,
    /// Wall time for vault records; monotonic time for the Solana sign-time check (Windows:
    /// `system_clock::SystemClock`, the App's time base).
    clock: Box<dyn Clock>,
    /// The last `LoadMeta` could not read `meta.ywm` (most importantly: it opened with this
    /// wallet's key but this build cannot read it, a newer build's format): `SaveMeta` is refused
    /// until a load succeeds, so a document the UI queued before is never sealed over it (the
    /// vault itself only refuses a file that failed to open, spec/02 §6.3).
    meta_unreadable: bool,
    /// The app language (`KeyJob::SetLanguage`, spec/14 §1): the default labels this worker
    /// writes (`계정 1` / `Account 1` …). Korean until the app says otherwise.
    lang: yw_core::lang::Lang,
}

impl core::fmt::Debug for KeyWorker {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyWorker")
    }
}

/// Wall-clock Unix seconds of vault records (2026-11-17: from the injected clock; before,
/// `SystemTime` here).
fn now_unix(clock: &dyn Clock) -> u64 {
    clock.now_unix_ms() / 1_000
}

/// Whether this build can read a sidecar's plaintext: meta parses, the journal decodes. The
/// `.prev` choice of E-VLT-006 and the password change (spec/02 §4.4 step 0) both ask this.
#[must_use]
pub fn sidecar_readable(kind: FileKind, plaintext: &[u8]) -> bool {
    match kind {
        FileKind::Meta => meta::parse(plaintext).is_ok(),
        FileKind::Journal => yw_core::journal::JournalPlain::decode(plaintext).is_ok(),
        FileKind::Vault => false,
    }
}

/// The Argon2id derivations `Vault::recover_from_prev` runs from `status` (spec/15 §5.3 "한 호출
/// 안의 Argon2 둘"): from `Locked` it opens the main file first and, when that fails, derives
/// again for `vault.ywv.prev` in the same call, two; from `Corrupt`/`MainMissing` only `.prev`,
/// one. Any other state is refused by the vault before a derivation (one asked, none run).
/// (2026-11-25 A2-8 review: before, always one, so Android let the two-run case through its
/// one-run memory gate with no purge between the two.)
const fn recover_runs(status: Option<VaultStatus>) -> KdfRuns {
    match status {
        Some(VaultStatus::Locked) => KdfRuns::Two,
        _ => KdfRuns::One,
    }
}

fn ascii(bytes: &[u8]) -> Result<&str, KeyError> {
    core::str::from_utf8(bytes).map_err(|_| KeyError::MnemonicFormat)
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
fn reconcile_imported(document: &mut Meta, keys: &ImportedKeys, lang: yw_core::lang::Lang) -> bool {
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
                        lang,
                        meta::EVM_IMPORTED_LABEL,
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
                        lang,
                        meta::SOL_IMPORTED_LABEL,
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

/// The default `YubiKey` account labels written before 2026-11-15 (spec/14; recognised only,
/// never written: [`hw_list`] replaces a stored label that still equals its index's old default).
pub mod text {
    yw_core::texts! {
        /// Before 2026-11-15: an EVM key connected without recovery words, {0} number.
        LEGACY_HW_EVM_CARD_KEY(1) = "YubiKey 카드 키 {0}" / "YubiKey card key {0}";
        /// Before 2026-11-15: a Solana key connected without recovery words, {0} number.
        LEGACY_HW_SOL_CARD_KEY(1) = "YubiKey Solana 카드 키 {0}" / "YubiKey Solana card key {0}";
        /// Before 2026-11-15: an EVM `YubiKey` account, {0} index + 1.
        LEGACY_HW_EVM_ACCOUNT(1) = "YubiKey 계정 {0}" / "YubiKey account {0}";
        /// Before 2026-11-15: a Solana `YubiKey` account, {0} index + 1.
        LEGACY_HW_SOL_ACCOUNT(1) = "YubiKey Solana {0}" / "YubiKey Solana {0}";
    }
}

/// The default label of a new `YubiKey` account (2026-11-15, spec/10 §13): the account is named
/// like a software account of its chain — EVM `계정 N` / `Account N`, Solana `Solana N` — with
/// `N` one above the highest such number among `taken` (every label of the chain, as
/// `Meta::next_evm_number`), so the name says which account it is and the drop-down's source
/// part (`YubiKey: 메인·백업`) says which cards hold it. A key connected without recovery words
/// (index 900–999, spec/10 §7.6) is named the same way (its path line says the path is not
/// known).
///
/// Before 2026-11-15 the default named the card instead of the account: `YubiKey 계정 {i + 1}` /
/// `YubiKey Solana {i + 1}` by index, `YubiKey 카드 키 {n}` / `YubiKey Solana 카드 키 {n}` for
/// index `900 + n − 1` — two cards from one mnemonic read as one `YubiKey 계정 1`, which looked
/// like a card number.
fn hw_label<'a>(
    lang: yw_core::lang::Lang,
    evm: bool,
    taken: impl IntoIterator<Item = &'a str>,
) -> String {
    let template = if evm {
        crate::meta::EVM_ACCOUNT_LABEL
    } else {
        crate::meta::SOL_ACCOUNT_LABEL
    };
    crate::meta::next_imported_label(lang, template, taken)
}

/// Whether `label` is still the default the account `index` got before 2026-11-15 (either
/// language; see [`hw_label`]); such a label is replaced by the new default, a label the user
/// chose is kept.
fn is_legacy_hw_label(evm: bool, index: u32, label: &str) -> bool {
    let (template, number) = if yw_core::yubikey::plan::is_unknown_index(index) {
        (
            if evm {
                text::LEGACY_HW_EVM_CARD_KEY
            } else {
                text::LEGACY_HW_SOL_CARD_KEY
            },
            index.saturating_sub(yw_core::yubikey::plan::UNKNOWN_PATH_FIRST),
        )
    } else if evm {
        (text::LEGACY_HW_EVM_ACCOUNT, index)
    } else {
        (text::LEGACY_HW_SOL_ACCOUNT, index)
    };
    let expected = usize::try_from(number).ok().map(|n| n.saturating_add(1));
    yw_core::lang::Lang::ALL
        .into_iter()
        .any(|lang| expected.is_some_and(|n| template.fill(lang, [&n.to_string()]) == label))
}

/// One chain's `hw_accounts` list from the slot map's accounts: labels and hidden flags kept by
/// index, addresses recomputed; a new account, and one whose label is still its old default
/// (2026-11-15, [`is_legacy_hw_label`]), gets [`hw_label`] numbered after `taken` (the chain's
/// other labels) and the labels kept, in index order. Returns the list and whether it differs
/// from `old`.
fn hw_list<'a>(
    old: &[Account],
    found: impl Iterator<Item = (u32, String)>,
    evm: bool,
    lang: yw_core::lang::Lang,
    taken: impl Iterator<Item = &'a str>,
) -> (Vec<Account>, bool) {
    let mut list: Vec<(Account, bool)> = found
        .map(|(index, address)| {
            let existing = old.iter().find(|account| account.index == index);
            let kept = existing
                .map(|account| account.label.as_str())
                .filter(|label| !is_legacy_hw_label(evm, index, label));
            (
                Account {
                    index,
                    label: kept.unwrap_or_default().to_owned(),
                    address,
                    hidden: existing.is_some_and(|account| account.hidden),
                },
                kept.is_none(),
            )
        })
        .collect();
    list.sort_by_key(|(account, _)| account.index);
    list.dedup_by_key(|(account, _)| account.index);
    let mut taken: Vec<String> = taken
        .map(str::to_owned)
        .chain(
            list.iter()
                .filter(|(_, fresh)| !fresh)
                .map(|(account, _)| account.label.clone()),
        )
        .collect();
    for (account, fresh) in &mut list {
        if *fresh {
            account.label = hw_label(lang, evm, taken.iter().map(String::as_str));
            taken.push(account.label.clone());
        }
    }
    let list: Vec<Account> = list.into_iter().map(|(account, _)| account).collect();
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
fn reconcile_hardware(
    document: &mut Meta,
    vault: &Vault,
    lang: yw_core::lang::Lang,
) -> Result<bool, VaultError> {
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
        lang,
        document.evm_software_labels(),
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
        lang,
        document.sol_software_labels(),
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
    // Card names (2026-11-15): only of cards a tag-5 record still holds.
    let before = document.hw_card_names.len();
    document
        .hw_card_names
        .retain(|(serial, _)| present.contains(serial));
    changed |= document.hw_card_names.len() != before;
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

/// The stable addresses (receive address 0) of every Bitcoin account of a reconciled meta
/// document on every network: meta `btc` and `btc_accounts`, and BIP84 account 0 of every
/// network from the vault — meta `btc` holds only the settings network's, the others come back
/// when that network is chosen again and their grants are kept (spec/05 §4.9). `None` when one
/// is not known.
fn btc_stable_addresses(document: &Meta, vault: &Vault, has_mnemonic: bool) -> Option<Vec<String>> {
    use yw_core::bip32::path::BtcChain;
    let stable = |meta: &BtcMeta| {
        meta.address(BtcChain::Receive, 0)
            .ok()
            .map(|address| address.as_str().to_owned())
    };
    let mut addresses = document
        .btc
        .as_deref()
        .into_iter()
        .chain(document.btc_accounts.accounts.iter())
        .map(stable)
        .collect::<Option<Vec<String>>>()?;
    if has_mnemonic {
        for network in BtcNetwork::ALL {
            let xpub = vault.btc_account_xpub(network.coin_type()).ok()?;
            addresses.push(stable(&BtcMeta::new(network, xpub))?);
        }
    }
    Some(addresses)
}

/// The wallet's accounts in a reconciled meta document, hidden ones included (the input of
/// `grants::prune_grants`): derived, imported, `YubiKey` and added-mnemonic accounts of EVM and
/// Solana, and [`btc_stable_addresses`] (only when a Bitcoin grant is there to check; `None`
/// keeps the Bitcoin grants).
fn wallet_accounts(
    document: &Meta,
    vault: &Vault,
    has_mnemonic: bool,
) -> crate::browser::grants::WalletAccounts {
    let evm = document
        .evm_accounts
        .iter()
        .chain(document.mnemonics.iter().flat_map(|entry| &entry.evm))
        .chain(&document.hw_accounts.evm)
        .map(|account| account.address.as_str())
        .chain(
            document
                .evm_raw_accounts
                .iter()
                .map(|raw| raw.address.as_str()),
        )
        .filter_map(|text| yw_core::evm::address::parse_address(text).ok())
        .collect();
    let sol = document
        .sol_accounts
        .iter()
        .chain(&document.hw_accounts.sol)
        .chain(
            document
                .mnemonic_accounts
                .sol
                .iter()
                .map(|(_, account)| account),
        )
        .map(|account| account.address.as_str())
        .chain(
            document
                .sol_raw_accounts
                .iter()
                .map(|raw| raw.address.as_str()),
        )
        .filter_map(|text| SolAddress::parse(text).ok())
        .map(SolAddress::to_bytes)
        .collect();
    let btc = if document.chain_sites.btc.is_empty() {
        // Nothing to check (and no seed derived for it).
        Some(Vec::new())
    } else {
        btc_stable_addresses(document, vault, has_mnemonic)
    };
    crate::browser::grants::WalletAccounts { evm, sol, btc }
}

impl KeyWorker {
    /// A worker for the data folder `dir` with its platform services (2026-11-17, spec/15
    /// §11.4 S2: `main.rs` passes `store::WinKeyPlatform`, `SystemClock` and `PcscSource`;
    /// before, the worker chose them itself).
    #[must_use]
    pub fn new(dir: &Path, deps: KeyDeps) -> Self {
        let KeyDeps {
            platform,
            clock,
            cards,
        } = deps;
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
            cards,
            platform,
            clock,
            meta_unreadable: false,
            lang: yw_core::lang::Lang::Ko,
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
            overwrite: false,
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
            .add_hardware_key(enrolled.record.clone(), now_unix(&*self.clock))
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
            &*self.clock,
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

    /// `SignSolDappCard` (spec/10 §6.4, spec/07 §20.8): the journal's dApp send step with the
    /// card signer (one touch); a refused PIN returns the unused approval first.
    fn sign_sol_dapp_card(
        &mut self,
        approved: Box<yw_core::approval::Approved>,
        job: crate::workers::journal::SolDappSignJob,
        pin: &[u8],
        alt: bool,
    ) -> Vec<KeyOutcome> {
        use crate::events::{SolDappSigned, SolSignFailure};
        use crate::yubikey::CardJobError;
        use yw_core::sol::dapp::{SolTxCardError, SolTxSignError};
        let ticket = job.ticket;
        let failed = |error: SolSignFailure| {
            KeyOutcome::SignedSolDapp(SolDappSigned {
                ticket,
                result: Err(error),
            })
        };
        let role = crate::yubikey::approval_role(&approved);
        if let Some(error) = self.card_refusal(role, pin) {
            return vec![
                KeyOutcome::CardUnused(approved, error),
                failed(SolSignFailure::DappCard(error)),
            ];
        }
        let Some(vault) = self.vault.as_mut() else {
            return vec![failed(SolSignFailure::JournalWrite(
                VaultError::InvalidState,
            ))];
        };
        let records = match Self::hardware_records(vault) {
            Ok(records) => records,
            Err(error) => return vec![failed(SolSignFailure::JournalWrite(error))],
        };
        let Some(yw_core::yubikey::plan::KeyRole::Sol { index }) = role else {
            return vec![failed(SolSignFailure::DappSign(
                SolTxSignError::KindMismatch,
            ))];
        };
        let cards = self.cards.as_mut();
        self.journal.sign_sol_dapp_with(
            vault,
            approved,
            job,
            alt,
            &*self.clock,
            &mut |_, approved, consumed_at_ms, now_ms, check| {
                let mut failure = None;
                let mut card = |message: &[u8]| {
                    crate::yubikey::sign_sol_message(cards, &records, index, pin, message).map_err(
                        |error| {
                            failure = Some(error);
                            yw_core::yubikey::CardError::Internal
                        },
                    )
                };
                let result = yw_core::sol::dapp::sign_send_card(
                    approved,
                    consumed_at_ms,
                    now_ms,
                    check,
                    &mut card,
                );
                result.map_err(|error| match (failure, error) {
                    (Some(failure), _) => SolSignFailure::DappCard(failure),
                    (None, SolTxCardError::Sign(error)) => SolSignFailure::DappSign(error),
                    (None, SolTxCardError::Card(error)) => {
                        SolSignFailure::DappCard(CardJobError::Card(error))
                    }
                })
            },
        )
    }

    /// A Zcash step (spec/12 §10–§12).
    fn zec_job(&mut self, job: crate::workers::journal::zec::ZecKeyJob) -> Vec<KeyOutcome> {
        use crate::workers::journal::zec::{ZecKeyJob, ZecKeyOutcome, ZecSignFailure};
        let locked = || {
            vec![KeyOutcome::Zec(Box::new(ZecKeyOutcome::Signed(Err(
                ZecSignFailure::JournalWrite,
            ))))]
        };
        match job {
            ZecKeyJob::PublicKey { network, source } => match self.vault.as_ref() {
                Some(vault) => self.journal.zec_public_key(vault, network, source),
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

    /// `SignChainMessageCard` (spec/10 §10): a Solana message or the transactions of a sign-only
    /// dApp request (PIV Ed25519, one touch each) or a Bitcoin message (BIP137 / BIP322 on
    /// `OpenPGP`) of a `YubiKey` account.
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
            (Some(KeyRole::Sol { index }), Some(records))
                if approved.kind() == yw_core::approval::ApprovalKind::SolTransaction =>
            {
                // One card signature (touch) per transaction (spec/10 §6.4).
                yw_core::sol::dapp::sign_txs_card(*approved, &mut |message: &[u8]| {
                    crate::yubikey::sign_sol_message(cards, &records, index, pin, message)
                        .map_err(|_| yw_core::yubikey::CardError::Internal)
                })
                .map(ChainSignature::SolTxs)
                .map_err(|_| false)
            }
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

    /// The platform's leave for the next vault call, which derives the KEK with Argon2id `runs`
    /// times (2026-11-25 A2-8, spec/15 §5.3; [`KeyPlatform::kdf_begin`]). Every such call in
    /// this worker holds it across the call (source check
    /// `every_argon2_call_holds_the_platform_leave`); a refusal is the job's own error
    /// (`VaultError::OutOfMemory`, E-VLT-007). Windows: always given, nothing after.
    fn kdf(&self, runs: KdfRuns) -> Result<KdfPass, VaultError> {
        self.platform.kdf_begin(runs)
    }

    /// The derivations of the next `Vault::recover_from_prev` ([`recover_runs`]).
    fn recover_runs(&self) -> KdfRuns {
        recover_runs(self.vault.as_ref().map(Vault::status))
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
        self.yk_wipe();
        self.pending_mnemonic = None;
        self.journal.clear();
        if let Some(vault) = self.vault.as_mut() {
            vault.lock();
        }
    }

    fn load(&mut self) -> KeyOutcome {
        let storage = match self.platform.open_storage(&self.dir) {
            Ok(storage) => storage,
            Err(error) => {
                return KeyOutcome::Status(Err(VaultError::Storage(error)));
            }
        };
        let leftover =
            storage.any_present(FileKind::Meta) || storage.any_present(FileKind::Journal);
        match Vault::load(storage) {
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

    fn write_default_meta(
        vault: &mut Vault,
        address: &yw_core::evm::address::Address,
        lang: yw_core::lang::Lang,
    ) {
        let mut document = Meta::new_in(lang);
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
        let slot = self.platform.new_slot()?;
        let lang = self.lang;
        let now = now_unix(&*self.clock);
        let kdf = self.kdf(KdfRuns::One)?;
        let vault = self.vault()?;
        let phrase = vault.create_wallet(&password, slot, now);
        drop(kdf);
        let phrase = phrase?;
        let address = vault.evm_address(EvmKeySource::Derived(AccountIndex::ZERO))?;
        Self::write_default_meta(vault, &address, lang);
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
        let slot = self.platform.new_slot()?;
        let lang = self.lang;
        let now = now_unix(&*self.clock);
        let kdf = self.kdf(KdfRuns::One)?;
        let vault = self.vault()?;
        let imported = vault.import_mnemonic(&password, phrase, passphrase, slot, now);
        drop(kdf);
        imported?;
        let address = vault.evm_address(EvmKeySource::Derived(AccountIndex::ZERO))?;
        Self::write_default_meta(vault, &address, lang);
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
    fn write_key_only_meta(
        vault: &mut Vault,
        chain: ImportChain,
        lang: yw_core::lang::Lang,
    ) -> Result<(), VaultError> {
        let keys = vault.imported_keys()?;
        let mut document = Meta::key_only();
        reconcile_imported(&mut document, &keys, lang);
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
        let slot = self.platform.new_slot()?;
        let lang = self.lang;
        let now = now_unix(&*self.clock);
        let kdf = self.kdf(KdfRuns::One)?;
        let vault = self.vault()?;
        let created = vault.create_with_key(&password, key, slot, now);
        drop(kdf);
        created?;
        Self::write_key_only_meta(vault, pending.spec.chain(), lang)
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
        let now = now_unix(&*self.clock);
        let id = self.vault()?.import_key(key, now)?;
        Ok(match preview {
            ImportPreview::Evm(address) => ImportedAccount::Evm(id, address),
            ImportPreview::Sol(address) => ImportedAccount::Sol(id, address),
            ImportPreview::Btc(info) => ImportedAccount::Btc(id, info),
            ImportPreview::Zec(info) => ImportedAccount::Zec(id, info),
        })
    }

    /// `삭제` of an imported key (spec/04 §2.18): refused while an imported Bitcoin key's account
    /// has an in-flight record, or an imported Zcash key's account has a ZEC record that may
    /// still confirm or its records cannot be checked (`ImportedKeyBusy`, whatever the UI
    /// showed); otherwise the password check and the vault removal, then — for a Bitcoin key —
    /// its account leaves meta `btc_accounts`.
    fn remove_imported(&mut self, password_bytes: &[u8], id: RecordId) -> Vec<KeyOutcome> {
        let alt = self.is_alt();
        if let Some(vault) = self.vault.as_ref()
            && (self
                .journal
                .btc_imported_busy(vault, *id.as_bytes(), now_unix(&*self.clock))
                || self.journal.zec_imported_busy(vault, id))
        {
            return vec![KeyOutcome::ImportedKeyBusy(id)];
        }
        let result = (|| {
            let password = password(password_bytes).map_err(|_| VaultError::UnlockFailed)?;
            let _kdf = self.kdf(KdfRuns::One)?;
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
        let now = now_unix(&*self.clock);
        let result = (|| {
            let password = password(bytes).map_err(|_| VaultError::UnlockFailed)?;
            let slot = self.platform.new_slot()?;
            let _kdf = self.kdf(self.recover_runs())?;
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
        // Every arm checks the password (one derivation); the leave ends with this fn.
        let _kdf = self.kdf(KdfRuns::One)?;
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

    /// The stored meta document (the default when there is none) and whether its `prefs` fell
    /// back. The file opened with this wallet's key, so some build of this app wrote it: a
    /// document this build cannot read is `SidecarUnsupported` (a newer format, not damage,
    /// spec/02 §6.3).
    fn read_meta(vault: &Vault, lang: yw_core::lang::Lang) -> Result<(Meta, bool), VaultError> {
        match vault.open_sidecar(FileKind::Meta)? {
            None => Ok((Meta::new_in(lang), false)),
            Some((_, plaintext)) => meta::parse(plaintext.expose())
                .map(|parsed| (parsed.meta, parsed.prefs_reset))
                .map_err(|_| VaultError::SidecarUnsupported(FileKind::Meta)),
        }
    }

    fn load_meta(&mut self) -> Result<MetaLoaded, VaultError> {
        let alt = self.is_alt();
        let lang = self.lang;
        let read = if alt {
            Ok((Meta::new_in(lang), false))
        } else {
            Self::read_meta(self.vault()?, lang)
        };
        // Nothing is sealed over a meta that could not be read until a load succeeds (the vault
        // itself refuses only a file that failed to open; T-META-FAILED keeps the UI's copy away).
        self.meta_unreadable = read.is_err();
        let (mut document, prefs_reset) = read?;
        let vault = self.vault()?;
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
            document.evm_accounts = Meta::new_in(lang).evm_accounts;
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
        mismatch |= reconcile_imported(&mut document, &keys, lang);
        mismatch |= reconcile_hardware(&mut document, vault, lang)?;
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
        mismatch |= mnemonics::reconcile_mnemonics(&mut document, vault, lang)?;
        mismatch |= mnemonics::reconcile_mnemonic_chains(&mut document, vault)?;
        // Bitcoin account names after the accounts are settled (2026-11-15, spec/08 §12.3d):
        // every account keeps the default name it gets now, names of gone accounts go.
        // Not an address mismatch: written below without the warning.
        let named = document.reconcile_btc_view(lang);
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
        // dApp grants follow the accounts: one naming an account the wallet no longer has (a
        // key or recovery phrase removed while the session could not clean its grants up — a
        // lock during the removal, a meta that failed to load) goes before the dispatcher loads
        // it, so adding the same key or words again never brings it back (spec/05 §4.1, §4.9).
        // Not in an alt session (nothing is stored), nor beside keys of a newer version, whose
        // accounts this one may not know.
        if !alt && document.unknown.is_empty() {
            let held = wallet_accounts(&document, vault, keys.has_mnemonic);
            let sites = &mut *document.chain_sites;
            if crate::browser::grants::prune_grants(
                &mut document.connected_sites,
                &mut sites.sol,
                &mut sites.btc,
                &held,
            ) {
                logging::info("key", "meta.grants_pruned", &[]);
                mismatch = true;
            }
        }
        if mismatch {
            logging::warn("key", "MetaAddressMismatch", &[]);
        }
        if (mismatch || named) && !alt {
            vault.save_sidecar(FileKind::Meta, &document.to_json())?;
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

    /// Whether `<name>.prev` opens with this wallet's key and this build can read it.
    fn prev_readable(&self, kind: FileKind) -> Result<(), SidecarRefusal> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(SidecarRefusal::Failed(ErrorCode::App009))?;
        let (_, plaintext) = vault
            .open_sidecar_prev(kind)
            .map_err(|_| SidecarRefusal::PrevUnreadable)?
            .ok_or(SidecarRefusal::NoPrev)?;
        if sidecar_readable(kind, plaintext.expose()) {
            Ok(())
        } else {
            Err(SidecarRefusal::PrevUnreadable)
        }
    }

    /// The E-VLT-006 choice for `meta.ywm` or `journal.ywj` that did not open (spec/02 §6.3,
    /// spec/04 §2.5). `.prev`: the copy is opened and read first; when it is missing or cannot be
    /// read, nothing moves (no `.corrupt-<t>` per click, no loop back to the same choice).
    /// Fresh: the file and its `.prev` both move aside, never deleted, so the new file's saves
    /// never rotate over the last readable copy. A file already gone (a click repeated, a move
    /// that failed half-way) is skipped. The new names are reported for the notice.
    fn resolve_sidecar(
        &mut self,
        kind: FileKind,
        use_prev: bool,
    ) -> Result<SidecarMoves, SidecarRefusal> {
        if kind == FileKind::Vault {
            return Err(SidecarRefusal::Failed(ErrorCode::App009));
        }
        if use_prev {
            self.prev_readable(kind)?;
        }
        let failed = |error| {
            logging::warn(
                "key",
                "sidecar.resolve_failed",
                &[("error", Field::Word(crate::errors::storage_name(error)))],
            );
            SidecarRefusal::Failed(ErrorCode::Vlt003)
        };
        let mut storage = self.platform.open_storage(&self.dir).map_err(failed)?;
        let now = now_unix(&*self.clock);
        let moves = if use_prev {
            SidecarMoves {
                quarantined: storage.restore_prev(kind, now).map_err(failed)?,
                prev: None,
            }
        } else {
            let quarantined = storage.quarantine_main(kind, now).map_err(failed)?;
            SidecarMoves {
                quarantined,
                prev: storage.set_prev_aside(kind, now).map_err(failed)?,
            }
        };
        logging::warn(
            "key",
            "sidecar.resolved",
            &[
                ("file", Field::Word(crate::wallet_files::file_name(kind))),
                (
                    "prev",
                    Field::Word(if use_prev { "used" } else { "set_aside" }),
                ),
            ],
        );
        Ok(moves)
    }

    /// Runs one non-control job; journal jobs can report several outcomes (signing result,
    /// journal view, moved activity).
    #[expect(clippy::too_many_lines, reason = "one arm per multi-outcome job")]
    pub fn handle(&mut self, job: KeyJob) -> Vec<KeyOutcome> {
        let alt = self.is_alt();
        match job {
            KeyJob::SetLanguage(lang) => {
                self.lang = lang;
                self.journal.set_lang(lang);
                Vec::new()
            }
            KeyJob::LoadJournal => match self.vault.as_mut() {
                Some(vault) => match self.journal.load(vault) {
                    Ok(view) => {
                        let mut out = self.journal.btc_startup(vault, now_unix(&*self.clock), alt);
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
                    &*self.clock,
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
            KeyJob::SignSolDapp {
                ticket,
                approved,
                consumed_at_ms,
                now_unix_ms,
                last_valid_block_height,
                check,
                origin,
            } => {
                let job = crate::workers::journal::SolDappSignJob {
                    ticket,
                    consumed_at_ms,
                    last_valid_block_height,
                    now_unix_ms,
                    check,
                    origin,
                };
                match self.vault.as_mut() {
                    Some(vault) => {
                        self.journal
                            .sign_sol_dapp(vault, approved, job, alt, &*self.clock)
                    }
                    None => vec![KeyOutcome::SignedSolDapp(crate::events::SolDappSigned {
                        ticket,
                        result: Err(crate::events::SolSignFailure::JournalWrite(
                            VaultError::InvalidState,
                        )),
                    })],
                }
            }
            KeyJob::SignSolDappCard {
                ticket,
                approved,
                consumed_at_ms,
                now_unix_ms,
                last_valid_block_height,
                check,
                origin,
                pin,
            } => self.sign_sol_dapp_card(
                approved,
                crate::workers::journal::SolDappSignJob {
                    ticket,
                    consumed_at_ms,
                    last_valid_block_height,
                    now_unix_ms,
                    check,
                    origin,
                },
                &pin,
                alt,
            ),
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
                let slot = self.platform.new_slot()?;
                let _kdf = self.kdf(KdfRuns::One)?;
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
                // A meta or journal this build cannot read refuses the change (E-VLT-006):
                // the rotation would push out its readable older `.prev` (spec/02 §4.4 step 0).
                // Two derivations in one call (spec/15 §5.3: Android refuses it in A2).
                let _kdf = self.kdf(KdfRuns::Two)?;
                self.vault()?.change_password(&old, &new, &sidecar_readable)
            })()),
            KeyJob::ImportPrivateKey { hex } => KeyOutcome::RawKeyImported((|| {
                let text = core::str::from_utf8(&hex)
                    .map_err(|_| VaultError::Key(KeyError::InvalidPrivateKey))?;
                let now = now_unix(&*self.clock);
                let vault = self.vault()?;
                let id = vault.import_evm_private_key(text, now)?;
                let address = vault.evm_address(EvmKeySource::Raw(id))?;
                Ok((id, address))
            })()),
            KeyJob::RemoveRawKey {
                password: bytes,
                id,
            } => KeyOutcome::RawKeyRemoved((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                let _kdf = self.kdf(KdfRuns::One)?;
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
                // A document queued before the load that could not read the file.
                if self.meta_unreadable {
                    return Err(VaultError::SidecarUnsupported(FileKind::Meta));
                }
                let mut document = *meta;
                let vault = self.vault.as_mut().ok_or(VaultError::InvalidState)?;
                self.journal.merge_overlay(vault, &mut document);
                vault
                    .save_sidecar(FileKind::Meta, &document.to_json())
                    .map(|_| ())
            })()),
            KeyJob::ResolveSidecar { kind, use_prev } => KeyOutcome::SidecarResolved {
                kind,
                use_prev,
                result: self.resolve_sidecar(kind, use_prev),
            },
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
                lang,
            } => {
                // No unlock: the files are moved as they are. Every vault write runs on this
                // thread, so nothing writes them while (or after) they move.
                self.lock();
                self.vault = None;
                KeyOutcome::WalletReset(self.platform.move_wallet_files(
                    &self.dir,
                    &stamp,
                    include_settings,
                    lang,
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
                        // A sign-only dApp Solana request (spec/07 §20.8): every approved
                        // transaction in one key lending.
                        Some(vault)
                            if approved.kind()
                                == yw_core::approval::ApprovalKind::SolTransaction =>
                        {
                            yw_core::sol::dapp::sign_txs(vault, *approved)
                                .map(crate::events::ChainSignature::SolTxs)
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
            KeyJob::SetLanguage(_)
            | KeyJob::LoadJournal
            | KeyJob::SignEvm { .. }
            | KeyJob::SignEvmCard { .. }
            | KeyJob::SignMessageCard { .. }
            | KeyJob::SignChainMessageCard { .. }
            | KeyJob::SignSolCard { .. }
            | KeyJob::SignBtcCard { .. }
            | KeyJob::JournalApply { .. }
            | KeyJob::SignSol { .. }
            | KeyJob::SignSolDapp { .. }
            | KeyJob::SignSolDappCard { .. }
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

/// A default account entry for `계정 추가`: label `계정 {number}`, where the app passes the number
/// one above the highest `계정 N` of every recovery phrase (`Meta::next_evm_number`, 2026-11-10;
/// before, `index + 1` repeated `계정 1` once per phrase).
#[must_use]
pub fn new_account(
    lang: yw_core::lang::Lang,
    index: u32,
    number: usize,
    address: &yw_core::evm::address::Address,
) -> Account {
    Account {
        index,
        label: crate::meta::EVM_ACCOUNT_LABEL.fill(lang, [&number.to_string()]),
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
            // 2026-11-23 (S4d F22, owner decision spec/15 §18 26 (가) "저장 후 잠금"; spec/04
            // §5.3 step 2, spec/02 §7.2): first the meta saves queued before this `Lock` (the
            // lock's and the shutdown's own grant writes, `flush_grant_writes`, queue them just
            // before it; `Lock` jumped ahead of them), each at its own epoch, so the UI drops its
            // result as one of an older epoch like any result from before the lock. Only
            // `SaveMeta` (it writes the meta sidecar only; never a signing, derivation, export or
            // other job) and only what is queued now. A failed or refused save is logged and the
            // lock goes on: the wipe always follows, and the `LockSignal` (the `Suspend` and
            // shutdown waits) still comes after it. Before F22 the `Lock` wiped first and
            // `cancel_pending` cancelled those saves (`KeyOutcome::Cancelled`) unless the worker
            // had taken them before the `Lock` arrived — a race. (2026-11-23, F22 review) Only
            // the newest of them runs: every `SaveMeta` carries the whole document (yw-app
            // `save_meta` sends the meta it holds), so the older ones are answered cancelled
            // (`Locked`, as before F22) and the wipe waits for one seal and atomic write (and the
            // rest of an interrupted DEK rotation, which that write finishes first:
            // `Vault::save_sidecar` → `continue_rotation`), never for one write per queued save.
            let mut saves = queue.take_saves_before(epoch);
            let newest = saves.pop();
            for (superseded_epoch, superseded) in saves {
                sink(KeyResult {
                    epoch: superseded_epoch,
                    outcome: superseded.cancelled_outcome(),
                });
            }
            if let Some((save_epoch, save)) = newest {
                for outcome in worker.handle(save) {
                    if let KeyOutcome::MetaSaved(Err(error)) = &outcome {
                        logging::warn(
                            "key",
                            "meta.lock_save_failed",
                            &[("code", Field::Code(crate::errors::vault_code(*error)))],
                        );
                    }
                    sink(KeyResult {
                        epoch: save_epoch,
                        outcome,
                    });
                }
            }
            worker.lock();
            for (cancelled_epoch, cancelled) in queue.cancel_pending(epoch) {
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

    use super::platform::testing;
    use super::{KeyWorker, run};
    use crate::events::{
        KeyJob, KeyJobError, KeyOutcome, KeyQueue, KeyResult, LockSignal, accept_result,
    };
    use crate::testkit::yubikey_wallet;

    #[test]
    fn lk2_lock_jumps_the_queue_and_cancels_pending_jobs() {
        let dir = testing::temp_name("lk2");
        let queue = KeyQueue::default();
        queue.push(1, KeyJob::Load);
        queue.push(1, KeyJob::BackupChallenge);
        queue.push(2, KeyJob::Lock);
        queue.push(2, KeyJob::Shutdown);
        let results: Mutex<Vec<KeyResult>> = Mutex::new(Vec::new());
        let signal = LockSignal::default();
        let before = signal.count();
        run(
            KeyWorker::new(&dir, testing::deps()),
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
    }

    /// The password of [`unlocked_worker`]'s vault.
    const LOCK_SAVE_PASSWORD: &str = "lock save password";

    /// A worker on the in-memory `abandon … about` vault, unlocked, with its meta loaded; the
    /// shared store of its data folder (no file, no reader).
    fn unlocked_worker(tag: &str) -> (KeyWorker, testing::MemStore, crate::meta::Meta) {
        use yw_core::secret::Zeroizing;

        let store = testing::MemStore::default();
        let deps = super::platform::KeyDeps {
            platform: Box::new(testing::MemPlatform(store.clone())),
            clock: Box::new(testing::FixedClock),
            cards: Box::new(crate::yubikey::NoReaders),
        };
        let mut worker = KeyWorker::new(&testing::temp_name(tag), deps);
        // The public `abandon`×11 `about` test mnemonic, built at run time.
        let about = format!("{} about", ["abandon"; 11].join(" "));
        let bytes = |text: &str| Zeroizing::new(text.as_bytes().to_vec());
        worker.handle(KeyJob::Load);
        worker.handle(KeyJob::PreviewImport {
            password: Some(bytes(LOCK_SAVE_PASSWORD)),
            phrase: bytes(&about),
            passphrase: None,
        });
        assert!(matches!(
            worker.handle(KeyJob::CommitImport).first(),
            Some(KeyOutcome::Imported(Ok(())))
        ));
        let Some(KeyOutcome::Meta(Ok(loaded))) = worker.handle(KeyJob::LoadMeta).pop() else {
            unreachable!("meta");
        };
        (worker, store, *loaded.meta)
    }

    /// `meta` with one EVM grant of `https://app.example` to account 0 of the `abandon` wallet.
    fn with_grant(meta: &crate::meta::Meta) -> crate::meta::Meta {
        let site = yw_core::policy::ConnectedSite::new(
            yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
            vec![
                yw_core::evm::address::parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
                    .unwrap(),
            ],
            yw_core::evm::chain::SEPOLIA,
            1,
        )
        .unwrap();
        let mut granted = meta.clone();
        granted.connected_sites = crate::browser::grants::sites_to_values(&[site]);
        granted
    }

    /// The outcomes as `name@epoch` (names only: no outcome's data).
    fn outcome_names(results: &[KeyResult]) -> Vec<String> {
        use crate::events::{MessageSignFailure, MessageSigned};
        results
            .iter()
            .map(|result| {
                let name = match &result.outcome {
                    KeyOutcome::MetaSaved(Ok(())) => "MetaSaved".to_owned(),
                    KeyOutcome::MetaSaved(Err(_)) => "MetaSaveFailed".to_owned(),
                    KeyOutcome::SignedMessage(MessageSigned {
                        result: Err(MessageSignFailure::Locked),
                        ..
                    }) => "SignMessageLocked".to_owned(),
                    KeyOutcome::Cancelled(name, KeyJobError::Locked) => format!("Cancelled:{name}"),
                    KeyOutcome::LockDone => "LockDone".to_owned(),
                    _ => "other".to_owned(),
                };
                format!("{name}@{}", result.epoch)
            })
            .collect()
    }

    /// 2026-11-23 (S4d F22, owner decision spec/15 §18 26 (가) "저장 후 잠금", spec/04 §5.3 step
    /// 2): the race of §18 26 made deterministic. At step time the queue is `[Lock, SaveMeta
    /// (the revoke), SignMessage, SaveMeta]`: the lock's own grant write (epoch 1) queued its meta
    /// save and the UI then put `Lock` (epoch 2) in front of it; a consumed signing job waits
    /// behind, and a save at the lock's epoch stands for one queued after the `Lock`. The `Lock`
    /// writes the revoke first (`MetaSaved` at its own epoch 1, which the UI drops as an older
    /// epoch's), then wipes the DEK, then cancels the rest as before — the signing job answers
    /// `Locked`, the later save is cancelled — then `LockSignal` and `LockDone`. The next unlock
    /// reads the document without the revoked site. Before F22 the `Lock` cancelled the revoke's
    /// save (`Cancelled:SaveMeta@1`) and the grant came back at the unlock. (2026-11-23, F22
    /// review) An older whole document queued before the revoke's is superseded: it is answered
    /// `Cancelled:SaveMeta@1` and never written, so the wipe waits for one write only (the unlock
    /// reading the revoked document shows the newest one was the one written); a written save
    /// logs no `meta.lock_save_failed`.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one scenario")]
    fn a_lock_writes_the_meta_saves_queued_before_it_first() {
        use yw_core::approval::{ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore};
        use yw_core::bip32::path::AccountIndex;
        use yw_core::secret::Zeroizing;
        use yw_core::vault::{EvmKeySource, VaultStatus};

        use crate::events::SignTicket;

        let (mut worker, _store, meta) = unlocked_worker("lock-save");
        let granted = with_grant(&meta);
        assert!(matches!(
            worker
                .handle(KeyJob::SaveMeta {
                    meta: Box::new(granted.clone())
                })
                .pop(),
            Some(KeyOutcome::MetaSaved(Ok(())))
        ));
        let mut revoked = granted.clone();
        revoked.connected_sites.clear();
        // A consumed `personal_sign` of account 0 (the job is cancelled before it signs).
        let source = EvmKeySource::Derived(AccountIndex::ZERO);
        let account = worker.vault.as_ref().unwrap().evm_address(source).unwrap();
        let chain = yw_core::evm::chain::sepolia();
        let draft = yw_core::approval::build_personal_request(
            yw_core::lang::Lang::Ko,
            ApprovalId::random().unwrap(),
            ApprovalOrigin::Site(
                yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
            ),
            source,
            account,
            ApprovalKind::EvmPersonalSign,
            &chain,
            &yw_core::evm::eip191::decode_personal_message(b"lock".to_vec()),
            1_790_000_000_000,
        )
        .unwrap();
        let mut approvals = ApprovalStore::new();
        let request = approvals.issue(draft, 0, 1_790_000_000_000).unwrap();
        let approved = approvals.consume(request.id, request.digest, 1).unwrap();
        let queue = KeyQueue::default();
        // An older whole document queued first (before the revoke): superseded by the newer one.
        queue.push(
            1,
            KeyJob::SaveMeta {
                meta: Box::new(granted.clone()),
            },
        );
        queue.push(
            1,
            KeyJob::SaveMeta {
                meta: Box::new(revoked),
            },
        );
        queue.push(
            1,
            KeyJob::SignMessage {
                ticket: SignTicket(5),
                approved: Box::new(approved),
                typed: false,
            },
        );
        queue.push(2, KeyJob::Lock);
        queue.push(
            2,
            KeyJob::SaveMeta {
                meta: Box::new(granted.clone()),
            },
        );
        let results: Mutex<Vec<KeyResult>> = Mutex::new(Vec::new());
        let signal = LockSignal::default();
        let before = signal.count();
        let entry = queue.pop().unwrap();
        assert!(
            matches!(entry, (2, KeyJob::Lock)),
            "the lock is at the front"
        );
        let ((), lines) = crate::logging::capture(|| {
            assert!(super::step(
                &mut worker,
                &queue,
                entry,
                &|result| results.lock().unwrap().push(result),
                &signal,
            ));
        });
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("meta.lock_save_failed")),
            "a written save logs no failure"
        );
        let results = results.into_inner().unwrap();
        assert_eq!(
            outcome_names(&results),
            [
                "Cancelled:SaveMeta@1",
                "MetaSaved@1",
                "SignMessageLocked@1",
                "Cancelled:SaveMeta@2",
                "LockDone@2"
            ]
        );
        assert!(queue.is_empty());
        assert_eq!(
            signal.count(),
            before + 1,
            "one lock signal, after the wipe"
        );
        assert!(
            matches!(
                worker.vault.as_ref().map(yw_core::vault::Vault::status),
                Some(VaultStatus::Locked)
            ),
            "the DEK is wiped"
        );
        // The save above ran before the wipe: a save now (locked) cannot be written.
        assert!(matches!(
            worker
                .handle(KeyJob::SaveMeta {
                    meta: Box::new(granted)
                })
                .pop(),
            Some(KeyOutcome::MetaSaved(Err(_)))
        ));
        // The UI drops the save's result and the superseded save's answer (epoch 1) once it is at
        // the lock's epoch 2.
        assert!(!accept_result(&results[0], 2));
        assert!(!accept_result(&results[1], 2));
        // The next unlock reads the document the lock wrote: the revoked site is gone.
        let _ = worker.handle(KeyJob::Unlock {
            password: Zeroizing::new(LOCK_SAVE_PASSWORD.as_bytes().to_vec()),
        });
        let Some(KeyOutcome::Meta(Ok(loaded))) = worker.handle(KeyJob::LoadMeta).pop() else {
            unreachable!("meta after the unlock");
        };
        assert!(
            loaded.meta.connected_sites.is_empty(),
            "the revoke was written before the lock"
        );
    }

    /// 2026-11-23 (S4d F22, spec/15 §18 26 (가)): a meta save the `Lock` runs first and that
    /// fails (here the meta file left the data folder, so the vault's generation check refuses
    /// the write) is answered `MetaSaved(Err)` at its own epoch and logged
    /// (`meta.lock_save_failed`); the lock still wipes the DEK, signals and reports `LockDone`.
    /// (2026-11-23, F22 review) The log line is pinned (`logging::capture`): the event name and
    /// the error code only.
    #[test]
    fn a_failing_save_before_a_lock_still_locks() {
        use yw_core::vault::{FileKind, VaultStatus, VaultStorage};

        let (mut worker, store, meta) = unlocked_worker("lock-save-fails");
        let mut files = store.clone();
        files.quarantine(FileKind::Meta, 1).unwrap();
        let queue = KeyQueue::default();
        queue.push(
            1,
            KeyJob::SaveMeta {
                meta: Box::new(with_grant(&meta)),
            },
        );
        queue.push(2, KeyJob::Lock);
        let results: Mutex<Vec<KeyResult>> = Mutex::new(Vec::new());
        let signal = LockSignal::default();
        let before = signal.count();
        let entry = queue.pop().unwrap();
        let ((), lines) = crate::logging::capture(|| {
            assert!(super::step(
                &mut worker,
                &queue,
                entry,
                &|result| results.lock().unwrap().push(result),
                &signal,
            ));
        });
        let results = results.into_inner().unwrap();
        assert_eq!(outcome_names(&results), ["MetaSaveFailed@1", "LockDone@2"]);
        // The failure is logged by its static name with its error code only (no path, no value).
        let Some(KeyOutcome::MetaSaved(Err(error))) = results.first().map(|result| &result.outcome)
        else {
            unreachable!("the failed save");
        };
        let failed: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("meta.lock_save_failed"))
            .collect();
        assert_eq!(
            failed,
            [&format!(
                "1970-01-01T00:00:00.000Z WARN key meta.lock_save_failed code={}\n",
                crate::errors::vault_code(*error).code()
            )]
        );
        assert!(queue.is_empty());
        assert_eq!(signal.count(), before + 1);
        assert!(matches!(
            worker.vault.as_ref().map(yw_core::vault::Vault::status),
            Some(VaultStatus::Locked)
        ));
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
        let dir = testing::temp_name("yubikey");
        let cards = Arc::new(Mutex::new(vec![MockCard::new(7_700_001)]));
        let mut worker =
            KeyWorker::new(&dir, testing::deps()).with_card_source(Box::new(MockSource {
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
                    yw_core::lang::Lang::Ko,
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
                    yw_core::lang::Lang::Ko,
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
    }

    /// spec/10 §13 (2026-11-15): a new `YubiKey` account is named like a software account of
    /// its chain, numbered after every label of the chain (`계정 N`, `Solana N`), and a stored
    /// label that is still its index's old default (`YubiKey 계정 {i+1}`, `YubiKey account
    /// {i+1}`, `YubiKey Solana {i+1}`, `YubiKey 카드 키 {n}` …, either language) is replaced the
    /// same way, in index order; a renamed label — even one that looks like another index's old
    /// default — stays.
    #[test]
    fn hw_labels_name_the_account_and_old_defaults_migrate() {
        use super::hw_list;
        use crate::meta::Account;
        use yw_core::lang::Lang;
        let account = |index: u32, label: &str| Account {
            index,
            label: label.to_owned(),
            address: format!("a{index}"),
            hidden: index == 1,
        };
        let found = |indices: &[u32]| {
            indices
                .iter()
                .map(|index| (*index, format!("a{index}")))
                .collect::<Vec<_>>()
                .into_iter()
        };
        let labels = |list: &[Account]| {
            list.iter()
                .map(|account| (account.index, account.label.clone()))
                .collect::<Vec<_>>()
        };
        // New accounts after the software `계정 1`, `Account 4` and a user's `계정 x`.
        let (list, changed) = hw_list(
            &[],
            found(&[0, 1, 900]),
            true,
            Lang::Ko,
            ["계정 1", "Account 4", "계정 x"].into_iter(),
        );
        assert!(changed);
        assert_eq!(
            labels(&list),
            [
                (0, "계정 5".to_owned()),
                (1, "계정 6".to_owned()),
                (900, "계정 7".to_owned())
            ]
        );
        // Stored old defaults migrate (hidden flags kept); renamed labels stay, including one
        // equal to another index's old default.
        let old = [
            account(0, "YubiKey 계정 1"),
            account(1, "YubiKey account 2"),
            account(2, "YubiKey 계정 1"),
            account(3, "메인 지갑"),
            account(900, "YubiKey card key 1"),
            account(901, "YubiKey 카드 키 1"),
        ];
        let (list, changed) = hw_list(
            &old,
            found(&[0, 1, 2, 3, 900, 901]),
            true,
            Lang::En,
            ["계정 1"].into_iter(),
        );
        assert!(changed);
        assert_eq!(
            labels(&list),
            [
                (0, "Account 2".to_owned()),
                (1, "Account 3".to_owned()),
                (2, "YubiKey 계정 1".to_owned()),
                (3, "메인 지갑".to_owned()),
                (900, "Account 4".to_owned()),
                (901, "YubiKey 카드 키 1".to_owned())
            ]
        );
        assert!(
            list.get(1).is_some_and(|account| account.hidden),
            "the hidden flag survives the migration"
        );
        // Migrated labels are stable: a second pass changes nothing.
        let (again, changed) = hw_list(
            &list,
            found(&[0, 1, 2, 3, 900, 901]),
            true,
            Lang::Ko,
            ["계정 1"].into_iter(),
        );
        assert!(!changed);
        assert_eq!(again, list);
        // Solana: `YubiKey Solana 1` → `Solana N` after the software `Solana 1`; a renamed one
        // stays.
        let (list, _) = hw_list(
            &[
                account(0, "YubiKey Solana 1"),
                account(1, "트레이딩"),
                account(900, "YubiKey Solana 카드 키 1"),
            ],
            found(&[0, 1, 900, 2]),
            false,
            Lang::Ko,
            ["Solana 1"].into_iter(),
        );
        assert_eq!(
            labels(&list),
            [
                (0, "Solana 2".to_owned()),
                (1, "트레이딩".to_owned()),
                (2, "Solana 3".to_owned()),
                (900, "Solana 4".to_owned())
            ]
        );
    }

    /// spec/10 §13: after enrolment the meta reconcile lists the slot map's accounts — EVM 0/1
    /// and Solana 0 in `hw_accounts`, the BIP84 address key as a single-address `YubiKey` account
    /// of `btc_accounts` — with the `abandon` vectors as addresses; a second load changes
    /// nothing; labels and hidden flags survive; a key no card holds any more is dropped; card
    /// names (2026-11-15) survive a reload and leave with their record.
    #[test]
    #[allow(clippy::indexing_slicing, reason = "fixed test lists")]
    #[expect(
        clippy::too_many_lines,
        reason = "one wallet through enrolment, renames, card names and a removed card"
    )]
    fn reconcile_lists_yubikey_accounts_of_every_chain() {
        use yw_core::bip32::path::BtcChain;
        use yw_core::btc::account::HwBtcKey;
        use yw_core::btc::{BtcAccountId, ScriptType};

        let (mut worker, _cards, _, loaded) =
            yubikey_wallet(testing::temp_name("yk-reconcile"), testing::deps());
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
                (0, "계정 2", "0x9858effd232b4033e47d90003d41ec34ecaeda94"),
                (1, "계정 3", "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0")
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
        // Idempotent; a renamed and hidden account keeps its label and flag, and the cards keep
        // their names (2026-11-15) while a name of a card no record holds is dropped.
        let serials: Vec<u32> = worker
            .vault
            .as_ref()
            .unwrap()
            .hardware_keys()
            .unwrap()
            .iter()
            .map(|key| key.record.serial)
            .collect();
        assert_eq!(serials.len(), 2);
        let mut edited = (*loaded.meta).clone();
        edited.hw_accounts.evm[1].label = "카드 계정".to_owned();
        edited.hw_accounts.evm[1].hidden = true;
        edited.set_card_name(serials[0], Some("메인".to_owned()));
        edited.set_card_name(serials[1], Some("백업".to_owned()));
        let mut stale = edited.clone();
        stale.set_card_name(9_999_999, Some("잃어버린 카드".to_owned()));
        assert!(matches!(
            worker
                .handle(KeyJob::SaveMeta {
                    meta: Box::new(stale)
                })
                .pop(),
            Some(KeyOutcome::MetaSaved(Ok(())))
        ));
        let Some(KeyOutcome::Meta(Ok(cleaned))) = worker.handle(KeyJob::LoadMeta).pop() else {
            unreachable!("meta");
        };
        assert!(cleaned.mismatch, "the stale name is dropped");
        assert_eq!(cleaned.meta.hw_card_names, edited.hw_card_names);
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
        assert_eq!(again.meta.card_name(serials[0]), Some("메인"));
        // The vault without card B's record: its Bitcoin account leaves `btc_accounts`.
        let mut document = (*again.meta).clone();
        {
            let vault = worker.vault.as_mut().unwrap();
            let keys = vault.hardware_keys().unwrap();
            let password =
                yw_core::password::VaultPassword::new(b"yubikey wallet password").unwrap();
            vault.remove_hardware_key(&password, keys[1].id).unwrap();
            assert!(
                super::reconcile_hardware(&mut document, vault, yw_core::lang::Lang::Ko).unwrap()
            );
        }
        assert!(document.btc_accounts.get(BtcNetwork::Mainnet, id).is_none());
        assert_eq!(document.hw_accounts.evm.len(), 2);
        assert_eq!(
            document.hw_card_names,
            [(serials[0], "메인".to_owned())],
            "the removed card's name goes with its record"
        );
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
        let (mut worker, cards, _, _) =
            yubikey_wallet(testing::temp_name("yk-sol"), testing::deps());
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
                account_label: "Solana 2".to_owned(),
                recipient: check_recipient(TO, &intent.core.from, &[]).unwrap(),
                recipient_account: AccountClass::Missing,
                balance: 10_000_000_000,
                rent0: 890_880,
                rpc_fee: Some(5_000),
                simulation: SimSummary::Ok { units: 450 },
                spl: None,
                blocks: Vec::new(),
            };
            let draft = build_sol_transfer_request(
                yw_core::lang::Lang::Ko,
                &intent,
                &intent.cluster.genesis(),
                &facts,
            )
            .unwrap();
            let mut store = ApprovalStore::new();
            let request = store.issue(draft, 1, NOW).unwrap();
            store.consume(request.id, request.digest, 2).unwrap()
        };
        let sign = |worker: &mut KeyWorker, id: u8, pin: &str| {
            worker.handle(KeyJob::SignSolCard {
                approved: Box::new(approve(id)),
                consumed_at_ms: testing::MONO_MS,
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
    }

    /// spec/07 §20.8, spec/10 §6.4: a sign-only dApp request of three transactions goes the
    /// chain-message route — `SignChainMessageCard` on the emulator's PIV slot takes one touch
    /// per transaction, `SignChainMessage` signs with the vault key; either way only our slot
    /// changes and it verifies strictly. A wrong PIN signs nothing.
    #[test]
    #[allow(clippy::indexing_slicing, reason = "Solana wire offsets")]
    #[allow(clippy::too_many_lines, reason = "one emulator scenario")]
    fn sign_sol_dapp_transactions_on_the_card_and_in_software() {
        use yw_core::approval::ApprovalStore;
        use yw_core::bip32::path::AccountIndex;
        use yw_core::secret::Zeroizing;
        use yw_core::slip10::SolKeySource;
        use yw_core::sol::SolCluster;
        use yw_core::sol::dapp::{
            SolSendOptions, SolTxFacts, SolTxItemFacts, SolTxMode, SolTxRequest,
            build_sol_tx_request,
        };
        use yw_core::sol::display::SimSummary;

        use crate::events::{ChainMessageSigned, ChainSignature, SignTicket};

        const NOW: u64 = 1_800_000_000_000;
        let public = yw_core::codec::base58::base58_decode_32(
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        )
        .unwrap();
        // The wallet signs and pays; one unknown-program instruction each.
        let tx = |tag: u8| {
            let mut out = vec![1_u8];
            out.extend_from_slice(&[0; 64]);
            out.extend_from_slice(&[1, 0, 1, 2]);
            out.extend_from_slice(&public);
            out.extend_from_slice(&[5; 32]);
            out.extend_from_slice(&[7; 32]);
            out.extend_from_slice(&[1, 1, 1, 0, 1, tag]);
            out
        };
        let txs: Vec<Vec<u8>> = (1..=3).map(tx).collect();
        let (mut worker, cards, _, _) =
            yubikey_wallet(testing::temp_name("yk-sol-dapp"), testing::deps());
        let approve = |id: u8, source: SolKeySource| {
            let item = SolTxItemFacts {
                tables: Ok((0, Vec::new())),
                pre: Vec::new(),
                post: None,
                sim: SimSummary::NoResult,
                sim_replaced_blockhash: false,
                rpc_fee: Some(5_000),
                blockhash_valid: Some(true),
            };
            let request = SolTxRequest {
                id: yw_core::approval::ApprovalId([id; 16]),
                origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
                cluster: SolCluster::Devnet,
                source,
                public,
                label: "Solana 1".to_owned(),
                mode: SolTxMode::SignOnly,
                options: SolSendOptions::default(),
                txs: txs.clone(),
            };
            let facts = SolTxFacts {
                items: vec![item; 3],
                mints: Vec::new(),
                unread_mints: Vec::new(),
                known: Vec::new(),
                fee_cap: 100_000,
            };
            let draft = build_sol_tx_request(yw_core::lang::Lang::Ko, &request, &facts).unwrap();
            let mut store = ApprovalStore::new();
            let request = store.issue(draft, 1, NOW).unwrap();
            Box::new(store.consume(request.id, request.digest, 2).unwrap())
        };
        let check = |signed: &[Vec<u8>]| {
            assert_eq!(signed.len(), 3);
            for (signed, sent) in signed.iter().zip(&txs) {
                assert_eq!(signed.len(), sent.len());
                assert_eq!(signed[0], 1);
                assert_eq!(&signed[65..], &sent[65..], "the message is untouched");
                let signature: [u8; 64] = signed[1..65].try_into().unwrap();
                assert!(yw_core::sol::keys::verify_strict(
                    &public,
                    &signed[65..],
                    &signature
                ));
            }
        };
        let hardware = SolKeySource::Hardware(AccountIndex::ZERO);
        let card = |worker: &mut KeyWorker, id: u8, pin: &str| {
            worker.handle(KeyJob::SignChainMessageCard {
                ticket: SignTicket(u64::from(id)),
                approved: approve(id, hardware),
                pin: Zeroizing::new(pin.as_bytes().to_vec()),
            })
        };
        let touches = |cards: &std::sync::Mutex<Vec<yw_core::yubikey::mock::MockCard>>| {
            cards
                .lock()
                .unwrap()
                .iter()
                .map(|card| card.touches)
                .sum::<u32>()
        };
        // The card step's touch prompt (one per transaction, E3) is tested in `app_card`.
        let refused = card(&mut worker, 1, "000000");
        assert!(matches!(refused[0], KeyOutcome::CardUnused(_, _)));
        assert!(matches!(
            refused[1],
            KeyOutcome::SignedChainMessage(ChainMessageSigned {
                result: Err(false),
                ..
            })
        ));
        assert_eq!(touches(&cards), 0);
        let signed = card(&mut worker, 2, "123456");
        let [
            KeyOutcome::SignedChainMessage(ChainMessageSigned {
                ticket: SignTicket(2),
                result: Ok(ChainSignature::SolTxs(list)),
            }),
        ] = signed.as_slice()
        else {
            unreachable!("card signed: {signed:?}");
        };
        check(list);
        assert_eq!(touches(&cards), 3, "one touch per transaction");
        let software = worker.handle(KeyJob::SignChainMessage {
            ticket: SignTicket(3),
            approved: approve(3, SolKeySource::Standard(AccountIndex::ZERO)),
        });
        let [
            KeyOutcome::SignedChainMessage(ChainMessageSigned {
                result: Ok(ChainSignature::SolTxs(list)),
                ..
            }),
        ] = software.as_slice()
        else {
            unreachable!("software signed: {software:?}");
        };
        check(list);
        assert_eq!(touches(&cards), 3);
    }

    /// spec/07 §20.8, spec/10 §6.4: `SignSolDappCard` signs an approved dApp send of `YubiKey`
    /// Solana account 0 on the emulator's PIV slot with one touch — the version 3 `Pending`
    /// record is journaled before the transaction is returned and our signature verifies
    /// strictly; a wrong PIN returns the unused approval and a card failure with nothing
    /// journaled; a job cancelled by the lock answers its ticket as `Locked`.
    #[test]
    #[allow(clippy::indexing_slicing, reason = "Solana wire offsets")]
    #[allow(clippy::too_many_lines, reason = "one emulator scenario")]
    fn sign_sol_dapp_send_on_the_card() {
        use yw_core::approval::ApprovalStore;
        use yw_core::bip32::path::AccountIndex;
        use yw_core::secret::Zeroizing;
        use yw_core::slip10::SolKeySource;
        use yw_core::sol::SolCluster;
        use yw_core::sol::dapp::{
            PreSignCheck, SolSendOptions, SolTxFacts, SolTxItemFacts, SolTxMode, SolTxRequest,
            build_sol_tx_request,
        };
        use yw_core::sol::display::SimSummary;

        use crate::events::{SignTicket, SolDappSigned, SolSignFailure};
        use crate::yubikey::CardJobError;

        const NOW: u64 = 1_800_000_000_000;
        let public = yw_core::codec::base58::base58_decode_32(
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        )
        .unwrap();
        let mut tx = vec![1_u8];
        tx.extend_from_slice(&[0; 64]);
        tx.extend_from_slice(&[1, 0, 1, 2]);
        tx.extend_from_slice(&public);
        tx.extend_from_slice(&[5; 32]);
        tx.extend_from_slice(&[7; 32]);
        tx.extend_from_slice(&[1, 1, 1, 0, 1, 9]);
        let (mut worker, cards, _, _) =
            yubikey_wallet(testing::temp_name("yk-sol-dapp-send"), testing::deps());
        let approve = |id: u8| {
            let request = SolTxRequest {
                id: yw_core::approval::ApprovalId([id; 16]),
                origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
                cluster: SolCluster::Devnet,
                source: SolKeySource::Hardware(AccountIndex::ZERO),
                public,
                label: "Solana 2".to_owned(),
                mode: SolTxMode::SignAndSend,
                options: SolSendOptions::default(),
                txs: vec![tx.clone()],
            };
            let facts = SolTxFacts {
                items: vec![SolTxItemFacts {
                    tables: Ok((0, Vec::new())),
                    pre: Vec::new(),
                    post: None,
                    sim: SimSummary::NoResult,
                    sim_replaced_blockhash: false,
                    rpc_fee: Some(5_000),
                    blockhash_valid: Some(true),
                }],
                mints: Vec::new(),
                unread_mints: Vec::new(),
                known: Vec::new(),
                fee_cap: 100_000,
            };
            let draft = build_sol_tx_request(yw_core::lang::Lang::Ko, &request, &facts).unwrap();
            let mut store = ApprovalStore::new();
            let request = store.issue(draft, 1, NOW).unwrap();
            Box::new(store.consume(request.id, request.digest, 2).unwrap())
        };
        let job = |id: u8, pin: &str| KeyJob::SignSolDappCard {
            ticket: SignTicket(u64::from(id)),
            approved: approve(id),
            consumed_at_ms: testing::MONO_MS,
            now_unix_ms: NOW,
            last_valid_block_height: 1_150,
            check: PreSignCheck {
                blockhash: [7; 32],
                loaded: None,
            },
            origin: "https://app.example".to_owned(),
            pin: Zeroizing::new(pin.as_bytes().to_vec()),
        };
        let touches = |cards: &std::sync::Mutex<Vec<yw_core::yubikey::mock::MockCard>>| {
            cards
                .lock()
                .unwrap()
                .iter()
                .map(|card| card.touches)
                .sum::<u32>()
        };
        let journal = |worker: &KeyWorker| {
            crate::workers::journal::JournalState::default()
                .load(worker.vault.as_ref().unwrap())
                .unwrap()
        };
        // Wrong PIN: the approval comes back unused, nothing is signed or journaled.
        let refused = worker.handle(job(1, "000000"));
        assert!(matches!(refused[0], KeyOutcome::CardUnused(_, _)));
        assert!(matches!(
            refused[1],
            KeyOutcome::SignedSolDapp(SolDappSigned {
                ticket: SignTicket(1),
                result: Err(SolSignFailure::DappCard(CardJobError::Card(
                    yw_core::yubikey::CardError::WrongPin { retries: 2 }
                ))),
            })
        ));
        assert_eq!(touches(&cards), 0);
        assert!(journal(&worker).sol_records.is_empty());
        let signed = worker.handle(job(2, "123456"));
        let Some(KeyOutcome::SignedSolDapp(SolDappSigned {
            ticket: SignTicket(2),
            result: Ok(summary),
        })) = signed.first()
        else {
            unreachable!("card signed: {signed:?}");
        };
        assert_eq!(touches(&cards), 1, "one touch");
        assert_eq!(summary.public, public);
        assert_eq!(&summary.tx[65..], &tx[65..], "the message is untouched");
        assert_eq!(&summary.tx[1..65], &summary.tx_id[..]);
        assert!(yw_core::sol::keys::verify_strict(
            &public,
            &summary.tx[65..],
            &summary.tx_id
        ));
        let records = journal(&worker).sol_records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tx, summary.tx);
        assert_eq!(
            records[0].source,
            SolKeySource::Hardware(AccountIndex::ZERO)
        );
        assert!(records[0].dapp.is_some());
        // Cancelled by the lock before it ran: its ticket is answered as locked.
        assert!(matches!(
            job(3, "123456").cancelled_outcome(),
            KeyOutcome::SignedSolDapp(SolDappSigned {
                ticket: SignTicket(3),
                result: Err(SolSignFailure::Locked),
            })
        ));
        assert!(
            cards.lock().unwrap().iter().all(|card| !card.saw_write()),
            "card signing sends no write"
        );
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
        let (mut worker, cards, _, _) =
            yubikey_wallet(testing::temp_name("yk-btc"), testing::deps());
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
                        skipped: Vec::new(),
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
            let draft = build_btc_request(
                yw_core::lang::Lang::Ko,
                ApprovalId::random().unwrap(),
                &plan,
                meta.account(),
                &facts,
            )
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
        let dir = testing::temp_name("yk-jobs");
        let cards = Arc::new(Mutex::new(vec![MockCard::new(9_900_001)]));
        let mut worker = KeyWorker::new(&dir, testing::deps()).with_card_source(Box::new(
            crate::yubikey::MockSource {
                cards: Arc::clone(&cards),
            },
        ));
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
                    overwrite: false,
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
        // "복구 단어 추가 가져오기" of the card's words names the card (T-YK-SAME before saving);
        // other words name none.
        let mn_preview = |worker: &mut KeyWorker, phrase: &str| match worker
            .handle(KeyJob::Mnemonics(
                crate::workers::key::mnemonics::MnJob::Preview {
                    phrase: bytes(phrase),
                    passphrase: None,
                },
            ))
            .pop()
        {
            Some(KeyOutcome::Mnemonics(crate::workers::key::mnemonics::MnOutcome::Preview(
                Ok((_, cards)),
            ))) => cards,
            other => unreachable!("{other:?}"),
        };
        assert_eq!(mn_preview(&mut worker, &about), vec![9_900_001]);
        // The public `zoo`×11 `wrong` vector, built at run time like `about`.
        let other = format!("{} wrong", ["zoo"; 11].join(" "));
        assert!(mn_preview(&mut worker, &other).is_empty());
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
                    last_try: false,
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
                last_tries: crate::yubikey::LastTries::default(),
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

        let dir = testing::temp_name("yk-one");
        let cards = Arc::new(Mutex::new(vec![
            MockCard::new(9_900_101),
            MockCard::new(9_900_102),
        ]));
        let mut worker = KeyWorker::new(&dir, testing::deps()).with_card_source(Box::new(
            crate::yubikey::MockSource {
                cards: Arc::clone(&cards),
            },
        ));
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
            last_try,
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
    }

    /// The platform of [`argon2_calls_take_the_platform_leave`]: the in-memory folder, a record of
    /// every leave asked for, a switch that refuses them, and a count of the leaves dropped.
    struct Gated {
        inner: testing::MemPlatform,
        asked: std::sync::Arc<Mutex<Vec<super::KdfRuns>>>,
        refuse: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    /// Leaves dropped (only [`argon2_calls_take_the_platform_leave`] counts them).
    static LEAVES_DONE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn leave_done() {
        LEAVES_DONE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    impl super::KeyPlatform for Gated {
        fn open_storage(
            &self,
            dir: &std::path::Path,
        ) -> Result<Box<dyn super::platform::WalletStore>, yw_core::error::StorageError> {
            self.inner.open_storage(dir)
        }

        fn new_slot(
            &self,
        ) -> Result<Box<dyn yw_core::vault::LockedSlot>, yw_core::error::VaultError> {
            self.inner.new_slot()
        }

        fn move_wallet_files(
            &self,
            dir: &std::path::Path,
            stamp: &str,
            include_settings: bool,
            lang: yw_core::lang::Lang,
        ) -> Result<crate::wallet_files::ResetReport, crate::wallet_files::ResetError> {
            self.inner
                .move_wallet_files(dir, stamp, include_settings, lang)
        }

        fn kdf_begin(
            &self,
            runs: super::KdfRuns,
        ) -> Result<super::KdfPass, yw_core::error::VaultError> {
            self.asked.lock().unwrap().push(runs);
            if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
                Err(yw_core::error::VaultError::OutOfMemory)
            } else {
                Ok(super::KdfPass::then(leave_done))
            }
        }
    }

    /// 2026-11-25 A2-8 (spec/15 §5.3): every Argon2-bound job asks the platform first; a refusal
    /// is the job's own error (`OutOfMemory`, E-VLT-007) and the vault call is not made (the vault
    /// stays as it was), a granted leave is dropped right after the call, and a password change
    /// and a `.prev` recovery from `Locked` ask for two derivations (the latter since the
    /// 2026-11-25 A2-8 review). The default platform (Windows) grants every leave.
    #[test]
    fn argon2_calls_take_the_platform_leave() {
        use std::sync::atomic::Ordering;
        use yw_core::error::VaultError;
        use yw_core::secret::Zeroizing;
        use yw_core::vault::VaultStatus;

        use super::KdfRuns;

        let asked = std::sync::Arc::new(Mutex::new(Vec::new()));
        let refuse = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let deps = super::platform::KeyDeps {
            platform: Box::new(Gated {
                inner: testing::MemPlatform::default(),
                asked: std::sync::Arc::clone(&asked),
                refuse: std::sync::Arc::clone(&refuse),
            }),
            clock: Box::new(testing::FixedClock),
            cards: Box::new(crate::yubikey::NoReaders),
        };
        let mut worker = KeyWorker::new(&testing::temp_name("kdf-leave"), deps);
        let about = format!("{} about", ["abandon"; 11].join(" "));
        let bytes = |text: &str| Zeroizing::new(text.as_bytes().to_vec());
        let done_before = LEAVES_DONE.load(Ordering::SeqCst);
        worker.handle(KeyJob::Load);
        worker.handle(KeyJob::PreviewImport {
            password: Some(bytes(LOCK_SAVE_PASSWORD)),
            phrase: bytes(&about),
            passphrase: None,
        });
        assert!(
            asked.lock().unwrap().is_empty(),
            "a preview derives nothing"
        );
        assert!(matches!(
            worker.handle(KeyJob::CommitImport).first(),
            Some(KeyOutcome::Imported(Ok(())))
        ));
        assert_eq!(*asked.lock().unwrap(), [KdfRuns::One]);
        assert_eq!(LEAVES_DONE.load(Ordering::SeqCst), done_before + 1);
        worker.lock();
        // Refused: the unlock is not tried, the vault stays locked, no leave to drop.
        refuse.store(true, Ordering::SeqCst);
        assert!(matches!(
            worker
                .handle(KeyJob::Unlock {
                    password: bytes(LOCK_SAVE_PASSWORD),
                })
                .first(),
            Some(KeyOutcome::Status(Err(VaultError::OutOfMemory)))
        ));
        assert!(matches!(
            worker.vault.as_ref().map(yw_core::vault::Vault::status),
            Some(VaultStatus::Locked)
        ));
        assert!(matches!(
            worker
                .handle(KeyJob::ChangePassword {
                    old: bytes(LOCK_SAVE_PASSWORD),
                    new: bytes("another synthetic password"),
                })
                .first(),
            Some(KeyOutcome::PasswordChanged(Err(VaultError::OutOfMemory)))
        ));
        // 2026-11-25 A2-8 review: a `.prev` recovery from `Locked` tries the main file and then
        // `.prev`, two derivations in one call, so it asks for two (Android refuses it in A2).
        assert!(matches!(
            worker
                .handle(KeyJob::RecoverFromPrev {
                    password: bytes(LOCK_SAVE_PASSWORD),
                })
                .first(),
            Some(KeyOutcome::Status(Err(VaultError::OutOfMemory)))
        ));
        assert!(matches!(
            worker.vault.as_ref().map(yw_core::vault::Vault::status),
            Some(VaultStatus::Locked)
        ));
        assert_eq!(
            *asked.lock().unwrap(),
            [KdfRuns::One, KdfRuns::One, KdfRuns::Two, KdfRuns::Two]
        );
        assert_eq!(LEAVES_DONE.load(Ordering::SeqCst), done_before + 1);
        // Granted again: the unlock runs and its leave is dropped after it.
        refuse.store(false, Ordering::SeqCst);
        assert!(matches!(
            worker
                .handle(KeyJob::Unlock {
                    password: bytes(LOCK_SAVE_PASSWORD),
                })
                .first(),
            Some(KeyOutcome::Status(Ok(VaultStatus::Unlocked { .. })))
        ));
        assert_eq!(LEAVES_DONE.load(Ordering::SeqCst), done_before + 2);
        // The default platform grants every leave and drops nothing.
        let pass = super::KeyPlatform::kdf_begin(&testing::MemPlatform::default(), KdfRuns::Two);
        assert!(pass.is_ok());
        drop(pass);
        assert_eq!(LEAVES_DONE.load(Ordering::SeqCst), done_before + 2);
    }

    /// 2026-11-25 A2-8 review (spec/15 §5.3): a `.prev` recovery asks for two derivations from
    /// `Locked` (the main file first, then `.prev`) and for one from `Corrupt`/`MainMissing`.
    #[test]
    fn recover_runs_follow_the_vault_state() {
        use super::KdfRuns;
        use yw_core::vault::VaultStatus;

        // The vault refuses other states before a derivation.
        for (status, runs) in [
            (Some(VaultStatus::Locked), KdfRuns::Two),
            (
                Some(VaultStatus::Corrupt {
                    prev_available: true,
                }),
                KdfRuns::One,
            ),
            (Some(VaultStatus::MainMissing), KdfRuns::One),
            (Some(VaultStatus::NoVault), KdfRuns::One),
            (None, KdfRuns::One),
        ] {
            assert_eq!(super::recover_runs(status), runs, "{status:?}");
        }
    }

    /// The vault calls that derive the KEK with Argon2id (the yw-core fns that call `derive_kek`:
    /// `unwrap_dek`, `seal_create_with`, `verify_password`) and the argument of the leave each
    /// must hold, `self.kdf(<it>)`: the runs it asks for (spec/15 §5.3). A `.prev` recovery's
    /// runs follow the vault's state (`recover_runs`; 2026-11-25 A2-8 review).
    const ARGON2: [(&str, &str); 18] = [
        ("create_wallet", "KdfRuns::One"),
        ("import_mnemonic", "KdfRuns::One"),
        ("create_with_key", "KdfRuns::One"),
        ("create_with_hardware", "KdfRuns::One"),
        ("unlock", "KdfRuns::One"),
        ("recover_from_prev", "self.recover_runs()"),
        ("change_password", "KdfRuns::Two"),
        ("remove_imported_key", "KdfRuns::One"),
        ("remove_evm_raw_key", "KdfRuns::One"),
        ("remove_hardware_key", "KdfRuns::One"),
        ("reveal_mnemonic", "KdfRuns::One"),
        ("reveal_evm_private_key", "KdfRuns::One"),
        ("reveal_imported_key", "KdfRuns::One"),
        ("reveal_evm_shared_wif", "KdfRuns::One"),
        ("generate_mnemonic", "KdfRuns::One"),
        ("remove_mnemonic", "KdfRuns::One"),
        ("reveal_mnemonic_of", "KdfRuns::One"),
        ("add_mnemonic", "KdfRuns::One"),
    ];

    /// The worker's sources the scan reads.
    const KEY_SOURCES: [(&str, &str); 5] = [
        ("key.rs", include_str!("key.rs")),
        ("key/mnemonics.rs", include_str!("key/mnemonics.rs")),
        ("key/yubikey.rs", include_str!("key/yubikey.rs")),
        (
            "key/yubikey/connect.rs",
            include_str!("key/yubikey/connect.rs"),
        ),
        (
            "key/yubikey/manage.rs",
            include_str!("key/yubikey/manage.rs"),
        ),
    ];

    fn is_fn_line(line: &str) -> bool {
        let mut rest = line.trim_start();
        for prefix in ["pub(crate) ", "pub(super) ", "pub ", "const ", "unsafe "] {
            rest = rest.strip_prefix(prefix).unwrap_or(rest);
        }
        rest.starts_with("fn ")
    }

    /// Moves `depth` back over the braces of `text`, read from its end: a `}` enters a block
    /// that closed before the call, a `{` leaves one (or, at 0, steps out to an enclosing block).
    fn braces_back(text: &str, depth: &mut usize) {
        for unit in text.chars().rev() {
            match unit {
                '}' => *depth += 1,
                '{' => *depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }

    /// The scan of [`every_argon2_call_holds_the_platform_leave`] over one source (up to its
    /// `#[cfg(test)] mod tests`): the number of vault Argon2 calls and a line for each that holds
    /// no leave of its row's runs. From the call back to the start of its fn it tracks the braces,
    /// so only a leave in a block that encloses the call counts (one in a block that already
    /// closed, such as another match arm or closure, does not), the first `self.kdf(` met in an
    /// enclosing block must be a binding (`let kdf`/`let _kdf`) with the row's argument, and a
    /// `drop(kdf)` between it and the call ends it (2026-11-25 A2-8 review: before, any
    /// `self.kdf(KdfRuns::` up to 25 lines back counted, across match arms, and the runs were not
    /// checked).
    fn unheld_argon2_calls(name: &str, source: &str) -> (usize, Vec<String>) {
        let lines: Vec<&str> = source.lines().collect();
        let end = lines
            .windows(2)
            .position(|pair| pair[0].trim() == "#[cfg(test)]" && pair[1].contains("mod tests"))
            .unwrap_or(lines.len());
        let mut calls = 0;
        let mut bad = Vec::new();
        for (at, line) in lines.iter().enumerate().take(end) {
            for (function, runs) in ARGON2 {
                let needle = format!(".{function}(");
                let Some(found) = line.find(&needle) else {
                    continue;
                };
                // Only a vault's: on `vault`, on `self.vault()?` (or a line that continues one).
                // A worker method of the same name (`self.remove_mnemonic(…)`) or another type's
                // (`document.mnemonic_accounts.remove_mnemonic(…)`) is no vault call.
                let receiver: String = line[..found]
                    .chars()
                    .rev()
                    .take_while(|unit| unit.is_ascii_alphanumeric() || *unit == '_')
                    .collect();
                if (!receiver.is_empty() && receiver != "tluav")
                    || line.trim_start().starts_with("//")
                {
                    continue;
                }
                calls += 1;
                let leave = format!("kdf = self.kdf({runs})");
                // How many blocks deeper than an enclosing one the scan is (0: a block that
                // encloses the call).
                let mut depth = 0_usize;
                let mut dropped = false;
                let mut verdict = Err("no leave in its fn");
                braces_back(&line[..found], &mut depth);
                for before in lines[..at].iter().rev() {
                    let text = before.trim_start();
                    if text.starts_with("//") {
                        continue;
                    }
                    if depth == 0 {
                        if text.contains("drop(kdf)") || text.contains("drop(_kdf)") {
                            dropped = true;
                        }
                        if text.contains("self.kdf(") {
                            verdict = if !text.starts_with("let ") || !text.contains(&leave) {
                                Err("a leave of other runs")
                            } else if dropped {
                                Err("its leave dropped before it")
                            } else {
                                Ok(())
                            };
                            break;
                        }
                    }
                    if is_fn_line(before) {
                        break;
                    }
                    braces_back(before, &mut depth);
                }
                if let Err(why) = verdict {
                    bad.push(format!("{name}:{}: `{function}`: {why}", at + 1));
                }
            }
        }
        (calls, bad)
    }

    /// 2026-11-25 A2-8 (spec/15 §5.3), source check: every vault call of this worker that derives
    /// the KEK with Argon2id holds the platform's leave of the runs it makes (`ARGON2`), taken in
    /// a block that encloses the call within the same fn (`let kdf = self.kdf(…)?`, not dropped
    /// before it), so Android's memory check and purge cannot be skipped by a new job or asked
    /// for too few runs. 2026-11-25 A2-8 review: the scan follows the braces (before, it looked up
    /// to 25 lines back, so another match arm's leave counted) and checks the runs; the mutations
    /// below are its negative self-tests.
    #[test]
    fn every_argon2_call_holds_the_platform_leave() {
        let mut calls = 0;
        for (name, source) in KEY_SOURCES {
            let (found, bad) = unheld_argon2_calls(name, source);
            calls += found;
            assert!(bad.is_empty(), "{bad:#?}");
        }
        assert!(calls >= 18, "the scan found the calls ({calls})");

        // Negative self-tests on mutated copies of key.rs's code (not this test's own text).
        let source = KEY_SOURCES[0].1;
        let source = &source[..source.find("#[cfg(test)]\npub(crate) mod tests").unwrap()];
        let lines: Vec<&str> = source.lines().collect();
        // (1) The `RemoveRawKey` arm without its leave: the `ChangePassword` arm's leave above it
        // is in a closed block and does not count.
        let call = lines
            .iter()
            .position(|line| line.contains("self.vault()?.remove_evm_raw_key("))
            .unwrap();
        assert!(lines[call - 1].contains("let _kdf = self.kdf(KdfRuns::One)?;"));
        let mut cut = lines.clone();
        cut.remove(call - 1);
        let (_, bad) = unheld_argon2_calls("key.rs", &cut.join("\n"));
        assert_eq!(bad.len(), 1, "{bad:#?}");
        assert!(
            bad[0].contains("`remove_evm_raw_key`: no leave"),
            "{bad:#?}"
        );
        // (2) The password change asking for one run.
        assert_eq!(source.matches("self.kdf(KdfRuns::Two)").count(), 1);
        let one = source.replacen("self.kdf(KdfRuns::Two)", "self.kdf(KdfRuns::One)", 1);
        let (_, bad) = unheld_argon2_calls("key.rs", &one);
        assert_eq!(bad.len(), 1, "{bad:#?}");
        assert!(
            bad[0].contains("`change_password`: a leave of other runs"),
            "{bad:#?}"
        );
        // (3) A `.prev` recovery asking for one run whatever the vault's state.
        assert_eq!(source.matches("self.kdf(self.recover_runs())").count(), 1);
        let one = source.replacen("self.kdf(self.recover_runs())", "self.kdf(KdfRuns::One)", 1);
        let (_, bad) = unheld_argon2_calls("key.rs", &one);
        assert_eq!(bad.len(), 1, "{bad:#?}");
        assert!(
            bad[0].contains("`recover_from_prev`: a leave of other runs"),
            "{bad:#?}"
        );
        // (4) The leave dropped before the call (`create`).
        let early = source.replacen(
            "let vault = self.vault()?;\n        let phrase = vault.create_wallet(",
            "drop(kdf);\n        let vault = self.vault()?;\n        let phrase = vault.create_wallet(",
            1,
        );
        assert_ne!(early, source);
        let (_, bad) = unheld_argon2_calls("key.rs", &early);
        assert!(
            bad.iter()
                .any(|line| line.contains("`create_wallet`: its leave dropped before it")),
            "{bad:#?}"
        );
    }
}
