//! The decrypted `meta.ywm` JSON (`schema = "yw-meta/3"`, spec/02 §5.3) and its `prefs` object
//! (spec/04 §6.4). yw-core only seals bytes; this module parses and writes the JSON with yw-json.
//! Duplicate keys, a missing known key or an invalid value reject the whole document (the key
//! worker reports it as `SidecarUnsupported`, E-VLT-006: the file opened with the wallet's key, so
//! a build of this app wrote it — usually a newer one), except `prefs`, which falls back to its
//! default on any error.
//! Unknown top-level keys (a newer minor version's) are kept and written back after the known keys
//! (spec/04 §6.6, spec/02 §5.3). The imported-key keys (`sol_raw_accounts`, `sol_raw_selected`)
//! are optional on read (files written before key import lack them) and always written after
//! `prefs`; `btc_accounts` (spec/08 §12.3a) is optional too and written last. Imported Bitcoin
//! keys have no list of their own: each is a single-key account in `btc_accounts`. The optional
//! `token_view` (hidden token rows, `crate::token_view`) is written only when not the default and
//! falls back to the default when invalid, like `prefs`.

pub use yw_core::btc::meta::BTC_ACCOUNTS_EXT_KEY;
use yw_core::btc::meta::{BtcAccounts, BtcMeta, btc_meta_from_values, btc_meta_values};
use yw_json::{Limits, Number, Object, Value};

use crate::network::NetworkId;
use crate::text::{is_valid_label, json_object, json_object_owned, json_str, json_u64};
use crate::token_view::{TOKEN_VIEW_KEY, TokenView};

/// Schema tag.
pub const META_SCHEMA: &str = "yw-meta/3";
/// Derived EVM accounts bound.
pub const MAX_EVM_ACCOUNTS: usize = 100;
/// Imported keys bound, per chain (EVM, Solana, Bitcoin; spec/02 §5.3).
pub const MAX_RAW_ACCOUNTS: usize = 15;
/// Largest account index (`AccountIndex`, spec/02 §3.3).
pub const MAX_ACCOUNT_INDEX: u64 = 999;
/// Address-book bound (all chains together).
pub const MAX_ADDRESS_BOOK: usize = 500;
/// Connected-sites bound.
pub const MAX_SITES: usize = 256;
/// User tokens per EVM network.
pub const MAX_TOKENS_PER_NETWORK: usize = 100;
const MAX_TOKENS_TOTAL: usize = 1_000;
const MAX_ACTIVITY_PER_NETWORK: usize = 500;
const MAX_ACTIVITY_TOTAL: usize = 3_000;
/// Largest meta plaintext (spec/02 §5.2).
const META_MAX_BYTES: usize = 8 * 1_024 * 1_024;
/// The top-level keys of `yw-meta/3`, in write order.
const KEYS: [&str; 10] = [
    "schema",
    "evm_accounts",
    "evm_raw_accounts",
    "sol_accounts",
    "btc",
    "address_book",
    "connected_sites",
    "tokens",
    "activity",
    "prefs",
];
/// Imported-key keys added with key import: optional on read, written after `prefs`.
const OPTIONAL_KEYS: [&str; 2] = ["sol_raw_accounts", "sol_raw_selected"];

/// The optional top-level key of the non-primary BTC accounts (spec/08 §12.3a): written after
/// the required keys when there is something to store; a file without it has no such accounts.
pub const BTC_ACCOUNTS_KEY: &str = "btc_accounts";

/// The optional top-level keys of the Solana and Bitcoin dApp grants (spec/02 §5.3, spec/05
/// §4.9): written only when non-empty, kept unread (as unknown keys) by earlier versions.
pub const SOL_SITES_KEY: &str = "sol_sites";
/// See [`SOL_SITES_KEY`].
pub const BTC_SITES_KEY: &str = "btc_sites";

/// The optional top-level key of the security settings snapshot (review M1/L15,
/// `crate::settings::SecuritySnapshot`): written whenever the app has one; absent in files of
/// earlier versions, which keep it unread (as an unknown key) when they write.
pub const SECURITY_KEY: &str = "security_settings";
/// The optional top-level key of the highest `vault.ywv` generation seen with this meta
/// (review L17): a smaller generation at the next unlock means `vault.ywv` was rolled back on its
/// own. Written when non-zero.
pub const VAULT_SEEN_KEY: &str = "vault_generation_seen";
/// The optional top-level key of the last journal reset (2026-11-10, spec/04 §2.5): Unix seconds
/// of `격리하고 새로 시작` on a `journal.ywj` that did not open. A transaction the old journal
/// tracked may still confirm without a record, so for a while after it the Bitcoin send form asks
/// for a check and Solana and Zcash sends wait (`crate::app_sidecar`). Written when non-zero.
pub const JOURNAL_RESET_KEY: &str = "journal_reset_at";

/// The optional top-level key of the address-book favorites (spec/02 §5.3, spec/04 §2.10):
/// `[{"chain": "evm"|"sol"|"btc", "address": string}]` naming `address_book` entries, in the
/// order they were starred. A view preference kept apart from the entries because earlier
/// versions reject an `AddressBookEntry` with an extra member (the whole meta would become
/// unreadable, E-VLT-006) but keep an unknown top-level key unread and write it back. Written
/// only when non-empty; an invalid value falls back to no favorites (like `token_view`), and
/// names of entries that no longer exist are dropped on read.
pub const BOOK_FAVORITES_KEY: &str = "address_book_favorites";

/// The optional top-level key of the `YubiKey` accounts (spec/10 §8, §13): labels, hidden flags,
/// the Solana selection and the cards still on default PINs. The truth source is vault tag 5
/// (the accounts and addresses are recomputed from it at unlock); written only when not the
/// default, kept unread (as an unknown key) by earlier versions.
pub const HW_ACCOUNTS_KEY: &str = "hw_accounts";
/// `hw_accounts` bound per chain (8 cards × 24 slots).
pub const MAX_HW_ACCOUNTS: usize = 192;
/// `hw_accounts.defaults` bound (`MAX_CARDS`).
const MAX_HW_DEFAULTS: usize = 8;
const HW_KEYS: [&str; 4] = ["evm", "sol", "sol_selected", "defaults"];

/// The optional top-level key of the recovery phrases (spec/02 §5.3, 2026-11-07 "여러 복구
/// 단어"): `[{"record_id": Hex16, "label": Label, "evm": Account[]}]`, one entry per vault
/// `Bip39` record in vault order. The primary (first) mnemonic's accounts stay in
/// `evm_accounts` (its `evm` is `[]`); the others' EVM accounts `m/44'/60'/0'/0/i` live here,
/// apart from `evm_accounts` because earlier versions reject an `Account` with an extra member.
/// Not written for a wallet with one mnemonic under its default label. Strict like
/// `hw_accounts` (an invalid value rejects the document).
pub const MNEMONICS_KEY: &str = "mnemonics";
const MNEMONIC_KEYS: [&str; 3] = ["record_id", "label", "evm"];
/// Default label prefix of a recovery phrase (`니모닉 N`).
pub const MNEMONIC_LABEL_PREFIX: &str = "복구 단어 ";
/// The default-label prefix before 2026-11-08 (stored labels keep it; both count as default).
pub const LEGACY_MNEMONIC_LABEL_PREFIX: &str = "니모닉 ";

/// `N` of a default recovery-phrase label (`복구 단어 N`, or `니모닉 N` written by earlier
/// versions); `None` for a label the user chose.
#[must_use]
pub fn default_mnemonic_number(label: &str) -> Option<usize> {
    label
        .strip_prefix(MNEMONIC_LABEL_PREFIX)
        .or_else(|| label.strip_prefix(LEGACY_MNEMONIC_LABEL_PREFIX))?
        .parse()
        .ok()
}

/// One recovery phrase of meta `mnemonics`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MnemonicEntry {
    /// The vault `Bip39` record id (the mnemonic id).
    pub record_id: [u8; 16],
    /// Label (`복구 단어 N` by default; `니모닉 N` before 2026-11-08).
    pub label: String,
    /// EVM accounts of this mnemonic (index ascending, index 0 first; empty for the primary
    /// mnemonic, whose accounts are `evm_accounts`).
    pub evm: Vec<Account>,
}

impl MnemonicEntry {
    /// The next EVM account index of this mnemonic (`None` at 100 accounts or index 999).
    #[must_use]
    pub fn next_index(&self) -> Option<u32> {
        if self.evm.len() >= MAX_EVM_ACCOUNTS {
            return None;
        }
        let next = self
            .evm
            .iter()
            .map(|account| account.index)
            .max()
            .map_or(Some(0), |max| max.checked_add(1))?;
        (u64::from(next) <= MAX_ACCOUNT_INDEX).then_some(next)
    }
}

fn parse_mnemonics(value: Option<&Value>) -> Option<Vec<MnemonicEntry>> {
    let Some(value) = value else {
        return Some(Vec::new());
    };
    let list = value.as_array()?;
    if list.len() > yw_core::vault::MAX_MNEMONICS {
        return None;
    }
    let mut out: Vec<MnemonicEntry> = Vec::with_capacity(list.len());
    for item in list {
        let object = item.as_object()?;
        if !exact_keys(object, &MNEMONIC_KEYS) {
            return None;
        }
        let record_id = parse_hex16(object.get("record_id")?.as_str()?)?;
        let label = object.get("label")?.as_str()?;
        let evm = HwAccounts::parse_list(object.get("evm")?, true)?;
        if !is_valid_label(label)
            || out.iter().any(|entry| entry.record_id == record_id)
            || evm.len() > MAX_EVM_ACCOUNTS
            || evm.first().is_some_and(|account| account.index != 0)
        {
            return None;
        }
        out.push(MnemonicEntry {
            record_id,
            label: label.to_owned(),
            evm,
        });
    }
    Some(out)
}

fn mnemonics_json(entries: &[MnemonicEntry]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                json_object(vec![
                    (
                        "record_id",
                        json_str(&yw_core::hex::encode(&entry.record_id)),
                    ),
                    ("label", json_str(&entry.label)),
                    (
                        "evm",
                        Value::Array(entry.evm.iter().map(account_json).collect()),
                    ),
                ])
            })
            .collect(),
    )
}

/// The optional top-level key of the Solana and Zcash accounts of added mnemonics (spec/02
/// §5.3, §8.6): `{"version": 1, "sol": [{"mnemonic": Hex16, "index", "label", "address",
/// "hidden"}], "sol_selected": null | {"mnemonic": Hex16, "index": u32}, "zec": {"mainnet"?:
/// {"mnemonic": Hex16, "a": u32, "b": u32, "pubkey": hex66}, "testnet"?: …}}`. Kept apart from
/// `sol_accounts`, `prefs`, `zcash` and `mnemonics` because earlier builds parse those strictly (an
/// extra member would make them reject the document or drop the entry). Written only when not
/// empty; strict (an invalid value rejects the document, like `hw_accounts`). Bitcoin accounts
/// of added mnemonics are `btc_accounts_mn` (spec/08 §12.3c).
pub const MNEMONIC_ACCOUNTS_KEY: &str = "mnemonic_accounts";
const MNEMONIC_ACCOUNTS_VERSION: u64 = 1;
const MN_ACCOUNTS_KEYS: [&str; 4] = ["version", "sol", "sol_selected", "zec"];
const MN_SOL_KEYS: [&str; 5] = ["mnemonic", "index", "label", "address", "hidden"];

/// meta `mnemonic_accounts` (Solana part; the Zcash part lives in `Meta::zcash` in memory).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MnemonicAccounts {
    /// Solana standard accounts `m/44'/501'/i'/0'` of added mnemonics: (mnemonic record id,
    /// account; `address` = base58 display cache), grouped by mnemonic, index ascending.
    pub sol: Vec<([u8; 16], Account)>,
    /// The selected Solana account is this one (after `hw_accounts.sol_selected`, before
    /// `sol_raw_selected` and `prefs.sol_account`).
    pub sol_selected: Option<([u8; 16], u32)>,
}

impl MnemonicAccounts {
    /// The Solana accounts of mnemonic `id`.
    pub fn sol_of(&self, id: [u8; 16]) -> impl Iterator<Item = &Account> {
        self.sol
            .iter()
            .filter(move |(mnemonic, _)| *mnemonic == id)
            .map(|(_, account)| account)
    }

    /// The next Solana index of mnemonic `id` (`None` at 100 accounts or index 999).
    #[must_use]
    pub fn next_sol_index(&self, id: [u8; 16]) -> Option<u32> {
        if self.sol_of(id).count() >= MAX_EVM_ACCOUNTS {
            return None;
        }
        let next = self
            .sol_of(id)
            .map(|account| account.index)
            .max()
            .map_or(Some(0), |max| max.checked_add(1))?;
        (u64::from(next) <= MAX_ACCOUNT_INDEX).then_some(next)
    }

    /// Adds (or replaces) account `account.index` of mnemonic `id`, keeping the order.
    pub fn upsert_sol(&mut self, id: [u8; 16], account: Account) {
        if let Some(slot) = self
            .sol
            .iter_mut()
            .find(|(mnemonic, known)| *mnemonic == id && known.index == account.index)
        {
            slot.1 = account;
        } else {
            self.sol.push((id, account));
        }
        let order: Vec<[u8; 16]> = self.sol.iter().fold(Vec::new(), |mut seen, (mnemonic, _)| {
            if !seen.contains(mnemonic) {
                seen.push(*mnemonic);
            }
            seen
        });
        self.sol.sort_by_key(|(mnemonic, known)| {
            (
                order.iter().position(|id| id == mnemonic).unwrap_or(0),
                known.index,
            )
        });
    }

    /// Drops every account of mnemonic `id` and a selection naming one.
    pub fn remove_mnemonic(&mut self, id: [u8; 16]) {
        self.sol.retain(|(mnemonic, _)| *mnemonic != id);
        if self
            .sol_selected
            .is_some_and(|(mnemonic, _)| mnemonic == id)
        {
            self.sol_selected = None;
        }
    }

    fn from_json(value: Option<&Value>, zcash: &mut crate::zec::meta::ZcashMeta) -> Option<Self> {
        let Some(value) = value else {
            return Some(Self::default());
        };
        let object = value.as_object()?;
        if !exact_keys(object, &MN_ACCOUNTS_KEYS)
            || u64_of(object.get("version")?)? != MNEMONIC_ACCOUNTS_VERSION
        {
            return None;
        }
        let mut out = Self::default();
        let list = object.get("sol")?.as_array()?;
        if list.len() > MAX_EVM_ACCOUNTS.saturating_mul(yw_core::vault::MAX_MNEMONICS) {
            return None;
        }
        for item in list {
            let entry = item.as_object()?;
            if !exact_keys(entry, &MN_SOL_KEYS) {
                return None;
            }
            let id = parse_hex16(entry.get("mnemonic")?.as_str()?)?;
            let account = parse_account(
                &json_object(vec![
                    ("index", entry.get("index")?.clone()),
                    ("label", entry.get("label")?.clone()),
                    ("address", entry.get("address")?.clone()),
                    ("hidden", entry.get("hidden")?.clone()),
                ]),
                false,
            )?;
            if id == [0; 16]
                || out
                    .sol
                    .iter()
                    .any(|(known, other)| *known == id && other.index == account.index)
            {
                return None;
            }
            out.sol.push((id, account));
        }
        out.sol_selected = match object.get("sol_selected")? {
            Value::Null => None,
            other => {
                let selected = other.as_object()?;
                if !exact_keys(selected, &["mnemonic", "index"]) {
                    return None;
                }
                let id = parse_hex16(selected.get("mnemonic")?.as_str()?)?;
                let index = u32::try_from(u64_of(selected.get("index")?)?).ok()?;
                out.sol
                    .iter()
                    .any(|(known, account)| *known == id && account.index == index)
                    .then_some((id, index))
            }
        };
        if !zcash.read_mnemonic_accounts(object.get("zec")?) {
            return None;
        }
        Some(out)
    }

    fn to_json(&self, zcash: &crate::zec::meta::ZcashMeta) -> Option<Value> {
        let zec = zcash.mnemonic_accounts_json();
        if self.sol.is_empty() && self.sol_selected.is_none() && zec.is_none() {
            return None;
        }
        Some(json_object(vec![
            ("version", json_u64(MNEMONIC_ACCOUNTS_VERSION)),
            (
                "sol",
                Value::Array(
                    self.sol
                        .iter()
                        .map(|(id, account)| {
                            json_object(vec![
                                ("mnemonic", json_str(&yw_core::hex::encode(id))),
                                ("index", json_u64(u64::from(account.index))),
                                ("label", json_str(&account.label)),
                                ("address", json_str(&account.address)),
                                ("hidden", Value::Bool(account.hidden)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "sol_selected",
                self.sol_selected.map_or(Value::Null, |(id, index)| {
                    json_object(vec![
                        ("mnemonic", json_str(&yw_core::hex::encode(&id))),
                        ("index", json_u64(u64::from(index))),
                    ])
                }),
            ),
            ("zec", zec.unwrap_or_else(|| json_object(Vec::new()))),
        ]))
    }
}

/// meta `hw_accounts` (spec/10 §8, §13).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HwAccounts {
    /// `YubiKey` EVM accounts: `index` = EVM account `i` (`m/44'/60'/0'/0/i`), `address` = display
    /// cache of the slot-map public key (index ascending).
    pub evm: Vec<Account>,
    /// `YubiKey` Solana accounts (`m/44'/501'/i'/0'` on a PIV slot; base58 cache).
    pub sol: Vec<Account>,
    /// The selected Solana account is this `YubiKey` account (before `sol_raw_selected` and
    /// `prefs.sol_account`).
    pub sol_selected: Option<u32>,
    /// Serials of the cards whose PIN, admin PIN or management key was still the default at
    /// enrolment (the "기본 PIN 사용 중" warning, spec/10 §9.3), ascending.
    pub defaults: Vec<u32>,
}

impl HwAccounts {
    fn parse_list(value: &Value, evm: bool) -> Option<Vec<Account>> {
        let list: Vec<Account> = value
            .as_array()?
            .iter()
            .map(|item| parse_account(item, evm))
            .collect::<Option<_>>()?;
        let ascending = list
            .windows(2)
            .all(|pair| pair.first().map(|a| a.index) < pair.get(1).map(|b| b.index));
        (list.len() <= MAX_HW_ACCOUNTS
            && ascending
            && list.iter().all(|account| !account.address.is_empty()))
        .then_some(list)
    }

    /// Strict decoding (absent = the default).
    fn from_json(value: Option<&Value>) -> Option<Self> {
        let Some(value) = value else {
            return Some(Self::default());
        };
        let object = value.as_object()?;
        if !exact_keys(object, &HW_KEYS) {
            return None;
        }
        let evm = Self::parse_list(object.get("evm")?, true)?;
        let sol = Self::parse_list(object.get("sol")?, false)?;
        let sol_selected = match object.get("sol_selected")? {
            Value::Null => None,
            other => {
                let index = u32::try_from(u64_of(other)?).ok()?;
                sol.iter()
                    .any(|account| account.index == index)
                    .then_some(index)?;
                Some(index)
            }
        };
        let defaults: Vec<u32> = object
            .get("defaults")?
            .as_array()?
            .iter()
            .map(|item| u32::try_from(u64_of(item)?).ok())
            .collect::<Option<_>>()?;
        let ascending = defaults.windows(2).all(|pair| pair.first() < pair.get(1));
        (defaults.len() <= MAX_HW_DEFAULTS && ascending).then_some(Self {
            evm,
            sol,
            sol_selected,
            defaults,
        })
    }

    fn to_json(&self) -> Value {
        json_object(vec![
            (
                "evm",
                Value::Array(self.evm.iter().map(account_json).collect()),
            ),
            (
                "sol",
                Value::Array(self.sol.iter().map(account_json).collect()),
            ),
            (
                "sol_selected",
                self.sol_selected
                    .map_or(Value::Null, |index| json_u64(u64::from(index))),
            ),
            (
                "defaults",
                Value::Array(
                    self.defaults
                        .iter()
                        .map(|serial| json_u64(u64::from(*serial)))
                        .collect(),
                ),
            ),
        ])
    }

    /// Nothing to store (the key is then not written).
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// meta `security_settings` and `vault_generation_seen` (review M1/L15/L17).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetaSecurity {
    /// The security settings snapshot (`None` until the first check after an unlock creates it).
    pub snapshot: Option<crate::settings::SecuritySnapshot>,
    /// The highest `vault.ywv` generation seen (0 = none recorded).
    pub vault_generation_seen: u64,
    /// `journal_reset_at`: Unix seconds of the last journal reset (0 = none recorded).
    pub journal_reset_at: u64,
}

/// meta `sol_sites` and `btc_sites` as validated JSON values (spec/05 §4.9).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainSites {
    /// `sol_sites`.
    pub sol: Vec<Value>,
    /// `btc_sites`.
    pub btc: Vec<Value>,
    /// `walletconnect` (optional key, spec/13 §8): the relay client key and the `WalletConnect`
    /// sessions, validated by `crate::walletconnect::store`; written only when present.
    pub walletconnect: Option<Value>,
}

const LIMITS: Limits = Limits {
    max_bytes: META_MAX_BYTES,
    max_depth: 16,
    max_nodes: 1_000_000,
    max_items: 1_000_000,
};

/// A derived account (`Account`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// Index `i` of `m/44'/60'/0'/0/i`.
    pub index: u32,
    /// Label.
    pub label: String,
    /// Display cache: `0x` + 40 lowercase hex.
    pub address: String,
    /// Hidden from the list.
    pub hidden: bool,
}

/// Default label prefix of an imported EVM key (`가져온 계정 N`).
pub const EVM_IMPORTED_PREFIX: &str = "가져온 계정 ";
/// Default label prefix of an imported Solana key (`가져온 Solana N`).
pub const SOL_IMPORTED_PREFIX: &str = "가져온 Solana ";

/// The default label for the next imported key: `prefix` + one more than the highest number
/// among the existing default labels (`len + 1` repeated a number after a removal).
#[must_use]
pub fn next_imported_label<'a>(prefix: &str, labels: impl IntoIterator<Item = &'a str>) -> String {
    let highest = labels
        .into_iter()
        .filter_map(|label| label.strip_prefix(prefix)?.parse::<usize>().ok())
        .max()
        .unwrap_or(0);
    format!("{prefix}{}", highest.saturating_add(1))
}

/// An imported raw EVM key (`RawAccount`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawAccount {
    /// Vault record id.
    pub record_id: [u8; 16],
    /// Label.
    pub label: String,
    /// `0x` + 40 lowercase hex.
    pub address: String,
}

/// An imported Solana key (`SolRawAccount`, vault `tag 3`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolRawAccount {
    /// Vault record id.
    pub record_id: [u8; 16],
    /// Label.
    pub label: String,
    /// Canonical base58 address (= public key).
    pub address: String,
}

/// Selected EVM account preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmAccountPref {
    /// Derived account index.
    Index(u32),
    /// Raw key record.
    Record([u8; 16]),
    /// `YubiKey` EVM account `i` (`EvmKeySource::Hardware`, meta `hw_accounts.evm`; prefs
    /// `{"hardware": i}` — an older version resets such prefs to the default).
    Hardware(u32),
    /// EVM account `i` of the added mnemonic `record_id` (`EvmKeySource::Mnemonic`, meta
    /// `mnemonics`; prefs `{"mnemonic": Hex16, "index": i}`).
    Mnemonic([u8; 16], u32),
}

/// The main-window chain tab (spec/04 §6.4 `tab`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tab {
    /// `"evm"`.
    #[default]
    Evm,
    /// `"sol"` (M7).
    Sol,
    /// `"btc"` (M8).
    Btc,
    /// `"zec"` (spec/12; earlier versions reset `prefs` to the default when they read it).
    Zec,
}

impl Tab {
    /// The meta string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Sol => "sol",
            Self::Btc => "btc",
            Self::Zec => "zec",
        }
    }
}

/// `prefs` (spec/04 §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefs {
    /// Selected EVM account.
    pub evm_account: EvmAccountPref,
    /// Selected Solana account index.
    pub sol_account: u32,
    /// Chain tab.
    pub tab: Tab,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            evm_account: EvmAccountPref::Index(0),
            sol_account: 0,
            tab: Tab::Evm,
        }
    }
}

/// The meta document. Sections without a typed model (address book, sites, tokens, activity) are
/// kept as validated JSON values so they round-trip unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    /// Derived EVM accounts (index ascending, index 0 present; empty in a key-only wallet).
    pub evm_accounts: Vec<Account>,
    /// Imported raw keys.
    pub evm_raw_accounts: Vec<RawAccount>,
    /// Imported Solana keys (0..=15).
    pub sol_raw_accounts: Vec<SolRawAccount>,
    /// The selected Solana account is this imported key (`None`: the derived `prefs.sol_account`).
    pub sol_raw_selected: Option<[u8; 16]>,
    /// Solana standard accounts `m/44'/501'/i'/0'` (M7; `address` = base58 display cache).
    pub sol_accounts: Vec<Account>,
    /// `btc` (M8, spec/08 §12.3), `None` = `null` (BTC never enabled, or reset): the BIP84
    /// account 0.
    pub btc: Option<Box<BtcMeta>>,
    /// `btc_accounts` (spec/08 §12.3a): the other BTC accounts (address types, account numbers,
    /// imported keys: one single-key account per vault tag-4 record) and the selected one. An optional top-level key: absent in files of
    /// earlier versions (= no other accounts), which keep it unread when they write.
    pub btc_accounts: BtcAccounts,
    /// Address book (validated `AddressBookEntry` values; EVM entries use `chain = "evm"` and
    /// are shared by every EVM chain).
    pub address_book: Vec<Value>,
    /// `address_book_favorites` (optional key): the starred entries, in starring order.
    pub book_favorites: Vec<(BookChain, String)>,
    /// Connected sites (M5).
    pub connected_sites: Vec<Value>,
    /// Solana and Bitcoin dApp grants (`sol_sites`/`btc_sites`, optional keys; boxed to keep
    /// the document small in key-worker messages).
    pub chain_sites: Box<ChainSites>,
    /// Tokens per network.
    pub tokens: Vec<(String, Vec<Value>)>,
    /// Activity per network.
    pub activity: Vec<(String, Vec<Value>)>,
    /// Preferences.
    pub prefs: Prefs,
    /// `security_settings` and `vault_generation_seen` (boxed to keep the document small in
    /// key-worker messages).
    pub security: Box<MetaSecurity>,
    /// `token_view` (optional key, 2026-11-03): hidden token rows and `잔액 0인 토큰 숨기기`
    /// (display only, `crate::token_view`).
    pub token_view: Box<TokenView>,
    /// `hw_accounts` (optional key, spec/10 §13): the `YubiKey` accounts' labels, hidden flags and
    /// selection (vault tag 5 is the truth source).
    pub hw_accounts: HwAccounts,
    /// `mnemonics` (optional key, 2026-11-07): the recovery phrases' labels and the added
    /// mnemonics' EVM accounts (vault `Bip39` records are the truth source).
    pub mnemonics: Vec<MnemonicEntry>,
    /// `zcash` (optional key, spec/12 §12.3): the Zcash account of each network (an account on
    /// an added mnemonic's key is written to `mnemonic_accounts.zec` instead).
    pub zcash: Box<crate::zec::meta::ZcashMeta>,
    /// `mnemonic_accounts` (optional key, 2026-11-08): the Solana accounts of added mnemonics
    /// and their selection.
    pub mnemonic_accounts: Box<MnemonicAccounts>,
    /// Top-level keys this version does not know (a newer minor version's), in file order; written
    /// back after the known keys while the plaintext stays within 8 MiB (spec/04 §6.6).
    pub unknown: Vec<(String, Value)>,
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            evm_accounts: vec![Account {
                index: 0,
                label: "계정 1".to_owned(),
                address: String::new(),
                hidden: false,
            }],
            evm_raw_accounts: Vec::new(),
            sol_raw_accounts: Vec::new(),
            sol_raw_selected: None,
            sol_accounts: Vec::new(),
            btc: None,
            btc_accounts: BtcAccounts::default(),
            address_book: Vec::new(),
            book_favorites: Vec::new(),
            connected_sites: Vec::new(),
            chain_sites: Box::default(),
            tokens: Vec::new(),
            activity: Vec::new(),
            prefs: Prefs::default(),
            security: Box::default(),
            token_view: Box::default(),
            hw_accounts: HwAccounts::default(),
            mnemonics: Vec::new(),
            zcash: Box::default(),
            mnemonic_accounts: Box::default(),
            unknown: Vec::new(),
        }
    }
}

impl Meta {
    /// The default meta of a key-only wallet (no derived accounts, spec/02 §5.3).
    #[must_use]
    pub fn key_only() -> Self {
        Self {
            evm_accounts: Vec::new(),
            ..Self::default()
        }
    }
}

/// The meta document is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetaError;

/// Result of parsing: the document and whether `prefs` fell back to the default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaParse {
    /// Document.
    pub meta: Meta,
    /// `prefs` or `token_view` was invalid and reset to its default (logged).
    pub prefs_reset: bool,
}

/// `0x` + 40 lowercase hex.
#[must_use]
pub fn is_evm_addr(text: &str) -> bool {
    text.strip_prefix("0x").is_some_and(|digits| {
        digits.len() == 40
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn parse_hex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    yw_core::hex::decode_array::<16>(text).ok()
}

fn u64_of(value: &Value) -> Option<u64> {
    value.as_number().and_then(Number::as_u64)
}

fn exact_keys(object: &Object, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.get(key).is_some())
}

/// A canonical base58 Solana address (strict 32-byte decoder, spec/07 §5).
#[must_use]
pub fn is_sol_addr(text: &str) -> bool {
    yw_core::sol::SolAddress::parse(text).is_ok()
}

fn parse_account(value: &Value, evm: bool) -> Option<Account> {
    let object = value.as_object()?;
    if !exact_keys(object, &["index", "label", "address", "hidden"]) {
        return None;
    }
    let index = u64_of(object.get("index")?)?;
    if index > MAX_ACCOUNT_INDEX {
        return None;
    }
    let label = object.get("label")?.as_str()?;
    let address = object.get("address")?.as_str()?;
    let address_ok = if evm {
        address.is_empty() || is_evm_addr(address)
    } else {
        address.is_empty() || is_sol_addr(address)
    };
    if !is_valid_label(label) || !address_ok {
        return None;
    }
    Some(Account {
        index: u32::try_from(index).ok()?,
        label: label.to_owned(),
        address: address.to_owned(),
        hidden: object.get("hidden")?.as_bool()?,
    })
}

fn parse_raw(value: &Value) -> Option<RawAccount> {
    let object = value.as_object()?;
    if !exact_keys(object, &["record_id", "label", "address"]) {
        return None;
    }
    let label = object.get("label")?.as_str()?;
    let address = object.get("address")?.as_str()?;
    if !is_valid_label(label) || !is_evm_addr(address) {
        return None;
    }
    Some(RawAccount {
        record_id: parse_hex16(object.get("record_id")?.as_str()?)?,
        label: label.to_owned(),
        address: address.to_owned(),
    })
}

fn parse_sol_raw(value: &Value) -> Option<SolRawAccount> {
    let object = value.as_object()?;
    if !exact_keys(object, &["record_id", "label", "address"]) {
        return None;
    }
    let label = object.get("label")?.as_str()?;
    let address = object.get("address")?.as_str()?;
    if !is_valid_label(label) || !is_sol_addr(address) {
        return None;
    }
    Some(SolRawAccount {
        record_id: parse_hex16(object.get("record_id")?.as_str()?)?,
        label: label.to_owned(),
        address: address.to_owned(),
    })
}

/// The optional imported-key keys (absent in files written before key import).
type RawLists = (Vec<SolRawAccount>, Option<[u8; 16]>);

fn parse_raw_lists(object: &Object) -> Option<RawLists> {
    let sol = match object.get("sol_raw_accounts") {
        None => Vec::new(),
        Some(value) => value
            .as_array()?
            .iter()
            .map(parse_sol_raw)
            .collect::<Option<Vec<_>>>()?,
    };
    let selected = match object.get("sol_raw_selected") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_hex16(value.as_str()?)?),
    };
    let ids_unique = |ids: Vec<[u8; 16]>| {
        ids.iter().enumerate().all(|(at, id)| {
            !ids.iter()
                .skip(at.saturating_add(1))
                .any(|other| other == id)
        })
    };
    let valid = sol.len() <= MAX_RAW_ACCOUNTS
        && ids_unique(sol.iter().map(|raw| raw.record_id).collect())
        && selected.is_none_or(|id| sol.iter().any(|raw| raw.record_id == id));
    valid.then_some((sol, selected))
}

fn valid_book_entry(value: &Value) -> bool {
    let check = || -> Option<()> {
        let object = value.as_object()?;
        exact_keys(
            object,
            &["chain", "address", "label", "verified", "added_at_unix_ms"],
        )
        .then_some(())?;
        let chain = object.get("chain")?.as_str()?;
        // `eip155:<chainId>` is read as a legacy alias of `evm` and folded into it on load
        // ([`migrate_book`]); it is never written.
        let chain = if legacy_evm_chain(chain) {
            "evm"
        } else {
            chain
        };
        matches!(chain, "evm" | "sol" | "btc").then_some(())?;
        let address = object.get("address")?.as_str()?;
        (chain != "evm" || is_evm_addr(address)).then_some(())?;
        (chain != "sol" || is_sol_addr(address)).then_some(())?;
        (!address.is_empty() && address.len() <= 128).then_some(())?;
        is_valid_label(object.get("label")?.as_str()?).then_some(())?;
        object.get("verified")?.as_bool()?;
        u64_of(object.get("added_at_unix_ms")?)?;
        Some(())
    };
    check().is_some()
}

/// A per-chain EVM `chain` value (`eip155:` + strict decimal chain id).
fn legacy_evm_chain(chain: &str) -> bool {
    chain
        .strip_prefix("eip155:")
        .and_then(crate::network::parse_decimal_u64)
        .is_some()
}

/// Folds the address book into one entry per `(family, address)` (2026-11-06): a legacy
/// per-chain EVM entry (`eip155:<id>`) becomes `chain = "evm"`, shared by every EVM chain, and
/// duplicates merge into the first one, which keeps its label and position, becomes verified
/// when any duplicate was, and keeps the earliest `added_at_unix_ms`. Returns whether anything
/// changed. Releases of `yw-meta/3` only ever wrote `evm`/`sol`/`btc`, so for their files this
/// only removes duplicates (which `add_*` never creates).
fn migrate_book(entries: &mut Vec<Value>) -> bool {
    let mut merged: Vec<Contact> = Vec::with_capacity(entries.len());
    let mut changed = false;
    for value in entries.iter() {
        let Some(object) = value.as_object() else {
            continue;
        };
        let raw_chain = object.get("chain").and_then(Value::as_str).unwrap_or("");
        let Some(chain) = BookChain::parse(raw_chain)
            .or_else(|| legacy_evm_chain(raw_chain).then_some(BookChain::Evm))
        else {
            continue;
        };
        changed |= raw_chain != chain.as_str();
        let (Some(address), Some(label), Some(verified), Some(added)) = (
            object.get("address").and_then(Value::as_str),
            object.get("label").and_then(Value::as_str),
            object.get("verified").and_then(Value::as_bool),
            object.get("added_at_unix_ms").and_then(u64_of),
        ) else {
            continue;
        };
        if let Some(first) = merged
            .iter_mut()
            .find(|known| known.chain == chain && known.address == address)
        {
            first.verified |= verified;
            first.added_at_unix_ms = first.added_at_unix_ms.min(added);
            changed = true;
            continue;
        }
        merged.push(Contact {
            chain,
            address: address.to_owned(),
            label: label.to_owned(),
            verified,
            added_at_unix_ms: added,
        });
    }
    if changed {
        *entries = merged.iter().map(Contact::to_value).collect();
    }
    changed
}

/// `address_book_favorites` of the file: `None` when the value is invalid (the caller falls
/// back to no favorites). Duplicates and names of entries the book does not hold are dropped.
fn parse_favorites(value: &Value, book: &[Value]) -> Option<Vec<(BookChain, String)>> {
    let items = value.as_array()?;
    if items.len() > MAX_ADDRESS_BOOK {
        return None;
    }
    let held: Vec<Contact> = book.iter().filter_map(Contact::from_value).collect();
    let mut out: Vec<(BookChain, String)> = Vec::new();
    for item in items {
        let object = item.as_object()?;
        exact_keys(object, &["chain", "address"]).then_some(())?;
        let chain = BookChain::parse(object.get("chain")?.as_str()?)?;
        let address = object.get("address")?.as_str()?;
        let in_book = held
            .iter()
            .any(|entry| entry.chain == chain && entry.address == address);
        if in_book && !out.iter().any(|(c, a)| *c == chain && a == address) {
            out.push((chain, address.to_owned()));
        }
    }
    Some(out)
}

fn valid_site(value: &Value) -> bool {
    let check = || -> Option<()> {
        let object = value.as_object()?;
        exact_keys(
            object,
            &["origin", "accounts", "chain_id", "granted_at_unix_ms"],
        )
        .then_some(())?;
        let origin = object.get("origin")?.as_str()?;
        (!origin.is_empty() && origin.len() <= 256 && origin.is_ascii()).then_some(())?;
        let accounts = object.get("accounts")?.as_array()?;
        ((1..=16).contains(&accounts.len())
            && accounts
                .iter()
                .all(|account| account.as_str().is_some_and(is_evm_addr)))
        .then_some(())?;
        (u64_of(object.get("chain_id")?)? >= 1).then_some(())?;
        u64_of(object.get("granted_at_unix_ms")?)?;
        Some(())
    };
    check().is_some()
}

fn valid_token(value: &Value) -> bool {
    let check = || -> Option<()> {
        let object = value.as_object()?;
        exact_keys(object, &["address", "label", "decimals"]).then_some(())?;
        is_evm_addr(object.get("address")?.as_str()?).then_some(())?;
        is_valid_label(object.get("label")?.as_str()?).then_some(())?;
        (u64_of(object.get("decimals")?)? <= 36).then_some(())?;
        Some(())
    };
    check().is_some()
}

fn valid_activity(value: &Value) -> bool {
    let check = || -> Option<()> {
        let object = value.as_object()?;
        exact_keys(
            object,
            &[
                "account",
                "tx_id",
                "title",
                "asset",
                "amount",
                "counterparty",
                "status",
                "time_unix_ms",
            ],
        )
        .then_some(())?;
        for key in ["account", "tx_id", "asset", "counterparty"] {
            (object.get(key)?.as_str()?.len() <= 128).then_some(())?;
        }
        (object.get("title")?.as_str()?.len() <= 256).then_some(())?;
        let amount = object.get("amount")?.as_str()?;
        (!amount.is_empty()
            && amount.len() <= 78
            && amount.bytes().all(|byte| byte.is_ascii_digit()))
        .then_some(())?;
        matches!(
            object.get("status")?.as_str()?,
            "succeeded"
                | "failed"
                | "dropped"
                | "replaced"
                | "expired"
                | "rejected"
                | "conflicted"
                | "abandoned"
        )
        .then_some(())?;
        u64_of(object.get("time_unix_ms")?)?;
        Some(())
    };
    check().is_some()
}

fn parse_network_map(
    value: &Value,
    per_network: usize,
    total: usize,
    evm_only: bool,
    valid: fn(&Value) -> bool,
) -> Option<Vec<(String, Vec<Value>)>> {
    let object = value.as_object()?;
    let mut out = Vec::new();
    let mut count = 0_usize;
    for (key, items) in object.iter() {
        let network = NetworkId::parse(key)?;
        if evm_only && !matches!(network, NetworkId::Eip155(_)) {
            return None;
        }
        let items = items.as_array()?;
        if items.is_empty() || items.len() > per_network || !items.iter().all(valid) {
            return None;
        }
        count = count.checked_add(items.len())?;
        out.push((key.to_owned(), items.to_vec()));
    }
    (count <= total).then_some(out)
}

fn parse_prefs(value: &Value, meta: &Meta) -> Option<Prefs> {
    let object = value.as_object()?;
    let mut prefs = Prefs::default();
    for (key, entry) in object.iter() {
        match key {
            "evm_account" => {
                let selector = entry.as_object()?;
                if let Some(id) = selector.get("mnemonic") {
                    let id = parse_hex16(id.as_str()?)?;
                    let index = u32::try_from(u64_of(selector.get("index")?)?).ok()?;
                    (selector.len() == 2
                        && meta.mnemonics.iter().any(|entry| {
                            entry.record_id == id
                                && entry.evm.iter().any(|account| account.index == index)
                        }))
                    .then_some(())?;
                    prefs.evm_account = EvmAccountPref::Mnemonic(id, index);
                    continue;
                }
                if selector.len() != 1 {
                    return None;
                }
                prefs.evm_account = if let Some(index) = selector.get("index") {
                    let index = u32::try_from(u64_of(index)?).ok()?;
                    // A key-only wallet has no derived account: the default `{"index": 0}` then
                    // means "the first imported account".
                    (meta.evm_accounts.is_empty()
                        || meta
                            .evm_accounts
                            .iter()
                            .any(|account| account.index == index))
                    .then_some(EvmAccountPref::Index(index))?
                } else if let Some(index) = selector.get("hardware") {
                    let index = u32::try_from(u64_of(index)?).ok()?;
                    meta.hw_accounts
                        .evm
                        .iter()
                        .any(|account| account.index == index)
                        .then_some(EvmAccountPref::Hardware(index))?
                } else {
                    let id = parse_hex16(selector.get("record_id")?.as_str()?)?;
                    meta.evm_raw_accounts
                        .iter()
                        .any(|account| account.record_id == id)
                        .then_some(EvmAccountPref::Record(id))?
                };
            }
            "sol_account" => {
                let index = u32::try_from(u64_of(entry)?).ok()?;
                (meta.sol_accounts.is_empty()
                    || meta
                        .sol_accounts
                        .iter()
                        .any(|account| account.index == index))
                .then_some(())?;
                prefs.sol_account = index;
            }
            "tab" => {
                prefs.tab = match entry.as_str()? {
                    "evm" => Tab::Evm,
                    "sol" => Tab::Sol,
                    "btc" => Tab::Btc,
                    "zec" => Tab::Zec,
                    _ => return None,
                };
            }
            _ => return None,
        }
    }
    Some(prefs)
}

/// Parses the meta plaintext.
///
/// # Errors
///
/// [`MetaError`] for any schema violation (outside `prefs`). Unknown top-level keys are not a
/// violation: they are kept in [`Meta::unknown`] (spec/04 §6.6).
#[expect(
    clippy::too_many_lines,
    reason = "every top-level key of spec/02 §5.3 in order"
)]
pub fn parse(bytes: &[u8]) -> Result<MetaParse, MetaError> {
    let root = yw_json::parse(bytes, &LIMITS).map_err(|_| MetaError)?;
    let object = root.as_object().ok_or(MetaError)?;
    if !KEYS.iter().all(|key| object.get(key).is_some())
        || object.get("schema").and_then(Value::as_str) != Some(META_SCHEMA)
    {
        return Err(MetaError);
    }
    let unknown: Vec<(String, Value)> = object
        .iter()
        .filter(|(key, _)| {
            !KEYS.contains(key)
                && !OPTIONAL_KEYS.contains(key)
                && *key != BTC_ACCOUNTS_KEY
                && *key != BTC_ACCOUNTS_EXT_KEY
                && *key != yw_core::btc::meta::BTC_ACCOUNTS_MN_KEY
                && *key != MNEMONIC_ACCOUNTS_KEY
                && *key != SOL_SITES_KEY
                && *key != BTC_SITES_KEY
                && *key != SECURITY_KEY
                && *key != VAULT_SEEN_KEY
                && *key != JOURNAL_RESET_KEY
                && *key != TOKEN_VIEW_KEY
                && *key != HW_ACCOUNTS_KEY
                && *key != MNEMONICS_KEY
                && *key != crate::walletconnect::store::META_KEY
                && *key != crate::zec::meta::ZCASH_KEY
                && *key != BOOK_FAVORITES_KEY
        })
        .map(|(key, value)| (key.to_owned(), value.clone()))
        .collect();
    let get = |key: &str| object.get(key).ok_or(MetaError);
    let array = |key: &str| get(key)?.as_array().ok_or(MetaError);
    let evm_accounts: Vec<Account> = array("evm_accounts")?
        .iter()
        .map(|value| parse_account(value, true))
        .collect::<Option<_>>()
        .ok_or(MetaError)?;
    // Empty only in a key-only wallet (spec/02 §5.3); otherwise index 0 comes first.
    if evm_accounts.len() > MAX_EVM_ACCOUNTS
        || evm_accounts
            .first()
            .is_some_and(|account| account.index != 0)
        || evm_accounts
            .windows(2)
            .any(|pair| pair.first().map(|a| a.index) >= pair.get(1).map(|b| b.index))
    {
        return Err(MetaError);
    }
    let evm_raw_accounts: Vec<RawAccount> = array("evm_raw_accounts")?
        .iter()
        .map(parse_raw)
        .collect::<Option<_>>()
        .ok_or(MetaError)?;
    if evm_raw_accounts.len() > MAX_RAW_ACCOUNTS {
        return Err(MetaError);
    }
    let sol_accounts: Vec<Account> = array("sol_accounts")?
        .iter()
        .map(|value| parse_account(value, false))
        .collect::<Option<_>>()
        .ok_or(MetaError)?;
    if sol_accounts.len() > MAX_EVM_ACCOUNTS
        || sol_accounts
            .windows(2)
            .any(|pair| pair.first().map(|a| a.index) >= pair.get(1).map(|b| b.index))
    {
        return Err(MetaError);
    }
    // Strict BtcMeta decoding: any violation rejects the document like other keys (spec/02 §5.3).
    // spec/08 §12.3b: also the placement of the 2026-11-05/06 builds (migrated on load).
    let (btc, btc_accounts) = btc_meta_from_values(
        get("btc")?,
        object.get(BTC_ACCOUNTS_KEY),
        object.get(BTC_ACCOUNTS_EXT_KEY),
        object.get(yw_core::btc::meta::BTC_ACCOUNTS_MN_KEY),
    )
    .map_err(|_| MetaError)?;
    let btc = btc.map(Box::new);
    let mut address_book = array("address_book")?.to_vec();
    if address_book.len() > MAX_ADDRESS_BOOK || !address_book.iter().all(valid_book_entry) {
        return Err(MetaError);
    }
    // Written back at the next meta save (the in-memory book is already migrated).
    let _ = migrate_book(&mut address_book);
    let book_favorites = object
        .get(BOOK_FAVORITES_KEY)
        .and_then(|value| parse_favorites(value, &address_book))
        .unwrap_or_default();
    let connected_sites = array("connected_sites")?.to_vec();
    if connected_sites.len() > MAX_SITES || !connected_sites.iter().all(valid_site) {
        return Err(MetaError);
    }
    let chain_sites = |key: &str| -> Result<Vec<Value>, MetaError> {
        match object.get(key) {
            None => Ok(Vec::new()),
            Some(value) => {
                let items = value.as_array().ok_or(MetaError)?;
                if items.len() > MAX_SITES || !items.iter().all(|item| item.as_object().is_some()) {
                    return Err(MetaError);
                }
                Ok(items.to_vec())
            }
        }
    };
    let sol_sites = chain_sites(SOL_SITES_KEY)?;
    let btc_sites = chain_sites(BTC_SITES_KEY)?;
    let tokens = parse_network_map(
        get("tokens")?,
        MAX_TOKENS_PER_NETWORK,
        MAX_TOKENS_TOTAL,
        true,
        valid_token,
    )
    .ok_or(MetaError)?;
    let activity = parse_network_map(
        get("activity")?,
        MAX_ACTIVITY_PER_NETWORK,
        MAX_ACTIVITY_TOTAL,
        false,
        valid_activity,
    )
    .ok_or(MetaError)?;
    let (sol_raw_accounts, sol_raw_selected) = parse_raw_lists(object).ok_or(MetaError)?;
    let snapshot = match object.get(SECURITY_KEY) {
        None => None,
        Some(value) => Some(crate::settings::SecuritySnapshot::from_json(value).ok_or(MetaError)?),
    };
    let vault_generation_seen = match object.get(VAULT_SEEN_KEY) {
        None => 0,
        Some(value) => u64_of(value).ok_or(MetaError)?,
    };
    let journal_reset_at = match object.get(JOURNAL_RESET_KEY) {
        None => 0,
        Some(value) => u64_of(value).ok_or(MetaError)?,
    };
    // A view preference: an invalid value falls back to the default like `prefs`.
    let (token_view, token_view_reset) = match object.get(TOKEN_VIEW_KEY) {
        None => (TokenView::default(), false),
        Some(value) => {
            TokenView::from_json(value).map_or((TokenView::default(), true), |view| (view, false))
        }
    };
    let hw_accounts = HwAccounts::from_json(object.get(HW_ACCOUNTS_KEY)).ok_or(MetaError)?;
    let mnemonics = parse_mnemonics(object.get(MNEMONICS_KEY)).ok_or(MetaError)?;
    let mut zcash = crate::zec::meta::ZcashMeta::from_json(object.get(crate::zec::meta::ZCASH_KEY));
    let mnemonic_accounts =
        MnemonicAccounts::from_json(object.get(MNEMONIC_ACCOUNTS_KEY), &mut zcash)
            .ok_or(MetaError)?;
    let mut meta = Meta {
        evm_accounts,
        evm_raw_accounts,
        sol_raw_accounts,
        sol_raw_selected,
        sol_accounts,
        btc,
        btc_accounts,
        address_book,
        book_favorites,
        connected_sites,
        chain_sites: Box::new(ChainSites {
            sol: sol_sites,
            btc: btc_sites,
            walletconnect: object.get(crate::walletconnect::store::META_KEY).cloned(),
        }),
        tokens,
        activity,
        prefs: Prefs::default(),
        security: Box::new(MetaSecurity {
            snapshot,
            vault_generation_seen,
            journal_reset_at,
        }),
        token_view: Box::new(token_view),
        hw_accounts,
        mnemonics,
        zcash: Box::new(zcash),
        mnemonic_accounts: Box::new(mnemonic_accounts),
        unknown,
    };
    let prefs = parse_prefs(get("prefs")?, &meta);
    let prefs_reset = prefs.is_none() || token_view_reset;
    meta.prefs = prefs.unwrap_or_default();
    Ok(MetaParse { meta, prefs_reset })
}

fn account_json(account: &Account) -> Value {
    json_object(vec![
        ("index", json_u64(u64::from(account.index))),
        ("label", json_str(&account.label)),
        ("address", json_str(&account.address)),
        ("hidden", Value::Bool(account.hidden)),
    ])
}

fn network_map_json(map: &[(String, Vec<Value>)]) -> Value {
    json_object_owned(
        map.iter()
            .map(|(key, items)| (key.clone(), Value::Array(items.clone())))
            .collect(),
    )
    .unwrap_or_else(|| json_object(Vec::new()))
}

impl Meta {
    /// Serializes in the spec/02 §5.3 key order, followed by the unknown top-level keys kept from
    /// the file (spec/04 §6.6) while the plaintext stays within 8 MiB.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        crate::settings::serialize_with_unknown(
            &|| self.known_members(),
            &self.unknown,
            META_MAX_BYTES,
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "every key of spec/02 §5.3 in write order"
    )]
    fn known_members(&self) -> Vec<(&'static str, Value)> {
        let evm_account = match self.prefs.evm_account {
            EvmAccountPref::Index(index) => {
                json_object(vec![("index", json_u64(u64::from(index)))])
            }
            EvmAccountPref::Record(id) => {
                json_object(vec![("record_id", json_str(&yw_core::hex::encode(&id)))])
            }
            EvmAccountPref::Hardware(index) => {
                json_object(vec![("hardware", json_u64(u64::from(index)))])
            }
            EvmAccountPref::Mnemonic(id, index) => json_object(vec![
                ("mnemonic", json_str(&yw_core::hex::encode(&id))),
                ("index", json_u64(u64::from(index))),
            ]),
        };
        // spec/08 §12.3b: `btc`/`btc_accounts` hold only what earlier builds decode.
        let btc_values = btc_meta_values(self.btc.as_deref(), &self.btc_accounts);
        let mut members = vec![
            ("schema", json_str(META_SCHEMA)),
            (
                "evm_accounts",
                Value::Array(self.evm_accounts.iter().map(account_json).collect()),
            ),
            (
                "evm_raw_accounts",
                Value::Array(
                    self.evm_raw_accounts
                        .iter()
                        .map(|raw| {
                            json_object(vec![
                                ("record_id", json_str(&yw_core::hex::encode(&raw.record_id))),
                                ("label", json_str(&raw.label)),
                                ("address", json_str(&raw.address)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "sol_accounts",
                Value::Array(self.sol_accounts.iter().map(account_json).collect()),
            ),
            ("btc", btc_values.btc),
            ("address_book", Value::Array(self.address_book.clone())),
            (
                "connected_sites",
                Value::Array(self.connected_sites.clone()),
            ),
            ("tokens", network_map_json(&self.tokens)),
            ("activity", network_map_json(&self.activity)),
            (
                "prefs",
                json_object(vec![
                    ("evm_account", evm_account),
                    ("sol_account", json_u64(u64::from(self.prefs.sol_account))),
                    ("tab", json_str(self.prefs.tab.as_str())),
                ]),
            ),
            (
                "sol_raw_accounts",
                Value::Array(
                    self.sol_raw_accounts
                        .iter()
                        .map(|raw| {
                            json_object(vec![
                                ("record_id", json_str(&yw_core::hex::encode(&raw.record_id))),
                                ("label", json_str(&raw.label)),
                                ("address", json_str(&raw.address)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "sol_raw_selected",
                self.sol_raw_selected
                    .map_or(Value::Null, |id| json_str(&yw_core::hex::encode(&id))),
            ),
        ];
        if let Some(accounts) = btc_values.accounts {
            members.push((BTC_ACCOUNTS_KEY, accounts));
        }
        if let Some(ext) = btc_values.ext {
            members.push((BTC_ACCOUNTS_EXT_KEY, ext));
        }
        if let Some(mnemonic) = btc_values.mnemonic {
            members.push((yw_core::btc::meta::BTC_ACCOUNTS_MN_KEY, mnemonic));
        }
        if !self.chain_sites.sol.is_empty() {
            members.push((SOL_SITES_KEY, Value::Array(self.chain_sites.sol.clone())));
        }
        if !self.chain_sites.btc.is_empty() {
            members.push((BTC_SITES_KEY, Value::Array(self.chain_sites.btc.clone())));
        }
        if let Some(snapshot) = &self.security.snapshot {
            members.push((SECURITY_KEY, snapshot.to_json()));
        }
        if self.security.vault_generation_seen != 0 {
            members.push((
                VAULT_SEEN_KEY,
                json_u64(self.security.vault_generation_seen),
            ));
        }
        if self.security.journal_reset_at != 0 {
            members.push((JOURNAL_RESET_KEY, json_u64(self.security.journal_reset_at)));
        }
        if !self.token_view.is_default() {
            members.push((TOKEN_VIEW_KEY, self.token_view.to_json()));
        }
        if !self.hw_accounts.is_default() {
            members.push((HW_ACCOUNTS_KEY, self.hw_accounts.to_json()));
        }
        if !self.mnemonics.is_empty() {
            members.push((MNEMONICS_KEY, mnemonics_json(&self.mnemonics)));
        }

        if !self.zcash.is_default() {
            members.push((crate::zec::meta::ZCASH_KEY, self.zcash.to_json()));
        }
        if let Some(accounts) = self.mnemonic_accounts.to_json(&self.zcash) {
            members.push((MNEMONIC_ACCOUNTS_KEY, accounts));
        }
        if !self.book_favorites.is_empty() {
            members.push((BOOK_FAVORITES_KEY, self.favorites_json()));
        }
        if let Some(walletconnect) = &self.chain_sites.walletconnect {
            members.push((crate::walletconnect::store::META_KEY, walletconnect.clone()));
        }
        members
    }

    /// `address_book_favorites`.
    fn favorites_json(&self) -> Value {
        Value::Array(
            self.book_favorites
                .iter()
                .map(|(chain, address)| {
                    json_object(vec![
                        ("chain", json_str(chain.as_str())),
                        ("address", json_str(address)),
                    ])
                })
                .collect(),
        )
    }

    /// The next Solana standard index (largest + 1, or 0 for the first account), `None` at the
    /// bounds (100 accounts, index 999).
    #[must_use]
    pub fn next_sol_index(&self) -> Option<u32> {
        if self.sol_accounts.len() >= MAX_EVM_ACCOUNTS {
            return None;
        }
        let next = match self.sol_accounts.iter().map(|account| account.index).max() {
            Some(max) => max.checked_add(1)?,
            None => 0,
        };
        (u64::from(next) <= MAX_ACCOUNT_INDEX).then_some(next)
    }

    /// The next derived index for `계정 추가` (largest + 1), `None` at the bounds.
    #[must_use]
    pub fn next_index(&self) -> Option<u32> {
        if self.evm_accounts.len() >= MAX_EVM_ACCOUNTS {
            return None;
        }
        let next = self
            .evm_accounts
            .iter()
            .map(|account| account.index)
            .max()?
            .checked_add(1)?;
        (u64::from(next) <= MAX_ACCOUNT_INDEX).then_some(next)
    }
}

/// A typed `ActivityEntry` (spec/02 §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityEntry {
    /// Account (EVM lowercase `0x`).
    pub account: String,
    /// `0x` + tx hash.
    pub tx_id: String,
    /// Approval title at signing time.
    pub title: String,
    /// `"native"` or the token address.
    pub asset: String,
    /// Smallest-unit decimal amount.
    pub amount: String,
    /// Recipient.
    pub counterparty: String,
    /// `succeeded` | `failed` | `dropped` | `replaced` | ….
    pub status: String,
    /// Terminal observation time.
    pub time_unix_ms: u64,
}

impl ActivityEntry {
    /// From an EVM journal activity row (spec/03 §5.4).
    #[must_use]
    pub fn from_row(row: &yw_core::journal::evm::ActivityRow) -> Self {
        Self {
            account: row.account.clone(),
            tx_id: row.tx_id.clone(),
            title: row.title.clone(),
            asset: row.asset.clone(),
            amount: row.amount.clone(),
            counterparty: row.counterparty.clone(),
            status: row.status.as_str().to_owned(),
            time_unix_ms: row.time_unix_ms,
        }
    }

    fn to_value(&self) -> Value {
        json_object(vec![
            ("account", json_str(&self.account)),
            ("tx_id", json_str(&self.tx_id)),
            ("title", json_str(&self.title)),
            ("asset", json_str(&self.asset)),
            ("amount", json_str(&self.amount)),
            ("counterparty", json_str(&self.counterparty)),
            ("status", json_str(&self.status)),
            ("time_unix_ms", json_u64(self.time_unix_ms)),
        ])
    }

    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            account: text("account")?,
            tx_id: text("tx_id")?,
            title: text("title")?,
            asset: text("asset")?,
            amount: text("amount")?,
            counterparty: text("counterparty")?,
            status: text("status")?,
            time_unix_ms: object.get("time_unix_ms").and_then(u64_of)?,
        })
    }
}

/// The address family of an `AddressBookEntry` (`chain`). One EVM entry serves every EVM chain
/// (built-in and user-added: the address is the same everywhere); one Solana entry serves
/// mainnet and devnet (the same base58 key); Bitcoin entries are one family too, but an address
/// belongs to one network (`bc1…`/`1…`/`3…` mainnet, `tb1…`/`m…`/`n…`/`2…` testnet4), so a
/// send form only offers the entries its network parses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BookChain {
    /// `evm`.
    #[default]
    Evm,
    /// `sol`.
    Sol,
    /// `btc`.
    Btc,
}

impl BookChain {
    /// Every family, in S14 order.
    pub const ALL: [Self; 3] = [Self::Evm, Self::Sol, Self::Btc];

    /// The `chain` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Sol => "sol",
            Self::Btc => "btc",
        }
    }

    /// Parses a canonical `chain` value.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "evm" => Some(Self::Evm),
            "sol" => Some(Self::Sol),
            "btc" => Some(Self::Btc),
            _ => None,
        }
    }
}

/// A typed `AddressBookEntry` of any family (the address in its canonical form, spec/02 §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Family.
    pub chain: BookChain,
    /// Canonical address (EVM lowercase `0x`, SOL base58, BTC lowercase bech32 or base58check).
    pub address: String,
    /// Label.
    pub label: String,
    /// Verified out of band.
    pub verified: bool,
    /// Added (Unix ms).
    pub added_at_unix_ms: u64,
}

impl Contact {
    fn to_value(&self) -> Value {
        json_object(vec![
            ("chain", json_str(self.chain.as_str())),
            ("address", json_str(&self.address)),
            ("label", json_str(&self.label)),
            ("verified", Value::Bool(self.verified)),
            ("added_at_unix_ms", json_u64(self.added_at_unix_ms)),
        ])
    }

    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        Some(Self {
            chain: BookChain::parse(object.get("chain")?.as_str()?)?,
            address: object.get("address")?.as_str()?.to_owned(),
            label: object.get("label")?.as_str()?.to_owned(),
            verified: object.get("verified")?.as_bool()?,
            added_at_unix_ms: object.get("added_at_unix_ms").and_then(u64_of)?,
        })
    }
}

/// A typed EVM `AddressBookEntry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookEntry {
    /// Lowercase `0x` address.
    pub address: String,
    /// Label.
    pub label: String,
    /// Verified out of band.
    pub verified: bool,
    /// Added (Unix ms).
    pub added_at_unix_ms: u64,
}

impl BookEntry {
    fn to_value(&self) -> Value {
        json_object(vec![
            ("chain", json_str("evm")),
            ("address", json_str(&self.address)),
            ("label", json_str(&self.label)),
            ("verified", Value::Bool(self.verified)),
            ("added_at_unix_ms", json_u64(self.added_at_unix_ms)),
        ])
    }

    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if object.get("chain")?.as_str()? != "evm" {
            return None;
        }
        Some(Self {
            address: object.get("address")?.as_str()?.to_owned(),
            label: object.get("label")?.as_str()?.to_owned(),
            verified: object.get("verified")?.as_bool()?,
            added_at_unix_ms: object.get("added_at_unix_ms").and_then(u64_of)?,
        })
    }
}

/// A typed Solana `AddressBookEntry` (`chain = "sol"`, base58 address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolBookEntry {
    /// Base58 address.
    pub address: String,
    /// Label.
    pub label: String,
    /// Verified out of band.
    pub verified: bool,
    /// Added (Unix ms).
    pub added_at_unix_ms: u64,
}

impl SolBookEntry {
    fn to_value(&self) -> Value {
        json_object(vec![
            ("chain", json_str("sol")),
            ("address", json_str(&self.address)),
            ("label", json_str(&self.label)),
            ("verified", Value::Bool(self.verified)),
            ("added_at_unix_ms", json_u64(self.added_at_unix_ms)),
        ])
    }

    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if object.get("chain")?.as_str()? != "sol" {
            return None;
        }
        Some(Self {
            address: object.get("address")?.as_str()?.to_owned(),
            label: object.get("label")?.as_str()?.to_owned(),
            verified: object.get("verified")?.as_bool()?,
            added_at_unix_ms: object.get("added_at_unix_ms").and_then(u64_of)?,
        })
    }
}

/// A typed `TokenEntry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenEntry {
    /// Lowercase `0x` contract.
    pub address: String,
    /// Label.
    pub label: String,
    /// Decimals.
    pub decimals: u8,
}

impl TokenEntry {
    fn to_value(&self) -> Value {
        json_object(vec![
            ("address", json_str(&self.address)),
            ("label", json_str(&self.label)),
            ("decimals", json_u64(u64::from(self.decimals))),
        ])
    }

    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        Some(Self {
            address: object.get("address")?.as_str()?.to_owned(),
            label: object.get("label")?.as_str()?.to_owned(),
            decimals: u8::try_from(object.get("decimals").and_then(u64_of)?).ok()?,
        })
    }
}

/// Address-book or token list limit reached, or a duplicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListError {
    /// Same address already present (E-INP-016 for the book).
    Duplicate,
    /// Bound reached.
    Full,
}

fn network_items<'map>(map: &'map [(String, Vec<Value>)], network: &str) -> &'map [Value] {
    map.iter()
        .find(|(key, _)| key == network)
        .map_or(&[], |(_, items)| items.as_slice())
}

impl Meta {
    /// Activity rows of a network (newest first as stored).
    #[must_use]
    pub fn activity_of(&self, network: &str) -> Vec<ActivityEntry> {
        network_items(&self.activity, network)
            .iter()
            .filter_map(ActivityEntry::from_value)
            .collect()
    }

    /// Adds or replaces (same `tx_id`) an activity row; keeps newest first, at most 500 per
    /// network and 3,000 overall (the oldest go first, spec/02 §5.3).
    pub fn upsert_activity(&mut self, network: &str, entry: &ActivityEntry) {
        let mut rows = self.activity_of(network);
        rows.retain(|row| row.tx_id != entry.tx_id);
        rows.push(entry.clone());
        rows.sort_by_key(|row| std::cmp::Reverse(row.time_unix_ms));
        rows.truncate(MAX_ACTIVITY_PER_NETWORK);
        let values: Vec<Value> = rows.iter().map(ActivityEntry::to_value).collect();
        match self.activity.iter_mut().find(|(key, _)| key == network) {
            Some((_, items)) => *items = values,
            None => self.activity.push((network.to_owned(), values)),
        }
        loop {
            let total: usize = self.activity.iter().map(|(_, items)| items.len()).sum();
            if total <= MAX_ACTIVITY_TOTAL {
                break;
            }
            let oldest = self
                .activity
                .iter()
                .enumerate()
                .flat_map(|(map_index, (_, items))| {
                    items.iter().enumerate().map(move |(item_index, item)| {
                        let time =
                            ActivityEntry::from_value(item).map_or(0, |row| row.time_unix_ms);
                        (time, map_index, item_index)
                    })
                })
                .min();
            let Some((_, map_index, item_index)) = oldest else {
                break;
            };
            match self.activity.get_mut(map_index) {
                Some((_, items)) if item_index < items.len() => {
                    items.remove(item_index);
                }
                _ => break,
            }
        }
        self.activity.retain(|(_, items)| !items.is_empty());
    }

    /// EVM address-book entries.
    #[must_use]
    pub fn book(&self) -> Vec<BookEntry> {
        self.address_book
            .iter()
            .filter_map(BookEntry::from_value)
            .collect()
    }

    /// Adds an EVM address-book entry.
    ///
    /// # Errors
    ///
    /// [`ListError`].
    pub fn add_book(&mut self, entry: &BookEntry) -> Result<(), ListError> {
        if self
            .book()
            .iter()
            .any(|known| known.address == entry.address)
        {
            return Err(ListError::Duplicate);
        }
        if self.address_book.len() >= MAX_ADDRESS_BOOK {
            return Err(ListError::Full);
        }
        self.address_book.push(entry.to_value());
        Ok(())
    }

    /// Replaces the EVM entry for `entry.address` (label, verified).
    pub fn update_book(&mut self, entry: &BookEntry) {
        for value in &mut self.address_book {
            if BookEntry::from_value(value).is_some_and(|known| known.address == entry.address) {
                *value = entry.to_value();
            }
        }
    }

    /// Solana address-book entries.
    #[must_use]
    pub fn sol_book(&self) -> Vec<SolBookEntry> {
        self.address_book
            .iter()
            .filter_map(SolBookEntry::from_value)
            .collect()
    }

    /// Adds a Solana address-book entry.
    ///
    /// # Errors
    ///
    /// [`ListError`].
    pub fn add_sol_book(&mut self, entry: &SolBookEntry) -> Result<(), ListError> {
        if self
            .sol_book()
            .iter()
            .any(|known| known.address == entry.address)
        {
            return Err(ListError::Duplicate);
        }
        if self.address_book.len() >= MAX_ADDRESS_BOOK {
            return Err(ListError::Full);
        }
        self.address_book.push(entry.to_value());
        Ok(())
    }

    /// Removes the Solana entry for `address`.
    pub fn remove_sol_book(&mut self, address: &str) {
        self.remove_contact(BookChain::Sol, address);
    }

    /// Removes the EVM entry for `address`.
    pub fn remove_book(&mut self, address: &str) {
        self.remove_contact(BookChain::Evm, address);
    }

    /// The entries of one family, in book order.
    #[must_use]
    pub fn contacts(&self, chain: BookChain) -> Vec<Contact> {
        self.address_book
            .iter()
            .filter_map(Contact::from_value)
            .filter(|entry| entry.chain == chain)
            .collect()
    }

    /// The entries of one family with the favorites first (in starring order), then the rest
    /// in book order.
    #[must_use]
    pub fn contacts_favorites_first(&self, chain: BookChain) -> Vec<Contact> {
        let mut entries = self.contacts(chain);
        entries.sort_by_key(|entry| {
            self.book_favorites
                .iter()
                .position(|(c, a)| *c == entry.chain && *a == entry.address)
                .unwrap_or(usize::MAX)
        });
        entries
    }

    /// The entry for `(chain, address)`.
    #[must_use]
    pub fn contact(&self, chain: BookChain, address: &str) -> Option<Contact> {
        self.contacts(chain)
            .into_iter()
            .find(|entry| entry.address == address)
    }

    /// Adds an entry.
    ///
    /// # Errors
    ///
    /// [`ListError`].
    pub fn add_contact(&mut self, entry: &Contact) -> Result<(), ListError> {
        if self.contact(entry.chain, &entry.address).is_some() {
            return Err(ListError::Duplicate);
        }
        if self.address_book.len() >= MAX_ADDRESS_BOOK {
            return Err(ListError::Full);
        }
        self.address_book.push(entry.to_value());
        Ok(())
    }

    /// Replaces the label and verified flag of the entry for `(entry.chain, entry.address)`
    /// (its `added_at_unix_ms` stays).
    pub fn update_contact(&mut self, entry: &Contact) {
        for value in &mut self.address_book {
            if let Some(known) = Contact::from_value(value)
                && known.chain == entry.chain
                && known.address == entry.address
            {
                *value = Contact {
                    label: entry.label.clone(),
                    verified: entry.verified,
                    ..known
                }
                .to_value();
            }
        }
    }

    /// Removes the entry for `(chain, address)` and its star.
    pub fn remove_contact(&mut self, chain: BookChain, address: &str) {
        self.address_book.retain(|value| {
            Contact::from_value(value)
                .is_none_or(|known| known.chain != chain || known.address != address)
        });
        self.set_favorite(chain, address, false);
    }

    /// Whether the entry is starred.
    #[must_use]
    pub fn is_favorite(&self, chain: BookChain, address: &str) -> bool {
        self.book_favorites
            .iter()
            .any(|(c, a)| *c == chain && a == address)
    }

    /// Stars or unstars an entry (only entries the book holds can be starred).
    pub fn set_favorite(&mut self, chain: BookChain, address: &str, on: bool) {
        let starred = self.is_favorite(chain, address);
        if on && !starred && self.contact(chain, address).is_some() {
            self.book_favorites.push((chain, address.to_owned()));
        } else if !on && starred {
            self.book_favorites
                .retain(|(c, a)| *c != chain || a != address);
        }
    }

    /// User tokens of a network.
    #[must_use]
    pub fn tokens_of(&self, network: &str) -> Vec<TokenEntry> {
        network_items(&self.tokens, network)
            .iter()
            .filter_map(TokenEntry::from_value)
            .collect()
    }

    /// Adds a user token (spec/04 §2.6 S16).
    ///
    /// # Errors
    ///
    /// [`ListError`] for a duplicate or the 100 / 1,000 bounds.
    pub fn add_token(&mut self, network: &str, entry: &TokenEntry) -> Result<(), ListError> {
        let current = self.tokens_of(network);
        if current.iter().any(|known| known.address == entry.address) {
            return Err(ListError::Duplicate);
        }
        let total: usize = self.tokens.iter().map(|(_, items)| items.len()).sum();
        if current.len() >= MAX_TOKENS_PER_NETWORK || total >= MAX_TOKENS_TOTAL {
            return Err(ListError::Full);
        }
        match self.tokens.iter_mut().find(|(key, _)| key == network) {
            Some((_, items)) => items.push(entry.to_value()),
            None => self
                .tokens
                .push((network.to_owned(), vec![entry.to_value()])),
        }
        Ok(())
    }

    /// Removes a user token (and its hidden mark: a token added again starts visible).
    pub fn remove_token(&mut self, network: &str, address: &str) {
        self.token_view.set_hidden(network, address, false);
        for (key, items) in &mut self.tokens {
            if key == network {
                items.retain(|value| {
                    TokenEntry::from_value(value).is_none_or(|known| known.address != address)
                });
            }
        }
        self.tokens.retain(|(_, items)| !items.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Account, BOOK_FAVORITES_KEY, BookChain, Contact, EvmAccountPref, LIMITS, Meta, RawAccount,
        SolBookEntry, SolRawAccount, Tab, parse,
    };
    use yw_core::btc::{BtcAccountKey, BtcMeta, BtcNetwork, BtcPubKey, ScriptType};

    /// The BIP84 test vector key (abandon `m/84'/0'/0'/0/0`) as an imported single-key account.
    fn imported_btc() -> BtcMeta {
        let pubkey = BtcPubKey::parse(
            &yw_core::hex::decode(
                "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
            )
            .unwrap(),
        )
        .unwrap();
        BtcMeta::with_key(
            BtcNetwork::Mainnet,
            BtcAccountKey::single([3; 16], ScriptType::P2wpkh, pubkey).unwrap(),
        )
    }

    fn imported_meta() -> Meta {
        let mut meta = Meta::key_only();
        meta.evm_raw_accounts.push(RawAccount {
            record_id: [1; 16],
            label: "가져온 계정 1".to_owned(),
            address: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".to_owned(),
        });
        meta.sol_raw_accounts.push(SolRawAccount {
            record_id: [2; 16],
            label: "가져온 Solana 1".to_owned(),
            address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned(),
        });
        // An imported Bitcoin key is an account of `btc_accounts` (no list of its own).
        meta.btc_accounts.upsert(imported_btc()).unwrap();
        meta.sol_raw_selected = Some([2; 16]);
        meta.prefs.tab = Tab::Sol;
        meta
    }

    /// spec/02 §8.6: the Solana, Bitcoin and Zcash accounts of an added mnemonic live only in
    /// the new top-level keys `mnemonic_accounts` and `btc_accounts_mn` (earlier builds keep them
    /// unread): `sol_accounts`, `prefs`, `btc`, `btc_accounts`, `btc_accounts_ext` and `zcash`
    /// carry nothing new, and the document round-trips.
    #[test]
    fn added_mnemonic_accounts_stay_in_new_top_level_keys() {
        use yw_core::bip32::AccountXpub;
        use yw_core::vault::RecordId;
        use yw_core::zec::{ZecAccount, ZecKeySource, ZecNetwork};
        let id = [0x5c; 16];
        let xpub = AccountXpub {
            pubkey: yw_core::hex::decode_array::<33>(
                "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
            )
            .unwrap(),
            chain_code: [7; 32],
        };
        let mut meta = Meta::default();
        meta.sol_accounts.push(Account {
            index: 0,
            label: "Solana 1".to_owned(),
            address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned(),
            hidden: false,
        });
        meta.mnemonic_accounts.upsert_sol(
            id,
            Account {
                index: 0,
                label: "Solana 1".to_owned(),
                address: "oeYf6KAJkLYhBuR8CiGc6L4D4Xtfepr85fuDgA9kq96".to_owned(),
                hidden: false,
            },
        );
        meta.mnemonic_accounts.sol_selected = Some((id, 0));
        meta.btc = Some(Box::new(BtcMeta::new(BtcNetwork::Mainnet, xpub)));
        let added = BtcAccountKey::hd(ScriptType::P2wpkh, 0, xpub)
            .unwrap()
            .with_mnemonic(Some(RecordId::from_bytes(id)));
        meta.btc_accounts
            .upsert(BtcMeta::with_key(BtcNetwork::Mainnet, added))
            .unwrap();
        meta.btc_accounts
            .upsert(BtcMeta::with_key(
                BtcNetwork::Mainnet,
                added.with_single_address(false).with_mnemonic(None),
            ))
            .unwrap_err();
        meta.btc_accounts.selected = Some(added.id());
        meta.zcash.set(ZecAccount {
            network: ZecNetwork::Mainnet,
            source: ZecKeySource::Mnemonic {
                mnemonic: RecordId::from_bytes(id),
                account: 0,
                index: 0,
            },
            pubkey: xpub.pubkey,
        });
        let bytes = meta.to_json();
        let root = yw_json::parse(&bytes, &LIMITS).unwrap();
        let object = root.as_object().unwrap();
        let hex = yw_core::hex::encode(&id);
        for key in [
            "sol_accounts",
            "prefs",
            "btc",
            "btc_accounts",
            "btc_accounts_ext",
        ] {
            let text = object
                .get(key)
                .map(|value| String::from_utf8(yw_json::to_vec(value)).unwrap())
                .unwrap_or_default();
            assert!(!text.contains(&hex), "{key}");
        }
        assert!(object.get("zcash").is_none());
        assert!(object.get("btc_accounts").is_none());
        for key in ["mnemonic_accounts", "btc_accounts_mn"] {
            let text = String::from_utf8(yw_json::to_vec(object.get(key).unwrap())).unwrap();
            assert!(text.contains(&hex), "{key}");
        }
        assert_eq!(parse(&bytes).unwrap().meta, meta);
    }

    #[test]
    fn imported_lists_and_key_only_meta_round_trip() {
        let meta = imported_meta();
        let bytes = meta.to_json();
        let text = String::from_utf8(bytes.clone()).unwrap();
        // Written after `prefs`, never as unknown keys.
        assert!(text.contains("\"evm_accounts\":[]"));
        assert!(text.contains("\"network\":\"mainnet\",\"script_type\":\"p2wpkh\""));
        assert!(text.contains("\"imported\":{\"id\":\"03030303030303030303030303030303\""));
        assert!(!text.contains("btc_raw_accounts"));
        let prefs_at = text.find("\"prefs\"").unwrap();
        assert!(text.find("\"sol_raw_accounts\"").unwrap() > prefs_at);
        assert!(text.find("\"btc_accounts\"").unwrap() > prefs_at);
        let parsed = parse(&bytes).unwrap();
        // `{"index": 0}` without derived accounts is not a reset (key-only wallet).
        assert!(!parsed.prefs_reset);
        assert_eq!(parsed.meta, meta);
        assert!(parsed.meta.unknown.is_empty());
        assert_eq!(parsed.meta.to_json(), bytes);
        assert_eq!(
            parsed.meta.next_index(),
            None,
            "no 계정 추가 without derived accounts"
        );
        // A file written before key import (no imported keys) still parses, with empty lists.
        let old = String::from_utf8(Meta::default().to_json()).unwrap();
        let old = old
            .split(",\"sol_raw_accounts\"")
            .next()
            .unwrap()
            .to_owned()
            + "}";
        let parsed = parse(old.as_bytes()).unwrap();
        assert!(
            parsed.meta.sol_raw_accounts.is_empty() && parsed.meta.btc_accounts.accounts.is_empty()
        );
        assert_eq!(parsed.meta.sol_raw_selected, None);
        assert_eq!(parsed.meta.evm_accounts.len(), 1);
    }

    #[test]
    fn imported_lists_are_validated() {
        let text = String::from_utf8(imported_meta().to_json()).unwrap();
        for bad in [
            text.replacen("\"network\":\"mainnet\"", "\"network\":\"signet\"", 1),
            text.replacen("\"script_type\":\"p2wpkh\"", "\"script_type\":\"p2wsh\"", 1),
            text.replacen("0330d54fd0dd", "0430d54fd0dd", 1),
            text.replacen("HAgk14", "0xHAgk", 1),
            text.replacen(
                "\"sol_raw_selected\":\"02020202020202020202020202020202\"",
                "\"sol_raw_selected\":\"09090909090909090909090909090909\"",
                1,
            ),
            text.replacen(
                "\"label\":\"가져온 Solana 1\"",
                "\"label\":\"가져온 Solana 1\",\"x\":1",
                1,
            ),
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
        // A derived list that does not start at index 0 is still refused.
        let mut meta = Meta::key_only();
        meta.evm_accounts.push(Account {
            index: 1,
            label: "계정 2".to_owned(),
            address: String::new(),
            hidden: false,
        });
        assert!(parse(&meta.to_json()).is_err());
    }

    #[test]
    fn solana_accounts_tab_and_book_round_trip() {
        let mut meta = Meta::default();
        assert_eq!(meta.next_sol_index(), Some(0));
        meta.sol_accounts.push(Account {
            index: 0,
            label: "Solana 1".to_owned(),
            address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned(),
            hidden: false,
        });
        meta.prefs.tab = Tab::Sol;
        meta.add_sol_book(&SolBookEntry {
            address: "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb".to_owned(),
            label: "친구".to_owned(),
            verified: true,
            added_at_unix_ms: 1,
        })
        .unwrap();
        assert!(
            meta.add_sol_book(&SolBookEntry {
                address: "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb".to_owned(),
                label: "중복".to_owned(),
                verified: false,
                added_at_unix_ms: 2,
            })
            .is_err()
        );
        let parsed = parse(&meta.to_json()).unwrap();
        assert!(!parsed.prefs_reset);
        assert_eq!(parsed.meta, meta);
        assert_eq!(parsed.meta.next_sol_index(), Some(1));
        assert_eq!(parsed.meta.sol_book().len(), 1);
        assert!(parsed.meta.book().is_empty());
        // A non-canonical or EVM-style address in sol_accounts rejects the document.
        let bad = String::from_utf8(meta.to_json())
            .unwrap()
            .replacen("HAgk14", "0xHAgk", 1);
        assert!(parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn book_favorites_round_trip_and_stay_out_of_the_entries() {
        let a = "0x52908400098527886e0f7030069857d2e4169ee7";
        let b = "0x8617e340b3d01fa5f11f306f4090fd50e238070d";
        let contact = |chain, address: &str, label: &str| Contact {
            chain,
            address: address.to_owned(),
            label: label.to_owned(),
            verified: false,
            added_at_unix_ms: 7,
        };
        let mut meta = Meta::default();
        meta.add_contact(&contact(BookChain::Evm, a, "가")).unwrap();
        meta.add_contact(&contact(BookChain::Evm, b, "나")).unwrap();
        let sol = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
        meta.add_contact(&contact(BookChain::Sol, sol, "다"))
            .unwrap();
        let btc = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        meta.add_contact(&contact(BookChain::Btc, btc, "라"))
            .unwrap();
        assert!(
            meta.add_contact(&contact(BookChain::Evm, a, "중복"))
                .is_err()
        );
        // Unknown entries cannot be starred; starring is idempotent.
        meta.set_favorite(BookChain::Sol, a, true);
        meta.set_favorite(BookChain::Evm, b, true);
        meta.set_favorite(BookChain::Evm, b, true);
        assert_eq!(meta.book_favorites, vec![(BookChain::Evm, b.to_owned())]);
        let labels: Vec<String> = meta
            .contacts_favorites_first(BookChain::Evm)
            .into_iter()
            .map(|entry| entry.label)
            .collect();
        assert_eq!(labels, ["나", "가"]);
        let text = String::from_utf8(meta.to_json()).unwrap();
        assert!(text.ends_with(
            r#","address_book_favorites":[{"chain":"evm","address":"0x8617e340b3d01fa5f11f306f4090fd50e238070d"}]}"#
        ));
        // The entries keep exactly the five members an earlier version accepts.
        let root = yw_json::parse(text.as_bytes(), &LIMITS).unwrap();
        let entries = root.as_object().unwrap().get("address_book").unwrap();
        for entry in entries.as_array().unwrap() {
            assert_eq!(entry.as_object().unwrap().len(), 5);
        }
        let parsed = parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.meta, meta);
        assert!(parsed.meta.unknown.is_empty());
        // An earlier version keeps the key unread (an unknown key) and writes it back.
        let mut older = parsed.meta.clone();
        older.unknown = vec![(BOOK_FAVORITES_KEY.to_owned(), older.favorites_json())];
        older.book_favorites.clear();
        assert_eq!(
            parse(&older.to_json()).unwrap().meta.book_favorites,
            meta.book_favorites
        );
        // Deleting an entry drops its star; a stale or invalid favorites value is ignored.
        meta.remove_contact(BookChain::Evm, b);
        assert!(meta.book_favorites.is_empty());
        let stale = text.replace(
            r#""address":"0x8617e340b3d01fa5f11f306f4090fd50e238070d"}]}"#,
            r#""address":"0x1111111111111111111111111111111111111111"}]}"#,
        );
        assert!(
            parse(stale.as_bytes())
                .unwrap()
                .meta
                .book_favorites
                .is_empty()
        );
        let invalid = text.replace(
            r#""address_book_favorites":[{"chain":"evm","address""#,
            r#""address_book_favorites":[{"chain":"evm","x":1,"address""#,
        );
        let invalid = parse(invalid.as_bytes()).unwrap();
        assert!(invalid.meta.book_favorites.is_empty());
        assert_eq!(invalid.meta.contacts(BookChain::Evm).len(), 2);
    }

    #[test]
    fn per_chain_and_duplicate_entries_fold_into_one_evm_entry() {
        let a = "0x52908400098527886e0f7030069857d2e4169ee7";
        let b = "0x8617e340b3d01fa5f11f306f4090fd50e238070d";
        let entry = |chain: &str, address: &str, label: &str, verified: bool, added: u64| {
            format!(
                r#"{{"chain":"{chain}","address":"{address}","label":"{label}","verified":{verified},"added_at_unix_ms":{added}}}"#
            )
        };
        let book = [
            entry("eip155:1", a, "첫 이름", false, 50),
            entry("evm", b, "다른", false, 10),
            entry("eip155:8453", a, "둘째 이름", true, 20),
            entry("evm", a, "셋째", false, 90),
        ]
        .join(",");
        let good = String::from_utf8(Meta::default().to_json()).unwrap();
        let text = good.replacen(
            "\"address_book\":[]",
            &format!("\"address_book\":[{book}]"),
            1,
        );
        let meta = parse(text.as_bytes()).unwrap().meta;
        assert_eq!(
            meta.contacts(BookChain::Evm),
            vec![
                Contact {
                    chain: BookChain::Evm,
                    address: a.to_owned(),
                    label: "첫 이름".to_owned(),
                    verified: true,
                    added_at_unix_ms: 20,
                },
                Contact {
                    chain: BookChain::Evm,
                    address: b.to_owned(),
                    label: "다른".to_owned(),
                    verified: false,
                    added_at_unix_ms: 10,
                },
            ]
        );
        let written = String::from_utf8(meta.to_json()).unwrap();
        assert!(!written.contains("eip155:1\""));
        assert!(!written.contains("eip155:8453"));
        // A per-chain value with a non-EVM address, or an unknown family, still rejects the file.
        let bad = good.replacen(
            "\"address_book\":[]",
            &format!(
                "\"address_book\":[{}]",
                entry(
                    "eip155:1",
                    "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb",
                    "x",
                    false,
                    1
                )
            ),
            1,
        );
        assert!(parse(bad.as_bytes()).is_err());
        let unknown = good.replacen(
            "\"address_book\":[]",
            &format!(
                "\"address_book\":[{}]",
                entry("hypercore", a, "x", false, 1)
            ),
            1,
        );
        assert!(parse(unknown.as_bytes()).is_err());
    }

    #[test]
    fn bitcoin_meta_and_tab_round_trip_strictly() {
        let account = yw_core::bip32::AccountXpub {
            pubkey: yw_core::hex::decode_array::<33>(
                "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
            )
            .unwrap(),
            chain_code: [7; 32],
        };
        let mut meta = Meta {
            btc: Some(Box::new(yw_core::btc::BtcMeta::new(
                yw_core::btc::BtcNetwork::Testnet4,
                account,
            ))),
            ..Meta::default()
        };
        meta.prefs.tab = Tab::Btc;
        let bytes = meta.to_json();
        let parsed = parse(&bytes).unwrap();
        assert!(!parsed.prefs_reset);
        assert_eq!(parsed.meta, meta);
        assert_eq!(parsed.meta.to_json(), bytes);
        // A strict BtcMeta violation rejects the whole document (spec/02 §5.3).
        let text = String::from_utf8(bytes).unwrap();
        for bad in [
            text.replacen("\"version\":1", "\"version\":2", 1),
            text.replacen("\"network\":\"testnet4\"", "\"network\":\"signet\"", 1),
            text.replacen("\"receive_next\":0", "\"receive_next\":0,\"extra\":1", 1),
            text.replacen("\"btc\":{", "\"btc\":[{", 1),
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
        // `null` stays `null`.
        let null = String::from_utf8(Meta::default().to_json()).unwrap();
        assert!(null.contains("\"btc\":null"));
        assert_eq!(parse(null.as_bytes()).unwrap().meta.btc, None);
    }

    /// spec/08 §12.3a: `btc_accounts` is an optional top-level key. A file without it (every
    /// earlier version) has no other accounts and is written back without it; with accounts it
    /// round-trips after the required keys, and meta `btc` keeps its version 1 bytes. An invalid
    /// `btc_accounts` rejects the document like any known key.
    #[test]
    fn btc_accounts_is_an_optional_known_key() {
        use yw_core::btc::{BtcAccountId, BtcAccountKey, BtcAccounts, BtcMeta, BtcNetwork};
        let node = yw_core::bip32::AccountXpub {
            pubkey: yw_core::hex::decode_array::<33>(
                "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
            )
            .unwrap(),
            chain_code: [7; 32],
        };
        let primary = BtcMeta::new(BtcNetwork::Testnet4, node);
        let without = Meta {
            btc: Some(Box::new(primary.clone())),
            ..Meta::default()
        };
        let old_bytes = without.to_json();
        let old_text = String::from_utf8(old_bytes.clone()).unwrap();
        assert!(!old_text.contains(super::BTC_ACCOUNTS_KEY));
        let parsed = parse(&old_bytes).unwrap().meta;
        assert_eq!(parsed.btc_accounts, BtcAccounts::default());
        assert_eq!(parsed.to_json(), old_bytes);
        let taproot = BtcAccountKey::hd(yw_core::btc::ScriptType::P2tr, 0, node).unwrap();
        let mut with = without.clone();
        with.btc_accounts
            .upsert(BtcMeta::with_key(BtcNetwork::Testnet4, taproot))
            .unwrap();
        with.btc_accounts.selected = Some(taproot.id());
        let bytes = with.to_json();
        let text = String::from_utf8(bytes.clone()).unwrap();
        // Meta `btc` is byte-identical; `btc_accounts` follows the required keys.
        assert!(text.contains(
            &old_text
                [old_text.find("\"btc\":").unwrap()..old_text.find(",\"address_book\"").unwrap()]
        ));
        assert!(text.find("\"prefs\"").unwrap() < text.find("\"btc_accounts\"").unwrap());
        let parsed = parse(&bytes).unwrap().meta;
        assert_eq!(parsed, with);
        assert_eq!(parsed.to_json(), bytes);
        assert!(parsed.unknown.is_empty());
        assert_eq!(
            parsed.btc_accounts.selected_on(BtcNetwork::Testnet4),
            BtcAccountId::Hd {
                mnemonic: None,
                script_type: yw_core::btc::ScriptType::P2tr,
                account: 0
            }
        );
        assert!(
            parse(
                text.replacen(
                    "\"btc_accounts\":{\"version\":1",
                    "\"btc_accounts\":{\"version\":2",
                    1
                )
                .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse(
                text.replacen("\"selected\":{", "\"selected\":7,\"x\":{", 1)
                    .as_bytes()
            )
            .is_err()
        );
    }

    /// spec/08 §3.5/§12.3: the address mode of an HD account. A meta written before the mode
    /// existed (no `single_address`) loads every HD account in fixed-address mode and is written
    /// back byte-identical; HD mode adds `"single_address":false` to that account only; an
    /// account on an EVM account's key round-trips in `btc_accounts`.
    #[test]
    fn btc_address_mode_and_evm_shared_accounts() {
        use yw_core::btc::{BtcAccountKey, BtcMeta, BtcNetwork, ScriptType};
        let node = yw_core::bip32::AccountXpub {
            pubkey: yw_core::hex::decode_array::<33>(
                "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
            )
            .unwrap(),
            chain_code: [7; 32],
        };
        let taproot = BtcAccountKey::hd(ScriptType::P2tr, 0, node).unwrap();
        let mut old = Meta {
            btc: Some(Box::new(BtcMeta::new(BtcNetwork::Testnet4, node))),
            ..Meta::default()
        };
        old.btc_accounts
            .upsert(BtcMeta::with_key(BtcNetwork::Testnet4, taproot))
            .unwrap();
        let old_bytes = old.to_json();
        assert!(
            !String::from_utf8(old_bytes.clone())
                .unwrap()
                .contains("single_address")
        );
        let parsed = parse(&old_bytes).unwrap().meta;
        assert!(parsed.btc.as_deref().unwrap().fixed_address());
        assert!(
            parsed
                .btc_accounts
                .accounts
                .iter()
                .all(BtcMeta::fixed_address)
        );
        assert_eq!(parsed.to_json(), old_bytes);
        // HD mode on the taproot account only.
        let mut hd = parsed;
        assert_eq!(
            hd.btc_accounts.accounts[0].set_single_address(false),
            Ok(true)
        );
        let key = BtcAccountKey::evm_shared(2, ScriptType::P2wpkh, node.pubkey).unwrap();
        hd.btc_accounts
            .upsert(BtcMeta::with_key(BtcNetwork::Testnet4, key))
            .unwrap();
        let bytes = hd.to_json();
        let text = String::from_utf8(bytes.clone()).unwrap();
        // spec/08 §12.3b: nothing new inside `btc`/`btc_accounts` (earlier builds decode those
        // strictly); the HD-mode flag and the EVM-key account are in `btc_accounts_ext`.
        assert!(!text.contains("single_address"));
        let ext_at = text.find("\"btc_accounts_ext\":").unwrap();
        assert!(text.find("\"btc_accounts\":").unwrap() < ext_at);
        assert!(!text[..ext_at].contains("\"evm\":{\"index\""));
        assert!(text[ext_at..].contains("\"key\":{\"evm\":{\"index\":2,"));
        assert!(text[ext_at..].contains(
            "\"hd_mode\":[{\"network\":\"testnet4\",\"account\":{\"hd\":{\"script_type\":\"p2tr\""
        ));
        let back = parse(&bytes).unwrap().meta;
        assert_eq!(back, hd);
        assert!(back.unknown.is_empty());
        assert!(back.btc.as_deref().unwrap().fixed_address());
        assert!(!back.btc_accounts.accounts[0].fixed_address());
        assert!(back.btc_accounts.accounts[1].is_single());
        // The placement of the 2026-11-05/06 builds (flag and EVM key inside `btc_accounts`) is
        // read too and moved by the next write.
        let values = super::btc_meta_values(hd.btc.as_deref(), &hd.btc_accounts);
        let legacy = String::from_utf8(yw_json::to_vec(&values.accounts.unwrap())).unwrap();
        let ext = String::from_utf8(yw_json::to_vec(&values.ext.unwrap())).unwrap();
        let full = String::from_utf8(yw_json::to_vec(&hd.btc_accounts.to_json())).unwrap();
        assert!(full.contains("\"single_address\":false"));
        let old_placement = text
            .replacen(&format!(",\"btc_accounts_ext\":{ext}"), "", 1)
            .replacen(&legacy, &full, 1);
        assert!(!old_placement.contains("btc_accounts_ext"));
        let migrated = parse(old_placement.as_bytes()).unwrap().meta;
        assert_eq!(migrated, hd);
        assert_eq!(migrated.to_json(), bytes);
    }

    #[test]
    fn default_round_trips_and_has_account_zero() {
        let mut meta = Meta::default();
        meta.evm_accounts[0].address = format!("0x{}", "ab".repeat(20));
        let bytes = meta.to_json();
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.meta, meta);
        assert!(!parsed.prefs_reset);
        assert_eq!(parsed.meta.to_json(), bytes);
        assert_eq!(meta.next_index(), Some(1));
    }

    #[test]
    fn unknown_top_level_keys_are_kept_and_written_back() {
        // A newer minor version added two top-level keys (spec/04 §6.6 fixture).
        let good = String::from_utf8(Meta::default().to_json()).unwrap();
        let newer = good.replacen(
            "\"btc\":null",
            "\"future_notes\":{\"a\":[1,\"x\"]},\"btc\":null,\"future_flag\":true",
            1,
        );
        let parsed = parse(newer.as_bytes()).unwrap();
        assert!(!parsed.prefs_reset);
        let names: Vec<&str> = parsed
            .meta
            .unknown
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(names, ["future_notes", "future_flag"]);
        let mut meta = parsed.meta;
        meta.evm_accounts[0].label = "주 계정".to_owned();
        let written = String::from_utf8(meta.to_json()).unwrap();
        assert!(written.ends_with(",\"future_notes\":{\"a\":[1,\"x\"]},\"future_flag\":true}"));
        let again = parse(written.as_bytes()).unwrap();
        assert_eq!(again.meta, meta);
        assert_eq!(again.meta.to_json(), written.as_bytes());
        // Unknown keys never push the plaintext over 8 MiB: they are dropped instead.
        let big = Meta {
            unknown: vec![
                ("small".to_owned(), super::Value::Bool(true)),
                (
                    "huge".to_owned(),
                    super::Value::String("x".repeat(super::META_MAX_BYTES)),
                ),
                ("after".to_owned(), super::Value::Null),
            ],
            ..Meta::default()
        };
        let bytes = big.to_json();
        assert!(bytes.len() <= super::META_MAX_BYTES);
        let kept = parse(&bytes).unwrap().meta.unknown;
        assert_eq!(kept, vec![("small".to_owned(), super::Value::Bool(true))]);
    }

    #[test]
    fn missing_keys_other_schemas_and_bad_accounts_are_rejected() {
        let good = String::from_utf8(Meta::default().to_json()).unwrap();
        let missing = good.replacen("\"btc\":null,", "", 1);
        assert!(parse(missing.as_bytes()).is_err());
        let other_schema = good.replacen("yw-meta/3", "yw-meta/4", 1);
        assert!(parse(other_schema.as_bytes()).is_err());
        // Unknown keys inside typed records are still a violation (only top-level keys may grow).
        let nested = good.replacen("\"hidden\":false", "\"hidden\":false,\"extra\":1", 1);
        assert!(parse(nested.as_bytes()).is_err());
        let no_zero = good.replacen("\"index\":0", "\"index\":1", 1);
        assert!(parse(no_zero.as_bytes()).is_err());
        let bad_label = good.replacen("계정 1", " padded", 1);
        assert!(parse(bad_label.as_bytes()).is_err());
        let duplicate = good.replacen("{\"schema\"", "{\"schema\":\"x\",\"schema\"", 1);
        assert!(parse(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn invalid_prefs_fall_back_without_rejecting_meta() {
        let good = String::from_utf8(Meta::default().to_json()).unwrap();
        let bad = good.replacen("\"index\":0}", "\"index\":7}", 1);
        let parsed = parse(bad.as_bytes()).unwrap();
        assert!(parsed.prefs_reset);
        assert_eq!(parsed.meta.prefs.evm_account, EvmAccountPref::Index(0));
    }

    /// `token_view` (2026-11-03): an optional key written only when not the default, after the
    /// required keys; a file without it (every earlier version) reads as "nothing hidden" and is
    /// written back byte-identical; an older app keeps it as an unknown key; an invalid value
    /// resets only the view (`prefs_reset`), never the document.
    #[test]
    fn token_view_is_an_optional_key_with_fallback() {
        const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let old = Meta::default().to_json();
        assert!(
            !String::from_utf8(old.clone())
                .unwrap()
                .contains("token_view")
        );
        let parsed = parse(&old).unwrap();
        assert!(!parsed.prefs_reset);
        assert!(parsed.meta.token_view.is_default());
        assert_eq!(parsed.meta.to_json(), old);

        let mut meta = Meta::default();
        meta.add_token(
            "eip155:1",
            &super::TokenEntry {
                address: "0x1111111111111111111111111111111111111111".to_owned(),
                label: "SCAM".to_owned(),
                decimals: 18,
            },
        )
        .unwrap();
        assert!(meta.token_view.set_hidden("eip155:1", USDC, true));
        assert!(meta.token_view.set_hidden(
            "eip155:1",
            "0x1111111111111111111111111111111111111111",
            true
        ));
        assert!(meta.token_view.set_hidden("solana:mainnet", MINT, true));
        meta.token_view.hide_zero = true;
        let bytes = meta.to_json();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.find("\"prefs\"").unwrap() < text.find("\"token_view\"").unwrap());
        let parsed = parse(&bytes).unwrap();
        assert!(!parsed.prefs_reset);
        assert_eq!(parsed.meta, meta);
        assert!(parsed.meta.unknown.is_empty());
        assert_eq!(parsed.meta.to_json(), bytes);

        // Deleting a user token also forgets its hidden mark; registry marks stay.
        let mut removed = parsed.meta;
        removed.remove_token("eip155:1", "0x1111111111111111111111111111111111111111");
        assert!(removed.tokens_of("eip155:1").is_empty());
        assert_eq!(removed.token_view.hidden_of("eip155:1"), [USDC.to_owned()]);

        // An app that predates the key keeps it unread (as an unknown key) and writes it back.
        let older = text.replacen("\"token_view\"", "\"token_view_next\"", 1);
        let kept = parse(older.as_bytes()).unwrap().meta;
        assert!(kept.token_view.is_default());
        assert_eq!(kept.unknown.len(), 1);
        assert_eq!(kept.to_json(), older.as_bytes());

        // Invalid values reset the view only.
        for bad in [
            text.replacen("\"hide_zero\":true", "\"hide_zero\":1", 1),
            text.replacen("\"hide_zero\":true", "\"hide_zero\":true,\"x\":1", 1),
            text.replacen(USDC, &USDC.to_uppercase().replacen("0X", "0x", 1), 1),
            text.replacen("\"solana:mainnet\"", "\"bitcoin:mainnet\"", 1),
        ] {
            let parsed = parse(bad.as_bytes()).unwrap();
            assert!(parsed.prefs_reset, "{bad}");
            assert!(parsed.meta.token_view.is_default());
            assert_eq!(parsed.meta.tokens_of("eip155:1").len(), 1);
            assert!(
                !parsed
                    .meta
                    .to_json()
                    .windows(10)
                    .any(|w| w == b"token_view")
            );
        }
    }

    #[test]
    fn accounts_must_be_ascending() {
        let mut meta = Meta::default();
        meta.evm_accounts.push(Account {
            index: 0,
            label: "중복".to_owned(),
            address: String::new(),
            hidden: false,
        });
        assert!(parse(&meta.to_json()).is_err());
    }

    /// spec/10 §13: `hw_accounts` is an optional key (spec/02 §5.3 "새 최상위 키"): absent in
    /// older files (= no `YubiKey` accounts, written back byte-identical), written after the
    /// required keys only when not the default, decoded strictly (a violation rejects the
    /// document like other keys), kept unread by an app that predates it; `prefs` may select a
    /// `YubiKey` EVM account (`{"hardware": i}`), which falls back when no such account exists.
    #[test]
    fn hw_accounts_is_an_optional_strict_key() {
        use super::HwAccounts;
        let old = Meta::default().to_json();
        assert!(
            !String::from_utf8(old.clone())
                .unwrap()
                .contains("hw_accounts")
        );
        let parsed = parse(&old).unwrap();
        assert!(parsed.meta.hw_accounts.is_default());
        assert_eq!(parsed.meta.to_json(), old);

        let mut meta = Meta {
            hw_accounts: HwAccounts {
                evm: vec![
                    Account {
                        index: 0,
                        label: "YubiKey 계정 1".to_owned(),
                        address: "0x9858effd232b4033e47d90003d41ec34ecaeda94".to_owned(),
                        hidden: false,
                    },
                    Account {
                        index: 1,
                        label: "카드 2".to_owned(),
                        address: "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0".to_owned(),
                        hidden: true,
                    },
                ],
                sol: vec![Account {
                    index: 0,
                    label: "YubiKey Solana 1".to_owned(),
                    address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned(),
                    hidden: false,
                }],
                sol_selected: Some(0),
                defaults: vec![7_700_011, 7_700_012],
            },
            ..Meta::default()
        };
        meta.prefs.evm_account = EvmAccountPref::Hardware(1);
        let bytes = meta.to_json();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.find("\"prefs\"").unwrap() < text.find("\"hw_accounts\"").unwrap());
        assert!(text.contains("\"evm_account\":{\"hardware\":1}"));
        let parsed = parse(&bytes).unwrap();
        assert!(!parsed.prefs_reset);
        assert_eq!(parsed.meta, meta);
        assert!(parsed.meta.unknown.is_empty());
        assert_eq!(parsed.meta.to_json(), bytes);

        // An app that predates the key keeps it unread and writes it back (its `prefs` naming a
        // YubiKey account resets there — accepted, spec/10 §13).
        let older = text.replacen("\"hw_accounts\"", "\"hw_accounts_next\"", 1);
        let kept = parse(older.as_bytes()).unwrap();
        assert!(kept.meta.hw_accounts.is_default());
        assert_eq!(kept.meta.unknown.len(), 1);
        assert!(kept.prefs_reset);

        // Strict inside: each violation rejects the document.
        for bad in [
            text.replacen("\"sol_selected\":0", "\"sol_selected\":5", 1),
            text.replacen("\"sol_selected\":0", "\"sol_selected\":\"0\"", 1),
            text.replacen(
                "\"defaults\":[7700011,7700012]",
                "\"defaults\":[7700012,7700011]",
                1,
            ),
            text.replacen("\"defaults\":[7700011,7700012]", "\"defaults\":[-1]", 1),
            text.replacen(",\"defaults\":[7700011,7700012]", "", 1),
            text.replacen("\"defaults\":", "\"extra\":1,\"defaults\":", 1),
            text.replacen(
                "\"index\":1,\"label\":\"카드 2\"",
                "\"index\":0,\"label\":\"카드 2\"",
                1,
            ),
            text.replacen(
                "\"address\":\"0x6fac4d18c912343bf86fa7049364dd4e424ab9c0\"",
                "\"address\":\"\"",
                1,
            ),
            text.replacen(
                "\"address\":\"HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk\"",
                "\"address\":\"0x9858effd232b4033e47d90003d41ec34ecaeda94\"",
                1,
            ),
            text.replacen(
                "\"index\":1,\"label\":\"카드 2\"",
                "\"index\":1000,\"label\":\"카드 2\"",
                1,
            ),
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
        // `prefs` naming a YubiKey account that is not listed: only `prefs` resets.
        let unlisted = text.replacen(
            "\"evm_account\":{\"hardware\":1}",
            "\"evm_account\":{\"hardware\":4}",
            1,
        );
        let parsed = parse(unlisted.as_bytes()).unwrap();
        assert!(parsed.prefs_reset);
        assert_eq!(parsed.meta.prefs.evm_account, EvmAccountPref::Index(0));
        assert_eq!(parsed.meta.hw_accounts, meta.hw_accounts);
    }
}
