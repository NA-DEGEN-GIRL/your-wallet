//! The decrypted `meta.ywm` JSON (`schema = "yw-meta/3"`, spec/02 §5.3) and its `prefs` object
//! (spec/04 §6.4). yw-core only seals bytes; this module parses and writes the JSON with yw-json.
//! Duplicate keys, a missing known key or an invalid value reject the whole document (treated as
//! `SidecarCorrupt`, E-VLT-006), except `prefs`, which falls back to its default on any error.
//! Unknown top-level keys (a newer minor version's) are kept and written back after the known keys
//! (spec/04 §6.6, spec/02 §5.3). The imported-key keys (`sol_raw_accounts`, `sol_raw_selected`)
//! are optional on read (files written before key import lack them) and always written after
//! `prefs`; `btc_accounts` (spec/08 §12.3a) is optional too and written last. Imported Bitcoin
//! keys have no list of their own: each is a single-key account in `btc_accounts`. The optional
//! `token_view` (hidden token rows, `crate::token_view`) is written only when not the default and
//! falls back to the default when invalid, like `prefs`.

use yw_core::btc::meta::{BtcAccounts, BtcMeta, btc_meta_from_json, btc_meta_to_json};
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
}

impl Tab {
    /// The meta string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Sol => "sol",
            Self::Btc => "btc",
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
    /// Address book.
    pub address_book: Vec<Value>,
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
            connected_sites: Vec::new(),
            chain_sites: Box::default(),
            tokens: Vec::new(),
            activity: Vec::new(),
            prefs: Prefs::default(),
            security: Box::default(),
            token_view: Box::default(),
            hw_accounts: HwAccounts::default(),
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
                && *key != SOL_SITES_KEY
                && *key != BTC_SITES_KEY
                && *key != SECURITY_KEY
                && *key != VAULT_SEEN_KEY
                && *key != TOKEN_VIEW_KEY
                && *key != HW_ACCOUNTS_KEY
                && *key != crate::walletconnect::store::META_KEY
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
    let btc = btc_meta_from_json(get("btc")?)
        .map_err(|_| MetaError)?
        .map(Box::new);
    let btc_accounts =
        BtcAccounts::from_json(object.get(BTC_ACCOUNTS_KEY)).map_err(|_| MetaError)?;
    let address_book = array("address_book")?.to_vec();
    if address_book.len() > MAX_ADDRESS_BOOK || !address_book.iter().all(valid_book_entry) {
        return Err(MetaError);
    }
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
    // A view preference: an invalid value falls back to the default like `prefs`.
    let (token_view, token_view_reset) = match object.get(TOKEN_VIEW_KEY) {
        None => (TokenView::default(), false),
        Some(value) => {
            TokenView::from_json(value).map_or((TokenView::default(), true), |view| (view, false))
        }
    };
    let hw_accounts = HwAccounts::from_json(object.get(HW_ACCOUNTS_KEY)).ok_or(MetaError)?;
    let mut meta = Meta {
        evm_accounts,
        evm_raw_accounts,
        sol_raw_accounts,
        sol_raw_selected,
        sol_accounts,
        btc,
        btc_accounts,
        address_book,
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
        }),
        token_view: Box::new(token_view),
        hw_accounts,
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

    #[expect(clippy::too_many_lines, reason = "one member per key of spec/02 §5.3")]
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
        };
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
            ("btc", btc_meta_to_json(self.btc.as_deref())),
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
        if self.btc_accounts != BtcAccounts::default() {
            members.push((BTC_ACCOUNTS_KEY, self.btc_accounts.to_json()));
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
        if !self.token_view.is_default() {
            members.push((TOKEN_VIEW_KEY, self.token_view.to_json()));
        }
        if !self.hw_accounts.is_default() {
            members.push((HW_ACCOUNTS_KEY, self.hw_accounts.to_json()));
        }
        if let Some(walletconnect) = &self.chain_sites.walletconnect {
            members.push((crate::walletconnect::store::META_KEY, walletconnect.clone()));
        }
        members
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
        self.address_book.retain(|value| {
            SolBookEntry::from_value(value).is_none_or(|known| known.address != address)
        });
    }

    /// Removes the EVM entry for `address`.
    pub fn remove_book(&mut self, address: &str) {
        self.address_book.retain(|value| {
            BookEntry::from_value(value).is_none_or(|known| known.address != address)
        });
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
        Account, EvmAccountPref, Meta, RawAccount, SolBookEntry, SolRawAccount, Tab, parse,
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
        assert_eq!(text.matches("\"single_address\":false").count(), 1);
        assert!(text.contains("\"key\":{\"evm\":{\"index\":2,"));
        let back = parse(&bytes).unwrap().meta;
        assert_eq!(back, hd);
        assert!(back.btc.as_deref().unwrap().fixed_address());
        assert!(!back.btc_accounts.accounts[0].fixed_address());
        assert!(back.btc_accounts.accounts[1].is_single());
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
