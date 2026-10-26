//! The decrypted `meta.ywm` JSON (`schema = "yw-meta/3"`, spec/02 §5.3) and its `prefs` object
//! (spec/04 §6.4). yw-core only seals bytes; this module parses and writes the JSON with yw-json.
//! Unknown or duplicate keys reject the whole document (treated as `SidecarCorrupt`, E-VLT-006),
//! except `prefs`, which falls back to its default on any error.

use yw_json::{Limits, Number, Object, Value};

use crate::network::NetworkId;
use crate::text::{is_valid_label, json_object, json_object_owned, json_str, json_u64};

/// Schema tag.
pub const META_SCHEMA: &str = "yw-meta/3";
/// Derived EVM accounts bound.
pub const MAX_EVM_ACCOUNTS: usize = 100;
/// Raw EVM keys bound.
pub const MAX_RAW_ACCOUNTS: usize = 15;
const MAX_ACCOUNT_INDEX: u64 = 999;
const MAX_ADDRESS_BOOK: usize = 500;
const MAX_SITES: usize = 256;
const MAX_TOKENS_PER_NETWORK: usize = 100;
const MAX_TOKENS_TOTAL: usize = 1_000;
const MAX_ACTIVITY_PER_NETWORK: usize = 500;
const MAX_ACTIVITY_TOTAL: usize = 3_000;

const LIMITS: Limits = Limits {
    max_bytes: 8 * 1_024 * 1_024,
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

/// Selected EVM account preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmAccountPref {
    /// Derived account index.
    Index(u32),
    /// Raw key record.
    Record([u8; 16]),
}

/// `prefs` (spec/04 §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefs {
    /// Selected EVM account.
    pub evm_account: EvmAccountPref,
    /// Selected Solana account index.
    pub sol_account: u32,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            evm_account: EvmAccountPref::Index(0),
            sol_account: 0,
        }
    }
}

/// The meta document. Sections not used before M4/M5/M7/M8 are kept as validated JSON values so
/// they round-trip unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    /// Derived EVM accounts (index ascending, index 0 present).
    pub evm_accounts: Vec<Account>,
    /// Imported raw keys.
    pub evm_raw_accounts: Vec<RawAccount>,
    /// Solana accounts (M7).
    pub sol_accounts: Vec<Value>,
    /// `btc` (M8), `null` before.
    pub btc: Value,
    /// Address book.
    pub address_book: Vec<Value>,
    /// Connected sites (M5).
    pub connected_sites: Vec<Value>,
    /// Tokens per network.
    pub tokens: Vec<(String, Vec<Value>)>,
    /// Activity per network.
    pub activity: Vec<(String, Vec<Value>)>,
    /// Preferences.
    pub prefs: Prefs,
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
            sol_accounts: Vec::new(),
            btc: Value::Null,
            address_book: Vec::new(),
            connected_sites: Vec::new(),
            tokens: Vec::new(),
            activity: Vec::new(),
            prefs: Prefs::default(),
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
    /// `prefs` was invalid and reset (logged).
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
    if !is_valid_label(label) || (evm && !(address.is_empty() || is_evm_addr(address))) {
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
                    meta.evm_accounts
                        .iter()
                        .any(|account| account.index == index)
                        .then_some(EvmAccountPref::Index(index))?
                } else {
                    let id = parse_hex16(selector.get("record_id")?.as_str()?)?;
                    meta.evm_raw_accounts
                        .iter()
                        .any(|account| account.record_id == id)
                        .then_some(EvmAccountPref::Record(id))?
                };
            }
            "sol_account" => prefs.sol_account = u32::try_from(u64_of(entry)?).ok()?,
            "tab" => {
                if entry.as_str()? != "evm" {
                    return None;
                }
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
/// [`MetaError`] for any schema violation (outside `prefs`).
pub fn parse(bytes: &[u8]) -> Result<MetaParse, MetaError> {
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
    let root = yw_json::parse(bytes, &LIMITS).map_err(|_| MetaError)?;
    let object = root.as_object().ok_or(MetaError)?;
    if !exact_keys(object, &KEYS)
        || object.get("schema").and_then(Value::as_str) != Some(META_SCHEMA)
    {
        return Err(MetaError);
    }
    let get = |key: &str| object.get(key).ok_or(MetaError);
    let array = |key: &str| get(key)?.as_array().ok_or(MetaError);
    let evm_accounts: Vec<Account> = array("evm_accounts")?
        .iter()
        .map(|value| parse_account(value, true))
        .collect::<Option<_>>()
        .ok_or(MetaError)?;
    if evm_accounts.is_empty()
        || evm_accounts.len() > MAX_EVM_ACCOUNTS
        || evm_accounts.first().map(|account| account.index) != Some(0)
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
    let sol_accounts = array("sol_accounts")?.to_vec();
    if sol_accounts.len() > MAX_EVM_ACCOUNTS
        || !sol_accounts
            .iter()
            .all(|value| parse_account(value, false).is_some())
    {
        return Err(MetaError);
    }
    let btc = get("btc")?.clone();
    if !btc.is_null() && btc.as_object().is_none() {
        return Err(MetaError);
    }
    let address_book = array("address_book")?.to_vec();
    if address_book.len() > MAX_ADDRESS_BOOK || !address_book.iter().all(valid_book_entry) {
        return Err(MetaError);
    }
    let connected_sites = array("connected_sites")?.to_vec();
    if connected_sites.len() > MAX_SITES || !connected_sites.iter().all(valid_site) {
        return Err(MetaError);
    }
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
    let mut meta = Meta {
        evm_accounts,
        evm_raw_accounts,
        sol_accounts,
        btc,
        address_book,
        connected_sites,
        tokens,
        activity,
        prefs: Prefs::default(),
    };
    let prefs = parse_prefs(get("prefs")?, &meta);
    let prefs_reset = prefs.is_none();
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
    /// Serializes in the spec/02 §5.3 key order.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        let evm_account = match self.prefs.evm_account {
            EvmAccountPref::Index(index) => {
                json_object(vec![("index", json_u64(u64::from(index)))])
            }
            EvmAccountPref::Record(id) => {
                json_object(vec![("record_id", json_str(&yw_core::hex::encode(&id)))])
            }
        };
        let root = json_object(vec![
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
            ("sol_accounts", Value::Array(self.sol_accounts.clone())),
            ("btc", self.btc.clone()),
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
                    ("tab", json_str("evm")),
                ]),
            ),
        ]);
        yw_json::to_vec(&root)
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

    /// Removes a user token.
    pub fn remove_token(&mut self, network: &str, address: &str) {
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
    use super::{Account, EvmAccountPref, Meta, parse};

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
    fn unknown_keys_and_bad_accounts_are_rejected() {
        let good = String::from_utf8(Meta::default().to_json()).unwrap();
        let unknown = good.replacen("\"btc\":null", "\"btc\":null,\"extra\":1", 1);
        assert!(parse(unknown.as_bytes()).is_err());
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
}
