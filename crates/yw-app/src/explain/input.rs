//! The model input `yw.explain.input.v1` (spec/06 §4.3–§4.4) and the trusted sets of §5.3.
//!
//! Everything comes from the wallet's own decoding ([`DecodedTx`], [`DecodedPersonalMessage`],
//! [`DecodedTypedData`]) and the simulation status; the dApp's raw JSON and the raw calldata are
//! never included. Strings the wallet did not choose (origin, RPC token names and symbols,
//! EIP-712 domain and string fields, unknown-schema type and field names, SIWE fields, the
//! personal-sign text) are wrapped as `{"untrusted": …}`, cleaned, capped per field and in total,
//! and never contribute to the trusted sets. The trusted sets are recorded while the JSON is
//! built (the JSON is never re-parsed for them).

use std::collections::{BTreeMap, BTreeSet};

use yw_core::approval::{ChainFacts, SimNoneReason, SimVerdict, is_forbidden_display_char};
use yw_core::evm::abi::AbiValue;
use yw_core::evm::address::Address;
use yw_core::evm::amount::{Delta, U256, format_units};
use yw_core::evm::chain::{ChainInfo, TokenRole};
use yw_core::evm::decode::{DecodedCall, DecodedTx, MAX_MULTICALL_INNER};
use yw_core::evm::eip191::DecodedPersonalMessage;
use yw_core::evm::eip712::{DecodedTypedData, KnownSchema, TdNode, TdValue};
use yw_core::evm::simulate::{ApprovalKindEvm, AssetId, SimResult, SimulationDiff};
use yw_json::{Number, Value};

use super::{ExplainError, UNTRUSTED_TOTAL_SCALARS};
use crate::text::{json_object, json_str};

/// Schema tag of the input.
pub const INPUT_SCHEMA: &str = "yw.explain.input.v1";
const MAX_ASSETS: usize = 16;
const MAX_CHANGES: usize = 32;
const MAX_APPROVALS: usize = 16;
const MAX_TRANSFERS: usize = 32;
const MAX_FIELDS: usize = 64;
const MAX_RESOURCES: usize = 8;
const CAP_ORIGIN: usize = 256;
const CAP_SYMBOL: usize = 32;
const CAP_TEXT: usize = 2_048;
const CAP_STATEMENT: usize = 512;
const CAP_SIWE: usize = 256;
const CAP_DOMAIN: usize = 64;
const CAP_PATH: usize = 128;
const CAP_STRING: usize = 128;
const UNLIMITED: &str = "무제한";

/// The simulation status of an EVM transaction (§4.3 `simulation.status`).
#[derive(Clone, Copy, Debug)]
pub enum ExplainSim<'a> {
    /// Simulated and interpreted: the diff is included.
    Success(&'a SimulationDiff),
    /// The chain is `simulation = unsupported`; no call was made.
    Unsupported,
    /// No result (transport, timeout, RPC error, malformed).
    Unavailable,
    /// The simulated call reverted.
    Reverted,
    /// A response arrived but did not pass the spec/03 §6 checks.
    Incomplete,
}

impl<'a> ExplainSim<'a> {
    /// Maps a preparation result to the five statuses; `None` for a request blocked before
    /// simulation (`Skipped`), which is not explained.
    #[must_use]
    pub fn of(sim: &'a SimResult) -> Option<Self> {
        Some(match sim {
            SimResult::Simulated {
                verdict: SimVerdict::Ok,
                diff,
                ..
            } => Self::Success(diff),
            SimResult::Simulated {
                verdict: SimVerdict::Reverted,
                ..
            } => Self::Reverted,
            SimResult::Simulated {
                verdict: SimVerdict::Incomplete,
                ..
            } => Self::Incomplete,
            SimResult::Unavailable {
                reason: SimNoneReason::Skipped,
                ..
            } => return None,
            SimResult::Unavailable {
                reason: SimNoneReason::Unsupported,
                ..
            } => Self::Unsupported,
            SimResult::Unavailable { .. } => Self::Unavailable,
        })
    }

    const fn status(self) -> &'static str {
        match self {
            Self::Success(_) => "success",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::Reverted => "reverted",
            Self::Incomplete => "incomplete",
        }
    }
}

/// What is explained (§3.1). `origin` and `user` are common arguments of [`build_input`].
#[derive(Clone, Copy, Debug)]
pub enum ExplainSource<'a> {
    /// `eth_sendTransaction` after the simulation step.
    EvmTx(&'a DecodedTx, ExplainSim<'a>),
    /// `personal_sign` (SIWE included).
    PersonalSign(&'a DecodedPersonalMessage),
    /// `eth_signTypedData_v4`.
    TypedData(&'a DecodedTypedData),
}

/// The request kind (`request` and the log's `kind=`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    /// `evm_tx`.
    EvmTx,
    /// `personal_sign`.
    PersonalSign,
    /// `typed_data_v4`.
    TypedData,
}

impl RequestKind {
    /// The `request` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvmTx => "evm_tx",
            Self::PersonalSign => "personal_sign",
            Self::TypedData => "typed_data_v4",
        }
    }
}

/// The trusted sets of §5.3: values written outside `{"untrusted": …}`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TrustedSets {
    /// `A`: addresses.
    pub(crate) addresses: BTreeSet<[u8; 20]>,
    /// `H`: other hex values (lowercase, `0x` prefix).
    pub(crate) hex: BTreeSet<String>,
    /// `M`: `norm` of every Amount `raw`/`display`, and `무제한`.
    pub(crate) amounts: BTreeSet<String>,
    /// `D`: `tokens()` of every trusted string and number.
    pub(crate) numbers: BTreeSet<String>,
    /// `S`: `assets[].asset_id`.
    pub(crate) assets: BTreeSet<String>,
    /// Display symbols: `native` → chain symbol, registry token → registry symbol (§6).
    pub(crate) symbols: BTreeMap<String, String>,
}

impl core::fmt::Debug for TrustedSets {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TrustedSets")
            .field("addresses", &self.addresses.len())
            .field("hex", &self.hex.len())
            .field("amounts", &self.amounts.len())
            .field("numbers", &self.numbers.len())
            .field("assets", &self.assets.len())
            .field("symbols", &self.symbols.len())
            .finish()
    }
}

impl TrustedSets {
    /// Whether `address` is in `A`.
    #[must_use]
    pub fn has_address(&self, address: &[u8; 20]) -> bool {
        self.addresses.contains(address)
    }

    /// Whether the normalized `amount` is in `M`.
    #[must_use]
    pub fn has_amount(&self, normalized: &str) -> bool {
        self.amounts.contains(normalized)
    }

    /// Whether the normalized number is in `D` or `M`.
    #[must_use]
    pub fn has_number(&self, normalized: &str) -> bool {
        self.numbers.contains(normalized) || self.amounts.contains(normalized)
    }

    /// Whether the lowercase hex value is in `H`.
    #[must_use]
    pub fn has_hex(&self, lower: &str) -> bool {
        self.hex.contains(lower)
    }

    /// Whether `asset_id` (`native` or a lowercase address) is in `S`.
    #[must_use]
    pub fn has_asset(&self, asset_id: &str) -> bool {
        self.assets.contains(asset_id)
    }

    /// The trusted display symbol of an asset id.
    #[must_use]
    pub fn symbol(&self, asset_id: &str) -> Option<&str> {
        self.symbols.get(asset_id).map(String::as_str)
    }
}

/// A built input: the JSON bytes sent as the user message, and its trusted sets. `Debug` prints
/// sizes only (the JSON can carry signed-message text, D28).
#[derive(Clone, PartialEq, Eq)]
pub struct ExplainInput {
    json: Vec<u8>,
    trusted: TrustedSets,
    kind: RequestKind,
}

impl core::fmt::Debug for ExplainInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ExplainInput")
            .field("kind", &self.kind)
            .field("json_bytes", &self.json.len())
            .field("trusted", &self.trusted)
            .finish()
    }
}

#[cfg(test)]
impl ExplainInput {
    /// An input with exactly `json` (body-size boundary tests).
    pub(crate) const fn raw(json: Vec<u8>, kind: RequestKind) -> Self {
        Self {
            json,
            trusted: TrustedSets {
                addresses: BTreeSet::new(),
                hex: BTreeSet::new(),
                amounts: BTreeSet::new(),
                numbers: BTreeSet::new(),
                assets: BTreeSet::new(),
                symbols: BTreeMap::new(),
            },
            kind,
        }
    }
}

impl ExplainInput {
    /// The JSON bytes.
    #[must_use]
    pub fn json(&self) -> &[u8] {
        &self.json
    }

    /// The trusted sets.
    #[must_use]
    pub const fn trusted(&self) -> &TrustedSets {
        &self.trusted
    }

    /// The request kind.
    #[must_use]
    pub const fn kind(&self) -> RequestKind {
        self.kind
    }
}

/// `norm(s)` of §5.3: drop ASCII whitespace and `,`, a leading `+`/`-`, and, when there is a
/// `.`, trailing `0`s and a trailing `.`.
#[must_use]
pub fn norm(text: &str) -> String {
    let mut out: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != ',')
        .collect();
    if out.starts_with(['+', '-']) {
        out.remove(0);
    }
    if out.contains('.') {
        let trimmed = out.trim_end_matches('0').trim_end_matches('.').len();
        out.truncate(trimmed);
    }
    out
}

/// The `0x[0-9A-Fa-f]+` tokens of `text` (byte ranges).
#[must_use]
pub fn hex_tokens(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        let is_start = bytes.get(index) == Some(&b'0')
            && bytes.get(index.saturating_add(1)) == Some(&b'x')
            && bytes
                .get(index.saturating_add(2))
                .is_some_and(u8::is_ascii_hexdigit);
        if is_start {
            let mut end = index.saturating_add(2);
            while bytes.get(end).is_some_and(u8::is_ascii_hexdigit) {
                end = end.saturating_add(1);
            }
            out.push((index, end));
            index = end;
        } else {
            index = index.saturating_add(1);
        }
    }
    out
}

/// The raw number tokens `[0-9][0-9,]*(\.[0-9]+)?` of `text` after removing hex tokens.
#[must_use]
pub fn number_tokens(text: &str) -> Vec<String> {
    let mut cleaned = String::with_capacity(text.len());
    let mut cursor = 0_usize;
    for (start, end) in hex_tokens(text) {
        cleaned.push_str(text.get(cursor..start).unwrap_or(""));
        cleaned.push(' ');
        cursor = end;
    }
    cleaned.push_str(text.get(cursor..).unwrap_or(""));
    let bytes = cleaned.as_bytes();
    let mut out = Vec::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        if !bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index = index.saturating_add(1);
            continue;
        }
        let start = index;
        index = index.saturating_add(1);
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b',')
        {
            index = index.saturating_add(1);
        }
        if bytes.get(index) == Some(&b'.')
            && bytes
                .get(index.saturating_add(1))
                .is_some_and(u8::is_ascii_digit)
        {
            index = index.saturating_add(1);
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index = index.saturating_add(1);
            }
        }
        out.push(cleaned.get(start..index).unwrap_or("").to_owned());
    }
    out
}

/// `tokens(s)` of §5.3: the normalized number tokens.
#[must_use]
pub fn tokens(text: &str) -> Vec<String> {
    number_tokens(text)
        .iter()
        .map(|token| norm(token))
        .collect()
}

/// Untrusted text cleaning (§4.4 ①): CRLF → LF, display-forbidden characters and controls other
/// than LF → U+FFFD.
#[must_use]
pub fn clean_untrusted(text: &str) -> String {
    text.replace("\r\n", "\n")
        .chars()
        .map(|character| {
            if character == '\n' {
                character
            } else if character.is_control() || is_forbidden_display_char(character) {
                '\u{FFFD}'
            } else {
                character
            }
        })
        .collect()
}

/// `raw / 10^decimals` exactly, without separators (§4.3 Amount `display`).
fn plain_units(value: &U256, decimals: u8) -> String {
    format_units(value, decimals).replace(',', "")
}

fn utc_display(seconds: u64) -> Option<String> {
    if seconds >= 1_u64 << 40 {
        return None;
    }
    let text = crate::logging::format_utc(seconds.checked_mul(1_000)?);
    let date_time = text.get(..19)?.replace('T', " ");
    Some(format!("{date_time} UTC"))
}

struct Asset {
    id: String,
    address: Option<Address>,
    standard: &'static str,
}

struct Builder<'a> {
    chain: &'a ChainInfo,
    facts: &'a ChainFacts,
    trusted: TrustedSets,
    untrusted_used: usize,
    exhausted: bool,
    assets: Vec<Asset>,
}

impl<'a> Builder<'a> {
    fn new(chain: &'a ChainInfo, facts: &'a ChainFacts) -> Self {
        Self {
            chain,
            facts,
            trusted: TrustedSets::default(),
            untrusted_used: 0,
            exhausted: false,
            assets: Vec::new(),
        }
    }

    /// A trusted fixed or wallet-made string (its numbers go to `D`).
    fn text(&mut self, text: &str) -> Value {
        self.digits(text);
        json_str(text)
    }

    fn digits(&mut self, text: &str) {
        for token in tokens(text) {
            self.trusted.numbers.insert(token);
        }
    }

    fn number(&mut self, value: u64) -> Value {
        self.trusted.numbers.insert(value.to_string());
        Value::Number(Number::from_u64(value))
    }

    fn decimal(&mut self, value: &U256) -> Value {
        let text = value.to_decimal_string();
        self.text(&text)
    }

    fn address(&mut self, address: &Address) -> Value {
        self.trusted.addresses.insert(*address.as_bytes());
        json_str(&address.to_lower_hex())
    }

    fn hex(&mut self, bytes: &[u8]) -> Value {
        let text = format!("0x{}", yw_core::hex::encode(bytes));
        self.trusted.hex.insert(text.clone());
        json_str(&text)
    }

    fn amount(
        &mut self,
        value: &U256,
        negative: bool,
        decimals: Option<u8>,
        unlimited: bool,
    ) -> Value {
        let digits = value.to_decimal_string();
        let sign = if negative && !value.is_zero() {
            "-"
        } else {
            ""
        };
        let raw = format!("{sign}{digits}");
        let display = if unlimited {
            UNLIMITED.to_owned()
        } else {
            let plain = decimals.map_or_else(|| digits.clone(), |d| plain_units(value, d));
            format!("{sign}{plain}")
        };
        self.trusted.amounts.insert(norm(&raw));
        self.trusted.amounts.insert(norm(&display));
        self.digits(&raw);
        self.digits(&display);
        json_object(vec![
            ("raw", json_str(&raw)),
            ("display", json_str(&display)),
            ("unlimited", Value::Bool(unlimited)),
        ])
    }

    /// `{"untrusted": …}` with §4.4 cleaning, the field cap and the request budget.
    fn untrusted(&mut self, text: &str, cap: usize) -> Value {
        let cleaned = clean_untrusted(text);
        let mut characters: Vec<char> = cleaned.chars().collect();
        let mut truncated = false;
        if characters.len() > cap {
            characters.truncate(cap);
            truncated = true;
        }
        if self.exhausted
            || self.untrusted_used.saturating_add(characters.len()) > UNTRUSTED_TOTAL_SCALARS
        {
            self.exhausted = true;
            characters.clear();
            truncated = true;
        }
        self.untrusted_used = self.untrusted_used.saturating_add(characters.len());
        let text: String = characters.into_iter().collect();
        let mut pairs = vec![("untrusted", json_str(&text))];
        if truncated {
            pairs.push(("truncated", Value::Bool(true)));
        }
        json_object(pairs)
    }

    fn registry(&self, address: &Address) -> Option<&'static yw_core::evm::chain::KnownToken> {
        self.chain
            .tokens
            .iter()
            .find(|token| token.address == *address)
    }

    fn decimals_of(&self, address: &Address) -> Option<u8> {
        self.registry(address)
            .map(|token| token.decimals)
            .or_else(|| {
                self.facts
                    .tokens
                    .iter()
                    .find(|(token, _)| token == address)
                    .and_then(|(_, meta)| meta.decimals)
            })
    }

    fn wrapped_symbol(&self) -> &'static str {
        self.chain
            .tokens
            .iter()
            .find(|token| token.role == TokenRole::Weth)
            .map_or("WETH", |token| token.symbol)
    }

    fn label(&mut self, title: &str) -> Value {
        let label = title
            .replace("{native}", &self.chain.native_symbol)
            .replace("{wrapped}", self.wrapped_symbol());
        self.text(&label)
    }

    fn add_native(&mut self) {
        if !self.assets.iter().any(|asset| asset.id == "native") {
            self.trusted.assets.insert("native".to_owned());
            self.trusted
                .symbols
                .insert("native".to_owned(), self.chain.native_symbol.clone());
            self.assets.insert(
                0,
                Asset {
                    id: "native".to_owned(),
                    address: None,
                    standard: "native",
                },
            );
        }
    }

    fn add_token(&mut self, address: &Address, standard: &'static str) {
        let id = address.to_lower_hex();
        if let Some(existing) = self.assets.iter_mut().find(|asset| asset.id == id) {
            if existing.standard == "unknown" {
                existing.standard = standard;
            }
            return;
        }
        if self.assets.len() >= MAX_ASSETS {
            return;
        }
        self.trusted.assets.insert(id.clone());
        self.trusted.addresses.insert(*address.as_bytes());
        if let Some(token) = self.registry(address) {
            self.trusted
                .symbols
                .insert(id.clone(), token.symbol.to_owned());
        }
        self.assets.push(Asset {
            id,
            address: Some(*address),
            standard,
        });
    }

    fn asset_id(&mut self, asset: &AssetId, standard: &'static str) -> Value {
        match asset {
            AssetId::Native => {
                self.add_native();
                json_str("native")
            }
            AssetId::Token(address) => {
                self.add_token(address, standard);
                self.address(address)
            }
        }
    }

    fn assets_value(&mut self) -> Value {
        let assets = core::mem::take(&mut self.assets);
        let mut out = Vec::with_capacity(assets.len());
        for asset in &assets {
            let value = match asset.address {
                None => {
                    let symbol = self.chain.native_symbol.clone();
                    let decimals = self.chain.native_decimals;
                    let pairs = vec![
                        ("asset_id", json_str("native")),
                        ("standard", json_str("native")),
                        ("symbol", self.text(&symbol)),
                        ("name", Value::Null),
                        ("decimals", self.number(u64::from(decimals))),
                        ("in_registry", Value::Bool(true)),
                    ];
                    json_object(pairs)
                }
                Some(address) => {
                    let registry = self.registry(&address);
                    let symbol = match registry {
                        Some(token) => self.text(token.symbol),
                        None => match self
                            .facts
                            .tokens
                            .iter()
                            .find(|(token, _)| *token == address)
                            .and_then(|(_, meta)| meta.symbol.clone())
                        {
                            Some(symbol) => self.untrusted(&symbol, CAP_SYMBOL),
                            None => Value::Null,
                        },
                    };
                    let decimals = match self.decimals_of(&address) {
                        Some(decimals) => self.number(u64::from(decimals)),
                        None => Value::Null,
                    };
                    let id = self.address(&address);
                    let standard = self.text(asset.standard);
                    json_object(vec![
                        ("asset_id", id),
                        ("standard", standard),
                        ("symbol", symbol),
                        ("name", Value::Null),
                        ("decimals", decimals),
                        ("in_registry", Value::Bool(registry.is_some())),
                    ])
                }
            };
            out.push(value);
        }
        self.assets = assets;
        Value::Array(out)
    }

    // ----- EVM transactions --------------------------------------------------------------

    fn arg(&mut self, kind: &str, name: &str, value: &AbiValue, token: Option<&Address>) -> Value {
        let (type_name, rendered) = self.abi_value(kind, name, value, token);
        let name = self.text(name);
        let type_name = self.text(type_name);
        json_object(vec![
            ("name", name),
            ("type", type_name),
            ("value", rendered),
        ])
    }

    fn abi_value(
        &mut self,
        kind: &str,
        name: &str,
        value: &AbiValue,
        token: Option<&Address>,
    ) -> (&'static str, Value) {
        match value {
            AbiValue::Address(address) => ("address", self.address(address)),
            AbiValue::Uint(number) => {
                let amount_arg = matches!(name, "amount" | "added" | "subtracted")
                    || (kind == "erc2612_permit_submit" && name == "value");
                if amount_arg {
                    let fungible = kind.starts_with("erc20")
                        || kind.starts_with("weth")
                        || kind.starts_with("permit2")
                        || kind == "erc2612_permit_submit";
                    let decimals = if fungible {
                        token.and_then(|token| self.decimals_of(token))
                    } else {
                        None
                    };
                    let unlimited = *number == U256::MAX
                        || (kind.starts_with("permit2") && *number == U256::MAX_U160);
                    ("uint", self.amount(number, false, decimals, unlimited))
                } else {
                    ("uint", self.decimal(number))
                }
            }
            AbiValue::Bool(flag) => ("bool", Value::Bool(*flag)),
            AbiValue::Bytes(bytes) if bytes.len() <= 32 => ("bytes", self.hex(bytes)),
            AbiValue::Bytes(bytes) => (
                "bytes",
                json_object(vec![(
                    "hex_len",
                    self.number(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
                )]),
            ),
            AbiValue::Bytes32(bytes) => ("bytes32", self.hex(bytes)),
            AbiValue::Array(items) | AbiValue::Tuple(items) => {
                let type_name = if matches!(value, AbiValue::Array(_)) {
                    "array"
                } else {
                    "tuple"
                };
                let rendered = items
                    .iter()
                    .take(MAX_FIELDS)
                    .map(|item| self.abi_value(kind, name, item, token).1)
                    .collect();
                (type_name, Value::Array(rendered))
            }
        }
    }

    fn token_standard(kind: &str) -> Option<&'static str> {
        if kind.starts_with("erc20") || kind.starts_with("weth") || kind.ends_with("permit_submit")
        {
            Some("erc20")
        } else if kind.starts_with("erc721") {
            Some("erc721")
        } else if kind.starts_with("erc1155") {
            Some("erc1155")
        } else if kind == "set_approval_for_all" {
            Some("unknown")
        } else {
            None
        }
    }

    fn call_value(&mut self, call: &DecodedCall, to: &Address) -> Value {
        match call {
            DecodedCall::NativeTransfer => {
                let label = self.label("{native} 보내기");
                json_object(vec![
                    ("kind", self.text("native_transfer")),
                    ("label", label),
                    ("args", Value::Array(Vec::new())),
                ])
            }
            DecodedCall::Known { kind, title, args } => {
                if let Some(standard) = Self::token_standard(kind) {
                    self.add_token(to, standard);
                }
                let token = if kind.starts_with("permit2") {
                    let found = args.iter().find_map(|(name, value)| match value {
                        AbiValue::Address(address) if *name == "token" => Some(*address),
                        _ => None,
                    });
                    if let Some(address) = found {
                        self.add_token(&address, "erc20");
                    }
                    found
                } else {
                    Some(*to)
                };
                let label = self.label(title);
                let args = args
                    .iter()
                    .map(|(name, value)| self.arg(kind, name, value, token.as_ref()))
                    .collect();
                json_object(vec![
                    ("kind", self.text(kind)),
                    ("label", label),
                    ("args", Value::Array(args)),
                ])
            }
            DecodedCall::Multicall { kind, head, .. } => {
                let label = self.label("묶음 호출");
                let args = head
                    .iter()
                    .map(|(name, value)| self.arg(kind, name, value, Some(to)))
                    .collect();
                json_object(vec![
                    ("kind", self.text(kind)),
                    ("label", label),
                    ("args", Value::Array(args)),
                ])
            }
            DecodedCall::Uninterpreted { .. } => Value::Null,
        }
    }

    fn tx_value(&mut self, decoded: &DecodedTx) -> Value {
        let tx = &decoded.tx;
        self.add_native();
        let to = self.address(&tx.to);
        let value = self.amount(&tx.value, false, Some(self.chain.native_decimals), false);
        let selector = match tx.data.get(..4) {
            Some(bytes) => self.hex(bytes),
            None => Value::Null,
        };
        let calldata_len = self.number(u64::try_from(tx.data.len()).unwrap_or(u64::MAX));
        let call = self.call_value(&decoded.call, &tx.to);
        let inner: Vec<Value> = match &decoded.call {
            DecodedCall::Multicall { inner, .. } => inner
                .iter()
                .take(MAX_MULTICALL_INNER)
                .map(|call| self.call_value(call, &tx.to))
                .collect(),
            _ => Vec::new(),
        };
        json_object(vec![
            ("to", to),
            ("value", value),
            ("selector", selector),
            ("calldata_len", calldata_len),
            ("call", call),
            ("inner_calls", Value::Array(inner)),
        ])
    }

    fn token_id(&mut self, token_id: Option<&U256>) -> Value {
        match token_id {
            Some(id) => self.decimal(id),
            None => Value::Null,
        }
    }

    fn token_decimals(&self, asset: &AssetId, token_id: Option<&U256>) -> Option<u8> {
        match (asset, token_id) {
            (AssetId::Native, _) => Some(self.chain.native_decimals),
            (AssetId::Token(address), None) => self.decimals_of(address),
            (AssetId::Token(_), Some(_)) => None,
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the three diff arrays of §4.3 in order"
    )]
    fn simulation_value(&mut self, sim: ExplainSim<'_>) -> Value {
        let status = json_str(sim.status());
        let ExplainSim::Success(diff) = sim else {
            return json_object(vec![
                ("status", status),
                ("block", Value::Null),
                ("changes", Value::Null),
                ("approvals", Value::Null),
                ("transfers", Value::Null),
                ("truncated", Value::Null),
            ]);
        };
        let mut truncated = diff.omitted_rows > 0;
        let block = self.number(diff.block.number);
        let mut changes = Vec::new();
        for change in &diff.changes {
            if changes.len() >= MAX_CHANGES {
                truncated = true;
                break;
            }
            let standard = if change.token_id.is_some() {
                "unknown"
            } else {
                "erc20"
            };
            let asset = self.asset_id(&change.asset, standard);
            let token_id = self.token_id(change.token_id.as_ref());
            let decimals = self.token_decimals(&change.asset, change.token_id.as_ref());
            let delta = match change.delta {
                Some(Delta::Zero) => continue,
                Some(Delta::In(value)) => self.amount(&value, false, decimals, false),
                Some(Delta::Out(value)) => self.amount(&value, true, decimals, false),
                None => Value::Null,
            };
            changes.push(json_object(vec![
                ("asset_id", asset),
                ("token_id", token_id),
                ("delta", delta),
            ]));
        }
        let mut approvals = Vec::new();
        for approval in &diff.approvals {
            if approvals.len() >= MAX_APPROVALS {
                truncated = true;
                break;
            }
            let (standard, amount, all) = match approval.kind {
                ApprovalKindEvm::Erc20 { amount } => {
                    let decimals = self.decimals_of(&approval.asset);
                    let unlimited = amount == U256::MAX;
                    (
                        "erc20",
                        Some(self.amount(&amount, false, decimals, unlimited)),
                        false,
                    )
                }
                ApprovalKindEvm::Erc721 { .. } => ("erc721", None, false),
                ApprovalKindEvm::ForAll { approved } => ("unknown", None, approved),
                ApprovalKindEvm::Permit2 { amount, .. } => {
                    let decimals = self.decimals_of(&approval.asset);
                    let unlimited = amount == U256::MAX_U160;
                    (
                        "erc20",
                        Some(self.amount(&amount, false, decimals, unlimited)),
                        false,
                    )
                }
                ApprovalKindEvm::Permit2Lockdown => ("erc20", None, false),
            };
            let asset = self.asset_id(&AssetId::Token(approval.asset), standard);
            let spender = self.address(&approval.spender);
            approvals.push(json_object(vec![
                ("asset_id", asset),
                ("spender", spender),
                ("amount", amount.unwrap_or(Value::Null)),
                ("all", Value::Bool(all)),
            ]));
        }
        let mut transfers = Vec::new();
        for transfer in &diff.transfers {
            if transfers.len() >= MAX_TRANSFERS {
                truncated = true;
                break;
            }
            let standard = if transfer.token_id.is_some() {
                "unknown"
            } else {
                "erc20"
            };
            let asset = self.asset_id(&transfer.asset, standard);
            let token_id = self.token_id(transfer.token_id.as_ref());
            let from = self.address(&transfer.from);
            let to = self.address(&transfer.to);
            let decimals = self.token_decimals(&transfer.asset, transfer.token_id.as_ref());
            let amount = self.amount(&transfer.amount, false, decimals, false);
            transfers.push(json_object(vec![
                ("asset_id", asset),
                ("token_id", token_id),
                ("from", from),
                ("to", to),
                ("amount", amount),
            ]));
        }
        json_object(vec![
            ("status", status),
            ("block", block),
            ("changes", Value::Array(changes)),
            ("approvals", Value::Array(approvals)),
            ("transfers", Value::Array(transfers)),
            ("truncated", Value::Bool(truncated)),
        ])
    }

    // ----- personal_sign ---------------------------------------------------------------------

    fn message_value(&mut self, message: &DecodedPersonalMessage) -> Value {
        let raw = core::str::from_utf8(&message.bytes).ok();
        let bytes_len = self.number(u64::try_from(message.bytes.len()).unwrap_or(u64::MAX));
        let text = match raw {
            Some(text) => self.untrusted(text, CAP_TEXT),
            None => Value::Null,
        };
        let siwe = match &message.siwe {
            Some(siwe) => {
                let domain = self.untrusted(&siwe.domain, CAP_SIWE);
                let address = self.address(&siwe.address);
                let statement = match &siwe.statement {
                    Some(statement) => self.untrusted(statement, CAP_STATEMENT),
                    None => Value::Null,
                };
                let uri = self.untrusted(&siwe.uri, CAP_SIWE);
                let chain_id = self.number(siwe.chain_id);
                let issued_at = self.text(&siwe.issued_at_text);
                let expiration_time = match &siwe.expiration_time_text {
                    Some(text) => self.text(text),
                    None => Value::Null,
                };
                let resources = siwe
                    .resources
                    .iter()
                    .take(MAX_RESOURCES)
                    .map(|resource| self.untrusted(resource, CAP_SIWE))
                    .collect();
                json_object(vec![
                    ("domain", domain),
                    ("address", address),
                    ("statement", statement),
                    ("uri", uri),
                    ("chain_id", chain_id),
                    ("issued_at", issued_at),
                    ("expiration_time", expiration_time),
                    ("resources", Value::Array(resources)),
                ])
            }
            None => Value::Null,
        };
        json_object(vec![
            ("utf8", Value::Bool(raw.is_some())),
            ("bytes_len", bytes_len),
            ("text", text),
            ("siwe", siwe),
        ])
    }

    // ----- typed data ------------------------------------------------------------------------

    fn typed_value(&mut self, typed: &DecodedTypedData) -> Value {
        let schema = typed.schema.as_ref();
        let known = schema.is_some();
        let schema_id = schema.map_or(Value::Null, |schema| self.text(schema.schema_id()));
        let name = match &typed.domain.name {
            Some(name) => self.untrusted(name, CAP_DOMAIN),
            None => Value::Null,
        };
        let version = match &typed.domain.version {
            Some(version) => self.untrusted(version, CAP_DOMAIN),
            None => Value::Null,
        };
        let chain_id = match &typed.domain.chain_id {
            Some(id) => self.decimal(id),
            None => Value::Null,
        };
        let verifying = match &typed.domain.verifying_contract {
            Some(address) => {
                if matches!(schema, Some(KnownSchema::Eip2612Permit)) {
                    self.add_token(address, "erc20");
                }
                self.address(address)
            }
            None => Value::Null,
        };
        let primary = if known {
            self.text(&typed.primary_type)
        } else {
            self.untrusted(&typed.primary_type, CAP_PATH)
        };
        let mut fields = Vec::new();
        let mut truncated = false;
        self.walk(
            typed,
            &typed.root,
            "",
            "",
            None,
            &mut fields,
            &mut truncated,
        );
        json_object(vec![
            ("schema_id", schema_id),
            (
                "domain",
                json_object(vec![
                    ("name", name),
                    ("version", version),
                    ("chain_id", chain_id),
                    ("verifying_contract", verifying),
                ]),
            ),
            ("primary_type", primary),
            ("fields", Value::Array(fields)),
            ("fields_truncated", Value::Bool(truncated)),
        ])
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one recursive walk with its context"
    )]
    fn walk(
        &mut self,
        typed: &DecodedTypedData,
        node: &TdNode,
        path: &str,
        name: &str,
        siblings: Option<&[(String, TdNode)]>,
        out: &mut Vec<Value>,
        truncated: &mut bool,
    ) {
        match node {
            TdNode::Struct { fields, .. } => {
                for (field, child) in fields {
                    let child_path = if path.is_empty() {
                        field.clone()
                    } else {
                        format!("{path}.{field}")
                    };
                    self.walk(
                        typed,
                        child,
                        &child_path,
                        field,
                        Some(fields),
                        out,
                        truncated,
                    );
                }
            }
            TdNode::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let child_path = format!("{path}[{index}]");
                    self.walk(typed, item, &child_path, name, None, out, truncated);
                }
            }
            TdNode::Value(value) => {
                if out.len() >= MAX_FIELDS {
                    *truncated = true;
                    return;
                }
                let leaf = self.leaf(typed, path, name, value, siblings);
                out.push(leaf);
            }
        }
    }

    fn leaf(
        &mut self,
        typed: &DecodedTypedData,
        path: &str,
        name: &str,
        value: &TdValue,
        siblings: Option<&[(String, TdNode)]>,
    ) -> Value {
        let schema = typed.schema.as_ref();
        let path_value = if schema.is_some() {
            self.text(path)
        } else {
            self.untrusted(path, CAP_PATH)
        };
        let sibling_token = siblings.and_then(|fields| {
            fields.iter().find_map(|(field, node)| match node {
                TdNode::Value(TdValue::Address(address)) if field == "token" => Some(*address),
                _ => None,
            })
        });
        let (type_name, rendered) = match value {
            TdValue::Address(address) => {
                if schema.is_some() && name == "token" {
                    let standard = if matches!(schema, Some(KnownSchema::SeaportOrder)) {
                        "unknown"
                    } else {
                        "erc20"
                    };
                    self.add_token(address, standard);
                }
                ("address", self.address(address))
            }
            TdValue::Uint(number) => {
                let amount_field = schema.is_some()
                    && (matches!(name, "amount" | "startAmount" | "endAmount")
                        || (matches!(schema, Some(KnownSchema::Eip2612Permit)) && name == "value"));
                let time_field = schema.is_some()
                    && matches!(
                        name,
                        "deadline"
                            | "sigDeadline"
                            | "expiration"
                            | "expiry"
                            | "startTime"
                            | "endTime"
                    );
                if amount_field {
                    let token = sibling_token.or_else(|| {
                        matches!(schema, Some(KnownSchema::Eip2612Permit))
                            .then_some(typed.domain.verifying_contract)
                            .flatten()
                    });
                    let decimals = token.and_then(|token| self.decimals_of(&token));
                    let permit2 = schema.is_some_and(KnownSchema::is_permit2);
                    let unlimited = (*number == U256::MAX && !permit2)
                        || (permit2 && *number == U256::MAX_U160);
                    ("uint", self.amount(number, false, decimals, unlimited))
                } else if time_field {
                    let raw = self.decimal(number);
                    let display = number
                        .to_u64()
                        .and_then(utc_display)
                        .unwrap_or_else(|| number.to_decimal_string());
                    let display = self.text(&display);
                    (
                        "uint",
                        json_object(vec![("raw", raw), ("display", display)]),
                    )
                } else {
                    ("uint", self.decimal(number))
                }
            }
            TdValue::Int {
                negative,
                magnitude,
            } => {
                let sign = if *negative && !magnitude.is_zero() {
                    "-"
                } else {
                    ""
                };
                let text = format!("{sign}{}", magnitude.to_decimal_string());
                ("int", self.text(&text))
            }
            TdValue::Bool(flag) => ("bool", Value::Bool(*flag)),
            TdValue::Bytes(bytes) if bytes.len() <= 32 => ("bytes", self.hex(bytes)),
            TdValue::Bytes(bytes) => (
                "bytes",
                json_object(vec![(
                    "hex_len",
                    self.number(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
                )]),
            ),
            TdValue::String(text) => ("string", self.untrusted(text, CAP_STRING)),
        };
        let type_name = self.text(type_name);
        json_object(vec![
            ("path", path_value),
            ("type", type_name),
            ("value", rendered),
        ])
    }
}

/// Builds the input of §4.3 for `src` from the requesting `origin` (shown as untrusted), the
/// signing account `user`, the request's chain and the facts the display used (RPC token
/// metadata). The registry of `chain` decides which symbols are trusted.
///
/// # Errors
///
/// [`ExplainError::InputTooLarge`] when the JSON alone exceeds the request body bound.
pub fn build_input(
    src: &ExplainSource<'_>,
    origin: &str,
    user: &Address,
    chain: &ChainInfo,
    facts: &ChainFacts,
) -> Result<ExplainInput, ExplainError> {
    let mut builder = Builder::new(chain, facts);
    let kind = match src {
        ExplainSource::EvmTx(..) => RequestKind::EvmTx,
        ExplainSource::PersonalSign(_) => RequestKind::PersonalSign,
        ExplainSource::TypedData(_) => RequestKind::TypedData,
    };
    let chain_value = json_object(vec![
        ("id", builder.number(chain.chain_id)),
        ("name", builder.text(&chain.name)),
        ("native_symbol", builder.text(&chain.native_symbol)),
    ]);
    let origin_value = builder.untrusted(origin, CAP_ORIGIN);
    let user_value = builder.address(user);
    let (tx, simulation, message, typed_data) = match src {
        ExplainSource::EvmTx(decoded, sim) => {
            let tx = builder.tx_value(decoded);
            let simulation = builder.simulation_value(*sim);
            (tx, simulation, Value::Null, Value::Null)
        }
        ExplainSource::PersonalSign(message) => (
            Value::Null,
            Value::Null,
            builder.message_value(message),
            Value::Null,
        ),
        ExplainSource::TypedData(typed) => (
            Value::Null,
            Value::Null,
            Value::Null,
            builder.typed_value(typed),
        ),
    };
    let assets = builder.assets_value();
    let root = json_object(vec![
        ("schema", json_str(INPUT_SCHEMA)),
        ("request", json_str(kind.as_str())),
        ("chain", chain_value),
        ("origin", origin_value),
        ("user", user_value),
        ("assets", assets),
        ("tx", tx),
        ("simulation", simulation),
        ("message", message),
        ("typed_data", typed_data),
    ]);
    let json = yw_json::to_vec(&root);
    if json.len() > super::MAX_REQUEST_BODY {
        return Err(ExplainError::InputTooLarge);
    }
    Ok(ExplainInput {
        json,
        trusted: builder.trusted,
        kind,
    })
}
