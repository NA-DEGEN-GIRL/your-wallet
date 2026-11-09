//! dApp parameter validation and normalization (spec/05 §3.3–§3.4, spec/03 §3.2, §8.1, §9.1).
//!
//! Ported from `archive/spec-v2.4:crates/broker/src/params.rs:105-671` (exact parameter arrays,
//! exact object key sets, call/tx objects, access lists, log filters, fee history, permissions)
//! on yw-json, with the eight fixes of spec/05 §3.4: EIP-55 mixed-case addresses (spec/03 §2.1
//! via `yw_core::evm::address::parse_address`), upper-case and leading-zero quantities normalized
//! instead of rejected, reads without `to`, `personal_sign` hex **or** UTF-8, typed data as a
//! string **or** an object, EIP-1898 block references, `data` = `input` accepted when the bytes
//! are equal, and one-sided `eth_getLogs` ranges resolved against the cached block number (the
//! archive required both bounds). `wallet_addEthereumChain`, `wallet_watchAsset` and
//! `wallet_getCapabilities` schemas are gone (4200 before validation). Every violation is
//! -32602 `Invalid params.`; account membership (4100) and the origin chain (`chainId`, T01)
//! are checked by the dispatcher.

use yw_core::evm::address::{Address, parse_address};
use yw_core::evm::amount::U256;
use yw_core::evm::tx::AccessListItem;
use yw_core::policy::{Method, ProviderError};
use yw_json::{Limits, Number, Object, Value};

use crate::text::{json_object, json_str};

/// Largest call/transaction `data` (spec/03 §3.1).
pub const MAX_CALL_DATA_BYTES: usize = 131_072;
/// Largest `personal_sign` message.
pub const MAX_PERSONAL_MESSAGE_BYTES: usize = 65_536;
/// Largest typed-data source (string or canonical serialization).
pub const MAX_TYPED_DATA_BYTES: usize = 131_072;
/// Access-list bounds.
pub const MAX_ACCESS_LIST_ENTRIES: usize = 256;
/// Storage keys per access-list entry.
pub const MAX_ACCESS_LIST_KEYS: usize = 256;
/// `eth_getLogs` address alternatives.
pub const MAX_LOG_ADDRESSES: usize = 32;
/// `eth_getLogs` topic alternatives.
pub const MAX_LOG_TOPIC_ALTERNATIVES: usize = 32;
/// `eth_getLogs` block range (spec/05 §3.4, §8.4).
pub const MAX_LOGS_BLOCK_RANGE: u64 = 10_000;
/// `eth_feeHistory` block count.
pub const MAX_FEE_HISTORY_BLOCKS: u64 = 1_024;
/// `eth_feeHistory` percentiles.
pub const MAX_FEE_HISTORY_PERCENTILES: usize = 100;
/// D20 gas ceiling.
pub const MAX_GAS: u64 = 16_777_216;

type Checked<T> = Result<T, ProviderError>;

const fn invalid<T>() -> Checked<T> {
    Err(ProviderError::InvalidParams)
}

fn ok_or_invalid<T>(value: Option<T>) -> Checked<T> {
    value.ok_or(ProviderError::InvalidParams)
}

/// One `eth_getLogs` bound of a one-sided range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogsBound {
    /// A block number.
    Number(u64),
    /// `latest`, `safe`, `finalized` or omitted: resolved as the cached block number B.
    Tag,
}

/// A one-sided `eth_getLogs` range checked by the read worker just before forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogsRange {
    /// `fromBlock`.
    pub from: LogsBound,
    /// `toBlock`.
    pub to: LogsBound,
}

/// The normalized parameters of a read (forwarded as is).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadParams {
    /// Normalized params array.
    pub params: Value,
    /// Range still to check against the block number (one-sided `eth_getLogs` only).
    pub logs: Option<LogsRange>,
}

/// `eth_sendTransaction` parameters after spec/03 §3.2 format checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxParams {
    /// Sender (must be a granted account: the dispatcher answers 4100).
    pub from: Address,
    /// Recipient (no deployment, D19).
    pub to: Address,
    /// Value (default 0).
    pub value: U256,
    /// Calldata (`data`/`input` merged).
    pub data: Vec<u8>,
    /// dApp `gas` (≤ 16,777,216).
    pub gas: Option<u64>,
    /// dApp `nonce` (must equal the wallet's nonce, spec/03 §3.6).
    pub nonce: Option<u64>,
    /// dApp `chainId` (must equal the origin chain).
    pub chain_id: Option<u64>,
    /// `gasPrice`/`maxFeePerGas`/`maxPriorityFeePerGas` were present (values ignored, E31).
    pub fee_fields: bool,
    /// Access list.
    pub access_list: Vec<AccessListItem>,
}

/// A validated request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Validated {
    /// `[]`.
    Empty,
    /// `wallet_switchEthereumChain` target.
    Switch(u64),
    /// `[{ "eth_accounts": {} }]`.
    Permissions,
    /// A read.
    Read(ReadParams),
    /// `eth_sendTransaction`.
    Send(Box<TxParams>),
    /// `personal_sign`.
    PersonalSign {
        /// Message bytes.
        message: Vec<u8>,
        /// Signing account.
        account: Address,
    },
    /// `eth_signTypedData_v4`.
    TypedData {
        /// Signing account.
        account: Address,
        /// Source bytes (the string's UTF-8, or the object's canonical serialization).
        source: Vec<u8>,
        /// The typed-data object.
        value: Value,
    },
    /// `sol_connect`.
    SolConnect {
        /// Answer from the grant only, never open a window (Phantom `onlyIfTrusted`).
        only_if_trusted: bool,
    },
    /// `sol_signMessage`.
    SolSignMessage {
        /// Signing account.
        public: [u8; 32],
        /// Message bytes.
        message: Vec<u8>,
    },
    /// `sol_signIn` (`domain`/`address` empty when the dApp left them out).
    SolSignIn {
        /// Signing account.
        public: [u8; 32],
        /// The validated sign-in input.
        input: Box<yw_core::sol::msgsign::SiwsMessage>,
    },
    /// `btc_requestAccounts`.
    BtcRequestAccounts(Vec<yw_core::policy::BtcPurpose>),
    /// `btc_signMessage`.
    BtcSignMessage {
        /// Signing address (a granted one).
        address: String,
        /// UTF-8 message bytes.
        message: Vec<u8>,
        /// Requested protocol (`None`: the address type's default).
        protocol: Option<yw_core::btc::msgsign::BtcMessageProtocol>,
    },
}

fn array(params: &Value) -> Checked<&[Value]> {
    ok_or_invalid(params.as_array())
}

fn exact_keys(object: &Object, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|key| object.get(key).is_some())
        && object
            .keys()
            .all(|key| required.contains(&key) || optional.contains(&key))
}

fn text(value: &Value) -> Checked<&str> {
    ok_or_invalid(value.as_str())
}

/// spec/05 §3.3 address: all-lowercase, all-uppercase or EIP-55 mixed case.
fn address(value: &Value) -> Checked<Address> {
    parse_address(text(value)?).map_err(|_| ProviderError::InvalidParams)
}

fn address_value(address: &Address) -> Value {
    json_str(&address.to_lower_hex())
}

/// spec/05 §3.3 quantity: `0x` + 1–64 hex, any case, leading zeros allowed.
fn quantity(value: &Value) -> Checked<U256> {
    U256::parse_quantity_lenient(text(value)?).map_err(|_| ProviderError::InvalidParams)
}

fn quantity_u64(value: &Value) -> Checked<u64> {
    ok_or_invalid(quantity(value)?.to_u64())
}

fn quantity_value(value: &U256) -> Value {
    json_str(&value.to_quantity())
}

/// spec/05 §3.3 data: `0x` + even hex, any case, `0x` allowed.
fn data(value: &Value, max_bytes: usize) -> Checked<Vec<u8>> {
    let digits = ok_or_invalid(text(value)?.strip_prefix("0x"))?;
    if digits.len() > max_bytes.saturating_mul(2) {
        return invalid();
    }
    yw_core::hex::decode(&digits.to_ascii_lowercase()).map_err(|_| ProviderError::InvalidParams)
}

fn data_value(bytes: &[u8]) -> Value {
    json_str(&format!("0x{}", yw_core::hex::encode(bytes)))
}

/// spec/05 §3.3 hash32.
fn hash32(value: &Value) -> Checked<[u8; 32]> {
    let digits = ok_or_invalid(text(value)?.strip_prefix("0x"))?;
    if digits.len() != 64 {
        return invalid();
    }
    yw_core::hex::decode_array::<32>(&digits.to_ascii_lowercase())
        .map_err(|_| ProviderError::InvalidParams)
}

fn hash_value(hash: &[u8; 32]) -> Value {
    data_value(hash)
}

const TAGS: [&str; 5] = ["latest", "earliest", "pending", "safe", "finalized"];

/// spec/05 §3.3 block tag: a tag or a u64 quantity.
fn block_tag(value: &Value) -> Checked<Value> {
    let tag = text(value)?;
    if TAGS.contains(&tag) {
        return Ok(json_str(tag));
    }
    Ok(json_str(
        &U256::from_u64(quantity_u64(value)?).to_quantity(),
    ))
}

/// spec/05 §3.3 block reference (EIP-1898).
fn block_ref(value: &Value) -> Checked<Value> {
    let Some(object) = value.as_object() else {
        return block_tag(value);
    };
    if exact_keys(object, &["blockNumber"], &[]) {
        let number = quantity_u64(ok_or_invalid(object.get("blockNumber"))?)?;
        return Ok(json_object(vec![(
            "blockNumber",
            quantity_value(&U256::from_u64(number)),
        )]));
    }
    if exact_keys(object, &["blockHash"], &["requireCanonical"]) {
        let hash = hash32(ok_or_invalid(object.get("blockHash"))?)?;
        let mut pairs = vec![("blockHash", hash_value(&hash))];
        if let Some(flag) = object.get("requireCanonical") {
            pairs.push((
                "requireCanonical",
                Value::Bool(ok_or_invalid(flag.as_bool())?),
            ));
        }
        return Ok(json_object(pairs));
    }
    invalid()
}

fn access_list(value: &Value, unique: bool) -> Checked<(Vec<AccessListItem>, Value)> {
    let entries = array(value)?;
    if entries.len() > MAX_ACCESS_LIST_ENTRIES {
        return invalid();
    }
    let mut items: Vec<AccessListItem> = Vec::with_capacity(entries.len());
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = ok_or_invalid(entry.as_object())?;
        if !exact_keys(object, &["address", "storageKeys"], &[]) {
            return invalid();
        }
        let address = address(ok_or_invalid(object.get("address"))?)?;
        if unique && items.iter().any(|item| item.address == address) {
            return invalid();
        }
        let keys = array(ok_or_invalid(object.get("storageKeys"))?)?;
        if keys.len() > MAX_ACCESS_LIST_KEYS {
            return invalid();
        }
        let storage_keys = keys.iter().map(hash32).collect::<Checked<Vec<_>>>()?;
        out.push(json_object(vec![
            ("address", address_value(&address)),
            (
                "storageKeys",
                Value::Array(storage_keys.iter().map(hash_value).collect()),
            ),
        ]));
        items.push(AccessListItem {
            address,
            storage_keys,
        });
    }
    Ok((items, Value::Array(out)))
}

const CALL_KEYS: [&str; 13] = [
    "from",
    "to",
    "gas",
    "gasPrice",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "value",
    "data",
    "input",
    "nonce",
    "type",
    "chainId",
    "accessList",
];

/// The `to` member of a call object.
#[derive(Clone, Copy)]
enum To {
    Absent,
    Null,
    Address(Address),
}

/// A call or transaction object after the common rules.
struct CallObject {
    from: Option<Address>,
    to: To,
    gas: Option<u64>,
    fee: [Option<U256>; 3],
    value: Option<U256>,
    input: Option<Vec<u8>>,
    nonce: Option<u64>,
    tx_type: Option<u64>,
    chain_id: Option<u64>,
    access: Option<(Vec<AccessListItem>, Value)>,
}

impl CallObject {
    fn parse(value: &Value, unique_access: bool) -> Checked<Self> {
        let object = ok_or_invalid(value.as_object())?;
        if !exact_keys(object, &[], &CALL_KEYS) {
            return invalid();
        }
        let opt = |key: &str| object.get(key);
        let input = match (opt("data"), opt("input")) {
            (Some(left), Some(right)) => {
                let left = data(left, MAX_CALL_DATA_BYTES)?;
                if left != data(right, MAX_CALL_DATA_BYTES)? {
                    return invalid();
                }
                Some(left)
            }
            (Some(one), None) | (None, Some(one)) => Some(data(one, MAX_CALL_DATA_BYTES)?),
            (None, None) => None,
        };
        let to = match opt("to") {
            None => To::Absent,
            Some(Value::Null) => To::Null,
            Some(value) => To::Address(address(value)?),
        };
        let mut fee = [None, None, None];
        for (slot, key) in fee
            .iter_mut()
            .zip(["gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"])
        {
            *slot = opt(key).map(quantity).transpose()?;
        }
        Ok(Self {
            from: opt("from").map(address).transpose()?,
            to,
            gas: opt("gas").map(quantity_u64).transpose()?,
            fee,
            value: opt("value").map(quantity).transpose()?,
            input,
            nonce: opt("nonce").map(quantity_u64).transpose()?,
            tx_type: opt("type").map(quantity_u64).transpose()?,
            chain_id: opt("chainId").map(quantity_u64).transpose()?,
            access: opt("accessList")
                .map(|list| access_list(list, unique_access))
                .transpose()?,
        })
    }

    /// The normalized object forwarded to RPC (canonical quantities, lowercase hex, `input`).
    fn normalized(&self) -> Value {
        let mut pairs: Vec<(&str, Value)> = Vec::new();
        if let Some(from) = &self.from {
            pairs.push(("from", address_value(from)));
        }
        match &self.to {
            To::Address(to) => pairs.push(("to", address_value(to))),
            To::Null => pairs.push(("to", Value::Null)),
            To::Absent => {}
        }
        if let Some(gas) = self.gas {
            pairs.push(("gas", quantity_value(&U256::from_u64(gas))));
        }
        for (key, fee) in ["gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"]
            .into_iter()
            .zip(&self.fee)
        {
            if let Some(fee) = fee {
                pairs.push((key, quantity_value(fee)));
            }
        }
        if let Some(value) = &self.value {
            pairs.push(("value", quantity_value(value)));
        }
        if let Some(input) = &self.input {
            pairs.push(("input", data_value(input)));
        }
        for (key, number) in [
            ("nonce", self.nonce),
            ("type", self.tx_type),
            ("chainId", self.chain_id),
        ] {
            if let Some(number) = number {
                pairs.push((key, quantity_value(&U256::from_u64(number))));
            }
        }
        if let Some((_, list)) = &self.access {
            pairs.push(("accessList", list.clone()));
        }
        json_object(pairs)
    }
}

fn tx_params(value: &Value) -> Checked<TxParams> {
    let call = CallObject::parse(value, true)?;
    let from = ok_or_invalid(call.from)?;
    let To::Address(to) = call.to else {
        return invalid();
    };
    if !matches!(call.tx_type, None | Some(0 | 2)) || call.gas.is_some_and(|gas| gas > MAX_GAS) {
        return invalid();
    }
    Ok(TxParams {
        from,
        to,
        value: call.value.unwrap_or(U256::ZERO),
        data: call.input.unwrap_or_default(),
        gas: call.gas,
        nonce: call.nonce,
        chain_id: call.chain_id,
        fee_fields: call.fee.iter().any(Option::is_some),
        access_list: call.access.map(|(items, _)| items).unwrap_or_default(),
    })
}

fn read(params: Vec<Value>) -> Validated {
    Validated::Read(ReadParams {
        params: Value::Array(params),
        logs: None,
    })
}

fn address_and_block(values: &[Value]) -> Checked<Validated> {
    match values {
        [account] => Ok(read(vec![
            address_value(&address(account)?),
            json_str("latest"),
        ])),
        [account, block] => Ok(read(vec![
            address_value(&address(account)?),
            block_ref(block)?,
        ])),
        _ => invalid(),
    }
}

fn storage_at(values: &[Value]) -> Checked<Validated> {
    let (account, slot, block) = match values {
        [account, slot] => (account, slot, json_str("latest")),
        [account, slot, block] => (account, slot, block_ref(block)?),
        _ => return invalid(),
    };
    Ok(read(vec![
        address_value(&address(account)?),
        quantity_value(&quantity(slot)?),
        block,
    ]))
}

fn call_params(values: &[Value]) -> Checked<Validated> {
    let (call, block) = match values {
        [call] => (call, json_str("latest")),
        [call, block] => (call, block_ref(block)?),
        _ => return invalid(),
    };
    Ok(read(vec![
        CallObject::parse(call, false)?.normalized(),
        block,
    ]))
}

fn percentile(value: &Value) -> Checked<f64> {
    let number = ok_or_invalid(value.as_number())?;
    let parsed: f64 = number
        .as_str()
        .parse()
        .map_err(|_| ProviderError::InvalidParams)?;
    if parsed.is_finite() && (0.0..=100.0).contains(&parsed) && !number.is_negative_zero() {
        Ok(parsed)
    } else {
        invalid()
    }
}

fn fee_history(values: &[Value]) -> Checked<Validated> {
    let (count, newest, percentiles) = match values {
        [count, newest] => (count, newest, None),
        [count, newest, percentiles] => (count, newest, Some(percentiles)),
        _ => return invalid(),
    };
    let count = match count {
        Value::Number(number) => ok_or_invalid(number.as_u64())?,
        other => quantity_u64(other)?,
    };
    if !(1..=MAX_FEE_HISTORY_BLOCKS).contains(&count) {
        return invalid();
    }
    let mut out = vec![quantity_value(&U256::from_u64(count)), block_tag(newest)?];
    if let Some(percentiles) = percentiles {
        let list = array(percentiles)?;
        if list.len() > MAX_FEE_HISTORY_PERCENTILES {
            return invalid();
        }
        let mut previous: Option<f64> = None;
        for item in list {
            let value = percentile(item)?;
            if previous.is_some_and(|last| value <= last) {
                return invalid();
            }
            previous = Some(value);
        }
        out.push(Value::Array(list.to_vec()));
    }
    Ok(read(out))
}

/// A `fromBlock`/`toBlock` of `eth_getLogs`: u64 quantity or `latest`/`safe`/`finalized`.
fn logs_bound(value: Option<&Value>) -> Checked<(LogsBound, Option<Value>)> {
    let Some(value) = value else {
        return Ok((LogsBound::Tag, None));
    };
    let tag = text(value)?;
    if matches!(tag, "latest" | "safe" | "finalized") {
        return Ok((LogsBound::Tag, Some(json_str(tag))));
    }
    let number = quantity_u64(value)?;
    Ok((
        LogsBound::Number(number),
        Some(quantity_value(&U256::from_u64(number))),
    ))
}

fn log_filter(values: &[Value]) -> Checked<Validated> {
    let [filter] = values else {
        return invalid();
    };
    let object = ok_or_invalid(filter.as_object())?;
    if !exact_keys(
        object,
        &[],
        &["fromBlock", "toBlock", "blockHash", "address", "topics"],
    ) {
        return invalid();
    }
    let mut pairs: Vec<(&str, Value)> = Vec::new();
    let mut logs = None;
    if let Some(hash) = object.get("blockHash") {
        if object.get("fromBlock").is_some() || object.get("toBlock").is_some() {
            return invalid();
        }
        pairs.push(("blockHash", hash_value(&hash32(hash)?)));
    } else {
        let (from, from_value) = logs_bound(object.get("fromBlock"))?;
        let (to, to_value) = logs_bound(object.get("toBlock"))?;
        match (from, to) {
            (LogsBound::Number(start), LogsBound::Number(end)) => {
                if start > end || end.saturating_sub(start) > MAX_LOGS_BLOCK_RANGE {
                    return invalid();
                }
            }
            (LogsBound::Tag, LogsBound::Tag) => {}
            _ => logs = Some(LogsRange { from, to }),
        }
        if let Some(value) = from_value {
            pairs.push(("fromBlock", value));
        }
        if let Some(value) = to_value {
            pairs.push(("toBlock", value));
        }
    }
    if let Some(value) = object.get("address") {
        let normalized = match value {
            Value::Array(list) => {
                if !(1..=MAX_LOG_ADDRESSES).contains(&list.len()) {
                    return invalid();
                }
                Value::Array(
                    list.iter()
                        .map(|item| address(item).map(|a| address_value(&a)))
                        .collect::<Checked<_>>()?,
                )
            }
            single => address_value(&address(single)?),
        };
        pairs.push(("address", normalized));
    }
    if let Some(topics) = object.get("topics") {
        let list = array(topics)?;
        if list.len() > 4 {
            return invalid();
        }
        let mut out = Vec::with_capacity(list.len());
        for topic in list {
            out.push(match topic {
                Value::Null => Value::Null,
                Value::Array(alternatives) => {
                    if !(1..=MAX_LOG_TOPIC_ALTERNATIVES).contains(&alternatives.len()) {
                        return invalid();
                    }
                    Value::Array(
                        alternatives
                            .iter()
                            .map(|item| hash32(item).map(|h| hash_value(&h)))
                            .collect::<Checked<_>>()?,
                    )
                }
                single => hash_value(&hash32(single)?),
            });
        }
        pairs.push(("topics", Value::Array(out)));
    }
    Ok(Validated::Read(ReadParams {
        params: Value::Array(vec![json_object(pairs)]),
        logs,
    }))
}

/// The one-sided range rule of spec/05 §3.4 with the cached block number `latest` = B: tags
/// become B, then `to.saturating_sub(from) ≤ 10,000` (`from ≤ to` is not checked).
///
/// # Errors
///
/// -32602 when the range is too large.
pub fn check_logs_range(range: &LogsRange, latest: u64) -> Result<(), ProviderError> {
    let resolve = |bound: LogsBound| match bound {
        LogsBound::Number(number) => number,
        LogsBound::Tag => latest,
    };
    if resolve(range.to).saturating_sub(resolve(range.from)) <= MAX_LOGS_BLOCK_RANGE {
        Ok(())
    } else {
        invalid()
    }
}

fn switch_chain(values: &[Value]) -> Checked<Validated> {
    let [target] = values else {
        return invalid();
    };
    let object = ok_or_invalid(target.as_object())?;
    if !exact_keys(object, &["chainId"], &[]) {
        return invalid();
    }
    Ok(Validated::Switch(quantity_u64(ok_or_invalid(
        object.get("chainId"),
    )?)?))
}

fn permissions(values: &[Value]) -> Checked<Validated> {
    let [request] = values else {
        return invalid();
    };
    let object = ok_or_invalid(request.as_object())?;
    let ok = exact_keys(object, &["eth_accounts"], &[])
        && object
            .get("eth_accounts")
            .and_then(Value::as_object)
            .is_some_and(Object::is_empty);
    if ok {
        Ok(Validated::Permissions)
    } else {
        invalid()
    }
}

/// `0x` + 40 hex digits, any case (an address, checksum valid or not).
fn address_shaped(text: &str) -> bool {
    text.len() == 42
        && (text.starts_with("0x") || text.starts_with("0X"))
        && text.bytes().skip(2).all(|byte| byte.is_ascii_hexdigit())
}

fn personal_sign(values: &[Value]) -> Checked<Validated> {
    let [message, account, rest @ ..] = values else {
        return invalid();
    };
    // web3.js (`web3.eth.personal.sign(message, address, password)`) always sends a third
    // element, the node-account password or `null`; MetaMask ignores it, and so does this wallet
    // (never read, logged or kept). Only `null`, a string or an object may stand there.
    if !matches!(
        rest,
        [] | [Value::Null | Value::String(_) | Value::Object(_)]
    ) {
        return invalid();
    }
    let account = address(account)?;
    let message = text(message)?;
    // spec/05 §3.4: the swapped `[address, message]` is refused. When the "message" is itself
    // address-shaped the order cannot be told apart (`[A0, A1]` would sign A0's 20 bytes for
    // A1), so it is refused as swapped rather than guessed (security review L11).
    if address_shaped(message) {
        return invalid();
    }
    let message = yw_core::evm::eip191::parse_personal_param(message)
        .map_err(|_| ProviderError::InvalidParams)?;
    if message.len() > MAX_PERSONAL_MESSAGE_BYTES {
        return invalid();
    }
    Ok(Validated::PersonalSign { message, account })
}

fn typed_data(values: &[Value]) -> Checked<Validated> {
    let [account, typed] = values else {
        return invalid();
    };
    let account = address(account)?;
    let (source, value) = match typed {
        Value::String(source) => {
            if source.len() > MAX_TYPED_DATA_BYTES {
                return invalid();
            }
            let parsed = yw_json::parse(source.as_bytes(), &Limits::REQUEST)
                .map_err(|_| ProviderError::InvalidParams)?;
            (source.as_bytes().to_vec(), parsed)
        }
        Value::Object(_) => (yw_json::to_vec(typed), typed.clone()),
        _ => return invalid(),
    };
    let object = ok_or_invalid(value.as_object())?;
    if !exact_keys(object, &["types", "primaryType", "domain", "message"], &[])
        || yw_json::to_vec(&value).len() > MAX_TYPED_DATA_BYTES
    {
        return invalid();
    }
    Ok(Validated::TypedData {
        account,
        source,
        value,
    })
}

fn exactly_empty(values: &[Value]) -> Checked<Validated> {
    if values.is_empty() {
        Ok(Validated::Empty)
    } else {
        invalid()
    }
}

/// Validates and normalizes the params of `method` (spec/05 §3.4 table).
///
/// # Errors
///
/// -32602 `Invalid params.`
pub fn validate(method: Method, params: &Value) -> Result<Validated, ProviderError> {
    let values = array(params)?;
    match method {
        Method::RequestAccounts
        | Method::Accounts
        | Method::ChainId
        | Method::NetVersion
        | Method::GetPermissions
        | Method::ClientVersion
        | Method::SolDisconnect
        | Method::SolAccounts
        | Method::BtcGetAccounts
        | Method::BtcDisconnect
        | Method::BtcGetNetwork => exactly_empty(values),
        Method::SolConnect => super::chain_params::sol_connect(values),
        Method::SolSignMessage => super::chain_params::sol_sign_message(values),
        Method::SolSignIn => super::chain_params::sol_sign_in(values),
        Method::BtcRequestAccounts => super::chain_params::btc_request_accounts(values),
        Method::BtcSignMessage => super::chain_params::btc_sign_message(values),
        Method::BlockNumber | Method::GasPrice | Method::MaxPriorityFeePerGas => {
            exactly_empty(values).map(|_| read(Vec::new()))
        }
        Method::SwitchEthereumChain => switch_chain(values),
        Method::RequestPermissions | Method::RevokePermissions => permissions(values),
        Method::GetBalance | Method::GetCode | Method::GetTransactionCount => {
            address_and_block(values)
        }
        Method::GetStorageAt => storage_at(values),
        Method::Call | Method::EstimateGas => call_params(values),
        Method::FeeHistory => fee_history(values),
        Method::GetBlockByHash => match values {
            [hash, full] => Ok(read(vec![
                hash_value(&hash32(hash)?),
                Value::Bool(ok_or_invalid(full.as_bool())?),
            ])),
            _ => invalid(),
        },
        Method::GetBlockByNumber => match values {
            [tag, full] => Ok(read(vec![
                block_tag(tag)?,
                Value::Bool(ok_or_invalid(full.as_bool())?),
            ])),
            _ => invalid(),
        },
        Method::GetTransactionByHash | Method::GetTransactionReceipt => match values {
            [hash] => Ok(read(vec![hash_value(&hash32(hash)?)])),
            _ => invalid(),
        },
        Method::GetLogs => log_filter(values),
        Method::SendTransaction => match values {
            [tx] => Ok(Validated::Send(Box::new(tx_params(tx)?))),
            _ => invalid(),
        },
        Method::PersonalSign => personal_sign(values),
        Method::SignTypedDataV4 => typed_data(values),
    }
}

/// The EIP-2255 permission object (spec/05 §3.1).
#[must_use]
pub fn permission_value(origin: &str, accounts: &[[u8; 20]], granted_at_unix_ms: u64) -> Value {
    json_object(vec![
        ("invoker", json_str(origin)),
        ("parentCapability", json_str("eth_accounts")),
        (
            "caveats",
            Value::Array(vec![json_object(vec![
                ("type", json_str("restrictReturnedAccounts")),
                ("value", super::envelope::accounts_value(accounts)),
            ])]),
        ),
        ("date", Value::Number(Number::from_u64(granted_at_unix_ms))),
    ])
}
