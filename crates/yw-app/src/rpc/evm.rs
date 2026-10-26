//! `rpc::evm` (spec/03 §0): the `eth_simulateV1` response parser (M2, spec/09 §3.8) and, from M4,
//! the EVM JSON-RPC calls with their JSON ↔ core-type conversions (spec/03 §1.4 method list).
//!
//! The parser reads the raw JSON-RPC response bytes with yw-json and produces
//! [`SimOutcome`] for `yw_core::evm::simulate::interpret` (spec/03 §6.2). Unknown fields are
//! ignored (`maxUsedGas` is optional, `blockAccessListHash`, `slotNumber`, … are skipped);
//! missing required fields and grammar violations are `Malformed`; size and log limits are
//! `TooLarge`. The RPC `error.message` is never read (spec/03 §1.4). Response handling follows
//! `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:1125-1464` with serde replaced by yw-json.

use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::fee::FeeHistory;
use yw_core::evm::simulate::simulate_request;
use yw_core::evm::simulate::{
    MAX_LOG_DATA, MAX_LOG_TOPICS, MAX_RETURN_DATA, MAX_SIM_LOGS, MAX_SIM_RESPONSE_BYTES, SimBlock,
    SimCall, SimCallError, SimLog, SimOutcome, SimStatus, TransportKind,
};
use yw_core::evm::tx::{AccessListItem, Eip1559Tx};
use yw_json::{Limits, Object, ParseError, Value};
use yw_win::http::{HttpError, HttpsUrl};

use super::{DEFAULT_MAX_RESPONSE, RpcClient, RpcFailure, canonical_quantity};
use crate::text::{json_object, json_str};

/// yw-json limits for `eth_simulateV1` responses (4 MiB, spec/03 §1.4).
pub const SIMULATE_RESPONSE_LIMITS: Limits = Limits {
    max_bytes: MAX_SIM_RESPONSE_BYTES,
    max_depth: 32,
    max_nodes: 262_144,
    max_items: 262_144,
};

/// Parse failure classes, mapped onto [`SimOutcome`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Malformed,
    TooLarge,
}

impl From<Failure> for SimOutcome {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Malformed => Self::Malformed,
            Failure::TooLarge => Self::TooLarge,
        }
    }
}

type Parsed<T> = Result<T, Failure>;

fn field<'a>(object: &'a Object, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

fn required<'a>(object: &'a Object, key: &str) -> Parsed<&'a Value> {
    field(object, key).ok_or(Failure::Malformed)
}

fn quantity(value: &Value) -> Parsed<U256> {
    let text = value.as_str().ok_or(Failure::Malformed)?;
    U256::parse_quantity_lenient(text).map_err(|_| Failure::Malformed)
}

fn quantity_u64(value: &Value) -> Parsed<u64> {
    quantity(value)?.to_u64().ok_or(Failure::Malformed)
}

fn hex_data(value: &Value, limit: usize) -> Parsed<Vec<u8>> {
    let text = value.as_str().ok_or(Failure::Malformed)?;
    let digits = text.strip_prefix("0x").ok_or(Failure::Malformed)?;
    if digits.len() % 2 != 0 {
        return Err(Failure::Malformed);
    }
    if digits.len() / 2 > limit {
        return Err(Failure::TooLarge);
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().chunks_exact(2) {
        let text = core::str::from_utf8(pair).map_err(|_| Failure::Malformed)?;
        if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Failure::Malformed);
        }
        out.push(u8::from_str_radix(text, 16).map_err(|_| Failure::Malformed)?);
    }
    Ok(out)
}

fn fixed<const N: usize>(value: &Value) -> Parsed<[u8; N]> {
    hex_data(value, N)
        .map_err(|_| Failure::Malformed)?
        .try_into()
        .map_err(|_| Failure::Malformed)
}

fn parse_log(value: &Value) -> Parsed<SimLog> {
    let object = value.as_object().ok_or(Failure::Malformed)?;
    let address = Address::from_bytes(fixed::<20>(required(object, "address")?)?);
    let topics = required(object, "topics")?
        .as_array()
        .ok_or(Failure::Malformed)?;
    if topics.len() > MAX_LOG_TOPICS {
        return Err(Failure::TooLarge);
    }
    let topics = topics.iter().map(fixed::<32>).collect::<Parsed<Vec<_>>>()?;
    let data = hex_data(required(object, "data")?, MAX_LOG_DATA)?;
    Ok(SimLog {
        address,
        topics,
        data,
    })
}

fn parse_call(value: &Value) -> Parsed<SimCall> {
    let object = value.as_object().ok_or(Failure::Malformed)?;
    let status = match quantity_u64(required(object, "status")?)? {
        1 => SimStatus::Success,
        0 => SimStatus::Failure,
        _ => return Err(Failure::Malformed),
    };
    let gas_used = quantity_u64(required(object, "gasUsed")?)?;
    let max_used_gas = field(object, "maxUsedGas").map(quantity_u64).transpose()?;
    let return_data = field(object, "returnData")
        .map(|value| hex_data(value, MAX_RETURN_DATA))
        .transpose()?
        .unwrap_or_default();
    let logs = if status == SimStatus::Success {
        let logs = required(object, "logs")?
            .as_array()
            .ok_or(Failure::Malformed)?;
        if logs.len() > MAX_SIM_LOGS {
            return Err(Failure::TooLarge);
        }
        logs.iter().map(parse_log).collect::<Parsed<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let error = match field(object, "error") {
        Some(error) => {
            let error = error.as_object().ok_or(Failure::Malformed)?;
            let code = required(error, "code")?
                .as_number()
                .and_then(yw_json::Number::as_i64)
                .ok_or(Failure::Malformed)?;
            let data = field(error, "data")
                .map(|value| hex_data(value, MAX_RETURN_DATA))
                .transpose()?;
            Some(SimCallError { code, data })
        }
        None => None,
    };
    Ok(SimCall {
        status,
        gas_used,
        max_used_gas,
        return_data,
        logs,
        error,
    })
}

fn parse_block(value: &Value) -> Parsed<SimBlock> {
    let object = value.as_object().ok_or(Failure::Malformed)?;
    let calls = required(object, "calls")?
        .as_array()
        .ok_or(Failure::Malformed)?;
    let [call] = calls else {
        return Err(Failure::Malformed);
    };
    Ok(SimBlock {
        number: quantity_u64(required(object, "number")?)?,
        parent_hash: fixed::<32>(required(object, "parentHash")?)?,
        timestamp: quantity_u64(required(object, "timestamp")?)?,
        base_fee_per_gas: quantity(required(object, "baseFeePerGas")?)?,
        call: parse_call(call)?,
    })
}

fn parse_document(value: &Value, expected_id: u64) -> Parsed<SimOutcome> {
    let object = value.as_object().ok_or(Failure::Malformed)?;
    if field(object, "jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(Failure::Malformed);
    }
    let id = field(object, "id")
        .and_then(Value::as_number)
        .and_then(yw_json::Number::as_u64);
    if id != Some(expected_id) {
        return Err(Failure::Malformed);
    }
    match (field(object, "result"), field(object, "error")) {
        (Some(result), None) => {
            let blocks = result.as_array().ok_or(Failure::Malformed)?;
            let [block] = blocks else {
                return Err(Failure::Malformed);
            };
            Ok(SimOutcome::Block(parse_block(block)?))
        }
        (None, Some(error)) => {
            let error = error.as_object().ok_or(Failure::Malformed)?;
            let code = required(error, "code")?
                .as_number()
                .and_then(yw_json::Number::as_i64)
                .ok_or(Failure::Malformed)?;
            Ok(if code == 429 {
                SimOutcome::Transport(TransportKind::RateLimited)
            } else {
                SimOutcome::RpcError { code }
            })
        }
        _ => Err(Failure::Malformed),
    }
}

/// Parses the body of an HTTP 200 `eth_simulateV1` response with the request id `expected_id`.
#[must_use]
pub fn parse_simulate_response(body: &[u8], expected_id: u64) -> SimOutcome {
    if body.len() > MAX_SIM_RESPONSE_BYTES {
        return SimOutcome::TooLarge;
    }
    let value = match yw_json::parse(body, &SIMULATE_RESPONSE_LIMITS) {
        Ok(value) => value,
        Err(ParseError::TooLarge | ParseError::TooManyNodes | ParseError::TooManyItems) => {
            return SimOutcome::TooLarge;
        }
        Err(_) => return SimOutcome::Malformed,
    };
    parse_document(&value, expected_id).unwrap_or_else(SimOutcome::from)
}

/// Classifies an HTTP response: 429 → `RateLimited`, other non-200 → transport error, 200 → the
/// body parser.
#[must_use]
pub fn simulate_http_outcome(status: u16, body: &[u8], expected_id: u64) -> SimOutcome {
    match status {
        200 => parse_simulate_response(body, expected_id),
        429 => SimOutcome::Transport(TransportKind::RateLimited),
        _ => SimOutcome::Transport(TransportKind::Other),
    }
}

// ----- M4: EVM calls (spec/03 §1.4, §3–§4, §12) ---------------------------------------------
//
// Structure and limits follow `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:491-524`
// (chain id + genesis verification with bounded retries) and `:866-932` (strict envelope, id
// check, size bound) with serde replaced by yw-json, one endpoint URL per network (D13) and the
// transport behind [`crate::rpc::Transport`] so tests use a fake.

/// `eth_simulateV1` response bound (4 MiB).
pub const SIMULATE_MAX_RESPONSE: usize = MAX_SIM_RESPONSE_BYTES;

fn quantity_value(value: u64) -> Value {
    json_str(&canonical_quantity(value))
}

fn address_value(address: &Address) -> Value {
    json_str(&address.to_lower_hex())
}

fn data_value(bytes: &[u8]) -> Value {
    json_str(&format!("0x{}", yw_core::hex::encode(bytes)))
}

fn parse_quantity_value(value: &Value) -> Result<U256, RpcFailure> {
    value
        .as_str()
        .and_then(|text| U256::parse_quantity_lenient(text).ok())
        .ok_or(RpcFailure::Malformed)
}

fn parse_u64_value(value: &Value) -> Result<u64, RpcFailure> {
    parse_quantity_value(value)?
        .to_u64()
        .ok_or(RpcFailure::Malformed)
}

fn parse_bytes_value(value: &Value) -> Result<Vec<u8>, RpcFailure> {
    let digits = value
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or(RpcFailure::Malformed)?;
    yw_core::hex::decode(digits).map_err(|_| RpcFailure::Malformed)
}

fn parse_hash_value(value: &Value) -> Result<[u8; 32], RpcFailure> {
    parse_bytes_value(value)?
        .try_into()
        .map_err(|_| RpcFailure::Malformed)
}

fn parse_address_value(value: &Value) -> Result<Address, RpcFailure> {
    let bytes: [u8; 20] = parse_bytes_value(value)?
        .try_into()
        .map_err(|_| RpcFailure::Malformed)?;
    Ok(Address::from_bytes(bytes))
}

fn array(values: Vec<Value>) -> Value {
    Value::Array(values)
}

/// `eth_chainId` as returned (compared lowercase with the canonical quantity, spec/03 §1.4).
///
/// # Errors
///
/// [`RpcFailure`] (`Malformed` for a non-string result).
pub fn chain_id_text(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<String, RpcFailure> {
    match client.call(url, "eth_chainId", array(Vec::new()))? {
        Value::String(text) => Ok(text),
        _ => Err(RpcFailure::Malformed),
    }
}

/// The parsed chain id of an `eth_chainId` answer (`None` when not a quantity).
#[must_use]
pub fn parse_chain_id(text: &str) -> Option<u64> {
    U256::parse_quantity_lenient(text).ok()?.to_u64()
}

/// A block number and hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    /// Number.
    pub number: u64,
    /// Hash.
    pub hash: [u8; 32],
}

/// `eth_getBlockByNumber([tag, false])` → number and hash; `None` for a null result.
///
/// # Errors
///
/// [`RpcFailure`] (`Malformed` when the result is not an object with a quantity `number` and a
/// 32-byte `hash`).
pub fn block_by_tag(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    tag: &str,
) -> Result<Option<BlockRef>, RpcFailure> {
    let result = client.call(
        url,
        "eth_getBlockByNumber",
        array(vec![json_str(tag), Value::Bool(false)]),
    )?;
    if result.is_null() {
        return Ok(None);
    }
    let object = result.as_object().ok_or(RpcFailure::Malformed)?;
    let hash = parse_hash_value(object.get("hash").ok_or(RpcFailure::Malformed)?)?;
    let number = parse_u64_value(object.get("number").ok_or(RpcFailure::Malformed)?)?;
    Ok(Some(BlockRef { number, hash }))
}

/// The block-0 hash (`eth_getBlockByNumber(["0x0", false]).hash`, spec/03 §1.4): a result that is
/// not an object or a `hash` that is not 32 bytes is `Malformed` (treated like a transport
/// failure by the chain check).
///
/// # Errors
///
/// [`RpcFailure`].
pub fn genesis_hash(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<[u8; 32], RpcFailure> {
    let result = client.call(
        url,
        "eth_getBlockByNumber",
        array(vec![json_str("0x0"), Value::Bool(false)]),
    )?;
    let object = result.as_object().ok_or(RpcFailure::Malformed)?;
    parse_hash_value(object.get("hash").ok_or(RpcFailure::Malformed)?)
}

/// `eth_blockNumber`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn block_number(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<u64, RpcFailure> {
    parse_u64_value(&client.call(url, "eth_blockNumber", array(Vec::new()))?)
}

/// `eth_getTransactionCount(account, tag)`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn transaction_count(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    account: &Address,
    tag: &str,
) -> Result<u64, RpcFailure> {
    parse_u64_value(&client.call(
        url,
        "eth_getTransactionCount",
        array(vec![address_value(account), json_str(tag)]),
    )?)
}

/// `eth_getBalance(account, tag)`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn balance(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    account: &Address,
    tag: &str,
) -> Result<U256, RpcFailure> {
    parse_quantity_value(&client.call(
        url,
        "eth_getBalance",
        array(vec![address_value(account), json_str(tag)]),
    )?)
}

/// `eth_getCode(address, "latest")`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn code(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    address: &Address,
) -> Result<Vec<u8>, RpcFailure> {
    parse_bytes_value(&client.call(
        url,
        "eth_getCode",
        array(vec![address_value(address), json_str("latest")]),
    )?)
}

/// `eth_call({to, input}, tag)` → return data.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn eth_call(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    to: &Address,
    data: &[u8],
    tag: &str,
) -> Result<Vec<u8>, RpcFailure> {
    let call = json_object(vec![("to", address_value(to)), ("input", data_value(data))]);
    parse_bytes_value(&client.call(url, "eth_call", array(vec![call, json_str(tag)]))?)
}

/// `eth_estimateGas` result (spec/03 §3.5 step 1): any failure is "failed", with the revert
/// data when the node returned it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EstimateOutcome {
    /// Estimate.
    Estimated(u64),
    /// Failure (revert, execution error, top-level error, transport, timeout).
    Failed {
        /// `error.data` of a revert.
        revert_data: Option<Vec<u8>>,
        /// Classification input (for logs).
        failure: RpcFailure,
    },
}

fn access_list_value(list: &[AccessListItem]) -> Value {
    Value::Array(
        list.iter()
            .map(|item| {
                json_object(vec![
                    ("address", address_value(&item.address)),
                    (
                        "storageKeys",
                        Value::Array(
                            item.storage_keys
                                .iter()
                                .map(|key| data_value(key))
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect(),
    )
}

/// `eth_estimateGas([{from, to, value, input, accessList?}, "latest"])` without fee or gas
/// fields (spec/03 §3.5).
#[must_use]
pub fn estimate_gas(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    from: &Address,
    tx: &Eip1559Tx,
) -> EstimateOutcome {
    let mut fields = vec![
        ("from", address_value(from)),
        ("to", address_value(&tx.to)),
        ("value", json_str(&tx.value.to_quantity())),
        ("input", data_value(&tx.data)),
    ];
    if !tx.access_list.is_empty() {
        fields.push(("accessList", access_list_value(&tx.access_list)));
    }
    let request = array(vec![json_object(fields), json_str("latest")]);
    match client.call_detailed(url, "eth_estimateGas", request, DEFAULT_MAX_RESPONSE) {
        Ok(value) => match parse_u64_value(&value) {
            Ok(estimate) => EstimateOutcome::Estimated(estimate),
            Err(failure) => EstimateOutcome::Failed {
                revert_data: None,
                failure,
            },
        },
        Err(error) => EstimateOutcome::Failed {
            revert_data: error.data,
            failure: error.failure,
        },
    }
}

/// Whether a JSON number token is zero (`0`, `0.0`, `0e5`), without floating point.
#[must_use]
pub fn number_token_is_zero(token: &str) -> bool {
    let mantissa = token
        .split(['e', 'E'])
        .next()
        .unwrap_or(token)
        .trim_start_matches('-');
    mantissa
        .bytes()
        .filter(u8::is_ascii_digit)
        .all(|digit| digit == b'0')
}

fn fee_history_call(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    blocks: u64,
) -> Result<Value, RpcFailure> {
    client.call(
        url,
        "eth_feeHistory",
        array(vec![
            quantity_value(blocks),
            json_str("latest"),
            Value::Array(vec![Value::Number(yw_json::Number::from_u64(50))]),
        ]),
    )
}

/// `eth_feeHistory([blocks, "latest", [50]])` (spec/03 §3.4 uses 10 blocks). Shape violations
/// are `Malformed` (E35 at the caller); the length rules are checked by `suggest_fees`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn fee_history(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    blocks: u64,
) -> Result<FeeHistory, RpcFailure> {
    let result = fee_history_call(client, url, blocks)?;
    let object = result.as_object().ok_or(RpcFailure::Malformed)?;
    let base = object
        .get("baseFeePerGas")
        .and_then(Value::as_array)
        .ok_or(RpcFailure::Malformed)?
        .iter()
        .map(parse_quantity_value)
        .collect::<Result<Vec<_>, _>>()?;
    let nonempty = object
        .get("gasUsedRatio")
        .and_then(Value::as_array)
        .ok_or(RpcFailure::Malformed)?
        .iter()
        .map(|value| {
            value
                .as_number()
                .map(|number| !number_token_is_zero(number.as_str()))
                .ok_or(RpcFailure::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let reward = object
        .get("reward")
        .and_then(Value::as_array)
        .ok_or(RpcFailure::Malformed)?
        .iter()
        .map(|row| match row.as_array() {
            Some([value]) => parse_quantity_value(value),
            _ => Err(RpcFailure::Malformed),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FeeHistory {
        base_fee_per_gas: base,
        nonempty,
        reward_p50: reward,
    })
}

/// Whether `eth_feeHistory(["0x1","latest",[50]])` reports `baseFeePerGas` (EIP-1559 check of a
/// user chain, spec/03 §1.6 step 4).
///
/// # Errors
///
/// [`RpcFailure`] for transport and JSON-RPC errors.
pub fn has_base_fee(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<bool, RpcFailure> {
    let result = fee_history_call(client, url, 1)?;
    Ok(result
        .as_object()
        .and_then(|object| object.get("baseFeePerGas"))
        .and_then(Value::as_array)
        .is_some_and(|fees| {
            !fees.is_empty() && fees.iter().all(|fee| parse_quantity_value(fee).is_ok())
        }))
}

/// `eth_simulateV1` for exactly the transaction to sign (spec/03 §6.1) with the 4 MiB bound.
/// Transport classes map onto [`SimOutcome`] (§6.3).
#[must_use]
pub fn simulate(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    tx: &Eip1559Tx,
    from: &Address,
    chain_and_type: bool,
) -> SimOutcome {
    let id = client.next_id();
    let body = simulate_request(id, tx, from, chain_and_type);
    match client.post_raw(url, &body, SIMULATE_MAX_RESPONSE) {
        Ok(reply) => simulate_http_outcome(reply.status, &reply.body, id),
        Err(HttpError::Timeout) => SimOutcome::Transport(TransportKind::Timeout),
        Err(HttpError::TooLarge) => SimOutcome::TooLarge,
        Err(_) => SimOutcome::Transport(TransportKind::Other),
    }
}

/// `eth_sendRawTransaction(["0x…"])` → the returned hash.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn send_raw(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    raw: &[u8],
) -> Result<[u8; 32], RpcFailure> {
    parse_hash_value(&client.call(url, "eth_sendRawTransaction", array(vec![data_value(raw)]))?)
}

/// `eth_getTransactionByHash` → whether the node knows the transaction (non-null result).
///
/// # Errors
///
/// [`RpcFailure`].
pub fn transaction_known(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    hash: &[u8; 32],
) -> Result<bool, RpcFailure> {
    let result = client.call(
        url,
        "eth_getTransactionByHash",
        array(vec![data_value(hash)]),
    )?;
    Ok(!result.is_null())
}

/// A validated receipt (spec/03 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Block number.
    pub block_number: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// `status 0x1`.
    pub success: bool,
    /// Gas used.
    pub gas_used: Option<u64>,
    /// Effective gas price.
    pub effective_gas_price: Option<U256>,
}

/// Receipt lookup result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptLookup {
    /// No receipt yet.
    None,
    /// A receipt that passed the §4.5 checks.
    Valid(Receipt),
    /// A receipt that violates §4.5 (ignored, logged).
    Invalid,
}

fn validate_receipt(
    object: &Object,
    hash: &[u8; 32],
    account: &Address,
) -> Result<Receipt, RpcFailure> {
    let field = |key: &str| object.get(key).ok_or(RpcFailure::Malformed);
    if parse_hash_value(field("transactionHash")?)? != *hash
        || parse_address_value(field("from")?)? != *account
    {
        return Err(RpcFailure::Malformed);
    }
    let success = match parse_u64_value(field("status")?)? {
        0 => false,
        1 => true,
        _ => return Err(RpcFailure::Malformed),
    };
    Ok(Receipt {
        block_number: parse_u64_value(field("blockNumber")?)?,
        block_hash: parse_hash_value(field("blockHash")?)?,
        success,
        gas_used: object
            .get("gasUsed")
            .and_then(|value| parse_u64_value(value).ok()),
        effective_gas_price: object
            .get("effectiveGasPrice")
            .and_then(|value| parse_quantity_value(value).ok()),
    })
}

/// `eth_getTransactionReceipt(hash)` with the §4.5 checks (`transactionHash`, `from`, `status`,
/// `blockNumber`, 32-byte `blockHash`).
///
/// # Errors
///
/// [`RpcFailure`] for transport and JSON-RPC errors.
pub fn receipt(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    hash: &[u8; 32],
    account: &Address,
) -> Result<ReceiptLookup, RpcFailure> {
    let result = client.call(
        url,
        "eth_getTransactionReceipt",
        array(vec![data_value(hash)]),
    )?;
    if result.is_null() {
        return Ok(ReceiptLookup::None);
    }
    let Some(object) = result.as_object() else {
        return Ok(ReceiptLookup::Invalid);
    };
    Ok(
        validate_receipt(object, hash, account)
            .map_or(ReceiptLookup::Invalid, ReceiptLookup::Valid),
    )
}
