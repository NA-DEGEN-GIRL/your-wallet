//! `rpc::evm` (spec/03 §0): the `eth_simulateV1` response parser (M2, spec/09 §3.8). RPC calls and
//! the JSON ↔ core-type conversions of the other methods arrive with M4.
//!
//! The parser reads the raw JSON-RPC response bytes with yw-json and produces
//! [`SimOutcome`] for `yw_core::evm::simulate::interpret` (spec/03 §6.2). Unknown fields are
//! ignored (`maxUsedGas` is optional, `blockAccessListHash`, `slotNumber`, … are skipped);
//! missing required fields and grammar violations are `Malformed`; size and log limits are
//! `TooLarge`. The RPC `error.message` is never read (spec/03 §1.4). Response handling follows
//! `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:1125-1464` with serde replaced by yw-json.

use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::simulate::{
    MAX_LOG_DATA, MAX_LOG_TOPICS, MAX_RETURN_DATA, MAX_SIM_LOGS, MAX_SIM_RESPONSE_BYTES, SimBlock,
    SimCall, SimCallError, SimLog, SimOutcome, SimStatus, TransportKind,
};
use yw_json::{Limits, Object, ParseError, Value};

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
