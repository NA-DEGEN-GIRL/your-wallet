//! `sol::rpc` (spec/07 §15.2): the Solana JSON-RPC calls over the shared transport and their
//! JSON → core-type conversions. Integers are read with `Number::as_u64` (no `f64`); unknown
//! fields are ignored; missing or mistyped required fields are `Malformed` (`RpcAnomaly`). RPC
//! strings (`message`, logs) are never read or shown: errors are classified from their JSON
//! structure only (spec/07 §15.3). Every request uses `"commitment":"finalized"` and base64.

use yw_core::sol::SolAddress;
use yw_core::sol::broadcast::{SendResult, SigStatus, err};
use yw_core::sol::display::SimSummary;
use yw_json::{Number, Value};
use yw_win::http::HttpsUrl;

use crate::rpc::{CallError, DEFAULT_MAX_RESPONSE, RpcClient, RpcFailure};
use crate::text::{json_object, json_str, json_u64};

/// Program of an instruction, for the `InstructionError` classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IxProgram {
    /// `ComputeBudget`.
    ComputeBudget,
    /// System.
    System,
    /// Token or ATA (v1.1).
    Token,
}

/// `T_SOL` instruction programs (limit, price, transfer).
pub const T_SOL_PROGRAMS: [IxProgram; 3] = [
    IxProgram::ComputeBudget,
    IxProgram::ComputeBudget,
    IxProgram::System,
];

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (transactions and messages are sent as base64, spec/07 §15.2).
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    let symbol = |index: u32| {
        char::from(
            ALPHABET
                .get(usize::try_from(index & 0x3f).unwrap_or(0))
                .copied()
                .unwrap_or(b'A'),
        )
    };
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(symbol(triple >> 18));
        out.push(symbol(triple >> 12));
        if chunk.len() > 1 {
            out.push(symbol(triple >> 6));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(symbol(triple));
        } else {
            out.push('=');
        }
    }
    out
}

fn finalized() -> Value {
    json_object(vec![("commitment", json_str("finalized"))])
}

fn u64_of(value: &Value) -> Result<u64, RpcFailure> {
    value
        .as_number()
        .and_then(Number::as_u64)
        .ok_or(RpcFailure::Malformed)
}

fn context_value(result: &Value) -> Result<&Value, RpcFailure> {
    result
        .as_object()
        .and_then(|object| object.get("value"))
        .ok_or(RpcFailure::Malformed)
}

fn address_of(value: &Value) -> Result<SolAddress, RpcFailure> {
    value
        .as_str()
        .and_then(|text| SolAddress::parse(text).ok())
        .ok_or(RpcFailure::Malformed)
}

/// `getGenesisHash` → 32 bytes.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn genesis_hash(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<[u8; 32], RpcFailure> {
    let result = client.call(url, "getGenesisHash", Value::Array(Vec::new()))?;
    address_of(&result).map(SolAddress::to_bytes)
}

/// `getBalance(addr, finalized)` → lamports.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn balance(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    address: &SolAddress,
) -> Result<u64, RpcFailure> {
    let result = client.call(
        url,
        "getBalance",
        Value::Array(vec![json_str(&address.to_base58()), finalized()]),
    )?;
    u64_of(context_value(&result)?)
}

/// What `getAccountInfo` says about an account (data is not requested: `dataSlice` 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountInfo {
    /// Owner program.
    pub owner: SolAddress,
    /// Executable.
    pub executable: bool,
    /// Lamports.
    pub lamports: u64,
}

/// `getAccountInfo(addr, {base64, finalized, dataSlice 0/0})` → `None` for a missing account.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn account_info(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    address: &SolAddress,
) -> Result<Option<AccountInfo>, RpcFailure> {
    let config = json_object(vec![
        ("encoding", json_str("base64")),
        ("commitment", json_str("finalized")),
        (
            "dataSlice",
            json_object(vec![("offset", json_u64(0)), ("length", json_u64(0))]),
        ),
    ]);
    let result = client.call(
        url,
        "getAccountInfo",
        Value::Array(vec![json_str(&address.to_base58()), config]),
    )?;
    let value = context_value(&result)?;
    if value.is_null() {
        return Ok(None);
    }
    let object = value.as_object().ok_or(RpcFailure::Malformed)?;
    Ok(Some(AccountInfo {
        owner: address_of(object.get("owner").ok_or(RpcFailure::Malformed)?)?,
        executable: object
            .get("executable")
            .and_then(Value::as_bool)
            .ok_or(RpcFailure::Malformed)?,
        lamports: u64_of(object.get("lamports").ok_or(RpcFailure::Malformed)?)?,
    }))
}

/// `getMinimumBalanceForRentExemption(size, finalized)`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn minimum_rent(client: &RpcClient<'_>, url: &HttpsUrl, size: u64) -> Result<u64, RpcFailure> {
    let result = client.call(
        url,
        "getMinimumBalanceForRentExemption",
        Value::Array(vec![json_u64(size), finalized()]),
    )?;
    u64_of(&result)
}

/// `getRecentPrioritizationFees([writable…])` → the `prioritizationFee` values.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn prioritization_fees(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    writable: &[SolAddress],
) -> Result<Vec<u64>, RpcFailure> {
    let accounts = writable
        .iter()
        .map(|address| json_str(&address.to_base58()))
        .collect();
    let result = client.call(
        url,
        "getRecentPrioritizationFees",
        Value::Array(vec![Value::Array(accounts)]),
    )?;
    result
        .as_array()
        .ok_or(RpcFailure::Malformed)?
        .iter()
        .map(|entry| {
            entry
                .as_object()
                .and_then(|object| object.get("prioritizationFee"))
                .ok_or(RpcFailure::Malformed)
                .and_then(u64_of)
        })
        .collect()
}

/// `getLatestBlockhash(finalized)` → `(blockhash, lastValidBlockHeight)`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn latest_blockhash(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
) -> Result<([u8; 32], u64), RpcFailure> {
    let result = client.call(url, "getLatestBlockhash", Value::Array(vec![finalized()]))?;
    let value = context_value(&result)?
        .as_object()
        .ok_or(RpcFailure::Malformed)?;
    let blockhash = address_of(value.get("blockhash").ok_or(RpcFailure::Malformed)?)?;
    let height = u64_of(
        value
            .get("lastValidBlockHeight")
            .ok_or(RpcFailure::Malformed)?,
    )?;
    Ok((blockhash.to_bytes(), height))
}

/// `getBlockHeight(finalized)`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn block_height(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<u64, RpcFailure> {
    let result = client.call(url, "getBlockHeight", Value::Array(vec![finalized()]))?;
    u64_of(&result)
}

/// `getFeeForMessage(base64(message), finalized)` → `None` for `null`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn fee_for_message(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    message: &[u8],
) -> Result<Option<u64>, RpcFailure> {
    let result = client.call(
        url,
        "getFeeForMessage",
        Value::Array(vec![json_str(&base64(message)), finalized()]),
    )?;
    let value = context_value(&result)?;
    if value.is_null() {
        return Ok(None);
    }
    u64_of(value).map(Some)
}

/// Classifies a `TransactionError` JSON value (spec/07 §15.3) by structure only.
#[must_use]
pub fn classify_tx_error(value: &Value, programs: &[IxProgram]) -> u16 {
    match value {
        Value::String(name) => match name.as_str() {
            "InsufficientFundsForFee" => err::INSUFFICIENT_FUNDS_FOR_FEE,
            "AccountNotFound" => err::ACCOUNT_NOT_FOUND,
            "BlockhashNotFound" => err::BLOCKHASH_NOT_FOUND,
            "AlreadyProcessed" => err::ALREADY_PROCESSED,
            _ => err::OTHER,
        },
        Value::Object(object) => {
            if object.get("InsufficientFundsForRent").is_some() {
                return err::INSUFFICIENT_FUNDS_FOR_RENT;
            }
            let Some(pair) = object.get("InstructionError").and_then(Value::as_array) else {
                return err::OTHER;
            };
            let (Some(index), Some(inner)) = (
                pair.first()
                    .and_then(Value::as_number)
                    .and_then(Number::as_u64),
                pair.get(1),
            ) else {
                return err::OTHER;
            };
            if inner.as_str() == Some("ComputationalBudgetExceeded") {
                return err::COMPUTE_EXCEEDED;
            }
            match usize::try_from(index)
                .ok()
                .and_then(|index| programs.get(index))
            {
                Some(IxProgram::System) => err::SYSTEM_INSTRUCTION,
                Some(IxProgram::Token) => err::TOKEN_INSTRUCTION,
                Some(IxProgram::ComputeBudget) | None => err::OTHER,
            }
        }
        _ => err::OTHER,
    }
}

/// `simulateTransaction(base64(tx), {sigVerify:false, replaceRecentBlockhash:true})` (reference
/// only, D27). Transport/RPC failures are `NoResult`.
#[must_use]
pub fn simulate(client: &RpcClient<'_>, url: &HttpsUrl, tx: &[u8]) -> SimSummary {
    let config = json_object(vec![
        ("encoding", json_str("base64")),
        ("sigVerify", Value::Bool(false)),
        ("replaceRecentBlockhash", Value::Bool(true)),
        ("commitment", json_str("finalized")),
    ]);
    let Ok(result) = client.call(
        url,
        "simulateTransaction",
        Value::Array(vec![json_str(&base64(tx)), config]),
    ) else {
        return SimSummary::NoResult;
    };
    let Some(value) = context_value(&result).ok().and_then(Value::as_object) else {
        return SimSummary::NoResult;
    };
    let units = value
        .get("unitsConsumed")
        .and_then(|units| u64_of(units).ok());
    match value.get("err") {
        Some(Value::Null) => units.map_or(SimSummary::NoResult, |units| SimSummary::Ok { units }),
        Some(error) => SimSummary::Failed {
            err: classify_tx_error(error, &T_SOL_PROGRAMS),
            units,
        },
        None => SimSummary::NoResult,
    }
}

/// `sendTransaction(base64(tx), {skipPreflight:false, preflightCommitment:finalized,
/// maxRetries:0})`, classified for the broadcast loop (spec/07 §14.2): a returned signature is
/// compared with the local one; preflight errors with a deterministic structure (§15.3 codes 1–6)
/// stop re-sending; everything else is transient.
#[must_use]
pub fn send_transaction(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    tx: &[u8],
    local_signature: &str,
) -> SendResult {
    let config = json_object(vec![
        ("encoding", json_str("base64")),
        ("skipPreflight", Value::Bool(false)),
        ("preflightCommitment", json_str("finalized")),
        ("maxRetries", json_u64(0)),
    ]);
    match client.call_detailed(
        url,
        "sendTransaction",
        Value::Array(vec![json_str(&base64(tx)), config]),
        DEFAULT_MAX_RESPONSE,
    ) {
        Ok(Value::String(signature)) => SendResult::Accepted {
            matches: signature == local_signature,
        },
        Err(CallError {
            failure: RpcFailure::Rpc(_),
            data_value: Some(data),
            ..
        }) => {
            let code = data
                .as_object()
                .and_then(|object| object.get("err"))
                .map_or(err::OTHER, |error| {
                    classify_tx_error(error, &T_SOL_PROGRAMS)
                });
            if err::is_deterministic(code) {
                SendResult::Deterministic(code)
            } else {
                SendResult::Transient
            }
        }
        Ok(_) | Err(_) => SendResult::Transient,
    }
}

/// `getSignatureStatuses([sig], {searchTransactionHistory})` for one signature.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn signature_status(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    signature: &str,
    history: bool,
) -> Result<SigStatus, RpcFailure> {
    let config = json_object(vec![("searchTransactionHistory", Value::Bool(history))]);
    let result = client.call(
        url,
        "getSignatureStatuses",
        Value::Array(vec![Value::Array(vec![json_str(signature)]), config]),
    )?;
    let list = context_value(&result)?
        .as_array()
        .ok_or(RpcFailure::Malformed)?;
    let entry = list.first().ok_or(RpcFailure::Malformed)?;
    if entry.is_null() {
        return Ok(SigStatus::NotFound);
    }
    let object = entry.as_object().ok_or(RpcFailure::Malformed)?;
    let slot = u64_of(object.get("slot").ok_or(RpcFailure::Malformed)?)?;
    let status = object
        .get("confirmationStatus")
        .and_then(Value::as_str)
        .ok_or(RpcFailure::Malformed)?;
    match status {
        "finalized" => {
            let error = object.get("err").ok_or(RpcFailure::Malformed)?;
            Ok(SigStatus::Finalized {
                slot,
                err: (!error.is_null()).then(|| classify_tx_error(error, &T_SOL_PROGRAMS)),
            })
        }
        "processed" | "confirmed" => Ok(SigStatus::Processing),
        _ => Err(RpcFailure::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use yw_core::sol::broadcast::err;
    use yw_json::Limits;

    use super::{IxProgram, T_SOL_PROGRAMS, base64, classify_tx_error};

    fn json(text: &str) -> yw_json::Value {
        yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap()
    }

    #[test]
    fn base64_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn transaction_error_classification() {
        let cases = [
            (
                r#""InsufficientFundsForFee""#,
                err::INSUFFICIENT_FUNDS_FOR_FEE,
            ),
            (
                r#"{"InsufficientFundsForRent":{"account_index":1}}"#,
                err::INSUFFICIENT_FUNDS_FOR_RENT,
            ),
            (r#""AccountNotFound""#, err::ACCOUNT_NOT_FOUND),
            (
                r#"{"InstructionError":[2,{"Custom":1}]}"#,
                err::SYSTEM_INSTRUCTION,
            ),
            (
                r#"{"InstructionError":[0,"ComputationalBudgetExceeded"]}"#,
                err::COMPUTE_EXCEEDED,
            ),
            (
                r#"{"InstructionError":[0,"InvalidInstructionData"]}"#,
                err::OTHER,
            ),
            (r#"{"InstructionError":[9,{"Custom":1}]}"#, err::OTHER),
            (r#""BlockhashNotFound""#, err::BLOCKHASH_NOT_FOUND),
            (r#""AlreadyProcessed""#, err::ALREADY_PROCESSED),
            (r#""SomethingNew""#, err::OTHER),
            ("7", err::OTHER),
        ];
        for (text, code) in cases {
            assert_eq!(
                classify_tx_error(&json(text), &T_SOL_PROGRAMS),
                code,
                "{text}"
            );
        }
        assert_eq!(
            classify_tx_error(
                &json(r#"{"InstructionError":[1,{"Custom":4}]}"#),
                &[IxProgram::System, IxProgram::Token]
            ),
            err::TOKEN_INSTRUCTION
        );
    }
}
