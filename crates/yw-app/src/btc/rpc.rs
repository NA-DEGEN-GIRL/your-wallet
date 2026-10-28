//! `btc::rpc` (spec/08 §4.2): the Bitcoin Core JSON-RPC calls on the `bitcoin:<net>` endpoint
//! with their response caps and strict result checks. Numbers are read from their source token
//! (`Number::as_str`), BTC amounts through `parse_btc_decimal` (BTC/kvB → sat/kvB by moving the
//! decimal point); nothing goes through `f64`. Server strings (`error.message`, `warnings`,
//! `errors`, `reject-reason`) are never returned: a `reject-reason` is kept only as its known
//! spec/08 §13 token (or `unknown`). The parsed answers are yw-core's `policy` input types; the
//! decisions (`check_mempool_accept`, `broadcast_outcome`) are yw-core's.

use yw_core::btc::amount::parse_btc_decimal;
use yw_core::btc::policy::{MempoolAccept, SendRawResult, known_reject_token};
use yw_core::btc::{BtcNetwork, OutPoint, Sats, Txid};
use yw_json::{Number, Object, Value};

use super::client::BtcClient;
use super::indexer::raw_tx_hex;
use crate::rpc::RpcFailure;
use crate::text::json_str;

/// `getblockhash` cap.
pub const CAP_GETBLOCKHASH: usize = 4 * 1_024;
/// `getblockchaininfo` cap.
pub const CAP_GETBLOCKCHAININFO: usize = 16 * 1_024;
/// `getrawtransaction` cap (801 KiB).
pub const CAP_GETRAWTRANSACTION: usize = 801 * 1_024;
/// `estimatesmartfee` cap.
pub const CAP_ESTIMATESMARTFEE: usize = 4 * 1_024;
/// `getmempoolinfo` cap.
pub const CAP_GETMEMPOOLINFO: usize = 4 * 1_024;
/// `testmempoolaccept` cap.
pub const CAP_TESTMEMPOOLACCEPT: usize = 16 * 1_024;
/// `sendrawtransaction` cap.
pub const CAP_SENDRAWTRANSACTION: usize = 4 * 1_024;
/// `getmempoolentry` cap.
pub const CAP_GETMEMPOOLENTRY: usize = 16 * 1_024;
/// `gettxout` cap.
pub const CAP_GETTXOUT: usize = 16 * 1_024;
/// `incrementalrelayfee` when `getmempoolinfo` lacks a usable value (spec/08 §9: 1,000 sat/kvB).
pub const INCREMENTAL_RELAY_DEFAULT: u64 = 1_000;

/// Core "Invalid address or key" / "No such mempool or blockchain transaction".
pub const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;
/// Core "Method not found".
pub const RPC_METHOD_NOT_FOUND: i64 = -32_601;
/// Core `RPC_VERIFY_ERROR` (missing or spent inputs).
pub const RPC_VERIFY_ERROR: i64 = -25;
/// Core `RPC_VERIFY_REJECTED`.
pub const RPC_VERIFY_REJECTED: i64 = -26;
/// Core `RPC_VERIFY_ALREADY_IN_CHAIN`.
pub const RPC_VERIFY_ALREADY_IN_CHAIN: i64 = -27;

fn no_params() -> Value {
    Value::Array(Vec::new())
}

fn u64_of(value: Option<&Value>) -> Result<u64, RpcFailure> {
    value
        .and_then(Value::as_number)
        .and_then(Number::as_u64)
        .ok_or(RpcFailure::Malformed)
}

fn u32_of(value: Option<&Value>) -> Result<u32, RpcFailure> {
    u64_of(value).and_then(|value| u32::try_from(value).map_err(|_| RpcFailure::Malformed))
}

/// A BTC decimal JSON number → sats (or sat/kvB for BTC/kvB values).
fn btc_number(value: Option<&Value>) -> Result<u64, RpcFailure> {
    value
        .and_then(Value::as_number)
        .and_then(|number| parse_btc_decimal(number.as_str()).ok())
        .map(Sats::get)
        .ok_or(RpcFailure::Malformed)
}

fn hex64(value: Option<&Value>) -> Result<[u8; 32], RpcFailure> {
    let text = value.and_then(Value::as_str).ok_or(RpcFailure::Malformed)?;
    yw_core::hex::decode_array::<32>(text).map_err(|_| RpcFailure::Malformed)
}

fn object_of(value: &Value) -> Result<&Object, RpcFailure> {
    value.as_object().ok_or(RpcFailure::Malformed)
}

/// `getblockhash [0]` → display-order bytes (64 lowercase hex).
///
/// # Errors
///
/// [`RpcFailure`].
pub fn get_block_hash_0(client: &BtcClient<'_>) -> Result<[u8; 32], RpcFailure> {
    let params = Value::Array(vec![Value::Number(Number::from_u64(0))]);
    let result = client.core_call("getblockhash", &params, CAP_GETBLOCKHASH, None)?;
    hex64(Some(&result))
}

/// The `getblockchaininfo` fields of `check_chain` step 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockchainInfo {
    /// `chain` (`main` / `testnet4`); `None` for any other value (not kept).
    pub chain: Option<BtcNetwork>,
    /// `blocks` (tip height).
    pub blocks: u32,
    /// `headers`.
    pub headers: u32,
    /// `initialblockdownload`.
    pub initial_block_download: bool,
    /// `mediantime` (Unix seconds).
    pub median_time: u64,
}

/// `getblockchaininfo []`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn get_blockchain_info(client: &BtcClient<'_>) -> Result<BlockchainInfo, RpcFailure> {
    let result = client.core_call(
        "getblockchaininfo",
        &no_params(),
        CAP_GETBLOCKCHAININFO,
        None,
    )?;
    let object = object_of(&result)?;
    let chain = object
        .get("chain")
        .and_then(Value::as_str)
        .ok_or(RpcFailure::Malformed)?;
    Ok(BlockchainInfo {
        chain: BtcNetwork::ALL
            .into_iter()
            .find(|net| net.core_chain() == chain),
        blocks: u32_of(object.get("blocks"))?,
        headers: u32_of(object.get("headers"))?,
        initial_block_download: object
            .get("initialblockdownload")
            .and_then(Value::as_bool)
            .ok_or(RpcFailure::Malformed)?,
        median_time: u64_of(object.get("mediantime"))?,
    })
}

/// `getrawtransaction [txid, false]` → raw bytes (lowercase even hex,
/// `<= BTC_MAX_PREV_TX_BYTES` decoded).
///
/// # Errors
///
/// [`RpcFailure`] (`Rpc(-5)` for an unknown txid).
pub fn get_raw_transaction(client: &BtcClient<'_>, txid: &Txid) -> Result<Vec<u8>, RpcFailure> {
    let params = Value::Array(vec![json_str(&txid.to_display_hex()), Value::Bool(false)]);
    let result = client.core_call(
        "getrawtransaction",
        &params,
        CAP_GETRAWTRANSACTION,
        Some(*txid),
    )?;
    let text = result.as_str().ok_or(RpcFailure::Malformed)?;
    raw_tx_hex(text).map_err(|_| RpcFailure::Malformed)
}

/// `estimatesmartfee [target, "economical"]` → sat/kvB, `None` without a usable `feerate`
/// (only `errors`, common on testnet4; or a value that is not a plain BTC decimal, e.g. an
/// exponent or more than 8 decimals: "no estimate", manual input only, spec/08 §8.2). The
/// strings are not read.
///
/// # Errors
///
/// [`RpcFailure`] (a result that is not an object).
pub fn estimate_smart_fee(client: &BtcClient<'_>, target: u32) -> Result<Option<u64>, RpcFailure> {
    let params = Value::Array(vec![
        Value::Number(Number::from_u64(u64::from(target))),
        json_str("economical"),
    ]);
    let result = client.core_call("estimatesmartfee", &params, CAP_ESTIMATESMARTFEE, None)?;
    Ok(feerate_of(object_of(&result)?))
}

/// The `feerate` of an `estimatesmartfee` result in sat/kvB; `None` when absent, `null`, zero
/// or not a plain BTC decimal.
#[must_use]
pub fn feerate_of(object: &Object) -> Option<u64> {
    btc_number(object.get("feerate"))
        .ok()
        .filter(|rate| *rate > 0)
}

/// `getmempoolinfo` fee floor inputs, sat/kvB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MempoolInfo {
    /// `mempoolminfee`.
    pub mempool_min: u64,
    /// `minrelaytxfee`.
    pub min_relay: u64,
    /// `incrementalrelayfee`.
    pub incremental: u64,
}

/// `getmempoolinfo []`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn get_mempool_info(client: &BtcClient<'_>) -> Result<MempoolInfo, RpcFailure> {
    let result = client.core_call("getmempoolinfo", &no_params(), CAP_GETMEMPOOLINFO, None)?;
    mempool_info_of(object_of(&result)?)
}

/// The fee floor inputs of a `getmempoolinfo` result: `mempoolminfee` and `minrelaytxfee` are
/// required; a missing or malformed `incrementalrelayfee` is 1,000 sat/kvB (spec/08 §9).
///
/// # Errors
///
/// [`RpcFailure::Malformed`].
pub fn mempool_info_of(object: &Object) -> Result<MempoolInfo, RpcFailure> {
    Ok(MempoolInfo {
        mempool_min: btc_number(object.get("mempoolminfee"))?,
        min_relay: btc_number(object.get("minrelaytxfee"))?,
        incremental: btc_number(object.get("incrementalrelayfee"))
            .ok()
            .filter(|rate| *rate > 0)
            .unwrap_or(INCREMENTAL_RELAY_DEFAULT),
    })
}

/// The `maxfeerate` JSON number of a literal from yw-core (`VerifiedSignedTx::maxfeerate` /
/// `fee::maxfeerate_literal`, BTC/kvB with 8 decimals, e.g. `0.00012000`, spec/08 §8.3).
///
/// # Errors
///
/// [`RpcFailure::Malformed`] when the literal is not a JSON number (never for core literals).
pub fn maxfeerate_value(literal: &str) -> Result<Value, RpcFailure> {
    Number::from_literal(literal)
        .map(Value::Number)
        .map_err(|_| RpcFailure::Malformed)
}

/// The kept `reject-reason`: the known token of spec/08 §13 or `unknown` (the server string is
/// never kept, logged or shown).
fn reject_token(object: &Object) -> &'static str {
    object
        .get("reject-reason")
        .and_then(Value::as_str)
        .and_then(known_reject_token)
        .unwrap_or("unknown")
}

fn accept_element(value: &Value) -> Result<MempoolAccept, RpcFailure> {
    let list = value.as_array().ok_or(RpcFailure::Malformed)?;
    let [element] = list else {
        return Err(RpcFailure::Malformed);
    };
    let object = object_of(element)?;
    let txid = object
        .get("txid")
        .and_then(Value::as_str)
        .and_then(|text| Txid::from_display_hex(text).ok())
        .ok_or(RpcFailure::Malformed)?;
    let wtxid = object
        .get("wtxid")
        .and_then(Value::as_str)
        .and_then(|text| Txid::from_display_hex(text).ok())
        .ok_or(RpcFailure::Malformed)?
        .to_bytes();
    let allowed = object
        .get("allowed")
        .and_then(Value::as_bool)
        .ok_or(RpcFailure::Malformed)?;
    if allowed {
        let fees = object
            .get("fees")
            .and_then(Value::as_object)
            .ok_or(RpcFailure::Malformed)?;
        Ok(MempoolAccept {
            txid,
            wtxid,
            allowed,
            vsize: Some(u64_of(object.get("vsize"))?),
            fee_base: Some(Sats::new(btc_number(fees.get("base"))?).ok_or(RpcFailure::Malformed)?),
            reject_reason: None,
        })
    } else {
        Ok(MempoolAccept {
            txid,
            wtxid,
            allowed,
            vsize: None,
            fee_base: None,
            reject_reason: Some(reject_token(object).to_owned()),
        })
    }
}

/// `testmempoolaccept [[hex], maxfeerate]` (one element), parsed into yw-core's
/// [`MempoolAccept`] (`policy::check_mempool_accept` decides).
///
/// # Errors
///
/// [`RpcFailure`].
pub fn test_mempool_accept(
    client: &BtcClient<'_>,
    raw: &[u8],
    maxfeerate: &str,
) -> Result<MempoolAccept, RpcFailure> {
    let params = Value::Array(vec![
        Value::Array(vec![json_str(&yw_core::hex::encode(raw))]),
        maxfeerate_value(maxfeerate)?,
    ]);
    let result = client.core_call("testmempoolaccept", &params, CAP_TESTMEMPOOLACCEPT, None)?;
    accept_element(&result)
}

/// Maps a failed `sendrawtransaction` call to yw-core's [`SendRawResult`]: a deadline is
/// `Timeout`; transport errors, HTTP 5xx and 429 aborts are `Transport` (communication
/// failures, spec/08 §11.3); RPC codes other than the 429 family are `RpcError`; anything else
/// (HTTP 401/403/4xx, malformed envelope) is `Refused`.
#[must_use]
pub const fn send_failure(failure: RpcFailure) -> SendRawResult {
    match failure {
        RpcFailure::Late => SendRawResult::Timeout,
        RpcFailure::Http(_)
        | RpcFailure::Status(429 | 500..=599)
        | RpcFailure::Rpc(429 | -32_005) => SendRawResult::Transport,
        RpcFailure::Rpc(code) => SendRawResult::RpcError { code },
        RpcFailure::Status(_) | RpcFailure::Malformed => SendRawResult::Refused,
    }
}

/// `sendrawtransaction [hex, maxfeerate, 0]` as yw-core's [`SendRawResult`]
/// (`policy::broadcast_outcome` decides against the local txid).
#[must_use]
pub fn send_raw_transaction(
    client: &BtcClient<'_>,
    raw: &[u8],
    maxfeerate: &str,
    local_txid: &Txid,
) -> SendRawResult {
    let Ok(literal) = maxfeerate_value(maxfeerate) else {
        return SendRawResult::Refused;
    };
    let params = Value::Array(vec![
        json_str(&yw_core::hex::encode(raw)),
        literal,
        Value::Number(Number::from_u64(0)),
    ]);
    match client.core_call(
        "sendrawtransaction",
        &params,
        CAP_SENDRAWTRANSACTION,
        Some(*local_txid),
    ) {
        Ok(result) => result
            .as_str()
            .and_then(|text| Txid::from_display_hex(text).ok())
            .map_or(SendRawResult::NotTxid, SendRawResult::Txid),
        Err(failure) => send_failure(failure),
    }
}

/// Core's view of an unspent output (`gettxout [txid, vout, true]`, mempool spends included).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutInfo {
    /// `value` (BTC decimal → sats).
    pub value: Sats,
    /// `scriptPubKey.hex`.
    pub script_pubkey: Vec<u8>,
    /// `confirmations` (0 = only in the mempool).
    pub confirmations: u32,
    /// `coinbase`.
    pub coinbase: bool,
}

/// A `gettxout` answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxOutAnswer {
    /// Unspent (not spent by a mempool transaction either).
    Unspent(TxOutInfo),
    /// `null`: spent (on chain or in the node's mempool) or unknown.
    Missing,
    /// `-32601`: the endpoint does not offer the method.
    Unsupported,
}

/// Parses a non-null `gettxout` result.
///
/// # Errors
///
/// [`RpcFailure::Malformed`].
pub fn tx_out_of(value: &Value) -> Result<TxOutAnswer, RpcFailure> {
    if value.is_null() {
        return Ok(TxOutAnswer::Missing);
    }
    let object = object_of(value)?;
    let script = object
        .get("scriptPubKey")
        .and_then(Value::as_object)
        .and_then(|script| script.get("hex"))
        .and_then(Value::as_str)
        .filter(|hex| {
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .and_then(|hex| yw_core::hex::decode(hex).ok())
        .ok_or(RpcFailure::Malformed)?;
    Ok(TxOutAnswer::Unspent(TxOutInfo {
        value: Sats::new(btc_number(object.get("value"))?).ok_or(RpcFailure::Malformed)?,
        script_pubkey: script,
        confirmations: u32_of(object.get("confirmations"))?,
        coinbase: object
            .get("coinbase")
            .and_then(Value::as_bool)
            .ok_or(RpcFailure::Malformed)?,
    }))
}

/// `gettxout [txid, vout, true]` (spec/08 §4.7-3): Core's own view of a candidate output.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn get_tx_out(client: &BtcClient<'_>, outpoint: &OutPoint) -> Result<TxOutAnswer, RpcFailure> {
    let params = Value::Array(vec![
        json_str(&outpoint.txid.to_display_hex()),
        Value::Number(Number::from_u64(u64::from(outpoint.vout))),
        Value::Bool(true),
    ]);
    match client.core_call_nullable("gettxout", &params, CAP_GETTXOUT, Some(outpoint.txid)) {
        Ok(value) => tx_out_of(&value),
        Err(RpcFailure::Rpc(RPC_METHOD_NOT_FOUND)) => Ok(TxOutAnswer::Unsupported),
        Err(failure) => Err(failure),
    }
}

/// `getmempoolentry` observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MempoolEntry {
    /// An object: in the node's mempool.
    InMempool,
    /// `-5`: not in the mempool.
    Absent,
    /// `-32601`: the endpoint does not offer the method (spec/08 §4.5 C2).
    Unsupported,
}

/// `getmempoolentry [txid]`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn get_mempool_entry(client: &BtcClient<'_>, txid: &Txid) -> Result<MempoolEntry, RpcFailure> {
    let params = Value::Array(vec![json_str(&txid.to_display_hex())]);
    match client.core_call("getmempoolentry", &params, CAP_GETMEMPOOLENTRY, Some(*txid)) {
        Ok(Value::Object(_)) => Ok(MempoolEntry::InMempool),
        Ok(_) => Err(RpcFailure::Malformed),
        Err(RpcFailure::Rpc(RPC_INVALID_ADDRESS_OR_KEY)) => Ok(MempoolEntry::Absent),
        Err(RpcFailure::Rpc(RPC_METHOD_NOT_FOUND)) => Ok(MempoolEntry::Unsupported),
        Err(failure) => Err(failure),
    }
}
