//! `btc::indexer` (spec/08 §4.3): the address indexer behind one request type. Requests are
//! built only from [`BtcIndexerReq`] (our own `BtcAddress`, a `Txid`, or the fixed genesis / tip
//! requests), so no other string can reach a path or params: `esplora` GETs
//! `<esploraBaseUrl>/address/{a}/utxo`, `/address/{a}`, `/tx/{t}/status`, `/tx/{t}/hex`,
//! `/block-height/0`, `/blocks/tip/height` (no trailing `/`, no query); `bb-rpc` calls
//! `bb_getUTXOs`, `bb_getAddress`, `bb_getTx`, `bb_getBlockHash` on the Core URL; `bb-rest` GETs
//! `utxo/`, `address/`, `tx/`, `block-index/0` under `<Core URL>/api/v2/`. `TipHeight` exists
//! for `esplora` only. The opt-in received history's `AddressTxs` (spec/04 §2.6) is Esplora
//! `/address/{a}/txs` (2026-11-11) and, since 2026-11-13, Blockbook `details=txs` page 1
//! (`bb-rest` `address/{a}?details=txs&page=1&pageSize=25`, `bb-rpc` `bb_getAddress` with
//! `{"details":"txs","page":1,"size":25}`).
//!
//! The parsers are strict (spec/08 §4.1): Esplora integers are JSON integer tokens within the
//! field bound, Blockbook amounts are decimal strings, txids and hashes are 64 lowercase hex,
//! status fields must agree, the address is echoed, counts are consistent, no duplicate
//! outpoints, Esplora `Content-Type` matches the path, text endpoints are exact bodies. Anything
//! else is `Malformed` (E-BTC-004). A `Utxo` list over 1,000 entries or over its 1 MiB cap is
//! `TooMany` (E-BTC-005, one crowded address: the refresh skips it). Server bodies are never kept.

use std::collections::HashSet;

use yw_core::btc::address::BtcAddress;
use yw_core::btc::{BTC_INDEXER_MAX_UTXOS, BTC_MAX_PREV_TX_BYTES, MAX_MONEY, OutPoint, Sats, Txid};
use yw_json::{Limits, Number, Object, Value};
use yw_win::http::{HttpError, HttpsUrl, Response};

use super::client::{BtcClient, Tag};
use super::indexer_display;
use crate::errors::ErrorCode;
use crate::logging::Field;
use crate::rpc::{RpcFailure, classify};
use crate::settings::{BtcIndexer, LogLevel};
use crate::text::{json_object, json_str, json_u64};

/// `Utxo` response cap (1 MiB).
pub const CAP_UTXO: usize = 1_048_576;
/// `Address` response cap (16 KiB).
pub const CAP_ADDRESS: usize = 16 * 1_024;
/// Esplora `/tx/{t}/status` cap (4 KiB).
pub const CAP_ESPLORA_TX_STATUS: usize = 4 * 1_024;
/// Esplora `/tx/{t}/hex` cap (801 KiB).
pub const CAP_ESPLORA_TX_HEX: usize = 801 * 1_024;
/// Blockbook `bb_getTx` / `tx/{t}` cap (2 MiB).
pub const CAP_BB_TX: usize = 2 * 1_048_576;
/// `GenesisHash` cap (4 KiB).
pub const CAP_GENESIS: usize = 4 * 1_024;
/// Esplora `/blocks/tip/height` cap (4 KiB).
pub const CAP_TIP: usize = 4 * 1_024;
/// Esplora `/address/{a}/txs` cap (4 MiB: up to 50 mempool and 25 confirmed transactions).
pub const CAP_ADDRESS_TXS: usize = 4 * 1_048_576;
/// Blockbook `details=txs` page cap (4 MiB: every mempool transaction plus 25 confirmed ones; a
/// mempool flood over it is `Malformed` and that address is skipped).
pub const CAP_BB_ADDRESS_TXS: usize = 4 * 1_048_576;

const U32_MAX: u64 = 4_294_967_295;
const I64_MAX: u64 = 9_223_372_036_854_775_807;

/// An indexer request (spec/08 §4.3); the only way to build indexer traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BtcIndexerReq {
    /// UTXO candidates of one of our addresses.
    Utxo(BtcAddress),
    /// History counts of one of our addresses.
    Address(BtcAddress),
    /// Confirmation status of a txid (tracking, spec/08 §12.2).
    TxStatus(Txid),
    /// Raw transaction (fallback when Core `getrawtransaction` fails, spec/08 §4.7-4).
    TxRaw(Txid),
    /// Block 0 hash (spec/08 §2 step 3).
    GenesisHash,
    /// Indexer tip height (`esplora` only, spec/08 §2 step 4).
    TipHeight,
    /// Recent transactions of one of our addresses, mempool included (the opt-in received
    /// history, spec/04 §2.6; every indexer since 2026-11-13).
    AddressTxs(BtcAddress),
}

impl BtcIndexerReq {
    const fn txid(&self) -> Option<Txid> {
        match self {
            Self::TxStatus(txid) | Self::TxRaw(txid) => Some(*txid),
            Self::Utxo(_)
            | Self::Address(_)
            | Self::AddressTxs(_)
            | Self::GenesisHash
            | Self::TipHeight => None,
        }
    }

    const fn address(&self) -> Option<&BtcAddress> {
        match self {
            Self::Utxo(address) | Self::Address(address) | Self::AddressTxs(address) => {
                Some(address)
            }
            Self::TxStatus(_) | Self::TxRaw(_) | Self::GenesisHash | Self::TipHeight => None,
        }
    }
}

/// One UTXO candidate (never an amount source: spec/08 §5 decides).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoCandidate {
    /// Outpoint.
    pub outpoint: OutPoint,
    /// Indexer value (hint only).
    pub value_hint: Sats,
    /// Block height; `None` = unconfirmed.
    pub height: Option<u32>,
}

/// History of one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrSummary {
    /// Confirmed + mempool transactions (`> 0` = used).
    pub tx_count: u64,
    /// The address has confirmed unspent outputs (ask `Utxo`).
    pub confirmed_unspent: bool,
    /// Unconfirmed incoming funds ("미확정 입금", unverified).
    pub unconfirmed_incoming: bool,
}

/// Confirmation status of a txid (the yw-core tracking input type, spec/08 §4.3 `TxSeen`).
pub use yw_core::journal::btc::TxSeen;

/// A parsed indexer response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BtcIndexerResp {
    /// ≤ 1,000 candidates, no duplicate outpoint.
    Utxo(Vec<UtxoCandidate>),
    /// Address summary.
    Address(AddrSummary),
    /// Tx status.
    TxStatus(TxSeen),
    /// Raw transaction bytes (unverified until spec/08 §5).
    TxRaw(Vec<u8>),
    /// Block 0 hash, display-order bytes.
    GenesisHash([u8; 32]),
    /// Indexer tip height.
    TipHeight(u32),
    /// Recent transactions of an address (the received history derives from them).
    AddressTxs(Vec<crate::received::btc::AddrTx>),
}

/// Why an indexer request failed (spec/08 §4.3, spec/04 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexerError {
    /// E-BTC-001: transport error (cause E-RPC-001/002/008), HTTP 3xx/5xx/other.
    Unreachable(Option<ErrorCode>),
    /// E-BTC-002: HTTP 429 after three retries (job aborted, cooldown started).
    RateLimited,
    /// E-BTC-004: response format, `Content-Type` or unexpected 404.
    Malformed,
    /// E-BTC-005: Esplora HTTP 400 on `Utxo` / `Address`.
    Rejected,
    /// E-BTC-005: a `Utxo` list over [`BTC_INDEXER_MAX_UTXOS`] entries or over [`CAP_UTXO`]
    /// (too many outputs at one address; the refresh skips that address, spec/08 §4.7-3).
    TooMany,
    /// E-BTC-007: HTTP 401/403, `bb-*` add-on disabled (`-32601`).
    Auth,
    /// HTTP 404 of `TxRaw` (`NotFound`, spec/08 §4.3): not shown by itself.
    NotFound,
    /// Not built: `TipHeight` on `bb-*`, an address of another network, an address before
    /// `check_chain` step 3 passed (internal error, nothing sent).
    Refused,
}

impl IndexerError {
    /// The classified code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::Unreachable(_) => ErrorCode::Btc001,
            Self::RateLimited => ErrorCode::Btc002,
            Self::Malformed | Self::NotFound => ErrorCode::Btc004,
            Self::Rejected | Self::TooMany => ErrorCode::Btc005,
            Self::Auth => ErrorCode::Btc007,
            Self::Refused => ErrorCode::App009,
        }
    }

    /// The fixed text in `lang`, E-BTC-001 with the indexer name and its cause code.
    #[must_use]
    pub fn text(self, lang: yw_core::lang::Lang, indexer: BtcIndexer) -> String {
        match self {
            Self::Unreachable(cause) => {
                ErrorCode::Btc001.render_with_cause_in(lang, indexer_display(indexer), cause)
            }
            other => other.code().text_in(lang),
        }
    }
}

impl core::fmt::Display for IndexerError {
    /// The code only (never a server string).
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code().code())
    }
}

impl std::error::Error for IndexerError {}

/// Esplora path, log kind, cap and expected media type of a request.
fn esplora_path(request: &BtcIndexerReq) -> (String, &'static str, usize, &'static str) {
    const JSON: &str = "application/json";
    const TEXT: &str = "text/plain";
    match request {
        BtcIndexerReq::Utxo(address) => (
            format!("/address/{}/utxo", address.as_str()),
            "utxo",
            CAP_UTXO,
            JSON,
        ),
        BtcIndexerReq::Address(address) => (
            format!("/address/{}", address.as_str()),
            "address",
            CAP_ADDRESS,
            JSON,
        ),
        BtcIndexerReq::TxStatus(txid) => (
            format!("/tx/{}/status", txid.to_display_hex()),
            "tx-status",
            CAP_ESPLORA_TX_STATUS,
            JSON,
        ),
        BtcIndexerReq::TxRaw(txid) => (
            format!("/tx/{}/hex", txid.to_display_hex()),
            "tx-hex",
            CAP_ESPLORA_TX_HEX,
            TEXT,
        ),
        BtcIndexerReq::GenesisHash => (
            "/block-height/0".to_owned(),
            "block-height",
            CAP_GENESIS,
            TEXT,
        ),
        BtcIndexerReq::TipHeight => ("/blocks/tip/height".to_owned(), "tip-height", CAP_TIP, TEXT),
        BtcIndexerReq::AddressTxs(address) => (
            format!("/address/{}/txs", address.as_str()),
            "address-txs",
            CAP_ADDRESS_TXS,
            JSON,
        ),
    }
}

/// `bb-rest` path (under `/api/v2/`), log kind and cap.
fn bb_rest_path(request: &BtcIndexerReq) -> Option<(String, &'static str, usize)> {
    Some(match request {
        BtcIndexerReq::Utxo(address) => (
            format!("utxo/{}?confirmed=true", address.as_str()),
            "utxo",
            CAP_UTXO,
        ),
        BtcIndexerReq::Address(address) => (
            format!("address/{}?details=basic", address.as_str()),
            "address",
            CAP_ADDRESS,
        ),
        BtcIndexerReq::TxStatus(txid) | BtcIndexerReq::TxRaw(txid) => {
            (format!("tx/{}", txid.to_display_hex()), "tx", CAP_BB_TX)
        }
        BtcIndexerReq::GenesisHash => ("block-index/0".to_owned(), "block-index", CAP_GENESIS),
        BtcIndexerReq::AddressTxs(address) => (
            format!(
                "address/{}?details=txs&page=1&pageSize={}",
                address.as_str(),
                crate::received::btc::BB_PAGE_SIZE
            ),
            "address-txs",
            CAP_BB_ADDRESS_TXS,
        ),
        BtcIndexerReq::TipHeight => return None,
    })
}

/// `bb-rpc` method, params and cap.
fn bb_rpc_call(request: &BtcIndexerReq) -> Option<(&'static str, Value, usize)> {
    Some(match request {
        BtcIndexerReq::Utxo(address) => (
            "bb_getUTXOs",
            Value::Array(vec![
                json_str(address.as_str()),
                json_object(vec![("confirmed", Value::Bool(true))]),
            ]),
            CAP_UTXO,
        ),
        BtcIndexerReq::Address(address) => (
            "bb_getAddress",
            Value::Array(vec![
                json_str(address.as_str()),
                json_object(vec![("details", json_str("basic"))]),
            ]),
            CAP_ADDRESS,
        ),
        BtcIndexerReq::TxStatus(txid) | BtcIndexerReq::TxRaw(txid) => (
            "bb_getTx",
            Value::Array(vec![json_str(&txid.to_display_hex())]),
            CAP_BB_TX,
        ),
        BtcIndexerReq::GenesisHash => (
            "bb_getBlockHash",
            Value::Array(vec![json_str("0")]),
            CAP_GENESIS,
        ),
        // `size` in bb-rpc, `pageSize` in bb-rest (spec/08 §4.3).
        BtcIndexerReq::AddressTxs(address) => (
            "bb_getAddress",
            Value::Array(vec![
                json_str(address.as_str()),
                json_object(vec![
                    ("details", json_str("txs")),
                    ("page", json_u64(1)),
                    (
                        "size",
                        json_u64(u64::from(crate::received::btc::BB_PAGE_SIZE)),
                    ),
                ]),
            ]),
            CAP_BB_ADDRESS_TXS,
        ),
        BtcIndexerReq::TipHeight => return None,
    })
}

fn join(base: &str, tail: &str) -> Result<HttpsUrl, IndexerError> {
    HttpsUrl::parse(&format!("{base}{tail}")).map_err(|_| IndexerError::Refused)
}

/// Transport failure → E-BTC-001 with its cause (too large responses are malformed).
#[must_use]
pub const fn transport_error(error: HttpError) -> IndexerError {
    match error {
        HttpError::TooLarge => IndexerError::Malformed,
        other => IndexerError::Unreachable(Some(classify(RpcFailure::Http(other)))),
    }
}

/// [`transport_error`], except that a `Utxo` answer over its cap is [`IndexerError::TooMany`]
/// (the size of one address's list, not a broken indexer).
fn transport_error_of(request: &BtcIndexerReq, error: HttpError) -> IndexerError {
    match (request, error) {
        (BtcIndexerReq::Utxo(_), HttpError::TooLarge) => IndexerError::TooMany,
        (_, other) => transport_error(other),
    }
}

/// `bb-rpc` failure mapping (spec/08 §4.3 "`bb-*` 오류").
#[must_use]
pub const fn bb_rpc_error(failure: RpcFailure) -> IndexerError {
    match failure {
        RpcFailure::Http(error) => transport_error(error),
        RpcFailure::Late => IndexerError::Unreachable(Some(ErrorCode::Rpc002)),
        RpcFailure::Status(401 | 403) | RpcFailure::Rpc(-32_601) => IndexerError::Auth,
        RpcFailure::Status(429) | RpcFailure::Rpc(429 | -32_005) => IndexerError::RateLimited,
        RpcFailure::Malformed => IndexerError::Malformed,
        RpcFailure::Status(_) | RpcFailure::Rpc(_) => IndexerError::Unreachable(None),
    }
}

/// Sends `request` to the configured indexer and parses the reply (low level: the pipelines of
/// `btc::flow` send `Utxo` / `Address` / `TxRaw` only after `check_chain` step 3 passed in the
/// session, and `btc::chain` sends `GenesisHash` / `TipHeight`).
///
/// # Errors
///
/// [`IndexerError`]; nothing is sent for [`IndexerError::Refused`].
pub fn fetch(
    client: &BtcClient<'_>,
    request: &BtcIndexerReq,
) -> Result<BtcIndexerResp, IndexerError> {
    let endpoint = client.endpoint();
    if request
        .address()
        .is_some_and(|address| address.network() != endpoint.net)
    {
        return Err(IndexerError::Refused);
    }
    let txid = request.txid();
    let (result, tag) = match endpoint.indexer {
        BtcIndexer::Esplora => {
            let (path, kind, cap, _) = esplora_path(request);
            let tag = Tag {
                idx: Some(BtcIndexer::Esplora),
                what: kind,
                is_method: false,
                txid,
            };
            let base = endpoint.esplora_base.expose();
            let result = join(base.strip_suffix('/').unwrap_or(base), &path).and_then(|url| {
                client
                    .get(&url, cap, tag)
                    .map_err(|error| transport_error_of(request, error))
                    .and_then(|response| parse_esplora(request, &response))
            });
            (result, tag)
        }
        BtcIndexer::BbRest => {
            let Some((path, kind, cap)) = bb_rest_path(request) else {
                return Err(IndexerError::Refused);
            };
            let tag = Tag {
                idx: Some(BtcIndexer::BbRest),
                what: kind,
                is_method: false,
                txid,
            };
            let core = endpoint.core_url.expose();
            let base = format!("{}/api/v2/", core.strip_suffix('/').unwrap_or(core));
            let result = join(&base, &path).and_then(|url| {
                client
                    .get(&url, cap, tag)
                    .map_err(|error| transport_error_of(request, error))
                    .and_then(|response| parse_bb_rest(request, &response))
            });
            (result, tag)
        }
        BtcIndexer::BbRpc => {
            let Some((method, params, cap)) = bb_rpc_call(request) else {
                return Err(IndexerError::Refused);
            };
            let tag = Tag {
                idx: Some(BtcIndexer::BbRpc),
                what: method,
                is_method: true,
                txid,
            };
            let result = client
                .json_rpc(&endpoint.core_url, method, &params, cap, tag)
                .map_err(|failure| match (request, failure) {
                    (_, RpcFailure::Http(error)) => transport_error_of(request, error),
                    // A Blockbook that refuses `details=txs` for this address (2026-11-13):
                    // that address is skipped; `-32601` (the add-on is off) and rate limits
                    // keep their meaning.
                    (BtcIndexerReq::AddressTxs(_), RpcFailure::Rpc(code))
                        if !matches!(code, -32_601 | 429 | -32_005) =>
                    {
                        IndexerError::Rejected
                    }
                    (_, other) => bb_rpc_error(other),
                })
                .and_then(|value| parse_bb(request, &value));
            (result, tag)
        }
    };
    if let Err(error) = result
        && error != IndexerError::NotFound
    {
        client.log(
            LogLevel::Warn,
            error.code().code(),
            tag,
            &[("cause", Field::Word(error_word(error)))],
        );
    }
    result
}

const fn error_word(error: IndexerError) -> &'static str {
    match error {
        IndexerError::Unreachable(_) => "unreachable",
        IndexerError::RateLimited => "rate_limited",
        IndexerError::Malformed => "malformed",
        IndexerError::Rejected => "rejected",
        IndexerError::TooMany => "too_many",
        IndexerError::Auth => "auth",
        IndexerError::NotFound => "not_found",
        IndexerError::Refused => "refused",
    }
}

/// The media type of a `Content-Type` value: before `;`, trimmed, lowercase.
#[must_use]
pub fn media_type(content_type: Option<&str>) -> Option<String> {
    content_type
        .and_then(|value| value.split(';').next())
        .map(|media| media.trim().to_ascii_lowercase())
}

const fn malformed<T>() -> Result<T, IndexerError> {
    Err(IndexerError::Malformed)
}

fn parse_json(body: &[u8], cap: usize) -> Result<Value, IndexerError> {
    let limits = Limits {
        max_bytes: cap,
        ..Limits::RESPONSE
    };
    yw_json::parse(body, &limits).map_err(|_| IndexerError::Malformed)
}

/// Esplora integer rule (spec/08 §4.1): a JSON number token `^(0|[1-9][0-9]*)$` with value
/// `<= max`.
///
/// # Errors
///
/// [`IndexerError::Malformed`].
pub fn esplora_uint(value: &Value, max: u64) -> Result<u64, IndexerError> {
    let Some(number) = value.as_number() else {
        return malformed();
    };
    let text = number.as_str();
    let canonical = text == "0"
        || (text
            .bytes()
            .next()
            .is_some_and(|first| (b'1'..=b'9').contains(&first))
            && text.bytes().all(|byte| byte.is_ascii_digit()));
    match number.as_u64() {
        Some(parsed) if canonical && parsed <= max => Ok(parsed),
        _ => malformed(),
    }
}

fn uint_field(object: &Object, key: &str, max: u64) -> Result<u64, IndexerError> {
    object
        .get(key)
        .ok_or(IndexerError::Malformed)
        .and_then(|value| esplora_uint(value, max))
}

fn u32_field(object: &Object, key: &str) -> Result<u32, IndexerError> {
    uint_field(object, key, U32_MAX)
        .and_then(|value| u32::try_from(value).map_err(|_| IndexerError::Malformed))
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_text(value: Option<&Value>) -> Result<[u8; 32], IndexerError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(IndexerError::Malformed)?;
    if text.len() != 64 || !is_lower_hex(text) {
        return malformed();
    }
    yw_core::hex::decode_array::<32>(text).map_err(|_| IndexerError::Malformed)
}

fn txid_text(value: Option<&Value>) -> Result<Txid, IndexerError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(IndexerError::Malformed)?;
    Txid::from_display_hex(text).map_err(|_| IndexerError::Malformed)
}

/// Raw transaction hex: `^([0-9a-f]{2})+$`, decoded `<= BTC_MAX_PREV_TX_BYTES`.
///
/// # Errors
///
/// [`IndexerError::Malformed`].
pub fn raw_tx_hex(text: &str) -> Result<Vec<u8>, IndexerError> {
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || text.len() / 2 > BTC_MAX_PREV_TX_BYTES
        || !is_lower_hex(text)
    {
        return malformed();
    }
    yw_core::hex::decode(text).map_err(|_| IndexerError::Malformed)
}

/// The `status` object rule shared by `Utxo` and `TxStatus`: `confirmed:true` needs
/// `block_height`, `block_hash`, `block_time`; `confirmed:false` needs all three absent or
/// `null`. Returns the height when confirmed.
fn esplora_status(value: &Value) -> Result<Option<u32>, IndexerError> {
    let object = value.as_object().ok_or(IndexerError::Malformed)?;
    let confirmed = object
        .get("confirmed")
        .and_then(Value::as_bool)
        .ok_or(IndexerError::Malformed)?;
    let present = |key: &str| object.get(key).filter(|value| !value.is_null());
    if confirmed {
        let height = present("block_height")
            .ok_or(IndexerError::Malformed)
            .and_then(|value| esplora_uint(value, U32_MAX))?;
        hash_text(present("block_hash"))?;
        present("block_time")
            .ok_or(IndexerError::Malformed)
            .and_then(|value| esplora_uint(value, I64_MAX))?;
        u32::try_from(height)
            .map(Some)
            .map_err(|_| IndexerError::Malformed)
    } else if ["block_height", "block_hash", "block_time"]
        .iter()
        .any(|key| present(key).is_some())
    {
        malformed()
    } else {
        Ok(None)
    }
}

fn esplora_utxos(value: &Value) -> Result<Vec<UtxoCandidate>, IndexerError> {
    let items = value.as_array().ok_or(IndexerError::Malformed)?;
    if items.len() > BTC_INDEXER_MAX_UTXOS {
        return Err(IndexerError::TooMany);
    }
    let mut seen = HashSet::with_capacity(items.len());
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let object = item.as_object().ok_or(IndexerError::Malformed)?;
        let outpoint = OutPoint {
            txid: txid_text(object.get("txid"))?,
            vout: u32_field(object, "vout")?,
        };
        let value_hint =
            Sats::new(uint_field(object, "value", MAX_MONEY)?).ok_or(IndexerError::Malformed)?;
        let height = esplora_status(object.get("status").ok_or(IndexerError::Malformed)?)?;
        if !seen.insert(outpoint) {
            return malformed();
        }
        out.push(UtxoCandidate {
            outpoint,
            value_hint,
            height,
        });
    }
    Ok(out)
}

#[derive(Clone, Copy)]
struct Stats {
    funded: u64,
    spent: u64,
    txs: u64,
}

fn esplora_stats(value: Option<&Value>) -> Result<Stats, IndexerError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or(IndexerError::Malformed)?;
    let stats = Stats {
        funded: uint_field(object, "funded_txo_count", U32_MAX)?,
        spent: uint_field(object, "spent_txo_count", U32_MAX)?,
        txs: uint_field(object, "tx_count", U32_MAX)?,
    };
    if stats.txs == 0 && (stats.funded != 0 || stats.spent != 0) {
        return malformed();
    }
    Ok(stats)
}

fn esplora_address(value: &Value, requested: &BtcAddress) -> Result<AddrSummary, IndexerError> {
    let object = value.as_object().ok_or(IndexerError::Malformed)?;
    if object.get("address").and_then(Value::as_str) != Some(requested.as_str()) {
        return malformed();
    }
    let chain = esplora_stats(object.get("chain_stats"))?;
    let mempool = esplora_stats(object.get("mempool_stats"))?;
    // Mempool transactions may spend confirmed outputs, so only the sums are compared.
    if chain.spent > chain.funded || chain.spent + mempool.spent > chain.funded + mempool.funded {
        return malformed();
    }
    Ok(AddrSummary {
        tx_count: chain.txs + mempool.txs,
        confirmed_unspent: chain.funded > chain.spent,
        unconfirmed_incoming: mempool.funded > 0,
    })
}

fn body_text(body: &[u8]) -> Result<&str, IndexerError> {
    core::str::from_utf8(body).map_err(|_| IndexerError::Malformed)
}

fn genesis_body(body: &[u8]) -> Result<[u8; 32], IndexerError> {
    let text = body_text(body)?;
    if text.len() != 64 || !is_lower_hex(text) {
        return malformed();
    }
    yw_core::hex::decode_array::<32>(text).map_err(|_| IndexerError::Malformed)
}

fn tip_body(body: &[u8]) -> Result<u32, IndexerError> {
    let text = body_text(body)?;
    let canonical = text == "0"
        || ((1..=10).contains(&text.len())
            && text
                .bytes()
                .next()
                .is_some_and(|first| (b'1'..=b'9').contains(&first))
            && text.bytes().all(|byte| byte.is_ascii_digit()));
    if !canonical {
        return malformed();
    }
    text.parse::<u32>().map_err(|_| IndexerError::Malformed)
}

/// Maps an Esplora response (status, `Content-Type`, body) for `request` (spec/08 §4.3).
///
/// # Errors
///
/// [`IndexerError`].
pub fn parse_esplora(
    request: &BtcIndexerReq,
    response: &Response,
) -> Result<BtcIndexerResp, IndexerError> {
    match (response.status, request) {
        (200, _) => {}
        (
            400,
            BtcIndexerReq::Utxo(_) | BtcIndexerReq::Address(_) | BtcIndexerReq::AddressTxs(_),
        ) => {
            return Err(IndexerError::Rejected);
        }
        (404, BtcIndexerReq::TxStatus(_)) => return Ok(BtcIndexerResp::TxStatus(TxSeen::NotFound)),
        (404, BtcIndexerReq::TxRaw(_)) => return Err(IndexerError::NotFound),
        (404, _) => return malformed(),
        (429, _) => return Err(IndexerError::RateLimited),
        (401 | 403, _) => return Err(IndexerError::Auth),
        _ => return Err(IndexerError::Unreachable(None)),
    }
    let (_, _, cap, media) = esplora_path(request);
    if media_type(response.content_type.as_deref()).as_deref() != Some(media) {
        return malformed();
    }
    let body = response.body.as_slice();
    match request {
        BtcIndexerReq::Utxo(_) => esplora_utxos(&parse_json(body, cap)?).map(BtcIndexerResp::Utxo),
        BtcIndexerReq::Address(address) => {
            esplora_address(&parse_json(body, cap)?, address).map(BtcIndexerResp::Address)
        }
        BtcIndexerReq::TxStatus(_) => esplora_status(&parse_json(body, cap)?).map(|height| {
            BtcIndexerResp::TxStatus(height.map_or(TxSeen::UnconfirmedOrUnknown, |height| {
                TxSeen::Confirmed { height }
            }))
        }),
        BtcIndexerReq::TxRaw(_) => raw_tx_hex(body_text(body)?).map(BtcIndexerResp::TxRaw),
        BtcIndexerReq::GenesisHash => genesis_body(body).map(BtcIndexerResp::GenesisHash),
        BtcIndexerReq::TipHeight => tip_body(body).map(BtcIndexerResp::TipHeight),
        BtcIndexerReq::AddressTxs(_) => {
            crate::received::btc::parse_txs(&parse_json(body, cap)?).map(BtcIndexerResp::AddressTxs)
        }
    }
}

/// A Blockbook sats amount string `^(0|-?[1-9][0-9]{0,18})$` with magnitude `<= MAX_MONEY`;
/// negative only when `signed`. Returns `(negative, magnitude)`.
///
/// # Errors
///
/// [`IndexerError::Malformed`] (also for a JSON number).
pub fn bb_amount(value: Option<&Value>, signed: bool) -> Result<(bool, u64), IndexerError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(IndexerError::Malformed)?;
    if text == "0" {
        return Ok((false, 0));
    }
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) if signed => (true, digits),
        Some(_) => return malformed(),
        None => (false, text),
    };
    let canonical = (1..=19).contains(&digits.len())
        && digits
            .bytes()
            .next()
            .is_some_and(|first| (b'1'..=b'9').contains(&first))
        && digits.bytes().all(|byte| byte.is_ascii_digit());
    match digits.parse::<u64>() {
        Ok(magnitude) if canonical && magnitude <= MAX_MONEY => Ok((negative, magnitude)),
        _ => malformed(),
    }
}

fn echo_matches(object: &Object, key: &str, expected: &str) -> bool {
    object
        .get(key)
        .is_none_or(|value| value.as_str() == Some(expected))
}

fn bb_utxos(value: &Value) -> Result<Vec<UtxoCandidate>, IndexerError> {
    let items = value.as_array().ok_or(IndexerError::Malformed)?;
    if items.len() > BTC_INDEXER_MAX_UTXOS {
        return Err(IndexerError::TooMany);
    }
    let mut seen = HashSet::with_capacity(items.len());
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let object = item.as_object().ok_or(IndexerError::Malformed)?;
        let outpoint = OutPoint {
            txid: txid_text(object.get("txid"))?,
            vout: u32_field(object, "vout")?,
        };
        let (_, value) = bb_amount(object.get("value"), false)?;
        let value_hint = Sats::new(value).ok_or(IndexerError::Malformed)?;
        let confirmations = u32_field(object, "confirmations")?;
        if !seen.insert(outpoint) {
            return malformed();
        }
        // `confirmed:true` was asked; an unconfirmed element is dropped.
        if confirmations >= 1 {
            out.push(UtxoCandidate {
                outpoint,
                value_hint,
                height: Some(u32_field(object, "height")?),
            });
        }
    }
    Ok(out)
}

fn bb_address(value: &Value, requested: &BtcAddress) -> Result<AddrSummary, IndexerError> {
    let object = value.as_object().ok_or(IndexerError::Malformed)?;
    if !echo_matches(object, "address", requested.as_str()) {
        return malformed();
    }
    let txs = uint_field(object, "txs", U32_MAX)?;
    let unconfirmed_txs = uint_field(object, "unconfirmedTxs", U32_MAX)?;
    let (_, balance) = bb_amount(object.get("balance"), false)?;
    let (negative, unconfirmed) = bb_amount(object.get("unconfirmedBalance"), true)?;
    Ok(AddrSummary {
        tx_count: txs + unconfirmed_txs,
        confirmed_unspent: balance != 0,
        unconfirmed_incoming: !negative && unconfirmed > 0,
    })
}

fn bb_tx_object<'v>(value: &'v Value, txid: &Txid) -> Result<&'v Object, IndexerError> {
    let object = value.as_object().ok_or(IndexerError::Malformed)?;
    if echo_matches(object, "txid", &txid.to_display_hex()) {
        Ok(object)
    } else {
        malformed()
    }
}

fn bb_tx_status(object: &Object) -> Result<TxSeen, IndexerError> {
    let confirmations = u32_field(object, "confirmations")?;
    if confirmations == 0 {
        return Ok(TxSeen::Unconfirmed);
    }
    let height = object
        .get("blockHeight")
        .and_then(Value::as_number)
        .and_then(Number::as_i64)
        .and_then(|height| u32::try_from(height).ok())
        .ok_or(IndexerError::Malformed)?;
    Ok(TxSeen::Confirmed { height })
}

/// Maps a Blockbook JSON value (`bb-rpc` `result` or `bb-rest` body) for `request`.
///
/// # Errors
///
/// [`IndexerError::Malformed`] or [`IndexerError::Refused`] (`TipHeight`).
pub fn parse_bb(request: &BtcIndexerReq, value: &Value) -> Result<BtcIndexerResp, IndexerError> {
    match request {
        BtcIndexerReq::Utxo(_) => bb_utxos(value).map(BtcIndexerResp::Utxo),
        BtcIndexerReq::Address(address) => bb_address(value, address).map(BtcIndexerResp::Address),
        BtcIndexerReq::TxStatus(txid) => {
            bb_tx_status(bb_tx_object(value, txid)?).map(BtcIndexerResp::TxStatus)
        }
        BtcIndexerReq::TxRaw(txid) => {
            let object = bb_tx_object(value, txid)?;
            let hex = object
                .get("hex")
                .and_then(Value::as_str)
                .ok_or(IndexerError::Malformed)?;
            raw_tx_hex(hex).map(BtcIndexerResp::TxRaw)
        }
        BtcIndexerReq::GenesisHash => {
            let object = value.as_object().ok_or(IndexerError::Malformed)?;
            hash_text(object.get("blockHash")).map(BtcIndexerResp::GenesisHash)
        }
        BtcIndexerReq::AddressTxs(address) => {
            crate::received::btc::parse_bb_txs(value, address.as_str())
                .map(BtcIndexerResp::AddressTxs)
        }
        BtcIndexerReq::TipHeight => Err(IndexerError::Refused),
    }
}

/// Maps a `bb-rest` response: 200 → [`parse_bb`]; 401/403 → `Auth`; 404 → `NotFound` for
/// `TxStatus` / `TxRaw`; 400/404 → `Rejected` for `AddressTxs` (no `details=txs`, 2026-11-13),
/// `Malformed` otherwise; 429 → `RateLimited`; others → E-BTC-001.
///
/// # Errors
///
/// [`IndexerError`].
pub fn parse_bb_rest(
    request: &BtcIndexerReq,
    response: &Response,
) -> Result<BtcIndexerResp, IndexerError> {
    match (response.status, request) {
        (200, _) => {}
        (404, BtcIndexerReq::TxStatus(_)) => return Ok(BtcIndexerResp::TxStatus(TxSeen::NotFound)),
        (404, BtcIndexerReq::TxRaw(_)) => return Err(IndexerError::NotFound),
        (400 | 404, BtcIndexerReq::AddressTxs(_)) => return Err(IndexerError::Rejected),
        (404, _) => return malformed(),
        (429, _) => return Err(IndexerError::RateLimited),
        (401 | 403, _) => return Err(IndexerError::Auth),
        _ => return Err(IndexerError::Unreachable(None)),
    }
    let cap = bb_rest_path(request).map_or(CAP_GENESIS, |(_, _, cap)| cap);
    parse_bb(request, &parse_json(&response.body, cap)?)
}
