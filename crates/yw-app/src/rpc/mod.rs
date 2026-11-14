//! RPC transport shared by every chain (spec/04 §1.9) and the endpoint `테스트` of the settings
//! screen (spec/04 §2.11.1). `rpc::evm` holds the EVM calls; the Solana calls are
//! `crate::sol::rpc` (M7).
//!
//! JSON-RPC 2.0 over `yw_win::http::Client` (HTTPS only, TLS 1.2/1.3, no redirects/cookies/auth,
//! no Origin), one increasing `id` per request checked against the response. Failures are
//! classified into fixed codes; URLs, hosts and remote strings never leave this module.

pub mod evm;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use yw_core::evm::amount::U256;
use yw_json::{Limits, Number, Value};
use yw_win::http::{Client, EndpointUrl, HttpError, HttpsUrl, Response, Timeouts};

use crate::errors::ErrorCode;
use crate::network::{BtcNet, NetworkId, SolCluster};
use crate::text::{json_object, json_str, json_u64};

/// RPC timeouts (spec/03 §1.4: resolve 5 s, connect 5 s, send 10 s, receive 10 s).
pub const RPC_TIMEOUTS: Timeouts = Timeouts {
    resolve_ms: 5_000,
    connect_ms: 5_000,
    send_ms: 10_000,
    receive_ms: 10_000,
};
/// Per-call deadline; later results count as timeouts (spec/01 §7.4).
pub const CALL_DEADLINE_MS: u128 = 10_000;
/// Default response bound.
pub const DEFAULT_MAX_RESPONSE: usize = 1_048_576;

/// A raw HTTP reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    /// Status.
    pub status: u16,
    /// Body.
    pub body: Vec<u8>,
}

/// The transport seam (real `WinHTTP` client, or a fake in tests).
pub trait Transport: Send + Sync {
    /// POSTs a JSON body.
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    fn post_json(
        &self,
        url: &HttpsUrl,
        body: &[u8],
        max_response: usize,
    ) -> Result<HttpReply, HttpError>;

    /// GETs `url` with `Accept: application/json` and returns status, `Content-Type` and body
    /// (Bitcoin `esplora`/`bb-rest` indexers, spec/08 §4.1). Transports that only speak JSON-RPC
    /// keep the default, which sends nothing and fails with [`HttpError::InvalidUrl`].
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    fn http_get(&self, _url: &HttpsUrl, _max_response: usize) -> Result<Response, HttpError> {
        Err(HttpError::InvalidUrl)
    }

    /// POSTs `body` with exactly `Content-Type: text/plain` (only the user-confirmed Esplora
    /// `POST /tx`, spec/08 §11.3). The default sends nothing and fails with
    /// [`HttpError::InvalidUrl`].
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    fn http_post_text(
        &self,
        _url: &HttpsUrl,
        _body: &[u8],
        _max_response: usize,
    ) -> Result<Response, HttpError> {
        Err(HttpError::InvalidUrl)
    }
}

impl Transport for Client {
    fn post_json(
        &self,
        url: &HttpsUrl,
        body: &[u8],
        max_response: usize,
    ) -> Result<HttpReply, HttpError> {
        Self::post_json(self, url, None, body, max_response).map(|response| HttpReply {
            status: response.status,
            body: response.body,
        })
    }

    fn http_get(&self, url: &HttpsUrl, max_response: usize) -> Result<Response, HttpError> {
        self.get(url, max_response)
    }

    fn http_post_text(
        &self,
        url: &HttpsUrl,
        body: &[u8],
        max_response: usize,
    ) -> Result<Response, HttpError> {
        self.post(
            &EndpointUrl::Https(url.clone()),
            &[("Content-Type", "text/plain")],
            body,
            max_response,
        )
    }
}

/// Why a call failed (classification input, spec/04 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcFailure {
    /// Transport error.
    Http(HttpError),
    /// Non-2xx HTTP status.
    Status(u16),
    /// JSON-RPC `error.code`.
    Rpc(i64),
    /// Malformed response or id mismatch.
    Malformed,
    /// Returned after the per-call deadline.
    Late,
}

impl core::fmt::Display for RpcFailure {
    /// The classified code only (no URL, host or remote text).
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(classify(*self).code())
    }
}

impl std::error::Error for RpcFailure {}

/// spec/04 §1.9 classification.
#[must_use]
pub const fn classify(failure: RpcFailure) -> ErrorCode {
    match failure {
        RpcFailure::Http(HttpError::Timeout) | RpcFailure::Late => ErrorCode::Rpc002,
        RpcFailure::Http(HttpError::Tls) => ErrorCode::Rpc008,
        RpcFailure::Http(HttpError::TooLarge) | RpcFailure::Malformed => ErrorCode::Rpc005,
        RpcFailure::Http(HttpError::InvalidUrl) => ErrorCode::Key003,
        RpcFailure::Http(HttpError::Os(_) | HttpError::InvalidHeader) => ErrorCode::Rpc001,
        RpcFailure::Status(401 | 403) => ErrorCode::Rpc003,
        RpcFailure::Status(429) | RpcFailure::Rpc(-32_005 | 429) => ErrorCode::Rpc004,
        RpcFailure::Status(_) | RpcFailure::Rpc(_) => ErrorCode::Rpc007,
    }
}

/// A JSON-RPC client over a transport.
pub struct RpcClient<'t> {
    transport: &'t dyn Transport,
    next_id: AtomicU64,
}

impl core::fmt::Debug for RpcClient<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RpcClient")
    }
}

impl<'t> RpcClient<'t> {
    /// A client starting at id 1.
    #[must_use]
    pub fn new(transport: &'t dyn Transport) -> Self {
        Self {
            transport,
            next_id: AtomicU64::new(1),
        }
    }

    /// The next request id (also for pre-built request bodies such as `eth_simulateV1`).
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// POSTs a pre-built body (`eth_simulateV1`) and returns the raw reply; a reply after the
    /// per-call deadline is a timeout.
    ///
    /// # Errors
    ///
    /// [`HttpError`] (`Timeout` also for late replies).
    pub fn post_raw(
        &self,
        url: &HttpsUrl,
        body: &[u8],
        max_response: usize,
    ) -> Result<HttpReply, HttpError> {
        let started = Instant::now();
        let reply = self.transport.post_json(url, body, max_response)?;
        if started.elapsed().as_millis() > CALL_DEADLINE_MS {
            return Err(HttpError::Timeout);
        }
        Ok(reply)
    }

    /// Calls `method` with `params`; returns `result`.
    ///
    /// # Errors
    ///
    /// [`RpcFailure`].
    pub fn call(
        &self,
        url: &HttpsUrl,
        method: &'static str,
        params: Value,
    ) -> Result<Value, RpcFailure> {
        self.call_limited(url, method, params, DEFAULT_MAX_RESPONSE)
    }

    /// [`Self::call`] with an explicit response bound.
    ///
    /// # Errors
    ///
    /// [`RpcFailure`].
    pub fn call_limited(
        &self,
        url: &HttpsUrl,
        method: &'static str,
        params: Value,
        max_response: usize,
    ) -> Result<Value, RpcFailure> {
        self.call_detailed(url, method, params, max_response)
            .map_err(|error| error.failure)
    }

    /// Calls `method`; on a JSON-RPC error also returns `error.data` when it is hex (revert
    /// bytes of `eth_estimateGas`). The RPC `error.message` is never read.
    ///
    /// # Errors
    ///
    /// [`CallError`].
    pub fn call_detailed(
        &self,
        url: &HttpsUrl,
        method: &'static str,
        params: Value,
        max_response: usize,
    ) -> Result<Value, CallError> {
        let id = self.next_id();
        let request = json_object(vec![
            ("jsonrpc", json_str("2.0")),
            ("id", json_u64(id)),
            ("method", json_str(method)),
            ("params", params),
        ]);
        let started = Instant::now();
        let reply = self
            .transport
            .post_json(url, &yw_json::to_vec(&request), max_response)
            .map_err(|error| CallError::from(RpcFailure::Http(error)))?;
        if started.elapsed().as_millis() > CALL_DEADLINE_MS {
            return Err(RpcFailure::Late.into());
        }
        if !(200..300).contains(&reply.status) {
            return Err(RpcFailure::Status(reply.status).into());
        }
        let limits = Limits {
            max_bytes: max_response,
            ..Limits::RESPONSE
        };
        let value = yw_json::parse(&reply.body, &limits).map_err(|error| CallError {
            over_limit: matches!(
                error,
                yw_json::ParseError::TooLarge
                    | yw_json::ParseError::TooManyNodes
                    | yw_json::ParseError::TooManyItems
            ),
            ..CallError::from(RpcFailure::Malformed)
        })?;
        let object = value
            .as_object()
            .ok_or_else(|| CallError::from(RpcFailure::Malformed))?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || object
                .get("id")
                .and_then(Value::as_number)
                .and_then(Number::as_u64)
                != Some(id)
        {
            return Err(RpcFailure::Malformed.into());
        }
        if let Some(error) = object.get("error") {
            let error = error
                .as_object()
                .ok_or_else(|| CallError::from(RpcFailure::Malformed))?;
            let code = error
                .get("code")
                .and_then(Value::as_number)
                .and_then(Number::as_i64)
                .ok_or_else(|| CallError::from(RpcFailure::Malformed))?;
            let data = error
                .get("data")
                .and_then(Value::as_str)
                .and_then(|text| text.strip_prefix("0x"))
                .and_then(|digits| yw_core::hex::decode(digits).ok());
            return Err(CallError {
                failure: RpcFailure::Rpc(code),
                data,
                data_value: error.get("data").cloned(),
                over_limit: false,
            });
        }
        object
            .get("result")
            .cloned()
            .ok_or_else(|| CallError::from(RpcFailure::Malformed))
    }
}

/// A failed call with the optional JSON-RPC `error.data` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallError {
    /// Classification input.
    pub failure: RpcFailure,
    /// `error.data` when it was a hex string.
    pub data: Option<Vec<u8>>,
    /// The raw `error.data` JSON (Solana `sendTransaction` preflight errors carry a structured
    /// `err`; only its structure is classified, never its strings, spec/07 §15.3).
    pub data_value: Option<Value>,
    /// The answer went past its size bounds: the transport's byte cap or the JSON byte / node /
    /// item limits (the failure stays `Http(TooLarge)` / `Malformed` for classification).
    pub over_limit: bool,
}

impl From<RpcFailure> for CallError {
    fn from(failure: RpcFailure) -> Self {
        Self {
            failure,
            data: None,
            data_value: None,
            over_limit: matches!(failure, RpcFailure::Http(HttpError::TooLarge)),
        }
    }
}

/// Solana genesis hashes (spec/07 §15.1).
#[must_use]
pub const fn solana_genesis(cluster: SolCluster) -> &'static str {
    match cluster {
        SolCluster::Mainnet => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        SolCluster::Devnet => "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
    }
}

/// Bitcoin Core `getblockchaininfo.chain` (spec/08 §2).
#[must_use]
pub const fn bitcoin_chain(net: BtcNet) -> &'static str {
    match net {
        BtcNet::Mainnet => "main",
        BtcNet::Testnet4 => "testnet4",
    }
}

/// The fixed texts of the endpoint test (spec/14).
pub mod text {
    yw_core::texts! {
        /// T-RPC-OK: {0} network name, {1} the checked item.
        RPC_OK(2) = "RPC 주소가 작동합니다. ({0}, {1})" / "The RPC address works. ({0}, {1})";
        /// The checked item of a genesis-pinned network.
        GENESIS_MATCH = "genesis 일치" / "genesis matches";
    }
}

/// The [`TestOutcome::Ok`] item of a matching genesis hash (shown as [`text::GENESIS_MATCH`]).
pub const GENESIS_ITEM: &str = "genesis";

/// Result of an endpoint test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TestOutcome {
    /// Matches; the checked item (`chainId 1`, [`GENESIS_ITEM`] — shown as `genesis 일치` —,
    /// `chain main`).
    Ok(String),
    /// Answered for another network: the item name and, for EVM, the RPC chain id.
    Mismatch {
        /// `chainId`, `genesis` or `chain`.
        item: &'static str,
        /// Parsed RPC chain id (EVM).
        rpc_chain_id: Option<u64>,
    },
    /// Failed.
    Failed(ErrorCode),
}

impl TestOutcome {
    /// Code for logs (`ok` or the error code).
    #[must_use]
    pub const fn log_word(&self) -> &'static str {
        match self {
            Self::Ok(_) => "ok",
            Self::Mismatch { .. } => "E-RPC-010",
            Self::Failed(code) => code.code(),
        }
    }

    /// The fixed message (T-RPC-OK or the error text) in `lang`, never including remote strings.
    #[must_use]
    pub fn message(&self, lang: yw_core::lang::Lang, network_name: &str) -> String {
        match self {
            Self::Ok(item) => {
                let item = if item == GENESIS_ITEM {
                    text::GENESIS_MATCH.get(lang)
                } else {
                    item.as_str()
                };
                text::RPC_OK.fill(lang, [network_name, item])
            }
            Self::Mismatch {
                item,
                rpc_chain_id: Some(id),
            } => {
                let base = ErrorCode::Rpc010.render_in(lang, item);
                let code = format!(" ({})", ErrorCode::Rpc010.code());
                let head = base.strip_suffix(&code).unwrap_or(&base);
                format!("{head} (RPC chainId {id}){code}")
            }
            Self::Mismatch { item, .. } => ErrorCode::Rpc010.render_in(lang, item),
            Self::Failed(code) => code.text_in(lang),
        }
    }
}

/// `eth_chainId` canonical form: `0x` + lowercase hex without leading zeros.
#[must_use]
pub fn canonical_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

/// One endpoint test call (spec/04 §2.11.1 table), no retry.
#[must_use]
pub fn test_endpoint(client: &RpcClient<'_>, network: NetworkId, url: &HttpsUrl) -> TestOutcome {
    let empty = Value::Array(Vec::new());
    match network {
        NetworkId::Eip155(expected) => match client.call(url, "eth_chainId", empty) {
            Ok(Value::String(text)) => {
                let Some(value) = U256::parse_quantity_lenient(&text)
                    .ok()
                    .and_then(U256::to_u64)
                else {
                    return TestOutcome::Failed(ErrorCode::Rpc005);
                };
                if text.to_ascii_lowercase() == canonical_quantity(expected) {
                    TestOutcome::Ok(format!("chainId {expected}"))
                } else {
                    TestOutcome::Mismatch {
                        item: "chainId",
                        rpc_chain_id: Some(value),
                    }
                }
            }
            Ok(_) => TestOutcome::Failed(ErrorCode::Rpc005),
            Err(failure) => TestOutcome::Failed(classify(failure)),
        },
        NetworkId::Solana(cluster) => match client.call(url, "getGenesisHash", empty) {
            Ok(Value::String(hash)) if hash == solana_genesis(cluster) => {
                TestOutcome::Ok(GENESIS_ITEM.to_owned())
            }
            Ok(Value::String(_)) => TestOutcome::Mismatch {
                item: "genesis",
                rpc_chain_id: None,
            },
            Ok(_) => TestOutcome::Failed(ErrorCode::Rpc005),
            Err(failure) => TestOutcome::Failed(classify(failure)),
        },
        NetworkId::Bitcoin(net) => match client.call(url, "getblockchaininfo", empty) {
            Ok(Value::Object(info)) => match info.get("chain").and_then(Value::as_str) {
                Some(chain) if chain == bitcoin_chain(net) => {
                    TestOutcome::Ok(format!("chain {chain}"))
                }
                Some(_) => TestOutcome::Mismatch {
                    item: "chain",
                    rpc_chain_id: None,
                },
                None => TestOutcome::Failed(ErrorCode::Rpc005),
            },
            Ok(_) => TestOutcome::Failed(ErrorCode::Rpc005),
            Err(failure) => TestOutcome::Failed(classify(failure)),
        },
        // spec/12 §2: the genesis pin (`getblockhash 0`).
        NetworkId::Zcash(net) => {
            match client.call(
                url,
                "getblockhash",
                Value::Array(vec![Value::Number(yw_json::Number::from_u64(0))]),
            ) {
                Ok(Value::String(hash)) if hash == net.genesis_hex() => {
                    TestOutcome::Ok(GENESIS_ITEM.to_owned())
                }
                Ok(Value::String(_)) => TestOutcome::Mismatch {
                    item: "genesis",
                    rpc_chain_id: None,
                },
                Ok(_) => TestOutcome::Failed(ErrorCode::Rpc005),
                Err(failure) => TestOutcome::Failed(classify(failure)),
            }
        }
    }
}

/// The URL a `테스트` uses (spec/04 §2.11.1): the typed replacement if any (format-checked,
/// E-KEY-003), otherwise the stored URL, otherwise E-KEY-005 without any call.
///
/// # Errors
///
/// [`ErrorCode::Key003`] or [`ErrorCode::Key005`].
pub fn endpoint_for_test(typed: &str, stored: Option<HttpsUrl>) -> Result<HttpsUrl, ErrorCode> {
    let typed = typed.trim();
    if typed.is_empty() {
        stored.ok_or(ErrorCode::Key005)
    } else {
        HttpsUrl::parse(typed).map_err(|_| ErrorCode::Key003)
    }
}
