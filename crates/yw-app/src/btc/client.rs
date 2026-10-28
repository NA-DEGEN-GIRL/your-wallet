//! `btc::client` (spec/08 §4.1–§4.4): every Bitcoin request of a job goes through one
//! [`BtcClient`]: paced on the session's request line ([`super::Pace`], ≥ 200 ms between
//! starts), deadline-checked against the injected clock (10 s per call), repeated after HTTP 429
//! (and JSON-RPC 429 / -32005) after 2 s, 4 s and 8 s; a fourth 429 aborts the job and starts the
//! 300 s cooldown. 5xx and timeouts are not retried. JSON-RPC uses the Bitcoin envelope rule
//! ([`parse_envelope`]); `error.message` is never read.

use std::sync::atomic::{AtomicU64, Ordering};

use yw_core::btc::{BTC_429_BACKOFF_MS, Txid};
use yw_json::{Limits, Number, Value};
use yw_win::http::{HttpError, HttpsUrl, Response};

use super::{BtcEndpoint, BtcEnv, indexer_word, network_id};
use crate::logging::Field;
use crate::rpc::RpcFailure;
use crate::settings::{BtcIndexer, LogLevel};
use crate::text::{json_object, json_str, json_u64};

/// Per-call deadline (spec/08 §4.1: 10 s, Esplora included).
pub const BTC_CALL_DEADLINE_MS: u64 = 10_000;

/// Whether a JSON-RPC failure is a rate limit (HTTP 429, JSON-RPC 429 / -32005).
#[must_use]
pub const fn is_rate_limited(failure: RpcFailure) -> bool {
    matches!(
        failure,
        RpcFailure::Status(429) | RpcFailure::Rpc(429 | -32_005)
    )
}

/// What a request is, for its log line only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    /// `idx=` for indexer requests.
    pub idx: Option<BtcIndexer>,
    /// Path kind (`utxo`, `tx-status`, …) or JSON-RPC method.
    pub what: &'static str,
    /// `what` is a JSON-RPC method (`method=`) rather than a path kind (`path=`).
    pub is_method: bool,
    /// The txid of the request, if any.
    pub txid: Option<Txid>,
}

impl Tag {
    /// A Core method.
    #[must_use]
    pub const fn core(method: &'static str, txid: Option<Txid>) -> Self {
        Self {
            idx: None,
            what: method,
            is_method: true,
            txid,
        }
    }
}

/// Validates a Bitcoin JSON-RPC reply (spec/08 §4.2): `id` echoed, `jsonrpc` absent or `"2.0"`,
/// exactly one of `result` / `error` non-null (`"error":null` of Core 1.0 accepted), `error` an
/// object with an integer `code`. HTTP 2xx carries the envelope; 401/403/429 are statuses; any
/// other status is read as an error envelope when it is one (Core answers RPC errors with HTTP
/// 500/404 to 1.0 clients), otherwise it stays a status.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn parse_envelope(status: u16, body: &[u8], id: u64, cap: usize) -> Result<Value, RpcFailure> {
    if matches!(status, 401 | 403 | 429) {
        return Err(RpcFailure::Status(status));
    }
    let parsed = envelope_member(body, id, cap);
    if (200..300).contains(&status) {
        return parsed;
    }
    match parsed {
        Err(RpcFailure::Rpc(code)) => Err(RpcFailure::Rpc(code)),
        _ => Err(RpcFailure::Status(status)),
    }
}

fn envelope_member(body: &[u8], id: u64, cap: usize) -> Result<Value, RpcFailure> {
    let limits = Limits {
        max_bytes: cap,
        ..Limits::RESPONSE
    };
    let value = yw_json::parse(body, &limits).map_err(|_| RpcFailure::Malformed)?;
    let object = value.as_object().ok_or(RpcFailure::Malformed)?;
    if let Some(version) = object.get("jsonrpc")
        && version.as_str() != Some("2.0")
    {
        return Err(RpcFailure::Malformed);
    }
    if object
        .get("id")
        .and_then(Value::as_number)
        .and_then(Number::as_u64)
        != Some(id)
    {
        return Err(RpcFailure::Malformed);
    }
    let result = object.get("result").filter(|value| !value.is_null());
    let error = object.get("error").filter(|value| !value.is_null());
    match (result, error) {
        (Some(result), None) => Ok(result.clone()),
        (None, Some(error)) => {
            let code = error
                .as_object()
                .and_then(|error| error.get("code"))
                .and_then(Value::as_number)
                .and_then(Number::as_i64)
                .ok_or(RpcFailure::Malformed)?;
            Err(RpcFailure::Rpc(code))
        }
        _ => Err(RpcFailure::Malformed),
    }
}

/// The request line of one job: endpoint, environment and the JSON-RPC id counter.
pub struct BtcClient<'a> {
    env: BtcEnv<'a>,
    endpoint: &'a BtcEndpoint,
    next_id: AtomicU64,
}

impl core::fmt::Debug for BtcClient<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "BtcClient({:?})", self.endpoint)
    }
}

impl<'a> BtcClient<'a> {
    /// A client whose JSON-RPC ids start at 1.
    #[must_use]
    pub const fn new(env: BtcEnv<'a>, endpoint: &'a BtcEndpoint) -> Self {
        Self {
            env,
            endpoint,
            next_id: AtomicU64::new(1),
        }
    }

    /// The endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &'a BtcEndpoint {
        self.endpoint
    }

    /// The environment.
    #[must_use]
    pub const fn env(&self) -> BtcEnv<'a> {
        self.env
    }

    /// Monotonic now.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.env.clock.now_ms()
    }

    /// One log line with `net=`, `idx=`, `path=`/`method=`, `tx=` and `extra`.
    pub fn log(
        &self,
        level: LogLevel,
        event: &'static str,
        tag: Tag,
        extra: &[(&'static str, Field<'_>)],
    ) {
        let mut fields: Vec<(&'static str, Field<'_>)> = Vec::with_capacity(extra.len() + 4);
        fields.push(("net", Field::Net(network_id(self.endpoint.net))));
        if let Some(idx) = tag.idx {
            fields.push(("idx", Field::Word(indexer_word(idx))));
        }
        fields.push((
            if tag.is_method { "method" } else { "path" },
            Field::Word(tag.what),
        ));
        if let Some(txid) = tag.txid {
            fields.push(("tx", Field::BtcTxid(txid)));
        }
        fields.extend_from_slice(extra);
        self.env.log.log(level, event, &fields);
    }

    /// Runs `attempt` on the request line, repeating it after a rate limit with the §4.4
    /// back-off. Returns the last outcome and whether the job is aborted (cooldown started).
    fn paced<T>(
        &self,
        tag: Tag,
        mut attempt: impl FnMut() -> T,
        limited: impl Fn(&T) -> bool,
    ) -> (T, bool) {
        let mut retry: u64 = 0;
        loop {
            self.env.pace.wait_turn(self.env.clock);
            let outcome = attempt();
            if !limited(&outcome) {
                return (outcome, false);
            }
            let next_wait = usize::try_from(retry)
                .ok()
                .and_then(|index| BTC_429_BACKOFF_MS.get(index));
            if let Some(wait) = next_wait {
                retry = retry.saturating_add(1);
                self.log(
                    LogLevel::Info,
                    "rate_limited_retry",
                    tag,
                    &[("retry", Field::Num(retry)), ("wait_ms", Field::Num(*wait))],
                );
                self.env.clock.sleep_ms(*wait);
            } else {
                self.env.pace.start_cooldown(self.env.clock.now_ms());
                self.log(
                    LogLevel::Warn,
                    "rate_limited_abort",
                    tag,
                    &[("cooldown_s", Field::Num(super::pace::COOLDOWN_MS / 1_000))],
                );
                return (outcome, true);
            }
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// A Core call (spec/08 §4.2) with the method's response cap.
    ///
    /// # Errors
    ///
    /// [`RpcFailure`]; a rate limit after three retries is returned as is (E-RPC-004).
    pub fn core_call(
        &self,
        method: &'static str,
        params: &Value,
        cap: usize,
        txid: Option<Txid>,
    ) -> Result<Value, RpcFailure> {
        self.json_rpc(
            &self.endpoint.core_url,
            method,
            params,
            cap,
            Tag::core(method, txid),
        )
    }

    /// A JSON-RPC call (Core or `bb-rpc`) on the request line.
    ///
    /// # Errors
    ///
    /// [`RpcFailure`].
    pub fn json_rpc(
        &self,
        url: &HttpsUrl,
        method: &'static str,
        params: &Value,
        cap: usize,
        tag: Tag,
    ) -> Result<Value, RpcFailure> {
        let (result, _) = self.paced(
            tag,
            || self.json_rpc_once(url, method, params, cap, tag),
            |outcome| matches!(outcome, Err(failure) if is_rate_limited(*failure)),
        );
        result
    }

    fn json_rpc_once(
        &self,
        url: &HttpsUrl,
        method: &'static str,
        params: &Value,
        cap: usize,
        tag: Tag,
    ) -> Result<Value, RpcFailure> {
        let id = self.next_id();
        let request = json_object(vec![
            ("jsonrpc", json_str("2.0")),
            ("id", json_u64(id)),
            ("method", json_str(method)),
            ("params", params.clone()),
        ]);
        let started = self.now_ms();
        let reply = self
            .env
            .transport
            .post_json(url, &yw_json::to_vec(&request), cap);
        let elapsed = self.now_ms().saturating_sub(started);
        let outcome = match reply {
            Err(error) => Err(RpcFailure::Http(error)),
            Ok(_) if elapsed > BTC_CALL_DEADLINE_MS => Err(RpcFailure::Late),
            Ok(reply) => parse_envelope(reply.status, &reply.body, id, cap),
        };
        let detail = match outcome {
            Ok(_) => ("result", Field::Word("ok")),
            Err(RpcFailure::Status(status)) => ("http", Field::Num(u64::from(status))),
            Err(RpcFailure::Rpc(code)) => ("rpc_code", Field::Int(code)),
            Err(RpcFailure::Http(error)) => ("transport", Field::Word(http_word(error))),
            Err(RpcFailure::Malformed) => ("result", Field::Word("malformed")),
            Err(RpcFailure::Late) => ("result", Field::Word("late")),
        };
        self.log(
            LogLevel::Debug,
            "request",
            tag,
            &[("ms", Field::Num(elapsed)), detail],
        );
        outcome
    }

    /// A paced GET (`esplora`, `bb-rest`). The final 429 after three retries is returned as the
    /// response (status 429).
    ///
    /// # Errors
    ///
    /// [`HttpError`] (`Timeout` also after the 10 s deadline).
    pub fn get(&self, url: &HttpsUrl, cap: usize, tag: Tag) -> Result<Response, HttpError> {
        let (result, _) = self.paced(
            tag,
            || self.http_once(tag, || self.env.transport.http_get(url, cap)),
            |outcome| matches!(outcome, Ok(response) if response.status == 429),
        );
        result
    }

    /// A paced `text/plain` POST (only the manual Esplora `POST /tx`).
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub fn post_text(
        &self,
        url: &HttpsUrl,
        body: &[u8],
        cap: usize,
        tag: Tag,
    ) -> Result<Response, HttpError> {
        let (result, _) = self.paced(
            tag,
            || self.http_once(tag, || self.env.transport.http_post_text(url, body, cap)),
            |outcome| matches!(outcome, Ok(response) if response.status == 429),
        );
        result
    }

    fn http_once(
        &self,
        tag: Tag,
        send: impl FnOnce() -> Result<Response, HttpError>,
    ) -> Result<Response, HttpError> {
        let started = self.now_ms();
        let reply = send();
        let elapsed = self.now_ms().saturating_sub(started);
        let outcome = match reply {
            Ok(_) if elapsed > BTC_CALL_DEADLINE_MS => Err(HttpError::Timeout),
            other => other,
        };
        let mut extra = vec![("ms", Field::Num(elapsed))];
        match &outcome {
            Ok(response) => extra.push(("http", Field::Num(u64::from(response.status)))),
            Err(error) => extra.push(("transport", Field::Word(http_word(*error)))),
        }
        self.log(LogLevel::Debug, "request", tag, &extra);
        outcome
    }
}

/// Transport error word for logs.
#[must_use]
pub const fn http_word(error: HttpError) -> &'static str {
    match error {
        HttpError::InvalidUrl => "invalid_url",
        HttpError::InvalidHeader => "invalid_header",
        HttpError::Timeout => "timeout",
        HttpError::Tls => "tls",
        HttpError::TooLarge => "too_large",
        HttpError::Os(_) => "os",
    }
}
