//! Read forwarding (spec/05 §3.5, spec/03 §12): the `yw-read-0..3` workers send the normalized
//! params to the origin chain's own endpoint (`rpc:eip155:<chainId>`, never another chain's or a
//! template's), after the spec/03 §1.4 chain check, and return the parsed `result` or a sanitized
//! upstream error. One-sided `eth_getLogs` ranges are resolved here against a 12 s block-number
//! cache (spec/05 §3.4), so the reader thread never waits for RPC.

use std::sync::{Arc, Mutex};

use yw_core::policy::{Method, ProviderError};
use yw_json::{Limits, Number, Value};
use yw_win::http::{HttpError, HttpsUrl};

use super::dispatch::{BrowserCore, ReadTask};
use super::params::check_logs_range;
use super::{DappEvent, LOGS_BLOCK_CACHE_MS, MAX_RESULT_BYTES};
use crate::flow::evm::{
    CHAIN_CHECK_RETRY_MS, ChainCache, ChainCheck, SharedTransport, check_chain,
};
use crate::rpc::{CALL_DEADLINE_MS, RpcClient};
use crate::text::{json_object, json_str, json_u64};

/// Largest HTTP body accepted for a read (the result bound plus the JSON-RPC envelope).
pub const MAX_READ_RESPONSE: usize = 1_048_576;

/// What the read workers share: the transport and their own chain-check cache (spec/03 §1.4,
/// separate from the `yw-rpc` worker's; both report results to the UI).
pub struct ReadContext {
    /// HTTPS transport (`None` when the client could not be created: every read is 4901).
    pub transport: Option<SharedTransport>,
    /// Chain checks.
    pub checks: Mutex<ChainCache>,
    /// Delay between chain-check retries.
    pub retry_delay_ms: u64,
}

impl core::fmt::Debug for ReadContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReadContext")
    }
}

impl ReadContext {
    /// Production context.
    #[must_use]
    pub fn new(transport: Option<SharedTransport>) -> Self {
        Self {
            transport,
            checks: Mutex::new(ChainCache::default()),
            retry_delay_ms: CHAIN_CHECK_RETRY_MS,
        }
    }

    /// Forgets a chain's check (URL or definition changed).
    pub fn reset_chain(&self, chain_id: u64) {
        if let Ok(mut checks) = self.checks.lock() {
            checks.reset(chain_id);
        }
    }
}

/// The worker loop: runs until [`BrowserCore::stop`].
pub fn run_worker(core: &Arc<BrowserCore>, context: &ReadContext) {
    while let Some(task) = core.next_read() {
        let body = execute(core, context, &task);
        core.finish_read(&task, body);
    }
}

type Answer = Result<Value, ProviderError>;

/// Executes one read (spec/05 §3.5 error mapping).
///
/// # Errors
///
/// The [`ProviderError`] answered to the dApp.
pub fn execute(core: &BrowserCore, context: &ReadContext, task: &ReadTask) -> Answer {
    if !core.is_pending(&task.reply) {
        return Err(ProviderError::Internal);
    }
    if core.clock().now_ms() >= task.deadline_ms {
        return Err(ProviderError::TimedOut);
    }
    let wallet = core.wallet();
    let Some(entry) = wallet.chain(task.chain_id) else {
        return Err(ProviderError::ChainUnavailable);
    };
    let (Some(url), Some(transport)) = (entry.url.clone(), context.transport.clone()) else {
        return Err(ProviderError::ChainUnavailable);
    };
    if wallet.blocked.contains(&task.chain_id) {
        return Err(ProviderError::ChainUnavailable);
    }
    let client = RpcClient::new(&*transport);
    let cached = context
        .checks
        .lock()
        .ok()
        .and_then(|checks| checks.get(task.chain_id));
    let check = if let Some(check) = cached {
        check
    } else {
        let check = check_chain(
            &client,
            &url,
            &entry.info,
            core.clock(),
            context.retry_delay_ms,
        );
        if !matches!(check, ChainCheck::Unverified(_))
            && let Ok(mut checks) = context.checks.lock()
        {
            checks.store(task.chain_id, check);
        }
        let _ = core.sink().push(DappEvent::ChainChecked {
            chain_id: task.chain_id,
            check,
        });
        check
    };
    if !matches!(check, ChainCheck::Verified { .. }) {
        return Err(ProviderError::ChainUnavailable);
    }
    if let Some(range) = &task.params.logs {
        let latest =
            if let Some(latest) = core.cached_block_number(task.chain_id, LOGS_BLOCK_CACHE_MS) {
                latest
            } else {
                let latest = block_number(&client, &url)?;
                core.store_block_number(task.chain_id, latest);
                latest
            };
        check_logs_range(range, latest)?;
    }
    let result = forward(&client, &url, task.method, task.params.params.clone())?;
    if task.method == Method::BlockNumber
        && let Some(latest) = result.as_str().and_then(parse_u64_quantity)
    {
        core.store_block_number(task.chain_id, latest);
    }
    Ok(result)
}

fn parse_u64_quantity(text: &str) -> Option<u64> {
    yw_core::evm::amount::U256::parse_quantity_lenient(text)
        .ok()
        .and_then(yw_core::evm::amount::U256::to_u64)
}

fn block_number(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<u64, ProviderError> {
    match forward(client, url, Method::BlockNumber, Value::Array(Vec::new())) {
        Ok(Value::String(text)) => parse_u64_quantity(&text).ok_or(ProviderError::ChainUnavailable),
        _ => Err(ProviderError::ChainUnavailable),
    }
}

/// spec/05 §3.5: an answer over the `RESPONSE_LIMITS` (bytes, depth, nodes, items) is -32603
/// `Response too large.`; malformed JSON is 4901.
const fn parse_error(error: yw_json::ParseError) -> ProviderError {
    match error {
        yw_json::ParseError::TooLarge
        | yw_json::ParseError::TooDeep
        | yw_json::ParseError::TooManyNodes
        | yw_json::ParseError::TooManyItems => ProviderError::ResponseTooLarge,
        _ => ProviderError::ChainUnavailable,
    }
}

/// One JSON-RPC call with the spec/05 §3.5 mapping: transport, TLS, timeout, non-2xx (except
/// 429) and malformed answers → 4901; 429 → -32005; a body or JSON structure over the bounds →
/// -32603 `Response too large.`; a JSON-RPC `error` → sanitized `Upstream`; a result above
/// 1,044,480 bytes → `ResponseTooLarge`.
///
/// # Errors
///
/// [`ProviderError`].
pub fn forward(client: &RpcClient<'_>, url: &HttpsUrl, method: Method, params: Value) -> Answer {
    let id = client.next_id();
    let body = yw_json::to_vec(&json_object(vec![
        ("jsonrpc", json_str("2.0")),
        ("id", json_u64(id)),
        ("method", json_str(method.as_str())),
        ("params", params),
    ]));
    let started = std::time::Instant::now();
    let reply = match client.post_raw(url, &body, MAX_READ_RESPONSE) {
        Ok(reply) => reply,
        Err(HttpError::TooLarge) => return Err(ProviderError::ResponseTooLarge),
        Err(_) => return Err(ProviderError::ChainUnavailable),
    };
    if started.elapsed().as_millis() > CALL_DEADLINE_MS {
        return Err(ProviderError::ChainUnavailable);
    }
    if reply.status == 429 {
        return Err(ProviderError::RateLimited);
    }
    if !(200..300).contains(&reply.status) {
        return Err(ProviderError::ChainUnavailable);
    }
    let limits = Limits {
        max_bytes: MAX_READ_RESPONSE,
        ..Limits::RESPONSE
    };
    let value = yw_json::parse(&reply.body, &limits).map_err(parse_error)?;
    let object = value.as_object().ok_or(ProviderError::ChainUnavailable)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object
            .get("id")
            .and_then(Value::as_number)
            .and_then(Number::as_u64)
            != Some(id)
    {
        return Err(ProviderError::ChainUnavailable);
    }
    if let Some(error) = object.get("error") {
        let error = error.as_object().ok_or(ProviderError::ChainUnavailable)?;
        let code = error
            .get("code")
            .and_then(Value::as_number)
            .and_then(Number::as_i64);
        let message = error.get("message").and_then(Value::as_str);
        let data = error.get("data").and_then(Value::as_str);
        return Err(ProviderError::upstream(code, message, data));
    }
    let result = object
        .get("result")
        .cloned()
        .ok_or(ProviderError::ChainUnavailable)?;
    if yw_json::to_vec(&result).len() > MAX_RESULT_BYTES {
        return Err(ProviderError::ResponseTooLarge);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use yw_core::policy::{Method, ProviderError};
    use yw_json::Value;
    use yw_win::http::{HttpError, HttpsUrl};

    use super::forward;
    use crate::rpc::{HttpReply, RpcClient, Transport};

    struct Raw(Vec<u8>);

    impl Transport for Raw {
        fn post_json(
            &self,
            _url: &HttpsUrl,
            _body: &[u8],
            _max_response: usize,
        ) -> Result<HttpReply, HttpError> {
            Ok(HttpReply {
                status: 200,
                body: self.0.clone(),
            })
        }
    }

    fn read(body: &str) -> Result<Value, ProviderError> {
        let url = HttpsUrl::parse("https://rpc.example.test/").unwrap();
        let transport = Raw(body.as_bytes().to_vec());
        forward(
            &RpcClient::new(&transport),
            &url,
            Method::BlockNumber,
            Value::Array(Vec::new()),
        )
    }

    /// spec/05 §3.5: an answer over `RESPONSE_LIMITS` is -32603 `Response too large.`, only
    /// malformed JSON is 4901.
    #[test]
    fn json_over_the_response_limits_is_too_large() {
        let deep = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{}1{}}}"#,
            "[".repeat(40),
            "]".repeat(40)
        );
        assert_eq!(read(&deep), Err(ProviderError::ResponseTooLarge));
        assert_eq!(
            read(r#"{"jsonrpc":"2.0","id":"#),
            Err(ProviderError::ChainUnavailable)
        );
    }
}
