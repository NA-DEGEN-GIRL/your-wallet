//! The chat-completions request (spec/06 §4.1–§4.5) and its transport.

use yw_json::{Limits, Number, Value};
use yw_win::http::{Client, EndpointUrl, HttpError, Timeouts};

use super::config::{LlmConfig, ResponseFormatMode};
use super::input::ExplainInput;
use super::response::{Explanation, parse_response};
use super::{ExplainError, MAX_REQUEST_BODY, MAX_RESPONSE_BODY, RequestStats};
use crate::text::{json_object, json_str};

/// `WinHTTP` per-phase timeouts of the LLM session (spec/01 §7.4: four × 10 s).
pub const LLM_TIMEOUTS: Timeouts = Timeouts {
    resolve_ms: 10_000,
    connect_ms: 10_000,
    send_ms: 10_000,
    receive_ms: 10_000,
};

/// `SYSTEM_PROMPT_V1` (§4.2) in both languages: the lines joined by LF, no trailing newline. A
/// change needs a new version. The request uses the input's language.
pub const SYSTEM_PROMPT_V1: yw_core::lang::Text = super::text::SYSTEM_PROMPT_V1;

/// `response_format` for `json_schema` (§4.5), verbatim.
pub const RESPONSE_FORMAT_SCHEMA: &str = r#"{"type":"json_schema","json_schema":{"name":"yw_explain_v1","strict":true,"schema":{"type":"object","additionalProperties":false,"required":["summary","actions","unknowns"],"properties":{"summary":{"type":"string"},"actions":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["type","asset","amount","from","to"],"properties":{"type":{"type":"string","enum":["send","receive","approve","revoke_approval","approve_all","permit","sign_in","sign_message","contract_call","other"]},"asset":{"type":"string"},"amount":{"type":"string"},"from":{"type":"string"},"to":{"type":"string"}}}},"unknowns":{"type":"array","items":{"type":"string"}}}}}}"#;

fn response_format(mode: ResponseFormatMode) -> Value {
    match mode {
        ResponseFormatMode::JsonSchema => yw_json::parse(
            RESPONSE_FORMAT_SCHEMA.as_bytes(),
            &Limits {
                max_bytes: 4_096,
                max_depth: 16,
                max_nodes: 1_024,
                max_items: 1_024,
            },
        )
        .unwrap_or(Value::Null),
        ResponseFormatMode::JsonObject => json_object(vec![("type", json_str("json_object"))]),
    }
}

/// The request body (§4.1): fixed key order, no whitespace, `max_tokens` only when set and the
/// endpoint is not `api.openai.com` ([`LlmConfig::sent_max_tokens`]), `reasoning_effort` last
/// and only when set. The explanation and the connection test both go through here.
///
/// # Errors
///
/// [`ExplainError::InputTooLarge`] when the body exceeds [`MAX_REQUEST_BODY`].
pub fn build_body(cfg: &LlmConfig, input: &ExplainInput) -> Result<Vec<u8>, ExplainError> {
    let user = String::from_utf8(input.json().to_vec()).map_err(|_| ExplainError::InputTooLarge)?;
    let mut pairs = vec![
        ("model", json_str(cfg.model())),
        ("stream", Value::Bool(false)),
        (
            "messages",
            Value::Array(vec![
                json_object(vec![
                    ("role", json_str("system")),
                    ("content", json_str(SYSTEM_PROMPT_V1.get(input.lang()))),
                ]),
                json_object(vec![
                    ("role", json_str("user")),
                    ("content", json_str(&user)),
                ]),
            ]),
        ),
        ("response_format", response_format(cfg.response_format())),
    ];
    if let Some(max_tokens) = cfg.sent_max_tokens() {
        pairs.push((
            "max_tokens",
            Value::Number(Number::from_u64(u64::from(max_tokens))),
        ));
    }
    if let Some(effort) = cfg.reasoning_effort() {
        pairs.push(("reasoning_effort", json_str(effort.as_str())));
    }
    let body = yw_json::to_vec(&json_object(pairs));
    if body.len() > MAX_REQUEST_BODY {
        return Err(ExplainError::InputTooLarge);
    }
    Ok(body)
}

/// An HTTP response of the transport.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// Body (at most `max_response` bytes).
    pub body: Vec<u8>,
}

impl core::fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Transport failures (the `WinHTTP` error kinds; no URL or text).
pub type TransportError = HttpError;

/// The POST used for explanations (§9). Tests use a mock; production is [`WinHttpTransport`].
pub trait LlmTransport: Send {
    /// POSTs `body` with exactly `headers`, reading at most `max_response` bytes.
    ///
    /// # Errors
    ///
    /// [`TransportError`].
    fn post(
        &self,
        url: &EndpointUrl,
        headers: &[(&str, &str)],
        body: &[u8],
        max_response: usize,
    ) -> Result<HttpResponse, TransportError>;
}

/// `yw_win::http::Client` for the LLM: its own session (not the RPC one), `Client::new` for https
/// and `Client::new_loopback` (no proxy) for loopback http, [`LLM_TIMEOUTS`], no redirects,
/// cookies or automatic authentication (spec/01 §7.4).
#[derive(Debug)]
pub struct WinHttpTransport {
    client: Client,
}

impl WinHttpTransport {
    /// Opens the session matching `endpoint`.
    ///
    /// # Errors
    ///
    /// [`HttpError`] from session creation.
    pub fn new(endpoint: &EndpointUrl) -> Result<Self, HttpError> {
        let client = match endpoint {
            EndpointUrl::Https(_) => Client::new(LLM_TIMEOUTS)?,
            EndpointUrl::Loopback(_) => Client::new_loopback(LLM_TIMEOUTS)?,
        };
        Ok(Self { client })
    }
}

impl LlmTransport for WinHttpTransport {
    fn post(
        &self,
        url: &EndpointUrl,
        headers: &[(&str, &str)],
        body: &[u8],
        max_response: usize,
    ) -> Result<HttpResponse, TransportError> {
        let response = self.client.post(url, headers, body, max_response)?;
        Ok(HttpResponse {
            status: response.status,
            content_type: response.content_type,
            body: response.body,
        })
    }
}

const fn transport_error(error: TransportError) -> ExplainError {
    match error {
        HttpError::Timeout => ExplainError::Timeout,
        HttpError::Tls => ExplainError::Tls,
        HttpError::TooLarge => ExplainError::TooLarge,
        HttpError::InvalidUrl | HttpError::InvalidHeader | HttpError::Os(_) => {
            ExplainError::Network
        }
    }
}

/// One complete request (§4–§5): body, POST with exactly `Content-Type`, `Accept` and (with a key)
/// `Authorization`, and the full response validation. Nothing is sent when the body is too large.
pub fn explain_once(
    transport: &dyn LlmTransport,
    cfg: &LlmConfig,
    input: &ExplainInput,
) -> (Result<Explanation, ExplainError>, RequestStats) {
    let started = yw_win::time::monotonic_ms();
    let mut stats = RequestStats::default();
    let body = match build_body(cfg, input) {
        Ok(body) => body,
        Err(error) => return (Err(error), stats),
    };
    stats.req_bytes = body.len();
    // The key goes only to the host it was entered for (spec/06 §2.1).
    let bearer = cfg.api_key().and_then(|key| key.bearer_for(cfg.host()));
    let mut headers: Vec<(&str, &str)> = vec![
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
    ];
    if let Some(bearer) = bearer.as_ref() {
        headers.push(("Authorization", bearer.as_str()));
    }
    let response = transport.post(cfg.endpoint(), &headers, &body, MAX_RESPONSE_BODY);
    stats.elapsed_ms = yw_win::time::monotonic_ms().saturating_sub(started);
    let response = match response {
        Ok(response) => response,
        Err(error) => return (Err(transport_error(error)), stats),
    };
    stats.http = Some(response.status);
    stats.resp_bytes = response.body.len();
    let result = parse_response(
        response.status,
        response.content_type.as_deref(),
        &response.body,
        input,
    );
    (result, stats)
}
