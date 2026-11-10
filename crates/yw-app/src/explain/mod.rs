//! Optional LLM transaction explanation (M6, spec/06, D21).
//!
//! The approval window may show a separate, clearly labelled panel "AI 설명 (참고용, 틀릴 수
//! 있음)" with a Korean explanation written by an OpenAI-compatible endpoint the user configured.
//! The explanation is reference text only: it is never an input of the risk level, the warnings,
//! the approval gate (`ui::interaction::can_approve`) or the approval digest, and the approval
//! never waits for it (spec/06 §1).
//!
//! - [`config`]: `llm_explain` settings, endpoint/model/key rules, the privacy notice (§2).
//! - [`input`]: `yw.explain.input.v1` built from the wallet's own decoding and the simulation
//!   status, with untrusted strings wrapped and capped, and the trusted sets of §5.3 (§4.3–§4.4).
//! - [`request`]: the HTTP body, the transport trait and its `WinHTTP` implementation (§4.1–§4.5).
//! - [`response`]: envelope, content schema, forbidden content and consistency checks (§5).
//! - [`panel`]: the per-window state machine and the display model (§3, §6–§7).
//! - [`ExplainService`]: the single `yw-llm` worker thread (§3.2, §9). It exists only while the
//!   feature is effectively on; when it is off nothing here runs and no connection is made.
//!
//! Logging (§8): one line per request from the UI thread (`llm_explain …`), never the prompt,
//! the input, the response body, model text, the key, the `Authorization` header or the endpoint
//! path. `Debug` of every type here prints kinds and sizes only.

pub mod config;
pub mod input;
pub mod panel;
pub mod request;
pub mod response;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;

pub use config::{LlmConfig, PRIVACY_NOTICE_VERSION, ReasoningEffort, ResponseFormatMode};
pub use input::{ExplainInput, ExplainSim, ExplainSource, build_input};
pub use panel::{AiPanel, AiPanelState};
pub use request::{HttpResponse, LlmTransport, WinHttpTransport, build_body, explain_once};
pub use response::{ActionType, ExplainAction, Explanation, parse_response};

/// The UI deadline of one request (spec/06 §3.2).
pub const REQUEST_DEADLINE_MS: u64 = 10_000;
/// Largest request body (§4.1).
pub const MAX_REQUEST_BODY: usize = 49_152;
/// Largest response body (§5.1).
pub const MAX_RESPONSE_BODY: usize = 16_384;
/// Requests per approval window (§3.2).
pub const MAX_REQUESTS_PER_APPROVAL: u8 = 3;
/// Requests in flight at once (one `yw-llm` worker).
pub const MAX_CONCURRENT_REQUESTS: usize = 1;
/// Untrusted scalars per request (§4.4).
pub const UNTRUSTED_TOTAL_SCALARS: usize = 6_144;

/// Why the AI text was hidden (§5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenReason {
    /// A character outside the allowlist.
    ForbiddenChar,
    /// `://` or `www.`.
    Link,
    /// A safety verdict or an approval recommendation.
    Verdict,
}

impl HiddenReason {
    /// Log word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForbiddenChar => "ForbiddenChar",
            Self::Link => "Link",
            Self::Verdict => "Verdict",
        }
    }
}

/// Which consistency rule failed (§5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MismatchReason {
    /// An action's `asset` is not an input asset.
    ActionAsset,
    /// An action's `amount` is not an input amount.
    ActionAmount,
    /// An action's `from`/`to` is not an input address.
    ActionAddress,
    /// A hex token of the text is not an input address or hex value.
    HexToken,
    /// A number of the text is not an input number or amount.
    NumberToken,
}

impl MismatchReason {
    /// Log word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActionAsset => "ActionAsset",
            Self::ActionAmount => "ActionAmount",
            Self::ActionAddress => "ActionAddress",
            Self::HexToken => "HexToken",
            Self::NumberToken => "NumberToken",
        }
    }
}

/// Every non-success outcome (spec/06 §7). `Debug` shows the kind only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainError {
    /// Endpoint or model invalid (connection test).
    NotConfigured,
    /// The body would exceed [`MAX_REQUEST_BODY`].
    InputTooLarge,
    /// [`REQUEST_DEADLINE_MS`] passed (or `WinHTTP` timed out).
    Timeout,
    /// Connection or name resolution failed.
    Network,
    /// TLS failed.
    Tls,
    /// HTTP status other than 200 (3xx included: redirects are never followed).
    Http(u16),
    /// The response exceeds [`MAX_RESPONSE_BODY`].
    TooLarge,
    /// The envelope is not an `OpenAI` chat completion (§5.1).
    Envelope,
    /// The content breaks the schema (§5.2).
    Schema,
    /// `finish_reason` `length` or `content_filter`.
    Truncated,
    /// The model refused.
    Refusal,
    /// Forbidden content (§5.2).
    Hidden(HiddenReason),
    /// The text does not match the input (§5.3).
    Mismatch(MismatchReason),
    /// More than [`MAX_REQUESTS_PER_APPROVAL`] requests.
    LimitReached,
}

impl ExplainError {
    /// Log word (§8 `result=`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "NotConfigured",
            Self::InputTooLarge => "InputTooLarge",
            Self::Timeout => "Timeout",
            Self::Network => "Network",
            Self::Tls => "Tls",
            Self::Http(_) => "Http",
            Self::TooLarge => "TooLarge",
            Self::Envelope => "Envelope",
            Self::Schema => "Schema",
            Self::Truncated => "Truncated",
            Self::Refusal => "Refusal",
            Self::Hidden(_) => "Hidden",
            Self::Mismatch(_) => "Mismatch",
            Self::LimitReached => "LimitReached",
        }
    }

    /// Log word of the reason (`-` when none).
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Hidden(reason) => reason.as_str(),
            Self::Mismatch(reason) => reason.as_str(),
            _ => "-",
        }
    }

    /// The one-line panel text (§7).
    #[must_use]
    pub fn panel_text(self) -> String {
        match self {
            Self::NotConfigured => "AI 설명 설정이 완료되지 않았습니다".to_owned(),
            Self::InputTooLarge => "요청 데이터가 커서 AI 설명을 건너뜁니다".to_owned(),
            Self::Timeout => "AI 응답 시간 초과(10초)".to_owned(),
            Self::Network | Self::Tls => "AI 공급자에 연결할 수 없습니다".to_owned(),
            Self::Http(401 | 403) => "AI API 키가 거부되었습니다".to_owned(),
            Self::Http(429) => "AI 요청 한도를 초과했습니다".to_owned(),
            Self::Http(code) => format!("AI 공급자 오류(HTTP {code})"),
            Self::TooLarge => "AI 응답이 너무 큽니다".to_owned(),
            Self::Envelope | Self::Schema | Self::Truncated => {
                "AI 응답 형식이 올바르지 않습니다".to_owned()
            }
            Self::Refusal => "AI가 설명을 거부했습니다".to_owned(),
            Self::Hidden(_) => "AI 설명에 허용되지 않는 내용이 있어 숨겼습니다".to_owned(),
            Self::Mismatch(_) => "AI 설명이 실제 데이터와 다릅니다".to_owned(),
            Self::LimitReached => "AI 설명 요청 횟수를 모두 사용했습니다".to_owned(),
        }
    }
}

/// What one request measured (logged by the UI thread, §8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestStats {
    /// HTTP status, if a response arrived.
    pub http: Option<u16>,
    /// Request body bytes (0 when nothing was sent).
    pub req_bytes: usize,
    /// Response body bytes.
    pub resp_bytes: usize,
    /// Elapsed milliseconds in the worker.
    pub elapsed_ms: u64,
}

/// A job for the `yw-llm` worker.
#[derive(Debug)]
pub struct LlmJob {
    /// The approval window it belongs to.
    pub window: u64,
    /// The panel generation at request time (§3.2).
    pub generation: u64,
    /// The input.
    pub input: ExplainInput,
}

/// A finished job.
#[derive(Debug)]
pub struct LlmDone {
    /// Window.
    pub window: u64,
    /// Generation.
    pub generation: u64,
    /// Result.
    pub result: Result<Explanation, ExplainError>,
    /// Measurements.
    pub stats: RequestStats,
}

/// The `yw-llm` worker (spec/06 §3.2, §9): one thread, one request at a time, owning the
/// endpoint, the API key (D10: not a wallet secret) and its own `WinHTTP` session. It exists only
/// while the feature is effectively on (`Option<ExplainService>` = `None` otherwise).
pub struct ExplainService {
    jobs: Option<mpsc::Sender<LlmJob>>,
    busy: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    host: String,
    model: String,
}

impl core::fmt::Debug for ExplainService {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ExplainService")
            .field("busy", &self.busy())
            .finish_non_exhaustive()
    }
}

impl ExplainService {
    /// Starts the worker with the production `WinHTTP` transport (created on the worker).
    ///
    /// # Errors
    ///
    /// [`ExplainError::Network`] when the thread cannot start.
    pub fn start(
        config: LlmConfig,
        sink: Box<dyn Fn(LlmDone) + Send>,
    ) -> Result<Self, ExplainError> {
        Self::spawn(config, None, sink)
    }

    /// Starts the worker with a caller-supplied transport (tests).
    ///
    /// # Errors
    ///
    /// [`ExplainError::Network`] when the thread cannot start.
    pub fn start_with(
        config: LlmConfig,
        transport: Box<dyn LlmTransport>,
        sink: Box<dyn Fn(LlmDone) + Send>,
    ) -> Result<Self, ExplainError> {
        Self::spawn(config, Some(transport), sink)
    }

    fn spawn(
        config: LlmConfig,
        transport: Option<Box<dyn LlmTransport>>,
        sink: Box<dyn Fn(LlmDone) + Send>,
    ) -> Result<Self, ExplainError> {
        let (tx, rx) = mpsc::channel::<LlmJob>();
        let busy = Arc::new(AtomicBool::new(false));
        let worker_busy = Arc::clone(&busy);
        let host = config.host().to_owned();
        let model = config.model().to_owned();
        let thread = std::thread::Builder::new()
            .name("yw-llm".to_owned())
            .spawn(move || {
                let transport: Option<Box<dyn LlmTransport>> = transport.or_else(|| {
                    WinHttpTransport::new(config.endpoint())
                        .ok()
                        .map(|transport| Box::new(transport) as Box<dyn LlmTransport>)
                });
                for job in rx {
                    let (result, stats) = match transport.as_deref() {
                        Some(transport) => explain_once(transport, &config, &job.input),
                        None => (Err(ExplainError::Network), RequestStats::default()),
                    };
                    worker_busy.store(false, Ordering::SeqCst);
                    sink(LlmDone {
                        window: job.window,
                        generation: job.generation,
                        result,
                        stats,
                    });
                }
            })
            .map_err(|_| ExplainError::Network)?;
        Ok(Self {
            jobs: Some(tx),
            busy,
            thread: Some(thread),
            host,
            model,
        })
    }

    /// Whether a request is in flight (a new one then waits, §3.2).
    #[must_use]
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    /// Queues `job` unless a request is in flight ([`MAX_CONCURRENT_REQUESTS`]).
    #[must_use]
    pub fn submit(&self, job: LlmJob) -> bool {
        let Some(jobs) = self.jobs.as_ref() else {
            return false;
        };
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        if jobs.send(job).is_err() {
            self.busy.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// `host[:port]` of the endpoint (display and log, §6, §8).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The model name (display).
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Closes the job channel and waits up to `wait_ms` for the worker (it may still be inside
    /// `WinHTTP`; then it is left to finish and its result is dropped).
    pub fn stop(mut self, wait_ms: u64) {
        drop(self.jobs.take());
        let Some(thread) = self.thread.take() else {
            return;
        };
        let deadline = yw_win::time::monotonic_ms().saturating_add(wait_ms);
        while !thread.is_finished() && yw_win::time::monotonic_ms() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if thread.is_finished() {
            let _ = thread.join();
        }
    }
}
