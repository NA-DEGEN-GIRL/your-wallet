//! The Windows transport of the LLM explanation (spec/06 §4.1, §9): yw-win `http::Client`.
//!
//! 2026-11-17 S2: moved unchanged from `explain::request` (where it was re-exported as
//! `explain::WinHttpTransport`), so `explain` names only the [`LlmTransport`] seam.
//! [`llm_factory`] is the app's `Services::llm` (2026-11-20, S4 P2; before, `app_llm` handed
//! [`factory`] to `ExplainService::start` and built [`WinHttpTransport`] for the connection test
//! itself): it runs on the `yw-llm` worker when the service starts, or for the connection test,
//! so with the feature off no session is opened (D21).

use std::sync::Arc;

use yw_engine::services::LlmFactory;
use yw_platform::http::{EndpointUrl, HttpError};
use yw_win::http::Client;

use crate::explain::TransportFactory;
use crate::explain::request::{HttpResponse, LLM_TIMEOUTS, LlmTransport, TransportError};

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

/// A [`WinHttpTransport`] for the endpoint, or `None` when the session cannot be opened (every
/// job then fails with `ExplainError::Network`).
fn open(endpoint: &EndpointUrl) -> Option<Box<dyn LlmTransport>> {
    WinHttpTransport::new(endpoint)
        .ok()
        .map(|transport| Box::new(transport) as Box<dyn LlmTransport>)
}

/// A one-shot factory over `open` for `ExplainService::start` (the app's own start uses
/// `Services::llm` since 2026-11-20 S4 P2; the loopback tests still call this).
#[must_use]
pub fn factory() -> TransportFactory {
    Box::new(open)
}

/// The production [`LlmFactory`] of `yw_engine::services::Services` (2026-11-20, S4 P2): the
/// same `open`, reusable by the worker start and the connection test (`app::windows_services`).
#[must_use]
pub fn llm_factory() -> LlmFactory {
    Arc::new(open)
}
