//! The Windows transport of the LLM explanation (spec/06 §4.1, §9): yw-win `http::Client`.
//!
//! 2026-11-17 S2: moved unchanged from `explain::request` (where it was re-exported as
//! `explain::WinHttpTransport`), so `explain` names only the [`LlmTransport`] seam.
//! [`factory`] is what the app hands to `ExplainService::start`; it runs on the `yw-llm` worker
//! when the service starts, so with the feature off no session is opened (D21).

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

/// The production transport factory: a [`WinHttpTransport`] for the endpoint, or `None` when
/// the session cannot be opened (every job then fails with `ExplainError::Network`).
#[must_use]
pub fn factory() -> TransportFactory {
    Box::new(|endpoint: &EndpointUrl| {
        WinHttpTransport::new(endpoint)
            .ok()
            .map(|transport| Box::new(transport) as Box<dyn LlmTransport>)
    })
}
