//! The platform services the application logic starts its optional network workers from
//! (spec/15 §11.2, §11.4 S4 P2; owner decision O-8): the transport of the LLM explanation
//! (spec/06 §4.1, §9) and the platform parts of the `WalletConnect` relay worker (spec/13 §4, §7),
//! plus the platform word of the relay user agent.
//!
//! [`Services`] is a bundle of factories, not an OS abstraction: nothing here opens a session or
//! a socket by itself. The LLM factory runs only when the `yw-llm` worker starts (on its thread)
//! or when the user presses the connection test, so with the feature off no transport is ever
//! made (D21); the `WalletConnect` parts are asked for only when the relay worker starts (after
//! an unlock with a project id). Windows: yw-app `app::windows_services` (`WinHTTP` for the LLM,
//! `WsConnector` + `WinHTTP` + CNG P-256 for `WalletConnect`, user agent word `"windows"`).
//!
//! `Debug` of [`Services`] prints which parts are present and the platform word only.
//!
//! 2026-11-20 (spec/15 §11.4 S4 P2): created. Before, `impl App` built these platform values
//! inline in `app_llm.rs` (`explain_transport::factory()`, `WinHttpTransport::new`) and
//! `app_walletconnect.rs` (`WsConnector`, `yw_win::http::Client::new`, `yw_win::cng::p256_verify`,
//! `"windows"`).

use core::fmt;
use std::sync::Arc;

use yw_platform::http::EndpointUrl;

use crate::explain::{LlmTransport, TransportFactory};
use crate::walletconnect::verify::{P256Verify, VerifyHttp};
use crate::walletconnect::worker::RelayConnector;

/// Creates the LLM transport for an endpoint (`None`: no transport; every request then fails
/// with `ExplainError::Network`). Reusable: the worker start and the connection test both call
/// it, each time it is needed and never while the feature is off (D21).
pub type LlmFactory = Arc<dyn Fn(&EndpointUrl) -> Option<Box<dyn LlmTransport>> + Send + Sync>;

/// The platform parts of the `WalletConnect` relay worker (spec/13 §4, §7), asked for once per
/// worker start.
pub trait WcPlatform: Send {
    /// The relay socket connector (Windows: the `WinHTTP` WebSocket).
    fn connector(&self) -> Box<dyn RelayConnector>;
    /// The Verify API HTTP client (`None` when its session cannot be opened: Verify is then
    /// `Unknown`, never a block, spec/13 §7).
    fn verify_http(&self) -> Option<Box<dyn VerifyHttp + Send>>;
    /// The P-256 signature check of Verify v3 attestations (Windows: CNG).
    fn p256(&self) -> P256Verify;
}

/// What the platform gives the application logic to start its optional network workers.
pub struct Services {
    /// The LLM explanation transport factory.
    pub llm: LlmFactory,
    /// The `WalletConnect` platform parts (`None`: the relay worker is never started).
    pub walletconnect: Option<Box<dyn WcPlatform>>,
    /// The last word of the relay user agent (`wc-2/rust-yourwallet-{version}/{word}`,
    /// spec/13 §4; Windows `"windows"`).
    pub ua_platform: &'static str,
}

impl Services {
    /// A one-shot [`TransportFactory`] for `ExplainService::start` over [`Self::llm`] (called on
    /// the `yw-llm` thread when the service starts).
    #[must_use]
    pub fn llm_factory(&self) -> TransportFactory {
        let llm = Arc::clone(&self.llm);
        Box::new(move |endpoint: &EndpointUrl| llm(endpoint))
    }
}

impl fmt::Debug for Services {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Services")
            .field("walletconnect", &self.walletconnect.is_some())
            .field("ua_platform", &self.ua_platform)
            .finish_non_exhaustive()
    }
}
