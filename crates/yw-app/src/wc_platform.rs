//! The Windows `WalletConnect` platform parts (spec/13 §4, §6): the relay connector over the
//! `WinHTTP` WebSocket and the Verify API client with the CNG P-256 check, which
//! `yw_engine::services::Services` hands to the relay worker. 2026-11-22 (S4d E0c): moved
//! unchanged from `app_walletconnect` (a file that moves to the engine at S4d E1, which must not
//! name `yw_win`).

use std::sync::Arc;

use yw_engine::services::WcPlatform;

use yw_engine::walletconnect::verify::{P256Verify, VerifyHttp};
use yw_engine::walletconnect::worker::{ConnectError, RelayConnector, RelayLink, connect_error};

/// Relay connect timeout.
const CONNECT_TIMEOUT_MS: u32 = 15_000;

/// The production relay connector: the `WinHTTP` WebSocket (`yw_win::ws`). 2026-11-17 S2: moved
/// unchanged from `walletconnect::worker`, which names only the `RelayConnector` seam.
#[derive(Debug, Default)]
pub struct WsConnector;

impl RelayConnector for WsConnector {
    fn connect(&mut self, url: &str) -> Result<Arc<dyn RelayLink>, ConnectError> {
        let url = yw_platform::http::HttpsUrl::parse(url).map_err(|_| ConnectError::Network)?;
        match yw_win::ws::WebSocket::connect(&url, CONNECT_TIMEOUT_MS) {
            Ok(socket) => Ok(Arc::new(socket)),
            Err(error) => Err(connect_error(error)),
        }
    }
}

/// The Windows `WalletConnect` platform parts of `yw_engine::services::Services` (2026-11-20, S4
/// P2; before, `wc_start` built them inline): [`WsConnector`], the Verify API's
/// `yw_win::http::Client` with 5 s for each phase, and `yw_win::cng::p256_verify`.
#[derive(Debug, Default)]
pub struct WinWcPlatform;

impl WcPlatform for WinWcPlatform {
    fn connector(&self) -> Box<dyn RelayConnector> {
        Box::new(WsConnector)
    }

    fn verify_http(&self) -> Option<Box<dyn VerifyHttp + Send>> {
        yw_win::http::Client::new(yw_platform::http::Timeouts {
            resolve_ms: 5_000,
            connect_ms: 5_000,
            send_ms: 5_000,
            receive_ms: 5_000,
        })
        .ok()
        .map(|client| Box::new(client) as Box<dyn VerifyHttp + Send>)
    }

    fn p256(&self) -> P256Verify {
        yw_win::cng::p256_verify
    }
}
