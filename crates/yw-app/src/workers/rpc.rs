//! The RPC worker thread `yw-rpc` (spec/04 §1.2): FIFO jobs over the shared HTTPS client. M3 has
//! only the endpoint `테스트`; balances, fees, simulation and sending arrive with M4. It never
//! touches the DEK.

use std::sync::mpsc::Receiver;

use yw_win::http::HttpsUrl;

use crate::errors::ErrorCode;
use crate::events::{EventQueue, RpcEvent, UiEvent};
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::rpc::{RpcClient, TestOutcome, Transport, test_endpoint};

/// An RPC job.
pub enum RpcJob {
    /// Endpoint test with an explicit URL (typed or stored).
    Test {
        /// Network.
        network: NetworkId,
        /// Display name for the message.
        name: String,
        /// URL (secret).
        url: HttpsUrl,
    },
    /// Stop.
    Shutdown,
}

impl core::fmt::Debug for RpcJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Test { network, .. } => write!(formatter, "RpcJob::Test({network})"),
            Self::Shutdown => formatter.write_str("RpcJob::Shutdown"),
        }
    }
}

/// Runs one test and builds its event; logs `rpc.test net=<NetworkId> result=<code|ok>`.
#[must_use]
pub fn run_test(
    transport: &dyn Transport,
    network: NetworkId,
    name: &str,
    url: &HttpsUrl,
) -> RpcEvent {
    let client = RpcClient::new(transport);
    let outcome = test_endpoint(&client, network, url);
    logging::info(
        "rpc",
        "rpc.test",
        &[
            ("net", Field::Net(network)),
            ("result", Field::Word(outcome.log_word())),
        ],
    );
    RpcEvent::Test {
        network,
        message: outcome.message(name),
        ok: matches!(outcome, TestOutcome::Ok(_)),
    }
}

/// The worker loop. `transport = None` (client creation failed) answers every test with
/// E-RPC-001.
pub fn run(transport: Option<&dyn Transport>, jobs: &Receiver<RpcJob>, events: &EventQueue) {
    while let Ok(job) = jobs.recv() {
        match job {
            RpcJob::Shutdown => break,
            RpcJob::Test { network, name, url } => {
                let event = match transport {
                    Some(transport) => run_test(transport, network, &name, &url),
                    None => RpcEvent::Test {
                        network,
                        message: ErrorCode::Rpc001.text(),
                        ok: false,
                    },
                };
                if events.push(UiEvent::Rpc(event)).is_err() {
                    logging::warn("rpc", "E-APP-005", &[("net", Field::Net(network))]);
                }
            }
        }
    }
}
