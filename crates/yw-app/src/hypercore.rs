//! `HyperCore` HTTP calls on the RPC worker (spec/11 §4, §5.3): `POST {api}/info` for the token
//! list and balances, `POST {api}/exchange` for a signed action. The API base is public (no
//! secret); logs carry the network word only.

use yw_core::evm::address::Address;
use yw_core::hypercore::{
    HcExchangeReply, HcNetwork, HcPerpState, HcSpotBalance, HcToken, info_perp_state_body,
    info_spot_meta_body, info_spot_state_body, parse_exchange_reply, parse_perp_state,
    parse_spot_meta, parse_spot_state,
};
use yw_json::{Limits, Value};
use yw_win::http::{HttpError, HttpsUrl};

use crate::logging::{self, Field};
use crate::rpc::Transport;

/// Largest `/info` response (testnet `spotMeta` is ≈ 0.45 MB with 1,677 tokens).
pub const MAX_INFO_RESPONSE: usize = 8 * 1_024 * 1_024;
/// Largest `/exchange` response.
pub const MAX_EXCHANGE_RESPONSE: usize = 64 * 1_024;
const INFO_LIMITS: Limits = Limits {
    max_bytes: MAX_INFO_RESPONSE,
    max_depth: 16,
    max_nodes: 2_000_000,
    max_items: 2_000_000,
};

/// Where to call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HcEndpoint {
    /// Network.
    pub network: HcNetwork,
    /// API base (`https://…`, no trailing `/`).
    pub api: String,
}

/// A `HyperCore` job of the RPC worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HcRpcJob {
    /// Balances of `account` (and `spotMeta` when `meta`).
    Load {
        /// UI job.
        job: u64,
        /// Endpoint.
        endpoint: HcEndpoint,
        /// Account.
        account: Address,
        /// Also fetch `spotMeta`.
        meta: bool,
    },
    /// Post a signed action.
    Submit {
        /// Endpoint.
        endpoint: HcEndpoint,
        /// Action nonce (activity key).
        nonce: u64,
        /// The `/exchange` body.
        body: Vec<u8>,
    },
}

/// Balances of one account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HcBalances {
    /// Spot balances.
    pub spot: Vec<HcSpotBalance>,
    /// Perp summary.
    pub perp: HcPerpState,
}

/// A `HyperCore` result for the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HcEvent {
    /// [`HcRpcJob::Load`] finished.
    Loaded {
        /// UI job.
        job: u64,
        /// Network.
        network: HcNetwork,
        /// Account.
        account: Address,
        /// `spotMeta` when asked.
        meta: Option<Result<Vec<HcToken>, String>>,
        /// Balances.
        balances: Result<HcBalances, String>,
    },
    /// [`HcRpcJob::Submit`] finished.
    Submitted {
        /// Network.
        network: HcNetwork,
        /// Action nonce.
        nonce: u64,
        /// The server answer, or why there is none (unknown outcome: the action may still
        /// have been processed).
        result: Result<HcExchangeReply, String>,
    },
}

fn failure_text(error: &HttpError) -> String {
    match error {
        HttpError::Timeout => "Hyperliquid API 응답 시간이 초과되었습니다".to_owned(),
        _ => "Hyperliquid API에 연결할 수 없습니다".to_owned(),
    }
}

fn post(
    transport: &dyn Transport,
    endpoint: &HcEndpoint,
    path: &str,
    body: &[u8],
    max_response: usize,
) -> Result<Value, String> {
    let url = HttpsUrl::parse(&format!("{}{path}", endpoint.api))
        .map_err(|_| "Hyperliquid API 주소가 올바르지 않습니다".to_owned())?;
    let reply = transport
        .post_json(&url, body, max_response)
        .map_err(|error| failure_text(&error))?;
    if reply.status != 200 {
        return Err(format!(
            "Hyperliquid API가 HTTP {}로 응답했습니다",
            reply.status
        ));
    }
    yw_json::parse(&reply.body, &INFO_LIMITS)
        .map_err(|_| "Hyperliquid API 응답 형식이 올바르지 않습니다".to_owned())
}

const SHAPE: &str = "Hyperliquid API 응답 형식이 올바르지 않습니다";

/// Runs one job.
#[must_use]
pub fn run(transport: &dyn Transport, job: HcRpcJob) -> HcEvent {
    match job {
        HcRpcJob::Load {
            job,
            endpoint,
            account,
            meta,
        } => {
            let meta = meta.then(|| {
                post(
                    transport,
                    &endpoint,
                    "/info",
                    &info_spot_meta_body(),
                    MAX_INFO_RESPONSE,
                )
                .and_then(|value| parse_spot_meta(&value).map_err(|_| SHAPE.to_owned()))
            });
            let balances = post(
                transport,
                &endpoint,
                "/info",
                &info_spot_state_body(&account),
                MAX_INFO_RESPONSE,
            )
            .and_then(|value| parse_spot_state(&value).map_err(|_| SHAPE.to_owned()))
            .and_then(|spot| {
                post(
                    transport,
                    &endpoint,
                    "/info",
                    &info_perp_state_body(&account),
                    MAX_INFO_RESPONSE,
                )
                .and_then(|value| parse_perp_state(&value).map_err(|_| SHAPE.to_owned()))
                .map(|perp| HcBalances { spot, perp })
            });
            logging::info(
                "rpc",
                "hypercore.load",
                &[
                    ("net", Field::Word(endpoint.network.as_str())),
                    (
                        "ok",
                        Field::Word(if balances.is_ok() { "yes" } else { "no" }),
                    ),
                ],
            );
            HcEvent::Loaded {
                job,
                network: endpoint.network,
                account,
                meta,
                balances,
            }
        }
        HcRpcJob::Submit {
            endpoint,
            nonce,
            body,
        } => {
            let result = post(
                transport,
                &endpoint,
                "/exchange",
                &body,
                MAX_EXCHANGE_RESPONSE,
            )
            .and_then(|value| parse_exchange_reply(&value).map_err(|_| SHAPE.to_owned()));
            logging::info(
                "rpc",
                "hypercore.submit",
                &[
                    ("net", Field::Word(endpoint.network.as_str())),
                    (
                        "result",
                        Field::Word(match &result {
                            Ok(HcExchangeReply::Ok) => "ok",
                            Ok(HcExchangeReply::Err(_)) => "err",
                            Err(_) => "unknown",
                        }),
                    ),
                ],
            );
            HcEvent::Submitted {
                network: endpoint.network,
                nonce,
                result,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use yw_core::evm::address::Address;
    use yw_core::hypercore::{HcExchangeReply, HcNetwork, TESTNET_API};
    use yw_win::http::{HttpError, HttpsUrl};

    use super::{HcEndpoint, HcEvent, HcRpcJob, run};
    use crate::rpc::{HttpReply, Transport};

    /// Answers by request `type` (docs examples); records the paths it was asked for.
    #[derive(Default)]
    struct Fake(Mutex<Vec<String>>);

    impl Transport for Fake {
        fn post_json(
            &self,
            url: &HttpsUrl,
            body: &[u8],
            _max_response: usize,
        ) -> Result<HttpReply, HttpError> {
            self.0
                .lock()
                .map_err(|_| HttpError::InvalidUrl)?
                .push(url.path().to_owned());
            let text = String::from_utf8_lossy(body);
            let answer: &[u8] = if text.contains(r#""type":"spotMeta""#) {
                br#"{"tokens":[{"name":"USDC","szDecimals":8,"weiDecimals":8,"index":0,"tokenId":"0xeb62eee3685fc4c43992febcd9e75443","isCanonical":true,"evmContract":null,"fullName":null}],"universe":[]}"#
            } else if text.contains("spotClearinghouseState") {
                br#"{"balances":[{"coin":"USDC","token":0,"hold":"0.0","total":"14.625485","entryNtl":"0.0"}]}"#
            } else if text.contains("clearinghouseState") {
                br#"{"assetPositions":[],"marginSummary":{"accountValue":"10.5","totalMarginUsed":"0.0","totalNtlPos":"0.0","totalRawUsd":"10.5"},"withdrawable":"10.5","time":1}"#
            } else {
                br#"{"status":"err","response":"Insufficient balance for withdrawal"}"#
            };
            Ok(HttpReply {
                status: 200,
                body: answer.to_vec(),
            })
        }
    }

    #[test]
    fn load_and_submit_through_the_worker() {
        let fake = Fake::default();
        let endpoint = HcEndpoint {
            network: HcNetwork::Testnet,
            api: TESTNET_API.to_owned(),
        };
        let event = run(
            &fake,
            HcRpcJob::Load {
                job: 7,
                endpoint: endpoint.clone(),
                account: Address::from_bytes([1; 20]),
                meta: true,
            },
        );
        let loaded = match event {
            HcEvent::Loaded {
                job: 7,
                meta: Some(Ok(tokens)),
                balances: Ok(balances),
                ..
            } => Some((tokens, balances)),
            _ => None,
        };
        let (tokens, balances) = loaded.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(balances.spot[0].total, "14.625485");
        assert_eq!(balances.perp.withdrawable, "10.5");
        let event = run(
            &fake,
            HcRpcJob::Submit {
                endpoint,
                nonce: 5,
                body: b"{}".to_vec(),
            },
        );
        assert!(matches!(
            event,
            HcEvent::Submitted { nonce: 5, result: Ok(HcExchangeReply::Err(message)), .. }
                if message.contains("Insufficient")
        ));
        assert_eq!(
            fake.0.lock().unwrap().as_slice(),
            ["/info", "/info", "/info", "/exchange"]
        );
    }
}
