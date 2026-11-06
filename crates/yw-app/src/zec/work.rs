//! Zcash jobs on the RPC worker (spec/12 §4, §11): `Refresh` (chain check, address UTXOs and
//! the status of every journal transaction that may still confirm) and `Send`
//! (`sendrawtransaction`). The worker keeps no state; every result goes back to the UI, which
//! asks the key worker to apply journal steps. URLs are never logged (D13).

use yw_core::zec::{ZecNetwork, ZecUtxo};
use yw_win::http::HttpsUrl;

use super::rpc::{
    ChainView, SendOutcome, TxStatus, ZecRpcError, chain_check, send_raw, tx_status,
    utxos_blockbook, utxos_node,
};
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::rpc::{RpcClient, Transport};
use crate::settings::ZecIndexer;

/// A Zcash RPC job.
pub enum ZecRpcJob {
    /// Chain check, UTXOs of `address`, status of `track`.
    Refresh {
        /// Job number (stale answers are dropped by the UI).
        job: u64,
        /// Network.
        network: ZecNetwork,
        /// Endpoint URL (secret).
        url: HttpsUrl,
        /// UTXO source.
        indexer: ZecIndexer,
        /// Our address.
        address: String,
        /// Our `scriptPubKey` (lowercase hex).
        script_hex: String,
        /// Txids (display hex) of records that may still confirm.
        track: Vec<String>,
    },
    /// `sendrawtransaction` of a journaled, disclosed transaction.
    Send {
        /// Network.
        network: ZecNetwork,
        /// Endpoint URL (secret).
        url: HttpsUrl,
        /// Signed bytes.
        raw: Vec<u8>,
        /// Txid (internal order).
        txid: [u8; 32],
    },
}

impl core::fmt::Debug for ZecRpcJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl ZecRpcJob {
    /// Fixed name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Refresh { .. } => "ZecRefresh",
            Self::Send { .. } => "ZecSend",
        }
    }
}

/// A refresh answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecSnapshot {
    /// Chain view.
    pub chain: ChainView,
    /// UTXOs of our address.
    pub utxos: Vec<ZecUtxo>,
    /// Status of every tracked txid (display hex), `Err` when that call failed.
    pub tracked: Vec<(String, Result<TxStatus, ZecRpcError>)>,
}

/// A Zcash RPC result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZecRpcEvent {
    /// `Refresh` finished.
    Refreshed {
        /// Job number.
        job: u64,
        /// Network.
        network: ZecNetwork,
        /// The snapshot or the first failure.
        result: Result<Box<ZecSnapshot>, ZecRpcError>,
    },
    /// `Send` finished.
    Sent {
        /// Network.
        network: ZecNetwork,
        /// Txid (internal order).
        txid: [u8; 32],
        /// The node's answer.
        outcome: SendOutcome,
    },
}

/// Runs one job and returns its event.
#[must_use]
pub fn handle(transport: &dyn Transport, job: ZecRpcJob) -> ZecRpcEvent {
    let client = RpcClient::new(transport);
    match job {
        ZecRpcJob::Refresh {
            job,
            network,
            url,
            indexer,
            address,
            script_hex,
            track,
        } => {
            let result = (|| {
                let chain = chain_check(&client, &url, network)?;
                let utxos = match indexer {
                    ZecIndexer::Node => utxos_node(&client, &url, &address, &script_hex)?,
                    ZecIndexer::BbRest => utxos_blockbook(transport, &url, &address)?,
                };
                let tracked = track
                    .into_iter()
                    .map(|txid| {
                        let status = tx_status(&client, &url, &txid);
                        (txid, status)
                    })
                    .collect();
                Ok(Box::new(ZecSnapshot {
                    chain,
                    utxos,
                    tracked,
                }))
            })();
            logging::info(
                "rpc",
                "zec.refresh",
                &[
                    ("net", Field::Net(NetworkId::Zcash(network))),
                    (
                        "result",
                        Field::Word(if result.is_ok() { "ok" } else { "error" }),
                    ),
                ],
            );
            ZecRpcEvent::Refreshed {
                job,
                network,
                result,
            }
        }
        ZecRpcJob::Send {
            network,
            url,
            raw,
            txid,
        } => {
            let outcome = send_raw(&client, &url, &raw, &yw_core::zec::tx::txid_display(&txid));
            logging::info(
                "rpc",
                "zec.send",
                &[
                    ("net", Field::Net(NetworkId::Zcash(network))),
                    (
                        "result",
                        Field::Word(match outcome {
                            SendOutcome::Accepted => "accepted",
                            SendOutcome::Rejected(_) => "rejected",
                            SendOutcome::Unknown(_) => "unknown",
                        }),
                    ),
                ],
            );
            ZecRpcEvent::Sent {
                network,
                txid,
                outcome,
            }
        }
    }
}
