//! Zcash jobs on the RPC worker (spec/12 §4, §11): `Refresh` (chain check, address UTXOs and
//! the status of every journal transaction that may still confirm) and `Send`
//! (`sendrawtransaction`). The worker keeps no state; every result goes back to the UI, which
//! asks the key worker to apply journal steps. URLs are never logged (D13).

use yw_core::zec::{ZecNetwork, ZecOutPoint, ZecUtxo};
use yw_win::http::HttpsUrl;

use super::rpc::{
    ChainView, SendOutcome, TxStatus, UsefulUtxos, ZecRpcError, chain_check, keep_useful, send_raw,
    tx_status, unspent_of, utxos_blockbook, utxos_node,
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
        /// Inputs of those records: which are still unspent decides `Expired` (spec/12 §12.2).
        watch: Vec<ZecOutPoint>,
        /// The largest outputs of the last answer (at most `ZEC_MAX_INPUTS`): what is still
        /// sent from when the address answer goes over its limits (checked with `gettxout`).
        known: Vec<ZecUtxo>,
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
    /// UTXOs of our address (dust dropped, the largest [`yw_core::zec::ZEC_MAX_UTXOS`]); empty
    /// when the lookup failed (`utxo_error`).
    pub utxos: Vec<ZecUtxo>,
    /// Outputs left out of `utxos` (dust, beyond the limit).
    pub ignored_utxos: usize,
    /// The UTXO lookup failed: tracking still ran, sending is not possible.
    pub utxo_error: Option<ZecRpcError>,
    /// The watched inputs still listed as unspent (`None`: unknown, the lookup failed).
    pub unspent_watch: Option<Vec<ZecOutPoint>>,
    /// The address answer is over its limits and the node has no `gettxout`: whether a watched
    /// input is unspent cannot be learned from this endpoint (an expired record is closed as
    /// `InputsSpent` instead of blocking sends forever, spec/12 §12.2).
    pub watch_unknowable: bool,
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
        /// The address asked about (an answer for another account is dropped).
        address: String,
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

/// What a refresh learned about the address outputs.
struct UtxoView {
    useful: UsefulUtxos,
    error: Option<ZecRpcError>,
    unspent_watch: Option<Vec<ZecOutPoint>>,
    watch_unknowable: bool,
}

/// The address outputs from the lookup `listed`; over the limits (a dust flood), the outputs
/// already `known` and the `watch`ed inputs are each asked with `gettxout` (spec/12 §4.3).
fn utxo_view(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    listed: Result<Vec<ZecUtxo>, ZecRpcError>,
    watch: &[ZecOutPoint],
    known: Vec<ZecUtxo>,
) -> UtxoView {
    let view = |useful, error, unspent_watch| UtxoView {
        useful,
        error,
        unspent_watch,
        watch_unknowable: false,
    };
    match listed {
        Ok(all) => {
            let unspent = watch
                .iter()
                .filter(|point| all.iter().any(|utxo| utxo.outpoint == **point))
                .copied()
                .collect();
            view(keep_useful(all), None, Some(unspent))
        }
        Err(ZecRpcError::TooMany) => {
            let mut points = watch.to_vec();
            for utxo in &known {
                if !points.contains(&utxo.outpoint) {
                    points.push(utxo.outpoint);
                }
            }
            let over = Some(ZecRpcError::TooMany);
            match unspent_of(client, url, &points) {
                Ok(unspent) => {
                    let kept = known
                        .into_iter()
                        .filter(|utxo| unspent.contains(&utxo.outpoint))
                        .collect();
                    let watched = watch
                        .iter()
                        .filter(|point| unspent.contains(point))
                        .copied()
                        .collect();
                    view(keep_useful(kept), over, Some(watched))
                }
                // No `gettxout`: the known outputs as they were (a spent one only makes the node
                // refuse the signed transaction); the watch can never be resolved here.
                Err(ZecRpcError::NoAddressIndex) => UtxoView {
                    watch_unknowable: true,
                    ..view(keep_useful(known), over, None)
                },
                Err(_) => view(UsefulUtxos::default(), over, None),
            }
        }
        Err(error) => view(UsefulUtxos::default(), Some(error), None),
    }
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
            watch,
            known,
        } => {
            let result = (|| {
                let chain = chain_check(&client, &url, network)?;
                // The UTXO lookup and the tracking are independent: a UTXO problem (dust flood,
                // indexer error) never stops the journal transitions.
                let listed = match indexer {
                    ZecIndexer::Node => utxos_node(&client, &url, &address, &script_hex),
                    ZecIndexer::BbRest => utxos_blockbook(transport, &url, &address),
                };
                let view = utxo_view(&client, &url, listed, &watch, known);
                let tracked = track
                    .into_iter()
                    .map(|txid| {
                        let status = tx_status(&client, &url, &txid);
                        (txid, status)
                    })
                    .collect();
                Ok(Box::new(ZecSnapshot {
                    chain,
                    utxos: view.useful.utxos,
                    ignored_utxos: view.useful.ignored,
                    utxo_error: view.error,
                    unspent_watch: view.unspent_watch,
                    watch_unknowable: view.watch_unknowable,
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
                address,
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
