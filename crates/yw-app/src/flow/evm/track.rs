//! Broadcast (spec/03 §4.4) and receipt tracking / reconcile (§4.5, §5.4) of journaled
//! transactions. Signed bytes are only ever re-sent as they are: nothing here signs.

use yw_core::evm::chain::ChainInfo;
use yw_core::journal::evm::{
    DROP_CONFIRM_MS, EvmRecord, FLAG_MANUAL_RESEND, FLAG_RPC_HASH_MISMATCH,
    REBROADCAST_INTERVAL_MS, Transition, TxState, latest_candidate,
};
use yw_win::http::HttpsUrl;

use super::{ChainCheck, Clock, Limits, MismatchKind, SharedTransport, check_chain, check_once};
use crate::errors::ErrorCode;
use crate::rpc::evm::{self as rpc, ReceiptLookup};
use crate::rpc::{RpcClient, RpcFailure, canonical_quantity, classify};

/// Confirmations used as finality when the node rejects the `finalized` tag (spec/03 §4.5 note).
pub const FALLBACK_CONFIRMATIONS: u64 = 64;

/// Result of a broadcast (spec/03 §4.4 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// The RPC returned the same hash: `Broadcast`.
    Sent,
    /// The RPC returned another hash: stays `Signed` + `rpc_hash_mismatch`, no automatic resend.
    HashMismatch,
    /// JSON-RPC error; `known` = `eth_getTransactionByHash` found it (→ `Broadcast`).
    Rejected {
        /// The node knows the transaction.
        known: bool,
    },
    /// Transport errors after the 2 s and 5 s resends; `known` as above.
    Unconfirmed {
        /// The node knows the transaction.
        known: bool,
    },
    /// `eth_chainId` or the block-0 hash no longer matches: nothing sent, manual resend only.
    ChainMismatch,
    /// The chain could not be re-checked (transport failures after the retries of spec/03
    /// §1.4): nothing sent, the record stays `Signed` and tracking re-sends it automatically.
    ChainUnverified,
}

impl BroadcastOutcome {
    /// The journal transition of this outcome: a definite refusal (unknown to the node) and a
    /// chain mismatch persist `manual_resend` so no automatic re-broadcast follows the failure
    /// the dApp was told about — not even after a restart.
    #[must_use]
    pub const fn transition(self, tx_hash: [u8; 32], at_unix_ms: u64) -> Option<Transition> {
        match self {
            Self::Sent | Self::Rejected { known: true } | Self::Unconfirmed { known: true } => {
                Some(Transition::Broadcast {
                    tx_hash,
                    at_unix_ms,
                })
            }
            Self::HashMismatch => Some(Transition::HashMismatch {
                tx_hash,
                at_unix_ms,
            }),
            Self::Rejected { known: false } | Self::ChainMismatch => {
                Some(Transition::ManualResend {
                    tx_hash,
                    at_unix_ms,
                })
            }
            Self::Unconfirmed { known: false } | Self::ChainUnverified => None,
        }
    }

    /// Whether an automatic re-broadcast follows this outcome (§5.4-2). Only then may the dApp be
    /// given the hash of a transaction the node does not know yet; otherwise it is told the
    /// broadcast failed (spec/05 §5 `BroadcastFailed`).
    #[must_use]
    pub const fn resends_automatically(self) -> bool {
        matches!(
            self,
            Self::Unconfirmed { known: false } | Self::ChainUnverified
        )
    }

    /// Fixed name for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sent => "Sent",
            Self::HashMismatch => "HashMismatch",
            Self::Rejected { known: true } => "RejectedKnown",
            Self::Rejected { known: false } => "Rejected",
            Self::Unconfirmed { known: true } => "UnconfirmedKnown",
            Self::Unconfirmed { known: false } => "Unconfirmed",
            Self::ChainMismatch => "ChainMismatch",
            Self::ChainUnverified => "ChainUnverified",
        }
    }
}

const fn is_transport(failure: RpcFailure) -> bool {
    matches!(
        failure,
        RpcFailure::Http(_) | RpcFailure::Late | RpcFailure::Status(_)
    )
}

/// Sends the signed bytes (spec/03 §4.4); see [`broadcast_checked`].
#[must_use]
pub fn broadcast(
    transport: &SharedTransport,
    url: &HttpsUrl,
    chain: &ChainInfo,
    raw: &[u8],
    tx_hash: &[u8; 32],
    clock: &dyn Clock,
    limits: &Limits,
) -> BroadcastOutcome {
    broadcast_checked(transport, url, chain, raw, tx_hash, clock, limits).0
}

/// Sends the signed bytes (spec/03 §4.4) after the full chain re-check of this connection
/// (spec/03 §1.4, D14: `eth_chainId` and the block-0 hash against the genesis rule, every
/// broadcast regardless of any cached state; transport failures retried `retry_delay_ms` apart)
/// — a mismatch sends nothing (`ChainMismatch`), an unverifiable chain sends nothing
/// (`ChainUnverified`, re-sent by tracking). Then `eth_sendRawTransaction`; transport errors
/// resend the same bytes after `broadcast_retry_ms[0]` and `[1]` and then ask
/// `eth_getTransactionByHash`. Returns the outcome and the chain check made.
#[must_use]
pub fn broadcast_checked(
    transport: &SharedTransport,
    url: &HttpsUrl,
    chain: &ChainInfo,
    raw: &[u8],
    tx_hash: &[u8; 32],
    clock: &dyn Clock,
    limits: &Limits,
) -> (BroadcastOutcome, ChainCheck) {
    let client = RpcClient::new(&**transport);
    let check = check_chain(&client, url, chain, clock, limits.retry_delay_ms);
    let outcome = match check {
        ChainCheck::Verified { .. } => {
            send_raw_with_retries(&client, url, raw, tx_hash, clock, limits.broadcast_retry_ms)
        }
        ChainCheck::Mismatch(_) => BroadcastOutcome::ChainMismatch,
        ChainCheck::Unverified(_) => BroadcastOutcome::ChainUnverified,
    };
    (outcome, check)
}

fn send_raw_with_retries(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    raw: &[u8],
    tx_hash: &[u8; 32],
    clock: &dyn Clock,
    retry_ms: [u64; 2],
) -> BroadcastOutcome {
    let known = || rpc::transaction_known(client, url, tx_hash).unwrap_or(false);
    match rpc::send_raw(client, url, raw) {
        Ok(hash) if hash == *tx_hash => return BroadcastOutcome::Sent,
        Ok(_) => return BroadcastOutcome::HashMismatch,
        Err(RpcFailure::Rpc(_)) => return BroadcastOutcome::Rejected { known: known() },
        Err(_) => {}
    }
    for delay in retry_ms {
        clock.sleep_ms(delay);
        match rpc::send_raw(client, url, raw) {
            Ok(hash) if hash == *tx_hash => return BroadcastOutcome::Sent,
            Ok(_) => return BroadcastOutcome::HashMismatch,
            Err(failure) if !is_transport(failure) => break,
            Err(_) => {}
        }
    }
    BroadcastOutcome::Unconfirmed { known: known() }
}

/// Tracking input for one nonce group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackInput {
    /// All records of the group.
    pub group: Vec<EvmRecord>,
    /// First `latest nonce > nonce` observation (in memory, §5.2 drop rule).
    pub drop_seen_unix_ms: Option<u64>,
    /// Now.
    pub now_unix_ms: u64,
    /// Re-broadcast allowed (§5.4-2; off while the user sees a manual resend choice).
    pub allow_rebroadcast: bool,
}

/// Tracking result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrackResult {
    /// Transitions to commit.
    pub transitions: Vec<Transition>,
    /// Updated drop observation.
    pub drop_seen_unix_ms: Option<u64>,
    /// An RPC failure stopped this round (retried next round).
    pub error: Option<ErrorCode>,
    /// Receipts that failed the §4.5 checks (logged).
    pub invalid_receipts: u32,
    /// The latest candidate was re-sent.
    pub rebroadcast: bool,
    /// The chain re-check right before a re-broadcast found another chain (nothing was sent;
    /// the worker blocks the chain, spec/03 §1.4 `RpcMismatch`).
    pub chain_mismatch: Option<MismatchKind>,
}

fn finality(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    record: &EvmRecord,
    now: u64,
) -> Result<Option<Transition>, RpcFailure> {
    let finalized = match rpc::block_by_tag(client, url, "finalized") {
        Ok(block) => block.map(|block| block.number),
        Err(RpcFailure::Rpc(_)) => {
            Some(rpc::block_number(client, url)?.saturating_sub(FALLBACK_CONFIRMATIONS))
        }
        Err(failure) => return Err(failure),
    };
    if finalized.is_none_or(|number| number < record.included_block_number) {
        return Ok(None);
    }
    let block = rpc::block_by_tag(
        client,
        url,
        &canonical_quantity(record.included_block_number),
    )?;
    Ok(Some(match block {
        Some(block) if block.hash == record.included_block_hash => Transition::Finalized {
            tx_hash: record.tx_hash,
            at_unix_ms: now,
        },
        _ => Transition::Reorged {
            tx_hash: record.tx_hash,
            at_unix_ms: now,
        },
    }))
}

fn receipts(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    open: &[&EvmRecord],
    now: u64,
    result: &mut TrackResult,
) -> Result<bool, RpcFailure> {
    for record in open {
        match rpc::receipt(client, url, &record.tx_hash, &record.account)? {
            ReceiptLookup::Valid(receipt) => {
                result.transitions.push(Transition::Included {
                    tx_hash: record.tx_hash,
                    block_number: receipt.block_number,
                    block_hash: receipt.block_hash,
                    success: receipt.success,
                    at_unix_ms: now,
                });
                return Ok(true);
            }
            ReceiptLookup::Invalid => {
                result.invalid_receipts = result.invalid_receipts.saturating_add(1);
            }
            ReceiptLookup::None => {}
        }
    }
    Ok(false)
}

fn rebroadcast(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    chain: &ChainInfo,
    latest: &EvmRecord,
    now: u64,
    result: &mut TrackResult,
) -> Result<(), RpcFailure> {
    let known = rpc::transaction_known(client, url, &latest.tx_hash)?;
    if known {
        if latest.state == TxState::Signed {
            result.transitions.push(Transition::Broadcast {
                tx_hash: latest.tx_hash,
                at_unix_ms: now,
            });
        }
        return Ok(());
    }
    if latest.has_flag(FLAG_RPC_HASH_MISMATCH)
        || latest.has_flag(FLAG_MANUAL_RESEND)
        || now.saturating_sub(latest.last_broadcast_unix_ms) < REBROADCAST_INTERVAL_MS
    {
        return Ok(());
    }
    // spec/03 §1.4, D14: chain id and genesis again on this connection right before
    // `eth_sendRawTransaction` (a transport failure ends the round; the next one retries).
    if let ChainCheck::Mismatch(kind) = check_once(client, url, chain)? {
        result.chain_mismatch = Some(kind);
        return Ok(());
    }
    result.rebroadcast = true;
    result.transitions.push(Transition::Rebroadcast {
        tx_hash: latest.tx_hash,
        at_unix_ms: now,
    });
    match rpc::send_raw(client, url, &latest.raw) {
        Ok(hash) if hash == latest.tx_hash => {
            result.transitions.push(Transition::Broadcast {
                tx_hash: latest.tx_hash,
                at_unix_ms: now,
            });
        }
        Ok(_) => result.transitions.push(Transition::HashMismatch {
            tx_hash: latest.tx_hash,
            at_unix_ms: now,
        }),
        Err(_) => {}
    }
    Ok(())
}

fn track_inner(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    chain: &ChainInfo,
    input: &TrackInput,
    result: &mut TrackResult,
) -> Result<(), RpcFailure> {
    let now = input.now_unix_ms;
    let members: Vec<&EvmRecord> = input.group.iter().collect();
    if let Some(included) = members
        .iter()
        .find(|record| record.state == TxState::Included)
    {
        if let Some(transition) = finality(client, url, included, now)? {
            result.transitions.push(transition);
        }
        return Ok(());
    }
    let open: Vec<&EvmRecord> = members
        .iter()
        .copied()
        .filter(|record| matches!(record.state, TxState::Signed | TxState::Broadcast))
        .collect();
    let Some(first) = open.first() else {
        return Ok(());
    };
    let key = first.key();
    if receipts(client, url, &open, now, result)? {
        result.drop_seen_unix_ms = None;
        return Ok(());
    }
    let latest_nonce = rpc::transaction_count(client, url, &key.account, "latest")?;
    if latest_nonce > key.nonce {
        match input.drop_seen_unix_ms {
            Some(seen) if now.saturating_sub(seen) >= DROP_CONFIRM_MS => {
                result.transitions.push(Transition::Dropped {
                    key,
                    at_unix_ms: now,
                });
                result.drop_seen_unix_ms = None;
            }
            Some(seen) => result.drop_seen_unix_ms = Some(seen),
            None => result.drop_seen_unix_ms = Some(now),
        }
        return Ok(());
    }
    result.drop_seen_unix_ms = None;
    if latest_nonce == key.nonce
        && input.allow_rebroadcast
        && let Some(latest) = latest_candidate(&open)
    {
        rebroadcast(client, url, chain, latest, now, result)?;
    }
    Ok(())
}

/// One tracking round for a nonce group (spec/03 §4.5 receipts and finality, §5.2 drop rule,
/// §5.4 reconcile with the re-broadcast of the newest candidate at most once per 60 s, never for
/// `rpc_hash_mismatch` or `manual_resend`, and only after the chain re-check of `chain`).
#[must_use]
pub fn track_group(
    transport: &SharedTransport,
    url: &HttpsUrl,
    chain: &ChainInfo,
    input: &TrackInput,
) -> TrackResult {
    let client = RpcClient::new(&**transport);
    let mut result = TrackResult {
        drop_seen_unix_ms: input.drop_seen_unix_ms,
        ..TrackResult::default()
    };
    if let Err(failure) = track_inner(&client, url, chain, input, &mut result) {
        result.error = Some(classify(failure));
    }
    result
}

/// Polling interval for a group (spec/03 §4.5): 4 s for the first 120 s after the last
/// broadcast, then 15 s; 60 s while waiting for finality.
#[must_use]
pub fn poll_interval_ms(group: &[EvmRecord], now_unix_ms: u64) -> u64 {
    if group.iter().any(|record| record.state == TxState::Included) {
        return 60_000;
    }
    let last = group
        .iter()
        .map(|record| record.last_broadcast_unix_ms.max(record.created_unix_ms))
        .max()
        .unwrap_or(0);
    if now_unix_ms.saturating_sub(last) <= 120_000 {
        4_000
    } else {
        15_000
    }
}
