//! Solana dApp transactions on the UI thread (spec/07 §20, spec/05 §3.6): the refusals of a
//! granted request before its window (no endpoint, too many pending sends), the RPC preview and
//! the approval draft built from it, and the hand-off of an approved request to the key worker.
//! A sign-only request goes the chain-message route (`SignChainMessage(Card)`, answered by
//! `browser_chain_message_signed` after the grant re-check). A send runs the pre-sign RPC check
//! (`RpcJob::SolDappPreSign`), then `SignSolDapp(Card)` journals it first (version 3), the
//! broadcast loop sends it and the dApp gets the transaction id after the first round. The
//! wallet never builds or changes these transactions; the core signs the exact approved bytes
//! in our slot.

use yw_core::approval::{ApprovalDraft, Approved, SigningPayload};
use yw_core::journal::sol::{
    SOL_DAPP_MAX_PENDING, SOL_DAPP_MAX_PENDING_TOTAL, SolRecord, SolTxState, pending_dapp_count,
    pending_dapp_total,
};
use yw_core::policy::{BrowserOrigin, ProviderError};
use yw_core::sol::broadcast::Outcome;
use yw_core::sol::dapp::{
    PreSignCheck, SolTxMode, SolTxRequest, SolTxSignError, build_sol_tx_request, parse_wire_tx,
};
use yw_core::sol::{SolAddress, SolCluster};
use yw_json::Value;

use crate::app::{App, AppMode};
use crate::app_browser::SignWaiter;
use crate::app_card::{CardJobKind, PinBuffer};
use crate::app_chain_sites::ChainAnswer;
use crate::app_evm::QueuedItem;
use crate::app_sol::SolTrackState;
use crate::browser::{Reply, SiteKind, SiteRequest};
use crate::errors::ErrorCode;
use crate::events::{KeyJob, SignTicket, SolDappSigned, SolSignFailure};
use crate::logging::{self, Field};
use crate::sol::flow::{DappPreview, DappPreviewJob, PreSignError, TrackResult};
use crate::text::{json_object, json_str};
use crate::workers::rpc::RpcJob;

/// An approved dApp send waiting for its pre-sign check (spec/07 §20.10-2).
#[derive(Debug)]
pub struct PendingDappSign {
    /// The waiter that answers it.
    pub ticket: SignTicket,
    /// The one-time approval.
    pub approved: Box<Approved>,
    /// The `YubiKey` PIN of a card send: moved into `SignSolDappCard` with the check, wiped
    /// with this entry otherwise.
    pub pin: Option<PinBuffer>,
    /// The requesting site (journal version 3 origin).
    pub origin: String,
}

/// A journaled dApp send whose answer waits for the first broadcast round (spec/07 §20.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolBroadcast {
    /// Who gets the answer.
    pub reply: Reply,
    /// Our signing account (`publicKey` of the answer; its grant is checked again).
    pub public: [u8; 32],
    /// The requesting site.
    pub origin: BrowserOrigin,
    /// `minContextSlot` of the dApp's options: the first send only.
    pub min_context_slot: Option<u64>,
}

/// The answer of `sol_signAndSendTransaction` (spec/05 §3.6): `{publicKey, signature}` with the
/// transaction id (signature 0, the fee payer's) in lowercase hex.
#[must_use]
pub fn sol_send_answer(public: &[u8; 32], tx_id: &[u8; 64]) -> Value {
    json_object(vec![
        (
            "publicKey",
            json_str(&yw_core::codec::base58::base58_encode(public)),
        ),
        ("signature", json_str(&yw_core::hex::encode(tx_id))),
    ])
}

/// Whether the first broadcast round of a dApp send fails it for the dApp (-32603 `Transaction
/// broadcast failed.`, spec/05 §5): nothing will send it without a new request — the RPC points
/// to another cluster, a deterministic preflight error stopped the re-sends, the RPC answered
/// another signature, or expiry is proven. Everything else (sent, found, landed, failed on
/// chain, a transient lookup failure) is answered with the transaction id: the record is
/// journaled and the loop keeps sending it.
#[must_use]
pub fn sol_round_failed(result: &TrackResult) -> bool {
    result.genesis_ok == Some(false)
        || result.state.preflight_err.is_some()
        || result.state.anomaly
        || matches!(result.outcome, Ok(Outcome::Expired))
}

/// The S10 title of a journaled dApp send (spec/07 §20.9): "사이트 거래 진행 중 · origin" while
/// it is `Pending`, then "사이트 거래 · origin" as its activity row says; empty for a wallet send.
#[must_use]
pub fn dapp_record_title(record: &SolRecord) -> String {
    match &record.dapp {
        Some(dapp) if record.state == SolTxState::Pending => {
            format!("사이트 거래 진행 중 · {}", dapp.origin)
        }
        Some(dapp) => format!("사이트 거래 · {}", dapp.origin),
        None => String::new(),
    }
}

/// The reason of a failed pre-sign check, after "사이트 거래를 보내지 못했습니다: ".
fn presign_reason(error: PreSignError) -> String {
    match error {
        PreSignError::BlockhashExpired => {
            "거래의 블록해시가 만료되었습니다. 사이트에서 다시 요청하세요".to_owned()
        }
        PreSignError::TablesChanged => {
            "조회 테이블 주소가 승인한 값과 달라졌습니다. 서명하지 않았습니다".to_owned()
        }
        PreSignError::ClusterMismatch => ErrorCode::Rpc006.text(),
        PreSignError::RpcAnomaly => ErrorCode::Rpc005.text(),
        PreSignError::Rpc(code) => code.text(),
    }
}

/// The reason of a dApp send that was not signed or journaled, after "사이트 거래에 서명하지
/// 못했습니다: ".
fn sign_reason(failure: SolSignFailure) -> String {
    match failure {
        SolSignFailure::DappSign(SolTxSignError::Vault(error)) => {
            crate::errors::vault_code(error).text()
        }
        SolSignFailure::DappSign(error) => error.to_string(),
        SolSignFailure::DappCard(error) | SolSignFailure::Card(error) => error.to_string(),
        SolSignFailure::JournalFull => ErrorCode::Tx005.text(),
        SolSignFailure::JournalWrite(_) => ErrorCode::Vlt003.text(),
        SolSignFailure::Sign(_)
        | SolSignFailure::AlreadySigned
        | SolSignFailure::Locked
        | SolSignFailure::TooManyPending => ErrorCode::Tx003.text(),
    }
}

impl App {
    /// Why a granted dApp transaction request of `public` on `cluster` ends before its window
    /// (spec/05 §3.6): `cluster` is no longer the wallet's (-32602, Q16: switched while it
    /// waited), no endpoint for the cluster (4901; the preview needs RPC), or for a send the
    /// (cluster, signer) or whole-journal cap of pending dApp sends (-32002). `None`: open the
    /// window.
    pub(crate) fn sol_dapp_refusal(
        &self,
        public: &[u8; 32],
        cluster: SolCluster,
        mode: SolTxMode,
    ) -> Option<ProviderError> {
        if cluster != self.sol_cluster() {
            return Some(ProviderError::InvalidParams);
        }
        if self.sol_endpoint(cluster).is_err() {
            return Some(ProviderError::ChainUnavailable);
        }
        if mode == SolTxMode::SignAndSend {
            let records = self.sol_records();
            let signer = SolAddress::from_bytes(*public);
            if pending_dapp_count(&records, cluster, &signer) >= SOL_DAPP_MAX_PENDING
                || pending_dapp_total(&records) >= SOL_DAPP_MAX_PENDING_TOTAL
            {
                return Some(ProviderError::TransactionPending);
            }
        }
        None
    }

    /// The preview on the RPC worker (called by `prepare_site`, spec/07 §20.7).
    pub(crate) fn prepare_sol_dapp(&mut self, job: u64, site: &SiteRequest) {
        let SiteKind::SolTx {
            public,
            cluster,
            txs,
            ..
        } = &site.kind
        else {
            self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
            return;
        };
        // The request's cluster, never the one shown now: the preview facts, the draft and the
        // signature all belong to the cluster the dApp asked for.
        let endpoint = match self.sol_endpoint(*cluster) {
            Ok(endpoint) => endpoint,
            Err(code) => {
                self.show_failure(code, false, code.text());
                return;
            }
        };
        let sent = self.rpc(RpcJob::SolDappPreview(Box::new(DappPreviewJob {
            job,
            endpoint,
            wallet: SolAddress::from_bytes(*public),
            txs: txs.clone(),
        })));
        if !sent {
            self.show_failure(ErrorCode::Rpc001, true, ErrorCode::Rpc001.text());
        }
    }

    /// The preview of the shown request finished: its draft ([`Self::sol_dapp_draft`]) or the
    /// failure goes to the window.
    pub(crate) fn on_sol_dapp_previewed(
        &mut self,
        job: u64,
        result: Result<DappPreview, ErrorCode>,
    ) {
        let site = match self.evm.window.as_ref() {
            Some(window) if window.job() == job => match window.item() {
                QueuedItem::Site(site) => site.clone(),
                _ => return,
            },
            _ => return,
        };
        match self.sol_dapp_draft(&site, result) {
            Ok(draft) => self.show_ready_draft(draft, None),
            Err((code, retryable)) => self.show_failure(code, retryable, code.text()),
        }
    }

    /// The approval draft of the dApp transaction request `site` from its preview: the core
    /// builder with the address book, own accounts and the fee cap, on the request's cluster.
    /// Otherwise the window's failure `(code, retryable)`, never a draft without the preview (no
    /// X01): the wallet switched to another cluster since the request came (Q16) or a genesis
    /// mismatch is E-RPC-006, not retried; a transport error keeps its own code.
    pub(crate) fn sol_dapp_draft(
        &self,
        site: &SiteRequest,
        result: Result<DappPreview, ErrorCode>,
    ) -> Result<ApprovalDraft, (ErrorCode, bool)> {
        let SiteKind::SolTx {
            public,
            cluster,
            txs,
            mode,
            options,
            ..
        } = &site.kind
        else {
            return Err((ErrorCode::App009, false));
        };
        if *cluster != self.sol_cluster() {
            logging::warn("app", "sol.dapp_cluster_changed", &[]);
            return Err((ErrorCode::Rpc006, false));
        }
        let preview = result.map_err(|code| {
            logging::warn(
                "app",
                "sol.dapp_preview_failed",
                &[("code", Field::Code(code))],
            );
            (code, crate::sol::flow::retryable(code))
        })?;
        let row = self
            .sol_dapp_rows()
            .into_iter()
            .find(|row| row.public == *public)
            .ok_or((ErrorCode::App009, false))?;
        let id = Self::new_approval_id().map_err(|_| (ErrorCode::Vlt005, false))?;
        let request = SolTxRequest {
            id,
            origin: site.origin.clone(),
            cluster: *cluster,
            source: row.source,
            public: *public,
            label: row.label,
            mode: *mode,
            options: *options,
            txs: txs.clone(),
        };
        let facts = preview.into_facts(self.sol_known(), self.settings.solana.max_fee_lamports);
        build_sol_tx_request(&request, &facts).map_err(|_| (ErrorCode::App009, false))
    }

    /// An approved dApp transaction request (spec/07 §20.8): the waiter that answers it, then a
    /// sign-only request goes the chain-message route — a `YubiKey` account through its PIN
    /// (one touch per transaction), otherwise `SignChainMessage`; nothing is sent or journaled.
    /// A send goes to its pre-sign check — a `YubiKey` account after its PIN (the signing
    /// deadline starts at the check's answer, after the PIN).
    pub(crate) fn sol_dapp_consumed(&mut self, approved: Approved, site: &SiteRequest) {
        let (
            SiteKind::SolTx {
                public,
                cluster,
                batch,
                ..
            },
            SigningPayload::SolTx(payload),
        ) = (&site.kind, approved.payload())
        else {
            self.respond(&site.reply, Err(ProviderError::Internal));
            return;
        };
        let send = payload.mode == SolTxMode::SignAndSend;
        let cluster = *cluster;
        let answer = ChainAnswer::SolTx {
            public: *public,
            origin: site.origin.clone(),
            batch: *batch,
            send,
        };
        let ticket = self.push_sign_waiter(SignWaiter::Chain(site.reply, Box::new(answer)));
        if send {
            if let Err(approved) =
                self.card_begin(approved, CardJobKind::SolDappSend { cluster }, Some(ticket))
            {
                self.sol_dapp_presign(*approved, cluster, None, ticket);
            }
        } else if let Err(approved) =
            self.card_begin(approved, CardJobKind::ChainMessage, Some(ticket))
        {
            self.key(KeyJob::SignChainMessage { ticket, approved });
        }
    }

    /// The pre-sign check of an approved send (spec/07 §20.10-2) on the request's cluster:
    /// genesis, the transaction's blockhash still valid, its lookup tables re-resolved and
    /// `lastValidBlockHeight` bound. No endpoint answers 4901.
    pub(crate) fn sol_dapp_presign(
        &mut self,
        approved: Approved,
        cluster: SolCluster,
        pin: Option<PinBuffer>,
        ticket: SignTicket,
    ) {
        let origin = self
            .browser
            .as_ref()
            .and_then(|browser| match browser.waiters.get(&ticket) {
                Some(SignWaiter::Chain(_, answer)) => match &**answer {
                    ChainAnswer::SolTx {
                        origin, send: true, ..
                    } => Some(origin.as_str().to_owned()),
                    _ => None,
                },
                _ => None,
            });
        let Some(origin) = origin else {
            // Nobody waits for it any more: nothing is signed.
            self.card_abandon_dapp(ticket);
            return;
        };
        let message = match approved.payload() {
            SigningPayload::SolTx(payload) => payload
                .items
                .first()
                .and_then(|item| parse_wire_tx(&item.wire).ok())
                .map(|wire| wire.message),
            _ => None,
        };
        let Some(message) = message else {
            self.sol_dapp_send_failed(ticket, ProviderError::Internal, None);
            return;
        };
        let endpoint = match self.sol_endpoint(cluster) {
            Ok(endpoint) => endpoint,
            Err(code) => {
                self.sol_dapp_send_failed(
                    ticket,
                    ProviderError::ChainUnavailable,
                    Some(code.text()),
                );
                return;
            }
        };
        let job = self.sol.job();
        self.sol.dapp_presign.insert(
            job,
            PendingDappSign {
                ticket,
                approved: Box::new(approved),
                pin,
                origin,
            },
        );
        let sent = self.rpc(RpcJob::SolDappPreSign {
            job,
            endpoint,
            message: Box::new(message),
        });
        if !sent {
            self.sol.dapp_presign.remove(&job);
            self.sol_dapp_send_failed(
                ticket,
                ProviderError::Internal,
                Some(ErrorCode::Rpc001.text()),
            );
        }
    }

    /// The pre-sign check finished: the key worker signs and journals the send (the 20 s
    /// signing deadline runs from now), or the dApp gets -32603 `BroadcastFailed` with the
    /// reason in a band. A check whose entry is gone (the lock answered it) is dropped.
    pub(crate) fn on_sol_dapp_presigned(
        &mut self,
        job: u64,
        result: Result<(u64, PreSignCheck), PreSignError>,
    ) {
        let Some(pending) = self.sol.dapp_presign.remove(&job) else {
            return;
        };
        let PendingDappSign {
            ticket,
            approved,
            pin,
            origin,
        } = pending;
        match result {
            Ok((last_valid_block_height, check)) => {
                let consumed_at_ms = yw_win::time::monotonic_ms();
                let now_unix_ms = crate::app_sol::now_unix_ms();
                match pin {
                    Some(pin) => self.key(KeyJob::SignSolDappCard {
                        ticket,
                        approved,
                        consumed_at_ms,
                        now_unix_ms,
                        last_valid_block_height,
                        check,
                        origin,
                        pin: pin.into_inner(),
                    }),
                    None => self.key(KeyJob::SignSolDapp {
                        ticket,
                        approved,
                        consumed_at_ms,
                        now_unix_ms,
                        last_valid_block_height,
                        check,
                        origin,
                    }),
                }
            }
            Err(error) => {
                drop(approved);
                drop(pin);
                logging::warn(
                    "app",
                    "sol.dapp_presign_failed",
                    &[(
                        "reason",
                        Field::Word(match error {
                            PreSignError::Rpc(_) => "rpc",
                            PreSignError::ClusterMismatch => "cluster",
                            PreSignError::RpcAnomaly => "anomaly",
                            PreSignError::BlockhashExpired => "blockhash",
                            PreSignError::TablesChanged => "tables",
                        }),
                    )],
                );
                self.sol_dapp_send_failed(
                    ticket,
                    ProviderError::BroadcastFailed,
                    Some(presign_reason(error)),
                );
            }
        }
    }

    /// A dApp send ends before signing: its waiter gets `error`, a card step after the PIN
    /// ends, and `reason` (when given) goes to a band "사이트 거래를 보내지 못했습니다: …".
    fn sol_dapp_send_failed(
        &mut self,
        ticket: SignTicket,
        error: ProviderError,
        reason: Option<String>,
    ) {
        self.card_abandon_dapp(ticket);
        if let Some(SignWaiter::Chain(reply, _)) = self.take_sign_waiter(ticket) {
            self.respond(&reply, Err(error));
        }
        if let Some(reason) = reason {
            self.banner(None, format!("사이트 거래를 보내지 못했습니다: {reason}"));
        }
        self.refresh();
    }

    /// `SignSolDapp` finished (spec/07 §20.8). Journaled: the broadcast loop tracks the record and
    /// the dApp's answer waits for its first round — or comes now while locked (the loop resumes
    /// after unlock) or when the same transaction was approved before and has ended. Before the
    /// answer the origin's grant must still name the key (4100 otherwise; the transaction is
    /// journaled and still broadcast, spec/07 §20.10-4). A lock before signing answers 4001, the
    /// caps -32002, anything else -32603 with the reason in a band.
    pub(crate) fn on_sol_dapp_signed(&mut self, signed: SolDappSigned) {
        let SolDappSigned { ticket, result } = signed;
        if matches!(result, Err(SolSignFailure::Locked)) {
            self.browser_sign_cancelled(ticket);
            return;
        }
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        if let Ok(summary) = &result {
            logging::info(
                "app",
                "sol.dapp_signed",
                &[
                    (
                        "net",
                        Field::Net(crate::workers::journal::sol_network(summary.cluster)),
                    ),
                    (
                        "reused",
                        Field::Word(if summary.reused { "yes" } else { "no" }),
                    ),
                ],
            );
            if unlocked && !summary.reused {
                // Signed just now after the pre-sign genesis check.
                self.sol
                    .tracking
                    .entry(summary.tx_id)
                    .or_insert(SolTrackState {
                        next_ms: 0,
                        genesis_checked: true,
                        ..SolTrackState::default()
                    });
            }
        }
        let Some(SignWaiter::Chain(reply, answer)) = self.take_sign_waiter(ticket) else {
            return;
        };
        let ChainAnswer::SolTx {
            public,
            origin,
            send: true,
            ..
        } = *answer
        else {
            self.respond(&reply, Err(ProviderError::Internal));
            return;
        };
        match result {
            Ok(summary) => {
                if unlocked && !self.sol_grant_holds(&origin, &public) {
                    logging::info("browser", "sol_tx.grant_gone", &[]);
                    self.respond(&reply, Err(ProviderError::Unauthorized));
                    return;
                }
                // The same bytes approved before: answered now unless that record is still
                // pending and its loop runs (then with its next round).
                let running = self.sol_records().iter().any(|record| {
                    record.signature() == summary.tx_id && record.state == SolTxState::Pending
                }) && self
                    .sol
                    .tracking
                    .get(&summary.tx_id)
                    .is_some_and(|state| state.halt.is_none());
                if !unlocked || (summary.reused && !running) {
                    self.respond(&reply, Ok(sol_send_answer(&public, &summary.tx_id)));
                    return;
                }
                if let Some(browser) = self.browser.as_mut() {
                    browser
                        .sol_broadcasts
                        .entry(summary.tx_id)
                        .or_default()
                        .push(SolBroadcast {
                            reply,
                            public,
                            origin,
                            min_context_slot: summary.min_context_slot,
                        });
                }
                self.sol_tick_tracking(yw_win::time::monotonic_ms());
                self.refresh();
            }
            Err(SolSignFailure::TooManyPending) => {
                self.respond(&reply, Err(ProviderError::TransactionPending));
            }
            Err(failure) => {
                logging::warn("app", "sol.dapp_sign_failed", &[]);
                self.respond(&reply, Err(ProviderError::Internal));
                self.banner(
                    None,
                    format!(
                        "사이트 거래에 서명하지 못했습니다: {}",
                        sign_reason(failure)
                    ),
                );
                self.refresh();
            }
        }
    }

    /// `minContextSlot` for a send of the dApp record `signature`: only while its answer waits
    /// for the first round (spec/07 §20.8).
    pub(crate) fn sol_dapp_min_context_slot(&self, signature: &[u8; 64]) -> Option<u64> {
        self.browser
            .as_ref()?
            .sol_broadcasts
            .get(signature)?
            .iter()
            .filter_map(|broadcast| broadcast.min_context_slot)
            .max()
    }

    /// A broadcast round of a record finished: the dApp sends waiting for it are answered once
    /// ([`sol_round_failed`]: -32603, otherwise the transaction id while the grant still names
    /// the key, 4100 when it does not).
    pub(crate) fn browser_sol_broadcast(&mut self, result: &TrackResult) {
        let Some(waiting) = self
            .browser
            .as_mut()
            .and_then(|browser| browser.sol_broadcasts.remove(&result.signature))
        else {
            return;
        };
        let failed = sol_round_failed(result);
        for broadcast in waiting {
            let body = if failed {
                Err(ProviderError::BroadcastFailed)
            } else if self.sol_grant_holds(&broadcast.origin, &broadcast.public) {
                Ok(sol_send_answer(&broadcast.public, &result.signature))
            } else {
                Err(ProviderError::Unauthorized)
            };
            self.respond(&broadcast.reply, body);
        }
    }

    /// Lock (spec/07 §20.10-5, before the Solana state is cleared): a send still waiting for its
    /// pre-sign check gets 4001 (its approval and PIN are dropped, nothing signed); a journaled
    /// send waiting for its first round gets its transaction id now (the loop resumes from the
    /// journal after unlock; the grants are already put away by the lock, so none is checked).
    pub(crate) fn sol_dapp_lock(&mut self) {
        let tickets: Vec<SignTicket> = self
            .sol
            .dapp_presign
            .drain()
            .map(|(_, pending)| pending.ticket)
            .collect();
        for ticket in tickets {
            self.browser_sign_cancelled(ticket);
        }
        let waiting: Vec<([u8; 64], Vec<SolBroadcast>)> = self
            .browser
            .as_mut()
            .map(|browser| browser.sol_broadcasts.drain().collect())
            .unwrap_or_default();
        for (tx_id, list) in waiting {
            for broadcast in list {
                self.respond(
                    &broadcast.reply,
                    Ok(sol_send_answer(&broadcast.public, &tx_id)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use yw_core::journal::sol::{SolDappMeta, SolRecord, SolTxState};
    use yw_core::sol::broadcast::{LoopState, Outcome};

    use super::{dapp_record_title, sol_round_failed, sol_send_answer};
    use crate::errors::ErrorCode;
    use crate::sol::flow::TrackResult;

    fn round(
        state: LoopState,
        genesis_ok: Option<bool>,
        outcome: Result<Outcome, ErrorCode>,
    ) -> TrackResult {
        TrackResult {
            signature: [1; 64],
            state,
            outcome,
            genesis_ok,
            sends: 1,
            generation: 0,
        }
    }

    /// spec/05 §5: the first round fails a dApp send only when nothing will send it without a
    /// new request; a transient failure, a landing or an on-chain failure answer the id.
    #[test]
    fn only_a_round_that_ends_the_sends_fails_the_answer() {
        let pending = Ok(Outcome::Pending { notice: false });
        for (state, genesis, outcome, failed) in [
            (LoopState::default(), Some(true), pending, false),
            (LoopState::default(), None, Err(ErrorCode::Rpc002), false),
            (
                LoopState::default(),
                None,
                Ok(Outcome::Landed { slot: 9 }),
                false,
            ),
            (
                LoopState::default(),
                None,
                Ok(Outcome::FailedOnChain { slot: 9, err: 9 }),
                false,
            ),
            (
                LoopState::default(),
                Some(false),
                Err(ErrorCode::Rpc006),
                true,
            ),
            (LoopState::default(), None, Ok(Outcome::Expired), true),
            (
                LoopState {
                    preflight_err: Some(9),
                    stop_rebroadcast: true,
                    ..LoopState::default()
                },
                None,
                pending,
                true,
            ),
            (
                LoopState {
                    anomaly: true,
                    ..LoopState::default()
                },
                None,
                pending,
                true,
            ),
        ] {
            assert_eq!(
                sol_round_failed(&round(state, genesis, outcome)),
                failed,
                "{state:?} {genesis:?} {outcome:?}"
            );
        }
    }

    /// spec/05 §3.6: `{publicKey: base58, signature: hex(signature 0)}`.
    #[test]
    fn the_send_answer_is_the_key_and_the_transaction_id() {
        let value = sol_send_answer(&[0; 32], &[0xab; 64]);
        assert_eq!(
            String::from_utf8(yw_json::to_vec(&value)).unwrap(),
            format!(
                r#"{{"publicKey":"11111111111111111111111111111111","signature":"{}"}}"#,
                "ab".repeat(64)
            )
        );
    }

    /// spec/07 §20.9: S10 names the site of a dApp send ("진행 중" only while `Pending`).
    #[test]
    fn a_dapp_record_is_titled_by_its_site() {
        let mut record = SolRecord {
            state: SolTxState::Pending,
            cluster: yw_core::sol::SolCluster::Devnet,
            source: yw_core::slip10::SolKeySource::Standard(
                yw_core::bip32::path::AccountIndex::ZERO,
            ),
            intent_id: [0; 16],
            intent_hash: [0; 32],
            signed_at_ms: 1,
            last_valid_block_height: 1,
            terminal_slot: 0,
            terminal_err: 0,
            tx: vec![1; 66],
            dapp: Some(SolDappMeta {
                public: [1; 32],
                signer_slot: 0,
                flags: 1,
                origin: "https://app.example".to_owned(),
            }),
        };
        assert_eq!(
            dapp_record_title(&record),
            "사이트 거래 진행 중 · https://app.example"
        );
        record.state = SolTxState::Landed;
        assert_eq!(
            dapp_record_title(&record),
            "사이트 거래 · https://app.example"
        );
        record.dapp = None;
        assert_eq!(dapp_record_title(&record), "");
    }
}
