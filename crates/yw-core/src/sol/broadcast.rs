//! Broadcast-loop decisions (spec/07 §14.2–§14.3), pure: yw-app makes the RPC calls of one
//! round and passes what it observed and its clock readings (nothing here reads a clock). The
//! loop only ever re-sends the same signed bytes; there is no re-signing anywhere in it. The
//! configured RPC is trusted (spec.md §2.2): a `confirmed` (or `finalized`) status is final, and
//! one round proves expiry, in this order: a `getEpochInfo({commitment:"confirmed"})` view whose
//! block height is above `lastValidBlockHeight`, then a `null` history status answered at a
//! `context.slot` not behind that view's slot. There is no wall-clock or monotonic minimum and no
//! second round. Before that point the user may ask for an immediate re-send of the same bytes
//! ([`LoopState::send_now`]): one signature can land at most once.

/// Status poll period.
pub const SOL_POLL_INTERVAL_MS: u64 = 1_000;
/// Re-send / block-height period.
pub const SOL_REBROADCAST_INTERVAL_MS: u64 = 2_500;
/// "네트워크/RPC 확인 필요" notice after this long.
pub const SOL_PENDING_NOTICE_SECS: u64 = 120;

/// spec/07 §15.3 error codes.
pub mod err {
    /// `InsufficientFundsForFee`.
    pub const INSUFFICIENT_FUNDS_FOR_FEE: u16 = 1;
    /// `InsufficientFundsForRent`.
    pub const INSUFFICIENT_FUNDS_FOR_RENT: u16 = 2;
    /// `AccountNotFound`.
    pub const ACCOUNT_NOT_FOUND: u16 = 3;
    /// `InstructionError` in a System instruction.
    pub const SYSTEM_INSTRUCTION: u16 = 4;
    /// `InstructionError` in a Token/ATA instruction.
    pub const TOKEN_INSTRUCTION: u16 = 5;
    /// `ComputationalBudgetExceeded`.
    pub const COMPUTE_EXCEEDED: u16 = 6;
    /// `BlockhashNotFound` (transient).
    pub const BLOCKHASH_NOT_FOUND: u16 = 7;
    /// `AlreadyProcessed`.
    pub const ALREADY_PROCESSED: u16 = 8;
    /// Anything else.
    pub const OTHER: u16 = 0xFFFF;

    /// Codes 1–6: deterministic transaction errors (preflight stops re-sending).
    #[must_use]
    pub const fn is_deterministic(code: u16) -> bool {
        matches!(code, 1..=6)
    }

    /// Fixed Korean text of a code (never the RPC message).
    #[must_use]
    pub const fn text(code: u16) -> &'static str {
        match code {
            1 => "수수료를 낼 잔액이 부족합니다",
            2 => "rent 기준을 채우지 못했습니다",
            3 => "계정을 찾을 수 없습니다",
            4 => "System 명령이 실패했습니다",
            5 => "토큰 명령이 실패했습니다",
            6 => "계산 한도(CU)를 넘었습니다",
            7 => "블록해시를 찾을 수 없습니다(일시적)",
            8 => "이미 처리된 거래입니다",
            _ => "알 수 없는 거래 오류",
        }
    }
}

/// `getSignatureStatuses` value for the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigStatus {
    /// `null`.
    NotFound,
    /// `processed`: not final yet.
    Processing,
    /// `confirmed` or `finalized` (final for this wallet) with `err` classified (`None` =
    /// `err: null`).
    Confirmed {
        /// Slot.
        slot: u64,
        /// spec/07 §15.3 code.
        err: Option<u16>,
    },
}

/// What one `sendTransaction` returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendResult {
    /// Accepted; `matches` = the returned signature equals the local one.
    Accepted {
        /// Returned signature == local base58 signature.
        matches: bool,
    },
    /// Transport error, timeout or `BlockhashNotFound` and other transient preflight errors.
    Transient,
    /// A deterministic preflight transaction error (§15.3 codes 1–6).
    Deterministic(u16),
}

/// The pending transaction as journaled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingTx {
    /// Wall-clock Unix ms of signing.
    pub signed_at_ms: u64,
    /// `lastValidBlockHeight` of the blockhash.
    pub last_valid_block_height: u64,
}

/// In-memory loop state of one pending record (rebuilt after restart).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoopState {
    /// Monotonic ms of the last re-send/height round.
    pub last_round_ms: Option<u64>,
    /// Re-sending stopped after a deterministic preflight error (memory flag only).
    pub stop_rebroadcast: bool,
    /// The RPC returned another signature (`RpcAnomaly`, state unchanged).
    pub anomaly: bool,
    /// Last deterministic preflight error code shown.
    pub preflight_err: Option<u16>,
    /// Last status was `processed`.
    pub processing: bool,
}

impl LoopState {
    /// The user asked to re-send the same signed bytes now (spec/07 §14.3 "지금 다시 전송"):
    /// the next round sends before its status lookup, like the first round of a session, and a
    /// re-send stop after a deterministic preflight error is lifted. The bytes and signature are
    /// the journaled ones, so this can never pay twice.
    pub const fn send_now(&mut self) {
        self.last_round_ms = None;
        self.stop_rebroadcast = false;
        self.preflight_err = None;
    }
}

/// What the app should do this round after the status poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundPlan {
    /// Re-send the same bytes (`skipPreflight:false`, `maxRetries:0`).
    pub send: bool,
    /// Ask `getEpochInfo(confirmed)` (block height and slot of one view).
    pub height: bool,
}

/// Plans the rest of a round once `status` (history `false`) is known.
#[must_use]
pub fn plan(state: &LoopState, status: SigStatus, now_ms: u64) -> RoundPlan {
    let due = state
        .last_round_ms
        .is_none_or(|last| now_ms.saturating_sub(last) >= SOL_REBROADCAST_INTERVAL_MS);
    let not_found = status == SigStatus::NotFound;
    RoundPlan {
        send: due && not_found && !state.stop_rebroadcast,
        height: due && not_found,
    }
}

/// One `getEpochInfo({commitment:"confirmed"})` answer: the confirmed block height and slot of
/// the same RPC view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainView {
    /// `blockHeight`.
    pub block_height: u64,
    /// `absoluteSlot`.
    pub slot: u64,
}

/// `getSignatureStatuses([sig], {searchTransactionHistory:true})` with the slot it was answered
/// at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryView {
    /// The status.
    pub status: SigStatus,
    /// The response's `context.slot`.
    pub context_slot: u64,
}

/// Whether the history lookup is needed (confirmed height above `lastValidBlockHeight`).
#[must_use]
pub const fn wants_history(tx: &PendingTx, chain: Option<ChainView>) -> bool {
    match chain {
        Some(chain) => chain.block_height > tx.last_valid_block_height,
        None => false,
    }
}

/// Whether a new signature with a new blockhash may replace `tx` (spec/07 §14.3): only when
/// the RPC's confirmed block height is above `lastValidBlockHeight`. At or below it the old
/// transaction can still land, so only the same bytes may be re-sent.
#[must_use]
pub const fn may_resign(tx: &PendingTx, chain: ChainView) -> bool {
    chain.block_height > tx.last_valid_block_height
}

/// Everything observed in one round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// `getSignatureStatuses([sig], {searchTransactionHistory:false})`.
    pub status: SigStatus,
    /// `sendTransaction` result when sent this round.
    pub send: Option<SendResult>,
    /// `getEpochInfo(confirmed)` when asked and answered.
    pub chain: Option<ChainView>,
    /// The history lookup, when asked and answered.
    pub history: Option<HistoryView>,
}

/// The clock readings of one round (yw-app clocks; yw-core only compares them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundTimes {
    /// Monotonic ms now (the re-send period).
    pub now_ms: u64,
    /// Wall-clock Unix ms now (only for the "네트워크/RPC 확인 필요" notice; never part of the
    /// expiry proof).
    pub now_unix_ms: u64,
}

/// The outcome of a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Still pending; `notice` = show "네트워크/RPC 확인 필요".
    Pending {
        /// [`SOL_PENDING_NOTICE_SECS`] passed.
        notice: bool,
    },
    /// Confirmed, `err: null`.
    Landed {
        /// Slot.
        slot: u64,
    },
    /// Confirmed with an error (the fee was charged).
    FailedOnChain {
        /// Slot.
        slot: u64,
        /// spec/07 §15.3 code.
        err: u16,
    },
    /// Expiry proven: never sent (a new review and approval is needed to send again).
    Expired,
}

const fn terminal(status: SigStatus) -> Option<Outcome> {
    match status {
        SigStatus::Confirmed { slot, err: None } => Some(Outcome::Landed { slot }),
        SigStatus::Confirmed {
            slot,
            err: Some(err),
        } => Some(Outcome::FailedOnChain { slot, err }),
        SigStatus::NotFound | SigStatus::Processing => None,
    }
}

/// Records a re-send/height round at `now_ms` and what `sendTransaction` returned (also used
/// when the first send of a round happened before a status lookup that then failed).
pub fn note_round(state: &mut LoopState, send: Option<SendResult>, asked: bool, now_ms: u64) {
    if send.is_some() || asked {
        state.last_round_ms = Some(now_ms);
    }
    match send {
        Some(SendResult::Accepted { matches: false }) => state.anomaly = true,
        Some(SendResult::Deterministic(code)) => {
            state.stop_rebroadcast = true;
            state.preflight_err = Some(code);
        }
        Some(SendResult::Accepted { matches: true } | SendResult::Transient) | None => {}
    }
}

/// Whether one round proves expiry (spec/07 §14.3): the view's confirmed height is above
/// `lastValidBlockHeight` ([`may_resign`]), and the history status is `null` and was answered
/// at a `context.slot` not behind the view's slot (the same or a later RPC view). One such
/// round is enough; no clock is involved.
#[must_use]
pub fn expiry_round(tx: &PendingTx, chain: ChainView, history: Option<HistoryView>) -> bool {
    may_resign(tx, chain)
        && history.is_some_and(|history| {
            history.status == SigStatus::NotFound && history.context_slot >= chain.slot
        })
}

/// Decides a round (spec/07 §14.2 table, §14.3 expiry proof) and updates `state`.
pub fn decide(
    tx: &PendingTx,
    state: &mut LoopState,
    obs: &Observation,
    times: &RoundTimes,
) -> Outcome {
    if let Some(outcome) = terminal(obs.status) {
        return outcome;
    }
    state.processing = obs.status == SigStatus::Processing;
    note_round(state, obs.send, obs.chain.is_some(), times.now_ms);
    if obs.status == SigStatus::NotFound
        && let Some(chain) = obs.chain
    {
        if wants_history(tx, Some(chain))
            && let Some(history) = obs.history
        {
            if let Some(outcome) = terminal(history.status) {
                return outcome;
            }
            if history.status == SigStatus::Processing {
                state.processing = true;
            }
        }
        if expiry_round(tx, chain, obs.history) {
            return Outcome::Expired;
        }
    }
    Outcome::Pending {
        notice: times.now_unix_ms.saturating_sub(tx.signed_at_ms)
            >= SOL_PENDING_NOTICE_SECS.saturating_mul(1_000),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChainView, HistoryView, LoopState, Observation, Outcome, PendingTx, RoundTimes, SendResult,
        SigStatus, decide, expiry_round, may_resign, note_round, plan, wants_history,
    };

    const TX: PendingTx = PendingTx {
        signed_at_ms: 1_000_000,
        last_valid_block_height: 500,
    };
    const VIEW_SLOT: u64 = 9_000;

    fn obs(status: SigStatus) -> Observation {
        Observation {
            status,
            send: None,
            chain: None,
            history: None,
        }
    }

    const fn view(block_height: u64) -> ChainView {
        ChainView {
            block_height,
            slot: VIEW_SLOT,
        }
    }

    const fn history(status: SigStatus, context_slot: u64) -> HistoryView {
        HistoryView {
            status,
            context_slot,
        }
    }

    /// `wall` ms of wall clock and `mono` ms of monotonic clock since signing.
    const fn at(wall: u64, mono: u64) -> RoundTimes {
        RoundTimes {
            now_ms: mono,
            now_unix_ms: TX.signed_at_ms + wall,
        }
    }

    /// A round whose confirmed height is past `lastValidBlockHeight` with a `null` history.
    fn expiring() -> Observation {
        let mut round = obs(SigStatus::NotFound);
        round.chain = Some(view(501));
        round.history = Some(history(SigStatus::NotFound, VIEW_SLOT));
        round
    }

    #[test]
    fn confirmed_statuses_are_terminal() {
        let mut state = LoopState::default();
        assert_eq!(
            decide(
                &TX,
                &mut state,
                &obs(SigStatus::Confirmed { slot: 9, err: None }),
                &at(0, 0)
            ),
            Outcome::Landed { slot: 9 }
        );
        assert_eq!(
            decide(
                &TX,
                &mut state,
                &obs(SigStatus::Confirmed {
                    slot: 9,
                    err: Some(1)
                }),
                &at(0, 0)
            ),
            Outcome::FailedOnChain { slot: 9, err: 1 }
        );
        assert!(matches!(
            decide(&TX, &mut state, &obs(SigStatus::Processing), &at(0, 0)),
            Outcome::Pending { .. }
        ));
        assert!(state.processing);
        // processed: no re-send, no height.
        let p = plan(&state, SigStatus::Processing, 100_000);
        assert!(!p.send && !p.height);
    }

    #[test]
    fn one_round_past_lvbh_with_a_null_history_expires_at_once() {
        let ok = expiring();
        assert!(expiry_round(&TX, view(501), ok.history));
        // Height not above lvbh, a history answered behind the view, or no history: no proof.
        assert!(!expiry_round(&TX, view(500), ok.history));
        assert!(!may_resign(&TX, view(500)));
        assert!(may_resign(&TX, view(501)));
        assert!(!expiry_round(
            &TX,
            view(501),
            Some(history(SigStatus::NotFound, VIEW_SLOT - 1))
        ));
        assert!(!expiry_round(&TX, view(501), None));
        // The first such round expires the record: 1 s after signing, no second round, no clock.
        let mut state = LoopState::default();
        assert_eq!(
            decide(&TX, &mut state, &ok, &at(1_000, 1)),
            Outcome::Expired
        );
        // A wall clock behind the signing time does not matter either.
        let mut early = TX;
        early.signed_at_ms = u64::MAX;
        assert_eq!(
            decide(&early, &mut LoopState::default(), &ok, &at(0, 0)),
            Outcome::Expired
        );
        // Height at lvbh: never expired, whatever the history says.
        let mut state = LoopState::default();
        let mut low = ok;
        low.chain = Some(view(500));
        for _ in 0..3 {
            assert!(matches!(
                decide(&TX, &mut state, &low, &at(900_000, 900_000)),
                Outcome::Pending { notice: true }
            ));
        }
        assert!(!wants_history(&TX, Some(view(500))));
        assert!(wants_history(&TX, Some(view(501))));
        // A late landing found by the history search wins (any context slot).
        let mut late = ok;
        late.history = Some(history(SigStatus::Confirmed { slot: 7, err: None }, 0));
        assert_eq!(
            decide(&TX, &mut state, &late, &at(900_000, 900_000)),
            Outcome::Landed { slot: 7 }
        );
        late.history = None;
        assert!(matches!(
            decide(&TX, &mut state, &late, &at(900_000, 900_000)),
            Outcome::Pending { .. }
        ));
    }

    #[test]
    fn send_now_resends_the_same_bytes_at_once() {
        // A round just happened: the next send would wait for the 2.5 s period.
        let mut state = LoopState::default();
        note_round(&mut state, Some(SendResult::Deterministic(1)), true, 10_000);
        assert!(!plan(&state, SigStatus::NotFound, 10_001).send);
        state.send_now();
        assert_eq!(state.last_round_ms, None);
        assert!(!state.stop_rebroadcast);
        assert_eq!(state.preflight_err, None);
        assert!(plan(&state, SigStatus::NotFound, 10_001).send);
    }

    #[test]
    fn preflight_and_anomaly_flags() {
        let mut state = LoopState::default();
        let mut round = obs(SigStatus::NotFound);
        round.send = Some(SendResult::Deterministic(1));
        round.chain = Some(view(10));
        let _ = decide(&TX, &mut state, &round, &at(0, 5_000));
        assert!(state.stop_rebroadcast);
        assert_eq!(state.preflight_err, Some(1));
        let p = plan(&state, SigStatus::NotFound, 7_500);
        assert!(
            !p.send && p.height,
            "height keeps being checked for the expiry proof"
        );
        let mut other = LoopState::default();
        round.send = Some(SendResult::Accepted { matches: false });
        let _ = decide(&TX, &mut other, &round, &at(0, 0));
        assert!(other.anomaly && !other.stop_rebroadcast);
        // Transient errors keep re-sending, every 2.5 s.
        let mut transient = LoopState::default();
        assert!(plan(&transient, SigStatus::NotFound, 0).send);
        round.send = Some(SendResult::Transient);
        let _ = decide(&TX, &mut transient, &round, &at(0, 1_000));
        assert!(!plan(&transient, SigStatus::NotFound, 3_499).send);
        assert!(plan(&transient, SigStatus::NotFound, 3_500).send);
        // A send recorded on its own (status lookup failed after it) keeps the same period.
        let mut early = LoopState::default();
        note_round(&mut early, Some(SendResult::Deterministic(2)), false, 4_000);
        assert_eq!(early.last_round_ms, Some(4_000));
        assert!(early.stop_rebroadcast);
        assert_eq!(early.preflight_err, Some(2));
    }
}
