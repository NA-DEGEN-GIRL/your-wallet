//! Broadcast-loop decisions (spec/07 §14.2–§14.3), pure: yw-app makes the RPC calls of one
//! round and passes what it observed and its clock readings (elapsed values are inputs; nothing
//! here reads a clock). The loop only ever re-sends the same signed bytes; there is no re-signing
//! anywhere in it. An expiry round needs, in this order, one `getEpochInfo` view whose finalized
//! block height is above `lastValidBlockHeight`, then a `null` history status answered at a
//! `context.slot` not behind that view's slot, and at least [`SOL_EXPIRY_MIN_WALL_SECS`] of both
//! the local wall clock since signing and the monotonic clock of this session. `Expired` needs
//! [`SOL_EXPIRY_ROUNDS`] such rounds in a row (separate RPC observations).

/// Status poll period.
pub const SOL_POLL_INTERVAL_MS: u64 = 1_000;
/// Re-send / block-height period.
pub const SOL_REBROADCAST_INTERVAL_MS: u64 = 2_500;
/// Local wall-clock minimum before `Expired` (≈ 3 × 150 blocks × 200 ms); the monotonic clock
/// must show the same minimum.
pub const SOL_EXPIRY_MIN_WALL_SECS: u64 = 90;
/// Consecutive height rounds that must each satisfy the whole expiry proof.
pub const SOL_EXPIRY_ROUNDS: u8 = 2;
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
    /// `processed` / `confirmed`: not success yet.
    Processing,
    /// `finalized` with `err` classified (`None` = `err: null`).
    Finalized {
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
    /// Last status was `processed`/`confirmed`.
    pub processing: bool,
    /// Height rounds in a row that satisfied the whole expiry proof (reset by any other height
    /// round or a non-`null` status).
    pub expiry_rounds: u8,
}

/// What the app should do this round after the status poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundPlan {
    /// Re-send the same bytes (`skipPreflight:false`, `maxRetries:0`).
    pub send: bool,
    /// Ask `getEpochInfo(finalized)` (block height and slot of one view).
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

/// One `getEpochInfo({commitment:"finalized"})` answer: the finalized block height and slot of
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

/// Whether the history lookup is needed (finalized height above `lastValidBlockHeight`).
#[must_use]
pub const fn wants_history(tx: &PendingTx, chain: Option<ChainView>) -> bool {
    match chain {
        Some(chain) => chain.block_height > tx.last_valid_block_height,
        None => false,
    }
}

/// Everything observed in one round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// `getSignatureStatuses([sig], {searchTransactionHistory:false})`.
    pub status: SigStatus,
    /// `sendTransaction` result when sent this round.
    pub send: Option<SendResult>,
    /// `getEpochInfo(finalized)` when asked and answered.
    pub chain: Option<ChainView>,
    /// The history lookup, when asked and answered.
    pub history: Option<HistoryView>,
}

/// The clock readings of one round (yw-app clocks; yw-core only compares them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundTimes {
    /// Monotonic ms now (the re-send period).
    pub now_ms: u64,
    /// Wall-clock Unix ms now (compared with the journal's `signed_at_ms`, spec.md §2.2).
    pub now_unix_ms: u64,
    /// Monotonic ms since the record was signed in this session, or since its loop resumed
    /// (start, unlock): a wall clock that jumps forward cannot shorten it.
    pub mono_elapsed: u64,
}

/// The outcome of a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Still pending; `notice` = show "네트워크/RPC 확인 필요".
    Pending {
        /// [`SOL_PENDING_NOTICE_SECS`] passed.
        notice: bool,
    },
    /// Finalized, `err: null`.
    Landed {
        /// Slot.
        slot: u64,
    },
    /// Finalized with an error (the fee was charged).
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
        SigStatus::Finalized { slot, err: None } => Some(Outcome::Landed { slot }),
        SigStatus::Finalized {
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

/// Whether one round satisfies the whole expiry proof (spec/07 §14.3): the view's finalized
/// height is above `lastValidBlockHeight`; the history status is `null` and was answered at a
/// `context.slot` not behind the view's slot (the same or a later RPC view); and both the wall
/// clock since signing and the monotonic clock show [`SOL_EXPIRY_MIN_WALL_SECS`].
#[must_use]
pub fn expiry_round(
    tx: &PendingTx,
    chain: ChainView,
    history: Option<HistoryView>,
    times: &RoundTimes,
) -> bool {
    let minimum = SOL_EXPIRY_MIN_WALL_SECS.saturating_mul(1_000);
    chain.block_height > tx.last_valid_block_height
        && history.is_some_and(|history| {
            history.status == SigStatus::NotFound && history.context_slot >= chain.slot
        })
        && times.now_unix_ms.saturating_sub(tx.signed_at_ms) >= minimum
        && times.mono_elapsed >= minimum
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
    if obs.status != SigStatus::NotFound {
        state.expiry_rounds = 0;
    }
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
        if expiry_round(tx, chain, obs.history, times) {
            state.expiry_rounds = state.expiry_rounds.saturating_add(1);
            if state.expiry_rounds >= SOL_EXPIRY_ROUNDS {
                return Outcome::Expired;
            }
        } else {
            state.expiry_rounds = 0;
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
        SigStatus, decide, expiry_round, note_round, plan, wants_history,
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
            mono_elapsed: mono,
        }
    }

    /// A round where everything satisfies the expiry proof 90 s after signing.
    fn expiring() -> Observation {
        let mut round = obs(SigStatus::NotFound);
        round.chain = Some(view(501));
        round.history = Some(history(SigStatus::NotFound, VIEW_SLOT));
        round
    }

    #[test]
    fn finalized_statuses_are_terminal() {
        let mut state = LoopState::default();
        assert_eq!(
            decide(
                &TX,
                &mut state,
                &obs(SigStatus::Finalized { slot: 9, err: None }),
                &at(0, 0)
            ),
            Outcome::Landed { slot: 9 }
        );
        assert_eq!(
            decide(
                &TX,
                &mut state,
                &obs(SigStatus::Finalized {
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
        // processed/confirmed: no re-send, no height.
        let p = plan(&state, SigStatus::Processing, 100_000);
        assert!(!p.send && !p.height);
    }

    #[test]
    fn expiry_needs_two_rounds_of_one_view_history_and_both_clocks() {
        // Each condition alone keeps the round from counting.
        let times = at(90_000, 90_000);
        let ok = expiring();
        assert!(expiry_round(&TX, ok.chain.unwrap(), ok.history, &times));
        assert!(!expiry_round(&TX, view(500), ok.history, &times));
        assert!(!expiry_round(
            &TX,
            view(501),
            Some(history(SigStatus::NotFound, VIEW_SLOT - 1)),
            &times
        ));
        assert!(!expiry_round(&TX, view(501), None, &times));
        assert!(!expiry_round(
            &TX,
            view(501),
            ok.history,
            &at(89_999, 90_000)
        ));
        assert!(!expiry_round(
            &TX,
            view(501),
            ok.history,
            &at(90_000, 89_999)
        ));
        // A wall clock moved forward by a day does not replace the monotonic minimum.
        assert!(!expiry_round(
            &TX,
            view(501),
            ok.history,
            &at(86_400_000, 1_000)
        ));
        // Two height rounds in a row are needed.
        let mut state = LoopState::default();
        assert!(matches!(
            decide(&TX, &mut state, &ok, &at(90_000, 90_000)),
            Outcome::Pending { .. }
        ));
        assert_eq!(state.expiry_rounds, 1);
        // A round without a height lookup neither counts nor resets.
        assert!(matches!(
            decide(
                &TX,
                &mut state,
                &obs(SigStatus::NotFound),
                &at(91_000, 91_000)
            ),
            Outcome::Pending { .. }
        ));
        assert_eq!(state.expiry_rounds, 1);
        assert_eq!(
            decide(&TX, &mut state, &ok, &at(92_500, 92_500)),
            Outcome::Expired
        );
        // A failing height round in between starts over.
        let mut state = LoopState::default();
        let _ = decide(&TX, &mut state, &ok, &at(90_000, 90_000));
        let mut behind = ok;
        behind.history = Some(history(SigStatus::NotFound, VIEW_SLOT - 1));
        let _ = decide(&TX, &mut state, &behind, &at(92_500, 92_500));
        assert_eq!(state.expiry_rounds, 0);
        assert!(matches!(
            decide(&TX, &mut state, &ok, &at(95_000, 95_000)),
            Outcome::Pending { .. }
        ));
        assert_eq!(
            decide(&TX, &mut state, &ok, &at(97_500, 97_500)),
            Outcome::Expired
        );
        // A non-null status resets the count.
        let mut state = LoopState::default();
        let _ = decide(&TX, &mut state, &ok, &at(90_000, 90_000));
        let _ = decide(
            &TX,
            &mut state,
            &obs(SigStatus::Processing),
            &at(91_000, 91_000),
        );
        assert_eq!(state.expiry_rounds, 0);
        // Height not above lvbh: never expired, whatever the history says.
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
        late.history = Some(history(SigStatus::Finalized { slot: 7, err: None }, 0));
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
