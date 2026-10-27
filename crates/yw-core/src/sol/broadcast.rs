//! Broadcast-loop decisions (spec/07 §14.2–§14.3), pure: yw-app makes the RPC calls of one
//! round and passes what it observed. The loop only ever re-sends the same signed bytes; there is
//! no re-signing anywhere in it. `Expired` needs, in one round and in this order, a finalized
//! block height above `lastValidBlockHeight`, then a `null` history status, and at least
//! [`SOL_EXPIRY_MIN_WALL_SECS`] of local wall clock since signing.

/// Status poll period.
pub const SOL_POLL_INTERVAL_MS: u64 = 1_000;
/// Re-send / block-height period.
pub const SOL_REBROADCAST_INTERVAL_MS: u64 = 2_500;
/// Local wall-clock minimum before `Expired` (≈ 3 × 150 blocks × 200 ms).
pub const SOL_EXPIRY_MIN_WALL_SECS: u64 = 90;
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
}

/// What the app should do this round after the status poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundPlan {
    /// Re-send the same bytes (`skipPreflight:false`, `maxRetries:0`).
    pub send: bool,
    /// Ask `getBlockHeight(finalized)`.
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

/// Whether the history lookup is needed (finalized height above `lastValidBlockHeight`).
#[must_use]
pub const fn wants_history(tx: &PendingTx, height: Option<u64>) -> bool {
    match height {
        Some(height) => height > tx.last_valid_block_height,
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
    /// `getBlockHeight(finalized)` when asked and answered.
    pub height: Option<u64>,
    /// `getSignatureStatuses([sig], {searchTransactionHistory:true})` when asked and answered.
    pub history: Option<SigStatus>,
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

/// Decides a round (spec/07 §14.2 table, §14.3 expiry proof) and updates `state`.
pub fn decide(
    tx: &PendingTx,
    state: &mut LoopState,
    obs: &Observation,
    now_ms: u64,
    now_unix_ms: u64,
) -> Outcome {
    if let Some(outcome) = terminal(obs.status) {
        return outcome;
    }
    state.processing = obs.status == SigStatus::Processing;
    if obs.send.is_some() || obs.height.is_some() {
        state.last_round_ms = Some(now_ms);
    }
    match obs.send {
        Some(SendResult::Accepted { matches: false }) => state.anomaly = true,
        Some(SendResult::Deterministic(code)) => {
            state.stop_rebroadcast = true;
            state.preflight_err = Some(code);
        }
        Some(SendResult::Accepted { matches: true } | SendResult::Transient) | None => {}
    }
    if obs.status == SigStatus::NotFound
        && wants_history(tx, obs.height)
        && let Some(history) = obs.history
    {
        if let Some(outcome) = terminal(history) {
            return outcome;
        }
        let waited = now_unix_ms.saturating_sub(tx.signed_at_ms);
        if history == SigStatus::NotFound
            && waited >= SOL_EXPIRY_MIN_WALL_SECS.saturating_mul(1_000)
        {
            return Outcome::Expired;
        }
        if history == SigStatus::Processing {
            state.processing = true;
        }
    }
    Outcome::Pending {
        notice: now_unix_ms.saturating_sub(tx.signed_at_ms)
            >= SOL_PENDING_NOTICE_SECS.saturating_mul(1_000),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LoopState, Observation, Outcome, PendingTx, SendResult, SigStatus, decide, plan,
        wants_history,
    };

    const TX: PendingTx = PendingTx {
        signed_at_ms: 1_000_000,
        last_valid_block_height: 500,
    };

    fn obs(status: SigStatus) -> Observation {
        Observation {
            status,
            send: None,
            height: None,
            history: None,
        }
    }

    #[test]
    fn finalized_statuses_are_terminal() {
        let mut state = LoopState::default();
        assert_eq!(
            decide(
                &TX,
                &mut state,
                &obs(SigStatus::Finalized { slot: 9, err: None }),
                0,
                0
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
                0,
                0
            ),
            Outcome::FailedOnChain { slot: 9, err: 1 }
        );
        assert!(matches!(
            decide(&TX, &mut state, &obs(SigStatus::Processing), 0, 0),
            Outcome::Pending { .. }
        ));
        assert!(state.processing);
        // processed/confirmed: no re-send, no height.
        let p = plan(&state, SigStatus::Processing, 100_000);
        assert!(!p.send && !p.height);
    }

    #[test]
    fn expiry_needs_height_history_and_wall_clock() {
        let mut state = LoopState::default();
        let mut round = obs(SigStatus::NotFound);
        round.height = Some(501);
        round.history = Some(SigStatus::NotFound);
        // < 90 s of wall clock: stays pending.
        assert!(matches!(
            decide(&TX, &mut state, &round, 0, TX.signed_at_ms + 89_999),
            Outcome::Pending { .. }
        ));
        assert_eq!(
            decide(&TX, &mut state, &round, 0, TX.signed_at_ms + 90_000),
            Outcome::Expired
        );
        // Height not above lvbh: never expired, whatever the history says.
        round.height = Some(500);
        assert!(matches!(
            decide(&TX, &mut state, &round, 0, TX.signed_at_ms + 900_000),
            Outcome::Pending { notice: true }
        ));
        assert!(!wants_history(&TX, Some(500)));
        assert!(wants_history(&TX, Some(501)));
        // A late landing found by the history search wins.
        round.height = Some(501);
        round.history = Some(SigStatus::Finalized { slot: 7, err: None });
        assert_eq!(
            decide(&TX, &mut state, &round, 0, TX.signed_at_ms + 900_000),
            Outcome::Landed { slot: 7 }
        );
        round.history = None;
        assert!(matches!(
            decide(&TX, &mut state, &round, 0, TX.signed_at_ms + 900_000),
            Outcome::Pending { .. }
        ));
    }

    #[test]
    fn preflight_and_anomaly_flags() {
        let mut state = LoopState::default();
        let mut round = obs(SigStatus::NotFound);
        round.send = Some(SendResult::Deterministic(1));
        round.height = Some(10);
        let _ = decide(&TX, &mut state, &round, 5_000, TX.signed_at_ms);
        assert!(state.stop_rebroadcast);
        assert_eq!(state.preflight_err, Some(1));
        let p = plan(&state, SigStatus::NotFound, 7_500);
        assert!(
            !p.send && p.height,
            "height keeps being checked for the expiry proof"
        );
        let mut other = LoopState::default();
        round.send = Some(SendResult::Accepted { matches: false });
        let _ = decide(&TX, &mut other, &round, 0, TX.signed_at_ms);
        assert!(other.anomaly && !other.stop_rebroadcast);
        // Transient errors keep re-sending, every 2.5 s.
        let mut transient = LoopState::default();
        assert!(plan(&transient, SigStatus::NotFound, 0).send);
        round.send = Some(SendResult::Transient);
        let _ = decide(&TX, &mut transient, &round, 1_000, TX.signed_at_ms);
        assert!(!plan(&transient, SigStatus::NotFound, 3_499).send);
        assert!(plan(&transient, SigStatus::NotFound, 3_500).send);
    }
}
