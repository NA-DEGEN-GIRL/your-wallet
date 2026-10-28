//! `btc::pace` (spec/08 §4.4): one request line for every Bitcoin request of a session (Core and
//! indexer alike). Request starts are at least `BTC_REQ_MIN_INTERVAL_MS` (200 ms) apart; after a
//! job is aborted by a fourth HTTP 429 a `BTC_429_COOLDOWN_SECS` (300 s) cooldown starts during
//! which automatic refreshes are skipped (user-initiated ones still run). Time comes from the
//! injected [`Clock`] so tests use a manual clock (spec/09 §1 rule 5).

use std::sync::Mutex;

use yw_core::btc::{BTC_429_COOLDOWN_SECS, BTC_REQ_MIN_INTERVAL_MS};

use crate::flow::evm::Clock;

/// Cooldown length in milliseconds.
pub const COOLDOWN_MS: u64 = BTC_429_COOLDOWN_SECS * 1_000;

#[derive(Clone, Copy, Debug, Default)]
struct PaceState {
    last_start_ms: Option<u64>,
    cooldown_until_ms: Option<u64>,
}

/// The pacing state of one unlock session (kept by the worker across jobs).
#[derive(Debug, Default)]
pub struct Pace {
    state: Mutex<PaceState>,
}

impl Pace {
    /// No request made yet, no cooldown.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, action: impl FnOnce(&mut PaceState) -> T) -> T {
        match self.state.lock() {
            Ok(mut state) => action(&mut state),
            Err(poisoned) => action(&mut poisoned.into_inner()),
        }
    }

    /// Waits (through `clock`) until `BTC_REQ_MIN_INTERVAL_MS` after the previous request start,
    /// then records the new start.
    pub fn wait_turn(&self, clock: &dyn Clock) {
        let last = self.with(|state| state.last_start_ms);
        if let Some(last) = last {
            let ready_at = last.saturating_add(BTC_REQ_MIN_INTERVAL_MS);
            let now = clock.now_ms();
            if now < ready_at {
                clock.sleep_ms(ready_at - now);
            }
        }
        let start = clock.now_ms();
        self.with(|state| state.last_start_ms = Some(start));
    }

    /// Starts the 300 s cooldown at `now_ms` (a job was aborted by HTTP 429).
    pub fn start_cooldown(&self, now_ms: u64) {
        self.with(|state| state.cooldown_until_ms = Some(now_ms.saturating_add(COOLDOWN_MS)));
    }

    /// Whether automatic refreshes are skipped at `now_ms`.
    #[must_use]
    pub fn in_cooldown(&self, now_ms: u64) -> bool {
        self.with(|state| state.cooldown_until_ms.is_some_and(|until| now_ms < until))
    }

    /// Milliseconds left in the cooldown at `now_ms`.
    #[must_use]
    pub fn cooldown_remaining_ms(&self, now_ms: u64) -> Option<u64> {
        self.with(|state| {
            state
                .cooldown_until_ms
                .filter(|until| now_ms < *until)
                .map(|until| until - now_ms)
        })
    }
}
