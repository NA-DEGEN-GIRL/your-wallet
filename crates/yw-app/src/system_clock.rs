//! The Windows [`Clock`] of the pipelines and workers (2026-11-17, spec/15 §11.4 S2: moved here
//! from `flow::evm`, so the pipelines name only the `yw_platform::Clock` trait).
//!
//! The monotonic base is yw-win `time::monotonic_ms` (`GetTickCount64`), the same base the App
//! uses for approval expiry and the Solana sign-time check. Production code always passes this
//! clock; an `Instant`-based clock is for local elapsed time and tests only.

use yw_platform::Clock;

/// The real clock (Windows: yw-win `time::monotonic_ms`).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        yw_win::time::monotonic_ms()
    }

    fn now_unix_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}
