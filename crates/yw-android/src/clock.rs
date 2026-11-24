//! The Android shell's clock (2026-11-25 A2-6, spec/15 §11.2): monotonic milliseconds from the
//! process's first reading (`std::time::Instant`, `CLOCK_MONOTONIC` on Android), the wall clock
//! from `SystemTime`, and plain sleeps. Platform-neutral (std only); the wallet and its workers
//! share one through an `Arc`.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use yw_platform::clock::Clock;

/// The clock (module doc).
#[derive(Debug)]
pub struct AndroidClock {
    base: Instant,
}

impl AndroidClock {
    /// A clock whose monotonic reading starts at 0 now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
        }
    }
}

impl Default for AndroidClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for AndroidClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readings_count_up() {
        let clock = AndroidClock::new();
        let first = clock.now_ms();
        clock.sleep_ms(2);
        assert!(clock.now_ms() >= first.saturating_add(1));
        assert!(clock.now_unix_ms() > 1_700_000_000_000);
    }
}
