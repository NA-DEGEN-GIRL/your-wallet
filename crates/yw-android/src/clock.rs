//! The Android shell's clock (2026-11-25 A2-6, spec/15 §11.2): monotonic milliseconds from the
//! process's first reading, the wall clock from `SystemTime`, and plain sleeps. The wallet and its
//! workers share one through an `Arc`.
//!
//! 2026-11-25 A2-8 (spec/15 §5.4): on Android the monotonic reading is `CLOCK_BOOTTIME`
//! (`crate::boottime`, the clock of `SystemClock.elapsedRealtime()`), which keeps counting in deep
//! sleep, so the background lock, the idle lock and every time limit count the minutes the phone
//! slept. Readings never go back: one that is lower than the last (or a failed read) gives the last
//! one. Before, the reading was `std::time::Instant` (`CLOCK_MONOTONIC`, which stops in deep sleep);
//! the gate's Windows build still uses it (std only there).
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use yw_platform::clock::Clock;

/// The clock (module doc).
#[derive(Debug)]
pub struct AndroidClock {
    /// The first raw reading (the monotonic reading counts from it).
    base: u64,
    /// The last reading handed out.
    last: AtomicU64,
}

/// The raw monotonic milliseconds: `CLOCK_BOOTTIME` on Android (`None` when the call fails).
#[cfg(target_os = "android")]
fn raw_ms() -> Option<u64> {
    crate::boottime::now_ms()
}

/// The raw monotonic milliseconds off Android: an `Instant` from the first reading.
#[cfg(not(target_os = "android"))]
fn raw_ms() -> Option<u64> {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).ok()
}

impl AndroidClock {
    /// A clock whose monotonic reading starts at 0 now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: raw_ms().unwrap_or(0),
            last: AtomicU64::new(0),
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
        let reading = raw_ms().map_or(0, |raw| raw.saturating_sub(self.base));
        // Never back: the larger of this reading and the last one handed out.
        let last = self.last.fetch_max(reading, Ordering::AcqRel);
        last.max(reading)
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

/// The one clock of the wallet, handed to a worker that takes a `Box<dyn Clock>` (2026-11-25
/// A2-8): every reading comes from the same [`AndroidClock`], so the workers and the wallet share
/// one time base (Windows: yw-app `system_clock::ArcClock`).
#[derive(Clone)]
pub struct SharedClock(pub std::sync::Arc<dyn Clock>);

impl core::fmt::Debug for SharedClock {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SharedClock")
    }
}

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }

    fn now_unix_ms(&self) -> u64 {
        self.0.now_unix_ms()
    }

    fn sleep_ms(&self, ms: u64) {
        self.0.sleep_ms(ms);
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

    /// Readings never go back, also across clocks made at different times.
    #[test]
    fn readings_never_go_back() {
        let clock = AndroidClock::new();
        let mut last = 0;
        for _ in 0..1_000 {
            let now = clock.now_ms();
            assert!(now >= last);
            last = now;
        }
        let later = AndroidClock::new();
        assert!(later.now_ms() <= clock.now_ms().saturating_add(1));
    }
}
