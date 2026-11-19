//! The Windows [`Clock`] of the pipelines and workers (2026-11-17, spec/15 §11.4 S2: moved here
//! from `flow::evm`, so the pipelines name only the `yw_platform::Clock` trait).
//!
//! The monotonic base is yw-win `time::monotonic_ms` (`GetTickCount64`), the same base the App
//! uses for approval expiry and the Solana sign-time check. Production code always passes this
//! clock; an `Instant`-based clock is for local elapsed time and tests only.

use std::sync::Arc;

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

/// One shared clock for a holder that takes a `Box<dyn Clock>` (2026-11-19, S4 B1a, spec/15
/// §11.4 S4 critique A-9/B-19): `main.rs` gives the App's `Arc` to the RPC worker
/// (`RpcWorker::new`) and to the key worker (`WinKeyPlatform::deps`) through it, so the App, the
/// workers and the browser dispatcher read one time base (before, each got its own
/// `SystemClock`, which read the same `GetTickCount64` base). It only forwards.
#[derive(Clone)]
pub struct ArcClock(pub Arc<dyn Clock>);

impl core::fmt::Debug for ArcClock {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ArcClock")
    }
}

impl Clock for ArcClock {
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
