//! The pipelines' time source (spec/01 §2.3a).
//!
//! 2026-11-17: moved unchanged from yw-app `flow::evm` (which re-exports it); the Windows
//! implementation `SystemClock` stays in yw-app (`system_clock`, 2026-11-17 S2).

/// Time source of the pipelines (monotonic ms for budgets, wall clock for records).
pub trait Clock: Send + Sync {
    /// Monotonic milliseconds (Windows: yw-win `time::monotonic_ms`).
    fn now_ms(&self) -> u64;
    /// Wall-clock Unix milliseconds.
    fn now_unix_ms(&self) -> u64;
    /// Sleeps (retry delays).
    fn sleep_ms(&self, ms: u64);
}
