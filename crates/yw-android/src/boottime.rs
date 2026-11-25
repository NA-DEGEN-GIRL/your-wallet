#![allow(unsafe_code)]
//! The boot-time clock (spec/15 §5.4; 2026-11-25 A2-8): `clock_gettime(CLOCK_BOOTTIME)`, the clock
//! of `SystemClock.elapsedRealtime()`, which keeps counting while the device is in deep sleep.
//! `std::time::Instant` is `CLOCK_MONOTONIC` on Android, which stops in deep sleep: a background
//! lock measured with it would come late by every minute the phone slept. Android only; the
//! shell's clock (`crate::clock::AndroidClock`) reads it.

/// Milliseconds of `CLOCK_BOOTTIME` (since boot, deep sleep included), `None` when the call fails.
pub(crate) fn now_ms() -> Option<u64> {
    let mut spec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `spec` is a valid, writable `timespec` for the length of the call; `CLOCK_BOOTTIME`
    // is a clock id every Linux kernel Android runs on knows (2.6.39+); the call writes only
    // `spec` and returns 0 or -1.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut spec) };
    if result != 0 {
        return None;
    }
    let seconds = u64::try_from(spec.tv_sec).ok()?;
    let nanos = u64::try_from(spec.tv_nsec).ok()?;
    seconds.checked_mul(1_000)?.checked_add(nanos / 1_000_000)
}
