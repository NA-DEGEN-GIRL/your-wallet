#![allow(unsafe_code)]
//! Monotonic and idle clocks and the local wall-clock offset (spec/01 §7.1).

use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::Storage::FileSystem::FileTimeToLocalFileTime;
use windows_sys::Win32::System::SystemInformation::{GetTickCount, GetTickCount64};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

/// Milliseconds since boot (`GetTickCount64`): the `now_ms` passed to yw-core.
#[must_use]
pub fn monotonic_ms() -> u64 {
    // SAFETY: `GetTickCount64` takes no arguments and only reads the system tick count.
    unsafe { GetTickCount64() }
}

/// Milliseconds since the last system-wide input (`GetTickCount() - LASTINPUTINFO.dwTime`,
/// 32-bit wrap handled). Returns 0 when the query fails.
#[must_use]
pub fn system_idle_ms() -> u64 {
    let mut info = LASTINPUTINFO {
        cbSize: u32::try_from(core::mem::size_of::<LASTINPUTINFO>()).unwrap_or(8),
        dwTime: 0,
    };
    // SAFETY: `info` is a writable LASTINPUTINFO with `cbSize` set, live for the call.
    let ok = unsafe { GetLastInputInfo(&raw mut info) };
    if ok == 0 {
        return 0;
    }
    // SAFETY: `GetTickCount` takes no arguments.
    let now = unsafe { GetTickCount() };
    u64::from(idle_between(now, info.dwTime))
}

/// 1601-01-01 → 1970-01-01 in milliseconds.
const FILETIME_UNIX_EPOCH_MS: u64 = 11_644_473_600_000;

/// The local wall-clock time of `unix_ms`, as milliseconds on the Unix scale
/// (`FileTimeToLocalFileTime`: the current time-zone bias); `None` when the conversion fails.
/// For display only (activity rows, spec/04 §2.6).
#[must_use]
pub fn local_wall_ms(unix_ms: u64) -> Option<u64> {
    let ticks = unix_ms
        .checked_add(FILETIME_UNIX_EPOCH_MS)?
        .checked_mul(10_000)?;
    let utc = FILETIME {
        dwLowDateTime: u32::try_from(ticks & 0xFFFF_FFFF).ok()?,
        dwHighDateTime: u32::try_from(ticks >> 32).ok()?,
    };
    let mut local = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: both pointers refer to live FILETIME values for the duration of the call.
    let ok = unsafe { FileTimeToLocalFileTime(&raw const utc, &raw mut local) };
    if ok == 0 {
        return None;
    }
    let ticks = (u64::from(local.dwHighDateTime) << 32) | u64::from(local.dwLowDateTime);
    (ticks / 10_000).checked_sub(FILETIME_UNIX_EPOCH_MS)
}

/// Wrapping 32-bit difference `now - last`.
const fn idle_between(now: u32, last: u32) -> u32 {
    now.wrapping_sub(last)
}

#[cfg(test)]
mod tests {
    use super::{idle_between, local_wall_ms, monotonic_ms};

    #[test]
    fn idle_difference_handles_wrap() {
        assert_eq!(idle_between(10, 4), 6);
        assert_eq!(idle_between(5, u32::MAX - 4), 10);
    }

    #[test]
    fn local_wall_time_is_within_a_day_of_utc() {
        let utc = 1_790_000_000_123_u64;
        let local = local_wall_ms(utc).unwrap();
        assert!(local.abs_diff(utc) <= 14 * 3_600_000);
        assert_eq!(local % 60_000, utc % 60_000, "offsets are whole minutes");
    }

    #[test]
    fn monotonic_clock_does_not_go_backwards() {
        let first = monotonic_ms();
        let second = monotonic_ms();
        assert!(second >= first);
    }
}
