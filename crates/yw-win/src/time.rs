#![allow(unsafe_code)]
//! Monotonic and idle clocks (spec/01 §7.1).

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

/// Wrapping 32-bit difference `now - last`.
const fn idle_between(now: u32, last: u32) -> u32 {
    now.wrapping_sub(last)
}

#[cfg(test)]
mod tests {
    use super::{idle_between, monotonic_ms};

    #[test]
    fn idle_difference_handles_wrap() {
        assert_eq!(idle_between(10, 4), 6);
        assert_eq!(idle_between(5, u32::MAX - 4), 10);
    }

    #[test]
    fn monotonic_clock_does_not_go_backwards() {
        let first = monotonic_ms();
        let second = monotonic_ms();
        assert!(second >= first);
    }
}
