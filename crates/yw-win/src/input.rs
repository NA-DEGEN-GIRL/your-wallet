#![allow(unsafe_code)]
//! Physical input queries (spec/01 §7.7). These are consistency checks, not a security boundary:
//! injected input cannot be told apart reliably (spec.md §2.2).

use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, GetKeyState};
use windows_sys::Win32::UI::Input::{
    GetCurrentInputMessageSource, IMO_INJECTED, INPUT_MESSAGE_SOURCE,
};

/// Whether `vk` is physically down now (`GetAsyncKeyState` high bit).
#[must_use]
pub fn is_down(vk: u16) -> bool {
    // SAFETY: Reads the asynchronous key state; no pointers involved.
    let state = unsafe { GetAsyncKeyState(i32::from(vk)) };
    state < 0
}

/// Whether `vk` was down when the message being processed was generated (`GetKeyState` high
/// bit). The thread's synchronous key state follows the input queue only: a `WM_KEYDOWN` posted
/// or sent by another process does not set it, so a synthetic Enter reads "up".
#[must_use]
pub fn is_down_in_message(vk: u16) -> bool {
    // SAFETY: Reads the calling thread's key state; no pointers involved.
    let state = unsafe { GetKeyState(i32::from(vk)) };
    state < 0
}

/// Whether the message being processed was injected (`GetCurrentInputMessageSource`).
#[must_use]
pub fn injected() -> bool {
    let mut source = INPUT_MESSAGE_SOURCE {
        deviceType: 0,
        originId: 0,
    };
    // SAFETY: `source` is writable storage for the call.
    let ok = unsafe { GetCurrentInputMessageSource(&raw mut source) };
    ok != 0 && source.originId == IMO_INJECTED
}
