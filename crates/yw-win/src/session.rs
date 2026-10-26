#![allow(unsafe_code)]
//! Windows session notifications (spec/01 §7.6). Lock/unlock/disconnect/logoff arrive as
//! `ui::Msg::Session*` on the registered top-level window.

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};

use crate::error::WinError;
use crate::ui::Window;

fn raw(window: &Window) -> HWND {
    core::ptr::with_exposed_provenance_mut(window.raw_id())
}

/// `WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)`.
///
/// # Errors
///
/// [`WinError`] (e.g. `RPC_S_INVALID_BINDING` early in logon; the app retries, spec/04 §1.4).
pub fn register_session_notifications(window: &Window) -> Result<(), WinError> {
    // SAFETY: Registers our live top-level window for session notifications.
    let ok = unsafe { WTSRegisterSessionNotification(raw(window), NOTIFY_FOR_THIS_SESSION) };
    if ok == 0 {
        return Err(WinError::last("WTSRegisterSessionNotification"));
    }
    Ok(())
}

/// `WTSUnRegisterSessionNotification(hwnd)` (call before destroying the window).
pub fn unregister_session_notifications(window: &Window) {
    // SAFETY: Unregisters our window; failure (never registered) is harmless.
    unsafe { WTSUnRegisterSessionNotification(raw(window)) };
}
