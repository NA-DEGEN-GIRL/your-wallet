//! Window message decoding (spec/01 §7.7), the secret-window message block list (spec/04 §4.4) and
//! the capture-exclusion outcome table (spec/04 §4.5). All pure, tested without windows.
//!
//! The block list is `is_blocked_secret_message` of
//! `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:1468-1498` unchanged.

use windows_sys::Win32::UI::WindowsAndMessaging::{
    PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND, WM_ACTIVATEAPP, WM_APP, WM_CANCELMODE,
    WM_CAPTURECHANGED, WM_CHAR, WM_CLEAR, WM_CLOSE, WM_COMMAND, WM_CONTEXTMENU, WM_COPY, WM_CREATE,
    WM_CUT, WM_DESTROY, WM_DPICHANGED, WM_DROPFILES, WM_ENDSESSION, WM_GETOBJECT, WM_GETTEXT,
    WM_GETTEXTLENGTH, WM_IME_CHAR, WM_IME_COMPOSITION, WM_IME_ENDCOMPOSITION, WM_IME_KEYDOWN,
    WM_IME_KEYUP, WM_IME_STARTCOMPOSITION, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEACTIVATE, WM_MOUSEMOVE, WM_MOUSEWHEEL,
    WM_PAINT, WM_PASTE, WM_POWERBROADCAST, WM_PRINT, WM_PRINTCLIENT, WM_QUERYENDSESSION,
    WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SETTEXT, WM_SIZE, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_TIMER,
    WM_UNDO, WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
    WTS_SESSION_LOGOFF, WTS_SESSION_UNLOCK,
};

/// Last application message number (`WM_APP..=0xBFFF`).
const WM_APP_LAST: u32 = 0xBFFF;

/// A decoded window message delivered to a [`super::Handler`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg {
    /// The handler was attached (after `WM_CREATE`, or after capture exclusion for secret classes).
    Create,
    /// `WM_PAINT`; paint with [`super::Window::begin_paint`].
    Paint,
    /// `WM_SIZE` client size in pixels.
    Size {
        /// Width.
        w: i32,
        /// Height.
        h: i32,
    },
    /// `WM_DPICHANGED`; `Reply::Default` applies the suggested rectangle.
    DpiChanged {
        /// New DPI.
        dpi: u32,
    },
    /// `WM_CHAR` UTF-16 unit.
    Char(u16),
    /// `WM_KEYDOWN` / `WM_SYSKEYDOWN`.
    KeyDown {
        /// Virtual key.
        vk: u16,
        /// lParam bit 30 (auto-repeat).
        repeat: bool,
    },
    /// `WM_KEYUP` / `WM_SYSKEYUP`.
    KeyUp {
        /// Virtual key.
        vk: u16,
    },
    /// `WM_LBUTTONDOWN` in client coordinates.
    MouseDown {
        /// X.
        x: i32,
        /// Y.
        y: i32,
    },
    /// `WM_LBUTTONUP`.
    MouseUp {
        /// X.
        x: i32,
        /// Y.
        y: i32,
    },
    /// `WM_MOUSEMOVE`.
    MouseMove {
        /// X.
        x: i32,
        /// Y.
        y: i32,
    },
    /// `WM_MOUSEWHEEL` delta.
    Wheel(i16),
    /// `WM_MOUSEACTIVATE`; reply `Handled(MA_ACTIVATEANDEAT)` to eat a click-through.
    MouseActivate,
    /// `WM_TIMER` id.
    Timer(usize),
    /// `WM_COMMAND` from a child control.
    Command {
        /// Control id.
        id: u16,
        /// Notification code.
        code: u16,
    },
    /// `WM_ACTIVATEAPP`.
    ActivateApp(bool),
    /// `WM_KILLFOCUS`; `to_foreign` when focus leaves this window and its children.
    KillFocus {
        /// Focus goes to a window outside this one.
        to_foreign: bool,
    },
    /// `WM_CAPTURECHANGED`.
    CaptureChanged,
    /// `WM_CANCELMODE`.
    CancelMode,
    /// `WM_CLOSE`; `Reply::Default` destroys the window.
    Close,
    /// `WM_DESTROY`.
    Destroy,
    /// `WM_WTSSESSION_CHANGE` / `WTS_SESSION_LOCK` (0x7).
    SessionLock,
    /// `WM_WTSSESSION_CHANGE` / `WTS_SESSION_UNLOCK` (0x8).
    SessionUnlock,
    /// `WM_WTSSESSION_CHANGE` / `WTS_CONSOLE_DISCONNECT` (0x2) or `WTS_REMOTE_DISCONNECT` (0x4).
    SessionDisconnect,
    /// `WM_WTSSESSION_CHANGE` / `WTS_SESSION_LOGOFF` (0x6).
    SessionLogoff,
    /// `WM_POWERBROADCAST` / `PBT_APMSUSPEND`.
    Suspend,
    /// `WM_POWERBROADCAST` / `PBT_APMRESUMEAUTOMATIC`.
    Resume,
    /// `WM_QUERYENDSESSION` (`Reply::Default` allows the shutdown).
    QueryEndSession,
    /// `WM_ENDSESSION` with wParam TRUE (FALSE is not delivered).
    EndSession,
    /// `WM_IME_STARTCOMPOSITION` (reported before a secret window blocks it).
    ImeAttempt,
    /// `WM_APP..=0xBFFF`.
    App {
        /// Message number.
        msg: u32,
        /// wParam.
        wparam: usize,
    },
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "LOWORD/HIWORD extraction is a deliberate truncation"
)]
const fn loword(value: usize) -> u16 {
    (value & 0xFFFF) as u16
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "LOWORD/HIWORD extraction is a deliberate truncation"
)]
const fn hiword(value: usize) -> u16 {
    ((value >> 16) & 0xFFFF) as u16
}

#[expect(
    clippy::cast_sign_loss,
    reason = "lParam is reinterpreted bitwise as in GET_X_LPARAM"
)]
const fn lparam_bits(lparam: isize) -> usize {
    lparam as usize
}

#[expect(
    clippy::cast_possible_wrap,
    reason = "GET_X_LPARAM sign-extends the low word"
)]
const fn signed_word(word: u16) -> i32 {
    word as i16 as i32
}

/// Decodes a raw message. `None` means "not for the handler" (the caller uses `DefWindowProcW`).
/// `is_foreign(wparam)` answers whether a `WM_KILLFOCUS` target lies outside the window.
pub(crate) fn decode(
    msg: u32,
    wparam: usize,
    lparam: isize,
    is_foreign: impl FnOnce(usize) -> bool,
) -> Option<Msg> {
    let bits = lparam_bits(lparam);
    let point = || (signed_word(loword(bits)), signed_word(hiword(bits)));
    Some(match msg {
        WM_CREATE => Msg::Create,
        WM_PAINT => Msg::Paint,
        WM_SIZE => Msg::Size {
            w: i32::from(loword(bits)),
            h: i32::from(hiword(bits)),
        },
        WM_DPICHANGED => Msg::DpiChanged {
            dpi: u32::from(hiword(wparam)),
        },
        WM_CHAR => Msg::Char(loword(wparam)),
        WM_KEYDOWN | WM_SYSKEYDOWN => Msg::KeyDown {
            vk: loword(wparam),
            repeat: bits & (1 << 30) != 0,
        },
        WM_KEYUP | WM_SYSKEYUP => Msg::KeyUp { vk: loword(wparam) },
        WM_LBUTTONDOWN => {
            let (x, y) = point();
            Msg::MouseDown { x, y }
        }
        WM_LBUTTONUP => {
            let (x, y) = point();
            Msg::MouseUp { x, y }
        }
        WM_MOUSEMOVE => {
            let (x, y) = point();
            Msg::MouseMove { x, y }
        }
        WM_MOUSEWHEEL => Msg::Wheel(i16::from_ne_bytes(hiword(wparam).to_ne_bytes())),
        WM_MOUSEACTIVATE => Msg::MouseActivate,
        WM_TIMER => Msg::Timer(wparam),
        WM_COMMAND => Msg::Command {
            id: loword(wparam),
            code: hiword(wparam),
        },
        WM_ACTIVATEAPP => Msg::ActivateApp(wparam != 0),
        WM_KILLFOCUS => Msg::KillFocus {
            to_foreign: is_foreign(wparam),
        },
        WM_CAPTURECHANGED => Msg::CaptureChanged,
        WM_CANCELMODE => Msg::CancelMode,
        WM_CLOSE => Msg::Close,
        WM_DESTROY => Msg::Destroy,
        WM_WTSSESSION_CHANGE => match u32::try_from(wparam).ok()? {
            WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => Msg::SessionDisconnect,
            WTS_SESSION_LOGOFF => Msg::SessionLogoff,
            WTS_SESSION_LOCK => Msg::SessionLock,
            WTS_SESSION_UNLOCK => Msg::SessionUnlock,
            _ => return None,
        },
        WM_POWERBROADCAST => match u32::try_from(wparam).ok()? {
            PBT_APMSUSPEND => Msg::Suspend,
            PBT_APMRESUMEAUTOMATIC => Msg::Resume,
            _ => return None,
        },
        WM_QUERYENDSESSION => Msg::QueryEndSession,
        WM_ENDSESSION if wparam != 0 => Msg::EndSession,
        WM_IME_STARTCOMPOSITION => Msg::ImeAttempt,
        WM_APP..=WM_APP_LAST => Msg::App { msg, wparam },
        _ => return None,
    })
}

/// The exactly 22 messages a secret window never passes to its handler or `DefWindowProcW`
/// (spec/04 §4.4), plus `WM_SETTEXT` once the secret state is attached (`armed`).
#[must_use]
pub const fn is_blocked_secret_msg(msg: u32, armed: bool) -> bool {
    matches!(
        msg,
        WM_GETTEXT
            | WM_GETTEXTLENGTH
            | WM_GETOBJECT
            | WM_PRINT
            | WM_PRINTCLIENT
            | WM_COPY
            | WM_CUT
            | WM_PASTE
            | WM_CLEAR
            | WM_UNDO
            | WM_CONTEXTMENU
            | WM_DROPFILES
            | WM_RBUTTONDOWN
            | WM_RBUTTONUP
            | WM_MBUTTONDOWN
            | WM_MBUTTONUP
            | WM_IME_STARTCOMPOSITION
            | WM_IME_COMPOSITION
            | WM_IME_ENDCOMPOSITION
            | WM_IME_CHAR
            | WM_IME_KEYDOWN
            | WM_IME_KEYUP
    ) || (armed && msg == WM_SETTEXT)
}

/// Capture-exclusion failure policy of a secret class (spec/01 §7.7, spec/04 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureExclusion {
    /// Mnemonic / private-key display windows: failure destroys the window.
    Required,
    /// Password, mnemonic and key entry windows: failure keeps the window with a warning.
    Preferred,
}

/// What `create_window` does after the exclusion attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureOutcome {
    /// Exclusion is set and read back as `WDA_EXCLUDEFROMCAPTURE`.
    Excluded,
    /// Not excluded; the window is kept and `capture_excluded() == false`.
    Unprotected,
    /// Not excluded; the window is destroyed and `CaptureExclusionFailed` returned.
    Destroy,
}

/// The four-case table of spec/01 §7.7.
#[must_use]
pub const fn capture_outcome(mode: CaptureExclusion, excluded: bool) -> CaptureOutcome {
    match (mode, excluded) {
        (_, true) => CaptureOutcome::Excluded,
        (CaptureExclusion::Required, false) => CaptureOutcome::Destroy,
        (CaptureExclusion::Preferred, false) => CaptureOutcome::Unprotected,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CaptureExclusion, CaptureOutcome, Msg, capture_outcome, decode, is_blocked_secret_msg,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        WM_APP, WM_CHAR, WM_COMMAND, WM_CONTEXTMENU, WM_COPY, WM_ENDSESSION, WM_GETTEXT,
        WM_IME_NOTIFY, WM_IME_SETCONTEXT, WM_IME_STARTCOMPOSITION, WM_KEYDOWN, WM_KILLFOCUS,
        WM_LBUTTONDOWN, WM_POWERBROADCAST, WM_QUERYENDSESSION, WM_RBUTTONDBLCLK, WM_SETTEXT,
        WM_SIZE, WM_TIMER, WM_WTSSESSION_CHANGE,
    };

    fn plain(msg: u32, wparam: usize, lparam: isize) -> Option<Msg> {
        decode(msg, wparam, lparam, |_| true)
    }

    #[test]
    fn session_change_values_decode_exactly() {
        assert_eq!(
            plain(WM_WTSSESSION_CHANGE, 0x2, 0),
            Some(Msg::SessionDisconnect)
        );
        assert_eq!(
            plain(WM_WTSSESSION_CHANGE, 0x4, 0),
            Some(Msg::SessionDisconnect)
        );
        assert_eq!(
            plain(WM_WTSSESSION_CHANGE, 0x6, 0),
            Some(Msg::SessionLogoff)
        );
        assert_eq!(plain(WM_WTSSESSION_CHANGE, 0x7, 0), Some(Msg::SessionLock));
        assert_eq!(
            plain(WM_WTSSESSION_CHANGE, 0x8, 0),
            Some(Msg::SessionUnlock)
        );
        for other in [0x1, 0x3, 0x5, 0x9, 0xA, 0xB, 0xFFFF] {
            assert_eq!(plain(WM_WTSSESSION_CHANGE, other, 0), None);
        }
    }

    #[test]
    fn power_and_end_session_decode() {
        assert_eq!(plain(WM_POWERBROADCAST, 0x4, 0), Some(Msg::Suspend));
        assert_eq!(plain(WM_POWERBROADCAST, 0x12, 0), Some(Msg::Resume));
        assert_eq!(plain(WM_POWERBROADCAST, 0xA, 0), None);
        assert_eq!(plain(WM_QUERYENDSESSION, 0, 0), Some(Msg::QueryEndSession));
        assert_eq!(plain(WM_ENDSESSION, 1, 0), Some(Msg::EndSession));
        assert_eq!(plain(WM_ENDSESSION, 0, 0), None);
    }

    #[test]
    fn input_and_command_decode() {
        assert_eq!(plain(WM_CHAR, 0x61, 0), Some(Msg::Char(0x61)));
        assert_eq!(
            plain(WM_KEYDOWN, 0x20, 1 << 30),
            Some(Msg::KeyDown {
                vk: 0x20,
                repeat: true
            })
        );
        assert_eq!(
            plain(WM_LBUTTONDOWN, 0, 0x0005_FFFE),
            Some(Msg::MouseDown { x: -2, y: 5 })
        );
        assert_eq!(
            plain(WM_SIZE, 0, 0x0200_0300),
            Some(Msg::Size { w: 0x300, h: 0x200 })
        );
        assert_eq!(
            plain(WM_COMMAND, 0x0001_0064, 0),
            Some(Msg::Command { id: 100, code: 1 })
        );
        assert_eq!(plain(WM_TIMER, 7, 0), Some(Msg::Timer(7)));
        assert_eq!(
            plain(WM_APP + 1, 3, 0),
            Some(Msg::App {
                msg: WM_APP + 1,
                wparam: 3
            })
        );
        assert_eq!(
            decode(WM_KILLFOCUS, 0, 0, |_| false),
            Some(Msg::KillFocus { to_foreign: false })
        );
        assert_eq!(plain(WM_IME_STARTCOMPOSITION, 0, 0), Some(Msg::ImeAttempt));
        assert_eq!(plain(WM_RBUTTONDBLCLK, 0, 0), None);
    }

    #[test]
    fn exactly_the_listed_secret_messages_are_blocked() {
        let blocked: Vec<u32> = (0..0x1000)
            .filter(|msg| is_blocked_secret_msg(*msg, false))
            .collect();
        assert_eq!(blocked.len(), 22);
        assert!(is_blocked_secret_msg(WM_GETTEXT, false));
        assert!(is_blocked_secret_msg(WM_COPY, false));
        assert!(is_blocked_secret_msg(WM_CONTEXTMENU, false));
        assert!(!is_blocked_secret_msg(WM_SETTEXT, false));
        assert!(is_blocked_secret_msg(WM_SETTEXT, true));
        assert!(!is_blocked_secret_msg(WM_RBUTTONDBLCLK, true));
        assert!(!is_blocked_secret_msg(WM_IME_SETCONTEXT, true));
        assert!(!is_blocked_secret_msg(WM_IME_NOTIFY, true));
        assert!(!is_blocked_secret_msg(WM_TIMER, true));
    }

    #[test]
    fn capture_outcome_four_cases() {
        assert_eq!(
            capture_outcome(CaptureExclusion::Required, true),
            CaptureOutcome::Excluded
        );
        assert_eq!(
            capture_outcome(CaptureExclusion::Preferred, true),
            CaptureOutcome::Excluded
        );
        assert_eq!(
            capture_outcome(CaptureExclusion::Required, false),
            CaptureOutcome::Destroy
        );
        assert_eq!(
            capture_outcome(CaptureExclusion::Preferred, false),
            CaptureOutcome::Unprotected
        );
    }
}
