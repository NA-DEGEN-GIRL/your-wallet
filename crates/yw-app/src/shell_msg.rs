//! Windows shell messages (spec/04 §1.3): the `WM_APP` message numbers the message loop posts to
//! the main window, the keyboard shortcuts the loop observer recognizes ([`Shortcut`],
//! [`NavKey`], [`chain_tab_key`]) and the main window timer. 2026-11-17 (spec/15 §11.4 S2): moved
//! out of `events`, which keeps only the platform-neutral queues and events.
//!
//! 2026-11-21 (S4 W1, spec/15 §11.4 S4, plan §3.3): also what the main window does with the
//! Windows session, power and shutdown messages ([`system_action`], spec/04 §5.1 and LK-3),
//! moved from `lock`, which keeps the wallet's `LockReason` and `IdleTracker`.

use yw_win::ui::Msg;

use crate::lock::LockReason;

/// Event queue doorbell (`WM_APP + 1`).
pub const WM_YW_EVENTS: u32 = 0x8001;
/// Second instance → first instance (`WM_APP + 2`).
pub const WM_YW_ACTIVATE: u32 = 0x8002;
/// Secret window → main window (`WM_APP + 3`, wParam = window id).
pub const WM_YW_CHILD_DONE: u32 = 0x8003;
/// Ctrl+L observed by the message loop (`WM_APP + 4`).
pub const WM_YW_LOCK_SHORTCUT: u32 = 0x8004;
/// Ctrl+1/2/3/4 observed by the message loop (`WM_APP + 5`, wParam = tab 1–4): the chain tabs.
pub const WM_YW_TAB_SHORTCUT: u32 = 0x8005;
/// A navigation key observed by the message loop (`WM_APP + 6`, wParam = [`NavKey::code`]),
/// handled after the dialog manager has moved the focus (spec/04 §1.7).
pub const WM_YW_NAV_KEY: u32 = 0x8006;
/// F5 or Ctrl+, observed by the message loop (`WM_APP + 7`, wParam = [`Shortcut::code`]); the
/// main window decides whether it applies (spec/04 §1.7, 2026-11-10).
pub const WM_YW_SHORTCUT: u32 = 0x8007;

/// A main-window shortcut other than Ctrl+L and Ctrl+1–4 (2026-11-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shortcut {
    /// F5: the visible chain tab's `새로고침`.
    Refresh,
    /// Ctrl+,: `설정` (the section last opened in this run).
    Settings,
}

impl Shortcut {
    /// The shortcut of virtual key `vk` with these modifiers, or `None` (F5 without Ctrl or Alt;
    /// Ctrl+, without Alt).
    #[must_use]
    pub const fn of(vk: u16, ctrl: bool, alt: bool) -> Option<Self> {
        match vk {
            0x74 if !ctrl && !alt => Some(Self::Refresh),
            0xBC if ctrl && !alt => Some(Self::Settings),
            _ => None,
        }
    }

    /// The `WM_YW_SHORTCUT` wParam.
    #[must_use]
    pub const fn code(self) -> usize {
        match self {
            Self::Refresh => 1,
            Self::Settings => 2,
        }
    }

    /// The shortcut of a `WM_YW_SHORTCUT` wParam (`None` for any other value).
    #[must_use]
    pub const fn from_code(code: usize) -> Option<Self> {
        match code {
            1 => Some(Self::Refresh),
            2 => Some(Self::Settings),
            _ => None,
        }
    }
}

/// A keyboard key that moves around the main window (spec/04 §1.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NavKey {
    /// Tab (`back` = Shift+Tab).
    Tab {
        /// Shift held.
        back: bool,
    },
    /// Page Up (`up`) / Page Down.
    Page {
        /// Page Up.
        up: bool,
    },
    /// Home (`top`) / End, with or without Ctrl.
    Edge {
        /// Home.
        top: bool,
    },
    /// An arrow key (the dialog manager may move the focus within a group): Up (`up ==
    /// Some(true)`), Down (`Some(false)`), Left or Right (`None`).
    Arrow {
        /// Up or Down.
        up: Option<bool>,
    },
}

impl NavKey {
    /// The navigation key of virtual key `vk` with these modifiers, or `None` (never with Alt;
    /// Tab, Page Up/Down and the arrows without Ctrl; Home/End with or without it since
    /// 2026-11-12 — the main window leaves them to an edit that has the focus).
    #[must_use]
    pub const fn of(vk: u16, ctrl: bool, alt: bool, shift: bool) -> Option<Self> {
        if alt {
            return None;
        }
        match vk {
            0x09 if !ctrl => Some(Self::Tab { back: shift }),
            0x21 if !ctrl => Some(Self::Page { up: true }),
            0x22 if !ctrl => Some(Self::Page { up: false }),
            0x24 => Some(Self::Edge { top: true }),
            0x23 => Some(Self::Edge { top: false }),
            0x26 if !ctrl => Some(Self::Arrow { up: Some(true) }),
            0x28 if !ctrl => Some(Self::Arrow { up: Some(false) }),
            0x25 | 0x27 if !ctrl => Some(Self::Arrow { up: None }),
            _ => None,
        }
    }

    /// The `WM_YW_NAV_KEY` wParam.
    #[must_use]
    pub const fn code(self) -> usize {
        match self {
            Self::Tab { back: false } => 1,
            Self::Tab { back: true } => 2,
            Self::Page { up: true } => 3,
            Self::Page { up: false } => 4,
            Self::Edge { top: true } => 5,
            Self::Edge { top: false } => 6,
            Self::Arrow { up: None } => 7,
            Self::Arrow { up: Some(true) } => 8,
            Self::Arrow { up: Some(false) } => 9,
        }
    }

    /// The key of a `WM_YW_NAV_KEY` wParam (`None` for any other value).
    #[must_use]
    pub const fn from_code(code: usize) -> Option<Self> {
        Some(match code {
            1 => Self::Tab { back: false },
            2 => Self::Tab { back: true },
            3 => Self::Page { up: true },
            4 => Self::Page { up: false },
            5 => Self::Edge { top: true },
            6 => Self::Edge { top: false },
            7 => Self::Arrow { up: None },
            8 => Self::Arrow { up: Some(true) },
            9 => Self::Arrow { up: Some(false) },
            _ => return None,
        })
    }
}

/// The chain tab (1 EVM, 2 Solana, 3 Bitcoin, 4 Zcash) of a digit key's virtual-key code
/// (`'1'`–`'4'`, used with Ctrl), or `None`.
#[must_use]
pub const fn chain_tab_key(vk: u16) -> Option<usize> {
    match vk {
        0x31 => Some(1),
        0x32 => Some(2),
        0x33 => Some(3),
        0x34 => Some(4),
        _ => None,
    }
}

/// Main window timer.
pub const MAIN_TIMER_MS: u32 = 250;

/// What a system message asks the main window to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemAction {
    /// Lock now.
    Lock(LockReason),
    /// Run the shutdown sequence (spec/04 §1.5).
    Shutdown,
    /// `WM_QUERYENDSESSION`: reply TRUE, change nothing.
    AllowEndSession,
}

/// Session, power and shutdown mapping (spec/04 §1.5, §5.1; LK-3). 2026-11-21 (S4 W1): moved
/// from `lock` unchanged.
#[must_use]
pub const fn system_action(msg: &Msg) -> Option<SystemAction> {
    match msg {
        Msg::SessionLock => Some(SystemAction::Lock(LockReason::SessionLock)),
        Msg::SessionDisconnect => Some(SystemAction::Lock(LockReason::SessionDisconnect)),
        Msg::Suspend => Some(SystemAction::Lock(LockReason::Suspend)),
        Msg::Close | Msg::EndSession | Msg::SessionLogoff => Some(SystemAction::Shutdown),
        Msg::QueryEndSession => Some(SystemAction::AllowEndSession),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{SystemAction, system_action};
    use crate::lock::LockReason;
    use yw_win::ui::Msg;

    /// LK-3 (2026-11-21, S4 W1: moved from `lock::tests` unchanged).
    #[test]
    fn lk3_system_messages() {
        assert_eq!(
            system_action(&Msg::SessionDisconnect),
            Some(SystemAction::Lock(LockReason::SessionDisconnect))
        );
        assert_eq!(
            system_action(&Msg::SessionLock),
            Some(SystemAction::Lock(LockReason::SessionLock))
        );
        assert_eq!(
            system_action(&Msg::Suspend),
            Some(SystemAction::Lock(LockReason::Suspend))
        );
        assert_eq!(
            system_action(&Msg::SessionLogoff),
            Some(SystemAction::Shutdown)
        );
        assert_eq!(
            system_action(&Msg::EndSession),
            Some(SystemAction::Shutdown)
        );
        assert_eq!(system_action(&Msg::Close), Some(SystemAction::Shutdown));
        assert_eq!(
            system_action(&Msg::QueryEndSession),
            Some(SystemAction::AllowEndSession)
        );
        assert_eq!(system_action(&Msg::SessionUnlock), None);
        assert_eq!(system_action(&Msg::Resume), None);
    }
}
