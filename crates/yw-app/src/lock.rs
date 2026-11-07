//! Automatic lock triggers (spec/04 §5, D12): the app-input idle tracker and the mapping of
//! session, power and shutdown messages to actions.

use yw_win::ui::Msg;

/// Why the wallet locked (logged as `lock reason=<…>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockReason {
    /// `잠금` button or Ctrl+L.
    Manual,
    /// No app input for `autoLockMinutes`.
    Idle,
    /// Windows session locked.
    SessionLock,
    /// User switch or remote disconnect.
    SessionDisconnect,
    /// Sleep / hibernate.
    Suspend,
    /// App shutdown.
    Shutdown,
}

impl LockReason {
    /// Log word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "Manual",
            Self::Idle => "Idle",
            Self::SessionLock => "SessionLock",
            Self::SessionDisconnect => "SessionDisconnect",
            Self::Suspend => "Suspend",
            Self::Shutdown => "Shutdown",
        }
    }
}

/// Idle check period.
pub const IDLE_CHECK_MS: u64 = 1_000;

/// App-input idle tracking. Only input to yw-app windows counts (never `GetLastInputInfo`);
/// while an approval or W08/W09 window is open the clock is paused. Closing one does not restart
/// the count: only user input does (a window that expired or was answered for the user — e.g. a
/// dApp's request nobody looked at — must not keep the wallet unlocked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleTracker {
    last_input_ms: u64,
    paused: bool,
}

impl IdleTracker {
    /// Starts counting at `now_ms`.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            last_input_ms: now_ms,
            paused: false,
        }
    }

    /// Key or button input to a yw-app window (and unlock success).
    pub const fn input(&mut self, now_ms: u64) {
        self.last_input_ms = now_ms;
    }

    /// Pauses while a self-timed window is open. Resuming keeps the last input time: input to
    /// the window itself (approve, reject, scrolling) already counted through [`Self::input`].
    pub const fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    /// Whether `minutes` of app inactivity have passed.
    #[must_use]
    pub const fn should_lock(&self, now_ms: u64, minutes: u8) -> bool {
        let limit = (minutes as u64).saturating_mul(60_000);
        !self.paused && now_ms.saturating_sub(self.last_input_ms) >= limit
    }
}

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

/// Session, power and shutdown mapping (spec/04 §1.5, §5.1; LK-3).
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
    use super::{IdleTracker, LockReason, SystemAction, system_action};
    use yw_win::ui::Msg;

    #[test]
    fn lk1_idle_threshold_and_pause() {
        let minutes = 3_u8;
        let limit = 180_000_u64;
        let idle = IdleTracker::new(1_000);
        assert!(!idle.should_lock(1_000 + limit - 1_000, minutes));
        assert!(idle.should_lock(1_000 + limit, minutes));
        // Input to other applications never reaches `input`, so the wallet still locks.
        let mut idle = IdleTracker::new(0);
        idle.input(10_000);
        assert!(idle.should_lock(10_000 + limit, minutes));
        // An approval window open across the whole period: no lock while it is open.
        let mut idle = IdleTracker::new(0);
        idle.set_paused(true);
        assert!(!idle.should_lock(limit * 2, minutes));
        // It closed by itself (expired, or a dApp request answered without the user): the count
        // is not restarted — the wallet locks at once.
        idle.set_paused(false);
        assert!(idle.should_lock(limit * 2, minutes));
        // The user answered it: that click is input, the count starts there.
        let mut idle = IdleTracker::new(0);
        idle.set_paused(true);
        idle.input(limit * 2);
        idle.set_paused(false);
        assert!(!idle.should_lock(limit * 3 - 1, minutes));
        assert!(idle.should_lock(limit * 3, minutes));
    }

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
