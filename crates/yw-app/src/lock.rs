//! Automatic lock triggers (spec/04 §5, D12): the lock reasons and the app-input idle tracker.
//! Wallet code: no Windows type (source check `the_lock_module_names_no_shell`).
//!
//! 2026-11-21 (S4 W1, spec/15 §11.4 S4, plan §3.3): the mapping of the Windows session, power
//! and shutdown messages to actions (`SystemAction`, `system_action`, with its test LK-3) moved
//! to the shell's `shell_msg`; before, this file held it and named `yw_win::ui::Msg`.

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
/// dApp's request nobody looked at — must not keep the wallet unlocked). One pause per input:
/// a window shown after another one without input in between (a page re-sending its requests
/// as each expires) does not pause again, so unattended windows extend the session once, never
/// indefinitely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleTracker {
    last_input_ms: u64,
    /// The window that pauses the clock now.
    paused: Option<u64>,
    /// No window has paused the clock since the last input.
    pause_left: bool,
}

impl IdleTracker {
    /// Starts counting at `now_ms`.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            last_input_ms: now_ms,
            paused: None,
            pause_left: true,
        }
    }

    /// Key or button input to a yw-app window (and unlock success).
    pub const fn input(&mut self, now_ms: u64) {
        self.last_input_ms = now_ms;
        self.pause_left = true;
    }

    /// The self-timed window open now (`Some(identity)`, `None` when none is). A window pauses
    /// the clock when it is the one already pausing it, or when no window has paused it since
    /// the last input. Resuming keeps the last input time: input to the window itself (approve,
    /// reject, scrolling) already counted through [`Self::input`].
    pub const fn set_window(&mut self, window: Option<u64>) {
        self.paused = match (window, self.paused) {
            (Some(window), Some(paused)) if window == paused => Some(window),
            (Some(window), _) if self.pause_left => {
                self.pause_left = false;
                Some(window)
            }
            _ => None,
        };
    }

    /// Whether `minutes` of app inactivity have passed.
    #[must_use]
    pub const fn should_lock(&self, now_ms: u64, minutes: u8) -> bool {
        let limit = (minutes as u64).saturating_mul(60_000);
        self.paused.is_none() && now_ms.saturating_sub(self.last_input_ms) >= limit
    }
}

#[cfg(test)]
mod tests {
    use super::IdleTracker;

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
        idle.set_window(Some(1));
        assert!(!idle.should_lock(limit * 2, minutes));
        // It closed by itself (expired, or a dApp request answered without the user): the count
        // is not restarted — the wallet locks at once.
        idle.set_window(None);
        assert!(idle.should_lock(limit * 2, minutes));
        // The user answered it: that click is input, the count starts there, and the next
        // window pauses again.
        let mut idle = IdleTracker::new(0);
        idle.set_window(Some(1));
        idle.input(limit * 2);
        idle.set_window(None);
        assert!(!idle.should_lock(limit * 3 - 1, minutes));
        assert!(idle.should_lock(limit * 3, minutes));
        idle.set_window(Some(2));
        assert!(!idle.should_lock(limit * 4, minutes));
        // Windows nobody touches, shown back to back (a page re-sending each request as it
        // expires): the first pauses, the next one does not — the wallet locks.
        let mut idle = IdleTracker::new(0);
        idle.set_window(Some(1));
        assert!(!idle.should_lock(limit * 2, minutes));
        idle.set_window(Some(2));
        assert!(idle.should_lock(limit * 2, minutes));
        // Input while it is shown (the user reads and scrolls it): it pauses again.
        idle.input(limit * 2);
        idle.set_window(Some(2));
        assert!(!idle.should_lock(limit * 4, minutes));
    }

    /// 2026-11-21 (S4 W1): the lock reasons and the idle tracker are wallet code; the Win32
    /// message mapping is the shell's (`shell_msg::system_action`). Code lines only (comments
    /// dropped), split so that this test's own text does not match.
    #[test]
    fn the_lock_module_names_no_shell() {
        let code: String = include_str!("lock.rs")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(code.contains("pub struct IdleTracker"), "found the file");
        for shell in [
            concat!("yw_", "win"),
            concat!("Ms", "g::"),
            concat!("system_", "action"),
        ] {
            assert!(!code.contains(shell), "lock.rs names {shell}");
        }
    }
}
