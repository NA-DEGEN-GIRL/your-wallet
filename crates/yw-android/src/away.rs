//! The background lock's state (spec/15 §5.4, §18 42 N17; 2026-11-25 A2-8). Java sends `life back`
//! when no Activity of the app is started any more and `life front` when the first one starts
//! again (its started-Activity count, `dev.yw.app.Screen`; a secret window covering the main one is
//! not the background). The shell records when the app left ([`Away::back`]) on its clock, which on
//! Android counts deep sleep (`crate::clock`, `CLOCK_BOOTTIME`, the clock of
//! `SystemClock.elapsedRealtime()`).
//!
//! The app counts as in the background once the count has stayed 0 for [`SETTLE_MS`] (the spec's
//! allowance for late reports of other processes; A2 counts the main process only, and a new
//! Activity's `onStart` always came before the old one's `onStop`, P0-9). It locks when it has been
//! away [`SETTLE_MS`] + the background time (default [`BACKGROUND_LOCK_MS`], 0 = at once):
//!
//! - in the background, when Java's one-shot wake timer fires ([`Away::wake`]); a frozen or
//!   sleeping process may run it late or never, so
//! - on the way back, before anything is drawn ([`Away::front`]): the check runs first, the lock
//!   (when due) next, and only then the screen is drawn and Java shows it.
//!
//! Platform-neutral (no `unsafe`): the gate's Windows build tests it.
#![forbid(unsafe_code)]

/// How long the started-Activity count must stay 0 before the app counts as in the background.
pub const SETTLE_MS: u64 = 500;

/// The background time before the lock (spec/15 §5.4: 0–10 minutes, default 1 minute). A2 has no
/// settings screen on Android, so the default holds; the setting comes with the settings (A7).
pub const BACKGROUND_LOCK_MS: u64 = 60_000;

/// When the app left, and how often it came back (module doc).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Away {
    /// When the started-Activity count went to 0 (`None`: an Activity is started, or the lock it
    /// called for was done).
    left_at: Option<u64>,
    /// How many `front` events were handled (Java counts the ones it sent; the `shown` frame
    /// names this count, so Java shows the screen only after its own `front` was checked).
    fronts: u64,
}

impl Away {
    /// Not away, no `front` yet.
    pub const NEW: Self = Self {
        left_at: None,
        fronts: 0,
    };

    /// No Activity is started any more at `now`; returns the milliseconds until the lock is due
    /// (when Java's wake timer should fire). A second `back` keeps the first time.
    pub fn back(&mut self, now: u64, delay: u64) -> u64 {
        let left = *self.left_at.get_or_insert(now);
        lock_after(delay).saturating_sub(now.saturating_sub(left))
    }

    /// An Activity started again at `now`: whether the lock is due (the time away reached
    /// [`SETTLE_MS`] + `delay`). Away ends either way.
    pub fn front(&mut self, now: u64, delay: u64) -> bool {
        self.fronts = self.fronts.saturating_add(1);
        let due = self.due(now, delay);
        self.left_at = None;
        due
    }

    /// Java's wake timer fired at `now`: `Ok(true)` when the lock is due (away then ends: the
    /// lock is done), `Ok(false)` when the app is not away, `Err(rest)` when it is away but the
    /// lock is not due yet (wake again after `rest` milliseconds).
    ///
    /// # Errors
    ///
    /// The milliseconds still to wait.
    pub fn wake(&mut self, now: u64, delay: u64) -> Result<bool, u64> {
        let Some(left) = self.left_at else {
            return Ok(false);
        };
        if self.due(now, delay) {
            self.left_at = None;
            return Ok(true);
        }
        Err(lock_after(delay).saturating_sub(now.saturating_sub(left)))
    }

    /// The milliseconds until the lock is due (0 when it is due now), `None` when not away.
    #[must_use]
    pub fn remaining(&self, now: u64, delay: u64) -> Option<u64> {
        self.left_at
            .map(|left| lock_after(delay).saturating_sub(now.saturating_sub(left)))
    }

    /// How many `front` events were handled.
    #[must_use]
    pub const fn fronts(&self) -> u64 {
        self.fronts
    }

    /// Whether the app is away (an unanswered `back`).
    #[must_use]
    pub const fn is_away(&self) -> bool {
        self.left_at.is_some()
    }

    fn due(&self, now: u64, delay: u64) -> bool {
        self.left_at
            .is_some_and(|left| now.saturating_sub(left) >= lock_after(delay))
    }
}

/// The time away after which the lock is due.
#[must_use]
pub const fn lock_after(delay: u64) -> u64 {
    SETTLE_MS.saturating_add(delay)
}

#[cfg(test)]
mod tests {
    use super::{Away, BACKGROUND_LOCK_MS, SETTLE_MS, lock_after};

    #[test]
    fn a_short_absence_is_no_background() {
        let mut away = Away::default();
        assert_eq!(away.back(1_000, 0), SETTLE_MS);
        assert!(away.is_away());
        assert!(
            !away.front(1_000 + SETTLE_MS - 1, 0),
            "inside the settle time"
        );
        assert!(!away.is_away());
        assert_eq!(away.fronts(), 1);
        // With the default time: away for less than a minute (plus the settle time).
        let _ = away.back(5_000, BACKGROUND_LOCK_MS);
        assert!(!away.front(
            5_000 + lock_after(BACKGROUND_LOCK_MS) - 1,
            BACKGROUND_LOCK_MS
        ));
        assert_eq!(away.fronts(), 2);
    }

    #[test]
    fn the_lock_is_due_on_the_way_back() {
        let mut away = Away::default();
        // 0: at once once the app counts as in the background.
        let _ = away.back(1_000, 0);
        assert!(away.front(1_000 + SETTLE_MS, 0));
        // The default minute, the process frozen (no wake): checked before drawing.
        let wait = away.back(10_000, BACKGROUND_LOCK_MS);
        assert_eq!(wait, SETTLE_MS + BACKGROUND_LOCK_MS);
        assert!(away.front(10_000 + 3_600_000, BACKGROUND_LOCK_MS));
        assert!(
            !away.front(10_000 + 3_600_001, BACKGROUND_LOCK_MS),
            "away ended"
        );
    }

    #[test]
    fn the_wake_timer_locks_or_waits_again() {
        let mut away = Away::default();
        assert_eq!(away.wake(5, 0), Ok(false), "not away");
        let wait = away.back(100, BACKGROUND_LOCK_MS);
        // A second `back` keeps the first time.
        assert_eq!(away.back(200, BACKGROUND_LOCK_MS), wait - 100);
        assert_eq!(
            away.wake(100 + 30_000, BACKGROUND_LOCK_MS),
            Err(wait - 30_000)
        );
        assert_eq!(away.wake(100 + wait, BACKGROUND_LOCK_MS), Ok(true));
        assert!(!away.is_away(), "the lock ends away");
        assert_eq!(away.wake(100 + wait + 1, BACKGROUND_LOCK_MS), Ok(false));
        assert!(!away.front(100 + wait + 2, BACKGROUND_LOCK_MS));
    }
}
