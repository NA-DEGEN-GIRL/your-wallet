//! Test observation points in the wallet code (hidden; 2026-11-23, spec/15 §11.4 S4d E0b, S4d
//! preflight O-4, 주인 상시 결정(2026-11-21): 권고안).
//!
//! The wallet code notes a [`Probe`] at the two points the secret characterization logs from
//! inside the wallet (`s4_secret/{secret,lock}.txt`): a display secret wiped because its window
//! was refused or failed, and an approval window's close. A note carries kinds, flags and counts
//! only, never a value, and does nothing unless a test thread installed a sink. Before E0b these
//! were `#[cfg(test)]` calls into the yw-app seam `app::secret_seam`, which would vanish once the
//! wallet code is compiled as a dependency of yw-app's tests (`cfg(test)` does not cross crates).
//!
//! Production installs no sink: the only installer is the yw-app test seam
//! (`app::secret_seam::install_probe`, `cfg(test)`), pinned by the source check
//! `the_probe_is_installed_only_by_tests`. A note with no sink reads one thread-local and
//! returns.

use core::cell::Cell;

/// One observation of the wallet code (kinds, flags, counts; never a value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// `Wallet::drop_display_secret` wiped the display secret of a refused or failed window.
    DisplayDropped,
    /// `Wallet::close_approval_window` ran: whether a flow was shown, and how many effects were
    /// queued before it (the shell applies them first, then this close).
    ApprovalClose {
        /// An approval flow was shown.
        shown: bool,
        /// Effects queued before the close.
        queued: usize,
    },
}

thread_local! {
    static SINK: Cell<Option<fn(Probe)>> = const { Cell::new(None) };
}

/// Installs `sink` for this thread's notes (`None` removes it) and returns the previous one.
/// Test seams only (source check `the_probe_is_installed_only_by_tests`).
#[must_use = "the previous sink, for a test that restores it"]
pub fn install(sink: Option<fn(Probe)>) -> Option<fn(Probe)> {
    SINK.with(|slot| slot.replace(sink))
}

/// Notes `probe` to this thread's sink, if a test installed one.
pub fn note(probe: Probe) {
    if let Some(sink) = SINK.try_with(Cell::get).ok().flatten() {
        sink(probe);
    }
}
