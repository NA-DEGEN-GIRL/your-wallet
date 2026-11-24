//! The device facts of this process and the warning bands they give (spec/15 §1.1, §8.2, §17;
//! 2026-11-25 A2-5). The decisions are yw-engine's `protection`; this module keeps the last facts
//! the Java side sent (the interim facts input, `crate::interim::facts`) and the build's
//! test-build constant.
//!
//! - [`TEST_BUILD`]: every build before A5 is a test build (spec/15 §17: no tap-jacking or
//!   accessibility defences yet), so every screen shows the test-build band. A build-time
//!   constant, never a setting; A5 changes it.
//! - [`record`] keeps the newest facts (Java sends them at start and again whenever a screen that
//!   shows the debugging band could open, since `adb_enabled`/`adb_wifi_enabled` change while the
//!   app runs; A2 plan critic 25). The first record writes one log line with the tier, the API
//!   level and whether the patch is old (no patch date, no setting).
//! - [`bands`]: the bands of a surface from the newest facts; with none recorded yet, the worst
//!   case (`protection::bands`).
//!
//! Platform-neutral (no `unsafe`): the Windows gate tests it.
#![forbid(unsafe_code)]

use std::sync::Mutex;

use yw_engine::logging::{self, Field};
use yw_engine::protection::{self, Band, DeviceFacts, Surface};

/// Every build before A5 is a test build (module doc).
pub const TEST_BUILD: bool = true;

/// The newest facts.
static FACTS: Mutex<Option<DeviceFacts>> = Mutex::new(None);

/// Keeps `facts` as the newest; the first one is logged (module doc).
pub fn record(facts: DeviceFacts, now_unix_ms: u64) {
    let first = match FACTS.lock() {
        Ok(mut kept) => kept.replace(facts).is_none(),
        Err(_) => return,
    };
    if first {
        let yes_no = |yes: bool| Field::Word(if yes { "yes" } else { "no" });
        logging::info(
            "app",
            "device.facts",
            &[
                ("tier", Field::Word(facts.tier().word())),
                ("sdk", Field::Num(u64::from(facts.sdk))),
                ("old_patch", yes_no(facts.patch_is_old(now_unix_ms))),
            ],
        );
    }
}

/// The newest facts, if any were sent (a poisoned lock reads as none: the worst case).
#[must_use]
pub fn current() -> Option<DeviceFacts> {
    FACTS.lock().ok().and_then(|kept| *kept)
}

/// The bands of `surface` now (module doc).
#[must_use]
pub fn bands(surface: Surface, now_unix_ms: u64) -> Vec<Band> {
    protection::bands(current().as_ref(), surface, TEST_BUILD, now_unix_ms)
}

#[cfg(test)]
mod tests {
    use yw_engine::protection::{Band, DeviceFacts, PatchDate, Surface};

    use super::{TEST_BUILD, bands, current, record};

    /// 2026-11-25T00:00:00Z.
    const NOW: u64 = 1_795_564_800_000;

    /// spec/15 §17: every build before A5 shows the test-build band. A5 turns this off together
    /// with this test.
    #[test]
    fn builds_before_a5_are_test_builds() {
        const { assert!(TEST_BUILD) };
    }

    /// Before any facts the worst case; then the newest facts (the only test that records, so
    /// the order inside it is the order of the process).
    #[test]
    fn the_newest_facts_decide() {
        assert_eq!(current(), None);
        assert_eq!(
            bands(Surface::Secret, NOW),
            [Band::TestBuild, Band::WeakDevice, Band::Debugging]
        );
        let device = DeviceFacts {
            sdk: 36,
            patch: PatchDate::parse("2026-10-01"),
            adb: true,
            adb_wifi: false,
        };
        record(device, NOW);
        assert_eq!(bands(Surface::Main, NOW), [Band::TestBuild]);
        assert_eq!(
            bands(Surface::Secret, NOW),
            [Band::TestBuild, Band::Debugging]
        );
        record(
            DeviceFacts {
                adb: false,
                ..device
            },
            NOW,
        );
        assert_eq!(bands(Surface::Secret, NOW), [Band::TestBuild]);
        assert_eq!(current().map(|facts| facts.adb), Some(false));
    }
}
