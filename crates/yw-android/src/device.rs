//! The device facts of this process and the warning bands they give (spec/15 §1.1, §8.2, §17;
//! 2026-11-25 A2-5). The decisions are yw-engine's `protection`; this module keeps the last facts
//! the Java side sent (the interim facts input, `crate::interim::facts`) and the build's
//! test-build constant.
//!
//! - [`TEST_BUILD`]: every build before A5 is a test build (spec/15 §17: no tap-jacking or
//!   accessibility defences yet), so every screen shows the test-build band. A build-time
//!   constant, never a setting; A5 changes it.
//! - [`bands_with`]: the bands of a surface from the facts that came with this open, never from
//!   facts kept from before (2026-11-25 A2-5 review, A2 plan critic 25: `adb_enabled` and
//!   `adb_wifi_enabled` change while the app runs, so a secret or approval screen that forgot to
//!   send them must not show stale ones; before, `bands(surface, now)` read the newest facts of the
//!   process, from any time). No facts with the open (`None`: none sent, or a facts input that did
//!   not parse) is the worst case (`protection::bands`).
//! - Facts that came are also kept ([`current`], for what does not change while the process runs,
//!   such as the tier of the settings screen, A7); the first ones write one log line with the
//!   tier, the API level and whether the patch is old (no patch date, no setting).
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
fn record(facts: DeviceFacts, now_unix_ms: u64) {
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

/// The newest facts, if any were sent (a poisoned lock reads as none). Never for the bands: the
/// debugging settings in them may be stale (module doc).
#[must_use]
pub fn current() -> Option<DeviceFacts> {
    FACTS.lock().ok().and_then(|kept| *kept)
}

/// The bands of `surface` now, from `fresh`, the facts the shell read for this open (kept too, as
/// the newest); `None` is the worst case (module doc).
#[must_use]
pub fn bands_with(fresh: Option<DeviceFacts>, surface: Surface, now_unix_ms: u64) -> Vec<Band> {
    if let Some(facts) = fresh {
        record(facts, now_unix_ms);
    }
    protection::bands(fresh.as_ref(), surface, TEST_BUILD, now_unix_ms)
}

#[cfg(test)]
mod tests {
    use yw_engine::protection::{Band, DeviceFacts, PatchDate, Surface};

    use super::{TEST_BUILD, bands_with, current};

    /// 2026-11-25T00:00:00Z.
    const NOW: u64 = 1_795_564_800_000;

    /// spec/15 §17: every build before A5 shows the test-build band. A5 turns this off together
    /// with this test.
    #[test]
    fn builds_before_a5_are_test_builds() {
        const { assert!(TEST_BUILD) };
    }

    /// The facts of the open decide; without them the worst case, even after facts were kept
    /// (2026-11-25 A2-5 review). The only test that records, so the order inside it is the order
    /// of the process.
    #[test]
    fn only_the_facts_of_the_open_decide() {
        assert_eq!(current(), None);
        let worst = [Band::TestBuild, Band::WeakDevice, Band::Debugging];
        assert_eq!(bands_with(None, Surface::Secret, NOW), worst);
        assert_eq!(current(), None);
        let device = DeviceFacts {
            sdk: 36,
            patch: PatchDate::parse("2026-10-01"),
            adb: true,
            adb_wifi: false,
        };
        assert_eq!(
            bands_with(Some(device), Surface::Main, NOW),
            [Band::TestBuild]
        );
        assert_eq!(
            bands_with(Some(device), Surface::Secret, NOW),
            [Band::TestBuild, Band::Debugging]
        );
        let off = DeviceFacts {
            adb: false,
            ..device
        };
        assert_eq!(
            bands_with(Some(off), Surface::Secret, NOW),
            [Band::TestBuild]
        );
        assert_eq!(current(), Some(off));
        // Kept facts with debugging off never hide the band of an open that sent none.
        assert_eq!(bands_with(None, Surface::Secret, NOW), worst);
        assert_eq!(bands_with(None, Surface::Approval, NOW), worst);
        assert_eq!(
            bands_with(None, Surface::Main, NOW),
            [Band::TestBuild, Band::WeakDevice]
        );
        assert_eq!(current(), Some(off), "a worst-case open keeps the facts");
    }
}
