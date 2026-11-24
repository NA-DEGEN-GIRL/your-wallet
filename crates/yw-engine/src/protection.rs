//! The Android protection tier and the warning bands (spec/15 §1.1, §8.2, §17 A5 note;
//! 2026-11-25 A2-5). Pure decisions over the facts the platform shell reads and passes in
//! ([`DeviceFacts`]): the shell asks nothing here and this module reads no clock (the caller
//! passes the time). Windows never draws these bands (it has no tier); the Android shell draws
//! [`bands`] on every screen it builds.
//!
//! - [`Tier`]: from the API level alone (spec/15 §1.1 table): 36+ `완전`, 34–35 `기본`, 31–33
//!   `약함`, below 31 `시험용` (the build's floor is API 29; anything lower reads as `시험용` too).
//! - [`Band::TestBuild`]: every screen of every build before A5 (spec/15 §17: no tap-jacking or
//!   accessibility defences yet); the shell passes `test_build` from a build-time constant.
//! - [`Band::WeakDevice`]: every screen when the tier is `약함` or `시험용`, or the security patch
//!   (`Build.VERSION.SECURITY_PATCH`) is more than one year before today, or unknown (fail toward
//!   the warning: a patch string the shell could not read never hides it). It warns and never
//!   blocks (`spec.md` §2.3).
//! - [`Band::Debugging`]: the secret and approval screens while `adb_enabled` or
//!   `adb_wifi_enabled` is on (spec/15 §8.2). Those two settings change while the app runs, so the
//!   shell passes fresh facts whenever such a screen opens (A2 plan critic 25), not only at start.
//!
//! No facts yet (`None`) reads as the worst case: the weak-device band, and the debugging band
//! where it applies.

use yw_core::lang::Lang;

use crate::logging::format_utc;
use crate::screen::Tone;
use crate::screen::model::Item;

/// The texts of the tier names and the bands (spec/14 §5; spec/15 §1.1, §8.2).
pub mod text {
    yw_core::texts! {
        /// Tier name, API 36+ (spec/15 §1.1).
        TIER_FULL = "완전" / "Full";
        /// Tier name, API 34–35.
        TIER_BASIC = "기본" / "Basic";
        /// Tier name, API 31–33.
        TIER_WEAK = "약함" / "Weak";
        /// Tier name, API 29–30.
        TIER_TEST = "시험용" / "Test only";
        /// The band of every build before A5 (spec/15 §17): no real phrase, no real funds.
        BAND_TEST_BUILD = "시험용 빌드입니다. 실제 복구 단어와 실제 자금을 쓰지 마세요"
            / "This is a test build. Do not use a real recovery phrase or real funds.";
        /// The weak-protection band (spec/15 §1.1).
        BAND_WEAK_DEVICE = "이 기기는 보호가 약합니다(시험용으로만 쓰세요)"
            / "This device's protection is weak (use it for testing only).";
        /// The debugging band of the secret and approval screens (spec/15 §8.2).
        BAND_DEBUGGING = "USB·무선 디버깅이 켜져 있습니다. 컴퓨터가 대신 누를 수 있습니다"
            / "USB or wireless debugging is on. A computer can press buttons for you.";
    }
}

/// The protection tier of the device (spec/15 §1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// API 36+.
    Full,
    /// API 34–35.
    Basic,
    /// API 31–33.
    Weak,
    /// API 30 and below.
    Test,
}

impl Tier {
    /// The tier of an API level (`Build.VERSION.SDK_INT`).
    #[must_use]
    pub const fn of_sdk(sdk: u32) -> Self {
        match sdk {
            36.. => Self::Full,
            34..=35 => Self::Basic,
            31..=33 => Self::Weak,
            _ => Self::Test,
        }
    }

    /// The tier's word in the log (never translated).
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Basic => "basic",
            Self::Weak => "weak",
            Self::Test => "test",
        }
    }

    /// The tier's name on the screen (settings → security, spec/15 §1.1).
    #[must_use]
    pub const fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::Full => text::TIER_FULL,
            Self::Basic => text::TIER_BASIC,
            Self::Weak => text::TIER_WEAK,
            Self::Test => text::TIER_TEST,
        }
        .get(lang)
    }

    /// `약함` or `시험용`: the weak-device band applies.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(self, Self::Weak | Self::Test)
    }
}

/// A security patch date, `YYYY-MM-DD` (`Build.VERSION.SECURITY_PATCH`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatchDate {
    year: u16,
    month: u8,
    day: u8,
}

impl PatchDate {
    /// Parses exactly `YYYY-MM-DD` (year 2000–9999, month 1–12, day 1–31); anything else is
    /// `None` (the shell then passes no date, which reads as old).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }
        let number = |range: core::ops::Range<usize>| -> Option<u16> {
            let part = text.get(range)?;
            if !part.bytes().all(|unit| unit.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let year = number(0..4)?;
        let month = u8::try_from(number(5..7)?).ok()?;
        let day = u8::try_from(number(8..10)?).ok()?;
        ((2_000..=9_999).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day))
            .then_some(Self { year, month, day })
    }

    /// The UTC calendar day of `unix_ms`.
    fn of_unix_ms(unix_ms: u64) -> Option<Self> {
        Self::parse(format_utc(unix_ms).get(..10)?)
    }

    /// The day count of the date (days since 1 March of year 0, proleptic Gregorian; only
    /// differences are used). A day past the month's end (`2021-02-31`) counts on into the next
    /// month.
    fn day_number(self) -> u32 {
        // Year 2000–9999 only (`parse`), so nothing here can overflow or go below zero.
        let month = u32::from(self.month);
        let year = u32::from(self.year) - u32::from(month <= 2);
        let era = year / 400;
        let year_of_era = year - era * 400;
        let month_from_march = (month + 9) % 12;
        let day_of_year = (153 * month_from_march + 2) / 5 + u32::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era
    }

    /// More than one year before `today`: `today` is after the same day one year later (a
    /// 29 February patch is old from 1 March of the next year). A `today` more than
    /// [`CLOCK_MARGIN_DAYS`] before the patch date is a clock that cannot be right and reads as
    /// old too (2026-11-25 A2-5 review; before, any clock before the patch read as not old).
    fn is_old_on(self, today: Self) -> bool {
        if today.day_number().saturating_add(CLOCK_MARGIN_DAYS) < self.day_number() {
            return true;
        }
        let year_later = Self {
            year: self.year.saturating_add(1),
            ..self
        };
        today > year_later
    }
}

/// How far the clock may be before the security patch date and still be trusted: vendors set
/// patch dates up to about two months ahead (2026-11-25 A2-5 review). A clock earlier than that
/// (reset to a firmware build date, moved back by hand) is unknown, so the patch reads as old.
const CLOCK_MARGIN_DAYS: u32 = 62;

/// What the shell read from the device (spec/15 §1.1, §8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceFacts {
    /// `Build.VERSION.SDK_INT`.
    pub sdk: u32,
    /// `Build.VERSION.SECURITY_PATCH`, `None` when it was not exactly `YYYY-MM-DD`.
    pub patch: Option<PatchDate>,
    /// `Settings.Global` `adb_enabled`.
    pub adb: bool,
    /// `Settings.Global` `adb_wifi_enabled` (API 30+; off on API 29).
    pub adb_wifi: bool,
}

impl DeviceFacts {
    /// The protection tier.
    #[must_use]
    pub const fn tier(&self) -> Tier {
        Tier::of_sdk(self.sdk)
    }

    /// The security patch is more than one year before the UTC day of `now_unix_ms`, or unknown.
    /// A clock before 2000 cannot be compared and reads as old too, and so does a clock more than
    /// 62 days before the patch date (2026-11-25 A2-5 review; before, any clock before the patch
    /// date read as not old).
    #[must_use]
    pub fn patch_is_old(&self, now_unix_ms: u64) -> bool {
        match (self.patch, PatchDate::of_unix_ms(now_unix_ms)) {
            (Some(patch), Some(today)) => patch.is_old_on(today),
            (None, _) | (_, None) => true,
        }
    }

    /// USB or wireless debugging is on.
    #[must_use]
    pub const fn debugging(&self) -> bool {
        self.adb || self.adb_wifi
    }
}

/// Where the bands are drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// The main window's screens.
    Main,
    /// A secret window (W01–W12).
    Secret,
    /// An approval window.
    Approval,
}

/// One warning band (spec/15 §1.1, §8.2, §17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    /// A build before A5.
    TestBuild,
    /// Tier `약함`/`시험용` or an old (or unknown) security patch.
    WeakDevice,
    /// USB or wireless debugging on (secret and approval screens).
    Debugging,
}

impl Band {
    /// The band's text.
    #[must_use]
    pub const fn text(self, lang: Lang) -> &'static str {
        match self {
            Self::TestBuild => text::BAND_TEST_BUILD,
            Self::WeakDevice => text::BAND_WEAK_DEVICE,
            Self::Debugging => text::BAND_DEBUGGING,
        }
        .get(lang)
    }

    /// The band as a screen item: a `주의` banner that cannot be closed.
    #[must_use]
    pub fn item(self, lang: Lang) -> Item {
        Item::Banner(self.text(lang).to_owned(), Tone::Warn)
    }
}

/// The bands of one surface, top first: the test-build band, the weak-device band, then the
/// debugging band (module doc). `facts` `None` (not read yet) is the worst case.
#[must_use]
pub fn bands(
    facts: Option<&DeviceFacts>,
    surface: Surface,
    test_build: bool,
    now_unix_ms: u64,
) -> Vec<Band> {
    let weak = facts.is_none_or(|facts| facts.tier().is_weak() || facts.patch_is_old(now_unix_ms));
    let debugging = matches!(surface, Surface::Secret | Surface::Approval)
        && facts.is_none_or(DeviceFacts::debugging);
    let mut out = Vec::with_capacity(3);
    if test_build {
        out.push(Band::TestBuild);
    }
    if weak {
        out.push(Band::WeakDevice);
    }
    if debugging {
        out.push(Band::Debugging);
    }
    out
}

#[cfg(test)]
mod tests {
    use yw_core::lang::{Lang, has_hangul};

    use super::{Band, DeviceFacts, PatchDate, Surface, Tier, bands, text};
    use crate::screen::Tone;
    use crate::screen::model::Item;

    /// 2026-11-25T00:00:00Z.
    const NOW: u64 = 1_795_564_800_000;

    fn facts(sdk: u32, patch: &str, adb: bool, adb_wifi: bool) -> DeviceFacts {
        DeviceFacts {
            sdk,
            patch: PatchDate::parse(patch),
            adb,
            adb_wifi,
        }
    }

    #[test]
    fn the_now_constant_is_the_day_it_names() {
        assert_eq!(PatchDate::of_unix_ms(NOW), PatchDate::parse("2026-11-25"));
    }

    /// spec/15 §1.1: the tier is the API level's alone.
    #[test]
    fn tier_table() {
        for (sdk, tier) in [
            (0, Tier::Test),
            (28, Tier::Test),
            (29, Tier::Test),
            (30, Tier::Test),
            (31, Tier::Weak),
            (32, Tier::Weak),
            (33, Tier::Weak),
            (34, Tier::Basic),
            (35, Tier::Basic),
            (36, Tier::Full),
            (37, Tier::Full),
            (u32::MAX, Tier::Full),
        ] {
            assert_eq!(Tier::of_sdk(sdk), tier, "API {sdk}");
            assert_eq!(
                tier.is_weak(),
                matches!(tier, Tier::Weak | Tier::Test),
                "API {sdk}"
            );
        }
        assert_eq!(
            [Tier::Full, Tier::Basic, Tier::Weak, Tier::Test].map(Tier::word),
            ["full", "basic", "weak", "test"]
        );
        assert_eq!(Tier::Test.label(Lang::Ko), "시험용");
        assert_eq!(Tier::Full.label(Lang::En), "Full");
    }

    #[test]
    fn patch_dates_parse_exactly() {
        assert_eq!(
            PatchDate::parse("2021-01-01"),
            Some(PatchDate {
                year: 2021,
                month: 1,
                day: 1
            })
        );
        for bad in [
            "",
            "2021-1-01",
            "2021-01-1",
            "2021/01/01",
            "2021-00-01",
            "2021-13-01",
            "2021-01-00",
            "2021-01-32",
            "1999-12-31",
            "+021-01-01",
            "2021-+1-01",
            "2021-01-01 ",
            " 2021-01-01",
            "２０２１-01-01",
            "2021-01-01\0",
        ] {
            assert_eq!(PatchDate::parse(bad), None, "{bad:?}");
        }
    }

    /// "1년 넘게 지난": old from the day after the patch's first anniversary.
    #[test]
    fn a_patch_is_old_after_one_year() {
        for (patch, old) in [
            ("2025-11-25", false),
            ("2025-11-24", true),
            ("2025-11-26", false),
            ("2026-11-25", false),
            ("2027-01-01", false),
            ("2021-01-01", true),
        ] {
            assert_eq!(
                facts(36, patch, false, false).patch_is_old(NOW),
                old,
                "{patch}"
            );
        }
        // 29 February: one year later is 29 February of a common year, before 1 March.
        let leap = PatchDate::parse("2024-02-29").unwrap();
        assert!(!leap.is_old_on(PatchDate::parse("2025-02-28").unwrap()));
        assert!(leap.is_old_on(PatchDate::parse("2025-03-01").unwrap()));
        // Unknown patch reads as old, and so does a clock before 2000 or more than 62 days before
        // the patch (2026-11-25 A2-5 review: before, any clock before the patch read as not old;
        // 2020-01-01T00:00:00Z here).
        assert!(facts(36, "unknown", false, false).patch_is_old(NOW));
        assert!(facts(36, "2026-11-25", false, false).patch_is_old(0));
        assert!(facts(36, "2026-11-25", false, false).patch_is_old(1_577_836_800_000));
        // The margin: NOW (2026-11-25) is 62 days before 2027-01-26 and 63 before 2027-01-27.
        for (patch, old) in [
            ("2026-12-25", false),
            ("2027-01-25", false),
            ("2027-01-26", false),
            ("2027-01-27", true),
            ("2027-11-25", true),
            ("9999-12-31", true),
        ] {
            assert_eq!(
                facts(36, patch, false, false).patch_is_old(NOW),
                old,
                "clock before {patch}"
            );
        }
    }

    /// The day count agrees with the UTC calendar, across month, leap-day and century ends.
    #[test]
    fn day_numbers_count_days() {
        let day = |text: &str| PatchDate::parse(text).unwrap().day_number();
        for (earlier, later, days) in [
            ("2026-11-25", "2026-11-26", 1),
            ("2026-11-25", "2027-01-26", 62),
            ("2024-02-28", "2024-03-01", 2),
            ("2023-02-28", "2023-03-01", 1),
            ("2000-02-28", "2000-03-01", 2),
            ("2099-12-31", "2100-03-01", 60),
            ("2000-01-01", "2026-11-25", 9_825),
        ] {
            assert_eq!(day(later) - day(earlier), days, "{earlier} → {later}");
        }
        // The day count of NOW's day is its Unix day plus the fixed offset of 1 March year 0.
        assert_eq!(
            u64::from(day("2026-11-25")),
            NOW / 86_400_000 + 719_468,
            "Unix epoch offset"
        );
    }

    /// The band table: API × patch × adb × surface.
    #[test]
    fn band_table() {
        /// API, patch, `adb_enabled`, `adb_wifi_enabled`, surface, the bands.
        type Case = (u32, &'static str, bool, bool, Surface, &'static [Band]);
        use Band::{Debugging, TestBuild, WeakDevice};
        use Surface::{Approval, Main, Secret};
        let fresh = "2026-10-01";
        let old = "2021-01-01";
        let cases: &[Case] = &[
            // The test device of A2 (API 29, 2021 patch, USB debugging on).
            (29, old, true, false, Main, &[TestBuild, WeakDevice]),
            (
                29,
                old,
                true,
                false,
                Secret,
                &[TestBuild, WeakDevice, Debugging],
            ),
            (
                29,
                old,
                true,
                false,
                Approval,
                &[TestBuild, WeakDevice, Debugging],
            ),
            // The tier alone makes the weak band.
            (30, fresh, false, false, Main, &[TestBuild, WeakDevice]),
            (33, fresh, false, false, Secret, &[TestBuild, WeakDevice]),
            (34, fresh, false, false, Main, &[TestBuild]),
            (35, fresh, false, false, Secret, &[TestBuild]),
            (36, fresh, false, false, Approval, &[TestBuild]),
            // An old or unknown patch makes it on any tier.
            (36, old, false, false, Main, &[TestBuild, WeakDevice]),
            (36, "", false, false, Main, &[TestBuild, WeakDevice]),
            // Wireless debugging alone, and both; never on the main screens.
            (36, fresh, false, true, Secret, &[TestBuild, Debugging]),
            (36, fresh, true, true, Approval, &[TestBuild, Debugging]),
            (36, fresh, true, true, Main, &[TestBuild]),
        ];
        for &(sdk, patch, adb, adb_wifi, surface, want) in cases {
            let facts = facts(sdk, patch, adb, adb_wifi);
            assert_eq!(
                bands(Some(&facts), surface, true, NOW),
                want,
                "{facts:?} {surface:?}"
            );
            let without: Vec<Band> = want.iter().copied().filter(|b| *b != TestBuild).collect();
            assert_eq!(
                bands(Some(&facts), surface, false, NOW),
                without,
                "after A5: {facts:?} {surface:?}"
            );
        }
    }

    #[test]
    fn no_facts_is_the_worst_case() {
        assert_eq!(
            bands(None, Surface::Main, true, NOW),
            [Band::TestBuild, Band::WeakDevice]
        );
        assert_eq!(
            bands(None, Surface::Secret, false, NOW),
            [Band::WeakDevice, Band::Debugging]
        );
        assert_eq!(
            bands(None, Surface::Approval, false, NOW),
            [Band::WeakDevice, Band::Debugging]
        );
    }

    #[test]
    fn bands_are_warning_banners_in_both_languages() {
        for band in [Band::TestBuild, Band::WeakDevice, Band::Debugging] {
            for lang in [Lang::Ko, Lang::En] {
                assert_eq!(
                    band.item(lang),
                    Item::Banner(band.text(lang).to_owned(), Tone::Warn)
                );
            }
            assert!(has_hangul(band.text(Lang::Ko)));
            assert!(!has_hangul(band.text(Lang::En)));
        }
        assert_eq!(
            Band::WeakDevice.text(Lang::Ko),
            "이 기기는 보호가 약합니다(시험용으로만 쓰세요)",
            "spec/15 §1.1"
        );
        assert_eq!(
            Band::Debugging.text(Lang::Ko),
            "USB·무선 디버깅이 켜져 있습니다. 컴퓨터가 대신 누를 수 있습니다",
            "spec/15 §8.2"
        );
        assert_eq!(text::ALL.len(), 7);
    }
}
