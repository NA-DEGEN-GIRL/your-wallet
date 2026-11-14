//! UTC calendar helpers (civil ↔ days since 1970-01-01, H. Hinnant's algorithms) used for
//! approval time display (spec/03 §8.3) and SIWE date-times (§9.3). No OS clock: callers pass
//! `now_unix_ms`.

use crate::lang::Lang;

/// Days since 1970-01-01 of a proleptic Gregorian date.
#[must_use]
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = i64::from((month + 9) % 12);
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `(year, month, day)` of days since 1970-01-01.
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// Whether `day` exists in `month` of `year`.
#[must_use]
pub fn valid_date(year: i64, month: u32, day: u32) -> bool {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=last).contains(&day)
}

/// `YYYY-MM-DD HH:MM:SS UTC` of unix seconds.
#[must_use]
pub fn format_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        of_day / 3_600,
        of_day % 3_600 / 60,
        of_day % 60
    )
}

/// `YYYY-MM-DD HH:MM:SS UTC (약 N일 후/전)` (spec/03 §8.3; English `(in about N days)` /
/// `(about N days ago)`, spec/14 §4); under a day it uses hours/minutes.
#[must_use]
pub fn format_utc_relative(lang: Lang, seconds: i64, now_unix_ms: u64) -> String {
    let now = i64::try_from(now_unix_ms / 1_000).unwrap_or(i64::MAX);
    let delta = seconds.saturating_sub(now);
    let magnitude = delta.unsigned_abs();
    let (count, unit) = if magnitude >= 86_400 {
        (magnitude / 86_400, 0)
    } else if magnitude >= 3_600 {
        (magnitude / 3_600, 1)
    } else {
        (magnitude / 60, 2)
    };
    let template = match (delta >= 0, unit) {
        (true, 0) => IN_DAYS,
        (true, 1) => IN_HOURS,
        (true, _) => IN_MINUTES,
        (false, 0) => DAYS_AGO,
        (false, 1) => HOURS_AGO,
        (false, _) => MINUTES_AGO,
    };
    format!(
        "{} ({})",
        format_utc(seconds),
        template.fill(lang, [&count.to_string()])
    )
}

crate::texts! {
    IN_DAYS(1) = "약 {0}일 후" / "in about {0} days";
    IN_HOURS(1) = "약 {0}시간 후" / "in about {0} hours";
    IN_MINUTES(1) = "약 {0}분 후" / "in about {0} minutes";
    DAYS_AGO(1) = "약 {0}일 전" / "about {0} days ago";
    HOURS_AGO(1) = "약 {0}시간 전" / "about {0} hours ago";
    MINUTES_AGO(1) = "약 {0}분 전" / "about {0} minutes ago";
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, days_from_civil, format_utc, format_utc_relative, valid_date};
    use crate::lang::Lang;

    #[test]
    fn calendar_round_trips() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        for days in [-1_000_000_i64, -1, 0, 1, 11_016, 20_000, 2_932_896] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
        assert!(valid_date(2024, 2, 29));
        assert!(!valid_date(2023, 2, 29));
        assert!(!valid_date(1900, 2, 29));
        assert!(valid_date(2000, 2, 29));
        assert!(!valid_date(2026, 13, 1));
    }

    #[test]
    fn formatting() {
        // Sepolia amsterdam_time 1,791,294,816 = 2026-10-06 13:53:36 UTC (spec/03 §1.1).
        assert_eq!(format_utc(1_791_294_816), "2026-10-06 13:53:36 UTC");
        assert_eq!(
            format_utc_relative(Lang::Ko, 1_791_294_816 + 3 * 86_400, 1_791_294_816_000),
            "2026-10-09 13:53:36 UTC (약 3일 후)"
        );
        assert_eq!(
            format_utc_relative(Lang::Ko, 1_791_294_816 - 7_200, 1_791_294_816_000),
            "2026-10-06 11:53:36 UTC (약 2시간 전)"
        );
    }
}
