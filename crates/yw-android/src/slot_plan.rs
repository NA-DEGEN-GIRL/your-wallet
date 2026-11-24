//! Locked-slot arithmetic (spec/15 §5.3): how many bytes one slot maps and whether the locked total
//! stays inside the budget. Platform-neutral (no `unsafe`), so the gate's Windows build tests it; the
//! Android `slot` module calls it with `sysconf(_SC_PAGESIZE)` and `getrlimit(RLIMIT_MEMLOCK)`.
//!
//! The budget is the smaller of the process `RLIMIT_MEMLOCK` and the 64 KiB design limit: P0-1
//! measured exactly 64 KiB in an app process on API 35 and 64 MiB on the test device (API 29), and
//! the slots must fit the smaller one on every device, so a device with more does not hide a plan
//! that would fail elsewhere (2026-11-24 A2-1). A slot that does not fit is not made, and the vault
//! is not unlocked (fail closed, like E-VLT-007).
#![forbid(unsafe_code)]

/// The design limit of locked memory (spec/15 §5.3): what current Android gives an app process.
pub const DESIGN_LIMIT: usize = 64 * 1024;

/// The most slots alive at once (the panic hook wipes them from a fixed table).
pub const MAX_SLOTS: usize = 16;

/// Smallest and largest page size accepted (4 KiB and 16 KiB devices exist; 64 KiB is the
/// largest Linux page on arm64).
const PAGE_MIN: usize = 4 * 1024;
const PAGE_MAX: usize = 64 * 1024;

/// The bytes one slot of `need` bytes maps: `need` rounded up to whole pages of `page`. `None` when
/// `page` is not a power of two in 4 KiB..=64 KiB, `need` is 0, or the sum overflows.
#[must_use]
pub fn slot_bytes(page: usize, need: usize) -> Option<usize> {
    if !page.is_power_of_two() || !(PAGE_MIN..=PAGE_MAX).contains(&page) || need == 0 {
        return None;
    }
    need.checked_next_multiple_of(page)
}

/// The locked-memory budget: the smaller of the process limit (`None` = `RLIM_INFINITY`) and
/// [`DESIGN_LIMIT`].
#[must_use]
pub fn budget(limit: Option<u64>) -> usize {
    limit.map_or(DESIGN_LIMIT, |limit| {
        usize::try_from(limit).map_or(DESIGN_LIMIT, |limit| limit.min(DESIGN_LIMIT))
    })
}

/// Whether `more` bytes can be locked on top of `locked` under `limit` ([`budget`]).
#[must_use]
pub fn fits(limit: Option<u64>, locked: usize, more: usize) -> bool {
    locked
        .checked_add(more)
        .is_some_and(|total| total <= budget(limit))
}

#[cfg(test)]
mod tests {
    use super::{DESIGN_LIMIT, MAX_SLOTS, budget, fits, slot_bytes};

    /// `yw_core::vault::SLOT_LEN` (2,304 bytes, the DEK slot) is one page on 4 KiB and 16 KiB
    /// devices.
    #[test]
    fn the_dek_slot_is_one_page() {
        let need = yw_core::vault::SLOT_LEN;
        assert_eq!(need, 2_304);
        assert_eq!(slot_bytes(4_096, need), Some(4_096));
        assert_eq!(slot_bytes(16_384, need), Some(16_384));
        assert_eq!(slot_bytes(4_096, 4_096), Some(4_096));
        assert_eq!(slot_bytes(4_096, 4_097), Some(8_192));
    }

    #[test]
    fn odd_page_sizes_and_empty_slots_are_refused() {
        for page in [0, 1, 512, 2_048, 4_095, 6_144, 131_072, usize::MAX] {
            assert_eq!(slot_bytes(page, 1), None, "{page}");
        }
        assert_eq!(slot_bytes(4_096, 0), None);
        assert_eq!(slot_bytes(4_096, usize::MAX), None);
    }

    /// The budget is never more than the design limit, and a smaller process limit wins.
    #[test]
    fn budget_is_the_smaller_limit() {
        assert_eq!(budget(None), DESIGN_LIMIT);
        assert_eq!(
            budget(Some(64 * 1024 * 1024)),
            DESIGN_LIMIT,
            "the test device's 64 MiB"
        );
        assert_eq!(budget(Some(65_536)), 65_536, "API 35's 64 KiB");
        assert_eq!(budget(Some(16_384)), 16_384);
        assert_eq!(budget(Some(0)), 0);
        assert_eq!(budget(Some(u64::MAX)), DESIGN_LIMIT);
    }

    #[test]
    fn fits_counts_what_is_locked() {
        assert!(fits(Some(65_536), 0, 4_096));
        assert!(fits(Some(65_536), 61_440, 4_096));
        assert!(!fits(Some(65_536), 61_441, 4_096));
        assert!(!fits(Some(0), 0, 4_096), "no locked memory: no slot");
        assert!(!fits(None, usize::MAX, 1));
        assert!(fits(None, 0, DESIGN_LIMIT));
        assert!(!fits(None, 0, DESIGN_LIMIT + 1));
        // The slot table holds as many one-page (4 KiB) slots as the design limit.
        assert_eq!(MAX_SLOTS * 4_096, DESIGN_LIMIT);
    }
}
