//! The memory check before every Argon2id run on Android (spec/15 §5.3, §18 45; 2026-11-25 A2-4b).
//!
//! Android does not fail an allocation when memory runs out: lmkd kills the process. So before a
//! call that runs Argon2id (m = 256 MiB, unchanged, D7) the shell asks Java for the memory facts
//! (`ActivityManager.MemoryInfo`, `isLowRamDevice()`; an I/O request, Rust never calls Java) and
//! [`gate`] decides:
//!
//! - [`Gate::Unsupported`]: `isLowRamDevice()` or `totalMem` < 3 GiB — the device cannot hold a
//!   vault (no vault is made or opened);
//! - [`Gate::LowNow`]: `lowMemory` or `availMem − threshold` < 512 MiB — not now (close other
//!   apps and try again);
//! - [`Gate::Go`] otherwise.
//!
//! Right after every Argon2 run the shell gives the freed 256 MiB back with `mallopt(M_PURGE)`
//! (`crate::purge`, Android only): without it the second Argon2 of a process held about 586 MB
//! and the third unlock was refused falsely (P0-3 F3-1). There is no bypass for tests.
//!
//! The answer body (little-endian, 25 bytes): `totalMem` u64 ‖ `availMem` u64 ‖ `threshold` u64 ‖
//! flags u8 (bit 0 `lowMemory`, bit 1 `isLowRamDevice()`, the other bits 0). Java's `IoFrame`
//! builds the same bytes (`JvmTests`). Platform-neutral: tested on the Windows gate.
#![forbid(unsafe_code)]

/// `totalMem` below this: unsupported device.
pub const MIN_TOTAL: u64 = 3 * 1024 * 1024 * 1024;
/// `availMem − threshold` below this: not now.
pub const MIN_HEADROOM: u64 = 512 * 1024 * 1024;
/// The answer body's length.
pub const FACTS_LEN: usize = 25;

/// `ActivityManager` facts at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryFacts {
    /// `MemoryInfo.totalMem`.
    pub total: u64,
    /// `MemoryInfo.availMem`.
    pub avail: u64,
    /// `MemoryInfo.threshold` (where lmkd starts killing background work).
    pub threshold: u64,
    /// `MemoryInfo.lowMemory`.
    pub low_memory: bool,
    /// `ActivityManager.isLowRamDevice()`.
    pub low_ram_device: bool,
}

/// What [`gate`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Run Argon2.
    Go,
    /// Not now: too little free memory (or the system says memory is low).
    LowNow,
    /// Never on this device.
    Unsupported,
}

/// The decision for `facts` (module doc).
#[must_use]
pub const fn gate(facts: MemoryFacts) -> Gate {
    if facts.low_ram_device || facts.total < MIN_TOTAL {
        return Gate::Unsupported;
    }
    if facts.low_memory {
        return Gate::LowNow;
    }
    match facts.avail.checked_sub(facts.threshold) {
        Some(headroom) if headroom >= MIN_HEADROOM => Gate::Go,
        _ => Gate::LowNow,
    }
}

/// Reads Java's answer body; `None` unless it is exactly [`FACTS_LEN`] bytes with no unknown
/// flag bit (a malformed answer is no answer: the caller does not run Argon2).
#[must_use]
pub fn parse(body: &[u8]) -> Option<MemoryFacts> {
    let bytes = <&[u8; FACTS_LEN]>::try_from(body).ok()?;
    let (total, rest) = bytes.split_first_chunk::<8>()?;
    let (avail, rest) = rest.split_first_chunk::<8>()?;
    let (threshold, rest) = rest.split_first_chunk::<8>()?;
    let [flags] = rest else {
        return None;
    };
    if flags & !0b11 != 0 {
        return None;
    }
    Some(MemoryFacts {
        total: u64::from_le_bytes(*total),
        avail: u64::from_le_bytes(*avail),
        threshold: u64::from_le_bytes(*threshold),
        low_memory: flags & 1 != 0,
        low_ram_device: flags & 2 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::{FACTS_LEN, Gate, MIN_HEADROOM, MIN_TOTAL, MemoryFacts, gate, parse};

    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;

    fn facts(total: u64, avail: u64, threshold: u64, low: bool, low_ram: bool) -> MemoryFacts {
        MemoryFacts {
            total,
            avail,
            threshold,
            low_memory: low,
            low_ram_device: low_ram,
        }
    }

    /// The spec/15 §5.3 table, with the test device's figures (P0-3: `totalMem` ≈ 3.56 GiB,
    /// `availMem` 1.2–1.5 GB with a large cached process, `threshold` 332 800 000 B).
    #[test]
    fn the_table() {
        let rows = [
            // total, avail, threshold, lowMemory, lowRam → gate
            (
                3_736_464 * 1024,
                1_400 * MIB,
                317 * MIB,
                false,
                false,
                Gate::Go,
            ),
            (
                3_736_464 * 1024,
                700 * MIB,
                317 * MIB,
                false,
                false,
                Gate::LowNow,
            ),
            (
                3_736_464 * 1024,
                1_400 * MIB,
                317 * MIB,
                true,
                false,
                Gate::LowNow,
            ),
            (
                3_736_464 * 1024,
                1_400 * MIB,
                317 * MIB,
                false,
                true,
                Gate::Unsupported,
            ),
            (MIN_TOTAL, MIN_HEADROOM + 100, 100, false, false, Gate::Go),
            (MIN_TOTAL - 1, 8 * GIB, 0, false, false, Gate::Unsupported),
            (8 * GIB, MIN_HEADROOM + 100, 101, false, false, Gate::LowNow),
            (8 * GIB, 100, 200, false, false, Gate::LowNow),
            (8 * GIB, 0, 0, false, false, Gate::LowNow),
            (0, 0, 0, false, false, Gate::Unsupported),
            (u64::MAX, u64::MAX, 0, false, false, Gate::Go),
        ];
        for (total, avail, threshold, low, low_ram, want) in rows {
            assert_eq!(
                gate(facts(total, avail, threshold, low, low_ram)),
                want,
                "{total} {avail} {threshold} {low} {low_ram}"
            );
        }
        assert_eq!(MIN_TOTAL, 3 * GIB);
        assert_eq!(MIN_HEADROOM, 512 * MIB);
    }

    #[test]
    fn the_answer_bytes() {
        let mut body = Vec::new();
        body.extend_from_slice(&(3 * GIB).to_le_bytes());
        body.extend_from_slice(&(GIB).to_le_bytes());
        body.extend_from_slice(&(200 * MIB).to_le_bytes());
        body.push(0b10);
        assert_eq!(body.len(), FACTS_LEN);
        assert_eq!(
            parse(&body),
            Some(facts(3 * GIB, GIB, 200 * MIB, false, true))
        );
        body[24] = 0b01;
        assert_eq!(parse(&body).map(|facts| facts.low_memory), Some(true));
        body[24] = 0b100;
        assert_eq!(parse(&body), None, "an unknown flag bit");
        assert_eq!(parse(&body[..24]), None);
        body[24] = 0;
        body.push(0);
        assert_eq!(parse(&body), None);
        assert_eq!(parse(&[]), None);
    }
}
