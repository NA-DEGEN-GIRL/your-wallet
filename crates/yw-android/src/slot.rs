#![allow(unsafe_code)]
//! `LockedSlot` pages on Android (spec/15 §5.3, [02] §7.3, D10): an anonymous private `mmap`, locked
//! with `mlock` and kept out of core dumps with `madvise(MADV_DONTDUMP)`. Any failure is returned
//! and nothing is unlocked with it (fail closed, like E-VLT-007). The size is
//! `yw_core::vault::SLOT_LEN` rounded up to `sysconf(_SC_PAGESIZE)`, and the locked total stays
//! inside [`slot_plan::budget`] of `getrlimit(RLIMIT_MEMLOCK)`.
//!
//! Every live slot is in a fixed table so that the panic hook can wipe them all ([`wipe_all`])
//! without a lock (the panicking thread may hold one). An entry is claimed with a compare-and-swap
//! before it is wiped, by the hook or by `Drop`, so the hook never writes to a page that `Drop` is
//! unmapping. 2026-11-24 A2-1.

use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering, compiler_fence};
use std::sync::Mutex;

use yw_core::vault::{LockedSlot, SLOT_LEN};

use crate::slot_plan::{self, MAX_SLOTS};

/// Entry states.
const FREE: u8 = 0;
/// Being made or being dropped by one thread (the hook leaves it alone).
const BUSY: u8 = 1;
/// Mapped, locked and handed out.
const LIVE: u8 = 2;
/// Wiped by the panic hook; the process is ending.
const WIPED: u8 = 3;

struct Entry {
    state: AtomicU8,
    addr: AtomicPtr<u8>,
    len: AtomicUsize,
}

impl Entry {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(FREE),
            addr: AtomicPtr::new(core::ptr::null_mut()),
            len: AtomicUsize::new(0),
        }
    }
}

static TABLE: [Entry; MAX_SLOTS] = [const { Entry::new() }; MAX_SLOTS];

/// Makes and frees slots one at a time, so the budget check and the table entry agree. The panic
/// hook does not take it.
static ALLOC: Mutex<()> = Mutex::new(());

/// Why no slot was made. The kinds only: no address, no errno text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError {
    /// `sysconf(_SC_PAGESIZE)` gave no usable page size.
    PageSize,
    /// `getrlimit(RLIMIT_MEMLOCK)` failed.
    Limit,
    /// The slot does not fit the locked-memory budget.
    Budget,
    /// Every table entry is in use.
    Full,
    /// Another slot operation panicked (the process is ending).
    Busy,
    /// `mmap` failed.
    Map,
    /// `mlock` failed.
    Lock,
    /// `madvise(MADV_DONTDUMP)` failed.
    Advise,
}

impl fmt::Display for SlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PageSize => "no usable page size",
            Self::Limit => "locked-memory limit unreadable",
            Self::Budget => "locked-memory budget exceeded",
            Self::Full => "slot table full",
            Self::Busy => "slot allocator unavailable",
            Self::Map => "page mapping failed",
            Self::Lock => "page locking failed",
            Self::Advise => "dump exclusion failed",
        })
    }
}

impl std::error::Error for SlotError {}

/// Overwrites `buf` with zeros using volatile writes followed by a `SeqCst` compiler fence (as
/// yw-win `mem::wipe`; spec/01 §5.3).
fn wipe(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference into `buf`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// The page size, checked by [`slot_plan::slot_bytes`].
fn page_size() -> Option<usize> {
    // SAFETY: `sysconf` takes an integer name and reads no memory of ours.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(page).ok()
}

/// `RLIMIT_MEMLOCK` (soft), `None` for `RLIM_INFINITY`.
fn memlock_limit() -> Result<Option<u64>, SlotError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` that outlives the call.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) };
    if result != 0 {
        return Err(SlotError::Limit);
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return Ok(None);
    }
    Ok(Some(limit.rlim_cur))
}

/// Unlocks and unmaps a region made by [`map_locked`] (its contents already wiped).
fn unmap(base: NonNull<u8>, len: usize) {
    // SAFETY: `base..base+len` is a region this module mapped and locked; unlocking it has no
    // other effect on memory.
    unsafe { libc::munlock(base.as_ptr().cast_const().cast(), len) };
    // SAFETY: The region is no longer referenced: its only owner is giving it up.
    unsafe { libc::munmap(base.as_ptr().cast(), len) };
}

/// Maps `len` zeroed bytes, locks them and excludes them from dumps; on any failure nothing is left
/// mapped.
fn map_locked(len: usize) -> Result<NonNull<u8>, SlotError> {
    // SAFETY: Requests a fresh anonymous private mapping; no existing memory is referenced.
    let raw = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(SlotError::Map);
    }
    let base = NonNull::new(raw.cast::<u8>()).ok_or(SlotError::Map)?;
    // SAFETY: `base..base+len` is the region just mapped.
    let locked = unsafe { libc::mlock(base.as_ptr().cast_const().cast(), len) };
    if locked != 0 {
        // SAFETY: The region was mapped above and nothing references it.
        unsafe { libc::munmap(base.as_ptr().cast(), len) };
        return Err(SlotError::Lock);
    }
    // SAFETY: Advises on the region just mapped; `MADV_DONTDUMP` changes no contents.
    let advised = unsafe { libc::madvise(base.as_ptr().cast(), len, libc::MADV_DONTDUMP) };
    if advised != 0 {
        unmap(base, len);
        return Err(SlotError::Advise);
    }
    Ok(base)
}

/// One locked slot of `SLOT_LEN` bytes on its own page(s). Drop wipes the whole region, unlocks
/// and unmaps it.
pub struct AndroidSlot {
    base: NonNull<u8>,
    len: usize,
    entry: usize,
}

impl AndroidSlot {
    /// Makes a zeroed slot.
    ///
    /// # Errors
    ///
    /// [`SlotError`]: no page size or limit, over the budget, the table full, or a failing
    /// `mmap`/`mlock`/`madvise`. Nothing stays mapped or locked then.
    pub fn new() -> Result<Self, SlotError> {
        let len = page_size()
            .and_then(|page| slot_plan::slot_bytes(page, SLOT_LEN))
            .ok_or(SlotError::PageSize)?;
        let limit = memlock_limit()?;
        let _guard = ALLOC.lock().map_err(|_| SlotError::Busy)?;
        let locked: usize = TABLE
            .iter()
            .filter(|entry| entry.state.load(Ordering::Acquire) != FREE)
            .map(|entry| entry.len.load(Ordering::Acquire))
            .sum();
        if !slot_plan::fits(limit, locked, len) {
            return Err(SlotError::Budget);
        }
        let entry = TABLE
            .iter()
            .position(|entry| {
                entry
                    .state
                    .compare_exchange(FREE, BUSY, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            })
            .ok_or(SlotError::Full)?;
        let Some(slot) = TABLE.get(entry) else {
            return Err(SlotError::Full);
        };
        match map_locked(len) {
            Ok(base) => {
                slot.addr.store(base.as_ptr(), Ordering::Release);
                slot.len.store(len, Ordering::Release);
                slot.state.store(LIVE, Ordering::Release);
                Ok(Self { base, len, entry })
            }
            Err(error) => {
                slot.state.store(FREE, Ordering::Release);
                Err(error)
            }
        }
    }
}

impl LockedSlot for AndroidSlot {
    fn bytes(&self) -> &[u8; SLOT_LEN] {
        // SAFETY: The region holds `len >= SLOT_LEN` initialized bytes (zeroed by `mmap`) owned by
        // `self`, aligned for `u8`; a shared borrow of `self` only allows shared access.
        unsafe { &*self.base.as_ptr().cast::<[u8; SLOT_LEN]>() }
    }

    fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
        // SAFETY: As in `bytes`; `&mut self` guarantees exclusive access.
        unsafe { &mut *self.base.as_ptr().cast::<[u8; SLOT_LEN]>() }
    }
}

impl Drop for AndroidSlot {
    fn drop(&mut self) {
        let Some(entry) = TABLE.get(self.entry) else {
            return;
        };
        if entry
            .state
            .compare_exchange(LIVE, BUSY, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // The panic hook claimed it (wiped, the process is ending): leave the page mapped.
            return;
        }
        // SAFETY: The region holds `len` initialized bytes exclusively owned by `self`, and the
        // claimed entry keeps the hook away from it.
        let whole = unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.len) };
        wipe(whole);
        let guard = ALLOC.lock();
        unmap(self.base, self.len);
        entry.addr.store(core::ptr::null_mut(), Ordering::Release);
        entry.len.store(0, Ordering::Release);
        entry.state.store(FREE, Ordering::Release);
        drop(guard);
    }
}

// SAFETY: `AndroidSlot` exclusively owns its private mapping (no pointer to it escapes except through
// borrows of `self`; the table keeps only the address for the panic hook), so moving it to another
// thread is sound (`LockedSlot: Send`).
unsafe impl Send for AndroidSlot {}

impl fmt::Debug for AndroidSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AndroidSlot({} bytes, [REDACTED])", self.len)
    }
}

/// Wipes every live slot (the panic hook and the other fatal ends, spec/15 §5.3). Takes no lock:
/// each live entry is claimed with a compare-and-swap and left claimed, since the process ends right
/// after. A slot being made or dropped at that moment is skipped (new pages are zero; a dropping one
/// is being wiped by its owner).
pub(crate) fn wipe_all() {
    for entry in &TABLE {
        if entry
            .state
            .compare_exchange(LIVE, WIPED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        let addr = entry.addr.load(Ordering::Acquire);
        let len = entry.len.load(Ordering::Acquire);
        let Some(base) = NonNull::new(addr) else {
            continue;
        };
        // No slice is formed: another thread may still hold a borrow of the slot, and the hook
        // writes through the raw pointer only.
        for offset in 0..len {
            let byte = base.as_ptr().wrapping_add(offset);
            // SAFETY: A LIVE entry names a mapped, writable region of `len` bytes that stays mapped
            // while the entry is claimed (`Drop` unmaps only after it claims the entry itself), and
            // `offset < len`. The process ends right after this wipe, which is its purpose.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use yw_core::vault::LockedSlot;

    use super::{AndroidSlot, SlotError, wipe_all};
    use crate::slot_plan::{DESIGN_LIMIT, MAX_SLOTS};

    /// `VmLck` of this process, in kB.
    fn locked_kb() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status
            .lines()
            .find(|line| line.starts_with("VmLck:"))
            .unwrap();
        line.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    /// Android only, run by hand on a device or the emulator (spec/09 §2.6; 2026-11-24 A2-1):
    /// one test, because the slot table is process-wide. A slot is locked, zeroed, writable and
    /// redacted; slots are made until one is refused, which must be the budget, the table or the
    /// lock (fail closed) and never more than the design limit; dropping gives the room back; the
    /// panic path's `wipe_all` zeroes a live slot, after which its drop leaves it mapped.
    #[test]
    fn slots_are_locked_bounded_and_wiped() {
        let before = locked_kb();
        let mut first = AndroidSlot::new().expect("one slot");
        assert!(first.bytes().iter().all(|byte| *byte == 0));
        first.bytes_mut()[0] = 0xAA;
        first.bytes_mut()[yw_core::vault::SLOT_LEN - 1] = 0x55;
        assert_eq!(first.bytes()[0], 0xAA);
        assert!(format!("{first:?}").ends_with("bytes, [REDACTED])"));
        assert!(locked_kb() >= before + 4, "the slot's page is locked");

        let mut more = Vec::new();
        let refused = loop {
            match AndroidSlot::new() {
                Ok(slot) => more.push(slot),
                Err(error) => break error,
            }
            assert!(more.len() < MAX_SLOTS, "the table bounds the slots");
        };
        assert!(
            matches!(
                refused,
                SlotError::Budget | SlotError::Full | SlotError::Lock
            ),
            "{refused:?}"
        );
        assert!((more.len() + 1) * first.len <= DESIGN_LIMIT);
        drop(more);
        let again = AndroidSlot::new().expect("room again after a drop");
        drop(again);

        wipe_all();
        assert!(first.bytes().iter().all(|byte| *byte == 0), "wiped");
        // The entry stays claimed by the hook, so this drop leaves the page mapped (the process
        // would have ended); the test process ends soon after.
        drop(first);
    }
}
