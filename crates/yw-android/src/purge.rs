#![allow(unsafe_code)]
//! `mallopt(M_PURGE, 0)` right after every Argon2 run (spec/15 §5.3, §18 45; 2026-11-25 A2-4b):
//! bionic keeps the 256 MiB that yw-core's `derive_kek` freed (its contents already zero), and
//! without giving it back the memory check before the next Argon2 refuses falsely (P0-3 F3-1).
//!
//! `libc` 0.2.189 declares neither `mallopt` for Android nor `M_PURGE`, so both are written here
//! from the NDK r30 `sysroot/usr/include/malloc.h`: `int mallopt(int __option, int __value)` and
//! `#define M_PURGE (-101)` (API 28+, the value is ignored). This is the one exception to the
//! rule that `libc`'s declarations are used, not hand-copied ones (spec/15 §4.1). A wrong value
//! would not merely fail to purge: the neighbouring options change the allocator's hardening
//! (-102 `M_MEMTAG_TUNING`, -103 `M_THREAD_DISABLE_MEM_INIT`, -203 `M_BIONIC_ZERO_INIT`,
//! -204 `M_BIONIC_SET_HEAP_TAGGING_LEVEL`, where value 0 turns heap tagging off). So the value is
//! pinned by the source check `purge_is_the_one_mallopt` (lib tests), and [`purge`] takes no option
//! argument: nothing else calls `mallopt` (the same check).

use core::ffi::c_int;

/// NDK r30 `malloc.h`: `#define M_PURGE (-101)`.
const M_PURGE: c_int = -101;

unsafe extern "C" {
    /// bionic `int mallopt(int __option, int __value)` (NDK r30 `malloc.h`).
    fn mallopt(option: c_int, value: c_int) -> c_int;
}

/// Gives freed heap memory back to the system; `false` when bionic says it failed (`mallopt`
/// returns 1 on success, 0 on error). The caller logs a fixed event on failure.
pub(crate) fn purge() -> bool {
    // SAFETY: bionic's `mallopt` takes two integers and reads no memory of ours; `M_PURGE` (with
    // its ignored value 0) only releases free pages of the allocator.
    let done = unsafe { mallopt(M_PURGE, 0) };
    done == 1
}
