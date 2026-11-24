//! yw-android: the Rust half of the Android shell, `libyw.so` (spec/15 §3, D4, D40).
//!
//! With yw-win, the second and last crate allowed `unsafe` (D4; spec/15 §3.1): only in FFI modules whose
//! first line is `#![allow(unsafe_code)]`, one unsafe operation per block, each with a `// SAFETY:`
//! comment (spec/01 §5.1). Those modules are compiled for Android only. On every other target (the
//! Windows gate, spec/15 §13) the crate is its platform-neutral helpers and their unit tests:
//! [`jni_table`] (the hand-declared JNI function-table indices and the five registered methods) and
//! [`slot_plan`] (the locked-slot size and budget arithmetic).
//!
//! 2026-11-24 A2-1 (spec/15 §17 A2): the skeleton. `JNI_OnLoad` calls `prctl(PR_SET_DUMPABLE, 0)`
//! first, installs the panic hook and registers the five methods of spec/15 §3.2 as stubs; `slot`
//! holds `LockedSlot` pages (`mmap` + `mlock` + `madvise(MADV_DONTDUMP)`, fail closed); the panic hook
//! writes the one `app.panic` line, wipes every live slot and `_exit`s. The engine, the wire format,
//! storage and the screens come in the later A2 steps.

pub mod jni_table;
pub mod slot_plan;

#[cfg(target_os = "android")]
mod jni;
#[cfg(target_os = "android")]
mod panic_hook;
#[cfg(target_os = "android")]
pub mod slot;
