//! yw-android: the Rust half of the Android shell, `libyw.so` (spec/15 §3, D4, D40).
//!
//! With yw-win, the second and last crate allowed `unsafe` (D4; spec/15 §3.1): only in FFI modules whose
//! first line is `#![allow(unsafe_code)]`, one unsafe operation per block, each with a `// SAFETY:`
//! comment (spec/01 §5.1). Those modules are compiled for Android only. On every other target (the
//! Windows gate, spec/15 §13) the crate is its platform-neutral helpers and their unit tests:
//! [`jni_table`] (the hand-declared JNI function-table indices and the five registered methods) and
//! [`slot_plan`] (the locked-slot size and budget arithmetic), and since 2026-11-24 A2-3
//! [`interim`] (the fixed inputs `call` knows before the wire format of A2-6).
//!
//! 2026-11-24 A2-1 (spec/15 §17 A2): the skeleton. `JNI_OnLoad` calls `prctl(PR_SET_DUMPABLE, 0)`
//! first, installs the panic hook and registers the five methods of spec/15 §3.2 as stubs; `slot`
//! holds `LockedSlot` pages (`mmap` + `mlock` + `madvise(MADV_DONTDUMP)`, fail closed); the panic hook
//! wipes every live slot, writes the one `app.panic` line and `_exit`s (2026-11-24 A2-1 review: wipe
//! first; before, the line came first). `JNI_OnLoad` sets a loaded flag only after all five methods
//! are registered, and each method answers "nothing" without it. The engine, the wire format,
//! storage and the screens come in the later A2 steps.
//!
//! 2026-11-25 A2-4b (spec/15 §5.1–§5.3, §3.2): storage. Platform-neutral and tested on the gate:
//! [`io_request`] (the platform I/O requests `next`/`ioComplete` serve), [`device_key`] (the
//! Keystore device key as yw-core's `DeviceKey`, and the memory facts), [`sealed_files`] (the
//! `YWK2` envelope under yw-engine's `FileStorage`), [`storage`] (the key worker's platform and the
//! app store), [`kdf_gate`] (the memory check before Argon2) and [`log_file`] (the log file).
//! Android only: `android_files` (the std/`libc` `Files`), `purge` (`mallopt(M_PURGE)`), `shell`
//! (the broker, the data folder, the Argon2 wrapper) and, in a `-DeviceTest` debug build only,
//! `devtest` (the create → kill → reopen round trip).
//!
//! 2026-11-25 A2-5 (spec/15 §1.1, §3.3, §5.3, §8.2): [`device`] (the newest device facts from the
//! interim facts input and the build's test-build constant; the tier and band decisions are
//! yw-engine `protection`), Java's uncaught-exception end with its own log line
//! (`panic_hook::java_uncaught`), and in a `-DeviceTest` build the panic test's fault points
//! (`devtest::fault_points`).
//!
//! 2026-11-25 A2-7 (spec/15 §9.1–§9.2, §3.2, §18 42 N22·N23): the secret windows —
//! [`secret_host`] (the engine form's instance per window, the two-phase open with the display
//! host, the window model with fill handles, `secretFill`'s units), [`secret_keys`] (the app
//! keyboard's and the window buttons' map to the form's events) and [`secret_wire`] (the secret
//! windows' inputs and frames); `jni` gives `secretKey` and `secretFill` their bodies.
//!
//! 2026-11-25 A2-8 (spec/15 §5.3–§5.4, §17 A2): the wallet runs — `shell` starts the key worker
//! (its Argon2 calls behind the memory check and `M_PURGE`) and the RPC worker with no transport,
//! [`ui_host`] drains their events and composes the locks (manual, idle, screen off, background),
//! [`away`] keeps the time away for the background lock, and on Android the clock is
//! `CLOCK_BOOTTIME` (`boottime`, the clock of `elapsedRealtime`).

pub mod away;
pub mod clock;
pub mod device;
pub mod device_key;
pub mod interim;
pub mod io_request;
pub mod jni_table;
pub mod kdf_gate;
pub mod log_file;
pub mod sealed_files;
pub mod secret_host;
pub mod secret_keys;
pub mod secret_wire;
pub mod slot_plan;
pub mod storage;
pub mod ui_host;

#[cfg(target_os = "android")]
mod android_files;
#[cfg(target_os = "android")]
mod boottime;
#[cfg(all(target_os = "android", yw_device_test))]
mod devtest;
#[cfg(target_os = "android")]
mod jni;
#[cfg(target_os = "android")]
mod panic_hook;
#[cfg(target_os = "android")]
mod purge;
#[cfg(target_os = "android")]
mod shell;
#[cfg(target_os = "android")]
pub mod slot;

#[cfg(test)]
mod source_checks;
