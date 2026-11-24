#![allow(unsafe_code)]
//! The fatal end of the Android shell (spec/15 §5.3, §3.3; D28): one `app.panic` log line (spec/04
//! §1.5, the same `yw_engine::logging::panic_line` as Windows: where, never the message), every live
//! slot wiped, then `_exit`. Not `abort`: SIGABRT makes debuggerd write a tombstone with stack and
//! register-adjacent memory even with `PR_SET_DUMPABLE 0` (P0-1 F1-2 measured it), and the Rust
//! default hook is not called (nothing goes to stderr). 2026-11-24 A2-1: the skeleton; the Java
//! uncaught-exception path joins it in A2-5, and the log sink is installed in A2-4b (until then the
//! line has nowhere to go and is dropped).

use yw_engine::logging;

/// The process exit status of a fatal end (`EX_SOFTWARE`).
const FATAL_EXIT: libc::c_int = 70;

/// Installs the hook. `JNI_OnLoad` calls it right after `prctl`, before anything else can panic.
pub(crate) fn install() {
    std::panic::set_hook(Box::new(|info| {
        logging::panic_line(info.location());
        fatal_end();
    }));
}

/// Wipes every slot and ends the process at once (no unwinding, no `atexit` handlers, no abort).
pub(crate) fn fatal_end() -> ! {
    crate::slot::wipe_all();
    // SAFETY: `_exit` takes an integer status and never returns; it reads no memory of ours.
    unsafe { libc::_exit(FATAL_EXIT) }
}
