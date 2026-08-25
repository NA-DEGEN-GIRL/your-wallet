//! Inert Windows Key Agent SCM feasibility executable.
//!
//! Ordinary and release builds are unavailable. The explicit debug-only hook
//! exercises only the fixed SCM lifecycle and contains no wallet operation.

#![cfg_attr(windows, windows_subsystem = "windows")]

const SERVICE_UNAVAILABLE: i32 = 78;

#[cfg(all(windows, feature = "scm-feasibility-test-hook", debug_assertions))]
fn main() {
    let exit_code =
        platform_windows::run_inert_key_agent_service_fixture().map_or(SERVICE_UNAVAILABLE, |()| 0);
    std::process::exit(exit_code);
}

#[cfg(not(all(windows, feature = "scm-feasibility-test-hook", debug_assertions)))]
fn main() {
    std::process::exit(SERVICE_UNAVAILABLE);
}
