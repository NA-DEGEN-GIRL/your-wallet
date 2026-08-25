//! Windows Key Agent SCM feasibility executable.
//!
//! Ordinary and release builds are unavailable. The explicit debug-only hook
//! exercises either the inert lifecycle or bounded local-RPC status surface and
//! contains no wallet operation.

#![cfg_attr(windows, windows_subsystem = "windows")]

const SERVICE_UNAVAILABLE: i32 = 78;

#[cfg(all(
    windows,
    feature = "rpc-status-feasibility-test-hook",
    debug_assertions
))]
fn main() {
    let exit_code = platform_windows::run_status_rpc_key_agent_service_fixture()
        .map_or(SERVICE_UNAVAILABLE, |()| 0);
    std::process::exit(exit_code);
}

#[cfg(all(
    windows,
    not(feature = "rpc-status-feasibility-test-hook"),
    feature = "scm-feasibility-test-hook",
    debug_assertions
))]
fn main() {
    let exit_code =
        platform_windows::run_inert_key_agent_service_fixture().map_or(SERVICE_UNAVAILABLE, |()| 0);
    std::process::exit(exit_code);
}

#[cfg(not(any(
    all(
        windows,
        feature = "rpc-status-feasibility-test-hook",
        debug_assertions
    ),
    all(
        windows,
        not(feature = "rpc-status-feasibility-test-hook"),
        feature = "scm-feasibility-test-hook",
        debug_assertions
    )
)))]
fn main() {
    std::process::exit(SERVICE_UNAVAILABLE);
}
