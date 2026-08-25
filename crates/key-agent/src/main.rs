//! Key Agent process entrypoint.
//!
//! On Windows, the binary's only application operation seals the exact inherited
//! standard handles, proves the fixed storage-startup transcript through exact
//! request and response EOF, and then remains inert while the supervisor owns
//! its kill-on-close Job. Startup streams are closed and no public or
//! accidental signing interface exists.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    let Ok(()) = platform_windows::serve_inherited_key_agent_storage_startup() else {
        std::process::exit(78);
    };
    std::process::exit(78);
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(78);
}
