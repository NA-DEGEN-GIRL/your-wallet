//! Key Agent process entrypoint.
//!
//! On Windows, the binary's only application operation seals the exact inherited
//! standard handles, proves the fixed storage-startup transcript, and then waits
//! for the supervisor to close its retained request endpoint. It always exits
//! fail-closed afterward; no public or accidental signing interface exists.

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
