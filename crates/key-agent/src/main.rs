//! Key Agent process entrypoint.
//!
//! The production inherited channel remains a stop-ship item. On Windows, the
//! binary nevertheless seals the exact three inherited standard handles before
//! any other application operation, preventing their accidental propagation to
//! a later descendant. It then remains fail-closed so no public or accidental
//! raw-sign interface exists while release evidence is absent.

#[cfg(windows)]
fn main() {
    let Ok(_sealed_stdio) = platform_windows::seal_inherited_key_agent_stdio() else {
        std::process::exit(78);
    };
    std::process::exit(78);
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(78);
}
