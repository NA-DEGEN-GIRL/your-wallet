//! Broker process entrypoint.
//!
//! Public IPC is deliberately disabled until the Windows SID/DACL and remote-
//! client rejection integration is attested. Exiting closed is safer than a
//! placeholder listener that accidentally becomes a signing boundary.

fn main() {
    std::process::exit(78);
}
