//! Key Agent process entrypoint.
//!
//! The production inherited-channel and Windows sandbox launcher are a Phase-zero
//! stop-ship item. This binary refuses to run standalone, ensuring no public or
//! accidental raw-sign interface exists while that evidence is absent.

fn main() {
    std::process::exit(78);
}
