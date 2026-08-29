//! Dormant one-shot Windows Key Agent debugger transport feasibility helper.
//!
//! Ordinary and release builds are intentionally unavailable. The explicit
//! debug-only hook accepts one fixed inherited-handle protocol. Its debugger
//! mode can create one suspended copy of this executable in an inert, exact
//! target-only mode; neither mode performs a Windows debug API operation.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(all(windows, feature = "transport-feasibility-test-hook", debug_assertions))]
#[allow(unsafe_code)]
mod child;

#[cfg(all(windows, feature = "transport-feasibility-test-hook", debug_assertions))]
mod target;

#[cfg(all(windows, feature = "transport-feasibility-test-hook", debug_assertions))]
fn main() {
    if target::is_exact_invocation(std::env::args_os().skip(1)) {
        target::run();
    }
    std::process::exit(child::run().code());
}

#[cfg(not(all(windows, feature = "transport-feasibility-test-hook", debug_assertions)))]
fn main() {
    std::process::exit(key_agent_debugger_wire::DebuggerExitCode::Disabled.code());
}

#[cfg(test)]
mod tests {
    use key_agent_debugger_wire::DebuggerExitCode;

    #[test]
    fn unavailable_exit_category_is_stable() {
        assert_eq!(DebuggerExitCode::Disabled.code(), 78);
    }
}
