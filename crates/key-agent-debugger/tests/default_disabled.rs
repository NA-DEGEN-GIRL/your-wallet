//! Fail-closed executable contract for the debugger feasibility helper.

#[cfg(any(
    not(feature = "transport-feasibility-test-hook"),
    not(debug_assertions)
))]
use std::process::Command;

#[cfg(any(
    not(feature = "transport-feasibility-test-hook"),
    not(debug_assertions)
))]
fn assert_silent_and_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_key-agent-debugger")).output()?;

    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[cfg(not(feature = "transport-feasibility-test-hook"))]
#[test]
fn direct_launch_is_silent_and_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    assert_silent_and_unavailable()
}

#[cfg(all(feature = "transport-feasibility-test-hook", not(debug_assertions)))]
#[test]
fn release_hook_launch_is_silent_and_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    assert_silent_and_unavailable()
}
