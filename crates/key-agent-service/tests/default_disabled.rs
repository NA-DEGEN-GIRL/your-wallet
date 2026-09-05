//! Fail-closed executable contract for the inert SCM feasibility binary.

use std::process::Command;

#[test]
fn direct_launch_is_silent_and_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_key-agent-service")).output()?;

    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[cfg(not(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "desktop-rpc-probe-feasibility-test-hook"
)))]
#[test]
fn desktop_probe_default_or_release_is_silent_before_rpc() -> Result<(), Box<dyn std::error::Error>>
{
    let output = Command::new(env!("CARGO_BIN_EXE_key-agent-service-probe")).output()?;
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "desktop-rpc-probe-feasibility-test-hook"
))]
#[test]
fn desktop_probe_rejects_arguments_before_rpc() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_key-agent-service-probe"))
        .arg("UNSUPPORTED_ARGUMENT_MUST_NOT_BE_ECHOED")
        .output()?;
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout == b"SERVICE_APPROVAL_TRANSPORT_UNAVAILABLE\n");
    assert!(output.stderr.is_empty());
    Ok(())
}
