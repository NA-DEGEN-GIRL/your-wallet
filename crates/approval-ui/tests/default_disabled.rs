#![cfg(any(
    all(
        not(feature = "service-helper-rpc-probe-feasibility-test-hook"),
        not(feature = "runtime-entrypoint")
    ),
    all(
        feature = "service-helper-rpc-probe-feasibility-test-hook",
        not(all(windows, target_arch = "x86_64", target_env = "msvc", debug_assertions))
    )
))]

use std::process::Command;

#[test]
fn ordinary_binary_exits_unavailable_without_io() -> Result<(), String> {
    let output = Command::new(env!("CARGO_BIN_EXE_approval-ui"))
        .output()
        .map_err(|_| "could not run approval-ui")?;

    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}
