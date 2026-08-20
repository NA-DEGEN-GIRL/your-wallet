#![cfg(not(feature = "runtime-entrypoint"))]

use std::process::Command;

#[test]
fn ordinary_binary_exits_unavailable_without_io() -> Result<(), String> {
    let output = Command::new(env!("CARGO_BIN_EXE_secret-input-ui"))
        .output()
        .map_err(|_| "could not run secret-input-ui")?;

    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}
