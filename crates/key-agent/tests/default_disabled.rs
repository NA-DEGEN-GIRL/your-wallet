//! Release-disabled Key Agent executable contract.

use std::process::Command;

#[test]
fn ordinary_binary_remains_silent_and_release_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_key-agent"))
        .output()
        .map_err(|_| "could not run key-agent")?;

    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}
