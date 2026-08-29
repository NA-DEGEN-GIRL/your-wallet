#![cfg(all(
    feature = "runtime-contract-test-hook",
    not(feature = "service-helper-rpc-probe-feasibility-test-hook"),
    debug_assertions
))]

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use secret_input_ui::{PromptKind, SecretPrompt};

fn run_child(input: &[u8]) -> Result<Output, String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-input-ui"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "could not start secret-input-ui")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "secret-input-ui stdin was not piped".to_owned())?;
    // A fail-closed child can reject the anonymous streams before the writer
    // reaches this call. Either result is acceptable for this negative test.
    let _ = stdin.write_all(input);
    drop(stdin);
    child
        .wait_with_output()
        .map_err(|_| "could not collect secret-input-ui output".to_owned())
}

fn prompt() -> SecretPrompt {
    SecretPrompt::new(PromptKind::UnlockPassword, "blue comet".to_owned())
        .unwrap_or_else(|_| unreachable!("test prompt is canonical"))
}

#[test]
fn direct_launch_with_legacy_prompt_fails_silently() -> Result<(), String> {
    let request = secret_input_ui::encode_prompt(&prompt())
        .map_err(|_| "secret prompt was invalid".to_owned())?;
    let output = run_child(&request)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn trailing_request_byte_fails_without_output() -> Result<(), String> {
    let mut request = secret_input_ui::encode_prompt(&prompt())
        .map_err(|_| "secret prompt was invalid".to_owned())?;
    request.push(0);
    let output = run_child(&request)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}
