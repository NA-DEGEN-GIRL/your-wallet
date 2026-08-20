#![cfg(all(feature = "runtime-contract-test-hook", debug_assertions))]

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use approval_ui::{
    ApprovalDisplay, ApprovalRequest, Decision, DisplayField, FieldSemantic, OperationKind,
    RiskLevel, SimulationStatus,
};

fn field(semantic: FieldSemantic, value: &str) -> Result<DisplayField, String> {
    DisplayField::new(semantic, value, semantic != FieldSemantic::SimulationEngine)
        .map_err(|_| "invalid display field".to_owned())
}

fn valid_request() -> Result<ApprovalRequest, String> {
    let display = ApprovalDisplay::new(
        RiskLevel::High,
        vec![
            field(
                FieldSemantic::NoSimulationWarning,
                "No simulation was performed.",
            )?,
            field(FieldSemantic::Origin, "https://example.test")?,
            field(
                FieldSemantic::PersonalMessageWarning,
                "Personal signatures can be reused by protocols.",
            )?,
            field(
                FieldSemantic::Account,
                "0x1111111111111111111111111111111111111111",
            )?,
            field(FieldSemantic::NetworkName, "Ethereum")?,
            field(FieldSemantic::ChainId, "1")?,
            field(
                FieldSemantic::GenesisHash,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )?,
            field(
                FieldSemantic::RulesetRevision,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )?,
            field(
                FieldSemantic::RpcObservationsDigest,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )?,
            field(
                FieldSemantic::OperationKind,
                OperationKind::PersonalMessage.value(),
            )?,
            field(FieldSemantic::PersonalMessageBytes, "0x0102")?,
            field(
                FieldSemantic::SimulationStatus,
                SimulationStatus::NotPerformed.value(),
            )?,
            field(
                FieldSemantic::OriginProvenance,
                "Browser-reported; not independently verified",
            )?,
            field(
                FieldSemantic::OriginWarning,
                "Browser origin is not independently attested.",
            )?,
        ],
    )
    .map_err(|_| "invalid display fixture".to_owned())?;
    ApprovalRequest::new([7; 32], [9; 32], 120_000, "blue comet", display)
        .map_err(|_| "invalid request fixture".to_owned())
}

fn run_child(input: &[u8]) -> Result<Output, String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_approval-ui"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "could not start approval-ui")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "approval-ui stdin was not piped".to_owned())?;
    stdin
        .write_all(input)
        .map_err(|_| "could not write approval request".to_owned())?;
    drop(stdin);
    child
        .wait_with_output()
        .map_err(|_| "could not collect approval-ui output".to_owned())
}

#[test]
fn inherited_stream_contract_is_exact_and_silent() -> Result<(), String> {
    let request = valid_request()?;
    let request_bytes = approval_wire::encode_request(&request);
    let output = run_child(&request_bytes)?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response = approval_wire::decode_response(&output.stdout)
        .map_err(|_| "approval response was malformed".to_owned())?;
    assert_eq!(response.decision(), Decision::Reject);
    assert_eq!(response.digest(), request.digest());
    assert_eq!(response.approval_nonce(), request.approval_nonce());
    Ok(())
}

#[test]
fn trailing_request_byte_fails_without_output() -> Result<(), String> {
    let request = valid_request()?;
    let mut request_bytes = approval_wire::encode_request(&request);
    request_bytes.push(0);
    let output = run_child(&request_bytes)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}
