//! One-shot Approval Frontend process.
//!
//! Ordinary builds remain disabled until the Key Agent can prove an authenticated
//! private parent/channel and an immutable helper image before launch. The
//! `runtime-entrypoint` feature only defines the child-side authenticated
//! inherited-stream contract. On Windows the child first seals its exact
//! inherited synchronous server pipe objects while the parent retains the
//! overlapped client ends. It then checks LPAC and Job policy, correlates the two
//! pipe-client PID/session reports with a live same-session process proof, and
//! requires case-preserving exact normalized path-string equality between that
//! process image path and a separate held file path before checking the held
//! path's executable suffix and version metadata and performing held-handle-
//! backed Authenticode and SHA-256 policy checks.
//! PID/session correlation is not an exact endpoint/process-object
//! capability, and path equality plus held-file checks do not prove that the
//! live process was mapped from that exact file object. Signed release-path
//! positive evidence covering case-sensitive directories and alternate path
//! forms, immutable installation, the complete DLL/dependency graph,
//! supervisor-held activation capability, and endpoint topology/exclusivity
//! remain release blockers. There are zero production orchestration callers
//! composing `launch_approval_frontend` through a verified response into signing,
//! and no positive signed-handshake E2E exists. `COMPILED_PARENT_POLICY` remains
//! `None`; ordinary builds exit 78, and raw or legacy runtime launch fails
//! without diagnostics.

#[cfg(feature = "runtime-entrypoint")]
mod bootstrap;

#[cfg(not(feature = "runtime-entrypoint"))]
const PRIVATE_LAUNCH_UNAVAILABLE: i32 = 78;

#[cfg(not(feature = "runtime-entrypoint"))]
fn main() {
    std::process::exit(PRIVATE_LAUNCH_UNAVAILABLE);
}

#[cfg(feature = "runtime-entrypoint")]
const RUNTIME_FAILURE: i32 = 1;

#[cfg(feature = "runtime-entrypoint")]
fn main() {
    let exit_code = match run_once() {
        Ok(()) => 0,
        Err(_) => RUNTIME_FAILURE,
    };
    std::process::exit(exit_code);
}

#[cfg(feature = "runtime-entrypoint")]
fn run_once() -> Result<(), approval_ui::ApprovalError> {
    let authenticated = bootstrap::authenticate_inherited_parent()?;
    let request = authenticated.request();

    #[cfg(all(feature = "runtime-contract-test-hook", debug_assertions))]
    let decision = approval_ui::Decision::Reject;
    #[cfg(not(all(feature = "runtime-contract-test-hook", debug_assertions)))]
    let decision = approval_ui::present(request)?;
    let response = approval_ui::ApprovalResponse::for_request(decision, request);
    let output = std::io::stdout();
    let mut writer = output.lock();
    let result = approval_ui::write_response(&mut writer, response);
    drop(writer);
    drop(authenticated);
    result
}
