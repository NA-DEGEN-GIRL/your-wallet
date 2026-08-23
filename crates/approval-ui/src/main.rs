//! One-shot Approval Frontend process.
//!
//! Ordinary builds remain disabled until the Key Agent can prove an authenticated
//! private parent/channel and an immutable helper image before launch. The
//! `runtime-entrypoint` feature only defines the child-side authenticated
//! inherited-stream contract. On Windows the child first seals its exact
//! inherited synchronous server pipe objects while the parent retains the
//! overlapped client ends. It then checks LPAC and Job policy and makes fresh
//! child-local duplicates of the two injected proof handles. Only those copies
//! become authoritative and remain retained through response write; the
//! launcher-known original slots are never adopted and remain only for bounded
//! process-exit cleanup. From the retained live exact parent process handle it
//! derives the parent PID and process-token `TokenSessionId`, then requires the parent hello, both pipe
//! server client PID/session observations, and the child token session to match.
//! The binding remains owned across UI presentation and response write and is
//! revalidated before release of the response. While that retained process
//! handle remains live, this prevents PID-reuse substitution and corroborates
//! the pipe observations against the exact live parent process object. Because
//! pipe handles are transferable and duplicable, it does not prove exclusive
//! endpoint ownership, endpoint topology/exclusivity, or per-write attribution.
//! The child also requires case-preserving exact normalized path-string equality
//! between the process image path and a separate held file path before checking
//! the held path's executable suffix and version metadata and performing held-
//! handle-backed Authenticode and SHA-256 policy checks. Path equality plus
//! held-file checks do not prove that the live process was mapped from that exact
//! file object. No positive kernel availability test yet proves that the
//! zero-capability Approval LPAC can complete `OpenProcessToken(parent)`, so this
//! success path remains release-unproven. Signed release-path
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
    authenticated.revalidate_parent()?;
    let response = approval_ui::ApprovalResponse::for_request(decision, request);
    let output = std::io::stdout();
    let mut writer = output.lock();
    let result = approval_ui::write_response(&mut writer, response);
    drop(writer);
    drop(authenticated);
    result
}
