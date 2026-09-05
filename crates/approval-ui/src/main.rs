//! One-shot Approval Frontend process.
//!
//! Ordinary builds remain disabled until the Key Agent can prove an authenticated
//! private parent/channel and an immutable helper image before launch. The
//! `runtime-entrypoint` feature only defines the child-side authenticated
//! inherited-stream contract. The separate
//! `service-helper-rpc-probe-feasibility-test-hook` entrypoint is restricted to
//! debug Windows x64 MSVC builds and only completes the debugger-injected
//! service-channel bootstrap, authenticated `HelperReady`, and one bounded
//! native Approval request/decision transport probe with a no-signing title; it
//! is not a production activation path. On Windows the child first seals its exact
//! inherited synchronous server pipe objects while the parent retains the
//! overlapped client ends. It then checks LPAC and Job policy and makes fresh
//! child-local duplicates of the three injected proof handles: the ordinary
//! channel-supervisor process, its separately held image file, and the Key Agent
//! logical-parent process. Only those copies become authoritative and remain
//! retained through response write; the launcher-known original slots are never
//! adopted and remain only for bounded process-exit cleanup. From the retained
//! live supervisor process it derives the PID and token session, then requires
//! the parent hello and both pipe server client PID/session observations to
//! match that ordinary supervisor. Independently, the logical-parent handle must
//! name a distinct live same-session Key Agent process with the transcript-bound
//! PID, `key-agent.exe` image suffix, fixed `YourWallet.KeyAgent.LPAC.v1` SID,
//! `AppContainer` and LPAC flags, zero capabilities, query-only token access, and
//! denial of the enumerated stronger token/process requests. The Approval LPAC
//! must not contain `SeDebugPrivilege`. The five-object binding remains owned
//! across UI presentation and response write and revalidates both exact process
//! authorities before release of the response. Retaining those objects prevents
//! PID-reuse substitution and keeps pipe evidence scoped only to the ordinary
//! channel supervisor. Because
//! pipe handles are transferable and duplicable, it does not prove exclusive
//! endpoint ownership, endpoint topology/exclusivity, or per-write attribution.
//! The child also requires case-preserving exact normalized path-string equality
//! between the process image path and a separate held file path before checking
//! the held path's executable suffix and version metadata and performing held-
//! handle-backed Authenticode and SHA-256 policy checks. Path equality plus
//! held-file checks do not prove that the live process was mapped from that exact
//! file object. A repo-local kernel test proves that a zero-capability Approval
//! LPAC can complete `OpenProcessToken(..., TOKEN_QUERY)` for one exact injected
//! Key Agent logical-parent process proof while the documented stronger
//! token/process requests are denied. The child runtime now requires the corresponding fifth-object
//! authentication, but this remains neither signed/mapped release evidence nor a
//! production activation path. Signed release-path positive evidence covering
//! case-sensitive directories and alternate path forms, immutable installation,
//! the complete DLL/dependency graph, a release-proven resumable supervisor-held
//! activation capability, and endpoint topology/exclusivity remain release
//! blockers. The sealed hello bootstrap and full exchange both have zero
//! production callers. The parent-side platform issues one monotonic window and
//! splits it into matching non-Clone authorization and transport halves. The Key
//! Agent binds its exact digest/nonce/canonical display/protected-phrase request
//! once; the opaque carrier reaches dormant activation before allocation. The
//! bootstrap cap is the earlier of the original expiry and a fresh five-second
//! grace, and the full exchange accepts no raw request or deadline. It applies
//! that same original deadline across finish/request EOF, fixed response/EOF,
//! and the exact held child's natural exit-code-zero wait, then revalidates the
//! logical Key Agent after exit, observes that deadline once more, and retains
//! the carrier in its terminal value.
//! Its opaque `VerifiedParentBoundApprovalExchange` has no public
//! verified-response or signing conversion, and there is no positive signed-
//! handshake E2E. The transport supervisor remains the pipe authority; the Key
//! Agent remains only the distinct logical parent. That final Key-Agent check is
//! point-in-time evidence; any future evidence-to-authorization edge must
//! revalidate the retained exact Key Agent immediately before use. Session invalidation drops
//! any unbound transport half, and no full-exchange path reconstructs the
//! deadline from the wire-relative lifetime.
//! `COMPILED_PARENT_POLICY` remains `None`; ordinary builds exit 78. Raw
//! executable direct launch exits without diagnostics, while the legacy Rust API
//! returns `LogicalParentUnavailable` before resource allocation.

#[cfg(all(
    not(feature = "service-helper-rpc-probe-feasibility-test-hook"),
    feature = "runtime-entrypoint"
))]
mod bootstrap;

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
use key_agent_service_helper_bootstrap::{
    HelperBootstrapRole, capture_and_adopt_injected_channels, complete_injected_channel_bootstrap,
    receive_service_approval_request,
};

#[cfg(any(
    all(
        not(feature = "service-helper-rpc-probe-feasibility-test-hook"),
        not(feature = "runtime-entrypoint")
    ),
    all(
        feature = "service-helper-rpc-probe-feasibility-test-hook",
        not(all(windows, target_arch = "x86_64", target_env = "msvc", debug_assertions))
    )
))]
const PRIVATE_LAUNCH_UNAVAILABLE: i32 = 78;

#[cfg(any(
    all(
        not(feature = "service-helper-rpc-probe-feasibility-test-hook"),
        not(feature = "runtime-entrypoint")
    ),
    all(
        feature = "service-helper-rpc-probe-feasibility-test-hook",
        not(all(windows, target_arch = "x86_64", target_env = "msvc", debug_assertions))
    )
))]
fn main() {
    std::process::exit(PRIVATE_LAUNCH_UNAVAILABLE);
}

#[cfg(all(
    not(feature = "service-helper-rpc-probe-feasibility-test-hook"),
    feature = "runtime-entrypoint"
))]
const RUNTIME_FAILURE: i32 = 1;

#[cfg(all(
    not(feature = "service-helper-rpc-probe-feasibility-test-hook"),
    feature = "runtime-entrypoint"
))]
fn main() {
    let exit_code = match run_once() {
        Ok(()) => 0,
        Err(_) => RUNTIME_FAILURE,
    };
    std::process::exit(exit_code);
}

#[cfg(all(
    not(feature = "service-helper-rpc-probe-feasibility-test-hook"),
    feature = "runtime-entrypoint"
))]
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

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
const SERVICE_HELPER_ROLE: HelperBootstrapRole = HelperBootstrapRole::Approval;

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
fn main() {
    run_service_helper_rpc_probe();
}

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
fn run_service_helper_rpc_probe() -> ! {
    let adopted = capture_and_adopt_injected_channels();
    let bootstrapped = complete_injected_channel_bootstrap(adopted, SERVICE_HELPER_ROLE);
    let request = receive_service_approval_request(bootstrapped);
    request.present_and_respond(|request| approval_ui::present_service_probe(request).ok())
}

#[cfg(all(
    test,
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
mod service_helper_rpc_probe_contract_tests {
    use super::{HelperBootstrapRole, SERVICE_HELPER_ROLE, run_service_helper_rpc_probe};

    const _: fn() -> ! = run_service_helper_rpc_probe;

    #[test]
    fn entrypoint_role_is_fixed_to_approval() {
        assert_eq!(SERVICE_HELPER_ROLE, HelperBootstrapRole::Approval);
    }
}
