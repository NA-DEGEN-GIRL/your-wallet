//! One-shot Secret Input Frontend process.
//!
//! Ordinary builds remain disabled until the Key Agent can prove an authenticated
//! private parent/channel and an immutable helper image before launch. The
//! `runtime-entrypoint` feature only defines the child-side inherited-stream
//! contract. The separate `service-helper-rpc-probe-feasibility-test-hook`
//! entrypoint is restricted to debug Windows x64 MSVC builds and only completes
//! the debugger-injected service-channel bootstrap plus the authenticated
//! `HelperReady` RPC probe. Neither path activates or bypasses
//! `ReleaseAttestation`.

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
use key_agent_service_helper_bootstrap::{
    HelperBootstrapRole, capture_and_adopt_injected_channels, complete_helper_ready_rpc_probe,
    complete_injected_channel_bootstrap,
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
fn run_once() -> Result<(), secret_input_ui::SecretInputError> {
    match secret_input_ui::bootstrap::authenticate_inherited_request()? {
        secret_input_ui::bootstrap::AuthenticatedRequestSession::Secret(session) => {
            #[cfg(all(feature = "runtime-contract-test-hook", debug_assertions))]
            let outcome = secret_input_ui::SecretOutcome::Cancelled;
            #[cfg(not(all(feature = "runtime-contract-test-hook", debug_assertions)))]
            let outcome = secret_input_ui::present_authenticated(&session)?;
            let output = std::io::stdout();
            let mut writer = output.lock();
            secret_input_ui::bootstrap::write_authenticated_outcome(&mut writer, session, outcome)
        }
        secret_input_ui::bootstrap::AuthenticatedRequestSession::Recovery(session) => {
            #[cfg(all(feature = "runtime-contract-test-hook", debug_assertions))]
            let outcome = secret_input_ui::cancel_authenticated_recovery(&session);
            #[cfg(not(all(feature = "runtime-contract-test-hook", debug_assertions)))]
            let outcome = secret_input_ui::present_authenticated_recovery(&session)?;
            let output = std::io::stdout();
            let mut writer = output.lock();
            secret_input_ui::bootstrap::write_authenticated_recovery_outcome(
                &mut writer,
                session,
                outcome,
            )
        }
    }
}

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
const SERVICE_HELPER_ROLE: HelperBootstrapRole = HelperBootstrapRole::SecretInput;

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
    complete_helper_ready_rpc_probe(bootstrapped, SERVICE_HELPER_ROLE)
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
    fn entrypoint_role_is_fixed_to_secret_input() {
        assert_eq!(SERVICE_HELPER_ROLE, HelperBootstrapRole::SecretInput);
    }
}
