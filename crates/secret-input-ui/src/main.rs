//! One-shot Secret Input Frontend process.
//!
//! Ordinary builds remain disabled until the Key Agent can prove an authenticated
//! private parent/channel and an immutable helper image before launch. The
//! `runtime-entrypoint` feature only defines the child-side inherited-stream
//! contract; it does not activate or bypass `ReleaseAttestation`.

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
