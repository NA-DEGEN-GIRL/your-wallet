//! One-shot Approval Frontend process.
//!
//! Ordinary builds remain disabled until the Key Agent can prove an authenticated
//! private parent/channel and an immutable helper image before launch. The
//! `runtime-entrypoint` feature only defines the child-side inherited-stream
//! contract. On Windows it first seals the exact inherited stdio pipe objects;
//! it does not activate or bypass `ReleaseAttestation`.

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
    let sealed_stdio = bootstrap::seal_inherited_approval_stdio()?;
    bootstrap::set_binary_stdio(&sealed_stdio)?;

    let input = std::io::stdin();
    let mut reader = input.lock();
    let request = approval_ui::read_request(&mut reader)?;
    drop(reader);

    #[cfg(all(feature = "runtime-contract-test-hook", debug_assertions))]
    let decision = approval_ui::Decision::Reject;
    #[cfg(not(all(feature = "runtime-contract-test-hook", debug_assertions)))]
    let decision = approval_ui::present(&request)?;
    let response = approval_ui::ApprovalResponse::for_request(decision, &request);
    let output = std::io::stdout();
    let mut writer = output.lock();
    let result = approval_ui::write_response(&mut writer, response);
    drop(writer);
    drop(sealed_stdio);
    result
}
