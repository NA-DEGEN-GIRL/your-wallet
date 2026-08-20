//! One-shot Approval Frontend process.
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
fn run_once() -> Result<(), approval_ui::ApprovalError> {
    set_binary_stdio()?;

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
    approval_ui::write_response(&mut writer, response)
}

#[cfg(all(feature = "runtime-entrypoint", windows))]
fn set_binary_stdio() -> Result<(), approval_ui::ApprovalError> {
    const O_BINARY: i32 = 0x8000;

    unsafe extern "C" {
        fn _setmode(file_descriptor: i32, mode: i32) -> i32;
    }

    // SAFETY: File descriptors 0 and 1 are the process's inherited standard
    // input/output descriptors. `_setmode` neither takes ownership nor retains
    // a pointer; it only changes the CRT translation mode for this process.
    let (input_mode, output_mode) = unsafe { (_setmode(0, O_BINARY), _setmode(1, O_BINARY)) };
    if input_mode == -1 || output_mode == -1 {
        return Err(std::io::Error::other("binary standard I/O unavailable").into());
    }
    Ok(())
}

#[cfg(all(feature = "runtime-entrypoint", not(windows)))]
fn set_binary_stdio() -> Result<(), approval_ui::ApprovalError> {
    Ok(())
}
