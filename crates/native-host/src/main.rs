//! Chrome-launched native-host shim.
//!
//! The executable validates one exact version-1 frame. Until an authenticated,
//! release-attested broker transport is installed, valid requests receive a
//! stable provider-unavailable response and the process exits closed.

const PRIVATE_BROKER_UNAVAILABLE: i32 = 78;

fn main() {
    if native_host::set_binary_stdio().is_err() {
        std::process::exit(PRIVATE_BROKER_UNAVAILABLE);
    }

    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let _outcome = native_host::run_unattested_once(&mut input, &mut output);
    drop(input);
    drop(output);
    std::process::exit(PRIVATE_BROKER_UNAVAILABLE);
}
