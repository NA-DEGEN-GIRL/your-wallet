//! Chrome-launched native-host shim.
//!
//! The executable validates one bounded persistent version-1 stream. Until an
//! authenticated, release-attested broker transport is installed, valid
//! requests receive a stable provider-unavailable response and the process
//! exits closed after EOF or the first terminal error.

const PRIVATE_BROKER_UNAVAILABLE: i32 = 78;

fn main() {
    if native_host::set_binary_stdio().is_err() {
        std::process::exit(PRIVATE_BROKER_UNAVAILABLE);
    }

    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let _summary = native_host::run_release_disabled_stream(&mut input, &mut output);
    drop(input);
    drop(output);
    std::process::exit(PRIVATE_BROKER_UNAVAILABLE);
}
