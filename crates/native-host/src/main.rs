//! Chrome-launched native-host shim.
//!
//! The executable validates one bounded persistent version-1 stream. Until an
//! authenticated, release-attested broker transport is installed, ordinary and
//! release builds return the stable provider-unavailable response and exit
//! closed after EOF or the first terminal error. An explicit debug-only feature
//! drives a secret/network-free Broker subprocess contract test.

const PRIVATE_BROKER_UNAVAILABLE: i32 = 78;

#[cfg(not(all(feature = "broker-ipc-contract-test-hook", debug_assertions)))]
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

#[cfg(all(feature = "broker-ipc-contract-test-hook", debug_assertions))]
fn main() {
    if native_host::set_binary_stdio().is_err() {
        std::process::exit(PRIVATE_BROKER_UNAVAILABLE);
    }
    let _closed_result = run_contract_process();
    std::process::exit(PRIVATE_BROKER_UNAVAILABLE);
}

#[cfg(all(feature = "broker-ipc-contract-test-hook", debug_assertions))]
struct BrokerChildGuard(std::process::Child);

#[cfg(all(feature = "broker-ipc-contract-test-hook", debug_assertions))]
impl Drop for BrokerChildGuard {
    fn drop(&mut self) {
        let _kill_result = self.0.kill();
        let _wait_result = self.0.wait();
    }
}

#[cfg(all(feature = "broker-ipc-contract-test-hook", debug_assertions))]
fn run_contract_process() -> Result<(), ()> {
    use std::process::{Command, Stdio};

    let mut executable = std::env::current_exe().map_err(|_| ())?;
    executable.set_file_name(if cfg!(windows) {
        "broker.exe"
    } else {
        "broker"
    });
    let metadata = std::fs::symlink_metadata(&executable).map_err(|_| ())?;
    if !metadata.file_type().is_file() {
        return Err(());
    }
    let mut command = Command::new(executable);
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = BrokerChildGuard(command.spawn().map_err(|_| ())?);
    let mut broker_writer = child.0.stdin.take().ok_or(())?;
    let mut broker_reader = child.0.stdout.take().ok_or(())?;
    let mut random_nonce = || {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| native_host::ContractBridgeError::Randomness)?;
        Ok(nonce)
    };
    let result = {
        let input = std::io::stdin();
        let output = std::io::stdout();
        let mut native_reader = input.lock();
        let mut native_writer = output.lock();
        native_host::run_broker_contract_test_stream(
            &mut native_reader,
            &mut native_writer,
            &mut broker_reader,
            &mut broker_writer,
            &mut random_nonce,
        )
        .map_err(|_| ())
    };
    drop(broker_writer);
    result
}
