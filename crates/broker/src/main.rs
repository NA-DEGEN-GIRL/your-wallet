//! Broker process entrypoint.
//!
//! Ordinary and release builds remain disabled until the Windows SID/DACL,
//! remote-client rejection, exact native-host identity, and bootstrap are
//! release-attested. The debug-only contract hook exposes only the bounded
//! `eth_chainId` IPC path and cannot represent signing, network, account, or Key
//! Agent operations.

#[cfg(not(all(feature = "ipc-contract-test-hook", debug_assertions)))]
fn main() {
    std::process::exit(78);
}

#[cfg(all(feature = "ipc-contract-test-hook", debug_assertions))]
fn main() {
    let exit_code = run_contract_server().map_or(78, |()| 0);
    std::process::exit(exit_code);
}

#[cfg(all(feature = "ipc-contract-test-hook", debug_assertions))]
fn run_contract_server() -> Result<(), broker::ipc::BrokerIpcError> {
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use broker::{PermissionStore, TransportBroker};
    use wallet_model::{Address20, U256};

    let mut server_nonce = [0_u8; 32];
    getrandom::fill(&mut server_nonce).map_err(|_| broker::ipc::BrokerIpcError::Binding)?;
    let mut broker = TransportBroker::new(
        PermissionStore::default(),
        Address20::new([1; 20]),
        U256::from_u64(11_155_111),
    );
    let mut clock = || {
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| broker::ipc::BrokerIpcError::Binding)?
            .as_millis();
        let now_unix_ms =
            u64::try_from(now_unix_ms).map_err(|_| broker::ipc::BrokerIpcError::Binding)?;
        Ok((Instant::now(), now_unix_ms))
    };
    let input = std::io::stdin();
    let output = std::io::stdout();
    let mut reader = input.lock();
    let mut writer = output.lock();
    let _summary = broker::ipc::run_secretless_server(
        &mut reader,
        &mut writer,
        &mut broker,
        server_nonce,
        &mut clock,
    )?;
    Ok(())
}
