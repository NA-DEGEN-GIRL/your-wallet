//! Debug-only native-host composition with the exact Windows Broker channel.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use broker::ipc::{BrokerIpcError, BrokerIpcPayloads};
use platform_windows::DormantBrokerPayloadChannel;

use crate::{ContractBridgeError, run_broker_contract_test_payloads};

const BROKER_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const BROKER_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

struct WindowsBrokerPayloads(DormantBrokerPayloadChannel);

impl BrokerIpcPayloads for WindowsBrokerPayloads {
    fn read_payload(&mut self) -> Result<Option<Vec<u8>>, BrokerIpcError> {
        self.0
            .read_payload(Instant::now() + BROKER_OPERATION_TIMEOUT)
            .map_err(|_| BrokerIpcError::Io)
    }

    fn write_payload(&mut self, payload: &[u8]) -> Result<(), BrokerIpcError> {
        self.0
            .write_payload(payload, Instant::now() + BROKER_OPERATION_TIMEOUT)
            .map_err(|_| BrokerIpcError::Io)
    }
}

/// Runs the native contract stream through one exact, hidden Broker child.
///
/// # Errors
///
/// Returns on the first exact-launch, native frame, typed Broker payload,
/// sequence, nonce, or output error. No stdio fallback is attempted.
pub fn run_windows_broker_contract_test_stream<Random>(
    native_reader: &mut impl Read,
    native_writer: &mut impl Write,
    random_nonce: &mut Random,
) -> Result<(), ContractBridgeError>
where
    Random: FnMut() -> Result<[u8; 32], ContractBridgeError>,
{
    let channel =
        platform_windows::launch_dormant_broker_channel(Instant::now() + BROKER_STARTUP_TIMEOUT)
            .map_err(|_| BrokerIpcError::Io)?;
    let mut payloads = WindowsBrokerPayloads(channel);
    run_broker_contract_test_payloads(native_reader, native_writer, &mut payloads, random_nonce)
}
