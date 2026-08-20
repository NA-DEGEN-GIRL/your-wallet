//! Debug-only native-host/Broker subprocess contract bridge.
//!
//! This module is absent unless both the explicit Cargo feature and debug
//! assertions are enabled. Its success path is structurally limited to
//! `eth_chainId`; every signing, RPC/network, account, and Key Agent request
//! remains unavailable.

use core::fmt;
use std::collections::BTreeSet;
use std::io::{Read, Write};

use broker::TransportCancellationOutcome;
use broker::ipc::{BrokerIpcClient, BrokerIpcError};
use thiserror::Error;

use crate::wire::{
    ExtensionEnvelope, ProtocolError, encode_contract_chain_id_response,
    encode_contract_unavailable_response, parse_extension_envelope,
};
use crate::{MAX_FRAME_BYTES, read_frame, write_frame};

const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_FRAMES_PER_STREAM: u64 = 4_096;

/// Failure in the debug-only subprocess bridge contract.
#[derive(Error)]
pub enum ContractBridgeError {
    /// Native Messaging framing or exact envelope validation failed.
    #[error("native contract bridge protocol failed")]
    Protocol(#[from] ProtocolError),
    /// The typed Broker IPC connection failed closed.
    #[error("native contract bridge broker IPC failed")]
    Broker(#[from] BrokerIpcError),
    /// OS randomness was unavailable.
    #[error("native contract bridge randomness failed")]
    Randomness,
}

impl fmt::Debug for ContractBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Protocol(_) => "ContractBridgeError::Protocol([REDACTED])",
            Self::Broker(_) => "ContractBridgeError::Broker([REDACTED])",
            Self::Randomness => "ContractBridgeError::Randomness",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NativeSequence {
    session_id: Option<[u8; 32]>,
    next_inbound: u64,
    next_outbound: u64,
}

impl NativeSequence {
    const fn new() -> Self {
        Self {
            session_id: None,
            next_inbound: 1,
            next_outbound: 1,
        }
    }

    fn observe(&mut self, session_id: [u8; 32], sequence: u64) -> Result<(), ProtocolError> {
        match self.session_id {
            None if sequence == 1 => {
                self.session_id = Some(session_id);
                self.next_inbound = 2;
                Ok(())
            }
            Some(current) if current == session_id && sequence == self.next_inbound => {
                self.next_inbound = advance(self.next_inbound)?;
                Ok(())
            }
            None | Some(_) => Err(ProtocolError::SessionSequence),
        }
    }

    fn take_outbound(&mut self) -> Result<u64, ProtocolError> {
        let sequence = self.next_outbound;
        self.next_outbound = advance(sequence)?;
        Ok(sequence)
    }
}

/// Drive a real Broker IPC stream behind the debug-only native contract hook.
///
/// `eth_chainId` is the only raw request forwarded. Every other exact extension
/// method sends only typed correlation metadata through Broker IPC before the
/// stable unavailable response.
/// Cancellations for forwarded requests receive an internal Broker ack but no
/// Chrome response.
///
/// # Errors
///
/// Returns on the first framing, schema, sequence, nonce, Broker, or output
/// error. No resynchronization or fallback is attempted.
pub fn run_broker_contract_test_stream<Random>(
    native_reader: &mut impl Read,
    native_writer: &mut impl Write,
    broker_reader: &mut impl Read,
    broker_writer: &mut impl Write,
    random_nonce: &mut Random,
) -> Result<(), ContractBridgeError>
where
    Random: FnMut() -> Result<[u8; 32], ContractBridgeError>,
{
    let mut broker = BrokerIpcClient::connect(broker_reader, broker_writer, random_nonce()?)?;
    let mut native_sequence = NativeSequence::new();
    let mut broker_completed = BTreeSet::new();
    let mut frames = 0_u64;
    loop {
        let Some(value) = read_frame(native_reader).map_err(ProtocolError::Framing)? else {
            return Ok(());
        };
        if frames >= MAX_FRAMES_PER_STREAM {
            return Err(ProtocolError::StreamLimit.into());
        }
        frames = frames.checked_add(1).ok_or(ProtocolError::StreamLimit)?;
        let envelope = parse_extension_envelope(value)?;
        match envelope {
            ExtensionEnvelope::Request(request) => {
                let context = request.context();
                native_sequence.observe(*context.session_id.as_bytes(), context.sequence)?;
                let response_sequence = native_sequence.take_outbound()?;
                let response = if request.method_name() == "eth_chainId" {
                    let chain_id = broker.execute_chain_id(
                        broker_reader,
                        broker_writer,
                        &request,
                        random_nonce()?,
                    )?;
                    encode_contract_chain_id_response(&request, response_sequence, chain_id)?
                } else {
                    broker.complete_unavailable(
                        broker_reader,
                        broker_writer,
                        &request,
                        random_nonce()?,
                    )?;
                    encode_contract_unavailable_response(&request, response_sequence)?
                };
                let inserted = broker_completed.insert((
                    *context.activation_nonce.as_bytes(),
                    *context.request_id.as_bytes(),
                    context.sequence,
                ));
                if !inserted {
                    return Err(ProtocolError::SessionSequence.into());
                }
                ensure_native_response_bound(&response)?;
                write_frame(native_writer, &response).map_err(ProtocolError::Framing)?;
            }
            ExtensionEnvelope::Cancel(cancellation) => {
                native_sequence.observe(cancellation.session_id, cancellation.sequence)?;
                let key = (
                    *cancellation.activation_nonce.as_bytes(),
                    cancellation.request_id,
                    cancellation.request_sequence,
                );
                if !broker_completed.remove(&key) {
                    return Err(ProtocolError::SessionSequence.into());
                }
                let disposition =
                    broker.cancel(broker_reader, broker_writer, cancellation, random_nonce()?)?;
                if disposition != TransportCancellationOutcome::AlreadyCompleted {
                    return Err(BrokerIpcError::Binding.into());
                }
            }
        }
    }
}

fn ensure_native_response_bound(response: &serde_json::Value) -> Result<(), ContractBridgeError> {
    let encoded = serde_json::to_vec(response).map_err(|_| ProtocolError::ResponseEncoding)?;
    if encoded.is_empty() || encoded.len() > MAX_FRAME_BYTES || !response.is_object() {
        return Err(ProtocolError::ResponseEncoding.into());
    }
    Ok(())
}

fn advance(value: u64) -> Result<u64, ProtocolError> {
    value
        .checked_add(1)
        .filter(|next| *next <= JAVASCRIPT_MAX_SAFE_INTEGER)
        .ok_or(ProtocolError::SessionSequence)
}

#[cfg(test)]
mod tests {
    use super::{ContractBridgeError, NativeSequence};
    use crate::wire::ProtocolError;

    #[test]
    fn native_sequences_reject_reuse_skip_and_cross_session() -> Result<(), ProtocolError> {
        let mut sequence = NativeSequence::new();
        sequence.observe([1; 32], 1)?;
        assert!(matches!(
            sequence.observe([1; 32], 1),
            Err(ProtocolError::SessionSequence)
        ));
        assert!(matches!(
            sequence.observe([2; 32], 2),
            Err(ProtocolError::SessionSequence)
        ));
        sequence.observe([1; 32], 2)?;
        assert_eq!(sequence.take_outbound()?, 1);
        Ok(())
    }

    #[test]
    fn error_debug_redacts_nested_details() {
        let error = ContractBridgeError::Protocol(ProtocolError::SessionSequence);
        assert_eq!(
            format!("{error:?}"),
            "ContractBridgeError::Protocol([REDACTED])"
        );
    }
}
