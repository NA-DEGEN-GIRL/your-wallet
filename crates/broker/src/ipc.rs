//! Transport-neutral, bounded Broker IPC contract for the secretless local bridge.
//!
//! Version 1 is deliberately tiny: it can represent only `eth_chainId` with
//! empty parameters plus an exactly bound cancellation. It cannot represent a
//! signing request, an RPC/network request, account disclosure, arbitrary JSON,
//! or a Key Agent command. The production Windows transport and authenticated
//! bootstrap remain separate release work.

use core::fmt;
use std::io::{self, Read, Write};
use std::time::Instant;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use wallet_model::{
    ActivationNonce, BrowserContext, BrowserFamily, BrowserOrigin, BrowserProvenance, ChannelNonce,
    DocumentId, DocumentLifecycle, ExtensionId, ProfileInstallId, RequestId, SessionId, U256,
};

use crate::transport::{SecretlessLocalOutcome, TransportUnavailable};
use crate::{
    BrokerError, ProviderMethod, ProviderRoute, TransportBroker, TransportCancellation,
    TransportCancellationOutcome, TransportRequest,
};

const PROTOCOL_VERSION: u8 = 1;
const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Maximum encoded frame accepted on the first secretless Broker IPC contract.
pub const MAX_BROKER_IPC_FRAME_BYTES: usize = 8_192;
/// Maximum command frames accepted after the one mandatory handshake frame.
pub const MAX_BROKER_IPC_COMMANDS: u64 = 4_096;

/// Broker IPC framing, schema, binding, or state failure.
#[derive(Error)]
pub enum BrokerIpcError {
    /// The stream ended within a length prefix or payload.
    #[error("broker IPC frame ended early")]
    Truncated,
    /// The advertised or encoded frame exceeded the fixed limit.
    #[error("broker IPC frame exceeds its policy limit")]
    Oversized,
    /// Allocation failed without an unbounded fallback.
    #[error("broker IPC frame allocation failed")]
    Allocation,
    /// The fixed post-handshake command lifetime was exhausted.
    #[error("broker IPC command limit reached")]
    Capacity,
    /// JSON did not match the exact typed schema.
    #[error("broker IPC frame is malformed")]
    Malformed,
    /// Connection, request, or response binding did not match.
    #[error("broker IPC binding mismatch")]
    Binding,
    /// A connection sequence was replayed or skipped.
    #[error("broker IPC sequence mismatch")]
    Sequence,
    /// The Broker rejected an otherwise typed request.
    #[error("broker IPC request was rejected")]
    BrokerRejected,
    /// Underlying transport I/O failed.
    #[error("broker IPC transport failed")]
    Io,
}

impl fmt::Debug for BrokerIpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "BrokerIpcError::Truncated",
            Self::Oversized => "BrokerIpcError::Oversized",
            Self::Allocation => "BrokerIpcError::Allocation",
            Self::Capacity => "BrokerIpcError::Capacity",
            Self::Malformed => "BrokerIpcError::Malformed",
            Self::Binding => "BrokerIpcError::Binding",
            Self::Sequence => "BrokerIpcError::Sequence",
            Self::BrokerRejected => "BrokerIpcError::BrokerRejected",
            Self::Io => "BrokerIpcError::Io([REDACTED])",
        })
    }
}

/// Non-sensitive counters returned after a clean Broker IPC EOF.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokerIpcSummary {
    commands: u64,
    responses: u64,
    cancellations: u64,
    unavailable_completions: u64,
}

impl BrokerIpcSummary {
    /// Number of request, unavailable-completion, and cancellation commands consumed.
    #[must_use]
    pub const fn commands(self) -> u64 {
        self.commands
    }

    /// Number of internal response/acknowledgement frames written.
    #[must_use]
    pub const fn responses(self) -> u64 {
        self.responses
    }

    /// Number of exactly bound cancellation commands consumed.
    #[must_use]
    pub const fn cancellations(self) -> u64 {
        self.cancellations
    }

    /// Number of correlation-only unavailable requests completed by Broker.
    #[must_use]
    pub const fn unavailable_completions(self) -> u64 {
        self.unavailable_completions
    }
}

/// Stateful client codec for one native-host/Broker connection.
pub struct BrokerIpcClient {
    client_nonce: FixedHex<32>,
    server_nonce: FixedHex<32>,
    next_outbound_sequence: u64,
    next_inbound_sequence: u64,
}

impl fmt::Debug for BrokerIpcClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrokerIpcClient([REDACTED CONNECTION STATE])")
    }
}

impl BrokerIpcClient {
    /// Perform the exact two-nonce role handshake.
    ///
    /// # Errors
    ///
    /// Returns a bounded framing, schema, nonce, role, or sequence error.
    pub fn connect(
        reader: &mut impl Read,
        writer: &mut impl Write,
        client_nonce: [u8; 32],
    ) -> Result<Self, BrokerIpcError> {
        let client_nonce = nonzero(FixedHex(client_nonce))?;
        let hello = ClientFrameWire {
            namespace: Namespace::YourWalletBroker,
            version: PROTOCOL_VERSION,
            role: ClientRole::NativeHost,
            client_nonce,
            sequence: 1,
            body: ClientBodyWire::Hello,
        };
        write_frame(writer, &hello)?;
        let response: ServerFrameWire = read_required_frame(reader)?;
        let ServerBodyWire::Hello { server_nonce } = response.body else {
            return Err(BrokerIpcError::Binding);
        };
        if response.namespace != Namespace::YourWalletBroker
            || response.version != PROTOCOL_VERSION
            || response.role != ServerRole::Broker
            || response.client_nonce != client_nonce
            || response.sequence != 1
        {
            return Err(BrokerIpcError::Binding);
        }
        let server_nonce = nonzero(server_nonce)?;
        Ok(Self {
            client_nonce,
            server_nonce,
            next_outbound_sequence: 2,
            next_inbound_sequence: 2,
        })
    }

    /// Send one exact `eth_chainId` request and consume its bound result.
    ///
    /// # Errors
    ///
    /// Returns an error for any non-chain-id request, binding mismatch, skipped
    /// sequence, malformed response, or transport failure.
    pub fn execute_chain_id(
        &mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        request: &TransportRequest,
        request_nonce: [u8; 32],
    ) -> Result<U256, BrokerIpcError> {
        let request_nonce = nonzero(FixedHex(request_nonce))?;
        let request_wire = LocalRequestWire::from_transport(request)?;
        let binding = ResponseBindingWire::from_context(request.context());
        let sequence = self.take_outbound_sequence()?;
        let frame = ClientFrameWire {
            namespace: Namespace::YourWalletBroker,
            version: PROTOCOL_VERSION,
            role: ClientRole::NativeHost,
            client_nonce: self.client_nonce,
            sequence,
            body: ClientBodyWire::Request {
                server_nonce: self.server_nonce,
                request_nonce,
                request: request_wire,
            },
        };
        write_frame(writer, &frame)?;

        let response = self.read_bound_response(reader)?;
        let ServerBodyWire::ChainId {
            server_nonce,
            request_nonce: returned_nonce,
            binding: returned_binding,
            chain_id,
        } = response.body
        else {
            return Err(BrokerIpcError::Binding);
        };
        if server_nonce != self.server_nonce
            || returned_nonce != request_nonce
            || returned_binding != binding
        {
            return Err(BrokerIpcError::Binding);
        }
        Ok(U256::from_be_bytes(chain_id.0))
    }

    /// Consume one allowlisted request as unavailable without forwarding its
    /// raw parameters, message bytes, accounts, addresses, or origin.
    ///
    /// The Broker acknowledges only after the exact extension sequence and
    /// request correlation have been recorded as completed. The caller may then
    /// emit the stable provider-unavailable response.
    ///
    /// # Errors
    ///
    /// Returns an error for `eth_chainId`, an unrecognized method, mismatched
    /// correlation/nonce, skipped IPC sequence, or transport failure.
    pub fn complete_unavailable(
        &mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        request: &TransportRequest,
        request_nonce: [u8; 32],
    ) -> Result<(), BrokerIpcError> {
        let request_nonce = nonzero(FixedHex(request_nonce))?;
        let unavailable = UnavailableRequestWire::from_transport(request)?;
        let binding = ResponseBindingWire::from_context(request.context());
        let method = unavailable.method;
        let sequence = self.take_outbound_sequence()?;
        write_frame(
            writer,
            &ClientFrameWire {
                namespace: Namespace::YourWalletBroker,
                version: PROTOCOL_VERSION,
                role: ClientRole::NativeHost,
                client_nonce: self.client_nonce,
                sequence,
                body: ClientBodyWire::Unavailable {
                    server_nonce: self.server_nonce,
                    request_nonce,
                    unavailable,
                },
            },
        )?;

        let response = self.read_bound_response(reader)?;
        let ServerBodyWire::Unavailable {
            server_nonce,
            request_nonce: returned_nonce,
            binding: returned_binding,
            method: returned_method,
        } = response.body
        else {
            return Err(BrokerIpcError::Binding);
        };
        if server_nonce != self.server_nonce
            || returned_nonce != request_nonce
            || returned_binding != binding
            || returned_method != method
        {
            return Err(BrokerIpcError::Binding);
        }
        Ok(())
    }

    /// Send one exact cancellation and consume its internal acknowledgement.
    ///
    /// The acknowledgement never crosses the Chrome Native Messaging boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid binding, sequence, schema, or transport.
    pub fn cancel(
        &mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        cancellation: TransportCancellation,
        cancellation_nonce: [u8; 32],
    ) -> Result<TransportCancellationOutcome, BrokerIpcError> {
        let cancellation_nonce = nonzero(FixedHex(cancellation_nonce))?;
        let binding = CancellationBindingWire::from_transport(cancellation);
        let sequence = self.take_outbound_sequence()?;
        let frame = ClientFrameWire {
            namespace: Namespace::YourWalletBroker,
            version: PROTOCOL_VERSION,
            role: ClientRole::NativeHost,
            client_nonce: self.client_nonce,
            sequence,
            body: ClientBodyWire::Cancel {
                server_nonce: self.server_nonce,
                cancellation_nonce,
                cancellation: binding,
            },
        };
        write_frame(writer, &frame)?;

        let response = self.read_bound_response(reader)?;
        let ServerBodyWire::Cancelled {
            server_nonce,
            cancellation_nonce: returned_nonce,
            cancellation: returned_binding,
            disposition,
        } = response.body
        else {
            return Err(BrokerIpcError::Binding);
        };
        if server_nonce != self.server_nonce
            || returned_nonce != cancellation_nonce
            || returned_binding != binding
        {
            return Err(BrokerIpcError::Binding);
        }
        Ok(match disposition {
            CancellationDispositionWire::Cancelled => TransportCancellationOutcome::Cancelled,
            CancellationDispositionWire::AlreadyCompleted => {
                TransportCancellationOutcome::AlreadyCompleted
            }
        })
    }

    fn read_bound_response(
        &mut self,
        reader: &mut impl Read,
    ) -> Result<ServerFrameWire, BrokerIpcError> {
        let response: ServerFrameWire = read_required_frame(reader)?;
        if response.namespace != Namespace::YourWalletBroker
            || response.version != PROTOCOL_VERSION
            || response.role != ServerRole::Broker
            || response.client_nonce != self.client_nonce
            || response.sequence != self.next_inbound_sequence
        {
            return Err(BrokerIpcError::Sequence);
        }
        self.next_inbound_sequence = advance_sequence(self.next_inbound_sequence)?;
        Ok(response)
    }

    fn take_outbound_sequence(&mut self) -> Result<u64, BrokerIpcError> {
        let sequence = self.next_outbound_sequence;
        self.next_outbound_sequence = advance_sequence(sequence)?;
        Ok(sequence)
    }
}

/// Run one bounded, secretless Broker IPC session until clean EOF.
///
/// The supplied Broker remains the sole owner of admission, local response,
/// completion, and cancellation state. No arbitrary executor is invoked.
/// The mandatory hello is not a command: exactly 4,096 post-handshake command
/// frames may be dispatched, and the next complete frame fails before any
/// Broker state mutation or response.
///
/// # Errors
///
/// Returns on the first framing, handshake, sequence, binding, clock, or Broker
/// policy failure. No resynchronization is attempted.
pub fn run_secretless_server<Clock>(
    reader: &mut impl Read,
    writer: &mut impl Write,
    broker: &mut TransportBroker,
    server_nonce: [u8; 32],
    clock: &mut Clock,
) -> Result<BrokerIpcSummary, BrokerIpcError>
where
    Clock: FnMut() -> Result<(Instant, u64), BrokerIpcError>,
{
    let hello: ClientFrameWire = read_required_frame(reader)?;
    if hello.namespace != Namespace::YourWalletBroker
        || hello.version != PROTOCOL_VERSION
        || hello.role != ClientRole::NativeHost
        || hello.sequence != 1
        || !matches!(hello.body, ClientBodyWire::Hello)
    {
        return Err(BrokerIpcError::Binding);
    }
    let client_nonce = nonzero(hello.client_nonce)?;
    let server_nonce = nonzero(FixedHex(server_nonce))?;
    write_frame(
        writer,
        &ServerFrameWire {
            namespace: Namespace::YourWalletBroker,
            version: PROTOCOL_VERSION,
            role: ServerRole::Broker,
            client_nonce,
            sequence: 1,
            body: ServerBodyWire::Hello { server_nonce },
        },
    )?;

    let mut next_client_sequence = 2_u64;
    let mut next_server_sequence = 2_u64;
    let mut extension_session = None;
    let mut summary = BrokerIpcSummary::default();
    loop {
        let Some(frame): Option<ClientFrameWire> = read_frame(reader)? else {
            return Ok(summary);
        };
        if summary.commands >= MAX_BROKER_IPC_COMMANDS {
            return Err(BrokerIpcError::Capacity);
        }
        if frame.namespace != Namespace::YourWalletBroker
            || frame.version != PROTOCOL_VERSION
            || frame.role != ClientRole::NativeHost
            || frame.client_nonce != client_nonce
            || frame.sequence != next_client_sequence
        {
            return Err(BrokerIpcError::Sequence);
        }
        next_client_sequence = advance_sequence(next_client_sequence)?;
        summary.commands = advance_counter(summary.commands)?;

        let response_body = handle_server_command(
            frame.body,
            server_nonce,
            &mut extension_session,
            broker,
            clock,
            &mut summary,
        )?;
        let response_sequence = next_server_sequence;
        next_server_sequence = advance_sequence(next_server_sequence)?;
        write_frame(
            writer,
            &ServerFrameWire {
                namespace: Namespace::YourWalletBroker,
                version: PROTOCOL_VERSION,
                role: ServerRole::Broker,
                client_nonce,
                sequence: response_sequence,
                body: response_body,
            },
        )?;
        summary.responses = advance_counter(summary.responses)?;
    }
}

fn handle_server_command<Clock>(
    command: ClientBodyWire,
    server_nonce: FixedHex<32>,
    extension_session: &mut Option<[u8; 32]>,
    broker: &mut TransportBroker,
    clock: &mut Clock,
    summary: &mut BrokerIpcSummary,
) -> Result<ServerBodyWire, BrokerIpcError>
where
    Clock: FnMut() -> Result<(Instant, u64), BrokerIpcError>,
{
    match command {
        ClientBodyWire::Hello => Err(BrokerIpcError::Binding),
        ClientBodyWire::Request {
            server_nonce: returned_server_nonce,
            request_nonce,
            request,
        } => {
            if returned_server_nonce != server_nonce {
                return Err(BrokerIpcError::Binding);
            }
            let request_nonce = nonzero(request_nonce)?;
            let transport = request.into_transport()?;
            bind_extension_session(
                extension_session,
                broker,
                *transport.context().session_id.as_bytes(),
            )?;
            let binding = ResponseBindingWire::from_context(transport.context());
            let (admitted_at, now_unix_ms) = clock()?;
            if now_unix_ms > JAVASCRIPT_MAX_SAFE_INTEGER {
                return Err(BrokerIpcError::Malformed);
            }
            let (completed_at, _) = clock()?;
            let outcome = broker
                .execute_secretless_local(&transport, admitted_at, completed_at, now_unix_ms)
                .map_err(|_| BrokerIpcError::BrokerRejected)?;
            let SecretlessLocalOutcome::ChainId(chain_id) = outcome;
            Ok(ServerBodyWire::ChainId {
                server_nonce,
                request_nonce,
                binding,
                chain_id: FixedHex(*chain_id.as_be_bytes()),
            })
        }
        ClientBodyWire::Unavailable {
            server_nonce: returned_server_nonce,
            request_nonce,
            unavailable,
        } => {
            if returned_server_nonce != server_nonce {
                return Err(BrokerIpcError::Binding);
            }
            let request_nonce = nonzero(request_nonce)?;
            let binding = unavailable.binding();
            let method = unavailable.method;
            let transport = unavailable.into_transport()?;
            bind_extension_session(extension_session, broker, transport.session_id())?;
            broker
                .complete_unavailable(transport)
                .map_err(|_| BrokerIpcError::BrokerRejected)?;
            summary.unavailable_completions = advance_counter(summary.unavailable_completions)?;
            Ok(ServerBodyWire::Unavailable {
                server_nonce,
                request_nonce,
                binding,
                method,
            })
        }
        ClientBodyWire::Cancel {
            server_nonce: returned_server_nonce,
            cancellation_nonce,
            cancellation,
        } => {
            if returned_server_nonce != server_nonce
                || *extension_session != Some(cancellation.session_id.0)
            {
                return Err(BrokerIpcError::Binding);
            }
            let cancellation_nonce = nonzero(cancellation_nonce)?;
            let transport = cancellation.into_transport()?;
            let disposition = broker
                .cancel(transport)
                .map_err(|_| BrokerIpcError::BrokerRejected)?;
            summary.cancellations = advance_counter(summary.cancellations)?;
            Ok(ServerBodyWire::Cancelled {
                server_nonce,
                cancellation_nonce,
                cancellation,
                disposition: match disposition {
                    TransportCancellationOutcome::Cancelled => {
                        CancellationDispositionWire::Cancelled
                    }
                    TransportCancellationOutcome::AlreadyCompleted => {
                        CancellationDispositionWire::AlreadyCompleted
                    }
                },
            })
        }
    }
}

fn bind_extension_session(
    current: &mut Option<[u8; 32]>,
    broker: &mut TransportBroker,
    observed: [u8; 32],
) -> Result<(), BrokerIpcError> {
    match current {
        None => {
            broker
                .begin_session(observed)
                .map_err(|_| BrokerIpcError::BrokerRejected)?;
            *current = Some(observed);
            Ok(())
        }
        Some(existing) if *existing == observed => Ok(()),
        Some(_) => Err(BrokerIpcError::Binding),
    }
}

fn advance_counter(value: u64) -> Result<u64, BrokerIpcError> {
    value.checked_add(1).ok_or(BrokerIpcError::Sequence)
}

fn advance_sequence(value: u64) -> Result<u64, BrokerIpcError> {
    value
        .checked_add(1)
        .filter(|next| *next <= JAVASCRIPT_MAX_SAFE_INTEGER)
        .ok_or(BrokerIpcError::Sequence)
}

fn nonzero<const LENGTH: usize>(
    value: FixedHex<LENGTH>,
) -> Result<FixedHex<LENGTH>, BrokerIpcError> {
    if value.0.iter().all(|byte| *byte == 0) {
        Err(BrokerIpcError::Binding)
    } else {
        Ok(value)
    }
}

fn read_required_frame<T: for<'de> Deserialize<'de>>(
    reader: &mut impl Read,
) -> Result<T, BrokerIpcError> {
    read_frame(reader)?.ok_or(BrokerIpcError::Truncated)
}

fn read_frame<T: for<'de> Deserialize<'de>>(
    reader: &mut impl Read,
) -> Result<Option<T>, BrokerIpcError> {
    let mut length_bytes = [0_u8; 4];
    let first = reader
        .read(&mut length_bytes[..1])
        .map_err(|_| BrokerIpcError::Io)?;
    if first == 0 {
        return Ok(None);
    }
    read_exact(reader, &mut length_bytes[1..])?;
    let length =
        usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| BrokerIpcError::Oversized)?;
    if length == 0 || length > MAX_BROKER_IPC_FRAME_BYTES {
        return Err(BrokerIpcError::Oversized);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| BrokerIpcError::Allocation)?;
    payload.resize(length, 0);
    read_exact(reader, &mut payload)?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|_| BrokerIpcError::Malformed)
}

fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), BrokerIpcError> {
    let payload = serde_json::to_vec(value).map_err(|_| BrokerIpcError::Malformed)?;
    if payload.is_empty() || payload.len() > MAX_BROKER_IPC_FRAME_BYTES {
        return Err(BrokerIpcError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| BrokerIpcError::Oversized)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(&payload))
        .and_then(|()| writer.flush())
        .map_err(|_| BrokerIpcError::Io)
}

fn read_exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), BrokerIpcError> {
    reader.read_exact(bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            BrokerIpcError::Truncated
        } else {
            BrokerIpcError::Io
        }
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum Namespace {
    #[serde(rename = "your-wallet-broker")]
    YourWalletBroker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ClientRole {
    #[serde(rename = "native-host")]
    NativeHost,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ServerRole {
    #[serde(rename = "broker")]
    Broker,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClientFrameWire {
    namespace: Namespace,
    version: u8,
    role: ClientRole,
    client_nonce: FixedHex<32>,
    sequence: u64,
    body: ClientBodyWire,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
enum ClientBodyWire {
    #[serde(rename = "hello")]
    Hello,
    #[serde(rename = "request")]
    Request {
        server_nonce: FixedHex<32>,
        request_nonce: FixedHex<32>,
        request: LocalRequestWire,
    },
    #[serde(rename = "unavailable")]
    Unavailable {
        server_nonce: FixedHex<32>,
        request_nonce: FixedHex<32>,
        unavailable: UnavailableRequestWire,
    },
    #[serde(rename = "cancel")]
    Cancel {
        server_nonce: FixedHex<32>,
        cancellation_nonce: FixedHex<32>,
        cancellation: CancellationBindingWire,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ServerFrameWire {
    namespace: Namespace,
    version: u8,
    role: ServerRole,
    client_nonce: FixedHex<32>,
    sequence: u64,
    body: ServerBodyWire,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
enum ServerBodyWire {
    #[serde(rename = "hello")]
    Hello { server_nonce: FixedHex<32> },
    #[serde(rename = "chainId")]
    ChainId {
        server_nonce: FixedHex<32>,
        request_nonce: FixedHex<32>,
        binding: ResponseBindingWire,
        chain_id: FixedHex<32>,
    },
    #[serde(rename = "unavailable")]
    Unavailable {
        server_nonce: FixedHex<32>,
        request_nonce: FixedHex<32>,
        binding: ResponseBindingWire,
        method: UnavailableMethodWire,
    },
    #[serde(rename = "cancelled")]
    Cancelled {
        server_nonce: FixedHex<32>,
        cancellation_nonce: FixedHex<32>,
        cancellation: CancellationBindingWire,
        disposition: CancellationDispositionWire,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum CancellationDispositionWire {
    #[serde(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "already-completed")]
    AlreadyCompleted,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UnavailableRequestWire {
    session_id: FixedHex<32>,
    request_sequence: u64,
    activation_nonce: FixedHex<32>,
    request_id: FixedHex<16>,
    method: UnavailableMethodWire,
}

impl fmt::Debug for UnavailableRequestWire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnavailableRequestWire([REDACTED CORRELATION])")
    }
}

impl UnavailableRequestWire {
    fn from_transport(request: &TransportRequest) -> Result<Self, BrokerIpcError> {
        let method = ProviderMethod::parse(request.method_name())
            .ok_or(BrokerIpcError::Malformed)
            .and_then(UnavailableMethodWire::from_provider)?;
        let context = request.context();
        Ok(Self {
            session_id: FixedHex(*context.session_id.as_bytes()),
            request_sequence: context.sequence,
            activation_nonce: FixedHex(*context.activation_nonce.as_bytes()),
            request_id: FixedHex(*context.request_id.as_bytes()),
            method,
        })
    }

    fn into_transport(self) -> Result<TransportUnavailable, BrokerIpcError> {
        if self.request_sequence == 0 || self.request_sequence > JAVASCRIPT_MAX_SAFE_INTEGER {
            return Err(BrokerIpcError::Malformed);
        }
        Ok(TransportUnavailable::new(
            nonzero(self.session_id)?.0,
            self.request_sequence,
            ActivationNonce::new(nonzero(self.activation_nonce)?.0),
            nonzero(self.request_id)?.0,
            self.method.into_provider(),
        ))
    }

    const fn binding(self) -> ResponseBindingWire {
        ResponseBindingWire {
            session_id: self.session_id,
            request_sequence: self.request_sequence,
            activation_nonce: self.activation_nonce,
            request_id: self.request_id,
        }
    }
}

/// Closed, parameter-free method taxonomy for debug-unavailable completion.
///
/// These enum labels are not arbitrary RPC method strings and cannot carry any
/// request body. `eth_chainId` is intentionally absent because it has a
/// separate exact local-execution command.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum UnavailableMethodWire {
    RequestAccounts,
    Accounts,
    NetworkVersion,
    BlockNumber,
    GetBalance,
    GetCode,
    GetStorageAt,
    GetTransactionCount,
    Call,
    EstimateGas,
    GasPrice,
    FeeHistory,
    MaxPriorityFeePerGas,
    GetBlockByHash,
    GetBlockByNumber,
    GetTransactionByHash,
    GetTransactionReceipt,
    GetLogs,
    SendTransaction,
    PersonalSign,
    SignTypedDataV4,
    AddEthereumChain,
    SwitchEthereumChain,
    WatchAsset,
    GetCapabilities,
    RequestPermissions,
    GetPermissions,
}

impl UnavailableMethodWire {
    fn from_provider(method: ProviderMethod) -> Result<Self, BrokerIpcError> {
        Ok(match method {
            ProviderMethod::RequestAccounts => Self::RequestAccounts,
            ProviderMethod::Accounts => Self::Accounts,
            ProviderMethod::ChainId => return Err(BrokerIpcError::Malformed),
            ProviderMethod::NetVersion => Self::NetworkVersion,
            ProviderMethod::BlockNumber => Self::BlockNumber,
            ProviderMethod::GetBalance => Self::GetBalance,
            ProviderMethod::GetCode => Self::GetCode,
            ProviderMethod::GetStorageAt => Self::GetStorageAt,
            ProviderMethod::GetTransactionCount => Self::GetTransactionCount,
            ProviderMethod::Call => Self::Call,
            ProviderMethod::EstimateGas => Self::EstimateGas,
            ProviderMethod::GasPrice => Self::GasPrice,
            ProviderMethod::FeeHistory => Self::FeeHistory,
            ProviderMethod::MaxPriorityFeePerGas => Self::MaxPriorityFeePerGas,
            ProviderMethod::GetBlockByHash => Self::GetBlockByHash,
            ProviderMethod::GetBlockByNumber => Self::GetBlockByNumber,
            ProviderMethod::GetTransactionByHash => Self::GetTransactionByHash,
            ProviderMethod::GetTransactionReceipt => Self::GetTransactionReceipt,
            ProviderMethod::GetLogs => Self::GetLogs,
            ProviderMethod::SendTransaction => Self::SendTransaction,
            ProviderMethod::PersonalSign => Self::PersonalSign,
            ProviderMethod::SignTypedDataV4 => Self::SignTypedDataV4,
            ProviderMethod::AddEthereumChain => Self::AddEthereumChain,
            ProviderMethod::SwitchEthereumChain => Self::SwitchEthereumChain,
            ProviderMethod::WatchAsset => Self::WatchAsset,
            ProviderMethod::GetCapabilities => Self::GetCapabilities,
            ProviderMethod::RequestPermissions => Self::RequestPermissions,
            ProviderMethod::GetPermissions => Self::GetPermissions,
        })
    }

    const fn into_provider(self) -> ProviderMethod {
        match self {
            Self::RequestAccounts => ProviderMethod::RequestAccounts,
            Self::Accounts => ProviderMethod::Accounts,
            Self::NetworkVersion => ProviderMethod::NetVersion,
            Self::BlockNumber => ProviderMethod::BlockNumber,
            Self::GetBalance => ProviderMethod::GetBalance,
            Self::GetCode => ProviderMethod::GetCode,
            Self::GetStorageAt => ProviderMethod::GetStorageAt,
            Self::GetTransactionCount => ProviderMethod::GetTransactionCount,
            Self::Call => ProviderMethod::Call,
            Self::EstimateGas => ProviderMethod::EstimateGas,
            Self::GasPrice => ProviderMethod::GasPrice,
            Self::FeeHistory => ProviderMethod::FeeHistory,
            Self::MaxPriorityFeePerGas => ProviderMethod::MaxPriorityFeePerGas,
            Self::GetBlockByHash => ProviderMethod::GetBlockByHash,
            Self::GetBlockByNumber => ProviderMethod::GetBlockByNumber,
            Self::GetTransactionByHash => ProviderMethod::GetTransactionByHash,
            Self::GetTransactionReceipt => ProviderMethod::GetTransactionReceipt,
            Self::GetLogs => ProviderMethod::GetLogs,
            Self::SendTransaction => ProviderMethod::SendTransaction,
            Self::PersonalSign => ProviderMethod::PersonalSign,
            Self::SignTypedDataV4 => ProviderMethod::SignTypedDataV4,
            Self::AddEthereumChain => ProviderMethod::AddEthereumChain,
            Self::SwitchEthereumChain => ProviderMethod::SwitchEthereumChain,
            Self::WatchAsset => ProviderMethod::WatchAsset,
            Self::GetCapabilities => ProviderMethod::GetCapabilities,
            Self::RequestPermissions => ProviderMethod::RequestPermissions,
            Self::GetPermissions => ProviderMethod::GetPermissions,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalRequestWire {
    session_id: FixedHex<32>,
    request_sequence: u64,
    deadline_unix_ms: u64,
    profile_install_id: FixedHex<32>,
    activation_nonce: FixedHex<32>,
    request_id: FixedHex<16>,
    method: LocalMethodWire,
    params: [(); 0],
    route: LocalRouteWire,
    context: BrowserContextWire,
}

impl LocalRequestWire {
    fn from_transport(request: &TransportRequest) -> Result<Self, BrokerIpcError> {
        if request.method_name() != "eth_chainId"
            || request.route() != ProviderRoute::Permission
            || request
                .params()
                .as_array()
                .is_none_or(|params| !params.is_empty())
        {
            return Err(BrokerIpcError::Malformed);
        }
        let context = request.context();
        Ok(Self {
            session_id: FixedHex(*context.session_id.as_bytes()),
            request_sequence: context.sequence,
            deadline_unix_ms: context.deadline_ms,
            profile_install_id: FixedHex(*context.profile_install_id.as_bytes()),
            activation_nonce: FixedHex(*context.activation_nonce.as_bytes()),
            request_id: FixedHex(*context.request_id.as_bytes()),
            method: LocalMethodWire::ChainId,
            params: [],
            route: LocalRouteWire::Permission,
            context: BrowserContextWire::from_context(context),
        })
    }

    fn into_transport(self) -> Result<TransportRequest, BrokerIpcError> {
        let Self {
            session_id,
            request_sequence,
            deadline_unix_ms,
            profile_install_id,
            activation_nonce,
            request_id,
            method: LocalMethodWire::ChainId,
            params: [],
            route: LocalRouteWire::Permission,
            context,
        } = self;
        if request_sequence == 0
            || request_sequence > JAVASCRIPT_MAX_SAFE_INTEGER
            || deadline_unix_ms == 0
            || deadline_unix_ms > JAVASCRIPT_MAX_SAFE_INTEGER
        {
            return Err(BrokerIpcError::Malformed);
        }
        let session_id = nonzero(session_id)?;
        let profile_install_id = nonzero(profile_install_id)?;
        let activation_nonce = nonzero(activation_nonce)?;
        let request_id = nonzero(request_id)?;
        let context = context.into_context(
            profile_install_id,
            activation_nonce,
            session_id,
            request_sequence,
            deadline_unix_ms,
            request_id,
        )?;
        TransportRequest::new(
            context,
            "eth_chainId".to_owned(),
            serde_json::Value::Array(Vec::new()),
            ProviderRoute::Permission,
        )
        .map_err(|_| BrokerIpcError::Malformed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum LocalMethodWire {
    #[serde(rename = "eth_chainId")]
    ChainId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum LocalRouteWire {
    #[serde(rename = "permission")]
    Permission,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BrowserContextWire {
    browser_family: BrowserFamilyWire,
    extension_id: String,
    tab_id: u64,
    frame_id: u64,
    document_id: String,
    top_origin: String,
    frame_origin: String,
    document_lifecycle: DocumentLifecycleWire,
    channel_nonce: FixedHex<32>,
}

impl BrowserContextWire {
    fn from_context(context: &BrowserContext) -> Self {
        Self {
            browser_family: BrowserFamilyWire::Chrome,
            extension_id: context.extension_id.as_str().to_owned(),
            tab_id: context.tab_id,
            frame_id: context.frame_id,
            document_id: context.document_id.as_str().to_owned(),
            top_origin: context.top_origin.as_str().to_owned(),
            frame_origin: context.frame_origin.as_str().to_owned(),
            document_lifecycle: DocumentLifecycleWire::Active,
            channel_nonce: FixedHex(*context.channel_nonce.as_bytes()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn into_context(
        self,
        profile_install_id: FixedHex<32>,
        activation_nonce: FixedHex<32>,
        session_id: FixedHex<32>,
        sequence: u64,
        deadline_ms: u64,
        request_id: FixedHex<16>,
    ) -> Result<BrowserContext, BrokerIpcError> {
        let Self {
            browser_family: BrowserFamilyWire::Chrome,
            extension_id,
            tab_id,
            frame_id,
            document_id,
            top_origin,
            frame_origin,
            document_lifecycle: DocumentLifecycleWire::Active,
            channel_nonce,
        } = self;
        if tab_id > JAVASCRIPT_MAX_SAFE_INTEGER || frame_id != 0 {
            return Err(BrokerIpcError::Malformed);
        }
        let channel_nonce = nonzero(channel_nonce)?;
        let top_origin = BrowserOrigin::new(top_origin).map_err(|_| BrokerIpcError::Malformed)?;
        let frame_origin =
            BrowserOrigin::new(frame_origin).map_err(|_| BrokerIpcError::Malformed)?;
        if !top_origin.as_str().starts_with("https://") || top_origin != frame_origin {
            return Err(BrokerIpcError::Malformed);
        }
        Ok(BrowserContext {
            browser_family: BrowserFamily::Chrome,
            profile_install_id: ProfileInstallId::new(profile_install_id.0),
            extension_id: ExtensionId::new(extension_id).map_err(|_| BrokerIpcError::Malformed)?,
            tab_id,
            frame_id,
            document_id: DocumentId::new(document_id).map_err(|_| BrokerIpcError::Malformed)?,
            activation_nonce: ActivationNonce::new(activation_nonce.0),
            top_origin,
            frame_origin,
            document_lifecycle: DocumentLifecycle::Active,
            channel_nonce: ChannelNonce::new(channel_nonce.0),
            provenance: BrowserProvenance::BrowserReportedUnverified,
            session_id: SessionId::new(session_id.0),
            sequence,
            deadline_ms,
            request_id: RequestId::new(request_id.0),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum BrowserFamilyWire {
    #[serde(rename = "chrome")]
    Chrome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum DocumentLifecycleWire {
    #[serde(rename = "active")]
    Active,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResponseBindingWire {
    session_id: FixedHex<32>,
    request_sequence: u64,
    activation_nonce: FixedHex<32>,
    request_id: FixedHex<16>,
}

impl ResponseBindingWire {
    fn from_context(context: &BrowserContext) -> Self {
        Self {
            session_id: FixedHex(*context.session_id.as_bytes()),
            request_sequence: context.sequence,
            activation_nonce: FixedHex(*context.activation_nonce.as_bytes()),
            request_id: FixedHex(*context.request_id.as_bytes()),
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CancellationBindingWire {
    session_id: FixedHex<32>,
    cancellation_sequence: u64,
    activation_nonce: FixedHex<32>,
    request_id: FixedHex<16>,
    request_sequence: u64,
}

impl CancellationBindingWire {
    const fn from_transport(cancellation: TransportCancellation) -> Self {
        Self {
            session_id: FixedHex(cancellation.session_id),
            cancellation_sequence: cancellation.sequence,
            activation_nonce: FixedHex(*cancellation.activation_nonce.as_bytes()),
            request_id: FixedHex(cancellation.request_id),
            request_sequence: cancellation.request_sequence,
        }
    }

    fn into_transport(self) -> Result<TransportCancellation, BrokerIpcError> {
        if self.cancellation_sequence == 0
            || self.cancellation_sequence > JAVASCRIPT_MAX_SAFE_INTEGER
            || self.request_sequence == 0
            || self.request_sequence >= self.cancellation_sequence
        {
            return Err(BrokerIpcError::Malformed);
        }
        Ok(TransportCancellation {
            session_id: nonzero(self.session_id)?.0,
            sequence: self.cancellation_sequence,
            activation_nonce: ActivationNonce::new(nonzero(self.activation_nonce)?.0),
            request_id: nonzero(self.request_id)?.0,
            request_sequence: self.request_sequence,
        })
    }
}

impl fmt::Debug for ResponseBindingWire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponseBindingWire([REDACTED])")
    }
}

impl fmt::Debug for CancellationBindingWire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CancellationBindingWire([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FixedHex<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> fmt::Debug for FixedHex<LENGTH> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedHex([REDACTED])")
    }
}

impl<'de, const LENGTH: usize> Deserialize<'de> for FixedHex<LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        if text.len() != LENGTH.saturating_mul(2)
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(serde::de::Error::custom(
                "expected fixed-width lowercase hexadecimal",
            ));
        }
        let mut bytes = [0_u8; LENGTH];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index.saturating_mul(2);
            let high = decode_nibble(text.as_bytes()[offset])
                .ok_or_else(|| serde::de::Error::custom("invalid hexadecimal"))?;
            let low = decode_nibble(text.as_bytes()[offset.saturating_add(1)])
                .ok_or_else(|| serde::de::Error::custom("invalid hexadecimal"))?;
            *output = high << 4 | low;
        }
        Ok(Self(bytes))
    }
}

impl<const LENGTH: usize> Serialize for FixedHex<LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(LENGTH.saturating_mul(2));
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        serializer.serialize_str(&output)
    }
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl From<BrokerError> for BrokerIpcError {
    fn from(_value: BrokerError) -> Self {
        Self::BrokerRejected
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::Instant;

    use serde_json::json;
    use wallet_model::{
        ActivationNonce, Address20, BrowserContext, BrowserFamily, BrowserOrigin,
        BrowserProvenance, ChannelNonce, DocumentId, DocumentLifecycle, ExtensionId,
        ProfileInstallId, RequestId, SessionId, U256,
    };

    use super::{
        BrokerIpcClient, BrokerIpcError, ClientBodyWire, ClientFrameWire, FixedHex,
        MAX_BROKER_IPC_COMMANDS, MAX_BROKER_IPC_FRAME_BYTES, Namespace, ServerBodyWire,
        ServerFrameWire, run_secretless_server, write_frame,
    };
    use crate::{
        PermissionStore, ProviderRoute, TransportBroker, TransportCancellation, TransportRequest,
    };

    fn request(sequence: u64, id: u8) -> Result<TransportRequest, Box<dyn std::error::Error>> {
        request_for(
            sequence,
            id,
            "eth_chainId",
            json!([]),
            ProviderRoute::Permission,
        )
    }

    fn request_for(
        sequence: u64,
        id: u8,
        method: &str,
        params: serde_json::Value,
        route: ProviderRoute,
    ) -> Result<TransportRequest, Box<dyn std::error::Error>> {
        request_for_id(sequence, [id; 16], method, params, route)
    }

    fn request_for_id(
        sequence: u64,
        id: [u8; 16],
        method: &str,
        params: serde_json::Value,
        route: ProviderRoute,
    ) -> Result<TransportRequest, Box<dyn std::error::Error>> {
        let context = BrowserContext {
            browser_family: BrowserFamily::Chrome,
            profile_install_id: ProfileInstallId::new([1; 32]),
            extension_id: ExtensionId::new("abcdefghijklmnopabcdefghijklmnop")?,
            tab_id: 17,
            frame_id: 0,
            document_id: DocumentId::new("document-17")?,
            activation_nonce: ActivationNonce::new([3; 32]),
            top_origin: BrowserOrigin::new("https://dapp.example")?,
            frame_origin: BrowserOrigin::new("https://dapp.example")?,
            document_lifecycle: DocumentLifecycle::Active,
            channel_nonce: ChannelNonce::new([4; 32]),
            provenance: BrowserProvenance::BrowserReportedUnverified,
            session_id: SessionId::new([2; 32]),
            sequence,
            deadline_ms: 1_700_000_120_000,
            request_id: RequestId::new(id),
        };
        Ok(TransportRequest::new(
            context,
            method.to_owned(),
            params,
            route,
        )?)
    }

    fn client_frame(sequence: u64, body: ClientBodyWire) -> ClientFrameWire {
        ClientFrameWire {
            namespace: Namespace::YourWalletBroker,
            version: 1,
            role: super::ClientRole::NativeHost,
            client_nonce: FixedHex([7; 32]),
            sequence,
            body,
        }
    }

    fn assert_unavailable_has_no_raw_request_data(
        unavailable: &super::UnavailableRequestWire,
    ) -> Result<(), serde_json::Error> {
        let encoded = serde_json::to_string(unavailable)?;
        for forbidden in [
            "params",
            "personal_sign",
            "0xfeed",
            "1111111111111111111111111111111111111111",
            "dapp.example",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn client_and_server_round_trip_chain_id_and_complete_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut client_to_server = Vec::new();
        write_frame(
            &mut client_to_server,
            &ClientFrameWire {
                namespace: Namespace::YourWalletBroker,
                version: 1,
                role: super::ClientRole::NativeHost,
                client_nonce: FixedHex([7; 32]),
                sequence: 1,
                body: ClientBodyWire::Hello,
            },
        )?;
        let request = request(1, 8)?;
        write_frame(
            &mut client_to_server,
            &ClientFrameWire {
                namespace: Namespace::YourWalletBroker,
                version: 1,
                role: super::ClientRole::NativeHost,
                client_nonce: FixedHex([7; 32]),
                sequence: 2,
                body: ClientBodyWire::Request {
                    server_nonce: FixedHex([9; 32]),
                    request_nonce: FixedHex([11; 32]),
                    request: super::LocalRequestWire::from_transport(&request)?,
                },
            },
        )?;

        let mut broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([1; 20]),
            U256::from_u64(11_155_111),
        );
        let now = Instant::now();
        let mut clock = || Ok((now, 1_700_000_000_000));
        let mut server_output = Vec::new();
        let summary = run_secretless_server(
            &mut Cursor::new(client_to_server),
            &mut server_output,
            &mut broker,
            [9; 32],
            &mut clock,
        )?;
        assert_eq!(summary.commands(), 1);
        assert_eq!(summary.responses(), 1);
        assert_eq!(broker.pending_len(), 0);

        let mut responses = Cursor::new(server_output);
        let mut client_hello_input = Vec::new();
        let hello: ServerFrameWire = super::read_required_frame(&mut responses)?;
        write_frame(&mut client_hello_input, &hello)?;
        let mut client = BrokerIpcClient::connect(
            &mut Cursor::new(client_hello_input),
            &mut Vec::new(),
            [7; 32],
        )?;
        let result: ServerFrameWire = super::read_required_frame(&mut responses)?;
        let mut result_input = Vec::new();
        write_frame(&mut result_input, &result)?;
        let mut ignored_request_output = Vec::new();
        assert_eq!(
            client.execute_chain_id(
                &mut Cursor::new(result_input),
                &mut ignored_request_output,
                &request,
                [11; 32],
            )?,
            U256::from_u64(11_155_111)
        );
        Ok(())
    }

    #[test]
    fn unavailable_command_preserves_global_sequence_and_late_cancel_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = request(1, 8)?;
        let unavailable_request = request_for(
            2,
            9,
            "personal_sign",
            json!(["0xfeed", "0x1111111111111111111111111111111111111111"]),
            ProviderRoute::Signing,
        )?;
        let third = request(3, 10)?;
        let unavailable = super::UnavailableRequestWire::from_transport(&unavailable_request)?;
        assert_unavailable_has_no_raw_request_data(&unavailable)?;

        let cancellation = TransportCancellation {
            session_id: [2; 32],
            sequence: 4,
            activation_nonce: ActivationNonce::new([3; 32]),
            request_id: [9; 16],
            request_sequence: 2,
        };
        let mut client_to_server = Vec::new();
        for frame in [
            client_frame(1, ClientBodyWire::Hello),
            client_frame(
                2,
                ClientBodyWire::Request {
                    server_nonce: FixedHex([9; 32]),
                    request_nonce: FixedHex([11; 32]),
                    request: super::LocalRequestWire::from_transport(&first)?,
                },
            ),
            client_frame(
                3,
                ClientBodyWire::Unavailable {
                    server_nonce: FixedHex([9; 32]),
                    request_nonce: FixedHex([12; 32]),
                    unavailable,
                },
            ),
            client_frame(
                4,
                ClientBodyWire::Request {
                    server_nonce: FixedHex([9; 32]),
                    request_nonce: FixedHex([13; 32]),
                    request: super::LocalRequestWire::from_transport(&third)?,
                },
            ),
            client_frame(
                5,
                ClientBodyWire::Cancel {
                    server_nonce: FixedHex([9; 32]),
                    cancellation_nonce: FixedHex([14; 32]),
                    cancellation: super::CancellationBindingWire::from_transport(cancellation),
                },
            ),
        ] {
            write_frame(&mut client_to_server, &frame)?;
        }

        let mut broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([1; 20]),
            U256::from_u64(11_155_111),
        );
        let now = Instant::now();
        let mut clock = || Ok((now, 1_700_000_000_000));
        let mut server_output = Vec::new();
        let summary = run_secretless_server(
            &mut Cursor::new(client_to_server),
            &mut server_output,
            &mut broker,
            [9; 32],
            &mut clock,
        )?;
        assert_eq!(summary.commands(), 4);
        assert_eq!(summary.responses(), 4);
        assert_eq!(summary.unavailable_completions(), 1);
        assert_eq!(summary.cancellations(), 1);
        assert_eq!(broker.pending_len(), 0);

        let mut responses = Cursor::new(server_output);
        let bodies = (0..5)
            .map(|_| super::read_required_frame::<ServerFrameWire>(&mut responses))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|frame| frame.body)
            .collect::<Vec<_>>();
        assert!(matches!(bodies[0], ServerBodyWire::Hello { .. }));
        assert!(matches!(bodies[1], ServerBodyWire::ChainId { .. }));
        assert!(matches!(bodies[2], ServerBodyWire::Unavailable { .. }));
        assert!(matches!(bodies[3], ServerBodyWire::ChainId { .. }));
        assert!(matches!(
            bodies[4],
            ServerBodyWire::Cancelled {
                disposition: super::CancellationDispositionWire::AlreadyCompleted,
                ..
            }
        ));
        assert!(super::read_frame::<ServerFrameWire>(&mut responses)?.is_none());
        Ok(())
    }

    #[test]
    fn server_accepts_exact_command_lifetime_and_rejects_the_next_frame_before_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut exact_input = Vec::new();
        write_frame(&mut exact_input, &client_frame(1, ClientBodyWire::Hello))?;
        for command_index in 1..=MAX_BROKER_IPC_COMMANDS {
            let request = request_for_id(
                command_index,
                u128::from(command_index).to_be_bytes(),
                "eth_chainId",
                json!([]),
                ProviderRoute::Permission,
            )?;
            let mut request_nonce = [0_u8; 32];
            request_nonce[24..].copy_from_slice(&command_index.to_be_bytes());
            write_frame(
                &mut exact_input,
                &client_frame(
                    command_index + 1,
                    ClientBodyWire::Request {
                        server_nonce: FixedHex([9; 32]),
                        request_nonce: FixedHex(request_nonce),
                        request: super::LocalRequestWire::from_transport(&request)?,
                    },
                ),
            )?;
        }

        let mut overflow_input = exact_input.clone();
        let overflow_index = MAX_BROKER_IPC_COMMANDS + 1;
        let overflow_request = request_for_id(
            overflow_index,
            u128::from(overflow_index).to_be_bytes(),
            "eth_chainId",
            json!([]),
            ProviderRoute::Permission,
        )?;
        let mut overflow_nonce = [0_u8; 32];
        overflow_nonce[24..].copy_from_slice(&overflow_index.to_be_bytes());
        write_frame(
            &mut overflow_input,
            &client_frame(
                overflow_index + 1,
                ClientBodyWire::Request {
                    server_nonce: FixedHex([9; 32]),
                    request_nonce: FixedHex(overflow_nonce),
                    request: super::LocalRequestWire::from_transport(&overflow_request)?,
                },
            ),
        )?;

        let now = Instant::now();
        let mut exact_clock = || Ok((now, 1_700_000_000_000));
        let mut exact_broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([1; 20]),
            U256::from_u64(11_155_111),
        );
        let summary = run_secretless_server(
            &mut Cursor::new(exact_input),
            &mut std::io::sink(),
            &mut exact_broker,
            [9; 32],
            &mut exact_clock,
        )?;
        assert_eq!(summary.commands(), MAX_BROKER_IPC_COMMANDS);
        assert_eq!(summary.responses(), MAX_BROKER_IPC_COMMANDS);
        assert_eq!(exact_broker.pending_len(), 0);

        let mut overflow_clock = || Ok((now, 1_700_000_000_000));
        let mut overflow_broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([1; 20]),
            U256::from_u64(11_155_111),
        );
        assert!(matches!(
            run_secretless_server(
                &mut Cursor::new(overflow_input),
                &mut std::io::sink(),
                &mut overflow_broker,
                [9; 32],
                &mut overflow_clock,
            ),
            Err(BrokerIpcError::Capacity)
        ));
        assert_eq!(overflow_broker.pending_len(), 0);
        Ok(())
    }

    #[test]
    fn codec_rejects_oversize_duplicate_and_wrong_role_frames() {
        let advertised = u32::try_from(MAX_BROKER_IPC_FRAME_BYTES + 1)
            .unwrap_or(u32::MAX)
            .to_be_bytes();
        assert!(matches!(
            super::read_frame::<ClientFrameWire>(&mut Cursor::new(advertised)),
            Err(BrokerIpcError::Oversized)
        ));

        let payload = br#"{"namespace":"your-wallet-broker","namespace":"your-wallet-broker","version":1,"role":"native-host","clientNonce":"0707070707070707070707070707070707070707070707070707070707070707","sequence":1,"body":{"kind":"hello"}}"#;
        let mut duplicate = u32::try_from(payload.len())
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();
        duplicate.extend_from_slice(payload);
        assert!(matches!(
            super::read_frame::<ClientFrameWire>(&mut Cursor::new(duplicate)),
            Err(BrokerIpcError::Malformed)
        ));

        let wrong = ServerFrameWire {
            namespace: Namespace::YourWalletBroker,
            version: 1,
            role: super::ServerRole::Broker,
            client_nonce: FixedHex([8; 32]),
            sequence: 1,
            body: ServerBodyWire::Hello {
                server_nonce: FixedHex([9; 32]),
            },
        };
        let mut input = Vec::new();
        write_frame(&mut input, &wrong).unwrap_or(());
        assert!(matches!(
            BrokerIpcClient::connect(&mut Cursor::new(input), &mut Vec::new(), [7; 32]),
            Err(BrokerIpcError::Binding)
        ));
    }

    #[test]
    fn error_debug_never_repeats_transport_details() {
        let error = BrokerIpcError::Io;
        assert_eq!(format!("{error:?}"), "BrokerIpcError::Io([REDACTED])");
        assert_eq!(error.to_string(), "broker IPC transport failed");
        assert!(std::error::Error::source(&error).is_none());
    }
}
