//! Exact version-1 extension/native-host wire contract.

use core::fmt;
use std::io::{Read, Write};

use broker::{
    AuthorizedDispatch, BrokerError, ProviderRoute, TransportBroker, TransportCancellation,
    TransportRequest,
};
use platform_windows::attestation::ReleaseAttestation;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;
use wallet_model::{
    ActivationNonce, BrowserContext, BrowserFamily, BrowserOrigin, BrowserProvenance, ChannelNonce,
    DocumentId, DocumentLifecycle, ExtensionId, ProfileInstallId, RequestId, SessionId,
};

use crate::{FrameError, MAX_FRAME_BYTES, read_frame, write_frame};

const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const PROTOCOL_VERSION: u8 = 1;
const UNAVAILABLE_CODE: i64 = 4_900;
const UNAVAILABLE_MESSAGE: &str = "Private wallet broker is unavailable.";
const MAX_ERROR_MESSAGE_UTF16_UNITS: usize = 512;

/// Maximum messages accepted on one persistent native-messaging stream.
///
/// This is a session-wide resource ceiling across both requests and
/// cancellations. Reaching the ceiling is allowed; an additional frame is a
/// terminal protocol error.
pub const MAX_FRAMES_PER_STREAM: u64 = 4_096;

/// Exact parsed extension message.
pub enum ExtensionEnvelope {
    /// Provider request with browser-owned context.
    Request(Box<TransportRequest>),
    /// Cancellation bound to an earlier request and the same activation.
    Cancel(TransportCancellation),
}

impl fmt::Debug for ExtensionEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Request(_) => "ExtensionEnvelope::Request([REDACTED])",
            Self::Cancel(_) => "ExtensionEnvelope::Cancel([REDACTED])",
        })
    }
}

/// Result of applying one typed envelope to the in-memory dispatcher.
// The admitted capability intentionally remains an owned, unboxed linear value;
// adding indirection here would change the public wire-dispatch API.
#[allow(clippy::large_enum_variant)]
pub enum DispatchOutcome {
    /// A public response is ready to return to Chrome.
    Response(Value),
    /// A release-attested broker accepted the request; its sealed admission must
    /// be consumed by the selected downstream adapter.
    Admitted(AuthorizedDispatch),
    /// A cancellation was consumed and has no native response.
    Cancelled,
}

/// Downstream adapter that consumes one broker-authorized linear admission.
///
/// The implementation must finish all request work, including broker pending
/// state completion, before returning. The native host assigns an outbound
/// sequence and emits a response only after this call returns.
pub trait DownstreamExecutor {
    /// Execute an admitted operation to completion.
    fn execute_to_completion(&mut self, admission: AuthorizedDispatch) -> ExecutionOutcome;
}

/// Exact JSON-RPC result returned by an admitted downstream operation.
pub enum ExecutionOutcome {
    /// Successful JSON result value.
    Success(Value),
    /// Stable provider-facing error.
    Error(NativeRpcError),
}

impl ExecutionOutcome {
    /// Create a successful downstream result.
    #[must_use]
    pub const fn success(value: Value) -> Self {
        Self::Success(value)
    }

    /// Create a downstream provider error.
    #[must_use]
    pub const fn error(error: NativeRpcError) -> Self {
        Self::Error(error)
    }
}

impl fmt::Debug for ExecutionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Success(_) => "ExecutionOutcome::Success([REDACTED])",
            Self::Error(_) => "ExecutionOutcome::Error([REDACTED])",
        })
    }
}

/// Provider error body that cannot alter response correlation fields.
pub struct NativeRpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl NativeRpcError {
    /// Create a bounded provider error.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ResponseEncoding`] when the code is not a
    /// JavaScript-safe integer or the message is empty or longer than 512
    /// UTF-16 code units. The final framed-size bound is checked at encoding.
    pub fn new(
        code: i64,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> Result<Self, ProtocolError> {
        let message = message.into();
        let safe_integer = i64::try_from(JAVASCRIPT_MAX_SAFE_INTEGER)
            .map_err(|_| ProtocolError::ResponseEncoding)?;
        if !(-safe_integer..=safe_integer).contains(&code)
            || message.is_empty()
            || message.encode_utf16().count() > MAX_ERROR_MESSAGE_UTF16_UNITS
        {
            return Err(ProtocolError::ResponseEncoding);
        }
        Ok(Self {
            code,
            message,
            data,
        })
    }
}

impl fmt::Debug for NativeRpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeRpcError([REDACTED])")
    }
}

impl fmt::Debug for DispatchOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Response(_) => "DispatchOutcome::Response([REDACTED])",
            Self::Admitted(_) => "DispatchOutcome::Admitted([REDACTED])",
            Self::Cancelled => "DispatchOutcome::Cancelled",
        })
    }
}

/// Version-1 protocol parse or state failure.
#[derive(Error)]
pub enum ProtocolError {
    /// JSON object does not match one exact version-1 message schema.
    #[error("invalid extension envelope")]
    InvalidEnvelope,
    /// Session identifier or the combined request/cancellation sequence changed.
    #[error("extension session sequence mismatch")]
    SessionSequence,
    /// Broker endpoint was unavailable or rejected the request.
    #[error("private broker endpoint rejected the request")]
    BrokerRejected,
    /// A response could not be encoded within the native-messaging contract.
    #[error("native response encoding failed")]
    ResponseEncoding,
    /// The fixed per-stream frame ceiling was exceeded.
    #[error("native messaging stream frame limit exceeded")]
    StreamLimit,
    /// Native-messaging framing failed.
    #[error("native messaging framing failed")]
    Framing(#[from] FrameError),
}

impl fmt::Debug for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEnvelope => "ProtocolError::InvalidEnvelope",
            Self::SessionSequence => "ProtocolError::SessionSequence",
            Self::BrokerRejected => "ProtocolError::BrokerRejected",
            Self::ResponseEncoding => "ProtocolError::ResponseEncoding",
            Self::StreamLimit => "ProtocolError::StreamLimit",
            Self::Framing(_) => "ProtocolError::Framing([REDACTED])",
        })
    }
}

/// Failure returned by an authenticated broker endpoint implementation.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BrokerEndpointError {
    /// Public broker policy rejected the request.
    #[error("broker policy rejected request")]
    Policy,
    /// The private endpoint became unavailable.
    #[error("broker transport unavailable")]
    Unavailable,
}

impl From<BrokerError> for BrokerEndpointError {
    fn from(_value: BrokerError) -> Self {
        Self::Policy
    }
}

/// Private broker endpoint used only after release attestation succeeds.
pub trait BrokerEndpoint {
    /// Start a fresh extension/native session and invalidate the previous one.
    ///
    /// # Errors
    ///
    /// Returns a stable endpoint failure without falling back to public IPC.
    fn begin_session(&mut self, session_id: [u8; 32]) -> Result<(), BrokerEndpointError>;

    /// Validate and admit a request. This contract does not itself execute RPC
    /// or signing work; downstream code must consume the returned sealed admission.
    ///
    /// # Errors
    ///
    /// Returns a stable endpoint failure on any policy or transport rejection.
    fn admit(
        &mut self,
        request: &TransportRequest,
        now_unix_ms: u64,
    ) -> Result<AuthorizedDispatch, BrokerEndpointError>;

    /// Cancel one exactly bound pending request.
    ///
    /// # Errors
    ///
    /// Returns a stable endpoint failure on a replay or context mismatch.
    fn cancel(&mut self, cancellation: TransportCancellation) -> Result<(), BrokerEndpointError>;
}

impl BrokerEndpoint for TransportBroker {
    fn begin_session(&mut self, session_id: [u8; 32]) -> Result<(), BrokerEndpointError> {
        Self::begin_session(self, session_id).map_err(Into::into)
    }

    fn admit(
        &mut self,
        request: &TransportRequest,
        now_unix_ms: u64,
    ) -> Result<AuthorizedDispatch, BrokerEndpointError> {
        Self::admit(self, request, std::time::Instant::now(), now_unix_ms).map_err(Into::into)
    }

    fn cancel(&mut self, cancellation: TransportCancellation) -> Result<(), BrokerEndpointError> {
        Self::cancel(self, cancellation).map_err(Into::into)
    }
}

/// Stateful in-memory dispatcher. It never contacts an endpoint unless the
/// immutable release-attestation gate is enabled.
pub struct NativeHostDispatcher<Endpoint> {
    endpoint: Endpoint,
    attestation: ReleaseAttestation,
    session_id: Option<[u8; 32]>,
    next_inbound_sequence: u64,
    next_outbound_sequence: u64,
}

impl<Endpoint> fmt::Debug for NativeHostDispatcher<Endpoint> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeHostDispatcher")
            .field("endpoint", &"[REDACTED]")
            .field("attestation", &self.attestation.signing_enabled())
            .field("session_id", &"[REDACTED]")
            .field("next_inbound_sequence", &"[REDACTED]")
            .field("next_outbound_sequence", &"[REDACTED]")
            .finish()
    }
}

impl<Endpoint: BrokerEndpoint> NativeHostDispatcher<Endpoint> {
    /// Create a dispatcher. Development attestation is disabled, so injected
    /// endpoints remain unreachable in non-release-policy builds.
    #[must_use]
    pub const fn new(endpoint: Endpoint, attestation: ReleaseAttestation) -> Self {
        Self {
            endpoint,
            attestation,
            session_id: None,
            next_inbound_sequence: 1,
            next_outbound_sequence: 1,
        }
    }

    /// Dispatch one parsed envelope and return an optional native response.
    ///
    /// A cancellation has no response. An unattested request receives the same
    /// stable provider error and is never passed to the endpoint.
    ///
    /// # Errors
    ///
    /// Returns a session/sequence or response-codec failure.
    pub fn dispatch(
        &mut self,
        envelope: ExtensionEnvelope,
        now_unix_ms: u64,
    ) -> Result<DispatchOutcome, ProtocolError> {
        match envelope {
            ExtensionEnvelope::Request(request) => {
                self.observe(
                    *request.context().session_id.as_bytes(),
                    request.context().sequence,
                )?;
                if !self.attestation.signing_enabled() {
                    let response_sequence = self.take_outbound_sequence()?;
                    return unavailable_response(&request, response_sequence)
                        .map(DispatchOutcome::Response);
                }
                let admission = self
                    .endpoint
                    .admit(&request, now_unix_ms)
                    .map_err(|_| ProtocolError::BrokerRejected)?;
                Ok(DispatchOutcome::Admitted(admission))
            }
            ExtensionEnvelope::Cancel(cancellation) => {
                self.observe(cancellation.session_id, cancellation.sequence)?;
                if self.attestation.signing_enabled() {
                    self.endpoint
                        .cancel(cancellation)
                        .map_err(|_| ProtocolError::BrokerRejected)?;
                }
                Ok(DispatchOutcome::Cancelled)
            }
        }
    }

    fn execute_admitted<Executor: DownstreamExecutor>(
        &mut self,
        admission: AuthorizedDispatch,
        executor: &mut Executor,
    ) -> Result<Value, ProtocolError> {
        let binding = ResponseBinding::from_admission(&admission);
        let outcome = executor.execute_to_completion(admission);
        let response_sequence = self.take_outbound_sequence()?;
        encode_execution_response(binding, response_sequence, outcome)
    }

    fn observe(&mut self, session_id: [u8; 32], sequence: u64) -> Result<(), ProtocolError> {
        match self.session_id {
            None => {
                if sequence != 1 {
                    return Err(ProtocolError::SessionSequence);
                }
                self.session_id = Some(session_id);
                self.next_inbound_sequence = 2;
                if self.attestation.signing_enabled() {
                    self.endpoint
                        .begin_session(session_id)
                        .map_err(|_| ProtocolError::BrokerRejected)?;
                }
                Ok(())
            }
            Some(current) if current == session_id && sequence == self.next_inbound_sequence => {
                self.next_inbound_sequence = self
                    .next_inbound_sequence
                    .checked_add(1)
                    .ok_or(ProtocolError::SessionSequence)?;
                Ok(())
            }
            Some(_) => Err(ProtocolError::SessionSequence),
        }
    }

    fn take_outbound_sequence(&mut self) -> Result<u64, ProtocolError> {
        let current = self.next_outbound_sequence;
        self.next_outbound_sequence = current
            .checked_add(1)
            .filter(|next| *next <= JAVASCRIPT_MAX_SAFE_INTEGER)
            .ok_or(ProtocolError::SessionSequence)?;
        Ok(current)
    }
}

/// Non-sensitive counters returned when a persistent stream reaches clean EOF.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeSummary {
    frames_read: u64,
    responses_written: u64,
    cancellations: u64,
}

impl RuntimeSummary {
    /// Number of accepted request and cancellation frames.
    #[must_use]
    pub const fn frames_read(self) -> u64 {
        self.frames_read
    }

    /// Number of response frames flushed after completed requests.
    #[must_use]
    pub const fn responses_written(self) -> u64 {
        self.responses_written
    }

    /// Number of cancellation frames consumed without a response.
    #[must_use]
    pub const fn cancellations(self) -> u64 {
        self.cancellations
    }
}

/// Process a bounded sequence of exact native-messaging frames until clean EOF.
///
/// Requests are dispatched through the supplied attestation-gated dispatcher.
/// An admitted request is synchronously consumed by `executor`; only after it
/// returns is the next outbound sequence assigned and the response flushed.
/// Cancellations never produce a response. Any malformed frame or state error
/// terminates the stream without attempting to parse later bytes.
///
/// `now_unix_ms` is invoked once per request, never for a cancellation.
///
/// # Errors
///
/// Returns on the first framing, envelope, sequence, clock, broker, executor
/// response-encoding, or stream-limit error. No recovery or resynchronization is
/// attempted after an error.
pub fn run_persistent_stream<Endpoint, Executor, Clock>(
    reader: &mut impl Read,
    writer: &mut impl Write,
    dispatcher: &mut NativeHostDispatcher<Endpoint>,
    executor: &mut Executor,
    now_unix_ms: &mut Clock,
) -> Result<RuntimeSummary, ProtocolError>
where
    Endpoint: BrokerEndpoint,
    Executor: DownstreamExecutor,
    Clock: FnMut() -> Result<u64, ProtocolError>,
{
    run_persistent_stream_with_limit(
        reader,
        writer,
        dispatcher,
        executor,
        now_unix_ms,
        MAX_FRAMES_PER_STREAM,
    )
}

fn run_persistent_stream_with_limit<Endpoint, Executor, Clock>(
    reader: &mut impl Read,
    writer: &mut impl Write,
    dispatcher: &mut NativeHostDispatcher<Endpoint>,
    executor: &mut Executor,
    now_unix_ms: &mut Clock,
    frame_limit: u64,
) -> Result<RuntimeSummary, ProtocolError>
where
    Endpoint: BrokerEndpoint,
    Executor: DownstreamExecutor,
    Clock: FnMut() -> Result<u64, ProtocolError>,
{
    let mut summary = RuntimeSummary::default();
    loop {
        let Some(value) = read_frame(reader)? else {
            return Ok(summary);
        };
        if summary.frames_read >= frame_limit {
            return Err(ProtocolError::StreamLimit);
        }
        summary.frames_read = summary
            .frames_read
            .checked_add(1)
            .ok_or(ProtocolError::StreamLimit)?;

        let envelope = parse_extension_envelope(value)?;
        let observed_at = if matches!(&envelope, ExtensionEnvelope::Request(_)) {
            let now = now_unix_ms()?;
            if now > JAVASCRIPT_MAX_SAFE_INTEGER {
                return Err(ProtocolError::InvalidEnvelope);
            }
            now
        } else {
            0
        };
        match dispatcher.dispatch(envelope, observed_at)? {
            DispatchOutcome::Response(response) => {
                write_frame(writer, &response)?;
                summary.responses_written = summary
                    .responses_written
                    .checked_add(1)
                    .ok_or(ProtocolError::StreamLimit)?;
            }
            DispatchOutcome::Admitted(admission) => {
                let response = dispatcher.execute_admitted(admission, executor)?;
                write_frame(writer, &response)?;
                summary.responses_written = summary
                    .responses_written
                    .checked_add(1)
                    .ok_or(ProtocolError::StreamLimit)?;
            }
            DispatchOutcome::Cancelled => {
                summary.cancellations = summary
                    .cancellations
                    .checked_add(1)
                    .ok_or(ProtocolError::StreamLimit)?;
            }
        }
    }
}

/// Result of the deliberately unattested executable path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnattestedOutcome {
    /// Input ended before a frame began.
    EndOfStream,
    /// A valid request received the stable unavailable response.
    RespondedUnavailable,
    /// A valid cancellation was consumed without contacting a broker.
    CancelledUnavailable,
}

/// Read one Chrome frame, validate the exact envelope, and fail closed without
/// contacting any broker endpoint.
///
/// # Errors
///
/// Returns a framing or exact-envelope error. Valid requests always receive the
/// stable `4900` response before this function returns.
pub fn run_unattested_once(
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<UnattestedOutcome, ProtocolError> {
    let Some(value) = read_frame(reader)? else {
        return Ok(UnattestedOutcome::EndOfStream);
    };
    match parse_extension_envelope(value)? {
        ExtensionEnvelope::Request(request) => {
            let response = unavailable_response(&request, 1)?;
            write_frame(writer, &response)?;
            Ok(UnattestedOutcome::RespondedUnavailable)
        }
        ExtensionEnvelope::Cancel(_) => Ok(UnattestedOutcome::CancelledUnavailable),
    }
}

/// Parse a strict JSON object into one exact version-1 typed envelope.
///
/// Unknown keys, wrong literal values, noncanonical hexadecimal identifiers,
/// unsafe JavaScript integers, route/method mismatches, and invalid browser
/// context are rejected.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidEnvelope`] for every public schema failure.
pub fn parse_extension_envelope(value: Value) -> Result<ExtensionEnvelope, ProtocolError> {
    let kind = value
        .as_object()
        .and_then(|object| object.get("kind"))
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidEnvelope)?;
    match kind {
        "request" => parse_request(value)
            .map(Box::new)
            .map(ExtensionEnvelope::Request),
        "cancel" => parse_cancellation(value).map(ExtensionEnvelope::Cancel),
        _ => Err(ProtocolError::InvalidEnvelope),
    }
}

fn parse_request(value: Value) -> Result<TransportRequest, ProtocolError> {
    let wire: RequestWire =
        serde_json::from_value(value).map_err(|_| ProtocolError::InvalidEnvelope)?;
    if wire.version != PROTOCOL_VERSION
        || wire.sequence == 0
        || wire.sequence > JAVASCRIPT_MAX_SAFE_INTEGER
        || wire.deadline_unix_ms == 0
        || wire.deadline_unix_ms > JAVASCRIPT_MAX_SAFE_INTEGER
        || wire.context.tab_id > JAVASCRIPT_MAX_SAFE_INTEGER
        || wire.context.frame_id != 0
        || wire.session_id.is_zero()
        || wire.profile_install_id.is_zero()
        || wire.activation_nonce.is_zero()
        || wire.request_id.is_zero()
        || wire.context.channel_nonce.is_zero()
        || !valid_document_id(&wire.context.document_id)
    {
        return Err(ProtocolError::InvalidEnvelope);
    }
    let route = ProviderRoute::parse(&wire.route).ok_or(ProtocolError::InvalidEnvelope)?;
    let top_origin =
        BrowserOrigin::new(wire.context.top_origin).map_err(|_| ProtocolError::InvalidEnvelope)?;
    let frame_origin = BrowserOrigin::new(wire.context.frame_origin)
        .map_err(|_| ProtocolError::InvalidEnvelope)?;
    if !top_origin.as_str().starts_with("https://") || top_origin != frame_origin {
        return Err(ProtocolError::InvalidEnvelope);
    }
    let context = BrowserContext {
        browser_family: BrowserFamily::Chrome,
        profile_install_id: ProfileInstallId::new(wire.profile_install_id.0),
        extension_id: ExtensionId::new(wire.context.extension_id)
            .map_err(|_| ProtocolError::InvalidEnvelope)?,
        tab_id: wire.context.tab_id,
        frame_id: wire.context.frame_id,
        document_id: DocumentId::new(wire.context.document_id)
            .map_err(|_| ProtocolError::InvalidEnvelope)?,
        activation_nonce: ActivationNonce::new(wire.activation_nonce.0),
        top_origin,
        frame_origin,
        document_lifecycle: DocumentLifecycle::Active,
        channel_nonce: ChannelNonce::new(wire.context.channel_nonce.0),
        provenance: BrowserProvenance::BrowserReportedUnverified,
        session_id: SessionId::new(wire.session_id.0),
        sequence: wire.sequence,
        deadline_ms: wire.deadline_unix_ms,
        request_id: RequestId::new(wire.request_id.0),
    };
    TransportRequest::new(context, wire.method, wire.params, route)
        .map_err(|_| ProtocolError::InvalidEnvelope)
}

fn parse_cancellation(value: Value) -> Result<TransportCancellation, ProtocolError> {
    let wire: CancelWire =
        serde_json::from_value(value).map_err(|_| ProtocolError::InvalidEnvelope)?;
    if wire.version != PROTOCOL_VERSION
        || wire.sequence == 0
        || wire.sequence > JAVASCRIPT_MAX_SAFE_INTEGER
        || wire.request_sequence == 0
        || wire.request_sequence >= wire.sequence
        || wire.request_sequence > JAVASCRIPT_MAX_SAFE_INTEGER
        || wire.session_id.is_zero()
        || wire.activation_nonce.is_zero()
        || wire.request_id.is_zero()
        || !valid_cancel_reason(&wire.reason)
    {
        return Err(ProtocolError::InvalidEnvelope);
    }
    Ok(TransportCancellation {
        session_id: wire.session_id.0,
        sequence: wire.sequence,
        activation_nonce: ActivationNonce::new(wire.activation_nonce.0),
        request_id: wire.request_id.0,
        request_sequence: wire.request_sequence,
    })
}

fn valid_document_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_cancel_reason(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn unavailable_response(request: &TransportRequest, sequence: u64) -> Result<Value, ProtocolError> {
    let binding = ResponseBinding::from_context(request.context());
    let error = NativeRpcError {
        code: UNAVAILABLE_CODE,
        message: UNAVAILABLE_MESSAGE.to_owned(),
        data: None,
    };
    encode_execution_response(binding, sequence, ExecutionOutcome::Error(error))
}

#[derive(Clone, Copy)]
struct ResponseBinding {
    session_id: [u8; 32],
    request_sequence: u64,
    activation_nonce: [u8; 32],
    request_id: [u8; 16],
}

impl ResponseBinding {
    const fn from_admission(admission: &AuthorizedDispatch) -> Self {
        Self::from_context(admission.context())
    }

    const fn from_context(context: &BrowserContext) -> Self {
        Self {
            session_id: *context.session_id.as_bytes(),
            request_sequence: context.sequence,
            activation_nonce: *context.activation_nonce.as_bytes(),
            request_id: *context.request_id.as_bytes(),
        }
    }
}

fn encode_execution_response(
    binding: ResponseBinding,
    sequence: u64,
    outcome: ExecutionOutcome,
) -> Result<Value, ProtocolError> {
    if sequence == 0 || sequence > JAVASCRIPT_MAX_SAFE_INTEGER {
        return Err(ProtocolError::ResponseEncoding);
    }
    let response = match outcome {
        ExecutionOutcome::Success(result) => serde_json::to_value(NativeSuccessResponse {
            namespace: Namespace::YourWallet,
            version: PROTOCOL_VERSION,
            role: NativeRole::NativeHost,
            kind: ResponseKind::Response,
            session_id: FixedHex(binding.session_id),
            sequence,
            request_sequence: binding.request_sequence,
            activation_nonce: FixedHex(binding.activation_nonce),
            request_id: FixedHex(binding.request_id),
            result: &result,
        }),
        ExecutionOutcome::Error(error) => serde_json::to_value(NativeErrorResponse {
            namespace: Namespace::YourWallet,
            version: PROTOCOL_VERSION,
            role: NativeRole::NativeHost,
            kind: ResponseKind::Response,
            session_id: FixedHex(binding.session_id),
            sequence,
            request_sequence: binding.request_sequence,
            activation_nonce: FixedHex(binding.activation_nonce),
            request_id: FixedHex(binding.request_id),
            error: RpcErrorWire {
                code: error.code,
                message: &error.message,
                data: error.data.as_ref(),
            },
        }),
    }
    .map_err(|_| ProtocolError::ResponseEncoding)?;
    let encoded = serde_json::to_vec(&response).map_err(|_| ProtocolError::ResponseEncoding)?;
    if !response.is_object() || encoded.is_empty() || encoded.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::ResponseEncoding);
    }
    Ok(response)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeSuccessResponse<'result> {
    namespace: Namespace,
    version: u8,
    role: NativeRole,
    kind: ResponseKind,
    session_id: FixedHex<32>,
    sequence: u64,
    request_sequence: u64,
    activation_nonce: FixedHex<32>,
    request_id: FixedHex<16>,
    result: &'result Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeErrorResponse<'message, 'data> {
    namespace: Namespace,
    version: u8,
    role: NativeRole,
    kind: ResponseKind,
    session_id: FixedHex<32>,
    sequence: u64,
    request_sequence: u64,
    activation_nonce: FixedHex<32>,
    request_id: FixedHex<16>,
    error: RpcErrorWire<'message, 'data>,
}

#[derive(Serialize)]
struct RpcErrorWire<'message, 'data> {
    code: i64,
    message: &'message str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'data Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum Namespace {
    #[serde(rename = "your-wallet")]
    YourWallet,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum ExtensionRole {
    #[serde(rename = "extension")]
    Extension,
}

#[derive(Clone, Copy, Debug, Serialize)]
enum NativeRole {
    #[serde(rename = "native-host")]
    NativeHost,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum RequestKind {
    #[serde(rename = "request")]
    Request,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum CancelKind {
    #[serde(rename = "cancel")]
    Cancel,
}

#[derive(Clone, Copy, Debug, Serialize)]
enum ResponseKind {
    #[serde(rename = "response")]
    Response,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum BrowserFamilyWire {
    #[serde(rename = "chrome")]
    Chrome,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum DocumentLifecycleWire {
    #[serde(rename = "active")]
    Active,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RequestWire {
    #[serde(rename = "namespace")]
    _namespace: Namespace,
    version: u8,
    #[serde(rename = "role")]
    _role: ExtensionRole,
    #[serde(rename = "kind")]
    _kind: RequestKind,
    session_id: FixedHex<32>,
    sequence: u64,
    deadline_unix_ms: u64,
    profile_install_id: FixedHex<32>,
    activation_nonce: FixedHex<32>,
    request_id: FixedHex<16>,
    method: String,
    params: Value,
    route: String,
    context: ContextWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ContextWire {
    #[serde(rename = "browserFamily")]
    _browser_family: BrowserFamilyWire,
    extension_id: String,
    tab_id: u64,
    frame_id: u64,
    document_id: String,
    top_origin: String,
    frame_origin: String,
    #[serde(rename = "documentLifecycle")]
    _document_lifecycle: DocumentLifecycleWire,
    channel_nonce: FixedHex<32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CancelWire {
    #[serde(rename = "namespace")]
    _namespace: Namespace,
    version: u8,
    #[serde(rename = "role")]
    _role: ExtensionRole,
    #[serde(rename = "kind")]
    _kind: CancelKind,
    session_id: FixedHex<32>,
    sequence: u64,
    activation_nonce: FixedHex<32>,
    request_id: FixedHex<16>,
    request_sequence: u64,
    reason: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FixedHex<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> FixedHex<LENGTH> {
    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

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

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;
    use std::rc::Rc;

    use broker::{
        AuthorizedDispatch, PermissionStore, TransportBroker, TransportCancellation,
        TransportRequest,
    };
    use platform_windows::attestation::ReleaseAttestation;
    use serde_json::{Value, json};
    use wallet_model::{Address20, U256};

    use super::{
        BrokerEndpoint, BrokerEndpointError, DispatchOutcome, DownstreamExecutor, ExecutionOutcome,
        ExtensionEnvelope, NativeHostDispatcher, NativeRpcError, ProtocolError, UnattestedOutcome,
        parse_extension_envelope, run_persistent_stream, run_persistent_stream_with_limit,
        run_unattested_once,
    };
    use crate::{read_frame, write_frame};

    const REQUEST_GOLDEN: &str =
        include_str!("../../../extension/native-host/v1-request.golden.json");
    const RESPONSE_GOLDEN: &str =
        include_str!("../../../extension/native-host/v1-unavailable-response.golden.json");

    fn golden_request() -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_str(REQUEST_GOLDEN)?)
    }

    fn sequenced_request(
        sequence: u64,
        request_byte: u8,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut request = golden_request()?;
        let object = request
            .as_object_mut()
            .ok_or("golden request is not an object")?;
        object.insert("sequence".to_owned(), json!(sequence));
        object.insert(
            "requestId".to_owned(),
            Value::String(format!("{request_byte:02x}").repeat(16)),
        );
        Ok(request)
    }

    fn cancellation(sequence: u64, request_sequence: u64, request_byte: u8) -> Value {
        json!({
            "namespace": "your-wallet",
            "version": 1,
            "role": "extension",
            "kind": "cancel",
            "sessionId": "bb".repeat(32),
            "sequence": sequence,
            "activationNonce": format!("{}0c", "00".repeat(31)),
            "requestId": format!("{request_byte:02x}").repeat(16),
            "requestSequence": request_sequence,
            "reason": "navigation"
        })
    }

    #[test]
    fn cross_layer_golden_request_maps_to_exact_model() -> Result<(), Box<dyn std::error::Error>> {
        let ExtensionEnvelope::Request(request) = parse_extension_envelope(golden_request()?)?
        else {
            return Err("golden request parsed as cancellation".into());
        };
        assert_eq!(request.method_name(), "eth_chainId");
        assert_eq!(
            request.context().top_origin.as_str(),
            "https://dapp.example"
        );
        assert_eq!(request.context().sequence, 1);
        assert_eq!(request.context().tab_id, 17);
        Ok(())
    }

    #[test]
    fn unknown_keys_widths_literals_and_routes_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = golden_request()?;
        for mutation in [
            json!({"extra": true}),
            json!({"sessionId": "aa"}),
            json!({"role": "broker"}),
            json!({"route": "read"}),
        ] {
            let mut candidate = base.clone();
            let object = candidate
                .as_object_mut()
                .ok_or("golden request is not an object")?;
            let fields = mutation.as_object().ok_or("mutation is not an object")?;
            for (key, value) in fields {
                object.insert(key.clone(), value.clone());
            }
            assert!(matches!(
                parse_extension_envelope(candidate),
                Err(ProtocolError::InvalidEnvelope)
            ));
        }
        Ok(())
    }

    #[test]
    fn unattested_executable_path_returns_stable_golden_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = Vec::new();
        write_frame(&mut input, &golden_request()?)?;
        let mut output = Vec::new();
        assert_eq!(
            run_unattested_once(&mut Cursor::new(input), &mut output)?,
            UnattestedOutcome::RespondedUnavailable
        );
        let actual = read_frame(&mut Cursor::new(output))?.ok_or("missing response")?;
        let expected: Value = serde_json::from_str(RESPONSE_GOLDEN)?;
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn cancellation_requires_request_sequence_before_cancel_sequence() {
        let invalid = json!({
            "namespace": "your-wallet",
            "version": 1,
            "role": "extension",
            "kind": "cancel",
            "sessionId": "bb".repeat(32),
            "sequence": 1,
            "activationNonce": "cc".repeat(32),
            "requestId": "01".repeat(16),
            "requestSequence": 1,
            "reason": "navigation"
        });
        assert!(matches!(
            parse_extension_envelope(invalid),
            Err(ProtocolError::InvalidEnvelope)
        ));
    }

    #[derive(Debug)]
    struct CountingEndpoint {
        calls: Rc<Cell<usize>>,
    }

    impl BrokerEndpoint for CountingEndpoint {
        fn begin_session(&mut self, _session_id: [u8; 32]) -> Result<(), BrokerEndpointError> {
            self.calls.set(self.calls.get().saturating_add(1));
            Err(BrokerEndpointError::Unavailable)
        }

        fn admit(
            &mut self,
            _request: &TransportRequest,
            _now_unix_ms: u64,
        ) -> Result<AuthorizedDispatch, BrokerEndpointError> {
            self.calls.set(self.calls.get().saturating_add(1));
            Err(BrokerEndpointError::Unavailable)
        }

        fn cancel(
            &mut self,
            _cancellation: TransportCancellation,
        ) -> Result<(), BrokerEndpointError> {
            self.calls.set(self.calls.get().saturating_add(1));
            Err(BrokerEndpointError::Unavailable)
        }
    }

    #[derive(Debug)]
    struct CountingExecutor {
        calls: Rc<Cell<usize>>,
    }

    impl DownstreamExecutor for CountingExecutor {
        fn execute_to_completion(&mut self, _admission: AuthorizedDispatch) -> ExecutionOutcome {
            self.calls.set(self.calls.get().saturating_add(1));
            ExecutionOutcome::success(json!("unexpected"))
        }
    }

    #[test]
    fn public_wire_debug_redacts_payloads_and_session_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let envelope = parse_extension_envelope(golden_request()?)?;
        let envelope_debug = format!("{envelope:?}");
        assert!(envelope_debug.contains("ExtensionEnvelope::Request"));
        assert!(envelope_debug.contains("[REDACTED]"));
        assert!(!envelope_debug.contains("dapp.example"));
        assert!(!envelope_debug.contains("eth_chainId"));

        let response = DispatchOutcome::Response(json!({
            "result": "private-response-marker"
        }));
        let response_debug = format!("{response:?}");
        assert!(response_debug.contains("DispatchOutcome::Response"));
        assert!(!response_debug.contains("private-response-marker"));

        let dispatcher = NativeHostDispatcher::new(
            CountingEndpoint {
                calls: Rc::new(Cell::new(0)),
            },
            ReleaseAttestation::default(),
        );
        let dispatcher_debug = format!("{dispatcher:?}");
        assert!(dispatcher_debug.contains("[REDACTED]"));
        assert!(!dispatcher_debug.contains("CountingEndpoint"));

        let framing_error = ProtocolError::Framing(crate::FrameError::Io(std::io::Error::other(
            "private-local-path-marker",
        )));
        let error_debug = format!("{framing_error:?}");
        assert!(error_debug.contains("ProtocolError::Framing"));
        assert!(!error_debug.contains("private-local-path-marker"));
        Ok(())
    }

    #[test]
    fn disabled_release_attestation_never_calls_injected_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let calls = Rc::new(Cell::new(0));
        let endpoint = CountingEndpoint {
            calls: Rc::clone(&calls),
        };
        let mut dispatcher = NativeHostDispatcher::new(endpoint, ReleaseAttestation::default());
        let request = parse_extension_envelope(golden_request()?)?;
        assert!(matches!(
            dispatcher.dispatch(request, 1_700_000_000_000)?,
            DispatchOutcome::Response(_)
        ));
        let cancellation = parse_extension_envelope(json!({
            "namespace": "your-wallet",
            "version": 1,
            "role": "extension",
            "kind": "cancel",
            "sessionId": "bb".repeat(32),
            "sequence": 2,
            "activationNonce": format!("{}0c", "00".repeat(31)),
            "requestId": "01".repeat(16),
            "requestSequence": 1,
            "reason": "navigation"
        }))?;
        assert!(matches!(
            dispatcher.dispatch(cancellation, 1_700_000_000_001)?,
            DispatchOutcome::Cancelled
        ));
        assert_eq!(calls.get(), 0);
        Ok(())
    }

    #[test]
    fn persistent_stream_preserves_sequences_and_cancellation_has_no_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = Vec::new();
        write_frame(&mut input, &sequenced_request(1, 1)?)?;
        write_frame(&mut input, &cancellation(2, 1, 1))?;
        write_frame(&mut input, &sequenced_request(3, 2)?)?;

        let endpoint_calls = Rc::new(Cell::new(0));
        let executor_calls = Rc::new(Cell::new(0));
        let mut dispatcher = NativeHostDispatcher::new(
            CountingEndpoint {
                calls: Rc::clone(&endpoint_calls),
            },
            ReleaseAttestation::default(),
        );
        let mut executor = CountingExecutor {
            calls: Rc::clone(&executor_calls),
        };
        let clock_calls = Rc::new(Cell::new(0_usize));
        let observed_clock_calls = Rc::clone(&clock_calls);
        let mut clock = move || {
            observed_clock_calls.set(observed_clock_calls.get().saturating_add(1));
            Ok(1_700_000_000_000)
        };
        let mut output = Vec::new();
        let summary = run_persistent_stream(
            &mut Cursor::new(input),
            &mut output,
            &mut dispatcher,
            &mut executor,
            &mut clock,
        )?;

        assert_eq!(summary.frames_read(), 3);
        assert_eq!(summary.responses_written(), 2);
        assert_eq!(summary.cancellations(), 1);
        assert_eq!(endpoint_calls.get(), 0);
        assert_eq!(executor_calls.get(), 0);
        assert_eq!(clock_calls.get(), 2);

        let mut responses = Cursor::new(output);
        let first = read_frame(&mut responses)?.ok_or("missing first response")?;
        let second = read_frame(&mut responses)?.ok_or("missing second response")?;
        assert!(read_frame(&mut responses)?.is_none());
        assert_eq!(first.get("sequence"), Some(&json!(1)));
        assert_eq!(first.get("requestSequence"), Some(&json!(1)));
        assert_eq!(second.get("sequence"), Some(&json!(2)));
        assert_eq!(second.get("requestSequence"), Some(&json!(3)));
        Ok(())
    }

    #[test]
    fn malformed_frame_is_terminal_and_later_frames_are_not_processed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut invalid = sequenced_request(2, 2)?;
        invalid
            .as_object_mut()
            .ok_or("request is not an object")?
            .insert("unexpected".to_owned(), Value::Bool(true));
        let mut input = Vec::new();
        write_frame(&mut input, &sequenced_request(1, 1)?)?;
        write_frame(&mut input, &invalid)?;
        write_frame(&mut input, &sequenced_request(3, 3)?)?;

        let endpoint_calls = Rc::new(Cell::new(0));
        let executor_calls = Rc::new(Cell::new(0));
        let mut dispatcher = NativeHostDispatcher::new(
            CountingEndpoint {
                calls: Rc::clone(&endpoint_calls),
            },
            ReleaseAttestation::default(),
        );
        let mut executor = CountingExecutor {
            calls: Rc::clone(&executor_calls),
        };
        let mut clock = || Ok(1_700_000_000_000);
        let mut output = Vec::new();
        assert!(matches!(
            run_persistent_stream(
                &mut Cursor::new(input),
                &mut output,
                &mut dispatcher,
                &mut executor,
                &mut clock,
            ),
            Err(ProtocolError::InvalidEnvelope)
        ));
        assert_eq!(endpoint_calls.get(), 0);
        assert_eq!(executor_calls.get(), 0);

        let mut responses = Cursor::new(output);
        assert!(read_frame(&mut responses)?.is_some());
        assert!(read_frame(&mut responses)?.is_none());
        Ok(())
    }

    #[test]
    fn persistent_stream_rejects_a_frame_past_its_fixed_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = Vec::new();
        write_frame(&mut input, &sequenced_request(1, 1)?)?;
        write_frame(&mut input, &sequenced_request(2, 2)?)?;
        let calls = Rc::new(Cell::new(0));
        let mut dispatcher = NativeHostDispatcher::new(
            CountingEndpoint {
                calls: Rc::clone(&calls),
            },
            ReleaseAttestation::default(),
        );
        let mut executor = CountingExecutor {
            calls: Rc::clone(&calls),
        };
        let mut clock = || Ok(1_700_000_000_000);
        let mut output = Vec::new();
        assert!(matches!(
            run_persistent_stream_with_limit(
                &mut Cursor::new(input),
                &mut output,
                &mut dispatcher,
                &mut executor,
                &mut clock,
                1,
            ),
            Err(ProtocolError::StreamLimit)
        ));
        let mut responses = Cursor::new(output);
        assert!(read_frame(&mut responses)?.is_some());
        assert!(read_frame(&mut responses)?.is_none());
        assert_eq!(calls.get(), 0);
        Ok(())
    }

    fn admitted_golden_request() -> Result<AuthorizedDispatch, Box<dyn std::error::Error>> {
        let ExtensionEnvelope::Request(request) = parse_extension_envelope(golden_request()?)?
        else {
            return Err("golden request parsed as cancellation".into());
        };
        let session_id = *request.context().session_id.as_bytes();
        let mut broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([1; 20]),
            U256::from_u64(11_155_111),
        );
        broker.begin_session(session_id)?;
        Ok(broker.admit(&request, std::time::Instant::now(), 1_700_000_000_000)?)
    }

    #[derive(Clone, Copy, Debug)]
    enum CompletionBody {
        Success,
        Error,
    }

    #[derive(Debug)]
    struct CompletingExecutor {
        completed: Rc<Cell<bool>>,
        body: CompletionBody,
    }

    impl DownstreamExecutor for CompletingExecutor {
        fn execute_to_completion(&mut self, _admission: AuthorizedDispatch) -> ExecutionOutcome {
            self.completed.set(true);
            match self.body {
                CompletionBody::Success => {
                    ExecutionOutcome::success(json!({"chainId": "0xaa36a7"}))
                }
                CompletionBody::Error => ExecutionOutcome::error(NativeRpcError {
                    code: 4_001,
                    message: "User rejected the request.".to_owned(),
                    data: Some(json!({"reason": "user"})),
                }),
            }
        }
    }

    fn dispatcher_for_encoder() -> NativeHostDispatcher<CountingEndpoint> {
        NativeHostDispatcher::new(
            CountingEndpoint {
                calls: Rc::new(Cell::new(0)),
            },
            ReleaseAttestation::default(),
        )
    }

    #[test]
    fn admitted_success_is_encoded_only_after_executor_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let completed = Rc::new(Cell::new(false));
        let mut executor = CompletingExecutor {
            completed: Rc::clone(&completed),
            body: CompletionBody::Success,
        };
        let mut dispatcher = dispatcher_for_encoder();
        let response = dispatcher.execute_admitted(admitted_golden_request()?, &mut executor)?;

        assert!(completed.get());
        assert_eq!(response.as_object().map_or(0, serde_json::Map::len), 10);
        assert_eq!(response.get("sequence"), Some(&json!(1)));
        assert_eq!(response.get("requestSequence"), Some(&json!(1)));
        assert_eq!(
            response.get("result"),
            Some(&json!({"chainId": "0xaa36a7"}))
        );
        assert!(response.get("error").is_none());
        Ok(())
    }

    #[test]
    fn admitted_error_has_exact_correlation_and_bounded_error_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let completed = Rc::new(Cell::new(false));
        let mut executor = CompletingExecutor {
            completed: Rc::clone(&completed),
            body: CompletionBody::Error,
        };
        let mut dispatcher = dispatcher_for_encoder();
        let response = dispatcher.execute_admitted(admitted_golden_request()?, &mut executor)?;

        assert!(completed.get());
        assert_eq!(response.as_object().map_or(0, serde_json::Map::len), 10);
        assert_eq!(response.get("sequence"), Some(&json!(1)));
        assert_eq!(response.get("requestSequence"), Some(&json!(1)));
        assert_eq!(
            response.get("error"),
            Some(&json!({
                "code": 4001,
                "message": "User rejected the request.",
                "data": {"reason": "user"}
            }))
        );
        assert!(response.get("result").is_none());
        Ok(())
    }

    #[test]
    fn native_rpc_error_rejects_unsafe_codes_and_utf16_oversize_messages() {
        let unsafe_code = i64::try_from(super::JAVASCRIPT_MAX_SAFE_INTEGER)
            .map_or(i64::MAX, |maximum| maximum.saturating_add(1));
        assert!(matches!(
            NativeRpcError::new(unsafe_code, "error", None),
            Err(ProtocolError::ResponseEncoding)
        ));
        assert!(matches!(
            NativeRpcError::new(4_001, "", None),
            Err(ProtocolError::ResponseEncoding)
        ));
        assert!(matches!(
            NativeRpcError::new(4_001, "😀".repeat(257), None),
            Err(ProtocolError::ResponseEncoding)
        ));
    }
}
