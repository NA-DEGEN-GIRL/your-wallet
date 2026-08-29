//! Debug-only version-2 feasibility wire contract.
//!
//! Version 2 adds only bounded desktop probe commands and a helper-ready
//! correlation exchange. It deliberately carries no caller role, process
//! identifier, image identity, or other peer authority. The authenticated
//! transport derives that authority independently.

use super::{EpochNonce, ServiceRequestId, WireError};

/// Fixed protocol magic for every version-2 frame.
pub const PROTOCOL_MAGIC: [u8; 8] = *b"YWKASV02";
/// Exact byte length of an open-epoch request.
pub const OPEN_EPOCH_REQUEST_BYTES: usize = 20;
/// Exact byte length of an open-epoch acknowledgement.
pub const OPEN_EPOCH_ACK_BYTES: usize = 52;
/// Exact byte length of a desktop-command request.
pub const DESKTOP_COMMAND_REQUEST_BYTES: usize = 72;
/// Exact byte length of a desktop-command response.
pub const DESKTOP_COMMAND_RESPONSE_BYTES: usize = 72;
/// Exact byte length of a helper-ready request.
pub const HELPER_READY_REQUEST_BYTES: usize = 68;
/// Exact byte length of a helper-ready acknowledgement.
pub const HELPER_READY_ACK_BYTES: usize = 68;
/// Maximum accepted version-2 request frame length.
pub const MAX_SERVICE_REQUEST_BYTES: usize = DESKTOP_COMMAND_REQUEST_BYTES;
/// Maximum accepted version-2 response frame length.
pub const MAX_SERVICE_RESPONSE_BYTES: usize = DESKTOP_COMMAND_RESPONSE_BYTES;

const HEADER_BYTES: usize = 16;
const CHECKSUM_BYTES: usize = 4;
const VERSION_V2: u16 = 2;
const FRAME_OPEN_EPOCH_REQUEST: u16 = 1;
const FRAME_OPEN_EPOCH_ACK: u16 = 2;
const FRAME_DESKTOP_COMMAND_REQUEST: u16 = 3;
const FRAME_DESKTOP_COMMAND_RESPONSE: u16 = 4;
const FRAME_HELPER_READY_REQUEST: u16 = 5;
const FRAME_HELPER_READY_ACK: u16 = 6;
const COMMAND_STATUS: u16 = 1;
const COMMAND_LAUNCH_APPROVAL_RPC_PROBE: u16 = 2;
const COMMAND_LAUNCH_SECRET_INPUT_RPC_PROBE: u16 = 3;
const RESULT_UNAVAILABLE: u16 = 1;
const RESULT_APPROVAL_RPC_PROBE_COMPLETED: u16 = 2;
const RESULT_SECRET_INPUT_RPC_PROBE_COMPLETED: u16 = 3;
const EPOCH_NONCE_BYTES: usize = 32;
const REQUEST_ID_BYTES: usize = 16;

const EPOCH_OFFSET: usize = HEADER_BYTES;
const REQUEST_ID_OFFSET: usize = EPOCH_OFFSET + EPOCH_NONCE_BYTES;
const BODY_KIND_OFFSET: usize = REQUEST_ID_OFFSET + REQUEST_ID_BYTES;
const BODY_RESERVED_OFFSET: usize = BODY_KIND_OFFSET + 2;

/// The only protocol version accepted by this debug-only module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolVersion {
    /// Debug feasibility protocol version 2.
    V2,
}

impl ProtocolVersion {
    /// Returns the canonical unsigned wire code.
    #[must_use]
    pub const fn wire_code(self) -> u16 {
        match self {
            Self::V2 => VERSION_V2,
        }
    }
}

impl TryFrom<u16> for ProtocolVersion {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            VERSION_V2 => Ok(Self::V2),
            _ => Err(WireError::UnsupportedVersion),
        }
    }
}

/// Empty request asking the service to establish a fresh version-2 epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OpenEpochRequest;

impl OpenEpochRequest {
    /// Constructs the only canonical open-epoch request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Version-2 acknowledgement carrying a fresh service-issued epoch nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenEpochAck {
    epoch_nonce: EpochNonce,
}

impl OpenEpochAck {
    /// Binds an acknowledgement to a validated service-issued nonce.
    #[must_use]
    pub const fn new(epoch_nonce: EpochNonce) -> Self {
        Self { epoch_nonce }
    }

    /// Returns the fresh epoch nonce.
    #[must_use]
    pub const fn epoch_nonce(&self) -> EpochNonce {
        self.epoch_nonce
    }
}

/// Closed desktop command set supported by version 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopCommand {
    /// Request only a coarse non-secret service status.
    Status,
    /// Launch the bounded Approval RPC feasibility probe.
    LaunchApprovalRpcProbe,
    /// Launch the bounded Secret Input RPC feasibility probe.
    LaunchSecretInputRpcProbe,
}

/// Closed desktop result set supported by version 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopResult {
    /// The requested operation is unavailable.
    Unavailable,
    /// The Approval RPC feasibility probe completed.
    ApprovalRpcProbeCompleted,
    /// The Secret Input RPC feasibility probe completed.
    SecretInputRpcProbeCompleted,
}

/// One desktop command bound to an authenticated epoch and request identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesktopCommandRequest {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
    command: DesktopCommand,
}

impl DesktopCommandRequest {
    /// Constructs a request from validated binding values.
    #[must_use]
    pub const fn new(
        epoch_nonce: EpochNonce,
        request_id: ServiceRequestId,
        command: DesktopCommand,
    ) -> Self {
        Self {
            epoch_nonce,
            request_id,
            command,
        }
    }

    /// Returns the bound epoch nonce.
    #[must_use]
    pub const fn epoch_nonce(&self) -> EpochNonce {
        self.epoch_nonce
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> ServiceRequestId {
        self.request_id
    }

    /// Returns the closed desktop command.
    #[must_use]
    pub const fn command(&self) -> DesktopCommand {
        self.command
    }
}

/// One desktop result bound to the exact epoch and request identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesktopCommandResponse {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
    result: DesktopResult,
}

impl DesktopCommandResponse {
    /// Constructs a response from validated binding values.
    #[must_use]
    pub const fn new(
        epoch_nonce: EpochNonce,
        request_id: ServiceRequestId,
        result: DesktopResult,
    ) -> Self {
        Self {
            epoch_nonce,
            request_id,
            result,
        }
    }

    /// Returns the bound epoch nonce.
    #[must_use]
    pub const fn epoch_nonce(&self) -> EpochNonce {
        self.epoch_nonce
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> ServiceRequestId {
        self.request_id
    }

    /// Returns the closed desktop result.
    #[must_use]
    pub const fn result(&self) -> DesktopResult {
        self.result
    }

    /// Verifies exact command binding and a result valid for that command.
    ///
    /// [`DesktopResult::Unavailable`] is the fail-closed coarse result for
    /// every command. Each completed-probe result correlates only with its
    /// matching launch command.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BindingMismatch`] for a different epoch, request
    /// identifier, or command/result pairing.
    pub fn ensure_correlates_with(&self, request: &DesktopCommandRequest) -> Result<(), WireError> {
        if self.epoch_nonce == request.epoch_nonce
            && self.request_id == request.request_id
            && result_matches_command(request.command, self.result)
        {
            Ok(())
        } else {
            Err(WireError::BindingMismatch)
        }
    }
}

/// One helper-ready request bound to an authenticated epoch and request ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperReadyRequest {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
}

impl HelperReadyRequest {
    /// Constructs a request from validated binding values.
    #[must_use]
    pub const fn new(epoch_nonce: EpochNonce, request_id: ServiceRequestId) -> Self {
        Self {
            epoch_nonce,
            request_id,
        }
    }

    /// Returns the bound epoch nonce.
    #[must_use]
    pub const fn epoch_nonce(&self) -> EpochNonce {
        self.epoch_nonce
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> ServiceRequestId {
        self.request_id
    }
}

/// One helper-ready acknowledgement bound to the exact request values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperReadyAck {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
}

impl HelperReadyAck {
    /// Constructs an acknowledgement from validated binding values.
    #[must_use]
    pub const fn new(epoch_nonce: EpochNonce, request_id: ServiceRequestId) -> Self {
        Self {
            epoch_nonce,
            request_id,
        }
    }

    /// Returns the bound epoch nonce.
    #[must_use]
    pub const fn epoch_nonce(&self) -> EpochNonce {
        self.epoch_nonce
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> ServiceRequestId {
        self.request_id
    }

    /// Verifies exact helper-ready request binding.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BindingMismatch`] when either binding differs.
    pub fn ensure_correlates_with(&self, request: &HelperReadyRequest) -> Result<(), WireError> {
        if self.epoch_nonce == request.epoch_nonce && self.request_id == request.request_id {
            Ok(())
        } else {
            Err(WireError::BindingMismatch)
        }
    }
}

/// Canonical request frame variants accepted by version 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRequest {
    /// Establish a fresh authenticated epoch.
    OpenEpoch(OpenEpochRequest),
    /// Execute one desktop command within an established epoch.
    DesktopCommand(DesktopCommandRequest),
    /// Confirm that one expected helper reached the authenticated endpoint.
    HelperReady(HelperReadyRequest),
}

/// Canonical response frame variants emitted by version 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceResponse {
    /// Fresh epoch establishment acknowledgement.
    OpenEpoch(OpenEpochAck),
    /// Result of one bound desktop command.
    DesktopCommand(DesktopCommandResponse),
    /// Acknowledgement of one bound helper-ready request.
    HelperReady(HelperReadyAck),
}

impl ServiceResponse {
    /// Verifies canonical pairing and exact correlation values.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BindingMismatch`] for different variants,
    /// different binding values, or an invalid command/result pairing.
    pub fn ensure_correlates_with(&self, request: &ServiceRequest) -> Result<(), WireError> {
        match (self, request) {
            (Self::OpenEpoch(_), ServiceRequest::OpenEpoch(_)) => Ok(()),
            (Self::DesktopCommand(response), ServiceRequest::DesktopCommand(request)) => {
                response.ensure_correlates_with(request)
            }
            (Self::HelperReady(response), ServiceRequest::HelperReady(request)) => {
                response.ensure_correlates_with(request)
            }
            _ => Err(WireError::BindingMismatch),
        }
    }
}

/// Encodes one canonical version-2 request frame.
#[must_use]
pub fn encode_request(request: &ServiceRequest) -> Vec<u8> {
    match request {
        ServiceRequest::OpenEpoch(_) => {
            let mut frame = Vec::with_capacity(OPEN_EPOCH_REQUEST_BYTES);
            encode_header(&mut frame, FRAME_OPEN_EPOCH_REQUEST);
            finish_frame(frame)
        }
        ServiceRequest::DesktopCommand(request) => {
            let mut frame = Vec::with_capacity(DESKTOP_COMMAND_REQUEST_BYTES);
            encode_header(&mut frame, FRAME_DESKTOP_COMMAND_REQUEST);
            encode_bindings(&mut frame, request.epoch_nonce, request.request_id);
            frame.extend_from_slice(&command_code(request.command).to_be_bytes());
            frame.extend_from_slice(&0_u16.to_be_bytes());
            finish_frame(frame)
        }
        ServiceRequest::HelperReady(request) => {
            let mut frame = Vec::with_capacity(HELPER_READY_REQUEST_BYTES);
            encode_header(&mut frame, FRAME_HELPER_READY_REQUEST);
            encode_bindings(&mut frame, request.epoch_nonce, request.request_id);
            finish_frame(frame)
        }
    }
}

/// Decodes one complete version-2 request and rejects every noncanonical byte.
///
/// # Errors
///
/// Returns a stable [`WireError`] category for malformed input.
pub fn decode_request(bytes: &[u8]) -> Result<ServiceRequest, WireError> {
    match decode_header(bytes)? {
        FRAME_OPEN_EPOCH_REQUEST => {
            require_exact_length(bytes, OPEN_EPOCH_REQUEST_BYTES)?;
            verify_checksum(bytes)?;
            Ok(ServiceRequest::OpenEpoch(OpenEpochRequest::new()))
        }
        FRAME_DESKTOP_COMMAND_REQUEST => {
            require_exact_length(bytes, DESKTOP_COMMAND_REQUEST_BYTES)?;
            verify_checksum(bytes)?;
            let (epoch_nonce, request_id) = decode_bindings(bytes)?;
            require_zero_u16(bytes, BODY_RESERVED_OFFSET)?;
            let command = match read_u16(bytes, BODY_KIND_OFFSET) {
                COMMAND_STATUS => DesktopCommand::Status,
                COMMAND_LAUNCH_APPROVAL_RPC_PROBE => DesktopCommand::LaunchApprovalRpcProbe,
                COMMAND_LAUNCH_SECRET_INPUT_RPC_PROBE => DesktopCommand::LaunchSecretInputRpcProbe,
                _ => return Err(WireError::UnknownKind),
            };
            Ok(ServiceRequest::DesktopCommand(DesktopCommandRequest::new(
                epoch_nonce,
                request_id,
                command,
            )))
        }
        FRAME_HELPER_READY_REQUEST => {
            require_exact_length(bytes, HELPER_READY_REQUEST_BYTES)?;
            verify_checksum(bytes)?;
            let (epoch_nonce, request_id) = decode_bindings(bytes)?;
            Ok(ServiceRequest::HelperReady(HelperReadyRequest::new(
                epoch_nonce,
                request_id,
            )))
        }
        _ => Err(WireError::UnknownKind),
    }
}

/// Encodes one canonical version-2 response frame.
#[must_use]
pub fn encode_response(response: &ServiceResponse) -> Vec<u8> {
    match response {
        ServiceResponse::OpenEpoch(ack) => {
            let mut frame = Vec::with_capacity(OPEN_EPOCH_ACK_BYTES);
            encode_header(&mut frame, FRAME_OPEN_EPOCH_ACK);
            frame.extend_from_slice(ack.epoch_nonce.as_bytes());
            finish_frame(frame)
        }
        ServiceResponse::DesktopCommand(response) => {
            let mut frame = Vec::with_capacity(DESKTOP_COMMAND_RESPONSE_BYTES);
            encode_header(&mut frame, FRAME_DESKTOP_COMMAND_RESPONSE);
            encode_bindings(&mut frame, response.epoch_nonce, response.request_id);
            frame.extend_from_slice(&result_code(response.result).to_be_bytes());
            frame.extend_from_slice(&0_u16.to_be_bytes());
            finish_frame(frame)
        }
        ServiceResponse::HelperReady(ack) => {
            let mut frame = Vec::with_capacity(HELPER_READY_ACK_BYTES);
            encode_header(&mut frame, FRAME_HELPER_READY_ACK);
            encode_bindings(&mut frame, ack.epoch_nonce, ack.request_id);
            finish_frame(frame)
        }
    }
}

/// Decodes one complete version-2 response and rejects every noncanonical byte.
///
/// # Errors
///
/// Returns a stable [`WireError`] category for malformed input.
pub fn decode_response(bytes: &[u8]) -> Result<ServiceResponse, WireError> {
    match decode_header(bytes)? {
        FRAME_OPEN_EPOCH_ACK => {
            require_exact_length(bytes, OPEN_EPOCH_ACK_BYTES)?;
            verify_checksum(bytes)?;
            let epoch_nonce = decode_epoch_nonce(bytes)?;
            Ok(ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce)))
        }
        FRAME_DESKTOP_COMMAND_RESPONSE => {
            require_exact_length(bytes, DESKTOP_COMMAND_RESPONSE_BYTES)?;
            verify_checksum(bytes)?;
            let (epoch_nonce, request_id) = decode_bindings(bytes)?;
            require_zero_u16(bytes, BODY_RESERVED_OFFSET)?;
            let result = match read_u16(bytes, BODY_KIND_OFFSET) {
                RESULT_UNAVAILABLE => DesktopResult::Unavailable,
                RESULT_APPROVAL_RPC_PROBE_COMPLETED => DesktopResult::ApprovalRpcProbeCompleted,
                RESULT_SECRET_INPUT_RPC_PROBE_COMPLETED => {
                    DesktopResult::SecretInputRpcProbeCompleted
                }
                _ => return Err(WireError::UnknownKind),
            };
            Ok(ServiceResponse::DesktopCommand(
                DesktopCommandResponse::new(epoch_nonce, request_id, result),
            ))
        }
        FRAME_HELPER_READY_ACK => {
            require_exact_length(bytes, HELPER_READY_ACK_BYTES)?;
            verify_checksum(bytes)?;
            let (epoch_nonce, request_id) = decode_bindings(bytes)?;
            Ok(ServiceResponse::HelperReady(HelperReadyAck::new(
                epoch_nonce,
                request_id,
            )))
        }
        _ => Err(WireError::UnknownKind),
    }
}

const fn result_matches_command(command: DesktopCommand, result: DesktopResult) -> bool {
    matches!(
        (command, result),
        (_, DesktopResult::Unavailable)
            | (
                DesktopCommand::LaunchApprovalRpcProbe,
                DesktopResult::ApprovalRpcProbeCompleted
            )
            | (
                DesktopCommand::LaunchSecretInputRpcProbe,
                DesktopResult::SecretInputRpcProbeCompleted
            )
    )
}

const fn command_code(command: DesktopCommand) -> u16 {
    match command {
        DesktopCommand::Status => COMMAND_STATUS,
        DesktopCommand::LaunchApprovalRpcProbe => COMMAND_LAUNCH_APPROVAL_RPC_PROBE,
        DesktopCommand::LaunchSecretInputRpcProbe => COMMAND_LAUNCH_SECRET_INPUT_RPC_PROBE,
    }
}

const fn result_code(result: DesktopResult) -> u16 {
    match result {
        DesktopResult::Unavailable => RESULT_UNAVAILABLE,
        DesktopResult::ApprovalRpcProbeCompleted => RESULT_APPROVAL_RPC_PROBE_COMPLETED,
        DesktopResult::SecretInputRpcProbeCompleted => RESULT_SECRET_INPUT_RPC_PROBE_COMPLETED,
    }
}

fn encode_header(output: &mut Vec<u8>, frame_kind: u16) {
    output.extend_from_slice(&PROTOCOL_MAGIC);
    output.extend_from_slice(&ProtocolVersion::V2.wire_code().to_be_bytes());
    output.extend_from_slice(&frame_kind.to_be_bytes());
    output.extend_from_slice(&0_u32.to_be_bytes());
}

fn encode_bindings(output: &mut Vec<u8>, epoch_nonce: EpochNonce, request_id: ServiceRequestId) {
    output.extend_from_slice(epoch_nonce.as_bytes());
    output.extend_from_slice(request_id.as_bytes());
}

fn finish_frame(mut frame: Vec<u8>) -> Vec<u8> {
    let checksum = super::crc32c(&frame);
    frame.extend_from_slice(&checksum.to_be_bytes());
    frame
}

fn decode_header(bytes: &[u8]) -> Result<u16, WireError> {
    if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES {
        return Err(WireError::Truncated);
    }
    if bytes.get(..PROTOCOL_MAGIC.len()) != Some(PROTOCOL_MAGIC.as_slice()) {
        return Err(WireError::InvalidMagic);
    }
    ProtocolVersion::try_from(read_u16(bytes, 8))?;
    require_zero_u32(bytes, 12)?;
    Ok(read_u16(bytes, 10))
}

fn require_exact_length(bytes: &[u8], expected: usize) -> Result<(), WireError> {
    match bytes.len().cmp(&expected) {
        core::cmp::Ordering::Less => Err(WireError::Truncated),
        core::cmp::Ordering::Equal => Ok(()),
        core::cmp::Ordering::Greater => Err(WireError::TrailingData),
    }
}

fn verify_checksum(bytes: &[u8]) -> Result<(), WireError> {
    let checksum_offset = bytes
        .len()
        .checked_sub(CHECKSUM_BYTES)
        .ok_or(WireError::Truncated)?;
    let actual = read_u32(bytes, checksum_offset);
    if super::crc32c(&bytes[..checksum_offset]) == actual {
        Ok(())
    } else {
        Err(WireError::Integrity)
    }
}

fn decode_bindings(bytes: &[u8]) -> Result<(EpochNonce, ServiceRequestId), WireError> {
    Ok((decode_epoch_nonce(bytes)?, decode_request_id(bytes)?))
}

fn decode_epoch_nonce(bytes: &[u8]) -> Result<EpochNonce, WireError> {
    let mut value = [0_u8; EPOCH_NONCE_BYTES];
    value.copy_from_slice(&bytes[EPOCH_OFFSET..EPOCH_OFFSET + EPOCH_NONCE_BYTES]);
    EpochNonce::new(value)
}

fn decode_request_id(bytes: &[u8]) -> Result<ServiceRequestId, WireError> {
    let mut value = [0_u8; REQUEST_ID_BYTES];
    value.copy_from_slice(&bytes[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + REQUEST_ID_BYTES]);
    ServiceRequestId::new(value)
}

fn require_zero_u16(bytes: &[u8], offset: usize) -> Result<(), WireError> {
    if read_u16(bytes, offset) == 0 {
        Ok(())
    } else {
        Err(WireError::NonZeroReserved)
    }
}

fn require_zero_u32(bytes: &[u8], offset: usize) -> Result<(), WireError> {
    if read_u32(bytes, offset) == 0 {
        Ok(())
    } else {
        Err(WireError::NonZeroReserved)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch_nonce() -> Result<EpochNonce, WireError> {
        EpochNonce::new([0xA5; EPOCH_NONCE_BYTES])
    }

    fn request_id() -> Result<ServiceRequestId, WireError> {
        ServiceRequestId::new([0x5A; REQUEST_ID_BYTES])
    }

    fn desktop_request(command: DesktopCommand) -> Result<ServiceRequest, WireError> {
        Ok(ServiceRequest::DesktopCommand(DesktopCommandRequest::new(
            epoch_nonce()?,
            request_id()?,
            command,
        )))
    }

    fn desktop_response(result: DesktopResult) -> Result<ServiceResponse, WireError> {
        Ok(ServiceResponse::DesktopCommand(
            DesktopCommandResponse::new(epoch_nonce()?, request_id()?, result),
        ))
    }

    fn canonical_requests() -> Result<Vec<ServiceRequest>, WireError> {
        Ok(vec![
            ServiceRequest::OpenEpoch(OpenEpochRequest::new()),
            desktop_request(DesktopCommand::Status)?,
            desktop_request(DesktopCommand::LaunchApprovalRpcProbe)?,
            desktop_request(DesktopCommand::LaunchSecretInputRpcProbe)?,
            ServiceRequest::HelperReady(HelperReadyRequest::new(epoch_nonce()?, request_id()?)),
        ])
    }

    fn canonical_responses() -> Result<Vec<ServiceResponse>, WireError> {
        Ok(vec![
            ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce()?)),
            desktop_response(DesktopResult::Unavailable)?,
            desktop_response(DesktopResult::ApprovalRpcProbeCompleted)?,
            desktop_response(DesktopResult::SecretInputRpcProbeCompleted)?,
            ServiceResponse::HelperReady(HelperReadyAck::new(epoch_nonce()?, request_id()?)),
        ])
    }

    fn rewrite_checksum(frame: &mut [u8]) {
        let checksum_offset = frame.len() - CHECKSUM_BYTES;
        let checksum = super::super::crc32c(&frame[..checksum_offset]).to_be_bytes();
        frame[checksum_offset..].copy_from_slice(&checksum);
    }

    fn assert_every_single_byte_request_corruption_is_rejected(frame: &[u8]) {
        for index in 0..frame.len() {
            for replacement in u8::MIN..=u8::MAX {
                if replacement == frame[index] {
                    continue;
                }
                let mut corrupted = frame.to_vec();
                corrupted[index] = replacement;
                assert!(decode_request(&corrupted).is_err());
            }
        }
    }

    fn assert_every_single_byte_response_corruption_is_rejected(frame: &[u8]) {
        for index in 0..frame.len() {
            for replacement in u8::MIN..=u8::MAX {
                if replacement == frame[index] {
                    continue;
                }
                let mut corrupted = frame.to_vec();
                corrupted[index] = replacement;
                assert!(decode_response(&corrupted).is_err());
            }
        }
    }

    #[test]
    fn version_is_exactly_two_and_v1_remains_outside_this_module() {
        assert_eq!(ProtocolVersion::V2.wire_code(), 2);
        assert_eq!(ProtocolVersion::try_from(2), Ok(ProtocolVersion::V2));
        for version in [u16::MIN, 1, 3, u16::MAX] {
            assert_eq!(
                ProtocolVersion::try_from(version),
                Err(WireError::UnsupportedVersion)
            );
        }
    }

    #[test]
    fn all_canonical_values_round_trip_at_exact_lengths() -> Result<(), WireError> {
        for request in canonical_requests()? {
            let encoded = encode_request(&request);
            let expected_length = match request {
                ServiceRequest::OpenEpoch(_) => OPEN_EPOCH_REQUEST_BYTES,
                ServiceRequest::DesktopCommand(_) => DESKTOP_COMMAND_REQUEST_BYTES,
                ServiceRequest::HelperReady(_) => HELPER_READY_REQUEST_BYTES,
            };
            assert_eq!(encoded.len(), expected_length);
            assert_eq!(decode_request(&encoded)?, request);
        }

        for response in canonical_responses()? {
            let encoded = encode_response(&response);
            let expected_length = match response {
                ServiceResponse::OpenEpoch(_) => OPEN_EPOCH_ACK_BYTES,
                ServiceResponse::DesktopCommand(_) => DESKTOP_COMMAND_RESPONSE_BYTES,
                ServiceResponse::HelperReady(_) => HELPER_READY_ACK_BYTES,
            };
            assert_eq!(encoded.len(), expected_length);
            assert_eq!(decode_response(&encoded)?, response);
        }
        assert_eq!(MAX_SERVICE_REQUEST_BYTES, 72);
        assert_eq!(MAX_SERVICE_RESPONSE_BYTES, 72);
        Ok(())
    }

    #[test]
    fn every_prefix_and_trailing_suffix_is_rejected() -> Result<(), WireError> {
        for request in canonical_requests()? {
            let frame = encode_request(&request);
            for prefix_length in 0..frame.len() {
                assert_eq!(
                    decode_request(&frame[..prefix_length]),
                    Err(WireError::Truncated)
                );
            }
            for trailing_length in 1..=4 {
                let mut trailing = frame.clone();
                trailing.resize(frame.len() + trailing_length, 0);
                assert_eq!(decode_request(&trailing), Err(WireError::TrailingData));
            }
        }

        for response in canonical_responses()? {
            let frame = encode_response(&response);
            for prefix_length in 0..frame.len() {
                assert_eq!(
                    decode_response(&frame[..prefix_length]),
                    Err(WireError::Truncated)
                );
            }
            for trailing_length in 1..=4 {
                let mut trailing = frame.clone();
                trailing.resize(frame.len() + trailing_length, 0);
                assert_eq!(decode_response(&trailing), Err(WireError::TrailingData));
            }
        }
        Ok(())
    }

    #[test]
    fn every_magic_version_and_header_reserved_bit_is_rejected() -> Result<(), WireError> {
        let canonical = encode_request(&ServiceRequest::OpenEpoch(OpenEpochRequest::new()));
        let mut v1_magic = canonical.clone();
        v1_magic[..8].copy_from_slice(b"YWKASV01");
        rewrite_checksum(&mut v1_magic);
        assert_eq!(decode_request(&v1_magic), Err(WireError::InvalidMagic));

        let mut v1_version = canonical;
        v1_version[8..10].copy_from_slice(&1_u16.to_be_bytes());
        rewrite_checksum(&mut v1_version);
        assert_eq!(
            decode_request(&v1_version),
            Err(WireError::UnsupportedVersion)
        );

        for request in canonical_requests()? {
            let frame = encode_request(&request);
            for offset in 0..8 {
                for bit in 0..8 {
                    let mut mutated = frame.clone();
                    mutated[offset] ^= 1_u8 << bit;
                    rewrite_checksum(&mut mutated);
                    assert_eq!(decode_request(&mutated), Err(WireError::InvalidMagic));
                }
            }
            for offset in 8..10 {
                for bit in 0..8 {
                    let mut mutated = frame.clone();
                    mutated[offset] ^= 1_u8 << bit;
                    rewrite_checksum(&mut mutated);
                    assert_eq!(decode_request(&mutated), Err(WireError::UnsupportedVersion));
                }
            }
            for offset in 12..16 {
                for bit in 0..8 {
                    let mut mutated = frame.clone();
                    mutated[offset] = 1_u8 << bit;
                    rewrite_checksum(&mut mutated);
                    assert_eq!(decode_request(&mutated), Err(WireError::NonZeroReserved));
                }
            }
        }

        for response in canonical_responses()? {
            let frame = encode_response(&response);
            for offset in 0..8 {
                for bit in 0..8 {
                    let mut mutated = frame.clone();
                    mutated[offset] ^= 1_u8 << bit;
                    rewrite_checksum(&mut mutated);
                    assert_eq!(decode_response(&mutated), Err(WireError::InvalidMagic));
                }
            }
            for offset in 8..10 {
                for bit in 0..8 {
                    let mut mutated = frame.clone();
                    mutated[offset] ^= 1_u8 << bit;
                    rewrite_checksum(&mut mutated);
                    assert_eq!(
                        decode_response(&mutated),
                        Err(WireError::UnsupportedVersion)
                    );
                }
            }
            for offset in 12..16 {
                for bit in 0..8 {
                    let mut mutated = frame.clone();
                    mutated[offset] = 1_u8 << bit;
                    rewrite_checksum(&mut mutated);
                    assert_eq!(decode_response(&mutated), Err(WireError::NonZeroReserved));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn unknown_frame_command_and_result_codes_are_rejected() -> Result<(), WireError> {
        let open_request = encode_request(&ServiceRequest::OpenEpoch(OpenEpochRequest::new()));
        for frame_kind in [u16::MIN, 7, u16::MAX] {
            let mut mutated = open_request.clone();
            mutated[10..12].copy_from_slice(&frame_kind.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_request(&mutated), Err(WireError::UnknownKind));
        }

        let open_response = encode_response(&ServiceResponse::OpenEpoch(OpenEpochAck::new(
            epoch_nonce()?,
        )));
        for frame_kind in [u16::MIN, 7, u16::MAX] {
            let mut mutated = open_response.clone();
            mutated[10..12].copy_from_slice(&frame_kind.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_response(&mutated), Err(WireError::UnknownKind));
        }

        let command = encode_request(&desktop_request(DesktopCommand::Status)?);
        for command_kind in [u16::MIN, 4, u16::MAX] {
            let mut mutated = command.clone();
            mutated[BODY_KIND_OFFSET..BODY_KIND_OFFSET + 2]
                .copy_from_slice(&command_kind.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_request(&mutated), Err(WireError::UnknownKind));
        }

        let result = encode_response(&desktop_response(DesktopResult::Unavailable)?);
        for result_kind in [u16::MIN, 4, u16::MAX] {
            let mut mutated = result.clone();
            mutated[BODY_KIND_OFFSET..BODY_KIND_OFFSET + 2]
                .copy_from_slice(&result_kind.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_response(&mutated), Err(WireError::UnknownKind));
        }
        Ok(())
    }

    #[test]
    fn every_desktop_body_reserved_bit_is_rejected() -> Result<(), WireError> {
        let request = encode_request(&desktop_request(DesktopCommand::Status)?);
        for offset in BODY_RESERVED_OFFSET..BODY_RESERVED_OFFSET + 2 {
            for bit in 0..8 {
                let mut mutated = request.clone();
                mutated[offset] = 1_u8 << bit;
                rewrite_checksum(&mut mutated);
                assert_eq!(decode_request(&mutated), Err(WireError::NonZeroReserved));
            }
        }

        let response = encode_response(&desktop_response(DesktopResult::Unavailable)?);
        for offset in BODY_RESERVED_OFFSET..BODY_RESERVED_OFFSET + 2 {
            for bit in 0..8 {
                let mut mutated = response.clone();
                mutated[offset] = 1_u8 << bit;
                rewrite_checksum(&mut mutated);
                assert_eq!(decode_response(&mutated), Err(WireError::NonZeroReserved));
            }
        }
        Ok(())
    }

    #[test]
    fn every_required_binding_rejects_the_zero_sentinel() -> Result<(), WireError> {
        let request_frames = [
            encode_request(&desktop_request(DesktopCommand::Status)?),
            encode_request(&ServiceRequest::HelperReady(HelperReadyRequest::new(
                epoch_nonce()?,
                request_id()?,
            ))),
        ];
        for frame in request_frames {
            let mut zero_epoch = frame.clone();
            zero_epoch[EPOCH_OFFSET..EPOCH_OFFSET + EPOCH_NONCE_BYTES].fill(0);
            rewrite_checksum(&mut zero_epoch);
            assert_eq!(decode_request(&zero_epoch), Err(WireError::InvalidValue));

            let mut zero_request_id = frame;
            zero_request_id[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + REQUEST_ID_BYTES].fill(0);
            rewrite_checksum(&mut zero_request_id);
            assert_eq!(
                decode_request(&zero_request_id),
                Err(WireError::InvalidValue)
            );
        }

        let response_frames = [
            encode_response(&desktop_response(DesktopResult::Unavailable)?),
            encode_response(&ServiceResponse::HelperReady(HelperReadyAck::new(
                epoch_nonce()?,
                request_id()?,
            ))),
        ];
        for frame in response_frames {
            let mut zero_epoch = frame.clone();
            zero_epoch[EPOCH_OFFSET..EPOCH_OFFSET + EPOCH_NONCE_BYTES].fill(0);
            rewrite_checksum(&mut zero_epoch);
            assert_eq!(decode_response(&zero_epoch), Err(WireError::InvalidValue));

            let mut zero_request_id = frame;
            zero_request_id[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + REQUEST_ID_BYTES].fill(0);
            rewrite_checksum(&mut zero_request_id);
            assert_eq!(
                decode_response(&zero_request_id),
                Err(WireError::InvalidValue)
            );
        }

        let mut open_ack = encode_response(&ServiceResponse::OpenEpoch(OpenEpochAck::new(
            epoch_nonce()?,
        )));
        open_ack[EPOCH_OFFSET..EPOCH_OFFSET + EPOCH_NONCE_BYTES].fill(0);
        rewrite_checksum(&mut open_ack);
        assert_eq!(decode_response(&open_ack), Err(WireError::InvalidValue));
        Ok(())
    }

    #[test]
    fn request_and_response_directions_are_not_interchangeable() -> Result<(), WireError> {
        for request in canonical_requests()? {
            assert_eq!(
                decode_response(&encode_request(&request)),
                Err(WireError::UnknownKind)
            );
        }
        for response in canonical_responses()? {
            assert_eq!(
                decode_request(&encode_response(&response)),
                Err(WireError::UnknownKind)
            );
        }
        Ok(())
    }

    #[test]
    fn correlation_allows_fail_closed_unavailable_and_binds_completed_results()
    -> Result<(), WireError> {
        let status =
            DesktopCommandRequest::new(epoch_nonce()?, request_id()?, DesktopCommand::Status);
        let approval = DesktopCommandRequest::new(
            epoch_nonce()?,
            request_id()?,
            DesktopCommand::LaunchApprovalRpcProbe,
        );
        let secret = DesktopCommandRequest::new(
            epoch_nonce()?,
            request_id()?,
            DesktopCommand::LaunchSecretInputRpcProbe,
        );
        let unavailable =
            DesktopCommandResponse::new(epoch_nonce()?, request_id()?, DesktopResult::Unavailable);
        unavailable.ensure_correlates_with(&status)?;
        unavailable.ensure_correlates_with(&approval)?;
        unavailable.ensure_correlates_with(&secret)?;

        let approval_complete = DesktopCommandResponse::new(
            epoch_nonce()?,
            request_id()?,
            DesktopResult::ApprovalRpcProbeCompleted,
        );
        approval_complete.ensure_correlates_with(&approval)?;
        assert_eq!(
            approval_complete.ensure_correlates_with(&status),
            Err(WireError::BindingMismatch)
        );
        assert_eq!(
            approval_complete.ensure_correlates_with(&secret),
            Err(WireError::BindingMismatch)
        );

        let secret_complete = DesktopCommandResponse::new(
            epoch_nonce()?,
            request_id()?,
            DesktopResult::SecretInputRpcProbeCompleted,
        );
        secret_complete.ensure_correlates_with(&secret)?;
        assert_eq!(
            secret_complete.ensure_correlates_with(&approval),
            Err(WireError::BindingMismatch)
        );

        let wrong_epoch = DesktopCommandResponse::new(
            EpochNonce::new([0xA6; EPOCH_NONCE_BYTES])?,
            request_id()?,
            DesktopResult::Unavailable,
        );
        assert_eq!(
            wrong_epoch.ensure_correlates_with(&status),
            Err(WireError::BindingMismatch)
        );
        let wrong_request_id = DesktopCommandResponse::new(
            epoch_nonce()?,
            ServiceRequestId::new([0x5B; REQUEST_ID_BYTES])?,
            DesktopResult::Unavailable,
        );
        assert_eq!(
            wrong_request_id.ensure_correlates_with(&status),
            Err(WireError::BindingMismatch)
        );

        let helper_request = HelperReadyRequest::new(epoch_nonce()?, request_id()?);
        let helper_ack = HelperReadyAck::new(epoch_nonce()?, request_id()?);
        helper_ack.ensure_correlates_with(&helper_request)?;
        let wrong_helper = HelperReadyAck::new(
            epoch_nonce()?,
            ServiceRequestId::new([0x5B; REQUEST_ID_BYTES])?,
        );
        assert_eq!(
            wrong_helper.ensure_correlates_with(&helper_request),
            Err(WireError::BindingMismatch)
        );

        let open_request = ServiceRequest::OpenEpoch(OpenEpochRequest::new());
        let open_response = ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce()?));
        open_response.ensure_correlates_with(&open_request)?;
        let helper_outer_request = ServiceRequest::HelperReady(helper_request);
        let helper_outer_response = ServiceResponse::HelperReady(helper_ack);
        helper_outer_response.ensure_correlates_with(&helper_outer_request)?;
        assert_eq!(
            helper_outer_response.ensure_correlates_with(&open_request),
            Err(WireError::BindingMismatch)
        );
        assert_eq!(
            open_response.ensure_correlates_with(&helper_outer_request),
            Err(WireError::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn getters_and_debug_output_preserve_only_redacted_bindings() -> Result<(), WireError> {
        let command = DesktopCommandRequest::new(
            epoch_nonce()?,
            request_id()?,
            DesktopCommand::LaunchApprovalRpcProbe,
        );
        assert_eq!(command.epoch_nonce(), epoch_nonce()?);
        assert_eq!(command.request_id(), request_id()?);
        assert_eq!(command.command(), DesktopCommand::LaunchApprovalRpcProbe);

        let response = DesktopCommandResponse::new(
            epoch_nonce()?,
            request_id()?,
            DesktopResult::ApprovalRpcProbeCompleted,
        );
        assert_eq!(response.epoch_nonce(), epoch_nonce()?);
        assert_eq!(response.request_id(), request_id()?);
        assert_eq!(response.result(), DesktopResult::ApprovalRpcProbeCompleted);

        let helper_request = HelperReadyRequest::new(epoch_nonce()?, request_id()?);
        let helper_ack = HelperReadyAck::new(epoch_nonce()?, request_id()?);
        assert_eq!(helper_request.epoch_nonce(), epoch_nonce()?);
        assert_eq!(helper_request.request_id(), request_id()?);
        assert_eq!(helper_ack.epoch_nonce(), epoch_nonce()?);
        assert_eq!(helper_ack.request_id(), request_id()?);
        assert_eq!(
            OpenEpochAck::new(epoch_nonce()?).epoch_nonce(),
            epoch_nonce()?
        );

        for debug_value in [
            format!("{command:?}"),
            format!("{response:?}"),
            format!("{helper_request:?}"),
            format!("{helper_ack:?}"),
            format!("{:?}", ServiceRequest::DesktopCommand(command)),
            format!("{:?}", ServiceResponse::DesktopCommand(response)),
        ] {
            assert!(debug_value.contains("[REDACTED]"));
            assert!(!debug_value.contains("165, 165"));
            assert!(!debug_value.contains("90, 90"));
        }
        Ok(())
    }

    #[test]
    fn every_single_byte_substitution_is_rejected() -> Result<(), WireError> {
        for request in canonical_requests()? {
            assert_every_single_byte_request_corruption_is_rejected(&encode_request(&request));
        }
        for response in canonical_responses()? {
            assert_every_single_byte_response_corruption_is_rejected(&encode_response(&response));
        }
        Ok(())
    }

    #[test]
    fn checksum_uses_the_v1_crc32c_convention() {
        assert_eq!(super::super::crc32c(b"123456789"), 0xE306_9283);
    }
}
