//! Bounded, transport-neutral wire contract for the Windows Key Agent service.
//!
//! Version 1 deliberately carries only epoch establishment and a coarse
//! unavailable status. Operating-system caller metadata and trusted timing
//! constraints are derived by the authenticated service transport and are
//! never accepted as wire authority.
//!
//! Every frame has a fixed length and ends in a CRC32C framing check. The CRC
//! detects accidental and single-byte corruption; it is not authentication.
//! The surrounding authenticated local RPC transport remains responsible for
//! authentication, integrity, privacy, peer identity, and replay-resistant
//! call epochs.

#![forbid(unsafe_code)]

use core::fmt;

/// Debug-only version-2 feasibility wire contract.
///
/// This module is excluded from default builds and does not change the
/// immutable version-1 public contract.
#[cfg(feature = "debug-feasibility-v2")]
pub mod debug_v2;

/// Fixed protocol magic for every version-1 frame.
pub const PROTOCOL_MAGIC: [u8; 8] = *b"YWKASV01";

/// Exact byte length of an open-epoch request.
pub const OPEN_EPOCH_REQUEST_BYTES: usize = 20;
/// Exact byte length of an open-epoch acknowledgement.
pub const OPEN_EPOCH_ACK_BYTES: usize = 52;
/// Exact byte length of a bound command request.
pub const COMMAND_REQUEST_BYTES: usize = 72;
/// Exact byte length of a bound command response.
pub const COMMAND_RESPONSE_BYTES: usize = 72;
/// Maximum accepted request frame length.
pub const MAX_SERVICE_REQUEST_BYTES: usize = COMMAND_REQUEST_BYTES;
/// Maximum accepted response frame length.
pub const MAX_SERVICE_RESPONSE_BYTES: usize = COMMAND_RESPONSE_BYTES;

const HEADER_BYTES: usize = 16;
const CHECKSUM_BYTES: usize = 4;
const VERSION_V1: u16 = 1;
const FRAME_OPEN_EPOCH_REQUEST: u16 = 1;
const FRAME_OPEN_EPOCH_ACK: u16 = 2;
const FRAME_COMMAND_REQUEST: u16 = 3;
const FRAME_COMMAND_RESPONSE: u16 = 4;
const COMMAND_STATUS: u16 = 1;
const STATUS_UNAVAILABLE: u16 = 1;
const EPOCH_NONCE_BYTES: usize = 32;
const REQUEST_ID_BYTES: usize = 16;
const CRC32C_POLYNOMIAL_REVERSED: u32 = 0x82F6_3B78;

const EPOCH_OFFSET: usize = HEADER_BYTES;
const REQUEST_ID_OFFSET: usize = EPOCH_OFFSET + EPOCH_NONCE_BYTES;
const BODY_KIND_OFFSET: usize = REQUEST_ID_OFFSET + REQUEST_ID_BYTES;
const BODY_RESERVED_OFFSET: usize = BODY_KIND_OFFSET + 2;

/// The only protocol version accepted by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolVersion {
    /// Initial bounded service protocol.
    V1,
}

impl ProtocolVersion {
    /// Returns the canonical unsigned wire code.
    #[must_use]
    pub const fn wire_code(self) -> u16 {
        match self {
            Self::V1 => VERSION_V1,
        }
    }
}

impl TryFrom<u16> for ProtocolVersion {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            VERSION_V1 => Ok(Self::V1),
            _ => Err(WireError::UnsupportedVersion),
        }
    }
}

/// Fresh, service-issued epoch nonce.
///
/// The all-zero sentinel is rejected. Debug output never exposes nonce bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EpochNonce([u8; EPOCH_NONCE_BYTES]);

impl EpochNonce {
    /// Validates a freshly generated epoch nonce.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for the all-zero sentinel.
    pub fn new(bytes: [u8; EPOCH_NONCE_BYTES]) -> Result<Self, WireError> {
        if is_all_zero(&bytes) {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact bytes for canonical encoding or correlation binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EPOCH_NONCE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for EpochNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochNonce([REDACTED])")
    }
}

/// Nonzero request identifier scoped to one authenticated epoch.
///
/// Debug output never exposes identifier bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServiceRequestId([u8; REQUEST_ID_BYTES]);

impl ServiceRequestId {
    /// Validates a request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for the all-zero sentinel.
    pub fn new(bytes: [u8; REQUEST_ID_BYTES]) -> Result<Self, WireError> {
        if is_all_zero(&bytes) {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact bytes for canonical encoding or correlation binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REQUEST_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ServiceRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceRequestId([REDACTED])")
    }
}

/// Empty request asking the service to establish a fresh authenticated epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OpenEpochRequest;

impl OpenEpochRequest {
    /// Constructs the only canonical open-epoch request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Acknowledgement carrying the fresh nonce minted for one authenticated epoch.
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

/// Closed command set supported by version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceCommand {
    /// Request only a coarse non-secret service status.
    Status,
}

/// Closed coarse status set supported by version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStatus {
    /// No production wallet operation is available.
    Unavailable,
}

/// One command bound to an authenticated service epoch and request identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceCommandRequest {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
    command: ServiceCommand,
}

impl ServiceCommandRequest {
    /// Constructs a request from already validated binding values.
    #[must_use]
    pub const fn new(
        epoch_nonce: EpochNonce,
        request_id: ServiceRequestId,
        command: ServiceCommand,
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

    /// Returns the closed command.
    #[must_use]
    pub const fn command(&self) -> ServiceCommand {
        self.command
    }
}

/// One coarse status response bound to the exact epoch and request identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceStatusResponse {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
    status: ServiceStatus,
}

impl ServiceStatusResponse {
    /// Constructs a response from already validated binding values.
    #[must_use]
    pub const fn new(
        epoch_nonce: EpochNonce,
        request_id: ServiceRequestId,
        status: ServiceStatus,
    ) -> Self {
        Self {
            epoch_nonce,
            request_id,
            status,
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

    /// Returns the coarse service status.
    #[must_use]
    pub const fn status(&self) -> ServiceStatus {
        self.status
    }

    /// Verifies that this response is bound to the exact command request.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BindingMismatch`] when either the epoch nonce or
    /// request identifier differs.
    pub fn ensure_correlates_with(&self, request: &ServiceCommandRequest) -> Result<(), WireError> {
        if request.command == ServiceCommand::Status
            && self.epoch_nonce == request.epoch_nonce
            && self.request_id == request.request_id
        {
            Ok(())
        } else {
            Err(WireError::BindingMismatch)
        }
    }
}

/// Canonical request frame variants accepted by version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRequest {
    /// Establish a fresh authenticated epoch.
    OpenEpoch(OpenEpochRequest),
    /// Execute one command within an established epoch.
    Command(ServiceCommandRequest),
}

/// Canonical response frame variants emitted by version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceResponse {
    /// Fresh epoch establishment acknowledgement.
    OpenEpoch(OpenEpochAck),
    /// Coarse response to a bound status command.
    Status(ServiceStatusResponse),
}

impl ServiceResponse {
    /// Verifies canonical request/response pairing and command bindings.
    ///
    /// An open-epoch request has no caller-provided correlation value. Its
    /// acknowledgement is correlated by being the response to that same
    /// authenticated RPC call. Bound commands additionally require exact
    /// epoch-nonce and request-identifier equality here.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BindingMismatch`] for different variants or
    /// different command binding values.
    pub fn ensure_correlates_with(&self, request: &ServiceRequest) -> Result<(), WireError> {
        match (self, request) {
            (Self::OpenEpoch(_), ServiceRequest::OpenEpoch(_)) => Ok(()),
            (Self::Status(response), ServiceRequest::Command(request)) => {
                response.ensure_correlates_with(request)
            }
            _ => Err(WireError::BindingMismatch),
        }
    }
}

/// Stable, data-free wire failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// The frame ended before its exact required length.
    Truncated,
    /// Bytes followed the exact required frame.
    TrailingData,
    /// The fixed protocol magic did not match.
    InvalidMagic,
    /// The encoded protocol version is not supported.
    UnsupportedVersion,
    /// A frame, command, status, or result kind is outside the decoded generation's closed set.
    UnknownKind,
    /// A reserved field was not exactly zero.
    NonZeroReserved,
    /// A required nonce or request identifier used its invalid sentinel.
    InvalidValue,
    /// The CRC32C framing check did not match the exact preceding bytes.
    Integrity,
    /// A response did not match its request variant or binding values.
    BindingMismatch,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "service wire frame was truncated",
            Self::TrailingData => "service wire frame had trailing data",
            Self::InvalidMagic => "service wire magic was invalid",
            Self::UnsupportedVersion => "service wire version was unsupported",
            Self::UnknownKind => "service wire kind was unknown",
            Self::NonZeroReserved => "service wire reserved field was nonzero",
            Self::InvalidValue => "service wire value was invalid",
            Self::Integrity => "service wire framing integrity check failed",
            Self::BindingMismatch => "service wire response binding did not match",
        })
    }
}

impl std::error::Error for WireError {}

/// Encodes one canonical request frame.
#[must_use]
pub fn encode_request(request: &ServiceRequest) -> Vec<u8> {
    match request {
        ServiceRequest::OpenEpoch(_) => {
            let mut frame = Vec::with_capacity(OPEN_EPOCH_REQUEST_BYTES);
            encode_header(&mut frame, FRAME_OPEN_EPOCH_REQUEST);
            finish_frame(frame)
        }
        ServiceRequest::Command(request) => {
            let mut frame = Vec::with_capacity(COMMAND_REQUEST_BYTES);
            encode_header(&mut frame, FRAME_COMMAND_REQUEST);
            frame.extend_from_slice(request.epoch_nonce.as_bytes());
            frame.extend_from_slice(request.request_id.as_bytes());
            frame.extend_from_slice(&command_code(request.command).to_be_bytes());
            frame.extend_from_slice(&0_u16.to_be_bytes());
            finish_frame(frame)
        }
    }
}

/// Decodes one complete request and rejects every noncanonical byte.
///
/// # Errors
///
/// Returns a stable [`WireError`] category for malformed input.
pub fn decode_request(bytes: &[u8]) -> Result<ServiceRequest, WireError> {
    let frame_kind = decode_header(bytes)?;
    match frame_kind {
        FRAME_OPEN_EPOCH_REQUEST => {
            require_exact_length(bytes, OPEN_EPOCH_REQUEST_BYTES)?;
            verify_checksum(bytes)?;
            Ok(ServiceRequest::OpenEpoch(OpenEpochRequest::new()))
        }
        FRAME_COMMAND_REQUEST => {
            require_exact_length(bytes, COMMAND_REQUEST_BYTES)?;
            verify_checksum(bytes)?;
            let epoch_nonce = decode_epoch_nonce(bytes)?;
            let request_id = decode_request_id(bytes)?;
            require_zero_u16(bytes, BODY_RESERVED_OFFSET)?;
            let command = match read_u16(bytes, BODY_KIND_OFFSET) {
                COMMAND_STATUS => ServiceCommand::Status,
                _ => return Err(WireError::UnknownKind),
            };
            Ok(ServiceRequest::Command(ServiceCommandRequest::new(
                epoch_nonce,
                request_id,
                command,
            )))
        }
        _ => Err(WireError::UnknownKind),
    }
}

/// Encodes one canonical response frame.
#[must_use]
pub fn encode_response(response: &ServiceResponse) -> Vec<u8> {
    match response {
        ServiceResponse::OpenEpoch(ack) => {
            let mut frame = Vec::with_capacity(OPEN_EPOCH_ACK_BYTES);
            encode_header(&mut frame, FRAME_OPEN_EPOCH_ACK);
            frame.extend_from_slice(ack.epoch_nonce.as_bytes());
            finish_frame(frame)
        }
        ServiceResponse::Status(response) => {
            let mut frame = Vec::with_capacity(COMMAND_RESPONSE_BYTES);
            encode_header(&mut frame, FRAME_COMMAND_RESPONSE);
            frame.extend_from_slice(response.epoch_nonce.as_bytes());
            frame.extend_from_slice(response.request_id.as_bytes());
            frame.extend_from_slice(&status_code(response.status).to_be_bytes());
            frame.extend_from_slice(&0_u16.to_be_bytes());
            finish_frame(frame)
        }
    }
}

/// Decodes one complete response and rejects every noncanonical byte.
///
/// # Errors
///
/// Returns a stable [`WireError`] category for malformed input.
pub fn decode_response(bytes: &[u8]) -> Result<ServiceResponse, WireError> {
    let frame_kind = decode_header(bytes)?;
    match frame_kind {
        FRAME_OPEN_EPOCH_ACK => {
            require_exact_length(bytes, OPEN_EPOCH_ACK_BYTES)?;
            verify_checksum(bytes)?;
            let epoch_nonce = decode_epoch_nonce(bytes)?;
            Ok(ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce)))
        }
        FRAME_COMMAND_RESPONSE => {
            require_exact_length(bytes, COMMAND_RESPONSE_BYTES)?;
            verify_checksum(bytes)?;
            let epoch_nonce = decode_epoch_nonce(bytes)?;
            let request_id = decode_request_id(bytes)?;
            require_zero_u16(bytes, BODY_RESERVED_OFFSET)?;
            let status = match read_u16(bytes, BODY_KIND_OFFSET) {
                STATUS_UNAVAILABLE => ServiceStatus::Unavailable,
                _ => return Err(WireError::UnknownKind),
            };
            Ok(ServiceResponse::Status(ServiceStatusResponse::new(
                epoch_nonce,
                request_id,
                status,
            )))
        }
        _ => Err(WireError::UnknownKind),
    }
}

const fn command_code(command: ServiceCommand) -> u16 {
    match command {
        ServiceCommand::Status => COMMAND_STATUS,
    }
}

const fn status_code(status: ServiceStatus) -> u16 {
    match status {
        ServiceStatus::Unavailable => STATUS_UNAVAILABLE,
    }
}

fn encode_header(output: &mut Vec<u8>, frame_kind: u16) {
    output.extend_from_slice(&PROTOCOL_MAGIC);
    output.extend_from_slice(&ProtocolVersion::V1.wire_code().to_be_bytes());
    output.extend_from_slice(&frame_kind.to_be_bytes());
    output.extend_from_slice(&0_u32.to_be_bytes());
}

fn finish_frame(mut frame: Vec<u8>) -> Vec<u8> {
    let checksum = crc32c(&frame);
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
    if crc32c(&bytes[..checksum_offset]) == actual {
        Ok(())
    } else {
        Err(WireError::Integrity)
    }
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

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let low_bit_mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (CRC32C_POLYNOMIAL_REVERSED & low_bit_mask);
        }
    }
    !crc
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

    fn command_request() -> Result<ServiceRequest, WireError> {
        Ok(ServiceRequest::Command(ServiceCommandRequest::new(
            epoch_nonce()?,
            request_id()?,
            ServiceCommand::Status,
        )))
    }

    fn status_response() -> Result<ServiceResponse, WireError> {
        Ok(ServiceResponse::Status(ServiceStatusResponse::new(
            epoch_nonce()?,
            request_id()?,
            ServiceStatus::Unavailable,
        )))
    }

    fn rewrite_checksum(frame: &mut [u8]) {
        let checksum_offset = frame.len() - CHECKSUM_BYTES;
        let checksum = crc32c(&frame[..checksum_offset]).to_be_bytes();
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
    fn value_sentinels_are_rejected_and_debug_is_redacted() -> Result<(), WireError> {
        assert_eq!(
            EpochNonce::new([0; EPOCH_NONCE_BYTES]),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            ServiceRequestId::new([0; REQUEST_ID_BYTES]),
            Err(WireError::InvalidValue)
        );
        assert_eq!(format!("{:?}", epoch_nonce()?), "EpochNonce([REDACTED])");
        assert_eq!(
            format!("{:?}", request_id()?),
            "ServiceRequestId([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn all_canonical_frames_round_trip_at_exact_lengths() -> Result<(), WireError> {
        let open_request = ServiceRequest::OpenEpoch(OpenEpochRequest::new());
        let open_ack = ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce()?));
        let command = command_request()?;
        let status = status_response()?;

        let encoded_open_request = encode_request(&open_request);
        let encoded_open_ack = encode_response(&open_ack);
        let encoded_command = encode_request(&command);
        let encoded_status = encode_response(&status);

        assert_eq!(encoded_open_request.len(), OPEN_EPOCH_REQUEST_BYTES);
        assert_eq!(encoded_open_ack.len(), OPEN_EPOCH_ACK_BYTES);
        assert_eq!(encoded_command.len(), COMMAND_REQUEST_BYTES);
        assert_eq!(encoded_status.len(), COMMAND_RESPONSE_BYTES);
        assert_eq!(decode_request(&encoded_open_request)?, open_request);
        assert_eq!(decode_response(&encoded_open_ack)?, open_ack);
        assert_eq!(decode_request(&encoded_command)?, command);
        assert_eq!(decode_response(&encoded_status)?, status);
        Ok(())
    }

    #[test]
    fn every_prefix_and_suffix_length_is_rejected() -> Result<(), WireError> {
        let requests = [
            encode_request(&ServiceRequest::OpenEpoch(OpenEpochRequest::new())),
            encode_request(&command_request()?),
        ];
        for frame in &requests {
            for prefix_length in 0..frame.len() {
                assert_eq!(
                    decode_request(&frame[..prefix_length]),
                    Err(WireError::Truncated)
                );
            }
            let mut trailing = frame.clone();
            trailing.push(0);
            assert_eq!(decode_request(&trailing), Err(WireError::TrailingData));
        }

        let responses = [
            encode_response(&ServiceResponse::OpenEpoch(OpenEpochAck::new(
                epoch_nonce()?
            ))),
            encode_response(&status_response()?),
        ];
        for frame in &responses {
            for prefix_length in 0..frame.len() {
                assert_eq!(
                    decode_response(&frame[..prefix_length]),
                    Err(WireError::Truncated)
                );
            }
            let mut trailing = frame.clone();
            trailing.push(0);
            assert_eq!(decode_response(&trailing), Err(WireError::TrailingData));
        }
        Ok(())
    }

    #[test]
    fn semantic_header_failures_have_stable_categories() {
        let canonical = encode_request(&ServiceRequest::OpenEpoch(OpenEpochRequest::new()));

        let mut wrong_magic = canonical.clone();
        wrong_magic[0] ^= 1;
        rewrite_checksum(&mut wrong_magic);
        assert_eq!(decode_request(&wrong_magic), Err(WireError::InvalidMagic));

        let mut wrong_version = canonical.clone();
        wrong_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        rewrite_checksum(&mut wrong_version);
        assert_eq!(
            decode_request(&wrong_version),
            Err(WireError::UnsupportedVersion)
        );

        let mut unknown_kind = canonical.clone();
        unknown_kind[10..12].copy_from_slice(&0x7FFF_u16.to_be_bytes());
        rewrite_checksum(&mut unknown_kind);
        assert_eq!(decode_request(&unknown_kind), Err(WireError::UnknownKind));

        let mut reserved = canonical;
        reserved[15] = 1;
        rewrite_checksum(&mut reserved);
        assert_eq!(decode_request(&reserved), Err(WireError::NonZeroReserved));
    }

    #[test]
    fn version_and_kind_extrema_are_rejected() -> Result<(), WireError> {
        let request = encode_request(&ServiceRequest::OpenEpoch(OpenEpochRequest::new()));
        for version in [u16::MIN, u16::MAX] {
            let mut mutated = request.clone();
            mutated[8..10].copy_from_slice(&version.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_request(&mutated), Err(WireError::UnsupportedVersion));
        }
        for frame_kind in [u16::MIN, u16::MAX] {
            let mut mutated = request.clone();
            mutated[10..12].copy_from_slice(&frame_kind.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_request(&mutated), Err(WireError::UnknownKind));
        }

        let response = encode_response(&ServiceResponse::OpenEpoch(OpenEpochAck::new(
            epoch_nonce()?,
        )));
        for version in [u16::MIN, u16::MAX] {
            let mut mutated = response.clone();
            mutated[8..10].copy_from_slice(&version.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(
                decode_response(&mutated),
                Err(WireError::UnsupportedVersion)
            );
        }
        for frame_kind in [u16::MIN, u16::MAX] {
            let mut mutated = response.clone();
            mutated[10..12].copy_from_slice(&frame_kind.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_response(&mutated), Err(WireError::UnknownKind));
        }

        let command = encode_request(&command_request()?);
        for command_kind in [u16::MIN, u16::MAX] {
            let mut mutated = command.clone();
            mutated[BODY_KIND_OFFSET..BODY_KIND_OFFSET + 2]
                .copy_from_slice(&command_kind.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_request(&mutated), Err(WireError::UnknownKind));
        }

        let status = encode_response(&status_response()?);
        for status_kind in [u16::MIN, u16::MAX] {
            let mut mutated = status.clone();
            mutated[BODY_KIND_OFFSET..BODY_KIND_OFFSET + 2]
                .copy_from_slice(&status_kind.to_be_bytes());
            rewrite_checksum(&mut mutated);
            assert_eq!(decode_response(&mutated), Err(WireError::UnknownKind));
        }
        Ok(())
    }

    #[test]
    fn every_reserved_bit_is_rejected_after_checksum_recomputation() -> Result<(), WireError> {
        let request_frames = [
            encode_request(&ServiceRequest::OpenEpoch(OpenEpochRequest::new())),
            encode_request(&command_request()?),
        ];
        for frame in &request_frames {
            for offset in 12..16 {
                for bit in 0..8 {
                    let mut mutated = frame.clone();
                    mutated[offset] = 1_u8 << bit;
                    rewrite_checksum(&mut mutated);
                    assert_eq!(decode_request(&mutated), Err(WireError::NonZeroReserved));
                }
            }
        }

        let response_frames = [
            encode_response(&ServiceResponse::OpenEpoch(OpenEpochAck::new(
                epoch_nonce()?
            ))),
            encode_response(&status_response()?),
        ];
        for frame in &response_frames {
            for offset in 12..16 {
                for bit in 0..8 {
                    let mut mutated = frame.clone();
                    mutated[offset] = 1_u8 << bit;
                    rewrite_checksum(&mut mutated);
                    assert_eq!(decode_response(&mutated), Err(WireError::NonZeroReserved));
                }
            }
        }

        let command = encode_request(&command_request()?);
        for offset in BODY_RESERVED_OFFSET..BODY_RESERVED_OFFSET + 2 {
            for bit in 0..8 {
                let mut mutated = command.clone();
                mutated[offset] = 1_u8 << bit;
                rewrite_checksum(&mut mutated);
                assert_eq!(decode_request(&mutated), Err(WireError::NonZeroReserved));
            }
        }

        let status = encode_response(&status_response()?);
        for offset in BODY_RESERVED_OFFSET..BODY_RESERVED_OFFSET + 2 {
            for bit in 0..8 {
                let mut mutated = status.clone();
                mutated[offset] = 1_u8 << bit;
                rewrite_checksum(&mut mutated);
                assert_eq!(decode_response(&mutated), Err(WireError::NonZeroReserved));
            }
        }
        Ok(())
    }

    #[test]
    fn command_and_status_payloads_are_closed_and_reserved() -> Result<(), WireError> {
        let mut command = encode_request(&command_request()?);
        command[BODY_KIND_OFFSET..BODY_KIND_OFFSET + 2].copy_from_slice(&2_u16.to_be_bytes());
        rewrite_checksum(&mut command);
        assert_eq!(decode_request(&command), Err(WireError::UnknownKind));

        let mut command_reserved = encode_request(&command_request()?);
        command_reserved[BODY_RESERVED_OFFSET + 1] = 1;
        rewrite_checksum(&mut command_reserved);
        assert_eq!(
            decode_request(&command_reserved),
            Err(WireError::NonZeroReserved)
        );

        let mut status = encode_response(&status_response()?);
        status[BODY_KIND_OFFSET..BODY_KIND_OFFSET + 2].copy_from_slice(&2_u16.to_be_bytes());
        rewrite_checksum(&mut status);
        assert_eq!(decode_response(&status), Err(WireError::UnknownKind));

        let mut status_reserved = encode_response(&status_response()?);
        status_reserved[BODY_RESERVED_OFFSET + 1] = 1;
        rewrite_checksum(&mut status_reserved);
        assert_eq!(
            decode_response(&status_reserved),
            Err(WireError::NonZeroReserved)
        );
        Ok(())
    }

    #[test]
    fn zero_bindings_and_checksum_mismatches_are_rejected() -> Result<(), WireError> {
        let mut zero_epoch = encode_request(&command_request()?);
        zero_epoch[EPOCH_OFFSET..EPOCH_OFFSET + EPOCH_NONCE_BYTES].fill(0);
        rewrite_checksum(&mut zero_epoch);
        assert_eq!(decode_request(&zero_epoch), Err(WireError::InvalidValue));

        let mut zero_request_id = encode_request(&command_request()?);
        zero_request_id[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + REQUEST_ID_BYTES].fill(0);
        rewrite_checksum(&mut zero_request_id);
        assert_eq!(
            decode_request(&zero_request_id),
            Err(WireError::InvalidValue)
        );

        let mut zero_status_epoch = encode_response(&status_response()?);
        zero_status_epoch[EPOCH_OFFSET..EPOCH_OFFSET + EPOCH_NONCE_BYTES].fill(0);
        rewrite_checksum(&mut zero_status_epoch);
        assert_eq!(
            decode_response(&zero_status_epoch),
            Err(WireError::InvalidValue)
        );

        let mut zero_status_request_id = encode_response(&status_response()?);
        zero_status_request_id[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + REQUEST_ID_BYTES].fill(0);
        rewrite_checksum(&mut zero_status_request_id);
        assert_eq!(
            decode_response(&zero_status_request_id),
            Err(WireError::InvalidValue)
        );

        let mut zero_open_epoch = encode_response(&ServiceResponse::OpenEpoch(OpenEpochAck::new(
            epoch_nonce()?,
        )));
        zero_open_epoch[EPOCH_OFFSET..EPOCH_OFFSET + EPOCH_NONCE_BYTES].fill(0);
        rewrite_checksum(&mut zero_open_epoch);
        assert_eq!(
            decode_response(&zero_open_epoch),
            Err(WireError::InvalidValue)
        );

        let mut corrupt = encode_response(&status_response()?);
        corrupt[EPOCH_OFFSET] ^= 1;
        assert_eq!(decode_response(&corrupt), Err(WireError::Integrity));
        Ok(())
    }

    #[test]
    fn request_and_response_directions_are_not_interchangeable() -> Result<(), WireError> {
        let requests = [
            encode_request(&ServiceRequest::OpenEpoch(OpenEpochRequest::new())),
            encode_request(&command_request()?),
        ];
        for request in &requests {
            assert_eq!(decode_response(request), Err(WireError::UnknownKind));
        }

        let responses = [
            encode_response(&ServiceResponse::OpenEpoch(OpenEpochAck::new(
                epoch_nonce()?
            ))),
            encode_response(&status_response()?),
        ];
        for response in &responses {
            assert_eq!(decode_request(response), Err(WireError::UnknownKind));
        }
        Ok(())
    }

    #[test]
    fn response_correlation_requires_pairing_epoch_and_request_id() -> Result<(), WireError> {
        let request =
            ServiceCommandRequest::new(epoch_nonce()?, request_id()?, ServiceCommand::Status);
        let response =
            ServiceStatusResponse::new(epoch_nonce()?, request_id()?, ServiceStatus::Unavailable);
        assert_eq!(request.command(), ServiceCommand::Status);
        response.ensure_correlates_with(&request)?;

        let request_outer = ServiceRequest::Command(request);
        let response_outer = ServiceResponse::Status(response);
        response_outer.ensure_correlates_with(&request_outer)?;

        let other_epoch = EpochNonce::new([0xA6; EPOCH_NONCE_BYTES])?;
        let wrong_epoch = ServiceResponse::Status(ServiceStatusResponse::new(
            other_epoch,
            request_id()?,
            ServiceStatus::Unavailable,
        ));
        assert_eq!(
            wrong_epoch.ensure_correlates_with(&request_outer),
            Err(WireError::BindingMismatch)
        );

        let other_request_id = ServiceRequestId::new([0x5B; REQUEST_ID_BYTES])?;
        let wrong_request_id = ServiceResponse::Status(ServiceStatusResponse::new(
            epoch_nonce()?,
            other_request_id,
            ServiceStatus::Unavailable,
        ));
        assert_eq!(
            wrong_request_id.ensure_correlates_with(&request_outer),
            Err(WireError::BindingMismatch)
        );

        let open_request = ServiceRequest::OpenEpoch(OpenEpochRequest::new());
        let open_response = ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce()?));
        open_response.ensure_correlates_with(&open_request)?;
        assert_eq!(
            open_response.ensure_correlates_with(&request_outer),
            Err(WireError::BindingMismatch)
        );
        assert_eq!(
            response_outer.ensure_correlates_with(&open_request),
            Err(WireError::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn wrapper_and_outer_debug_never_expose_binding_bytes() -> Result<(), WireError> {
        let command =
            ServiceCommandRequest::new(epoch_nonce()?, request_id()?, ServiceCommand::Status);
        let status =
            ServiceStatusResponse::new(epoch_nonce()?, request_id()?, ServiceStatus::Unavailable);
        let debug_values = [
            format!("{:?}", OpenEpochAck::new(epoch_nonce()?)),
            format!("{command:?}"),
            format!("{status:?}"),
            format!("{:?}", ServiceRequest::Command(command)),
            format!(
                "{:?}",
                ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce()?))
            ),
            format!("{:?}", ServiceResponse::Status(status)),
        ];
        for debug_value in debug_values {
            assert!(debug_value.contains("[REDACTED]"));
            assert!(!debug_value.contains("165, 165"));
            assert!(!debug_value.contains("90, 90"));
        }
        Ok(())
    }

    #[test]
    fn every_wire_error_display_is_a_stable_data_free_category() {
        let categories = [
            (WireError::Truncated, "service wire frame was truncated"),
            (
                WireError::TrailingData,
                "service wire frame had trailing data",
            ),
            (WireError::InvalidMagic, "service wire magic was invalid"),
            (
                WireError::UnsupportedVersion,
                "service wire version was unsupported",
            ),
            (WireError::UnknownKind, "service wire kind was unknown"),
            (
                WireError::NonZeroReserved,
                "service wire reserved field was nonzero",
            ),
            (WireError::InvalidValue, "service wire value was invalid"),
            (
                WireError::Integrity,
                "service wire framing integrity check failed",
            ),
            (
                WireError::BindingMismatch,
                "service wire response binding did not match",
            ),
        ];
        for (error, expected) in categories {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn every_single_byte_substitution_is_rejected() -> Result<(), WireError> {
        assert_every_single_byte_request_corruption_is_rejected(&encode_request(
            &ServiceRequest::OpenEpoch(OpenEpochRequest::new()),
        ));
        assert_every_single_byte_request_corruption_is_rejected(&encode_request(
            &command_request()?
        ));
        assert_every_single_byte_response_corruption_is_rejected(&encode_response(
            &ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce()?)),
        ));
        assert_every_single_byte_response_corruption_is_rejected(&encode_response(
            &status_response()?,
        ));
        Ok(())
    }

    #[test]
    fn crc32c_matches_the_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }
}
