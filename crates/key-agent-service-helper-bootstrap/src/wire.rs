//! Fixed, secret-free acknowledgement for helper-handle adoption.
//!
//! This frame carries correlation evidence only. Its CRC32C detects framing
//! corruption, but neither the frame nor its checksum authenticates a peer or
//! grants authority. The surrounding trusted launch flow remains responsible
//! for peer identity, transport security, and handle provenance.

#![forbid(unsafe_code)]

use core::fmt;

use key_agent_service_wire::{EpochNonce, ServiceRequestId, WireError};

/// Exact byte length of a helper-adoption acknowledgement.
pub const HELPER_ADOPTION_ACK_BYTES: usize = 72;

/// Stable, data-free failure categories for the adoption acknowledgement.
///
/// The codec deliberately shares the service wire's closed framing-error
/// vocabulary so callers cannot recover or log malformed correlation bytes.
pub type AdoptionWireError = WireError;

const HELPER_ADOPTION_MAGIC: [u8; 8] = *b"YWKHBA01";
const VERSION_V1: u16 = 1;
const FRAME_HELPER_ADOPTION_ACK: u16 = 1;
const HEADER_RESERVED_OFFSET: usize = 12;
const EPOCH_NONCE_OFFSET: usize = 16;
const EPOCH_NONCE_BYTES: usize = 32;
const REQUEST_ID_OFFSET: usize = EPOCH_NONCE_OFFSET + EPOCH_NONCE_BYTES;
const REQUEST_ID_BYTES: usize = 16;
const ROLE_OFFSET: usize = REQUEST_ID_OFFSET + REQUEST_ID_BYTES;
const ROLE_RESERVED_OFFSET: usize = ROLE_OFFSET + 2;
const CHECKSUM_OFFSET: usize = ROLE_RESERVED_OFFSET + 2;
const CRC32C_POLYNOMIAL_REVERSED: u32 = 0x82F6_3B78;

/// Closed role set for a service-launched helper process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelperBootstrapRole {
    /// The helper displays an approval decision.
    Approval,
    /// The helper collects secret input.
    SecretInput,
}

impl HelperBootstrapRole {
    const fn wire_code(self) -> u16 {
        match self {
            Self::Approval => 1,
            Self::SecretInput => 2,
        }
    }

    fn from_wire_code(code: u16) -> Result<Self, WireError> {
        match code {
            1 => Ok(Self::Approval),
            2 => Ok(Self::SecretInput),
            _ => Err(WireError::UnknownKind),
        }
    }
}

/// Correlation evidence that a helper adopted its bootstrap handles.
///
/// This value is deliberately not an authentication or authorization proof.
/// Its fields contain no secret, process identifier, deadline, or handle.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HelperAdoptionAck {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
    role: HelperBootstrapRole,
}

impl HelperAdoptionAck {
    /// Constructs an acknowledgement from already validated correlation data.
    #[must_use]
    pub const fn new(
        epoch_nonce: EpochNonce,
        request_id: ServiceRequestId,
        role: HelperBootstrapRole,
    ) -> Self {
        Self {
            epoch_nonce,
            request_id,
            role,
        }
    }

    /// Returns the service epoch correlated by this acknowledgement.
    #[must_use]
    pub const fn epoch_nonce(&self) -> EpochNonce {
        self.epoch_nonce
    }

    /// Returns the service request correlated by this acknowledgement.
    #[must_use]
    pub const fn request_id(&self) -> ServiceRequestId {
        self.request_id
    }

    /// Returns the helper role correlated by this acknowledgement.
    #[must_use]
    pub const fn role(&self) -> HelperBootstrapRole {
        self.role
    }

    /// Encodes the one canonical fixed-length acknowledgement frame.
    #[must_use]
    pub fn encode(&self) -> [u8; HELPER_ADOPTION_ACK_BYTES] {
        let mut frame = [0_u8; HELPER_ADOPTION_ACK_BYTES];
        frame[..HELPER_ADOPTION_MAGIC.len()].copy_from_slice(&HELPER_ADOPTION_MAGIC);
        frame[8..10].copy_from_slice(&VERSION_V1.to_be_bytes());
        frame[10..12].copy_from_slice(&FRAME_HELPER_ADOPTION_ACK.to_be_bytes());
        frame[EPOCH_NONCE_OFFSET..REQUEST_ID_OFFSET].copy_from_slice(self.epoch_nonce.as_bytes());
        frame[REQUEST_ID_OFFSET..ROLE_OFFSET].copy_from_slice(self.request_id.as_bytes());
        frame[ROLE_OFFSET..ROLE_RESERVED_OFFSET]
            .copy_from_slice(&self.role.wire_code().to_be_bytes());
        let checksum = crc32c(&frame[..CHECKSUM_OFFSET]);
        frame[CHECKSUM_OFFSET..].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    /// Decodes one complete frame and rejects every noncanonical byte.
    ///
    /// # Errors
    ///
    /// Returns a stable [`WireError`] category for malformed or unbounded
    /// input.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        require_exact_length(bytes)?;
        if bytes.get(..HELPER_ADOPTION_MAGIC.len()) != Some(HELPER_ADOPTION_MAGIC.as_slice()) {
            return Err(WireError::InvalidMagic);
        }
        if read_u16(bytes, 8) != VERSION_V1 {
            return Err(WireError::UnsupportedVersion);
        }
        if read_u16(bytes, 10) != FRAME_HELPER_ADOPTION_ACK {
            return Err(WireError::UnknownKind);
        }
        require_zero_u32(bytes, HEADER_RESERVED_OFFSET)?;
        verify_checksum(bytes)?;
        require_zero_u16(bytes, ROLE_RESERVED_OFFSET)?;

        let mut epoch_nonce = [0_u8; EPOCH_NONCE_BYTES];
        epoch_nonce.copy_from_slice(&bytes[EPOCH_NONCE_OFFSET..REQUEST_ID_OFFSET]);
        let epoch_nonce = EpochNonce::new(epoch_nonce)?;

        let mut request_id = [0_u8; REQUEST_ID_BYTES];
        request_id.copy_from_slice(&bytes[REQUEST_ID_OFFSET..ROLE_OFFSET]);
        let request_id = ServiceRequestId::new(request_id)?;

        let role = HelperBootstrapRole::from_wire_code(read_u16(bytes, ROLE_OFFSET))?;
        Ok(Self::new(epoch_nonce, request_id, role))
    }

    /// Checks all correlation fields against trusted launch-side expectations.
    ///
    /// A successful comparison is still correlation evidence only; callers
    /// must not treat it as peer authentication or authority.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BindingMismatch`] if any correlation field differs.
    pub fn ensure_correlates_with(
        &self,
        epoch_nonce: EpochNonce,
        request_id: ServiceRequestId,
        role: HelperBootstrapRole,
    ) -> Result<(), WireError> {
        if self.epoch_nonce == epoch_nonce && self.request_id == request_id && self.role == role {
            Ok(())
        } else {
            Err(WireError::BindingMismatch)
        }
    }
}

impl fmt::Debug for HelperAdoptionAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperAdoptionAck")
            .field("epoch_nonce", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .field("role", &self.role)
            .finish()
    }
}

/// Encodes one canonical helper-adoption acknowledgement.
#[must_use]
pub fn encode_adoption_ack(acknowledgement: &HelperAdoptionAck) -> [u8; HELPER_ADOPTION_ACK_BYTES] {
    acknowledgement.encode()
}

/// Decodes one complete helper-adoption acknowledgement.
///
/// # Errors
///
/// Returns a stable [`AdoptionWireError`] category for malformed or unbounded
/// input.
pub fn decode_adoption_ack(bytes: &[u8]) -> Result<HelperAdoptionAck, AdoptionWireError> {
    HelperAdoptionAck::decode(bytes)
}

fn require_exact_length(bytes: &[u8]) -> Result<(), WireError> {
    match bytes.len().cmp(&HELPER_ADOPTION_ACK_BYTES) {
        core::cmp::Ordering::Less => Err(WireError::Truncated),
        core::cmp::Ordering::Equal => Ok(()),
        core::cmp::Ordering::Greater => Err(WireError::TrailingData),
    }
}

fn verify_checksum(bytes: &[u8]) -> Result<(), WireError> {
    let actual = read_u32(bytes, CHECKSUM_OFFSET);
    if crc32c(&bytes[..CHECKSUM_OFFSET]) == actual {
        Ok(())
    } else {
        Err(WireError::Integrity)
    }
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

    fn sample_ack(role: HelperBootstrapRole) -> Result<HelperAdoptionAck, WireError> {
        Ok(HelperAdoptionAck::new(
            EpochNonce::new([0xA5; EPOCH_NONCE_BYTES])?,
            ServiceRequestId::new([0x5A; REQUEST_ID_BYTES])?,
            role,
        ))
    }

    fn rewrite_checksum(frame: &mut [u8; HELPER_ADOPTION_ACK_BYTES]) {
        let checksum = crc32c(&frame[..CHECKSUM_OFFSET]).to_be_bytes();
        frame[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    }

    #[test]
    fn both_roles_round_trip() -> Result<(), WireError> {
        for role in [
            HelperBootstrapRole::Approval,
            HelperBootstrapRole::SecretInput,
        ] {
            let original = sample_ack(role)?;
            let encoded = encode_adoption_ack(&original);
            assert_eq!(decode_adoption_ack(&encoded)?, original);
        }
        Ok(())
    }

    #[test]
    fn approval_golden_vector_is_stable() -> Result<(), WireError> {
        let ack = HelperAdoptionAck::new(
            EpochNonce::new([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                0x1D, 0x1E, 0x1F, 0x20,
            ])?,
            ServiceRequestId::new([
                0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
                0xAE, 0xAF,
            ])?,
            HelperBootstrapRole::Approval,
        );
        let expected = [
            0x59, 0x57, 0x4B, 0x48, 0x42, 0x41, 0x30, 0x31, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
            0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
            0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0x00, 0x01, 0x00, 0x00, 0x78, 0xBE,
            0x04, 0xD0,
        ];
        assert_eq!(encode_adoption_ack(&ack), expected);
        assert_eq!(decode_adoption_ack(&expected)?, ack);
        Ok(())
    }

    #[test]
    fn every_nonexact_length_is_rejected() -> Result<(), WireError> {
        let encoded = sample_ack(HelperBootstrapRole::Approval)?.encode();
        for length in 0..HELPER_ADOPTION_ACK_BYTES {
            assert_eq!(
                HelperAdoptionAck::decode(&encoded[..length]),
                Err(WireError::Truncated)
            );
        }

        let mut with_trailing = [0_u8; HELPER_ADOPTION_ACK_BYTES * 2];
        with_trailing[..HELPER_ADOPTION_ACK_BYTES].copy_from_slice(&encoded);
        for length in HELPER_ADOPTION_ACK_BYTES + 1..=with_trailing.len() {
            assert_eq!(
                HelperAdoptionAck::decode(&with_trailing[..length]),
                Err(WireError::TrailingData)
            );
        }
        Ok(())
    }

    #[test]
    fn every_single_byte_mutation_is_rejected() -> Result<(), WireError> {
        let encoded = sample_ack(HelperBootstrapRole::SecretInput)?.encode();
        for index in 0..HELPER_ADOPTION_ACK_BYTES {
            let mut mutated = encoded;
            mutated[index] ^= 1;
            assert!(HelperAdoptionAck::decode(&mutated).is_err());
        }
        Ok(())
    }

    #[test]
    fn recomputed_crc_cannot_make_invalid_header_fields_canonical() -> Result<(), WireError> {
        let encoded = sample_ack(HelperBootstrapRole::Approval)?.encode();

        let mut invalid_magic = encoded;
        invalid_magic[0] ^= 1;
        rewrite_checksum(&mut invalid_magic);
        assert_eq!(
            HelperAdoptionAck::decode(&invalid_magic),
            Err(WireError::InvalidMagic)
        );

        let mut unsupported_version = encoded;
        unsupported_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        rewrite_checksum(&mut unsupported_version);
        assert_eq!(
            HelperAdoptionAck::decode(&unsupported_version),
            Err(WireError::UnsupportedVersion)
        );

        let mut unknown_kind = encoded;
        unknown_kind[10..12].copy_from_slice(&2_u16.to_be_bytes());
        rewrite_checksum(&mut unknown_kind);
        assert_eq!(
            HelperAdoptionAck::decode(&unknown_kind),
            Err(WireError::UnknownKind)
        );

        let mut nonzero_reserved = encoded;
        nonzero_reserved[HEADER_RESERVED_OFFSET] = 1;
        rewrite_checksum(&mut nonzero_reserved);
        assert_eq!(
            HelperAdoptionAck::decode(&nonzero_reserved),
            Err(WireError::NonZeroReserved)
        );
        Ok(())
    }

    #[test]
    fn recomputed_crc_cannot_make_invalid_body_fields_canonical() -> Result<(), WireError> {
        let encoded = sample_ack(HelperBootstrapRole::Approval)?.encode();

        let mut zero_epoch_nonce = encoded;
        zero_epoch_nonce[EPOCH_NONCE_OFFSET..REQUEST_ID_OFFSET].fill(0);
        rewrite_checksum(&mut zero_epoch_nonce);
        assert_eq!(
            HelperAdoptionAck::decode(&zero_epoch_nonce),
            Err(WireError::InvalidValue)
        );

        let mut zero_request_id = encoded;
        zero_request_id[REQUEST_ID_OFFSET..ROLE_OFFSET].fill(0);
        rewrite_checksum(&mut zero_request_id);
        assert_eq!(
            HelperAdoptionAck::decode(&zero_request_id),
            Err(WireError::InvalidValue)
        );

        let mut unknown_role = encoded;
        unknown_role[ROLE_OFFSET..ROLE_RESERVED_OFFSET].copy_from_slice(&3_u16.to_be_bytes());
        rewrite_checksum(&mut unknown_role);
        assert_eq!(
            HelperAdoptionAck::decode(&unknown_role),
            Err(WireError::UnknownKind)
        );

        let mut nonzero_reserved = encoded;
        nonzero_reserved[ROLE_RESERVED_OFFSET] = 1;
        rewrite_checksum(&mut nonzero_reserved);
        assert_eq!(
            HelperAdoptionAck::decode(&nonzero_reserved),
            Err(WireError::NonZeroReserved)
        );
        Ok(())
    }

    #[test]
    fn correlation_requires_every_field_to_match() -> Result<(), WireError> {
        let epoch_nonce = EpochNonce::new([0xA5; EPOCH_NONCE_BYTES])?;
        let request_id = ServiceRequestId::new([0x5A; REQUEST_ID_BYTES])?;
        let ack = HelperAdoptionAck::new(epoch_nonce, request_id, HelperBootstrapRole::Approval);
        assert_eq!(
            ack.ensure_correlates_with(epoch_nonce, request_id, HelperBootstrapRole::Approval),
            Ok(())
        );
        assert_eq!(
            ack.ensure_correlates_with(
                EpochNonce::new([0xA6; EPOCH_NONCE_BYTES])?,
                request_id,
                HelperBootstrapRole::Approval
            ),
            Err(WireError::BindingMismatch)
        );
        assert_eq!(
            ack.ensure_correlates_with(
                epoch_nonce,
                ServiceRequestId::new([0x5B; REQUEST_ID_BYTES])?,
                HelperBootstrapRole::Approval
            ),
            Err(WireError::BindingMismatch)
        );
        assert_eq!(
            ack.ensure_correlates_with(epoch_nonce, request_id, HelperBootstrapRole::SecretInput),
            Err(WireError::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn debug_output_redacts_correlation_values() -> Result<(), WireError> {
        let ack = sample_ack(HelperBootstrapRole::Approval)?;
        assert_eq!(
            format!("{ack:?}"),
            "HelperAdoptionAck { epoch_nonce: \"[REDACTED]\", request_id: \"[REDACTED]\", role: Approval }"
        );
        Ok(())
    }
}
