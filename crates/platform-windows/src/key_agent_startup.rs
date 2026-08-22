//! Fixed, allocation-bounded startup frames for the Key Agent handshake.
//!
//! The codec carries only process and storage-object binding evidence. It does
//! not authenticate, hash, or otherwise turn the startup transcript into a
//! protected-settings capability. Encoded frames and decoded state zeroize the
//! one-attempt nonce when dropped, and all diagnostics are value-free.

#![allow(dead_code)]

use core::fmt;

use zeroize::Zeroizing;

use crate::key_agent_storage::KeyAgentStorageRootIdentity;

/// Exact byte length of one Key Agent startup request.
pub(crate) const KEY_AGENT_STARTUP_REQUEST_BYTES: usize = 188;
/// Exact byte length of one Key Agent startup response.
pub(crate) const KEY_AGENT_STARTUP_RESPONSE_BYTES: usize = 88;

const REQUEST_MAGIC: [u8; 8] = *b"YWKSREQ1";
const RESPONSE_MAGIC: [u8; 8] = *b"YWKSRES1";
const STARTUP_VERSION: u16 = 1;
const PRODUCTION_FLAGS: u16 = 0;
#[cfg(test)]
const TEST_FLAGS: u16 = 1;
const SUCCESS_STATUS: u16 = 0;
const NONCE_BYTES: usize = 32;
const STORAGE_IDENTITY_BYTES: usize = 24;
const STORAGE_LEAF_BYTES: usize = 96;
const PRODUCTION_STORAGE_LEAF: &str = "YourWallet.KeyAgent.Storage.v1";
#[cfg(test)]
const TEST_STORAGE_LEAF_PREFIX: &str = "YourWallet.KeyAgent.Storage.Test.";
#[cfg(test)]
const TEST_STORAGE_LEAF_SUFFIX_BYTES: usize = 32;

const REQUEST_VERSION_OFFSET: usize = 8;
const REQUEST_FLAGS_OFFSET: usize = 10;
const REQUEST_LENGTH_OFFSET: usize = 12;
const REQUEST_NONCE_OFFSET: usize = 16;
const REQUEST_PROCESS_ID_OFFSET: usize = 48;
const REQUEST_RESERVED_OFFSET: usize = 52;
const REQUEST_CREATION_TIME_OFFSET: usize = 56;
const REQUEST_STORAGE_IDENTITY_OFFSET: usize = 64;
const REQUEST_LEAF_LENGTH_OFFSET: usize = 88;
const REQUEST_LEAF_RESERVED_OFFSET: usize = 90;
const REQUEST_LEAF_OFFSET: usize = 92;

const RESPONSE_VERSION_OFFSET: usize = 8;
const RESPONSE_STATUS_OFFSET: usize = 10;
const RESPONSE_LENGTH_OFFSET: usize = 12;
const RESPONSE_NONCE_OFFSET: usize = 16;
const RESPONSE_PROCESS_ID_OFFSET: usize = 48;
const RESPONSE_RESERVED_OFFSET: usize = 52;
const RESPONSE_CREATION_TIME_OFFSET: usize = 56;
const RESPONSE_STORAGE_IDENTITY_OFFSET: usize = 64;

/// Stable, input-free failures from the fixed Key Agent startup codec.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum KeyAgentStartupCodecError {
    /// A request field, frame, or fixed codec invariant was invalid.
    InvalidRequest,
    /// A response field, frame, binding, or fixed codec invariant was invalid.
    InvalidResponse,
}

impl fmt::Debug for KeyAgentStartupCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "KeyAgentStartupCodecError::InvalidRequest",
            Self::InvalidResponse => "KeyAgentStartupCodecError::InvalidResponse",
        })
    }
}

impl fmt::Display for KeyAgentStartupCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "Key Agent startup request is invalid",
            Self::InvalidResponse => "Key Agent startup response is invalid",
        })
    }
}

impl std::error::Error for KeyAgentStartupCodecError {}

/// One encoded request whose complete nonce-bearing storage is zeroized.
#[must_use = "the encoded startup request must be written or explicitly dropped"]
pub(crate) struct KeyAgentStartupRequestFrame {
    bytes: Zeroizing<[u8; KEY_AGENT_STARTUP_REQUEST_BYTES]>,
}

impl KeyAgentStartupRequestFrame {
    /// Borrows the complete fixed frame for an exact write.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_AGENT_STARTUP_REQUEST_BYTES] {
        &self.bytes
    }
}

impl AsRef<[u8]> for KeyAgentStartupRequestFrame {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for KeyAgentStartupRequestFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentStartupRequestFrame([REDACTED])")
    }
}

/// One encoded response whose complete nonce-bearing storage is zeroized.
#[must_use = "the encoded startup response must be written or explicitly dropped"]
pub(crate) struct KeyAgentStartupResponseFrame {
    bytes: Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]>,
}

impl KeyAgentStartupResponseFrame {
    /// Borrows the complete fixed frame for an exact write.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES] {
        &self.bytes
    }
}

impl AsRef<[u8]> for KeyAgentStartupResponseFrame {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for KeyAgentStartupResponseFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentStartupResponseFrame([REDACTED])")
    }
}

/// A strictly validated Key Agent startup request.
///
/// Production construction fixes the storage leaf internally. Test builds add
/// one explicit fixture grammar without relaxing the production grammar.
#[must_use = "a validated startup request must be consumed or explicitly dropped"]
pub(crate) struct KeyAgentStartupRequest {
    nonce: Zeroizing<[u8; NONCE_BYTES]>,
    expected_process_id: u32,
    expected_creation_time: u64,
    storage_root_identity: KeyAgentStorageRootIdentity,
    storage_leaf: String,
}

impl KeyAgentStartupRequest {
    /// Constructs the sole production request form with its fixed storage leaf.
    pub(crate) fn new(
        nonce: &[u8; NONCE_BYTES],
        expected_process_id: u32,
        expected_creation_time: u64,
        storage_root_identity: KeyAgentStorageRootIdentity,
    ) -> Result<Self, KeyAgentStartupCodecError> {
        Self::from_parts(
            zeroizing_nonce(nonce),
            expected_process_id,
            expected_creation_time,
            storage_root_identity,
            PRODUCTION_FLAGS,
            String::from(PRODUCTION_STORAGE_LEAF),
        )
    }

    /// Constructs the exact test-fixture request form.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        nonce: &[u8; NONCE_BYTES],
        expected_process_id: u32,
        expected_creation_time: u64,
        storage_root_identity: KeyAgentStorageRootIdentity,
        storage_leaf: &str,
    ) -> Result<Self, KeyAgentStartupCodecError> {
        Self::from_parts(
            zeroizing_nonce(nonce),
            expected_process_id,
            expected_creation_time,
            storage_root_identity,
            TEST_FLAGS,
            String::from(storage_leaf),
        )
    }

    fn from_parts(
        nonce: Zeroizing<[u8; NONCE_BYTES]>,
        expected_process_id: u32,
        expected_creation_time: u64,
        storage_root_identity: KeyAgentStorageRootIdentity,
        flags: u16,
        storage_leaf: String,
    ) -> Result<Self, KeyAgentStartupCodecError> {
        if nonce.iter().all(|byte| *byte == 0)
            || expected_process_id == 0
            || expected_creation_time == 0
            || !request_leaf_is_valid(flags, &storage_leaf)
        {
            return Err(KeyAgentStartupCodecError::InvalidRequest);
        }
        Ok(Self {
            nonce,
            expected_process_id,
            expected_creation_time,
            storage_root_identity,
            storage_leaf,
        })
    }

    /// Encodes this validated request into one zeroizing fixed frame.
    pub(crate) fn encode(&self) -> Result<KeyAgentStartupRequestFrame, KeyAgentStartupCodecError> {
        let leaf_length = u16::try_from(self.storage_leaf.len())
            .map_err(|_| KeyAgentStartupCodecError::InvalidRequest)?;
        let mut leaf_field = [0_u8; STORAGE_LEAF_BYTES];
        let leaf_target = leaf_field
            .get_mut(..self.storage_leaf.len())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        for (target, source) in leaf_target
            .iter_mut()
            .zip(self.storage_leaf.as_bytes().iter())
        {
            *target = *source;
        }

        let mut frame = FrameBuilder::<KEY_AGENT_STARTUP_REQUEST_BYTES>::new();
        frame
            .push(&REQUEST_MAGIC)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&STARTUP_VERSION.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&request_flags_for_leaf(&self.storage_leaf)?.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&188_u32.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(self.nonce.as_slice())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&self.expected_process_id.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&0_u32.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&self.expected_creation_time.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&self.storage_root_identity.encode_be())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&leaf_length.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&0_u16.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        frame
            .push(&leaf_field)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;

        let bytes = frame
            .finish()
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        Ok(KeyAgentStartupRequestFrame { bytes })
    }

    /// Decodes exactly one request and rejects both truncation and trailing data.
    pub(crate) fn decode(frame: &[u8]) -> Result<Self, KeyAgentStartupCodecError> {
        if frame.len() != KEY_AGENT_STARTUP_REQUEST_BYTES
            || read_array::<8>(frame, 0) != Some(REQUEST_MAGIC)
            || read_u16(frame, REQUEST_VERSION_OFFSET) != Some(STARTUP_VERSION)
            || read_u32(frame, REQUEST_LENGTH_OFFSET) != Some(188)
            || read_u32(frame, REQUEST_RESERVED_OFFSET) != Some(0)
            || read_u16(frame, REQUEST_LEAF_RESERVED_OFFSET) != Some(0)
        {
            return Err(KeyAgentStartupCodecError::InvalidRequest);
        }

        let flags = read_u16(frame, REQUEST_FLAGS_OFFSET)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        let expected_process_id = read_u32(frame, REQUEST_PROCESS_ID_OFFSET)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        let expected_creation_time = read_u64(frame, REQUEST_CREATION_TIME_OFFSET)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        let encoded_identity =
            read_array::<STORAGE_IDENTITY_BYTES>(frame, REQUEST_STORAGE_IDENTITY_OFFSET)
                .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        let storage_root_identity = KeyAgentStorageRootIdentity::decode_be(encoded_identity)
            .map_err(|_| KeyAgentStartupCodecError::InvalidRequest)?;

        let leaf_length = usize::from(
            read_u16(frame, REQUEST_LEAF_LENGTH_OFFSET)
                .ok_or(KeyAgentStartupCodecError::InvalidRequest)?,
        );
        if leaf_length > STORAGE_LEAF_BYTES {
            return Err(KeyAgentStartupCodecError::InvalidRequest);
        }
        let leaf_end = REQUEST_LEAF_OFFSET
            .checked_add(leaf_length)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        let leaf_bytes = frame
            .get(REQUEST_LEAF_OFFSET..leaf_end)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        let padding = frame
            .get(leaf_end..KEY_AGENT_STARTUP_REQUEST_BYTES)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(KeyAgentStartupCodecError::InvalidRequest);
        }
        let storage_leaf = core::str::from_utf8(leaf_bytes)
            .map_err(|_| KeyAgentStartupCodecError::InvalidRequest)?;
        if !storage_leaf.is_ascii() || !request_leaf_is_valid(flags, storage_leaf) {
            return Err(KeyAgentStartupCodecError::InvalidRequest);
        }

        let nonce_bytes = frame
            .get(REQUEST_NONCE_OFFSET..REQUEST_NONCE_OFFSET + NONCE_BYTES)
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        let mut nonce = Zeroizing::new([0_u8; NONCE_BYTES]);
        nonce.copy_from_slice(nonce_bytes);
        Self::from_parts(
            nonce,
            expected_process_id,
            expected_creation_time,
            storage_root_identity,
            flags,
            String::from(storage_leaf),
        )
    }

    /// Returns the one-attempt startup nonce.
    pub(crate) fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// Returns the supervisor-observed process identifier.
    pub(crate) const fn expected_process_id(&self) -> u32 {
        self.expected_process_id
    }

    /// Returns the supervisor-observed process creation `FILETIME`.
    pub(crate) const fn expected_creation_time(&self) -> u64 {
        self.expected_creation_time
    }

    /// Returns the supervisor-held storage-root identity evidence.
    pub(crate) const fn storage_root_identity(&self) -> KeyAgentStorageRootIdentity {
        self.storage_root_identity
    }

    /// Returns the exact validated ASCII storage leaf.
    pub(crate) fn storage_leaf(&self) -> &str {
        &self.storage_leaf
    }

    /// Reports whether this validated request uses the test-only leaf grammar.
    #[cfg(test)]
    pub(crate) fn is_test_mode(&self) -> bool {
        is_exact_test_storage_leaf(&self.storage_leaf)
    }
}

impl fmt::Debug for KeyAgentStartupRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentStartupRequest([REDACTED])")
    }
}

/// A strictly validated successful Key Agent startup response.
#[must_use = "a validated startup response must be consumed or explicitly dropped"]
pub(crate) struct KeyAgentStartupResponse {
    echoed_nonce: Zeroizing<[u8; NONCE_BYTES]>,
    actual_process_id: u32,
    actual_creation_time: u64,
    storage_root_identity: KeyAgentStorageRootIdentity,
}

impl KeyAgentStartupResponse {
    /// Constructs a success response only after exact request-field validation.
    ///
    /// The child must write nothing when any actual value differs from the
    /// request. The parent must still independently compare the decoded reply.
    pub(crate) fn from_validated_request(
        request: &KeyAgentStartupRequest,
        actual_process_id: u32,
        actual_creation_time: u64,
        storage_root_identity: KeyAgentStorageRootIdentity,
    ) -> Result<Self, KeyAgentStartupCodecError> {
        if actual_process_id != request.expected_process_id
            || actual_creation_time != request.expected_creation_time
            || storage_root_identity != request.storage_root_identity
        {
            return Err(KeyAgentStartupCodecError::InvalidResponse);
        }
        Self::from_parts(
            zeroizing_nonce(request.nonce()),
            actual_process_id,
            actual_creation_time,
            storage_root_identity,
        )
    }

    fn from_parts(
        echoed_nonce: Zeroizing<[u8; NONCE_BYTES]>,
        actual_process_id: u32,
        actual_creation_time: u64,
        storage_root_identity: KeyAgentStorageRootIdentity,
    ) -> Result<Self, KeyAgentStartupCodecError> {
        if echoed_nonce.iter().all(|byte| *byte == 0)
            || actual_process_id == 0
            || actual_creation_time == 0
        {
            return Err(KeyAgentStartupCodecError::InvalidResponse);
        }
        Ok(Self {
            echoed_nonce,
            actual_process_id,
            actual_creation_time,
            storage_root_identity,
        })
    }

    /// Encodes this validated response into one zeroizing fixed frame.
    pub(crate) fn encode(&self) -> Result<KeyAgentStartupResponseFrame, KeyAgentStartupCodecError> {
        let mut frame = FrameBuilder::<KEY_AGENT_STARTUP_RESPONSE_BYTES>::new();
        frame
            .push(&RESPONSE_MAGIC)
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        frame
            .push(&STARTUP_VERSION.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        frame
            .push(&SUCCESS_STATUS.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        frame
            .push(&88_u32.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        frame
            .push(self.echoed_nonce.as_slice())
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        frame
            .push(&self.actual_process_id.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        frame
            .push(&0_u32.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        frame
            .push(&self.actual_creation_time.to_be_bytes())
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        frame
            .push(&self.storage_root_identity.encode_be())
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;

        let bytes = frame
            .finish()
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        Ok(KeyAgentStartupResponseFrame { bytes })
    }

    /// Decodes exactly one response and rejects truncation and trailing data.
    pub(crate) fn decode(frame: &[u8]) -> Result<Self, KeyAgentStartupCodecError> {
        if frame.len() != KEY_AGENT_STARTUP_RESPONSE_BYTES
            || read_array::<8>(frame, 0) != Some(RESPONSE_MAGIC)
            || read_u16(frame, RESPONSE_VERSION_OFFSET) != Some(STARTUP_VERSION)
            || read_u16(frame, RESPONSE_STATUS_OFFSET) != Some(SUCCESS_STATUS)
            || read_u32(frame, RESPONSE_LENGTH_OFFSET) != Some(88)
            || read_u32(frame, RESPONSE_RESERVED_OFFSET) != Some(0)
        {
            return Err(KeyAgentStartupCodecError::InvalidResponse);
        }

        let actual_process_id = read_u32(frame, RESPONSE_PROCESS_ID_OFFSET)
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        let actual_creation_time = read_u64(frame, RESPONSE_CREATION_TIME_OFFSET)
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        let encoded_identity =
            read_array::<STORAGE_IDENTITY_BYTES>(frame, RESPONSE_STORAGE_IDENTITY_OFFSET)
                .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        let storage_root_identity = KeyAgentStorageRootIdentity::decode_be(encoded_identity)
            .map_err(|_| KeyAgentStartupCodecError::InvalidResponse)?;
        let echoed_nonce_bytes = frame
            .get(RESPONSE_NONCE_OFFSET..RESPONSE_NONCE_OFFSET + NONCE_BYTES)
            .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
        let mut echoed_nonce = Zeroizing::new([0_u8; NONCE_BYTES]);
        echoed_nonce.copy_from_slice(echoed_nonce_bytes);

        Self::from_parts(
            echoed_nonce,
            actual_process_id,
            actual_creation_time,
            storage_root_identity,
        )
    }

    /// Returns the exact nonce echoed from the validated request.
    pub(crate) fn echoed_nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.echoed_nonce
    }

    /// Returns the child-observed process identifier.
    pub(crate) const fn actual_process_id(&self) -> u32 {
        self.actual_process_id
    }

    /// Returns the child-observed process creation `FILETIME`.
    pub(crate) const fn actual_creation_time(&self) -> u64 {
        self.actual_creation_time
    }

    /// Returns the child-opened storage-root identity evidence.
    pub(crate) const fn storage_root_identity(&self) -> KeyAgentStorageRootIdentity {
        self.storage_root_identity
    }
}

impl fmt::Debug for KeyAgentStartupResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentStartupResponse([REDACTED])")
    }
}

fn zeroizing_nonce(nonce: &[u8; NONCE_BYTES]) -> Zeroizing<[u8; NONCE_BYTES]> {
    let mut owned = Zeroizing::new([0_u8; NONCE_BYTES]);
    owned.copy_from_slice(nonce);
    owned
}

fn request_flags_for_leaf(storage_leaf: &str) -> Result<u16, KeyAgentStartupCodecError> {
    if storage_leaf == PRODUCTION_STORAGE_LEAF {
        return Ok(PRODUCTION_FLAGS);
    }
    #[cfg(test)]
    if is_exact_test_storage_leaf(storage_leaf) {
        return Ok(TEST_FLAGS);
    }
    Err(KeyAgentStartupCodecError::InvalidRequest)
}

fn request_leaf_is_valid(flags: u16, storage_leaf: &str) -> bool {
    if !storage_leaf.is_ascii() {
        return false;
    }
    if flags == PRODUCTION_FLAGS {
        return storage_leaf == PRODUCTION_STORAGE_LEAF;
    }
    #[cfg(test)]
    if flags == TEST_FLAGS {
        return is_exact_test_storage_leaf(storage_leaf);
    }
    false
}

#[cfg(test)]
fn is_exact_test_storage_leaf(storage_leaf: &str) -> bool {
    let Some(suffix) = storage_leaf.strip_prefix(TEST_STORAGE_LEAF_PREFIX) else {
        return false;
    };
    suffix.len() == TEST_STORAGE_LEAF_SUFFIX_BYTES
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct FrameBuilder<const N: usize> {
    bytes: Zeroizing<[u8; N]>,
    cursor: usize,
}

impl<const N: usize> FrameBuilder<N> {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0_u8; N]),
            cursor: 0,
        }
    }

    fn push(&mut self, field: &[u8]) -> Option<()> {
        let end = self.cursor.checked_add(field.len())?;
        let destination = self.bytes.get_mut(self.cursor..end)?;
        if destination.len() != field.len() {
            return None;
        }
        for (target, source) in destination.iter_mut().zip(field.iter()) {
            *target = *source;
        }
        self.cursor = end;
        Some(())
    }

    fn finish(self) -> Option<Zeroizing<[u8; N]>> {
        (self.cursor == N).then_some(self.bytes)
    }
}

fn read_array<const N: usize>(frame: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    frame.get(offset..end)?.try_into().ok()
}

fn read_u16(frame: &[u8], offset: usize) -> Option<u16> {
    read_array::<2>(frame, offset).map(u16::from_be_bytes)
}

fn read_u32(frame: &[u8], offset: usize) -> Option<u32> {
    read_array::<4>(frame, offset).map(u32::from_be_bytes)
}

fn read_u64(frame: &[u8], offset: usize) -> Option<u64> {
    read_array::<8>(frame, offset).map(u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NONCE: [u8; NONCE_BYTES] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const TEST_PROCESS_ID: u32 = 0x4142_4344;
    const TEST_CREATION_TIME: u64 = 0x5152_5354_5556_5758;
    const TEST_IDENTITY: [u8; STORAGE_IDENTITY_BYTES] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
        0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];
    const VALID_TEST_LEAF: &str =
        "YourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcdef";

    fn test_identity() -> Result<KeyAgentStorageRootIdentity, KeyAgentStartupCodecError> {
        KeyAgentStorageRootIdentity::decode_be(TEST_IDENTITY)
            .map_err(|_| KeyAgentStartupCodecError::InvalidRequest)
    }

    fn production_request() -> Result<KeyAgentStartupRequest, KeyAgentStartupCodecError> {
        KeyAgentStartupRequest::new(
            &TEST_NONCE,
            TEST_PROCESS_ID,
            TEST_CREATION_TIME,
            test_identity()?,
        )
    }

    fn production_response(
        request: &KeyAgentStartupRequest,
    ) -> Result<KeyAgentStartupResponse, KeyAgentStartupCodecError> {
        KeyAgentStartupResponse::from_validated_request(
            request,
            TEST_PROCESS_ID,
            TEST_CREATION_TIME,
            test_identity()?,
        )
    }

    fn overwrite(frame: &mut [u8], offset: usize, replacement: &[u8]) -> bool {
        let Some(end) = offset.checked_add(replacement.len()) else {
            return false;
        };
        let Some(destination) = frame.get_mut(offset..end) else {
            return false;
        };
        if destination.len() != replacement.len() {
            return false;
        }
        for (target, source) in destination.iter_mut().zip(replacement.iter()) {
            *target = *source;
        }
        true
    }

    fn request_mutation(
        frame: &KeyAgentStartupRequestFrame,
        offset: usize,
        replacement: &[u8],
    ) -> Zeroizing<[u8; KEY_AGENT_STARTUP_REQUEST_BYTES]> {
        let mut mutated = Zeroizing::new(*frame.as_bytes());
        assert!(overwrite(mutated.as_mut(), offset, replacement));
        mutated
    }

    fn response_mutation(
        frame: &KeyAgentStartupResponseFrame,
        offset: usize,
        replacement: &[u8],
    ) -> Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]> {
        let mut mutated = Zeroizing::new(*frame.as_bytes());
        assert!(overwrite(mutated.as_mut(), offset, replacement));
        mutated
    }

    fn set_request_leaf(frame: &mut [u8], flags: u16, leaf: &[u8]) -> bool {
        let Ok(leaf_length) = u16::try_from(leaf.len()) else {
            return false;
        };
        if leaf.len() > STORAGE_LEAF_BYTES
            || !overwrite(frame, REQUEST_FLAGS_OFFSET, &flags.to_be_bytes())
            || !overwrite(
                frame,
                REQUEST_LEAF_LENGTH_OFFSET,
                &leaf_length.to_be_bytes(),
            )
        {
            return false;
        }
        let Some(leaf_field) = frame
            .get_mut(REQUEST_LEAF_OFFSET..REQUEST_LEAF_OFFSET.saturating_add(STORAGE_LEAF_BYTES))
        else {
            return false;
        };
        leaf_field.fill(0);
        let Some(destination) = leaf_field.get_mut(..leaf.len()) else {
            return false;
        };
        for (target, source) in destination.iter_mut().zip(leaf.iter()) {
            *target = *source;
        }
        true
    }

    fn request_decode_is_invalid(frame: &[u8]) -> bool {
        matches!(
            KeyAgentStartupRequest::decode(frame),
            Err(KeyAgentStartupCodecError::InvalidRequest)
        )
    }

    fn response_decode_is_invalid(frame: &[u8]) -> bool {
        matches!(
            KeyAgentStartupResponse::decode(frame),
            Err(KeyAgentStartupCodecError::InvalidResponse)
        )
    }

    #[test]
    fn request_golden_offsets_and_round_trip() -> Result<(), KeyAgentStartupCodecError> {
        let request = production_request()?;
        let frame = request.encode()?;
        let bytes = frame.as_bytes();

        assert_eq!(bytes.len(), KEY_AGENT_STARTUP_REQUEST_BYTES);
        assert_eq!(read_array::<8>(bytes, 0), Some(REQUEST_MAGIC));
        assert_eq!(read_u16(bytes, REQUEST_VERSION_OFFSET), Some(1));
        assert_eq!(read_u16(bytes, REQUEST_FLAGS_OFFSET), Some(0));
        assert_eq!(read_u32(bytes, REQUEST_LENGTH_OFFSET), Some(188));
        assert_eq!(
            read_array::<NONCE_BYTES>(bytes, REQUEST_NONCE_OFFSET),
            Some(TEST_NONCE)
        );
        assert_eq!(
            read_u32(bytes, REQUEST_PROCESS_ID_OFFSET),
            Some(TEST_PROCESS_ID)
        );
        assert_eq!(read_u32(bytes, REQUEST_RESERVED_OFFSET), Some(0));
        assert_eq!(
            read_u64(bytes, REQUEST_CREATION_TIME_OFFSET),
            Some(TEST_CREATION_TIME)
        );
        assert_eq!(
            read_array::<STORAGE_IDENTITY_BYTES>(bytes, REQUEST_STORAGE_IDENTITY_OFFSET),
            Some(TEST_IDENTITY)
        );
        assert_eq!(
            read_u16(bytes, REQUEST_LEAF_LENGTH_OFFSET),
            u16::try_from(PRODUCTION_STORAGE_LEAF.len()).ok()
        );
        assert_eq!(read_u16(bytes, REQUEST_LEAF_RESERVED_OFFSET), Some(0));
        let leaf_end = REQUEST_LEAF_OFFSET
            .checked_add(PRODUCTION_STORAGE_LEAF.len())
            .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
        assert_eq!(
            bytes.get(REQUEST_LEAF_OFFSET..leaf_end),
            Some(PRODUCTION_STORAGE_LEAF.as_bytes())
        );
        assert!(
            bytes
                .get(leaf_end..KEY_AGENT_STARTUP_REQUEST_BYTES)
                .is_some_and(|padding| padding.iter().all(|byte| *byte == 0))
        );

        let decoded = KeyAgentStartupRequest::decode(frame.as_ref())?;
        assert_eq!(decoded.nonce(), &TEST_NONCE);
        assert_eq!(decoded.expected_process_id(), TEST_PROCESS_ID);
        assert_eq!(decoded.expected_creation_time(), TEST_CREATION_TIME);
        assert_eq!(decoded.storage_root_identity().encode_be(), TEST_IDENTITY);
        assert_eq!(decoded.storage_leaf(), PRODUCTION_STORAGE_LEAF);
        Ok(())
    }

    #[test]
    fn response_golden_offsets_and_round_trip() -> Result<(), KeyAgentStartupCodecError> {
        let request = production_request()?;
        let response = production_response(&request)?;
        let frame = response.encode()?;
        let bytes = frame.as_bytes();

        assert_eq!(bytes.len(), KEY_AGENT_STARTUP_RESPONSE_BYTES);
        assert_eq!(read_array::<8>(bytes, 0), Some(RESPONSE_MAGIC));
        assert_eq!(read_u16(bytes, RESPONSE_VERSION_OFFSET), Some(1));
        assert_eq!(read_u16(bytes, RESPONSE_STATUS_OFFSET), Some(0));
        assert_eq!(read_u32(bytes, RESPONSE_LENGTH_OFFSET), Some(88));
        assert_eq!(
            read_array::<NONCE_BYTES>(bytes, RESPONSE_NONCE_OFFSET),
            Some(TEST_NONCE)
        );
        assert_eq!(
            read_u32(bytes, RESPONSE_PROCESS_ID_OFFSET),
            Some(TEST_PROCESS_ID)
        );
        assert_eq!(read_u32(bytes, RESPONSE_RESERVED_OFFSET), Some(0));
        assert_eq!(
            read_u64(bytes, RESPONSE_CREATION_TIME_OFFSET),
            Some(TEST_CREATION_TIME)
        );
        assert_eq!(
            read_array::<STORAGE_IDENTITY_BYTES>(bytes, RESPONSE_STORAGE_IDENTITY_OFFSET),
            Some(TEST_IDENTITY)
        );

        let decoded = KeyAgentStartupResponse::decode(frame.as_ref())?;
        assert_eq!(decoded.echoed_nonce(), &TEST_NONCE);
        assert_eq!(decoded.actual_process_id(), TEST_PROCESS_ID);
        assert_eq!(decoded.actual_creation_time(), TEST_CREATION_TIME);
        assert_eq!(decoded.storage_root_identity().encode_be(), TEST_IDENTITY);
        Ok(())
    }

    #[test]
    fn request_rejects_every_truncation_and_trailing_byte() -> Result<(), KeyAgentStartupCodecError>
    {
        let frame = production_request()?.encode()?;
        for length in 0..KEY_AGENT_STARTUP_REQUEST_BYTES {
            let prefix = frame
                .as_ref()
                .get(..length)
                .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
            assert!(request_decode_is_invalid(prefix));
        }
        let mut trailing = Zeroizing::new(frame.as_ref().to_vec());
        trailing.push(0);
        assert!(request_decode_is_invalid(trailing.as_slice()));
        Ok(())
    }

    #[test]
    fn response_rejects_every_truncation_and_trailing_byte() -> Result<(), KeyAgentStartupCodecError>
    {
        let request = production_request()?;
        let frame = production_response(&request)?.encode()?;
        for length in 0..KEY_AGENT_STARTUP_RESPONSE_BYTES {
            let prefix = frame
                .as_ref()
                .get(..length)
                .ok_or(KeyAgentStartupCodecError::InvalidResponse)?;
            assert!(response_decode_is_invalid(prefix));
        }
        let mut trailing = Zeroizing::new(frame.as_ref().to_vec());
        trailing.push(0);
        assert!(response_decode_is_invalid(trailing.as_slice()));
        Ok(())
    }

    #[test]
    fn request_rejects_header_and_reserved_mutations() -> Result<(), KeyAgentStartupCodecError> {
        let frame = production_request()?.encode()?;
        for (offset, replacement) in [
            (0, [b'X', 0, 0, 0]),
            (REQUEST_VERSION_OFFSET, [0, 2, 0, 0]),
            (REQUEST_FLAGS_OFFSET, [0, 2, 0, 0]),
            (REQUEST_LENGTH_OFFSET, 189_u32.to_be_bytes()),
            (REQUEST_RESERVED_OFFSET, 1_u32.to_be_bytes()),
        ] {
            let replacement_length = if offset == 0 {
                1
            } else if matches!(offset, REQUEST_VERSION_OFFSET | REQUEST_FLAGS_OFFSET) {
                2
            } else {
                4
            };
            let replacement = replacement
                .get(..replacement_length)
                .ok_or(KeyAgentStartupCodecError::InvalidRequest)?;
            let mutated = request_mutation(&frame, offset, replacement);
            assert!(request_decode_is_invalid(mutated.as_slice()));
        }
        let mutated = request_mutation(&frame, REQUEST_LEAF_RESERVED_OFFSET, &[0, 1]);
        assert!(request_decode_is_invalid(mutated.as_slice()));
        Ok(())
    }

    #[test]
    fn request_rejects_zero_common_fields_and_identity_sentinels()
    -> Result<(), KeyAgentStartupCodecError> {
        let frame = production_request()?.encode()?;
        for (offset, replacement) in [
            (REQUEST_NONCE_OFFSET, vec![0_u8; NONCE_BYTES]),
            (REQUEST_PROCESS_ID_OFFSET, vec![0_u8; 4]),
            (REQUEST_CREATION_TIME_OFFSET, vec![0_u8; 8]),
            (REQUEST_STORAGE_IDENTITY_OFFSET, vec![0_u8; 8]),
        ] {
            let mutated = request_mutation(&frame, offset, &replacement);
            assert!(request_decode_is_invalid(mutated.as_slice()));
        }

        let zero_id = request_mutation(&frame, REQUEST_STORAGE_IDENTITY_OFFSET + 8, &[0_u8; 16]);
        assert!(request_decode_is_invalid(zero_id.as_slice()));
        let maximum_id =
            request_mutation(&frame, REQUEST_STORAGE_IDENTITY_OFFSET + 8, &[u8::MAX; 16]);
        assert!(request_decode_is_invalid(maximum_id.as_slice()));

        assert!(matches!(
            KeyAgentStartupRequest::new(
                &[0_u8; NONCE_BYTES],
                TEST_PROCESS_ID,
                TEST_CREATION_TIME,
                test_identity()?
            ),
            Err(KeyAgentStartupCodecError::InvalidRequest)
        ));
        assert!(matches!(
            KeyAgentStartupRequest::new(&TEST_NONCE, 0, TEST_CREATION_TIME, test_identity()?),
            Err(KeyAgentStartupCodecError::InvalidRequest)
        ));
        assert!(matches!(
            KeyAgentStartupRequest::new(&TEST_NONCE, TEST_PROCESS_ID, 0, test_identity()?),
            Err(KeyAgentStartupCodecError::InvalidRequest)
        ));
        Ok(())
    }

    #[test]
    fn production_and_test_leaf_grammars_are_exact() -> Result<(), KeyAgentStartupCodecError> {
        let identity = test_identity()?;
        let test_request = KeyAgentStartupRequest::new_for_test(
            &TEST_NONCE,
            TEST_PROCESS_ID,
            TEST_CREATION_TIME,
            identity,
            VALID_TEST_LEAF,
        )?;
        let test_frame = test_request.encode()?;
        assert_eq!(read_u16(test_frame.as_ref(), REQUEST_FLAGS_OFFSET), Some(1));
        let decoded = KeyAgentStartupRequest::decode(test_frame.as_ref())?;
        assert_eq!(decoded.storage_leaf(), VALID_TEST_LEAF);
        assert!(decoded.is_test_mode());

        let production = production_request()?;
        assert!(!production.is_test_mode());

        for rejected in [
            PRODUCTION_STORAGE_LEAF,
            "YourWallet.KeyAgent.Storage.Test.",
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcde",
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcdef0",
            "YourWallet.KeyAgent.Storage.Test.0123456789ABCDEF0123456789ABCDEF",
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcdeg",
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef/123456789abcdef",
            "yourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcdef",
        ] {
            assert!(matches!(
                KeyAgentStartupRequest::new_for_test(
                    &TEST_NONCE,
                    TEST_PROCESS_ID,
                    TEST_CREATION_TIME,
                    identity,
                    rejected,
                ),
                Err(KeyAgentStartupCodecError::InvalidRequest)
            ));
        }

        let production_frame = production_request()?.encode()?;
        let mut wrong_flag = Zeroizing::new(*production_frame.as_bytes());
        assert!(overwrite(
            wrong_flag.as_mut(),
            REQUEST_FLAGS_OFFSET,
            &TEST_FLAGS.to_be_bytes(),
        ));
        assert!(request_decode_is_invalid(wrong_flag.as_slice()));

        let mut wrong_leaf = Zeroizing::new(*production_frame.as_bytes());
        assert!(set_request_leaf(
            wrong_leaf.as_mut(),
            PRODUCTION_FLAGS,
            VALID_TEST_LEAF.as_bytes(),
        ));
        assert!(request_decode_is_invalid(wrong_leaf.as_slice()));

        let mut non_ascii = Zeroizing::new(*production_frame.as_bytes());
        assert!(overwrite(non_ascii.as_mut(), REQUEST_LEAF_OFFSET, &[0x80],));
        assert!(request_decode_is_invalid(non_ascii.as_slice()));

        let nonzero_padding =
            request_mutation(&production_frame, KEY_AGENT_STARTUP_REQUEST_BYTES - 1, &[1]);
        assert!(request_decode_is_invalid(nonzero_padding.as_slice()));

        for length in [0_u16, 97_u16, u16::MAX] {
            let mutated = request_mutation(
                &production_frame,
                REQUEST_LEAF_LENGTH_OFFSET,
                &length.to_be_bytes(),
            );
            assert!(request_decode_is_invalid(mutated.as_slice()));
        }
        Ok(())
    }

    #[test]
    fn response_constructor_requires_exact_request_bindings()
    -> Result<(), KeyAgentStartupCodecError> {
        let request = production_request()?;
        let identity = test_identity()?;
        assert!(matches!(
            KeyAgentStartupResponse::from_validated_request(
                &request,
                TEST_PROCESS_ID.wrapping_add(1),
                TEST_CREATION_TIME,
                identity,
            ),
            Err(KeyAgentStartupCodecError::InvalidResponse)
        ));
        assert!(matches!(
            KeyAgentStartupResponse::from_validated_request(
                &request,
                TEST_PROCESS_ID,
                TEST_CREATION_TIME.wrapping_add(1),
                identity,
            ),
            Err(KeyAgentStartupCodecError::InvalidResponse)
        ));
        let different_identity = KeyAgentStorageRootIdentity::decode_be([
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x69, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
            0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        ])
        .map_err(|_| KeyAgentStartupCodecError::InvalidResponse)?;
        assert!(matches!(
            KeyAgentStartupResponse::from_validated_request(
                &request,
                TEST_PROCESS_ID,
                TEST_CREATION_TIME,
                different_identity,
            ),
            Err(KeyAgentStartupCodecError::InvalidResponse)
        ));
        Ok(())
    }

    #[test]
    fn response_rejects_every_header_and_value_mutation() -> Result<(), KeyAgentStartupCodecError> {
        let request = production_request()?;
        let frame = production_response(&request)?.encode()?;

        for (offset, replacement) in [
            (0, vec![b'X']),
            (RESPONSE_VERSION_OFFSET, 2_u16.to_be_bytes().to_vec()),
            (RESPONSE_STATUS_OFFSET, 1_u16.to_be_bytes().to_vec()),
            (RESPONSE_LENGTH_OFFSET, 89_u32.to_be_bytes().to_vec()),
            (RESPONSE_NONCE_OFFSET, vec![0_u8; NONCE_BYTES]),
            (RESPONSE_PROCESS_ID_OFFSET, vec![0_u8; 4]),
            (RESPONSE_RESERVED_OFFSET, 1_u32.to_be_bytes().to_vec()),
            (RESPONSE_CREATION_TIME_OFFSET, vec![0_u8; 8]),
            (RESPONSE_STORAGE_IDENTITY_OFFSET, vec![0_u8; 8]),
        ] {
            let mutated = response_mutation(&frame, offset, &replacement);
            assert!(response_decode_is_invalid(mutated.as_slice()));
        }

        let zero_id = response_mutation(&frame, RESPONSE_STORAGE_IDENTITY_OFFSET + 8, &[0_u8; 16]);
        assert!(response_decode_is_invalid(zero_id.as_slice()));
        let maximum_id =
            response_mutation(&frame, RESPONSE_STORAGE_IDENTITY_OFFSET + 8, &[u8::MAX; 16]);
        assert!(response_decode_is_invalid(maximum_id.as_slice()));
        Ok(())
    }

    #[test]
    fn debug_errors_and_zeroizing_ownership_are_stable() -> Result<(), KeyAgentStartupCodecError> {
        let request = production_request()?;
        let request_frame = request.encode()?;
        let response = production_response(&request)?;
        let response_frame = response.encode()?;

        assert_eq!(format!("{request:?}"), "KeyAgentStartupRequest([REDACTED])");
        assert_eq!(
            format!("{request_frame:?}"),
            "KeyAgentStartupRequestFrame([REDACTED])"
        );
        assert_eq!(
            format!("{response:?}"),
            "KeyAgentStartupResponse([REDACTED])"
        );
        assert_eq!(
            format!("{response_frame:?}"),
            "KeyAgentStartupResponseFrame([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", KeyAgentStartupCodecError::InvalidRequest),
            "KeyAgentStartupCodecError::InvalidRequest"
        );
        assert_eq!(
            KeyAgentStartupCodecError::InvalidResponse.to_string(),
            "Key Agent startup response is invalid"
        );
        assert!(core::mem::needs_drop::<KeyAgentStartupRequest>());
        assert!(core::mem::needs_drop::<KeyAgentStartupResponse>());
        assert!(core::mem::needs_drop::<KeyAgentStartupRequestFrame>());
        assert!(core::mem::needs_drop::<KeyAgentStartupResponseFrame>());
        Ok(())
    }
}
