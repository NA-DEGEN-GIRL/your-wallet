//! Fixed, transport-neutral wire contract for the Windows Key Agent debugger.
//!
//! Version 1 carries one bootstrap, one frozen-ready acknowledgement, and one
//! commit-or-abort decision. Every frame has an exact length, big-endian
//! integers, zeroed reserved fields, and a trailing CRC32C framing check. The
//! checksum detects corruption; it does not authenticate the transport.

#![forbid(unsafe_code)]

use core::fmt;

/// Exact byte length of a debugger bootstrap frame.
pub const BOOTSTRAP_FRAME_BYTES: usize = 80;
/// Exact byte length of a frozen-ready frame.
pub const READY_FROZEN_FRAME_BYTES: usize = 72;
/// Exact byte length of a debugger decision frame.
pub const DECISION_FRAME_BYTES: usize = 56;

const PROTOCOL_MAGIC: [u8; 8] = *b"YWKDBG01";
const VERSION_V1: u16 = 1;
const FRAME_BOOTSTRAP: u16 = 1;
const FRAME_READY_FROZEN: u16 = 2;
const FRAME_DECISION: u16 = 3;
const DECISION_COMMIT: u16 = 1;
const DECISION_ABORT: u16 = 2;
const HEADER_BYTES: usize = 16;
const NONCE_BYTES: usize = 32;
const CHECKSUM_BYTES: usize = 4;
const CRC32C_POLYNOMIAL_REVERSED: u32 = 0x82F6_3B78;

const HEADER_MAGIC_OFFSET: usize = 0;
const HEADER_VERSION_OFFSET: usize = 8;
const HEADER_KIND_OFFSET: usize = 10;
const HEADER_RESERVED_OFFSET: usize = 12;

const BOOTSTRAP_NONCE_OFFSET: usize = HEADER_BYTES;
const BOOTSTRAP_PARENT_PID_OFFSET: usize = BOOTSTRAP_NONCE_OFFSET + NONCE_BYTES;
const BOOTSTRAP_DEBUGGER_PID_OFFSET: usize = BOOTSTRAP_PARENT_PID_OFFSET + 4;
const BOOTSTRAP_SENTINEL_OFFSET: usize = BOOTSTRAP_DEBUGGER_PID_OFFSET + 4;
const BOOTSTRAP_DEADLINE_OFFSET: usize = BOOTSTRAP_SENTINEL_OFFSET + 8;
const BOOTSTRAP_RESERVED_OFFSET: usize = BOOTSTRAP_DEADLINE_OFFSET + 8;
const BOOTSTRAP_CHECKSUM_OFFSET: usize = BOOTSTRAP_RESERVED_OFFSET + 4;

const READY_NONCE_OFFSET: usize = HEADER_BYTES;
const READY_DEBUGGER_PID_OFFSET: usize = READY_NONCE_OFFSET + NONCE_BYTES;
const READY_PID_RESERVED_OFFSET: usize = READY_DEBUGGER_PID_OFFSET + 4;
const READY_SENTINEL_OFFSET: usize = READY_PID_RESERVED_OFFSET + 4;
const READY_SENTINEL_RESERVED_OFFSET: usize = READY_SENTINEL_OFFSET + 8;
const READY_CHECKSUM_OFFSET: usize = READY_SENTINEL_RESERVED_OFFSET + 4;

const DECISION_NONCE_OFFSET: usize = HEADER_BYTES;
const DECISION_VALUE_OFFSET: usize = DECISION_NONCE_OFFSET + NONCE_BYTES;
const DECISION_RESERVED_OFFSET: usize = DECISION_VALUE_OFFSET + 2;
const DECISION_CHECKSUM_OFFSET: usize = DECISION_RESERVED_OFFSET + 2;

const _: [(); HEADER_BYTES] = [(); HEADER_RESERVED_OFFSET + 4];
const _: [(); BOOTSTRAP_FRAME_BYTES] = [(); BOOTSTRAP_CHECKSUM_OFFSET + CHECKSUM_BYTES];
const _: [(); READY_FROZEN_FRAME_BYTES] = [(); READY_CHECKSUM_OFFSET + CHECKSUM_BYTES];
const _: [(); DECISION_FRAME_BYTES] = [(); DECISION_CHECKSUM_OFFSET + CHECKSUM_BYTES];

/// Fresh nonce binding every frame in one debugger run.
///
/// The all-zero sentinel is invalid. Debug output never exposes nonce bytes.
#[derive(Eq, PartialEq)]
pub struct DebuggerRunNonce([u8; NONCE_BYTES]);

impl DebuggerRunNonce {
    /// Validates a debugger-run nonce.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for the all-zero sentinel.
    pub fn new(bytes: [u8; NONCE_BYTES]) -> Result<Self, WireError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for DebuggerRunNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerRunNonce([REDACTED])")
    }
}

/// Nonzero native handle word meaningful only in its named source process.
///
/// Debug output never exposes the numeric handle value.
#[derive(Eq, PartialEq)]
pub struct RemoteHandleWord(u64);

impl RemoteHandleWord {
    /// Validates a remote handle word.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for the null-handle sentinel.
    pub const fn new(value: u64) -> Result<Self, WireError> {
        if value == 0 {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(value))
    }

    /// Returns the validated numeric handle word.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }
}

impl fmt::Debug for RemoteHandleWord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteHandleWord([REDACTED])")
    }
}

/// Parent-to-debugger bootstrap for one bounded debugger run.
#[derive(Eq, PartialEq)]
pub struct DebuggerBootstrap {
    run_nonce: DebuggerRunNonce,
    parent_process_id: u32,
    debugger_process_id: u32,
    sentinel_handle: RemoteHandleWord,
    absolute_tick_deadline: u64,
}

impl DebuggerBootstrap {
    /// Constructs a canonical bootstrap from validated authority bindings.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when either process identifier or
    /// the absolute tick deadline is zero.
    pub const fn new(
        run_nonce: DebuggerRunNonce,
        parent_process_id: u32,
        debugger_process_id: u32,
        sentinel_handle: RemoteHandleWord,
        absolute_tick_deadline: u64,
    ) -> Result<Self, WireError> {
        if parent_process_id == 0 || debugger_process_id == 0 || absolute_tick_deadline == 0 {
            return Err(WireError::InvalidValue);
        }
        Ok(Self {
            run_nonce,
            parent_process_id,
            debugger_process_id,
            sentinel_handle,
            absolute_tick_deadline,
        })
    }

    /// Returns the debugger-run nonce.
    #[must_use]
    pub const fn run_nonce(&self) -> &DebuggerRunNonce {
        &self.run_nonce
    }

    /// Returns the trusted parent process identifier.
    #[must_use]
    pub const fn parent_process_id(&self) -> u32 {
        self.parent_process_id
    }

    /// Returns the expected debugger process identifier.
    #[must_use]
    pub const fn debugger_process_id(&self) -> u32 {
        self.debugger_process_id
    }

    /// Returns the sentinel handle word installed in the debugger process.
    #[must_use]
    pub const fn sentinel_handle(&self) -> &RemoteHandleWord {
        &self.sentinel_handle
    }

    /// Returns the absolute monotonic-tick deadline.
    #[must_use]
    pub const fn absolute_tick_deadline(&self) -> u64 {
        self.absolute_tick_deadline
    }

    /// Consumes the frame and returns its validated fields without cloning
    /// security-bearing values.
    #[must_use]
    pub fn into_parts(self) -> (DebuggerRunNonce, u32, u32, RemoteHandleWord, u64) {
        (
            self.run_nonce,
            self.parent_process_id,
            self.debugger_process_id,
            self.sentinel_handle,
            self.absolute_tick_deadline,
        )
    }

    /// Encodes this value as the exact canonical version-1 frame.
    #[must_use]
    pub fn encode(&self) -> [u8; BOOTSTRAP_FRAME_BYTES] {
        let mut frame = [0_u8; BOOTSTRAP_FRAME_BYTES];
        encode_header(&mut frame, FRAME_BOOTSTRAP);
        frame[BOOTSTRAP_NONCE_OFFSET..BOOTSTRAP_NONCE_OFFSET + NONCE_BYTES]
            .copy_from_slice(self.run_nonce.as_bytes());
        write_u32(
            &mut frame,
            BOOTSTRAP_PARENT_PID_OFFSET,
            self.parent_process_id,
        );
        write_u32(
            &mut frame,
            BOOTSTRAP_DEBUGGER_PID_OFFSET,
            self.debugger_process_id,
        );
        write_u64(
            &mut frame,
            BOOTSTRAP_SENTINEL_OFFSET,
            self.sentinel_handle.value(),
        );
        write_u64(
            &mut frame,
            BOOTSTRAP_DEADLINE_OFFSET,
            self.absolute_tick_deadline,
        );
        finish_frame(&mut frame, BOOTSTRAP_CHECKSUM_OFFSET);
        frame
    }

    /// Decodes one exact canonical version-1 bootstrap frame.
    ///
    /// # Errors
    ///
    /// Returns a stable [`WireError`] category for malformed input.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, WireError> {
        require_exact_length(bytes, BOOTSTRAP_FRAME_BYTES)?;
        decode_header(bytes, FRAME_BOOTSTRAP)?;
        require_zero_u32(bytes, BOOTSTRAP_RESERVED_OFFSET)?;
        verify_checksum(bytes, BOOTSTRAP_CHECKSUM_OFFSET)?;
        Self::new(
            decode_nonce(bytes, BOOTSTRAP_NONCE_OFFSET)?,
            read_u32(bytes, BOOTSTRAP_PARENT_PID_OFFSET),
            read_u32(bytes, BOOTSTRAP_DEBUGGER_PID_OFFSET),
            RemoteHandleWord::new(read_u64(bytes, BOOTSTRAP_SENTINEL_OFFSET))?,
            read_u64(bytes, BOOTSTRAP_DEADLINE_OFFSET),
        )
    }
}

impl fmt::Debug for DebuggerBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerBootstrap([REDACTED])")
    }
}

/// Debugger-to-parent acknowledgement that the target remains frozen.
#[derive(Eq, PartialEq)]
pub struct DebuggerReadyFrozen {
    run_nonce: DebuggerRunNonce,
    debugger_process_id: u32,
    sentinel_source_handle: RemoteHandleWord,
}

impl DebuggerReadyFrozen {
    /// Constructs a canonical frozen-ready acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the debugger process
    /// identifier is zero.
    pub const fn new(
        run_nonce: DebuggerRunNonce,
        debugger_process_id: u32,
        sentinel_source_handle: RemoteHandleWord,
    ) -> Result<Self, WireError> {
        if debugger_process_id == 0 {
            return Err(WireError::InvalidValue);
        }
        Ok(Self {
            run_nonce,
            debugger_process_id,
            sentinel_source_handle,
        })
    }

    /// Returns the debugger-run nonce.
    #[must_use]
    pub const fn run_nonce(&self) -> &DebuggerRunNonce {
        &self.run_nonce
    }

    /// Returns the debugger process identifier.
    #[must_use]
    pub const fn debugger_process_id(&self) -> u32 {
        self.debugger_process_id
    }

    /// Returns the sentinel source handle word in the debugger process.
    #[must_use]
    pub const fn sentinel_source_handle(&self) -> &RemoteHandleWord {
        &self.sentinel_source_handle
    }

    /// Consumes the frame and returns its validated fields without cloning
    /// security-bearing values.
    #[must_use]
    pub fn into_parts(self) -> (DebuggerRunNonce, u32, RemoteHandleWord) {
        (
            self.run_nonce,
            self.debugger_process_id,
            self.sentinel_source_handle,
        )
    }

    /// Encodes this value as the exact canonical version-1 frame.
    #[must_use]
    pub fn encode(&self) -> [u8; READY_FROZEN_FRAME_BYTES] {
        let mut frame = [0_u8; READY_FROZEN_FRAME_BYTES];
        encode_header(&mut frame, FRAME_READY_FROZEN);
        frame[READY_NONCE_OFFSET..READY_NONCE_OFFSET + NONCE_BYTES]
            .copy_from_slice(self.run_nonce.as_bytes());
        write_u32(
            &mut frame,
            READY_DEBUGGER_PID_OFFSET,
            self.debugger_process_id,
        );
        write_u64(
            &mut frame,
            READY_SENTINEL_OFFSET,
            self.sentinel_source_handle.value(),
        );
        finish_frame(&mut frame, READY_CHECKSUM_OFFSET);
        frame
    }

    /// Decodes one exact canonical version-1 frozen-ready frame.
    ///
    /// # Errors
    ///
    /// Returns a stable [`WireError`] category for malformed input.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, WireError> {
        require_exact_length(bytes, READY_FROZEN_FRAME_BYTES)?;
        decode_header(bytes, FRAME_READY_FROZEN)?;
        require_zero_u32(bytes, READY_PID_RESERVED_OFFSET)?;
        require_zero_u32(bytes, READY_SENTINEL_RESERVED_OFFSET)?;
        verify_checksum(bytes, READY_CHECKSUM_OFFSET)?;
        Self::new(
            decode_nonce(bytes, READY_NONCE_OFFSET)?,
            read_u32(bytes, READY_DEBUGGER_PID_OFFSET),
            RemoteHandleWord::new(read_u64(bytes, READY_SENTINEL_OFFSET))?,
        )
    }
}

impl fmt::Debug for DebuggerReadyFrozen {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerReadyFrozen([REDACTED])")
    }
}

/// Stable process-exit categories shared by the parent and debugger helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DebuggerExitCode {
    /// The bounded debugger protocol completed successfully.
    Success = 0,
    /// The dormant debugger helper was invoked without explicit enablement.
    Disabled = 78,
    /// The parent explicitly aborted the debugger run.
    Aborted = 80,
    /// The bound parent control channel reached end-of-file.
    ParentEof = 81,
    /// The absolute debugger-run deadline elapsed.
    DeadlineElapsed = 82,
    /// A noncanonical or out-of-sequence protocol message was observed.
    ProtocolViolation = 83,
    /// A required operating-system operation failed closed.
    OperatingSystem = 84,
}

impl DebuggerExitCode {
    /// Returns the stable process exit code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// Closed parent decision set accepted by debugger protocol version 1.
#[derive(Eq, PartialEq)]
pub enum DebuggerDecision {
    /// Commit the verified frozen target to its next protocol state.
    Commit,
    /// Abort the debugger run and leave no admitted target behind.
    Abort,
}

impl DebuggerDecision {
    /// Validates the canonical unsigned wire code for a decision.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnknownDecision`] for every unrecognized code.
    pub const fn new(wire_code: u16) -> Result<Self, WireError> {
        match wire_code {
            DECISION_COMMIT => Ok(Self::Commit),
            DECISION_ABORT => Ok(Self::Abort),
            _ => Err(WireError::UnknownDecision),
        }
    }

    /// Returns the canonical unsigned wire code.
    #[must_use]
    pub const fn wire_code(&self) -> u16 {
        match self {
            Self::Commit => DECISION_COMMIT,
            Self::Abort => DECISION_ABORT,
        }
    }
}

impl fmt::Debug for DebuggerDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerDecision([REDACTED])")
    }
}

/// Parent-to-debugger decision bound to one debugger-run nonce.
#[derive(Eq, PartialEq)]
pub struct DebuggerDecisionFrame {
    run_nonce: DebuggerRunNonce,
    decision: DebuggerDecision,
}

impl DebuggerDecisionFrame {
    /// Constructs a canonical debugger decision frame.
    #[must_use]
    pub const fn new(run_nonce: DebuggerRunNonce, decision: DebuggerDecision) -> Self {
        Self {
            run_nonce,
            decision,
        }
    }

    /// Returns the debugger-run nonce.
    #[must_use]
    pub const fn run_nonce(&self) -> &DebuggerRunNonce {
        &self.run_nonce
    }

    /// Returns the commit-or-abort decision.
    #[must_use]
    pub const fn decision(&self) -> &DebuggerDecision {
        &self.decision
    }

    /// Consumes the frame and returns its validated fields without cloning
    /// security-bearing values.
    #[must_use]
    pub fn into_parts(self) -> (DebuggerRunNonce, DebuggerDecision) {
        (self.run_nonce, self.decision)
    }

    /// Encodes this value as the exact canonical version-1 frame.
    #[must_use]
    pub fn encode(&self) -> [u8; DECISION_FRAME_BYTES] {
        let mut frame = [0_u8; DECISION_FRAME_BYTES];
        encode_header(&mut frame, FRAME_DECISION);
        frame[DECISION_NONCE_OFFSET..DECISION_NONCE_OFFSET + NONCE_BYTES]
            .copy_from_slice(self.run_nonce.as_bytes());
        write_u16(&mut frame, DECISION_VALUE_OFFSET, self.decision.wire_code());
        finish_frame(&mut frame, DECISION_CHECKSUM_OFFSET);
        frame
    }

    /// Decodes one exact canonical version-1 decision frame.
    ///
    /// # Errors
    ///
    /// Returns a stable [`WireError`] category for malformed input.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, WireError> {
        require_exact_length(bytes, DECISION_FRAME_BYTES)?;
        decode_header(bytes, FRAME_DECISION)?;
        require_zero_u16(bytes, DECISION_RESERVED_OFFSET)?;
        verify_checksum(bytes, DECISION_CHECKSUM_OFFSET)?;
        Ok(Self::new(
            decode_nonce(bytes, DECISION_NONCE_OFFSET)?,
            DebuggerDecision::new(read_u16(bytes, DECISION_VALUE_OFFSET))?,
        ))
    }
}

impl fmt::Debug for DebuggerDecisionFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerDecisionFrame([REDACTED])")
    }
}

/// Stable, data-free wire failure categories.
#[derive(Debug, Eq, PartialEq)]
pub enum WireError {
    /// The frame ended before its exact required length.
    Truncated,
    /// Bytes followed the exact required frame.
    TrailingData,
    /// The fixed protocol magic did not match.
    InvalidMagic,
    /// The encoded protocol version is not supported.
    UnsupportedVersion,
    /// The frame kind did not match the decoder's expected kind.
    UnexpectedFrameKind,
    /// A reserved field was not exactly zero.
    NonZeroReserved,
    /// A required nonce, process identifier, handle, or deadline was zero.
    InvalidValue,
    /// The CRC32C framing check did not match the exact preceding bytes.
    Integrity,
    /// The decision code is not in the closed version-1 set.
    UnknownDecision,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "debugger wire frame was truncated",
            Self::TrailingData => "debugger wire frame had trailing data",
            Self::InvalidMagic => "debugger wire magic was invalid",
            Self::UnsupportedVersion => "debugger wire version was unsupported",
            Self::UnexpectedFrameKind => "debugger wire frame kind was unexpected",
            Self::NonZeroReserved => "debugger wire reserved field was nonzero",
            Self::InvalidValue => "debugger wire value was invalid",
            Self::Integrity => "debugger wire framing integrity check failed",
            Self::UnknownDecision => "debugger wire decision was unknown",
        })
    }
}

impl std::error::Error for WireError {}

fn encode_header(frame: &mut [u8], frame_kind: u16) {
    frame[HEADER_MAGIC_OFFSET..HEADER_MAGIC_OFFSET + PROTOCOL_MAGIC.len()]
        .copy_from_slice(&PROTOCOL_MAGIC);
    write_u16(frame, HEADER_VERSION_OFFSET, VERSION_V1);
    write_u16(frame, HEADER_KIND_OFFSET, frame_kind);
}

fn decode_header(bytes: &[u8], expected_kind: u16) -> Result<(), WireError> {
    if bytes[HEADER_MAGIC_OFFSET..HEADER_MAGIC_OFFSET + PROTOCOL_MAGIC.len()] != PROTOCOL_MAGIC {
        return Err(WireError::InvalidMagic);
    }
    if read_u16(bytes, HEADER_VERSION_OFFSET) != VERSION_V1 {
        return Err(WireError::UnsupportedVersion);
    }
    if read_u16(bytes, HEADER_KIND_OFFSET) != expected_kind {
        return Err(WireError::UnexpectedFrameKind);
    }
    require_zero_u32(bytes, HEADER_RESERVED_OFFSET)
}

fn require_exact_length(bytes: &[u8], expected: usize) -> Result<(), WireError> {
    match bytes.len().cmp(&expected) {
        core::cmp::Ordering::Less => Err(WireError::Truncated),
        core::cmp::Ordering::Equal => Ok(()),
        core::cmp::Ordering::Greater => Err(WireError::TrailingData),
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

fn decode_nonce(bytes: &[u8], offset: usize) -> Result<DebuggerRunNonce, WireError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    nonce.copy_from_slice(&bytes[offset..offset + NONCE_BYTES]);
    DebuggerRunNonce::new(nonce)
}

fn finish_frame(frame: &mut [u8], checksum_offset: usize) {
    let checksum = crc32c(&frame[..checksum_offset]);
    write_u32(frame, checksum_offset, checksum);
}

fn verify_checksum(bytes: &[u8], checksum_offset: usize) -> Result<(), WireError> {
    if crc32c(&bytes[..checksum_offset]) == read_u32(bytes, checksum_offset) {
        Ok(())
    } else {
        Err(WireError::Integrity)
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
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

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC32C_POLYNOMIAL_REVERSED & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PARENT_PID: u32 = 0x1020_3040;
    const TEST_DEBUGGER_PID: u32 = 0x5060_7080;
    const TEST_HANDLE: u64 = 0x1122_3344_5566_7788;
    const TEST_DEADLINE: u64 = 0x8877_6655_4433_2211;

    fn nonce() -> Result<DebuggerRunNonce, WireError> {
        DebuggerRunNonce::new([0xA5; NONCE_BYTES])
    }

    fn handle() -> Result<RemoteHandleWord, WireError> {
        RemoteHandleWord::new(TEST_HANDLE)
    }

    fn bootstrap() -> Result<DebuggerBootstrap, WireError> {
        DebuggerBootstrap::new(
            nonce()?,
            TEST_PARENT_PID,
            TEST_DEBUGGER_PID,
            handle()?,
            TEST_DEADLINE,
        )
    }

    fn ready() -> Result<DebuggerReadyFrozen, WireError> {
        DebuggerReadyFrozen::new(nonce()?, TEST_DEBUGGER_PID, handle()?)
    }

    fn decision(decision: DebuggerDecision) -> Result<DebuggerDecisionFrame, WireError> {
        Ok(DebuggerDecisionFrame::new(nonce()?, decision))
    }

    fn rewrite_checksum(frame: &mut [u8], checksum_offset: usize) {
        finish_frame(frame, checksum_offset);
    }

    fn assert_all_truncations_and_trailing<const N: usize>(
        frame: &[u8; N],
        decode: fn(&[u8]) -> Result<(), WireError>,
    ) {
        for prefix_length in 0..N {
            assert_eq!(decode(&frame[..prefix_length]), Err(WireError::Truncated));
        }
        let mut trailing = frame.to_vec();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(WireError::TrailingData));
    }

    fn assert_every_single_byte_mutation_is_rejected<const N: usize>(
        frame: &[u8; N],
        decode: fn(&[u8]) -> Result<(), WireError>,
    ) {
        for index in 0..N {
            for replacement in u8::MIN..=u8::MAX {
                if replacement == frame[index] {
                    continue;
                }
                let mut mutated = *frame;
                mutated[index] = replacement;
                assert!(decode(&mutated).is_err());
            }
        }
    }

    fn assert_semantic_header_failures<const N: usize>(
        canonical: &[u8; N],
        checksum_offset: usize,
        expected_kind: u16,
        decode: fn(&[u8]) -> Result<(), WireError>,
    ) {
        let mut wrong_magic = *canonical;
        wrong_magic[HEADER_MAGIC_OFFSET] ^= 1;
        rewrite_checksum(&mut wrong_magic, checksum_offset);
        assert_eq!(decode(&wrong_magic), Err(WireError::InvalidMagic));

        let mut wrong_version = *canonical;
        write_u16(&mut wrong_version, HEADER_VERSION_OFFSET, 2);
        rewrite_checksum(&mut wrong_version, checksum_offset);
        assert_eq!(decode(&wrong_version), Err(WireError::UnsupportedVersion));

        for wrong_kind in [
            FRAME_BOOTSTRAP,
            FRAME_READY_FROZEN,
            FRAME_DECISION,
            u16::MAX,
        ] {
            if wrong_kind == expected_kind {
                continue;
            }
            let mut frame = *canonical;
            write_u16(&mut frame, HEADER_KIND_OFFSET, wrong_kind);
            rewrite_checksum(&mut frame, checksum_offset);
            assert_eq!(decode(&frame), Err(WireError::UnexpectedFrameKind));
        }
    }

    fn decode_bootstrap_unit(bytes: &[u8]) -> Result<(), WireError> {
        DebuggerBootstrap::decode_exact(bytes).map(|_| ())
    }

    fn decode_ready_unit(bytes: &[u8]) -> Result<(), WireError> {
        DebuggerReadyFrozen::decode_exact(bytes).map(|_| ())
    }

    fn decode_decision_unit(bytes: &[u8]) -> Result<(), WireError> {
        DebuggerDecisionFrame::decode_exact(bytes).map(|_| ())
    }

    #[test]
    fn all_frames_round_trip_with_exact_big_endian_layouts() -> Result<(), WireError> {
        let bootstrap = bootstrap()?;
        let bootstrap_frame = bootstrap.encode();
        assert_eq!(bootstrap_frame.len(), BOOTSTRAP_FRAME_BYTES);
        assert_eq!(
            &bootstrap_frame[BOOTSTRAP_PARENT_PID_OFFSET..BOOTSTRAP_PARENT_PID_OFFSET + 4],
            &TEST_PARENT_PID.to_be_bytes()
        );
        assert_eq!(
            &bootstrap_frame[BOOTSTRAP_SENTINEL_OFFSET..BOOTSTRAP_SENTINEL_OFFSET + 8],
            &TEST_HANDLE.to_be_bytes()
        );
        assert_eq!(
            DebuggerBootstrap::decode_exact(&bootstrap_frame)?,
            bootstrap
        );

        let ready = ready()?;
        let ready_frame = ready.encode();
        assert_eq!(ready_frame.len(), READY_FROZEN_FRAME_BYTES);
        assert_eq!(DebuggerReadyFrozen::decode_exact(&ready_frame)?, ready);

        for value in [DebuggerDecision::Commit, DebuggerDecision::Abort] {
            let decision = decision(value)?;
            let frame = decision.encode();
            assert_eq!(frame.len(), DECISION_FRAME_BYTES);
            assert_eq!(DebuggerDecisionFrame::decode_exact(&frame)?, decision);
        }
        Ok(())
    }

    #[test]
    fn field_accessors_return_validated_values() -> Result<(), WireError> {
        let bootstrap = bootstrap()?;
        assert_eq!(bootstrap.run_nonce().as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(bootstrap.parent_process_id(), TEST_PARENT_PID);
        assert_eq!(bootstrap.debugger_process_id(), TEST_DEBUGGER_PID);
        assert_eq!(bootstrap.sentinel_handle().value(), TEST_HANDLE);
        assert_eq!(bootstrap.absolute_tick_deadline(), TEST_DEADLINE);

        let ready = ready()?;
        assert_eq!(ready.run_nonce().as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(ready.debugger_process_id(), TEST_DEBUGGER_PID);
        assert_eq!(ready.sentinel_source_handle().value(), TEST_HANDLE);

        let decision = decision(DebuggerDecision::Commit)?;
        assert_eq!(decision.run_nonce().as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(decision.decision(), &DebuggerDecision::Commit);
        assert_eq!(decision.decision().wire_code(), DECISION_COMMIT);
        Ok(())
    }

    #[test]
    fn consuming_accessors_move_security_values_without_clone_or_copy() -> Result<(), WireError> {
        let (run_nonce, parent_pid, debugger_pid, sentinel, deadline) = bootstrap()?.into_parts();
        assert_eq!(run_nonce.as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(parent_pid, TEST_PARENT_PID);
        assert_eq!(debugger_pid, TEST_DEBUGGER_PID);
        assert_eq!(sentinel.value(), TEST_HANDLE);
        assert_eq!(deadline, TEST_DEADLINE);

        let (run_nonce, debugger_pid, sentinel) = ready()?.into_parts();
        assert_eq!(run_nonce.as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(debugger_pid, TEST_DEBUGGER_PID);
        assert_eq!(sentinel.value(), TEST_HANDLE);

        let (run_nonce, decision) = decision(DebuggerDecision::Abort)?.into_parts();
        assert_eq!(run_nonce.as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(decision, DebuggerDecision::Abort);
        Ok(())
    }

    #[test]
    fn every_prefix_and_trailing_byte_is_rejected() -> Result<(), WireError> {
        assert_all_truncations_and_trailing(&bootstrap()?.encode(), decode_bootstrap_unit);
        assert_all_truncations_and_trailing(&ready()?.encode(), decode_ready_unit);
        assert_all_truncations_and_trailing(
            &decision(DebuggerDecision::Commit)?.encode(),
            decode_decision_unit,
        );
        Ok(())
    }

    #[test]
    fn every_single_byte_mutation_without_checksum_rewrite_is_rejected() -> Result<(), WireError> {
        assert_every_single_byte_mutation_is_rejected(
            &bootstrap()?.encode(),
            decode_bootstrap_unit,
        );
        assert_every_single_byte_mutation_is_rejected(&ready()?.encode(), decode_ready_unit);
        assert_every_single_byte_mutation_is_rejected(
            &decision(DebuggerDecision::Abort)?.encode(),
            decode_decision_unit,
        );
        Ok(())
    }

    #[test]
    fn semantic_header_failures_have_stable_categories() -> Result<(), WireError> {
        assert_semantic_header_failures(
            &bootstrap()?.encode(),
            BOOTSTRAP_CHECKSUM_OFFSET,
            FRAME_BOOTSTRAP,
            decode_bootstrap_unit,
        );
        assert_semantic_header_failures(
            &ready()?.encode(),
            READY_CHECKSUM_OFFSET,
            FRAME_READY_FROZEN,
            decode_ready_unit,
        );
        assert_semantic_header_failures(
            &decision(DebuggerDecision::Commit)?.encode(),
            DECISION_CHECKSUM_OFFSET,
            FRAME_DECISION,
            decode_decision_unit,
        );
        Ok(())
    }

    #[test]
    fn every_reserved_bit_is_rejected_after_checksum_rewrite() -> Result<(), WireError> {
        let cases = vec![
            (
                bootstrap()?.encode().to_vec(),
                BOOTSTRAP_CHECKSUM_OFFSET,
                vec![12..16, 72..76],
            ),
            (
                ready()?.encode().to_vec(),
                READY_CHECKSUM_OFFSET,
                vec![12..16, 52..56, 64..68],
            ),
            (
                decision(DebuggerDecision::Commit)?.encode().to_vec(),
                DECISION_CHECKSUM_OFFSET,
                vec![12..16, 50..52],
            ),
        ];

        for (canonical, checksum_offset, ranges) in cases {
            for range in ranges {
                for offset in range {
                    for bit in 0..8 {
                        let mut mutated = canonical.clone();
                        mutated[offset] = 1_u8 << bit;
                        rewrite_checksum(&mut mutated, checksum_offset);
                        let error = match canonical.len() {
                            BOOTSTRAP_FRAME_BYTES => {
                                DebuggerBootstrap::decode_exact(&mutated).err()
                            }
                            READY_FROZEN_FRAME_BYTES => {
                                DebuggerReadyFrozen::decode_exact(&mutated).err()
                            }
                            DECISION_FRAME_BYTES => {
                                DebuggerDecisionFrame::decode_exact(&mutated).err()
                            }
                            _ => None,
                        };
                        assert_eq!(error, Some(WireError::NonZeroReserved));
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn all_zero_and_numeric_zero_sentinels_are_rejected() -> Result<(), WireError> {
        assert_eq!(
            DebuggerRunNonce::new([0; NONCE_BYTES]),
            Err(WireError::InvalidValue)
        );
        assert_eq!(RemoteHandleWord::new(0), Err(WireError::InvalidValue));
        assert_eq!(
            DebuggerBootstrap::new(nonce()?, 0, TEST_DEBUGGER_PID, handle()?, TEST_DEADLINE),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            DebuggerBootstrap::new(nonce()?, TEST_PARENT_PID, 0, handle()?, TEST_DEADLINE),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            DebuggerBootstrap::new(nonce()?, TEST_PARENT_PID, TEST_DEBUGGER_PID, handle()?, 0),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            DebuggerReadyFrozen::new(nonce()?, 0, handle()?),
            Err(WireError::InvalidValue)
        );

        let mut zero_nonce = bootstrap()?.encode();
        zero_nonce[BOOTSTRAP_NONCE_OFFSET..BOOTSTRAP_NONCE_OFFSET + NONCE_BYTES].fill(0);
        rewrite_checksum(&mut zero_nonce, BOOTSTRAP_CHECKSUM_OFFSET);
        assert_eq!(
            DebuggerBootstrap::decode_exact(&zero_nonce),
            Err(WireError::InvalidValue)
        );

        let mut zero_handle = ready()?.encode();
        zero_handle[READY_SENTINEL_OFFSET..READY_SENTINEL_OFFSET + 8].fill(0);
        rewrite_checksum(&mut zero_handle, READY_CHECKSUM_OFFSET);
        assert_eq!(
            DebuggerReadyFrozen::decode_exact(&zero_handle),
            Err(WireError::InvalidValue)
        );

        for range in [
            BOOTSTRAP_PARENT_PID_OFFSET..BOOTSTRAP_PARENT_PID_OFFSET + 4,
            BOOTSTRAP_DEBUGGER_PID_OFFSET..BOOTSTRAP_DEBUGGER_PID_OFFSET + 4,
            BOOTSTRAP_SENTINEL_OFFSET..BOOTSTRAP_SENTINEL_OFFSET + 8,
            BOOTSTRAP_DEADLINE_OFFSET..BOOTSTRAP_DEADLINE_OFFSET + 8,
        ] {
            let mut frame = bootstrap()?.encode();
            frame[range].fill(0);
            rewrite_checksum(&mut frame, BOOTSTRAP_CHECKSUM_OFFSET);
            assert_eq!(
                DebuggerBootstrap::decode_exact(&frame),
                Err(WireError::InvalidValue)
            );
        }

        for range in [
            READY_NONCE_OFFSET..READY_NONCE_OFFSET + NONCE_BYTES,
            READY_DEBUGGER_PID_OFFSET..READY_DEBUGGER_PID_OFFSET + 4,
            READY_SENTINEL_OFFSET..READY_SENTINEL_OFFSET + 8,
        ] {
            let mut frame = ready()?.encode();
            frame[range].fill(0);
            rewrite_checksum(&mut frame, READY_CHECKSUM_OFFSET);
            assert_eq!(
                DebuggerReadyFrozen::decode_exact(&frame),
                Err(WireError::InvalidValue)
            );
        }

        let mut zero_decision_nonce = decision(DebuggerDecision::Abort)?.encode();
        zero_decision_nonce[DECISION_NONCE_OFFSET..DECISION_NONCE_OFFSET + NONCE_BYTES].fill(0);
        rewrite_checksum(&mut zero_decision_nonce, DECISION_CHECKSUM_OFFSET);
        assert_eq!(
            DebuggerDecisionFrame::decode_exact(&zero_decision_nonce),
            Err(WireError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn cross_kind_decoders_reject_every_other_canonical_frame() -> Result<(), WireError> {
        let bootstrap = bootstrap()?.encode();
        let ready = ready()?.encode();
        let decision = decision(DebuggerDecision::Commit)?.encode();

        assert!(DebuggerBootstrap::decode_exact(&ready).is_err());
        assert!(DebuggerBootstrap::decode_exact(&decision).is_err());
        assert!(DebuggerReadyFrozen::decode_exact(&bootstrap).is_err());
        assert!(DebuggerReadyFrozen::decode_exact(&decision).is_err());
        assert!(DebuggerDecisionFrame::decode_exact(&bootstrap).is_err());
        assert!(DebuggerDecisionFrame::decode_exact(&ready).is_err());
        Ok(())
    }

    #[test]
    fn unknown_decision_and_checksum_mismatch_are_rejected() -> Result<(), WireError> {
        for unknown in [0, 3, u16::MAX] {
            let mut frame = decision(DebuggerDecision::Commit)?.encode();
            write_u16(&mut frame, DECISION_VALUE_OFFSET, unknown);
            rewrite_checksum(&mut frame, DECISION_CHECKSUM_OFFSET);
            assert_eq!(
                DebuggerDecisionFrame::decode_exact(&frame),
                Err(WireError::UnknownDecision)
            );
        }

        let mut corrupt = ready()?.encode();
        corrupt[READY_NONCE_OFFSET] ^= 1;
        assert_eq!(
            DebuggerReadyFrozen::decode_exact(&corrupt),
            Err(WireError::Integrity)
        );
        Ok(())
    }

    #[test]
    fn security_value_debug_output_is_fixed_and_redacted() -> Result<(), WireError> {
        assert_eq!(format!("{:?}", nonce()?), "DebuggerRunNonce([REDACTED])");
        assert_eq!(format!("{:?}", handle()?), "RemoteHandleWord([REDACTED])");
        assert_eq!(
            format!("{:?}", bootstrap()?),
            "DebuggerBootstrap([REDACTED])"
        );
        assert_eq!(format!("{:?}", ready()?), "DebuggerReadyFrozen([REDACTED])");
        assert_eq!(
            format!("{:?}", DebuggerDecision::Commit),
            "DebuggerDecision([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", decision(DebuggerDecision::Abort)?),
            "DebuggerDecisionFrame([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn every_wire_error_display_is_stable_and_data_free() {
        let cases = [
            (WireError::Truncated, "debugger wire frame was truncated"),
            (
                WireError::TrailingData,
                "debugger wire frame had trailing data",
            ),
            (WireError::InvalidMagic, "debugger wire magic was invalid"),
            (
                WireError::UnsupportedVersion,
                "debugger wire version was unsupported",
            ),
            (
                WireError::UnexpectedFrameKind,
                "debugger wire frame kind was unexpected",
            ),
            (
                WireError::NonZeroReserved,
                "debugger wire reserved field was nonzero",
            ),
            (WireError::InvalidValue, "debugger wire value was invalid"),
            (
                WireError::Integrity,
                "debugger wire framing integrity check failed",
            ),
            (
                WireError::UnknownDecision,
                "debugger wire decision was unknown",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn crc32c_matches_the_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn debugger_exit_codes_and_debug_names_are_stable() {
        let cases = [
            (DebuggerExitCode::Success, 0, "Success"),
            (DebuggerExitCode::Disabled, 78, "Disabled"),
            (DebuggerExitCode::Aborted, 80, "Aborted"),
            (DebuggerExitCode::ParentEof, 81, "ParentEof"),
            (DebuggerExitCode::DeadlineElapsed, 82, "DeadlineElapsed"),
            (DebuggerExitCode::ProtocolViolation, 83, "ProtocolViolation"),
            (DebuggerExitCode::OperatingSystem, 84, "OperatingSystem"),
        ];
        for (exit_code, expected_code, expected_debug) in cases {
            assert_eq!(exit_code.code(), expected_code);
            assert_eq!(format!("{exit_code:?}"), expected_debug);
        }
    }
}
