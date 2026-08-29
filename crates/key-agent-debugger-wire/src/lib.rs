//! Fixed, transport-neutral wire contract for the Windows Key Agent debugger.
//!
//! Version 1 carries one bootstrap, one frozen-ready acknowledgement, one
//! frozen-target description, one commit-or-abort decision, and dormant
//! parent-death fixture command/report frames. Every frame has an exact length,
//! big-endian integers, zeroed reserved fields, and a trailing CRC32C framing
//! check. The checksum detects corruption; it does not authenticate transport.

#![forbid(unsafe_code)]

use core::fmt;

/// Exact byte length of a debugger bootstrap frame.
pub const BOOTSTRAP_FRAME_BYTES: usize = 80;
/// Exact byte length of a frozen-ready frame.
pub const READY_FROZEN_FRAME_BYTES: usize = 72;
/// Exact byte length of a frozen-target frame.
pub const TARGET_FROZEN_FRAME_BYTES: usize = 96;
/// Exact byte length of a debugger decision frame.
pub const DECISION_FRAME_BYTES: usize = 56;
/// Exact byte length of a parent-death supervisor command frame.
pub const PARENT_DEATH_COMMAND_FRAME_BYTES: usize = 56;
/// Exact byte length of a parent-death supervisor report frame.
pub const PARENT_DEATH_REPORT_FRAME_BYTES: usize = 96;

const PROTOCOL_MAGIC: [u8; 8] = *b"YWKDBG01";
const VERSION_V1: u16 = 1;
const FRAME_BOOTSTRAP: u16 = 1;
const FRAME_READY_FROZEN: u16 = 2;
const FRAME_DECISION: u16 = 3;
const FRAME_TARGET_FROZEN: u16 = 4;
const FRAME_PARENT_DEATH_COMMAND: u16 = 5;
const FRAME_PARENT_DEATH_REPORT: u16 = 6;
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

const TARGET_NONCE_OFFSET: usize = HEADER_BYTES;
const TARGET_DEBUGGER_PID_OFFSET: usize = TARGET_NONCE_OFFSET + NONCE_BYTES;
const TARGET_PROCESS_PID_OFFSET: usize = TARGET_DEBUGGER_PID_OFFSET + 4;
const TARGET_THREAD_TID_OFFSET: usize = TARGET_PROCESS_PID_OFFSET + 4;
const TARGET_ID_RESERVED_OFFSET: usize = TARGET_THREAD_TID_OFFSET + 4;
const TARGET_PROCESS_HANDLE_OFFSET: usize = TARGET_ID_RESERVED_OFFSET + 4;
const TARGET_THREAD_HANDLE_OFFSET: usize = TARGET_PROCESS_HANDLE_OFFSET + 8;
const TARGET_CREATION_TIME_OFFSET: usize = TARGET_THREAD_HANDLE_OFFSET + 8;
const TARGET_TIME_RESERVED_OFFSET: usize = TARGET_CREATION_TIME_OFFSET + 8;
const TARGET_CHECKSUM_OFFSET: usize = TARGET_TIME_RESERVED_OFFSET + 4;

const DECISION_NONCE_OFFSET: usize = HEADER_BYTES;
const DECISION_VALUE_OFFSET: usize = DECISION_NONCE_OFFSET + NONCE_BYTES;
const DECISION_RESERVED_OFFSET: usize = DECISION_VALUE_OFFSET + 2;
const DECISION_CHECKSUM_OFFSET: usize = DECISION_RESERVED_OFFSET + 2;

const PARENT_DEATH_COMMAND_NONCE_OFFSET: usize = HEADER_BYTES;
const PARENT_DEATH_COMMAND_STAGE_OFFSET: usize = PARENT_DEATH_COMMAND_NONCE_OFFSET + NONCE_BYTES;
const PARENT_DEATH_COMMAND_RESERVED_OFFSET: usize = PARENT_DEATH_COMMAND_STAGE_OFFSET + 2;
const PARENT_DEATH_COMMAND_CHECKSUM_OFFSET: usize = PARENT_DEATH_COMMAND_RESERVED_OFFSET + 2;

const PARENT_DEATH_REPORT_NONCE_OFFSET: usize = HEADER_BYTES;
const PARENT_DEATH_REPORT_STAGE_OFFSET: usize = PARENT_DEATH_REPORT_NONCE_OFFSET + NONCE_BYTES;
const PARENT_DEATH_REPORT_STAGE_RESERVED_OFFSET: usize = PARENT_DEATH_REPORT_STAGE_OFFSET + 2;
const PARENT_DEATH_REPORT_SUPERVISOR_PID_OFFSET: usize =
    PARENT_DEATH_REPORT_STAGE_RESERVED_OFFSET + 2;
const PARENT_DEATH_REPORT_DEBUGGER_PID_OFFSET: usize =
    PARENT_DEATH_REPORT_SUPERVISOR_PID_OFFSET + 4;
const PARENT_DEATH_REPORT_TARGET_PID_OFFSET: usize = PARENT_DEATH_REPORT_DEBUGGER_PID_OFFSET + 4;
const PARENT_DEATH_REPORT_SUPERVISOR_TIME_OFFSET: usize = PARENT_DEATH_REPORT_TARGET_PID_OFFSET + 4;
const PARENT_DEATH_REPORT_DEBUGGER_TIME_OFFSET: usize =
    PARENT_DEATH_REPORT_SUPERVISOR_TIME_OFFSET + 8;
const PARENT_DEATH_REPORT_TARGET_TIME_OFFSET: usize = PARENT_DEATH_REPORT_DEBUGGER_TIME_OFFSET + 8;
const PARENT_DEATH_REPORT_PROOFS_OFFSET: usize = PARENT_DEATH_REPORT_TARGET_TIME_OFFSET + 8;
const PARENT_DEATH_REPORT_CHECKSUM_OFFSET: usize = PARENT_DEATH_REPORT_PROOFS_OFFSET + 4;

const _: [(); HEADER_BYTES] = [(); HEADER_RESERVED_OFFSET + 4];
const _: [(); BOOTSTRAP_FRAME_BYTES] = [(); BOOTSTRAP_CHECKSUM_OFFSET + CHECKSUM_BYTES];
const _: [(); READY_FROZEN_FRAME_BYTES] = [(); READY_CHECKSUM_OFFSET + CHECKSUM_BYTES];
const _: [(); TARGET_FROZEN_FRAME_BYTES] = [(); TARGET_CHECKSUM_OFFSET + CHECKSUM_BYTES];
const _: [(); DECISION_FRAME_BYTES] = [(); DECISION_CHECKSUM_OFFSET + CHECKSUM_BYTES];
const _: [(); PARENT_DEATH_COMMAND_FRAME_BYTES] =
    [(); PARENT_DEATH_COMMAND_CHECKSUM_OFFSET + CHECKSUM_BYTES];
const _: [(); PARENT_DEATH_REPORT_FRAME_BYTES] =
    [(); PARENT_DEATH_REPORT_CHECKSUM_OFFSET + CHECKSUM_BYTES];

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

/// Debugger-to-parent description of one real suspended target.
///
/// The handle words are source-table values in the named debugger process.
/// They grant no authority until the parent pulls independently constrained
/// duplicates from that exact process and revalidates every identity field.
#[derive(Eq, PartialEq)]
pub struct DebuggerTargetFrozen {
    run_nonce: DebuggerRunNonce,
    debugger_process_id: u32,
    target_process_id: u32,
    target_thread_id: u32,
    target_process_source_handle: RemoteHandleWord,
    target_thread_source_handle: RemoteHandleWord,
    target_creation_time: u64,
}

impl DebuggerTargetFrozen {
    /// Constructs a canonical frozen-target description.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for a zero identifier or creation
    /// time, equal debugger/target process identifiers, or equal source words.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        run_nonce: DebuggerRunNonce,
        debugger_process_id: u32,
        target_process_id: u32,
        target_thread_id: u32,
        target_process_source_handle: RemoteHandleWord,
        target_thread_source_handle: RemoteHandleWord,
        target_creation_time: u64,
    ) -> Result<Self, WireError> {
        if debugger_process_id == 0
            || target_process_id == 0
            || target_thread_id == 0
            || target_creation_time == 0
            || debugger_process_id == target_process_id
            || target_process_source_handle.value() == target_thread_source_handle.value()
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self {
            run_nonce,
            debugger_process_id,
            target_process_id,
            target_thread_id,
            target_process_source_handle,
            target_thread_source_handle,
            target_creation_time,
        })
    }

    /// Returns the debugger-run nonce.
    #[must_use]
    pub const fn run_nonce(&self) -> &DebuggerRunNonce {
        &self.run_nonce
    }

    /// Returns the debugger process identifier naming the source table.
    #[must_use]
    pub const fn debugger_process_id(&self) -> u32 {
        self.debugger_process_id
    }

    /// Returns the suspended target process identifier.
    #[must_use]
    pub const fn target_process_id(&self) -> u32 {
        self.target_process_id
    }

    /// Returns the suspended target primary-thread identifier.
    #[must_use]
    pub const fn target_thread_id(&self) -> u32 {
        self.target_thread_id
    }

    /// Returns the target-process source word in the debugger table.
    #[must_use]
    pub const fn target_process_source_handle(&self) -> &RemoteHandleWord {
        &self.target_process_source_handle
    }

    /// Returns the target-thread source word in the debugger table.
    #[must_use]
    pub const fn target_thread_source_handle(&self) -> &RemoteHandleWord {
        &self.target_thread_source_handle
    }

    /// Returns the target process creation `FILETIME` as one 64-bit word.
    #[must_use]
    pub const fn target_creation_time(&self) -> u64 {
        self.target_creation_time
    }

    /// Consumes the frame and returns its validated fields without cloning
    /// security-bearing values.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        DebuggerRunNonce,
        u32,
        u32,
        u32,
        RemoteHandleWord,
        RemoteHandleWord,
        u64,
    ) {
        (
            self.run_nonce,
            self.debugger_process_id,
            self.target_process_id,
            self.target_thread_id,
            self.target_process_source_handle,
            self.target_thread_source_handle,
            self.target_creation_time,
        )
    }

    /// Encodes this value as the exact canonical version-1 frame.
    #[must_use]
    pub fn encode(&self) -> [u8; TARGET_FROZEN_FRAME_BYTES] {
        let mut frame = [0_u8; TARGET_FROZEN_FRAME_BYTES];
        encode_header(&mut frame, FRAME_TARGET_FROZEN);
        frame[TARGET_NONCE_OFFSET..TARGET_NONCE_OFFSET + NONCE_BYTES]
            .copy_from_slice(self.run_nonce.as_bytes());
        write_u32(
            &mut frame,
            TARGET_DEBUGGER_PID_OFFSET,
            self.debugger_process_id,
        );
        write_u32(
            &mut frame,
            TARGET_PROCESS_PID_OFFSET,
            self.target_process_id,
        );
        write_u32(&mut frame, TARGET_THREAD_TID_OFFSET, self.target_thread_id);
        write_u64(
            &mut frame,
            TARGET_PROCESS_HANDLE_OFFSET,
            self.target_process_source_handle.value(),
        );
        write_u64(
            &mut frame,
            TARGET_THREAD_HANDLE_OFFSET,
            self.target_thread_source_handle.value(),
        );
        write_u64(
            &mut frame,
            TARGET_CREATION_TIME_OFFSET,
            self.target_creation_time,
        );
        finish_frame(&mut frame, TARGET_CHECKSUM_OFFSET);
        frame
    }

    /// Decodes one exact canonical version-1 frozen-target frame.
    ///
    /// # Errors
    ///
    /// Returns a stable [`WireError`] category for malformed input.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, WireError> {
        require_exact_length(bytes, TARGET_FROZEN_FRAME_BYTES)?;
        decode_header(bytes, FRAME_TARGET_FROZEN)?;
        require_zero_u32(bytes, TARGET_ID_RESERVED_OFFSET)?;
        require_zero_u32(bytes, TARGET_TIME_RESERVED_OFFSET)?;
        verify_checksum(bytes, TARGET_CHECKSUM_OFFSET)?;
        Self::new(
            decode_nonce(bytes, TARGET_NONCE_OFFSET)?,
            read_u32(bytes, TARGET_DEBUGGER_PID_OFFSET),
            read_u32(bytes, TARGET_PROCESS_PID_OFFSET),
            read_u32(bytes, TARGET_THREAD_TID_OFFSET),
            RemoteHandleWord::new(read_u64(bytes, TARGET_PROCESS_HANDLE_OFFSET))?,
            RemoteHandleWord::new(read_u64(bytes, TARGET_THREAD_HANDLE_OFFSET))?,
            read_u64(bytes, TARGET_CREATION_TIME_OFFSET),
        )
    }
}

impl fmt::Debug for DebuggerTargetFrozen {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerTargetFrozen([REDACTED])")
    }
}

const PARENT_DEATH_PROOF_JOB_SLOT_ABSENT: u32 = 1 << 0;
const PARENT_DEATH_PROOF_DEBUGGER_FLAGS_ZERO: u32 = 1 << 1;
const PARENT_DEATH_PROOF_TARGET_FLAGS_ZERO: u32 = 1 << 2;

/// Exact forced-parent-death checkpoint selected by the dormant fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ParentDeathStage {
    /// The debugger exists but its explicit creation suspend is retained.
    PreReady = 1,
    /// The debugger has frozen and reported one suspended target.
    Ready = 2,
    /// The debugger exited and this implementation retained the target Job.
    PostHandoff = 3,
}

impl ParentDeathStage {
    const fn from_wire(value: u16) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::PreReady),
            2 => Ok(Self::Ready),
            3 => Ok(Self::PostHandoff),
            _ => Err(WireError::InvalidValue),
        }
    }

    const fn requires_target(self) -> bool {
        matches!(self, Self::Ready | Self::PostHandoff)
    }

    const fn required_proofs(self) -> u32 {
        let base = PARENT_DEATH_PROOF_JOB_SLOT_ABSENT | PARENT_DEATH_PROOF_DEBUGGER_FLAGS_ZERO;
        if self.requires_target() {
            base | PARENT_DEATH_PROOF_TARGET_FLAGS_ZERO
        } else {
            base
        }
    }
}

/// Outer-to-supervisor command for one exact parent-death checkpoint.
#[derive(Eq, PartialEq)]
pub struct DebuggerParentDeathCommand {
    run_nonce: DebuggerRunNonce,
    stage: ParentDeathStage,
}

impl DebuggerParentDeathCommand {
    /// Constructs one canonical supervisor command.
    #[must_use]
    pub const fn new(run_nonce: DebuggerRunNonce, stage: ParentDeathStage) -> Self {
        Self { run_nonce, stage }
    }

    /// Returns the debugger-run nonce.
    #[must_use]
    pub const fn run_nonce(&self) -> &DebuggerRunNonce {
        &self.run_nonce
    }

    /// Returns the requested forced-parent-death checkpoint.
    #[must_use]
    pub const fn stage(&self) -> ParentDeathStage {
        self.stage
    }

    /// Consumes the command without cloning its nonce.
    #[must_use]
    pub fn into_parts(self) -> (DebuggerRunNonce, ParentDeathStage) {
        (self.run_nonce, self.stage)
    }

    /// Encodes this command as one exact canonical frame.
    #[must_use]
    pub fn encode(&self) -> [u8; PARENT_DEATH_COMMAND_FRAME_BYTES] {
        let mut frame = [0_u8; PARENT_DEATH_COMMAND_FRAME_BYTES];
        encode_header(&mut frame, FRAME_PARENT_DEATH_COMMAND);
        frame[PARENT_DEATH_COMMAND_NONCE_OFFSET..PARENT_DEATH_COMMAND_NONCE_OFFSET + NONCE_BYTES]
            .copy_from_slice(self.run_nonce.as_bytes());
        write_u16(
            &mut frame,
            PARENT_DEATH_COMMAND_STAGE_OFFSET,
            self.stage as u16,
        );
        finish_frame(&mut frame, PARENT_DEATH_COMMAND_CHECKSUM_OFFSET);
        frame
    }

    /// Decodes one exact canonical supervisor command.
    ///
    /// # Errors
    ///
    /// Returns a stable [`WireError`] category for malformed input.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, WireError> {
        require_exact_length(bytes, PARENT_DEATH_COMMAND_FRAME_BYTES)?;
        decode_header(bytes, FRAME_PARENT_DEATH_COMMAND)?;
        require_zero_u16(bytes, PARENT_DEATH_COMMAND_RESERVED_OFFSET)?;
        verify_checksum(bytes, PARENT_DEATH_COMMAND_CHECKSUM_OFFSET)?;
        Ok(Self::new(
            decode_nonce(bytes, PARENT_DEATH_COMMAND_NONCE_OFFSET)?,
            ParentDeathStage::from_wire(read_u16(bytes, PARENT_DEATH_COMMAND_STAGE_OFFSET))?,
        ))
    }
}

impl fmt::Debug for DebuggerParentDeathCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerParentDeathCommand([REDACTED])")
    }
}

/// Supervisor-to-outer fixed identity report at one parent-death checkpoint.
#[derive(Eq, PartialEq)]
pub struct DebuggerParentDeathReport {
    run_nonce: DebuggerRunNonce,
    stage: ParentDeathStage,
    supervisor_process_id: u32,
    debugger_process_id: u32,
    target_process_id: u32,
    supervisor_creation_time: u64,
    debugger_creation_time: u64,
    target_creation_time: u64,
}

impl DebuggerParentDeathReport {
    /// Constructs one canonical checkpoint identity report.
    ///
    /// # Errors
    ///
    /// Rejects zero or aliased required identities and rejects any target
    /// identity outside the READY and post-handoff stages.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        run_nonce: DebuggerRunNonce,
        stage: ParentDeathStage,
        supervisor_process_id: u32,
        debugger_process_id: u32,
        target_process_id: u32,
        supervisor_creation_time: u64,
        debugger_creation_time: u64,
        target_creation_time: u64,
    ) -> Result<Self, WireError> {
        let base_invalid = supervisor_process_id == 0
            || debugger_process_id == 0
            || supervisor_process_id == debugger_process_id
            || supervisor_creation_time == 0
            || debugger_creation_time == 0;
        let target_invalid = if stage.requires_target() {
            target_process_id == 0
                || target_creation_time == 0
                || target_process_id == supervisor_process_id
                || target_process_id == debugger_process_id
        } else {
            target_process_id != 0 || target_creation_time != 0
        };
        if base_invalid || target_invalid {
            return Err(WireError::InvalidValue);
        }
        Ok(Self {
            run_nonce,
            stage,
            supervisor_process_id,
            debugger_process_id,
            target_process_id,
            supervisor_creation_time,
            debugger_creation_time,
            target_creation_time,
        })
    }

    /// Returns the run nonce.
    #[must_use]
    pub const fn run_nonce(&self) -> &DebuggerRunNonce {
        &self.run_nonce
    }

    /// Returns the reported checkpoint.
    #[must_use]
    pub const fn stage(&self) -> ParentDeathStage {
        self.stage
    }

    /// Returns the supervisor PID.
    #[must_use]
    pub const fn supervisor_process_id(&self) -> u32 {
        self.supervisor_process_id
    }

    /// Returns the debugger PID.
    #[must_use]
    pub const fn debugger_process_id(&self) -> u32 {
        self.debugger_process_id
    }

    /// Returns the target PID, or zero before READY.
    #[must_use]
    pub const fn target_process_id(&self) -> u32 {
        self.target_process_id
    }

    /// Returns the supervisor creation `FILETIME` word.
    #[must_use]
    pub const fn supervisor_creation_time(&self) -> u64 {
        self.supervisor_creation_time
    }

    /// Returns the debugger creation `FILETIME` word.
    #[must_use]
    pub const fn debugger_creation_time(&self) -> u64 {
        self.debugger_creation_time
    }

    /// Returns the target creation `FILETIME` word, or zero before READY.
    #[must_use]
    pub const fn target_creation_time(&self) -> u64 {
        self.target_creation_time
    }

    /// Consumes the report without cloning its nonce.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        DebuggerRunNonce,
        ParentDeathStage,
        u32,
        u32,
        u32,
        u64,
        u64,
        u64,
    ) {
        (
            self.run_nonce,
            self.stage,
            self.supervisor_process_id,
            self.debugger_process_id,
            self.target_process_id,
            self.supervisor_creation_time,
            self.debugger_creation_time,
            self.target_creation_time,
        )
    }

    /// Encodes this report as one exact canonical frame.
    #[must_use]
    pub fn encode(&self) -> [u8; PARENT_DEATH_REPORT_FRAME_BYTES] {
        let mut frame = [0_u8; PARENT_DEATH_REPORT_FRAME_BYTES];
        encode_header(&mut frame, FRAME_PARENT_DEATH_REPORT);
        frame[PARENT_DEATH_REPORT_NONCE_OFFSET..PARENT_DEATH_REPORT_NONCE_OFFSET + NONCE_BYTES]
            .copy_from_slice(self.run_nonce.as_bytes());
        write_u16(
            &mut frame,
            PARENT_DEATH_REPORT_STAGE_OFFSET,
            self.stage as u16,
        );
        write_u32(
            &mut frame,
            PARENT_DEATH_REPORT_SUPERVISOR_PID_OFFSET,
            self.supervisor_process_id,
        );
        write_u32(
            &mut frame,
            PARENT_DEATH_REPORT_DEBUGGER_PID_OFFSET,
            self.debugger_process_id,
        );
        write_u32(
            &mut frame,
            PARENT_DEATH_REPORT_TARGET_PID_OFFSET,
            self.target_process_id,
        );
        write_u64(
            &mut frame,
            PARENT_DEATH_REPORT_SUPERVISOR_TIME_OFFSET,
            self.supervisor_creation_time,
        );
        write_u64(
            &mut frame,
            PARENT_DEATH_REPORT_DEBUGGER_TIME_OFFSET,
            self.debugger_creation_time,
        );
        write_u64(
            &mut frame,
            PARENT_DEATH_REPORT_TARGET_TIME_OFFSET,
            self.target_creation_time,
        );
        write_u32(
            &mut frame,
            PARENT_DEATH_REPORT_PROOFS_OFFSET,
            self.stage.required_proofs(),
        );
        finish_frame(&mut frame, PARENT_DEATH_REPORT_CHECKSUM_OFFSET);
        frame
    }

    /// Decodes one exact canonical checkpoint report.
    ///
    /// # Errors
    ///
    /// Returns a stable [`WireError`] category for malformed input.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, WireError> {
        require_exact_length(bytes, PARENT_DEATH_REPORT_FRAME_BYTES)?;
        decode_header(bytes, FRAME_PARENT_DEATH_REPORT)?;
        require_zero_u16(bytes, PARENT_DEATH_REPORT_STAGE_RESERVED_OFFSET)?;
        verify_checksum(bytes, PARENT_DEATH_REPORT_CHECKSUM_OFFSET)?;
        let stage = ParentDeathStage::from_wire(read_u16(bytes, PARENT_DEATH_REPORT_STAGE_OFFSET))?;
        if read_u32(bytes, PARENT_DEATH_REPORT_PROOFS_OFFSET) != stage.required_proofs() {
            return Err(WireError::InvalidValue);
        }
        Self::new(
            decode_nonce(bytes, PARENT_DEATH_REPORT_NONCE_OFFSET)?,
            stage,
            read_u32(bytes, PARENT_DEATH_REPORT_SUPERVISOR_PID_OFFSET),
            read_u32(bytes, PARENT_DEATH_REPORT_DEBUGGER_PID_OFFSET),
            read_u32(bytes, PARENT_DEATH_REPORT_TARGET_PID_OFFSET),
            read_u64(bytes, PARENT_DEATH_REPORT_SUPERVISOR_TIME_OFFSET),
            read_u64(bytes, PARENT_DEATH_REPORT_DEBUGGER_TIME_OFFSET),
            read_u64(bytes, PARENT_DEATH_REPORT_TARGET_TIME_OFFSET),
        )
    }
}

impl fmt::Debug for DebuggerParentDeathReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerParentDeathReport([REDACTED])")
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
    const TEST_TARGET_PID: u32 = 0x90A0_B0C0;
    const TEST_TARGET_TID: u32 = 0xD0E0_F001;
    const TEST_SUPERVISOR_PID: u32 = 0x0102_0304;
    const TEST_HANDLE: u64 = 0x1122_3344_5566_7788;
    const TEST_THREAD_HANDLE: u64 = 0x8877_6655_4433_2211;
    const TEST_DEADLINE: u64 = 0x8877_6655_4433_2211;
    const TEST_CREATION_TIME: u64 = 0x0123_4567_89AB_CDEF;
    const TEST_SUPERVISOR_CREATION_TIME: u64 = 0x1020_3040_5060_7080;
    const TEST_DEBUGGER_CREATION_TIME: u64 = 0x2030_4050_6070_8090;

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

    fn target() -> Result<DebuggerTargetFrozen, WireError> {
        DebuggerTargetFrozen::new(
            nonce()?,
            TEST_DEBUGGER_PID,
            TEST_TARGET_PID,
            TEST_TARGET_TID,
            handle()?,
            RemoteHandleWord::new(TEST_THREAD_HANDLE)?,
            TEST_CREATION_TIME,
        )
    }

    fn decision(decision: DebuggerDecision) -> Result<DebuggerDecisionFrame, WireError> {
        Ok(DebuggerDecisionFrame::new(nonce()?, decision))
    }

    fn parent_death_command(
        stage: ParentDeathStage,
    ) -> Result<DebuggerParentDeathCommand, WireError> {
        Ok(DebuggerParentDeathCommand::new(nonce()?, stage))
    }

    fn parent_death_report(
        stage: ParentDeathStage,
    ) -> Result<DebuggerParentDeathReport, WireError> {
        let (target_process_id, target_creation_time) = if stage == ParentDeathStage::PreReady {
            (0, 0)
        } else {
            (TEST_TARGET_PID, TEST_CREATION_TIME)
        };
        DebuggerParentDeathReport::new(
            nonce()?,
            stage,
            TEST_SUPERVISOR_PID,
            TEST_DEBUGGER_PID,
            target_process_id,
            TEST_SUPERVISOR_CREATION_TIME,
            TEST_DEBUGGER_CREATION_TIME,
            target_creation_time,
        )
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
            FRAME_TARGET_FROZEN,
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

    fn decode_target_unit(bytes: &[u8]) -> Result<(), WireError> {
        DebuggerTargetFrozen::decode_exact(bytes).map(|_| ())
    }

    fn decode_parent_death_command_unit(bytes: &[u8]) -> Result<(), WireError> {
        DebuggerParentDeathCommand::decode_exact(bytes).map(|_| ())
    }

    fn decode_parent_death_report_unit(bytes: &[u8]) -> Result<(), WireError> {
        DebuggerParentDeathReport::decode_exact(bytes).map(|_| ())
    }

    #[test]
    fn parent_death_frames_round_trip_every_stage_and_expose_bound_fields() -> Result<(), WireError>
    {
        for stage in [
            ParentDeathStage::PreReady,
            ParentDeathStage::Ready,
            ParentDeathStage::PostHandoff,
        ] {
            let command = parent_death_command(stage)?;
            let command_frame = command.encode();
            assert_eq!(command_frame.len(), PARENT_DEATH_COMMAND_FRAME_BYTES);
            assert_eq!(
                DebuggerParentDeathCommand::decode_exact(&command_frame)?,
                command
            );
            assert_eq!(command.run_nonce().as_bytes(), &[0xA5; NONCE_BYTES]);
            assert_eq!(command.stage(), stage);

            let report = parent_death_report(stage)?;
            let report_frame = report.encode();
            assert_eq!(report_frame.len(), PARENT_DEATH_REPORT_FRAME_BYTES);
            assert_eq!(
                DebuggerParentDeathReport::decode_exact(&report_frame)?,
                report
            );
            assert_eq!(report.run_nonce().as_bytes(), &[0xA5; NONCE_BYTES]);
            assert_eq!(report.stage(), stage);
            assert_eq!(report.supervisor_process_id(), TEST_SUPERVISOR_PID);
            assert_eq!(report.debugger_process_id(), TEST_DEBUGGER_PID);
            assert_eq!(
                report.target_process_id(),
                if stage == ParentDeathStage::PreReady {
                    0
                } else {
                    TEST_TARGET_PID
                }
            );
            assert_eq!(
                report.supervisor_creation_time(),
                TEST_SUPERVISOR_CREATION_TIME
            );
            assert_eq!(report.debugger_creation_time(), TEST_DEBUGGER_CREATION_TIME);
            assert_eq!(
                report.target_creation_time(),
                if stage == ParentDeathStage::PreReady {
                    0
                } else {
                    TEST_CREATION_TIME
                }
            );
        }
        Ok(())
    }

    #[test]
    fn parent_death_frames_reject_every_prefix_trailer_and_byte_mutation() -> Result<(), WireError>
    {
        for stage in [
            ParentDeathStage::PreReady,
            ParentDeathStage::Ready,
            ParentDeathStage::PostHandoff,
        ] {
            let command = parent_death_command(stage)?.encode();
            assert_all_truncations_and_trailing(&command, decode_parent_death_command_unit);
            assert_every_single_byte_mutation_is_rejected(
                &command,
                decode_parent_death_command_unit,
            );

            let report = parent_death_report(stage)?.encode();
            assert_all_truncations_and_trailing(&report, decode_parent_death_report_unit);
            assert_every_single_byte_mutation_is_rejected(&report, decode_parent_death_report_unit);
        }
        Ok(())
    }

    #[test]
    fn parent_death_semantics_reject_every_field_class_after_checksum_rewrite()
    -> Result<(), WireError> {
        let command = parent_death_command(ParentDeathStage::Ready)?.encode();
        assert_semantic_header_failures(
            &command,
            PARENT_DEATH_COMMAND_CHECKSUM_OFFSET,
            FRAME_PARENT_DEATH_COMMAND,
            decode_parent_death_command_unit,
        );
        for invalid_stage in [0, 4, u16::MAX] {
            let mut mutated = command;
            write_u16(
                &mut mutated,
                PARENT_DEATH_COMMAND_STAGE_OFFSET,
                invalid_stage,
            );
            rewrite_checksum(&mut mutated, PARENT_DEATH_COMMAND_CHECKSUM_OFFSET);
            assert_eq!(
                DebuggerParentDeathCommand::decode_exact(&mutated),
                Err(WireError::InvalidValue)
            );
        }

        let report = parent_death_report(ParentDeathStage::Ready)?.encode();
        assert_semantic_header_failures(
            &report,
            PARENT_DEATH_REPORT_CHECKSUM_OFFSET,
            FRAME_PARENT_DEATH_REPORT,
            decode_parent_death_report_unit,
        );
        for range in [
            PARENT_DEATH_REPORT_NONCE_OFFSET..PARENT_DEATH_REPORT_NONCE_OFFSET + NONCE_BYTES,
            PARENT_DEATH_REPORT_SUPERVISOR_PID_OFFSET
                ..PARENT_DEATH_REPORT_SUPERVISOR_PID_OFFSET + 4,
            PARENT_DEATH_REPORT_DEBUGGER_PID_OFFSET..PARENT_DEATH_REPORT_DEBUGGER_PID_OFFSET + 4,
            PARENT_DEATH_REPORT_TARGET_PID_OFFSET..PARENT_DEATH_REPORT_TARGET_PID_OFFSET + 4,
            PARENT_DEATH_REPORT_SUPERVISOR_TIME_OFFSET
                ..PARENT_DEATH_REPORT_SUPERVISOR_TIME_OFFSET + 8,
            PARENT_DEATH_REPORT_DEBUGGER_TIME_OFFSET..PARENT_DEATH_REPORT_DEBUGGER_TIME_OFFSET + 8,
            PARENT_DEATH_REPORT_TARGET_TIME_OFFSET..PARENT_DEATH_REPORT_TARGET_TIME_OFFSET + 8,
        ] {
            let mut mutated = report;
            mutated[range].fill(0);
            rewrite_checksum(&mut mutated, PARENT_DEATH_REPORT_CHECKSUM_OFFSET);
            assert_eq!(
                DebuggerParentDeathReport::decode_exact(&mutated),
                Err(WireError::InvalidValue)
            );
        }
        for invalid_stage in [0, 4, u16::MAX] {
            let mut mutated = report;
            write_u16(
                &mut mutated,
                PARENT_DEATH_REPORT_STAGE_OFFSET,
                invalid_stage,
            );
            rewrite_checksum(&mut mutated, PARENT_DEATH_REPORT_CHECKSUM_OFFSET);
            assert_eq!(
                DebuggerParentDeathReport::decode_exact(&mutated),
                Err(WireError::InvalidValue)
            );
        }
        for invalid_proofs in [0, 1, 3, 5, 6, 8, u32::MAX] {
            let mut mutated = report;
            write_u32(
                &mut mutated,
                PARENT_DEATH_REPORT_PROOFS_OFFSET,
                invalid_proofs,
            );
            rewrite_checksum(&mut mutated, PARENT_DEATH_REPORT_CHECKSUM_OFFSET);
            assert_eq!(
                DebuggerParentDeathReport::decode_exact(&mutated),
                Err(WireError::InvalidValue)
            );
        }

        let mut reserved = report;
        reserved[PARENT_DEATH_REPORT_STAGE_RESERVED_OFFSET] = 1;
        rewrite_checksum(&mut reserved, PARENT_DEATH_REPORT_CHECKSUM_OFFSET);
        assert_eq!(
            DebuggerParentDeathReport::decode_exact(&reserved),
            Err(WireError::NonZeroReserved)
        );
        let mut command_reserved = command;
        command_reserved[PARENT_DEATH_COMMAND_RESERVED_OFFSET] = 1;
        rewrite_checksum(&mut command_reserved, PARENT_DEATH_COMMAND_CHECKSUM_OFFSET);
        assert_eq!(
            DebuggerParentDeathCommand::decode_exact(&command_reserved),
            Err(WireError::NonZeroReserved)
        );
        Ok(())
    }

    #[test]
    fn parent_death_report_stage_specific_target_semantics_are_closed() -> Result<(), WireError> {
        assert_eq!(
            DebuggerParentDeathReport::new(
                nonce()?,
                ParentDeathStage::PreReady,
                TEST_SUPERVISOR_PID,
                TEST_DEBUGGER_PID,
                TEST_TARGET_PID,
                TEST_SUPERVISOR_CREATION_TIME,
                TEST_DEBUGGER_CREATION_TIME,
                TEST_CREATION_TIME,
            ),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            DebuggerParentDeathReport::new(
                nonce()?,
                ParentDeathStage::Ready,
                TEST_SUPERVISOR_PID,
                TEST_DEBUGGER_PID,
                0,
                TEST_SUPERVISOR_CREATION_TIME,
                TEST_DEBUGGER_CREATION_TIME,
                0,
            ),
            Err(WireError::InvalidValue)
        );
        for aliased_target in [TEST_SUPERVISOR_PID, TEST_DEBUGGER_PID] {
            assert_eq!(
                DebuggerParentDeathReport::new(
                    nonce()?,
                    ParentDeathStage::PostHandoff,
                    TEST_SUPERVISOR_PID,
                    TEST_DEBUGGER_PID,
                    aliased_target,
                    TEST_SUPERVISOR_CREATION_TIME,
                    TEST_DEBUGGER_CREATION_TIME,
                    TEST_CREATION_TIME,
                ),
                Err(WireError::InvalidValue)
            );
        }
        Ok(())
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

        let target = target()?;
        let target_frame = target.encode();
        assert_eq!(target_frame.len(), TARGET_FROZEN_FRAME_BYTES);
        assert_eq!(
            &target_frame[TARGET_PROCESS_PID_OFFSET..TARGET_PROCESS_PID_OFFSET + 4],
            &TEST_TARGET_PID.to_be_bytes()
        );
        assert_eq!(
            &target_frame[TARGET_CREATION_TIME_OFFSET..TARGET_CREATION_TIME_OFFSET + 8],
            &TEST_CREATION_TIME.to_be_bytes()
        );
        assert_eq!(DebuggerTargetFrozen::decode_exact(&target_frame)?, target);

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

        let target = target()?;
        assert_eq!(target.run_nonce().as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(target.debugger_process_id(), TEST_DEBUGGER_PID);
        assert_eq!(target.target_process_id(), TEST_TARGET_PID);
        assert_eq!(target.target_thread_id(), TEST_TARGET_TID);
        assert_eq!(target.target_process_source_handle().value(), TEST_HANDLE);
        assert_eq!(
            target.target_thread_source_handle().value(),
            TEST_THREAD_HANDLE
        );
        assert_eq!(target.target_creation_time(), TEST_CREATION_TIME);

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

        let (run_nonce, debugger_pid, target_pid, target_thread_id, process, thread, creation_time) =
            target()?.into_parts();
        assert_eq!(run_nonce.as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(debugger_pid, TEST_DEBUGGER_PID);
        assert_eq!(target_pid, TEST_TARGET_PID);
        assert_eq!(target_thread_id, TEST_TARGET_TID);
        assert_eq!(process.value(), TEST_HANDLE);
        assert_eq!(thread.value(), TEST_THREAD_HANDLE);
        assert_eq!(creation_time, TEST_CREATION_TIME);

        let (run_nonce, decision) = decision(DebuggerDecision::Abort)?.into_parts();
        assert_eq!(run_nonce.as_bytes(), &[0xA5; NONCE_BYTES]);
        assert_eq!(decision, DebuggerDecision::Abort);
        Ok(())
    }

    #[test]
    fn every_prefix_and_trailing_byte_is_rejected() -> Result<(), WireError> {
        assert_all_truncations_and_trailing(&bootstrap()?.encode(), decode_bootstrap_unit);
        assert_all_truncations_and_trailing(&ready()?.encode(), decode_ready_unit);
        assert_all_truncations_and_trailing(&target()?.encode(), decode_target_unit);
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
        assert_every_single_byte_mutation_is_rejected(&target()?.encode(), decode_target_unit);
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
            &target()?.encode(),
            TARGET_CHECKSUM_OFFSET,
            FRAME_TARGET_FROZEN,
            decode_target_unit,
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
            (
                target()?.encode().to_vec(),
                TARGET_CHECKSUM_OFFSET,
                vec![12..16, 60..64, 88..92],
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
                            TARGET_FROZEN_FRAME_BYTES => {
                                DebuggerTargetFrozen::decode_exact(&mutated).err()
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
    #[allow(clippy::too_many_lines)]
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
        assert_eq!(
            DebuggerTargetFrozen::new(
                nonce()?,
                TEST_DEBUGGER_PID,
                TEST_DEBUGGER_PID,
                TEST_TARGET_TID,
                handle()?,
                RemoteHandleWord::new(TEST_THREAD_HANDLE)?,
                TEST_CREATION_TIME,
            ),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            DebuggerTargetFrozen::new(
                nonce()?,
                TEST_DEBUGGER_PID,
                TEST_TARGET_PID,
                TEST_TARGET_TID,
                handle()?,
                handle()?,
                TEST_CREATION_TIME,
            ),
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

        for range in [
            TARGET_NONCE_OFFSET..TARGET_NONCE_OFFSET + NONCE_BYTES,
            TARGET_DEBUGGER_PID_OFFSET..TARGET_DEBUGGER_PID_OFFSET + 4,
            TARGET_PROCESS_PID_OFFSET..TARGET_PROCESS_PID_OFFSET + 4,
            TARGET_THREAD_TID_OFFSET..TARGET_THREAD_TID_OFFSET + 4,
            TARGET_PROCESS_HANDLE_OFFSET..TARGET_PROCESS_HANDLE_OFFSET + 8,
            TARGET_THREAD_HANDLE_OFFSET..TARGET_THREAD_HANDLE_OFFSET + 8,
            TARGET_CREATION_TIME_OFFSET..TARGET_CREATION_TIME_OFFSET + 8,
        ] {
            let mut frame = target()?.encode();
            frame[range].fill(0);
            rewrite_checksum(&mut frame, TARGET_CHECKSUM_OFFSET);
            assert_eq!(
                DebuggerTargetFrozen::decode_exact(&frame),
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
        let target = target()?.encode();
        let decision = decision(DebuggerDecision::Commit)?.encode();

        assert!(DebuggerBootstrap::decode_exact(&ready).is_err());
        assert!(DebuggerBootstrap::decode_exact(&decision).is_err());
        assert!(DebuggerBootstrap::decode_exact(&target).is_err());
        assert!(DebuggerReadyFrozen::decode_exact(&bootstrap).is_err());
        assert!(DebuggerReadyFrozen::decode_exact(&decision).is_err());
        assert!(DebuggerReadyFrozen::decode_exact(&target).is_err());
        assert!(DebuggerTargetFrozen::decode_exact(&bootstrap).is_err());
        assert!(DebuggerTargetFrozen::decode_exact(&ready).is_err());
        assert!(DebuggerTargetFrozen::decode_exact(&decision).is_err());
        assert!(DebuggerDecisionFrame::decode_exact(&bootstrap).is_err());
        assert!(DebuggerDecisionFrame::decode_exact(&ready).is_err());
        assert!(DebuggerDecisionFrame::decode_exact(&target).is_err());
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
            format!("{:?}", target()?),
            "DebuggerTargetFrozen([REDACTED])"
        );
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
