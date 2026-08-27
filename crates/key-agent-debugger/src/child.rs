//! Windows-only one-shot debugger transport feasibility runner.
//!
//! `READY_FROZEN` means only that the sentinel source handle set is fixed and
//! the protocol has entered its decision-only state. This dormant helper does
//! not create, debug, or suspend a target process and calls no Windows debug API.

use core::{ffi::c_void, fmt};
use std::io::{Read as _, Write as _};
use std::mem::ManuallyDrop;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use key_agent_debugger_wire::{
    BOOTSTRAP_FRAME_BYTES, DECISION_FRAME_BYTES, DebuggerBootstrap, DebuggerDecision,
    DebuggerDecisionFrame, DebuggerExitCode, DebuggerReadyFrozen, DebuggerRunNonce,
    READY_FROZEN_FRAME_BYTES,
};
use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF,
    GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, INVALID_HANDLE_VALUE,
    SetHandleInformation, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{FILE_TYPE_CHAR, FILE_TYPE_PIPE, GetFileType};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, PeekNamedPipe};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, SetEvent, Sleep, WaitForSingleObject,
};

const MAX_RUN_WINDOW_MILLISECONDS: u64 = 5_000;
const POLL_MILLISECONDS: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportFailure {
    ParentEof,
    DeadlineElapsed,
    ProtocolViolation,
    OperatingSystem,
}

impl TransportFailure {
    const fn exit_code(self) -> DebuggerExitCode {
        match self {
            Self::ParentEof => DebuggerExitCode::ParentEof,
            Self::DeadlineElapsed => DebuggerExitCode::DeadlineElapsed,
            Self::ProtocolViolation => DebuggerExitCode::ProtocolViolation,
            Self::OperatingSystem => DebuggerExitCode::OperatingSystem,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SealedStdio {
    stdin: HANDLE,
    stdout: HANDLE,
    #[allow(dead_code)]
    stderr: HANDLE,
}

impl fmt::Debug for SealedStdio {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedStdio([STDIO HANDLES REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeekState {
    Bytes(u32),
    Eof,
}

/// Runs one bounded bootstrap, frozen-ready, and decision exchange.
///
/// Every returned value is consumed immediately by `main` through
/// `std::process::exit`. After `READY_FROZEN`, the sentinel owner is wrapped in
/// `ManuallyDrop` before the first READY byte is attempted, so no later Rust
/// return path changes that source handle table before process termination.
pub(super) fn run() -> DebuggerExitCode {
    match run_protocol() {
        Ok(decision) => match decision {
            DebuggerDecision::Commit => DebuggerExitCode::Success,
            DebuggerDecision::Abort => DebuggerExitCode::Aborted,
        },
        Err(failure) => failure.exit_code(),
    }
}

fn run_protocol() -> Result<DebuggerDecision, TransportFailure> {
    let stdio = seal_inherited_stdio()?;
    let bootstrap_intake_deadline = bounded_deadline_from_now()?;
    let mut bootstrap_bytes = [0_u8; BOOTSTRAP_FRAME_BYTES];
    read_exact_polled(stdio.stdin, &mut bootstrap_bytes, bootstrap_intake_deadline)?;
    let bootstrap = DebuggerBootstrap::decode_exact(&bootstrap_bytes)
        .map_err(|_| TransportFailure::ProtocolViolation)?;
    let current_process_id = current_process_id()?;
    let run_deadline = validate_bootstrap(&bootstrap, current_process_id)?;
    validate_parent_pipe_identity(stdio, bootstrap.parent_process_id())?;

    let (run_nonce, _, _, sentinel_word, _) = bootstrap.into_parts();
    let sentinel = adopt_sentinel(sentinel_word.value())?;
    validate_sentinel(&sentinel, stdio)?;
    require_no_early_input(stdio.stdin)?;

    let ready = DebuggerReadyFrozen::new(run_nonce, current_process_id, sentinel_word)
        .map_err(|_| TransportFailure::ProtocolViolation)?;
    let ready_bytes = ready.encode();
    let (run_nonce, _, _) = ready.into_parts();

    // From the first externally observable READY byte onward, no Rust unwind
    // or error return may individually close this source handle. In
    // particular, stdout detachment and close are two native operations and
    // can report a half-success after EOF has become observable. Process exit
    // is therefore the sole reclamation path before attempting the write.
    let sentinel = ManuallyDrop::new(sentinel);
    write_exact(stdio.stdout, &ready_bytes)?;
    close_ready_output(stdio.stdout)?;

    // After READY plus EOF, the only remaining protocol operation is a bounded
    // read from sealed stdin; the source remains process-exit-only throughout.
    let mut decision_bytes = [0_u8; DECISION_FRAME_BYTES];
    let decision_result = read_exact_polled(stdio.stdin, &mut decision_bytes, run_deadline)
        .and_then(|()| {
            DebuggerDecisionFrame::decode_exact(&decision_bytes)
                .map_err(|_| TransportFailure::ProtocolViolation)
        })
        .and_then(|decision| {
            let decision = validate_decision(decision, &run_nonce)?;
            await_exact_eof(stdio.stdin, run_deadline)?;
            Ok(decision)
        });
    core::hint::black_box(&sentinel);
    decision_result
}

fn validate_decision(
    frame: DebuggerDecisionFrame,
    expected_nonce: &DebuggerRunNonce,
) -> Result<DebuggerDecision, TransportFailure> {
    let (decision_nonce, decision) = frame.into_parts();
    if decision_nonce.as_bytes() != expected_nonce.as_bytes() {
        return Err(TransportFailure::ProtocolViolation);
    }
    Ok(decision)
}

fn seal_inherited_stdio() -> Result<SealedStdio, TransportFailure> {
    // SAFETY: GetStdHandle returns borrowed process-table values. This function
    // neither adopts nor closes them during validation and sealing.
    let stdin =
        unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(|_| TransportFailure::OperatingSystem)?;
    // SAFETY: same borrowed-handle contract as stdin.
    let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
        .map_err(|_| TransportFailure::OperatingSystem)?;
    // SAFETY: same borrowed-handle contract as stdin.
    let stderr =
        unsafe { GetStdHandle(STD_ERROR_HANDLE) }.map_err(|_| TransportFailure::OperatingSystem)?;
    let handles = [stdin, stdout, stderr];

    if handles.iter().copied().any(invalid_handle)
        || same_object(stdin, stdout)?
        || same_object(stdin, stderr)?
        || same_object(stdout, stderr)?
        || file_type(stdin) != FILE_TYPE_PIPE
        || file_type(stdout) != FILE_TYPE_PIPE
        || file_type(stderr) != FILE_TYPE_CHAR
    {
        return Err(TransportFailure::ProtocolViolation);
    }
    for handle in handles {
        if handle_flags(handle)? != HANDLE_FLAG_INHERIT.0 {
            return Err(TransportFailure::ProtocolViolation);
        }
    }

    let mut clear_failed = false;
    for handle in handles {
        // SAFETY: each value is a live borrowed standard handle and only its
        // current-process inherit flag is cleared. Ownership is unchanged.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.is_err()
        {
            clear_failed = true;
        }
    }
    let exact_zero_flags = handles.iter().all(|handle| handle_flags(*handle) == Ok(0));
    if clear_failed || !exact_zero_flags {
        return Err(TransportFailure::OperatingSystem);
    }

    Ok(SealedStdio {
        stdin,
        stdout,
        stderr,
    })
}

fn validate_bootstrap(
    bootstrap: &DebuggerBootstrap,
    current_process_id: u32,
) -> Result<u64, TransportFailure> {
    if bootstrap.debugger_process_id() != current_process_id
        || bootstrap.parent_process_id() == current_process_id
    {
        return Err(TransportFailure::ProtocolViolation);
    }

    let now = tick_count();
    let deadline = bootstrap.absolute_tick_deadline();
    let maximum = now
        .checked_add(MAX_RUN_WINDOW_MILLISECONDS)
        .ok_or(TransportFailure::ProtocolViolation)?;
    if deadline <= now {
        return Err(TransportFailure::DeadlineElapsed);
    }
    if deadline > maximum {
        return Err(TransportFailure::ProtocolViolation);
    }
    Ok(deadline)
}

fn validate_parent_pipe_identity(
    stdio: SealedStdio,
    parent_process_id: u32,
) -> Result<(), TransportFailure> {
    for pipe in [stdio.stdin, stdio.stdout] {
        let mut client_process_id = 0_u32;
        // SAFETY: pipe is a retained live named-pipe server handle and the
        // output pointer names one initialized process-id word.
        unsafe { GetNamedPipeClientProcessId(pipe, &raw mut client_process_id) }
            .map_err(|_| TransportFailure::OperatingSystem)?;
        if client_process_id != parent_process_id {
            return Err(TransportFailure::ProtocolViolation);
        }
    }
    Ok(())
}

fn adopt_sentinel(word: u64) -> Result<OwnedHandle, TransportFailure> {
    let raw = usize::try_from(word).map_err(|_| TransportFailure::ProtocolViolation)?;
    let handle = HANDLE(raw as *mut c_void);
    if invalid_handle(handle) {
        return Err(TransportFailure::ProtocolViolation);
    }
    // SAFETY: the canonical bootstrap binds this fresh process-local handle
    // word to this debugger process. It is adopted exactly once immediately
    // after frame, PID, deadline, and pipe-peer validation.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}

fn validate_sentinel(sentinel: &OwnedHandle, stdio: SealedStdio) -> Result<(), TransportFailure> {
    let handle = HANDLE(sentinel.as_raw_handle());
    if handle_flags(handle)? != 0
        || same_object(handle, stdio.stdin)?
        || same_object(handle, stdio.stdout)?
        || same_object(handle, stdio.stderr)?
    {
        return Err(TransportFailure::ProtocolViolation);
    }

    // SAFETY: the adopted sentinel is a live waitable handle. A zero timeout
    // only observes its current state and must report exactly unsignaled.
    if unsafe { WaitForSingleObject(handle, 0) } != WAIT_TIMEOUT {
        return Err(TransportFailure::ProtocolViolation);
    }
    // SAFETY: the sentinel is intentionally expected to have SYNCHRONIZE only.
    // A successful SetEvent would prove excess mutation authority and fails the
    // ceremony; the expected access-denied result leaves the event unchanged.
    match unsafe { SetEvent(handle) } {
        Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
        Ok(()) | Err(_) => return Err(TransportFailure::ProtocolViolation),
    }
    Ok(())
}

fn require_no_early_input(stdin: HANDLE) -> Result<(), TransportFailure> {
    match peek(stdin)? {
        PeekState::Bytes(0) => Ok(()),
        PeekState::Bytes(_) => Err(TransportFailure::ProtocolViolation),
        PeekState::Eof => Err(TransportFailure::ParentEof),
    }
}

fn read_exact_polled(
    handle: HANDLE,
    bytes: &mut [u8],
    deadline: u64,
) -> Result<(), TransportFailure> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        match peek(handle)? {
            PeekState::Eof => return Err(TransportFailure::ParentEof),
            PeekState::Bytes(0) => wait_for_poll(deadline)?,
            PeekState::Bytes(available) => {
                let remaining = bytes
                    .get_mut(offset..)
                    .ok_or(TransportFailure::ProtocolViolation)?;
                let offered = remaining.len().min(
                    usize::try_from(available).map_err(|_| TransportFailure::ProtocolViolation)?,
                );
                let destination = remaining
                    .get_mut(..offered)
                    .ok_or(TransportFailure::ProtocolViolation)?;
                let transferred = read_available(handle, destination)?;
                if transferred == 0 || transferred > destination.len() {
                    return Err(TransportFailure::ProtocolViolation);
                }
                offset = offset
                    .checked_add(transferred)
                    .ok_or(TransportFailure::ProtocolViolation)?;
            }
        }
    }
    Ok(())
}

fn await_exact_eof(handle: HANDLE, deadline: u64) -> Result<(), TransportFailure> {
    loop {
        match peek(handle)? {
            PeekState::Eof => return Ok(()),
            PeekState::Bytes(0) => wait_for_poll(deadline)?,
            PeekState::Bytes(_) => return Err(TransportFailure::ProtocolViolation),
        }
    }
}

fn peek(handle: HANDLE) -> Result<PeekState, TransportFailure> {
    let mut available = 0_u32;
    // SAFETY: handle is the retained synchronous stdin named pipe. No payload
    // buffer is supplied; the one output pointer names initialized storage.
    let result = unsafe { PeekNamedPipe(handle, None, 0, None, Some(&raw mut available), None) };
    match result {
        Ok(()) => Ok(PeekState::Bytes(available)),
        Err(error) if is_eof_error(&error) => Ok(PeekState::Eof),
        Err(_) => Err(TransportFailure::OperatingSystem),
    }
}

fn read_available(handle: HANDLE, bytes: &mut [u8]) -> Result<usize, TransportFailure> {
    if standard_handle(STD_INPUT_HANDLE)? != handle {
        return Err(TransportFailure::ProtocolViolation);
    }
    match std::io::stdin().read(bytes) {
        Ok(0) => Err(TransportFailure::ParentEof),
        Ok(transferred) => Ok(transferred),
        Err(error) if is_io_eof_error(&error) => Err(TransportFailure::ParentEof),
        Err(_) => Err(TransportFailure::OperatingSystem),
    }
}

fn write_exact(
    handle: HANDLE,
    bytes: &[u8; READY_FROZEN_FRAME_BYTES],
) -> Result<(), TransportFailure> {
    if standard_handle(STD_OUTPUT_HANDLE)? != handle {
        return Err(TransportFailure::ProtocolViolation);
    }
    let mut stdout = std::io::stdout();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let remaining = bytes
            .get(offset..)
            .ok_or(TransportFailure::ProtocolViolation)?;
        let transferred = stdout
            .write(remaining)
            .map_err(|_| TransportFailure::OperatingSystem)?;
        if transferred == 0 || transferred > remaining.len() {
            return Err(TransportFailure::ProtocolViolation);
        }
        offset = offset
            .checked_add(transferred)
            .ok_or(TransportFailure::ProtocolViolation)?;
    }
    // Flush only Rust's user-space stdout buffer so all 72 bytes reach the
    // sealed pipe before its handle is closed. `FlushFileBuffers` is
    // deliberately forbidden here because named-pipe drain acknowledgement can
    // wait indefinitely for an unresponsive parent; EOF after the close below
    // is the parent-observed completion proof.
    stdout
        .flush()
        .map_err(|_| TransportFailure::OperatingSystem)
}

fn close_ready_output(stdout: HANDLE) -> Result<(), TransportFailure> {
    // SAFETY: stdout is the exact de-inherited standard response handle. Nulling
    // its table entry before close prevents numeric reuse from becoming ambient
    // output access. No stdout operation occurs afterward.
    let detached = unsafe { SetStdHandle(STD_OUTPUT_HANDLE, HANDLE::default()) };
    // SAFETY: no Rust owner exists for this exact inherited raw handle and this
    // is its sole close transition. It is attempted even if detachment failed.
    let closed = unsafe { CloseHandle(stdout) };
    if detached.is_err() || closed.is_err() {
        return Err(TransportFailure::OperatingSystem);
    }
    Ok(())
}

fn bounded_deadline_from_now() -> Result<u64, TransportFailure> {
    tick_count()
        .checked_add(MAX_RUN_WINDOW_MILLISECONDS)
        .ok_or(TransportFailure::OperatingSystem)
}

fn wait_for_poll(deadline: u64) -> Result<(), TransportFailure> {
    if tick_count() >= deadline {
        return Err(TransportFailure::DeadlineElapsed);
    }
    // SAFETY: a short non-alertable sleep has no failure result and bounds the
    // polling rate without creating additional handles or threads.
    unsafe { Sleep(POLL_MILLISECONDS) };
    if tick_count() >= deadline {
        return Err(TransportFailure::DeadlineElapsed);
    }
    Ok(())
}

fn current_process_id() -> Result<u32, TransportFailure> {
    // SAFETY: this scalar query has no preconditions.
    let process_id = unsafe { GetCurrentProcessId() };
    (process_id != 0)
        .then_some(process_id)
        .ok_or(TransportFailure::OperatingSystem)
}

fn standard_handle(
    standard_handle: windows::Win32::System::Console::STD_HANDLE,
) -> Result<HANDLE, TransportFailure> {
    // SAFETY: this returns one borrowed scalar process-table value. The caller
    // uses it only to prove the sealed entry has not changed.
    unsafe { GetStdHandle(standard_handle) }.map_err(|_| TransportFailure::OperatingSystem)
}

fn tick_count() -> u64 {
    // SAFETY: this monotonic scalar query has no preconditions.
    unsafe { GetTickCount64() }
}

fn handle_flags(handle: HANDLE) -> Result<u32, TransportFailure> {
    let mut flags = u32::MAX;
    // SAFETY: the output points to one initialized flag word and the caller
    // retains the borrowed or owned handle for the complete scalar query.
    unsafe { GetHandleInformation(handle, &raw mut flags) }
        .map_err(|_| TransportFailure::OperatingSystem)?;
    Ok(flags)
}

fn same_object(first: HANDLE, second: HANDLE) -> Result<bool, TransportFailure> {
    if invalid_handle(first) || invalid_handle(second) {
        return Err(TransportFailure::ProtocolViolation);
    }
    // SAFETY: both values name live handles retained by the current process.
    Ok(unsafe { CompareObjectHandles(first, second) }.as_bool())
}

fn file_type(handle: HANDLE) -> windows::Win32::Storage::FileSystem::FILE_TYPE {
    // SAFETY: the caller retains this live standard handle.
    unsafe { GetFileType(handle) }
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.is_invalid() || handle == INVALID_HANDLE_VALUE
}

fn is_eof_error(error: &windows::core::Error) -> bool {
    error.code() == ERROR_BROKEN_PIPE.to_hresult() || error.code() == ERROR_HANDLE_EOF.to_hresult()
}

fn is_io_eof_error(error: &std::io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        code == ERROR_BROKEN_PIPE.0.cast_signed() || code == ERROR_HANDLE_EOF.0.cast_signed()
    })
}

#[cfg(test)]
mod tests {
    use key_agent_debugger_wire::{
        DebuggerDecision, DebuggerDecisionFrame, DebuggerRunNonce, WireError,
    };

    use super::{DebuggerExitCode, SealedStdio, TransportFailure, validate_decision};
    use windows::Win32::Foundation::HANDLE;

    #[test]
    fn sealed_stdio_debug_is_fixed_and_redacted() {
        let sealed = SealedStdio {
            stdin: HANDLE::default(),
            stdout: HANDLE::default(),
            stderr: HANDLE::default(),
        };
        assert_eq!(
            format!("{sealed:?}"),
            "SealedStdio([STDIO HANDLES REDACTED])"
        );
    }

    #[test]
    fn transport_failures_have_stable_data_free_exit_categories() {
        assert_eq!(
            TransportFailure::ParentEof.exit_code(),
            DebuggerExitCode::ParentEof
        );
        assert_eq!(
            TransportFailure::DeadlineElapsed.exit_code(),
            DebuggerExitCode::DeadlineElapsed
        );
        assert_eq!(
            TransportFailure::ProtocolViolation.exit_code(),
            DebuggerExitCode::ProtocolViolation
        );
        assert_eq!(
            TransportFailure::OperatingSystem.exit_code(),
            DebuggerExitCode::OperatingSystem
        );
    }

    #[test]
    fn decision_validation_accepts_only_the_bound_nonce_and_closed_set() -> Result<(), WireError> {
        let expected = DebuggerRunNonce::new([0xA5; 32])?;

        for decision in [DebuggerDecision::Commit, DebuggerDecision::Abort] {
            let frame_nonce = DebuggerRunNonce::new([0xA5; 32])?;
            let frame = DebuggerDecisionFrame::new(frame_nonce, decision);
            assert!(validate_decision(frame, &expected).is_ok());
        }

        let different_nonce = DebuggerRunNonce::new([0x5A; 32])?;
        let mismatched = DebuggerDecisionFrame::new(different_nonce, DebuggerDecision::Commit);
        assert_eq!(
            validate_decision(mismatched, &expected),
            Err(TransportFailure::ProtocolViolation)
        );
        Ok(())
    }
}
