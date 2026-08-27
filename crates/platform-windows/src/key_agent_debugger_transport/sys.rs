//! Native boundary for the dormant debugger parent transport.

#![allow(unsafe_code)]
#![allow(dead_code)] // Native half of an explicitly dormant feasibility surface.

use core::ffi::c_void;
use core::mem::{size_of, size_of_val};
use core::ptr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(test)]
use windows::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows::Win32::Foundation::{
    CompareObjectHandles, DUPLICATE_HANDLE_OPTIONS, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    ERROR_ACCESS_DENIED, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
    GetProcessId, GetThreadId, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, SetEvent, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
#[cfg(test)]
use windows::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;
use windows::core::PCWSTR;

use key_agent_debugger_wire::DebuggerExitCode;

use super::DebuggerTransportError;
use crate::inheritable_handle_launch::InheritableHandleLaunchFlight;
use crate::pipe::PreparedKeyAgentDebuggerInheritance;
use crate::restricted_process_context::RestrictedProcessContext;

pub(super) const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000;
const MAX_RUN_MILLISECONDS: u64 = 5_000;
const HANDLE_ATTRIBUTE_COUNT: u32 = 1;

/// Heap-stable one-slot process attribute list containing exactly three stdio
/// handles. Drop deletes the native list before either backing allocation.
struct HandleListAttributes<'resources, 'pipes, 'flight> {
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    _words: Vec<usize>,
    handles: Box<[HANDLE; 3]>,
    _inheritance: &'resources PreparedKeyAgentDebuggerInheritance<'pipes, 'flight>,
}

impl<'resources, 'pipes, 'flight> HandleListAttributes<'resources, 'pipes, 'flight> {
    fn new(
        inheritance: &'resources PreparedKeyAgentDebuggerInheritance<'pipes, 'flight>,
    ) -> Result<Self, DebuggerTransportError> {
        let mut bytes = 0_usize;
        // SAFETY: the documented sizing call uses a null list and initializes
        // `bytes`; its expected false result is not an error.
        let _ = unsafe {
            InitializeProcThreadAttributeList(None, HANDLE_ATTRIBUTE_COUNT, None, &raw mut bytes)
        };
        if bytes == 0 {
            return Err(DebuggerTransportError::ProcessCreation);
        }
        let word_size = size_of::<usize>();
        let word_count = bytes
            .checked_add(word_size - 1)
            .and_then(|rounded| rounded.checked_div(word_size))
            .ok_or(DebuggerTransportError::ProcessCreation)?;
        let mut words = vec![0_usize; word_count];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(words.as_mut_ptr().cast::<c_void>());
        // SAFETY: `words` is aligned writable storage of at least `bytes` and is
        // retained without reallocation until the list is deleted.
        unsafe {
            InitializeProcThreadAttributeList(
                Some(pointer),
                HANDLE_ATTRIBUTE_COUNT,
                None,
                &raw mut bytes,
            )
        }
        .map_err(|_| DebuggerTransportError::ProcessCreation)?;

        let handles = Box::new([
            windows_handle(inheritance.stdin()),
            windows_handle(inheritance.stdout()),
            windows_handle(inheritance.stderr()),
        ]);
        let attributes = Self {
            pointer,
            _words: words,
            handles,
            _inheritance: inheritance,
        };
        // SAFETY: the list is initialized with exactly one free slot. The boxed
        // three-HANDLE array is address-stable and retained through creation.
        unsafe {
            UpdateProcThreadAttribute(
                attributes.pointer,
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                    .map_err(|_| DebuggerTransportError::ProcessCreation)?,
                Some(attributes.handles.as_ptr().cast::<c_void>()),
                size_of_val(attributes.handles.as_ref()),
                None,
                None,
            )
        }
        .map_err(|_| DebuggerTransportError::ProcessCreation)?;
        Ok(attributes)
    }

    const fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.pointer
    }

    const fn stdin(&self) -> HANDLE {
        self.handles[0]
    }

    const fn stdout(&self) -> HANDLE {
        self.handles[1]
    }

    const fn stderr(&self) -> HANDLE {
        self.handles[2]
    }
}

impl Drop for HandleListAttributes<'_, '_, '_> {
    fn drop(&mut self) {
        // SAFETY: construction returns only after list initialization. The list
        // owns no backing allocations and is deleted before fields are dropped.
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
    }
}

/// Owned debugger process and its not-yet-consumed primary-thread handle.
pub(super) struct DebuggerChild {
    process: OwnedHandle,
    primary_thread: Option<OwnedHandle>,
    process_id: u32,
    reaped: bool,
}

impl DebuggerChild {
    pub(super) fn create_suspended(
        executable: &Path,
        context: &RestrictedProcessContext,
        inheritance: &PreparedKeyAgentDebuggerInheritance<'_, '_>,
        flight: &InheritableHandleLaunchFlight<'_>,
        deadline: Instant,
    ) -> Result<Self, DebuggerTransportError> {
        if Instant::now() >= deadline {
            return Err(DebuggerTransportError::Deadline);
        }
        context
            .recheck_thread()
            .map_err(|_| DebuggerTransportError::ProcessContext)?;
        let application = executable
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect::<Vec<_>>();
        let attributes = HandleListAttributes::new(inheritance)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
            .map_err(|_| DebuggerTransportError::ProcessCreation)?;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = attributes.stdin();
        startup.StartupInfo.hStdOutput = attributes.stdout();
        startup.StartupInfo.hStdError = attributes.stderr();
        startup.lpAttributeList = attributes.pointer();
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: the canonical absolute application and context buffers are
        // NUL-terminated and retained. `startup` is a complete STARTUPINFOEXW;
        // its sole attribute is HANDLE_LIST with the three live inheritable
        // stdio handles created under `flight`. TRUE inheritance therefore has
        // exactly stdin/stdout/stderr as candidates. Flags are the exact dormant
        // helper policy and keep user code suspended through return.
        unsafe {
            flight
                .create_process_with_explicit_handle_list(
                    PCWSTR(application.as_ptr()),
                    None,
                    None,
                    debugger_creation_flags(),
                    Some(context.environment().as_ptr().cast::<c_void>()),
                    PCWSTR(context.current_directory().as_ptr()),
                    ptr::from_ref(&startup.StartupInfo),
                    &raw mut information,
                )
                .map_err(|_| DebuggerTransportError::ProcessCreation)?;
        }
        Self::adopt(information)
    }

    fn adopt(information: PROCESS_INFORMATION) -> Result<Self, DebuggerTransportError> {
        if information.hProcess.is_invalid()
            || information.hThread.is_invalid()
            || information.hProcess == information.hThread
        {
            // A successful CreateProcessW contract must return both handles. If
            // the process half is absent there is no race-free object on which
            // cleanup can be proven, so process-wide fail-fast is mandatory.
            if information.hProcess.is_invalid() {
                fail_fast();
            }
            // SAFETY: the fresh non-invalid process half from successful native
            // output is uniquely adopted before any fallible observation. Its
            // object identity, not the potentially corrupted scalar PID output,
            // is the authority used for cleanup below.
            let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
            // SAFETY: the uniquely owned fresh handle remains live. A zero result
            // means the impossible malformed output did not provide verifiable
            // process-object authority, so only process-wide fail-fast is safe.
            if unsafe { GetProcessId(windows_owned_handle(&process)) } == 0 {
                fail_fast();
            }
            // Even a zero or mismatched dwProcessId is only scalar-output
            // corruption: the exact fresh process object above is still safe to
            // terminate and remains live through the bounded reap proof.
            if terminate_live_process_and_reap(
                windows_owned_handle(&process),
                DebuggerExitCode::OperatingSystem,
                Instant::now() + Duration::from_millis(u64::from(CLEANUP_TIMEOUT_MILLISECONDS)),
            )
            .is_err()
            {
                // Do not close the last known process owner and continue after
                // an unproved cleanup. Aborting reclaims the complete parent
                // handle table and prevents this launch path from proceeding.
                fail_fast();
            }
            if !information.hThread.is_invalid() && information.hThread != information.hProcess {
                // SAFETY: this fresh valid companion half is uniquely adopted
                // only after the exact child process is terminal.
                unsafe { drop(OwnedHandle::from_raw_handle(information.hThread.0)) };
            }
            drop(process);
            return Err(DebuggerTransportError::ProcessIdentity);
        }
        // SAFETY: successful process creation returned two fresh owned handles.
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
        // SAFETY: same unique ownership transfer for the primary thread.
        let primary_thread = unsafe { OwnedHandle::from_raw_handle(information.hThread.0) };
        let process_handle = windows_owned_handle(&process);
        let thread_handle = windows_owned_handle(&primary_thread);
        // SAFETY: both retained handles are live objects of the expected type.
        let actual_process_id = unsafe { GetProcessId(process_handle) };
        // SAFETY: same retained ownership for the primary thread.
        let actual_thread_id = unsafe { GetThreadId(thread_handle) };
        if actual_process_id == 0
            || actual_thread_id == 0
            || actual_process_id != information.dwProcessId
            || actual_thread_id != information.dwThreadId
        {
            let mut rejected = Self {
                process,
                primary_thread: Some(primary_thread),
                process_id: information.dwProcessId,
                reaped: false,
            };
            let cleanup = rejected.terminate_and_wait(
                DebuggerExitCode::OperatingSystem,
                Instant::now() + Duration::from_millis(u64::from(CLEANUP_TIMEOUT_MILLISECONDS)),
            );
            if cleanup.is_err() && !rejected.reaped {
                fail_fast();
            }
            return Err(DebuggerTransportError::ProcessIdentity);
        }
        Ok(Self {
            process,
            primary_thread: Some(primary_thread),
            process_id: actual_process_id,
            reaped: false,
        })
    }

    pub(super) const fn process_id(&self) -> u32 {
        self.process_id
    }

    pub(super) fn install_sentinel(&self) -> Result<(SentinelOwner, u64), DebuggerTransportError> {
        SentinelOwner::create_and_install(self.process_handle())
    }

    pub(super) fn resume_exactly_once(&mut self) -> Result<(), DebuggerTransportError> {
        let thread = self
            .primary_thread
            .as_ref()
            .ok_or(DebuggerTransportError::Resume)?;
        // SAFETY: this is the live primary-thread handle returned for one
        // CREATE_SUSPENDED process. Exactly one resume count must be consumed.
        if unsafe { ResumeThread(windows_owned_handle(thread)) } != 1 {
            return Err(DebuggerTransportError::Resume);
        }
        drop(self.primary_thread.take());
        Ok(())
    }

    pub(super) fn pull_sentinel_observer(
        &self,
        remote_word: u64,
    ) -> Result<SentinelObserver, DebuggerTransportError> {
        let remote_word =
            usize::try_from(remote_word).map_err(|_| DebuggerTransportError::SentinelPull)?;
        let remote = HANDLE(remote_word as *mut c_void);
        if remote.is_invalid() {
            return Err(DebuggerTransportError::SentinelPull);
        }
        let mut observer = HANDLE::default();
        // SAFETY: `process` is the retained debugger process with duplication
        // authority; `remote` is the source word returned by that same helper.
        // A successful fresh current-process result is adopted immediately.
        unsafe {
            DuplicateHandle(
                self.process_handle(),
                remote,
                GetCurrentProcess(),
                &raw mut observer,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|_| DebuggerTransportError::SentinelPull)?;
        if observer.is_invalid() {
            return Err(DebuggerTransportError::SentinelPull);
        }
        // SAFETY: DuplicateHandle created one fresh current-process owner.
        let observer = unsafe { OwnedHandle::from_raw_handle(observer.0) };
        if handle_flags(windows_owned_handle(&observer))? != 0 {
            return Err(DebuggerTransportError::SentinelProof);
        }
        Ok(SentinelObserver(observer))
    }

    pub(super) fn wait_for_exact_exit(
        &mut self,
        expected: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let timeout = remaining_milliseconds(deadline)?;
        // SAFETY: the process handle is retained and the wait is finite.
        if unsafe { WaitForSingleObject(self.process_handle(), timeout) } != WAIT_OBJECT_0 {
            return Err(DebuggerTransportError::ProcessExit);
        }
        // A signaled process object is the survivor/reap proof independently
        // of whether the following diagnostic exit-code query succeeds or
        // matches the caller's scenario assertion.
        self.reaped = true;
        let mut exit_code = u32::MAX;
        // SAFETY: the exact process is signaled and output storage is writable.
        unsafe { GetExitCodeProcess(self.process_handle(), &raw mut exit_code) }
            .map_err(|_| DebuggerTransportError::ProcessExit)?;
        if exit_code != exit_code_u32(expected) {
            return Err(DebuggerTransportError::ProcessExit);
        }
        Ok(())
    }

    pub(super) fn terminate_and_wait(
        &mut self,
        code: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        // SAFETY: a zero-timeout observation borrows the retained process only.
        let state = unsafe { WaitForSingleObject(self.process_handle(), 0) };
        if state == WAIT_TIMEOUT {
            // SAFETY: this owner retains termination authority from process
            // creation. Natural exit can win between the observation and this
            // request, so the result is not itself a cleanup verdict. The
            // following bounded wait proves or rejects terminal state.
            let _ = unsafe { TerminateProcess(self.process_handle(), exit_code_u32(code)) };
        } else if state != WAIT_OBJECT_0 {
            return Err(DebuggerTransportError::ProcessExit);
        }
        self.wait_for_exact_exit(code, deadline)
    }

    #[cfg(test)]
    pub(super) fn observe_terminal_without_reaping_for_test(
        &self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let timeout = remaining_milliseconds(deadline)?;
        // SAFETY: the test retains the exact process owner. This deliberately
        // observes terminal state without updating `reaped`, so Drop exercises
        // its natural-exit/expected-code-mismatch cleanup branch.
        if unsafe { WaitForSingleObject(self.process_handle(), timeout) } != WAIT_OBJECT_0 {
            return Err(DebuggerTransportError::ProcessExit);
        }
        Ok(())
    }

    fn process_handle(&self) -> HANDLE {
        windows_owned_handle(&self.process)
    }
}

impl Drop for DebuggerChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let deadline =
            Instant::now() + Duration::from_millis(u64::from(CLEANUP_TIMEOUT_MILLISECONDS));
        let cleanup = self.terminate_and_wait(DebuggerExitCode::OperatingSystem, deadline);
        if cleanup.is_err() && !self.reaped {
            // Closing the last process handle after an unproved cleanup could
            // silently leave the helper alive. Process-wide fail-fast prevents
            // parent continuation, but this intentionally Job-free feasibility
            // slice cannot claim that abort itself terminates the child.
            fail_fast();
        }
    }
}

impl core::fmt::Debug for DebuggerChild {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DebuggerChild([PROCESS; PRIMARY THREAD REDACTED])")
    }
}

/// Parent-owned manual-reset event and the child-table source installed with
/// exact SYNCHRONIZE access.
pub(super) struct SentinelOwner(OwnedHandle);

impl SentinelOwner {
    fn create_and_install(debugger_process: HANDLE) -> Result<(Self, u64), DebuggerTransportError> {
        // SAFETY: no name or security descriptor is supplied. The manual-reset
        // event begins unsignaled and the fresh result is uniquely adopted.
        let sentinel =
            unsafe { windows::Win32::System::Threading::CreateEventW(None, true, false, None) }
                .map_err(|_| DebuggerTransportError::SentinelInstall)?;
        // SAFETY: CreateEventW returned one fresh owned event handle.
        let sentinel = unsafe { OwnedHandle::from_raw_handle(sentinel.0) };
        let sentinel_handle = windows_owned_handle(&sentinel);
        if handle_flags(sentinel_handle)? != 0
            // SAFETY: the retained manual-reset event is queried without mutation.
            || unsafe { WaitForSingleObject(sentinel_handle, 0) } != WAIT_TIMEOUT
        {
            return Err(DebuggerTransportError::SentinelInstall);
        }
        let mut remote = HANDLE::default();
        // SAFETY: source and debugger-process handles are live. A successful
        // result is installed directly in the suspended debugger table with
        // exact SYNCHRONIZE access, no inheritance, and no option bits.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                sentinel_handle,
                debugger_process,
                &raw mut remote,
                SYNCHRONIZE_ACCESS,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| DebuggerTransportError::SentinelInstall)?;
        if remote.is_invalid() {
            return Err(DebuggerTransportError::SentinelInstall);
        }
        let word = u64::try_from(remote.0 as usize)
            .map_err(|_| DebuggerTransportError::SentinelInstall)?;
        if word == 0 {
            return Err(DebuggerTransportError::SentinelInstall);
        }
        Ok((Self(sentinel), word))
    }

    fn raw(&self) -> HANDLE {
        windows_owned_handle(&self.0)
    }
}

impl core::fmt::Debug for SentinelOwner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SentinelOwner([HANDLE REDACTED])")
    }
}

/// Parent-side duplicate pulled from the debugger's SYNCHRONIZE-only source.
pub(super) struct SentinelObserver(OwnedHandle);

impl SentinelObserver {
    fn raw(&self) -> HANDLE {
        windows_owned_handle(&self.0)
    }
}

impl core::fmt::Debug for SentinelObserver {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SentinelObserver([HANDLE REDACTED])")
    }
}

/// Retained original and observer after object identity, access denial, and
/// signal propagation are proven.
pub(super) struct SentinelEvidence {
    _original: SentinelOwner,
    observer: SentinelObserver,
}

impl SentinelEvidence {
    pub(super) fn prove(
        original: SentinelOwner,
        observer: SentinelObserver,
    ) -> Result<Self, DebuggerTransportError> {
        // SAFETY: both owners retain live handles during this identity query.
        if !unsafe { CompareObjectHandles(original.raw(), observer.raw()) }.as_bool() {
            return Err(DebuggerTransportError::SentinelProof);
        }
        // SAFETY: the observer is deliberately SYNCHRONIZE-only. Mutation must
        // fail with access denied and leave the shared event unsignaled.
        let denied = unsafe { SetEvent(observer.raw()) }
            .err()
            .ok_or(DebuggerTransportError::SentinelProof)?;
        if denied.code() != ERROR_ACCESS_DENIED.to_hresult()
            // SAFETY: a zero-timeout wait borrows the live observer only.
            || unsafe { WaitForSingleObject(observer.raw(), 0) } != WAIT_TIMEOUT
        {
            return Err(DebuggerTransportError::SentinelProof);
        }
        // SAFETY: the original CreateEventW handle retains EVENT_MODIFY_STATE.
        unsafe { SetEvent(original.raw()) }.map_err(|_| DebuggerTransportError::SentinelProof)?;
        // SAFETY: the observer owns SYNCHRONIZE access to the identical event.
        if unsafe { WaitForSingleObject(observer.raw(), 1_000) } != WAIT_OBJECT_0 {
            return Err(DebuggerTransportError::SentinelProof);
        }
        Ok(Self {
            _original: original,
            observer,
        })
    }

    #[cfg(test)]
    pub(super) const fn observer(&self) -> &SentinelObserver {
        &self.observer
    }
}

impl core::fmt::Debug for SentinelEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SentinelEvidence([IDENTICAL SYNCHRONIZE-ONLY HANDLE REDACTED])")
    }
}

#[cfg(test)]
pub(super) fn native_granted_access_for_test(
    observer: &SentinelObserver,
) -> Result<u32, DebuggerTransportError> {
    let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let information_size = u32::try_from(size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>())
        .map_err(|_| DebuggerTransportError::SentinelProof)?;
    let mut returned = 0_u32;
    // SAFETY: this kernel-matrix-only query receives one exact live observer,
    // correctly sized initialized output, and writable returned-length storage.
    let status = unsafe {
        NtQueryObject(
            Some(observer.raw()),
            ObjectBasicInformation,
            Some((&raw mut information).cast()),
            information_size,
            Some(&raw mut returned),
        )
    };
    if status != windows::Win32::Foundation::STATUS_SUCCESS || returned != information_size {
        return Err(DebuggerTransportError::SentinelProof);
    }
    Ok(information.GrantedAccess)
}

pub(super) fn current_process_id() -> u32 {
    // SAFETY: this scalar query has no preconditions.
    unsafe { GetCurrentProcessId() }
}

pub(super) fn absolute_tick_deadline(deadline: Instant) -> Result<u64, DebuggerTransportError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(DebuggerTransportError::Deadline)?;
    let rounded = remaining
        .checked_add(Duration::from_nanos(999_999))
        .ok_or(DebuggerTransportError::Deadline)?
        .as_millis();
    let milliseconds =
        u64::try_from(rounded.max(1)).map_err(|_| DebuggerTransportError::Deadline)?;
    if milliseconds > MAX_RUN_MILLISECONDS {
        return Err(DebuggerTransportError::Deadline);
    }
    // SAFETY: this monotonic scalar query has no preconditions.
    let now = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() };
    now.checked_add(milliseconds)
        .filter(|absolute| *absolute != 0)
        .ok_or(DebuggerTransportError::Deadline)
}

const fn debugger_creation_flags() -> PROCESS_CREATION_FLAGS {
    PROCESS_CREATION_FLAGS(
        CREATE_SUSPENDED.0
            | CREATE_NO_WINDOW.0
            | CREATE_UNICODE_ENVIRONMENT.0
            | EXTENDED_STARTUPINFO_PRESENT.0,
    )
}

fn remaining_milliseconds(deadline: Instant) -> Result<u32, DebuggerTransportError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(DebuggerTransportError::Deadline)?;
    let rounded = remaining
        .checked_add(Duration::from_nanos(999_999))
        .ok_or(DebuggerTransportError::Deadline)?
        .as_millis();
    u32::try_from(rounded.max(1)).map_err(|_| DebuggerTransportError::Deadline)
}

fn terminate_live_process_and_reap(
    process: HANDLE,
    code: DebuggerExitCode,
    deadline: Instant,
) -> Result<(), DebuggerTransportError> {
    // SAFETY: the caller retains the identity-validated live process owner.
    let state = unsafe { WaitForSingleObject(process, 0) };
    if state == WAIT_TIMEOUT {
        // SAFETY: the retained creator handle carries termination authority.
        // Natural exit may race this request; only the bounded process-object
        // wait below decides whether cleanup succeeded.
        let _ = unsafe { TerminateProcess(process, exit_code_u32(code)) };
    } else if state != WAIT_OBJECT_0 {
        return Err(DebuggerTransportError::ProcessExit);
    } else {
        // A process already observed terminal needs no termination request; the
        // signaled object itself is the bounded reap proof for this malformed
        // native-success branch.
        return Ok(());
    }
    let timeout = remaining_milliseconds(deadline)?;
    // SAFETY: this bounded wait borrows the retained process owner.
    if unsafe { WaitForSingleObject(process, timeout) } != WAIT_OBJECT_0 {
        return Err(DebuggerTransportError::ProcessExit);
    }
    Ok(())
}

fn fail_fast() -> ! {
    // No attacker-controlled diagnostics are emitted. Aborting prevents the
    // parent from continuing after it cannot prove terminal state. Because this
    // feasibility slice has no kill-on-close Job, abort is not child-death
    // evidence and that containment gap remains explicit STOP-SHIP work.
    std::process::abort()
}

fn handle_flags(handle: HANDLE) -> Result<u32, DebuggerTransportError> {
    let mut flags = HANDLE_FLAG_INHERIT.0;
    // SAFETY: callers retain a live handle for this scalar query.
    unsafe { GetHandleInformation(handle, &raw mut flags) }
        .map_err(|_| DebuggerTransportError::SentinelProof)?;
    Ok(flags)
}

const fn exit_code_u32(code: DebuggerExitCode) -> u32 {
    code.code().cast_unsigned()
}

fn windows_handle(handle: BorrowedHandle<'_>) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

fn windows_owned_handle(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}
