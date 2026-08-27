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
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
    GetProcessId, GetThreadId, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, SetEvent,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
#[cfg(test)]
use windows::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;
use windows::core::{BOOL, PCWSTR};

use key_agent_debugger_wire::DebuggerExitCode;

use super::DebuggerTransportError;
use crate::inheritable_handle_launch::InheritableHandleLaunchFlight;
use crate::pipe::PreparedKeyAgentDebuggerInheritance;
use crate::restricted_process_context::RestrictedProcessContext;

pub(super) const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000;
const MAX_RUN_MILLISECONDS: u64 = 5_000;
const JOB_TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(1);
const CREATION_ATTRIBUTE_COUNT: u32 = 2;
const DEBUGGER_CONTAINMENT_JOB_LIMITS: JOB_OBJECT_LIMIT =
    JOB_OBJECT_LIMIT(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0);

/// Heap-stable two-slot process attribute list containing exactly three stdio
/// handles and one borrowed containment Job handle. Drop deletes the native
/// list before any backing allocation or borrowed owner can leave scope.
struct DebuggerCreationAttributes<'resources, 'pipes, 'flight> {
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    _words: Vec<usize>,
    handles: Box<[HANDLE; 3]>,
    job_handle: Box<[HANDLE; 1]>,
    _inheritance: &'resources PreparedKeyAgentDebuggerInheritance<'pipes, 'flight>,
    _job: &'resources DebuggerContainmentJob,
}

impl<'resources, 'pipes, 'flight> DebuggerCreationAttributes<'resources, 'pipes, 'flight> {
    fn new(
        inheritance: &'resources PreparedKeyAgentDebuggerInheritance<'pipes, 'flight>,
        job: &'resources DebuggerContainmentJob,
    ) -> Result<Self, DebuggerTransportError> {
        let mut bytes = 0_usize;
        // SAFETY: the documented sizing call uses a null list and initializes
        // `bytes`; its expected false result is not an error.
        let _ = unsafe {
            InitializeProcThreadAttributeList(None, CREATION_ATTRIBUTE_COUNT, None, &raw mut bytes)
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
                CREATION_ATTRIBUTE_COUNT,
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
        let job_handle = Box::new([job.raw()]);
        let attributes = Self {
            pointer,
            _words: words,
            handles,
            job_handle,
            _inheritance: inheritance,
            _job: job,
        };
        attributes.install(
            usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                .map_err(|_| DebuggerTransportError::ProcessCreation)?,
            attributes.handles.as_ref(),
        )?;
        attributes.install(
            usize::try_from(PROC_THREAD_ATTRIBUTE_JOB_LIST)
                .map_err(|_| DebuggerTransportError::ProcessCreation)?,
            attributes.job_handle.as_ref(),
        )?;
        Ok(attributes)
    }

    fn install(&self, kind: usize, handles: &[HANDLE]) -> Result<(), DebuggerTransportError> {
        // SAFETY: the initialized list has one free slot for each call. The
        // boxed handle array and the corresponding resource owner remain
        // address-stable and live until this list is deleted.
        unsafe {
            UpdateProcThreadAttribute(
                self.pointer,
                0,
                kind,
                Some(handles.as_ptr().cast::<c_void>()),
                size_of_val(handles),
                None,
                None,
            )
        }
        .map_err(|_| DebuggerTransportError::ProcessCreation)
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

impl Drop for DebuggerCreationAttributes<'_, '_, '_> {
    fn drop(&mut self) {
        // SAFETY: construction returns only after list initialization. The list
        // owns no backing allocations and is deleted before fields are dropped.
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
    }
}

/// One parent-created and retained handle for the unnamed debugger Job.
///
/// The exact policy is kill-on-close with neither an active-process limit nor
/// either breakaway mode. Creation-time assignment proves the benign suspended
/// helper is a member without prematurely deciding whether a future Key Agent
/// target is an external peer or a descendant in the same Job tree. It does not
/// prove that an executed helper could not duplicate another Job handle.
struct DebuggerContainmentJob(OwnedHandle);

impl DebuggerContainmentJob {
    fn create() -> Result<Self, DebuggerTransportError> {
        // SAFETY: an unnamed Job retains no caller-owned name or descriptor.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|_| DebuggerTransportError::JobPreparation)?;
        if handle.is_invalid() {
            return Err(DebuggerTransportError::JobPreparation);
        }
        // SAFETY: successful creation returned one fresh owned Job handle.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle.0) });
        let mut flags = HANDLE_FLAG_INHERIT.0;
        // SAFETY: the exact Job owner remains live and output is one DWORD.
        unsafe { GetHandleInformation(job.raw(), &raw mut flags) }
            .map_err(|_| DebuggerTransportError::JobPreparation)?;
        if flags != 0 {
            return Err(DebuggerTransportError::JobPreparation);
        }

        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = DEBUGGER_CONTAINMENT_JOB_LIMITS;
        // SAFETY: the exact Job and immutable correctly sized policy remain
        // live for the complete configuration call.
        unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&information).cast::<c_void>(),
                u32::try_from(size_of_val(&information))
                    .map_err(|_| DebuggerTransportError::JobPreparation)?,
            )
        }
        .map_err(|_| DebuggerTransportError::JobPreparation)?;
        job.verify_exact_limits()?;
        Ok(job)
    }

    fn raw(&self) -> HANDLE {
        windows_owned_handle(&self.0)
    }

    fn verify_exact_limits(&self) -> Result<(), DebuggerTransportError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let expected = u32::try_from(size_of_val(&information))
            .map_err(|_| DebuggerTransportError::JobProof)?;
        let mut returned = 0_u32;
        // SAFETY: output is exact writable storage and the Job remains live.
        unsafe {
            QueryInformationJobObject(
                Some(self.raw()),
                JobObjectExtendedLimitInformation,
                ptr::from_mut(&mut information).cast::<c_void>(),
                expected,
                Some(&raw mut returned),
            )
        }
        .map_err(|_| DebuggerTransportError::JobProof)?;
        if returned != expected
            || !exact_containment_limits(information.BasicLimitInformation.LimitFlags)
        {
            return Err(DebuggerTransportError::JobProof);
        }
        Ok(())
    }

    fn verify_exact_member(&self, process: HANDLE) -> Result<(), DebuggerTransportError> {
        self.verify_exact_limits()?;
        let mut in_job = BOOL(0);
        // SAFETY: the exact process and Job owners remain live and output is
        // one writable BOOL.
        unsafe { IsProcessInJob(process, Some(self.raw()), &raw mut in_job) }
            .map_err(|_| DebuggerTransportError::JobProof)?;
        if !in_job.as_bool() || self.active_process_count()? != 1 {
            return Err(DebuggerTransportError::JobProof);
        }
        Ok(())
    }

    fn active_process_count(&self) -> Result<u32, DebuggerTransportError> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let expected = u32::try_from(size_of_val(&accounting))
            .map_err(|_| DebuggerTransportError::JobProof)?;
        let mut returned = 0_u32;
        // SAFETY: output is the exact structure selected by the information
        // class and the Job remains live for the complete query.
        unsafe {
            QueryInformationJobObject(
                Some(self.raw()),
                JobObjectBasicAccountingInformation,
                ptr::from_mut(&mut accounting).cast::<c_void>(),
                expected,
                Some(&raw mut returned),
            )
        }
        .map_err(|_| DebuggerTransportError::JobProof)?;
        if returned != expected {
            return Err(DebuggerTransportError::JobProof);
        }
        Ok(accounting.ActiveProcesses)
    }

    fn terminate(&self, code: DebuggerExitCode) -> Result<(), DebuggerTransportError> {
        // SAFETY: this is the retained exact Job, so termination targets every
        // process still associated with it. Pre-resume readback excludes
        // breakaway then; excluding post-resume policy mutation or escape by an
        // executed helper remains production STOP-SHIP.
        unsafe { TerminateJobObject(self.raw(), exit_code_u32(code)) }
            .map_err(|_| DebuggerTransportError::ProcessExit)
    }

    fn terminate_and_wait_empty(
        &self,
        code: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        if self.active_process_count()? != 0 {
            self.terminate(code)?;
        }
        self.wait_until_empty(deadline)
    }

    fn wait_until_empty(&self, deadline: Instant) -> Result<(), DebuggerTransportError> {
        loop {
            if self.active_process_count()? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(DebuggerTransportError::ProcessExit);
            }
            std::thread::sleep(JOB_TERMINATION_POLL_INTERVAL);
        }
    }
}

impl core::fmt::Debug for DebuggerContainmentJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DebuggerContainmentJob([OWNED HANDLE REDACTED; KILL-ON-CLOSE])")
    }
}

const fn exact_containment_limits(flags: JOB_OBJECT_LIMIT) -> bool {
    flags.0 == DEBUGGER_CONTAINMENT_JOB_LIMITS.0
        && flags.0 & JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0 == 0
        && flags.0 & JOB_OBJECT_LIMIT_BREAKAWAY_OK.0 == 0
        && flags.0 & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK.0 == 0
}

/// Owned debugger process and its not-yet-consumed primary-thread handle.
pub(super) struct DebuggerChild {
    process: OwnedHandle,
    primary_thread: Option<OwnedHandle>,
    job: Option<DebuggerContainmentJob>,
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
        let job = DebuggerContainmentJob::create()?;
        let attributes = DebuggerCreationAttributes::new(inheritance, &job)?;
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
        // its attributes are one HANDLE_LIST with the three live inheritable
        // stdio handles created under `flight` and one borrowed JOB_LIST with
        // the configured non-inheritable containment Job. TRUE inheritance
        // therefore has exactly stdin/stdout/stderr as candidates. Flags are
        // the exact dormant helper policy and keep user code suspended through
        // return while Job assignment occurs as part of creation.
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
        drop(attributes);
        Self::adopt(information, job)
    }

    fn adopt(
        information: PROCESS_INFORMATION,
        job: DebuggerContainmentJob,
    ) -> Result<Self, DebuggerTransportError> {
        if information.hProcess.is_invalid()
            || information.hThread.is_invalid()
            || information.hProcess == information.hThread
        {
            let cleanup_deadline =
                Instant::now() + Duration::from_millis(u64::from(CLEANUP_TIMEOUT_MILLISECONDS));
            // A successful CreateProcessW contract with JOB_LIST assigned the
            // child before its initial thread can run. Even if the impossible
            // native output omitted the process handle, this retained Job can
            // terminate its complete membership and prove exact-zero accounting.
            if information.hProcess.is_invalid() {
                let termination = job.active_process_count().and_then(|active| {
                    if active == 0 {
                        Ok(())
                    } else {
                        job.terminate(DebuggerExitCode::OperatingSystem)
                    }
                });
                if termination.is_err() {
                    fail_fast();
                }
                if !information.hThread.is_invalid() {
                    // SAFETY: the Job was already empty or termination was
                    // requested before this unique fresh companion reference is
                    // released. This avoids retaining a thread handle while
                    // exact-zero accounting is polled on kernels that defer the
                    // decrement for references.
                    unsafe { drop(OwnedHandle::from_raw_handle(information.hThread.0)) };
                }
                if job.wait_until_empty(cleanup_deadline).is_err() {
                    fail_fast();
                }
                return Err(DebuggerTransportError::ProcessIdentity);
            }
            // SAFETY: the fresh non-invalid process half from successful native
            // output is uniquely adopted before any fallible observation. Its
            // object identity, not the potentially corrupted scalar PID output,
            // is the authority used for cleanup below.
            let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
            // The exact fresh process object and containment Job are both safe
            // cleanup authorities even if scalar IDs or the companion handle
            // are malformed.
            if terminate_live_process_and_reap(
                windows_owned_handle(&process),
                &job,
                DebuggerExitCode::OperatingSystem,
                cleanup_deadline,
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
        let identity_valid = actual_process_id != 0
            && actual_thread_id != 0
            && actual_process_id == information.dwProcessId
            && actual_thread_id == information.dwThreadId;
        let job_valid = job.verify_exact_member(process_handle).is_ok();
        if !identity_valid || !job_valid {
            let rejection = if identity_valid {
                DebuggerTransportError::JobProof
            } else {
                DebuggerTransportError::ProcessIdentity
            };
            let mut rejected = Self {
                process,
                primary_thread: Some(primary_thread),
                job: Some(job),
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
            return Err(rejection);
        }
        Ok(Self {
            process,
            primary_thread: Some(primary_thread),
            job: Some(job),
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
        self.wait_for_terminal(deadline)?;
        let mut exit_code = u32::MAX;
        // SAFETY: the exact process is signaled and output storage is writable.
        unsafe { GetExitCodeProcess(self.process_handle(), &raw mut exit_code) }
            .map_err(|_| DebuggerTransportError::ProcessExit)?;
        if exit_code != exit_code_u32(expected) {
            return Err(DebuggerTransportError::ProcessExit);
        }
        Ok(())
    }

    fn wait_for_terminal(&mut self, deadline: Instant) -> Result<(), DebuggerTransportError> {
        let timeout = remaining_milliseconds(deadline)?;
        // SAFETY: the process handle is retained and the wait is finite.
        if unsafe { WaitForSingleObject(self.process_handle(), timeout) } != WAIT_OBJECT_0 {
            return Err(DebuggerTransportError::ProcessExit);
        }
        // A signaled process object is exact helper-process terminal proof,
        // independently of any subsequent diagnostic exit-code query.
        self.reaped = true;
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
            let job_termination = self
                .job
                .as_ref()
                .ok_or(DebuggerTransportError::JobProof)
                .and_then(|job| job.terminate(code));
            // SAFETY: this owner retains termination authority from process
            // creation. This is a fallback if the Job request failed or a
            // natural exit won either request; only the following wait proves
            // terminal state.
            let process_termination =
                unsafe { TerminateProcess(self.process_handle(), exit_code_u32(code)) };
            if job_termination.is_err() && process_termination.is_err() {
                return Err(DebuggerTransportError::ProcessExit);
            }
        } else if state != WAIT_OBJECT_0 {
            return Err(DebuggerTransportError::ProcessExit);
        }
        self.wait_for_exact_exit(code, deadline)
    }

    fn close_job_and_wait_for_terminal(
        &mut self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let job = self.job.take().ok_or(DebuggerTransportError::JobProof)?;
        // This closes the Job handle retained by this implementation. The live
        // suspended helper becoming terminal is benign current-host evidence
        // for last-close mechanics; this test neither enumerates nor excludes
        // system-wide duplicates. Production must prove that separately.
        drop(job);
        self.wait_for_terminal(deadline)
    }

    #[cfg(test)]
    pub(super) fn close_job_and_wait_for_terminal_for_test(
        &mut self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        self.close_job_and_wait_for_terminal(deadline)
    }

    #[cfg(test)]
    pub(super) fn terminate_job_and_wait_empty_without_process_for_test(
        &mut self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        if self
            .job
            .as_ref()
            .ok_or(DebuggerTransportError::JobProof)?
            .active_process_count()?
            != 1
        {
            return Err(DebuggerTransportError::JobProof);
        }
        // The thread remains suspended; releasing only its creator handle
        // avoids making that reference a prerequisite for Job accounting.
        drop(self.primary_thread.take());
        self.job
            .as_ref()
            .ok_or(DebuggerTransportError::JobProof)?
            .terminate_and_wait_empty(DebuggerExitCode::OperatingSystem, deadline)?;
        // Creation-time membership and the Job's exact-zero accounting prove
        // this one suspended helper terminal without consulting its process
        // handle, matching the malformed native-success cleanup authority.
        self.reaped = true;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn observe_exact_exit_without_reaping_for_test(
        &self,
        expected: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let timeout = remaining_milliseconds(deadline)?;
        // SAFETY: the test retains the exact process owner. This deliberately
        // observes terminal state without updating `reaped`, so Drop exercises
        // its natural-exit/expected-code-mismatch cleanup branch.
        if unsafe { WaitForSingleObject(self.process_handle(), timeout) } != WAIT_OBJECT_0 {
            return Err(DebuggerTransportError::ProcessExit);
        }
        let mut exit_code = u32::MAX;
        // SAFETY: the exact process is signaled and output storage is writable.
        unsafe { GetExitCodeProcess(self.process_handle(), &raw mut exit_code) }
            .map_err(|_| DebuggerTransportError::ProcessExit)?;
        if exit_code != exit_code_u32(expected) {
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
            let containment_deadline =
                Instant::now() + Duration::from_millis(u64::from(CLEANUP_TIMEOUT_MILLISECONDS));
            if self
                .close_job_and_wait_for_terminal(containment_deadline)
                .is_err()
                && !self.reaped
            {
                // The abort closes the complete parent handle table, including
                // any Job handle still retained here, and prevents this parent
                // from continuing without terminal proof. It does not prove a
                // system-wide last Job close after helper code has run; future
                // production admission must exclude duplicated Job handles.
                fail_fast();
            }
        }
    }
}

impl core::fmt::Debug for DebuggerChild {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DebuggerChild([PROCESS; PRIMARY THREAD; CONTAINMENT JOB REDACTED])")
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
    job: &DebuggerContainmentJob,
    code: DebuggerExitCode,
    deadline: Instant,
) -> Result<(), DebuggerTransportError> {
    // SAFETY: the caller retains the fresh non-invalid process-handle output;
    // an unexpected object type fails the wait/termination calls closed.
    let state = unsafe { WaitForSingleObject(process, 0) };
    if state == WAIT_TIMEOUT {
        let job_termination = job.terminate(code);
        // SAFETY: the retained creator handle carries termination authority as
        // an exact fallback if Job termination failed. Natural exit may race
        // either request; only the bounded process-object wait below decides
        // whether cleanup succeeded.
        let process_termination = unsafe { TerminateProcess(process, exit_code_u32(code)) };
        if job_termination.is_err() && process_termination.is_err() {
            return Err(DebuggerTransportError::ProcessExit);
        }
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
    // parent from continuing after it cannot prove terminal state and closes
    // every Job handle retained by this process. KILL_ON_JOB_CLOSE terminates
    // members only when the system-wide last Job handle closes; proving that an
    // executed helper could not duplicate one remains production STOP-SHIP.
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

#[cfg(test)]
mod tests {
    use windows::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };

    use super::{DEBUGGER_CONTAINMENT_JOB_LIMITS, exact_containment_limits};

    #[test]
    fn containment_policy_is_kill_only_without_topology_or_breakaway_policy() {
        assert_eq!(
            DEBUGGER_CONTAINMENT_JOB_LIMITS,
            JOB_OBJECT_LIMIT(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0)
        );
        assert!(exact_containment_limits(DEBUGGER_CONTAINMENT_JOB_LIMITS));
        for rejected in [
            JOB_OBJECT_LIMIT(0),
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_BREAKAWAY_OK,
            JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
            JOB_OBJECT_LIMIT(
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0,
            ),
            JOB_OBJECT_LIMIT(
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_BREAKAWAY_OK.0,
            ),
            JOB_OBJECT_LIMIT(
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK.0,
            ),
        ] {
            assert!(!exact_containment_limits(rejected));
        }
    }
}
