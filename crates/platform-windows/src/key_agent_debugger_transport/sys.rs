//! Native boundary for the dormant debugger parent transport.

#![allow(unsafe_code)]
#![allow(dead_code)] // Native half of an explicitly dormant feasibility surface.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::{size_of, size_of_val};
use core::ptr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
#[cfg(test)]
use std::process::Child;
use std::rc::Rc;
use std::time::{Duration, Instant};

use windows::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DBG_CONTINUE, DUPLICATE_HANDLE_OPTIONS,
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE,
    ERROR_SEM_TIMEOUT, FILETIME, GetHandleInformation, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, CheckRemoteDebuggerPresent, ContinueDebugEvent, DEBUG_EVENT,
    DEBUG_EVENT_CODE, DebugActiveProcessStop, LOAD_DLL_DEBUG_EVENT, WaitForDebugEventEx,
};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS,
    DEBUG_PROCESS, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetCurrentProcessId, GetExitCodeProcess, GetProcessId, GetProcessIdOfThread, GetProcessTimes,
    GetThreadId, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, SetEvent,
    SuspendThread, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
#[cfg(test)]
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};
use windows::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;
use windows::core::{BOOL, PCWSTR};

use key_agent_debugger_wire::DebuggerExitCode;

use super::super::artifact::{
    MappedReleaseDebuggerArtifact, PreparedReleaseDebuggerArtifact,
    authenticate_release_debugger_mapped_image,
};
use super::DebuggerTransportError;
use crate::inheritable_handle_launch::InheritableHandleLaunchFlight;
use crate::pipe::PreparedKeyAgentDebuggerInheritance;
use crate::restricted_process_context::RestrictedProcessContext;

pub(super) const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000;
const FIRST_EVENT_TIMEOUT_MILLISECONDS: u32 = 5_000;
const MAX_RUN_MILLISECONDS: u64 = 5_000;
const JOB_TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(1);
const CREATION_ATTRIBUTE_COUNT: u32 = 2;
const DEBUGGER_CONTAINMENT_ACTIVE_PROCESS_LIMIT: u32 = 2;
const DEBUGGER_CONTAINMENT_JOB_LIMITS: JOB_OBJECT_LIMIT =
    JOB_OBJECT_LIMIT(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0);
const TARGET_PROCESS_REQUESTED_ACCESS: u32 = SYNCHRONIZE_ACCESS | 0x0000_1000 | 0x0000_0001;
const TARGET_PROCESS_GRANTED_ACCESS: u32 = TARGET_PROCESS_REQUESTED_ACCESS;
const TARGET_THREAD_REQUESTED_ACCESS: u32 = SYNCHRONIZE_ACCESS | 0x0000_0800 | 0x0000_0002;
// Current-host object-manager normalization adds THREAD_RESUME when
// THREAD_SUSPEND_RESUME is requested. Supported-kernel generalization remains
// STOP-SHIP; this dormant fixture accepts this one observed granted mask only.
const TARGET_THREAD_GRANTED_ACCESS: u32 = TARGET_THREAD_REQUESTED_ACCESS | 0x0000_1000;
#[cfg(test)]
const PARENT_DEATH_OBSERVATION_ACCESS: u32 =
    PROCESS_QUERY_LIMITED_INFORMATION.0 | PROCESS_SYNCHRONIZE.0;

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
/// The exact policy is kill-on-close plus an active-process limit of two, with
/// neither breakaway mode. Creation-time assignment admits the debugger and
/// inherited Job membership admits exactly one subsequently created target.
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
        information.BasicLimitInformation.ActiveProcessLimit =
            DEBUGGER_CONTAINMENT_ACTIVE_PROCESS_LIMIT;
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
            || !exact_containment_limits(
                information.BasicLimitInformation.LimitFlags,
                information.BasicLimitInformation.ActiveProcessLimit,
            )
        {
            return Err(DebuggerTransportError::JobProof);
        }
        Ok(())
    }

    fn verify_exact_member(
        &self,
        process: HANDLE,
        process_id: u32,
    ) -> Result<(), DebuggerTransportError> {
        self.verify_exact_limits()?;
        if !self.is_member(process)? || !self.has_exact_process_ids(&[process_id])? {
            return Err(DebuggerTransportError::JobProof);
        }
        Ok(())
    }

    fn verify_exact_pair(
        &self,
        debugger_process: HANDLE,
        debugger_process_id: u32,
        target_process: HANDLE,
        target_process_id: u32,
    ) -> Result<(), DebuggerTransportError> {
        self.verify_exact_limits()?;
        if debugger_process_id == 0
            || target_process_id == 0
            || debugger_process_id == target_process_id
            || !self.is_member(debugger_process)?
            || !self.is_member(target_process)?
            || !self.has_exact_process_ids(&[debugger_process_id, target_process_id])?
        {
            return Err(DebuggerTransportError::JobProof);
        }
        Ok(())
    }

    fn prove_slot_not_inherited_by(&self, process: HANDLE) -> Result<(), DebuggerTransportError> {
        if handle_flags(self.raw()).map_err(|_| DebuggerTransportError::JobProof)? != 0 {
            return Err(DebuggerTransportError::JobProof);
        }
        let mut duplicate = HANDLE::default();
        // SAFETY: `process` is the retained debugger process with duplication
        // authority. An inherited handle retains its numeric slot, so probing
        // the exact parent Job word either finds no source slot or duplicates
        // an object that must compare different from this Job. This does not
        // exclude a same-token duplicate placed in another slot.
        let duplicated = unsafe {
            DuplicateHandle(
                process,
                self.raw(),
                GetCurrentProcess(),
                &raw mut duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        };
        match duplicated {
            Err(error) if error.code() == ERROR_INVALID_HANDLE.to_hresult() => Ok(()),
            Err(_) => Err(DebuggerTransportError::JobProof),
            Ok(()) if duplicate.is_invalid() => Err(DebuggerTransportError::JobProof),
            Ok(()) => {
                // SAFETY: successful DuplicateHandle returned one fresh owner.
                let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate.0) };
                // SAFETY: both retained handles are live for this identity
                // comparison. A different object occupying the same numeric
                // child slot is permitted but cannot satisfy Job inheritance.
                let inherited_job =
                    unsafe { CompareObjectHandles(windows_owned_handle(&duplicate), self.raw()) }
                        .as_bool();
                if handle_flags(windows_owned_handle(&duplicate))
                    .map_err(|_| DebuggerTransportError::JobProof)?
                    != 0
                    || inherited_job
                {
                    Err(DebuggerTransportError::JobProof)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn wait_for_exact_member(
        &self,
        process: HANDLE,
        process_id: u32,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        self.verify_exact_limits()?;
        if !self.is_member(process)? {
            return Err(DebuggerTransportError::JobProof);
        }
        loop {
            if self.has_exact_process_ids(&[process_id])? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(DebuggerTransportError::JobProof);
            }
            std::thread::sleep(JOB_TERMINATION_POLL_INTERVAL);
        }
    }

    fn is_member(&self, process: HANDLE) -> Result<bool, DebuggerTransportError> {
        let mut in_job = BOOL(0);
        // SAFETY: the exact process and Job owners remain live and output is
        // one writable BOOL.
        unsafe { IsProcessInJob(process, Some(self.raw()), &raw mut in_job) }
            .map_err(|_| DebuggerTransportError::JobProof)?;
        Ok(in_job.as_bool())
    }

    fn has_exact_process_ids(&self, expected_ids: &[u32]) -> Result<bool, DebuggerTransportError> {
        let facts = self.process_id_facts()?;
        Ok(exact_process_id_topology(facts, expected_ids))
    }

    fn process_id_facts(&self) -> Result<JobProcessIdFacts, DebuggerTransportError> {
        let mut list = TwoProcessIdList::default();
        let mut returned = 0_u32;
        let supplied = u32::try_from(size_of::<TwoProcessIdList>())
            .map_err(|_| DebuggerTransportError::JobProof)?;
        // SAFETY: the output is a repr(C) two-entry extension of the documented
        // variable-size process-id list and the Job remains live throughout.
        unsafe {
            QueryInformationJobObject(
                Some(self.raw()),
                JobObjectBasicProcessIdList,
                ptr::from_mut(&mut list).cast::<c_void>(),
                supplied,
                Some(&raw mut returned),
            )
        }
        .map_err(|_| DebuggerTransportError::JobProof)?;
        let minimum = u32::try_from(size_of::<u32>() * 2 + size_of::<usize>())
            .map_err(|_| DebuggerTransportError::JobProof)?;
        if returned < minimum || returned > supplied {
            return Err(DebuggerTransportError::JobProof);
        }
        Ok(JobProcessIdFacts {
            assigned: list.assigned,
            listed: list.listed,
            ids: list.ids,
        })
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
            .map_err(|_| DebuggerTransportError::JobTermination)
    }

    fn terminate_and_wait_empty(
        &self,
        code: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let active = self.active_process_count();
        let termination = if job_termination_required(active) {
            self.terminate(code)
        } else {
            Ok(())
        };
        let empty = self.wait_until_empty(deadline);
        match (termination, empty) {
            (_, Err(error)) | (Err(error), Ok(())) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    fn wait_until_empty(&self, deadline: Instant) -> Result<(), DebuggerTransportError> {
        loop {
            if self.active_process_count()? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(DebuggerTransportError::JobNotEmpty);
            }
            std::thread::sleep(JOB_TERMINATION_POLL_INTERVAL);
        }
    }
}

fn job_termination_required(active: Result<u32, DebuggerTransportError>) -> bool {
    !matches!(active, Ok(0))
}

impl core::fmt::Debug for DebuggerContainmentJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DebuggerContainmentJob([OWNED HANDLE REDACTED; KILL-ON-CLOSE])")
    }
}

const fn exact_containment_limits(flags: JOB_OBJECT_LIMIT, active_process_limit: u32) -> bool {
    flags.0 == DEBUGGER_CONTAINMENT_JOB_LIMITS.0
        && active_process_limit == DEBUGGER_CONTAINMENT_ACTIVE_PROCESS_LIMIT
        && flags.0 & JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0 != 0
        && flags.0 & JOB_OBJECT_LIMIT_BREAKAWAY_OK.0 == 0
        && flags.0 & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK.0 == 0
}

const fn exact_target_access(process_access: u32, thread_access: u32) -> bool {
    process_access == TARGET_PROCESS_GRANTED_ACCESS && thread_access == TARGET_THREAD_GRANTED_ACCESS
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TwoProcessIdList {
    assigned: u32,
    listed: u32,
    ids: [usize; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JobProcessIdFacts {
    assigned: u32,
    listed: u32,
    ids: [usize; 2],
}

fn exact_process_id_topology(facts: JobProcessIdFacts, expected_ids: &[u32]) -> bool {
    let Ok(expected_count) = u32::try_from(expected_ids.len()) else {
        return false;
    };
    if expected_ids.is_empty()
        || expected_ids.len() > facts.ids.len()
        || facts.assigned != expected_count
        || facts.listed != expected_count
        || expected_ids.contains(&0)
    {
        return false;
    }
    let mut observed = facts.ids;
    observed.sort_unstable();
    let mut expected = [0_usize; 2];
    for (slot, process_id) in expected.iter_mut().zip(expected_ids.iter().copied()) {
        let Ok(process_id) = usize::try_from(process_id) else {
            return false;
        };
        *slot = process_id;
    }
    expected.sort_unstable();
    observed == expected
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingDebugEvent {
    process_id: u32,
    thread_id: u32,
}

struct ReceivedFirstDebugEvent {
    kind: DEBUG_EVENT_CODE,
    process_id: u32,
    thread_id: u32,
    process: HANDLE,
    thread: HANDLE,
    file: Option<CheckedDebugEventFile>,
}

#[derive(Clone, Copy)]
struct DebugEventAliasSlots {
    process: HANDLE,
    thread: HANDLE,
}

#[derive(Clone, Copy)]
struct HandleRetirementObservation {
    query_succeeded: bool,
    error: u32,
}

#[derive(Clone, Copy)]
struct FirstEventFacts {
    kind: DEBUG_EVENT_CODE,
    event_process_id: u32,
    event_thread_id: u32,
    expected_process_id: u32,
    expected_thread_id: u32,
    alias_process_id: u32,
    alias_thread_id: u32,
    alias_thread_process_id: u32,
    proofs: u8,
}

const FIRST_EVENT_FILE_PRESENT: u8 = 1 << 0;
const FIRST_EVENT_PROCESS_ALIAS: u8 = 1 << 1;
const FIRST_EVENT_THREAD_ALIAS: u8 = 1 << 2;
const FIRST_EVENT_ZERO_FLAGS: u8 = 1 << 3;
const ALL_FIRST_EVENT_PROOFS: u8 = FIRST_EVENT_FILE_PRESENT
    | FIRST_EVENT_PROCESS_ALIAS
    | FIRST_EVENT_THREAD_ALIAS
    | FIRST_EVENT_ZERO_FLAGS;

/// Checked owner for the one image-file handle transferred by a debug event.
struct CheckedDebugEventFile {
    handle: Option<HANDLE>,
}

impl CheckedDebugEventFile {
    fn adopt(handle: HANDLE) -> Result<Self, DebuggerTransportError> {
        if handle.is_invalid() {
            return Err(DebuggerTransportError::DebugEvent);
        }
        Ok(Self {
            handle: Some(handle),
        })
    }

    fn raw(&self) -> Result<HANDLE, DebuggerTransportError> {
        self.handle.ok_or(DebuggerTransportError::DebugEvent)
    }

    fn as_borrowed(&self) -> Result<BorrowedHandle<'_>, DebuggerTransportError> {
        let handle = self.raw()?;
        // SAFETY: this checked owner retains the transferred event-file handle
        // for the complete borrow and closes it exactly once afterward.
        Ok(unsafe { BorrowedHandle::borrow_raw(handle.0) })
    }

    fn close(mut self) {
        let Some(handle) = self.handle.take() else {
            fail_fast();
        };
        // SAFETY: this is the exact event-file owner transferred by Windows.
        if unsafe { CloseHandle(handle) }.is_err() {
            // A failed close leaves ownership ambiguous. Continuing could leak
            // a mapped executable authority into later launches.
            fail_fast();
        }
    }
}

impl Drop for CheckedDebugEventFile {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        // SAFETY: unwinding/rejection still owns this exact event-file handle.
        if unsafe { CloseHandle(handle) }.is_err() {
            fail_fast();
        }
    }
}

/// Creator-thread-bound owner from native success through exact detach.
///
/// Drop requests termination before releasing a pending event, detaches on the
/// same thread, and proves both process terminal state and Job active count
/// zero. Any ambiguous cleanup aborts the parent process.
struct AttachedDebuggerCreation {
    process: Option<OwnedHandle>,
    primary_thread: Option<OwnedHandle>,
    job: Option<DebuggerContainmentJob>,
    prepared_artifact: Option<PreparedReleaseDebuggerArtifact>,
    mapped_artifact: Option<MappedReleaseDebuggerArtifact>,
    creation_resource_slots: [HANDLE; 3],
    process_id: u32,
    thread_id: u32,
    pending_event: Option<PendingDebugEvent>,
    event_alias_slots: Option<DebugEventAliasSlots>,
    debug_attached: bool,
    suspend_count: u32,
    released: bool,
    _creator_thread: PhantomData<Rc<()>>,
}

impl AttachedDebuggerCreation {
    fn adopt(
        information: PROCESS_INFORMATION,
        job: DebuggerContainmentJob,
        prepared_artifact: PreparedReleaseDebuggerArtifact,
        creation_resource_slots: [HANDLE; 3],
    ) -> Self {
        let aliased =
            !information.hProcess.is_invalid() && information.hProcess == information.hThread;
        let process = if information.hProcess.is_invalid() {
            None
        } else {
            // SAFETY: successful CreateProcessW returned this fresh process
            // owner; an aliased companion is deliberately not adopted twice.
            Some(unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) })
        };
        let primary_thread = if information.hThread.is_invalid() || aliased {
            None
        } else {
            // SAFETY: the non-invalid, non-aliased fresh thread owner is adopted
            // exactly once before any fallible validation.
            Some(unsafe { OwnedHandle::from_raw_handle(information.hThread.0) })
        };
        Self {
            process,
            primary_thread,
            job: Some(job),
            prepared_artifact: Some(prepared_artifact),
            mapped_artifact: None,
            creation_resource_slots,
            process_id: information.dwProcessId,
            thread_id: information.dwThreadId,
            pending_event: None,
            event_alias_slots: None,
            debug_attached: true,
            suspend_count: 1,
            released: false,
            _creator_thread: PhantomData,
        }
    }

    fn validate_creation(&self) -> Result<(), DebuggerTransportError> {
        let process = self
            .process
            .as_ref()
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        let primary_thread = self
            .primary_thread
            .as_ref()
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        let process_handle = windows_owned_handle(process);
        let thread_handle = windows_owned_handle(primary_thread);
        // SAFETY: both creator-returned owners remain live for scalar queries.
        let actual_process_id = unsafe { GetProcessId(process_handle) };
        // SAFETY: same retained primary-thread owner.
        let actual_thread_id = unsafe { GetThreadId(thread_handle) };
        // SAFETY: same retained thread object, queried for its owning process.
        let thread_process_id = unsafe { GetProcessIdOfThread(thread_handle) };
        if actual_process_id == 0
            || actual_thread_id == 0
            || actual_process_id != self.process_id
            || actual_thread_id != self.thread_id
            || thread_process_id != self.process_id
            || debug_handle_flags(process_handle)? != 0
            || debug_handle_flags(thread_handle)? != 0
        {
            return Err(DebuggerTransportError::ProcessIdentity);
        }
        self.job
            .as_ref()
            .ok_or(DebuggerTransportError::JobProof)?
            .verify_exact_member(process_handle, self.process_id)
    }

    fn release_creation_suspend(&mut self) -> Result<(), DebuggerTransportError> {
        let thread = self
            .primary_thread
            .as_ref()
            .ok_or(DebuggerTransportError::Suspension)?;
        // SAFETY: this exact primary thread has the one CREATE_SUSPENDED count.
        if unsafe { ResumeThread(windows_owned_handle(thread)) } != 1 {
            // An unexpected zero could mean helper user mode was already
            // released; no recoverable rejection can re-establish that order.
            fail_fast();
        }
        self.suspend_count = 0;
        Ok(())
    }

    fn authenticate_first_event(
        &mut self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        if self.suspend_count != 0 || self.pending_event.is_some() {
            return Err(DebuggerTransportError::DebugEvent);
        }
        let mut event = self.receive_first_event(deadline)?;
        self.validate_first_event(&event)?;
        let file = event
            .file
            .take()
            .ok_or(DebuggerTransportError::DebugEvent)?;
        let prepared = self
            .prepared_artifact
            .take()
            .ok_or(DebuggerTransportError::MappedImage)?;
        let mapped = authenticate_release_debugger_mapped_image(prepared, file.as_borrowed()?)
            .map_err(|_| DebuggerTransportError::MappedImage)?;
        self.mapped_artifact = Some(mapped);
        file.close();

        let primary_thread = self
            .primary_thread
            .as_ref()
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        // Windows freezes every thread while reporting this event. The
        // creation suspend was consumed, so the previous explicit count is 0.
        // SAFETY: the exact primary-thread owner remains live.
        if unsafe { SuspendThread(windows_owned_handle(primary_thread)) } != 0 {
            return Err(DebuggerTransportError::Suspension);
        }
        self.suspend_count = 1;
        if Instant::now() >= deadline {
            return Err(DebuggerTransportError::Deadline);
        }
        Ok(())
    }

    fn receive_first_event(
        &mut self,
        deadline: Instant,
    ) -> Result<ReceivedFirstDebugEvent, DebuggerTransportError> {
        let first_event_deadline = deadline.min(
            Instant::now() + Duration::from_millis(u64::from(FIRST_EVENT_TIMEOUT_MILLISECONDS)),
        );
        let timeout = remaining_milliseconds(first_event_deadline)?;
        let mut event = DEBUG_EVENT::default();
        // SAFETY: this exact creator thread owns the debug relationship and the
        // output is complete writable DEBUG_EVENT storage.
        if unsafe { WaitForDebugEventEx(&raw mut event, timeout) }.is_err() {
            // SAFETY: sampled immediately after the failed wait on this thread.
            return Err(if unsafe { GetLastError() } == ERROR_SEM_TIMEOUT {
                DebuggerTransportError::Deadline
            } else {
                DebuggerTransportError::DebugEvent
            });
        }
        self.pending_event = Some(PendingDebugEvent {
            process_id: event.dwProcessId,
            thread_id: event.dwThreadId,
        });
        let creator_process = self
            .process
            .as_ref()
            .map(windows_owned_handle)
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        let creator_thread = self
            .primary_thread
            .as_ref()
            .map(windows_owned_handle)
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        let job = self
            .job
            .as_ref()
            .map(DebuggerContainmentJob::raw)
            .ok_or(DebuggerTransportError::JobProof)?;
        let prepared_artifact = self
            .prepared_artifact
            .as_ref()
            .ok_or(DebuggerTransportError::MappedImage)?;

        let (file, process, thread) = if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
            // SAFETY: the union discriminant was checked immediately above.
            let create = unsafe { event.u.CreateProcessInfo };
            let event_slots = [
                creator_process,
                creator_thread,
                job,
                self.creation_resource_slots[0],
                self.creation_resource_slots[1],
                self.creation_resource_slots[2],
                create.hProcess,
                create.hThread,
                create.hFile,
            ];
            if !raw_handle_slots_are_distinct(&event_slots)
                || !raw_slots_are_distinct_from_artifact(prepared_artifact, &event_slots)
            {
                // Ownership cannot be assigned without risking a stale
                // creator/event alias or double close.
                fail_fast();
            }
            self.register_first_event_alias_slots(create.hProcess, create.hThread);
            (
                Some(CheckedDebugEventFile::adopt(create.hFile)?),
                create.hProcess,
                create.hThread,
            )
        } else {
            let event_file = if event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT {
                // SAFETY: the union discriminant was checked immediately above.
                let load = unsafe { event.u.LoadDll };
                if load.hFile.is_invalid() {
                    None
                } else {
                    let event_slots = [
                        creator_process,
                        creator_thread,
                        job,
                        self.creation_resource_slots[0],
                        self.creation_resource_slots[1],
                        self.creation_resource_slots[2],
                        load.hFile,
                    ];
                    if !raw_handle_slots_are_distinct(&event_slots)
                        || !raw_slots_are_distinct_from_artifact(prepared_artifact, &event_slots)
                    {
                        fail_fast();
                    }
                    Some(CheckedDebugEventFile::adopt(load.hFile)?)
                }
            } else {
                None
            };
            (event_file, HANDLE::default(), HANDLE::default())
        };
        Ok(ReceivedFirstDebugEvent {
            kind: event.dwDebugEventCode,
            process_id: event.dwProcessId,
            thread_id: event.dwThreadId,
            process,
            thread,
            file,
        })
    }

    fn validate_first_event(
        &self,
        event: &ReceivedFirstDebugEvent,
    ) -> Result<(), DebuggerTransportError> {
        if event.process_id != self.process_id || event.thread_id != self.thread_id {
            // DEBUG_ONLY_THIS_PROCESS cannot yield an unrelated first event.
            // There is no exact process authority for a contradictory event,
            // so process-wide abort is the only fail-closed cleanup.
            fail_fast();
        }
        let process = self
            .process
            .as_ref()
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        let primary_thread = self
            .primary_thread
            .as_ref()
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        let process_handle = windows_owned_handle(process);
        let thread_handle = windows_owned_handle(primary_thread);
        let event_process_id = if event.process.is_invalid() {
            0
        } else {
            // SAFETY: CREATE_PROCESS supplied a borrowed live process alias.
            unsafe { GetProcessId(event.process) }
        };
        let event_thread_id = if event.thread.is_invalid() {
            0
        } else {
            // SAFETY: CREATE_PROCESS supplied a borrowed live thread alias.
            unsafe { GetThreadId(event.thread) }
        };
        let event_thread_process_id = if event.thread.is_invalid() {
            0
        } else {
            // SAFETY: same borrowed event-thread alias.
            unsafe { GetProcessIdOfThread(event.thread) }
        };
        let process_alias_matches = !event.process.is_invalid()
            // SAFETY: both handles remain live for this object comparison.
            && unsafe { CompareObjectHandles(event.process, process_handle) }.as_bool();
        let thread_alias_matches = !event.thread.is_invalid()
            // SAFETY: both handles remain live for this object comparison.
            && unsafe { CompareObjectHandles(event.thread, thread_handle) }.as_bool();
        let event_flags_are_zero = !event.process.is_invalid()
            && !event.thread.is_invalid()
            && debug_handle_flags(event.process)? == 0
            && debug_handle_flags(event.thread)? == 0;
        let facts = FirstEventFacts {
            kind: event.kind,
            event_process_id: event.process_id,
            event_thread_id: event.thread_id,
            expected_process_id: self.process_id,
            expected_thread_id: self.thread_id,
            alias_process_id: event_process_id,
            alias_thread_id: event_thread_id,
            alias_thread_process_id: event_thread_process_id,
            proofs: if event.file.is_some() {
                FIRST_EVENT_FILE_PRESENT
            } else {
                0
            } | if process_alias_matches {
                FIRST_EVENT_PROCESS_ALIAS
            } else {
                0
            } | if thread_alias_matches {
                FIRST_EVENT_THREAD_ALIAS
            } else {
                0
            } | if event_flags_are_zero {
                FIRST_EVENT_ZERO_FLAGS
            } else {
                0
            },
        };
        if !exact_first_event_fields(&facts) {
            return Err(DebuggerTransportError::DebugEvent);
        }

        let file_handle = event
            .file
            .as_ref()
            .ok_or(DebuggerTransportError::DebugEvent)?;
        let file_handle = file_handle.raw()?;
        // SAFETY: the event file and both system-managed aliases remain live.
        if unsafe { CompareObjectHandles(file_handle, event.process) }.as_bool()
            // SAFETY: same live handles with deliberately distinct object types.
            || unsafe { CompareObjectHandles(file_handle, event.thread) }.as_bool()
            || debug_handle_flags(file_handle)? != 0
        {
            return Err(DebuggerTransportError::DebugEvent);
        }
        Ok(())
    }

    fn register_first_event_alias_slots(&mut self, process: HANDLE, thread: HANDLE) {
        if self.event_alias_slots.is_some() {
            fail_fast();
        }
        self.event_alias_slots = Some(DebugEventAliasSlots { process, thread });
    }

    fn require_event_alias_slots_retired(&mut self) {
        let Some(slots) = self.event_alias_slots else {
            return;
        };
        // These are system-managed borrowed aliases, not handles owned by this
        // transport. Never CloseHandle them. Immediately after detach, accept
        // only exact invalid-slot observations from this creator thread.
        let process = observe_handle_retirement(slots.process);
        let thread = observe_handle_retirement(slots.thread);
        if !exact_event_alias_retirement(process, thread) {
            fail_fast();
        }
        self.event_alias_slots = None;
    }

    fn detach_while_suspended(&mut self) -> Result<(), DebuggerTransportError> {
        if self.suspend_count != 1 || self.mapped_artifact.is_none() || !self.debug_attached {
            return Err(DebuggerTransportError::DebugDetach);
        }
        let pending = self
            .pending_event
            .ok_or(DebuggerTransportError::DebugDetach)?;
        // SAFETY: these are the exact IDs from the one pending event retained
        // by this creator thread.
        unsafe { ContinueDebugEvent(pending.process_id, pending.thread_id, DBG_CONTINUE) }
            .map_err(|_| DebuggerTransportError::DebugDetach)?;
        self.pending_event = None;
        // SAFETY: this creator thread owns the exact continued relationship.
        unsafe { DebugActiveProcessStop(self.process_id) }
            .map_err(|_| DebuggerTransportError::DebugDetach)?;
        self.debug_attached = false;
        self.require_event_alias_slots_retired();
        self.prove_detached_suspended()
    }

    fn prove_detached_suspended(&self) -> Result<(), DebuggerTransportError> {
        let process = self
            .process
            .as_ref()
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        let primary_thread = self
            .primary_thread
            .as_ref()
            .ok_or(DebuggerTransportError::ProcessIdentity)?;
        let process_handle = windows_owned_handle(process);
        let thread_handle = windows_owned_handle(primary_thread);
        let mut debugger_present = BOOL(1);
        // SAFETY: retained process owner and one writable BOOL are exact.
        unsafe { CheckRemoteDebuggerPresent(process_handle, &raw mut debugger_present) }
            .map_err(|_| DebuggerTransportError::DebugDetach)?;
        // SAFETY: zero-timeout observation cannot release the suspended child.
        let process_state = unsafe { WaitForSingleObject(process_handle, 0) };
        if debugger_present.as_bool() || process_state != WAIT_TIMEOUT {
            return Err(DebuggerTransportError::DebugDetach);
        }
        // A 1->2->1 probe proves one explicit count without allowing execution.
        // SAFETY: the exact live primary-thread owner remains retained.
        let previous = unsafe { SuspendThread(thread_handle) };
        if previous != 1 {
            // Any successful unexpected observation leaves the newly added
            // count in place; rejection cleanup terminates without releasing
            // helper user mode.
            return Err(DebuggerTransportError::Suspension);
        }
        // SAFETY: successful SuspendThread added exactly one count above.
        let resumed = unsafe { ResumeThread(thread_handle) };
        if resumed == u32::MAX {
            return Err(DebuggerTransportError::Suspension);
        }
        if resumed != 2 {
            // A successful unexpected decrement could have released helper
            // user mode after detach; ordinary cleanup cannot undo that race.
            fail_fast();
        }
        self.job
            .as_ref()
            .ok_or(DebuggerTransportError::JobProof)?
            .verify_exact_member(process_handle, self.process_id)
    }

    fn into_child(mut self) -> Result<DebuggerChild, DebuggerTransportError> {
        if self.debug_attached
            || self.pending_event.is_some()
            || self.event_alias_slots.is_some()
            || self.suspend_count != 1
            || self.prepared_artifact.is_some()
        {
            return Err(DebuggerTransportError::DebugDetach);
        }
        let child = DebuggerChild {
            process: self
                .process
                .take()
                .ok_or(DebuggerTransportError::ProcessIdentity)?,
            primary_thread: Some(
                self.primary_thread
                    .take()
                    .ok_or(DebuggerTransportError::ProcessIdentity)?,
            ),
            job: Some(self.job.take().ok_or(DebuggerTransportError::JobProof)?),
            _artifact: self
                .mapped_artifact
                .take()
                .ok_or(DebuggerTransportError::MappedImage)?,
            process_id: self.process_id,
            suspend_count: 1,
            reaped: false,
        };
        self.released = true;
        Ok(child)
    }

    fn abort_and_prove_terminal(&mut self) -> Result<(), DebuggerTransportError> {
        let deadline =
            Instant::now() + Duration::from_millis(u64::from(CLEANUP_TIMEOUT_MILLISECONDS));
        let process_handle = self.process.as_ref().map(windows_owned_handle);
        let already_terminal = process_handle.is_some_and(|process| {
            // SAFETY: this zero-timeout observation borrows the retained owner.
            (unsafe { WaitForSingleObject(process, 0) }) == WAIT_OBJECT_0
        });
        if !already_terminal {
            let job_termination = self
                .job
                .as_ref()
                .ok_or(DebuggerTransportError::JobProof)?
                .terminate(DebuggerExitCode::OperatingSystem);
            let process_termination = process_handle.map_or(Err(()), |process| {
                // SAFETY: this exact creator-returned owner is a fallback to the
                // creation-time containment Job termination request.
                unsafe {
                    TerminateProcess(process, exit_code_u32(DebuggerExitCode::OperatingSystem))
                }
                .map_err(|_| ())
            });
            if job_termination.is_err() && process_termination.is_err() {
                return Err(DebuggerTransportError::ProcessExit);
            }
        }
        if let Some(pending) = self.pending_event {
            // SAFETY: termination was accepted before this exact event is freed.
            unsafe { ContinueDebugEvent(pending.process_id, pending.thread_id, DBG_CONTINUE) }
                .map_err(|_| DebuggerTransportError::DebugDetach)?;
            self.pending_event = None;
        }
        if self.debug_attached {
            // SAFETY: this same creator thread owns the relationship.
            unsafe { DebugActiveProcessStop(self.process_id) }
                .map_err(|_| DebuggerTransportError::DebugDetach)?;
            self.debug_attached = false;
            self.require_event_alias_slots_retired();
        }
        if self.event_alias_slots.is_some() {
            fail_fast();
        }
        if let Some(process) = process_handle {
            let timeout = remaining_milliseconds(deadline)?;
            // SAFETY: the exact retained process owner remains live.
            if unsafe { WaitForSingleObject(process, timeout) } != WAIT_OBJECT_0 {
                return Err(DebuggerTransportError::ProcessExit);
            }
        }
        // Terminal process proof or the creation-time Job termination request
        // now makes the creator thread owner unnecessary. Release it before
        // exact-zero Job accounting on kernels that defer reference teardown.
        drop(self.primary_thread.take());
        self.job
            .as_ref()
            .ok_or(DebuggerTransportError::JobProof)?
            .wait_until_empty(deadline)
    }
}

impl Drop for AttachedDebuggerCreation {
    fn drop(&mut self) {
        if !self.released && self.abort_and_prove_terminal().is_err() {
            fail_fast();
        }
    }
}

impl core::fmt::Debug for AttachedDebuggerCreation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(
            "AttachedDebuggerCreation([THREAD-BOUND DEBUGGEE/EVENT/JOB/ARTIFACT REDACTED])",
        )
    }
}

/// Owned, mapped-image-authenticated and fully detached debugger helper.
pub(super) struct DebuggerChild {
    process: OwnedHandle,
    primary_thread: Option<OwnedHandle>,
    job: Option<DebuggerContainmentJob>,
    _artifact: MappedReleaseDebuggerArtifact,
    process_id: u32,
    suspend_count: u32,
    reaped: bool,
}

#[cfg(test)]
pub(super) type ParentDeathProcessIdentity = (u32, u64);

impl DebuggerChild {
    pub(super) fn create_suspended(
        prepared_artifact: PreparedReleaseDebuggerArtifact,
        context: &RestrictedProcessContext,
        inheritance: &PreparedKeyAgentDebuggerInheritance<'_, '_>,
        flight: &InheritableHandleLaunchFlight<'_>,
        deadline: Instant,
    ) -> Result<Self, DebuggerTransportError> {
        let application = encoded_application(prepared_artifact.path());
        Self::create_suspended_encoded(
            prepared_artifact,
            &application,
            context,
            inheritance,
            flight,
            deadline,
        )
    }

    #[cfg(test)]
    pub(super) fn create_suspended_with_application_override_for_test(
        prepared_artifact: PreparedReleaseDebuggerArtifact,
        application_override: &Path,
        context: &RestrictedProcessContext,
        inheritance: &PreparedKeyAgentDebuggerInheritance<'_, '_>,
        flight: &InheritableHandleLaunchFlight<'_>,
        deadline: Instant,
    ) -> Result<Self, DebuggerTransportError> {
        let application = encoded_application(application_override);
        Self::create_suspended_encoded(
            prepared_artifact,
            &application,
            context,
            inheritance,
            flight,
            deadline,
        )
    }

    fn create_suspended_encoded(
        prepared_artifact: PreparedReleaseDebuggerArtifact,
        application: &[u16],
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
        let creation_resource_slots =
            [attributes.stdin(), attributes.stdout(), attributes.stderr()];
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: the verified absolute application and context buffers are
        // NUL-terminated and retained. The exact HANDLE_LIST contains only the
        // three stdio owners and JOB_LIST assigns the non-inheritable
        // containment Job at creation. DEBUG_PROCESS plus
        // DEBUG_ONLY_THIS_PROCESS establishes one creator-thread-bound first
        // image event while CREATE_SUSPENDED prevents helper user mode.
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
        let native_slots = [
            job.raw(),
            creation_resource_slots[0],
            creation_resource_slots[1],
            creation_resource_slots[2],
            information.hProcess,
            information.hThread,
        ];
        if !raw_handle_slots_are_distinct(&native_slots)
            || !raw_slots_are_distinct_from_artifact(&prepared_artifact, &native_slots)
        {
            // A successful native call with an aliased live slot cannot be
            // adopted or closed without risking stale ownership. Parent abort
            // closes the complete handle table and the kill-on-close Job.
            fail_fast();
        }
        drop(attributes);
        let mut attached = AttachedDebuggerCreation::adopt(
            information,
            job,
            prepared_artifact,
            creation_resource_slots,
        );
        attached.validate_creation()?;
        attached.release_creation_suspend()?;
        attached.authenticate_first_event(deadline)?;
        attached.detach_while_suspended()?;
        attached.into_child()
    }

    pub(super) const fn process_id(&self) -> u32 {
        self.process_id
    }

    #[cfg(test)]
    pub(super) fn prove_pre_ready_parent_death_identity(
        &self,
    ) -> Result<(u32, u64), DebuggerTransportError> {
        let job = self.job.as_ref().ok_or(DebuggerTransportError::JobProof)?;
        job.verify_exact_member(self.process_handle(), self.process_id)?;
        self.prove_parent_death_identity()
    }

    #[cfg(test)]
    pub(super) fn prove_ready_parent_death_identities(
        &self,
        target: &FrozenTargetEvidence,
    ) -> Result<(ParentDeathProcessIdentity, ParentDeathProcessIdentity), DebuggerTransportError>
    {
        target.prove_exact()?;
        self.job
            .as_ref()
            .ok_or(DebuggerTransportError::JobProof)?
            .verify_exact_pair(
                self.process_handle(),
                self.process_id,
                target.process_handle(),
                target.process_id,
            )?;
        Ok((
            self.prove_parent_death_identity()?,
            target.parent_death_identity(),
        ))
    }

    #[cfg(test)]
    fn prove_parent_death_identity(&self) -> Result<(u32, u64), DebuggerTransportError> {
        if self.process_id == 0
            // SAFETY: the retained process owner is live for this scalar query.
            || unsafe { GetProcessId(self.process_handle()) } != self.process_id
            || debug_handle_flags(self.process_handle())? != 0
            // SAFETY: zero-timeout wait observes only helper liveness.
            || unsafe { WaitForSingleObject(self.process_handle(), 0) } != WAIT_TIMEOUT
        {
            return Err(DebuggerTransportError::ProcessIdentity);
        }
        let job = self.job.as_ref().ok_or(DebuggerTransportError::JobProof)?;
        job.verify_exact_limits()?;
        if !job.is_member(self.process_handle())? {
            return Err(DebuggerTransportError::JobProof);
        }
        job.prove_slot_not_inherited_by(self.process_handle())?;
        Ok((
            self.process_id,
            process_creation_time(
                self.process_handle(),
                DebuggerTransportError::ProcessIdentity,
            )?,
        ))
    }

    pub(super) fn install_sentinel(&self) -> Result<(SentinelOwner, u64), DebuggerTransportError> {
        SentinelOwner::create_and_install(self.process_handle())
    }

    pub(super) fn resume_exactly_once(&mut self) -> Result<(), DebuggerTransportError> {
        if self.suspend_count != 1 {
            return Err(DebuggerTransportError::Resume);
        }
        let thread = self
            .primary_thread
            .as_ref()
            .ok_or(DebuggerTransportError::Resume)?;
        // SAFETY: mapped-image authentication and detach installed exactly one
        // explicit count on this retained primary thread.
        if unsafe { ResumeThread(windows_owned_handle(thread)) } != 1 {
            return Err(DebuggerTransportError::Resume);
        }
        self.suspend_count = 0;
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pull_target_topology(
        &self,
        target_process_id: u32,
        target_thread_id: u32,
        process_source_word: u64,
        thread_source_word: u64,
        creation_time: u64,
    ) -> Result<FrozenTargetEvidence, DebuggerTransportError> {
        if target_process_id == 0
            || target_thread_id == 0
            || target_process_id == self.process_id
            || process_source_word == 0
            || thread_source_word == 0
            || process_source_word == thread_source_word
            || creation_time == 0
        {
            return Err(DebuggerTransportError::TargetBinding);
        }
        let process =
            self.pull_target_handle(process_source_word, TARGET_PROCESS_REQUESTED_ACCESS)?;
        let primary_thread =
            self.pull_target_handle(thread_source_word, TARGET_THREAD_REQUESTED_ACCESS)?;
        let target = FrozenTargetEvidence {
            process,
            primary_thread,
            process_id: target_process_id,
            primary_thread_id: target_thread_id,
            creation_time,
        };
        target.prove_exact()?;
        self.job
            .as_ref()
            .ok_or(DebuggerTransportError::JobProof)?
            .verify_exact_pair(
                self.process_handle(),
                self.process_id,
                target.process_handle(),
                target.process_id,
            )?;
        Ok(target)
    }

    fn pull_target_handle(
        &self,
        remote_word: u64,
        exact_access: u32,
    ) -> Result<OwnedHandle, DebuggerTransportError> {
        let remote_word =
            usize::try_from(remote_word).map_err(|_| DebuggerTransportError::TargetPull)?;
        let remote = HANDLE(remote_word as *mut c_void);
        if remote.is_invalid() {
            return Err(DebuggerTransportError::TargetPull);
        }
        let mut observer = HANDLE::default();
        // SAFETY: the retained debugger process names the source table and the
        // frozen frame supplies the exact source word. The new local handle is
        // non-inheritable and receives only the explicit narrow access mask.
        unsafe {
            DuplicateHandle(
                self.process_handle(),
                remote,
                GetCurrentProcess(),
                &raw mut observer,
                exact_access,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| DebuggerTransportError::TargetPull)?;
        if observer.is_invalid() {
            return Err(DebuggerTransportError::TargetPull);
        }
        // SAFETY: DuplicateHandle returned one fresh current-process owner.
        Ok(unsafe { OwnedHandle::from_raw_handle(observer.0) })
    }

    pub(super) fn handoff_target_after_exact_exit(
        mut self,
        target: FrozenTargetEvidence,
        expected: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<DetachedTargetTopology, DebuggerTransportError> {
        self.wait_for_exact_exit(expected, deadline)?;
        let job = self.job.as_ref().ok_or(DebuggerTransportError::JobProof)?;
        job.wait_for_exact_member(target.process_handle(), target.process_id, deadline)?;
        target.prove_exact()?;
        let job = self.job.take().ok_or(DebuggerTransportError::JobProof)?;
        Ok(DetachedTargetTopology {
            job: Some(job),
            target,
            cleaned: false,
        })
    }

    #[cfg(test)]
    pub(super) fn reject_post_exit_target_termination_for_test(
        mut self,
        target: &FrozenTargetEvidence,
        expected: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        self.wait_for_exact_exit(expected, deadline)?;
        let job = self.job.as_ref().ok_or(DebuggerTransportError::JobProof)?;
        job.wait_for_exact_member(target.process_handle(), target.process_id, deadline)?;
        target.terminate_for_test(deadline)?;
        match target.prove_exact() {
            Err(DebuggerTransportError::TargetState) => Ok(()),
            Ok(()) | Err(_) => Err(DebuggerTransportError::TargetProof),
        }
    }

    pub(super) fn terminate_job_and_wait_empty(
        &mut self,
        code: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        self.job
            .as_ref()
            .ok_or(DebuggerTransportError::JobProof)?
            .terminate_and_wait_empty(code, deadline)
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

/// Parent-pulled narrow process and primary-thread handles after exact target
/// identity, creation-time, suspended-count, and Job-pair proof.
pub(super) struct FrozenTargetEvidence {
    process: OwnedHandle,
    primary_thread: OwnedHandle,
    process_id: u32,
    primary_thread_id: u32,
    creation_time: u64,
}

impl FrozenTargetEvidence {
    fn prove_exact(&self) -> Result<(), DebuggerTransportError> {
        let process = self.process_handle();
        let thread = self.thread_handle();
        // SAFETY: both pulled handles remain live for exact scalar identity
        // queries and carry the corresponding limited-query rights.
        let observed_process_id = unsafe { GetProcessId(process) };
        // SAFETY: retained primary-thread observer.
        let observed_thread_id = unsafe { GetThreadId(thread) };
        // SAFETY: retained primary-thread observer.
        let observed_thread_process_id = unsafe { GetProcessIdOfThread(thread) };
        if observed_process_id != self.process_id
            || observed_thread_id != self.primary_thread_id
            || observed_thread_process_id != self.process_id
        {
            return Err(DebuggerTransportError::TargetIdentity);
        }
        if target_handle_flags(process)? != 0 || target_handle_flags(thread)? != 0 {
            return Err(DebuggerTransportError::TargetAccess);
        }
        if native_granted_access(process, DebuggerTransportError::TargetProcessAccess)?
            != TARGET_PROCESS_GRANTED_ACCESS
        {
            return Err(DebuggerTransportError::TargetProcessAccess);
        }
        let thread_access =
            native_granted_access(thread, DebuggerTransportError::TargetThreadAccess)?;
        if thread_access != TARGET_THREAD_GRANTED_ACCESS {
            return Err(DebuggerTransportError::TargetThreadAccess);
        }
        if
        // SAFETY: distinct retained objects are compared without mutation.
        unsafe { CompareObjectHandles(process, thread) }.as_bool()
            // SAFETY: zero-timeout waits only observe target liveness.
            || unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT
            // SAFETY: same for the primary thread.
            || unsafe { WaitForSingleObject(thread, 0) } != WAIT_TIMEOUT
        {
            return Err(DebuggerTransportError::TargetState);
        }

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: all outputs are initialized and the process observer remains
        // live with limited-query rights for the complete call.
        unsafe {
            GetProcessTimes(
                process,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        }
        .map_err(|_| DebuggerTransportError::TargetCreation)?;
        if filetime_word(creation) != self.creation_time {
            return Err(DebuggerTransportError::TargetCreation);
        }

        // A 1->2->1 probe proves the target's one creation suspend count
        // without permitting its primary thread to execute.
        // SAFETY: the exact retained thread has THREAD_SUSPEND_RESUME.
        let previous = unsafe { SuspendThread(thread) };
        if previous != 1 {
            return Err(DebuggerTransportError::Suspension);
        }
        // SAFETY: successful SuspendThread added exactly one count above.
        let resumed = unsafe { ResumeThread(thread) };
        if resumed == u32::MAX {
            return Err(DebuggerTransportError::Suspension);
        }
        if resumed != 2 {
            fail_fast();
        }
        Ok(())
    }

    fn process_handle(&self) -> HANDLE {
        windows_owned_handle(&self.process)
    }

    fn thread_handle(&self) -> HANDLE {
        windows_owned_handle(&self.primary_thread)
    }

    #[cfg(test)]
    const fn parent_death_identity(&self) -> (u32, u64) {
        (self.process_id, self.creation_time)
    }

    #[cfg(test)]
    fn terminate_for_test(&self, deadline: Instant) -> Result<(), DebuggerTransportError> {
        // SAFETY: the exact pulled process observer intentionally carries only
        // TERMINATE, limited-query, and synchronize rights.
        unsafe {
            TerminateProcess(
                self.process_handle(),
                exit_code_u32(DebuggerExitCode::OperatingSystem),
            )
        }
        .map_err(|_| DebuggerTransportError::TargetState)?;
        let timeout = remaining_milliseconds(deadline)?;
        // SAFETY: the retained process observer remains live for this bounded
        // terminal-state wait.
        if unsafe { WaitForSingleObject(self.process_handle(), timeout) } != WAIT_OBJECT_0 {
            return Err(DebuggerTransportError::TargetState);
        }
        Ok(())
    }
}

impl core::fmt::Debug for FrozenTargetEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .write_str("FrozenTargetEvidence([NARROW TARGET PROCESS AND THREAD HANDLES REDACTED])")
    }
}

/// The only Job handle retained by this implementation after the debugger
/// exits, plus the frozen target. System-wide last-handle status is unproved.
pub(super) struct DetachedTargetTopology {
    job: Option<DebuggerContainmentJob>,
    target: FrozenTargetEvidence,
    cleaned: bool,
}

impl DetachedTargetTopology {
    pub(super) fn terminate_and_wait_empty(
        mut self,
        code: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        self.cleanup(code, deadline)?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn prove_parent_death_target_identity(
        &self,
    ) -> Result<(u32, u64), DebuggerTransportError> {
        let job = self.job.as_ref().ok_or(DebuggerTransportError::JobProof)?;
        job.verify_exact_member(self.target.process_handle(), self.target.process_id)?;
        self.target.prove_exact()?;
        Ok(self.target.parent_death_identity())
    }

    fn cleanup(
        &mut self,
        code: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        if self.cleaned {
            return Ok(());
        }
        let job = self.job.as_ref().ok_or(DebuggerTransportError::JobProof)?;
        let topology =
            job.verify_exact_member(self.target.process_handle(), self.target.process_id);
        let containment = job.terminate_and_wait_empty(code, deadline);
        let process_timeout = remaining_milliseconds(deadline)
            .map_err(|_| DebuggerTransportError::TargetProcessTerminal);
        let terminal = process_timeout.and_then(|timeout| {
            // SAFETY: the exact target process observer remains retained. Job
            // zero can precede object signaling briefly, so this wait consumes
            // only the remaining cleanup bound.
            if unsafe { WaitForSingleObject(self.target.process_handle(), timeout) }
                != WAIT_OBJECT_0
            {
                return Err(DebuggerTransportError::TargetProcessTerminal);
            }
            let timeout = remaining_milliseconds(deadline)
                .map_err(|_| DebuggerTransportError::TargetThreadTerminal)?;
            // SAFETY: same bounded terminal proof for the retained thread.
            if unsafe { WaitForSingleObject(self.target.thread_handle(), timeout) } != WAIT_OBJECT_0
            {
                return Err(DebuggerTransportError::TargetThreadTerminal);
            }
            Ok(())
        });
        let (cleaned, result) = detached_cleanup_result(topology, containment, terminal);
        self.cleaned = cleaned;
        result
    }
}

impl Drop for DetachedTargetTopology {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        let deadline =
            Instant::now() + Duration::from_millis(u64::from(CLEANUP_TIMEOUT_MILLISECONDS));
        let cleanup = self.cleanup(DebuggerExitCode::OperatingSystem, deadline);
        if cleanup.is_err() && !self.cleaned {
            fail_fast();
        }
    }
}

fn detached_cleanup_result(
    topology: Result<(), DebuggerTransportError>,
    containment: Result<(), DebuggerTransportError>,
    terminal: Result<(), DebuggerTransportError>,
) -> (bool, Result<(), DebuggerTransportError>) {
    if let Err(error) = containment {
        return (false, Err(error));
    }
    if let Err(error) = terminal {
        return (false, Err(error));
    }
    (true, topology)
}

impl core::fmt::Debug for DetachedTargetTopology {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(
            "DetachedTargetTopology([TARGET PROCESS; PRIMARY THREAD; JOB OWNER REDACTED])",
        )
    }
}

impl Drop for DebuggerChild {
    fn drop(&mut self) {
        if self.reaped {
            let Some(job) = self.job.as_ref() else {
                return;
            };
            let deadline =
                Instant::now() + Duration::from_millis(u64::from(CLEANUP_TIMEOUT_MILLISECONDS));
            if job
                .terminate_and_wait_empty(DebuggerExitCode::OperatingSystem, deadline)
                .is_err()
            {
                fail_fast();
            }
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
    native_granted_access(observer.raw(), DebuggerTransportError::SentinelProof)
}

fn native_granted_access(
    handle: HANDLE,
    failure: DebuggerTransportError,
) -> Result<u32, DebuggerTransportError> {
    let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let information_size =
        u32::try_from(size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>()).map_err(|_| failure)?;
    let mut returned = 0_u32;
    // SAFETY: this dormant proof query receives one exact live observer,
    // correctly sized initialized output, and writable returned-length storage.
    let status = unsafe {
        NtQueryObject(
            Some(handle),
            ObjectBasicInformation,
            Some((&raw mut information).cast()),
            information_size,
            Some(&raw mut returned),
        )
    };
    if status != windows::Win32::Foundation::STATUS_SUCCESS || returned != information_size {
        return Err(failure);
    }
    Ok(information.GrantedAccess)
}

pub(super) fn current_process_id() -> u32 {
    // SAFETY: this scalar query has no preconditions.
    unsafe { GetCurrentProcessId() }
}

#[cfg(test)]
pub(super) fn current_process_creation_time() -> Result<u64, DebuggerTransportError> {
    process_creation_time(
        // SAFETY: this pseudohandle is valid for the lifetime of the process.
        unsafe { GetCurrentProcess() },
        DebuggerTransportError::ProcessIdentity,
    )
}

/// Outer-process observation-only owner bound to one PID and creation time.
#[cfg(test)]
pub(super) struct ParentDeathProcessObservation {
    process: OwnedHandle,
    process_id: u32,
    creation_time: u64,
}

#[cfg(test)]
impl ParentDeathProcessObservation {
    pub(super) fn open_exact(
        process_id: u32,
        creation_time: u64,
    ) -> Result<Self, DebuggerTransportError> {
        if process_id == 0 || creation_time == 0 {
            return Err(DebuggerTransportError::ProcessIdentity);
        }
        // SAFETY: the report supplies a numeric PID only. The returned handle
        // is observation-only, is adopted immediately, and is subsequently
        // bound to creation time to exclude PID reuse.
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                process_id,
            )
        }
        .map_err(|_| DebuggerTransportError::ProcessIdentity)?;
        if process.is_invalid() {
            return Err(DebuggerTransportError::ProcessIdentity);
        }
        // SAFETY: OpenProcess returned one fresh owned handle.
        let process = unsafe { OwnedHandle::from_raw_handle(process.0) };
        let observation = Self {
            process,
            process_id,
            creation_time,
        };
        observation.prove_live()?;
        Ok(observation)
    }

    pub(super) fn prove_live(&self) -> Result<(), DebuggerTransportError> {
        let process = windows_owned_handle(&self.process);
        if
        // SAFETY: the retained observation owner is live for this query.
        unsafe { GetProcessId(process) } != self.process_id
            || handle_flags(process).map_err(|_| DebuggerTransportError::ProcessIdentity)? != 0
            || native_granted_access(process, DebuggerTransportError::ProcessIdentity)?
                != PARENT_DEATH_OBSERVATION_ACCESS
            || process_creation_time(process, DebuggerTransportError::ProcessIdentity)?
                != self.creation_time
            // SAFETY: zero-timeout wait only observes process liveness.
            || unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT
        {
            return Err(DebuggerTransportError::ProcessIdentity);
        }
        Ok(())
    }

    pub(super) fn wait_for_terminal(
        &self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let timeout = remaining_milliseconds(deadline)?;
        // SAFETY: this retained process observer has SYNCHRONIZE and the wait
        // is bounded by the outer fixture deadline.
        if unsafe { WaitForSingleObject(windows_owned_handle(&self.process), timeout) }
            != WAIT_OBJECT_0
        {
            return Err(DebuggerTransportError::ProcessExit);
        }
        Ok(())
    }
}

#[cfg(test)]
impl core::fmt::Debug for ParentDeathProcessObservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .write_str("ParentDeathProcessObservation([QUERY-LIMITED SYNCHRONIZE HANDLE REDACTED])")
    }
}

#[cfg(test)]
pub(super) fn terminate_parent_death_supervisor(
    child: &Child,
) -> Result<(), DebuggerTransportError> {
    prove_parent_death_supervisor_identity(child)?;
    let process = HANDLE(child.as_raw_handle());
    // SAFETY: this exact Child owner has termination authority; the fixture
    // parks only after emitting a fully bound checkpoint report.
    unsafe { TerminateProcess(process, exit_code_u32(DebuggerExitCode::OperatingSystem)) }
        .map_err(|_| DebuggerTransportError::ProcessExit)
}

#[cfg(test)]
pub(super) fn prove_parent_death_supervisor_identity(
    child: &Child,
) -> Result<(u32, u64), DebuggerTransportError> {
    let process = HANDLE(child.as_raw_handle());
    if process.is_invalid()
        || child.id() == 0
        // SAFETY: Child retains its process owner for this identity query.
        || unsafe { GetProcessId(process) } != child.id()
        || handle_flags(process).map_err(|_| DebuggerTransportError::ProcessIdentity)? != 0
        // SAFETY: zero-timeout wait observes only supervisor liveness.
        || unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT
    {
        return Err(DebuggerTransportError::ProcessIdentity);
    }
    Ok((
        child.id(),
        process_creation_time(process, DebuggerTransportError::ProcessIdentity)?,
    ))
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

fn encoded_application(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(core::iter::once(0))
        .collect()
}

fn process_creation_time(
    process: HANDLE,
    failure: DebuggerTransportError,
) -> Result<u64, DebuggerTransportError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: caller retains a process handle with limited-query authority and
    // all four outputs are writable exact FILETIME storage.
    unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .map_err(|_| failure)?;
    let creation = filetime_word(creation);
    if creation == 0 {
        return Err(failure);
    }
    Ok(creation)
}

const fn debugger_creation_flags() -> PROCESS_CREATION_FLAGS {
    PROCESS_CREATION_FLAGS(
        CREATE_SUSPENDED.0
            | CREATE_NO_WINDOW.0
            | CREATE_UNICODE_ENVIRONMENT.0
            | EXTENDED_STARTUPINFO_PRESENT.0
            | DEBUG_PROCESS.0
            | DEBUG_ONLY_THIS_PROCESS.0,
    )
}

fn exact_first_event_fields(facts: &FirstEventFacts) -> bool {
    facts.kind == CREATE_PROCESS_DEBUG_EVENT
        && facts.expected_process_id != 0
        && facts.expected_thread_id != 0
        && facts.event_process_id == facts.expected_process_id
        && facts.event_thread_id == facts.expected_thread_id
        && facts.alias_process_id == facts.expected_process_id
        && facts.alias_thread_id == facts.expected_thread_id
        && facts.alias_thread_process_id == facts.expected_process_id
        && facts.proofs == ALL_FIRST_EVENT_PROOFS
}

const fn exact_event_alias_retirement(
    process: HandleRetirementObservation,
    thread: HandleRetirementObservation,
) -> bool {
    !process.query_succeeded
        && process.error == ERROR_INVALID_HANDLE.0
        && !thread.query_succeeded
        && thread.error == ERROR_INVALID_HANDLE.0
}

fn observe_handle_retirement(handle: HANDLE) -> HandleRetirementObservation {
    let mut flags = 0_u32;
    // SAFETY: the numeric slot is retained only as a borrowed event-alias
    // accounting record. This probe neither adopts nor closes the handle.
    let query_succeeded = unsafe { GetHandleInformation(handle, &raw mut flags) }.is_ok();
    let error = if query_succeeded {
        0
    } else {
        // SAFETY: sampled immediately after the failed query on this same
        // creator thread, before any other Win32 call can overwrite it.
        unsafe { GetLastError() }.0
    };
    HandleRetirementObservation {
        query_succeeded,
        error,
    }
}

fn debug_handle_flags(handle: HANDLE) -> Result<u32, DebuggerTransportError> {
    let mut flags = HANDLE_FLAG_INHERIT.0;
    // SAFETY: callers retain the creator/event handle for this scalar query.
    unsafe { GetHandleInformation(handle, &raw mut flags) }
        .map_err(|_| DebuggerTransportError::DebugEvent)?;
    Ok(flags)
}

fn raw_handle_slots_are_distinct(slots: &[HANDLE]) -> bool {
    for (index, left) in slots.iter().enumerate() {
        if left.is_invalid() {
            continue;
        }
        for right in &slots[index + 1..] {
            if !right.is_invalid() && left == right {
                return false;
            }
        }
    }
    true
}

fn raw_slots_are_distinct_from_artifact(
    artifact: &PreparedReleaseDebuggerArtifact,
    slots: &[HANDLE],
) -> bool {
    slots.iter().filter(|slot| !slot.is_invalid()).all(|slot| {
        // SAFETY: each slot is a live creator/event output for the duration of
        // this synchronous comparison; no ownership is transferred here.
        let borrowed = unsafe { BorrowedHandle::borrow_raw(slot.0) };
        artifact.is_raw_slot_distinct(borrowed)
    })
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

fn target_handle_flags(handle: HANDLE) -> Result<u32, DebuggerTransportError> {
    let mut flags = HANDLE_FLAG_INHERIT.0;
    // SAFETY: callers retain a live pulled target handle for this query.
    unsafe { GetHandleInformation(handle, &raw mut flags) }
        .map_err(|_| DebuggerTransportError::TargetAccess)?;
    Ok(flags)
}

const fn filetime_word(value: FILETIME) -> u64 {
    (value.dwHighDateTime as u64) << 32 | value.dwLowDateTime as u64
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
    use core::ffi::c_void;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Diagnostics::Debug::{
        CREATE_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
    };
    use windows::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS,
        DEBUG_PROCESS, EXTENDED_STARTUPINFO_PRESENT, PROCESS_CREATION_FLAGS,
    };

    use super::{
        ALL_FIRST_EVENT_PROOFS, DEBUGGER_CONTAINMENT_ACTIVE_PROCESS_LIMIT,
        DEBUGGER_CONTAINMENT_JOB_LIMITS, FIRST_EVENT_FILE_PRESENT, FIRST_EVENT_PROCESS_ALIAS,
        FIRST_EVENT_THREAD_ALIAS, FIRST_EVENT_ZERO_FLAGS, FirstEventFacts,
        HandleRetirementObservation, JobProcessIdFacts, TARGET_PROCESS_GRANTED_ACCESS,
        TARGET_PROCESS_REQUESTED_ACCESS, TARGET_THREAD_GRANTED_ACCESS,
        TARGET_THREAD_REQUESTED_ACCESS, debugger_creation_flags, detached_cleanup_result,
        exact_containment_limits, exact_event_alias_retirement, exact_first_event_fields,
        exact_process_id_topology, exact_target_access, job_termination_required,
        raw_handle_slots_are_distinct,
    };

    #[test]
    fn containment_policy_is_kill_and_two_process_limit_without_breakaway() {
        assert_eq!(
            DEBUGGER_CONTAINMENT_JOB_LIMITS,
            JOB_OBJECT_LIMIT(
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0
            )
        );
        assert_eq!(DEBUGGER_CONTAINMENT_ACTIVE_PROCESS_LIMIT, 2);
        assert!(exact_containment_limits(
            DEBUGGER_CONTAINMENT_JOB_LIMITS,
            DEBUGGER_CONTAINMENT_ACTIVE_PROCESS_LIMIT,
        ));
        for rejected_flags in [
            JOB_OBJECT_LIMIT(0),
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_BREAKAWAY_OK,
            JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
            JOB_OBJECT_LIMIT(DEBUGGER_CONTAINMENT_JOB_LIMITS.0 | JOB_OBJECT_LIMIT_BREAKAWAY_OK.0),
            JOB_OBJECT_LIMIT(
                DEBUGGER_CONTAINMENT_JOB_LIMITS.0 | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK.0,
            ),
        ] {
            assert!(!exact_containment_limits(rejected_flags, 2));
        }
        for rejected_limit in [0, 1, 3, u32::MAX] {
            assert!(!exact_containment_limits(
                DEBUGGER_CONTAINMENT_JOB_LIMITS,
                rejected_limit,
            ));
        }
    }

    #[test]
    fn process_id_topology_rejects_every_count_slot_and_identity_mutation() {
        let exact = JobProcessIdFacts {
            assigned: 2,
            listed: 2,
            ids: [11, 12],
        };
        assert!(exact_process_id_topology(exact, &[11, 12]));
        assert!(exact_process_id_topology(
            JobProcessIdFacts {
                ids: [12, 11],
                ..exact
            },
            &[11, 12],
        ));
        for rejected in [
            JobProcessIdFacts {
                assigned: 1,
                ..exact
            },
            JobProcessIdFacts { listed: 1, ..exact },
            JobProcessIdFacts {
                ids: [0, 12],
                ..exact
            },
            JobProcessIdFacts {
                ids: [11, 0],
                ..exact
            },
            JobProcessIdFacts {
                ids: [11, 11],
                ..exact
            },
            JobProcessIdFacts {
                ids: [11, 13],
                ..exact
            },
        ] {
            assert!(!exact_process_id_topology(rejected, &[11, 12]));
        }
        assert!(exact_process_id_topology(
            JobProcessIdFacts {
                assigned: 1,
                listed: 1,
                ids: [11, 0],
            },
            &[11],
        ));
        for rejected_expected in [Vec::new(), vec![0], vec![11, 12, 13]] {
            assert!(!exact_process_id_topology(exact, &rejected_expected));
        }
    }

    #[test]
    fn target_access_masks_reject_every_single_bit_mutation() {
        assert_eq!(
            TARGET_PROCESS_REQUESTED_ACCESS,
            TARGET_PROCESS_GRANTED_ACCESS
        );
        assert_eq!(TARGET_THREAD_REQUESTED_ACCESS, 0x0010_0802);
        assert_eq!(TARGET_THREAD_GRANTED_ACCESS, 0x0010_1802);
        assert!(exact_target_access(
            TARGET_PROCESS_GRANTED_ACCESS,
            TARGET_THREAD_GRANTED_ACCESS,
        ));
        for bit in 0..u32::BITS {
            assert!(!exact_target_access(
                TARGET_PROCESS_GRANTED_ACCESS ^ (1_u32 << bit),
                TARGET_THREAD_GRANTED_ACCESS,
            ));
            assert!(!exact_target_access(
                TARGET_PROCESS_GRANTED_ACCESS,
                TARGET_THREAD_GRANTED_ACCESS ^ (1_u32 << bit),
            ));
        }
    }

    #[test]
    fn cleanup_policy_requests_containment_on_count_error_and_prioritizes_cleanup_failure() {
        assert!(!job_termination_required(Ok(0)));
        assert!(job_termination_required(Ok(1)));
        assert!(job_termination_required(Err(
            super::DebuggerTransportError::JobProof
        )));

        let topology_error = Err(super::DebuggerTransportError::JobProof);
        let containment_error = Err(super::DebuggerTransportError::ProcessExit);
        let terminal_error = Err(super::DebuggerTransportError::TargetState);
        assert_eq!(
            detached_cleanup_result(topology_error, Ok(()), Ok(())),
            (true, topology_error)
        );
        assert_eq!(
            detached_cleanup_result(topology_error, containment_error, Ok(())),
            (false, containment_error)
        );
        assert_eq!(
            detached_cleanup_result(topology_error, Ok(()), terminal_error),
            (false, terminal_error)
        );
    }

    #[test]
    fn creation_flags_are_exactly_suspended_private_debug_process_flags() {
        assert_eq!(
            debugger_creation_flags(),
            PROCESS_CREATION_FLAGS(
                CREATE_SUSPENDED.0
                    | CREATE_NO_WINDOW.0
                    | CREATE_UNICODE_ENVIRONMENT.0
                    | EXTENDED_STARTUPINFO_PRESENT.0
                    | DEBUG_PROCESS.0
                    | DEBUG_ONLY_THIS_PROCESS.0
            )
        );
    }

    #[test]
    fn first_event_classifier_rejects_every_identity_or_ownership_ambiguity() {
        let exact = FirstEventFacts {
            kind: CREATE_PROCESS_DEBUG_EVENT,
            event_process_id: 11,
            event_thread_id: 12,
            expected_process_id: 11,
            expected_thread_id: 12,
            alias_process_id: 11,
            alias_thread_id: 12,
            alias_thread_process_id: 11,
            proofs: ALL_FIRST_EVENT_PROOFS,
        };
        assert!(exact_first_event_fields(&exact));
        for rejected in [
            FirstEventFacts {
                kind: LOAD_DLL_DEBUG_EVENT,
                ..exact
            },
            FirstEventFacts {
                event_process_id: 10,
                ..exact
            },
            FirstEventFacts {
                event_thread_id: 13,
                ..exact
            },
            FirstEventFacts {
                alias_process_id: 10,
                ..exact
            },
            FirstEventFacts {
                alias_thread_id: 13,
                ..exact
            },
            FirstEventFacts {
                alias_thread_process_id: 10,
                ..exact
            },
            FirstEventFacts {
                proofs: ALL_FIRST_EVENT_PROOFS & !FIRST_EVENT_FILE_PRESENT,
                ..exact
            },
            FirstEventFacts {
                proofs: ALL_FIRST_EVENT_PROOFS & !FIRST_EVENT_PROCESS_ALIAS,
                ..exact
            },
            FirstEventFacts {
                proofs: ALL_FIRST_EVENT_PROOFS & !FIRST_EVENT_THREAD_ALIAS,
                ..exact
            },
            FirstEventFacts {
                proofs: ALL_FIRST_EVENT_PROOFS & !FIRST_EVENT_ZERO_FLAGS,
                ..exact
            },
        ] {
            assert!(!exact_first_event_fields(&rejected));
        }
    }

    #[test]
    fn raw_debug_event_slots_must_be_distinct_before_ownership_adoption() {
        let first = HANDLE(core::ptr::without_provenance_mut::<c_void>(1));
        let second = HANDLE(core::ptr::without_provenance_mut::<c_void>(2));
        let third = HANDLE(core::ptr::without_provenance_mut::<c_void>(3));
        assert!(raw_handle_slots_are_distinct(&[
            first,
            second,
            third,
            HANDLE::default(),
        ]));
        assert!(!raw_handle_slots_are_distinct(&[
            first, second, first, third,
        ]));
    }

    #[test]
    fn event_alias_retirement_requires_two_exact_invalid_handle_observations() {
        let invalid = HandleRetirementObservation {
            query_succeeded: false,
            error: windows::Win32::Foundation::ERROR_INVALID_HANDLE.0,
        };
        assert!(exact_event_alias_retirement(invalid, invalid));

        let live = HandleRetirementObservation {
            query_succeeded: true,
            error: 0,
        };
        let ambiguous = HandleRetirementObservation {
            query_succeeded: false,
            error: windows::Win32::Foundation::ERROR_ACCESS_DENIED.0,
        };
        for rejected in [
            (live, invalid),
            (invalid, live),
            (live, live),
            (ambiguous, invalid),
            (invalid, ambiguous),
            (ambiguous, ambiguous),
        ] {
            assert!(!exact_event_alias_retirement(rejected.0, rejected.1));
        }
    }
}
