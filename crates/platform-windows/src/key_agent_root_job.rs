//! Dormant root Job Object for the two-process Key Agent topology.
//!
//! The job is configured before any process can be associated with it. Its
//! only creation seam is a lifetime-bound handle borrow intended for
//! `PROC_THREAD_ATTRIBUTE_JOB_LIST`; there is deliberately no process-resume
//! operation and no public raw-handle escape.

#![allow(dead_code)]

use core::fmt;
use std::marker::PhantomData;
use std::os::windows::io::{AsHandle as _, BorrowedHandle, OwnedHandle};
use std::time::Duration;

use thiserror::Error;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;

const KEY_AGENT_ROOT_PROCESS_LIMIT: u32 = 2;
const ROOT_JOB_TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Stable failures from the dormant Key Agent root-job boundary.
///
/// Raw handles, process identifiers, and operating-system diagnostics are
/// intentionally excluded.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum KeyAgentRootJobError {
    /// The supervisor's enclosing Job hierarchy cannot preserve this root
    /// job's deterministic two-process topology.
    #[error("supervisor Job context is unsupported")]
    UnsupportedSupervisorContext,
    /// Windows could not create the unnamed root Job Object.
    #[error("Key Agent root Job creation failed")]
    Creation,
    /// Windows could not install the exact root-job limits.
    #[error("Key Agent root Job configuration failed")]
    Configuration,
    /// The effective root-job limits did not exactly match the requested
    /// fail-closed policy.
    #[error("Key Agent root Job limit verification failed")]
    LimitVerification,
    /// Windows could not query job accounting or membership.
    #[error("Key Agent root Job query failed")]
    Query,
    /// This root Job has already entered terminal shutdown.
    #[error("Key Agent root Job is already shut down")]
    ShutDown,
    /// Windows did not accept whole-job termination.
    #[error("Key Agent root Job termination failed")]
    Termination,
    /// The Job did not become empty inside the fixed cleanup bound.
    #[error("Key Agent root Job termination timed out")]
    TerminationTimeout,
}

/// Opaque ownership of the Key Agent's exact two-process root Job Object.
///
/// This value is crate-private and non-cloneable. Safe borrows prevent a
/// creation attribute from outliving the Job or racing terminal shutdown.
/// Closing its last handle is also kernel-configured to kill the complete
/// contained tree.
pub(crate) struct KeyAgentRootJob {
    handle: OwnedHandle,
    shut_down: bool,
    #[cfg(test)]
    supervisor_context_bypass_for_kernel_test: bool,
}

impl KeyAgentRootJob {
    /// Creates an empty Job, installs the exact limits, and reads them back.
    pub(crate) fn create() -> Result<Self, KeyAgentRootJobError> {
        sys::verify_supervisor_context()?;
        Self::create_configured()
    }

    fn create_configured() -> Result<Self, KeyAgentRootJobError> {
        let handle = sys::create_root_job()?;
        sys::install_exact_limits(handle.as_handle())?;
        sys::verify_exact_limits(handle.as_handle())?;
        Ok(Self {
            handle,
            shut_down: false,
            #[cfg(test)]
            supervisor_context_bypass_for_kernel_test: false,
        })
    }

    #[cfg(test)]
    /// Test-runner-only constructor that bypasses the enclosing-Job rejection.
    pub(crate) fn create_for_kernel_test() -> Result<Self, KeyAgentRootJobError> {
        // Test runners are commonly Job-contained. Kernel tests exercise the
        // isolated object through this seam, while a separate test proves the
        // production constructor rejects a nested supervisor.
        let mut job = Self::create_configured()?;
        job.supervisor_context_bypass_for_kernel_test = true;
        Ok(job)
    }

    /// Borrows the sole job handle for a process-creation attribute list.
    ///
    /// The returned value carries this Job's lifetime. A later attribute-list
    /// wrapper must retain it until `DeleteProcThreadAttributeList` so both the
    /// copied handle value and the underlying Job remain valid through
    /// `CreateProcessW`.
    pub(crate) fn creation_attribute(
        &self,
    ) -> Result<KeyAgentRootJobAttribute<'_>, KeyAgentRootJobError> {
        if self.shut_down {
            return Err(KeyAgentRootJobError::ShutDown);
        }
        Ok(KeyAgentRootJobAttribute {
            handle: Box::new(sys::windows_handle(self.handle.as_handle())),
            _job: PhantomData,
        })
    }

    /// Returns whether the exact process belongs to this root Job.
    pub(crate) fn contains_process(
        &self,
        process: BorrowedHandle<'_>,
    ) -> Result<bool, KeyAgentRootJobError> {
        sys::contains_process(self.handle.as_handle(), process)
    }

    /// Returns the kernel's current count of active processes in this Job.
    pub(crate) fn active_process_count(&self) -> Result<u32, KeyAgentRootJobError> {
        sys::active_process_count(self.handle.as_handle())
    }

    #[cfg(test)]
    pub(crate) fn verify_kernel_fixture_topology_for_test(
        &self,
        expected_process_id: u32,
    ) -> Result<bool, KeyAgentRootJobError> {
        sys::verify_kernel_fixture_topology_for_test(self.handle.as_handle(), expected_process_id)
    }

    /// Re-reads and verifies the exact effective limit record.
    pub(crate) fn verify_effective_limits(&self) -> Result<(), KeyAgentRootJobError> {
        sys::verify_exact_limits(self.handle.as_handle())
    }

    /// Rechecks that the supervisor remains outside every enclosing Job.
    ///
    /// The activation boundary calls this immediately before process creation
    /// and again after exact-image authentication while the child remains
    /// suspended. This turns an external assignment during the setup window
    /// into a fail-closed activation error. Preventing later reassignment still
    /// belongs to the production supervisor process ACL and bootstrap policy.
    pub(crate) fn recheck_supervisor_context(&self) -> Result<(), KeyAgentRootJobError> {
        if self.shut_down {
            return Err(KeyAgentRootJobError::ShutDown);
        }
        #[cfg(test)]
        if self.supervisor_context_bypass_for_kernel_test {
            // The Rust test runner is commonly inside an outer Job. Positive
            // kernel activation tests use an isolated inner object but do not
            // claim evidence for the production supervisor-context policy.
            return Ok(());
        }
        sys::verify_supervisor_context()
    }

    /// Permanently shuts down the Job and synchronously verifies it is empty.
    ///
    /// No creation-attribute borrow can coexist with this mutable borrow. On a
    /// timeout the caller receives an error while `Drop` still retains the
    /// kernel `KILL_ON_JOB_CLOSE` fallback.
    pub(crate) fn terminate_and_wait(&mut self) -> Result<(), KeyAgentRootJobError> {
        if self.shut_down {
            return Ok(());
        }
        sys::terminate_and_wait(self.handle.as_handle(), ROOT_JOB_TERMINATION_TIMEOUT)?;
        self.shut_down = true;
        Ok(())
    }
}

impl Drop for KeyAgentRootJob {
    fn drop(&mut self) {
        // Best-effort synchronous cleanup occurs while the owned handle is
        // still live. Even if querying/waiting fails, field destruction closes
        // the last unshared handle and KILL_ON_JOB_CLOSE remains the fallback.
        let _ = self.terminate_and_wait();
    }
}

impl fmt::Debug for KeyAgentRootJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyAgentRootJob")
            .field("handle", &"[OWNED ROOT JOB HANDLE]")
            .field("active_process_limit", &KEY_AGENT_ROOT_PROCESS_LIMIT)
            .field("kill_on_close", &true)
            .field("breakaway", &false)
            .field("shut_down", &self.shut_down)
            .finish_non_exhaustive()
    }
}

/// Lifetime-bound, non-owning Job handle for one creation attribute list.
///
/// This type intentionally exposes only a standard borrowed handle inside the
/// crate. It has no ownership, duplication, termination, assignment, or resume
/// operation.
pub(crate) struct KeyAgentRootJobAttribute<'job> {
    // Heap allocation keeps the HANDLE value's address stable even when this
    // wrapper or its containing attribute-list owner moves.
    handle: Box<HANDLE>,
    _job: PhantomData<&'job KeyAgentRootJob>,
}

impl KeyAgentRootJobAttribute<'_> {
    /// Installs this single lifetime-bound handle as a Job-list attribute.
    ///
    /// # Safety
    ///
    /// `attribute_list` must be a live, initialized list with capacity for this
    /// attribute, and this value must remain alive until that list is deleted.
    #[allow(unsafe_code)]
    pub(crate) unsafe fn install_into(
        &self,
        attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    ) -> Result<(), KeyAgentRootJobError> {
        // SAFETY: the caller establishes the attribute-list lifetime and this
        // wrapper owns stable HANDLE-value storage tied to the live root Job.
        unsafe { sys::install_creation_attribute(attribute_list, self.handle.as_ref()) }
    }
}

impl fmt::Debug for KeyAgentRootJobAttribute<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentRootJobAttribute([BORROWED ROOT JOB HANDLE])")
    }
}

#[cfg(windows)]
mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
    use std::time::{Duration, Instant};

    #[cfg(test)]
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
        SetInformationJobObject, TerminateJobObject,
    };
    #[cfg(test)]
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows::Win32::System::Threading::GetCurrentProcess;
    #[cfg(test)]
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    #[cfg(test)]
    use windows::core::PWSTR;
    use windows::core::{BOOL, PCWSTR};

    use super::{KEY_AGENT_ROOT_PROCESS_LIMIT, KeyAgentRootJobError};

    const ROOT_JOB_FLAGS: JOB_OBJECT_LIMIT =
        JOB_OBJECT_LIMIT(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0);
    const ROOT_JOB_EXIT_CODE: u32 = 0xE0A1_0002;
    const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(1);

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    struct RootJobProcessIdList {
        number_of_assigned_processes: u32,
        number_of_process_ids_in_list: u32,
        process_ids: [usize; KEY_AGENT_ROOT_PROCESS_LIMIT as usize],
    }

    pub(super) fn verify_supervisor_context() -> Result<(), KeyAgentRootJobError> {
        (!supervisor_is_nested()?)
            .then_some(())
            .ok_or(KeyAgentRootJobError::UnsupportedSupervisorContext)
    }

    fn supervisor_is_nested() -> Result<bool, KeyAgentRootJobError> {
        let mut in_job = BOOL(0);
        // SAFETY: `in_job` is writable BOOL storage. None asks whether the
        // current supervisor belongs to any Job Object. Windows does not offer
        // this boundary a handle enumeration for the complete parent chain, so
        // any nesting prevents an exact whole-topology limit proof.
        unsafe { IsProcessInJob(GetCurrentProcess(), None, &raw mut in_job) }
            .map_err(|_| KeyAgentRootJobError::UnsupportedSupervisorContext)?;
        Ok(in_job.as_bool())
    }

    pub(super) fn create_root_job() -> Result<OwnedHandle, KeyAgentRootJobError> {
        // SAFETY: an unnamed Job uses no retained input pointers.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|_| KeyAgentRootJobError::Creation)?;
        if handle.is_invalid() {
            return Err(KeyAgentRootJobError::Creation);
        }
        // SAFETY: success returned a fresh owned Job handle and this conversion
        // transfers its sole ownership into the standard RAII wrapper.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
    }

    pub(super) fn install_exact_limits(
        job: BorrowedHandle<'_>,
    ) -> Result<(), KeyAgentRootJobError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = ROOT_JOB_FLAGS;
        information.BasicLimitInformation.ActiveProcessLimit = KEY_AGENT_ROOT_PROCESS_LIMIT;
        // SAFETY: job is a live owned Job borrow and `information` is the exact
        // input structure and byte size selected by the information class.
        unsafe {
            SetInformationJobObject(
                windows_handle(job),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&information).cast::<c_void>(),
                structure_size::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()?,
            )
        }
        .map_err(|_| KeyAgentRootJobError::Configuration)
    }

    pub(super) fn verify_exact_limits(job: BorrowedHandle<'_>) -> Result<(), KeyAgentRootJobError> {
        let information = query_extended_limits(Some(windows_handle(job)))?;
        let basic = information.BasicLimitInformation;
        // Fields whose flags are absent are explicitly ignored by Win32 and
        // may read back operating-system defaults (for example scheduling
        // class). Exact flag equality proves none of those fields is active.
        if basic.LimitFlags != ROOT_JOB_FLAGS
            || basic.ActiveProcessLimit != KEY_AGENT_ROOT_PROCESS_LIMIT
            || basic.LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK != JOB_OBJECT_LIMIT(0)
            || basic.LimitFlags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != JOB_OBJECT_LIMIT(0)
        {
            return Err(KeyAgentRootJobError::LimitVerification);
        }
        Ok(())
    }

    pub(super) fn contains_process(
        job: BorrowedHandle<'_>,
        process: BorrowedHandle<'_>,
    ) -> Result<bool, KeyAgentRootJobError> {
        let mut in_job = BOOL(0);
        // SAFETY: both borrows are live for the call and `in_job` is writable.
        unsafe {
            IsProcessInJob(
                windows_handle(process),
                Some(windows_handle(job)),
                &raw mut in_job,
            )
        }
        .map_err(|_| KeyAgentRootJobError::Query)?;
        Ok(in_job.as_bool())
    }

    pub(super) fn active_process_count(
        job: BorrowedHandle<'_>,
    ) -> Result<u32, KeyAgentRootJobError> {
        Ok(active_process_id_list(job)?.number_of_process_ids_in_list)
    }

    fn active_process_id_list(
        job: BorrowedHandle<'_>,
    ) -> Result<RootJobProcessIdList, KeyAgentRootJobError> {
        let mut processes = RootJobProcessIdList::default();
        let buffer_bytes = structure_size::<RootJobProcessIdList>()?;
        let mut returned_bytes = 0_u32;
        // SAFETY: this repr(C) buffer has the documented two DWORD header and
        // exactly the maximum two pointer-sized process-ID slots permitted by
        // this Job. ERROR_MORE_DATA therefore fails closed as a topology
        // violation instead of allocating an attacker-sized buffer.
        unsafe {
            QueryInformationJobObject(
                Some(windows_handle(job)),
                JobObjectBasicProcessIdList,
                ptr::from_mut(&mut processes).cast::<c_void>(),
                buffer_bytes,
                Some(&raw mut returned_bytes),
            )
        }
        .map_err(|_| KeyAgentRootJobError::Query)?;
        let count = processes.number_of_process_ids_in_list;
        let count_usize = usize::try_from(count).map_err(|_| KeyAgentRootJobError::Query)?;
        let header_bytes = size_of::<u32>() * 2;
        let used_bytes = header_bytes
            .checked_add(
                count_usize
                    .checked_mul(size_of::<usize>())
                    .ok_or(KeyAgentRootJobError::Query)?,
            )
            .ok_or(KeyAgentRootJobError::Query)?;
        if processes.number_of_assigned_processes != count
            || count > KEY_AGENT_ROOT_PROCESS_LIMIT
            || returned_bytes
                < u32::try_from(used_bytes).map_err(|_| KeyAgentRootJobError::Query)?
            || returned_bytes > buffer_bytes
            || processes.process_ids[..count_usize].contains(&0)
            || (count == 2 && processes.process_ids[0] == processes.process_ids[1])
        {
            return Err(KeyAgentRootJobError::Query);
        }
        Ok(processes)
    }

    #[cfg(test)]
    pub(super) fn verify_kernel_fixture_topology_for_test(
        job: BorrowedHandle<'_>,
        expected_process_id: u32,
    ) -> Result<bool, KeyAgentRootJobError> {
        let processes = active_process_id_list(job)?;
        let count = usize::try_from(processes.number_of_process_ids_in_list)
            .map_err(|_| KeyAgentRootJobError::Query)?;
        if !(1..=2).contains(&count) {
            return Ok(false);
        }
        let mut system_directory = vec![0_u16; 32_768];
        // SAFETY: the complete fixed-size UTF-16 output buffer is writable.
        let system_length = unsafe { GetSystemDirectoryW(Some(&mut system_directory)) };
        let system_length =
            usize::try_from(system_length).map_err(|_| KeyAgentRootJobError::Query)?;
        if system_length == 0 || system_length >= system_directory.len() {
            return Err(KeyAgentRootJobError::Query);
        }
        let mut expected_conhost = String::from_utf16(
            system_directory
                .get(..system_length)
                .ok_or(KeyAgentRootJobError::Query)?,
        )
        .map_err(|_| KeyAgentRootJobError::Query)?;
        expected_conhost.push_str("\\conhost.exe");

        let mut saw_expected = false;
        let mut saw_system_conhost = false;
        for process_id in &processes.process_ids[..count] {
            let process_id = u32::try_from(*process_id).map_err(|_| KeyAgentRootJobError::Query)?;
            if process_id == expected_process_id {
                if saw_expected {
                    return Ok(false);
                }
                saw_expected = true;
                continue;
            }
            // SAFETY: the scalar process ID is kernel-reported. The returned
            // query handle, when successful, is closed exactly once below.
            let process =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
                    .map_err(|_| KeyAgentRootJobError::Query)?;
            let mut image = [0_u16; 1_024];
            let mut length = u32::try_from(image.len()).map_err(|_| KeyAgentRootJobError::Query)?;
            // SAFETY: the process handle is live and the UTF-16 output buffer
            // and length are writable for the complete call.
            let query = unsafe {
                QueryFullProcessImageNameW(
                    process,
                    PROCESS_NAME_WIN32,
                    PWSTR(image.as_mut_ptr()),
                    &raw mut length,
                )
            };
            // SAFETY: OpenProcess returned this fresh handle above.
            unsafe {
                let _ = CloseHandle(process);
            }
            query.map_err(|_| KeyAgentRootJobError::Query)?;
            let length = usize::try_from(length).map_err(|_| KeyAgentRootJobError::Query)?;
            let image = String::from_utf16(image.get(..length).ok_or(KeyAgentRootJobError::Query)?)
                .map_err(|_| KeyAgentRootJobError::Query)?;
            if saw_system_conhost || !image.eq_ignore_ascii_case(&expected_conhost) {
                return Ok(false);
            }
            saw_system_conhost = true;
        }
        Ok(saw_expected && (count == 1 || saw_system_conhost))
    }

    pub(super) fn terminate_and_wait(
        job: BorrowedHandle<'_>,
        timeout: Duration,
    ) -> Result<(), KeyAgentRootJobError> {
        if active_process_count(job)? == 0 {
            return Ok(());
        }
        // SAFETY: the exact owned root Job remains live throughout this call.
        unsafe { TerminateJobObject(windows_handle(job), ROOT_JOB_EXIT_CODE) }
            .map_err(|_| KeyAgentRootJobError::Termination)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(KeyAgentRootJobError::TerminationTimeout)?;
        loop {
            if active_process_count(job)? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(KeyAgentRootJobError::TerminationTimeout);
            }
            std::thread::sleep(TERMINATION_POLL_INTERVAL);
        }
    }

    pub(super) unsafe fn install_creation_attribute(
        attribute_list: windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
        handle: &HANDLE,
    ) -> Result<(), KeyAgentRootJobError> {
        use windows::Win32::System::Threading::{
            PROC_THREAD_ATTRIBUTE_JOB_LIST, UpdateProcThreadAttribute,
        };

        // SAFETY: caller guarantees a live initialized list and keeps the
        // borrowed attribute (and therefore this stable HANDLE value) alive
        // until the list is deleted.
        unsafe {
            UpdateProcThreadAttribute(
                attribute_list,
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_JOB_LIST)
                    .map_err(|_| KeyAgentRootJobError::Configuration)?,
                Some(ptr::from_ref(handle).cast::<c_void>()),
                size_of::<HANDLE>(),
                None,
                None,
            )
        }
        .map_err(|_| KeyAgentRootJobError::Configuration)
    }

    fn query_extended_limits(
        job: Option<HANDLE>,
    ) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION, KeyAgentRootJobError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        query_information(job, JobObjectExtendedLimitInformation, &mut information)?;
        Ok(information)
    }

    fn query_information<T>(
        job: Option<HANDLE>,
        class: windows::Win32::System::JobObjects::JOBOBJECTINFOCLASS,
        information: &mut T,
    ) -> Result<(), KeyAgentRootJobError> {
        let expected_bytes = structure_size::<T>()?;
        let mut returned_bytes = 0_u32;
        // SAFETY: `information` is live writable storage with the exact byte
        // size selected by `class`; `returned_bytes` is a live output.
        unsafe {
            QueryInformationJobObject(
                job,
                class,
                ptr::from_mut(information).cast::<c_void>(),
                expected_bytes,
                Some(&raw mut returned_bytes),
            )
        }
        .map_err(|_| KeyAgentRootJobError::Query)?;
        if returned_bytes != expected_bytes {
            return Err(KeyAgentRootJobError::Query);
        }
        Ok(())
    }

    fn structure_size<T>() -> Result<u32, KeyAgentRootJobError> {
        u32::try_from(size_of::<T>()).map_err(|_| KeyAgentRootJobError::Query)
    }

    pub(super) fn windows_handle(handle: BorrowedHandle<'_>) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    #[cfg(test)]
    pub(super) const fn exact_limit_flags_for_test() -> JOB_OBJECT_LIMIT {
        ROOT_JOB_FLAGS
    }

    #[cfg(test)]
    pub(super) const fn process_limit_for_test() -> u32 {
        KEY_AGENT_ROOT_PROCESS_LIMIT
    }

    #[cfg(test)]
    pub(super) fn assign_process_for_test(
        job: BorrowedHandle<'_>,
        process: BorrowedHandle<'_>,
    ) -> windows::core::Result<()> {
        use windows::Win32::System::JobObjects::AssignProcessToJobObject;

        // SAFETY: both handles are live for this direct suspended-fixture test.
        unsafe { AssignProcessToJobObject(windows_handle(job), windows_handle(process)) }
    }

    #[cfg(test)]
    pub(super) const fn cleanup_timeout_for_test() -> Duration {
        super::ROOT_JOB_TERMINATION_TIMEOUT
    }

    #[cfg(test)]
    pub(super) fn supervisor_is_nested_for_test() -> Result<bool, KeyAgentRootJobError> {
        supervisor_is_nested()
    }
}

#[cfg(all(test, windows))]
mod tests {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::ffi::OsStr;
    use std::io::Write as _;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::os::windows::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetProcessId, InitializeProcThreadAttributeList,
        LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_CREATION_FLAGS,
        PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, STARTUPINFOEXW,
        WaitForSingleObject,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::{
        KEY_AGENT_ROOT_PROCESS_LIMIT, KeyAgentRootJob, KeyAgentRootJobAttribute,
        KeyAgentRootJobError, ROOT_JOB_TERMINATION_TIMEOUT, sys,
    };

    const FIXTURE_TEST: &str = "key_agent_root_job::tests::headless_inert_fixture";
    const TREE_PARENT_TEST: &str = "key_agent_root_job::tests::headless_tree_parent_fixture";
    const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    #[derive(Debug)]
    struct TestProcess {
        process: OwnedHandle,
        primary_thread: OwnedHandle,
    }

    impl TestProcess {
        fn create_suspended(
            attribute_list: Option<LPPROC_THREAD_ATTRIBUTE_LIST>,
            test_name: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let executable = std::env::current_exe()?;
            let application = wide_nul(executable.as_os_str());
            let mut command_line = wide_nul(OsStr::new(&format!(
                "\"{}\" --exact {test_name} --ignored --test-threads=1",
                executable.display()
            )));
            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = u32::try_from(if attribute_list.is_some() {
                size_of::<STARTUPINFOEXW>()
            } else {
                size_of::<windows::Win32::System::Threading::STARTUPINFOW>()
            })?;
            startup.lpAttributeList = attribute_list.unwrap_or_default();
            let flags = CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | attribute_list.map_or(PROCESS_CREATION_FLAGS::default(), |_| {
                    EXTENDED_STARTUPINFO_PRESENT
                });
            let mut information = PROCESS_INFORMATION::default();
            // SAFETY: the application and mutable command line are NUL
            // terminated and live for the call. The optional attribute list is
            // initialized and retained by its caller. No handles are inherited,
            // and creation is both suspended and headless.
            unsafe {
                CreateProcessW(
                    PCWSTR(application.as_ptr()),
                    Some(PWSTR(command_line.as_mut_ptr())),
                    None,
                    None,
                    false,
                    flags,
                    None,
                    PCWSTR::null(),
                    ptr::from_ref(&startup.StartupInfo),
                    &raw mut information,
                )?;
            }
            let process = owned_handle(information.hProcess)?;
            let primary_thread = owned_handle(information.hThread)?;
            Ok(Self {
                process,
                primary_thread,
            })
        }

        fn resume_once(&self) -> Result<(), Box<dyn std::error::Error>> {
            // SAFETY: this is the still-live primary thread created with one
            // CREATE_SUSPENDED count by this test helper.
            let previous = unsafe { ResumeThread(windows_handle(self.primary_thread.as_handle())) };
            if previous != 1 {
                return Err(std::io::Error::other("unexpected fixture suspend count").into());
            }
            Ok(())
        }

        fn process_id(&self) -> Result<u32, Box<dyn std::error::Error>> {
            // SAFETY: process is the exact live process handle returned by
            // CreateProcessW.
            let process_id = unsafe { GetProcessId(windows_handle(self.process.as_handle())) };
            if process_id == 0 {
                return Err(std::io::Error::other("fixture process ID query failed").into());
            }
            Ok(process_id)
        }

        fn wait_for_exit(&self, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
            let milliseconds = u32::try_from(timeout.as_millis())?;
            // SAFETY: process is a live observation handle and the wait is finite.
            if unsafe {
                WaitForSingleObject(windows_handle(self.process.as_handle()), milliseconds)
            } != WAIT_OBJECT_0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "fixture process did not exit",
                )
                .into());
            }
            Ok(())
        }
    }

    struct TestAttributeList<'job> {
        // Keep the lifetime-bound handle value alive until the native list is
        // deleted. UpdateProcThreadAttribute retains a pointer to this value.
        attribute: KeyAgentRootJobAttribute<'job>,
        words: Vec<usize>,
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    }

    impl<'job> TestAttributeList<'job> {
        fn new(job: &'job KeyAgentRootJob) -> Result<Self, Box<dyn std::error::Error>> {
            let attribute = job.creation_attribute()?;
            let mut bytes = 0_usize;
            // SAFETY: this sizing call uses a null list and initializes bytes.
            let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &raw mut bytes) };
            if bytes == 0 {
                return Err(std::io::Error::other("attribute list sizing failed").into());
            }
            let word_size = size_of::<usize>();
            let word_count = bytes
                .checked_add(word_size - 1)
                .and_then(|rounded| rounded.checked_div(word_size))
                .ok_or_else(|| std::io::Error::other("attribute list size overflow"))?;
            let mut words = vec![0_usize; word_count];
            let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(words.as_mut_ptr().cast::<c_void>());
            // SAFETY: words is aligned writable storage of at least bytes and
            // cannot reallocate while this wrapper is live.
            unsafe {
                InitializeProcThreadAttributeList(Some(pointer), 1, None, &raw mut bytes)?;
            }
            let list = Self {
                attribute,
                words,
                pointer,
            };
            list.install_job_list()?;
            Ok(list)
        }

        fn install_job_list(&self) -> Result<(), Box<dyn std::error::Error>> {
            // SAFETY: pointer is an initialized one-slot list and this wrapper
            // retains `attribute` until Drop deletes that list.
            unsafe { self.attribute.install_into(self.pointer)? };
            Ok(())
        }

        const fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.pointer
        }
    }

    impl Drop for TestAttributeList<'_> {
        fn drop(&mut self) {
            debug_assert!(!self.words.is_empty());
            // SAFETY: initialization succeeded and this pointer is deleted once
            // before its backing words and attribute storage are dropped.
            unsafe { DeleteProcThreadAttributeList(self.pointer) };
        }
    }

    #[derive(Debug)]
    struct TreeMarker(PathBuf);

    impl TreeMarker {
        fn for_parent_process(parent_process_id: u32) -> Result<Self, std::io::Error> {
            if parent_process_id == 0 {
                return Err(std::io::Error::other("invalid tree parent process ID"));
            }
            let path = tree_marker_path(parent_process_id);
            if path.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "tree marker collision",
                ));
            }
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn wait_for_child_process_id(&self) -> Result<u32, Box<dyn std::error::Error>> {
            let deadline = Instant::now()
                .checked_add(ROOT_JOB_TERMINATION_TIMEOUT)
                .ok_or_else(|| std::io::Error::other("tree marker deadline overflow"))?;
            loop {
                match std::fs::read_to_string(&self.0) {
                    Ok(value) => {
                        let process_id = value.parse::<u32>()?;
                        if process_id == 0 {
                            return Err(
                                std::io::Error::other("invalid tree child process ID").into()
                            );
                        }
                        return Ok(process_id);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "tree child marker timed out",
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl Drop for TreeMarker {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn root_job_type_is_non_clone_and_non_copy() {
        let _ = <KeyAgentRootJob as AmbiguousIfClone<_>>::marker;
        let _ = <KeyAgentRootJob as AmbiguousIfCopy<_>>::marker;
        let _ = <KeyAgentRootJobAttribute<'static> as AmbiguousIfClone<_>>::marker;
        let _ = <KeyAgentRootJobAttribute<'static> as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn exact_policy_has_two_processes_kill_on_close_and_no_breakaway() {
        let flags = sys::exact_limit_flags_for_test();
        assert_eq!(sys::process_limit_for_test(), KEY_AGENT_ROOT_PROCESS_LIMIT);
        assert_eq!(KEY_AGENT_ROOT_PROCESS_LIMIT, 2);
        assert_eq!(
            flags,
            JOB_OBJECT_LIMIT(
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0
            )
        );
        assert_eq!(flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT(0));
        assert_eq!(
            flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
            JOB_OBJECT_LIMIT(0)
        );
    }

    #[test]
    fn production_constructor_rejects_any_nested_supervisor_context()
    -> Result<(), Box<dyn std::error::Error>> {
        if sys::supervisor_is_nested_for_test()? {
            assert!(matches!(
                KeyAgentRootJob::create(),
                Err(KeyAgentRootJobError::UnsupportedSupervisorContext)
            ));
        } else {
            let job = KeyAgentRootJob::create()?;
            job.recheck_supervisor_context()?;
            job.verify_effective_limits()?;
        }
        Ok(())
    }

    #[test]
    fn kernel_test_job_marks_the_outer_runner_context_as_bypassed()
    -> Result<(), Box<dyn std::error::Error>> {
        let job = KeyAgentRootJob::create_for_kernel_test()?;
        job.recheck_supervisor_context()?;
        Ok(())
    }

    #[test]
    fn live_job_reads_back_exact_effective_limits() -> Result<(), Box<dyn std::error::Error>> {
        let job = KeyAgentRootJob::create_for_kernel_test()?;
        job.verify_effective_limits()?;
        assert_eq!(job.active_process_count()?, 0);
        assert!(format!("{job:?}").contains("[OWNED ROOT JOB HANDLE]"));
        Ok(())
    }

    #[test]
    fn two_suspended_headless_members_succeed_and_third_is_denied()
    -> Result<(), Box<dyn std::error::Error>> {
        let job = KeyAgentRootJob::create_for_kernel_test()?;
        let attributes = TestAttributeList::new(&job)?;
        let first = TestProcess::create_suspended(Some(attributes.pointer()), FIXTURE_TEST)?;
        let second = TestProcess::create_suspended(Some(attributes.pointer()), FIXTURE_TEST)?;
        assert!(job.contains_process(first.process.as_handle())?);
        assert!(job.contains_process(second.process.as_handle())?);
        assert_eq!(job.active_process_count()?, 2);

        assert!(TestProcess::create_suspended(Some(attributes.pointer()), FIXTURE_TEST).is_err());
        assert_eq!(job.active_process_count()?, 2);
        drop(attributes);
        drop(job);
        first.wait_for_exit(ROOT_JOB_TERMINATION_TIMEOUT)?;
        second.wait_for_exit(ROOT_JOB_TERMINATION_TIMEOUT)?;
        Ok(())
    }

    #[test]
    fn explicit_shutdown_is_terminal_and_waits_until_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut job = KeyAgentRootJob::create_for_kernel_test()?;
        let member = TestProcess::create_suspended(None, FIXTURE_TEST)?;
        sys::assign_process_for_test(job.handle.as_handle(), member.process.as_handle())?;
        assert_eq!(job.active_process_count()?, 1);
        job.terminate_and_wait()?;
        member.wait_for_exit(ROOT_JOB_TERMINATION_TIMEOUT)?;
        assert_eq!(job.active_process_count()?, 0);
        assert!(matches!(
            job.creation_attribute(),
            Err(KeyAgentRootJobError::ShutDown)
        ));
        Ok(())
    }

    #[test]
    fn drop_kills_a_resumed_member_without_a_visible_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let job = KeyAgentRootJob::create_for_kernel_test()?;
        let member = TestProcess::create_suspended(None, FIXTURE_TEST)?;
        sys::assign_process_for_test(job.handle.as_handle(), member.process.as_handle())?;
        member.resume_once()?;
        drop(job);
        member.wait_for_exit(ROOT_JOB_TERMINATION_TIMEOUT)?;
        Ok(())
    }

    #[test]
    fn drop_kills_the_inherited_two_process_tree_headlessly()
    -> Result<(), Box<dyn std::error::Error>> {
        let job = KeyAgentRootJob::create_for_kernel_test()?;
        let attributes = TestAttributeList::new(&job)?;
        let parent = TestProcess::create_suspended(Some(attributes.pointer()), TREE_PARENT_TEST)?;
        drop(attributes);
        let marker = TreeMarker::for_parent_process(parent.process_id()?)?;
        parent.resume_once()?;

        let child_process_id = marker.wait_for_child_process_id()?;
        let child_observation = open_process_observation(child_process_id)?;
        assert!(job.contains_process(parent.process.as_handle())?);
        assert!(job.contains_process(child_observation.as_handle())?);

        // In the supported standalone context, Drop takes the synchronous
        // terminate-and-empty path. In this deliberately nested test harness,
        // aggregate child-job accounting can exceed the local limit and the
        // query fails closed; closing the sole handle must still kill the whole
        // inherited tree through KILL_ON_JOB_CLOSE.
        drop(job);
        parent.wait_for_exit(ROOT_JOB_TERMINATION_TIMEOUT)?;
        wait_for_observation(&child_observation, ROOT_JOB_TERMINATION_TIMEOUT)?;
        Ok(())
    }

    #[test]
    fn cleanup_timeout_is_fixed_and_bounded() {
        assert_eq!(ROOT_JOB_TERMINATION_TIMEOUT, Duration::from_secs(5));
        assert_eq!(
            sys::cleanup_timeout_for_test(),
            ROOT_JOB_TERMINATION_TIMEOUT
        );
    }

    #[test]
    #[ignore = "headless inert child fixture; invoked only by parent kernel tests"]
    fn headless_inert_fixture() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "headless tree parent fixture; invoked only by the parent kernel test"]
    fn headless_tree_parent_fixture() -> Result<(), Box<dyn std::error::Error>> {
        let current_executable = std::env::current_exe()?;
        let mut child = Command::new(current_executable)
            .arg("--exact")
            .arg(FIXTURE_TEST)
            .arg("--ignored")
            .arg("--test-threads=1")
            .creation_flags(CREATE_NO_WINDOW.0)
            .spawn()?;
        let marker_path = tree_marker_path(std::process::id());
        let mut marker = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker_path)?;
        write!(marker, "{}", child.id())?;
        marker.sync_all()?;
        let _ = child.wait()?;
        Ok(())
    }

    fn wide_nul(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(core::iter::once(0)).collect()
    }

    fn owned_handle(handle: HANDLE) -> Result<OwnedHandle, std::io::Error> {
        if handle.is_invalid() {
            return Err(std::io::Error::other("invalid fixture handle"));
        }
        // SAFETY: successful CreateProcessW transferred one owned handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
    }

    fn windows_handle(handle: std::os::windows::io::BorrowedHandle<'_>) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn tree_marker_path(parent_process_id: u32) -> PathBuf {
        std::env::temp_dir().join(format!(
            "your-wallet-key-agent-root-tree-{parent_process_id}.marker"
        ))
    }

    fn open_process_observation(process_id: u32) -> Result<OwnedHandle, std::io::Error> {
        // SAFETY: the access mask is observation-only and process_id came from
        // a freshly synchronized child marker.
        let handle = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                process_id,
            )
        }
        .map_err(|_| std::io::Error::other("tree child observation open failed"))?;
        owned_handle(handle)
    }

    fn wait_for_observation(
        process: &OwnedHandle,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let milliseconds = u32::try_from(timeout.as_millis())?;
        // SAFETY: this is a live SYNCHRONIZE process handle and wait is finite.
        if unsafe { WaitForSingleObject(windows_handle(process.as_handle()), milliseconds) }
            != WAIT_OBJECT_0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tree child process did not exit",
            )
            .into());
        }
        Ok(())
    }
}
