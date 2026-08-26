//! One-process Job Object for the debug-only service helper launch probe.
//!
//! This is deliberately distinct from the two-process Key Agent root Job. It
//! proves only an exact one-child, kill-on-close creation primitive and has no
//! production process-launch caller yet.

#![allow(dead_code)]
#![deny(unsafe_code)]

use core::cell::Cell;
use core::fmt;
use std::marker::PhantomData;
use std::os::windows::io::{AsHandle as _, BorrowedHandle, OwnedHandle};
use std::time::Duration;

use thiserror::Error;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};
use windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;

const SERVICE_PROBE_PROCESS_LIMIT: u32 = 1;
const SERVICE_PROBE_TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);
const SERVICE_PROBE_JOB_FLAGS: JOB_OBJECT_LIMIT =
    JOB_OBJECT_LIMIT(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0);

/// Data-free failures from the service helper Job feasibility boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum ServiceProbeJobError {
    /// The service is already enclosed by a Job, so exact root ownership is
    /// not established by this primitive.
    #[error("service helper Job context is unsupported")]
    NestedService,
    /// Windows could not create the unnamed Job.
    #[error("service helper Job creation is unavailable")]
    Creation,
    /// Windows could not install the exact limits or creation attribute.
    #[error("service helper Job configuration is unavailable")]
    Configuration,
    /// Effective limits differed from the exact one-process policy.
    #[error("service helper Job limits did not match")]
    LimitVerification,
    /// Membership or accounting could not be observed exactly.
    #[error("service helper Job query is unavailable")]
    Query,
    /// Whole-Job termination has been requested, so no further admission or
    /// ordinary observation is permitted.
    #[error("service helper Job termination is pending")]
    TerminationPending,
    /// Post-join completion was attempted before whole-Job termination had
    /// been requested.
    #[error("service helper Job termination was not requested")]
    TerminationNotRequested,
    /// Terminal cleanup has already completed.
    #[error("service helper Job is already shut down")]
    ShutDown,
    /// Whole-Job termination failed.
    #[error("service helper Job termination is unavailable")]
    Termination,
    /// The Job did not become empty inside the fixed bound.
    #[error("service helper Job termination timed out")]
    TerminationTimeout,
}

trait JobPrepareOps {
    type Handle;

    fn require_non_nested(&self) -> Result<(), ServiceProbeJobError>;

    fn create(&self) -> Result<Self::Handle, ServiceProbeJobError>;

    fn install_limits(&self, handle: &Self::Handle) -> Result<(), ServiceProbeJobError>;

    fn verify_limits(&self, handle: &Self::Handle) -> Result<(), ServiceProbeJobError>;
}

fn prepare_job<O: JobPrepareOps>(ops: &O) -> Result<O::Handle, ServiceProbeJobError> {
    ops.require_non_nested()?;
    let handle = ops.create()?;
    ops.install_limits(&handle)?;
    ops.verify_limits(&handle)?;
    ops.require_non_nested()?;
    Ok(handle)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceProbeJobState {
    Active,
    TerminationRequested,
    ShutDown,
}

trait JobTerminationOps {
    fn request_termination(&self) -> Result<(), ServiceProbeJobError>;

    fn wait_until_empty(&self, timeout: Duration) -> Result<(), ServiceProbeJobError>;
}

fn require_active_job(state: ServiceProbeJobState) -> Result<(), ServiceProbeJobError> {
    match state {
        ServiceProbeJobState::Active => Ok(()),
        ServiceProbeJobState::TerminationRequested => Err(ServiceProbeJobError::TerminationPending),
        ServiceProbeJobState::ShutDown => Err(ServiceProbeJobError::ShutDown),
    }
}

fn request_job_termination<O: JobTerminationOps>(
    state: &mut ServiceProbeJobState,
    ops: &O,
) -> Result<(), ServiceProbeJobError> {
    require_active_job(*state)?;
    // Latch before the native call. Even a failed termination attempt must
    // permanently forbid later admission through this Job owner.
    *state = ServiceProbeJobState::TerminationRequested;
    ops.request_termination()
}

fn finish_job_termination_and_wait<O: JobTerminationOps>(
    state: &mut ServiceProbeJobState,
    ops: &O,
    timeout: Duration,
) -> Result<(), ServiceProbeJobError> {
    match *state {
        ServiceProbeJobState::Active => {
            return Err(ServiceProbeJobError::TerminationNotRequested);
        }
        ServiceProbeJobState::TerminationRequested => {}
        ServiceProbeJobState::ShutDown => return Err(ServiceProbeJobError::ShutDown),
    }
    ops.wait_until_empty(timeout)?;
    *state = ServiceProbeJobState::ShutDown;
    Ok(())
}

fn terminate_job_and_wait<O: JobTerminationOps>(
    state: &mut ServiceProbeJobState,
    ops: &O,
    timeout: Duration,
) -> Result<(), ServiceProbeJobError> {
    if *state == ServiceProbeJobState::Active {
        request_job_termination(state, ops)?;
    }
    finish_job_termination_and_wait(state, ops, timeout)
}

/// Move-only ownership of one exact, unnamed, one-process Job Object.
///
/// The final handle close remains kill-authoritative. This owner is `Send` but
/// deliberately `!Sync`; one dedicated launch/debug thread must sequence its
/// admission, observation, and terminal cleanup.
pub(super) struct ServiceProbeJob {
    handle: OwnedHandle,
    state: ServiceProbeJobState,
    _not_sync: PhantomData<Cell<()>>,
}

impl ServiceProbeJob {
    /// Creates an empty non-nested Job, installs the exact limits, and reads
    /// them back before returning any creation attribute.
    pub(super) fn create_non_nested() -> Result<Self, ServiceProbeJobError> {
        let handle = prepare_job(&sys::WindowsJobPrepareOps)?;
        Ok(Self {
            handle,
            state: ServiceProbeJobState::Active,
            _not_sync: PhantomData,
        })
    }

    /// Revalidates the enclosing-service and Job-limit assumptions immediately
    /// before a future creation call.
    pub(super) fn recheck_non_nested(&self) -> Result<(), ServiceProbeJobError> {
        require_active_job(self.state)?;
        sys::require_current_process_not_in_job()?;
        sys::verify_exact_limits(self.handle.as_handle())
    }

    /// Returns one lifetime-bound, stable Job-list attribute value.
    pub(super) fn creation_attribute(
        &self,
    ) -> Result<ServiceProbeJobAttribute<'_>, ServiceProbeJobError> {
        self.recheck_non_nested()?;
        Ok(ServiceProbeJobAttribute {
            handle: Box::new(sys::windows_handle(self.handle.as_handle())),
            _job: PhantomData,
        })
    }

    /// Observes exact membership of a retained process object.
    pub(super) fn contains_process(
        &self,
        process: BorrowedHandle<'_>,
    ) -> Result<bool, ServiceProbeJobError> {
        require_active_job(self.state)?;
        sys::contains_process(self.handle.as_handle(), process)
    }

    /// Returns the exact active process count, bounded by the one-process
    /// topology rather than an attacker-sized allocation.
    pub(super) fn active_process_count(&self) -> Result<u32, ServiceProbeJobError> {
        require_active_job(self.state)?;
        sys::active_process_count(self.handle.as_handle())
    }

    /// Requests whole-Job termination without querying, waiting, or sleeping.
    ///
    /// The pending state is latched before the native request. The dedicated
    /// debugger thread can therefore return immediately even when Windows has
    /// not yet completed debuggee termination, while every later admission
    /// path remains permanently closed.
    pub(super) fn request_termination(&mut self) -> Result<(), ServiceProbeJobError> {
        let ops = sys::WindowsJobTerminationOps::new(self.handle.as_handle());
        request_job_termination(&mut self.state, &ops)
    }

    /// Waits after debugger-thread exit until exact Job accounting is empty.
    ///
    /// A query failure or timeout retains the pending state for another
    /// bounded completion attempt. Only an exact zero count marks shutdown.
    pub(super) fn finish_termination_and_wait(&mut self) -> Result<(), ServiceProbeJobError> {
        let ops = sys::WindowsJobTerminationOps::new(self.handle.as_handle());
        finish_job_termination_and_wait(&mut self.state, &ops, SERVICE_PROBE_TERMINATION_TIMEOUT)
    }

    /// Requests whole-Job termination and then waits until accounting is empty.
    ///
    /// This compatibility operation is valid only after any debugger thread
    /// has exited. A pending owner skips a second termination request and
    /// retries only the bounded exact-zero observation.
    pub(super) fn terminate_and_wait(&mut self) -> Result<(), ServiceProbeJobError> {
        let ops = sys::WindowsJobTerminationOps::new(self.handle.as_handle());
        terminate_job_and_wait(&mut self.state, &ops, SERVICE_PROBE_TERMINATION_TIMEOUT)
    }
}

impl fmt::Debug for ServiceProbeJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceProbeJob")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Stable, lifetime-bound storage for exactly one Job-list attribute.
pub(super) struct ServiceProbeJobAttribute<'job> {
    handle: Box<HANDLE>,
    _job: PhantomData<&'job ServiceProbeJob>,
}

impl ServiceProbeJobAttribute<'_> {
    /// Installs this exact handle into one live attribute-list slot.
    ///
    /// # Safety
    ///
    /// `attribute_list` must be initialized with a free slot, and the caller
    /// must retain this value until `DeleteProcThreadAttributeList` completes.
    #[allow(unsafe_code)]
    pub(super) unsafe fn install_into(
        &self,
        attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    ) -> Result<(), ServiceProbeJobError> {
        // SAFETY: the caller owns the list lifetime and this heap allocation
        // keeps the borrowed Job HANDLE value stable for that complete lifetime.
        unsafe { sys::install_creation_attribute(attribute_list, self.handle.as_ref()) }
    }
}

impl fmt::Debug for ServiceProbeJobAttribute<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeJobAttribute([REDACTED])")
    }
}

mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::os::windows::io::{
        AsHandle as _, AsRawHandle as _, BorrowedHandle, FromRawHandle, OwnedHandle,
    };
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
        UpdateProcThreadAttribute,
    };
    use windows::core::{BOOL, PCWSTR};

    use super::{
        SERVICE_PROBE_JOB_FLAGS, SERVICE_PROBE_PROCESS_LIMIT, ServiceProbeJobError,
        exact_limits_match,
    };

    const SERVICE_PROBE_EXIT_CODE: u32 = 0xE0A1_1001;
    const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(1);

    pub(super) struct WindowsJobPrepareOps;

    impl super::JobPrepareOps for WindowsJobPrepareOps {
        type Handle = OwnedHandle;

        fn require_non_nested(&self) -> Result<(), ServiceProbeJobError> {
            require_current_process_not_in_job()
        }

        fn create(&self) -> Result<Self::Handle, ServiceProbeJobError> {
            create_job()
        }

        fn install_limits(&self, handle: &Self::Handle) -> Result<(), ServiceProbeJobError> {
            install_exact_limits(handle.as_handle())
        }

        fn verify_limits(&self, handle: &Self::Handle) -> Result<(), ServiceProbeJobError> {
            verify_exact_limits(handle.as_handle())
        }
    }

    pub(super) struct WindowsJobTerminationOps<'job> {
        job: BorrowedHandle<'job>,
    }

    impl<'job> WindowsJobTerminationOps<'job> {
        pub(super) const fn new(job: BorrowedHandle<'job>) -> Self {
            Self { job }
        }
    }

    impl super::JobTerminationOps for WindowsJobTerminationOps<'_> {
        fn request_termination(&self) -> Result<(), ServiceProbeJobError> {
            request_termination(self.job)
        }

        fn wait_until_empty(&self, timeout: Duration) -> Result<(), ServiceProbeJobError> {
            wait_until_empty(self.job, timeout)
        }
    }

    pub(super) fn require_current_process_not_in_job() -> Result<(), ServiceProbeJobError> {
        let mut in_job = BOOL(0);
        // SAFETY: the current-process pseudo handle is valid and `in_job` is
        // exact writable scalar storage. `None` queries any enclosing Job.
        unsafe { IsProcessInJob(GetCurrentProcess(), None, &raw mut in_job) }
            .map_err(|_| ServiceProbeJobError::Query)?;
        (!in_job.as_bool())
            .then_some(())
            .ok_or(ServiceProbeJobError::NestedService)
    }

    pub(super) fn create_job() -> Result<OwnedHandle, ServiceProbeJobError> {
        // SAFETY: an unnamed Job retains no caller-owned name or descriptor.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|_| ServiceProbeJobError::Creation)?;
        if handle.is_invalid() {
            return Err(ServiceProbeJobError::Creation);
        }
        // SAFETY: successful creation returned one fresh owned Job handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
    }

    pub(super) fn install_exact_limits(
        job: BorrowedHandle<'_>,
    ) -> Result<(), ServiceProbeJobError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = SERVICE_PROBE_JOB_FLAGS;
        information.BasicLimitInformation.ActiveProcessLimit = SERVICE_PROBE_PROCESS_LIMIT;
        // SAFETY: `job` is live and the exact information structure is retained
        // for the complete call.
        unsafe {
            SetInformationJobObject(
                windows_handle(job),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&information).cast::<c_void>(),
                structure_size::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()?,
            )
        }
        .map_err(|_| ServiceProbeJobError::Configuration)
    }

    pub(super) fn verify_exact_limits(job: BorrowedHandle<'_>) -> Result<(), ServiceProbeJobError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        query_information(
            Some(windows_handle(job)),
            JobObjectExtendedLimitInformation,
            &mut information,
        )?;
        exact_limits_match(
            information.BasicLimitInformation.LimitFlags,
            information.BasicLimitInformation.ActiveProcessLimit,
        )
        .then_some(())
        .ok_or(ServiceProbeJobError::LimitVerification)
    }

    pub(super) fn contains_process(
        job: BorrowedHandle<'_>,
        process: BorrowedHandle<'_>,
    ) -> Result<bool, ServiceProbeJobError> {
        let mut in_job = BOOL(0);
        // SAFETY: both kernel handles are borrowed for the complete call and
        // `in_job` is one exact writable BOOL.
        unsafe {
            IsProcessInJob(
                windows_handle(process),
                Some(windows_handle(job)),
                &raw mut in_job,
            )
        }
        .map_err(|_| ServiceProbeJobError::Query)?;
        Ok(in_job.as_bool())
    }

    pub(super) fn active_process_count(
        job: BorrowedHandle<'_>,
    ) -> Result<u32, ServiceProbeJobError> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        query_information(
            Some(windows_handle(job)),
            JobObjectBasicAccountingInformation,
            &mut accounting,
        )?;
        (accounting.ActiveProcesses <= SERVICE_PROBE_PROCESS_LIMIT)
            .then_some(accounting.ActiveProcesses)
            .ok_or(ServiceProbeJobError::Query)
    }

    pub(super) fn request_termination(job: BorrowedHandle<'_>) -> Result<(), ServiceProbeJobError> {
        // SAFETY: the exact Job owner remains live throughout termination.
        unsafe { TerminateJobObject(windows_handle(job), SERVICE_PROBE_EXIT_CODE) }
            .map_err(|_| ServiceProbeJobError::Termination)
    }

    pub(super) fn wait_until_empty(
        job: BorrowedHandle<'_>,
        timeout: Duration,
    ) -> Result<(), ServiceProbeJobError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ServiceProbeJobError::TerminationTimeout)?;
        loop {
            if active_process_count(job)? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ServiceProbeJobError::TerminationTimeout);
            }
            std::thread::sleep(TERMINATION_POLL_INTERVAL);
        }
    }

    pub(super) unsafe fn install_creation_attribute(
        attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
        handle: &HANDLE,
    ) -> Result<(), ServiceProbeJobError> {
        // SAFETY: the caller guarantees the initialized list and stable handle
        // storage lifetimes through list deletion.
        unsafe {
            UpdateProcThreadAttribute(
                attribute_list,
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_JOB_LIST)
                    .map_err(|_| ServiceProbeJobError::Configuration)?,
                Some(ptr::from_ref(handle).cast::<c_void>()),
                size_of::<HANDLE>(),
                None,
                None,
            )
        }
        .map_err(|_| ServiceProbeJobError::Configuration)
    }

    fn query_information<T>(
        job: Option<HANDLE>,
        class: windows::Win32::System::JobObjects::JOBOBJECTINFOCLASS,
        information: &mut T,
    ) -> Result<(), ServiceProbeJobError> {
        let expected = structure_size::<T>()?;
        let mut returned = 0_u32;
        // SAFETY: the selected class matches the exact writable structure and
        // byte length; `returned` remains live for the complete call.
        unsafe {
            QueryInformationJobObject(
                job,
                class,
                ptr::from_mut(information).cast::<c_void>(),
                expected,
                Some(&raw mut returned),
            )
        }
        .map_err(|_| ServiceProbeJobError::Query)?;
        if returned != expected {
            return Err(ServiceProbeJobError::Query);
        }
        Ok(())
    }

    fn structure_size<T>() -> Result<u32, ServiceProbeJobError> {
        u32::try_from(size_of::<T>()).map_err(|_| ServiceProbeJobError::Query)
    }

    pub(super) fn windows_handle(handle: BorrowedHandle<'_>) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }
}

fn exact_limits_match(flags: JOB_OBJECT_LIMIT, process_limit: u32) -> bool {
    flags == SERVICE_PROBE_JOB_FLAGS
        && process_limit == SERVICE_PROBE_PROCESS_LIMIT
        && flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK == JOB_OBJECT_LIMIT(0)
        && flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK == JOB_OBJECT_LIMIT(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PrepareEvent {
        Preflight,
        Create,
        Install,
        Verify,
        Recheck,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TerminationEvent {
        Request,
        Wait(Duration),
    }

    struct FakeHandle {
        drops: Rc<Cell<u32>>,
    }

    impl Drop for FakeHandle {
        fn drop(&mut self) {
            self.drops.set(self.drops.get().saturating_add(1));
        }
    }

    struct FakePrepareOps {
        events: RefCell<Vec<PrepareEvent>>,
        fail: Cell<Option<PrepareEvent>>,
        nested_checks: Cell<u32>,
        drops: Rc<Cell<u32>>,
    }

    impl FakePrepareOps {
        fn new(fail: Option<PrepareEvent>) -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                fail: Cell::new(fail),
                nested_checks: Cell::new(0),
                drops: Rc::new(Cell::new(0)),
            }
        }

        fn record(&self, event: PrepareEvent) -> Result<(), ServiceProbeJobError> {
            self.events.borrow_mut().push(event);
            if self.fail.get() == Some(event) {
                Err(match event {
                    PrepareEvent::Preflight | PrepareEvent::Recheck => {
                        ServiceProbeJobError::NestedService
                    }
                    PrepareEvent::Create => ServiceProbeJobError::Creation,
                    PrepareEvent::Install => ServiceProbeJobError::Configuration,
                    PrepareEvent::Verify => ServiceProbeJobError::LimitVerification,
                })
            } else {
                Ok(())
            }
        }
    }

    impl JobPrepareOps for FakePrepareOps {
        type Handle = FakeHandle;

        fn require_non_nested(&self) -> Result<(), ServiceProbeJobError> {
            let checks = self.nested_checks.get();
            self.nested_checks.set(checks.saturating_add(1));
            self.record(if checks == 0 {
                PrepareEvent::Preflight
            } else {
                PrepareEvent::Recheck
            })
        }

        fn create(&self) -> Result<Self::Handle, ServiceProbeJobError> {
            self.record(PrepareEvent::Create)?;
            Ok(FakeHandle {
                drops: Rc::clone(&self.drops),
            })
        }

        fn install_limits(&self, _handle: &Self::Handle) -> Result<(), ServiceProbeJobError> {
            self.record(PrepareEvent::Install)
        }

        fn verify_limits(&self, _handle: &Self::Handle) -> Result<(), ServiceProbeJobError> {
            self.record(PrepareEvent::Verify)
        }
    }

    struct FakeTerminationOps {
        events: RefCell<Vec<TerminationEvent>>,
        request_failure: Cell<Option<ServiceProbeJobError>>,
        wait_failure: Cell<Option<ServiceProbeJobError>>,
    }

    impl FakeTerminationOps {
        fn new(
            request_failure: Option<ServiceProbeJobError>,
            wait_failure: Option<ServiceProbeJobError>,
        ) -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                request_failure: Cell::new(request_failure),
                wait_failure: Cell::new(wait_failure),
            }
        }
    }

    impl JobTerminationOps for FakeTerminationOps {
        fn request_termination(&self) -> Result<(), ServiceProbeJobError> {
            self.events.borrow_mut().push(TerminationEvent::Request);
            self.request_failure.get().map_or(Ok(()), Err)
        }

        fn wait_until_empty(&self, timeout: Duration) -> Result<(), ServiceProbeJobError> {
            self.events
                .borrow_mut()
                .push(TerminationEvent::Wait(timeout));
            self.wait_failure.get().map_or(Ok(()), Err)
        }
    }

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

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

    fn assert_send<T: Send>() {}

    #[test]
    fn exact_one_process_kill_on_close_policy_rejects_every_mutation() {
        assert!(exact_limits_match(
            SERVICE_PROBE_JOB_FLAGS,
            SERVICE_PROBE_PROCESS_LIMIT
        ));
        for flags in [
            JOB_OBJECT_LIMIT(0),
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT(SERVICE_PROBE_JOB_FLAGS.0 | JOB_OBJECT_LIMIT_BREAKAWAY_OK.0),
            JOB_OBJECT_LIMIT(SERVICE_PROBE_JOB_FLAGS.0 | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK.0),
        ] {
            assert!(!exact_limits_match(flags, SERVICE_PROBE_PROCESS_LIMIT));
        }
        assert!(!exact_limits_match(SERVICE_PROBE_JOB_FLAGS, 0));
        assert!(!exact_limits_match(SERVICE_PROBE_JOB_FLAGS, 2));
    }

    #[test]
    fn preparation_order_is_exact_and_every_partial_handle_is_closed() {
        let expected = [
            PrepareEvent::Preflight,
            PrepareEvent::Create,
            PrepareEvent::Install,
            PrepareEvent::Verify,
            PrepareEvent::Recheck,
        ];

        let success = FakePrepareOps::new(None);
        let handle = prepare_job(&success);
        assert!(handle.is_ok());
        assert_eq!(success.events.borrow().as_slice(), expected.as_slice());
        assert_eq!(success.drops.get(), 0);
        drop(handle);
        assert_eq!(success.drops.get(), 1);

        for (index, failure) in expected.into_iter().enumerate() {
            let ops = FakePrepareOps::new(Some(failure));
            assert!(prepare_job(&ops).is_err());
            assert_eq!(ops.events.borrow().as_slice(), &expected[..=index]);
            let expected_drops = u32::from(index >= 2);
            assert_eq!(ops.drops.get(), expected_drops);
        }
    }

    #[test]
    fn job_owner_is_move_only_send_and_not_sync() {
        assert_send::<ServiceProbeJob>();
        let _ = <ServiceProbeJob as AmbiguousIfSync<_>>::marker;
        let _ = <ServiceProbeJob as AmbiguousIfClone<_>>::marker;
        let _ = <ServiceProbeJob as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn split_termination_requests_once_then_waits_and_latches_shutdown() {
        let ops = FakeTerminationOps::new(None, None);
        let mut state = ServiceProbeJobState::Active;

        assert_eq!(request_job_termination(&mut state, &ops), Ok(()));
        assert_eq!(state, ServiceProbeJobState::TerminationRequested);
        assert_eq!(ops.events.borrow().as_slice(), [TerminationEvent::Request]);

        assert_eq!(
            finish_job_termination_and_wait(&mut state, &ops, SERVICE_PROBE_TERMINATION_TIMEOUT,),
            Ok(())
        );
        assert_eq!(state, ServiceProbeJobState::ShutDown);
        assert_eq!(
            ops.events.borrow().as_slice(),
            [
                TerminationEvent::Request,
                TerminationEvent::Wait(SERVICE_PROBE_TERMINATION_TIMEOUT),
            ]
        );

        assert_eq!(
            request_job_termination(&mut state, &ops),
            Err(ServiceProbeJobError::ShutDown)
        );
        assert_eq!(
            finish_job_termination_and_wait(&mut state, &ops, SERVICE_PROBE_TERMINATION_TIMEOUT,),
            Err(ServiceProbeJobError::ShutDown)
        );
        assert_eq!(ops.events.borrow().len(), 2);
    }

    #[test]
    fn failed_termination_request_stays_pending_and_cannot_be_reissued() {
        let ops = FakeTerminationOps::new(Some(ServiceProbeJobError::Termination), None);
        let mut state = ServiceProbeJobState::Active;

        assert_eq!(
            request_job_termination(&mut state, &ops),
            Err(ServiceProbeJobError::Termination)
        );
        assert_eq!(state, ServiceProbeJobState::TerminationRequested);
        assert_eq!(
            request_job_termination(&mut state, &ops),
            Err(ServiceProbeJobError::TerminationPending)
        );
        assert_eq!(ops.events.borrow().as_slice(), [TerminationEvent::Request]);

        assert_eq!(
            finish_job_termination_and_wait(&mut state, &ops, SERVICE_PROBE_TERMINATION_TIMEOUT,),
            Ok(())
        );
        assert_eq!(state, ServiceProbeJobState::ShutDown);
    }

    #[test]
    fn finish_requires_request_and_failed_wait_is_bounded_and_retriable() {
        for failure in [
            ServiceProbeJobError::Query,
            ServiceProbeJobError::TerminationTimeout,
        ] {
            let ops = FakeTerminationOps::new(None, Some(failure));
            let mut state = ServiceProbeJobState::Active;
            assert_eq!(
                finish_job_termination_and_wait(
                    &mut state,
                    &ops,
                    SERVICE_PROBE_TERMINATION_TIMEOUT,
                ),
                Err(ServiceProbeJobError::TerminationNotRequested)
            );
            assert!(ops.events.borrow().is_empty());

            assert_eq!(request_job_termination(&mut state, &ops), Ok(()));
            assert_eq!(
                finish_job_termination_and_wait(
                    &mut state,
                    &ops,
                    SERVICE_PROBE_TERMINATION_TIMEOUT,
                ),
                Err(failure)
            );
            assert_eq!(state, ServiceProbeJobState::TerminationRequested);

            ops.wait_failure.set(None);
            assert_eq!(
                finish_job_termination_and_wait(
                    &mut state,
                    &ops,
                    SERVICE_PROBE_TERMINATION_TIMEOUT,
                ),
                Ok(())
            );
            assert_eq!(state, ServiceProbeJobState::ShutDown);
            assert_eq!(
                ops.events.borrow().as_slice(),
                [
                    TerminationEvent::Request,
                    TerminationEvent::Wait(SERVICE_PROBE_TERMINATION_TIMEOUT),
                    TerminationEvent::Wait(SERVICE_PROBE_TERMINATION_TIMEOUT),
                ]
            );
        }
    }

    #[test]
    fn compatibility_cleanup_skips_a_second_request_while_pending() {
        let ops = FakeTerminationOps::new(None, None);
        let mut fresh = ServiceProbeJobState::Active;
        assert_eq!(
            terminate_job_and_wait(&mut fresh, &ops, SERVICE_PROBE_TERMINATION_TIMEOUT),
            Ok(())
        );
        assert_eq!(fresh, ServiceProbeJobState::ShutDown);
        assert_eq!(
            ops.events.borrow().as_slice(),
            [
                TerminationEvent::Request,
                TerminationEvent::Wait(SERVICE_PROBE_TERMINATION_TIMEOUT),
            ]
        );

        let pending_ops = FakeTerminationOps::new(Some(ServiceProbeJobError::Termination), None);
        let mut pending = ServiceProbeJobState::Active;
        assert_eq!(
            terminate_job_and_wait(
                &mut pending,
                &pending_ops,
                SERVICE_PROBE_TERMINATION_TIMEOUT,
            ),
            Err(ServiceProbeJobError::Termination)
        );
        pending_ops.request_failure.set(None);
        assert_eq!(
            terminate_job_and_wait(
                &mut pending,
                &pending_ops,
                SERVICE_PROBE_TERMINATION_TIMEOUT,
            ),
            Ok(())
        );
        assert_eq!(pending, ServiceProbeJobState::ShutDown);
        assert_eq!(
            pending_ops.events.borrow().as_slice(),
            [
                TerminationEvent::Request,
                TerminationEvent::Wait(SERVICE_PROBE_TERMINATION_TIMEOUT),
            ]
        );
    }

    #[test]
    fn pending_and_shutdown_states_reject_all_admission() {
        assert_eq!(require_active_job(ServiceProbeJobState::Active), Ok(()));
        assert_eq!(
            require_active_job(ServiceProbeJobState::TerminationRequested),
            Err(ServiceProbeJobError::TerminationPending)
        );
        assert_eq!(
            require_active_job(ServiceProbeJobState::ShutDown),
            Err(ServiceProbeJobError::ShutDown)
        );
    }

    #[test]
    fn errors_and_attribute_debug_are_data_free() {
        for error in [
            ServiceProbeJobError::NestedService,
            ServiceProbeJobError::Creation,
            ServiceProbeJobError::Configuration,
            ServiceProbeJobError::LimitVerification,
            ServiceProbeJobError::Query,
            ServiceProbeJobError::TerminationPending,
            ServiceProbeJobError::TerminationNotRequested,
            ServiceProbeJobError::ShutDown,
            ServiceProbeJobError::Termination,
            ServiceProbeJobError::TerminationTimeout,
        ] {
            assert!(!error.to_string().contains("0x"));
        }
        assert_eq!(
            format!(
                "{:?}",
                ServiceProbeJobAttribute {
                    handle: Box::new(HANDLE::default()),
                    _job: PhantomData,
                }
            ),
            "ServiceProbeJobAttribute([REDACTED])"
        );
    }

    #[test]
    #[ignore = "requires a Windows process that is not already Job-contained"]
    fn live_empty_job_has_exact_limits_and_bounded_shutdown() -> Result<(), ServiceProbeJobError> {
        let mut job = ServiceProbeJob::create_non_nested()?;
        assert_eq!(job.active_process_count()?, 0);
        let mut outside = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "exit", "0"])
            .spawn()
            .map_err(|_| ServiceProbeJobError::Query)?;
        let is_contained = job.contains_process(outside.as_handle())?;
        outside.wait().map_err(|_| ServiceProbeJobError::Query)?;
        assert!(!is_contained);
        job.request_termination()?;
        job.finish_termination_and_wait()?;
        Ok(())
    }
}
