//! Dormant debug-only exact Broker process and channel composition.
//!
//! The supervisor pins the sibling Broker executable, creates it under a fresh
//! debugger thread with an exact inherited-handle list (one restricted parent
//! capability plus one read/write NUL handle shared by all standard streams)
//! and a one-process kill-on-close Job, authenticates the first mapped image by
//! `FILE_ID_INFO` before user-mode entry, and only then releases the process to
//! connect to the private process-bound channel.

use core::fmt;
#[cfg(test)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::windows::io::AsHandle;
use std::path::Path;
use std::time::Instant;

use thiserror::Error;

use crate::broker_channel::{
    BrokerChannelError, BrokerEndpointCapability, DormantBrokerPipe, ExpectedBrokerPeer,
    VerifiedBrokerChannel,
};
use crate::exact_image::{ExactImageError, PinnedBrokerImage};

const BROKER_ENDPOINT_ENV: &str = "YOUR_WALLET_DORMANT_BROKER_ENDPOINT_V1";
const PARENT_PROCESS_HANDLE_ENV: &str = "YOUR_WALLET_DORMANT_PARENT_PROCESS_HANDLE_V1";

/// Stable failures from the dormant Broker composition boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DormantBrokerError {
    /// The sibling debug Broker artifact was unavailable or not exact.
    #[error("dormant Broker artifact is unavailable")]
    Artifact,
    /// The private process-bound channel could not be established.
    #[error("dormant Broker channel is unavailable")]
    Channel,
    /// Exact process creation, image proof, or Job policy failed.
    #[error("dormant Broker process proof failed")]
    ProcessProof,
    /// An absolute operation deadline elapsed.
    #[error("dormant Broker operation deadline elapsed")]
    Deadline,
    /// The one inherited parent-process capability was absent or malformed.
    #[error("dormant Broker parent capability is unavailable")]
    ParentCapability,
    /// The exact Broker process could not be synchronously cleaned up.
    #[error("dormant Broker cleanup failed")]
    Cleanup,
    /// This move-only payload channel has already closed.
    #[error("dormant Broker payload channel is closed")]
    Closed,
}

impl From<ExactImageError> for DormantBrokerError {
    fn from(_error: ExactImageError) -> Self {
        Self::Artifact
    }
}

impl From<BrokerChannelError> for DormantBrokerError {
    fn from(error: BrokerChannelError) -> Self {
        if matches!(error, BrokerChannelError::DeadlineElapsed) {
            Self::Deadline
        } else {
            Self::Channel
        }
    }
}

/// Opaque payload channel bound to the exact native-host/Broker process pair.
///
/// The native-host side additionally owns the pinned Broker artifact, exact
/// process handle, and one-process kill-on-close Job. No raw name, handle, PID,
/// stream resynchronization, RPC, account, or signing capability is exposed.
/// The byte payload methods are public only because the two debug-gated
/// cross-crate `BrokerIpcPayloads` adapters must supply framing-free JSON to the
/// closed typed state machine. Their exact callsites are architecture-guarded;
/// the facade and adapters are absent from default and release builds.
pub struct DormantBrokerPayloadChannel {
    channel: Option<VerifiedBrokerChannel>,
    supervisor: Option<sys::RunningBroker>,
}

impl DormantBrokerPayloadChannel {
    /// Writes one non-empty JSON payload with the channel-owned BE frame.
    ///
    /// # Errors
    ///
    /// Returns a closed error on any partial write, peer drift, or deadline.
    pub fn write_payload(
        &mut self,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<(), DormantBrokerError> {
        let channel = self.channel.take().ok_or(DormantBrokerError::Closed)?;
        match channel.write_frame(payload, deadline) {
            Ok(channel) => {
                self.channel = Some(channel);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Reads one complete JSON payload, or a clean EOF before a new prefix.
    ///
    /// # Errors
    ///
    /// Returns a closed error on any partial frame, peer drift, or deadline.
    pub fn read_payload(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, DormantBrokerError> {
        let channel = self.channel.take().ok_or(DormantBrokerError::Closed)?;
        match channel.read_frame_or_eof(deadline) {
            Ok((channel, Some(payload))) => {
                self.channel = Some(channel);
                Ok(Some(payload))
            }
            Ok((_channel, None)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(test)]
    fn process_observation_for_test(&self) -> Result<sys::ProcessObservation, DormantBrokerError> {
        self.supervisor
            .as_ref()
            .ok_or(DormantBrokerError::ProcessProof)?
            .duplicate_process_observation()
    }
}

impl fmt::Debug for DormantBrokerPayloadChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DormantBrokerPayloadChannel([PROCESS-BOUND])")
    }
}

impl Drop for DormantBrokerPayloadChannel {
    fn drop(&mut self) {
        drop(self.channel.take());
        if let Some(mut supervisor) = self.supervisor.take() {
            let _ = supervisor.shutdown();
        }
    }
}

/// Launches and binds the exact sibling debug Broker.
///
/// This function exists only when both the dormant feature and debug assertions
/// are enabled. Release builds cannot name it.
///
/// # Errors
///
/// Returns a fail-closed artifact, process proof, channel, or deadline error.
pub fn launch_dormant_broker_channel(
    deadline: Instant,
) -> Result<DormantBrokerPayloadChannel, DormantBrokerError> {
    let executable = std::env::current_exe().map_err(|_| DormantBrokerError::Artifact)?;
    let directory = executable.parent().ok_or(DormantBrokerError::Artifact)?;
    let broker = directory.join("broker.exe");
    launch_broker_path(&broker, None, deadline)
}

/// Connects the Broker child to the exact inherited native-host process.
///
/// The pipe name and inherited handle are read only from the supervisor's
/// minimal child environment. The process object is never reopened by PID.
///
/// # Errors
///
/// Returns a fail-closed parent-capability, channel, or deadline error.
pub fn connect_inherited_native_host_channel(
    deadline: Instant,
) -> Result<DormantBrokerPayloadChannel, DormantBrokerError> {
    let endpoint =
        std::env::var_os(BROKER_ENDPOINT_ENV).ok_or(DormantBrokerError::ParentCapability)?;
    let parent =
        std::env::var_os(PARENT_PROCESS_HANDLE_ENV).ok_or(DormantBrokerError::ParentCapability)?;
    let parent = sys::take_inherited_parent_process(&parent)?;
    let expected = ExpectedBrokerPeer::from_process_handle(parent.as_handle())?;
    let capability = BrokerEndpointCapability::from_environment_value(&endpoint)?;
    let channel = capability.connect(expected, deadline)?;
    Ok(DormantBrokerPayloadChannel {
        channel: Some(channel),
        supervisor: None,
    })
}

fn launch_broker_path(
    broker_path: &Path,
    command_line: Option<OsString>,
    deadline: Instant,
) -> Result<DormantBrokerPayloadChannel, DormantBrokerError> {
    check_deadline(deadline)?;
    let image = PinnedBrokerImage::hold(broker_path)?;
    let (server, endpoint) = DormantBrokerPipe::create("ipc-v1")?;
    let endpoint = endpoint.into_environment_value();
    let worker = std::thread::Builder::new()
        .name("dormant-broker-activation".to_owned())
        .spawn(move || sys::launch_broker(image, &endpoint, command_line, deadline))
        .map_err(|_| DormantBrokerError::ProcessProof)?;
    let running = worker
        .join()
        .map_err(|_| DormantBrokerError::ProcessProof)??;
    let expected = ExpectedBrokerPeer::from_process_handle(running.process_handle())?;
    match server.accept(expected, deadline) {
        Ok(channel) => Ok(DormantBrokerPayloadChannel {
            channel: Some(channel),
            supervisor: Some(running),
        }),
        Err(error) => {
            drop(running);
            Err(error.into())
        }
    }
}

fn check_deadline(deadline: Instant) -> Result<(), DormantBrokerError> {
    (Instant::now() < deadline)
        .then_some(())
        .ok_or(DormantBrokerError::Deadline)
}

#[cfg(test)]
fn launch_broker_path_for_test(
    broker_path: &Path,
    command_line: &OsStr,
    deadline: Instant,
) -> Result<DormantBrokerPayloadChannel, DormantBrokerError> {
    launch_broker_path(broker_path, Some(command_line.to_os_string()), deadline)
}

mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::{size_of, size_of_val};
    use core::ptr;
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{
        AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle as StdOwnedHandle,
    };
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        CloseHandle, DBG_CONTINUE, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, ERROR_SEM_TIMEOUT,
        GENERIC_READ, GENERIC_WRITE, GetHandleInformation, GetLastError, HANDLE,
        HANDLE_FLAG_INHERIT, HANDLE_FLAGS, INVALID_HANDLE_VALUE, SetHandleInformation,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_CHAR,
        GetFileType, OPEN_EXISTING,
    };
    #[cfg(test)]
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows::Win32::System::Diagnostics::Debug::{
        CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcessStop,
        LOAD_DLL_DEBUG_EVENT, WaitForDebugEventEx,
    };
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DEBUG_ONLY_THIS_PROCESS, DEBUG_PROCESS, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetProcessId, GetThreadId,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, ResumeThread, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, SuspendThread, TerminateProcess, UpdateProcThreadAttribute,
        WaitForSingleObject,
    };
    #[cfg(test)]
    use windows::Win32::System::Threading::{CreateEventW, SetEvent};
    use windows::core::{BOOL, PCWSTR, PWSTR};

    use super::{
        BROKER_ENDPOINT_ENV, DormantBrokerError, PARENT_PROCESS_HANDLE_ENV, PinnedBrokerImage,
    };

    const CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000;
    const FIRST_EVENT_TIMEOUT_MILLISECONDS: u32 = 5_000;
    const REJECTED_EXIT_CODE: u32 = 0xE0B0_0001;
    const JOB_EXIT_CODE: u32 = 0xE0B0_0002;
    const JOB_LIMITS: windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT =
        windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT(
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION.0
                | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0,
        );
    const NULL_DEVICE: [u16; 8] = [
        b'\\' as u16,
        b'\\' as u16,
        b'.' as u16,
        b'\\' as u16,
        b'N' as u16,
        b'U' as u16,
        b'L' as u16,
        0,
    ];

    pub(super) struct RunningBroker {
        process: OwnedWinHandle,
        job: BrokerJob,
        _image: PinnedBrokerImage,
        shut_down: bool,
    }

    // SAFETY: debugger-thread-affine operations are completed before this type
    // is constructed. Only process-wide wait/termination and owned-handle Drop
    // cross the join boundary.
    unsafe impl Send for RunningBroker {}

    impl RunningBroker {
        pub(super) fn process_handle(&self) -> BorrowedHandle<'_> {
            self.process.as_borrowed()
        }

        pub(super) fn shutdown(&mut self) -> Result<(), DormantBrokerError> {
            if self.shut_down {
                return Ok(());
            }
            // Give a clean channel close a short opportunity to finish first.
            // SAFETY: the retained exact process handle remains live.
            let initial = unsafe { WaitForSingleObject(self.process.raw(), 100) };
            if initial == WAIT_OBJECT_0 {
                self.shut_down = true;
                return Ok(());
            }
            if initial != WAIT_TIMEOUT {
                return Err(DormantBrokerError::Cleanup);
            }
            // SAFETY: this is the retained exact one-process Job.
            unsafe { TerminateJobObject(self.job.raw(), JOB_EXIT_CODE) }
                .map_err(|_| DormantBrokerError::Cleanup)?;
            // SAFETY: the exact process handle remains live for the bounded wait.
            if unsafe { WaitForSingleObject(self.process.raw(), CLEANUP_TIMEOUT_MILLISECONDS) }
                != WAIT_OBJECT_0
            {
                return Err(DormantBrokerError::Cleanup);
            }
            self.shut_down = true;
            Ok(())
        }

        #[cfg(test)]
        pub(super) fn duplicate_process_observation(
            &self,
        ) -> Result<ProcessObservation, DormantBrokerError> {
            duplicate_process_observation(&self.process)
        }
    }

    impl Drop for RunningBroker {
        fn drop(&mut self) {
            if self.shutdown().is_err() && !self.shut_down {
                // SAFETY: the fallback still targets the retained exact process;
                // no PID lookup or process-name reopen is involved.
                let _ = unsafe { TerminateProcess(self.process.raw(), JOB_EXIT_CODE) };
                // SAFETY: the same exact process handle remains retained for
                // this final bounded cleanup observation.
                let _ = unsafe {
                    WaitForSingleObject(self.process.raw(), CLEANUP_TIMEOUT_MILLISECONDS)
                };
                self.shut_down = true;
            }
        }
    }

    impl core::fmt::Debug for RunningBroker {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("RunningBroker([EXACT PROCESS/JOB/ARTIFACT])")
        }
    }

    #[cfg(test)]
    pub(super) struct ProcessObservation(OwnedWinHandle);

    #[cfg(test)]
    // SAFETY: this test-only observation owns only a synchronize-only duplicate
    // of the exact process object; it has no debugger-thread-affine operation.
    unsafe impl Send for ProcessObservation {}

    #[cfg(test)]
    impl ProcessObservation {
        pub(super) fn wait_terminated(&self) -> Result<(), DormantBrokerError> {
            // SAFETY: the observation retains the exact synchronize handle.
            if unsafe { WaitForSingleObject(self.0.raw(), CLEANUP_TIMEOUT_MILLISECONDS) }
                == WAIT_OBJECT_0
            {
                Ok(())
            } else {
                Err(DormantBrokerError::Cleanup)
            }
        }
    }

    #[cfg(test)]
    fn duplicate_process_observation(
        process: &OwnedWinHandle,
    ) -> Result<ProcessObservation, DormantBrokerError> {
        let mut duplicate = HANDLE::default();
        // SAFETY: the source is the retained exact process and the result is a
        // non-inheritable synchronize-only duplicate in this process.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                process.raw(),
                GetCurrentProcess(),
                &raw mut duplicate,
                PROCESS_SYNCHRONIZE.0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| DormantBrokerError::Cleanup)?;
        Ok(ProcessObservation(
            OwnedWinHandle::new(duplicate).ok_or(DormantBrokerError::Cleanup)?,
        ))
    }

    #[cfg(test)]
    pub(super) struct InheritableSentinel(OwnedWinHandle);

    #[cfg(test)]
    impl InheritableSentinel {
        pub(super) fn create() -> Result<Self, DormantBrokerError> {
            // SAFETY: this unnamed manual-reset event has no borrowed security
            // descriptor or name and is owned only by the test parent.
            let event = unsafe { CreateEventW(None, true, false, None) }
                .map_err(|_| DormantBrokerError::ProcessProof)?;
            let event = OwnedWinHandle::new(event).ok_or(DormantBrokerError::ProcessProof)?;
            // SAFETY: the exact live event is made inheritable solely to prove
            // the explicit HANDLE_LIST excludes unrelated inheritable handles.
            unsafe {
                SetHandleInformation(event.raw(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
            }
            .map_err(|_| DormantBrokerError::ProcessProof)?;
            Ok(Self(event))
        }

        pub(super) fn raw_value(&self) -> usize {
            self.0.raw().0 as usize
        }

        pub(super) fn assert_not_signaled(&self) -> Result<(), DormantBrokerError> {
            // SAFETY: the parent retains this exact event while the child has
            // already attempted the numeric-handle SetEvent challenge.
            if unsafe { WaitForSingleObject(self.0.raw(), 0) } == WAIT_TIMEOUT {
                Ok(())
            } else {
                Err(DormantBrokerError::ProcessProof)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn assert_child_kernel_contract(
        unrelated_parent_handle: usize,
    ) -> Result<(), DormantBrokerError> {
        if unrelated_parent_handle == 0 {
            return Err(DormantBrokerError::ProcessProof);
        }
        let unrelated = HANDLE(unrelated_parent_handle as *mut c_void);
        // SAFETY: this is a challenge against the parent's recorded handle
        // value. A numeric collision may signal another event or fail, but only
        // inheritance of the parent's exact retained event can wake that event.
        let _ = unsafe { SetEvent(unrelated) };

        let mut expected_stdio = None;
        for standard_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            // SAFETY: these scalar process-table queries borrow no caller memory.
            let handle = unsafe { GetStdHandle(standard_handle) }
                .map_err(|_| DormantBrokerError::ProcessProof)?;
            if invalid(handle) {
                return Err(DormantBrokerError::ProcessProof);
            }
            if expected_stdio.is_some_and(|expected| expected != handle) {
                return Err(DormantBrokerError::ProcessProof);
            }
            expected_stdio = Some(handle);
            let mut standard_flags = 0_u32;
            // SAFETY: the inherited standard handle remains live in the child
            // for these scalar kernel-object queries.
            unsafe { GetHandleInformation(handle, &raw mut standard_flags) }
                .map_err(|_| DormantBrokerError::ProcessProof)?;
            // SAFETY: this scalar query borrows the same retained child handle.
            let file_type = unsafe { GetFileType(handle) };
            if standard_flags & HANDLE_FLAG_INHERIT.0 == 0 || file_type != FILE_TYPE_CHAR {
                return Err(DormantBrokerError::ProcessProof);
            }
        }
        Ok(())
    }

    pub(super) fn launch_broker(
        image: PinnedBrokerImage,
        endpoint: &OsStr,
        command_line: Option<OsString>,
        deadline: Instant,
    ) -> Result<RunningBroker, DormantBrokerError> {
        launch_broker_application(image, None, endpoint, command_line, deadline)
    }

    #[cfg(test)]
    pub(super) fn launch_broker_application_for_test(
        image: PinnedBrokerImage,
        application: &std::path::Path,
        endpoint: &OsStr,
        command_line: Option<OsString>,
        deadline: Instant,
    ) -> Result<RunningBroker, DormantBrokerError> {
        launch_broker_application(image, Some(application), endpoint, command_line, deadline)
    }

    #[cfg(test)]
    pub(super) fn panic_after_create_for_test(
        image: PinnedBrokerImage,
        application: &std::path::Path,
        endpoint: &OsStr,
        command_line: Option<OsString>,
        deadline: Instant,
        observation_sender: std::sync::mpsc::SyncSender<ProcessObservation>,
    ) -> Result<RunningBroker, DormantBrokerError> {
        launch_broker_application_with_after_create(
            image,
            Some(application),
            endpoint,
            command_line,
            deadline,
            move |debuggee| {
                if let Ok(observation) = debuggee.duplicate_process_observation() {
                    let _ = observation_sender.send(observation);
                }
                std::panic::resume_unwind(Box::new(
                    "intentional dormant Broker post-create unwind",
                ));
            },
        )
    }

    fn launch_broker_application(
        image: PinnedBrokerImage,
        application_override: Option<&std::path::Path>,
        endpoint: &OsStr,
        command_line: Option<OsString>,
        deadline: Instant,
    ) -> Result<RunningBroker, DormantBrokerError> {
        launch_broker_application_with_after_create(
            image,
            application_override,
            endpoint,
            command_line,
            deadline,
            |_debuggee| {},
        )
    }

    fn launch_broker_application_with_after_create<AfterCreate>(
        image: PinnedBrokerImage,
        application_override: Option<&std::path::Path>,
        endpoint: &OsStr,
        command_line: Option<OsString>,
        deadline: Instant,
        after_create: AfterCreate,
    ) -> Result<RunningBroker, DormantBrokerError>
    where
        AfterCreate: FnOnce(&Debuggee),
    {
        check_deadline(deadline)?;
        let job = BrokerJob::create()?;
        let inherited_parent = InheritedParentProcess::duplicate_current()?;
        let inherited_stdio = InheritedNullStdio::create()?;
        let environment = minimal_environment(endpoint, inherited_parent.environment_value())?;
        let attributes = CreationAttributes::new(&inherited_parent, &inherited_stdio, &job)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
            .map_err(|_| DormantBrokerError::ProcessProof)?;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited_stdio.raw();
        startup.StartupInfo.hStdOutput = inherited_stdio.raw();
        startup.StartupInfo.hStdError = inherited_stdio.raw();
        startup.lpAttributeList = attributes.pointer();
        let application_path = application_override.unwrap_or_else(|| image.path());
        let application: Vec<u16> = application_path
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        let mut command_line: Option<Vec<u16>> = command_line.map(|line| {
            line.encode_wide()
                .chain(core::iter::once(0))
                .collect::<Vec<_>>()
        });
        let command_line_pointer = command_line
            .as_mut()
            .map_or(PWSTR::null(), |line| PWSTR(line.as_mut_ptr()));
        let mut information = PROCESS_INFORMATION::default();
        check_deadline(deadline)?;
        // SAFETY: every pointer targets retained NUL-terminated or initialized
        // storage. The attribute list contains exactly HANDLE_LIST(parent,NUL)
        // and JOB_LIST(job=1); all three explicit standard streams use that
        // same read/write NUL handle, and `environment` is double-NUL Unicode.
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                Some(command_line_pointer).filter(|pointer| !pointer.is_null()),
                None,
                None,
                true,
                creation_flags(),
                Some(environment.as_ptr().cast::<c_void>()),
                PCWSTR::null(),
                ptr::from_ref(&startup.StartupInfo),
                &raw mut information,
            )
        }
        .map_err(|_| DormantBrokerError::ProcessProof)?;
        drop(attributes);
        drop(inherited_stdio);
        drop(inherited_parent);

        let mut debuggee = Debuggee::new(information)?;
        after_create(&debuggee);
        debuggee.release_creation_suspend()?;
        debuggee.authenticate_first_event(&image, deadline)?;
        debuggee.detach_while_suspended()?;
        check_deadline(deadline)?;
        job.verify_exact_member(debuggee.process_handle()?)?;
        check_deadline(deadline)?;
        debuggee.start_user_mode()?;
        let process = debuggee.into_running()?;
        Ok(RunningBroker {
            process,
            job,
            _image: image,
            shut_down: false,
        })
    }

    pub(super) fn take_inherited_parent_process(
        value: &OsStr,
    ) -> Result<StdOwnedHandle, DormantBrokerError> {
        let text = value.to_str().ok_or(DormantBrokerError::ParentCapability)?;
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DormantBrokerError::ParentCapability);
        }
        let raw = text
            .parse::<usize>()
            .map_err(|_| DormantBrokerError::ParentCapability)?;
        if raw == 0 {
            return Err(DormantBrokerError::ParentCapability);
        }
        let handle = HANDLE(raw as *mut c_void);
        if invalid(handle) {
            return Err(DormantBrokerError::ParentCapability);
        }
        let mut flags = 0_u32;
        // SAFETY: a valid inherited handle value is the sole bootstrap input.
        unsafe { GetHandleInformation(handle, &raw mut flags) }
            .map_err(|_| DormantBrokerError::ParentCapability)?;
        if flags & HANDLE_FLAG_INHERIT.0 == 0 {
            return Err(DormantBrokerError::ParentCapability);
        }
        // SAFETY: this exact inherited handle is live; clearing its inheritance
        // flag prevents the bootstrap capability from escaping a later child.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
            .map_err(|_| DormantBrokerError::ParentCapability)?;
        // SAFETY: the supervisor explicitly transferred sole ownership of this
        // one inherited duplicate into the child process.
        Ok(unsafe { StdOwnedHandle::from_raw_handle(handle.0) })
    }

    struct InheritedParentProcess(OwnedWinHandle);

    impl InheritedParentProcess {
        fn duplicate_current() -> Result<Self, DormantBrokerError> {
            let mut duplicate = HANDLE::default();
            let desired = (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE).0;
            // SAFETY: both pseudo source and target name the current process;
            // the result is restricted and explicitly inheritable.
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    GetCurrentProcess(),
                    GetCurrentProcess(),
                    &raw mut duplicate,
                    desired,
                    true,
                    DUPLICATE_HANDLE_OPTIONS(0),
                )
            }
            .map_err(|_| DormantBrokerError::ParentCapability)?;
            let handle =
                OwnedWinHandle::new(duplicate).ok_or(DormantBrokerError::ParentCapability)?;
            let mut flags = 0_u32;
            // SAFETY: the successful duplicate remains owned during the query.
            unsafe { GetHandleInformation(handle.raw(), &raw mut flags) }
                .map_err(|_| DormantBrokerError::ParentCapability)?;
            if flags & HANDLE_FLAG_INHERIT.0 == 0 {
                return Err(DormantBrokerError::ParentCapability);
            }
            Ok(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0.raw()
        }

        fn environment_value(&self) -> usize {
            self.raw().0 as usize
        }
    }

    struct InheritedNullStdio(OwnedWinHandle);

    impl InheritedNullStdio {
        fn create() -> Result<Self, DormantBrokerError> {
            // SAFETY: the constant device name is NUL terminated and retained
            // for this call. The handle is opened read/write without an
            // inheritable security descriptor, then explicitly constrained by
            // the process HANDLE_LIST before creation.
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(NULL_DEVICE.as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }
            .map_err(|_| DormantBrokerError::ProcessProof)?;
            let handle = OwnedWinHandle::new(handle).ok_or(DormantBrokerError::ProcessProof)?;
            // SAFETY: this exact live NUL handle is the second and final member
            // of the explicit inherited HANDLE_LIST.
            unsafe {
                SetHandleInformation(handle.raw(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
            }
            .map_err(|_| DormantBrokerError::ProcessProof)?;
            let mut flags = 0_u32;
            // SAFETY: the successful handle remains owned during both queries.
            unsafe { GetHandleInformation(handle.raw(), &raw mut flags) }
                .map_err(|_| DormantBrokerError::ProcessProof)?;
            // SAFETY: this scalar query borrows the retained exact handle only.
            let file_type = unsafe { GetFileType(handle.raw()) };
            if flags & HANDLE_FLAG_INHERIT.0 == 0 || file_type != FILE_TYPE_CHAR {
                return Err(DormantBrokerError::ProcessProof);
            }
            Ok(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0.raw()
        }
    }

    struct BrokerJob(OwnedWinHandle);

    impl BrokerJob {
        fn create() -> Result<Self, DormantBrokerError> {
            // SAFETY: an unnamed Job retains no caller-owned pointers.
            let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
                .map_err(|_| DormantBrokerError::ProcessProof)?;
            let job = Self(OwnedWinHandle::new(handle).ok_or(DormantBrokerError::ProcessProof)?);
            let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            information.BasicLimitInformation.LimitFlags = JOB_LIMITS;
            information.BasicLimitInformation.ActiveProcessLimit = 1;
            // SAFETY: the exact Job and immutable information buffer remain live.
            unsafe {
                SetInformationJobObject(
                    job.raw(),
                    JobObjectExtendedLimitInformation,
                    ptr::from_ref(&information).cast::<c_void>(),
                    u32::try_from(size_of_val(&information))
                        .map_err(|_| DormantBrokerError::ProcessProof)?,
                )
            }
            .map_err(|_| DormantBrokerError::ProcessProof)?;
            job.verify_limits()?;
            Ok(job)
        }

        fn raw(&self) -> HANDLE {
            self.0.raw()
        }

        fn verify_limits(&self) -> Result<(), DormantBrokerError> {
            let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // SAFETY: output is exact writable storage and the Job is retained.
            unsafe {
                QueryInformationJobObject(
                    Some(self.raw()),
                    JobObjectExtendedLimitInformation,
                    ptr::from_mut(&mut information).cast::<c_void>(),
                    u32::try_from(size_of_val(&information))
                        .map_err(|_| DormantBrokerError::ProcessProof)?,
                    None,
                )
            }
            .map_err(|_| DormantBrokerError::ProcessProof)?;
            if information.BasicLimitInformation.LimitFlags != JOB_LIMITS
                || information.BasicLimitInformation.ActiveProcessLimit != 1
            {
                return Err(DormantBrokerError::ProcessProof);
            }
            Ok(())
        }

        fn verify_exact_member(
            &self,
            process: BorrowedHandle<'_>,
        ) -> Result<(), DormantBrokerError> {
            self.verify_limits()?;
            let mut in_job = BOOL(0);
            // SAFETY: both the exact process borrow and Job remain live.
            unsafe {
                IsProcessInJob(
                    HANDLE(process.as_raw_handle()),
                    Some(self.raw()),
                    &raw mut in_job,
                )
            }
            .map_err(|_| DormantBrokerError::ProcessProof)?;
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            // SAFETY: output is exact writable storage and the Job is retained.
            unsafe {
                QueryInformationJobObject(
                    Some(self.raw()),
                    JobObjectBasicAccountingInformation,
                    ptr::from_mut(&mut accounting).cast::<c_void>(),
                    u32::try_from(size_of_val(&accounting))
                        .map_err(|_| DormantBrokerError::ProcessProof)?,
                    None,
                )
            }
            .map_err(|_| DormantBrokerError::ProcessProof)?;
            if !in_job.as_bool() || accounting.ActiveProcesses != 1 {
                return Err(DormantBrokerError::ProcessProof);
            }
            Ok(())
        }
    }

    struct CreationAttributes<'resources> {
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        words: Vec<usize>,
        inherited_handles: Box<[HANDLE; 2]>,
        job_handle: Box<[HANDLE; 1]>,
        _parent: &'resources InheritedParentProcess,
        _stdio: &'resources InheritedNullStdio,
        _job: &'resources BrokerJob,
    }

    impl<'resources> CreationAttributes<'resources> {
        fn new(
            parent: &'resources InheritedParentProcess,
            stdio: &'resources InheritedNullStdio,
            job: &'resources BrokerJob,
        ) -> Result<Self, DormantBrokerError> {
            if parent.raw() == stdio.raw() {
                return Err(DormantBrokerError::ProcessProof);
            }
            let mut bytes = 0_usize;
            // SAFETY: this documented sizing call uses a null list and writes
            // only the required allocation byte count.
            let _ = unsafe { InitializeProcThreadAttributeList(None, 2, None, &raw mut bytes) };
            if bytes == 0 {
                return Err(DormantBrokerError::ProcessProof);
            }
            let word_size = size_of::<usize>();
            let words = bytes
                .checked_add(word_size.saturating_sub(1))
                .and_then(|rounded| rounded.checked_div(word_size))
                .ok_or(DormantBrokerError::ProcessProof)?;
            let mut words = vec![0_usize; words];
            let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(words.as_mut_ptr().cast::<c_void>());
            // SAFETY: `words` is aligned stable writable storage of `bytes`.
            unsafe { InitializeProcThreadAttributeList(Some(pointer), 2, None, &raw mut bytes) }
                .map_err(|_| DormantBrokerError::ProcessProof)?;
            let attributes = Self {
                pointer,
                words,
                inherited_handles: Box::new([parent.raw(), stdio.raw()]),
                job_handle: Box::new([job.raw()]),
                _parent: parent,
                _stdio: stdio,
                _job: job,
            };
            attributes.install(
                usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                    .map_err(|_| DormantBrokerError::ProcessProof)?,
                attributes.inherited_handles.as_ref(),
            )?;
            attributes.install(
                usize::try_from(PROC_THREAD_ATTRIBUTE_JOB_LIST)
                    .map_err(|_| DormantBrokerError::ProcessProof)?,
                attributes.job_handle.as_ref(),
            )?;
            Ok(attributes)
        }

        fn install(&self, kind: usize, handles: &[HANDLE]) -> Result<(), DormantBrokerError> {
            // SAFETY: the initialized list has a free slot, and the boxed handle
            // array plus its owning resource remain stable through creation.
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
            .map_err(|_| DormantBrokerError::ProcessProof)
        }

        fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.pointer
        }
    }

    impl Drop for CreationAttributes<'_> {
        fn drop(&mut self) {
            debug_assert!(!self.words.is_empty());
            // SAFETY: initialization succeeded and this exact list is deleted once.
            unsafe { DeleteProcThreadAttributeList(self.pointer) };
        }
    }

    struct Debuggee {
        process: Option<OwnedWinHandle>,
        primary_thread: Option<OwnedWinHandle>,
        process_id: u32,
        thread_id: u32,
        pending_event: Option<(u32, u32)>,
        debug_attached: bool,
        suspend_count: u32,
        released: bool,
    }

    impl Debuggee {
        fn new(information: PROCESS_INFORMATION) -> Result<Self, DormantBrokerError> {
            let process = OwnedWinHandle::new(information.hProcess);
            let primary_thread = OwnedWinHandle::new(information.hThread);
            let (process, primary_thread) = match (process, primary_thread) {
                (Some(process), Some(primary_thread)) => (process, primary_thread),
                (process, primary_thread) => {
                    if let Some(process) = process.as_ref() {
                        // SAFETY: this is the process handle returned by the
                        // successful creation whose handle invariant failed.
                        let _ = unsafe { TerminateProcess(process.raw(), REJECTED_EXIT_CODE) };
                        // SAFETY: the same exact process remains retained.
                        let _ = unsafe {
                            WaitForSingleObject(process.raw(), CLEANUP_TIMEOUT_MILLISECONDS)
                        };
                    }
                    // SAFETY: the PID came directly from this creator's
                    // successful `CreateProcessW` result.
                    let _ = unsafe { DebugActiveProcessStop(information.dwProcessId) };
                    drop(primary_thread);
                    return Err(DormantBrokerError::ProcessProof);
                }
            };
            // SAFETY: both exact creation-returned handles remain live.
            let process_id = unsafe { GetProcessId(process.raw()) };
            // SAFETY: same retained creation-handle argument.
            let thread_id = unsafe { GetThreadId(primary_thread.raw()) };
            if process_id == 0
                || thread_id == 0
                || process_id != information.dwProcessId
                || thread_id != information.dwThreadId
            {
                // SAFETY: this is the exact process handle returned by the
                // successful creation whose reported identity was rejected.
                let _ = unsafe { TerminateProcess(process.raw(), REJECTED_EXIT_CODE) };
                // SAFETY: this creator thread exclusively owns the debugger
                // relationship established by the successful creation.
                let _ = unsafe { DebugActiveProcessStop(information.dwProcessId) };
                // SAFETY: the same exact process handle remains retained.
                let _ = unsafe { WaitForSingleObject(process.raw(), CLEANUP_TIMEOUT_MILLISECONDS) };
                return Err(DormantBrokerError::ProcessProof);
            }
            Ok(Self {
                process: Some(process),
                primary_thread: Some(primary_thread),
                process_id,
                thread_id,
                pending_event: None,
                debug_attached: true,
                suspend_count: 1,
                released: false,
            })
        }

        fn primary_thread(&self) -> Result<&OwnedWinHandle, DormantBrokerError> {
            self.primary_thread
                .as_ref()
                .ok_or(DormantBrokerError::ProcessProof)
        }

        fn process_handle(&self) -> Result<BorrowedHandle<'_>, DormantBrokerError> {
            self.process
                .as_ref()
                .map(OwnedWinHandle::as_borrowed)
                .ok_or(DormantBrokerError::ProcessProof)
        }

        #[cfg(test)]
        fn duplicate_process_observation(&self) -> Result<ProcessObservation, DormantBrokerError> {
            let process = self
                .process
                .as_ref()
                .ok_or(DormantBrokerError::ProcessProof)?;
            duplicate_process_observation(process)
        }

        fn release_creation_suspend(&mut self) -> Result<(), DormantBrokerError> {
            // SAFETY: this is the exact primary thread returned suspended with
            // one `CREATE_SUSPENDED` count.
            let previous = unsafe { ResumeThread(self.primary_thread()?.raw()) };
            if previous != 1 {
                return Err(DormantBrokerError::ProcessProof);
            }
            self.suspend_count = 0;
            Ok(())
        }

        fn authenticate_first_event(
            &mut self,
            image: &PinnedBrokerImage,
            deadline: Instant,
        ) -> Result<(), DormantBrokerError> {
            let mut event = DEBUG_EVENT::default();
            let timeout = remaining_milliseconds(deadline, FIRST_EVENT_TIMEOUT_MILLISECONDS)?;
            // SAFETY: this fresh creator thread owns the debugger relationship
            // and `event` is exact writable storage.
            if unsafe { WaitForDebugEventEx(&raw mut event, timeout) }.is_err() {
                // SAFETY: the error is sampled immediately after the failed
                // debugger wait on this same creator thread.
                let timed_out = unsafe { GetLastError() } == ERROR_SEM_TIMEOUT;
                return Err(classify_debug_wait_failure(timed_out, deadline));
            }
            // Record every delivered event before inspecting it so any reject
            // path can continue that exact event before detaching and reaping.
            self.pending_event = Some((event.dwProcessId, event.dwThreadId));
            if event.dwProcessId != self.process_id || event.dwThreadId != self.thread_id {
                return Err(DormantBrokerError::ProcessProof);
            }
            let event_file = match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    // SAFETY: the discriminant was checked immediately above.
                    let create = unsafe { event.u.CreateProcessInfo };
                    // SAFETY: event process/thread handles remain borrowed and live.
                    let event_process_id = unsafe { GetProcessId(create.hProcess) };
                    // SAFETY: same debug-event handle lifetime.
                    let event_thread_id = unsafe { GetThreadId(create.hThread) };
                    if event_process_id != self.process_id || event_thread_id != self.thread_id {
                        return Err(DormantBrokerError::ProcessProof);
                    }
                    OwnedWinHandle::new(create.hFile).ok_or(DormantBrokerError::ProcessProof)?
                }
                LOAD_DLL_DEBUG_EVENT => {
                    // SAFETY: the discriminant was checked immediately above.
                    let load = unsafe { event.u.LoadDll };
                    drop(OwnedWinHandle::new(load.hFile));
                    return Err(DormantBrokerError::ProcessProof);
                }
                _ => return Err(DormantBrokerError::ProcessProof),
            };
            image.authenticate_mapped_image(event_file.raw())?;
            drop(event_file);
            // SAFETY: Windows holds every debuggee thread for this event; the
            // exact primary thread currently has zero explicit suspend counts.
            let previous = unsafe { SuspendThread(self.primary_thread()?.raw()) };
            if previous != 0 {
                return Err(DormantBrokerError::ProcessProof);
            }
            self.suspend_count = 1;
            check_deadline(deadline)
        }

        fn detach_while_suspended(&mut self) -> Result<(), DormantBrokerError> {
            if self.pending_event.is_none() || self.suspend_count != 1 || !self.debug_attached {
                return Err(DormantBrokerError::ProcessProof);
            }
            let (process_id, thread_id) =
                self.pending_event.ok_or(DormantBrokerError::ProcessProof)?;
            // SAFETY: these IDs came from the one pending event on this fresh thread.
            unsafe { ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE) }
                .map_err(|_| DormantBrokerError::ProcessProof)?;
            self.pending_event = None;
            // SAFETY: this creator just continued its exact event while the
            // primary thread retains one explicit suspend count.
            unsafe { DebugActiveProcessStop(self.process_id) }
                .map_err(|_| DormantBrokerError::ProcessProof)?;
            self.debug_attached = false;
            Ok(())
        }

        fn start_user_mode(&mut self) -> Result<(), DormantBrokerError> {
            if self.pending_event.is_some() || self.debug_attached || self.suspend_count != 1 {
                return Err(DormantBrokerError::ProcessProof);
            }
            // SAFETY: the exact detached primary thread retains one proven count.
            let previous = unsafe { ResumeThread(self.primary_thread()?.raw()) };
            if previous != 1 {
                return Err(DormantBrokerError::ProcessProof);
            }
            self.suspend_count = 0;
            Ok(())
        }

        fn into_running(mut self) -> Result<OwnedWinHandle, DormantBrokerError> {
            if self.pending_event.is_some() || self.debug_attached || self.suspend_count != 0 {
                return Err(DormantBrokerError::ProcessProof);
            }
            let process = self
                .process
                .take()
                .ok_or(DormantBrokerError::ProcessProof)?;
            drop(self.primary_thread.take());
            self.released = true;
            Ok(process)
        }

        fn abort(&mut self) {
            let Some(process) = self.process.as_ref() else {
                return;
            };
            // SAFETY: rejection always targets the exact still-owned debuggee.
            let _ = unsafe { TerminateProcess(process.raw(), REJECTED_EXIT_CODE) };
            if let Some((process_id, thread_id)) = self.pending_event {
                // SAFETY: these IDs name the one event retained by this thread;
                // termination was requested before it is released.
                let _ = unsafe { ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE) };
                self.pending_event = None;
            }
            if self.debug_attached {
                // SAFETY: only this creator thread owns this debug relationship.
                let _ = unsafe { DebugActiveProcessStop(self.process_id) };
                self.debug_attached = false;
            }
            // SAFETY: the exact retained process handle remains live for the wait.
            let _ = unsafe { WaitForSingleObject(process.raw(), CLEANUP_TIMEOUT_MILLISECONDS) };
        }
    }

    impl Drop for Debuggee {
        fn drop(&mut self) {
            if !self.released {
                self.abort();
            }
        }
    }

    fn minimal_environment(
        endpoint: &OsStr,
        parent_handle: usize,
    ) -> Result<Vec<u16>, DormantBrokerError> {
        let parent = parent_handle.to_string();
        let mut entries = [
            environment_entry(BROKER_ENDPOINT_ENV, endpoint)?,
            environment_entry(PARENT_PROCESS_HANDLE_ENV, OsStr::new(&parent))?,
        ];
        entries.sort_by_key(|entry| entry.to_ascii_uppercase());
        let mut block = Vec::new();
        for entry in entries {
            block.extend(entry.encode_wide());
            block.push(0);
        }
        block.push(0);
        Ok(block)
    }

    fn environment_entry(name: &str, value: &OsStr) -> Result<OsString, DormantBrokerError> {
        if name.is_empty()
            || name.contains('=')
            || name.contains('\0')
            || value.encode_wide().any(|unit| unit == 0)
        {
            return Err(DormantBrokerError::ProcessProof);
        }
        let mut entry = OsString::from(name);
        entry.push("=");
        entry.push(value);
        Ok(entry)
    }

    fn creation_flags() -> windows::Win32::System::Threading::PROCESS_CREATION_FLAGS {
        CREATE_SUSPENDED
            | DEBUG_PROCESS
            | DEBUG_ONLY_THIS_PROCESS
            | CREATE_NO_WINDOW
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT
    }

    fn classify_debug_wait_failure(timed_out: bool, deadline: Instant) -> DormantBrokerError {
        if timed_out && Instant::now() >= deadline {
            DormantBrokerError::Deadline
        } else {
            DormantBrokerError::ProcessProof
        }
    }

    #[cfg(test)]
    pub(super) fn classify_debug_wait_failure_for_test(
        timed_out: bool,
        deadline: Instant,
    ) -> DormantBrokerError {
        classify_debug_wait_failure(timed_out, deadline)
    }

    fn remaining_milliseconds(deadline: Instant, maximum: u32) -> Result<u32, DormantBrokerError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(DormantBrokerError::Deadline);
        }
        let remaining = deadline.duration_since(now);
        let rounded = remaining
            .checked_add(Duration::from_nanos(999_999))
            .ok_or(DormantBrokerError::Deadline)?
            .as_millis();
        let milliseconds =
            u32::try_from(rounded.max(1)).map_err(|_| DormantBrokerError::ProcessProof)?;
        Ok(milliseconds.min(maximum))
    }

    fn check_deadline(deadline: Instant) -> Result<(), DormantBrokerError> {
        (Instant::now() < deadline)
            .then_some(())
            .ok_or(DormantBrokerError::Deadline)
    }

    fn invalid(handle: HANDLE) -> bool {
        handle.is_invalid() || handle == INVALID_HANDLE_VALUE
    }

    struct OwnedWinHandle(HANDLE);

    impl OwnedWinHandle {
        fn new(handle: HANDLE) -> Option<Self> {
            (!invalid(handle)).then_some(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0
        }

        fn as_borrowed(&self) -> BorrowedHandle<'_> {
            // SAFETY: `self` uniquely owns this live handle and bounds the borrow.
            unsafe { BorrowedHandle::borrow_raw(self.0.0) }
        }
    }

    impl Drop for OwnedWinHandle {
        fn drop(&mut self) {
            if !invalid(self.0) {
                // SAFETY: this wrapper owns one successful handle result exactly once.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::{
        BROKER_ENDPOINT_ENV, DormantBrokerError, PARENT_PROCESS_HANDLE_ENV,
        connect_inherited_native_host_channel, launch_broker_path_for_test, sys,
    };
    use crate::exact_image::PinnedBrokerImage;

    const CHILD_ECHO_TEST: &str = "broker_supervisor::tests::dormant_broker_child_echo";
    const CHILD_HANG_TEST: &str = "broker_supervisor::tests::dormant_broker_child_hang";
    const SENTINEL_HANDLE_FILE: &str = "unrelated-inheritable-handle.txt";
    const HEX: &[u8; 16] = b"0123456789abcdef";

    struct TestArtifacts {
        directory: PathBuf,
        broker: PathBuf,
        mismatch: PathBuf,
    }

    impl TestArtifacts {
        fn create() -> Result<Self, Box<dyn std::error::Error>> {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| DormantBrokerError::ProcessProof)?;
            let mut token = String::with_capacity(random.len() * 2);
            for byte in random {
                token.push(char::from(HEX[usize::from(byte >> 4)]));
                token.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
            let directory =
                std::env::temp_dir().join(format!("your-wallet-dormant-broker-{token}"));
            fs::create_dir(&directory)?;
            let source = std::env::current_exe()?;
            let broker = directory.join("broker.exe");
            let mismatch = directory.join("mismatch.exe");
            fs::copy(&source, &broker)?;
            fs::copy(&source, &mismatch)?;
            Ok(Self {
                directory,
                broker,
                mismatch,
            })
        }

        fn arm_unrelated_inheritable_sentinel(
            &self,
        ) -> Result<sys::InheritableSentinel, Box<dyn std::error::Error>> {
            let sentinel = sys::InheritableSentinel::create()?;
            fs::write(
                self.directory.join(SENTINEL_HANDLE_FILE),
                sentinel.raw_value().to_string(),
            )?;
            Ok(sentinel)
        }
    }

    impl Drop for TestArtifacts {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn exact_hidden_supervisor_round_trips_one_be_frame_and_8192_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifacts = TestArtifacts::create()?;
        let unrelated_sentinel = artifacts.arm_unrelated_inheritable_sentinel()?;
        let command = child_command(&artifacts.broker, CHILD_ECHO_TEST);
        let mut channel =
            launch_broker_path_for_test(&artifacts.broker, &command, deadline_after(20))?;
        unrelated_sentinel.assert_not_signaled()?;

        let golden = br#"{"kind":"golden","value":1}"#;
        channel.write_payload(golden, deadline_after(5))?;
        assert_eq!(
            channel.read_payload(deadline_after(5))?,
            Some(golden.to_vec())
        );

        let mut maximum = vec![b'a'; 8_192];
        maximum[0] = b'"';
        maximum[8_191] = b'"';
        channel.write_payload(&maximum, deadline_after(5))?;
        assert_eq!(channel.read_payload(deadline_after(5))?, Some(maximum));
        drop(channel);
        Ok(())
    }

    #[test]
    fn mismatched_mapped_file_is_rejected_before_user_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifacts = TestArtifacts::create()?;
        let image = PinnedBrokerImage::hold(&artifacts.broker)?;
        let result = sys::launch_broker_application_for_test(
            image,
            &artifacts.mismatch,
            &OsString::from(r"\\.\pipe\LOCAL\unreachable-dormant-broker-test"),
            None,
            deadline_after(10),
        );
        assert!(matches!(result, Err(DormantBrokerError::Artifact)));
        Ok(())
    }

    #[test]
    fn dropping_channel_terminates_and_reaps_a_hung_exact_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifacts = TestArtifacts::create()?;
        let unrelated_sentinel = artifacts.arm_unrelated_inheritable_sentinel()?;
        let command = child_command(&artifacts.broker, CHILD_HANG_TEST);
        let mut channel =
            launch_broker_path_for_test(&artifacts.broker, &command, deadline_after(20))?;
        unrelated_sentinel.assert_not_signaled()?;
        assert_eq!(
            channel.read_payload(deadline_after(5))?,
            Some(br#"{"ready":true}"#.to_vec())
        );
        let observation = channel.process_observation_for_test()?;
        drop(channel);
        observation.wait_terminated()?;
        Ok(())
    }

    #[test]
    fn panic_after_create_terminates_and_reaps_the_exact_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifacts = TestArtifacts::create()?;
        let image = PinnedBrokerImage::hold(&artifacts.broker)?;
        let application = artifacts.broker.clone();
        let command = child_command(&application, CHILD_HANG_TEST);
        let endpoint = OsString::from(r"\\.\pipe\LOCAL\unreachable-panic-broker-test");
        let (observation_sender, observation_receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            sys::panic_after_create_for_test(
                image,
                &application,
                &endpoint,
                Some(command),
                deadline_after(10),
                observation_sender,
            )
        });
        assert!(worker.join().is_err());
        observation_receiver.recv()?.wait_terminated()?;
        Ok(())
    }

    #[test]
    fn debug_wait_timeout_maps_to_deadline_only_at_absolute_expiry() {
        let expired = Instant::now();
        assert_eq!(
            sys::classify_debug_wait_failure_for_test(true, expired),
            DormantBrokerError::Deadline
        );
        assert_eq!(
            sys::classify_debug_wait_failure_for_test(true, deadline_after(10)),
            DormantBrokerError::ProcessProof
        );
        assert_eq!(
            sys::classify_debug_wait_failure_for_test(false, expired),
            DormantBrokerError::ProcessProof
        );
    }

    #[test]
    #[ignore = "launched only as the exact hidden Broker child"]
    fn dormant_broker_child_echo() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(BROKER_ENDPOINT_ENV).is_none() {
            return Ok(());
        }
        assert_child_kernel_contract()?;
        let mut channel = connect_inherited_native_host_channel(deadline_after(10))?;
        for _ in 0..2 {
            let payload = channel
                .read_payload(deadline_after(10))?
                .ok_or(DormantBrokerError::Channel)?;
            channel.write_payload(&payload, deadline_after(10))?;
        }
        assert_eq!(channel.read_payload(deadline_after(10))?, None);
        Ok(())
    }

    #[test]
    #[ignore = "launched only as the exact hidden Broker child"]
    fn dormant_broker_child_hang() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(BROKER_ENDPOINT_ENV).is_none() {
            return Ok(());
        }
        assert_child_kernel_contract()?;
        let mut channel = connect_inherited_native_host_channel(deadline_after(10))?;
        channel.write_payload(br#"{"ready":true}"#, deadline_after(10))?;
        loop {
            std::thread::park_timeout(Duration::from_mins(1));
        }
    }

    fn assert_minimal_environment() {
        let names = std::env::vars_os()
            .map(|(name, _value)| name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            [
                OsString::from(BROKER_ENDPOINT_ENV),
                OsString::from(PARENT_PROCESS_HANDLE_ENV),
            ]
            .into_iter()
            .collect()
        );
    }

    fn assert_child_kernel_contract() -> Result<(), Box<dyn std::error::Error>> {
        assert_minimal_environment();
        let executable = std::env::current_exe()?;
        let directory = executable
            .parent()
            .ok_or(DormantBrokerError::ProcessProof)?;
        let raw = fs::read_to_string(directory.join(SENTINEL_HANDLE_FILE))?;
        let unrelated_parent_handle = raw.parse::<usize>()?;
        sys::assert_child_kernel_contract(unrelated_parent_handle)?;
        Ok(())
    }

    fn child_command(executable: &Path, test_name: &str) -> OsString {
        let mut command = OsString::from("\"");
        command.push(executable.as_os_str());
        command.push("\" ");
        command.push(test_name);
        command.push(" --exact --ignored --test-threads=1");
        command
    }

    fn deadline_after(seconds: u64) -> Instant {
        Instant::now() + Duration::from_secs(seconds)
    }
}
