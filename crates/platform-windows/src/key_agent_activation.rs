//! Dormant, fail-closed proof for one exact suspended Key Agent activation.
//!
//! This module deliberately exposes no runtime arming API outside this crate.
//! The supervisor must verify and pin the Key Agent artifact before creation,
//! then compare that held file with the image-file handle supplied by the first
//! Windows process-creation debug event. A successful value still owns a
//! suspended process; dropping it terminates the process without resuming user
//! code.

#![allow(dead_code)]

use core::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Instant;

use thiserror::Error;

use crate::{
    attestation::ReleaseAttestation,
    helper::VerifiedHelper,
    key_agent_root_job::{KeyAgentRootJob, KeyAgentRootJobAttribute},
    pipe::PrivateKeyAgentPipes,
};

const FIRST_DEBUG_EVENT_TIMEOUT_MILLISECONDS: u32 = 5_000;

/// Stable failures from the dormant Key Agent activation boundary.
///
/// Raw paths, handles, file identifiers, process identifiers, timestamps, and
/// operating-system diagnostics are intentionally excluded.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum KeyAgentActivationError {
    /// The verified manifest did not name the exact Key Agent role.
    #[error("verified artifact is not the Key Agent")]
    WrongRole,
    /// Release-bound Windows evidence is not compiled into this build.
    #[error("Key Agent activation release evidence is unavailable")]
    ReleaseNotAttested,
    /// The exact manifest was absent from the compiled release allowlist.
    #[error("Key Agent manifest is not release-allowlisted")]
    ManifestNotAllowed,
    /// The verified executable path was not an absolute path.
    #[error("Key Agent executable path is invalid")]
    InvalidPath,
    /// Windows could not query the exact file-object identity.
    #[error("Key Agent artifact identity query failed")]
    ArtifactIdentity,
    /// Windows could not create the process in the required suspended state.
    #[error("suspended Key Agent creation failed")]
    ProcessCreation,
    /// The exact minimal environment or System32 working directory was unsafe.
    #[error("Key Agent process context policy failed")]
    ProcessContextPolicy,
    /// The inherited private-channel creation attributes could not be bound.
    #[error("Key Agent private-channel creation policy failed")]
    PrivateChannelPolicy,
    /// The process was not proven to be the sole member of the exact root Job.
    #[error("Key Agent root Job binding verification failed")]
    RootJobPolicy,
    /// The child token did not prove the exact zero-capability Key Agent LPAC.
    #[error("Key Agent LPAC policy verification failed")]
    LpacPolicy,
    /// The fresh activation worker could not be created or did not return.
    #[error("dedicated Key Agent activation worker failed")]
    ActivationWorker,
    /// Returned process or thread objects did not match `PROCESS_INFORMATION`.
    #[error("created Key Agent process identity mismatch")]
    ProcessIdentityMismatch,
    /// A documented suspend-count transition was not exact.
    #[error("Key Agent suspension invariant mismatch")]
    SuspensionMismatch,
    /// The first debug event did not arrive inside the fixed bound.
    #[error("Key Agent process-creation debug event timed out")]
    DebugEventTimeout,
    /// The first debug event was not the exact process-creation event.
    #[error("unexpected Key Agent debug event")]
    UnexpectedDebugEvent,
    /// Windows did not provide a valid executable-image file handle.
    #[error("Key Agent mapped-image handle is unavailable")]
    MissingMappedImage,
    /// The mapped executable and the pre-held verified artifact were different
    /// file objects.
    #[error("Key Agent mapped image does not match the held artifact")]
    MappedImageMismatch,
    /// The exact process creation time could not be sampled.
    #[error("Key Agent creation time query failed")]
    CreationTime,
    /// The debug event could not be continued and detached while suspended.
    #[error("Key Agent debugger detach failed")]
    DebugDetach,
    /// A rejected suspended process could not be synchronously cleaned up.
    #[error("rejected Key Agent cleanup failed")]
    Cleanup,
}

/// Exact identity used only to compare two simultaneously open file handles.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ExactFileObjectIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

impl ExactFileObjectIdentity {
    fn from_file_id_info(
        volume_serial_number: u64,
        file_id: [u8; 16],
    ) -> Result<Self, KeyAgentActivationError> {
        // [MS-FSCC] 2.1.10 reserves all-zero for filesystems without a
        // 128-bit identifier and all-ones when a unique identifier cannot be
        // established. Neither value can authenticate an exact file object.
        // A zero volume serial likewise cannot contribute the second required
        // half of Microsoft's (volume, 128-bit ID) identity tuple.
        if volume_serial_number == 0 || file_id == [0; 16] || file_id == [u8::MAX; 16] {
            return Err(KeyAgentActivationError::ArtifactIdentity);
        }
        Ok(Self {
            volume_serial_number,
            file_id,
        })
    }
}

impl fmt::Debug for ExactFileObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactFileObjectIdentity([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchPhase {
    AwaitingCreateEvent,
    CreateEventHeld,
    EventContinued,
    DetachedSuspended,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchTransition {
    ReceiveCreateEvent,
    ContinueCreateEvent,
    DetachDebugger,
    Abort,
}

impl LaunchPhase {
    fn transition(self, transition: LaunchTransition) -> Result<Self, KeyAgentActivationError> {
        match (self, transition) {
            (Self::AwaitingCreateEvent, LaunchTransition::ReceiveCreateEvent) => {
                Ok(Self::CreateEventHeld)
            }
            (Self::CreateEventHeld, LaunchTransition::ContinueCreateEvent) => {
                Ok(Self::EventContinued)
            }
            (Self::EventContinued, LaunchTransition::DetachDebugger) => Ok(Self::DetachedSuspended),
            (
                Self::AwaitingCreateEvent
                | Self::CreateEventHeld
                | Self::EventContinued
                | Self::DetachedSuspended,
                LaunchTransition::Abort,
            ) => Ok(Self::Aborted),
            _ => Err(KeyAgentActivationError::DebugDetach),
        }
    }
}

/// Opaque ownership of one exact Key Agent that has not executed user code.
///
/// This type is non-cloneable and crate-private. It retains the original
/// `FILE_SHARE_READ`-only [`VerifiedHelper`] handle, exact process and primary
/// thread handles, the 128-bit file-object proof, and process creation time.
/// There is deliberately no resume method in this dormant slice.
pub(crate) struct HeldKeyAgentActivation {
    process: sys::DetachedSuspendedDebuggee,
    // Keep the process field first so its Drop cleanup runs before the pinned
    // artifact is closed, even if the explicit Held drop cleanup failed.
    artifact: VerifiedHelper,
    artifact_identity: ExactFileObjectIdentity,
    creation_time: u64,
}

impl HeldKeyAgentActivation {
    pub(crate) const fn process_id(&self) -> u32 {
        self.process.process_id()
    }

    pub(crate) const fn creation_time(&self) -> u64 {
        self.creation_time
    }

    pub(crate) const fn artifact_identity(&self) -> ExactFileObjectIdentity {
        self.artifact_identity
    }

    pub(crate) fn is_detached_and_suspended(&self) -> bool {
        self.process.is_detached_and_suspended()
    }

    #[cfg(test)]
    pub(crate) fn duplicate_process_observation(
        &self,
    ) -> Result<KeyAgentProcessObservation, KeyAgentActivationError> {
        self.process
            .duplicate_process_observation()
            .map(KeyAgentProcessObservation)
    }

    #[cfg(test)]
    pub(crate) fn is_member_of_root_job_for_test(
        &self,
        root_job: &KeyAgentRootJob,
    ) -> Result<bool, KeyAgentActivationError> {
        self.process.is_member_of_root_job_for_test(root_job)
    }
}

/// Test-only, observation-only duplicate of the exact activated process.
///
/// This capability exposes no handle, process identifier, termination, suspend,
/// resume, or duplication operation. It exists only so integrated kernel tests
/// can prove that dropping the dormant aggregate synchronously kills the child.
#[cfg(test)]
pub(crate) struct KeyAgentProcessObservation(sys::TestProcessObservation);

#[cfg(test)]
impl KeyAgentProcessObservation {
    pub(crate) fn rejected_exit_code(&self) -> Result<u32, KeyAgentActivationError> {
        self.0.rejected_exit_code()
    }
}

#[cfg(test)]
impl fmt::Debug for KeyAgentProcessObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentProcessObservation([OBSERVATION-ONLY HANDLE])")
    }
}

impl fmt::Debug for HeldKeyAgentActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeldKeyAgentActivation")
            .field("artifact", &"[VERIFIED KEY AGENT ARTIFACT]")
            .field("process", &"[SUSPENDED PROCESS AND THREAD HANDLES]")
            .field("lpac", &"[VERIFIED ZERO-CAPABILITY KEY AGENT LPAC]")
            .field("artifact_identity", &"[FILE_ID_INFO]")
            .field("creation_time", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for HeldKeyAgentActivation {
    fn drop(&mut self) {
        // Abort while `artifact` still pins the verified file object. Field
        // destruction closes that read-only pin only after the process has
        // synchronously terminated (or cleanup has failed closed).
        let _ = self.process.abort();
    }
}

/// Opaque pre-spawn proof that the pinned artifact passed every release gate.
///
/// Construction performs the complete role -> release evidence -> manifest
/// allowlist -> absolute-path sequence before a worker, Job, pipe, or process
/// is created. The held [`VerifiedHelper`] remains pinned through exact-image
/// authentication. This capability is non-cloneable and has no artifact or
/// raw-handle accessor.
pub(crate) struct PreflightKeyAgentArtifact {
    artifact: VerifiedHelper,
}

impl fmt::Debug for PreflightKeyAgentArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreflightKeyAgentArtifact([PINNED VERIFIED ARTIFACT])")
    }
}

/// Performs all release gates before any activation resource is allocated.
pub(crate) fn preflight_key_agent_activation(
    attestation: ReleaseAttestation,
    artifact: VerifiedHelper,
) -> Result<PreflightKeyAgentArtifact, KeyAgentActivationError> {
    if !artifact.is_key_agent() {
        return Err(KeyAgentActivationError::WrongRole);
    }
    if !attestation.signing_enabled() {
        return Err(KeyAgentActivationError::ReleaseNotAttested);
    }
    if !attestation.allows_helper_manifest(artifact.manifest_digest()) {
        return Err(KeyAgentActivationError::ManifestNotAllowed);
    }
    if !artifact.path().is_absolute() {
        return Err(KeyAgentActivationError::InvalidPath);
    }

    Ok(PreflightKeyAgentArtifact { artifact })
}

/// One-shot proof that code is running on the activation-owned fresh OS thread.
///
/// The constructor and field are module-private. The `Rc` marker makes the
/// token `!Send + !Sync`; it is created only after the worker starts and is
/// consumed by the single process-creation operation, so callers cannot forge,
/// transfer, return, or reuse the debugger-thread authority.
pub(crate) struct FreshKeyAgentDebugThread {
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for FreshKeyAgentDebugThread {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshKeyAgentDebugThread([ONE-SHOT WORKER PROOF])")
    }
}

/// Runs one closure on a newly-created Key Agent debugger OS thread.
///
/// Win32 associates `WaitForDebugEventEx`, `ContinueDebugEvent`, and debugger
/// detach with the thread that called `CreateProcessW`. A caller thread may
/// already own unrelated debuggees, so using it would let their queued events
/// contaminate this one-event authentication protocol. `std::thread::spawn`
/// creates a fresh OS thread and constructs the unforgeable one-shot token only
/// inside it. Only a `Send + 'static` result can cross the join boundary.
pub(crate) fn run_on_fresh_key_agent_debug_thread<T, E, F>(worker: F) -> Result<T, E>
where
    T: Send + 'static,
    E: From<KeyAgentActivationError> + Send + 'static,
    F: FnOnce(FreshKeyAgentDebugThread) -> Result<T, E> + Send + 'static,
{
    let worker = std::thread::Builder::new()
        .name("key-agent-activation".to_owned())
        .spawn(move || {
            worker(FreshKeyAgentDebugThread {
                _not_send_or_sync: PhantomData,
            })
        })
        .map_err(|_| E::from(KeyAgentActivationError::ActivationWorker))?;
    worker
        .join()
        .map_err(|_| E::from(KeyAgentActivationError::ActivationWorker))?
}

/// Creates and exact-image authenticates one preflighted Key Agent.
///
/// The one-shot debugger-thread token and both lifetime-bound creation
/// capabilities must have been constructed inside the same fresh worker. The
/// returned process remains detached with one proven suspend count. This
/// function exposes neither a raw handle nor a resume/start operation.
pub(crate) fn activate_preflighted_key_agent_on_fresh_worker(
    fresh_thread: FreshKeyAgentDebugThread,
    preflighted: PreflightKeyAgentArtifact,
    pipes: &PrivateKeyAgentPipes,
    root_job: &KeyAgentRootJob,
    root_job_attribute: &KeyAgentRootJobAttribute<'_>,
    coordination_deadline: Instant,
) -> Result<HeldKeyAgentActivation, KeyAgentActivationError> {
    let PreflightKeyAgentArtifact { artifact } = preflighted;
    let artifact_identity = sys::exact_file_identity(artifact.raw_handle())?;
    activate_preflighted_key_agent_on_fresh_worker_with_identity(
        fresh_thread,
        artifact,
        artifact_identity,
        pipes,
        root_job,
        root_job_attribute,
        coordination_deadline,
    )
}

fn activate_preflighted_key_agent_on_fresh_worker_with_identity(
    _fresh_thread: FreshKeyAgentDebugThread,
    artifact: VerifiedHelper,
    artifact_identity: ExactFileObjectIdentity,
    pipes: &PrivateKeyAgentPipes,
    root_job: &KeyAgentRootJob,
    root_job_attribute: &KeyAgentRootJobAttribute<'_>,
    coordination_deadline: Instant,
) -> Result<HeldKeyAgentActivation, KeyAgentActivationError> {
    verify_empty_root_job(root_job)?;
    let mut process = sys::SuspendedDebuggee::create(
        &artifact,
        pipes,
        root_job,
        root_job_attribute,
        coordination_deadline,
    )?;
    let first_event = match process
        .authenticate_first_event(artifact_identity, FIRST_DEBUG_EVENT_TIMEOUT_MILLISECONDS)
    {
        Ok(event) => event,
        Err(error) => return fail_after_cleanup(&mut process, error),
    };
    if let Err(error) = process.detach_still_suspended() {
        return fail_after_cleanup(&mut process, error);
    }
    if let Err(error) = verify_bound_root_process(root_job, process.process_handle()) {
        return fail_after_cleanup(&mut process, error);
    }
    let process = process.into_detached()?;

    Ok(HeldKeyAgentActivation {
        process,
        artifact,
        artifact_identity,
        creation_time: first_event.creation_time,
    })
}

fn verify_empty_root_job(root_job: &KeyAgentRootJob) -> Result<(), KeyAgentActivationError> {
    root_job
        .verify_effective_limits()
        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
    (root_job
        .active_process_count()
        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?
        == 0)
        .then_some(())
        .ok_or(KeyAgentActivationError::RootJobPolicy)
}

fn verify_bound_root_process(
    root_job: &KeyAgentRootJob,
    process: std::os::windows::io::BorrowedHandle<'_>,
) -> Result<(), KeyAgentActivationError> {
    root_job
        .recheck_supervisor_context()
        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
    root_job
        .verify_effective_limits()
        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
    let is_member = root_job
        .contains_process(process)
        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
    let active_processes = root_job
        .active_process_count()
        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
    (is_member && active_processes == 1)
        .then_some(())
        .ok_or(KeyAgentActivationError::RootJobPolicy)
}

fn fail_after_cleanup<T>(
    process: &mut sys::SuspendedDebuggee,
    error: KeyAgentActivationError,
) -> Result<T, KeyAgentActivationError> {
    process
        .abort()
        .map_err(|_| KeyAgentActivationError::Cleanup)?;
    Err(error)
}

#[cfg(windows)]
mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::fmt;
    use core::mem::{size_of, size_of_val};
    use core::ptr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};
    #[cfg(test)]
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::time::Instant;

    use windows::Win32::Foundation::{
        CloseHandle, DBG_CONTINUE, ERROR_SEM_TIMEOUT, FILETIME, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    #[cfg(test)]
    use windows::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
    use windows::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };
    use windows::Win32::System::Diagnostics::Debug::{
        CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcessStop,
        LOAD_DLL_DEBUG_EVENT, WaitForDebugEventEx,
    };
    #[cfg(test)]
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS,
        DEBUG_PROCESS, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        GetExitCodeProcess, GetProcessId, GetProcessTimes, GetThreadId,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, SuspendThread, TerminateProcess, UpdateProcThreadAttribute,
        WaitForSingleObject,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::{ExactFileObjectIdentity, KeyAgentActivationError, LaunchPhase, LaunchTransition};
    use crate::helper::VerifiedHelper;
    use crate::inheritable_handle_launch::{
        InheritableHandleLaunchFlight, acquire_inheritable_handle_launch,
    };
    use crate::key_agent_lpac::{PreparedKeyAgentLpac, VerifiedKeyAgentLpac};
    use crate::key_agent_root_job::{KeyAgentRootJob, KeyAgentRootJobAttribute};
    use crate::pipe::{PreparedKeyAgentInheritance, PrivateKeyAgentPipes};
    use crate::restricted_process_context::RestrictedProcessContext;

    const CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000;
    const REJECTED_PROCESS_EXIT_CODE: u32 = 0xE0A0_0001;

    /// Initialized four-slot process-creation policy retained through one call.
    ///
    /// The backing words, the exact three-HANDLE array, the prepared pipe
    /// capability, and the stable Job-HANDLE attribute all outlive
    /// `CreateProcessW`. Drop deletes the native list before any retained
    /// storage or borrow is released.
    struct KeyAgentCreationAttributes<'resources, 'pipes, 'flight, 'job> {
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        words: Vec<usize>,
        inherited_handles: Box<[HANDLE; 3]>,
        _inheritance: &'resources PreparedKeyAgentInheritance<'pipes, 'flight>,
        root_job_attribute: &'resources KeyAgentRootJobAttribute<'job>,
        lpac: &'resources PreparedKeyAgentLpac,
    }

    impl<'resources, 'pipes, 'flight, 'job>
        KeyAgentCreationAttributes<'resources, 'pipes, 'flight, 'job>
    {
        fn new(
            inheritance: &'resources PreparedKeyAgentInheritance<'pipes, 'flight>,
            root_job_attribute: &'resources KeyAgentRootJobAttribute<'job>,
            lpac: &'resources PreparedKeyAgentLpac,
        ) -> Result<Self, KeyAgentActivationError> {
            let mut bytes = 0_usize;
            // SAFETY: the documented sizing call uses a null attribute list and
            // initializes `bytes`; its expected false result is not an error.
            let _ = unsafe { InitializeProcThreadAttributeList(None, 4, None, &raw mut bytes) };
            if bytes == 0 {
                return Err(KeyAgentActivationError::PrivateChannelPolicy);
            }
            let word_size = size_of::<usize>();
            let word_count = bytes
                .checked_add(word_size - 1)
                .and_then(|rounded| rounded.checked_div(word_size))
                .ok_or(KeyAgentActivationError::PrivateChannelPolicy)?;
            let mut words = vec![0_usize; word_count];
            let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(words.as_mut_ptr().cast::<c_void>());
            // SAFETY: `words` is aligned writable storage of at least `bytes`
            // and cannot reallocate while this wrapper is alive.
            unsafe { InitializeProcThreadAttributeList(Some(pointer), 4, None, &raw mut bytes) }
                .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;

            let inherited_handles = Box::new([
                windows_handle(inheritance.stdin()),
                windows_handle(inheritance.stdout()),
                windows_handle(inheritance.stderr()),
            ]);
            let attributes = Self {
                pointer,
                words,
                inherited_handles,
                _inheritance: inheritance,
                root_job_attribute,
                lpac,
            };
            attributes.install_handle_list()?;
            // SAFETY: this initialized list has its second free slot, and this
            // wrapper retains the stable lifetime-bound Job attribute until its
            // Drop deletes the list.
            unsafe {
                attributes
                    .root_job_attribute
                    .install_into(attributes.pointer)
            }
            .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
            // SAFETY: the initialized list has exactly two slots remaining.
            // `lpac` retains both its SID and heap-stable attribute values until
            // this list is deleted by Drop.
            unsafe { attributes.lpac.install_into(attributes.pointer) }
                .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
            Ok(attributes)
        }

        fn install_handle_list(&self) -> Result<(), KeyAgentActivationError> {
            // SAFETY: the list is live with one free slot. The boxed array has
            // a stable address and all three values remain valid/inheritable
            // through CreateProcess because `_inheritance` is retained.
            unsafe {
                UpdateProcThreadAttribute(
                    self.pointer,
                    0,
                    usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                        .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?,
                    Some(self.inherited_handles.as_ptr().cast::<c_void>()),
                    size_of_val(self.inherited_handles.as_ref()),
                    None,
                    None,
                )
            }
            .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)
        }

        const fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.pointer
        }

        const fn stdin(&self) -> HANDLE {
            self.inherited_handles[0]
        }

        const fn stdout(&self) -> HANDLE {
            self.inherited_handles[1]
        }

        const fn stderr(&self) -> HANDLE {
            self.inherited_handles[2]
        }

        #[cfg(test)]
        const fn explicit_handle_count(&self) -> usize {
            self.inherited_handles.len()
        }
    }

    impl Drop for KeyAgentCreationAttributes<'_, '_, '_, '_> {
        fn drop(&mut self) {
            debug_assert!(!self.words.is_empty());
            // SAFETY: initialization succeeded, and this exact list is deleted
            // once before its backing storage and borrowed attributes drop.
            unsafe { DeleteProcThreadAttributeList(self.pointer) };
        }
    }

    struct PreparedKeyAgentProcess {
        application: Vec<u16>,
        context: RestrictedProcessContext,
        environment: Box<[u16]>,
        lpac: PreparedKeyAgentLpac,
    }

    impl PreparedKeyAgentProcess {
        fn into_lpac(self) -> PreparedKeyAgentLpac {
            self.lpac
        }
    }

    fn prepare_key_agent_process(
        artifact: &VerifiedHelper,
    ) -> Result<PreparedKeyAgentProcess, KeyAgentActivationError> {
        #[cfg(test)]
        let context = RestrictedProcessContext::prepare_for_kernel_test();
        #[cfg(not(test))]
        let context = RestrictedProcessContext::prepare();
        let context = context.map_err(|_| KeyAgentActivationError::ProcessContextPolicy)?;
        let lpac =
            PreparedKeyAgentLpac::prepare().map_err(|_| KeyAgentActivationError::LpacPolicy)?;
        let environment = lpac
            .environment_with_local_app_data(context.environment())
            .map_err(|_| KeyAgentActivationError::ProcessContextPolicy)?;
        let application = artifact
            .path()
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        Ok(PreparedKeyAgentProcess {
            application,
            context,
            environment,
            lpac,
        })
    }

    fn create_suspended_debuggee_process(
        flight: &InheritableHandleLaunchFlight<'_>,
        prepared_process: &PreparedKeyAgentProcess,
        inheritance: &PreparedKeyAgentInheritance<'_, '_>,
        root_job: &KeyAgentRootJob,
        root_job_attribute: &KeyAgentRootJobAttribute<'_>,
        coordination_deadline: Instant,
        command_line: Option<&mut [u16]>,
    ) -> Result<PROCESS_INFORMATION, KeyAgentActivationError> {
        let attributes = KeyAgentCreationAttributes::new(
            inheritance,
            root_job_attribute,
            &prepared_process.lpac,
        )?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
            .map_err(|_| KeyAgentActivationError::ProcessCreation)?;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = attributes.stdin();
        startup.StartupInfo.hStdOutput = attributes.stdout();
        startup.StartupInfo.hStdError = attributes.stderr();
        startup.lpAttributeList = attributes.pointer();
        let mut information = PROCESS_INFORMATION::default();
        let command_line = command_line.map(|buffer| PWSTR(buffer.as_mut_ptr()));
        root_job
            .recheck_supervisor_context()
            .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
        if Instant::now() >= coordination_deadline {
            return Err(KeyAgentActivationError::ProcessCreation);
        }
        prepared_process
            .context
            .recheck_thread()
            .map_err(|_| KeyAgentActivationError::ProcessContextPolicy)?;
        // SAFETY: the verified absolute path is NUL terminated and retained for
        // the call. Production supplies no command line; the test-only buffer is
        // writable and retained. `attributes` is a live initialized four-slot
        // list containing exactly HANDLE_LIST(3), JOB_LIST(1),
        // SECURITY_CAPABILITIES(zero), and the LPAC AAP opt-out policy; the three
        // listed stdio handles are the only inheritable handles. The retained
        // process context supplies a validated System32 current directory and
        // an exact three-name Unicode environment: its OS-derived SystemRoot
        // and WINDIR plus the OS-derived LOCALAPPDATA required by AppContainer
        // creation. The flags keep creation both
        // headless and suspended before user-mode entry.
        unsafe {
            flight
                .create_process_with_explicit_handle_list(
                    PCWSTR(prepared_process.application.as_ptr()),
                    command_line,
                    key_agent_creation_flags(),
                    Some(prepared_process.environment.as_ptr().cast::<c_void>()),
                    PCWSTR(prepared_process.context.current_directory().as_ptr()),
                    ptr::from_ref(&startup.StartupInfo),
                    &raw mut information,
                )
                .map_err(|_| KeyAgentActivationError::ProcessCreation)?;
        }
        Ok(information)
    }

    pub(super) struct SuspendedDebuggee {
        process: OwnedWinHandle,
        primary_thread: OwnedWinHandle,
        process_id: u32,
        thread_id: u32,
        pending_event: Option<(u32, u32)>,
        phase: LaunchPhase,
        prepared_lpac: Option<PreparedKeyAgentLpac>,
        // Present only after the exact suspended primary token proved the
        // fixed Key Agent SID, zero capabilities, and differential LPAC
        // access-membership behavior.
        lpac: Option<VerifiedKeyAgentLpac>,
        // CREATE_SUSPENDED starts at one, then is consumed exactly once so the
        // kernel can deliver the pre-user-mode CREATE_PROCESS debug event. A
        // new explicit count is installed while that event holds all threads.
        // The dormant capability returns detached with exactly that count.
        proven_suspend_count: u32,
        cleanup_exit_code: Option<u32>,
    }

    impl SuspendedDebuggee {
        pub(super) fn create(
            artifact: &VerifiedHelper,
            pipes: &PrivateKeyAgentPipes,
            root_job: &KeyAgentRootJob,
            root_job_attribute: &KeyAgentRootJobAttribute<'_>,
            coordination_deadline: Instant,
        ) -> Result<Self, KeyAgentActivationError> {
            Self::create_inner(
                artifact,
                pipes,
                root_job,
                root_job_attribute,
                coordination_deadline,
                None,
            )
        }

        #[cfg(test)]
        pub(super) fn create_with_test_command_line(
            artifact: &VerifiedHelper,
            pipes: &PrivateKeyAgentPipes,
            root_job: &KeyAgentRootJob,
            root_job_attribute: &KeyAgentRootJobAttribute<'_>,
            coordination_deadline: Instant,
            command_line: &mut [u16],
        ) -> Result<Self, KeyAgentActivationError> {
            Self::create_inner(
                artifact,
                pipes,
                root_job,
                root_job_attribute,
                coordination_deadline,
                Some(command_line),
            )
        }

        fn create_inner(
            artifact: &VerifiedHelper,
            pipes: &PrivateKeyAgentPipes,
            root_job: &KeyAgentRootJob,
            root_job_attribute: &KeyAgentRootJobAttribute<'_>,
            coordination_deadline: Instant,
            command_line: Option<&mut [u16]>,
        ) -> Result<Self, KeyAgentActivationError> {
            let prepared_process = prepare_key_agent_process(artifact)?;
            let flight = acquire_inheritable_handle_launch(coordination_deadline)
                .map_err(|_| KeyAgentActivationError::ProcessCreation)?;
            if Instant::now() >= coordination_deadline {
                return Err(KeyAgentActivationError::ProcessCreation);
            }
            let inheritance = pipes
                .prepare_child_inheritance(&flight)
                .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
            let information = create_suspended_debuggee_process(
                &flight,
                &prepared_process,
                &inheritance,
                root_job,
                root_job_attribute,
                coordination_deadline,
                command_line,
            )?;
            let prepared_lpac = prepared_process.into_lpac();
            let process = OwnedWinHandle::new(information.hProcess);
            let primary_thread = OwnedWinHandle::new(information.hThread);
            drop(inheritance);
            drop(flight);

            let (process, primary_thread) = match (process, primary_thread) {
                (Some(process), Some(primary_thread)) => (process, primary_thread),
                (process, primary_thread) => {
                    // CreateProcessW success is documented to return both
                    // handles. If that invariant is violated, terminate
                    // through whichever process handle exists, detach, and let
                    // the wrappers close every valid handle.
                    if let Some(process) = process.as_ref() {
                        // SAFETY: this is the valid process handle returned by
                        // the successful CreateProcessW call above.
                        let _ =
                            unsafe { TerminateProcess(process.raw(), REJECTED_PROCESS_EXIT_CODE) };
                    }
                    // SAFETY: the PID is the one returned by CreateProcessW
                    // and this creator owns the debug relationship.
                    let _ = unsafe { DebugActiveProcessStop(information.dwProcessId) };
                    if let Some(process) = process.as_ref() {
                        // SAFETY: wait is bounded and uses the same live handle.
                        let _ = unsafe {
                            WaitForSingleObject(process.raw(), CLEANUP_TIMEOUT_MILLISECONDS)
                        };
                    }
                    drop(primary_thread);
                    return Err(KeyAgentActivationError::ProcessIdentityMismatch);
                }
            };
            // SAFETY: both handles are live objects returned by CreateProcessW.
            let actual_process_id = unsafe { GetProcessId(process.raw()) };
            // SAFETY: same ownership argument for the primary thread handle.
            let actual_thread_id = unsafe { GetThreadId(primary_thread.raw()) };
            if actual_process_id == 0
                || actual_thread_id == 0
                || actual_process_id != information.dwProcessId
                || actual_thread_id != information.dwThreadId
            {
                let mut rejected = Self {
                    process,
                    primary_thread,
                    process_id: information.dwProcessId,
                    thread_id: information.dwThreadId,
                    pending_event: None,
                    phase: LaunchPhase::AwaitingCreateEvent,
                    prepared_lpac: None,
                    lpac: None,
                    proven_suspend_count: 1,
                    cleanup_exit_code: None,
                };
                rejected
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::ProcessIdentityMismatch);
            }

            let mut created = Self {
                process,
                primary_thread,
                process_id: actual_process_id,
                thread_id: actual_thread_id,
                pending_event: None,
                phase: LaunchPhase::AwaitingCreateEvent,
                prepared_lpac: Some(prepared_lpac),
                lpac: None,
                proven_suspend_count: 1,
                cleanup_exit_code: None,
            };
            if let Err(error) = super::verify_bound_root_process(root_job, created.process_handle())
            {
                created
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(error);
            }

            // SAFETY: the child primary thread is different from the caller and
            // was returned with suspend/resume access. CREATE_SUSPENDED provides
            // exactly one count. Consuming it is necessary for Windows to
            // generate the CREATE_PROCESS debug event; Microsoft documents that
            // event as occurring before any user-mode execution.
            let previous_suspend_count = unsafe { ResumeThread(created.primary_thread.raw()) };
            if previous_suspend_count != 1 {
                created
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::SuspensionMismatch);
            }
            created.proven_suspend_count = 0;
            Ok(created)
        }

        pub(super) const fn process_id(&self) -> u32 {
            self.process_id
        }

        pub(super) fn process_handle(&self) -> BorrowedHandle<'_> {
            // SAFETY: `self` uniquely owns this live process handle and the
            // returned borrow cannot outlive `self`.
            unsafe { BorrowedHandle::borrow_raw(self.process.raw().0) }
        }

        pub(super) fn is_detached_and_suspended(&self) -> bool {
            self.phase == LaunchPhase::DetachedSuspended
                && self.proven_suspend_count == 1
                && self.prepared_lpac.is_none()
                && self.lpac.is_some()
        }

        pub(super) fn into_detached(
            self,
        ) -> Result<DetachedSuspendedDebuggee, KeyAgentActivationError> {
            if !self.is_detached_and_suspended() || self.pending_event.is_some() {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            Ok(DetachedSuspendedDebuggee(self))
        }

        pub(super) fn authenticate_first_event(
            &mut self,
            expected_artifact: ExactFileObjectIdentity,
            timeout_milliseconds: u32,
        ) -> Result<AuthenticatedFirstEvent, KeyAgentActivationError> {
            if self.phase != LaunchPhase::AwaitingCreateEvent
                || self.prepared_lpac.is_none()
                || self.lpac.is_some()
            {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            let mut event = DEBUG_EVENT::default();
            // SAFETY: event points to exact writable storage and this is the same
            // thread that called CreateProcessW for the debuggee.
            if unsafe { WaitForDebugEventEx(&raw mut event, timeout_milliseconds) }.is_err() {
                // SAFETY: queried immediately after the failed Win32 call.
                return if unsafe { GetLastError() } == ERROR_SEM_TIMEOUT {
                    Err(KeyAgentActivationError::DebugEventTimeout)
                } else {
                    Err(KeyAgentActivationError::UnexpectedDebugEvent)
                };
            }
            // Own and close either documented debug-event file handle before
            // any rejection is returned. Only the create-process handle can be
            // authenticated; a LOAD_DLL first event remains an error.
            let event_file = match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    // SAFETY: the discriminant was matched immediately above.
                    OwnedWinHandle::new(unsafe { event.u.CreateProcessInfo }.hFile)
                }
                LOAD_DLL_DEBUG_EVENT => {
                    // SAFETY: the discriminant was matched immediately above.
                    OwnedWinHandle::new(unsafe { event.u.LoadDll }.hFile)
                }
                _ => None,
            };

            if event.dwProcessId != self.process_id || event.dwThreadId != self.thread_id {
                // Never continue a debug event for an identity outside this
                // activation. Dropping its file handle and retaining the event
                // stop is safer than releasing an unrelated process.
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            self.pending_event = Some((event.dwProcessId, event.dwThreadId));
            self.phase = self
                .phase
                .transition(LaunchTransition::ReceiveCreateEvent)?;
            if event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            // SAFETY: the discriminant was checked immediately above.
            let create = unsafe { event.u.CreateProcessInfo };
            if invalid(create.hFile) {
                return Err(KeyAgentActivationError::MissingMappedImage);
            }
            let event_file = event_file.ok_or(KeyAgentActivationError::MissingMappedImage)?;
            if invalid(create.hProcess) || invalid(create.hThread) {
                return Err(KeyAgentActivationError::ProcessIdentityMismatch);
            }
            // SAFETY: the debug event supplies live borrowed process/thread
            // handles. Windows retains their ownership; only hFile is ours.
            let event_process_id = unsafe { GetProcessId(create.hProcess) };
            // SAFETY: same event-handle ownership argument.
            let event_thread_id = unsafe { GetThreadId(create.hThread) };
            if event_process_id != self.process_id || event_thread_id != self.thread_id {
                return Err(KeyAgentActivationError::ProcessIdentityMismatch);
            }

            let mapped_identity = exact_file_identity(event_file.raw())?;
            if mapped_identity != expected_artifact {
                return Err(KeyAgentActivationError::MappedImageMismatch);
            }
            // The event hFile can carry broader rights than the retained verified
            // artifact. Close it during this event exactly as Microsoft directs;
            // it is never duplicated into the activation capability.
            drop(event_file);

            let creation_time = process_creation_time(self.process.raw())?;

            // SAFETY: Windows has stopped every process thread for this exact
            // CREATE_PROCESS event. The primary thread's explicit count must be
            // zero because CREATE_SUSPENDED was consumed before waiting. Adding
            // one count here guarantees ContinueDebugEvent and detach cannot
            // enter user-mode code.
            let previous_suspend_count = unsafe { SuspendThread(self.primary_thread.raw()) };
            if previous_suspend_count != 0 {
                return Err(KeyAgentActivationError::SuspensionMismatch);
            }
            self.proven_suspend_count = 1;

            let prepared_lpac = self
                .prepared_lpac
                .take()
                .ok_or(KeyAgentActivationError::LpacPolicy)?;
            let verified_lpac = prepared_lpac
                .verify_suspended_process(self.process_handle())
                .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
            self.lpac = Some(verified_lpac);

            Ok(AuthenticatedFirstEvent { creation_time })
        }

        pub(super) fn detach_still_suspended(&mut self) -> Result<(), KeyAgentActivationError> {
            if self.phase != LaunchPhase::CreateEventHeld
                || self.proven_suspend_count != 1
                || self.prepared_lpac.is_some()
                || self.lpac.is_none()
            {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            let (process_id, thread_id) = self
                .pending_event
                .ok_or(KeyAgentActivationError::DebugDetach)?;
            // SAFETY: these exact identifiers came from the event still held by
            // this creator thread. DBG_CONTINUE releases only the debugger event
            // suspension; the explicit guard suspend count remains.
            unsafe { ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE) }
                .map_err(|_| KeyAgentActivationError::DebugDetach)?;
            self.pending_event = None;
            self.phase = self
                .phase
                .transition(LaunchTransition::ContinueCreateEvent)?;

            // SAFETY: this thread created the exact debuggee and just continued
            // its only pending event. The explicit suspension count installed
            // while that event was held prevents user-mode execution.
            unsafe { DebugActiveProcessStop(self.process_id) }
                .map_err(|_| KeyAgentActivationError::DebugDetach)?;
            self.phase = self.phase.transition(LaunchTransition::DetachDebugger)?;

            // SAFETY: the detached primary thread is still owned and explicitly
            // suspended. A previous count of one proves that detachment did not
            // consume the guard. Incrementing to two makes the proof observable.
            let previous_suspend_count = unsafe { SuspendThread(self.primary_thread.raw()) };
            if previous_suspend_count != 1 {
                return Err(KeyAgentActivationError::SuspensionMismatch);
            }
            // SAFETY: the immediately preceding exact transition established a
            // count of two. ResumeThread must return two and restore, not remove,
            // the one retained guard count.
            let previous_suspend_count = unsafe { ResumeThread(self.primary_thread.raw()) };
            if previous_suspend_count != 2 {
                return Err(KeyAgentActivationError::SuspensionMismatch);
            }
            self.proven_suspend_count = 1;
            Ok(())
        }

        pub(super) fn abort(&mut self) -> Result<(), KeyAgentActivationError> {
            if self.phase == LaunchPhase::Aborted {
                return Ok(());
            }
            // SAFETY: this is the exact still-owned process. Termination is
            // requested before a pending event is ever continued, so rejection
            // cannot release the process into user-mode code.
            let termination_requested =
                unsafe { TerminateProcess(self.process.raw(), REJECTED_PROCESS_EXIT_CODE) }.is_ok();
            if !termination_requested {
                // SAFETY: a zero-time wait only observes the exact owned process.
                let already_exited =
                    unsafe { WaitForSingleObject(self.process.raw(), 0) } == WAIT_OBJECT_0;
                if !already_exited {
                    // Keeping the debug event pending is safer than continuing
                    // when Windows did not accept termination.
                    return Err(KeyAgentActivationError::Cleanup);
                }
            }
            if let Some((process_id, thread_id)) = self.pending_event {
                // SAFETY: these identifiers name the pending event owned by this
                // creator thread. Termination was accepted (or the process was
                // already signaled) before this event is continued, so user
                // code cannot be released by this call.
                unsafe { ContinueDebugEvent(process_id, thread_id, DBG_CONTINUE) }
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                self.pending_event = None;
            }
            if self.phase != LaunchPhase::DetachedSuspended {
                // SAFETY: only the creator thread owns this debug relationship.
                // It is best-effort because termination may already have removed
                // the relationship; the process wait below is authoritative.
                let _ = unsafe { DebugActiveProcessStop(self.process_id) };
            }
            // SAFETY: process is a live owned handle and the wait is finite.
            let wait =
                unsafe { WaitForSingleObject(self.process.raw(), CLEANUP_TIMEOUT_MILLISECONDS) };
            if wait != WAIT_OBJECT_0 {
                return Err(KeyAgentActivationError::Cleanup);
            }
            let mut exit_code = 0;
            // SAFETY: the exact process handle remains owned and is signaled.
            unsafe { GetExitCodeProcess(self.process.raw(), &raw mut exit_code) }
                .map_err(|_| KeyAgentActivationError::Cleanup)?;
            if exit_code != REJECTED_PROCESS_EXIT_CODE {
                return Err(KeyAgentActivationError::Cleanup);
            }
            self.cleanup_exit_code = Some(exit_code);
            self.phase = self.phase.transition(LaunchTransition::Abort)?;
            Ok(())
        }

        #[cfg(test)]
        pub(super) fn is_aborted(&self) -> bool {
            self.phase == LaunchPhase::Aborted
        }

        #[cfg(test)]
        pub(super) const fn cleanup_exit_code(&self) -> Option<u32> {
            self.cleanup_exit_code
        }

        #[cfg(test)]
        pub(super) fn duplicate_process_observation(
            &self,
        ) -> Result<TestProcessObservation, KeyAgentActivationError> {
            TestProcessObservation::duplicate(self.process.raw())
        }
    }

    impl fmt::Debug for SuspendedDebuggee {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SuspendedDebuggee([REDACTED HANDLES AND IDENTITY])")
        }
    }

    impl Drop for SuspendedDebuggee {
        fn drop(&mut self) {
            let _ = self.abort();
        }
    }

    /// Type-state proof that the debugger relationship has ended while the
    /// primary thread retains exactly one explicit suspend count.
    ///
    /// Construction is possible only through `SuspendedDebuggee::into_detached`
    /// after `ContinueDebugEvent`, `DebugActiveProcessStop`, and the observable
    /// post-detach suspend-count probe all succeeded. It exposes no raw handle
    /// and no creator-thread-only debug operation.
    pub(super) struct DetachedSuspendedDebuggee(SuspendedDebuggee);

    // SAFETY: Win32 process and thread handles are process-wide. The only
    // constructor above rejects every pending/debug-attached phase and requires
    // the post-detach suspension proof. After construction, the wrapper exposes
    // only process-wide metadata, termination/wait cleanup, and Drop; it cannot
    // call WaitForDebugEventEx, ContinueDebugEvent, or DebugActiveProcessStop.
    // SuspendedDebuggee itself and OwnedWinHandle intentionally remain !Send.
    unsafe impl Send for DetachedSuspendedDebuggee {}

    impl DetachedSuspendedDebuggee {
        pub(super) const fn process_id(&self) -> u32 {
            self.0.process_id()
        }

        pub(super) fn is_detached_and_suspended(&self) -> bool {
            self.0.is_detached_and_suspended()
        }

        pub(super) fn abort(&mut self) -> Result<(), KeyAgentActivationError> {
            self.0.abort()
        }

        #[cfg(test)]
        pub(super) fn duplicate_process_observation(
            &self,
        ) -> Result<TestProcessObservation, KeyAgentActivationError> {
            self.0.duplicate_process_observation()
        }

        #[cfg(test)]
        pub(super) fn is_member_of_root_job_for_test(
            &self,
            root_job: &KeyAgentRootJob,
        ) -> Result<bool, KeyAgentActivationError> {
            root_job
                .contains_process(self.0.process_handle())
                .map_err(|_| KeyAgentActivationError::RootJobPolicy)
        }
    }

    impl fmt::Debug for DetachedSuspendedDebuggee {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("DetachedSuspendedDebuggee([REDACTED HANDLES AND IDENTITY])")
        }
    }

    #[cfg(test)]
    pub(super) struct TestProcessObservation(OwnedHandle);

    #[cfg(test)]
    impl TestProcessObservation {
        fn duplicate(source: HANDLE) -> Result<Self, KeyAgentActivationError> {
            let mut duplicate = HANDLE::default();
            // SAFETY: source is the exact live process handle. The duplicate is
            // created in this process, is non-inheritable, and ownership is
            // transferred exactly once into `OwnedHandle` below.
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    source,
                    GetCurrentProcess(),
                    &raw mut duplicate,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            }
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
            if invalid(duplicate) {
                return Err(KeyAgentActivationError::Cleanup);
            }
            // SAFETY: DuplicateHandle returned a new owned process handle and
            // no other wrapper owns `duplicate`.
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(duplicate.0) }))
        }

        pub(super) fn rejected_exit_code(&self) -> Result<u32, KeyAgentActivationError> {
            let handle = HANDLE(self.0.as_raw_handle());
            // SAFETY: the observation owns this exact process handle and the
            // wait is bounded by the same cleanup policy as production.
            if unsafe { WaitForSingleObject(handle, CLEANUP_TIMEOUT_MILLISECONDS) } != WAIT_OBJECT_0
            {
                return Err(KeyAgentActivationError::Cleanup);
            }
            let mut exit_code = 0;
            // SAFETY: the exact observed process is signaled and the output is
            // valid writable storage.
            unsafe { GetExitCodeProcess(handle, &raw mut exit_code) }
                .map_err(|_| KeyAgentActivationError::Cleanup)?;
            Ok(exit_code)
        }
    }

    #[cfg(test)]
    impl fmt::Debug for TestProcessObservation {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("TestProcessObservation([REDACTED PROCESS HANDLE])")
        }
    }

    pub(super) struct AuthenticatedFirstEvent {
        pub(super) creation_time: u64,
    }

    pub(super) fn exact_file_identity(
        handle: HANDLE,
    ) -> Result<ExactFileObjectIdentity, KeyAgentActivationError> {
        if invalid(handle) {
            return Err(KeyAgentActivationError::ArtifactIdentity);
        }
        let mut information = FILE_ID_INFO::default();
        // SAFETY: handle is a live file handle and information points to exact
        // writable FILE_ID_INFO storage with its documented byte size.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                ptr::from_mut(&mut information).cast::<c_void>(),
                u32::try_from(size_of_val(&information))
                    .map_err(|_| KeyAgentActivationError::ArtifactIdentity)?,
            )
        }
        .map_err(|_| KeyAgentActivationError::ArtifactIdentity)?;
        ExactFileObjectIdentity::from_file_id_info(
            information.VolumeSerialNumber,
            information.FileId.Identifier,
        )
    }

    fn process_creation_time(process: HANDLE) -> Result<u64, KeyAgentActivationError> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: process is the exact live process handle and all outputs are
        // initialized FILETIME storage.
        unsafe {
            GetProcessTimes(
                process,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        }
        .map_err(|_| KeyAgentActivationError::CreationTime)?;
        let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        (value != 0)
            .then_some(value)
            .ok_or(KeyAgentActivationError::CreationTime)
    }

    fn invalid(handle: HANDLE) -> bool {
        handle.is_invalid() || handle == INVALID_HANDLE_VALUE
    }

    fn key_agent_creation_flags() -> windows::Win32::System::Threading::PROCESS_CREATION_FLAGS {
        CREATE_SUSPENDED
            | DEBUG_PROCESS
            | DEBUG_ONLY_THIS_PROCESS
            | CREATE_NO_WINDOW
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT
    }

    #[cfg(test)]
    pub(super) fn key_agent_creation_flag_bits_for_test() -> u32 {
        key_agent_creation_flags().0
    }

    #[cfg(test)]
    pub(super) const fn rejected_process_exit_code_for_test() -> u32 {
        REJECTED_PROCESS_EXIT_CODE
    }

    #[cfg(test)]
    pub(super) fn creation_attribute_handle_count_for_test(
        inheritance: &PreparedKeyAgentInheritance<'_, '_>,
        root_job_attribute: &KeyAgentRootJobAttribute<'_>,
    ) -> Result<usize, KeyAgentActivationError> {
        let lpac =
            PreparedKeyAgentLpac::prepare().map_err(|_| KeyAgentActivationError::LpacPolicy)?;
        let attributes = KeyAgentCreationAttributes::new(inheritance, root_job_attribute, &lpac)?;
        Ok(attributes.explicit_handle_count())
    }

    fn windows_handle(handle: BorrowedHandle<'_>) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    struct OwnedWinHandle(HANDLE);

    impl OwnedWinHandle {
        fn new(handle: HANDLE) -> Option<Self> {
            (!invalid(handle)).then_some(Self(handle))
        }

        const fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedWinHandle {
        fn drop(&mut self) {
            if !invalid(self.0) {
                // SAFETY: this wrapper owns the handle exactly once.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
                self.0 = HANDLE::default();
            }
        }
    }

    impl fmt::Debug for OwnedWinHandle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("OwnedWinHandle([REDACTED])")
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::ffi::OsStr;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle as _;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS,
        DEBUG_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
    };

    use super::{
        ExactFileObjectIdentity, FreshKeyAgentDebugThread, HeldKeyAgentActivation,
        KeyAgentActivationError, LaunchPhase, LaunchTransition, PreflightKeyAgentArtifact,
        activate_preflighted_key_agent_on_fresh_worker,
        activate_preflighted_key_agent_on_fresh_worker_with_identity, fail_after_cleanup,
        preflight_key_agent_activation, run_on_fresh_key_agent_debug_thread, sys,
    };
    use crate::{
        attestation::ReleaseAttestation, helper::VerifiedHelper,
        inheritable_handle_launch::acquire_inheritable_handle_launch,
        key_agent_root_job::KeyAgentRootJob, pipe::PrivateKeyAgentPipes,
    };

    fn require_send<T: Send>() {}

    fn test_root_job() -> Result<KeyAgentRootJob, KeyAgentActivationError> {
        KeyAgentRootJob::create_for_kernel_test()
            .map_err(|_| KeyAgentActivationError::RootJobPolicy)
    }

    fn activation_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn activate_for_test<R, F>(
        attestation: ReleaseAttestation,
        artifact: VerifiedHelper,
        inspect: F,
    ) -> Result<R, KeyAgentActivationError>
    where
        R: Send + 'static,
        F: FnOnce(HeldKeyAgentActivation, &KeyAgentRootJob) -> Result<R, KeyAgentActivationError>
            + Send
            + 'static,
    {
        let preflighted = preflight_key_agent_activation(attestation, artifact)?;
        run_on_fresh_key_agent_debug_thread(move |fresh_thread| {
            let root_job = test_root_job()?;
            let pipes = PrivateKeyAgentPipes::create()
                .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
            let root_job_attribute = root_job
                .creation_attribute()
                .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
            let activation = activate_preflighted_key_agent_on_fresh_worker(
                fresh_thread,
                preflighted,
                &pipes,
                &root_job,
                &root_job_attribute,
                activation_deadline(),
            )?;
            inspect(activation, &root_job)
        })
    }

    trait AmbiguousIfSend<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

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

    #[derive(Debug)]
    struct SentinelPath(PathBuf);

    impl SentinelPath {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "your-wallet-key-agent-{}-{unique}.sentinel",
                std::process::id()
            ));
            if path.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "headless sentinel path collision",
                )
                .into());
            }
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for SentinelPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn attestation_for(artifact: &VerifiedHelper) -> ReleaseAttestation {
        ReleaseAttestation::with_helper_manifests_for_test([
            artifact.manifest_digest(),
            [25; 32],
            [26; 32],
        ])
    }

    #[test]
    fn launch_state_machine_rejects_skip_replay_and_post_abort_transitions() {
        assert_eq!(
            LaunchPhase::AwaitingCreateEvent.transition(LaunchTransition::ReceiveCreateEvent),
            Ok(LaunchPhase::CreateEventHeld)
        );
        assert_eq!(
            LaunchPhase::CreateEventHeld.transition(LaunchTransition::ContinueCreateEvent),
            Ok(LaunchPhase::EventContinued)
        );
        assert_eq!(
            LaunchPhase::EventContinued.transition(LaunchTransition::DetachDebugger),
            Ok(LaunchPhase::DetachedSuspended)
        );
        assert_eq!(
            LaunchPhase::AwaitingCreateEvent.transition(LaunchTransition::DetachDebugger),
            Err(KeyAgentActivationError::DebugDetach)
        );
        assert_eq!(
            LaunchPhase::DetachedSuspended.transition(LaunchTransition::Abort),
            Ok(LaunchPhase::Aborted)
        );
        assert_eq!(
            LaunchPhase::Aborted.transition(LaunchTransition::ReceiveCreateEvent),
            Err(KeyAgentActivationError::DebugDetach)
        );
    }

    #[test]
    fn exact_file_identity_comparator_uses_volume_and_all_128_bits() {
        let base = ExactFileObjectIdentity {
            volume_serial_number: 7,
            file_id: [8; 16],
        };
        let mut different_id = base;
        different_id.file_id[15] ^= 1;
        assert_eq!(base, base);
        assert_ne!(base, different_id);
        assert_ne!(
            base,
            ExactFileObjectIdentity {
                volume_serial_number: 9,
                ..base
            }
        );
    }

    #[test]
    fn invalid_file_identity_sentinels_fail_closed() {
        assert_eq!(
            ExactFileObjectIdentity::from_file_id_info(0, [1; 16]),
            Err(KeyAgentActivationError::ArtifactIdentity)
        );
        assert_eq!(
            ExactFileObjectIdentity::from_file_id_info(1, [0; 16]),
            Err(KeyAgentActivationError::ArtifactIdentity)
        );
        assert_eq!(
            ExactFileObjectIdentity::from_file_id_info(1, [u8::MAX; 16]),
            Err(KeyAgentActivationError::ArtifactIdentity)
        );
        assert!(ExactFileObjectIdentity::from_file_id_info(1, [2; 16]).is_ok());
    }

    #[test]
    fn live_file_identity_is_valid_and_stable_across_held_handles()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = VerifiedHelper::for_key_agent_activation_test()?;
        let second = std::fs::File::open(first.path())?;
        let first_identity = sys::exact_file_identity(first.raw_handle())?;
        let second_identity = sys::exact_file_identity(HANDLE(second.as_raw_handle()))?;
        assert_ne!(first_identity.volume_serial_number, 0);
        assert_ne!(first_identity.file_id, [0; 16]);
        assert_ne!(first_identity.file_id, [u8::MAX; 16]);
        assert_eq!(first_identity, second_identity);
        Ok(())
    }

    #[test]
    fn authority_and_detached_type_states_have_exact_transfer_traits() {
        require_send::<PreflightKeyAgentArtifact>();
        require_send::<sys::DetachedSuspendedDebuggee>();
        require_send::<HeldKeyAgentActivation>();

        let _ = <FreshKeyAgentDebugThread as AmbiguousIfSend<_>>::marker;
        let _ = <FreshKeyAgentDebugThread as AmbiguousIfSync<_>>::marker;
        let _ = <FreshKeyAgentDebugThread as AmbiguousIfClone<_>>::marker;
        let _ = <FreshKeyAgentDebugThread as AmbiguousIfCopy<_>>::marker;
        let _ = <PreflightKeyAgentArtifact as AmbiguousIfClone<_>>::marker;
        let _ = <PreflightKeyAgentArtifact as AmbiguousIfCopy<_>>::marker;
        let _ = <sys::SuspendedDebuggee as AmbiguousIfSend<_>>::marker;
        let _ = <sys::DetachedSuspendedDebuggee as AmbiguousIfSync<_>>::marker;
        let _ = <sys::DetachedSuspendedDebuggee as AmbiguousIfClone<_>>::marker;
        let _ = <sys::DetachedSuspendedDebuggee as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn process_creation_flags_are_exact_and_do_not_debug_descendants() {
        let expected = (CREATE_SUSPENDED
            | DEBUG_PROCESS
            | DEBUG_ONLY_THIS_PROCESS
            | CREATE_NO_WINDOW
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT)
            .0;
        assert_eq!(sys::key_agent_creation_flag_bits_for_test(), expected);
    }

    #[test]
    fn startup_attribute_list_has_exactly_three_explicit_stdio_handles()
    -> Result<(), Box<dyn std::error::Error>> {
        let root_job = test_root_job()?;
        let pipes = PrivateKeyAgentPipes::create()?;
        let flight = acquire_inheritable_handle_launch(activation_deadline())
            .map_err(|_| KeyAgentActivationError::ProcessCreation)?;
        let inheritance = pipes.prepare_child_inheritance(&flight)?;
        let root_job_attribute = root_job.creation_attribute()?;
        assert_eq!(
            sys::creation_attribute_handle_count_for_test(&inheritance, &root_job_attribute)?,
            3
        );
        Ok(())
    }

    #[test]
    fn wrong_role_is_rejected_before_release_or_process_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let wrong = VerifiedHelper::for_secret_input_channel_test()?;
        let attestation = attestation_for(&wrong);
        assert!(matches!(
            preflight_key_agent_activation(attestation, wrong),
            Err(KeyAgentActivationError::WrongRole)
        ));
        Ok(())
    }

    #[test]
    fn development_release_gate_rejects_exact_role_before_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        assert!(matches!(
            preflight_key_agent_activation(ReleaseAttestation::default(), artifact),
            Err(KeyAgentActivationError::ReleaseNotAttested)
        ));
        Ok(())
    }

    #[test]
    fn mapped_image_mismatch_is_rejected_and_cleaned_up_before_detach()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let mut wrong_identity = sys::exact_file_identity(artifact.raw_handle())?;
        wrong_identity.file_id[0] ^= 1;
        run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |_fresh_thread| {
                let root_job = test_root_job()?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let mut process = sys::SuspendedDebuggee::create(
                    &artifact,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    activation_deadline(),
                )?;
                assert!(matches!(
                    process.authenticate_first_event(wrong_identity, 5_000),
                    Err(KeyAgentActivationError::MappedImageMismatch)
                ));
                process.abort()?;
                assert!(process.is_aborted());
                assert_eq!(
                    process.cleanup_exit_code(),
                    Some(sys::rejected_process_exit_code_for_test())
                );
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    fn timeout_cleanup_terminates_without_dispatching_the_first_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |_fresh_thread| {
                let root_job = test_root_job()?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let mut process = sys::SuspendedDebuggee::create(
                    &artifact,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    activation_deadline(),
                )?;
                let timeout_result: Result<(), KeyAgentActivationError> =
                    fail_after_cleanup(&mut process, KeyAgentActivationError::DebugEventTimeout);
                assert_eq!(
                    timeout_result,
                    Err(KeyAgentActivationError::DebugEventTimeout)
                );
                assert!(process.is_aborted());
                assert_eq!(
                    process.cleanup_exit_code(),
                    Some(sys::rejected_process_exit_code_for_test())
                );
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    fn successful_kernel_proof_detaches_with_one_verified_suspend_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let attestation = attestation_for(&artifact);
        activate_for_test(attestation, artifact, |activation, root_job| {
            assert!(activation.process_id() != 0);
            assert!(activation.creation_time() != 0);
            assert!(activation.is_detached_and_suspended());
            assert!(activation.is_member_of_root_job_for_test(root_job)?);
            assert_eq!(
                root_job
                    .active_process_count()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?,
                1
            );
            let rendered = format!("{activation:?}");
            assert!(rendered.contains("HeldKeyAgentActivation"));
            assert!(rendered.contains("[FILE_ID_INFO]"));
            assert!(!rendered.contains(&activation.process_id().to_string()));
            assert!(!rendered.contains(&activation.creation_time().to_string()));
            let observation = activation.process.duplicate_process_observation()?;
            drop(activation);
            assert_eq!(
                observation.rejected_exit_code()?,
                sys::rejected_process_exit_code_for_test()
            );
            assert_eq!(
                root_job
                    .active_process_count()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?,
                0
            );
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn caller_debuggee_does_not_contaminate_dedicated_activation_worker()
    -> Result<(), Box<dyn std::error::Error>> {
        let caller_artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let caller_identity = sys::exact_file_identity(caller_artifact.raw_handle())?;
        let caller_root_job = test_root_job()?;
        let caller_pipes = PrivateKeyAgentPipes::create()?;
        let caller_root_job_attribute = caller_root_job.creation_attribute()?;
        let mut caller_debuggee = sys::SuspendedDebuggee::create(
            &caller_artifact,
            &caller_pipes,
            &caller_root_job,
            &caller_root_job_attribute,
            activation_deadline(),
        )?;

        let activation_artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let activation_attestation = attestation_for(&activation_artifact);
        activate_for_test(
            activation_attestation,
            activation_artifact,
            |activation, _root_job| {
                assert!(activation.is_detached_and_suspended());
                drop(activation);
                Ok(())
            },
        )?;

        let caller_event = caller_debuggee.authenticate_first_event(caller_identity, 5_000)?;
        assert_ne!(caller_event.creation_time, 0);
        caller_debuggee.abort()?;
        assert_eq!(
            caller_debuggee.cleanup_exit_code(),
            Some(sys::rejected_process_exit_code_for_test())
        );
        Ok(())
    }

    #[test]
    fn concurrent_activations_use_isolated_workers() -> Result<(), Box<dyn std::error::Error>> {
        let first_artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let first_attestation = attestation_for(&first_artifact);
        let second_artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let second_attestation = attestation_for(&second_artifact);
        let barrier = Arc::new(Barrier::new(3));

        let first_barrier = Arc::clone(&barrier);
        let first_worker = std::thread::spawn(move || {
            first_barrier.wait();
            activate_for_test(
                first_attestation,
                first_artifact,
                |activation, _root_job| {
                    let process_id = activation.process_id();
                    assert!(activation.is_detached_and_suspended());
                    drop(activation);
                    Ok(process_id)
                },
            )
        });
        let second_barrier = Arc::clone(&barrier);
        let second_worker = std::thread::spawn(move || {
            second_barrier.wait();
            activate_for_test(
                second_attestation,
                second_artifact,
                |activation, _root_job| {
                    let process_id = activation.process_id();
                    assert!(activation.is_detached_and_suspended());
                    drop(activation);
                    Ok(process_id)
                },
            )
        });
        barrier.wait();

        let first = first_worker
            .join()
            .map_err(|_| std::io::Error::other("first activation caller panicked"))??;
        let second = second_worker
            .join()
            .map_err(|_| std::io::Error::other("second activation caller panicked"))??;
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn mismatched_job_attribute_is_rejected_and_process_is_cleaned_up()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let preflighted = preflight_key_agent_activation(attestation_for(&artifact), artifact)?;
        run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |fresh_thread| {
                let assigned_job = test_root_job()?;
                let checked_job = test_root_job()?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let mismatched_attribute = assigned_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                assert!(matches!(
                    activate_preflighted_key_agent_on_fresh_worker(
                        fresh_thread,
                        preflighted,
                        &pipes,
                        &checked_job,
                        &mismatched_attribute,
                        activation_deadline(),
                    ),
                    Err(KeyAgentActivationError::RootJobPolicy)
                ));
                assert_eq!(
                    assigned_job
                        .active_process_count()
                        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?,
                    0
                );
                assert_eq!(
                    checked_job
                        .active_process_count()
                        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?,
                    0
                );
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    fn worker_error_cleans_up_exact_process() -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let mut wrong_identity = sys::exact_file_identity(artifact.raw_handle())?;
        wrong_identity.file_id[3] ^= 1;
        let preflighted = preflight_key_agent_activation(attestation_for(&artifact), artifact)?;
        let result = run_on_fresh_key_agent_debug_thread(move |fresh_thread| {
            let root_job = test_root_job()?;
            let pipes = PrivateKeyAgentPipes::create()
                .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
            let root_job_attribute = root_job
                .creation_attribute()
                .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
            let PreflightKeyAgentArtifact { artifact } = preflighted;
            activate_preflighted_key_agent_on_fresh_worker_with_identity(
                fresh_thread,
                artifact,
                wrong_identity,
                &pipes,
                &root_job,
                &root_job_attribute,
                activation_deadline(),
            )
        });
        assert!(matches!(
            result,
            Err(KeyAgentActivationError::MappedImageMismatch)
        ));
        Ok(())
    }

    #[test]
    fn worker_panic_after_create_cleans_up_exact_process() -> Result<(), Box<dyn std::error::Error>>
    {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let (observation_sender, observation_receiver) = mpsc::sync_channel(1);
        let result = run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |_fresh_thread| {
                let root_job = test_root_job()?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let process = sys::SuspendedDebuggee::create(
                    &artifact,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    activation_deadline(),
                )?;
                let observation = process.duplicate_process_observation()?;
                observation_sender
                    .send(observation)
                    .map_err(|_| KeyAgentActivationError::ActivationWorker)?;
                std::panic::resume_unwind(Box::new("intentional activation worker test unwind"));
            },
        );
        assert_eq!(result, Err(KeyAgentActivationError::ActivationWorker));
        let observation = observation_receiver.recv()?;
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        Ok(())
    }

    #[test]
    fn rejected_image_never_reaches_headless_user_mode_sentinel()
    -> Result<(), Box<dyn std::error::Error>> {
        let sentinel = SentinelPath::new()?;
        let child_test = "key_agent_activation::tests::headless_child_user_mode_sentinel";
        let command_line = format!(
            "\"{}\" --exact {child_test} --ignored --test-threads=1",
            sentinel.path().display()
        );
        let mut command_line: Vec<u16> = OsStr::new(&command_line)
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();

        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let mut wrong_identity = sys::exact_file_identity(artifact.raw_handle())?;
        wrong_identity.file_id[7] ^= 1;
        run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |_fresh_thread| {
                let root_job = test_root_job()?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let mut process = sys::SuspendedDebuggee::create_with_test_command_line(
                    &artifact,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    activation_deadline(),
                    &mut command_line,
                )?;
                assert!(matches!(
                    process.authenticate_first_event(wrong_identity, 5_000),
                    Err(KeyAgentActivationError::MappedImageMismatch)
                ));
                process.abort()?;
                assert_eq!(
                    process.cleanup_exit_code(),
                    Some(sys::rejected_process_exit_code_for_test())
                );
                Ok(())
            },
        )?;
        assert!(!sentinel.path().exists());
        Ok(())
    }

    #[test]
    #[ignore = "headless child sentinel; invoked only by the parent kernel test"]
    fn headless_child_user_mode_sentinel() -> Result<(), Box<dyn std::error::Error>> {
        let marker = std::env::args_os().next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing sentinel argument",
            )
        })?;
        let marker = PathBuf::from(marker);
        let temp = std::env::temp_dir();
        let valid_name = marker
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with("your-wallet-key-agent-") && name.ends_with(".sentinel")
            });
        if marker.parent() != Some(temp.as_path()) || !valid_name {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid sentinel location",
            )
            .into());
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker)?;
        file.write_all(b"user-mode-reached")?;
        file.sync_all()?;
        Ok(())
    }
}
