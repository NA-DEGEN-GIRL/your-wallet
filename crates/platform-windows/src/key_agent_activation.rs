//! Fail-closed proofs for one exact Key Agent activation.
//!
//! This module deliberately exposes no runtime arming API outside this crate.
//! The supervisor must verify and pin the Key Agent artifact before creation,
//! then compare that held file with the image-file handle supplied by the first
//! Windows process-creation debug event. The dormant value owns a suspended
//! process and a retained process-token continuity proof, and exposes only one
//! consuming transition into the fixed storage-startup probe; both dormant and
//! running proofs terminate on drop.

#![allow(dead_code)]

use core::fmt;
use core::mem::size_of;
use std::io::Read;
use std::marker::PhantomData;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use thiserror::Error;
use windows::Win32::Foundation::HANDLE;

use crate::{
    attestation::{AttestedArtifactDigest, ReleaseAttestation},
    helper::VerifiedHelper,
    key_agent_child_bootstrap::KEY_AGENT_DEFAULT_DACL_GATE_MARKER,
    key_agent_lpac::PreparedKeyAgentProvisioning,
    key_agent_root_job::{KeyAgentDebugThreadWitness, KeyAgentRootJob, KeyAgentRootJobAttribute},
    launch::{ApprovalLogicalParentInjectionSeal, InjectedApprovalLogicalParent},
    pipe::PrivateKeyAgentPipes,
};

const FIRST_DEBUG_EVENT_TIMEOUT_MILLISECONDS: u32 = 5_000;
const MAX_KEY_AGENT_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const KEY_AGENT_DEFAULT_DACL_GATE_BYTES: usize = 11;

struct DetachedDebugEventHandleSet {
    process: Option<usize>,
    primary_thread: Option<usize>,
    rejected_thread: Option<usize>,
    process_id: u32,
    thread_id: u32,
    rejected_thread_id: Option<u32>,
}

impl DetachedDebugEventHandleSet {
    const fn is_empty(&self) -> bool {
        self.process.is_none()
            && self.primary_thread.is_none()
            && self.rejected_thread.is_none()
            && self.rejected_thread_id.is_none()
    }

    const fn is_registerable(&self) -> bool {
        !self.is_empty()
            && self.rejected_thread.is_none()
            && self.rejected_thread_id.is_none()
            && !matches!(
                (self.process, self.primary_thread),
                (Some(process), Some(primary_thread)) if process == primary_thread
            )
            && self.process_id != 0
            && self.thread_id != 0
    }

    const fn is_complete(&self) -> bool {
        matches!(
            (self.process, self.primary_thread),
            (Some(process), Some(primary_thread)) if process != primary_thread
        ) && self.process_id != 0
            && self.thread_id != 0
            && self.rejected_thread.is_none()
            && self.rejected_thread_id.is_none()
    }
}

struct KeyAgentDebugEventCleanup {
    witness: Arc<KeyAgentDebugThreadWitness>,
    handles: Mutex<Option<DetachedDebugEventHandleSet>>,
}

impl KeyAgentDebugEventCleanup {
    fn new_shared(witness: Arc<KeyAgentDebugThreadWitness>) -> Arc<Self> {
        Arc::new(Self {
            witness,
            handles: Mutex::new(None),
        })
    }

    fn matches_witness(&self, witness: &KeyAgentDebugThreadWitness) -> bool {
        core::ptr::eq(Arc::as_ptr(&self.witness), witness)
    }

    fn register_while_attached(
        &self,
        handles: DetachedDebugEventHandleSet,
    ) -> Result<(), KeyAgentActivationError> {
        if self.witness.is_joined() {
            return Err(KeyAgentActivationError::DebuggerJoinProof);
        }
        let mut slot = self
            .handles
            .lock()
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
        if slot.is_some() || !handles.is_registerable() {
            return Err(KeyAgentActivationError::DebugDetach);
        }
        *slot = Some(handles);
        Ok(())
    }

    fn verify_registered_while_attached(
        &self,
        process_id: u32,
        thread_id: u32,
    ) -> Result<(), KeyAgentActivationError> {
        if self.witness.is_joined() {
            return Err(KeyAgentActivationError::DebuggerJoinProof);
        }
        let slot = self
            .handles
            .lock()
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
        let handles = slot.as_ref().ok_or(KeyAgentActivationError::DebugDetach)?;
        if !handles.is_complete()
            || handles.process_id != process_id
            || handles.thread_id != thread_id
        {
            return Err(KeyAgentActivationError::DebugDetach);
        }
        Ok(())
    }

    fn register_rejected_thread_while_attached(
        &self,
        process_id: u32,
        primary_thread_id: u32,
        rejected_thread_id: u32,
        rejected_thread: usize,
    ) -> Result<(), KeyAgentActivationError> {
        if self.witness.is_joined()
            || process_id == 0
            || primary_thread_id == 0
            || rejected_thread_id == 0
            || rejected_thread_id == primary_thread_id
            || rejected_thread == 0
        {
            return Err(KeyAgentActivationError::DebugDetach);
        }
        let mut slot = self
            .handles
            .lock()
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
        let handles = slot
            .as_mut()
            .filter(|handles| {
                handles.is_complete()
                    && handles.process_id == process_id
                    && handles.thread_id == primary_thread_id
                    && handles.process != Some(rejected_thread)
                    && handles.primary_thread != Some(rejected_thread)
            })
            .ok_or(KeyAgentActivationError::DebugDetach)?;
        handles.rejected_thread = Some(rejected_thread);
        handles.rejected_thread_id = Some(rejected_thread_id);
        Ok(())
    }

    #[cfg(test)]
    fn observation_while_attached_for_test(
        &self,
    ) -> Result<sys::TestDebugEventHandleObservation, KeyAgentActivationError> {
        if self.witness.is_joined() {
            return Err(KeyAgentActivationError::DebuggerJoinProof);
        }
        let slot = self
            .handles
            .lock()
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
        let handles = slot
            .as_ref()
            .filter(|handles| handles.is_complete())
            .ok_or(KeyAgentActivationError::DebugDetach)?;
        Ok(sys::TestDebugEventHandleObservation::new(
            handles
                .process
                .ok_or(KeyAgentActivationError::DebugDetach)?,
            handles
                .primary_thread
                .ok_or(KeyAgentActivationError::DebugDetach)?,
        ))
    }

    #[cfg(test)]
    fn rejected_thread_observation_while_attached_for_test(
        &self,
    ) -> Result<sys::TestRejectedThreadEventHandleObservation, KeyAgentActivationError> {
        if self.witness.is_joined() {
            return Err(KeyAgentActivationError::DebuggerJoinProof);
        }
        let slot = self
            .handles
            .lock()
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
        let handles = slot.as_ref().ok_or(KeyAgentActivationError::DebugDetach)?;
        let rejected_thread = handles
            .rejected_thread
            .filter(|_| handles.rejected_thread_id.is_some())
            .ok_or(KeyAgentActivationError::DebugDetach)?;
        Ok(sys::TestRejectedThreadEventHandleObservation::new(
            rejected_thread,
        ))
    }

    fn take_after_join(
        &self,
        witness: &KeyAgentDebugThreadWitness,
    ) -> Result<DetachedDebugEventHandleSet, KeyAgentActivationError> {
        if !self.matches_witness(witness) || !witness.is_joined() {
            return Err(KeyAgentActivationError::DebuggerJoinProof);
        }
        self.handles
            .lock()
            .map_err(|_| KeyAgentActivationError::Cleanup)?
            .take()
            .ok_or(KeyAgentActivationError::DebugDetach)
    }

    fn restore_after_join(
        &self,
        witness: &KeyAgentDebugThreadWitness,
        handles: DetachedDebugEventHandleSet,
    ) -> Result<(), KeyAgentActivationError> {
        if !self.matches_witness(witness) || !witness.is_joined() || handles.is_empty() {
            return Err(KeyAgentActivationError::Cleanup);
        }
        let mut slot = self
            .handles
            .lock()
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
        if slot.is_some() {
            return Err(KeyAgentActivationError::Cleanup);
        }
        *slot = Some(handles);
        Ok(())
    }

    fn close_after_join(
        &self,
        witness: &KeyAgentDebugThreadWitness,
    ) -> Result<(), KeyAgentActivationError> {
        if !self.matches_witness(witness) || !witness.is_joined() {
            return Err(KeyAgentActivationError::DebuggerJoinProof);
        }
        let mut slot = self
            .handles
            .lock()
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
        if let Some(handles) = slot.as_mut() {
            sys::close_detached_debug_event_handles_after_join(handles)
                .map_err(|_| KeyAgentActivationError::Cleanup)?;
            if handles.is_empty() {
                *slot = None;
            }
        }
        Ok(())
    }
}

impl Drop for KeyAgentDebugEventCleanup {
    fn drop(&mut self) {
        if !self.witness.is_joined() {
            return;
        }
        let Ok(slot) = self.handles.get_mut() else {
            return;
        };
        if let Some(handles) = slot.as_mut() {
            // Explicit paths report the first checked-close failure. Last-owner
            // Drop makes two bounded retries so a partial close cannot lose its
            // remaining high-authority alias without another kernel attempt.
            for _ in 0..2 {
                if handles.is_empty()
                    || sys::close_detached_debug_event_handles_after_join(handles).is_ok()
                {
                    break;
                }
            }
        }
    }
}

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
    /// The returned process or primary-thread object did not retain the exact
    /// creation-time owner, group, DACL, or non-inheritable handle policy.
    #[error("created Key Agent object security policy failed")]
    CreationSecurityPolicy,
    /// Creator-strength process or primary-thread handles could not be replaced
    /// by the exact non-inheritable resident capabilities before `Held`.
    #[error("Key Agent resident handle attenuation failed")]
    HandleAttenuation,
    /// A documented suspend-count transition was not exact.
    #[error("Key Agent suspension invariant mismatch")]
    SuspensionMismatch,
    /// The exact detached primary thread could not enter the storage probe.
    #[error("Key Agent storage-startup resume failed")]
    StartupResume,
    /// The exact post-startup process was no longer live in its resident phase.
    #[error("Key Agent resident process state is invalid")]
    ResidentState,
    /// The exact running Key Agent could not mint the least-authority Approval
    /// parent process capability.
    #[error("Approval parent process capability is unavailable")]
    ApprovalParentCapability,
    /// The first debug event did not arrive inside the fixed bound.
    #[error("Key Agent process-creation debug event timed out")]
    DebugEventTimeout,
    /// The first debug event was not the exact process-creation event.
    #[error("unexpected Key Agent debug event")]
    UnexpectedDebugEvent,
    /// Windows did not provide a valid executable-image file handle.
    #[error("Key Agent mapped-image handle is unavailable")]
    MissingMappedImage,
    /// The authenticated image did not contain exactly one reviewed
    /// cooperative default-DACL gate instruction sequence.
    #[error("Key Agent cooperative default-DACL gate policy failed")]
    CooperativeGatePolicy,
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
    /// The pending activation did not belong to the exact joined debugger run.
    #[error("Key Agent debugger join proof mismatch")]
    DebuggerJoinProof,
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

    pub(crate) fn encode_be(self) -> [u8; 24] {
        let mut encoded = [0_u8; 24];
        let (volume, file_id) = encoded.split_at_mut(8);
        volume.copy_from_slice(&self.volume_serial_number.to_be_bytes());
        file_id.copy_from_slice(&self.file_id);
        encoded
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
    LoaderRunning,
    GateEventHeld,
    GateEventContinued,
    NoKillArmedAwaitingDebuggerExit,
    DebuggerExitedPendingVerification,
    DetachedSuspended,
    DetachedRunning,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchTransition {
    ReceiveCreateEvent,
    ContinueCreateEvent,
    ReceiveCooperativeGate,
    ContinueCooperativeGate,
    ArmNoKill,
    ObserveDebuggerExit,
    VerifyDetached,
    ResumeStorageStartup,
    Abort,
}

impl LaunchPhase {
    fn transition(self, transition: LaunchTransition) -> Result<Self, KeyAgentActivationError> {
        match (self, transition) {
            (Self::AwaitingCreateEvent, LaunchTransition::ReceiveCreateEvent) => {
                Ok(Self::CreateEventHeld)
            }
            (Self::CreateEventHeld, LaunchTransition::ContinueCreateEvent) => {
                Ok(Self::LoaderRunning)
            }
            (Self::LoaderRunning, LaunchTransition::ReceiveCooperativeGate) => {
                Ok(Self::GateEventHeld)
            }
            (Self::GateEventHeld, LaunchTransition::ContinueCooperativeGate) => {
                Ok(Self::GateEventContinued)
            }
            (Self::GateEventContinued, LaunchTransition::ArmNoKill) => {
                Ok(Self::NoKillArmedAwaitingDebuggerExit)
            }
            (Self::NoKillArmedAwaitingDebuggerExit, LaunchTransition::ObserveDebuggerExit) => {
                Ok(Self::DebuggerExitedPendingVerification)
            }
            (Self::DebuggerExitedPendingVerification, LaunchTransition::VerifyDetached) => {
                Ok(Self::DetachedSuspended)
            }
            (Self::DetachedSuspended, LaunchTransition::ResumeStorageStartup) => {
                Ok(Self::DetachedRunning)
            }
            (
                Self::AwaitingCreateEvent
                | Self::CreateEventHeld
                | Self::LoaderRunning
                | Self::GateEventHeld
                | Self::GateEventContinued
                | Self::NoKillArmedAwaitingDebuggerExit
                | Self::DebuggerExitedPendingVerification
                | Self::DetachedSuspended
                | Self::DetachedRunning,
                LaunchTransition::Abort,
            ) => Ok(Self::Aborted),
            _ => Err(KeyAgentActivationError::DebugDetach),
        }
    }
}

/// Debugger-thread-bound activation after the first event was authenticated
/// and continued while one exact explicit primary-thread suspend count remains.
///
/// This state is deliberately `!Send + !Sync` through its process owner. It is
/// the last point at which the worker may perform fallible provisioning, lease,
/// root-Job, or endpoint preparation before arming no-kill-on-debugger-exit.
#[must_use = "the authenticated worker-local activation must be armed or rejected"]
pub(crate) struct AuthenticatedKeyAgentActivation {
    process: sys::SuspendedDebuggee,
    debug_thread_witness: Arc<KeyAgentDebugThreadWitness>,
    debug_event_cleanup: Arc<KeyAgentDebugEventCleanup>,
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
    artifact_identity: ExactFileObjectIdentity,
    creation_time: u64,
}

impl AuthenticatedKeyAgentActivation {
    /// Revalidates every process-local and root-Job invariant available on the
    /// debugger thread immediately before the no-kill arm.
    pub(crate) fn revalidate_before_no_kill(
        &self,
        root_job: &KeyAgentRootJob,
    ) -> Result<(), KeyAgentActivationError> {
        self.process.revalidate_before_no_kill()?;
        verify_bound_root_process(root_job, self.process.process_handle())
    }

    /// Arms documented debugger-thread-exit detachment as the final fallible
    /// worker operation and returns a move-only, non-detached pending state.
    pub(crate) fn arm_no_kill(self) -> Result<PendingKeyAgentActivation, KeyAgentActivationError> {
        let Self {
            process,
            debug_thread_witness,
            debug_event_cleanup,
            artifact,
            release_identity,
            artifact_identity,
            creation_time,
        } = self;
        if debug_thread_witness.is_joined() {
            return Err(KeyAgentActivationError::DebuggerJoinProof);
        }
        let process = process.arm_no_kill(&debug_event_cleanup)?;
        // No fallible operation follows the successful no-kill arm. These are
        // ownership-only moves into a state with no detached-facing methods.
        Ok(PendingKeyAgentActivation {
            process,
            debug_thread_witness,
            debug_event_cleanup,
            artifact,
            release_identity,
            artifact_identity,
            creation_time,
        })
    }
}

impl fmt::Debug for AuthenticatedKeyAgentActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "AuthenticatedKeyAgentActivation([WORKER-LOCAL CONTINUED DEBUGGEE; REDACTED])",
        )
    }
}

/// Opaque transfer state after no-kill was armed but before debugger-thread
/// exit and join have been independently established.
///
/// It exposes no PID, process state, resume, detached, or token operation. The
/// sole transition requires an unforgeable non-Send join proof minted only by
/// [`run_on_fresh_key_agent_debug_thread`] after the debugger OS thread exits.
#[must_use = "pending activation requires post-join debugger-exit verification"]
pub(crate) struct PendingKeyAgentActivation {
    process: sys::PendingDebuggerExitSuspendedDebuggee,
    debug_thread_witness: Arc<KeyAgentDebugThreadWitness>,
    debug_event_cleanup: Arc<KeyAgentDebugEventCleanup>,
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
    artifact_identity: ExactFileObjectIdentity,
    creation_time: u64,
}

impl PendingKeyAgentActivation {
    /// Switches Drop to authoritative retained-handle cleanup after the exact
    /// debugger OS thread was joined, without exposing or minting detachment.
    pub(crate) fn observe_debugger_exit_for_cleanup(
        &mut self,
        root_job: &KeyAgentRootJob,
        joined: &JoinedKeyAgentDebugThreadProof,
    ) -> Result<(), KeyAgentActivationError> {
        if !Arc::ptr_eq(&self.debug_thread_witness, &joined.witness)
            || !self.debug_thread_witness.is_joined()
            || !root_job.matches_debugger_cleanup_gate(&self.debug_thread_witness)
        {
            return Err(KeyAgentActivationError::DebuggerJoinProof);
        }
        self.process.observe_debugger_exit_for_cleanup()
    }
}

impl fmt::Debug for PendingKeyAgentActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "PendingKeyAgentActivation([NO-KILL ARMED; DEBUGGER EXIT UNVERIFIED; REDACTED])",
        )
    }
}

/// Opaque ownership of one exact Key Agent that has not executed user code.
///
/// This type is non-cloneable and crate-private. It retains the original
/// `FILE_SHARE_READ`-only [`VerifiedHelper`] handle, opaque whole-release
/// identity, an exact terminate/query/synchronize process handle, one
/// resume-only primary-thread handle, the retained process-token continuity
/// proof, the 128-bit file-object proof, and process creation time.
/// The only consuming transition resumes it for the fixed storage-startup
/// probe; no generic resume or raw thread operation is exposed.
pub(crate) struct HeldKeyAgentActivation {
    process: sys::DetachedSuspendedDebuggee,
    // Keep the process field first so its Drop cleanup runs before the pinned
    // artifact is closed, even if the explicit Held drop cleanup failed.
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
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

    /// Consumes the dormant proof and releases exactly its one verified primary
    /// suspend count for the fixed storage-startup protocol.
    pub(crate) fn resume_for_storage_startup(
        self,
    ) -> Result<RunningKeyAgentActivation, KeyAgentActivationError> {
        let Self {
            process,
            artifact,
            release_identity,
            artifact_identity,
            creation_time,
        } = self;
        let process = process.resume_for_storage_startup()?;
        Ok(RunningKeyAgentActivation {
            process,
            artifact,
            release_identity,
            artifact_identity,
            creation_time,
        })
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

/// Opaque ownership of the exact verified Key Agent after the one permitted
/// storage-startup resume transition.
///
/// It retains the pinned artifact, opaque whole-release identity, and
/// process-token continuity proof, but proves only that the primary thread was
/// released from the exact detached suspend count. The supervisor must still
/// authenticate the startup response before wrapping it in a storage-proven
/// aggregate.
pub(crate) struct RunningKeyAgentActivation {
    process: sys::DetachedRunningDebuggee,
    // Keep process cleanup ahead of the verified artifact pin.
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
    artifact_identity: ExactFileObjectIdentity,
    creation_time: u64,
}

impl RunningKeyAgentActivation {
    pub(crate) const fn process_id(&self) -> u32 {
        self.process.process_id()
    }

    pub(crate) const fn creation_time(&self) -> u64 {
        self.creation_time
    }

    pub(crate) const fn artifact_identity(&self) -> ExactFileObjectIdentity {
        self.artifact_identity
    }

    pub(crate) fn is_detached_and_running(&self) -> bool {
        self.process.is_detached_and_running()
    }

    /// Revalidates that the exact detached process is still live and still owns
    /// the verified token after both startup streams reached EOF.
    pub(crate) fn revalidate_resident_process(&self) -> Result<(), KeyAgentActivationError> {
        self.process.revalidate_resident_process()
    }

    /// Revalidates membership of this exact retained process in the supplied
    /// root Job rather than trusting only an aggregate active-process count.
    pub(crate) fn is_member_of_root_job(
        &self,
        root_job: &KeyAgentRootJob,
    ) -> Result<bool, KeyAgentActivationError> {
        self.process.is_member_of_root_job(root_job)
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
    pub(crate) fn retained_process_authority_for_test(
        &self,
    ) -> Result<(u32, u32), KeyAgentActivationError> {
        self.process.retained_process_authority_for_test()
    }

    #[cfg(test)]
    pub(crate) fn is_member_of_root_job_for_test(
        &self,
        root_job: &KeyAgentRootJob,
    ) -> Result<bool, KeyAgentActivationError> {
        self.is_member_of_root_job(root_job)
    }
}

impl fmt::Debug for RunningKeyAgentActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningKeyAgentActivation")
            .field("artifact", &"[VERIFIED KEY AGENT ARTIFACT]")
            .field("process", &"[NARROW RUNNING PROCESS; NO THREAD HANDLE]")
            .field("lpac", &"[VERIFIED ZERO-CAPABILITY KEY AGENT LPAC]")
            .field("artifact_identity", &"[FILE_ID_INFO]")
            .field("creation_time", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// One exact running Key Agent process object held only with the rights needed
/// by a future Approval parent binding.
///
/// The non-cloneable capability is a fresh, non-inheritable duplicate with
/// exactly `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`. It exposes no
/// PID, path, raw handle, duplication, termination, VM, or launch operation.
#[must_use = "dropping the Approval parent process capability closes its exact narrow handle"]
pub(crate) struct PreparedApprovalParentProcess(sys::PreparedApprovalParentProcess);

impl PreparedApprovalParentProcess {
    /// Revalidates exact PID, zero handle flags, liveness, process-token query,
    /// and image-path query through only the retained least-authority handle.
    pub(crate) fn revalidate(&self) -> Result<(), KeyAgentActivationError> {
        self.0.revalidate()
    }

    /// Copies this exact least-authority process handle into one still-
    /// suspended Approval LPAC under the launch module's unforgeable seal.
    ///
    /// The returned opaque proof contains only child-local coordinates and
    /// exposes no source process handle to the caller.
    pub(crate) fn duplicate_into_suspended_approval(
        &self,
        suspended_child: BorrowedHandle<'_>,
        seal: &ApprovalLogicalParentInjectionSeal,
    ) -> Result<InjectedApprovalLogicalParent, KeyAgentActivationError> {
        let (process_handle, process_id) =
            self.0.duplicate_into_suspended_child(suspended_child)?;
        Ok(InjectedApprovalLogicalParent::from_child_local(
            process_handle,
            process_id,
            seal,
        ))
    }

    #[cfg(test)]
    pub(crate) const fn access_mask_for_test() -> u32 {
        sys::approval_parent_process_access_for_test()
    }
}

impl fmt::Debug for PreparedApprovalParentProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedApprovalParentProcess([EXACT QLI+SYNCHRONIZE KEY AGENT])")
    }
}

/// Mints one least-authority parent process capability from the exact running
/// Key Agent without exposing or reopening by PID.
pub(crate) fn prepare_approval_parent_process(
    activation: &RunningKeyAgentActivation,
) -> Result<PreparedApprovalParentProcess, KeyAgentActivationError> {
    activation.revalidate_resident_process()?;
    sys::PreparedApprovalParentProcess::duplicate(&activation.process, activation.creation_time)
        .map(PreparedApprovalParentProcess)
}

/// Test-only, observation-only duplicate of the exact activated process.
///
/// This capability exposes no handle, process identifier, suspend, resume, or
/// duplication operation. It exists only so integrated kernel tests can prove
/// synchronous aggregate cleanup and force the exact resident process to exit
/// before exercising fail-closed liveness revalidation.
#[cfg(test)]
pub(crate) struct KeyAgentProcessObservation(sys::TestProcessObservation);

#[cfg(test)]
impl KeyAgentProcessObservation {
    pub(crate) fn rejected_exit_code(&self) -> Result<u32, KeyAgentActivationError> {
        self.0.rejected_exit_code()
    }

    pub(crate) fn terminate_for_resident_revalidation_test(
        &self,
    ) -> Result<(), KeyAgentActivationError> {
        self.0.terminate_for_resident_revalidation_test()
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

/// Opaque pre-spawn proof that the pinned artifact passed every release gate.
///
/// Construction performs the complete role -> release evidence -> manifest
/// allowlist -> absolute-path sequence before a worker, Job, pipe, or process
/// is created. The held [`VerifiedHelper`] and opaque whole-release identity
/// remain pinned through exact-image authentication. This capability is
/// non-cloneable and has no artifact, release-digest, or raw-handle accessor.
pub(crate) struct PreflightKeyAgentArtifact {
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
    gate_layout: KeyAgentGateLayout,
}

impl PreflightKeyAgentArtifact {
    /// Compares durable install provenance with the exact release cohort that
    /// authorized this already-held Key Agent artifact. No raw release digest
    /// is exposed to callers.
    pub(crate) fn matches_release_identity(&self, expected: &[u8; 32]) -> bool {
        self.release_identity.matches(expected)
    }
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
    let release_identity = attestation
        .attested_artifact()
        .ok_or(KeyAgentActivationError::ReleaseNotAttested)?;
    if !attestation.allows_helper_manifest(artifact.manifest_digest()) {
        return Err(KeyAgentActivationError::ManifestNotAllowed);
    }
    if !artifact.path().is_absolute() {
        return Err(KeyAgentActivationError::InvalidPath);
    }
    let gate_layout = verify_unique_default_dacl_gate_sequence(&artifact)?;

    Ok(PreflightKeyAgentArtifact {
        artifact,
        release_identity,
        gate_layout,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeyAgentGateLayout {
    sequence_rva: u32,
    breakpoint_rva: u32,
    size_of_image: u32,
}

fn default_dacl_gate_sequence(marker: u64) -> [u8; KEY_AGENT_DEFAULT_DACL_GATE_BYTES] {
    let marker = marker.to_le_bytes();
    let mut sequence = [0_u8; KEY_AGENT_DEFAULT_DACL_GATE_BYTES];
    sequence[0] = 0x49;
    sequence[1] = 0xBA;
    sequence[2..10].copy_from_slice(&marker);
    sequence[10] = 0xCC;
    sequence
}

/// Reopens the already pinned artifact for sequential reading, proves that the
/// path still names the exact held file object, and counts the structural gate
/// sequence across the entire bounded PE file. Counting the whole file is
/// deliberately stronger than accepting a probabilistic marker collision in a
/// loaded executable page: every admitted artifact must contain exactly one
/// occurrence before any activation resource is allocated.
fn verify_unique_default_dacl_gate_sequence(
    artifact: &VerifiedHelper,
) -> Result<KeyAgentGateLayout, KeyAgentActivationError> {
    let mut image = std::fs::File::open(artifact.path())
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
    let reopened_identity = sys::exact_file_identity(HANDLE(image.as_raw_handle()))?;
    let held_identity = sys::exact_file_identity(artifact.raw_handle())?;
    if reopened_identity != held_identity {
        return Err(KeyAgentActivationError::CooperativeGatePolicy);
    }

    let length = image
        .metadata()
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?
        .len();
    if length < KEY_AGENT_DEFAULT_DACL_GATE_BYTES as u64 || length > MAX_KEY_AGENT_IMAGE_BYTES {
        return Err(KeyAgentActivationError::CooperativeGatePolicy);
    }

    // Keep the marker runtime-derived so the verifier itself need not embed a
    // second contiguous copy of the sequence into a test artifact that also
    // contains the child gate. The artifact scan remains authoritative even if
    // a future compiler chooses a different lowering.
    let sequence =
        default_dacl_gate_sequence(std::hint::black_box(KEY_AGENT_DEFAULT_DACL_GATE_MARKER));
    let capacity =
        usize::try_from(length).map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
    let mut bytes = Vec::with_capacity(capacity);
    image
        .read_to_end(&mut bytes)
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;

    let final_identity = sys::exact_file_identity(HANDLE(image.as_raw_handle()))?;
    if bytes.len() != capacity
        || final_identity != reopened_identity
        || sys::exact_file_identity(artifact.raw_handle())? != held_identity
    {
        return Err(KeyAgentActivationError::CooperativeGatePolicy);
    }

    parse_unique_default_dacl_gate_layout(&bytes, &sequence)
}

fn pe_u16(bytes: &[u8], offset: usize) -> Result<u16, KeyAgentActivationError> {
    let end = offset
        .checked_add(size_of::<u16>())
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
    let value: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?
        .try_into()
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
    Ok(u16::from_le_bytes(value))
}

fn pe_u32(bytes: &[u8], offset: usize) -> Result<u32, KeyAgentActivationError> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?
        .try_into()
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
    Ok(u32::from_le_bytes(value))
}

#[derive(Clone, Copy)]
struct PeSectionRange {
    raw_start: usize,
    raw_end: usize,
    initialized_raw_length: usize,
    virtual_start: u32,
    virtual_end: u32,
    characteristics: u32,
}

fn ranges_overlap<T: Ord + Copy>(first: (T, T), second: (T, T)) -> bool {
    first.0 < second.1 && second.0 < first.1
}

#[allow(clippy::too_many_lines)]
fn parse_unique_default_dacl_gate_layout(
    bytes: &[u8],
    sequence: &[u8; KEY_AGENT_DEFAULT_DACL_GATE_BYTES],
) -> Result<KeyAgentGateLayout, KeyAgentActivationError> {
    const DOS_HEADER_BYTES: usize = 64;
    const DOS_PE_OFFSET: usize = 0x3C;
    const COFF_HEADER_BYTES: usize = 20;
    const OPTIONAL_HEADER64_MINIMUM_BYTES: usize = 112;
    const SECTION_HEADER_BYTES: usize = 40;
    const MAX_PE_SECTIONS: usize = 96;
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
    const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    const IMAGE_FILE_DLL: u16 = 0x2000;
    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

    if bytes.len() < DOS_HEADER_BYTES || pe_u16(bytes, 0)? != 0x5A4D {
        return Err(KeyAgentActivationError::CooperativeGatePolicy);
    }
    let pe_offset_u32 = pe_u32(bytes, DOS_PE_OFFSET)?;
    if pe_offset_u32 > i32::MAX.unsigned_abs() {
        return Err(KeyAgentActivationError::CooperativeGatePolicy);
    }
    let pe_offset = usize::try_from(pe_offset_u32)
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
    let coff_offset = pe_offset
        .checked_add(4)
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
    let optional_offset = coff_offset
        .checked_add(COFF_HEADER_BYTES)
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
    if bytes.get(pe_offset..coff_offset) != Some(b"PE\0\0".as_slice())
        || pe_u16(bytes, coff_offset)? != IMAGE_FILE_MACHINE_AMD64
    {
        return Err(KeyAgentActivationError::CooperativeGatePolicy);
    }

    let section_count = usize::from(pe_u16(bytes, coff_offset + 2)?);
    let optional_size = usize::from(pe_u16(bytes, coff_offset + 16)?);
    let file_characteristics = pe_u16(bytes, coff_offset + 18)?;
    if !(1..=MAX_PE_SECTIONS).contains(&section_count)
        || optional_size < OPTIONAL_HEADER64_MINIMUM_BYTES
        || file_characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
        || file_characteristics & IMAGE_FILE_DLL != 0
        || pe_u16(bytes, optional_offset)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        return Err(KeyAgentActivationError::CooperativeGatePolicy);
    }

    let optional_end = optional_offset
        .checked_add(optional_size)
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
    let section_table_bytes = section_count
        .checked_mul(SECTION_HEADER_BYTES)
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
    let section_table_end = optional_end
        .checked_add(section_table_bytes)
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
    let section_alignment = pe_u32(bytes, optional_offset + 32)?;
    let file_alignment = pe_u32(bytes, optional_offset + 36)?;
    let size_of_image = pe_u32(bytes, optional_offset + 56)?;
    let size_of_headers = pe_u32(bytes, optional_offset + 60)?;
    let size_of_headers_usize = usize::try_from(size_of_headers)
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
    if section_alignment == 0
        || file_alignment == 0
        || !section_alignment.is_power_of_two()
        || !file_alignment.is_power_of_two()
        || section_alignment < file_alignment
        || size_of_image == 0
        || u64::from(size_of_image) > MAX_KEY_AGENT_IMAGE_BYTES
        || size_of_headers == 0
        || size_of_headers > size_of_image
        || section_table_end > size_of_headers_usize
        || size_of_headers_usize > bytes.len()
        || size_of_image % section_alignment != 0
    {
        return Err(KeyAgentActivationError::CooperativeGatePolicy);
    }

    let mut occurrence = None;
    for (offset, candidate) in bytes.windows(KEY_AGENT_DEFAULT_DACL_GATE_BYTES).enumerate() {
        if candidate == sequence && occurrence.replace(offset).is_some() {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
    }
    let occurrence = occurrence.ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
    let occurrence_end = occurrence
        .checked_add(KEY_AGENT_DEFAULT_DACL_GATE_BYTES)
        .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;

    let mut sections: Vec<PeSectionRange> = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let section_offset = optional_end
            .checked_add(
                index
                    .checked_mul(SECTION_HEADER_BYTES)
                    .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?,
            )
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        let virtual_size = pe_u32(bytes, section_offset + 8)?;
        let virtual_start = pe_u32(bytes, section_offset + 12)?;
        let raw_size = pe_u32(bytes, section_offset + 16)?;
        let raw_start_u32 = pe_u32(bytes, section_offset + 20)?;
        let characteristics = pe_u32(bytes, section_offset + 36)?;
        let raw_start = usize::try_from(raw_start_u32)
            .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        let raw_size_usize = usize::try_from(raw_size)
            .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        let raw_end = raw_start
            .checked_add(raw_size_usize)
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        let mapped_size = virtual_size.max(raw_size);
        let virtual_end = virtual_start
            .checked_add(mapped_size)
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        if virtual_start % section_alignment != 0
            || (raw_size != 0
                && (raw_start_u32 % file_alignment != 0
                    || raw_size % file_alignment != 0
                    || raw_start < size_of_headers_usize
                    || raw_end > bytes.len()))
            || virtual_end > size_of_image
        {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
        let initialized_raw_length = usize::try_from(virtual_size.min(raw_size))
            .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        let section = PeSectionRange {
            raw_start,
            raw_end,
            initialized_raw_length,
            virtual_start,
            virtual_end,
            characteristics,
        };
        for prior in &sections {
            if (section.raw_start != section.raw_end
                && prior.raw_start != prior.raw_end
                && ranges_overlap(
                    (section.raw_start, section.raw_end),
                    (prior.raw_start, prior.raw_end),
                ))
                || (section.virtual_start != section.virtual_end
                    && prior.virtual_start != prior.virtual_end
                    && ranges_overlap(
                        (section.virtual_start, section.virtual_end),
                        (prior.virtual_start, prior.virtual_end),
                    ))
            {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }
        }
        sections.push(section);
    }

    let mut layout = None;
    for section in sections {
        if occurrence < section.raw_start || occurrence_end > section.raw_end {
            continue;
        }
        let delta = occurrence
            .checked_sub(section.raw_start)
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        let initialized_end = delta
            .checked_add(KEY_AGENT_DEFAULT_DACL_GATE_BYTES)
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        if section.characteristics & IMAGE_SCN_CNT_CODE == 0
            || section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0
            || section.characteristics & IMAGE_SCN_MEM_WRITE != 0
            || initialized_end > section.initialized_raw_length
        {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
        let delta =
            u32::try_from(delta).map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        let sequence_rva = section
            .virtual_start
            .checked_add(delta)
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        let sequence_end = sequence_rva
            .checked_add(
                u32::try_from(KEY_AGENT_DEFAULT_DACL_GATE_BYTES)
                    .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?,
            )
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        let breakpoint_rva = sequence_rva
            .checked_add(
                u32::try_from(KEY_AGENT_DEFAULT_DACL_GATE_BYTES - 1)
                    .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?,
            )
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        if sequence_end > section.virtual_end
            || sequence_end > size_of_image
            || layout
                .replace(KeyAgentGateLayout {
                    sequence_rva,
                    breakpoint_rva,
                    size_of_image,
                })
                .is_some()
        {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
    }
    layout.ok_or(KeyAgentActivationError::CooperativeGatePolicy)
}

/// One-shot proof that code is running on the activation-owned fresh OS thread.
///
/// The constructor and field are module-private. The `Rc` marker makes the
/// token `!Send + !Sync`; it is created only after the worker starts and is
/// consumed by the single process-creation operation, so callers cannot forge,
/// transfer, return, or reuse the debugger-thread authority.
pub(crate) struct FreshKeyAgentDebugThread {
    witness: Arc<KeyAgentDebugThreadWitness>,
    debug_event_cleanup: Arc<KeyAgentDebugEventCleanup>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl FreshKeyAgentDebugThread {
    pub(crate) fn bind_root_job_cleanup(
        self,
        root_job: &mut KeyAgentRootJob,
    ) -> Result<RootJobBoundFreshKeyAgentDebugThread, KeyAgentActivationError> {
        root_job
            .bind_debugger_cleanup_gate(Arc::clone(&self.witness))
            .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
        Ok(RootJobBoundFreshKeyAgentDebugThread {
            witness: self.witness,
            debug_event_cleanup: self.debug_event_cleanup,
            _not_send_or_sync: PhantomData,
        })
    }
}

impl fmt::Debug for FreshKeyAgentDebugThread {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshKeyAgentDebugThread([ONE-SHOT WORKER PROOF])")
    }
}

/// One-shot fresh-thread proof after installing this run's witness into a root
/// Job before any creation-attribute borrow can exist.
///
/// Detached finalization later requires the pending state, join proof, and
/// supplied root Job to share that exact witness.
pub(crate) struct RootJobBoundFreshKeyAgentDebugThread {
    witness: Arc<KeyAgentDebugThreadWitness>,
    debug_event_cleanup: Arc<KeyAgentDebugEventCleanup>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl RootJobBoundFreshKeyAgentDebugThread {
    fn into_run_context(
        self,
    ) -> (
        Arc<KeyAgentDebugThreadWitness>,
        Arc<KeyAgentDebugEventCleanup>,
    ) {
        (self.witness, self.debug_event_cleanup)
    }
}

impl fmt::Debug for RootJobBoundFreshKeyAgentDebugThread {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootJobBoundFreshKeyAgentDebugThread([ONE-SHOT BOUND PROOF])")
    }
}

/// Proof minted on the caller only after the dedicated debugger OS thread was
/// joined successfully.
///
/// The private constructor prevents forgery. The `Rc` marker makes the proof
/// `!Send + !Sync`; independently, an exact shared witness identity brands it
/// to one run so a proof from a different joined worker is rejected.
#[must_use = "the join proof must be consumed by post-debugger-exit finalization"]
pub(crate) struct JoinedKeyAgentDebugThreadProof {
    witness: Arc<KeyAgentDebugThreadWitness>,
    debug_event_cleanup: Arc<KeyAgentDebugEventCleanup>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl Drop for JoinedKeyAgentDebugThreadProof {
    fn drop(&mut self) {
        let _ = self.debug_event_cleanup.close_after_join(&self.witness);
    }
}

impl fmt::Debug for JoinedKeyAgentDebugThreadProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JoinedKeyAgentDebugThreadProof([JOINED])")
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
pub(crate) fn run_on_fresh_key_agent_debug_thread<T, E, F>(
    worker: F,
) -> Result<(T, JoinedKeyAgentDebugThreadProof), E>
where
    T: Send + 'static,
    E: From<KeyAgentActivationError> + Send + 'static,
    F: FnOnce(FreshKeyAgentDebugThread) -> Result<T, E> + Send + 'static,
{
    let witness = KeyAgentDebugThreadWitness::new_shared();
    let debug_event_cleanup = KeyAgentDebugEventCleanup::new_shared(Arc::clone(&witness));
    let worker_witness = Arc::clone(&witness);
    let worker_debug_event_cleanup = Arc::clone(&debug_event_cleanup);
    let worker = std::thread::Builder::new()
        .name("key-agent-activation".to_owned())
        .spawn(move || {
            worker(FreshKeyAgentDebugThread {
                witness: worker_witness,
                debug_event_cleanup: worker_debug_event_cleanup,
                _not_send_or_sync: PhantomData,
            })
        })
        .map_err(|_| E::from(KeyAgentActivationError::ActivationWorker))?;
    let outcome = worker.join();
    // Joining establishes that Windows has processed debugger-thread exit. The
    // release store also switches any surviving root-Job owner back to its
    // ordinary synchronous cleanup policy before an outcome is returned.
    if witness.mark_joined().is_err() {
        debug_event_cleanup
            .close_after_join(&witness)
            .map_err(E::from)?;
        return Err(E::from(KeyAgentActivationError::ActivationWorker));
    }
    let value = match outcome {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            debug_event_cleanup
                .close_after_join(&witness)
                .map_err(E::from)?;
            return Err(error);
        }
        Err(_) => {
            debug_event_cleanup
                .close_after_join(&witness)
                .map_err(E::from)?;
            return Err(E::from(KeyAgentActivationError::ActivationWorker));
        }
    };
    Ok((
        value,
        JoinedKeyAgentDebugThreadProof {
            witness,
            debug_event_cleanup,
            _not_send_or_sync: PhantomData,
        },
    ))
}

/// Converts the no-kill pending state into a detached dormant activation only
/// after the dedicated debugger thread has exited and been joined.
pub(crate) fn finalize_pending_key_agent_activation(
    mut pending: PendingKeyAgentActivation,
    root_job: &KeyAgentRootJob,
    joined: JoinedKeyAgentDebugThreadProof,
) -> Result<HeldKeyAgentActivation, KeyAgentActivationError> {
    if !Arc::ptr_eq(&pending.debug_event_cleanup, &joined.debug_event_cleanup) {
        return Err(KeyAgentActivationError::DebuggerJoinProof);
    }
    pending.observe_debugger_exit_for_cleanup(root_job, &joined)?;
    let event_handles = pending
        .debug_event_cleanup
        .take_after_join(&joined.witness)?;
    if let Err((error, event_handles)) = pending
        .process
        .adopt_detached_debug_event_handles(event_handles)
    {
        pending
            .debug_event_cleanup
            .restore_after_join(&joined.witness, event_handles)
            .map_err(|_| KeyAgentActivationError::Cleanup)?;
        return Err(error);
    }
    let PendingKeyAgentActivation {
        process,
        debug_thread_witness,
        debug_event_cleanup,
        artifact,
        release_identity,
        artifact_identity,
        creation_time,
    } = pending;
    debug_assert!(Arc::ptr_eq(&debug_thread_witness, &joined.witness));
    debug_assert!(Arc::ptr_eq(
        &debug_event_cleanup,
        &joined.debug_event_cleanup
    ));
    drop(debug_event_cleanup);
    drop(joined);
    let process = process.finalize_after_debugger_exit(root_job)?;
    Ok(HeldKeyAgentActivation {
        process,
        artifact,
        release_identity,
        artifact_identity,
        creation_time,
    })
}

/// Creates and exact-image authenticates one preflighted Key Agent.
///
/// The one-shot debugger-thread token and both lifetime-bound creation
/// capabilities must have been constructed inside the same fresh worker. The
/// returned process remains debug-attached, with its first event continued and
/// one proven explicit suspend count. This function exposes neither a raw
/// handle nor a resume/start operation.
pub(crate) fn activate_preflighted_key_agent_on_fresh_worker(
    fresh_thread: RootJobBoundFreshKeyAgentDebugThread,
    preflighted: PreflightKeyAgentArtifact,
    provisioning: &PreparedKeyAgentProvisioning,
    pipes: &PrivateKeyAgentPipes,
    root_job: &KeyAgentRootJob,
    root_job_attribute: &KeyAgentRootJobAttribute<'_>,
    coordination_deadline: Instant,
) -> Result<AuthenticatedKeyAgentActivation, KeyAgentActivationError> {
    let PreflightKeyAgentArtifact {
        artifact,
        release_identity,
        gate_layout,
    } = preflighted;
    let artifact_identity = sys::exact_file_identity(artifact.raw_handle())?;
    activate_preflighted_key_agent_on_fresh_worker_with_identity(
        fresh_thread,
        artifact,
        release_identity,
        artifact_identity,
        gate_layout,
        provisioning,
        pipes,
        root_job,
        root_job_attribute,
        coordination_deadline,
    )
}

/// Test-only equivalent that selects one exact ignored child fixture through
/// the test executable's command line. Production activation never supplies a
/// command line and therefore cannot select this seam.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_preflighted_key_agent_on_fresh_worker_for_kernel_test(
    fresh_thread: RootJobBoundFreshKeyAgentDebugThread,
    preflighted: PreflightKeyAgentArtifact,
    provisioning: &PreparedKeyAgentProvisioning,
    pipes: &PrivateKeyAgentPipes,
    root_job: &KeyAgentRootJob,
    root_job_attribute: &KeyAgentRootJobAttribute<'_>,
    coordination_deadline: Instant,
    command_line: &mut [u16],
) -> Result<AuthenticatedKeyAgentActivation, KeyAgentActivationError> {
    let PreflightKeyAgentArtifact {
        artifact,
        release_identity,
        gate_layout,
    } = preflighted;
    let artifact_identity = sys::exact_file_identity(artifact.raw_handle())?;
    verify_empty_root_job(root_job)?;
    let (debug_thread_witness, debug_event_cleanup) = fresh_thread.into_run_context();
    let process = sys::SuspendedDebuggee::create_with_test_command_line(
        &artifact,
        provisioning,
        pipes,
        root_job,
        root_job_attribute,
        sys::DebuggeeLaunchPolicy::new(coordination_deadline, gate_layout),
        command_line,
    )?;
    authenticate_and_continue_activation(
        artifact,
        release_identity,
        artifact_identity,
        debug_thread_witness,
        debug_event_cleanup,
        root_job,
        process,
    )
}

// Keeping each lifetime-bound launch authority explicit makes mismatched Job,
// pipe, provisioning, and deadline inputs visible at this one testable leaf.
#[allow(clippy::too_many_arguments)]
fn activate_preflighted_key_agent_on_fresh_worker_with_identity(
    fresh_thread: RootJobBoundFreshKeyAgentDebugThread,
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
    artifact_identity: ExactFileObjectIdentity,
    gate_layout: KeyAgentGateLayout,
    provisioning: &PreparedKeyAgentProvisioning,
    pipes: &PrivateKeyAgentPipes,
    root_job: &KeyAgentRootJob,
    root_job_attribute: &KeyAgentRootJobAttribute<'_>,
    coordination_deadline: Instant,
) -> Result<AuthenticatedKeyAgentActivation, KeyAgentActivationError> {
    verify_empty_root_job(root_job)?;
    let (debug_thread_witness, debug_event_cleanup) = fresh_thread.into_run_context();
    let process = sys::SuspendedDebuggee::create(
        &artifact,
        provisioning,
        pipes,
        root_job,
        root_job_attribute,
        sys::DebuggeeLaunchPolicy::new(coordination_deadline, gate_layout),
    )?;
    authenticate_and_continue_activation(
        artifact,
        release_identity,
        artifact_identity,
        debug_thread_witness,
        debug_event_cleanup,
        root_job,
        process,
    )
}

fn authenticate_and_continue_activation(
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
    artifact_identity: ExactFileObjectIdentity,
    debug_thread_witness: Arc<KeyAgentDebugThreadWitness>,
    debug_event_cleanup: Arc<KeyAgentDebugEventCleanup>,
    root_job: &KeyAgentRootJob,
    mut process: sys::SuspendedDebuggee,
) -> Result<AuthenticatedKeyAgentActivation, KeyAgentActivationError> {
    let first_event = match process.authenticate_first_event(
        artifact_identity,
        FIRST_DEBUG_EVENT_TIMEOUT_MILLISECONDS,
        &debug_event_cleanup,
    ) {
        Ok(event) => event,
        Err(error) => return fail_after_cleanup(&mut process, error),
    };
    if let Err(error) =
        process.continue_to_cooperative_gate(first_event.deadline, &debug_event_cleanup)
    {
        return fail_after_cleanup(&mut process, error);
    }
    if let Err(error) = verify_bound_root_process(root_job, process.process_handle()) {
        return fail_after_cleanup(&mut process, error);
    }
    if let Err(error) = process.revalidate_before_no_kill() {
        return fail_after_cleanup(&mut process, error);
    }

    Ok(AuthenticatedKeyAgentActivation {
        process,
        debug_thread_witness,
        debug_event_cleanup,
        artifact,
        release_identity,
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

    use core::cell::Cell;
    use core::ffi::c_void;
    use core::fmt;
    use core::marker::PhantomData;
    use core::mem::{size_of, size_of_val};
    use core::ptr;
    use std::ffi::OsString;
    use std::fs::OpenOptions;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{
        AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle,
    };
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[cfg(test)]
    use windows::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
    use windows::Win32::Foundation::DUPLICATE_SAME_ACCESS;
    use windows::Win32::Foundation::{
        CloseHandle, CompareObjectHandles, DBG_CONTINUE, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle,
        ERROR_SEM_TIMEOUT, EXCEPTION_BREAKPOINT, FILETIME, GetHandleInformation, GetLastError,
        HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    #[cfg(test)]
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_SUCCESS, STATUS_SUCCESS, SetLastError,
    };
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_SHARE_READ, FileAttributeTagInfo,
        FileIdInfo, GetFileInformationByHandleEx,
    };
    use windows::Win32::System::Diagnostics::Debug::{
        CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64, CREATE_PROCESS_DEBUG_EVENT,
        CREATE_THREAD_DEBUG_EVENT, CheckRemoteDebuggerPresent, ContinueDebugEvent, DEBUG_EVENT,
        DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
        EXIT_THREAD_DEBUG_EVENT, GetThreadContext, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT,
        RIP_EVENT, ReadProcessMemory, SetThreadContext, WaitForDebugEventEx,
    };
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_GUARD, VirtualQueryEx,
    };
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS,
        DEBUG_PROCESS, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        GetCurrentProcess, GetExitCodeProcess, GetProcessId, GetProcessIdOfThread, GetProcessTimes,
        GetThreadId, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROCESS_ACCESS_RIGHTS, PROCESS_INFORMATION,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        QueryFullProcessImageNameW, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        SuspendThread, THREAD_ACCESS_RIGHTS, THREAD_RESUME, THREAD_SUSPEND_RESUME,
        TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    #[cfg(test)]
    use windows::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;
    use windows::core::{BOOL, PCWSTR, PWSTR};

    use super::{
        DetachedDebugEventHandleSet, ExactFileObjectIdentity, KEY_AGENT_DEFAULT_DACL_GATE_BYTES,
        KeyAgentActivationError, KeyAgentDebugEventCleanup, KeyAgentGateLayout, LaunchPhase,
        LaunchTransition,
    };
    use crate::helper::VerifiedHelper;
    use crate::inheritable_handle_launch::{
        InheritableHandleLaunchFlight, acquire_inheritable_handle_launch,
    };
    use crate::key_agent_lpac::{
        PendingKeyAgentLpac, PreparedKeyAgentCreationSecurity, PreparedKeyAgentLpac,
        PreparedKeyAgentProvisioning, VerifiedKeyAgentLpac,
    };
    use crate::key_agent_root_job::{KeyAgentRootJob, KeyAgentRootJobAttribute};
    use crate::pipe::{PreparedKeyAgentInheritance, PrivateKeyAgentPipes};
    use crate::restricted_process_context::RestrictedProcessContext;

    const CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000;
    const REJECTED_PROCESS_EXIT_CODE: u32 = 0xE0A0_0001;
    const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);
    const RESIDENT_KEY_AGENT_PROCESS_ACCESS: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(
        PROCESS_TERMINATE.0 | PROCESS_QUERY_LIMITED_INFORMATION.0 | PROCESS_SYNCHRONIZE.0,
    );
    const POST_DETACH_THREAD_PROBE_ACCESS: THREAD_ACCESS_RIGHTS = THREAD_SUSPEND_RESUME;
    const STORAGE_STARTUP_THREAD_ACCESS: THREAD_ACCESS_RIGHTS = THREAD_RESUME;
    const APPROVAL_PARENT_PROCESS_ACCESS: PROCESS_ACCESS_RIGHTS =
        PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_LIMITED_INFORMATION.0 | PROCESS_SYNCHRONIZE.0);
    const MAX_PROCESS_IMAGE_PATH_UNITS: usize = 32_768;
    const MAX_LOADER_DEBUG_EVENTS: usize = 128;
    const MAX_PRE_GATE_DEBUG_EVENTS: usize = 160;
    const KEY_AGENT_CREATION_ATTRIBUTE_COUNT: u32 = 5;

    const MITIGATION_DEP_ENABLE: u64 = 1;
    const MITIGATION_SEHOP_ENABLE: u64 = 1 << 2;
    const MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON: u64 = 1 << 8;
    const MITIGATION_HEAP_TERMINATE_ALWAYS_ON: u64 = 1 << 12;
    const MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON: u64 = 1 << 16;
    const MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON: u64 = 1 << 20;
    const MITIGATION_STRICT_HANDLE_CHECKS_ALWAYS_ON: u64 = 1 << 24;
    const MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 1 << 32;
    const MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON: u64 = 1 << 36;
    const MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 1 << 44;
    const MITIGATION_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON: u64 = 1 << 52;
    const MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON: u64 = 1 << 56;
    const MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON: u64 = 1 << 60;

    // Intentionally identical to launch.rs's HELPER_MITIGATION_POLICY and the
    // service startup path's SERVICE_PROBE_MITIGATION_POLICY.
    const KEY_AGENT_MITIGATION_POLICY: u64 = MITIGATION_DEP_ENABLE
        | MITIGATION_SEHOP_ENABLE
        | MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON
        | MITIGATION_HEAP_TERMINATE_ALWAYS_ON
        | MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON
        | MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON
        | MITIGATION_STRICT_HANDLE_CHECKS_ALWAYS_ON
        | MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON
        | MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
        | MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
        | MITIGATION_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
        | MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
        | MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;

    fn wait_for_debug_event_until(
        deadline: Instant,
    ) -> Result<DEBUG_EVENT, KeyAgentActivationError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(KeyAgentActivationError::DebugEventTimeout)?;
        let rounded_milliseconds = remaining.as_millis().saturating_add(1);
        let timeout = u32::try_from(rounded_milliseconds.min(u128::from(u32::MAX)))
            .map_err(|_| KeyAgentActivationError::DebugEventTimeout)?
            .max(1);
        let mut event = DEBUG_EVENT::default();
        // SAFETY: event points to exact writable storage and the caller is the
        // same dedicated OS thread that created this debuggee.
        if unsafe { WaitForDebugEventEx(&raw mut event, timeout) }.is_err() {
            // SAFETY: queried immediately after the failed Win32 call.
            return if unsafe { GetLastError() } == ERROR_SEM_TIMEOUT {
                Err(KeyAgentActivationError::DebugEventTimeout)
            } else {
                Err(KeyAgentActivationError::UnexpectedDebugEvent)
            };
        }
        Ok(event)
    }

    fn query_remote_image_page(
        process: HANDLE,
        address: usize,
        required_allocation_base: usize,
        required_end: usize,
        require_executable: bool,
    ) -> Result<MEMORY_BASIC_INFORMATION, KeyAgentActivationError> {
        if address == 0 || required_allocation_base == 0 || required_end <= address {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
        let mut information = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: process is the retained live debuggee; the address is used
        // only as a remote query key and information is exact writable storage.
        let returned = unsafe {
            VirtualQueryEx(
                process,
                Some(address as *const c_void),
                &raw mut information,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        let region_start = information.BaseAddress.addr();
        let region_end = region_start
            .checked_add(information.RegionSize)
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        let base_protection = information.Protect.0 & 0xFF;
        let executable_nonwritable =
            base_protection == PAGE_EXECUTE.0 || base_protection == PAGE_EXECUTE_READ.0;
        if returned != size_of::<MEMORY_BASIC_INFORMATION>()
            || information.AllocationBase.addr() != required_allocation_base
            || information.State != MEM_COMMIT
            || information.Type != MEM_IMAGE
            || information.Protect.0 & PAGE_GUARD.0 != 0
            || (require_executable && !executable_nonwritable)
            || region_start > address
            || required_end > region_end
        {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
        Ok(information)
    }

    fn read_remote_exact<const N: usize>(
        process: HANDLE,
        address: usize,
    ) -> Result<[u8; N], KeyAgentActivationError> {
        let mut bytes = [0_u8; N];
        let mut read = 0_usize;
        // SAFETY: the destination is exact writable local storage. The source
        // is read-only remote memory whose committed range was authenticated by
        // the caller immediately beforehand.
        unsafe {
            ReadProcessMemory(
                process,
                address as *const c_void,
                bytes.as_mut_ptr().cast::<c_void>(),
                N,
                Some(&raw mut read),
            )
        }
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        if read != N {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
        Ok(bytes)
    }

    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct AlignedAmd64Context(CONTEXT);

    fn primary_thread_context(
        thread: HANDLE,
    ) -> Result<AlignedAmd64Context, KeyAgentActivationError> {
        let mut context = AlignedAmd64Context(CONTEXT {
            ContextFlags: CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
            ..CONTEXT::default()
        });
        // SAFETY: this exact primary-thread handle remains live and Windows has
        // stopped the thread for the debug event. AMD64 CONTEXT storage is
        // explicitly 16-byte aligned even though the generated Rust type has a
        // weaker alignment than the native ABI declaration.
        unsafe { GetThreadContext(thread, &raw mut context.0) }
            .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        if context.0.ContextFlags != (CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64) {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
        Ok(context)
    }

    fn context_matches_after_r10_clear(before: &CONTEXT, after: &CONTEXT) -> bool {
        const AMD64_EFLAGS_RESERVED_ONE: u32 = 1 << 1;

        after.ContextFlags == before.ContextFlags
            && after.R10 == 0
            && after.P1Home == before.P1Home
            && after.P2Home == before.P2Home
            && after.P3Home == before.P3Home
            && after.P4Home == before.P4Home
            && after.P5Home == before.P5Home
            && after.P6Home == before.P6Home
            && after.SegCs == before.SegCs
            && after.SegSs == before.SegSs
            // SetThreadContext/GetThreadContext may canonicalize away the
            // architecturally reserved, always-one EFLAGS bit in its API
            // representation. Every mutable flag bit must remain exact.
            && before.EFlags & AMD64_EFLAGS_RESERVED_ONE != 0
            && after.EFlags & !AMD64_EFLAGS_RESERVED_ONE
                == before.EFlags & !AMD64_EFLAGS_RESERVED_ONE
            && after.Rax == before.Rax
            && after.Rcx == before.Rcx
            && after.Rdx == before.Rdx
            && after.Rbx == before.Rbx
            && after.Rsp == before.Rsp
            && after.Rbp == before.Rbp
            && after.Rsi == before.Rsi
            && after.Rdi == before.Rdi
            && after.R8 == before.R8
            && after.R9 == before.R9
            && after.R11 == before.R11
            && after.R12 == before.R12
            && after.R13 == before.R13
            && after.R14 == before.R14
            && after.R15 == before.R15
            && after.Rip == before.Rip
    }

    /// Initialized five-slot process-creation policy retained through one call.
    ///
    /// The backing words, the exact three-HANDLE array, the heap-stable
    /// mitigation word, the prepared pipe capability, and the stable Job-HANDLE
    /// and LPAC attributes all outlive `CreateProcessW`. Drop deletes the native
    /// list before any retained storage or borrow is released.
    struct KeyAgentCreationAttributes<'resources, 'pipes, 'flight, 'job> {
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        words: Vec<usize>,
        inherited_handles: Box<[HANDLE; 3]>,
        mitigation_policy: Box<u64>,
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
            let _ = unsafe {
                InitializeProcThreadAttributeList(
                    None,
                    KEY_AGENT_CREATION_ATTRIBUTE_COUNT,
                    None,
                    &raw mut bytes,
                )
            };
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
            unsafe {
                InitializeProcThreadAttributeList(
                    Some(pointer),
                    KEY_AGENT_CREATION_ATTRIBUTE_COUNT,
                    None,
                    &raw mut bytes,
                )
            }
            .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;

            let inherited_handles = Box::new([
                windows_handle(inheritance.stdin()),
                windows_handle(inheritance.stdout()),
                windows_handle(inheritance.stderr()),
            ]);
            let mitigation_policy = Box::new(KEY_AGENT_MITIGATION_POLICY);
            let attributes = Self {
                pointer,
                words,
                inherited_handles,
                mitigation_policy,
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
            attributes.install_mitigation_policy()?;
            // SAFETY: the initialized list has exactly two slots remaining
            // after the fixed HANDLE, Job, and mitigation-policy prefix.
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

        fn install_mitigation_policy(&self) -> Result<(), KeyAgentActivationError> {
            // SAFETY: the list is live with its third slot free. The boxed u64
            // has a stable address and is retained through CreateProcessW and
            // attribute-list deletion.
            unsafe {
                UpdateProcThreadAttribute(
                    self.pointer,
                    0,
                    usize::try_from(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)
                        .map_err(|_| KeyAgentActivationError::ProcessCreation)?,
                    Some(ptr::from_ref(self.mitigation_policy.as_ref()).cast::<c_void>()),
                    size_of::<u64>(),
                    None,
                    None,
                )
            }
            .map_err(|_| KeyAgentActivationError::ProcessCreation)
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

        #[cfg(test)]
        fn retained_mitigation_policy(&self) -> u64 {
            *self.mitigation_policy
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
        creation_security: PreparedKeyAgentCreationSecurity,
        system_ntdll: PinnedSystemNtdll,
    }

    impl PreparedKeyAgentProcess {
        fn into_security_parts(
            self,
        ) -> (
            PreparedKeyAgentLpac,
            PreparedKeyAgentCreationSecurity,
            PinnedSystemNtdll,
        ) {
            (self.lpac, self.creation_security, self.system_ntdll)
        }
    }

    struct PinnedSystemNtdll {
        handle: OwnedWinHandle,
        identity: ExactFileObjectIdentity,
    }

    fn pin_system_ntdll(
        context: &RestrictedProcessContext,
    ) -> Result<PinnedSystemNtdll, KeyAgentActivationError> {
        let system_directory = context.current_directory();
        let path_units = system_directory
            .strip_suffix(&[0])
            .filter(|units| !units.is_empty() && !units.contains(&0))
            .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        let path = PathBuf::from(OsString::from_wide(path_units)).join("ntdll.dll");
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)
            .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        let raw = HANDLE(file.as_raw_handle());
        let mut flags = u32::MAX;
        // SAFETY: the newly opened file remains owned by `file` and `flags`
        // names exact initialized writable storage.
        unsafe { GetHandleInformation(raw, &raw mut flags) }
            .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: `raw` is the exact live file and `attributes` is correctly
        // sized writable storage for FileAttributeTagInfo.
        unsafe {
            GetFileInformationByHandleEx(
                raw,
                FileAttributeTagInfo,
                ptr::from_mut(&mut attributes).cast::<c_void>(),
                u32::try_from(size_of_val(&attributes))
                    .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?,
            )
        }
        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
        if flags != 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        {
            return Err(KeyAgentActivationError::CooperativeGatePolicy);
        }
        let identity = exact_file_identity(raw)?;
        let raw = HANDLE(file.into_raw_handle());
        let handle =
            OwnedWinHandle::new(raw).ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
        Ok(PinnedSystemNtdll { handle, identity })
    }

    fn prepare_key_agent_process(
        artifact: &VerifiedHelper,
        provisioning: &PreparedKeyAgentProvisioning,
    ) -> Result<PreparedKeyAgentProcess, KeyAgentActivationError> {
        #[cfg(test)]
        let context = RestrictedProcessContext::prepare_for_kernel_test();
        #[cfg(not(test))]
        let context = RestrictedProcessContext::prepare();
        let context = context.map_err(|_| KeyAgentActivationError::ProcessContextPolicy)?;
        let system_ntdll = pin_system_ntdll(&context)?;
        provisioning
            .revalidate()
            .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
        let creation_security = provisioning
            .prepare_creation_security()
            .map_err(|_| KeyAgentActivationError::CreationSecurityPolicy)?;
        let lpac = provisioning
            .prepare_lpac()
            .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
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
            creation_security,
            system_ntdll,
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
        let process_thread_security = prepared_process.creation_security.creation_security();
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
        // writable and retained. `attributes` is a live initialized five-slot
        // list containing exactly HANDLE_LIST(3), JOB_LIST(1), the full helper
        // MITIGATION_POLICY, SECURITY_CAPABILITIES(zero), and the LPAC AAP
        // opt-out policy; the three listed stdio handles are the only inheritable
        // handles. The paired
        // non-inheritable process/thread security attributes retain their exact
        // protected descriptors through this call. The retained process context
        // supplies a validated System32 current directory and an exact three-name
        // Unicode environment: its OS-derived SystemRoot and WINDIR plus the
        // exact AppContainer FOLDERID_LocalAppData path. The flags keep
        // creation both headless and suspended
        // before user-mode entry.
        unsafe {
            flight
                .create_process_with_explicit_handle_list(
                    PCWSTR(prepared_process.application.as_ptr()),
                    command_line,
                    Some(process_thread_security),
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PendingDebugEventKind {
        CreateProcess,
        Loader,
        CooperativeGate,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PendingDebugEvent {
        process_id: u32,
        thread_id: u32,
        kind: PendingDebugEventKind,
    }

    #[derive(Clone, Copy)]
    pub(super) struct DebuggeeLaunchPolicy {
        coordination_deadline: Instant,
        gate_layout: KeyAgentGateLayout,
    }

    impl DebuggeeLaunchPolicy {
        pub(super) const fn new(
            coordination_deadline: Instant,
            gate_layout: KeyAgentGateLayout,
        ) -> Self {
            Self {
                coordination_deadline,
                gate_layout,
            }
        }
    }

    pub(super) struct SuspendedDebuggee {
        process: OwnedWinHandle,
        primary_thread: OwnedWinHandle,
        process_id: u32,
        thread_id: u32,
        pending_event: Option<PendingDebugEvent>,
        // Distinct raw aliases supplied by CREATE_PROCESS_DEBUG_EVENT. They are
        // system-managed while attached, transferred to the run's shared cleanup
        // registry before no-kill arming, then adopted and checked-closed only
        // after the exact debugger OS thread has joined.
        debug_event_process: Option<HANDLE>,
        debug_event_primary_thread: Option<HANDLE>,
        phase: LaunchPhase,
        gate_layout: KeyAgentGateLayout,
        main_image_base: Option<usize>,
        system_ntdll: Option<PinnedSystemNtdll>,
        loaded_system_ntdll_base: Option<usize>,
        system_breakpoint_seen: bool,
        prepared_lpac: Option<PreparedKeyAgentLpac>,
        pending_lpac: Option<PendingKeyAgentLpac>,
        // Present only after the exact suspended primary token proved the
        // fixed Key Agent SID, zero capabilities, and differential LPAC
        // access-membership behavior. The proof retains a process-wide token
        // handle and opaque continuity evidence for every later checkpoint.
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
            provisioning: &PreparedKeyAgentProvisioning,
            pipes: &PrivateKeyAgentPipes,
            root_job: &KeyAgentRootJob,
            root_job_attribute: &KeyAgentRootJobAttribute<'_>,
            policy: DebuggeeLaunchPolicy,
        ) -> Result<Self, KeyAgentActivationError> {
            Self::create_inner(
                artifact,
                provisioning,
                pipes,
                root_job,
                root_job_attribute,
                policy,
                None,
            )
        }

        #[cfg(test)]
        pub(super) fn create_with_test_command_line(
            artifact: &VerifiedHelper,
            provisioning: &PreparedKeyAgentProvisioning,
            pipes: &PrivateKeyAgentPipes,
            root_job: &KeyAgentRootJob,
            root_job_attribute: &KeyAgentRootJobAttribute<'_>,
            policy: DebuggeeLaunchPolicy,
            command_line: &mut [u16],
        ) -> Result<Self, KeyAgentActivationError> {
            Self::create_inner(
                artifact,
                provisioning,
                pipes,
                root_job,
                root_job_attribute,
                policy,
                Some(command_line),
            )
        }

        fn initial_suspended(
            process: OwnedWinHandle,
            primary_thread: OwnedWinHandle,
            process_id: u32,
            thread_id: u32,
            gate_layout: KeyAgentGateLayout,
            system_ntdll: PinnedSystemNtdll,
            prepared_lpac: Option<PreparedKeyAgentLpac>,
        ) -> Self {
            Self {
                process,
                primary_thread,
                process_id,
                thread_id,
                pending_event: None,
                debug_event_process: None,
                debug_event_primary_thread: None,
                phase: LaunchPhase::AwaitingCreateEvent,
                gate_layout,
                main_image_base: None,
                system_ntdll: Some(system_ntdll),
                loaded_system_ntdll_base: None,
                system_breakpoint_seen: false,
                prepared_lpac,
                pending_lpac: None,
                lpac: None,
                proven_suspend_count: 1,
                cleanup_exit_code: None,
            }
        }

        fn adopt_created_process(
            information: PROCESS_INFORMATION,
            gate_layout: KeyAgentGateLayout,
            system_ntdll: PinnedSystemNtdll,
            prepared_lpac: PreparedKeyAgentLpac,
        ) -> Result<Self, KeyAgentActivationError> {
            let process = OwnedWinHandle::new(information.hProcess);
            let primary_thread = OwnedWinHandle::new(information.hThread);
            let (process, primary_thread) = match (process, primary_thread) {
                (Some(process), Some(primary_thread)) => (process, primary_thread),
                (process, primary_thread) => {
                    // CreateProcessW success is documented to return both
                    // handles. If that invariant is violated, request
                    // termination through whichever process handle exists and
                    // let debugger-thread exit plus Job close finish cleanup.
                    if let Some(process) = process.as_ref() {
                        // SAFETY: this is the valid process handle returned by
                        // the successful CreateProcessW call above.
                        let _ =
                            unsafe { TerminateProcess(process.raw(), REJECTED_PROCESS_EXIT_CODE) };
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
                let mut rejected = Self::initial_suspended(
                    process,
                    primary_thread,
                    information.dwProcessId,
                    information.dwThreadId,
                    gate_layout,
                    system_ntdll,
                    None,
                );
                rejected
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::ProcessIdentityMismatch);
            }

            Ok(Self::initial_suspended(
                process,
                primary_thread,
                actual_process_id,
                actual_thread_id,
                gate_layout,
                system_ntdll,
                Some(prepared_lpac),
            ))
        }

        fn create_inner(
            artifact: &VerifiedHelper,
            provisioning: &PreparedKeyAgentProvisioning,
            pipes: &PrivateKeyAgentPipes,
            root_job: &KeyAgentRootJob,
            root_job_attribute: &KeyAgentRootJobAttribute<'_>,
            policy: DebuggeeLaunchPolicy,
            command_line: Option<&mut [u16]>,
        ) -> Result<Self, KeyAgentActivationError> {
            let DebuggeeLaunchPolicy {
                coordination_deadline,
                gate_layout,
            } = policy;
            let prepared_process = prepare_key_agent_process(artifact, provisioning)?;
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
            let (prepared_lpac, creation_security, system_ntdll) =
                prepared_process.into_security_parts();
            drop(inheritance);
            drop(flight);
            let mut created =
                Self::adopt_created_process(information, gate_layout, system_ntdll, prepared_lpac)?;
            if creation_security
                .verify_created_objects(created.process_handle(), created.primary_thread_handle())
                .is_err()
            {
                created
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::CreationSecurityPolicy);
            }
            drop(creation_security);
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

        fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
            // SAFETY: `self` uniquely owns this live primary-thread handle and
            // the returned borrow cannot outlive `self`.
            unsafe { BorrowedHandle::borrow_raw(self.primary_thread.raw().0) }
        }

        pub(super) fn is_detached_and_suspended(&self) -> bool {
            self.phase == LaunchPhase::DetachedSuspended
                && self.proven_suspend_count == 1
                && self.prepared_lpac.is_none()
                && self.pending_lpac.is_none()
                && self.lpac.is_some()
                && self.system_ntdll.is_none()
                && self.system_breakpoint_seen
                && self.debug_event_process.is_none()
                && self.debug_event_primary_thread.is_none()
        }

        fn close_remaining_detached_debug_event_handles(
            &mut self,
        ) -> Result<(), KeyAgentActivationError> {
            if self.phase != LaunchPhase::DebuggerExitedPendingVerification {
                return Err(KeyAgentActivationError::DebugDetach);
            }

            let mut first_error = None;

            // CREATE_PROCESS_DEBUG_EVENT aliases are system-managed while the
            // process is attached. Once the matching debugger OS thread is
            // joined and the kernel reports no debugger, no later exit event
            // can retire them. This host's kernel leaves the distinct aliases
            // live, so adopt and close each one exactly once before Held.
            if let Some(event_primary_thread) = self.debug_event_primary_thread {
                let mut flags = u32::MAX;
                let rejected = invalid(event_primary_thread)
                    || event_primary_thread == self.process.raw()
                    || event_primary_thread == self.primary_thread.raw()
                    // SAFETY: both handles are live until the checked close below.
                    || !unsafe {
                        CompareObjectHandles(self.primary_thread.raw(), event_primary_thread)
                    }
                    .as_bool()
                    // SAFETY: the still-live event alias is only observed here.
                    || unsafe { GetThreadId(event_primary_thread) } != self.thread_id
                    // SAFETY: flags points to exact initialized writable storage.
                    || unsafe { GetHandleInformation(event_primary_thread, &raw mut flags) }
                        .is_err()
                    || flags != 0;
                if rejected {
                    first_error.get_or_insert(KeyAgentActivationError::DebugDetach);
                } else {
                    // SAFETY: the debugger is gone and this distinct live alias
                    // was reauthenticated immediately above. Clear it only after
                    // the kernel confirms the close.
                    if unsafe { CloseHandle(event_primary_thread) }.is_ok() {
                        self.debug_event_primary_thread = None;
                    } else {
                        first_error.get_or_insert(KeyAgentActivationError::HandleAttenuation);
                    }
                }
            }

            if let Some(event_process) = self.debug_event_process {
                let mut flags = u32::MAX;
                let rejected = invalid(event_process)
                    || event_process == self.process.raw()
                    || event_process == self.primary_thread.raw()
                    // SAFETY: both handles are live until the checked close below.
                    || !unsafe { CompareObjectHandles(self.process.raw(), event_process) }.as_bool()
                    // SAFETY: the still-live event alias is only observed here.
                    || unsafe { GetProcessId(event_process) } != self.process_id
                    // SAFETY: flags points to exact initialized writable storage.
                    || unsafe { GetHandleInformation(event_process, &raw mut flags) }.is_err()
                    || flags != 0;
                if rejected {
                    first_error.get_or_insert(KeyAgentActivationError::DebugDetach);
                } else {
                    // SAFETY: same post-detach adoption and authentication
                    // argument as the thread alias above.
                    if unsafe { CloseHandle(event_process) }.is_ok() {
                        self.debug_event_process = None;
                    } else {
                        first_error.get_or_insert(KeyAgentActivationError::HandleAttenuation);
                    }
                }
            }

            first_error.map_or(Ok(()), Err)
        }

        fn close_detached_debug_event_handles(&mut self) -> Result<(), KeyAgentActivationError> {
            if self.phase != LaunchPhase::DebuggerExitedPendingVerification
                || self.debug_event_process.is_none()
                || self.debug_event_primary_thread.is_none()
                || self.debug_event_process == self.debug_event_primary_thread
            {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            #[cfg(test)]
            let observation = TestDebugEventHandleObservation::new(
                self.debug_event_process
                    .ok_or(KeyAgentActivationError::DebugDetach)?
                    .0 as usize,
                self.debug_event_primary_thread
                    .ok_or(KeyAgentActivationError::DebugDetach)?
                    .0 as usize,
            );
            self.close_remaining_detached_debug_event_handles()?;
            #[cfg(test)]
            if !observation.aliases_are_closed() {
                return Err(KeyAgentActivationError::HandleAttenuation);
            }
            Ok(())
        }

        fn attenuate_for_held(
            mut self,
            root_job: &KeyAgentRootJob,
        ) -> Result<DetachedSuspendedDebuggee, KeyAgentActivationError> {
            let attenuation = (|| {
                if !self.is_detached_and_suspended() || self.pending_event.is_some() {
                    return Err(KeyAgentActivationError::HandleAttenuation);
                }

                let resident_process = duplicate_resident_process_handle(self.process.raw())?;
                let post_detach_thread_probe =
                    duplicate_post_detach_thread_probe_handle(self.primary_thread.raw())?;
                let storage_startup_thread =
                    duplicate_storage_startup_thread_handle(self.primary_thread.raw())?;
                let resident_process_handle = windows_handle(resident_process.as_handle());

                // SAFETY: the duplicate is a live process handle with query-limited
                // access and this call only observes its stable process identity.
                let resident_process_id = unsafe { GetProcessId(resident_process_handle) };
                // SAFETY: the same live query+synchronize handle is observed with
                // a zero timeout, which cannot mutate process state.
                let resident_wait = unsafe { WaitForSingleObject(resident_process_handle, 0) };
                if resident_process_id == 0
                    || resident_process_id != self.process_id
                    || resident_wait != WAIT_TIMEOUT
                {
                    return Err(KeyAgentActivationError::HandleAttenuation);
                }

                let post_detach_thread_probe_raw =
                    windows_handle(post_detach_thread_probe.as_handle());
                // SAFETY: CompareObjectHandles already proved this exact narrow
                // probe aliases the suspended primary thread. A 1→2→1 probe
                // proves THREAD_SUSPEND_RESUME works without entering user code;
                // the separate retained handle has resume-only authority.
                let previous_suspend_count = unsafe { SuspendThread(post_detach_thread_probe_raw) };
                if previous_suspend_count != 1 {
                    return Err(KeyAgentActivationError::HandleAttenuation);
                }
                // SAFETY: the immediately preceding probe raised the exact
                // primary thread count to two; this restores it to one.
                let previous_suspend_count = unsafe { ResumeThread(post_detach_thread_probe_raw) };
                if previous_suspend_count != 2 {
                    return Err(KeyAgentActivationError::HandleAttenuation);
                }

                #[cfg(test)]
                {
                    // On the tested Windows kernel, a zero-option 0x2 request is
                    // reported as effective 0x1002. Pin that host evidence
                    // independently from both production constants.
                    let (probe_access, probe_attributes) =
                        query_handle_authority_for_test(post_detach_thread_probe_raw)?;
                    if probe_access != 0x0000_1002 || probe_attributes != 0 {
                        return Err(KeyAgentActivationError::HandleAttenuation);
                    }
                }

                self.lpac
                    .as_ref()
                    .ok_or(KeyAgentActivationError::LpacPolicy)?
                    .revalidate_current_process_token(resident_process.as_handle())
                    .map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
                super::verify_bound_root_process(root_job, resident_process.as_handle())
                    .map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
                Ok((
                    resident_process,
                    resident_process_id,
                    post_detach_thread_probe,
                    storage_startup_thread,
                ))
            })();
            let (
                resident_process,
                resident_process_id,
                post_detach_thread_probe,
                storage_startup_thread,
            ) = match attenuation {
                Ok(attenuation) => attenuation,
                Err(error) => {
                    self.abort().map_err(|_| KeyAgentActivationError::Cleanup)?;
                    return Err(error);
                }
            };

            if close_owned_handle_checked(post_detach_thread_probe).is_err() {
                self.abort().map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::HandleAttenuation);
            }

            let Some(lpac) = self.lpac.take() else {
                self.abort().map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::LpacPolicy);
            };
            let mut resident = ResidentKeyAgentProcess {
                process: resident_process,
                process_id: resident_process_id,
                lpac,
                cleanup_complete: false,
                _not_sync: PhantomData,
            };

            // All narrow-handle preparation succeeded. Close the creator thread
            // first, then the creator process, checking both kernel results. A
            // close failure synchronously rejects through the already-proven
            // narrow process rather than returning a partially attenuated value.
            let creator_thread_close = self.primary_thread.close_checked();
            let creator_process_close = self.process.close_checked();
            if creator_thread_close.is_err() || creator_process_close.is_err() {
                resident
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::HandleAttenuation);
            }
            self.phase = LaunchPhase::Aborted;
            self.proven_suspend_count = 0;
            drop(self);
            Ok(DetachedSuspendedDebuggee {
                resident,
                primary_thread: storage_startup_thread,
            })
        }

        fn authenticate_create_event_handles(
            &self,
            event_process: HANDLE,
            event_primary_thread: HANDLE,
            event_file: HANDLE,
            debug_event_cleanup: &KeyAgentDebugEventCleanup,
        ) -> Result<OwnedWinHandle, KeyAgentActivationError> {
            let creator_process = self.process.raw();
            let creator_thread = self.primary_thread.raw();
            let safe_event_process = (!invalid(event_process)
                && event_process != creator_process
                && event_process != creator_thread)
                .then_some(event_process.0 as usize);
            let mut safe_event_primary_thread = (!invalid(event_primary_thread)
                && event_primary_thread != creator_process
                && event_primary_thread != creator_thread)
                .then_some(event_primary_thread.0 as usize);
            // A malformed event can repeat one numeric handle in both fields.
            // Register it at most once so post-join cleanup cannot double-close.
            if safe_event_process == safe_event_primary_thread {
                safe_event_primary_thread = None;
            }
            let event_aliases = DetachedDebugEventHandleSet {
                process: safe_event_process,
                primary_thread: safe_event_primary_thread,
                rejected_thread: None,
                process_id: self.process_id,
                thread_id: self.thread_id,
                rejected_thread_id: None,
            };
            let event_file = if !invalid(event_file)
                && event_file != creator_process
                && event_file != creator_thread
                && event_file != event_process
                && event_file != event_primary_thread
            {
                OwnedWinHandle::new(event_file)
            } else {
                None
            };
            if event_aliases.is_registerable() {
                // Register every independently safe event alias before hFile or
                // any other fallible authentication. They remain system-managed
                // while attached, but this shared owner survives all later worker
                // errors and unwinds and closes them only after the exact join.
                debug_event_cleanup.register_while_attached(event_aliases)?;
            }
            if invalid(event_process)
                || invalid(event_primary_thread)
                || event_process == creator_process
                || event_process == creator_thread
                || event_primary_thread == creator_process
                || event_primary_thread == creator_thread
                || event_process == event_primary_thread
            {
                return Err(KeyAgentActivationError::ProcessIdentityMismatch);
            }
            let event_file = event_file.ok_or(KeyAgentActivationError::MissingMappedImage)?;
            // SAFETY: the debug event supplies live process/thread aliases that
            // remain system-managed until this debugger relationship ends.
            let event_process_id = unsafe { GetProcessId(event_process) };
            // SAFETY: same event-handle ownership argument.
            let event_thread_id = unsafe { GetThreadId(event_primary_thread) };
            if event_process_id != self.process_id || event_thread_id != self.thread_id {
                return Err(KeyAgentActivationError::ProcessIdentityMismatch);
            }
            // SAFETY: the creator and event process handles are simultaneously
            // live and this comparison only observes their kernel objects.
            let same_process = unsafe { CompareObjectHandles(creator_process, event_process) };
            // SAFETY: the creator and event thread handles are simultaneously
            // live and this comparison only observes their kernel objects.
            let same_thread = unsafe { CompareObjectHandles(creator_thread, event_primary_thread) };
            if !same_process.as_bool() || !same_thread.as_bool() {
                return Err(KeyAgentActivationError::ProcessIdentityMismatch);
            }
            Ok(event_file)
        }

        fn adopt_loader_event_file(
            &self,
            handle: HANDLE,
        ) -> Result<Option<OwnedWinHandle>, KeyAgentActivationError> {
            if handle == HANDLE::default() {
                return Ok(None);
            }
            if invalid(handle)
                || handle == self.process.raw()
                || handle == self.primary_thread.raw()
                || self.debug_event_process == Some(handle)
                || self.debug_event_primary_thread == Some(handle)
                || self
                    .system_ntdll
                    .as_ref()
                    .is_some_and(|pinned| pinned.handle.raw() == handle)
            {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            OwnedWinHandle::new(handle)
                .map(Some)
                .ok_or(KeyAgentActivationError::UnexpectedDebugEvent)
        }

        fn register_rejected_create_thread_event_handle(
            &self,
            event: &DEBUG_EVENT,
            debug_event_cleanup: &KeyAgentDebugEventCleanup,
        ) -> Result<(), KeyAgentActivationError> {
            if event.dwDebugEventCode != CREATE_THREAD_DEBUG_EVENT
                || event.dwProcessId != self.process_id
                || event.dwThreadId == 0
                || event.dwThreadId == self.thread_id
            {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            // SAFETY: the caller and guard above matched the event discriminant.
            let event_thread = unsafe { event.u.CreateThread.hThread };
            if invalid(event_thread)
                || event_thread == self.process.raw()
                || event_thread == self.primary_thread.raw()
                || self.debug_event_process == Some(event_thread)
                || self.debug_event_primary_thread == Some(event_thread)
                || self
                    .system_ntdll
                    .as_ref()
                    .is_some_and(|pinned| pinned.handle.raw() == event_thread)
            {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }

            // Register the independently safe numeric alias before any later
            // fallible identity check. Windows manages it while the debug event
            // is attached; the shared owner survives every error and closes it
            // only after the exact debugger OS thread has joined.
            debug_event_cleanup.register_rejected_thread_while_attached(
                self.process_id,
                self.thread_id,
                event.dwThreadId,
                event_thread.0 as usize,
            )?;

            let mut flags = u32::MAX;
            // SAFETY: the registered event alias remains live while attached.
            let observed_thread_id = unsafe { GetThreadId(event_thread) };
            // SAFETY: same event-alias lifetime argument.
            let observed_process_id = unsafe { GetProcessIdOfThread(event_thread) };
            // SAFETY: flags is exact initialized writable storage.
            let flags_result = unsafe { GetHandleInformation(event_thread, &raw mut flags) };
            if observed_thread_id != event.dwThreadId
                || observed_process_id != self.process_id
                || flags_result.is_err()
                || flags != 0
            {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            Ok(())
        }

        fn continue_pending_event(
            &mut self,
            expected: PendingDebugEventKind,
        ) -> Result<(), KeyAgentActivationError> {
            let pending = self
                .pending_event
                .filter(|pending| pending.kind == expected)
                .ok_or(KeyAgentActivationError::DebugDetach)?;
            // SAFETY: these identifiers came from the exact event still held by
            // this dedicated debugger thread.
            unsafe { ContinueDebugEvent(pending.process_id, pending.thread_id, DBG_CONTINUE) }
                .map_err(|_| KeyAgentActivationError::DebugDetach)?;
            self.pending_event = None;
            Ok(())
        }

        fn authenticate_load_dll_event(
            &mut self,
            event: &DEBUG_EVENT,
        ) -> Result<(), KeyAgentActivationError> {
            // SAFETY: the caller matched the event discriminant.
            let load = unsafe { event.u.LoadDll };
            let Some(mut event_file) = self.adopt_loader_event_file(load.hFile)? else {
                return Ok(());
            };
            let proof = (|| {
                let identity = exact_file_identity(event_file.raw())?;
                let Some(pinned) = self.system_ntdll.as_ref() else {
                    return Ok(());
                };
                if identity != pinned.identity {
                    return Ok(());
                }
                if self.loaded_system_ntdll_base.is_some()
                    || exact_file_identity(pinned.handle.raw())? != pinned.identity
                {
                    return Err(KeyAgentActivationError::CooperativeGatePolicy);
                }
                let base = load.lpBaseOfDll.addr();
                let end = base
                    .checked_add(1)
                    .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
                let _ = query_remote_image_page(self.process.raw(), base, base, end, false)?;
                if Some(base) == self.main_image_base {
                    return Err(KeyAgentActivationError::CooperativeGatePolicy);
                }
                self.loaded_system_ntdll_base = Some(base);
                Ok(())
            })();
            let close = event_file.close_checked();
            proof?;
            close
        }

        fn authenticate_system_breakpoint(
            &mut self,
            event: &DEBUG_EVENT,
        ) -> Result<(), KeyAgentActivationError> {
            if self.system_breakpoint_seen {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            // SAFETY: the caller matched the exception-event discriminant.
            let exception = unsafe { event.u.Exception };
            let record = exception.ExceptionRecord;
            let address = record.ExceptionAddress.addr();
            let allocation_base = self
                .loaded_system_ntdll_base
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            let end = address
                .checked_add(1)
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            if exception.dwFirstChance != 1 || record.ExceptionCode != EXCEPTION_BREAKPOINT {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            let _ =
                query_remote_image_page(self.process.raw(), address, allocation_base, end, true)?;
            if read_remote_exact::<1>(self.process.raw(), address)? != [0xCC] {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }
            let context = primary_thread_context(self.primary_thread.raw())?;
            let expected_rip =
                u64::try_from(end).map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
            if context.0.Rip != expected_rip {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }
            let pinned = self
                .system_ntdll
                .as_mut()
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            if exact_file_identity(pinned.handle.raw())? != pinned.identity {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }
            pinned.handle.close_checked()?;
            self.system_ntdll = None;
            self.system_breakpoint_seen = true;
            Ok(())
        }

        fn authenticate_cooperative_gate(
            &mut self,
            event: &DEBUG_EVENT,
        ) -> Result<(), KeyAgentActivationError> {
            if !self.system_breakpoint_seen
                || self.system_ntdll.is_some()
                || self.loaded_system_ntdll_base.is_none()
            {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }
            // SAFETY: the caller matched the exception-event discriminant.
            let exception = unsafe { event.u.Exception };
            let record = exception.ExceptionRecord;
            let image_base = self
                .main_image_base
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            let sequence_address = image_base
                .checked_add(
                    usize::try_from(self.gate_layout.sequence_rva)
                        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?,
                )
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            let breakpoint_address = image_base
                .checked_add(
                    usize::try_from(self.gate_layout.breakpoint_rva)
                        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?,
                )
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            let sequence_end = sequence_address
                .checked_add(KEY_AGENT_DEFAULT_DACL_GATE_BYTES)
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            let image_end = image_base
                .checked_add(
                    usize::try_from(self.gate_layout.size_of_image)
                        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?,
                )
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            if exception.dwFirstChance != 1
                || record.ExceptionCode != EXCEPTION_BREAKPOINT
                || record.ExceptionAddress.addr() != breakpoint_address
                || sequence_end > image_end
                || breakpoint_address
                    .checked_add(1)
                    .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?
                    != sequence_end
            {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            let _ = query_remote_image_page(
                self.process.raw(),
                sequence_address,
                image_base,
                sequence_end,
                true,
            )?;
            let expected = super::default_dacl_gate_sequence(
                crate::key_agent_child_bootstrap::KEY_AGENT_DEFAULT_DACL_GATE_MARKER,
            );
            if read_remote_exact::<KEY_AGENT_DEFAULT_DACL_GATE_BYTES>(
                self.process.raw(),
                sequence_address,
            )? != expected
            {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }

            let before = primary_thread_context(self.primary_thread.raw())?;
            let expected_rip = u64::try_from(sequence_end)
                .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
            if before.0.Rip != expected_rip
                || before.0.R10
                    != crate::key_agent_child_bootstrap::KEY_AGENT_DEFAULT_DACL_GATE_MARKER
            {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }
            let mut cleared = before;
            cleared.0.R10 = 0;
            // SAFETY: the event still stops this exact primary thread. The
            // context was captured in this event and differs only in R10.
            unsafe { SetThreadContext(self.primary_thread.raw(), &raw const cleared.0) }
                .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?;
            let after = primary_thread_context(self.primary_thread.raw())?;
            if !context_matches_after_r10_clear(&before.0, &after.0) {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }

            // SAFETY: the debug event supplies the process-wide stop while this
            // exact creator handle adds one explicit, independently retained
            // suspend count. No CREATE_THREAD event was admitted before here.
            let previous_suspend_count = unsafe { SuspendThread(self.primary_thread.raw()) };
            if previous_suspend_count != 0 {
                return Err(KeyAgentActivationError::SuspensionMismatch);
            }
            self.proven_suspend_count = 1;

            let pending_lpac = self
                .pending_lpac
                .take()
                .ok_or(KeyAgentActivationError::LpacPolicy)?;
            let verified_lpac = pending_lpac
                .finalize_after_gate(self.process_handle())
                .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
            self.lpac = Some(verified_lpac);
            Ok(())
        }

        pub(super) fn authenticate_first_event(
            &mut self,
            expected_artifact: ExactFileObjectIdentity,
            timeout_milliseconds: u32,
            debug_event_cleanup: &KeyAgentDebugEventCleanup,
        ) -> Result<AuthenticatedFirstEvent, KeyAgentActivationError> {
            if self.phase != LaunchPhase::AwaitingCreateEvent
                || timeout_milliseconds == 0
                || self.prepared_lpac.is_none()
                || self.pending_lpac.is_some()
                || self.lpac.is_some()
                || self.main_image_base.is_some()
                || self.system_ntdll.is_none()
                || self.loaded_system_ntdll_base.is_some()
                || self.system_breakpoint_seen
                || self.debug_event_process.is_some()
                || self.debug_event_primary_thread.is_some()
            {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(u64::from(timeout_milliseconds)))
                .ok_or(KeyAgentActivationError::DebugEventTimeout)?;
            let event = wait_for_debug_event_until(deadline)?;
            if event.dwProcessId != self.process_id || event.dwThreadId != self.thread_id {
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            self.pending_event = Some(PendingDebugEvent {
                process_id: event.dwProcessId,
                thread_id: event.dwThreadId,
                kind: if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
                    PendingDebugEventKind::CreateProcess
                } else {
                    PendingDebugEventKind::Loader
                },
            });
            if event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT {
                if event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT {
                    // SAFETY: the discriminant was checked immediately above.
                    let load_dll = unsafe { event.u.LoadDll };
                    if let Some(mut file) = self.adopt_loader_event_file(load_dll.hFile)? {
                        file.close_checked()?;
                    }
                }
                return Err(KeyAgentActivationError::UnexpectedDebugEvent);
            }
            self.phase = self
                .phase
                .transition(LaunchTransition::ReceiveCreateEvent)?;
            // SAFETY: the discriminant was checked immediately above.
            let create = unsafe { event.u.CreateProcessInfo };
            let mut event_file = self.authenticate_create_event_handles(
                create.hProcess,
                create.hThread,
                create.hFile,
                debug_event_cleanup,
            )?;
            let mapped_identity = exact_file_identity(event_file.raw())?;
            if mapped_identity != expected_artifact {
                return Err(KeyAgentActivationError::MappedImageMismatch);
            }
            let image_base = create.lpBaseOfImage.addr();
            let image_end = image_base
                .checked_add(
                    usize::try_from(self.gate_layout.size_of_image)
                        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?,
                )
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            let breakpoint = image_base
                .checked_add(
                    usize::try_from(self.gate_layout.breakpoint_rva)
                        .map_err(|_| KeyAgentActivationError::CooperativeGatePolicy)?,
                )
                .ok_or(KeyAgentActivationError::CooperativeGatePolicy)?;
            if image_base == 0 || breakpoint >= image_end {
                return Err(KeyAgentActivationError::CooperativeGatePolicy);
            }
            self.main_image_base = Some(image_base);

            // The event hFile can carry broader rights than the retained
            // artifact. Checked-close it before this event can be continued.
            event_file.close_checked()?;
            let creation_time = process_creation_time(self.process.raw())?;
            let prepared_lpac = self
                .prepared_lpac
                .take()
                .ok_or(KeyAgentActivationError::LpacPolicy)?;
            let pending_lpac = prepared_lpac
                .prepare_suspended_process_for_gate(self.process_handle())
                .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
            self.pending_lpac = Some(pending_lpac);

            Ok(AuthenticatedFirstEvent {
                creation_time,
                deadline,
            })
        }

        pub(super) fn continue_to_cooperative_gate(
            &mut self,
            deadline: Instant,
            debug_event_cleanup: &KeyAgentDebugEventCleanup,
        ) -> Result<(), KeyAgentActivationError> {
            if self.phase != LaunchPhase::CreateEventHeld
                || self.proven_suspend_count != 0
                || self.prepared_lpac.is_some()
                || self.pending_lpac.is_none()
                || self.lpac.is_some()
                || self.main_image_base.is_none()
                || self.system_ntdll.is_none()
                || self.system_breakpoint_seen
            {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            self.continue_pending_event(PendingDebugEventKind::CreateProcess)?;
            self.phase = self
                .phase
                .transition(LaunchTransition::ContinueCreateEvent)?;

            let mut load_dll_events = 0_usize;
            for _ in 0..MAX_PRE_GATE_DEBUG_EVENTS {
                let event = wait_for_debug_event_until(deadline)?;
                if event.dwProcessId != self.process_id {
                    return Err(KeyAgentActivationError::UnexpectedDebugEvent);
                }
                self.pending_event = Some(PendingDebugEvent {
                    process_id: event.dwProcessId,
                    thread_id: event.dwThreadId,
                    kind: PendingDebugEventKind::Loader,
                });
                if event.dwThreadId != self.thread_id {
                    match event.dwDebugEventCode {
                        CREATE_THREAD_DEBUG_EVENT => self
                            .register_rejected_create_thread_event_handle(
                                &event,
                                debug_event_cleanup,
                            )?,
                        LOAD_DLL_DEBUG_EVENT => {
                            // SAFETY: the discriminant was checked immediately above.
                            let load = unsafe { event.u.LoadDll };
                            if let Some(mut file) = self.adopt_loader_event_file(load.hFile)? {
                                file.close_checked()?;
                            }
                        }
                        _ => {}
                    }
                    return Err(KeyAgentActivationError::UnexpectedDebugEvent);
                }
                match event.dwDebugEventCode {
                    LOAD_DLL_DEBUG_EVENT => {
                        load_dll_events = load_dll_events
                            .checked_add(1)
                            .filter(|count| *count <= MAX_LOADER_DEBUG_EVENTS)
                            .ok_or(KeyAgentActivationError::UnexpectedDebugEvent)?;
                        self.authenticate_load_dll_event(&event)?;
                        self.continue_pending_event(PendingDebugEventKind::Loader)?;
                    }
                    EXCEPTION_DEBUG_EVENT => {
                        if !self.system_breakpoint_seen {
                            self.authenticate_system_breakpoint(&event)?;
                            self.continue_pending_event(PendingDebugEventKind::Loader)?;
                            continue;
                        }
                        self.pending_event = Some(PendingDebugEvent {
                            process_id: event.dwProcessId,
                            thread_id: event.dwThreadId,
                            kind: PendingDebugEventKind::CooperativeGate,
                        });
                        self.phase = self
                            .phase
                            .transition(LaunchTransition::ReceiveCooperativeGate)?;
                        self.authenticate_cooperative_gate(&event)?;
                        self.continue_pending_event(PendingDebugEventKind::CooperativeGate)?;
                        self.phase = self
                            .phase
                            .transition(LaunchTransition::ContinueCooperativeGate)?;
                        return Ok(());
                    }
                    CREATE_THREAD_DEBUG_EVENT
                    | EXIT_THREAD_DEBUG_EVENT
                    | EXIT_PROCESS_DEBUG_EVENT
                    | OUTPUT_DEBUG_STRING_EVENT
                    | RIP_EVENT
                    | CREATE_PROCESS_DEBUG_EVENT => {
                        return Err(KeyAgentActivationError::UnexpectedDebugEvent);
                    }
                    _ => return Err(KeyAgentActivationError::UnexpectedDebugEvent),
                }
            }
            Err(KeyAgentActivationError::UnexpectedDebugEvent)
        }

        pub(super) fn revalidate_before_no_kill(&self) -> Result<(), KeyAgentActivationError> {
            if self.phase != LaunchPhase::GateEventContinued
                || self.pending_event.is_some()
                || self.proven_suspend_count != 1
                || self.prepared_lpac.is_some()
                || self.pending_lpac.is_some()
                || self.lpac.is_none()
                || self.system_ntdll.is_some()
                || !self.system_breakpoint_seen
                || self.debug_event_process.is_some()
                || self.debug_event_primary_thread.is_some()
            {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            // SAFETY: a zero-time wait observes only the retained creator
            // process handle. The explicit primary-thread count must still hold
            // a live process before debugger-exit detachment is armed.
            if unsafe { WaitForSingleObject(self.process.raw(), 0) } != WAIT_TIMEOUT {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            let mut debugger_present = BOOL::default();
            // SAFETY: the creator process handle remains live and the BOOL is
            // exact writable storage. This worker owns the debug relationship.
            unsafe { CheckRemoteDebuggerPresent(self.process.raw(), &raw mut debugger_present) }
                .map_err(|_| KeyAgentActivationError::DebugDetach)?;
            if !debugger_present.as_bool() {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            self.lpac
                .as_ref()
                .ok_or(KeyAgentActivationError::LpacPolicy)?
                .revalidate_current_process_token(self.process_handle())
                .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
            Ok(())
        }

        pub(super) fn arm_no_kill(
            mut self,
            debug_event_cleanup: &KeyAgentDebugEventCleanup,
        ) -> Result<PendingDebuggerExitSuspendedDebuggee, KeyAgentActivationError> {
            self.revalidate_before_no_kill()?;
            debug_event_cleanup
                .verify_registered_while_attached(self.process_id, self.thread_id)?;
            // SAFETY: this is the dedicated debugger thread that created the
            // exact process. Its sole event was continued, and an explicit
            // suspend count still prevents user-mode entry. Microsoft documents
            // FALSE as detaching this thread's debuggees when the thread exits.
            if unsafe { DebugSetProcessKillOnExit(false) }.is_err() {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            // From this successful arm to the returned pending value there are
            // no fallible calls: only an exact phase write and ownership move.
            self.phase = LaunchPhase::NoKillArmedAwaitingDebuggerExit;
            Ok(PendingDebuggerExitSuspendedDebuggee(self))
        }

        pub(super) fn abort(&mut self) -> Result<(), KeyAgentActivationError> {
            if self.phase == LaunchPhase::Aborted {
                return Ok(());
            }
            let debugger_thread_has_exited = matches!(
                self.phase,
                LaunchPhase::DebuggerExitedPendingVerification
                    | LaunchPhase::DetachedSuspended
                    | LaunchPhase::DetachedRunning
            );
            // SAFETY: this is the exact still-owned process. Termination is
            // requested before a pending event is ever continued, so rejection
            // cannot release the process into user-mode code.
            let termination_requested =
                unsafe { TerminateProcess(self.process.raw(), REJECTED_PROCESS_EXIT_CODE) }.is_ok();
            let termination_accepted = if termination_requested {
                true
            } else {
                // SAFETY: a zero-time wait only observes the exact owned process.
                (unsafe { WaitForSingleObject(self.process.raw(), 0) }) == WAIT_OBJECT_0
            };
            if let Some(pending) = self.pending_event {
                if !termination_accepted {
                    // Keeping the debug event pending is safer than continuing
                    // when Windows did not accept termination.
                    return Err(KeyAgentActivationError::Cleanup);
                }
                // SAFETY: these identifiers name the pending event owned by this
                // creator thread. Termination was accepted (or the process was
                // already signaled) before this event is continued, so user
                // code cannot be released by this call.
                unsafe { ContinueDebugEvent(pending.process_id, pending.thread_id, DBG_CONTINUE) }
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                self.pending_event = None;
            }
            if !debugger_thread_has_exited {
                if !termination_accepted {
                    return Err(KeyAgentActivationError::Cleanup);
                }
                // Waiting here would deadlock progress: a live debugger thread
                // must return before Windows can apply either default
                // kill-on-exit or the successfully armed no-kill detach. The
                // per-run root Job gate likewise avoids waiting until this exact
                // OS thread has joined. TerminateProcess above fixes the desired
                // exit code; join-time retained-handle tests verify the result.
                self.phase = LaunchPhase::Aborted;
                return Ok(());
            }

            // Once the debugger thread has exited, process cleanup and adopted
            // event-alias closure are independent obligations. Attempt both so
            // a wait/exit-code failure cannot starve high-authority alias close.
            let process_cleanup = (|| {
                if !termination_accepted {
                    return Err(KeyAgentActivationError::Cleanup);
                }
                // SAFETY: process is a live owned handle and the wait is finite.
                let wait = unsafe {
                    WaitForSingleObject(self.process.raw(), CLEANUP_TIMEOUT_MILLISECONDS)
                };
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
                Ok(exit_code)
            })();
            let alias_cleanup = if self.phase == LaunchPhase::DebuggerExitedPendingVerification {
                self.close_remaining_detached_debug_event_handles()
                    .map_err(|_| KeyAgentActivationError::Cleanup)
            } else if self.debug_event_process.is_some()
                || self.debug_event_primary_thread.is_some()
            {
                Err(KeyAgentActivationError::Cleanup)
            } else {
                Ok(())
            };
            let (Ok(exit_code), Ok(())) = (process_cleanup, alias_cleanup) else {
                return Err(KeyAgentActivationError::Cleanup);
            };
            if self.debug_event_process.is_some() || self.debug_event_primary_thread.is_some() {
                return Err(KeyAgentActivationError::Cleanup);
            }
            self.cleanup_exit_code = Some(exit_code);
            self.phase = LaunchPhase::Aborted;
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

    /// Transfer-only owner after documented no-kill-on-debugger-exit arming.
    ///
    /// The first event has been continued, there is no pending debug event, the
    /// exact primary thread retains one explicit count, and LPAC continuity is
    /// held. This state is not detached and exposes no handle or resume method.
    pub(super) struct PendingDebuggerExitSuspendedDebuggee(SuspendedDebuggee);

    // SAFETY: after a successful DebugSetProcessKillOnExit(FALSE), this wrapper
    // performs no debugger-thread-affine operation. It exposes only a consuming
    // post-join finalizer; its inner Drop requests termination without waiting
    // while the phase is still pending. The outer activation state separately
    // brands it to the exact per-run join witness.
    unsafe impl Send for PendingDebuggerExitSuspendedDebuggee {}

    impl PendingDebuggerExitSuspendedDebuggee {
        pub(super) fn observe_debugger_exit_for_cleanup(
            &mut self,
        ) -> Result<(), KeyAgentActivationError> {
            if self.0.phase == LaunchPhase::DebuggerExitedPendingVerification {
                return Ok(());
            }
            if self.0.phase != LaunchPhase::NoKillArmedAwaitingDebuggerExit
                || self.0.pending_event.is_some()
                || self.0.proven_suspend_count != 1
                || self.0.prepared_lpac.is_some()
                || self.0.pending_lpac.is_some()
                || self.0.lpac.is_none()
                || self.0.system_ntdll.is_some()
                || !self.0.system_breakpoint_seen
                || self.0.debug_event_process.is_some()
                || self.0.debug_event_primary_thread.is_some()
            {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            // The outer pending state has already matched its exact joined
            // witness and root gate. This phase changes cleanup behavior only;
            // it exposes no detached, handle, or resume capability.
            self.0.phase = LaunchPhase::DebuggerExitedPendingVerification;
            Ok(())
        }

        pub(super) fn adopt_detached_debug_event_handles(
            &mut self,
            handles: DetachedDebugEventHandleSet,
        ) -> Result<(), (KeyAgentActivationError, DetachedDebugEventHandleSet)> {
            let (Some(event_process), Some(event_primary_thread)) =
                (handles.process, handles.primary_thread)
            else {
                return Err((KeyAgentActivationError::DebugDetach, handles));
            };
            let event_process = HANDLE(event_process as *mut c_void);
            let event_primary_thread = HANDLE(event_primary_thread as *mut c_void);
            if self.0.phase != LaunchPhase::DebuggerExitedPendingVerification
                || self.0.debug_event_process.is_some()
                || self.0.debug_event_primary_thread.is_some()
                || handles.process_id != self.0.process_id
                || handles.thread_id != self.0.thread_id
                || handles.rejected_thread.is_some()
                || handles.rejected_thread_id.is_some()
                || invalid(event_process)
                || invalid(event_primary_thread)
                || event_process == event_primary_thread
                || event_process == self.0.process.raw()
                || event_process == self.0.primary_thread.raw()
                || event_primary_thread == self.0.process.raw()
                || event_primary_thread == self.0.primary_thread.raw()
            {
                return Err((KeyAgentActivationError::DebugDetach, handles));
            }
            // All validation is complete. These assignments are the infallible
            // ownership transfer from the joined-run cleanup registry.
            self.0.debug_event_process = Some(event_process);
            self.0.debug_event_primary_thread = Some(event_primary_thread);
            Ok(())
        }

        pub(super) fn finalize_after_debugger_exit(
            self,
            root_job: &KeyAgentRootJob,
        ) -> Result<DetachedSuspendedDebuggee, KeyAgentActivationError> {
            let mut process = self.0;
            if process.phase != LaunchPhase::DebuggerExitedPendingVerification
                || process.pending_event.is_some()
                || process.proven_suspend_count != 1
                || process.prepared_lpac.is_some()
                || process.pending_lpac.is_some()
                || process.lpac.is_none()
                || process.system_ntdll.is_some()
                || !process.system_breakpoint_seen
                || process.debug_event_process.is_none()
                || process.debug_event_primary_thread.is_none()
            {
                return Err(KeyAgentActivationError::DebugDetach);
            }
            let verification = (|| {
                let mut debugger_present = BOOL::default();
                // SAFETY: the retained creator process handle is live and BOOL
                // is exact writable storage. The dedicated debugger thread has
                // exited and its matching proof was consumed by the caller.
                unsafe {
                    CheckRemoteDebuggerPresent(process.process.raw(), &raw mut debugger_present)
                }
                .map_err(|_| KeyAgentActivationError::DebugDetach)?;
                if debugger_present.as_bool() {
                    return Err(KeyAgentActivationError::DebugDetach);
                }
                process.close_detached_debug_event_handles()?;

                // SAFETY: the exact creator primary-thread handle remains live.
                // One explicit guard count crossed debugger-thread exit; a 1→2
                // increment is the first observable post-detach proof.
                let previous_suspend_count = unsafe { SuspendThread(process.primary_thread.raw()) };
                if previous_suspend_count != 1 {
                    return Err(KeyAgentActivationError::SuspensionMismatch);
                }
                // SAFETY: the immediately preceding exact transition installed
                // count two. This restores exactly one without entering code.
                let previous_suspend_count = unsafe { ResumeThread(process.primary_thread.raw()) };
                if previous_suspend_count != 2 {
                    return Err(KeyAgentActivationError::SuspensionMismatch);
                }
                process.proven_suspend_count = 1;

                process
                    .lpac
                    .as_ref()
                    .ok_or(KeyAgentActivationError::LpacPolicy)?
                    .revalidate_current_process_token(process.process_handle())
                    .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
                super::verify_bound_root_process(root_job, process.process_handle())?;
                Ok(())
            })();

            if let Err(error) = verification {
                process
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(error);
            }
            process.phase = LaunchPhase::DetachedSuspended;
            process.attenuate_for_held(root_job)
        }
    }

    impl fmt::Debug for PendingDebuggerExitSuspendedDebuggee {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(
                "PendingDebuggerExitSuspendedDebuggee([DEBUGGER EXIT UNVERIFIED; REDACTED])",
            )
        }
    }

    /// Exact resident process capability after creator-handle attenuation.
    ///
    /// Its process handle has exactly terminate, query-limited-information, and
    /// synchronize access. The retained LPAC proof supplies token continuity;
    /// no creator-strength process or thread handle can enter this owner.
    struct ResidentKeyAgentProcess {
        process: OwnedHandle,
        process_id: u32,
        lpac: VerifiedKeyAgentLpac,
        cleanup_complete: bool,
        _not_sync: PhantomData<Cell<()>>,
    }

    // SAFETY: the debug relationship has ended before this owner is built. Its
    // exact process and retained token handles are process-wide; methods expose
    // only query, Job membership, termination/wait cleanup, and token readback.
    unsafe impl Send for ResidentKeyAgentProcess {}

    impl ResidentKeyAgentProcess {
        fn process_handle(&self) -> BorrowedHandle<'_> {
            self.process.as_handle()
        }

        fn process_raw(&self) -> HANDLE {
            windows_handle(self.process_handle())
        }

        const fn process_id(&self) -> u32 {
            self.process_id
        }

        fn revalidate(&self) -> Result<(), KeyAgentActivationError> {
            if self.cleanup_complete || self.process_id == 0 {
                return Err(KeyAgentActivationError::ResidentState);
            }
            let process = self.process_raw();
            // SAFETY: this capability owns the exact query+sync process handle;
            // this call only observes its stable process identity.
            let process_id = unsafe { GetProcessId(process) };
            // SAFETY: zero-time waiting only observes this exact live process.
            let wait = unsafe { WaitForSingleObject(process, 0) };
            if process_id != self.process_id || wait != WAIT_TIMEOUT {
                return Err(KeyAgentActivationError::ResidentState);
            }
            self.lpac
                .revalidate_current_process_token(self.process_handle())
                .map_err(|_| KeyAgentActivationError::LpacPolicy)
        }

        fn is_member_of_root_job(
            &self,
            root_job: &KeyAgentRootJob,
        ) -> Result<bool, KeyAgentActivationError> {
            root_job
                .contains_process(self.process_handle())
                .map_err(|_| KeyAgentActivationError::RootJobPolicy)
        }

        fn abort(&mut self) -> Result<(), KeyAgentActivationError> {
            if self.cleanup_complete {
                return Ok(());
            }
            let process = self.process_raw();
            // SAFETY: the exact resident process handle retains terminate access.
            let termination_requested =
                unsafe { TerminateProcess(process, REJECTED_PROCESS_EXIT_CODE) }.is_ok();
            if !termination_requested
                // SAFETY: zero-time waiting only observes this exact process.
                && unsafe { WaitForSingleObject(process, 0) } != WAIT_OBJECT_0
            {
                return Err(KeyAgentActivationError::Cleanup);
            }
            // SAFETY: the process handle retains synchronize access and the wait
            // is bounded by the fixed rejection cleanup policy.
            if unsafe { WaitForSingleObject(process, CLEANUP_TIMEOUT_MILLISECONDS) }
                != WAIT_OBJECT_0
            {
                return Err(KeyAgentActivationError::Cleanup);
            }
            let mut exit_code = 0;
            // SAFETY: query-limited-information permits reading this signaled
            // process's exit code into initialized writable storage.
            unsafe { GetExitCodeProcess(process, &raw mut exit_code) }
                .map_err(|_| KeyAgentActivationError::Cleanup)?;
            if exit_code != REJECTED_PROCESS_EXIT_CODE {
                return Err(KeyAgentActivationError::Cleanup);
            }
            self.cleanup_complete = true;
            Ok(())
        }

        #[cfg(test)]
        fn duplicate_process_observation(
            &self,
        ) -> Result<TestProcessObservation, KeyAgentActivationError> {
            TestProcessObservation::duplicate(self.process_raw())
        }

        #[cfg(test)]
        fn process_authority_for_test(&self) -> Result<(u32, u32), KeyAgentActivationError> {
            query_handle_authority_for_test(self.process_raw())
        }
    }

    impl Drop for ResidentKeyAgentProcess {
        fn drop(&mut self) {
            let _ = self.abort();
        }
    }

    /// Type-state proof that debugger exit was verified, creator-strength
    /// handles were closed, and one exact least-authority thread handle retains
    /// the sole explicit suspend count.
    pub(super) struct DetachedSuspendedDebuggee {
        resident: ResidentKeyAgentProcess,
        primary_thread: OwnedHandle,
    }

    // SAFETY: the debugger OS thread has joined before construction. The exact
    // process handle is process-wide and the sole thread operation is one
    // consuming ResumeThread call through THREAD_RESUME-only access.
    unsafe impl Send for DetachedSuspendedDebuggee {}

    impl DetachedSuspendedDebuggee {
        pub(super) const fn process_id(&self) -> u32 {
            self.resident.process_id()
        }

        pub(super) fn is_detached_and_suspended(&self) -> bool {
            !self.resident.cleanup_complete
        }

        pub(super) fn abort(&mut self) -> Result<(), KeyAgentActivationError> {
            self.resident.abort()
        }

        pub(super) fn resume_for_storage_startup(
            self,
        ) -> Result<DetachedRunningDebuggee, KeyAgentActivationError> {
            // Keep the only abstract transition check before the irreversible
            // one-shot resume and checked thread-handle close.
            LaunchPhase::DetachedSuspended.transition(LaunchTransition::ResumeStorageStartup)?;
            let Self {
                mut resident,
                primary_thread,
            } = self;
            if let Err(error) = resident.revalidate() {
                resident
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(error);
            }
            let primary_thread_raw = windows_handle(primary_thread.as_handle());
            // SAFETY: the exact detached primary-thread duplicate has only the
            // suspend/resume right and the post-detach proof established one
            // explicit count. This is its sole production operation.
            let previous_suspend_count = unsafe { ResumeThread(primary_thread_raw) };
            if previous_suspend_count != 1 {
                resident
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::SuspensionMismatch);
            }
            // No thread operation remains after the one successful resume. Close
            // the exact THREAD_RESUME handle with a checked kernel result before
            // observing or returning the running process capability.
            if close_owned_handle_checked(primary_thread).is_err() {
                resident
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::HandleAttenuation);
            }

            // SAFETY: zero-time waiting only observes the exact resident process.
            if unsafe { WaitForSingleObject(resident.process_raw(), 0) } != WAIT_TIMEOUT {
                resident
                    .abort()
                    .map_err(|_| KeyAgentActivationError::Cleanup)?;
                return Err(KeyAgentActivationError::StartupResume);
            }
            Ok(DetachedRunningDebuggee(resident))
        }

        #[cfg(test)]
        pub(super) fn duplicate_process_observation(
            &self,
        ) -> Result<TestProcessObservation, KeyAgentActivationError> {
            self.resident.duplicate_process_observation()
        }

        #[cfg(test)]
        pub(super) fn is_member_of_root_job_for_test(
            &self,
            root_job: &KeyAgentRootJob,
        ) -> Result<bool, KeyAgentActivationError> {
            self.resident.is_member_of_root_job(root_job)
        }

        #[cfg(test)]
        pub(super) fn retained_handle_authority_for_test(
            &self,
        ) -> Result<(u32, u32, u32, u32), KeyAgentActivationError> {
            let (process_access, process_attributes) =
                query_handle_authority_for_test(self.resident.process_raw())?;
            let (thread_access, thread_attributes) =
                query_handle_authority_for_test(windows_handle(self.primary_thread.as_handle()))?;
            Ok((
                process_access,
                process_attributes,
                thread_access,
                thread_attributes,
            ))
        }

        #[cfg(test)]
        pub(super) fn resume_only_thread_rejects_suspend_for_test(&self) -> bool {
            // SAFETY: establishes an unambiguous sentinel for the immediately
            // following negative access check.
            unsafe { SetLastError(ERROR_SUCCESS) };
            // SAFETY: this negative kernel probe uses the exact retained thread
            // handle and succeeds only when the forbidden operation is denied
            // without changing the one proven suspend count.
            (unsafe { SuspendThread(windows_handle(self.primary_thread.as_handle())) }) == u32::MAX
                // SAFETY: read immediately after the failed Win32 operation.
                && (unsafe { GetLastError() }) == ERROR_ACCESS_DENIED
        }
    }

    impl fmt::Debug for DetachedSuspendedDebuggee {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("DetachedSuspendedDebuggee([NARROW PROCESS + RESUME-ONLY THREAD])")
        }
    }

    /// Type-state proof that the primary thread was resumed exactly once and
    /// its sole `THREAD_RESUME` handle was closed. Only the narrow resident
    /// process capability and retained token continuity remain.
    pub(super) struct DetachedRunningDebuggee(ResidentKeyAgentProcess);

    // SAFETY: no thread or debugger handle remains. The resident process owner
    // is explicitly Send and exposes only process-wide operations.
    unsafe impl Send for DetachedRunningDebuggee {}

    impl DetachedRunningDebuggee {
        pub(super) const fn process_id(&self) -> u32 {
            self.0.process_id()
        }

        pub(super) fn is_detached_and_running(&self) -> bool {
            !self.0.cleanup_complete
        }

        pub(super) fn revalidate_resident_process(&self) -> Result<(), KeyAgentActivationError> {
            self.0.revalidate()
        }

        pub(super) fn is_member_of_root_job(
            &self,
            root_job: &KeyAgentRootJob,
        ) -> Result<bool, KeyAgentActivationError> {
            self.0.is_member_of_root_job(root_job)
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
            self.is_member_of_root_job(root_job)
        }

        #[cfg(test)]
        pub(super) fn retained_process_authority_for_test(
            &self,
        ) -> Result<(u32, u32), KeyAgentActivationError> {
            self.0.process_authority_for_test()
        }
    }

    impl fmt::Debug for DetachedRunningDebuggee {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("DetachedRunningDebuggee([NARROW PROCESS; NO THREAD HANDLE])")
        }
    }

    #[cfg(test)]
    pub(super) struct TestDebugEventHandleObservation {
        process: usize,
        primary_thread: usize,
    }

    #[cfg(test)]
    impl TestDebugEventHandleObservation {
        pub(super) const fn new(process: usize, primary_thread: usize) -> Self {
            Self {
                process,
                primary_thread,
            }
        }

        pub(super) fn aliases_are_closed(&self) -> bool {
            for raw in [self.primary_thread, self.process] {
                let handle = HANDLE(raw as *mut c_void);
                let mut flags = u32::MAX;
                // SAFETY: this is a test-only post-join probe of the registered
                // numeric handle values; it never adopts or closes them.
                if unsafe { GetHandleInformation(handle, &raw mut flags) }.is_ok()
                    // SAFETY: read immediately after the failed Win32 probe.
                    || unsafe { GetLastError() } != ERROR_INVALID_HANDLE
                {
                    return false;
                }
            }
            true
        }
    }

    #[cfg(test)]
    pub(super) struct TestRejectedThreadEventHandleObservation {
        thread: usize,
    }

    #[cfg(test)]
    impl TestRejectedThreadEventHandleObservation {
        pub(super) const fn new(thread: usize) -> Self {
            Self { thread }
        }

        pub(super) fn alias_is_closed(&self) -> bool {
            let handle = HANDLE(self.thread as *mut c_void);
            let mut flags = u32::MAX;
            // SAFETY: this is a test-only post-join probe of the registered
            // numeric handle value; it never adopts or closes the handle.
            unsafe { GetHandleInformation(handle, &raw mut flags) }.is_err()
                // SAFETY: read immediately after the failed Win32 probe.
                && unsafe { GetLastError() } == ERROR_INVALID_HANDLE
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

        pub(super) fn terminate_for_resident_revalidation_test(
            &self,
        ) -> Result<(), KeyAgentActivationError> {
            let handle = HANDLE(self.0.as_raw_handle());
            // SAFETY: this test-only capability owns a duplicate of the exact
            // process handle and waits for that same object before returning.
            unsafe { TerminateProcess(handle, REJECTED_PROCESS_EXIT_CODE) }
                .map_err(|_| KeyAgentActivationError::Cleanup)?;
            // SAFETY: the duplicate remains live for this bounded wait on the
            // exact process just terminated above.
            if unsafe { WaitForSingleObject(handle, CLEANUP_TIMEOUT_MILLISECONDS) } != WAIT_OBJECT_0
            {
                return Err(KeyAgentActivationError::Cleanup);
            }
            Ok(())
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
        pub(super) deadline: Instant,
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

    pub(super) fn close_detached_debug_event_handles_after_join(
        handles: &mut DetachedDebugEventHandleSet,
    ) -> Result<(), KeyAgentActivationError> {
        if handles.process_id == 0
            || handles.thread_id == 0
            || matches!(
                (handles.process, handles.primary_thread),
                (Some(process), Some(thread)) if process == thread
            )
        {
            return Err(KeyAgentActivationError::Cleanup);
        }

        let mut failed = false;

        match (handles.rejected_thread, handles.rejected_thread_id) {
            (Some(rejected_thread), Some(rejected_thread_id)) => {
                let rejected_thread = HANDLE(rejected_thread as *mut c_void);
                let mut flags = u32::MAX;
                let rejected = invalid(rejected_thread)
                    || handles.process == Some(rejected_thread.0 as usize)
                    || handles.primary_thread == Some(rejected_thread.0 as usize)
                    || rejected_thread_id == handles.thread_id
                    // SAFETY: the caller joined the exact debugger thread; this
                    // registered CREATE_THREAD alias remains live until close.
                    || unsafe { GetThreadId(rejected_thread) } != rejected_thread_id
                    // SAFETY: same joined event-alias lifetime argument.
                    || unsafe { GetProcessIdOfThread(rejected_thread) } != handles.process_id
                    // SAFETY: flags is exact initialized writable storage.
                    || unsafe { GetHandleInformation(rejected_thread, &raw mut flags) }.is_err()
                    || flags != 0;
                if rejected {
                    failed = true;
                } else {
                    // SAFETY: the exact debugger thread has joined and this
                    // authenticated rejected-worker alias is now owned here.
                    if unsafe { CloseHandle(rejected_thread) }.is_ok() {
                        handles.rejected_thread = None;
                        handles.rejected_thread_id = None;
                    } else {
                        failed = true;
                    }
                }
            }
            (None, None) => {}
            _ => failed = true,
        }

        if let Some(event_primary_thread) = handles.primary_thread {
            let event_primary_thread = HANDLE(event_primary_thread as *mut c_void);
            let mut flags = u32::MAX;
            let rejected = invalid(event_primary_thread)
                // SAFETY: the caller has joined the exact debugger thread; this
                // registered alias remains live until the checked close below.
                || unsafe { GetThreadId(event_primary_thread) } != handles.thread_id
                // SAFETY: flags is exact initialized writable storage.
                || unsafe { GetHandleInformation(event_primary_thread, &raw mut flags) }.is_err()
                || flags != 0;
            if rejected {
                failed = true;
            } else {
                // SAFETY: join ended system management of this authenticated
                // alias; the registry clears the value only after success.
                if unsafe { CloseHandle(event_primary_thread) }.is_ok() {
                    handles.primary_thread = None;
                } else {
                    failed = true;
                }
            }
        }

        if let Some(event_process) = handles.process {
            let event_process = HANDLE(event_process as *mut c_void);
            let mut flags = u32::MAX;
            let rejected = invalid(event_process)
                // SAFETY: same joined-registry ownership argument as above.
                || unsafe { GetProcessId(event_process) } != handles.process_id
                // SAFETY: flags is exact initialized writable storage.
                || unsafe { GetHandleInformation(event_process, &raw mut flags) }.is_err()
                || flags != 0;
            if rejected {
                failed = true;
            } else {
                // SAFETY: the registry owns this exact post-detach alias and
                // clears it only after the kernel confirms the close.
                if unsafe { CloseHandle(event_process) }.is_ok() {
                    handles.process = None;
                } else {
                    failed = true;
                }
            }
        }

        if failed {
            Err(KeyAgentActivationError::Cleanup)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn query_handle_authority_for_test(
        handle: HANDLE,
    ) -> Result<(u32, u32), KeyAgentActivationError> {
        if invalid(handle) {
            return Err(KeyAgentActivationError::HandleAttenuation);
        }
        let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
        let information_size = u32::try_from(size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>())
            .map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
        let mut returned_length = 0_u32;
        // SAFETY: this test-only native query receives the exact live handle,
        // a correctly sized initialized output object, and exact writable
        // returned-length storage. Production code never depends on this
        // change-prone native API.
        let status = unsafe {
            NtQueryObject(
                Some(handle),
                ObjectBasicInformation,
                Some((&raw mut information).cast()),
                information_size,
                Some(&raw mut returned_length),
            )
        };
        if status != STATUS_SUCCESS || returned_length != information_size {
            return Err(KeyAgentActivationError::HandleAttenuation);
        }
        Ok((information.GrantedAccess, information.Attributes))
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
    pub(super) const fn resident_process_access_for_test() -> u32 {
        RESIDENT_KEY_AGENT_PROCESS_ACCESS.0
    }

    #[cfg(test)]
    pub(super) const fn storage_startup_thread_access_for_test() -> u32 {
        STORAGE_STARTUP_THREAD_ACCESS.0
    }

    #[cfg(test)]
    pub(super) const fn rejected_process_exit_code_for_test() -> u32 {
        REJECTED_PROCESS_EXIT_CODE
    }

    #[cfg(test)]
    pub(super) const fn creation_attribute_count_for_test() -> u32 {
        KEY_AGENT_CREATION_ATTRIBUTE_COUNT
    }

    #[cfg(test)]
    pub(super) const fn key_agent_mitigation_policy_for_test() -> u64 {
        KEY_AGENT_MITIGATION_POLICY
    }

    #[cfg(test)]
    pub(super) fn creation_attribute_retained_values_for_test(
        inheritance: &PreparedKeyAgentInheritance<'_, '_>,
        root_job_attribute: &KeyAgentRootJobAttribute<'_>,
    ) -> Result<(usize, u64), KeyAgentActivationError> {
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()
            .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
        let lpac = provisioning
            .prepare_lpac()
            .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
        let attributes = KeyAgentCreationAttributes::new(inheritance, root_job_attribute, &lpac)?;
        Ok((
            attributes.explicit_handle_count(),
            attributes.retained_mitigation_policy(),
        ))
    }

    fn windows_handle(handle: BorrowedHandle<'_>) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn finish_exact_noninheritable_duplicate(
        source: HANDLE,
        duplicate: HANDLE,
    ) -> Result<OwnedHandle, KeyAgentActivationError> {
        if invalid(source) || invalid(duplicate) {
            return Err(KeyAgentActivationError::HandleAttenuation);
        }
        // SAFETY: successful duplication returned one newly owned handle and
        // ownership transfers exactly once to the standard wrapper.
        let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate.0) };
        let duplicate_raw = windows_handle(duplicate.as_handle());
        let mut flags = u32::MAX;
        // SAFETY: the duplicate is live and `flags` is initialized writable
        // storage. CompareObjectHandles only observes both live handles.
        unsafe { GetHandleInformation(duplicate_raw, &raw mut flags) }
            .map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
        // SAFETY: source and duplicate are simultaneously live and this call
        // only compares their underlying kernel objects.
        let same_object = unsafe { CompareObjectHandles(source, duplicate_raw) }.as_bool();
        if flags != 0 || !same_object {
            return Err(KeyAgentActivationError::HandleAttenuation);
        }
        Ok(duplicate)
    }

    fn duplicate_resident_process_handle(
        source_process: HANDLE,
    ) -> Result<OwnedHandle, KeyAgentActivationError> {
        if invalid(source_process) {
            return Err(KeyAgentActivationError::HandleAttenuation);
        }
        let mut duplicate = HANDLE::default();
        // SAFETY: both process parameters name the current supervisor and
        // `source_process` is the live creator process handle. Windows writes
        // at most one local handle with exactly terminate + QLI + synchronize;
        // zero options keep that mask authoritative and false forbids inheritance.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source_process,
                GetCurrentProcess(),
                &raw mut duplicate,
                RESIDENT_KEY_AGENT_PROCESS_ACCESS.0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
        finish_exact_noninheritable_duplicate(source_process, duplicate)
    }

    fn duplicate_post_detach_thread_probe_handle(
        source_thread: HANDLE,
    ) -> Result<OwnedHandle, KeyAgentActivationError> {
        if invalid(source_thread) {
            return Err(KeyAgentActivationError::HandleAttenuation);
        }
        let mut duplicate = HANDLE::default();
        // SAFETY: both process parameters name the current supervisor and
        // `source_thread` is the live creator primary-thread handle. Windows
        // writes at most one local probe handle requested with exactly
        // THREAD_SUSPEND_RESUME; zero options and false forbid broader copy
        // semantics and inheritance.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source_thread,
                GetCurrentProcess(),
                &raw mut duplicate,
                POST_DETACH_THREAD_PROBE_ACCESS.0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
        finish_exact_noninheritable_duplicate(source_thread, duplicate)
    }

    fn duplicate_storage_startup_thread_handle(
        source_thread: HANDLE,
    ) -> Result<OwnedHandle, KeyAgentActivationError> {
        if invalid(source_thread) {
            return Err(KeyAgentActivationError::HandleAttenuation);
        }
        let mut duplicate = HANDLE::default();
        // SAFETY: both process parameters name the current supervisor and
        // `source_thread` is the live creator primary-thread handle. The final
        // resident thread capability requests only THREAD_RESUME for its one
        // consuming storage-startup operation; options and inheritance are zero.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source_thread,
                GetCurrentProcess(),
                &raw mut duplicate,
                STORAGE_STARTUP_THREAD_ACCESS.0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
        finish_exact_noninheritable_duplicate(source_thread, duplicate)
    }

    fn close_owned_handle_checked(handle: OwnedHandle) -> Result<(), KeyAgentActivationError> {
        let raw = HANDLE(handle.as_raw_handle());
        // SAFETY: `handle` remains the sole RAII owner during this checked call.
        // On failure, ordinary Drop immediately retries instead of losing the
        // raw capability. On success, forget only the now-closed wrapper so it
        // cannot issue a second close against a potentially reused value.
        unsafe { CloseHandle(raw) }.map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
        core::mem::forget(handle);
        Ok(())
    }

    struct OwnedWinHandle(HANDLE);

    impl OwnedWinHandle {
        fn new(handle: HANDLE) -> Option<Self> {
            (!invalid(handle)).then_some(Self(handle))
        }

        const fn raw(&self) -> HANDLE {
            self.0
        }

        fn close_checked(&mut self) -> Result<(), KeyAgentActivationError> {
            if invalid(self.0) {
                return Err(KeyAgentActivationError::HandleAttenuation);
            }
            // SAFETY: this wrapper owns the exact live handle. Preserve its raw
            // value on failure so Drop can retry cleanup; clear it only after a
            // successful checked close.
            unsafe { CloseHandle(self.0) }
                .map_err(|_| KeyAgentActivationError::HandleAttenuation)?;
            self.0 = HANDLE::default();
            Ok(())
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

    pub(super) struct PreparedApprovalParentProcess {
        process: OwnedHandle,
        process_id: u32,
        creation_time: u64,
    }

    impl PreparedApprovalParentProcess {
        pub(super) fn duplicate(
            source: &DetachedRunningDebuggee,
            expected_creation_time: u64,
        ) -> Result<Self, KeyAgentActivationError> {
            if !source.is_detached_and_running() || expected_creation_time == 0 {
                return Err(KeyAgentActivationError::ApprovalParentCapability);
            }

            let source_process = source.0.process_raw();
            let expected_process_id = source.process_id();
            let mut duplicate = HANDLE::default();
            // SAFETY: both process parameters name the current supervisor; the
            // source is the live exact Key Agent process handle. Windows writes
            // at most one duplicate handle into initialized output storage.
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    source_process,
                    GetCurrentProcess(),
                    &raw mut duplicate,
                    APPROVAL_PARENT_PROCESS_ACCESS.0,
                    false,
                    DUPLICATE_HANDLE_OPTIONS(0),
                )
            }
            .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            if invalid(duplicate) {
                return Err(KeyAgentActivationError::ApprovalParentCapability);
            }
            // SAFETY: successful duplication returned one newly owned handle,
            // and this transfers its sole ownership into the standard wrapper.
            let process = unsafe { OwnedHandle::from_raw_handle(duplicate.0) };

            // SAFETY: both handles are live process handles owned or borrowed
            // by this supervisor for the duration of the comparison.
            if !unsafe { CompareObjectHandles(source_process, windows_handle(process.as_handle())) }
                .as_bool()
            {
                return Err(KeyAgentActivationError::ApprovalParentCapability);
            }

            let prepared = Self {
                process,
                process_id: expected_process_id,
                creation_time: expected_creation_time,
            };
            prepared.revalidate()?;
            Ok(prepared)
        }

        pub(super) fn revalidate(&self) -> Result<(), KeyAgentActivationError> {
            let mut flags = u32::MAX;
            let process = windows_handle(self.process.as_handle());
            // SAFETY: the capability owns a live process handle and the flags
            // pointer names initialized writable storage.
            unsafe { GetHandleInformation(process, &raw mut flags) }
                .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            // SAFETY: the capability owns the queried process handle.
            let process_id = unsafe { GetProcessId(process) };
            // SAFETY: zero-timeout waiting only observes this live handle.
            let wait = unsafe { WaitForSingleObject(process, 0) };
            let creation_time = process_creation_time(process)
                .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            if flags != 0
                || process_id == 0
                || process_id != self.process_id
                || creation_time != self.creation_time
                || wait != WAIT_TIMEOUT
            {
                return Err(KeyAgentActivationError::ApprovalParentCapability);
            }

            let mut token = HANDLE::default();
            // SAFETY: the process handle has query-limited-information rights;
            // the output points to initialized handle storage.
            unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }
                .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            let token = OwnedWinHandle::new(token)
                .ok_or(KeyAgentActivationError::ApprovalParentCapability)?;
            drop(token);

            let mut image_path = vec![0_u16; MAX_PROCESS_IMAGE_PATH_UNITS];
            let mut image_path_units = u32::try_from(image_path.len())
                .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            // SAFETY: the process handle has query-limited-information rights;
            // the mutable UTF-16 buffer and its in/out length are valid.
            unsafe {
                QueryFullProcessImageNameW(
                    process,
                    PROCESS_NAME_WIN32,
                    PWSTR(image_path.as_mut_ptr()),
                    &raw mut image_path_units,
                )
            }
            .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            let image_path_units = usize::try_from(image_path_units)
                .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            if image_path_units == 0 || image_path_units >= image_path.len() {
                return Err(KeyAgentActivationError::ApprovalParentCapability);
            }
            Ok(())
        }

        pub(super) fn duplicate_into_suspended_child(
            &self,
            suspended_child: BorrowedHandle<'_>,
        ) -> Result<(u64, u32), KeyAgentActivationError> {
            self.revalidate()?;
            let target_process = windows_handle(suspended_child);
            if invalid(target_process) {
                return Err(KeyAgentActivationError::ApprovalParentCapability);
            }

            let mut child_local_process = HANDLE::default();
            // SAFETY: this capability retains the exact live Key Agent process
            // handle. `suspended_child` is owned by the launch guard and has
            // PROCESS_DUP_HANDLE from CreateProcessW. Windows writes one value
            // valid only in that child, explicitly marked non-inheritable.
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    windows_handle(self.process.as_handle()),
                    target_process,
                    &raw mut child_local_process,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            }
            .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            if invalid(child_local_process) {
                return Err(KeyAgentActivationError::ApprovalParentCapability);
            }
            self.revalidate()?;
            let child_local_process = u64::try_from(child_local_process.0 as usize)
                .map_err(|_| KeyAgentActivationError::ApprovalParentCapability)?;
            Ok((child_local_process, self.process_id))
        }
    }

    #[cfg(test)]
    pub(super) const fn approval_parent_process_access_for_test() -> u32 {
        APPROVAL_PARENT_PROCESS_ACCESS.0
    }

    #[cfg(test)]
    pub(super) const fn amd64_context_storage_alignment_for_test() -> usize {
        core::mem::align_of::<AlignedAmd64Context>()
    }

    #[cfg(test)]
    pub(super) fn context_r10_clear_readback_policy_for_test(
        before_flags: u32,
        after_flags: u32,
        after_r10: u64,
        after_rip_delta: u64,
    ) -> bool {
        let before = CONTEXT {
            ContextFlags: CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
            EFlags: before_flags,
            R10: crate::key_agent_child_bootstrap::KEY_AGENT_DEFAULT_DACL_GATE_MARKER,
            Rip: 0x1000,
            ..CONTEXT::default()
        };
        let mut after = before;
        after.EFlags = after_flags;
        after.R10 = after_r10;
        after.Rip = after.Rip.wrapping_add(after_rip_delta);
        context_matches_after_r10_clear(&before, &after)
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
        AuthenticatedKeyAgentActivation, ExactFileObjectIdentity, FreshKeyAgentDebugThread,
        HeldKeyAgentActivation, JoinedKeyAgentDebugThreadProof, KeyAgentActivationError,
        LaunchPhase, LaunchTransition, PendingKeyAgentActivation, PreflightKeyAgentArtifact,
        RootJobBoundFreshKeyAgentDebugThread, RunningKeyAgentActivation,
        activate_preflighted_key_agent_on_fresh_worker, default_dacl_gate_sequence,
        fail_after_cleanup, finalize_pending_key_agent_activation,
        parse_unique_default_dacl_gate_layout, preflight_key_agent_activation,
        run_on_fresh_key_agent_debug_thread, sys, verify_unique_default_dacl_gate_sequence,
    };
    use crate::{
        attestation::{ArtifactDigest, ReleaseAttestation},
        helper::VerifiedHelper,
        inheritable_handle_launch::acquire_inheritable_handle_launch,
        key_agent_lpac::PreparedKeyAgentProvisioning,
        key_agent_root_job::KeyAgentRootJob,
        pipe::PrivateKeyAgentPipes,
    };

    fn require_send<T: Send>() {}

    fn test_root_job() -> Result<KeyAgentRootJob, KeyAgentActivationError> {
        KeyAgentRootJob::create_for_kernel_test()
            .map_err(|_| KeyAgentActivationError::RootJobPolicy)
    }

    fn test_provisioning() -> Result<PreparedKeyAgentProvisioning, KeyAgentActivationError> {
        PreparedKeyAgentProvisioning::prepare_for_kernel_test()
            .map_err(|_| KeyAgentActivationError::LpacPolicy)
    }

    fn activation_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn require_root_job_empty_after_join(
        root_job: &KeyAgentRootJob,
    ) -> Result<(), KeyAgentActivationError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if root_job
                .active_process_count()
                .map_err(|_| KeyAgentActivationError::RootJobPolicy)?
                == 0
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(KeyAgentActivationError::Cleanup);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn pending_for_test(
        attestation: ReleaseAttestation,
        artifact: VerifiedHelper,
    ) -> Result<
        (
            PendingKeyAgentActivation,
            KeyAgentRootJob,
            JoinedKeyAgentDebugThreadProof,
        ),
        KeyAgentActivationError,
    > {
        let preflighted = preflight_key_agent_activation(attestation, artifact)?;
        let ((activation, root_job), joined) =
            run_on_fresh_key_agent_debug_thread(move |fresh_thread| {
                let provisioning = test_provisioning()?;
                let mut root_job = test_root_job()?;
                let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let activation = activate_preflighted_key_agent_on_fresh_worker(
                    fresh_thread,
                    preflighted,
                    &provisioning,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    activation_deadline(),
                )?;
                drop(root_job_attribute);
                drop(pipes);
                provisioning
                    .revalidate()
                    .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
                activation.revalidate_before_no_kill(&root_job)?;
                let activation = activation.arm_no_kill()?;
                Ok((activation, root_job))
            })?;
        Ok((activation, root_job, joined))
    }

    fn activate_for_test<R, F>(
        attestation: ReleaseAttestation,
        artifact: VerifiedHelper,
        inspect: F,
    ) -> Result<R, KeyAgentActivationError>
    where
        F: FnOnce(HeldKeyAgentActivation, &KeyAgentRootJob) -> Result<R, KeyAgentActivationError>,
    {
        let (activation, root_job, joined) = pending_for_test(attestation, artifact)?;
        let activation = finalize_pending_key_agent_activation(activation, &root_job, joined)?;
        inspect(activation, &root_job)
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
        ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test([23; 32]),
            [artifact.manifest_digest(), [25; 32], [26; 32]],
        )
    }

    fn test_pe_u16(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn test_pe_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    fn set_test_pe_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn set_test_pe_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn launch_state_machine_rejects_skip_replay_and_post_abort_transitions() {
        assert_eq!(
            LaunchPhase::AwaitingCreateEvent.transition(LaunchTransition::ReceiveCreateEvent),
            Ok(LaunchPhase::CreateEventHeld)
        );
        assert_eq!(
            LaunchPhase::CreateEventHeld.transition(LaunchTransition::ContinueCreateEvent),
            Ok(LaunchPhase::LoaderRunning)
        );
        assert_eq!(
            LaunchPhase::LoaderRunning.transition(LaunchTransition::ReceiveCooperativeGate),
            Ok(LaunchPhase::GateEventHeld)
        );
        assert_eq!(
            LaunchPhase::GateEventHeld.transition(LaunchTransition::ContinueCooperativeGate),
            Ok(LaunchPhase::GateEventContinued)
        );
        assert_eq!(
            LaunchPhase::GateEventContinued.transition(LaunchTransition::ArmNoKill),
            Ok(LaunchPhase::NoKillArmedAwaitingDebuggerExit)
        );
        assert_eq!(
            LaunchPhase::NoKillArmedAwaitingDebuggerExit
                .transition(LaunchTransition::ObserveDebuggerExit),
            Ok(LaunchPhase::DebuggerExitedPendingVerification)
        );
        assert_eq!(
            LaunchPhase::DebuggerExitedPendingVerification
                .transition(LaunchTransition::VerifyDetached),
            Ok(LaunchPhase::DetachedSuspended)
        );
        assert_eq!(
            LaunchPhase::DetachedSuspended.transition(LaunchTransition::ResumeStorageStartup),
            Ok(LaunchPhase::DetachedRunning)
        );
        assert_eq!(
            LaunchPhase::DetachedRunning.transition(LaunchTransition::ResumeStorageStartup),
            Err(KeyAgentActivationError::DebugDetach)
        );
        assert_eq!(
            LaunchPhase::DetachedRunning.transition(LaunchTransition::Abort),
            Ok(LaunchPhase::Aborted)
        );
        assert_eq!(
            LaunchPhase::AwaitingCreateEvent.transition(LaunchTransition::ArmNoKill),
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
        assert_eq!(
            LaunchPhase::Aborted.transition(LaunchTransition::ResumeStorageStartup),
            Err(KeyAgentActivationError::DebugDetach)
        );
    }

    #[test]
    fn amd64_context_storage_and_r10_readback_policy_are_exact() {
        assert_eq!(sys::amd64_context_storage_alignment_for_test(), 16);
        assert!(sys::context_r10_clear_readback_policy_for_test(
            0x202, 0x200, 0, 0
        ));
        assert!(sys::context_r10_clear_readback_policy_for_test(
            0x202, 0x202, 0, 0
        ));
        assert!(!sys::context_r10_clear_readback_policy_for_test(
            0x202, 0x200, 1, 0
        ));
        assert!(!sys::context_r10_clear_readback_policy_for_test(
            0x202, 0x204, 0, 0
        ));
        assert!(!sys::context_r10_clear_readback_policy_for_test(
            0x202, 0x200, 0, 1
        ));
    }

    #[test]
    fn minimal_gate_pe_parser_binds_exact_rvas_and_rejects_shape_mutations()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let bytes = std::fs::read(artifact.path())?;
        let sequence = default_dacl_gate_sequence(
            crate::key_agent_child_bootstrap::KEY_AGENT_DEFAULT_DACL_GATE_MARKER,
        );
        let layout = parse_unique_default_dacl_gate_layout(&bytes, &sequence)?;

        let pe_offset = usize::try_from(test_pe_u32(&bytes, 0x3c))?;
        let coff_offset = pe_offset + 4;
        let optional_offset = coff_offset + 20;
        let section_offset = optional_offset + usize::from(test_pe_u16(&bytes, coff_offset + 16));
        assert_eq!(test_pe_u16(&bytes, coff_offset + 2), 2);
        assert_eq!(layout.sequence_rva, 0x1000);
        assert_eq!(layout.breakpoint_rva, 0x100a);
        assert_eq!(
            layout.size_of_image,
            test_pe_u32(&bytes, optional_offset + 56)
        );

        let rejected = |candidate: &[u8]| {
            matches!(
                parse_unique_default_dacl_gate_layout(candidate, &sequence),
                Err(KeyAgentActivationError::CooperativeGatePolicy)
            )
        };

        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&sequence);
        assert!(rejected(&duplicate));

        let mut wrong_machine = bytes.clone();
        set_test_pe_u16(&mut wrong_machine, coff_offset, 0x014c);
        assert!(rejected(&wrong_machine));

        let mut dll = bytes.clone();
        let characteristics = test_pe_u16(&dll, coff_offset + 18);
        set_test_pe_u16(&mut dll, coff_offset + 18, characteristics | 0x2000);
        assert!(rejected(&dll));

        let mut writable_code = bytes.clone();
        let characteristics = test_pe_u32(&writable_code, section_offset + 36);
        set_test_pe_u32(
            &mut writable_code,
            section_offset + 36,
            characteristics | 0x8000_0000,
        );
        assert!(rejected(&writable_code));

        let mut raw_padding = bytes.clone();
        set_test_pe_u32(&mut raw_padding, section_offset + 8, 10);
        assert!(rejected(&raw_padding));

        let mut overlapping_raw_sections = bytes.clone();
        let first_raw_start = test_pe_u32(&overlapping_raw_sections, section_offset + 20);
        set_test_pe_u32(
            &mut overlapping_raw_sections,
            section_offset + 40 + 20,
            first_raw_start,
        );
        assert!(rejected(&overlapping_raw_sections));

        let mut unaligned_image = bytes;
        let size_of_image = test_pe_u32(&unaligned_image, optional_offset + 56);
        set_test_pe_u32(
            &mut unaligned_image,
            optional_offset + 56,
            size_of_image + 1,
        );
        assert!(rejected(&unaligned_image));
        Ok(())
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
        require_send::<PendingKeyAgentActivation>();
        require_send::<sys::PendingDebuggerExitSuspendedDebuggee>();
        require_send::<sys::DetachedSuspendedDebuggee>();
        require_send::<sys::DetachedRunningDebuggee>();
        require_send::<HeldKeyAgentActivation>();
        require_send::<RunningKeyAgentActivation>();

        let _ = <FreshKeyAgentDebugThread as AmbiguousIfSend<_>>::marker;
        let _ = <FreshKeyAgentDebugThread as AmbiguousIfSync<_>>::marker;
        let _ = <FreshKeyAgentDebugThread as AmbiguousIfClone<_>>::marker;
        let _ = <FreshKeyAgentDebugThread as AmbiguousIfCopy<_>>::marker;
        let _ = <RootJobBoundFreshKeyAgentDebugThread as AmbiguousIfSend<_>>::marker;
        let _ = <RootJobBoundFreshKeyAgentDebugThread as AmbiguousIfSync<_>>::marker;
        let _ = <RootJobBoundFreshKeyAgentDebugThread as AmbiguousIfClone<_>>::marker;
        let _ = <RootJobBoundFreshKeyAgentDebugThread as AmbiguousIfCopy<_>>::marker;
        let _ = <AuthenticatedKeyAgentActivation as AmbiguousIfSend<_>>::marker;
        let _ = <AuthenticatedKeyAgentActivation as AmbiguousIfSync<_>>::marker;
        let _ = <JoinedKeyAgentDebugThreadProof as AmbiguousIfSend<_>>::marker;
        let _ = <JoinedKeyAgentDebugThreadProof as AmbiguousIfSync<_>>::marker;
        let _ = <JoinedKeyAgentDebugThreadProof as AmbiguousIfClone<_>>::marker;
        let _ = <JoinedKeyAgentDebugThreadProof as AmbiguousIfCopy<_>>::marker;
        let _ = <PendingKeyAgentActivation as AmbiguousIfSync<_>>::marker;
        let _ = <PendingKeyAgentActivation as AmbiguousIfClone<_>>::marker;
        let _ = <PendingKeyAgentActivation as AmbiguousIfCopy<_>>::marker;
        let _ = <PreflightKeyAgentArtifact as AmbiguousIfClone<_>>::marker;
        let _ = <PreflightKeyAgentArtifact as AmbiguousIfCopy<_>>::marker;
        let _ = <HeldKeyAgentActivation as AmbiguousIfSync<_>>::marker;
        let _ = <HeldKeyAgentActivation as AmbiguousIfClone<_>>::marker;
        let _ = <HeldKeyAgentActivation as AmbiguousIfCopy<_>>::marker;
        let _ = <sys::SuspendedDebuggee as AmbiguousIfSend<_>>::marker;
        let _ = <sys::DetachedSuspendedDebuggee as AmbiguousIfSync<_>>::marker;
        let _ = <sys::DetachedSuspendedDebuggee as AmbiguousIfClone<_>>::marker;
        let _ = <sys::DetachedSuspendedDebuggee as AmbiguousIfCopy<_>>::marker;
        let _ = <sys::DetachedRunningDebuggee as AmbiguousIfSync<_>>::marker;
        let _ = <sys::DetachedRunningDebuggee as AmbiguousIfClone<_>>::marker;
        let _ = <sys::DetachedRunningDebuggee as AmbiguousIfCopy<_>>::marker;
        let _ = <RunningKeyAgentActivation as AmbiguousIfSync<_>>::marker;
        let _ = <RunningKeyAgentActivation as AmbiguousIfClone<_>>::marker;
        let _ = <RunningKeyAgentActivation as AmbiguousIfCopy<_>>::marker;
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
    fn key_agent_creation_mitigation_matches_the_full_helper_policy() {
        let mitigation = sys::key_agent_mitigation_policy_for_test();
        assert_eq!(mitigation, 0x1110_1011_0111_1105);
        assert_ne!(mitigation & (1 << 32), 0, "extension points disabled");
        assert_ne!(mitigation & (1 << 44), 0, "non-Microsoft binaries blocked");
        assert_eq!(sys::creation_attribute_count_for_test(), 5);
    }

    #[test]
    fn creation_attribute_source_contract_installs_mitigation_before_lpac()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = include_str!("key_agent_activation.rs");
        let start = source
            .find("struct KeyAgentCreationAttributes")
            .ok_or(std::io::Error::other("creation-attribute owner must exist"))?;
        let drop_offset = source[start..]
            .find("impl Drop for KeyAgentCreationAttributes")
            .ok_or(std::io::Error::other(
                "creation-attribute owner must have Drop",
            ))?;
        let end = start + drop_offset;
        let contract = &source[start..end];

        assert!(contract.contains("mitigation_policy: Box<u64>"));
        assert_eq!(
            contract
                .matches("InitializeProcThreadAttributeList(")
                .count(),
            2
        );
        assert_eq!(
            contract
                .matches("KEY_AGENT_CREATION_ATTRIBUTE_COUNT")
                .count(),
            2
        );
        assert!(contract.contains("PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY"));

        let handle = contract
            .find("attributes.install_handle_list()?;")
            .ok_or(std::io::Error::other("handle list must be installed first"))?;
        let installation = &contract[handle..];
        let job = installation
            .find(".root_job_attribute")
            .ok_or(std::io::Error::other("Job list must be installed"))?;
        let mitigation = installation
            .find("attributes.install_mitigation_policy()?;")
            .ok_or(std::io::Error::other("mitigation policy must be installed"))?;
        let lpac = installation
            .find("attributes.lpac.install_into")
            .ok_or(std::io::Error::other("LPAC attributes must be installed"))?;
        assert!(0 < job && job < mitigation && mitigation < lpac);
        Ok(())
    }

    #[test]
    fn startup_attribute_list_retains_policy_and_exactly_three_stdio_handles()
    -> Result<(), Box<dyn std::error::Error>> {
        let root_job = test_root_job()?;
        let pipes = PrivateKeyAgentPipes::create()?;
        let flight = acquire_inheritable_handle_launch(activation_deadline())
            .map_err(|_| KeyAgentActivationError::ProcessCreation)?;
        let inheritance = pipes.prepare_child_inheritance(&flight)?;
        let root_job_attribute = root_job.creation_attribute()?;
        assert_eq!(
            sys::creation_attribute_retained_values_for_test(&inheritance, &root_job_attribute)?,
            (3, sys::key_agent_mitigation_policy_for_test())
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
        let (observation, joined) = run_on_fresh_key_agent_debug_thread::<
            _,
            KeyAgentActivationError,
            _,
        >(move |fresh_thread| {
            let provisioning = test_provisioning()?;
            let mut root_job = test_root_job()?;
            let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
            let (_debug_thread_witness, debug_event_cleanup) = fresh_thread.into_run_context();
            let pipes = PrivateKeyAgentPipes::create()
                .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
            let root_job_attribute = root_job
                .creation_attribute()
                .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
            let mut process = sys::SuspendedDebuggee::create(
                &artifact,
                &provisioning,
                &pipes,
                &root_job,
                &root_job_attribute,
                sys::DebuggeeLaunchPolicy::new(
                    activation_deadline(),
                    verify_unique_default_dacl_gate_sequence(&artifact)?,
                ),
            )?;
            let observation = process.duplicate_process_observation()?;
            assert!(matches!(
                process.authenticate_first_event(wrong_identity, 5_000, &debug_event_cleanup,),
                Err(KeyAgentActivationError::MappedImageMismatch)
            ));
            process.abort()?;
            assert!(process.is_aborted());
            assert_eq!(process.cleanup_exit_code(), None);
            Ok(observation)
        })?;
        drop(joined);
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        Ok(())
    }

    #[test]
    fn timeout_cleanup_terminates_without_dispatching_the_first_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let (observation, joined) = run_on_fresh_key_agent_debug_thread::<
            _,
            KeyAgentActivationError,
            _,
        >(move |fresh_thread| {
            let provisioning = test_provisioning()?;
            let mut root_job = test_root_job()?;
            let _fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
            let pipes = PrivateKeyAgentPipes::create()
                .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
            let root_job_attribute = root_job
                .creation_attribute()
                .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
            let mut process = sys::SuspendedDebuggee::create(
                &artifact,
                &provisioning,
                &pipes,
                &root_job,
                &root_job_attribute,
                sys::DebuggeeLaunchPolicy::new(
                    activation_deadline(),
                    verify_unique_default_dacl_gate_sequence(&artifact)?,
                ),
            )?;
            let observation = process.duplicate_process_observation()?;
            let timeout_result: Result<(), KeyAgentActivationError> =
                fail_after_cleanup(&mut process, KeyAgentActivationError::DebugEventTimeout);
            assert_eq!(
                timeout_result,
                Err(KeyAgentActivationError::DebugEventTimeout)
            );
            assert!(process.is_aborted());
            assert_eq!(process.cleanup_exit_code(), None);
            Ok(observation)
        })?;
        drop(joined);
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        Ok(())
    }

    #[test]
    fn real_key_agent_loader_activity_fails_closed_before_detach()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_primary_gate_activation_test()?;
        let preflighted = preflight_key_agent_activation(attestation_for(&artifact), artifact)?;
        let ((root_job, rejected_thread_observation), joined) =
            run_on_fresh_key_agent_debug_thread::<_, KeyAgentActivationError, _>(
                move |fresh_thread| {
                    let provisioning = test_provisioning()?;
                    let mut root_job = test_root_job()?;
                    let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
                    let debug_event_cleanup = Arc::clone(&fresh_thread.debug_event_cleanup);
                    let pipes = PrivateKeyAgentPipes::create()
                        .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                    let root_job_attribute = root_job
                        .creation_attribute()
                        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                    let result = activate_preflighted_key_agent_on_fresh_worker(
                        fresh_thread,
                        preflighted,
                        &provisioning,
                        &pipes,
                        &root_job,
                        &root_job_attribute,
                        activation_deadline(),
                    );
                    assert!(matches!(
                        result,
                        Err(KeyAgentActivationError::UnexpectedDebugEvent)
                    ));
                    drop(root_job_attribute);
                    drop(pipes);
                    drop(provisioning);
                    let rejected_thread_observation = debug_event_cleanup
                        .rejected_thread_observation_while_attached_for_test()?;
                    Ok((root_job, rejected_thread_observation))
                },
            )?;
        drop(joined);
        assert!(rejected_thread_observation.alias_is_closed());
        require_root_job_empty_after_join(&root_job)?;
        Ok(())
    }

    #[test]
    fn minimal_primary_gate_proof_detaches_with_one_verified_suspend_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let attestation = attestation_for(&artifact);
        activate_for_test(attestation, artifact, |activation, root_job| {
            assert!(activation.process_id() != 0);
            assert!(activation.creation_time() != 0);
            assert!(activation.is_detached_and_suspended());
            assert!(activation.is_member_of_root_job_for_test(root_job)?);
            let (
                process_granted_access,
                process_attributes,
                thread_granted_access,
                thread_attributes,
            ) = activation.process.retained_handle_authority_for_test()?;
            assert_eq!(sys::resident_process_access_for_test(), 0x0010_1001);
            assert_eq!(sys::storage_startup_thread_access_for_test(), 0x0000_1000);
            assert_eq!(process_granted_access, 0x0010_1001);
            assert_eq!(process_attributes, 0);
            assert_eq!(thread_granted_access, 0x0000_1000);
            assert_eq!(thread_attributes, 0);
            assert!(
                activation
                    .process
                    .resume_only_thread_rejects_suspend_for_test()
            );
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
    fn pending_finalization_rejects_swapped_join_and_root_job_witnesses()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let first = pending_for_test(attestation_for(&first_artifact), first_artifact)?;
        let second_artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let second = pending_for_test(attestation_for(&second_artifact), second_artifact)?;
        let third_artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let third = pending_for_test(attestation_for(&third_artifact), third_artifact)?;

        let (first_pending, first_root, first_joined) = first;
        let (second_pending, second_root, second_joined) = second;
        let (third_pending, third_root, third_joined) = third;
        assert!(matches!(
            finalize_pending_key_agent_activation(first_pending, &first_root, second_joined),
            Err(KeyAgentActivationError::DebuggerJoinProof)
        ));
        assert!(matches!(
            finalize_pending_key_agent_activation(third_pending, &second_root, third_joined),
            Err(KeyAgentActivationError::DebuggerJoinProof)
        ));

        // The remaining deliberately unmatched pair is never observable as a
        // detached capability; Drop requests termination and the joined root
        // gate restores authoritative bounded Job cleanup.
        drop(first_joined);
        drop(second_pending);
        drop(third_root);
        drop(second_root);
        drop(first_root);
        Ok(())
    }

    #[test]
    fn caller_debuggee_does_not_contaminate_dedicated_activation_worker()
    -> Result<(), Box<dyn std::error::Error>> {
        let caller_artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let (caller_ready_sender, caller_ready_receiver) = mpsc::sync_channel(1);
        let (caller_release_sender, caller_release_receiver) = mpsc::sync_channel(1);
        let caller = std::thread::spawn(move || {
            let (observation, joined) = run_on_fresh_key_agent_debug_thread(move |fresh_thread| {
                let caller_identity = sys::exact_file_identity(caller_artifact.raw_handle())?;
                let caller_provisioning = test_provisioning()?;
                let mut caller_root_job = test_root_job()?;
                let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut caller_root_job)?;
                let (_debug_thread_witness, debug_event_cleanup) = fresh_thread.into_run_context();
                let caller_pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let caller_root_job_attribute = caller_root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let mut caller_debuggee = sys::SuspendedDebuggee::create(
                    &caller_artifact,
                    &caller_provisioning,
                    &caller_pipes,
                    &caller_root_job,
                    &caller_root_job_attribute,
                    sys::DebuggeeLaunchPolicy::new(
                        activation_deadline(),
                        verify_unique_default_dacl_gate_sequence(&caller_artifact)?,
                    ),
                )?;
                let observation = caller_debuggee.duplicate_process_observation()?;
                caller_ready_sender
                    .send(())
                    .map_err(|_| KeyAgentActivationError::ActivationWorker)?;
                caller_release_receiver
                    .recv()
                    .map_err(|_| KeyAgentActivationError::ActivationWorker)?;
                let caller_event = caller_debuggee.authenticate_first_event(
                    caller_identity,
                    5_000,
                    &debug_event_cleanup,
                )?;
                if caller_event.creation_time == 0 {
                    return Err(KeyAgentActivationError::CreationTime);
                }
                caller_debuggee.abort()?;
                Ok(observation)
            })?;
            drop(joined);
            Ok::<_, KeyAgentActivationError>(observation)
        });
        caller_ready_receiver.recv()?;

        let activation_artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
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
        caller_release_sender.send(())?;
        let observation = caller
            .join()
            .map_err(|_| std::io::Error::other("caller debugger worker panicked"))??;
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        Ok(())
    }

    #[test]
    fn concurrent_activations_use_isolated_workers() -> Result<(), Box<dyn std::error::Error>> {
        let first_artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let first_attestation = attestation_for(&first_artifact);
        let second_artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
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
        let ((assigned_job, checked_job), joined) =
            run_on_fresh_key_agent_debug_thread::<_, KeyAgentActivationError, _>(
                move |fresh_thread| {
                    let provisioning = test_provisioning()?;
                    let mut assigned_job = test_root_job()?;
                    let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut assigned_job)?;
                    let checked_job = test_root_job()?;
                    let pipes = PrivateKeyAgentPipes::create()
                        .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                    let mismatched_attribute = assigned_job
                        .creation_attribute()
                        .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                    let result = activate_preflighted_key_agent_on_fresh_worker(
                        fresh_thread,
                        preflighted,
                        &provisioning,
                        &pipes,
                        &checked_job,
                        &mismatched_attribute,
                        activation_deadline(),
                    );
                    assert!(matches!(
                        result,
                        Err(KeyAgentActivationError::RootJobPolicy)
                    ));
                    drop(mismatched_attribute);
                    Ok((assigned_job, checked_job))
                },
            )?;
        drop(joined);
        require_root_job_empty_after_join(&assigned_job)?;
        require_root_job_empty_after_join(&checked_job)?;
        Ok(())
    }

    #[test]
    fn worker_error_cleans_up_exact_process() -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let mut wrong_identity = sys::exact_file_identity(artifact.raw_handle())?;
        wrong_identity.file_id[3] ^= 1;
        let (observation_sender, observation_receiver) = mpsc::sync_channel(1);
        let result = run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |fresh_thread| {
                let provisioning = test_provisioning()?;
                let mut root_job = test_root_job()?;
                let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
                let (_debug_thread_witness, debug_event_cleanup) = fresh_thread.into_run_context();
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let mut process = sys::SuspendedDebuggee::create(
                    &artifact,
                    &provisioning,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    sys::DebuggeeLaunchPolicy::new(
                        activation_deadline(),
                        verify_unique_default_dacl_gate_sequence(&artifact)?,
                    ),
                )?;
                let observation = process.duplicate_process_observation()?;
                let Err(error) =
                    process.authenticate_first_event(wrong_identity, 5_000, &debug_event_cleanup)
                else {
                    return Err(KeyAgentActivationError::MappedImageMismatch);
                };
                let event_observation =
                    debug_event_cleanup.observation_while_attached_for_test()?;
                observation_sender
                    .send((observation, event_observation))
                    .map_err(|_| KeyAgentActivationError::ActivationWorker)?;
                fail_after_cleanup(&mut process, error)
            },
        );
        assert!(matches!(
            result,
            Err(KeyAgentActivationError::MappedImageMismatch)
        ));
        let (observation, event_observation) = observation_receiver.recv()?;
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        assert!(event_observation.aliases_are_closed());
        Ok(())
    }

    #[test]
    fn worker_panic_after_create_cleans_up_exact_process() -> Result<(), Box<dyn std::error::Error>>
    {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let (observation_sender, observation_receiver) = mpsc::sync_channel(1);
        let result = run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |fresh_thread| {
                let provisioning = test_provisioning()?;
                let mut root_job = test_root_job()?;
                let _fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let process = sys::SuspendedDebuggee::create(
                    &artifact,
                    &provisioning,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    sys::DebuggeeLaunchPolicy::new(
                        activation_deadline(),
                        verify_unique_default_dacl_gate_sequence(&artifact)?,
                    ),
                )?;
                let observation = process.duplicate_process_observation()?;
                observation_sender
                    .send(observation)
                    .map_err(|_| KeyAgentActivationError::ActivationWorker)?;
                std::panic::resume_unwind(Box::new("intentional activation worker test unwind"));
            },
        );
        assert!(matches!(
            result,
            Err(KeyAgentActivationError::ActivationWorker)
        ));
        let observation = observation_receiver.recv()?;
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        Ok(())
    }

    #[test]
    fn worker_panic_after_event_alias_registration_cleans_up_after_join()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let preflighted = preflight_key_agent_activation(attestation_for(&artifact), artifact)?;
        let (observation_sender, observation_receiver) = mpsc::sync_channel(1);
        let result = run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |fresh_thread| {
                let provisioning = test_provisioning()?;
                let mut root_job = test_root_job()?;
                let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let activation = activate_preflighted_key_agent_on_fresh_worker(
                    fresh_thread,
                    preflighted,
                    &provisioning,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    activation_deadline(),
                )?;
                let observation = activation.process.duplicate_process_observation()?;
                let event_observation = activation
                    .debug_event_cleanup
                    .observation_while_attached_for_test()?;
                observation_sender
                    .send((observation, event_observation))
                    .map_err(|_| KeyAgentActivationError::ActivationWorker)?;
                std::panic::resume_unwind(Box::new(
                    "intentional post-event-registration activation worker unwind",
                ));
            },
        );
        assert!(matches!(
            result,
            Err(KeyAgentActivationError::ActivationWorker)
        ));
        let (observation, event_observation) = observation_receiver.recv()?;
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        assert!(event_observation.aliases_are_closed());
        Ok(())
    }

    #[test]
    fn worker_panic_immediately_after_no_kill_arm_cleans_up_after_join()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let preflighted = preflight_key_agent_activation(attestation_for(&artifact), artifact)?;
        let (observation_sender, observation_receiver) = mpsc::sync_channel(1);
        let result = run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |fresh_thread| {
                let provisioning = test_provisioning()?;
                let mut root_job = test_root_job()?;
                let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let activation = activate_preflighted_key_agent_on_fresh_worker(
                    fresh_thread,
                    preflighted,
                    &provisioning,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    activation_deadline(),
                )?;
                let observation = activation.process.duplicate_process_observation()?;
                let event_observation = activation
                    .debug_event_cleanup
                    .observation_while_attached_for_test()?;
                drop(root_job_attribute);
                drop(pipes);
                provisioning
                    .revalidate()
                    .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
                activation.revalidate_before_no_kill(&root_job)?;
                let _pending = activation.arm_no_kill()?;
                observation_sender
                    .send((observation, event_observation))
                    .map_err(|_| KeyAgentActivationError::ActivationWorker)?;
                std::panic::resume_unwind(Box::new(
                    "intentional post-no-kill-arm activation worker unwind",
                ));
            },
        );
        assert!(matches!(
            result,
            Err(KeyAgentActivationError::ActivationWorker)
        ));
        let (observation, event_observation) = observation_receiver.recv()?;
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        assert!(event_observation.aliases_are_closed());
        Ok(())
    }

    #[test]
    fn worker_error_immediately_after_no_kill_arm_cleans_up_after_join()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_minimal_primary_gate_activation_test()?;
        let preflighted = preflight_key_agent_activation(attestation_for(&artifact), artifact)?;
        let (observation_sender, observation_receiver) = mpsc::sync_channel(1);
        let result = run_on_fresh_key_agent_debug_thread::<(), KeyAgentActivationError, _>(
            move |fresh_thread| {
                let provisioning = test_provisioning()?;
                let mut root_job = test_root_job()?;
                let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
                let pipes = PrivateKeyAgentPipes::create()
                    .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
                let root_job_attribute = root_job
                    .creation_attribute()
                    .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
                let activation = activate_preflighted_key_agent_on_fresh_worker(
                    fresh_thread,
                    preflighted,
                    &provisioning,
                    &pipes,
                    &root_job,
                    &root_job_attribute,
                    activation_deadline(),
                )?;
                let observation = activation.process.duplicate_process_observation()?;
                let event_observation = activation
                    .debug_event_cleanup
                    .observation_while_attached_for_test()?;
                drop(root_job_attribute);
                drop(pipes);
                provisioning
                    .revalidate()
                    .map_err(|_| KeyAgentActivationError::LpacPolicy)?;
                activation.revalidate_before_no_kill(&root_job)?;
                let _pending = activation.arm_no_kill()?;
                observation_sender
                    .send((observation, event_observation))
                    .map_err(|_| KeyAgentActivationError::ActivationWorker)?;
                Err(KeyAgentActivationError::ActivationWorker)
            },
        );
        assert!(matches!(
            result,
            Err(KeyAgentActivationError::ActivationWorker)
        ));
        let (observation, event_observation) = observation_receiver.recv()?;
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
        assert!(event_observation.aliases_are_closed());
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
        let (observation, joined) = run_on_fresh_key_agent_debug_thread::<
            _,
            KeyAgentActivationError,
            _,
        >(move |fresh_thread| {
            let provisioning = test_provisioning()?;
            let mut root_job = test_root_job()?;
            let fresh_thread = fresh_thread.bind_root_job_cleanup(&mut root_job)?;
            let (_debug_thread_witness, debug_event_cleanup) = fresh_thread.into_run_context();
            let pipes = PrivateKeyAgentPipes::create()
                .map_err(|_| KeyAgentActivationError::PrivateChannelPolicy)?;
            let root_job_attribute = root_job
                .creation_attribute()
                .map_err(|_| KeyAgentActivationError::RootJobPolicy)?;
            let mut process = sys::SuspendedDebuggee::create_with_test_command_line(
                &artifact,
                &provisioning,
                &pipes,
                &root_job,
                &root_job_attribute,
                sys::DebuggeeLaunchPolicy::new(
                    activation_deadline(),
                    verify_unique_default_dacl_gate_sequence(&artifact)?,
                ),
                &mut command_line,
            )?;
            let observation = process.duplicate_process_observation()?;
            assert!(matches!(
                process.authenticate_first_event(wrong_identity, 5_000, &debug_event_cleanup,),
                Err(KeyAgentActivationError::MappedImageMismatch)
            ));
            process.abort()?;
            assert_eq!(process.cleanup_exit_code(), None);
            Ok(observation)
        })?;
        drop(joined);
        assert_eq!(
            observation.rejected_exit_code()?,
            sys::rejected_process_exit_code_for_test()
        );
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
