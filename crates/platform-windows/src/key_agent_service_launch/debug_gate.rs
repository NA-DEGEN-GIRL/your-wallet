//! Dormant parent-side two-breakpoint debugger gate for service UI helpers.
//!
//! The native entrypoints in this module remain unreachable outside the
//! explicit debug feasibility feature. The protocol authenticates one fresh
//! suspended helper, injects exactly two private channel handles through
//! `R10`/`R11`, correlates a fixed bootstrap hello and acknowledgement, then
//! installs a new suspend count while the adoption-complete event still holds
//! the primary thread. Every rejected prefix remains process-terminal.

#![allow(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;
use core::mem::{size_of, size_of_val};
use core::num::{NonZeroU32, NonZeroU64};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use std::cell::Cell;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle, IntoRawHandle as _};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use key_agent_service_helper_bootstrap::{
    ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET, ADOPTION_COMPLETE_GATE_BYTES,
    ADOPTION_COMPLETE_R10_MARKER, ADOPTION_COMPLETE_R11_MARKER, CAPTURE_GATE_BREAKPOINT_OFFSET,
    CAPTURE_GATE_BYTES, HELPER_ADOPTION_ACK_BYTES, HELPER_RPC_CONFIRMATION_BYTES,
    HelperAdoptionAck, HelperBootstrapHello, HelperBootstrapRole, HelperRpcConfirmation,
    REQUEST_INPUT_MARKER, RESPONSE_OUTPUT_MARKER, adoption_complete_gate_bytes, capture_gate_bytes,
    encode_service_approval_request_prefix,
};
use key_agent_service_wire::{EpochNonce, ServiceRequestId};
use thiserror::Error;
use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DBG_CONTINUE, ERROR_SEM_TIMEOUT, EXCEPTION_BREAKPOINT,
    FILETIME, GetHandleInformation, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_SHARE_READ, FileAttributeTagInfo, FileIdInfo,
    GetFileInformationByHandleEx,
};
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64, CREATE_PROCESS_DEBUG_EVENT,
    CREATE_THREAD_DEBUG_EVENT, CheckRemoteDebuggerPresent, ContinueDebugEvent, DEBUG_EVENT,
    DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, GetThreadContext, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT,
    RIP_EVENT, ReadProcessMemory, SetThreadContext, WaitForDebugEventEx,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_GUARD,
    VirtualQueryEx,
};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetProcessId, GetProcessIdOfThread, GetProcessTimes, GetThreadId,
    OpenProcess, OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, SuspendThread,
    THREAD_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};
use windows::core::BOOL;
use zeroize::Zeroizing;

use super::channel::{
    InjectedChildChannelHandles, duplicate_approval_channels_for_child,
    duplicate_secret_input_channels_for_child,
};
use super::gate::ServiceHelperGateLayout;
use super::process::{
    DebuggerThreadExitProof, DetachedSuspendedServiceProbe, PendingServiceProbeCleanup,
    PendingServiceProbeDetach, PreparedServiceProbeDetach, ServiceProbeRole, SuspendedServiceProbe,
};
use crate::exact_image::{authenticate_mapped_image, held_helper_file_identity};
use crate::key_agent_service_rpc::{
    ExpectedHelperAdmission, ExpectedHelperLease, ExpectedHelperPeer, ExpectedHelperRole,
    ExpectedPeerKey, ExpectedPeerRegistryError, ExpectedPeerVerificationError,
    ServiceCreatedLpacCandidate,
};
use crate::pipe::{
    ApprovalRequestWriter, ApprovalResponseReader, PrivateApprovalPipes, PrivateSecretInputPipes,
    SecretRequestWriter, SecretResponseReader,
};

pub(super) const MAX_COORDINATION_MILLISECONDS: u32 = 5_000;
const MAX_LOADER_DEBUG_EVENTS: usize = 128;
const MAX_PRE_CAPTURE_DEBUG_EVENTS: usize = 160;

/// Caller-supplied, nonzero correlation bound for one two-gate run.
#[must_use = "the correlation must be consumed by one service-helper gate"]
pub(super) struct ServiceProbeDebugCorrelation {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
    timeout_milliseconds: NonZeroU32,
}

impl ServiceProbeDebugCorrelation {
    pub(super) fn new(
        epoch_nonce: EpochNonce,
        request_id: ServiceRequestId,
        timeout_milliseconds: NonZeroU32,
    ) -> Result<Self, ServiceProbeDebugGateError> {
        if timeout_milliseconds.get() > MAX_COORDINATION_MILLISECONDS {
            return Err(ServiceProbeDebugGateError::Deadline);
        }
        Ok(Self {
            epoch_nonce,
            request_id,
            timeout_milliseconds,
        })
    }
}

impl fmt::Debug for ServiceProbeDebugCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeDebugCorrelation([REDACTED])")
    }
}

/// Role-typed local channel sources consumed only after capture-gate identity.
#[must_use = "private channel sources must be injected or dropped"]
pub(super) enum ServiceProbeChannelSources {
    Approval(PrivateApprovalPipes),
    SecretInput(PrivateSecretInputPipes),
}

impl fmt::Debug for ServiceProbeChannelSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeChannelSources([REDACTED])")
    }
}

enum ParentBootstrapChannelKind {
    Approval {
        request: ApprovalRequestWriter,
        response: Option<ApprovalResponseReader>,
    },
    SecretInput {
        request: SecretRequestWriter,
        response: Option<SecretResponseReader>,
    },
}

/// Unique parent endpoints retained across join after bootstrap I/O completed.
struct ParentBootstrapChannels {
    kind: ParentBootstrapChannelKind,
    _not_sync: PhantomData<Cell<()>>,
}

// SAFETY: each variant exclusively owns two non-inheritable process-wide named
// pipe handles. All in-flight bootstrap I/O is synchronously completed or
// cancelled-and-drained before this owner crosses the join boundary; the later
// confirmation read has not started yet. No method shares a handle or performs
// debugger-thread-affine work, and `Cell` keeps the owner deliberately `!Sync`.
unsafe impl Send for ParentBootstrapChannels {}

impl ParentBootstrapChannels {
    fn role(&self) -> HelperBootstrapRole {
        match self.kind {
            ParentBootstrapChannelKind::Approval { .. } => HelperBootstrapRole::Approval,
            ParentBootstrapChannelKind::SecretInput { .. } => HelperBootstrapRole::SecretInput,
        }
    }

    fn write_hello(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), ServiceProbeDebugGateError> {
        match &mut self.kind {
            ParentBootstrapChannelKind::Approval { request, .. } => request
                .write_bytes(bytes, deadline)
                .map_err(|_| ServiceProbeDebugGateError::Correlation),
            ParentBootstrapChannelKind::SecretInput { request, .. } => request
                .write_bytes(bytes, deadline)
                .map_err(|_| ServiceProbeDebugGateError::Correlation),
        }
    }

    fn read_ack(
        &self,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceProbeDebugGateError> {
        match &self.kind {
            ParentBootstrapChannelKind::Approval { response, .. } => response
                .as_ref()
                .ok_or(ServiceProbeDebugGateError::Correlation)?
                .read_exact(HELPER_ADOPTION_ACK_BYTES, deadline)
                .map_err(|_| ServiceProbeDebugGateError::Correlation),
            ParentBootstrapChannelKind::SecretInput { response, .. } => response
                .as_ref()
                .ok_or(ServiceProbeDebugGateError::Correlation)?
                .read_exact(HELPER_ADOPTION_ACK_BYTES, deadline)
                .map_err(|_| ServiceProbeDebugGateError::Correlation),
        }
    }

    fn read_exact_confirmation(
        &mut self,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceProbeDebugGateError> {
        match &mut self.kind {
            ParentBootstrapChannelKind::Approval { response, .. } => {
                let response = response
                    .take()
                    .ok_or(ServiceProbeDebugGateError::Correlation)?;
                let result = response
                    .read_exact_frame(HELPER_RPC_CONFIRMATION_BYTES, deadline)
                    .map(Zeroizing::new)
                    .map_err(|_| ServiceProbeDebugGateError::Correlation);
                // Keep the child's request reader open until the exact frame and
                // EOF observation has completed. The enclosing waiter continues
                // to own it after this method returns; this branch never moves
                // or drops the request field.
                result
            }
            ParentBootstrapChannelKind::SecretInput { response, .. } => {
                let response = response
                    .take()
                    .ok_or(ServiceProbeDebugGateError::Correlation)?;
                let result = response
                    .read_bounded_to_end(HELPER_RPC_CONFIRMATION_BYTES, deadline)
                    .map_err(|_| ServiceProbeDebugGateError::Correlation)
                    .and_then(|bytes| {
                        (bytes.len() == HELPER_RPC_CONFIRMATION_BYTES)
                            .then_some(bytes)
                            .ok_or(ServiceProbeDebugGateError::Correlation)
                    });
                // As above, the request field remains owned by the waiter
                // throughout the frame-plus-EOF read and afterward.
                result
            }
        }
    }
}

impl fmt::Debug for ParentBootstrapChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParentBootstrapChannels([REDACTED HANDLES])")
    }
}

/// Post-join owner for one role-typed helper confirmation channel pair.
///
/// Reading consumes only the response endpoint. The request writer remains
/// owned by this value so a helper that closes its response after its exact
/// role-specific exchange stays blocked on request input until the coordinator
/// has freshly checked admission/liveness and completed terminal cleanup.
/// Approval sends a request and receives a bound response after confirmation;
/// Secret Input closes immediately after its ready-only confirmation.
#[must_use = "retain the helper request writer through server-side admission"]
pub(super) struct ServiceHelperConfirmationWaiter {
    channels: ParentBootstrapChannels,
    expected: HelperRpcConfirmation,
    deadline: Instant,
    _not_sync: PhantomData<Cell<()>>,
}

impl ServiceHelperConfirmationWaiter {
    fn new(
        channels: ParentBootstrapChannels,
        expected: HelperRpcConfirmation,
        deadline: Instant,
    ) -> Self {
        Self {
            channels,
            expected,
            deadline,
            _not_sync: PhantomData,
        }
    }

    /// Returns the fixed bootstrap role carried only as correlation evidence.
    /// Server-side authority must still come from expected-peer admission.
    pub(super) fn role(&self) -> HelperBootstrapRole {
        self.expected.role()
    }

    /// Reads exactly one 72-byte confirmation plus EOF before the original
    /// two-gate coordination deadline. The retained request writer stays owned
    /// by `self` on both success and failure and a second read fails closed.
    pub(super) fn wait_for_confirmation(
        &mut self,
    ) -> Result<HelperRpcConfirmation, ServiceProbeDebugGateError> {
        let bytes = self.channels.read_exact_confirmation(self.deadline)?;
        let confirmation = HelperRpcConfirmation::decode(&bytes)
            .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
        confirmation
            .ensure_correlates_with(
                self.expected.epoch_nonce(),
                self.expected.request_id(),
                self.expected.role(),
            )
            .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
        Ok(confirmation)
    }

    /// Completes the Approval-only, non-signing transport experiment. The child
    /// keeps its response open after `HelperReady`, receives one framed canonical
    /// request, then closes it after one bound response. No decision escapes.
    pub(super) fn exchange_approval_probe(
        &mut self,
        approval: &approval_wire::ApprovalRequest,
    ) -> Result<(), ServiceProbeDebugGateError> {
        self.ensure_live_deadline()?;
        if self.expected.role() != HelperBootstrapRole::Approval {
            return Err(ServiceProbeDebugGateError::Correlation);
        }
        let ParentBootstrapChannelKind::Approval { request, response } = &mut self.channels.kind
        else {
            return Err(ServiceProbeDebugGateError::Correlation);
        };
        // Take once before any read; failure cannot replay this exchange. Keep
        // the request writer in self until the coordinator has killed/reaped.
        let response = response
            .take()
            .ok_or(ServiceProbeDebugGateError::Correlation)?;
        let confirmation = response
            .read_exact(HELPER_RPC_CONFIRMATION_BYTES, self.deadline)
            .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
        validate_probe_confirmation(&confirmation, &self.expected)?;
        let bytes = approval_wire::encode_request(approval);
        let prefix = encode_service_approval_request_prefix(bytes.len())
            .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
        request
            .write_bytes(&prefix, self.deadline)
            .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
        request
            .write_bytes(&bytes, self.deadline)
            .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
        // EOF is required while the process must still be running. A forced
        // process termination must not manufacture a successful response EOF.
        let bytes = response
            .read_exact_frame(approval_wire::RESPONSE_BYTES, self.deadline)
            .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
        validate_probe_response(&bytes, approval.digest(), approval.approval_nonce())?;
        self.ensure_live_deadline()
    }

    /// Rechecks the original absolute deadline, including after terminal cleanup.
    pub(super) fn ensure_live_deadline(&self) -> Result<(), ServiceProbeDebugGateError> {
        if Instant::now() >= self.deadline {
            return Err(ServiceProbeDebugGateError::Deadline);
        }
        Ok(())
    }
}

fn validate_probe_confirmation(
    bytes: &[u8],
    expected: &HelperRpcConfirmation,
) -> Result<(), ServiceProbeDebugGateError> {
    HelperRpcConfirmation::decode(bytes)
        .and_then(|confirmation| {
            confirmation.ensure_correlates_with(
                expected.epoch_nonce(),
                expected.request_id(),
                expected.role(),
            )
        })
        .map_err(|_| ServiceProbeDebugGateError::Correlation)
}

fn validate_probe_response(
    bytes: &[u8],
    expected_digest: &[u8; 32],
    expected_nonce: &[u8; 32],
) -> Result<(), ServiceProbeDebugGateError> {
    let response = approval_wire::decode_response(bytes)
        .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
    if response.digest() != expected_digest || response.approval_nonce() != expected_nonce {
        return Err(ServiceProbeDebugGateError::Correlation);
    }
    // Both decisions demonstrate transport only. Never return approval authority.
    Ok(())
}

impl fmt::Debug for ServiceHelperConfirmationWaiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceHelperConfirmationWaiter([REDACTED])")
    }
}

/// Sendable two-gate success owner that exposes no process or channel handle.
#[must_use = "consume the exact debugger-thread join proof"]
pub(super) struct PendingDebuggerExitServiceProbe {
    process: PendingServiceProbeDetach,
    confirmation: ServiceHelperConfirmationWaiter,
    expected_key: ExpectedPeerKey,
    _not_sync: PhantomData<Cell<()>>,
}

impl PendingDebuggerExitServiceProbe {
    pub(super) fn finish_after_debugger_exit(
        self,
        proof: DebuggerThreadExitProof,
    ) -> Result<DetachedServiceProbe, ServiceProbeDebugGateError> {
        let Self {
            process,
            confirmation,
            expected_key,
            _not_sync: _,
        } = self;
        let process = process
            .finish_after_debugger_exit(proof)
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        let expected_role = expected_role_for_channel(process.role(), confirmation.role())
            .ok_or(ServiceProbeDebugGateError::Correlation)?;
        Ok(DetachedServiceProbe {
            peer: DetachedExpectedServiceHelper {
                process,
                expected_key,
                expected_role,
                _not_sync: PhantomData,
            },
            confirmation,
            _not_sync: PhantomData,
        })
    }
}

impl fmt::Debug for PendingDebuggerExitServiceProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingDebuggerExitServiceProbe([REDACTED])")
    }
}

/// Post-join detached, explicitly suspended service-helper foundation.
///
/// Resident handle attenuation remains outside this type. Its only resume path
/// first registers and revalidates the exact suspended peer, then resumes once.
#[must_use = "the detached helper remains process-terminal on drop"]
pub(super) struct DetachedServiceProbe {
    peer: DetachedExpectedServiceHelper,
    confirmation: ServiceHelperConfirmationWaiter,
    _not_sync: PhantomData<Cell<()>>,
}

/// Process-only expected-peer owner moved into the admission registry.
///
/// No bootstrap pipe endpoint crosses this boundary. The independently owned
/// confirmation waiter therefore remains available to the launch coordinator
/// while RPC manager admission operates on the exact process owner.
#[must_use = "the detached helper remains process-terminal on drop"]
pub(crate) struct DetachedExpectedServiceHelper {
    process: DetachedSuspendedServiceProbe,
    expected_key: ExpectedPeerKey,
    expected_role: ExpectedHelperRole,
    _not_sync: PhantomData<Cell<()>>,
}

pub(crate) type ServiceHelperAdmission =
    ExpectedHelperAdmission<DetachedExpectedServiceHelper, ServiceCreatedLpacCandidate>;
pub(super) type ServiceHelperLease =
    ExpectedHelperLease<DetachedExpectedServiceHelper, ServiceCreatedLpacCandidate>;

impl DetachedServiceProbe {
    /// Registers the exact still-suspended service-created peer before the sole
    /// resume transition. No unregistered resume is exposed by this type.
    pub(super) fn register_revalidate_and_resume_once(
        self,
        admission: &ServiceHelperAdmission,
    ) -> Result<(ServiceHelperLease, ServiceHelperConfirmationWaiter), ExpectedPeerRegistryError>
    {
        let Self {
            peer,
            confirmation,
            _not_sync: _,
        } = self;
        let lease = admission
            .register_suspended(peer)?
            .revalidate_and_resume_once()?;
        Ok((lease, confirmation))
    }
}

impl DetachedExpectedServiceHelper {
    fn revalidate_role_binding(&self) -> Result<(), ExpectedPeerVerificationError> {
        let exact = matches!(
            (self.process.role(), self.expected_role),
            (ServiceProbeRole::Approval, ExpectedHelperRole::Approval)
                | (
                    ServiceProbeRole::SecretInput,
                    ExpectedHelperRole::SecretInput
                )
        );
        exact
            .then_some(())
            .ok_or(ExpectedPeerVerificationError::Denied)
    }
}

impl ExpectedHelperPeer<ServiceCreatedLpacCandidate> for DetachedExpectedServiceHelper {
    fn key(&self) -> ExpectedPeerKey {
        self.expected_key
    }

    fn session_id(&self) -> NonZeroU32 {
        self.process.session_id()
    }

    fn role(&self) -> ExpectedHelperRole {
        self.expected_role
    }

    fn revalidate_suspended(&self) -> Result<(), ExpectedPeerVerificationError> {
        self.process
            .revalidate_suspended()
            .map_err(|_| ExpectedPeerVerificationError::Internal)?;
        self.revalidate_role_binding()
    }

    fn resume_once(&mut self) -> Result<(), ExpectedPeerVerificationError> {
        self.process
            .resume_once()
            .map_err(|_| ExpectedPeerVerificationError::Internal)
    }

    fn exactly_matches(
        &self,
        candidate: &ServiceCreatedLpacCandidate,
    ) -> Result<bool, ExpectedPeerVerificationError> {
        candidate
            .exactly_matches_process(self.process.process_handle())
            .map_err(|_| ExpectedPeerVerificationError::Internal)
    }

    fn revalidate_running(&self) -> Result<(), ExpectedPeerVerificationError> {
        self.process
            .revalidate_running()
            .map_err(|_| ExpectedPeerVerificationError::Internal)?;
        self.revalidate_role_binding()
    }

    fn cancel(&mut self) -> Result<(), ExpectedPeerVerificationError> {
        self.process
            .terminate_and_reap()
            .map_err(|_| ExpectedPeerVerificationError::Internal)
    }
}

impl fmt::Debug for DetachedExpectedServiceHelper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.process;
        formatter.write_str("DetachedExpectedServiceHelper([REDACTED])")
    }
}

impl fmt::Debug for DetachedServiceProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.peer, &self.confirmation);
        formatter.write_str("DetachedServiceProbe([REDACTED])")
    }
}

fn expected_role_for_channel(
    process_role: ServiceProbeRole,
    channel_role: HelperBootstrapRole,
) -> Option<ExpectedHelperRole> {
    match (process_role, channel_role) {
        (ServiceProbeRole::Approval, HelperBootstrapRole::Approval) => {
            Some(ExpectedHelperRole::Approval)
        }
        (ServiceProbeRole::SecretInput, HelperBootstrapRole::SecretInput) => {
            Some(ExpectedHelperRole::SecretInput)
        }
        _ => None,
    }
}

/// Process-terminal gate failure returned by the debugger worker.
#[must_use = "join the debugger thread and complete the retained cleanup"]
pub(super) struct FailedServiceProbeDebugGate {
    cleanup: PendingServiceProbeCleanup,
    error: ServiceProbeDebugGateError,
}

impl FailedServiceProbeDebugGate {
    pub(super) const fn error(&self) -> ServiceProbeDebugGateError {
        self.error
    }

    pub(super) fn into_cleanup(self) -> PendingServiceProbeCleanup {
        self.cleanup
    }
}

impl fmt::Debug for FailedServiceProbeDebugGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FailedServiceProbeDebugGate([REDACTED])")
    }
}

/// A minimum-authority canonical owner used to authenticate a rejected event
/// alias after debugger-thread exit.
///
/// This owner never replaces the raw event word. It pins the exact object so a
/// post-join `CompareObjectHandles` can reject a different-object ABA before
/// the raw event alias is checked-closed. The feasibility slice remains
/// kernel-matrix-qualified: Windows offers no atomic compare-and-close, so a
/// kernel that retires and reuses the raw slot for another handle to the same
/// object is not supported.
struct CheckedCanonicalAlias {
    handle: HANDLE,
    #[cfg(test)]
    synthetic: bool,
    #[cfg(test)]
    synthetic_close_fails: bool,
}

// SAFETY: this wrapper uniquely owns one process-wide kernel handle. It has no
// thread-affine API, is accessed behind the registry mutex, and moves across a
// thread boundary only for post-join checked cleanup.
unsafe impl Send for CheckedCanonicalAlias {}

impl CheckedCanonicalAlias {
    fn from_windows(handle: HANDLE) -> Result<Self, ServiceProbeDebugGateError> {
        if invalid_handle(handle) {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        }
        Ok(Self {
            handle,
            #[cfg(test)]
            synthetic: false,
            #[cfg(test)]
            synthetic_close_fails: false,
        })
    }

    #[cfg(test)]
    fn synthetic(handle: HANDLE, close_fails: bool) -> Self {
        Self {
            handle,
            synthetic: true,
            synthetic_close_fails: close_fails,
        }
    }

    const fn raw(&self) -> HANDLE {
        self.handle
    }

    fn close_checked(&mut self) -> Result<(), ServiceProbeDebugGateError> {
        if invalid_handle(self.handle) {
            return Err(ServiceProbeDebugGateError::Cleanup);
        }
        #[cfg(test)]
        if self.synthetic {
            if self.synthetic_close_fails {
                return Err(ServiceProbeDebugGateError::Cleanup);
            }
            self.handle = HANDLE::default();
            return Ok(());
        }
        // SAFETY: OpenProcess/OpenThread returned this fresh, uniquely owned,
        // non-inheritable minimum-authority canonical handle.
        unsafe { CloseHandle(self.handle) }.map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        self.handle = HANDLE::default();
        Ok(())
    }
}

impl Drop for CheckedCanonicalAlias {
    fn drop(&mut self) {
        if invalid_handle(self.handle) {
            return;
        }
        #[cfg(test)]
        if self.synthetic {
            return;
        }
        // SAFETY: a failed explicit checked close leaves this exact canonical
        // owner armed for one ordinary RAII retry.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Raw debug-event aliases retained outside the debugger worker result.
///
/// Windows owns their lifetime while the debugger remains attached. Numeric
/// words are registered before every fallible identity check. Rejected-event
/// words additionally retain exact minimum-authority canonical object owners.
struct DetachedDebugEventAliases {
    process: Option<usize>,
    primary_thread: Option<usize>,
    rejected_thread: Option<usize>,
    rejected_process: Option<usize>,
    rejected_primary_thread: Option<usize>,
    process_id: u32,
    primary_thread_id: u32,
    process_alias_id: Option<u32>,
    primary_thread_alias_process_id: Option<u32>,
    primary_thread_alias_id: Option<u32>,
    rejected_thread_id: Option<u32>,
    rejected_thread_process_id: Option<u32>,
    rejected_thread_anchor: Option<CheckedCanonicalAlias>,
    rejected_process_id: Option<u32>,
    rejected_process_anchor: Option<CheckedCanonicalAlias>,
    rejected_primary_thread_id: Option<u32>,
    rejected_primary_thread_process_id: Option<u32>,
    rejected_primary_thread_anchor: Option<CheckedCanonicalAlias>,
}

impl DetachedDebugEventAliases {
    fn blank(process_id: u32, primary_thread_id: u32) -> Self {
        Self {
            process: None,
            primary_thread: None,
            rejected_thread: None,
            rejected_process: None,
            rejected_primary_thread: None,
            process_id,
            primary_thread_id,
            process_alias_id: None,
            primary_thread_alias_process_id: None,
            primary_thread_alias_id: None,
            rejected_thread_id: None,
            rejected_thread_process_id: None,
            rejected_thread_anchor: None,
            rejected_process_id: None,
            rejected_process_anchor: None,
            rejected_primary_thread_id: None,
            rejected_primary_thread_process_id: None,
            rejected_primary_thread_anchor: None,
        }
    }

    fn complete(&self) -> bool {
        matches!(
            (self.process, self.primary_thread),
            (Some(process), Some(thread)) if process != thread
        ) && self.process_id != 0
            && self.primary_thread_id != 0
            && self.process_alias_id == Some(self.process_id)
            && self.primary_thread_alias_process_id == Some(self.process_id)
            && self.primary_thread_alias_id == Some(self.primary_thread_id)
            && self.rejected_thread.is_none()
            && self.rejected_process.is_none()
            && self.rejected_primary_thread.is_none()
            && self.rejected_thread_id.is_none()
            && self.rejected_thread_process_id.is_none()
            && self.rejected_thread_anchor.is_none()
            && self.rejected_process_id.is_none()
            && self.rejected_process_anchor.is_none()
            && self.rejected_primary_thread_id.is_none()
            && self.rejected_primary_thread_process_id.is_none()
            && self.rejected_primary_thread_anchor.is_none()
    }

    fn empty(&self) -> bool {
        self.process.is_none()
            && self.primary_thread.is_none()
            && self.rejected_thread.is_none()
            && self.rejected_process.is_none()
            && self.rejected_primary_thread.is_none()
            && self.process_alias_id.is_none()
            && self.primary_thread_alias_process_id.is_none()
            && self.primary_thread_alias_id.is_none()
            && self.rejected_thread_id.is_none()
            && self.rejected_thread_process_id.is_none()
            && self.rejected_thread_anchor.is_none()
            && self.rejected_process_id.is_none()
            && self.rejected_process_anchor.is_none()
            && self.rejected_primary_thread_id.is_none()
            && self.rejected_primary_thread_process_id.is_none()
            && self.rejected_primary_thread_anchor.is_none()
    }

    fn has_rejected_authority(&self) -> bool {
        self.rejected_thread.is_some()
            || self.rejected_process.is_some()
            || self.rejected_primary_thread.is_some()
            || self.rejected_thread_id.is_some()
            || self.rejected_thread_process_id.is_some()
            || self.rejected_thread_anchor.is_some()
            || self.rejected_process_id.is_some()
            || self.rejected_process_anchor.is_some()
            || self.rejected_primary_thread_id.is_some()
            || self.rejected_primary_thread_process_id.is_some()
            || self.rejected_primary_thread_anchor.is_some()
    }
}

fn repeated_rejected_registration_requires_fail_fast(
    aliases: Option<&DetachedDebugEventAliases>,
) -> bool {
    aliases.is_some_and(DetachedDebugEventAliases::has_rejected_authority)
}

#[derive(Clone, Copy)]
struct ThreadAliasIdentity {
    process_id: u32,
    thread_id: u32,
}

trait DebugEventAliasIdentityApi {
    fn process_id(&self, handle: HANDLE) -> Option<u32>;

    fn thread_identity(&self, handle: HANDLE) -> Option<ThreadAliasIdentity>;

    fn open_process_anchor(
        &self,
        event_handle: HANDLE,
        process_id: u32,
    ) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError>;

    fn open_thread_anchor(
        &self,
        event_handle: HANDLE,
        identity: ThreadAliasIdentity,
    ) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError>;

    fn same_object(&self, first: HANDLE, second: HANDLE) -> bool;
}

struct WindowsDebugEventAliasIdentityApi;

impl DebugEventAliasIdentityApi for WindowsDebugEventAliasIdentityApi {
    fn process_id(&self, handle: HANDLE) -> Option<u32> {
        // SAFETY: the caller holds the debug event that supplied this handle.
        let process_id = unsafe { GetProcessId(handle) };
        (process_id != 0 && handle_flags_are_zero(handle)).then_some(process_id)
    }

    fn thread_identity(&self, handle: HANDLE) -> Option<ThreadAliasIdentity> {
        // SAFETY: the caller holds the debug event that supplied this handle.
        let thread_id = unsafe { GetThreadId(handle) };
        // SAFETY: same held-event lifetime argument.
        let process_id = unsafe { GetProcessIdOfThread(handle) };
        (thread_id != 0 && process_id != 0 && handle_flags_are_zero(handle)).then_some(
            ThreadAliasIdentity {
                process_id,
                thread_id,
            },
        )
    }

    fn open_process_anchor(
        &self,
        _event_handle: HANDLE,
        process_id: u32,
    ) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError> {
        // SAFETY: the observed nonzero PID belongs to the still-held event
        // alias. FALSE requests a non-inheritable minimum-query owner.
        let opened = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
            .map_err(|_| ServiceProbeDebugGateError::EventIdentity)?;
        CheckedCanonicalAlias::from_windows(opened)
    }

    fn open_thread_anchor(
        &self,
        _event_handle: HANDLE,
        identity: ThreadAliasIdentity,
    ) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError> {
        // SAFETY: the observed nonzero TID belongs to the still-held event
        // alias. FALSE requests a non-inheritable minimum-query owner.
        let opened =
            unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, identity.thread_id) }
                .map_err(|_| ServiceProbeDebugGateError::EventIdentity)?;
        CheckedCanonicalAlias::from_windows(opened)
    }

    fn same_object(&self, first: HANDLE, second: HANDLE) -> bool {
        // SAFETY: the caller retains both live handles for this observation.
        unsafe { CompareObjectHandles(first, second) }.as_bool()
    }
}

fn retain_process_anchor<Api: DebugEventAliasIdentityApi>(
    api: &Api,
    event_handle: HANDLE,
    process_id: u32,
) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError> {
    let mut owner = api.open_process_anchor(event_handle, process_id)?;
    let proof = (owner.raw() != event_handle
        && api.process_id(owner.raw()) == Some(process_id)
        && api.same_object(owner.raw(), event_handle))
    .then_some(())
    .ok_or(ServiceProbeDebugGateError::EventIdentity);
    if let Err(error) = proof {
        owner.close_checked()?;
        return Err(error);
    }
    Ok(owner)
}

fn retain_thread_anchor<Api: DebugEventAliasIdentityApi>(
    api: &Api,
    event_handle: HANDLE,
    identity: ThreadAliasIdentity,
) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError> {
    let mut owner = api.open_thread_anchor(event_handle, identity)?;
    let proof = (owner.raw() != event_handle
        && api.thread_identity(owner.raw()).is_some_and(|observed| {
            observed.process_id == identity.process_id && observed.thread_id == identity.thread_id
        })
        && api.same_object(owner.raw(), event_handle))
    .then_some(())
    .ok_or(ServiceProbeDebugGateError::EventIdentity);
    if let Err(error) = proof {
        owner.close_checked()?;
        return Err(error);
    }
    Ok(owner)
}

/// Join-surviving registry for high-authority handles supplied by debug events.
///
/// The registry is allocated by the caller of the fresh-thread runner before
/// the worker exists. Consequently worker `Err`, panic, or output abandonment
/// cannot discard aliases before the caller observes an exact join.
pub(super) struct ServiceProbeDebugEventCleanup {
    joined: AtomicBool,
    close_authorized: AtomicBool,
    aliases: Mutex<Option<DetachedDebugEventAliases>>,
}

#[cfg(test)]
type RegisteredRejectedWords = (Option<usize>, Option<usize>, Option<usize>);

impl ServiceProbeDebugEventCleanup {
    pub(super) fn new_shared() -> Arc<Self> {
        Arc::new(Self {
            joined: AtomicBool::new(false),
            close_authorized: AtomicBool::new(false),
            aliases: Mutex::new(None),
        })
    }

    /// Marks the exact worker as joined. This is a single infallible atomic
    /// phase transition performed by the outer runner after `JoinHandle::join`.
    pub(super) fn mark_joined(&self) {
        self.joined.store(true, Ordering::Release);
    }

    pub(super) fn debugger_thread_has_joined(&self) -> bool {
        self.joined.load(Ordering::Acquire)
    }

    pub(super) fn require_empty_after_join(&self) -> Result<(), ServiceProbeDebugGateError> {
        if !self.joined.load(Ordering::Acquire) {
            return Err(ServiceProbeDebugGateError::JoinProof);
        }
        let slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        if slot.is_none() {
            Ok(())
        } else {
            Err(ServiceProbeDebugGateError::Cleanup)
        }
    }

    fn register_create_process_aliases(
        &self,
        process: HANDLE,
        primary_thread: HANDLE,
        creator_process: HANDLE,
        creator_primary_thread: HANDLE,
        process_id: u32,
        primary_thread_id: u32,
    ) -> Result<(), ServiceProbeDebugGateError> {
        self.register_create_process_aliases_with(
            &WindowsDebugEventAliasIdentityApi,
            process,
            primary_thread,
            creator_process,
            creator_primary_thread,
            process_id,
            primary_thread_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_create_process_aliases_with<Api: DebugEventAliasIdentityApi>(
        &self,
        api: &Api,
        process: HANDLE,
        primary_thread: HANDLE,
        creator_process: HANDLE,
        creator_primary_thread: HANDLE,
        process_id: u32,
        primary_thread_id: u32,
    ) -> Result<(), ServiceProbeDebugGateError> {
        let creator_process = raw_handle_word(creator_process)?;
        let creator_primary_thread = raw_handle_word(creator_primary_thread)?;
        let process_word = raw_handle_word(process)
            .ok()
            .filter(|value| *value != creator_process && *value != creator_primary_thread);
        let mut primary_thread_word = raw_handle_word(primary_thread)
            .ok()
            .filter(|value| *value != creator_process && *value != creator_primary_thread);
        if primary_thread_word == process_word {
            primary_thread_word = None;
        }
        let mut aliases = DetachedDebugEventAliases::blank(process_id, primary_thread_id);
        aliases.process = process_word;
        aliases.primary_thread = primary_thread_word;
        if self.joined.load(Ordering::Acquire) || aliases.empty() {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        }
        let mut slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        if slot.is_some() {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        }
        *slot = Some(aliases);
        let aliases = slot.as_mut().ok_or(ServiceProbeDebugGateError::Cleanup)?;
        if aliases.process.is_some() {
            aliases.process_alias_id = api.process_id(process);
        }
        if aliases.primary_thread.is_some() {
            let identity = api.thread_identity(primary_thread);
            aliases.primary_thread_alias_process_id = identity.map(|value| value.process_id);
            aliases.primary_thread_alias_id = identity.map(|value| value.thread_id);
        }
        if aliases.complete() {
            Ok(())
        } else {
            Err(ServiceProbeDebugGateError::EventIdentity)
        }
    }

    fn register_rejected_thread_alias(
        &self,
        process_id: u32,
        primary_thread_id: u32,
        rejected_thread_id: u32,
        rejected_thread: HANDLE,
        creator_process: HANDLE,
        creator_primary_thread: HANDLE,
    ) -> Result<(), ServiceProbeDebugGateError> {
        self.register_rejected_thread_alias_with(
            &WindowsDebugEventAliasIdentityApi,
            process_id,
            primary_thread_id,
            rejected_thread_id,
            rejected_thread,
            creator_process,
            creator_primary_thread,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_rejected_thread_alias_with<Api: DebugEventAliasIdentityApi>(
        &self,
        api: &Api,
        process_id: u32,
        primary_thread_id: u32,
        rejected_thread_id: u32,
        rejected_thread: HANDLE,
        creator_process: HANDLE,
        creator_primary_thread: HANDLE,
    ) -> Result<(), ServiceProbeDebugGateError> {
        let rejected_thread = raw_handle_word(rejected_thread)?;
        let mut slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        if repeated_rejected_registration_requires_fail_fast(slot.as_ref()) {
            // A second held rejection owns fresh event authority that cannot
            // replace the first raw/canonical set. Process-wide exit is the
            // only transition that reclaims both generations without loss.
            windows_fail_fast();
        }
        let creator_process = raw_handle_word(creator_process)?;
        let creator_primary_thread = raw_handle_word(creator_primary_thread)?;
        if self.joined.load(Ordering::Acquire)
            || rejected_thread == creator_process
            || rejected_thread == creator_primary_thread
        {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        }
        let missing_primary_event = slot.is_none();
        if missing_primary_event {
            *slot = Some(DetachedDebugEventAliases::blank(
                process_id,
                primary_thread_id,
            ));
        }
        let aliases = slot.as_mut().ok_or(ServiceProbeDebugGateError::Cleanup)?;
        if [
            aliases.process,
            aliases.primary_thread,
            aliases.rejected_thread,
            aliases.rejected_process,
            aliases.rejected_primary_thread,
        ]
        .contains(&Some(rejected_thread))
        {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        }
        aliases.rejected_thread = Some(rejected_thread);
        let event_handle = HANDLE(rejected_thread as *mut core::ffi::c_void);
        let Some(identity) = api.thread_identity(event_handle) else {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        };
        aliases.rejected_thread_id = Some(identity.thread_id);
        aliases.rejected_thread_process_id = Some(identity.process_id);
        let anchor = retain_thread_anchor(api, event_handle, identity)?;
        aliases.rejected_thread_anchor = Some(anchor);
        let semantic_matches = !missing_primary_event
            && aliases.process_id == process_id
            && aliases.primary_thread_id == primary_thread_id
            && rejected_thread_id != 0
            && rejected_thread_id != primary_thread_id
            && identity.process_id == process_id
            && identity.thread_id == rejected_thread_id;
        if semantic_matches {
            Ok(())
        } else if missing_primary_event {
            Err(ServiceProbeDebugGateError::UnexpectedEvent)
        } else {
            Err(ServiceProbeDebugGateError::EventIdentity)
        }
    }

    fn register_rejected_process_aliases(
        &self,
        process: HANDLE,
        primary_thread: HANDLE,
        creator_process: HANDLE,
        creator_primary_thread: HANDLE,
        rejected_process_id: u32,
        rejected_primary_thread_id: u32,
    ) -> Result<(), ServiceProbeDebugGateError> {
        self.register_rejected_process_aliases_with(
            &WindowsDebugEventAliasIdentityApi,
            process,
            primary_thread,
            creator_process,
            creator_primary_thread,
            rejected_process_id,
            rejected_primary_thread_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_rejected_process_aliases_with<Api: DebugEventAliasIdentityApi>(
        &self,
        api: &Api,
        process: HANDLE,
        primary_thread: HANDLE,
        creator_process: HANDLE,
        creator_primary_thread: HANDLE,
        rejected_process_id: u32,
        rejected_primary_thread_id: u32,
    ) -> Result<(), ServiceProbeDebugGateError> {
        let mut process_word = raw_handle_word(process).ok();
        let mut primary_thread_word = raw_handle_word(primary_thread).ok();
        if process_word.is_none() && primary_thread_word.is_none() {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        }
        let mut slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        if repeated_rejected_registration_requires_fail_fast(slot.as_ref()) {
            // Never overwrite an earlier rejected raw word or its canonical
            // owner. The newly held event makes recovery ambiguous, so abort
            // while the complete process handle table still contains both.
            windows_fail_fast();
        }
        if self.joined.load(Ordering::Acquire) {
            return Err(ServiceProbeDebugGateError::JoinProof);
        }
        let creator_process = raw_handle_word(creator_process)?;
        let creator_primary_thread = raw_handle_word(creator_primary_thread)?;
        let occupied = slot.as_ref().map_or([None; 5], |aliases| {
            [
                aliases.process,
                aliases.primary_thread,
                aliases.rejected_thread,
                aliases.rejected_process,
                aliases.rejected_primary_thread,
            ]
        });
        let missing_primary_event = slot.is_none();
        process_word = process_word.filter(|value| {
            *value != creator_process
                && *value != creator_primary_thread
                && !occupied.contains(&Some(*value))
        });
        primary_thread_word = primary_thread_word.filter(|value| {
            *value != creator_process
                && *value != creator_primary_thread
                && !occupied.contains(&Some(*value))
                && process_word != Some(*value)
        });
        if process_word.is_none() && primary_thread_word.is_none() {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        }
        if slot.is_none() {
            *slot = Some(DetachedDebugEventAliases::blank(0, 0));
        }
        let aliases = slot.as_mut().ok_or(ServiceProbeDebugGateError::Cleanup)?;
        aliases.rejected_process = process_word;
        aliases.rejected_primary_thread = primary_thread_word;
        let process_proof = process_word.map_or(Ok(None), |word| {
            let handle = HANDLE(word as *mut core::ffi::c_void);
            let identity = api
                .process_id(handle)
                .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
            aliases.rejected_process_id = Some(identity);
            let anchor = retain_process_anchor(api, handle, identity)?;
            aliases.rejected_process_anchor = Some(anchor);
            Ok(Some(identity))
        });
        let thread_proof = primary_thread_word.map_or(Ok(None), |word| {
            let handle = HANDLE(word as *mut core::ffi::c_void);
            let identity = api
                .thread_identity(handle)
                .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
            aliases.rejected_primary_thread_id = Some(identity.thread_id);
            aliases.rejected_primary_thread_process_id = Some(identity.process_id);
            let anchor = retain_thread_anchor(api, handle, identity)?;
            aliases.rejected_primary_thread_anchor = Some(anchor);
            Ok(Some(identity))
        });
        if matches!(process_proof, Err(ServiceProbeDebugGateError::Cleanup))
            || matches!(thread_proof, Err(ServiceProbeDebugGateError::Cleanup))
        {
            return Err(ServiceProbeDebugGateError::Cleanup);
        }
        let process_identity = process_proof?;
        let thread_identity = thread_proof?;
        let semantic_matches = !missing_primary_event
            && rejected_process_id != 0
            && rejected_primary_thread_id != 0
            && process_identity == Some(rejected_process_id)
            && thread_identity.is_some_and(|identity| {
                identity.process_id == rejected_process_id
                    && identity.thread_id == rejected_primary_thread_id
            });
        if aliases.rejected_process.is_some()
            && aliases.rejected_primary_thread.is_some()
            && semantic_matches
        {
            Ok(())
        } else if missing_primary_event {
            Err(ServiceProbeDebugGateError::UnexpectedEvent)
        } else {
            Err(ServiceProbeDebugGateError::EventIdentity)
        }
    }

    fn verify_complete_while_attached(
        &self,
        process_id: u32,
        primary_thread_id: u32,
    ) -> Result<(), ServiceProbeDebugGateError> {
        if self.joined.load(Ordering::Acquire) {
            return Err(ServiceProbeDebugGateError::JoinProof);
        }
        let slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        let aliases = slot
            .as_ref()
            .filter(|aliases| {
                aliases.complete()
                    && aliases.process_id == process_id
                    && aliases.primary_thread_id == primary_thread_id
            })
            .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
        let _ = aliases;
        Ok(())
    }

    fn contains_handle_while_attached(
        &self,
        handle: HANDLE,
    ) -> Result<bool, ServiceProbeDebugGateError> {
        if self.joined.load(Ordering::Acquire) {
            return Err(ServiceProbeDebugGateError::JoinProof);
        }
        let word = raw_handle_word(handle)?;
        let slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        Ok(slot.as_ref().is_some_and(|aliases| {
            [
                aliases.process,
                aliases.primary_thread,
                aliases.rejected_thread,
                aliases.rejected_process,
                aliases.rejected_primary_thread,
            ]
            .contains(&Some(word))
        }))
    }

    /// Authorizes post-join alias adoption only after the caller has proved
    /// that the exact retained creator process is no longer debug-attached.
    pub(super) fn authorize_after_debugger_absence(
        &self,
        process_id: u32,
        primary_thread_id: u32,
    ) -> Result<(), ServiceProbeDebugGateError> {
        if !self.joined.load(Ordering::Acquire) {
            return Err(ServiceProbeDebugGateError::JoinProof);
        }
        let slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        let aliases = slot
            .as_ref()
            .filter(|aliases| {
                aliases.complete()
                    && aliases.process_id == process_id
                    && aliases.primary_thread_id == primary_thread_id
            })
            .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
        let _ = aliases;
        self.close_authorized.store(true, Ordering::Release);
        Ok(())
    }

    /// Authorizes partial-prefix alias cleanup only after the exact process and
    /// one-process Job have both been proved terminal after debugger join.
    pub(super) fn authorize_after_process_terminal(
        &self,
    ) -> Result<(), ServiceProbeDebugGateError> {
        if !self.joined.load(Ordering::Acquire) {
            return Err(ServiceProbeDebugGateError::JoinProof);
        }
        let slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        drop(slot);
        self.close_authorized.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) fn close_after_join(
        &self,
        creator_process: BorrowedHandle<'_>,
        creator_primary_thread: BorrowedHandle<'_>,
    ) -> Result<(), ServiceProbeDebugGateError> {
        if !self.joined.load(Ordering::Acquire) || !self.close_authorized.load(Ordering::Acquire) {
            return Err(ServiceProbeDebugGateError::JoinProof);
        }
        let mut slot = match self.aliases.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(aliases) = slot.as_mut() {
            close_detached_aliases(
                aliases,
                Some(windows_handle(creator_process)),
                Some(windows_handle(creator_primary_thread)),
            )?;
            if aliases.empty() {
                *slot = None;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn registered_primary_words_for_test(
        &self,
    ) -> Result<(Option<usize>, Option<usize>), ServiceProbeDebugGateError> {
        let slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        let aliases = slot
            .as_ref()
            .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
        Ok((aliases.process, aliases.primary_thread))
    }

    #[cfg(test)]
    fn registered_rejected_words_for_test(
        &self,
    ) -> Result<RegisteredRejectedWords, ServiceProbeDebugGateError> {
        let slot = self
            .aliases
            .lock()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        let aliases = slot
            .as_ref()
            .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
        Ok((
            aliases.rejected_thread,
            aliases.rejected_process,
            aliases.rejected_primary_thread,
        ))
    }

    #[cfg(test)]
    fn disarm_synthetic_aliases_for_test(&self) {
        let mut slot = self
            .aliases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = None;
    }
}

fn cleanup_registry_drop_is_safe(poisoned: bool, aliases_remain: bool) -> bool {
    !poisoned && !aliases_remain
}

impl Drop for ServiceProbeDebugEventCleanup {
    fn drop(&mut self) {
        let safe = match self.aliases.get_mut() {
            Ok(slot) => cleanup_registry_drop_is_safe(false, slot.is_some()),
            Err(_) => cleanup_registry_drop_is_safe(true, true),
        };
        if !safe {
            // Never silently lose a registered high-authority event word or a
            // poisoned ownership record. Process-wide termination is the only
            // universally safe cleanup when exact checked close did not clear
            // the last registry owner.
            windows_fail_fast();
        }
    }
}

impl fmt::Debug for ServiceProbeDebugEventCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeDebugEventCleanup([REDACTED])")
    }
}

fn raw_handle_word(handle: HANDLE) -> Result<usize, ServiceProbeDebugGateError> {
    let value = handle.0 as usize;
    if value == 0 || value > isize::MAX.cast_unsigned() {
        return Err(ServiceProbeDebugGateError::EventIdentity);
    }
    Ok(value)
}

#[allow(clippy::too_many_lines)]
fn close_detached_aliases(
    aliases: &mut DetachedDebugEventAliases,
    creator_process: Option<HANDLE>,
    creator_primary_thread: Option<HANDLE>,
) -> Result<(), ServiceProbeDebugGateError> {
    let mut failed = false;

    failed |= !close_anchored_thread_alias(
        &mut aliases.rejected_thread,
        &mut aliases.rejected_thread_id,
        &mut aliases.rejected_thread_process_id,
        &mut aliases.rejected_thread_anchor,
        Some(aliases.primary_thread_id),
    );
    failed |= !close_anchored_thread_alias(
        &mut aliases.rejected_primary_thread,
        &mut aliases.rejected_primary_thread_id,
        &mut aliases.rejected_primary_thread_process_id,
        &mut aliases.rejected_primary_thread_anchor,
        None,
    );
    failed |= !close_anchored_process_alias(
        &mut aliases.rejected_process,
        &mut aliases.rejected_process_id,
        &mut aliases.rejected_process_anchor,
    );

    if let Some(value) = aliases.primary_thread {
        let handle = HANDLE(value as *mut core::ffi::c_void);
        let same_creator = creator_primary_thread.is_some_and(|creator| {
            // SAFETY: explicit finalization retains both exact live handles.
            unsafe { CompareObjectHandles(creator, handle) }.as_bool()
        });
        // SAFETY: these APIs interpret the registered numeric word only as a
        // kernel handle; exact creator comparison, IDs, and flags must all pass
        // before the matrix-qualified CloseHandle below.
        let valid = aliases.process_id != 0
            && aliases.primary_thread_id != 0
            // SAFETY: post-join authorization retains the exact creator and
            // this registered raw event alias until checked close.
            && unsafe { GetThreadId(handle) } == aliases.primary_thread_id
            // SAFETY: same retained-alias lifetime argument.
            && unsafe { GetProcessIdOfThread(handle) } == aliases.process_id
            && same_creator
            && handle_flags_are_zero(handle);
        if valid && close_registered_alias(handle) {
            aliases.primary_thread = None;
            aliases.primary_thread_alias_id = None;
            aliases.primary_thread_alias_process_id = None;
        } else {
            failed = true;
        }
    } else if aliases.primary_thread_alias_id.is_some()
        || aliases.primary_thread_alias_process_id.is_some()
    {
        failed = true;
    }

    if let Some(value) = aliases.process {
        let handle = HANDLE(value as *mut core::ffi::c_void);
        let same_creator = creator_process.is_some_and(|creator| {
            // SAFETY: explicit finalization retains both exact live handles.
            unsafe { CompareObjectHandles(creator, handle) }.as_bool()
        });
        // SAFETY: these APIs interpret the registered numeric word only as a
        // kernel handle; exact creator comparison, ID, and flags must all pass
        // before the matrix-qualified CloseHandle below.
        let valid = aliases.process_id != 0
            // SAFETY: post-join authorization retains the exact creator and
            // this registered raw event alias until checked close.
            && unsafe { GetProcessId(handle) } == aliases.process_id
            && same_creator
            && handle_flags_are_zero(handle);
        if valid && close_registered_alias(handle) {
            aliases.process = None;
            aliases.process_alias_id = None;
        } else {
            failed = true;
        }
    } else if aliases.process_alias_id.is_some() {
        failed = true;
    }

    if failed {
        Err(ServiceProbeDebugGateError::Cleanup)
    } else {
        Ok(())
    }
}

fn close_anchored_thread_alias(
    raw: &mut Option<usize>,
    thread_id: &mut Option<u32>,
    process_id: &mut Option<u32>,
    anchor: &mut Option<CheckedCanonicalAlias>,
    forbidden_thread_id: Option<u32>,
) -> bool {
    if let Some(value) = *raw {
        let handle = HANDLE(value as *mut core::ffi::c_void);
        let valid = thread_id.zip(*process_id).zip(anchor.as_ref()).is_some_and(
            |((thread_id, process_id), anchor)| {
                forbidden_thread_id != Some(thread_id)
                    // SAFETY: post-join authorization retains both the raw
                    // event alias and its canonical object owner.
                    && unsafe { GetThreadId(handle) } == thread_id
                    // SAFETY: same two live-handle argument.
                    && unsafe { GetProcessIdOfThread(handle) } == process_id
                    // SAFETY: the canonical minimum-query owner is live.
                    && unsafe { GetThreadId(anchor.raw()) } == thread_id
                    // SAFETY: same canonical-owner lifetime argument.
                    && unsafe { GetProcessIdOfThread(anchor.raw()) } == process_id
                    && handle_flags_are_zero(handle)
                    && handle_flags_are_zero(anchor.raw())
                    // SAFETY: both handles remain live across this exact
                    // comparison. The feasibility slice separately records
                    // the non-atomic same-object slot-reuse limitation.
                    && unsafe { CompareObjectHandles(anchor.raw(), handle) }.as_bool()
            },
        );
        if !valid || !close_registered_alias(handle) {
            return false;
        }
        *raw = None;
    }
    if raw.is_none()
        && let Some(owner) = anchor.as_mut()
    {
        if owner.close_checked().is_err() {
            return false;
        }
        *anchor = None;
    }
    if raw.is_none() && anchor.is_none() {
        *thread_id = None;
        *process_id = None;
        true
    } else {
        false
    }
}

fn close_anchored_process_alias(
    raw: &mut Option<usize>,
    process_id: &mut Option<u32>,
    anchor: &mut Option<CheckedCanonicalAlias>,
) -> bool {
    if let Some(value) = *raw {
        let handle = HANDLE(value as *mut core::ffi::c_void);
        let valid = process_id
            .zip(anchor.as_ref())
            .is_some_and(|(process_id, anchor)| {
                // SAFETY: post-join authorization retains both the raw event
                // alias and its canonical object owner.
                (unsafe { GetProcessId(handle) }) == process_id
                    // SAFETY: the canonical minimum-query owner is live.
                    && unsafe { GetProcessId(anchor.raw()) } == process_id
                    && handle_flags_are_zero(handle)
                    && handle_flags_are_zero(anchor.raw())
                    // SAFETY: both handles remain live across this comparison;
                    // see the feasibility-only non-atomic limitation above.
                    && unsafe { CompareObjectHandles(anchor.raw(), handle) }.as_bool()
            });
        if !valid || !close_registered_alias(handle) {
            return false;
        }
        *raw = None;
    }
    if raw.is_none()
        && let Some(owner) = anchor.as_mut()
    {
        if owner.close_checked().is_err() {
            return false;
        }
        *anchor = None;
    }
    if raw.is_none() && anchor.is_none() {
        *process_id = None;
        true
    } else {
        false
    }
}

fn handle_flags_are_zero(handle: HANDLE) -> bool {
    let mut flags = u32::MAX;
    // SAFETY: caller supplies one registered post-join alias and exact writable
    // initialized flag storage.
    unsafe { GetHandleInformation(handle, &raw mut flags) }.is_ok() && flags == 0
}

fn close_registered_alias(handle: HANDLE) -> bool {
    // SAFETY: the alias passed all kind, identifier, flag, and optional creator
    // object checks after the exact debugger-thread join was authorized.
    unsafe { CloseHandle(handle) }.is_ok()
}

fn cleanup_result_dominates<T>(
    semantic: Result<T, ServiceProbeDebugGateError>,
    cleanup: Result<(), ServiceProbeDebugGateError>,
) -> Result<T, ServiceProbeDebugGateError> {
    match cleanup {
        Ok(()) => semantic,
        Err(cleanup_error) => Err(cleanup_error),
    }
}

fn merge_authority_errors(
    first: Option<ServiceProbeDebugGateError>,
    second: ServiceProbeDebugGateError,
) -> ServiceProbeDebugGateError {
    if first == Some(ServiceProbeDebugGateError::Cleanup)
        || second == ServiceProbeDebugGateError::Cleanup
    {
        ServiceProbeDebugGateError::Cleanup
    } else {
        first.unwrap_or(second)
    }
}

fn authenticate_loader_event_then_increment<Authenticate>(
    current_count: usize,
    authenticate_and_close: Authenticate,
) -> Result<usize, ServiceProbeDebugGateError>
where
    Authenticate: FnOnce() -> Result<(), ServiceProbeDebugGateError>,
{
    // The held event's optional hFile must be adopted and checked-closed even
    // when this event will exceed the semantic loader-event bound. Any checked
    // cleanup failure therefore dominates the later count rejection.
    authenticate_and_close()?;
    current_count
        .checked_add(1)
        .filter(|count| *count <= MAX_LOADER_DEBUG_EVENTS)
        .ok_or(ServiceProbeDebugGateError::UnexpectedEvent)
}

/// Stable, data-free failures from the dormant parent debugger gate.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum ServiceProbeDebugGateError {
    /// The single coordination deadline was zero, too large, or expired.
    #[error("service helper debugger coordination timed out")]
    Deadline,
    /// A debug event did not match the closed two-gate protocol.
    #[error("service helper debugger received an unexpected event")]
    UnexpectedEvent,
    /// Event identifiers or event-supplied handles did not bind to creation.
    #[error("service helper debug-event identity was rejected")]
    EventIdentity,
    /// The mapped main image or trusted system loader identity changed.
    #[error("service helper debug image identity was rejected")]
    ImageIdentity,
    /// Remote gate bytes, page policy, instruction pointer, or markers differed.
    #[error("service helper cooperative gate was rejected")]
    GateAuthentication,
    /// The role-typed private channel injection boundary failed.
    #[error("service helper channel injection failed")]
    Channel,
    /// The exact hello or acknowledgement frame was unavailable or mismatched.
    #[error("service helper bootstrap correlation failed")]
    Correlation,
    /// The explicit primary-thread suspend count was not exact.
    #[error("service helper suspend count was not exact")]
    Suspension,
    /// Live/debug-attached state or the no-kill detach preparation changed.
    #[error("service helper debugger detach state was rejected")]
    Detach,
    /// The supplied join proof did not belong to this exact worker.
    #[error("service helper debugger join proof was rejected")]
    JoinProof,
    /// Process-terminal or detached event-handle cleanup was incomplete.
    #[error("service helper debugger cleanup was incomplete")]
    Cleanup,
}

#[derive(Clone, Copy)]
struct CoordinationDeadline {
    instant: Instant,
    tick_count_milliseconds: NonZeroU64,
}

impl CoordinationDeadline {
    fn start(timeout_milliseconds: NonZeroU32) -> Result<Self, ServiceProbeDebugGateError> {
        if timeout_milliseconds.get() > MAX_COORDINATION_MILLISECONDS {
            return Err(ServiceProbeDebugGateError::Deadline);
        }
        let timeout = Duration::from_millis(u64::from(timeout_milliseconds.get()));
        let instant = Instant::now()
            .checked_add(timeout)
            .ok_or(ServiceProbeDebugGateError::Deadline)?;
        // SAFETY: GetTickCount64 is a process-independent monotonic scalar
        // observation with no pointer or handle preconditions.
        let now_tick = unsafe { GetTickCount64() };
        let tick_count_milliseconds = now_tick
            .checked_add(u64::from(timeout_milliseconds.get()))
            .and_then(NonZeroU64::new)
            .ok_or(ServiceProbeDebugGateError::Deadline)?;
        Ok(Self {
            instant,
            tick_count_milliseconds,
        })
    }

    fn remaining_timeout(self) -> Result<u32, ServiceProbeDebugGateError> {
        let remaining = self
            .instant
            .checked_duration_since(Instant::now())
            .ok_or(ServiceProbeDebugGateError::Deadline)?;
        let rounded = remaining.as_millis().saturating_add(1);
        u32::try_from(rounded.min(u128::from(u32::MAX)))
            .map_err(|_| ServiceProbeDebugGateError::Deadline)
            .map(|value| value.max(1))
    }
}

#[derive(Eq, PartialEq)]
struct FileObjectIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

impl FileObjectIdentity {
    fn query(handle: HANDLE) -> Result<Self, ServiceProbeDebugGateError> {
        if invalid_handle(handle) {
            return Err(ServiceProbeDebugGateError::ImageIdentity);
        }
        let mut information = FILE_ID_INFO::default();
        // SAFETY: handle is a simultaneously live file object and information
        // is exact writable FILE_ID_INFO storage.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                ptr::from_mut(&mut information).cast::<core::ffi::c_void>(),
                u32::try_from(size_of_val(&information))
                    .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)?,
            )
        }
        .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)?;
        if information.VolumeSerialNumber == 0
            || information.FileId.Identifier == [0; 16]
            || information.FileId.Identifier == [u8::MAX; 16]
        {
            return Err(ServiceProbeDebugGateError::ImageIdentity);
        }
        Ok(Self {
            volume_serial_number: information.VolumeSerialNumber,
            file_id: information.FileId.Identifier,
        })
    }
}

impl fmt::Debug for FileObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileObjectIdentity([FILE_ID_INFO])")
    }
}

struct CheckedFileHandle(HANDLE);

impl CheckedFileHandle {
    fn adopt_event(handle: HANDLE) -> Result<Self, ServiceProbeDebugGateError> {
        if invalid_handle(handle) {
            return Err(ServiceProbeDebugGateError::ImageIdentity);
        }
        let mut owner = Self(handle);
        let mut flags = u32::MAX;
        // SAFETY: this event-supplied file handle remains live until adopted
        // and flags is exact initialized writable storage.
        let validation = unsafe { GetHandleInformation(handle, &raw mut flags) }
            .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)
            .and_then(|()| {
                (flags == 0)
                    .then_some(())
                    .ok_or(ServiceProbeDebugGateError::ImageIdentity)
            });
        if let Err(validation_error) = validation {
            // A checked close is an independent authority-cleanup obligation;
            // it dominates a validation error if Windows rejects the close.
            owner.close_checked()?;
            return Err(validation_error);
        }
        Ok(owner)
    }

    fn adopt_optional_event(handle: HANDLE) -> Result<Option<Self>, ServiceProbeDebugGateError> {
        if handle.0.is_null() {
            Ok(None)
        } else {
            Self::adopt_event(handle).map(Some)
        }
    }

    fn adopt_event_distinct(
        handle: HANDLE,
        cleanup: &ServiceProbeDebugEventCleanup,
        forbidden: &[HANDLE],
    ) -> Result<Self, ServiceProbeDebugGateError> {
        if forbidden.contains(&handle) || cleanup.contains_handle_while_attached(handle)? {
            return Err(ServiceProbeDebugGateError::EventIdentity);
        }
        Self::adopt_event(handle)
    }

    fn adopt_optional_event_distinct(
        handle: HANDLE,
        cleanup: &ServiceProbeDebugEventCleanup,
        forbidden: &[HANDLE],
    ) -> Result<Option<Self>, ServiceProbeDebugGateError> {
        if handle.0.is_null() {
            Ok(None)
        } else {
            Self::adopt_event_distinct(handle, cleanup, forbidden).map(Some)
        }
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }

    fn close_checked(&mut self) -> Result<(), ServiceProbeDebugGateError> {
        if invalid_handle(self.0) {
            return Err(ServiceProbeDebugGateError::Cleanup);
        }
        // SAFETY: this wrapper uniquely owns the event/pinned file handle.
        unsafe { CloseHandle(self.0) }.map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        self.0 = HANDLE::default();
        Ok(())
    }
}

impl Drop for CheckedFileHandle {
    fn drop(&mut self) {
        if !invalid_handle(self.0) {
            // SAFETY: a failed explicit checked close leaves this exact owner
            // armed for one ordinary RAII retry.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct PinnedSystemNtdll {
    handle: CheckedFileHandle,
    identity: FileObjectIdentity,
}

fn pin_system_ntdll(
    system_directory: &[u16],
) -> Result<PinnedSystemNtdll, ServiceProbeDebugGateError> {
    let units = system_directory
        .strip_suffix(&[0])
        .filter(|units| !units.is_empty() && !units.contains(&0))
        .ok_or(ServiceProbeDebugGateError::ImageIdentity)?;
    let path = PathBuf::from(OsString::from_wide(units)).join("ntdll.dll");
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)?;
    let mut handle = CheckedFileHandle(HANDLE(file.into_raw_handle()));
    let raw = handle.raw();
    let mut flags = u32::MAX;
    let validation = (|| {
        // SAFETY: the just-opened file remains owned through every observation.
        unsafe { GetHandleInformation(raw, &raw mut flags) }
            .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)?;
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: raw is live and attributes is exact writable output storage.
        unsafe {
            GetFileInformationByHandleEx(
                raw,
                FileAttributeTagInfo,
                ptr::from_mut(&mut attributes).cast::<core::ffi::c_void>(),
                u32::try_from(size_of_val(&attributes))
                    .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)?,
            )
        }
        .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)?;
        if flags != 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        {
            return Err(ServiceProbeDebugGateError::ImageIdentity);
        }
        FileObjectIdentity::query(raw)
    })();
    let identity = match validation {
        Ok(identity) => identity,
        Err(error) => {
            handle.close_checked()?;
            return Err(error);
        }
    };
    Ok(PinnedSystemNtdll { handle, identity })
}

fn process_creation_filetime(
    process: BorrowedHandle<'_>,
) -> Result<NonZeroU64, ServiceProbeDebugGateError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the exact creator process handle remains live and all four
    // FILETIME outputs are initialized writable storage.
    unsafe {
        GetProcessTimes(
            windows_handle(process),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .map_err(|_| ServiceProbeDebugGateError::EventIdentity)?;
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    NonZeroU64::new(value).ok_or(ServiceProbeDebugGateError::EventIdentity)
}

fn query_remote_image_page(
    process: HANDLE,
    address: usize,
    allocation_base: usize,
    range_end: usize,
    require_executable: bool,
) -> Result<(), ServiceProbeDebugGateError> {
    if address == 0 || allocation_base == 0 || range_end <= address {
        return Err(ServiceProbeDebugGateError::GateAuthentication);
    }
    let mut information = MEMORY_BASIC_INFORMATION::default();
    // SAFETY: process is the retained debuggee, address is a remote query key,
    // and information is exact writable native storage.
    let returned = unsafe {
        VirtualQueryEx(
            process,
            Some(address as *const core::ffi::c_void),
            &raw mut information,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    let region_start = information.BaseAddress.addr();
    let region_end = region_start
        .checked_add(information.RegionSize)
        .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
    let base_protection = information.Protect.0 & 0xff;
    if returned != size_of::<MEMORY_BASIC_INFORMATION>()
        || information.AllocationBase.addr() != allocation_base
        || information.State != MEM_COMMIT
        || information.Type != MEM_IMAGE
        || information.Protect.0 & PAGE_GUARD.0 != 0
        || (require_executable
            && base_protection != PAGE_EXECUTE.0
            && base_protection != PAGE_EXECUTE_READ.0)
        || region_start > address
        || range_end > region_end
    {
        return Err(ServiceProbeDebugGateError::GateAuthentication);
    }
    Ok(())
}

fn read_remote_exact<const N: usize>(
    process: HANDLE,
    address: usize,
) -> Result<[u8; N], ServiceProbeDebugGateError> {
    let mut bytes = [0_u8; N];
    let mut read = 0_usize;
    // SAFETY: destination is exact local writable storage; the caller already
    // authenticated the complete committed remote image range.
    unsafe {
        ReadProcessMemory(
            process,
            address as *const core::ffi::c_void,
            bytes.as_mut_ptr().cast::<core::ffi::c_void>(),
            N,
            Some(&raw mut read),
        )
    }
    .map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?;
    if read != N {
        return Err(ServiceProbeDebugGateError::GateAuthentication);
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct AlignedAmd64Context(CONTEXT);

fn primary_thread_context(
    thread: HANDLE,
) -> Result<AlignedAmd64Context, ServiceProbeDebugGateError> {
    let mut context = AlignedAmd64Context(CONTEXT {
        ContextFlags: CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
        ..CONTEXT::default()
    });
    // SAFETY: a held debug event or explicit suspend count stops this exact
    // primary thread; storage is explicitly aligned for the AMD64 ABI.
    unsafe { GetThreadContext(thread, &raw mut context.0) }
        .map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?;
    if context.0.ContextFlags != (CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64) {
        return Err(ServiceProbeDebugGateError::GateAuthentication);
    }
    Ok(context)
}

fn contexts_match_except_r10_r11(
    before: &CONTEXT,
    after: &CONTEXT,
    expected_r10: u64,
    expected_r11: u64,
) -> bool {
    const AMD64_EFLAGS_RESERVED_ONE: u32 = 1 << 1;
    after.ContextFlags == before.ContextFlags
        && after.R10 == expected_r10
        && after.R11 == expected_r11
        && after.P1Home == before.P1Home
        && after.P2Home == before.P2Home
        && after.P3Home == before.P3Home
        && after.P4Home == before.P4Home
        && after.P5Home == before.P5Home
        && after.P6Home == before.P6Home
        && after.SegCs == before.SegCs
        && after.SegSs == before.SegSs
        && before.EFlags & AMD64_EFLAGS_RESERVED_ONE != 0
        && after.EFlags & !AMD64_EFLAGS_RESERVED_ONE == before.EFlags & !AMD64_EFLAGS_RESERVED_ONE
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
        && after.R12 == before.R12
        && after.R13 == before.R13
        && after.R14 == before.R14
        && after.R15 == before.R15
        && after.Rip == before.Rip
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.0.is_null() || handle == INVALID_HANDLE_VALUE || handle.is_invalid()
}

fn windows_handle(handle: BorrowedHandle<'_>) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebugProtocolPhase {
    AwaitingCreate,
    CreateHeld,
    LoaderEvents,
    CaptureHeld,
    CaptureContinued,
    AdoptionHeld,
    AdoptionContinued,
    PreparedForNoKill,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebugProtocolTransition {
    HoldCreate,
    ContinueCreate,
    HoldCapture,
    ContinueCapture,
    HoldAdoption,
    ContinueAdoption,
    PrepareNoKill,
}

impl DebugProtocolPhase {
    fn transition(
        self,
        transition: DebugProtocolTransition,
    ) -> Result<Self, ServiceProbeDebugGateError> {
        match (self, transition) {
            (Self::AwaitingCreate, DebugProtocolTransition::HoldCreate) => Ok(Self::CreateHeld),
            (Self::CreateHeld, DebugProtocolTransition::ContinueCreate) => Ok(Self::LoaderEvents),
            (Self::LoaderEvents, DebugProtocolTransition::HoldCapture) => Ok(Self::CaptureHeld),
            (Self::CaptureHeld, DebugProtocolTransition::ContinueCapture) => {
                Ok(Self::CaptureContinued)
            }
            (Self::CaptureContinued, DebugProtocolTransition::HoldAdoption) => {
                Ok(Self::AdoptionHeld)
            }
            (Self::AdoptionHeld, DebugProtocolTransition::ContinueAdoption) => {
                Ok(Self::AdoptionContinued)
            }
            (Self::AdoptionContinued, DebugProtocolTransition::PrepareNoKill) => {
                Ok(Self::PreparedForNoKill)
            }
            _ => Err(ServiceProbeDebugGateError::UnexpectedEvent),
        }
    }
}

#[derive(Clone, Copy)]
struct HeldDebugEvent {
    process_id: u32,
    thread_id: u32,
}

enum AdvanceFailure {
    Gate(ServiceProbeDebugGateError),
    PreparedCleanup(PendingServiceProbeCleanup, ServiceProbeDebugGateError),
}

impl From<ServiceProbeDebugGateError> for AdvanceFailure {
    fn from(error: ServiceProbeDebugGateError) -> Self {
        Self::Gate(error)
    }
}

struct WindowsGateAttempt<'client, 'proof, 'context> {
    probe: Option<SuspendedServiceProbe<'client, 'proof, 'context>>,
    layout: ServiceHelperGateLayout,
    correlation: ServiceProbeDebugCorrelation,
    deadline: CoordinationDeadline,
    pending: Option<HeldDebugEvent>,
    phase: DebugProtocolPhase,
    main_image_base: Option<usize>,
    creation_filetime: Option<NonZeroU64>,
    system_ntdll: Option<PinnedSystemNtdll>,
    loaded_system_ntdll_base: Option<usize>,
    system_breakpoint_seen: bool,
}

impl<'client, 'proof, 'context> WindowsGateAttempt<'client, 'proof, 'context> {
    fn new(
        probe: SuspendedServiceProbe<'client, 'proof, 'context>,
        layout: ServiceHelperGateLayout,
        correlation: ServiceProbeDebugCorrelation,
        deadline: CoordinationDeadline,
    ) -> Self {
        Self {
            probe: Some(probe),
            layout,
            correlation,
            deadline,
            pending: None,
            phase: DebugProtocolPhase::AwaitingCreate,
            main_image_base: None,
            creation_filetime: None,
            system_ntdll: None,
            loaded_system_ntdll_base: None,
            system_breakpoint_seen: false,
        }
    }

    fn probe(
        &self,
    ) -> Result<&SuspendedServiceProbe<'client, 'proof, 'context>, ServiceProbeDebugGateError> {
        self.probe
            .as_ref()
            .ok_or(ServiceProbeDebugGateError::Detach)
    }

    fn probe_mut(
        &mut self,
    ) -> Result<&mut SuspendedServiceProbe<'client, 'proof, 'context>, ServiceProbeDebugGateError>
    {
        self.probe
            .as_mut()
            .ok_or(ServiceProbeDebugGateError::Detach)
    }

    fn wait_event(&mut self) -> Result<DEBUG_EVENT, ServiceProbeDebugGateError> {
        if self.pending.is_some() {
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        let mut event = DEBUG_EVENT::default();
        let timeout = self.deadline.remaining_timeout()?;
        // SAFETY: exact writable event storage is supplied on the same fresh
        // debugger OS thread that created the process.
        if unsafe { WaitForDebugEventEx(&raw mut event, timeout) }.is_err() {
            // SAFETY: queried immediately after the failed native call.
            return if unsafe { GetLastError() } == ERROR_SEM_TIMEOUT {
                Err(ServiceProbeDebugGateError::Deadline)
            } else {
                Err(ServiceProbeDebugGateError::UnexpectedEvent)
            };
        }
        self.pending = Some(HeldDebugEvent {
            process_id: event.dwProcessId,
            thread_id: event.dwThreadId,
        });
        Ok(event)
    }

    fn continue_pending(&mut self) -> Result<(), ServiceProbeDebugGateError> {
        let pending = self
            .pending
            .ok_or(ServiceProbeDebugGateError::UnexpectedEvent)?;
        // SAFETY: these identifiers name the exact event currently held by
        // this debugger thread and no other continue is in flight.
        unsafe { ContinueDebugEvent(pending.process_id, pending.thread_id, DBG_CONTINUE) }
            .map_err(|_| ServiceProbeDebugGateError::Detach)?;
        self.pending = None;
        Ok(())
    }

    fn adopt_rejected_event_resources(
        &mut self,
        event: &DEBUG_EVENT,
    ) -> Result<(), ServiceProbeDebugGateError> {
        match event.dwDebugEventCode {
            LOAD_DLL_DEBUG_EVENT => {
                // SAFETY: the discriminant was matched immediately above.
                let load = unsafe { event.u.LoadDll };
                let creator_process = windows_handle(self.probe()?.process_handle());
                let creator_thread = windows_handle(self.probe()?.primary_thread_handle());
                let pinned = self
                    .system_ntdll
                    .as_ref()
                    .map_or(HANDLE::default(), |pinned| pinned.handle.raw());
                if let Some(mut file) = CheckedFileHandle::adopt_optional_event_distinct(
                    load.hFile,
                    self.probe()?.debug_event_cleanup(),
                    &[creator_process, creator_thread, pinned],
                )? {
                    file.close_checked()?;
                }
            }
            CREATE_THREAD_DEBUG_EVENT => {
                // SAFETY: the discriminant was matched immediately above.
                let create = unsafe { event.u.CreateThread };
                let expected_process_id = self.probe()?.process_id().get();
                let expected_thread_id = self.probe()?.primary_thread_id().get();
                self.probe()?
                    .debug_event_cleanup()
                    .register_rejected_thread_alias(
                        expected_process_id,
                        expected_thread_id,
                        event.dwThreadId,
                        create.hThread,
                        windows_handle(self.probe()?.process_handle()),
                        windows_handle(self.probe()?.primary_thread_handle()),
                    )?;
            }
            CREATE_PROCESS_DEBUG_EVENT => {
                // A second create-process event is never admitted under
                // DEBUG_ONLY_THIS_PROCESS. The expected one-process Job cannot
                // prove this other process terminal, so no recoverable cleanup
                // result may escape. Its hFile obligation is still attempted
                // before process-wide fail-fast reclaims the entire handle table.
                // SAFETY: the discriminant was matched immediately above.
                let create = unsafe { event.u.CreateProcessInfo };
                let creator_process = windows_handle(self.probe()?.process_handle());
                let creator_thread = windows_handle(self.probe()?.primary_thread_handle());
                let registration = self
                    .probe()?
                    .debug_event_cleanup()
                    .register_rejected_process_aliases(
                        create.hProcess,
                        create.hThread,
                        creator_process,
                        creator_thread,
                        event.dwProcessId,
                        event.dwThreadId,
                    );
                let Ok(mut file) = CheckedFileHandle::adopt_optional_event_distinct(
                    create.hFile,
                    self.probe()?.debug_event_cleanup(),
                    &[creator_process, creator_thread],
                ) else {
                    windows_fail_fast();
                };
                let close = match file.as_mut() {
                    Some(file) => file.close_checked(),
                    None => Ok(()),
                };
                if cleanup_result_dominates(registration, close).is_err() {
                    windows_fail_fast();
                }
                windows_fail_fast();
            }
            _ => {}
        }
        Ok(())
    }

    fn authenticate_create_event(&mut self) -> Result<(), ServiceProbeDebugGateError> {
        if self.phase != DebugProtocolPhase::AwaitingCreate {
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        let expected_image = held_helper_file_identity(self.probe()?.helper())
            .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)?;

        // CREATE_SUSPENDED contributes exactly one count. It is consumed only
        // so the kernel can deliver pre-user-mode debug events.
        // SAFETY: this is the exact still-live primary-thread creator handle.
        let previous =
            unsafe { ResumeThread(windows_handle(self.probe()?.primary_thread_handle())) };
        if previous != 1 {
            return Err(ServiceProbeDebugGateError::Suspension);
        }

        let event = self.wait_event()?;
        if event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT {
            self.adopt_rejected_event_resources(&event)?;
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        // SAFETY: the event discriminant was checked immediately above.
        let create = unsafe { event.u.CreateProcessInfo };

        // Register both aliases before any later event check can fail. The
        // outer Arc registry survives worker Err and panic until exact join.
        let creator_process = windows_handle(self.probe()?.process_handle());
        let creator_thread = windows_handle(self.probe()?.primary_thread_handle());
        let expected_process_id = self.probe()?.process_id().get();
        let expected_thread_id = self.probe()?.primary_thread_id().get();
        let registration = self
            .probe()?
            .debug_event_cleanup()
            .register_create_process_aliases(
                create.hProcess,
                create.hThread,
                creator_process,
                creator_thread,
                expected_process_id,
                expected_thread_id,
            );
        let mut event_file = match CheckedFileHandle::adopt_event_distinct(
            create.hFile,
            self.probe()?.debug_event_cleanup(),
            &[creator_process, creator_thread],
        ) {
            Ok(file) => file,
            Err(file_error) => {
                return Err(merge_authority_errors(registration.err(), file_error));
            }
        };
        if let Err(registration_error) = registration {
            event_file.close_checked()?;
            return Err(registration_error);
        }
        let proof = (|| {
            let probe = self.probe()?;
            if event.dwProcessId != probe.process_id().get()
                || event.dwThreadId != probe.primary_thread_id().get()
            {
                return Err(ServiceProbeDebugGateError::EventIdentity);
            }
            // SAFETY: both event aliases remain system-managed while this exact
            // CREATE_PROCESS event is held.
            let event_process_id = unsafe { GetProcessId(create.hProcess) };
            // SAFETY: same held-event lifetime argument.
            let event_thread_id = unsafe { GetThreadId(create.hThread) };
            // SAFETY: same held-event lifetime argument.
            let event_thread_process_id = unsafe { GetProcessIdOfThread(create.hThread) };
            if event_process_id != event.dwProcessId
                || event_thread_id != event.dwThreadId
                || event_thread_process_id != event.dwProcessId
                || !handle_flags_are_zero(create.hProcess)
                || !handle_flags_are_zero(create.hThread)
            {
                return Err(ServiceProbeDebugGateError::EventIdentity);
            }
            // SAFETY: creator and event aliases are simultaneously live and
            // CompareObjectHandles only compares kernel object identity.
            if !unsafe {
                CompareObjectHandles(windows_handle(probe.process_handle()), create.hProcess)
            }
            .as_bool()
                // SAFETY: the exact creator thread and its event alias are
                // simultaneously live; this only compares kernel identity.
                || !unsafe {
                    CompareObjectHandles(
                        windows_handle(probe.primary_thread_handle()),
                        create.hThread,
                    )
                }
                .as_bool()
            {
                return Err(ServiceProbeDebugGateError::EventIdentity);
            }
            authenticate_mapped_image(&expected_image, event_file.raw())
                .map_err(|_| ServiceProbeDebugGateError::ImageIdentity)?;
            Ok(())
        })();
        let close = event_file.close_checked();
        cleanup_result_dominates(proof, close)?;

        let image_base = create.lpBaseOfImage.addr();
        self.verify_static_layout_bounds(image_base)?;
        let creation_filetime = process_creation_filetime(self.probe()?.process_handle())?;
        let system_ntdll = pin_system_ntdll(self.probe()?.system_directory())?;
        self.main_image_base = Some(image_base);
        self.creation_filetime = Some(creation_filetime);
        self.system_ntdll = Some(system_ntdll);
        self.phase = self.phase.transition(DebugProtocolTransition::HoldCreate)?;
        Ok(())
    }

    fn verify_static_layout_bounds(
        &self,
        image_base: usize,
    ) -> Result<(), ServiceProbeDebugGateError> {
        let image_size = usize::try_from(self.layout.size_of_image())
            .map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?;
        let image_end = image_base
            .checked_add(image_size)
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        let capture_start = checked_remote_rva(image_base, self.layout.capture_sequence_rva())?;
        let capture_breakpoint =
            checked_remote_rva(image_base, self.layout.capture_breakpoint_rva())?;
        let capture_end = capture_start
            .checked_add(CAPTURE_GATE_BYTES)
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        let adoption_start = checked_remote_rva(image_base, self.layout.adoption_sequence_rva())?;
        let adoption_breakpoint =
            checked_remote_rva(image_base, self.layout.adoption_breakpoint_rva())?;
        let adoption_end = adoption_start
            .checked_add(ADOPTION_COMPLETE_GATE_BYTES)
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        if image_base == 0
            || capture_breakpoint
                != capture_start
                    .checked_add(CAPTURE_GATE_BREAKPOINT_OFFSET)
                    .ok_or(ServiceProbeDebugGateError::GateAuthentication)?
            || adoption_breakpoint
                != adoption_start
                    .checked_add(ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET)
                    .ok_or(ServiceProbeDebugGateError::GateAuthentication)?
            || capture_end > image_end
            || adoption_end > image_end
        {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        Ok(())
    }

    fn authenticate_load_dll_event(
        &mut self,
        event: &DEBUG_EVENT,
    ) -> Result<(), ServiceProbeDebugGateError> {
        // SAFETY: caller dispatches only LOAD_DLL_DEBUG_EVENT here.
        let load = unsafe { event.u.LoadDll };
        let creator_process = windows_handle(self.probe()?.process_handle());
        let creator_thread = windows_handle(self.probe()?.primary_thread_handle());
        let pinned_handle = self
            .system_ntdll
            .as_ref()
            .map_or(HANDLE::default(), |pinned| pinned.handle.raw());
        let mut event_file = CheckedFileHandle::adopt_optional_event_distinct(
            load.hFile,
            self.probe()?.debug_event_cleanup(),
            &[creator_process, creator_thread, pinned_handle],
        )?;
        let proof = (|| {
            let base = load.lpBaseOfDll.addr();
            let end = base
                .checked_add(1)
                .ok_or(ServiceProbeDebugGateError::ImageIdentity)?;
            let main_base = self
                .main_image_base
                .ok_or(ServiceProbeDebugGateError::ImageIdentity)?;
            if base == 0 || base == main_base {
                return Err(ServiceProbeDebugGateError::ImageIdentity);
            }
            query_remote_image_page(
                windows_handle(self.probe()?.process_handle()),
                base,
                base,
                end,
                false,
            )?;
            if let Some(file) = event_file.as_ref() {
                let identity = FileObjectIdentity::query(file.raw())?;
                let pinned = self
                    .system_ntdll
                    .as_ref()
                    .ok_or(ServiceProbeDebugGateError::ImageIdentity)?;
                if identity == pinned.identity
                    && self.loaded_system_ntdll_base.replace(base).is_some()
                {
                    return Err(ServiceProbeDebugGateError::UnexpectedEvent);
                }
            }
            Ok(())
        })();
        let close = match event_file.as_mut() {
            Some(file) => file.close_checked(),
            None => Ok(()),
        };
        cleanup_result_dominates(proof, close)
    }

    fn authenticate_system_breakpoint(
        &mut self,
        event: &DEBUG_EVENT,
    ) -> Result<(), ServiceProbeDebugGateError> {
        if self.system_breakpoint_seen {
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        // SAFETY: caller dispatches only EXCEPTION_DEBUG_EVENT here.
        let exception = unsafe { event.u.Exception };
        let record = exception.ExceptionRecord;
        let address = record.ExceptionAddress.addr();
        let allocation_base = self
            .loaded_system_ntdll_base
            .ok_or(ServiceProbeDebugGateError::ImageIdentity)?;
        let end = address
            .checked_add(1)
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        if exception.dwFirstChance != 1 || record.ExceptionCode != EXCEPTION_BREAKPOINT {
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        let process = windows_handle(self.probe()?.process_handle());
        query_remote_image_page(process, address, allocation_base, end, true)?;
        if read_remote_exact::<1>(process, address)? != [0xcc] {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        let context =
            primary_thread_context(windows_handle(self.probe()?.primary_thread_handle()))?;
        let expected_rip =
            u64::try_from(end).map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?;
        if context.0.Rip != expected_rip {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        let pinned = self
            .system_ntdll
            .as_mut()
            .ok_or(ServiceProbeDebugGateError::ImageIdentity)?;
        if FileObjectIdentity::query(pinned.handle.raw())? != pinned.identity {
            return Err(ServiceProbeDebugGateError::ImageIdentity);
        }
        pinned.handle.close_checked()?;
        self.system_ntdll = None;
        self.system_breakpoint_seen = true;
        Ok(())
    }

    fn authenticate_capture_gate(
        &mut self,
        event: &DEBUG_EVENT,
    ) -> Result<AlignedAmd64Context, ServiceProbeDebugGateError> {
        if !self.system_breakpoint_seen
            || self.system_ntdll.is_some()
            || self.loaded_system_ntdll_base.is_none()
        {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        let image_base = self
            .main_image_base
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        let context = self.authenticate_gate::<CAPTURE_GATE_BYTES>(
            event,
            self.layout.capture_sequence_rva(),
            self.layout.capture_breakpoint_rva(),
            CAPTURE_GATE_BREAKPOINT_OFFSET,
            capture_gate_bytes(),
            REQUEST_INPUT_MARKER,
            RESPONSE_OUTPUT_MARKER,
        )?;
        let sequence = checked_remote_rva(image_base, self.layout.capture_sequence_rva())?;
        let end = sequence
            .checked_add(CAPTURE_GATE_BYTES)
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        let image_end = image_base
            .checked_add(
                usize::try_from(self.layout.size_of_image())
                    .map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?,
            )
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        if end > image_end {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        self.phase = self
            .phase
            .transition(DebugProtocolTransition::HoldCapture)?;
        Ok(context)
    }

    #[allow(clippy::too_many_arguments)]
    fn authenticate_gate<const N: usize>(
        &self,
        event: &DEBUG_EVENT,
        sequence_rva: u32,
        breakpoint_rva: u32,
        breakpoint_offset: usize,
        expected_bytes: [u8; N],
        expected_r10: u64,
        expected_r11: u64,
    ) -> Result<AlignedAmd64Context, ServiceProbeDebugGateError> {
        if event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT {
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        // SAFETY: the event discriminant was checked immediately above.
        let exception = unsafe { event.u.Exception };
        let record = exception.ExceptionRecord;
        let image_base = self
            .main_image_base
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        let sequence = checked_remote_rva(image_base, sequence_rva)?;
        let breakpoint = checked_remote_rva(image_base, breakpoint_rva)?;
        let sequence_end = sequence
            .checked_add(N)
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        let image_end = image_base
            .checked_add(
                usize::try_from(self.layout.size_of_image())
                    .map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?,
            )
            .ok_or(ServiceProbeDebugGateError::GateAuthentication)?;
        if exception.dwFirstChance != 1
            || record.ExceptionCode != EXCEPTION_BREAKPOINT
            || record.ExceptionAddress.addr() != breakpoint
            || breakpoint
                != sequence
                    .checked_add(breakpoint_offset)
                    .ok_or(ServiceProbeDebugGateError::GateAuthentication)?
            || sequence_end > image_end
        {
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        let process = windows_handle(self.probe()?.process_handle());
        query_remote_image_page(process, sequence, image_base, sequence_end, true)?;
        if read_remote_exact::<N>(process, sequence)? != expected_bytes {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        let context =
            primary_thread_context(windows_handle(self.probe()?.primary_thread_handle()))?;
        let expected_rip = u64::try_from(
            breakpoint
                .checked_add(1)
                .ok_or(ServiceProbeDebugGateError::GateAuthentication)?,
        )
        .map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?;
        if context.0.Rip != expected_rip
            || context.0.R10 != expected_r10
            || context.0.R11 != expected_r11
        {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        Ok(context)
    }

    fn continue_to_capture_gate(
        &mut self,
    ) -> Result<AlignedAmd64Context, ServiceProbeDebugGateError> {
        self.continue_pending()?;
        self.phase = self
            .phase
            .transition(DebugProtocolTransition::ContinueCreate)?;
        let mut loader_events = 0_usize;
        for _ in 0..MAX_PRE_CAPTURE_DEBUG_EVENTS {
            let event = self.wait_event()?;
            let expected_process_id = self.probe()?.process_id().get();
            let expected_thread_id = self.probe()?.primary_thread_id().get();
            if event.dwProcessId != expected_process_id || event.dwThreadId != expected_thread_id {
                self.adopt_rejected_event_resources(&event)?;
                return Err(ServiceProbeDebugGateError::UnexpectedEvent);
            }
            match event.dwDebugEventCode {
                LOAD_DLL_DEBUG_EVENT => {
                    loader_events =
                        authenticate_loader_event_then_increment(loader_events, || {
                            self.authenticate_load_dll_event(&event)
                        })?;
                    self.continue_pending()?;
                }
                EXCEPTION_DEBUG_EVENT if !self.system_breakpoint_seen => {
                    self.authenticate_system_breakpoint(&event)?;
                    self.continue_pending()?;
                }
                EXCEPTION_DEBUG_EVENT => return self.authenticate_capture_gate(&event),
                CREATE_THREAD_DEBUG_EVENT
                | EXIT_THREAD_DEBUG_EVENT
                | EXIT_PROCESS_DEBUG_EVENT
                | OUTPUT_DEBUG_STRING_EVENT
                | RIP_EVENT
                | CREATE_PROCESS_DEBUG_EVENT => {
                    self.adopt_rejected_event_resources(&event)?;
                    return Err(ServiceProbeDebugGateError::UnexpectedEvent);
                }
                _ => return Err(ServiceProbeDebugGateError::UnexpectedEvent),
            }
        }
        Err(ServiceProbeDebugGateError::UnexpectedEvent)
    }

    fn inject_channels(
        &self,
        sources: ServiceProbeChannelSources,
    ) -> Result<(InjectedChildChannelHandles, ParentBootstrapChannels), ServiceProbeDebugGateError>
    {
        let probe = self.probe()?;
        match (probe.role(), sources) {
            (ServiceProbeRole::Approval, ServiceProbeChannelSources::Approval(pipes)) => {
                let injected = duplicate_approval_channels_for_child(pipes, probe.process_handle())
                    .map_err(|_| ServiceProbeDebugGateError::Channel)?;
                let (child, parent) = injected.into_parts();
                let (request, response) = parent.into_parts();
                Ok((
                    child,
                    ParentBootstrapChannels {
                        kind: ParentBootstrapChannelKind::Approval {
                            request,
                            response: Some(response),
                        },
                        _not_sync: PhantomData,
                    },
                ))
            }
            (ServiceProbeRole::SecretInput, ServiceProbeChannelSources::SecretInput(pipes)) => {
                let injected =
                    duplicate_secret_input_channels_for_child(pipes, probe.process_handle())
                        .map_err(|_| ServiceProbeDebugGateError::Channel)?;
                let (child, parent) = injected.into_parts();
                let (request, response) = parent.into_parts();
                Ok((
                    child,
                    ParentBootstrapChannels {
                        kind: ParentBootstrapChannelKind::SecretInput {
                            request,
                            response: Some(response),
                        },
                        _not_sync: PhantomData,
                    },
                ))
            }
            _ => Err(ServiceProbeDebugGateError::Channel),
        }
    }

    fn install_channel_words(
        &self,
        authenticated_capture: &AlignedAmd64Context,
        handles: InjectedChildChannelHandles,
    ) -> Result<(), ServiceProbeDebugGateError> {
        let thread = windows_handle(self.probe()?.primary_thread_handle());
        let before = primary_thread_context(thread)?;
        if !contexts_match_except_r10_r11(
            &authenticated_capture.0,
            &before.0,
            REQUEST_INPUT_MARKER,
            RESPONSE_OUTPUT_MARKER,
        ) {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        let (request, response) = handles.into_register_words();
        let mut injected = before;
        injected.0.R10 = request;
        injected.0.R11 = response;
        // SAFETY: the capture event still stops this exact primary thread. The
        // context differs only in R10/R11, which receive opaque remote words.
        unsafe { SetThreadContext(thread, &raw const injected.0) }
            .map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?;
        let after = primary_thread_context(thread)?;
        if !contexts_match_except_r10_r11(&before.0, &after.0, request, response) {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        Ok(())
    }

    fn bootstrap_hello(
        &self,
        role: HelperBootstrapRole,
    ) -> Result<HelperBootstrapHello, ServiceProbeDebugGateError> {
        // SAFETY: GetCurrentProcessId has no pointer or handle preconditions.
        let service_process_id = NonZeroU32::new(unsafe { GetCurrentProcessId() })
            .ok_or(ServiceProbeDebugGateError::Correlation)?;
        let child_process_id = self.probe()?.process_id();
        let child_creation_filetime = self
            .creation_filetime
            .ok_or(ServiceProbeDebugGateError::Correlation)?;
        Ok(HelperBootstrapHello::new(
            self.correlation.epoch_nonce,
            self.correlation.request_id,
            role,
            service_process_id,
            child_process_id,
            child_creation_filetime,
            self.deadline.tick_count_milliseconds,
        ))
    }

    fn continue_capture_and_require_ack(
        &mut self,
        channels: &ParentBootstrapChannels,
    ) -> Result<(), ServiceProbeDebugGateError> {
        self.continue_pending()?;
        self.phase = self
            .phase
            .transition(DebugProtocolTransition::ContinueCapture)?;
        let bytes = channels.read_ack(self.deadline.instant)?;
        let acknowledgement = HelperAdoptionAck::decode(&bytes)
            .map_err(|_| ServiceProbeDebugGateError::Correlation)?;
        acknowledgement
            .ensure_correlates_with(
                self.correlation.epoch_nonce,
                self.correlation.request_id,
                channels.role(),
            )
            .map_err(|_| ServiceProbeDebugGateError::Correlation)
    }

    fn authenticate_adoption_gate(
        &mut self,
    ) -> Result<AlignedAmd64Context, ServiceProbeDebugGateError> {
        if self.phase != DebugProtocolPhase::CaptureContinued {
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        let event = self.wait_event()?;
        let probe = self.probe()?;
        if event.dwProcessId != probe.process_id().get()
            || event.dwThreadId != probe.primary_thread_id().get()
            || event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT
        {
            self.adopt_rejected_event_resources(&event)?;
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        let context = self.authenticate_gate::<ADOPTION_COMPLETE_GATE_BYTES>(
            &event,
            self.layout.adoption_sequence_rva(),
            self.layout.adoption_breakpoint_rva(),
            ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET,
            adoption_complete_gate_bytes(),
            ADOPTION_COMPLETE_R10_MARKER,
            ADOPTION_COMPLETE_R11_MARKER,
        )?;
        self.phase = self
            .phase
            .transition(DebugProtocolTransition::HoldAdoption)?;
        Ok(context)
    }

    fn install_suspend_and_continue_adoption(
        &mut self,
        authenticated: &AlignedAmd64Context,
    ) -> Result<(), ServiceProbeDebugGateError> {
        let thread = windows_handle(self.probe()?.primary_thread_handle());
        // SAFETY: gate 2's debug event supplies the process-wide stop. No
        // CREATE_THREAD event was admitted, and this exact primary-thread
        // creator handle installs the one independently retained count.
        let previous = unsafe { SuspendThread(thread) };
        if previous != 0 {
            return Err(ServiceProbeDebugGateError::Suspension);
        }
        self.continue_pending()?;
        self.phase = self
            .phase
            .transition(DebugProtocolTransition::ContinueAdoption)?;
        let after = primary_thread_context(thread)?;
        if !contexts_match_except_r10_r11(
            &authenticated.0,
            &after.0,
            ADOPTION_COMPLETE_R10_MARKER,
            ADOPTION_COMPLETE_R11_MARKER,
        ) {
            return Err(ServiceProbeDebugGateError::GateAuthentication);
        }
        Ok(())
    }

    fn require_no_queued_event(&mut self) -> Result<(), ServiceProbeDebugGateError> {
        if self.pending.is_some() {
            return Err(ServiceProbeDebugGateError::UnexpectedEvent);
        }
        let mut event = DEBUG_EVENT::default();
        // SAFETY: exact writable storage is supplied on the same fresh debugger
        // thread; zero performs a nonblocking queue observation.
        match unsafe { WaitForDebugEventEx(&raw mut event, 0) } {
            Ok(()) => {
                self.pending = Some(HeldDebugEvent {
                    process_id: event.dwProcessId,
                    thread_id: event.dwThreadId,
                });
                self.adopt_rejected_event_resources(&event)?;
                Err(ServiceProbeDebugGateError::UnexpectedEvent)
            }
            Err(_) => {
                // SAFETY: queried immediately after the failed native call.
                if unsafe { GetLastError() } == ERROR_SEM_TIMEOUT {
                    Ok(())
                } else {
                    Err(ServiceProbeDebugGateError::Detach)
                }
            }
        }
    }

    fn revalidate_before_no_kill(&mut self) -> Result<(), ServiceProbeDebugGateError> {
        if self.phase != DebugProtocolPhase::AdoptionContinued
            || self.pending.is_some()
            || self.system_ntdll.is_some()
            || !self.system_breakpoint_seen
            || self.loaded_system_ntdll_base.is_none()
        {
            return Err(ServiceProbeDebugGateError::Detach);
        }
        self.require_no_queued_event()?;
        let process = windows_handle(self.probe()?.process_handle());
        // SAFETY: a zero wait observes the exact retained creator process.
        if unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT {
            return Err(ServiceProbeDebugGateError::Detach);
        }
        let mut debugger_present = BOOL::default();
        // SAFETY: process remains live and the BOOL is writable exact storage.
        unsafe { CheckRemoteDebuggerPresent(process, &raw mut debugger_present) }
            .map_err(|_| ServiceProbeDebugGateError::Detach)?;
        if !debugger_present.as_bool() {
            return Err(ServiceProbeDebugGateError::Detach);
        }
        self.probe_mut()?
            .revalidate_held()
            .map_err(|_| ServiceProbeDebugGateError::Detach)?;
        self.probe()?
            .debug_event_cleanup()
            .verify_complete_while_attached(
                self.probe()?.process_id().get(),
                self.probe()?.primary_thread_id().get(),
            )?;
        self.phase = self
            .phase
            .transition(DebugProtocolTransition::PrepareNoKill)?;
        Ok(())
    }

    fn advance(
        &mut self,
        sources: ServiceProbeChannelSources,
    ) -> Result<(PreparedServiceProbeDetach, ParentBootstrapChannels), AdvanceFailure> {
        self.authenticate_create_event()?;
        let capture = self.continue_to_capture_gate()?;
        self.probe_mut()?
            .revalidate_held()
            .map_err(|_| ServiceProbeDebugGateError::Detach)?;
        let (handles, mut channels) = self.inject_channels(sources)?;
        self.install_channel_words(&capture, handles)?;
        let hello = self.bootstrap_hello(channels.role())?;
        channels.write_hello(&hello.encode(), self.deadline.instant)?;
        self.continue_capture_and_require_ack(&channels)?;
        let adoption = self.authenticate_adoption_gate()?;
        self.install_suspend_and_continue_adoption(&adoption)?;
        self.revalidate_before_no_kill()?;

        // Taking and preparing the probe is the final fallible Rust transition
        // before DebugSetProcessKillOnExit(FALSE). If preparation rejects, it
        // already returns a process-terminal cleanup owner.
        let probe = self
            .probe
            .take()
            .ok_or(ServiceProbeDebugGateError::Detach)?;
        let prepared = probe
            .prepare_pending_debugger_exit_success()
            .map_err(|cleanup| {
                AdvanceFailure::PreparedCleanup(cleanup, ServiceProbeDebugGateError::Detach)
            })?;
        Ok((prepared, channels))
    }

    fn into_failure(mut self, error: ServiceProbeDebugGateError) -> FailedServiceProbeDebugGate {
        let Some(probe) = self.probe.take() else {
            // This branch can only indicate an internal lost transition;
            // no recoverable owner exists, so fail closed process-wide.
            windows_fail_fast();
        };
        let mut cleanup = probe.abort_for_debugger_exit();
        // Every error keeps its current event held. Returning from the exact
        // debugger OS thread therefore preserves default kill-on-exit even if
        // a process/Job termination request failed. It also prevents an EXIT
        // Continue from retiring CREATE aliases behind the registry.
        if let Some(mut pinned) = self.system_ntdll.take()
            && pinned.handle.close_checked().is_err()
        {
            cleanup.note_worker_cleanup_failure();
        }
        FailedServiceProbeDebugGate { cleanup, error }
    }
}

fn checked_remote_rva(image_base: usize, rva: u32) -> Result<usize, ServiceProbeDebugGateError> {
    image_base
        .checked_add(
            usize::try_from(rva).map_err(|_| ServiceProbeDebugGateError::GateAuthentication)?,
        )
        .ok_or(ServiceProbeDebugGateError::GateAuthentication)
}

/// Runs the complete dormant two-gate protocol on the fresh creator thread.
///
/// The join-surviving cleanup registry is carried inside the unforgeable fresh
/// creator-thread proof and therefore cannot be substituted by the caller. On
/// success, `DebugSetProcessKillOnExit(FALSE)` is the final fallible operation
/// before the returned Send/!Sync pending owner is constructed.
pub(super) fn authenticate_and_arm_service_probe(
    probe: SuspendedServiceProbe<'_, '_, '_>,
    layout: ServiceHelperGateLayout,
    correlation: ServiceProbeDebugCorrelation,
    sources: ServiceProbeChannelSources,
) -> Result<PendingDebuggerExitServiceProbe, FailedServiceProbeDebugGate> {
    let expected_key = ExpectedPeerKey::new(correlation.epoch_nonce, correlation.request_id);
    let deadline = match CoordinationDeadline::start(correlation.timeout_milliseconds) {
        Ok(deadline) => deadline,
        Err(error) => {
            return Err(FailedServiceProbeDebugGate {
                cleanup: probe.abort_for_debugger_exit(),
                error,
            });
        }
    };
    let mut attempt = WindowsGateAttempt::new(probe, layout, correlation, deadline);
    let (prepared, channels) = match attempt.advance(sources) {
        Ok(success) => success,
        Err(AdvanceFailure::Gate(error)) => return Err(attempt.into_failure(error)),
        Err(AdvanceFailure::PreparedCleanup(cleanup, error)) => {
            return Err(FailedServiceProbeDebugGate { cleanup, error });
        }
    };

    // SAFETY: every fallible debugger-thread query, lock, I/O completion,
    // context check, cleanup-registry check, and ownership preparation has
    // succeeded. FALSE disables the documented default kill-on-debugger-exit
    // policy. Actual debugger absence and surviving event-alias cleanup are
    // separately reauthenticated after join and remain kernel-matrix facts.
    // This is intentionally the final fallible call.
    if unsafe { DebugSetProcessKillOnExit(false) }.is_err() {
        return Err(FailedServiceProbeDebugGate {
            cleanup: prepared.abort_after_no_kill_failure(),
            error: ServiceProbeDebugGateError::Detach,
        });
    }

    let expected_confirmation = HelperRpcConfirmation::new(
        attempt.correlation.epoch_nonce,
        attempt.correlation.request_id,
        channels.role(),
    );
    let confirmation = ServiceHelperConfirmationWaiter::new(
        channels,
        expected_confirmation,
        attempt.deadline.instant,
    );
    let process = prepared.commit_after_no_kill();
    Ok(PendingDebuggerExitServiceProbe {
        process,
        confirmation,
        expected_key,
        _not_sync: PhantomData,
    })
}

fn windows_fail_fast() -> ! {
    // Delegate to an unconditional process abort without formatting, logging,
    // allocation, or revealing any sensitive state.
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::num::NonZeroU32;
    use std::os::windows::io::AsRawHandle as _;
    use std::os::windows::process::CommandExt as _;
    use std::process::{Child, Command};
    use std::time::Duration;

    use key_agent_service_helper_bootstrap::HelperBootstrapRole;
    use key_agent_service_wire::{EpochNonce, ServiceRequestId};
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Diagnostics::Debug::{
        CONTEXT, CONTEXT_FLAGS, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT,
        EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
    };
    use windows::Win32::System::Threading::{CREATE_NO_WINDOW, DEBUG_ONLY_THIS_PROCESS};

    use super::{
        CheckedCanonicalAlias, CheckedFileHandle, ContinueDebugEvent, DBG_CONTINUE,
        DebugEventAliasIdentityApi, DebugProtocolPhase, DebugProtocolTransition,
        DetachedDebugEventAliases, DetachedExpectedServiceHelper, DetachedServiceProbe,
        MAX_LOADER_DEBUG_EVENTS, ParentBootstrapChannels, PendingDebuggerExitServiceProbe,
        ServiceHelperConfirmationWaiter, ServiceProbeDebugCorrelation,
        ServiceProbeDebugEventCleanup, ServiceProbeDebugGateError, ThreadAliasIdentity,
        WaitForDebugEventEx, WaitForSingleObject, WindowsDebugEventAliasIdentityApi,
        authenticate_loader_event_then_increment, cleanup_registry_drop_is_safe,
        cleanup_result_dominates, close_registered_alias, contexts_match_except_r10_r11,
        expected_role_for_channel, handle_flags_are_zero, merge_authority_errors, raw_handle_word,
        repeated_rejected_registration_requires_fail_fast, retain_process_anchor,
        retain_thread_anchor,
    };
    use crate::key_agent_service_launch::process::ServiceProbeRole;
    use crate::key_agent_service_rpc::ExpectedHelperRole;

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
    fn approval_probe_confirmation_rejects_wrong_epoch_request_role_and_trailing_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::validate_probe_confirmation;
        use key_agent_service_helper_bootstrap::HelperRpcConfirmation;
        let epoch = EpochNonce::new([0xA5; 32])?;
        let request = ServiceRequestId::new([0x5A; 16])?;
        let expected = HelperRpcConfirmation::new(epoch, request, HelperBootstrapRole::Approval);
        assert_eq!(
            validate_probe_confirmation(&expected.encode(), &expected),
            Ok(())
        );
        for wrong in [
            HelperRpcConfirmation::new(
                EpochNonce::new([0xA6; 32])?,
                request,
                HelperBootstrapRole::Approval,
            ),
            HelperRpcConfirmation::new(
                epoch,
                ServiceRequestId::new([0x5B; 16])?,
                HelperBootstrapRole::Approval,
            ),
            HelperRpcConfirmation::new(epoch, request, HelperBootstrapRole::SecretInput),
        ] {
            assert_eq!(
                validate_probe_confirmation(&wrong.encode(), &expected),
                Err(ServiceProbeDebugGateError::Correlation)
            );
        }
        let mut trailing = expected.encode().to_vec();
        trailing.push(0);
        assert_eq!(
            validate_probe_confirmation(&trailing, &expected),
            Err(ServiceProbeDebugGateError::Correlation)
        );
        assert_eq!(
            validate_probe_confirmation(&trailing[..71], &expected),
            Err(ServiceProbeDebugGateError::Correlation)
        );
        Ok(())
    }

    #[test]
    fn approval_probe_response_rejects_mismatched_bindings_and_noncanonical_frames() {
        use super::validate_probe_response;
        // Public protocol correlation only; not wallet keys or entropy fixtures.
        let digest = [0xA5; 32];
        let nonce = [0x5A; 32];
        for decision in [0_u8, 1_u8] {
            let mut bytes = [0_u8; approval_wire::RESPONSE_BYTES];
            bytes[..8].copy_from_slice(b"YWAPRS02");
            bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
            bytes[10] = decision;
            bytes[11..43].copy_from_slice(&digest);
            bytes[43..75].copy_from_slice(&nonce);
            assert_eq!(validate_probe_response(&bytes, &digest, &nonce), Ok(()));
            assert_eq!(
                validate_probe_response(&bytes, &[0xA6; 32], &nonce),
                Err(ServiceProbeDebugGateError::Correlation)
            );
            assert_eq!(
                validate_probe_response(&bytes, &digest, &[0x5B; 32]),
                Err(ServiceProbeDebugGateError::Correlation)
            );
            assert_eq!(
                validate_probe_response(&bytes[..74], &digest, &nonce),
                Err(ServiceProbeDebugGateError::Correlation)
            );
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert_eq!(
                validate_probe_response(&trailing, &digest, &nonce),
                Err(ServiceProbeDebugGateError::Correlation)
            );
            bytes[0] ^= 1;
            assert_eq!(
                validate_probe_response(&bytes, &digest, &nonce),
                Err(ServiceProbeDebugGateError::Correlation)
            );
        }
    }

    fn handle(value: usize) -> HANDLE {
        HANDLE(value as *mut core::ffi::c_void)
    }

    struct FakeAliasIdentity;

    impl DebugEventAliasIdentityApi for FakeAliasIdentity {
        fn process_id(&self, handle: HANDLE) -> Option<u32> {
            match (handle.0 as usize)
                .checked_sub(1_000)
                .unwrap_or(handle.0 as usize)
            {
                10 => Some(20),
                13 => Some(30),
                _ => None,
            }
        }

        fn thread_identity(&self, handle: HANDLE) -> Option<ThreadAliasIdentity> {
            match (handle.0 as usize)
                .checked_sub(1_000)
                .unwrap_or(handle.0 as usize)
            {
                11 => Some(ThreadAliasIdentity {
                    process_id: 20,
                    thread_id: 21,
                }),
                12 => Some(ThreadAliasIdentity {
                    process_id: 20,
                    thread_id: 22,
                }),
                14 => Some(ThreadAliasIdentity {
                    process_id: 30,
                    thread_id: 31,
                }),
                _ => None,
            }
        }

        fn open_process_anchor(
            &self,
            event_handle: HANDLE,
            _process_id: u32,
        ) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError> {
            Ok(CheckedCanonicalAlias::synthetic(
                handle(event_handle.0 as usize + 1_000),
                false,
            ))
        }

        fn open_thread_anchor(
            &self,
            event_handle: HANDLE,
            _identity: ThreadAliasIdentity,
        ) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError> {
            Ok(CheckedCanonicalAlias::synthetic(
                handle(event_handle.0 as usize + 1_000),
                false,
            ))
        }

        fn same_object(&self, _first: HANDLE, _second: HANDLE) -> bool {
            true
        }
    }

    #[derive(Clone, Copy)]
    enum AnchorFailureStage {
        IdentityQuery,
        CanonicalOpen,
        CanonicalCompare,
        CanonicalCompareClose,
    }

    struct FailingAliasIdentity(AnchorFailureStage);

    impl DebugEventAliasIdentityApi for FailingAliasIdentity {
        fn process_id(&self, _handle: HANDLE) -> Option<u32> {
            (!matches!(self.0, AnchorFailureStage::IdentityQuery)).then_some(30)
        }

        fn thread_identity(&self, _handle: HANDLE) -> Option<ThreadAliasIdentity> {
            (!matches!(self.0, AnchorFailureStage::IdentityQuery)).then_some(ThreadAliasIdentity {
                process_id: 30,
                thread_id: 31,
            })
        }

        fn open_process_anchor(
            &self,
            event_handle: HANDLE,
            _process_id: u32,
        ) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError> {
            if matches!(self.0, AnchorFailureStage::CanonicalOpen) {
                Err(ServiceProbeDebugGateError::EventIdentity)
            } else {
                Ok(CheckedCanonicalAlias::synthetic(
                    handle(event_handle.0 as usize + 1_000),
                    matches!(self.0, AnchorFailureStage::CanonicalCompareClose),
                ))
            }
        }

        fn open_thread_anchor(
            &self,
            event_handle: HANDLE,
            _identity: ThreadAliasIdentity,
        ) -> Result<CheckedCanonicalAlias, ServiceProbeDebugGateError> {
            if matches!(self.0, AnchorFailureStage::CanonicalOpen) {
                Err(ServiceProbeDebugGateError::EventIdentity)
            } else {
                Ok(CheckedCanonicalAlias::synthetic(
                    handle(event_handle.0 as usize + 1_000),
                    matches!(self.0, AnchorFailureStage::CanonicalCompareClose),
                ))
            }
        }

        fn same_object(&self, _first: HANDLE, _second: HANDLE) -> bool {
            !matches!(self.0, AnchorFailureStage::IdentityQuery)
                && !matches!(self.0, AnchorFailureStage::CanonicalCompare)
                && !matches!(self.0, AnchorFailureStage::CanonicalCompareClose)
        }
    }

    #[test]
    fn detached_alias_shape_is_closed() {
        let complete = DetachedDebugEventAliases {
            process: Some(10),
            primary_thread: Some(11),
            rejected_thread: None,
            rejected_process: None,
            rejected_primary_thread: None,
            process_id: 20,
            primary_thread_id: 21,
            process_alias_id: Some(20),
            primary_thread_alias_process_id: Some(20),
            primary_thread_alias_id: Some(21),
            rejected_thread_id: None,
            rejected_thread_process_id: None,
            rejected_thread_anchor: None,
            rejected_process_id: None,
            rejected_process_anchor: None,
            rejected_primary_thread_id: None,
            rejected_primary_thread_process_id: None,
            rejected_primary_thread_anchor: None,
        };
        assert!(complete.complete());
        assert!(!complete.empty());

        let aliased = DetachedDebugEventAliases {
            primary_thread: Some(10),
            ..complete
        };
        assert!(!aliased.complete());
    }

    #[test]
    fn cleanup_registry_debug_is_data_free() {
        let cleanup = ServiceProbeDebugEventCleanup::new_shared();
        assert_eq!(
            format!("{cleanup:?}"),
            "ServiceProbeDebugEventCleanup([REDACTED])"
        );
    }

    #[test]
    fn cleanup_registry_accepts_one_exact_pair_and_latches_rejected_thread() {
        let cleanup = ServiceProbeDebugEventCleanup::new_shared();
        let process = handle(10);
        let primary_thread = handle(11);
        assert_eq!(
            cleanup.register_create_process_aliases_with(
                &FakeAliasIdentity,
                process,
                primary_thread,
                handle(100),
                handle(101),
                20,
                21,
            ),
            Ok(())
        );
        assert_eq!(cleanup.verify_complete_while_attached(20, 21), Ok(()));
        assert_eq!(
            cleanup.register_rejected_thread_alias_with(
                &FakeAliasIdentity,
                20,
                21,
                22,
                handle(12),
                handle(100),
                handle(101),
            ),
            Ok(())
        );
        assert_eq!(
            cleanup.verify_complete_while_attached(20, 21),
            Err(ServiceProbeDebugGateError::EventIdentity)
        );
        cleanup.disarm_synthetic_aliases_for_test();
    }

    #[test]
    fn cleanup_registry_retains_each_independently_safe_malformed_alias_once() {
        for (process, thread, expected) in [
            (handle(10), HANDLE::default(), (Some(10), None)),
            (HANDLE::default(), handle(11), (None, Some(11))),
            (handle(10), handle(10), (Some(10), None)),
            (handle(100), handle(11), (None, Some(11))),
            (handle(10), handle(101), (Some(10), None)),
        ] {
            let cleanup = ServiceProbeDebugEventCleanup::new_shared();
            assert_eq!(
                cleanup.register_create_process_aliases_with(
                    &FakeAliasIdentity,
                    process,
                    thread,
                    handle(100),
                    handle(101),
                    20,
                    21,
                ),
                Err(ServiceProbeDebugGateError::EventIdentity)
            );
            assert_eq!(cleanup.registered_primary_words_for_test(), Ok(expected));
            cleanup.disarm_synthetic_aliases_for_test();
        }

        let cleanup = ServiceProbeDebugEventCleanup::new_shared();
        assert_eq!(
            cleanup.register_create_process_aliases_with(
                &FailingAliasIdentity(AnchorFailureStage::IdentityQuery),
                handle(10),
                handle(11),
                handle(100),
                handle(101),
                20,
                21,
            ),
            Err(ServiceProbeDebugGateError::EventIdentity)
        );
        assert_eq!(
            cleanup.registered_primary_words_for_test(),
            Ok((Some(10), Some(11)))
        );
        cleanup.disarm_synthetic_aliases_for_test();

        let cleanup = ServiceProbeDebugEventCleanup::new_shared();
        assert_eq!(
            cleanup.register_create_process_aliases_with(
                &FakeAliasIdentity,
                handle(10),
                handle(11),
                handle(100),
                handle(101),
                0,
                0,
            ),
            Err(ServiceProbeDebugGateError::EventIdentity)
        );
        assert_eq!(
            cleanup.registered_primary_words_for_test(),
            Ok((Some(10), Some(11)))
        );
        cleanup.disarm_synthetic_aliases_for_test();
    }

    #[test]
    fn later_event_file_rejection_cannot_discard_registered_aliases() {
        let cleanup = ServiceProbeDebugEventCleanup::new_shared();
        assert_eq!(
            cleanup.register_create_process_aliases_with(
                &FakeAliasIdentity,
                handle(10),
                handle(11),
                handle(100),
                handle(101),
                20,
                21,
            ),
            Ok(())
        );
        assert!(matches!(
            CheckedFileHandle::adopt_event_distinct(handle(10), &cleanup, &[]),
            Err(ServiceProbeDebugGateError::EventIdentity)
        ));
        assert_eq!(
            cleanup.registered_primary_words_for_test(),
            Ok((Some(10), Some(11)))
        );
        cleanup.disarm_synthetic_aliases_for_test();
    }

    #[test]
    fn malformed_rejected_event_ids_do_not_discard_safe_aliases() {
        let cleanup = ServiceProbeDebugEventCleanup::new_shared();
        assert_eq!(
            cleanup.register_rejected_thread_alias_with(
                &FakeAliasIdentity,
                20,
                21,
                22,
                handle(12),
                handle(100),
                handle(101),
            ),
            Err(ServiceProbeDebugGateError::UnexpectedEvent)
        );
        assert_eq!(
            cleanup.registered_rejected_words_for_test(),
            Ok((Some(12), None, None))
        );
        cleanup.disarm_synthetic_aliases_for_test();

        let cleanup = ServiceProbeDebugEventCleanup::new_shared();
        assert_eq!(
            cleanup.register_create_process_aliases_with(
                &FakeAliasIdentity,
                handle(10),
                handle(11),
                handle(100),
                handle(101),
                20,
                21,
            ),
            Ok(())
        );
        assert_eq!(
            cleanup.register_rejected_thread_alias_with(
                &FakeAliasIdentity,
                20,
                21,
                0,
                handle(12),
                handle(100),
                handle(101),
            ),
            Err(ServiceProbeDebugGateError::EventIdentity)
        );
        assert_eq!(
            cleanup.registered_rejected_words_for_test(),
            Ok((Some(12), None, None))
        );
        cleanup.disarm_synthetic_aliases_for_test();

        for (process, thread, expected) in [
            (handle(13), HANDLE::default(), (None, Some(13), None)),
            (HANDLE::default(), handle(14), (None, None, Some(14))),
        ] {
            let cleanup = ServiceProbeDebugEventCleanup::new_shared();
            assert_eq!(
                cleanup.register_rejected_process_aliases_with(
                    &FakeAliasIdentity,
                    process,
                    thread,
                    handle(100),
                    handle(101),
                    0,
                    0,
                ),
                Err(ServiceProbeDebugGateError::UnexpectedEvent)
            );
            assert_eq!(cleanup.registered_rejected_words_for_test(), Ok(expected));
            cleanup.disarm_synthetic_aliases_for_test();
        }

        let cleanup = ServiceProbeDebugEventCleanup::new_shared();
        assert_eq!(
            cleanup.register_create_process_aliases_with(
                &FakeAliasIdentity,
                handle(10),
                handle(11),
                handle(100),
                handle(101),
                20,
                21,
            ),
            Ok(())
        );
        assert_eq!(
            cleanup.register_rejected_process_aliases_with(
                &FakeAliasIdentity,
                handle(13),
                handle(14),
                handle(100),
                handle(101),
                0,
                0,
            ),
            Err(ServiceProbeDebugGateError::EventIdentity)
        );
        assert_eq!(
            cleanup.registered_rejected_words_for_test(),
            Ok((None, Some(13), Some(14)))
        );
        cleanup.disarm_synthetic_aliases_for_test();
    }

    #[test]
    fn identity_open_compare_and_compare_close_failures_preserve_safe_raw_words() {
        for stage in [
            AnchorFailureStage::IdentityQuery,
            AnchorFailureStage::CanonicalOpen,
            AnchorFailureStage::CanonicalCompare,
            AnchorFailureStage::CanonicalCompareClose,
        ] {
            let expected_error = if matches!(stage, AnchorFailureStage::CanonicalCompareClose) {
                ServiceProbeDebugGateError::Cleanup
            } else {
                ServiceProbeDebugGateError::EventIdentity
            };
            let cleanup = ServiceProbeDebugEventCleanup::new_shared();
            assert_eq!(
                cleanup.register_create_process_aliases_with(
                    &FakeAliasIdentity,
                    handle(10),
                    handle(11),
                    handle(100),
                    handle(101),
                    20,
                    21,
                ),
                Ok(())
            );
            assert_eq!(
                cleanup.register_rejected_thread_alias_with(
                    &FailingAliasIdentity(stage),
                    20,
                    21,
                    31,
                    handle(14),
                    handle(100),
                    handle(101),
                ),
                Err(expected_error)
            );
            assert_eq!(
                cleanup.registered_rejected_words_for_test(),
                Ok((Some(14), None, None))
            );
            cleanup.disarm_synthetic_aliases_for_test();

            let cleanup = ServiceProbeDebugEventCleanup::new_shared();
            assert_eq!(
                cleanup.register_create_process_aliases_with(
                    &FakeAliasIdentity,
                    handle(10),
                    handle(11),
                    handle(100),
                    handle(101),
                    20,
                    21,
                ),
                Ok(())
            );
            assert_eq!(
                cleanup.register_rejected_process_aliases_with(
                    &FailingAliasIdentity(stage),
                    handle(13),
                    handle(14),
                    handle(100),
                    handle(101),
                    30,
                    31,
                ),
                Err(expected_error)
            );
            assert_eq!(
                cleanup.registered_rejected_words_for_test(),
                Ok((None, Some(13), Some(14)))
            );
            cleanup.disarm_synthetic_aliases_for_test();
        }
    }

    #[test]
    fn checked_authority_cleanup_failure_dominates_semantic_failure() {
        assert_eq!(
            cleanup_result_dominates::<()>(
                Err(ServiceProbeDebugGateError::EventIdentity),
                Err(ServiceProbeDebugGateError::Cleanup),
            ),
            Err(ServiceProbeDebugGateError::Cleanup)
        );
        assert_eq!(
            cleanup_result_dominates::<()>(Err(ServiceProbeDebugGateError::EventIdentity), Ok(()),),
            Err(ServiceProbeDebugGateError::EventIdentity)
        );
        assert_eq!(cleanup_result_dominates(Ok(7_u8), Ok(())), Ok(7));
        assert_eq!(
            merge_authority_errors(
                Some(ServiceProbeDebugGateError::EventIdentity),
                ServiceProbeDebugGateError::Cleanup,
            ),
            ServiceProbeDebugGateError::Cleanup
        );
        assert_eq!(
            merge_authority_errors(
                Some(ServiceProbeDebugGateError::Cleanup),
                ServiceProbeDebugGateError::EventIdentity,
            ),
            ServiceProbeDebugGateError::Cleanup
        );
        assert_eq!(
            merge_authority_errors(
                Some(ServiceProbeDebugGateError::EventIdentity),
                ServiceProbeDebugGateError::ImageIdentity,
            ),
            ServiceProbeDebugGateError::EventIdentity
        );

        let mut canonical = CheckedCanonicalAlias::synthetic(handle(500), false);
        assert_eq!(canonical.close_checked(), Ok(()));
        assert_eq!(canonical.raw(), HANDLE::default());
        let mut failing = CheckedCanonicalAlias::synthetic(handle(501), true);
        assert_eq!(
            failing.close_checked(),
            Err(ServiceProbeDebugGateError::Cleanup)
        );
        assert_eq!(failing.raw(), handle(501));
    }

    #[test]
    fn loader_limit_runs_authority_cleanup_first_and_cleanup_dominates() {
        let cleanup_attempted = Cell::new(false);
        assert_eq!(
            authenticate_loader_event_then_increment(MAX_LOADER_DEBUG_EVENTS, || {
                cleanup_attempted.set(true);
                Ok(())
            }),
            Err(ServiceProbeDebugGateError::UnexpectedEvent)
        );
        assert!(cleanup_attempted.get());

        cleanup_attempted.set(false);
        assert_eq!(
            authenticate_loader_event_then_increment(MAX_LOADER_DEBUG_EVENTS, || {
                cleanup_attempted.set(true);
                Err(ServiceProbeDebugGateError::Cleanup)
            }),
            Err(ServiceProbeDebugGateError::Cleanup)
        );
        assert!(cleanup_attempted.get());
        assert_eq!(
            authenticate_loader_event_then_increment(MAX_LOADER_DEBUG_EVENTS - 1, || Ok(())),
            Ok(MAX_LOADER_DEBUG_EVENTS)
        );
    }

    #[test]
    fn every_existing_rejected_authority_requires_fail_fast_before_overwrite() {
        assert!(!repeated_rejected_registration_requires_fail_fast(None));
        let mut aliases = DetachedDebugEventAliases::blank(20, 21);
        assert!(!repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));

        aliases.rejected_thread = Some(12);
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_thread = None;
        aliases.rejected_process = Some(13);
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_process = None;
        aliases.rejected_primary_thread = Some(14);
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_primary_thread = None;

        aliases.rejected_thread_id = Some(22);
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_thread_id = None;
        aliases.rejected_thread_process_id = Some(20);
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_thread_process_id = None;
        aliases.rejected_process_id = Some(30);
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_process_id = None;
        aliases.rejected_primary_thread_id = Some(31);
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_primary_thread_id = None;
        aliases.rejected_primary_thread_process_id = Some(30);
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_primary_thread_process_id = None;

        aliases.rejected_thread_anchor =
            Some(CheckedCanonicalAlias::synthetic(handle(1_012), false));
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_thread_anchor = None;
        aliases.rejected_process_anchor =
            Some(CheckedCanonicalAlias::synthetic(handle(1_013), false));
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
        aliases.rejected_process_anchor = None;
        aliases.rejected_primary_thread_anchor =
            Some(CheckedCanonicalAlias::synthetic(handle(1_014), false));
        assert!(repeated_rejected_registration_requires_fail_fast(Some(
            &aliases
        )));
    }

    #[test]
    fn residual_or_poisoned_registry_requires_process_wide_fail_fast() {
        assert!(cleanup_registry_drop_is_safe(false, false));
        assert!(!cleanup_registry_drop_is_safe(false, true));
        assert!(!cleanup_registry_drop_is_safe(true, false));
        assert!(!cleanup_registry_drop_is_safe(true, true));
    }

    struct KillOnExitAliasObservation {
        child: Child,
        process: usize,
        primary_thread: usize,
        rejected_thread: usize,
        process_anchor: CheckedCanonicalAlias,
        primary_thread_anchor: CheckedCanonicalAlias,
        rejected_thread_anchor: CheckedCanonicalAlias,
    }

    #[test]
    #[ignore = "kernel-matrix characterization: creates and kills a debuggee"]
    #[allow(clippy::too_many_lines)]
    fn kernel_matrix_default_kill_leaves_held_create_thread_aliases_live()
    -> Result<(), ServiceProbeDebugGateError> {
        let worker = std::thread::spawn(|| {
            let executable =
                std::env::current_exe().map_err(|_| ServiceProbeDebugGateError::UnexpectedEvent)?;
            let mut command = Command::new(executable);
            command
                .args([
                    "--exact",
                    "key_agent_service_launch::debug_gate::tests::kernel_matrix_probe_child",
                    "--ignored",
                    "--test-threads=1",
                ])
                .creation_flags((DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW).0);
            let child = command
                .spawn()
                .map_err(|_| ServiceProbeDebugGateError::UnexpectedEvent)?;
            let api = WindowsDebugEventAliasIdentityApi;
            let mut process = None;
            let mut primary_thread = None;
            let mut process_anchor = None;
            let mut primary_thread_anchor = None;
            for _ in 0..512 {
                let mut event = DEBUG_EVENT::default();
                // SAFETY: event is exact initialized writable storage and this
                // is the fresh OS thread that created the debuggee.
                unsafe { WaitForDebugEventEx(&raw mut event, 5_000) }
                    .map_err(|_| ServiceProbeDebugGateError::UnexpectedEvent)?;
                match event.dwDebugEventCode {
                    CREATE_PROCESS_DEBUG_EVENT => {
                        // SAFETY: the discriminant was matched above.
                        let create = unsafe { event.u.CreateProcessInfo };
                        let process_identity = api
                            .process_id(create.hProcess)
                            .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
                        let thread_identity = api
                            .thread_identity(create.hThread)
                            .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
                        if process_identity != child.id()
                            || thread_identity.process_id != child.id()
                            || event.dwProcessId != child.id()
                        {
                            return Err(ServiceProbeDebugGateError::EventIdentity);
                        }
                        process = Some(raw_handle_word(create.hProcess)?);
                        primary_thread = Some(raw_handle_word(create.hThread)?);
                        process_anchor = Some(retain_process_anchor(
                            &api,
                            create.hProcess,
                            process_identity,
                        )?);
                        primary_thread_anchor =
                            Some(retain_thread_anchor(&api, create.hThread, thread_identity)?);
                        if let Some(mut file) =
                            CheckedFileHandle::adopt_optional_event(create.hFile)?
                        {
                            file.close_checked()?;
                        }
                    }
                    CREATE_THREAD_DEBUG_EVENT => {
                        // SAFETY: the discriminant was matched above.
                        let create = unsafe { event.u.CreateThread };
                        let identity = api
                            .thread_identity(create.hThread)
                            .ok_or(ServiceProbeDebugGateError::EventIdentity)?;
                        if identity.process_id != child.id() {
                            return Err(ServiceProbeDebugGateError::EventIdentity);
                        }
                        return Ok(KillOnExitAliasObservation {
                            child,
                            process: process.ok_or(ServiceProbeDebugGateError::UnexpectedEvent)?,
                            primary_thread: primary_thread
                                .ok_or(ServiceProbeDebugGateError::UnexpectedEvent)?,
                            rejected_thread: raw_handle_word(create.hThread)?,
                            process_anchor: process_anchor
                                .ok_or(ServiceProbeDebugGateError::UnexpectedEvent)?,
                            primary_thread_anchor: primary_thread_anchor
                                .ok_or(ServiceProbeDebugGateError::UnexpectedEvent)?,
                            rejected_thread_anchor: retain_thread_anchor(
                                &api,
                                create.hThread,
                                identity,
                            )?,
                        });
                    }
                    LOAD_DLL_DEBUG_EVENT => {
                        // SAFETY: the discriminant was matched above.
                        let load = unsafe { event.u.LoadDll };
                        if let Some(mut file) = CheckedFileHandle::adopt_optional_event(load.hFile)?
                        {
                            file.close_checked()?;
                        }
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        return Err(ServiceProbeDebugGateError::UnexpectedEvent);
                    }
                    _ => {}
                }
                // SAFETY: this fresh worker still holds this exact event.
                unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) }
                    .map_err(|_| ServiceProbeDebugGateError::Detach)?;
            }
            Err(ServiceProbeDebugGateError::UnexpectedEvent)
        });
        let observation = worker
            .join()
            .map_err(|_| ServiceProbeDebugGateError::UnexpectedEvent)??;
        let KillOnExitAliasObservation {
            mut child,
            process,
            primary_thread,
            rejected_thread,
            mut process_anchor,
            mut primary_thread_anchor,
            mut rejected_thread_anchor,
        } = observation;
        let api = WindowsDebugEventAliasIdentityApi;
        let child_handle = HANDLE(child.as_raw_handle());
        // SAFETY: the creator process owner remains live; the default policy
        // should have made the child terminal when the worker exited.
        if unsafe { WaitForSingleObject(child_handle, 5_000) } != WAIT_OBJECT_0 {
            return Err(ServiceProbeDebugGateError::Cleanup);
        }
        let process = HANDLE(process as *mut core::ffi::c_void);
        let primary_thread = HANDLE(primary_thread as *mut core::ffi::c_void);
        let rejected_thread = HANDLE(rejected_thread as *mut core::ffi::c_void);
        if !handle_flags_are_zero(process)
            || !handle_flags_are_zero(primary_thread)
            || !handle_flags_are_zero(rejected_thread)
            || !api.same_object(process_anchor.raw(), process)
            || !api.same_object(primary_thread_anchor.raw(), primary_thread)
            || !api.same_object(rejected_thread_anchor.raw(), rejected_thread)
            || !api.same_object(child_handle, process)
        {
            return Err(ServiceProbeDebugGateError::Cleanup);
        }
        if !close_registered_alias(rejected_thread)
            || !close_registered_alias(primary_thread)
            || !close_registered_alias(process)
        {
            return Err(ServiceProbeDebugGateError::Cleanup);
        }
        rejected_thread_anchor.close_checked()?;
        primary_thread_anchor.close_checked()?;
        process_anchor.close_checked()?;
        child
            .wait()
            .map_err(|_| ServiceProbeDebugGateError::Cleanup)?;
        Ok(())
    }

    #[test]
    #[ignore = "child sentinel for the parent kernel-matrix characterization"]
    fn kernel_matrix_probe_child() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn protocol_phase_accepts_only_the_exact_two_gate_order() {
        use DebugProtocolPhase as Phase;
        use DebugProtocolTransition as Transition;

        let exact = [
            (
                Phase::AwaitingCreate,
                Transition::HoldCreate,
                Phase::CreateHeld,
            ),
            (
                Phase::CreateHeld,
                Transition::ContinueCreate,
                Phase::LoaderEvents,
            ),
            (
                Phase::LoaderEvents,
                Transition::HoldCapture,
                Phase::CaptureHeld,
            ),
            (
                Phase::CaptureHeld,
                Transition::ContinueCapture,
                Phase::CaptureContinued,
            ),
            (
                Phase::CaptureContinued,
                Transition::HoldAdoption,
                Phase::AdoptionHeld,
            ),
            (
                Phase::AdoptionHeld,
                Transition::ContinueAdoption,
                Phase::AdoptionContinued,
            ),
            (
                Phase::AdoptionContinued,
                Transition::PrepareNoKill,
                Phase::PreparedForNoKill,
            ),
        ];
        let phases = [
            Phase::AwaitingCreate,
            Phase::CreateHeld,
            Phase::LoaderEvents,
            Phase::CaptureHeld,
            Phase::CaptureContinued,
            Phase::AdoptionHeld,
            Phase::AdoptionContinued,
            Phase::PreparedForNoKill,
        ];
        let transitions = [
            Transition::HoldCreate,
            Transition::ContinueCreate,
            Transition::HoldCapture,
            Transition::ContinueCapture,
            Transition::HoldAdoption,
            Transition::ContinueAdoption,
            Transition::PrepareNoKill,
        ];
        for phase in phases {
            for transition in transitions {
                let expected = exact
                    .iter()
                    .find(|(from, event, _)| *from == phase && *event == transition)
                    .map(|(_, _, to)| *to);
                assert_eq!(phase.transition(transition).ok(), expected);
            }
        }
    }

    #[test]
    fn both_channel_duplicate_callers_are_confined_to_one_private_injection_step() {
        let source = include_str!("debug_gate.rs");
        let approval = ["duplicate_approval_", "channels_for_child("].concat();
        let secret = ["duplicate_secret_input_", "channels_for_child("].concat();
        let inject_call = ["self.inject_", "channels(sources)?"].concat();
        assert_eq!(source.matches(&approval).count(), 1);
        assert_eq!(source.matches(&secret).count(), 1);
        assert_eq!(source.matches(&inject_call).count(), 1);
        let injection_start = source.find("fn inject_channels(").unwrap_or(source.len());
        let injection_end = source[injection_start..]
            .find("fn install_channel_words(")
            .map_or(source.len(), |offset| injection_start + offset);
        assert!(injection_start < injection_end && injection_end <= source.len());
        assert!(
            source[injection_start..injection_end].contains(&approval)
                && source[injection_start..injection_end].contains(&secret)
        );
    }

    #[test]
    fn complete_context_readback_allows_only_r10_r11_and_reserved_eflags_bit() {
        let before = CONTEXT {
            ContextFlags: CONTEXT_FLAGS(0x0010_0003),
            P1Home: 1,
            P2Home: 2,
            P3Home: 3,
            P4Home: 4,
            P5Home: 5,
            P6Home: 6,
            SegCs: 0x33,
            SegSs: 0x2b,
            EFlags: 0x202,
            Rax: 7,
            Rcx: 8,
            Rdx: 9,
            Rbx: 10,
            Rsp: 11,
            Rbp: 12,
            Rsi: 13,
            Rdi: 14,
            R8: 15,
            R9: 16,
            R10: 17,
            R11: 18,
            R12: 19,
            R13: 20,
            R14: 21,
            R15: 22,
            Rip: 23,
            ..CONTEXT::default()
        };
        let mut after = before;
        after.R10 = 0x100;
        after.R11 = 0x200;
        after.EFlags &= !(1 << 1);
        assert!(contexts_match_except_r10_r11(&before, &after, 0x100, 0x200));

        for mutate in [
            |context: &mut CONTEXT| context.Rax ^= 1,
            |context: &mut CONTEXT| context.Rsp ^= 1,
            |context: &mut CONTEXT| context.R12 ^= 1,
            |context: &mut CONTEXT| context.Rip ^= 1,
            |context: &mut CONTEXT| context.P1Home ^= 1,
            |context: &mut CONTEXT| context.EFlags ^= 1 << 8,
        ] {
            let mut changed = after;
            mutate(&mut changed);
            assert!(!contexts_match_except_r10_r11(
                &before, &changed, 0x100, 0x200
            ));
        }
        let mut invalid_before = before;
        invalid_before.EFlags &= !(1 << 1);
        assert!(!contexts_match_except_r10_r11(
            &invalid_before,
            &after,
            0x100,
            0x200
        ));
    }

    #[test]
    fn correlation_deadline_is_nonzero_and_bounded_to_five_seconds()
    -> Result<(), key_agent_service_wire::WireError> {
        let epoch = EpochNonce::new([0x11; 32])?;
        let request = ServiceRequestId::new([0x22; 16])?;
        assert!(
            ServiceProbeDebugCorrelation::new(
                epoch,
                request,
                NonZeroU32::new(1).ok_or(key_agent_service_wire::WireError::InvalidValue)?,
            )
            .is_ok()
        );
        assert!(
            ServiceProbeDebugCorrelation::new(
                epoch,
                request,
                NonZeroU32::new(5_000).ok_or(key_agent_service_wire::WireError::InvalidValue)?,
            )
            .is_ok()
        );
        assert_eq!(
            ServiceProbeDebugCorrelation::new(
                epoch,
                request,
                NonZeroU32::new(5_001).ok_or(key_agent_service_wire::WireError::InvalidValue)?,
            )
            .err(),
            Some(ServiceProbeDebugGateError::Deadline)
        );
        let correlation = ServiceProbeDebugCorrelation::new(
            epoch,
            request,
            NonZeroU32::new(1).ok_or(key_agent_service_wire::WireError::InvalidValue)?,
        )
        .map_err(|_| key_agent_service_wire::WireError::InvalidValue)?;
        assert_eq!(
            format!("{correlation:?}"),
            "ServiceProbeDebugCorrelation([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn pending_success_is_send_but_not_sync_clone_or_copy() {
        assert_send::<PendingDebuggerExitServiceProbe>();
        assert_send::<ParentBootstrapChannels>();
        assert_send::<DetachedServiceProbe>();
        assert_send::<DetachedExpectedServiceHelper>();
        assert_send::<ServiceHelperConfirmationWaiter>();
        let _ = <PendingDebuggerExitServiceProbe as AmbiguousIfSync<_>>::marker;
        let _ = <PendingDebuggerExitServiceProbe as AmbiguousIfClone<_>>::marker;
        let _ = <PendingDebuggerExitServiceProbe as AmbiguousIfCopy<_>>::marker;
        let _ = <ParentBootstrapChannels as AmbiguousIfSync<_>>::marker;
        let _ = <ParentBootstrapChannels as AmbiguousIfClone<_>>::marker;
        let _ = <ParentBootstrapChannels as AmbiguousIfCopy<_>>::marker;
        let _ = <DetachedServiceProbe as AmbiguousIfSync<_>>::marker;
        let _ = <DetachedServiceProbe as AmbiguousIfClone<_>>::marker;
        let _ = <DetachedServiceProbe as AmbiguousIfCopy<_>>::marker;
        let _ = <DetachedExpectedServiceHelper as AmbiguousIfSync<_>>::marker;
        let _ = <DetachedExpectedServiceHelper as AmbiguousIfClone<_>>::marker;
        let _ = <DetachedExpectedServiceHelper as AmbiguousIfCopy<_>>::marker;
        let _ = <ServiceHelperConfirmationWaiter as AmbiguousIfSync<_>>::marker;
        let _ = <ServiceHelperConfirmationWaiter as AmbiguousIfClone<_>>::marker;
        let _ = <ServiceHelperConfirmationWaiter as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn process_and_confirmation_roles_split_only_on_exact_pair() {
        assert_eq!(
            expected_role_for_channel(ServiceProbeRole::Approval, HelperBootstrapRole::Approval,),
            Some(ExpectedHelperRole::Approval)
        );
        assert_eq!(
            expected_role_for_channel(
                ServiceProbeRole::SecretInput,
                HelperBootstrapRole::SecretInput,
            ),
            Some(ExpectedHelperRole::SecretInput)
        );
        assert_eq!(
            expected_role_for_channel(ServiceProbeRole::Approval, HelperBootstrapRole::SecretInput,),
            None
        );
        assert_eq!(
            expected_role_for_channel(ServiceProbeRole::SecretInput, HelperBootstrapRole::Approval,),
            None
        );
    }

    #[test]
    fn debugger_gate_errors_are_data_free() {
        for error in [
            ServiceProbeDebugGateError::Deadline,
            ServiceProbeDebugGateError::UnexpectedEvent,
            ServiceProbeDebugGateError::EventIdentity,
            ServiceProbeDebugGateError::ImageIdentity,
            ServiceProbeDebugGateError::GateAuthentication,
            ServiceProbeDebugGateError::Channel,
            ServiceProbeDebugGateError::Correlation,
            ServiceProbeDebugGateError::Suspension,
            ServiceProbeDebugGateError::Detach,
            ServiceProbeDebugGateError::JoinProof,
            ServiceProbeDebugGateError::Cleanup,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("0x"));
            assert!(!debug.contains('\\'));
        }
    }
}
