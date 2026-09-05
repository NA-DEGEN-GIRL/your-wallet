//! Per-call authentication for the debug-only local Key Agent RPC fixture.
//!
//! This module deliberately proves only a narrow Windows desktop-client
//! property. It does not identify an enrolled Broker image, establish service
//! identity, authorize wallet/signing operations, or atomically bind the RPC
//! origin process to the PID exposed by the V2 call-attributes API. The PID is
//! reopened, immediately re-queried from the live call, and retained only as a
//! fail-closed correlation observation.

mod sys;

use core::ffi::c_void;
use core::fmt;
use std::cell::Cell;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::os::windows::io::BorrowedHandle;
use std::rc::Rc;

use key_agent_service_rpc_sys::CallBinding;
#[cfg(test)]
use key_agent_service_rpc_sys::ManagerError;
use windows::Win32::System::Threading::STARTUPINFOW;
use zeroize::Zeroize as _;

use crate::inheritable_handle_launch::ProcessThreadCreationSecurity;

use super::expected_peer::{ExpectedHelperCandidate, ExpectedPeerVerificationError};

const RPC_AUTHN_LEVEL_PACKET_PRIVACY: u32 = 6;
const RPC_AUTHN_SERVICE_WINNT: u32 = 10;
const RPC_AUTHZ_SERVICE_NONE: u32 = 0;
// The Windows SDK defines `CallStatus` as cancellation/disconnection bits:
// zero is an active call, bit 0 is cancelled, and bit 1 is disconnected.
const RPC_CALL_STATUS_ACTIVE: u32 = 0;
const MEDIUM_INTEGRITY_RID: u32 = 0x2000;
const LOW_INTEGRITY_RID: u32 = 0x1000;
const MAX_BINARY_SID_BYTES: usize = 68;
pub(crate) const DESKTOP_PROCESS_CLEANUP_WAIT_MILLISECONDS: u64 =
    sys::DESKTOP_PROCESS_CLEANUP_WAIT_MILLISECONDS as u64;

/// Data-free authentication failure returned to the RPC manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RpcAuthError {
    /// A complete observation was inconsistent with the fixed caller policy.
    AccessDenied,
    /// Windows could not produce a complete, trustworthy observation.
    CallFailed,
}

#[cfg(test)]
impl RpcAuthError {
    pub(crate) const fn manager_error(self) -> ManagerError {
        match self {
            Self::AccessDenied => ManagerError::AccessDenied,
            Self::CallFailed => ManagerError::CallFailed,
        }
    }
}

impl fmt::Display for RpcAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AccessDenied => "RPC caller authentication was denied",
            Self::CallFailed => "RPC caller authentication could not be completed",
        })
    }
}

impl std::error::Error for RpcAuthError {}

/// Data-free failure classes for the sole desktop-user process-creation call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopProcessCreateError {
    /// The authenticated client or retained desktop token failed revalidation.
    Authentication,
    /// A required process-creation input did not have the exact fixed shape.
    InvalidInput,
    /// Windows rejected the exact `CreateProcessAsUserW` request.
    OperatingSystem,
}

impl fmt::Display for DesktopProcessCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Authentication => "desktop process authentication is unavailable",
            Self::InvalidInput => "desktop process creation inputs are invalid",
            Self::OperatingSystem => "desktop process creation failed",
        })
    }
}

impl std::error::Error for DesktopProcessCreateError {}

/// Data-free failure classes reported after debugger-thread exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopProcessCleanupError {
    /// The exact creator-owned process handle rejected the termination request.
    TerminationRequest,
    /// The terminated process did not signal within the fixed bounded wait.
    Wait,
    /// Both the termination request and the bounded wait failed.
    TerminationRequestAndWait,
}

impl fmt::Display for DesktopProcessCleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TerminationRequest => "desktop process termination request failed",
            Self::Wait => "desktop process cleanup wait failed",
            Self::TerminationRequestAndWait => {
                "desktop process termination request and cleanup wait failed"
            }
        })
    }
}

impl std::error::Error for DesktopProcessCleanupError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationError {
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopProcessAccessError {
    AccessAllowed,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadTokenState {
    Clear,
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallProtocol {
    LocalRpc,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallKind {
    Normal,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)] // These are independent native call facts, not mutable state.
struct CallObservation {
    local: bool,
    protocol: CallProtocol,
    interface_uuid_matches: bool,
    process_id: Option<NonZeroU32>,
    operation_number: u16,
    null_session: bool,
    kernel_mode_caller: bool,
    call_status: u32,
    call_kind: CallKind,
    authentication_level: u32,
    authentication_service: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthenticationObservation {
    authentication_level: u32,
    authentication_service: u32,
    authorization_service: u32,
}

#[derive(Eq, PartialEq)]
struct SidBytes(Vec<u8>);

impl SidBytes {
    fn has_valid_length(&self) -> bool {
        (8..=MAX_BINARY_SID_BYTES).contains(&self.0.len())
    }
}

impl fmt::Debug for SidBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SidBytes([REDACTED])")
    }
}

impl Drop for SidBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct AuthenticationId {
    low_part: u32,
    high_part: i32,
}

impl fmt::Debug for AuthenticationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticationId([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TokenId {
    low_part: u32,
    high_part: i32,
}

impl fmt::Debug for TokenId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenId([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Primary,
    Impersonation,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenLevel {
    NotApplicable,
    Impersonation,
    Delegation,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ElevationKind {
    Default,
    Limited,
    Full,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebugPrivilegeState {
    Absent,
    PresentDisabled,
    PresentEnabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenPolicy {
    DesktopBroker,
    ServiceCreatedLpacCandidate,
}

#[allow(clippy::struct_excessive_bools)] // Each boolean is an independently queried token-policy fact.
struct TokenObservation {
    user_sid: SidBytes,
    logon_sid_count: u32,
    logon_sid: Option<SidBytes>,
    session_id: u32,
    authentication_id: AuthenticationId,
    token_id: TokenId,
    token_kind: TokenKind,
    token_level: TokenLevel,
    app_container: bool,
    ui_access: bool,
    integrity_rid: u32,
    elevation: ElevationKind,
    restricted: bool,
    interactive_sid_enabled: bool,
    debug_privilege: DebugPrivilegeState,
}

impl fmt::Debug for TokenObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenObservation([REDACTED])")
    }
}

trait ProcessAuthOps {
    type Process;
    type DesktopPrimaryToken;

    fn open_process(&self, process_id: NonZeroU32) -> Result<Self::Process, ObservationError>;

    fn primary_token(&self, process: &Self::Process) -> Result<TokenObservation, ObservationError>;

    fn desktop_primary_token(
        &self,
        token: &Self::DesktopPrimaryToken,
    ) -> Result<TokenObservation, ObservationError>;

    fn exact_process_is_live(
        &self,
        process: &Self::Process,
        process_id: NonZeroU32,
    ) -> Result<bool, ObservationError>;

    fn same_process(
        &self,
        first: &Self::Process,
        second: &Self::Process,
    ) -> Result<bool, ObservationError>;
}

#[cfg(any(
    test,
    all(
        target_arch = "x86_64",
        target_env = "msvc",
        debug_assertions,
        feature = "key-agent-service-desktop-rpc-probe-feasibility-test-hook"
    )
))]
trait CurrentDesktopProbeOps: ProcessAuthOps {
    fn current_process_id(&self) -> Result<NonZeroU32, ObservationError>;

    fn current_thread_token_state(&self) -> Result<ThreadTokenState, ObservationError>;
}

/// Query-only preflight for the explicitly selected non-signing desktop probe.
///
/// This returns no identity or launch capability and does not authenticate the
/// service. Every RPC call still needs its own independent server-side checks.
#[cfg(all(
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "key-agent-service-desktop-rpc-probe-feasibility-test-hook"
))]
pub(super) fn preflight_current_desktop_probe() -> Result<(), RpcAuthError> {
    preflight_current_desktop_probe_with(&sys::WindowsProcessAuthOps)
}

#[cfg(any(
    test,
    all(
        target_arch = "x86_64",
        target_env = "msvc",
        debug_assertions,
        feature = "key-agent-service-desktop-rpc-probe-feasibility-test-hook"
    )
))]
fn preflight_current_desktop_probe_with<O: CurrentDesktopProbeOps>(
    ops: &O,
) -> Result<(), RpcAuthError> {
    if ops
        .current_thread_token_state()
        .map_err(|_| RpcAuthError::CallFailed)?
        != ThreadTokenState::Clear
    {
        return Err(RpcAuthError::AccessDenied);
    }
    let process_id = ops
        .current_process_id()
        .map_err(|_| RpcAuthError::CallFailed)?;
    let process = ops
        .open_process(process_id)
        .map_err(|_| RpcAuthError::CallFailed)?;
    let primary = ops
        .primary_token(&process)
        .map_err(|_| RpcAuthError::CallFailed)?;
    validate_token_policy(&primary, TokenKind::Primary, TokenPolicy::DesktopBroker)?;
    let _current = revalidate_client_process(
        process_id,
        &process,
        &primary,
        TokenPolicy::DesktopBroker,
        ops,
    )?;
    if ops
        .current_thread_token_state()
        .map_err(|_| RpcAuthError::CallFailed)?
        != ThreadTokenState::Clear
    {
        return Err(RpcAuthError::AccessDenied);
    }
    Ok(())
}

/// Query-only observation of the token currently effective on this thread.
///
/// The native handle remains confined to the Windows adapter. This narrow
/// seam exists only so the target-profile impersonation guard can prove that
/// Windows installed the already-authenticated desktop identity.
trait EffectiveThreadAuthOps: ProcessAuthOps {
    fn effective_thread_token(&self) -> Result<TokenObservation, ObservationError>;
}

trait DesktopImpersonationOps: EffectiveThreadAuthOps {
    fn thread_token_state(&self) -> Result<ThreadTokenState, ObservationError>;

    fn current_thread_cookie(&self) -> Result<NonZeroU32, ObservationError>;

    fn impersonate_desktop_primary_token(
        &self,
        token: &Self::DesktopPrimaryToken,
    ) -> Result<(), ObservationError>;

    fn revert_desktop_impersonation(&self) -> Result<(), ObservationError>;

    fn require_process_dup_handle_denied(
        &self,
        process_id: NonZeroU32,
    ) -> Result<(), DesktopProcessAccessError>;

    fn fail_fast(&self) -> !;
}

trait RpcAuthOps: ProcessAuthOps {
    fn call_observation(&self) -> Result<CallObservation, ObservationError>;

    fn authentication_observation(&self) -> Result<AuthenticationObservation, ObservationError>;

    fn thread_token_state(&self) -> Result<ThreadTokenState, ObservationError>;

    fn current_thread_cookie(&self) -> Result<NonZeroU32, ObservationError>;

    fn impersonate(&self) -> Result<(), ObservationError>;

    fn impersonation_token(&self) -> Result<TokenObservation, ObservationError>;

    fn duplicate_desktop_primary_token(
        &self,
    ) -> Result<Self::DesktopPrimaryToken, ObservationError>;

    fn revert(&self) -> Result<(), ObservationError>;

    fn fail_fast(&self) -> !;
}

/// A retained process and primary-token correlation for one authenticated call.
///
/// Debug output intentionally exposes neither PID, session, token identifiers,
/// nor SID material. V2 call attributes expose only a PID, so this value does
/// not claim an atomic kernel binding to the process that originated the RPC.
pub(crate) struct AuthenticatedClient<P, T> {
    process_id: NonZeroU32,
    process: P,
    primary: TokenObservation,
    desktop_primary_token: T,
    desktop_primary: TokenObservation,
    desktop_process_creation_claimed: Cell<bool>,
    desktop_process_dup_handle_denial_claimed: Cell<bool>,
}

impl<P, T> fmt::Debug for AuthenticatedClient<P, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedRpcClient([REDACTED])")
    }
}

pub(crate) type AuthenticatedRpcClient =
    AuthenticatedClient<sys::RetainedProcess, sys::DesktopPrimaryToken>;

/// A transport-authenticated `AppContainer` caller awaiting exact expected-peer
/// correlation.
///
/// This value proves only the local RPC transport, a retained process object,
/// and the deliberately broad `AppContainer` candidate policy. It does not by
/// itself prove LPAC, helper image, role, or service-created provenance. Those
/// facts remain owned by the expected-peer registry and must match this exact
/// process object before admission.
pub(crate) struct ServiceCreatedLpacCandidate<P = sys::RetainedProcess> {
    process_id: NonZeroU32,
    process: P,
    primary: TokenObservation,
}

impl<P> fmt::Debug for ServiceCreatedLpacCandidate<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceCreatedLpacCandidate([REDACTED])")
    }
}

impl<P> ServiceCreatedLpacCandidate<P> {
    fn revalidate_with<O>(&self, ops: &O) -> Result<(), RpcAuthError>
    where
        O: ProcessAuthOps<Process = P>,
    {
        let _current = revalidate_client_process(
            self.process_id,
            &self.process,
            &self.primary,
            TokenPolicy::ServiceCreatedLpacCandidate,
            ops,
        )?;
        Ok(())
    }
}

impl ServiceCreatedLpacCandidate {
    /// Compares the retained RPC caller process with another live process
    /// handle without exposing either raw handle.
    pub(crate) fn exactly_matches_process(
        &self,
        process: BorrowedHandle<'_>,
    ) -> Result<bool, RpcAuthError> {
        sys::retained_process_matches_borrowed(&self.process, process)
            .map_err(|_| RpcAuthError::CallFailed)
    }
}

impl ExpectedHelperCandidate for ServiceCreatedLpacCandidate {
    fn revalidate(&self) -> Result<(), ExpectedPeerVerificationError> {
        self.revalidate_with(&sys::WINDOWS_PROCESS_AUTH_OPS)
            .map_err(|error| match error {
                RpcAuthError::AccessDenied => ExpectedPeerVerificationError::Denied,
                RpcAuthError::CallFailed => ExpectedPeerVerificationError::Internal,
            })
    }
}

/// Server-derived manager-call kind. No helper role is accepted from the
/// client; a successful helper match receives its role from the registry.
pub(crate) enum AuthenticatedManagerPeer<P, T> {
    Desktop(AuthenticatedClient<P, T>),
    ServiceCreatedLpac(ServiceCreatedLpacCandidate<P>),
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
pub(crate) type AuthenticatedRpcManagerPeer =
    AuthenticatedManagerPeer<sys::RetainedProcess, sys::DesktopPrimaryToken>;

/// Callback authentication deliberately cannot mint desktop launch authority.
pub(crate) enum AuthenticatedCallbackPeer<P> {
    Desktop(AuthenticatedRpcCallback),
    ServiceCreatedLpac(ServiceCreatedLpacCandidate<P>),
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
pub(crate) type AuthenticatedRpcCallbackPeer = AuthenticatedCallbackPeer<sys::RetainedProcess>;

/// One-shot authority for the sole desktop-user process-creation call.
///
/// Claiming this value irreversibly consumes the authenticated client's launch
/// capability before revalidation. The authority is move-only and thread-bound.
#[must_use = "desktop process-creation authority must be consumed by one attempt"]
pub(crate) struct AuthenticatedDesktopProcessCreateAttempt<'client> {
    client: &'client AuthenticatedRpcClient,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl AuthenticatedDesktopProcessCreateAttempt<'_> {
    /// Creates the exact desktop-user child suspended under the fixed policy.
    ///
    /// # Safety
    ///
    /// `startup_info` must point to the `STARTUPINFOW` prefix of the live
    /// `STARTUPINFOEXW` retained by the service-probe startup owner. Its desktop
    /// string, attribute list, and every attribute backing allocation must stay
    /// valid and unmodified until this synchronous call returns.
    pub(crate) unsafe fn create_suspended_process(
        self,
        application_name: &[u16],
        security: ProcessThreadCreationSecurity<'_>,
        environment: &[u16],
        current_directory: &[u16],
        startup_info: *const STARTUPINFOW,
    ) -> Result<CreatedDesktopProcess, DesktopProcessCreateError> {
        self.client
            .revalidate()
            .map_err(|_| DesktopProcessCreateError::Authentication)?;
        // SAFETY: the caller upholds the complete startup allocation contract;
        // the remaining borrowed slices and paired attributes stay live for
        // this synchronous call by their ordinary Rust lifetimes.
        let state = unsafe {
            sys::create_process_as_desktop_user(
                &self.client.desktop_primary_token,
                application_name,
                security,
                environment,
                current_directory,
                startup_info,
            )
        }
        .map_err(map_native_process_create_error)?;
        Ok(CreatedDesktopProcess {
            state,
            _thread_bound: PhantomData,
        })
    }
}

impl fmt::Debug for AuthenticatedDesktopProcessCreateAttempt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedDesktopProcessCreateAttempt([REDACTED])")
    }
}

/// Creator-thread ownership of one suspended desktop-user process and thread.
///
/// This owner is deliberately `!Send + !Sync`. It must remain on the debugger
/// thread until its consuming termination transition is requested.
#[must_use = "the created desktop process requires an explicit cleanup transition"]
pub(crate) struct CreatedDesktopProcess {
    state: sys::CreatedDesktopProcess,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl CreatedDesktopProcess {
    /// Borrows the exact process handle returned by successful creation.
    pub(crate) fn process_handle(&self) -> BorrowedHandle<'_> {
        self.state.process_handle()
    }

    /// Borrows the exact primary-thread handle returned by successful creation.
    pub(crate) fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
        self.state.primary_thread_handle()
    }

    /// Returns the exact nonzero process identifier returned by creation.
    pub(crate) const fn process_id(&self) -> NonZeroU32 {
        self.state.process_id()
    }

    /// Returns the exact nonzero primary-thread identifier returned by creation.
    pub(crate) const fn primary_thread_id(&self) -> NonZeroU32 {
        self.state.primary_thread_id()
    }

    /// Requests termination without waiting and transfers both exact handles to
    /// the cleanup owner that may cross the debugger-thread join boundary.
    pub(crate) fn request_termination_into_pending_debugger_exit_cleanup(
        self,
    ) -> PendingDebuggerExitProcessCleanup {
        PendingDebuggerExitProcessCleanup {
            state: self
                .state
                .request_termination_into_pending_debugger_exit_cleanup(),
            _not_sync: PhantomData,
        }
    }

    /// Prepares the exact successful process-handle handoff before the final
    /// fallible debugger-thread operation.
    pub(crate) fn prepare_pending_debugger_exit_success(
        self,
    ) -> PreparedDebuggerExitProcessSuccess {
        PreparedDebuggerExitProcessSuccess {
            state: self.state.prepare_pending_debugger_exit_success(),
            _thread_bound: PhantomData,
        }
    }
}

impl fmt::Debug for CreatedDesktopProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CreatedDesktopProcess([REDACTED])")
    }
}

/// Thread-bound process handoff prepared before no-kill arming.
#[must_use = "the prepared process must commit or enter process-terminal cleanup"]
pub(crate) struct PreparedDebuggerExitProcessSuccess {
    state: sys::PreparedDebuggerExitProcessSuccess,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl PreparedDebuggerExitProcessSuccess {
    /// Infallibly commits the ownership phase after no-kill succeeds.
    pub(crate) fn commit_after_no_kill(self) -> PendingDebuggerExitProcessSuccess {
        PendingDebuggerExitProcessSuccess {
            state: self.state.commit_after_no_kill(),
            _not_sync: PhantomData,
        }
    }

    /// Requests termination after no-kill arming failed.
    pub(crate) fn abort_into_pending_cleanup(self) -> PendingDebuggerExitProcessCleanup {
        PendingDebuggerExitProcessCleanup {
            state: self.state.abort_into_pending_cleanup(),
            _not_sync: PhantomData,
        }
    }
}

impl fmt::Debug for PreparedDebuggerExitProcessSuccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedDebuggerExitProcessSuccess([REDACTED])")
    }
}

/// Sendable, non-shareable process owner awaiting debugger-thread join.
#[must_use = "consume the exact join proof before detached process access"]
pub(crate) struct PendingDebuggerExitProcessSuccess {
    state: sys::PendingDebuggerExitProcessSuccess,
    _not_sync: PhantomData<Cell<()>>,
}

impl PendingDebuggerExitProcessSuccess {
    pub(crate) fn finish_after_debugger_exit(self) -> DetachedDesktopProcess {
        DetachedDesktopProcess {
            state: self.state.finish_after_debugger_exit(),
            _not_sync: PhantomData,
        }
    }
}

impl fmt::Debug for PendingDebuggerExitProcessSuccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingDebuggerExitProcessSuccess([REDACTED])")
    }
}

/// Exact creator process/thread owners after debugger-thread join.
#[must_use = "the detached suspended process remains process-terminal on drop"]
pub(crate) struct DetachedDesktopProcess {
    state: sys::DetachedDesktopProcess,
    _not_sync: PhantomData<Cell<()>>,
}

impl DetachedDesktopProcess {
    pub(crate) fn process_handle(&self) -> BorrowedHandle<'_> {
        self.state.process_handle()
    }

    pub(crate) fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
        self.state.primary_thread_handle()
    }

    pub(crate) const fn process_id(&self) -> NonZeroU32 {
        self.state.process_id()
    }

    pub(crate) const fn primary_thread_id(&self) -> NonZeroU32 {
        self.state.primary_thread_id()
    }

    pub(crate) fn request_termination_for_cleanup(&self) -> Result<(), DesktopProcessCleanupError> {
        self.state
            .request_termination_for_cleanup()
            .map_err(map_native_process_cleanup_error)
    }

    pub(crate) fn wait_for_exit_for_cleanup(&self) -> Result<(), DesktopProcessCleanupError> {
        self.state
            .wait_for_exit_for_cleanup()
            .map_err(map_native_process_cleanup_error)
    }
}

impl fmt::Debug for DetachedDesktopProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DetachedDesktopProcess([REDACTED])")
    }
}

/// Sendable, non-shareable cleanup owner returned by the debugger thread.
///
/// The termination-request result is retained together with both exact handles;
/// after joining the debugger thread, the receiving thread must consume this
/// owner with `wait_and_close`.
#[must_use = "join the debugger thread, then wait and close the created process"]
pub(crate) struct PendingDebuggerExitProcessCleanup {
    state: sys::PendingDebuggerExitProcessCleanup,
    _not_sync: PhantomData<Cell<()>>,
}

impl PendingDebuggerExitProcessCleanup {
    pub(crate) fn process_handle(&self) -> BorrowedHandle<'_> {
        self.state.process_handle()
    }

    pub(crate) fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
        self.state.primary_thread_handle()
    }

    /// Waits for the process for the fixed bound, closes both exact handles, and
    /// reports the latched termination-request and wait outcomes.
    pub(crate) fn wait_and_close(self) -> Result<(), DesktopProcessCleanupError> {
        self.state
            .wait_and_close()
            .map_err(map_native_process_cleanup_error)
    }
}

impl fmt::Debug for PendingDebuggerExitProcessCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingDebuggerExitProcessCleanup([REDACTED])")
    }
}

/// Exact-once, same-thread ownership of target desktop impersonation.
///
/// No token handle is exposed. Dropping this value reverts the thread and
/// fail-fast terminates on a wrong-thread, revert, or residual-token anomaly.
#[must_use = "desktop impersonation must be finished on its originating thread"]
pub(crate) struct AuthenticatedDesktopImpersonation<'client> {
    state: DesktopImpersonation<
        'client,
        'static,
        sys::RetainedProcess,
        sys::DesktopPrimaryToken,
        sys::WindowsProcessAuthOps,
    >,
}

impl AuthenticatedDesktopImpersonation<'_> {
    /// Revalidates the exact originating thread and effective desktop token.
    pub(crate) fn recheck(&self) -> Result<(), RpcAuthError> {
        self.state.recheck()
    }

    /// Reverts exactly once, proves a clean thread, and revalidates the client.
    pub(crate) fn finish(self) -> Result<(), RpcAuthError> {
        self.state.finish()
    }
}

impl fmt::Debug for AuthenticatedDesktopImpersonation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedDesktopImpersonation([REDACTED])")
    }
}

/// Data-free success marker for the callback's independent identity check.
///
/// Unlike `AuthenticatedRpcClient`, this cannot carry launch authority and is
/// intentionally not usable as an epoch peer.
pub(crate) struct AuthenticatedRpcCallback {
    _private: (),
}

impl fmt::Debug for AuthenticatedRpcCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedRpcCallback([REDACTED])")
    }
}

impl AuthenticatedRpcClient {
    /// Reopens the PID, compares the exact process objects, checks liveness and
    /// restricted handle flags, then repeats the complete primary-token policy.
    pub(crate) fn revalidate(&self) -> Result<(), RpcAuthError> {
        self.revalidate_with(&sys::WindowsProcessAuthOps)
    }

    /// Revalidates and requires the retained client and desktop primary tokens
    /// to belong to the exact expected interactive session.
    pub(crate) fn require_desktop_session(&self, expected: NonZeroU32) -> Result<(), RpcAuthError> {
        self.require_desktop_session_with(expected, &sys::WindowsProcessAuthOps)
    }

    /// Proves that a created primary token retains the authenticated desktop
    /// user's exact identity while allowing the child's LPAC policy fields to
    /// differ from the source desktop token.
    pub(crate) fn require_desktop_child_identity(
        &self,
        token: BorrowedHandle<'_>,
    ) -> Result<(), RpcAuthError> {
        self.require_desktop_child_identity_with(&sys::WindowsProcessAuthOps, || {
            sys::desktop_child_token_observation(token)
        })
    }

    /// Irreversibly claims the client's single desktop process-creation attempt.
    /// The claim remains consumed even if the following revalidation fails.
    pub(crate) fn claim_desktop_process_creation(
        &self,
    ) -> Result<AuthenticatedDesktopProcessCreateAttempt<'_>, RpcAuthError> {
        self.claim_desktop_process_creation_with(&sys::WindowsProcessAuthOps)?;
        Ok(AuthenticatedDesktopProcessCreateAttempt {
            client: self,
            _thread_bound: PhantomData,
        })
    }

    /// Proves that the exact retained authenticated desktop token has no
    /// assigned `SeDebugPrivilege` and cannot reopen the exact still-suspended
    /// child with `PROCESS_DUP_HANDLE`.
    ///
    /// This authority is available exactly once and only after the client's
    /// process-creation authority was consumed. The access check runs while the
    /// current thread is impersonating the retained desktop primary token; both
    /// the effective token and retained client are revalidated around it. This
    /// is not evidence about external administrators or distinct tokens.
    pub(crate) fn require_desktop_process_dup_handle_denied(
        &self,
        process_id: NonZeroU32,
    ) -> Result<(), RpcAuthError> {
        self.require_desktop_process_dup_handle_denied_with(
            process_id,
            &sys::WINDOWS_PROCESS_AUTH_OPS,
        )
    }

    /// Revalidates and impersonates the exact retained desktop token, returning
    /// the only exact-once revert authority without exposing a token handle.
    pub(crate) fn impersonate_desktop_user(
        &self,
    ) -> Result<AuthenticatedDesktopImpersonation<'_>, RpcAuthError> {
        let state = self.impersonate_desktop_user_with(&sys::WINDOWS_PROCESS_AUTH_OPS)?;
        Ok(AuthenticatedDesktopImpersonation { state })
    }

    /// Establishes exact equality between two retained process handles only
    /// after both sides pass full liveness and primary-token revalidation.
    ///
    /// This compares the retained observations; it does not upgrade the initial
    /// non-atomic RPC PID correlation into an origin-process proof.
    pub(crate) fn exact_match(&self, current: &Self) -> Result<bool, RpcAuthError> {
        self.revalidate()?;
        current.revalidate()?;
        if self.process_id != current.process_id
            || !same_primary_token(&self.primary, &current.primary)
        {
            return Ok(false);
        }
        sys::WindowsProcessAuthOps
            .same_process(&self.process, &current.process)
            .map_err(|_| RpcAuthError::CallFailed)
    }
}

impl super::epoch::sealed::Sealed for AuthenticatedRpcClient {}

impl super::epoch::ExactEpochPeer for AuthenticatedRpcClient {
    fn exactly_matches(&self, current: &Self) -> Result<bool, super::epoch::PeerRevalidationError> {
        self.exact_match(current)
            .map_err(map_peer_revalidation_error)
    }

    fn revalidate(&self) -> Result<(), super::epoch::PeerRevalidationError> {
        AuthenticatedRpcClient::revalidate(self).map_err(map_peer_revalidation_error)
    }
}

impl From<RpcAuthError> for super::dispatch::AuthenticationFailure {
    fn from(error: RpcAuthError) -> Self {
        match error {
            RpcAuthError::AccessDenied => Self::Denied,
            RpcAuthError::CallFailed => Self::Internal,
        }
    }
}

const fn map_peer_revalidation_error(error: RpcAuthError) -> super::epoch::PeerRevalidationError {
    match error {
        RpcAuthError::AccessDenied => super::epoch::PeerRevalidationError::Denied,
        RpcAuthError::CallFailed => super::epoch::PeerRevalidationError::Internal,
    }
}

const fn map_native_process_create_error(
    error: sys::NativeDesktopProcessCreateError,
) -> DesktopProcessCreateError {
    match error {
        sys::NativeDesktopProcessCreateError::Authentication => {
            DesktopProcessCreateError::Authentication
        }
        sys::NativeDesktopProcessCreateError::InvalidInput => {
            DesktopProcessCreateError::InvalidInput
        }
        sys::NativeDesktopProcessCreateError::OperatingSystem => {
            DesktopProcessCreateError::OperatingSystem
        }
    }
}

const fn map_native_process_cleanup_error(
    error: sys::NativeDesktopProcessCleanupError,
) -> DesktopProcessCleanupError {
    match error {
        sys::NativeDesktopProcessCleanupError::TerminationRequest => {
            DesktopProcessCleanupError::TerminationRequest
        }
        sys::NativeDesktopProcessCleanupError::Wait => DesktopProcessCleanupError::Wait,
        sys::NativeDesktopProcessCleanupError::TerminationRequestAndWait => {
            DesktopProcessCleanupError::TerminationRequestAndWait
        }
    }
}

impl<P, T> AuthenticatedClient<P, T> {
    fn revalidate_with<O>(&self, ops: &O) -> Result<(), RpcAuthError>
    where
        O: ProcessAuthOps<Process = P, DesktopPrimaryToken = T>,
    {
        let current = revalidate_client_process(
            self.process_id,
            &self.process,
            &self.primary,
            TokenPolicy::DesktopBroker,
            ops,
        )?;

        let desktop_primary = ops
            .desktop_primary_token(&self.desktop_primary_token)
            .map_err(|_| RpcAuthError::CallFailed)?;
        validate_token_policy(
            &desktop_primary,
            TokenKind::Primary,
            TokenPolicy::DesktopBroker,
        )?;
        if !same_primary_token(&self.desktop_primary, &desktop_primary)
            || !same_token_identity(&desktop_primary, &current)
        {
            return Err(RpcAuthError::AccessDenied);
        }
        Ok(())
    }

    fn require_desktop_session_with<O>(
        &self,
        expected: NonZeroU32,
        ops: &O,
    ) -> Result<(), RpcAuthError>
    where
        O: ProcessAuthOps<Process = P, DesktopPrimaryToken = T>,
    {
        self.revalidate_with(ops)?;
        if self.primary.session_id != expected.get()
            || self.desktop_primary.session_id != expected.get()
        {
            return Err(RpcAuthError::AccessDenied);
        }
        Ok(())
    }

    fn require_desktop_child_identity_with<O, F>(
        &self,
        ops: &O,
        observe_child: F,
    ) -> Result<(), RpcAuthError>
    where
        O: ProcessAuthOps<Process = P, DesktopPrimaryToken = T>,
        F: FnOnce() -> Result<TokenObservation, ObservationError>,
    {
        self.revalidate_with(ops)?;
        let identity = observe_child()
            .map_err(|_| RpcAuthError::CallFailed)
            .and_then(|child| validate_desktop_child_identity(&self.desktop_primary, &child));
        let post_revalidation = self.revalidate_with(ops);
        match post_revalidation {
            Ok(()) => identity,
            Err(error) => Err(error),
        }
    }

    fn claim_desktop_process_creation_with<O>(&self, ops: &O) -> Result<(), RpcAuthError>
    where
        O: ProcessAuthOps<Process = P, DesktopPrimaryToken = T>,
    {
        if self.desktop_process_creation_claimed.replace(true) {
            return Err(RpcAuthError::AccessDenied);
        }
        self.revalidate_with(ops)
    }

    fn require_desktop_process_dup_handle_denied_with<O>(
        &self,
        process_id: NonZeroU32,
        ops: &O,
    ) -> Result<(), RpcAuthError>
    where
        O: DesktopImpersonationOps<Process = P, DesktopPrimaryToken = T>,
    {
        let already_claimed = self.desktop_process_dup_handle_denial_claimed.replace(true);
        if already_claimed || !self.desktop_process_creation_claimed.get() {
            return Err(RpcAuthError::AccessDenied);
        }

        let impersonation = self.impersonate_desktop_user_with(ops)?;
        let access =
            ops.require_process_dup_handle_denied(process_id)
                .map_err(|error| match error {
                    DesktopProcessAccessError::AccessAllowed => RpcAuthError::AccessDenied,
                    DesktopProcessAccessError::Incomplete => RpcAuthError::CallFailed,
                });
        let effective_postcheck = impersonation.recheck();
        let finish = impersonation.finish();

        finish?;
        effective_postcheck?;
        access
    }

    fn revalidate_effective_desktop_thread_with<O>(&self, ops: &O) -> Result<(), RpcAuthError>
    where
        O: EffectiveThreadAuthOps<Process = P, DesktopPrimaryToken = T>,
    {
        self.revalidate_with(ops)?;

        let effective = ops
            .effective_thread_token()
            .map_err(|_| RpcAuthError::CallFailed)?;
        validate_effective_desktop_thread_token(&effective)?;
        if !same_token_identity(&effective, &self.primary)
            || !same_token_identity(&effective, &self.desktop_primary)
        {
            return Err(RpcAuthError::AccessDenied);
        }
        Ok(())
    }

    fn impersonate_desktop_user_with<'client, 'ops, O>(
        &'client self,
        ops: &'ops O,
    ) -> Result<DesktopImpersonation<'client, 'ops, P, T, O>, RpcAuthError>
    where
        O: DesktopImpersonationOps<Process = P, DesktopPrimaryToken = T>,
    {
        self.revalidate_with(ops)?;
        if ops
            .thread_token_state()
            .map_err(|_| RpcAuthError::CallFailed)?
            != ThreadTokenState::Clear
        {
            return Err(RpcAuthError::AccessDenied);
        }
        let thread_cookie = ops
            .current_thread_cookie()
            .map_err(|_| RpcAuthError::CallFailed)?;
        ops.impersonate_desktop_primary_token(&self.desktop_primary_token)
            .map_err(|_| RpcAuthError::CallFailed)?;

        // There is no fallible operation between successful impersonation and
        // construction of this exact-once owner.
        let state = DesktopImpersonation::new(self, ops, thread_cookie);
        state.recheck()?;
        Ok(state)
    }
}

/// Authenticates exactly one synchronous manager invocation.
///
/// The `CallBinding` is consumed and remains confined to the Windows adapter;
/// it cannot be retained by the returned process proof.
#[cfg(not(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
)))]
pub(crate) fn authenticate_call(
    binding: CallBinding<'_>,
) -> Result<AuthenticatedRpcClient, RpcAuthError> {
    let ops = sys::WindowsRpcAuthOps::new(binding);
    authenticate_with(&ops)
}

/// Authenticates a manager invocation and derives only its transport peer kind.
///
/// A helper candidate is not admitted here. Exact LPAC/image/role provenance
/// remains a separate expected-peer registry decision.
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
pub(crate) fn authenticate_role_aware_call(
    binding: CallBinding<'_>,
) -> Result<AuthenticatedRpcManagerPeer, RpcAuthError> {
    let ops = sys::WindowsRpcAuthOps::new(binding);
    authenticate_role_aware_with(&ops)
}

/// Independently authenticates the binding context supplied to an If3
/// security callback.
///
/// # Safety
///
/// `raw` must be the non-null binding context passed by the RPC runtime to the
/// currently executing security callback. It must remain valid on this thread
/// until this function returns and must not be retained or freed by the caller.
#[cfg(any(
    not(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )),
    test
))]
pub(crate) unsafe fn authenticate_callback_context(
    raw: *const c_void,
) -> Result<AuthenticatedRpcCallback, RpcAuthError> {
    // SAFETY: the caller supplies the active callback's synchronous context;
    // the adapter retains it only inside this function.
    let ops = unsafe { sys::WindowsRpcAuthOps::from_callback(raw) }
        .map_err(|_| RpcAuthError::CallFailed)?;
    authenticate_callback_with(&ops)?;
    Ok(AuthenticatedRpcCallback { _private: () })
}

/// Independently derives the callback transport peer kind without minting
/// desktop launch authority or consuming an expected helper.
///
/// # Safety
///
/// `raw` must be the non-null synchronous callback binding supplied by the RPC
/// runtime and must remain valid until this function returns.
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
pub(crate) unsafe fn authenticate_role_aware_callback_context(
    raw: *const c_void,
) -> Result<AuthenticatedRpcCallbackPeer, RpcAuthError> {
    // SAFETY: the caller supplies the active callback's synchronous context;
    // the adapter retains it only inside this function.
    let ops = unsafe { sys::WindowsRpcAuthOps::from_callback(raw) }
        .map_err(|_| RpcAuthError::CallFailed)?;
    authenticate_role_aware_callback_with(&ops)
}

#[cfg(any(
    not(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )),
    test
))]
fn authenticate_with<O>(
    ops: &O,
) -> Result<AuthenticatedClient<O::Process, O::DesktopPrimaryToken>, RpcAuthError>
where
    O: RpcAuthOps,
{
    match authenticate_role_aware_with(ops)? {
        AuthenticatedManagerPeer::Desktop(client) => Ok(client),
        AuthenticatedManagerPeer::ServiceCreatedLpac(_) => Err(RpcAuthError::AccessDenied),
    }
}

enum AuthenticatedPeerMaterial<T> {
    Desktop {
        primary_token: T,
        primary: TokenObservation,
    },
    ServiceCreatedLpacCandidate,
}

fn authenticate_role_aware_with<O>(
    ops: &O,
) -> Result<AuthenticatedManagerPeer<O::Process, O::DesktopPrimaryToken>, RpcAuthError>
where
    O: RpcAuthOps,
{
    let (process_id, process, primary, material) = authenticate_identity_with(
        ops,
        |ops, impersonation, primary| match classify_peer_policy(impersonation, primary)? {
            TokenPolicy::DesktopBroker => {
                let desktop_primary_token = ops
                    .duplicate_desktop_primary_token()
                    .map_err(|_| RpcAuthError::CallFailed)?;
                let desktop_primary = ops
                    .desktop_primary_token(&desktop_primary_token)
                    .map_err(|_| RpcAuthError::CallFailed)?;
                validate_token_policy(
                    &desktop_primary,
                    TokenKind::Primary,
                    TokenPolicy::DesktopBroker,
                )?;
                if !same_token_identity(impersonation, &desktop_primary)
                    || !same_token_identity(primary, &desktop_primary)
                {
                    return Err(RpcAuthError::AccessDenied);
                }
                Ok(AuthenticatedPeerMaterial::Desktop {
                    primary_token: desktop_primary_token,
                    primary: desktop_primary,
                })
            }
            TokenPolicy::ServiceCreatedLpacCandidate => {
                Ok(AuthenticatedPeerMaterial::ServiceCreatedLpacCandidate)
            }
        },
    )?;

    match material {
        AuthenticatedPeerMaterial::Desktop {
            primary_token: desktop_primary_token,
            primary: desktop_primary,
        } => {
            let authenticated = AuthenticatedClient {
                process_id,
                process,
                primary,
                desktop_primary_token,
                desktop_primary,
                desktop_process_creation_claimed: Cell::new(false),
                desktop_process_dup_handle_denial_claimed: Cell::new(false),
            };
            authenticated.revalidate_with(ops)?;
            Ok(AuthenticatedManagerPeer::Desktop(authenticated))
        }
        AuthenticatedPeerMaterial::ServiceCreatedLpacCandidate => {
            let candidate = ServiceCreatedLpacCandidate {
                process_id,
                process,
                primary,
            };
            candidate.revalidate_with(ops)?;
            Ok(AuthenticatedManagerPeer::ServiceCreatedLpac(candidate))
        }
    }
}

#[cfg(any(
    not(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )),
    test
))]
fn authenticate_callback_with<O>(ops: &O) -> Result<(), RpcAuthError>
where
    O: RpcAuthOps,
{
    match authenticate_role_aware_callback_with(ops)? {
        AuthenticatedCallbackPeer::Desktop(_) => Ok(()),
        AuthenticatedCallbackPeer::ServiceCreatedLpac(_) => Err(RpcAuthError::AccessDenied),
    }
}

fn authenticate_role_aware_callback_with<O>(
    ops: &O,
) -> Result<AuthenticatedCallbackPeer<O::Process>, RpcAuthError>
where
    O: RpcAuthOps,
{
    let (process_id, process, primary, policy) =
        authenticate_identity_with(ops, |_ops, impersonation, primary| {
            classify_peer_policy(impersonation, primary)
        })?;
    match policy {
        TokenPolicy::DesktopBroker => {
            let _current = revalidate_client_process(
                process_id,
                &process,
                &primary,
                TokenPolicy::DesktopBroker,
                ops,
            )?;
            Ok(AuthenticatedCallbackPeer::Desktop(
                AuthenticatedRpcCallback { _private: () },
            ))
        }
        TokenPolicy::ServiceCreatedLpacCandidate => {
            let candidate = ServiceCreatedLpacCandidate {
                process_id,
                process,
                primary,
            };
            candidate.revalidate_with(ops)?;
            Ok(AuthenticatedCallbackPeer::ServiceCreatedLpac(candidate))
        }
    }
}

fn authenticate_identity_with<O, T, F>(
    ops: &O,
    while_impersonating: F,
) -> Result<(NonZeroU32, O::Process, TokenObservation, T), RpcAuthError>
where
    O: RpcAuthOps,
    F: FnOnce(&O, &TokenObservation, &TokenObservation) -> Result<T, RpcAuthError>,
{
    let call = ops
        .call_observation()
        .map_err(|_| RpcAuthError::CallFailed)?;
    let process_id = validate_call(call)?;

    let authentication = ops
        .authentication_observation()
        .map_err(|_| RpcAuthError::CallFailed)?;
    validate_authentication(authentication)?;

    match ops
        .thread_token_state()
        .map_err(|_| RpcAuthError::CallFailed)?
    {
        ThreadTokenState::Clear => {}
        ThreadTokenState::Present => return Err(RpcAuthError::AccessDenied),
    }

    // RPC_CALL_ATTRIBUTES_V2 exposes a numeric PID rather than an atomic
    // process object. Open it as soon as the two independent call/auth facts
    // are complete, then re-query the still-live call before trusting it even
    // as a retained correlation observation.
    let process = ops
        .open_process(process_id)
        .map_err(|_| RpcAuthError::CallFailed)?;
    let confirmed_call = ops
        .call_observation()
        .map_err(|_| RpcAuthError::CallFailed)?;
    if validate_call(confirmed_call)? != process_id {
        return Err(RpcAuthError::AccessDenied);
    }

    let thread_cookie = ops
        .current_thread_cookie()
        .map_err(|_| RpcAuthError::CallFailed)?;
    ops.impersonate().map_err(|_| RpcAuthError::CallFailed)?;
    let guard = ImpersonationGuard::new(ops, thread_cookie);

    let impersonation = ops
        .impersonation_token()
        .map_err(|_| RpcAuthError::CallFailed)?;
    validate_transport_token(&impersonation, TokenKind::Impersonation)?;

    let primary = ops
        .primary_token(&process)
        .map_err(|_| RpcAuthError::CallFailed)?;
    validate_transport_token(&primary, TokenKind::Primary)?;
    if !same_token_identity(&impersonation, &primary) {
        return Err(RpcAuthError::AccessDenied);
    }
    let extra = while_impersonating(ops, &impersonation, &primary)?;

    guard.finish();
    Ok((process_id, process, primary, extra))
}

fn revalidate_client_process<P, O>(
    process_id: NonZeroU32,
    process: &P,
    primary: &TokenObservation,
    policy: TokenPolicy,
    ops: &O,
) -> Result<TokenObservation, RpcAuthError>
where
    O: ProcessAuthOps<Process = P>,
{
    if !ops
        .exact_process_is_live(process, process_id)
        .map_err(|_| RpcAuthError::CallFailed)?
    {
        return Err(RpcAuthError::AccessDenied);
    }
    let current = ops
        .primary_token(process)
        .map_err(|_| RpcAuthError::CallFailed)?;
    validate_token_policy(&current, TokenKind::Primary, policy)?;
    if !same_primary_token(primary, &current) {
        return Err(RpcAuthError::AccessDenied);
    }
    Ok(current)
}

fn validate_call(call: CallObservation) -> Result<NonZeroU32, RpcAuthError> {
    if !call.local
        || call.protocol != CallProtocol::LocalRpc
        || !call.interface_uuid_matches
        || call.operation_number != 0
        || call.null_session
        || call.kernel_mode_caller
        || call.call_status != RPC_CALL_STATUS_ACTIVE
        || call.call_kind != CallKind::Normal
        || call.authentication_level != RPC_AUTHN_LEVEL_PACKET_PRIVACY
        || call.authentication_service != RPC_AUTHN_SERVICE_WINNT
    {
        return Err(RpcAuthError::AccessDenied);
    }
    call.process_id.ok_or(RpcAuthError::AccessDenied)
}

fn validate_authentication(authentication: AuthenticationObservation) -> Result<(), RpcAuthError> {
    if authentication.authentication_level != RPC_AUTHN_LEVEL_PACKET_PRIVACY
        || authentication.authentication_service != RPC_AUTHN_SERVICE_WINNT
        || authentication.authorization_service != RPC_AUTHZ_SERVICE_NONE
    {
        return Err(RpcAuthError::AccessDenied);
    }
    Ok(())
}

fn validate_transport_token(
    token: &TokenObservation,
    expected: TokenKind,
) -> Result<(), RpcAuthError> {
    let expected_level = match expected {
        TokenKind::Primary => TokenLevel::NotApplicable,
        TokenKind::Impersonation => TokenLevel::Impersonation,
        TokenKind::Other => return Err(RpcAuthError::AccessDenied),
    };
    if token.token_kind != expected || token.token_level != expected_level {
        return Err(RpcAuthError::AccessDenied);
    }
    Ok(())
}

fn validate_token_policy(
    token: &TokenObservation,
    expected: TokenKind,
    policy: TokenPolicy,
) -> Result<(), RpcAuthError> {
    validate_transport_token(token, expected)?;
    let accepted = match policy {
        TokenPolicy::DesktopBroker => satisfies_desktop_token_policy(token),
        TokenPolicy::ServiceCreatedLpacCandidate => {
            satisfies_service_created_lpac_candidate_policy(token)
        }
    };
    accepted.then_some(()).ok_or(RpcAuthError::AccessDenied)
}

fn classify_peer_policy(
    impersonation: &TokenObservation,
    primary: &TokenObservation,
) -> Result<TokenPolicy, RpcAuthError> {
    if validate_token_policy(
        impersonation,
        TokenKind::Impersonation,
        TokenPolicy::DesktopBroker,
    )
    .is_ok()
        && validate_token_policy(primary, TokenKind::Primary, TokenPolicy::DesktopBroker).is_ok()
    {
        return Ok(TokenPolicy::DesktopBroker);
    }
    validate_token_policy(
        impersonation,
        TokenKind::Impersonation,
        TokenPolicy::ServiceCreatedLpacCandidate,
    )?;
    validate_token_policy(
        primary,
        TokenKind::Primary,
        TokenPolicy::ServiceCreatedLpacCandidate,
    )?;
    Ok(TokenPolicy::ServiceCreatedLpacCandidate)
}

fn validate_effective_desktop_thread_token(token: &TokenObservation) -> Result<(), RpcAuthError> {
    if token.token_kind != TokenKind::Impersonation
        || !matches!(
            token.token_level,
            TokenLevel::Impersonation | TokenLevel::Delegation
        )
        || !satisfies_desktop_token_policy(token)
    {
        return Err(RpcAuthError::AccessDenied);
    }
    Ok(())
}

fn satisfies_desktop_token_policy(token: &TokenObservation) -> bool {
    // Reject assignment itself, not only an enabled bit: an assigned-but-
    // disabled SeDebugPrivilege could otherwise be enabled after admission and
    // bypass the child process DACL.
    if !token.user_sid.has_valid_length()
        || token.logon_sid_count != 1
        || token.session_id == 0
        || token
            .logon_sid
            .as_ref()
            .is_none_or(|sid| !sid.has_valid_length())
        || token.app_container
        || token.ui_access
        || token.integrity_rid != MEDIUM_INTEGRITY_RID
        || matches!(token.elevation, ElevationKind::Full | ElevationKind::Other)
        || !token.interactive_sid_enabled
        || token.debug_privilege != DebugPrivilegeState::Absent
    {
        return false;
    }
    true
}

fn satisfies_service_created_lpac_candidate_policy(token: &TokenObservation) -> bool {
    // This is intentionally only a transport candidate policy. Authoritative
    // LPAC class, exact profile SID, zero capabilities, image, and role remain
    // facts of the independently retained service-created peer.
    token.user_sid.has_valid_length()
        && token.logon_sid_count == 1
        && token.session_id != 0
        && token
            .logon_sid
            .as_ref()
            .is_some_and(SidBytes::has_valid_length)
        && token.app_container
        && !token.ui_access
        && token.integrity_rid == LOW_INTEGRITY_RID
        && token.restricted
        && token.elevation == ElevationKind::Limited
        && !token.interactive_sid_enabled
        && token.debug_privilege == DebugPrivilegeState::Absent
}

fn same_token_identity(first: &TokenObservation, second: &TokenObservation) -> bool {
    first.user_sid == second.user_sid
        && first.logon_sid_count == second.logon_sid_count
        && first.logon_sid == second.logon_sid
        && first.session_id == second.session_id
        && first.authentication_id == second.authentication_id
        && first.integrity_rid == second.integrity_rid
        && first.elevation == second.elevation
        && first.restricted == second.restricted
        && first.debug_privilege == second.debug_privilege
}

fn same_primary_token(first: &TokenObservation, second: &TokenObservation) -> bool {
    same_token_identity(first, second) && first.token_id == second.token_id
}

fn validate_desktop_child_identity(
    desktop: &TokenObservation,
    child: &TokenObservation,
) -> Result<(), RpcAuthError> {
    let child_logon_sid_is_valid = child
        .logon_sid
        .as_ref()
        .is_some_and(SidBytes::has_valid_length);
    if child.token_kind != TokenKind::Primary
        || child.token_level != TokenLevel::NotApplicable
        || !child.user_sid.has_valid_length()
        || child.logon_sid_count != 1
        || !child_logon_sid_is_valid
        || child.session_id == 0
        || child.user_sid != desktop.user_sid
        || child.logon_sid != desktop.logon_sid
        || child.session_id != desktop.session_id
        || child.authentication_id != desktop.authentication_id
    {
        return Err(RpcAuthError::AccessDenied);
    }
    Ok(())
}

#[must_use = "desktop impersonation must be reverted on this exact thread"]
struct DesktopImpersonation<'client, 'ops, P, T, O>
where
    O: DesktopImpersonationOps<Process = P, DesktopPrimaryToken = T>,
{
    client: &'client AuthenticatedClient<P, T>,
    ops: &'ops O,
    thread_cookie: NonZeroU32,
    active: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl<'client, 'ops, P, T, O> DesktopImpersonation<'client, 'ops, P, T, O>
where
    O: DesktopImpersonationOps<Process = P, DesktopPrimaryToken = T>,
{
    const fn new(
        client: &'client AuthenticatedClient<P, T>,
        ops: &'ops O,
        thread_cookie: NonZeroU32,
    ) -> Self {
        Self {
            client,
            ops,
            thread_cookie,
            active: true,
            _thread_bound: PhantomData,
        }
    }

    fn recheck(&self) -> Result<(), RpcAuthError> {
        if self.ops.current_thread_cookie() != Ok(self.thread_cookie) {
            self.ops.fail_fast();
        }
        self.client
            .revalidate_effective_desktop_thread_with(self.ops)
    }

    fn finish(mut self) -> Result<(), RpcAuthError> {
        self.revert_exact();
        self.client.revalidate_with(self.ops)
    }

    fn revert_exact(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let current = self.ops.current_thread_cookie();
        let reverted = self.ops.revert_desktop_impersonation();
        let token_state = self.ops.thread_token_state();
        if current != Ok(self.thread_cookie)
            || reverted.is_err()
            || token_state != Ok(ThreadTokenState::Clear)
        {
            self.ops.fail_fast();
        }
    }
}

impl<P, T, O> Drop for DesktopImpersonation<'_, '_, P, T, O>
where
    O: DesktopImpersonationOps<Process = P, DesktopPrimaryToken = T>,
{
    fn drop(&mut self) {
        self.revert_exact();
    }
}

#[must_use = "successful RPC impersonation must be reverted on this exact thread"]
struct ImpersonationGuard<'ops, O: RpcAuthOps> {
    ops: &'ops O,
    thread_cookie: NonZeroU32,
    active: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl<'ops, O: RpcAuthOps> ImpersonationGuard<'ops, O> {
    const fn new(ops: &'ops O, thread_cookie: NonZeroU32) -> Self {
        Self {
            ops,
            thread_cookie,
            active: true,
            _thread_bound: PhantomData,
        }
    }

    fn finish(mut self) {
        self.revert_exact();
    }

    fn revert_exact(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let current = self.ops.current_thread_cookie();
        let reverted = self.ops.revert();
        let token_state = self.ops.thread_token_state();
        if current != Ok(self.thread_cookie)
            || reverted.is_err()
            || token_state != Ok(ThreadTokenState::Clear)
        {
            self.ops.fail_fast();
        }
    }
}

impl<O: RpcAuthOps> Drop for ImpersonationGuard<'_, O> {
    fn drop(&mut self) {
        self.revert_exact();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticatedClient, AuthenticationId, AuthenticationObservation, CallKind,
        CallObservation, CallProtocol, DebugPrivilegeState, DesktopImpersonationOps,
        DesktopProcessAccessError, EffectiveThreadAuthOps, ElevationKind, ImpersonationGuard,
        NonZeroU32, ObservationError, ProcessAuthOps, RPC_AUTHN_LEVEL_PACKET_PRIVACY,
        RPC_AUTHN_SERVICE_WINNT, RPC_AUTHZ_SERVICE_NONE, RPC_CALL_STATUS_ACTIVE, RpcAuthError,
        RpcAuthOps, SidBytes, ThreadTokenState, TokenId, TokenKind, TokenLevel, TokenObservation,
        authenticate_callback_with, authenticate_with,
    };
    use core::cell::{Cell, RefCell};
    use std::rc::Rc;

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

    fn assert_send<T: Send>() {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Call,
        Authentication,
        ThreadState,
        ThreadCookie,
        Impersonate,
        ImpersonationToken,
        OpenProcess,
        PrimaryToken,
        DuplicateDesktopPrimary,
        DesktopPrimaryToken,
        DesktopChildToken,
        EffectiveThreadToken,
        ProcessDupHandleDenial,
        Revert,
        ExactProcess,
        SameProcess,
        FailFast,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeProcess(u32);

    struct FakeDesktopPrimaryToken {
        drops: Rc<Cell<u32>>,
    }

    #[test]
    fn desktop_impersonation_authority_is_thread_bound_move_only() {
        type Authority = super::AuthenticatedDesktopImpersonation<'static>;

        let _ = <Authority as AmbiguousIfSend<_>>::marker;
        let _ = <Authority as AmbiguousIfSync<_>>::marker;
        let _ = <Authority as AmbiguousIfClone<_>>::marker;
        let _ = <Authority as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn desktop_process_owners_enforce_thread_and_join_boundaries() {
        type Attempt = super::AuthenticatedDesktopProcessCreateAttempt<'static>;
        type Created = super::CreatedDesktopProcess;
        type Pending = super::PendingDebuggerExitProcessCleanup;

        let _ = <Attempt as AmbiguousIfSend<_>>::marker;
        let _ = <Attempt as AmbiguousIfSync<_>>::marker;
        let _ = <Attempt as AmbiguousIfClone<_>>::marker;
        let _ = <Attempt as AmbiguousIfCopy<_>>::marker;
        let _ = <Created as AmbiguousIfSend<_>>::marker;
        let _ = <Created as AmbiguousIfSync<_>>::marker;
        let _ = <Created as AmbiguousIfClone<_>>::marker;
        let _ = <Created as AmbiguousIfCopy<_>>::marker;
        assert_send::<Pending>();
        let _ = <Pending as AmbiguousIfSync<_>>::marker;
        let _ = <Pending as AmbiguousIfClone<_>>::marker;
        let _ = <Pending as AmbiguousIfCopy<_>>::marker;
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum EffectiveTokenMutation {
        Exact,
        UserSid,
        LogonSidCount,
        LogonSid,
        SessionId,
        AuthenticationId,
        IntegrityRid,
        Elevation,
        Restricted,
        AppContainer,
        UiAccess,
        InteractiveSidDisabled,
        DebugPrivilegePresentDisabled,
        DebugPrivilegePresentEnabled,
        WrongKind,
        WrongLevel,
        Delegation,
    }

    const REJECTED_EFFECTIVE_TOKEN_MUTATIONS: [EffectiveTokenMutation; 15] = [
        EffectiveTokenMutation::UserSid,
        EffectiveTokenMutation::LogonSidCount,
        EffectiveTokenMutation::LogonSid,
        EffectiveTokenMutation::SessionId,
        EffectiveTokenMutation::AuthenticationId,
        EffectiveTokenMutation::IntegrityRid,
        EffectiveTokenMutation::Elevation,
        EffectiveTokenMutation::Restricted,
        EffectiveTokenMutation::AppContainer,
        EffectiveTokenMutation::UiAccess,
        EffectiveTokenMutation::InteractiveSidDisabled,
        EffectiveTokenMutation::DebugPrivilegePresentDisabled,
        EffectiveTokenMutation::DebugPrivilegePresentEnabled,
        EffectiveTokenMutation::WrongKind,
        EffectiveTokenMutation::WrongLevel,
    ];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DesktopChildTokenMutation {
        Exact,
        UserSid,
        LogonSidCount,
        LogonSid,
        SessionId,
        AuthenticationId,
        TokenKind,
        TokenLevel,
    }

    impl Drop for FakeDesktopPrimaryToken {
        fn drop(&mut self) {
            self.drops.set(self.drops.get().saturating_add(1));
        }
    }

    struct FakeOps {
        events: RefCell<Vec<Event>>,
        call: Cell<Result<CallObservation, ObservationError>>,
        call_count: Cell<u32>,
        confirmed_process_id: Cell<u32>,
        authentication: Cell<Result<AuthenticationObservation, ObservationError>>,
        thread_present: Cell<bool>,
        thread_query_ok: Cell<bool>,
        residual_thread_present: Cell<bool>,
        residual_thread_query_ok: Cell<bool>,
        thread_cookie: Cell<u32>,
        impersonate_ok: Cell<bool>,
        impersonation_token_ok: Cell<bool>,
        service_created_lpac_candidate: Cell<bool>,
        impersonation_debug_privilege: Cell<DebugPrivilegeState>,
        matching_tokens: Cell<bool>,
        primary_token_id: Cell<u32>,
        primary_debug_privilege: Cell<DebugPrivilegeState>,
        open_process_ok: Cell<bool>,
        primary_token_ok: Cell<bool>,
        duplicate_desktop_primary_ok: Cell<bool>,
        desktop_primary_token_ok: Cell<bool>,
        desktop_primary_matches: Cell<bool>,
        desktop_primary_kind: Cell<TokenKind>,
        desktop_primary_session_id: Cell<u32>,
        desktop_primary_token_id: Cell<u32>,
        desktop_primary_debug_privilege: Cell<DebugPrivilegeState>,
        desktop_primary_drops: Rc<Cell<u32>>,
        effective_thread_token_ok: Cell<bool>,
        effective_token_mutation: Cell<EffectiveTokenMutation>,
        effective_token_mutation_after_access: Cell<Option<EffectiveTokenMutation>>,
        primary_debug_privilege_after_access: Cell<Option<DebugPrivilegeState>>,
        desktop_primary_debug_privilege_after_access: Cell<Option<DebugPrivilegeState>>,
        process_dup_handle_result: Cell<Result<(), DesktopProcessAccessError>>,
        exact_process: Cell<bool>,
        same_process: Cell<bool>,
        revert_ok: Cell<bool>,
    }

    impl FakeOps {
        fn approved() -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                call: Cell::new(Ok(approved_call())),
                call_count: Cell::new(0),
                confirmed_process_id: Cell::new(42),
                authentication: Cell::new(Ok(approved_authentication())),
                thread_present: Cell::new(false),
                thread_query_ok: Cell::new(true),
                residual_thread_present: Cell::new(false),
                residual_thread_query_ok: Cell::new(true),
                thread_cookie: Cell::new(7),
                impersonate_ok: Cell::new(true),
                impersonation_token_ok: Cell::new(true),
                service_created_lpac_candidate: Cell::new(false),
                impersonation_debug_privilege: Cell::new(DebugPrivilegeState::Absent),
                matching_tokens: Cell::new(true),
                primary_token_id: Cell::new(12),
                primary_debug_privilege: Cell::new(DebugPrivilegeState::Absent),
                open_process_ok: Cell::new(true),
                primary_token_ok: Cell::new(true),
                duplicate_desktop_primary_ok: Cell::new(true),
                desktop_primary_token_ok: Cell::new(true),
                desktop_primary_matches: Cell::new(true),
                desktop_primary_kind: Cell::new(TokenKind::Primary),
                desktop_primary_session_id: Cell::new(3),
                desktop_primary_token_id: Cell::new(21),
                desktop_primary_debug_privilege: Cell::new(DebugPrivilegeState::Absent),
                desktop_primary_drops: Rc::new(Cell::new(0)),
                effective_thread_token_ok: Cell::new(true),
                effective_token_mutation: Cell::new(EffectiveTokenMutation::Exact),
                effective_token_mutation_after_access: Cell::new(None),
                primary_debug_privilege_after_access: Cell::new(None),
                desktop_primary_debug_privilege_after_access: Cell::new(None),
                process_dup_handle_result: Cell::new(Ok(())),
                exact_process: Cell::new(true),
                same_process: Cell::new(true),
                revert_ok: Cell::new(true),
            }
        }

        fn record(&self, event: Event) {
            self.events.borrow_mut().push(event);
        }

        fn events(&self) -> Vec<Event> {
            self.events.borrow().clone()
        }
    }

    impl EffectiveThreadAuthOps for FakeOps {
        fn effective_thread_token(&self) -> Result<TokenObservation, ObservationError> {
            self.record(Event::EffectiveThreadToken);
            if !self.effective_thread_token_ok.get() {
                return Err(ObservationError::Incomplete);
            }
            let mut token = approved_token(TokenKind::Impersonation, 1);
            match self.effective_token_mutation.get() {
                EffectiveTokenMutation::Exact => {}
                EffectiveTokenMutation::UserSid => token.user_sid = SidBytes(vec![4; 12]),
                EffectiveTokenMutation::LogonSidCount => token.logon_sid_count = 2,
                EffectiveTokenMutation::LogonSid => {
                    token.logon_sid = Some(SidBytes(vec![4; 12]));
                }
                EffectiveTokenMutation::SessionId => token.session_id = 4,
                EffectiveTokenMutation::AuthenticationId => {
                    token.authentication_id.low_part = 19;
                }
                EffectiveTokenMutation::IntegrityRid => token.integrity_rid = 0x3000,
                EffectiveTokenMutation::Elevation => token.elevation = ElevationKind::Limited,
                EffectiveTokenMutation::Restricted => token.restricted = true,
                EffectiveTokenMutation::AppContainer => token.app_container = true,
                EffectiveTokenMutation::UiAccess => token.ui_access = true,
                EffectiveTokenMutation::InteractiveSidDisabled => {
                    token.interactive_sid_enabled = false;
                }
                EffectiveTokenMutation::DebugPrivilegePresentDisabled => {
                    token.debug_privilege = DebugPrivilegeState::PresentDisabled;
                }
                EffectiveTokenMutation::DebugPrivilegePresentEnabled => {
                    token.debug_privilege = DebugPrivilegeState::PresentEnabled;
                }
                EffectiveTokenMutation::WrongKind => token.token_kind = TokenKind::Primary,
                EffectiveTokenMutation::WrongLevel => token.token_level = TokenLevel::Other,
                EffectiveTokenMutation::Delegation => {
                    token.token_level = TokenLevel::Delegation;
                }
            }
            Ok(token)
        }
    }

    impl ProcessAuthOps for FakeOps {
        type Process = FakeProcess;
        type DesktopPrimaryToken = FakeDesktopPrimaryToken;

        fn open_process(&self, process_id: NonZeroU32) -> Result<Self::Process, ObservationError> {
            self.record(Event::OpenProcess);
            self.open_process_ok
                .get()
                .then_some(FakeProcess(process_id.get()))
                .ok_or(ObservationError::Incomplete)
        }

        fn primary_token(
            &self,
            _process: &Self::Process,
        ) -> Result<TokenObservation, ObservationError> {
            self.record(Event::PrimaryToken);
            if !self.primary_token_ok.get() {
                return Err(ObservationError::Incomplete);
            }
            let marker = if self.matching_tokens.get() { 1 } else { 2 };
            let mut token = if self.service_created_lpac_candidate.get() {
                approved_service_created_lpac_candidate_token(TokenKind::Primary, marker)
            } else {
                approved_token(TokenKind::Primary, marker)
            };
            token.token_id.low_part = self.primary_token_id.get();
            token.debug_privilege = self.primary_debug_privilege.get();
            Ok(token)
        }

        fn desktop_primary_token(
            &self,
            _token: &Self::DesktopPrimaryToken,
        ) -> Result<TokenObservation, ObservationError> {
            self.record(Event::DesktopPrimaryToken);
            if !self.desktop_primary_token_ok.get() {
                return Err(ObservationError::Incomplete);
            }
            let marker = if self.desktop_primary_matches.get() {
                1
            } else {
                3
            };
            let mut token = approved_token(self.desktop_primary_kind.get(), marker);
            token.session_id = self.desktop_primary_session_id.get();
            token.token_id.low_part = self.desktop_primary_token_id.get();
            token.debug_privilege = self.desktop_primary_debug_privilege.get();
            Ok(token)
        }

        fn exact_process_is_live(
            &self,
            _process: &Self::Process,
            _process_id: NonZeroU32,
        ) -> Result<bool, ObservationError> {
            self.record(Event::ExactProcess);
            Ok(self.exact_process.get())
        }

        fn same_process(
            &self,
            _first: &Self::Process,
            _second: &Self::Process,
        ) -> Result<bool, ObservationError> {
            self.record(Event::SameProcess);
            Ok(self.same_process.get())
        }
    }

    impl RpcAuthOps for FakeOps {
        fn call_observation(&self) -> Result<CallObservation, ObservationError> {
            self.record(Event::Call);
            let call_index = self.call_count.get();
            self.call_count.set(call_index.saturating_add(1));
            let mut call = self.call.get()?;
            if call_index > 0 {
                call.process_id = NonZeroU32::new(self.confirmed_process_id.get());
            }
            Ok(call)
        }

        fn authentication_observation(
            &self,
        ) -> Result<AuthenticationObservation, ObservationError> {
            self.record(Event::Authentication);
            self.authentication.get()
        }

        fn thread_token_state(&self) -> Result<ThreadTokenState, ObservationError> {
            self.record(Event::ThreadState);
            let after_revert = self.events.borrow().contains(&Event::Revert);
            let query_ok = if after_revert {
                self.residual_thread_query_ok.get()
            } else {
                self.thread_query_ok.get()
            };
            if !query_ok {
                return Err(ObservationError::Incomplete);
            }
            let present = if after_revert {
                self.residual_thread_present.get()
            } else {
                self.thread_present.get()
            };
            Ok(if present {
                ThreadTokenState::Present
            } else {
                ThreadTokenState::Clear
            })
        }

        fn current_thread_cookie(&self) -> Result<NonZeroU32, ObservationError> {
            self.record(Event::ThreadCookie);
            NonZeroU32::new(self.thread_cookie.get()).ok_or(ObservationError::Incomplete)
        }

        fn impersonate(&self) -> Result<(), ObservationError> {
            self.record(Event::Impersonate);
            self.impersonate_ok
                .get()
                .then_some(())
                .ok_or(ObservationError::Incomplete)
        }

        fn impersonation_token(&self) -> Result<TokenObservation, ObservationError> {
            self.record(Event::ImpersonationToken);
            self.impersonation_token_ok
                .get()
                .then(|| {
                    let mut token = if self.service_created_lpac_candidate.get() {
                        approved_service_created_lpac_candidate_token(TokenKind::Impersonation, 1)
                    } else {
                        approved_token(TokenKind::Impersonation, 1)
                    };
                    token.debug_privilege = self.impersonation_debug_privilege.get();
                    token
                })
                .ok_or(ObservationError::Incomplete)
        }

        fn duplicate_desktop_primary_token(
            &self,
        ) -> Result<Self::DesktopPrimaryToken, ObservationError> {
            self.record(Event::DuplicateDesktopPrimary);
            self.duplicate_desktop_primary_ok
                .get()
                .then(|| FakeDesktopPrimaryToken {
                    drops: Rc::clone(&self.desktop_primary_drops),
                })
                .ok_or(ObservationError::Incomplete)
        }

        fn revert(&self) -> Result<(), ObservationError> {
            self.record(Event::Revert);
            self.revert_ok
                .get()
                .then_some(())
                .ok_or(ObservationError::Incomplete)
        }

        fn fail_fast(&self) -> ! {
            self.record(Event::FailFast);
            std::panic::resume_unwind(Box::new("test fail-fast sentinel"))
        }
    }

    impl DesktopImpersonationOps for FakeOps {
        fn thread_token_state(&self) -> Result<ThreadTokenState, ObservationError> {
            <Self as RpcAuthOps>::thread_token_state(self)
        }

        fn current_thread_cookie(&self) -> Result<NonZeroU32, ObservationError> {
            <Self as RpcAuthOps>::current_thread_cookie(self)
        }

        fn impersonate_desktop_primary_token(
            &self,
            _token: &Self::DesktopPrimaryToken,
        ) -> Result<(), ObservationError> {
            <Self as RpcAuthOps>::impersonate(self)
        }

        fn revert_desktop_impersonation(&self) -> Result<(), ObservationError> {
            <Self as RpcAuthOps>::revert(self)
        }

        fn require_process_dup_handle_denied(
            &self,
            _process_id: NonZeroU32,
        ) -> Result<(), DesktopProcessAccessError> {
            self.record(Event::ProcessDupHandleDenial);
            if let Some(mutation) = self.effective_token_mutation_after_access.get() {
                self.effective_token_mutation.set(mutation);
            }
            if let Some(state) = self.primary_debug_privilege_after_access.get() {
                self.primary_debug_privilege.set(state);
            }
            if let Some(state) = self.desktop_primary_debug_privilege_after_access.get() {
                self.desktop_primary_debug_privilege.set(state);
            }
            self.process_dup_handle_result.get()
        }

        fn fail_fast(&self) -> ! {
            <Self as RpcAuthOps>::fail_fast(self)
        }
    }

    fn approved_call() -> CallObservation {
        CallObservation {
            local: true,
            protocol: CallProtocol::LocalRpc,
            interface_uuid_matches: true,
            process_id: NonZeroU32::new(42),
            operation_number: 0,
            null_session: false,
            kernel_mode_caller: false,
            call_status: RPC_CALL_STATUS_ACTIVE,
            call_kind: CallKind::Normal,
            authentication_level: RPC_AUTHN_LEVEL_PACKET_PRIVACY,
            authentication_service: RPC_AUTHN_SERVICE_WINNT,
        }
    }

    const fn approved_authentication() -> AuthenticationObservation {
        AuthenticationObservation {
            authentication_level: RPC_AUTHN_LEVEL_PACKET_PRIVACY,
            authentication_service: RPC_AUTHN_SERVICE_WINNT,
            authorization_service: RPC_AUTHZ_SERVICE_NONE,
        }
    }

    fn approved_token(kind: TokenKind, marker: u8) -> TokenObservation {
        TokenObservation {
            user_sid: SidBytes(vec![marker; 12]),
            logon_sid_count: 1,
            logon_sid: Some(SidBytes(vec![marker.saturating_add(1); 12])),
            session_id: 3,
            authentication_id: AuthenticationId {
                low_part: 11,
                high_part: 0,
            },
            token_id: TokenId {
                low_part: 12,
                high_part: 0,
            },
            token_kind: kind,
            token_level: match kind {
                TokenKind::Primary => TokenLevel::NotApplicable,
                TokenKind::Impersonation => TokenLevel::Impersonation,
                TokenKind::Other => TokenLevel::Other,
            },
            app_container: false,
            ui_access: false,
            integrity_rid: super::MEDIUM_INTEGRITY_RID,
            elevation: ElevationKind::Default,
            restricted: false,
            interactive_sid_enabled: true,
            debug_privilege: DebugPrivilegeState::Absent,
        }
    }

    fn approved_service_created_lpac_candidate_token(
        kind: TokenKind,
        marker: u8,
    ) -> TokenObservation {
        let mut token = approved_token(kind, marker);
        token.app_container = true;
        token.integrity_rid = super::LOW_INTEGRITY_RID;
        token.elevation = ElevationKind::Limited;
        token.restricted = true;
        token.interactive_sid_enabled = false;
        token
    }

    fn desktop_child_token(mutation: DesktopChildTokenMutation) -> TokenObservation {
        let mut token = approved_token(TokenKind::Primary, 1);
        // A target LPAC token intentionally differs from its source desktop
        // token on policy facts that are not identity: these changes must not
        // be folded into the narrow child-identity comparison.
        token.token_id.low_part = 91;
        token.integrity_rid = 0x1000;
        token.elevation = ElevationKind::Limited;
        token.restricted = true;
        token.app_container = true;
        token.interactive_sid_enabled = false;
        match mutation {
            DesktopChildTokenMutation::Exact => {}
            DesktopChildTokenMutation::UserSid => token.user_sid = SidBytes(vec![4; 12]),
            DesktopChildTokenMutation::LogonSidCount => token.logon_sid_count = 2,
            DesktopChildTokenMutation::LogonSid => {
                token.logon_sid = Some(SidBytes(vec![4; 12]));
            }
            DesktopChildTokenMutation::SessionId => token.session_id = 4,
            DesktopChildTokenMutation::AuthenticationId => {
                token.authentication_id.low_part = 19;
            }
            DesktopChildTokenMutation::TokenKind => token.token_kind = TokenKind::Other,
            DesktopChildTokenMutation::TokenLevel => token.token_level = TokenLevel::Other,
        }
        token
    }

    #[test]
    fn approved_call_runs_the_complete_order_and_reverts_before_revalidation() {
        let ops = FakeOps::approved();
        let result = authenticate_with(&ops);
        assert!(result.is_ok());
        assert_eq!(
            ops.events(),
            vec![
                Event::Call,
                Event::Authentication,
                Event::ThreadState,
                Event::OpenProcess,
                Event::Call,
                Event::ThreadCookie,
                Event::Impersonate,
                Event::ImpersonationToken,
                Event::PrimaryToken,
                Event::DuplicateDesktopPrimary,
                Event::DesktopPrimaryToken,
                Event::ThreadCookie,
                Event::Revert,
                Event::ThreadState,
                Event::ExactProcess,
                Event::PrimaryToken,
                Event::DesktopPrimaryToken,
            ]
        );
    }

    #[test]
    fn callback_authenticates_independently_without_minting_launch_authority() {
        let ops = FakeOps::approved();
        assert_eq!(authenticate_callback_with(&ops), Ok(()));
        assert!(!ops.events().contains(&Event::DuplicateDesktopPrimary));
        assert!(!ops.events().contains(&Event::DesktopPrimaryToken));
        assert_eq!(ops.desktop_primary_drops.get(), 0);
        assert_eq!(
            ops.events()
                .iter()
                .filter(|event| **event == Event::Revert)
                .count(),
            1
        );
    }

    #[test]
    fn role_aware_transport_derives_helper_without_desktop_launch_authority() {
        let manager_ops = FakeOps::approved();
        manager_ops.service_created_lpac_candidate.set(true);
        let manager = super::authenticate_role_aware_with(&manager_ops);
        assert!(matches!(
            manager,
            Ok(super::AuthenticatedManagerPeer::ServiceCreatedLpac(_))
        ));
        assert!(
            !manager_ops
                .events()
                .contains(&Event::DuplicateDesktopPrimary)
        );
        assert!(!manager_ops.events().contains(&Event::DesktopPrimaryToken));
        assert_eq!(manager_ops.desktop_primary_drops.get(), 0);

        let callback_ops = FakeOps::approved();
        callback_ops.service_created_lpac_candidate.set(true);
        let callback = super::authenticate_role_aware_callback_with(&callback_ops);
        assert!(matches!(
            callback,
            Ok(super::AuthenticatedCallbackPeer::ServiceCreatedLpac(_))
        ));
        assert!(
            !callback_ops
                .events()
                .contains(&Event::DuplicateDesktopPrimary)
        );
        assert!(!callback_ops.events().contains(&Event::DesktopPrimaryToken));

        let desktop_only_ops = FakeOps::approved();
        desktop_only_ops.service_created_lpac_candidate.set(true);
        assert!(matches!(
            authenticate_with(&desktop_only_ops),
            Err(RpcAuthError::AccessDenied)
        ));
    }

    #[test]
    fn helper_candidate_policy_rejects_every_selected_transport_fact() {
        let exact = approved_service_created_lpac_candidate_token(TokenKind::Primary, 1);
        assert_eq!(
            super::validate_token_policy(
                &exact,
                TokenKind::Primary,
                super::TokenPolicy::ServiceCreatedLpacCandidate,
            ),
            Ok(())
        );

        let mutations: [fn(&mut TokenObservation); 17] = [
            |token| token.user_sid = SidBytes(vec![1; 7]),
            |token| token.logon_sid_count = 0,
            |token| token.logon_sid_count = 2,
            |token| token.logon_sid = None,
            |token| token.logon_sid = Some(SidBytes(vec![2; 7])),
            |token| token.session_id = 0,
            |token| token.app_container = false,
            |token| token.ui_access = true,
            |token| token.integrity_rid = super::MEDIUM_INTEGRITY_RID,
            |token| token.elevation = ElevationKind::Default,
            |token| token.elevation = ElevationKind::Full,
            |token| token.restricted = false,
            |token| token.interactive_sid_enabled = true,
            |token| token.debug_privilege = DebugPrivilegeState::PresentDisabled,
            |token| token.debug_privilege = DebugPrivilegeState::PresentEnabled,
            |token| token.token_kind = TokenKind::Other,
            |token| token.token_level = TokenLevel::Other,
        ];
        for mutate in mutations {
            let mut rejected = approved_service_created_lpac_candidate_token(TokenKind::Primary, 1);
            mutate(&mut rejected);
            assert_eq!(
                super::validate_token_policy(
                    &rejected,
                    TokenKind::Primary,
                    super::TokenPolicy::ServiceCreatedLpacCandidate,
                ),
                Err(RpcAuthError::AccessDenied)
            );
        }

        let helper = approved_service_created_lpac_candidate_token(TokenKind::Impersonation, 1);
        let desktop = approved_token(TokenKind::Primary, 1);
        assert_eq!(
            super::classify_peer_policy(&helper, &desktop),
            Err(RpcAuthError::AccessDenied)
        );
    }

    #[test]
    fn helper_candidate_is_move_only_send_and_data_free() {
        type Candidate = super::ServiceCreatedLpacCandidate<FakeProcess>;
        assert_send::<Candidate>();
        let _ = <Candidate as AmbiguousIfClone<_>>::marker;
        let _ = <Candidate as AmbiguousIfCopy<_>>::marker;
        let candidate = Candidate {
            process_id: NonZeroU32::MIN,
            process: FakeProcess(1),
            primary: approved_service_created_lpac_candidate_token(TokenKind::Primary, 1),
        };
        assert_eq!(
            format!("{candidate:?}"),
            "ServiceCreatedLpacCandidate([REDACTED])"
        );
    }

    #[test]
    fn every_call_attribute_is_fail_closed_before_authentication() {
        let mutations: [fn(&mut CallObservation); 13] = [
            |call: &mut CallObservation| call.local = false,
            |call: &mut CallObservation| call.protocol = CallProtocol::Other,
            |call: &mut CallObservation| call.interface_uuid_matches = false,
            |call: &mut CallObservation| call.process_id = None,
            |call: &mut CallObservation| call.operation_number = 1,
            |call: &mut CallObservation| call.null_session = true,
            |call: &mut CallObservation| call.kernel_mode_caller = true,
            |call: &mut CallObservation| call.call_status = 1,
            |call: &mut CallObservation| call.call_status = 2,
            |call: &mut CallObservation| call.call_status = 3,
            |call: &mut CallObservation| call.call_kind = CallKind::Other,
            |call: &mut CallObservation| call.authentication_level = 5,
            |call: &mut CallObservation| call.authentication_service = 9,
        ];
        for mutate in mutations {
            let ops = FakeOps::approved();
            let mut call = approved_call();
            mutate(&mut call);
            ops.call.set(Ok(call));
            assert!(matches!(
                authenticate_with(&ops),
                Err(RpcAuthError::AccessDenied)
            ));
            assert_eq!(ops.events(), vec![Event::Call]);
        }
    }

    #[test]
    fn independent_authentication_query_is_required() {
        let observations = [
            AuthenticationObservation {
                authentication_level: 5,
                ..approved_authentication()
            },
            AuthenticationObservation {
                authentication_service: 9,
                ..approved_authentication()
            },
            AuthenticationObservation {
                authorization_service: 1,
                ..approved_authentication()
            },
        ];
        for observation in observations {
            let ops = FakeOps::approved();
            ops.authentication.set(Ok(observation));
            assert!(matches!(
                authenticate_with(&ops),
                Err(RpcAuthError::AccessDenied)
            ));
            assert_eq!(ops.events(), vec![Event::Call, Event::Authentication]);
        }
    }

    #[test]
    fn preexisting_thread_token_is_rejected_without_impersonating() {
        let ops = FakeOps::approved();
        ops.thread_present.set(true);
        assert!(matches!(
            authenticate_with(&ops),
            Err(RpcAuthError::AccessDenied)
        ));
        assert_eq!(
            ops.events(),
            vec![Event::Call, Event::Authentication, Event::ThreadState]
        );
    }

    #[test]
    fn failed_impersonation_does_not_attempt_revert() {
        let ops = FakeOps::approved();
        ops.impersonate_ok.set(false);
        assert!(matches!(
            authenticate_with(&ops),
            Err(RpcAuthError::CallFailed)
        ));
        assert!(!ops.events().contains(&Event::Revert));
    }

    #[test]
    fn every_post_impersonation_failure_reverts_exactly_once() {
        for failure in [
            Event::ImpersonationToken,
            Event::PrimaryToken,
            Event::DuplicateDesktopPrimary,
            Event::DesktopPrimaryToken,
        ] {
            let ops = FakeOps::approved();
            match failure {
                Event::ImpersonationToken => ops.impersonation_token_ok.set(false),
                Event::PrimaryToken => ops.primary_token_ok.set(false),
                Event::DuplicateDesktopPrimary => ops.duplicate_desktop_primary_ok.set(false),
                Event::DesktopPrimaryToken => ops.desktop_primary_token_ok.set(false),
                _ => {}
            }
            assert!(matches!(
                authenticate_with(&ops),
                Err(RpcAuthError::CallFailed)
            ));
            assert_eq!(
                ops.events()
                    .iter()
                    .filter(|event| **event == Event::Revert)
                    .count(),
                1
            );
            let expected_drops = u32::from(matches!(failure, Event::DesktopPrimaryToken));
            assert_eq!(ops.desktop_primary_drops.get(), expected_drops);
        }
    }

    #[test]
    fn process_open_or_pid_reconfirmation_failure_never_impersonates() {
        let open_failure = FakeOps::approved();
        open_failure.open_process_ok.set(false);
        assert!(matches!(
            authenticate_with(&open_failure),
            Err(RpcAuthError::CallFailed)
        ));
        assert!(!open_failure.events().contains(&Event::Impersonate));
        assert!(!open_failure.events().contains(&Event::Revert));

        let pid_change = FakeOps::approved();
        pid_change.confirmed_process_id.set(43);
        assert!(matches!(
            authenticate_with(&pid_change),
            Err(RpcAuthError::AccessDenied)
        ));
        assert_eq!(
            pid_change.events(),
            vec![
                Event::Call,
                Event::Authentication,
                Event::ThreadState,
                Event::OpenProcess,
                Event::Call,
            ]
        );
    }

    #[test]
    fn impersonation_and_primary_identity_mismatch_reverts_and_denies() {
        let ops = FakeOps::approved();
        ops.matching_tokens.set(false);
        assert!(matches!(
            authenticate_with(&ops),
            Err(RpcAuthError::AccessDenied)
        ));
        assert_eq!(
            ops.events()
                .iter()
                .filter(|event| **event == Event::Revert)
                .count(),
            1
        );
    }

    #[test]
    fn duplicated_primary_must_match_both_effective_client_tokens() {
        let ops = FakeOps::approved();
        ops.desktop_primary_matches.set(false);
        assert!(matches!(
            authenticate_with(&ops),
            Err(RpcAuthError::AccessDenied)
        ));
        assert_eq!(
            ops.events()
                .iter()
                .filter(|event| **event == Event::Revert)
                .count(),
            1
        );
        assert_eq!(ops.desktop_primary_drops.get(), 1);

        let wrong_kind = FakeOps::approved();
        wrong_kind
            .desktop_primary_kind
            .set(TokenKind::Impersonation);
        assert_eq!(
            authenticate_with(&wrong_kind).map(|_| ()),
            Err(RpcAuthError::AccessDenied)
        );
        assert_eq!(wrong_kind.desktop_primary_drops.get(), 1);

        let wrong_session = FakeOps::approved();
        wrong_session.desktop_primary_session_id.set(4);
        assert_eq!(
            authenticate_with(&wrong_session).map(|_| ()),
            Err(RpcAuthError::AccessDenied)
        );
        assert_eq!(wrong_session.desktop_primary_drops.get(), 1);
    }

    #[test]
    fn successful_proof_retains_one_move_only_primary_until_drop() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        assert_eq!(ops.desktop_primary_drops.get(), 0);
        drop(proof);
        assert_eq!(ops.desktop_primary_drops.get(), 1);
    }

    #[test]
    fn token_policy_rejects_each_forbidden_property() {
        let mut tokens = Vec::new();
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.user_sid = SidBytes(Vec::new());
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.logon_sid = None;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.logon_sid = Some(SidBytes(vec![1; 7]));
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.logon_sid_count = 2;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.session_id = 0;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.app_container = true;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.ui_access = true;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.integrity_rid = 0x3000;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.elevation = ElevationKind::Full;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.elevation = ElevationKind::Other;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.interactive_sid_enabled = false;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.debug_privilege = DebugPrivilegeState::PresentDisabled;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.debug_privilege = DebugPrivilegeState::PresentEnabled;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Impersonation, 1);
        token.token_level = TokenLevel::Other;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Other, 1);
        token.token_level = TokenLevel::Impersonation;
        tokens.push(token);
        tokens.push(approved_token(TokenKind::Primary, 1));

        for rejected in tokens {
            assert_eq!(
                super::validate_token_policy(
                    &rejected,
                    TokenKind::Impersonation,
                    super::TokenPolicy::DesktopBroker,
                ),
                Err(RpcAuthError::AccessDenied)
            );
        }

        let mut primary = approved_token(TokenKind::Primary, 1);
        assert!(
            super::validate_token_policy(
                &primary,
                TokenKind::Primary,
                super::TokenPolicy::DesktopBroker,
            )
            .is_ok()
        );
        primary.token_level = TokenLevel::Impersonation;
        assert_eq!(
            super::validate_token_policy(
                &primary,
                TokenKind::Primary,
                super::TokenPolicy::DesktopBroker,
            ),
            Err(RpcAuthError::AccessDenied)
        );

        let mut limited = approved_token(TokenKind::Impersonation, 1);
        limited.elevation = ElevationKind::Limited;
        assert!(
            super::validate_token_policy(
                &limited,
                TokenKind::Impersonation,
                super::TokenPolicy::DesktopBroker,
            )
            .is_ok()
        );

        let mut filtered = approved_token(TokenKind::Impersonation, 1);
        filtered.restricted = true;
        assert!(
            super::validate_token_policy(
                &filtered,
                TokenKind::Impersonation,
                super::TokenPolicy::DesktopBroker,
            )
            .is_ok()
        );
    }

    #[test]
    fn authentication_rejects_debug_privilege_presence_in_each_initial_token() {
        for state in [
            DebugPrivilegeState::PresentDisabled,
            DebugPrivilegeState::PresentEnabled,
        ] {
            for observed_token in 0..3 {
                let ops = FakeOps::approved();
                match observed_token {
                    0 => ops.impersonation_debug_privilege.set(state),
                    1 => ops.primary_debug_privilege.set(state),
                    2 => ops.desktop_primary_debug_privilege.set(state),
                    _ => unreachable!(),
                }

                assert_eq!(
                    authenticate_with(&ops).map(|_| ()),
                    Err(RpcAuthError::AccessDenied),
                    "state {state:?}, observed token {observed_token} must fail closed"
                );
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::Revert)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn exact_identity_facts_must_match_across_effective_tokens() {
        let mut impersonation = approved_token(TokenKind::Impersonation, 1);
        let mut primary = approved_token(TokenKind::Primary, 1);
        assert!(super::same_token_identity(&impersonation, &primary));

        impersonation.logon_sid_count = 2;
        assert!(!super::same_token_identity(&impersonation, &primary));
        primary.logon_sid_count = 2;
        assert!(super::same_token_identity(&impersonation, &primary));

        impersonation.integrity_rid = 0x3000;
        assert!(!super::same_token_identity(&impersonation, &primary));
        primary.integrity_rid = 0x3000;
        assert!(super::same_token_identity(&impersonation, &primary));

        impersonation.restricted = true;
        assert!(!super::same_token_identity(&impersonation, &primary));
        primary.restricted = true;
        assert!(super::same_token_identity(&impersonation, &primary));

        impersonation.elevation = ElevationKind::Limited;
        assert!(!super::same_token_identity(&impersonation, &primary));
        primary.elevation = ElevationKind::Limited;
        assert!(super::same_token_identity(&impersonation, &primary));

        impersonation.debug_privilege = DebugPrivilegeState::PresentDisabled;
        assert!(!super::same_token_identity(&impersonation, &primary));
        primary.debug_privilege = DebugPrivilegeState::PresentDisabled;
        assert!(super::same_token_identity(&impersonation, &primary));

        impersonation.debug_privilege = DebugPrivilegeState::PresentEnabled;
        assert!(!super::same_token_identity(&impersonation, &primary));
        primary.debug_privilege = DebugPrivilegeState::PresentEnabled;
        assert!(super::same_token_identity(&impersonation, &primary));
    }

    #[test]
    fn effective_desktop_thread_revalidation_accepts_exact_or_delegation_level() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        if let Ok(proof) = proof {
            ops.events.borrow_mut().clear();
            assert_eq!(proof.revalidate_effective_desktop_thread_with(&ops), Ok(()));
            assert_eq!(
                ops.events(),
                vec![
                    Event::ExactProcess,
                    Event::PrimaryToken,
                    Event::DesktopPrimaryToken,
                    Event::EffectiveThreadToken,
                ]
            );

            ops.events.borrow_mut().clear();
            ops.effective_token_mutation
                .set(EffectiveTokenMutation::Delegation);
            assert_eq!(proof.revalidate_effective_desktop_thread_with(&ops), Ok(()));
            assert_eq!(ops.events().last(), Some(&Event::EffectiveThreadToken));
        }
    }

    #[test]
    fn effective_desktop_thread_revalidation_rejects_every_changed_fact() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        if let Ok(proof) = proof {
            for mutation in REJECTED_EFFECTIVE_TOKEN_MUTATIONS {
                ops.events.borrow_mut().clear();
                ops.effective_token_mutation.set(mutation);
                assert_eq!(
                    proof.revalidate_effective_desktop_thread_with(&ops),
                    Err(RpcAuthError::AccessDenied),
                    "mutation {mutation:?} must fail closed"
                );
                assert_eq!(ops.events().last(), Some(&Event::EffectiveThreadToken));
            }
        }
    }

    #[test]
    fn missing_or_unobservable_effective_thread_token_fails_closed() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        if let Ok(proof) = proof {
            ops.events.borrow_mut().clear();
            ops.effective_thread_token_ok.set(false);
            assert_eq!(
                proof.revalidate_effective_desktop_thread_with(&ops),
                Err(RpcAuthError::CallFailed)
            );
            assert_eq!(ops.events().last(), Some(&Event::EffectiveThreadToken));
        }
    }

    #[test]
    fn stale_retained_proof_fails_before_effective_thread_observation() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        if let Ok(proof) = proof {
            ops.events.borrow_mut().clear();
            ops.primary_token_id.set(13);
            assert_eq!(
                proof.revalidate_effective_desktop_thread_with(&ops),
                Err(RpcAuthError::AccessDenied)
            );
            assert!(!ops.events().contains(&Event::EffectiveThreadToken));

            ops.events.borrow_mut().clear();
            ops.primary_token_id.set(12);
            ops.desktop_primary_token_id.set(22);
            assert_eq!(
                proof.revalidate_effective_desktop_thread_with(&ops),
                Err(RpcAuthError::AccessDenied)
            );
            assert!(!ops.events().contains(&Event::EffectiveThreadToken));
        }
    }

    #[test]
    fn revert_failure_or_thread_change_fail_fast_after_one_exact_revert() {
        for change_thread in [false, true] {
            let ops = FakeOps::approved();
            let cookie = NonZeroU32::new(7);
            assert!(cookie.is_some());
            if let Some(cookie) = cookie {
                let guard = ImpersonationGuard::new(&ops, cookie);
                if change_thread {
                    ops.thread_cookie.set(8);
                } else {
                    ops.revert_ok.set(false);
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    guard.finish();
                }));
                assert!(result.is_err());
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::Revert)
                        .count(),
                    1
                );
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::FailFast)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn residual_or_unobservable_thread_token_fail_fasts_on_success_and_error_paths() {
        for fail_during_authentication in [false, true] {
            for residual_query_fails in [false, true] {
                let ops = FakeOps::approved();
                ops.impersonation_token_ok.set(!fail_during_authentication);
                ops.residual_thread_present.set(!residual_query_fails);
                ops.residual_thread_query_ok.set(!residual_query_fails);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = authenticate_with(&ops);
                }));
                assert!(result.is_err());
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::Revert)
                        .count(),
                    1
                );
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::FailFast)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn unobservable_preclean_state_fails_before_open_or_impersonation() {
        let ops = FakeOps::approved();
        ops.thread_query_ok.set(false);
        assert!(matches!(
            authenticate_with(&ops),
            Err(RpcAuthError::CallFailed)
        ));
        assert!(!ops.events().contains(&Event::OpenProcess));
        assert!(!ops.events().contains(&Event::Impersonate));
    }

    #[test]
    fn retained_process_revalidation_and_exact_match_are_fail_closed() {
        let ops = FakeOps::approved();
        let first = authenticate_with(&ops);
        let second = authenticate_with(&ops);
        assert!(first.is_ok());
        assert!(second.is_ok());
        if let (Ok(first), Ok(second)) = (first, second) {
            assert!(first.revalidate_with(&ops).is_ok());
            assert!(second.revalidate_with(&ops).is_ok());
            assert!(ops.same_process(&first.process, &second.process).is_ok());

            ops.primary_token_id.set(13);
            assert_eq!(first.revalidate_with(&ops), Err(RpcAuthError::AccessDenied));
            ops.primary_token_id.set(12);
            ops.desktop_primary_token_id.set(22);
            assert_eq!(first.revalidate_with(&ops), Err(RpcAuthError::AccessDenied));
            ops.desktop_primary_token_id.set(21);
            ops.exact_process.set(false);
            assert_eq!(first.revalidate_with(&ops), Err(RpcAuthError::AccessDenied));
        }
    }

    #[test]
    fn desktop_session_requirement_revalidates_and_matches_exactly() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        if let Ok(proof) = proof {
            assert_eq!(
                proof.require_desktop_session_with(
                    NonZeroU32::new(3).unwrap_or(NonZeroU32::MIN),
                    &ops,
                ),
                Ok(())
            );
            assert_eq!(
                proof.require_desktop_session_with(
                    NonZeroU32::new(4).unwrap_or(NonZeroU32::MIN),
                    &ops,
                ),
                Err(RpcAuthError::AccessDenied)
            );
            ops.primary_token_ok.set(false);
            assert_eq!(
                proof.require_desktop_session_with(
                    NonZeroU32::new(3).unwrap_or(NonZeroU32::MIN),
                    &ops,
                ),
                Err(RpcAuthError::CallFailed)
            );
        }
    }

    #[test]
    fn desktop_child_identity_is_narrow_and_post_revalidated_on_every_mismatch() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        if let Ok(proof) = proof {
            let complete_order = [
                Event::ExactProcess,
                Event::PrimaryToken,
                Event::DesktopPrimaryToken,
                Event::DesktopChildToken,
                Event::ExactProcess,
                Event::PrimaryToken,
                Event::DesktopPrimaryToken,
            ];
            ops.events.borrow_mut().clear();
            assert_eq!(
                proof.require_desktop_child_identity_with(&ops, || {
                    ops.record(Event::DesktopChildToken);
                    Ok(desktop_child_token(DesktopChildTokenMutation::Exact))
                }),
                Ok(())
            );
            assert_eq!(ops.events(), complete_order);

            for mutation in [
                DesktopChildTokenMutation::UserSid,
                DesktopChildTokenMutation::LogonSidCount,
                DesktopChildTokenMutation::LogonSid,
                DesktopChildTokenMutation::SessionId,
                DesktopChildTokenMutation::AuthenticationId,
                DesktopChildTokenMutation::TokenKind,
                DesktopChildTokenMutation::TokenLevel,
            ] {
                ops.events.borrow_mut().clear();
                assert_eq!(
                    proof.require_desktop_child_identity_with(&ops, || {
                        ops.record(Event::DesktopChildToken);
                        Ok(desktop_child_token(mutation))
                    }),
                    Err(RpcAuthError::AccessDenied),
                    "mutation {mutation:?} must fail closed"
                );
                assert_eq!(
                    ops.events(),
                    complete_order,
                    "mutation {mutation:?} must still perform full post revalidation"
                );
            }
        }
    }

    #[test]
    fn desktop_child_identity_pre_observe_and_post_failures_have_exact_order() {
        let pre_ops = FakeOps::approved();
        let pre_proof = authenticate_with(&pre_ops);
        assert!(pre_proof.is_ok());
        if let Ok(pre_proof) = pre_proof {
            pre_ops.events.borrow_mut().clear();
            pre_ops.primary_token_ok.set(false);
            let observed = Cell::new(false);
            assert_eq!(
                pre_proof.require_desktop_child_identity_with(&pre_ops, || {
                    observed.set(true);
                    Ok(desktop_child_token(DesktopChildTokenMutation::Exact))
                }),
                Err(RpcAuthError::CallFailed)
            );
            assert!(!observed.get());
            assert_eq!(pre_ops.events(), [Event::ExactProcess, Event::PrimaryToken]);
        }

        let observe_ops = FakeOps::approved();
        let observe_proof = authenticate_with(&observe_ops);
        assert!(observe_proof.is_ok());
        if let Ok(observe_proof) = observe_proof {
            observe_ops.events.borrow_mut().clear();
            assert_eq!(
                observe_proof.require_desktop_child_identity_with(&observe_ops, || {
                    observe_ops.record(Event::DesktopChildToken);
                    Err(ObservationError::Incomplete)
                }),
                Err(RpcAuthError::CallFailed)
            );
            assert_eq!(
                observe_ops.events(),
                [
                    Event::ExactProcess,
                    Event::PrimaryToken,
                    Event::DesktopPrimaryToken,
                    Event::DesktopChildToken,
                    Event::ExactProcess,
                    Event::PrimaryToken,
                    Event::DesktopPrimaryToken,
                ]
            );
        }

        let post_ops = FakeOps::approved();
        let post_proof = authenticate_with(&post_ops);
        assert!(post_proof.is_ok());
        if let Ok(post_proof) = post_proof {
            post_ops.events.borrow_mut().clear();
            assert_eq!(
                post_proof.require_desktop_child_identity_with(&post_ops, || {
                    post_ops.record(Event::DesktopChildToken);
                    post_ops.primary_token_ok.set(false);
                    Ok(desktop_child_token(DesktopChildTokenMutation::Exact))
                }),
                Err(RpcAuthError::CallFailed)
            );
            assert_eq!(
                post_ops.events(),
                [
                    Event::ExactProcess,
                    Event::PrimaryToken,
                    Event::DesktopPrimaryToken,
                    Event::DesktopChildToken,
                    Event::ExactProcess,
                    Event::PrimaryToken,
                ]
            );
        }
    }

    #[test]
    fn desktop_process_creation_claim_is_one_shot_before_revalidation() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        if let Ok(proof) = proof {
            assert_eq!(proof.claim_desktop_process_creation_with(&ops), Ok(()));
            ops.events.borrow_mut().clear();
            assert_eq!(
                proof.claim_desktop_process_creation_with(&ops),
                Err(RpcAuthError::AccessDenied)
            );
            assert!(ops.events().is_empty());
        }

        let failing_ops = FakeOps::approved();
        let failing_proof = authenticate_with(&failing_ops);
        assert!(failing_proof.is_ok());
        if let Ok(failing_proof) = failing_proof {
            failing_ops.primary_token_ok.set(false);
            assert_eq!(
                failing_proof.claim_desktop_process_creation_with(&failing_ops),
                Err(RpcAuthError::CallFailed)
            );
            failing_ops.primary_token_ok.set(true);
            assert_eq!(
                failing_proof.claim_desktop_process_creation_with(&failing_ops),
                Err(RpcAuthError::AccessDenied)
            );
        }
    }

    #[test]
    fn process_dup_handle_denial_is_ordered_after_creation_and_consumed_once() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        if let Ok(proof) = proof {
            assert_eq!(proof.claim_desktop_process_creation_with(&ops), Ok(()));
            ops.events.borrow_mut().clear();

            assert_eq!(
                proof.require_desktop_process_dup_handle_denied_with(
                    NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                    &ops,
                ),
                Ok(())
            );
            assert_eq!(
                ops.events(),
                [
                    Event::ExactProcess,
                    Event::PrimaryToken,
                    Event::DesktopPrimaryToken,
                    Event::ThreadState,
                    Event::ThreadCookie,
                    Event::Impersonate,
                    Event::ThreadCookie,
                    Event::ExactProcess,
                    Event::PrimaryToken,
                    Event::DesktopPrimaryToken,
                    Event::EffectiveThreadToken,
                    Event::ProcessDupHandleDenial,
                    Event::ThreadCookie,
                    Event::ExactProcess,
                    Event::PrimaryToken,
                    Event::DesktopPrimaryToken,
                    Event::EffectiveThreadToken,
                    Event::ThreadCookie,
                    Event::Revert,
                    Event::ThreadState,
                    Event::ExactProcess,
                    Event::PrimaryToken,
                    Event::DesktopPrimaryToken,
                ]
            );

            ops.events.borrow_mut().clear();
            assert_eq!(
                proof.require_desktop_process_dup_handle_denied_with(
                    NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                    &ops,
                ),
                Err(RpcAuthError::AccessDenied)
            );
            assert!(ops.events().is_empty());
        }

        let premature_ops = FakeOps::approved();
        let premature = authenticate_with(&premature_ops);
        assert!(premature.is_ok());
        if let Ok(premature) = premature {
            premature_ops.events.borrow_mut().clear();
            assert_eq!(
                premature.require_desktop_process_dup_handle_denied_with(
                    NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                    &premature_ops,
                ),
                Err(RpcAuthError::AccessDenied)
            );
            assert!(premature_ops.events().is_empty());
            assert_eq!(
                premature.claim_desktop_process_creation_with(&premature_ops),
                Ok(())
            );
            premature_ops.events.borrow_mut().clear();
            assert_eq!(
                premature.require_desktop_process_dup_handle_denied_with(
                    NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                    &premature_ops,
                ),
                Err(RpcAuthError::AccessDenied)
            );
            assert!(premature_ops.events().is_empty());
        }
    }

    #[test]
    fn process_dup_handle_denial_classifies_access_and_os_failures_after_revert() {
        for (native, expected) in [
            (
                DesktopProcessAccessError::AccessAllowed,
                RpcAuthError::AccessDenied,
            ),
            (
                DesktopProcessAccessError::Incomplete,
                RpcAuthError::CallFailed,
            ),
        ] {
            let ops = FakeOps::approved();
            let proof = authenticate_with(&ops);
            assert!(proof.is_ok());
            if let Ok(proof) = proof {
                assert_eq!(proof.claim_desktop_process_creation_with(&ops), Ok(()));
                ops.process_dup_handle_result.set(Err(native));
                ops.events.borrow_mut().clear();
                assert_eq!(
                    proof.require_desktop_process_dup_handle_denied_with(
                        NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                        &ops,
                    ),
                    Err(expected)
                );
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::ProcessDupHandleDenial)
                        .count(),
                    1
                );
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::Revert)
                        .count(),
                    1
                );
                assert_eq!(ops.events().last(), Some(&Event::DesktopPrimaryToken));
            }
        }
    }

    #[test]
    fn process_dup_handle_denial_never_runs_under_unverified_effective_identity() {
        for mutation in REJECTED_EFFECTIVE_TOKEN_MUTATIONS {
            let ops = FakeOps::approved();
            let proof = authenticate_with(&ops);
            assert!(proof.is_ok());
            if let Ok(proof) = proof {
                assert_eq!(proof.claim_desktop_process_creation_with(&ops), Ok(()));
                ops.effective_token_mutation.set(mutation);
                ops.events.borrow_mut().clear();
                assert_eq!(
                    proof.require_desktop_process_dup_handle_denied_with(
                        NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                        &ops,
                    ),
                    Err(RpcAuthError::AccessDenied),
                    "mutation {mutation:?} must fail closed"
                );
                assert!(!ops.events().contains(&Event::ProcessDupHandleDenial));
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::Revert)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn process_dup_handle_denial_rejects_retained_debug_privilege_before_and_after_access() {
        for state in [
            DebugPrivilegeState::PresentDisabled,
            DebugPrivilegeState::PresentEnabled,
        ] {
            for retained_token in 0..2 {
                let pre_ops = FakeOps::approved();
                let pre_proof = authenticate_with(&pre_ops);
                assert!(pre_proof.is_ok());
                if let Ok(pre_proof) = pre_proof {
                    assert_eq!(
                        pre_proof.claim_desktop_process_creation_with(&pre_ops),
                        Ok(())
                    );
                    match retained_token {
                        0 => pre_ops.primary_debug_privilege.set(state),
                        1 => pre_ops.desktop_primary_debug_privilege.set(state),
                        _ => unreachable!(),
                    }
                    pre_ops.events.borrow_mut().clear();
                    assert_eq!(
                        pre_proof.require_desktop_process_dup_handle_denied_with(
                            NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                            &pre_ops,
                        ),
                        Err(RpcAuthError::AccessDenied)
                    );
                    assert!(!pre_ops.events().contains(&Event::Impersonate));
                    assert!(!pre_ops.events().contains(&Event::ProcessDupHandleDenial));
                }

                let post_ops = FakeOps::approved();
                let post_proof = authenticate_with(&post_ops);
                assert!(post_proof.is_ok());
                if let Ok(post_proof) = post_proof {
                    assert_eq!(
                        post_proof.claim_desktop_process_creation_with(&post_ops),
                        Ok(())
                    );
                    match retained_token {
                        0 => post_ops
                            .primary_debug_privilege_after_access
                            .set(Some(state)),
                        1 => post_ops
                            .desktop_primary_debug_privilege_after_access
                            .set(Some(state)),
                        _ => unreachable!(),
                    }
                    post_ops.events.borrow_mut().clear();
                    assert_eq!(
                        post_proof.require_desktop_process_dup_handle_denied_with(
                            NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                            &post_ops,
                        ),
                        Err(RpcAuthError::AccessDenied)
                    );
                    assert_eq!(
                        post_ops
                            .events()
                            .iter()
                            .filter(|event| **event == Event::ProcessDupHandleDenial)
                            .count(),
                        1
                    );
                    assert_eq!(
                        post_ops
                            .events()
                            .iter()
                            .filter(|event| **event == Event::Revert)
                            .count(),
                        1
                    );
                }
            }
        }
    }

    #[test]
    fn process_dup_handle_denial_postcheck_rejects_every_changed_effective_fact() {
        for mutation in REJECTED_EFFECTIVE_TOKEN_MUTATIONS {
            let ops = FakeOps::approved();
            let proof = authenticate_with(&ops);
            assert!(proof.is_ok());
            if let Ok(proof) = proof {
                assert_eq!(proof.claim_desktop_process_creation_with(&ops), Ok(()));
                ops.effective_token_mutation_after_access
                    .set(Some(mutation));
                ops.events.borrow_mut().clear();
                assert_eq!(
                    proof.require_desktop_process_dup_handle_denied_with(
                        NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                        &ops,
                    ),
                    Err(RpcAuthError::AccessDenied),
                    "post-access mutation {mutation:?} must fail closed"
                );
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::ProcessDupHandleDenial)
                        .count(),
                    1
                );
                assert_eq!(
                    ops.events()
                        .iter()
                        .filter(|event| **event == Event::Revert)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn process_dup_handle_denial_impersonation_and_revert_fail_closed() {
        let impersonate_ops = FakeOps::approved();
        let impersonate_proof = authenticate_with(&impersonate_ops);
        assert!(impersonate_proof.is_ok());
        if let Ok(impersonate_proof) = impersonate_proof {
            assert_eq!(
                impersonate_proof.claim_desktop_process_creation_with(&impersonate_ops),
                Ok(())
            );
            impersonate_ops.impersonate_ok.set(false);
            impersonate_ops.events.borrow_mut().clear();
            assert_eq!(
                impersonate_proof.require_desktop_process_dup_handle_denied_with(
                    NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                    &impersonate_ops,
                ),
                Err(RpcAuthError::CallFailed)
            );
            assert_eq!(impersonate_ops.events().last(), Some(&Event::Impersonate));
            assert!(
                !impersonate_ops
                    .events()
                    .contains(&Event::ProcessDupHandleDenial)
            );
            assert!(!impersonate_ops.events().contains(&Event::Revert));
        }

        let revert_ops = FakeOps::approved();
        let revert_proof = authenticate_with(&revert_ops);
        assert!(revert_proof.is_ok());
        if let Ok(revert_proof) = revert_proof {
            assert_eq!(
                revert_proof.claim_desktop_process_creation_with(&revert_ops),
                Ok(())
            );
            revert_ops.revert_ok.set(false);
            revert_ops.events.borrow_mut().clear();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = revert_proof.require_desktop_process_dup_handle_denied_with(
                    NonZeroU32::new(77).unwrap_or(NonZeroU32::MIN),
                    &revert_ops,
                );
            }));
            assert!(result.is_err());
            assert_eq!(
                revert_ops
                    .events()
                    .iter()
                    .filter(|event| **event == Event::Revert)
                    .count(),
                1
            );
            assert_eq!(
                revert_ops
                    .events()
                    .iter()
                    .filter(|event| **event == Event::FailFast)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn debug_is_data_free() {
        let error = RpcAuthError::AccessDenied;
        assert_eq!(format!("{error:?}"), "AccessDenied");
        let proof = AuthenticatedClient {
            process_id: NonZeroU32::new(9).unwrap_or(NonZeroU32::MIN),
            process: FakeProcess(9),
            primary: approved_token(TokenKind::Primary, 9),
            desktop_primary_token: FakeDesktopPrimaryToken {
                drops: Rc::new(Cell::new(0)),
            },
            desktop_primary: approved_token(TokenKind::Primary, 9),
            desktop_process_creation_claimed: Cell::new(false),
            desktop_process_dup_handle_denial_claimed: Cell::new(false),
        };
        let debug = format!("{proof:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains('9'));

        let observation = approved_token(TokenKind::Impersonation, 7);
        assert_eq!(format!("{observation:?}"), "TokenObservation([REDACTED])");

        let callback = super::AuthenticatedRpcCallback { _private: () };
        assert_eq!(
            format!("{callback:?}"),
            "AuthenticatedRpcCallback([REDACTED])"
        );
    }

    #[test]
    fn desktop_impersonation_lease_rechecks_and_reverts_exactly_once() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        ops.events.borrow_mut().clear();

        if let Ok(proof) = proof {
            let lease = proof.impersonate_desktop_user_with(&ops);
            assert!(lease.is_ok());
            if let Ok(lease) = lease {
                assert_eq!(lease.recheck(), Ok(()));
                assert_eq!(lease.finish(), Ok(()));
            }
        }
        assert_eq!(
            ops.events()
                .iter()
                .filter(|event| **event == Event::Impersonate)
                .count(),
            1
        );
        assert_eq!(
            ops.events()
                .iter()
                .filter(|event| **event == Event::Revert)
                .count(),
            1
        );
    }

    #[test]
    fn desktop_impersonation_lease_drop_is_exact_once_fallback() {
        let ops = FakeOps::approved();
        let proof = authenticate_with(&ops);
        assert!(proof.is_ok());
        ops.events.borrow_mut().clear();

        if let Ok(proof) = proof {
            let lease = proof.impersonate_desktop_user_with(&ops);
            assert!(lease.is_ok());
            ops.events.borrow_mut().clear();
            drop(lease);
        }
        assert_eq!(
            ops.events()
                .iter()
                .filter(|event| **event == Event::Revert)
                .count(),
            1
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DesktopProbeEvent {
        InitialThread,
        CurrentProcess,
        OpenProcess,
        InitialPrimary,
        ExactProcess,
        RevalidatedPrimary,
        FinalThread,
    }

    const DESKTOP_PROBE_ORDER: [DesktopProbeEvent; 7] = [
        DesktopProbeEvent::InitialThread,
        DesktopProbeEvent::CurrentProcess,
        DesktopProbeEvent::OpenProcess,
        DesktopProbeEvent::InitialPrimary,
        DesktopProbeEvent::ExactProcess,
        DesktopProbeEvent::RevalidatedPrimary,
        DesktopProbeEvent::FinalThread,
    ];

    struct DesktopProbeProcess {
        process_id: NonZeroU32,
        drops: Rc<Cell<u32>>,
    }

    impl Drop for DesktopProbeProcess {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    type DesktopProbeTokenMutation = fn(&mut TokenObservation);

    struct DesktopProbeOps {
        events: RefCell<Vec<DesktopProbeEvent>>,
        fail_at: Option<DesktopProbeEvent>,
        thread_present_at: Option<DesktopProbeEvent>,
        process_live: bool,
        primary_reads: Cell<usize>,
        token_mutations: [Option<DesktopProbeTokenMutation>; 2],
        process_drops: Rc<Cell<u32>>,
    }

    impl DesktopProbeOps {
        fn approved() -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                fail_at: None,
                thread_present_at: None,
                process_live: true,
                primary_reads: Cell::new(0),
                token_mutations: [None, None],
                process_drops: Rc::new(Cell::new(0)),
            }
        }

        fn observe(&self, event: DesktopProbeEvent) -> Result<(), ObservationError> {
            self.events.borrow_mut().push(event);
            if self.fail_at == Some(event) {
                Err(ObservationError::Incomplete)
            } else {
                Ok(())
            }
        }
    }

    impl ProcessAuthOps for DesktopProbeOps {
        type Process = DesktopProbeProcess;
        type DesktopPrimaryToken = ();

        fn open_process(&self, process_id: NonZeroU32) -> Result<Self::Process, ObservationError> {
            self.observe(DesktopProbeEvent::OpenProcess)?;
            assert_eq!(process_id.get(), 42);
            Ok(DesktopProbeProcess {
                process_id,
                drops: Rc::clone(&self.process_drops),
            })
        }

        fn primary_token(
            &self,
            process: &Self::Process,
        ) -> Result<TokenObservation, ObservationError> {
            let index = self.primary_reads.get();
            self.primary_reads.set(index + 1);
            self.observe(if index == 0 {
                DesktopProbeEvent::InitialPrimary
            } else {
                DesktopProbeEvent::RevalidatedPrimary
            })?;
            assert_eq!(process.process_id.get(), 42);
            let mut token = approved_token(TokenKind::Primary, 1);
            if let Some(mutate) = self.token_mutations[index] {
                mutate(&mut token);
            }
            Ok(token)
        }

        fn desktop_primary_token(
            &self,
            _token: &Self::DesktopPrimaryToken,
        ) -> Result<TokenObservation, ObservationError> {
            unreachable!()
        }

        fn exact_process_is_live(
            &self,
            process: &Self::Process,
            process_id: NonZeroU32,
        ) -> Result<bool, ObservationError> {
            self.observe(DesktopProbeEvent::ExactProcess)?;
            assert_eq!(process.process_id, process_id);
            assert_eq!(process_id.get(), 42);
            Ok(self.process_live)
        }

        fn same_process(
            &self,
            _first: &Self::Process,
            _second: &Self::Process,
        ) -> Result<bool, ObservationError> {
            unreachable!()
        }
    }

    impl super::CurrentDesktopProbeOps for DesktopProbeOps {
        fn current_process_id(&self) -> Result<NonZeroU32, ObservationError> {
            self.observe(DesktopProbeEvent::CurrentProcess)?;
            NonZeroU32::new(42).ok_or(ObservationError::Incomplete)
        }

        fn current_thread_token_state(&self) -> Result<ThreadTokenState, ObservationError> {
            let event = if self.events.borrow().is_empty() {
                DesktopProbeEvent::InitialThread
            } else {
                DesktopProbeEvent::FinalThread
            };
            self.observe(event)?;
            Ok(if self.thread_present_at == Some(event) {
                ThreadTokenState::Present
            } else {
                ThreadTokenState::Clear
            })
        }
    }

    #[test]
    fn desktop_probe_preflight_is_query_only_ordered_and_releases_its_process() {
        for elevation in [ElevationKind::Default, ElevationKind::Limited] {
            let mut ops = DesktopProbeOps::approved();
            if elevation == ElevationKind::Limited {
                ops.token_mutations = [Some(|token| token.elevation = ElevationKind::Limited); 2];
            }
            let result: Result<(), RpcAuthError> =
                super::preflight_current_desktop_probe_with(&ops);
            assert_eq!(result, Ok(()));
            assert_eq!(*ops.events.borrow(), DESKTOP_PROBE_ORDER);
            assert_eq!(ops.primary_reads.get(), 2);
            assert_eq!(ops.process_drops.get(), 1);
        }
    }

    #[test]
    fn desktop_probe_preflight_fails_closed_at_every_observation_edge() {
        for (index, event) in DESKTOP_PROBE_ORDER.into_iter().enumerate() {
            let mut ops = DesktopProbeOps::approved();
            ops.fail_at = Some(event);
            assert_eq!(
                super::preflight_current_desktop_probe_with(&ops),
                Err(RpcAuthError::CallFailed)
            );
            assert_eq!(*ops.events.borrow(), DESKTOP_PROBE_ORDER[..=index]);
            assert_eq!(ops.process_drops.get(), u32::from(index >= 3));
        }
    }

    #[test]
    fn desktop_probe_preflight_rejects_initial_and_late_thread_tokens() {
        for event in [
            DesktopProbeEvent::InitialThread,
            DesktopProbeEvent::FinalThread,
        ] {
            let mut ops = DesktopProbeOps::approved();
            ops.thread_present_at = Some(event);
            assert_eq!(
                super::preflight_current_desktop_probe_with(&ops),
                Err(RpcAuthError::AccessDenied)
            );
            let observed = if event == DesktopProbeEvent::InitialThread {
                1
            } else {
                7
            };
            assert_eq!(*ops.events.borrow(), DESKTOP_PROBE_ORDER[..observed]);
            assert_eq!(ops.process_drops.get(), u32::from(observed == 7));
        }
    }

    #[test]
    fn desktop_probe_preflight_rejects_a_nonlive_or_nonexact_process() {
        let mut ops = DesktopProbeOps::approved();
        ops.process_live = false;
        assert_eq!(
            super::preflight_current_desktop_probe_with(&ops),
            Err(RpcAuthError::AccessDenied)
        );
        assert_eq!(*ops.events.borrow(), DESKTOP_PROBE_ORDER[..5]);
        assert_eq!(ops.process_drops.get(), 1);
    }

    #[test]
    fn desktop_probe_preflight_rejects_every_desktop_policy_fact_on_both_reads() {
        let mutations: [DesktopProbeTokenMutation; 20] = [
            |token| token.user_sid = SidBytes(vec![1; 7]),
            |token| token.user_sid = SidBytes(vec![1; 69]),
            |token| token.logon_sid_count = 0,
            |token| token.logon_sid_count = 2,
            |token| token.logon_sid = None,
            |token| token.logon_sid = Some(SidBytes(vec![2; 7])),
            |token| token.logon_sid = Some(SidBytes(vec![2; 69])),
            |token| token.session_id = 0,
            |token| token.app_container = true,
            |token| token.ui_access = true,
            |token| token.integrity_rid = 0x1000,
            |token| token.integrity_rid = 0x3000,
            |token| token.elevation = ElevationKind::Full,
            |token| token.elevation = ElevationKind::Other,
            |token| token.interactive_sid_enabled = false,
            |token| token.debug_privilege = DebugPrivilegeState::PresentDisabled,
            |token| token.debug_privilege = DebugPrivilegeState::PresentEnabled,
            |token| token.token_kind = TokenKind::Impersonation,
            |token| token.token_kind = TokenKind::Other,
            |token| token.token_level = TokenLevel::Other,
        ];
        for read in 0..2 {
            for mutate in mutations {
                let mut ops = DesktopProbeOps::approved();
                ops.token_mutations[read] = Some(mutate);
                assert_eq!(
                    super::preflight_current_desktop_probe_with(&ops),
                    Err(RpcAuthError::AccessDenied)
                );
                assert_eq!(ops.primary_reads.get(), read + 1);
                let observed = if read == 0 { 4 } else { 6 };
                assert_eq!(*ops.events.borrow(), DESKTOP_PROBE_ORDER[..observed]);
                assert_eq!(ops.process_drops.get(), 1);
            }
        }
    }

    #[test]
    fn desktop_probe_preflight_rejects_policy_valid_primary_identity_drift() {
        let mutations: [DesktopProbeTokenMutation; 9] = [
            |token| token.user_sid = SidBytes(vec![3; 12]),
            |token| token.logon_sid = Some(SidBytes(vec![4; 12])),
            |token| token.session_id = 4,
            |token| token.authentication_id.low_part += 1,
            |token| token.authentication_id.high_part += 1,
            |token| token.token_id.low_part += 1,
            |token| token.token_id.high_part += 1,
            |token| token.elevation = ElevationKind::Limited,
            |token| token.restricted = true,
        ];
        for mutate in mutations {
            let mut ops = DesktopProbeOps::approved();
            ops.token_mutations[1] = Some(mutate);
            assert_eq!(
                super::preflight_current_desktop_probe_with(&ops),
                Err(RpcAuthError::AccessDenied)
            );
            assert_eq!(*ops.events.borrow(), DESKTOP_PROBE_ORDER[..6]);
            assert_eq!(ops.process_drops.get(), 1);
        }
    }

    #[test]
    fn null_callback_context_fails_before_any_rpc_query() {
        // SAFETY: null is intentionally supplied to exercise the constructor's
        // fail-closed rejection; it is never passed to a Windows API.
        let result = unsafe { super::authenticate_callback_context(core::ptr::null()) };
        assert!(matches!(result, Err(RpcAuthError::CallFailed)));
    }
}
