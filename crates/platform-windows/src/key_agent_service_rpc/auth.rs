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
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::rc::Rc;

use key_agent_service_rpc_sys::CallBinding;
#[cfg(test)]
use key_agent_service_rpc_sys::ManagerError;
use zeroize::Zeroize as _;

const RPC_AUTHN_LEVEL_PACKET_PRIVACY: u32 = 6;
const RPC_AUTHN_SERVICE_WINNT: u32 = 10;
const RPC_AUTHZ_SERVICE_NONE: u32 = 0;
// The Windows SDK defines `CallStatus` as cancellation/disconnection bits:
// zero is an active call, bit 0 is cancelled, and bit 1 is disconnected.
const RPC_CALL_STATUS_ACTIVE: u32 = 0;
const MEDIUM_INTEGRITY_RID: u32 = 0x2000;
const MAX_BINARY_SID_BYTES: usize = 68;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationError {
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
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ElevationKind {
    Default,
    Limited,
    Full,
    Other,
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
}

impl fmt::Debug for TokenObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenObservation([REDACTED])")
    }
}

trait ProcessAuthOps {
    type Process;

    fn open_process(&self, process_id: NonZeroU32) -> Result<Self::Process, ObservationError>;

    fn primary_token(&self, process: &Self::Process) -> Result<TokenObservation, ObservationError>;

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

trait RpcAuthOps: ProcessAuthOps {
    fn call_observation(&self) -> Result<CallObservation, ObservationError>;

    fn authentication_observation(&self) -> Result<AuthenticationObservation, ObservationError>;

    fn thread_token_state(&self) -> Result<ThreadTokenState, ObservationError>;

    fn current_thread_cookie(&self) -> Result<NonZeroU32, ObservationError>;

    fn impersonate(&self) -> Result<(), ObservationError>;

    fn impersonation_token(&self) -> Result<TokenObservation, ObservationError>;

    fn revert(&self) -> Result<(), ObservationError>;

    fn fail_fast(&self) -> !;
}

/// A retained process and primary-token correlation for one authenticated call.
///
/// Debug output intentionally exposes neither PID, session, token identifiers,
/// nor SID material. V2 call attributes expose only a PID, so this value does
/// not claim an atomic kernel binding to the process that originated the RPC.
pub(crate) struct AuthenticatedClient<P> {
    process_id: NonZeroU32,
    process: P,
    primary: TokenObservation,
}

impl<P> fmt::Debug for AuthenticatedClient<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedRpcClient([REDACTED])")
    }
}

pub(crate) type AuthenticatedRpcClient = AuthenticatedClient<sys::RetainedProcess>;

impl AuthenticatedRpcClient {
    /// Reopens the PID, compares the exact process objects, checks liveness and
    /// restricted handle flags, then repeats the complete primary-token policy.
    pub(crate) fn revalidate(&self) -> Result<(), RpcAuthError> {
        self.revalidate_with(&sys::WindowsProcessAuthOps)
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

impl<P> AuthenticatedClient<P> {
    fn revalidate_with<O>(&self, ops: &O) -> Result<(), RpcAuthError>
    where
        O: ProcessAuthOps<Process = P>,
    {
        if !ops
            .exact_process_is_live(&self.process, self.process_id)
            .map_err(|_| RpcAuthError::CallFailed)?
        {
            return Err(RpcAuthError::AccessDenied);
        }
        let current = ops
            .primary_token(&self.process)
            .map_err(|_| RpcAuthError::CallFailed)?;
        validate_token(&current, TokenKind::Primary)?;
        if !same_primary_token(&self.primary, &current) {
            return Err(RpcAuthError::AccessDenied);
        }
        Ok(())
    }
}

/// Authenticates exactly one synchronous manager invocation.
///
/// The `CallBinding` is consumed and remains confined to the Windows adapter;
/// it cannot be retained by the returned process proof.
pub(crate) fn authenticate_call(
    binding: CallBinding<'_>,
) -> Result<AuthenticatedRpcClient, RpcAuthError> {
    let ops = sys::WindowsRpcAuthOps::new(binding);
    authenticate_with(&ops)
}

/// Independently authenticates the binding context supplied to an If3
/// security callback.
///
/// # Safety
///
/// `raw` must be the non-null binding context passed by the RPC runtime to the
/// currently executing security callback. It must remain valid on this thread
/// until this function returns and must not be retained or freed by the caller.
pub(crate) unsafe fn authenticate_callback_context(
    raw: *const c_void,
) -> Result<AuthenticatedRpcClient, RpcAuthError> {
    // SAFETY: the caller supplies the active callback's synchronous context;
    // the adapter retains it only inside this function.
    let ops = unsafe { sys::WindowsRpcAuthOps::from_callback(raw) }
        .map_err(|_| RpcAuthError::CallFailed)?;
    authenticate_with(&ops)
}

fn authenticate_with<O>(ops: &O) -> Result<AuthenticatedClient<O::Process>, RpcAuthError>
where
    O: RpcAuthOps,
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
    validate_token(&impersonation, TokenKind::Impersonation)?;

    let primary = ops
        .primary_token(&process)
        .map_err(|_| RpcAuthError::CallFailed)?;
    validate_token(&primary, TokenKind::Primary)?;
    if !same_token_identity(&impersonation, &primary) {
        return Err(RpcAuthError::AccessDenied);
    }

    guard.finish();

    let authenticated = AuthenticatedClient {
        process_id,
        process,
        primary,
    };
    authenticated.revalidate_with(ops)?;
    Ok(authenticated)
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

fn validate_token(token: &TokenObservation, expected: TokenKind) -> Result<(), RpcAuthError> {
    let expected_level = match expected {
        TokenKind::Primary => TokenLevel::NotApplicable,
        TokenKind::Impersonation => TokenLevel::Impersonation,
        TokenKind::Other => return Err(RpcAuthError::AccessDenied),
    };
    if token.token_kind != expected
        || token.token_level != expected_level
        || !token.user_sid.has_valid_length()
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
    {
        return Err(RpcAuthError::AccessDenied);
    }
    Ok(())
}

fn same_token_identity(first: &TokenObservation, second: &TokenObservation) -> bool {
    first.user_sid == second.user_sid
        && first.logon_sid == second.logon_sid
        && first.session_id == second.session_id
        && first.authentication_id == second.authentication_id
        && first.elevation == second.elevation
        && first.restricted == second.restricted
}

fn same_primary_token(first: &TokenObservation, second: &TokenObservation) -> bool {
    same_token_identity(first, second) && first.token_id == second.token_id
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
        CallObservation, CallProtocol, ElevationKind, ImpersonationGuard, NonZeroU32,
        ObservationError, ProcessAuthOps, RPC_AUTHN_LEVEL_PACKET_PRIVACY, RPC_AUTHN_SERVICE_WINNT,
        RPC_AUTHZ_SERVICE_NONE, RPC_CALL_STATUS_ACTIVE, RpcAuthError, RpcAuthOps, SidBytes,
        ThreadTokenState, TokenId, TokenKind, TokenLevel, TokenObservation, authenticate_with,
    };
    use core::cell::{Cell, RefCell};

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
        Revert,
        ExactProcess,
        SameProcess,
        FailFast,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeProcess(u32);

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
        matching_tokens: Cell<bool>,
        primary_token_id: Cell<u32>,
        open_process_ok: Cell<bool>,
        primary_token_ok: Cell<bool>,
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
                matching_tokens: Cell::new(true),
                primary_token_id: Cell::new(12),
                open_process_ok: Cell::new(true),
                primary_token_ok: Cell::new(true),
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

    impl ProcessAuthOps for FakeOps {
        type Process = FakeProcess;

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
            let mut token = approved_token(TokenKind::Primary, marker);
            token.token_id.low_part = self.primary_token_id.get();
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
                .then(|| approved_token(TokenKind::Impersonation, 1))
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
        }
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
                Event::ThreadCookie,
                Event::Revert,
                Event::ThreadState,
                Event::ExactProcess,
                Event::PrimaryToken,
            ]
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
        for failure in [Event::ImpersonationToken, Event::PrimaryToken] {
            let ops = FakeOps::approved();
            match failure {
                Event::ImpersonationToken => ops.impersonation_token_ok.set(false),
                Event::PrimaryToken => ops.primary_token_ok.set(false),
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
        token.token_level = TokenLevel::Other;
        tokens.push(token);
        let mut token = approved_token(TokenKind::Other, 1);
        token.token_level = TokenLevel::Impersonation;
        tokens.push(token);
        tokens.push(approved_token(TokenKind::Primary, 1));

        for rejected in tokens {
            assert_eq!(
                super::validate_token(&rejected, TokenKind::Impersonation),
                Err(RpcAuthError::AccessDenied)
            );
        }

        let mut primary = approved_token(TokenKind::Primary, 1);
        assert!(super::validate_token(&primary, TokenKind::Primary).is_ok());
        primary.token_level = TokenLevel::Impersonation;
        assert_eq!(
            super::validate_token(&primary, TokenKind::Primary),
            Err(RpcAuthError::AccessDenied)
        );

        let mut limited = approved_token(TokenKind::Impersonation, 1);
        limited.elevation = ElevationKind::Limited;
        assert!(super::validate_token(&limited, TokenKind::Impersonation).is_ok());

        let mut filtered = approved_token(TokenKind::Impersonation, 1);
        filtered.restricted = true;
        assert!(super::validate_token(&filtered, TokenKind::Impersonation).is_ok());
    }

    #[test]
    fn elevation_and_filtering_must_match_across_effective_tokens() {
        let mut impersonation = approved_token(TokenKind::Impersonation, 1);
        let mut primary = approved_token(TokenKind::Primary, 1);
        assert!(super::same_token_identity(&impersonation, &primary));

        impersonation.restricted = true;
        assert!(!super::same_token_identity(&impersonation, &primary));
        primary.restricted = true;
        assert!(super::same_token_identity(&impersonation, &primary));

        impersonation.elevation = ElevationKind::Limited;
        assert!(!super::same_token_identity(&impersonation, &primary));
        primary.elevation = ElevationKind::Limited;
        assert!(super::same_token_identity(&impersonation, &primary));
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
            ops.exact_process.set(false);
            assert_eq!(first.revalidate_with(&ops), Err(RpcAuthError::AccessDenied));
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
        };
        let debug = format!("{proof:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains('9'));
    }

    #[test]
    fn null_callback_context_fails_before_any_rpc_query() {
        // SAFETY: null is intentionally supplied to exercise the constructor's
        // fail-closed rejection; it is never passed to a Windows API.
        let result = unsafe { super::authenticate_callback_context(core::ptr::null()) };
        assert!(matches!(result, Err(RpcAuthError::CallFailed)));
    }
}
