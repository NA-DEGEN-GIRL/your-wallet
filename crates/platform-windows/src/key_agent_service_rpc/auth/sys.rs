//! Narrow Windows adapter for per-call RPC and token observations.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use core::mem::{offset_of, size_of};
use core::ptr;
use std::cell::Cell;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::ptr::NonNull;

use key_agent_service_rpc_sys::{CallBinding, INTERFACE_UUID};
use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, ERROR_NO_TOKEN, GetHandleInformation, HANDLE,
    INVALID_HANDLE_VALUE, LUID, WAIT_TIMEOUT,
};
use windows::Win32::Security::{
    DuplicateTokenEx, GetLengthSid, GetTokenInformation, ImpersonateLoggedOnUser, IsValidSid, PSID,
    RevertToSelf, SECURITY_IMPERSONATION_LEVEL, SID_AND_ATTRIBUTES, SecurityDelegation,
    SecurityImpersonation, TOKEN_ACCESS_MASK, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_ELEVATION_TYPE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_USER, TokenElevationType,
    TokenElevationTypeDefault, TokenElevationTypeFull, TokenElevationTypeLimited, TokenGroups,
    TokenHasRestrictions, TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel,
    TokenIsAppContainer, TokenPrimary, TokenSessionId, TokenStatistics, TokenUIAccess, TokenUser,
};
use windows::Win32::System::Diagnostics::Debug::RaiseFailFastException;
use windows::Win32::System::Rpc::{
    RPC_CALL_ATTRIBUTES_V2_W, RPC_CALL_ATTRIBUTES_VERSION, RPC_PROTSEQ_LRPC, RPC_QUERY_CLIENT_PID,
    RPC_QUERY_IS_CLIENT_LOCAL, RpcBindingInqAuthClientExW, RpcImpersonateClient, RpcRevertToSelfEx,
    RpcServerInqCallAttributesW, rcclLocal, rctNormal,
};
use windows::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_LOGON_ID,
};
use windows::Win32::System::Threading::{
    GetCurrentThread, GetCurrentThreadId, GetProcessId, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows::core::GUID;
use zeroize::Zeroize as _;

use super::{
    AuthenticationId, AuthenticationObservation, CallKind, CallObservation, CallProtocol,
    DesktopImpersonationOps, EffectiveThreadAuthOps, ElevationKind, ObservationError,
    ProcessAuthOps, RpcAuthOps, SidBytes, ThreadTokenState, TokenId, TokenKind, TokenLevel,
    TokenObservation,
};

const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_BINARY_SID_BYTES: usize = 68;
const INTERACTIVE_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 4, 0, 0, 0];
const MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];
const EXPECTED_INTERFACE_UUID: GUID = GUID::from_u128(u128::from_be_bytes(INTERFACE_UUID));
const DESKTOP_PRIMARY_TOKEN_ACCESS: TOKEN_ACCESS_MASK =
    TOKEN_ACCESS_MASK(TOKEN_ASSIGN_PRIMARY.0 | TOKEN_DUPLICATE.0 | TOKEN_QUERY.0);

pub(crate) struct RetainedProcess(HANDLE);

// SAFETY: this owns only a process kernel handle. All uses are synchronous
// handle/token queries; no thread-affine impersonation or RPC binding state is
// retained. Ownership still closes exactly once after a move.
unsafe impl Send for RetainedProcess {}

impl RetainedProcess {
    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl fmt::Debug for RetainedProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedProcess([REDACTED])")
    }
}

impl Drop for RetainedProcess {
    fn drop(&mut self) {
        if !invalid_handle(self.0) {
            // SAFETY: every RetainedProcess owns one successful OpenProcess
            // result and closes it exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Exact primary-token handle derived while the RPC client is impersonated.
///
/// The owner is move-only, non-inheritable, and deliberately not `Sync`. Its
/// only external operations are exact observations and narrowly scoped native
/// uses implemented inside this adapter; raw ownership never leaves the module.
pub(crate) struct DesktopPrimaryToken {
    token: OwnedToken,
    _not_sync: PhantomData<Cell<()>>,
}

// SAFETY: this value owns one non-inheritable token kernel handle and contains
// no thread-affine impersonation state. Moving ownership to the later dedicated
// process-creation/debugger thread does not duplicate or alias that handle.
unsafe impl Send for DesktopPrimaryToken {}

impl DesktopPrimaryToken {
    const fn raw(&self) -> HANDLE {
        self.token.raw()
    }
}

impl fmt::Debug for DesktopPrimaryToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DesktopPrimaryToken([REDACTED])")
    }
}

struct OwnedToken(HANDLE);

impl OwnedToken {
    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !invalid_handle(self.0) {
            // SAFETY: every OwnedToken owns one successful token-open result.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct TokenInformationBuffer {
    words: Vec<usize>,
    returned_bytes: usize,
}

impl TokenInformationBuffer {
    fn as_ptr<T>(&self) -> *const T {
        self.words.as_ptr().cast::<T>()
    }

    fn initialized_bytes(&self) -> &[u8] {
        // SAFETY: `returned_bytes` was bounded by the initialized allocation
        // before construction and the backing words remain live for `self`.
        unsafe {
            core::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.returned_bytes)
        }
    }
}

impl Drop for TokenInformationBuffer {
    fn drop(&mut self) {
        self.words.zeroize();
        self.returned_bytes.zeroize();
    }
}

pub(super) struct WindowsRpcAuthOps<'call> {
    binding: ScopedCallBinding<'call>,
}

enum ScopedCallBinding<'call> {
    Manager(CallBinding<'call>),
    Callback {
        raw: NonNull<c_void>,
        _call_lifetime: PhantomData<&'call mut c_void>,
    },
}

impl<'call> WindowsRpcAuthOps<'call> {
    pub(super) const fn new(binding: CallBinding<'call>) -> Self {
        Self {
            binding: ScopedCallBinding::Manager(binding),
        }
    }

    /// Wraps the synchronous binding context supplied by an If3 callback.
    ///
    /// # Safety
    ///
    /// `raw` must remain a valid callback binding on this thread for the
    /// returned adapter's entire lifetime and must not be freed by Rust.
    pub(super) unsafe fn from_callback(raw: *const c_void) -> Result<Self, ObservationError> {
        let raw = NonNull::new(raw.cast_mut()).ok_or(ObservationError::Incomplete)?;
        Ok(Self {
            binding: ScopedCallBinding::Callback {
                raw,
                _call_lifetime: PhantomData,
            },
        })
    }

    fn raw_binding(&self) -> *const c_void {
        match &self.binding {
            ScopedCallBinding::Manager(binding) => {
                // SAFETY: the raw value is used synchronously by one RPC
                // observation or impersonation API and never escapes the
                // manager-call lifetime.
                unsafe { binding.as_raw() }.cast_const()
            }
            ScopedCallBinding::Callback { raw, .. } => raw.as_ptr().cast_const(),
        }
    }
}

pub(super) struct WindowsProcessAuthOps;

pub(super) static WINDOWS_PROCESS_AUTH_OPS: WindowsProcessAuthOps = WindowsProcessAuthOps;

impl ProcessAuthOps for WindowsProcessAuthOps {
    type Process = RetainedProcess;
    type DesktopPrimaryToken = DesktopPrimaryToken;

    fn open_process(&self, process_id: NonZeroU32) -> Result<Self::Process, ObservationError> {
        open_restricted_process(process_id)
    }

    fn primary_token(&self, process: &Self::Process) -> Result<TokenObservation, ObservationError> {
        primary_token_observation(process)
    }

    fn desktop_primary_token(
        &self,
        token: &Self::DesktopPrimaryToken,
    ) -> Result<TokenObservation, ObservationError> {
        desktop_primary_token_observation(token)
    }

    fn exact_process_is_live(
        &self,
        process: &Self::Process,
        process_id: NonZeroU32,
    ) -> Result<bool, ObservationError> {
        if !validate_process_handle(process, process_id)? {
            return Ok(false);
        }
        let reopened = open_restricted_process(process_id)?;
        // SAFETY: both restricted process handles remain live for the complete
        // object-manager comparison.
        Ok(unsafe { CompareObjectHandles(process.raw(), reopened.raw()) }.as_bool())
    }

    fn same_process(
        &self,
        first: &Self::Process,
        second: &Self::Process,
    ) -> Result<bool, ObservationError> {
        if invalid_handle(first.raw()) || invalid_handle(second.raw()) {
            return Err(ObservationError::Incomplete);
        }
        // SAFETY: both retained handles are live and only observed here.
        Ok(unsafe { CompareObjectHandles(first.raw(), second.raw()) }.as_bool())
    }
}

impl EffectiveThreadAuthOps for WindowsProcessAuthOps {
    fn effective_thread_token(&self) -> Result<TokenObservation, ObservationError> {
        effective_thread_token_observation()
    }
}

impl DesktopImpersonationOps for WindowsProcessAuthOps {
    fn thread_token_state(&self) -> Result<ThreadTokenState, ObservationError> {
        thread_token_state()
    }

    fn current_thread_cookie(&self) -> Result<NonZeroU32, ObservationError> {
        current_thread_cookie()
    }

    fn impersonate_desktop_primary_token(
        &self,
        token: &Self::DesktopPrimaryToken,
    ) -> Result<(), ObservationError> {
        impersonate_desktop_primary_token(token)
    }

    fn revert_desktop_impersonation(&self) -> Result<(), ObservationError> {
        // SAFETY: the auth-owned same-thread lease calls this exactly once
        // after successful ImpersonateLoggedOnUser.
        unsafe { RevertToSelf() }.map_err(|_| ObservationError::Incomplete)
    }

    fn fail_fast(&self) -> ! {
        fail_fast()
    }
}

impl ProcessAuthOps for WindowsRpcAuthOps<'_> {
    type Process = RetainedProcess;
    type DesktopPrimaryToken = DesktopPrimaryToken;

    fn open_process(&self, process_id: NonZeroU32) -> Result<Self::Process, ObservationError> {
        WindowsProcessAuthOps.open_process(process_id)
    }

    fn primary_token(&self, process: &Self::Process) -> Result<TokenObservation, ObservationError> {
        WindowsProcessAuthOps.primary_token(process)
    }

    fn desktop_primary_token(
        &self,
        token: &Self::DesktopPrimaryToken,
    ) -> Result<TokenObservation, ObservationError> {
        WindowsProcessAuthOps.desktop_primary_token(token)
    }

    fn exact_process_is_live(
        &self,
        process: &Self::Process,
        process_id: NonZeroU32,
    ) -> Result<bool, ObservationError> {
        WindowsProcessAuthOps.exact_process_is_live(process, process_id)
    }

    fn same_process(
        &self,
        first: &Self::Process,
        second: &Self::Process,
    ) -> Result<bool, ObservationError> {
        WindowsProcessAuthOps.same_process(first, second)
    }
}

impl RpcAuthOps for WindowsRpcAuthOps<'_> {
    fn call_observation(&self) -> Result<CallObservation, ObservationError> {
        let mut attributes = RPC_CALL_ATTRIBUTES_V2_W {
            Version: RPC_CALL_ATTRIBUTES_VERSION,
            Flags: RPC_QUERY_CLIENT_PID | RPC_QUERY_IS_CLIENT_LOCAL,
            ..RPC_CALL_ATTRIBUTES_V2_W::default()
        };
        // SAFETY: the V2 structure is fully initialized and the lifetime-bound
        // binding is valid for this synchronous server-call query.
        let status = unsafe {
            RpcServerInqCallAttributesW(
                Some(self.raw_binding()),
                ptr::from_mut(&mut attributes).cast::<c_void>(),
            )
        };
        if status.0 != 0 || attributes.Version != RPC_CALL_ATTRIBUTES_VERSION {
            return Err(ObservationError::Incomplete);
        }

        let process_id = u32::try_from(attributes.ClientPID.0.addr())
            .ok()
            .and_then(NonZeroU32::new);
        Ok(CallObservation {
            local: attributes.IsClientLocal == rcclLocal,
            protocol: if attributes.ProtocolSequence == RPC_PROTSEQ_LRPC {
                CallProtocol::LocalRpc
            } else {
                CallProtocol::Other
            },
            interface_uuid_matches: attributes.InterfaceUuid == EXPECTED_INTERFACE_UUID,
            process_id,
            operation_number: attributes.OpNum,
            null_session: attributes.NullSession.as_bool(),
            kernel_mode_caller: attributes.KernelModeCaller.as_bool(),
            call_status: attributes.CallStatus,
            call_kind: if attributes.CallType == rctNormal {
                CallKind::Normal
            } else {
                CallKind::Other
            },
            authentication_level: attributes.AuthenticationLevel,
            authentication_service: attributes.AuthenticationService,
        })
    }

    fn authentication_observation(&self) -> Result<AuthenticationObservation, ObservationError> {
        let mut privileges = ptr::null_mut::<c_void>();
        let mut authentication_level = u32::MAX;
        let mut authentication_service = u32::MAX;
        let mut authorization_service = u32::MAX;
        // SAFETY: all requested scalar outputs are live; no principal-name
        // buffer is requested; the binding cannot outlive this manager call.
        let status = unsafe {
            RpcBindingInqAuthClientExW(
                Some(self.raw_binding()),
                &raw mut privileges,
                None,
                Some(&raw mut authentication_level),
                Some(&raw mut authentication_service),
                Some(&raw mut authorization_service),
                0,
            )
        };
        if status.0 != 0 {
            return Err(ObservationError::Incomplete);
        }
        Ok(AuthenticationObservation {
            authentication_level,
            authentication_service,
            authorization_service,
        })
    }

    fn thread_token_state(&self) -> Result<ThreadTokenState, ObservationError> {
        thread_token_state()
    }

    fn current_thread_cookie(&self) -> Result<NonZeroU32, ObservationError> {
        // SAFETY: this scalar query has no preconditions.
        NonZeroU32::new(unsafe { GetCurrentThreadId() }).ok_or(ObservationError::Incomplete)
    }

    fn impersonate(&self) -> Result<(), ObservationError> {
        // SAFETY: the lifetime-bound call binding is live and used on this
        // manager thread only. A successful result is immediately guarded.
        let status = unsafe { RpcImpersonateClient(Some(self.raw_binding())) };
        rpc_success(status.0)
    }

    fn impersonation_token(&self) -> Result<TokenObservation, ObservationError> {
        let token = open_current_thread_token()?;
        token_observation(token.raw())
    }

    fn duplicate_desktop_primary_token(
        &self,
    ) -> Result<Self::DesktopPrimaryToken, ObservationError> {
        duplicate_current_thread_desktop_primary_token()
    }

    fn revert(&self) -> Result<(), ObservationError> {
        // SAFETY: this is the exact binding used for successful impersonation;
        // the non-Send guard keeps the call on the originating thread.
        let status = unsafe { RpcRevertToSelfEx(Some(self.raw_binding())) };
        rpc_success(status.0)
    }

    fn fail_fast(&self) -> ! {
        // SAFETY: null records request the operating system's canonical
        // fail-fast exception with no attacker-controlled diagnostic payload.
        unsafe { RaiseFailFastException(None, None, 0) };
        std::process::abort()
    }
}

fn rpc_success(status: i32) -> Result<(), ObservationError> {
    if status == 0 {
        Ok(())
    } else {
        Err(ObservationError::Incomplete)
    }
}

fn current_thread_cookie() -> Result<NonZeroU32, ObservationError> {
    // SAFETY: this scalar query has no preconditions.
    NonZeroU32::new(unsafe { GetCurrentThreadId() }).ok_or(ObservationError::Incomplete)
}

fn fail_fast() -> ! {
    // SAFETY: null records request the canonical fail-fast exception without
    // attacker-controlled diagnostic material.
    unsafe { RaiseFailFastException(None, None, 0) };
    std::process::abort()
}

fn thread_token_state() -> Result<ThreadTokenState, ObservationError> {
    let mut token = HANDLE::default();
    // SAFETY: the current-thread pseudo-handle is valid; OpenAsSelf makes this
    // cleanliness query independent of an existing token's access level.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) };
    match result {
        Ok(()) if invalid_handle(token) => Err(ObservationError::Incomplete),
        Ok(()) => {
            let _owned = OwnedToken(token);
            Ok(ThreadTokenState::Present)
        }
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(ThreadTokenState::Clear),
        Err(_) => Err(ObservationError::Incomplete),
    }
}

fn open_current_thread_token() -> Result<OwnedToken, ObservationError> {
    let mut token = HANDLE::default();
    // SAFETY: successful RPC impersonation installed a thread token. OpenAsSelf
    // requests only query access while preserving the impersonated identity.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) }
        .map_err(|_| ObservationError::Incomplete)?;
    if invalid_handle(token) {
        return Err(ObservationError::Incomplete);
    }
    Ok(OwnedToken(token))
}

fn effective_thread_token_observation() -> Result<TokenObservation, ObservationError> {
    let token = open_current_thread_token()?;
    token_observation(token.raw())
}

pub(super) fn impersonate_desktop_primary_token(
    token: &DesktopPrimaryToken,
) -> Result<(), ObservationError> {
    validate_desktop_primary_token_handle(token)?;
    // SAFETY: this adapter retains the exact validated primary-token handle.
    // The caller installs an exact-once RevertToSelf owner immediately after
    // this success and independently validates the resulting thread token.
    unsafe { ImpersonateLoggedOnUser(token.raw()) }.map_err(|_| ObservationError::Incomplete)
}

fn duplicate_current_thread_desktop_primary_token() -> Result<DesktopPrimaryToken, ObservationError>
{
    let mut source = HANDLE::default();
    // SAFETY: successful RPC impersonation installed the current thread token.
    // OpenAsSelf lets the service request only query and duplication authority
    // without changing the effective client identity being copied.
    unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            true,
            &raw mut source,
        )
    }
    .map_err(|_| ObservationError::Incomplete)?;
    if invalid_handle(source) {
        return Err(ObservationError::Incomplete);
    }
    let source = OwnedToken(source);

    let mut duplicate = HANDLE::default();
    // SAFETY: `source` is the exact live impersonation token opened above.
    // A null SECURITY_ATTRIBUTES pointer makes the new handle non-inheritable;
    // the desired mask is exactly CreateProcessAsUserW's documented token
    // requirement, and TokenPrimary produces the required primary-token type.
    unsafe {
        DuplicateTokenEx(
            source.raw(),
            DESKTOP_PRIMARY_TOKEN_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &raw mut duplicate,
        )
    }
    .map_err(|_| ObservationError::Incomplete)?;
    if invalid_handle(duplicate) {
        return Err(ObservationError::Incomplete);
    }
    let token = DesktopPrimaryToken {
        token: OwnedToken(duplicate),
        _not_sync: PhantomData,
    };
    validate_desktop_primary_token_handle(&token)?;
    Ok(token)
}

fn open_restricted_process(process_id: NonZeroU32) -> Result<RetainedProcess, ObservationError> {
    let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    // SAFETY: a nonzero RPC-observed PID is supplied, inheritance is disabled,
    // and only the fixed query/liveness rights are requested.
    let raw = unsafe { OpenProcess(access, false, process_id.get()) }
        .map_err(|_| ObservationError::Incomplete)?;
    if invalid_handle(raw) {
        return Err(ObservationError::Incomplete);
    }
    let process = RetainedProcess(raw);
    if !validate_process_handle(&process, process_id)? {
        return Err(ObservationError::Incomplete);
    }
    Ok(process)
}

fn validate_process_handle(
    process: &RetainedProcess,
    process_id: NonZeroU32,
) -> Result<bool, ObservationError> {
    if invalid_handle(process.raw()) {
        return Err(ObservationError::Incomplete);
    }
    let mut flags = u32::MAX;
    // SAFETY: the retained process handle is live and the scalar output is
    // initialized. OpenProcess requested a non-inheritable exact handle.
    unsafe { GetHandleInformation(process.raw(), &raw mut flags) }
        .map_err(|_| ObservationError::Incomplete)?;
    if flags != 0 {
        return Ok(false);
    }
    // SAFETY: the retained process handle is live for this scalar query.
    if unsafe { GetProcessId(process.raw()) } != process_id.get() {
        return Ok(false);
    }
    // SAFETY: SYNCHRONIZE was requested and a zero timeout only observes state.
    Ok(unsafe { WaitForSingleObject(process.raw(), 0) } == WAIT_TIMEOUT)
}

fn primary_token_observation(
    process: &RetainedProcess,
) -> Result<TokenObservation, ObservationError> {
    let mut token = HANDLE::default();
    // SAFETY: the retained process is live with query-limited-information and
    // output receives one query-only primary-token handle.
    unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &raw mut token) }
        .map_err(|_| ObservationError::Incomplete)?;
    if invalid_handle(token) {
        return Err(ObservationError::Incomplete);
    }
    let token = OwnedToken(token);
    token_observation(token.raw())
}

fn desktop_primary_token_observation(
    token: &DesktopPrimaryToken,
) -> Result<TokenObservation, ObservationError> {
    validate_desktop_primary_token_handle(token)?;
    token_observation(token.raw())
}

fn validate_desktop_primary_token_handle(
    token: &DesktopPrimaryToken,
) -> Result<(), ObservationError> {
    if invalid_handle(token.raw()) {
        return Err(ObservationError::Incomplete);
    }
    let mut flags = u32::MAX;
    // SAFETY: the move-only owner retains this live handle and `flags` is exact
    // writable scalar storage. DuplicateTokenEx received no inheritable
    // SECURITY_ATTRIBUTES, so any nonzero flag is a fail-closed mismatch.
    unsafe { GetHandleInformation(token.raw(), &raw mut flags) }
        .map_err(|_| ObservationError::Incomplete)?;
    if flags != 0 {
        return Err(ObservationError::Incomplete);
    }
    Ok(())
}

fn token_observation(token: HANDLE) -> Result<TokenObservation, ObservationError> {
    if invalid_handle(token) {
        return Err(ObservationError::Incomplete);
    }

    let mut statistics = TOKEN_STATISTICS::default();
    fill_token_fixed(token, TokenStatistics, &mut statistics)?;
    let (token_kind, token_level) = token_kind_and_level(token, statistics.TokenType)?;
    let user_sid = token_user_sid(token)?;
    let groups = token_group_observation(token)?;
    let session_id = token_u32(token, TokenSessionId)?;
    let app_container = exact_boolean(token_u32(token, TokenIsAppContainer)?)?;
    let ui_access = exact_boolean(token_u32(token, TokenUIAccess)?)?;
    let integrity_rid = token_integrity_rid(token)?;
    let elevation = token_elevation(token)?;
    // TokenHasRestrictions distinguishes an unfiltered token from any token
    // produced by filtering. Supported Windows builds report either the
    // documented DWORD or the native one-byte BOOLEAN width; all other shapes
    // and non-canonical Boolean values fail closed.
    let restricted = token_has_restrictions(token)?;

    Ok(TokenObservation {
        user_sid,
        logon_sid_count: groups.logon_sid_count,
        logon_sid: groups.logon_sid,
        session_id,
        authentication_id: authentication_id(statistics.AuthenticationId),
        token_id: token_id(statistics.TokenId),
        token_kind,
        token_level,
        app_container,
        ui_access,
        integrity_rid,
        elevation,
        restricted,
        interactive_sid_enabled: groups.interactive_sid_enabled,
    })
}

fn token_kind_and_level(
    token: HANDLE,
    token_type: TOKEN_TYPE,
) -> Result<(TokenKind, TokenLevel), ObservationError> {
    if token_type == TokenPrimary {
        return Ok((TokenKind::Primary, TokenLevel::NotApplicable));
    }
    if token_type != TokenImpersonation {
        return Ok((TokenKind::Other, TokenLevel::Other));
    }

    let mut level = SECURITY_IMPERSONATION_LEVEL::default();
    fill_token_fixed(token, TokenImpersonationLevel, &mut level)?;
    Ok((
        TokenKind::Impersonation,
        classify_impersonation_level(level),
    ))
}

fn classify_impersonation_level(level: SECURITY_IMPERSONATION_LEVEL) -> TokenLevel {
    if level == SecurityImpersonation {
        TokenLevel::Impersonation
    } else if level == SecurityDelegation {
        TokenLevel::Delegation
    } else {
        TokenLevel::Other
    }
}

fn token_elevation(token: HANDLE) -> Result<ElevationKind, ObservationError> {
    let mut elevation = TOKEN_ELEVATION_TYPE::default();
    fill_token_fixed(token, TokenElevationType, &mut elevation)?;
    Ok(if elevation == TokenElevationTypeDefault {
        ElevationKind::Default
    } else if elevation == TokenElevationTypeLimited {
        ElevationKind::Limited
    } else if elevation == TokenElevationTypeFull {
        ElevationKind::Full
    } else {
        ElevationKind::Other
    })
}

fn token_user_sid(token: HANDLE) -> Result<SidBytes, ObservationError> {
    let information = token_information(token, TokenUser, size_of::<TOKEN_USER>())?;
    // SAFETY: the query returned at least a complete TOKEN_USER header in an
    // aligned buffer that remains live through SID copying.
    let user = unsafe { &*information.as_ptr::<TOKEN_USER>() };
    copy_sid(user.User.Sid)
}

struct TokenGroupObservation {
    logon_sid_count: u32,
    logon_sid: Option<SidBytes>,
    interactive_sid_enabled: bool,
}

fn token_group_observation(token: HANDLE) -> Result<TokenGroupObservation, ObservationError> {
    let information = token_information(token, TokenGroups, size_of::<TOKEN_GROUPS>())?;
    let groups = information.as_ptr::<TOKEN_GROUPS>();
    // SAFETY: the query returned at least a complete TOKEN_GROUPS prefix.
    let count = usize::try_from(unsafe { (*groups).GroupCount })
        .map_err(|_| ObservationError::Incomplete)?;
    let required = token_groups_bytes(count)?;
    if required > information.returned_bytes {
        return Err(ObservationError::Incomplete);
    }
    // SAFETY: count was bounded against the initialized flexible-array bytes.
    let entries = unsafe {
        core::slice::from_raw_parts(
            ptr::addr_of!((*groups).Groups).cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let logon_flag = u32::from_ne_bytes(SE_GROUP_LOGON_ID.to_ne_bytes());
    let enabled_flag = u32::from_ne_bytes(SE_GROUP_ENABLED.to_ne_bytes());
    let mut logon_sid_count = 0_u32;
    let mut logon_sid = None;
    let mut interactive_sid_enabled = false;
    for entry in entries {
        let sid = copy_sid(entry.Sid)?;
        if entry.Attributes & logon_flag == logon_flag {
            logon_sid_count = logon_sid_count
                .checked_add(1)
                .ok_or(ObservationError::Incomplete)?;
            if logon_sid.is_none() {
                logon_sid = Some(sid);
                continue;
            }
        }
        if entry.Attributes & enabled_flag == enabled_flag && sid.0 == INTERACTIVE_SID {
            interactive_sid_enabled = true;
        }
    }
    Ok(TokenGroupObservation {
        logon_sid_count,
        logon_sid,
        interactive_sid_enabled,
    })
}

fn token_groups_bytes(count: usize) -> Result<usize, ObservationError> {
    count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|bytes| bytes.checked_add(offset_of!(TOKEN_GROUPS, Groups)))
        .ok_or(ObservationError::Incomplete)
}

fn token_integrity_rid(token: HANDLE) -> Result<u32, ObservationError> {
    let information = token_information(
        token,
        TokenIntegrityLevel,
        size_of::<TOKEN_MANDATORY_LABEL>(),
    )?;
    // SAFETY: the query returned a complete aligned TOKEN_MANDATORY_LABEL.
    let label = unsafe { &*information.as_ptr::<TOKEN_MANDATORY_LABEL>() };
    let integrity_flag = u32::from_ne_bytes(SE_GROUP_INTEGRITY.to_ne_bytes());
    let integrity_enabled_flag = u32::from_ne_bytes(SE_GROUP_INTEGRITY_ENABLED.to_ne_bytes());
    if label.Label.Attributes & integrity_flag != integrity_flag
        || label.Label.Attributes & integrity_enabled_flag != integrity_enabled_flag
    {
        return Err(ObservationError::Incomplete);
    }
    let sid = copy_sid(label.Label.Sid)?;
    integrity_rid(&sid)
}

fn integrity_rid(sid: &SidBytes) -> Result<u32, ObservationError> {
    if !sid.has_valid_length()
        || sid.0.first().copied() != Some(1)
        || sid.0.get(2..8) != Some(MANDATORY_LABEL_AUTHORITY.as_slice())
    {
        return Err(ObservationError::Incomplete);
    }
    let sub_authority_count = usize::from(sid.0[1]);
    if sub_authority_count == 0
        || 8_usize
            .checked_add(
                sub_authority_count
                    .checked_mul(size_of::<u32>())
                    .ok_or(ObservationError::Incomplete)?,
            )
            .ok_or(ObservationError::Incomplete)?
            != sid.0.len()
    {
        return Err(ObservationError::Incomplete);
    }
    let offset = 8_usize
        .checked_add(
            sub_authority_count
                .saturating_sub(1)
                .checked_mul(size_of::<u32>())
                .ok_or(ObservationError::Incomplete)?,
        )
        .ok_or(ObservationError::Incomplete)?;
    let bytes: [u8; 4] = sid
        .0
        .get(offset..offset + size_of::<u32>())
        .ok_or(ObservationError::Incomplete)?
        .try_into()
        .map_err(|_| ObservationError::Incomplete)?;
    Ok(u32::from_le_bytes(bytes))
}

fn token_u32(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<u32, ObservationError> {
    let mut value = u32::MAX;
    fill_token_fixed(token, class, &mut value)?;
    Ok(value)
}

fn exact_boolean(value: u32) -> Result<bool, ObservationError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ObservationError::Incomplete),
    }
}

fn token_has_restrictions(token: HANDLE) -> Result<bool, ObservationError> {
    let information = token_information(token, TokenHasRestrictions, 1)?;
    parse_token_has_restrictions(information.initialized_bytes())
}

fn parse_token_has_restrictions(bytes: &[u8]) -> Result<bool, ObservationError> {
    match bytes {
        [value] => exact_boolean(u32::from(*value)),
        [first, second, third, fourth] => {
            exact_boolean(u32::from_ne_bytes([*first, *second, *third, *fourth]))
        }
        _ => Err(ObservationError::Incomplete),
    }
}

fn fill_token_fixed<T>(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    value: &mut T,
) -> Result<(), ObservationError> {
    let bytes = u32::try_from(size_of::<T>()).map_err(|_| ObservationError::Incomplete)?;
    let mut returned = 0_u32;
    // SAFETY: every caller supplies initialized storage of the exact documented
    // C type for `class`; the live query token is borrowed for this call only.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(ptr::from_mut(value).cast::<c_void>()),
            bytes,
            &raw mut returned,
        )
    }
    .map_err(|_| ObservationError::Incomplete)?;
    if returned != bytes {
        return Err(ObservationError::Incomplete);
    }
    Ok(())
}

fn token_information(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    minimum_bytes: usize,
) -> Result<TokenInformationBuffer, ObservationError> {
    let mut needed = 0_u32;
    // SAFETY: the first query deliberately requests only the required size.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &raw mut needed) };
    let needed_usize = usize::try_from(needed).map_err(|_| ObservationError::Incomplete)?;
    if needed_usize < minimum_bytes || needed_usize > MAX_TOKEN_INFORMATION_BYTES {
        return Err(ObservationError::Incomplete);
    }
    let word_size = size_of::<usize>();
    let word_count = needed_usize
        .checked_add(word_size.saturating_sub(1))
        .and_then(|rounded| rounded.checked_div(word_size))
        .ok_or(ObservationError::Incomplete)?;
    let mut words = vec![0_usize; word_count];
    let capacity_bytes = words
        .len()
        .checked_mul(word_size)
        .ok_or(ObservationError::Incomplete)?;
    let capacity_u32 = u32::try_from(capacity_bytes).map_err(|_| ObservationError::Incomplete)?;
    let mut returned = capacity_u32;
    // SAFETY: the aligned allocation is writable for capacity_u32 bytes and
    // remains live while all returned interior pointers are consumed.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(words.as_mut_ptr().cast::<c_void>()),
            capacity_u32,
            &raw mut returned,
        )
    }
    .map_err(|_| ObservationError::Incomplete)?;
    let returned_bytes = usize::try_from(returned).map_err(|_| ObservationError::Incomplete)?;
    if returned_bytes < minimum_bytes || returned_bytes > capacity_bytes {
        return Err(ObservationError::Incomplete);
    }
    Ok(TokenInformationBuffer {
        words,
        returned_bytes,
    })
}

fn copy_sid(sid: PSID) -> Result<SidBytes, ObservationError> {
    // SAFETY: callers pass a SID pointer returned inside a still-live token
    // information buffer.
    if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(ObservationError::Incomplete);
    }
    // SAFETY: IsValidSid accepted the complete SID.
    let length =
        usize::try_from(unsafe { GetLengthSid(sid) }).map_err(|_| ObservationError::Incomplete)?;
    if !(MIN_BINARY_SID_BYTES..=MAX_BINARY_SID_BYTES).contains(&length) {
        return Err(ObservationError::Incomplete);
    }
    let mut bytes = vec![0_u8; length];
    // SAFETY: source contains `length` validated SID bytes and destination has
    // exactly that writable capacity.
    unsafe { ptr::copy_nonoverlapping(sid.0.cast::<u8>(), bytes.as_mut_ptr(), length) };
    Ok(SidBytes(bytes))
}

const fn authentication_id(luid: LUID) -> AuthenticationId {
    AuthenticationId {
        low_part: luid.LowPart,
        high_part: luid.HighPart,
    }
}

const fn token_id(luid: LUID) -> TokenId {
    TokenId {
        low_part: luid.LowPart,
        high_part: luid.HighPart,
    }
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.0.is_null() || handle == INVALID_HANDLE_VALUE || handle.is_invalid()
}

#[cfg(test)]
mod tests {
    use super::{
        DESKTOP_PRIMARY_TOKEN_ACCESS, DesktopPrimaryToken, MANDATORY_LABEL_AUTHORITY, OwnedToken,
        SidBytes, TokenLevel, classify_impersonation_level, exact_boolean, integrity_rid,
        parse_token_has_restrictions, token_groups_bytes,
    };
    use std::marker::PhantomData;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        SecurityAnonymous, SecurityDelegation, SecurityIdentification, SecurityImpersonation,
        TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
    };

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
    fn desktop_primary_token_is_move_only_send_and_not_sync() {
        assert_send::<DesktopPrimaryToken>();
        let _ = <DesktopPrimaryToken as AmbiguousIfSync<_>>::marker;
        let _ = <DesktopPrimaryToken as AmbiguousIfClone<_>>::marker;
        let _ = <DesktopPrimaryToken as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn desktop_primary_token_debug_is_data_free() {
        let token = DesktopPrimaryToken {
            token: OwnedToken(HANDLE::default()),
            _not_sync: PhantomData,
        };
        assert_eq!(format!("{token:?}"), "DesktopPrimaryToken([REDACTED])");
    }

    #[test]
    fn desktop_primary_token_rights_are_exactly_create_process_as_user_minimum() {
        assert_eq!(
            DESKTOP_PRIMARY_TOKEN_ACCESS.0,
            TOKEN_ASSIGN_PRIMARY.0 | TOKEN_DUPLICATE.0 | TOKEN_QUERY.0
        );
        let forbidden = TOKEN_IMPERSONATE.0
            | TOKEN_ADJUST_PRIVILEGES.0
            | TOKEN_ADJUST_GROUPS.0
            | TOKEN_ADJUST_DEFAULT.0
            | TOKEN_ADJUST_SESSIONID.0;
        assert_eq!(DESKTOP_PRIMARY_TOKEN_ACCESS.0 & forbidden, 0);
    }

    #[test]
    fn effective_thread_level_accepts_impersonation_or_delegation_only() {
        assert_eq!(
            classify_impersonation_level(SecurityImpersonation),
            TokenLevel::Impersonation
        );
        assert_eq!(
            classify_impersonation_level(SecurityDelegation),
            TokenLevel::Delegation
        );
        assert_eq!(
            classify_impersonation_level(SecurityAnonymous),
            TokenLevel::Other
        );
        assert_eq!(
            classify_impersonation_level(SecurityIdentification),
            TokenLevel::Other
        );
    }

    #[test]
    fn integrity_sid_parser_requires_mandatory_authority_and_exact_shape() {
        let mut medium = vec![1, 1];
        medium.extend_from_slice(&MANDATORY_LABEL_AUTHORITY);
        medium.extend_from_slice(&0x2000_u32.to_le_bytes());
        assert_eq!(integrity_rid(&SidBytes(medium)), Ok(0x2000));

        let wrong_authority = SidBytes(vec![1, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0x20, 0]);
        assert!(integrity_rid(&wrong_authority).is_err());
        let wrong_count = SidBytes(vec![1, 2, 0, 0, 0, 0, 0, 16, 0, 0, 0x20, 0]);
        assert!(integrity_rid(&wrong_count).is_err());
    }

    #[test]
    fn exact_token_booleans_and_group_bounds_fail_closed() {
        assert_eq!(exact_boolean(0), Ok(false));
        assert_eq!(exact_boolean(1), Ok(true));
        assert!(exact_boolean(2).is_err());
        assert!(token_groups_bytes(0).is_ok());
        assert!(token_groups_bytes(usize::MAX).is_err());
    }

    #[test]
    fn token_restriction_widths_are_closed_and_canonical() {
        assert_eq!(parse_token_has_restrictions(&[0]), Ok(false));
        assert_eq!(parse_token_has_restrictions(&[1]), Ok(true));
        assert_eq!(
            parse_token_has_restrictions(&0_u32.to_ne_bytes()),
            Ok(false)
        );
        assert_eq!(parse_token_has_restrictions(&1_u32.to_ne_bytes()), Ok(true));
        assert!(parse_token_has_restrictions(&[2]).is_err());
        assert!(parse_token_has_restrictions(&2_u32.to_ne_bytes()).is_err());
        assert!(parse_token_has_restrictions(&[]).is_err());
        assert!(parse_token_has_restrictions(&[0, 0]).is_err());
        assert!(parse_token_has_restrictions(&[0; 8]).is_err());
    }
}
