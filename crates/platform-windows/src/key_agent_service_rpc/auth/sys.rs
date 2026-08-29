//! Narrow Windows adapter for per-call RPC and token observations.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use core::mem::{MaybeUninit, align_of, offset_of, size_of};
use core::ptr;
use std::cell::Cell;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::os::windows::io::{
    AsHandle as _, AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle,
};
use std::ptr::NonNull;
use std::rc::Rc;

use key_agent_service_rpc_sys::{CallBinding, INTERFACE_UUID};
use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, ERROR_ACCESS_DENIED, ERROR_NO_TOKEN, GetHandleInformation,
    HANDLE, INVALID_HANDLE_VALUE, LUID, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::{
    DuplicateTokenEx, GetLengthSid, GetTokenInformation, ImpersonateLoggedOnUser, IsValidSid,
    LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PSID, RevertToSelf, SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PRIVILEGE_USED_FOR_ACCESS,
    SECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, SID_AND_ATTRIBUTES, SecurityDelegation,
    SecurityImpersonation, TOKEN_ACCESS_MASK, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_ELEVATION_TYPE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_USER, TokenElevationType,
    TokenElevationTypeDefault, TokenElevationTypeFull, TokenElevationTypeLimited, TokenGroups,
    TokenHasRestrictions, TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel,
    TokenIsAppContainer, TokenPrimary, TokenPrivileges, TokenSessionId, TokenStatistics,
    TokenUIAccess, TokenUser,
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
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DEBUG_ONLY_THIS_PROCESS, EXTENDED_STARTUPINFO_PRESENT, GetCurrentThread, GetCurrentThreadId,
    GetProcessId, GetProcessIdOfThread, GetThreadId, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_CREATION_FLAGS, PROCESS_DUP_HANDLE, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, STARTUPINFOEXW, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};
use windows::core::{GUID, PCWSTR};
use zeroize::Zeroize as _;

use crate::inheritable_handle_launch::ProcessThreadCreationSecurity;

use super::{
    AuthenticationId, AuthenticationObservation, CallKind, CallObservation, CallProtocol,
    DebugPrivilegeState, DesktopImpersonationOps, DesktopProcessAccessError,
    EffectiveThreadAuthOps, ElevationKind, ObservationError, ProcessAuthOps, RpcAuthOps, SidBytes,
    ThreadTokenState, TokenId, TokenKind, TokenLevel, TokenObservation,
};

const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_BINARY_SID_BYTES: usize = 68;
const INTERACTIVE_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 4, 0, 0, 0];
const MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];
const EXPECTED_INTERFACE_UUID: GUID = GUID::from_u128(u128::from_be_bytes(INTERFACE_UUID));
const DESKTOP_PRIMARY_TOKEN_ACCESS: TOKEN_ACCESS_MASK =
    TOKEN_ACCESS_MASK(TOKEN_ASSIGN_PRIMARY.0 | TOKEN_DUPLICATE.0 | TOKEN_QUERY.0);
const DESKTOP_PROCESS_CREATION_FLAGS: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(
    CREATE_SUSPENDED.0
        | DEBUG_ONLY_THIS_PROCESS.0
        | CREATE_NO_WINDOW.0
        | CREATE_UNICODE_ENVIRONMENT.0
        | EXTENDED_STARTUPINFO_PRESENT.0,
);
const MAX_UNICODE_PROCESS_PARAMETER_UNITS: usize = 32_767;
pub(super) const DESKTOP_PROCESS_CLEANUP_WAIT_MILLISECONDS: u32 = 5_000;
const DESKTOP_PROCESS_TERMINATION_EXIT_CODE: u32 = 0xE052_0001;
const DESKTOP_NAME_WIDE: [u16; 16] = [
    119, 105, 110, 115, 116, 97, 48, 92, 100, 101, 102, 97, 117, 108, 116, 0,
];
const LOCAL_APP_DATA_PREFIX: [u16; 13] = [76, 79, 67, 65, 76, 65, 80, 80, 68, 65, 84, 65, 61];
const SYSTEM_ROOT_PREFIX: [u16; 11] = [83, 121, 115, 116, 101, 109, 82, 111, 111, 116, 61];
const WINDIR_PREFIX: [u16; 7] = [87, 73, 78, 68, 73, 82, 61];

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

pub(super) fn retained_process_matches_borrowed(
    retained: &RetainedProcess,
    process: BorrowedHandle<'_>,
) -> Result<bool, ObservationError> {
    let process = windows_handle(process);
    if invalid_handle(retained.raw()) || invalid_handle(process) {
        return Err(ObservationError::Incomplete);
    }
    // SAFETY: the retained owner and lifetime-bound borrowed handle remain live
    // for the complete object-manager comparison.
    Ok(unsafe { CompareObjectHandles(retained.raw(), process) }.as_bool())
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

struct UnexpectedProcessAccess(HANDLE);

impl UnexpectedProcessAccess {
    fn new(handle: HANDLE) -> Result<Self, DesktopProcessAccessError> {
        if invalid_handle(handle) {
            Err(DesktopProcessAccessError::Incomplete)
        } else {
            Ok(Self(handle))
        }
    }

    fn close_checked(mut self) -> Result<(), DesktopProcessAccessError> {
        let handle = self.0;
        // SAFETY: this owner was created only from one successful OpenProcess
        // result and still owns the exact live handle.
        unsafe { CloseHandle(handle) }.map_err(|_| DesktopProcessAccessError::Incomplete)?;
        self.0 = HANDLE::default();
        Ok(())
    }
}

impl Drop for UnexpectedProcessAccess {
    fn drop(&mut self) {
        if !invalid_handle(self.0) {
            // SAFETY: a failed checked close leaves this exact owner armed for
            // one ordinary RAII retry without exporting the handle.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeDesktopProcessCreateError {
    Authentication,
    InvalidInput,
    OperatingSystem,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeDesktopProcessCleanupError {
    TerminationRequest,
    Wait,
    TerminationRequestAndWait,
}

/// Private creator-thread ownership of successful process-creation outputs.
pub(super) struct CreatedDesktopProcess {
    process: Option<OwnedHandle>,
    primary_thread: Option<OwnedHandle>,
    process_id: NonZeroU32,
    primary_thread_id: NonZeroU32,
    creator_thread_id: NonZeroU32,
    must_transition: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl CreatedDesktopProcess {
    pub(super) fn process_handle(&self) -> BorrowedHandle<'_> {
        match self.process.as_ref() {
            Some(process) => process.as_handle(),
            None => fail_fast(),
        }
    }

    pub(super) fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
        match self.primary_thread.as_ref() {
            Some(thread) => thread.as_handle(),
            None => fail_fast(),
        }
    }

    pub(super) const fn process_id(&self) -> NonZeroU32 {
        self.process_id
    }

    pub(super) const fn primary_thread_id(&self) -> NonZeroU32 {
        self.primary_thread_id
    }

    pub(super) fn request_termination_into_pending_debugger_exit_cleanup(
        mut self,
    ) -> PendingDebuggerExitProcessCleanup {
        // SAFETY: this scalar query has no preconditions and is compared with
        // the exact creator-thread identity captured before the native call.
        if NonZeroU32::new(unsafe { GetCurrentThreadId() }) != Some(self.creator_thread_id) {
            fail_fast();
        }
        let Some(process) = self.process.as_ref() else {
            fail_fast();
        };
        // SAFETY: this is the exact live process handle returned by the
        // successful creation call. Termination is asynchronous; the result is
        // retained without waiting while this thread still owns debugger state.
        let termination_requested = unsafe {
            TerminateProcess(
                windows_handle(process.as_handle()),
                DESKTOP_PROCESS_TERMINATION_EXIT_CODE,
            )
        }
        .is_ok();
        let Some(process) = self.process.take() else {
            fail_fast();
        };
        let Some(primary_thread) = self.primary_thread.take() else {
            fail_fast();
        };
        self.must_transition = false;
        PendingDebuggerExitProcessCleanup {
            process: Some(process),
            primary_thread: Some(primary_thread),
            termination_requested,
            must_wait_and_close: true,
            _not_sync: PhantomData,
        }
    }

    /// Performs every fallible creator-thread check needed by the successful
    /// debugger-exit handoff before kill-on-debugger-exit is disabled.
    ///
    /// The returned owner remains creator-thread-bound. Its only successful
    /// transition is an infallible field move, so the caller can make
    /// `DebugSetProcessKillOnExit(FALSE)` its final fallible debugger-thread
    /// operation.
    pub(super) fn prepare_pending_debugger_exit_success(
        mut self,
    ) -> PreparedDebuggerExitProcessSuccess {
        // SAFETY: this scalar query has no preconditions and is compared with
        // the exact creator-thread identity captured before process creation.
        if NonZeroU32::new(unsafe { GetCurrentThreadId() }) != Some(self.creator_thread_id) {
            fail_fast();
        }
        let Some(process) = self.process.take() else {
            fail_fast();
        };
        let Some(primary_thread) = self.primary_thread.take() else {
            fail_fast();
        };
        self.must_transition = false;
        PreparedDebuggerExitProcessSuccess {
            process: Some(process),
            primary_thread: Some(primary_thread),
            process_id: self.process_id,
            primary_thread_id: self.primary_thread_id,
            commit_required: true,
            _thread_bound: PhantomData,
        }
    }
}

impl fmt::Debug for CreatedDesktopProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CreatedDesktopProcess([REDACTED])")
    }
}

impl Drop for CreatedDesktopProcess {
    fn drop(&mut self) {
        if !self.must_transition {
            return;
        }
        if let Some(process) = self.process.as_ref() {
            // SAFETY: this owner still retains the exact successfully returned
            // process handle. Best-effort termination precedes fail-fast so a
            // missed explicit transition cannot silently leave a child alive.
            unsafe {
                let _ = TerminateProcess(
                    windows_handle(process.as_handle()),
                    DESKTOP_PROCESS_TERMINATION_EXIT_CODE,
                );
            }
        }
        fail_fast();
    }
}

/// Creator-thread-bound successful handoff prepared before no-kill arming.
///
/// Construction performs the creator-thread check and extracts both exact
/// handles. After `DebugSetProcessKillOnExit(FALSE)` succeeds,
/// [`Self::commit_after_no_kill`] performs no allocation, lock, query, close,
/// or fallible native operation.
pub(super) struct PreparedDebuggerExitProcessSuccess {
    process: Option<OwnedHandle>,
    primary_thread: Option<OwnedHandle>,
    process_id: NonZeroU32,
    primary_thread_id: NonZeroU32,
    commit_required: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PreparedDebuggerExitProcessSuccess {
    /// Commits the already-prepared ownership move after successful no-kill
    /// arming. This function is deliberately infallible.
    pub(super) fn commit_after_no_kill(mut self) -> PendingDebuggerExitProcessSuccess {
        let Some(process) = self.process.take() else {
            fail_fast();
        };
        let Some(primary_thread) = self.primary_thread.take() else {
            fail_fast();
        };
        self.commit_required = false;
        PendingDebuggerExitProcessSuccess {
            process: Some(process),
            primary_thread: Some(primary_thread),
            process_id: self.process_id,
            primary_thread_id: self.primary_thread_id,
            must_finalize: true,
            _not_sync: PhantomData,
        }
    }

    /// Converts a failed no-kill attempt into the ordinary process-terminal
    /// cleanup state without waiting on the still-live debugger thread.
    pub(super) fn abort_into_pending_cleanup(mut self) -> PendingDebuggerExitProcessCleanup {
        let Some(process) = self.process.as_ref() else {
            fail_fast();
        };
        // SAFETY: this is the exact live creator process handle. The result is
        // latched and the post-join cleanup owner performs the bounded wait.
        let termination_requested = unsafe {
            TerminateProcess(
                windows_handle(process.as_handle()),
                DESKTOP_PROCESS_TERMINATION_EXIT_CODE,
            )
        }
        .is_ok();
        let Some(process) = self.process.take() else {
            fail_fast();
        };
        let Some(primary_thread) = self.primary_thread.take() else {
            fail_fast();
        };
        self.commit_required = false;
        PendingDebuggerExitProcessCleanup {
            process: Some(process),
            primary_thread: Some(primary_thread),
            termination_requested,
            must_wait_and_close: true,
            _not_sync: PhantomData,
        }
    }
}

impl fmt::Debug for PreparedDebuggerExitProcessSuccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedDebuggerExitProcessSuccess([REDACTED])")
    }
}

impl Drop for PreparedDebuggerExitProcessSuccess {
    fn drop(&mut self) {
        if !self.commit_required {
            return;
        }
        if let Some(process) = self.process.as_ref() {
            // SAFETY: this is the exact retained process owner. Best-effort
            // termination precedes fail-fast if an explicit transition is lost.
            unsafe {
                let _ = TerminateProcess(
                    windows_handle(process.as_handle()),
                    DESKTOP_PROCESS_TERMINATION_EXIT_CODE,
                );
            }
        }
        fail_fast();
    }
}

/// Sendable but non-shareable process owner awaiting exact debugger-thread join.
///
/// No handle is exposed until the launch layer consumes its run-specific join
/// proof. Dropping this state requests process termination before closing the
/// handles, preserving process-terminal behavior on abandonment.
pub(super) struct PendingDebuggerExitProcessSuccess {
    process: Option<OwnedHandle>,
    primary_thread: Option<OwnedHandle>,
    process_id: NonZeroU32,
    primary_thread_id: NonZeroU32,
    must_finalize: bool,
    _not_sync: PhantomData<Cell<()>>,
}

impl PendingDebuggerExitProcessSuccess {
    /// Commits the post-join ownership phase. The caller owns the unforgeable
    /// join proof; this adapter performs only an infallible field move.
    pub(super) fn finish_after_debugger_exit(mut self) -> DetachedDesktopProcess {
        let Some(process) = self.process.take() else {
            fail_fast();
        };
        let Some(primary_thread) = self.primary_thread.take() else {
            fail_fast();
        };
        self.must_finalize = false;
        DetachedDesktopProcess {
            process: Some(process),
            primary_thread: Some(primary_thread),
            process_id: self.process_id,
            primary_thread_id: self.primary_thread_id,
            _not_sync: PhantomData,
        }
    }
}

impl fmt::Debug for PendingDebuggerExitProcessSuccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingDebuggerExitProcessSuccess([REDACTED])")
    }
}

impl Drop for PendingDebuggerExitProcessSuccess {
    fn drop(&mut self) {
        if !self.must_finalize {
            return;
        }
        if let Some(process) = self.process.as_ref() {
            // SAFETY: this owner retains the exact creator process handle. A
            // join-pending success must fail closed if abandoned.
            unsafe {
                let _ = TerminateProcess(
                    windows_handle(process.as_handle()),
                    DESKTOP_PROCESS_TERMINATION_EXIT_CODE,
                );
            }
        }
        // Losing the only post-join finalization path would otherwise discard
        // the registry's numeric debug-event aliases after creator handles are
        // closed. Process-wide fail-fast reclaims the complete service handle
        // table without ever raw-closing an unverified/reused word.
        fail_fast();
    }
}

/// Exact creator handles after the run-specific debugger-thread join proof.
pub(super) struct DetachedDesktopProcess {
    process: Option<OwnedHandle>,
    primary_thread: Option<OwnedHandle>,
    process_id: NonZeroU32,
    primary_thread_id: NonZeroU32,
    _not_sync: PhantomData<Cell<()>>,
}

impl DetachedDesktopProcess {
    pub(super) fn process_handle(&self) -> BorrowedHandle<'_> {
        match self.process.as_ref() {
            Some(process) => process.as_handle(),
            None => fail_fast(),
        }
    }

    pub(super) fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
        match self.primary_thread.as_ref() {
            Some(thread) => thread.as_handle(),
            None => fail_fast(),
        }
    }

    pub(super) const fn process_id(&self) -> NonZeroU32 {
        self.process_id
    }

    pub(super) const fn primary_thread_id(&self) -> NonZeroU32 {
        self.primary_thread_id
    }

    /// Requests termination while retaining both creator handles so the
    /// launch layer can validate and close joined debug-event aliases only
    /// after an exact terminal observation.
    pub(super) fn request_termination_for_cleanup(
        &self,
    ) -> Result<(), NativeDesktopProcessCleanupError> {
        // SAFETY: this is the exact retained creator process handle.
        unsafe {
            TerminateProcess(
                windows_handle(self.process_handle()),
                DESKTOP_PROCESS_TERMINATION_EXIT_CODE,
            )
        }
        .map_err(|_| NativeDesktopProcessCleanupError::TerminationRequest)
    }

    /// Proves process termination without closing either creator handle.
    pub(super) fn wait_for_exit_for_cleanup(&self) -> Result<(), NativeDesktopProcessCleanupError> {
        // SAFETY: this retained creator handle includes SYNCHRONIZE and remains
        // live for the complete bounded wait.
        if unsafe {
            WaitForSingleObject(
                windows_handle(self.process_handle()),
                DESKTOP_PROCESS_CLEANUP_WAIT_MILLISECONDS,
            )
        } == WAIT_OBJECT_0
        {
            Ok(())
        } else {
            Err(NativeDesktopProcessCleanupError::Wait)
        }
    }
}

impl fmt::Debug for DetachedDesktopProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DetachedDesktopProcess([REDACTED])")
    }
}

impl Drop for DetachedDesktopProcess {
    fn drop(&mut self) {
        if let Some(process) = self.process.as_ref() {
            // SAFETY: until a later resident attenuation owner exists, this
            // dormant detached capability remains process-terminal on drop.
            unsafe {
                let _ = TerminateProcess(
                    windows_handle(process.as_handle()),
                    DESKTOP_PROCESS_TERMINATION_EXIT_CODE,
                );
            }
        }
    }
}

/// Private post-debugger-exit owner of the exact process and thread handles.
pub(super) struct PendingDebuggerExitProcessCleanup {
    process: Option<OwnedHandle>,
    primary_thread: Option<OwnedHandle>,
    termination_requested: bool,
    must_wait_and_close: bool,
    _not_sync: PhantomData<Cell<()>>,
}

impl PendingDebuggerExitProcessCleanup {
    pub(super) fn process_handle(&self) -> BorrowedHandle<'_> {
        match self.process.as_ref() {
            Some(process) => process.as_handle(),
            None => fail_fast(),
        }
    }

    pub(super) fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
        match self.primary_thread.as_ref() {
            Some(thread) => thread.as_handle(),
            None => fail_fast(),
        }
    }

    pub(super) fn wait_and_close(mut self) -> Result<(), NativeDesktopProcessCleanupError> {
        let Some(process) = self.process.as_ref() else {
            fail_fast();
        };
        // SAFETY: the debugger thread has been joined by the caller and this
        // owner retains SYNCHRONIZE access on the exact process handle.
        let wait_succeeded = unsafe {
            WaitForSingleObject(
                windows_handle(process.as_handle()),
                DESKTOP_PROCESS_CLEANUP_WAIT_MILLISECONDS,
            )
        } == WAIT_OBJECT_0;
        let termination_requested = self.termination_requested;
        self.must_wait_and_close = false;
        drop(self.primary_thread.take());
        drop(self.process.take());
        match (termination_requested, wait_succeeded) {
            (true, true) => Ok(()),
            (false, true) => Err(NativeDesktopProcessCleanupError::TerminationRequest),
            (true, false) => Err(NativeDesktopProcessCleanupError::Wait),
            (false, false) => Err(NativeDesktopProcessCleanupError::TerminationRequestAndWait),
        }
    }
}

impl fmt::Debug for PendingDebuggerExitProcessCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingDebuggerExitProcessCleanup([REDACTED])")
    }
}

impl Drop for PendingDebuggerExitProcessCleanup {
    fn drop(&mut self) {
        if self.must_wait_and_close {
            fail_fast();
        }
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

    fn require_process_dup_handle_denied(
        &self,
        process_id: NonZeroU32,
    ) -> Result<(), DesktopProcessAccessError> {
        require_process_dup_handle_denied(process_id)
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

fn require_process_dup_handle_denied(
    process_id: NonZeroU32,
) -> Result<(), DesktopProcessAccessError> {
    // SAFETY: the nonzero PID names the still-suspended creator-owned child.
    // Inheritance is disabled and the desired mask is exactly one process bit.
    match unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, process_id.get()) } {
        Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => Ok(()),
        Err(_) => Err(DesktopProcessAccessError::Incomplete),
        Ok(handle) => {
            UnexpectedProcessAccess::new(handle)?.close_checked()?;
            Err(DesktopProcessAccessError::AccessAllowed)
        }
    }
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

/// Calls the sole `CreateProcessAsUserW` boundary for an authenticated desktop
/// primary token and immediately adopts every successful returned object.
///
/// # Safety
///
/// `startup_info` must be the prefix of the live extended startup allocation
/// described by the facade method. Every nested pointer must remain valid and
/// immutable for this synchronous call.
pub(super) unsafe fn create_process_as_desktop_user(
    token: &DesktopPrimaryToken,
    application_name: &[u16],
    security: ProcessThreadCreationSecurity<'_>,
    environment: &[u16],
    current_directory: &[u16],
    startup_info: *const STARTUPINFOW,
) -> Result<CreatedDesktopProcess, NativeDesktopProcessCreateError> {
    let (process_attributes, thread_attributes) = security.as_pair();
    if !application_name_is_exact(application_name)
        || !creation_attributes_are_exact(process_attributes, thread_attributes)
        || !environment_is_exact(environment)
        || !current_directory_is_exact(current_directory)
        // SAFETY: this function's caller upholds the complete live extended
        // startup allocation contract while validation reads its fixed prefix.
        || !unsafe { startup_info_is_exact(startup_info) }
    {
        return Err(NativeDesktopProcessCreateError::InvalidInput);
    }
    // SAFETY: this scalar query has no preconditions and binds the resulting
    // owner to the exact process-creation/debugger thread.
    let creator_thread_id = NonZeroU32::new(unsafe { GetCurrentThreadId() })
        .ok_or(NativeDesktopProcessCreateError::Authentication)?;
    match thread_token_state() {
        Ok(ThreadTokenState::Clear) => {}
        Ok(ThreadTokenState::Present) | Err(_) => {
            return Err(NativeDesktopProcessCreateError::Authentication);
        }
    }
    validate_desktop_primary_token_handle(token)
        .map_err(|_| NativeDesktopProcessCreateError::Authentication)?;

    let mut output = ProcessInformationOutput::new();
    // SAFETY: every borrowed pointer was validated above and remains live for
    // this synchronous call. The command line is absent, inheritance is false,
    // both security attributes are mandatory and non-inheritable, and creation
    // flags are the fixed five-value policy. `output` provides writable native
    // storage whose bytes are ignored unless Windows reports success.
    let result = unsafe {
        CreateProcessAsUserW(
            Some(token.raw()),
            PCWSTR(application_name.as_ptr()),
            None,
            Some(ptr::from_ref(process_attributes)),
            Some(ptr::from_ref(thread_attributes)),
            false,
            DESKTOP_PROCESS_CREATION_FLAGS,
            Some(environment.as_ptr().cast::<c_void>()),
            PCWSTR(current_directory.as_ptr()),
            startup_info,
            output.as_mut_ptr(),
        )
    };
    if result.is_err() {
        return Err(NativeDesktopProcessCreateError::OperatingSystem);
    }
    output.arm_success();
    Ok(output.adopt_success(creator_thread_id))
}

struct ProcessInformationOutput {
    raw: MaybeUninit<PROCESS_INFORMATION>,
    successful: bool,
}

impl ProcessInformationOutput {
    const fn new() -> Self {
        Self {
            raw: MaybeUninit::uninit(),
            successful: false,
        }
    }

    const fn as_mut_ptr(&mut self) -> *mut PROCESS_INFORMATION {
        self.raw.as_mut_ptr()
    }

    const fn arm_success(&mut self) {
        self.successful = true;
    }

    fn adopt_success(mut self, creator_thread_id: NonZeroU32) -> CreatedDesktopProcess {
        // SAFETY: only the native success branch arms this output, and the API's
        // success contract initializes the complete PROCESS_INFORMATION value.
        let information = unsafe { self.raw.assume_init_ref() };
        if !created_process_information_is_exact(information) {
            terminate_safely_unique_malformed_process(information);
            fail_fast();
        }
        // SAFETY: the same armed native-success contract initializes the value;
        // validation above proved that both handles are live, distinct, exact,
        // non-inheritable creator-owned handles.
        let information = unsafe { self.raw.assume_init_read() };
        self.successful = false;
        // SAFETY: each validated native handle is non-null, non-pseudo, distinct,
        // and transferred exactly once out of PROCESS_INFORMATION here.
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
        // SAFETY: the primary-thread handle passed the same exact validation and
        // is distinct from the process handle transferred immediately above.
        let primary_thread = unsafe { OwnedHandle::from_raw_handle(information.hThread.0) };
        CreatedDesktopProcess {
            process: Some(process),
            primary_thread: Some(primary_thread),
            process_id: NonZeroU32::new(information.dwProcessId).unwrap_or_else(|| fail_fast()),
            primary_thread_id: NonZeroU32::new(information.dwThreadId)
                .unwrap_or_else(|| fail_fast()),
            creator_thread_id,
            must_transition: true,
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for ProcessInformationOutput {
    fn drop(&mut self) {
        if !self.successful {
            // Native failure deliberately observes none of the output bytes.
            return;
        }
        // SAFETY: only a successful native return arms this guard, which makes
        // the complete output initialized under the API contract.
        let information = unsafe { self.raw.assume_init_ref() };
        terminate_safely_unique_malformed_process(information);
        fail_fast();
    }
}

fn created_process_information_is_exact(information: &PROCESS_INFORMATION) -> bool {
    let Some(process_id) = NonZeroU32::new(information.dwProcessId) else {
        return false;
    };
    let Some(thread_id) = NonZeroU32::new(information.dwThreadId) else {
        return false;
    };
    if invalid_handle(information.hProcess)
        || invalid_handle(information.hThread)
        || information.hProcess == information.hThread
        || !handle_flags_are_zero(information.hProcess)
        || !handle_flags_are_zero(information.hThread)
    {
        return false;
    }
    // SAFETY: both handles passed exact validity and handle-flag observations;
    // the successful creation contract grants the required query/synchronize
    // rights on these creator-owned process and primary-thread handles.
    unsafe {
        GetProcessId(information.hProcess) == process_id.get()
            && GetThreadId(information.hThread) == thread_id.get()
            && GetProcessIdOfThread(information.hThread) == process_id.get()
            && WaitForSingleObject(information.hProcess, 0) == WAIT_TIMEOUT
            && WaitForSingleObject(information.hThread, 0) == WAIT_TIMEOUT
    }
}

fn terminate_safely_unique_malformed_process(information: &PROCESS_INFORMATION) {
    if invalid_handle(information.hProcess)
        || information.hProcess == information.hThread
        || information.dwProcessId == 0
    {
        return;
    }
    // SAFETY: the scalar query proves that this distinct live handle names the
    // exact process ID returned in the successful native output before the
    // best-effort termination request is issued. Fail-fast follows regardless.
    unsafe {
        if GetProcessId(information.hProcess) == information.dwProcessId {
            let _ = TerminateProcess(information.hProcess, DESKTOP_PROCESS_TERMINATION_EXIT_CODE);
        }
    }
}

fn handle_flags_are_zero(handle: HANDLE) -> bool {
    let mut flags = u32::MAX;
    // SAFETY: the successful native contract produced a creator-owned handle;
    // this exact scalar query either proves its flags or fails closed.
    unsafe { GetHandleInformation(handle, &raw mut flags) }.is_ok() && flags == 0
}

fn creation_attributes_are_exact(
    process: &SECURITY_ATTRIBUTES,
    thread: &SECURITY_ATTRIBUTES,
) -> bool {
    let expected_length = u32::try_from(size_of::<SECURITY_ATTRIBUTES>());
    expected_length.ok() == Some(process.nLength)
        && expected_length.ok() == Some(thread.nLength)
        && !process.lpSecurityDescriptor.is_null()
        && !thread.lpSecurityDescriptor.is_null()
        && process.lpSecurityDescriptor != thread.lpSecurityDescriptor
        && process.bInheritHandle.0 == 0
        && thread.bInheritHandle.0 == 0
        && !ptr::eq(process, thread)
}

fn application_name_is_exact(application_name: &[u16]) -> bool {
    if !absolute_drive_path_with_nul(application_name, true) {
        return false;
    }
    let path = &application_name[..application_name.len() - 1];
    let file_name = path.rsplit(|unit| *unit == u16::from(b'\\')).next();
    match file_name {
        Some(file_name) if file_name.len() >= 4 => {
            let extension = &file_name[file_name.len() - 4..];
            extension[0] == u16::from(b'.')
                && ascii_eq_ignore_case(extension[1], b'e')
                && ascii_eq_ignore_case(extension[2], b'x')
                && ascii_eq_ignore_case(extension[3], b'e')
        }
        Some(_) | None => false,
    }
}

fn current_directory_is_exact(current_directory: &[u16]) -> bool {
    absolute_drive_path_with_nul(current_directory, false)
}

fn absolute_drive_path_with_nul(value: &[u16], allow_extended: bool) -> bool {
    if value.len() < 5
        || value.len() > MAX_UNICODE_PROCESS_PARAMETER_UNITS
        || value.last() != Some(&0)
        || value[..value.len() - 1].contains(&0)
    {
        return false;
    }
    let path = &value[..value.len() - 1];
    absolute_drive_path(path, allow_extended)
}

fn absolute_drive_path(path: &[u16], allow_extended: bool) -> bool {
    let root_length = if allow_extended
        && path.len() >= 7
        && path[..4]
            == [
                u16::from(b'\\'),
                u16::from(b'\\'),
                u16::from(b'?'),
                u16::from(b'\\'),
            ]
        && ascii_alpha(path[4])
        && path[5] == u16::from(b':')
        && path[6] == u16::from(b'\\')
    {
        7
    } else if path.len() >= 3
        && ascii_alpha(path[0])
        && path[1] == u16::from(b':')
        && path[2] == u16::from(b'\\')
    {
        3
    } else {
        return false;
    };
    let remainder = &path[root_length..];
    !remainder.is_empty()
        && !remainder.contains(&u16::from(b'/'))
        && !remainder.contains(&u16::from(b':'))
        && remainder
            .split(|unit| *unit == u16::from(b'\\'))
            .all(|segment| {
                !segment.is_empty()
                    && segment != [u16::from(b'.')]
                    && segment != [u16::from(b'.'), u16::from(b'.')]
            })
}

fn environment_is_exact(environment: &[u16]) -> bool {
    if environment.len() > MAX_UNICODE_PROCESS_PARAMETER_UNITS || !environment.ends_with(&[0, 0]) {
        return false;
    }
    let mut entries = environment[..environment.len() - 1].split(|unit| *unit == 0);
    let (Some(local_app_data), Some(system_root), Some(windir), Some(final_empty)) = (
        entries.next(),
        entries.next(),
        entries.next(),
        entries.next(),
    ) else {
        return false;
    };
    if entries.next().is_some() || !final_empty.is_empty() {
        return false;
    }
    let Some(local_value) = local_app_data.strip_prefix(&LOCAL_APP_DATA_PREFIX) else {
        return false;
    };
    let Some(system_root_value) = system_root.strip_prefix(&SYSTEM_ROOT_PREFIX) else {
        return false;
    };
    let Some(windir_value) = windir.strip_prefix(&WINDIR_PREFIX) else {
        return false;
    };
    !local_value.is_empty()
        && !system_root_value.is_empty()
        && system_root_value == windir_value
        && absolute_drive_path(local_value, false)
        && absolute_drive_path(system_root_value, false)
}

unsafe fn startup_info_is_exact(startup_info: *const STARTUPINFOW) -> bool {
    if startup_info.is_null()
        || !(startup_info as usize).is_multiple_of(align_of::<STARTUPINFOEXW>())
    {
        return false;
    }
    // SAFETY: the caller guarantees that this aligned pointer is the live
    // STARTUPINFOW prefix of a complete STARTUPINFOEXW allocation.
    let startup = unsafe { &*startup_info.cast::<STARTUPINFOEXW>() };
    let info = &startup.StartupInfo;
    if info.lpDesktop.0.is_null() || !(info.lpDesktop.0 as usize).is_multiple_of(align_of::<u16>())
    {
        return false;
    }
    // SAFETY: the caller keeps the live desktop backing allocation valid; the
    // exact expected desktop including its NUL occupies these fixed 16 units.
    let desktop = unsafe {
        core::slice::from_raw_parts(info.lpDesktop.0.cast_const(), DESKTOP_NAME_WIDE.len())
    };
    u32::try_from(size_of::<STARTUPINFOEXW>()).ok() == Some(info.cb)
        && desktop == DESKTOP_NAME_WIDE
        && !startup.lpAttributeList.0.is_null()
        && info.lpReserved.0.is_null()
        && info.lpTitle.0.is_null()
        && info.dwX == 0
        && info.dwY == 0
        && info.dwXSize == 0
        && info.dwYSize == 0
        && info.dwXCountChars == 0
        && info.dwYCountChars == 0
        && info.dwFillAttribute == 0
        && info.dwFlags.0 == 0
        && info.wShowWindow == 0
        && info.cbReserved2 == 0
        && info.lpReserved2.is_null()
        && info.hStdInput.0.is_null()
        && info.hStdOutput.0.is_null()
        && info.hStdError.0.is_null()
}

const fn ascii_alpha(unit: u16) -> bool {
    (unit >= 65 && unit <= 90) || (unit >= 97 && unit <= 122)
}

const fn ascii_eq_ignore_case(unit: u16, expected_lower: u8) -> bool {
    unit == expected_lower as u16 || unit == (expected_lower - (b'a' - b'A')) as u16
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

/// Observes a lifetime-bound created-child token without exposing or retaining
/// its raw handle outside this Windows adapter.
pub(super) fn desktop_child_token_observation(
    token: BorrowedHandle<'_>,
) -> Result<TokenObservation, ObservationError> {
    token_observation(windows_handle(token))
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
    let debug_privilege = token_debug_privilege_state(token)?;
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
        debug_privilege,
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

fn token_debug_privilege_state(token: HANDLE) -> Result<DebugPrivilegeState, ObservationError> {
    let privilege_name: Vec<u16> = "SeDebugPrivilege"
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    let mut debug_luid = LUID::default();
    // SAFETY: the fixed privilege name is NUL terminated and the output is one
    // initialized LUID. A null system name selects the local system.
    unsafe {
        LookupPrivilegeValueW(
            PCWSTR::null(),
            PCWSTR(privilege_name.as_ptr()),
            &raw mut debug_luid,
        )
    }
    .map_err(|_| ObservationError::Incomplete)?;

    let minimum_bytes = offset_of!(TOKEN_PRIVILEGES, Privileges).max(size_of::<u32>());
    let information = token_information(token, TokenPrivileges, minimum_bytes)?;
    debug_privilege_state_from_bytes(information.initialized_bytes(), debug_luid)
}

fn debug_privilege_state_from_bytes(
    bytes: &[u8],
    debug_luid: LUID,
) -> Result<DebugPrivilegeState, ObservationError> {
    let entries_offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
    if bytes.len() < entries_offset.max(size_of::<u32>()) {
        return Err(ObservationError::Incomplete);
    }
    let count = usize::try_from(u32::from_ne_bytes(
        bytes[..size_of::<u32>()]
            .try_into()
            .map_err(|_| ObservationError::Incomplete)?,
    ))
    .map_err(|_| ObservationError::Incomplete)?;
    let expected_bytes = count
        .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|bytes| entries_offset.checked_add(bytes))
        .ok_or(ObservationError::Incomplete)?;
    if expected_bytes != bytes.len() {
        return Err(ObservationError::Incomplete);
    }

    let known_attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT.0
        | SE_PRIVILEGE_ENABLED.0
        | SE_PRIVILEGE_REMOVED.0
        | SE_PRIVILEGE_USED_FOR_ACCESS.0;
    let mut debug_privilege = DebugPrivilegeState::Absent;
    for index in 0..count {
        let offset = index
            .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
            .and_then(|bytes| entries_offset.checked_add(bytes))
            .ok_or(ObservationError::Incomplete)?;
        // SAFETY: exact flexible-array length and total returned extent were
        // checked above; unaligned read avoids assuming entry alignment.
        let entry = unsafe {
            ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<LUID_AND_ATTRIBUTES>())
        };
        if entry.Attributes.0 & !known_attributes != 0 {
            return Err(ObservationError::Incomplete);
        }
        if entry.Luid == debug_luid {
            if debug_privilege != DebugPrivilegeState::Absent {
                return Err(ObservationError::Incomplete);
            }
            debug_privilege = if entry.Attributes.0 & SE_PRIVILEGE_ENABLED.0 == 0 {
                DebugPrivilegeState::PresentDisabled
            } else {
                DebugPrivilegeState::PresentEnabled
            };
        }
    }
    Ok(debug_privilege)
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

fn windows_handle(handle: BorrowedHandle<'_>) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.0.is_null() || handle == INVALID_HANDLE_VALUE || handle.is_invalid()
}

#[cfg(test)]
mod tests {
    use super::{
        DESKTOP_NAME_WIDE, DESKTOP_PRIMARY_TOKEN_ACCESS, DESKTOP_PROCESS_CREATION_FLAGS,
        DebugPrivilegeState, DesktopPrimaryToken, MANDATORY_LABEL_AUTHORITY,
        NativeDesktopProcessCleanupError, NativeDesktopProcessCreateError, OwnedToken,
        PendingDebuggerExitProcessCleanup, PendingDebuggerExitProcessSuccess,
        PreparedDebuggerExitProcessSuccess, SidBytes, TokenLevel, application_name_is_exact,
        classify_impersonation_level, creation_attributes_are_exact, current_directory_is_exact,
        debug_privilege_state_from_bytes, environment_is_exact, exact_boolean, integrity_rid,
        parse_token_has_restrictions, startup_info_is_exact, token_groups_bytes,
    };
    use core::ffi::c_void;
    use core::mem::{offset_of, size_of};
    use core::ptr;
    use std::marker::PhantomData;
    use windows::Win32::Foundation::{HANDLE, LUID};
    use windows::Win32::Security::{
        LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
        SECURITY_ATTRIBUTES, SecurityAnonymous, SecurityDelegation, SecurityIdentification,
        SecurityImpersonation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_DUP_HANDLE,
        STARTUPINFOEXW,
    };
    use windows::core::{BOOL, PWSTR};

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

    #[test]
    fn desktop_primary_token_is_move_only_send_and_not_sync() {
        assert_send::<DesktopPrimaryToken>();
        let _ = <DesktopPrimaryToken as AmbiguousIfSync<_>>::marker;
        let _ = <DesktopPrimaryToken as AmbiguousIfClone<_>>::marker;
        let _ = <DesktopPrimaryToken as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn desktop_process_native_owners_have_exact_thread_traits() {
        let _ = <super::CreatedDesktopProcess as AmbiguousIfSend<_>>::marker;
        let _ = <super::CreatedDesktopProcess as AmbiguousIfSync<_>>::marker;
        let _ = <super::CreatedDesktopProcess as AmbiguousIfClone<_>>::marker;
        let _ = <super::CreatedDesktopProcess as AmbiguousIfCopy<_>>::marker;
        assert_send::<PendingDebuggerExitProcessCleanup>();
        let _ = <PendingDebuggerExitProcessCleanup as AmbiguousIfSync<_>>::marker;
        let _ = <PendingDebuggerExitProcessCleanup as AmbiguousIfClone<_>>::marker;
        let _ = <PendingDebuggerExitProcessCleanup as AmbiguousIfCopy<_>>::marker;

        let _ = <PreparedDebuggerExitProcessSuccess as AmbiguousIfSend<_>>::marker;
        let _ = <PreparedDebuggerExitProcessSuccess as AmbiguousIfSync<_>>::marker;
        let _ = <PreparedDebuggerExitProcessSuccess as AmbiguousIfClone<_>>::marker;
        let _ = <PreparedDebuggerExitProcessSuccess as AmbiguousIfCopy<_>>::marker;

        assert_send::<PendingDebuggerExitProcessSuccess>();
        let _ = <PendingDebuggerExitProcessSuccess as AmbiguousIfSync<_>>::marker;
        let _ = <PendingDebuggerExitProcessSuccess as AmbiguousIfClone<_>>::marker;
        let _ = <PendingDebuggerExitProcessSuccess as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn desktop_process_creation_flags_are_the_exact_five_values() {
        assert_eq!(
            DESKTOP_PROCESS_CREATION_FLAGS.0,
            CREATE_SUSPENDED.0
                | DEBUG_ONLY_THIS_PROCESS.0
                | CREATE_NO_WINDOW.0
                | CREATE_UNICODE_ENVIRONMENT.0
                | EXTENDED_STARTUPINFO_PRESENT.0
        );
    }

    #[test]
    fn desktop_reopen_probe_requests_exactly_process_dup_handle() {
        assert_eq!(PROCESS_DUP_HANDLE.0, 0x0000_0040);
        assert_eq!(PROCESS_DUP_HANDLE.0.count_ones(), 1);
    }

    #[test]
    fn debug_privilege_parser_distinguishes_presence_and_rejects_ambiguous_bytes() {
        let debug = LUID {
            LowPart: 7,
            HighPart: 11,
        };
        let other = LUID {
            LowPart: 13,
            HighPart: 17,
        };
        let bytes = |entries: &[(LUID, u32)]| {
            assert_eq!(offset_of!(TOKEN_PRIVILEGES, Privileges), size_of::<u32>());
            assert_eq!(size_of::<LUID_AND_ATTRIBUTES>(), 12);
            let mut bytes = Vec::with_capacity(size_of::<u32>() + entries.len() * 12);
            bytes.extend_from_slice(
                &u32::try_from(entries.len())
                    .unwrap_or(u32::MAX)
                    .to_ne_bytes(),
            );
            for (luid, attributes) in entries {
                bytes.extend_from_slice(&luid.LowPart.to_ne_bytes());
                bytes.extend_from_slice(&luid.HighPart.to_ne_bytes());
                bytes.extend_from_slice(&attributes.to_ne_bytes());
            }
            bytes
        };

        assert_eq!(
            debug_privilege_state_from_bytes(&bytes(&[]), debug),
            Ok(DebugPrivilegeState::Absent)
        );
        assert_eq!(
            debug_privilege_state_from_bytes(&bytes(&[(other, SE_PRIVILEGE_ENABLED.0)]), debug),
            Ok(DebugPrivilegeState::Absent)
        );
        assert_eq!(
            debug_privilege_state_from_bytes(&bytes(&[(debug, 0)]), debug),
            Ok(DebugPrivilegeState::PresentDisabled)
        );
        assert_eq!(
            debug_privilege_state_from_bytes(
                &bytes(&[(debug, SE_PRIVILEGE_ENABLED_BY_DEFAULT.0)]),
                debug,
            ),
            Ok(DebugPrivilegeState::PresentDisabled)
        );
        assert_eq!(
            debug_privilege_state_from_bytes(&bytes(&[(debug, SE_PRIVILEGE_ENABLED.0)]), debug,),
            Ok(DebugPrivilegeState::PresentEnabled)
        );
        assert_eq!(
            debug_privilege_state_from_bytes(&bytes(&[(debug, 0), (debug, 0)]), debug),
            Err(super::ObservationError::Incomplete)
        );
        assert_eq!(
            debug_privilege_state_from_bytes(&bytes(&[(other, 0x0000_0008)]), debug),
            Err(super::ObservationError::Incomplete)
        );
        assert_eq!(
            debug_privilege_state_from_bytes(&bytes(&[(debug, 0x0000_0008)]), debug),
            Err(super::ObservationError::Incomplete)
        );

        let exact = bytes(&[(debug, 0)]);
        for truncated_len in 0..exact.len() {
            assert_eq!(
                debug_privilege_state_from_bytes(&exact[..truncated_len], debug),
                Err(super::ObservationError::Incomplete),
                "truncated extent {truncated_len} must fail closed"
            );
        }
        for wrong_count in [0_u32, 2, u32::MAX] {
            let mut wrong_extent = exact.clone();
            wrong_extent[..size_of::<u32>()].copy_from_slice(&wrong_count.to_ne_bytes());
            assert_eq!(
                debug_privilege_state_from_bytes(&wrong_extent, debug),
                Err(super::ObservationError::Incomplete)
            );
        }
        let mut trailing = exact;
        trailing.push(0);
        assert_eq!(
            debug_privilege_state_from_bytes(&trailing, debug),
            Err(super::ObservationError::Incomplete)
        );
    }

    #[test]
    fn process_creation_paths_and_environment_require_exact_shapes() {
        let application = wide_nul(r"C:\Program Files\Your Wallet\approval.exe");
        let extended_application = wide_nul(r"\\?\C:\Program Files\Your Wallet\approval.exe");
        let current_directory = wide_nul(r"C:\Windows\System32");
        let environment = environment_block(
            r"C:\Profiles\target\AppData\Local\Packages\profile\AC",
            r"C:\Windows",
        );
        assert!(application_name_is_exact(&application));
        assert!(application_name_is_exact(&extended_application));
        assert!(current_directory_is_exact(&current_directory));
        assert!(environment_is_exact(&environment));

        assert!(!application_name_is_exact(&wide_nul(
            r"\\server\share\approval.exe"
        )));
        assert!(!application_name_is_exact(&wide_nul(r"C:\tool.bin")));
        assert!(!current_directory_is_exact(&wide_nul(
            r"\\?\C:\Windows\System32"
        )));
        let mut wrong_environment = environment.clone();
        wrong_environment[0] = u16::from(b'X');
        assert!(!environment_is_exact(&wrong_environment));
        let mut mismatched_roots = environment_block(
            r"C:\Profiles\target\AppData\Local\Packages\profile\AC",
            r"C:\Windows",
        );
        let windir_start = mismatched_roots
            .windows(7)
            .position(|units| units == super::WINDIR_PREFIX)
            .unwrap_or(0);
        if windir_start != 0 {
            let value_start = windir_start + super::WINDIR_PREFIX.len();
            mismatched_roots[value_start] = u16::from(b'D');
        }
        assert!(!environment_is_exact(&mismatched_roots));
    }

    #[test]
    fn paired_security_and_startup_prefix_require_exact_non_inheriting_shape() {
        let mut descriptors = [0_u8; 2];
        let length = u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0);
        let mut process = SECURITY_ATTRIBUTES {
            nLength: length,
            lpSecurityDescriptor: ptr::from_mut(&mut descriptors[0]).cast::<c_void>(),
            bInheritHandle: BOOL(0),
        };
        let thread = SECURITY_ATTRIBUTES {
            nLength: length,
            lpSecurityDescriptor: ptr::from_mut(&mut descriptors[1]).cast::<c_void>(),
            bInheritHandle: BOOL(0),
        };
        assert!(creation_attributes_are_exact(&process, &thread));
        process.bInheritHandle = BOOL(1);
        assert!(!creation_attributes_are_exact(&process, &thread));

        let mut desktop = DESKTOP_NAME_WIDE;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or(0);
        startup.StartupInfo.lpDesktop = PWSTR(desktop.as_mut_ptr());
        startup.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(ptr::dangling_mut::<c_void>());
        // SAFETY: the live local extended startup value and desktop backing stay
        // valid for the complete validator call.
        assert!(unsafe { startup_info_is_exact(ptr::from_ref(&startup.StartupInfo)) });
        startup.StartupInfo.hStdInput = HANDLE(ptr::dangling_mut::<c_void>());
        // SAFETY: the same live local allocations remain valid after mutation.
        assert!(!unsafe { startup_info_is_exact(ptr::from_ref(&startup.StartupInfo)) });
    }

    #[test]
    fn process_creation_errors_are_data_free() {
        assert_eq!(
            format!("{:?}", NativeDesktopProcessCreateError::InvalidInput),
            "InvalidInput"
        );
        assert_eq!(
            format!(
                "{:?}",
                NativeDesktopProcessCleanupError::TerminationRequestAndWait
            ),
            "TerminationRequestAndWait"
        );
    }

    fn wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(core::iter::once(0)).collect()
    }

    fn environment_block(local_app_data: &str, windows_root: &str) -> Vec<u16> {
        let mut environment = Vec::new();
        for (name, value) in [
            ("LOCALAPPDATA=", local_app_data),
            ("SystemRoot=", windows_root),
            ("WINDIR=", windows_root),
        ] {
            environment.extend(name.encode_utf16());
            environment.extend(value.encode_utf16());
            environment.push(0);
        }
        environment.push(0);
        environment
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
