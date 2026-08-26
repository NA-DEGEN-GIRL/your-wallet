//! Process-wide coordination for Windows `AppContainer` profile APIs.
//!
//! Windows can transiently reject concurrent operations over `AppContainer`
//! profiles. Every profile creator in this crate uses this one short-lived
//! gate around only the native profile API calls.

#![allow(unsafe_code)]

use std::cell::Cell;
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Mutex, MutexGuard};

use windows::Win32::Foundation::{CloseHandle, ERROR_NO_TOKEN, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

static APP_CONTAINER_PROFILE_API: Mutex<()> = Mutex::new(());

thread_local! {
    static PROFILE_API_HELD_BY_THREAD: Cell<bool> = const { Cell::new(false) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AppContainerProfileApiCoordinationError {
    ThreadImpersonation,
    OperatingSystem,
    Reentrant,
    Poisoned,
}

/// Exclusive process-wide authority to call one Windows `AppContainer` profile
/// API sequence. It is deliberately non-cloneable and thread-bound.
#[must_use = "the AppContainer profile API authority must outlive every protected native call"]
pub(crate) struct AppContainerProfileApiGuard {
    _mutex: MutexGuard<'static, ()>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl AppContainerProfileApiGuard {
    /// Rechecks the calling thread immediately before or after a protected
    /// native profile API call.
    #[allow(clippy::unused_self)] // The receiver is the live non-cloneable call authority.
    pub(crate) fn recheck_thread(&self) -> Result<(), AppContainerProfileApiCoordinationError> {
        reject_thread_impersonation()
    }
}

pub(crate) fn acquire_appcontainer_profile_api()
-> Result<AppContainerProfileApiGuard, AppContainerProfileApiCoordinationError> {
    reject_thread_impersonation()?;
    if PROFILE_API_HELD_BY_THREAD
        .try_with(Cell::get)
        .map_err(|_| AppContainerProfileApiCoordinationError::Poisoned)?
    {
        return Err(AppContainerProfileApiCoordinationError::Reentrant);
    }
    let mutex = APP_CONTAINER_PROFILE_API
        .lock()
        .map_err(|_| AppContainerProfileApiCoordinationError::Poisoned)?;
    reject_thread_impersonation()?;
    let was_held = PROFILE_API_HELD_BY_THREAD
        .try_with(|held| held.replace(true))
        .map_err(|_| AppContainerProfileApiCoordinationError::Poisoned)?;
    debug_assert!(!was_held);
    Ok(AppContainerProfileApiGuard {
        _mutex: mutex,
        _thread_bound: PhantomData,
    })
}

/// Data-free failure categories for the target-user profile-API authority.
///
/// The exact desktop identity and token remain confined to the authenticated
/// RPC client and are never copied into an error or diagnostic value.
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetAppContainerProfileApiError {
    ThreadImpersonation,
    Coordination,
    Authentication,
    OperatingSystem,
}

/// Exclusive, thread-bound authority for profile calls made as the exact
/// authenticated desktop user.
///
/// The ordinary profile gate is retained until the authentication-owned lease
/// has reverted and proved its clean-thread postcondition. No desktop token or
/// independent revert authority is exposed by this capability.
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
#[must_use = "target-user impersonation must be finished before releasing the profile API gate"]
pub(crate) struct TargetAppContainerProfileApiGuard<'client> {
    state: TargetProfileApiState<
        crate::key_agent_service_rpc::AuthenticatedDesktopImpersonation<'client>,
        AppContainerProfileApiGuard,
    >,
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl fmt::Debug for TargetAppContainerProfileApiGuard<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetAppContainerProfileApiGuard([REDACTED])")
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl TargetAppContainerProfileApiGuard<'_> {
    /// Rechecks the originating thread and exact authenticated desktop
    /// identity immediately before or after a protected profile operation.
    pub(crate) fn recheck_target(&self) -> Result<(), TargetAppContainerProfileApiError> {
        self.state.recheck_target()
    }

    /// Reverts exactly once, proves that the thread has no residual token, and
    /// then revalidates the retained desktop client proof.
    pub(crate) fn finish(self) -> Result<(), TargetAppContainerProfileApiError> {
        self.state.finish()
    }
}

/// Acquires the existing process-wide profile gate and impersonates the exact
/// desktop identity retained by `client` for the shortest profile-call scope.
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
pub(crate) fn acquire_target_appcontainer_profile_api(
    client: &crate::key_agent_service_rpc::AuthenticatedRpcClient,
) -> Result<TargetAppContainerProfileApiGuard<'_>, TargetAppContainerProfileApiError> {
    let ops = WindowsTargetProfileOps { client };
    acquire_target_profile_api_with(&ops).map(|state| TargetAppContainerProfileApiGuard { state })
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetThreadTokenState {
    Clear,
    Present,
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
trait TargetProfileApiOps {
    type ProfileGuard;
    type Impersonation: TargetProfileImpersonation;

    fn thread_token_state(
        &self,
    ) -> Result<TargetThreadTokenState, TargetAppContainerProfileApiError>;

    fn acquire_profile_api(&self) -> Result<Self::ProfileGuard, TargetAppContainerProfileApiError>;

    fn revalidate_client(&self) -> Result<(), TargetAppContainerProfileApiError>;

    fn begin_impersonation(&self)
    -> Result<Self::Impersonation, TargetAppContainerProfileApiError>;
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
trait TargetProfileImpersonation {
    fn recheck(&self) -> Result<(), TargetAppContainerProfileApiError>;

    fn finish(self) -> Result<(), TargetAppContainerProfileApiError>;
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
struct WindowsTargetProfileOps<'client> {
    client: &'client crate::key_agent_service_rpc::AuthenticatedRpcClient,
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl<'client> TargetProfileApiOps for WindowsTargetProfileOps<'client> {
    type ProfileGuard = AppContainerProfileApiGuard;
    type Impersonation = crate::key_agent_service_rpc::AuthenticatedDesktopImpersonation<'client>;

    fn thread_token_state(
        &self,
    ) -> Result<TargetThreadTokenState, TargetAppContainerProfileApiError> {
        current_thread_token_state()
    }

    fn acquire_profile_api(&self) -> Result<Self::ProfileGuard, TargetAppContainerProfileApiError> {
        acquire_appcontainer_profile_api()
            .map_err(|_| TargetAppContainerProfileApiError::Coordination)
    }

    fn revalidate_client(&self) -> Result<(), TargetAppContainerProfileApiError> {
        self.client
            .revalidate()
            .map_err(|_| TargetAppContainerProfileApiError::Authentication)
    }

    fn begin_impersonation(
        &self,
    ) -> Result<Self::Impersonation, TargetAppContainerProfileApiError> {
        self.client
            .impersonate_desktop_user()
            .map_err(|_| TargetAppContainerProfileApiError::Authentication)
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl TargetProfileImpersonation
    for crate::key_agent_service_rpc::AuthenticatedDesktopImpersonation<'_>
{
    fn recheck(&self) -> Result<(), TargetAppContainerProfileApiError> {
        crate::key_agent_service_rpc::AuthenticatedDesktopImpersonation::recheck(self)
            .map_err(|_| TargetAppContainerProfileApiError::Authentication)
    }

    fn finish(self) -> Result<(), TargetAppContainerProfileApiError> {
        crate::key_agent_service_rpc::AuthenticatedDesktopImpersonation::finish(self)
            .map_err(|_| TargetAppContainerProfileApiError::Authentication)
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
fn current_thread_token_state() -> Result<TargetThreadTokenState, TargetAppContainerProfileApiError>
{
    let mut token = HANDLE::default();
    // SAFETY: the current pseudo-thread handle is valid; OpenAsSelf makes the
    // cleanliness probe independent of an existing token's access level.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) };
    match result {
        Ok(()) if token.is_invalid() || token == INVALID_HANDLE_VALUE => {
            Err(TargetAppContainerProfileApiError::OperatingSystem)
        }
        Ok(()) => {
            // SAFETY: successful OpenThreadToken returned one fresh owned
            // handle. The identity represented by it is never inspected or
            // exported from this cleanliness-only boundary.
            unsafe {
                let _ = CloseHandle(token);
            }
            Ok(TargetThreadTokenState::Present)
        }
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => {
            Ok(TargetThreadTokenState::Clear)
        }
        Err(_) => Err(TargetAppContainerProfileApiError::OperatingSystem),
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
fn require_clear_thread<O: TargetProfileApiOps>(
    ops: &O,
) -> Result<(), TargetAppContainerProfileApiError> {
    match ops.thread_token_state()? {
        TargetThreadTokenState::Clear => Ok(()),
        TargetThreadTokenState::Present => {
            Err(TargetAppContainerProfileApiError::ThreadImpersonation)
        }
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
fn acquire_target_profile_api_with<O: TargetProfileApiOps>(
    ops: &O,
) -> Result<
    TargetProfileApiState<O::Impersonation, O::ProfileGuard>,
    TargetAppContainerProfileApiError,
> {
    require_clear_thread(ops)?;
    let profile_api = ops.acquire_profile_api()?;
    require_clear_thread(ops)?;
    ops.revalidate_client()?;
    let impersonation = ops.begin_impersonation()?;
    impersonation.recheck()?;

    Ok(TargetProfileApiState {
        // The authentication-owned lease deliberately drops before the
        // process-wide profile guard on every implicit cleanup path.
        impersonation,
        profile_api,
    })
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
struct TargetProfileApiState<I: TargetProfileImpersonation, P> {
    impersonation: I,
    profile_api: P,
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl<I: TargetProfileImpersonation, P> TargetProfileApiState<I, P> {
    fn recheck_target(&self) -> Result<(), TargetAppContainerProfileApiError> {
        self.impersonation.recheck()
    }

    fn finish(self) -> Result<(), TargetAppContainerProfileApiError> {
        let Self {
            impersonation,
            profile_api,
        } = self;
        let result = impersonation.finish();
        // This explicit order is security-significant: another thread must not
        // enter profile APIs until the target token is completely removed.
        drop(profile_api);
        result
    }
}

fn reject_thread_impersonation() -> Result<(), AppContainerProfileApiCoordinationError> {
    let mut token = HANDLE::default();
    // SAFETY: the current pseudo-thread handle is valid for this scalar query;
    // OpenAsSelf makes the query itself independent of impersonation level.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) };
    match result {
        Ok(()) if token.is_invalid() || token == INVALID_HANDLE_VALUE => {
            Err(AppContainerProfileApiCoordinationError::OperatingSystem)
        }
        Ok(()) => {
            // SAFETY: successful OpenThreadToken returned one fresh owned handle.
            unsafe {
                let _ = CloseHandle(token);
            }
            Err(AppContainerProfileApiCoordinationError::ThreadImpersonation)
        }
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(()),
        Err(_) => Err(AppContainerProfileApiCoordinationError::OperatingSystem),
    }
}

impl Drop for AppContainerProfileApiGuard {
    fn drop(&mut self) {
        // A guard cannot legitimately outlive this thread's TLS. If teardown
        // ordering nevertheless makes the key unavailable, release the native
        // mutex without a second panic; the terminating thread cannot reenter.
        if let Ok(was_held) = PROFILE_API_HELD_BY_THREAD.try_with(|held| held.replace(false)) {
            debug_assert!(was_held);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppContainerProfileApiCoordinationError, AppContainerProfileApiGuard,
        acquire_appcontainer_profile_api,
    };
    use windows::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};

    struct RevertImpersonation;

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

    impl Drop for RevertImpersonation {
        fn drop(&mut self) {
            // SAFETY: this guard exists only after ImpersonateSelf succeeded.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }

    #[test]
    fn profile_api_guard_is_thread_bound_non_clone_and_non_copy() {
        let _ = <AppContainerProfileApiGuard as AmbiguousIfSend<_>>::marker;
        let _ = <AppContainerProfileApiGuard as AmbiguousIfSync<_>>::marker;
        let _ = <AppContainerProfileApiGuard as AmbiguousIfClone<_>>::marker;
        let _ = <AppContainerProfileApiGuard as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn same_thread_reentry_fails_closed_without_poisoning_gate()
    -> Result<(), AppContainerProfileApiCoordinationError> {
        let guard = acquire_appcontainer_profile_api()?;
        assert!(matches!(
            acquire_appcontainer_profile_api(),
            Err(AppContainerProfileApiCoordinationError::Reentrant)
        ));
        drop(guard);
        drop(acquire_appcontainer_profile_api()?);
        Ok(())
    }

    #[test]
    fn impersonating_thread_is_rejected_before_profile_gate() -> windows::core::Result<()> {
        // SAFETY: the test immediately installs an unwind-safe RevertToSelf guard.
        unsafe { ImpersonateSelf(SecurityImpersonation) }?;
        let _revert = RevertImpersonation;
        assert!(matches!(
            acquire_appcontainer_profile_api(),
            Err(AppContainerProfileApiCoordinationError::ThreadImpersonation)
        ));
        Ok(())
    }

    #[test]
    fn held_guard_rechecks_thread_impersonation_around_native_call()
    -> Result<(), AppContainerProfileApiCoordinationError> {
        let guard = acquire_appcontainer_profile_api()?;

        // SAFETY: the test immediately installs an unwind-safe RevertToSelf guard.
        unsafe { ImpersonateSelf(SecurityImpersonation) }
            .map_err(|_| AppContainerProfileApiCoordinationError::OperatingSystem)?;
        let revert = RevertImpersonation;

        assert!(matches!(
            guard.recheck_thread(),
            Err(AppContainerProfileApiCoordinationError::ThreadImpersonation)
        ));

        drop(revert);
        assert_eq!(guard.recheck_thread(), Ok(()));
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    mod target_user {
        use super::super::{
            TargetAppContainerProfileApiError, TargetAppContainerProfileApiGuard,
            TargetProfileApiOps, TargetProfileImpersonation, TargetThreadTokenState,
            acquire_target_profile_api_with,
        };
        use super::{AmbiguousIfClone, AmbiguousIfCopy, AmbiguousIfSend, AmbiguousIfSync};
        use std::cell::{Cell, RefCell};
        use std::fmt;
        use std::num::NonZeroU32;
        use std::panic::{AssertUnwindSafe, catch_unwind};
        use std::rc::Rc;

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Event {
            ThreadState,
            ProfileAcquire,
            ProfileDrop,
            ClientRevalidate,
            ThreadCookie,
            Impersonate,
            EffectiveTarget,
            Revert,
            FailFast,
        }

        struct FakeState {
            events: RefCell<Vec<Event>>,
            thread_state_calls: Cell<usize>,
            thread_state_error_at: Cell<Option<usize>>,
            thread_state_present_at: Cell<Option<usize>>,
            profile_ok: Cell<bool>,
            client_calls: Cell<usize>,
            client_error_at: Cell<Option<usize>>,
            cookie_calls: Cell<usize>,
            cookie_error_at: Cell<Option<usize>>,
            cookie_mismatch_at: Cell<Option<usize>>,
            impersonate_ok: Cell<bool>,
            effective_calls: Cell<usize>,
            effective_error_at: Cell<Option<usize>>,
            revert_ok: Cell<bool>,
        }

        impl Default for FakeState {
            fn default() -> Self {
                Self {
                    events: RefCell::new(Vec::new()),
                    thread_state_calls: Cell::new(0),
                    thread_state_error_at: Cell::new(None),
                    thread_state_present_at: Cell::new(None),
                    profile_ok: Cell::new(true),
                    client_calls: Cell::new(0),
                    client_error_at: Cell::new(None),
                    cookie_calls: Cell::new(0),
                    cookie_error_at: Cell::new(None),
                    cookie_mismatch_at: Cell::new(None),
                    impersonate_ok: Cell::new(true),
                    effective_calls: Cell::new(0),
                    effective_error_at: Cell::new(None),
                    revert_ok: Cell::new(true),
                }
            }
        }

        impl FakeState {
            fn record(&self, event: Event) {
                self.events.borrow_mut().push(event);
            }

            fn events(&self) -> Vec<Event> {
                self.events.borrow().clone()
            }

            fn event_count(&self, expected: Event) -> usize {
                self.events
                    .borrow()
                    .iter()
                    .filter(|event| **event == expected)
                    .count()
            }

            fn thread_token_state(
                &self,
            ) -> Result<TargetThreadTokenState, TargetAppContainerProfileApiError> {
                self.record(Event::ThreadState);
                let call = self.thread_state_calls.get() + 1;
                self.thread_state_calls.set(call);
                if self.thread_state_error_at.get() == Some(call) {
                    return Err(TargetAppContainerProfileApiError::OperatingSystem);
                }
                if self.thread_state_present_at.get() == Some(call) {
                    return Ok(TargetThreadTokenState::Present);
                }
                Ok(TargetThreadTokenState::Clear)
            }

            fn revalidate_client(&self) -> Result<(), TargetAppContainerProfileApiError> {
                self.record(Event::ClientRevalidate);
                let call = self.client_calls.get() + 1;
                self.client_calls.set(call);
                (self.client_error_at.get() != Some(call))
                    .then_some(())
                    .ok_or(TargetAppContainerProfileApiError::Authentication)
            }

            fn current_thread_cookie(
                &self,
            ) -> Result<NonZeroU32, TargetAppContainerProfileApiError> {
                self.record(Event::ThreadCookie);
                let call = self.cookie_calls.get() + 1;
                self.cookie_calls.set(call);
                if self.cookie_error_at.get() == Some(call) {
                    return Err(TargetAppContainerProfileApiError::OperatingSystem);
                }
                let raw = if self.cookie_mismatch_at.get() == Some(call) {
                    2
                } else {
                    1
                };
                NonZeroU32::new(raw).ok_or(TargetAppContainerProfileApiError::OperatingSystem)
            }

            fn revalidate_effective_target(&self) -> Result<(), TargetAppContainerProfileApiError> {
                self.record(Event::EffectiveTarget);
                let call = self.effective_calls.get() + 1;
                self.effective_calls.set(call);
                (self.effective_error_at.get() != Some(call))
                    .then_some(())
                    .ok_or(TargetAppContainerProfileApiError::Authentication)
            }

            fn revert(&self) -> Result<(), TargetAppContainerProfileApiError> {
                self.record(Event::Revert);
                self.revert_ok
                    .get()
                    .then_some(())
                    .ok_or(TargetAppContainerProfileApiError::OperatingSystem)
            }

            fn fail_fast(&self) -> ! {
                self.record(Event::FailFast);
                std::panic::resume_unwind(Box::new("target profile fail-fast sentinel"))
            }
        }

        struct FakeOps {
            state: Rc<FakeState>,
        }

        impl FakeOps {
            fn new() -> (Self, Rc<FakeState>) {
                let state = Rc::new(FakeState::default());
                (
                    Self {
                        state: Rc::clone(&state),
                    },
                    state,
                )
            }
        }

        struct FakeProfileGuard {
            state: Rc<FakeState>,
        }

        impl Drop for FakeProfileGuard {
            fn drop(&mut self) {
                self.state.record(Event::ProfileDrop);
            }
        }

        struct FakeImpersonation {
            state: Rc<FakeState>,
            thread_cookie: NonZeroU32,
            active: bool,
        }

        impl FakeImpersonation {
            fn revert_exact(&mut self) {
                if !self.active {
                    return;
                }
                self.active = false;
                let current = self.state.current_thread_cookie();
                let reverted = self.state.revert();
                let token_state = self.state.thread_token_state();
                if current != Ok(self.thread_cookie)
                    || reverted.is_err()
                    || token_state != Ok(TargetThreadTokenState::Clear)
                {
                    self.state.fail_fast();
                }
            }
        }

        impl TargetProfileImpersonation for FakeImpersonation {
            fn recheck(&self) -> Result<(), TargetAppContainerProfileApiError> {
                if self.state.current_thread_cookie() != Ok(self.thread_cookie) {
                    self.state.fail_fast();
                }
                self.state.revalidate_effective_target()
            }

            fn finish(mut self) -> Result<(), TargetAppContainerProfileApiError> {
                self.revert_exact();
                self.state.revalidate_client()
            }
        }

        impl Drop for FakeImpersonation {
            fn drop(&mut self) {
                self.revert_exact();
            }
        }

        impl TargetProfileApiOps for FakeOps {
            type ProfileGuard = FakeProfileGuard;
            type Impersonation = FakeImpersonation;

            fn thread_token_state(
                &self,
            ) -> Result<TargetThreadTokenState, TargetAppContainerProfileApiError> {
                self.state.thread_token_state()
            }

            fn acquire_profile_api(
                &self,
            ) -> Result<Self::ProfileGuard, TargetAppContainerProfileApiError> {
                self.state.record(Event::ProfileAcquire);
                self.state
                    .profile_ok
                    .get()
                    .then(|| FakeProfileGuard {
                        state: Rc::clone(&self.state),
                    })
                    .ok_or(TargetAppContainerProfileApiError::Coordination)
            }

            fn revalidate_client(&self) -> Result<(), TargetAppContainerProfileApiError> {
                self.state.revalidate_client()
            }

            fn begin_impersonation(
                &self,
            ) -> Result<Self::Impersonation, TargetAppContainerProfileApiError> {
                let thread_cookie = self.state.current_thread_cookie()?;
                self.state.record(Event::Impersonate);
                if !self.state.impersonate_ok.get() {
                    return Err(TargetAppContainerProfileApiError::OperatingSystem);
                }
                Ok(FakeImpersonation {
                    state: Rc::clone(&self.state),
                    thread_cookie,
                    active: true,
                })
            }
        }

        fn acquire_fake() -> (
            Result<
                super::super::TargetProfileApiState<FakeImpersonation, FakeProfileGuard>,
                TargetAppContainerProfileApiError,
            >,
            Rc<FakeState>,
        ) {
            let (ops, state) = FakeOps::new();
            (acquire_target_profile_api_with(&ops), state)
        }

        fn assert_debug<T: fmt::Debug>() {}

        fn assert_fail_fast(result: &std::thread::Result<()>, state: &FakeState) {
            assert!(result.is_err());
            assert_eq!(state.event_count(Event::FailFast), 1);
            assert_eq!(state.event_count(Event::Revert), 1);
            assert_eq!(state.event_count(Event::ProfileDrop), 1);
        }

        #[test]
        fn target_guard_is_thread_bound_non_clone_non_copy_and_redacted_debug() {
            let _ = <TargetAppContainerProfileApiGuard<'static> as AmbiguousIfSend<_>>::marker;
            let _ = <TargetAppContainerProfileApiGuard<'static> as AmbiguousIfSync<_>>::marker;
            let _ = <TargetAppContainerProfileApiGuard<'static> as AmbiguousIfClone<_>>::marker;
            let _ = <TargetAppContainerProfileApiGuard<'static> as AmbiguousIfCopy<_>>::marker;

            assert_debug::<TargetAppContainerProfileApiGuard<'static>>();
            assert_eq!(
                format!("{:?}", TargetAppContainerProfileApiError::Authentication),
                "Authentication"
            );
        }

        #[test]
        fn successful_finish_reverts_and_proves_clear_before_releasing_profile_gate()
        -> Result<(), TargetAppContainerProfileApiError> {
            let (guard, state) = acquire_fake();
            guard?.finish()?;
            assert_eq!(
                state.events(),
                vec![
                    Event::ThreadState,
                    Event::ProfileAcquire,
                    Event::ThreadState,
                    Event::ClientRevalidate,
                    Event::ThreadCookie,
                    Event::Impersonate,
                    Event::ThreadCookie,
                    Event::EffectiveTarget,
                    Event::ThreadCookie,
                    Event::Revert,
                    Event::ThreadState,
                    Event::ClientRevalidate,
                    Event::ProfileDrop,
                ]
            );
            Ok(())
        }

        #[test]
        fn drop_fallback_reverts_exactly_once_before_profile_gate_drop()
        -> Result<(), TargetAppContainerProfileApiError> {
            let (guard, state) = acquire_fake();
            drop(guard?);
            assert_eq!(state.event_count(Event::Revert), 1);
            assert_eq!(state.event_count(Event::ProfileDrop), 1);
            assert_eq!(
                state.events().as_slice(),
                &[
                    Event::ThreadState,
                    Event::ProfileAcquire,
                    Event::ThreadState,
                    Event::ClientRevalidate,
                    Event::ThreadCookie,
                    Event::Impersonate,
                    Event::ThreadCookie,
                    Event::EffectiveTarget,
                    Event::ThreadCookie,
                    Event::Revert,
                    Event::ThreadState,
                    Event::ProfileDrop,
                ]
            );
            Ok(())
        }

        #[test]
        fn profile_operation_error_still_cleans_up_in_security_order() {
            let (guard, state) = acquire_fake();
            let operation = (|| -> Result<(), TargetAppContainerProfileApiError> {
                let _guard = guard?;
                Err(TargetAppContainerProfileApiError::OperatingSystem)
            })();
            assert_eq!(
                operation,
                Err(TargetAppContainerProfileApiError::OperatingSystem)
            );
            let events = state.events();
            let revert = events.iter().position(|event| *event == Event::Revert);
            let profile_drop = events.iter().position(|event| *event == Event::ProfileDrop);
            assert!(revert < profile_drop);
            assert_eq!(state.event_count(Event::Revert), 1);
        }

        #[test]
        fn every_pre_impersonation_failure_stops_at_the_exact_boundary() {
            let (ops, state) = FakeOps::new();
            state.thread_state_present_at.set(Some(1));
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::ThreadImpersonation)
            ));
            assert_eq!(state.events(), vec![Event::ThreadState]);

            let (ops, state) = FakeOps::new();
            state.thread_state_error_at.set(Some(1));
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::OperatingSystem)
            ));
            assert_eq!(state.events(), vec![Event::ThreadState]);

            let (ops, state) = FakeOps::new();
            state.profile_ok.set(false);
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::Coordination)
            ));
            assert_eq!(
                state.events(),
                vec![Event::ThreadState, Event::ProfileAcquire]
            );

            let (ops, state) = FakeOps::new();
            state.thread_state_present_at.set(Some(2));
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::ThreadImpersonation)
            ));
            assert_eq!(
                state.events(),
                vec![
                    Event::ThreadState,
                    Event::ProfileAcquire,
                    Event::ThreadState,
                    Event::ProfileDrop,
                ]
            );

            let (ops, state) = FakeOps::new();
            state.thread_state_error_at.set(Some(2));
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::OperatingSystem)
            ));
            assert_eq!(
                state.events(),
                vec![
                    Event::ThreadState,
                    Event::ProfileAcquire,
                    Event::ThreadState,
                    Event::ProfileDrop,
                ]
            );

            let (ops, state) = FakeOps::new();
            state.client_error_at.set(Some(1));
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::Authentication)
            ));
            assert_eq!(
                state.events(),
                vec![
                    Event::ThreadState,
                    Event::ProfileAcquire,
                    Event::ThreadState,
                    Event::ClientRevalidate,
                    Event::ProfileDrop,
                ]
            );

            let (ops, state) = FakeOps::new();
            state.cookie_error_at.set(Some(1));
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::OperatingSystem)
            ));
            assert_eq!(
                state.events(),
                vec![
                    Event::ThreadState,
                    Event::ProfileAcquire,
                    Event::ThreadState,
                    Event::ClientRevalidate,
                    Event::ThreadCookie,
                    Event::ProfileDrop,
                ]
            );

            let (ops, state) = FakeOps::new();
            state.impersonate_ok.set(false);
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::OperatingSystem)
            ));
            assert_eq!(state.event_count(Event::Revert), 0);
            assert_eq!(state.event_count(Event::ProfileDrop), 1);
        }

        #[test]
        fn acquisition_thread_change_after_impersonation_fails_fast_then_cleans_up_once() {
            let (ops, state) = FakeOps::new();
            state.cookie_mismatch_at.set(Some(2));
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = acquire_target_profile_api_with(&ops);
            }));
            assert_fail_fast(&result, &state);
        }

        #[test]
        fn post_impersonation_auth_failure_reverts_before_returning_error() {
            let (ops, state) = FakeOps::new();
            state.effective_error_at.set(Some(1));
            assert!(matches!(
                acquire_target_profile_api_with(&ops),
                Err(TargetAppContainerProfileApiError::Authentication)
            ));
            assert_eq!(state.event_count(Event::Revert), 1);
            assert_eq!(state.event_count(Event::ProfileDrop), 1);
            let events = state.events();
            assert!(
                events.iter().position(|event| *event == Event::Revert)
                    < events.iter().position(|event| *event == Event::ProfileDrop)
            );
        }

        #[test]
        fn active_effective_identity_error_is_returned_before_drop_cleanup()
        -> Result<(), TargetAppContainerProfileApiError> {
            let (guard, state) = acquire_fake();
            let guard = guard?;
            state.effective_error_at.set(Some(2));
            assert_eq!(
                guard.recheck_target(),
                Err(TargetAppContainerProfileApiError::Authentication)
            );
            assert_eq!(state.event_count(Event::Revert), 0);
            drop(guard);
            assert_eq!(state.event_count(Event::Revert), 1);
            assert_eq!(state.event_count(Event::ProfileDrop), 1);
            Ok(())
        }

        #[test]
        fn explicit_finish_revalidates_client_after_cleanup_and_returns_auth_error()
        -> Result<(), TargetAppContainerProfileApiError> {
            let (guard, state) = acquire_fake();
            state.client_error_at.set(Some(2));
            assert_eq!(
                guard?.finish(),
                Err(TargetAppContainerProfileApiError::Authentication)
            );
            assert_eq!(state.event_count(Event::Revert), 1);
            let events = state.events();
            assert!(
                events.iter().position(|event| *event == Event::Revert)
                    < events
                        .iter()
                        .rposition(|event| *event == Event::ClientRevalidate)
            );
            assert_eq!(events.last(), Some(&Event::ProfileDrop));
            Ok(())
        }

        #[test]
        fn active_recheck_thread_change_enters_fail_fast_seam() {
            let (guard, state) = acquire_fake();
            let guard = match guard {
                Ok(guard) => guard,
                Err(error) => std::panic::resume_unwind(Box::new(error)),
            };
            state.cookie_mismatch_at.set(Some(3));
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = guard.recheck_target();
            }));
            assert!(result.is_err());
            assert_eq!(state.event_count(Event::FailFast), 1);

            // The fake fail-fast seam unwinds, unlike production. Restore the
            // observation so dropping the still-active guard can cleanly prove
            // exact-once revert without a second sentinel.
            state.cookie_mismatch_at.set(None);
            drop(guard);
            assert_eq!(state.event_count(Event::Revert), 1);
        }

        #[test]
        fn finish_thread_revert_and_residual_anomalies_all_fail_fast_after_one_revert() {
            for configure in [
                |state: &FakeState| state.cookie_mismatch_at.set(Some(3)),
                |state: &FakeState| state.cookie_error_at.set(Some(3)),
                |state: &FakeState| state.revert_ok.set(false),
                |state: &FakeState| state.thread_state_present_at.set(Some(3)),
                |state: &FakeState| state.thread_state_error_at.set(Some(3)),
            ] {
                let (guard, state) = acquire_fake();
                let guard = match guard {
                    Ok(guard) => guard,
                    Err(error) => std::panic::resume_unwind(Box::new(error)),
                };
                configure(&state);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let _ = guard.finish();
                }));
                assert_fail_fast(&result, &state);
            }
        }

        #[test]
        fn drop_revert_failure_uses_the_same_exact_once_fail_fast_seam() {
            let (guard, state) = acquire_fake();
            let guard = match guard {
                Ok(guard) => guard,
                Err(error) => std::panic::resume_unwind(Box::new(error)),
            };
            state.revert_ok.set(false);
            let result = catch_unwind(AssertUnwindSafe(|| drop(guard)));
            assert_fail_fast(&result, &state);
        }
    }
}
