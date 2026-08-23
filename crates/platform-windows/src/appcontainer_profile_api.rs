//! Process-wide coordination for Windows `AppContainer` profile APIs.
//!
//! Windows can transiently reject concurrent operations over `AppContainer`
//! profiles. Every profile creator in this crate uses this one short-lived
//! gate around only the native profile API calls.

#![allow(unsafe_code)]

use std::cell::Cell;
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
}
