//! Process-wide coordination for Windows `AppContainer` profile APIs.
//!
//! Windows can transiently reject concurrent operations over `AppContainer`
//! profiles. Every profile creator in this crate uses this one short-lived
//! gate around only the native profile API calls.

#![allow(unsafe_code)]

use std::cell::Cell;
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
    let was_held = PROFILE_API_HELD_BY_THREAD
        .try_with(|held| held.replace(true))
        .map_err(|_| AppContainerProfileApiCoordinationError::Poisoned)?;
    debug_assert!(!was_held);
    Ok(AppContainerProfileApiGuard { _mutex: mutex })
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
    use super::{AppContainerProfileApiCoordinationError, acquire_appcontainer_profile_api};
    use windows::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};

    struct RevertImpersonation;

    impl Drop for RevertImpersonation {
        fn drop(&mut self) {
            // SAFETY: this guard exists only after ImpersonateSelf succeeded.
            unsafe {
                let _ = RevertToSelf();
            }
        }
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
}
