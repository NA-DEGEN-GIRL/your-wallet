//! Process-wide coordination for Windows `AppContainer` profile APIs.
//!
//! Windows can transiently reject concurrent operations over `AppContainer`
//! profiles. Every profile creator in this crate uses this one short-lived
//! gate around only the native profile API calls.

use std::cell::Cell;
use std::sync::{Mutex, MutexGuard};

static APP_CONTAINER_PROFILE_API: Mutex<()> = Mutex::new(());

thread_local! {
    static PROFILE_API_HELD_BY_THREAD: Cell<bool> = const { Cell::new(false) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AppContainerProfileApiCoordinationError {
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
}
