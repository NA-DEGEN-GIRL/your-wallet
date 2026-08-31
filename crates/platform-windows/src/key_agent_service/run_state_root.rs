//! Dormant held-root adapter for the fixed service run-state objects.
//!
//! This module can only open and verify installer-created objects. It has no
//! production constructor for the expected identities or security policy, no
//! production caller, and no conversion into Phase 2D boot evidence.

use core::fmt;

use thiserror::Error;

mod sys;

#[cfg(test)]
mod tests;

/// Path-free failures from opening or revalidating fixed run-state objects.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ServiceRunStateError {
    /// A thread impersonation token was present or could not be ruled out.
    #[error("service run-state access was attempted under an untrusted thread token")]
    Impersonation,
    /// The fixed `ProgramData` location could not be resolved or validated.
    #[error("service run-state location policy failed")]
    Location,
    /// An installer-created fixed object was absent.
    #[error("an installed service run-state object is missing")]
    Missing,
    /// Another process already holds the exclusive persistent run lock.
    #[error("the service run lock is already held")]
    Contended,
    /// Windows rejected an exact existing-object open.
    #[error("service run-state existing-object open failed")]
    Open,
    /// An object had the wrong type, link count, or length.
    #[error("service run-state object shape policy failed")]
    Shape,
    /// A reparse point was present in the fixed object chain.
    #[error("service run-state reparse policy failed")]
    Reparse,
    /// The objects were not on one supported local fixed NTFS volume.
    #[error("service run-state volume policy failed")]
    Volume,
    /// Full installer-recorded file identity did not match.
    #[error("service run-state identity policy failed")]
    Identity,
    /// Owner or exact protected DACL verification failed.
    #[error("service run-state security policy failed")]
    Security,
    /// A handle was inheritable or could not be queried.
    #[error("service run-state handle policy failed")]
    Handle,
    /// A checked handle release failed.
    #[error("service run-state checked release failed")]
    Release,
}

/// Installer-recorded identities and service security policy.
///
/// This type deliberately has no production constructor. A future installer
/// handoff must define and authenticate its provenance before a caller can mint
/// it. Tests alone can create a current-user surrogate.
#[must_use = "expected installed identities must be consumed by the fixed-root opener"]
pub(crate) struct ExpectedInstalledRunStateObjects(sys::ExpectedObjects);

impl fmt::Debug for ExpectedInstalledRunStateObjects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedInstalledRunStateObjects([REDACTED])")
    }
}

/// A move-only, no-delete-share handle to the exact fixed service root.
#[must_use = "the held service root must be consumed by lock acquisition"]
pub(crate) struct HeldServiceRunStateRoot {
    inner: sys::HeldRoot,
}

impl HeldServiceRunStateRoot {
    /// Revalidates the held object and its fixed-path binding.
    pub(crate) fn revalidate(&self) -> Result<(), ServiceRunStateError> {
        self.inner.revalidate()
    }

    /// Opens the already-installed `run.lock` with data access and no sharing.
    #[allow(clippy::result_large_err)] // WithLock must retain the complete held writer.
    pub(crate) fn acquire_run_lock(
        self,
    ) -> Result<HeldServiceRunStateWriter, RuntimeRunLockStartFailure> {
        match self.inner.acquire_run_lock() {
            Ok(inner) => Ok(HeldServiceRunStateWriter { inner }),
            Err(sys::AcquireFailure::BeforeLock(cause)) => {
                Err(RuntimeRunLockStartFailure::BeforeLock(cause))
            }
            Err(sys::AcquireFailure::WithLock { inner, cause }) => {
                Err(RuntimeRunLockStartFailure::WithLock(HeldRunLockFailure {
                    inner,
                    cause,
                }))
            }
        }
    }
}

impl fmt::Debug for HeldServiceRunStateRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldServiceRunStateRoot([REDACTED])")
    }
}

/// A move-only exclusive writer holding the root, `run.lock` handle, and exact
/// one-byte kernel range lock.
#[must_use = "the held writer must be explicitly released"]
pub(crate) struct HeldServiceRunStateWriter {
    inner: sys::HeldWriter,
}

impl HeldServiceRunStateWriter {
    /// Revalidates both exact objects and their fixed-path binding.
    pub(crate) fn revalidate(&self) -> Result<(), ServiceRunStateError> {
        self.inner.revalidate()
    }

    /// Revalidates, explicitly unlocks the exact kernel range, checked-closes
    /// the lock handle, revalidates the still-held root, and checked-closes the
    /// root before issuing a terminal receipt.
    #[allow(clippy::result_large_err)] // Failure is a move-only authority-bearing typestate.
    pub(crate) fn release(self) -> Result<ServiceRunLockReleased, HeldRunLockFailure> {
        match self.inner.release_verified() {
            Ok(()) => Ok(ServiceRunLockReleased { _sealed: () }),
            Err(sys::ReleaseFailure { inner, cause }) => Err(HeldRunLockFailure { inner, cause }),
        }
    }
}

impl fmt::Debug for HeldServiceRunStateWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldServiceRunStateWriter([REDACTED])")
    }
}

/// Startup failure separated by whether Windows returned a `run.lock` handle.
#[must_use = "a WithLock failure must be explicitly retired"]
pub(crate) enum RuntimeRunLockStartFailure {
    /// The failure occurred before Windows returned a valid `run.lock` handle.
    BeforeLock(ServiceRunStateError),
    /// A valid `run.lock` handle remains in the terminal failure state; its
    /// exclusive byte range may or may not have been acquired.
    WithLock(HeldRunLockFailure),
}

impl fmt::Debug for RuntimeRunLockStartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeLock(cause) => formatter.debug_tuple("BeforeLock").field(cause).finish(),
            Self::WithLock(_) => formatter.write_str("WithLock([REDACTED])"),
        }
    }
}

/// A terminal failure state that may still own the root and lock handles.
#[must_use = "the failed held lock must be explicitly retired"]
pub(crate) struct HeldRunLockFailure {
    inner: sys::HeldWriter,
    cause: ServiceRunStateError,
}

impl HeldRunLockFailure {
    /// Returns the path-free reason while retaining all handle authority.
    pub(crate) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }

    /// Checked-closes every remaining handle and issues a terminal receipt.
    pub(crate) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }
}

impl fmt::Debug for HeldRunLockFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeldRunLockFailure")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Terminal proof that a fully revalidated writer was checked-released.
pub(crate) struct ServiceRunLockReleased {
    _sealed: (),
}

impl fmt::Debug for ServiceRunLockReleased {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceRunLockReleased")
    }
}

/// Terminal proof that a failed held state was checked-retired.
pub(crate) struct FailedRunLockRetired {
    _sealed: (),
}

impl fmt::Debug for FailedRunLockRetired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FailedRunLockRetired")
    }
}

/// Opens the fixed `%ProgramData%\\YourWallet\\KeyAgent\\v1` root.
///
/// Only installer-recorded identity/security authority is accepted; the
/// adapter never creates, repairs, replaces, or adopts an object.
pub(crate) fn open_fixed_service_run_state_root(
    expected: ExpectedInstalledRunStateObjects,
) -> Result<HeldServiceRunStateRoot, ServiceRunStateError> {
    sys::HeldRoot::open_fixed(expected.0).map(|inner| HeldServiceRunStateRoot { inner })
}

#[cfg(test)]
fn open_test_service_run_state_root(
    base: &std::path::Path,
    expected: ExpectedInstalledRunStateObjects,
) -> Result<HeldServiceRunStateRoot, ServiceRunStateError> {
    sys::HeldRoot::open_test(base, expected.0).map(|inner| HeldServiceRunStateRoot { inner })
}
