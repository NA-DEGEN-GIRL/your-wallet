//! Dormant held-root and fixed-record adapter for service run state.
//!
//! The adapter opens and verifies installer-created root/lock/state objects and,
//! only while their exact writer is held, can replace the fixed marker and
//! checkpoint pair through two fixed temporary leaves. It has no production
//! constructor for expected identities or security policy, no production
//! caller, and no conversion into Phase 2D boot or durable-state evidence.

use core::fmt;

use thiserror::Error;

mod sys;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(super) use tests::{RuntimePairFault, RuntimePairFixture, RuntimePairProcessDeathCutpoint};

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
    /// Exact fixed-record I/O did not complete as requested.
    #[error("service run-state fixed-record I/O failed")]
    RecordIo,
    /// The fixed marker/checkpoint pair changed before its consuming commit.
    #[error("service run-state fixed-record comparison failed")]
    Compare,
    /// A handle-relative fixed-record rename failed or became ambiguous.
    #[error("service run-state fixed-record rename failed")]
    Rename,
    /// Checked cleanup of a fixed temporary record failed.
    #[error("service run-state fixed-record cleanup failed")]
    Cleanup,
}

/// Exact byte length of each fixed V1 marker/checkpoint record.
pub(super) const FIXED_RUN_STATE_RECORD_BYTES: usize = 148;

/// One exact candidate pair. Leaf selection remains internal to this module.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ExactFixedRunStatePair {
    marker: [u8; FIXED_RUN_STATE_RECORD_BYTES],
    checkpoint: [u8; FIXED_RUN_STATE_RECORD_BYTES],
}

impl ExactFixedRunStatePair {
    pub(super) const fn new(
        marker: [u8; FIXED_RUN_STATE_RECORD_BYTES],
        checkpoint: [u8; FIXED_RUN_STATE_RECORD_BYTES],
    ) -> Self {
        Self { marker, checkpoint }
    }

    pub(super) const fn marker(&self) -> &[u8; FIXED_RUN_STATE_RECORD_BYTES] {
        &self.marker
    }

    pub(super) const fn checkpoint(&self) -> &[u8; FIXED_RUN_STATE_RECORD_BYTES] {
        &self.checkpoint
    }
}

impl fmt::Debug for ExactFixedRunStatePair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactFixedRunStatePair([REDACTED])")
    }
}

/// Shape-only observation of one fixed record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FixedRunStateRecordObservation {
    Missing,
    Malformed,
    Exact([u8; FIXED_RUN_STATE_RECORD_BYTES]),
}

impl fmt::Debug for FixedRunStateRecordObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("Missing"),
            Self::Malformed => formatter.write_str("Malformed"),
            Self::Exact(_) => formatter.write_str("Exact([REDACTED])"),
        }
    }
}

/// Authority-free marker/checkpoint observation copied from a held writer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct FixedRunStatePairObservation {
    marker: FixedRunStateRecordObservation,
    checkpoint: FixedRunStateRecordObservation,
}

impl FixedRunStatePairObservation {
    const fn new(
        marker: FixedRunStateRecordObservation,
        checkpoint: FixedRunStateRecordObservation,
    ) -> Self {
        Self { marker, checkpoint }
    }

    pub(super) const fn marker(&self) -> FixedRunStateRecordObservation {
        self.marker
    }

    pub(super) const fn checkpoint(&self) -> FixedRunStateRecordObservation {
        self.checkpoint
    }
}

impl fmt::Debug for FixedRunStatePairObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedRunStatePairObservation")
            .field("marker", &self.marker)
            .field("checkpoint", &self.checkpoint)
            .finish()
    }
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

    /// Opens the already-installed `run.lock` with data access and no sharing,
    /// acquires its exclusive range, and then opens the installed `state`
    /// directory with exact mutation authority.
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

/// A move-only exclusive writer holding the root, `run.lock`, exact one-byte
/// kernel range lock, and installer-recorded `state` directory.
#[must_use = "the held writer must be explicitly released"]
pub(crate) struct HeldServiceRunStateWriter {
    inner: sys::HeldWriter,
}

impl HeldServiceRunStateWriter {
    /// Revalidates all three exact objects and their fixed-path bindings.
    pub(crate) fn revalidate(&self) -> Result<(), ServiceRunStateError> {
        self.inner.revalidate()
    }

    /// Revalidates, checked-closes `state`, explicitly unlocks the exact kernel
    /// range, checked-closes the lock handle, revalidates the still-held root,
    /// and checked-closes the root before issuing a terminal receipt.
    #[allow(clippy::result_large_err)] // Failure is a move-only authority-bearing typestate.
    pub(crate) fn release(self) -> Result<ServiceRunLockReleased, HeldRunLockFailure> {
        match self.inner.release_verified() {
            Ok(()) => Ok(ServiceRunLockReleased { _sealed: () }),
            Err(sys::ReleaseFailure { inner, cause }) => Err(HeldRunLockFailure { inner, cause }),
        }
    }

    /// Terminally retires every held authority without issuing a normal
    /// verified-release receipt.
    pub(crate) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }

    /// Consumes the writer into one exact fixed-pair observation whose hidden
    /// full identities are retained for the later second CAS.
    #[allow(clippy::result_large_err)] // Failure retains the complete writer authority.
    pub(super) fn observe_fixed_pair(
        self,
    ) -> Result<ObservedFixedRunStatePair, FixedPairKnownFailure> {
        match self.inner.observe_fixed_pair() {
            Ok(inner) => Ok(ObservedFixedRunStatePair { inner }),
            Err(sys::PairFailure { inner, cause }) => Err(FixedPairKnownFailure { inner, cause }),
        }
    }
}

impl fmt::Debug for HeldServiceRunStateWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldServiceRunStateWriter([REDACTED])")
    }
}

/// A move-only fixed-pair observation bound to the exact held writer and IDs.
#[must_use = "the observed fixed pair must be committed, verified-released, or retired"]
pub(super) struct ObservedFixedRunStatePair {
    inner: sys::ObservedPairWriter,
}

impl ObservedFixedRunStatePair {
    pub(super) const fn observation(&self) -> FixedRunStatePairObservation {
        self.inner.observation()
    }

    #[allow(clippy::large_types_passed_by_value)] // The exact one-shot candidate is consumed.
    pub(super) fn compare_and_replace(
        self,
        candidate: ExactFixedRunStatePair,
    ) -> FixedPairCommitOutcome {
        match self.inner.compare_and_replace(candidate) {
            sys::PairCommitOutcome::Committed(inner) => {
                FixedPairCommitOutcome::Committed(FixedPairCommitted { inner })
            }
            sys::PairCommitOutcome::KnownNotCommitted(sys::PairFailure { inner, cause }) => {
                FixedPairCommitOutcome::KnownNotCommitted(FixedPairKnownFailure { inner, cause })
            }
            sys::PairCommitOutcome::Ambiguous(inner, cause) => {
                FixedPairCommitOutcome::Ambiguous(FixedPairAmbiguous { inner, cause })
            }
        }
    }

    /// Releases an exact pair only after binding zero-share final handles to
    /// this observation's bytes and full identities for the complete writer
    /// release sequence.
    #[allow(clippy::result_large_err)] // Failure retains move-only writer authority inline.
    pub(super) fn release_verified(self) -> Result<FixedPairReleased, FixedPairReleaseFailure> {
        match self.inner.release_verified() {
            Ok(pair) => Ok(FixedPairReleased { pair, _sealed: () }),
            Err(failure) => Err(map_fixed_pair_release_failure(failure)),
        }
    }

    pub(super) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }
}

impl fmt::Debug for ObservedFixedRunStatePair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObservedFixedRunStatePair([REDACTED])")
    }
}

/// Complete consuming commit outcome. No variant exposes a raw file handle.
#[must_use = "the fixed-pair commit outcome retains writer authority"]
#[allow(clippy::large_enum_variant)] // Inline move-only authority avoids fallible allocation.
pub(super) enum FixedPairCommitOutcome {
    Committed(FixedPairCommitted),
    KnownNotCommitted(FixedPairKnownFailure),
    Ambiguous(FixedPairAmbiguous),
}

impl fmt::Debug for FixedPairCommitOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed(_) => formatter.write_str("Committed([REDACTED])"),
            Self::KnownNotCommitted(failure) => formatter
                .debug_tuple("KnownNotCommitted")
                .field(&failure.cause)
                .finish(),
            Self::Ambiguous(failure) => formatter
                .debug_tuple("Ambiguous")
                .field(&failure.cause)
                .finish(),
        }
    }
}

/// Both ordered renames and their exact confirmation reopens completed.
#[must_use = "a committed fixed pair requires an independent reread or retirement"]
pub(super) struct FixedPairCommitted {
    inner: sys::CommittedPairWriter,
}

impl FixedPairCommitted {
    pub(super) const fn candidate(&self) -> ExactFixedRunStatePair {
        self.inner.candidate()
    }

    #[allow(clippy::result_large_err)] // Ambiguity retains the complete writer authority.
    pub(super) fn reread(self) -> Result<FixedPairReread, FixedPairAmbiguous> {
        match self.inner.reread() {
            Ok(inner) => Ok(FixedPairReread { inner }),
            Err((inner, cause)) => Err(FixedPairAmbiguous { inner, cause }),
        }
    }

    pub(super) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }
}

impl fmt::Debug for FixedPairCommitted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedPairCommitted([REDACTED])")
    }
}

/// Independent exact reread after a confirmed ordered pair commit.
#[must_use = "the reread fixed pair must continue toward commit/release or retire"]
pub(super) struct FixedPairReread {
    inner: sys::RereadPairWriter,
}

impl FixedPairReread {
    pub(super) const fn observation(&self) -> FixedRunStatePairObservation {
        self.inner.observation()
    }

    /// Continues the active writer while retaining the independently reread
    /// bytes and full file identities as the next consuming CAS expectation.
    pub(super) fn continue_observed(self) -> ObservedFixedRunStatePair {
        ObservedFixedRunStatePair {
            inner: self.inner.continue_observed(),
        }
    }

    #[cfg(test)]
    pub(super) fn into_writer(self) -> HeldServiceRunStateWriter {
        HeldServiceRunStateWriter {
            inner: self.inner.into_writer(),
        }
    }

    pub(super) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }
}

impl fmt::Debug for FixedPairReread {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedPairReread([REDACTED])")
    }
}

/// Terminal pre-first-rename failure retaining the exact writer.
#[must_use = "a known fixed-pair failure must be explicitly retired"]
pub(super) struct FixedPairKnownFailure {
    inner: sys::HeldWriter,
    cause: ServiceRunStateError,
}

impl FixedPairKnownFailure {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }

    pub(super) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }
}

impl fmt::Debug for FixedPairKnownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedPairKnownFailure")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// First-rename-onward ambiguity retaining mandatory reload/retire authority.
#[must_use = "an ambiguous fixed-pair commit must be reloaded or retired"]
pub(super) struct FixedPairAmbiguous {
    inner: sys::AmbiguousPairWriter,
    cause: ServiceRunStateError,
}

impl FixedPairAmbiguous {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }

    #[allow(clippy::result_large_err)] // Failure retains the complete writer authority.
    pub(super) fn reload(self) -> Result<FixedPairReloaded, FixedPairReloadFailure> {
        match self.inner.reload() {
            Ok(inner) => Ok(FixedPairReloaded { inner }),
            Err(sys::AmbiguousPairFailure { inner, cause }) => {
                Err(FixedPairReloadFailure { inner, cause })
            }
        }
    }

    pub(super) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }
}

/// Reload failure that remains first-rename-onward ambiguous and can only retire.
#[must_use = "an ambiguous reload failure must be explicitly retired"]
pub(super) struct FixedPairReloadFailure {
    inner: sys::AmbiguousPairWriter,
    cause: ServiceRunStateError,
}

impl FixedPairReloadFailure {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }

    pub(super) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }
}

impl fmt::Debug for FixedPairReloadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedPairReloadFailure")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for FixedPairAmbiguous {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedPairAmbiguous")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Exact final observation obtained only through an ambiguity reload.
#[must_use = "the reloaded fixed pair must continue toward commit/release or retire"]
pub(super) struct FixedPairReloaded {
    inner: sys::ReloadedPairWriter,
}

impl FixedPairReloaded {
    pub(super) const fn observation(&self) -> FixedRunStatePairObservation {
        self.inner.observation()
    }

    /// Continues the active writer while retaining the ambiguity reload's
    /// exact bytes and full file identities as the next CAS expectation.
    pub(super) fn continue_observed(self) -> ObservedFixedRunStatePair {
        ObservedFixedRunStatePair {
            inner: self.inner.continue_observed(),
        }
    }

    #[cfg(test)]
    pub(super) fn into_writer(self) -> HeldServiceRunStateWriter {
        HeldServiceRunStateWriter {
            inner: self.inner.into_writer(),
        }
    }

    pub(super) fn retire(self) -> Result<FailedRunLockRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedRunLockRetired { _sealed: () })
    }
}

impl fmt::Debug for FixedPairReloaded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedPairReloaded([REDACTED])")
    }
}

/// Authority-free evidence that an exact pair stayed bound while the writer
/// was fully released and every pair handle was checked-closed.
#[must_use = "the verified fixed-pair release receipt is terminal evidence"]
pub(super) struct FixedPairReleased {
    pair: ExactFixedRunStatePair,
    _sealed: (),
}

impl FixedPairReleased {
    pub(super) const fn pair(&self) -> ExactFixedRunStatePair {
        self.pair
    }
}

impl fmt::Debug for FixedPairReleased {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedPairReleased([REDACTED])")
    }
}

/// A verified pair release either still owns the writer and held pair handles,
/// or reached an irreversible pair-close ambiguity after releasing the writer.
#[must_use = "a failed fixed-pair release cannot issue a normal receipt"]
#[allow(clippy::large_enum_variant)] // Inline authority keeps failure allocation-free.
pub(super) enum FixedPairReleaseFailure {
    WriterRetained(FixedPairReleaseWithWriter),
    WriterReleasedNoReceipt(FixedPairReleaseAfterWriter),
}

impl FixedPairReleaseFailure {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        match self {
            Self::WriterRetained(failure) => failure.cause(),
            Self::WriterReleasedNoReceipt(failure) => failure.cause(),
        }
    }
}

impl fmt::Debug for FixedPairReleaseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriterRetained(failure) => formatter
                .debug_tuple("WriterRetained")
                .field(&failure.cause())
                .finish(),
            Self::WriterReleasedNoReceipt(failure) => formatter
                .debug_tuple("WriterReleasedNoReceipt")
                .field(&failure.cause())
                .finish(),
        }
    }
}

/// Terminal failure authority that still owns the partial writer release and
/// every pair handle opened before the failure.
#[must_use = "the retained fixed-pair release authority must be retired"]
pub(super) struct FixedPairReleaseWithWriter {
    inner: sys::PairReleaseWithWriter,
}

impl FixedPairReleaseWithWriter {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.inner.cause
    }

    pub(super) fn retire(self) -> Result<FailedFixedPairReleaseRetired, ServiceRunStateError> {
        self.inner.retire()?;
        Ok(FailedFixedPairReleaseRetired { _sealed: () })
    }
}

impl fmt::Debug for FixedPairReleaseWithWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedPairReleaseWithWriter")
            .field("cause", &self.cause())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Irreversible no-receipt terminal reached only when the writer was already
/// released but a later checked pair-handle close became ambiguous.
#[must_use = "this terminal state deliberately has no normal release receipt"]
pub(super) struct FixedPairReleaseAfterWriter {
    cause: ServiceRunStateError,
    _sealed: (),
}

impl FixedPairReleaseAfterWriter {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }
}

impl fmt::Debug for FixedPairReleaseAfterWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedPairReleaseAfterWriter")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

/// Checked terminal cleanup receipt for a release failure that retained the
/// writer. It can never be confused with `FixedPairReleased`.
#[must_use = "the failed fixed-pair release was terminally retired"]
pub(super) struct FailedFixedPairReleaseRetired {
    _sealed: (),
}

fn map_fixed_pair_release_failure(failure: sys::PairReleaseFailure) -> FixedPairReleaseFailure {
    match failure {
        sys::PairReleaseFailure::WriterRetained(inner) => {
            FixedPairReleaseFailure::WriterRetained(FixedPairReleaseWithWriter { inner })
        }
        sys::PairReleaseFailure::WriterReleasedNoReceipt(cause) => {
            FixedPairReleaseFailure::WriterReleasedNoReceipt(FixedPairReleaseAfterWriter {
                cause,
                _sealed: (),
            })
        }
    }
}

/// Startup failure separated by whether Windows returned a `run.lock` handle.
#[must_use = "a WithLock failure must be explicitly retired"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids a fallible allocation while failing.
pub(crate) enum RuntimeRunLockStartFailure {
    /// The failure occurred before Windows returned a valid `run.lock` handle.
    BeforeLock(ServiceRunStateError),
    /// A valid `run.lock` handle remains in the terminal failure state; its
    /// exclusive byte range may or may not have been acquired, and a valid
    /// `state` handle may also remain held.
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

/// A terminal failure state that may still own the root, lock, and state handles.
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
