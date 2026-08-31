//! Dormant Windows adapter for one exact marker/checkpoint pair.
//!
//! This child module joins the private durable codec to the held-writer facade
//! without exposing native handles or minting Phase 2D authority. Every state
//! that owns the writer is move-only. Known failures can only be retired, and
//! ambiguous commits must be independently reloaded or retired. A failed
//! ambiguity reload remains ambiguity-bearing and terminal-only.

use core::fmt;

use super::super::run_state_root::{
    ExactFixedRunStatePair, FIXED_RUN_STATE_RECORD_BYTES, FailedRunLockRetired, FixedPairAmbiguous,
    FixedPairCommitOutcome as RootFixedPairCommitOutcome, FixedPairCommitted,
    FixedPairKnownFailure, FixedPairReleaseAfterWriter, FixedPairReleaseFailure,
    FixedPairReleaseWithWriter, FixedPairReleased, FixedPairReloadFailure, FixedPairReloaded,
    FixedPairReread, FixedRunStatePairObservation, FixedRunStateRecordObservation,
    HeldServiceRunStateWriter, ObservedFixedRunStatePair, ServiceRunStateError,
};
use super::{
    CanonicalSnapshot, FixedObservation, HIGH_WATER_BYTES, RUN_MARKER_BYTES, SnapshotObservation,
};

const _: [(); RUN_MARKER_BYTES] = [(); FIXED_RUN_STATE_RECORD_BYTES];
const _: [(); HIGH_WATER_BYTES] = [(); FIXED_RUN_STATE_RECORD_BYTES];

const fn record_observation(
    observed: FixedRunStateRecordObservation,
) -> FixedObservation<FIXED_RUN_STATE_RECORD_BYTES> {
    match observed {
        FixedRunStateRecordObservation::Missing => FixedObservation::Missing,
        FixedRunStateRecordObservation::Malformed => FixedObservation::Malformed,
        FixedRunStateRecordObservation::Exact(bytes) => FixedObservation::Exact(bytes),
    }
}

const fn snapshot_observation_from_records(
    marker: FixedRunStateRecordObservation,
    checkpoint: FixedRunStateRecordObservation,
) -> SnapshotObservation {
    SnapshotObservation {
        marker: record_observation(marker),
        checkpoint: record_observation(checkpoint),
    }
}

const fn snapshot_observation(observed: &FixedRunStatePairObservation) -> SnapshotObservation {
    snapshot_observation_from_records(observed.marker(), observed.checkpoint())
}

const fn exact_pair(snapshot: &CanonicalSnapshot) -> ExactFixedRunStatePair {
    ExactFixedRunStatePair::new(snapshot.marker, snapshot.checkpoint)
}

const fn canonical_snapshot(pair: &ExactFixedRunStatePair) -> CanonicalSnapshot {
    CanonicalSnapshot {
        marker: *pair.marker(),
        checkpoint: *pair.checkpoint(),
    }
}

fn retirement(
    result: Result<FailedRunLockRetired, ServiceRunStateError>,
) -> Result<WindowsPairRetired, ServiceRunStateError> {
    result.map(|_receipt| WindowsPairRetired { _sealed: () })
}

/// The only pair shapes accepted as a compare-and-replace expectation.
#[must_use = "the expected Windows pair must be checked against a held observation"]
pub(super) struct ExpectedWindowsPair {
    exact: Option<CanonicalSnapshot>,
}

impl ExpectedWindowsPair {
    /// Requires the fixed marker and checkpoint to both be absent.
    pub(super) const fn missing() -> Self {
        Self { exact: None }
    }

    /// Requires both fixed records to equal the supplied canonical snapshot.
    #[allow(clippy::large_types_passed_by_value)] // The exact expectation is intentionally consumed.
    pub(super) const fn exact(snapshot: CanonicalSnapshot) -> Self {
        Self {
            exact: Some(snapshot),
        }
    }

    fn matches(&self, observed: &SnapshotObservation) -> bool {
        match &self.exact {
            None => {
                observed.marker == FixedObservation::Missing
                    && observed.checkpoint == FixedObservation::Missing
            }
            Some(snapshot) => *observed == snapshot.observation(),
        }
    }
}

impl fmt::Debug for ExpectedWindowsPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.exact {
            None => formatter.write_str("ExpectedWindowsPair::Missing"),
            Some(_) => formatter.write_str("ExpectedWindowsPair::Exact([REDACTED])"),
        }
    }
}

/// Initial move-only adapter state owning the complete held writer.
#[must_use = "the Windows pair writer must be observed or explicitly retired"]
pub(super) struct WindowsPairWriter {
    inner: HeldServiceRunStateWriter,
}

impl WindowsPairWriter {
    /// Takes the opaque held writer without exposing its native handles.
    #[allow(clippy::large_types_passed_by_value)] // This constructor transfers writer authority.
    pub(super) const fn from_held_writer(inner: HeldServiceRunStateWriter) -> Self {
        Self { inner }
    }

    /// Captures both fixed records while retaining the same writer authority.
    #[allow(clippy::result_large_err)] // Failure retains the complete writer authority.
    pub(super) fn observe(self) -> Result<WindowsObservedPair, WindowsPairKnownFailure> {
        match self.inner.observe_fixed_pair() {
            Ok(inner) => {
                let root_observation = inner.observation();
                let observation = snapshot_observation(&root_observation);
                Ok(WindowsObservedPair { inner, observation })
            }
            Err(inner) => Err(WindowsPairKnownFailure { inner }),
        }
    }

    /// Terminally retires the writer without issuing a normal release receipt.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsPairWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsPairWriter([REDACTED])")
    }
}

/// One fixed-pair observation bound to the exact held writer and file IDs.
#[must_use = "the observed Windows pair must be prepared or explicitly retired"]
pub(super) struct WindowsObservedPair {
    inner: ObservedFixedRunStatePair,
    observation: SnapshotObservation,
}

impl WindowsObservedPair {
    /// Returns an authority-free copy of the fixed-pair observation.
    pub(super) const fn observation(&self) -> SnapshotObservation {
        self.observation
    }

    /// Checks the durable expectation before enabling the sole CAS attempt.
    #[allow(clippy::result_large_err)] // Mismatch retains the complete writer authority.
    #[allow(clippy::large_types_passed_by_value)] // Both exact envelopes are intentionally consumed.
    #[allow(clippy::needless_pass_by_value)] // Consuming the expectation makes this gate one-shot.
    pub(super) fn prepare_commit(
        self,
        expected: ExpectedWindowsPair,
        candidate: CanonicalSnapshot,
    ) -> Result<WindowsPreparedPairCommit, WindowsPairExpectationMismatch> {
        if !expected.matches(&self.observation) {
            return Err(WindowsPairExpectationMismatch { inner: self.inner });
        }
        Ok(WindowsPreparedPairCommit {
            inner: self.inner,
            candidate,
        })
    }

    /// Releases the exact writer only while this observation's pair bytes and
    /// full identities remain bound throughout checked close.
    #[allow(clippy::result_large_err)] // Failure retains authority inline.
    pub(super) fn release_verified(self) -> Result<WindowsPairReleased, WindowsPairReleaseFailure> {
        match self.inner.release_verified() {
            Ok(inner) => Ok(WindowsPairReleased {
                pair: canonical_snapshot(&inner.pair()),
                inner,
            }),
            Err(FixedPairReleaseFailure::WriterRetained(inner)) => Err(
                WindowsPairReleaseFailure::WriterRetained(WindowsPairReleaseWithWriter { inner }),
            ),
            Err(FixedPairReleaseFailure::WriterReleasedNoReceipt(inner)) => {
                Err(WindowsPairReleaseFailure::WriterReleasedNoReceipt(
                    WindowsPairReleaseAfterWriter { inner },
                ))
            }
        }
    }

    /// Terminally retires the writer without attempting a commit.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsObservedPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsObservedPair([REDACTED])")
    }
}

/// Exact expected/candidate pair ready for one consuming CAS attempt.
#[must_use = "the prepared Windows pair commit must be attempted or explicitly retired"]
pub(super) struct WindowsPreparedPairCommit {
    inner: ObservedFixedRunStatePair,
    candidate: CanonicalSnapshot,
}

impl WindowsPreparedPairCommit {
    /// Performs the sole full-identity-bound compare-and-replace attempt.
    pub(super) fn commit(self) -> WindowsPairCommitOutcome {
        let Self { inner, candidate } = self;
        match inner.compare_and_replace(exact_pair(&candidate)) {
            RootFixedPairCommitOutcome::Committed(inner) => {
                WindowsPairCommitOutcome::Committed(WindowsCommittedPair { inner })
            }
            RootFixedPairCommitOutcome::KnownNotCommitted(inner) => {
                WindowsPairCommitOutcome::KnownNotCommitted(WindowsPairKnownFailure { inner })
            }
            RootFixedPairCommitOutcome::Ambiguous(inner) => {
                WindowsPairCommitOutcome::Ambiguous(WindowsPairReloadRequired { inner })
            }
        }
    }

    /// Terminally retires the writer without attempting the prepared commit.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsPreparedPairCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsPreparedPairCommit([REDACTED])")
    }
}

/// Complete outcome of the one consuming pair commit attempt.
#[must_use = "the Windows pair commit outcome retains writer authority"]
#[allow(clippy::large_enum_variant)] // Inline move-only authority avoids fallible allocation.
pub(super) enum WindowsPairCommitOutcome {
    /// Both ordered replacements and their confirmation reopens completed.
    Committed(WindowsCommittedPair),
    /// No replacement occurred; only terminal retirement remains valid.
    KnownNotCommitted(WindowsPairKnownFailure),
    /// At least the first replacement may have occurred; reload is mandatory.
    Ambiguous(WindowsPairReloadRequired),
}

impl fmt::Debug for WindowsPairCommitOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed(_) => formatter.write_str("Committed([REDACTED])"),
            Self::KnownNotCommitted(failure) => formatter
                .debug_tuple("KnownNotCommitted")
                .field(&failure.cause())
                .finish(),
            Self::Ambiguous(failure) => formatter
                .debug_tuple("Ambiguous")
                .field(&failure.cause())
                .finish(),
        }
    }
}

/// Confirmed ordered pair commit awaiting an independent reread.
#[must_use = "the committed Windows pair must be reread or explicitly retired"]
pub(super) struct WindowsCommittedPair {
    inner: FixedPairCommitted,
}

impl WindowsCommittedPair {
    /// Returns the exact canonical candidate named by this commit state.
    pub(super) const fn candidate(&self) -> CanonicalSnapshot {
        let candidate = self.inner.candidate();
        canonical_snapshot(&candidate)
    }

    /// Independently reopens and rereads both installed fixed records.
    #[allow(clippy::result_large_err)] // Ambiguity retains the complete writer authority.
    pub(super) fn reread(self) -> Result<WindowsRereadPair, WindowsPairReloadRequired> {
        match self.inner.reread() {
            Ok(inner) => {
                let root_observation = inner.observation();
                let observation = snapshot_observation(&root_observation);
                Ok(WindowsRereadPair { inner, observation })
            }
            Err(inner) => Err(WindowsPairReloadRequired { inner }),
        }
    }

    /// Terminally retires the writer without performing the reread.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsCommittedPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsCommittedPair([REDACTED])")
    }
}

/// Independent post-commit observation retaining terminal writer authority.
#[must_use = "the reread Windows pair must be consumed by terminal retirement"]
pub(super) struct WindowsRereadPair {
    inner: FixedPairReread,
    observation: SnapshotObservation,
}

impl WindowsRereadPair {
    /// Returns the independently captured fixed-pair observation.
    pub(super) const fn observation(&self) -> SnapshotObservation {
        self.observation
    }

    /// Continues with the independently reopened bytes and full identities as
    /// the next consuming pair expectation.
    pub(super) fn continue_observed(self) -> WindowsObservedPair {
        WindowsObservedPair {
            inner: self.inner.continue_observed(),
            observation: self.observation,
        }
    }

    /// Terminally retires the writer after the independent reread.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsRereadPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsRereadPair([REDACTED])")
    }
}

/// Known pre-first-replacement failure retaining terminal writer authority.
#[must_use = "the known Windows pair failure must be explicitly retired"]
pub(super) struct WindowsPairKnownFailure {
    inner: FixedPairKnownFailure,
}

impl WindowsPairKnownFailure {
    /// Returns the path-free low-level failure reason.
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.inner.cause()
    }

    /// Provides the sole terminal path for this known failure.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsPairKnownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPairKnownFailure")
            .field("cause", &self.cause())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Local expectation mismatch retaining terminal-only writer authority.
#[must_use = "the mismatched Windows pair observation must be explicitly retired"]
pub(super) struct WindowsPairExpectationMismatch {
    inner: ObservedFixedRunStatePair,
}

impl WindowsPairExpectationMismatch {
    /// Provides the sole terminal path after the expectation mismatch.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsPairExpectationMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsPairExpectationMismatch([REDACTED])")
    }
}

/// Ambiguous pair state permitting only a fresh reload or retirement.
#[must_use = "the ambiguous Windows pair must be reloaded or explicitly retired"]
pub(super) struct WindowsPairReloadRequired {
    inner: FixedPairAmbiguous,
}

impl WindowsPairReloadRequired {
    /// Returns the path-free low-level ambiguity reason.
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.inner.cause()
    }

    /// Consumes the ambiguous state into one fresh pair reload.
    #[allow(clippy::result_large_err)] // Failure retains ambiguity and the complete writer.
    pub(super) fn reload(self) -> Result<WindowsReloadedPair, WindowsPairReloadFailure> {
        match self.inner.reload() {
            Ok(inner) => {
                let root_observation = inner.observation();
                let observation = snapshot_observation(&root_observation);
                Ok(WindowsReloadedPair { inner, observation })
            }
            Err(inner) => Err(WindowsPairReloadFailure { inner }),
        }
    }

    /// Terminally retires the ambiguous writer without reloading it.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsPairReloadRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPairReloadRequired")
            .field("cause", &self.cause())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Failed ambiguity reload retaining terminal-only ambiguous writer authority.
#[must_use = "the failed Windows pair reload must be explicitly retired"]
pub(super) struct WindowsPairReloadFailure {
    inner: FixedPairReloadFailure,
}

impl WindowsPairReloadFailure {
    /// Returns the path-free reload failure without downgrading ambiguity.
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.inner.cause()
    }

    /// Provides the sole terminal path after a failed ambiguity reload.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsPairReloadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPairReloadFailure")
            .field("cause", &self.cause())
            .field("ambiguous_authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Fresh post-ambiguity observation retaining only terminal writer authority.
#[must_use = "the reloaded Windows pair must be consumed by terminal retirement"]
pub(super) struct WindowsReloadedPair {
    inner: FixedPairReloaded,
    observation: SnapshotObservation,
}

impl WindowsReloadedPair {
    /// Returns the freshly reloaded fixed-pair observation.
    pub(super) const fn observation(&self) -> SnapshotObservation {
        self.observation
    }

    /// Continues with the ambiguity reload's bytes and full identities as the
    /// next consuming pair expectation.
    pub(super) fn continue_observed(self) -> WindowsObservedPair {
        WindowsObservedPair {
            inner: self.inner.continue_observed(),
            observation: self.observation,
        }
    }

    /// Terminally retires the writer after ambiguity resolution.
    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        retirement(self.inner.retire())
    }
}

impl fmt::Debug for WindowsReloadedPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsReloadedPair([REDACTED])")
    }
}

/// Terminal receipt that carries no writer authority.
#[must_use = "terminal Windows pair retirement evidence must be observed"]
pub(super) struct WindowsPairRetired {
    _sealed: (),
}

/// Exact pair-bound normal writer-release receipt.
#[must_use = "the Windows pair release receipt must be consumed by the composite"]
pub(super) struct WindowsPairReleased {
    pair: CanonicalSnapshot,
    inner: FixedPairReleased,
}

impl WindowsPairReleased {
    /// Returns the exact pair that stayed bound through verified release.
    pub(super) const fn pair(&self) -> CanonicalSnapshot {
        self.pair
    }
}

impl fmt::Debug for WindowsPairReleased {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.inner;
        formatter.write_str("WindowsPairReleased([REDACTED])")
    }
}

/// Pair-bound final release failed either before writer release or after the
/// writer was irreversibly released without a normal receipt.
#[must_use = "a failed Windows pair release cannot issue stopped evidence"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids allocation.
pub(super) enum WindowsPairReleaseFailure {
    WriterRetained(WindowsPairReleaseWithWriter),
    WriterReleasedNoReceipt(WindowsPairReleaseAfterWriter),
}

impl WindowsPairReleaseFailure {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        match self {
            Self::WriterRetained(failure) => failure.cause(),
            Self::WriterReleasedNoReceipt(failure) => failure.cause(),
        }
    }
}

impl fmt::Debug for WindowsPairReleaseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPairReleaseFailure")
            .field("cause", &self.cause())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Failed release still holding writer and pair authority for terminal retire.
#[must_use = "the retained Windows pair release must be terminally retired"]
pub(super) struct WindowsPairReleaseWithWriter {
    inner: FixedPairReleaseWithWriter,
}

impl WindowsPairReleaseWithWriter {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.inner.cause()
    }

    pub(super) fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        self.inner
            .retire()
            .map(|_receipt| WindowsPairRetired { _sealed: () })
    }
}

impl fmt::Debug for WindowsPairReleaseWithWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPairReleaseWithWriter")
            .field("cause", &self.cause())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Irreversible final state: the writer was released but checked pair close
/// failed, so no retry, retirement receipt, or stopped evidence is possible.
#[must_use = "the no-receipt Windows release is an irreversible terminal state"]
pub(super) struct WindowsPairReleaseAfterWriter {
    inner: FixedPairReleaseAfterWriter,
}

impl WindowsPairReleaseAfterWriter {
    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.inner.cause()
    }
}

impl fmt::Debug for WindowsPairReleaseAfterWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPairReleaseAfterWriter")
            .field("cause", &self.cause())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for WindowsPairRetired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsPairRetired")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn snapshot(marker: u8, checkpoint: u8) -> CanonicalSnapshot {
        CanonicalSnapshot {
            marker: [marker; RUN_MARKER_BYTES],
            checkpoint: [checkpoint; HIGH_WATER_BYTES],
        }
    }

    #[test]
    fn record_shapes_map_without_widening_the_codec() {
        let exact = [0x41; FIXED_RUN_STATE_RECORD_BYTES];
        assert!(
            record_observation(FixedRunStateRecordObservation::Missing)
                == FixedObservation::Missing
        );
        assert!(
            record_observation(FixedRunStateRecordObservation::Malformed)
                == FixedObservation::Malformed
        );
        assert!(
            record_observation(FixedRunStateRecordObservation::Exact(exact))
                == FixedObservation::Exact(exact)
        );
    }

    #[test]
    fn exact_pair_round_trips_the_two_canonical_envelopes() {
        let canonical = snapshot(0x43, 0x44);
        let pair = exact_pair(&canonical);
        assert!(canonical_snapshot(&pair) == canonical);
    }

    #[test]
    fn missing_expectation_accepts_only_missing_missing() {
        let expected = ExpectedWindowsPair::missing();
        let missing = FixedRunStateRecordObservation::Missing;
        let malformed = FixedRunStateRecordObservation::Malformed;
        let exact = FixedRunStateRecordObservation::Exact([0x42; FIXED_RUN_STATE_RECORD_BYTES]);

        assert!(expected.matches(&snapshot_observation_from_records(missing, missing)));
        assert!(!expected.matches(&snapshot_observation_from_records(missing, malformed)));
        assert!(!expected.matches(&snapshot_observation_from_records(malformed, missing)));
        assert!(!expected.matches(&snapshot_observation_from_records(exact, missing)));
    }

    #[test]
    fn exact_expectation_requires_both_complete_canonical_records() {
        let canonical = snapshot(0x51, 0x52);
        let expected = ExpectedWindowsPair::exact(canonical);
        assert!(expected.matches(&canonical.observation()));

        let mut changed_marker = canonical;
        changed_marker.marker[RUN_MARKER_BYTES - 1] ^= 1;
        assert!(!expected.matches(&changed_marker.observation()));

        let mut changed_checkpoint = canonical;
        changed_checkpoint.checkpoint[HIGH_WATER_BYTES - 1] ^= 1;
        assert!(!expected.matches(&changed_checkpoint.observation()));

        assert!(!expected.matches(&snapshot_observation_from_records(
            FixedRunStateRecordObservation::Missing,
            FixedRunStateRecordObservation::Exact(canonical.checkpoint),
        )));
        assert!(!expected.matches(&snapshot_observation_from_records(
            FixedRunStateRecordObservation::Exact(canonical.marker),
            FixedRunStateRecordObservation::Malformed,
        )));
    }

    #[test]
    fn expectation_debug_redacts_exact_envelopes() {
        let exact = format!("{:?}", ExpectedWindowsPair::exact(snapshot(0x61, 0x62)));
        assert_eq!(exact, "ExpectedWindowsPair::Exact([REDACTED])");
        assert_eq!(
            format!("{:?}", ExpectedWindowsPair::missing()),
            "ExpectedWindowsPair::Missing"
        );
    }

    #[test]
    fn authority_states_and_receipts_are_move_only() {
        trait AmbiguousIfClone<Marker> {
            fn marker() {}
        }
        impl<T> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}

        trait AmbiguousIfCopy<Marker> {
            fn marker() {}
        }
        impl<T> AmbiguousIfCopy<()> for T {}
        impl<T: Copy> AmbiguousIfCopy<u8> for T {}

        macro_rules! assert_move_only {
            ($type:ty) => {
                let _ = <$type as AmbiguousIfClone<_>>::marker;
                let _ = <$type as AmbiguousIfCopy<_>>::marker;
            };
        }

        assert_move_only!(ExpectedWindowsPair);
        assert_move_only!(WindowsPairWriter);
        assert_move_only!(WindowsObservedPair);
        assert_move_only!(WindowsPreparedPairCommit);
        assert_move_only!(WindowsPairCommitOutcome);
        assert_move_only!(WindowsCommittedPair);
        assert_move_only!(WindowsRereadPair);
        assert_move_only!(WindowsPairKnownFailure);
        assert_move_only!(WindowsPairExpectationMismatch);
        assert_move_only!(WindowsPairReloadRequired);
        assert_move_only!(WindowsPairReloadFailure);
        assert_move_only!(WindowsReloadedPair);
        assert_move_only!(WindowsPairRetired);
        assert_move_only!(WindowsPairReleased);
        assert_move_only!(WindowsPairReleaseFailure);
        assert_move_only!(WindowsPairReleaseWithWriter);
        assert_move_only!(WindowsPairReleaseAfterWriter);
    }
}
