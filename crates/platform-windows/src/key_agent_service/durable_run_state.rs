//! Authenticated, no-secret durable run-state fixture.
//!
//! The private Phase 2D evidence model remains backed only by a bounded
//! in-memory fault fixture compiled under `cfg(test)`. A separate dormant
//! Windows-only child joins its exact marker/checkpoint codec to the held
//! run-state writer facade, which performs fixed-pair operating-system I/O.
//! Its production-compiled consumers are the sibling dormant Windows runtime
//! and fresh-install provisioning compositors; there is no executable/top-level
//! caller, production provider source, or fresh-install authority mint, and this
//! slice makes no crash/power-loss claim.

use std::cell::Cell;
use std::fmt;
use std::num::NonZeroU64;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use subtle::ConstantTimeEq as _;
use thiserror::Error;

mod authentication;

mod provisioning;

#[cfg(windows)]
mod windows_pair;

#[cfg(windows)]
mod windows_runtime;

#[cfg(windows)]
#[allow(unused_imports)] // Reserved for the sibling Windows lifecycle adapter.
pub(in crate::key_agent_service) use windows_runtime::{
    WindowsActiveCommitOutcome, WindowsActiveReloadOutcome, WindowsActiveReloadRequired,
    WindowsActiveRunLease, WindowsBootEvidence, WindowsCheckedRetired,
    WindowsCheckedRetirementFailure, WindowsCleanCommitOutcome, WindowsCleanReloadOutcome,
    WindowsCleanReloadRequired, WindowsCleanWithWriter, WindowsPostReleaseTerminal,
    WindowsPreparedActiveTransition, WindowsReleasedNoReceipt, WindowsRetirementPending,
    WindowsRuntimeBindingFailure, WindowsRuntimeStartFailure, WindowsStopOutcome,
    WindowsStoppedRunEvidence, WindowsTerminalCause, WindowsTerminalFailure, WindowsUnboundRetired,
    WindowsUnboundRetirementFailure, start_windows_runtime,
};

#[cfg(all(test, windows))]
#[allow(unused_imports)] // Consumed by sibling Windows lifecycle kernel tests.
pub(in crate::key_agent_service) use windows_runtime::install_windows_runtime_clean_fixture;

pub(super) use authentication::{RunStateAuthenticationProvider, RuntimeRunStateAuthority};
use authentication::{RunStateProviderIdentity, build_snapshot, verify_observation};

#[cfg(test)]
use authentication::{resign_checkpoint_for_test, resign_marker_for_test};

const INSTALLATION_IDENTITY_BYTES: usize = 32;
const COMMITMENT_BYTES: usize = 32;
const MAC_BYTES: usize = 32;
const RUN_MARKER_BODY_BYTES: usize = 116;
const RUN_MARKER_BYTES: usize = RUN_MARKER_BODY_BYTES + MAC_BYTES;
const HIGH_WATER_BODY_BYTES: usize = 116;
const HIGH_WATER_BYTES: usize = HIGH_WATER_BODY_BYTES + MAC_BYTES;
const MARKER_VERSION_OFFSET: usize = 8;
const MARKER_STATE_OFFSET: usize = 10;
const MARKER_RESERVED_OFFSET: usize = 11;
const MARKER_GENERATION_OFFSET: usize = 12;
const MARKER_INSTALLATION_OFFSET: usize = 20;
const MARKER_PREDECESSOR_OFFSET: usize = 52;
const MARKER_CURRENT_OFFSET: usize = 84;
const CHECKPOINT_VERSION_OFFSET: usize = 8;
const CHECKPOINT_RESERVED_OFFSET: usize = 10;
const CHECKPOINT_GENERATION_OFFSET: usize = 12;
const CHECKPOINT_INSTALLATION_OFFSET: usize = 20;
const CHECKPOINT_PREDECESSOR_OFFSET: usize = 52;
const CHECKPOINT_CURRENT_OFFSET: usize = 84;

/// Canonical authenticated run-marker state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RunMarkerState {
    /// The previous service run completed its exact shutdown transition.
    Clean,
    /// One service run is active or did not prove a clean shutdown.
    Active,
    /// Recovery was durably required before another ordinary startup.
    RecoveryRequired,
}

impl RunMarkerState {
    const fn tag(self) -> u8 {
        match self {
            Self::Clean => 1,
            Self::Active => 2,
            Self::RecoveryRequired => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, RecoveryRequired> {
        match tag {
            1 => Ok(Self::Clean),
            2 => Ok(Self::Active),
            3 => Ok(Self::RecoveryRequired),
            _ => Err(RecoveryRequired::MalformedRunMarker),
        }
    }
}

/// Stable fail-closed classifications produced by the durable model.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum RecoveryRequired {
    /// The expected installation identity was an invalid all-zero sentinel.
    #[error("the fixed installation identity is invalid")]
    InvalidInstallationIdentity,
    /// The synthetic fixture authentication provider received an invalid provider.
    #[cfg(test)]
    #[error("the fixture run-state authentication provider is invalid")]
    InvalidFixtureAuthenticationKey,
    /// No durable run marker was observed.
    #[error("the durable run marker is missing")]
    MissingRunMarker,
    /// No independent high-water checkpoint was observed.
    #[error("the durable run-state high-water checkpoint is missing")]
    MissingHighWaterCheckpoint,
    /// The run marker was not the exact canonical V1 envelope.
    #[error("the durable run marker is malformed")]
    MalformedRunMarker,
    /// The high-water checkpoint was not the exact canonical V1 envelope.
    #[error("the durable run-state high-water checkpoint is malformed")]
    MalformedHighWaterCheckpoint,
    /// An authenticated envelope did not verify under the sealed provider.
    #[error("durable run-state authentication failed")]
    AuthenticationFailed,
    /// Marker, checkpoint, or writer authority named another installation.
    #[error("the durable run-state installation identity mismatched")]
    InstallationIdentityMismatch,
    /// A marker fell below the independent high-water generation.
    #[error("durable run-state rollback was detected")]
    RollbackDetected,
    /// Equal generations carried different authenticated lineage commitments.
    #[error("durable run-state equivocation was detected")]
    EquivocationDetected,
    /// Marker and independent checkpoint generations did not agree.
    #[error("the durable run marker and high-water checkpoint drifted")]
    HighWaterDrift,
    /// The next nonzero generation could not be represented.
    #[error("the durable run-state generation is exhausted")]
    GenerationExhausted,
    /// Startup observed an authenticated non-clean state.
    #[error("the authenticated startup state requires recovery")]
    PersistedNonCleanState,
    /// A single-writer lease was unavailable or already held.
    #[error("the durable run-state single-writer lease is unavailable")]
    WriterLeaseUnavailable,
    /// A writer lease or its release receipt did not match exactly.
    #[error("the durable run-state writer lease mismatched")]
    WriterLeaseMismatch,
    /// An optimistic compare-and-swap did not match the exact prior snapshot.
    #[error("the durable run-state compare-and-swap conflicted")]
    CompareAndSwapConflict,
    /// A claimed commit receipt did not name the exact candidate snapshot.
    #[error("the durable run-state commit receipt mismatched")]
    CommitReceiptMismatch,
    /// Post-commit marker or checkpoint readback drifted.
    #[error("the durable run-state post-commit readback drifted")]
    RereadDrift,
    /// A clean commit remained at the prior authenticated Active state.
    #[error("an ambiguous clean commit reloaded as an active run")]
    AmbiguousCleanCommitNotApplied,
    /// A runtime receipt was produced by another backend instance.
    #[error("the durable run-state backend binding mismatched")]
    BackendBindingMismatch,
    /// The bounded fixture could not allocate another unique backend binding.
    #[error("the durable run-state backend binding is exhausted")]
    BackendBindingExhausted,
    /// The dormant Windows fixed-pair backend failed while logical authority
    /// remained held for terminal retirement.
    #[error("the Windows durable run-state backend failed")]
    WindowsBackendFailure,
    /// Final writer release may or may not have completed.
    #[error("the durable run-state writer release is ambiguous")]
    WriterReleaseAmbiguous,
    /// Fresh-install provisioning observed any pre-existing durable bytes.
    #[error("fresh-install provisioning did not observe an exactly empty run state")]
    InitialProvisioningStateNotEmpty,
    /// A provisioning receipt named another fresh-install authority attempt.
    #[error("the fresh-install provisioning authority attempt mismatched")]
    ProvisioningAttemptMismatch,
    /// A provisioning receipt was not captured in the exact fresh reload round.
    #[error("the fresh-install provisioning reload round mismatched")]
    ProvisioningReloadRoundMismatch,
    /// The bounded fixture could not allocate another provisioning attempt.
    #[error("the fresh-install provisioning authority attempt is exhausted")]
    ProvisioningAttemptExhausted,
    /// The bounded fixture could not allocate another ambiguity reload round.
    #[error("the fresh-install provisioning reload round is exhausted")]
    ProvisioningReloadRoundExhausted,
    /// An ambiguous commit must be resolved by its exact reload path.
    #[error("the ambiguous durable run-state commit requires exact reload")]
    CommitReloadRequired,
    /// An uncertain completed writer release requires terminal reconciliation.
    #[error("the durable run-state writer release requires terminal reconciliation")]
    WriterReleaseReconciliationRequired,
    /// A one-shot backend operation was attempted more than once.
    #[error("the durable run-state one-shot operation was already attempted")]
    OperationAttemptReused,
    /// Receipts were presented outside their exact backend operation phase.
    #[error("the durable run-state backend operation phase mismatched")]
    OperationPhaseMismatch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CommitOperationPhase {
    Ready,
    CommitAttempted,
    CommitReceiptIssued,
    RereadIssued,
}

struct OneShotCommitOperation(Cell<CommitOperationPhase>);

impl OneShotCommitOperation {
    const fn new() -> Self {
        Self(Cell::new(CommitOperationPhase::Ready))
    }

    fn begin_commit(&self) -> Result<(), RecoveryRequired> {
        if self.0.get() != CommitOperationPhase::Ready {
            return Err(RecoveryRequired::OperationAttemptReused);
        }
        self.0.set(CommitOperationPhase::CommitAttempted);
        Ok(())
    }

    fn record_commit_receipt(&self) -> Result<(), RecoveryRequired> {
        if self.0.get() != CommitOperationPhase::CommitAttempted {
            return Err(RecoveryRequired::OperationPhaseMismatch);
        }
        self.0.set(CommitOperationPhase::CommitReceiptIssued);
        Ok(())
    }

    fn begin_reread(&self) -> Result<(), RecoveryRequired> {
        match self.0.get() {
            CommitOperationPhase::CommitReceiptIssued => {
                self.0.set(CommitOperationPhase::RereadIssued);
                Ok(())
            }
            CommitOperationPhase::RereadIssued => Err(RecoveryRequired::OperationAttemptReused),
            CommitOperationPhase::Ready | CommitOperationPhase::CommitAttempted => {
                Err(RecoveryRequired::OperationPhaseMismatch)
            }
        }
    }

    fn has_exact_receipt_pair(&self) -> bool {
        self.0.get() == CommitOperationPhase::RereadIssued
    }

    fn has_unresolved_commit_attempt(&self) -> bool {
        self.0.get() == CommitOperationPhase::CommitAttempted
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReleaseOperationPhase {
    Ready,
    Attempted,
    ReceiptIssued,
}

struct OneShotReleaseOperation(Cell<ReleaseOperationPhase>);

impl OneShotReleaseOperation {
    const fn new() -> Self {
        Self(Cell::new(ReleaseOperationPhase::Ready))
    }

    fn begin_release(&self) -> Result<(), RecoveryRequired> {
        if self.0.get() != ReleaseOperationPhase::Ready {
            return Err(RecoveryRequired::OperationAttemptReused);
        }
        self.0.set(ReleaseOperationPhase::Attempted);
        Ok(())
    }

    fn record_release_receipt(&self) -> Result<(), RecoveryRequired> {
        if self.0.get() != ReleaseOperationPhase::Attempted {
            return Err(RecoveryRequired::OperationPhaseMismatch);
        }
        self.0.set(ReleaseOperationPhase::ReceiptIssued);
        Ok(())
    }

    fn has_exact_receipt(&self) -> bool {
        self.0.get() == ReleaseOperationPhase::ReceiptIssued
    }
}

struct OneShotReloadOperation(Cell<bool>);

impl OneShotReloadOperation {
    const fn new() -> Self {
        Self(Cell::new(false))
    }

    fn record_reload_receipt(&self) -> Result<(), RecoveryRequired> {
        if self.0.replace(true) {
            return Err(RecoveryRequired::OperationAttemptReused);
        }
        Ok(())
    }

    fn has_exact_receipt(&self) -> bool {
        self.0.get()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct BackendBinding(NonZeroU64);

impl fmt::Debug for BackendBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendBinding([REDACTED])")
    }
}

/// Fixed-width installation identity bound into every marker and checkpoint.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct InstallationIdentity([u8; INSTALLATION_IDENTITY_BYTES]);

impl InstallationIdentity {
    /// Imports the exact fixed-width identity selected during installation.
    ///
    /// # Errors
    ///
    /// Returns recovery-required evidence for the all-zero sentinel.
    pub(super) fn from_fixed_bytes(
        bytes: [u8; INSTALLATION_IDENTITY_BYTES],
    ) -> Result<Self, RecoveryRequired> {
        if bytes == [0; INSTALLATION_IDENTITY_BYTES] {
            return Err(RecoveryRequired::InvalidInstallationIdentity);
        }
        Ok(Self(bytes))
    }

    const fn as_bytes(&self) -> &[u8; INSTALLATION_IDENTITY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for InstallationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallationIdentity([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Commitment([u8; COMMITMENT_BYTES]);

impl Commitment {
    const ZERO: Self = Self([0; COMMITMENT_BYTES]);

    const fn as_bytes(&self) -> &[u8; COMMITMENT_BYTES] {
        &self.0
    }

    fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FixedObservation<const BYTES: usize> {
    Missing,
    Malformed,
    Exact([u8; BYTES]),
}

impl<const BYTES: usize> FixedObservation<BYTES> {
    fn capture(observed: Option<&[u8]>) -> Self {
        let Some(bytes) = observed else {
            return Self::Missing;
        };
        let Ok(exact) = <[u8; BYTES]>::try_from(bytes) else {
            return Self::Malformed;
        };
        Self::Exact(exact)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SnapshotObservation {
    marker: FixedObservation<RUN_MARKER_BYTES>,
    checkpoint: FixedObservation<HIGH_WATER_BYTES>,
}

impl SnapshotObservation {
    fn capture(marker: Option<&[u8]>, checkpoint: Option<&[u8]>) -> Self {
        Self {
            marker: FixedObservation::capture(marker),
            checkpoint: FixedObservation::capture(checkpoint),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CanonicalSnapshot {
    marker: [u8; RUN_MARKER_BYTES],
    checkpoint: [u8; HIGH_WATER_BYTES],
}

impl CanonicalSnapshot {
    const fn observation(self) -> SnapshotObservation {
        SnapshotObservation {
            marker: FixedObservation::Exact(self.marker),
            checkpoint: FixedObservation::Exact(self.checkpoint),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct VerifiedRunMarker {
    state: RunMarkerState,
    generation: NonZeroU64,
    installation: InstallationIdentity,
    predecessor: Commitment,
    current: Commitment,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct VerifiedHighWaterCheckpoint {
    generation: NonZeroU64,
    installation: InstallationIdentity,
    predecessor: Commitment,
    current: Commitment,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DurableSnapshot {
    bytes: CanonicalSnapshot,
    marker: VerifiedRunMarker,
}

/// Test-only, authority-free inspection of one authenticated durable pair.
///
/// Runtime boot cannot retain this observation and later bind a writer to it.
/// The fixture's runtime path instead acquires its writer first and captures a
/// fresh observation while that exact writer remains held.
#[cfg(test)]
pub(super) struct StartupObservationInspection {
    durable: DurableSnapshot,
}

#[cfg(test)]
impl StartupObservationInspection {
    fn from_durable_bytes(
        marker: Option<&[u8]>,
        checkpoint: Option<&[u8]>,
        expected_installation: InstallationIdentity,
        provider: &RunStateAuthenticationProvider,
    ) -> Result<Self, RecoveryRequired> {
        if expected_installation != provider.installation() {
            return Err(RecoveryRequired::InstallationIdentityMismatch);
        }
        let observed = SnapshotObservation::capture(marker, checkpoint);
        verify_observation(&observed, provider).map(|durable| Self { durable })
    }

    /// Returns the authenticated state without exposing its raw envelope.
    #[must_use]
    pub(super) const fn state(&self) -> RunMarkerState {
        self.durable.marker.state
    }

    /// Returns the authenticated nonzero generation.
    #[must_use]
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.durable.marker.generation
    }
}

#[cfg(test)]
impl fmt::Debug for StartupObservationInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupObservationInspection")
            .field("state", &self.durable.marker.state)
            .field("generation", &"[REDACTED]")
            .field("installation", &"[REDACTED]")
            .field("commitment", &"[REDACTED]")
            .field("checkpoint", &"[REDACTED]")
            .finish()
    }
}

/// Move-only proof that one external writer lease is held.
///
/// The constructor records an already-proven exclusive acquisition; this pure
/// model does not acquire an OS lock itself.
pub(super) struct SingleWriterLease<'provider> {
    authority: RuntimeRunStateAuthority<'provider>,
    epoch: NonZeroU64,
    binding: BackendBinding,
}

impl<'provider> SingleWriterLease<'provider> {
    const fn from_exclusive_acquisition(
        authority: RuntimeRunStateAuthority<'provider>,
        epoch: NonZeroU64,
        binding: BackendBinding,
    ) -> Self {
        Self {
            authority,
            epoch,
            binding,
        }
    }

    const fn installation(&self) -> InstallationIdentity {
        self.authority.installation()
    }
}

impl fmt::Debug for SingleWriterLease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleWriterLease([REDACTED])")
    }
}

/// Move-only runtime-start state proving the writer was acquired before any
/// marker or checkpoint observation was captured.
pub(super) struct RuntimeWriterAcquired<'provider> {
    lease: SingleWriterLease<'provider>,
}

impl<'provider> RuntimeWriterAcquired<'provider> {
    /// Seals one already-held external writer into the shared Phase 2D model.
    ///
    /// The caller must have acquired the external writer before capturing the
    /// observation supplied to [`Self::authenticate_observation`].
    const fn from_exclusive_acquisition(
        authority: RuntimeRunStateAuthority<'provider>,
        epoch: NonZeroU64,
        binding: BackendBinding,
    ) -> Self {
        Self {
            lease: SingleWriterLease::from_exclusive_acquisition(authority, epoch, binding),
        }
    }

    /// Authenticates one writer-bound observation through the same sealed
    /// helper used by the bounded Phase 2D fixture.
    #[allow(clippy::large_types_passed_by_value)] // The exact pair is consumed once.
    fn authenticate_observation(
        self,
        observed: SnapshotObservation,
    ) -> Result<BootEvidence<'provider>, DurableFailureWithWriter<'provider>> {
        let Self { lease } = self;
        let durable = match lease.authority.verify_observation(&observed) {
            Ok(durable) => durable,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        if durable.marker.state != RunMarkerState::Clean {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::PersistedNonCleanState,
                lease,
            ));
        }
        Ok(BootEvidence { durable, lease })
    }

    /// Converts a pre-authentication writer into terminal-only logical state.
    #[must_use]
    fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }
}

impl fmt::Debug for RuntimeWriterAcquired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeWriterAcquired([REDACTED])")
    }
}

/// Runtime authority retained when boot fails before writer acquisition.
#[must_use]
pub(super) struct RuntimeBootBeforeWriterFailure<'provider> {
    reason: RecoveryRequired,
    _authority: RuntimeRunStateAuthority<'provider>,
}

impl<'provider> RuntimeBootBeforeWriterFailure<'provider> {
    const fn new(reason: RecoveryRequired, authority: RuntimeRunStateAuthority<'provider>) -> Self {
        Self {
            reason,
            _authority: authority,
        }
    }

    /// Returns the stable fail-closed reason without exposing runtime authority.
    #[must_use]
    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }
}

impl fmt::Debug for RuntimeBootBeforeWriterFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeBootBeforeWriterFailure")
            .field("reason", &self.reason)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimeBootBeforeWriterFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "runtime boot failed before writer acquisition: {}",
            self.reason
        )
    }
}

impl std::error::Error for RuntimeBootBeforeWriterFailure<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

/// Stable classification for runtime boot failures before or after writer
/// acquisition. Both arms retain the consumed provider-bound authority.
#[must_use]
pub(super) enum RuntimeBootStartFailure<'provider> {
    /// No writer was acquired, so no release obligation exists, but the
    /// consumed runtime authority remains terminally retained.
    BeforeWriter(RuntimeBootBeforeWriterFailure<'provider>),
    /// The exact runtime writer remains held and must retire terminally.
    WithWriter(DurableFailureWithWriter<'provider>),
}

impl<'provider> RuntimeBootStartFailure<'provider> {
    /// Returns the stable fail-closed reason without exposing writer authority.
    #[must_use]
    pub(super) const fn reason(&self) -> RecoveryRequired {
        match self {
            Self::BeforeWriter(failure) => failure.reason(),
            Self::WithWriter(failure) => failure.reason(),
        }
    }

    /// Consumes the failure, returning the terminal writer obligation exactly
    /// when acquisition had completed.
    pub(super) fn into_writer_exit(
        self,
    ) -> Result<
        (RecoveryRequired, WriterExitPending<'provider>),
        RuntimeBootBeforeWriterFailure<'provider>,
    > {
        match self {
            Self::BeforeWriter(failure) => Err(failure),
            Self::WithWriter(failure) => {
                let reason = failure.reason();
                Ok((reason, failure.into_writer_exit()))
            }
        }
    }
}

impl fmt::Debug for RuntimeBootStartFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeBootStartFailure")
            .field(
                "phase",
                &match self {
                    Self::BeforeWriter(_) => "before-writer",
                    Self::WithWriter(_) => "with-writer",
                },
            )
            .field("reason", &self.reason())
            .field("writer", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for RuntimeBootStartFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeWriter(failure) => fmt::Display::fmt(failure, formatter),
            Self::WithWriter(failure) => write!(
                formatter,
                "runtime boot failed after writer acquisition: {}; terminal writer retirement is required",
                failure.reason()
            ),
        }
    }
}

impl std::error::Error for RuntimeBootStartFailure<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BeforeWriter(failure) => Some(&failure.reason),
            Self::WithWriter(failure) => Some(&failure.reason),
        }
    }
}

/// Clean startup evidence bound to exactly one writer lease.
pub(super) struct BootEvidence<'provider> {
    durable: DurableSnapshot,
    lease: SingleWriterLease<'provider>,
}

impl<'provider> BootEvidence<'provider> {
    /// Consumes boot evidence and prepares the exact successor Active snapshot.
    ///
    /// # Errors
    ///
    /// Returns recovery-required evidence when the held snapshot does not
    /// authenticate under the lease-owned provider, the generation is exhausted,
    /// or fixture authentication cannot construct the canonical successor.
    pub(super) fn prepare_active(
        self,
    ) -> Result<PreparedActiveTransition<'provider>, DurableFailureWithWriter<'provider>> {
        let Self { durable, lease } = self;
        let authenticated_prior = match lease
            .authority
            .verify_observation(&durable.bytes.observation())
        {
            Ok(authenticated_prior) => authenticated_prior,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        if authenticated_prior != durable {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::EquivocationDetected,
                lease,
            ));
        }
        let generation = match next_generation(durable.marker.generation) {
            Ok(generation) => generation,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        let successor = match lease.authority.build_snapshot(
            RunMarkerState::Active,
            generation,
            durable.marker.current,
        ) {
            Ok(successor) => successor,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        Ok(PreparedActiveTransition {
            prior: durable,
            successor,
            lease,
            operation: OneShotCommitOperation::new(),
        })
    }

    /// Abandons startup without allowing any runtime or clean authority.
    pub(super) fn abort(self, reason: RecoveryRequired) -> DurableFailureWithWriter<'provider> {
        DurableFailureWithWriter::new(reason, self.lease)
    }

    /// Retires the writer for a non-durable lifecycle failure.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }

    /// Returns the authenticated clean generation without exposing raw bytes.
    #[must_use]
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.durable.marker.generation
    }
}

impl fmt::Debug for BootEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootEvidence([REDACTED])")
    }
}

/// Exact Active transition awaiting durable commit and post-commit readback.
pub(super) struct PreparedActiveTransition<'provider> {
    prior: DurableSnapshot,
    successor: DurableSnapshot,
    lease: SingleWriterLease<'provider>,
    operation: OneShotCommitOperation,
}

impl<'provider> PreparedActiveTransition<'provider> {
    const fn expected_marker_bytes(&self) -> &[u8; RUN_MARKER_BYTES] {
        &self.prior.bytes.marker
    }

    const fn expected_checkpoint_bytes(&self) -> &[u8; HIGH_WATER_BYTES] {
        &self.prior.bytes.checkpoint
    }

    const fn candidate_marker_bytes(&self) -> &[u8; RUN_MARKER_BYTES] {
        &self.successor.bytes.marker
    }

    const fn candidate_checkpoint_bytes(&self) -> &[u8; HIGH_WATER_BYTES] {
        &self.successor.bytes.checkpoint
    }

    /// Verifies distinct commit and reread receipts, minting runtime authority.
    ///
    /// # Errors
    ///
    /// A lease mismatch, CAS/commit mismatch, missing readback, or any readback
    /// drift requires recovery and never returns runtime authority.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn complete(
        self,
        committed: CommittedActiveMarker,
        reread: RereadActiveMarker,
    ) -> Result<ActiveRunLease<'provider>, DurableFailureWithWriter<'provider>> {
        let Self {
            prior: _,
            successor,
            lease,
            operation,
        } = self;
        let CommittedActiveMarker {
            observed: committed_observation,
            lease_epoch: committed_epoch,
            binding: committed_binding,
        } = committed;
        let RereadActiveMarker {
            observed: reread_observation,
            lease_epoch: reread_epoch,
            binding: reread_binding,
        } = reread;
        if committed_binding != lease.binding || reread_binding != lease.binding {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::BackendBindingMismatch,
                lease,
            ));
        }
        if committed_epoch != lease.epoch || reread_epoch != lease.epoch {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::WriterLeaseMismatch,
                lease,
            ));
        }
        if !operation.has_exact_receipt_pair() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                lease,
            ));
        }
        if committed_observation != successor.bytes.observation() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::CommitReceiptMismatch,
                lease,
            ));
        }
        if reread_observation != successor.bytes.observation() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::RereadDrift,
                lease,
            ));
        }
        Ok(ActiveRunLease {
            durable: successor,
            lease,
        })
    }

    /// Consumes an ambiguous commit into mandatory reload state.
    #[must_use]
    pub(super) fn commit_ambiguous(self) -> ActiveReloadRequired<'provider> {
        ActiveReloadRequired {
            prior: self.prior,
            successor: self.successor,
            lease: self.lease,
            operation: OneShotReloadOperation::new(),
        }
    }

    /// Abandons a known failed commit without allowing runtime authority.
    pub(super) fn abort(self, reason: RecoveryRequired) -> DurableFailureWithWriter<'provider> {
        DurableFailureWithWriter::new(reason, self.lease)
    }

    /// Retires the writer for a non-durable lifecycle failure.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }
}

impl fmt::Debug for PreparedActiveTransition<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedActiveTransition([REDACTED])")
    }
}

/// Backend receipt claiming the exact Active marker/checkpoint commit.
#[derive(Eq, PartialEq)]
pub(super) struct CommittedActiveMarker {
    observed: SnapshotObservation,
    lease_epoch: NonZeroU64,
    binding: BackendBinding,
}

impl CommittedActiveMarker {
    fn from_durable_observation(
        marker: Option<&[u8]>,
        checkpoint: Option<&[u8]>,
        lease_epoch: NonZeroU64,
        binding: BackendBinding,
    ) -> Self {
        Self {
            observed: SnapshotObservation::capture(marker, checkpoint),
            lease_epoch,
            binding,
        }
    }
}

impl fmt::Debug for CommittedActiveMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedActiveMarker([REDACTED])")
    }
}

/// Independent post-commit Active marker/checkpoint reread receipt.
pub(super) struct RereadActiveMarker {
    observed: SnapshotObservation,
    lease_epoch: NonZeroU64,
    binding: BackendBinding,
}

impl RereadActiveMarker {
    fn from_durable_observation(
        marker: Option<&[u8]>,
        checkpoint: Option<&[u8]>,
        lease_epoch: NonZeroU64,
        binding: BackendBinding,
    ) -> Self {
        Self {
            observed: SnapshotObservation::capture(marker, checkpoint),
            lease_epoch,
            binding,
        }
    }
}

impl fmt::Debug for RereadActiveMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RereadActiveMarker([REDACTED])")
    }
}

/// Runtime authority available only after exact Active commit and reread.
pub(super) struct ActiveRunLease<'provider> {
    durable: DurableSnapshot,
    lease: SingleWriterLease<'provider>,
}

impl<'provider> ActiveRunLease<'provider> {
    /// Returns the authenticated Active generation.
    #[must_use]
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.durable.marker.generation
    }

    /// Prepares the exact successor Clean state while retaining the writer.
    ///
    /// # Errors
    ///
    /// A held snapshot that does not authenticate under the lease-owned provider,
    /// generation exhaustion, or canonical construction failure retains only a
    /// terminal writer-exit authority.
    pub(super) fn prepare_clean(
        self,
    ) -> Result<PreparedCleanTransition<'provider>, DurableFailureWithWriter<'provider>> {
        let Self { durable, lease } = self;
        let authenticated_prior = match lease
            .authority
            .verify_observation(&durable.bytes.observation())
        {
            Ok(authenticated_prior) => authenticated_prior,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        if authenticated_prior != durable {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::EquivocationDetected,
                lease,
            ));
        }
        let generation = match next_generation(durable.marker.generation) {
            Ok(generation) => generation,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        let successor = match lease.authority.build_snapshot(
            RunMarkerState::Clean,
            generation,
            durable.marker.current,
        ) {
            Ok(successor) => successor,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        Ok(PreparedCleanTransition {
            prior: durable,
            successor,
            lease,
            operation: OneShotCommitOperation::new(),
        })
    }

    /// Abandons runtime without creating clean or stopped evidence.
    pub(super) fn abort(self, reason: RecoveryRequired) -> DurableFailureWithWriter<'provider> {
        DurableFailureWithWriter::new(reason, self.lease)
    }

    /// Retires the writer for a non-durable lifecycle failure.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }
}

impl fmt::Debug for ActiveRunLease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveRunLease([REDACTED])")
    }
}

/// Exact Clean transition awaiting durable commit and independent reread while
/// the same writer lease remains held.
pub(super) struct PreparedCleanTransition<'provider> {
    prior: DurableSnapshot,
    successor: DurableSnapshot,
    lease: SingleWriterLease<'provider>,
    operation: OneShotCommitOperation,
}

impl<'provider> PreparedCleanTransition<'provider> {
    const fn expected_marker_bytes(&self) -> &[u8; RUN_MARKER_BYTES] {
        &self.prior.bytes.marker
    }

    const fn expected_checkpoint_bytes(&self) -> &[u8; HIGH_WATER_BYTES] {
        &self.prior.bytes.checkpoint
    }

    const fn candidate_marker_bytes(&self) -> &[u8; RUN_MARKER_BYTES] {
        &self.successor.bytes.marker
    }

    const fn candidate_checkpoint_bytes(&self) -> &[u8; HIGH_WATER_BYTES] {
        &self.successor.bytes.checkpoint
    }

    /// Verifies distinct Clean commit and reread receipts.
    ///
    /// # Errors
    ///
    /// CAS/commit mismatch or any missing/drifting reread requires recovery and
    /// never returns stopped evidence.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn complete(
        self,
        committed: CommittedCleanMarker,
        reread: RereadCleanMarker,
    ) -> Result<CleanCommittedWithWriter<'provider>, DurableFailureWithWriter<'provider>> {
        let Self {
            prior: _,
            successor,
            lease,
            operation,
        } = self;
        let CommittedCleanMarker {
            observed: committed_observation,
            lease_epoch: committed_epoch,
            binding: committed_binding,
        } = committed;
        let RereadCleanMarker {
            observed: reread_observation,
            lease_epoch: reread_epoch,
            binding: reread_binding,
        } = reread;
        if committed_binding != lease.binding || reread_binding != lease.binding {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::BackendBindingMismatch,
                lease,
            ));
        }
        if committed_epoch != lease.epoch || reread_epoch != lease.epoch {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::WriterLeaseMismatch,
                lease,
            ));
        }
        if !operation.has_exact_receipt_pair() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                lease,
            ));
        }
        if committed_observation != successor.bytes.observation() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::CommitReceiptMismatch,
                lease,
            ));
        }
        if reread_observation != successor.bytes.observation() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::RereadDrift,
                lease,
            ));
        }
        Ok(CleanCommittedWithWriter {
            durable: successor,
            lease,
        })
    }

    /// Consumes an ambiguous Clean commit into mandatory reload state.
    ///
    /// Reload restores Clean-with-writer authority only when both the marker
    /// and independent checkpoint are the exact same authenticated Clean
    /// candidate. A one-sided advance or any uncertainty requires recovery.
    #[must_use]
    pub(super) fn commit_ambiguous(self) -> CleanReloadRequired<'provider> {
        CleanReloadRequired {
            prior: self.prior,
            successor: self.successor,
            lease: self.lease,
            operation: OneShotReloadOperation::new(),
        }
    }

    /// Abandons a known failed Clean commit without stopped evidence.
    pub(super) fn abort(self, reason: RecoveryRequired) -> DurableFailureWithWriter<'provider> {
        DurableFailureWithWriter::new(reason, self.lease)
    }

    /// Retires the writer for a non-durable lifecycle failure.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }
}

impl fmt::Debug for PreparedCleanTransition<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedCleanTransition([REDACTED])")
    }
}

/// Backend receipt claiming the exact Clean marker/checkpoint commit.
#[derive(Eq, PartialEq)]
pub(super) struct CommittedCleanMarker {
    observed: SnapshotObservation,
    lease_epoch: NonZeroU64,
    binding: BackendBinding,
}

impl CommittedCleanMarker {
    fn from_durable_observation(
        marker: Option<&[u8]>,
        checkpoint: Option<&[u8]>,
        lease_epoch: NonZeroU64,
        binding: BackendBinding,
    ) -> Self {
        Self {
            observed: SnapshotObservation::capture(marker, checkpoint),
            lease_epoch,
            binding,
        }
    }
}

impl fmt::Debug for CommittedCleanMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedCleanMarker([REDACTED])")
    }
}

/// Independent post-commit Clean marker/checkpoint reread receipt.
pub(super) struct RereadCleanMarker {
    observed: SnapshotObservation,
    lease_epoch: NonZeroU64,
    binding: BackendBinding,
}

impl RereadCleanMarker {
    fn from_durable_observation(
        marker: Option<&[u8]>,
        checkpoint: Option<&[u8]>,
        lease_epoch: NonZeroU64,
        binding: BackendBinding,
    ) -> Self {
        Self {
            observed: SnapshotObservation::capture(marker, checkpoint),
            lease_epoch,
            binding,
        }
    }
}

impl fmt::Debug for RereadCleanMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RereadCleanMarker([REDACTED])")
    }
}

/// Exact authenticated Clean state that still owns the original writer.
pub(super) struct CleanCommittedWithWriter<'provider> {
    durable: DurableSnapshot,
    lease: SingleWriterLease<'provider>,
}

impl<'provider> CleanCommittedWithWriter<'provider> {
    /// Returns the authenticated Clean generation while the writer is held.
    #[must_use]
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.durable.marker.generation
    }

    /// Begins the sole normal final writer-release path.
    #[must_use]
    pub(super) fn prepare_writer_release(self) -> PendingFinalWriterRelease<'provider> {
        PendingFinalWriterRelease {
            durable: self.durable,
            lease: self.lease,
            operation: OneShotReleaseOperation::new(),
        }
    }

    /// Abandons normal stop reporting and retains terminal-only retirement.
    pub(super) fn abort(self, reason: RecoveryRequired) -> DurableFailureWithWriter<'provider> {
        DurableFailureWithWriter::new(reason, self.lease)
    }

    /// Retires the writer for a non-durable lifecycle failure.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }
}

impl fmt::Debug for CleanCommittedWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanCommittedWithWriter([REDACTED])")
    }
}

/// Clean evidence waiting for the exact final writer-release receipt.
pub(super) struct PendingFinalWriterRelease<'provider> {
    durable: DurableSnapshot,
    lease: SingleWriterLease<'provider>,
    operation: OneShotReleaseOperation,
}

impl<'provider> PendingFinalWriterRelease<'provider> {
    /// Verifies exact release and mints the sole stopped evidence.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn complete(
        self,
        receipt: WriterLeaseReleaseReceipt,
    ) -> Result<StoppedRunEvidence<'provider>, DurableFailureWithWriter<'provider>> {
        let Self {
            durable,
            lease,
            operation,
        } = self;
        if receipt.binding != lease.binding {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::BackendBindingMismatch,
                lease,
            ));
        }
        if receipt.installation != lease.installation() || receipt.epoch != lease.epoch {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::WriterLeaseMismatch,
                lease,
            ));
        }
        if !operation.has_exact_receipt() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                lease,
            ));
        }
        let SingleWriterLease { authority, .. } = lease;
        Ok(StoppedRunEvidence {
            durable,
            _authority: authority,
        })
    }

    /// Converts known or ambiguous release failure into terminal-only state.
    pub(super) fn abort(self, reason: RecoveryRequired) -> DurableFailureWithWriter<'provider> {
        DurableFailureWithWriter::new(reason, self.lease)
    }

    /// Retires or reconciles the writer for a non-durable lifecycle failure.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }
}

impl fmt::Debug for PendingFinalWriterRelease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingFinalWriterRelease([REDACTED])")
    }
}

/// Move-only exact receipt proving the final writer was released.
pub(super) struct WriterLeaseReleaseReceipt {
    installation: InstallationIdentity,
    epoch: NonZeroU64,
    binding: BackendBinding,
}

impl WriterLeaseReleaseReceipt {
    const fn from_release_readback(
        installation: InstallationIdentity,
        epoch: NonZeroU64,
        binding: BackendBinding,
    ) -> Self {
        Self {
            installation,
            epoch,
            binding,
        }
    }
}

impl fmt::Debug for WriterLeaseReleaseReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WriterLeaseReleaseReceipt([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WriterObservation {
    Missing,
    Held {
        installation: InstallationIdentity,
        epoch: NonZeroU64,
    },
}

fn writer_observation_matches(observed: WriterObservation, lease: &SingleWriterLease<'_>) -> bool {
    observed
        == (WriterObservation::Held {
            installation: lease.installation(),
            epoch: lease.epoch,
        })
}

/// Move-only state entered after an ambiguous Active commit.
pub(super) struct ActiveReloadRequired<'provider> {
    prior: DurableSnapshot,
    successor: DurableSnapshot,
    lease: SingleWriterLease<'provider>,
    operation: OneShotReloadOperation,
}

impl<'provider> ActiveReloadRequired<'provider> {
    /// Consumes an independently captured backend reload receipt.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn complete_reload(
        self,
        receipt: ActiveReloadReceipt,
    ) -> Result<ReloadedActiveRunState<'provider>, DurableFailureWithWriter<'provider>> {
        let Self {
            prior,
            successor,
            lease,
            operation,
        } = self;
        if receipt.binding != lease.binding {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::BackendBindingMismatch,
                lease,
            ));
        }
        if !writer_observation_matches(receipt.writer, &lease) {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::WriterLeaseMismatch,
                lease,
            ));
        }
        if !operation.has_exact_receipt() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                lease,
            ));
        }
        let durable = match lease.authority.verify_observation(&receipt.observed) {
            Ok(durable) => durable,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        if durable == successor {
            return Ok(ReloadedActiveRunState::Active(ActiveRunLease {
                durable,
                lease,
            }));
        }
        if durable == prior {
            return Ok(ReloadedActiveRunState::Boot(BootEvidence {
                durable,
                lease,
            }));
        }
        Err(DurableFailureWithWriter::new(
            classify_unknown_reload(&durable, &prior),
            lease,
        ))
    }

    /// Abandons reload without restoring boot or runtime authority.
    pub(super) fn abort(self, reason: RecoveryRequired) -> DurableFailureWithWriter<'provider> {
        DurableFailureWithWriter::new(reason, self.lease)
    }

    /// Retires the writer for a non-durable lifecycle failure.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }
}

impl fmt::Debug for ActiveReloadRequired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveReloadRequired([REDACTED])")
    }
}

/// Backend-bound Active reload observation.
pub(super) struct ActiveReloadReceipt {
    observed: SnapshotObservation,
    writer: WriterObservation,
    binding: BackendBinding,
}

impl fmt::Debug for ActiveReloadReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveReloadReceipt([REDACTED])")
    }
}

/// Exact resolution of an ambiguous Active commit.
pub(super) enum ReloadedActiveRunState<'provider> {
    /// Active commit did not apply; exact prior Clean boot evidence was restored.
    Boot(BootEvidence<'provider>),
    /// Active commit applied completely; runtime authority was restored.
    Active(ActiveRunLease<'provider>),
}

impl fmt::Debug for ReloadedActiveRunState<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boot(_) => formatter.write_str("ReloadedActiveRunState::Boot([REDACTED])"),
            Self::Active(_) => formatter.write_str("ReloadedActiveRunState::Active([REDACTED])"),
        }
    }
}

/// Move-only state entered after an ambiguous Clean commit.
pub(super) struct CleanReloadRequired<'provider> {
    prior: DurableSnapshot,
    successor: DurableSnapshot,
    lease: SingleWriterLease<'provider>,
    operation: OneShotReloadOperation,
}

impl<'provider> CleanReloadRequired<'provider> {
    /// Exact Clean reload restores Clean-with-writer, never stopped evidence.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn complete_reload(
        self,
        receipt: CleanReloadReceipt,
    ) -> Result<CleanCommittedWithWriter<'provider>, DurableFailureWithWriter<'provider>> {
        let Self {
            prior,
            successor,
            lease,
            operation,
        } = self;
        if receipt.binding != lease.binding {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::BackendBindingMismatch,
                lease,
            ));
        }
        if !writer_observation_matches(receipt.writer, &lease) {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::WriterLeaseMismatch,
                lease,
            ));
        }
        if !operation.has_exact_receipt() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                lease,
            ));
        }
        let durable = match lease.authority.verify_observation(&receipt.observed) {
            Ok(durable) => durable,
            Err(reason) => return Err(DurableFailureWithWriter::new(reason, lease)),
        };
        if durable == successor {
            return Ok(CleanCommittedWithWriter { durable, lease });
        }
        let reason = if durable == prior {
            RecoveryRequired::AmbiguousCleanCommitNotApplied
        } else {
            classify_unknown_reload(&durable, &prior)
        };
        Err(DurableFailureWithWriter::new(reason, lease))
    }

    /// Abandons reload without producing Clean or stopped authority.
    pub(super) fn abort(self, reason: RecoveryRequired) -> DurableFailureWithWriter<'provider> {
        DurableFailureWithWriter::new(reason, self.lease)
    }

    /// Retires the writer for a non-durable lifecycle failure.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        WriterExitPending::new(self.lease)
    }
}

impl fmt::Debug for CleanReloadRequired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanReloadRequired([REDACTED])")
    }
}

/// Backend-bound Clean reload observation.
pub(super) struct CleanReloadReceipt {
    observed: SnapshotObservation,
    writer: WriterObservation,
    binding: BackendBinding,
}

impl fmt::Debug for CleanReloadReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanReloadReceipt([REDACTED])")
    }
}

/// Terminal-only durable failure that still owns the exact writer.
#[must_use]
pub(super) struct DurableFailureWithWriter<'provider> {
    reason: RecoveryRequired,
    exit: WriterExitPending<'provider>,
}

impl<'provider> DurableFailureWithWriter<'provider> {
    fn new(reason: RecoveryRequired, lease: SingleWriterLease<'provider>) -> Self {
        Self {
            reason,
            exit: WriterExitPending::new(lease),
        }
    }

    /// Returns the stable fail-closed reason without exposing writer authority.
    #[must_use]
    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    /// Consumes the failure into its sole terminal writer-retirement path.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> WriterExitPending<'provider> {
        self.exit
    }
}

impl fmt::Debug for DurableFailureWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableFailureWithWriter")
            .field("reason", &self.reason)
            .field("exit", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for DurableFailureWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; terminal writer retirement is required",
            self.reason
        )
    }
}

impl std::error::Error for DurableFailureWithWriter<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

/// Move-only writer authority that can only retire for process exit.
pub(super) struct WriterExitPending<'provider> {
    lease: SingleWriterLease<'provider>,
    operation: OneShotReleaseOperation,
}

impl<'provider> WriterExitPending<'provider> {
    const fn new(lease: SingleWriterLease<'provider>) -> Self {
        Self {
            lease,
            operation: OneShotReleaseOperation::new(),
        }
    }

    /// Verifies exact retirement/reconciliation and yields no reusable authority.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn complete(
        self,
        receipt: WriterExitReceipt,
    ) -> Result<RecoveryExitEvidence<'provider>, DurableFailureWithWriter<'provider>> {
        let Self { lease, operation } = self;
        if receipt.binding != lease.binding {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::BackendBindingMismatch,
                lease,
            ));
        }
        if receipt.installation != lease.installation() || receipt.epoch != lease.epoch {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::WriterLeaseMismatch,
                lease,
            ));
        }
        if !operation.has_exact_receipt() {
            return Err(DurableFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                lease,
            ));
        }
        let SingleWriterLease { authority, .. } = lease;
        Ok(RecoveryExitEvidence {
            _binding: receipt.binding,
            _authority: authority,
        })
    }
}

impl fmt::Debug for WriterExitPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WriterExitPending([REDACTED])")
    }
}

/// Exact terminal retirement receipt; it cannot mint normal lifecycle state.
pub(super) struct WriterExitReceipt {
    installation: InstallationIdentity,
    epoch: NonZeroU64,
    binding: BackendBinding,
}

impl fmt::Debug for WriterExitReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WriterExitReceipt([REDACTED])")
    }
}

/// Opaque evidence that terminal writer retirement completed.
pub(super) struct RecoveryExitEvidence<'provider> {
    _binding: BackendBinding,
    _authority: RuntimeRunStateAuthority<'provider>,
}

impl fmt::Debug for RecoveryExitEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryExitEvidence([REDACTED])")
    }
}

/// Opaque proof of one exact authenticated Clean state after final release.
pub(super) struct StoppedRunEvidence<'provider> {
    durable: DurableSnapshot,
    _authority: RuntimeRunStateAuthority<'provider>,
}

impl StoppedRunEvidence<'_> {
    /// Returns the authenticated Clean generation.
    #[must_use]
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.durable.marker.generation
    }
}

impl fmt::Debug for StoppedRunEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoppedRunEvidence([REDACTED])")
    }
}

fn classify_unknown_reload(durable: &DurableSnapshot, prior: &DurableSnapshot) -> RecoveryRequired {
    if durable.marker.generation < prior.marker.generation {
        RecoveryRequired::RollbackDetected
    } else {
        RecoveryRequired::EquivocationDetected
    }
}

fn next_generation(generation: NonZeroU64) -> Result<NonZeroU64, RecoveryRequired> {
    generation
        .get()
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .ok_or(RecoveryRequired::GenerationExhausted)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DurableRunStateCommitFault {
    /// Complete the exact two-object commit.
    None,
    /// Report a known compare-and-swap conflict before mutation.
    CompareAndSwapConflict,
    /// Return ambiguity before either durable object advances.
    AmbiguousBeforeWrite,
    /// Return ambiguity after only the marker advances.
    AmbiguousAfterMarker,
    /// Return ambiguity after both durable objects advance.
    AmbiguousAfterCheckpoint,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DurableRunStateRereadFault {
    /// Return the exact current marker and checkpoint.
    None,
    /// Omit the marker from post-commit readback.
    MissingMarker,
    /// Return the prior marker with the current checkpoint.
    MarkerDrift,
    /// Return the current marker with the prior checkpoint.
    CheckpointDrift,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum DurableRunStateCommitFailure {
    /// The commit may or may not have reached durable storage.
    #[error("the bounded fixture reported an ambiguous commit")]
    Ambiguous,
    /// A known fail-closed condition requires recovery.
    #[error(transparent)]
    Recovery(#[from] RecoveryRequired),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DurableRunStateReleaseFault {
    /// Complete the exact release and return its exact receipt.
    None,
    /// Return ambiguity while the writer remains held.
    AmbiguousBeforeRelease,
    /// Release the writer, then return ambiguity without a receipt.
    AmbiguousAfterRelease,
    /// Release the writer, then return a deliberately mismatched receipt.
    MismatchedReceiptAfterRelease,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum DurableRunStateReleaseFailure {
    /// Final writer release may or may not have completed.
    #[error("the bounded fixture reported an ambiguous writer release")]
    Ambiguous,
    /// A known fail-closed condition requires recovery.
    #[error(transparent)]
    Recovery(#[from] RecoveryRequired),
}

/// Fixed startup states supported by the bounded test facade.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DurableRunStateFixtureSeed {
    /// Canonical generation-two Active marker and checkpoint.
    Active,
    /// Canonical generation-two persisted recovery marker and checkpoint.
    RecoveryRequired,
    /// Marker absent while the independent checkpoint remains present.
    MissingMarker,
    /// Checkpoint absent while the marker remains present.
    MissingCheckpoint,
    /// Fixed-size marker with an invalid authentication tag.
    Invalid,
}

/// Mutually exclusive writer roles used by the bounded test backend.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FixtureWriterRole {
    /// Ordinary boot/runtime/shutdown writer authority.
    Runtime,
    /// Fresh-install generation-one provisioning writer authority.
    Provisioning,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct FixtureWriterRecord {
    role: FixtureWriterRole,
    installation: InstallationIdentity,
    epoch: NonZeroU64,
    provisioning_attempt: Option<NonZeroU64>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FixtureCommitKind {
    Active,
    Clean,
    InitialClean,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct FixtureCommitAmbiguity {
    kind: FixtureCommitKind,
    writer_epoch: NonZeroU64,
    provisioning_round: Option<NonZeroU64>,
    reload_allowed: bool,
}

#[cfg(test)]
impl FixtureCommitAmbiguity {
    const fn runtime(kind: FixtureCommitKind, writer: FixtureWriterRecord) -> Self {
        Self {
            kind,
            writer_epoch: writer.epoch,
            provisioning_round: None,
            reload_allowed: true,
        }
    }

    const fn terminal_runtime(kind: FixtureCommitKind, writer: FixtureWriterRecord) -> Self {
        Self {
            kind,
            writer_epoch: writer.epoch,
            provisioning_round: None,
            reload_allowed: false,
        }
    }

    pub(super) const fn provisioning(writer: FixtureWriterRecord, round: NonZeroU64) -> Self {
        Self {
            kind: FixtureCommitKind::InitialClean,
            writer_epoch: writer.epoch,
            provisioning_round: Some(round),
            reload_allowed: true,
        }
    }

    pub(super) const fn terminal_provisioning(
        writer: FixtureWriterRecord,
        round: NonZeroU64,
    ) -> Self {
        Self {
            kind: FixtureCommitKind::InitialClean,
            writer_epoch: writer.epoch,
            provisioning_round: Some(round),
            reload_allowed: false,
        }
    }
}

#[cfg(test)]
impl FixtureWriterRecord {
    const fn runtime(installation: InstallationIdentity, epoch: NonZeroU64) -> Self {
        Self {
            role: FixtureWriterRole::Runtime,
            installation,
            epoch,
            provisioning_attempt: None,
        }
    }

    pub(super) const fn provisioning(
        installation: InstallationIdentity,
        epoch: NonZeroU64,
        attempt: NonZeroU64,
    ) -> Self {
        Self {
            role: FixtureWriterRole::Provisioning,
            installation,
            epoch,
            provisioning_attempt: Some(attempt),
        }
    }
}

/// Bounded, allocation-free in-memory backend used only by unit tests.
#[cfg(test)]
pub(super) struct DurableRunStateFixture {
    marker: Option<[u8; RUN_MARKER_BYTES]>,
    checkpoint: Option<[u8; HIGH_WATER_BYTES]>,
    installation: InstallationIdentity,
    binding: BackendBinding,
    held_writer: Option<FixtureWriterRecord>,
    last_released_writer: Option<FixtureWriterRecord>,
    last_writer_epoch: u64,
    last_provisioning_attempt: u64,
    provisioning_reload_round: u64,
    unresolved_commit_ambiguity: Option<FixtureCommitAmbiguity>,
    release_reconciliation: Option<NonZeroU64>,
    commit_fault: DurableRunStateCommitFault,
    reread_fault: DurableRunStateRereadFault,
    release_fault: DurableRunStateReleaseFault,
}

#[cfg(test)]
static NEXT_FIXTURE_BACKEND_BINDING: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
fn allocate_fixture_backend_binding() -> Result<BackendBinding, RecoveryRequired> {
    let value = NEXT_FIXTURE_BACKEND_BINDING
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| RecoveryRequired::BackendBindingExhausted)?;
    NonZeroU64::new(value)
        .map(BackendBinding)
        .ok_or(RecoveryRequired::BackendBindingExhausted)
}

#[cfg(test)]
impl DurableRunStateFixture {
    /// Creates one bounded canonical or faulted startup fixture.
    ///
    /// # Errors
    ///
    /// Returns recovery-required evidence if canonical fixture construction
    /// cannot represent its fixed generation or identity.
    pub(super) fn new(
        seed: DurableRunStateFixtureSeed,
        provider: &RunStateAuthenticationProvider,
        installation: InstallationIdentity,
    ) -> Result<Self, RecoveryRequired> {
        let (state, generation) = match seed {
            DurableRunStateFixtureSeed::MissingMarker
            | DurableRunStateFixtureSeed::MissingCheckpoint
            | DurableRunStateFixtureSeed::Invalid => (RunMarkerState::Clean, 1),
            DurableRunStateFixtureSeed::Active => (RunMarkerState::Active, 2),
            DurableRunStateFixtureSeed::RecoveryRequired => (RunMarkerState::RecoveryRequired, 2),
        };
        let generation = NonZeroU64::new(generation).ok_or(RecoveryRequired::MalformedRunMarker)?;
        let predecessor = if generation.get() == 1 {
            Commitment::ZERO
        } else {
            Commitment([0x31; COMMITMENT_BYTES])
        };
        let mut fixture = Self::seeded(state, generation, installation, predecessor, provider)?;
        match seed {
            DurableRunStateFixtureSeed::MissingMarker => fixture.marker = None,
            DurableRunStateFixtureSeed::MissingCheckpoint => fixture.checkpoint = None,
            DurableRunStateFixtureSeed::Invalid => {
                if let Some(marker) = fixture.marker.as_mut() {
                    marker[RUN_MARKER_BODY_BYTES] ^= 1;
                }
            }
            DurableRunStateFixtureSeed::Active | DurableRunStateFixtureSeed::RecoveryRequired => {}
        }
        Ok(fixture)
    }

    fn seeded(
        state: RunMarkerState,
        generation: NonZeroU64,
        installation: InstallationIdentity,
        predecessor: Commitment,
        provider: &RunStateAuthenticationProvider,
    ) -> Result<Self, RecoveryRequired> {
        if installation != provider.installation() {
            return Err(RecoveryRequired::InstallationIdentityMismatch);
        }
        let durable = build_snapshot(state, generation, predecessor, provider)?;
        Ok(Self {
            marker: Some(durable.bytes.marker),
            checkpoint: Some(durable.bytes.checkpoint),
            installation,
            binding: allocate_fixture_backend_binding()?,
            held_writer: None,
            last_released_writer: None,
            last_writer_epoch: 0,
            last_provisioning_attempt: 0,
            provisioning_reload_round: 0,
            unresolved_commit_ambiguity: None,
            release_reconciliation: None,
            commit_fault: DurableRunStateCommitFault::None,
            reread_fault: DurableRunStateRereadFault::None,
            release_fault: DurableRunStateReleaseFault::None,
        })
    }

    fn marker_bytes(&self) -> Option<&[u8]> {
        self.marker.as_ref().map(<[u8; RUN_MARKER_BYTES]>::as_slice)
    }

    fn checkpoint_bytes(&self) -> Option<&[u8]> {
        self.checkpoint
            .as_ref()
            .map(<[u8; HIGH_WATER_BYTES]>::as_slice)
    }

    fn canonical_snapshot(&self) -> Result<CanonicalSnapshot, RecoveryRequired> {
        let marker = self.marker.ok_or(RecoveryRequired::MissingRunMarker)?;
        let checkpoint = self
            .checkpoint
            .ok_or(RecoveryRequired::MissingHighWaterCheckpoint)?;
        Ok(CanonicalSnapshot { marker, checkpoint })
    }

    /// Acquires the runtime writer before any marker or checkpoint observation.
    ///
    /// Pre-acquisition identity, exclusivity, and unresolved-operation failures
    /// carry no writer obligation.
    pub(super) fn begin_runtime_boot<'provider>(
        &mut self,
        authority: RuntimeRunStateAuthority<'provider>,
    ) -> Result<RuntimeWriterAcquired<'provider>, RuntimeBootStartFailure<'provider>> {
        let installation = authority.installation();
        if installation != self.installation {
            return Err(RuntimeBootStartFailure::BeforeWriter(
                RuntimeBootBeforeWriterFailure::new(
                    RecoveryRequired::InstallationIdentityMismatch,
                    authority,
                ),
            ));
        }
        if self.held_writer.is_some() {
            return Err(RuntimeBootStartFailure::BeforeWriter(
                RuntimeBootBeforeWriterFailure::new(
                    RecoveryRequired::WriterLeaseUnavailable,
                    authority,
                ),
            ));
        }
        if self.release_reconciliation.is_some() {
            return Err(RuntimeBootStartFailure::BeforeWriter(
                RuntimeBootBeforeWriterFailure::new(
                    RecoveryRequired::WriterReleaseReconciliationRequired,
                    authority,
                ),
            ));
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(RuntimeBootStartFailure::BeforeWriter(
                RuntimeBootBeforeWriterFailure::new(
                    RecoveryRequired::CommitReloadRequired,
                    authority,
                ),
            ));
        }
        let Some(epoch) = self
            .last_writer_epoch
            .checked_add(1)
            .and_then(NonZeroU64::new)
        else {
            return Err(RuntimeBootStartFailure::BeforeWriter(
                RuntimeBootBeforeWriterFailure::new(
                    RecoveryRequired::WriterLeaseUnavailable,
                    authority,
                ),
            ));
        };
        self.last_writer_epoch = epoch.get();
        self.held_writer = Some(FixtureWriterRecord::runtime(installation, epoch));
        Ok(RuntimeWriterAcquired::from_exclusive_acquisition(
            authority,
            epoch,
            self.binding,
        ))
    }

    fn writer_observation(&self) -> WriterObservation {
        match self.held_writer {
            Some(FixtureWriterRecord {
                role: FixtureWriterRole::Runtime,
                installation,
                epoch,
                provisioning_attempt: None,
            }) => WriterObservation::Held {
                installation,
                epoch,
            },
            Some(_) | None => WriterObservation::Missing,
        }
    }

    /// Captures authority-free test inspection without acquiring a writer.
    pub(super) fn inspect_startup_for_test(
        &self,
        provider: &RunStateAuthenticationProvider,
        installation: InstallationIdentity,
    ) -> Result<StartupObservationInspection, RecoveryRequired> {
        StartupObservationInspection::from_durable_bytes(
            self.marker_bytes(),
            self.checkpoint_bytes(),
            installation,
            provider,
        )
    }

    /// Consumes the exact acquired writer, verifies that it is still held by
    /// this backend, and only then freshly reads and authenticates both durable
    /// objects.
    pub(super) fn finish_runtime_boot<'provider>(
        &self,
        acquired: RuntimeWriterAcquired<'provider>,
    ) -> Result<BootEvidence<'provider>, RuntimeBootStartFailure<'provider>> {
        if acquired.lease.binding != self.binding {
            return Err(RuntimeBootStartFailure::WithWriter(
                DurableFailureWithWriter::new(
                    RecoveryRequired::BackendBindingMismatch,
                    acquired.lease,
                ),
            ));
        }
        if acquired.lease.installation() != self.installation {
            return Err(RuntimeBootStartFailure::WithWriter(
                DurableFailureWithWriter::new(
                    RecoveryRequired::InstallationIdentityMismatch,
                    acquired.lease,
                ),
            ));
        }
        let expected =
            FixtureWriterRecord::runtime(acquired.lease.installation(), acquired.lease.epoch);
        if self.held_writer != Some(expected) {
            return Err(RuntimeBootStartFailure::WithWriter(
                DurableFailureWithWriter::new(
                    RecoveryRequired::WriterLeaseMismatch,
                    acquired.lease,
                ),
            ));
        }
        let observed = SnapshotObservation::capture(self.marker_bytes(), self.checkpoint_bytes());
        acquired
            .authenticate_observation(observed)
            .map_err(RuntimeBootStartFailure::WithWriter)
    }

    /// Structurally chains writer-first acquisition into the sole fresh
    /// observation path.
    ///
    /// # Errors
    ///
    /// Pre-writer exclusivity failures remain distinct from post-acquisition
    /// durable failures that retain terminal writer retirement.
    pub(super) fn boot<'provider>(
        &mut self,
        authority: RuntimeRunStateAuthority<'provider>,
    ) -> Result<BootEvidence<'provider>, RuntimeBootStartFailure<'provider>> {
        let acquired = self.begin_runtime_boot(authority)?;
        self.finish_runtime_boot(acquired)
    }

    /// Captures a fresh backend-bound Active reload receipt without consuming
    /// the pending durable authority.
    pub(super) fn reload_active(
        &mut self,
        pending: &ActiveReloadRequired<'_>,
    ) -> Result<ActiveReloadReceipt, RecoveryRequired> {
        let expected =
            FixtureWriterRecord::runtime(pending.lease.installation(), pending.lease.epoch);
        if pending.lease.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch);
        }
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch);
        }
        if self.unresolved_commit_ambiguity
            != Some(FixtureCommitAmbiguity::runtime(
                FixtureCommitKind::Active,
                expected,
            ))
        {
            return Err(RecoveryRequired::CommitReloadRequired);
        }
        pending.operation.record_reload_receipt()?;
        self.unresolved_commit_ambiguity = None;
        Ok(ActiveReloadReceipt {
            observed: SnapshotObservation::capture(self.marker_bytes(), self.checkpoint_bytes()),
            writer: self.writer_observation(),
            binding: self.binding,
        })
    }

    /// Captures a fresh backend-bound Clean reload receipt without consuming
    /// the pending durable authority.
    pub(super) fn reload_clean(
        &mut self,
        pending: &CleanReloadRequired<'_>,
    ) -> Result<CleanReloadReceipt, RecoveryRequired> {
        let expected =
            FixtureWriterRecord::runtime(pending.lease.installation(), pending.lease.epoch);
        if pending.lease.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch);
        }
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch);
        }
        if self.unresolved_commit_ambiguity
            != Some(FixtureCommitAmbiguity::runtime(
                FixtureCommitKind::Clean,
                expected,
            ))
        {
            return Err(RecoveryRequired::CommitReloadRequired);
        }
        pending.operation.record_reload_receipt()?;
        self.unresolved_commit_ambiguity = None;
        Ok(CleanReloadReceipt {
            observed: SnapshotObservation::capture(self.marker_bytes(), self.checkpoint_bytes()),
            writer: self.writer_observation(),
            binding: self.binding,
        })
    }

    pub(super) fn set_commit_fault(&mut self, fault: DurableRunStateCommitFault) {
        self.commit_fault = fault;
    }

    pub(super) fn set_reread_fault(&mut self, fault: DurableRunStateRereadFault) {
        self.reread_fault = fault;
    }

    pub(super) fn set_release_fault(&mut self, fault: DurableRunStateReleaseFault) {
        self.release_fault = fault;
    }

    fn take_commit_fault(&mut self) -> DurableRunStateCommitFault {
        let fault = self.commit_fault;
        self.commit_fault = DurableRunStateCommitFault::None;
        fault
    }

    fn take_reread_fault(&mut self) -> DurableRunStateRereadFault {
        let fault = self.reread_fault;
        self.reread_fault = DurableRunStateRereadFault::None;
        fault
    }

    fn take_release_fault(&mut self) -> DurableRunStateReleaseFault {
        let fault = self.release_fault;
        self.release_fault = DurableRunStateReleaseFault::None;
        fault
    }

    pub(super) fn commit_active(
        &mut self,
        transition: &PreparedActiveTransition<'_>,
    ) -> Result<CommittedActiveMarker, DurableRunStateCommitFailure> {
        if transition.lease.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch.into());
        }
        let expected =
            FixtureWriterRecord::runtime(transition.lease.installation(), transition.lease.epoch);
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch.into());
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(RecoveryRequired::CommitReloadRequired.into());
        }
        transition.operation.begin_commit()?;
        if self.marker.as_ref() != Some(transition.expected_marker_bytes())
            || self.checkpoint.as_ref() != Some(transition.expected_checkpoint_bytes())
        {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::terminal_runtime(
                FixtureCommitKind::Active,
                expected,
            ));
            return Err(RecoveryRequired::CompareAndSwapConflict.into());
        }
        let fault = self.take_commit_fault();
        if fault == DurableRunStateCommitFault::CompareAndSwapConflict {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::terminal_runtime(
                FixtureCommitKind::Active,
                expected,
            ));
            return Err(RecoveryRequired::CompareAndSwapConflict.into());
        }
        if fault == DurableRunStateCommitFault::AmbiguousBeforeWrite {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::runtime(
                FixtureCommitKind::Active,
                expected,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        self.marker = Some(*transition.candidate_marker_bytes());
        if fault == DurableRunStateCommitFault::AmbiguousAfterMarker {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::runtime(
                FixtureCommitKind::Active,
                expected,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        self.checkpoint = Some(*transition.candidate_checkpoint_bytes());
        if fault == DurableRunStateCommitFault::AmbiguousAfterCheckpoint {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::runtime(
                FixtureCommitKind::Active,
                expected,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        transition.operation.record_commit_receipt()?;
        Ok(CommittedActiveMarker::from_durable_observation(
            self.marker_bytes(),
            self.checkpoint_bytes(),
            transition.lease.epoch,
            self.binding,
        ))
    }

    pub(super) fn reread_active(
        &mut self,
        transition: &PreparedActiveTransition<'_>,
    ) -> Result<RereadActiveMarker, RecoveryRequired> {
        if transition.lease.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch);
        }
        let expected =
            FixtureWriterRecord::runtime(transition.lease.installation(), transition.lease.epoch);
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch);
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(RecoveryRequired::CommitReloadRequired);
        }
        transition.operation.begin_reread()?;
        let fault = self.take_reread_fault();
        let marker = match fault {
            DurableRunStateRereadFault::MissingMarker => None,
            DurableRunStateRereadFault::MarkerDrift => {
                Some(transition.expected_marker_bytes().as_slice())
            }
            DurableRunStateRereadFault::None | DurableRunStateRereadFault::CheckpointDrift => {
                self.marker_bytes()
            }
        };
        let checkpoint = match fault {
            DurableRunStateRereadFault::CheckpointDrift => {
                Some(transition.expected_checkpoint_bytes().as_slice())
            }
            DurableRunStateRereadFault::None
            | DurableRunStateRereadFault::MissingMarker
            | DurableRunStateRereadFault::MarkerDrift => self.checkpoint_bytes(),
        };
        Ok(RereadActiveMarker::from_durable_observation(
            marker,
            checkpoint,
            transition.lease.epoch,
            self.binding,
        ))
    }

    pub(super) fn commit_clean(
        &mut self,
        transition: &PreparedCleanTransition<'_>,
    ) -> Result<CommittedCleanMarker, DurableRunStateCommitFailure> {
        if transition.lease.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch.into());
        }
        let expected =
            FixtureWriterRecord::runtime(transition.lease.installation(), transition.lease.epoch);
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch.into());
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(RecoveryRequired::CommitReloadRequired.into());
        }
        transition.operation.begin_commit()?;
        if self.marker.as_ref() != Some(transition.expected_marker_bytes())
            || self.checkpoint.as_ref() != Some(transition.expected_checkpoint_bytes())
        {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::terminal_runtime(
                FixtureCommitKind::Clean,
                expected,
            ));
            return Err(RecoveryRequired::CompareAndSwapConflict.into());
        }
        let fault = self.take_commit_fault();
        if fault == DurableRunStateCommitFault::CompareAndSwapConflict {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::terminal_runtime(
                FixtureCommitKind::Clean,
                expected,
            ));
            return Err(RecoveryRequired::CompareAndSwapConflict.into());
        }
        if fault == DurableRunStateCommitFault::AmbiguousBeforeWrite {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::runtime(
                FixtureCommitKind::Clean,
                expected,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        self.marker = Some(*transition.candidate_marker_bytes());
        if fault == DurableRunStateCommitFault::AmbiguousAfterMarker {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::runtime(
                FixtureCommitKind::Clean,
                expected,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        self.checkpoint = Some(*transition.candidate_checkpoint_bytes());
        if fault == DurableRunStateCommitFault::AmbiguousAfterCheckpoint {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::runtime(
                FixtureCommitKind::Clean,
                expected,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        transition.operation.record_commit_receipt()?;
        Ok(CommittedCleanMarker::from_durable_observation(
            self.marker_bytes(),
            self.checkpoint_bytes(),
            transition.lease.epoch,
            self.binding,
        ))
    }

    pub(super) fn reread_clean(
        &mut self,
        transition: &PreparedCleanTransition<'_>,
    ) -> Result<RereadCleanMarker, RecoveryRequired> {
        if transition.lease.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch);
        }
        let expected =
            FixtureWriterRecord::runtime(transition.lease.installation(), transition.lease.epoch);
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch);
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(RecoveryRequired::CommitReloadRequired);
        }
        transition.operation.begin_reread()?;
        let fault = self.take_reread_fault();
        let marker = match fault {
            DurableRunStateRereadFault::MissingMarker => None,
            DurableRunStateRereadFault::MarkerDrift => {
                Some(transition.expected_marker_bytes().as_slice())
            }
            DurableRunStateRereadFault::None | DurableRunStateRereadFault::CheckpointDrift => {
                self.marker_bytes()
            }
        };
        let checkpoint = match fault {
            DurableRunStateRereadFault::CheckpointDrift => {
                Some(transition.expected_checkpoint_bytes().as_slice())
            }
            DurableRunStateRereadFault::None
            | DurableRunStateRereadFault::MissingMarker
            | DurableRunStateRereadFault::MarkerDrift => self.checkpoint_bytes(),
        };
        Ok(RereadCleanMarker::from_durable_observation(
            marker,
            checkpoint,
            transition.lease.epoch,
            self.binding,
        ))
    }

    /// Releases the exact writer only after authenticated Clean completion.
    pub(super) fn release_writer(
        &mut self,
        pending: &PendingFinalWriterRelease<'_>,
    ) -> Result<WriterLeaseReleaseReceipt, DurableRunStateReleaseFailure> {
        if pending.lease.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch.into());
        }
        let expected =
            FixtureWriterRecord::runtime(pending.lease.installation(), pending.lease.epoch);
        if self.release_reconciliation.is_some() {
            return Err(RecoveryRequired::WriterReleaseReconciliationRequired.into());
        }
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch.into());
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(RecoveryRequired::CommitReloadRequired.into());
        }
        pending.operation.begin_release()?;
        let fault = self.take_release_fault();
        if fault == DurableRunStateReleaseFault::AmbiguousBeforeRelease {
            self.release_reconciliation = Some(expected.epoch);
            return Err(DurableRunStateReleaseFailure::Ambiguous);
        }
        self.held_writer = None;
        self.last_released_writer = Some(expected);
        if fault == DurableRunStateReleaseFault::AmbiguousAfterRelease {
            self.release_reconciliation = Some(expected.epoch);
            return Err(DurableRunStateReleaseFailure::Ambiguous);
        }
        let receipt_epoch = if fault == DurableRunStateReleaseFault::MismatchedReceiptAfterRelease {
            if pending.lease.epoch.get() == 1 {
                NonZeroU64::new(2).ok_or(RecoveryRequired::WriterLeaseMismatch)?
            } else {
                NonZeroU64::new(1).ok_or(RecoveryRequired::WriterLeaseMismatch)?
            }
        } else {
            pending.lease.epoch
        };
        if fault == DurableRunStateReleaseFault::MismatchedReceiptAfterRelease {
            self.release_reconciliation = Some(expected.epoch);
        }
        pending.operation.record_release_receipt()?;
        Ok(WriterLeaseReleaseReceipt::from_release_readback(
            pending.lease.installation(),
            receipt_epoch,
            self.binding,
        ))
    }

    /// Retires or reconciles an exact writer for terminal process exit.
    pub(super) fn retire_writer_for_exit(
        &mut self,
        pending: &WriterExitPending<'_>,
    ) -> Result<WriterExitReceipt, RecoveryRequired> {
        if pending.lease.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch);
        }
        let expected =
            FixtureWriterRecord::runtime(pending.lease.installation(), pending.lease.epoch);
        if self
            .unresolved_commit_ambiguity
            .is_some_and(|ambiguity| ambiguity.writer_epoch != expected.epoch)
        {
            return Err(RecoveryRequired::WriterLeaseMismatch);
        }
        if self
            .release_reconciliation
            .is_some_and(|reconciliation| reconciliation != expected.epoch)
        {
            return Err(RecoveryRequired::WriterLeaseMismatch);
        }
        let writer_was_held = match self.held_writer {
            Some(held) if held == expected => true,
            None if self.last_released_writer == Some(expected) => false,
            Some(_) | None => return Err(RecoveryRequired::WriterLeaseMismatch),
        };
        pending.operation.begin_release()?;
        if writer_was_held {
            self.held_writer = None;
            self.last_released_writer = Some(expected);
        }
        self.unresolved_commit_ambiguity = None;
        self.release_reconciliation = None;
        pending.operation.record_release_receipt()?;
        Ok(WriterExitReceipt {
            installation: pending.lease.installation(),
            epoch: pending.lease.epoch,
            binding: self.binding,
        })
    }
}

#[cfg(test)]
impl fmt::Debug for DurableRunStateFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableRunStateFixture([REDACTED])")
    }
}

#[cfg(test)]
#[path = "durable_run_state/provisioning_tests.rs"]
mod provisioning_tests;

#[cfg(test)]
mod tests {
    use std::{error::Error, io};

    use super::{
        ActiveReloadRequired, ActiveRunLease, BootEvidence, CanonicalSnapshot,
        CleanCommittedWithWriter, CleanReloadRequired, Commitment, DurableFailureWithWriter,
        DurableRunStateCommitFailure as FixtureCommitFailure,
        DurableRunStateCommitFault as FixtureCommitFault, DurableRunStateFixture as FaultBackend,
        DurableRunStateFixtureSeed as FixtureSeed,
        DurableRunStateReleaseFailure as FixtureReleaseFailure,
        DurableRunStateReleaseFault as FixtureReleaseFault,
        DurableRunStateRereadFault as FixtureRereadFault, HIGH_WATER_BODY_BYTES,
        InstallationIdentity, MARKER_RESERVED_OFFSET, NonZeroU64, PendingFinalWriterRelease,
        PreparedActiveTransition, PreparedCleanTransition, RUN_MARKER_BODY_BYTES,
        RecoveryExitEvidence, RecoveryRequired, ReloadedActiveRunState, RunMarkerState,
        RunStateAuthenticationProvider, RuntimeBootStartFailure, RuntimeWriterAcquired,
        SingleWriterLease, StartupObservationInspection, StoppedRunEvidence,
        resign_checkpoint_for_test, resign_marker_for_test,
    };
    use sha2::{Digest as _, Sha256};

    type TestResult = Result<(), Box<dyn Error>>;

    fn owned_debug_error(error: impl std::fmt::Debug) -> io::Error {
        io::Error::other(format!("{error:?}"))
    }

    fn fixture_provider(
        installation: InstallationIdentity,
    ) -> Result<RunStateAuthenticationProvider, RecoveryRequired> {
        RunStateAuthenticationProvider::from_fixture_bytes(installation, [0x5a; 32])
    }

    fn fixture_identity(seed: u8) -> Result<InstallationIdentity, RecoveryRequired> {
        InstallationIdentity::from_fixed_bytes([seed; 32])
    }

    fn nonzero(value: u64) -> Result<NonZeroU64, RecoveryRequired> {
        NonZeroU64::new(value).ok_or(RecoveryRequired::MalformedRunMarker)
    }

    fn predecessor(generation: NonZeroU64, seed: u8) -> Commitment {
        if generation.get() == 1 {
            Commitment::ZERO
        } else {
            Commitment([seed; 32])
        }
    }

    fn seeded_backend(
        state: RunMarkerState,
        generation: u64,
        provider: &RunStateAuthenticationProvider,
        installation: InstallationIdentity,
    ) -> Result<FaultBackend, RecoveryRequired> {
        let generation = nonzero(generation)?;
        FaultBackend::seeded(
            state,
            generation,
            installation,
            predecessor(generation, 0x31),
            provider,
        )
    }

    fn freshly_provisioned_backend(
        provider: &RunStateAuthenticationProvider,
        installation: InstallationIdentity,
    ) -> Result<FaultBackend, Box<dyn Error>> {
        let mut backend = FaultBackend::empty(installation)?;
        let unprovisioned = backend
            .begin_initial_provisioning(provider, installation)
            .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
        let transition = unprovisioned
            .prepare_initial_clean()
            .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
        let committed = backend.commit_initial_clean(&transition)?;
        let reread = backend.reread_initial_clean(&transition)?;
        let clean = transition
            .complete(committed, reread)
            .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
        let pending = clean.prepare_writer_release();
        let receipt = backend.release_provisioning_writer(&pending)?;
        let provisioned = pending
            .complete(receipt)
            .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
        assert_eq!(provisioned.generation(), NonZeroU64::MIN);
        Ok(backend)
    }

    fn startup_inspection(
        backend: &FaultBackend,
        provider: &RunStateAuthenticationProvider,
        installation: InstallationIdentity,
    ) -> Result<StartupObservationInspection, RecoveryRequired> {
        backend.inspect_startup_for_test(provider, installation)
    }

    fn boot_evidence<'provider>(
        backend: &mut FaultBackend,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> Result<BootEvidence<'provider>, RuntimeBootStartFailure<'provider>> {
        backend.boot(provider.runtime_authority())
    }

    fn active_run<'provider>(
        backend: &mut FaultBackend,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> Result<ActiveRunLease<'provider>, Box<dyn Error>> {
        let transition = boot_evidence(backend, provider)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        let committed = backend.commit_active(&transition)?;
        let reread = backend.reread_active(&transition)?;
        Ok(transition
            .complete(committed, reread)
            .map_err(owned_debug_error)?)
    }

    fn clean_transition<'provider>(
        backend: &mut FaultBackend,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> Result<PreparedCleanTransition<'provider>, Box<dyn Error>> {
        let active = active_run(backend, provider)?;
        Ok(active.prepare_clean().map_err(owned_debug_error)?)
    }

    fn clean_committed<'provider>(
        backend: &mut FaultBackend,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> Result<CleanCommittedWithWriter<'provider>, Box<dyn Error>> {
        let transition = clean_transition(backend, provider)?;
        let committed = backend.commit_clean(&transition)?;
        let reread = backend.reread_clean(&transition)?;
        Ok(transition
            .complete(committed, reread)
            .map_err(owned_debug_error)?)
    }

    fn stop_clean_run<'provider>(
        backend: &mut FaultBackend,
        clean: CleanCommittedWithWriter<'provider>,
    ) -> Result<StoppedRunEvidence<'provider>, Box<dyn Error>> {
        let pending = clean.prepare_writer_release();
        let receipt = backend.release_writer(&pending)?;
        Ok(pending.complete(receipt).map_err(owned_debug_error)?)
    }

    fn reload_active_from_backend<'provider>(
        reload: ActiveReloadRequired<'provider>,
        backend: &mut FaultBackend,
    ) -> Result<ReloadedActiveRunState<'provider>, DurableFailureWithWriter<'provider>> {
        let receipt = match backend.reload_active(&reload) {
            Ok(receipt) => receipt,
            Err(reason) => return Err(reload.abort(reason)),
        };
        reload.complete_reload(receipt)
    }

    fn reload_clean_from_backend<'provider>(
        reload: CleanReloadRequired<'provider>,
        backend: &mut FaultBackend,
    ) -> Result<CleanCommittedWithWriter<'provider>, DurableFailureWithWriter<'provider>> {
        let receipt = match backend.reload_clean(&reload) {
            Ok(receipt) => receipt,
            Err(reason) => return Err(reload.abort(reason)),
        };
        reload.complete_reload(receipt)
    }

    fn retire_failure<'provider>(
        backend: &mut FaultBackend,
        failure: DurableFailureWithWriter<'provider>,
    ) -> Result<RecoveryExitEvidence<'provider>, Box<dyn Error>> {
        let pending = failure.into_writer_exit();
        let receipt = backend.retire_writer_for_exit(&pending)?;
        Ok(pending.complete(receipt).map_err(owned_debug_error)?)
    }

    fn retire_runtime_boot_failure(
        backend: &mut FaultBackend,
        failure: RuntimeBootStartFailure<'_>,
    ) -> Result<RecoveryRequired, Box<dyn Error>> {
        let (reason, pending) = failure
            .into_writer_exit()
            .map_err(|reason| io::Error::other(format!("no runtime writer to retire: {reason}")))?;
        let receipt = backend.retire_writer_for_exit(&pending)?;
        let _retired = pending.complete(receipt).map_err(owned_debug_error)?;
        Ok(reason)
    }

    fn assert_runtime_pair_requires_terminal_retirement(
        provider: &mut RunStateAuthenticationProvider,
        installation: InstallationIdentity,
        marker: [u8; super::RUN_MARKER_BYTES],
        checkpoint: [u8; super::HIGH_WATER_BYTES],
        expected: RecoveryRequired,
    ) -> TestResult {
        let mut contender = fixture_provider(installation)?;
        let mut backend = freshly_provisioned_backend(provider, installation)?;
        backend.marker = Some(marker);
        backend.checkpoint = Some(checkpoint);
        let before = (backend.marker, backend.checkpoint);

        let acquired = backend
            .begin_runtime_boot(provider.runtime_authority())
            .map_err(owned_debug_error)?;
        let Err(failure) = backend.finish_runtime_boot(acquired) else {
            return Err("rejected durable pair minted BootEvidence".into());
        };
        assert_eq!(failure.reason(), expected);
        assert!(matches!(&failure, RuntimeBootStartFailure::WithWriter(_)));
        let Err(runtime_reacquire) = backend.begin_runtime_boot(contender.runtime_authority())
        else {
            return Err("post-acquisition failure allowed runtime writer reacquisition".into());
        };
        assert!(matches!(
            runtime_reacquire,
            RuntimeBootStartFailure::BeforeWriter(failure)
                if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
        ));
        if backend
            .begin_initial_provisioning(&contender, installation)
            .is_ok()
        {
            return Err(
                "post-acquisition failure allowed provisioning writer reacquisition".into(),
            );
        }
        assert_eq!((backend.marker, backend.checkpoint), before);
        assert_eq!(
            retire_runtime_boot_failure(&mut backend, failure)?,
            expected
        );
        assert!(backend.held_writer.is_none());
        assert_eq!((backend.marker, backend.checkpoint), before);
        Ok(())
    }

    fn resign_marker(
        marker: &mut [u8; super::RUN_MARKER_BYTES],
        provider: &RunStateAuthenticationProvider,
    ) -> Result<(), RecoveryRequired> {
        resign_marker_for_test(marker, provider)
    }

    fn resign_checkpoint(
        checkpoint: &mut [u8; super::HIGH_WATER_BYTES],
        provider: &RunStateAuthenticationProvider,
    ) -> Result<(), RecoveryRequired> {
        resign_checkpoint_for_test(checkpoint, provider)
    }

    #[test]
    fn canonical_v1_clean_marker_and_checkpoint_round_trip() -> TestResult {
        let installation = fixture_identity(0x21)?;
        let provider = fixture_provider(installation)?;
        let backend = freshly_provisioned_backend(&provider, installation)?;
        let snapshot = backend.canonical_snapshot()?;
        assert_eq!(&snapshot.marker[..8], b"YWRUNV01");
        assert_eq!(&snapshot.checkpoint[..8], b"YWHIWV01");
        assert_eq!(snapshot.marker[MARKER_RESERVED_OFFSET], 0);
        assert_eq!(&snapshot.checkpoint[10..12], &[0, 0]);
        let observation = startup_inspection(&backend, &provider, installation)?;
        assert_eq!(observation.state(), RunMarkerState::Clean);
        assert_eq!(observation.generation(), nonzero(1)?);
        Ok(())
    }

    #[test]
    fn canonical_v1_layout_matches_independent_golden_digests() -> TestResult {
        let installation = fixture_identity(0x21)?;
        let provider = fixture_provider(installation)?;
        let backend = freshly_provisioned_backend(&provider, installation)?;
        let snapshot = backend.canonical_snapshot()?;

        assert_eq!(snapshot.marker.len(), 148);
        assert_eq!(snapshot.checkpoint.len(), 148);
        assert_eq!(&snapshot.marker[0..8], b"YWRUNV01");
        assert_eq!(&snapshot.marker[8..10], &[0, 1]);
        assert_eq!(snapshot.marker[10], 1);
        assert_eq!(snapshot.marker[11], 0);
        assert_eq!(&snapshot.marker[12..20], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&snapshot.marker[20..52], &[0x21; 32]);
        assert_eq!(&snapshot.marker[52..84], &[0; 32]);
        assert_eq!(&snapshot.checkpoint[0..8], b"YWHIWV01");
        assert_eq!(&snapshot.checkpoint[8..12], &[0, 1, 0, 0]);
        assert_eq!(&snapshot.checkpoint[12..20], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&snapshot.checkpoint[20..52], &[0x21; 32]);
        assert_eq!(&snapshot.checkpoint[52..84], &[0; 32]);
        assert_eq!(&snapshot.marker[84..116], &snapshot.checkpoint[84..116]);

        let marker_digest: [u8; 32] = Sha256::digest(snapshot.marker).into();
        let checkpoint_digest: [u8; 32] = Sha256::digest(snapshot.checkpoint).into();
        assert_eq!(
            marker_digest,
            [
                0xc1, 0x42, 0xd6, 0x61, 0x94, 0x0b, 0x06, 0x90, 0xfd, 0x53, 0xbb, 0x16, 0x62, 0x31,
                0xf0, 0xe1, 0xb5, 0x2d, 0x78, 0x1c, 0x18, 0x25, 0x2c, 0x16, 0x54, 0xae, 0xc9, 0x33,
                0xcc, 0xb2, 0x19, 0x20,
            ]
        );
        assert_eq!(
            checkpoint_digest,
            [
                0xa7, 0x74, 0x75, 0x1a, 0xc5, 0x70, 0x32, 0x2c, 0xdc, 0xc3, 0x12, 0x49, 0xa3, 0xbc,
                0x24, 0xf7, 0x90, 0x46, 0x46, 0xe4, 0xcb, 0xb2, 0x50, 0x4a, 0xc4, 0x49, 0xa1, 0x28,
                0x46, 0xff, 0xe2, 0xce,
            ]
        );
        Ok(())
    }

    #[test]
    fn missing_marker_or_checkpoint_requires_recovery() -> TestResult {
        let installation = fixture_identity(0x22)?;
        let provider = fixture_provider(installation)?;
        let missing_marker =
            FaultBackend::new(FixtureSeed::MissingMarker, &provider, installation)?;
        assert_eq!(
            missing_marker
                .inspect_startup_for_test(&provider, installation)
                .map(|_| ()),
            Err(RecoveryRequired::MissingRunMarker)
        );
        let missing_checkpoint =
            FaultBackend::new(FixtureSeed::MissingCheckpoint, &provider, installation)?;
        assert_eq!(
            missing_checkpoint
                .inspect_startup_for_test(&provider, installation)
                .map(|_| ()),
            Err(RecoveryRequired::MissingHighWaterCheckpoint)
        );
        Ok(())
    }

    #[test]
    fn malformed_or_noncanonical_envelopes_require_recovery() -> TestResult {
        let installation = fixture_identity(0x23)?;
        let provider = fixture_provider(installation)?;
        let backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        assert_eq!(
            StartupObservationInspection::from_durable_bytes(
                Some(&[0_u8; 3]),
                backend.checkpoint_bytes(),
                installation,
                &provider,
            )
            .map(|_| ()),
            Err(RecoveryRequired::MalformedRunMarker)
        );
        let mut snapshot = backend.canonical_snapshot()?;
        snapshot.marker[MARKER_RESERVED_OFFSET] = 1;
        resign_marker(&mut snapshot.marker, &provider)?;
        assert_eq!(
            StartupObservationInspection::from_durable_bytes(
                Some(&snapshot.marker),
                Some(&snapshot.checkpoint),
                installation,
                &provider,
            )
            .map(|_| ()),
            Err(RecoveryRequired::MalformedRunMarker)
        );
        snapshot = backend.canonical_snapshot()?;
        snapshot.checkpoint[10] = 1;
        resign_checkpoint(&mut snapshot.checkpoint, &provider)?;
        assert_eq!(
            StartupObservationInspection::from_durable_bytes(
                Some(&snapshot.marker),
                Some(&snapshot.checkpoint),
                installation,
                &provider,
            )
            .map(|_| ()),
            Err(RecoveryRequired::MalformedHighWaterCheckpoint)
        );
        Ok(())
    }

    #[test]
    fn malformed_runtime_objects_retain_writer_until_terminal_retirement() -> TestResult {
        let installation = fixture_identity(0x6d)?;
        let mut provider = fixture_provider(installation)?;
        let template =
            freshly_provisioned_backend(&provider, installation)?.canonical_snapshot()?;

        let mut malformed_marker = template.marker;
        malformed_marker[MARKER_RESERVED_OFFSET] = 1;
        resign_marker(&mut malformed_marker, &provider)?;
        let mut malformed_checkpoint = template.checkpoint;
        malformed_checkpoint[10] = 1;
        resign_checkpoint(&mut malformed_checkpoint, &provider)?;

        for (marker, checkpoint, expected) in [
            (
                malformed_marker,
                template.checkpoint,
                RecoveryRequired::MalformedRunMarker,
            ),
            (
                template.marker,
                malformed_checkpoint,
                RecoveryRequired::MalformedHighWaterCheckpoint,
            ),
        ] {
            let mut backend = freshly_provisioned_backend(&provider, installation)?;
            backend.marker = Some(marker);
            backend.checkpoint = Some(checkpoint);
            let before = (backend.marker, backend.checkpoint);

            let acquired = backend
                .begin_runtime_boot(provider.runtime_authority())
                .map_err(owned_debug_error)?;
            let Err(failure) = backend.finish_runtime_boot(acquired) else {
                return Err("malformed runtime objects minted BootEvidence".into());
            };
            assert_eq!(failure.reason(), expected);
            assert!(matches!(&failure, RuntimeBootStartFailure::WithWriter(_)));
            assert_eq!((backend.marker, backend.checkpoint), before);
            assert_eq!(
                retire_runtime_boot_failure(&mut backend, failure)?,
                expected
            );
            assert!(backend.held_writer.is_none());
            assert_eq!((backend.marker, backend.checkpoint), before);
        }
        Ok(())
    }

    #[test]
    fn stale_test_inspection_cannot_override_fresh_writer_bound_observation() -> TestResult {
        let installation = fixture_identity(0x6f)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = freshly_provisioned_backend(&provider, installation)?;
        let stale_inspection = backend.inspect_startup_for_test(&provider, installation)?;
        assert_eq!(stale_inspection.state(), RunMarkerState::Clean);

        let active = seeded_backend(RunMarkerState::Active, 1, &provider, installation)?
            .canonical_snapshot()?;
        backend.marker = Some(active.marker);
        backend.checkpoint = Some(active.checkpoint);

        let Err(failure) = backend.boot(provider.runtime_authority()) else {
            return Err("stale clean inspection overrode the fresh Active observation".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::PersistedNonCleanState);
        assert!(matches!(&failure, RuntimeBootStartFailure::WithWriter(_)));
        assert_eq!(stale_inspection.state(), RunMarkerState::Clean);
        assert_eq!(
            retire_runtime_boot_failure(&mut backend, failure)?,
            RecoveryRequired::PersistedNonCleanState
        );
        assert!(backend.held_writer.is_none());
        Ok(())
    }

    #[test]
    fn runtime_writer_epoch_mismatch_retains_original_writer_authority() -> TestResult {
        let installation = fixture_identity(0x6e)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = freshly_provisioned_backend(&provider, installation)?;
        let acquired = backend
            .begin_runtime_boot(provider.runtime_authority())
            .map_err(owned_debug_error)?;
        let original_writer = backend
            .held_writer
            .ok_or_else(|| io::Error::other("runtime writer was not recorded"))?;
        let substituted_epoch = original_writer
            .epoch
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| io::Error::other("fixture writer epoch overflowed"))?;
        let mut substituted_writer = original_writer;
        substituted_writer.epoch = substituted_epoch;
        backend.held_writer = Some(substituted_writer);

        let Err(failure) = backend.finish_runtime_boot(acquired) else {
            return Err("substituted runtime writer epoch minted BootEvidence".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::WriterLeaseMismatch);
        assert!(matches!(&failure, RuntimeBootStartFailure::WithWriter(_)));
        let (reason, pending) = failure.into_writer_exit().map_err(|reason| {
            io::Error::other(format!("epoch mismatch lost its writer: {reason}"))
        })?;
        assert_eq!(reason, RecoveryRequired::WriterLeaseMismatch);
        assert!(matches!(
            backend.retire_writer_for_exit(&pending),
            Err(RecoveryRequired::WriterLeaseMismatch)
        ));

        backend.held_writer = Some(original_writer);
        let receipt = backend.retire_writer_for_exit(&pending)?;
        let _retired = pending.complete(receipt).map_err(owned_debug_error)?;
        assert!(backend.held_writer.is_none());
        Ok(())
    }

    #[test]
    fn valid_mac_noncanonical_fields_and_domain_swapped_tags_fail_closed() -> TestResult {
        let installation = fixture_identity(0x23)?;
        let provider = fixture_provider(installation)?;
        let backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;

        let marker_mutations: [fn(&mut [u8; super::RUN_MARKER_BYTES]); 3] = [
            |bytes: &mut [u8; super::RUN_MARKER_BYTES]| bytes[0] ^= 1,
            |bytes: &mut [u8; super::RUN_MARKER_BYTES]| bytes[8..10].copy_from_slice(&[0, 2]),
            |bytes: &mut [u8; super::RUN_MARKER_BYTES]| bytes[10] = 0xff,
        ];
        for mutate in marker_mutations {
            let mut snapshot = backend.canonical_snapshot()?;
            mutate(&mut snapshot.marker);
            resign_marker(&mut snapshot.marker, &provider)?;
            assert_eq!(
                StartupObservationInspection::from_durable_bytes(
                    Some(&snapshot.marker),
                    Some(&snapshot.checkpoint),
                    installation,
                    &provider,
                )
                .map(|_| ()),
                Err(RecoveryRequired::MalformedRunMarker)
            );
        }

        let checkpoint_mutations: [fn(&mut [u8; super::HIGH_WATER_BYTES]); 2] = [
            |bytes: &mut [u8; super::HIGH_WATER_BYTES]| bytes[0] ^= 1,
            |bytes: &mut [u8; super::HIGH_WATER_BYTES]| {
                bytes[8..10].copy_from_slice(&[0, 2]);
            },
        ];
        for mutate in checkpoint_mutations {
            let mut snapshot = backend.canonical_snapshot()?;
            mutate(&mut snapshot.checkpoint);
            resign_checkpoint(&mut snapshot.checkpoint, &provider)?;
            assert_eq!(
                StartupObservationInspection::from_durable_bytes(
                    Some(&snapshot.marker),
                    Some(&snapshot.checkpoint),
                    installation,
                    &provider,
                )
                .map(|_| ()),
                Err(RecoveryRequired::MalformedHighWaterCheckpoint)
            );
        }

        let mut swapped = backend.canonical_snapshot()?;
        let checkpoint_tag =
            <[u8; super::MAC_BYTES]>::try_from(&swapped.checkpoint[HIGH_WATER_BODY_BYTES..])?;
        swapped.marker[RUN_MARKER_BODY_BYTES..].copy_from_slice(&checkpoint_tag);
        assert_eq!(
            StartupObservationInspection::from_durable_bytes(
                Some(&swapped.marker),
                Some(&swapped.checkpoint),
                installation,
                &provider,
            )
            .map(|_| ()),
            Err(RecoveryRequired::AuthenticationFailed)
        );

        let mut corrupt_checkpoint = backend.canonical_snapshot()?;
        corrupt_checkpoint.checkpoint[HIGH_WATER_BODY_BYTES] ^= 1;
        assert_eq!(
            StartupObservationInspection::from_durable_bytes(
                Some(&corrupt_checkpoint.marker),
                Some(&corrupt_checkpoint.checkpoint),
                installation,
                &provider,
            )
            .map(|_| ()),
            Err(RecoveryRequired::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn authentication_and_installation_mismatch_require_recovery() -> TestResult {
        let installation = fixture_identity(0x24)?;
        let provider = fixture_provider(installation)?;
        let other_provider =
            RunStateAuthenticationProvider::from_fixture_bytes(installation, [0x6b; 32])?;
        let backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        assert_eq!(
            startup_inspection(&backend, &other_provider, installation).map(|_| ()),
            Err(RecoveryRequired::AuthenticationFailed)
        );
        assert_eq!(
            startup_inspection(&backend, &provider, fixture_identity(0x25)?).map(|_| ()),
            Err(RecoveryRequired::InstallationIdentityMismatch)
        );
        Ok(())
    }

    #[test]
    fn rollback_and_one_sided_high_water_advance_require_recovery() -> TestResult {
        let installation = fixture_identity(0x26)?;
        let provider = fixture_provider(installation)?;
        let older = seeded_backend(RunMarkerState::Clean, 2, &provider, installation)?;
        let newer = seeded_backend(RunMarkerState::Clean, 3, &provider, installation)?;
        assert_eq!(
            StartupObservationInspection::from_durable_bytes(
                older.marker_bytes(),
                newer.checkpoint_bytes(),
                installation,
                &provider,
            )
            .map(|_| ()),
            Err(RecoveryRequired::RollbackDetected)
        );
        assert_eq!(
            StartupObservationInspection::from_durable_bytes(
                newer.marker_bytes(),
                older.checkpoint_bytes(),
                installation,
                &provider,
            )
            .map(|_| ()),
            Err(RecoveryRequired::HighWaterDrift)
        );
        Ok(())
    }

    #[test]
    fn same_generation_equivocation_requires_recovery() -> TestResult {
        let installation = fixture_identity(0x27)?;
        let provider = fixture_provider(installation)?;
        let generation = nonzero(4)?;
        let first = FaultBackend::seeded(
            RunMarkerState::Clean,
            generation,
            installation,
            Commitment([0x41; 32]),
            &provider,
        )?;
        let second = FaultBackend::seeded(
            RunMarkerState::Clean,
            generation,
            installation,
            Commitment([0x42; 32]),
            &provider,
        )?;
        assert_eq!(
            StartupObservationInspection::from_durable_bytes(
                first.marker_bytes(),
                second.checkpoint_bytes(),
                installation,
                &provider,
            )
            .map(|_| ()),
            Err(RecoveryRequired::EquivocationDetected)
        );
        Ok(())
    }

    #[test]
    fn runtime_lineage_and_installation_failures_are_writer_retaining() -> TestResult {
        let installation = fixture_identity(0x70)?;
        let mut provider = fixture_provider(installation)?;
        let older = seeded_backend(RunMarkerState::Clean, 2, &provider, installation)?
            .canonical_snapshot()?;
        let newer = seeded_backend(RunMarkerState::Clean, 3, &provider, installation)?
            .canonical_snapshot()?;

        assert_runtime_pair_requires_terminal_retirement(
            &mut provider,
            installation,
            older.marker,
            newer.checkpoint,
            RecoveryRequired::RollbackDetected,
        )?;
        assert_runtime_pair_requires_terminal_retirement(
            &mut provider,
            installation,
            newer.marker,
            older.checkpoint,
            RecoveryRequired::HighWaterDrift,
        )?;

        let generation = nonzero(4)?;
        let first = FaultBackend::seeded(
            RunMarkerState::Clean,
            generation,
            installation,
            Commitment([0x41; 32]),
            &provider,
        )?
        .canonical_snapshot()?;
        let second = FaultBackend::seeded(
            RunMarkerState::Clean,
            generation,
            installation,
            Commitment([0x42; 32]),
            &provider,
        )?
        .canonical_snapshot()?;
        assert_runtime_pair_requires_terminal_retirement(
            &mut provider,
            installation,
            first.marker,
            second.checkpoint,
            RecoveryRequired::EquivocationDetected,
        )?;

        let other_installation = fixture_identity(0x71)?;
        let foreign_provider = fixture_provider(other_installation)?;
        let foreign = seeded_backend(
            RunMarkerState::Clean,
            1,
            &foreign_provider,
            other_installation,
        )?
        .canonical_snapshot()?;
        assert_runtime_pair_requires_terminal_retirement(
            &mut provider,
            installation,
            foreign.marker,
            foreign.checkpoint,
            RecoveryRequired::InstallationIdentityMismatch,
        )
    }

    #[test]
    fn authenticated_non_clean_startup_cannot_mint_boot_evidence() -> TestResult {
        let installation = fixture_identity(0x28)?;
        let mut provider = fixture_provider(installation)?;
        for state in [RunMarkerState::Active, RunMarkerState::RecoveryRequired] {
            let mut backend = seeded_backend(state, 2, &provider, installation)?;
            let inspection = startup_inspection(&backend, &provider, installation)?;
            assert_eq!(inspection.state(), state);
            let acquired = backend
                .begin_runtime_boot(provider.runtime_authority())
                .map_err(owned_debug_error)?;
            let Err(start_failure) = backend.finish_runtime_boot(acquired) else {
                return Err("non-clean observation minted boot authority".into());
            };
            let RuntimeBootStartFailure::WithWriter(failure) = start_failure else {
                return Err("non-clean observation lost the acquired writer".into());
            };
            assert_eq!(failure.reason(), RecoveryRequired::PersistedNonCleanState);
            let _exit = retire_failure(&mut backend, failure)?;
        }
        Ok(())
    }

    #[test]
    fn lease_owned_provider_reauthenticates_the_held_lineage() -> TestResult {
        let installation = fixture_identity(0x69)?;
        let mut provider = fixture_provider(installation)?;
        let wrong_provider =
            RunStateAuthenticationProvider::from_fixture_bytes(installation, [0xa5; 32])?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;

        let mut boot = boot_evidence(&mut backend, &mut provider).map_err(owned_debug_error)?;
        resign_marker(&mut boot.durable.bytes.marker, &wrong_provider)?;
        resign_checkpoint(&mut boot.durable.bytes.checkpoint, &wrong_provider)?;
        let Err(active_failure) = boot.prepare_active() else {
            return Err("wrong-provider lineage minted Active preparation authority".into());
        };
        assert_eq!(
            active_failure.reason(),
            RecoveryRequired::AuthenticationFailed
        );
        let _exit = retire_failure(&mut backend, active_failure)?;
        assert_eq!(
            startup_inspection(&backend, &provider, installation)?.state(),
            RunMarkerState::Clean
        );

        let mut active = active_run(&mut backend, &mut provider)?;
        resign_marker(&mut active.durable.bytes.marker, &wrong_provider)?;
        resign_checkpoint(&mut active.durable.bytes.checkpoint, &wrong_provider)?;
        let Err(clean_failure) = active.prepare_clean() else {
            return Err("wrong-provider lineage minted Clean preparation authority".into());
        };
        assert_eq!(
            clean_failure.reason(),
            RecoveryRequired::AuthenticationFailed
        );
        let _exit = retire_failure(&mut backend, clean_failure)?;
        assert_eq!(
            startup_inspection(&backend, &provider, installation)?.state(),
            RunMarkerState::Active
        );
        Ok(())
    }

    #[test]
    fn crash_release_preserves_active_recovery_evidence_and_frees_writer() -> TestResult {
        let installation = fixture_identity(0x29)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let active = active_run(&mut backend, &mut provider)?;
        assert_eq!(active.generation(), nonzero(2)?);
        let exit = active.into_writer_exit();
        let receipt = backend.retire_writer_for_exit(&exit)?;
        let _exit = exit.complete(receipt).map_err(owned_debug_error)?;
        assert_eq!(
            startup_inspection(&backend, &provider, installation)?.state(),
            RunMarkerState::Active
        );
        let Err(start_failure) = boot_evidence(&mut backend, &mut provider) else {
            return Err("persisted Active state minted boot authority".into());
        };
        assert_eq!(
            start_failure.reason(),
            RecoveryRequired::PersistedNonCleanState
        );
        let RuntimeBootStartFailure::WithWriter(failure) = start_failure else {
            return Err("post-acquisition Active failure lost its writer".into());
        };
        let _exit = retire_failure(&mut backend, failure)?;
        Ok(())
    }

    #[test]
    fn active_cas_conflict_and_commit_receipt_mismatch_require_recovery() -> TestResult {
        let installation = fixture_identity(0x2a)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = boot_evidence(&mut backend, &mut provider)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        backend.set_commit_fault(FixtureCommitFault::CompareAndSwapConflict);
        assert_eq!(
            backend.commit_active(&transition).map(|_| ()),
            Err(FixtureCommitFailure::Recovery(
                RecoveryRequired::CompareAndSwapConflict
            ))
        );
        assert_eq!(
            backend.commit_active(&transition).map(|_| ()),
            Err(FixtureCommitFailure::Recovery(
                RecoveryRequired::CommitReloadRequired
            ))
        );
        let _exit = retire_failure(
            &mut backend,
            transition.abort(RecoveryRequired::CompareAndSwapConflict),
        )?;

        let mut receipt_backend =
            seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = boot_evidence(&mut receipt_backend, &mut provider)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        let prior = receipt_backend.canonical_snapshot()?;
        let _exact_committed = receipt_backend.commit_active(&transition)?;
        let committed = super::CommittedActiveMarker::from_durable_observation(
            Some(&prior.marker),
            Some(&prior.checkpoint),
            transition.lease.epoch,
            receipt_backend.binding,
        );
        let reread = receipt_backend.reread_active(&transition)?;
        let Err(failure) = transition.complete(committed, reread) else {
            return Err("mismatched Active receipt minted runtime authority".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::CommitReceiptMismatch);
        let _exit = retire_failure(&mut receipt_backend, failure)?;
        Ok(())
    }

    #[test]
    fn active_post_commit_reread_drift_requires_recovery() -> TestResult {
        let installation = fixture_identity(0x2b)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = boot_evidence(&mut backend, &mut provider)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        let committed = backend.commit_active(&transition)?;
        backend.set_reread_fault(FixtureRereadFault::CheckpointDrift);
        let reread = backend.reread_active(&transition)?;
        let Err(failure) = transition.complete(committed, reread) else {
            return Err("drifting Active reread minted runtime authority".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::RereadDrift);
        let _exit = retire_failure(&mut backend, failure)?;
        Ok(())
    }

    #[test]
    fn runtime_commit_and_reread_attempts_are_one_shot() -> TestResult {
        let installation = fixture_identity(0x6a)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = boot_evidence(&mut backend, &mut provider)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        let committed = backend.commit_active(&transition)?;
        assert_eq!(
            backend.commit_active(&transition).map(|_| ()),
            Err(FixtureCommitFailure::Recovery(
                RecoveryRequired::OperationAttemptReused
            ))
        );
        let reread = backend.reread_active(&transition)?;
        assert_eq!(
            backend.reread_active(&transition).map(|_| ()),
            Err(RecoveryRequired::OperationAttemptReused)
        );
        let active = transition
            .complete(committed, reread)
            .map_err(owned_debug_error)?;
        let exit = active.into_writer_exit();
        let receipt = backend.retire_writer_for_exit(&exit)?;
        assert_eq!(
            backend.retire_writer_for_exit(&exit).map(|_| ()),
            Err(RecoveryRequired::OperationAttemptReused)
        );
        let _retired = exit.complete(receipt).map_err(owned_debug_error)?;
        Ok(())
    }

    #[test]
    fn ambiguous_active_before_write_reloads_exact_boot_evidence() -> TestResult {
        let installation = fixture_identity(0x2c)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = boot_evidence(&mut backend, &mut provider)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        backend.set_commit_fault(FixtureCommitFault::AmbiguousBeforeWrite);
        assert_eq!(
            backend.commit_active(&transition),
            Err(FixtureCommitFailure::Ambiguous)
        );
        assert_eq!(
            backend.commit_active(&transition).map(|_| ()),
            Err(FixtureCommitFailure::Recovery(
                RecoveryRequired::CommitReloadRequired
            ))
        );
        let reloaded = reload_active_from_backend(transition.commit_ambiguous(), &mut backend)
            .map_err(owned_debug_error)?;
        let ReloadedActiveRunState::Boot(boot) = reloaded else {
            return Err("ambiguous pre-write Active commit did not restore boot evidence".into());
        };
        assert_eq!(boot.generation(), nonzero(1)?);
        let exit = boot.into_writer_exit();
        let receipt = backend.retire_writer_for_exit(&exit)?;
        let _exit = exit.complete(receipt).map_err(owned_debug_error)?;
        Ok(())
    }

    #[test]
    fn ambiguous_active_after_marker_requires_recovery() -> TestResult {
        let installation = fixture_identity(0x2d)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = boot_evidence(&mut backend, &mut provider)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        backend.set_commit_fault(FixtureCommitFault::AmbiguousAfterMarker);
        assert_eq!(
            backend.commit_active(&transition),
            Err(FixtureCommitFailure::Ambiguous)
        );
        let Err(failure) = reload_active_from_backend(transition.commit_ambiguous(), &mut backend)
        else {
            return Err("partial Active commit reloaded authority".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::HighWaterDrift);
        let _exit = retire_failure(&mut backend, failure)?;
        Ok(())
    }

    #[test]
    fn ambiguous_active_after_checkpoint_reloads_runtime_authority() -> TestResult {
        let installation = fixture_identity(0x2e)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = boot_evidence(&mut backend, &mut provider)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        backend.set_commit_fault(FixtureCommitFault::AmbiguousAfterCheckpoint);
        assert_eq!(
            backend.commit_active(&transition),
            Err(FixtureCommitFailure::Ambiguous)
        );
        let reloaded = reload_active_from_backend(transition.commit_ambiguous(), &mut backend)
            .map_err(owned_debug_error)?;
        let ReloadedActiveRunState::Active(active) = reloaded else {
            return Err(
                "complete ambiguous Active commit did not restore runtime authority".into(),
            );
        };
        assert_eq!(active.generation(), nonzero(2)?);
        let exit = active.into_writer_exit();
        let receipt = backend.retire_writer_for_exit(&exit)?;
        let _exit = exit.complete(receipt).map_err(owned_debug_error)?;
        Ok(())
    }

    #[test]
    fn writer_lease_is_exclusive_and_release_receipt_is_exact() -> TestResult {
        let installation = fixture_identity(0x2f)?;
        let mut provider = fixture_provider(installation)?;
        let mut contender = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let first = backend
            .begin_runtime_boot(provider.runtime_authority())
            .map_err(owned_debug_error)?;
        let Err(second) = backend.begin_runtime_boot(contender.runtime_authority()) else {
            return Err("a second runtime writer was acquired".into());
        };
        assert!(matches!(
            second,
            RuntimeBootStartFailure::BeforeWriter(failure)
                if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
        ));
        let boot = backend
            .finish_runtime_boot(first)
            .map_err(owned_debug_error)?;
        let transition = boot.prepare_active().map_err(owned_debug_error)?;
        let committed = backend.commit_active(&transition)?;
        let reread = backend.reread_active(&transition)?;
        let active = transition
            .complete(committed, reread)
            .map_err(owned_debug_error)?;
        let clean_transition = active.prepare_clean().map_err(owned_debug_error)?;
        let committed = backend.commit_clean(&clean_transition)?;
        let reread = backend.reread_clean(&clean_transition)?;
        let clean = clean_transition
            .complete(committed, reread)
            .map_err(owned_debug_error)?;
        let pending = clean.prepare_writer_release();
        let wrong = super::WriterLeaseReleaseReceipt::from_release_readback(
            installation,
            nonzero(99)?,
            backend.binding,
        );
        let Err(failure) = pending.complete(wrong) else {
            return Err("wrong final-release receipt minted stopped evidence".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::WriterLeaseMismatch);
        let _exit = retire_failure(&mut backend, failure)?;
        Ok(())
    }

    #[test]
    fn exact_clean_commit_and_reread_mint_stopped_evidence() -> TestResult {
        let installation = fixture_identity(0x30)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = clean_transition(&mut backend, &mut provider)?;
        let committed = backend.commit_clean(&transition)?;
        let reread = backend.reread_clean(&transition)?;
        let clean = transition
            .complete(committed, reread)
            .map_err(owned_debug_error)?;
        assert_eq!(clean.generation(), nonzero(3)?);
        let stopped = stop_clean_run(&mut backend, clean)?;
        assert_eq!(stopped.generation(), nonzero(3)?);
        assert_eq!(
            startup_inspection(&backend, &provider, installation)?.state(),
            RunMarkerState::Clean
        );
        Ok(())
    }

    #[test]
    fn ambiguous_clean_after_checkpoint_recovers_clean_with_writer_before_stopped() -> TestResult {
        let installation = fixture_identity(0x32)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = clean_transition(&mut backend, &mut provider)?;
        backend.set_commit_fault(FixtureCommitFault::AmbiguousAfterCheckpoint);
        assert_eq!(
            backend.commit_clean(&transition),
            Err(FixtureCommitFailure::Ambiguous)
        );
        let clean = reload_clean_from_backend(transition.commit_ambiguous(), &mut backend)
            .map_err(owned_debug_error)?;
        assert_eq!(clean.generation(), nonzero(3)?);
        assert!(backend.held_writer.is_some());
        let stopped = stop_clean_run(&mut backend, clean)?;
        assert_eq!(stopped.generation(), nonzero(3)?);
        Ok(())
    }

    #[test]
    fn ambiguous_clean_before_write_requires_recovery() -> TestResult {
        let installation = fixture_identity(0x33)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = clean_transition(&mut backend, &mut provider)?;
        backend.set_commit_fault(FixtureCommitFault::AmbiguousBeforeWrite);
        assert_eq!(
            backend.commit_clean(&transition),
            Err(FixtureCommitFailure::Ambiguous)
        );
        let Err(failure) = reload_clean_from_backend(transition.commit_ambiguous(), &mut backend)
        else {
            return Err("unapplied ambiguous Clean commit restored authority".into());
        };
        assert_eq!(
            failure.reason(),
            RecoveryRequired::AmbiguousCleanCommitNotApplied
        );
        let _exit = retire_failure(&mut backend, failure)?;
        Ok(())
    }

    #[test]
    fn ambiguous_clean_after_marker_requires_recovery() -> TestResult {
        let installation = fixture_identity(0x34)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = clean_transition(&mut backend, &mut provider)?;
        backend.set_commit_fault(FixtureCommitFault::AmbiguousAfterMarker);
        assert_eq!(
            backend.commit_clean(&transition),
            Err(FixtureCommitFailure::Ambiguous)
        );
        let Err(failure) = reload_clean_from_backend(transition.commit_ambiguous(), &mut backend)
        else {
            return Err("partial Clean commit restored authority".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::HighWaterDrift);
        let _exit = retire_failure(&mut backend, failure)?;
        Ok(())
    }

    #[test]
    fn clean_post_commit_reread_drift_requires_recovery() -> TestResult {
        let installation = fixture_identity(0x35)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let transition = clean_transition(&mut backend, &mut provider)?;
        let committed = backend.commit_clean(&transition)?;
        backend.set_reread_fault(FixtureRereadFault::MissingMarker);
        let reread = backend.reread_clean(&transition)?;
        let Err(failure) = transition.complete(committed, reread) else {
            return Err("drifting Clean reread restored clean authority".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::RereadDrift);
        let _exit = retire_failure(&mut backend, failure)?;
        Ok(())
    }

    #[test]
    fn cross_backend_commit_reread_and_release_receipts_are_rejected() -> TestResult {
        let installation = fixture_identity(0x38)?;
        let mut provider_a = fixture_provider(installation)?;
        let mut provider_b = fixture_provider(installation)?;

        let mut active_a = seeded_backend(RunMarkerState::Clean, 1, &provider_a, installation)?;
        let mut active_b = seeded_backend(RunMarkerState::Clean, 1, &provider_b, installation)?;
        let transition_a = boot_evidence(&mut active_a, &mut provider_a)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        let transition_b = boot_evidence(&mut active_b, &mut provider_b)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        let committed_a = active_a.commit_active(&transition_a)?;
        let reread_a = active_a.reread_active(&transition_a)?;
        let Err(failure_b) = transition_b.complete(committed_a, reread_a) else {
            return Err("cross-backend Active receipts minted runtime authority".into());
        };
        assert_eq!(failure_b.reason(), RecoveryRequired::BackendBindingMismatch);
        let _exit_b = retire_failure(&mut active_b, failure_b)?;
        let exit_a = transition_a.into_writer_exit();
        let receipt_a = active_a.retire_writer_for_exit(&exit_a)?;
        let _exit_a = exit_a.complete(receipt_a).map_err(owned_debug_error)?;

        let mut clean_a = seeded_backend(RunMarkerState::Clean, 1, &provider_a, installation)?;
        let mut clean_b = seeded_backend(RunMarkerState::Clean, 1, &provider_b, installation)?;
        let transition_a = clean_transition(&mut clean_a, &mut provider_a)?;
        let transition_b = clean_transition(&mut clean_b, &mut provider_b)?;
        let committed_a = clean_a.commit_clean(&transition_a)?;
        let reread_a = clean_a.reread_clean(&transition_a)?;
        let Err(failure_b) = transition_b.complete(committed_a, reread_a) else {
            return Err("cross-backend Clean receipts restored clean authority".into());
        };
        assert_eq!(failure_b.reason(), RecoveryRequired::BackendBindingMismatch);
        let _exit_b = retire_failure(&mut clean_b, failure_b)?;
        let exit_a = transition_a.into_writer_exit();
        let receipt_a = clean_a.retire_writer_for_exit(&exit_a)?;
        let _exit_a = exit_a.complete(receipt_a).map_err(owned_debug_error)?;

        let mut release_a = seeded_backend(RunMarkerState::Clean, 1, &provider_a, installation)?;
        let mut release_b = seeded_backend(RunMarkerState::Clean, 1, &provider_b, installation)?;
        let pending_a = clean_committed(&mut release_a, &mut provider_a)?.prepare_writer_release();
        let pending_b = clean_committed(&mut release_b, &mut provider_b)?.prepare_writer_release();
        let receipt_a = release_a.release_writer(&pending_a)?;
        let Err(failure_b) = pending_b.complete(receipt_a) else {
            return Err("cross-backend release receipt minted stopped evidence".into());
        };
        assert_eq!(failure_b.reason(), RecoveryRequired::BackendBindingMismatch);
        let _exit_b = retire_failure(&mut release_b, failure_b)?;
        let exit_a = pending_a.into_writer_exit();
        let receipt_a = release_a.retire_writer_for_exit(&exit_a)?;
        let _exit_a = exit_a.complete(receipt_a).map_err(owned_debug_error)?;

        let mut terminal_a = seeded_backend(RunMarkerState::Clean, 1, &provider_a, installation)?;
        let mut terminal_b = seeded_backend(RunMarkerState::Clean, 1, &provider_b, installation)?;
        let exit_a = boot_evidence(&mut terminal_a, &mut provider_a)
            .map_err(owned_debug_error)?
            .into_writer_exit();
        let exit_b = boot_evidence(&mut terminal_b, &mut provider_b)
            .map_err(owned_debug_error)?
            .into_writer_exit();
        let receipt_a = terminal_a.retire_writer_for_exit(&exit_a)?;
        let receipt_b = terminal_b.retire_writer_for_exit(&exit_b)?;
        let Err(failure_a) = exit_a.complete(receipt_b) else {
            return Err("cross-backend terminal receipt completed writer retirement".into());
        };
        let Err(failure_b) = exit_b.complete(receipt_a) else {
            return Err(
                "reverse cross-backend terminal receipt completed writer retirement".into(),
            );
        };
        assert_eq!(failure_a.reason(), RecoveryRequired::BackendBindingMismatch);
        assert_eq!(failure_b.reason(), RecoveryRequired::BackendBindingMismatch);
        let _exit_a = retire_failure(&mut terminal_a, failure_a)?;
        let _exit_b = retire_failure(&mut terminal_b, failure_b)?;
        Ok(())
    }

    #[test]
    fn cross_backend_reload_receipts_are_rejected() -> TestResult {
        let installation = fixture_identity(0x39)?;
        let mut provider_a = fixture_provider(installation)?;
        let mut provider_b = fixture_provider(installation)?;

        let mut active_a = seeded_backend(RunMarkerState::Clean, 1, &provider_a, installation)?;
        let mut active_b = seeded_backend(RunMarkerState::Clean, 1, &provider_b, installation)?;
        let transition_a = boot_evidence(&mut active_a, &mut provider_a)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        let transition_b = boot_evidence(&mut active_b, &mut provider_b)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        active_a.set_commit_fault(FixtureCommitFault::AmbiguousBeforeWrite);
        active_b.set_commit_fault(FixtureCommitFault::AmbiguousBeforeWrite);
        assert!(matches!(
            active_a.commit_active(&transition_a),
            Err(FixtureCommitFailure::Ambiguous)
        ));
        assert!(matches!(
            active_b.commit_active(&transition_b),
            Err(FixtureCommitFailure::Ambiguous)
        ));
        let reload_a = transition_a.commit_ambiguous();
        let reload_b = transition_b.commit_ambiguous();
        let receipt_a = active_a.reload_active(&reload_a)?;
        let Err(failure_b) = reload_b.complete_reload(receipt_a) else {
            return Err("cross-backend Active reload restored authority".into());
        };
        assert_eq!(failure_b.reason(), RecoveryRequired::BackendBindingMismatch);
        let _exit_b = retire_failure(&mut active_b, failure_b)?;
        let exit_a = reload_a.into_writer_exit();
        let receipt_a = active_a.retire_writer_for_exit(&exit_a)?;
        let _exit_a = exit_a.complete(receipt_a).map_err(owned_debug_error)?;

        let mut clean_a = seeded_backend(RunMarkerState::Clean, 1, &provider_a, installation)?;
        let mut clean_b = seeded_backend(RunMarkerState::Clean, 1, &provider_b, installation)?;
        let transition_a = clean_transition(&mut clean_a, &mut provider_a)?;
        let transition_b = clean_transition(&mut clean_b, &mut provider_b)?;
        clean_a.set_commit_fault(FixtureCommitFault::AmbiguousBeforeWrite);
        clean_b.set_commit_fault(FixtureCommitFault::AmbiguousBeforeWrite);
        assert!(matches!(
            clean_a.commit_clean(&transition_a),
            Err(FixtureCommitFailure::Ambiguous)
        ));
        assert!(matches!(
            clean_b.commit_clean(&transition_b),
            Err(FixtureCommitFailure::Ambiguous)
        ));
        let reload_a = transition_a.commit_ambiguous();
        let reload_b = transition_b.commit_ambiguous();
        let receipt_a = clean_a.reload_clean(&reload_a)?;
        let Err(failure_b) = reload_b.complete_reload(receipt_a) else {
            return Err("cross-backend Clean reload restored authority".into());
        };
        assert_eq!(failure_b.reason(), RecoveryRequired::BackendBindingMismatch);
        let _exit_b = retire_failure(&mut clean_b, failure_b)?;
        let exit_a = reload_a.into_writer_exit();
        let receipt_a = clean_a.retire_writer_for_exit(&exit_a)?;
        let _exit_a = exit_a.complete(receipt_a).map_err(owned_debug_error)?;
        Ok(())
    }

    #[test]
    fn ambiguous_or_mismatched_final_release_retires_without_stopped_authority() -> TestResult {
        let installation = fixture_identity(0x3a)?;
        let mut provider = fixture_provider(installation)?;
        let mut runtime_provider = fixture_provider(installation)?;

        for fault in [
            FixtureReleaseFault::AmbiguousBeforeRelease,
            FixtureReleaseFault::AmbiguousAfterRelease,
        ] {
            let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
            let pending = clean_committed(&mut backend, &mut provider)?.prepare_writer_release();
            backend.set_release_fault(fault);
            assert!(matches!(
                backend.release_writer(&pending),
                Err(FixtureReleaseFailure::Ambiguous)
            ));
            assert_eq!(
                backend.release_writer(&pending).map(|_| ()),
                Err(FixtureReleaseFailure::Recovery(
                    RecoveryRequired::WriterReleaseReconciliationRequired
                ))
            );
            let expected_boot_error = if fault == FixtureReleaseFault::AmbiguousBeforeRelease {
                RecoveryRequired::WriterLeaseUnavailable
            } else {
                RecoveryRequired::WriterReleaseReconciliationRequired
            };
            let Err(boot_failure) = backend.boot(runtime_provider.runtime_authority()) else {
                return Err("unresolved final release allowed runtime boot".into());
            };
            assert_eq!(boot_failure.reason(), expected_boot_error);
            assert!(matches!(
                boot_failure,
                RuntimeBootStartFailure::BeforeWriter(_)
            ));
            let failure = pending.abort(RecoveryRequired::WriterReleaseAmbiguous);
            let _exit = retire_failure(&mut backend, failure)?;
            let restarted =
                boot_evidence(&mut backend, &mut provider).map_err(owned_debug_error)?;
            let exit = restarted.into_writer_exit();
            let receipt = backend.retire_writer_for_exit(&exit)?;
            let _exit = exit.complete(receipt).map_err(owned_debug_error)?;
        }

        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let pending = clean_committed(&mut backend, &mut provider)?.prepare_writer_release();
        backend.set_release_fault(FixtureReleaseFault::MismatchedReceiptAfterRelease);
        let mismatched = backend.release_writer(&pending)?;
        let Err(failure) = pending.complete(mismatched) else {
            return Err("mismatched release receipt minted stopped evidence".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::WriterLeaseMismatch);
        let Err(boot_failure) = backend.boot(runtime_provider.runtime_authority()) else {
            return Err("mismatched final release allowed runtime boot".into());
        };
        assert!(matches!(
            boot_failure,
            RuntimeBootStartFailure::BeforeWriter(failure)
                if failure.reason()
                    == RecoveryRequired::WriterReleaseReconciliationRequired
        ));
        let _exit = retire_failure(&mut backend, failure)?;
        Ok(())
    }

    #[test]
    fn generation_exhaustion_requires_recovery() -> TestResult {
        let installation = fixture_identity(0x36)?;
        let mut provider = fixture_provider(installation)?;
        let generation = nonzero(u64::MAX)?;
        let mut backend = FaultBackend::seeded(
            RunMarkerState::Clean,
            generation,
            installation,
            predecessor(generation, 0x51),
            &provider,
        )?;
        let boot = boot_evidence(&mut backend, &mut provider).map_err(owned_debug_error)?;
        let Err(failure) = boot.prepare_active() else {
            return Err("exhausted generation prepared Active".into());
        };
        assert_eq!(failure.reason(), RecoveryRequired::GenerationExhausted);
        let _exit = retire_failure(&mut backend, failure)?;
        let restarted = boot_evidence(&mut backend, &mut provider).map_err(owned_debug_error)?;
        let exit = restarted.into_writer_exit();
        let receipt = backend.retire_writer_for_exit(&exit)?;
        let _exit = exit.complete(receipt).map_err(owned_debug_error)?;
        Ok(())
    }

    #[test]
    fn move_only_authorities_and_receipts_cannot_be_clone_or_copy() {
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

        assert_move_only!(StartupObservationInspection);
        assert_move_only!(SingleWriterLease<'static>);
        assert_move_only!(RuntimeWriterAcquired<'static>);
        assert_move_only!(RuntimeBootStartFailure<'static>);
        assert_move_only!(BootEvidence<'static>);
        assert_move_only!(PreparedActiveTransition<'static>);
        assert_move_only!(super::CommittedActiveMarker);
        assert_move_only!(super::RereadActiveMarker);
        assert_move_only!(ActiveRunLease<'static>);
        assert_move_only!(ActiveReloadRequired<'static>);
        assert_move_only!(super::ActiveReloadReceipt);
        assert_move_only!(ReloadedActiveRunState<'static>);
        assert_move_only!(PreparedCleanTransition<'static>);
        assert_move_only!(super::CommittedCleanMarker);
        assert_move_only!(super::RereadCleanMarker);
        assert_move_only!(CleanReloadRequired<'static>);
        assert_move_only!(super::CleanReloadReceipt);
        assert_move_only!(CleanCommittedWithWriter<'static>);
        assert_move_only!(PendingFinalWriterRelease<'static>);
        assert_move_only!(super::WriterLeaseReleaseReceipt);
        assert_move_only!(DurableFailureWithWriter<'static>);
        assert_move_only!(super::WriterExitPending<'static>);
        assert_move_only!(super::WriterExitReceipt);
        assert_move_only!(RecoveryExitEvidence<'static>);
        assert_move_only!(StoppedRunEvidence<'static>);
    }

    #[test]
    fn debug_redacts_provider_generation_installation_mac_and_checkpoint() -> TestResult {
        let installation = fixture_identity(0x37)?;
        let mut provider = fixture_provider(installation)?;
        let mut backend = seeded_backend(RunMarkerState::Clean, 1, &provider, installation)?;
        let inspection = startup_inspection(&backend, &provider, installation)?;
        assert_eq!(
            format!("{provider:?}"),
            "RunStateAuthenticationProvider([REDACTED])"
        );
        assert!(format!("{installation:?}").contains("[REDACTED]"));
        assert!(format!("{inspection:?}").contains("[REDACTED]"));
        let acquired = backend
            .begin_runtime_boot(provider.runtime_authority())
            .map_err(owned_debug_error)?;
        assert!(format!("{acquired:?}").contains("[REDACTED]"));
        let transition = backend
            .finish_runtime_boot(acquired)
            .map_err(owned_debug_error)?
            .prepare_active()
            .map_err(owned_debug_error)?;
        assert!(format!("{transition:?}").contains("[REDACTED]"));
        let exit = transition.into_writer_exit();
        let receipt = backend.retire_writer_for_exit(&exit)?;
        let _exit = exit.complete(receipt).map_err(owned_debug_error)?;
        assert_eq!(format!("{backend:?}"), "DurableRunStateFixture([REDACTED])");

        let other_installation = fixture_identity(0x47)?;
        let mut other_provider = fixture_provider(other_installation)?;
        let Err(before_writer) = backend.begin_runtime_boot(other_provider.runtime_authority())
        else {
            return Err("wrong installation minted runtime writer authority".into());
        };
        assert_eq!(
            format!("{before_writer:?}"),
            "RuntimeBootStartFailure { phase: \"before-writer\", reason: InstallationIdentityMismatch, writer: \"[REDACTED]\" }"
        );
        assert_eq!(
            format!("{before_writer}"),
            "runtime boot failed before writer acquisition: the durable run-state installation identity mismatched"
        );
        assert!(std::error::Error::source(&before_writer).is_some());
        let Err(before_writer) = before_writer.into_writer_exit() else {
            return Err("pre-writer failure retained a writer".into());
        };
        assert_eq!(
            before_writer.reason(),
            RecoveryRequired::InstallationIdentityMismatch
        );

        let mut missing = FaultBackend::empty(installation)?;
        let Err(with_writer) = missing.boot(provider.runtime_authority()) else {
            return Err("missing state minted runtime boot authority".into());
        };
        assert_eq!(with_writer.reason(), RecoveryRequired::MissingRunMarker);
        assert_eq!(
            format!("{with_writer:?}"),
            "RuntimeBootStartFailure { phase: \"with-writer\", reason: MissingRunMarker, writer: \"[REDACTED]\" }"
        );
        assert_eq!(
            format!("{with_writer}"),
            "runtime boot failed after writer acquisition: the durable run marker is missing; terminal writer retirement is required"
        );
        assert!(std::error::Error::source(&with_writer).is_some());
        let (reason, pending) = with_writer.into_writer_exit().map_err(|reason| {
            io::Error::other(format!("post-acquisition failure lost writer: {reason}"))
        })?;
        assert_eq!(reason, RecoveryRequired::MissingRunMarker);
        let receipt = missing.retire_writer_for_exit(&pending)?;
        let _exit = pending.complete(receipt).map_err(owned_debug_error)?;
        Ok(())
    }

    #[test]
    fn fixture_backend_is_fixed_capacity_and_has_no_history_growth() {
        assert!(std::mem::size_of::<FaultBackend>() <= 512);
        assert_eq!(std::mem::size_of::<CanonicalSnapshot>(), 296);
    }
}
