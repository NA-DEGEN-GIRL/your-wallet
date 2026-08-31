//! Dormant Windows composite binding the Phase 2D logical writer to one
//! independently verified fixed marker/checkpoint pair.
//!
//! This module deliberately has no production caller or authentication-key
//! source. Its move-only typestates keep the logical and operating-system
//! writer authorities together until normal stopped evidence or terminal
//! retirement is reached.

use core::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::run_state_root::{HeldServiceRunStateWriter, ServiceRunStateError};
use super::windows_pair::{
    ExpectedWindowsPair, WindowsCommittedPair, WindowsObservedPair, WindowsPairCommitOutcome,
    WindowsPairExpectationMismatch, WindowsPairKnownFailure, WindowsPairReleaseAfterWriter,
    WindowsPairReleaseFailure, WindowsPairReleaseWithWriter, WindowsPairReleased,
    WindowsPairReloadFailure, WindowsPairReloadRequired, WindowsPairRetired, WindowsPairWriter,
    WindowsPreparedPairCommit, WindowsReloadedPair, WindowsRereadPair,
};
use super::{
    ActiveReloadReceipt, ActiveReloadRequired, ActiveRunLease, BackendBinding, BootEvidence,
    CleanCommittedWithWriter, CleanReloadReceipt, CleanReloadRequired, CommittedActiveMarker,
    CommittedCleanMarker, DurableFailureWithWriter, FixtureRunStateAuthenticationKey,
    InstallationIdentity, PendingFinalWriterRelease, PreparedActiveTransition,
    PreparedCleanTransition, RecoveryExitEvidence, RecoveryRequired, ReloadedActiveRunState,
    RereadActiveMarker, RereadCleanMarker, RuntimeWriterAcquired, StoppedRunEvidence,
    WriterExitPending, WriterExitReceipt, WriterLeaseReleaseReceipt, WriterObservation,
};

static NEXT_WINDOWS_BACKEND_BINDING: AtomicU64 = AtomicU64::new(1);

fn allocate_windows_backend_binding() -> Result<NonZeroU64, RecoveryRequired> {
    let value = NEXT_WINDOWS_BACKEND_BINDING
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| RecoveryRequired::BackendBindingExhausted)?;
    NonZeroU64::new(value).ok_or(RecoveryRequired::BackendBindingExhausted)
}

/// Starts the dormant Windows composite from an already-held exclusive OS
/// writer. Authentication happens only after the fresh pair observation.
#[allow(clippy::large_types_passed_by_value)] // Transfers the opaque writer once.
#[allow(clippy::result_large_err)] // Failure retains both move-only authorities.
pub(super) fn start_windows_runtime(
    writer: HeldServiceRunStateWriter,
    installation: InstallationIdentity,
    key: &FixtureRunStateAuthenticationKey,
) -> Result<WindowsBootEvidence<'_>, WindowsRuntimeStartFailure<'_>> {
    let acquired = WindowsRuntimeWriterAcquired::from_held_writer(writer, installation, key)
        .map_err(WindowsRuntimeStartFailure::Binding)?;
    acquired
        .authenticate()
        .map_err(WindowsRuntimeStartFailure::Terminal)
}

/// Complete startup failure split by whether a logical binding was allocated.
#[must_use = "a failed Windows runtime start must be terminally retired"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsRuntimeStartFailure<'key> {
    Binding(WindowsRuntimeBindingFailure),
    Terminal(WindowsTerminalFailure<'key>),
}

impl WindowsRuntimeStartFailure<'_> {
    pub(super) const fn reason(&self) -> RecoveryRequired {
        match self {
            Self::Binding(failure) => failure.reason(),
            Self::Terminal(failure) => failure.reason(),
        }
    }
}

impl fmt::Debug for WindowsRuntimeStartFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsRuntimeStartFailure")
            .field("reason", &self.reason())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

const fn backend_reason(cause: ServiceRunStateError) -> RecoveryRequired {
    match cause {
        ServiceRunStateError::Compare => RecoveryRequired::CompareAndSwapConflict,
        _ => RecoveryRequired::WindowsBackendFailure,
    }
}

/// Failure to allocate the private logical binding after the OS writer was held.
#[must_use = "the unbound Windows writer must be terminally retired"]
pub(super) struct WindowsRuntimeBindingFailure {
    reason: RecoveryRequired,
    pair: WindowsPairWriter,
}

impl WindowsRuntimeBindingFailure {
    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    pub(super) fn retire(self) -> Result<WindowsUnboundRetired, ServiceRunStateError> {
        self.pair
            .retire()
            .map(|pair| WindowsUnboundRetired { _pair: pair })
    }
}

impl fmt::Debug for WindowsRuntimeBindingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsRuntimeBindingFailure")
            .field("reason", &self.reason)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Terminal receipt for the pre-logical-binding allocation failure path.
pub(super) struct WindowsUnboundRetired {
    _pair: WindowsPairRetired,
}

impl fmt::Debug for WindowsUnboundRetired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsUnboundRetired")
    }
}

/// Writer-first composite. No pair bytes have been observed yet.
#[must_use = "the acquired Windows runtime writer must authenticate its fresh pair"]
pub(super) struct WindowsRuntimeWriterAcquired<'key> {
    logical: RuntimeWriterAcquired,
    pair: WindowsPairWriter,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl<'key> WindowsRuntimeWriterAcquired<'key> {
    /// Seals an already-held OS writer and the same borrowed authentication key.
    #[allow(clippy::large_types_passed_by_value)]
    #[allow(clippy::result_large_err)] // Failure retains the complete OS writer inline.
    pub(super) fn from_held_writer(
        writer: HeldServiceRunStateWriter,
        installation: InstallationIdentity,
        key: &'key FixtureRunStateAuthenticationKey,
    ) -> Result<Self, WindowsRuntimeBindingFailure> {
        let epoch = match allocate_windows_backend_binding() {
            Ok(epoch) => epoch,
            Err(reason) => {
                return Err(WindowsRuntimeBindingFailure {
                    reason,
                    pair: WindowsPairWriter::from_held_writer(writer),
                });
            }
        };
        let pair = WindowsPairWriter::from_held_writer(writer);
        Ok(Self {
            logical: RuntimeWriterAcquired::from_exclusive_acquisition(
                installation,
                epoch,
                BackendBinding(epoch),
            ),
            pair,
            key,
        })
    }

    /// Freshly observes and authenticates exactly one Clean pair.
    #[allow(clippy::result_large_err)] // Failure retains both move-only authorities inline.
    pub(super) fn authenticate(
        self,
    ) -> Result<WindowsBootEvidence<'key>, WindowsTerminalFailure<'key>> {
        let Self { logical, pair, key } = self;
        let pair = match pair.observe() {
            Ok(pair) => pair,
            Err(pair) => {
                let cause = pair.cause();
                return Err(WindowsTerminalFailure::new(
                    backend_reason(cause),
                    Some(cause),
                    logical.into_writer_exit(),
                    WindowsTerminalPair::Known(pair),
                    key,
                ));
            }
        };
        match logical.authenticate_observation(pair.observation(), key) {
            Ok(logical) => Ok(WindowsBootEvidence { logical, pair, key }),
            Err(failure) => Err(WindowsTerminalFailure::from_durable(
                failure,
                WindowsTerminalPair::Observed(pair),
                key,
            )),
        }
    }

    /// Converts a pre-authentication lifecycle abort into the shared checked
    /// terminal retirement path without dropping either authority.
    pub(super) fn into_terminal(self, reason: RecoveryRequired) -> WindowsTerminalFailure<'key> {
        let Self { logical, pair, key } = self;
        WindowsTerminalFailure::new(
            reason,
            None,
            logical.into_writer_exit(),
            WindowsTerminalPair::Writer(pair),
            key,
        )
    }
}

impl fmt::Debug for WindowsRuntimeWriterAcquired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsRuntimeWriterAcquired([REDACTED])")
    }
}

/// Authenticated Clean Phase 2D boot evidence holding the same OS writer.
#[must_use = "Windows boot evidence must prepare Active or retire terminally"]
pub(super) struct WindowsBootEvidence<'key> {
    logical: BootEvidence,
    pair: WindowsObservedPair,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl<'key> WindowsBootEvidence<'key> {
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }

    #[allow(clippy::result_large_err)] // Failure retains both move-only authorities inline.
    pub(super) fn prepare_active(
        self,
    ) -> Result<WindowsPreparedActiveTransition<'key>, WindowsTerminalFailure<'key>> {
        let Self { logical, pair, key } = self;
        let logical = match logical.prepare_active(key) {
            Ok(logical) => logical,
            Err(failure) => {
                return Err(WindowsTerminalFailure::from_durable(
                    failure,
                    WindowsTerminalPair::Observed(pair),
                    key,
                ));
            }
        };
        let expected = logical.prior.bytes;
        let candidate = logical.successor.bytes;
        match pair.prepare_commit(ExpectedWindowsPair::exact(expected), candidate) {
            Ok(pair) => Ok(WindowsPreparedActiveTransition { logical, pair, key }),
            Err(pair) => Err(WindowsTerminalFailure::from_durable(
                logical.abort(RecoveryRequired::CompareAndSwapConflict),
                WindowsTerminalPair::ExpectationMismatch(pair),
                key,
            )),
        }
    }

    /// Abandons authenticated startup through the sole checked terminal path.
    pub(super) fn into_terminal(self, reason: RecoveryRequired) -> WindowsTerminalFailure<'key> {
        let Self { logical, pair, key } = self;
        WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Observed(pair),
            key,
        )
    }
}

impl fmt::Debug for WindowsBootEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsBootEvidence([REDACTED])")
    }
}

/// Exact Active successor and exact OS pair expectation awaiting one commit.
#[must_use = "the prepared Windows Active transition must commit or retire"]
pub(super) struct WindowsPreparedActiveTransition<'key> {
    logical: PreparedActiveTransition,
    pair: WindowsPreparedPairCommit,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl<'key> WindowsPreparedActiveTransition<'key> {
    pub(super) fn commit_and_reread(self) -> WindowsActiveCommitOutcome<'key> {
        let Self { logical, pair, key } = self;
        if let Err(reason) = logical.operation.begin_commit() {
            return WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Prepared(pair),
                key,
            ));
        }
        match pair.commit() {
            WindowsPairCommitOutcome::KnownNotCommitted(pair) => {
                let cause = pair.cause();
                WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::new(
                    backend_reason(cause),
                    Some(cause),
                    logical.abort(backend_reason(cause)).into_writer_exit(),
                    WindowsTerminalPair::Known(pair),
                    key,
                ))
            }
            WindowsPairCommitOutcome::Ambiguous(pair) => {
                WindowsActiveCommitOutcome::ReloadRequired(WindowsActiveReloadRequired {
                    logical: logical.commit_ambiguous(),
                    pair,
                    key,
                })
            }
            WindowsPairCommitOutcome::Committed(pair) => complete_active_commit(logical, pair, key),
        }
    }

    /// Abandons the unattempted Active transition through checked retirement.
    pub(super) fn into_terminal(self, reason: RecoveryRequired) -> WindowsTerminalFailure<'key> {
        let Self { logical, pair, key } = self;
        WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Prepared(pair),
            key,
        )
    }
}

fn complete_active_commit(
    logical: PreparedActiveTransition,
    pair: WindowsCommittedPair,
    key: &FixtureRunStateAuthenticationKey,
) -> WindowsActiveCommitOutcome<'_> {
    let committed_observation = pair.candidate().observation();
    if let Err(reason) = logical.operation.record_commit_receipt() {
        return WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Committed(pair),
            key,
        ));
    }
    let committed = CommittedActiveMarker {
        observed: committed_observation,
        lease_epoch: logical.lease.epoch,
        binding: logical.lease.binding,
    };
    if let Err(reason) = logical.operation.begin_reread() {
        return WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Committed(pair),
            key,
        ));
    }
    let pair = match pair.reread() {
        Ok(pair) => pair,
        Err(pair) => {
            let cause = pair.cause();
            return WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::new(
                RecoveryRequired::RereadDrift,
                Some(cause),
                logical
                    .abort(RecoveryRequired::RereadDrift)
                    .into_writer_exit(),
                WindowsTerminalPair::Ambiguous(pair),
                key,
            ));
        }
    };
    let reread_observation = pair.observation();
    let reread = RereadActiveMarker {
        observed: reread_observation,
        lease_epoch: logical.lease.epoch,
        binding: logical.lease.binding,
    };
    match logical.complete(committed, reread) {
        Ok(logical) => WindowsActiveCommitOutcome::Active(WindowsActiveRunLease {
            logical,
            pair: pair.continue_observed(),
            key,
        }),
        Err(failure) => WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            failure,
            WindowsTerminalPair::Reread(pair),
            key,
        )),
    }
}

impl fmt::Debug for WindowsPreparedActiveTransition<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsPreparedActiveTransition([REDACTED])")
    }
}

/// Complete consuming result of the Active commit plus independent reread.
#[must_use = "the Windows Active outcome retains both authorities"]
#[allow(clippy::large_enum_variant)]
pub(super) enum WindowsActiveCommitOutcome<'key> {
    Active(WindowsActiveRunLease<'key>),
    ReloadRequired(WindowsActiveReloadRequired<'key>),
    Terminal(WindowsTerminalFailure<'key>),
}

/// Runtime authority holding both the authenticated Active state and OS pair.
#[must_use = "the Windows Active run must prepare Clean or retire terminally"]
pub(super) struct WindowsActiveRunLease<'key> {
    logical: ActiveRunLease,
    pair: WindowsObservedPair,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl<'key> WindowsActiveRunLease<'key> {
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }

    /// Commits and independently rereads the exact successor Clean pair while
    /// retaining the same logical lease and OS writer.
    pub(super) fn commit_clean(self) -> WindowsCleanCommitOutcome<'key> {
        let Self { logical, pair, key } = self;
        let logical = match logical.prepare_clean(key) {
            Ok(logical) => logical,
            Err(failure) => {
                return WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    failure,
                    WindowsTerminalPair::Observed(pair),
                    key,
                ));
            }
        };
        let expected = logical.prior.bytes;
        let candidate = logical.successor.bytes;
        let pair = match pair.prepare_commit(ExpectedWindowsPair::exact(expected), candidate) {
            Ok(pair) => pair,
            Err(pair) => {
                return WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    logical.abort(RecoveryRequired::CompareAndSwapConflict),
                    WindowsTerminalPair::ExpectationMismatch(pair),
                    key,
                ));
            }
        };
        if let Err(reason) = logical.operation.begin_commit() {
            return WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Prepared(pair),
                key,
            ));
        }
        match pair.commit() {
            WindowsPairCommitOutcome::KnownNotCommitted(pair) => {
                let cause = pair.cause();
                WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::new(
                    backend_reason(cause),
                    Some(cause),
                    logical.abort(backend_reason(cause)).into_writer_exit(),
                    WindowsTerminalPair::Known(pair),
                    key,
                ))
            }
            WindowsPairCommitOutcome::Ambiguous(pair) => {
                WindowsCleanCommitOutcome::ReloadRequired(WindowsCleanReloadRequired {
                    logical: logical.commit_ambiguous(),
                    pair,
                    key,
                })
            }
            WindowsPairCommitOutcome::Committed(pair) => complete_clean_commit(logical, pair, key),
        }
    }

    /// Abandons Active runtime authority through checked terminal retirement.
    pub(super) fn into_terminal(self, reason: RecoveryRequired) -> WindowsTerminalFailure<'key> {
        let Self { logical, pair, key } = self;
        WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Observed(pair),
            key,
        )
    }
}

fn complete_clean_commit(
    logical: PreparedCleanTransition,
    pair: WindowsCommittedPair,
    key: &FixtureRunStateAuthenticationKey,
) -> WindowsCleanCommitOutcome<'_> {
    let committed_observation = pair.candidate().observation();
    if let Err(reason) = logical.operation.record_commit_receipt() {
        return WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Committed(pair),
            key,
        ));
    }
    let committed = CommittedCleanMarker {
        observed: committed_observation,
        lease_epoch: logical.lease.epoch,
        binding: logical.lease.binding,
    };
    if let Err(reason) = logical.operation.begin_reread() {
        return WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Committed(pair),
            key,
        ));
    }
    let pair = match pair.reread() {
        Ok(pair) => pair,
        Err(pair) => {
            return WindowsCleanCommitOutcome::ReloadRequired(WindowsCleanReloadRequired {
                logical: logical.commit_ambiguous(),
                pair,
                key,
            });
        }
    };
    let reread = RereadCleanMarker {
        observed: pair.observation(),
        lease_epoch: logical.lease.epoch,
        binding: logical.lease.binding,
    };
    match logical.complete(committed, reread) {
        Ok(logical) => WindowsCleanCommitOutcome::Clean(WindowsCleanWithWriter {
            logical,
            pair: pair.continue_observed(),
            key,
        }),
        Err(failure) => WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            failure,
            WindowsTerminalPair::Reread(pair),
            key,
        )),
    }
}

/// Complete consuming result of the Clean commit plus independent reread.
#[must_use = "the Windows Clean outcome retains both authorities"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsCleanCommitOutcome<'key> {
    Clean(WindowsCleanWithWriter<'key>),
    ReloadRequired(WindowsCleanReloadRequired<'key>),
    Terminal(WindowsTerminalFailure<'key>),
}

/// Exact authenticated Clean state retaining the final pair-bound writer.
#[must_use = "the Windows Clean writer must stop or retire terminally"]
pub(super) struct WindowsCleanWithWriter<'key> {
    logical: CleanCommittedWithWriter,
    pair: WindowsObservedPair,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl<'key> WindowsCleanWithWriter<'key> {
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }

    /// Performs the sole pair-bound final release. Stopped evidence is minted
    /// only after the OS receipt exactly names the authenticated Clean pair.
    pub(super) fn stop(self) -> WindowsStopOutcome<'key> {
        let Self { logical, pair, key } = self;
        if pair.observation() != logical.durable.bytes.observation() {
            return WindowsStopOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(RecoveryRequired::CompareAndSwapConflict),
                WindowsTerminalPair::Observed(pair),
                key,
            ));
        }
        let logical = logical.prepare_writer_release();
        if let Err(reason) = logical.operation.begin_release() {
            return WindowsStopOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Observed(pair),
                key,
            ));
        }
        match pair.release_verified() {
            Ok(pair) => complete_final_release(logical, pair, key),
            Err(WindowsPairReleaseFailure::WriterRetained(pair)) => {
                let cause = pair.cause();
                WindowsStopOutcome::Terminal(WindowsTerminalFailure::new(
                    RecoveryRequired::WriterReleaseAmbiguous,
                    Some(cause),
                    logical
                        .abort(RecoveryRequired::WriterReleaseAmbiguous)
                        .into_writer_exit(),
                    WindowsTerminalPair::ReleaseWithWriter(pair),
                    key,
                ))
            }
            Err(WindowsPairReleaseFailure::WriterReleasedNoReceipt(pair)) => {
                let cause = pair.cause();
                WindowsStopOutcome::ReleasedNoReceipt(WindowsReleasedNoReceipt {
                    reason: RecoveryRequired::WriterReleaseAmbiguous,
                    cause,
                    _logical: logical.into_writer_exit(),
                    _pair: pair,
                    key,
                })
            }
        }
    }

    /// Abandons normal stop and consumes both authorities into retirement.
    pub(super) fn into_terminal(self, reason: RecoveryRequired) -> WindowsTerminalFailure<'key> {
        let Self { logical, pair, key } = self;
        WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Observed(pair),
            key,
        )
    }
}

fn complete_final_release(
    logical: PendingFinalWriterRelease,
    pair: WindowsPairReleased,
    key: &FixtureRunStateAuthenticationKey,
) -> WindowsStopOutcome<'_> {
    if pair.pair() != logical.durable.bytes {
        return WindowsStopOutcome::PostReleaseTerminal(WindowsPostReleaseTerminal {
            reason: RecoveryRequired::WriterReleaseAmbiguous,
            _logical: logical.into_writer_exit(),
            _pair: pair,
            key,
        });
    }
    if let Err(reason) = logical.operation.record_release_receipt() {
        return WindowsStopOutcome::PostReleaseTerminal(WindowsPostReleaseTerminal {
            reason,
            _logical: logical.into_writer_exit(),
            _pair: pair,
            key,
        });
    }
    let receipt = WriterLeaseReleaseReceipt {
        installation: logical.lease.installation,
        epoch: logical.lease.epoch,
        binding: logical.lease.binding,
    };
    match logical.complete(receipt) {
        Ok(logical) => WindowsStopOutcome::Stopped(WindowsStoppedRunEvidence {
            logical,
            _pair: pair,
        }),
        Err(failure) => WindowsStopOutcome::PostReleaseTerminal(WindowsPostReleaseTerminal {
            reason: failure.reason(),
            _logical: failure.into_writer_exit(),
            _pair: pair,
            key,
        }),
    }
}

/// Complete final release result. Only `Stopped` carries normal authority.
#[must_use = "the Windows stop outcome must be handled explicitly"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsStopOutcome<'key> {
    Stopped(WindowsStoppedRunEvidence),
    Terminal(WindowsTerminalFailure<'key>),
    ReleasedNoReceipt(WindowsReleasedNoReceipt<'key>),
    PostReleaseTerminal(WindowsPostReleaseTerminal<'key>),
}

/// Exact authenticated Clean evidence after pair-bound writer release.
#[must_use = "Windows stopped evidence is the sole normal terminal receipt"]
pub(super) struct WindowsStoppedRunEvidence {
    logical: StoppedRunEvidence,
    _pair: WindowsPairReleased,
}

impl WindowsStoppedRunEvidence {
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }
}

impl fmt::Debug for WindowsStoppedRunEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsStoppedRunEvidence([REDACTED])")
    }
}

/// Irreversible OS close ambiguity after the logical release attempt began.
/// No retry, retirement, recovery-exit, or stopped conversion is exposed.
#[must_use = "a no-receipt release is an irreversible terminal state"]
pub(super) struct WindowsReleasedNoReceipt<'key> {
    reason: RecoveryRequired,
    cause: ServiceRunStateError,
    _logical: WriterExitPending,
    _pair: WindowsPairReleaseAfterWriter,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl WindowsReleasedNoReceipt<'_> {
    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    pub(super) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }
}

impl fmt::Debug for WindowsReleasedNoReceipt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.key;
        formatter
            .debug_struct("WindowsReleasedNoReceipt")
            .field("reason", &self.reason)
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// The OS produced a checked pair receipt, but logical stopped completion
/// failed afterward. No writer remains and no normal/retirement API exists.
#[must_use = "post-release logical failure cannot mint stopped evidence"]
pub(super) struct WindowsPostReleaseTerminal<'key> {
    reason: RecoveryRequired,
    _logical: WriterExitPending,
    _pair: WindowsPairReleased,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl WindowsPostReleaseTerminal<'_> {
    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }
}

impl fmt::Debug for WindowsPostReleaseTerminal<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.key;
        formatter
            .debug_struct("WindowsPostReleaseTerminal")
            .field("reason", &self.reason)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for WindowsCleanWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsCleanWithWriter([REDACTED])")
    }
}

/// Ambiguous Clean commit retaining exact logical and OS reload authority.
#[must_use = "the Windows Clean ambiguity must reload or retire"]
pub(super) struct WindowsCleanReloadRequired<'key> {
    logical: CleanReloadRequired,
    pair: WindowsPairReloadRequired,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl<'key> WindowsCleanReloadRequired<'key> {
    pub(super) fn reload(self) -> WindowsCleanReloadOutcome<'key> {
        let Self { logical, pair, key } = self;
        let pair = match pair.reload() {
            Ok(pair) => pair,
            Err(pair) => {
                let cause = pair.cause();
                return WindowsCleanReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    logical.abort(backend_reason(cause)),
                    WindowsTerminalPair::ReloadFailure(pair),
                    key,
                ));
            }
        };
        if let Err(reason) = logical.operation.record_reload_receipt() {
            return WindowsCleanReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Reloaded(pair),
                key,
            ));
        }
        let receipt = CleanReloadReceipt {
            observed: pair.observation(),
            writer: WriterObservation::Held {
                installation: logical.lease.installation,
                epoch: logical.lease.epoch,
            },
            binding: logical.lease.binding,
        };
        match logical.complete_reload(receipt, key) {
            Ok(logical) => WindowsCleanReloadOutcome::Clean(WindowsCleanWithWriter {
                logical,
                pair: pair.continue_observed(),
                key,
            }),
            Err(failure) => {
                WindowsCleanReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    failure,
                    WindowsTerminalPair::Reloaded(pair),
                    key,
                ))
            }
        }
    }

    /// Retires an unresolved Clean ambiguity without downgrading it.
    pub(super) fn into_terminal(self, reason: RecoveryRequired) -> WindowsTerminalFailure<'key> {
        let Self { logical, pair, key } = self;
        WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Ambiguous(pair),
            key,
        )
    }
}

impl fmt::Debug for WindowsCleanReloadRequired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsCleanReloadRequired([REDACTED])")
    }
}

/// Exact resolution of one ambiguous Clean commit.
#[must_use = "the Windows Clean reload outcome retains terminal authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsCleanReloadOutcome<'key> {
    Clean(WindowsCleanWithWriter<'key>),
    Terminal(WindowsTerminalFailure<'key>),
}

impl fmt::Debug for WindowsActiveRunLease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsActiveRunLease([REDACTED])")
    }
}

/// Ambiguous Active commit retaining exact logical reload and OS ambiguity.
#[must_use = "the Windows Active ambiguity must reload or retire"]
pub(super) struct WindowsActiveReloadRequired<'key> {
    logical: ActiveReloadRequired,
    pair: WindowsPairReloadRequired,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl<'key> WindowsActiveReloadRequired<'key> {
    pub(super) fn reload(self) -> WindowsActiveReloadOutcome<'key> {
        let Self { logical, pair, key } = self;
        let pair = match pair.reload() {
            Ok(pair) => pair,
            Err(pair) => {
                let cause = pair.cause();
                return WindowsActiveReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    logical.abort(backend_reason(cause)),
                    WindowsTerminalPair::ReloadFailure(pair),
                    key,
                ));
            }
        };
        if let Err(reason) = logical.operation.record_reload_receipt() {
            return WindowsActiveReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Reloaded(pair),
                key,
            ));
        }
        let receipt = ActiveReloadReceipt {
            observed: pair.observation(),
            writer: WriterObservation::Held {
                installation: logical.lease.installation,
                epoch: logical.lease.epoch,
            },
            binding: logical.lease.binding,
        };
        match logical.complete_reload(receipt, key) {
            Ok(ReloadedActiveRunState::Boot(logical)) => {
                WindowsActiveReloadOutcome::Boot(WindowsBootEvidence {
                    logical,
                    pair: pair.continue_observed(),
                    key,
                })
            }
            Ok(ReloadedActiveRunState::Active(logical)) => {
                WindowsActiveReloadOutcome::Active(WindowsActiveRunLease {
                    logical,
                    pair: pair.continue_observed(),
                    key,
                })
            }
            Err(failure) => {
                WindowsActiveReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    failure,
                    WindowsTerminalPair::Reloaded(pair),
                    key,
                ))
            }
        }
    }

    /// Retires an unresolved Active ambiguity without downgrading it.
    pub(super) fn into_terminal(self, reason: RecoveryRequired) -> WindowsTerminalFailure<'key> {
        let Self { logical, pair, key } = self;
        WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Ambiguous(pair),
            key,
        )
    }
}

/// Complete exact resolution of one ambiguous Active commit.
#[must_use = "the Active reload outcome retains both authorities"]
#[allow(clippy::large_enum_variant)]
pub(super) enum WindowsActiveReloadOutcome<'key> {
    Boot(WindowsBootEvidence<'key>),
    Active(WindowsActiveRunLease<'key>),
    Terminal(WindowsTerminalFailure<'key>),
}

enum WindowsTerminalPair {
    Writer(WindowsPairWriter),
    Observed(WindowsObservedPair),
    Prepared(WindowsPreparedPairCommit),
    Committed(WindowsCommittedPair),
    Reread(WindowsRereadPair),
    Known(WindowsPairKnownFailure),
    ExpectationMismatch(WindowsPairExpectationMismatch),
    Ambiguous(WindowsPairReloadRequired),
    ReloadFailure(WindowsPairReloadFailure),
    Reloaded(WindowsReloadedPair),
    ReleaseWithWriter(WindowsPairReleaseWithWriter),
}

impl WindowsTerminalPair {
    fn retire(self) -> Result<WindowsPairRetired, ServiceRunStateError> {
        match self {
            Self::Writer(pair) => pair.retire(),
            Self::Observed(pair) => pair.retire(),
            Self::Prepared(pair) => pair.retire(),
            Self::Committed(pair) => pair.retire(),
            Self::Reread(pair) => pair.retire(),
            Self::Known(pair) => pair.retire(),
            Self::ExpectationMismatch(pair) => pair.retire(),
            Self::Ambiguous(pair) => pair.retire(),
            Self::ReloadFailure(pair) => pair.retire(),
            Self::Reloaded(pair) => pair.retire(),
            Self::ReleaseWithWriter(pair) => pair.retire(),
        }
    }
}

/// Terminal composite retaining logical exit authority and the exact OS writer.
#[must_use = "the Windows terminal writer must be explicitly retired"]
pub(super) struct WindowsTerminalFailure<'key> {
    reason: RecoveryRequired,
    platform_cause: Option<ServiceRunStateError>,
    logical: WriterExitPending,
    pair: WindowsTerminalPair,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl<'key> WindowsTerminalFailure<'key> {
    fn new(
        reason: RecoveryRequired,
        platform_cause: Option<ServiceRunStateError>,
        logical: WriterExitPending,
        pair: WindowsTerminalPair,
        key: &'key FixtureRunStateAuthenticationKey,
    ) -> Self {
        Self {
            reason,
            platform_cause,
            logical,
            pair,
            key,
        }
    }

    fn from_durable(
        failure: DurableFailureWithWriter,
        pair: WindowsTerminalPair,
        key: &'key FixtureRunStateAuthenticationKey,
    ) -> Self {
        let reason = failure.reason();
        Self::new(reason, None, failure.into_writer_exit(), pair, key)
    }

    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    pub(super) const fn platform_cause(&self) -> Option<ServiceRunStateError> {
        self.platform_cause
    }

    pub(super) fn retire(
        self,
    ) -> Result<WindowsRecoveryExit<'key>, WindowsRetirementFailure<'key>> {
        let Self {
            reason,
            platform_cause,
            logical,
            pair,
            key,
        } = self;
        // Every constructor that produces `WriterExitPending` currently leaves
        // this one-shot operation Ready. Keep the check fail-closed anyway: if
        // that creation invariant ever regresses, OS retirement is still
        // attempted and no logical or platform receipt is fabricated.
        if logical.operation.begin_release().is_err() {
            let cause = pair.retire().err().unwrap_or(ServiceRunStateError::Release);
            return Err(WindowsRetirementFailure {
                reason,
                cause,
                _logical: logical,
                key,
            });
        }
        let pair = match pair.retire() {
            Ok(pair) => pair,
            Err(cause) => {
                return Err(WindowsRetirementFailure {
                    reason,
                    cause,
                    _logical: logical,
                    key,
                });
            }
        };
        if logical.operation.record_release_receipt().is_err() {
            return Err(WindowsRetirementFailure {
                reason,
                cause: ServiceRunStateError::Release,
                _logical: logical,
                key,
            });
        }
        let receipt = WriterExitReceipt {
            installation: logical.lease.installation,
            epoch: logical.lease.epoch,
            binding: logical.lease.binding,
        };
        match logical.complete(receipt) {
            Ok(logical) => Ok(WindowsRecoveryExit {
                reason,
                platform_cause,
                _logical: logical,
                _pair: pair,
                key,
            }),
            Err(failure) => Err(WindowsRetirementFailure {
                reason: failure.reason(),
                cause: ServiceRunStateError::Release,
                _logical: failure.into_writer_exit(),
                key,
            }),
        }
    }
}

impl fmt::Debug for WindowsTerminalFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsTerminalFailure")
            .field("reason", &self.reason)
            .field("platform_cause", &self.platform_cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Exact terminal retirement evidence; it can never re-enter normal runtime.
pub(super) struct WindowsRecoveryExit<'key> {
    reason: RecoveryRequired,
    platform_cause: Option<ServiceRunStateError>,
    _logical: RecoveryExitEvidence,
    _pair: WindowsPairRetired,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl WindowsRecoveryExit<'_> {
    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }
    pub(super) const fn platform_cause(&self) -> Option<ServiceRunStateError> {
        self.platform_cause
    }
}

impl fmt::Debug for WindowsRecoveryExit<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.key;
        formatter
            .debug_struct("WindowsRecoveryExit")
            .field("reason", &self.reason)
            .field("platform_cause", &self.platform_cause)
            .finish()
    }
}

/// Irrecoverable checked-retirement failure. No normal receipt can follow.
pub(super) struct WindowsRetirementFailure<'key> {
    reason: RecoveryRequired,
    cause: ServiceRunStateError,
    _logical: WriterExitPending,
    key: &'key FixtureRunStateAuthenticationKey,
}

impl fmt::Debug for WindowsRetirementFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.key;
        formatter
            .debug_struct("WindowsRetirementFailure")
            .field("reason", &self.reason)
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_agent_service::run_state_root::{RuntimePairFault, RuntimePairFixture};

    use super::super::{Commitment, RunMarkerState, build_snapshot};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;

    fn test_installation(byte: u8) -> Result<InstallationIdentity, RecoveryRequired> {
        InstallationIdentity::from_fixed_bytes([byte; 32])
    }

    fn test_key(byte: u8) -> Result<FixtureRunStateAuthenticationKey, RecoveryRequired> {
        FixtureRunStateAuthenticationKey::from_fixture_bytes([byte; 32])
    }

    fn snapshot(
        state: RunMarkerState,
        generation: u64,
        installation: InstallationIdentity,
        key: &FixtureRunStateAuthenticationKey,
    ) -> Result<super::super::CanonicalSnapshot, RecoveryRequired> {
        build_snapshot(
            state,
            NonZeroU64::new(generation).ok_or(RecoveryRequired::GenerationExhausted)?,
            installation,
            Commitment::ZERO,
            key,
        )
        .map(|durable| durable.bytes)
    }

    fn install_pair(
        fixture: &RuntimePairFixture,
        candidate: &super::super::CanonicalSnapshot,
    ) -> TestResult {
        let pair = WindowsPairWriter::from_held_writer(fixture.acquire_writer()?);
        let observed = match pair.observe() {
            Ok(observed) => observed,
            Err(failure) => {
                let cause = failure.cause();
                let _ = failure.retire();
                return Err(cause.into());
            }
        };
        let prepared = match observed.prepare_commit(ExpectedWindowsPair::missing(), *candidate) {
            Ok(prepared) => prepared,
            Err(failure) => {
                let _retired = failure.retire()?;
                return Err(std::io::Error::other(
                    "fresh runtime fixture did not expose a missing pair",
                )
                .into());
            }
        };
        let committed = match prepared.commit() {
            WindowsPairCommitOutcome::Committed(committed) => committed,
            WindowsPairCommitOutcome::KnownNotCommitted(failure) => {
                let cause = failure.cause();
                let _retired = failure.retire()?;
                return Err(cause.into());
            }
            WindowsPairCommitOutcome::Ambiguous(failure) => {
                let cause = failure.cause();
                let _retired = failure.retire()?;
                return Err(cause.into());
            }
        };
        let reread = match committed.reread() {
            Ok(reread) => reread,
            Err(failure) => {
                let cause = failure.cause();
                let _retired = failure.retire()?;
                return Err(cause.into());
            }
        };
        match reread.continue_observed().release_verified() {
            Ok(released) if released.pair() == *candidate => Ok(()),
            Ok(_released) => Err(std::io::Error::other(
                "initial pair release named a different canonical snapshot",
            )
            .into()),
            Err(WindowsPairReleaseFailure::WriterRetained(failure)) => {
                let cause = failure.cause();
                let _retired = failure.retire()?;
                Err(cause.into())
            }
            Err(WindowsPairReleaseFailure::WriterReleasedNoReceipt(failure)) => {
                Err(failure.cause().into())
            }
        }
    }

    fn start<'key>(
        fixture: &RuntimePairFixture,
        installation: InstallationIdentity,
        key: &'key FixtureRunStateAuthenticationKey,
    ) -> TestResultWith<WindowsBootEvidence<'key>> {
        match start_windows_runtime(fixture.acquire_writer()?, installation, key) {
            Ok(boot) => Ok(boot),
            Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                let reason = failure.reason();
                let _retired = failure.retire()?;
                Err(reason.into())
            }
            Err(WindowsRuntimeStartFailure::Terminal(failure)) => {
                let reason = failure.reason();
                match failure.retire() {
                    Ok(_exit) => Err(reason.into()),
                    Err(retirement) => Err(std::io::Error::other(format!(
                        "runtime start retirement failed: {retirement:?}"
                    ))
                    .into()),
                }
            }
        }
    }

    fn retire_terminal(failure: WindowsTerminalFailure<'_>) -> TestResult {
        let reason = failure.reason();
        match failure.retire() {
            Ok(_exit) => Err(reason.into()),
            Err(retirement) => Err(std::io::Error::other(format!(
                "terminal composite retirement failed: {retirement:?}"
            ))
            .into()),
        }
    }

    fn retire_checked(failure: WindowsTerminalFailure<'_>) -> TestResult {
        failure.retire().map(|_exit| ()).map_err(|failure| {
            std::io::Error::other(format!("terminal composite retirement failed: {failure:?}"))
                .into()
        })
    }

    fn prepare_active<'key>(
        fixture: &RuntimePairFixture,
        installation: InstallationIdentity,
        key: &'key FixtureRunStateAuthenticationKey,
    ) -> TestResultWith<WindowsPreparedActiveTransition<'key>> {
        let boot = start(fixture, installation, key)?;
        match boot.prepare_active() {
            Ok(prepared) => Ok(prepared),
            Err(failure) => {
                let reason = failure.reason();
                retire_checked(failure)?;
                Err(reason.into())
            }
        }
    }

    fn exact_active<'key>(
        fixture: &RuntimePairFixture,
        installation: InstallationIdentity,
        key: &'key FixtureRunStateAuthenticationKey,
    ) -> TestResultWith<WindowsActiveRunLease<'key>> {
        match prepare_active(fixture, installation, key)?.commit_and_reread() {
            WindowsActiveCommitOutcome::Active(active) => Ok(active),
            WindowsActiveCommitOutcome::ReloadRequired(reload) => {
                retire_checked(reload.into_terminal(RecoveryRequired::CommitReloadRequired))?;
                Err(RecoveryRequired::CommitReloadRequired.into())
            }
            WindowsActiveCommitOutcome::Terminal(failure) => {
                let reason = failure.reason();
                retire_checked(failure)?;
                Err(reason.into())
            }
        }
    }

    fn exact_clean<'key>(
        fixture: &RuntimePairFixture,
        installation: InstallationIdentity,
        key: &'key FixtureRunStateAuthenticationKey,
    ) -> TestResultWith<WindowsCleanWithWriter<'key>> {
        match exact_active(fixture, installation, key)?.commit_clean() {
            WindowsCleanCommitOutcome::Clean(clean) => Ok(clean),
            WindowsCleanCommitOutcome::ReloadRequired(reload) => {
                retire_checked(reload.into_terminal(RecoveryRequired::CommitReloadRequired))?;
                Err(RecoveryRequired::CommitReloadRequired.into())
            }
            WindowsCleanCommitOutcome::Terminal(failure) => {
                let reason = failure.reason();
                retire_checked(failure)?;
                Err(reason.into())
            }
        }
    }

    #[test]
    fn kernel_clean_boot_active_clean_stop_is_exact() -> TestResult {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0x31)?;
        let key = test_key(0x42)?;
        let initial = snapshot(RunMarkerState::Clean, 1, installation, &key)?;
        install_pair(&fixture, &initial)?;

        let boot = start(&fixture, installation, &key)?;
        assert_eq!(boot.generation().get(), 1);
        let prepared = boot.prepare_active().map_err(|failure| {
            let reason = failure.reason();
            let _ = failure.retire();
            reason
        })?;
        let active = match prepared.commit_and_reread() {
            WindowsActiveCommitOutcome::Active(active) => active,
            WindowsActiveCommitOutcome::ReloadRequired(reload) => {
                return match reload.reload() {
                    WindowsActiveReloadOutcome::Terminal(failure) => retire_terminal(failure),
                    WindowsActiveReloadOutcome::Boot(_boot) => Err(std::io::Error::other(
                        "exact Active commit reloaded as prior Clean",
                    )
                    .into()),
                    WindowsActiveReloadOutcome::Active(_active) => Err(std::io::Error::other(
                        "exact Active commit unexpectedly required reload",
                    )
                    .into()),
                };
            }
            WindowsActiveCommitOutcome::Terminal(failure) => return retire_terminal(failure),
        };
        assert_eq!(active.generation().get(), 2);
        let clean = match active.commit_clean() {
            WindowsCleanCommitOutcome::Clean(clean) => clean,
            WindowsCleanCommitOutcome::ReloadRequired(reload) => {
                return match reload.reload() {
                    WindowsCleanReloadOutcome::Clean(_clean) => Err(std::io::Error::other(
                        "exact Clean commit unexpectedly required reload",
                    )
                    .into()),
                    WindowsCleanReloadOutcome::Terminal(failure) => retire_terminal(failure),
                };
            }
            WindowsCleanCommitOutcome::Terminal(failure) => return retire_terminal(failure),
        };
        assert_eq!(clean.generation().get(), 3);
        match clean.stop() {
            WindowsStopOutcome::Stopped(stopped) => assert_eq!(stopped.generation().get(), 3),
            WindowsStopOutcome::Terminal(failure) => return retire_terminal(failure),
            WindowsStopOutcome::ReleasedNoReceipt(failure) => {
                return Err(failure.cause().into());
            }
            WindowsStopOutcome::PostReleaseTerminal(failure) => {
                return Err(failure.reason().into());
            }
        }
        fixture.cleanup_checked()
    }

    #[test]
    fn kernel_missing_pair_is_terminal_and_checked_retired() -> TestResult {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0x53)?;
        let key = test_key(0x64)?;
        let failure = match start_windows_runtime(fixture.acquire_writer()?, installation, &key) {
            Err(WindowsRuntimeStartFailure::Terminal(failure)) => failure,
            Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                let reason = failure.reason();
                let _retired = failure.retire()?;
                return Err(reason.into());
            }
            Ok(_boot) => {
                return Err(std::io::Error::other("missing pair minted boot evidence").into());
            }
        };
        assert_eq!(failure.reason(), RecoveryRequired::MissingRunMarker);
        assert!(format!("{failure:?}").contains("[REDACTED]"));
        let _exit = failure.retire().map_err(|failure| {
            std::io::Error::other(format!("missing-pair retirement failed: {failure:?}"))
        })?;
        fixture.cleanup_checked()
    }

    #[test]
    fn kernel_wrong_key_and_nonclean_pairs_never_boot() -> TestResult {
        let wrong_key_fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0x75)?;
        let original_key = test_key(0x86)?;
        let wrong_key = test_key(0x97)?;
        install_pair(
            &wrong_key_fixture,
            &snapshot(RunMarkerState::Clean, 1, installation, &original_key)?,
        )?;
        let failure = match start_windows_runtime(
            wrong_key_fixture.acquire_writer()?,
            installation,
            &wrong_key,
        ) {
            Err(WindowsRuntimeStartFailure::Terminal(failure)) => failure,
            Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                let reason = failure.reason();
                let _retired = failure.retire()?;
                return Err(reason.into());
            }
            Ok(_boot) => return Err(std::io::Error::other("wrong key booted").into()),
        };
        assert_eq!(failure.reason(), RecoveryRequired::AuthenticationFailed);
        let _exit = failure.retire().map_err(|failure| {
            std::io::Error::other(format!("wrong-key retirement failed: {failure:?}"))
        })?;
        wrong_key_fixture.cleanup_checked()?;

        let wrong_install_fixture = RuntimePairFixture::new()?;
        let installed = test_installation(0x98)?;
        let presented = test_installation(0x99)?;
        let key = test_key(0x9a)?;
        let initial = snapshot(RunMarkerState::Clean, 1, installed, &key)?;
        install_pair(&wrong_install_fixture, &initial)?;
        let failure =
            match start_windows_runtime(wrong_install_fixture.acquire_writer()?, presented, &key) {
                Err(WindowsRuntimeStartFailure::Terminal(failure)) => failure,
                Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                    let reason = failure.reason();
                    let _retired = failure.retire()?;
                    return Err(reason.into());
                }
                Ok(_boot) => {
                    return Err(std::io::Error::other("wrong installation booted").into());
                }
            };
        assert_eq!(
            failure.reason(),
            RecoveryRequired::InstallationIdentityMismatch
        );
        retire_checked(failure)?;
        wrong_install_fixture.cleanup_checked()?;

        for (state, byte) in [
            (RunMarkerState::Active, 0xa8),
            (RunMarkerState::RecoveryRequired, 0xb9),
        ] {
            let fixture = RuntimePairFixture::new()?;
            let installation = test_installation(byte)?;
            let key = test_key(byte.wrapping_add(1))?;
            install_pair(&fixture, &snapshot(state, 1, installation, &key)?)?;
            let failure = match start_windows_runtime(fixture.acquire_writer()?, installation, &key)
            {
                Err(WindowsRuntimeStartFailure::Terminal(failure)) => failure,
                Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                    let reason = failure.reason();
                    let _retired = failure.retire()?;
                    return Err(reason.into());
                }
                Ok(_boot) => {
                    return Err(std::io::Error::other("non-Clean pair booted").into());
                }
            };
            assert_eq!(failure.reason(), RecoveryRequired::PersistedNonCleanState);
            let _exit = failure.retire().map_err(|failure| {
                std::io::Error::other(format!("non-Clean retirement failed: {failure:?}"))
            })?;
            fixture.cleanup_checked()?;
        }
        Ok(())
    }

    #[test]
    fn kernel_active_ambiguity_reload_classifies_prior_candidate_and_partial() -> TestResult {
        #[derive(Clone, Copy)]
        enum ExpectedResolution {
            Prior,
            Candidate,
            Partial,
        }

        for (fault, expected, byte) in [
            (
                RuntimePairFault::MarkerRenameAttempt,
                ExpectedResolution::Prior,
                0xc1,
            ),
            (
                RuntimePairFault::AfterCheckpointRename,
                ExpectedResolution::Candidate,
                0xc2,
            ),
            (
                RuntimePairFault::AfterMarkerRename,
                ExpectedResolution::Partial,
                0xc3,
            ),
        ] {
            let fixture = RuntimePairFixture::new()?;
            let installation = test_installation(byte)?;
            let key = test_key(byte.wrapping_add(1))?;
            let initial = snapshot(RunMarkerState::Clean, 1, installation, &key)?;
            install_pair(&fixture, &initial)?;
            let prepared = prepare_active(&fixture, installation, &key)?;
            fixture.inject_fault(fault);
            let reload = match prepared.commit_and_reread() {
                WindowsActiveCommitOutcome::ReloadRequired(reload) => reload,
                WindowsActiveCommitOutcome::Active(active) => {
                    retire_checked(active.into_terminal(RecoveryRequired::CommitReloadRequired))?;
                    return Err(std::io::Error::other(
                        "faulted Active commit bypassed mandatory reload",
                    )
                    .into());
                }
                WindowsActiveCommitOutcome::Terminal(failure) => {
                    let reason = failure.reason();
                    retire_checked(failure)?;
                    return Err(reason.into());
                }
            };
            match (expected, reload.reload()) {
                (ExpectedResolution::Prior, WindowsActiveReloadOutcome::Boot(boot)) => {
                    assert_eq!(boot.generation().get(), 1);
                    retire_checked(boot.into_terminal(RecoveryRequired::WindowsBackendFailure))?;
                }
                (ExpectedResolution::Candidate, WindowsActiveReloadOutcome::Active(active)) => {
                    assert_eq!(active.generation().get(), 2);
                    retire_checked(active.into_terminal(RecoveryRequired::WindowsBackendFailure))?;
                }
                (ExpectedResolution::Partial, WindowsActiveReloadOutcome::Terminal(failure)) => {
                    assert_ne!(failure.reason(), RecoveryRequired::CommitReloadRequired);
                    retire_checked(failure)?;
                }
                (_, WindowsActiveReloadOutcome::Boot(boot)) => {
                    retire_checked(boot.into_terminal(RecoveryRequired::WindowsBackendFailure))?;
                    return Err(std::io::Error::other(
                        "Active ambiguity reloaded an unexpected prior pair",
                    )
                    .into());
                }
                (_, WindowsActiveReloadOutcome::Active(active)) => {
                    retire_checked(active.into_terminal(RecoveryRequired::WindowsBackendFailure))?;
                    return Err(std::io::Error::other(
                        "Active ambiguity reloaded an unexpected candidate pair",
                    )
                    .into());
                }
                (_, WindowsActiveReloadOutcome::Terminal(failure)) => {
                    let reason = failure.reason();
                    retire_checked(failure)?;
                    return Err(reason.into());
                }
            }
            fixture.cleanup_checked()?;
        }
        Ok(())
    }

    #[test]
    fn kernel_confirmed_active_reread_failure_never_reloads_as_boot() -> TestResult {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0xd1)?;
        let key = test_key(0xd2)?;
        let initial = snapshot(RunMarkerState::Clean, 1, installation, &key)?;
        install_pair(&fixture, &initial)?;
        let prepared = prepare_active(&fixture, installation, &key)?;
        fixture.inject_fault(RuntimePairFault::CommittedRereadRevalidation);
        match prepared.commit_and_reread() {
            WindowsActiveCommitOutcome::Terminal(failure) => {
                assert_eq!(failure.reason(), RecoveryRequired::RereadDrift);
                assert!(failure.platform_cause().is_some());
                let retirement = match failure.retire() {
                    Err(retirement) => retirement,
                    Ok(_exit) => {
                        return Err(std::io::Error::other(
                            "reread close ambiguity minted a retirement receipt",
                        )
                        .into());
                    }
                };
                assert_eq!(retirement.reason, RecoveryRequired::RereadDrift);
                assert_eq!(retirement.cause, ServiceRunStateError::Release);
            }
            WindowsActiveCommitOutcome::ReloadRequired(reload) => {
                retire_checked(reload.into_terminal(RecoveryRequired::RereadDrift))?;
                return Err(std::io::Error::other(
                    "confirmed Active commit exposed the pre-commit reload surface",
                )
                .into());
            }
            WindowsActiveCommitOutcome::Active(active) => {
                retire_checked(active.into_terminal(RecoveryRequired::RereadDrift))?;
                return Err(std::io::Error::other(
                    "injected independent reread failure minted Active authority",
                )
                .into());
            }
        }
        fixture.cleanup_checked()
    }

    #[test]
    fn kernel_clean_ambiguity_reload_accepts_only_exact_candidate() -> TestResult {
        #[derive(Clone, Copy)]
        enum ExpectedResolution {
            Candidate,
            Prior,
            Partial,
        }

        for (fault, expected, byte) in [
            (
                RuntimePairFault::AfterCheckpointRename,
                ExpectedResolution::Candidate,
                0xe1,
            ),
            (
                RuntimePairFault::MarkerRenameAttempt,
                ExpectedResolution::Prior,
                0xe2,
            ),
            (
                RuntimePairFault::AfterMarkerRename,
                ExpectedResolution::Partial,
                0xe3,
            ),
        ] {
            let fixture = RuntimePairFixture::new()?;
            let installation = test_installation(byte)?;
            let key = test_key(byte.wrapping_add(1))?;
            let initial = snapshot(RunMarkerState::Clean, 1, installation, &key)?;
            install_pair(&fixture, &initial)?;
            let active = exact_active(&fixture, installation, &key)?;
            fixture.inject_fault(fault);
            let reload = match active.commit_clean() {
                WindowsCleanCommitOutcome::ReloadRequired(reload) => reload,
                WindowsCleanCommitOutcome::Clean(clean) => {
                    retire_checked(clean.into_terminal(RecoveryRequired::CommitReloadRequired))?;
                    return Err(std::io::Error::other(
                        "faulted Clean commit bypassed mandatory reload",
                    )
                    .into());
                }
                WindowsCleanCommitOutcome::Terminal(failure) => {
                    let reason = failure.reason();
                    retire_checked(failure)?;
                    return Err(reason.into());
                }
            };
            match (expected, reload.reload()) {
                (ExpectedResolution::Candidate, WindowsCleanReloadOutcome::Clean(clean)) => {
                    assert_eq!(clean.generation().get(), 3);
                    retire_checked(clean.into_terminal(RecoveryRequired::WindowsBackendFailure))?;
                }
                (ExpectedResolution::Prior, WindowsCleanReloadOutcome::Terminal(failure)) => {
                    assert_eq!(
                        failure.reason(),
                        RecoveryRequired::AmbiguousCleanCommitNotApplied
                    );
                    retire_checked(failure)?;
                }
                (ExpectedResolution::Partial, WindowsCleanReloadOutcome::Terminal(failure)) => {
                    assert_ne!(
                        failure.reason(),
                        RecoveryRequired::AmbiguousCleanCommitNotApplied
                    );
                    retire_checked(failure)?;
                }
                (_, WindowsCleanReloadOutcome::Clean(clean)) => {
                    retire_checked(clean.into_terminal(RecoveryRequired::WindowsBackendFailure))?;
                    return Err(std::io::Error::other(
                        "non-candidate Clean ambiguity minted Clean authority",
                    )
                    .into());
                }
                (_, WindowsCleanReloadOutcome::Terminal(failure)) => {
                    let reason = failure.reason();
                    retire_checked(failure)?;
                    return Err(reason.into());
                }
            }
            fixture.cleanup_checked()?;
        }
        Ok(())
    }

    #[test]
    fn kernel_stop_failures_never_mint_stopped() -> TestResult {
        let retained_fixture = RuntimePairFixture::new()?;
        let retained_installation = test_installation(0xf1)?;
        let retained_key = test_key(0xf2)?;
        let initial = snapshot(
            RunMarkerState::Clean,
            1,
            retained_installation,
            &retained_key,
        )?;
        install_pair(&retained_fixture, &initial)?;
        let clean = exact_clean(&retained_fixture, retained_installation, &retained_key)?;
        retained_fixture.inject_fault(RuntimePairFault::WriterReleaseUnlock);
        match clean.stop() {
            WindowsStopOutcome::Terminal(failure) => {
                assert_eq!(failure.reason(), RecoveryRequired::WriterReleaseAmbiguous);
                retire_checked(failure)?;
            }
            WindowsStopOutcome::Stopped(_stopped) => {
                return Err(std::io::Error::other(
                    "writer-retaining release fault minted Stopped evidence",
                )
                .into());
            }
            WindowsStopOutcome::ReleasedNoReceipt(failure) => {
                return Err(failure.cause().into());
            }
            WindowsStopOutcome::PostReleaseTerminal(failure) => {
                return Err(failure.reason().into());
            }
        }
        retained_fixture.cleanup_checked()?;

        let no_receipt_fixture = RuntimePairFixture::new()?;
        let no_receipt_installation = test_installation(0xf3)?;
        let no_receipt_key = test_key(0xf4)?;
        let initial = snapshot(
            RunMarkerState::Clean,
            1,
            no_receipt_installation,
            &no_receipt_key,
        )?;
        install_pair(&no_receipt_fixture, &initial)?;
        let clean = exact_clean(
            &no_receipt_fixture,
            no_receipt_installation,
            &no_receipt_key,
        )?;
        no_receipt_fixture.inject_fault(RuntimePairFault::CheckpointFinalClose);
        match clean.stop() {
            WindowsStopOutcome::ReleasedNoReceipt(failure) => {
                assert_eq!(failure.reason(), RecoveryRequired::WriterReleaseAmbiguous);
                assert_eq!(failure.cause(), ServiceRunStateError::Release);
            }
            WindowsStopOutcome::Stopped(_stopped) => {
                return Err(
                    std::io::Error::other("pair-close ambiguity minted Stopped evidence").into(),
                );
            }
            WindowsStopOutcome::Terminal(failure) => return retire_terminal(failure),
            WindowsStopOutcome::PostReleaseTerminal(failure) => {
                return Err(failure.reason().into());
            }
        }
        no_receipt_fixture.cleanup_checked()
    }

    #[test]
    fn kernel_stop_precheck_rejects_crossed_pair_before_release() -> TestResult {
        let first_fixture = RuntimePairFixture::new()?;
        let first_installation = test_installation(0x11)?;
        let first_key = test_key(0x12)?;
        let first_initial = snapshot(RunMarkerState::Clean, 1, first_installation, &first_key)?;
        install_pair(&first_fixture, &first_initial)?;
        let first = exact_clean(&first_fixture, first_installation, &first_key)?;

        let second_fixture = RuntimePairFixture::new()?;
        let second_installation = test_installation(0x13)?;
        let second_key = test_key(0x14)?;
        let second_initial = snapshot(RunMarkerState::Clean, 1, second_installation, &second_key)?;
        install_pair(&second_fixture, &second_initial)?;
        let second = exact_clean(&second_fixture, second_installation, &second_key)?;

        let WindowsCleanWithWriter {
            logical: first_logical,
            pair: first_pair,
            key: first_key,
        } = first;
        let WindowsCleanWithWriter {
            logical: second_logical,
            pair: second_pair,
            key: second_key,
        } = second;
        for crossed in [
            WindowsCleanWithWriter {
                logical: first_logical,
                pair: second_pair,
                key: first_key,
            },
            WindowsCleanWithWriter {
                logical: second_logical,
                pair: first_pair,
                key: second_key,
            },
        ] {
            match crossed.stop() {
                WindowsStopOutcome::Terminal(failure) => {
                    assert_eq!(failure.reason(), RecoveryRequired::CompareAndSwapConflict);
                    retire_checked(failure)?;
                }
                WindowsStopOutcome::Stopped(_stopped) => {
                    return Err(std::io::Error::other(
                        "crossed logical/pair authority minted Stopped evidence",
                    )
                    .into());
                }
                WindowsStopOutcome::ReleasedNoReceipt(failure) => {
                    return Err(failure.cause().into());
                }
                WindowsStopOutcome::PostReleaseTerminal(failure) => {
                    return Err(failure.reason().into());
                }
            }
        }
        first_fixture.cleanup_checked()?;
        second_fixture.cleanup_checked()
    }

    #[test]
    fn kernel_live_and_reload_states_have_checked_terminal_retirement() -> TestResult {
        let live_fixture = RuntimePairFixture::new()?;
        let live_installation = test_installation(0x21)?;
        let live_key = test_key(0x22)?;
        let initial = snapshot(RunMarkerState::Clean, 1, live_installation, &live_key)?;
        install_pair(&live_fixture, &initial)?;
        let boot = start(&live_fixture, live_installation, &live_key)?;
        retire_checked(boot.into_terminal(RecoveryRequired::WindowsBackendFailure))?;
        live_fixture.cleanup_checked()?;

        let reload_fixture = RuntimePairFixture::new()?;
        let reload_installation = test_installation(0x23)?;
        let reload_key = test_key(0x24)?;
        let initial = snapshot(RunMarkerState::Clean, 1, reload_installation, &reload_key)?;
        install_pair(&reload_fixture, &initial)?;
        let prepared = prepare_active(&reload_fixture, reload_installation, &reload_key)?;
        reload_fixture.inject_fault(RuntimePairFault::AfterMarkerRename);
        let reload = match prepared.commit_and_reread() {
            WindowsActiveCommitOutcome::ReloadRequired(reload) => reload,
            WindowsActiveCommitOutcome::Active(active) => {
                retire_checked(active.into_terminal(RecoveryRequired::CommitReloadRequired))?;
                return Err(std::io::Error::other("fault did not produce reload authority").into());
            }
            WindowsActiveCommitOutcome::Terminal(failure) => {
                let reason = failure.reason();
                retire_checked(failure)?;
                return Err(reason.into());
            }
        };
        retire_checked(reload.into_terminal(RecoveryRequired::CommitReloadRequired))?;
        reload_fixture.cleanup_checked()
    }

    #[test]
    fn composite_authority_and_receipts_are_move_only() {
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

        assert_move_only!(WindowsRuntimeStartFailure<'static>);
        assert_move_only!(WindowsRuntimeWriterAcquired<'static>);
        assert_move_only!(WindowsBootEvidence<'static>);
        assert_move_only!(WindowsPreparedActiveTransition<'static>);
        assert_move_only!(WindowsActiveCommitOutcome<'static>);
        assert_move_only!(WindowsActiveRunLease<'static>);
        assert_move_only!(WindowsActiveReloadRequired<'static>);
        assert_move_only!(WindowsActiveReloadOutcome<'static>);
        assert_move_only!(WindowsCleanCommitOutcome<'static>);
        assert_move_only!(WindowsCleanWithWriter<'static>);
        assert_move_only!(WindowsCleanReloadRequired<'static>);
        assert_move_only!(WindowsCleanReloadOutcome<'static>);
        assert_move_only!(WindowsStopOutcome<'static>);
        assert_move_only!(WindowsStoppedRunEvidence);
        assert_move_only!(WindowsTerminalFailure<'static>);
        assert_move_only!(WindowsReleasedNoReceipt<'static>);
        assert_move_only!(WindowsPostReleaseTerminal<'static>);
        assert_move_only!(WindowsRecoveryExit<'static>);
        assert_move_only!(WindowsRetirementFailure<'static>);
    }

    #[test]
    fn composite_live_states_expose_consuming_terminal_transitions() {
        let _: fn(
            WindowsRuntimeWriterAcquired<'static>,
            RecoveryRequired,
        ) -> WindowsTerminalFailure<'static> = WindowsRuntimeWriterAcquired::into_terminal;
        let _: fn(
            WindowsBootEvidence<'static>,
            RecoveryRequired,
        ) -> WindowsTerminalFailure<'static> = WindowsBootEvidence::into_terminal;
        let _: fn(
            WindowsPreparedActiveTransition<'static>,
            RecoveryRequired,
        ) -> WindowsTerminalFailure<'static> = WindowsPreparedActiveTransition::into_terminal;
        let _: fn(
            WindowsActiveRunLease<'static>,
            RecoveryRequired,
        ) -> WindowsTerminalFailure<'static> = WindowsActiveRunLease::into_terminal;
        let _: fn(
            WindowsActiveReloadRequired<'static>,
            RecoveryRequired,
        ) -> WindowsTerminalFailure<'static> = WindowsActiveReloadRequired::into_terminal;
        let _: fn(
            WindowsCleanWithWriter<'static>,
            RecoveryRequired,
        ) -> WindowsTerminalFailure<'static> = WindowsCleanWithWriter::into_terminal;
        let _: fn(
            WindowsCleanReloadRequired<'static>,
            RecoveryRequired,
        ) -> WindowsTerminalFailure<'static> = WindowsCleanReloadRequired::into_terminal;
    }
}
