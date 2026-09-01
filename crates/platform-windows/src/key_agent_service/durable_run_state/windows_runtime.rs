//! Dormant Windows composite binding the Phase 2D logical writer to one
//! independently verified fixed marker/checkpoint pair.
//!
//! This module deliberately has no production caller or authentication-provider
//! source. Its move-only typestates keep the logical and operating-system
//! writer authorities together until normal stopped evidence or terminal
//! retirement is reached.

use core::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use super::super::run_state_root::RuntimePairFixture;
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
    CommittedCleanMarker, DurableFailureWithWriter, PendingFinalWriterRelease,
    PreparedActiveTransition, PreparedCleanTransition, RecoveryExitEvidence, RecoveryRequired,
    ReloadedActiveRunState, RereadActiveMarker, RereadCleanMarker, RuntimeRunStateAuthority,
    RuntimeWriterAcquired, StoppedRunEvidence, WriterExitPending, WriterExitReceipt,
    WriterLeaseReleaseReceipt, WriterObservation,
};
#[cfg(test)]
use super::{InstallationIdentity, RunStateAuthenticationProvider};

static NEXT_WINDOWS_BACKEND_BINDING: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
std::thread_local! {
    static POST_RELEASE_RECEIPT_FAULT_FOR_TEST: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
struct PostReleaseReceiptFaultGuard;

#[cfg(test)]
impl PostReleaseReceiptFaultGuard {
    fn arm() -> Self {
        POST_RELEASE_RECEIPT_FAULT_FOR_TEST.with(|fault| fault.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for PostReleaseReceiptFaultGuard {
    fn drop(&mut self) {
        POST_RELEASE_RECEIPT_FAULT_FOR_TEST.with(|fault| fault.set(false));
    }
}

#[cfg(test)]
fn take_post_release_receipt_fault_for_test() -> bool {
    POST_RELEASE_RECEIPT_FAULT_FOR_TEST.with(|fault| fault.replace(false))
}

fn allocate_windows_backend_binding() -> Result<NonZeroU64, RecoveryRequired> {
    let value = NEXT_WINDOWS_BACKEND_BINDING
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| RecoveryRequired::BackendBindingExhausted)?;
    NonZeroU64::new(value).ok_or(RecoveryRequired::BackendBindingExhausted)
}

/// Installs one generation-one authenticated Clean pair for sibling
/// Windows-lifecycle kernel tests. The opaque fixture retains every path,
/// identity, and handle; this helper returns no pair or writer authority.
#[cfg(test)]
pub(in crate::key_agent_service) fn install_windows_runtime_clean_fixture(
    fixture: &RuntimePairFixture,
    installation: InstallationIdentity,
    provider: &RunStateAuthenticationProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    if installation != provider.installation() {
        return Err(RecoveryRequired::InstallationIdentityMismatch.into());
    }
    let generation = NonZeroU64::new(1).ok_or(RecoveryRequired::GenerationExhausted)?;
    let candidate = super::build_snapshot(
        super::RunMarkerState::Clean,
        generation,
        super::Commitment::ZERO,
        provider,
    )?
    .bytes;
    install_pair_for_test(fixture, &candidate)
}

#[cfg(test)]
fn install_pair_for_test(
    fixture: &RuntimePairFixture,
    candidate: &super::CanonicalSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
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

/// Starts the dormant Windows composite from an already-held exclusive OS
/// writer. Authentication happens only after the fresh pair observation.
#[allow(clippy::large_types_passed_by_value)] // Transfers the opaque writer once.
#[allow(clippy::result_large_err)] // Failure retains both move-only authorities.
pub(in crate::key_agent_service) fn start_windows_runtime(
    writer: HeldServiceRunStateWriter,
    authority: RuntimeRunStateAuthority<'_>,
) -> Result<WindowsBootEvidence<'_>, WindowsRuntimeStartFailure<'_>> {
    let acquired = WindowsRuntimeWriterAcquired::from_held_writer(writer, authority)
        .map_err(WindowsRuntimeStartFailure::Binding)?;
    acquired
        .authenticate()
        .map_err(WindowsRuntimeStartFailure::Terminal)
}

/// Complete startup failure split by whether a logical binding was allocated.
#[must_use = "a failed Windows runtime start must be terminally retired"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(in crate::key_agent_service) enum WindowsRuntimeStartFailure<'provider> {
    Binding(WindowsRuntimeBindingFailure<'provider>),
    Terminal(WindowsTerminalFailure<'provider>),
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
pub(in crate::key_agent_service) struct WindowsRuntimeBindingFailure<'provider> {
    reason: RecoveryRequired,
    pair: WindowsPairWriter,
    authority: RuntimeRunStateAuthority<'provider>,
}

impl<'provider> WindowsRuntimeBindingFailure<'provider> {
    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    pub(in crate::key_agent_service) fn retire(
        self,
    ) -> Result<WindowsUnboundRetired<'provider>, WindowsUnboundRetirementFailure<'provider>> {
        let Self {
            pair, authority, ..
        } = self;
        match pair.retire() {
            Ok(pair) => Ok(WindowsUnboundRetired {
                _pair: pair,
                _authority: authority,
            }),
            Err(cause) => Err(WindowsUnboundRetirementFailure {
                cause,
                _authority: authority,
            }),
        }
    }
}

impl fmt::Debug for WindowsRuntimeBindingFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsRuntimeBindingFailure")
            .field("reason", &self.reason)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Terminal receipt for the pre-logical-binding allocation failure path.
pub(in crate::key_agent_service) struct WindowsUnboundRetired<'provider> {
    _pair: WindowsPairRetired,
    _authority: RuntimeRunStateAuthority<'provider>,
}

impl fmt::Debug for WindowsUnboundRetired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsUnboundRetired")
    }
}

/// Irreversible OS retirement failure before a logical writer binding existed.
/// The runtime authentication authority remains sealed in this terminal value.
#[must_use = "an unbound retirement failure retains terminal runtime authority"]
pub(in crate::key_agent_service) struct WindowsUnboundRetirementFailure<'provider> {
    cause: ServiceRunStateError,
    _authority: RuntimeRunStateAuthority<'provider>,
}

impl WindowsUnboundRetirementFailure<'_> {
    pub(in crate::key_agent_service) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }
}

impl fmt::Debug for WindowsUnboundRetirementFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsUnboundRetirementFailure")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for WindowsUnboundRetirementFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unbound Windows writer retirement failed: {}",
            self.cause
        )
    }
}

impl std::error::Error for WindowsUnboundRetirementFailure<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Writer-first composite. No pair bytes have been observed yet.
#[must_use = "the acquired Windows runtime writer must authenticate its fresh pair"]
pub(super) struct WindowsRuntimeWriterAcquired<'provider> {
    logical: RuntimeWriterAcquired<'provider>,
    pair: WindowsPairWriter,
}

impl<'provider> WindowsRuntimeWriterAcquired<'provider> {
    /// Seals an already-held OS writer and its move-only runtime authority.
    #[allow(clippy::large_types_passed_by_value)]
    #[allow(clippy::result_large_err)] // Failure retains the complete OS writer inline.
    pub(super) fn from_held_writer(
        writer: HeldServiceRunStateWriter,
        authority: RuntimeRunStateAuthority<'provider>,
    ) -> Result<Self, WindowsRuntimeBindingFailure<'provider>> {
        let pair = WindowsPairWriter::from_held_writer(writer);
        let epoch = match allocate_windows_backend_binding() {
            Ok(epoch) => epoch,
            Err(reason) => {
                return Err(WindowsRuntimeBindingFailure {
                    reason,
                    pair,
                    authority,
                });
            }
        };
        Ok(Self {
            logical: RuntimeWriterAcquired::from_exclusive_acquisition(
                authority,
                epoch,
                BackendBinding(epoch),
            ),
            pair,
        })
    }

    /// Freshly observes and authenticates exactly one Clean pair.
    #[allow(clippy::result_large_err)] // Failure retains both move-only authorities inline.
    pub(super) fn authenticate(
        self,
    ) -> Result<WindowsBootEvidence<'provider>, WindowsTerminalFailure<'provider>> {
        let Self { logical, pair } = self;
        let pair = match pair.observe() {
            Ok(pair) => pair,
            Err(pair) => {
                let cause = pair.cause();
                return Err(WindowsTerminalFailure::new(
                    backend_reason(cause),
                    Some(cause),
                    logical.into_writer_exit(),
                    WindowsTerminalPair::Known(pair),
                ));
            }
        };
        match logical.authenticate_observation(pair.observation()) {
            Ok(logical) => Ok(WindowsBootEvidence { logical, pair }),
            Err(failure) => Err(WindowsTerminalFailure::from_durable(
                failure,
                WindowsTerminalPair::Observed(pair),
            )),
        }
    }

    /// Consumes the pre-authentication authority into reason-neutral checked
    /// retirement without dropping either half of the composite writer.
    pub(super) fn into_retirement(self) -> WindowsRetirementPending<'provider> {
        let Self { logical, pair } = self;
        WindowsRetirementPending::new(
            logical.into_writer_exit(),
            WindowsTerminalPair::Writer(pair),
        )
    }

    /// Compatibility wrapper that attaches a lifecycle cause to the shared
    /// reason-neutral checked-retirement seam.
    pub(super) fn into_terminal(
        self,
        reason: RecoveryRequired,
    ) -> WindowsTerminalFailure<'provider> {
        WindowsTerminalFailure::from_retirement(
            WindowsTerminalCause::new(reason, None),
            self.into_retirement(),
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
pub(in crate::key_agent_service) struct WindowsBootEvidence<'provider> {
    logical: BootEvidence<'provider>,
    pair: WindowsObservedPair,
}

impl<'provider> WindowsBootEvidence<'provider> {
    pub(in crate::key_agent_service) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }

    #[allow(clippy::result_large_err)] // Failure retains both move-only authorities inline.
    pub(in crate::key_agent_service) fn prepare_active(
        self,
    ) -> Result<WindowsPreparedActiveTransition<'provider>, WindowsTerminalFailure<'provider>> {
        let Self { logical, pair } = self;
        let logical = match logical.prepare_active() {
            Ok(logical) => logical,
            Err(failure) => {
                return Err(WindowsTerminalFailure::from_durable(
                    failure,
                    WindowsTerminalPair::Observed(pair),
                ));
            }
        };
        let expected = logical.prior.bytes;
        let candidate = logical.successor.bytes;
        match pair.prepare_commit(ExpectedWindowsPair::exact(expected), candidate) {
            Ok(pair) => Ok(WindowsPreparedActiveTransition { logical, pair }),
            Err(pair) => Err(WindowsTerminalFailure::from_durable(
                logical.abort(RecoveryRequired::CompareAndSwapConflict),
                WindowsTerminalPair::ExpectationMismatch(pair),
            )),
        }
    }

    /// Consumes authenticated startup into reason-neutral checked retirement.
    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsRetirementPending<'provider> {
        let Self { logical, pair } = self;
        WindowsRetirementPending::new(
            logical.into_writer_exit(),
            WindowsTerminalPair::Observed(pair),
        )
    }

    /// Compatibility wrapper that attaches a lifecycle cause to retirement.
    pub(super) fn into_terminal(
        self,
        reason: RecoveryRequired,
    ) -> WindowsTerminalFailure<'provider> {
        WindowsTerminalFailure::from_retirement(
            WindowsTerminalCause::new(reason, None),
            self.into_retirement(),
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
pub(in crate::key_agent_service) struct WindowsPreparedActiveTransition<'provider> {
    logical: PreparedActiveTransition<'provider>,
    pair: WindowsPreparedPairCommit,
}

impl<'provider> WindowsPreparedActiveTransition<'provider> {
    pub(in crate::key_agent_service) fn commit_and_reread(
        self,
    ) -> WindowsActiveCommitOutcome<'provider> {
        let Self { logical, pair } = self;
        if let Err(reason) = logical.operation.begin_commit() {
            return WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Prepared(pair),
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
                ))
            }
            WindowsPairCommitOutcome::Ambiguous(pair) => {
                WindowsActiveCommitOutcome::ReloadRequired(WindowsActiveReloadRequired {
                    logical: logical.commit_ambiguous(),
                    pair,
                })
            }
            WindowsPairCommitOutcome::Committed(pair) => complete_active_commit(logical, pair),
        }
    }

    /// Consumes the unattempted Active transition into checked retirement.
    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsRetirementPending<'provider> {
        let Self { logical, pair } = self;
        WindowsRetirementPending::new(
            logical.into_writer_exit(),
            WindowsTerminalPair::Prepared(pair),
        )
    }

    /// Compatibility wrapper that attaches a lifecycle cause to retirement.
    pub(super) fn into_terminal(
        self,
        reason: RecoveryRequired,
    ) -> WindowsTerminalFailure<'provider> {
        WindowsTerminalFailure::from_retirement(
            WindowsTerminalCause::new(reason, None),
            self.into_retirement(),
        )
    }
}

fn complete_active_commit(
    logical: PreparedActiveTransition<'_>,
    pair: WindowsCommittedPair,
) -> WindowsActiveCommitOutcome<'_> {
    let committed_observation = pair.candidate().observation();
    if let Err(reason) = logical.operation.record_commit_receipt() {
        return WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Committed(pair),
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
        }),
        Err(failure) => WindowsActiveCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            failure,
            WindowsTerminalPair::Reread(pair),
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
pub(in crate::key_agent_service) enum WindowsActiveCommitOutcome<'provider> {
    Active(WindowsActiveRunLease<'provider>),
    ReloadRequired(WindowsActiveReloadRequired<'provider>),
    Terminal(WindowsTerminalFailure<'provider>),
}

/// Runtime authority holding both the authenticated Active state and OS pair.
#[must_use = "the Windows Active run must prepare Clean or retire terminally"]
pub(in crate::key_agent_service) struct WindowsActiveRunLease<'provider> {
    logical: ActiveRunLease<'provider>,
    pair: WindowsObservedPair,
}

impl<'provider> WindowsActiveRunLease<'provider> {
    pub(in crate::key_agent_service) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }

    /// Commits and independently rereads the exact successor Clean pair while
    /// retaining the same logical lease and OS writer.
    pub(in crate::key_agent_service) fn commit_clean(self) -> WindowsCleanCommitOutcome<'provider> {
        let Self { logical, pair } = self;
        let logical = match logical.prepare_clean() {
            Ok(logical) => logical,
            Err(failure) => {
                return WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    failure,
                    WindowsTerminalPair::Observed(pair),
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
                ));
            }
        };
        if let Err(reason) = logical.operation.begin_commit() {
            return WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Prepared(pair),
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
                ))
            }
            WindowsPairCommitOutcome::Ambiguous(pair) => {
                WindowsCleanCommitOutcome::ReloadRequired(WindowsCleanReloadRequired {
                    logical: logical.commit_ambiguous(),
                    pair,
                })
            }
            WindowsPairCommitOutcome::Committed(pair) => complete_clean_commit(logical, pair),
        }
    }

    /// Consumes Active runtime authority into reason-neutral retirement.
    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsRetirementPending<'provider> {
        let Self { logical, pair } = self;
        WindowsRetirementPending::new(
            logical.into_writer_exit(),
            WindowsTerminalPair::Observed(pair),
        )
    }

    /// Compatibility wrapper that attaches a lifecycle cause to retirement.
    pub(super) fn into_terminal(
        self,
        reason: RecoveryRequired,
    ) -> WindowsTerminalFailure<'provider> {
        WindowsTerminalFailure::from_retirement(
            WindowsTerminalCause::new(reason, None),
            self.into_retirement(),
        )
    }
}

fn complete_clean_commit(
    logical: PreparedCleanTransition<'_>,
    pair: WindowsCommittedPair,
) -> WindowsCleanCommitOutcome<'_> {
    let committed_observation = pair.candidate().observation();
    if let Err(reason) = logical.operation.record_commit_receipt() {
        return WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            logical.abort(reason),
            WindowsTerminalPair::Committed(pair),
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
        ));
    }
    let pair = match pair.reread() {
        Ok(pair) => pair,
        Err(pair) => {
            return WindowsCleanCommitOutcome::ReloadRequired(WindowsCleanReloadRequired {
                logical: logical.commit_ambiguous(),
                pair,
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
        }),
        Err(failure) => WindowsCleanCommitOutcome::Terminal(WindowsTerminalFailure::from_durable(
            failure,
            WindowsTerminalPair::Reread(pair),
        )),
    }
}

/// Complete consuming result of the Clean commit plus independent reread.
#[must_use = "the Windows Clean outcome retains both authorities"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(in crate::key_agent_service) enum WindowsCleanCommitOutcome<'provider> {
    Clean(WindowsCleanWithWriter<'provider>),
    ReloadRequired(WindowsCleanReloadRequired<'provider>),
    Terminal(WindowsTerminalFailure<'provider>),
}

/// Exact authenticated Clean state retaining the final pair-bound writer.
#[must_use = "the Windows Clean writer must stop or retire terminally"]
pub(in crate::key_agent_service) struct WindowsCleanWithWriter<'provider> {
    logical: CleanCommittedWithWriter<'provider>,
    pair: WindowsObservedPair,
}

impl<'provider> WindowsCleanWithWriter<'provider> {
    pub(in crate::key_agent_service) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }

    /// Performs the sole pair-bound final release. Stopped evidence is minted
    /// only after the OS receipt exactly names the authenticated Clean pair.
    pub(in crate::key_agent_service) fn stop(self) -> WindowsStopOutcome<'provider> {
        let Self { logical, pair } = self;
        if pair.observation() != logical.durable.bytes.observation() {
            return WindowsStopOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(RecoveryRequired::CompareAndSwapConflict),
                WindowsTerminalPair::Observed(pair),
            ));
        }
        let logical = logical.prepare_writer_release();
        if let Err(reason) = logical.operation.begin_release() {
            return WindowsStopOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Observed(pair),
            ));
        }
        match pair.release_verified() {
            Ok(pair) => complete_final_release(logical, pair),
            Err(WindowsPairReleaseFailure::WriterRetained(pair)) => {
                let cause = pair.cause();
                WindowsStopOutcome::Terminal(WindowsTerminalFailure::new(
                    RecoveryRequired::WriterReleaseAmbiguous,
                    Some(cause),
                    logical
                        .abort(RecoveryRequired::WriterReleaseAmbiguous)
                        .into_writer_exit(),
                    WindowsTerminalPair::ReleaseWithWriter(pair),
                ))
            }
            Err(WindowsPairReleaseFailure::WriterReleasedNoReceipt(pair)) => {
                let cause = pair.cause();
                WindowsStopOutcome::ReleasedNoReceipt(WindowsReleasedNoReceipt {
                    reason: RecoveryRequired::WriterReleaseAmbiguous,
                    cause,
                    _logical: logical.into_writer_exit(),
                    _pair: pair,
                })
            }
        }
    }

    /// Exercises the irreversible post-release branch without exposing the
    /// logical writer, OS pair, path, handle, identity, or provider authority.
    #[cfg(test)]
    pub(in crate::key_agent_service) fn stop_with_post_release_fault_for_test(
        self,
    ) -> WindowsStopOutcome<'provider> {
        let _fault = PostReleaseReceiptFaultGuard::arm();
        self.stop()
    }

    /// Consumes the Clean writer into reason-neutral checked retirement.
    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsRetirementPending<'provider> {
        let Self { logical, pair } = self;
        WindowsRetirementPending::new(
            logical.into_writer_exit(),
            WindowsTerminalPair::Observed(pair),
        )
    }

    /// Compatibility wrapper that attaches a lifecycle cause to retirement.
    pub(super) fn into_terminal(
        self,
        reason: RecoveryRequired,
    ) -> WindowsTerminalFailure<'provider> {
        WindowsTerminalFailure::from_retirement(
            WindowsTerminalCause::new(reason, None),
            self.into_retirement(),
        )
    }
}

fn complete_final_release(
    logical: PendingFinalWriterRelease<'_>,
    pair: WindowsPairReleased,
) -> WindowsStopOutcome<'_> {
    if pair.pair() != logical.durable.bytes {
        return WindowsStopOutcome::PostReleaseTerminal(WindowsPostReleaseTerminal {
            reason: RecoveryRequired::WriterReleaseAmbiguous,
            _logical: logical.into_writer_exit(),
            _pair: pair,
        });
    }
    #[cfg(test)]
    if take_post_release_receipt_fault_for_test() {
        let _ = logical.operation.record_release_receipt();
    }
    if let Err(reason) = logical.operation.record_release_receipt() {
        return WindowsStopOutcome::PostReleaseTerminal(WindowsPostReleaseTerminal {
            reason,
            _logical: logical.into_writer_exit(),
            _pair: pair,
        });
    }
    let receipt = WriterLeaseReleaseReceipt {
        installation: logical.lease.installation(),
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
        }),
    }
}

/// Complete final release result. Only `Stopped` carries normal authority.
#[must_use = "the Windows stop outcome must be handled explicitly"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(in crate::key_agent_service) enum WindowsStopOutcome<'provider> {
    Stopped(WindowsStoppedRunEvidence<'provider>),
    Terminal(WindowsTerminalFailure<'provider>),
    ReleasedNoReceipt(WindowsReleasedNoReceipt<'provider>),
    PostReleaseTerminal(WindowsPostReleaseTerminal<'provider>),
}

/// Exact authenticated Clean evidence after pair-bound writer release.
#[must_use = "Windows stopped evidence is the sole normal terminal receipt"]
pub(in crate::key_agent_service) struct WindowsStoppedRunEvidence<'provider> {
    logical: StoppedRunEvidence<'provider>,
    _pair: WindowsPairReleased,
}

impl WindowsStoppedRunEvidence<'_> {
    pub(in crate::key_agent_service) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }
}

impl fmt::Debug for WindowsStoppedRunEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsStoppedRunEvidence([REDACTED])")
    }
}

/// Irreversible OS close ambiguity after the logical release attempt began.
/// No retry, retirement, recovery-exit, or stopped conversion is exposed.
#[must_use = "a no-receipt release is an irreversible terminal state"]
pub(in crate::key_agent_service) struct WindowsReleasedNoReceipt<'provider> {
    reason: RecoveryRequired,
    cause: ServiceRunStateError,
    _logical: WriterExitPending<'provider>,
    _pair: WindowsPairReleaseAfterWriter,
}

impl WindowsReleasedNoReceipt<'_> {
    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    pub(in crate::key_agent_service) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }
}

impl fmt::Debug for WindowsReleasedNoReceipt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
pub(in crate::key_agent_service) struct WindowsPostReleaseTerminal<'provider> {
    reason: RecoveryRequired,
    _logical: WriterExitPending<'provider>,
    _pair: WindowsPairReleased,
}

impl WindowsPostReleaseTerminal<'_> {
    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }
}

impl fmt::Debug for WindowsPostReleaseTerminal<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
pub(in crate::key_agent_service) struct WindowsCleanReloadRequired<'provider> {
    logical: CleanReloadRequired<'provider>,
    pair: WindowsPairReloadRequired,
}

impl<'provider> WindowsCleanReloadRequired<'provider> {
    pub(in crate::key_agent_service) fn reload(self) -> WindowsCleanReloadOutcome<'provider> {
        let Self { logical, pair } = self;
        let pair = match pair.reload() {
            Ok(pair) => pair,
            Err(pair) => {
                let cause = pair.cause();
                return WindowsCleanReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    logical.abort(backend_reason(cause)),
                    WindowsTerminalPair::ReloadFailure(pair),
                ));
            }
        };
        if let Err(reason) = logical.operation.record_reload_receipt() {
            return WindowsCleanReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Reloaded(pair),
            ));
        }
        let receipt = CleanReloadReceipt {
            observed: pair.observation(),
            writer: WriterObservation::Held {
                installation: logical.lease.installation(),
                epoch: logical.lease.epoch,
            },
            binding: logical.lease.binding,
        };
        match logical.complete_reload(receipt) {
            Ok(logical) => WindowsCleanReloadOutcome::Clean(WindowsCleanWithWriter {
                logical,
                pair: pair.continue_observed(),
            }),
            Err(failure) => WindowsCleanReloadOutcome::Terminal(
                WindowsTerminalFailure::from_durable(failure, WindowsTerminalPair::Reloaded(pair)),
            ),
        }
    }

    /// Consumes unresolved Clean ambiguity into reason-neutral retirement.
    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsRetirementPending<'provider> {
        let Self { logical, pair } = self;
        WindowsRetirementPending::new(
            logical.into_writer_exit(),
            WindowsTerminalPair::Ambiguous(pair),
        )
    }

    /// Compatibility wrapper that attaches a lifecycle cause to retirement.
    pub(super) fn into_terminal(
        self,
        reason: RecoveryRequired,
    ) -> WindowsTerminalFailure<'provider> {
        WindowsTerminalFailure::from_retirement(
            WindowsTerminalCause::new(reason, None),
            self.into_retirement(),
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
pub(in crate::key_agent_service) enum WindowsCleanReloadOutcome<'provider> {
    Clean(WindowsCleanWithWriter<'provider>),
    Terminal(WindowsTerminalFailure<'provider>),
}

impl fmt::Debug for WindowsActiveRunLease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsActiveRunLease([REDACTED])")
    }
}

/// Ambiguous Active commit retaining exact logical reload and OS ambiguity.
#[must_use = "the Windows Active ambiguity must reload or retire"]
pub(in crate::key_agent_service) struct WindowsActiveReloadRequired<'provider> {
    logical: ActiveReloadRequired<'provider>,
    pair: WindowsPairReloadRequired,
}

impl<'provider> WindowsActiveReloadRequired<'provider> {
    pub(in crate::key_agent_service) fn reload(self) -> WindowsActiveReloadOutcome<'provider> {
        let Self { logical, pair } = self;
        let pair = match pair.reload() {
            Ok(pair) => pair,
            Err(pair) => {
                let cause = pair.cause();
                return WindowsActiveReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                    logical.abort(backend_reason(cause)),
                    WindowsTerminalPair::ReloadFailure(pair),
                ));
            }
        };
        if let Err(reason) = logical.operation.record_reload_receipt() {
            return WindowsActiveReloadOutcome::Terminal(WindowsTerminalFailure::from_durable(
                logical.abort(reason),
                WindowsTerminalPair::Reloaded(pair),
            ));
        }
        let receipt = ActiveReloadReceipt {
            observed: pair.observation(),
            writer: WriterObservation::Held {
                installation: logical.lease.installation(),
                epoch: logical.lease.epoch,
            },
            binding: logical.lease.binding,
        };
        match logical.complete_reload(receipt) {
            Ok(ReloadedActiveRunState::Boot(logical)) => {
                WindowsActiveReloadOutcome::Boot(WindowsBootEvidence {
                    logical,
                    pair: pair.continue_observed(),
                })
            }
            Ok(ReloadedActiveRunState::Active(logical)) => {
                WindowsActiveReloadOutcome::Active(WindowsActiveRunLease {
                    logical,
                    pair: pair.continue_observed(),
                })
            }
            Err(failure) => WindowsActiveReloadOutcome::Terminal(
                WindowsTerminalFailure::from_durable(failure, WindowsTerminalPair::Reloaded(pair)),
            ),
        }
    }

    /// Consumes unresolved Active ambiguity into reason-neutral retirement.
    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsRetirementPending<'provider> {
        let Self { logical, pair } = self;
        WindowsRetirementPending::new(
            logical.into_writer_exit(),
            WindowsTerminalPair::Ambiguous(pair),
        )
    }

    /// Compatibility wrapper that attaches a lifecycle cause to retirement.
    pub(super) fn into_terminal(
        self,
        reason: RecoveryRequired,
    ) -> WindowsTerminalFailure<'provider> {
        WindowsTerminalFailure::from_retirement(
            WindowsTerminalCause::new(reason, None),
            self.into_retirement(),
        )
    }
}

/// Complete exact resolution of one ambiguous Active commit.
#[must_use = "the Active reload outcome retains both authorities"]
#[allow(clippy::large_enum_variant)]
pub(in crate::key_agent_service) enum WindowsActiveReloadOutcome<'provider> {
    Boot(WindowsBootEvidence<'provider>),
    Active(WindowsActiveRunLease<'provider>),
    Terminal(WindowsTerminalFailure<'provider>),
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

/// Durable terminal cause kept separate from reason-neutral retirement authority.
#[must_use = "a terminal cause must remain attached to its retirement outcome"]
pub(in crate::key_agent_service) struct WindowsTerminalCause {
    recovery: RecoveryRequired,
    platform: Option<ServiceRunStateError>,
}

impl WindowsTerminalCause {
    const fn new(recovery: RecoveryRequired, platform: Option<ServiceRunStateError>) -> Self {
        Self { recovery, platform }
    }

    pub(in crate::key_agent_service) const fn recovery(&self) -> RecoveryRequired {
        self.recovery
    }

    pub(in crate::key_agent_service) const fn platform(&self) -> Option<ServiceRunStateError> {
        self.platform
    }

    const fn into_parts(self) -> (RecoveryRequired, Option<ServiceRunStateError>) {
        (self.recovery, self.platform)
    }
}

impl fmt::Debug for WindowsTerminalCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsTerminalCause")
            .field("recovery", &self.recovery)
            .field("platform", &self.platform)
            .finish()
    }
}

/// Reason-neutral ownership of the logical writer exit and exact OS pair.
/// No raw handle, path, pair authority, or lifecycle policy can be recovered.
#[must_use = "the Windows retirement authority must be checked exactly once"]
pub(in crate::key_agent_service) struct WindowsRetirementPending<'provider> {
    logical: WriterExitPending<'provider>,
    pair: WindowsTerminalPair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsCheckedRetirementStage {
    BeginRelease,
    PairRetire,
    RecordReceipt,
    LogicalComplete,
}

impl<'provider> WindowsRetirementPending<'provider> {
    const fn new(logical: WriterExitPending<'provider>, pair: WindowsTerminalPair) -> Self {
        Self { logical, pair }
    }

    /// Releases the logical operation, retires the exact OS pair, records the
    /// logical receipt, then completes the logical exit. Every failure is
    /// terminal and consumes the pair authority without minting a receipt.
    #[allow(clippy::result_large_err)] // Failure retains the logical obligation inline.
    pub(in crate::key_agent_service) fn retire_checked(
        self,
    ) -> Result<WindowsCheckedRetired<'provider>, WindowsCheckedRetirementFailure<'provider>> {
        let Self { logical, pair } = self;
        if logical.operation.begin_release().is_err() {
            let cause = pair.retire().err().unwrap_or(ServiceRunStateError::Release);
            return Err(WindowsCheckedRetirementFailure::new(
                WindowsCheckedRetirementStage::BeginRelease,
                cause,
                logical,
            ));
        }
        let pair = match pair.retire() {
            Ok(pair) => pair,
            Err(cause) => {
                return Err(WindowsCheckedRetirementFailure::new(
                    WindowsCheckedRetirementStage::PairRetire,
                    cause,
                    logical,
                ));
            }
        };
        if logical.operation.record_release_receipt().is_err() {
            return Err(WindowsCheckedRetirementFailure::new(
                WindowsCheckedRetirementStage::RecordReceipt,
                ServiceRunStateError::Release,
                logical,
            ));
        }
        let receipt = WriterExitReceipt {
            installation: logical.lease.installation(),
            epoch: logical.lease.epoch,
            binding: logical.lease.binding,
        };
        match logical.complete(receipt) {
            Ok(logical) => Ok(WindowsCheckedRetired {
                _logical: logical,
                _pair: pair,
            }),
            Err(failure) => Err(WindowsCheckedRetirementFailure::new(
                WindowsCheckedRetirementStage::LogicalComplete,
                ServiceRunStateError::Release,
                failure.into_writer_exit(),
            )),
        }
    }
}

impl fmt::Debug for WindowsRetirementPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsRetirementPending([REDACTED])")
    }
}

/// Exact reason-neutral checked-retirement evidence. It cannot re-enter a
/// normal lifecycle and exposes neither logical nor operating-system authority.
#[must_use = "checked retirement evidence is terminal"]
pub(in crate::key_agent_service) struct WindowsCheckedRetired<'provider> {
    _logical: RecoveryExitEvidence<'provider>,
    _pair: WindowsPairRetired,
}

impl fmt::Debug for WindowsCheckedRetired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsCheckedRetired([REDACTED])")
    }
}

/// Irreversible reason-neutral retirement failure. Pair authority was consumed;
/// no retry, recovery-exit, checked-retired, or stopped conversion exists.
#[must_use = "a checked-retirement failure is irreversible"]
pub(in crate::key_agent_service) struct WindowsCheckedRetirementFailure<'provider> {
    stage: WindowsCheckedRetirementStage,
    cause: ServiceRunStateError,
    _logical: WriterExitPending<'provider>,
}

impl<'provider> WindowsCheckedRetirementFailure<'provider> {
    const fn new(
        stage: WindowsCheckedRetirementStage,
        cause: ServiceRunStateError,
        logical: WriterExitPending<'provider>,
    ) -> Self {
        Self {
            stage,
            cause,
            _logical: logical,
        }
    }

    pub(in crate::key_agent_service) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }

    const fn legacy_reason(&self, terminal: RecoveryRequired) -> RecoveryRequired {
        match self.stage {
            WindowsCheckedRetirementStage::LogicalComplete => {
                RecoveryRequired::OperationPhaseMismatch
            }
            WindowsCheckedRetirementStage::BeginRelease
            | WindowsCheckedRetirementStage::PairRetire
            | WindowsCheckedRetirementStage::RecordReceipt => terminal,
        }
    }
}

impl fmt::Debug for WindowsCheckedRetirementFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsCheckedRetirementFailure")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Terminal composite retaining a cause and reason-neutral retirement seam.
#[must_use = "the Windows terminal writer must be explicitly retired"]
pub(in crate::key_agent_service) struct WindowsTerminalFailure<'provider> {
    cause: WindowsTerminalCause,
    retirement: WindowsRetirementPending<'provider>,
}

impl<'provider> WindowsTerminalFailure<'provider> {
    fn new(
        recovery: RecoveryRequired,
        platform: Option<ServiceRunStateError>,
        logical: WriterExitPending<'provider>,
        pair: WindowsTerminalPair,
    ) -> Self {
        Self::from_retirement(
            WindowsTerminalCause::new(recovery, platform),
            WindowsRetirementPending::new(logical, pair),
        )
    }

    const fn from_retirement(
        cause: WindowsTerminalCause,
        retirement: WindowsRetirementPending<'provider>,
    ) -> Self {
        Self { cause, retirement }
    }

    fn from_durable(
        failure: DurableFailureWithWriter<'provider>,
        pair: WindowsTerminalPair,
    ) -> Self {
        let reason = failure.reason();
        Self::new(reason, None, failure.into_writer_exit(), pair)
    }

    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.cause.recovery()
    }

    pub(super) const fn platform_cause(&self) -> Option<ServiceRunStateError> {
        self.cause.platform()
    }

    /// Separates the legacy durable/platform cause from the reason-neutral,
    /// move-only checked-retirement authority.
    pub(in crate::key_agent_service) fn into_retirement_parts(
        self,
    ) -> (WindowsTerminalCause, WindowsRetirementPending<'provider>) {
        (self.cause, self.retirement)
    }

    pub(super) fn retire(
        self,
    ) -> Result<WindowsRecoveryExit<'provider>, WindowsRetirementFailure<'provider>> {
        let (terminal, retirement) = self.into_retirement_parts();
        match retirement.retire_checked() {
            Ok(retired) => Ok(WindowsRecoveryExit::from_checked(terminal, retired)),
            Err(failure) => Err(WindowsRetirementFailure::from_checked(terminal, failure)),
        }
    }
}

impl fmt::Debug for WindowsTerminalFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsTerminalFailure")
            .field("reason", &self.reason())
            .field("platform_cause", &self.platform_cause())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Exact terminal retirement evidence; it can never re-enter normal runtime.
pub(super) struct WindowsRecoveryExit<'provider> {
    reason: RecoveryRequired,
    platform_cause: Option<ServiceRunStateError>,
    _logical: RecoveryExitEvidence<'provider>,
    _pair: WindowsPairRetired,
}

impl<'provider> WindowsRecoveryExit<'provider> {
    fn from_checked(
        cause: WindowsTerminalCause,
        retired: WindowsCheckedRetired<'provider>,
    ) -> Self {
        let (reason, platform_cause) = cause.into_parts();
        let WindowsCheckedRetired {
            _logical: logical,
            _pair: pair,
        } = retired;
        WindowsRecoveryExit {
            reason,
            platform_cause,
            _logical: logical,
            _pair: pair,
        }
    }

    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }
    pub(super) const fn platform_cause(&self) -> Option<ServiceRunStateError> {
        self.platform_cause
    }
}

impl fmt::Debug for WindowsRecoveryExit<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsRecoveryExit")
            .field("reason", &self.reason)
            .field("platform_cause", &self.platform_cause)
            .finish()
    }
}

/// Irrecoverable checked-retirement failure. No normal receipt can follow.
pub(super) struct WindowsRetirementFailure<'provider> {
    reason: RecoveryRequired,
    platform_cause: Option<ServiceRunStateError>,
    cause: ServiceRunStateError,
    _logical: WriterExitPending<'provider>,
}

impl<'provider> WindowsRetirementFailure<'provider> {
    fn from_checked(
        terminal: WindowsTerminalCause,
        failure: WindowsCheckedRetirementFailure<'provider>,
    ) -> Self {
        let reason = failure.legacy_reason(terminal.recovery());
        let (_, platform_cause) = terminal.into_parts();
        let WindowsCheckedRetirementFailure {
            cause,
            _logical: logical,
            ..
        } = failure;
        Self {
            reason,
            platform_cause,
            cause,
            _logical: logical,
        }
    }
}

impl fmt::Debug for WindowsRetirementFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsRetirementFailure")
            .field("reason", &self.reason)
            .field("platform_cause", &self.platform_cause)
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_agent_service::run_state_root::{
        ExactFixedRunStatePair, RuntimePairFault, RuntimePairFixture,
        RuntimePairProcessDeathCutpoint,
    };

    use super::super::{Commitment, RunMarkerState, build_snapshot};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;

    fn test_installation(byte: u8) -> Result<InstallationIdentity, RecoveryRequired> {
        InstallationIdentity::from_fixed_bytes([byte; 32])
    }

    fn test_provider(
        installation: InstallationIdentity,
        byte: u8,
    ) -> Result<RunStateAuthenticationProvider, RecoveryRequired> {
        RunStateAuthenticationProvider::from_fixture_bytes(installation, [byte; 32])
    }

    fn snapshot(
        state: RunMarkerState,
        generation: u64,
        installation: InstallationIdentity,
        provider: &RunStateAuthenticationProvider,
    ) -> Result<super::super::CanonicalSnapshot, RecoveryRequired> {
        if installation != provider.installation() {
            return Err(RecoveryRequired::InstallationIdentityMismatch);
        }
        build_snapshot(
            state,
            NonZeroU64::new(generation).ok_or(RecoveryRequired::GenerationExhausted)?,
            Commitment::ZERO,
            provider,
        )
        .map(|durable| durable.bytes)
    }

    fn install_pair(
        fixture: &RuntimePairFixture,
        candidate: &super::super::CanonicalSnapshot,
    ) -> TestResult {
        install_pair_for_test(fixture, candidate)
    }

    fn start<'provider>(
        fixture: &RuntimePairFixture,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> TestResultWith<WindowsBootEvidence<'provider>> {
        match start_windows_runtime(fixture.acquire_writer()?, provider.runtime_authority()) {
            Ok(boot) => Ok(boot),
            Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                let reason = failure.reason();
                let _retired = failure.retire().map_err(|failure| failure.cause())?;
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

    fn retire_reason_neutral(pending: WindowsRetirementPending<'_>) -> TestResult {
        pending
            .retire_checked()
            .map(|_retired| ())
            .map_err(|failure| {
                std::io::Error::other(format!(
                    "reason-neutral composite retirement failed: {failure:?}"
                ))
                .into()
            })
    }

    fn prepare_active<'provider>(
        fixture: &RuntimePairFixture,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> TestResultWith<WindowsPreparedActiveTransition<'provider>> {
        let boot = start(fixture, provider)?;
        match boot.prepare_active() {
            Ok(prepared) => Ok(prepared),
            Err(failure) => {
                let reason = failure.reason();
                retire_checked(failure)?;
                Err(reason.into())
            }
        }
    }

    fn exact_active<'provider>(
        fixture: &RuntimePairFixture,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> TestResultWith<WindowsActiveRunLease<'provider>> {
        match prepare_active(fixture, provider)?.commit_and_reread() {
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

    fn exact_clean<'provider>(
        fixture: &RuntimePairFixture,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> TestResultWith<WindowsCleanWithWriter<'provider>> {
        match exact_active(fixture, provider)?.commit_clean() {
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
        let mut provider = test_provider(installation, 0x42)?;
        let initial = snapshot(RunMarkerState::Clean, 1, installation, &provider)?;
        install_pair(&fixture, &initial)?;

        let boot = start(&fixture, &mut provider)?;
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
    fn kernel_process_death_restart_boots_only_prior_clean_and_rejects_partial_or_active()
    -> TestResult {
        #[derive(Clone, Copy)]
        enum ExpectedRestart {
            PriorClean,
            Partial,
            Active,
        }

        for (cutpoint, expected, byte) in [
            (
                RuntimePairProcessDeathCutpoint::BeforeMarkerRename,
                ExpectedRestart::PriorClean,
                0x43,
            ),
            (
                RuntimePairProcessDeathCutpoint::AfterMarkerRename,
                ExpectedRestart::Partial,
                0x45,
            ),
            (
                RuntimePairProcessDeathCutpoint::AfterCheckpointRename,
                ExpectedRestart::Active,
                0x47,
            ),
        ] {
            let fixture = RuntimePairFixture::new()?;
            let installation = test_installation(byte)?;
            let mut provider = test_provider(installation, byte.wrapping_add(1))?;
            let initial = snapshot(RunMarkerState::Clean, 1, installation, &provider)?;
            install_pair(&fixture, &initial)?;

            let prepared = prepare_active(&fixture, &mut provider)?;
            let prior_generation = prepared.logical.prior.marker.generation.get();
            let candidate_generation = prepared.logical.successor.marker.generation.get();
            let prior = ExactFixedRunStatePair::new(
                prepared.logical.prior.bytes.marker,
                prepared.logical.prior.bytes.checkpoint,
            );
            let candidate = ExactFixedRunStatePair::new(
                prepared.logical.successor.bytes.marker,
                prepared.logical.successor.bytes.checkpoint,
            );
            let partial = ExactFixedRunStatePair::new(*candidate.marker(), *prior.checkpoint());
            retire_reason_neutral(prepared.into_retirement())?;
            assert_eq!(prior_generation, 1);
            assert_eq!(candidate_generation, 2);

            let writer = fixture.force_process_death_during_pair_commit(cutpoint, candidate)?;
            let startup = start_windows_runtime(writer, provider.runtime_authority());
            match (expected, startup) {
                (ExpectedRestart::PriorClean, Ok(boot)) => {
                    let generation = boot.generation().get();
                    retire_reason_neutral(boot.into_retirement())?;
                    assert_eq!(generation, 1);
                }
                (ExpectedRestart::Partial, Err(WindowsRuntimeStartFailure::Terminal(failure))) => {
                    let reason = failure.reason();
                    let platform_cause = failure.platform_cause();
                    retire_checked(failure)?;
                    assert_eq!(reason, RecoveryRequired::HighWaterDrift);
                    assert_eq!(platform_cause, None);
                }
                (ExpectedRestart::Active, Err(WindowsRuntimeStartFailure::Terminal(failure))) => {
                    let reason = failure.reason();
                    let platform_cause = failure.platform_cause();
                    retire_checked(failure)?;
                    assert_eq!(reason, RecoveryRequired::PersistedNonCleanState);
                    assert_eq!(platform_cause, None);
                }
                (_, Ok(boot)) => {
                    retire_reason_neutral(boot.into_retirement())?;
                    return Err(std::io::Error::other(
                        "a non-Clean process-death restart minted Boot authority",
                    )
                    .into());
                }
                (_, Err(WindowsRuntimeStartFailure::Binding(failure))) => {
                    let reason = failure.reason();
                    let _retired = failure.retire().map_err(|failure| failure.cause())?;
                    return Err(std::io::Error::other(format!(
                        "process-death restart failed before authentication: {reason}"
                    ))
                    .into());
                }
                (_, Err(WindowsRuntimeStartFailure::Terminal(failure))) => {
                    let reason = failure.reason();
                    let platform_cause = failure.platform_cause();
                    retire_checked(failure)?;
                    return Err(std::io::Error::other(format!(
                        "process-death restart had an unexpected terminal classification: {reason}; platform={platform_cause:?}"
                    ))
                    .into());
                }
            }

            let expected_pair = match expected {
                ExpectedRestart::PriorClean => prior,
                ExpectedRestart::Partial => partial,
                ExpectedRestart::Active => candidate,
            };
            fixture.assert_exact_pair_and_no_temps_for_test(expected_pair)?;
            fixture.cleanup_checked()?;
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One matrix keeps all three physical cutpoints auditable.
    fn kernel_process_death_restart_boots_only_full_clean_and_rejects_prior_active_or_partial()
    -> TestResult {
        #[derive(Clone, Copy)]
        enum ExpectedRestart {
            PriorActive,
            Partial,
            FullClean,
        }

        for (cutpoint, expected, byte) in [
            (
                RuntimePairProcessDeathCutpoint::BeforeMarkerRename,
                ExpectedRestart::PriorActive,
                0x49,
            ),
            (
                RuntimePairProcessDeathCutpoint::AfterMarkerRename,
                ExpectedRestart::Partial,
                0x4b,
            ),
            (
                RuntimePairProcessDeathCutpoint::AfterCheckpointRename,
                ExpectedRestart::FullClean,
                0x4d,
            ),
        ] {
            let fixture = RuntimePairFixture::new()?;
            let installation = test_installation(byte)?;
            let mut provider = test_provider(installation, byte.wrapping_add(1))?;
            let initial = snapshot(RunMarkerState::Clean, 1, installation, &provider)?;
            install_pair(&fixture, &initial)?;

            let active = exact_active(&fixture, &mut provider)?;
            let WindowsActiveRunLease { logical, pair } = active;
            let prepared = match logical.prepare_clean() {
                Ok(prepared) => prepared,
                Err(failure) => {
                    let failure = WindowsTerminalFailure::from_durable(
                        failure,
                        WindowsTerminalPair::Observed(pair),
                    );
                    let reason = failure.reason();
                    retire_checked(failure)?;
                    return Err(reason.into());
                }
            };
            let prior_generation = prepared.prior.marker.generation.get();
            let candidate_generation = prepared.successor.marker.generation.get();
            let prior_state = prepared.prior.marker.state;
            let candidate_state = prepared.successor.marker.state;
            let prior = ExactFixedRunStatePair::new(
                prepared.prior.bytes.marker,
                prepared.prior.bytes.checkpoint,
            );
            let candidate = ExactFixedRunStatePair::new(
                prepared.successor.bytes.marker,
                prepared.successor.bytes.checkpoint,
            );
            let partial = ExactFixedRunStatePair::new(*candidate.marker(), *prior.checkpoint());
            retire_reason_neutral(WindowsRetirementPending::new(
                prepared.into_writer_exit(),
                WindowsTerminalPair::Observed(pair),
            ))?;
            assert_eq!(prior_generation, 2);
            assert_eq!(candidate_generation, 3);
            assert_eq!(prior_state, RunMarkerState::Active);
            assert_eq!(candidate_state, RunMarkerState::Clean);

            let writer = fixture.force_process_death_during_pair_commit(cutpoint, candidate)?;
            let startup = start_windows_runtime(writer, provider.runtime_authority());
            match (expected, startup) {
                (
                    ExpectedRestart::PriorActive,
                    Err(WindowsRuntimeStartFailure::Terminal(failure)),
                ) => {
                    let reason = failure.reason();
                    let platform_cause = failure.platform_cause();
                    retire_checked(failure)?;
                    assert_eq!(reason, RecoveryRequired::PersistedNonCleanState);
                    assert_eq!(platform_cause, None);
                }
                (ExpectedRestart::Partial, Err(WindowsRuntimeStartFailure::Terminal(failure))) => {
                    let reason = failure.reason();
                    let platform_cause = failure.platform_cause();
                    retire_checked(failure)?;
                    assert_eq!(reason, RecoveryRequired::HighWaterDrift);
                    assert_eq!(platform_cause, None);
                }
                (ExpectedRestart::FullClean, Ok(boot)) => {
                    let generation = boot.generation().get();
                    retire_reason_neutral(boot.into_retirement())?;
                    assert_eq!(generation, 3);
                }
                (_, Ok(boot)) => {
                    retire_reason_neutral(boot.into_retirement())?;
                    return Err(std::io::Error::other(
                        "an Active or partial Clean process-death restart minted Boot authority",
                    )
                    .into());
                }
                (_, Err(WindowsRuntimeStartFailure::Binding(failure))) => {
                    let reason = failure.reason();
                    let _retired = failure.retire().map_err(|failure| failure.cause())?;
                    return Err(std::io::Error::other(format!(
                        "Clean process-death restart failed before authentication: {reason}"
                    ))
                    .into());
                }
                (_, Err(WindowsRuntimeStartFailure::Terminal(failure))) => {
                    let reason = failure.reason();
                    let platform_cause = failure.platform_cause();
                    retire_checked(failure)?;
                    return Err(std::io::Error::other(format!(
                        "Clean process-death restart had an unexpected terminal classification: {reason}; platform={platform_cause:?}"
                    ))
                    .into());
                }
            }

            let expected_pair = match expected {
                ExpectedRestart::PriorActive => prior,
                ExpectedRestart::Partial => partial,
                ExpectedRestart::FullClean => candidate,
            };
            fixture.assert_exact_pair_and_no_temps_for_test(expected_pair)?;
            fixture.cleanup_checked()?;
        }
        Ok(())
    }

    #[test]
    fn kernel_missing_pair_is_terminal_and_checked_retired() -> TestResult {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0x53)?;
        let mut provider = test_provider(installation, 0x64)?;
        let failure =
            match start_windows_runtime(fixture.acquire_writer()?, provider.runtime_authority()) {
                Err(WindowsRuntimeStartFailure::Terminal(failure)) => failure,
                Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                    let reason = failure.reason();
                    let _retired = failure.retire().map_err(|failure| failure.cause())?;
                    return Err(reason.into());
                }
                Ok(_boot) => {
                    return Err(std::io::Error::other("missing pair minted boot evidence").into());
                }
            };
        assert_eq!(failure.reason(), RecoveryRequired::MissingRunMarker);
        assert!(format!("{failure:?}").contains("[REDACTED]"));
        let (cause, pending) = failure.into_retirement_parts();
        assert_eq!(cause.recovery(), RecoveryRequired::MissingRunMarker);
        assert_eq!(cause.platform(), None);
        assert!(format!("{pending:?}").contains("[REDACTED]"));
        let retired = pending.retire_checked().map_err(|failure| {
            std::io::Error::other(format!("missing-pair retirement failed: {failure:?}"))
        })?;
        assert!(format!("{retired:?}").contains("[REDACTED]"));
        fixture.cleanup_checked()
    }

    #[test]
    fn kernel_wrong_provider_and_nonclean_pairs_never_boot() -> TestResult {
        let wrong_provider_fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0x75)?;
        let original_provider = test_provider(installation, 0x86)?;
        let mut wrong_provider = test_provider(installation, 0x97)?;
        install_pair(
            &wrong_provider_fixture,
            &snapshot(RunMarkerState::Clean, 1, installation, &original_provider)?,
        )?;
        let failure = match start_windows_runtime(
            wrong_provider_fixture.acquire_writer()?,
            wrong_provider.runtime_authority(),
        ) {
            Err(WindowsRuntimeStartFailure::Terminal(failure)) => failure,
            Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                let reason = failure.reason();
                let _retired = failure.retire().map_err(|failure| failure.cause())?;
                return Err(reason.into());
            }
            Ok(_boot) => return Err(std::io::Error::other("wrong provider booted").into()),
        };
        assert_eq!(failure.reason(), RecoveryRequired::AuthenticationFailed);
        let exit = failure.retire().map_err(|failure| {
            std::io::Error::other(format!("wrong-provider retirement failed: {failure:?}"))
        })?;
        assert_eq!(exit.reason(), RecoveryRequired::AuthenticationFailed);
        assert_eq!(exit.platform_cause(), None);
        wrong_provider_fixture.cleanup_checked()?;

        let wrong_install_fixture = RuntimePairFixture::new()?;
        let installed = test_installation(0x98)?;
        let presented = test_installation(0x99)?;
        let installed_provider = test_provider(installed, 0x9a)?;
        let mut presented_provider = test_provider(presented, 0x9a)?;
        let initial = snapshot(RunMarkerState::Clean, 1, installed, &installed_provider)?;
        install_pair(&wrong_install_fixture, &initial)?;
        let failure = match start_windows_runtime(
            wrong_install_fixture.acquire_writer()?,
            presented_provider.runtime_authority(),
        ) {
            Err(WindowsRuntimeStartFailure::Terminal(failure)) => failure,
            Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                let reason = failure.reason();
                let _retired = failure.retire().map_err(|failure| failure.cause())?;
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
            let mut provider = test_provider(installation, byte.wrapping_add(1))?;
            install_pair(&fixture, &snapshot(state, 1, installation, &provider)?)?;
            let failure = match start_windows_runtime(
                fixture.acquire_writer()?,
                provider.runtime_authority(),
            ) {
                Err(WindowsRuntimeStartFailure::Terminal(failure)) => failure,
                Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                    let reason = failure.reason();
                    let _retired = failure.retire().map_err(|failure| failure.cause())?;
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
            let mut provider = test_provider(installation, byte.wrapping_add(1))?;
            let initial = snapshot(RunMarkerState::Clean, 1, installation, &provider)?;
            install_pair(&fixture, &initial)?;
            let prepared = prepare_active(&fixture, &mut provider)?;
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
        let mut provider = test_provider(installation, 0xd2)?;
        let initial = snapshot(RunMarkerState::Clean, 1, installation, &provider)?;
        install_pair(&fixture, &initial)?;
        let prepared = prepare_active(&fixture, &mut provider)?;
        fixture.inject_fault(RuntimePairFault::CommittedRereadRevalidation);
        match prepared.commit_and_reread() {
            WindowsActiveCommitOutcome::Terminal(failure) => {
                assert_eq!(failure.reason(), RecoveryRequired::RereadDrift);
                let platform_cause = failure.platform_cause();
                assert!(platform_cause.is_some());
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
                assert_eq!(retirement.platform_cause, platform_cause);
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
            let mut provider = test_provider(installation, byte.wrapping_add(1))?;
            let initial = snapshot(RunMarkerState::Clean, 1, installation, &provider)?;
            install_pair(&fixture, &initial)?;
            let active = exact_active(&fixture, &mut provider)?;
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
        let mut retained_provider = test_provider(retained_installation, 0xf2)?;
        let initial = snapshot(
            RunMarkerState::Clean,
            1,
            retained_installation,
            &retained_provider,
        )?;
        install_pair(&retained_fixture, &initial)?;
        let clean = exact_clean(&retained_fixture, &mut retained_provider)?;
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
        let mut no_receipt_provider = test_provider(no_receipt_installation, 0xf4)?;
        let initial = snapshot(
            RunMarkerState::Clean,
            1,
            no_receipt_installation,
            &no_receipt_provider,
        )?;
        install_pair(&no_receipt_fixture, &initial)?;
        let clean = exact_clean(&no_receipt_fixture, &mut no_receipt_provider)?;
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
    fn kernel_post_release_receipt_fault_is_irreversible() -> TestResult {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0xf5)?;
        let mut provider = test_provider(installation, 0xf6)?;
        let initial = snapshot(RunMarkerState::Clean, 1, installation, &provider)?;
        install_pair(&fixture, &initial)?;

        let clean = exact_clean(&fixture, &mut provider)?;
        match clean.stop_with_post_release_fault_for_test() {
            WindowsStopOutcome::PostReleaseTerminal(failure) => {
                assert_eq!(failure.reason(), RecoveryRequired::OperationPhaseMismatch);
            }
            WindowsStopOutcome::Stopped(_stopped) => {
                return Err(std::io::Error::other(
                    "post-release receipt fault minted Stopped evidence",
                )
                .into());
            }
            WindowsStopOutcome::Terminal(failure) => return retire_terminal(failure),
            WindowsStopOutcome::ReleasedNoReceipt(failure) => {
                return Err(failure.cause().into());
            }
        }
        fixture.cleanup_checked()?;

        let normal_fixture = RuntimePairFixture::new()?;
        let normal_installation = test_installation(0xf7)?;
        let mut normal_provider = test_provider(normal_installation, 0xf8)?;
        let normal_initial = snapshot(
            RunMarkerState::Clean,
            1,
            normal_installation,
            &normal_provider,
        )?;
        install_pair(&normal_fixture, &normal_initial)?;
        let normal_clean = exact_clean(&normal_fixture, &mut normal_provider)?;
        match normal_clean.stop() {
            WindowsStopOutcome::Stopped(_stopped) => {}
            WindowsStopOutcome::Terminal(failure) => return retire_terminal(failure),
            WindowsStopOutcome::ReleasedNoReceipt(failure) => {
                return Err(failure.cause().into());
            }
            WindowsStopOutcome::PostReleaseTerminal(failure) => {
                return Err(failure.reason().into());
            }
        }
        normal_fixture.cleanup_checked()
    }

    #[test]
    fn kernel_stop_precheck_rejects_crossed_pair_before_release() -> TestResult {
        let first_fixture = RuntimePairFixture::new()?;
        let first_installation = test_installation(0x11)?;
        let mut first_provider = test_provider(first_installation, 0x12)?;
        let first_initial = snapshot(
            RunMarkerState::Clean,
            1,
            first_installation,
            &first_provider,
        )?;
        install_pair(&first_fixture, &first_initial)?;
        let first = exact_clean(&first_fixture, &mut first_provider)?;

        let second_fixture = RuntimePairFixture::new()?;
        let second_installation = test_installation(0x13)?;
        let mut second_provider = test_provider(second_installation, 0x14)?;
        let second_initial = snapshot(
            RunMarkerState::Clean,
            1,
            second_installation,
            &second_provider,
        )?;
        install_pair(&second_fixture, &second_initial)?;
        let second = exact_clean(&second_fixture, &mut second_provider)?;

        let WindowsCleanWithWriter {
            logical: first_logical,
            pair: first_pair,
        } = first;
        let WindowsCleanWithWriter {
            logical: second_logical,
            pair: second_pair,
        } = second;
        for crossed in [
            WindowsCleanWithWriter {
                logical: first_logical,
                pair: second_pair,
            },
            WindowsCleanWithWriter {
                logical: second_logical,
                pair: first_pair,
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
        let mut live_provider = test_provider(live_installation, 0x22)?;
        install_windows_runtime_clean_fixture(&live_fixture, live_installation, &live_provider)?;
        let boot = start(&live_fixture, &mut live_provider)?;
        let pending = boot.into_retirement();
        assert!(format!("{pending:?}").contains("[REDACTED]"));
        let retired = pending.retire_checked().map_err(|failure| {
            std::io::Error::other(format!("reason-neutral retirement failed: {failure:?}"))
        })?;
        assert!(format!("{retired:?}").contains("[REDACTED]"));
        live_fixture.cleanup_checked()?;

        let reload_fixture = RuntimePairFixture::new()?;
        let reload_installation = test_installation(0x23)?;
        let mut reload_provider = test_provider(reload_installation, 0x24)?;
        let initial = snapshot(
            RunMarkerState::Clean,
            1,
            reload_installation,
            &reload_provider,
        )?;
        install_pair(&reload_fixture, &initial)?;
        let prepared = prepare_active(&reload_fixture, &mut reload_provider)?;
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
        retire_reason_neutral(reload.into_retirement())?;
        reload_fixture.cleanup_checked()?;

        let fault_fixture = RuntimePairFixture::new()?;
        let fault_installation = test_installation(0x25)?;
        let mut fault_provider = test_provider(fault_installation, 0x26)?;
        install_windows_runtime_clean_fixture(&fault_fixture, fault_installation, &fault_provider)?;
        let prepared = prepare_active(&fault_fixture, &mut fault_provider)?;
        fault_fixture.inject_fault(RuntimePairFault::CommittedRereadRevalidation);
        let terminal = match prepared.commit_and_reread() {
            WindowsActiveCommitOutcome::Terminal(failure) => failure,
            WindowsActiveCommitOutcome::ReloadRequired(reload) => {
                retire_reason_neutral(reload.into_retirement())?;
                return Err(std::io::Error::other(
                    "confirmed commit fault exposed reload authority",
                )
                .into());
            }
            WindowsActiveCommitOutcome::Active(active) => {
                retire_reason_neutral(active.into_retirement())?;
                return Err(std::io::Error::other(
                    "confirmed commit fault minted Active authority",
                )
                .into());
            }
        };
        let (_cause, pending) = terminal.into_retirement_parts();
        let failure = match pending.retire_checked() {
            Err(failure) => failure,
            Ok(_retired) => {
                return Err(std::io::Error::other(
                    "OS retirement close ambiguity minted checked evidence",
                )
                .into());
            }
        };
        assert_eq!(failure.cause(), ServiceRunStateError::Release);
        assert!(format!("{failure:?}").contains("[REDACTED]"));
        fault_fixture.cleanup_checked()
    }

    #[test]
    fn composite_authority_and_receipts_are_move_only() -> TestResult {
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
        assert_move_only!(WindowsRuntimeBindingFailure<'static>);
        assert_move_only!(WindowsUnboundRetired<'static>);
        assert_move_only!(WindowsUnboundRetirementFailure<'static>);
        assert_move_only!(WindowsStoppedRunEvidence<'static>);
        assert_move_only!(WindowsTerminalCause);
        assert_move_only!(WindowsTerminalFailure<'static>);
        assert_move_only!(WindowsRetirementPending<'static>);
        assert_move_only!(WindowsCheckedRetired<'static>);
        assert_move_only!(WindowsCheckedRetirementFailure<'static>);
        assert_move_only!(WindowsReleasedNoReceipt<'static>);
        assert_move_only!(WindowsPostReleaseTerminal<'static>);
        assert_move_only!(WindowsRecoveryExit<'static>);
        assert_move_only!(WindowsRetirementFailure<'static>);

        let installation = test_installation(0x2f)?;
        let mut provider = test_provider(installation, 0x3f)?;
        let failure = WindowsUnboundRetirementFailure {
            cause: ServiceRunStateError::Release,
            _authority: provider.runtime_authority(),
        };
        assert_eq!(failure.cause(), ServiceRunStateError::Release);
        assert!(format!("{failure:?}").contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn composite_live_states_expose_consuming_terminal_transitions() {
        let _: fn(
            WindowsRuntimeBindingFailure<'static>,
        ) -> Result<
            WindowsUnboundRetired<'static>,
            WindowsUnboundRetirementFailure<'static>,
        > = WindowsRuntimeBindingFailure::retire;
        let _: fn(WindowsRuntimeWriterAcquired<'static>) -> WindowsRetirementPending<'static> =
            WindowsRuntimeWriterAcquired::into_retirement;
        let _: fn(WindowsBootEvidence<'static>) -> WindowsRetirementPending<'static> =
            WindowsBootEvidence::into_retirement;
        let _: fn(WindowsPreparedActiveTransition<'static>) -> WindowsRetirementPending<'static> =
            WindowsPreparedActiveTransition::into_retirement;
        let _: fn(WindowsActiveRunLease<'static>) -> WindowsRetirementPending<'static> =
            WindowsActiveRunLease::into_retirement;
        let _: fn(WindowsActiveReloadRequired<'static>) -> WindowsRetirementPending<'static> =
            WindowsActiveReloadRequired::into_retirement;
        let _: fn(WindowsCleanWithWriter<'static>) -> WindowsRetirementPending<'static> =
            WindowsCleanWithWriter::into_retirement;
        let _: fn(WindowsCleanReloadRequired<'static>) -> WindowsRetirementPending<'static> =
            WindowsCleanReloadRequired::into_retirement;
        let _: fn(
            WindowsRetirementPending<'static>,
        ) -> Result<
            WindowsCheckedRetired<'static>,
            WindowsCheckedRetirementFailure<'static>,
        > = WindowsRetirementPending::retire_checked;
        let _: fn(
            WindowsTerminalFailure<'static>,
        ) -> (WindowsTerminalCause, WindowsRetirementPending<'static>) =
            WindowsTerminalFailure::into_retirement_parts;

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
