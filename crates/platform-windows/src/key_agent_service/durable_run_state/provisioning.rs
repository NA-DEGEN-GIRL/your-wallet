//! Fresh-install generation-one provisioning typestate.
//!
//! The types in this module are production-compiled contracts, but their only
//! constructors live on the bounded `cfg(test)` backend. A future adapter must
//! supply equivalent authenticated fresh-install and exclusive-writer evidence.

// The evidence graph stays fixed-capacity and allocation-free. Boxing these
// move-only authorities would weaken that boundedness contract solely to make
// enum layout smaller.
#![allow(clippy::large_enum_variant, clippy::result_large_err)]

#[cfg(windows)]
#[path = "windows_provisioning.rs"]
mod windows;

#[cfg(windows)]
#[allow(unused_imports)] // Dormant production-compiled Windows provisioning seam.
pub(super) use windows::{
    WindowsFreshInstallAuthority, WindowsFreshInstallAuthorityBindingFailure,
    WindowsInitialCleanCommitOutcome, WindowsInitialCleanCommittedWithWriter,
    WindowsInitialCleanReloadOutcome, WindowsInitialCleanReloadRequired,
    WindowsInitialProvisioningStartFailure, WindowsInstallerProvisioningGrant,
    WindowsPostReleaseProvisioningTerminal, WindowsPreparedInitialCleanTransition,
    WindowsProvisionedRunState, WindowsProvisioningBindingFailure,
    WindowsProvisioningCheckedRetired, WindowsProvisioningCheckedRetirementFailure,
    WindowsProvisioningReleaseOutcome, WindowsProvisioningReleasedNoReceipt,
    WindowsProvisioningRetirementPending, WindowsProvisioningTerminalCause,
    WindowsProvisioningTerminalFailure, WindowsProvisioningUnboundRetired,
    WindowsProvisioningUnboundRetirementFailure, WindowsUnprovisionedWithWriter,
    bind_windows_fresh_install_authority, start_windows_initial_provisioning,
};

use std::fmt;
use std::num::NonZeroU64;

use super::{
    BackendBinding, Commitment, DurableSnapshot, InstallationIdentity, OneShotCommitOperation,
    OneShotReleaseOperation, OneShotReloadOperation, RecoveryRequired, RunMarkerState,
    RunStateAuthenticationProvider, RunStateProviderIdentity, SnapshotObservation, build_snapshot,
    verify_observation,
};

#[cfg(test)]
use super::{
    DurableRunStateCommitFailure, DurableRunStateCommitFault, DurableRunStateFixture,
    DurableRunStateReleaseFailure, DurableRunStateReleaseFault, DurableRunStateRereadFault,
    FixedObservation, FixtureCommitAmbiguity, FixtureWriterRecord, FixtureWriterRole,
    allocate_fixture_backend_binding,
};

/// Move-only fresh-install authority bound to one provider, installation, backend,
/// and provisioning attempt.
pub(in crate::key_agent_service) struct FreshInstallProvisioningAuthority<'provider> {
    provider: &'provider RunStateAuthenticationProvider,
    provider_identity: RunStateProviderIdentity,
    installation: InstallationIdentity,
    binding: BackendBinding,
    attempt: NonZeroU64,
}

impl fmt::Debug for FreshInstallProvisioningAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshInstallProvisioningAuthority([REDACTED])")
    }
}

/// Move-only writer lease whose role is distinct from the runtime writer.
pub(in crate::key_agent_service) struct ProvisioningWriterLease {
    installation: InstallationIdentity,
    epoch: NonZeroU64,
    binding: BackendBinding,
    attempt: NonZeroU64,
}

impl fmt::Debug for ProvisioningWriterLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningWriterLease([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ProvisioningOperationBinding {
    installation: InstallationIdentity,
    writer_epoch: NonZeroU64,
    backend: BackendBinding,
    authority_attempt: NonZeroU64,
    reload_round: NonZeroU64,
}

impl ProvisioningOperationBinding {
    const fn from_authority_and_lease(
        authority: &FreshInstallProvisioningAuthority<'_>,
        lease: &ProvisioningWriterLease,
        reload_round: NonZeroU64,
    ) -> Self {
        Self {
            installation: authority.installation,
            writer_epoch: lease.epoch,
            backend: authority.binding,
            authority_attempt: authority.attempt,
            reload_round,
        }
    }
}

fn validate_authority_and_lease(
    authority: &FreshInstallProvisioningAuthority<'_>,
    lease: &ProvisioningWriterLease,
) -> Result<(), RecoveryRequired> {
    if authority.installation != authority.provider.installation() {
        return Err(RecoveryRequired::InstallationIdentityMismatch);
    }
    if authority.provider_identity != authority.provider.identity() {
        return Err(RecoveryRequired::AuthenticationFailed);
    }
    if authority.binding != lease.binding {
        return Err(RecoveryRequired::BackendBindingMismatch);
    }
    if authority.installation != lease.installation {
        return Err(RecoveryRequired::InstallationIdentityMismatch);
    }
    if authority.attempt != lease.attempt {
        return Err(RecoveryRequired::ProvisioningAttemptMismatch);
    }
    Ok(())
}

fn validate_operation_binding(
    observed: ProvisioningOperationBinding,
    authority: &FreshInstallProvisioningAuthority<'_>,
    lease: &ProvisioningWriterLease,
    reload_round: NonZeroU64,
) -> Result<(), RecoveryRequired> {
    validate_authority_and_lease(authority, lease)?;
    if observed.backend != authority.binding {
        return Err(RecoveryRequired::BackendBindingMismatch);
    }
    if observed.installation != authority.installation {
        return Err(RecoveryRequired::InstallationIdentityMismatch);
    }
    if observed.writer_epoch != lease.epoch {
        return Err(RecoveryRequired::WriterLeaseMismatch);
    }
    if observed.authority_attempt != authority.attempt {
        return Err(RecoveryRequired::ProvisioningAttemptMismatch);
    }
    if observed.reload_round != reload_round {
        return Err(RecoveryRequired::ProvisioningReloadRoundMismatch);
    }
    Ok(())
}

/// Failure before or after the provisioning writer was acquired.
#[must_use]
pub(in crate::key_agent_service) enum InitialProvisioningStartFailure<'provider> {
    /// No writer was acquired, so there is no retirement authority.
    BeforeWriter(RecoveryRequired),
    /// The writer was acquired and must be retired for terminal process exit.
    WithWriter(ProvisioningFailureWithWriter<'provider>),
}

impl InitialProvisioningStartFailure<'_> {
    /// Returns the stable fail-closed reason.
    #[must_use]
    pub(super) const fn reason(&self) -> RecoveryRequired {
        match self {
            Self::BeforeWriter(reason) => *reason,
            Self::WithWriter(failure) => failure.reason(),
        }
    }
}

impl fmt::Debug for InitialProvisioningStartFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitialProvisioningStartFailure")
            .field("reason", &self.reason())
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

/// Exact Missing/Missing observation made while the provisioning writer is
/// still held.
pub(in crate::key_agent_service) struct UnprovisionedWithWriter<'provider> {
    authority: FreshInstallProvisioningAuthority<'provider>,
    lease: ProvisioningWriterLease,
    reload_round: NonZeroU64,
}

impl<'provider> UnprovisionedWithWriter<'provider> {
    /// Prepares only the canonical Clean/generation-one/ZERO-predecessor pair.
    pub(in crate::key_agent_service) fn prepare_initial_clean(
        self,
    ) -> Result<PreparedInitialCleanTransition<'provider>, ProvisioningFailureWithWriter<'provider>>
    {
        let Self {
            authority,
            lease,
            reload_round,
        } = self;
        if let Err(reason) = validate_authority_and_lease(&authority, &lease) {
            return Err(ProvisioningFailureWithWriter::new(
                reason,
                authority,
                lease,
                reload_round,
            ));
        }
        let candidate = match build_snapshot(
            RunMarkerState::Clean,
            NonZeroU64::MIN,
            Commitment::ZERO,
            authority.provider,
        ) {
            Ok(candidate) => candidate,
            Err(reason) => {
                return Err(ProvisioningFailureWithWriter::new(
                    reason,
                    authority,
                    lease,
                    reload_round,
                ));
            }
        };
        Ok(PreparedInitialCleanTransition {
            candidate,
            authority,
            lease,
            reload_round,
            operation: OneShotCommitOperation::new(),
        })
    }

    /// Abandons provisioning without producing another write authority.
    pub(super) fn abort(
        self,
        reason: RecoveryRequired,
    ) -> ProvisioningFailureWithWriter<'provider> {
        ProvisioningFailureWithWriter::new(reason, self.authority, self.lease, self.reload_round)
    }

    /// Retains only the terminal writer-retirement path.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> ProvisioningWriterExitPending<'provider> {
        ProvisioningWriterExitPending::new(self.authority, self.lease, self.reload_round)
    }
}

impl fmt::Debug for UnprovisionedWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnprovisionedWithWriter([REDACTED])")
    }
}

/// Canonical initial Clean candidate awaiting a distinct commit and readback.
pub(in crate::key_agent_service) struct PreparedInitialCleanTransition<'provider> {
    candidate: DurableSnapshot,
    authority: FreshInstallProvisioningAuthority<'provider>,
    lease: ProvisioningWriterLease,
    reload_round: NonZeroU64,
    operation: OneShotCommitOperation,
}

impl<'provider> PreparedInitialCleanTransition<'provider> {
    /// Verifies exact independently typed commit and reread receipts.
    #[allow(clippy::needless_pass_by_value)]
    pub(in crate::key_agent_service) fn complete(
        self,
        committed: CommittedInitialCleanMarker,
        reread: RereadInitialCleanMarker,
    ) -> Result<InitialCleanCommittedWithWriter<'provider>, ProvisioningFailureWithWriter<'provider>>
    {
        let Self {
            candidate,
            authority,
            lease,
            reload_round,
            operation,
        } = self;
        if let Err(reason) =
            validate_operation_binding(committed.proof, &authority, &lease, reload_round)
        {
            return Err(ProvisioningFailureWithWriter::new(
                reason,
                authority,
                lease,
                reload_round,
            ));
        }
        if let Err(reason) =
            validate_operation_binding(reread.proof, &authority, &lease, reload_round)
        {
            return Err(ProvisioningFailureWithWriter::new(
                reason,
                authority,
                lease,
                reload_round,
            ));
        }
        if !operation.has_exact_receipt_pair() {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                authority,
                lease,
                reload_round,
            ));
        }
        if committed.observed != candidate.bytes.observation() {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::CommitReceiptMismatch,
                authority,
                lease,
                reload_round,
            ));
        }
        if reread.observed != candidate.bytes.observation() {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::RereadDrift,
                authority,
                lease,
                reload_round,
            ));
        }
        let authenticated = match verify_observation(&reread.observed, authority.provider) {
            Ok(authenticated) => authenticated,
            Err(reason) => {
                return Err(ProvisioningFailureWithWriter::new(
                    reason,
                    authority,
                    lease,
                    reload_round,
                ));
            }
        };
        if authenticated != candidate {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::EquivocationDetected,
                authority,
                lease,
                reload_round,
            ));
        }
        Ok(InitialCleanCommittedWithWriter {
            durable: authenticated,
            authority,
            lease,
            reload_round,
        })
    }

    /// Requires a checked fresh reload round after an ambiguous commit.
    pub(in crate::key_agent_service) fn commit_ambiguous(
        self,
    ) -> Result<InitialCleanReloadRequired<'provider>, ProvisioningFailureWithWriter<'provider>>
    {
        let Self {
            candidate,
            authority,
            lease,
            reload_round,
            operation,
        } = self;
        if !operation.has_unresolved_commit_attempt() {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                authority,
                lease,
                reload_round,
            ));
        }
        let Some(next_round) = reload_round.get().checked_add(1).and_then(NonZeroU64::new) else {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::ProvisioningReloadRoundExhausted,
                authority,
                lease,
                reload_round,
            ));
        };
        Ok(InitialCleanReloadRequired {
            candidate,
            authority,
            lease,
            prior_round: reload_round,
            reload_round: next_round,
            operation: OneShotReloadOperation::new(),
        })
    }

    /// Converts a known commit failure into terminal-only state.
    pub(super) fn abort(
        self,
        reason: RecoveryRequired,
    ) -> ProvisioningFailureWithWriter<'provider> {
        ProvisioningFailureWithWriter::new(reason, self.authority, self.lease, self.reload_round)
    }

    /// Retains only the terminal writer-retirement path.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> ProvisioningWriterExitPending<'provider> {
        ProvisioningWriterExitPending::new(self.authority, self.lease, self.reload_round)
    }
}

impl fmt::Debug for PreparedInitialCleanTransition<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedInitialCleanTransition([REDACTED])")
    }
}

/// Backend receipt claiming the full initial Clean pair was committed.
#[derive(Eq, PartialEq)]
pub(in crate::key_agent_service) struct CommittedInitialCleanMarker {
    observed: SnapshotObservation,
    proof: ProvisioningOperationBinding,
}

impl fmt::Debug for CommittedInitialCleanMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedInitialCleanMarker([REDACTED])")
    }
}

/// Independently typed post-commit initial Clean readback.
#[derive(Eq, PartialEq)]
pub(in crate::key_agent_service) struct RereadInitialCleanMarker {
    observed: SnapshotObservation,
    proof: ProvisioningOperationBinding,
}

impl fmt::Debug for RereadInitialCleanMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RereadInitialCleanMarker([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProvisioningWriterObservation {
    Missing,
    Held {
        installation: InstallationIdentity,
        epoch: NonZeroU64,
        attempt: NonZeroU64,
    },
}

/// Move-only state that can only be resolved by a fresh backend reload receipt.
pub(in crate::key_agent_service) struct InitialCleanReloadRequired<'provider> {
    candidate: DurableSnapshot,
    authority: FreshInstallProvisioningAuthority<'provider>,
    lease: ProvisioningWriterLease,
    prior_round: NonZeroU64,
    reload_round: NonZeroU64,
    operation: OneShotReloadOperation,
}

impl<'provider> InitialCleanReloadRequired<'provider> {
    /// Resolves exact Missing/Missing as retry authority and the exact complete
    /// candidate as committed-with-writer. Every partial or drifting result is
    /// terminal.
    #[allow(clippy::needless_pass_by_value)]
    pub(in crate::key_agent_service) fn complete_reload(
        self,
        receipt: InitialCleanReloadReceipt,
    ) -> Result<ReloadedInitialCleanState<'provider>, ProvisioningFailureWithWriter<'provider>>
    {
        let Self {
            candidate,
            authority,
            lease,
            prior_round,
            reload_round,
            operation,
        } = self;
        let terminal_round = if operation.has_exact_receipt() {
            reload_round
        } else {
            prior_round
        };
        if let Err(reason) =
            validate_operation_binding(receipt.proof, &authority, &lease, reload_round)
        {
            return Err(ProvisioningFailureWithWriter::new(
                reason,
                authority,
                lease,
                terminal_round,
            ));
        }
        let expected_writer = ProvisioningWriterObservation::Held {
            installation: lease.installation,
            epoch: lease.epoch,
            attempt: lease.attempt,
        };
        if receipt.writer != expected_writer {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::WriterLeaseMismatch,
                authority,
                lease,
                terminal_round,
            ));
        }
        if !operation.has_exact_receipt() {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                authority,
                lease,
                terminal_round,
            ));
        }
        if observation_is_exactly_empty(&receipt.observed) {
            return Ok(ReloadedInitialCleanState::Retry(UnprovisionedWithWriter {
                authority,
                lease,
                reload_round,
            }));
        }
        if receipt.observed == candidate.bytes.observation() {
            let authenticated = match verify_observation(&receipt.observed, authority.provider) {
                Ok(authenticated) => authenticated,
                Err(reason) => {
                    return Err(ProvisioningFailureWithWriter::new(
                        reason,
                        authority,
                        lease,
                        terminal_round,
                    ));
                }
            };
            if authenticated != candidate {
                return Err(ProvisioningFailureWithWriter::new(
                    RecoveryRequired::EquivocationDetected,
                    authority,
                    lease,
                    terminal_round,
                ));
            }
            return Ok(ReloadedInitialCleanState::Committed(
                InitialCleanCommittedWithWriter {
                    durable: authenticated,
                    authority,
                    lease,
                    reload_round,
                },
            ));
        }
        Err(ProvisioningFailureWithWriter::new(
            classify_initial_observation(&receipt.observed),
            authority,
            lease,
            terminal_round,
        ))
    }

    fn terminal_round(&self) -> NonZeroU64 {
        if self.operation.has_exact_receipt() {
            self.reload_round
        } else {
            self.prior_round
        }
    }

    /// Abandons reload without restoring provisioning write authority.
    pub(super) fn abort(
        self,
        reason: RecoveryRequired,
    ) -> ProvisioningFailureWithWriter<'provider> {
        let terminal_round = self.terminal_round();
        ProvisioningFailureWithWriter::new(reason, self.authority, self.lease, terminal_round)
    }

    /// Retains only the terminal writer-retirement path.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> ProvisioningWriterExitPending<'provider> {
        let terminal_round = self.terminal_round();
        ProvisioningWriterExitPending::new(self.authority, self.lease, terminal_round)
    }
}

impl fmt::Debug for InitialCleanReloadRequired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitialCleanReloadRequired([REDACTED])")
    }
}

/// Fresh, backend-bound ambiguity observation.
pub(in crate::key_agent_service) struct InitialCleanReloadReceipt {
    observed: SnapshotObservation,
    writer: ProvisioningWriterObservation,
    proof: ProvisioningOperationBinding,
}

impl fmt::Debug for InitialCleanReloadReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitialCleanReloadReceipt([REDACTED])")
    }
}

/// Exact resolution of an ambiguous initial Clean commit.
pub(in crate::key_agent_service) enum ReloadedInitialCleanState<'provider> {
    /// No write occurred; retry is authorized only in this fresh reload round.
    Retry(UnprovisionedWithWriter<'provider>),
    /// Both objects reached the exact candidate and the writer remains held.
    Committed(InitialCleanCommittedWithWriter<'provider>),
}

impl fmt::Debug for ReloadedInitialCleanState<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry(_) => formatter.write_str("ReloadedInitialCleanState::Retry([REDACTED])"),
            Self::Committed(_) => {
                formatter.write_str("ReloadedInitialCleanState::Committed([REDACTED])")
            }
        }
    }
}

/// Exact authenticated initial Clean state that still owns the provisioning
/// writer.
pub(in crate::key_agent_service) struct InitialCleanCommittedWithWriter<'provider> {
    durable: DurableSnapshot,
    authority: FreshInstallProvisioningAuthority<'provider>,
    lease: ProvisioningWriterLease,
    reload_round: NonZeroU64,
}

impl<'provider> InitialCleanCommittedWithWriter<'provider> {
    /// Returns the exact initial generation.
    #[must_use]
    pub(in crate::key_agent_service) const fn generation(&self) -> NonZeroU64 {
        self.durable.marker.generation
    }

    /// Begins the sole normal provisioning-writer release path.
    #[must_use]
    pub(in crate::key_agent_service) fn prepare_writer_release(
        self,
    ) -> PendingProvisioningWriterRelease<'provider> {
        PendingProvisioningWriterRelease {
            durable: self.durable,
            authority: self.authority,
            lease: self.lease,
            reload_round: self.reload_round,
            operation: OneShotReleaseOperation::new(),
        }
    }

    /// Converts a known failure into terminal-only state.
    pub(super) fn abort(
        self,
        reason: RecoveryRequired,
    ) -> ProvisioningFailureWithWriter<'provider> {
        ProvisioningFailureWithWriter::new(reason, self.authority, self.lease, self.reload_round)
    }

    /// Retains only the terminal writer-retirement path.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> ProvisioningWriterExitPending<'provider> {
        ProvisioningWriterExitPending::new(self.authority, self.lease, self.reload_round)
    }
}

impl fmt::Debug for InitialCleanCommittedWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitialCleanCommittedWithWriter([REDACTED])")
    }
}

/// Initial Clean evidence waiting for the exact provisioning-writer release.
pub(in crate::key_agent_service) struct PendingProvisioningWriterRelease<'provider> {
    durable: DurableSnapshot,
    authority: FreshInstallProvisioningAuthority<'provider>,
    lease: ProvisioningWriterLease,
    reload_round: NonZeroU64,
    operation: OneShotReleaseOperation,
}

impl<'provider> PendingProvisioningWriterRelease<'provider> {
    /// Verifies the exact release receipt and mints provisioned state. This
    /// state deliberately has no conversion into ordinary boot evidence.
    #[allow(clippy::needless_pass_by_value)]
    pub(in crate::key_agent_service) fn complete(
        self,
        receipt: ProvisioningWriterReleaseReceipt,
    ) -> Result<ProvisionedRunState<'provider>, ProvisioningFailureWithWriter<'provider>> {
        let Self {
            durable,
            authority,
            lease,
            reload_round,
            operation,
        } = self;
        if let Err(reason) =
            validate_operation_binding(receipt.proof, &authority, &lease, reload_round)
        {
            return Err(ProvisioningFailureWithWriter::new(
                reason,
                authority,
                lease,
                reload_round,
            ));
        }
        if !operation.has_exact_receipt() {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                authority,
                lease,
                reload_round,
            ));
        }
        Ok(ProvisionedRunState {
            durable,
            _authority: authority,
        })
    }

    /// Converts any known or ambiguous release failure into terminal-only
    /// retirement/reconciliation state.
    pub(super) fn abort(
        self,
        reason: RecoveryRequired,
    ) -> ProvisioningFailureWithWriter<'provider> {
        ProvisioningFailureWithWriter::new(reason, self.authority, self.lease, self.reload_round)
    }

    /// Retains only the terminal writer-retirement/reconciliation path.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> ProvisioningWriterExitPending<'provider> {
        ProvisioningWriterExitPending::new(self.authority, self.lease, self.reload_round)
    }
}

impl fmt::Debug for PendingProvisioningWriterRelease<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingProvisioningWriterRelease([REDACTED])")
    }
}

/// Move-only exact provisioning-writer release receipt.
pub(in crate::key_agent_service) struct ProvisioningWriterReleaseReceipt {
    proof: ProvisioningOperationBinding,
}

impl fmt::Debug for ProvisioningWriterReleaseReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningWriterReleaseReceipt([REDACTED])")
    }
}

/// Opaque proof that generation-one Clean provisioning and exact writer
/// release completed. Ordinary boot must reopen/authenticate and acquire a new
/// runtime writer separately.
pub(in crate::key_agent_service) struct ProvisionedRunState<'provider> {
    durable: DurableSnapshot,
    _authority: FreshInstallProvisioningAuthority<'provider>,
}

impl ProvisionedRunState<'_> {
    /// Returns the exact provisioned generation.
    #[must_use]
    pub(in crate::key_agent_service) const fn generation(&self) -> NonZeroU64 {
        self.durable.marker.generation
    }
}

impl fmt::Debug for ProvisionedRunState<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisionedRunState([REDACTED])")
    }
}

/// Terminal-only provisioning failure that retains the exact writer.
#[must_use]
pub(in crate::key_agent_service) struct ProvisioningFailureWithWriter<'provider> {
    reason: RecoveryRequired,
    exit: ProvisioningWriterExitPending<'provider>,
}

impl<'provider> ProvisioningFailureWithWriter<'provider> {
    fn new(
        reason: RecoveryRequired,
        authority: FreshInstallProvisioningAuthority<'provider>,
        lease: ProvisioningWriterLease,
        reload_round: NonZeroU64,
    ) -> Self {
        Self {
            reason,
            exit: ProvisioningWriterExitPending::new(authority, lease, reload_round),
        }
    }

    /// Returns the stable fail-closed reason without exposing authority.
    #[must_use]
    pub(super) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    /// Consumes the failure into its sole terminal retirement path.
    #[must_use]
    pub(super) fn into_writer_exit(self) -> ProvisioningWriterExitPending<'provider> {
        self.exit
    }
}

impl fmt::Debug for ProvisioningFailureWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisioningFailureWithWriter")
            .field("reason", &self.reason)
            .field("exit", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for ProvisioningFailureWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; terminal provisioning-writer retirement is required",
            self.reason
        )
    }
}

impl std::error::Error for ProvisioningFailureWithWriter<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

/// Move-only provisioning writer authority usable only for terminal exit.
pub(in crate::key_agent_service) struct ProvisioningWriterExitPending<'provider> {
    authority: FreshInstallProvisioningAuthority<'provider>,
    lease: ProvisioningWriterLease,
    reload_round: NonZeroU64,
    operation: OneShotReleaseOperation,
}

impl<'provider> ProvisioningWriterExitPending<'provider> {
    const fn new(
        authority: FreshInstallProvisioningAuthority<'provider>,
        lease: ProvisioningWriterLease,
        reload_round: NonZeroU64,
    ) -> Self {
        Self {
            authority,
            lease,
            reload_round,
            operation: OneShotReleaseOperation::new(),
        }
    }

    /// Verifies exact retirement/reconciliation and yields no reusable writer.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn complete(
        self,
        receipt: ProvisioningWriterExitReceipt,
    ) -> Result<ProvisioningRecoveryExitEvidence<'provider>, ProvisioningFailureWithWriter<'provider>>
    {
        let Self {
            authority,
            lease,
            reload_round,
            operation,
        } = self;
        if let Err(reason) =
            validate_operation_binding(receipt.proof, &authority, &lease, reload_round)
        {
            return Err(ProvisioningFailureWithWriter::new(
                reason,
                authority,
                lease,
                reload_round,
            ));
        }
        if !operation.has_exact_receipt() {
            return Err(ProvisioningFailureWithWriter::new(
                RecoveryRequired::OperationPhaseMismatch,
                authority,
                lease,
                reload_round,
            ));
        }
        Ok(ProvisioningRecoveryExitEvidence {
            _binding: receipt.proof.backend,
            _authority: authority,
        })
    }
}

impl fmt::Debug for ProvisioningWriterExitPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningWriterExitPending([REDACTED])")
    }
}

/// Exact terminal provisioning-writer retirement receipt.
pub(in crate::key_agent_service) struct ProvisioningWriterExitReceipt {
    proof: ProvisioningOperationBinding,
}

impl fmt::Debug for ProvisioningWriterExitReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningWriterExitReceipt([REDACTED])")
    }
}

/// Opaque evidence that terminal provisioning-writer retirement completed.
pub(in crate::key_agent_service) struct ProvisioningRecoveryExitEvidence<'provider> {
    _binding: BackendBinding,
    _authority: FreshInstallProvisioningAuthority<'provider>,
}

impl fmt::Debug for ProvisioningRecoveryExitEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningRecoveryExitEvidence([REDACTED])")
    }
}

#[cfg(test)]
fn observation_is_exactly_empty(observed: &SnapshotObservation) -> bool {
    observed.marker == FixedObservation::Missing && observed.checkpoint == FixedObservation::Missing
}

#[cfg(not(test))]
fn observation_is_exactly_empty(observed: &SnapshotObservation) -> bool {
    matches!(
        (observed.marker, observed.checkpoint),
        (
            super::FixedObservation::Missing,
            super::FixedObservation::Missing
        )
    )
}

fn classify_initial_observation(observed: &SnapshotObservation) -> RecoveryRequired {
    match (observed.marker, observed.checkpoint) {
        (super::FixedObservation::Malformed, _) => RecoveryRequired::MalformedRunMarker,
        (_, super::FixedObservation::Malformed) => RecoveryRequired::MalformedHighWaterCheckpoint,
        _ => RecoveryRequired::InitialProvisioningStateNotEmpty,
    }
}

#[cfg(test)]
impl DurableRunStateFixture {
    /// Creates an exactly Missing/Missing fresh-install backend.
    pub(in crate::key_agent_service) fn empty(
        installation: InstallationIdentity,
    ) -> Result<Self, RecoveryRequired> {
        Ok(Self {
            marker: None,
            checkpoint: None,
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

    /// Acquires the provisioning writer before capturing the exact initial
    /// Missing/Missing observation.
    pub(in crate::key_agent_service) fn begin_initial_provisioning<'provider>(
        &mut self,
        provider: &'provider RunStateAuthenticationProvider,
        installation: InstallationIdentity,
    ) -> Result<UnprovisionedWithWriter<'provider>, InitialProvisioningStartFailure<'provider>>
    {
        if installation != self.installation || installation != provider.installation() {
            return Err(InitialProvisioningStartFailure::BeforeWriter(
                RecoveryRequired::InstallationIdentityMismatch,
            ));
        }
        if self.held_writer.is_some() {
            return Err(InitialProvisioningStartFailure::BeforeWriter(
                RecoveryRequired::WriterLeaseUnavailable,
            ));
        }
        if self.release_reconciliation.is_some() {
            return Err(InitialProvisioningStartFailure::BeforeWriter(
                RecoveryRequired::WriterReleaseReconciliationRequired,
            ));
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(InitialProvisioningStartFailure::BeforeWriter(
                RecoveryRequired::CommitReloadRequired,
            ));
        }
        let Some(epoch) = self
            .last_writer_epoch
            .checked_add(1)
            .and_then(NonZeroU64::new)
        else {
            return Err(InitialProvisioningStartFailure::BeforeWriter(
                RecoveryRequired::WriterLeaseUnavailable,
            ));
        };
        let Some(attempt) = self
            .last_provisioning_attempt
            .checked_add(1)
            .and_then(NonZeroU64::new)
        else {
            return Err(InitialProvisioningStartFailure::BeforeWriter(
                RecoveryRequired::ProvisioningAttemptExhausted,
            ));
        };
        self.last_writer_epoch = epoch.get();
        self.last_provisioning_attempt = attempt.get();
        self.provisioning_reload_round = NonZeroU64::MIN.get();
        self.held_writer = Some(FixtureWriterRecord::provisioning(
            installation,
            epoch,
            attempt,
        ));
        let authority = FreshInstallProvisioningAuthority {
            provider,
            provider_identity: provider.identity(),
            installation,
            binding: self.binding,
            attempt,
        };
        let lease = ProvisioningWriterLease {
            installation,
            epoch,
            binding: self.binding,
            attempt,
        };
        let observed = SnapshotObservation::capture(self.marker_bytes(), self.checkpoint_bytes());
        if !observation_is_exactly_empty(&observed) {
            return Err(InitialProvisioningStartFailure::WithWriter(
                ProvisioningFailureWithWriter::new(
                    classify_initial_observation(&observed),
                    authority,
                    lease,
                    NonZeroU64::MIN,
                ),
            ));
        }
        Ok(UnprovisionedWithWriter {
            authority,
            lease,
            reload_round: NonZeroU64::MIN,
        })
    }

    fn expected_provisioning_writer(
        &self,
        transition: &PreparedInitialCleanTransition<'_>,
    ) -> Result<FixtureWriterRecord, RecoveryRequired> {
        validate_authority_and_lease(&transition.authority, &transition.lease)?;
        if transition.authority.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch);
        }
        if transition.reload_round.get() != self.provisioning_reload_round {
            return Err(RecoveryRequired::ProvisioningReloadRoundMismatch);
        }
        Ok(FixtureWriterRecord::provisioning(
            transition.lease.installation,
            transition.lease.epoch,
            transition.lease.attempt,
        ))
    }

    /// Commits the exact initial Clean pair with Missing/Missing CAS semantics.
    pub(in crate::key_agent_service) fn commit_initial_clean(
        &mut self,
        transition: &PreparedInitialCleanTransition<'_>,
    ) -> Result<CommittedInitialCleanMarker, DurableRunStateCommitFailure> {
        let expected = self.expected_provisioning_writer(transition)?;
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch.into());
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(RecoveryRequired::CommitReloadRequired.into());
        }
        transition.operation.begin_commit()?;
        if self.marker.is_some() || self.checkpoint.is_some() {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::terminal_provisioning(
                expected,
                transition.reload_round,
            ));
            return Err(RecoveryRequired::CompareAndSwapConflict.into());
        }
        let fault = self.take_commit_fault();
        if fault == DurableRunStateCommitFault::CompareAndSwapConflict {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::terminal_provisioning(
                expected,
                transition.reload_round,
            ));
            return Err(RecoveryRequired::CompareAndSwapConflict.into());
        }
        if fault == DurableRunStateCommitFault::AmbiguousBeforeWrite {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::provisioning(
                expected,
                transition.reload_round,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        self.marker = Some(transition.candidate.bytes.marker);
        if fault == DurableRunStateCommitFault::AmbiguousAfterMarker {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::provisioning(
                expected,
                transition.reload_round,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        self.checkpoint = Some(transition.candidate.bytes.checkpoint);
        if fault == DurableRunStateCommitFault::AmbiguousAfterCheckpoint {
            self.unresolved_commit_ambiguity = Some(FixtureCommitAmbiguity::provisioning(
                expected,
                transition.reload_round,
            ));
            return Err(DurableRunStateCommitFailure::Ambiguous);
        }
        transition.operation.record_commit_receipt()?;
        Ok(CommittedInitialCleanMarker {
            observed: SnapshotObservation::capture(self.marker_bytes(), self.checkpoint_bytes()),
            proof: ProvisioningOperationBinding::from_authority_and_lease(
                &transition.authority,
                &transition.lease,
                transition.reload_round,
            ),
        })
    }

    /// Captures a separately typed post-commit initial Clean readback.
    pub(in crate::key_agent_service) fn reread_initial_clean(
        &mut self,
        transition: &PreparedInitialCleanTransition<'_>,
    ) -> Result<RereadInitialCleanMarker, RecoveryRequired> {
        let expected = self.expected_provisioning_writer(transition)?;
        if self.held_writer != Some(expected) {
            return Err(RecoveryRequired::WriterLeaseMismatch);
        }
        if self.unresolved_commit_ambiguity.is_some() {
            return Err(RecoveryRequired::CommitReloadRequired);
        }
        transition.operation.begin_reread()?;
        let fault = self.take_reread_fault();
        let marker = match fault {
            DurableRunStateRereadFault::MissingMarker | DurableRunStateRereadFault::MarkerDrift => {
                None
            }
            DurableRunStateRereadFault::None | DurableRunStateRereadFault::CheckpointDrift => {
                self.marker_bytes()
            }
        };
        let checkpoint = match fault {
            DurableRunStateRereadFault::CheckpointDrift => None,
            DurableRunStateRereadFault::None
            | DurableRunStateRereadFault::MissingMarker
            | DurableRunStateRereadFault::MarkerDrift => self.checkpoint_bytes(),
        };
        Ok(RereadInitialCleanMarker {
            observed: SnapshotObservation::capture(marker, checkpoint),
            proof: ProvisioningOperationBinding::from_authority_and_lease(
                &transition.authority,
                &transition.lease,
                transition.reload_round,
            ),
        })
    }

    /// Captures one fresh ambiguity reload and advances the backend round once.
    pub(in crate::key_agent_service) fn reload_initial_clean(
        &mut self,
        pending: &InitialCleanReloadRequired<'_>,
    ) -> Result<InitialCleanReloadReceipt, RecoveryRequired> {
        validate_authority_and_lease(&pending.authority, &pending.lease)?;
        if pending.authority.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch);
        }
        let expected_writer = FixtureWriterRecord::provisioning(
            pending.lease.installation,
            pending.lease.epoch,
            pending.lease.attempt,
        );
        if self.held_writer != Some(expected_writer) {
            return Err(RecoveryRequired::WriterLeaseMismatch);
        }
        if pending.operation.has_exact_receipt() {
            return Err(RecoveryRequired::OperationAttemptReused);
        }
        let current_round = NonZeroU64::new(self.provisioning_reload_round)
            .ok_or(RecoveryRequired::ProvisioningReloadRoundMismatch)?;
        if pending.prior_round != current_round {
            return Err(RecoveryRequired::ProvisioningReloadRoundMismatch);
        }
        if self.unresolved_commit_ambiguity
            != Some(FixtureCommitAmbiguity::provisioning(
                expected_writer,
                current_round,
            ))
        {
            return Err(RecoveryRequired::CommitReloadRequired);
        }
        let next_round = self
            .provisioning_reload_round
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(RecoveryRequired::ProvisioningReloadRoundExhausted)?;
        if pending.reload_round != next_round {
            return Err(RecoveryRequired::ProvisioningReloadRoundMismatch);
        }
        pending.operation.record_reload_receipt()?;
        self.provisioning_reload_round = next_round.get();
        let receipt = InitialCleanReloadReceipt {
            observed: SnapshotObservation::capture(self.marker_bytes(), self.checkpoint_bytes()),
            writer: ProvisioningWriterObservation::Held {
                installation: pending.lease.installation,
                epoch: pending.lease.epoch,
                attempt: pending.lease.attempt,
            },
            proof: ProvisioningOperationBinding::from_authority_and_lease(
                &pending.authority,
                &pending.lease,
                next_round,
            ),
        };
        self.unresolved_commit_ambiguity = None;
        Ok(receipt)
    }

    /// Releases only the exact provisioning-role writer after initial Clean
    /// commit and readback.
    pub(in crate::key_agent_service) fn release_provisioning_writer(
        &mut self,
        pending: &PendingProvisioningWriterRelease<'_>,
    ) -> Result<ProvisioningWriterReleaseReceipt, DurableRunStateReleaseFailure> {
        validate_authority_and_lease(&pending.authority, &pending.lease)?;
        if pending.authority.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch.into());
        }
        if pending.reload_round.get() != self.provisioning_reload_round {
            return Err(RecoveryRequired::ProvisioningReloadRoundMismatch.into());
        }
        let expected = FixtureWriterRecord::provisioning(
            pending.lease.installation,
            pending.lease.epoch,
            pending.lease.attempt,
        );
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
            if pending.lease.epoch == NonZeroU64::MIN {
                NonZeroU64::new(2).ok_or(RecoveryRequired::WriterLeaseMismatch)?
            } else {
                NonZeroU64::MIN
            }
        } else {
            pending.lease.epoch
        };
        if fault == DurableRunStateReleaseFault::MismatchedReceiptAfterRelease {
            self.release_reconciliation = Some(expected.epoch);
        }
        pending.operation.record_release_receipt()?;
        Ok(ProvisioningWriterReleaseReceipt {
            proof: ProvisioningOperationBinding {
                installation: pending.authority.installation,
                writer_epoch: receipt_epoch,
                backend: self.binding,
                authority_attempt: pending.authority.attempt,
                reload_round: pending.reload_round,
            },
        })
    }

    /// Retires or reconciles only the exact provisioning writer for terminal
    /// process exit.
    pub(in crate::key_agent_service) fn retire_provisioning_writer_for_exit(
        &mut self,
        pending: &ProvisioningWriterExitPending<'_>,
    ) -> Result<ProvisioningWriterExitReceipt, RecoveryRequired> {
        validate_authority_and_lease(&pending.authority, &pending.lease)?;
        if pending.authority.binding != self.binding {
            return Err(RecoveryRequired::BackendBindingMismatch);
        }
        let expected = FixtureWriterRecord::provisioning(
            pending.lease.installation,
            pending.lease.epoch,
            pending.lease.attempt,
        );
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
        if let Some(ambiguity) = self.unresolved_commit_ambiguity {
            let current_round = ambiguity
                .provisioning_round
                .ok_or(RecoveryRequired::ProvisioningReloadRoundMismatch)?;
            if pending.reload_round != current_round {
                return Err(RecoveryRequired::ProvisioningReloadRoundMismatch);
            }
        } else if pending.reload_round.get() != self.provisioning_reload_round {
            return Err(RecoveryRequired::ProvisioningReloadRoundMismatch);
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
        Ok(ProvisioningWriterExitReceipt {
            proof: ProvisioningOperationBinding::from_authority_and_lease(
                &pending.authority,
                &pending.lease,
                pending.reload_round,
            ),
        })
    }

    /// Test-only role observation used to prove runtime/provisioning exclusion.
    pub(super) fn held_writer_role(&self) -> Option<FixtureWriterRole> {
        self.held_writer.map(|writer| writer.role)
    }
}

#[cfg(test)]
impl CommittedInitialCleanMarker {
    pub(super) fn with_installation_for_fixture_test(
        mut self,
        installation: InstallationIdentity,
    ) -> Self {
        self.proof.installation = installation;
        self
    }

    pub(super) fn with_writer_epoch_for_fixture_test(mut self, epoch: NonZeroU64) -> Self {
        self.proof.writer_epoch = epoch;
        self
    }

    pub(super) fn with_attempt_for_fixture_test(mut self, attempt: NonZeroU64) -> Self {
        self.proof.authority_attempt = attempt;
        self
    }

    pub(super) fn with_round_for_fixture_test(mut self, round: NonZeroU64) -> Self {
        self.proof.reload_round = round;
        self
    }
}

#[cfg(test)]
impl InitialCleanReloadReceipt {
    pub(super) fn with_round_for_fixture_test(mut self, round: NonZeroU64) -> Self {
        self.proof.reload_round = round;
        self
    }
}

#[cfg(test)]
impl ProvisioningWriterExitReceipt {
    pub(super) fn with_round_for_fixture_test(mut self, round: NonZeroU64) -> Self {
        self.proof.reload_round = round;
        self
    }
}

#[cfg(test)]
impl UnprovisionedWithWriter<'_> {
    pub(super) fn with_round_for_fixture_test(mut self, round: NonZeroU64) -> Self {
        self.reload_round = round;
        self
    }
}
