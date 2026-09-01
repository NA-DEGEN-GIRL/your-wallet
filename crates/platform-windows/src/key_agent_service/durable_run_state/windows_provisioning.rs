//! Dormant Windows composition for fresh-install generation-one provisioning.
//!
//! A caller must already hold the fixed run-state writer and separately own a
//! fresh-install authority. This module has no production authority constructor
//! or caller. Its move-only states bind the logical provisioning protocol to
//! one independently observed Windows marker/checkpoint pair until verified
//! release or checked terminal retirement consumes both halves.

use core::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::super::run_state_root::{HeldServiceRunStateWriter, ServiceRunStateError};
use super::super::windows_pair::{
    ExpectedWindowsPair, WindowsCommittedPair, WindowsObservedPair, WindowsPairCommitOutcome,
    WindowsPairExpectationMismatch, WindowsPairKnownFailure, WindowsPairReleaseAfterWriter,
    WindowsPairReleaseFailure, WindowsPairReleaseWithWriter, WindowsPairReleased,
    WindowsPairReloadFailure, WindowsPairReloadRequired, WindowsPairRetired, WindowsPairWriter,
    WindowsPreparedPairCommit, WindowsReloadedPair, WindowsRereadPair,
};
use super::super::{InstallationIdentity, RecoveryRequired, RunStateAuthenticationProvider};
use super::{
    BackendBinding, CommittedInitialCleanMarker, FreshInstallProvisioningAuthority,
    InitialCleanCommittedWithWriter, InitialCleanReloadReceipt, InitialCleanReloadRequired,
    PendingProvisioningWriterRelease, PreparedInitialCleanTransition, ProvisionedRunState,
    ProvisioningFailureWithWriter, ProvisioningOperationBinding, ProvisioningRecoveryExitEvidence,
    ProvisioningWriterExitPending, ProvisioningWriterExitReceipt, ProvisioningWriterLease,
    ProvisioningWriterObservation, ProvisioningWriterReleaseReceipt, ReloadedInitialCleanState,
    RereadInitialCleanMarker, RunStateProviderIdentity, UnprovisionedWithWriter,
    classify_initial_observation, observation_is_exactly_empty,
};

static NEXT_WINDOWS_PROVISIONING_BINDING: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
static NEXT_WINDOWS_PROVISIONING_ATTEMPT: AtomicU64 = AtomicU64::new(1_u64 << 63);

#[cfg(test)]
std::thread_local! {
    static POST_RELEASE_PROVISIONING_RECEIPT_FAULT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
struct PostReleaseProvisioningReceiptFaultGuard;

#[cfg(test)]
impl PostReleaseProvisioningReceiptFaultGuard {
    fn arm() -> Self {
        POST_RELEASE_PROVISIONING_RECEIPT_FAULT.with(|fault| fault.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for PostReleaseProvisioningReceiptFaultGuard {
    fn drop(&mut self) {
        POST_RELEASE_PROVISIONING_RECEIPT_FAULT.with(|fault| fault.set(false));
    }
}

#[cfg(test)]
fn take_post_release_provisioning_receipt_fault() -> bool {
    POST_RELEASE_PROVISIONING_RECEIPT_FAULT.with(|fault| fault.replace(false))
}

fn allocate_windows_provisioning_value() -> Result<NonZeroU64, RecoveryRequired> {
    let value = NEXT_WINDOWS_PROVISIONING_BINDING
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| RecoveryRequired::BackendBindingExhausted)?;
    NonZeroU64::new(value).ok_or(RecoveryRequired::BackendBindingExhausted)
}

const fn backend_reason(cause: ServiceRunStateError) -> RecoveryRequired {
    match cause {
        ServiceRunStateError::Compare => RecoveryRequired::CompareAndSwapConflict,
        _ => RecoveryRequired::WindowsBackendFailure,
    }
}

/// Move-only installer grant sealed to one exact provider identity.
///
/// Production code can name and consume the grant, but this module deliberately
/// provides no production constructor.
#[must_use = "the installer provisioning grant must be bound or retained"]
pub(in crate::key_agent_service) struct WindowsInstallerProvisioningGrant {
    expected_provider: RunStateProviderIdentity,
    attempt: NonZeroU64,
    _sealed: (),
}

#[cfg(test)]
impl WindowsInstallerProvisioningGrant {
    /// Seals one bounded current-user fixture attempt to the exact provider.
    pub(in crate::key_agent_service) fn for_current_user_fixture(
        provider: &RunStateAuthenticationProvider,
    ) -> Result<Self, RecoveryRequired> {
        let value = NEXT_WINDOWS_PROVISIONING_ATTEMPT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| RecoveryRequired::ProvisioningAttemptExhausted)?;
        let attempt =
            NonZeroU64::new(value).ok_or(RecoveryRequired::ProvisioningAttemptExhausted)?;
        Ok(Self {
            expected_provider: provider.identity(),
            attempt,
            _sealed: (),
        })
    }
}

impl fmt::Debug for WindowsInstallerProvisioningGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsInstallerProvisioningGrant([REDACTED])")
    }
}

/// Exact provider/grant binding failure retaining the consumed installer grant.
#[must_use = "a rejected installer grant must be retained or rebound"]
pub(in crate::key_agent_service) struct WindowsFreshInstallAuthorityBindingFailure {
    reason: RecoveryRequired,
    grant: WindowsInstallerProvisioningGrant,
}

impl WindowsFreshInstallAuthorityBindingFailure {
    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    pub(in crate::key_agent_service) fn into_grant(self) -> WindowsInstallerProvisioningGrant {
        self.grant
    }
}

impl fmt::Debug for WindowsFreshInstallAuthorityBindingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsFreshInstallAuthorityBindingFailure")
            .field("reason", &self.reason)
            .field("grant", &"[REDACTED]")
            .finish()
    }
}

/// Binds one sealed installer grant to its exact provider.
#[allow(clippy::result_large_err)] // Failure retains the move-only grant inline.
pub(in crate::key_agent_service) fn bind_windows_fresh_install_authority(
    provider: &RunStateAuthenticationProvider,
    grant: WindowsInstallerProvisioningGrant,
) -> Result<WindowsFreshInstallAuthority<'_>, WindowsFreshInstallAuthorityBindingFailure> {
    if grant.expected_provider != provider.identity() {
        return Err(WindowsFreshInstallAuthorityBindingFailure {
            reason: RecoveryRequired::AuthenticationFailed,
            grant,
        });
    }
    Ok(WindowsFreshInstallAuthority {
        installation: provider.installation(),
        provider,
        provider_identity: grant.expected_provider,
        attempt: grant.attempt,
        _sealed: (),
    })
}

/// Move-only fresh-install authority. Only exact grant binding can construct it.
#[must_use = "fresh-install authority must be consumed by Windows provisioning"]
pub(in crate::key_agent_service) struct WindowsFreshInstallAuthority<'provider> {
    installation: InstallationIdentity,
    provider: &'provider RunStateAuthenticationProvider,
    provider_identity: RunStateProviderIdentity,
    attempt: NonZeroU64,
    _sealed: (),
}

impl fmt::Debug for WindowsFreshInstallAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsFreshInstallAuthority([REDACTED])")
    }
}

/// Begins fresh-install provisioning from an already-held OS writer. The
/// private logical binding is allocated only after the caller transfers that
/// writer, and pair bytes are freshly observed before Missing/Missing is
/// admitted.
#[allow(clippy::large_types_passed_by_value)] // Transfers both move-only authorities.
#[allow(clippy::result_large_err)] // Failure retains terminal writer authority inline.
pub(in crate::key_agent_service) fn start_windows_initial_provisioning(
    writer: HeldServiceRunStateWriter,
    authority: WindowsFreshInstallAuthority<'_>,
) -> Result<WindowsUnprovisionedWithWriter<'_>, WindowsInitialProvisioningStartFailure<'_>> {
    let acquired = WindowsProvisioningWriterAcquired::from_held_writer(writer, authority)
        .map_err(WindowsInitialProvisioningStartFailure::Binding)?;
    acquired
        .observe_empty()
        .map_err(WindowsInitialProvisioningStartFailure::Terminal)
}

/// Start failure split by whether the private logical binding was allocated.
#[must_use = "a failed Windows provisioning start must be terminally retired"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(in crate::key_agent_service) enum WindowsInitialProvisioningStartFailure<'provider> {
    Binding(WindowsProvisioningBindingFailure<'provider>),
    Terminal(WindowsProvisioningTerminalFailure<'provider>),
}

impl WindowsInitialProvisioningStartFailure<'_> {
    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        match self {
            Self::Binding(failure) => failure.reason(),
            Self::Terminal(failure) => failure.reason(),
        }
    }
}

impl fmt::Debug for WindowsInitialProvisioningStartFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsInitialProvisioningStartFailure")
            .field("reason", &self.reason())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Binding allocation failed after the OS writer was transferred. No logical
/// authority exists, so only direct pair retirement remains.
#[must_use = "the unbound provisioning writer must be retired"]
pub(in crate::key_agent_service) struct WindowsProvisioningBindingFailure<'provider> {
    reason: RecoveryRequired,
    pair: WindowsPairWriter,
    authority: WindowsFreshInstallAuthority<'provider>,
}

impl<'provider> WindowsProvisioningBindingFailure<'provider> {
    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    pub(in crate::key_agent_service) fn retire(
        self,
    ) -> Result<
        WindowsProvisioningUnboundRetired<'provider>,
        WindowsProvisioningUnboundRetirementFailure<'provider>,
    > {
        let Self {
            pair, authority, ..
        } = self;
        match pair.retire() {
            Ok(pair) => Ok(WindowsProvisioningUnboundRetired {
                _pair: pair,
                _authority: authority,
            }),
            Err(cause) => Err(WindowsProvisioningUnboundRetirementFailure {
                cause,
                _authority: authority,
            }),
        }
    }
}

impl fmt::Debug for WindowsProvisioningBindingFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsProvisioningBindingFailure")
            .field("reason", &self.reason)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Terminal receipt for an unbound writer retirement.
pub(in crate::key_agent_service) struct WindowsProvisioningUnboundRetired<'provider> {
    _pair: WindowsPairRetired,
    _authority: WindowsFreshInstallAuthority<'provider>,
}

impl fmt::Debug for WindowsProvisioningUnboundRetired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsProvisioningUnboundRetired")
    }
}

/// Terminal backend failure that still retains the fresh-install authority.
#[must_use = "failed unbound retirement retains fresh-install authority"]
pub(in crate::key_agent_service) struct WindowsProvisioningUnboundRetirementFailure<'provider> {
    cause: ServiceRunStateError,
    _authority: WindowsFreshInstallAuthority<'provider>,
}

impl WindowsProvisioningUnboundRetirementFailure<'_> {
    pub(in crate::key_agent_service) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }
}

impl fmt::Debug for WindowsProvisioningUnboundRetirementFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsProvisioningUnboundRetirementFailure")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for WindowsProvisioningUnboundRetirementFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unbound provisioning writer retirement failed: {}",
            self.cause
        )
    }
}

impl std::error::Error for WindowsProvisioningUnboundRetirementFailure<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Writer-first internal state before the required fresh pair observation.
#[must_use = "the acquired provisioning writer must observe or retire"]
struct WindowsProvisioningWriterAcquired<'provider> {
    authority: FreshInstallProvisioningAuthority<'provider>,
    lease: ProvisioningWriterLease,
    pair: WindowsPairWriter,
}

impl<'provider> WindowsProvisioningWriterAcquired<'provider> {
    #[allow(clippy::large_types_passed_by_value)]
    #[allow(clippy::result_large_err)]
    #[allow(clippy::needless_pass_by_value)] // Consumes the move-only fresh-install capability.
    fn from_held_writer(
        writer: HeldServiceRunStateWriter,
        authority: WindowsFreshInstallAuthority<'provider>,
    ) -> Result<Self, WindowsProvisioningBindingFailure<'provider>> {
        let pair = WindowsPairWriter::from_held_writer(writer);
        let attempt = authority.attempt;
        let binding = loop {
            match allocate_windows_provisioning_value() {
                Ok(binding) if binding != attempt => break binding,
                Ok(_) => {}
                Err(reason) => {
                    return Err(WindowsProvisioningBindingFailure {
                        reason,
                        pair,
                        authority,
                    });
                }
            }
        };
        let epoch = loop {
            match allocate_windows_provisioning_value() {
                Ok(epoch) if epoch != attempt && epoch != binding => break epoch,
                Ok(_) => {}
                Err(reason) => {
                    return Err(WindowsProvisioningBindingFailure {
                        reason,
                        pair,
                        authority,
                    });
                }
            }
        };
        let WindowsFreshInstallAuthority {
            installation,
            provider,
            provider_identity,
            attempt,
            ..
        } = authority;
        let backend = BackendBinding(binding);
        Ok(Self {
            authority: FreshInstallProvisioningAuthority {
                provider,
                provider_identity,
                installation,
                binding: backend,
                attempt,
            },
            lease: ProvisioningWriterLease {
                installation,
                epoch,
                binding: backend,
                attempt,
            },
            pair,
        })
    }

    #[allow(clippy::result_large_err)]
    fn observe_empty(
        self,
    ) -> Result<
        WindowsUnprovisionedWithWriter<'provider>,
        WindowsProvisioningTerminalFailure<'provider>,
    > {
        let Self {
            authority,
            lease,
            pair,
        } = self;
        let pair = match pair.observe() {
            Ok(pair) => pair,
            Err(pair) => {
                let cause = pair.cause();
                return Err(WindowsProvisioningTerminalFailure::new(
                    backend_reason(cause),
                    Some(cause),
                    ProvisioningWriterExitPending::new(authority, lease, NonZeroU64::MIN),
                    WindowsProvisioningTerminalPair::Known(pair),
                ));
            }
        };
        let logical = UnprovisionedWithWriter {
            authority,
            lease,
            reload_round: NonZeroU64::MIN,
        };
        if !observation_is_exactly_empty(&pair.observation()) {
            let reason = classify_initial_observation(&pair.observation());
            return Err(WindowsProvisioningTerminalFailure::from_logical(
                logical.abort(reason),
                WindowsProvisioningTerminalPair::Observed(pair),
            ));
        }
        Ok(WindowsUnprovisionedWithWriter { logical, pair })
    }

    fn into_retirement(self) -> WindowsProvisioningRetirementPending<'provider> {
        let Self {
            authority,
            lease,
            pair,
        } = self;
        WindowsProvisioningRetirementPending::new(
            ProvisioningWriterExitPending::new(authority, lease, NonZeroU64::MIN),
            WindowsProvisioningTerminalPair::Writer(pair),
        )
    }
}

impl fmt::Debug for WindowsProvisioningWriterAcquired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsProvisioningWriterAcquired([REDACTED])")
    }
}

/// Exact Missing/Missing observation bound to the provisioning writer.
#[must_use = "the unprovisioned writer must prepare Clean or retire"]
pub(in crate::key_agent_service) struct WindowsUnprovisionedWithWriter<'provider> {
    logical: UnprovisionedWithWriter<'provider>,
    pair: WindowsObservedPair,
}

impl<'provider> WindowsUnprovisionedWithWriter<'provider> {
    #[allow(clippy::result_large_err)]
    pub(in crate::key_agent_service) fn prepare_initial_clean(
        self,
    ) -> Result<
        WindowsPreparedInitialCleanTransition<'provider>,
        WindowsProvisioningTerminalFailure<'provider>,
    > {
        let Self { logical, pair } = self;
        let logical = match logical.prepare_initial_clean() {
            Ok(logical) => logical,
            Err(failure) => {
                return Err(WindowsProvisioningTerminalFailure::from_logical(
                    failure,
                    WindowsProvisioningTerminalPair::Observed(pair),
                ));
            }
        };
        let candidate = logical.candidate.bytes;
        let pair = match pair.prepare_commit(ExpectedWindowsPair::missing(), candidate) {
            Ok(pair) => pair,
            Err(pair) => {
                return Err(WindowsProvisioningTerminalFailure::from_logical(
                    logical.abort(RecoveryRequired::CompareAndSwapConflict),
                    WindowsProvisioningTerminalPair::ExpectationMismatch(pair),
                ));
            }
        };
        Ok(WindowsPreparedInitialCleanTransition { logical, pair })
    }

    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsProvisioningRetirementPending<'provider> {
        WindowsProvisioningRetirementPending::new(
            self.logical.into_writer_exit(),
            WindowsProvisioningTerminalPair::Observed(self.pair),
        )
    }
}

impl fmt::Debug for WindowsUnprovisionedWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsUnprovisionedWithWriter([REDACTED])")
    }
}

/// Canonical Clean/generation-one candidate awaiting one pair commit.
#[must_use = "the prepared initial Clean transition must commit or retire"]
pub(in crate::key_agent_service) struct WindowsPreparedInitialCleanTransition<'provider> {
    logical: PreparedInitialCleanTransition<'provider>,
    pair: WindowsPreparedPairCommit,
}

impl<'provider> WindowsPreparedInitialCleanTransition<'provider> {
    pub(in crate::key_agent_service) fn commit_and_reread(
        self,
    ) -> WindowsInitialCleanCommitOutcome<'provider> {
        let Self { logical, pair } = self;
        if let Err(reason) = logical.operation.begin_commit() {
            return WindowsInitialCleanCommitOutcome::Terminal(
                WindowsProvisioningTerminalFailure::from_logical(
                    logical.abort(reason),
                    WindowsProvisioningTerminalPair::Prepared(pair),
                ),
            );
        }
        match pair.commit() {
            WindowsPairCommitOutcome::KnownNotCommitted(pair) => {
                let cause = pair.cause();
                WindowsInitialCleanCommitOutcome::Terminal(WindowsProvisioningTerminalFailure::new(
                    backend_reason(cause),
                    Some(cause),
                    logical.abort(backend_reason(cause)).into_writer_exit(),
                    WindowsProvisioningTerminalPair::Known(pair),
                ))
            }
            WindowsPairCommitOutcome::Ambiguous(pair) => match logical.commit_ambiguous() {
                Ok(logical) => WindowsInitialCleanCommitOutcome::ReloadRequired(
                    WindowsInitialCleanReloadRequired { logical, pair },
                ),
                Err(failure) => WindowsInitialCleanCommitOutcome::Terminal(
                    WindowsProvisioningTerminalFailure::from_logical(
                        failure,
                        WindowsProvisioningTerminalPair::Ambiguous(pair),
                    ),
                ),
            },
            WindowsPairCommitOutcome::Committed(pair) => {
                complete_initial_clean_commit(logical, pair)
            }
        }
    }

    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsProvisioningRetirementPending<'provider> {
        WindowsProvisioningRetirementPending::new(
            self.logical.into_writer_exit(),
            WindowsProvisioningTerminalPair::Prepared(self.pair),
        )
    }
}

fn complete_initial_clean_commit(
    logical: PreparedInitialCleanTransition<'_>,
    pair: WindowsCommittedPair,
) -> WindowsInitialCleanCommitOutcome<'_> {
    let committed_observation = pair.candidate().observation();
    if let Err(reason) = logical.operation.record_commit_receipt() {
        return WindowsInitialCleanCommitOutcome::Terminal(
            WindowsProvisioningTerminalFailure::from_logical(
                logical.abort(reason),
                WindowsProvisioningTerminalPair::Committed(pair),
            ),
        );
    }
    let proof = ProvisioningOperationBinding::from_authority_and_lease(
        &logical.authority,
        &logical.lease,
        logical.reload_round,
    );
    let committed = CommittedInitialCleanMarker {
        observed: committed_observation,
        proof,
    };
    if let Err(reason) = logical.operation.begin_reread() {
        return WindowsInitialCleanCommitOutcome::Terminal(
            WindowsProvisioningTerminalFailure::from_logical(
                logical.abort(reason),
                WindowsProvisioningTerminalPair::Committed(pair),
            ),
        );
    }
    let pair = match pair.reread() {
        Ok(pair) => pair,
        Err(pair) => {
            let cause = pair.cause();
            return WindowsInitialCleanCommitOutcome::Terminal(
                WindowsProvisioningTerminalFailure::new(
                    RecoveryRequired::RereadDrift,
                    Some(cause),
                    logical
                        .abort(RecoveryRequired::RereadDrift)
                        .into_writer_exit(),
                    WindowsProvisioningTerminalPair::Ambiguous(pair),
                ),
            );
        }
    };
    let reread = RereadInitialCleanMarker {
        observed: pair.observation(),
        proof,
    };
    match logical.complete(committed, reread) {
        Ok(logical) => {
            WindowsInitialCleanCommitOutcome::Committed(WindowsInitialCleanCommittedWithWriter {
                logical,
                pair: pair.continue_observed(),
            })
        }
        Err(failure) => WindowsInitialCleanCommitOutcome::Terminal(
            WindowsProvisioningTerminalFailure::from_logical(
                failure,
                WindowsProvisioningTerminalPair::Reread(pair),
            ),
        ),
    }
}

impl fmt::Debug for WindowsPreparedInitialCleanTransition<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsPreparedInitialCleanTransition([REDACTED])")
    }
}

/// Complete consuming outcome of the initial pair commit and independent reread.
#[must_use = "the initial Clean outcome retains terminal authority"]
#[allow(clippy::large_enum_variant)]
pub(in crate::key_agent_service) enum WindowsInitialCleanCommitOutcome<'provider> {
    Committed(WindowsInitialCleanCommittedWithWriter<'provider>),
    ReloadRequired(WindowsInitialCleanReloadRequired<'provider>),
    Terminal(WindowsProvisioningTerminalFailure<'provider>),
}

/// Unresolved initial commit ambiguity. Only fresh reload or retirement is
/// available; confirmed-commit reread failures never enter this state.
#[must_use = "initial Clean ambiguity must reload or retire"]
pub(in crate::key_agent_service) struct WindowsInitialCleanReloadRequired<'provider> {
    logical: InitialCleanReloadRequired<'provider>,
    pair: WindowsPairReloadRequired,
}

impl<'provider> WindowsInitialCleanReloadRequired<'provider> {
    pub(in crate::key_agent_service) fn reload(
        self,
    ) -> WindowsInitialCleanReloadOutcome<'provider> {
        let Self { logical, pair } = self;
        let pair = match pair.reload() {
            Ok(pair) => pair,
            Err(pair) => {
                let cause = pair.cause();
                return WindowsInitialCleanReloadOutcome::Terminal(
                    WindowsProvisioningTerminalFailure::new(
                        backend_reason(cause),
                        Some(cause),
                        logical.abort(backend_reason(cause)).into_writer_exit(),
                        WindowsProvisioningTerminalPair::ReloadFailure(pair),
                    ),
                );
            }
        };
        if let Err(reason) = logical.operation.record_reload_receipt() {
            return WindowsInitialCleanReloadOutcome::Terminal(
                WindowsProvisioningTerminalFailure::from_logical(
                    logical.abort(reason),
                    WindowsProvisioningTerminalPair::Reloaded(pair),
                ),
            );
        }
        let receipt = InitialCleanReloadReceipt {
            observed: pair.observation(),
            writer: ProvisioningWriterObservation::Held {
                installation: logical.lease.installation,
                epoch: logical.lease.epoch,
                attempt: logical.lease.attempt,
            },
            proof: ProvisioningOperationBinding::from_authority_and_lease(
                &logical.authority,
                &logical.lease,
                logical.reload_round,
            ),
        };
        match logical.complete_reload(receipt) {
            Ok(ReloadedInitialCleanState::Retry(logical)) => {
                WindowsInitialCleanReloadOutcome::Retry(WindowsUnprovisionedWithWriter {
                    logical,
                    pair: pair.continue_observed(),
                })
            }
            Ok(ReloadedInitialCleanState::Committed(logical)) => {
                WindowsInitialCleanReloadOutcome::Committed(
                    WindowsInitialCleanCommittedWithWriter {
                        logical,
                        pair: pair.continue_observed(),
                    },
                )
            }
            Err(failure) => WindowsInitialCleanReloadOutcome::Terminal(
                WindowsProvisioningTerminalFailure::from_logical(
                    failure,
                    WindowsProvisioningTerminalPair::Reloaded(pair),
                ),
            ),
        }
    }

    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsProvisioningRetirementPending<'provider> {
        WindowsProvisioningRetirementPending::new(
            self.logical.into_writer_exit(),
            WindowsProvisioningTerminalPair::Ambiguous(self.pair),
        )
    }
}

impl fmt::Debug for WindowsInitialCleanReloadRequired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsInitialCleanReloadRequired([REDACTED])")
    }
}

/// Exact classification of one fresh ambiguity reload.
#[must_use = "the initial Clean reload outcome retains terminal authority"]
#[allow(clippy::large_enum_variant)]
pub(in crate::key_agent_service) enum WindowsInitialCleanReloadOutcome<'provider> {
    Retry(WindowsUnprovisionedWithWriter<'provider>),
    Committed(WindowsInitialCleanCommittedWithWriter<'provider>),
    Terminal(WindowsProvisioningTerminalFailure<'provider>),
}

/// Authenticated generation-one Clean state still holding the provisioning
/// writer and the independently reread pair identities.
#[must_use = "committed initial Clean must release or retire"]
pub(in crate::key_agent_service) struct WindowsInitialCleanCommittedWithWriter<'provider> {
    logical: InitialCleanCommittedWithWriter<'provider>,
    pair: WindowsObservedPair,
}

impl<'provider> WindowsInitialCleanCommittedWithWriter<'provider> {
    pub(in crate::key_agent_service) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }

    pub(in crate::key_agent_service) fn release(
        self,
    ) -> WindowsProvisioningReleaseOutcome<'provider> {
        self.release_inner()
    }

    #[cfg(test)]
    pub(in crate::key_agent_service) fn release_with_post_release_fault_for_test(
        self,
    ) -> WindowsProvisioningReleaseOutcome<'provider> {
        let _fault = PostReleaseProvisioningReceiptFaultGuard::arm();
        self.release_inner()
    }

    fn release_inner(self) -> WindowsProvisioningReleaseOutcome<'provider> {
        let Self { logical, pair } = self;
        if pair.observation() != logical.durable.bytes.observation() {
            return WindowsProvisioningReleaseOutcome::Terminal(
                WindowsProvisioningTerminalFailure::from_logical(
                    logical.abort(RecoveryRequired::CompareAndSwapConflict),
                    WindowsProvisioningTerminalPair::Observed(pair),
                ),
            );
        }
        let logical = logical.prepare_writer_release();
        if let Err(reason) = logical.operation.begin_release() {
            return WindowsProvisioningReleaseOutcome::Terminal(
                WindowsProvisioningTerminalFailure::from_logical(
                    logical.abort(reason),
                    WindowsProvisioningTerminalPair::Observed(pair),
                ),
            );
        }
        match pair.release_verified() {
            Ok(pair) => complete_provisioning_release(logical, pair),
            Err(WindowsPairReleaseFailure::WriterRetained(pair)) => {
                let cause = pair.cause();
                WindowsProvisioningReleaseOutcome::Terminal(
                    WindowsProvisioningTerminalFailure::new(
                        RecoveryRequired::WriterReleaseAmbiguous,
                        Some(cause),
                        logical
                            .abort(RecoveryRequired::WriterReleaseAmbiguous)
                            .into_writer_exit(),
                        WindowsProvisioningTerminalPair::ReleaseWithWriter(pair),
                    ),
                )
            }
            Err(WindowsPairReleaseFailure::WriterReleasedNoReceipt(pair)) => {
                let cause = pair.cause();
                WindowsProvisioningReleaseOutcome::ReleasedNoReceipt(
                    WindowsProvisioningReleasedNoReceipt {
                        reason: RecoveryRequired::WriterReleaseAmbiguous,
                        cause,
                        _logical: logical.into_writer_exit(),
                        _pair: pair,
                    },
                )
            }
        }
    }

    pub(in crate::key_agent_service) fn into_retirement(
        self,
    ) -> WindowsProvisioningRetirementPending<'provider> {
        WindowsProvisioningRetirementPending::new(
            self.logical.into_writer_exit(),
            WindowsProvisioningTerminalPair::Observed(self.pair),
        )
    }
}

fn complete_provisioning_release(
    logical: PendingProvisioningWriterRelease<'_>,
    pair: WindowsPairReleased,
) -> WindowsProvisioningReleaseOutcome<'_> {
    if pair.pair() != logical.durable.bytes {
        return WindowsProvisioningReleaseOutcome::PostReleaseTerminal(
            WindowsPostReleaseProvisioningTerminal {
                reason: RecoveryRequired::WriterReleaseAmbiguous,
                _logical: logical.into_writer_exit(),
                _pair: pair,
            },
        );
    }
    #[cfg(test)]
    if take_post_release_provisioning_receipt_fault() {
        let _ = logical.operation.record_release_receipt();
    }
    if let Err(reason) = logical.operation.record_release_receipt() {
        return WindowsProvisioningReleaseOutcome::PostReleaseTerminal(
            WindowsPostReleaseProvisioningTerminal {
                reason,
                _logical: logical.into_writer_exit(),
                _pair: pair,
            },
        );
    }
    let receipt = ProvisioningWriterReleaseReceipt {
        proof: ProvisioningOperationBinding::from_authority_and_lease(
            &logical.authority,
            &logical.lease,
            logical.reload_round,
        ),
    };
    match logical.complete(receipt) {
        Ok(logical) => WindowsProvisioningReleaseOutcome::Provisioned(WindowsProvisionedRunState {
            logical,
            _pair: pair,
        }),
        Err(failure) => WindowsProvisioningReleaseOutcome::PostReleaseTerminal(
            WindowsPostReleaseProvisioningTerminal {
                reason: failure.reason(),
                _logical: failure.into_writer_exit(),
                _pair: pair,
            },
        ),
    }
}

impl fmt::Debug for WindowsInitialCleanCommittedWithWriter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsInitialCleanCommittedWithWriter([REDACTED])")
    }
}

/// Complete pair-bound provisioning release result. Only `Provisioned` is a
/// normal receipt; the other variants expose no reusable writer.
#[must_use = "the provisioning release outcome must be handled explicitly"]
#[allow(clippy::large_enum_variant)]
pub(in crate::key_agent_service) enum WindowsProvisioningReleaseOutcome<'provider> {
    Provisioned(WindowsProvisionedRunState<'provider>),
    Terminal(WindowsProvisioningTerminalFailure<'provider>),
    ReleasedNoReceipt(WindowsProvisioningReleasedNoReceipt<'provider>),
    PostReleaseTerminal(WindowsPostReleaseProvisioningTerminal<'provider>),
}

/// Opaque proof that Clean/generation-one provisioning and exact pair-bound
/// writer release completed. It exposes only generation and cannot become Boot
/// evidence or return a writer/handle.
#[must_use = "provisioned state is terminal evidence, not runtime authority"]
pub(in crate::key_agent_service) struct WindowsProvisionedRunState<'provider> {
    logical: ProvisionedRunState<'provider>,
    _pair: WindowsPairReleased,
}

impl WindowsProvisionedRunState<'_> {
    pub(in crate::key_agent_service) const fn generation(&self) -> NonZeroU64 {
        self.logical.generation()
    }
}

impl fmt::Debug for WindowsProvisionedRunState<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsProvisionedRunState([REDACTED])")
    }
}

/// Irreversible close ambiguity after the OS writer was released. No retry,
/// checked-retirement, or provisioned conversion exists.
#[must_use = "released-without-receipt is irreversible terminal evidence"]
pub(in crate::key_agent_service) struct WindowsProvisioningReleasedNoReceipt<'provider> {
    reason: RecoveryRequired,
    cause: ServiceRunStateError,
    _logical: ProvisioningWriterExitPending<'provider>,
    _pair: WindowsPairReleaseAfterWriter,
}

impl WindowsProvisioningReleasedNoReceipt<'_> {
    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }

    pub(in crate::key_agent_service) const fn cause(&self) -> ServiceRunStateError {
        self.cause
    }
}

impl fmt::Debug for WindowsProvisioningReleasedNoReceipt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsProvisioningReleasedNoReceipt")
            .field("reason", &self.reason)
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// The OS produced a checked pair receipt, but logical completion failed after
/// release. No writer or normal/retirement API remains.
#[must_use = "post-release provisioning failure is irreversible"]
pub(in crate::key_agent_service) struct WindowsPostReleaseProvisioningTerminal<'provider> {
    reason: RecoveryRequired,
    _logical: ProvisioningWriterExitPending<'provider>,
    _pair: WindowsPairReleased,
}

impl WindowsPostReleaseProvisioningTerminal<'_> {
    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        self.reason
    }
}

impl fmt::Debug for WindowsPostReleaseProvisioningTerminal<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPostReleaseProvisioningTerminal")
            .field("reason", &self.reason)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

enum WindowsProvisioningTerminalPair {
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

impl WindowsProvisioningTerminalPair {
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

/// Stable logical/platform cause detached from reason-neutral retirement.
#[must_use = "terminal cause must remain attached to its retirement result"]
pub(in crate::key_agent_service) struct WindowsProvisioningTerminalCause {
    recovery: RecoveryRequired,
    platform: Option<ServiceRunStateError>,
}

impl WindowsProvisioningTerminalCause {
    const fn new(recovery: RecoveryRequired, platform: Option<ServiceRunStateError>) -> Self {
        Self { recovery, platform }
    }

    pub(in crate::key_agent_service) const fn recovery(&self) -> RecoveryRequired {
        self.recovery
    }

    pub(in crate::key_agent_service) const fn platform(&self) -> Option<ServiceRunStateError> {
        self.platform
    }
}

impl fmt::Debug for WindowsProvisioningTerminalCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsProvisioningTerminalCause")
            .field("recovery", &self.recovery)
            .field("platform", &self.platform)
            .finish()
    }
}

/// Reason-neutral ownership of the logical writer exit and exact OS pair.
#[must_use = "provisioning retirement must be checked exactly once"]
pub(in crate::key_agent_service) struct WindowsProvisioningRetirementPending<'provider> {
    logical: ProvisioningWriterExitPending<'provider>,
    pair: WindowsProvisioningTerminalPair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsProvisioningRetirementStage {
    BeginRelease,
    PairRetire,
    RecordReceipt,
    LogicalComplete,
}

impl<'provider> WindowsProvisioningRetirementPending<'provider> {
    const fn new(
        logical: ProvisioningWriterExitPending<'provider>,
        pair: WindowsProvisioningTerminalPair,
    ) -> Self {
        Self { logical, pair }
    }

    /// Begins the logical release, retires the exact pair, records the logical
    /// receipt, and only then completes logical retirement.
    #[allow(clippy::result_large_err)]
    pub(in crate::key_agent_service) fn retire_checked(
        self,
    ) -> Result<
        WindowsProvisioningCheckedRetired<'provider>,
        WindowsProvisioningCheckedRetirementFailure<'provider>,
    > {
        let Self { logical, pair } = self;
        if logical.operation.begin_release().is_err() {
            let cause = pair.retire().err().unwrap_or(ServiceRunStateError::Release);
            return Err(WindowsProvisioningCheckedRetirementFailure::new(
                WindowsProvisioningRetirementStage::BeginRelease,
                cause,
                logical,
            ));
        }
        let pair = match pair.retire() {
            Ok(pair) => pair,
            Err(cause) => {
                return Err(WindowsProvisioningCheckedRetirementFailure::new(
                    WindowsProvisioningRetirementStage::PairRetire,
                    cause,
                    logical,
                ));
            }
        };
        if logical.operation.record_release_receipt().is_err() {
            return Err(WindowsProvisioningCheckedRetirementFailure::new(
                WindowsProvisioningRetirementStage::RecordReceipt,
                ServiceRunStateError::Release,
                logical,
            ));
        }
        let receipt = ProvisioningWriterExitReceipt {
            proof: ProvisioningOperationBinding::from_authority_and_lease(
                &logical.authority,
                &logical.lease,
                logical.reload_round,
            ),
        };
        match logical.complete(receipt) {
            Ok(logical) => Ok(WindowsProvisioningCheckedRetired {
                _logical: logical,
                _pair: pair,
            }),
            Err(failure) => Err(WindowsProvisioningCheckedRetirementFailure::new(
                WindowsProvisioningRetirementStage::LogicalComplete,
                ServiceRunStateError::Release,
                failure.into_writer_exit(),
            )),
        }
    }
}

impl fmt::Debug for WindowsProvisioningRetirementPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsProvisioningRetirementPending([REDACTED])")
    }
}

/// Exact reason-neutral checked retirement evidence. It has no normal
/// lifecycle conversion.
#[must_use = "checked provisioning retirement is terminal evidence"]
pub(in crate::key_agent_service) struct WindowsProvisioningCheckedRetired<'provider> {
    _logical: ProvisioningRecoveryExitEvidence<'provider>,
    _pair: WindowsPairRetired,
}

impl fmt::Debug for WindowsProvisioningCheckedRetired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsProvisioningCheckedRetired([REDACTED])")
    }
}

/// Irreversible checked-retirement failure. Pair authority was consumed, so no
/// retry or normal receipt can follow.
#[must_use = "checked-retirement failure is irreversible"]
pub(in crate::key_agent_service) struct WindowsProvisioningCheckedRetirementFailure<'provider> {
    stage: WindowsProvisioningRetirementStage,
    cause: ServiceRunStateError,
    _logical: ProvisioningWriterExitPending<'provider>,
}

impl<'provider> WindowsProvisioningCheckedRetirementFailure<'provider> {
    const fn new(
        stage: WindowsProvisioningRetirementStage,
        cause: ServiceRunStateError,
        logical: ProvisioningWriterExitPending<'provider>,
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

    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        match self.stage {
            WindowsProvisioningRetirementStage::LogicalComplete => {
                RecoveryRequired::OperationPhaseMismatch
            }
            WindowsProvisioningRetirementStage::BeginRelease
            | WindowsProvisioningRetirementStage::PairRetire
            | WindowsProvisioningRetirementStage::RecordReceipt => {
                RecoveryRequired::WindowsBackendFailure
            }
        }
    }
}

impl fmt::Debug for WindowsProvisioningCheckedRetirementFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsProvisioningCheckedRetirementFailure")
            .field("reason", &self.reason())
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Terminal cause paired with the sole reason-neutral checked-retirement seam.
#[must_use = "terminal provisioning failure must be explicitly retired"]
pub(in crate::key_agent_service) struct WindowsProvisioningTerminalFailure<'provider> {
    cause: WindowsProvisioningTerminalCause,
    retirement: WindowsProvisioningRetirementPending<'provider>,
}

impl<'provider> WindowsProvisioningTerminalFailure<'provider> {
    fn new(
        recovery: RecoveryRequired,
        platform: Option<ServiceRunStateError>,
        logical: ProvisioningWriterExitPending<'provider>,
        pair: WindowsProvisioningTerminalPair,
    ) -> Self {
        Self {
            cause: WindowsProvisioningTerminalCause::new(recovery, platform),
            retirement: WindowsProvisioningRetirementPending::new(logical, pair),
        }
    }

    fn from_logical(
        failure: ProvisioningFailureWithWriter<'provider>,
        pair: WindowsProvisioningTerminalPair,
    ) -> Self {
        let reason = failure.reason();
        Self::new(reason, None, failure.into_writer_exit(), pair)
    }

    pub(in crate::key_agent_service) const fn reason(&self) -> RecoveryRequired {
        self.cause.recovery()
    }

    pub(in crate::key_agent_service) const fn platform_cause(
        &self,
    ) -> Option<ServiceRunStateError> {
        self.cause.platform()
    }

    pub(in crate::key_agent_service) fn into_retirement_parts(
        self,
    ) -> (
        WindowsProvisioningTerminalCause,
        WindowsProvisioningRetirementPending<'provider>,
    ) {
        (self.cause, self.retirement)
    }
}

impl fmt::Debug for WindowsProvisioningTerminalFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsProvisioningTerminalFailure")
            .field("reason", &self.reason())
            .field("platform_cause", &self.platform_cause())
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::run_state_root::{
        ExactFixedRunStatePair, RuntimePairFault, RuntimePairFixture,
    };
    use super::super::super::windows_runtime::{
        WindowsRuntimeStartFailure, install_windows_runtime_clean_fixture, start_windows_runtime,
    };
    use super::super::super::{CanonicalSnapshot, Commitment, RunMarkerState, build_snapshot};
    use super::*;

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

    fn initial_snapshot(
        installation: InstallationIdentity,
        provider: &RunStateAuthenticationProvider,
    ) -> Result<CanonicalSnapshot, RecoveryRequired> {
        if installation != provider.installation() {
            return Err(RecoveryRequired::InstallationIdentityMismatch);
        }
        build_snapshot(
            RunMarkerState::Clean,
            NonZeroU64::MIN,
            Commitment::ZERO,
            provider,
        )
        .map(|durable| durable.bytes)
    }

    fn fixture_authority(
        installation: InstallationIdentity,
        provider: &RunStateAuthenticationProvider,
    ) -> Result<WindowsFreshInstallAuthority<'_>, RecoveryRequired> {
        if installation != provider.installation() {
            return Err(RecoveryRequired::InstallationIdentityMismatch);
        }
        let grant = WindowsInstallerProvisioningGrant::for_current_user_fixture(provider)?;
        bind_windows_fresh_install_authority(provider, grant).map_err(|failure| failure.reason())
    }

    fn retire_pending(pending: WindowsProvisioningRetirementPending<'_>) -> TestResult {
        pending
            .retire_checked()
            .map(|_retired| ())
            .map_err(|failure| {
                std::io::Error::other(format!(
                    "checked Windows provisioning retirement failed: {failure:?}"
                ))
                .into()
            })
    }

    fn retire_terminal(failure: WindowsProvisioningTerminalFailure<'_>) -> TestResult {
        let (_cause, pending) = failure.into_retirement_parts();
        retire_pending(pending)
    }

    fn start<'provider>(
        fixture: &RuntimePairFixture,
        installation: InstallationIdentity,
        provider: &'provider RunStateAuthenticationProvider,
    ) -> TestResultWith<WindowsUnprovisionedWithWriter<'provider>> {
        match start_windows_initial_provisioning(
            fixture.acquire_writer()?,
            fixture_authority(installation, provider)?,
        ) {
            Ok(unprovisioned) => Ok(unprovisioned),
            Err(WindowsInitialProvisioningStartFailure::Binding(failure)) => {
                let reason = failure.reason();
                let _retired = failure
                    .retire()
                    .map_err(|failure| std::io::Error::other(format!("{failure:?}")))?;
                Err(reason.into())
            }
            Err(WindowsInitialProvisioningStartFailure::Terminal(failure)) => {
                let reason = failure.reason();
                retire_terminal(failure)?;
                Err(reason.into())
            }
        }
    }

    fn prepare<'provider>(
        fixture: &RuntimePairFixture,
        installation: InstallationIdentity,
        provider: &'provider RunStateAuthenticationProvider,
    ) -> TestResultWith<WindowsPreparedInitialCleanTransition<'provider>> {
        match start(fixture, installation, provider)?.prepare_initial_clean() {
            Ok(prepared) => Ok(prepared),
            Err(failure) => {
                let reason = failure.reason();
                retire_terminal(failure)?;
                Err(reason.into())
            }
        }
    }

    fn exact_committed<'provider>(
        fixture: &RuntimePairFixture,
        installation: InstallationIdentity,
        provider: &'provider RunStateAuthenticationProvider,
    ) -> TestResultWith<WindowsInitialCleanCommittedWithWriter<'provider>> {
        match prepare(fixture, installation, provider)?.commit_and_reread() {
            WindowsInitialCleanCommitOutcome::Committed(committed) => Ok(committed),
            WindowsInitialCleanCommitOutcome::ReloadRequired(reload) => {
                retire_pending(reload.into_retirement())?;
                Err(RecoveryRequired::CommitReloadRequired.into())
            }
            WindowsInitialCleanCommitOutcome::Terminal(failure) => {
                let reason = failure.reason();
                retire_terminal(failure)?;
                Err(reason.into())
            }
        }
    }

    #[test]
    fn kernel_missing_pair_provisions_clean_one_then_fresh_runtime_boots_one() -> TestResult {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0x51)?;
        let mut provider = test_provider(installation, 0x61)?;

        let committed = exact_committed(&fixture, installation, &provider)?;
        assert_eq!(committed.generation(), NonZeroU64::MIN);
        let provisioned = match committed.release() {
            WindowsProvisioningReleaseOutcome::Provisioned(provisioned) => provisioned,
            WindowsProvisioningReleaseOutcome::Terminal(failure) => {
                let reason = failure.reason();
                retire_terminal(failure)?;
                return Err(reason.into());
            }
            WindowsProvisioningReleaseOutcome::ReleasedNoReceipt(failure) => {
                return Err(failure.cause().into());
            }
            WindowsProvisioningReleaseOutcome::PostReleaseTerminal(failure) => {
                return Err(failure.reason().into());
            }
        };
        assert_eq!(provisioned.generation(), NonZeroU64::MIN);
        assert!(format!("{provisioned:?}").contains("[REDACTED]"));
        drop(provisioned);

        let boot =
            match start_windows_runtime(fixture.acquire_writer()?, provider.runtime_authority()) {
                Ok(boot) => boot,
                Err(WindowsRuntimeStartFailure::Binding(failure)) => {
                    let reason = failure.reason();
                    let _retired = failure
                        .retire()
                        .map_err(|failure| std::io::Error::other(format!("{failure:?}")))?;
                    return Err(reason.into());
                }
                Err(WindowsRuntimeStartFailure::Terminal(failure)) => {
                    let reason = failure.reason();
                    let (_cause, retirement) = failure.into_retirement_parts();
                    let _runtime_retired = retirement.retire_checked().map_err(|failure| {
                        std::io::Error::other(format!("runtime retirement failed: {failure:?}"))
                    })?;
                    return Err(reason.into());
                }
            };
        assert_eq!(boot.generation(), NonZeroU64::MIN);
        let _runtime_retired = boot.into_retirement().retire_checked().map_err(|failure| {
            std::io::Error::other(format!("fresh runtime retirement failed: {failure:?}"))
        })?;
        fixture.cleanup_checked()
    }

    #[test]
    fn kernel_preexisting_full_pair_is_unchanged_and_terminally_retired() -> TestResult {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0x52)?;
        let provider = test_provider(installation, 0x62)?;
        let initial = initial_snapshot(installation, &provider)?;
        install_windows_runtime_clean_fixture(&fixture, installation, &provider)?;

        let failure = match start_windows_initial_provisioning(
            fixture.acquire_writer()?,
            fixture_authority(installation, &provider)?,
        ) {
            Err(WindowsInitialProvisioningStartFailure::Terminal(failure)) => failure,
            Err(WindowsInitialProvisioningStartFailure::Binding(failure)) => {
                let reason = failure.reason();
                let _retired = failure
                    .retire()
                    .map_err(|failure| std::io::Error::other(format!("{failure:?}")))?;
                return Err(reason.into());
            }
            Ok(unprovisioned) => {
                retire_pending(unprovisioned.into_retirement())?;
                return Err(std::io::Error::other(
                    "preexisting pair minted fresh provisioning authority",
                )
                .into());
            }
        };
        assert_eq!(
            failure.reason(),
            RecoveryRequired::InitialProvisioningStateNotEmpty
        );
        assert_eq!(failure.platform_cause(), None);
        retire_terminal(failure)?;
        fixture.assert_exact_pair_and_no_temps_for_test(ExactFixedRunStatePair::new(
            initial.marker,
            initial.checkpoint,
        ))?;
        fixture.cleanup_checked()
    }

    #[test]
    fn kernel_initial_ambiguity_reload_classifies_missing_partial_and_candidate() -> TestResult {
        #[derive(Clone, Copy)]
        enum ExpectedResolution {
            Retry,
            Terminal,
            Committed,
        }

        for (fault, expected, byte) in [
            (
                RuntimePairFault::MarkerRenameAttempt,
                ExpectedResolution::Retry,
                0x71,
            ),
            (
                RuntimePairFault::AfterMarkerRename,
                ExpectedResolution::Terminal,
                0x72,
            ),
            (
                RuntimePairFault::AfterCheckpointRename,
                ExpectedResolution::Committed,
                0x73,
            ),
        ] {
            let fixture = RuntimePairFixture::new()?;
            let installation = test_installation(byte)?;
            let provider = test_provider(installation, byte.wrapping_add(1))?;
            let prepared = prepare(&fixture, installation, &provider)?;
            fixture.inject_fault(fault);
            let reload = match prepared.commit_and_reread() {
                WindowsInitialCleanCommitOutcome::ReloadRequired(reload) => reload,
                WindowsInitialCleanCommitOutcome::Committed(committed) => {
                    retire_pending(committed.into_retirement())?;
                    return Err(std::io::Error::other(
                        "faulted initial commit bypassed mandatory reload",
                    )
                    .into());
                }
                WindowsInitialCleanCommitOutcome::Terminal(failure) => {
                    let reason = failure.reason();
                    retire_terminal(failure)?;
                    return Err(reason.into());
                }
            };
            match (expected, reload.reload()) {
                (ExpectedResolution::Retry, WindowsInitialCleanReloadOutcome::Retry(retry)) => {
                    retire_pending(retry.into_retirement())?;
                }
                (
                    ExpectedResolution::Terminal,
                    WindowsInitialCleanReloadOutcome::Terminal(failure),
                ) => {
                    assert_eq!(
                        failure.reason(),
                        RecoveryRequired::InitialProvisioningStateNotEmpty
                    );
                    assert_eq!(failure.platform_cause(), None);
                    retire_terminal(failure)?;
                }
                (
                    ExpectedResolution::Committed,
                    WindowsInitialCleanReloadOutcome::Committed(committed),
                ) => {
                    assert_eq!(committed.generation(), NonZeroU64::MIN);
                    retire_pending(committed.into_retirement())?;
                }
                (_, WindowsInitialCleanReloadOutcome::Retry(retry)) => {
                    retire_pending(retry.into_retirement())?;
                    return Err(std::io::Error::other(
                        "ambiguity reload unexpectedly restored retry authority",
                    )
                    .into());
                }
                (_, WindowsInitialCleanReloadOutcome::Committed(committed)) => {
                    retire_pending(committed.into_retirement())?;
                    return Err(std::io::Error::other(
                        "ambiguity reload unexpectedly minted committed authority",
                    )
                    .into());
                }
                (_, WindowsInitialCleanReloadOutcome::Terminal(failure)) => {
                    let reason = failure.reason();
                    retire_terminal(failure)?;
                    return Err(reason.into());
                }
            }
            fixture.cleanup_checked()?;
        }
        Ok(())
    }

    #[test]
    fn kernel_confirmed_initial_commit_reread_failure_is_terminal_drift() -> TestResult {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(0x53)?;
        let provider = test_provider(installation, 0x63)?;
        let prepared = prepare(&fixture, installation, &provider)?;
        fixture.inject_fault(RuntimePairFault::CommittedRereadRevalidation);

        let failure = match prepared.commit_and_reread() {
            WindowsInitialCleanCommitOutcome::Terminal(failure) => failure,
            WindowsInitialCleanCommitOutcome::ReloadRequired(reload) => {
                retire_pending(reload.into_retirement())?;
                return Err(std::io::Error::other(
                    "confirmed initial commit exposed pre-commit reload authority",
                )
                .into());
            }
            WindowsInitialCleanCommitOutcome::Committed(committed) => {
                retire_pending(committed.into_retirement())?;
                return Err(std::io::Error::other(
                    "failed independent reread minted committed authority",
                )
                .into());
            }
        };
        assert_eq!(failure.reason(), RecoveryRequired::RereadDrift);
        assert!(failure.platform_cause().is_some());
        let (cause, retirement) = failure.into_retirement_parts();
        assert_eq!(cause.recovery(), RecoveryRequired::RereadDrift);
        assert!(cause.platform().is_some());
        let retirement = match retirement.retire_checked() {
            Err(failure) => failure,
            Ok(_retired) => {
                return Err(std::io::Error::other(
                    "reread close ambiguity minted checked retirement evidence",
                )
                .into());
            }
        };
        assert_eq!(retirement.cause(), ServiceRunStateError::Release);
        fixture.cleanup_checked()
    }

    #[test]
    fn kernel_provisioning_release_distinguishes_retained_no_receipt_and_post_release() -> TestResult
    {
        let retained_fixture = RuntimePairFixture::new()?;
        let retained_installation = test_installation(0x54)?;
        let retained_provider = test_provider(retained_installation, 0x64)?;
        let committed =
            exact_committed(&retained_fixture, retained_installation, &retained_provider)?;
        retained_fixture.inject_fault(RuntimePairFault::WriterReleaseUnlock);
        match committed.release() {
            WindowsProvisioningReleaseOutcome::Terminal(failure) => {
                assert_eq!(failure.reason(), RecoveryRequired::WriterReleaseAmbiguous);
                assert_eq!(
                    failure.platform_cause(),
                    Some(ServiceRunStateError::Release)
                );
                retire_terminal(failure)?;
            }
            WindowsProvisioningReleaseOutcome::Provisioned(_provisioned) => {
                return Err(std::io::Error::other(
                    "writer-retaining release fault minted provisioned evidence",
                )
                .into());
            }
            WindowsProvisioningReleaseOutcome::ReleasedNoReceipt(failure) => {
                return Err(failure.cause().into());
            }
            WindowsProvisioningReleaseOutcome::PostReleaseTerminal(failure) => {
                return Err(failure.reason().into());
            }
        }
        retained_fixture.cleanup_checked()?;

        let no_receipt_fixture = RuntimePairFixture::new()?;
        let no_receipt_installation = test_installation(0x55)?;
        let no_receipt_provider = test_provider(no_receipt_installation, 0x65)?;
        let committed = exact_committed(
            &no_receipt_fixture,
            no_receipt_installation,
            &no_receipt_provider,
        )?;
        no_receipt_fixture.inject_fault(RuntimePairFault::CheckpointFinalClose);
        match committed.release() {
            WindowsProvisioningReleaseOutcome::ReleasedNoReceipt(failure) => {
                assert_eq!(failure.reason(), RecoveryRequired::WriterReleaseAmbiguous);
                assert_eq!(failure.cause(), ServiceRunStateError::Release);
                assert!(format!("{failure:?}").contains("[REDACTED]"));
            }
            WindowsProvisioningReleaseOutcome::Provisioned(_provisioned) => {
                return Err(std::io::Error::other(
                    "post-writer close fault minted provisioned evidence",
                )
                .into());
            }
            WindowsProvisioningReleaseOutcome::Terminal(failure) => {
                let reason = failure.reason();
                retire_terminal(failure)?;
                return Err(reason.into());
            }
            WindowsProvisioningReleaseOutcome::PostReleaseTerminal(failure) => {
                return Err(failure.reason().into());
            }
        }
        no_receipt_fixture.cleanup_checked()?;

        let post_release_fixture = RuntimePairFixture::new()?;
        let post_release_installation = test_installation(0x56)?;
        let post_release_provider = test_provider(post_release_installation, 0x66)?;
        let committed = exact_committed(
            &post_release_fixture,
            post_release_installation,
            &post_release_provider,
        )?;
        match committed.release_with_post_release_fault_for_test() {
            WindowsProvisioningReleaseOutcome::PostReleaseTerminal(failure) => {
                assert_eq!(failure.reason(), RecoveryRequired::OperationPhaseMismatch);
                assert!(format!("{failure:?}").contains("[REDACTED]"));
            }
            WindowsProvisioningReleaseOutcome::Provisioned(_provisioned) => {
                return Err(std::io::Error::other(
                    "post-release logical fault minted provisioned evidence",
                )
                .into());
            }
            WindowsProvisioningReleaseOutcome::Terminal(failure) => {
                let reason = failure.reason();
                retire_terminal(failure)?;
                return Err(reason.into());
            }
            WindowsProvisioningReleaseOutcome::ReleasedNoReceipt(failure) => {
                return Err(failure.cause().into());
            }
        }
        post_release_fixture.cleanup_checked()
    }

    #[test]
    fn installer_grant_binds_only_its_exact_unique_provider_identity() -> TestResult {
        let installation = test_installation(0x56)?;
        let provider = test_provider(installation, 0x66)?;
        let same_material_provider = test_provider(installation, 0x66)?;
        assert_ne!(provider.identity(), same_material_provider.identity());

        let grant = WindowsInstallerProvisioningGrant::for_current_user_fixture(&provider)?;
        assert_eq!(
            format!("{grant:?}"),
            "WindowsInstallerProvisioningGrant([REDACTED])"
        );
        let Err(mismatch) = bind_windows_fresh_install_authority(&same_material_provider, grant)
        else {
            return Err("distinct provider identity accepted a sealed installer grant".into());
        };
        assert_eq!(mismatch.reason(), RecoveryRequired::AuthenticationFailed);
        assert!(format!("{mismatch:?}").contains("[REDACTED]"));

        let authority = bind_windows_fresh_install_authority(&provider, mismatch.into_grant())
            .map_err(|failure| failure.reason())?;
        assert_eq!(authority.provider_identity, provider.identity());
        assert_eq!(authority.installation, installation);
        assert_eq!(
            format!("{authority:?}"),
            "WindowsFreshInstallAuthority([REDACTED])"
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One inventory proves every live/reload retirement surface.
    fn live_provisioning_states_retire_checked_and_debug_is_redacted() -> TestResult {
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

        assert_move_only!(WindowsInstallerProvisioningGrant);
        assert_move_only!(WindowsFreshInstallAuthorityBindingFailure);
        assert_move_only!(WindowsFreshInstallAuthority<'static>);
        assert_move_only!(WindowsInitialProvisioningStartFailure<'static>);
        assert_move_only!(WindowsProvisioningWriterAcquired<'static>);
        assert_move_only!(WindowsUnprovisionedWithWriter<'static>);
        assert_move_only!(WindowsPreparedInitialCleanTransition<'static>);
        assert_move_only!(WindowsInitialCleanCommitOutcome<'static>);
        assert_move_only!(WindowsInitialCleanReloadRequired<'static>);
        assert_move_only!(WindowsInitialCleanReloadOutcome<'static>);
        assert_move_only!(WindowsInitialCleanCommittedWithWriter<'static>);
        assert_move_only!(WindowsProvisioningReleaseOutcome<'static>);
        assert_move_only!(WindowsProvisionedRunState);
        assert_move_only!(WindowsProvisioningTerminalCause);
        assert_move_only!(WindowsProvisioningTerminalFailure<'static>);
        assert_move_only!(WindowsProvisioningRetirementPending<'static>);
        assert_move_only!(WindowsProvisioningCheckedRetired);
        assert_move_only!(WindowsProvisioningCheckedRetirementFailure<'static>);
        assert_move_only!(WindowsProvisioningReleasedNoReceipt<'static>);
        assert_move_only!(WindowsPostReleaseProvisioningTerminal<'static>);
        assert_move_only!(WindowsProvisioningUnboundRetirementFailure<'static>);

        let _: fn(
            WindowsUnprovisionedWithWriter<'static>,
        ) -> WindowsProvisioningRetirementPending<'static> =
            WindowsUnprovisionedWithWriter::into_retirement;
        let _: fn(
            WindowsPreparedInitialCleanTransition<'static>,
        ) -> WindowsProvisioningRetirementPending<'static> =
            WindowsPreparedInitialCleanTransition::into_retirement;
        let _: fn(
            WindowsInitialCleanReloadRequired<'static>,
        ) -> WindowsProvisioningRetirementPending<'static> =
            WindowsInitialCleanReloadRequired::into_retirement;
        let _: fn(
            WindowsInitialCleanCommittedWithWriter<'static>,
        ) -> WindowsProvisioningRetirementPending<'static> =
            WindowsInitialCleanCommittedWithWriter::into_retirement;

        let acquired_fixture = RuntimePairFixture::new()?;
        let acquired_installation = test_installation(0x5c)?;
        let acquired_provider = test_provider(acquired_installation, 0x6c)?;
        let acquired = match WindowsProvisioningWriterAcquired::from_held_writer(
            acquired_fixture.acquire_writer()?,
            fixture_authority(acquired_installation, &acquired_provider)?,
        ) {
            Ok(acquired) => acquired,
            Err(failure) => {
                let reason = failure.reason();
                let _retired = failure
                    .retire()
                    .map_err(|failure| std::io::Error::other(format!("{failure:?}")))?;
                return Err(reason.into());
            }
        };
        assert!(format!("{acquired:?}").contains("[REDACTED]"));
        retire_pending(acquired.into_retirement())?;
        acquired_fixture.cleanup_checked()?;

        let live_fixture = RuntimePairFixture::new()?;
        let live_installation = test_installation(0x57)?;
        let live_provider = test_provider(live_installation, 0x67)?;
        let authority = fixture_authority(live_installation, &live_provider)?;
        assert_eq!(
            format!("{authority:?}"),
            "WindowsFreshInstallAuthority([REDACTED])"
        );
        let unprovisioned =
            start_windows_initial_provisioning(live_fixture.acquire_writer()?, authority).map_err(
                |failure| {
                    std::io::Error::other(format!("fresh provisioning start failed: {failure:?}"))
                },
            )?;
        assert_ne!(
            unprovisioned.logical.authority.attempt,
            unprovisioned.logical.authority.binding.0
        );
        assert_ne!(
            unprovisioned.logical.authority.attempt,
            unprovisioned.logical.lease.epoch
        );
        assert_ne!(
            unprovisioned.logical.authority.binding.0,
            unprovisioned.logical.lease.epoch
        );
        assert!(format!("{unprovisioned:?}").contains("[REDACTED]"));
        let pending = unprovisioned.into_retirement();
        assert!(format!("{pending:?}").contains("[REDACTED]"));
        let retired = pending.retire_checked().map_err(|failure| {
            std::io::Error::other(format!("live retirement failed: {failure:?}"))
        })?;
        assert!(format!("{retired:?}").contains("[REDACTED]"));
        live_fixture.cleanup_checked()?;

        let prepared_fixture = RuntimePairFixture::new()?;
        let prepared_installation = test_installation(0x58)?;
        let prepared_provider = test_provider(prepared_installation, 0x68)?;
        let prepared = prepare(&prepared_fixture, prepared_installation, &prepared_provider)?;
        assert!(format!("{prepared:?}").contains("[REDACTED]"));
        retire_pending(prepared.into_retirement())?;
        prepared_fixture.cleanup_checked()?;

        let committed_fixture = RuntimePairFixture::new()?;
        let committed_installation = test_installation(0x59)?;
        let committed_provider = test_provider(committed_installation, 0x69)?;
        let committed = exact_committed(
            &committed_fixture,
            committed_installation,
            &committed_provider,
        )?;
        assert!(format!("{committed:?}").contains("[REDACTED]"));
        retire_pending(committed.into_retirement())?;
        committed_fixture.cleanup_checked()?;

        let reload_fixture = RuntimePairFixture::new()?;
        let reload_installation = test_installation(0x5a)?;
        let reload_provider = test_provider(reload_installation, 0x6a)?;
        let prepared = prepare(&reload_fixture, reload_installation, &reload_provider)?;
        reload_fixture.inject_fault(RuntimePairFault::AfterMarkerRename);
        let reload = match prepared.commit_and_reread() {
            WindowsInitialCleanCommitOutcome::ReloadRequired(reload) => reload,
            WindowsInitialCleanCommitOutcome::Committed(committed) => {
                retire_pending(committed.into_retirement())?;
                return Err(std::io::Error::other("fault did not yield reload state").into());
            }
            WindowsInitialCleanCommitOutcome::Terminal(failure) => {
                let reason = failure.reason();
                retire_terminal(failure)?;
                return Err(reason.into());
            }
        };
        assert!(format!("{reload:?}").contains("[REDACTED]"));
        retire_pending(reload.into_retirement())?;
        reload_fixture.cleanup_checked()?;

        let retirement_fault_fixture = RuntimePairFixture::new()?;
        let retirement_fault_installation = test_installation(0x5b)?;
        let retirement_fault_provider = test_provider(retirement_fault_installation, 0x6b)?;
        let unprovisioned = start(
            &retirement_fault_fixture,
            retirement_fault_installation,
            &retirement_fault_provider,
        )?;
        retirement_fault_fixture.inject_fault(RuntimePairFault::WriterReleaseUnlock);
        let failure = match unprovisioned.into_retirement().retire_checked() {
            Err(failure) => failure,
            Ok(_retired) => {
                return Err(std::io::Error::other(
                    "retirement fault minted checked retirement evidence",
                )
                .into());
            }
        };
        assert_eq!(failure.reason(), RecoveryRequired::WindowsBackendFailure);
        assert_eq!(failure.cause(), ServiceRunStateError::Release);
        assert!(format!("{failure:?}").contains("[REDACTED]"));
        retirement_fault_fixture.cleanup_checked()
    }
}
