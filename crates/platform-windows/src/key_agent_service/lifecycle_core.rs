//! No-secret Windows Key Agent service lifecycle and recovery contract.
//!
//! This production-compiled module is deliberately private. Its sole runtime
//! consumer is the sibling dormant Windows lifecycle compositor, which still
//! has no executable/top-level caller. The core models ordering and fail-closed
//! decisions without creating an SCM listener, OS handle, secret, signing
//! operation, or release authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};

use thiserror::Error;

use super::durable_run_state::{
    ActiveReloadReceipt, ActiveReloadRequired, ActiveRunLease, BootEvidence, CleanReloadReceipt,
    CleanReloadRequired, CommittedActiveMarker, CommittedCleanMarker, DurableFailureWithWriter,
    PendingFinalWriterRelease, PreparedActiveTransition, PreparedCleanTransition,
    RecoveryExitEvidence, RecoveryRequired, ReloadedActiveRunState, RereadActiveMarker,
    RereadCleanMarker, RuntimeBootBeforeWriterFailure, RuntimeBootStartFailure, StoppedRunEvidence,
    WriterExitPending, WriterExitReceipt, WriterLeaseReleaseReceipt,
};

const LOGICAL_STARTUP_REQUIREMENT_COUNT: usize = 11;
const LEASE_BOUND_STARTUP_REQUIREMENT_COUNT: usize = 2;
const STARTUP_REQUIREMENT_COUNT: usize =
    LOGICAL_STARTUP_REQUIREMENT_COUNT - LEASE_BOUND_STARTUP_REQUIREMENT_COUNT;
const MAX_ACTIVE_FIXTURE_WORK: usize = 256;
const MAX_RETAINED_USER_TOKEN_SESSIONS: usize = 64;
const MAX_QUARANTINED_SESSIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NoSecretStartupRequirement {
    ServiceToken,
    RestrictedServiceSid,
    PrivilegeSet,
    InstalledImage,
    ServiceConfiguration,
    ProviderBinding,
    AnchorBinding,
    FirewallPolicy,
    EnrolledUser,
}

impl NoSecretStartupRequirement {
    pub(super) const ALL: [Self; STARTUP_REQUIREMENT_COUNT] = [
        Self::ServiceToken,
        Self::RestrictedServiceSid,
        Self::PrivilegeSet,
        Self::InstalledImage,
        Self::ServiceConfiguration,
        Self::ProviderBinding,
        Self::AnchorBinding,
        Self::FirewallPolicy,
        Self::EnrolledUser,
    ];

    const fn index(self) -> usize {
        match self {
            Self::ServiceToken => 0,
            Self::RestrictedServiceSid => 1,
            Self::PrivilegeSet => 2,
            Self::InstalledImage => 3,
            Self::ServiceConfiguration => 4,
            Self::ProviderBinding => 5,
            Self::AnchorBinding => 6,
            Self::FirewallPolicy => 7,
            Self::EnrolledUser => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StartupObservation {
    Verified,
    Mismatch,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum StartupFailure {
    #[error("a required no-secret startup observation is missing: {0:?}")]
    Missing(NoSecretStartupRequirement),
    #[error("a required no-secret startup observation mismatched: {0:?}")]
    Mismatch(NoSecretStartupRequirement),
    #[error("a required no-secret startup observation is unavailable: {0:?}")]
    Unavailable(NoSecretStartupRequirement),
    #[error("a no-secret startup observation was supplied more than once: {0:?}")]
    DuplicateObservation(NoSecretStartupRequirement),
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
enum StartupExitCause {
    #[error("authority-independent startup policy was rejected: {0}")]
    Checklist(StartupFailure),
    #[error("durable run-state recovery is required: {0}")]
    DurableRecovery(RecoveryRequired),
}

/// Authority-independent observations required before the service may enter
/// the ordered listener/SCM/admission startup chain.
///
/// This value deliberately contains neither durable authority nor Windows
/// handles. Its consuming completion is the only constructor for the next
/// policy typestate.
#[must_use = "a startup checklist must be completed or rejected explicitly"]
pub(super) struct StartupChecklist {
    observations: [Option<StartupObservation>; STARTUP_REQUIREMENT_COUNT],
    latched_failure: Option<StartupFailure>,
}

impl StartupChecklist {
    pub(super) const fn new() -> Self {
        Self {
            observations: [None; STARTUP_REQUIREMENT_COUNT],
            latched_failure: None,
        }
    }

    pub(super) fn observe(
        &mut self,
        requirement: NoSecretStartupRequirement,
        observation: StartupObservation,
    ) -> Result<(), StartupFailure> {
        let slot = &mut self.observations[requirement.index()];
        if slot.is_some() {
            let failure = StartupFailure::DuplicateObservation(requirement);
            self.latched_failure.get_or_insert(failure);
            return Err(failure);
        }
        *slot = Some(observation);
        Ok(())
    }

    pub(super) fn finish(self) -> Result<CompletedStartupChecklist, StartupFailure> {
        if let Some(failure) = self.latched_failure {
            return Err(failure);
        }
        for requirement in NoSecretStartupRequirement::ALL {
            match self.observations[requirement.index()] {
                None => return Err(StartupFailure::Missing(requirement)),
                Some(StartupObservation::Mismatch) => {
                    return Err(StartupFailure::Mismatch(requirement));
                }
                Some(StartupObservation::Unavailable) => {
                    return Err(StartupFailure::Unavailable(requirement));
                }
                Some(StartupObservation::Verified) => {}
            }
        }
        Ok(CompletedStartupChecklist { _sealed: () })
    }
}

impl fmt::Debug for StartupChecklist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StartupChecklist([REDACTED OBSERVATIONS])")
    }
}

/// Move-only proof that every authority-independent startup observation was
/// supplied exactly once and accepted in the fixed evaluation order.
#[must_use = "a completed startup checklist must enter the ordered startup chain"]
pub(super) struct CompletedStartupChecklist {
    _sealed: (),
}

impl CompletedStartupChecklist {
    pub(super) fn begin_listener_startup(self) -> ListenerPendingPolicy {
        ListenerPendingPolicy { checklist: self }
    }
}

impl fmt::Debug for CompletedStartupChecklist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletedStartupChecklist([REDACTED])")
    }
}

enum StartupWriterExit<'provider> {
    BeforeWriter(RuntimeBootBeforeWriterFailure<'provider>),
    Pending(WriterExitPending<'provider>),
}

/// Terminal startup evidence for a failure that occurred before writer
/// acquisition. It retains the consumed provider-bound runtime authority.
#[must_use]
struct StartupBeforeWriterExit<'provider> {
    failure: StartupExitCause,
    _runtime: RuntimeBootBeforeWriterFailure<'provider>,
}

impl StartupBeforeWriterExit<'_> {
    const fn failure(&self) -> StartupExitCause {
        self.failure
    }
}

impl fmt::Debug for StartupBeforeWriterExit<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupBeforeWriterExit")
            .field("failure", &self.failure)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

struct StartupExitRequired<'provider> {
    failure: StartupExitCause,
    writer_exit: StartupWriterExit<'provider>,
}

impl<'provider> StartupExitRequired<'provider> {
    const fn before_writer(
        failure: StartupExitCause,
        runtime: RuntimeBootBeforeWriterFailure<'provider>,
    ) -> Self {
        Self {
            failure,
            writer_exit: StartupWriterExit::BeforeWriter(runtime),
        }
    }

    const fn with_writer(
        failure: StartupExitCause,
        writer_exit: WriterExitPending<'provider>,
    ) -> Self {
        Self {
            failure,
            writer_exit: StartupWriterExit::Pending(writer_exit),
        }
    }

    fn from_durable(failure: DurableFailureWithWriter<'provider>) -> Self {
        let reason = failure.reason();
        Self::with_writer(
            StartupExitCause::DurableRecovery(reason),
            failure.into_writer_exit(),
        )
    }

    fn from_runtime_boot(failure: RuntimeBootStartFailure<'provider>) -> Self {
        let reason = failure.reason();
        match failure.into_writer_exit() {
            Err(runtime) => Self::before_writer(StartupExitCause::DurableRecovery(reason), runtime),
            Ok((_, writer_exit)) => {
                Self::with_writer(StartupExitCause::DurableRecovery(reason), writer_exit)
            }
        }
    }

    fn into_writer_exit(
        self,
    ) -> Result<(StartupExitCause, WriterExitPending<'provider>), StartupBeforeWriterExit<'provider>>
    {
        match self.writer_exit {
            StartupWriterExit::BeforeWriter(runtime) => Err(StartupBeforeWriterExit {
                failure: self.failure,
                _runtime: runtime,
            }),
            StartupWriterExit::Pending(writer_exit) => Ok((self.failure, writer_exit)),
        }
    }
}

impl fmt::Debug for StartupExitRequired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupExitRequired")
            .field("failure", &self.failure)
            .field("writer_exit", &"[REDACTED]")
            .finish()
    }
}

struct NoSecretStartupAttempt<'provider> {
    checklist: StartupChecklist,
    boot: Result<BootEvidence<'provider>, RuntimeBootStartFailure<'provider>>,
}

impl fmt::Debug for NoSecretStartupAttempt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoSecretStartupAttempt([REDACTED OBSERVATIONS])")
    }
}

impl<'provider> NoSecretStartupAttempt<'provider> {
    fn new(boot: Result<BootEvidence<'provider>, RuntimeBootStartFailure<'provider>>) -> Self {
        Self {
            checklist: StartupChecklist::new(),
            boot,
        }
    }

    fn observe(
        &mut self,
        requirement: NoSecretStartupRequirement,
        observation: StartupObservation,
    ) -> Result<(), StartupFailure> {
        self.checklist.observe(requirement, observation)
    }

    fn finish(self) -> Result<PendingNoSecretStartup<'provider>, StartupExitRequired<'provider>> {
        let Self { checklist, boot } = self;
        let checklist = match checklist.finish() {
            Ok(checklist) => checklist,
            Err(failure) => return Err(Self::into_exit_for_boot(boot, failure)),
        };
        let boot = boot.map_err(StartupExitRequired::from_runtime_boot)?;
        let active_transition = boot
            .prepare_active()
            .map_err(StartupExitRequired::from_durable)?;
        Ok(PendingNoSecretStartup {
            active_transition,
            checklist,
        })
    }

    fn into_exit(self, failure: StartupFailure) -> StartupExitRequired<'provider> {
        Self::into_exit_for_boot(self.boot, failure)
    }

    fn into_exit_for_boot(
        boot: Result<BootEvidence<'provider>, RuntimeBootStartFailure<'provider>>,
        failure: StartupFailure,
    ) -> StartupExitRequired<'provider> {
        let failure = StartupExitCause::Checklist(failure);
        match boot {
            Ok(boot) => StartupExitRequired::with_writer(failure, boot.into_writer_exit()),
            Err(runtime_failure) => match runtime_failure.into_writer_exit() {
                Err(runtime) => StartupExitRequired::before_writer(failure, runtime),
                Ok((_, writer_exit)) => StartupExitRequired::with_writer(failure, writer_exit),
            },
        }
    }
}

struct PendingNoSecretStartup<'provider> {
    active_transition: PreparedActiveTransition<'provider>,
    checklist: CompletedStartupChecklist,
}

impl<'provider> PendingNoSecretStartup<'provider> {
    fn transition_request(&self) -> &PreparedActiveTransition<'provider> {
        &self.active_transition
    }

    fn commit_and_reread_active_marker(
        self,
        committed: CommittedActiveMarker,
        reread: RereadActiveMarker,
    ) -> Result<ListenerPendingRuntime<'provider>, StartupExitRequired<'provider>> {
        let active_run = self
            .active_transition
            .complete(committed, reread)
            .map_err(StartupExitRequired::from_durable)?;
        Ok(ListenerPendingRuntime {
            active_run,
            policy: self.checklist.begin_listener_startup(),
        })
    }

    fn commit_ambiguous(self) -> PendingActiveReload<'provider> {
        PendingActiveReload {
            reload: self.active_transition.commit_ambiguous(),
            checklist: self.checklist,
        }
    }

    fn abort(self, reason: RecoveryRequired) -> StartupExitRequired<'provider> {
        StartupExitRequired::from_durable(self.active_transition.abort(reason))
    }
}

impl fmt::Debug for PendingNoSecretStartup<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingNoSecretStartup([GENERATIONS])")
    }
}

struct PendingActiveReload<'provider> {
    reload: ActiveReloadRequired<'provider>,
    checklist: CompletedStartupChecklist,
}

impl<'provider> PendingActiveReload<'provider> {
    fn reload_request(&self) -> &ActiveReloadRequired<'provider> {
        &self.reload
    }

    fn complete(
        self,
        receipt: ActiveReloadReceipt,
    ) -> Result<ActiveReloadResolution<'provider>, StartupExitRequired<'provider>> {
        let Self { reload, checklist } = self;
        let reloaded = reload
            .complete_reload(receipt)
            .map_err(StartupExitRequired::from_durable)?;
        Ok(match reloaded {
            ReloadedActiveRunState::Boot(boot) => {
                ActiveReloadResolution::Revalidate(NoSecretStartupAttempt::new(Ok(boot)))
            }
            ReloadedActiveRunState::Active(active_run) => {
                ActiveReloadResolution::Resume(ListenerPendingRuntime {
                    active_run,
                    policy: checklist.begin_listener_startup(),
                })
            }
        })
    }

    fn abort(self, reason: RecoveryRequired) -> StartupExitRequired<'provider> {
        StartupExitRequired::from_durable(self.reload.abort(reason))
    }
}

impl fmt::Debug for PendingActiveReload<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingActiveReload([REDACTED])")
    }
}

enum ActiveReloadResolution<'provider> {
    Revalidate(NoSecretStartupAttempt<'provider>),
    Resume(ListenerPendingRuntime<'provider>),
}

impl fmt::Debug for ActiveReloadResolution<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revalidate(_) => formatter.write_str("ActiveReloadResolution::Revalidate"),
            Self::Resume(_) => formatter.write_str("ActiveReloadResolution::Resume"),
        }
    }
}

/// Pure policy proof that durable Active state was confirmed before listeners
/// may be prepared.
#[must_use = "listener preparation must be recorded before startup continues"]
pub(super) struct ListenerPendingPolicy {
    checklist: CompletedStartupChecklist,
}

impl ListenerPendingPolicy {
    pub(super) fn record_listeners_prepared(self) -> ScmRunningPendingPolicy {
        ScmRunningPendingPolicy {
            checklist: self.checklist,
        }
    }
}

impl fmt::Debug for ListenerPendingPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ListenerPendingPolicy([REDACTED])")
    }
}

/// Pure policy proof that listener preparation preceded `SCM_RUNNING`.
#[must_use = "SCM_RUNNING publication must be recorded before startup continues"]
pub(super) struct ScmRunningPendingPolicy {
    checklist: CompletedStartupChecklist,
}

impl ScmRunningPendingPolicy {
    pub(super) fn record_scm_running_published(self) -> AdmissionPendingPolicy {
        AdmissionPendingPolicy {
            checklist: self.checklist,
        }
    }
}

impl fmt::Debug for ScmRunningPendingPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScmRunningPendingPolicy([REDACTED])")
    }
}

/// Pure policy proof that admission remains closed until both listener and SCM
/// publication ordering have been recorded.
#[must_use = "admission must be opened explicitly"]
pub(super) struct AdmissionPendingPolicy {
    checklist: CompletedStartupChecklist,
}

impl AdmissionPendingPolicy {
    pub(super) fn open_admission(self) -> RuntimePolicy {
        RuntimePolicy::new(self.checklist)
    }
}

impl fmt::Debug for AdmissionPendingPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionPendingPolicy([REDACTED])")
    }
}

struct ListenerPendingRuntime<'provider> {
    active_run: ActiveRunLease<'provider>,
    policy: ListenerPendingPolicy,
}

impl<'provider> ListenerPendingRuntime<'provider> {
    fn record_listeners_prepared(self) -> ScmRunningPendingRuntime<'provider> {
        ScmRunningPendingRuntime {
            active_run: self.active_run,
            policy: self.policy.record_listeners_prepared(),
        }
    }
}

impl fmt::Debug for ListenerPendingRuntime<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ListenerPendingRuntime([GENERATIONS])")
    }
}

struct ScmRunningPendingRuntime<'provider> {
    active_run: ActiveRunLease<'provider>,
    policy: ScmRunningPendingPolicy,
}

impl<'provider> ScmRunningPendingRuntime<'provider> {
    fn record_scm_running_published(self) -> AdmissionPendingRuntime<'provider> {
        AdmissionPendingRuntime {
            active_run: self.active_run,
            policy: self.policy.record_scm_running_published(),
        }
    }
}

impl fmt::Debug for ScmRunningPendingRuntime<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScmRunningPendingRuntime([GENERATIONS])")
    }
}

struct AdmissionPendingRuntime<'provider> {
    active_run: ActiveRunLease<'provider>,
    policy: AdmissionPendingPolicy,
}

impl<'provider> AdmissionPendingRuntime<'provider> {
    fn open_admission(self) -> NoSecretService<'provider> {
        NoSecretService::new(self.active_run, self.policy.open_admission())
    }
}

impl fmt::Debug for AdmissionPendingRuntime<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionPendingRuntime([GENERATIONS])")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct WorkId(NonZeroU64);

impl WorkId {
    pub(super) fn new(value: u64) -> Result<Self, LifecycleError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(LifecycleError::InvalidIdentifier)
    }
}

impl fmt::Debug for WorkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkId([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct SessionId(NonZeroU32);

impl SessionId {
    pub(super) fn new(value: u32) -> Result<Self, LifecycleError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(LifecycleError::InvalidIdentifier)
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NoSecretFixtureWorkKind {
    Approval,
    SecretInput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkState {
    Active,
    CancellationPending,
    TerminationPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixtureWork {
    session: SessionId,
    kind: NoSecretFixtureWorkKind,
    state: WorkState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StopReason {
    ScmStop,
    SystemShutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CleanupStep {
    RejectNewWork,
    InvalidateNonDurableAuthority,
    CloseAndDrainListeners,
    CancelRequests,
    TerminateHelpers,
    ReapHelpers,
    DiscardUserTokens,
    FlushDefinedDurableRecords,
    ReleaseRequestHardwareAndStorageHandles,
    CommitAndRereadCleanMarker,
    ReleaseSingleInstanceLease,
}

impl CleanupStep {
    const ORDERED: [Self; 11] = [
        Self::RejectNewWork,
        Self::InvalidateNonDurableAuthority,
        Self::CloseAndDrainListeners,
        Self::CancelRequests,
        Self::TerminateHelpers,
        Self::ReapHelpers,
        Self::DiscardUserTokens,
        Self::FlushDefinedDurableRecords,
        Self::ReleaseRequestHardwareAndStorageHandles,
        Self::CommitAndRereadCleanMarker,
        Self::ReleaseSingleInstanceLease,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FatalReason {
    ServiceCrash,
    SessionQuarantineExceeded,
    CleanupFailed(CleanupStep),
    CleanupDeadlineExpired,
    CleanupProtocolViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeState {
    Ready,
    Draining(StopReason),
    Fatal(FatalReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionEvent {
    Lock(SessionId),
    Unlock(SessionId),
    Logoff(SessionId),
    UserSwitch(SessionId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SessionInvalidationReport {
    authorities_invalidated: usize,
    helper_terminations_required: usize,
    user_tokens_discarded: usize,
    revalidation_required: bool,
}

impl SessionInvalidationReport {
    const fn empty(revalidation_required: bool) -> Self {
        Self {
            authorities_invalidated: 0,
            helper_terminations_required: 0,
            user_tokens_discarded: 0,
            revalidation_required,
        }
    }

    pub(super) const fn authorities_invalidated(self) -> usize {
        self.authorities_invalidated
    }

    pub(super) const fn helper_terminations_required(self) -> usize {
        self.helper_terminations_required
    }

    pub(super) const fn user_tokens_discarded(self) -> usize {
        self.user_tokens_discarded
    }

    pub(super) const fn revalidation_required(self) -> bool {
        self.revalidation_required
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum LifecycleError {
    #[error("a lifecycle identifier must be nonzero")]
    InvalidIdentifier,
    #[error("the no-secret service is not ready")]
    NotReady,
    #[error("the no-secret service is in a fatal state")]
    Fatal,
    #[error("the session requires fresh revalidation")]
    SessionInvalidated,
    #[error("the bounded session quarantine is exhausted")]
    SessionQuarantineExhausted,
    #[error("fixture work already exists")]
    DuplicateWork,
    #[error("the bounded fixture-work registry is exhausted")]
    WorkCapacityExhausted,
    #[error("the bounded retained-token registry is exhausted")]
    UserTokenCapacityExhausted,
    #[error("fixture work was not found")]
    UnknownWork,
    #[error("fixture work is not cancellation-pending")]
    WorkNotCancellationPending,
    #[error("cleanup was acknowledged out of order")]
    CleanupOutOfOrder,
    #[error("the clean-shutdown receipt is invalid")]
    InvalidCleanShutdownReceipt,
    #[error("cleanup is incomplete")]
    CleanupIncomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExitReason {
    CleanupOutOfOrder,
    CleanupIncomplete,
    FatalRuntime,
    DurableRecovery,
}

/// Pure runtime-policy failures. Durable recovery is deliberately absent so a
/// sibling adapter cannot confuse a local policy rejection with an OS or
/// durable-run-state failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum RuntimePolicyFailure {
    #[error("the first nine cleanup steps were not completed in exact order")]
    CleanupOutOfOrder,
    #[error("non-durable runtime registries remain populated")]
    CleanupIncomplete,
}

impl From<RuntimePolicyFailure> for ExitReason {
    fn from(failure: RuntimePolicyFailure) -> Self {
        match failure {
            RuntimePolicyFailure::CleanupOutOfOrder => Self::CleanupOutOfOrder,
            RuntimePolicyFailure::CleanupIncomplete => Self::CleanupIncomplete,
        }
    }
}

struct ExitRequired<'provider> {
    reason: ExitReason,
    durable_recovery: Option<RecoveryRequired>,
    writer_exit: WriterExitPending<'provider>,
}

impl<'provider> ExitRequired<'provider> {
    const fn cleanup(reason: ExitReason, writer_exit: WriterExitPending<'provider>) -> Self {
        Self {
            reason,
            durable_recovery: None,
            writer_exit,
        }
    }

    fn durable(failure: DurableFailureWithWriter<'provider>) -> Self {
        let recovery = failure.reason();
        Self {
            reason: ExitReason::DurableRecovery,
            durable_recovery: Some(recovery),
            writer_exit: failure.into_writer_exit(),
        }
    }

    fn writer_exit_request(&self) -> &WriterExitPending<'provider> {
        &self.writer_exit
    }

    fn complete_writer_exit(
        self,
        receipt: WriterExitReceipt,
    ) -> Result<RecoveryExitPermit<'provider>, DurableFailureWithWriter<'provider>> {
        let retired = self.writer_exit.complete(receipt)?;
        Ok(RecoveryExitPermit {
            reason: self.reason,
            durable_recovery: self.durable_recovery,
            _retired: retired,
        })
    }
}

impl fmt::Debug for ExitRequired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExitRequired")
            .field("reason", &self.reason)
            .field("durable_recovery", &self.durable_recovery)
            .field("writer_exit", &"[REDACTED]")
            .finish()
    }
}

struct RecoveryExitPermit<'provider> {
    reason: ExitReason,
    durable_recovery: Option<RecoveryRequired>,
    _retired: RecoveryExitEvidence<'provider>,
}

impl fmt::Debug for RecoveryExitPermit<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryExitPermit")
            .field("reason", &self.reason)
            .field("durable_recovery", &self.durable_recovery)
            .field("_retired", &"[REDACTED]")
            .finish()
    }
}

/// Move-only proof that runtime policy completed the first nine cleanup steps
/// with all non-durable registries empty.
#[must_use = "the clean boundary must be paired with a confirmed durable Clean commit"]
pub(super) struct CleanBoundaryPolicy {
    startup: CompletedStartupChecklist,
}

impl CleanBoundaryPolicy {
    /// Advances pure policy after the composition layer receives the exact
    /// durable/OS Clean success arm. This method does not verify that external
    /// result itself; the composition layer must gate the call.
    pub(super) fn record_clean_committed(self) -> ReleaseBoundaryPolicy {
        ReleaseBoundaryPolicy {
            startup: self.startup,
        }
    }
}

impl fmt::Debug for CleanBoundaryPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanBoundaryPolicy([REDACTED])")
    }
}

/// Move-only policy token for the interval after the composition layer records
/// its independently confirmed durable/OS Clean result.
#[must_use = "the release boundary must be paired with exact writer release"]
pub(super) struct ReleaseBoundaryPolicy {
    startup: CompletedStartupChecklist,
}

impl ReleaseBoundaryPolicy {
    /// Advances pure policy after the composition layer receives the exact
    /// writer-release success arm. This method does not verify that external
    /// result itself and must never be called for ambiguity or no receipt.
    pub(super) fn record_writer_released(self) -> StoppedRuntimePolicy {
        StoppedRuntimePolicy {
            _startup: self.startup,
        }
    }
}

impl fmt::Debug for ReleaseBoundaryPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReleaseBoundaryPolicy([REDACTED])")
    }
}

/// Final move-only pure-policy token minted after the composition layer records
/// exact writer release.
#[must_use = "stopped policy is terminal evidence"]
pub(super) struct StoppedRuntimePolicy {
    _startup: CompletedStartupChecklist,
}

impl fmt::Debug for StoppedRuntimePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoppedRuntimePolicy([REDACTED])")
    }
}

struct SingleInstanceReleasePending<'provider> {
    pending: PendingFinalWriterRelease<'provider>,
    policy: ReleaseBoundaryPolicy,
}

impl<'provider> SingleInstanceReleasePending<'provider> {
    fn release_request(&self) -> &PendingFinalWriterRelease<'provider> {
        &self.pending
    }

    fn complete(
        self,
        receipt: WriterLeaseReleaseReceipt,
    ) -> Result<StoppedPermit<'provider>, ExitRequired<'provider>> {
        let stopped = self
            .pending
            .complete(receipt)
            .map_err(ExitRequired::durable)?;
        Ok(StoppedPermit::from_durable_evidence(
            stopped,
            self.policy.record_writer_released(),
        ))
    }

    fn abort(self, reason: RecoveryRequired) -> ExitRequired<'provider> {
        ExitRequired::durable(self.pending.abort(reason))
    }
}

impl fmt::Debug for SingleInstanceReleasePending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleInstanceReleasePending([REDACTED])")
    }
}

struct CleanCommitPending<'provider> {
    transition: PreparedCleanTransition<'provider>,
    policy: CleanBoundaryPolicy,
}

impl<'provider> CleanCommitPending<'provider> {
    fn transition_request(&self) -> &PreparedCleanTransition<'provider> {
        &self.transition
    }

    fn commit_and_reread_clean_marker(
        self,
        committed: CommittedCleanMarker,
        reread: RereadCleanMarker,
    ) -> Result<SingleInstanceReleasePending<'provider>, ExitRequired<'provider>> {
        let committed = self
            .transition
            .complete(committed, reread)
            .map_err(ExitRequired::durable)?;
        Ok(SingleInstanceReleasePending {
            pending: committed.prepare_writer_release(),
            policy: self.policy.record_clean_committed(),
        })
    }

    fn commit_ambiguous(self) -> PendingCleanReload<'provider> {
        PendingCleanReload {
            reload: self.transition.commit_ambiguous(),
            policy: self.policy,
        }
    }

    fn abort(self, reason: RecoveryRequired) -> ExitRequired<'provider> {
        ExitRequired::durable(self.transition.abort(reason))
    }
}

impl fmt::Debug for CleanCommitPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanCommitPending([GENERATIONS])")
    }
}

struct PendingCleanReload<'provider> {
    reload: CleanReloadRequired<'provider>,
    policy: CleanBoundaryPolicy,
}

impl<'provider> PendingCleanReload<'provider> {
    fn reload_request(&self) -> &CleanReloadRequired<'provider> {
        &self.reload
    }

    fn complete(
        self,
        receipt: CleanReloadReceipt,
    ) -> Result<SingleInstanceReleasePending<'provider>, ExitRequired<'provider>> {
        let committed = self
            .reload
            .complete_reload(receipt)
            .map_err(ExitRequired::durable)?;
        Ok(SingleInstanceReleasePending {
            pending: committed.prepare_writer_release(),
            policy: self.policy.record_clean_committed(),
        })
    }

    fn abort(self, reason: RecoveryRequired) -> ExitRequired<'provider> {
        ExitRequired::durable(self.reload.abort(reason))
    }
}

impl fmt::Debug for PendingCleanReload<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingCleanReload([REDACTED])")
    }
}

struct StoppedPermit<'provider> {
    stopped: StoppedRunEvidence<'provider>,
    _policy: StoppedRuntimePolicy,
}

impl<'provider> StoppedPermit<'provider> {
    const fn from_durable_evidence(
        stopped: StoppedRunEvidence<'provider>,
        policy: StoppedRuntimePolicy,
    ) -> Self {
        Self {
            stopped,
            _policy: policy,
        }
    }
}

impl fmt::Debug for StoppedPermit<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoppedPermit([REDACTED DURABLE EVIDENCE])")
    }
}

/// Authority-independent runtime policy and bounded non-durable registries.
///
/// This value never owns a durable lease, Windows handle, authentication provider,
/// or release receipt. It can only be minted by consuming the ordered startup
/// policy chain.
#[must_use = "runtime policy must advance to a clean boundary or a terminal cause"]
pub(super) struct RuntimePolicy {
    startup: CompletedStartupChecklist,
    state: RuntimeState,
    work: BTreeMap<WorkId, FixtureWork>,
    user_token_sessions: BTreeSet<SessionId>,
    invalid_sessions: BTreeSet<SessionId>,
    next_cleanup_index: usize,
}

impl RuntimePolicy {
    fn new(startup: CompletedStartupChecklist) -> Self {
        Self {
            startup,
            state: RuntimeState::Ready,
            work: BTreeMap::new(),
            user_token_sessions: BTreeSet::new(),
            invalid_sessions: BTreeSet::new(),
            next_cleanup_index: 0,
        }
    }

    pub(super) const fn state(&self) -> RuntimeState {
        self.state
    }

    pub(super) fn work_count(&self) -> usize {
        self.work.len()
    }

    pub(super) fn retained_user_token_count(&self) -> usize {
        self.user_token_sessions.len()
    }

    pub(super) fn quarantined_session_count(&self) -> usize {
        self.invalid_sessions.len()
    }

    pub(super) fn admit_fixture_work(
        &mut self,
        id: WorkId,
        session: SessionId,
        kind: NoSecretFixtureWorkKind,
    ) -> Result<(), LifecycleError> {
        self.require_ready()?;
        if self.invalid_sessions.contains(&session) {
            return Err(LifecycleError::SessionInvalidated);
        }
        if self.work.contains_key(&id) {
            return Err(LifecycleError::DuplicateWork);
        }
        if self.work.len() >= MAX_ACTIVE_FIXTURE_WORK {
            return Err(LifecycleError::WorkCapacityExhausted);
        }
        self.work.insert(
            id,
            FixtureWork {
                session,
                kind,
                state: WorkState::Active,
            },
        );
        Ok(())
    }

    pub(super) fn retain_user_token(&mut self, session: SessionId) -> Result<(), LifecycleError> {
        self.require_ready()?;
        if self.invalid_sessions.contains(&session) {
            return Err(LifecycleError::SessionInvalidated);
        }
        if self.user_token_sessions.contains(&session) {
            return Ok(());
        }
        if self.user_token_sessions.len() >= MAX_RETAINED_USER_TOKEN_SESSIONS {
            return Err(LifecycleError::UserTokenCapacityExhausted);
        }
        self.user_token_sessions.insert(session);
        Ok(())
    }

    pub(super) fn handle_session_event(
        &mut self,
        event: SessionEvent,
    ) -> Result<SessionInvalidationReport, LifecycleError> {
        self.require_ready()?;
        match event {
            SessionEvent::Lock(session) | SessionEvent::Unlock(session) => {
                self.invalidate_session(session, false)
            }
            SessionEvent::Logoff(session) => self.invalidate_session(session, true),
            SessionEvent::UserSwitch(departing_session) => {
                self.invalidate_all_sessions(departing_session)
            }
        }
    }

    fn invalidate_session(
        &mut self,
        session: SessionId,
        discard_user_token: bool,
    ) -> Result<SessionInvalidationReport, LifecycleError> {
        self.quarantine_session(session)?;
        let mut report = SessionInvalidationReport::empty(true);
        for work in self.work.values_mut() {
            if work.session == session && work.state == WorkState::Active {
                work.state = WorkState::CancellationPending;
                report.authorities_invalidated += 1;
                report.helper_terminations_required += 1;
            }
        }
        if discard_user_token && self.user_token_sessions.remove(&session) {
            report.user_tokens_discarded = 1;
        }
        Ok(report)
    }

    fn invalidate_all_sessions(
        &mut self,
        departing_session: SessionId,
    ) -> Result<SessionInvalidationReport, LifecycleError> {
        let mut quarantined = self.invalid_sessions.clone();
        let mut overflowed = false;
        for session in [departing_session]
            .into_iter()
            .chain(self.work.values().map(|work| work.session))
            .chain(self.user_token_sessions.iter().copied())
        {
            if !quarantined.contains(&session) && quarantined.len() >= MAX_QUARANTINED_SESSIONS {
                overflowed = true;
                break;
            }
            quarantined.insert(session);
        }
        if overflowed {
            self.fail_closed_for_session_quarantine_exhaustion();
            return Err(LifecycleError::SessionQuarantineExhausted);
        }
        self.invalid_sessions = quarantined;
        let mut report = SessionInvalidationReport::empty(true);
        for work in self.work.values_mut() {
            if work.state == WorkState::Active {
                work.state = WorkState::CancellationPending;
                report.authorities_invalidated += 1;
                report.helper_terminations_required += 1;
            }
        }
        report.user_tokens_discarded = self.user_token_sessions.len();
        self.user_token_sessions.clear();
        Ok(report)
    }

    fn quarantine_session(&mut self, session: SessionId) -> Result<(), LifecycleError> {
        if self.invalid_sessions.contains(&session) {
            return Ok(());
        }
        if self.invalid_sessions.len() >= MAX_QUARANTINED_SESSIONS {
            self.fail_closed_for_session_quarantine_exhaustion();
            return Err(LifecycleError::SessionQuarantineExhausted);
        }
        self.invalid_sessions.insert(session);
        Ok(())
    }

    fn fail_closed_for_session_quarantine_exhaustion(&mut self) {
        for work in self.work.values_mut() {
            work.state = WorkState::TerminationPending;
        }
        self.user_token_sessions.clear();
        self.latch_fatal(FatalReason::SessionQuarantineExceeded);
    }

    pub(super) fn reap_cancelled_fixture_work(&mut self, id: WorkId) -> Result<(), LifecycleError> {
        self.require_ready()?;
        match self.work.get(&id).map(|work| work.state) {
            None => return Err(LifecycleError::UnknownWork),
            Some(WorkState::Active) => {
                return Err(LifecycleError::WorkNotCancellationPending);
            }
            Some(WorkState::CancellationPending | WorkState::TerminationPending) => {}
        }
        self.work.remove(&id);
        Ok(())
    }

    pub(super) fn begin_stop(&mut self, reason: StopReason) -> Result<(), LifecycleError> {
        match self.state {
            RuntimeState::Ready => {
                self.state = RuntimeState::Draining(reason);
                self.next_cleanup_index = 0;
                for work in self.work.values_mut() {
                    work.state = WorkState::CancellationPending;
                }
                Ok(())
            }
            RuntimeState::Draining(_) => Ok(()),
            RuntimeState::Fatal(_) => Err(LifecycleError::Fatal),
        }
    }

    pub(super) fn expected_cleanup_step(&self) -> Option<CleanupStep> {
        if !matches!(self.state, RuntimeState::Draining(_)) {
            return None;
        }
        CleanupStep::ORDERED.get(self.next_cleanup_index).copied()
    }

    pub(super) fn complete_cleanup_step(
        &mut self,
        step: CleanupStep,
    ) -> Result<(), LifecycleError> {
        if self.expected_cleanup_step() != Some(step) {
            self.latch_fatal(FatalReason::CleanupProtocolViolation);
            return Err(LifecycleError::CleanupOutOfOrder);
        }
        if matches!(
            step,
            CleanupStep::ReleaseSingleInstanceLease | CleanupStep::CommitAndRereadCleanMarker
        ) {
            self.latch_fatal(FatalReason::CleanupProtocolViolation);
            return Err(LifecycleError::InvalidCleanShutdownReceipt);
        }

        match step {
            CleanupStep::RejectNewWork
            | CleanupStep::CloseAndDrainListeners
            | CleanupStep::FlushDefinedDurableRecords
            | CleanupStep::ReleaseRequestHardwareAndStorageHandles => {}
            CleanupStep::InvalidateNonDurableAuthority | CleanupStep::CancelRequests => {
                for work in self.work.values_mut() {
                    work.state = WorkState::CancellationPending;
                }
            }
            CleanupStep::TerminateHelpers => {
                for work in self.work.values_mut() {
                    work.state = WorkState::TerminationPending;
                }
            }
            CleanupStep::ReapHelpers => self.work.clear(),
            CleanupStep::DiscardUserTokens => {
                self.user_token_sessions.clear();
                self.invalid_sessions.clear();
            }
            CleanupStep::ReleaseSingleInstanceLease | CleanupStep::CommitAndRereadCleanMarker => {
                self.latch_fatal(FatalReason::CleanupProtocolViolation);
                return Err(LifecycleError::InvalidCleanShutdownReceipt);
            }
        }
        self.next_cleanup_index += 1;
        Ok(())
    }

    pub(super) fn prepare_clean(self) -> Result<CleanBoundaryPolicy, RuntimePolicyFailure> {
        if self.expected_cleanup_step() != Some(CleanupStep::CommitAndRereadCleanMarker) {
            return Err(RuntimePolicyFailure::CleanupOutOfOrder);
        }
        if !self.work.is_empty()
            || !self.user_token_sessions.is_empty()
            || !self.invalid_sessions.is_empty()
        {
            return Err(RuntimePolicyFailure::CleanupIncomplete);
        }
        Ok(CleanBoundaryPolicy {
            startup: self.startup,
        })
    }

    pub(super) const fn is_fatal(&self) -> bool {
        matches!(self.state, RuntimeState::Fatal(_))
    }

    pub(super) fn fail_cleanup(&mut self, step: CleanupStep) -> Result<(), LifecycleError> {
        if self.expected_cleanup_step() != Some(step) {
            self.latch_fatal(FatalReason::CleanupProtocolViolation);
            return Err(LifecycleError::CleanupOutOfOrder);
        }
        self.latch_fatal(FatalReason::CleanupFailed(step));
        Ok(())
    }

    pub(super) fn cleanup_deadline_expired(&mut self) -> Result<(), LifecycleError> {
        if !matches!(self.state, RuntimeState::Draining(_)) {
            return Err(LifecycleError::NotReady);
        }
        self.latch_fatal(FatalReason::CleanupDeadlineExpired);
        Ok(())
    }

    pub(super) fn crash(&mut self) {
        self.latch_fatal(FatalReason::ServiceCrash);
    }

    fn require_ready(&self) -> Result<(), LifecycleError> {
        match self.state {
            RuntimeState::Ready => Ok(()),
            RuntimeState::Fatal(_) => Err(LifecycleError::Fatal),
            RuntimeState::Draining(_) => Err(LifecycleError::NotReady),
        }
    }

    fn latch_fatal(&mut self, reason: FatalReason) {
        if !matches!(self.state, RuntimeState::Fatal(_)) {
            self.state = RuntimeState::Fatal(reason);
        }
    }
}

impl fmt::Debug for RuntimePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePolicy")
            .field("startup", &"[REDACTED]")
            .field("state", &self.state)
            .field("work", &"[REDACTED FIXTURE WORK]")
            .field("user_token_sessions", &"[REDACTED SESSIONS]")
            .field("invalid_sessions", &"[REDACTED SESSIONS]")
            .field("next_cleanup_index", &self.next_cleanup_index)
            .finish()
    }
}

/// Compatibility wrapper that pairs the authority-independent policy with the
/// existing durable Active lease. All policy behavior remains implemented by
/// [`RuntimePolicy`]; this type only coordinates durable transitions.
struct NoSecretService<'provider> {
    policy: RuntimePolicy,
    active_run: ActiveRunLease<'provider>,
}

impl<'provider> NoSecretService<'provider> {
    fn new(active_run: ActiveRunLease<'provider>, policy: RuntimePolicy) -> Self {
        Self { policy, active_run }
    }

    fn admit_fixture_work(
        &mut self,
        id: WorkId,
        session: SessionId,
        kind: NoSecretFixtureWorkKind,
    ) -> Result<(), LifecycleError> {
        self.policy.admit_fixture_work(id, session, kind)
    }

    fn retain_user_token(&mut self, session: SessionId) -> Result<(), LifecycleError> {
        self.policy.retain_user_token(session)
    }

    fn handle_session_event(
        &mut self,
        event: SessionEvent,
    ) -> Result<SessionInvalidationReport, LifecycleError> {
        self.policy.handle_session_event(event)
    }

    fn reap_cancelled_fixture_work(&mut self, id: WorkId) -> Result<(), LifecycleError> {
        self.policy.reap_cancelled_fixture_work(id)
    }

    fn begin_stop(&mut self, reason: StopReason) -> Result<(), LifecycleError> {
        self.policy.begin_stop(reason)
    }

    fn expected_cleanup_step(&self) -> Option<CleanupStep> {
        self.policy.expected_cleanup_step()
    }

    fn complete_cleanup_step(&mut self, step: CleanupStep) -> Result<(), LifecycleError> {
        self.policy.complete_cleanup_step(step)
    }

    fn prepare_clean_commit(
        self,
    ) -> Result<CleanCommitPending<'provider>, ExitRequired<'provider>> {
        let Self { policy, active_run } = self;
        let policy = match policy.prepare_clean() {
            Ok(policy) => policy,
            Err(failure) => {
                return Err(ExitRequired::cleanup(
                    failure.into(),
                    active_run.into_writer_exit(),
                ));
            }
        };
        let transition = active_run.prepare_clean().map_err(ExitRequired::durable)?;
        Ok(CleanCommitPending { transition, policy })
    }

    fn prepare_fatal_exit(self) -> Result<ExitRequired<'provider>, LifecycleError> {
        if !self.policy.is_fatal() {
            return Err(LifecycleError::NotReady);
        }
        Ok(ExitRequired::cleanup(
            ExitReason::FatalRuntime,
            self.active_run.into_writer_exit(),
        ))
    }

    fn fail_cleanup(&mut self, step: CleanupStep) -> Result<(), LifecycleError> {
        self.policy.fail_cleanup(step)
    }

    fn cleanup_deadline_expired(&mut self) -> Result<(), LifecycleError> {
        self.policy.cleanup_deadline_expired()
    }

    fn crash(&mut self) {
        self.policy.crash();
    }
}

impl fmt::Debug for NoSecretService<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoSecretService")
            .field("state", &self.policy.state)
            .field("active_run", &"[REDACTED DURABLE AUTHORITY]")
            .field("work", &"[REDACTED FIXTURE WORK]")
            .field("user_token_sessions", &"[REDACTED SESSIONS]")
            .field("invalid_sessions", &"[REDACTED SESSIONS]")
            .field("next_cleanup_index", &self.policy.next_cleanup_index)
            .finish()
    }
}

#[cfg(test)]
#[path = "lifecycle_core_tests.rs"]
mod tests;
