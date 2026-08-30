//! No-secret Windows Key Agent service lifecycle and recovery contract.
//!
//! This production-compiled module is deliberately private and has no runtime
//! caller. It models the ordering and fail-closed decisions that future Windows
//! adapters must obey without creating an SCM listener, OS handle, secret,
//! signing operation, or release authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};

use thiserror::Error;

use super::durable_run_state::{
    ActiveReloadReceipt, ActiveReloadRequired, ActiveRunLease, BootEvidence, CleanReloadReceipt,
    CleanReloadRequired, CommittedActiveMarker, CommittedCleanMarker, DurableFailureWithWriter,
    FixtureRunStateAuthenticationKey, PendingFinalWriterRelease, PreparedActiveTransition,
    PreparedCleanTransition, RecoveryExitEvidence, RecoveryRequired, ReloadedActiveRunState,
    RereadActiveMarker, RereadCleanMarker, StoppedRunEvidence, WriterExitPending,
    WriterExitReceipt, WriterLeaseReleaseReceipt,
};

const STARTUP_REQUIREMENT_COUNT: usize = 11;
const MAX_ACTIVE_FIXTURE_WORK: usize = 256;
const MAX_RETAINED_USER_TOKEN_SESSIONS: usize = 64;
const MAX_QUARANTINED_SESSIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoSecretStartupRequirement {
    ServiceToken,
    RestrictedServiceSid,
    PrivilegeSet,
    InstalledImage,
    ServiceConfiguration,
    StorageBinding,
    ProviderBinding,
    AnchorBinding,
    FirewallPolicy,
    SingleInstanceLease,
    EnrolledUser,
}

impl NoSecretStartupRequirement {
    const ALL: [Self; STARTUP_REQUIREMENT_COUNT] = [
        Self::ServiceToken,
        Self::RestrictedServiceSid,
        Self::PrivilegeSet,
        Self::InstalledImage,
        Self::ServiceConfiguration,
        Self::StorageBinding,
        Self::ProviderBinding,
        Self::AnchorBinding,
        Self::FirewallPolicy,
        Self::SingleInstanceLease,
        Self::EnrolledUser,
    ];

    const fn index(self) -> usize {
        match self {
            Self::ServiceToken => 0,
            Self::RestrictedServiceSid => 1,
            Self::PrivilegeSet => 2,
            Self::InstalledImage => 3,
            Self::ServiceConfiguration => 4,
            Self::StorageBinding => 5,
            Self::ProviderBinding => 6,
            Self::AnchorBinding => 7,
            Self::FirewallPolicy => 8,
            Self::SingleInstanceLease => 9,
            Self::EnrolledUser => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupObservation {
    Verified,
    Mismatch,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
enum StartupFailure {
    #[error("a required no-secret startup observation is missing: {0:?}")]
    Missing(NoSecretStartupRequirement),
    #[error("a required no-secret startup observation mismatched: {0:?}")]
    Mismatch(NoSecretStartupRequirement),
    #[error("a required no-secret startup observation is unavailable: {0:?}")]
    Unavailable(NoSecretStartupRequirement),
    #[error("a no-secret startup observation was supplied more than once: {0:?}")]
    DuplicateObservation(NoSecretStartupRequirement),
    #[error("durable run-state recovery is required: {0}")]
    DurableRecovery(RecoveryRequired),
}

enum StartupWriterExit {
    NotAcquired,
    Pending(WriterExitPending),
}

struct StartupExitRequired {
    failure: StartupFailure,
    writer_exit: StartupWriterExit,
}

impl StartupExitRequired {
    const fn without_writer(failure: StartupFailure) -> Self {
        Self {
            failure,
            writer_exit: StartupWriterExit::NotAcquired,
        }
    }

    const fn with_writer(failure: StartupFailure, writer_exit: WriterExitPending) -> Self {
        Self {
            failure,
            writer_exit: StartupWriterExit::Pending(writer_exit),
        }
    }

    fn from_durable(failure: DurableFailureWithWriter) -> Self {
        let reason = failure.reason();
        Self::with_writer(
            StartupFailure::DurableRecovery(reason),
            failure.into_writer_exit(),
        )
    }

    fn into_writer_exit(self) -> Result<(StartupFailure, WriterExitPending), StartupFailure> {
        match self.writer_exit {
            StartupWriterExit::NotAcquired => Err(self.failure),
            StartupWriterExit::Pending(writer_exit) => Ok((self.failure, writer_exit)),
        }
    }
}

impl fmt::Debug for StartupExitRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupExitRequired")
            .field("failure", &self.failure)
            .field("writer_exit", &"[REDACTED]")
            .finish()
    }
}

struct NoSecretStartupAttempt {
    observations: [Option<StartupObservation>; STARTUP_REQUIREMENT_COUNT],
    boot: Result<BootEvidence, RecoveryRequired>,
    latched_failure: Option<StartupFailure>,
}

impl fmt::Debug for NoSecretStartupAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoSecretStartupAttempt([REDACTED OBSERVATIONS])")
    }
}

impl NoSecretStartupAttempt {
    fn new(boot: Result<BootEvidence, RecoveryRequired>) -> Self {
        Self {
            observations: [None; STARTUP_REQUIREMENT_COUNT],
            boot,
            latched_failure: None,
        }
    }

    fn observe(
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

    fn finish(
        self,
        key: &FixtureRunStateAuthenticationKey,
    ) -> Result<PendingNoSecretStartup, StartupExitRequired> {
        if let Some(failure) = self.latched_failure {
            return Err(self.into_exit(failure));
        }
        for requirement in NoSecretStartupRequirement::ALL {
            match self.observations[requirement.index()] {
                None => {
                    let failure = StartupFailure::Missing(requirement);
                    return Err(self.into_exit(failure));
                }
                Some(StartupObservation::Mismatch) => {
                    let failure = StartupFailure::Mismatch(requirement);
                    return Err(self.into_exit(failure));
                }
                Some(StartupObservation::Unavailable) => {
                    let failure = StartupFailure::Unavailable(requirement);
                    return Err(self.into_exit(failure));
                }
                Some(StartupObservation::Verified) => {}
            }
        }

        let boot = self.boot.map_err(|recovery| {
            StartupExitRequired::without_writer(StartupFailure::DurableRecovery(recovery))
        })?;
        let active_transition = boot
            .prepare_active(key)
            .map_err(StartupExitRequired::from_durable)?;
        Ok(PendingNoSecretStartup { active_transition })
    }

    fn into_exit(self, failure: StartupFailure) -> StartupExitRequired {
        match self.boot {
            Ok(boot) => StartupExitRequired::with_writer(failure, boot.into_writer_exit()),
            Err(_) => StartupExitRequired::without_writer(failure),
        }
    }
}

struct PendingNoSecretStartup {
    active_transition: PreparedActiveTransition,
}

impl PendingNoSecretStartup {
    fn transition_request(&self) -> &PreparedActiveTransition {
        &self.active_transition
    }

    fn commit_and_reread_active_marker(
        self,
        committed: CommittedActiveMarker,
        reread: RereadActiveMarker,
    ) -> Result<ListenerPendingRuntime, StartupExitRequired> {
        let active_run = self
            .active_transition
            .complete(committed, reread)
            .map_err(StartupExitRequired::from_durable)?;
        Ok(ListenerPendingRuntime { active_run })
    }

    fn commit_ambiguous(self) -> PendingActiveReload {
        PendingActiveReload {
            reload: self.active_transition.commit_ambiguous(),
        }
    }

    fn abort(self, reason: RecoveryRequired) -> StartupExitRequired {
        StartupExitRequired::from_durable(self.active_transition.abort(reason))
    }
}

impl fmt::Debug for PendingNoSecretStartup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingNoSecretStartup([GENERATIONS])")
    }
}

struct PendingActiveReload {
    reload: ActiveReloadRequired,
}

impl PendingActiveReload {
    fn reload_request(&self) -> &ActiveReloadRequired {
        &self.reload
    }

    fn complete(
        self,
        receipt: ActiveReloadReceipt,
        key: &FixtureRunStateAuthenticationKey,
    ) -> Result<ActiveReloadResolution, StartupExitRequired> {
        let reloaded = self
            .reload
            .complete_reload(receipt, key)
            .map_err(StartupExitRequired::from_durable)?;
        Ok(match reloaded {
            ReloadedActiveRunState::Boot(boot) => {
                ActiveReloadResolution::Revalidate(NoSecretStartupAttempt::new(Ok(boot)))
            }
            ReloadedActiveRunState::Active(active_run) => {
                ActiveReloadResolution::Resume(ListenerPendingRuntime { active_run })
            }
        })
    }

    fn abort(self, reason: RecoveryRequired) -> StartupExitRequired {
        StartupExitRequired::from_durable(self.reload.abort(reason))
    }
}

impl fmt::Debug for PendingActiveReload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingActiveReload([REDACTED])")
    }
}

enum ActiveReloadResolution {
    Revalidate(NoSecretStartupAttempt),
    Resume(ListenerPendingRuntime),
}

impl fmt::Debug for ActiveReloadResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revalidate(_) => formatter.write_str("ActiveReloadResolution::Revalidate"),
            Self::Resume(_) => formatter.write_str("ActiveReloadResolution::Resume"),
        }
    }
}

struct ListenerPendingRuntime {
    active_run: ActiveRunLease,
}

impl ListenerPendingRuntime {
    fn record_listeners_prepared(self) -> ScmRunningPendingRuntime {
        ScmRunningPendingRuntime {
            active_run: self.active_run,
        }
    }
}

impl fmt::Debug for ListenerPendingRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ListenerPendingRuntime([GENERATIONS])")
    }
}

struct ScmRunningPendingRuntime {
    active_run: ActiveRunLease,
}

impl ScmRunningPendingRuntime {
    fn record_scm_running_published(self) -> AdmissionPendingRuntime {
        AdmissionPendingRuntime {
            active_run: self.active_run,
        }
    }
}

impl fmt::Debug for ScmRunningPendingRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScmRunningPendingRuntime([GENERATIONS])")
    }
}

struct AdmissionPendingRuntime {
    active_run: ActiveRunLease,
}

impl AdmissionPendingRuntime {
    fn open_admission(self) -> NoSecretService {
        NoSecretService::new(self.active_run)
    }
}

impl fmt::Debug for AdmissionPendingRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionPendingRuntime([GENERATIONS])")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct WorkId(NonZeroU64);

impl WorkId {
    fn new(value: u64) -> Result<Self, LifecycleError> {
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
struct SessionId(NonZeroU32);

impl SessionId {
    fn new(value: u32) -> Result<Self, LifecycleError> {
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
enum NoSecretFixtureWorkKind {
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
enum StopReason {
    ScmStop,
    SystemShutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupStep {
    RejectNewWork,
    InvalidateNonDurableAuthority,
    CloseAndDrainListeners,
    CancelRequests,
    TerminateHelpers,
    ReapHelpers,
    DiscardUserTokens,
    FlushDefinedDurableRecords,
    ReleaseHardwareAndStorageHandles,
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
        Self::ReleaseHardwareAndStorageHandles,
        Self::CommitAndRereadCleanMarker,
        Self::ReleaseSingleInstanceLease,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FatalReason {
    ServiceCrash,
    SessionQuarantineExceeded,
    CleanupFailed(CleanupStep),
    CleanupDeadlineExpired,
    CleanupProtocolViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeState {
    Ready,
    Draining(StopReason),
    Fatal(FatalReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionEvent {
    Lock(SessionId),
    Unlock(SessionId),
    Logoff(SessionId),
    UserSwitch(SessionId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SessionInvalidationReport {
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
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
enum LifecycleError {
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

struct ExitRequired {
    reason: ExitReason,
    durable_recovery: Option<RecoveryRequired>,
    writer_exit: WriterExitPending,
}

impl ExitRequired {
    const fn cleanup(reason: ExitReason, writer_exit: WriterExitPending) -> Self {
        Self {
            reason,
            durable_recovery: None,
            writer_exit,
        }
    }

    fn durable(failure: DurableFailureWithWriter) -> Self {
        let recovery = failure.reason();
        Self {
            reason: ExitReason::DurableRecovery,
            durable_recovery: Some(recovery),
            writer_exit: failure.into_writer_exit(),
        }
    }

    fn writer_exit_request(&self) -> &WriterExitPending {
        &self.writer_exit
    }

    fn complete_writer_exit(
        self,
        receipt: WriterExitReceipt,
    ) -> Result<RecoveryExitPermit, DurableFailureWithWriter> {
        let retired = self.writer_exit.complete(receipt)?;
        Ok(RecoveryExitPermit {
            reason: self.reason,
            durable_recovery: self.durable_recovery,
            _retired: retired,
        })
    }
}

impl fmt::Debug for ExitRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExitRequired")
            .field("reason", &self.reason)
            .field("durable_recovery", &self.durable_recovery)
            .field("writer_exit", &"[REDACTED]")
            .finish()
    }
}

struct RecoveryExitPermit {
    reason: ExitReason,
    durable_recovery: Option<RecoveryRequired>,
    _retired: RecoveryExitEvidence,
}

impl fmt::Debug for RecoveryExitPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryExitPermit")
            .field("reason", &self.reason)
            .field("durable_recovery", &self.durable_recovery)
            .field("_retired", &"[REDACTED]")
            .finish()
    }
}

struct SingleInstanceReleasePending {
    pending: PendingFinalWriterRelease,
}

impl SingleInstanceReleasePending {
    fn release_request(&self) -> &PendingFinalWriterRelease {
        &self.pending
    }

    fn complete(self, receipt: WriterLeaseReleaseReceipt) -> Result<StoppedPermit, ExitRequired> {
        let stopped = self
            .pending
            .complete(receipt)
            .map_err(ExitRequired::durable)?;
        Ok(StoppedPermit::from_durable_evidence(stopped))
    }

    fn abort(self, reason: RecoveryRequired) -> ExitRequired {
        ExitRequired::durable(self.pending.abort(reason))
    }
}

impl fmt::Debug for SingleInstanceReleasePending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleInstanceReleasePending([REDACTED])")
    }
}

struct CleanCommitPending {
    transition: PreparedCleanTransition,
}

impl CleanCommitPending {
    fn transition_request(&self) -> &PreparedCleanTransition {
        &self.transition
    }

    fn commit_and_reread_clean_marker(
        self,
        committed: CommittedCleanMarker,
        reread: RereadCleanMarker,
    ) -> Result<SingleInstanceReleasePending, ExitRequired> {
        let committed = self
            .transition
            .complete(committed, reread)
            .map_err(ExitRequired::durable)?;
        Ok(SingleInstanceReleasePending {
            pending: committed.prepare_writer_release(),
        })
    }

    fn commit_ambiguous(self) -> PendingCleanReload {
        PendingCleanReload {
            reload: self.transition.commit_ambiguous(),
        }
    }

    fn abort(self, reason: RecoveryRequired) -> ExitRequired {
        ExitRequired::durable(self.transition.abort(reason))
    }
}

impl fmt::Debug for CleanCommitPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanCommitPending([GENERATIONS])")
    }
}

struct PendingCleanReload {
    reload: CleanReloadRequired,
}

impl PendingCleanReload {
    fn reload_request(&self) -> &CleanReloadRequired {
        &self.reload
    }

    fn complete(
        self,
        receipt: CleanReloadReceipt,
        key: &FixtureRunStateAuthenticationKey,
    ) -> Result<SingleInstanceReleasePending, ExitRequired> {
        let committed = self
            .reload
            .complete_reload(receipt, key)
            .map_err(ExitRequired::durable)?;
        Ok(SingleInstanceReleasePending {
            pending: committed.prepare_writer_release(),
        })
    }

    fn abort(self, reason: RecoveryRequired) -> ExitRequired {
        ExitRequired::durable(self.reload.abort(reason))
    }
}

impl fmt::Debug for PendingCleanReload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingCleanReload([REDACTED])")
    }
}

struct StoppedPermit {
    stopped: StoppedRunEvidence,
}

impl StoppedPermit {
    const fn from_durable_evidence(stopped: StoppedRunEvidence) -> Self {
        Self { stopped }
    }
}

impl fmt::Debug for StoppedPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoppedPermit([REDACTED DURABLE EVIDENCE])")
    }
}

struct NoSecretService {
    state: RuntimeState,
    active_run: ActiveRunLease,
    work: BTreeMap<WorkId, FixtureWork>,
    user_token_sessions: BTreeSet<SessionId>,
    invalid_sessions: BTreeSet<SessionId>,
    next_cleanup_index: usize,
}

impl NoSecretService {
    fn new(active_run: ActiveRunLease) -> Self {
        Self {
            state: RuntimeState::Ready,
            active_run,
            work: BTreeMap::new(),
            user_token_sessions: BTreeSet::new(),
            invalid_sessions: BTreeSet::new(),
            next_cleanup_index: 0,
        }
    }

    fn admit_fixture_work(
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

    fn retain_user_token(&mut self, session: SessionId) -> Result<(), LifecycleError> {
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

    fn handle_session_event(
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

    fn reap_cancelled_fixture_work(&mut self, id: WorkId) -> Result<(), LifecycleError> {
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

    fn begin_stop(&mut self, reason: StopReason) -> Result<(), LifecycleError> {
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

    fn expected_cleanup_step(&self) -> Option<CleanupStep> {
        if !matches!(self.state, RuntimeState::Draining(_)) {
            return None;
        }
        CleanupStep::ORDERED.get(self.next_cleanup_index).copied()
    }

    fn complete_cleanup_step(&mut self, step: CleanupStep) -> Result<(), LifecycleError> {
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
            | CleanupStep::ReleaseHardwareAndStorageHandles => {}
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
            CleanupStep::DiscardUserTokens => self.user_token_sessions.clear(),
            CleanupStep::ReleaseSingleInstanceLease | CleanupStep::CommitAndRereadCleanMarker => {
                self.latch_fatal(FatalReason::CleanupProtocolViolation);
                return Err(LifecycleError::InvalidCleanShutdownReceipt);
            }
        }
        self.next_cleanup_index += 1;
        Ok(())
    }

    fn prepare_clean_commit(
        self,
        key: &FixtureRunStateAuthenticationKey,
    ) -> Result<CleanCommitPending, ExitRequired> {
        if self.expected_cleanup_step() != Some(CleanupStep::CommitAndRereadCleanMarker) {
            return Err(ExitRequired::cleanup(
                ExitReason::CleanupOutOfOrder,
                self.active_run.into_writer_exit(),
            ));
        }
        if !self.work.is_empty() || !self.user_token_sessions.is_empty() {
            return Err(ExitRequired::cleanup(
                ExitReason::CleanupIncomplete,
                self.active_run.into_writer_exit(),
            ));
        }
        let transition = self
            .active_run
            .prepare_clean(key)
            .map_err(ExitRequired::durable)?;
        Ok(CleanCommitPending { transition })
    }

    fn prepare_fatal_exit(self) -> Result<ExitRequired, LifecycleError> {
        if !matches!(self.state, RuntimeState::Fatal(_)) {
            return Err(LifecycleError::NotReady);
        }
        Ok(ExitRequired::cleanup(
            ExitReason::FatalRuntime,
            self.active_run.into_writer_exit(),
        ))
    }

    fn fail_cleanup(&mut self, step: CleanupStep) -> Result<(), LifecycleError> {
        if self.expected_cleanup_step() != Some(step) {
            self.latch_fatal(FatalReason::CleanupProtocolViolation);
            return Err(LifecycleError::CleanupOutOfOrder);
        }
        self.latch_fatal(FatalReason::CleanupFailed(step));
        Ok(())
    }

    fn cleanup_deadline_expired(&mut self) -> Result<(), LifecycleError> {
        if !matches!(self.state, RuntimeState::Draining(_)) {
            return Err(LifecycleError::NotReady);
        }
        self.latch_fatal(FatalReason::CleanupDeadlineExpired);
        Ok(())
    }

    fn crash(&mut self) {
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

impl fmt::Debug for NoSecretService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoSecretService")
            .field("state", &self.state)
            .field("active_run", &"[REDACTED DURABLE AUTHORITY]")
            .field("work", &"[REDACTED FIXTURE WORK]")
            .field("user_token_sessions", &"[REDACTED SESSIONS]")
            .field("invalid_sessions", &"[REDACTED SESSIONS]")
            .field("next_cleanup_index", &self.next_cleanup_index)
            .finish()
    }
}

#[cfg(test)]
#[path = "lifecycle_core_tests.rs"]
mod tests;
