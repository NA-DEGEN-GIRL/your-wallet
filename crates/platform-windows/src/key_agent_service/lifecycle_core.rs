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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryReason {
    ActiveRunMarker,
    PersistedRecoveryRequired,
    MissingRunMarker,
    InvalidRunMarker,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DurableRunObservation {
    CleanShutdown { generation: u64 },
    ActiveRun { generation: u64 },
    RecoveryRequired,
    Missing,
    Invalid,
}

impl fmt::Debug for DurableRunObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CleanShutdown { .. } => {
                formatter.write_str("DurableRunObservation::CleanShutdown([GENERATION])")
            }
            Self::ActiveRun { .. } => {
                formatter.write_str("DurableRunObservation::ActiveRun([GENERATION])")
            }
            Self::RecoveryRequired => {
                formatter.write_str("DurableRunObservation::RecoveryRequired")
            }
            Self::Missing => formatter.write_str("DurableRunObservation::Missing"),
            Self::Invalid => formatter.write_str("DurableRunObservation::Invalid"),
        }
    }
}

struct CommittedRunMarkerObservation(DurableRunObservation);

impl CommittedRunMarkerObservation {
    const fn into_observation(self) -> DurableRunObservation {
        self.0
    }
}

impl fmt::Debug for CommittedRunMarkerObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedRunMarkerObservation([REDACTED])")
    }
}

struct RereadRunMarkerObservation(DurableRunObservation);

impl RereadRunMarkerObservation {
    const fn into_observation(self) -> DurableRunObservation {
        self.0
    }
}

impl fmt::Debug for RereadRunMarkerObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RereadRunMarkerObservation([REDACTED])")
    }
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
    #[error("service recovery is required: {0:?}")]
    RecoveryRequired(RecoveryReason),
    #[error("the clean-shutdown generation is invalid")]
    InvalidCleanShutdownGeneration,
    #[error("the clean-shutdown generation is exhausted")]
    CleanShutdownGenerationExhausted,
    #[error("the active-run marker commit did not match the expected generation")]
    ActiveMarkerCommitMismatch,
    #[error("the active-run marker readback did not match the committed generation")]
    ActiveMarkerReadbackMismatch,
}

struct NoSecretStartupAttempt {
    observations: [Option<StartupObservation>; STARTUP_REQUIREMENT_COUNT],
    durable_run: DurableRunObservation,
    latched_failure: Option<StartupFailure>,
}

impl fmt::Debug for NoSecretStartupAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoSecretStartupAttempt([REDACTED OBSERVATIONS])")
    }
}

impl NoSecretStartupAttempt {
    fn new(durable_run: DurableRunObservation) -> Self {
        Self {
            observations: [None; STARTUP_REQUIREMENT_COUNT],
            durable_run,
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

    fn finish(self) -> Result<PendingNoSecretStartup, StartupFailure> {
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

        let clean_generation = match self.durable_run {
            DurableRunObservation::CleanShutdown { generation: 0 } => {
                return Err(StartupFailure::InvalidCleanShutdownGeneration);
            }
            DurableRunObservation::CleanShutdown { generation } => generation,
            DurableRunObservation::ActiveRun { .. } => {
                return Err(StartupFailure::RecoveryRequired(
                    RecoveryReason::ActiveRunMarker,
                ));
            }
            DurableRunObservation::RecoveryRequired => {
                return Err(StartupFailure::RecoveryRequired(
                    RecoveryReason::PersistedRecoveryRequired,
                ));
            }
            DurableRunObservation::Missing => {
                return Err(StartupFailure::RecoveryRequired(
                    RecoveryReason::MissingRunMarker,
                ));
            }
            DurableRunObservation::Invalid => {
                return Err(StartupFailure::RecoveryRequired(
                    RecoveryReason::InvalidRunMarker,
                ));
            }
        };
        let active_generation = clean_generation
            .checked_add(1)
            .ok_or(StartupFailure::CleanShutdownGenerationExhausted)?;
        let next_clean_shutdown_generation = active_generation
            .checked_add(1)
            .ok_or(StartupFailure::CleanShutdownGenerationExhausted)?;

        Ok(PendingNoSecretStartup {
            active_generation: NonZeroU64::new(active_generation)
                .ok_or(StartupFailure::InvalidCleanShutdownGeneration)?,
            next_clean_shutdown_generation: NonZeroU64::new(next_clean_shutdown_generation)
                .ok_or(StartupFailure::InvalidCleanShutdownGeneration)?,
        })
    }
}

struct PendingNoSecretStartup {
    active_generation: NonZeroU64,
    next_clean_shutdown_generation: NonZeroU64,
}

impl PendingNoSecretStartup {
    fn commit_and_reread_active_marker(
        self,
        committed: CommittedRunMarkerObservation,
        reread: RereadRunMarkerObservation,
    ) -> Result<ListenerPendingRuntime, StartupFailure> {
        let committed = committed.into_observation();
        let reread = reread.into_observation();
        let expected = self.active_generation.get();
        if committed
            != (DurableRunObservation::ActiveRun {
                generation: expected,
            })
        {
            return Err(StartupFailure::ActiveMarkerCommitMismatch);
        }
        if reread != committed {
            return Err(StartupFailure::ActiveMarkerReadbackMismatch);
        }
        Ok(ListenerPendingRuntime {
            active_generation: self.active_generation,
            next_clean_shutdown_generation: self.next_clean_shutdown_generation,
        })
    }
}

impl fmt::Debug for PendingNoSecretStartup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingNoSecretStartup([GENERATIONS])")
    }
}

struct ListenerPendingRuntime {
    active_generation: NonZeroU64,
    next_clean_shutdown_generation: NonZeroU64,
}

impl ListenerPendingRuntime {
    fn record_listeners_prepared(self) -> ScmRunningPendingRuntime {
        ScmRunningPendingRuntime {
            active_generation: self.active_generation,
            next_clean_shutdown_generation: self.next_clean_shutdown_generation,
        }
    }
}

impl fmt::Debug for ListenerPendingRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ListenerPendingRuntime([GENERATIONS])")
    }
}

struct ScmRunningPendingRuntime {
    active_generation: NonZeroU64,
    next_clean_shutdown_generation: NonZeroU64,
}

impl ScmRunningPendingRuntime {
    fn record_scm_running_published(self) -> AdmissionPendingRuntime {
        AdmissionPendingRuntime {
            active_generation: self.active_generation,
            next_clean_shutdown_generation: self.next_clean_shutdown_generation,
        }
    }
}

impl fmt::Debug for ScmRunningPendingRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScmRunningPendingRuntime([GENERATIONS])")
    }
}

struct AdmissionPendingRuntime {
    active_generation: NonZeroU64,
    next_clean_shutdown_generation: NonZeroU64,
}

impl AdmissionPendingRuntime {
    fn open_admission(self) -> NoSecretService {
        NoSecretService::new(self.active_generation, self.next_clean_shutdown_generation)
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
    ReleaseSingleInstanceLease,
    CommitAndRereadCleanMarker,
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
        Self::ReleaseSingleInstanceLease,
        Self::CommitAndRereadCleanMarker,
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

#[derive(Clone, Copy, Eq, PartialEq)]
struct CleanShutdownRecord {
    generation: NonZeroU64,
}

impl CleanShutdownRecord {
    const fn recovery_observation(self) -> DurableRunObservation {
        DurableRunObservation::CleanShutdown {
            generation: self.generation.get(),
        }
    }
}

impl fmt::Debug for CleanShutdownRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanShutdownRecord([GENERATION])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExitReason {
    CleanupOutOfOrder,
    InvalidCleanShutdownReceipt,
    CleanupIncomplete,
}

struct ExitRequired {
    restart_observation: DurableRunObservation,
    reason: ExitReason,
}

impl ExitRequired {
    const fn restart_observation(&self) -> DurableRunObservation {
        self.restart_observation
    }
}

impl fmt::Debug for ExitRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExitRequired")
            .field("restart_observation", &"[REDACTED]")
            .field("reason", &self.reason)
            .finish()
    }
}

struct CleanCommitPending {
    active_generation: NonZeroU64,
    next_clean_shutdown_generation: NonZeroU64,
}

impl CleanCommitPending {
    fn commit_and_reread_clean_marker(
        self,
        committed: CommittedRunMarkerObservation,
        reread: RereadRunMarkerObservation,
    ) -> Result<StoppedPermit, ExitRequired> {
        let committed = committed.into_observation();
        let reread = reread.into_observation();
        let expected = DurableRunObservation::CleanShutdown {
            generation: self.next_clean_shutdown_generation.get(),
        };
        if committed != expected || reread != expected {
            return Err(ExitRequired {
                restart_observation: DurableRunObservation::RecoveryRequired,
                reason: ExitReason::InvalidCleanShutdownReceipt,
            });
        }
        Ok(StoppedPermit {
            clean_shutdown: CleanShutdownRecord {
                generation: self.next_clean_shutdown_generation,
            },
        })
    }
}

impl fmt::Debug for CleanCommitPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanCommitPending([GENERATIONS])")
    }
}

struct StoppedPermit {
    clean_shutdown: CleanShutdownRecord,
}

impl StoppedPermit {
    const fn restart_observation(&self) -> DurableRunObservation {
        self.clean_shutdown.recovery_observation()
    }
}

impl fmt::Debug for StoppedPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoppedPermit([CLEAN GENERATION])")
    }
}

struct NoSecretService {
    state: RuntimeState,
    active_generation: NonZeroU64,
    work: BTreeMap<WorkId, FixtureWork>,
    user_token_sessions: BTreeSet<SessionId>,
    invalid_sessions: BTreeSet<SessionId>,
    next_cleanup_index: usize,
    next_clean_shutdown_generation: NonZeroU64,
    single_instance_released: bool,
}

impl NoSecretService {
    fn new(active_generation: NonZeroU64, next_clean_shutdown_generation: NonZeroU64) -> Self {
        Self {
            state: RuntimeState::Ready,
            active_generation,
            work: BTreeMap::new(),
            user_token_sessions: BTreeSet::new(),
            invalid_sessions: BTreeSet::new(),
            next_cleanup_index: 0,
            next_clean_shutdown_generation,
            single_instance_released: false,
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
        if step == CleanupStep::CommitAndRereadCleanMarker {
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
            CleanupStep::ReleaseSingleInstanceLease => {
                self.single_instance_released = true;
            }
            CleanupStep::CommitAndRereadCleanMarker => {
                self.latch_fatal(FatalReason::CleanupProtocolViolation);
                return Err(LifecycleError::InvalidCleanShutdownReceipt);
            }
        }
        self.next_cleanup_index += 1;
        Ok(())
    }

    fn prepare_clean_commit(self) -> Result<CleanCommitPending, ExitRequired> {
        if self.expected_cleanup_step() != Some(CleanupStep::CommitAndRereadCleanMarker) {
            return Err(ExitRequired {
                restart_observation: DurableRunObservation::ActiveRun {
                    generation: self.active_generation.get(),
                },
                reason: ExitReason::CleanupOutOfOrder,
            });
        }
        if !self.work.is_empty()
            || !self.user_token_sessions.is_empty()
            || !self.single_instance_released
        {
            return Err(ExitRequired {
                restart_observation: DurableRunObservation::ActiveRun {
                    generation: self.active_generation.get(),
                },
                reason: ExitReason::CleanupIncomplete,
            });
        }
        Ok(CleanCommitPending {
            active_generation: self.active_generation,
            next_clean_shutdown_generation: self.next_clean_shutdown_generation,
        })
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

    const fn restart_observation(&self) -> DurableRunObservation {
        DurableRunObservation::ActiveRun {
            generation: self.active_generation.get(),
        }
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
            .field("active_generation", &"[GENERATION]")
            .field("work", &"[REDACTED FIXTURE WORK]")
            .field("user_token_sessions", &"[REDACTED SESSIONS]")
            .field("invalid_sessions", &"[REDACTED SESSIONS]")
            .field("next_cleanup_index", &self.next_cleanup_index)
            .field("next_clean_shutdown_generation", &"[GENERATION]")
            .field("single_instance_released", &self.single_instance_released)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        CleanupStep, CommittedRunMarkerObservation, DurableRunObservation, ExitReason, FatalReason,
        LifecycleError, MAX_ACTIVE_FIXTURE_WORK, MAX_QUARANTINED_SESSIONS,
        MAX_RETAINED_USER_TOKEN_SESSIONS, NoSecretFixtureWorkKind, NoSecretService,
        NoSecretStartupAttempt, NoSecretStartupRequirement, PendingNoSecretStartup, RecoveryReason,
        RereadRunMarkerObservation, RuntimeState, SessionEvent, SessionId,
        SessionInvalidationReport, StartupFailure, StartupObservation, StopReason, WorkId,
        WorkState,
    };

    fn pending_startup(
        durable_run: DurableRunObservation,
    ) -> Result<PendingNoSecretStartup, StartupFailure> {
        let mut attempt = NoSecretStartupAttempt::new(durable_run);
        for requirement in NoSecretStartupRequirement::ALL {
            attempt.observe(requirement, StartupObservation::Verified)?;
        }
        attempt.finish()
    }

    fn ready_service(clean_generation: u64) -> Result<NoSecretService, StartupFailure> {
        let pending = pending_startup(DurableRunObservation::CleanShutdown {
            generation: clean_generation,
        })?;
        let active = DurableRunObservation::ActiveRun {
            generation: pending.active_generation.get(),
        };
        Ok(pending
            .commit_and_reread_active_marker(
                CommittedRunMarkerObservation(active),
                RereadRunMarkerObservation(active),
            )?
            .record_listeners_prepared()
            .record_scm_running_published()
            .open_admission())
    }

    fn finish_nonfinal_cleanup_step(
        service: &mut NoSecretService,
        step: CleanupStep,
    ) -> Result<(), LifecycleError> {
        assert_ne!(step, CleanupStep::CommitAndRereadCleanMarker);
        service.complete_cleanup_step(step)
    }

    #[test]
    fn every_startup_requirement_is_mandatory() -> Result<(), Box<dyn Error>> {
        for missing in NoSecretStartupRequirement::ALL {
            let mut attempt =
                NoSecretStartupAttempt::new(DurableRunObservation::CleanShutdown { generation: 1 });
            for requirement in NoSecretStartupRequirement::ALL {
                if requirement != missing {
                    attempt.observe(requirement, StartupObservation::Verified)?;
                }
            }
            assert_eq!(
                attempt.finish().map(|_| ()),
                Err(StartupFailure::Missing(missing))
            );
        }
        Ok(())
    }

    #[test]
    fn mismatched_unavailable_and_duplicate_observations_fail_closed() -> Result<(), Box<dyn Error>>
    {
        for rejected in NoSecretStartupRequirement::ALL {
            for observation in [
                StartupObservation::Mismatch,
                StartupObservation::Unavailable,
            ] {
                let mut attempt =
                    NoSecretStartupAttempt::new(DurableRunObservation::CleanShutdown {
                        generation: 1,
                    });
                for requirement in NoSecretStartupRequirement::ALL {
                    let observed = if requirement == rejected {
                        observation
                    } else {
                        StartupObservation::Verified
                    };
                    attempt.observe(requirement, observed)?;
                }
                let expected = match observation {
                    StartupObservation::Mismatch => StartupFailure::Mismatch(rejected),
                    StartupObservation::Unavailable => StartupFailure::Unavailable(rejected),
                    StartupObservation::Verified => return Err("invalid test case".into()),
                };
                assert_eq!(attempt.finish().map(|_| ()), Err(expected));
            }
        }

        let requirement = NoSecretStartupRequirement::ServiceConfiguration;
        let mut attempt =
            NoSecretStartupAttempt::new(DurableRunObservation::CleanShutdown { generation: 1 });
        attempt.observe(requirement, StartupObservation::Mismatch)?;
        assert_eq!(
            attempt.observe(requirement, StartupObservation::Verified),
            Err(StartupFailure::DuplicateObservation(requirement))
        );
        for remaining in NoSecretStartupRequirement::ALL {
            if remaining != requirement {
                attempt.observe(remaining, StartupObservation::Verified)?;
            }
        }
        assert_eq!(
            attempt.finish().map(|_| ()),
            Err(StartupFailure::DuplicateObservation(requirement))
        );
        Ok(())
    }

    #[test]
    fn only_exact_clean_marker_can_enter_the_ordered_startup_chain() -> Result<(), Box<dyn Error>> {
        let clean = ready_service(7)?;
        assert_eq!(clean.active_generation.get(), 8);
        assert_eq!(clean.next_clean_shutdown_generation.get(), 9);

        assert_eq!(
            pending_startup(DurableRunObservation::CleanShutdown { generation: 0 }).map(|_| ()),
            Err(StartupFailure::InvalidCleanShutdownGeneration)
        );
        for (observation, reason) in [
            (
                DurableRunObservation::ActiveRun { generation: 7 },
                RecoveryReason::ActiveRunMarker,
            ),
            (
                DurableRunObservation::RecoveryRequired,
                RecoveryReason::PersistedRecoveryRequired,
            ),
            (
                DurableRunObservation::Missing,
                RecoveryReason::MissingRunMarker,
            ),
            (
                DurableRunObservation::Invalid,
                RecoveryReason::InvalidRunMarker,
            ),
        ] {
            assert_eq!(
                pending_startup(observation).map(|_| ()),
                Err(StartupFailure::RecoveryRequired(reason))
            );
        }
        for generation in [u64::MAX - 1, u64::MAX] {
            assert_eq!(
                pending_startup(DurableRunObservation::CleanShutdown { generation }).map(|_| ()),
                Err(StartupFailure::CleanShutdownGenerationExhausted)
            );
        }
        Ok(())
    }

    #[test]
    fn active_marker_commit_and_readback_are_exact_before_listener_preparation()
    -> Result<(), Box<dyn Error>> {
        let pending = pending_startup(DurableRunObservation::CleanShutdown { generation: 10 })?;
        assert_eq!(
            pending
                .commit_and_reread_active_marker(
                    CommittedRunMarkerObservation(DurableRunObservation::ActiveRun {
                        generation: 12,
                    }),
                    RereadRunMarkerObservation(DurableRunObservation::ActiveRun { generation: 12 }),
                )
                .map(|_| ()),
            Err(StartupFailure::ActiveMarkerCommitMismatch)
        );

        let pending = pending_startup(DurableRunObservation::CleanShutdown { generation: 10 })?;
        assert_eq!(
            pending
                .commit_and_reread_active_marker(
                    CommittedRunMarkerObservation(DurableRunObservation::ActiveRun {
                        generation: 11,
                    }),
                    RereadRunMarkerObservation(DurableRunObservation::CleanShutdown {
                        generation: 10,
                    }),
                )
                .map(|_| ()),
            Err(StartupFailure::ActiveMarkerReadbackMismatch)
        );

        let service = ready_service(10)?;
        assert_eq!(service.state, RuntimeState::Ready);
        assert_eq!(
            service.restart_observation(),
            DurableRunObservation::ActiveRun { generation: 11 }
        );
        Ok(())
    }

    #[test]
    fn lock_and_unlock_invalidate_exact_session_without_discarding_its_user_token()
    -> Result<(), Box<dyn Error>> {
        let first_session = SessionId::new(11)?;
        let second_session = SessionId::new(12)?;
        let first_work = WorkId::new(101)?;
        let second_work = WorkId::new(102)?;
        let mut service = ready_service(1)?;
        service.retain_user_token(first_session)?;
        service.retain_user_token(second_session)?;
        service.admit_fixture_work(first_work, first_session, NoSecretFixtureWorkKind::Approval)?;
        service.admit_fixture_work(
            second_work,
            second_session,
            NoSecretFixtureWorkKind::SecretInput,
        )?;

        let report = service.handle_session_event(SessionEvent::Lock(first_session))?;
        assert_eq!(report.authorities_invalidated, 1);
        assert_eq!(report.helper_terminations_required, 1);
        assert_eq!(report.user_tokens_discarded, 0);
        assert!(report.revalidation_required);
        assert!(service.user_token_sessions.contains(&first_session));
        assert_eq!(
            service.admit_fixture_work(
                WorkId::new(103)?,
                first_session,
                NoSecretFixtureWorkKind::Approval,
            ),
            Err(LifecycleError::SessionInvalidated)
        );
        service.reap_cancelled_fixture_work(first_work)?;
        assert!(service.work.contains_key(&second_work));

        let missed_lock_session = SessionId::new(13)?;
        let missed_lock_work = WorkId::new(104)?;
        let mut unlock_service = ready_service(1)?;
        unlock_service.retain_user_token(missed_lock_session)?;
        unlock_service.admit_fixture_work(
            missed_lock_work,
            missed_lock_session,
            NoSecretFixtureWorkKind::Approval,
        )?;
        let unlock =
            unlock_service.handle_session_event(SessionEvent::Unlock(missed_lock_session))?;
        assert_eq!(unlock.authorities_invalidated, 1);
        assert_eq!(unlock.helper_terminations_required, 1);
        assert_eq!(unlock.user_tokens_discarded, 0);
        assert_eq!(
            unlock_service
                .work
                .get(&missed_lock_work)
                .map(|work| work.state),
            Some(WorkState::CancellationPending)
        );
        Ok(())
    }

    #[test]
    fn logoff_and_user_switch_discard_user_tokens_and_require_helper_reap()
    -> Result<(), Box<dyn Error>> {
        let first_session = SessionId::new(21)?;
        let second_session = SessionId::new(22)?;
        let first_work = WorkId::new(201)?;
        let second_work = WorkId::new(202)?;
        let mut service = ready_service(1)?;
        service.retain_user_token(first_session)?;
        service.retain_user_token(second_session)?;
        service.admit_fixture_work(first_work, first_session, NoSecretFixtureWorkKind::Approval)?;
        service.admit_fixture_work(
            second_work,
            second_session,
            NoSecretFixtureWorkKind::SecretInput,
        )?;

        let logoff = service.handle_session_event(SessionEvent::Logoff(first_session))?;
        assert_eq!(logoff.authorities_invalidated, 1);
        assert_eq!(logoff.user_tokens_discarded, 1);
        assert!(!service.user_token_sessions.contains(&first_session));

        let switched = service.handle_session_event(SessionEvent::UserSwitch(second_session))?;
        assert_eq!(switched.authorities_invalidated, 1);
        assert_eq!(switched.helper_terminations_required, 1);
        assert_eq!(switched.user_tokens_discarded, 1);
        assert!(service.user_token_sessions.is_empty());
        assert_eq!(
            service.handle_session_event(SessionEvent::Unlock(first_session))?,
            SessionInvalidationReport::empty(true)
        );
        assert_eq!(
            service.admit_fixture_work(
                WorkId::new(203)?,
                first_session,
                NoSecretFixtureWorkKind::Approval,
            ),
            Err(LifecycleError::SessionInvalidated)
        );
        Ok(())
    }

    #[test]
    fn session_quarantine_exhaustion_fails_closed_and_discards_live_authority()
    -> Result<(), Box<dyn Error>> {
        let live_session = SessionId::new(999)?;
        let live_work = WorkId::new(901)?;
        let mut service = ready_service(1)?;
        service.retain_user_token(live_session)?;
        service.admit_fixture_work(
            live_work,
            live_session,
            NoSecretFixtureWorkKind::SecretInput,
        )?;

        let max_quarantined_sessions = u32::try_from(MAX_QUARANTINED_SESSIONS)?;
        for value in 1..=max_quarantined_sessions {
            service.handle_session_event(SessionEvent::Unlock(SessionId::new(value)?))?;
        }
        assert_eq!(service.invalid_sessions.len(), MAX_QUARANTINED_SESSIONS);
        assert_eq!(
            service.handle_session_event(SessionEvent::Lock(SessionId::new(100)?)),
            Err(LifecycleError::SessionQuarantineExhausted)
        );
        assert_eq!(
            service.state,
            RuntimeState::Fatal(FatalReason::SessionQuarantineExceeded)
        );
        assert!(service.user_token_sessions.is_empty());
        assert_eq!(
            service.work.get(&live_work).map(|work| work.state),
            Some(WorkState::TerminationPending)
        );
        service.crash();
        assert_eq!(
            service.state,
            RuntimeState::Fatal(FatalReason::SessionQuarantineExceeded)
        );
        assert_eq!(
            service.restart_observation(),
            DurableRunObservation::ActiveRun { generation: 2 }
        );

        let switch_live_session = SessionId::new(999)?;
        let switch_live_work = WorkId::new(902)?;
        let mut switch_service = ready_service(1)?;
        switch_service.admit_fixture_work(
            switch_live_work,
            switch_live_session,
            NoSecretFixtureWorkKind::Approval,
        )?;
        let max_retained_sessions = u32::try_from(MAX_RETAINED_USER_TOKEN_SESSIONS)?;
        for value in 1..=max_retained_sessions {
            switch_service.retain_user_token(SessionId::new(value)?)?;
        }
        assert_eq!(
            switch_service.handle_session_event(SessionEvent::UserSwitch(SessionId::new(1_000)?)),
            Err(LifecycleError::SessionQuarantineExhausted)
        );
        assert_eq!(
            switch_service.state,
            RuntimeState::Fatal(FatalReason::SessionQuarantineExceeded)
        );
        assert!(switch_service.user_token_sessions.is_empty());
        assert_eq!(
            switch_service
                .work
                .get(&switch_live_work)
                .map(|work| work.state),
            Some(WorkState::TerminationPending)
        );
        assert_eq!(
            switch_service.restart_observation(),
            DurableRunObservation::ActiveRun { generation: 2 }
        );
        Ok(())
    }

    #[test]
    fn runtime_registries_are_bounded_before_mutation() -> Result<(), Box<dyn Error>> {
        let shared_session = SessionId::new(500)?;
        let mut work_service = ready_service(1)?;
        let max_active_fixture_work = u64::try_from(MAX_ACTIVE_FIXTURE_WORK)?;
        for value in 1..=max_active_fixture_work {
            work_service.admit_fixture_work(
                WorkId::new(value)?,
                shared_session,
                NoSecretFixtureWorkKind::Approval,
            )?;
        }
        assert_eq!(work_service.work.len(), MAX_ACTIVE_FIXTURE_WORK);
        assert_eq!(
            work_service.admit_fixture_work(
                WorkId::new(max_active_fixture_work + 1)?,
                shared_session,
                NoSecretFixtureWorkKind::Approval,
            ),
            Err(LifecycleError::WorkCapacityExhausted)
        );
        assert_eq!(work_service.work.len(), MAX_ACTIVE_FIXTURE_WORK);

        let mut token_service = ready_service(1)?;
        let max_retained_user_token_sessions = u32::try_from(MAX_RETAINED_USER_TOKEN_SESSIONS)?;
        for value in 1..=max_retained_user_token_sessions {
            token_service.retain_user_token(SessionId::new(value)?)?;
        }
        assert_eq!(
            token_service.user_token_sessions.len(),
            MAX_RETAINED_USER_TOKEN_SESSIONS
        );
        token_service.retain_user_token(SessionId::new(1)?)?;
        assert_eq!(
            token_service.retain_user_token(SessionId::new(max_retained_user_token_sessions + 1,)?),
            Err(LifecycleError::UserTokenCapacityExhausted)
        );
        assert_eq!(
            token_service.user_token_sessions.len(),
            MAX_RETAINED_USER_TOKEN_SESSIONS
        );
        Ok(())
    }

    #[test]
    fn stop_closes_admission_and_clean_commit_atomically_mints_stopped_permit()
    -> Result<(), Box<dyn Error>> {
        let session = SessionId::new(31)?;
        let mut service = ready_service(1)?;
        service.retain_user_token(session)?;
        service.admit_fixture_work(
            WorkId::new(301)?,
            session,
            NoSecretFixtureWorkKind::Approval,
        )?;

        service.begin_stop(StopReason::ScmStop)?;
        service.begin_stop(StopReason::SystemShutdown)?;
        assert_eq!(
            service.expected_cleanup_step(),
            Some(CleanupStep::RejectNewWork)
        );
        assert_eq!(
            service.admit_fixture_work(
                WorkId::new(302)?,
                session,
                NoSecretFixtureWorkKind::SecretInput,
            ),
            Err(LifecycleError::NotReady)
        );
        for step in CleanupStep::ORDERED
            .iter()
            .take(CleanupStep::ORDERED.len() - 1)
            .copied()
        {
            assert_eq!(service.expected_cleanup_step(), Some(step));
            finish_nonfinal_cleanup_step(&mut service, step)?;
        }
        assert_eq!(
            service.expected_cleanup_step(),
            Some(CleanupStep::CommitAndRereadCleanMarker)
        );
        let clean = DurableRunObservation::CleanShutdown { generation: 3 };
        let Ok(clean_pending) = service.prepare_clean_commit() else {
            return Err("exact cleanup prerequisites unexpectedly required exit".into());
        };
        let Ok(stopped) = clean_pending.commit_and_reread_clean_marker(
            CommittedRunMarkerObservation(clean),
            RereadRunMarkerObservation(clean),
        ) else {
            return Err("exact clean marker unexpectedly required exit".into());
        };
        assert_eq!(
            stopped.restart_observation(),
            DurableRunObservation::CleanShutdown { generation: 3 }
        );

        let restarted = ready_service(3)?;
        assert_eq!(restarted.active_generation.get(), 4);
        assert_eq!(restarted.next_clean_shutdown_generation.get(), 5);
        Ok(())
    }

    #[test]
    fn every_cleanup_failure_requires_recovery_and_never_reports_stopped()
    -> Result<(), Box<dyn Error>> {
        for failed_index in 0..CleanupStep::ORDERED.len() {
            let mut service = ready_service(1)?;
            service.begin_stop(StopReason::ScmStop)?;
            for step in CleanupStep::ORDERED.iter().take(failed_index).copied() {
                finish_nonfinal_cleanup_step(&mut service, step)?;
            }
            let failed = CleanupStep::ORDERED[failed_index];
            service.fail_cleanup(failed)?;
            assert_eq!(service.expected_cleanup_step(), None);
            assert_eq!(
                service.state,
                RuntimeState::Fatal(FatalReason::CleanupFailed(failed))
            );
            assert_eq!(
                service.restart_observation(),
                DurableRunObservation::ActiveRun { generation: 2 }
            );
        }
        Ok(())
    }

    #[test]
    fn out_of_order_incomplete_or_invalid_clean_transition_requires_exit()
    -> Result<(), Box<dyn Error>> {
        let mut out_of_order = ready_service(1)?;
        out_of_order.begin_stop(StopReason::ScmStop)?;
        assert_eq!(
            out_of_order.complete_cleanup_step(CleanupStep::CancelRequests),
            Err(LifecycleError::CleanupOutOfOrder)
        );
        assert_eq!(
            out_of_order.begin_stop(StopReason::ScmStop),
            Err(LifecycleError::Fatal)
        );

        let mut premature = ready_service(1)?;
        premature.begin_stop(StopReason::ScmStop)?;
        let Err(exit) = premature.prepare_clean_commit() else {
            return Err("out-of-order cleanup unexpectedly prepared a clean commit".into());
        };
        assert_eq!(exit.reason, ExitReason::CleanupOutOfOrder);
        assert_eq!(
            exit.restart_observation(),
            DurableRunObservation::ActiveRun { generation: 2 }
        );

        let mut incomplete = ready_service(1)?;
        incomplete.begin_stop(StopReason::ScmStop)?;
        for step in CleanupStep::ORDERED
            .iter()
            .take_while(|step| **step != CleanupStep::CommitAndRereadCleanMarker)
            .copied()
        {
            finish_nonfinal_cleanup_step(&mut incomplete, step)?;
        }
        incomplete.single_instance_released = false;
        let Err(exit) = incomplete.prepare_clean_commit() else {
            return Err("incomplete cleanup unexpectedly prepared a clean commit".into());
        };
        assert_eq!(exit.reason, ExitReason::CleanupIncomplete);
        assert_eq!(
            exit.restart_observation(),
            DurableRunObservation::ActiveRun { generation: 2 }
        );

        let mut wrong_generation = ready_service(1)?;
        wrong_generation.begin_stop(StopReason::ScmStop)?;
        for step in CleanupStep::ORDERED
            .iter()
            .take_while(|step| **step != CleanupStep::CommitAndRereadCleanMarker)
            .copied()
        {
            finish_nonfinal_cleanup_step(&mut wrong_generation, step)?;
        }
        let Ok(clean_pending) = wrong_generation.prepare_clean_commit() else {
            return Err("exact cleanup prerequisites unexpectedly required exit".into());
        };
        let Err(exit) = clean_pending.commit_and_reread_clean_marker(
            CommittedRunMarkerObservation(DurableRunObservation::CleanShutdown { generation: 4 }),
            RereadRunMarkerObservation(DurableRunObservation::CleanShutdown { generation: 4 }),
        ) else {
            return Err("wrong clean generation unexpectedly minted a stopped permit".into());
        };
        assert_eq!(exit.reason, ExitReason::InvalidCleanShutdownReceipt);
        assert_eq!(
            exit.restart_observation(),
            DurableRunObservation::RecoveryRequired
        );
        assert_eq!(
            pending_startup(exit.restart_observation()).map(|_| ()),
            Err(StartupFailure::RecoveryRequired(
                RecoveryReason::PersistedRecoveryRequired
            ))
        );
        Ok(())
    }

    #[test]
    fn crash_and_cleanup_deadline_never_produce_clean_restart_evidence()
    -> Result<(), Box<dyn Error>> {
        let mut crashed = ready_service(1)?;
        crashed.crash();
        assert_eq!(
            crashed.restart_observation(),
            DurableRunObservation::ActiveRun { generation: 2 }
        );
        assert_eq!(
            crashed.state,
            RuntimeState::Fatal(FatalReason::ServiceCrash)
        );

        let mut expired = ready_service(1)?;
        expired.begin_stop(StopReason::SystemShutdown)?;
        expired.cleanup_deadline_expired()?;
        assert_eq!(
            expired.restart_observation(),
            DurableRunObservation::ActiveRun { generation: 2 }
        );
        assert_eq!(
            expired.state,
            RuntimeState::Fatal(FatalReason::CleanupDeadlineExpired)
        );
        Ok(())
    }

    #[test]
    fn debug_output_redacts_work_session_and_generation_identifiers() -> Result<(), Box<dyn Error>>
    {
        let session = SessionId::new(882_771)?;
        let work = WorkId::new(991_663)?;
        let mut service = ready_service(44)?;
        service.retain_user_token(session)?;
        service.admit_fixture_work(work, session, NoSecretFixtureWorkKind::Approval)?;

        let marker = DurableRunObservation::ActiveRun {
            generation: 775_544,
        };
        let startup = NoSecretStartupAttempt::new(marker);
        let committed = CommittedRunMarkerObservation(marker);
        let reread = RereadRunMarkerObservation(marker);
        let debug = format!(
            "{service:?} {session:?} {work:?} {marker:?} {startup:?} {committed:?} {reread:?}"
        );
        assert!(!debug.contains("882771"));
        assert!(!debug.contains("991663"));
        assert!(!debug.contains("775544"));
        assert!(!debug.contains("generation: 44"));
        assert!(debug.contains("[REDACTED"));
        assert!(debug.contains("[GENERATION]"));
        Ok(())
    }
}
