use std::error::Error;
use std::io;

use super::super::durable_run_state::{
    DurableRunStateCommitFailure, DurableRunStateCommitFault, DurableRunStateFixture,
    DurableRunStateFixtureSeed, DurableRunStateReleaseFailure, DurableRunStateReleaseFault,
    DurableRunStateRereadFault, FixtureRunStateAuthenticationKey, InstallationIdentity,
    RecoveryRequired, RunMarkerState,
};
use super::{
    ActiveReloadResolution, CleanupStep, ExitReason, ExitRequired, FatalReason, LifecycleError,
    MAX_ACTIVE_FIXTURE_WORK, MAX_QUARANTINED_SESSIONS, MAX_RETAINED_USER_TOKEN_SESSIONS,
    NoSecretFixtureWorkKind, NoSecretService, NoSecretStartupAttempt, NoSecretStartupRequirement,
    PendingNoSecretStartup, RuntimeState, SessionEvent, SessionId, SessionInvalidationReport,
    StartupExitRequired, StartupFailure, StartupObservation, StopReason, StoppedPermit, WorkId,
    WorkState,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct LifecycleHarness {
    store: DurableRunStateFixture,
    key: FixtureRunStateAuthenticationKey,
    installation: InstallationIdentity,
}

impl LifecycleHarness {
    fn new(seed: DurableRunStateFixtureSeed) -> TestResult<Self> {
        let key = FixtureRunStateAuthenticationKey::from_fixture_bytes([0x5a; 32])?;
        let installation = InstallationIdentity::from_fixed_bytes([0x41; 32])?;
        let store = DurableRunStateFixture::new(seed, &key, installation)?;
        Ok(Self {
            store,
            key,
            installation,
        })
    }

    fn provisioned() -> TestResult<Self> {
        let key = FixtureRunStateAuthenticationKey::from_fixture_bytes([0x5a; 32])?;
        let installation = InstallationIdentity::from_fixed_bytes([0x41; 32])?;
        let mut store = DurableRunStateFixture::empty(installation)?;
        let unprovisioned = store
            .begin_initial_provisioning(&key, installation)
            .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
        let transition = unprovisioned
            .prepare_initial_clean()
            .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
        let committed = store.commit_initial_clean(&transition)?;
        let reread = store.reread_initial_clean(&transition)?;
        let clean = transition
            .complete(committed, reread)
            .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
        let pending = clean.prepare_writer_release();
        let receipt = store.release_provisioning_writer(&pending)?;
        let provisioned = pending
            .complete(receipt)
            .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
        assert_eq!(provisioned.generation().get(), 1);
        Ok(Self {
            store,
            key,
            installation,
        })
    }

    fn boot(&mut self) -> Result<super::BootEvidence, RecoveryRequired> {
        self.store.boot(&self.key, self.installation)
    }

    fn startup_attempt(&mut self) -> NoSecretStartupAttempt {
        NoSecretStartupAttempt::new(self.boot())
    }

    fn pending_startup(&mut self) -> TestResult<PendingNoSecretStartup> {
        let mut attempt = self.startup_attempt();
        for requirement in NoSecretStartupRequirement::ALL {
            if let Err(failure) = attempt.observe(requirement, StartupObservation::Verified) {
                return require_startup_ok(Err(attempt.into_exit(failure)));
            }
        }
        require_startup_ok(attempt.finish(&self.key))
    }

    fn ready_service(&mut self) -> TestResult<NoSecretService> {
        let pending = self.pending_startup()?;
        let committed = self.store.commit_active(pending.transition_request())?;
        let reread = self.store.reread_active(pending.transition_request())?;
        let listener =
            require_startup_ok(pending.commit_and_reread_active_marker(committed, reread))?;
        Ok(listener
            .record_listeners_prepared()
            .record_scm_running_published()
            .open_admission())
    }

    fn prepare_clean(&mut self, service: NoSecretService) -> TestResult<super::CleanCommitPending> {
        require_exit_ok(service.prepare_clean_commit(&self.key))
    }

    fn commit_clean(
        &mut self,
        pending: super::CleanCommitPending,
    ) -> TestResult<super::SingleInstanceReleasePending> {
        let committed = self.store.commit_clean(pending.transition_request())?;
        let reread = self.store.reread_clean(pending.transition_request())?;
        require_exit_ok(pending.commit_and_reread_clean_marker(committed, reread))
    }

    fn release_clean(
        &mut self,
        pending: super::SingleInstanceReleasePending,
    ) -> TestResult<StoppedPermit> {
        let receipt = self.store.release_writer(pending.release_request())?;
        require_exit_ok(pending.complete(receipt))
    }

    fn retire_startup_exit(&mut self, exit: StartupExitRequired) -> TestResult<StartupFailure> {
        match exit.into_writer_exit() {
            Err(failure) => Ok(failure),
            Ok((failure, writer_exit)) => {
                let receipt = self.store.retire_writer_for_exit(&writer_exit)?;
                let _retired = writer_exit.complete(receipt)?;
                Ok(failure)
            }
        }
    }

    fn retire_exit(&mut self, exit: ExitRequired) -> TestResult<super::RecoveryExitPermit> {
        let receipt = self
            .store
            .retire_writer_for_exit(exit.writer_exit_request())?;
        Ok(exit.complete_writer_exit(receipt)?)
    }
}

fn require_exit_ok<T>(result: Result<T, ExitRequired>) -> TestResult<T> {
    result.map_err(|error| Box::new(io::Error::other(format!("{error:?}"))) as Box<dyn Error>)
}

fn require_startup_ok<T>(result: Result<T, StartupExitRequired>) -> TestResult<T> {
    result.map_err(|error| Box::new(io::Error::other(format!("{error:?}"))) as Box<dyn Error>)
}

fn finish_nonfinal_cleanup_step(
    service: &mut NoSecretService,
    step: CleanupStep,
) -> Result<(), LifecycleError> {
    assert!(!matches!(
        step,
        CleanupStep::ReleaseSingleInstanceLease | CleanupStep::CommitAndRereadCleanMarker
    ));
    service.complete_cleanup_step(step)
}

fn advance_to_clean_commit(service: &mut NoSecretService) -> Result<(), LifecycleError> {
    service.begin_stop(StopReason::ScmStop)?;
    for step in CleanupStep::ORDERED.into_iter().take(9) {
        finish_nonfinal_cleanup_step(service, step)?;
    }
    assert_eq!(
        service.expected_cleanup_step(),
        Some(CleanupStep::CommitAndRereadCleanMarker)
    );
    Ok(())
}

#[test]
fn every_startup_requirement_is_mandatory() -> TestResult {
    for missing in NoSecretStartupRequirement::ALL {
        let mut harness = LifecycleHarness::provisioned()?;
        let mut attempt = harness.startup_attempt();
        for requirement in NoSecretStartupRequirement::ALL {
            if requirement != missing {
                attempt.observe(requirement, StartupObservation::Verified)?;
            }
        }
        let Err(exit) = attempt.finish(&harness.key) else {
            return Err("missing startup observation produced authority".into());
        };
        assert!(format!("{exit:?}").contains("[REDACTED]"));
        assert_eq!(
            harness.retire_startup_exit(exit)?,
            StartupFailure::Missing(missing)
        );
    }
    Ok(())
}

#[test]
fn mismatched_unavailable_and_duplicate_observations_fail_closed() -> TestResult {
    for rejected in NoSecretStartupRequirement::ALL {
        for observation in [
            StartupObservation::Mismatch,
            StartupObservation::Unavailable,
        ] {
            let mut harness = LifecycleHarness::provisioned()?;
            let mut attempt = harness.startup_attempt();
            for requirement in NoSecretStartupRequirement::ALL {
                attempt.observe(
                    requirement,
                    if requirement == rejected {
                        observation
                    } else {
                        StartupObservation::Verified
                    },
                )?;
            }
            let expected = match observation {
                StartupObservation::Mismatch => StartupFailure::Mismatch(rejected),
                StartupObservation::Unavailable => StartupFailure::Unavailable(rejected),
                StartupObservation::Verified => return Err("invalid observation fixture".into()),
            };
            let Err(exit) = attempt.finish(&harness.key) else {
                return Err("rejected startup observation produced authority".into());
            };
            assert_eq!(harness.retire_startup_exit(exit)?, expected);
        }
    }

    let mut harness = LifecycleHarness::provisioned()?;
    let requirement = NoSecretStartupRequirement::ServiceConfiguration;
    let mut attempt = harness.startup_attempt();
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
    let Err(exit) = attempt.finish(&harness.key) else {
        return Err("duplicate startup observation produced authority".into());
    };
    assert_eq!(
        harness.retire_startup_exit(exit)?,
        StartupFailure::DuplicateObservation(requirement)
    );
    Ok(())
}

#[test]
fn only_sealed_clean_boot_can_enter_the_ordered_startup_chain() -> TestResult {
    let mut clean = LifecycleHarness::provisioned()?;
    assert!(clean.pending_startup().is_ok());

    for (seed, expected) in [
        (
            DurableRunStateFixtureSeed::Active,
            RecoveryRequired::PersistedNonCleanState,
        ),
        (
            DurableRunStateFixtureSeed::RecoveryRequired,
            RecoveryRequired::PersistedNonCleanState,
        ),
        (
            DurableRunStateFixtureSeed::MissingMarker,
            RecoveryRequired::MissingRunMarker,
        ),
        (
            DurableRunStateFixtureSeed::MissingCheckpoint,
            RecoveryRequired::MissingHighWaterCheckpoint,
        ),
        (
            DurableRunStateFixtureSeed::Invalid,
            RecoveryRequired::AuthenticationFailed,
        ),
    ] {
        let mut harness = LifecycleHarness::new(seed)?;
        for _ in 0..2 {
            let Err(observed) = harness.boot() else {
                return Err("non-clean startup minted boot authority".into());
            };
            assert_eq!(observed, expected);
            let mut attempt = NoSecretStartupAttempt::new(Err(observed));
            for requirement in NoSecretStartupRequirement::ALL {
                attempt.observe(requirement, StartupObservation::Verified)?;
            }
            let Err(exit) = attempt.finish(&harness.key) else {
                return Err("non-clean startup entered the ordered chain".into());
            };
            assert_eq!(
                harness.retire_startup_exit(exit)?,
                StartupFailure::DurableRecovery(expected)
            );
        }
    }
    Ok(())
}

#[test]
fn active_commit_readback_and_reload_are_exact_before_listener_preparation() -> TestResult {
    let mut happy = LifecycleHarness::provisioned()?;
    let service = happy.ready_service()?;
    assert_eq!(
        happy.store.reopen(&happy.key, happy.installation)?.state(),
        RunMarkerState::Active
    );
    drop(service);

    for fault in [
        DurableRunStateRereadFault::MissingMarker,
        DurableRunStateRereadFault::MarkerDrift,
        DurableRunStateRereadFault::CheckpointDrift,
    ] {
        let mut harness = LifecycleHarness::provisioned()?;
        let pending = harness.pending_startup()?;
        let committed = harness.store.commit_active(pending.transition_request())?;
        harness.store.set_reread_fault(fault);
        let reread = harness.store.reread_active(pending.transition_request())?;
        let Err(exit) = pending.commit_and_reread_active_marker(committed, reread) else {
            return Err("drifting Active readback produced listener authority".into());
        };
        assert_eq!(
            harness.retire_startup_exit(exit)?,
            StartupFailure::DurableRecovery(RecoveryRequired::RereadDrift)
        );
    }

    let mut conflict = LifecycleHarness::provisioned()?;
    let pending = conflict.pending_startup()?;
    conflict
        .store
        .set_commit_fault(DurableRunStateCommitFault::CompareAndSwapConflict);
    assert_eq!(
        conflict.store.commit_active(pending.transition_request()),
        Err(DurableRunStateCommitFailure::Recovery(
            RecoveryRequired::CompareAndSwapConflict
        ))
    );
    assert_eq!(
        conflict.retire_startup_exit(pending.abort(RecoveryRequired::CompareAndSwapConflict))?,
        StartupFailure::DurableRecovery(RecoveryRequired::CompareAndSwapConflict)
    );

    let mut before_write = LifecycleHarness::provisioned()?;
    let pending = before_write.pending_startup()?;
    before_write
        .store
        .set_commit_fault(DurableRunStateCommitFault::AmbiguousBeforeWrite);
    assert_eq!(
        before_write
            .store
            .commit_active(pending.transition_request()),
        Err(DurableRunStateCommitFailure::Ambiguous)
    );
    let reload = pending.commit_ambiguous();
    let receipt = before_write.store.reload_active(reload.reload_request())?;
    let resolution = require_startup_ok(reload.complete(receipt, &before_write.key))?;
    let ActiveReloadResolution::Revalidate(attempt) = resolution else {
        return Err("before-write Active ambiguity skipped startup revalidation".into());
    };
    let Err(exit) = attempt.finish(&before_write.key) else {
        return Err("unobserved retry startup produced authority".into());
    };
    assert_eq!(
        before_write.retire_startup_exit(exit)?,
        StartupFailure::Missing(NoSecretStartupRequirement::ServiceToken)
    );

    let mut ambiguous = LifecycleHarness::provisioned()?;
    let pending = ambiguous.pending_startup()?;
    ambiguous
        .store
        .set_commit_fault(DurableRunStateCommitFault::AmbiguousAfterCheckpoint);
    assert_eq!(
        ambiguous.store.commit_active(pending.transition_request()),
        Err(DurableRunStateCommitFailure::Ambiguous)
    );
    let reload = pending.commit_ambiguous();
    let receipt = ambiguous.store.reload_active(reload.reload_request())?;
    let listener = match require_startup_ok(reload.complete(receipt, &ambiguous.key))? {
        ActiveReloadResolution::Resume(listener) => listener,
        ActiveReloadResolution::Revalidate(_) => {
            return Err("exact Active candidate did not resume listener preparation".into());
        }
    };
    let reloaded = listener
        .record_listeners_prepared()
        .record_scm_running_published()
        .open_admission();
    assert!(matches!(reloaded.state, RuntimeState::Ready));
    Ok(())
}

#[test]
fn lock_and_unlock_invalidate_exact_session_without_discarding_its_user_token() -> TestResult {
    for event in [SessionEvent::Lock, SessionEvent::Unlock] {
        let mut harness = LifecycleHarness::provisioned()?;
        let mut service = harness.ready_service()?;
        let session = SessionId::new(7)?;
        service.retain_user_token(session)?;
        service.admit_fixture_work(WorkId::new(11)?, session, NoSecretFixtureWorkKind::Approval)?;
        let report = service.handle_session_event(event(session))?;
        assert_eq!(
            report,
            SessionInvalidationReport {
                authorities_invalidated: 1,
                helper_terminations_required: 1,
                user_tokens_discarded: 0,
                revalidation_required: true,
            }
        );
        assert!(service.user_token_sessions.contains(&session));
        assert_eq!(
            service.admit_fixture_work(
                WorkId::new(12)?,
                session,
                NoSecretFixtureWorkKind::SecretInput,
            ),
            Err(LifecycleError::SessionInvalidated)
        );
    }
    Ok(())
}

#[test]
fn logoff_and_user_switch_discard_tokens_and_require_helper_reap() -> TestResult {
    let mut logoff_harness = LifecycleHarness::provisioned()?;
    let mut logoff = logoff_harness.ready_service()?;
    let session = SessionId::new(17)?;
    logoff.retain_user_token(session)?;
    logoff.admit_fixture_work(
        WorkId::new(21)?,
        session,
        NoSecretFixtureWorkKind::SecretInput,
    )?;
    let report = logoff.handle_session_event(SessionEvent::Logoff(session))?;
    assert_eq!(report.user_tokens_discarded, 1);
    assert_eq!(report.helper_terminations_required, 1);

    let mut switch_harness = LifecycleHarness::provisioned()?;
    let mut switched = switch_harness.ready_service()?;
    for (work, session) in [(31, 27), (32, 28)] {
        let session = SessionId::new(session)?;
        switched.retain_user_token(session)?;
        switched.admit_fixture_work(
            WorkId::new(work)?,
            session,
            NoSecretFixtureWorkKind::Approval,
        )?;
    }
    let report = switched.handle_session_event(SessionEvent::UserSwitch(SessionId::new(27)?))?;
    assert_eq!(report.authorities_invalidated, 2);
    assert_eq!(report.helper_terminations_required, 2);
    assert_eq!(report.user_tokens_discarded, 2);
    assert!(switched.user_token_sessions.is_empty());
    assert!(
        switched
            .work
            .values()
            .all(|work| work.state == WorkState::CancellationPending)
    );
    Ok(())
}

#[test]
fn session_quarantine_exhaustion_fails_closed_and_preserves_first_fatal_reason() -> TestResult {
    let mut harness = LifecycleHarness::provisioned()?;
    let mut service = harness.ready_service()?;
    for value in 1..=MAX_QUARANTINED_SESSIONS {
        service
            .invalid_sessions
            .insert(SessionId::new(u32::try_from(value)?)?);
    }
    let live = SessionId::new(u32::try_from(MAX_QUARANTINED_SESSIONS + 1)?)?;
    service.retain_user_token(live)?;
    service.admit_fixture_work(WorkId::new(1)?, live, NoSecretFixtureWorkKind::Approval)?;
    assert_eq!(
        service.handle_session_event(SessionEvent::Lock(live)),
        Err(LifecycleError::SessionQuarantineExhausted)
    );
    assert!(service.user_token_sessions.is_empty());
    assert!(
        service
            .work
            .values()
            .all(|work| work.state == WorkState::TerminationPending)
    );
    assert_eq!(
        service.state,
        RuntimeState::Fatal(FatalReason::SessionQuarantineExceeded)
    );
    service.crash();
    assert_eq!(
        service.state,
        RuntimeState::Fatal(FatalReason::SessionQuarantineExceeded)
    );
    Ok(())
}

#[test]
fn runtime_registries_are_bounded_before_mutation() -> TestResult {
    let mut harness = LifecycleHarness::provisioned()?;
    let mut service = harness.ready_service()?;
    let session = SessionId::new(1)?;
    for value in 1..=MAX_ACTIVE_FIXTURE_WORK {
        service.admit_fixture_work(
            WorkId::new(value as u64)?,
            session,
            NoSecretFixtureWorkKind::Approval,
        )?;
    }
    assert_eq!(
        service.admit_fixture_work(
            WorkId::new((MAX_ACTIVE_FIXTURE_WORK + 1) as u64)?,
            session,
            NoSecretFixtureWorkKind::Approval,
        ),
        Err(LifecycleError::WorkCapacityExhausted)
    );
    assert_eq!(service.work.len(), MAX_ACTIVE_FIXTURE_WORK);

    for value in 1..=MAX_RETAINED_USER_TOKEN_SESSIONS {
        service.retain_user_token(SessionId::new(u32::try_from(value)?)?)?;
    }
    assert_eq!(
        service.retain_user_token(SessionId::new(u32::try_from(
            MAX_RETAINED_USER_TOKEN_SESSIONS + 1,
        )?)?),
        Err(LifecycleError::UserTokenCapacityExhausted)
    );
    assert_eq!(
        service.user_token_sessions.len(),
        MAX_RETAINED_USER_TOKEN_SESSIONS
    );
    Ok(())
}

#[test]
fn stop_commits_clean_while_held_then_exact_release_mints_stopped_permit() -> TestResult {
    let mut harness = LifecycleHarness::provisioned()?;
    let mut service = harness.ready_service()?;
    let session = SessionId::new(3)?;
    service.retain_user_token(session)?;
    service.admit_fixture_work(WorkId::new(9)?, session, NoSecretFixtureWorkKind::Approval)?;
    advance_to_clean_commit(&mut service)?;
    let clean = harness.prepare_clean(service)?;
    let release = harness.commit_clean(clean)?;
    assert_eq!(
        harness
            .store
            .reopen(&harness.key, harness.installation)?
            .state(),
        RunMarkerState::Clean
    );
    assert_eq!(
        harness
            .store
            .boot(&harness.key, harness.installation)
            .map(|_| ()),
        Err(RecoveryRequired::WriterLeaseUnavailable)
    );
    let stopped = harness.release_clean(release)?;
    assert!(format!("{stopped:?}").contains("[REDACTED DURABLE EVIDENCE]"));
    assert!(harness.ready_service().is_ok());
    Ok(())
}

#[test]
fn every_pre_clean_cleanup_failure_leaves_active_and_retires_the_writer() -> TestResult {
    for failed_step in CleanupStep::ORDERED.into_iter().take(10) {
        let mut harness = LifecycleHarness::provisioned()?;
        let mut service = harness.ready_service()?;
        service.begin_stop(StopReason::ScmStop)?;
        for step in CleanupStep::ORDERED {
            if step == failed_step {
                break;
            }
            finish_nonfinal_cleanup_step(&mut service, step)?;
        }
        service.fail_cleanup(failed_step)?;
        assert_eq!(
            service.state,
            RuntimeState::Fatal(FatalReason::CleanupFailed(failed_step))
        );
        assert_eq!(
            harness
                .store
                .reopen(&harness.key, harness.installation)?
                .state(),
            RunMarkerState::Active
        );
        let exit = service.prepare_fatal_exit()?;
        let retired = harness.retire_exit(exit)?;
        assert_eq!(retired.reason, ExitReason::FatalRuntime);
        assert_eq!(
            harness
                .store
                .boot(&harness.key, harness.installation)
                .map(|_| ()),
            Err(RecoveryRequired::PersistedNonCleanState)
        );
    }
    Ok(())
}

#[test]
fn out_of_order_incomplete_and_clean_reread_drift_require_exit() -> TestResult {
    let mut premature_harness = LifecycleHarness::provisioned()?;
    let premature = premature_harness.ready_service()?;
    let Err(exit) = premature.prepare_clean_commit(&premature_harness.key) else {
        return Err("out-of-order Clean preparation produced authority".into());
    };
    assert_eq!(exit.reason, ExitReason::CleanupOutOfOrder);
    let retired = premature_harness.retire_exit(exit)?;
    assert_eq!(retired.reason, ExitReason::CleanupOutOfOrder);

    let mut incomplete_harness = LifecycleHarness::provisioned()?;
    let mut incomplete = incomplete_harness.ready_service()?;
    advance_to_clean_commit(&mut incomplete)?;
    let session = SessionId::new(91)?;
    incomplete.work.insert(
        WorkId::new(92)?,
        super::FixtureWork {
            session,
            kind: NoSecretFixtureWorkKind::Approval,
            state: WorkState::TerminationPending,
        },
    );
    let Err(exit) = incomplete.prepare_clean_commit(&incomplete_harness.key) else {
        return Err("incomplete cleanup produced Clean authority".into());
    };
    assert_eq!(exit.reason, ExitReason::CleanupIncomplete);
    let retired = incomplete_harness.retire_exit(exit)?;
    assert_eq!(retired.reason, ExitReason::CleanupIncomplete);

    let mut conflict_harness = LifecycleHarness::provisioned()?;
    let mut conflict = conflict_harness.ready_service()?;
    advance_to_clean_commit(&mut conflict)?;
    let pending = conflict_harness.prepare_clean(conflict)?;
    conflict_harness
        .store
        .set_commit_fault(DurableRunStateCommitFault::CompareAndSwapConflict);
    assert_eq!(
        conflict_harness
            .store
            .commit_clean(pending.transition_request()),
        Err(DurableRunStateCommitFailure::Recovery(
            RecoveryRequired::CompareAndSwapConflict
        ))
    );
    let exit = pending.abort(RecoveryRequired::CompareAndSwapConflict);
    assert_eq!(
        exit.durable_recovery,
        Some(RecoveryRequired::CompareAndSwapConflict)
    );
    let retired = conflict_harness.retire_exit(exit)?;
    assert_eq!(retired.reason, ExitReason::DurableRecovery);
    assert_eq!(
        conflict_harness
            .store
            .boot(&conflict_harness.key, conflict_harness.installation)
            .map(|_| ()),
        Err(RecoveryRequired::PersistedNonCleanState)
    );

    let mut drift_harness = LifecycleHarness::provisioned()?;
    let mut drift = drift_harness.ready_service()?;
    advance_to_clean_commit(&mut drift)?;
    let pending = drift_harness.prepare_clean(drift)?;
    let committed = drift_harness
        .store
        .commit_clean(pending.transition_request())?;
    drift_harness
        .store
        .set_reread_fault(DurableRunStateRereadFault::MarkerDrift);
    let reread = drift_harness
        .store
        .reread_clean(pending.transition_request())?;
    let Err(exit) = pending.commit_and_reread_clean_marker(committed, reread) else {
        return Err("drifting Clean readback minted stopped authority".into());
    };
    assert_eq!(exit.reason, ExitReason::DurableRecovery);
    assert_eq!(exit.durable_recovery, Some(RecoveryRequired::RereadDrift));
    let retired = drift_harness.retire_exit(exit)?;
    assert_eq!(retired.reason, ExitReason::DurableRecovery);
    assert_eq!(
        retired.durable_recovery,
        Some(RecoveryRequired::RereadDrift)
    );
    assert!(
        drift_harness
            .store
            .boot(&drift_harness.key, drift_harness.installation)
            .is_ok()
    );
    Ok(())
}

#[test]
fn held_writer_closes_the_clean_commit_to_final_release_interleaving() -> TestResult {
    let mut harness = LifecycleHarness::provisioned()?;
    let mut service = harness.ready_service()?;
    advance_to_clean_commit(&mut service)?;

    for _ in 0..2 {
        assert_eq!(
            harness
                .store
                .boot(&harness.key, harness.installation)
                .map(|_| ()),
            Err(RecoveryRequired::PersistedNonCleanState)
        );
    }

    let clean = harness.prepare_clean(service)?;
    let release = harness.commit_clean(clean)?;
    for _ in 0..2 {
        assert_eq!(
            harness
                .store
                .boot(&harness.key, harness.installation)
                .map(|_| ()),
            Err(RecoveryRequired::WriterLeaseUnavailable)
        );
    }
    let _stopped = harness.release_clean(release)?;
    assert!(
        harness
            .store
            .boot(&harness.key, harness.installation)
            .is_ok()
    );
    Ok(())
}

#[test]
fn exact_clean_ambiguous_reload_still_requires_the_branded_final_release() -> TestResult {
    for (fault, expected_error) in [
        (
            DurableRunStateCommitFault::AmbiguousBeforeWrite,
            Some(RecoveryRequired::AmbiguousCleanCommitNotApplied),
        ),
        (
            DurableRunStateCommitFault::AmbiguousAfterMarker,
            Some(RecoveryRequired::HighWaterDrift),
        ),
        (DurableRunStateCommitFault::AmbiguousAfterCheckpoint, None),
    ] {
        let mut harness = LifecycleHarness::provisioned()?;
        let mut service = harness.ready_service()?;
        advance_to_clean_commit(&mut service)?;
        let pending = harness.prepare_clean(service)?;
        harness.store.set_commit_fault(fault);
        assert_eq!(
            harness.store.commit_clean(pending.transition_request()),
            Err(DurableRunStateCommitFailure::Ambiguous)
        );
        let reload = pending.commit_ambiguous();
        let receipt = harness.store.reload_clean(reload.reload_request())?;
        if let Some(expected) = expected_error {
            let Err(exit) = reload.complete(receipt, &harness.key) else {
                return Err("ambiguous Clean fault unexpectedly reloaded authority".into());
            };
            assert_eq!(exit.reason, ExitReason::DurableRecovery);
            assert_eq!(exit.durable_recovery, Some(expected));
            let retired = harness.retire_exit(exit)?;
            assert_eq!(retired.durable_recovery, Some(expected));
        } else {
            let release = require_exit_ok(reload.complete(receipt, &harness.key))?;
            assert_eq!(
                harness
                    .store
                    .boot(&harness.key, harness.installation)
                    .map(|_| ()),
                Err(RecoveryRequired::WriterLeaseUnavailable)
            );
            let _permit = harness.release_clean(release)?;
            assert!(
                harness
                    .store
                    .boot(&harness.key, harness.installation)
                    .is_ok()
            );
        }
    }
    Ok(())
}

#[test]
fn final_release_ambiguity_or_mismatch_retires_only_through_terminal_exit() -> TestResult {
    for fault in [
        DurableRunStateReleaseFault::AmbiguousBeforeRelease,
        DurableRunStateReleaseFault::AmbiguousAfterRelease,
    ] {
        let mut harness = LifecycleHarness::provisioned()?;
        let mut service = harness.ready_service()?;
        advance_to_clean_commit(&mut service)?;
        let clean = harness.prepare_clean(service)?;
        let release = harness.commit_clean(clean)?;
        harness.store.set_release_fault(fault);
        assert!(matches!(
            harness.store.release_writer(release.release_request()),
            Err(DurableRunStateReleaseFailure::Ambiguous)
        ));
        let exit = release.abort(RecoveryRequired::WriterReleaseAmbiguous);
        assert_eq!(
            exit.durable_recovery,
            Some(RecoveryRequired::WriterReleaseAmbiguous)
        );
        let retired = harness.retire_exit(exit)?;
        assert_eq!(
            retired.durable_recovery,
            Some(RecoveryRequired::WriterReleaseAmbiguous)
        );
        assert!(
            harness
                .store
                .boot(&harness.key, harness.installation)
                .is_ok()
        );
    }

    let mut harness = LifecycleHarness::provisioned()?;
    let mut service = harness.ready_service()?;
    advance_to_clean_commit(&mut service)?;
    let clean = harness.prepare_clean(service)?;
    let release = harness.commit_clean(clean)?;
    harness
        .store
        .set_release_fault(DurableRunStateReleaseFault::MismatchedReceiptAfterRelease);
    let receipt = harness.store.release_writer(release.release_request())?;
    let Err(exit) = release.complete(receipt) else {
        return Err("mismatched writer receipt minted stopped authority".into());
    };
    assert_eq!(
        exit.durable_recovery,
        Some(RecoveryRequired::WriterLeaseMismatch)
    );
    let retired = harness.retire_exit(exit)?;
    assert_eq!(
        retired.durable_recovery,
        Some(RecoveryRequired::WriterLeaseMismatch)
    );
    assert!(
        harness
            .store
            .boot(&harness.key, harness.installation)
            .is_ok()
    );
    Ok(())
}

#[test]
fn fatal_exit_preserves_active_marker_and_retires_the_fixture_writer() -> TestResult {
    let mut harness = LifecycleHarness::provisioned()?;
    let mut service = harness.ready_service()?;
    service.crash();
    let exit = service.prepare_fatal_exit()?;
    let retired = harness.retire_exit(exit)?;
    assert_eq!(retired.reason, ExitReason::FatalRuntime);
    assert_eq!(
        harness
            .store
            .reopen(&harness.key, harness.installation)?
            .state(),
        RunMarkerState::Active
    );
    for _ in 0..2 {
        assert_eq!(
            harness
                .store
                .boot(&harness.key, harness.installation)
                .map(|_| ()),
            Err(RecoveryRequired::PersistedNonCleanState)
        );
    }
    Ok(())
}

#[test]
fn crash_cleanup_deadline_and_debug_surfaces_never_claim_clean_or_leak_identifiers() -> TestResult {
    let mut crash_harness = LifecycleHarness::provisioned()?;
    let mut crashed = crash_harness.ready_service()?;
    crashed.crash();
    assert_eq!(
        crashed.state,
        RuntimeState::Fatal(FatalReason::ServiceCrash)
    );
    assert_eq!(
        crash_harness
            .store
            .reopen(&crash_harness.key, crash_harness.installation)?
            .state(),
        RunMarkerState::Active
    );

    let mut deadline_harness = LifecycleHarness::provisioned()?;
    let mut expired = deadline_harness.ready_service()?;
    expired.begin_stop(StopReason::SystemShutdown)?;
    expired.cleanup_deadline_expired()?;
    assert_eq!(
        expired.state,
        RuntimeState::Fatal(FatalReason::CleanupDeadlineExpired)
    );

    let work = WorkId::new(0x1234_5678_9abc_def0)?;
    let session = SessionId::new(0x7654_3210)?;
    let rendered = format!("{work:?} {session:?} {crashed:?} {:?}", crash_harness.store);
    assert!(rendered.contains("WorkId([REDACTED])"));
    assert!(rendered.contains("SessionId([REDACTED])"));
    assert!(rendered.contains("[REDACTED DURABLE AUTHORITY]"));
    assert!(rendered.contains("DurableRunStateFixture([REDACTED])"));
    let crash_exit = crashed.prepare_fatal_exit()?;
    assert!(format!("{crash_exit:?}").contains("[REDACTED]"));
    let deadline_exit = expired.prepare_fatal_exit()?;
    let _crash_retired = crash_harness.retire_exit(crash_exit)?;
    let _deadline_retired = deadline_harness.retire_exit(deadline_exit)?;
    assert!(!rendered.contains("123456789abcdef0"));
    assert!(!rendered.contains("76543210"));
    assert!(!rendered.contains("5a5a5a5a"));
    assert!(!rendered.contains("41414141"));
    Ok(())
}
