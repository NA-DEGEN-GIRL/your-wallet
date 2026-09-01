use std::error::Error;
use std::io;

use super::super::durable_run_state::{
    InstallationIdentity, RecoveryRequired, RunStateAuthenticationProvider,
    install_windows_runtime_clean_fixture,
};
use super::super::lifecycle_core::{
    CleanupStep, FatalReason, LifecycleError, NoSecretFixtureWorkKind, NoSecretStartupRequirement,
    RuntimePolicyFailure, RuntimeState, SessionEvent, SessionId, StartupFailure,
    StartupObservation, StopReason, WorkId,
};
use super::super::run_state_root::{RuntimePairFault, RuntimePairFixture, ServiceRunStateError};
use super::effects::{
    FixtureWindowsLifecycleEffectFault, WindowsLifecycleEffectDisposition,
    WindowsLifecycleEffectStage,
};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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

fn test_installation(byte: u8) -> Result<InstallationIdentity, RecoveryRequired> {
    InstallationIdentity::from_fixed_bytes([byte; 32])
}

fn test_provider(
    installation: InstallationIdentity,
    byte: u8,
) -> Result<RunStateAuthenticationProvider, RecoveryRequired> {
    RunStateAuthenticationProvider::from_fixture_bytes(installation, [byte; 32])
}

fn clean_fixture(
    byte: u8,
) -> TestResult<(
    RuntimePairFixture,
    InstallationIdentity,
    RunStateAuthenticationProvider,
)> {
    let fixture = RuntimePairFixture::new()?;
    let installation = test_installation(byte)?;
    let provider = test_provider(installation, byte.wrapping_add(1))?;
    install_windows_runtime_clean_fixture(&fixture, installation, &provider)?;
    Ok((fixture, installation, provider))
}

fn assert_checked_exit(exit: WindowsLifecycleExitRequired<'_>) -> TestResult {
    match exit.retire_checked() {
        Ok(receipt) => {
            assert_eq!(receipt.code(), WINDOWS_SERVICE_EXIT_CODE);
            assert!(format!("{receipt:?}").contains("[REDACTED]"));
            Ok(())
        }
        Err(failure) => Err(io::Error::other(format!(
            "checked retirement became irreversible: {failure:?}"
        ))
        .into()),
    }
}

fn assert_exit78(exit: WindowsLifecycleExitRequired<'_>) {
    match exit.retire_checked() {
        Ok(receipt) => {
            assert_eq!(receipt.code(), WINDOWS_SERVICE_EXIT_CODE);
        }
        Err(failure) => {
            assert_eq!(failure.code(), WINDOWS_SERVICE_EXIT_CODE);
        }
    }
}

fn begin<'provider>(
    fixture: &RuntimePairFixture,
    provider: &'provider mut RunStateAuthenticationProvider,
) -> TestResult<WindowsStartupAttempt<'provider>> {
    match begin_windows_lifecycle(fixture.acquire_writer()?, provider.runtime_authority()) {
        Ok(startup) => Ok(startup),
        Err(exit) => {
            assert_exit78(exit);
            Err(io::Error::other("clean fixture failed lifecycle startup").into())
        }
    }
}

fn test_effects() -> TestResult<WindowsLifecycleEffectAuthority> {
    Ok(WindowsLifecycleEffectAuthority::from_fixture(None)?)
}

fn faulting_effects(
    fault: FixtureWindowsLifecycleEffectFault,
) -> TestResult<WindowsLifecycleEffectAuthority> {
    Ok(WindowsLifecycleEffectAuthority::from_fixture(Some(fault))?)
}

#[allow(clippy::result_large_err)] // Failure retains checked retirement authority inline.
fn complete_checklist(
    mut startup: WindowsStartupAttempt<'_>,
) -> Result<WindowsActiveCommitPending<'_>, WindowsLifecycleExitRequired<'_>> {
    for requirement in NoSecretStartupRequirement::ALL {
        if let Err(cause) = startup.observe(requirement, StartupObservation::Verified) {
            return Err(startup.abort(cause));
        }
    }
    startup.finish()
}

fn prepared_active<'provider>(
    fixture: &RuntimePairFixture,
    provider: &'provider mut RunStateAuthenticationProvider,
) -> TestResult<WindowsActiveCommitPending<'provider>> {
    let startup = begin(fixture, provider)?;
    match complete_checklist(startup) {
        Ok(prepared) => Ok(prepared),
        Err(exit) => {
            assert_exit78(exit);
            Err(io::Error::other("verified checklist failed Active preparation").into())
        }
    }
}

fn listener_pending<'provider>(
    fixture: &RuntimePairFixture,
    provider: &'provider mut RunStateAuthenticationProvider,
) -> TestResult<WindowsListenerPending<'provider>> {
    match prepared_active(fixture, provider)?.commit_and_reread() {
        WindowsLifecycleActiveCommitOutcome::ListenerPending(listener) => Ok(listener),
        WindowsLifecycleActiveCommitOutcome::ReloadRequired(reload) => {
            assert_exit78(reload.abort(LifecycleError::NotReady));
            Err(io::Error::other("fault-free Active commit required reload").into())
        }
        WindowsLifecycleActiveCommitOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            Err(io::Error::other("fault-free Active commit became terminal").into())
        }
    }
}

fn ready_service<'provider>(
    fixture: &RuntimePairFixture,
    provider: &'provider mut RunStateAuthenticationProvider,
) -> TestResult<WindowsNoSecretService<'provider>> {
    ready_service_with_effects(fixture, provider, test_effects()?)
}

fn ready_service_with_effects<'provider>(
    fixture: &RuntimePairFixture,
    provider: &'provider mut RunStateAuthenticationProvider,
    effects: WindowsLifecycleEffectAuthority,
) -> TestResult<WindowsNoSecretService<'provider>> {
    attach_effects(listener_pending(fixture, provider)?, effects)
}

fn attach_effects(
    listener: WindowsListenerPending<'_>,
    effects: WindowsLifecycleEffectAuthority,
) -> TestResult<WindowsNoSecretService<'_>> {
    let scm = match listener.prepare_listeners(effects) {
        WindowsListenerPreparationOutcome::ScmRunningPending(scm) => scm,
        WindowsListenerPreparationOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("listener fixture effect failed").into());
        }
    };
    let admission = match scm.publish_scm_running() {
        WindowsScmRunningPublicationOutcome::AdmissionPending(admission) => admission,
        WindowsScmRunningPublicationOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("SCM_RUNNING fixture effect failed").into());
        }
    };
    match admission.establish_admission() {
        WindowsAdmissionOpenOutcome::Running(service) => Ok(service),
        WindowsAdmissionOpenOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            Err(io::Error::other("admission fixture effect failed").into())
        }
    }
}

fn begin_remaining_cleanup(
    service: WindowsNoSecretService<'_>,
) -> TestResult<WindowsRemainingCleanup<'_>> {
    let closed = match service.close_admission() {
        WindowsAdmissionCloseOutcome::StopPending(closed) => closed,
        WindowsAdmissionCloseOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("admission close fixture effect failed").into());
        }
    };
    let invalidation = match closed.begin_stop_and_reject(StopReason::ScmStop) {
        WindowsStopPolicyOutcome::InvalidationPending(invalidation) => invalidation,
        WindowsStopPolicyOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("stop/reject policy failed").into());
        }
    };
    let drain = match invalidation.invalidate_non_durable_authority() {
        WindowsInvalidationOutcome::ListenerDrainPending(drain) => drain,
        WindowsInvalidationOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("authority invalidation policy failed").into());
        }
    };
    match drain.drain_listeners() {
        WindowsListenerDrainOutcome::RemainingCleanup(cleanup) => Ok(cleanup),
        WindowsListenerDrainOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            Err(io::Error::other("listener drain fixture effect failed").into())
        }
    }
}

fn complete_first_nine(
    service: WindowsNoSecretService<'_>,
) -> TestResult<WindowsRemainingCleanup<'_>> {
    let mut cleanup = begin_remaining_cleanup(service)?;
    cleanup.cancel_requests()?;
    cleanup.terminate_helpers()?;
    cleanup.reap_helpers()?;
    cleanup.discard_user_tokens()?;
    cleanup.flush_defined_durable_records()?;
    cleanup.release_request_hardware_and_storage_handles()?;
    Ok(cleanup)
}

fn clean_release_pending<'provider>(
    fixture: &RuntimePairFixture,
    provider: &'provider mut RunStateAuthenticationProvider,
) -> TestResult<WindowsCleanReleasePending<'provider>> {
    clean_release_pending_with_effects(fixture, provider, test_effects()?)
}

fn clean_release_pending_with_effects<'provider>(
    fixture: &RuntimePairFixture,
    provider: &'provider mut RunStateAuthenticationProvider,
    effects: WindowsLifecycleEffectAuthority,
) -> TestResult<WindowsCleanReleasePending<'provider>> {
    let service = ready_service_with_effects(fixture, provider, effects)?;
    let cleanup = complete_first_nine(service)?;
    match cleanup.prepare_clean() {
        WindowsLifecycleCleanCommitOutcome::ReleasePending(release) => Ok(release),
        WindowsLifecycleCleanCommitOutcome::ReloadRequired(reload) => {
            assert_exit78(reload.abort(LifecycleError::NotReady));
            Err(io::Error::other("fault-free Clean commit required reload").into())
        }
        WindowsLifecycleCleanCommitOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            Err(io::Error::other("fault-free Clean commit became terminal").into())
        }
    }
}

fn assert_effect_exit(
    exit: WindowsLifecycleExitRequired<'_>,
    stage: WindowsLifecycleEffectStage,
    disposition: WindowsLifecycleEffectDisposition,
) -> TestResult {
    assert!(matches!(
        exit.cause(),
        WindowsLifecycleCause::Effect(cause)
            if cause.stage() == stage && cause.disposition() == disposition
    ));
    assert!(exit.effects_attached_for_test());
    assert!(
        exit.effect_failure_for_test()
            .is_some_and(|cause| { cause.stage() == stage && cause.disposition() == disposition })
    );
    match exit.retire_checked() {
        Ok(checked) => {
            assert!(checked.effects_attached_for_test());
            assert!(checked.effect_failure_for_test().is_some_and(|cause| {
                cause.stage() == stage && cause.disposition() == disposition
            }));
            Ok(())
        }
        Err(failure) => Err(io::Error::other(format!(
            "effect failure retirement became irreversible: {failure:?}"
        ))
        .into()),
    }
}

fn assert_attached_checked_exit(exit: WindowsLifecycleExitRequired<'_>) -> TestResult {
    assert!(exit.effects_attached_for_test());
    match exit.retire_checked() {
        Ok(checked) => {
            assert!(checked.effects_attached_for_test());
            Ok(())
        }
        Err(failure) => Err(io::Error::other(format!(
            "attached effect retirement became irreversible: {failure:?}"
        ))
        .into()),
    }
}

fn assert_exhausted_effect_attempt_is_terminal() -> TestResult {
    let (fixture, _installation, mut provider) = clean_fixture(0xc8)?;
    let effects = WindowsLifecycleEffectAuthority::from_attempt_exhaustion_fixture()?;
    let exit = match listener_pending(&fixture, &mut provider)?.prepare_listeners(effects) {
        WindowsListenerPreparationOutcome::ExitRequired(exit) => exit,
        WindowsListenerPreparationOutcome::ScmRunningPending(scm) => {
            assert_checked_exit(scm.abort(LifecycleError::NotReady))?;
            return Err(io::Error::other("exhausted effect attempt was accepted").into());
        }
    };
    assert_effect_exit(
        exit,
        WindowsLifecycleEffectStage::PrepareListeners,
        WindowsLifecycleEffectDisposition::InvalidReceipt,
    )?;
    fixture.cleanup_checked()
}

fn finish_normal_stop(
    release: WindowsCleanReleasePending<'_>,
) -> TestResult<WindowsLifecycleStopped<'_>> {
    let pending = match release.release_writer() {
        WindowsLifecycleWriterReleaseOutcome::ScmStopPending(pending) => pending,
        WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("writer release retained terminal writer").into());
        }
        WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => {
            return Err(io::Error::other(format!(
                "writer release became irreversible: {failure:?}"
            ))
            .into());
        }
    };
    match pending.publish_scm_stopped() {
        WindowsLifecycleScmStopOutcome::Stopped(stopped) => Ok(stopped),
        WindowsLifecycleScmStopOutcome::IrreversibleExit78(failure) => Err(io::Error::other(
            format!("SCM_STOPPED publication became irreversible: {failure:?}"),
        )
        .into()),
    }
}

#[test]
fn clean_startup_active_runtime_clean_release_reaches_normal_stopped() -> TestResult {
    let (fixture, _installation, mut provider) = clean_fixture(0x31)?;
    let release = clean_release_pending(&fixture, &mut provider)?;
    let stopped = finish_normal_stop(release)?;
    assert_eq!(stopped.generation().get(), 3);
    assert_eq!(
        format!("{stopped:?}"),
        "WindowsLifecycleStopped([REDACTED])"
    );
    fixture.cleanup_checked()
}

#[test]
fn startup_missing_and_mismatch_require_checked_silent_exit78() -> TestResult {
    for (byte, mismatch) in [(0x41, false), (0x43, true)] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let mut startup = begin(&fixture, &mut provider)?;
        if mismatch {
            for requirement in NoSecretStartupRequirement::ALL {
                startup.observe(
                    requirement,
                    if requirement == NoSecretStartupRequirement::ServiceToken {
                        StartupObservation::Mismatch
                    } else {
                        StartupObservation::Verified
                    },
                )?;
            }
        }
        let Err(exit) = startup.finish() else {
            return Err(io::Error::other("rejected startup minted Active preparation").into());
        };
        match exit.cause() {
            WindowsLifecycleCause::Startup(StartupFailure::Missing(
                NoSecretStartupRequirement::ServiceToken,
            )) if !mismatch => {}
            WindowsLifecycleCause::Startup(StartupFailure::Mismatch(
                NoSecretStartupRequirement::ServiceToken,
            )) if mismatch => {}
            cause => {
                return Err(io::Error::other(format!(
                    "startup retained the wrong cause: {cause:?}"
                ))
                .into());
            }
        }
        assert_checked_exit(exit)?;
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn active_ambiguity_reloads_prior_with_fresh_checks_candidate_with_carried_checks_and_partial_terminal()
-> TestResult {
    for (byte, fault) in [
        (0x51, RuntimePairFault::MarkerRenameAttempt),
        (0x53, RuntimePairFault::AfterCheckpointRename),
        (0x55, RuntimePairFault::AfterMarkerRename),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let prepared = prepared_active(&fixture, &mut provider)?;
        fixture.inject_fault(fault);
        let reload = match prepared.commit_and_reread() {
            WindowsLifecycleActiveCommitOutcome::ReloadRequired(reload) => reload,
            WindowsLifecycleActiveCommitOutcome::ListenerPending(listener) => {
                assert_checked_exit(listener.abort(LifecycleError::NotReady))?;
                return Err(io::Error::other("fault did not produce Active reload").into());
            }
            WindowsLifecycleActiveCommitOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("fault became terminal before Active reload").into());
            }
        };
        match (fault, reload.reload()) {
            (
                RuntimePairFault::MarkerRenameAttempt,
                WindowsLifecycleActiveReloadOutcome::Revalidate(startup),
            ) => {
                let Err(exit) = startup.finish() else {
                    return Err(io::Error::other("prior reload reused completed checklist").into());
                };
                assert!(matches!(
                    exit.cause(),
                    WindowsLifecycleCause::Startup(StartupFailure::Missing(
                        NoSecretStartupRequirement::ServiceToken
                    ))
                ));
                assert_checked_exit(exit)?;
            }
            (
                RuntimePairFault::AfterCheckpointRename,
                WindowsLifecycleActiveReloadOutcome::ListenerPending(listener),
            ) => {
                let service = attach_effects(listener, test_effects()?)?;
                assert_eq!(service.state(), RuntimeState::Ready);
                assert_checked_exit(service.into_exit(LifecycleError::NotReady))?;
            }
            (
                RuntimePairFault::AfterMarkerRename,
                WindowsLifecycleActiveReloadOutcome::ExitRequired(exit),
            ) => {
                assert!(matches!(exit.cause(), WindowsLifecycleCause::Durable(_)));
                assert_exit78(exit);
            }
            (_, _) => {
                return Err(io::Error::other("Active reload produced the wrong resolution").into());
            }
        }
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn confirmed_active_reread_failure_never_restores_boot_or_listener_authority() -> TestResult {
    let (fixture, _installation, mut provider) = clean_fixture(0x61)?;
    let prepared = prepared_active(&fixture, &mut provider)?;
    fixture.inject_fault(RuntimePairFault::CommittedRereadRevalidation);
    let exit = match prepared.commit_and_reread() {
        WindowsLifecycleActiveCommitOutcome::ExitRequired(exit) => exit,
        WindowsLifecycleActiveCommitOutcome::ReloadRequired(reload) => {
            assert_exit78(reload.abort(LifecycleError::NotReady));
            return Err(io::Error::other("confirmed reread failure exposed reload").into());
        }
        WindowsLifecycleActiveCommitOutcome::ListenerPending(listener) => {
            assert_exit78(listener.abort(LifecycleError::NotReady));
            return Err(io::Error::other("confirmed reread failure exposed listener").into());
        }
    };
    assert!(matches!(
        exit.cause(),
        WindowsLifecycleCause::Durable(cause)
            if cause.recovery() == RecoveryRequired::RereadDrift
    ));
    assert_exit78(exit);
    fixture.cleanup_checked()
}

#[test]
fn listener_scm_and_admission_typestates_are_ordered_and_move_only() {
    let _: fn(
        WindowsListenerPending<'static>,
        WindowsLifecycleEffectAuthority,
    ) -> WindowsListenerPreparationOutcome<'static> = WindowsListenerPending::prepare_listeners;
    let _: fn(WindowsScmRunningPending<'static>) -> WindowsScmRunningPublicationOutcome<'static> =
        WindowsScmRunningPending::publish_scm_running;
    let _: fn(WindowsAdmissionPending<'static>) -> WindowsAdmissionOpenOutcome<'static> =
        WindowsAdmissionPending::establish_admission;

    assert_move_only!(WindowsStartupAttempt<'static>);
    assert_move_only!(WindowsActiveCommitPending<'static>);
    assert_move_only!(WindowsActiveReloadPending<'static>);
    assert_move_only!(WindowsListenerPending<'static>);
    assert_move_only!(WindowsScmRunningPending<'static>);
    assert_move_only!(WindowsAdmissionPending<'static>);
    assert_move_only!(WindowsNoSecretService<'static>);
    assert_move_only!(WindowsAdmissionClosedService<'static>);
    assert_move_only!(WindowsInvalidationPending<'static>);
    assert_move_only!(WindowsListenerDrainPending<'static>);
    assert_move_only!(WindowsRemainingCleanup<'static>);
    assert_move_only!(WindowsCleanReloadPending<'static>);
    assert_move_only!(WindowsCleanReleasePending<'static>);
    assert_move_only!(WindowsScmStopPending<'static>);
    assert_move_only!(WindowsLifecycleExitRequired<'static>);
    assert_move_only!(WindowsLifecycleCheckedExit78<'static>);
    assert_move_only!(WindowsLifecycleIrreversibleExit78<'static>);
    assert_move_only!(WindowsLifecycleStopped);
}

#[test]
fn effect_authority_is_sealed_move_only_redacted_and_production_unmintable() -> TestResult {
    let source = include_str!("windows_lifecycle_effects.rs");
    assert!(source.contains("Unavailable(Infallible)"));
    assert!(source.contains("#[cfg(test)]\n    pub(super) fn from_fixture"));
    for forbidden in [
        "unsafe {",
        "dyn Any",
        "downcast",
        "RawHandle",
        "HANDLE",
        "canonicalize(",
        "impl Clone for WindowsLifecycleEffectAuthority",
        "impl Copy for WindowsLifecycleEffectAuthority",
        "impl Default for WindowsLifecycleEffectAuthority",
        "impl From<",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden effect surface: {forbidden}"
        );
    }

    let effects = test_effects()?;
    assert_eq!(
        format!("{effects:?}"),
        "WindowsLifecycleEffectAuthority([REDACTED])"
    );
    assert_move_only!(WindowsLifecycleEffectAuthority);
    assert_move_only!(WindowsListenersPreparedEffects);
    assert_move_only!(WindowsScmRunningEffects);
    assert_move_only!(WindowsAdmissionOpenEffects);
    assert_move_only!(WindowsAdmissionClosedEffects);
    assert_move_only!(WindowsListenersDrainedEffects);
    assert_move_only!(WindowsScmStoppedEffectEvidence);
    Ok(())
}

#[test]
fn effect_backed_startup_is_exactly_ordered_consuming_and_one_shot() -> TestResult {
    let _: fn(
        WindowsListenerPending<'static>,
        WindowsLifecycleEffectAuthority,
    ) -> WindowsListenerPreparationOutcome<'static> = WindowsListenerPending::prepare_listeners;
    let _: fn(WindowsScmRunningPending<'static>) -> WindowsScmRunningPublicationOutcome<'static> =
        WindowsScmRunningPending::publish_scm_running;
    let _: fn(WindowsAdmissionPending<'static>) -> WindowsAdmissionOpenOutcome<'static> =
        WindowsAdmissionPending::establish_admission;

    let source = include_str!("windows_lifecycle.rs");
    for removed in [
        "fn record_listeners_prepared(self)",
        "fn record_scm_running_published(self)",
        "pub(super) fn open_admission(self)",
    ] {
        assert!(
            !source.contains(removed),
            "zero-argument bypass survived: {removed}"
        );
    }

    let (fixture, _installation, mut provider) = clean_fixture(0xc1)?;
    let service = attach_effects(listener_pending(&fixture, &mut provider)?, test_effects()?)?;
    assert_eq!(service.state(), RuntimeState::Ready);
    assert_checked_exit(service.into_exit(LifecycleError::NotReady))?;
    fixture.cleanup_checked()
}

#[test]
fn cross_binding_duplicate_and_wrong_purpose_receipts_are_rejected_non_vacuously() -> TestResult {
    {
        let (fixture, _installation, mut provider) = clean_fixture(0xc3)?;
        let foreign = test_effects()?;
        let effects = WindowsLifecycleEffectAuthority::from_cross_bound_fixture(
            WindowsLifecycleEffectStage::PrepareListeners,
            &foreign,
        )?;
        assert!(effects.has_distinct_binding_for_test(&foreign));
        let exit = match listener_pending(&fixture, &mut provider)?.prepare_listeners(effects) {
            WindowsListenerPreparationOutcome::ExitRequired(exit) => exit,
            WindowsListenerPreparationOutcome::ScmRunningPending(scm) => {
                assert_checked_exit(scm.abort(LifecycleError::NotReady))?;
                return Err(io::Error::other("cross-bound listener receipt was accepted").into());
            }
        };
        assert_effect_exit(
            exit,
            WindowsLifecycleEffectStage::PrepareListeners,
            WindowsLifecycleEffectDisposition::InvalidReceipt,
        )?;
        fixture.cleanup_checked()?;
    }

    {
        let (fixture, _installation, mut provider) = clean_fixture(0xc5)?;
        let effects = faulting_effects(FixtureWindowsLifecycleEffectFault::DuplicateReceipt(
            WindowsLifecycleEffectStage::PublishScmRunning,
        ))?;
        let scm = match listener_pending(&fixture, &mut provider)?.prepare_listeners(effects) {
            WindowsListenerPreparationOutcome::ScmRunningPending(scm) => scm,
            WindowsListenerPreparationOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(
                    io::Error::other("duplicate fixture failed before target stage").into(),
                );
            }
        };
        let exit = match scm.publish_scm_running() {
            WindowsScmRunningPublicationOutcome::ExitRequired(exit) => exit,
            WindowsScmRunningPublicationOutcome::AdmissionPending(admission) => {
                assert_checked_exit(admission.abort(LifecycleError::NotReady))?;
                return Err(io::Error::other("duplicate SCM receipt was accepted").into());
            }
        };
        assert_effect_exit(
            exit,
            WindowsLifecycleEffectStage::PublishScmRunning,
            WindowsLifecycleEffectDisposition::InvalidReceipt,
        )?;
        fixture.cleanup_checked()?;
    }

    {
        let (fixture, _installation, mut provider) = clean_fixture(0xc7)?;
        let effects = faulting_effects(FixtureWindowsLifecycleEffectFault::WrongPurpose(
            WindowsLifecycleEffectStage::OpenAdmission,
        ))?;
        let listener = listener_pending(&fixture, &mut provider)?;
        let scm = match listener.prepare_listeners(effects) {
            WindowsListenerPreparationOutcome::ScmRunningPending(scm) => scm,
            WindowsListenerPreparationOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(
                    io::Error::other("purpose fixture failed before listener receipt").into(),
                );
            }
        };
        let admission = match scm.publish_scm_running() {
            WindowsScmRunningPublicationOutcome::AdmissionPending(admission) => admission,
            WindowsScmRunningPublicationOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("purpose fixture failed before SCM receipt").into());
            }
        };
        let exit = match admission.establish_admission() {
            WindowsAdmissionOpenOutcome::ExitRequired(exit) => exit,
            WindowsAdmissionOpenOutcome::Running(service) => {
                assert_checked_exit(service.into_exit(LifecycleError::NotReady))?;
                return Err(
                    io::Error::other("wrong-purpose admission receipt was accepted").into(),
                );
            }
        };
        assert_effect_exit(
            exit,
            WindowsLifecycleEffectStage::OpenAdmission,
            WindowsLifecycleEffectDisposition::InvalidReceipt,
        )?;
        fixture.cleanup_checked()?;
    }

    assert_exhausted_effect_attempt_is_terminal()?;
    Ok(())
}

#[test]
fn listener_preparation_failure_and_ambiguity_preserve_effects_through_checked_exit() -> TestResult
{
    for (byte, fault, disposition) in [
        (
            0xc9,
            FixtureWindowsLifecycleEffectFault::KnownNotApplied(
                WindowsLifecycleEffectStage::PrepareListeners,
            ),
            WindowsLifecycleEffectDisposition::KnownNotApplied,
        ),
        (
            0xcb,
            FixtureWindowsLifecycleEffectFault::Ambiguous(
                WindowsLifecycleEffectStage::PrepareListeners,
            ),
            WindowsLifecycleEffectDisposition::Ambiguous,
        ),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let exit = match listener_pending(&fixture, &mut provider)?
            .prepare_listeners(faulting_effects(fault)?)
        {
            WindowsListenerPreparationOutcome::ExitRequired(exit) => exit,
            WindowsListenerPreparationOutcome::ScmRunningPending(scm) => {
                assert_checked_exit(scm.abort(LifecycleError::NotReady))?;
                return Err(io::Error::other("listener effect fault was accepted").into());
            }
        };
        assert_effect_exit(
            exit,
            WindowsLifecycleEffectStage::PrepareListeners,
            disposition,
        )?;
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn scm_running_failure_and_ambiguity_preserve_effects_through_checked_exit() -> TestResult {
    for (byte, fault, disposition) in [
        (
            0xcd,
            FixtureWindowsLifecycleEffectFault::KnownNotApplied(
                WindowsLifecycleEffectStage::PublishScmRunning,
            ),
            WindowsLifecycleEffectDisposition::KnownNotApplied,
        ),
        (
            0xcf,
            FixtureWindowsLifecycleEffectFault::Ambiguous(
                WindowsLifecycleEffectStage::PublishScmRunning,
            ),
            WindowsLifecycleEffectDisposition::Ambiguous,
        ),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let effects = faulting_effects(fault)?;
        let scm = match listener_pending(&fixture, &mut provider)?.prepare_listeners(effects) {
            WindowsListenerPreparationOutcome::ScmRunningPending(scm) => scm,
            WindowsListenerPreparationOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("SCM fixture failed before target stage").into());
            }
        };
        let exit = match scm.publish_scm_running() {
            WindowsScmRunningPublicationOutcome::ExitRequired(exit) => exit,
            WindowsScmRunningPublicationOutcome::AdmissionPending(admission) => {
                assert_checked_exit(admission.abort(LifecycleError::NotReady))?;
                return Err(io::Error::other("SCM effect fault was accepted").into());
            }
        };
        assert_effect_exit(
            exit,
            WindowsLifecycleEffectStage::PublishScmRunning,
            disposition,
        )?;
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn admission_open_failure_and_ambiguity_preserve_effects_through_checked_exit() -> TestResult {
    for (byte, fault, disposition) in [
        (
            0xd1,
            FixtureWindowsLifecycleEffectFault::KnownNotApplied(
                WindowsLifecycleEffectStage::OpenAdmission,
            ),
            WindowsLifecycleEffectDisposition::KnownNotApplied,
        ),
        (
            0xd3,
            FixtureWindowsLifecycleEffectFault::Ambiguous(
                WindowsLifecycleEffectStage::OpenAdmission,
            ),
            WindowsLifecycleEffectDisposition::Ambiguous,
        ),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let listener = listener_pending(&fixture, &mut provider)?;
        let scm = match listener.prepare_listeners(faulting_effects(fault)?) {
            WindowsListenerPreparationOutcome::ScmRunningPending(scm) => scm,
            WindowsListenerPreparationOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(
                    io::Error::other("admission fixture failed before listener receipt").into(),
                );
            }
        };
        let admission = match scm.publish_scm_running() {
            WindowsScmRunningPublicationOutcome::AdmissionPending(admission) => admission,
            WindowsScmRunningPublicationOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("admission fixture failed before SCM receipt").into());
            }
        };
        let exit = match admission.establish_admission() {
            WindowsAdmissionOpenOutcome::ExitRequired(exit) => exit,
            WindowsAdmissionOpenOutcome::Running(service) => {
                assert_checked_exit(service.into_exit(LifecycleError::NotReady))?;
                return Err(io::Error::other("admission effect fault was accepted").into());
            }
        };
        assert_effect_exit(
            exit,
            WindowsLifecycleEffectStage::OpenAdmission,
            disposition,
        )?;
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn admission_close_precedes_stop_reject_and_failure_never_enters_cleanup() -> TestResult {
    let _: fn(WindowsNoSecretService<'static>) -> WindowsAdmissionCloseOutcome<'static> =
        WindowsNoSecretService::close_admission;
    let _: fn(
        WindowsAdmissionClosedService<'static>,
        StopReason,
    ) -> WindowsStopPolicyOutcome<'static> = WindowsAdmissionClosedService::begin_stop_and_reject;

    for (byte, fault, disposition) in [
        (
            0xd5,
            FixtureWindowsLifecycleEffectFault::KnownNotApplied(
                WindowsLifecycleEffectStage::CloseAdmission,
            ),
            WindowsLifecycleEffectDisposition::KnownNotApplied,
        ),
        (
            0xd7,
            FixtureWindowsLifecycleEffectFault::Ambiguous(
                WindowsLifecycleEffectStage::CloseAdmission,
            ),
            WindowsLifecycleEffectDisposition::Ambiguous,
        ),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let service =
            ready_service_with_effects(&fixture, &mut provider, faulting_effects(fault)?)?;
        assert_eq!(service.expected_cleanup_step(), None);
        let exit = match service.close_admission() {
            WindowsAdmissionCloseOutcome::ExitRequired(exit) => exit,
            WindowsAdmissionCloseOutcome::StopPending(closed) => {
                let exit = match closed.begin_stop_and_reject(StopReason::ScmStop) {
                    WindowsStopPolicyOutcome::ExitRequired(exit) => exit,
                    WindowsStopPolicyOutcome::InvalidationPending(invalidation) => {
                        match invalidation.invalidate_non_durable_authority() {
                            WindowsInvalidationOutcome::ExitRequired(exit) => exit,
                            WindowsInvalidationOutcome::ListenerDrainPending(drain) => {
                                match drain.drain_listeners() {
                                    WindowsListenerDrainOutcome::ExitRequired(exit) => exit,
                                    WindowsListenerDrainOutcome::RemainingCleanup(cleanup) => {
                                        let exit = cleanup.into_exit(LifecycleError::NotReady);
                                        assert_checked_exit(exit)?;
                                        return Err(io::Error::other(
                                            "admission-close fault was accepted",
                                        )
                                        .into());
                                    }
                                }
                            }
                        }
                    }
                };
                assert_checked_exit(exit)?;
                return Err(io::Error::other("admission-close fault skipped target stage").into());
            }
        };
        assert_effect_exit(
            exit,
            WindowsLifecycleEffectStage::CloseAdmission,
            disposition,
        )?;
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn invalidate_then_effect_drain_gates_fixed_remaining_cleanup_without_generic_bypass() -> TestResult
{
    let source = include_str!("windows_lifecycle.rs");
    assert!(!source.contains("pub(super) fn complete_cleanup_step"));
    assert!(!source.contains("pub(super) fn begin_stop(&mut self"));
    for required in [
        "pub(super) fn cancel_requests",
        "pub(super) fn terminate_helpers",
        "pub(super) fn reap_helpers",
        "pub(super) fn discard_user_tokens",
        "pub(super) fn flush_defined_durable_records",
        "pub(super) fn release_request_hardware_and_storage_handles",
    ] {
        assert!(
            source.contains(required),
            "missing fixed cleanup method: {required}"
        );
    }

    for (byte, fault, disposition) in [
        (
            0xd9,
            FixtureWindowsLifecycleEffectFault::KnownNotApplied(
                WindowsLifecycleEffectStage::DrainListeners,
            ),
            WindowsLifecycleEffectDisposition::KnownNotApplied,
        ),
        (
            0xdb,
            FixtureWindowsLifecycleEffectFault::Ambiguous(
                WindowsLifecycleEffectStage::DrainListeners,
            ),
            WindowsLifecycleEffectDisposition::Ambiguous,
        ),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let service =
            ready_service_with_effects(&fixture, &mut provider, faulting_effects(fault)?)?;
        let closed = match service.close_admission() {
            WindowsAdmissionCloseOutcome::StopPending(closed) => closed,
            WindowsAdmissionCloseOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("drain fixture failed during admission close").into());
            }
        };
        let invalidation = match closed.begin_stop_and_reject(StopReason::ScmStop) {
            WindowsStopPolicyOutcome::InvalidationPending(invalidation) => invalidation,
            WindowsStopPolicyOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("drain fixture failed during stop/reject").into());
            }
        };
        let drain = match invalidation.invalidate_non_durable_authority() {
            WindowsInvalidationOutcome::ListenerDrainPending(drain) => drain,
            WindowsInvalidationOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("drain fixture failed during invalidation").into());
            }
        };
        let exit = match drain.drain_listeners() {
            WindowsListenerDrainOutcome::ExitRequired(exit) => exit,
            WindowsListenerDrainOutcome::RemainingCleanup(cleanup) => {
                assert_checked_exit(cleanup.into_exit(LifecycleError::NotReady))?;
                return Err(io::Error::other("listener-drain effect fault was accepted").into());
            }
        };
        assert_effect_exit(
            exit,
            WindowsLifecycleEffectStage::DrainListeners,
            disposition,
        )?;
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn effect_carrier_survives_clean_reload_release_and_every_durable_terminal_class() -> TestResult {
    {
        let (fixture, _installation, mut provider) = clean_fixture(0xdd)?;
        let service = complete_first_nine(ready_service(&fixture, &mut provider)?)?;
        fixture.inject_fault(RuntimePairFault::MarkerRenameAttempt);
        let reload = match service.prepare_clean() {
            WindowsLifecycleCleanCommitOutcome::ReloadRequired(reload) => reload,
            WindowsLifecycleCleanCommitOutcome::ReleasePending(release) => {
                assert_attached_checked_exit(release.abort(LifecycleError::NotReady))?;
                return Err(io::Error::other("Clean fault skipped reload").into());
            }
            WindowsLifecycleCleanCommitOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("Clean fault became terminal before reload").into());
            }
        };
        assert_attached_checked_exit(reload.abort(LifecycleError::NotReady))?;
        fixture.cleanup_checked()?;
    }

    {
        let (fixture, _installation, mut provider) = clean_fixture(0xdf)?;
        let release = clean_release_pending(&fixture, &mut provider)?;
        fixture.inject_fault(RuntimePairFault::WriterReleaseUnlock);
        let exit = match release.release_writer() {
            WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => exit,
            WindowsLifecycleWriterReleaseOutcome::ScmStopPending(_) => {
                return Err(io::Error::other("writer-retained fault released writer").into());
            }
            WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => {
                return Err(io::Error::other(format!("wrong terminal class: {failure:?}")).into());
            }
        };
        assert_attached_checked_exit(exit)?;
        fixture.cleanup_checked()?;
    }

    for (byte, fault, post_release) in [
        (0xe1, Some(RuntimePairFault::CheckpointFinalClose), false),
        (0xe3, None, true),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let release = clean_release_pending(&fixture, &mut provider)?;
        if let Some(fault) = fault {
            fixture.inject_fault(fault);
        }
        let failure = if post_release {
            match release.release_writer_with_post_release_fault_for_test() {
                WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => failure,
                WindowsLifecycleWriterReleaseOutcome::ScmStopPending(_) => {
                    return Err(io::Error::other("post-release fault reached SCM stop").into());
                }
                WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => {
                    assert_exit78(exit);
                    return Err(io::Error::other("post-release fault retained writer").into());
                }
            }
        } else {
            match release.release_writer() {
                WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => failure,
                WindowsLifecycleWriterReleaseOutcome::ScmStopPending(_) => {
                    return Err(io::Error::other("no-receipt fault reached SCM stop").into());
                }
                WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => {
                    assert_exit78(exit);
                    return Err(io::Error::other("no-receipt fault retained writer").into());
                }
            }
        };
        assert!(failure.effects_attached_for_test());
        assert_eq!(failure.code(), WINDOWS_SERVICE_EXIT_CODE);
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn post_writer_release_scm_stop_failure_and_ambiguity_are_irreversible_with_both_evidences()
-> TestResult {
    for (byte, fault, disposition) in [
        (
            0xe5,
            FixtureWindowsLifecycleEffectFault::KnownNotApplied(
                WindowsLifecycleEffectStage::PublishScmStopped,
            ),
            WindowsLifecycleEffectDisposition::KnownNotApplied,
        ),
        (
            0xe7,
            FixtureWindowsLifecycleEffectFault::Ambiguous(
                WindowsLifecycleEffectStage::PublishScmStopped,
            ),
            WindowsLifecycleEffectDisposition::Ambiguous,
        ),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let effects = faulting_effects(fault)?;
        let binding = effects.binding_witness_for_test();
        let release = clean_release_pending_with_effects(&fixture, &mut provider, effects)?;
        let pending = match release.release_writer() {
            WindowsLifecycleWriterReleaseOutcome::ScmStopPending(pending) => pending,
            WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("fault-free writer release retained writer").into());
            }
            WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => {
                return Err(io::Error::other(format!(
                    "fault-free writer release became irreversible: {failure:?}"
                ))
                .into());
            }
        };
        let failure = match pending.publish_scm_stopped() {
            WindowsLifecycleScmStopOutcome::IrreversibleExit78(failure) => failure,
            WindowsLifecycleScmStopOutcome::Stopped(_) => {
                return Err(io::Error::other("SCM_STOPPED fault minted Stopped").into());
            }
        };
        assert_eq!(failure.code(), WINDOWS_SERVICE_EXIT_CODE);
        assert!(failure.effects_attached_for_test());
        assert!(failure.post_writer_release_effect_binding_matches_for_test(binding));
        assert_eq!(
            failure
                .post_writer_release_generation_for_test()
                .map(NonZeroU64::get),
            Some(3)
        );
        assert!(matches!(
            failure.cause(),
            WindowsLifecycleIrreversibleCause::ScmStoppedPublication { effect }
                if effect.stage() == WindowsLifecycleEffectStage::PublishScmStopped
                    && effect.disposition() == disposition
        ));
        assert!(format!("{failure:?}").contains("[REDACTED]"));
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn runtime_policy_alone_enforces_work_token_and_quarantine_bounds() -> TestResult {
    let (fixture, _installation, mut provider) = clean_fixture(0x71)?;
    let mut service = ready_service(&fixture, &mut provider)?;
    let work_session = SessionId::new(1)?;
    for value in 1..=256_u64 {
        service.admit_fixture_work(
            WorkId::new(value)?,
            work_session,
            NoSecretFixtureWorkKind::Approval,
        )?;
    }
    assert_eq!(
        service.admit_fixture_work(
            WorkId::new(257)?,
            work_session,
            NoSecretFixtureWorkKind::Approval,
        ),
        Err(LifecycleError::WorkCapacityExhausted)
    );
    assert_eq!(service.work_count(), 256);

    for value in 1..=64_u32 {
        service.retain_user_token(SessionId::new(value)?)?;
    }
    assert_eq!(
        service.retain_user_token(SessionId::new(65)?),
        Err(LifecycleError::UserTokenCapacityExhausted)
    );
    assert_eq!(service.retained_user_token_count(), 64);

    for value in 1..=64_u32 {
        let report = service.handle_session_event(SessionEvent::Lock(SessionId::new(value)?))?;
        assert!(report.revalidation_required());
        if value == 1 {
            assert_eq!(report.authorities_invalidated(), 256);
            assert_eq!(report.helper_terminations_required(), 256);
            assert_eq!(report.user_tokens_discarded(), 0);
        }
    }
    assert_eq!(service.quarantined_session_count(), 64);
    assert_eq!(
        service.handle_session_event(SessionEvent::Lock(SessionId::new(65)?)),
        Err(LifecycleError::SessionQuarantineExhausted)
    );
    assert_eq!(
        service.state(),
        RuntimeState::Fatal(FatalReason::SessionQuarantineExceeded)
    );
    assert_eq!(service.retained_user_token_count(), 0);
    let exit = service.into_fatal_exit();
    assert!(matches!(
        exit.cause(),
        WindowsLifecycleCause::Fatal(FatalReason::SessionQuarantineExceeded)
    ));
    assert_checked_exit(exit)?;
    fixture.cleanup_checked()
}

#[test]
fn cleanup_requires_exact_order_and_empties_all_runtime_registries_before_clean() -> TestResult {
    let (premature_fixture, _premature_installation, mut premature_provider) = clean_fixture(0x73)?;
    let premature = ready_service(&premature_fixture, &mut premature_provider)?;
    let premature = begin_remaining_cleanup(premature)?;
    let exit = match premature.prepare_clean() {
        WindowsLifecycleCleanCommitOutcome::ExitRequired(exit) => exit,
        WindowsLifecycleCleanCommitOutcome::ReleasePending(release) => {
            assert_checked_exit(release.abort(LifecycleError::NotReady))?;
            return Err(io::Error::other("out-of-order cleanup minted release policy").into());
        }
        WindowsLifecycleCleanCommitOutcome::ReloadRequired(reload) => {
            assert_checked_exit(reload.abort(LifecycleError::NotReady))?;
            return Err(io::Error::other("out-of-order cleanup minted reload policy").into());
        }
    };
    assert!(matches!(
        exit.cause(),
        WindowsLifecycleCause::RuntimePolicy(RuntimePolicyFailure::CleanupOutOfOrder)
    ));
    assert_checked_exit(exit)?;
    premature_fixture.cleanup_checked()?;

    let (fixture, _installation, mut provider) = clean_fixture(0x75)?;
    let mut service = ready_service(&fixture, &mut provider)?;
    let session = SessionId::new(9)?;
    service.retain_user_token(session)?;
    service.admit_fixture_work(
        WorkId::new(11)?,
        session,
        NoSecretFixtureWorkKind::SecretInput,
    )?;
    service.handle_session_event(SessionEvent::Lock(session))?;
    let service = complete_first_nine(service)?;
    assert_eq!(service.work_count(), 0);
    assert_eq!(service.retained_user_token_count(), 0);
    assert_eq!(service.quarantined_session_count(), 0);
    assert_eq!(
        service.expected_cleanup_step(),
        Some(CleanupStep::CommitAndRereadCleanMarker)
    );
    let release = match service.prepare_clean() {
        WindowsLifecycleCleanCommitOutcome::ReleasePending(release) => release,
        WindowsLifecycleCleanCommitOutcome::ReloadRequired(reload) => {
            assert_checked_exit(reload.abort(LifecycleError::NotReady))?;
            return Err(io::Error::other("fault-free Clean required reload").into());
        }
        WindowsLifecycleCleanCommitOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("complete cleanup became terminal").into());
        }
    };
    let _stopped = finish_normal_stop(release)?;
    fixture.cleanup_checked()
}

#[test]
fn clean_ambiguity_advances_release_policy_for_candidate_only() -> TestResult {
    for (byte, fault) in [
        (0x81, RuntimePairFault::AfterCheckpointRename),
        (0x83, RuntimePairFault::MarkerRenameAttempt),
        (0x85, RuntimePairFault::AfterMarkerRename),
    ] {
        let (fixture, _installation, mut provider) = clean_fixture(byte)?;
        let service = ready_service(&fixture, &mut provider)?;
        let service = complete_first_nine(service)?;
        fixture.inject_fault(fault);
        let reload = match service.prepare_clean() {
            WindowsLifecycleCleanCommitOutcome::ReloadRequired(reload) => reload,
            WindowsLifecycleCleanCommitOutcome::ReleasePending(release) => {
                assert_checked_exit(release.abort(LifecycleError::NotReady))?;
                return Err(io::Error::other("Clean fault skipped mandatory reload").into());
            }
            WindowsLifecycleCleanCommitOutcome::ExitRequired(exit) => {
                assert_exit78(exit);
                return Err(io::Error::other("Clean fault became terminal before reload").into());
            }
        };
        match (fault, reload.reload()) {
            (
                RuntimePairFault::AfterCheckpointRename,
                WindowsLifecycleCleanReloadOutcome::ReleasePending(release),
            ) => {
                let _stopped = finish_normal_stop(release)?;
            }
            (
                RuntimePairFault::MarkerRenameAttempt | RuntimePairFault::AfterMarkerRename,
                WindowsLifecycleCleanReloadOutcome::ExitRequired(exit),
            ) => {
                assert!(matches!(exit.cause(), WindowsLifecycleCause::Durable(_)));
                assert_exit78(exit);
            }
            (_, _) => {
                return Err(io::Error::other("Clean reload produced the wrong resolution").into());
            }
        }
        fixture.cleanup_checked()?;
    }
    Ok(())
}

#[test]
fn release_writer_retained_checks_retirement_and_no_receipt_is_irreversible_exit78() -> TestResult {
    let (retained_fixture, _retained_installation, mut retained_provider) = clean_fixture(0x91)?;
    let retained = clean_release_pending(&retained_fixture, &mut retained_provider)?;
    retained_fixture.inject_fault(RuntimePairFault::WriterReleaseUnlock);
    let exit = match retained.release_writer() {
        WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => exit,
        WindowsLifecycleWriterReleaseOutcome::ScmStopPending(_pending) => {
            return Err(io::Error::other("writer-retaining fault released the writer").into());
        }
        WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => {
            return Err(io::Error::other(format!(
                "writer-retaining fault lost retirement path: {failure:?}"
            ))
            .into());
        }
    };
    assert!(matches!(
        exit.cause(),
        WindowsLifecycleCause::Durable(cause)
            if cause.recovery() == RecoveryRequired::WriterReleaseAmbiguous
    ));
    assert_checked_exit(exit)?;
    retained_fixture.cleanup_checked()?;

    let (no_receipt_fixture, _no_receipt_installation, mut no_receipt_provider) =
        clean_fixture(0x93)?;
    let no_receipt = clean_release_pending(&no_receipt_fixture, &mut no_receipt_provider)?;
    no_receipt_fixture.inject_fault(RuntimePairFault::CheckpointFinalClose);
    let failure = match no_receipt.release_writer() {
        WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => failure,
        WindowsLifecycleWriterReleaseOutcome::ScmStopPending(_pending) => {
            return Err(io::Error::other("no-receipt fault advanced to SCM stop").into());
        }
        WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("no-receipt fault retained retry authority").into());
        }
    };
    assert_eq!(failure.code(), WINDOWS_SERVICE_EXIT_CODE);
    assert!(matches!(
        failure.cause(),
        WindowsLifecycleIrreversibleCause::ReleasedNoReceipt {
            recovery: RecoveryRequired::WriterReleaseAmbiguous,
            platform: ServiceRunStateError::Release,
        }
    ));
    assert!(format!("{failure:?}").contains("[REDACTED]"));
    no_receipt_fixture.cleanup_checked()
}

#[test]
fn post_release_logical_failure_is_irreversible_exit78_and_never_stopped() -> TestResult {
    let (fixture, _installation, mut provider) = clean_fixture(0x95)?;
    let release = clean_release_pending(&fixture, &mut provider)?;
    let failure = match release.release_writer_with_post_release_fault_for_test() {
        WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => failure,
        WindowsLifecycleWriterReleaseOutcome::ScmStopPending(_pending) => {
            return Err(io::Error::other("post-release logical fault advanced to SCM stop").into());
        }
        WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(
                io::Error::other("post-release logical fault retained writer retry").into(),
            );
        }
    };
    assert_eq!(failure.code(), WINDOWS_SERVICE_EXIT_CODE);
    assert!(matches!(
        failure.cause(),
        WindowsLifecycleIrreversibleCause::PostRelease {
            recovery: RecoveryRequired::OperationPhaseMismatch,
        }
    ));
    assert!(format!("{failure:?}").contains("[REDACTED]"));
    fixture.cleanup_checked()
}

#[test]
fn retirement_fault_preserves_original_lifecycle_and_platform_cleanup_causes() -> TestResult {
    let (fixture, _installation, mut provider) = clean_fixture(0xa1)?;
    let startup = begin(&fixture, &mut provider)?;
    let Err(exit) = startup.finish() else {
        return Err(io::Error::other("missing checklist minted Active preparation").into());
    };
    fixture.inject_fault(RuntimePairFault::WriterReleaseUnlock);
    let failure = match exit.retire_checked() {
        Err(failure) => failure,
        Ok(_receipt) => {
            return Err(io::Error::other("retirement fault minted checked exit evidence").into());
        }
    };
    assert_eq!(failure.code(), WINDOWS_SERVICE_EXIT_CODE);
    assert!(matches!(
        failure.cause(),
        WindowsLifecycleIrreversibleCause::Retirement {
            original: WindowsLifecycleCause::Startup(StartupFailure::Missing(
                NoSecretStartupRequirement::ServiceToken
            )),
            platform: ServiceRunStateError::Release,
        }
    ));
    assert!(format!("{failure:?}").contains("[REDACTED]"));
    fixture.cleanup_checked()
}

#[test]
fn debug_and_source_surfaces_are_redacted_silent_and_path_handle_free() -> TestResult {
    let source = include_str!("windows_lifecycle.rs");
    for forbidden in [
        "process::exit(",
        "println!",
        "eprintln!",
        "unsafe {",
        "RawHandle",
        "HANDLE",
        "file_name(",
        "canonicalize(",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden lifecycle source surface: {forbidden}"
        );
    }
    assert!(!source.contains("pub fn "));
    assert!(!source.contains("pub struct "));
    let stopped_impl = source
        .split("impl WindowsLifecycleStopped")
        .nth(1)
        .and_then(|tail| {
            tail.split("impl fmt::Debug for WindowsLifecycleStopped")
                .next()
        })
        .ok_or_else(|| io::Error::other("Stopped implementation source boundary changed"))?;
    assert!(!stopped_impl.contains("fn code"));

    let (fixture, installation, mut provider) = clean_fixture(0xb1)?;
    let provider_debug = format!("{provider:?}");
    let startup = begin(&fixture, &mut provider)?;
    let rendered = format!("{startup:?} {installation:?} {provider_debug}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("b1b1b1b1"));
    assert!(!rendered.contains("b2b2b2b2"));
    assert_checked_exit(startup.abort(StartupFailure::Unavailable(
        NoSecretStartupRequirement::FirewallPolicy,
    )))?;
    fixture.cleanup_checked()
}
