use std::error::Error;
use std::io;

use super::super::durable_run_state::{
    FixtureRunStateAuthenticationKey, InstallationIdentity, RecoveryRequired,
    install_windows_runtime_clean_fixture,
};
use super::super::lifecycle_core::{
    CleanupStep, FatalReason, LifecycleError, NoSecretFixtureWorkKind, NoSecretStartupRequirement,
    RuntimePolicyFailure, RuntimeState, SessionEvent, SessionId, StartupFailure,
    StartupObservation, StopReason, WorkId,
};
use super::super::run_state_root::{RuntimePairFault, RuntimePairFixture, ServiceRunStateError};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const FIRST_NINE_CLEANUP_STEPS: [CleanupStep; 9] = [
    CleanupStep::RejectNewWork,
    CleanupStep::InvalidateNonDurableAuthority,
    CleanupStep::CloseAndDrainListeners,
    CleanupStep::CancelRequests,
    CleanupStep::TerminateHelpers,
    CleanupStep::ReapHelpers,
    CleanupStep::DiscardUserTokens,
    CleanupStep::FlushDefinedDurableRecords,
    CleanupStep::ReleaseRequestHardwareAndStorageHandles,
];

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

fn test_key(byte: u8) -> Result<FixtureRunStateAuthenticationKey, RecoveryRequired> {
    FixtureRunStateAuthenticationKey::from_fixture_bytes([byte; 32])
}

fn clean_fixture(
    byte: u8,
) -> TestResult<(
    RuntimePairFixture,
    InstallationIdentity,
    FixtureRunStateAuthenticationKey,
)> {
    let fixture = RuntimePairFixture::new()?;
    let installation = test_installation(byte)?;
    let key = test_key(byte.wrapping_add(1))?;
    install_windows_runtime_clean_fixture(&fixture, installation, &key)?;
    Ok((fixture, installation, key))
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

fn begin<'key>(
    fixture: &RuntimePairFixture,
    installation: InstallationIdentity,
    key: &'key FixtureRunStateAuthenticationKey,
) -> TestResult<WindowsStartupAttempt<'key>> {
    match begin_windows_lifecycle(fixture.acquire_writer()?, installation, key) {
        Ok(startup) => Ok(startup),
        Err(exit) => {
            assert_exit78(exit);
            Err(io::Error::other("clean fixture failed lifecycle startup").into())
        }
    }
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

fn prepared_active<'key>(
    fixture: &RuntimePairFixture,
    installation: InstallationIdentity,
    key: &'key FixtureRunStateAuthenticationKey,
) -> TestResult<WindowsActiveCommitPending<'key>> {
    let startup = begin(fixture, installation, key)?;
    match complete_checklist(startup) {
        Ok(prepared) => Ok(prepared),
        Err(exit) => {
            assert_exit78(exit);
            Err(io::Error::other("verified checklist failed Active preparation").into())
        }
    }
}

fn ready_service<'key>(
    fixture: &RuntimePairFixture,
    installation: InstallationIdentity,
    key: &'key FixtureRunStateAuthenticationKey,
) -> TestResult<WindowsNoSecretService<'key>> {
    match prepared_active(fixture, installation, key)?.commit_and_reread() {
        WindowsLifecycleActiveCommitOutcome::ListenerPending(listener) => Ok(listener
            .record_listeners_prepared()
            .record_scm_running_published()
            .open_admission()),
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

fn complete_first_nine(service: &mut WindowsNoSecretService<'_>) -> Result<(), LifecycleError> {
    service.begin_stop(StopReason::ScmStop)?;
    for step in FIRST_NINE_CLEANUP_STEPS {
        service.complete_cleanup_step(step)?;
    }
    Ok(())
}

fn clean_release_pending<'key>(
    fixture: &RuntimePairFixture,
    installation: InstallationIdentity,
    key: &'key FixtureRunStateAuthenticationKey,
) -> TestResult<WindowsCleanReleasePending<'key>> {
    let mut service = ready_service(fixture, installation, key)?;
    complete_first_nine(&mut service)?;
    match service.prepare_clean() {
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

#[test]
fn clean_startup_active_runtime_clean_release_reaches_normal_stopped() -> TestResult {
    let (fixture, installation, key) = clean_fixture(0x31)?;
    let release = clean_release_pending(&fixture, installation, &key)?;
    let stopped = match release.release_writer() {
        WindowsLifecycleStopOutcome::Stopped(stopped) => stopped,
        WindowsLifecycleStopOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("happy release retained terminal writer").into());
        }
        WindowsLifecycleStopOutcome::IrreversibleExit78(failure) => {
            return Err(io::Error::other(format!(
                "happy release became irreversible: {failure:?}"
            ))
            .into());
        }
    };
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
        let (fixture, installation, key) = clean_fixture(byte)?;
        let mut startup = begin(&fixture, installation, &key)?;
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
        let (fixture, installation, key) = clean_fixture(byte)?;
        let prepared = prepared_active(&fixture, installation, &key)?;
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
                let service = listener
                    .record_listeners_prepared()
                    .record_scm_running_published()
                    .open_admission();
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
    let (fixture, installation, key) = clean_fixture(0x61)?;
    let prepared = prepared_active(&fixture, installation, &key)?;
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
    let _: fn(WindowsListenerPending<'static>) -> WindowsScmRunningPending<'static> =
        WindowsListenerPending::record_listeners_prepared;
    let _: fn(WindowsScmRunningPending<'static>) -> WindowsAdmissionPending<'static> =
        WindowsScmRunningPending::record_scm_running_published;
    let _: fn(WindowsAdmissionPending<'static>) -> WindowsNoSecretService<'static> =
        WindowsAdmissionPending::open_admission;

    assert_move_only!(WindowsStartupAttempt<'static>);
    assert_move_only!(WindowsActiveCommitPending<'static>);
    assert_move_only!(WindowsActiveReloadPending<'static>);
    assert_move_only!(WindowsListenerPending<'static>);
    assert_move_only!(WindowsScmRunningPending<'static>);
    assert_move_only!(WindowsAdmissionPending<'static>);
    assert_move_only!(WindowsNoSecretService<'static>);
    assert_move_only!(WindowsCleanReloadPending<'static>);
    assert_move_only!(WindowsCleanReleasePending<'static>);
    assert_move_only!(WindowsLifecycleExitRequired<'static>);
    assert_move_only!(WindowsLifecycleCheckedExit78<'static>);
    assert_move_only!(WindowsLifecycleIrreversibleExit78<'static>);
    assert_move_only!(WindowsLifecycleStopped);
}

#[test]
fn runtime_policy_alone_enforces_work_token_and_quarantine_bounds() -> TestResult {
    let (fixture, installation, key) = clean_fixture(0x71)?;
    let mut service = ready_service(&fixture, installation, &key)?;
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
    let (premature_fixture, premature_installation, premature_key) = clean_fixture(0x73)?;
    let premature = ready_service(&premature_fixture, premature_installation, &premature_key)?;
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

    let (fixture, installation, key) = clean_fixture(0x75)?;
    let mut service = ready_service(&fixture, installation, &key)?;
    let session = SessionId::new(9)?;
    service.retain_user_token(session)?;
    service.admit_fixture_work(
        WorkId::new(11)?,
        session,
        NoSecretFixtureWorkKind::SecretInput,
    )?;
    service.handle_session_event(SessionEvent::Lock(session))?;
    complete_first_nine(&mut service)?;
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
    match release.release_writer() {
        WindowsLifecycleStopOutcome::Stopped(_stopped) => {}
        WindowsLifecycleStopOutcome::ExitRequired(exit) => {
            assert_exit78(exit);
            return Err(io::Error::other("complete cleanup failed writer release").into());
        }
        WindowsLifecycleStopOutcome::IrreversibleExit78(failure) => {
            return Err(io::Error::other(format!(
                "complete cleanup became irreversible: {failure:?}"
            ))
            .into());
        }
    }
    fixture.cleanup_checked()
}

#[test]
fn clean_ambiguity_advances_release_policy_for_candidate_only() -> TestResult {
    for (byte, fault) in [
        (0x81, RuntimePairFault::AfterCheckpointRename),
        (0x83, RuntimePairFault::MarkerRenameAttempt),
        (0x85, RuntimePairFault::AfterMarkerRename),
    ] {
        let (fixture, installation, key) = clean_fixture(byte)?;
        let mut service = ready_service(&fixture, installation, &key)?;
        complete_first_nine(&mut service)?;
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
            ) => match release.release_writer() {
                WindowsLifecycleStopOutcome::Stopped(_stopped) => {}
                WindowsLifecycleStopOutcome::ExitRequired(exit) => {
                    assert_exit78(exit);
                    return Err(io::Error::other("Clean candidate failed exact release").into());
                }
                WindowsLifecycleStopOutcome::IrreversibleExit78(failure) => {
                    return Err(io::Error::other(format!(
                        "Clean candidate release became irreversible: {failure:?}"
                    ))
                    .into());
                }
            },
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
    let (retained_fixture, retained_installation, retained_key) = clean_fixture(0x91)?;
    let retained = clean_release_pending(&retained_fixture, retained_installation, &retained_key)?;
    retained_fixture.inject_fault(RuntimePairFault::WriterReleaseUnlock);
    let exit = match retained.release_writer() {
        WindowsLifecycleStopOutcome::ExitRequired(exit) => exit,
        WindowsLifecycleStopOutcome::Stopped(_stopped) => {
            return Err(io::Error::other("writer-retaining fault minted Stopped").into());
        }
        WindowsLifecycleStopOutcome::IrreversibleExit78(failure) => {
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

    let (no_receipt_fixture, no_receipt_installation, no_receipt_key) = clean_fixture(0x93)?;
    let no_receipt = clean_release_pending(
        &no_receipt_fixture,
        no_receipt_installation,
        &no_receipt_key,
    )?;
    no_receipt_fixture.inject_fault(RuntimePairFault::CheckpointFinalClose);
    let failure = match no_receipt.release_writer() {
        WindowsLifecycleStopOutcome::IrreversibleExit78(failure) => failure,
        WindowsLifecycleStopOutcome::Stopped(_stopped) => {
            return Err(io::Error::other("no-receipt fault minted Stopped").into());
        }
        WindowsLifecycleStopOutcome::ExitRequired(exit) => {
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
    let (fixture, installation, key) = clean_fixture(0x95)?;
    let release = clean_release_pending(&fixture, installation, &key)?;
    let failure = match release.release_writer_with_post_release_fault_for_test() {
        WindowsLifecycleStopOutcome::IrreversibleExit78(failure) => failure,
        WindowsLifecycleStopOutcome::Stopped(_stopped) => {
            return Err(io::Error::other("post-release logical fault minted Stopped").into());
        }
        WindowsLifecycleStopOutcome::ExitRequired(exit) => {
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
    let (fixture, installation, key) = clean_fixture(0xa1)?;
    let startup = begin(&fixture, installation, &key)?;
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

    let (fixture, installation, key) = clean_fixture(0xb1)?;
    let startup = begin(&fixture, installation, &key)?;
    let rendered = format!("{startup:?} {installation:?} {key:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("b1b1b1b1"));
    assert!(!rendered.contains("b2b2b2b2"));
    assert_checked_exit(startup.abort(StartupFailure::Unavailable(
        NoSecretStartupRequirement::FirewallPolicy,
    )))?;
    fixture.cleanup_checked()
}
