use std::{error::Error, fmt, io, num::NonZeroU64};

use super::provisioning::{
    CommittedInitialCleanMarker, FreshInstallProvisioningAuthority,
    InitialCleanCommittedWithWriter, InitialCleanReloadReceipt, InitialCleanReloadRequired,
    InitialProvisioningStartFailure, PendingProvisioningWriterRelease,
    PreparedInitialCleanTransition, ProvisionedRunState, ProvisioningFailureWithWriter,
    ProvisioningRecoveryExitEvidence, ProvisioningWriterExitPending, ProvisioningWriterExitReceipt,
    ProvisioningWriterLease, ProvisioningWriterReleaseReceipt, ReloadedInitialCleanState,
    RereadInitialCleanMarker, UnprovisionedWithWriter,
};
use super::{
    Commitment, DurableRunStateCommitFailure, DurableRunStateCommitFault, DurableRunStateFixture,
    DurableRunStateFixtureSeed, DurableRunStateReleaseFailure, DurableRunStateReleaseFault,
    DurableRunStateRereadFault, FixtureWriterRole, InstallationIdentity, RecoveryRequired,
    RunMarkerState, RunStateAuthenticationProvider, RuntimeBootStartFailure,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn fixture_provider(
    installation: InstallationIdentity,
    seed: u8,
) -> Result<RunStateAuthenticationProvider, RecoveryRequired> {
    RunStateAuthenticationProvider::from_fixture_bytes(installation, [seed; 32])
}

fn fixture_installation(seed: u8) -> Result<InstallationIdentity, RecoveryRequired> {
    InstallationIdentity::from_fixed_bytes([seed; 32])
}

fn boxed_debug(error: impl fmt::Debug) -> Box<dyn Error> {
    Box::new(io::Error::other(format!("{error:?}")))
}

fn start<'provider>(
    backend: &mut DurableRunStateFixture,
    provider: &'provider RunStateAuthenticationProvider,
    installation: InstallationIdentity,
) -> TestResult<UnprovisionedWithWriter<'provider>> {
    backend
        .begin_initial_provisioning(provider, installation)
        .map_err(boxed_debug)
}

fn prepare<'provider>(
    backend: &mut DurableRunStateFixture,
    provider: &'provider RunStateAuthenticationProvider,
    installation: InstallationIdentity,
) -> TestResult<PreparedInitialCleanTransition<'provider>> {
    start(backend, provider, installation)?
        .prepare_initial_clean()
        .map_err(boxed_debug)
}

fn commit_and_reread<'provider>(
    backend: &mut DurableRunStateFixture,
    transition: PreparedInitialCleanTransition<'provider>,
) -> TestResult<InitialCleanCommittedWithWriter<'provider>> {
    let committed = backend.commit_initial_clean(&transition)?;
    let reread = backend.reread_initial_clean(&transition)?;
    transition.complete(committed, reread).map_err(boxed_debug)
}

fn prepare_and_commit<'provider>(
    backend: &mut DurableRunStateFixture,
    provider: &'provider RunStateAuthenticationProvider,
    installation: InstallationIdentity,
) -> TestResult<InitialCleanCommittedWithWriter<'provider>> {
    let transition = prepare(backend, provider, installation)?;
    commit_and_reread(backend, transition)
}

fn release_initial<'provider>(
    backend: &mut DurableRunStateFixture,
    committed: InitialCleanCommittedWithWriter<'provider>,
) -> TestResult<ProvisionedRunState<'provider>> {
    let pending = committed.prepare_writer_release();
    let receipt = backend.release_provisioning_writer(&pending)?;
    pending.complete(receipt).map_err(boxed_debug)
}

fn retire_failure<'provider>(
    backend: &mut DurableRunStateFixture,
    failure: ProvisioningFailureWithWriter<'provider>,
) -> TestResult<ProvisioningRecoveryExitEvidence<'provider>> {
    let pending = failure.into_writer_exit();
    retire_pending(backend, pending)
}

fn retire_pending<'provider>(
    backend: &mut DurableRunStateFixture,
    pending: ProvisioningWriterExitPending<'provider>,
) -> TestResult<ProvisioningRecoveryExitEvidence<'provider>> {
    let receipt = backend.retire_provisioning_writer_for_exit(&pending)?;
    pending.complete(receipt).map_err(boxed_debug)
}

fn retire_runtime_boot_failure(
    backend: &mut DurableRunStateFixture,
    failure: RuntimeBootStartFailure<'_>,
) -> TestResult<RecoveryRequired> {
    let (reason, pending) = failure.into_writer_exit().map_err(boxed_debug)?;
    let receipt = backend.retire_writer_for_exit(&pending)?;
    let _retired = pending.complete(receipt).map_err(boxed_debug)?;
    Ok(reason)
}

fn durable_bytes(
    backend: &DurableRunStateFixture,
) -> (
    Option<[u8; super::RUN_MARKER_BYTES]>,
    Option<[u8; super::HIGH_WATER_BYTES]>,
) {
    (backend.marker, backend.checkpoint)
}

#[test]
fn golden_initial_clean_then_release_requires_a_fresh_runtime_boot() -> TestResult {
    let installation = fixture_installation(0x41)?;
    let mut provider = fixture_provider(installation, 0x5a)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;

    let committed = prepare_and_commit(&mut backend, &provider, installation)?;
    assert_eq!(committed.generation(), NonZeroU64::MIN);
    let snapshot = backend.canonical_snapshot()?;
    assert_eq!(&snapshot.marker[..8], b"YWRUNV01");
    assert_eq!(&snapshot.checkpoint[..8], b"YWHIWV01");
    assert_eq!(snapshot.marker[10], RunMarkerState::Clean.tag());
    assert_eq!(&snapshot.marker[12..20], &1_u64.to_be_bytes());
    assert_eq!(&snapshot.marker[52..84], &[0; 32]);
    assert_eq!(&snapshot.checkpoint[52..84], &[0; 32]);

    {
        let provisioned = release_initial(&mut backend, committed)?;
        assert_eq!(provisioned.generation(), NonZeroU64::MIN);
        assert_eq!(backend.held_writer_role(), None);
    }

    let boot = backend
        .boot(provider.runtime_authority())
        .map_err(boxed_debug)?;
    assert_eq!(boot.generation(), NonZeroU64::MIN);
    assert_eq!(backend.held_writer_role(), Some(FixtureWriterRole::Runtime));
    let exit = boot.into_writer_exit();
    let receipt = backend.retire_writer_for_exit(&exit)?;
    let _retired = exit.complete(receipt).map_err(boxed_debug)?;
    Ok(())
}

#[test]
fn ordinary_boot_missing_never_auto_initializes_and_requires_writer_retirement() -> TestResult {
    let installation = fixture_installation(0x42)?;
    let mut provider = fixture_provider(installation, 0x51)?;
    let mut contender = fixture_provider(installation, 0x51)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let Err(failure) = backend.boot(provider.runtime_authority()) else {
        return Err("missing runtime state minted boot authority".into());
    };
    assert_eq!(failure.reason(), RecoveryRequired::MissingRunMarker);
    assert!(matches!(failure, RuntimeBootStartFailure::WithWriter(_)));
    assert_eq!(durable_bytes(&backend), (None, None));
    assert_eq!(backend.held_writer_role(), Some(FixtureWriterRole::Runtime));
    let Err(runtime_reacquire) = backend.begin_runtime_boot(contender.runtime_authority()) else {
        return Err("retained missing-state failure allowed a second runtime writer".into());
    };
    assert!(matches!(
        runtime_reacquire,
        RuntimeBootStartFailure::BeforeWriter(failure)
            if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
    ));
    let Err(provisioning) = backend.begin_initial_provisioning(&contender, installation) else {
        return Err("missing runtime boot converted into provisioning authority".into());
    };
    assert!(matches!(
        provisioning,
        InitialProvisioningStartFailure::BeforeWriter(RecoveryRequired::WriterLeaseUnavailable)
    ));
    assert_eq!(
        retire_runtime_boot_failure(&mut backend, failure)?,
        RecoveryRequired::MissingRunMarker
    );
    assert_eq!(backend.held_writer_role(), None);
    assert_eq!(durable_bytes(&backend), (None, None));

    let Err(runtime_retry) = backend.boot(provider.runtime_authority()) else {
        return Err("Missing/Missing retry minted runtime boot authority".into());
    };
    assert!(matches!(
        &runtime_retry,
        RuntimeBootStartFailure::WithWriter(_)
    ));
    assert_eq!(
        retire_runtime_boot_failure(&mut backend, runtime_retry)?,
        RecoveryRequired::MissingRunMarker
    );
    let unprovisioned = backend
        .begin_initial_provisioning(&provider, installation)
        .map_err(boxed_debug)?;
    let _retired = retire_pending(&mut backend, unprovisioned.into_writer_exit())?;
    assert_eq!(durable_bytes(&backend), (None, None));
    Ok(())
}

#[test]
fn rejected_runtime_state_is_post_writer_nonmutating_and_blocks_both_writer_roles() -> TestResult {
    let installation = fixture_installation(0x48)?;
    let mut provider = fixture_provider(installation, 0x58)?;
    let mut contender = fixture_provider(installation, 0x58)?;
    for (seed, expected) in [
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
        (
            DurableRunStateFixtureSeed::Active,
            RecoveryRequired::PersistedNonCleanState,
        ),
        (
            DurableRunStateFixtureSeed::RecoveryRequired,
            RecoveryRequired::PersistedNonCleanState,
        ),
    ] {
        let mut backend = DurableRunStateFixture::new(seed, &provider, installation)?;
        let before = durable_bytes(&backend);
        let acquired = backend
            .begin_runtime_boot(provider.runtime_authority())
            .map_err(boxed_debug)?;
        assert_eq!(backend.held_writer_role(), Some(FixtureWriterRole::Runtime));
        let Err(failure) = backend.finish_runtime_boot(acquired) else {
            return Err("rejected durable state minted runtime boot authority".into());
        };
        assert_eq!(failure.reason(), expected);
        assert!(matches!(&failure, RuntimeBootStartFailure::WithWriter(_)));
        assert_eq!(durable_bytes(&backend), before);

        let Err(runtime_reacquire) = backend.begin_runtime_boot(contender.runtime_authority())
        else {
            return Err("retained runtime failure allowed a second runtime writer".into());
        };
        assert!(matches!(
            runtime_reacquire,
            RuntimeBootStartFailure::BeforeWriter(failure)
                if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
        ));
        let Err(provisioning_reacquire) =
            backend.begin_initial_provisioning(&contender, installation)
        else {
            return Err("retained runtime failure allowed a provisioning writer".into());
        };
        assert!(matches!(
            provisioning_reacquire,
            InitialProvisioningStartFailure::BeforeWriter(RecoveryRequired::WriterLeaseUnavailable)
        ));
        assert_eq!(
            retire_runtime_boot_failure(&mut backend, failure)?,
            expected
        );

        let Err(runtime_retry) = backend.boot(provider.runtime_authority()) else {
            return Err("rejected durable state became bootable after retirement".into());
        };
        assert!(matches!(
            &runtime_retry,
            RuntimeBootStartFailure::WithWriter(_)
        ));
        assert_eq!(
            retire_runtime_boot_failure(&mut backend, runtime_retry)?,
            expected
        );
        let Err(provisioning_retry) = backend.begin_initial_provisioning(&provider, installation)
        else {
            return Err("pre-existing durable bytes minted provisioning authority".into());
        };
        let InitialProvisioningStartFailure::WithWriter(provisioning_failure) = provisioning_retry
        else {
            return Err("post-retirement provisioning did not reacquire its writer".into());
        };
        let _retired = retire_failure(&mut backend, provisioning_failure)?;
        assert_eq!(backend.held_writer_role(), None);
        assert_eq!(durable_bytes(&backend), before);
    }
    Ok(())
}

#[test]
fn wrong_runtime_provider_is_post_writer_and_retires_before_clean_can_boot() -> TestResult {
    let installation = fixture_installation(0x49)?;
    let mut provider = fixture_provider(installation, 0x59)?;
    let mut wrong_provider = fixture_provider(installation, 0x69)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let committed = prepare_and_commit(&mut backend, &provider, installation)?;
    {
        let _provisioned = release_initial(&mut backend, committed)?;
    }
    let before = durable_bytes(&backend);

    let acquired = backend
        .begin_runtime_boot(wrong_provider.runtime_authority())
        .map_err(boxed_debug)?;
    let Err(failure) = backend.finish_runtime_boot(acquired) else {
        return Err("wrong authentication provider minted runtime boot authority".into());
    };
    assert_eq!(failure.reason(), RecoveryRequired::AuthenticationFailed);
    assert!(matches!(&failure, RuntimeBootStartFailure::WithWriter(_)));
    assert_eq!(durable_bytes(&backend), before);
    let Err(runtime_reacquire) = backend.begin_runtime_boot(provider.runtime_authority()) else {
        return Err("wrong-provider failure allowed runtime writer reacquisition".into());
    };
    assert!(matches!(
        runtime_reacquire,
        RuntimeBootStartFailure::BeforeWriter(failure)
            if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
    ));
    let Err(provisioning_reacquire) = backend.begin_initial_provisioning(&provider, installation)
    else {
        return Err("wrong-provider failure allowed provisioning writer reacquisition".into());
    };
    assert!(matches!(
        provisioning_reacquire,
        InitialProvisioningStartFailure::BeforeWriter(RecoveryRequired::WriterLeaseUnavailable)
    ));
    assert_eq!(
        retire_runtime_boot_failure(&mut backend, failure)?,
        RecoveryRequired::AuthenticationFailed
    );

    let boot = backend
        .boot(provider.runtime_authority())
        .map_err(boxed_debug)?;
    let pending = boot.into_writer_exit();
    let receipt = backend.retire_writer_for_exit(&pending)?;
    let _retired = pending.complete(receipt).map_err(boxed_debug)?;
    assert_eq!(backend.held_writer_role(), None);
    assert_eq!(durable_bytes(&backend), before);
    Ok(())
}

#[test]
fn cross_backend_runtime_failure_retires_only_the_originating_writer() -> TestResult {
    let installation = fixture_installation(0x4a)?;
    let mut provider = fixture_provider(installation, 0x5b)?;
    let mut contender = fixture_provider(installation, 0x5b)?;
    let mut origin = DurableRunStateFixture::empty(installation)?;
    let committed = prepare_and_commit(&mut origin, &provider, installation)?;
    {
        let _provisioned = release_initial(&mut origin, committed)?;
    }
    let mut other = DurableRunStateFixture::empty(installation)?;
    let committed = prepare_and_commit(&mut other, &provider, installation)?;
    {
        let _provisioned = release_initial(&mut other, committed)?;
    }

    let acquired = origin
        .begin_runtime_boot(provider.runtime_authority())
        .map_err(boxed_debug)?;
    let Err(failure) = other.finish_runtime_boot(acquired) else {
        return Err("cross-backend acquisition minted boot authority".into());
    };
    assert_eq!(failure.reason(), RecoveryRequired::BackendBindingMismatch);
    let (reason, pending) = failure.into_writer_exit().map_err(boxed_debug)?;
    assert_eq!(reason, RecoveryRequired::BackendBindingMismatch);
    assert!(matches!(
        other.retire_writer_for_exit(&pending),
        Err(RecoveryRequired::BackendBindingMismatch)
    ));
    let Err(runtime_reacquire) = origin.begin_runtime_boot(contender.runtime_authority()) else {
        return Err("origin allowed reacquisition before exact retirement".into());
    };
    assert!(matches!(
        runtime_reacquire,
        RuntimeBootStartFailure::BeforeWriter(failure)
            if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
    ));
    let receipt = origin.retire_writer_for_exit(&pending)?;
    let _retired = pending.complete(receipt).map_err(boxed_debug)?;
    assert_eq!(origin.held_writer_role(), None);

    let boot = origin
        .boot(provider.runtime_authority())
        .map_err(boxed_debug)?;
    let pending = boot.into_writer_exit();
    let receipt = origin.retire_writer_for_exit(&pending)?;
    let _retired = pending.complete(receipt).map_err(boxed_debug)?;
    Ok(())
}

#[test]
fn runtime_and_provisioning_writer_roles_are_mutually_exclusive() -> TestResult {
    let installation = fixture_installation(0x43)?;
    let provider = fixture_provider(installation, 0x52)?;
    let mut runtime_provider = fixture_provider(installation, 0x52)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let unprovisioned = start(&mut backend, &provider, installation)?;
    assert_eq!(
        backend.held_writer_role(),
        Some(FixtureWriterRole::Provisioning)
    );
    let Err(runtime_start) = backend.begin_runtime_boot(runtime_provider.runtime_authority())
    else {
        return Err("runtime writer overlapped provisioning".into());
    };
    assert!(matches!(
        runtime_start,
        RuntimeBootStartFailure::BeforeWriter(failure)
            if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
    ));
    let transition = unprovisioned.prepare_initial_clean().map_err(boxed_debug)?;
    let committed = commit_and_reread(&mut backend, transition)?;
    let Err(runtime_boot) = backend.boot(runtime_provider.runtime_authority()) else {
        return Err("runtime boot overlapped provisioning".into());
    };
    assert!(matches!(
        runtime_boot,
        RuntimeBootStartFailure::BeforeWriter(failure)
            if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
    ));
    {
        let _provisioned = release_initial(&mut backend, committed)?;
    }

    let runtime = backend
        .boot(runtime_provider.runtime_authority())
        .map_err(boxed_debug)?;
    assert_eq!(backend.held_writer_role(), Some(FixtureWriterRole::Runtime));
    let Err(start_error) = backend.begin_initial_provisioning(&provider, installation) else {
        return Err("runtime writer did not exclude provisioning".into());
    };
    assert!(matches!(
        start_error,
        InitialProvisioningStartFailure::BeforeWriter(RecoveryRequired::WriterLeaseUnavailable)
    ));
    let exit = runtime.into_writer_exit();
    let receipt = backend.retire_writer_for_exit(&exit)?;
    let _retired = exit.complete(receipt).map_err(boxed_debug)?;
    Ok(())
}

#[test]
fn preexisting_full_one_sided_and_invalid_bytes_are_rejected_without_mutation() -> TestResult {
    let installation = fixture_installation(0x44)?;
    let provider = fixture_provider(installation, 0x53)?;
    let mut backends = [
        DurableRunStateFixture::seeded(
            RunMarkerState::Clean,
            NonZeroU64::MIN,
            installation,
            Commitment::ZERO,
            &provider,
        )?,
        DurableRunStateFixture::new(
            DurableRunStateFixtureSeed::MissingMarker,
            &provider,
            installation,
        )?,
        DurableRunStateFixture::new(
            DurableRunStateFixtureSeed::MissingCheckpoint,
            &provider,
            installation,
        )?,
        DurableRunStateFixture::new(DurableRunStateFixtureSeed::Invalid, &provider, installation)?,
    ];
    for backend in &mut backends {
        let before = durable_bytes(backend);
        let Err(error) = backend.begin_initial_provisioning(&provider, installation) else {
            return Err("pre-existing bytes minted provisioning authority".into());
        };
        let InitialProvisioningStartFailure::WithWriter(failure) = error else {
            return Err("post-acquisition rejection lost writer authority".into());
        };
        assert_eq!(
            failure.reason(),
            RecoveryRequired::InitialProvisioningStateNotEmpty
        );
        assert_eq!(durable_bytes(backend), before);
        let _retired = retire_failure(backend, failure)?;
        assert_eq!(durable_bytes(backend), before);
    }
    Ok(())
}

#[test]
fn ambiguous_before_write_needs_one_fresh_round_before_retry() -> TestResult {
    let installation = fixture_installation(0x45)?;
    let provider = fixture_provider(installation, 0x54)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    backend.set_commit_fault(DurableRunStateCommitFault::AmbiguousBeforeWrite);
    assert_eq!(
        backend.commit_initial_clean(&transition),
        Err(DurableRunStateCommitFailure::Ambiguous)
    );
    assert_eq!(
        backend.commit_initial_clean(&transition).map(|_| ()),
        Err(DurableRunStateCommitFailure::Recovery(
            RecoveryRequired::CommitReloadRequired
        ))
    );
    let pending = transition.commit_ambiguous().map_err(boxed_debug)?;
    let receipt = backend.reload_initial_clean(&pending)?;
    assert_eq!(
        backend.reload_initial_clean(&pending).map(|_| ()),
        Err(RecoveryRequired::OperationAttemptReused)
    );
    let ReloadedInitialCleanState::Retry(retry) =
        pending.complete_reload(receipt).map_err(boxed_debug)?
    else {
        return Err("unapplied initial commit did not yield retry authority".into());
    };
    let retry_transition = retry.prepare_initial_clean().map_err(boxed_debug)?;
    let committed = commit_and_reread(&mut backend, retry_transition)?;
    let provisioned = release_initial(&mut backend, committed)?;
    assert_eq!(provisioned.generation(), NonZeroU64::MIN);
    Ok(())
}

#[test]
fn ambiguous_after_checkpoint_recovers_committed_with_writer_only() -> TestResult {
    let installation = fixture_installation(0x46)?;
    let provider = fixture_provider(installation, 0x55)?;
    let mut runtime_provider = fixture_provider(installation, 0x55)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    backend.set_commit_fault(DurableRunStateCommitFault::AmbiguousAfterCheckpoint);
    assert_eq!(
        backend.commit_initial_clean(&transition),
        Err(DurableRunStateCommitFailure::Ambiguous)
    );
    let pending = transition.commit_ambiguous().map_err(boxed_debug)?;
    let receipt = backend.reload_initial_clean(&pending)?;
    let ReloadedInitialCleanState::Committed(committed) =
        pending.complete_reload(receipt).map_err(boxed_debug)?
    else {
        return Err("complete candidate restored retry authority".into());
    };
    let Err(runtime_boot) = backend.boot(runtime_provider.runtime_authority()) else {
        return Err("committed provisioning writer allowed runtime boot".into());
    };
    assert!(matches!(
        runtime_boot,
        RuntimeBootStartFailure::BeforeWriter(failure)
            if failure.reason() == RecoveryRequired::WriterLeaseUnavailable
    ));
    let _provisioned = release_initial(&mut backend, committed)?;
    Ok(())
}

#[test]
fn partial_ambiguous_commit_is_terminal_and_retirement_preserves_bytes() -> TestResult {
    let installation = fixture_installation(0x47)?;
    let provider = fixture_provider(installation, 0x56)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    backend.set_commit_fault(DurableRunStateCommitFault::AmbiguousAfterMarker);
    assert_eq!(
        backend.commit_initial_clean(&transition),
        Err(DurableRunStateCommitFailure::Ambiguous)
    );
    let pending = transition.commit_ambiguous().map_err(boxed_debug)?;
    let receipt = backend.reload_initial_clean(&pending)?;
    let Err(failure) = pending.complete_reload(receipt) else {
        return Err("partial initial commit restored authority".into());
    };
    assert_eq!(
        failure.reason(),
        RecoveryRequired::InitialProvisioningStateNotEmpty
    );
    let before_retirement = durable_bytes(&backend);
    assert!(before_retirement.0.is_some() && before_retirement.1.is_none());
    let _retired = retire_failure(&mut backend, failure)?;
    assert_eq!(durable_bytes(&backend), before_retirement);
    Ok(())
}

#[test]
fn known_commit_failure_is_terminal_and_preserves_missing_missing() -> TestResult {
    let installation = fixture_installation(0x48)?;
    let provider = fixture_provider(installation, 0x57)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    backend.set_commit_fault(DurableRunStateCommitFault::CompareAndSwapConflict);
    assert_eq!(
        backend.commit_initial_clean(&transition),
        Err(DurableRunStateCommitFailure::Recovery(
            RecoveryRequired::CompareAndSwapConflict
        ))
    );
    assert_eq!(
        backend.commit_initial_clean(&transition).map(|_| ()),
        Err(DurableRunStateCommitFailure::Recovery(
            RecoveryRequired::CommitReloadRequired
        ))
    );
    let pending = transition.commit_ambiguous().map_err(boxed_debug)?;
    assert_eq!(
        backend.reload_initial_clean(&pending).map(|_| ()),
        Err(RecoveryRequired::CommitReloadRequired)
    );
    let _retired = retire_pending(&mut backend, pending.into_writer_exit())?;
    assert_eq!(durable_bytes(&backend), (None, None));
    Ok(())
}

#[test]
fn premature_or_successful_commit_ambiguous_cannot_strand_the_writer() -> TestResult {
    let installation = fixture_installation(0x67)?;
    let provider = fixture_provider(installation, 0x66)?;

    let mut premature_backend = DurableRunStateFixture::empty(installation)?;
    let premature = prepare(&mut premature_backend, &provider, installation)?;
    let Err(premature_failure) = premature.commit_ambiguous() else {
        return Err("a never-attempted commit entered ambiguity reload".into());
    };
    assert_eq!(
        premature_failure.reason(),
        RecoveryRequired::OperationPhaseMismatch
    );
    let _retired = retire_failure(&mut premature_backend, premature_failure)?;

    let mut successful_backend = DurableRunStateFixture::empty(installation)?;
    let successful = prepare(&mut successful_backend, &provider, installation)?;
    let _committed = successful_backend.commit_initial_clean(&successful)?;
    let committed_bytes = durable_bytes(&successful_backend);
    let Err(successful_failure) = successful.commit_ambiguous() else {
        return Err("a successful commit entered ambiguity reload".into());
    };
    assert_eq!(
        successful_failure.reason(),
        RecoveryRequired::OperationPhaseMismatch
    );
    let _retired = retire_failure(&mut successful_backend, successful_failure)?;
    assert_eq!(durable_bytes(&successful_backend), committed_bytes);
    Ok(())
}

#[test]
fn successful_commit_reread_and_release_attempts_are_one_shot() -> TestResult {
    let installation = fixture_installation(0x65)?;
    let provider = fixture_provider(installation, 0x64)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    let committed = backend.commit_initial_clean(&transition)?;
    assert_eq!(
        backend.commit_initial_clean(&transition).map(|_| ()),
        Err(DurableRunStateCommitFailure::Recovery(
            RecoveryRequired::OperationAttemptReused
        ))
    );
    let reread = backend.reread_initial_clean(&transition)?;
    assert_eq!(
        backend.reread_initial_clean(&transition).map(|_| ()),
        Err(RecoveryRequired::OperationAttemptReused)
    );
    let clean = transition
        .complete(committed, reread)
        .map_err(boxed_debug)?;
    let pending = clean.prepare_writer_release();
    let receipt = backend.release_provisioning_writer(&pending)?;
    assert_eq!(
        backend.release_provisioning_writer(&pending).map(|_| ()),
        Err(DurableRunStateReleaseFailure::Recovery(
            RecoveryRequired::WriterLeaseMismatch
        ))
    );
    let provisioned = pending.complete(receipt).map_err(boxed_debug)?;
    assert_eq!(provisioned.generation(), NonZeroU64::MIN);

    let terminal_installation = fixture_installation(0x66)?;
    let terminal_provider = fixture_provider(terminal_installation, 0x64)?;
    let mut terminal_backend = DurableRunStateFixture::empty(terminal_installation)?;
    let terminal = prepare(
        &mut terminal_backend,
        &terminal_provider,
        terminal_installation,
    )?
    .into_writer_exit();
    let terminal_receipt = terminal_backend.retire_provisioning_writer_for_exit(&terminal)?;
    assert_eq!(
        terminal_backend
            .retire_provisioning_writer_for_exit(&terminal)
            .map(|_| ()),
        Err(RecoveryRequired::OperationAttemptReused)
    );
    let _retired = terminal.complete(terminal_receipt).map_err(boxed_debug)?;
    Ok(())
}

#[test]
fn post_commit_reread_drift_is_terminal_and_keeps_committed_bytes() -> TestResult {
    let installation = fixture_installation(0x49)?;
    let provider = fixture_provider(installation, 0x58)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    let committed = backend.commit_initial_clean(&transition)?;
    let exact_bytes = durable_bytes(&backend);
    backend.set_reread_fault(DurableRunStateRereadFault::CheckpointDrift);
    let reread = backend.reread_initial_clean(&transition)?;
    let Err(failure) = transition.complete(committed, reread) else {
        return Err("drifting initial readback minted committed authority".into());
    };
    assert_eq!(failure.reason(), RecoveryRequired::RereadDrift);
    let _retired = retire_failure(&mut backend, failure)?;
    assert_eq!(durable_bytes(&backend), exact_bytes);
    Ok(())
}

#[test]
fn cross_backend_commit_receipts_and_reread_requests_are_rejected() -> TestResult {
    let installation = fixture_installation(0x4a)?;
    let provider = fixture_provider(installation, 0x59)?;
    let mut backend_a = DurableRunStateFixture::empty(installation)?;
    let mut backend_b = DurableRunStateFixture::empty(installation)?;
    let transition_a = prepare(&mut backend_a, &provider, installation)?;
    let transition_b = prepare(&mut backend_b, &provider, installation)?;

    assert_eq!(
        backend_a.reread_initial_clean(&transition_b).map(|_| ()),
        Err(RecoveryRequired::BackendBindingMismatch)
    );
    let committed_a = backend_a.commit_initial_clean(&transition_a)?;
    let reread_a = backend_a.reread_initial_clean(&transition_a)?;
    let Err(failure_b) = transition_b.complete(committed_a, reread_a) else {
        return Err("cross-backend initial receipts minted authority".into());
    };
    assert_eq!(failure_b.reason(), RecoveryRequired::BackendBindingMismatch);
    let _retired_b = retire_failure(&mut backend_b, failure_b)?;
    let _retired_a = retire_pending(&mut backend_a, transition_a.into_writer_exit())?;
    Ok(())
}

#[test]
fn cross_backend_reread_release_and_terminal_receipts_are_each_rejected() -> TestResult {
    let installation = fixture_installation(0x6b)?;
    let provider = fixture_provider(installation, 0x6a)?;

    let mut reread_a = DurableRunStateFixture::empty(installation)?;
    let mut reread_b = DurableRunStateFixture::empty(installation)?;
    let transition_a = prepare(&mut reread_a, &provider, installation)?;
    let transition_b = prepare(&mut reread_b, &provider, installation)?;
    let _committed_a = reread_a.commit_initial_clean(&transition_a)?;
    let committed_b = reread_b.commit_initial_clean(&transition_b)?;
    let receipt_a = reread_a.reread_initial_clean(&transition_a)?;
    let _receipt_b = reread_b.reread_initial_clean(&transition_b)?;
    let Err(reread_failure_b) = transition_b.complete(committed_b, receipt_a) else {
        return Err("cross-backend reread receipt minted committed authority".into());
    };
    assert_eq!(
        reread_failure_b.reason(),
        RecoveryRequired::BackendBindingMismatch
    );
    let _retired_b = retire_failure(&mut reread_b, reread_failure_b)?;
    let _retired_a = retire_pending(&mut reread_a, transition_a.into_writer_exit())?;

    let mut release_a = DurableRunStateFixture::empty(installation)?;
    let mut release_b = DurableRunStateFixture::empty(installation)?;
    let pending_a =
        prepare_and_commit(&mut release_a, &provider, installation)?.prepare_writer_release();
    let pending_b =
        prepare_and_commit(&mut release_b, &provider, installation)?.prepare_writer_release();
    let receipt_a = release_a.release_provisioning_writer(&pending_a)?;
    let receipt_b = release_b.release_provisioning_writer(&pending_b)?;
    let Err(release_failure_b) = pending_b.complete(receipt_a) else {
        return Err("cross-backend release receipt minted provisioned state".into());
    };
    assert_eq!(
        release_failure_b.reason(),
        RecoveryRequired::BackendBindingMismatch
    );
    let Err(release_failure_a) = pending_a.complete(receipt_b) else {
        return Err("reverse cross-backend release receipt minted provisioned state".into());
    };
    assert_eq!(
        release_failure_a.reason(),
        RecoveryRequired::BackendBindingMismatch
    );
    let _retired_b = retire_failure(&mut release_b, release_failure_b)?;
    let _retired_a = retire_failure(&mut release_a, release_failure_a)?;

    let mut exit_a = DurableRunStateFixture::empty(installation)?;
    let mut exit_b = DurableRunStateFixture::empty(installation)?;
    let pending_a = prepare(&mut exit_a, &provider, installation)?.into_writer_exit();
    let pending_b = prepare(&mut exit_b, &provider, installation)?.into_writer_exit();
    let receipt_a = exit_a.retire_provisioning_writer_for_exit(&pending_a)?;
    let receipt_b = exit_b.retire_provisioning_writer_for_exit(&pending_b)?;
    let Err(exit_failure_b) = pending_b.complete(receipt_a) else {
        return Err("cross-backend terminal receipt completed writer retirement".into());
    };
    assert_eq!(
        exit_failure_b.reason(),
        RecoveryRequired::BackendBindingMismatch
    );
    let Err(exit_failure_a) = pending_a.complete(receipt_b) else {
        return Err("reverse cross-backend terminal receipt completed writer retirement".into());
    };
    assert_eq!(
        exit_failure_a.reason(),
        RecoveryRequired::BackendBindingMismatch
    );
    let _retired_b = retire_failure(&mut exit_b, exit_failure_b)?;
    let _retired_a = retire_failure(&mut exit_a, exit_failure_a)?;
    Ok(())
}

#[test]
fn cross_backend_ambiguity_reload_receipts_are_rejected_at_the_advanced_round() -> TestResult {
    let installation = fixture_installation(0x69)?;
    let provider = fixture_provider(installation, 0x68)?;
    let mut backend_a = DurableRunStateFixture::empty(installation)?;
    let mut backend_b = DurableRunStateFixture::empty(installation)?;
    let transition_a = prepare(&mut backend_a, &provider, installation)?;
    let transition_b = prepare(&mut backend_b, &provider, installation)?;
    backend_a.set_commit_fault(DurableRunStateCommitFault::AmbiguousBeforeWrite);
    backend_b.set_commit_fault(DurableRunStateCommitFault::AmbiguousBeforeWrite);
    assert!(matches!(
        backend_a.commit_initial_clean(&transition_a),
        Err(DurableRunStateCommitFailure::Ambiguous)
    ));
    assert!(matches!(
        backend_b.commit_initial_clean(&transition_b),
        Err(DurableRunStateCommitFailure::Ambiguous)
    ));
    let pending_a = transition_a.commit_ambiguous().map_err(boxed_debug)?;
    let pending_b = transition_b.commit_ambiguous().map_err(boxed_debug)?;
    let receipt_a = backend_a.reload_initial_clean(&pending_a)?;
    let _receipt_b = backend_b.reload_initial_clean(&pending_b)?;

    let Err(failure_b) = pending_b.complete_reload(receipt_a) else {
        return Err("cross-backend reload receipt restored provisioning authority".into());
    };
    assert_eq!(failure_b.reason(), RecoveryRequired::BackendBindingMismatch);
    let _retired_b = retire_failure(&mut backend_b, failure_b)?;
    let _retired_a = retire_pending(&mut backend_a, pending_a.into_writer_exit())?;
    Ok(())
}

#[test]
fn wrong_installation_provider_and_receipt_installation_fail_closed() -> TestResult {
    let installation = fixture_installation(0x4b)?;
    let other_installation = fixture_installation(0x6b)?;
    let provider = fixture_provider(installation, 0x5a)?;
    let mut wrong_provider = fixture_provider(installation, 0x6a)?;
    let mut other_provider = fixture_provider(other_installation, 0x5a)?;

    let mut backend = DurableRunStateFixture::empty(installation)?;
    let Err(runtime_error) = backend.begin_runtime_boot(other_provider.runtime_authority()) else {
        return Err("wrong installation minted runtime writer authority".into());
    };
    assert!(matches!(
        &runtime_error,
        RuntimeBootStartFailure::BeforeWriter(failure)
            if failure.reason() == RecoveryRequired::InstallationIdentityMismatch
    ));
    let Err(runtime_error) = runtime_error.into_writer_exit() else {
        return Err("wrong-installation pre-writer failure retained a writer".into());
    };
    assert_eq!(
        runtime_error.reason(),
        RecoveryRequired::InstallationIdentityMismatch
    );
    assert_eq!(backend.held_writer_role(), None);
    let Err(error) = backend.begin_initial_provisioning(&provider, other_installation) else {
        return Err("wrong installation minted fresh authority".into());
    };
    assert!(matches!(
        error,
        InitialProvisioningStartFailure::BeforeWriter(
            RecoveryRequired::InstallationIdentityMismatch
        )
    ));
    let committed = prepare_and_commit(&mut backend, &provider, installation)?;
    let provisioned = release_initial(&mut backend, committed)?;
    assert_eq!(provisioned.generation(), NonZeroU64::MIN);
    let Err(runtime_failure) = backend.boot(wrong_provider.runtime_authority()) else {
        return Err("wrong runtime provider minted boot authority".into());
    };
    assert!(matches!(
        runtime_failure,
        RuntimeBootStartFailure::WithWriter(_)
    ));
    assert_eq!(
        retire_runtime_boot_failure(&mut backend, runtime_failure)?,
        RecoveryRequired::AuthenticationFailed
    );

    let mut receipt_backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut receipt_backend, &provider, installation)?;
    let committed = receipt_backend
        .commit_initial_clean(&transition)?
        .with_installation_for_fixture_test(other_installation);
    let reread = receipt_backend.reread_initial_clean(&transition)?;
    let Err(failure) = transition.complete(committed, reread) else {
        return Err("wrong-installation receipt minted authority".into());
    };
    assert_eq!(
        failure.reason(),
        RecoveryRequired::InstallationIdentityMismatch
    );
    let _retired = retire_failure(&mut receipt_backend, failure)?;
    Ok(())
}

#[test]
fn writer_epoch_substitution_is_rejected() -> TestResult {
    let installation = fixture_installation(0x4c)?;
    let provider = fixture_provider(installation, 0x5b)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    let committed = backend
        .commit_initial_clean(&transition)?
        .with_writer_epoch_for_fixture_test(NonZeroU64::new(99).ok_or("invalid epoch")?);
    let reread = backend.reread_initial_clean(&transition)?;
    let Err(failure) = transition.complete(committed, reread) else {
        return Err("wrong writer epoch minted committed authority".into());
    };
    assert_eq!(failure.reason(), RecoveryRequired::WriterLeaseMismatch);
    let _retired = retire_failure(&mut backend, failure)?;
    Ok(())
}

#[test]
fn authority_attempt_substitution_is_rejected() -> TestResult {
    let installation = fixture_installation(0x4d)?;
    let provider = fixture_provider(installation, 0x5c)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    let committed = backend
        .commit_initial_clean(&transition)?
        .with_attempt_for_fixture_test(NonZeroU64::new(99).ok_or("invalid attempt")?);
    let reread = backend.reread_initial_clean(&transition)?;
    let Err(failure) = transition.complete(committed, reread) else {
        return Err("wrong provisioning attempt minted committed authority".into());
    };
    assert_eq!(
        failure.reason(),
        RecoveryRequired::ProvisioningAttemptMismatch
    );
    let _retired = retire_failure(&mut backend, failure)?;
    Ok(())
}

#[test]
fn reload_round_substitution_and_replay_are_rejected() -> TestResult {
    let installation = fixture_installation(0x4e)?;
    let provider = fixture_provider(installation, 0x5d)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let transition = prepare(&mut backend, &provider, installation)?;
    backend.set_commit_fault(DurableRunStateCommitFault::AmbiguousBeforeWrite);
    assert!(matches!(
        backend.commit_initial_clean(&transition),
        Err(DurableRunStateCommitFailure::Ambiguous)
    ));
    let pending = transition.commit_ambiguous().map_err(boxed_debug)?;
    let receipt = backend
        .reload_initial_clean(&pending)?
        .with_round_for_fixture_test(NonZeroU64::new(99).ok_or("invalid round")?);
    let Err(failure) = pending.complete_reload(receipt) else {
        return Err("wrong reload round restored retry authority".into());
    };
    assert_eq!(
        failure.reason(),
        RecoveryRequired::ProvisioningReloadRoundMismatch
    );
    let _retired = retire_failure(&mut backend, failure)?;
    Ok(())
}

#[test]
fn ambiguous_final_release_never_mints_provisioned_and_preserves_bytes() -> TestResult {
    let installation = fixture_installation(0x4f)?;
    let provider = fixture_provider(installation, 0x5e)?;
    let mut runtime_provider = fixture_provider(installation, 0x5e)?;
    for fault in [
        DurableRunStateReleaseFault::AmbiguousBeforeRelease,
        DurableRunStateReleaseFault::AmbiguousAfterRelease,
    ] {
        let mut backend = DurableRunStateFixture::empty(installation)?;
        let committed = prepare_and_commit(&mut backend, &provider, installation)?;
        let pending = committed.prepare_writer_release();
        let before_release = durable_bytes(&backend);
        backend.set_release_fault(fault);
        assert!(matches!(
            backend.release_provisioning_writer(&pending),
            Err(DurableRunStateReleaseFailure::Ambiguous)
        ));
        assert_eq!(
            backend.release_provisioning_writer(&pending).map(|_| ()),
            Err(DurableRunStateReleaseFailure::Recovery(
                RecoveryRequired::WriterReleaseReconciliationRequired
            ))
        );
        let expected_boot_error = if fault == DurableRunStateReleaseFault::AmbiguousBeforeRelease {
            RecoveryRequired::WriterLeaseUnavailable
        } else {
            RecoveryRequired::WriterReleaseReconciliationRequired
        };
        let Err(runtime_failure) = backend.boot(runtime_provider.runtime_authority()) else {
            return Err("ambiguous provisioning release allowed runtime boot".into());
        };
        assert_eq!(runtime_failure.reason(), expected_boot_error);
        assert!(matches!(
            runtime_failure,
            RuntimeBootStartFailure::BeforeWriter(_)
        ));
        if fault == DurableRunStateReleaseFault::AmbiguousAfterRelease {
            let Err(start_error) = backend.begin_initial_provisioning(&provider, installation)
            else {
                return Err("release-reconciliation latch allowed reprovisioning".into());
            };
            assert!(matches!(
                start_error,
                InitialProvisioningStartFailure::BeforeWriter(
                    RecoveryRequired::WriterReleaseReconciliationRequired
                )
            ));
        }
        let failure = pending.abort(RecoveryRequired::WriterReleaseAmbiguous);
        let _retired = retire_failure(&mut backend, failure)?;
        assert_eq!(durable_bytes(&backend), before_release);
        assert_eq!(backend.held_writer_role(), None);
    }
    Ok(())
}

#[test]
fn mismatched_release_and_terminal_round_receipts_only_reconcile_for_exit() -> TestResult {
    let installation = fixture_installation(0x50)?;
    let provider = fixture_provider(installation, 0x5f)?;
    let mut runtime_provider = fixture_provider(installation, 0x5f)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let committed = prepare_and_commit(&mut backend, &provider, installation)?;
    let pending = committed.prepare_writer_release();
    let before_release = durable_bytes(&backend);
    backend.set_release_fault(DurableRunStateReleaseFault::MismatchedReceiptAfterRelease);
    let mismatched = backend.release_provisioning_writer(&pending)?;
    let Err(failure) = pending.complete(mismatched) else {
        return Err("mismatched final release minted provisioned state".into());
    };
    assert_eq!(failure.reason(), RecoveryRequired::WriterLeaseMismatch);
    let Err(runtime_failure) = backend.boot(runtime_provider.runtime_authority()) else {
        return Err("mismatched provisioning release allowed runtime boot".into());
    };
    assert!(matches!(
        runtime_failure,
        RuntimeBootStartFailure::BeforeWriter(failure)
            if failure.reason()
                == RecoveryRequired::WriterReleaseReconciliationRequired
    ));
    let Err(start_error) = backend.begin_initial_provisioning(&provider, installation) else {
        return Err("mismatched release receipt allowed reprovisioning".into());
    };
    assert!(matches!(
        start_error,
        InitialProvisioningStartFailure::BeforeWriter(
            RecoveryRequired::WriterReleaseReconciliationRequired
        )
    ));
    let exit = failure.into_writer_exit();
    let wrong_round = NonZeroU64::new(99).ok_or("invalid round")?;
    let receipt = backend
        .retire_provisioning_writer_for_exit(&exit)?
        .with_round_for_fixture_test(wrong_round);
    let Err(round_failure) = exit.complete(receipt) else {
        return Err("wrong terminal round receipt completed retirement".into());
    };
    assert_eq!(
        round_failure.reason(),
        RecoveryRequired::ProvisioningReloadRoundMismatch
    );
    let _retired = retire_failure(&mut backend, round_failure)?;
    assert_eq!(durable_bytes(&backend), before_release);
    Ok(())
}

#[test]
fn bounded_counter_overflow_fails_without_unbound_authority() -> TestResult {
    let installation = fixture_installation(0x61)?;
    let provider = fixture_provider(installation, 0x60)?;

    let mut epoch_backend = DurableRunStateFixture::empty(installation)?;
    epoch_backend.last_writer_epoch = u64::MAX;
    let Err(error) = epoch_backend.begin_initial_provisioning(&provider, installation) else {
        return Err("writer epoch overflow minted authority".into());
    };
    assert_eq!(error.reason(), RecoveryRequired::WriterLeaseUnavailable);
    assert_eq!(epoch_backend.held_writer_role(), None);

    let mut attempt_backend = DurableRunStateFixture::empty(installation)?;
    attempt_backend.last_provisioning_attempt = u64::MAX;
    let Err(error) = attempt_backend.begin_initial_provisioning(&provider, installation) else {
        return Err("attempt overflow minted authority".into());
    };
    assert_eq!(
        error.reason(),
        RecoveryRequired::ProvisioningAttemptExhausted
    );
    assert_eq!(attempt_backend.held_writer_role(), None);

    let mut round_backend = DurableRunStateFixture::empty(installation)?;
    let unprovisioned = start(&mut round_backend, &provider, installation)?
        .with_round_for_fixture_test(NonZeroU64::MAX);
    round_backend.provisioning_reload_round = u64::MAX;
    let transition = unprovisioned.prepare_initial_clean().map_err(boxed_debug)?;
    round_backend.set_commit_fault(DurableRunStateCommitFault::AmbiguousBeforeWrite);
    assert!(matches!(
        round_backend.commit_initial_clean(&transition),
        Err(DurableRunStateCommitFailure::Ambiguous)
    ));
    let Err(failure) = transition.commit_ambiguous() else {
        return Err("reload-round overflow minted pending reload authority".into());
    };
    assert_eq!(
        failure.reason(),
        RecoveryRequired::ProvisioningReloadRoundExhausted
    );
    let _retired = retire_failure(&mut round_backend, failure)?;
    assert_eq!(durable_bytes(&round_backend), (None, None));
    assert!(std::mem::size_of::<DurableRunStateFixture>() <= 512);
    Ok(())
}

#[test]
fn provisioning_authorities_are_move_only_and_debug_redacted() -> TestResult {
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

    let _ = <FreshInstallProvisioningAuthority<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <FreshInstallProvisioningAuthority<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <ProvisioningWriterLease as AmbiguousIfClone<_>>::marker;
    let _ = <ProvisioningWriterLease as AmbiguousIfCopy<_>>::marker;
    let _ = <UnprovisionedWithWriter<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <UnprovisionedWithWriter<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <PreparedInitialCleanTransition<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <PreparedInitialCleanTransition<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <CommittedInitialCleanMarker as AmbiguousIfClone<_>>::marker;
    let _ = <CommittedInitialCleanMarker as AmbiguousIfCopy<_>>::marker;
    let _ = <RereadInitialCleanMarker as AmbiguousIfClone<_>>::marker;
    let _ = <RereadInitialCleanMarker as AmbiguousIfCopy<_>>::marker;
    let _ = <InitialCleanReloadRequired<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <InitialCleanReloadRequired<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <InitialCleanReloadReceipt as AmbiguousIfClone<_>>::marker;
    let _ = <InitialCleanReloadReceipt as AmbiguousIfCopy<_>>::marker;
    let _ = <ReloadedInitialCleanState<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <ReloadedInitialCleanState<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <InitialCleanCommittedWithWriter<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <InitialCleanCommittedWithWriter<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <PendingProvisioningWriterRelease<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <PendingProvisioningWriterRelease<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <ProvisioningWriterReleaseReceipt as AmbiguousIfClone<_>>::marker;
    let _ = <ProvisioningWriterReleaseReceipt as AmbiguousIfCopy<_>>::marker;
    let _ = <ProvisionedRunState as AmbiguousIfClone<_>>::marker;
    let _ = <ProvisionedRunState as AmbiguousIfCopy<_>>::marker;
    let _ = <ProvisioningFailureWithWriter<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <ProvisioningFailureWithWriter<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <ProvisioningWriterExitPending<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <ProvisioningWriterExitPending<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <ProvisioningWriterExitReceipt as AmbiguousIfClone<_>>::marker;
    let _ = <ProvisioningWriterExitReceipt as AmbiguousIfCopy<_>>::marker;
    let _ = <ProvisioningRecoveryExitEvidence as AmbiguousIfClone<_>>::marker;
    let _ = <ProvisioningRecoveryExitEvidence as AmbiguousIfCopy<_>>::marker;

    let installation = fixture_installation(0x63)?;
    let provider = fixture_provider(installation, 0x62)?;
    let mut backend = DurableRunStateFixture::empty(installation)?;
    let unprovisioned = start(&mut backend, &provider, installation)?;
    assert!(format!("{unprovisioned:?}").contains("[REDACTED]"));
    let transition = unprovisioned.prepare_initial_clean().map_err(boxed_debug)?;
    assert!(format!("{transition:?}").contains("[REDACTED]"));
    let committed = backend.commit_initial_clean(&transition)?;
    let reread = backend.reread_initial_clean(&transition)?;
    assert!(format!("{committed:?}").contains("[REDACTED]"));
    assert!(format!("{reread:?}").contains("[REDACTED]"));
    let clean = transition
        .complete(committed, reread)
        .map_err(boxed_debug)?;
    assert!(format!("{clean:?}").contains("[REDACTED]"));
    let pending = clean.prepare_writer_release();
    assert!(format!("{pending:?}").contains("[REDACTED]"));
    let receipt = backend.release_provisioning_writer(&pending)?;
    assert!(format!("{receipt:?}").contains("[REDACTED]"));
    let provisioned = pending.complete(receipt).map_err(boxed_debug)?;
    assert_eq!(
        format!("{provisioned:?}"),
        "ProvisionedRunState([REDACTED])"
    );
    Ok(())
}
