//! Dormant held-object adoption for an existing Key Agent installation.
//!
//! The pure provenance module authenticates and compares installer snapshots;
//! this module alone bookends that proof with revalidation of the retained OS
//! objects. Production remains unreachable: there is no authoritative profile
//! observer or held-aggregate constructor, and the dormant fixed-root existing
//! opener, this transition, and its release binding have no production caller.
//! No journal/checkpoint reader or exclusive installer lease can supply the
//! required post-observation reread either.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;

use crate::attestation::ReleaseAttestation;
use crate::helper::VerifiedHelper;
use crate::key_agent_activation::{PreflightKeyAgentArtifact, preflight_key_agent_activation};
use crate::key_agent_install_provenance::{
    AuthenticatedKeyAgentInstallSnapshot, consume_stable_existing_key_agent_install_evidence,
    verify_existing_key_agent_install_snapshots,
};
use crate::key_agent_lpac::{HeldExistingKeyAgentInstallObjects, PreparedKeyAgentProvisioning};
use crate::key_agent_supervisor::KeyAgentSupervisorBindingSeal;

/// Unforgeable permission for the LPAC module's one held-object conversion.
///
/// The private field means only this adoption module can mint the value.
pub(crate) struct ExistingInstallAdoptionSeal {
    _private: (),
}

/// Held, authenticated proof of one existing installation.
///
/// The launch-capable provisioning remains private inside this aggregate. Its
/// sole compiled downstream binding compares the exact preflighted whole-release
/// identity and retains the result; that binding still has no production caller.
#[must_use = "verified existing Key Agent installation must remain release-bound"]
pub(crate) struct VerifiedExistingKeyAgentInstall {
    provisioning: PreparedKeyAgentProvisioning,
    installation_id: [u8; 32],
    release_identity: [u8; 32],
    journal_generation: u64,
    journal_record_digest: [u8; 32],
    _not_sync: PhantomData<Cell<()>>,
}

/// Durable provenance retained after exact release-artifact binding.
///
/// The installation identity is the future child-side expected identity. The
/// remaining fields are supervisor-side provenance continuity only; none is a
/// rollback-anchor, key-bundle, settings-owner, or signing capability.
#[must_use = "verified install continuity must remain bound to the activated Key Agent"]
pub(crate) struct VerifiedKeyAgentInstallContinuity {
    installation_id: [u8; 32],
    release_identity: [u8; 32],
    journal_generation: u64,
    journal_record_digest: [u8; 32],
    _not_sync: PhantomData<Cell<()>>,
}

impl fmt::Debug for VerifiedKeyAgentInstallContinuity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.installation_id,
            &self.release_identity,
            &self.journal_generation,
            &self.journal_record_digest,
        );
        formatter.write_str("VerifiedKeyAgentInstallContinuity([REDACTED])")
    }
}

/// One adopted installation bound to the exact attested release cohort and
/// pinned Key Agent artifact before any worker, Job, pipe, or process exists.
#[must_use = "artifact-bound Key Agent installation must be consumed by its supervisor"]
pub(crate) struct ArtifactBoundExistingKeyAgentInstall {
    preflighted: PreflightKeyAgentArtifact,
    provisioning: PreparedKeyAgentProvisioning,
    continuity: VerifiedKeyAgentInstallContinuity,
}

impl fmt::Debug for ArtifactBoundExistingKeyAgentInstall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.preflighted, &self.provisioning, &self.continuity);
        formatter.write_str("ArtifactBoundExistingKeyAgentInstall([HELD; REDACTED])")
    }
}

impl fmt::Debug for VerifiedExistingKeyAgentInstall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.provisioning,
            &self.installation_id,
            &self.release_identity,
            &self.journal_generation,
            &self.journal_record_digest,
        );
        formatter.write_str("VerifiedExistingKeyAgentInstall([HELD; REDACTED])")
    }
}

/// Stable fail-closed result for the dormant existing-install adoption seam.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum KeyAgentInstallAdoptionError {
    RecoveryRequired,
}

impl fmt::Display for KeyAgentInstallAdoptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Key Agent installation requires trusted recovery")
    }
}

impl fmt::Debug for KeyAgentInstallAdoptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentInstallAdoptionError::RecoveryRequired")
    }
}

impl core::error::Error for KeyAgentInstallAdoptionError {}

/// Stable failures from binding adopted install provenance to one release.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum KeyAgentInstallReleaseBindingError {
    ReleaseUnavailable,
    RecoveryRequired,
}

impl fmt::Display for KeyAgentInstallReleaseBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Key Agent installation release binding is unavailable")
    }
}

impl fmt::Debug for KeyAgentInstallReleaseBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReleaseUnavailable => {
                formatter.write_str("KeyAgentInstallReleaseBindingError::ReleaseUnavailable")
            }
            Self::RecoveryRequired => {
                formatter.write_str("KeyAgentInstallReleaseBindingError::RecoveryRequired")
            }
        }
    }
}

impl core::error::Error for KeyAgentInstallReleaseBindingError {}

/// Bookends pure snapshot matching with exact held-root/profile revalidation.
///
/// `reread` is contractually the authoritative snapshot obtained after the OS
/// observation while an exclusive installer transaction lease is retained.
/// The future backend must enforce that temporal ordering; the current code has
/// no production snapshot source or caller and therefore cannot bypass it.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn adopt_existing_key_agent_install(
    initial: AuthenticatedKeyAgentInstallSnapshot,
    held: HeldExistingKeyAgentInstallObjects,
    reread: AuthenticatedKeyAgentInstallSnapshot,
) -> Result<VerifiedExistingKeyAgentInstall, KeyAgentInstallAdoptionError> {
    held.revalidate()
        .map_err(|_| KeyAgentInstallAdoptionError::RecoveryRequired)?;
    let observation = held
        .install_observation()
        .map_err(|_| KeyAgentInstallAdoptionError::RecoveryRequired)?;
    let stable = verify_existing_key_agent_install_snapshots(initial, reread, observation)
        .ok_or(KeyAgentInstallAdoptionError::RecoveryRequired)?;
    let (installation_id, release_identity, journal_generation, journal_record_digest) =
        consume_stable_existing_key_agent_install_evidence(stable);

    held.revalidate()
        .map_err(|_| KeyAgentInstallAdoptionError::RecoveryRequired)?;
    let provisioning = held.into_prepared(ExistingInstallAdoptionSeal { _private: () });
    Ok(VerifiedExistingKeyAgentInstall {
        provisioning,
        installation_id,
        release_identity,
        journal_generation,
        journal_record_digest,
        _not_sync: PhantomData,
    })
}

/// Binds an adopted installation to the exact release cohort that authorized
/// the pinned Key Agent artifact.
///
/// The overall attested release digest is deliberately distinct from the
/// helper-manifest digest that preflight also allowlists. Provisioning is
/// revalidated on both sides of the constant-time release comparison. This
/// function allocates no activation resource and exposes no raw digest or
/// prepared-provisioning accessor.
pub(crate) fn bind_existing_key_agent_install_to_release(
    attestation: ReleaseAttestation,
    artifact: VerifiedHelper,
    verified: VerifiedExistingKeyAgentInstall,
) -> Result<ArtifactBoundExistingKeyAgentInstall, KeyAgentInstallReleaseBindingError> {
    let preflighted = preflight_key_agent_activation(attestation, artifact)
        .map_err(|_| KeyAgentInstallReleaseBindingError::ReleaseUnavailable)?;
    verified
        .provisioning
        .revalidate()
        .map_err(|_| KeyAgentInstallReleaseBindingError::RecoveryRequired)?;
    if !preflighted.matches_release_identity(&verified.release_identity) {
        return Err(KeyAgentInstallReleaseBindingError::RecoveryRequired);
    }
    verified
        .provisioning
        .revalidate()
        .map_err(|_| KeyAgentInstallReleaseBindingError::RecoveryRequired)?;

    let VerifiedExistingKeyAgentInstall {
        provisioning,
        installation_id,
        release_identity,
        journal_generation,
        journal_record_digest,
        _not_sync: _,
    } = verified;
    Ok(ArtifactBoundExistingKeyAgentInstall {
        preflighted,
        provisioning,
        continuity: VerifiedKeyAgentInstallContinuity {
            installation_id,
            release_identity,
            journal_generation,
            journal_record_digest,
            _not_sync: PhantomData,
        },
    })
}

/// Performs the sole sealed split needed by the supervisor activation leaf.
///
/// Only `key_agent_supervisor` can construct the private-field seal. The
/// architecture gate fixes this function's sole production consumer and keeps
/// the three returned values together in the same linear activation body.
pub(crate) fn consume_artifact_bound_existing_key_agent_install(
    bound: ArtifactBoundExistingKeyAgentInstall,
    _seal: KeyAgentSupervisorBindingSeal,
) -> (
    PreflightKeyAgentArtifact,
    PreparedKeyAgentProvisioning,
    VerifiedKeyAgentInstallContinuity,
) {
    let ArtifactBoundExistingKeyAgentInstall {
        preflighted,
        provisioning,
        continuity,
    } = bound;
    (preflighted, provisioning, continuity)
}

#[cfg(test)]
pub(crate) fn verified_install_continuity_for_supervisor_test() -> VerifiedKeyAgentInstallContinuity
{
    VerifiedKeyAgentInstallContinuity {
        installation_id: [0x21; 32],
        release_identity: [0x23; 32],
        journal_generation: 4,
        journal_record_digest: [0x24; 32],
        _not_sync: PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::attestation::{ArtifactDigest, ReleaseAttestation};
    use crate::helper::VerifiedHelper;
    use crate::key_agent_install_provenance::authenticated_install_snapshot_pair_for_test;
    use crate::key_agent_lpac::{HeldExistingKeyAgentInstallObjects, KeyAgentLpacError};
    use crate::key_agent_storage::KeyAgentStorageRootIdentity;

    use super::{
        ArtifactBoundExistingKeyAgentInstall, KeyAgentInstallAdoptionError,
        KeyAgentInstallReleaseBindingError, VerifiedExistingKeyAgentInstall,
        VerifiedKeyAgentInstallContinuity, adopt_existing_key_agent_install,
        bind_existing_key_agent_install_to_release,
        verified_install_continuity_for_supervisor_test,
    };

    const INSTALLATION_ID: [u8; 32] = [0x22; 32];
    const RELEASE_IDENTITY: [u8; 32] = [0x33; 32];

    trait AmbiguousIfClone<Marker> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<Marker> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    trait AmbiguousIfSync<Marker> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    fn assert_send<T: Send>() {}

    fn adopted_install_for(
        release_identity: [u8; 32],
    ) -> Result<VerifiedExistingKeyAgentInstall, KeyAgentLpacError> {
        let held = HeldExistingKeyAgentInstallObjects::for_kernel_test()?;
        let observation = held.install_observation()?;
        let Some((initial, reread)) = authenticated_install_snapshot_pair_for_test(
            observation.profile_sid(),
            observation.stable_user_sid(),
            observation.storage_root_identity(),
            INSTALLATION_ID,
            release_identity,
            4,
        ) else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        adopt_existing_key_agent_install(initial, held, reread)
            .map_err(|_| KeyAgentLpacError::Provisioning)
    }

    fn attestation_for(
        release_identity: [u8; 32],
        artifact: &VerifiedHelper,
    ) -> ReleaseAttestation {
        ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test(release_identity),
            [artifact.manifest_digest(), [0x35; 32], [0x36; 32]],
        )
    }

    #[test]
    fn exact_held_objects_and_unchanged_committed_snapshots_mint_adoption()
    -> Result<(), KeyAgentLpacError> {
        let held = HeldExistingKeyAgentInstallObjects::for_kernel_test()?;
        let observation = held.install_observation()?;
        let Some((initial, reread)) = authenticated_install_snapshot_pair_for_test(
            observation.profile_sid(),
            observation.stable_user_sid(),
            observation.storage_root_identity(),
            INSTALLATION_ID,
            RELEASE_IDENTITY,
            4,
        ) else {
            return Err(KeyAgentLpacError::Provisioning);
        };

        let verified = adopt_existing_key_agent_install(initial, held, reread)
            .map_err(|_| KeyAgentLpacError::Provisioning)?;
        verified.provisioning.revalidate()?;
        assert_eq!(
            format!("{verified:?}"),
            "VerifiedExistingKeyAgentInstall([HELD; REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn checkpoint_reread_drift_and_uncommitted_history_require_recovery()
    -> Result<(), KeyAgentLpacError> {
        let held = HeldExistingKeyAgentInstallObjects::for_kernel_test()?;
        let observation = held.install_observation()?;
        let Some((initial, _same_reread)) = authenticated_install_snapshot_pair_for_test(
            observation.profile_sid(),
            observation.stable_user_sid(),
            observation.storage_root_identity(),
            INSTALLATION_ID,
            RELEASE_IDENTITY,
            4,
        ) else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        let drifted_release = [0x34; 32];
        let Some((_drifted_initial, drifted_reread)) = authenticated_install_snapshot_pair_for_test(
            observation.profile_sid(),
            observation.stable_user_sid(),
            observation.storage_root_identity(),
            INSTALLATION_ID,
            drifted_release,
            4,
        ) else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        assert!(matches!(
            adopt_existing_key_agent_install(initial, held, drifted_reread),
            Err(KeyAgentInstallAdoptionError::RecoveryRequired)
        ));

        let held = HeldExistingKeyAgentInstallObjects::for_kernel_test()?;
        let observation = held.install_observation()?;
        let Some((initial, reread)) = authenticated_install_snapshot_pair_for_test(
            observation.profile_sid(),
            observation.stable_user_sid(),
            observation.storage_root_identity(),
            INSTALLATION_ID,
            RELEASE_IDENTITY,
            3,
        ) else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        assert!(matches!(
            adopt_existing_key_agent_install(initial, held, reread),
            Err(KeyAgentInstallAdoptionError::RecoveryRequired)
        ));
        Ok(())
    }

    #[test]
    fn held_root_identity_mismatch_requires_recovery() -> Result<(), KeyAgentLpacError> {
        let held = HeldExistingKeyAgentInstallObjects::for_kernel_test()?;
        let observation = held.install_observation()?;
        let mut wrong_identity = observation.storage_root_identity().encode_be();
        wrong_identity[8] ^= 1;
        let wrong_identity = KeyAgentStorageRootIdentity::decode_be(wrong_identity)
            .map_err(|_| KeyAgentLpacError::Provisioning)?;
        let Some((initial, reread)) = authenticated_install_snapshot_pair_for_test(
            observation.profile_sid(),
            observation.stable_user_sid(),
            wrong_identity,
            INSTALLATION_ID,
            RELEASE_IDENTITY,
            4,
        ) else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        assert!(matches!(
            adopt_existing_key_agent_install(initial, held, reread),
            Err(KeyAgentInstallAdoptionError::RecoveryRequired)
        ));
        Ok(())
    }

    #[test]
    fn held_sid_bindings_must_match_authenticated_snapshots() -> Result<(), KeyAgentLpacError> {
        let held = HeldExistingKeyAgentInstallObjects::for_kernel_test()?;
        let observation = held.install_observation()?;
        let mut wrong_profile_sid = observation.profile_sid().to_vec();
        let Some(last) = wrong_profile_sid.last_mut() else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        *last ^= 1;
        let Some((initial, reread)) = authenticated_install_snapshot_pair_for_test(
            &wrong_profile_sid,
            observation.stable_user_sid(),
            observation.storage_root_identity(),
            INSTALLATION_ID,
            RELEASE_IDENTITY,
            4,
        ) else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        assert!(matches!(
            adopt_existing_key_agent_install(initial, held, reread),
            Err(KeyAgentInstallAdoptionError::RecoveryRequired)
        ));

        let held = HeldExistingKeyAgentInstallObjects::for_kernel_test()?;
        let observation = held.install_observation()?;
        let mut wrong_stable_user_sid = observation.stable_user_sid().to_vec();
        let Some(last) = wrong_stable_user_sid.last_mut() else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        *last ^= 1;
        let Some((initial, reread)) = authenticated_install_snapshot_pair_for_test(
            observation.profile_sid(),
            &wrong_stable_user_sid,
            observation.storage_root_identity(),
            INSTALLATION_ID,
            RELEASE_IDENTITY,
            4,
        ) else {
            return Err(KeyAgentLpacError::Provisioning);
        };
        assert!(matches!(
            adopt_existing_key_agent_install(initial, held, reread),
            Err(KeyAgentInstallAdoptionError::RecoveryRequired)
        ));
        Ok(())
    }

    #[test]
    fn adoption_authority_is_send_only_noncopy_and_redacted() {
        assert_send::<VerifiedExistingKeyAgentInstall>();
        assert_send::<ArtifactBoundExistingKeyAgentInstall>();
        assert_send::<VerifiedKeyAgentInstallContinuity>();
        let _ = <VerifiedExistingKeyAgentInstall as AmbiguousIfClone<_>>::marker;
        let _ = <VerifiedExistingKeyAgentInstall as AmbiguousIfCopy<_>>::marker;
        let _ = <VerifiedExistingKeyAgentInstall as AmbiguousIfSync<_>>::marker;
        let _ = <ArtifactBoundExistingKeyAgentInstall as AmbiguousIfClone<_>>::marker;
        let _ = <ArtifactBoundExistingKeyAgentInstall as AmbiguousIfCopy<_>>::marker;
        let _ = <ArtifactBoundExistingKeyAgentInstall as AmbiguousIfSync<_>>::marker;
        let _ = <VerifiedKeyAgentInstallContinuity as AmbiguousIfClone<_>>::marker;
        let _ = <VerifiedKeyAgentInstallContinuity as AmbiguousIfCopy<_>>::marker;
        let _ = <VerifiedKeyAgentInstallContinuity as AmbiguousIfSync<_>>::marker;
        let _ = PhantomData::<VerifiedExistingKeyAgentInstall>;
        let continuity = verified_install_continuity_for_supervisor_test();
        assert_eq!(
            format!("{continuity:?}"),
            "VerifiedKeyAgentInstallContinuity([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", KeyAgentInstallAdoptionError::RecoveryRequired),
            "KeyAgentInstallAdoptionError::RecoveryRequired"
        );
    }

    #[test]
    fn exact_attested_release_mints_one_artifact_bound_install() -> Result<(), KeyAgentLpacError> {
        let verified = adopted_install_for(RELEASE_IDENTITY)?;
        let artifact = VerifiedHelper::for_key_agent_activation_test()
            .map_err(|_| KeyAgentLpacError::Provisioning)?;
        let attestation = attestation_for(RELEASE_IDENTITY, &artifact);
        let bound = bind_existing_key_agent_install_to_release(attestation, artifact, verified)
            .map_err(|_| KeyAgentLpacError::Provisioning)?;
        assert_eq!(
            format!("{bound:?}"),
            "ArtifactBoundExistingKeyAgentInstall([HELD; REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn release_mismatch_and_helper_manifest_substitution_require_recovery()
    -> Result<(), KeyAgentLpacError> {
        let verified = adopted_install_for(RELEASE_IDENTITY)?;
        let artifact = VerifiedHelper::for_key_agent_activation_test()
            .map_err(|_| KeyAgentLpacError::Provisioning)?;
        let wrong_release = [0x34; 32];
        let attestation = attestation_for(wrong_release, &artifact);
        assert!(matches!(
            bind_existing_key_agent_install_to_release(attestation, artifact, verified),
            Err(KeyAgentInstallReleaseBindingError::RecoveryRequired)
        ));

        let artifact = VerifiedHelper::for_key_agent_activation_test()
            .map_err(|_| KeyAgentLpacError::Provisioning)?;
        let verified = adopted_install_for(artifact.manifest_digest())?;
        let attestation = attestation_for(RELEASE_IDENTITY, &artifact);
        assert!(matches!(
            bind_existing_key_agent_install_to_release(attestation, artifact, verified),
            Err(KeyAgentInstallReleaseBindingError::RecoveryRequired)
        ));
        Ok(())
    }

    #[test]
    fn unavailable_release_fails_before_install_binding() -> Result<(), KeyAgentLpacError> {
        let verified = adopted_install_for(RELEASE_IDENTITY)?;
        let artifact = VerifiedHelper::for_key_agent_activation_test()
            .map_err(|_| KeyAgentLpacError::Provisioning)?;
        assert!(matches!(
            bind_existing_key_agent_install_to_release(
                ReleaseAttestation::default(),
                artifact,
                verified,
            ),
            Err(KeyAgentInstallReleaseBindingError::ReleaseUnavailable)
        ));
        Ok(())
    }
}
