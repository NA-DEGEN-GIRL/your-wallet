//! Dormant held-object adoption for an existing Key Agent installation.
//!
//! The pure provenance module authenticates and compares installer snapshots;
//! this module alone bookends that proof with revalidation of the retained OS
//! objects. Production remains unreachable: there is no authoritative profile
//! observer, fixed-root existing opener, journal/checkpoint reader, exclusive
//! installer lease, or caller that can supply a post-observation reread.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;

use crate::key_agent_install_provenance::{
    AuthenticatedKeyAgentInstallSnapshot, consume_stable_existing_key_agent_install_evidence,
    verify_existing_key_agent_install_snapshots,
};
use crate::key_agent_lpac::{HeldExistingKeyAgentInstallObjects, PreparedKeyAgentProvisioning};

/// Unforgeable permission for the LPAC module's one held-object conversion.
///
/// The private field means only this adoption module can mint the value.
pub(crate) struct ExistingInstallAdoptionSeal {
    _private: (),
}

/// Held, authenticated proof of one existing installation.
///
/// The launch-capable provisioning remains private inside this aggregate. A
/// later artifact-binding boundary must compare the exact preflighted release
/// identity before it may consume the proof. No such consumer exists yet.
#[must_use = "verified existing Key Agent installation must remain release-bound"]
pub(crate) struct VerifiedExistingKeyAgentInstall {
    provisioning: PreparedKeyAgentProvisioning,
    installation_id: [u8; 32],
    release_identity: [u8; 32],
    journal_generation: u64,
    journal_record_digest: [u8; 32],
    _not_sync: PhantomData<Cell<()>>,
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

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::key_agent_install_provenance::authenticated_install_snapshot_pair_for_test;
    use crate::key_agent_lpac::{HeldExistingKeyAgentInstallObjects, KeyAgentLpacError};
    use crate::key_agent_storage::KeyAgentStorageRootIdentity;

    use super::{
        KeyAgentInstallAdoptionError, VerifiedExistingKeyAgentInstall,
        adopt_existing_key_agent_install,
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
        let _ = <VerifiedExistingKeyAgentInstall as AmbiguousIfClone<_>>::marker;
        let _ = <VerifiedExistingKeyAgentInstall as AmbiguousIfCopy<_>>::marker;
        let _ = <VerifiedExistingKeyAgentInstall as AmbiguousIfSync<_>>::marker;
        let _ = PhantomData::<VerifiedExistingKeyAgentInstall>;
        assert_eq!(
            format!("{:?}", KeyAgentInstallAdoptionError::RecoveryRequired),
            "KeyAgentInstallAdoptionError::RecoveryRequired"
        );
    }
}
