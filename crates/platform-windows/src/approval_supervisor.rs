//! Dormant release-bound admission for one exact Approval artifact.
//!
//! This module allocates no Job, pipe, channel, thread, or process and exposes
//! no launch operation. It converts an already verified, pinned Approval file
//! into an opaque release capability, then consumes that capability into a
//! supervisor-owned same-handle file-identity state on Windows.

use core::fmt;

use thiserror::Error;
#[cfg(windows)]
use zeroize::Zeroize;

use crate::attestation::{AttestedArtifactDigest, ReleaseAttestation};
#[cfg(windows)]
use crate::exact_image::{ExactFileIdentity, ExactImageError, held_helper_file_identity};
use crate::helper::VerifiedHelper;

/// Stable failures from the dormant Approval artifact-admission boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ApprovalArtifactError {
    /// The verified manifest did not derive the exact Approval Frontend role.
    #[error("verified artifact is not the Approval Frontend")]
    WrongRole,
    /// The complete compiled release policy and evidence did not attest.
    #[error("Approval release evidence is unavailable")]
    ReleaseNotAttested,
    /// The verified Approval manifest was not in the release helper allowlist.
    #[error("Approval manifest is not release-allowed")]
    ManifestNotAllowed,
    /// The verified Approval artifact did not retain an absolute installed path.
    #[error("verified Approval path is invalid")]
    InvalidPath,
}

/// Stable failure from the release Approval supervisor preparation boundary.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ApprovalSupervisorPreflightError {
    /// The simultaneously held Approval file lacked an unambiguous 128-bit ID.
    #[error("held Approval artifact identity is unavailable")]
    IdentityUnavailable,
}

#[cfg(windows)]
impl From<ExactImageError> for ApprovalSupervisorPreflightError {
    fn from(_error: ExactImageError) -> Self {
        Self::IdentityUnavailable
    }
}

/// Opaque pre-spawn proof that one pinned Approval passed every release gate.
///
/// This capability is non-cloneable and retains the opaque whole-release
/// identity separately from the Approval manifest. It exposes no artifact,
/// release digest, path, or raw-handle accessor and has no launch operation.
#[must_use = "dropping the Approval preflight capability closes its pinned file"]
pub(crate) struct PreflightApprovalArtifact {
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
}

impl fmt::Debug for PreflightApprovalArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreflightApprovalArtifact([PINNED VERIFIED APPROVAL])")
    }
}

/// Opaque release Approval state prepared from one already-admitted file object.
///
/// The value retains the pinned artifact, opaque whole-release identity, and
/// same-held-file `FILE_ID_INFO`. It is non-cloneable, exposes no resource or
/// identity accessor, and supplies no activation operation.
#[cfg(windows)]
#[must_use = "dropping the prepared Approval supervisor closes its pinned file"]
pub(crate) struct PreparedReleaseApprovalSupervisor {
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
    identity: ExactFileIdentity,
}

#[cfg(windows)]
impl fmt::Debug for PreparedReleaseApprovalSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("PreparedReleaseApprovalSupervisor([HELD APPROVAL/RELEASE/FILE_ID_INFO])")
    }
}

#[cfg(windows)]
impl Drop for PreparedReleaseApprovalSupervisor {
    fn drop(&mut self) {
        self.identity.zeroize();
    }
}

/// Performs every release gate without allocating an activation resource.
///
/// The exact order is Approval role, complete release evidence, helper manifest
/// allowlist, then absolute installed path. Ownership moves only after all four
/// gates succeed.
pub(crate) fn preflight_approval_artifact(
    attestation: ReleaseAttestation,
    artifact: VerifiedHelper,
) -> Result<PreflightApprovalArtifact, ApprovalArtifactError> {
    if !artifact.is_approval_frontend() {
        return Err(ApprovalArtifactError::WrongRole);
    }
    let release_identity = attestation
        .attested_artifact()
        .ok_or(ApprovalArtifactError::ReleaseNotAttested)?;
    if !attestation.allows_helper_manifest(artifact.manifest_digest()) {
        return Err(ApprovalArtifactError::ManifestNotAllowed);
    }
    if !artifact.path().is_absolute() {
        return Err(ApprovalArtifactError::InvalidPath);
    }

    Ok(PreflightApprovalArtifact {
        artifact,
        release_identity,
    })
}

/// Consumes one admitted Approval capability into private prepared state.
///
/// Identity is queried only from the already retained file handle before the
/// held artifact and opaque whole-release identity move into the result. This
/// allocates no pipe, Job, channel, thread, process, launch state, or second
/// file handle.
#[cfg(windows)]
pub(crate) fn prepare_release_approval_supervisor(
    artifact: PreflightApprovalArtifact,
) -> Result<PreparedReleaseApprovalSupervisor, ApprovalSupervisorPreflightError> {
    let identity = held_helper_file_identity(&artifact.artifact)?;
    let PreflightApprovalArtifact {
        artifact,
        release_identity,
    } = artifact;
    Ok(PreparedReleaseApprovalSupervisor {
        artifact,
        release_identity,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[cfg(windows)]
    use super::prepare_release_approval_supervisor;
    use super::{ApprovalArtifactError, preflight_approval_artifact};
    use crate::attestation::{ArtifactDigest, ReleaseAttestation};
    #[cfg(windows)]
    use crate::exact_image::held_helper_file_identity;
    use crate::helper::VerifiedHelper;

    const APPROVAL_MANIFEST: [u8; 32] = [0x51; 32];
    const RELEASE_IDENTITY: [u8; 32] = [0x50; 32];

    fn artifact(
        path: PathBuf,
        manifest_digest: [u8; 32],
        approval_frontend_role: bool,
    ) -> Result<VerifiedHelper, Box<dyn std::error::Error>> {
        Ok(VerifiedHelper::for_approval_artifact_test(
            path,
            manifest_digest,
            approval_frontend_role,
        )?)
    }

    fn absolute_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(std::env::current_exe()?)
    }

    fn attestation_with(approval_manifest: [u8; 32]) -> ReleaseAttestation {
        ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test(RELEASE_IDENTITY),
            [approval_manifest, [0x52; 32], [0x53; 32]],
        )
    }

    #[test]
    fn role_is_rejected_before_release_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let wrong_role = artifact(absolute_path()?, APPROVAL_MANIFEST, false)?;
        assert!(matches!(
            preflight_approval_artifact(ReleaseAttestation::default(), wrong_role),
            Err(ApprovalArtifactError::WrongRole)
        ));
        Ok(())
    }

    #[test]
    fn absent_compiled_release_attestation_rejects_approval()
    -> Result<(), Box<dyn std::error::Error>> {
        let approval = artifact(absolute_path()?, APPROVAL_MANIFEST, true)?;
        assert!(matches!(
            preflight_approval_artifact(ReleaseAttestation::default(), approval),
            Err(ApprovalArtifactError::ReleaseNotAttested)
        ));
        Ok(())
    }

    #[test]
    fn exact_helper_manifest_is_required_before_path_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let relative_approval = artifact(
            PathBuf::from("approval-frontend.exe"),
            APPROVAL_MANIFEST,
            true,
        )?;
        assert!(matches!(
            preflight_approval_artifact(attestation_with([0x54; 32]), relative_approval),
            Err(ApprovalArtifactError::ManifestNotAllowed)
        ));
        Ok(())
    }

    #[test]
    fn relative_path_is_rejected_after_exact_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let relative_approval = artifact(
            PathBuf::from("approval-frontend.exe"),
            APPROVAL_MANIFEST,
            true,
        )?;
        assert!(matches!(
            preflight_approval_artifact(attestation_with(APPROVAL_MANIFEST), relative_approval,),
            Err(ApprovalArtifactError::InvalidPath)
        ));
        Ok(())
    }

    #[test]
    fn exact_release_bound_approval_mints_only_redacted_opaque_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let approval = artifact(absolute_path()?, APPROVAL_MANIFEST, true)?;
        let admitted = preflight_approval_artifact(attestation_with(APPROVAL_MANIFEST), approval)?;
        assert_eq!(admitted.artifact.manifest_digest(), APPROVAL_MANIFEST);
        assert!(admitted.release_identity.matches(&RELEASE_IDENTITY));
        assert_eq!(
            format!("{admitted:?}"),
            "PreflightApprovalArtifact([PINNED VERIFIED APPROVAL])"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn preparation_retains_same_held_file_identity_and_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let approval = artifact(absolute_path()?, APPROVAL_MANIFEST, true)?;
        let held_handle = approval.raw_handle();
        let expected_identity = held_helper_file_identity(&approval)?;
        let admitted = preflight_approval_artifact(attestation_with(APPROVAL_MANIFEST), approval)?;
        let prepared = prepare_release_approval_supervisor(admitted)?;

        assert_eq!(prepared.artifact.raw_handle(), held_handle);
        assert_eq!(prepared.identity, expected_identity);
        assert!(prepared.release_identity.matches(&RELEASE_IDENTITY));
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedReleaseApprovalSupervisor([HELD APPROVAL/RELEASE/FILE_ID_INFO])"
        );
        Ok(())
    }
}
