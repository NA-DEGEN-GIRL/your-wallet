//! Dormant release-bound admission for one exact Broker artifact.
//!
//! This module allocates no Job, pipe, thread, or process and exposes no launch
//! operation. It only converts an already verified, pinned Broker file into an
//! opaque capability after the complete release and role gates succeed.

use core::fmt;

use thiserror::Error;

use crate::attestation::ReleaseAttestation;
use crate::helper::VerifiedHelper;

/// Stable failures from the dormant Broker artifact-admission boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum BrokerArtifactError {
    /// The verified manifest did not derive the exact Broker role.
    #[error("verified artifact is not the Broker")]
    WrongRole,
    /// The complete compiled release policy and evidence did not attest.
    #[error("Broker release evidence is unavailable")]
    ReleaseNotAttested,
    /// The verified Broker manifest was not the release-bound Broker manifest.
    #[error("Broker manifest is not release-allowed")]
    ManifestNotAllowed,
    /// The verified Broker did not retain an absolute installed path.
    #[error("verified Broker path is invalid")]
    InvalidPath,
}

/// Opaque pre-spawn proof that one pinned Broker passed every release gate.
///
/// This capability is non-cloneable, exposes no artifact, path, or raw-handle
/// accessor, and has no launch operation. A later supervisor slice must consume
/// it without weakening the role, evidence, manifest, or path ordering here.
#[must_use = "dropping the Broker preflight capability closes its pinned file"]
pub(crate) struct PreflightBrokerArtifact {
    artifact: VerifiedHelper,
}

impl fmt::Debug for PreflightBrokerArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreflightBrokerArtifact([PINNED VERIFIED BROKER])")
    }
}

/// Performs all release gates without allocating an activation resource.
///
/// Role is checked before release evidence, the dedicated Broker manifest is
/// checked before the installed path, and ownership of the held artifact moves
/// only after every gate succeeds.
pub(crate) fn preflight_broker_artifact(
    attestation: ReleaseAttestation,
    artifact: VerifiedHelper,
) -> Result<PreflightBrokerArtifact, BrokerArtifactError> {
    if !artifact.is_broker() {
        return Err(BrokerArtifactError::WrongRole);
    }
    if !attestation.signing_enabled() {
        return Err(BrokerArtifactError::ReleaseNotAttested);
    }
    if !attestation.allows_broker_manifest(artifact.manifest_digest()) {
        return Err(BrokerArtifactError::ManifestNotAllowed);
    }
    if !artifact.path().is_absolute() {
        return Err(BrokerArtifactError::InvalidPath);
    }

    Ok(PreflightBrokerArtifact { artifact })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{BrokerArtifactError, preflight_broker_artifact};
    use crate::attestation::ReleaseAttestation;
    use crate::helper::VerifiedHelper;

    const BROKER_MANIFEST: [u8; 32] = [0x41; 32];

    fn artifact(
        path: PathBuf,
        manifest_digest: [u8; 32],
        broker_role: bool,
    ) -> Result<VerifiedHelper, Box<dyn std::error::Error>> {
        Ok(VerifiedHelper::for_broker_artifact_test(
            path,
            manifest_digest,
            broker_role,
        )?)
    }

    fn absolute_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(std::env::current_exe()?)
    }

    #[test]
    fn role_is_rejected_before_release_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let wrong_role = artifact(absolute_path()?, BROKER_MANIFEST, false)?;
        assert!(matches!(
            preflight_broker_artifact(ReleaseAttestation::default(), wrong_role),
            Err(BrokerArtifactError::WrongRole)
        ));
        Ok(())
    }

    #[test]
    fn absent_compiled_release_attestation_rejects_broker() -> Result<(), Box<dyn std::error::Error>>
    {
        let broker = artifact(absolute_path()?, BROKER_MANIFEST, true)?;
        assert!(matches!(
            preflight_broker_artifact(ReleaseAttestation::default(), broker),
            Err(BrokerArtifactError::ReleaseNotAttested)
        ));
        Ok(())
    }

    #[test]
    fn exact_broker_manifest_is_required_before_path_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let relative_broker = artifact(PathBuf::from("broker.exe"), BROKER_MANIFEST, true)?;
        let wrong_manifest = ReleaseAttestation::with_broker_manifest_for_test([0x42; 32]);
        assert!(matches!(
            preflight_broker_artifact(wrong_manifest, relative_broker),
            Err(BrokerArtifactError::ManifestNotAllowed)
        ));
        Ok(())
    }

    #[test]
    fn relative_path_is_rejected_after_exact_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let relative_broker = artifact(PathBuf::from("broker.exe"), BROKER_MANIFEST, true)?;
        let attestation = ReleaseAttestation::with_broker_manifest_for_test(BROKER_MANIFEST);
        assert!(matches!(
            preflight_broker_artifact(attestation, relative_broker),
            Err(BrokerArtifactError::InvalidPath)
        ));
        Ok(())
    }

    #[test]
    fn exact_release_bound_broker_mints_only_redacted_opaque_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let broker = artifact(absolute_path()?, BROKER_MANIFEST, true)?;
        let attestation = ReleaseAttestation::with_broker_manifest_for_test(BROKER_MANIFEST);
        let admitted = preflight_broker_artifact(attestation, broker)?;
        assert_eq!(admitted.artifact.manifest_digest(), BROKER_MANIFEST);
        assert_eq!(
            format!("{admitted:?}"),
            "PreflightBrokerArtifact([PINNED VERIFIED BROKER])"
        );
        Ok(())
    }
}
