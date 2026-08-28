//! Dormant release-bound admission for one exact Key Agent debugger artifact.
//!
//! This module allocates no Job, pipe, channel, thread, process, or debug
//! resource and exposes no launch operation. It converts an already verified,
//! pinned debugger file into opaque preflight and same-handle identity
//! capabilities while the compiled release policy remains disabled.

#![forbid(unsafe_code)]

use core::fmt;

use thiserror::Error;
#[cfg(windows)]
use zeroize::Zeroize as _;

use crate::attestation::{AttestedArtifactDigest, ReleaseAttestation};
#[cfg(windows)]
use crate::exact_image::{ExactFileIdentity, ExactImageError, held_helper_file_identity};
use crate::helper::VerifiedHelper;

/// Stable failures from the dormant debugger artifact-admission boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum DebuggerArtifactError {
    /// The verified manifest did not derive the exact debugger role.
    #[error("verified artifact is not the Key Agent debugger")]
    WrongRole,
    /// The complete compiled release policy and evidence did not attest.
    #[error("Key Agent debugger release evidence is unavailable")]
    ReleaseNotAttested,
    /// The verified debugger manifest was not the release-bound manifest.
    #[error("Key Agent debugger manifest is not release-allowed")]
    ManifestNotAllowed,
    /// The verified debugger did not retain an absolute installed path.
    #[error("verified Key Agent debugger path is invalid")]
    InvalidPath,
}

/// Stable failure from same-handle debugger artifact preparation.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum DebuggerArtifactPreparationError {
    /// The simultaneously held debugger file lacked an unambiguous 128-bit ID.
    #[error("held Key Agent debugger artifact identity is unavailable")]
    IdentityUnavailable,
}

#[cfg(windows)]
impl From<ExactImageError> for DebuggerArtifactPreparationError {
    fn from(_error: ExactImageError) -> Self {
        Self::IdentityUnavailable
    }
}

/// Opaque pre-spawn proof that one pinned debugger passed every release gate.
///
/// This capability is non-cloneable, retains the opaque whole-release identity
/// separately from the dedicated debugger manifest, and exposes no path, raw
/// handle, artifact, release digest, or launch operation.
#[must_use = "dropping debugger preflight closes its pinned file"]
pub(crate) struct PreflightDebuggerArtifact {
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
}

impl fmt::Debug for PreflightDebuggerArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreflightDebuggerArtifact([PINNED VERIFIED KEY AGENT DEBUGGER])")
    }
}

/// Performs all debugger release gates without allocating an activation resource.
///
/// Role is checked before whole-release evidence, the dedicated debugger
/// manifest is checked before the installed path, and ownership of the held
/// artifact moves only after every gate succeeds.
pub(crate) fn preflight_debugger_artifact(
    attestation: ReleaseAttestation,
    artifact: VerifiedHelper,
) -> Result<PreflightDebuggerArtifact, DebuggerArtifactError> {
    if !artifact.is_key_agent_debugger() {
        return Err(DebuggerArtifactError::WrongRole);
    }
    let release_identity = attestation
        .attested_artifact()
        .ok_or(DebuggerArtifactError::ReleaseNotAttested)?;
    if !attestation.allows_key_agent_debugger_manifest(artifact.manifest_digest()) {
        return Err(DebuggerArtifactError::ManifestNotAllowed);
    }
    if !artifact.path().is_absolute() {
        return Err(DebuggerArtifactError::InvalidPath);
    }

    Ok(PreflightDebuggerArtifact {
        artifact,
        release_identity,
    })
}

/// Opaque same-handle debugger artifact prepared for a future launch boundary.
///
/// The verified file remains pinned without write/delete sharing. Whole-release,
/// manifest, and complete `FILE_ID_INFO` identities remain separate and private.
/// No process or debug authority can be obtained from this type.
#[cfg(windows)]
#[must_use = "dropping prepared debugger admission closes its pinned file"]
pub(crate) struct PreparedReleaseDebuggerArtifact {
    artifact: VerifiedHelper,
    release_identity: AttestedArtifactDigest,
    identity: ExactFileIdentity,
}

#[cfg(windows)]
impl fmt::Debug for PreparedReleaseDebuggerArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedReleaseDebuggerArtifact([HELD DEBUGGER/RELEASE/FILE_ID_INFO])")
    }
}

#[cfg(windows)]
impl Drop for PreparedReleaseDebuggerArtifact {
    fn drop(&mut self) {
        self.identity.zeroize();
    }
}

/// Derives complete file identity from the same already-held debugger handle.
///
/// This performs no reopen, canonicalization, path lookup, process creation, or
/// debug operation. Ownership moves only after the identity query succeeds.
#[cfg(windows)]
pub(crate) fn prepare_release_debugger_artifact(
    preflight: PreflightDebuggerArtifact,
) -> Result<PreparedReleaseDebuggerArtifact, DebuggerArtifactPreparationError> {
    let identity = held_helper_file_identity(&preflight.artifact)?;
    let PreflightDebuggerArtifact {
        artifact,
        release_identity,
    } = preflight;
    Ok(PreparedReleaseDebuggerArtifact {
        artifact,
        release_identity,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[cfg(windows)]
    use super::prepare_release_debugger_artifact;
    use super::{DebuggerArtifactError, preflight_debugger_artifact};
    use crate::attestation::{ArtifactDigest, ReleaseAttestation};
    #[cfg(windows)]
    use crate::exact_image::held_helper_file_identity;
    use crate::helper::VerifiedHelper;

    const DEBUGGER_MANIFEST: [u8; 32] = [0x51; 32];

    fn artifact(
        path: PathBuf,
        manifest_digest: [u8; 32],
        debugger_role: bool,
    ) -> Result<VerifiedHelper, Box<dyn std::error::Error>> {
        Ok(VerifiedHelper::for_key_agent_debugger_artifact_test(
            path,
            manifest_digest,
            debugger_role,
        )?)
    }

    fn absolute_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(std::env::current_exe()?)
    }

    fn attestation(manifest: [u8; 32]) -> ReleaseAttestation {
        ReleaseAttestation::with_key_agent_debugger_manifest_for_test(
            ArtifactDigest::for_test([0x50; 32]),
            manifest,
        )
    }

    #[test]
    fn role_is_rejected_before_release_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let wrong_role = artifact(absolute_path()?, DEBUGGER_MANIFEST, false)?;
        assert!(matches!(
            preflight_debugger_artifact(ReleaseAttestation::default(), wrong_role),
            Err(DebuggerArtifactError::WrongRole)
        ));
        Ok(())
    }

    #[test]
    fn absent_compiled_release_attestation_rejects_debugger()
    -> Result<(), Box<dyn std::error::Error>> {
        let debugger = artifact(absolute_path()?, DEBUGGER_MANIFEST, true)?;
        assert!(matches!(
            preflight_debugger_artifact(ReleaseAttestation::default(), debugger),
            Err(DebuggerArtifactError::ReleaseNotAttested)
        ));
        Ok(())
    }

    #[test]
    fn exact_manifest_is_required_before_path_admission() -> Result<(), Box<dyn std::error::Error>>
    {
        let relative = artifact(
            PathBuf::from("key-agent-debugger.exe"),
            DEBUGGER_MANIFEST,
            true,
        )?;
        assert!(matches!(
            preflight_debugger_artifact(attestation([0x52; 32]), relative),
            Err(DebuggerArtifactError::ManifestNotAllowed)
        ));
        Ok(())
    }

    #[test]
    fn relative_path_is_rejected_after_exact_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let relative = artifact(
            PathBuf::from("key-agent-debugger.exe"),
            DEBUGGER_MANIFEST,
            true,
        )?;
        assert!(matches!(
            preflight_debugger_artifact(attestation(DEBUGGER_MANIFEST), relative),
            Err(DebuggerArtifactError::InvalidPath)
        ));
        Ok(())
    }

    #[test]
    fn exact_release_bound_debugger_mints_only_redacted_opaque_preflight()
    -> Result<(), Box<dyn std::error::Error>> {
        let debugger = artifact(absolute_path()?, DEBUGGER_MANIFEST, true)?;
        let admitted = preflight_debugger_artifact(attestation(DEBUGGER_MANIFEST), debugger)?;
        assert_eq!(admitted.artifact.manifest_digest(), DEBUGGER_MANIFEST);
        assert!(admitted.release_identity.matches(&[0x50; 32]));
        assert_eq!(
            format!("{admitted:?}"),
            "PreflightDebuggerArtifact([PINNED VERIFIED KEY AGENT DEBUGGER])"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn preparation_retains_release_artifact_and_complete_same_handle_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let debugger = artifact(absolute_path()?, DEBUGGER_MANIFEST, true)?;
        let held_handle = debugger.raw_handle();
        let expected_identity = held_helper_file_identity(&debugger)?;
        let admitted = preflight_debugger_artifact(attestation(DEBUGGER_MANIFEST), debugger)?;
        let prepared = prepare_release_debugger_artifact(admitted)?;
        assert_eq!(prepared.artifact.raw_handle(), held_handle);
        assert_eq!(prepared.artifact.manifest_digest(), DEBUGGER_MANIFEST);
        assert!(prepared.release_identity.matches(&[0x50; 32]));
        assert_eq!(prepared.identity, expected_identity);
        assert_ne!(prepared.identity.encode_be(), [0; 24]);
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedReleaseDebuggerArtifact([HELD DEBUGGER/RELEASE/FILE_ID_INFO])"
        );
        Ok(())
    }
}
