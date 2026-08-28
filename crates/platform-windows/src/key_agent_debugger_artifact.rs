//! Dormant release-bound admission for one exact Key Agent debugger artifact.
//!
//! This module allocates no Job, pipe, channel, thread, process, or debug
//! resource and exposes no launch operation. It converts an already verified,
//! pinned debugger file into opaque preflight and same-handle identity
//! capabilities while the compiled release policy remains disabled.

#![forbid(unsafe_code)]

use core::fmt;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
#[cfg(windows)]
use std::path::Path;

use thiserror::Error;
#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use zeroize::Zeroize as _;

use crate::attestation::{AttestedArtifactDigest, ReleaseAttestation};
#[cfg(windows)]
use crate::exact_image::{
    ExactFileIdentity, ExactImageError,
    authenticate_mapped_image as authenticate_exact_mapped_image, held_helper_file_identity,
};
use crate::helper::VerifiedHelper;

/// Stable failures from the dormant debugger artifact-admission boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(super) enum DebuggerArtifactError {
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
pub(super) enum DebuggerArtifactPreparationError {
    /// The simultaneously held debugger file lacked an unambiguous 128-bit ID.
    #[error("held Key Agent debugger artifact identity is unavailable")]
    IdentityUnavailable,
}

/// Stable failure from the mapped-image transition.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(super) enum DebuggerMappedImageError {
    /// Windows could not derive a complete identity from the event image.
    #[error("mapped Key Agent debugger image identity is unavailable")]
    IdentityUnavailable,
    /// The event image was not the simultaneously held release artifact.
    #[error("mapped Key Agent debugger image did not match the held release artifact")]
    Mismatch,
}

#[cfg(windows)]
impl From<ExactImageError> for DebuggerMappedImageError {
    fn from(error: ExactImageError) -> Self {
        if error == ExactImageError::MappedImageMismatch {
            Self::Mismatch
        } else {
            Self::IdentityUnavailable
        }
    }
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
pub(super) struct PreflightDebuggerArtifact {
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
pub(super) fn preflight_debugger_artifact(
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

/// Opaque same-handle debugger artifact prepared for its sole sibling launch.
///
/// The verified file remains pinned without write/delete sharing. Whole-release,
/// manifest, and complete `FILE_ID_INFO` identities remain separate and private.
/// No process or debug authority can be obtained from this type.
#[cfg(windows)]
#[must_use = "dropping prepared debugger admission closes its pinned file"]
pub(super) struct PreparedReleaseDebuggerArtifact {
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

#[cfg(windows)]
impl PreparedReleaseDebuggerArtifact {
    /// Borrows only the already-verified absolute application path.
    pub(super) fn path(&self) -> &Path {
        self.artifact.path()
    }

    /// Reports whether a live caller-owned slot differs from the held artifact
    /// slot without exposing either raw value.
    pub(super) fn is_raw_slot_distinct(&self, other: BorrowedHandle<'_>) -> bool {
        self.artifact.raw_handle() != HANDLE(other.as_raw_handle())
    }
}

/// Linear proof that the first mapped image matched the held release artifact.
#[cfg(windows)]
#[must_use = "dropping mapped debugger admission closes its pinned file"]
pub(super) struct MappedReleaseDebuggerArtifact {
    prepared: PreparedReleaseDebuggerArtifact,
}

#[cfg(windows)]
impl fmt::Debug for MappedReleaseDebuggerArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("MappedReleaseDebuggerArtifact([HELD AUTHENTICATED DEBUGGER IMAGE/RELEASE])")
    }
}

/// Consumes prepared admission only after a caller-owned mapped-image handle
/// proves complete `FILE_ID_INFO` equality with the already-held artifact.
#[cfg(windows)]
pub(super) fn authenticate_release_debugger_mapped_image(
    prepared: PreparedReleaseDebuggerArtifact,
    mapped_image: BorrowedHandle<'_>,
) -> Result<MappedReleaseDebuggerArtifact, DebuggerMappedImageError> {
    authenticate_exact_mapped_image(&prepared.identity, HANDLE(mapped_image.as_raw_handle()))?;
    Ok(MappedReleaseDebuggerArtifact { prepared })
}

/// Derives complete file identity from the same already-held debugger handle.
///
/// This performs no reopen, canonicalization, path lookup, process creation, or
/// debug operation. Ownership moves only after the identity query succeeds.
#[cfg(windows)]
pub(super) fn prepare_release_debugger_artifact(
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
    #[cfg(windows)]
    use std::os::windows::io::AsHandle as _;
    use std::path::PathBuf;

    use super::{DebuggerArtifactError, preflight_debugger_artifact};
    #[cfg(windows)]
    use super::{
        DebuggerMappedImageError, authenticate_release_debugger_mapped_image,
        prepare_release_debugger_artifact,
    };
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

    #[cfg(windows)]
    #[test]
    fn exact_mapped_file_identity_mints_only_retained_redacted_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = absolute_path()?;
        let debugger = artifact(path.clone(), DEBUGGER_MANIFEST, true)?;
        let admitted = preflight_debugger_artifact(attestation(DEBUGGER_MANIFEST), debugger)?;
        let prepared = prepare_release_debugger_artifact(admitted)?;
        let mapped_file = std::fs::File::open(path)?;
        assert!(prepared.is_raw_slot_distinct(mapped_file.as_handle()));
        let mapped = authenticate_release_debugger_mapped_image(prepared, mapped_file.as_handle())?;
        assert_eq!(
            mapped.prepared.artifact.manifest_digest(),
            DEBUGGER_MANIFEST
        );
        assert!(mapped.prepared.release_identity.matches(&[0x50; 32]));
        assert_ne!(mapped.prepared.identity.encode_be(), [0; 24]);
        assert_eq!(
            format!("{mapped:?}"),
            "MappedReleaseDebuggerArtifact([HELD AUTHENTICATED DEBUGGER IMAGE/RELEASE])"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn distinct_mapped_file_identity_is_rejected_before_capability_mint()
    -> Result<(), Box<dyn std::error::Error>> {
        let debugger = artifact(absolute_path()?, DEBUGGER_MANIFEST, true)?;
        let admitted = preflight_debugger_artifact(attestation(DEBUGGER_MANIFEST), debugger)?;
        let prepared = prepare_release_debugger_artifact(admitted)?;
        let distinct =
            std::fs::File::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))?;
        assert!(matches!(
            authenticate_release_debugger_mapped_image(prepared, distinct.as_handle()),
            Err(DebuggerMappedImageError::Mismatch)
        ));
        Ok(())
    }
}
