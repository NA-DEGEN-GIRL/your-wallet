//! Release gating for operating-system boundary evidence.
//!
//! This is a typed gate, not a test runner. The release pipeline must generate
//! evidence digests from tests performed against the exact artifact digest passed
//! to `ReleaseAttestation::evaluate`.

use thiserror::Error;

const REQUIRED_HELPER_MANIFESTS: usize = 3;

// A release build must replace `None` through a reviewed, reproducible generated
// source step whose output is covered by the final code signature. Keeping this
// absent makes it impossible for ordinary runtime callers to construct a true
// attestation merely by supplying arbitrary non-zero digests.
const COMPILED_RELEASE_POLICY: Option<ReleasePolicy> = None;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReleasePolicy {
    artifact: ArtifactDigest,
    appcontainer_suite_digest: [u8; 32],
    helper_suite_digest: [u8; 32],
    handle_suite_digest: [u8; 32],
    // Key Agent, approval UI, and secret-input UI. This is an artifact allowlist,
    // not launch-role authority: the public generic helper launcher separately
    // rejects the Key Agent, whose private supervisor seam owns its activation.
    helper_manifest_digests: [[u8; 32]; REQUIRED_HELPER_MANIFESTS],
}

/// A non-zero digest that identifies an exact release artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactDigest([u8; 32]);

impl ArtifactDigest {
    /// Constructs a release artifact identity.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::ZeroDigest`] for the reserved all-zero value.
    pub fn new(value: [u8; 32]) -> Result<Self, AttestationError> {
        if value == [0; 32] {
            return Err(AttestationError::ZeroDigest);
        }
        Ok(Self(value))
    }
}

/// Evidence from one release-bound boundary test suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestEvidence {
    artifact: ArtifactDigest,
    suite_digest: [u8; 32],
}

impl TestEvidence {
    /// Binds an independently produced test-result digest to an artifact.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::ZeroDigest`] for an all-zero suite digest.
    pub fn new(artifact: ArtifactDigest, suite_digest: [u8; 32]) -> Result<Self, AttestationError> {
        if suite_digest == [0; 32] {
            return Err(AttestationError::ZeroDigest);
        }
        Ok(Self {
            artifact,
            suite_digest,
        })
    }

    fn matches_artifact(self, artifact: ArtifactDigest) -> bool {
        self.artifact.0 == artifact.0 && self.suite_digest != [0; 32]
    }
}

/// Invalid release-evidence input.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AttestationError {
    /// Artifact and test-suite digests must not be the all-zero sentinel.
    #[error("release evidence digest must be non-zero")]
    ZeroDigest,
}

/// Independently collected evidence required by the Windows release gate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReleaseEvidence {
    appcontainer_network_denial: Option<TestEvidence>,
    helper_verification: Option<TestEvidence>,
    handle_leak_tests: Option<TestEvidence>,
}

impl ReleaseEvidence {
    /// Records no-network AppContainer/LPAC negative-test evidence.
    #[must_use]
    pub const fn with_appcontainer_network_denial(mut self, evidence: TestEvidence) -> Self {
        self.appcontainer_network_denial = Some(evidence);
        self
    }

    /// Records helper path/hash/version/AuthentiCode identity evidence.
    #[must_use]
    pub const fn with_helper_verification(mut self, evidence: TestEvidence) -> Self {
        self.helper_verification = Some(evidence);
        self
    }

    /// Records a child-process inherited-handle leak test.
    #[must_use]
    pub const fn with_handle_leak_tests(mut self, evidence: TestEvidence) -> Self {
        self.handle_leak_tests = Some(evidence);
        self
    }
}

/// A fail-closed signing-release attestation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReleaseAttestation {
    signing_enabled: bool,
    allowed_helper_manifest_digests: Option<[[u8; 32]; REQUIRED_HELPER_MANIFESTS]>,
}

impl ReleaseAttestation {
    /// Evaluates all evidence against the immutable policy compiled into the
    /// signed release artifact.
    ///
    /// Development builds deliberately contain no release policy, so this method
    /// always returns a disabled attestation regardless of caller-supplied values.
    #[must_use]
    pub fn evaluate(artifact: ArtifactDigest, evidence: ReleaseEvidence) -> Self {
        let Some(policy) = COMPILED_RELEASE_POLICY else {
            return Self::default();
        };
        Self::evaluate_against_policy(policy, artifact, evidence)
    }

    fn evaluate_against_policy(
        policy: ReleasePolicy,
        artifact: ArtifactDigest,
        evidence: ReleaseEvidence,
    ) -> Self {
        let signing_enabled = match (
            evidence.appcontainer_network_denial,
            evidence.helper_verification,
            evidence.handle_leak_tests,
        ) {
            (Some(appcontainer), Some(helper), Some(handles)) => {
                artifact == policy.artifact
                    && appcontainer.matches_artifact(artifact)
                    && appcontainer.suite_digest == policy.appcontainer_suite_digest
                    && helper.matches_artifact(artifact)
                    && helper.suite_digest == policy.helper_suite_digest
                    && handles.matches_artifact(artifact)
                    && handles.suite_digest == policy.handle_suite_digest
                    && valid_helper_manifest_allowlist(&policy.helper_manifest_digests)
            }
            _ => false,
        };
        let allowed_helper_manifest_digests =
            signing_enabled.then_some(policy.helper_manifest_digests);
        Self {
            signing_enabled,
            allowed_helper_manifest_digests,
        }
    }

    /// Returns true only when every stop-ship boundary suite has evidence for the
    /// same exact artifact.
    #[must_use]
    pub const fn signing_enabled(self) -> bool {
        self.signing_enabled
    }

    /// Returns whether this successful attestation retained the exact helper
    /// manifest digest compiled into the signed release policy.
    pub(crate) fn allows_helper_manifest(self, digest: [u8; 32]) -> bool {
        self.signing_enabled
            && self
                .allowed_helper_manifest_digests
                .is_some_and(|allowed| allowed.contains(&digest))
    }

    #[cfg(test)]
    pub(crate) const fn with_helper_manifests_for_test(
        digests: [[u8; 32]; REQUIRED_HELPER_MANIFESTS],
    ) -> Self {
        Self {
            signing_enabled: true,
            allowed_helper_manifest_digests: Some(digests),
        }
    }
}

fn valid_helper_manifest_allowlist(digests: &[[u8; 32]; REQUIRED_HELPER_MANIFESTS]) -> bool {
    digests
        .iter()
        .enumerate()
        .all(|(index, digest)| *digest != [0; 32] && !digests[..index].contains(digest))
}

#[cfg(test)]
mod tests {
    use super::{ArtifactDigest, ReleaseAttestation, ReleaseEvidence, ReleasePolicy, TestEvidence};

    fn artifact(byte: u8) -> Result<ArtifactDigest, Box<dyn std::error::Error>> {
        Ok(ArtifactDigest::new([byte; 32])?)
    }

    fn evidence(
        artifact: ArtifactDigest,
        byte: u8,
    ) -> Result<TestEvidence, Box<dyn std::error::Error>> {
        Ok(TestEvidence::new(artifact, [byte; 32])?)
    }

    #[test]
    fn gate_is_false_without_every_piece_of_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let incomplete = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, 2)?)
            .with_helper_verification(evidence(release, 3)?);
        assert!(!ReleaseAttestation::evaluate(release, incomplete).signing_enabled());
        assert!(!ReleaseAttestation::default().signing_enabled());
        Ok(())
    }

    #[test]
    fn evidence_for_another_artifact_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let other = artifact(9)?;
        let policy = ReleasePolicy {
            artifact: release,
            appcontainer_suite_digest: [2; 32],
            helper_suite_digest: [3; 32],
            handle_suite_digest: [4; 32],
            helper_manifest_digests: [[5; 32], [6; 32], [7; 32]],
        };
        let mismatched = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, 2)?)
            .with_helper_verification(evidence(other, 3)?)
            .with_handle_leak_tests(evidence(release, 4)?);
        assert!(
            !ReleaseAttestation::evaluate_against_policy(policy, release, mismatched)
                .signing_enabled()
        );
        Ok(())
    }

    #[test]
    fn gate_is_true_only_with_all_bound_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let complete = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, 2)?)
            .with_helper_verification(evidence(release, 3)?)
            .with_handle_leak_tests(evidence(release, 4)?);
        let policy = ReleasePolicy {
            artifact: release,
            appcontainer_suite_digest: [2; 32],
            helper_suite_digest: [3; 32],
            handle_suite_digest: [4; 32],
            helper_manifest_digests: [[5; 32], [6; 32], [7; 32]],
        };
        let attestation = ReleaseAttestation::evaluate_against_policy(policy, release, complete);
        assert!(attestation.signing_enabled());
        assert!(attestation.allows_helper_manifest([5; 32]));
        assert!(attestation.allows_helper_manifest([6; 32]));
        assert!(attestation.allows_helper_manifest([7; 32]));
        assert!(!attestation.allows_helper_manifest([8; 32]));
        assert!(
            !ReleaseAttestation::evaluate(release, complete).signing_enabled(),
            "development builds have no compiled release policy"
        );
        Ok(())
    }

    #[test]
    fn helper_manifest_allowlist_is_retained_only_after_exact_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let complete = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, 2)?)
            .with_helper_verification(evidence(release, 3)?)
            .with_handle_leak_tests(evidence(release, 4)?);
        let base = ReleasePolicy {
            artifact: release,
            appcontainer_suite_digest: [2; 32],
            helper_suite_digest: [3; 32],
            handle_suite_digest: [4; 32],
            helper_manifest_digests: [[5; 32], [6; 32], [7; 32]],
        };

        let wrong_suite = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, 2)?)
            .with_helper_verification(evidence(release, 9)?)
            .with_handle_leak_tests(evidence(release, 4)?);
        let disabled = ReleaseAttestation::evaluate_against_policy(base, release, wrong_suite);
        assert!(!disabled.signing_enabled());
        assert!(!disabled.allows_helper_manifest([5; 32]));

        for invalid_allowlist in [[[0; 32], [6; 32], [7; 32]], [[5; 32], [5; 32], [7; 32]]] {
            let invalid_policy = ReleasePolicy {
                helper_manifest_digests: invalid_allowlist,
                ..base
            };
            let disabled =
                ReleaseAttestation::evaluate_against_policy(invalid_policy, release, complete);
            assert!(!disabled.signing_enabled());
            assert!(!disabled.allows_helper_manifest([5; 32]));
        }
        Ok(())
    }
}
