//! Release gating for operating-system boundary evidence.
//!
//! This is a typed gate, not a test runner. The release pipeline must generate
//! evidence digests from tests performed against the exact artifact digest passed
//! to `ReleaseAttestation::evaluate`.

use subtle::ConstantTimeEq as _;
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
    broker_transport_suite_digest: [u8; 32],
    // Key Agent, approval UI, and secret-input UI. This is an artifact allowlist,
    // not launch-role authority: the crate-private generic helper launcher
    // separately rejects the Key Agent, whose private supervisor seam owns its
    // activation.
    helper_manifest_digests: [[u8; 32]; REQUIRED_HELPER_MANIFESTS],
    // Broker is deliberately separate from the three signing-TCB helpers. Its
    // manifest may authorize only the private Broker admission boundary.
    broker_manifest_digest: [u8; 32],
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

    #[cfg(test)]
    pub(crate) fn for_test(value: [u8; 32]) -> Self {
        assert!(
            value != [0; 32],
            "test release artifact digest must be nonzero"
        );
        Self(value)
    }
}

/// Opaque proof that the compiled release policy accepted one exact artifact.
///
/// Unlike [`ArtifactDigest`], ordinary callers cannot construct this type. It
/// is retained only by a successful [`ReleaseAttestation`] so later internal
/// boundaries can bind durable installation evidence to the same release
/// cohort without accepting a caller-supplied digest as authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AttestedArtifactDigest(ArtifactDigest);

impl AttestedArtifactDigest {
    /// Compares an authenticated release identity with durable opaque bytes.
    pub(crate) fn matches(self, expected: &[u8; 32]) -> bool {
        self.0.0.ct_eq(expected).into()
    }
}

impl core::fmt::Debug for AttestedArtifactDigest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AttestedArtifactDigest([REDACTED])")
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
    broker_transport: Option<TestEvidence>,
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

    /// Records exact native-host/Broker transport and process-binding evidence.
    #[must_use]
    pub const fn with_broker_transport(mut self, evidence: TestEvidence) -> Self {
        self.broker_transport = Some(evidence);
        self
    }
}

/// A fail-closed signing-release attestation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReleaseAttestation {
    attested_artifact: Option<AttestedArtifactDigest>,
    allowed_helper_manifest_digests: Option<[[u8; 32]; REQUIRED_HELPER_MANIFESTS]>,
    allowed_broker_manifest_digest: Option<[u8; 32]>,
}

impl ReleaseAttestation {
    /// Evaluates all evidence against the immutable policy compiled into the
    /// signed release artifact.
    ///
    /// Development builds deliberately contain no release policy, so this method
    /// always returns a disabled attestation regardless of caller-supplied values.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "preserve the established public release-evidence API"
    )]
    #[must_use]
    pub fn evaluate(artifact: ArtifactDigest, evidence: ReleaseEvidence) -> Self {
        let Some(policy) = COMPILED_RELEASE_POLICY else {
            return Self::default();
        };
        Self::evaluate_against_policy(&policy, artifact, &evidence)
    }

    fn evaluate_against_policy(
        policy: &ReleasePolicy,
        artifact: ArtifactDigest,
        evidence: &ReleaseEvidence,
    ) -> Self {
        let signing_enabled = match (
            evidence.appcontainer_network_denial,
            evidence.helper_verification,
            evidence.handle_leak_tests,
            evidence.broker_transport,
        ) {
            (Some(appcontainer), Some(helper), Some(handles), Some(broker_transport)) => {
                artifact == policy.artifact
                    && appcontainer.matches_artifact(artifact)
                    && appcontainer.suite_digest == policy.appcontainer_suite_digest
                    && helper.matches_artifact(artifact)
                    && helper.suite_digest == policy.helper_suite_digest
                    && handles.matches_artifact(artifact)
                    && handles.suite_digest == policy.handle_suite_digest
                    && broker_transport.matches_artifact(artifact)
                    && broker_transport.suite_digest == policy.broker_transport_suite_digest
                    && valid_helper_manifest_allowlist(&policy.helper_manifest_digests)
                    && valid_broker_manifest(
                        policy.broker_manifest_digest,
                        &policy.helper_manifest_digests,
                    )
            }
            _ => false,
        };
        let allowed_helper_manifest_digests =
            signing_enabled.then_some(policy.helper_manifest_digests);
        let allowed_broker_manifest_digest =
            signing_enabled.then_some(policy.broker_manifest_digest);
        Self {
            attested_artifact: signing_enabled.then_some(AttestedArtifactDigest(artifact)),
            allowed_helper_manifest_digests,
            allowed_broker_manifest_digest,
        }
    }

    /// Returns true only when every stop-ship boundary suite has evidence for the
    /// same exact artifact.
    #[must_use]
    pub const fn signing_enabled(self) -> bool {
        self.attested_artifact.is_some()
    }

    /// Returns the exact release identity only after complete compiled evidence
    /// accepted it. The returned type is opaque and cannot be forged from raw
    /// bytes by sibling modules.
    pub(crate) const fn attested_artifact(self) -> Option<AttestedArtifactDigest> {
        self.attested_artifact
    }

    /// Returns whether this successful attestation retained the exact helper
    /// manifest digest compiled into the signed release policy.
    pub(crate) fn allows_helper_manifest(self, digest: [u8; 32]) -> bool {
        self.attested_artifact.is_some()
            && self
                .allowed_helper_manifest_digests
                .is_some_and(|allowed| allowed.contains(&digest))
    }

    /// Returns whether this successful attestation retained the one exact
    /// Broker manifest digest compiled into the signed release policy.
    pub(crate) fn allows_broker_manifest(self, digest: [u8; 32]) -> bool {
        self.attested_artifact.is_some() && self.allowed_broker_manifest_digest == Some(digest)
    }

    #[cfg(test)]
    pub(crate) const fn with_helper_manifests_for_test(
        artifact: ArtifactDigest,
        digests: [[u8; 32]; REQUIRED_HELPER_MANIFESTS],
    ) -> Self {
        Self {
            attested_artifact: Some(AttestedArtifactDigest(artifact)),
            allowed_helper_manifest_digests: Some(digests),
            allowed_broker_manifest_digest: None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_broker_manifest_for_test(
        artifact: ArtifactDigest,
        digest: [u8; 32],
    ) -> Self {
        Self {
            attested_artifact: Some(AttestedArtifactDigest(artifact)),
            allowed_helper_manifest_digests: None,
            allowed_broker_manifest_digest: Some(digest),
        }
    }
}

fn valid_helper_manifest_allowlist(digests: &[[u8; 32]; REQUIRED_HELPER_MANIFESTS]) -> bool {
    digests
        .iter()
        .enumerate()
        .all(|(index, digest)| *digest != [0; 32] && !digests[..index].contains(digest))
}

fn valid_broker_manifest(
    broker: [u8; 32],
    helpers: &[[u8; 32]; REQUIRED_HELPER_MANIFESTS],
) -> bool {
    broker != [0; 32] && !helpers.contains(&broker)
}

#[cfg(test)]
mod tests {
    use super::{ArtifactDigest, ReleaseAttestation, ReleaseEvidence, ReleasePolicy, TestEvidence};

    const APP_CONTAINER_SUITE: u8 = 2;
    const HELPER_SUITE: u8 = 3;
    const HANDLE_SUITE: u8 = 4;
    const BROKER_TRANSPORT_SUITE: u8 = 5;
    const HELPER_MANIFESTS: [[u8; 32]; 3] = [[6; 32], [7; 32], [8; 32]];
    const BROKER_MANIFEST: [u8; 32] = [9; 32];

    fn artifact(byte: u8) -> Result<ArtifactDigest, Box<dyn std::error::Error>> {
        Ok(ArtifactDigest::new([byte; 32])?)
    }

    fn evidence(
        artifact: ArtifactDigest,
        byte: u8,
    ) -> Result<TestEvidence, Box<dyn std::error::Error>> {
        Ok(TestEvidence::new(artifact, [byte; 32])?)
    }

    fn policy(artifact: ArtifactDigest) -> ReleasePolicy {
        ReleasePolicy {
            artifact,
            appcontainer_suite_digest: [APP_CONTAINER_SUITE; 32],
            helper_suite_digest: [HELPER_SUITE; 32],
            handle_suite_digest: [HANDLE_SUITE; 32],
            broker_transport_suite_digest: [BROKER_TRANSPORT_SUITE; 32],
            helper_manifest_digests: HELPER_MANIFESTS,
            broker_manifest_digest: BROKER_MANIFEST,
        }
    }

    fn complete_evidence(
        artifact: ArtifactDigest,
    ) -> Result<ReleaseEvidence, Box<dyn std::error::Error>> {
        Ok(ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(artifact, APP_CONTAINER_SUITE)?)
            .with_helper_verification(evidence(artifact, HELPER_SUITE)?)
            .with_handle_leak_tests(evidence(artifact, HANDLE_SUITE)?)
            .with_broker_transport(evidence(artifact, BROKER_TRANSPORT_SUITE)?))
    }

    #[test]
    fn gate_is_false_without_every_piece_of_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let incomplete = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, APP_CONTAINER_SUITE)?)
            .with_helper_verification(evidence(release, HELPER_SUITE)?)
            .with_handle_leak_tests(evidence(release, HANDLE_SUITE)?);
        let disabled = ReleaseAttestation::evaluate(release, incomplete);
        assert!(!disabled.signing_enabled());
        assert!(disabled.attested_artifact().is_none());
        assert!(!ReleaseAttestation::default().signing_enabled());
        assert!(ReleaseAttestation::default().attested_artifact().is_none());
        assert!(!ReleaseAttestation::default().allows_broker_manifest(BROKER_MANIFEST));
        Ok(())
    }

    #[test]
    fn evidence_for_another_artifact_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let other = artifact(10)?;
        let mismatched = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, APP_CONTAINER_SUITE)?)
            .with_helper_verification(evidence(release, HELPER_SUITE)?)
            .with_handle_leak_tests(evidence(release, HANDLE_SUITE)?)
            .with_broker_transport(evidence(other, BROKER_TRANSPORT_SUITE)?);
        assert!(
            !ReleaseAttestation::evaluate_against_policy(&policy(release), release, &mismatched)
                .signing_enabled()
        );
        Ok(())
    }

    #[test]
    fn gate_is_true_only_with_all_bound_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let complete = complete_evidence(release)?;
        let attestation =
            ReleaseAttestation::evaluate_against_policy(&policy(release), release, &complete);
        assert!(attestation.signing_enabled());
        assert!(
            attestation
                .attested_artifact()
                .is_some_and(|identity| identity.matches(&[1; 32]))
        );
        assert!(attestation.allows_helper_manifest([6; 32]));
        assert!(attestation.allows_helper_manifest([7; 32]));
        assert!(attestation.allows_helper_manifest([8; 32]));
        assert!(!attestation.allows_helper_manifest(BROKER_MANIFEST));
        assert!(attestation.allows_broker_manifest(BROKER_MANIFEST));
        assert!(!attestation.allows_broker_manifest(HELPER_MANIFESTS[0]));
        assert!(
            !ReleaseAttestation::evaluate(release, complete).signing_enabled(),
            "development builds have no compiled release policy"
        );
        assert!(
            ReleaseAttestation::evaluate(release, complete)
                .attested_artifact()
                .is_none()
        );
        assert!(
            !ReleaseAttestation::evaluate(release, complete)
                .allows_broker_manifest(BROKER_MANIFEST)
        );
        Ok(())
    }

    #[test]
    fn helper_manifest_allowlist_is_retained_only_after_exact_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let complete = complete_evidence(release)?;
        let base = policy(release);

        let wrong_suite = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, APP_CONTAINER_SUITE)?)
            .with_helper_verification(evidence(release, 10)?)
            .with_handle_leak_tests(evidence(release, HANDLE_SUITE)?)
            .with_broker_transport(evidence(release, BROKER_TRANSPORT_SUITE)?);
        let disabled = ReleaseAttestation::evaluate_against_policy(&base, release, &wrong_suite);
        assert!(!disabled.signing_enabled());
        assert!(!disabled.allows_helper_manifest(HELPER_MANIFESTS[0]));

        for invalid_allowlist in [[[0; 32], [7; 32], [8; 32]], [[6; 32], [6; 32], [8; 32]]] {
            let invalid_policy = ReleasePolicy {
                helper_manifest_digests: invalid_allowlist,
                ..base
            };
            let disabled =
                ReleaseAttestation::evaluate_against_policy(&invalid_policy, release, &complete);
            assert!(!disabled.signing_enabled());
            assert!(!disabled.allows_helper_manifest(HELPER_MANIFESTS[0]));
        }
        Ok(())
    }

    #[test]
    fn broker_manifest_is_separate_and_retained_only_after_exact_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let release = artifact(1)?;
        let complete = complete_evidence(release)?;
        let base = policy(release);

        let wrong_broker_suite = ReleaseEvidence::default()
            .with_appcontainer_network_denial(evidence(release, APP_CONTAINER_SUITE)?)
            .with_helper_verification(evidence(release, HELPER_SUITE)?)
            .with_handle_leak_tests(evidence(release, HANDLE_SUITE)?)
            .with_broker_transport(evidence(release, 10)?);
        let disabled =
            ReleaseAttestation::evaluate_against_policy(&base, release, &wrong_broker_suite);
        assert!(!disabled.signing_enabled());
        assert!(!disabled.allows_broker_manifest(BROKER_MANIFEST));

        for invalid_broker_manifest in [[0; 32], HELPER_MANIFESTS[0]] {
            let invalid_policy = ReleasePolicy {
                broker_manifest_digest: invalid_broker_manifest,
                ..base
            };
            let disabled =
                ReleaseAttestation::evaluate_against_policy(&invalid_policy, release, &complete);
            assert!(!disabled.signing_enabled());
            assert!(!disabled.allows_broker_manifest(invalid_broker_manifest));
        }
        Ok(())
    }
}
