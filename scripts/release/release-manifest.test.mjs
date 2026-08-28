import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  ELIGIBILITY_CLAIM,
  MANIFEST_SCHEMA,
  RELEASE_PROFILE,
  REQUIRED_ARTIFACT_PATHS,
  REQUIRED_ARTIFACT_ROLES,
  REQUIRED_EVIDENCE_PATHS,
  REVIEW_EVIDENCE_EXCLUDED_KEYS,
  REQUIRED_REVIEW_SCOPE,
  REQUIRED_WINDOWS_NEGATIVE_TESTS,
  canonicalEncode,
  computeArtifactSetSha256,
  computeManifestReviewedEvidenceSetSha256,
  computeReviewedEvidenceSetSha256,
  parseStrictJson,
  sha256Hex,
  validateIndependentReviewAttestation,
  validateManifest,
  verifyExpectedExtensionId,
  verifyExpectedReleaseKeyId,
  verifyExpectedReleaseSequence,
  verifyExpectedPreviousManifestSha256,
  verifyExpectedReviewerKeyId,
  verifyExpectedSignerCertificateSha256,
} from "./release-manifest.mjs";

const RELEASE_MANIFEST_CLI = fileURLToPath(new URL("./release-manifest.mjs", import.meta.url));

function digest(label) {
  return sha256Hex(Buffer.from(label, "utf8"));
}

function fileRecord(relativePath) {
  return { bytes: "123", path: relativePath, sha256: digest(relativePath) };
}

function initialManifest() {
  const authEvidence = fileRecord("evidence/authenticode.json");
  const signer = digest("authenticode-signer-spki");
  const artifacts = REQUIRED_ARTIFACT_ROLES.map((role) => {
    const extension = role === "extension-package";
    return {
      authenticode: extension
        ? { evidenceSha256: null, signerCertificateSha256: null, status: "not-applicable" }
        : { evidenceSha256: authEvidence.sha256, signerCertificateSha256: signer, status: "valid" },
      file: fileRecord(REQUIRED_ARTIFACT_PATHS[role]),
      role,
    };
  });
  const evidence = {
    authenticodeReport: authEvidence,
    cargo: fileRecord("evidence/cargo-vv.txt"),
    cargoLock: fileRecord("evidence/Cargo.lock"),
    dependencyInventory: fileRecord("evidence/dependencies.json"),
    extensionAudit: fileRecord("evidence/extension-audit.json"),
    installerAclNegative: fileRecord("evidence/installer-acl-negative.json"),
    keyRevocationDrill: fileRecord("evidence/key-revocation-drill.json"),
    keyRotationDrill: fileRecord("evidence/key-rotation-drill.json"),
    licenseInventory: fileRecord("evidence/licenses.json"),
    nativeHostManifest: fileRecord("evidence/native-host-manifest.json"),
    nativeHostRegistration: fileRecord("evidence/native-host-registration.json"),
    osvAdvisoryReport: fileRecord("evidence/osv-advisory.json"),
    osvRawReport: fileRecord("evidence/osv-raw.json"),
    reproducibilityReport: fileRecord("evidence/reproducibility.json"),
    reviewAttestation: fileRecord("evidence/review-attestation.json"),
    reviewPublicKey: fileRecord("evidence/review-public-key.pem"),
    reviewSignature: fileRecord("evidence/review-attestation.sig"),
    rustSecAdvisoryReport: fileRecord("evidence/rustsec-advisory.json"),
    rustSecRawReport: fileRecord("evidence/rustsec-raw.json"),
    rustToolchain: fileRecord("evidence/rust-toolchain.toml"),
    rustc: fileRecord("evidence/rustc-vv.txt"),
    sbomSpdx: fileRecord("evidence/sbom.spdx.json"),
    sourceArchive: fileRecord("evidence/source.zip"),
    vendorInventory: fileRecord("evidence/vendor-inventory.json"),
  };
  const artifactSetSha256 = computeArtifactSetSha256(artifacts);
  const commit = "1".repeat(40);
  return {
    advisoryPolicy: {
      osv: {
        databaseSnapshotId: "2026-08-13T00:00:00Z",
        databaseSnapshotSha256: digest("osv-database"),
        scanner: "osv-scanner",
        scannerBinarySha256: digest("osv-scanner-binary"),
        scannerVersion: "2.0.0",
      },
      rustSec: {
        databaseCommit: "3".repeat(40),
        databaseTreeSha256: digest("rustsec-database"),
        scanner: "cargo-audit",
        scannerBinarySha256: digest("cargo-audit-binary"),
        scannerVersion: "0.21.0",
      },
    },
    artifactSetSha256,
    artifacts,
    assurances: {
      extensionPermissionAudit: "pass",
      extensionRemoteCodeAudit: "pass",
      independentReview: "pass",
      installerAclNegativeTest: "pass",
      lockedBuild: "pass",
      nativeHostRegistration: "pass",
      offlineBuild: "pass",
      openCritical: "0",
      openHigh: "0",
      osvAdvisoryAudit: "pass",
      revocationDrill: "pass",
      rotationDrill: "pass",
      rustSecAdvisoryAudit: "pass",
      twoCleanDirectoryReproducibility: "pass",
      unsignedArtifactSetSha256: digest("unsigned-artifact-set"),
    },
    eligibilityClaim: ELIGIBILITY_CLAIM,
    evidence,
    extension: {
      id: "a".repeat(32),
      manifestSha256: digest("extension-manifest"),
      nativeHostName: "com.your_wallet.native",
      packageSha256: artifacts.find((artifact) => artifact.role === "extension-package").file.sha256,
    },
    lineage: { previousManifestSha256: null, previousSequence: null, previousVersion: null },
    profile: RELEASE_PROFILE,
    schema: MANIFEST_SCHEMA,
    sequence: "1",
    signing: { algorithm: "Ed25519", keyIdSha256: digest("release-public-key") },
    source: {
      cargoLockSha256: evidence.cargoLock.sha256,
      commit,
      dirty: "no",
      rustToolchainSha256: evidence.rustToolchain.sha256,
      treeSha256: evidence.sourceArchive.sha256,
      vendorTreeSha256: evidence.vendorInventory.sha256,
    },
    toolchain: {
      cargoEvidenceSha256: evidence.cargo.sha256,
      rustcEvidenceSha256: evidence.rustc.sha256,
      target: "x86_64-pc-windows-msvc",
      windowsRunnerImage: "windows-2025",
    },
    version: "0.1.0",
    windowsNegativeTests: REQUIRED_WINDOWS_NEGATIVE_TESTS.map((id) => ({
      artifactSetSha256,
      id,
      log: fileRecord(`evidence/windows-negative/${id}.json`),
      result: "pass",
      sourceCommit: commit,
    })),
  };
}

function successor(previous, version = "0.1.1") {
  const current = structuredClone(previous);
  current.sequence = (BigInt(previous.sequence) + 1n).toString();
  current.version = version;
  current.lineage = {
    previousManifestSha256: digest("placeholder"),
    previousSequence: previous.sequence,
    previousVersion: previous.version,
  };
  current.lineage.previousManifestSha256 = sha256Hex(Buffer.from(canonicalEncode(previous), "utf8"));
  return current;
}

function verifyCliArguments(expectedReleaseSequence = "1") {
  return [
    "verify",
    "--manifest", "unread-manifest.json",
    "--signature", "unread-signature.sig",
    "--public-key", "unread-public-key.pem",
    "--bundle-root", "unread-bundle",
    "--expected-release-key-id", "1".repeat(64),
    "--expected-extension-id", "a".repeat(32),
    "--expected-release-sequence", expectedReleaseSequence,
    "--expected-reviewer-key-id", "2".repeat(64),
    "--expected-signer-certificate-sha256", "3".repeat(64),
  ];
}

function runReleaseManifestCli(argumentsList) {
  return spawnSync(process.execPath, [RELEASE_MANIFEST_CLI, ...argumentsList], {
    encoding: "utf8",
    windowsHide: true,
  });
}

function assertPreReadCliFailure(argumentsList, expectedMessage) {
  const result = runReleaseManifestCli(argumentsList);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, `RELEASE_INELIGIBLE: ${expectedMessage}\n`);
  assert.doesNotMatch(result.stderr, /unread-(?:manifest|signature|public-key|bundle)/u);
  assert.doesNotMatch(result.stderr, /unexpected release verifier failure/u);
}

test("canonical encoding is independent of object insertion order", () => {
  const left = parseStrictJson('{"z":"last","a":{"y":"2","x":"1"},"m":[true,null,"v"]}');
  const right = parseStrictJson('{"m":[true,null,"v"],"a":{"x":"1","y":"2"},"z":"last"}');
  assert.equal(canonicalEncode(left), canonicalEncode(right));
  assert.equal(canonicalEncode(left), '{"a":{"x":"1","y":"2"},"m":[true,null,"v"],"z":"last"}');
});

test("independent review evidence commitment is exact, canonical, and non-circular", () => {
  const manifest = initialManifest();
  const baseline = computeManifestReviewedEvidenceSetSha256(
    manifest.evidence,
    manifest.windowsNegativeTests,
  );
  assert.match(baseline, /^[0-9a-f]{64}$/u);

  const reviewedRecords = Object.entries(manifest.evidence)
    .filter(([key]) => !REVIEW_EVIDENCE_EXCLUDED_KEYS.includes(key))
    .map(([, record]) => record);
  reviewedRecords.push(...manifest.windowsNegativeTests.map((item) => item.log));
  const duplicate = [...reviewedRecords];
  duplicate[1] = duplicate[0];
  assert.throws(
    () => computeReviewedEvidenceSetSha256(duplicate),
    /duplicate Windows path/u,
  );
  assert.throws(
    () => computeReviewedEvidenceSetSha256([...reviewedRecords, reviewedRecords[0]]),
    /exact required file count/u,
  );

  const reordered = structuredClone(manifest);
  reordered.windowsNegativeTests.reverse();
  assert.equal(
    computeManifestReviewedEvidenceSetSha256(reordered.evidence, reordered.windowsNegativeTests),
    baseline,
  );

  const reviewPairChanged = structuredClone(manifest);
  reviewPairChanged.evidence.reviewAttestation = fileRecord(REQUIRED_EVIDENCE_PATHS.reviewAttestation);
  reviewPairChanged.evidence.reviewAttestation.sha256 = digest("replacement-review-attestation");
  reviewPairChanged.evidence.reviewSignature.sha256 = digest("replacement-review-signature");
  assert.equal(
    computeManifestReviewedEvidenceSetSha256(
      reviewPairChanged.evidence,
      reviewPairChanged.windowsNegativeTests,
    ),
    baseline,
  );

  const publicKeyChanged = structuredClone(manifest);
  publicKeyChanged.evidence.reviewPublicKey.sha256 = digest("replacement-review-public-key");
  assert.notEqual(
    computeManifestReviewedEvidenceSetSha256(
      publicKeyChanged.evidence,
      publicKeyChanged.windowsNegativeTests,
    ),
    baseline,
  );

  const missing = structuredClone(manifest);
  missing.windowsNegativeTests.pop();
  assert.throws(
    () => computeManifestReviewedEvidenceSetSha256(missing.evidence, missing.windowsNegativeTests),
    /exact required file count/u,
  );

  const caseAlias = structuredClone(manifest);
  caseAlias.windowsNegativeTests[0].log.path = caseAlias.windowsNegativeTests[0].log.path.toUpperCase();
  assert.throws(
    () => computeManifestReviewedEvidenceSetSha256(caseAlias.evidence, caseAlias.windowsNegativeTests),
    /must be below evidence|paths are not exact/u,
  );
});

test("independent review attestation v2 binds the reviewed evidence set", () => {
  const manifest = initialManifest();
  const validated = validateManifest(manifest);
  const attestation = {
    artifactSetSha256: manifest.artifactSetSha256,
    criticalOpen: "0",
    highOpen: "0",
    independenceAttestation: "pass",
    profile: RELEASE_PROFILE,
    reviewedEvidenceSetSha256: computeManifestReviewedEvidenceSetSha256(
      manifest.evidence,
      manifest.windowsNegativeTests,
    ),
    reviewerKeyIdSha256: digest("reviewer-public-key"),
    schema: "your-wallet-independent-security-review-v2",
    scope: REQUIRED_REVIEW_SCOPE,
    sourceCommit: manifest.source.commit,
    version: manifest.version,
  };
  assert.doesNotThrow(() => validateIndependentReviewAttestation(attestation, validated));

  const stale = structuredClone(attestation);
  stale.reviewedEvidenceSetSha256 = digest("stale-reviewed-evidence-set");
  assert.throws(
    () => validateIndependentReviewAttestation(stale, validated),
    /evidence-set commitment mismatch/u,
  );

  const versionOne = structuredClone(attestation);
  versionOne.schema = "your-wallet-independent-security-review-v1";
  delete versionOne.reviewedEvidenceSetSha256;
  assert.throws(
    () => validateIndependentReviewAttestation(versionOne, validated),
    /members must be exactly|schema must be/u,
  );
});

test("strict parser rejects duplicate members before canonicalization", () => {
  assert.throws(() => parseStrictJson('{"schema":"one","schema":"two"}'), /duplicate JSON member/u);
});

test("a complete initial candidate is structurally valid", () => {
  assert.doesNotThrow(() => validateManifest(initialManifest()));
});

test("key-agent debugger has one dedicated release artifact role and path", () => {
  assert.equal(
    REQUIRED_ARTIFACT_PATHS["key-agent-debugger-exe"],
    "payload/key-agent-debugger.exe",
  );
  assert.equal(
    REQUIRED_ARTIFACT_ROLES.filter((role) => role === "key-agent-debugger-exe").length,
    1,
  );
});

test("missing key-agent debugger artifact is rejected", () => {
  const manifest = initialManifest();
  manifest.artifacts = manifest.artifacts.filter(
    (artifact) => artifact.role !== "key-agent-debugger-exe",
  );
  manifest.artifactSetSha256 = computeArtifactSetSha256(manifest.artifacts);
  assert.throws(() => validateManifest(manifest), /artifact roles must be exactly/u);
});

test("release verification requires an independently pinned release key id", () => {
  const manifest = initialManifest();
  const validated = validateManifest(manifest);
  assert.doesNotThrow(() =>
    verifyExpectedReleaseKeyId(validated, manifest.signing.keyIdSha256),
  );
  assert.throws(
    () => verifyExpectedReleaseKeyId(validated, digest("attacker-selected-release-key")),
    /independently pinned release key identifier/u,
  );
  assert.throws(
    () => verifyExpectedReleaseKeyId(validated, "latest"),
    /independently pinned release key identifier/u,
  );
});

test("release verification requires an independently pinned stable extension id", () => {
  const manifest = initialManifest();
  const validated = validateManifest(manifest);
  assert.doesNotThrow(() =>
    verifyExpectedExtensionId(validated, manifest.extension.id),
  );
  const alternate = "b".repeat(32);
  assert.throws(
    () => verifyExpectedExtensionId(validated, alternate),
    (error) => {
      assert.match(error.message, /independently pinned extension identifier mismatch/u);
      assert.doesNotMatch(error.message, new RegExp(`${manifest.extension.id}|${alternate}`, "u"));
      return true;
    },
  );
  assert.throws(
    () => verifyExpectedExtensionId(validated, "A".repeat(32)),
    /independently pinned extension identifier has an invalid format/u,
  );
});

test("release sequence pin accepts exact initial and successor candidates", () => {
  const initial = initialManifest();
  const validatedInitial = validateManifest(initial);
  assert.doesNotThrow(() => verifyExpectedReleaseSequence(validatedInitial, "1"));

  const current = successor(initial);
  const validatedSuccessor = validateManifest(current, initial);
  assert.doesNotThrow(() => verifyExpectedReleaseSequence(validatedSuccessor, "2"));
});

test("release sequence pin rejects an old sequence-1 replay without echoing either value", () => {
  const validated = validateManifest(initialManifest());
  assert.throws(
    () => verifyExpectedReleaseSequence(validated, "2"),
    (error) => {
      assert.equal(error.message, "independently pinned release sequence mismatch");
      assert.doesNotMatch(error.message, /[12]/u);
      return true;
    },
  );
});

test("release sequence pin rejects malformed and leading-zero values", () => {
  const validated = validateManifest(initialManifest());
  for (const malformed of ["0", "01", "+1", "1.0", "1".repeat(33), "latest", "1\n", "1\r\n", "1\u2028"]) {
    assert.throws(
      () => verifyExpectedReleaseSequence(validated, malformed),
      /independently pinned release sequence has an invalid format/u,
    );
  }
});

test("verify CLI requires the external release sequence before reading candidate files", () => {
  const argumentsList = verifyCliArguments();
  const sequenceIndex = argumentsList.indexOf("--expected-release-sequence");
  argumentsList.splice(sequenceIndex, 2);
  assertPreReadCliFailure(
    argumentsList,
    "missing required argument --expected-release-sequence",
  );
});

test("verify CLI rejects extra and malformed sequence arguments before reading candidate files", () => {
  assertPreReadCliFailure(
    [...verifyCliArguments(), "--unexpected", "value"],
    "verify arguments do not match the exact initial or successor release shape",
  );
  for (const malformed of ["01", "latest"]) {
    assertPreReadCliFailure(
      verifyCliArguments(malformed),
      "independently pinned release sequence has an invalid format",
    );
  }
});

test("verify CLI derives previous-input shape from the external release sequence before file reads", () => {
  assertPreReadCliFailure(
    verifyCliArguments("2"),
    "successor verification requires --previous and --expected-previous-manifest-sha256 from the offline checkpoint",
  );
  assertPreReadCliFailure(
    [
      ...verifyCliArguments("1"),
      "--previous", "unread-previous.json",
      "--expected-previous-manifest-sha256", "4".repeat(64),
    ],
    "initial verification must not supply --previous or --expected-previous-manifest-sha256",
  );
});

test("release verification requires an independently pinned reviewer key id", () => {
  const pinned = digest("reviewer-public-key");
  assert.doesNotThrow(() => verifyExpectedReviewerKeyId(pinned, pinned));
  assert.throws(
    () => verifyExpectedReviewerKeyId(digest("bundled-reviewer-key"), pinned),
    /independently pinned reviewer key identifier/u,
  );
  assert.throws(
    () => verifyExpectedReviewerKeyId(pinned, "latest"),
    /independently pinned reviewer key identifier/u,
  );
});

test("release verification binds every Authenticode identity to the independent certificate pin", () => {
  const manifest = initialManifest();
  const validated = validateManifest(manifest);
  const pinned = manifest.artifacts.find((artifact) => artifact.role === "approval-ui-exe").authenticode.signerCertificateSha256;
  assert.doesNotThrow(() => verifyExpectedSignerCertificateSha256(validated, pinned));
  assert.throws(
    () => verifyExpectedSignerCertificateSha256(validated, digest("different-certificate")),
    /independently pinned Authenticode signer/u,
  );
});

test("non-initial verification requires the independently pinned previous manifest hash", () => {
  const previous = initialManifest();
  const current = successor(previous);
  const validated = validateManifest(current, previous);
  assert.doesNotThrow(() =>
    verifyExpectedPreviousManifestSha256(validated, current.lineage.previousManifestSha256),
  );
  assert.throws(
    () => verifyExpectedPreviousManifestSha256(validated, undefined),
    /independently pinned previous manifest hash/u,
  );
  assert.throws(
    () => verifyExpectedPreviousManifestSha256(validated, digest("unaccepted-fork")),
    /independently pinned previous manifest hash/u,
  );
});

test("missing independent-review evidence fails closed", () => {
  const manifest = initialManifest();
  delete manifest.evidence.reviewSignature;
  assert.throws(() => validateManifest(manifest), /evidence members must be exactly/u);
});

test("missing RustSec or OSV evidence fails closed", () => {
  const missingRustSec = initialManifest();
  delete missingRustSec.evidence.rustSecRawReport;
  assert.throws(() => validateManifest(missingRustSec), /evidence members must be exactly/u);
  const missingOsv = initialManifest();
  delete missingOsv.evidence.osvAdvisoryReport;
  assert.throws(() => validateManifest(missingOsv), /evidence members must be exactly/u);
});

test("floating advisory scanner versions are forbidden", () => {
  const manifest = initialManifest();
  manifest.advisoryPolicy.rustSec.scannerVersion = "latest";
  assert.throws(() => validateManifest(manifest), /scannerVersion/u);
});

test("an independent-review pass assertion cannot be omitted", () => {
  const manifest = initialManifest();
  manifest.assurances.independentReview = "pending";
  assert.throws(() => validateManifest(manifest), /independentReview must be/u);
});

test("mix-and-match Windows evidence is rejected", () => {
  const manifest = initialManifest();
  manifest.windowsNegativeTests[4].artifactSetSha256 = digest("different-artifact-set");
  assert.throws(() => validateManifest(manifest), /artifact binding/u);
});

test("missing one exact Windows negative test is rejected", () => {
  const manifest = initialManifest();
  manifest.windowsNegativeTests.pop();
  assert.throws(() => validateManifest(manifest), /exact Windows negative-test evidence set/u);
});

test("artifact substitution without a new artifact-set commitment is rejected", () => {
  const manifest = initialManifest();
  manifest.artifacts[0].file.sha256 = digest("substituted-binary");
  assert.throws(() => validateManifest(manifest), /artifactSetSha256/u);
});

test("key-agent debugger role cannot be swapped with the key-agent path", () => {
  const manifest = initialManifest();
  const debuggerArtifact = manifest.artifacts.find(
    (artifact) => artifact.role === "key-agent-debugger-exe",
  );
  const keyAgentArtifact = manifest.artifacts.find(
    (artifact) => artifact.role === "key-agent-exe",
  );
  assert.ok(debuggerArtifact);
  assert.ok(keyAgentArtifact);
  [debuggerArtifact.file.path, keyAgentArtifact.file.path] = [
    keyAgentArtifact.file.path,
    debuggerArtifact.file.path,
  ];
  manifest.artifactSetSha256 = computeArtifactSetSha256(manifest.artifacts);
  assert.throws(() => validateManifest(manifest), /file\.path/u);
});

test("artifact and evidence roles cannot be rebound to alternate Windows paths", () => {
  const artifactSwap = initialManifest();
  artifactSwap.artifacts[0].file.path = "payload/alternate.exe";
  assert.throws(() => validateManifest(artifactSwap), /file\.path/u);

  const evidenceCaseAlias = initialManifest();
  evidenceCaseAlias.evidence.cargoLock.path = "evidence/cargo.lock";
  assert.throws(() => validateManifest(evidenceCaseAlias), /evidence\.cargoLock\.path/u);
});

test("successor requires the exact prior canonical manifest", () => {
  const previous = initialManifest();
  const current = successor(previous);
  assert.doesNotThrow(() => validateManifest(current, previous));
  const otherPrevious = structuredClone(previous);
  otherPrevious.source.treeSha256 = digest("different-source-tree");
  otherPrevious.evidence.sourceArchive.sha256 = otherPrevious.source.treeSha256;
  assert.throws(() => validateManifest(current, otherPrevious), /previousManifestSha256/u);
});

test("successor cannot rotate the stable extension identity", () => {
  const previous = initialManifest();
  const current = successor(previous);
  current.extension.id = "b".repeat(32);
  assert.throws(
    () => validateManifest(current, previous),
    /stable extension identity changed across release lineage/u,
  );
});

test("version rollback and version reuse are rejected", () => {
  const previous = initialManifest();
  assert.throws(() => validateManifest(successor(previous, "0.1.0"), previous), /rollback or reuse/u);
  assert.throws(() => validateManifest(successor(previous, "0.0.9"), previous), /rollback or reuse/u);
});

test("a non-initial release cannot omit its previous manifest", () => {
  const previous = initialManifest();
  assert.throws(() => validateManifest(successor(previous)), /requires the exact previous manifest/u);
});

test("numbers are forbidden in the signed canonical form", () => {
  assert.throws(() => canonicalEncode({ sequence: 1 }), /decimal strings/u);
});
