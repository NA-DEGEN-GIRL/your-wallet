import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ELIGIBILITY_CLAIM,
  MANIFEST_SCHEMA,
  RELEASE_PROFILE,
  REQUIRED_ARTIFACT_PATHS,
  REQUIRED_ARTIFACT_ROLES,
  REQUIRED_WINDOWS_NEGATIVE_TESTS,
  canonicalEncode,
  computeArtifactSetSha256,
  parseStrictJson,
  sha256Hex,
  validateManifest,
  verifyExpectedExtensionId,
  verifyExpectedReleaseKeyId,
  verifyExpectedPreviousManifestSha256,
  verifyExpectedReviewerKeyId,
  verifyExpectedSignerCertificateSha256,
} from "./release-manifest.mjs";

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

test("canonical encoding is independent of object insertion order", () => {
  const left = parseStrictJson('{"z":"last","a":{"y":"2","x":"1"},"m":[true,null,"v"]}');
  const right = parseStrictJson('{"m":[true,null,"v"],"a":{"x":"1","y":"2"},"z":"last"}');
  assert.equal(canonicalEncode(left), canonicalEncode(right));
  assert.equal(canonicalEncode(left), '{"a":{"x":"1","y":"2"},"m":[true,null,"v"],"z":"last"}');
});

test("strict parser rejects duplicate members before canonicalization", () => {
  assert.throws(() => parseStrictJson('{"schema":"one","schema":"two"}'), /duplicate JSON member/u);
});

test("a complete initial candidate is structurally valid", () => {
  assert.doesNotThrow(() => validateManifest(initialManifest()));
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
