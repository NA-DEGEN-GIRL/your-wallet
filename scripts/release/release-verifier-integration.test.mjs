import assert from "node:assert/strict";
import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { test } from "node:test";

import {
  ELIGIBILITY_CLAIM,
  INDEPENDENT_REVIEW_SCHEMA,
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
  computeReviewedEvidenceSetSha256,
  ed25519PublicKeyIdSha256,
  sha256Hex,
  validateManifest,
  verifyBundleFiles,
  verifyEvidenceAttestations,
  verifyExpectedExtensionId,
  verifyExpectedSignerCertificateSha256,
} from "./release-manifest.mjs";

const SOURCE_COMMIT = "1".repeat(40);
const EXTENSION_ID = "a".repeat(32);
const VERSION = "0.1.0";
const execFileAsync = promisify(execFile);

function digest(label) {
  return sha256Hex(Buffer.from(label, "utf8"));
}

async function writeRelative(root, relativePath, contents) {
  const absolutePath = path.join(root, ...relativePath.split("/"));
  await mkdir(path.dirname(absolutePath), { recursive: true });
  await writeFile(absolutePath, contents, { flag: "wx" });
}

async function replaceRelative(root, relativePath, contents) {
  const absolutePath = path.join(root, ...relativePath.split("/"));
  await writeFile(absolutePath, contents, { flag: "w" });
}

async function writeJson(root, relativePath, value) {
  await writeRelative(root, relativePath, `${canonicalEncode(value)}\n`);
}

async function replaceJson(root, relativePath, value) {
  await replaceRelative(root, relativePath, `${canonicalEncode(value)}\n`);
}

async function fileRecord(root, relativePath) {
  const absolutePath = path.join(root, ...relativePath.split("/"));
  const [contents, metadata] = await Promise.all([readFile(absolutePath), stat(absolutePath)]);
  return { bytes: metadata.size.toString(), path: relativePath, sha256: sha256Hex(contents) };
}

async function createSyntheticBundle() {
  const root = await mkdtemp(path.join(os.tmpdir(), "your-wallet-release-verifier-"));
  const signerCertificateSha256 = digest("independently-pinned-authenticode-leaf");
  const { privateKey: releasePrivateKey, publicKey: releasePublicKey } = generateKeyPairSync("ed25519");
  const releasePublicKeyPem = releasePublicKey.export({ format: "pem", type: "spki" });
  const releaseKeyIdSha256 = ed25519PublicKeyIdSha256(releasePublicKeyPem);
  const unsignedArtifactSetSha256 = digest("unsigned-artifact-set");
  const extensionManifestSha256 = digest("extension-manifest");

  const artifacts = [];
  for (const role of REQUIRED_ARTIFACT_ROLES) {
    const relativePath = REQUIRED_ARTIFACT_PATHS[role];
    await writeRelative(root, relativePath, Buffer.from(`synthetic-${role}\n`, "utf8"));
    artifacts.push({
      authenticode: role === "extension-package"
        ? { evidenceSha256: null, signerCertificateSha256: null, status: "not-applicable" }
        : { evidenceSha256: digest("pending-auth-report"), signerCertificateSha256, status: "valid" },
      file: await fileRecord(root, relativePath),
      role,
    });
  }
  const artifactSetSha256 = computeArtifactSetSha256(artifacts);

  const signedArtifactsByPath = artifacts
    .filter((artifact) => artifact.role !== "extension-package")
    .sort((left, right) => left.file.path < right.file.path ? -1 : left.file.path > right.file.path ? 1 : 0);
  const authenticodeReport = {
    artifactSetSha256,
    entries: signedArtifactsByPath.map((artifact) => ({
      path: artifact.file.path,
      sha256: artifact.file.sha256,
      signerCertificateSha256,
      status: "valid",
    })),
    result: "pass",
    schema: "your-wallet-authenticode-evidence-v1",
  };
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.authenticodeReport, authenticodeReport);
  const authenticodeRecord = await fileRecord(root, REQUIRED_EVIDENCE_PATHS.authenticodeReport);
  for (const artifact of artifacts.filter((item) => item.role !== "extension-package")) {
    artifact.authenticode.evidenceSha256 = authenticodeRecord.sha256;
  }

  const rawFiles = new Map([
    ["cargo", "cargo 1.95.0 synthetic\n"],
    ["cargoLock", "# synthetic Cargo.lock\n"],
    ["osvRawReport", "{}\n"],
    ["rustSecRawReport", "{}\n"],
    ["rustToolchain", "[toolchain]\nchannel = \"1.95.0\"\n"],
    ["rustc", "rustc 1.95.0 synthetic\n"],
    ["sourceArchive", "synthetic source archive\n"],
    ["vendorInventory", "[]\n"],
  ]);
  for (const [key, contents] of rawFiles) {
    await writeRelative(root, REQUIRED_EVIDENCE_PATHS[key], contents);
  }

  const nativeHostManifest = {
    allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
    description: "Your Wallet private canary native host",
    name: "com.your_wallet.native",
    path: "C:\\Program Files\\Your Wallet\\native-host.exe",
    type: "stdio",
  };
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.nativeHostManifest, nativeHostManifest);
  const nativeHostManifestRecord = await fileRecord(root, REQUIRED_EVIDENCE_PATHS.nativeHostManifest);

  const packageRecord = artifacts.find((artifact) => artifact.role === "extension-package").file;
  const installerRecord = artifacts.find((artifact) => artifact.role === "installer").file;
  const sourceArchiveRecord = await fileRecord(root, REQUIRED_EVIDENCE_PATHS.sourceArchive);
  const vendorInventoryRecord = await fileRecord(root, REQUIRED_EVIDENCE_PATHS.vendorInventory);
  const cargoLockRecord = await fileRecord(root, REQUIRED_EVIDENCE_PATHS.cargoLock);
  const rustSecRawRecord = await fileRecord(root, REQUIRED_EVIDENCE_PATHS.rustSecRawReport);
  const osvRawRecord = await fileRecord(root, REQUIRED_EVIDENCE_PATHS.osvRawReport);

  const dependencyPackage = {
    dependencyIds: [],
    features: [],
    hasBuildScript: "no",
    license: "MIT",
    links: null,
    name: "synthetic-wallet",
    procMacro: "no",
    source: "workspace",
    version: VERSION,
    workspace: "yes",
  };
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.dependencyInventory, {
    cargoLockSha256: cargoLockRecord.sha256,
    packages: [dependencyPackage],
    schema: "your-wallet-cargo-dependency-inventory-v1",
    sourceCommit: SOURCE_COMMIT,
    target: "x86_64-pc-windows-msvc",
  });
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.licenseInventory, {
    cargoLockSha256: cargoLockRecord.sha256,
    packages: [{ license: "MIT", name: "synthetic-wallet", source: "workspace", version: VERSION }],
    schema: "your-wallet-license-inventory-v1",
    sourceCommit: SOURCE_COMMIT,
    target: "x86_64-pc-windows-msvc",
  });
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.sbomSpdx, {
    SPDXID: "SPDXRef-DOCUMENT",
    creationInfo: {
      created: "2026-08-13T00:00:00Z",
      creators: ["Tool: your-wallet/scripts/release/generate-inventories.mjs"],
    },
    dataLicense: "CC0-1.0",
    documentDescribes: ["SPDXRef-Package-synthetic-wallet"],
    documentNamespace: `https://spdx.org/spdxdocs/your-wallet-${SOURCE_COMMIT}-${cargoLockRecord.sha256}`,
    name: `your-wallet-${SOURCE_COMMIT}`,
    packages: [{ SPDXID: "SPDXRef-Package-synthetic-wallet" }],
    relationships: [],
    spdxVersion: "SPDX-2.3",
  });

  const rustSecPolicy = {
    databaseCommit: "3".repeat(40),
    databaseTreeSha256: digest("rustsec-database"),
    scanner: "cargo-audit",
    scannerBinarySha256: digest("cargo-audit-binary"),
    scannerVersion: "0.21.0",
  };
  const osvPolicy = {
    databaseSnapshotId: "2026-08-13T00:00:00Z",
    databaseSnapshotSha256: digest("osv-database"),
    scanner: "osv-scanner",
    scannerBinarySha256: digest("osv-scanner-binary"),
    scannerVersion: "2.0.0",
  };
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.rustSecAdvisoryReport, {
    acceptedWarnings: "0",
    cargoLockSha256: cargoLockRecord.sha256,
    databaseCommit: rustSecPolicy.databaseCommit,
    databaseTreeSha256: rustSecPolicy.databaseTreeSha256,
    rawReportSha256: rustSecRawRecord.sha256,
    result: "pass",
    scanner: rustSecPolicy.scanner,
    scannerBinarySha256: rustSecPolicy.scannerBinarySha256,
    scannerVersion: rustSecPolicy.scannerVersion,
    schema: "your-wallet-rustsec-advisory-evidence-v1",
    sourceCommit: SOURCE_COMMIT,
    vulnerabilitiesFound: "0",
  });
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.osvAdvisoryReport, {
    acceptedFindings: "0",
    cargoLockSha256: cargoLockRecord.sha256,
    databaseSnapshotId: osvPolicy.databaseSnapshotId,
    databaseSnapshotSha256: osvPolicy.databaseSnapshotSha256,
    rawReportSha256: osvRawRecord.sha256,
    result: "pass",
    scanner: osvPolicy.scanner,
    scannerBinarySha256: osvPolicy.scannerBinarySha256,
    scannerVersion: osvPolicy.scannerVersion,
    schema: "your-wallet-osv-advisory-evidence-v1",
    sourceCommit: SOURCE_COMMIT,
    vulnerabilitiesFound: "0",
  });
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.reproducibilityReport, {
    firstPayloadSetSha256: unsignedArtifactSetSha256,
    result: "pass",
    schema: "your-wallet-reproducibility-evidence-v1",
    secondPayloadSetSha256: unsignedArtifactSetSha256,
    sourceCommit: SOURCE_COMMIT,
    sourceTreeSha256: sourceArchiveRecord.sha256,
    unsignedArtifactSetSha256,
    vendorTreeSha256: vendorInventoryRecord.sha256,
  });
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.extensionAudit, {
    extensionManifestSha256,
    packageSha256: packageRecord.sha256,
    permissionAudit: "pass",
    remoteCodeAudit: "pass",
    result: "pass",
    schema: "your-wallet-extension-static-audit-v1",
  });
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.installerAclNegative, {
    extensionId: EXTENSION_ID,
    installerSha256: installerRecord.sha256,
    nativeHostManifestSha256: nativeHostManifestRecord.sha256,
    result: "pass",
    schema: "your-wallet-installer-acl-evidence-v1",
    tests: ["install-directory-not-user-writable", "native-host-manifest-not-user-writable", "path-reparse-rejected"],
  });
  await writeJson(root, REQUIRED_EVIDENCE_PATHS.nativeHostRegistration, {
    extensionId: EXTENSION_ID,
    nativeHostManifestSha256: nativeHostManifestRecord.sha256,
    nativeHostName: "com.your_wallet.native",
    result: "pass",
    schema: "your-wallet-native-host-registration-evidence-v1",
    tests: ["allowed-origin-exact", "registry-user-scope", "wrong-extension-id-rejected"],
  });

  for (const [key, schema] of [
    ["keyRotationDrill", "your-wallet-key-rotation-drill-v1"],
    ["keyRevocationDrill", "your-wallet-key-revocation-drill-v1"],
  ]) {
    await writeJson(root, REQUIRED_EVIDENCE_PATHS[key], {
      performedAtUtc: "2026-08-13T00:00:00Z",
      releaseKeyIdSha256,
      result: "pass",
      schema,
      sourceCommit: SOURCE_COMMIT,
      version: VERSION,
    });
  }

  const { privateKey: reviewerPrivateKey, publicKey: reviewerPublicKey } = generateKeyPairSync("ed25519");
  const reviewerPublicKeyPem = reviewerPublicKey.export({ format: "pem", type: "spki" });
  const reviewerKeyIdSha256 = ed25519PublicKeyIdSha256(reviewerPublicKeyPem);
  await writeRelative(root, REQUIRED_EVIDENCE_PATHS.reviewPublicKey, reviewerPublicKeyPem);

  const windowsNegativeTests = [];
  for (const id of REQUIRED_WINDOWS_NEGATIVE_TESTS) {
    const relativePath = `evidence/windows-negative/${id}.json`;
    await writeJson(root, relativePath, {
      artifactSetSha256,
      id,
      osBuild: "10.0.26100.1",
      profile: RELEASE_PROFILE,
      result: "pass",
      schema: "your-wallet-windows-negative-test-v1",
      sourceCommit: SOURCE_COMMIT,
    });
    windowsNegativeTests.push({
      artifactSetSha256,
      id,
      log: await fileRecord(root, relativePath),
      result: "pass",
      sourceCommit: SOURCE_COMMIT,
    });
  }

  const reviewedEvidenceRecords = [];
  for (const [key, relativePath] of Object.entries(REQUIRED_EVIDENCE_PATHS)) {
    if (!REVIEW_EVIDENCE_EXCLUDED_KEYS.includes(key)) {
      reviewedEvidenceRecords.push(await fileRecord(root, relativePath));
    }
  }
  reviewedEvidenceRecords.push(...windowsNegativeTests.map((item) => item.log));
  const reviewAttestation = {
    artifactSetSha256,
    criticalOpen: "0",
    highOpen: "0",
    independenceAttestation: "pass",
    profile: RELEASE_PROFILE,
    reviewedEvidenceSetSha256: computeReviewedEvidenceSetSha256(reviewedEvidenceRecords),
    reviewerKeyIdSha256,
    schema: INDEPENDENT_REVIEW_SCHEMA,
    scope: REQUIRED_REVIEW_SCOPE,
    sourceCommit: SOURCE_COMMIT,
    version: VERSION,
  };
  await writeRelative(root, REQUIRED_EVIDENCE_PATHS.reviewAttestation, canonicalEncode(reviewAttestation));
  await writeRelative(
    root,
    REQUIRED_EVIDENCE_PATHS.reviewSignature,
    signBytes(null, Buffer.from(canonicalEncode(reviewAttestation), "utf8"), reviewerPrivateKey).toString("base64"),
  );

  const evidence = {};
  for (const [key, relativePath] of Object.entries(REQUIRED_EVIDENCE_PATHS)) {
    evidence[key] = await fileRecord(root, relativePath);
  }
  const manifest = {
    advisoryPolicy: { osv: osvPolicy, rustSec: rustSecPolicy },
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
      unsignedArtifactSetSha256,
    },
    eligibilityClaim: ELIGIBILITY_CLAIM,
    evidence,
    extension: {
      id: EXTENSION_ID,
      manifestSha256: extensionManifestSha256,
      nativeHostName: "com.your_wallet.native",
      packageSha256: packageRecord.sha256,
    },
    lineage: { previousManifestSha256: null, previousSequence: null, previousVersion: null },
    profile: RELEASE_PROFILE,
    schema: MANIFEST_SCHEMA,
    sequence: "1",
    signing: { algorithm: "Ed25519", keyIdSha256: releaseKeyIdSha256 },
    source: {
      cargoLockSha256: evidence.cargoLock.sha256,
      commit: SOURCE_COMMIT,
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
    version: VERSION,
    windowsNegativeTests,
  };
  return {
    authenticodeReport,
    manifest,
    nativeHostManifest,
    releasePrivateKey,
    releasePublicKeyPem,
    reviewAttestation,
    reviewerPrivateKey,
    reviewerKeyIdSha256,
    root,
    signerCertificateSha256,
  };
}

async function rebindSyntheticExtensionIdentity(fixture, extensionId) {
  fixture.manifest.extension.id = extensionId;
  fixture.nativeHostManifest = {
    ...fixture.nativeHostManifest,
    allowed_origins: [`chrome-extension://${extensionId}/`],
  };
  await replaceJson(
    fixture.root,
    REQUIRED_EVIDENCE_PATHS.nativeHostManifest,
    fixture.nativeHostManifest,
  );
  const nativeHostManifestRecord = await fileRecord(
    fixture.root,
    REQUIRED_EVIDENCE_PATHS.nativeHostManifest,
  );
  fixture.manifest.evidence.nativeHostManifest = nativeHostManifestRecord;

  for (const key of ["installerAclNegative", "nativeHostRegistration"]) {
    const relativePath = REQUIRED_EVIDENCE_PATHS[key];
    const absolutePath = path.join(fixture.root, ...relativePath.split("/"));
    const evidence = JSON.parse(await readFile(absolutePath, "utf8"));
    evidence.extensionId = extensionId;
    evidence.nativeHostManifestSha256 = nativeHostManifestRecord.sha256;
    await replaceJson(fixture.root, relativePath, evidence);
    fixture.manifest.evidence[key] = await fileRecord(fixture.root, relativePath);
  }
}

async function reissueIndependentReview(fixture, overrides = {}) {
  const reviewedEvidenceRecords = Object.entries(fixture.manifest.evidence)
    .filter(([key]) => !REVIEW_EVIDENCE_EXCLUDED_KEYS.includes(key))
    .map(([, record]) => record);
  reviewedEvidenceRecords.push(...fixture.manifest.windowsNegativeTests.map((item) => item.log));
  fixture.reviewAttestation = {
    ...fixture.reviewAttestation,
    ...overrides,
    reviewedEvidenceSetSha256: computeReviewedEvidenceSetSha256(reviewedEvidenceRecords),
  };
  await replaceRelative(
    fixture.root,
    REQUIRED_EVIDENCE_PATHS.reviewAttestation,
    canonicalEncode(fixture.reviewAttestation),
  );
  await replaceRelative(
    fixture.root,
    REQUIRED_EVIDENCE_PATHS.reviewSignature,
    signBytes(
      null,
      Buffer.from(canonicalEncode(fixture.reviewAttestation), "utf8"),
      fixture.reviewerPrivateKey,
    ).toString("base64"),
  );
  fixture.manifest.evidence.reviewAttestation = await fileRecord(
    fixture.root,
    REQUIRED_EVIDENCE_PATHS.reviewAttestation,
  );
  fixture.manifest.evidence.reviewSignature = await fileRecord(
    fixture.root,
    REQUIRED_EVIDENCE_PATHS.reviewSignature,
  );
}

async function expectReviewEvidenceMismatch(fixture) {
  const invocation = await createVerifyCliInvocation(fixture);
  try {
    await assert.rejects(
      () => execFileAsync(process.execPath, invocation.arguments),
      (error) => {
        assert.equal(
          error.stderr,
          "RELEASE_INELIGIBLE: independent review evidence-set commitment mismatch\n",
        );
        assert.equal(error.stdout, "");
        return true;
      },
    );
  } finally {
    await rm(invocation.inputs, { force: true, recursive: true });
  }
}

async function replaceNativeHostDescriptionAndBindings(fixture) {
  fixture.nativeHostManifest = {
    ...fixture.nativeHostManifest,
    description: "Your Wallet replacement private canary native host",
  };
  await replaceJson(
    fixture.root,
    REQUIRED_EVIDENCE_PATHS.nativeHostManifest,
    fixture.nativeHostManifest,
  );
  const nativeHostManifestRecord = await fileRecord(
    fixture.root,
    REQUIRED_EVIDENCE_PATHS.nativeHostManifest,
  );
  fixture.manifest.evidence.nativeHostManifest = nativeHostManifestRecord;
  for (const key of ["installerAclNegative", "nativeHostRegistration"]) {
    const relativePath = REQUIRED_EVIDENCE_PATHS[key];
    const absolutePath = path.join(fixture.root, ...relativePath.split("/"));
    const evidence = JSON.parse(await readFile(absolutePath, "utf8"));
    evidence.nativeHostManifestSha256 = nativeHostManifestRecord.sha256;
    await replaceJson(fixture.root, relativePath, evidence);
    fixture.manifest.evidence[key] = await fileRecord(fixture.root, relativePath);
  }
}

async function replaceWindowsNegativeLog(fixture) {
  const item = fixture.manifest.windowsNegativeTests[0];
  const absolutePath = path.join(fixture.root, ...item.log.path.split("/"));
  const log = JSON.parse(await readFile(absolutePath, "utf8"));
  log.osBuild = "10.0.26100.2";
  await replaceJson(fixture.root, item.log.path, log);
  item.log = await fileRecord(fixture.root, item.log.path);
}

async function replaceOsvEvidenceAndPolicy(fixture) {
  const rawPath = REQUIRED_EVIDENCE_PATHS.osvRawReport;
  await replaceJson(fixture.root, rawPath, { results: [], variant: "replacement" });
  fixture.manifest.evidence.osvRawReport = await fileRecord(fixture.root, rawPath);

  const reportPath = REQUIRED_EVIDENCE_PATHS.osvAdvisoryReport;
  const absoluteReportPath = path.join(fixture.root, ...reportPath.split("/"));
  const report = JSON.parse(await readFile(absoluteReportPath, "utf8"));
  report.databaseSnapshotId = "2026-08-14T00:00:00Z";
  report.databaseSnapshotSha256 = digest("replacement-osv-database");
  report.rawReportSha256 = fixture.manifest.evidence.osvRawReport.sha256;
  await replaceJson(fixture.root, reportPath, report);
  fixture.manifest.evidence.osvAdvisoryReport = await fileRecord(fixture.root, reportPath);
  fixture.manifest.advisoryPolicy.osv.databaseSnapshotId = report.databaseSnapshotId;
  fixture.manifest.advisoryPolicy.osv.databaseSnapshotSha256 = report.databaseSnapshotSha256;
}

async function createVerifyCliInvocation(fixture, expectedExtensionId = EXTENSION_ID) {
  const inputs = await mkdtemp(path.join(os.tmpdir(), "your-wallet-release-cli-"));
  const manifestPath = path.join(inputs, "release-manifest.json");
  const signaturePath = path.join(inputs, "release-manifest.sig");
  const publicKeyPath = path.join(inputs, "release-public-key.pem");
  const manifestBytes = Buffer.from(canonicalEncode(fixture.manifest), "utf8");
  await writeFile(manifestPath, manifestBytes, { flag: "wx" });
  await writeFile(
    signaturePath,
    signBytes(null, manifestBytes, fixture.releasePrivateKey).toString("base64"),
    { flag: "wx" },
  );
  await writeFile(publicKeyPath, fixture.releasePublicKeyPem, { flag: "wx" });
  return {
    arguments: [
      path.resolve("scripts/release/release-manifest.mjs"),
      "verify",
      "--manifest", manifestPath,
      "--signature", signaturePath,
      "--public-key", publicKeyPath,
      "--bundle-root", fixture.root,
      "--expected-release-key-id", fixture.manifest.signing.keyIdSha256,
      "--expected-extension-id", expectedExtensionId,
      "--expected-reviewer-key-id", fixture.reviewerKeyIdSha256,
      "--expected-signer-certificate-sha256", fixture.signerCertificateSha256,
    ],
    inputs,
  };
}

async function createAssembleCliInvocation(fixture) {
  const inputs = await mkdtemp(path.join(os.tmpdir(), "your-wallet-release-assembly-"));
  const outputPath = path.join(inputs, "release-manifest.json");
  const publicKeyPath = path.join(inputs, "release-public-key.pem");
  await writeFile(publicKeyPath, fixture.releasePublicKeyPem, { flag: "wx" });
  const { osv, rustSec } = fixture.manifest.advisoryPolicy;
  return {
    arguments: [
      path.resolve("scripts/release/assemble-manifest.mjs"),
      "--bundle-root", fixture.root,
      "--output", outputPath,
      "--source-commit", fixture.manifest.source.commit,
      "--version", fixture.manifest.version,
      "--sequence", fixture.manifest.sequence,
      "--extension-id", fixture.manifest.extension.id,
      "--native-host-name", fixture.manifest.extension.nativeHostName,
      "--cargo-audit-version", rustSec.scannerVersion,
      "--cargo-audit-binary-sha256", rustSec.scannerBinarySha256,
      "--rustsec-db-commit", rustSec.databaseCommit,
      "--rustsec-db-tree-sha256", rustSec.databaseTreeSha256,
      "--osv-scanner-version", osv.scannerVersion,
      "--osv-scanner-binary-sha256", osv.scannerBinarySha256,
      "--osv-db-snapshot-id", osv.databaseSnapshotId,
      "--osv-db-snapshot-sha256", osv.databaseSnapshotSha256,
      "--release-public-key", publicKeyPath,
    ],
    inputs,
    outputPath,
  };
}

async function verifySyntheticBundle(fixture) {
  const validated = validateManifest(fixture.manifest);
  verifyExpectedSignerCertificateSha256(validated, fixture.signerCertificateSha256);
  await verifyBundleFiles(validated, fixture.root);
  await verifyEvidenceAttestations(
    validated,
    fixture.root,
    fixture.reviewerKeyIdSha256,
    fixture.signerCertificateSha256,
  );
}

test("synthetic final bundle verifies with canonical path-ordered Authenticode evidence", async () => {
  const fixture = await createSyntheticBundle();
  try {
    await assert.doesNotReject(() => verifySyntheticBundle(fixture));
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("verify CLI accepts the exact initial-release arity and cryptographic bindings", async () => {
  const fixture = await createSyntheticBundle();
  const invocation = await createVerifyCliInvocation(fixture);
  try {
    const { stdout } = await execFileAsync(process.execPath, invocation.arguments);
    assert.equal(stdout, "CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER\n");
  } finally {
    await Promise.all([
      rm(fixture.root, { force: true, recursive: true }),
      rm(invocation.inputs, { force: true, recursive: true }),
    ]);
  }
});

test("verify CLI rejects missing and extra extension-pin arguments", async () => {
  const fixture = await createSyntheticBundle();
  const invocation = await createVerifyCliInvocation(fixture);
  try {
    const extensionArgument = invocation.arguments.indexOf("--expected-extension-id");
    assert.notEqual(extensionArgument, -1);
    const missing = [...invocation.arguments];
    missing.splice(extensionArgument, 2);
    await assert.rejects(
      () => execFileAsync(process.execPath, missing),
      (error) => {
        assert.match(error.stderr, /verify requires .*--expected-extension-id/u);
        return true;
      },
    );

    const extra = [...invocation.arguments, "--candidate-extension-id", "c".repeat(32)];
    await assert.rejects(
      () => execFileAsync(process.execPath, extra),
      (error) => {
        assert.match(error.stderr, /verify requires .*--expected-extension-id/u);
        return true;
      },
    );
  } finally {
    await Promise.all([
      rm(fixture.root, { force: true, recursive: true }),
      rm(invocation.inputs, { force: true, recursive: true }),
    ]);
  }
});

test("verify CLI rejects a self-consistent signed attacker-selected extension id without echo", async () => {
  const fixture = await createSyntheticBundle();
  const attackerExtensionId = "b".repeat(32);
  await rebindSyntheticExtensionIdentity(fixture, attackerExtensionId);
  await reissueIndependentReview(fixture);
  const validated = validateManifest(fixture.manifest);
  verifyExpectedExtensionId(validated, attackerExtensionId);
  await assert.doesNotReject(() => verifySyntheticBundle(fixture));
  const invocation = await createVerifyCliInvocation(fixture, EXTENSION_ID);
  try {
    await assert.rejects(
      () => execFileAsync(process.execPath, invocation.arguments),
      (error) => {
        assert.equal(
          error.stderr,
          "RELEASE_INELIGIBLE: independently pinned extension identifier mismatch\n",
        );
        assert.equal(error.stdout, "");
        return true;
      },
    );
  } finally {
    await Promise.all([
      rm(fixture.root, { force: true, recursive: true }),
      rm(invocation.inputs, { force: true, recursive: true }),
    ]);
  }
});

test("old reviewer signature rejects a release-signed native-host evidence replacement", async () => {
  const fixture = await createSyntheticBundle();
  try {
    await replaceNativeHostDescriptionAndBindings(fixture);
    await expectReviewEvidenceMismatch(fixture);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("a refreshed v2 commitment cannot reuse the old reviewer signature under a fresh release signature", async () => {
  const fixture = await createSyntheticBundle();
  let invocation;
  try {
    const oldReviewSignature = await readFile(
      path.join(fixture.root, ...REQUIRED_EVIDENCE_PATHS.reviewSignature.split("/")),
    );
    await replaceNativeHostDescriptionAndBindings(fixture);
    const reviewedEvidenceRecords = Object.entries(fixture.manifest.evidence)
      .filter(([key]) => !REVIEW_EVIDENCE_EXCLUDED_KEYS.includes(key))
      .map(([, record]) => record);
    reviewedEvidenceRecords.push(...fixture.manifest.windowsNegativeTests.map((item) => item.log));
    fixture.reviewAttestation = {
      ...fixture.reviewAttestation,
      reviewedEvidenceSetSha256: computeReviewedEvidenceSetSha256(reviewedEvidenceRecords),
    };
    await replaceRelative(
      fixture.root,
      REQUIRED_EVIDENCE_PATHS.reviewAttestation,
      canonicalEncode(fixture.reviewAttestation),
    );
    fixture.manifest.evidence.reviewAttestation = await fileRecord(
      fixture.root,
      REQUIRED_EVIDENCE_PATHS.reviewAttestation,
    );
    assert.deepEqual(
      await readFile(path.join(fixture.root, ...REQUIRED_EVIDENCE_PATHS.reviewSignature.split("/"))),
      oldReviewSignature,
    );

    invocation = await createVerifyCliInvocation(fixture);
    await assert.rejects(
      () => execFileAsync(process.execPath, invocation.arguments),
      (error) => {
        assert.equal(
          error.stderr,
          "RELEASE_INELIGIBLE: independent review attestation signature is invalid\n",
        );
        assert.equal(error.stdout, "");
        return true;
      },
    );
  } finally {
    await Promise.all([
      rm(fixture.root, { force: true, recursive: true }),
      ...(invocation ? [rm(invocation.inputs, { force: true, recursive: true })] : []),
    ]);
  }
});

test("verify CLI keeps release, Authenticode, and reviewer pins in distinct external roles", async () => {
  const fixture = await createSyntheticBundle();
  const invocation = await createVerifyCliInvocation(fixture);
  let selfReviewInvocation;
  const replaceArgument = (argumentsList, name, value) => {
    const replaced = [...argumentsList];
    const index = replaced.indexOf(name);
    assert.notEqual(index, -1);
    replaced[index + 1] = value;
    return replaced;
  };
  const expectCliFailure = async (argumentsList, expectedStderr) => {
    await assert.rejects(
      () => execFileAsync(process.execPath, argumentsList),
      (error) => {
        assert.equal(error.stderr, expectedStderr);
        assert.equal(error.stdout, "");
        return true;
      },
    );
  };
  try {
    const wrongReleaseKeyId = digest("wrong-release-key-id");
    await expectCliFailure(
      replaceArgument(
        invocation.arguments,
        "--expected-release-key-id",
        wrongReleaseKeyId,
      ),
      `RELEASE_INELIGIBLE: independently pinned release key identifier must be "${wrongReleaseKeyId}"\n`,
    );

    const wrongSignerCertificateSha256 = digest("wrong-authenticode-signer-certificate");
    const firstSignedArtifact = fixture.manifest.artifacts.find(
      (artifact) => artifact.role !== "extension-package",
    );
    assert.ok(firstSignedArtifact);
    await expectCliFailure(
      replaceArgument(
        invocation.arguments,
        "--expected-signer-certificate-sha256",
        wrongSignerCertificateSha256,
      ),
      `RELEASE_INELIGIBLE: ${firstSignedArtifact.role} independently pinned Authenticode signer must be "${wrongSignerCertificateSha256}"\n`,
    );

    const wrongReviewerKeyId = digest("wrong-reviewer-key-id");
    await expectCliFailure(
      replaceArgument(
        invocation.arguments,
        "--expected-reviewer-key-id",
        wrongReviewerKeyId,
      ),
      `RELEASE_INELIGIBLE: independently pinned reviewer key identifier must be "${wrongReviewerKeyId}"\n`,
    );

    await replaceRelative(
      fixture.root,
      REQUIRED_EVIDENCE_PATHS.reviewPublicKey,
      fixture.releasePublicKeyPem,
    );
    fixture.manifest.evidence.reviewPublicKey = await fileRecord(
      fixture.root,
      REQUIRED_EVIDENCE_PATHS.reviewPublicKey,
    );
    fixture.reviewerPrivateKey = fixture.releasePrivateKey;
    fixture.reviewerKeyIdSha256 = fixture.manifest.signing.keyIdSha256;
    await reissueIndependentReview(fixture, {
      reviewerKeyIdSha256: fixture.reviewerKeyIdSha256,
    });
    selfReviewInvocation = await createVerifyCliInvocation(fixture);
    await expectCliFailure(
      selfReviewInvocation.arguments,
      "RELEASE_INELIGIBLE: independent reviewer key must differ from the release-manifest key\n",
    );
  } finally {
    await Promise.all([
      rm(fixture.root, { force: true, recursive: true }),
      rm(invocation.inputs, { force: true, recursive: true }),
      ...(selfReviewInvocation
        ? [rm(selfReviewInvocation.inputs, { force: true, recursive: true })]
        : []),
    ]);
  }
});

test("old reviewer signature rejects a release-signed Windows-negative log replacement", async () => {
  const fixture = await createSyntheticBundle();
  try {
    await replaceWindowsNegativeLog(fixture);
    await expectReviewEvidenceMismatch(fixture);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("old reviewer signature rejects advisory evidence and policy replacement", async () => {
  const fixture = await createSyntheticBundle();
  try {
    await replaceOsvEvidenceAndPolicy(fixture);
    await expectReviewEvidenceMismatch(fixture);

    await reissueIndependentReview(fixture);
    const invocation = await createVerifyCliInvocation(fixture);
    try {
      const { stdout } = await execFileAsync(process.execPath, invocation.arguments);
      assert.equal(stdout, "CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER\n");
    } finally {
      await rm(invocation.inputs, { force: true, recursive: true });
    }
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("independent review attestation v1 fails closed even with a valid old-schema signature", async () => {
  const fixture = await createSyntheticBundle();
  try {
    const versionOne = { ...fixture.reviewAttestation };
    versionOne.schema = "your-wallet-independent-security-review-v1";
    delete versionOne.reviewedEvidenceSetSha256;
    await replaceRelative(
      fixture.root,
      REQUIRED_EVIDENCE_PATHS.reviewAttestation,
      canonicalEncode(versionOne),
    );
    await replaceRelative(
      fixture.root,
      REQUIRED_EVIDENCE_PATHS.reviewSignature,
      signBytes(
        null,
        Buffer.from(canonicalEncode(versionOne), "utf8"),
        fixture.reviewerPrivateKey,
      ).toString("base64"),
    );
    fixture.manifest.evidence.reviewAttestation = await fileRecord(
      fixture.root,
      REQUIRED_EVIDENCE_PATHS.reviewAttestation,
    );
    fixture.manifest.evidence.reviewSignature = await fileRecord(
      fixture.root,
      REQUIRED_EVIDENCE_PATHS.reviewSignature,
    );
    const invocation = await createVerifyCliInvocation(fixture);
    try {
      await assert.rejects(
        () => execFileAsync(process.execPath, invocation.arguments),
        (error) => {
          assert.match(error.stderr, /independent review attestation members must be exactly/u);
          assert.equal(error.stdout, "");
          return true;
        },
      );
    } finally {
      await rm(invocation.inputs, { force: true, recursive: true });
    }
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("manifest assembly independently enforces review evidence-set v2 before output", async () => {
  const fixture = await createSyntheticBundle();
  const first = await createAssembleCliInvocation(fixture);
  let second;
  try {
    const result = await execFileAsync(process.execPath, first.arguments);
    assert.equal(result.stdout, "UNSIGNED_CANONICAL_MANIFEST_WRITTEN_NOT_RELEASE_ELIGIBLE\n");
    assert.equal(result.stderr, "");
    assert.equal(await readFile(first.outputPath, "utf8"), canonicalEncode(fixture.manifest));

    await replaceNativeHostDescriptionAndBindings(fixture);
    second = await createAssembleCliInvocation(fixture);
    await assert.rejects(
      () => execFileAsync(process.execPath, second.arguments),
      (error) => {
        assert.equal(
          error.stderr,
          "MANIFEST_ASSEMBLY_FAILED: independent review evidence-set commitment mismatch\n",
        );
        assert.equal(error.stdout, "");
        return true;
      },
    );
    await assert.rejects(() => stat(second.outputPath), { code: "ENOENT" });
  } finally {
    await Promise.all([
      rm(fixture.root, { force: true, recursive: true }),
      rm(first.inputs, { force: true, recursive: true }),
      ...(second ? [rm(second.inputs, { force: true, recursive: true })] : []),
    ]);
  }
});

test("offline wrapper requires a case-sensitive pin and withholds both child passes", async () => {
  const [wrapper, common] = await Promise.all([
    readFile("scripts/release/verify-release-offline.ps1", "utf8"),
    readFile("scripts/release/common.ps1", "utf8"),
  ]);
  const validation = '[ValidatePattern("^[a-p]{32}$", Options = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)][string]$ExpectedExtensionId';
  assert.ok(wrapper.includes(validation));
  assert.equal(
    wrapper.match(/"--expected-extension-id", \$ExpectedExtensionId/gu)?.length,
    1,
  );
  assert.equal(
    wrapper.match(/\[void\]\(Invoke-ReleaseCommand -Executable "node" -CommandArguments \$verifyArguments -WorkingDirectory \$PSScriptRoot\)/gu)?.length,
    2,
  );
  assert.equal(
    wrapper.match(/Write-Output "PRIVATE_MAINNET_CANARY_RELEASE_ELIGIBLE_AFTER_OFFLINE_VERIFICATION"/gu)?.length,
    1,
  );
  assert.ok(common.includes("output withheld; inspect locally with privacy redaction"));
  assert.ok(wrapper.includes("$bundle = $releaseLocks.CanonicalBundleRoot"));
  assert.ok(wrapper.includes("$canonicalInputs = @($releaseLocks.CanonicalAdditionalFiles)"));
  assert.ok(wrapper.includes("ConvertFrom-ExactNamedArguments"));
  assert.ok(wrapper.includes("Invoke-OfflineReleaseVerification @boundArguments"));
  assert.ok(!wrapper.includes("Invoke-OfflineReleaseVerification @args"));
  assert.ok(!wrapper.includes("Resolve-Path -LiteralPath $BundleRoot"));
  assert.ok(wrapper.includes("RELEASE_VERIFICATION_FAILED: offline release verification failed closed"));
  assert.ok(common.includes("GetFinalPathNameByHandleW"));
  assert.ok(common.includes("FileInfoByHandleClass.FileIdInfo"));

  const probeRoot = await mkdtemp(path.join(os.tmpdir(), "your-wallet-extension-pin-"));
  const probe = path.join(probeRoot, "validate-extension-id.ps1");
  try {
    await writeFile(probe, `param(${validation})\nWrite-Output "accepted"\n`, { flag: "wx" });
    const accepted = await execFileAsync("powershell", [
      "-NoProfile",
      "-ExecutionPolicy", "Bypass",
      "-File", probe,
      "-ExpectedExtensionId", EXTENSION_ID,
    ]);
    assert.equal(accepted.stdout.trim(), "accepted");
    await assert.rejects(
      () => execFileAsync("powershell", [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", probe,
        "-ExpectedExtensionId", "A".repeat(32),
      ]),
      (error) => {
        assert.equal(error.stdout, "");
        return true;
      },
    );

    const missingRoot = path.join(probeRoot, "private-missing-bundle");
    const wrapperPath = path.resolve("scripts/release/verify-release-offline.ps1");
    await assert.rejects(
      () => execFileAsync("powershell", [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", wrapperPath,
        "-Manifest", path.join(probeRoot, "private-missing-manifest.json"),
        "-Signature", path.join(probeRoot, "private-missing-signature.bin"),
        "-ReleasePublicKey", path.join(probeRoot, "private-missing-release-key.pem"),
        "-BundleRoot", missingRoot,
        "-ExpectedReleaseKeyIdSha256", "1".repeat(64),
        "-ExpectedExtensionId", EXTENSION_ID,
        "-ExpectedReviewerKeyIdSha256", "2".repeat(64),
        "-ExpectedSignerCertificateSha256", "3".repeat(64),
        "-OperatorConfirmedNetworkIsolation",
      ]),
      (error) => {
        const stderr = error.stderr.replace(/\r\n/gu, "\n");
        assert.ok(error.stdout === "", "offline wrapper failure stdout must remain empty");
        assert.ok(
          stderr === "RELEASE_VERIFICATION_FAILED: offline release verification failed closed\n",
          "offline wrapper failure stderr must be one fixed category line",
        );
        assert.ok(!stderr.includes(missingRoot), "offline wrapper must not disclose the supplied path");
        assert.ok(!stderr.includes(wrapperPath), "offline wrapper must not disclose the script path");
        return true;
      },
    );
    await assert.rejects(
      () => execFileAsync("powershell", [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", wrapperPath,
        "-UnknownPrivateParameter", probeRoot,
      ], { timeout: 10_000 }),
      (error) => {
        const stderr = error.stderr.replace(/\r\n/gu, "\n");
        assert.ok(error.stdout === "", "offline wrapper binding failure stdout must remain empty");
        assert.ok(
          stderr === "RELEASE_VERIFICATION_FAILED: offline release verification failed closed\n",
          "offline wrapper binding failure stderr must be one fixed category line",
        );
        assert.ok(!stderr.includes(probeRoot), "offline wrapper must not disclose binding inputs");
        assert.ok(!stderr.includes(wrapperPath), "offline wrapper must not disclose the script path");
        return true;
      },
    );
  } finally {
    await rm(probeRoot, { force: true, recursive: true });
  }
});

test("final verifier rejects role/path swaps and unlisted bundle files", async () => {
  const fixture = await createSyntheticBundle();
  try {
    const swapped = structuredClone(fixture.manifest);
    swapped.artifacts[0].file.path = "payload/not-the-reviewed-role.exe";
    assert.throws(() => validateManifest(swapped), /file\.path/u);

    await writeRelative(fixture.root, "payload/unlisted.dll", "unlisted\n");
    const validated = validateManifest(fixture.manifest);
    await assert.rejects(() => verifyBundleFiles(validated, fixture.root), /unexpected or duplicate file/u);
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("final verifier rejects noncanonical Authenticode order", async () => {
  const fixture = await createSyntheticBundle();
  try {
    const report = structuredClone(fixture.authenticodeReport);
    [report.entries[0], report.entries[1]] = [report.entries[1], report.entries[0]];
    await replaceJson(fixture.root, REQUIRED_EVIDENCE_PATHS.authenticodeReport, report);
    fixture.manifest.evidence.authenticodeReport = await fileRecord(fixture.root, REQUIRED_EVIDENCE_PATHS.authenticodeReport);
    for (const artifact of fixture.manifest.artifacts.filter((item) => item.role !== "extension-package")) {
      artifact.authenticode.evidenceSha256 = fixture.manifest.evidence.authenticodeReport.sha256;
    }
    const validated = validateManifest(fixture.manifest);
    await assert.doesNotReject(() => verifyBundleFiles(validated, fixture.root));
    await assert.rejects(
      () => verifyEvidenceAttestations(validated, fixture.root, fixture.reviewerKeyIdSha256, fixture.signerCertificateSha256),
      /Authenticode evidence\.entries\[0\]\.path/u,
    );
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});

test("final verifier parses and binds the exact native-host manifest", async () => {
  const fixture = await createSyntheticBundle();
  try {
    const invalidManifest = { ...fixture.nativeHostManifest, path: "C:\\Program Files\\Your Wallet\\approval-ui.exe" };
    await replaceJson(fixture.root, REQUIRED_EVIDENCE_PATHS.nativeHostManifest, invalidManifest);
    fixture.manifest.evidence.nativeHostManifest = await fileRecord(fixture.root, REQUIRED_EVIDENCE_PATHS.nativeHostManifest);

    const installerAclPath = REQUIRED_EVIDENCE_PATHS.installerAclNegative;
    const installerAcl = JSON.parse(await readFile(path.join(fixture.root, ...installerAclPath.split("/")), "utf8"));
    installerAcl.nativeHostManifestSha256 = fixture.manifest.evidence.nativeHostManifest.sha256;
    await replaceJson(fixture.root, installerAclPath, installerAcl);
    fixture.manifest.evidence.installerAclNegative = await fileRecord(fixture.root, installerAclPath);

    const registrationPath = REQUIRED_EVIDENCE_PATHS.nativeHostRegistration;
    const registration = JSON.parse(await readFile(path.join(fixture.root, ...registrationPath.split("/")), "utf8"));
    registration.nativeHostManifestSha256 = fixture.manifest.evidence.nativeHostManifest.sha256;
    await replaceJson(fixture.root, registrationPath, registration);
    fixture.manifest.evidence.nativeHostRegistration = await fileRecord(fixture.root, registrationPath);

    const validated = validateManifest(fixture.manifest);
    await assert.doesNotReject(() => verifyBundleFiles(validated, fixture.root));
    await assert.rejects(
      () => verifyEvidenceAttestations(validated, fixture.root, fixture.reviewerKeyIdSha256, fixture.signerCertificateSha256),
      /executable basename/u,
    );
  } finally {
    await rm(fixture.root, { force: true, recursive: true });
  }
});
