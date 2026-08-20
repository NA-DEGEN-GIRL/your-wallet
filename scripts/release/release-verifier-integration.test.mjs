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
  MANIFEST_SCHEMA,
  RELEASE_PROFILE,
  REQUIRED_ARTIFACT_PATHS,
  REQUIRED_ARTIFACT_ROLES,
  REQUIRED_EVIDENCE_PATHS,
  REQUIRED_REVIEW_SCOPE,
  REQUIRED_WINDOWS_NEGATIVE_TESTS,
  canonicalEncode,
  computeArtifactSetSha256,
  ed25519PublicKeyIdSha256,
  sha256Hex,
  validateManifest,
  verifyBundleFiles,
  verifyEvidenceAttestations,
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
  const reviewAttestation = {
    artifactSetSha256,
    criticalOpen: "0",
    highOpen: "0",
    independenceAttestation: "pass",
    profile: RELEASE_PROFILE,
    reviewerKeyIdSha256,
    schema: "your-wallet-independent-security-review-v1",
    scope: REQUIRED_REVIEW_SCOPE,
    sourceCommit: SOURCE_COMMIT,
    version: VERSION,
  };
  await writeRelative(root, REQUIRED_EVIDENCE_PATHS.reviewAttestation, canonicalEncode(reviewAttestation));
  await writeRelative(root, REQUIRED_EVIDENCE_PATHS.reviewPublicKey, reviewerPublicKeyPem);
  await writeRelative(
    root,
    REQUIRED_EVIDENCE_PATHS.reviewSignature,
    signBytes(null, Buffer.from(canonicalEncode(reviewAttestation), "utf8"), reviewerPrivateKey).toString("base64"),
  );

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
    reviewerKeyIdSha256,
    root,
    signerCertificateSha256,
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
  const inputs = await mkdtemp(path.join(os.tmpdir(), "your-wallet-release-cli-"));
  try {
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
    const verifierPath = path.resolve("scripts/release/release-manifest.mjs");
    const { stdout } = await execFileAsync(process.execPath, [
      verifierPath,
      "verify",
      "--manifest", manifestPath,
      "--signature", signaturePath,
      "--public-key", publicKeyPath,
      "--bundle-root", fixture.root,
      "--expected-release-key-id", fixture.manifest.signing.keyIdSha256,
      "--expected-reviewer-key-id", fixture.reviewerKeyIdSha256,
      "--expected-signer-certificate-sha256", fixture.signerCertificateSha256,
    ]);
    assert.equal(stdout, "CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER\n");
  } finally {
    await Promise.all([
      rm(fixture.root, { force: true, recursive: true }),
      rm(inputs, { force: true, recursive: true }),
    ]);
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
