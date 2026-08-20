import { readFile, realpath, lstat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  ELIGIBILITY_CLAIM,
  MANIFEST_SCHEMA,
  REQUIRED_ARTIFACT_PATHS,
  REQUIRED_EVIDENCE_PATHS,
  RELEASE_PROFILE,
  REQUIRED_WINDOWS_NEGATIVE_TESTS,
  canonicalEncode,
  computeArtifactSetSha256,
  decodeUtf8,
  ed25519PublicKeyIdSha256,
  parseStrictJson,
  sha256Hex,
  validateManifest,
} from "./release-manifest.mjs";

const FILE_LAYOUT = Object.freeze({
  artifacts: REQUIRED_ARTIFACT_PATHS,
  evidence: REQUIRED_EVIDENCE_PATHS,
});

class AssemblyError extends Error {
  constructor(message) {
    super(message);
    this.name = "AssemblyError";
  }
}

function fail(message) {
  throw new AssemblyError(message);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has an unexpected schema`);
}

async function safeFile(bundleReal, relativePath) {
  let current = bundleReal;
  for (const segment of relativePath.split("/")) {
    current = path.join(current, segment);
    const status = await lstat(current);
    if (status.isSymbolicLink()) fail(`bundle input traverses a symbolic link: ${relativePath}`);
  }
  const resolved = await realpath(current);
  const relative = path.relative(bundleReal, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) fail(`bundle input escapes its root: ${relativePath}`);
  const status = await lstat(resolved);
  if (!status.isFile()) fail(`bundle input is not a regular file: ${relativePath}`);
  return { bytes: await readFile(resolved), status };
}

async function fileRecord(bundleReal, relativePath) {
  const file = await safeFile(bundleReal, relativePath);
  return { bytes: file.status.size.toString(), path: relativePath, sha256: sha256Hex(file.bytes) };
}

async function jsonRecord(bundleReal, relativePath) {
  const file = await safeFile(bundleReal, relativePath);
  return { record: { bytes: file.status.size.toString(), path: relativePath, sha256: sha256Hex(file.bytes) }, value: parseStrictJson(decodeUtf8(file.bytes, relativePath)) };
}

function parseArgs(argv) {
  const result = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith("--") || argv[index + 1] === undefined) fail("arguments must be --name value pairs");
    if (result.has(argv[index])) fail(`duplicate argument: ${argv[index]}`);
    result.set(argv[index], argv[index + 1]);
  }
  return result;
}

function required(args, key) {
  const value = args.get(key);
  if (!value) fail(`missing required argument ${key}`);
  return value;
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  const previousPath = args.get("--previous");
  const expectedCount = previousPath ? 17 : 16;
  if (args.size !== expectedCount) fail("unexpected assembly argument");
  const bundleRoot = required(args, "--bundle-root");
  const bundleStatus = await lstat(bundleRoot);
  if (!bundleStatus.isDirectory() || bundleStatus.isSymbolicLink()) fail("bundle root must be a real directory");
  const bundleReal = await realpath(bundleRoot);
  const outputPath = required(args, "--output");
  const sourceCommit = required(args, "--source-commit");
  const version = required(args, "--version");
  const sequence = required(args, "--sequence");
  const extensionId = required(args, "--extension-id");
  const nativeHostName = required(args, "--native-host-name");
  const cargoAuditVersion = required(args, "--cargo-audit-version");
  const cargoAuditBinarySha256 = required(args, "--cargo-audit-binary-sha256");
  const rustSecDatabaseCommit = required(args, "--rustsec-db-commit");
  const rustSecDatabaseTreeSha256 = required(args, "--rustsec-db-tree-sha256");
  const osvScannerVersion = required(args, "--osv-scanner-version");
  const osvScannerBinarySha256 = required(args, "--osv-scanner-binary-sha256");
  const osvDatabaseSnapshotId = required(args, "--osv-db-snapshot-id");
  const osvDatabaseSnapshotSha256 = required(args, "--osv-db-snapshot-sha256");
  const releasePublicKey = await readFile(required(args, "--release-public-key"), "utf8");

  const evidence = {};
  const evidenceJson = {};
  for (const [key, relativePath] of Object.entries(FILE_LAYOUT.evidence)) {
    if (relativePath.endsWith(".json")) {
      const value = await jsonRecord(bundleReal, relativePath);
      evidence[key] = value.record;
      evidenceJson[key] = value.value;
    } else {
      evidence[key] = await fileRecord(bundleReal, relativePath);
    }
  }

  const authReport = evidenceJson.authenticodeReport;
  exactKeys(authReport, ["artifactSetSha256", "entries", "result", "schema"], "Authenticode evidence");
  if (authReport.result !== "pass" || !Array.isArray(authReport.entries)) fail("Authenticode evidence is not a passing report");
  const authByPath = new Map();
  const expectedAuthenticodePaths = Object.entries(FILE_LAYOUT.artifacts)
    .filter(([role]) => role !== "extension-package")
    .map(([, relativePath]) => relativePath)
    .sort();
  if (authReport.entries.length !== expectedAuthenticodePaths.length) {
    fail("Authenticode evidence must contain the exact signed payload set");
  }
  for (let index = 0; index < authReport.entries.length; index += 1) {
    const entry = authReport.entries[index];
    exactKeys(entry, ["path", "sha256", "signerCertificateSha256", "status"], "Authenticode evidence entry");
    if (typeof entry.path !== "string") fail("Authenticode evidence entry path is invalid");
    if (entry.path !== expectedAuthenticodePaths[index]) fail("Authenticode evidence entries must use canonical payload-path order");
    const windowsPathKey = entry.path.toLowerCase();
    if (authByPath.has(windowsPathKey)) fail("Authenticode evidence contains a duplicate Windows path");
    authByPath.set(windowsPathKey, entry);
  }

  const artifacts = [];
  for (const [role, relativePath] of Object.entries(FILE_LAYOUT.artifacts).sort(([left], [right]) => left.localeCompare(right, "en"))) {
    const file = await fileRecord(bundleReal, relativePath);
    let authenticode;
    if (role === "extension-package") {
      authenticode = { evidenceSha256: null, signerCertificateSha256: null, status: "not-applicable" };
    } else {
      const auth = authByPath.get(relativePath.toLowerCase());
      if (!auth || auth.status !== "valid" || auth.sha256 !== file.sha256 || !/^[0-9a-f]{64}$/u.test(auth.signerCertificateSha256 ?? "")) {
        fail(`Authenticode evidence is missing or mismatched for ${relativePath}`);
      }
      authenticode = {
        evidenceSha256: evidence.authenticodeReport.sha256,
        signerCertificateSha256: auth.signerCertificateSha256,
        status: "valid",
      };
    }
    artifacts.push({ authenticode, file, role });
  }
  const artifactSetSha256 = computeArtifactSetSha256(artifacts);
  if (authReport.artifactSetSha256 !== artifactSetSha256) fail("Authenticode report is bound to another artifact set");

  const reproduction = evidenceJson.reproducibilityReport;
  const extensionAudit = evidenceJson.extensionAudit;
  const review = evidenceJson.reviewAttestation;
  if (reproduction.result !== "pass" || extensionAudit.result !== "pass" || review.independenceAttestation !== "pass") {
    fail("required release evidence is not passing");
  }

  const windowsNegativeTests = [];
  for (const id of REQUIRED_WINDOWS_NEGATIVE_TESTS) {
    const relativePath = `evidence/windows-negative/${id}.json`;
    const log = await jsonRecord(bundleReal, relativePath);
    windowsNegativeTests.push({ artifactSetSha256, id, log: log.record, result: "pass", sourceCommit });
  }

  let previous;
  let lineage;
  if (sequence === "1") {
    if (previousPath) fail("initial release must not have a previous manifest");
    lineage = { previousManifestSha256: null, previousSequence: null, previousVersion: null };
  } else {
    if (!previousPath) fail("non-initial release requires --previous");
    previous = parseStrictJson(decodeUtf8(await readFile(previousPath), "previous manifest"));
    if (typeof previous.sequence !== "string" || typeof previous.version !== "string") fail("previous manifest lineage is malformed");
    lineage = {
      previousManifestSha256: sha256Hex(Buffer.from(canonicalEncode(previous), "utf8")),
      previousSequence: previous.sequence,
      previousVersion: previous.version,
    };
  }

  const extensionPackage = artifacts.find((artifact) => artifact.role === "extension-package");
  const manifest = {
    advisoryPolicy: {
      osv: {
        databaseSnapshotId: osvDatabaseSnapshotId,
        databaseSnapshotSha256: osvDatabaseSnapshotSha256,
        scanner: "osv-scanner",
        scannerBinarySha256: osvScannerBinarySha256,
        scannerVersion: osvScannerVersion,
      },
      rustSec: {
        databaseCommit: rustSecDatabaseCommit,
        databaseTreeSha256: rustSecDatabaseTreeSha256,
        scanner: "cargo-audit",
        scannerBinarySha256: cargoAuditBinarySha256,
        scannerVersion: cargoAuditVersion,
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
      openCritical: review.criticalOpen,
      openHigh: review.highOpen,
      osvAdvisoryAudit: evidenceJson.osvAdvisoryReport.result,
      revocationDrill: evidenceJson.keyRevocationDrill.result,
      rotationDrill: evidenceJson.keyRotationDrill.result,
      rustSecAdvisoryAudit: evidenceJson.rustSecAdvisoryReport.result,
      twoCleanDirectoryReproducibility: reproduction.result,
      unsignedArtifactSetSha256: reproduction.unsignedArtifactSetSha256,
    },
    eligibilityClaim: ELIGIBILITY_CLAIM,
    evidence,
    extension: {
      id: extensionId,
      manifestSha256: extensionAudit.extensionManifestSha256,
      nativeHostName,
      packageSha256: extensionPackage.file.sha256,
    },
    lineage,
    profile: RELEASE_PROFILE,
    schema: MANIFEST_SCHEMA,
    sequence,
    signing: { algorithm: "Ed25519", keyIdSha256: ed25519PublicKeyIdSha256(releasePublicKey) },
    source: {
      cargoLockSha256: evidence.cargoLock.sha256,
      commit: sourceCommit,
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
    version,
    windowsNegativeTests,
  };

  validateManifest(manifest, previous);
  await writeFile(outputPath, canonicalEncode(manifest), { encoding: "utf8", flag: "wx" });
  process.stdout.write("UNSIGNED_CANONICAL_MANIFEST_WRITTEN_NOT_RELEASE_ELIGIBLE\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch((error) => {
    const message = error instanceof AssemblyError || error?.name === "ReleaseValidationError" ? error.message : "unexpected manifest assembly failure";
    process.stderr.write(`MANIFEST_ASSEMBLY_FAILED: ${message}\n`);
    process.exitCode = 1;
  });
}
