import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { lstat, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  NATIVE_HOST_NAME,
  validateReleaseNativeManifest,
} from "../../extension/native-host/validate-manifest.mjs";

export const MANIFEST_SCHEMA = "your-wallet-private-mainnet-canary-release-v1";
export const RELEASE_PROFILE = "private-mainnet-canary";
export const ELIGIBILITY_CLAIM = "private-mainnet-canary-candidate";
export const REQUIRED_ARTIFACT_PATHS = Object.freeze({
  "approval-ui-exe": "payload/approval-ui.exe",
  "broker-exe": "payload/broker.exe",
  "dashboard-exe": "payload/dashboard.exe",
  "extension-package": "payload/extension-package.zip",
  installer: "payload/your-wallet-canary.msi",
  "key-agent-exe": "payload/key-agent.exe",
  "native-host-exe": "payload/native-host.exe",
  "secret-input-ui-exe": "payload/secret-input-ui.exe",
});
export const REQUIRED_ARTIFACT_ROLES = Object.freeze(Object.keys(REQUIRED_ARTIFACT_PATHS).sort());
export const REQUIRED_EVIDENCE_PATHS = Object.freeze({
  authenticodeReport: "evidence/authenticode.json",
  cargo: "evidence/cargo-vv.txt",
  cargoLock: "evidence/Cargo.lock",
  dependencyInventory: "evidence/dependencies.json",
  extensionAudit: "evidence/extension-audit.json",
  installerAclNegative: "evidence/installer-acl-negative.json",
  keyRevocationDrill: "evidence/key-revocation-drill.json",
  keyRotationDrill: "evidence/key-rotation-drill.json",
  licenseInventory: "evidence/licenses.json",
  nativeHostManifest: "evidence/native-host-manifest.json",
  nativeHostRegistration: "evidence/native-host-registration.json",
  osvAdvisoryReport: "evidence/osv-advisory.json",
  osvRawReport: "evidence/osv-raw.json",
  reproducibilityReport: "evidence/reproducibility.json",
  reviewAttestation: "evidence/review-attestation.json",
  reviewPublicKey: "evidence/review-public-key.pem",
  reviewSignature: "evidence/review-attestation.sig",
  rustSecAdvisoryReport: "evidence/rustsec-advisory.json",
  rustSecRawReport: "evidence/rustsec-raw.json",
  rustToolchain: "evidence/rust-toolchain.toml",
  rustc: "evidence/rustc-vv.txt",
  sbomSpdx: "evidence/sbom.spdx.json",
  sourceArchive: "evidence/source.zip",
  vendorInventory: "evidence/vendor-inventory.json",
});
export const REQUIRED_WINDOWS_NEGATIVE_TESTS = Object.freeze([
  "helper-binary-hash-mismatch",
  "helper-binary-reparse-point-rejected",
  "helper-binary-signing-leaf-mismatch",
  "helper-child-identity-mismatch",
  "helper-handle-inheritance-allowlist",
  "helper-job-kill-on-close",
  "helper-no-network-sandbox",
  "named-pipe-current-sid-dacl-denies-other-user",
  "named-pipe-first-instance-squatting",
  "named-pipe-rejects-remote-client",
  "native-host-registry-wrong-extension-id",
  "vault-crash-after-replace",
  "vault-crash-before-replace",
  "vault-file-acl-denies-other-user",
  "vault-reparse-point-rejected",
  "vault-rollback-detected",
  "virtual-lock-failure",
]);
export const REQUIRED_REVIEW_SCOPE = Object.freeze([
  "browser-origin-document-lifetime",
  "canonical-encoding",
  "chain-rpc-ssrf",
  "dependency-advisory-license",
  "display-sign-binding",
  "eip712-and-high-risk-signing",
  "entropy-key-lifecycle",
  "nonce-broadcast",
  "recovery",
  "release-update",
  "secret-input-memory",
  "vault-derivation-signing",
]);

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_NODES = 50_000;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const COMMIT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const DECIMAL_RE = /^(?:0|[1-9][0-9]*)$/u;
const EXTENSION_ID_RE = /^[a-p]{32}$/u;
const NATIVE_HOST_RE = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/u;
const SEMVER_RE = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const ALLOWED_LICENSE_IDENTIFIERS = new Set([
  "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0", "ISC", "MIT",
  "OFL-1.1", "Ubuntu-font-1.0", "Unicode-3.0", "Unlicense", "Zlib",
]);

export class ReleaseValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ReleaseValidationError";
  }
}

function fail(message) {
  throw new ReleaseValidationError(message);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

export function decodeUtf8(bytes, label = "input") {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
}

export function parseStrictJson(text) {
  if (typeof text !== "string") fail("JSON input must be text");
  if (Buffer.byteLength(text, "utf8") > MAX_JSON_BYTES) fail("JSON input exceeds the 1 MiB limit");

  let offset = 0;
  let nodes = 0;

  function bumpNode() {
    nodes += 1;
    if (nodes > MAX_JSON_NODES) fail("JSON node limit exceeded");
  }

  function skipWhitespace() {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset])) offset += 1;
  }

  function parseString() {
    if (text[offset] !== '"') fail(`expected string at byte ${offset}`);
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch {
          fail(`invalid JSON string at byte ${start}`);
        }
      }
      if (character === "\\") {
        offset += 1;
        if (offset >= text.length) fail(`unterminated escape at byte ${start}`);
        if (text[offset] === "u") {
          const digits = text.slice(offset + 1, offset + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(digits)) fail(`invalid Unicode escape at byte ${offset}`);
          offset += 5;
        } else {
          if (!/["\\/bfnrt]/u.test(text[offset])) fail(`invalid escape at byte ${offset}`);
          offset += 1;
        }
        continue;
      }
      if (character.charCodeAt(0) < 0x20) fail(`unescaped control character at byte ${offset}`);
      offset += 1;
    }
    fail(`unterminated string at byte ${start}`);
  }

  function parseValue(depth) {
    if (depth > MAX_JSON_DEPTH) fail("JSON depth limit exceeded");
    skipWhitespace();
    bumpNode();
    const character = text[offset];
    if (character === '"') return parseString();
    if (character === "{") {
      offset += 1;
      const result = {};
      const keys = new Set();
      skipWhitespace();
      if (text[offset] === "}") {
        offset += 1;
        return result;
      }
      while (offset < text.length) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) fail(`duplicate JSON member: ${key}`);
        keys.add(key);
        skipWhitespace();
        if (text[offset] !== ":") fail(`expected ':' at byte ${offset}`);
        offset += 1;
        result[key] = parseValue(depth + 1);
        skipWhitespace();
        if (text[offset] === "}") {
          offset += 1;
          return result;
        }
        if (text[offset] !== ",") fail(`expected ',' at byte ${offset}`);
        offset += 1;
      }
      fail("unterminated object");
    }
    if (character === "[") {
      offset += 1;
      const result = [];
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return result;
      }
      while (offset < text.length) {
        result.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[offset] === "]") {
          offset += 1;
          return result;
        }
        if (text[offset] !== ",") fail(`expected ',' at byte ${offset}`);
        offset += 1;
      }
      fail("unterminated array");
    }
    for (const [token, value] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(token, offset)) {
        offset += token.length;
        return value;
      }
    }
    const numberMatch = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (numberMatch) {
      offset += numberMatch[0].length;
      const number = Number(numberMatch[0]);
      if (!Number.isFinite(number)) fail("non-finite JSON number");
      return number;
    }
    fail(`invalid JSON value at byte ${offset}`);
  }

  const value = parseValue(0);
  skipWhitespace();
  if (offset !== text.length) fail(`trailing JSON data at byte ${offset}`);
  return value;
}

export function canonicalEncode(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    if (/[^\u0009\u000a\u000d\u0020-\u007e]/u.test(value)) fail("canonical manifest strings must be printable ASCII");
    return JSON.stringify(value);
  }
  if (typeof value === "number") fail("canonical release manifests encode all integers as decimal strings");
  if (Array.isArray(value)) return `[${value.map(canonicalEncode).join(",")}]`;
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${canonicalEncode(key)}:${canonicalEncode(value[key])}`).join(",")}}`;
  }
  fail("unsupported value in canonical release manifest");
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireObject(value, label, keys) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} members must be exactly: ${expected.join(", ")}`);
  }
  return value;
}

function requireArray(value, label, maxLength = 128) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  if (value.length > maxLength) fail(`${label} exceeds its item limit`);
  return value;
}

function requireString(value, label, pattern, maximum = 256) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) fail(`${label} must be a bounded non-empty string`);
  if (/[^\u0020-\u007e]/u.test(value)) fail(`${label} must contain printable ASCII only`);
  if (pattern && !pattern.test(value)) fail(`${label} has an invalid format`);
  return value;
}

function requireExact(value, expected, label) {
  if (value !== expected) fail(`${label} must be ${JSON.stringify(expected)}`);
}

function requireReviewedLicense(expression, label) {
  requireString(expression, label, /^[A-Za-z0-9+().: /-]+$/u, 256);
  const identifiers = expression.match(/[A-Za-z0-9][A-Za-z0-9.+-]*/gu) ?? [];
  for (const identifier of identifiers) {
    if (!["AND", "OR", "WITH"].includes(identifier) && !ALLOWED_LICENSE_IDENTIFIERS.has(identifier)) fail(`${label} contains an unreviewed license identifier`);
  }
}

function validateRelativePath(value, label, requiredPrefix) {
  requireString(value, label, /^[A-Za-z0-9._/-]+$/u, 240);
  if (value.includes("\\") || value.startsWith("/") || /^[A-Za-z]:/u.test(value)) fail(`${label} must use a relative forward-slash path`);
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) fail(`${label} contains a forbidden path segment`);
  if (requiredPrefix && !value.startsWith(`${requiredPrefix}/`)) fail(`${label} must be below ${requiredPrefix}/`);
  return value;
}

function validateFileRecord(value, label, requiredPrefix) {
  const record = requireObject(value, label, ["bytes", "path", "sha256"]);
  validateRelativePath(record.path, `${label}.path`, requiredPrefix);
  requireString(record.sha256, `${label}.sha256`, SHA256_RE, 64);
  requireString(record.bytes, `${label}.bytes`, DECIMAL_RE, 32);
  return record;
}

function validateSemver(value, label) {
  const match = requireString(value, label, SEMVER_RE, 64).match(SEMVER_RE);
  if (!match) fail(`${label} is not a release semantic version`);
  return match.slice(1).map((part) => BigInt(part));
}

function compareSemver(left, right) {
  const a = validateSemver(left, "current version");
  const b = validateSemver(right, "previous version");
  for (let index = 0; index < a.length; index += 1) {
    if (a[index] > b[index]) return 1;
    if (a[index] < b[index]) return -1;
  }
  return 0;
}

export function computeArtifactSetSha256(artifacts) {
  const summaries = artifacts
    .map((artifact) => ({ bytes: artifact.file.bytes, path: artifact.file.path, role: artifact.role, sha256: artifact.file.sha256 }))
    .sort((left, right) => left.role.localeCompare(right.role, "en"));
  return sha256Hex(Buffer.from(canonicalEncode(summaries), "utf8"));
}

function validateArtifact(value, index) {
  const label = `artifacts[${index}]`;
  const artifact = requireObject(value, label, ["authenticode", "file", "role"]);
  requireString(artifact.role, `${label}.role`, /^[a-z0-9-]+$/u, 64);
  const expectedPath = REQUIRED_ARTIFACT_PATHS[artifact.role];
  if (expectedPath === undefined) fail(`${label}.role is not a reviewed artifact role`);
  validateFileRecord(artifact.file, `${label}.file`, "payload");
  requireExact(artifact.file.path, expectedPath, `${label}.file.path`);
  const authenticode = requireObject(artifact.authenticode, `${label}.authenticode`, ["evidenceSha256", "signerCertificateSha256", "status"]);
  if (artifact.role === "extension-package") {
    requireExact(authenticode.status, "not-applicable", `${label}.authenticode.status`);
    requireExact(authenticode.evidenceSha256, null, `${label}.authenticode.evidenceSha256`);
    requireExact(authenticode.signerCertificateSha256, null, `${label}.authenticode.signerCertificateSha256`);
  } else {
    requireExact(authenticode.status, "valid", `${label}.authenticode.status`);
    requireString(authenticode.evidenceSha256, `${label}.authenticode.evidenceSha256`, SHA256_RE, 64);
    requireString(authenticode.signerCertificateSha256, `${label}.authenticode.signerCertificateSha256`, SHA256_RE, 64);
  }
  return artifact;
}

function validateEvidence(value) {
  const keys = Object.keys(REQUIRED_EVIDENCE_PATHS);
  const evidence = requireObject(value, "evidence", keys);
  for (const key of keys) {
    validateFileRecord(evidence[key], `evidence.${key}`, "evidence");
    requireExact(evidence[key].path, REQUIRED_EVIDENCE_PATHS[key], `evidence.${key}.path`);
  }
  return evidence;
}

function validateCore(manifest) {
  const top = requireObject(manifest, "manifest", [
    "advisoryPolicy", "artifactSetSha256", "artifacts", "assurances", "eligibilityClaim", "evidence", "extension",
    "lineage", "profile", "schema", "sequence", "signing", "source", "toolchain", "version",
    "windowsNegativeTests",
  ]);
  requireExact(top.schema, MANIFEST_SCHEMA, "manifest.schema");
  requireExact(top.profile, RELEASE_PROFILE, "manifest.profile");
  requireExact(top.eligibilityClaim, ELIGIBILITY_CLAIM, "manifest.eligibilityClaim");
  validateSemver(top.version, "manifest.version");
  requireString(top.sequence, "manifest.sequence", /^[1-9][0-9]*$/u, 32);

  const advisoryPolicy = requireObject(top.advisoryPolicy, "manifest.advisoryPolicy", ["osv", "rustSec"]);
  const rustSec = requireObject(advisoryPolicy.rustSec, "manifest.advisoryPolicy.rustSec", ["databaseCommit", "databaseTreeSha256", "scanner", "scannerBinarySha256", "scannerVersion"]);
  requireExact(rustSec.scanner, "cargo-audit", "manifest.advisoryPolicy.rustSec.scanner");
  validateSemver(rustSec.scannerVersion, "manifest.advisoryPolicy.rustSec.scannerVersion");
  requireString(rustSec.scannerBinarySha256, "manifest.advisoryPolicy.rustSec.scannerBinarySha256", SHA256_RE, 64);
  requireString(rustSec.databaseCommit, "manifest.advisoryPolicy.rustSec.databaseCommit", COMMIT_RE, 64);
  requireString(rustSec.databaseTreeSha256, "manifest.advisoryPolicy.rustSec.databaseTreeSha256", SHA256_RE, 64);
  const osv = requireObject(advisoryPolicy.osv, "manifest.advisoryPolicy.osv", ["databaseSnapshotId", "databaseSnapshotSha256", "scanner", "scannerBinarySha256", "scannerVersion"]);
  requireExact(osv.scanner, "osv-scanner", "manifest.advisoryPolicy.osv.scanner");
  validateSemver(osv.scannerVersion, "manifest.advisoryPolicy.osv.scannerVersion");
  requireString(osv.scannerBinarySha256, "manifest.advisoryPolicy.osv.scannerBinarySha256", SHA256_RE, 64);
  requireString(osv.databaseSnapshotId, "manifest.advisoryPolicy.osv.databaseSnapshotId", /^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/u, 20);
  requireString(osv.databaseSnapshotSha256, "manifest.advisoryPolicy.osv.databaseSnapshotSha256", SHA256_RE, 64);

  const source = requireObject(top.source, "manifest.source", ["cargoLockSha256", "commit", "dirty", "rustToolchainSha256", "treeSha256", "vendorTreeSha256"]);
  requireString(source.commit, "manifest.source.commit", COMMIT_RE, 64);
  requireExact(source.dirty, "no", "manifest.source.dirty");
  for (const key of ["cargoLockSha256", "rustToolchainSha256", "treeSha256", "vendorTreeSha256"]) requireString(source[key], `manifest.source.${key}`, SHA256_RE, 64);

  const toolchain = requireObject(top.toolchain, "manifest.toolchain", ["cargoEvidenceSha256", "rustcEvidenceSha256", "target", "windowsRunnerImage"]);
  requireExact(toolchain.target, "x86_64-pc-windows-msvc", "manifest.toolchain.target");
  requireExact(toolchain.windowsRunnerImage, "windows-2025", "manifest.toolchain.windowsRunnerImage");
  requireString(toolchain.cargoEvidenceSha256, "manifest.toolchain.cargoEvidenceSha256", SHA256_RE, 64);
  requireString(toolchain.rustcEvidenceSha256, "manifest.toolchain.rustcEvidenceSha256", SHA256_RE, 64);

  const assuranceKeys = [
    "extensionPermissionAudit", "extensionRemoteCodeAudit", "independentReview", "installerAclNegativeTest",
    "lockedBuild", "nativeHostRegistration", "offlineBuild", "openCritical", "openHigh",
    "osvAdvisoryAudit", "revocationDrill", "rotationDrill", "rustSecAdvisoryAudit",
    "twoCleanDirectoryReproducibility", "unsignedArtifactSetSha256",
  ];
  const assurances = requireObject(top.assurances, "manifest.assurances", assuranceKeys);
  for (const key of assuranceKeys.filter((key) => !["openCritical", "openHigh", "unsignedArtifactSetSha256"].includes(key))) {
    requireExact(assurances[key], "pass", `manifest.assurances.${key}`);
  }
  requireExact(assurances.openCritical, "0", "manifest.assurances.openCritical");
  requireExact(assurances.openHigh, "0", "manifest.assurances.openHigh");
  requireString(assurances.unsignedArtifactSetSha256, "manifest.assurances.unsignedArtifactSetSha256", SHA256_RE, 64);

  const extension = requireObject(top.extension, "manifest.extension", ["id", "manifestSha256", "nativeHostName", "packageSha256"]);
  requireString(extension.id, "manifest.extension.id", EXTENSION_ID_RE, 32);
  requireString(extension.nativeHostName, "manifest.extension.nativeHostName", NATIVE_HOST_RE, 128);
  requireExact(extension.nativeHostName, NATIVE_HOST_NAME, "manifest.extension.nativeHostName");
  requireString(extension.manifestSha256, "manifest.extension.manifestSha256", SHA256_RE, 64);
  requireString(extension.packageSha256, "manifest.extension.packageSha256", SHA256_RE, 64);

  const signing = requireObject(top.signing, "manifest.signing", ["algorithm", "keyIdSha256"]);
  requireExact(signing.algorithm, "Ed25519", "manifest.signing.algorithm");
  requireString(signing.keyIdSha256, "manifest.signing.keyIdSha256", SHA256_RE, 64);

  const artifacts = requireArray(top.artifacts, "manifest.artifacts", 32).map(validateArtifact);
  const roles = artifacts.map((artifact) => artifact.role).sort();
  if (roles.length !== REQUIRED_ARTIFACT_ROLES.length || roles.some((role, index) => role !== REQUIRED_ARTIFACT_ROLES[index])) {
    fail(`artifact roles must be exactly: ${REQUIRED_ARTIFACT_ROLES.join(", ")}`);
  }
  const artifactPaths = new Set(artifacts.map((artifact) => artifact.file.path));
  if (artifactPaths.size !== artifacts.length) fail("artifact paths must be unique");
  const computedArtifactSet = computeArtifactSetSha256(artifacts);
  requireExact(top.artifactSetSha256, computedArtifactSet, "manifest.artifactSetSha256");
  const extensionArtifact = artifacts.find((artifact) => artifact.role === "extension-package");
  requireExact(extension.packageSha256, extensionArtifact.file.sha256, "manifest.extension.packageSha256");

  const evidence = validateEvidence(top.evidence);
  requireExact(source.cargoLockSha256, evidence.cargoLock.sha256, "manifest.source.cargoLockSha256");
  requireExact(source.rustToolchainSha256, evidence.rustToolchain.sha256, "manifest.source.rustToolchainSha256");
  requireExact(source.treeSha256, evidence.sourceArchive.sha256, "manifest.source.treeSha256");
  requireExact(source.vendorTreeSha256, evidence.vendorInventory.sha256, "manifest.source.vendorTreeSha256");
  requireExact(toolchain.rustcEvidenceSha256, evidence.rustc.sha256, "manifest.toolchain.rustcEvidenceSha256");
  requireExact(toolchain.cargoEvidenceSha256, evidence.cargo.sha256, "manifest.toolchain.cargoEvidenceSha256");
  const authEvidenceHash = evidence.authenticodeReport.sha256;
  const signedArtifacts = artifacts.filter((artifact) => artifact.role !== "extension-package");
  for (const artifact of signedArtifacts) requireExact(artifact.authenticode.evidenceSha256, authEvidenceHash, `${artifact.role} Authenticode evidence`);
  const signers = new Set(signedArtifacts.map((artifact) => artifact.authenticode.signerCertificateSha256));
  if (signers.size !== 1) fail("all Windows payloads must bind to one reviewed Authenticode signer for this profile");

  const lineage = requireObject(top.lineage, "manifest.lineage", ["previousManifestSha256", "previousSequence", "previousVersion"]);
  if (top.sequence === "1") {
    for (const key of Object.keys(lineage)) requireExact(lineage[key], null, `manifest.lineage.${key}`);
  } else {
    requireString(lineage.previousManifestSha256, "manifest.lineage.previousManifestSha256", SHA256_RE, 64);
    requireString(lineage.previousSequence, "manifest.lineage.previousSequence", /^[1-9][0-9]*$/u, 32);
    validateSemver(lineage.previousVersion, "manifest.lineage.previousVersion");
  }

  const tests = requireArray(top.windowsNegativeTests, "manifest.windowsNegativeTests", 64);
  if (tests.length !== REQUIRED_WINDOWS_NEGATIVE_TESTS.length) fail("the exact Windows negative-test evidence set is required");
  tests.forEach((test, index) => {
    const item = requireObject(test, `manifest.windowsNegativeTests[${index}]`, ["artifactSetSha256", "id", "log", "result", "sourceCommit"]);
    requireExact(item.id, REQUIRED_WINDOWS_NEGATIVE_TESTS[index], `manifest.windowsNegativeTests[${index}].id`);
    requireExact(item.result, "pass", `Windows negative test ${item.id}`);
    requireExact(item.sourceCommit, source.commit, `Windows negative test ${item.id} source binding`);
    requireExact(item.artifactSetSha256, top.artifactSetSha256, `Windows negative test ${item.id} artifact binding`);
    validateFileRecord(item.log, `Windows negative test ${item.id} log`, "evidence/windows-negative");
    requireExact(item.log.path, `evidence/windows-negative/${item.id}.json`, `Windows negative test ${item.id} log path`);
  });

  const allFiles = [
    ...artifacts.map((artifact) => artifact.file),
    ...Object.values(evidence),
    ...tests.map((test) => test.log),
  ];
  const allPaths = new Set();
  for (const file of allFiles) {
    const windowsPathKey = file.path.toLowerCase();
    if (allPaths.has(windowsPathKey)) fail(`file record path is reused under Windows path rules: ${file.path}`);
    allPaths.add(windowsPathKey);
  }

  return { artifacts, evidence, files: allFiles, source, top };
}

export function validateManifest(manifest, previousManifest) {
  const current = validateCore(manifest);
  if (current.top.sequence === "1") {
    if (previousManifest !== undefined && previousManifest !== null) fail("initial release must not be verified with a previous manifest");
    return current;
  }
  if (previousManifest === undefined || previousManifest === null) fail("a non-initial release requires the exact previous manifest");
  const previous = validateCore(previousManifest);
  if (current.top.extension.id !== previous.top.extension.id) {
    fail("stable extension identity changed across release lineage");
  }
  const expectedSequence = (BigInt(previous.top.sequence) + 1n).toString();
  requireExact(current.top.sequence, expectedSequence, "manifest.sequence");
  requireExact(current.top.lineage.previousSequence, previous.top.sequence, "manifest.lineage.previousSequence");
  requireExact(current.top.lineage.previousVersion, previous.top.version, "manifest.lineage.previousVersion");
  const previousHash = sha256Hex(Buffer.from(canonicalEncode(previous.top), "utf8"));
  requireExact(current.top.lineage.previousManifestSha256, previousHash, "manifest.lineage.previousManifestSha256");
  if (compareSemver(current.top.version, previous.top.version) <= 0) fail("release version rollback or reuse is forbidden");
  return current;
}

async function assertNoReparseComponents(root, relativePath) {
  const rootReal = await realpath(root);
  let current = rootReal;
  for (const segment of relativePath.split("/")) {
    current = path.join(current, segment);
    const status = await lstat(current);
    if (status.isSymbolicLink()) fail(`release bundle path must not traverse a symbolic link: ${relativePath}`);
  }
  const fileReal = await realpath(current);
  const relative = path.relative(rootReal, fileReal);
  if (relative.startsWith("..") || path.isAbsolute(relative)) fail(`release bundle path escapes its root: ${relativePath}`);
  return fileReal;
}

function asciiPathCompare(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function expectedBundleDirectories(files) {
  const directories = new Set();
  for (const file of files) {
    let directory = path.posix.dirname(file.path);
    while (directory !== ".") {
      directories.add(directory.toLowerCase());
      directory = path.posix.dirname(directory);
    }
  }
  return directories;
}

async function verifyExactBundleTree(bundleRoot, files) {
  const expectedFiles = new Set(files.map((file) => file.path.toLowerCase()));
  const expectedDirectories = expectedBundleDirectories(files);
  const seenFiles = new Set();
  const seenDirectories = new Set();

  async function visit(absoluteDirectory, relativeDirectory) {
    const entries = await readdir(absoluteDirectory, { withFileTypes: true });
    for (const entry of entries) {
      const relativePath = relativeDirectory ? `${relativeDirectory}/${entry.name}` : entry.name;
      if (!/^[A-Za-z0-9._/-]+$/u.test(relativePath)) fail(`release bundle contains an unreviewed path: ${relativePath}`);
      const windowsPathKey = relativePath.toLowerCase();
      const absolutePath = path.join(absoluteDirectory, entry.name);
      const status = await lstat(absolutePath);
      if (status.isSymbolicLink()) fail(`release bundle contains a symbolic link: ${relativePath}`);
      if (entry.isDirectory() && status.isDirectory()) {
        if (!expectedDirectories.has(windowsPathKey) || seenDirectories.has(windowsPathKey)) {
          fail(`release bundle contains an unexpected or duplicate directory: ${relativePath}`);
        }
        seenDirectories.add(windowsPathKey);
        await visit(absolutePath, relativePath);
      } else if (entry.isFile() && status.isFile()) {
        if (!expectedFiles.has(windowsPathKey) || seenFiles.has(windowsPathKey)) {
          fail(`release bundle contains an unexpected or duplicate file: ${relativePath}`);
        }
        if (status.nlink !== 1) fail(`release bundle file must not be hard-linked: ${relativePath}`);
        seenFiles.add(windowsPathKey);
      } else {
        fail(`release bundle contains a non-regular entry: ${relativePath}`);
      }
    }
  }

  await visit(bundleRoot, "");
  if (seenFiles.size !== expectedFiles.size || [...expectedFiles].some((file) => !seenFiles.has(file))) {
    fail("release bundle does not contain the exact manifest-bound file set");
  }
  if (seenDirectories.size !== expectedDirectories.size || [...expectedDirectories].some((directory) => !seenDirectories.has(directory))) {
    fail("release bundle does not contain the exact manifest-bound directory set");
  }
}

export async function verifyBundleFiles(validated, bundleRoot) {
  const rootStatus = await lstat(bundleRoot);
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) fail("release bundle root must be a real directory");
  await verifyExactBundleTree(bundleRoot, validated.files);
  for (const record of validated.files) {
    const filePath = await assertNoReparseComponents(bundleRoot, record.path);
    const status = await lstat(filePath);
    if (!status.isFile()) fail(`release bundle record is not a regular file: ${record.path}`);
    if (status.nlink !== 1) fail(`release bundle record must not be hard-linked: ${record.path}`);
    if (status.size.toString() !== record.bytes) fail(`release bundle size mismatch: ${record.path}`);
    const contents = await readFile(filePath);
    if (sha256Hex(contents) !== record.sha256) fail(`release bundle hash mismatch: ${record.path}`);
  }
}

async function readVerifiedRecord(bundleRoot, record) {
  const filePath = await assertNoReparseComponents(bundleRoot, record.path);
  const status = await lstat(filePath);
  if (!status.isFile() || status.nlink !== 1 || status.size.toString() !== record.bytes) fail(`evidence file metadata mismatch: ${record.path}`);
  const contents = await readFile(filePath);
  if (sha256Hex(contents) !== record.sha256) fail(`evidence file hash mismatch: ${record.path}`);
  return contents;
}

async function readEvidenceJson(bundleRoot, record, label) {
  const bytes = await readVerifiedRecord(bundleRoot, record);
  try {
    return parseStrictJson(decodeUtf8(bytes, label));
  } catch (error) {
    if (error instanceof ReleaseValidationError) fail(`${label}: ${error.message}`);
    fail(`${label} could not be parsed`);
  }
}

async function readCanonicalEvidenceJson(bundleRoot, record, label) {
  const bytes = await readVerifiedRecord(bundleRoot, record);
  const text = decodeUtf8(bytes, label);
  const value = parseStrictJson(text);
  if (text !== canonicalEncode(value)) fail(`${label} must contain the exact canonical bytes that were signed`);
  return value;
}

function validateBoundAttestation(value, label, schema, current, extraKeys) {
  const attestation = requireObject(value, label, ["artifactSetSha256", "profile", "schema", "sourceCommit", "version", ...extraKeys]);
  requireExact(attestation.schema, schema, `${label}.schema`);
  requireExact(attestation.profile, RELEASE_PROFILE, `${label}.profile`);
  requireExact(attestation.version, current.top.version, `${label}.version`);
  requireExact(attestation.sourceCommit, current.source.commit, `${label}.sourceCommit`);
  requireExact(attestation.artifactSetSha256, current.top.artifactSetSha256, `${label}.artifactSetSha256`);
  return attestation;
}

function parsePublicKey(publicKeyText, label) {
  if (Buffer.byteLength(publicKeyText, "utf8") > 16 * 1024) fail(`${label} exceeds 16 KiB`);
  let publicKey;
  try {
    publicKey = createPublicKey(publicKeyText);
  } catch {
    fail(`${label} could not be decoded`);
  }
  if (publicKey.asymmetricKeyType !== "ed25519") fail(`${label} must be Ed25519`);
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  return { key: publicKey, keyIdSha256: sha256Hex(publicDer) };
}

export function ed25519PublicKeyIdSha256(publicKeyText) {
  return parsePublicKey(publicKeyText, "release public key").keyIdSha256;
}

function verifyEd25519Bytes(message, signatureText, publicKeyText, expectedKeyId, label) {
  const publicKey = parsePublicKey(publicKeyText, `${label} public key`);
  requireExact(expectedKeyId, publicKey.keyIdSha256, `${label} key identifier`);
  if (!verifySignature(null, message, publicKey.key, decodeDetachedSignature(signatureText))) fail(`${label} signature is invalid`);
}

export async function verifyEvidenceAttestations(
  validated,
  bundleRoot,
  expectedReviewerKeyId,
  expectedSignerCertificateSha256,
) {
  const { evidence, source, top } = validated;

  const dependencyInventory = requireObject(
    await readEvidenceJson(bundleRoot, evidence.dependencyInventory, "dependency inventory"),
    "dependency inventory",
    ["cargoLockSha256", "packages", "schema", "sourceCommit", "target"],
  );
  requireExact(dependencyInventory.schema, "your-wallet-cargo-dependency-inventory-v1", "dependency inventory.schema");
  requireExact(dependencyInventory.cargoLockSha256, source.cargoLockSha256, "dependency inventory lockfile binding");
  requireExact(dependencyInventory.sourceCommit, source.commit, "dependency inventory source binding");
  requireExact(dependencyInventory.target, top.toolchain.target, "dependency inventory target binding");
  const dependencyPackages = requireArray(dependencyInventory.packages, "dependency inventory.packages", 4096);
  if (dependencyPackages.length === 0) fail("dependency inventory must not be empty");
  for (let index = 0; index < dependencyPackages.length; index += 1) {
    const pkg = requireObject(dependencyPackages[index], `dependency inventory.packages[${index}]`, ["dependencyIds", "features", "hasBuildScript", "license", "links", "name", "procMacro", "source", "version", "workspace"]);
    requireString(pkg.name, `dependency inventory.packages[${index}].name`, /^[A-Za-z0-9_.-]+$/u, 128);
    requireString(pkg.version, `dependency inventory.packages[${index}].version`, /^[A-Za-z0-9+_.-]+$/u, 64);
    requireReviewedLicense(pkg.license, `dependency inventory.packages[${index}].license`);
    if (!new Set(["crates.io", "workspace"]).has(pkg.source)) fail("dependency inventory contains an unreviewed source kind");
    if (pkg.source === "crates.io" && pkg.license === "NOASSERTION") fail("third-party dependency lacks a declared license");
    if (!new Set(["yes", "no"]).has(pkg.hasBuildScript) || !new Set(["yes", "no"]).has(pkg.procMacro) || !new Set(["yes", "no"]).has(pkg.workspace)) fail("dependency inventory contains an invalid boolean marker");
    if (pkg.links !== null) requireString(pkg.links, `dependency inventory.packages[${index}].links`, /^[A-Za-z0-9_.-]+$/u, 128);
    const dependencyIds = requireArray(pkg.dependencyIds, `dependency inventory.packages[${index}].dependencyIds`, 4096);
    const features = requireArray(pkg.features, `dependency inventory.packages[${index}].features`, 1024);
    dependencyIds.forEach((id, item) => requireString(id, `dependency inventory package ${index} dependency ${item}`, /^[A-Za-z0-9+@_.-]+$/u, 256));
    features.forEach((feature, item) => requireString(feature, `dependency inventory package ${index} feature ${item}`, /^[A-Za-z0-9+_./-]+$/u, 128));
  }

  const licenseInventory = requireObject(
    await readEvidenceJson(bundleRoot, evidence.licenseInventory, "license inventory"),
    "license inventory",
    ["cargoLockSha256", "packages", "schema", "sourceCommit", "target"],
  );
  requireExact(licenseInventory.schema, "your-wallet-license-inventory-v1", "license inventory.schema");
  requireExact(licenseInventory.cargoLockSha256, source.cargoLockSha256, "license inventory lockfile binding");
  requireExact(licenseInventory.sourceCommit, source.commit, "license inventory source binding");
  requireExact(licenseInventory.target, top.toolchain.target, "license inventory target binding");
  const licensePackages = requireArray(licenseInventory.packages, "license inventory.packages", 4096);
  if (licensePackages.length !== dependencyPackages.length) fail("license and dependency inventories cover different package counts");
  for (let index = 0; index < licensePackages.length; index += 1) {
    const pkg = requireObject(licensePackages[index], `license inventory.packages[${index}]`, ["license", "name", "source", "version"]);
    const dependency = dependencyPackages[index];
    for (const key of ["license", "name", "source", "version"]) requireExact(pkg[key], dependency[key], `license inventory package ${index} ${key}`);
  }

  const sbom = requireObject(
    await readEvidenceJson(bundleRoot, evidence.sbomSpdx, "SPDX SBOM"),
    "SPDX SBOM",
    ["SPDXID", "creationInfo", "dataLicense", "documentDescribes", "documentNamespace", "name", "packages", "relationships", "spdxVersion"],
  );
  requireExact(sbom.SPDXID, "SPDXRef-DOCUMENT", "SPDX SBOM.SPDXID");
  requireExact(sbom.dataLicense, "CC0-1.0", "SPDX SBOM.dataLicense");
  requireExact(sbom.spdxVersion, "SPDX-2.3", "SPDX SBOM.spdxVersion");
  requireExact(sbom.name, `your-wallet-${source.commit}`, "SPDX SBOM source binding");
  requireExact(sbom.documentNamespace, `https://spdx.org/spdxdocs/your-wallet-${source.commit}-${source.cargoLockSha256}`, "SPDX SBOM lockfile binding");
  if (requireArray(sbom.packages, "SPDX SBOM.packages", 4096).length !== dependencyPackages.length) fail("SPDX SBOM and dependency inventory cover different package counts");
  requireArray(sbom.documentDescribes, "SPDX SBOM.documentDescribes", 64);
  requireArray(sbom.relationships, "SPDX SBOM.relationships", 65_536);
  const creationInfo = requireObject(sbom.creationInfo, "SPDX SBOM.creationInfo", ["created", "creators"]);
  requireString(creationInfo.created, "SPDX SBOM.creationInfo.created", /^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/u, 20);
  const creators = requireArray(creationInfo.creators, "SPDX SBOM.creationInfo.creators", 8);
  if (canonicalEncode(creators) !== canonicalEncode(["Tool: your-wallet/scripts/release/generate-inventories.mjs"])) fail("SPDX SBOM creator is unexpected");

  const rustSecReport = requireObject(
    await readEvidenceJson(bundleRoot, evidence.rustSecAdvisoryReport, "RustSec advisory evidence"),
    "RustSec advisory evidence",
    ["acceptedWarnings", "cargoLockSha256", "databaseCommit", "databaseTreeSha256", "rawReportSha256", "result", "scanner", "scannerBinarySha256", "scannerVersion", "schema", "sourceCommit", "vulnerabilitiesFound"],
  );
  requireExact(rustSecReport.schema, "your-wallet-rustsec-advisory-evidence-v1", "RustSec advisory evidence.schema");
  requireExact(rustSecReport.result, "pass", "RustSec advisory evidence.result");
  requireExact(rustSecReport.vulnerabilitiesFound, "0", "RustSec vulnerabilitiesFound");
  requireExact(rustSecReport.acceptedWarnings, "0", "RustSec acceptedWarnings");
  requireExact(rustSecReport.sourceCommit, source.commit, "RustSec source binding");
  requireExact(rustSecReport.cargoLockSha256, source.cargoLockSha256, "RustSec Cargo.lock binding");
  requireExact(rustSecReport.scanner, top.advisoryPolicy.rustSec.scanner, "RustSec scanner binding");
  requireExact(rustSecReport.scannerVersion, top.advisoryPolicy.rustSec.scannerVersion, "RustSec scanner-version binding");
  requireExact(rustSecReport.scannerBinarySha256, top.advisoryPolicy.rustSec.scannerBinarySha256, "RustSec scanner-binary binding");
  requireExact(rustSecReport.databaseCommit, top.advisoryPolicy.rustSec.databaseCommit, "RustSec database-commit binding");
  requireExact(rustSecReport.databaseTreeSha256, top.advisoryPolicy.rustSec.databaseTreeSha256, "RustSec database-tree binding");
  requireExact(rustSecReport.rawReportSha256, evidence.rustSecRawReport.sha256, "RustSec raw-report binding");

  const osvReport = requireObject(
    await readEvidenceJson(bundleRoot, evidence.osvAdvisoryReport, "OSV advisory evidence"),
    "OSV advisory evidence",
    ["acceptedFindings", "cargoLockSha256", "databaseSnapshotId", "databaseSnapshotSha256", "rawReportSha256", "result", "scanner", "scannerBinarySha256", "scannerVersion", "schema", "sourceCommit", "vulnerabilitiesFound"],
  );
  requireExact(osvReport.schema, "your-wallet-osv-advisory-evidence-v1", "OSV advisory evidence.schema");
  requireExact(osvReport.result, "pass", "OSV advisory evidence.result");
  requireExact(osvReport.vulnerabilitiesFound, "0", "OSV vulnerabilitiesFound");
  requireExact(osvReport.acceptedFindings, "0", "OSV acceptedFindings");
  requireExact(osvReport.sourceCommit, source.commit, "OSV source binding");
  requireExact(osvReport.cargoLockSha256, source.cargoLockSha256, "OSV Cargo.lock binding");
  requireExact(osvReport.scanner, top.advisoryPolicy.osv.scanner, "OSV scanner binding");
  requireExact(osvReport.scannerVersion, top.advisoryPolicy.osv.scannerVersion, "OSV scanner-version binding");
  requireExact(osvReport.scannerBinarySha256, top.advisoryPolicy.osv.scannerBinarySha256, "OSV scanner-binary binding");
  requireExact(osvReport.databaseSnapshotId, top.advisoryPolicy.osv.databaseSnapshotId, "OSV database-snapshot binding");
  requireExact(osvReport.databaseSnapshotSha256, top.advisoryPolicy.osv.databaseSnapshotSha256, "OSV database hash binding");
  requireExact(osvReport.rawReportSha256, evidence.osvRawReport.sha256, "OSV raw-report binding");

  const reproduction = requireObject(
    await readEvidenceJson(bundleRoot, evidence.reproducibilityReport, "reproducibility evidence"),
    "reproducibility evidence",
    ["firstPayloadSetSha256", "result", "schema", "secondPayloadSetSha256", "sourceCommit", "sourceTreeSha256", "unsignedArtifactSetSha256", "vendorTreeSha256"],
  );
  requireExact(reproduction.schema, "your-wallet-reproducibility-evidence-v1", "reproducibility evidence.schema");
  requireExact(reproduction.result, "pass", "reproducibility evidence.result");
  requireExact(reproduction.sourceCommit, source.commit, "reproducibility source binding");
  requireExact(reproduction.sourceTreeSha256, source.treeSha256, "reproducibility source-tree binding");
  requireExact(reproduction.vendorTreeSha256, source.vendorTreeSha256, "reproducibility vendor binding");
  requireExact(reproduction.unsignedArtifactSetSha256, top.assurances.unsignedArtifactSetSha256, "reproducibility payload binding");
  requireExact(reproduction.firstPayloadSetSha256, reproduction.unsignedArtifactSetSha256, "first clean build payload");
  requireExact(reproduction.secondPayloadSetSha256, reproduction.unsignedArtifactSetSha256, "second clean build payload");

  const extensionAudit = requireObject(
    await readEvidenceJson(bundleRoot, evidence.extensionAudit, "extension audit evidence"),
    "extension audit evidence",
    ["extensionManifestSha256", "packageSha256", "permissionAudit", "remoteCodeAudit", "result", "schema"],
  );
  requireExact(extensionAudit.schema, "your-wallet-extension-static-audit-v1", "extension audit evidence.schema");
  requireExact(extensionAudit.result, "pass", "extension audit evidence.result");
  requireExact(extensionAudit.permissionAudit, "pass", "extension permission audit");
  requireExact(extensionAudit.remoteCodeAudit, "pass", "extension remote-code audit");
  requireExact(extensionAudit.extensionManifestSha256, top.extension.manifestSha256, "extension manifest audit binding");
  requireExact(extensionAudit.packageSha256, top.extension.packageSha256, "extension package audit binding");

  const authenticode = requireObject(
    await readEvidenceJson(bundleRoot, evidence.authenticodeReport, "Authenticode evidence"),
    "Authenticode evidence",
    ["artifactSetSha256", "entries", "result", "schema"],
  );
  requireExact(authenticode.schema, "your-wallet-authenticode-evidence-v1", "Authenticode evidence.schema");
  requireExact(authenticode.result, "pass", "Authenticode evidence.result");
  requireExact(authenticode.artifactSetSha256, top.artifactSetSha256, "Authenticode artifact binding");
  const signedArtifacts = validated.artifacts
    .filter((artifact) => artifact.role !== "extension-package")
    .sort((left, right) => asciiPathCompare(left.file.path, right.file.path));
  const authEntries = requireArray(authenticode.entries, "Authenticode evidence.entries", 32);
  if (authEntries.length !== signedArtifacts.length) fail("Authenticode evidence must cover every signed payload exactly once");
  const seenAuthPaths = new Set();
  authEntries.forEach((entry, index) => {
    const item = requireObject(entry, `Authenticode evidence.entries[${index}]`, ["path", "sha256", "signerCertificateSha256", "status"]);
    const artifact = signedArtifacts[index];
    const windowsPathKey = requireString(item.path, `Authenticode evidence.entries[${index}].path`, /^[A-Za-z0-9._/-]+$/u, 240).toLowerCase();
    if (seenAuthPaths.has(windowsPathKey)) fail("Authenticode evidence contains a duplicate Windows path");
    seenAuthPaths.add(windowsPathKey);
    requireExact(item.path, artifact.file.path, `Authenticode evidence.entries[${index}].path`);
    requireExact(item.sha256, artifact.file.sha256, `Authenticode evidence.entries[${index}].sha256`);
    requireExact(item.status, "valid", `Authenticode evidence.entries[${index}].status`);
    requireExact(item.signerCertificateSha256, artifact.authenticode.signerCertificateSha256, `Authenticode evidence.entries[${index}].signerCertificateSha256`);
    requireExact(item.signerCertificateSha256, expectedSignerCertificateSha256, `Authenticode evidence.entries[${index}] independently pinned signer`);
  });

  const installerArtifact = validated.artifacts.find((artifact) => artifact.role === "installer");
  const installerAcl = requireObject(
    await readEvidenceJson(bundleRoot, evidence.installerAclNegative, "installer ACL evidence"),
    "installer ACL evidence",
    ["extensionId", "installerSha256", "nativeHostManifestSha256", "result", "schema", "tests"],
  );
  requireExact(installerAcl.schema, "your-wallet-installer-acl-evidence-v1", "installer ACL evidence.schema");
  requireExact(installerAcl.result, "pass", "installer ACL evidence.result");
  requireExact(installerAcl.extensionId, top.extension.id, "installer extension-ID binding");
  requireExact(installerAcl.installerSha256, installerArtifact.file.sha256, "installer ACL artifact binding");
  requireExact(installerAcl.nativeHostManifestSha256, evidence.nativeHostManifest.sha256, "installer native-host manifest binding");
  const aclTests = requireArray(installerAcl.tests, "installer ACL evidence.tests", 8);
  const requiredAclTests = ["install-directory-not-user-writable", "native-host-manifest-not-user-writable", "path-reparse-rejected"];
  if (canonicalEncode(aclTests) !== canonicalEncode(requiredAclTests)) fail("installer ACL evidence must contain the exact negative-test set");

  const nativeHostManifest = await readEvidenceJson(bundleRoot, evidence.nativeHostManifest, "native-host manifest");
  const nativeHostValidation = validateReleaseNativeManifest(nativeHostManifest);
  if (!nativeHostValidation.valid) fail("native-host manifest does not match the strict Windows release schema");
  requireExact(nativeHostManifest.name, NATIVE_HOST_NAME, "native-host manifest.name");
  requireExact(nativeHostManifest.name, top.extension.nativeHostName, "native-host manifest name binding");
  requireExact(nativeHostValidation.extensionId, top.extension.id, "native-host manifest extension-ID binding");
  requireString(nativeHostManifest.description, "native-host manifest.description", /^[\u0020-\u007e]+$/u, 128);
  requireString(nativeHostManifest.path, "native-host manifest.path", /^[\u0020-\u007e]+$/u, 32_767);
  requireExact(path.win32.basename(nativeHostManifest.path).toLowerCase(), "native-host.exe", "native-host manifest executable basename");

  const nativeRegistration = requireObject(
    await readEvidenceJson(bundleRoot, evidence.nativeHostRegistration, "native-host registration evidence"),
    "native-host registration evidence",
    ["extensionId", "nativeHostManifestSha256", "nativeHostName", "result", "schema", "tests"],
  );
  requireExact(nativeRegistration.schema, "your-wallet-native-host-registration-evidence-v1", "native-host registration evidence.schema");
  requireExact(nativeRegistration.result, "pass", "native-host registration evidence.result");
  requireExact(nativeRegistration.extensionId, top.extension.id, "native-host extension-ID binding");
  requireExact(nativeRegistration.nativeHostManifestSha256, evidence.nativeHostManifest.sha256, "native-host registration manifest binding");
  requireExact(nativeRegistration.nativeHostName, top.extension.nativeHostName, "native-host name binding");
  const registrationTests = requireArray(nativeRegistration.tests, "native-host registration evidence.tests", 8);
  const requiredRegistrationTests = ["allowed-origin-exact", "registry-user-scope", "wrong-extension-id-rejected"];
  if (canonicalEncode(registrationTests) !== canonicalEncode(requiredRegistrationTests)) fail("native-host registration evidence must contain the exact test set");

  const review = validateBoundAttestation(
    await readCanonicalEvidenceJson(bundleRoot, evidence.reviewAttestation, "independent review attestation"),
    "independent review attestation",
    "your-wallet-independent-security-review-v1",
    validated,
    ["criticalOpen", "highOpen", "independenceAttestation", "reviewerKeyIdSha256", "scope"],
  );
  requireExact(review.independenceAttestation, "pass", "independent review attestation.independenceAttestation");
  requireExact(review.criticalOpen, "0", "independent review attestation.criticalOpen");
  requireExact(review.highOpen, "0", "independent review attestation.highOpen");
  requireString(review.reviewerKeyIdSha256, "independent review attestation.reviewerKeyIdSha256", SHA256_RE, 64);
  verifyExpectedReviewerKeyId(review.reviewerKeyIdSha256, expectedReviewerKeyId);
  if (review.reviewerKeyIdSha256 === top.signing.keyIdSha256) fail("independent reviewer key must differ from the release-manifest key");
  const scope = requireArray(review.scope, "independent review attestation.scope", 32);
  if (canonicalEncode(scope) !== canonicalEncode(REQUIRED_REVIEW_SCOPE)) fail("independent review scope is incomplete or out of canonical order");
  const [reviewSignature, reviewPublicKey] = await Promise.all([
    readVerifiedRecord(bundleRoot, evidence.reviewSignature),
    readVerifiedRecord(bundleRoot, evidence.reviewPublicKey),
  ]);
  verifyEd25519Bytes(
    Buffer.from(canonicalEncode(review), "utf8"),
    reviewSignature.toString("utf8"),
    reviewPublicKey.toString("utf8"),
    review.reviewerKeyIdSha256,
    "independent review attestation",
  );

  for (const [key, schema, label] of [
    ["keyRotationDrill", "your-wallet-key-rotation-drill-v1", "key rotation drill"],
    ["keyRevocationDrill", "your-wallet-key-revocation-drill-v1", "key revocation drill"],
  ]) {
    const drill = requireObject(
      await readEvidenceJson(bundleRoot, evidence[key], label),
      label,
      ["performedAtUtc", "releaseKeyIdSha256", "result", "schema", "sourceCommit", "version"],
    );
    requireExact(drill.schema, schema, `${label}.schema`);
    requireExact(drill.result, "pass", `${label}.result`);
    requireExact(drill.sourceCommit, source.commit, `${label}.sourceCommit`);
    requireExact(drill.version, top.version, `${label}.version`);
    requireExact(drill.releaseKeyIdSha256, top.signing.keyIdSha256, `${label}.releaseKeyIdSha256`);
    requireString(drill.performedAtUtc, `${label}.performedAtUtc`, /^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/u, 20);
  }

  for (let index = 0; index < top.windowsNegativeTests.length; index += 1) {
    const expected = top.windowsNegativeTests[index];
    const log = requireObject(
      await readEvidenceJson(bundleRoot, expected.log, `Windows negative test ${expected.id}`),
      `Windows negative test ${expected.id}`,
      ["artifactSetSha256", "id", "osBuild", "profile", "result", "schema", "sourceCommit"],
    );
    requireExact(log.schema, "your-wallet-windows-negative-test-v1", `Windows negative test ${expected.id}.schema`);
    requireExact(log.id, expected.id, `Windows negative test ${expected.id}.id`);
    requireExact(log.result, "pass", `Windows negative test ${expected.id}.result`);
    requireExact(log.profile, RELEASE_PROFILE, `Windows negative test ${expected.id}.profile`);
    requireExact(log.sourceCommit, source.commit, `Windows negative test ${expected.id}.sourceCommit`);
    requireExact(log.artifactSetSha256, top.artifactSetSha256, `Windows negative test ${expected.id}.artifactSetSha256`);
    requireString(log.osBuild, `Windows negative test ${expected.id}.osBuild`, /^[0-9]+(?:\.[0-9]+){2,3}$/u, 32);
  }
}

function decodeDetachedSignature(text) {
  const compact = text.trim();
  if (!/^[A-Za-z0-9+/]{86}==$/u.test(compact)) fail("detached Ed25519 signature must be canonical base64 for exactly 64 bytes");
  const signature = Buffer.from(compact, "base64");
  if (signature.length !== 64 || signature.toString("base64") !== compact) fail("detached signature base64 is not canonical");
  return signature;
}

export async function verifyDetachedManifestSignature(manifest, signaturePath, publicKeyPath) {
  const [signatureText, publicKeyText] = await Promise.all([
    readFile(signaturePath, "utf8"),
    readFile(publicKeyPath, "utf8"),
  ]);
  const canonical = Buffer.from(canonicalEncode(manifest), "utf8");
  verifyEd25519Bytes(canonical, signatureText, publicKeyText, manifest.signing.keyIdSha256, "release manifest");
}

export function verifyExpectedReleaseKeyId(validated, expectedReleaseKeyId) {
  requireString(
    expectedReleaseKeyId,
    "independently pinned release key identifier",
    SHA256_RE,
    64,
  );
  requireExact(
    validated.top.signing.keyIdSha256,
    expectedReleaseKeyId,
    "independently pinned release key identifier",
  );
}

export function verifyExpectedExtensionId(validated, expectedExtensionId) {
  requireString(
    expectedExtensionId,
    "independently pinned extension identifier",
    EXTENSION_ID_RE,
    32,
  );
  if (validated.top.extension.id !== expectedExtensionId) {
    fail("independently pinned extension identifier mismatch");
  }
}

export function verifyExpectedReviewerKeyId(actualReviewerKeyId, expectedReviewerKeyId) {
  requireString(
    expectedReviewerKeyId,
    "independently pinned reviewer key identifier",
    SHA256_RE,
    64,
  );
  requireExact(
    actualReviewerKeyId,
    expectedReviewerKeyId,
    "independently pinned reviewer key identifier",
  );
}

export function verifyExpectedSignerCertificateSha256(validated, expectedSignerCertificateSha256) {
  requireString(
    expectedSignerCertificateSha256,
    "independently pinned Authenticode signer certificate hash",
    SHA256_RE,
    64,
  );
  for (const artifact of validated.artifacts.filter((item) => item.role !== "extension-package")) {
    requireExact(
      artifact.authenticode.signerCertificateSha256,
      expectedSignerCertificateSha256,
      `${artifact.role} independently pinned Authenticode signer`,
    );
  }
}

export function verifyExpectedPreviousManifestSha256(validated, expectedPreviousManifestSha256) {
  if (validated.top.sequence === "1") {
    if (expectedPreviousManifestSha256 !== undefined && expectedPreviousManifestSha256 !== null) {
      fail("initial release must not supply an independently pinned previous manifest hash");
    }
    return;
  }
  requireString(
    expectedPreviousManifestSha256,
    "independently pinned previous manifest hash",
    SHA256_RE,
    64,
  );
  requireExact(
    validated.top.lineage.previousManifestSha256,
    expectedPreviousManifestSha256,
    "independently pinned previous manifest hash",
  );
}

async function readStrictJsonFile(filePath, requireCanonical = false) {
  const bytes = await readFile(filePath);
  if (bytes.length > MAX_JSON_BYTES) fail("manifest file exceeds the 1 MiB limit");
  const text = decodeUtf8(bytes, "manifest");
  const value = parseStrictJson(text);
  if (requireCanonical && text !== canonicalEncode(value)) fail("signed manifest input must be exact canonical JSON bytes");
  return value;
}

function parseArguments(argv) {
  const [command, ...rest] = argv;
  const values = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    const value = rest[index + 1];
    if (!key?.startsWith("--") || value === undefined || value.startsWith("--")) fail("arguments must be --name value pairs");
    if (values.has(key)) fail(`duplicate argument: ${key}`);
    values.set(key, value);
  }
  return { command, values };
}

function requireArgument(values, name) {
  const value = values.get(name);
  if (!value) fail(`missing required argument ${name}`);
  return value;
}

async function runCli() {
  const { command, values } = parseArguments(process.argv.slice(2));
  if (command === "key-id") {
    if (values.size !== 1) fail("key-id accepts only --public-key");
    const publicKey = await readFile(requireArgument(values, "--public-key"), "utf8");
    process.stdout.write(`${ed25519PublicKeyIdSha256(publicKey)}\n`);
    return;
  }
  if (command === "canonicalize" || command === "canonicalize-json") {
    const input = requireArgument(values, "--input");
    const output = requireArgument(values, "--output");
    if (values.size !== 2) fail("canonicalize accepts only --input and --output");
    const manifest = await readStrictJsonFile(input);
    if (command === "canonicalize") validateCore(manifest);
    await writeFile(output, canonicalEncode(manifest), { encoding: "utf8", flag: "wx" });
    process.stdout.write(command === "canonicalize" ? "CANONICAL_CANDIDATE_WRITTEN_NOT_RELEASE_ELIGIBLE\n" : "CANONICAL_JSON_WRITTEN_NOT_SIGNED\n");
    return;
  }
  if (command === "validate" || command === "verify") {
    const requireCanonical = command === "verify";
    const manifest = await readStrictJsonFile(requireArgument(values, "--manifest"), requireCanonical);
    const previousPath = values.get("--previous");
    const previous = previousPath ? await readStrictJsonFile(previousPath, requireCanonical) : undefined;
    const validated = validateManifest(manifest, previous);
    if (command === "validate") {
      const expected = previousPath ? 2 : 1;
      if (values.size !== expected) fail("validate accepts only --manifest and optional --previous");
      process.stdout.write("STRUCTURALLY_VALID_CANDIDATE_NOT_RELEASE_ELIGIBLE\n");
      return;
    }
    const expectedPreviousManifestSha256 = values.get("--expected-previous-manifest-sha256");
    if (previousPath && !expectedPreviousManifestSha256) fail("non-initial verification requires --expected-previous-manifest-sha256 from the offline checkpoint");
    if (!previousPath && expectedPreviousManifestSha256) fail("initial verification must not supply --expected-previous-manifest-sha256");
    if (values.size !== (previousPath ? 10 : 8)) {
      fail("verify requires --manifest, --signature, --public-key, --bundle-root, --expected-release-key-id, --expected-extension-id, --expected-reviewer-key-id, --expected-signer-certificate-sha256, and paired --previous/--expected-previous-manifest-sha256 for non-initial releases");
    }
    verifyExpectedReleaseKeyId(validated, requireArgument(values, "--expected-release-key-id"));
    verifyExpectedExtensionId(validated, requireArgument(values, "--expected-extension-id"));
    verifyExpectedSignerCertificateSha256(
      validated,
      requireArgument(values, "--expected-signer-certificate-sha256"),
    );
    verifyExpectedPreviousManifestSha256(validated, expectedPreviousManifestSha256);
    const bundleRoot = requireArgument(values, "--bundle-root");
    await verifyBundleFiles(validated, bundleRoot);
    await verifyEvidenceAttestations(
      validated,
      bundleRoot,
      requireArgument(values, "--expected-reviewer-key-id"),
      requireArgument(values, "--expected-signer-certificate-sha256"),
    );
    await verifyDetachedManifestSignature(manifest, requireArgument(values, "--signature"), requireArgument(values, "--public-key"));
    process.stdout.write("CRYPTOGRAPHIC_BUNDLE_VERIFICATION_PASS_REQUIRES_WINDOWS_WRAPPER\n");
    return;
  }
  fail("usage: release-manifest.mjs key-id|canonicalize|canonicalize-json|validate|verify [arguments]");
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  runCli().catch((error) => {
    const message = error instanceof ReleaseValidationError ? error.message : "unexpected release verifier failure";
    process.stderr.write(`RELEASE_INELIGIBLE: ${message}\n`);
    process.exitCode = 1;
  });
}
