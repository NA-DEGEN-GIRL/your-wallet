import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const EVIDENCE_SCHEMA = "your-wallet-windows-readiness-evidence-v1";
const CASE_ID = "phase2g-lifecycle-local-fixture-v1";
const COMMAND_PROFILE = "cargo-test-locked-frozen-offline-v1";
const RELEASE_ELIGIBILITY = "not-release-evidence";
const ALLOWED_RESULTS = new Set(["local-fixture", "not-run", "blocked"]);
const EXACT_KEYS = Object.freeze([
  "caseId",
  "commandProfile",
  "qualifiedTests",
  "releaseEligibility",
  "result",
  "schema",
]);
const QUALIFIED_TESTS = Object.freeze([
  "key_agent_service::windows_lifecycle::tests::clean_startup_active_runtime_clean_release_reaches_normal_stopped",
  "key_agent_service::windows_lifecycle::tests::startup_missing_and_mismatch_require_checked_silent_exit78",
  "key_agent_service::windows_lifecycle::tests::active_ambiguity_reloads_prior_with_fresh_checks_candidate_with_carried_checks_and_partial_terminal",
  "key_agent_service::windows_lifecycle::tests::confirmed_active_reread_failure_never_restores_boot_or_listener_authority",
  "key_agent_service::windows_lifecycle::tests::listener_scm_and_admission_typestates_are_ordered_and_move_only",
  "key_agent_service::windows_lifecycle::tests::effect_authority_is_sealed_move_only_redacted_and_production_unmintable",
  "key_agent_service::windows_lifecycle::tests::effect_backed_startup_is_exactly_ordered_consuming_and_one_shot",
  "key_agent_service::windows_lifecycle::tests::cross_binding_duplicate_and_wrong_purpose_receipts_are_rejected_non_vacuously",
  "key_agent_service::windows_lifecycle::tests::listener_preparation_failure_and_ambiguity_preserve_effects_through_checked_exit",
  "key_agent_service::windows_lifecycle::tests::scm_running_failure_and_ambiguity_preserve_effects_through_checked_exit",
  "key_agent_service::windows_lifecycle::tests::admission_open_failure_and_ambiguity_preserve_effects_through_checked_exit",
  "key_agent_service::windows_lifecycle::tests::admission_close_precedes_stop_reject_and_failure_never_enters_cleanup",
  "key_agent_service::windows_lifecycle::tests::invalidate_then_effect_drain_gates_fixed_remaining_cleanup_without_generic_bypass",
  "key_agent_service::windows_lifecycle::tests::effect_carrier_survives_clean_reload_release_and_every_durable_terminal_class",
  "key_agent_service::windows_lifecycle::tests::post_writer_release_scm_stop_failure_and_ambiguity_are_irreversible_with_both_evidences",
  "key_agent_service::windows_lifecycle::tests::runtime_policy_alone_enforces_work_token_and_quarantine_bounds",
  "key_agent_service::windows_lifecycle::tests::cleanup_requires_exact_order_and_empties_all_runtime_registries_before_clean",
  "key_agent_service::windows_lifecycle::tests::clean_ambiguity_advances_release_policy_for_candidate_only",
  "key_agent_service::windows_lifecycle::tests::release_writer_retained_checks_retirement_and_no_receipt_is_irreversible_exit78",
  "key_agent_service::windows_lifecycle::tests::post_release_logical_failure_is_irreversible_exit78_and_never_stopped",
  "key_agent_service::windows_lifecycle::tests::retirement_fault_preserves_original_lifecycle_and_platform_cleanup_causes",
  "key_agent_service::windows_lifecycle::tests::debug_and_source_surfaces_are_redacted_silent_and_path_handle_free",
]);
const MAX_EVIDENCE_BYTES = 64 * 1024;
const UINT64_MAX = (1n << 64n) - 1n;

class WindowsReadinessEvidenceError extends Error {
  constructor(message) {
    super(message);
    this.name = "WindowsReadinessEvidenceError";
  }
}

function fail(message) {
  throw new WindowsReadinessEvidenceError(message);
}

function isPlainObject(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function requireExactObjectKeys(value) {
  if (!isPlainObject(value)) fail("Windows readiness evidence must be a plain object");
  const actual = Object.keys(value).sort();
  if (
    actual.length !== EXACT_KEYS.length ||
    actual.some((key, index) => key !== EXACT_KEYS[index])
  ) {
    fail("Windows readiness evidence has an unexpected member set");
  }
}

function requireExactString(value, expected, label) {
  if (value !== expected) fail(label + " is not the fixed readiness-contract value");
}

function requireExactQualifiedTests(value) {
  if (!Array.isArray(value) || value.length !== QUALIFIED_TESTS.length) {
    fail("qualifiedTests must contain the exact 22-test inventory");
  }
  for (let index = 0; index < QUALIFIED_TESTS.length; index += 1) {
    if (value[index] !== QUALIFIED_TESTS[index]) {
      fail("qualifiedTests must preserve the exact ordered 22-test inventory");
    }
  }
}

export function validateWindowsReadinessEvidence(value) {
  requireExactObjectKeys(value);
  requireExactString(value.caseId, CASE_ID, "caseId");
  requireExactString(value.commandProfile, COMMAND_PROFILE, "commandProfile");
  requireExactQualifiedTests(value.qualifiedTests);
  requireExactString(
    value.releaseEligibility,
    RELEASE_ELIGIBILITY,
    "releaseEligibility",
  );
  if (!ALLOWED_RESULTS.has(value.result)) {
    fail("result must be local-fixture, not-run, or blocked");
  }
  requireExactString(value.schema, EVIDENCE_SCHEMA, "schema");

  return Object.freeze({
    caseId: value.caseId,
    commandProfile: value.commandProfile,
    qualifiedTests: Object.freeze([...value.qualifiedTests]),
    releaseEligibility: value.releaseEligibility,
    result: value.result,
    schema: value.schema,
  });
}

function canonicalEncode(value) {
  if (typeof value === "string") {
    if (/[^\u0020-\u007e]/u.test(value)) {
      fail("canonical readiness evidence permits printable ASCII strings only");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalEncode(item)).join(",") + "]";
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    return "{" + keys
      .map((key) => canonicalEncode(key) + ":" + canonicalEncode(value[key]))
      .join(",") + "}";
  }
  fail("canonical readiness evidence permits objects, arrays, and strings only");
}

export function canonicalWindowsReadinessEvidence(value) {
  return canonicalEncode(validateWindowsReadinessEvidence(value)) + "\n";
}

function decodeEvidenceBytes(input) {
  if (typeof input === "string") {
    if (Buffer.byteLength(input, "utf8") > MAX_EVIDENCE_BYTES) {
      fail("Windows readiness evidence exceeds the 64 KiB limit");
    }
    if (input.charCodeAt(0) === 0xfeff) {
      fail("Windows readiness evidence must not contain a UTF-8 BOM");
    }
    return input;
  }
  if (!(input instanceof Uint8Array)) {
    fail("canonical Windows readiness evidence must be text or bytes");
  }
  if (input.byteLength > MAX_EVIDENCE_BYTES) {
    fail("Windows readiness evidence exceeds the 64 KiB limit");
  }
  if (
    input.byteLength >= 3 &&
    input[0] === 0xef &&
    input[1] === 0xbb &&
    input[2] === 0xbf
  ) {
    fail("Windows readiness evidence must not contain a UTF-8 BOM");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input);
  } catch {
    fail("Windows readiness evidence is not valid UTF-8");
  }
}

export function parseCanonicalWindowsReadinessEvidence(input) {
  const text = decodeEvidenceBytes(input);
  if (text.includes("\r")) {
    fail("Windows readiness evidence must use LF line endings");
  }
  if (!text.endsWith("\n")) {
    fail("Windows readiness evidence must end in exactly one LF");
  }

  const jsonText = text.slice(0, -1);
  let value;
  try {
    value = JSON.parse(jsonText);
  } catch {
    fail("Windows readiness evidence is not valid JSON");
  }
  const validated = validateWindowsReadinessEvidence(value);
  if (text !== canonicalEncode(validated) + "\n") {
    fail("Windows readiness evidence is not exact canonical JSON plus one LF");
  }
  return validated;
}

function samePinnedMetadata(left, right) {
  return (process.platform === "win32" || left.dev === right.dev) &&
    left.ino === right.ino &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

function hasSupportedIdentity(status) {
  return status.ino !== 0n && status.ino !== UINT64_MAX;
}

function exactPathMatches(resolved, real) {
  if (process.platform === "win32") {
    return resolved.toLowerCase() === real.toLowerCase();
  }
  return resolved === real;
}

async function resolveNonLinkedPath(inputPath) {
  const resolved = path.resolve(inputPath);
  const real = await realpath(resolved);
  if (!exactPathMatches(resolved, real)) {
    fail("Windows readiness evidence path must not traverse a symbolic link");
  }
  return resolved;
}

function requirePinnedRegularFile(status) {
  if (!status.isFile() || status.isSymbolicLink()) {
    fail("Windows readiness evidence input must be a regular file");
  }
  if (status.nlink !== 1n) {
    fail("Windows readiness evidence input must not be hard linked");
  }
  if (!hasSupportedIdentity(status)) {
    fail("Windows readiness evidence file identity is unavailable");
  }
  if (status.size > BigInt(MAX_EVIDENCE_BYTES)) {
    fail("Windows readiness evidence exceeds the 64 KiB limit");
  }
}

async function readPinnedEvidenceFile(inputPath) {
  const resolved = await resolveNonLinkedPath(inputPath);
  const pathBefore = await lstat(resolved, { bigint: true });
  requirePinnedRegularFile(pathBefore);

  const handle = await open(resolved, "r");
  try {
    const handleBefore = await handle.stat({ bigint: true });
    requirePinnedRegularFile(handleBefore);
    if (!samePinnedMetadata(pathBefore, handleBefore)) {
      fail("Windows readiness evidence identity changed before it was checked");
    }

    const chunks = [];
    let byteLength = 0;
    const stream = handle.createReadStream({ autoClose: false, start: 0 });
    for await (const chunk of stream) {
      byteLength += chunk.length;
      if (byteLength > MAX_EVIDENCE_BYTES) {
        stream.destroy();
        fail("Windows readiness evidence exceeds the 64 KiB limit");
      }
      chunks.push(chunk);
    }

    const handleAfter = await handle.stat({ bigint: true });
    const pathAfter = await lstat(resolved, { bigint: true });
    requirePinnedRegularFile(handleAfter);
    requirePinnedRegularFile(pathAfter);
    if (
      !samePinnedMetadata(handleBefore, handleAfter) ||
      !samePinnedMetadata(handleAfter, pathAfter) ||
      BigInt(byteLength) !== handleAfter.size
    ) {
      fail("Windows readiness evidence changed while it was checked");
    }

    const realAfter = await realpath(resolved);
    if (!exactPathMatches(resolved, realAfter)) {
      fail("Windows readiness evidence path changed while it was checked");
    }
    const pathHandle = await open(resolved, "r");
    try {
      const pathHandleStatus = await pathHandle.stat({ bigint: true });
      requirePinnedRegularFile(pathHandleStatus);
      if (!samePinnedMetadata(handleAfter, pathHandleStatus)) {
        fail("Windows readiness evidence identity changed while it was checked");
      }
    } finally {
      await pathHandle.close();
    }
    return Buffer.concat(chunks, byteLength);
  } finally {
    await handle.close();
  }
}

function parseCliArguments(argv) {
  if (
    argv.length !== 5 ||
    argv[0] !== "check" ||
    argv[1] !== "--input" ||
    typeof argv[2] !== "string" ||
    argv[2].length === 0 ||
    argv[2].startsWith("--") ||
    argv[3] !== "--expected-result" ||
    !ALLOWED_RESULTS.has(argv[4])
  ) {
    fail(
      "usage: evidence-contract.mjs check --input <evidence.json> " +
        "--expected-result <local-fixture|not-run|blocked>",
    );
  }
  return Object.freeze({ expectedResult: argv[4], inputPath: argv[2] });
}

async function runCli() {
  const { expectedResult, inputPath } = parseCliArguments(process.argv.slice(2));
  const bytes = await readPinnedEvidenceFile(inputPath);
  const evidence = parseCanonicalWindowsReadinessEvidence(bytes);
  if (evidence.result !== expectedResult) {
    fail("Windows readiness evidence result does not match the fixed expectation");
  }
  process.stdout.write("WINDOWS_READINESS_CONTRACT_VALID_NOT_RELEASE_EVIDENCE\n");
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (
  invokedPath !== "" &&
  exactPathMatches(invokedPath, fileURLToPath(import.meta.url))
) {
  runCli().catch(() => {
    process.stderr.write("WINDOWS_READINESS_CONTRACT_INVALID\n");
    process.exitCode = 1;
  });
}
