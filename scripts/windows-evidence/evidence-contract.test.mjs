import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  link,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  canonicalWindowsReadinessEvidence,
  parseCanonicalWindowsReadinessEvidence,
  validateWindowsReadinessEvidence,
} from "./evidence-contract.mjs";

const execFileAsync = promisify(execFile);
const CONTRACT_PATH = fileURLToPath(
  new URL("./evidence-contract.mjs", import.meta.url),
);
const PREFLIGHT_PATH = fileURLToPath(new URL("./preflight.ps1", import.meta.url));
const RUNNER_PATH = fileURLToPath(
  new URL("./run-current-user.ps1", import.meta.url),
);
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

function fixture(result = "local-fixture") {
  return {
    caseId: "phase2g-lifecycle-local-fixture-v1",
    commandProfile: "cargo-test-locked-frozen-offline-v1",
    qualifiedTests: [...QUALIFIED_TESTS],
    releaseEligibility: "not-release-evidence",
    result,
    schema: "your-wallet-windows-readiness-evidence-v1",
  };
}

async function withTemporaryDirectory(run) {
  const root = await mkdtemp(
    path.join(os.tmpdir(), "your-wallet-windows-readiness-"),
  );
  try {
    return await run(root);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

async function invokeContract(args) {
  try {
    const result = await execFileAsync(process.execPath, [CONTRACT_PATH, ...args], {
      encoding: "utf8",
      windowsHide: true,
    });
    return { code: 0, stderr: result.stderr, stdout: result.stdout };
  } catch (error) {
    return {
      code: typeof error.code === "number" ? error.code : 1,
      stderr: error.stderr ?? "",
      stdout: error.stdout ?? "",
    };
  }
}

async function invokePowerShellScript(scriptPath, args = []) {
  const systemRoot = process.env.SystemRoot;
  if (typeof systemRoot !== "string" || systemRoot.length === 0) {
    return { unavailable: true };
  }
  const executable = path.join(
    systemRoot,
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  try {
    const result = await execFileAsync(
      executable,
      [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        scriptPath,
        ...args,
      ],
      {
        encoding: "utf8",
        maxBuffer: 8192,
        timeout: 30_000,
        windowsHide: true,
      },
    );
    return { code: 0, stderr: result.stderr, stdout: result.stdout };
  } catch (error) {
    return {
      code: typeof error.code === "number" ? error.code : 1,
      stderr: error.stderr ?? "",
      stdout: error.stdout ?? "",
    };
  }
}

function exactCheckArguments(evidencePath, expectedResult = "local-fixture") {
  return [
    "check",
    "--input",
    evidencePath,
    "--expected-result",
    expectedResult,
  ];
}

test("exact six-field evidence validates for all readiness-only results", () => {
  for (const result of ["local-fixture", "not-run", "blocked"]) {
    const validated = validateWindowsReadinessEvidence(fixture(result));
    assert.equal(validated.result, result);
    assert.equal(validated.releaseEligibility, "not-release-evidence");
    assert.equal(validated.qualifiedTests.length, 22);
    assert.ok(Object.isFrozen(validated));
    assert.ok(Object.isFrozen(validated.qualifiedTests));
  }
});

test("fixed identifiers and exact member set cannot be widened", () => {
  const mutations = [
    (value) => {
      value.schema = "your-wallet-windows-readiness-evidence-v2";
    },
    (value) => {
      value.caseId = "another-case";
    },
    (value) => {
      value.commandProfile = "cargo-test-v1";
    },
    (value) => {
      value.releaseEligibility = "pass";
    },
    (value) => {
      value.result = "pass";
    },
    (value) => {
      value.timestamp = "2026-09-01T00:00:00Z";
    },
    (value) => {
      delete value.releaseEligibility;
    },
  ];
  for (const mutate of mutations) {
    const value = fixture();
    mutate(value);
    assert.throws(
      () => validateWindowsReadinessEvidence(value),
      /readiness|result|releaseEligibility|member/u,
    );
  }
  assert.throws(
    () => validateWindowsReadinessEvidence(Object.create(null)),
    /plain object/u,
  );
});

test("qualified test inventory is exact, fully qualified, ordered, and complete", () => {
  assert.equal(QUALIFIED_TESTS.length, 22);
  assert.ok(
    QUALIFIED_TESTS.every((name) =>
      name.startsWith("key_agent_service::windows_lifecycle::tests::")
    ),
  );

  const reordered = fixture();
  [reordered.qualifiedTests[0], reordered.qualifiedTests[1]] = [
    reordered.qualifiedTests[1],
    reordered.qualifiedTests[0],
  ];
  assert.throws(
    () => validateWindowsReadinessEvidence(reordered),
    /ordered 22-test inventory/u,
  );

  const missing = fixture();
  missing.qualifiedTests.pop();
  assert.throws(
    () => validateWindowsReadinessEvidence(missing),
    /exact 22-test inventory/u,
  );

  const substituted = fixture();
  substituted.qualifiedTests[21] =
    "key_agent_service::windows_lifecycle::tests::invented";
  assert.throws(
    () => validateWindowsReadinessEvidence(substituted),
    /ordered 22-test inventory/u,
  );
});

test("canonical encoder emits compact sorted JSON plus exactly one LF", () => {
  const canonical = canonicalWindowsReadinessEvidence(fixture());
  assert.ok(canonical.startsWith('{"caseId":'));
  assert.ok(canonical.endsWith("}\n"));
  assert.equal(canonical.endsWith("}\n\n"), false);
  assert.equal(canonical.includes("\r"), false);
  assert.equal(canonical.includes("\n "), false);
  assert.deepEqual(
    parseCanonicalWindowsReadinessEvidence(canonical),
    validateWindowsReadinessEvidence(fixture()),
  );
  assert.deepEqual(
    parseCanonicalWindowsReadinessEvidence(Buffer.from(canonical, "utf8")),
    validateWindowsReadinessEvidence(fixture()),
  );
});

test("canonical parser rejects BOM, CRLF, trailing bytes, whitespace, and duplicates", () => {
  const canonical = canonicalWindowsReadinessEvidence(fixture());
  const withoutLf = canonical.slice(0, -1);
  const pretty = JSON.stringify(fixture(), null, 2) + "\n";
  const duplicate = canonical.replace(
    '{"caseId":',
    '{"caseId":"phase2g-lifecycle-local-fixture-v1","caseId":',
  );
  const cases = [
    "\ufeff" + canonical,
    withoutLf,
    withoutLf + "\r\n",
    canonical + "\n",
    withoutLf + " \n",
    pretty,
    duplicate,
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(canonical)]),
    Buffer.from([0xc3, 0x28, 0x0a]),
  ];
  for (const value of cases) {
    assert.throws(
      () => parseCanonicalWindowsReadinessEvidence(value),
      /Windows readiness evidence|canonical/u,
    );
  }
});

test("CLI accepts only exact check input and prints the readiness-only marker", async () => {
  await withTemporaryDirectory(async (root) => {
    const evidencePath = path.join(root, "evidence.json");
    await writeFile(
      evidencePath,
      canonicalWindowsReadinessEvidence(fixture()),
      "utf8",
    );
    const result = await invokeContract(exactCheckArguments(evidencePath));
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.equal(
      result.stdout,
      "WINDOWS_READINESS_CONTRACT_VALID_NOT_RELEASE_EVIDENCE\n",
    );

    const mismatched = await invokeContract(
      exactCheckArguments(evidencePath, "blocked"),
    );
    assert.notEqual(mismatched.code, 0);
    assert.equal(mismatched.stdout, "");
    assert.equal(
      mismatched.stderr,
      "WINDOWS_READINESS_CONTRACT_INVALID\n",
    );
  });
});

test("CLI rejects noncanonical input and every argument-shape widening", async () => {
  await withTemporaryDirectory(async (root) => {
    const evidencePath = path.join(root, "evidence.json");
    await writeFile(evidencePath, JSON.stringify(fixture(), null, 2) + "\n");
    const invalidInput = await invokeContract(exactCheckArguments(evidencePath));
    assert.notEqual(invalidInput.code, 0);
    assert.equal(invalidInput.stdout, "");
    assert.equal(invalidInput.stderr, "WINDOWS_READINESS_CONTRACT_INVALID\n");

    for (const args of [
      [],
      ["check"],
      ["check", "--input"],
      ["check", "--input", evidencePath],
      ["check", "--other", evidencePath, "--expected-result", "local-fixture"],
      ["check", "--input", evidencePath, "--expected-result"],
      ["check", "--input", evidencePath, "--expected-result", "pass"],
      [...exactCheckArguments(evidencePath), "--extra", "value"],
      ["verify", ...exactCheckArguments(evidencePath).slice(1)],
    ]) {
      const result = await invokeContract(args);
      assert.notEqual(result.code, 0);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "WINDOWS_READINESS_CONTRACT_INVALID\n");
    }
  });
});

test("CLI rejects oversized and hard-linked evidence files", async () => {
  await withTemporaryDirectory(async (root) => {
    const oversizedPath = path.join(root, "oversized.json");
    await writeFile(oversizedPath, Buffer.alloc(64 * 1024 + 1, 0x78));
    const oversized = await invokeContract(exactCheckArguments(oversizedPath));
    assert.notEqual(oversized.code, 0);
    assert.equal(oversized.stderr, "WINDOWS_READINESS_CONTRACT_INVALID\n");

    const evidencePath = path.join(root, "evidence.json");
    const linkedPath = path.join(root, "linked.json");
    await writeFile(
      evidencePath,
      canonicalWindowsReadinessEvidence(fixture()),
      "utf8",
    );
    await link(evidencePath, linkedPath);
    const hardLinked = await invokeContract(exactCheckArguments(linkedPath));
    assert.notEqual(hardLinked.code, 0);
    assert.equal(hardLinked.stderr, "WINDOWS_READINESS_CONTRACT_INVALID\n");
  });
});

test("CLI rejects symbolic-link evidence input when the host can create it", async (context) => {
  await withTemporaryDirectory(async (root) => {
    const evidencePath = path.join(root, "evidence.json");
    const linkedPath = path.join(root, "linked.json");
    await writeFile(
      evidencePath,
      canonicalWindowsReadinessEvidence(fixture()),
      "utf8",
    );
    try {
      await symlink(evidencePath, linkedPath, "file");
    } catch (error) {
      if (error.code === "EPERM" || error.code === "EACCES") {
        context.skip("host policy does not permit an unprivileged file symlink");
        return;
      }
      throw error;
    }
    const result = await invokeContract(exactCheckArguments(linkedPath));
    assert.notEqual(result.code, 0);
    assert.equal(result.stderr, "WINDOWS_READINESS_CONTRACT_INVALID\n");
  });
});

test("PowerShell preflight exposes only one exact readiness marker", async (context) => {
  if (process.platform !== "win32") {
    context.skip("PowerShell readiness behavior is Windows-only");
    return;
  }
  const result = await invokePowerShellScript(PREFLIGHT_PATH);
  if (result.unavailable) {
    context.skip("fixed system Windows PowerShell is unavailable");
    return;
  }
  const passed = result.code === 0 &&
    result.stdout ===
      "WINDOWS_READINESS_PREFLIGHT_PASS_CURRENT_USER_NON_ELEVATED\r\n" &&
    result.stderr === "";
  const blocked = result.code === 20 && result.stdout === "" &&
    result.stderr === "WINDOWS_READINESS_PREFLIGHT_BLOCKED\r\n";
  assert.equal(passed || blocked, true);
});

test("PowerShell runner rejects every caller argument with one fixed marker", async (context) => {
  if (process.platform !== "win32") {
    context.skip("PowerShell readiness behavior is Windows-only");
    return;
  }
  const result = await invokePowerShellScript(RUNNER_PATH, [
    "--private-probe",
    "must-not-echo",
  ]);
  if (result.unavailable) {
    context.skip("fixed system Windows PowerShell is unavailable");
    return;
  }
  assert.equal(result.code, 21);
  assert.equal(result.stdout, "");
  assert.equal(
    result.stderr,
    "WINDOWS_READINESS_NOT_RUN_NOT_RELEASE_EVIDENCE\r\n",
  );
});
