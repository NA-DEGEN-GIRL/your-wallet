import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFile = promisify(execFileCallback);
const repositoryRoot = resolve(import.meta.dirname, "..");
const scannerPath = "scripts/architecture-scan.mjs";
const groupArguments = ["--check-group", "service-approval-transport"];
const sourcePaths = [
  "crates/key-agent-service-helper-bootstrap/src/child.rs",
  "crates/key-agent-service-helper-bootstrap/src/child/windows.rs",
  "crates/platform-windows/src/key_agent_service_launch/debug_gate.rs",
  "crates/platform-windows/src/key_agent_service_launch/rpc_probe.rs",
  "crates/approval-ui/src/main.rs",
  "crates/approval-ui/src/lib.rs",
  "crates/approval-ui/src/native.rs",
  "crates/key-agent-service-helper-bootstrap/src/wire.rs",
];
const checkNames = [
  "exactGates",
  "opaqueOwnership",
  "publicOneShot",
  "authenticatedReceive",
  "originalDeadline",
  "boundedReads",
  "canonicalRequest",
  "boundedPresentation",
  "retainUntilServiceKill",
  "stagedParentExchange",
  "exactCorrelation",
  "cleanupBeforeOutcome",
  "serviceAuthoredNonSigning",
  "nativeNonSigningTitle",
];
const passOutput =
  "ARCHITECTURE_DIAGNOSTIC_PASS service-approval-transport\nNOT_FULL_SCAN\n";
const failPrefix =
  "ARCHITECTURE_DIAGNOSTIC_FAIL service-approval-transport\n";
const readFailureOutput =
  `${failPrefix}INPUT_READ_OR_CHECK_ERROR\nNOT_FULL_SCAN\n`;

function sameSnapshot(left, right) {
  return left.isFile() && right.isFile() &&
    (process.platform === "win32" || left.dev === right.dev) &&
    left.ino === right.ino && left.mode === right.mode &&
    left.nlink === 1n && right.nlink === 1n &&
    left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

// Do not turn an untrusted repository symlink/hardlink into a trusted fixture.
// Hold and revalidate each source identity just as the scanner itself does.
async function readSource(root, path) {
  try {
    const absolute = join(root, path);
    const before = await lstat(absolute, { bigint: true });
    if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1n) {
      throw new Error();
    }
    const handle = await open(absolute, "r");
    try {
      const opened = await handle.stat({ bigint: true });
      if (!sameSnapshot(before, opened)) throw new Error();
      const source = await handle.readFile({ encoding: "utf8" });
      const after = await handle.stat({ bigint: true });
      const pathAfter = await lstat(absolute, { bigint: true });
      if (pathAfter.isSymbolicLink() || !sameSnapshot(opened, after) ||
          !sameSnapshot(after, pathAfter)) throw new Error();
      return source;
    } finally {
      await handle.close();
    }
  } catch {
    throw new Error("Diagnostic fixture source read failed.");
  }
}

function replaceExactlyOnce(source, search, replacement) {
  const first = source.indexOf(search);
  if (first < 0 || source.indexOf(search, first + search.length) >= 0 ||
      search === replacement) {
    throw new Error("Diagnostic fixture mutation was not uniquely applicable.");
  }
  return source.slice(0, first) + replacement + source.slice(first + search.length);
}

async function mutateSource(fixture, path, search, replacement) {
  const source = await readSource(fixture, path);
  const mutated = replaceExactlyOnce(source, search, replacement);
  try {
    await writeFile(join(fixture, path), mutated, "utf8");
  } catch {
    throw new Error("Diagnostic fixture mutation write failed.");
  }
}

async function withFixture(action, { includeSources = true } = {}) {
  const temporaryParent = resolve(tmpdir());
  let fixture;
  try {
    fixture = await mkdtemp(join(temporaryParent, "architecture-diagnostic-test-"));
  } catch {
    throw new Error("Diagnostic fixture allocation failed.");
  }
  // Only this exact mkdtemp result is eligible for recursive cleanup. Neither
  // repository paths nor a caller-supplied path can become the cleanup target.
  if (dirname(resolve(fixture)) !== temporaryParent ||
      !basename(fixture).startsWith("architecture-diagnostic-test-")) {
    throw new Error("Diagnostic fixture ownership validation failed.");
  }
  try {
    for (const path of [scannerPath, ...(includeSources ? sourcePaths : [])]) {
      const source = await readSource(repositoryRoot, path);
      try {
        await mkdir(dirname(join(fixture, path)), { recursive: true });
        await writeFile(join(fixture, path), source, { encoding: "utf8", flag: "wx" });
      } catch {
        throw new Error("Diagnostic fixture copy failed.");
      }
    }
    return await action(fixture);
  } finally {
    try {
      await rm(fixture, { recursive: true, force: true });
    } catch {
      throw new Error("Diagnostic fixture cleanup failed.");
    }
  }
}

async function runDiagnostic(root, arguments_ = groupArguments) {
  const options = {
    cwd: root,
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 16_384,
    windowsHide: true,
    env: { ...process.env, NODE_OPTIONS: "", NODE_PATH: "" },
  };
  try {
    const result = await execFile(process.execPath, [join(root, scannerPath), ...arguments_], options);
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    if (!Number.isInteger(error?.code) || error.killed || error.signal) {
      throw new Error("Diagnostic child process did not finish within its execution bounds.");
    }
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

function assertResult(result, code, output) {
  // Never attach captured child output, source bytes, or temporary paths to an
  // assertion. A failure still exposes only this fixed category and booleans.
  assert.equal(result.code === code, true, "Diagnostic exit status differed.");
  assert.equal(result.stderr === "", true, "Diagnostic emitted unexpected stderr.");
  assert.equal(result.stdout === output, true, "Diagnostic fixed output differed.");
}

test("actual CLI accepts the supported group without claiming a full scan", async () => {
  assertResult(await runDiagnostic(repositoryRoot), 0, passOutput);
});

test("actual CLI group needs only its explicit source inputs", async () => {
  await withFixture(async (fixture) => {
    assertResult(await runDiagnostic(fixture), 0, passOutput);
  });
});

test("actual CLI rejects missing, unknown, duplicate, and extra arguments before reads", async () => {
  await withFixture(async (fixture) => {
    for (const arguments_ of [
      ["--check-group"],
      ["--check-group", ""],
      ["--check-group", "unknown-group"],
      ["--check-group", "SERVICE-APPROVAL-TRANSPORT"],
      ["--check-group=service-approval-transport"],
      ["--unknown", "service-approval-transport"],
      [...groupArguments, ...groupArguments],
      [...groupArguments, "unexpected-extra-argument"],
    ]) {
      assertResult(
        await runDiagnostic(fixture, arguments_),
        2,
        "ARCHITECTURE_DIAGNOSTIC_ARGUMENT_ERROR\nNOT_FULL_SCAN\n",
      );
    }
  }, { includeSources: false });
});

test("actual CLI fails a changed baseline with a fixed check identifier", async () => {
  await withFixture(async (fixture) => {
    await mutateSource(
      fixture,
      "crates/platform-windows/src/key_agent_service_launch/rpc_probe.rs",
      '"TRANSPORT TEST - NO SIGNING",',
      '"TRANSPORT TEST - BASELINE MUTATION",',
    );
    assertResult(
      await runDiagnostic(fixture),
      1,
      `${failPrefix}checks=serviceAuthoredNonSigning\nNOT_FULL_SCAN\n`,
    );
  });
});

test("actual CLI fails an ineffective mutation independently of the baseline", async () => {
  await withFixture(async (fixture) => {
    // Patch one explicit mutation row in an owned full scanner copy. Execute
    // the real CLI; never extract/eval a regex-defined scanner fragment.
    await mutateSource(
      fixture,
      scannerPath,
      '["canonical bytes", "windows", "if canonical.as_slice() != bytes.as_slice()", "if false"],',
      '["canonical bytes", "windows", "if canonical.as_slice() != bytes.as_slice()", "if canonical.as_slice() != bytes.as_slice()"],',
    );
    assertResult(
      await runDiagnostic(fixture),
      1,
      `${failPrefix}mutations=canonical bytes\nNOT_FULL_SCAN\n`,
    );
  });
});

test("actual CLI rejects a same-count duplicate mutation row", async () => {
  await withFixture(async (fixture) => {
    await mutateSource(
      fixture,
      scannerPath,
      '["bounded allocation", "windows", "if length > approval_wire::MAX_REQUEST_BYTES", "if false"],',
      '["canonical bytes", "windows", "if canonical.as_slice() != bytes.as_slice()", "if false"],',
    );
    assertResult(
      await runDiagnostic(fixture),
      1,
      `${failPrefix}checks=mutationInventory\nNOT_FULL_SCAN\n`,
    );
  });
});

test("actual CLI rejects a source-defined mutation name without echoing it", async () => {
  await withFixture(async (fixture) => {
    await mutateSource(
      fixture,
      scannerPath,
      '["canonical bytes", "windows", "if canonical.as_slice() != bytes.as_slice()", "if false"],',
      '["SOURCE_DEFINED_MUTATION_MARKER_MUST_NOT_BE_EMITTED", "windows", "if canonical.as_slice() != bytes.as_slice()", "if canonical.as_slice() != bytes.as_slice()"],',
    );
    assertResult(
      await runDiagnostic(fixture),
      1,
      `${failPrefix}checks=mutationInventory\nNOT_FULL_SCAN\n`,
    );
  });
});

test("actual CLI cannot pass with zero transport predicates", async () => {
  await withFixture(async (fixture) => {
    await mutateSource(
      fixture,
      scannerPath,
      "function keyAgentServiceApprovalTransportChecks(inputs) {",
      "function keyAgentServiceApprovalTransportChecks(inputs) {\n  return {};",
    );
    assertResult(
      await runDiagnostic(fixture),
      1,
      `${failPrefix}checks=${[...checkNames, "checkInventory"].join(",")}\nNOT_FULL_SCAN\n`,
    );
  });
});

test("actual CLI rejects an extra predicate without echoing its source-defined name", async () => {
  await withFixture(async (fixture) => {
    const checks = Object.fromEntries(checkNames.map((name) => [name, true]));
    checks.SOURCE_DEFINED_MARKER_MUST_NOT_BE_EMITTED = false;
    await mutateSource(
      fixture,
      scannerPath,
      "function keyAgentServiceApprovalTransportChecks(inputs) {",
      `function keyAgentServiceApprovalTransportChecks(inputs) {\n  return ${JSON.stringify(checks)};`,
    );
    assertResult(
      await runDiagnostic(fixture),
      1,
      `${failPrefix}checks=checkInventory\nNOT_FULL_SCAN\n`,
    );
  });
});

test("actual CLI fails closed on a missing input without leaking its path", async () => {
  await withFixture(async (fixture) => {
    assertResult(await runDiagnostic(fixture), 1, readFailureOutput);
  }, { includeSources: false });
});

test("actual CLI rejects a non-regular input without leaking its path", async () => {
  await withFixture(async (fixture) => {
    try {
      await unlink(join(fixture, sourcePaths[0]));
      await mkdir(join(fixture, sourcePaths[0]));
    } catch {
      throw new Error("Diagnostic non-regular input fixture setup failed.");
    }
    assertResult(await runDiagnostic(fixture), 1, readFailureOutput);
  });
});

test("actual CLI preserves single-link input checks", async () => {
  await withFixture(async (fixture) => {
    try {
      await link(join(fixture, sourcePaths[0]), join(fixture, "owned-input-alias.rs"));
    } catch {
      throw new Error("Diagnostic hardlink fixture setup failed.");
    }
    assertResult(await runDiagnostic(fixture), 1, readFailureOutput);
  });
});
