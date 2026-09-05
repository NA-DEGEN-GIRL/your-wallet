import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFile = promisify(execFileCallback);
const inspectionStages = [
  "DIRECTORY", "DIRECTORY_SECURITY_OWNER_GROUP", "DIRECTORY_SECURITY_ACE_BYTES", "DIRECTORY_SECURITY_PROTECTED",
  "APPROVAL_FILE_PRESENCE", "DESKTOP_PROBE_FILE_PRESENCE", "SERVICE_FILE_PRESENCE", "SECRET_INPUT_FILE_PRESENCE",
  "MANIFEST_FILE_PRESENCE", "JOURNAL_FILE_PRESENCE", "SERVICE_QUERY", "SERVICE_CONFIG_BASE",
  "SERVICE_CONFIG_SID_TYPE", "SERVICE_CONFIG_PRIVILEGES", "SERVICE_STATUS_QUERY",
  "SERVICE_SECURITY_OWNER_GROUP", "SERVICE_SECURITY_ACE_BYTES", "SERVICE_SECURITY_PROTECTED",
  "SERVICE_SID", "RIGHTS", "MANIFEST", "JOURNAL",
  "APPROVAL_SECURITY", "DESKTOP_PROBE_SECURITY", "SERVICE_FILE_SECURITY", "SECRET_INPUT_SECURITY", "MANIFEST_SECURITY", "JOURNAL_SECURITY",
  "APPROVAL_HASH", "DESKTOP_PROBE_HASH", "SERVICE_FILE_HASH", "SECRET_INPUT_HASH", "INVENTORY",
];

function replaceOne(source, before, after) {
  const first = source.indexOf(before);
  if (first < 0 || source.indexOf(before, first + before.length) >= 0) {
    throw new Error("Service probe fixture mutation was not uniquely applicable.");
  }
  return source.slice(0, first) + after + source.slice(first + before.length);
}

async function withFixture(files, action, inspection = false) {
  const parent = resolve(tmpdir());
  let fixture;
  try { fixture = await mkdtemp(join(parent, "service-probe-cli-test-")); }
  catch { throw new Error("Service probe fixture allocation failed."); }
  if (dirname(resolve(fixture)) !== parent || !basename(fixture).startsWith("service-probe-cli-test-")) {
    throw new Error("Service probe fixture ownership failed.");
  }
  try {
    const scripts = join(fixture, "scripts", "service-probe");
    try {
      await mkdir(scripts, { recursive: true });
      for (const file of files) {
        let source = await readFile(join(import.meta.dirname, file), "utf8");
        if (file === "ServiceProbeNative.cs") {
          // Execute the complete real entry point and native helper source,
          // but replace the host preflight and poison both native execution
          // boundaries before any Windows call. Inspect's positive cases inject
          // only the separate query interface; its mutation path stays poisoned.
          source = source.replaceAll("\r\n", "\n");
          source = replaceOne(source,
            "internal static bool IsElevatedPrimary()\n        {",
            "internal static bool IsElevatedPrimary()\n        {\n            return " + (inspection ? "true" : "false") + ";");
          source = replaceOne(source,
            "public void Execute(string action, string workspace)\n            {\n                string programFiles",
            "public void Execute(string action, string workspace)\n            {\n                throw new InvalidOperationException(\"FORBIDDEN_NATIVE_EXECUTION_MARKER\");\n                string programFiles");
          source = replaceOne(source,
            "internal static Harness.InspectionOutcome InspectStage(Harness.InspectionStage stage)\n        {",
            "internal static Harness.InspectionOutcome InspectStage(Harness.InspectionStage stage)\n        {\n            throw new InvalidOperationException(\"FORBIDDEN_NATIVE_INSPECTION_MARKER\");");
          if (inspection) {
            const injected = inspection === "mixed" ?
              'if (stage == InspectionStage.JOURNAL_FILE_PRESENCE) throw new InvalidOperationException("PRIVATE_INSPECTION_MARKER_MUST_NOT_ESCAPE"); if (stage == InspectionStage.SERVICE_SECURITY_ACE_BYTES) return InspectionOutcome.FAIL; return stage == InspectionStage.SERVICE_STATUS_QUERY ? InspectionOutcome.RUNNING : InspectionOutcome.PASS;' :
              "return stage == InspectionStage.SERVICE_STATUS_QUERY ? InspectionOutcome.STOPPED : InspectionOutcome.PASS;";
            source = replaceOne(source, "public InspectionOutcome Check(InspectionStage stage) { return Native.InspectStage(stage); }",
              "public InspectionOutcome Check(InspectionStage stage) { " + injected + " }");
          }
          source = "#pragma warning disable 0162\n" + source;
        }
        await writeFile(join(scripts, file), source, { encoding: "utf8", flag: "wx" });
      }
    } catch { throw new Error("Service probe fixture copy failed."); }
    await action(scripts);
  } finally {
    try { await rm(fixture, { recursive: true, force: true }); }
    catch { throw new Error("Service probe fixture cleanup failed."); }
  }
}

async function run(scripts, arguments_) {
  try {
    const result = await execFile("powershell.exe", ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", join(scripts, "operate.ps1"), ...arguments_], {
      cwd: scripts,
      encoding: "utf8",
      timeout: 15_000,
      maxBuffer: 8192,
      windowsHide: true,
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    if (!Number.isInteger(error?.code) || error.killed || error.signal) {
      throw new Error("Service probe CLI did not complete within its bounds.");
    }
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

function assertResult(result, code, message) {
  assert.equal(result.code === code, true, "Service probe CLI exit status differed.");
  assert.equal(result.stderr === "", true, "Service probe CLI emitted unexpected stderr.");
  assert.equal(result.stdout.replaceAll("\r\n", "\n") === message + "\n", true,
    "Service probe CLI fixed output differed.");
}

test("operator CLI rejects noncanonical arguments before importing native code", async () => {
  await withFixture(["operate.ps1"], async (scripts) => {
    for (const arguments_ of [[], ["-Action"], ["Install"], ["-action", "Install"], ["-Action", "install"], ["-Action", "inspect"], ["-Action", "Unknown"], ["-Action", "Readback", "extra"], ["-Action", "Readback", "-Action", "Remove"]]) {
      assertResult(await run(scripts, arguments_), 2, "SERVICE_PROBE_ARGUMENT_ERROR");
    }
  });
});

test("operator CLI denies every operation before the poisoned native execution boundary", async () => {
  await withFixture(["operate.ps1", "common.ps1", "ServiceProbeNative.cs"], async (scripts) => {
    for (const action of ["Install", "Readback", "Start", "Stop", "Remove", "Inspect"]) {
      assertResult(await run(scripts, ["-Action", action]), 20,
        "SERVICE_PROBE_REQUIRES_ELEVATED_OPERATOR");
    }
  });
});

for (const mode of ["pass", "mixed"]) {
  test("operator Inspect emits finite " + mode + " observations without native queries or mutations", async () => {
    await withFixture(["operate.ps1", "common.ps1", "ServiceProbeNative.cs"], async (scripts) => {
      const lines = ["SERVICE_PROBE_INSPECT_READ_ONLY_NOT_OWNERSHIP_EVIDENCE"];
      for (const stage of inspectionStages) {
        let outcome = stage === "SERVICE_STATUS_QUERY" ? (mode === "mixed" ? "RUNNING" : "STOPPED") : "PASS";
        if (mode === "mixed" && stage === "JOURNAL_FILE_PRESENCE") outcome = "UNAVAILABLE";
        if (mode === "mixed" && stage === "SERVICE_SECURITY_ACE_BYTES") outcome = "FAIL";
        lines.push("SERVICE_PROBE_INSPECT_" + stage + "_" + outcome);
      }
      lines.push("SERVICE_PROBE_INSPECT_CLEANUP_PASS", "SERVICE_PROBE_INSPECT_COMPLETE_NOT_RELEASE_EVIDENCE");
      assertResult(await run(scripts, ["-Action", "Inspect"]), 0, lines.join("\n"));
    }, mode);
  });
}

test("operator CLI import failure emits no source path or compiler payload", async () => {
  await withFixture(["operate.ps1", "common.ps1"], async (scripts) => {
    assertResult(await run(scripts, ["-Action", "Readback"]), 20,
      "SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW");
  });
});

test("operator CLI compiler failure does not echo malformed native source", async () => {
  await withFixture(["operate.ps1", "common.ps1"], async (scripts) => {
    try {
      await writeFile(join(scripts, "ServiceProbeNative.cs"),
        "THIS_IS_NOT_CSHARP SOURCE_DEFINED_COMPILER_MARKER_MUST_NOT_BE_EMITTED\n",
        { encoding: "utf8", flag: "wx" });
    } catch { throw new Error("Malformed native-source fixture creation failed."); }
    assertResult(await run(scripts, ["-Action", "Readback"]), 20,
      "SERVICE_PROBE_FAILED_STATE_RETAINED_FOR_REVIEW");
  });
});
