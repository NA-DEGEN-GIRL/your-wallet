import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFile = promisify(execFileCallback);

function replaceOne(source, before, after) {
  const first = source.indexOf(before);
  if (first < 0 || source.indexOf(before, first + before.length) >= 0) {
    throw new Error("Service probe fixture mutation was not uniquely applicable.");
  }
  return source.slice(0, first) + after + source.slice(first + before.length);
}

async function withFixture(files, action) {
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
          // but force a denied preflight and poison the subsequent operation
          // before its first Windows call. No host token or SCM/LSA operation
          // is observed or changed, even on an elevated test runner.
          source = source.replaceAll("\r\n", "\n");
          source = replaceOne(source,
            "internal static bool IsElevatedPrimary()\n        {",
            "internal static bool IsElevatedPrimary()\n        {\n            return false;");
          source = replaceOne(source,
            "public void Execute(string action, string workspace)\n            {\n                string programFiles",
            "public void Execute(string action, string workspace)\n            {\n                throw new InvalidOperationException(\"FORBIDDEN_NATIVE_EXECUTION_MARKER\");\n                string programFiles");
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
    for (const arguments_ of [[], ["-Action"], ["Install"], ["-action", "Install"], ["-Action", "install"], ["-Action", "Unknown"], ["-Action", "Readback", "extra"], ["-Action", "Readback", "-Action", "Remove"]]) {
      assertResult(await run(scripts, arguments_), 2, "SERVICE_PROBE_ARGUMENT_ERROR");
    }
  });
});

test("operator CLI denies every operation before the poisoned native execution boundary", async () => {
  await withFixture(["operate.ps1", "common.ps1", "ServiceProbeNative.cs"], async (scripts) => {
    for (const action of ["Install", "Readback", "Start", "Stop", "Remove"]) {
      assertResult(await run(scripts, ["-Action", action]), 20,
        "SERVICE_PROBE_REQUIRES_ELEVATED_OPERATOR");
    }
  });
});

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
