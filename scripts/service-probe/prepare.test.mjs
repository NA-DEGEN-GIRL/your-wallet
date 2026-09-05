import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFile = promisify(execFileCallback);
const names = ["approval-ui.exe", "key-agent-service-probe.exe", "key-agent-service.exe", "secret-input-ui.exe"];
const featureSets = [
  ["service-helper-rpc-probe-feasibility-test-hook"],
  ["desktop-rpc-probe-feasibility-test-hook"],
  ["lpac-rpc-probe-feasibility-test-hook", "rpc-status-feasibility-test-hook", "scm-feasibility-test-hook", "service-token-feasibility-test-hook"],
  ["service-helper-rpc-probe-feasibility-test-hook"],
];
const forbiddenEnvironment = ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS", "CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS"];
function verify(condition) {
  assert.equal(condition, true, "Preparation contract differed; captured data suppressed.");
}

async function run(path, args = []) {
  const env = { ...process.env };
  for (const key of forbiddenEnvironment) delete env[key];
  try {
    const result = await execFile("powershell", ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path, ...args], {
      env, windowsHide: true, timeout: 30_000, maxBuffer: 8192, encoding: "utf8",
    });
    return { code: 0, stdout: result.stdout.replaceAll("\r\n", "\n"), stderr: result.stderr };
  } catch (error) {
    if (!Number.isInteger(error.code) || error.killed || error.signal) throw new Error("Preparation test child did not finish within its bounds.");
    return { code: error.code, stdout: error.stdout?.replaceAll("\r\n", "\n"), stderr: error.stderr };
  }
}

function checkedResult(result, code = 0, stdout = "PREPARATION_TEST_PASS\n") {
  if (result.code !== code) {
    const fixed = /^PREPARATION_TEST_FAIL\nstage=(INITIALIZE|PREFLIGHT|SOURCE_ROOT|BUILD|BUILD_PROVENANCE|HOLD_ARTIFACT|STAGE|MANIFEST|COMPLETE)\ndenials=([0-4])\nmask=([0-9]|1[0-5])\n$/u.exec(result.stdout ?? "");
    if (fixed !== null) throw new Error("Preparation test failed at fixed stage " + fixed[1] + "; alias denials=" + fixed[2] + "; mask=" + fixed[3]);
  }
  verify(result.code === code);
  verify(result.stdout === stdout);
  verify(result.stderr === "");
}

const harness = [
  "$ErrorActionPreference = 'Stop'",
  "Set-StrictMode -Version Latest",
  "$script:AliasDenials = 0; $script:AliasMask = 0; $script:ServiceProbePrepareStage = 'INITIALIZE'",
  "function Assert-PreparationTest([bool]$Condition) { if (-not $Condition) { throw 'PREPARATION_TEST_ASSERTION_FAILED' } }",
  "try {",
  "    . (Join-Path $PSScriptRoot 'scripts/service-probe/prepare.ps1')",
  "    $script:Scenario = $args[0]",
  "    $script:Metadata = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'metadata.json')))",
  "    $script:Specs = @(Get-ServiceProbeBuildSpecifications)",
  "    $script:Calls = 0; $script:Preflights = 0",
  "    $script:BuildRoot = Join-Path $PSScriptRoot 'target/service-probe-build'",
  "    $script:Candidate = Join-Path $PSScriptRoot 'artifacts/service-probe-candidate'",
  "    $script:Alias = Join-Path $PSScriptRoot 'owned-hardlink.exe'",
  "    $script:Finished = @{ reason = 'build-finished'; success = $true } | ConvertTo-Json -Compress",
  "    if ($script:Scenario -ceq 'provenance') {",
  "        $json = $script:Metadata[0] | ConvertTo-Json -Compress -Depth 8",
  "        $valid = [pscustomobject]@{ ExitCode = [int]0; Lines = @($json, $script:Finished) }",
  "        $accepted = Get-ServiceProbeBuiltArtifact $valid $script:Specs[0] $PSScriptRoot $script:BuildRoot",
  "        Assert-PreparationTest ($accepted -ceq $script:Metadata[0].executable)",
  "        $cases = @(",
  "            [pscustomobject]@{ ExitCode = [int]1; Lines = @($json, $script:Finished) },",
  "            [pscustomobject]@{ ExitCode = [int]0; Lines = @($script:Finished) },",
  "            [pscustomobject]@{ ExitCode = [int]0; Lines = @($json, $json, $script:Finished) },",
  "            [pscustomobject]@{ ExitCode = [int]0; Lines = @($json) },",
  "            [pscustomobject]@{ ExitCode = [int]0; Lines = @($json, $script:Finished, $script:Finished) },",
  "            [pscustomobject]@{ ExitCode = [int]0; Lines = @($json, (@{ reason = 'build-finished'; success = $false } | ConvertTo-Json -Compress)) }",
  "        )",
  "        foreach ($mutation in @('relative', 'root-relative', 'drive-relative', 'wrong-case', 'other-target', 'manifest', 'source', 'profile', 'debug', 'overflow', 'test', 'features', 'fresh')) {",
  "            $changed = $json | ConvertFrom-Json",
  "            switch ($mutation) {",
  "                'relative' { $changed.executable = 'approval-ui.exe' }",
  "                'root-relative' { $changed.executable = '\\approval-ui.exe' }",
  "                'drive-relative' { $changed.executable = 'C:approval-ui.exe' }",
  "                'wrong-case' { $changed.executable = $changed.executable.Replace('approval-ui.exe', 'APPROVAL-UI.EXE') }",
  "                'other-target' { $changed.executable = $changed.executable.Replace('debug', 'release') }",
  "                'manifest' { $changed.manifest_path = $changed.executable }",
  "                'source' { $changed.target.src_path = $changed.executable }",
  "                'profile' { $changed.profile.opt_level = '3' }",
  "                'debug' { $changed.profile.debug_assertions = $false }",
  "                'overflow' { $changed.profile.overflow_checks = $false }",
  "                'test' { $changed.profile.test = $true }",
  "                'features' { $changed.features += 'runtime-entrypoint' }",
  "                'fresh' { $changed.fresh = 'true' }",
  "            }",
  "            $cases += [pscustomobject]@{ ExitCode = [int]0; Lines = @(($changed | ConvertTo-Json -Compress -Depth 8), $script:Finished) }",
  "        }",
  "        foreach ($case in $cases) {",
  "            $rejected = $false",
  "            try { $null = Get-ServiceProbeBuiltArtifact $case $script:Specs[0] $PSScriptRoot $script:BuildRoot } catch { $rejected = $true }",
  "            Assert-PreparationTest $rejected",
  "        }",
  "    } elseif ($script:Scenario -ceq 'manifest') {",
  "        $records = @($script:Specs | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Bytes = [long]1; Sha256 = ('0' * 64) } })",
  "        $bytes = Get-ServiceProbeCandidateBytes $records",
  "        Assert-PreparationTest ($bytes[$bytes.Length - 1] -eq 10 -and @($bytes | Where-Object { $_ -gt 127 -or $_ -eq 13 }).Count -eq 0)",
  "        foreach ($mutation in @('zero', 'large', 'fractional', 'order', 'hash', 'missing')) {",
  "            $changed = @($records | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Bytes = $_.Bytes; Sha256 = $_.Sha256 } })",
  "            switch ($mutation) {",
  "                'zero' { $changed[0].Bytes = [long]0 }",
  "                'large' { $changed[0].Bytes = [long]536870913 }",
  "                'fractional' { $changed[0].Bytes = 1.5 }",
  "                'order' { $changed[0].Name = $changed[1].Name }",
  "                'hash' { $changed[0].Sha256 = ('A' * 64) }",
  "                'missing' { $changed = $changed[0..2] }",
  "            }",
  "            $rejected = $false",
  "            try { $null = Get-ServiceProbeCandidateBytes $changed } catch { $rejected = $true }",
  "            Assert-PreparationTest $rejected",
  "        }",
  "    } else {",
  "        $runCargo = {",
  "            param($arguments)",
  "            $index = $script:Calls; $script:Calls++",
  "            $spec = $script:Specs[$index]",
  "            $expected = @('build', '--offline', '--locked', '--no-default-features', '--profile', 'dev', '--target', 'x86_64-pc-windows-msvc', '--target-dir', $script:BuildRoot, '-p', $spec.Package, '--bin', $spec.Binary, '--features', $spec.Feature, '--message-format=json-render-diagnostics')",
  "            Assert-PreparationTest (($arguments -join '|') -ceq ($expected -join '|'))",
  "            if ($script:Scenario -ceq 'source-held' -and $index -eq 1) {",
  "                $denied = 0; $mask = 0; $bit = 1",
  "                foreach ($source in @($script:Metadata[0].executable, $script:Alias)) {",
  "                    try { $writer = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite); $writer.Dispose() } catch { $denied++; $mask = $mask -bor $bit }; $bit = $bit * 2",
  "                    if ($source -ceq $script:Metadata[0].executable) { try { [IO.File]::Delete($source) } catch { $denied++; $mask = $mask -bor $bit } }; $bit = $bit * 2",
  "                }",
  "                $script:AliasDenials = $denied",
  "                $script:AliasMask = $mask",
  "                Assert-PreparationTest ($denied -eq 3 -and $mask -eq 7)",
  "            }",
  "            if ($script:Scenario -ceq 'source-alias-deleted' -and $index -eq 1) {",
  "                [IO.File]::Delete($script:Alias)",
  "                Assert-PreparationTest (-not [IO.File]::Exists($script:Alias))",
  "            }",
  "            if ($script:Scenario -ceq 'cargo-failed') { return [pscustomobject]@{ ExitCode = [int]1; Lines = @('PRIVATE_COMPILER_MARKER_MUST_NOT_ESCAPE') } }",
  "            return [pscustomobject]@{ ExitCode = [int]0; Lines = @('PRIVATE_COMPILER_MARKER_MUST_NOT_ESCAPE', ($script:Metadata[$index] | ConvertTo-Json -Compress -Depth 8), $script:Finished) }",
  "        }",
  "        $preflight = {",
  "            $script:Preflights++",
  "            if ($script:Scenario -ceq 'preflight-failed' -or ($script:Scenario -ceq 'late-preflight-failed' -and $script:Preflights -eq 3)) { throw 'PRIVATE_PREFLIGHT_MARKER_MUST_NOT_ESCAPE' }",
  "        }",
  "        $failed = $false",
  "        try { Invoke-ServiceProbePrepare -RunCargo $runCargo -Preflight $preflight } catch { $failed = $true }",
  "        if ($script:Scenario -ceq 'success' -or $script:Scenario -ceq 'source-held') {",
  "            Assert-PreparationTest (-not $failed -and $script:Calls -eq 4 -and $script:Preflights -eq 5)",
  "        } else {",
  "            Assert-PreparationTest $failed",
  "            if ($script:Scenario -ceq 'preflight-failed' -or $script:Scenario -ceq 'existing') { Assert-PreparationTest ($script:Calls -eq 0) }",
  "            elseif ($script:Scenario -ceq 'source-alias-deleted') { Assert-PreparationTest ($script:Calls -eq 4) }",
  "            else { Assert-PreparationTest ($script:Calls -eq 1) }",
  "            $expectedStage = switch ($script:Scenario) { 'preflight-failed' { 'PREFLIGHT' }; 'late-preflight-failed' { 'BUILD' }; 'cargo-failed' { 'BUILD_PROVENANCE' }; 'existing' { 'SOURCE_ROOT' }; 'source-alias-deleted' { 'STAGE' }; default { 'HOLD_ARTIFACT' } }",
  "            Assert-PreparationTest ($script:ServiceProbePrepareStage -ceq $expectedStage)",
  "            Assert-PreparationTest (-not [IO.File]::Exists((Join-Path $script:Candidate 'candidate.json')))",
  "        }",
  "    }",
  "    [Console]::WriteLine('PREPARATION_TEST_PASS'); exit 0",
  "} catch { [Console]::WriteLine('PREPARATION_TEST_FAIL'); [Console]::WriteLine('stage=' + $script:ServiceProbePrepareStage); [Console]::WriteLine('denials=' + $script:AliasDenials); [Console]::WriteLine('mask=' + $script:AliasMask); exit 1 }",
].join("\r\n") + "\r\n";

async function fixture(action) {
  const parent = resolve(tmpdir());
  const root = await mkdtemp(join(parent, "wallet-probe-preparation-test-"));
  verify(dirname(resolve(root)) === parent && basename(root).startsWith("wallet-probe-preparation-test-"));
  try {
    await mkdir(join(root, "scripts/service-probe"), { recursive: true });
    for (const name of ["prepare.ps1", "common.ps1", "ServiceProbeNative.cs"]) {
      await copyFile(join(import.meta.dirname, name), join(root, "scripts/service-probe", name));
    }
    // Only these owned full-source copies replace the host's elevation fact.
    // Poison the real Cargo runner first: a lost fake-operation injection must
    // fail, never compile code in an elevated test host. File-handle/reparse/
    // hardlink/copy checks remain the real native implementation.
    const copiedPrepare = join(root, "scripts/service-probe/prepare.ps1");
    const prepareSource = await readFile(copiedPrepare, "utf8");
    const runnerHeader = "function Invoke-ServiceProbeCargo {\r\n    param([string[]]$Arguments)\r\n";
    verify(prepareSource.split(runnerHeader).length === 2);
    await writeFile(copiedPrepare, prepareSource.replace(runnerHeader, runnerHeader + "    throw 'HERMETIC_CARGO_FORBIDDEN'\r\n"));
    const copiedNative = join(root, "scripts/service-probe/ServiceProbeNative.cs");
    const nativeSource = await readFile(copiedNative, "utf8");
    const preflightBody = /internal static bool IsUnelevatedPreparation\(\)\s*\{[\s\S]*?\r?\n {8}\}/gu;
    verify([...nativeSource.matchAll(preflightBody)].length === 1);
    await writeFile(copiedNative, nativeSource.replace(preflightBody, "internal static bool IsUnelevatedPreparation() { return true; }"));
    const build = join(root, "target/service-probe-build/x86_64-pc-windows-msvc/debug");
    await mkdir(build, { recursive: true });
    const metadata = [];
    const payloads = [];
    for (let index = 0; index < names.length; index++) {
      const name = names[index];
      const binary = name.slice(0, -4);
      const packageName = index === 1 ? "key-agent-service" : binary;
      const payload = Buffer.from("inert preparation fixture " + index + "; never executable\n", "ascii");
      payloads.push(payload);
      const executable = join(build, name);
      await writeFile(executable, payload, { flag: "wx" });
      metadata.push({
        reason: "compiler-artifact", manifest_path: join(root, "crates", packageName, "Cargo.toml"),
        target: { name: binary, kind: ["bin"], crate_types: ["bin"], src_path: join(root, "crates", packageName, index === 1 ? "src/bin/key_agent_service_probe.rs" : "src/main.rs") },
        executable, profile: { opt_level: "0", debug_assertions: true, overflow_checks: true, test: false },
        features: featureSets[index], fresh: true,
      });
    }
    await writeFile(join(root, "metadata.json"), JSON.stringify(metadata));
    await writeFile(join(root, "harness.ps1"), harness);
    return await action({ root, build, payloads });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("preparation is ASCII CRLF and the actual Cargo runner always checks non-elevation", async () => {
  const bytes = await readFile(join(import.meta.dirname, "prepare.ps1"));
  verify([...bytes].every((byte) => byte < 128));
  const source = bytes.toString("ascii");
  verify(!source.replaceAll("\r\n", "").includes("\n"));
  const runner = source.slice(source.indexOf("function Invoke-ServiceProbeCargo"), source.indexOf("function Test-ServiceProbeExactPath"));
  verify(runner.indexOf("RequireUnelevatedPreparation()") >= 0 && runner.indexOf("RequireUnelevatedPreparation()") < runner.indexOf("& cargo @Arguments"));
});

test("actual preparation CLI rejects extra arguments before reads or Cargo", async () => {
  checkedResult(await run(join(import.meta.dirname, "prepare.ps1"), ["untrusted-argument"]), 2,
    "SERVICE_PROBE_PREPARE_ARGUMENT_ERROR\nNOT_RELEASE_EVIDENCE\n");
});

for (const scenario of ["provenance", "manifest", "preflight-failed", "late-preflight-failed", "cargo-failed"]) {
  test("hermetic preparation " + scenario + " controls", async () => {
    await fixture(async ({ root }) => checkedResult(await run(join(root, "harness.ps1"), [scenario])));
  });
}

for (const scenario of ["success", "source-held"]) {
  test("hermetic preparation " + scenario + " publishes exact held bytes and manifest", async () => {
    await fixture(async ({ root, build, payloads }) => {
      if (scenario === "source-held") await link(join(build, names[0]), join(root, "owned-hardlink.exe"));
      checkedResult(await run(join(root, "harness.ps1"), [scenario]));
      const candidate = join(root, "artifacts/service-probe-candidate");
      const expected = {
        schemaVersion: 1, purpose: "service-approval-transport-debug-only", architecture: "x86_64-pc-windows-msvc",
        artifacts: names.map((name, index) => ({ name, bytes: payloads[index].length, sha256: createHash("sha256").update(payloads[index]).digest("hex") })),
      };
      verify((await readFile(join(candidate, "candidate.json"), "ascii")) === JSON.stringify(expected) + "\n");
      for (let index = 0; index < names.length; index++) verify((await readFile(join(candidate, names[index]))).equals(payloads[index]));
    });
  });
}

test("existing candidate is refused before Cargo and never overwritten", async () => {
  await fixture(async ({ root }) => {
    const candidate = join(root, "artifacts/service-probe-candidate");
    await mkdir(candidate, { recursive: true });
    await writeFile(join(candidate, "retained.txt"), "retain");
    checkedResult(await run(join(root, "harness.ps1"), ["existing"]));
    verify((await readFile(join(candidate, "retained.txt"), "ascii")) === "retain");
  });
});

for (const scenario of ["source-alias-deleted", "source-three-links", "empty-source", "source-junction"]) {
  test("preparation rejects " + scenario + " without publishing a manifest", async () => {
    await fixture(async ({ root, build }) => {
      const source = join(build, names[0]);
      if (scenario === "source-alias-deleted") await link(source, join(root, "owned-hardlink.exe"));
      if (scenario === "source-three-links") {
        await link(source, join(root, "owned-hardlink.exe"));
        await link(source, join(root, "second-owned-hardlink.exe"));
      }
      if (scenario === "empty-source") await writeFile(source, "");
      if (scenario === "source-junction") {
        const redirected = join(root, "owned-junction-destination");
        await mkdir(redirected);
        for (const name of names) await copyFile(join(build, name), join(redirected, name));
        await rm(build, { recursive: true });
        await symlink(redirected, build, "junction");
      }
      checkedResult(await run(join(root, "harness.ps1"), [scenario]));
    });
  });
}
