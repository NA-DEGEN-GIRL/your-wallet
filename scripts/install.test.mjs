// scripts/install.test.mjs — install.cmd의 scripts/install.ps1·scripts/uninstall.ps1 (spec/01 §9, spec/09 §5.12 INS-1).
// install.cmd가 쓰는 Windows PowerShell 5.1로 실제 스크립트를 실행한다. 빌드는 하지 않는다(-NoBuild + 가짜 exe가 든
// CARGO_TARGET_DIR). LOCALAPPDATA와 설치 폴더는 임시 폴더이고 -NoShortcut -NoNativeHost라 HKCU·시작 메뉴를 바꾸지 않는다.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { auditExtensionRoot } from "./audit-extension.mjs";
import { extensionIdFromKey } from "./extension-key.mjs";
import { validateNativeManifestFile } from "../extension/native-host/validate-manifest.mjs";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const installScript = path.join(repoRoot, "scripts", "install.ps1");
const uninstallScript = path.join(repoRoot, "scripts", "uninstall.ps1");
const extensionRoot = path.join(repoRoot, "extension");
const windows = process.platform === "win32";
const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
const windowsPowerShell = path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
const EXTENSION_ID = "nnpjlobjgbanccjddghlpaafpohfkeph";

function findOnPath(name) {
  const candidates = [];
  if (process.env.ProgramFiles) candidates.push(path.join(process.env.ProgramFiles, "PowerShell", "7", name));
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) if (dir) candidates.push(path.join(dir, name));
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

// PSModulePath는 넘기지 않는다: PowerShell 7에서 시작한 node가 그 경로를 5.1에 넘기면 5.1이 7의 모듈을 읽으려 한다.
function childEnv(overrides = {}) {
  const drop = new Set(["psmodulepath", ...Object.keys(overrides).map((key) => key.toLowerCase())]);
  const env = {};
  for (const [key, value] of Object.entries(process.env)) if (!drop.has(key.toLowerCase())) env[key] = value;
  return { ...env, ...overrides };
}

// 비대화형(-NonInteractive, stdin 없음)이라 스크립트는 묻지 않고, 클립보드도 건드리지 않는다.
function runPowerShell(shell, args, env) {
  const result = spawnSync(shell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", ...args], {
    encoding: "utf8", env, stdio: ["ignore", "pipe", "pipe"], timeout: 120_000, windowsHide: true,
  });
  return { status: result.status, out: `${result.stdout ?? ""}${result.stderr ?? ""}${result.error ? String(result.error) : ""}` };
}

async function listFiles(root) {
  const files = [];
  async function walk(dir, prefix) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(path.join(dir, entry.name), rel);
      else files.push(rel);
    }
  }
  await walk(root, "");
  return files.sort();
}

async function modifiedTimes(root) {
  const times = {};
  for (const rel of await listFiles(root)) times[rel] = (await stat(path.join(root, ...rel.split("/")))).mtimeMs;
  return times;
}

async function workspaceVersion() {
  const cargoToml = await readFile(path.join(repoRoot, "Cargo.toml"), "utf8");
  const section = /^\[workspace\.package\][ \t]*\r?$([\s\S]*?)(?=^\[|(?![\s\S]))/mu.exec(cargoToml);
  return /^[ \t]*version[ \t]*=[ \t]*"(\d+\.\d+\.\d+)"/mu.exec(section[1])[1];
}

async function withTemp(prefix, callback) {
  const temp = await mkdtemp(path.join(os.tmpdir(), prefix));
  try {
    return await callback(temp);
  } finally {
    await rm(temp, { force: true, recursive: true });
  }
}

// INS-1 표본: validate-manifest.mjs와 install.ps1 Test-NativeManifestFile이 같은 판정을 내려야 한다.
function manifestSamples() {
  const base = {
    name: "com.your_wallet.native",
    description: "Your Wallet native messaging host",
    path: "C:\\Users\\Test\\AppData\\Local\\Programs\\YourWallet\\yw-host.exe",
    type: "stdio",
    allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
  };
  const json = (value) => Buffer.from(JSON.stringify(value, null, 2), "utf8");
  const withPath = (value) => json({ ...base, path: value });
  const withOrigins = (value) => json({ ...base, allowed_origins: value });
  const { type: _type, ...withoutType } = base;
  const invalidUtf8Text = JSON.stringify({ ...base, description: "AB" });
  const marker = invalidUtf8Text.indexOf("AB");
  return {
    valid: json(base),
    "valid compact with newline": Buffer.from(`${JSON.stringify(base)}\n`),
    "upper-case exe": withPath("D:\\Wallet\\YW-HOST.EXE"),
    "space and hangul path": withPath("C:\\Users\\홍 길동\\AppData\\Local\\Programs\\YourWallet\\yw-host.exe"),
    "file at drive root": withPath("C:\\yw-host.exe"),
    "description 128": json({ ...base, description: "x".repeat(128) }),
    "description 129": json({ ...base, description: "x".repeat(129) }),
    "emoji description 130 units": json({ ...base, description: "\u{1F600}".repeat(65) }),
    "empty description": json({ ...base, description: "" }),
    "other id": withOrigins(["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]),
    "two origins": withOrigins([`chrome-extension://${EXTENSION_ID}/`, `chrome-extension://${EXTENSION_ID}/`]),
    "origin without slash": withOrigins([`chrome-extension://${EXTENSION_ID}`]),
    "origin with newline": withOrigins([`chrome-extension://${EXTENSION_ID}/\n`]),
    "upper-case id": withOrigins([`chrome-extension://${EXTENSION_ID.toUpperCase()}/`]),
    "wildcard origin": withOrigins(["chrome-extension://*/"]),
    "placeholder origin": withOrigins(["chrome-extension://__EXTENSION_ID__/"]),
    "origins string": withOrigins(`chrome-extension://${EXTENSION_ID}/`),
    "origins empty": withOrigins([]),
    "extra key": json({ ...base, extra: true }),
    "missing key": json(withoutType),
    "wrong name": json({ ...base, name: "com.other.native" }),
    "wrong type": json({ ...base, type: "pipe" }),
    percent: withPath("C:\\%USERNAME%\\yw-host.exe"),
    ampersand: withPath("C:\\a&b\\yw-host.exe"),
    caret: withPath("C:\\a^b\\yw-host.exe"),
    bang: withPath("C:\\a!b\\yw-host.exe"),
    "control character": withPath("C:\\a\u0001b\\yw-host.exe"),
    relative: withPath("Programs\\YourWallet\\yw-host.exe"),
    unc: withPath("\\\\server\\share\\yw-host.exe"),
    "dot dot": withPath("C:\\a\\..\\yw-host.exe"),
    "trailing dot": withPath("C:\\a.\\yw-host.exe"),
    "trailing space": withPath("C:\\a \\yw-host.exe"),
    "empty segment": withPath("C:\\a\\\\yw-host.exe"),
    "forward slashes": withPath("C:/a/yw-host.exe"),
    "drive root": withPath("C:\\"),
    "yw-app.exe": withPath("C:\\a\\yw-app.exe"),
    "suffix only": withPath("C:\\a\\my-yw-host.exe"),
    "placeholder path": withPath("C:\\__INSTALL_DIR__\\yw-host.exe"),
    "path number": json({ ...base, path: 5 }),
    "not json": Buffer.from("not json"),
    "top-level array": Buffer.from("[]"),
    "top-level null": Buffer.from("null"),
    "utf-8 bom": Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), json(base)]),
    "invalid utf-8": Buffer.concat([Buffer.from(invalidUtf8Text.slice(0, marker)), Buffer.from([0xc3, 0x28]), Buffer.from(invalidUtf8Text.slice(marker + 2))]),
  };
}

const PARITY_SCRIPT = `param([string]$Script, [string]$Extension, [string]$SampleList, [string]$ExpectedId)
$ErrorActionPreference = 'Stop'
. $Script
$verdicts = @(foreach ($sample in [IO.File]::ReadAllLines($SampleList)) { [bool](Test-NativeManifestFile $sample $ExpectedId) })
$manifest = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Extension 'manifest.json')))
$result = [ordered]@{
    extensionId = $ExtensionId
    idFromKey   = Get-ExtensionIdFromKey ([string]$manifest.key)
    files       = Get-ExtensionRuntimeFiles $Extension
    verdicts    = $verdicts
}
[Console]::Out.Write((ConvertTo-Json -InputObject $result -Depth 3 -Compress))
`;

const parityShells = windows ? [["Windows PowerShell 5.1", windowsPowerShell], ["PowerShell 7", findOnPath("pwsh.exe")]] : [];
for (const [label, shell] of parityShells) {
  test(`INS-1 install.ps1 helpers match the Node validators and the audited extension file list (${label})`, { skip: shell === null ? "pwsh.exe not found" : false, timeout: 120_000 }, async () => {
    await withTemp("your-wallet-install-parity-", async (temp) => {
      const samples = Object.entries(manifestSamples());
      const files = [];
      for (const [index, [, bytes]] of samples.entries()) {
        const file = path.join(temp, `sample-${index}.json`);
        await writeFile(file, bytes);
        files.push(file);
      }
      const sampleList = path.join(temp, "samples.txt");
      await writeFile(sampleList, `${files.join("\r\n")}\r\n`);
      const helper = path.join(temp, "parity.ps1");
      await writeFile(helper, PARITY_SCRIPT);
      const run = runPowerShell(shell, ["-File", helper, "-Script", installScript, "-Extension", extensionRoot, "-SampleList", sampleList, "-ExpectedId", EXTENSION_ID], childEnv());
      assert.equal(run.status, 0, run.out);
      const result = JSON.parse(run.out);

      const extensionIdFile = (await readFile(path.join(extensionRoot, "extension-id.txt"), "utf8")).trim();
      const manifest = JSON.parse(await readFile(path.join(extensionRoot, "manifest.json"), "utf8"));
      assert.equal(result.extensionId, extensionIdFile);
      assert.equal(result.idFromKey, extensionIdFromKey(manifest.key));
      const audited = await auditExtensionRoot(extensionRoot);
      assert.equal(existsSync(path.join(extensionRoot, "icons")), false, "icons/ would be installed too; extend this assertion");
      assert.deepEqual(result.files, audited.packagedFiles);

      assert.equal(result.verdicts.length, samples.length);
      samples.forEach(([name], index) => {
        assert.equal(result.verdicts[index], validateNativeManifestFile(files[index], EXTENSION_ID).valid, name);
      });
      assert.equal(result.verdicts[0], true);
      assert.ok(result.verdicts.filter((verdict) => !verdict).length >= 30);
    });
  });
}

test("install.ps1 -NoBuild installs, re-installs, upgrades, refuses unsafe folders; uninstall.ps1 keeps wallet data (Windows PowerShell 5.1)", { skip: !windows, timeout: 300_000 }, async () => {
  await withTemp("your-wallet-install-", async (temp) => {
    const localAppData = path.join(temp, "LocalAppData");
    const dataDir = path.join(localAppData, "YourWallet");
    const sentinel = path.join(dataDir, "v3", "settings.json");
    await mkdir(path.dirname(sentinel), { recursive: true });
    await writeFile(sentinel, "{\"version\":1}\n");
    const cargoTarget = path.join(temp, "cargo-target");
    const releaseDir = path.join(cargoTarget, "release");
    await mkdir(releaseDir, { recursive: true });
    await writeFile(path.join(releaseDir, "yw-app.exe"), "fake yw-app 1\n");
    await writeFile(path.join(releaseDir, "yw-host.exe"), "fake yw-host 1\n");
    const env = childEnv({ LOCALAPPDATA: localAppData, CARGO_TARGET_DIR: cargoTarget });
    const install = (...args) => runPowerShell(windowsPowerShell, ["-File", installScript, "-NoBuild", "-NoShortcut", "-NoNativeHost", ...args], env);
    const installDir = path.join(temp, "Programs", "YourWallet");
    const { packagedFiles } = await auditExtensionRoot(extensionRoot);
    const programFiles = ["uninstall.ps1", "yw-app.exe", "yw-host.exe", ...packagedFiles.map((file) => `extension/${file}`)].sort();
    const version = await workspaceVersion();

    // -DryRun with the default folder: plan only, nothing created.
    let run = install("-DryRun");
    assert.equal(run.status, 0, run.out);
    assert.match(run.out, /\[DryRun\] .*yw-app\.exe/u);
    assert.ok(run.out.includes(path.join(localAppData, "Programs", "YourWallet")), run.out);
    assert.equal(existsSync(path.join(localAppData, "Programs")), false);

    // Install.
    run = install("-InstallDir", installDir);
    assert.equal(run.status, 0, run.out);
    assert.deepEqual(await listFiles(installDir), [...programFiles, "com.your_wallet.native.json", "yw-install.json"].sort());
    for (const file of packagedFiles) {
      assert.deepEqual(await readFile(path.join(installDir, "extension", file)), await readFile(path.join(extensionRoot, file)), file);
    }
    assert.equal(await readFile(path.join(installDir, "yw-app.exe"), "utf8"), "fake yw-app 1\n");
    assert.deepEqual(await readFile(path.join(installDir, "uninstall.ps1")), await readFile(uninstallScript));
    const manifestPath = path.join(installDir, "com.your_wallet.native.json");
    assert.deepEqual(validateNativeManifestFile(manifestPath, EXTENSION_ID), { valid: true, extensionId: EXTENSION_ID });
    assert.equal(JSON.parse(await readFile(manifestPath, "utf8")).path, path.join(installDir, "yw-host.exe"));
    let record = JSON.parse(await readFile(path.join(installDir, "yw-install.json"), "utf8"));
    assert.equal(record.product, "YourWallet");
    assert.equal(record.version, version);
    assert.equal(record.state, "installed");
    assert.ok(record.commit === null || /^[0-9a-f]{12}$/u.test(record.commit), String(record.commit));
    assert.deepEqual(record.files, programFiles);
    assert.equal(await readFile(sentinel, "utf8"), "{\"version\":1}\n");

    // Same source again: nothing is rewritten.
    const before = await modifiedTimes(installDir);
    run = install("-InstallDir", installDir);
    assert.equal(run.status, 0, run.out);
    assert.deepEqual(await modifiedTimes(installDir), before);

    // Upgrade from an older install record (the former zip layout): the changed exe is copied, files only the
    // old record listed are removed, and the record is rewritten.
    await writeFile(path.join(releaseDir, "yw-app.exe"), "fake yw-app 2\n");
    const oldReadme = "README-설치.txt";
    await writeFile(path.join(installDir, oldReadme), "old\n");
    await writeFile(path.join(installDir, "yw-install.json"), JSON.stringify({ product: "YourWallet", version: "0.2.0", state: "installed", files: [...programFiles, oldReadme].sort() }, null, 2));
    run = install("-InstallDir", installDir);
    assert.equal(run.status, 0, run.out);
    assert.equal(await readFile(path.join(installDir, "yw-app.exe"), "utf8"), "fake yw-app 2\n");
    assert.equal(existsSync(path.join(installDir, oldReadme)), false);
    record = JSON.parse(await readFile(path.join(installDir, "yw-install.json"), "utf8"));
    assert.equal(record.version, version);
    assert.deepEqual(record.files, programFiles);

    // Refusals change nothing.
    const ampersand = path.join(temp, "a&b");
    run = install("-InstallDir", ampersand);
    assert.equal(run.status, 1, run.out);
    assert.equal(existsSync(ampersand), false);
    const foreign = path.join(temp, "foreign");
    await mkdir(foreign);
    await writeFile(path.join(foreign, "keep.txt"), "keep\n");
    run = install("-InstallDir", foreign);
    assert.equal(run.status, 1, run.out);
    assert.deepEqual(await listFiles(foreign), ["keep.txt"]);
    run = install("-InstallDir", path.join(dataDir, "Programs"));
    assert.equal(run.status, 1, run.out);
    assert.equal(existsSync(path.join(dataDir, "Programs")), false);
    run = install("-InstallDir", path.join(repoRoot, "target", "yw-install-test"));
    assert.equal(run.status, 1, run.out);
    assert.equal(existsSync(path.join(repoRoot, "target", "yw-install-test")), false);
    const emptyTarget = path.join(temp, "empty-target");
    await mkdir(emptyTarget);
    const fresh = path.join(temp, "fresh");
    run = runPowerShell(windowsPowerShell, ["-File", installScript, "-NoBuild", "-NoShortcut", "-NoNativeHost", "-InstallDir", fresh], childEnv({ LOCALAPPDATA: localAppData, CARGO_TARGET_DIR: emptyTarget }));
    assert.equal(run.status, 2, run.out);
    assert.equal(existsSync(fresh), false);

    // Uninstall with the copy inside the install folder (it finds its own folder).
    const uninstall = (script, ...args) => runPowerShell(windowsPowerShell, ["-File", script, "-NoShortcut", "-NoNativeHost", ...args], env);
    const installed = await listFiles(installDir);
    run = uninstall(path.join(installDir, "uninstall.ps1"), "-DryRun");
    assert.equal(run.status, 0, run.out);
    assert.deepEqual(await listFiles(installDir), installed);
    run = uninstall(path.join(installDir, "uninstall.ps1"), "-RemoveWalletData");
    assert.equal(run.status, 3, run.out);
    assert.deepEqual(await listFiles(installDir), installed);
    assert.equal(await readFile(sentinel, "utf8"), "{\"version\":1}\n");
    run = uninstall(path.join(installDir, "uninstall.ps1"));
    assert.equal(run.status, 0, run.out);
    assert.equal(existsSync(installDir), false);
    assert.ok(run.out.includes(dataDir), run.out);
    assert.equal(await readFile(sentinel, "utf8"), "{\"version\":1}\n");
    run = uninstall(uninstallScript, "-InstallDir", installDir);
    assert.equal(run.status, 0, run.out);
  });
});

test("install.ps1 refuses a source tree whose extension is not the reviewed one", { skip: !windows, timeout: 120_000 }, async () => {
  await withTemp("your-wallet-install-source-", async (temp) => {
    const root = path.join(temp, "repo");
    for (const file of ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "scripts/install.ps1", "scripts/uninstall.ps1"]) {
      await mkdir(path.dirname(path.join(root, file)), { recursive: true });
      await cp(path.join(repoRoot, file), path.join(root, file));
    }
    await cp(extensionRoot, path.join(root, "extension"), { recursive: true });
    const cargoTarget = path.join(temp, "cargo-target");
    await mkdir(path.join(cargoTarget, "release"), { recursive: true });
    await writeFile(path.join(cargoTarget, "release", "yw-app.exe"), "fake\n");
    await writeFile(path.join(cargoTarget, "release", "yw-host.exe"), "fake\n");
    const env = childEnv({ LOCALAPPDATA: path.join(temp, "LocalAppData"), CARGO_TARGET_DIR: cargoTarget });
    const installDir = path.join(temp, "installed");
    const install = () => runPowerShell(windowsPowerShell, ["-File", path.join(root, "scripts", "install.ps1"), "-NoBuild", "-NoShortcut", "-NoNativeHost", "-InstallDir", installDir], env);

    // The unchanged copy installs; then reset.
    let run = install();
    assert.equal(run.status, 0, run.out);
    await rm(installDir, { force: true, recursive: true });

    // A different manifest key (another extension ID) is refused before anything is written.
    const manifestPath = path.join(root, "extension", "manifest.json");
    const original = await readFile(manifestPath, "utf8");
    const manifest = JSON.parse(original);
    manifest.key = Buffer.alloc(96, 7).toString("base64");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    run = install();
    assert.equal(run.status, 2, run.out);
    assert.equal(existsSync(installDir), false);
    await writeFile(manifestPath, original);

    // A non-JavaScript file in extension/src is refused (the static audit would reject it too).
    await writeFile(path.join(root, "extension", "src", "notes.txt"), "x\n");
    run = install();
    assert.equal(run.status, 2, run.out);
    assert.equal(existsSync(installDir), false);
  });
});
