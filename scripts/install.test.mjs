// scripts/install.test.mjs — install.cmd의 scripts/install.ps1·scripts/uninstall.ps1 (spec/01 §9, spec/09 §5.12 INS-1).
// install.cmd가 쓰는 Windows PowerShell 5.1로 실제 스크립트를 실행한다. 빌드는 하지 않는다(-NoBuild + 가짜 exe가 든
// CARGO_TARGET_DIR). LOCALAPPDATA와 설치 폴더는 임시 폴더이고 -NoShortcut -NoNativeHost라 HKCU·시작 메뉴를 바꾸지 않는다.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
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
// overrides의 값이 null이면 그 변수를 넘기지 않는다.
function childEnv(overrides = {}) {
  const drop = new Set(["psmodulepath", ...Object.keys(overrides).map((key) => key.toLowerCase())]);
  const env = {};
  for (const [key, value] of Object.entries(process.env)) if (!drop.has(key.toLowerCase())) env[key] = value;
  for (const [key, value] of Object.entries(overrides)) if (value !== null && value !== undefined) env[key] = value;
  return env;
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

let currentUserSid = null;
function userSid() {
  if (currentUserSid === null) {
    const result = spawnSync(path.join(systemRoot, "System32", "whoami.exe"), ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true });
    const match = /"(S-1-[0-9-]+)"/u.exec(result.stdout ?? "");
    assert.ok(match, `whoami /user: ${result.stdout}${result.stderr}`);
    currentUserSid = match[1];
  }
  return currentUserSid;
}

// Hermetic temp root: a protected DACL with only the current user, SYSTEM and Administrators, so the results do not
// depend on the host %TEMP% ACL (e.g. sandbox SIDs with Modify inherited into new temp folders).
function protectDir(dir) {
  icacls(dir, "/inheritance:r", "/grant:r", `*${userSid()}:(OI)(CI)F`, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F");
}

async function withTemp(prefix, callback) {
  const temp = await mkdtemp(path.join(os.tmpdir(), prefix));
  if (windows) protectDir(temp);
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
      assert.deepEqual(result.files, audited.packagedFiles);
      assert.deepEqual(result.files.filter((file) => file.startsWith("icons/")), ["icons/icon-128.png", "icons/icon-16.png", "icons/icon-32.png", "icons/icon-48.png"]);

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
    // Review L7: the record keeps the SHA-256 of every installed file.
    assert.deepEqual(Object.keys(record.hashes), programFiles);
    for (const file of programFiles) {
      const bytes = await readFile(path.join(installDir, ...file.split("/")));
      assert.equal(record.hashes[file], createHash("sha256").update(bytes).digest("hex"), file);
    }
    assert.equal(await readFile(sentinel, "utf8"), "{\"version\":1}\n");

    // Same source again: nothing is rewritten.
    const before = await modifiedTimes(installDir);
    run = install("-InstallDir", installDir);
    assert.equal(run.status, 0, run.out);
    assert.doesNotMatch(run.out, /설치한 뒤 바뀐 파일/u);
    assert.deepEqual(await modifiedTimes(installDir), before);

    // An installed file changed after the install: the next run warns (by name) and rewrites it.
    await writeFile(path.join(installDir, "yw-host.exe"), "tampered\n");
    run = install("-InstallDir", installDir);
    assert.equal(run.status, 0, run.out);
    assert.match(run.out, /설치한 뒤 바뀐 파일이 있습니다[^\n]*yw-host\.exe/u);
    assert.equal(await readFile(path.join(installDir, "yw-host.exe"), "utf8"), "fake yw-host 1\n");

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

    // A non-PNG file in extension/icons is refused (the static audit would reject it too).
    const iconNote = path.join(root, "extension", "icons", "notes.txt");
    await writeFile(iconNote, "x\n");
    run = install();
    assert.equal(run.status, 2, run.out);
    assert.equal(existsSync(installDir), false);
    await rm(iconNote);

    // A non-JavaScript file in extension/src is refused (the static audit would reject it too).
    await writeFile(path.join(root, "extension", "src", "notes.txt"), "x\n");
    run = install();
    assert.equal(run.status, 2, run.out);
    assert.equal(existsSync(installDir), false);
  });
});

// Review L7: the source tree and the build folder the files are copied from get the same ACL rule as the install
// folder (another user who can modify them could plant yw-host.exe or extension code). SIDs never given to a logon
// session (S-1-4-*, AppContainer) are ignored.
test("install.ps1 refuses a source or build folder other users can modify unless -AllowUnsafeSourcePath (Windows PowerShell 5.1)", { skip: !windows, timeout: 300_000 }, async () => {
  await withTemp("your-wallet-install-srcacl-", async (temp) => {
    const root = path.join(temp, "repo");
    for (const file of ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "scripts/install.ps1", "scripts/uninstall.ps1"]) {
      await mkdir(path.dirname(path.join(root, file)), { recursive: true });
      await cp(path.join(repoRoot, file), path.join(root, file));
    }
    await cp(extensionRoot, path.join(root, "extension"), { recursive: true });
    const cargoTarget = path.join(temp, "cargo-target");
    const releaseDir = path.join(cargoTarget, "release");
    await mkdir(releaseDir, { recursive: true });
    await writeFile(path.join(releaseDir, "yw-app.exe"), "fake\n");
    await writeFile(path.join(releaseDir, "yw-host.exe"), "fake\n");
    const env = childEnv({ LOCALAPPDATA: path.join(temp, "LocalAppData"), CARGO_TARGET_DIR: cargoTarget });
    const installDir = path.join(temp, "installed");
    const install = (...extra) => runPowerShell(windowsPowerShell, ["-File", path.join(root, "scripts", "install.ps1"), "-NoBuild", "-NoShortcut", "-NoNativeHost", "-InstallDir", installDir, ...extra], env);
    const AUTHENTICATED_USERS = "*S-1-5-11";

    // An AppContainer SID with write rights is ignored (not a logon principal) ...
    icacls(root, "/grant", "*S-1-15-2-1:(OI)(CI)M");
    let run = install();
    assert.equal(run.status, 0, run.out);
    await rm(installDir, { force: true, recursive: true });
    // ... and so is a sandbox's restricting SID (S-1-4-*; icacls cannot name an unmapped SID, so the rule is
    // checked on the SDDL directly), while the same rights for Authenticated Users are refused.
    const helper = path.join(temp, "source-acl.ps1");
    await writeFile(helper, `param([string]$Script)
$ErrorActionPreference = 'Stop'
. $Script
$user = Get-CurrentUserSid
$base = "O:$($user)D:(A;OICI;FA;;;$($user))(A;OICI;FA;;;SY)"
$verdicts = @(
    (Get-SourceAclProblem "$base(A;OICI;0x110156;;;S-1-4-554837906-625088534)" $user),
    (Get-SourceAclProblem "$base(A;OICI;0x1301bf;;;S-1-15-3-1)" $user),
    (Get-SourceAclProblem "$base(A;OICI;0x1301bf;;;AU)" $user),
    (Get-AclProblem "$base(A;OICI;0x110156;;;S-1-4-554837906-625088534)" $user)
) | ForEach-Object { $null -eq $_ }
[Console]::Out.Write((ConvertTo-Json -InputObject $verdicts -Compress))
`);
    const verdicts = runPowerShell(windowsPowerShell, ["-File", helper, "-Script", path.join(root, "scripts", "install.ps1")], childEnv());
    assert.equal(verdicts.status, 0, verdicts.out);
    // Install-folder rule (Get-AclProblem) is unchanged: it still refuses the S-1-4 ACE.
    assert.deepEqual(JSON.parse(verdicts.out), [true, true, false, false]);

    for (const [label, target, grant] of [
      ["repo root", root, `${AUTHENTICATED_USERS}:(OI)(CI)M`],
      ["one extension file", path.join(root, "extension", "manifest.json"), `${AUTHENTICATED_USERS}:M`],
      ["release folder", releaseDir, `${AUTHENTICATED_USERS}:(OI)(CI)M`],
      ["yw-host.exe", path.join(releaseDir, "yw-host.exe"), `${AUTHENTICATED_USERS}:W`],
    ]) {
      icacls(target, "/grant", grant);
      run = install();
      assert.equal(run.status, 1, `${label}: ${run.out}`);
      assert.match(run.out, /소스·빌드 폴더를 다른 사용자가 바꿀 수 있습니다/u, label);
      assert.equal(existsSync(installDir), false, label);
      // The override installs with a warning.
      run = install("-AllowUnsafeSourcePath");
      assert.equal(run.status, 0, `${label}: ${run.out}`);
      assert.match(run.out, /-AllowUnsafeSourcePath: 그대로 설치합니다/u, label);
      await rm(installDir, { force: true, recursive: true });
      icacls(target, "/remove:g", AUTHENTICATED_USERS);
    }
    run = install();
    assert.equal(run.status, 0, run.out);
  });
});

// The folder ACL of an install (security review: another local user must not be able to replace
// yw-host.exe, yw-app.exe, the extension or the native host manifest).
const ACL_SCRIPT = `param([string]$Path)
$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath $Path
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
    [ordered]@{ sid = $_.IdentityReference.Value; rights = [int]$_.FileSystemRights; allow = ($_.AccessControlType -eq 'Allow'); inherited = $_.IsInherited }
})
$result = [ordered]@{
    user      = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    owner     = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    protected = $acl.AreAccessRulesProtected
    rules     = $rules
}
[Console]::Out.Write((ConvertTo-Json -InputObject $result -Depth 4 -Compress))
`;

const ACL_PROBLEM_SCRIPT = `param([string]$Script, [string]$SampleList)
$ErrorActionPreference = 'Stop'
. $Script
$user = Get-CurrentUserSid
$verdicts = @(foreach ($sddl in [IO.File]::ReadAllLines($SampleList)) { $null -eq (Get-AclProblem $sddl.Replace('USER', $user) $user) })
[Console]::Out.Write((ConvertTo-Json -InputObject $verdicts -Compress))
`;

const FULL_CONTROL = 0x1f01ff;
const SYSTEM = "S-1-5-18";
const ADMINISTRATORS = "S-1-5-32-544";

async function readAcl(temp, target) {
  const helper = path.join(temp, "acl.ps1");
  await writeFile(helper, ACL_SCRIPT);
  const run = runPowerShell(windowsPowerShell, ["-File", helper, "-Path", target], childEnv());
  assert.equal(run.status, 0, run.out);
  return JSON.parse(run.out);
}

/** Only the current user, SYSTEM and Administrators, each with full control. */
function assertPrivate(acl, { inherited }) {
  const sids = acl.rules.map((rule) => rule.sid).sort();
  assert.deepEqual(sids, [acl.user, SYSTEM, ADMINISTRATORS].sort(), JSON.stringify(acl));
  for (const rule of acl.rules) {
    assert.equal(rule.allow, true, JSON.stringify(rule));
    assert.equal(rule.rights, FULL_CONTROL, JSON.stringify(rule));
    assert.equal(rule.inherited, inherited, JSON.stringify(rule));
  }
}

function icacls(...args) {
  const result = spawnSync(path.join(systemRoot, "System32", "icacls.exe"), args, { encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
}

test("install.ps1 Get-AclProblem: owner, other SIDs with write rights, CREATOR OWNER inherit-only, deny and read-only ACEs", { skip: !windows, timeout: 120_000 }, async () => {
  await withTemp("your-wallet-install-aclrules-", async (temp) => {
    const samples = [
      ["O:USERD:P(A;OICI;FA;;;USER)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true],
      ["O:SYD:P(A;OICI;FA;;;USER)", true],
      ["O:BAD:P(A;OICI;FA;;;USER)", true],
      ["O:WDD:P(A;OICI;FA;;;USER)", false],
      ["O:BUD:P(A;OICI;FA;;;USER)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;OICIIO;FA;;;CO)", true],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;OICI;FA;;;CO)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;OICIIO;0x1301bf;;;BU)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;OICI;0x1301bf;;;AU)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;OICI;0x1301bf;;;WD)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;;0x10000;;;BU)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;;0x40000;;;BU)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;;0x80000;;;BU)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;;GA;;;WD)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;;GW;;;WD)", false],
      ["O:USERD:P(A;OICI;FA;;;USER)(A;OICI;0x1200a9;;;BU)", true],
      ["O:USERD:P(A;OICI;FA;;;USER)(D;OICI;FA;;;WD)", true],
      ["O:USERD:NO_ACCESS_CONTROL", false],
    ];
    const sampleList = path.join(temp, "sddl.txt");
    await writeFile(sampleList, `${samples.map(([sddl]) => sddl).join("\r\n")}\r\n`);
    const helper = path.join(temp, "problem.ps1");
    await writeFile(helper, ACL_PROBLEM_SCRIPT);
    const run = runPowerShell(windowsPowerShell, ["-File", helper, "-Script", installScript, "-SampleList", sampleList], childEnv());
    assert.equal(run.status, 0, run.out);
    const verdicts = JSON.parse(run.out);
    samples.forEach(([sddl, safe], index) => assert.equal(verdicts[index], safe, sddl));
  });
});

test("install.ps1 creates a private install folder, refuses one other users can write, -FixPermissions hardens it (Windows PowerShell 5.1)", { skip: !windows, timeout: 300_000 }, async () => {
  await withTemp("your-wallet-install-acl-", async (temp) => {
    const localAppData = path.join(temp, "LocalAppData");
    await mkdir(localAppData, { recursive: true });
    const cargoTarget = path.join(temp, "cargo-target");
    const releaseDir = path.join(cargoTarget, "release");
    await mkdir(releaseDir, { recursive: true });
    await writeFile(path.join(releaseDir, "yw-app.exe"), "fake yw-app\n");
    await writeFile(path.join(releaseDir, "yw-host.exe"), "fake yw-host\n");
    const env = childEnv({ LOCALAPPDATA: localAppData, CARGO_TARGET_DIR: cargoTarget });
    const install = (...args) => runPowerShell(windowsPowerShell, ["-File", installScript, "-NoBuild", "-NoShortcut", "-NoNativeHost", ...args], env);

    // A fresh install: protected DACL with exactly the current user, SYSTEM and Administrators
    // (full control, nothing inherited from the temp folder); the files inherit only those.
    const fresh = path.join(temp, "parent", "YourWallet");
    let run = install("-InstallDir", fresh);
    assert.equal(run.status, 0, run.out);
    let acl = await readAcl(temp, fresh);
    assert.equal(acl.protected, true);
    assert.equal(acl.owner, acl.user);
    assertPrivate(acl, { inherited: false });
    // The missing parent is created the same way (one level at a time, verified).
    acl = await readAcl(temp, path.dirname(fresh));
    assert.equal(acl.protected, true);
    assertPrivate(acl, { inherited: false });
    for (const file of ["yw-host.exe", "yw-app.exe", "com.your_wallet.native.json", "extension/manifest.json"]) {
      const fileAcl = await readAcl(temp, path.join(fresh, ...file.split("/")));
      assertPrivate(fileAcl, { inherited: true });
    }
    // Re-install (upgrade path) of the private folder: accepted, unchanged.
    run = install("-InstallDir", fresh);
    assert.equal(run.status, 0, run.out);

    // An existing empty folder with an extra Everyone:Modify ACE: refused, nothing written.
    const shared = path.join(temp, "shared");
    await mkdir(shared);
    icacls(shared, "/grant", "*S-1-1-0:(OI)(CI)M");
    run = install("-InstallDir", shared);
    assert.equal(run.status, 1, run.out);
    assert.match(run.out, /-FixPermissions/u);
    assert.deepEqual(await readdir(shared), []);
    acl = await readAcl(temp, shared);
    assert.ok(acl.rules.some((rule) => rule.sid === "S-1-1-0"), "the ACL is not changed without -FixPermissions");
    // -DryRun -FixPermissions plans only.
    run = install("-InstallDir", shared, "-FixPermissions", "-DryRun");
    assert.equal(run.status, 0, run.out);
    acl = await readAcl(temp, shared);
    assert.ok(acl.rules.some((rule) => rule.sid === "S-1-1-0"));
    // -FixPermissions (the folder is the current user's): hardened, then installed.
    run = install("-InstallDir", shared, "-FixPermissions");
    assert.equal(run.status, 0, run.out);
    acl = await readAcl(temp, shared);
    assert.equal(acl.protected, true);
    assertPrivate(acl, { inherited: false });

    // An upgrade where one installed file got an explicit Everyone:Modify ACE: refused until fixed.
    icacls(path.join(fresh, "yw-host.exe"), "/grant", "*S-1-1-0:M");
    run = install("-InstallDir", fresh);
    assert.equal(run.status, 1, run.out);
    assert.ok(run.out.includes("yw-host.exe"), run.out);
    run = install("-InstallDir", fresh, "-FixPermissions");
    assert.equal(run.status, 0, run.out);
    assertPrivate(await readAcl(temp, path.join(fresh, "yw-host.exe")), { inherited: true });
  });
});

// Ancestor rule (install.ps1 header, Get-InstallAncestorProblems): with U = rights the untrusted SIDs get on an
// existing ancestor itself, refuse (a) a link, an untrusted owner, FILE_DELETE_CHILD/WRITE_DAC/WRITE_OWNER/GENERIC_ALL
// in U, (b) DELETE in U while the ancestor's parent gives the untrusted SIDs add-file/add-subdirectory. Read-only and
// add-only grants are fine; missing parents are created private.
test("install.ps1 -InstallDir checks every ancestor: delete-child, inherited Modify, WRITE_DAC and junctions are refused; read-only, add-only and DELETE without a re-creatable parent pass (Windows PowerShell 5.1)", { skip: !windows, timeout: 300_000 }, async () => {
  await withTemp("your-wallet-install-ancestors-", async (temp) => {
    const localAppData = path.join(temp, "LocalAppData");
    await mkdir(localAppData, { recursive: true });
    const cargoTarget = path.join(temp, "cargo-target");
    await mkdir(path.join(cargoTarget, "release"), { recursive: true });
    await writeFile(path.join(cargoTarget, "release", "yw-app.exe"), "fake yw-app\n");
    await writeFile(path.join(cargoTarget, "release", "yw-host.exe"), "fake yw-host\n");
    const env = childEnv({ LOCALAPPDATA: localAppData, CARGO_TARGET_DIR: cargoTarget });
    const install = (...args) => runPowerShell(windowsPowerShell, ["-File", installScript, "-NoBuild", "-NoShortcut", "-NoNativeHost", ...args], env);
    const refused = (run, dir) => {
      assert.equal(run.status, 1, run.out);
      assert.ok(run.out.includes(dir), run.out);
    };

    // A clean tree with two missing intermediate folders: installed; every created folder is private.
    const clean = path.join(temp, "clean");
    await mkdir(clean);
    const deep = path.join(clean, "new1", "new2", "YourWallet");
    let run = install("-InstallDir", deep);
    assert.equal(run.status, 0, run.out);
    for (const dir of [path.join(clean, "new1"), path.join(clean, "new1", "new2"), deep]) {
      const acl = await readAcl(temp, dir);
      assert.equal(acl.protected, true, dir);
      assertPrivate(acl, { inherited: false });
    }

    // Everyone may delete children of an ancestor: refused (also in -DryRun, before any build), nothing created.
    const deleteChild = path.join(temp, "dc");
    await mkdir(deleteChild);
    icacls(deleteChild, "/grant", "*S-1-1-0:(DC)");
    run = install("-InstallDir", path.join(deleteChild, "YourWallet"), "-DryRun");
    refused(run, deleteChild);
    run = install("-InstallDir", path.join(deleteChild, "YourWallet"));
    refused(run, deleteChild);
    assert.deepEqual(await readdir(deleteChild), []);

    // Users:Modify inherited by an existing intermediate folder: it can be moved away and re-created by others.
    const modify = path.join(temp, "mod");
    await mkdir(modify);
    icacls(modify, "/grant", "*S-1-5-32-545:(OI)(CI)M");
    const modifySub = path.join(modify, "sub");
    await mkdir(modifySub);
    run = install("-InstallDir", path.join(modifySub, "YourWallet"));
    refused(run, modifySub);
    assert.deepEqual(await readdir(modifySub), []);

    // WRITE_DAC for Authenticated Users on an ancestor: refused.
    const writeDac = path.join(temp, "wdac");
    await mkdir(writeDac);
    icacls(writeDac, "/grant", "*S-1-5-11:(WDAC)");
    run = install("-InstallDir", path.join(writeDac, "YourWallet"));
    refused(run, writeDac);
    assert.deepEqual(await readdir(writeDac), []);

    // A junction on the path: refused (the real folder's ancestors would not be the ones checked).
    const junctionTarget = path.join(temp, "jtarget");
    await mkdir(junctionTarget);
    const junction = path.join(temp, "link");
    await symlink(junctionTarget, junction, "junction");
    run = install("-InstallDir", path.join(junction, "YourWallet"));
    refused(run, junction);
    assert.deepEqual(await readdir(junctionTarget), []);

    // Like C:\ : Authenticated Users may create folders here (add-only) and get Modify on what they create
    // (inherit-only). The missing folder below is created private, so this passes.
    const addOnly = path.join(temp, "addonly");
    await mkdir(addOnly);
    icacls(addOnly, "/grant", "*S-1-5-11:(AD)", "*S-1-5-11:(OI)(CI)(IO)M");
    const addOnlyTarget = path.join(addOnly, "new", "YourWallet");
    run = install("-InstallDir", addOnlyTarget);
    assert.equal(run.status, 0, run.out);
    assertPrivate(await readAcl(temp, path.join(addOnly, "new")), { inherited: false });

    // Like a %TEMP% shared with sandbox accounts: INTERACTIVE has Modify (DELETE + add) on the folder itself, but
    // its parent gives them nothing, so the folder cannot be replaced; read-only grants never matter.
    const tempLike = path.join(temp, "templike");
    await mkdir(tempLike);
    icacls(tempLike, "/grant", "*S-1-5-4:M", "*S-1-1-0:(OI)(CI)RX");
    run = install("-InstallDir", path.join(tempLike, "YourWallet"));
    assert.equal(run.status, 0, run.out);
  });
});

// Build tools: full paths from %CARGO_HOME%\bin or %USERPROFILE%\.cargo\bin only, never PATH; their files and folders
// must not be writable by other SIDs.
const TOOLS_SCRIPT = `param([string]$Script, [string]$Out)
$ErrorActionPreference = 'Stop'
. $Script
$user = Get-CurrentUserSid
$tools = Get-RustTools
$problems = @(foreach ($file in @($tools.Rustup, $tools.Cargo, $tools.Rustc)) { if ($null -ne $file) { [string](Get-ToolPathProblem $file $user) } })
$result = [ordered]@{ bin = $tools.Bin; rustup = $tools.Rustup; cargo = $tools.Cargo; rustc = $tools.Rustc; problems = $problems }
[IO.File]::WriteAllText($Out, (ConvertTo-Json -InputObject $result -Depth 3 -Compress))
`;

async function fakeRustBin(bin) {
  await mkdir(bin, { recursive: true });
  for (const name of ["rustup.exe", "cargo.exe", "rustc.exe"]) await writeFile(path.join(bin, name), "not a real program\n");
}

test("install.ps1 resolves rustup/cargo/rustc from CARGO_HOME or USERPROFILE only and refuses tool files or folders other users can write (Windows PowerShell 5.1)", { skip: !windows, timeout: 300_000 }, async () => {
  await withTemp("your-wallet-install-tools-", async (temp) => {
    const helper = path.join(temp, "tools.ps1");
    await writeFile(helper, TOOLS_SCRIPT);
    const out = path.join(temp, "tools.json");
    const resolve = async (overrides) => {
      const run = runPowerShell(windowsPowerShell, ["-File", helper, "-Script", installScript, "-Out", out], childEnv(overrides));
      assert.equal(run.status, 0, run.out);
      return JSON.parse(await readFile(out, "utf8"));
    };
    const cargoHome = path.join(temp, "cargo-home");
    const cargoHomeBin = path.join(cargoHome, "bin");
    await fakeRustBin(cargoHomeBin);
    const profile = path.join(temp, "profile");
    const profileBin = path.join(profile, ".cargo", "bin");
    await fakeRustBin(profileBin);
    const pathDir = path.join(temp, "on-path");
    await fakeRustBin(pathDir);
    const PATH = `${pathDir};${process.env.PATH ?? ""}`;

    // CARGO_HOME set (absolute): its bin, not PATH.
    let result = await resolve({ CARGO_HOME: cargoHome, USERPROFILE: profile, PATH });
    assert.equal(result.bin, cargoHomeBin);
    assert.equal(result.cargo, path.join(cargoHomeBin, "cargo.exe"));
    assert.equal(result.rustup, path.join(cargoHomeBin, "rustup.exe"));
    assert.equal(result.rustc, path.join(cargoHomeBin, "rustc.exe"));
    assert.deepEqual(result.problems, ["", "", ""]);
    // CARGO_HOME unset, or not an absolute drive path: %USERPROFILE%\.cargo\bin.
    for (const value of [null, "relative\\cargo", ""]) {
      result = await resolve({ CARGO_HOME: value, USERPROFILE: profile, PATH });
      assert.equal(result.cargo, path.join(profileBin, "cargo.exe"), String(value));
      assert.deepEqual(result.problems, ["", "", ""]);
    }
    // Only PATH has cargo: nothing is used.
    const emptyHome = path.join(temp, "empty-home");
    await mkdir(emptyHome);
    result = await resolve({ CARGO_HOME: emptyHome, USERPROFILE: path.join(temp, "empty-profile"), PATH });
    assert.equal(result.cargo, null);
    assert.equal(result.rustup, null);
    assert.deepEqual(result.problems, []);

    // Everyone:Modify on one tool file only (USERPROFILE bin): that file is refused.
    icacls(path.join(profileBin, "rustc.exe"), "/grant", "*S-1-1-0:M");
    result = await resolve({ CARGO_HOME: null, USERPROFILE: profile, PATH });
    assert.equal(result.problems[0], "");
    assert.equal(result.problems[1], "");
    assert.ok(result.problems[2].includes(path.join(profileBin, "rustc.exe")), result.problems[2]);
    // Everyone:Modify on the CARGO_HOME bin folder: every tool is refused.
    icacls(cargoHomeBin, "/grant", "*S-1-1-0:(OI)(CI)M");
    result = await resolve({ CARGO_HOME: cargoHome, USERPROFILE: profile, PATH });
    assert.equal(result.problems.length, 3);
    for (const problem of result.problems) assert.ok(problem.includes(cargoHomeBin), problem);

    // A symlinked proxy (rustup may link cargo.exe to rustup.exe): the link target and its folder are checked too.
    // Creating symlinks needs Developer Mode or the privilege; skip this part where it is not available.
    const linkHome = path.join(temp, "link-home");
    const linkBin = path.join(linkHome, "bin");
    const realDir = path.join(temp, "real");
    await fakeRustBin(linkBin);
    await mkdir(realDir);
    await writeFile(path.join(realDir, "rustup.exe"), "not a real program\n");
    let linked = true;
    try {
      await rm(path.join(linkBin, "cargo.exe"));
      await symlink(path.join(realDir, "rustup.exe"), path.join(linkBin, "cargo.exe"), "file");
    } catch (error) {
      if (error.code !== "EPERM") throw error;
      linked = false;
    }
    if (linked) {
      result = await resolve({ CARGO_HOME: linkHome, USERPROFILE: profile, PATH });
      assert.deepEqual(result.problems, ["", "", ""]);
      icacls(realDir, "/grant", "*S-1-1-0:(OI)(CI)M");
      result = await resolve({ CARGO_HOME: linkHome, USERPROFILE: profile, PATH });
      assert.equal(result.problems[0], "");
      assert.ok(result.problems[1].includes(realDir), result.problems[1]);
    }

    // The installer itself: an unsafe tool location stops with 7 unless -AllowUnsafeToolchainPath (after the explanation).
    const localAppData = path.join(temp, "LocalAppData");
    await mkdir(localAppData);
    const env = childEnv({ LOCALAPPDATA: localAppData, CARGO_HOME: cargoHome, PATH });
    const installDir = path.join(temp, "installed");
    let run = runPowerShell(windowsPowerShell, ["-File", installScript, "-DryRun", "-NoShortcut", "-NoNativeHost", "-InstallDir", installDir], env);
    assert.equal(run.status, 7, run.out);
    assert.ok(run.out.includes("-AllowUnsafeToolchainPath"), run.out);
    assert.ok(run.out.includes(cargoHomeBin), run.out);
    // -AllowAncestorCargoConfig: this runs the real checkout, whose ancestors (outside the test's control) are not under test here.
    run = runPowerShell(windowsPowerShell, ["-File", installScript, "-DryRun", "-AllowUnsafeToolchainPath", "-AllowAncestorCargoConfig", "-NoShortcut", "-NoNativeHost", "-InstallDir", installDir], env);
    assert.equal(run.status, 0, run.out);
    assert.ok(run.out.includes(path.join(cargoHomeBin, "cargo.exe")), run.out);
    assert.equal(existsSync(installDir), false);
    // Only PATH has cargo: reported as missing (the PATH copy is named but not used); -DryRun still ends with 0.
    run = runPowerShell(windowsPowerShell, ["-File", installScript, "-DryRun", "-AllowAncestorCargoConfig", "-NoShortcut", "-NoNativeHost", "-InstallDir", installDir], childEnv({ LOCALAPPDATA: localAppData, CARGO_HOME: emptyHome, PATH }));
    assert.equal(run.status, 0, run.out);
    assert.ok(run.out.includes(path.join(pathDir, "cargo.exe")), run.out);
    assert.ok(!run.out.includes(`${path.join(pathDir, "cargo.exe")} +`), run.out);
  });
});

// Invoke-Build with fake rustup/cargo/rustc (.cmd files that log their arguments and environment).
const BUILD_SCRIPT = `param([string]$Script, [string]$Root, [string]$Bin, [string]$Out, [string]$Names)
$ErrorActionPreference = 'Stop'
. $Script
$tools = [pscustomobject]@{ Bin = $Bin; Rustup = (Join-Path $Bin 'rustup.cmd'); Cargo = (Join-Path $Bin 'cargo.cmd'); Rustc = (Join-Path $Bin 'rustc.cmd') }
Invoke-Build $Root $tools
$after = [ordered]@{}
foreach ($name in $Names.Split(',')) { $after[$name] = [Environment]::GetEnvironmentVariable($name) }
$result = [ordered]@{ after = $after; args = [string[]](Get-CargoBuildArguments) }
[IO.File]::WriteAllText($Out, (ConvertTo-Json -InputObject $result -Depth 3 -Compress))
`;

const FAKE_CARGO = `@echo off\r
if "%~2"=="--version" goto version\r
>>"%YW_FAKE_LOG%" echo ARGS %*\r
set >"%YW_FAKE_ENV%"\r
exit /b 0\r
:version\r
>>"%YW_FAKE_LOG%" echo VERSION %*\r
echo cargo %YW_FAKE_CARGO_VERSION% (fake 2026-01-01)\r
exit /b 0\r
`;
const FAKE_RUSTC = `@echo off\r
>>"%YW_FAKE_LOG%" echo RUSTC %*\r
echo rustc %YW_FAKE_RUSTC_VERSION% (fake 2026-01-01)\r
echo binary: rustc\r
echo release: %YW_FAKE_RUSTC_VERSION%\r
echo host: x86_64-pc-windows-msvc\r
exit /b 0\r
`;
const FAKE_RUSTUP = `@echo off\r
>>"%YW_FAKE_LOG%" echo RUSTUP %*\r
exit /b 0\r
`;

// Variables the build must not see (install.ps1 $ClearedBuildVariableNames/Prefixes and $RustflagsVariables).
const CLEARED = {
  CC: "evil-cc", CC_x86_64_pc_windows_msvc: "evil-cc", "CC_x86_64-pc-windows-msvc": "evil-cc", CFLAGS: "-O0", CFLAGS_x86_64_pc_windows_msvc: "-O0",
  CXX: "evil-cxx", CXXFLAGS: "-O0", "CXXFLAGS_x86_64-pc-windows-msvc": "-O0",
  RUSTC: "evil-rustc", RUSTC_WRAPPER: "evil-wrapper", RUSTC_WORKSPACE_WRAPPER: "evil-wrapper",
  CARGO_BUILD_RUSTC: "evil-rustc", CARGO_BUILD_RUSTC_WRAPPER: "evil-wrapper", CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER: "evil-wrapper",
  CARGO_PROFILE_RELEASE_LTO: "off", CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS: "false", CARGO_PROFILE_RELEASE_PACKAGE_YW_CORE_OPT_LEVEL: "0",
  RUSTFLAGS: "-Cdebug-assertions", CARGO_ENCODED_RUSTFLAGS: "-Cdebug-assertions",
};

function releaseProfile(cargoToml) {
  const section = /^\[profile\.release\][ \t]*\r?$([\s\S]*?)(?=^\[|(?![\s\S]))/mu.exec(cargoToml);
  assert.ok(section, "Cargo.toml has no [profile.release]");
  const values = {};
  for (const line of section[1].split(/\r?\n/u)) {
    const match = /^[ \t]*([A-Za-z0-9_-]+)[ \t]*=[ \t]*("[^"]*"|'[^']*'|[^ \t#]+)/u.exec(line);
    if (match) values[match[1]] = match[2].replace(/^["'](.*)["']$/u, "$1");
  }
  return values;
}

const buildShells = windows ? [["Windows PowerShell 5.1", windowsPowerShell], ["PowerShell 7", findOnPath("pwsh.exe")]] : [];
for (const [label, shell] of buildShells) {
  test(`install.ps1 Invoke-Build runs cargo +1.95.0 with Cargo.toml's release profile as --config, clears compiler/build env vars only for the build, and stops on a toolchain mismatch (${label})`, { skip: shell === null ? "pwsh.exe not found" : false, timeout: 120_000 }, async () => {
    await withTemp("your-wallet-install-build-", async (temp) => {
      const bin = path.join(temp, "bin");
      await mkdir(bin);
      await writeFile(path.join(bin, "cargo.cmd"), FAKE_CARGO);
      await writeFile(path.join(bin, "rustc.cmd"), FAKE_RUSTC);
      await writeFile(path.join(bin, "rustup.cmd"), FAKE_RUSTUP);
      const root = path.join(temp, "root");
      await mkdir(root);
      const helper = path.join(temp, "build.ps1");
      await writeFile(helper, BUILD_SCRIPT);
      const out = path.join(temp, "build.json");
      const log = path.join(temp, "log.txt");
      const envDump = path.join(temp, "env.txt");
      const names = [...Object.keys(CLEARED), "YW_KEEP"];
      const build = async (versions) => {
        await rm(log, { force: true });
        await rm(envDump, { force: true });
        const env = childEnv({ ...CLEARED, YW_KEEP: "kept", YW_FAKE_LOG: log, YW_FAKE_ENV: envDump, YW_FAKE_CARGO_VERSION: "1.95.0", YW_FAKE_RUSTC_VERSION: "1.95.0", ...versions });
        const run = runPowerShell(shell, ["-File", helper, "-Script", installScript, "-Root", root, "-Bin", bin, "-Out", out, "-Names", names.join(",")], env);
        const lines = existsSync(log) ? (await readFile(log, "utf8")).split(/\r?\n/u).map((line) => line.trim()).filter(Boolean) : [];
        return { run, lines };
      };

      const { run, lines } = await build({});
      assert.equal(run.status, 0, run.out);
      const result = JSON.parse(await readFile(out, "utf8"));

      // The argument list: +1.95.0 first, then Cargo.toml [profile.release] exactly, then the build.
      const expectedProfile = releaseProfile(await readFile(path.join(repoRoot, "Cargo.toml"), "utf8"));
      assert.equal(result.args[0], "+1.95.0");
      const configs = {};
      const others = [];
      let index = 1;
      while (result.args[index] === "--config") {
        const setting = result.args[index + 1];
        assert.doesNotMatch(setting, /[" ]/u, "no double quotes or spaces (Windows PowerShell 5.1 native argument passing)");
        const match = /^profile\.release\.([a-z-]+)=(.*)$/u.exec(setting);
        if (match) configs[match[1]] = match[2].replace(/^'(.*)'$/u, "$1");
        else others.push(setting);
        index += 2;
      }
      assert.deepEqual(configs, expectedProfile);
      // No compiler wrapper (empty string = none) and rustc's default MSVC linker, over any config file or variable.
      assert.deepEqual(others, ["build.rustc-wrapper=''", "build.rustc-workspace-wrapper=''", "target.x86_64-pc-windows-msvc.linker='link.exe'"]);
      assert.deepEqual(result.args.slice(index), ["build", "--release", "--locked", "-p", "yw-app", "-p", "yw-host"]);

      // What the fake tools received.
      assert.deepEqual(lines, ["VERSION +1.95.0 --version", "RUSTC +1.95.0 -vV", `ARGS ${result.args.join(" ")}`]);
      const seen = new Map();
      for (const line of (await readFile(envDump, "utf8")).split(/\r?\n/u)) {
        const eq = line.indexOf("=", 1);
        if (eq > 0) seen.set(line.slice(0, eq).toUpperCase(), line.slice(eq + 1));
      }
      for (const name of Object.keys(CLEARED)) assert.equal(seen.has(name.toUpperCase()), false, `${name} reached cargo`);
      assert.equal(seen.get("YW_KEEP"), "kept");
      assert.ok(seen.has("PATH"));
      // Restored after the build.
      for (const [name, value] of Object.entries(CLEARED)) assert.equal(result.after[name], value, name);
      assert.equal(result.after.YW_KEEP, "kept");

      // A different toolchain behind +1.95.0 stops with 7 before building.
      for (const versions of [{ YW_FAKE_CARGO_VERSION: "1.94.0" }, { YW_FAKE_CARGO_VERSION: "1.95.0-nightly" }, { YW_FAKE_RUSTC_VERSION: "1.96.0" }]) {
        const mismatch = await build(versions);
        assert.equal(mismatch.run.status, 7, `${JSON.stringify(versions)}\n${mismatch.run.out}`);
        assert.equal(mismatch.lines.some((line) => line.startsWith("ARGS")), false, mismatch.lines.join("\n"));
      }
    });
  });
}

// cargo config files (install.ps1 "cargo 설정 규칙"): cargo reads .cargo\config.toml and .cargo\config from the repo root and
// every ancestor, plus CARGO_HOME. Hermetic: every config file is created inside a temp tree; folders above the temp root
// are outside the test's control, so results are filtered to the temp tree and never asserted to be empty.
const CARGO_CONFIG_SCRIPT = `param([string]$Script, [string]$Root, [string]$CargoHome, [string]$Samples, [string]$Out)
$ErrorActionPreference = 'Stop'
. $Script
$keys = @(foreach ($sample in (ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Samples)))) { , [string[]](Get-CargoConfigRiskyKeys ([string]$sample)) })
$result = [ordered]@{ ancestors = [string[]](Get-AncestorCargoConfigs $Root $CargoHome); keys = $keys }
[IO.File]::WriteAllText($Out, (ConvertTo-Json -InputObject $result -Depth 4 -Compress))
`;

const RISKY_CONFIG = [
  "# build.rustc = 'commented out'",
  "[build]",
  "rustc-wrapper = \"C:/tools/sccache.exe\" # trailing comment",
  "jobs = 4",
  "target-dir = \"t#not-a-comment\"",
  "[target.x86_64-pc-windows-msvc]",
  "linker = 'evil.exe'",
  "runner = \"x\"",
  "[target.'cfg(windows)']",
  "rustflags = [\"-C\", \"linker=evil.exe\"]",
  "[profile.release]",
  "opt-level = 0",
  "[profile.dev]",
  "opt-level = 1",
  "[patch.crates-io]",
  "serde = { path = \"../serde\" }",
  "[source.crates-io]",
  "replace-with = \"vendored\"",
  "[net]",
  "offline = true",
  "",
].join("\r\n");

test("install.ps1 finds ancestor cargo configs (not the repo's own, not CARGO_HOME) and the CARGO_HOME keys that change the build", { skip: !windows, timeout: 120_000 }, async () => {
  await withTemp("your-wallet-install-cargo-config-", async (temp) => {
    const root = path.join(temp, "outer", "mid", "repo");
    await mkdir(path.join(root, ".cargo"), { recursive: true });
    await writeFile(path.join(root, ".cargo", "config.toml"), "[build]\nrustc-wrapper = 'repo-own'\n");
    await mkdir(path.join(temp, "outer", ".cargo"), { recursive: true });
    await writeFile(path.join(temp, "outer", ".cargo", "config.toml"), "[build]\n");
    await mkdir(path.join(temp, "outer", "mid", ".cargo"), { recursive: true });
    await writeFile(path.join(temp, "outer", "mid", ".cargo", "config"), "[build]\n");
    const samples = [
      RISKY_CONFIG,
      "build.rustc-workspace-wrapper = 'x'\nprofile = { release = { lto = false } }\ntarget.\"x86_64-pc-windows-msvc\".linker = \"a\"\npaths = [\"../x\"]\nbuild = { rustflags = [] }\n",
      "[build]\nrustdoc = 'x'\njobs = 2\n[env]\nRUSTC_WRAPPER = 'x'\n[target.x86_64-pc-windows-msvc]\nrunner = 'x'\n[profile.dev]\nlto = false\n[registries.x]\nindex = 'y'\n",
      "",
    ];
    const helper = path.join(temp, "cargo-config.ps1");
    await writeFile(helper, CARGO_CONFIG_SCRIPT);
    const samplesFile = path.join(temp, "samples.json");
    await writeFile(samplesFile, JSON.stringify(samples));
    const out = path.join(temp, "cargo-config.json");
    const inspect = async (cargoHome) => {
      const run = runPowerShell(windowsPowerShell, ["-File", helper, "-Script", installScript, "-Root", root, "-CargoHome", cargoHome, "-Samples", samplesFile, "-Out", out], childEnv());
      assert.equal(run.status, 0, run.out);
      const result = JSON.parse(await readFile(out, "utf8"));
      const ancestors = (result.ancestors ?? []).filter((file) => file.toLowerCase().startsWith(temp.toLowerCase()));
      return { ancestors, keys: result.keys.map((list) => list ?? []) };
    };

    let result = await inspect(path.join(temp, "elsewhere", ".cargo"));
    assert.deepEqual(result.ancestors, [path.join(temp, "outer", "mid", ".cargo", "config"), path.join(temp, "outer", ".cargo", "config.toml")]);
    assert.deepEqual(result.keys[0], [
      "build.rustc-wrapper", "target.x86_64-pc-windows-msvc.linker", "target.cfg(windows).rustflags", "profile.release.opt-level",
      "patch.crates-io.serde", "patch.crates-io.serde.path", "source.crates-io.replace-with",
    ]);
    assert.deepEqual(result.keys[1], ["build.rustc-workspace-wrapper", "profile.release", "target.x86_64-pc-windows-msvc.linker", "paths", "build.rustflags"]);
    assert.deepEqual(result.keys[2], []);
    assert.deepEqual(result.keys[3], []);
    // The .cargo folder that is CARGO_HOME (any case) is the user's own configuration, not an ancestor config.
    result = await inspect(path.join(temp, "OUTER", ".cargo"));
    assert.deepEqual(result.ancestors, [path.join(temp, "outer", "mid", ".cargo", "config")]);
  });
});

test("install.ps1 refuses to build under an ancestor cargo config (exit 7) unless -AllowAncestorCargoConfig, and warns about CARGO_HOME keys (Windows PowerShell 5.1)", { skip: !windows, timeout: 300_000 }, async () => {
  await withTemp("your-wallet-install-cargo-ancestor-", async (temp) => {
    const outer = path.join(temp, "outer");
    const root = path.join(outer, "mid", "repo");
    for (const file of ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml", "scripts/install.ps1", "scripts/uninstall.ps1"]) {
      await mkdir(path.dirname(path.join(root, file)), { recursive: true });
      await cp(path.join(repoRoot, file), path.join(root, file));
    }
    await cp(extensionRoot, path.join(root, "extension"), { recursive: true });
    const ancestorDotCargo = path.join(outer, ".cargo");
    const ancestorConfig = path.join(ancestorDotCargo, "config.toml");
    await mkdir(ancestorDotCargo, { recursive: true });
    await writeFile(ancestorConfig, "[build]\nrustc-wrapper = 'C:/evil/wrapper.exe'\n");
    const cargoHome = path.join(temp, "cargo-home");
    await fakeRustBin(path.join(cargoHome, "bin"));
    await writeFile(path.join(cargoHome, "config.toml"), RISKY_CONFIG);
    // Default install folder under a temp profile: the install-folder ancestor check stays inside the temp tree.
    const profile = path.join(temp, "profile");
    const localAppData = path.join(profile, "AppData", "Local");
    await mkdir(localAppData, { recursive: true });
    const install = (cargoHomeDir, ...args) => runPowerShell(windowsPowerShell, ["-File", path.join(root, "scripts", "install.ps1"), "-DryRun", "-NoShortcut", "-NoNativeHost", ...args],
      childEnv({ LOCALAPPDATA: localAppData, USERPROFILE: profile, CARGO_HOME: cargoHomeDir }));
    const listed = (out) => out.split(/\r?\n/u).map((line) => line.trim()).filter((line) => line.startsWith("- ")).map((line) => line.slice(2));
    const inTemp = (file) => file.toLowerCase().startsWith(temp.toLowerCase());

    let run = install(cargoHome);
    assert.equal(run.status, 7, run.out);
    assert.ok(listed(run.out).includes(ancestorConfig), run.out);
    assert.ok(run.out.includes("-AllowAncestorCargoConfig"), run.out);
    assert.ok(!run.out.includes(path.join(root, ".cargo")), "the repo's own .cargo is not an ancestor config");
    assert.ok(!run.out.includes("[DryRun] 실행:"), "refused before the build plan");
    assert.equal(existsSync(path.join(localAppData, "Programs")), false);

    run = install(cargoHome, "-AllowAncestorCargoConfig");
    assert.equal(run.status, 0, run.out);
    assert.ok(listed(run.out).includes(ancestorConfig), run.out);
    assert.ok(run.out.includes("[DryRun] 실행:"), run.out);
    assert.ok(run.out.includes("--config build.rustc-wrapper='' --config build.rustc-workspace-wrapper='' --config target.x86_64-pc-windows-msvc.linker='link.exe'"), run.out);
    // CARGO_HOME\config.toml: a warning naming the keys, never a refusal.
    assert.ok(run.out.includes(path.join(cargoHome, "config.toml")), run.out);
    for (const key of ["build.rustc-wrapper", "target.x86_64-pc-windows-msvc.linker", "profile.release.opt-level", "patch.crates-io.serde", "source.crates-io.replace-with"]) {
      assert.ok(run.out.includes(key), `${key}\n${run.out}`);
    }
    assert.ok(!run.out.includes("profile.dev"), run.out);

    // The ancestor .cargo that is CARGO_HOME itself is the user's configuration: its keys are warned about, not refused.
    // Folders above the temp root are not under test: if one of them has a cargo config, the refusal lists only those.
    await fakeRustBin(path.join(ancestorDotCargo, "bin"));
    run = install(ancestorDotCargo);
    assert.ok(!listed(run.out).some(inTemp), run.out);
    assert.ok(run.status === 0 || run.status === 7, run.out);
    if (run.status === 0) assert.ok(run.out.includes(ancestorConfig) && run.out.includes("build.rustc-wrapper"), run.out);

    // No cargo config left in the temp tree's ancestors.
    await rm(ancestorDotCargo, { force: true, recursive: true });
    run = install(cargoHome);
    assert.ok(!listed(run.out).some(inTemp), run.out);
    assert.ok(run.status === 0 || run.status === 7, run.out);
  });
});

// Review INFO: the gate (scripts/check.ps1) builds under the same conditions as the installer: the same cleared
// variables (the gate clears every CARGO_PROFILE_*, since it builds dev and test profiles) and the same --config
// overrides (clippy keeps cargo-clippy's own workspace wrapper).
test("check.ps1 clears the installer's build variables and passes its --config overrides", async () => {
  const checkText = await readFile(path.join(repoRoot, "scripts", "check.ps1"), "utf8");
  const installText = await readFile(installScript, "utf8");
  const list = (text, name) => {
    const match = new RegExp(`^\\$${name} = @\\((.*)\\)\\r?$`, "mu").exec(text);
    assert.ok(match, `${name} not found`);
    return [...match[1].matchAll(/(["'])(.*?)\1/gu)].map((item) => item[2]);
  };
  assert.deepEqual(list(checkText, "ClearedBuildVariableNames"), list(installText, "ClearedBuildVariableNames"));
  assert.deepEqual(list(checkText, "BuildConfigOverrides"), list(installText, "BuildConfigOverrides"));
  const checkPrefixes = list(checkText, "ClearedBuildVariablePrefixes");
  for (const prefix of list(installText, "ClearedBuildVariablePrefixes")) {
    assert.ok(checkPrefixes.some((ours) => prefix.toUpperCase().startsWith(ours.toUpperCase())), `check.ps1 does not clear ${prefix}*`);
  }
  assert.ok(checkPrefixes.includes("CARGO_PROFILE_"));
  // Every cargo build step of the gate passes the overrides.
  for (const step of ["clippy", "test", "fuzz", "build"]) {
    const line = new RegExp(`^Invoke-Step "${step}" .*$`, "mu").exec(checkText);
    assert.ok(line, step);
    assert.match(line[0], step === "clippy" ? /\$clippyConfig/u : /\$config\b/u, step);
  }
});
