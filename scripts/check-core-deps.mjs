// scripts/check-core-deps.mjs — 워크스페이스 크레이트별 의존성 폐포를 타깃별 허용 목록과 정확히 비교한다.
// Usage: node scripts/check-core-deps.mjs [--offline] [--list] [--target <triple>] [--metadata <file>]
//   --target <triple>: 그 타깃 하나만 검사한다(없으면 TARGETS 셋 모두, 타깃마다 `cargo metadata --filter-platform`).
//   --metadata <file>: cargo를 실행하지 않고 그 파일의 `cargo metadata` JSON을 검사한다(scripts/check-core-deps.test.mjs).
//     문서 하나는 타깃 하나의 것이므로 --target과 함께 쓴다(없으면 Windows 타깃).
// Exit: 0 = OK, 1 = 정책 위반, 2 = cargo metadata 실행/해석 실패·모르는 타깃.
// 2026-11-24 A2-1(spec/15 §4.1, spec/01 §3.3·§4.2, spec.md D5): 타깃별 표. 그 전에는 x86_64-pc-windows-msvc 하나였다.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const WINDOWS = "x86_64-pc-windows-msvc";
// x86_64-linux-android는 에뮬레이터의 CheckJNI 확인용이다(spec/15 §13).
export const ANDROID_TARGETS = ["aarch64-linux-android", "x86_64-linux-android"];
export const TARGETS = [WINDOWS, ...ANDROID_TARGETS];
// 2026-11-24 전의 이름: Windows 표의 타깃.
export const TARGET = WINDOWS;
export const CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index";
// 단계 진입 커밋에서만 바꾼다(spec/01 §3.4): M7 → "sol" 추가.
export const PHASES = new Set(["sol"]);

// name=version:n (런타임에 링크) | :b (빌드 시에만 실행: build-dependency와 그 폐포)
const table = (text) => Object.fromEntries(text.trim().split(/\s+/).map((entry) => entry.split(":")));
const CORE_EVM = table(`
aead=0.5.2:n argon2=0.5.3:n base64ct=1.8.3:n blake2=0.10.6:n block-buffer=0.10.4:n cfg-if=1.0.4:n
chacha20=0.9.1:n chacha20poly1305=0.10.1:n cipher=0.4.4:n cpufeatures=0.2.17:n crypto-common=0.1.7:n
digest=0.10.7:n generic-array=0.14.7:n getrandom=0.3.3:n hkdf=0.12.4:n hmac=0.12.1:n inout=0.1.4:n
keccak=0.1.6:n opaque-debug=0.3.1:n pbkdf2=0.12.2:n poly1305=0.8.0:n ripemd=0.1.3:n secp256k1=0.31.1:n
secp256k1-sys=0.11.0:n sha2=0.10.9:n sha3=0.10.8:n subtle=2.6.1:n typenum=1.20.1:n
universal-hash=0.5.1:n zeroize=1.8.1:n
cc=1.4.2:b find-msvc-tools=0.1.10:b shlex=2.0.1:b version_check=0.9.5:b`);
const CORE_SOL = table(`ed25519-dalek=2.2.0:n ed25519=2.2.3:n signature=2.2.0:n curve25519-dalek=4.1.3:n
rustc_version=0.4.1:b semver=1.0.28:b`);
const WIN = table(`windows-sys=0.61.2:n windows-link=0.2.1:n`);
// 2026-11-24(spec/15 §4.1, §11.4 S5-2): 화면 모델의 QR과 함께 yw-app에서 yw-engine으로 옮겼다(전 이름 APP).
const QR = table(`qrcodegen=1.8.0:n`);
// 2026-11-24 A2-1(spec/15 §4.1·§18 41): Android 표에만. sha2·keccak → cpufeatures → libc, getrandom → libc로 yw-core
// 폐포에 들어오고(어떤 cfg로도 뺄 수 없다) yw-android가 직접 쓴다. 그 build.rs도 Android 표에만 허용한다.
const LIBC = table(`libc=0.2.189:n`);

const CORE = { ...CORE_EVM, ...(PHASES.has("sol") ? CORE_SOL : {}) };
const isAndroid = (target) => ANDROID_TARGETS.includes(target);
// Android용으로 빌드하지 않는 멤버: Windows 셸과 그 도구. Android 표는 이들을 검사하지 않는다 — yw-win의 windows-sys
// 의존은 타깃으로 묶여 있지 않아 Android 메타데이터에도 나온다(spec/15 §4.1, P0-5 F5-2). 그 밖의 멤버는 모든 표에 있다.
export const WINDOWS_ONLY = new Set(["yw-win", "yw-app", "yw-host"]);

/** The policy rows of one target (throws for a target outside TARGETS). */
export function policyFor(target) {
  if (!TARGETS.includes(target)) throw new Error(`unknown target ${target} (one of ${TARGETS.join(", ")})`);
  const core = { ...CORE, ...(isAndroid(target) ? LIBC : {}) };
  const shared = {
    "yw-core": { allow: core, local: ["yw-json"] },
    "yw-json": { allow: {}, local: [] },
    // 2026-11-17: yw-platform(의존성 0) 추가. yw-host는 yw-win을 거쳐 링크한다.
    "yw-platform": { allow: {}, local: [] },
    // 2026-11-17(spec/15 §11.4 S2): yw-engine은 yw-core 폐포만(yw-win·windows-sys 없음).
    // 2026-11-24(S5-2): 그리고 qrcodegen(화면 모델의 QR, spec/15 §4.1).
    "yw-engine": { allow: { ...core, ...QR }, local: ["yw-core", "yw-json", "yw-platform"] },
    // 2026-11-24 A2-1(spec/15 §3·§4.1): Android 셸. 로컬 넷(yw-win 없음), qrcodegen은 yw-engine을 거쳐서만, 직접 쓰는
    // 서드파티는 Android 타깃의 libc뿐(Windows에서는 이식 가능한 도우미와 그 시험만 컴파일된다, spec/15 §13).
    "yw-android": { allow: { ...core, ...QR }, local: ["yw-core", "yw-engine", "yw-json", "yw-platform"], indirect: ["qrcodegen"] },
  };
  if (isAndroid(target)) return shared;
  return {
    ...shared,
    "yw-win": { allow: WIN, local: ["yw-platform"] },
    // indirect: 폐포에는 있어도 직접 의존하면 안 되는 크레이트(2026-11-24 S5-2: qrcodegen은 yw-engine을 거쳐서만, spec.md D5).
    "yw-app": { allow: { ...CORE, ...WIN, ...QR }, local: ["yw-core", "yw-engine", "yw-json", "yw-platform", "yw-win"], indirect: ["qrcodegen"] },
    "yw-host": { allow: WIN, local: ["yw-json", "yw-platform", "yw-win"] },
  };
}

/** The crates whose build.rs is reviewed, for one target. */
export function buildRsAllowFor(target) {
  return new Set(["generic-array", "getrandom", "secp256k1-sys", ...(PHASES.has("sol") ? ["curve25519-dalek"] : []),
    ...(isAndroid(target) ? ["libc"] : [])]);
}

// The Windows table under the names used before 2026-11-24.
export const POLICY = policyFor(WINDOWS);
export const BUILD_RS_ALLOW = buildRsAllowFor(WINDOWS);
export const OWN_BUILD_RS_ALLOW = new Set(["yw-app"]);
export const FORBIDDEN_FEATURES = {
  secp256k1: ["rand", "global-context", "hashes", "serde"], argon2: ["alloc", "password-hash", "rand"],
  chacha20poly1305: ["getrandom", "rand_core"], aead: ["getrandom", "rand_core"], zeroize: ["derive"],
  getrandom: ["wasm_js"], "ed25519-dalek": ["asm", "batch", "digest", "hazmat", "legacy_compatibility", "pem", "pkcs8", "rand_core", "serde"],
  "curve25519-dalek": ["group", "group-bits", "legacy_compatibility", "rand_core", "serde"],
  ed25519: ["pem", "pkcs8", "serde", "serde_bytes"], signature: ["derive", "digest", "rand_core"],
};

/**
 * Checks one `cargo metadata --format-version 1` document of `target` against that target's policy.
 * Returns `{ errors, ok, listing, skipped }`: violations, the per-crate OK lines, the `--list` rows and the
 * Windows-only members an Android table does not check.
 * Throws when the document lacks the fields it reads or the target is unknown (the CLI reports that as exit 2).
 */
export function checkMetadata(meta, target = WINDOWS) {
  const policies = policyFor(target);
  const buildRsAllow = buildRsAllowFor(target);
  const pkgs = new Map(meta.packages.map((p) => [p.id, p]));
  const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
  const key = (p) => `${p.name}=${p.version}`;
  const errors = [];
  const ok = [];
  const listing = [];
  const skipped = [];

  for (const id of meta.workspace_members) {
    const p = pkgs.get(id);
    if (!(p.name in policies)) {
      if (isAndroid(target) && WINDOWS_ONLY.has(p.name)) skipped.push(p.name);
      else errors.push(`${p.name}: workspace member without a policy`);
    }
    if (p.dependencies.some((d) => d.kind === "dev")) errors.push(`${p.name}: dev-dependencies are forbidden`);
    if (p.targets.some((t) => t.kind.includes("custom-build")) && !OWN_BUILD_RS_ALLOW.has(p.name)) errors.push(`${p.name}: build.rs is forbidden`);
  }

  for (const [root, policy] of Object.entries(policies)) {
    const rootId = meta.workspace_members.find((id) => pkgs.get(id).name === root);
    if (!rootId) { errors.push(`${root}: workspace member not found`); continue; }
    // BFS over normal + build edges (dev edges ignored); a crate reached at runtime is "n".
    const seen = new Map();
    const queue = [[rootId, "n"]];
    while (queue.length) {
      const [id, mode] = queue.shift();
      if (seen.get(id) === "n" || seen.get(id) === mode) continue;
      seen.set(id, mode);
      for (const d of nodes.get(id).deps) {
        const kinds = d.dep_kinds.map((k) => k.kind);
        if (kinds.includes(null)) queue.push([d.pkg, mode]);
        if (kinds.includes("build")) queue.push([d.pkg, "b"]);
      }
    }
    for (const d of nodes.get(rootId).deps) {
      const p = pkgs.get(d.pkg);
      if ((policy.indirect ?? []).includes(p.name)) errors.push(`${root} -> ${key(p)}: direct dependency not allowed (only through yw-engine)`);
    }
    const reached = new Set();
    for (const [id, mode] of seen) {
      if (id === rootId) continue;
      const p = pkgs.get(id), k = key(p), at = `${root} -> ${k}`;
      if (p.source === null) {
        if (!policy.local.includes(p.name)) errors.push(`${at}: local crate not allowed here`);
        continue;
      }
      reached.add(k);
      listing.push(`${root}\t${mode === "n" ? "runtime" : "build"}\t${k}\t${dirname(p.manifest_path)}`);
      if (p.source !== CRATES_IO) errors.push(`${at}: non-crates.io source ${p.source}`);
      if (!(k in policy.allow)) errors.push(`${at}: not in allowlist (${mode === "n" ? "runtime" : "build-time"})`);
      else if (policy.allow[k] === "b" && mode === "n") errors.push(`${at}: allowlisted build-only but linked at runtime`);
      if (p.targets.some((t) => t.kind.includes("custom-build")) && !buildRsAllow.has(p.name)) errors.push(`${at}: unreviewed build.rs`);
      if (p.targets.some((t) => t.kind.includes("proc-macro"))) errors.push(`${at}: proc-macro (curve25519-dalek-derive means the serial backend cfg is missing)`);
      const bad = (FORBIDDEN_FEATURES[p.name] ?? []).filter((f) => nodes.get(id).features.includes(f));
      if (bad.length) errors.push(`${at}: forbidden features ${bad.join(",")} (workspace-unified)`);
    }
    for (const k of Object.keys(policy.allow)) if (!reached.has(k)) errors.push(`${root}: ${k} allowlisted but not reached (prune or fix phase)`);
    if (!errors.some((e) => e.startsWith(`${root}:`) || e.startsWith(`${root} `))) ok.push(`${root} deps check OK: ${reached.size} crates (${target})`);
  }
  return { errors, ok, listing, skipped };
}

/** The targets the CLI checks: `--target <triple>`, else Windows for `--metadata`, else all. */
function targetsOf(argv) {
  const at = argv.indexOf("--target");
  if (at >= 0) {
    const target = argv[at + 1];
    if (!TARGETS.includes(target)) throw new Error(`--target needs one of ${TARGETS.join(", ")}`);
    return [target];
  }
  return argv.includes("--metadata") ? [WINDOWS] : TARGETS;
}

function loadMetadata(argv, target) {
  const file = argv.indexOf("--metadata");
  if (file >= 0) {
    if (!argv[file + 1]) throw new Error("--metadata needs a file");
    return JSON.parse(readFileSync(argv[file + 1], "utf8"));
  }
  const args = ["metadata", "--format-version", "1", "--locked", "--filter-platform", target];
  if (argv.includes("--offline")) args.push("--offline");
  return JSON.parse(execFileSync("cargo", args, { encoding: "utf8", maxBuffer: 64 << 20, windowsHide: true }));
}

const firstLine = (error) => (error instanceof Error ? error.message.split("\n")[0] : "unknown");
const invokedPath = process.argv[1];
if (invokedPath !== undefined && resolve(invokedPath) === resolve(fileURLToPath(import.meta.url))) {
  let targets;
  try {
    targets = targetsOf(process.argv);
  } catch (error) {
    console.error(`deps check: ${firstLine(error)}`);
    process.exit(2);
  }
  const phases = [...PHASES].join(",") || "evm";
  let failed = false;
  for (const target of targets) {
    let result;
    try {
      result = checkMetadata(loadMetadata(process.argv, target), target);
    } catch (error) {
      console.error(`deps check: cargo metadata failed (${target}): ${firstLine(error)}`);
      process.exit(2);
    }
    for (const line of result.ok) console.log(line);
    for (const name of result.skipped) console.log(`${name} deps check skipped: not built for ${target}`);
    if (process.argv.includes("--list")) console.log(result.listing.map((row) => `${target}\t${row}`).join("\n"));
    if (result.errors.length) {
      console.error(`deps check FAILED (${target}, phases: ${phases}):\n  ${result.errors.join("\n  ")}`);
      failed = true;
    } else {
      console.log(`deps check OK (${target}, phases: ${phases})`);
    }
  }
  if (failed) process.exit(1);
}
