// scripts/check-core-deps.mjs — 워크스페이스 크레이트별 의존성 폐포를 허용 목록과 정확히 비교한다.
// Usage: node scripts/check-core-deps.mjs [--offline] [--list]
// Exit: 0 = OK, 1 = 정책 위반, 2 = cargo metadata 실행/해석 실패.
import { execFileSync } from "node:child_process";
import { dirname } from "node:path";

const TARGET = "x86_64-pc-windows-msvc";
const CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index";
// 단계 진입 커밋에서만 바꾼다(spec/01 §3.4): M7 → "sol" 추가.
const PHASES = new Set([]);

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
const APP = table(`qrcodegen=1.8.0:n`);

const CORE = { ...CORE_EVM, ...(PHASES.has("sol") ? CORE_SOL : {}) };
const POLICY = {
  "yw-core": { allow: CORE, local: ["yw-json"] },
  "yw-json": { allow: {}, local: [] },
  "yw-win": { allow: WIN, local: [] },
  "yw-app": { allow: { ...CORE, ...WIN, ...APP }, local: ["yw-core", "yw-json", "yw-win"] },
  "yw-host": { allow: WIN, local: ["yw-json", "yw-win"] },
};
const BUILD_RS_ALLOW = new Set(["generic-array", "getrandom", "secp256k1-sys", ...(PHASES.has("sol") ? ["curve25519-dalek"] : [])]);
const OWN_BUILD_RS_ALLOW = new Set(["yw-app"]);
const FORBIDDEN_FEATURES = {
  secp256k1: ["rand", "global-context", "hashes", "serde"], argon2: ["alloc", "password-hash", "rand"],
  chacha20poly1305: ["getrandom", "rand_core"], aead: ["getrandom", "rand_core"], zeroize: ["derive"],
  getrandom: ["wasm_js"], "ed25519-dalek": ["asm", "batch", "digest", "hazmat", "legacy_compatibility", "pem", "pkcs8", "rand_core", "serde"],
  "curve25519-dalek": ["group", "group-bits", "legacy_compatibility", "rand_core", "serde"],
  ed25519: ["pem", "pkcs8", "serde", "serde_bytes"], signature: ["derive", "digest", "rand_core"],
};

let meta;
try {
  const args = ["metadata", "--format-version", "1", "--locked", "--filter-platform", TARGET];
  if (process.argv.includes("--offline")) args.push("--offline");
  meta = JSON.parse(execFileSync("cargo", args, { encoding: "utf8", maxBuffer: 64 << 20, windowsHide: true }));
} catch (error) {
  console.error(`deps check: cargo metadata failed: ${error instanceof Error ? error.message.split("\n")[0] : "unknown"}`);
  process.exit(2);
}
const pkgs = new Map(meta.packages.map((p) => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
const key = (p) => `${p.name}=${p.version}`;
const errors = [];
const listing = [];

for (const id of meta.workspace_members) {
  const p = pkgs.get(id);
  if (!(p.name in POLICY)) errors.push(`${p.name}: workspace member without a policy`);
  if (p.dependencies.some((d) => d.kind === "dev")) errors.push(`${p.name}: dev-dependencies are forbidden`);
  if (p.targets.some((t) => t.kind.includes("custom-build")) && !OWN_BUILD_RS_ALLOW.has(p.name)) errors.push(`${p.name}: build.rs is forbidden`);
}

for (const [root, policy] of Object.entries(POLICY)) {
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
    if (p.targets.some((t) => t.kind.includes("custom-build")) && !BUILD_RS_ALLOW.has(p.name)) errors.push(`${at}: unreviewed build.rs`);
    if (p.targets.some((t) => t.kind.includes("proc-macro"))) errors.push(`${at}: proc-macro (curve25519-dalek-derive means the serial backend cfg is missing)`);
    const bad = (FORBIDDEN_FEATURES[p.name] ?? []).filter((f) => nodes.get(id).features.includes(f));
    if (bad.length) errors.push(`${at}: forbidden features ${bad.join(",")} (workspace-unified)`);
  }
  for (const k of Object.keys(policy.allow)) if (!reached.has(k)) errors.push(`${root}: ${k} allowlisted but not reached (prune or fix phase)`);
  if (!errors.some((e) => e.startsWith(root))) console.log(`${root} deps check OK: ${reached.size} crates (${TARGET})`);
}

if (process.argv.includes("--list")) console.log(listing.join("\n"));
if (errors.length) { console.error(`deps check FAILED (${TARGET}, phases: ${[...PHASES].join(",") || "evm"}):\n  ${errors.join("\n  ")}`); process.exit(1); }
console.log(`deps check OK (${TARGET}, phases: ${[...PHASES].join(",") || "evm"})`);
