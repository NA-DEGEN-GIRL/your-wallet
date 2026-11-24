// scripts/check-core-deps.mjs on synthetic `cargo metadata` documents: a graph that matches a target's
// allowlists exactly passes, and each kind of violation is reported (spec/01 §4.2). The CLI is also run with
// `--metadata <file>` (and `--target`) for its exit codes (0 / 1 / 2). No cargo, no network.
// 2026-11-24 A2-1: per-target tables (spec/15 §4.1); before, the Windows table only.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ANDROID_TARGETS, BUILD_RS_ALLOW, CRATES_IO, POLICY, TARGETS, WINDOWS, WINDOWS_ONLY,
  buildRsAllowFor, checkMetadata, policyFor,
} from "./check-core-deps.mjs";

const SCRIPT = fileURLToPath(new URL("./check-core-deps.mjs", import.meta.url));
const ANDROID = "aarch64-linux-android";
const LOCAL_VERSION = "0.3.0";
const localId = (name) => `path+file:///ws/crates/${name}#${LOCAL_VERSION}`;
const registryId = (name, version) => `${CRATES_IO}#${name}@${version}`;
const normal = [{ kind: null, target: null }];
const build = [{ kind: "build", target: null }];
const MEMBERS = Object.keys(POLICY);

/**
 * A workspace whose closures are exactly the allowlists of `target`: yw-core links its runtime crates and
 * builds with its build-only ones (on Android also libc); yw-engine links yw-core, yw-json and yw-platform
 * (and through yw-core, its crates) and qrcodegen (2026-11-24, S5-2: before, yw-app linked it directly);
 * yw-android links the four local crates and, on Android, libc; yw-win links windows-* and yw-platform;
 * yw-app links the five local crates (and through yw-engine, qrcodegen); yw-host links yw-json and yw-win
 * (and through yw-win, yw-platform). Every member is there on every target, as in real metadata (the
 * Windows-only members and windows-sys show on Android too, spec/15 §4.1).
 */
function baseline(target = WINDOWS) {
  const packages = [];
  const nodes = [];
  const pkgById = new Map();
  const nodeById = new Map();
  const buildRs = buildRsAllowFor(ANDROID);
  const addPackage = (id, name, version, source) => {
    const pkg = {
      id, name, version, source,
      manifest_path: `/src/${name}-${version}/Cargo.toml`,
      dependencies: [],
      targets: [{ kind: ["lib"] }],
    };
    if (source !== null && buildRs.has(name)) pkg.targets.push({ kind: ["custom-build"] });
    const node = { id, deps: [], features: [] };
    packages.push(pkg);
    nodes.push(node);
    pkgById.set(id, pkg);
    nodeById.set(id, node);
  };
  for (const name of MEMBERS) addPackage(localId(name), name, LOCAL_VERSION, null);
  const external = new Map();
  for (const policies of [POLICY, policyFor(target)]) {
    for (const { allow } of Object.values(policies)) {
      for (const [key, mode] of Object.entries(allow)) external.set(key, mode);
    }
  }
  for (const key of external.keys()) {
    const [name, version] = key.split("=");
    addPackage(registryId(name, version), name, version, CRATES_IO);
  }
  const edge = (from, to, kinds) => nodeById.get(from).deps.push({ pkg: to, dep_kinds: kinds });
  for (const [key, mode] of Object.entries(policyFor(target)["yw-core"].allow)) {
    const [name, version] = key.split("=");
    edge(localId("yw-core"), registryId(name, version), mode === "b" ? build : normal);
  }
  for (const [key] of Object.entries(POLICY["yw-win"].allow)) {
    const [name, version] = key.split("=");
    edge(localId("yw-win"), registryId(name, version), normal);
  }
  edge(localId("yw-core"), localId("yw-json"), normal);
  edge(localId("yw-win"), localId("yw-platform"), normal);
  for (const local of ["yw-core", "yw-json", "yw-platform"]) edge(localId("yw-engine"), localId(local), normal);
  for (const local of ["yw-core", "yw-engine", "yw-json", "yw-platform"]) edge(localId("yw-android"), localId(local), normal);
  if (ANDROID_TARGETS.includes(target)) edge(localId("yw-android"), registryId("libc", "0.2.189"), normal);
  for (const local of ["yw-core", "yw-engine", "yw-json", "yw-platform", "yw-win"]) edge(localId("yw-app"), localId(local), normal);
  edge(localId("yw-engine"), registryId("qrcodegen", "1.8.0"), normal);
  for (const local of ["yw-json", "yw-win"]) edge(localId("yw-host"), localId(local), normal);
  return {
    meta: {
      packages,
      workspace_members: MEMBERS.map(localId),
      resolve: { nodes },
    },
    pkg: (id) => pkgById.get(id),
    node: (id) => nodeById.get(id),
    edge,
    addPackage,
  };
}

const run = (meta, target) => checkMetadata(meta, target);
const count = (line) => Number(line.split(": ")[1].split(" ")[0]);
const okLine = (ok, root) => ok.find((line) => line.startsWith(`${root} deps check OK: `));

test("a graph equal to the allowlists passes", () => {
  const { meta } = baseline();
  const result = run(meta);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.skipped, []);
  assert.equal(result.ok.length, Object.keys(POLICY).length);
  assert.ok(result.ok.includes("yw-json deps check OK: 0 crates (x86_64-pc-windows-msvc)"));
  assert.ok(result.ok.includes("yw-platform deps check OK: 0 crates (x86_64-pc-windows-msvc)"));
  const coreCount = okLine(result.ok, "yw-core");
  assert.ok(coreCount !== undefined);
  const engineCount = okLine(result.ok, "yw-engine");
  assert.ok(engineCount !== undefined);
  assert.equal(count(engineCount), count(coreCount) + 1, "yw-engine reaches yw-core's crates and qrcodegen");
  assert.equal(count(okLine(result.ok, "yw-android")), count(engineCount), "yw-android reaches yw-engine's crates (no libc on Windows)");
  assert.ok(result.listing.some((row) => row.startsWith("yw-core\tbuild\tcc=1.4.2\t")));
});

test("each Android graph equal to its allowlists passes; the Windows-only members are skipped there (2026-11-24, A2-1)", () => {
  const windows = run(baseline().meta);
  for (const target of ANDROID_TARGETS) {
    const result = run(baseline(target).meta, target);
    assert.deepEqual(result.errors, [], target);
    assert.deepEqual(result.skipped.sort(), [...WINDOWS_ONLY].sort(), target);
    assert.deepEqual(result.ok.map((line) => line.split(" ")[0]), ["yw-core", "yw-json", "yw-platform", "yw-engine", "yw-android"]);
    for (const root of ["yw-core", "yw-engine", "yw-android"]) {
      assert.equal(count(okLine(result.ok, root)), count(okLine(windows.ok, root)) + 1, `${target} ${root}: + libc`);
      assert.ok(okLine(result.ok, root).endsWith(`(${target})`));
    }
    assert.ok(result.listing.includes("yw-android\truntime\tlibc=0.2.189\t/src/libc-0.2.189"));
  }
  assert.deepEqual(TARGETS, [WINDOWS, ...ANDROID_TARGETS]);
});

test("libc and its build.rs are allowed on the Android tables only (2026-11-24, A2-1)", () => {
  assert.ok(!BUILD_RS_ALLOW.has("libc"));
  for (const target of ANDROID_TARGETS) assert.ok(buildRsAllowFor(target).has("libc"), target);
  for (const root of ["yw-core", "yw-engine", "yw-android"]) {
    assert.ok(!("libc=0.2.189" in policyFor(WINDOWS)[root].allow), root);
    assert.equal(policyFor(ANDROID)[root].allow["libc=0.2.189"], "n", root);
  }
  // A Windows graph that reaches libc (through yw-core) fails twice: allowlist and build script.
  const { meta, edge, addPackage } = baseline();
  addPackage(registryId("libc", "0.2.189"), "libc", "0.2.189", CRATES_IO);
  edge(localId("yw-core"), registryId("libc", "0.2.189"), normal);
  const { errors } = run(meta);
  for (const root of ["yw-core", "yw-engine", "yw-android", "yw-app"]) {
    assert.ok(errors.includes(`${root} -> libc=0.2.189: not in allowlist (runtime)`), `${root}\n${errors.join("\n")}`);
    assert.ok(errors.includes(`${root} -> libc=0.2.189: unreviewed build.rs`), root);
  }
});

test("a proc-macro on an Android table is reported (the serial cfg is missing)", () => {
  const { meta, edge, addPackage, pkg } = baseline("x86_64-linux-android");
  addPackage(registryId("curve25519-dalek-derive", "0.1.1"), "curve25519-dalek-derive", "0.1.1", CRATES_IO);
  pkg(registryId("curve25519-dalek-derive", "0.1.1")).targets = [{ kind: ["proc-macro"] }];
  edge(registryId("curve25519-dalek", "4.1.3"), registryId("curve25519-dalek-derive", "0.1.1"), normal);
  const { errors } = run(meta, "x86_64-linux-android");
  for (const root of ["yw-core", "yw-engine", "yw-android"]) {
    assert.ok(errors.includes(`${root} -> curve25519-dalek-derive=0.1.1: not in allowlist (runtime)`), root);
    assert.ok(errors.some((error) => error.startsWith(`${root} -> curve25519-dalek-derive=0.1.1: proc-macro`)), root);
  }
});

test("yw-android reaches qrcodegen only through yw-engine and never yw-win (2026-11-24, A2-1)", () => {
  for (const target of TARGETS) {
    const { meta, edge } = baseline(target);
    edge(localId("yw-android"), registryId("qrcodegen", "1.8.0"), normal);
    edge(localId("yw-android"), localId("yw-win"), normal);
    const { errors, ok } = run(meta, target);
    assert.ok(errors.includes("yw-android -> qrcodegen=1.8.0: direct dependency not allowed (only through yw-engine)"), target);
    assert.ok(errors.includes("yw-android -> yw-win=0.3.0: local crate not allowed here"), target);
    assert.ok(errors.includes("yw-android -> windows-sys=0.61.2: not in allowlist (runtime)"), target);
    assert.ok(!ok.some((line) => line.startsWith("yw-android ")), target);
  }
});

test("Android tables: an unknown member is still an error, a missing yw-android row's member too", () => {
  const { meta } = baseline(ANDROID);
  meta.packages.push({
    id: localId("yw-extra"), name: "yw-extra", version: LOCAL_VERSION, source: null,
    manifest_path: "/ws/crates/yw-extra/Cargo.toml", dependencies: [], targets: [{ kind: ["lib"] }],
  });
  meta.resolve.nodes.push({ id: localId("yw-extra"), deps: [], features: [] });
  meta.workspace_members.push(localId("yw-extra"));
  assert.ok(run(meta, ANDROID).errors.includes("yw-extra: workspace member without a policy"));
  for (const target of TARGETS) {
    const missing = baseline(target).meta;
    missing.workspace_members = missing.workspace_members.filter((id) => id !== localId("yw-android"));
    assert.ok(run(missing, target).errors.includes("yw-android: workspace member not found"), target);
  }
  // Member rules hold on every table, the Windows-only members included.
  const { meta: devMeta, pkg } = baseline(ANDROID);
  pkg(localId("yw-host")).dependencies.push({ name: "x", kind: "dev" });
  pkg(localId("yw-android")).targets.push({ kind: ["custom-build"] });
  const { errors } = run(devMeta, ANDROID);
  assert.ok(errors.includes("yw-host: dev-dependencies are forbidden"));
  assert.ok(errors.includes("yw-android: build.rs is forbidden"));
  assert.throws(() => policyFor("wasm32-unknown-unknown"), /unknown target/u);
});

test("an unlisted crate is reported for every root that reaches it", () => {
  const { meta, edge } = baseline();
  meta.packages.push({
    id: registryId("evil", "1.0.0"), name: "evil", version: "1.0.0", source: CRATES_IO,
    manifest_path: "/src/evil-1.0.0/Cargo.toml", dependencies: [], targets: [{ kind: ["lib"] }],
  });
  meta.resolve.nodes.push({ id: registryId("evil", "1.0.0"), deps: [], features: [] });
  edge(localId("yw-win"), registryId("evil", "1.0.0"), normal);
  const { errors, ok } = run(meta);
  for (const root of ["yw-win", "yw-app", "yw-host"]) {
    assert.ok(errors.includes(`${root} -> evil=1.0.0: not in allowlist (runtime)`), root);
  }
  assert.deepEqual(ok.map((line) => line.split(" ")[0]).sort(), ["yw-android", "yw-core", "yw-engine", "yw-json", "yw-platform"]);
});

test("yw-engine may not reach yw-win or windows-sys", () => {
  const { meta, edge } = baseline();
  edge(localId("yw-engine"), localId("yw-win"), normal);
  const { errors } = run(meta);
  assert.ok(errors.includes("yw-engine -> yw-win=0.3.0: local crate not allowed here"), errors.join("\n"));
  assert.ok(errors.includes("yw-engine -> windows-sys=0.61.2: not in allowlist (runtime)"), errors.join("\n"));
});

test("a build-only crate linked at runtime is a violation", () => {
  const { meta, node } = baseline();
  const ccEdge = node(localId("yw-core")).deps.find((dep) => dep.pkg === registryId("cc", "1.4.2"));
  ccEdge.dep_kinds = normal;
  assert.ok(run(meta).errors.includes("yw-core -> cc=1.4.2: allowlisted build-only but linked at runtime"));
});

test("dev-dependencies and an own build.rs are refused for workspace members", () => {
  const { meta, pkg } = baseline();
  pkg(localId("yw-host")).dependencies.push({ name: "x", kind: "dev" });
  pkg(localId("yw-win")).targets.push({ kind: ["custom-build"] });
  pkg(localId("yw-app")).targets.push({ kind: ["custom-build"] });
  const { errors } = run(meta);
  assert.ok(errors.includes("yw-host: dev-dependencies are forbidden"));
  assert.ok(errors.includes("yw-win: build.rs is forbidden"));
  assert.ok(!errors.includes("yw-app: build.rs is forbidden"), "yw-app's build.rs is allowed");
});

test("forbidden features, foreign sources, proc-macros and unreviewed build scripts", () => {
  const { meta, pkg, node } = baseline();
  node(registryId("secp256k1", "0.31.1")).features.push("alloc", "rand");
  pkg(registryId("sha2", "0.10.9")).source = "git+https://example.invalid/sha2";
  pkg(registryId("subtle", "2.6.1")).targets.push({ kind: ["proc-macro"] });
  pkg(registryId("keccak", "0.1.6")).targets.push({ kind: ["custom-build"] });
  const { errors } = run(meta);
  assert.ok(errors.includes("yw-core -> secp256k1=0.31.1: forbidden features rand (workspace-unified)"));
  assert.ok(errors.includes("yw-core -> sha2=0.10.9: non-crates.io source git+https://example.invalid/sha2"));
  assert.ok(errors.some((error) => error.startsWith("yw-core -> subtle=2.6.1: proc-macro")));
  assert.ok(errors.includes("yw-core -> keccak=0.1.6: unreviewed build.rs"));
});

test("an allowlisted crate that is no longer reached must be pruned", () => {
  const { meta, node } = baseline();
  const engine = node(localId("yw-engine"));
  engine.deps = engine.deps.filter((dep) => dep.pkg !== registryId("qrcodegen", "1.8.0"));
  assert.deepEqual(run(meta).errors, [
    "yw-engine: qrcodegen=1.8.0 allowlisted but not reached (prune or fix phase)",
    "yw-android: qrcodegen=1.8.0 allowlisted but not reached (prune or fix phase)",
    "yw-app: qrcodegen=1.8.0 allowlisted but not reached (prune or fix phase)",
  ]);
  // On Android, libc must be reached too (it is, through yw-core: a graph without it fails).
  const android = baseline(ANDROID);
  const core = android.node(localId("yw-core"));
  core.deps = core.deps.filter((dep) => dep.pkg !== registryId("libc", "0.2.189"));
  const ywAndroid = android.node(localId("yw-android"));
  ywAndroid.deps = ywAndroid.deps.filter((dep) => dep.pkg !== registryId("libc", "0.2.189"));
  assert.deepEqual(run(android.meta, ANDROID).errors, [
    "yw-core: libc=0.2.189 allowlisted but not reached (prune or fix phase)",
    "yw-engine: libc=0.2.189 allowlisted but not reached (prune or fix phase)",
    "yw-android: libc=0.2.189 allowlisted but not reached (prune or fix phase)",
  ]);
});

test("yw-app reaches qrcodegen only through yw-engine (2026-11-24, S5-2)", () => {
  const { meta, edge } = baseline();
  edge(localId("yw-app"), registryId("qrcodegen", "1.8.0"), normal);
  const { errors, ok } = run(meta);
  assert.deepEqual(errors, ["yw-app -> qrcodegen=1.8.0: direct dependency not allowed (only through yw-engine)"]);
  assert.ok(!ok.some((line) => line.startsWith("yw-app ")));
  // A build-only direct edge is refused too.
  const second = baseline();
  second.edge(localId("yw-app"), registryId("qrcodegen", "1.8.0"), build);
  assert.ok(run(second.meta).errors.includes("yw-app -> qrcodegen=1.8.0: direct dependency not allowed (only through yw-engine)"));
});

test("local crates outside the policy, unknown members and missing members", () => {
  const { meta, edge } = baseline();
  edge(localId("yw-json"), localId("yw-win"), normal);
  meta.packages.push({
    id: localId("yw-extra"), name: "yw-extra", version: LOCAL_VERSION, source: null,
    manifest_path: "/ws/crates/yw-extra/Cargo.toml", dependencies: [], targets: [{ kind: ["lib"] }],
  });
  meta.resolve.nodes.push({ id: localId("yw-extra"), deps: [], features: [] });
  meta.workspace_members.push(localId("yw-extra"));
  const { errors } = run(meta);
  assert.ok(errors.includes("yw-json -> yw-win=0.3.0: local crate not allowed here"));
  assert.ok(errors.includes("yw-extra: workspace member without a policy"));

  const missing = baseline().meta;
  missing.workspace_members = missing.workspace_members.filter((id) => id !== localId("yw-host"));
  assert.ok(run(missing).errors.includes("yw-host: workspace member not found"));
});

test("CLI with --metadata and --target: exit 0, 1 and 2", () => {
  const dir = mkdtempSync(join(tmpdir(), "check-core-deps-"));
  try {
    const cli = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8", windowsHide: true });
    const good = join(dir, "good.json");
    writeFileSync(good, JSON.stringify(baseline().meta));
    const passed = cli("--metadata", good);
    assert.equal(passed.status, 0, passed.stderr);
    assert.match(passed.stdout, /^deps check OK \(x86_64-pc-windows-msvc, phases: sol\)$/mu);
    assert.doesNotMatch(passed.stdout, /linux-android/u, "--metadata alone checks the Windows table only");

    const goodAndroid = join(dir, "good-android.json");
    writeFileSync(goodAndroid, JSON.stringify(baseline(ANDROID).meta));
    const androidPassed = cli("--target", ANDROID, "--metadata", goodAndroid, "--list");
    assert.equal(androidPassed.status, 0, androidPassed.stderr);
    assert.match(androidPassed.stdout, /^deps check OK \(aarch64-linux-android, phases: sol\)$/mu);
    assert.match(androidPassed.stdout, /^yw-app deps check skipped: not built for aarch64-linux-android$/mu);
    assert.match(androidPassed.stdout, /^aarch64-linux-android\tyw-android\truntime\tlibc=0\.2\.189\t/mu);
    // The Android document under the Windows table fails (libc).
    const wrongTable = cli("--metadata", goodAndroid);
    assert.equal(wrongTable.status, 1);
    assert.match(wrongTable.stderr, /deps check FAILED \(x86_64-pc-windows-msvc[\s\S]*libc=0\.2\.189: not in allowlist/u);

    const { meta, pkg } = baseline();
    pkg(localId("yw-host")).dependencies.push({ name: "x", kind: "dev" });
    const bad = join(dir, "bad.json");
    writeFileSync(bad, JSON.stringify(meta));
    const failed = cli("--metadata", bad);
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /deps check FAILED[\s\S]*yw-host: dev-dependencies are forbidden/u);

    const broken = join(dir, "broken.json");
    writeFileSync(broken, "{not json");
    assert.equal(cli("--metadata", broken).status, 2);
    assert.equal(cli("--metadata", join(dir, "missing.json")).status, 2);
    writeFileSync(broken, "{}");
    assert.equal(cli("--metadata", broken).status, 2, "a document without the fields it reads");
    assert.equal(cli("--metadata").status, 2);
    assert.equal(cli("--target", "wasm32-unknown-unknown", "--metadata", good).status, 2, "an unknown target");
    assert.equal(cli("--target").status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
