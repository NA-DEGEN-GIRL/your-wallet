// scripts/check-core-deps.mjs on synthetic `cargo metadata` documents: a graph that matches the
// allowlists exactly passes, and each kind of violation is reported (spec/01 §4.2). The CLI is
// also run with `--metadata <file>` for its exit codes (0 / 1 / 2). No cargo, no network.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { BUILD_RS_ALLOW, CRATES_IO, POLICY, checkMetadata } from "./check-core-deps.mjs";

const SCRIPT = fileURLToPath(new URL("./check-core-deps.mjs", import.meta.url));
const LOCAL_VERSION = "0.3.0";
const localId = (name) => `path+file:///ws/crates/${name}#${LOCAL_VERSION}`;
const registryId = (name, version) => `${CRATES_IO}#${name}@${version}`;
const normal = [{ kind: null, target: null }];
const build = [{ kind: "build", target: null }];

/**
 * A workspace whose closures are exactly the allowlists: yw-core links its runtime crates and
 * builds with its build-only ones; yw-win links windows-*; yw-app links qrcodegen and the three
 * local crates; yw-host links yw-json and yw-win.
 */
function baseline() {
  const packages = [];
  const nodes = [];
  const pkgById = new Map();
  const nodeById = new Map();
  const addPackage = (id, name, version, source) => {
    const pkg = {
      id, name, version, source,
      manifest_path: `/src/${name}-${version}/Cargo.toml`,
      dependencies: [],
      targets: [{ kind: ["lib"] }],
    };
    if (source !== null && BUILD_RS_ALLOW.has(name)) pkg.targets.push({ kind: ["custom-build"] });
    const node = { id, deps: [], features: [] };
    packages.push(pkg);
    nodes.push(node);
    pkgById.set(id, pkg);
    nodeById.set(id, node);
  };
  for (const name of Object.keys(POLICY)) addPackage(localId(name), name, LOCAL_VERSION, null);
  const external = new Map();
  for (const { allow } of Object.values(POLICY)) {
    for (const [key, mode] of Object.entries(allow)) external.set(key, mode);
  }
  for (const key of external.keys()) {
    const [name, version] = key.split("=");
    addPackage(registryId(name, version), name, version, CRATES_IO);
  }
  const edge = (from, to, kinds) => nodeById.get(from).deps.push({ pkg: to, dep_kinds: kinds });
  const allowOf = (root) => Object.entries(POLICY[root].allow);
  for (const [key, mode] of allowOf("yw-core")) {
    const [name, version] = key.split("=");
    edge(localId("yw-core"), registryId(name, version), mode === "b" ? build : normal);
  }
  for (const [key] of allowOf("yw-win")) {
    const [name, version] = key.split("=");
    edge(localId("yw-win"), registryId(name, version), normal);
  }
  edge(localId("yw-core"), localId("yw-json"), normal);
  for (const local of ["yw-core", "yw-json", "yw-win"]) edge(localId("yw-app"), localId(local), normal);
  edge(localId("yw-app"), registryId("qrcodegen", "1.8.0"), normal);
  for (const local of ["yw-json", "yw-win"]) edge(localId("yw-host"), localId(local), normal);
  return {
    meta: {
      packages,
      workspace_members: Object.keys(POLICY).map(localId),
      resolve: { nodes },
    },
    pkg: (id) => pkgById.get(id),
    node: (id) => nodeById.get(id),
    edge,
  };
}

const run = (meta) => checkMetadata(meta);

test("a graph equal to the allowlists passes", () => {
  const { meta } = baseline();
  const result = run(meta);
  assert.deepEqual(result.errors, []);
  assert.equal(result.ok.length, Object.keys(POLICY).length);
  assert.ok(result.ok.includes("yw-json deps check OK: 0 crates (x86_64-pc-windows-msvc)"));
  assert.ok(result.listing.some((row) => row.startsWith("yw-core\tbuild\tcc=1.4.2\t")));
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
  assert.deepEqual(ok.map((line) => line.split(" ")[0]).sort(), ["yw-core", "yw-json"]);
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
  const app = node(localId("yw-app"));
  app.deps = app.deps.filter((dep) => dep.pkg !== registryId("qrcodegen", "1.8.0"));
  assert.deepEqual(run(meta).errors, ["yw-app: qrcodegen=1.8.0 allowlisted but not reached (prune or fix phase)"]);
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

test("CLI with --metadata: exit 0, 1 and 2", () => {
  const dir = mkdtempSync(join(tmpdir(), "check-core-deps-"));
  try {
    const cli = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8", windowsHide: true });
    const good = join(dir, "good.json");
    writeFileSync(good, JSON.stringify(baseline().meta));
    const passed = cli("--metadata", good);
    assert.equal(passed.status, 0, passed.stderr);
    assert.match(passed.stdout, /^deps check OK \(x86_64-pc-windows-msvc, phases: sol\)$/mu);

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
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
