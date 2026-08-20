import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventories } from "./generate-inventories.mjs";
import { canonicalEncode } from "./release-manifest.mjs";

const options = {
  cargoLockSha256: "2".repeat(64),
  sourceCommit: "1".repeat(40),
  sourceDateEpoch: 1_700_000_000,
  target: "x86_64-pc-windows-msvc",
};

function metadata(source = "registry+https://github.com/rust-lang/crates.io-index") {
  return {
    packages: [
      {
        id: "path+file:///workspace#your-wallet@0.1.0",
        license: "Apache-2.0 OR MIT",
        links: null,
        name: "your-wallet",
        source: null,
        targets: [{ kind: ["bin"] }],
        version: "0.1.0",
      },
      {
        id: `${source}#safe-dependency@1.2.3`,
        license: "MIT",
        links: null,
        name: "safe-dependency",
        source,
        targets: [{ kind: ["lib"] }, { kind: ["custom-build"] }],
        version: "1.2.3",
      },
    ],
    resolve: {
      nodes: [
        { dependencies: [`${source}#safe-dependency@1.2.3`], features: [], id: "path+file:///workspace#your-wallet@0.1.0" },
        { dependencies: [], features: ["std"], id: `${source}#safe-dependency@1.2.3` },
      ],
    },
    workspace_members: ["path+file:///workspace#your-wallet@0.1.0"],
  };
}

test("inventory and SPDX output are deterministic", () => {
  const first = buildInventories(metadata(), options);
  const second = buildInventories(metadata(), options);
  assert.equal(canonicalEncode(first), canonicalEncode(second));
  assert.equal(first.dependencyInventory.packages[0].source, "crates.io");
  assert.equal(first.dependencyInventory.packages[0].hasBuildScript, "yes");
  assert.equal(first.sbom.spdxVersion, "SPDX-2.3");
  assert.equal(first.sbom.creationInfo.created, "2023-11-14T22:13:20Z");
});

test("private or unreviewed git dependency sources fail closed", () => {
  assert.throws(
    () => buildInventories(metadata("git+https://example.invalid/private/repository"), options),
    /refuses non-crates.io dependency sources/u,
  );
});

test("third-party packages without a declared license fail closed", () => {
  const input = metadata();
  input.packages[1].license = null;
  assert.throws(() => buildInventories(input, options), /has no declared license/u);
});

test("unreviewed license identifiers fail closed", () => {
  const input = metadata();
  input.packages[1].license = "GPL-3.0-only";
  assert.throws(() => buildInventories(input, options), /unreviewed license identifier/u);
});
