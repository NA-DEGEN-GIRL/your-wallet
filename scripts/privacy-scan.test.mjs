import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, mkdir, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  privacyFailureReport,
  runPrivacyScan,
  scanRepository,
} from "./privacy-scan.mjs";

const execFile = promisify(execFileCallback);

async function runGit(repositoryRoot, arguments_) {
  try {
    await execFile("git", ["-C", repositoryRoot, ...arguments_], {
      timeout: 30_000,
      windowsHide: true,
    });
  } catch {
    throw new Error("Git fixture setup failed.");
  }
}

async function createRepository() {
  const repositoryRoot = await mkdtemp(join(tmpdir(), "privacy-scan-test-"));
  try {
    await runGit(repositoryRoot, ["init", "--quiet"]);
    return repositoryRoot;
  } catch (error) {
    await rm(repositoryRoot, { force: true, recursive: true });
    throw error;
  }
}

async function removeRepository(repositoryRoot) {
  await rm(repositoryRoot, { force: true, recursive: true });
}

function secretMarker() {
  return ["[", "TOKEN", "]"].join("");
}

function privateKeyAssignment() {
  // Exercise the text detector with an invalid zero scalar, never a usable key.
  return ["private", "_key = \"", "0".repeat(64), "\";\n"].join("");
}

function authorizationHeader() {
  return ["author", "ization: Bearer ", "a".repeat(12), "\n"].join("");
}

function seedPhraseLabel() {
  // Detector syntax only: deliberately use a non-BIP39 word, never a mnemonic.
  return [
    "seed",
    " phrase = \"",
    Array.from({ length: 12 }, () => "notabipword").join(" "),
    "\"\n",
  ].join("");
}

function alchemyKeyUrl() {
  // Shape only: a fake 32-character path key assembled from fragments.
  return ["const url = \"https://eth-mainnet", ".g.alchemy", ".com/v2/", "Ab3".repeat(10), "xy\";\n"].join("");
}

function quicknodeUrl() {
  return ["const url = \"https://name.ethereum-sepolia", ".quiknode", ".pro/", "a1b2".repeat(8), "/\";\n"].join("");
}

function llmApiKey() {
  return ["const apiKey = \"", "sk", "-", "x".repeat(24), "\";\n"].join("");
}

function labeledPrivateKeyHex() {
  // Invalid zero scalar after a key label (no assignment quotes): only the labeled rule applies.
  return ["// signing", " key: 0x", "0".repeat(64), "\n"].join("");
}

function bip39WordSequence() {
  // Twelve BIP39 words joined by quotes, commas and brackets; not a checksum-valid mnemonic.
  return ["const words = [", Array.from({ length: 12 }, () => ["\"ab", "le\""].join("")).join(", "), "];\n"].join("");
}

const NINE_RULES = [
  "private-key-assignment",
  "authorization-header",
  "seed-phrase-label",
  "production-secret-marker",
  "alchemy-key-url",
  "quicknode-url",
  "llm-api-key",
  "labeled-private-key-hex",
  "bip39-word-sequence",
];

function allSignatures() {
  return [
    privateKeyAssignment(),
    authorizationHeader(),
    seedPhraseLabel(),
    secretMarker(),
    alchemyKeyUrl(),
    quicknodeUrl(),
    llmApiKey(),
    labeledPrivateKeyHex(),
    bip39WordSequence(),
  ].join("\n");
}

function vectorSignatures() {
  // Only the rules with vectorsAllowed: true.
  return [privateKeyAssignment(), seedPhraseLabel(), labeledPrivateKeyHex(), bip39WordSequence()].join("\n");
}

const rules = (...names) => names.map((rule) => ({ rule }));

async function writeRepositoryFile(repositoryRoot, relativePath, text) {
  const target = join(repositoryRoot, ...relativePath.split("/"));
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, text, "utf8");
}

test("scans tracked and nonignored untracked sources but excludes ignored output", async () => {
  const repositoryRoot = await createRepository();
  try {
    await writeFile(
      join(repositoryRoot, ".gitignore"),
      "node_modules/\nartifacts/\nignored-source.rs\n",
      "utf8",
    );
    await writeFile(join(repositoryRoot, "tracked.md"), "safe tracked source\n", "utf8");
    await writeFile(join(repositoryRoot, "untracked.rs"), "safe untracked source\n", "utf8");
    await mkdir(join(repositoryRoot, "node_modules"));
    await mkdir(join(repositoryRoot, "artifacts"));
    await writeFile(
      join(repositoryRoot, "node_modules", "dependency.js"),
      secretMarker(),
      "utf8",
    );
    await writeFile(
      join(repositoryRoot, "artifacts", "generated.json"),
      secretMarker(),
      "utf8",
    );
    await writeFile(
      join(repositoryRoot, "ignored-source.rs"),
      secretMarker(),
      "utf8",
    );
    await runGit(repositoryRoot, ["add", "--", ".gitignore", "tracked.md"]);

    assert.deepEqual(await scanRepository(repositoryRoot), []);

    // A quoted 64-hex private_key assignment also carries a key label, so both rules report it.
    const candidate = join(repositoryRoot, "candidate.rs");
    await writeFile(candidate, privateKeyAssignment(), "utf8");
    assert.deepEqual(
      await scanRepository(repositoryRoot),
      rules("private-key-assignment", "labeled-private-key-hex"),
    );

    await runGit(repositoryRoot, ["add", "--", "candidate.rs"]);
    assert.deepEqual(
      await scanRepository(repositoryRoot),
      rules("private-key-assignment", "labeled-private-key-hex"),
    );

    // Cached paths deleted only from the working tree have no bytes to inspect.
    await unlink(candidate);
    assert.deepEqual(await scanRepository(repositoryRoot), []);
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("rejects a source candidate that is a symbolic link", async (context) => {
  const repositoryRoot = await createRepository();
  try {
    await writeFile(join(repositoryRoot, "target.txt"), "safe target\n", "utf8");
    try {
      await symlink("target.txt", join(repositoryRoot, "linked.rs"), "file");
    } catch (error) {
      if (["EACCES", "EPERM", "UNKNOWN"].includes(error?.code)) {
        context.skip("Symbolic links are unavailable on this host.");
        return;
      }
      throw new Error("Symbolic-link fixture setup failed.");
    }
    await runGit(repositoryRoot, ["add", "--", "linked.rs"]);

    await assert.rejects(scanRepository(repositoryRoot), {
      message: "Privacy scan infrastructure failure.",
      name: "PrivacyScanInfrastructureError",
    });
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("reports findings only by fixed rule name and count", async () => {
  const repositoryRoot = await createRepository();
  try {
    await writeFile(join(repositoryRoot, "candidate.md"), secretMarker(), "utf8");

    let output = "";
    const exitCode = await runPrivacyScan(repositoryRoot, (message) => {
      output += message;
    });

    assert.equal(exitCode, 1);
    assert.equal(
      output,
      "Privacy scan failed (1 finding(s)).\n- production-secret-marker: 1\n",
    );
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("retains all nine forbidden source signatures", async () => {
  const repositoryRoot = await createRepository();
  try {
    await writeFile(join(repositoryRoot, "signatures.rs"), allSignatures(), "utf8");

    assert.deepEqual(await scanRepository(repositoryRoot), rules(...NINE_RULES));
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("detects each new rule on its own", async () => {
  const cases = [
    [alchemyKeyUrl(), "alchemy-key-url"],
    [quicknodeUrl(), "quicknode-url"],
    [llmApiKey(), "llm-api-key"],
    [labeledPrivateKeyHex(), "labeled-private-key-hex"],
    [bip39WordSequence(), "bip39-word-sequence"],
  ];
  const repositoryRoot = await createRepository();
  try {
    for (const [text, rule] of cases) {
      await writeFile(join(repositoryRoot, "candidate.rs"), text, "utf8");
      assert.deepEqual(await scanRepository(repositoryRoot), rules(rule), rule);
    }
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("ignores placeholders, documentation hosts, hashes and ordinary text", async () => {
  const negatives = [
    ["alchemy <KEY> placeholder", ["https://eth-mainnet", ".g.alchemy", ".com/v2/<KEY>"].join("")],
    ["alchemy {KEY} placeholder", ["https://<host>", ".g.alchemy", ".com/v2/{KEY}"].join("")],
    ["quicknode <token> placeholder", ["https://<name>.<subdomain>", ".quiknode", ".pro/<토큰>/"].join("")],
    ["quicknode docs host", ["https://docs-demo", ".quiknode", ".pro/"].join("")],
    ["short sk- prefix", ["task", "-", "runner"].join("")],
    ["genesis hash", ["genesis = \"0x", "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "\""].join("")],
    ["unlabeled 64-hex", ["const TRANSFER_TOPIC = \"0x", "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "\";"].join("")],
    ["key label with a long hash", ["public key hash: 0x", "ab".repeat(40)].join("")],
    ["english sentence", "the wallet keeps a small vault on this computer and signs only what the user approves after a review of the simulation"],
    ["dotted BIP39 words", Array.from({ length: 12 }, () => ["ab", "le"].join("")).join(".")],
    ["eleven BIP39 words", Array.from({ length: 11 }, () => ["ab", "le"].join("")).join(" ")],
  ];
  const repositoryRoot = await createRepository();
  try {
    for (const [label, text] of negatives) {
      await writeFile(join(repositoryRoot, "candidate.md"), `${text}\n`, "utf8");
      assert.deepEqual(await scanRepository(repositoryRoot), [], label);
    }
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("exempts test-vector paths only for vector rules", async () => {
  const exempt = [
    "crates/x/tests/v.rs",
    "crates/x/tests/vectors/v.rs",
    "crates/x/src/m/tests.rs",
    "crates/x/src/tests.rs",
    "tools/x/tests/v.rs",
    "extension/tests/v.test.mjs",
    "scripts/v.test.mjs",
    "spec/02.md",
  ];
  const repositoryRoot = await createRepository();
  try {
    for (const path of exempt) {
      await writeRepositoryFile(repositoryRoot, path, vectorSignatures());
    }
    assert.deepEqual(await scanRepository(repositoryRoot), []);

    // Endpoint and marker rules still apply inside exempt paths.
    await writeRepositoryFile(repositoryRoot, "spec/02.md", `${vectorSignatures()}\n${alchemyKeyUrl()}`);
    assert.deepEqual(await scanRepository(repositoryRoot), rules("alchemy-key-url"));
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("detects vectors outside the exempt paths", async () => {
  const nonExempt = [
    "crates/x/src/lib.rs",
    "crates/x/src/m/mod.rs",
    "crates/x/src/m/tests_helper.rs",
    "crates/x/benches/tests/v.rs",
    "tools/x/src/main.rs",
    "scripts/check-core-deps.mjs",
    "docs/acceptance/m1.md",
    "README.md",
  ];
  const repositoryRoot = await createRepository();
  try {
    for (const path of nonExempt) {
      await writeRepositoryFile(repositoryRoot, path, vectorSignatures());
      assert.deepEqual(
        await scanRepository(repositoryRoot),
        rules("private-key-assignment", "seed-phrase-label", "labeled-private-key-hex", "bip39-word-sequence"),
        path,
      );
      await rm(join(repositoryRoot, ...path.split("/")));
    }
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("formats multiple findings in stable rule order", () => {
  assert.equal(
    privacyFailureReport([
      { rule: "production-secret-marker" },
      { rule: "private-key-assignment" },
      { rule: "production-secret-marker" },
    ]),
    [
      "Privacy scan failed (3 finding(s)).",
      "- private-key-assignment: 1",
      "- production-secret-marker: 2",
      "",
    ].join("\n"),
  );
});

test("scans Rust harness sources before and after Git staging", async () => {
  const repositoryRoot = await createRepository();
  try {
    await writeFile(join(repositoryRoot, "harness.rs"), allSignatures(), "utf8");
    // .cs is no longer a scanned extension.
    await writeFile(join(repositoryRoot, "Harness.cs"), allSignatures(), "utf8");
    const expected = rules(...NINE_RULES);
    assert.deepEqual(await scanRepository(repositoryRoot), expected);
    await runGit(repositoryRoot, ["add", "--", "harness.rs", "Harness.cs"]);
    assert.deepEqual(await scanRepository(repositoryRoot), expected);
  } finally {
    await removeRepository(repositoryRoot);
  }
});

test("fails closed with a fixed diagnostic when Git inventory is unavailable", async () => {
  const nonRepository = await mkdtemp(join(tmpdir(), "privacy-scan-test-"));
  try {
    await assert.rejects(scanRepository(nonRepository), {
      message: "Privacy scan infrastructure failure.",
      name: "PrivacyScanInfrastructureError",
    });

    let output = "";
    const exitCode = await runPrivacyScan(nonRepository, (message) => {
      output += message;
    });

    assert.equal(exitCode, 1);
    assert.equal(
      output,
      "Privacy scan failed: repository inventory or source inspection was unavailable.\n",
    );
    assert.equal(output.includes(nonRepository), false);
  } finally {
    await removeRepository(nonRepository);
  }
});
