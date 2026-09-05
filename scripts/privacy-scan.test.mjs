import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, mkdir, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

    const candidate = join(repositoryRoot, "candidate.rs");
    await writeFile(candidate, privateKeyAssignment(), "utf8");
    assert.deepEqual(await scanRepository(repositoryRoot), [
      { rule: "private-key-assignment" },
    ]);

    await runGit(repositoryRoot, ["add", "--", "candidate.rs"]);
    assert.deepEqual(await scanRepository(repositoryRoot), [
      { rule: "private-key-assignment" },
    ]);

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

test("retains all four forbidden source signatures", async () => {
  const repositoryRoot = await createRepository();
  try {
    await writeFile(
      join(repositoryRoot, "signatures.rs"),
      [
        privateKeyAssignment(),
        authorizationHeader(),
        seedPhraseLabel(),
        secretMarker(),
      ].join("\n"),
      "utf8",
    );

    assert.deepEqual(await scanRepository(repositoryRoot), [
      { rule: "private-key-assignment" },
      { rule: "authorization-header" },
      { rule: "seed-phrase-label" },
      { rule: "production-secret-marker" },
    ]);
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

test("scans native C# harness sources before and after Git staging", async () => {
  const repositoryRoot = await createRepository();
  try {
    await writeFile(join(repositoryRoot, "Harness.cs"),
      [privateKeyAssignment(), authorizationHeader(), seedPhraseLabel(), secretMarker()].join("\n"),
      "utf8");
    const expected = [
      { rule: "private-key-assignment" },
      { rule: "authorization-header" },
      { rule: "seed-phrase-label" },
      { rule: "production-secret-marker" },
    ];
    assert.deepEqual(await scanRepository(repositoryRoot), expected);
    await runGit(repositoryRoot, ["add", "--", "Harness.cs"]);
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
