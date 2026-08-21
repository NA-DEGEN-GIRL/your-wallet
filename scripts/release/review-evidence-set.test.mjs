import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { link, lstat, mkdir, mkdtemp, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";

import {
  REQUIRED_REVIEWED_EVIDENCE_PATHS,
  REVIEW_EVIDENCE_SUBJECT_SCHEMA,
  canonicalEncode,
  computeReviewedEvidenceSetSha256,
  sha256Hex,
} from "./release-manifest.mjs";
import { collectReviewedEvidenceSetSubject } from "./review-evidence-set.mjs";

const execFileAsync = promisify(execFile);

async function createReviewedEvidenceStage() {
  const root = await mkdtemp(path.join(os.tmpdir(), "your-wallet-reviewed-evidence-"));
  const records = [];
  for (const relativePath of REQUIRED_REVIEWED_EVIDENCE_PATHS) {
    const absolutePath = path.join(root, ...relativePath.split("/"));
    const contents = Buffer.from(`reviewed evidence for ${relativePath}\n`, "utf8");
    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, contents, { flag: "wx" });
    records.push({ bytes: contents.length.toString(), path: relativePath, sha256: sha256Hex(contents) });
  }
  return { records, root };
}

async function metadataSnapshot(root) {
  const snapshot = [];
  for (const relativePath of REQUIRED_REVIEWED_EVIDENCE_PATHS) {
    const status = await lstat(path.join(root, ...relativePath.split("/")), { bigint: true });
    snapshot.push({
      ctimeNs: status.ctimeNs.toString(),
      mtimeNs: status.mtimeNs.toString(),
      path: relativePath,
      size: status.size.toString(),
    });
  }
  return snapshot;
}

test("review evidence-set subject is exact, deterministic, and read-only", async () => {
  const stage = await createReviewedEvidenceStage();
  try {
    const before = await metadataSnapshot(stage.root);
    const subject = await collectReviewedEvidenceSetSubject(stage.root);
    const after = await metadataSnapshot(stage.root);
    assert.deepEqual(subject, {
      reviewedEvidenceSetSha256: computeReviewedEvidenceSetSha256(stage.records),
      schema: REVIEW_EVIDENCE_SUBJECT_SCHEMA,
    });
    assert.deepEqual(after, before);

    const cli = await execFileAsync(process.execPath, [
      path.resolve("scripts/release/review-evidence-set.mjs"),
      "--bundle-root",
      stage.root,
    ]);
    assert.equal(cli.stdout, `${canonicalEncode(subject)}\n`);
    assert.equal(cli.stderr, "");
  } finally {
    await rm(stage.root, { force: true, recursive: true });
  }
});

test("review evidence-set command rejects missing, extra, and case-aliased files without path disclosure", async () => {
  const missing = await createReviewedEvidenceStage();
  const extra = await createReviewedEvidenceStage();
  const caseAlias = await createReviewedEvidenceStage();
  try {
    await unlink(path.join(missing.root, ...REQUIRED_REVIEWED_EVIDENCE_PATHS[0].split("/")));
    await writeFile(path.join(extra.root, "evidence", "unreviewed.txt"), "unreviewed\n", { flag: "wx" });
    const canonicalCargoLock = REQUIRED_REVIEWED_EVIDENCE_PATHS.find((item) => item.endsWith("Cargo.lock"));
    assert.ok(canonicalCargoLock);
    const canonicalCargoLockPath = path.join(caseAlias.root, ...canonicalCargoLock.split("/"));
    await rename(
      canonicalCargoLockPath,
      path.join(path.dirname(canonicalCargoLockPath), path.basename(canonicalCargoLockPath).toLowerCase()),
    );
    for (const root of [missing.root, extra.root, caseAlias.root]) {
      await assert.rejects(
        () => execFileAsync(process.execPath, [
          path.resolve("scripts/release/review-evidence-set.mjs"),
          "--bundle-root",
          root,
        ]),
        (error) => {
          assert.equal(error.stdout, "");
          assert.equal(
            error.stderr,
            "REVIEW_EVIDENCE_SET_FAILED: staged evidence set is not exact\n",
          );
          assert.doesNotMatch(error.stderr, /unreviewed|windows-negative|Cargo\.lock/u);
          return true;
        },
      );
    }
  } finally {
    await Promise.all([
      rm(missing.root, { force: true, recursive: true }),
      rm(extra.root, { force: true, recursive: true }),
      rm(caseAlias.root, { force: true, recursive: true }),
    ]);
  }
});

test("review evidence-set command rejects hard-linked evidence", async () => {
  const stage = await createReviewedEvidenceStage();
  try {
    const source = path.join(stage.root, ...REQUIRED_REVIEWED_EVIDENCE_PATHS[0].split("/"));
    const target = path.join(stage.root, ...REQUIRED_REVIEWED_EVIDENCE_PATHS[1].split("/"));
    await unlink(target);
    await link(source, target);
    await assert.rejects(
      () => collectReviewedEvidenceSetSubject(stage.root),
      /hard-linked file/u,
    );
  } finally {
    await rm(stage.root, { force: true, recursive: true });
  }
});

test("review evidence-set command rejects missing and extra arguments", async () => {
  for (const args of [[], ["--bundle-root", ".", "--output", "ignored"]]) {
    await assert.rejects(
      () => execFileAsync(process.execPath, [path.resolve("scripts/release/review-evidence-set.mjs"), ...args]),
      (error) => {
        assert.equal(error.stdout, "");
        assert.equal(
          error.stderr,
          "REVIEW_EVIDENCE_SET_FAILED: staged evidence set is not exact\n",
        );
        return true;
      },
    );
  }
});

test("Windows review wrapper holds one offline read-only tree around the exact subject command", async () => {
  const [wrapper, common] = await Promise.all([
    readFile("scripts/release/review-evidence-set.ps1", "utf8"),
    readFile("scripts/release/common.ps1", "utf8"),
  ]);
  assert.ok(wrapper.includes("[Parameter(Mandatory = $true)][switch]$OperatorConfirmedNetworkIsolation"));
  assert.ok(wrapper.includes("Open-ReadOnlyReleaseTreeLocks -BundleRoot $BundleRoot"));
  assert.ok(wrapper.includes("$bundle = $releaseLocks.CanonicalBundleRoot"));
  assert.ok(wrapper.includes("ConvertFrom-ExactNamedArguments"));
  assert.ok(wrapper.includes("Invoke-ReviewEvidenceSetCeremony @boundArguments"));
  assert.ok(!wrapper.includes("Invoke-ReviewEvidenceSetCeremony @args"));
  assert.ok(!wrapper.includes("Resolve-Path -LiteralPath $BundleRoot"));
  assert.equal(wrapper.match(/Assert-NoReparseTree -LiteralPath \$bundle/gu)?.length, 2);
  assert.equal(wrapper.match(/Assert-ReleaseTreeEffectivelyReadOnly -BundleRoot \$bundle/gu)?.length, 2);
  assert.equal(wrapper.match(/review-evidence-set\.mjs/gu)?.length, 1);
  assert.ok(wrapper.includes("--bundle-root"));
  assert.ok(wrapper.includes("if (-not [string]::IsNullOrEmpty($result.Stderr))"));
  assert.ok(wrapper.includes("your-wallet-reviewed-evidence-set-subject-v1"));
  assert.ok(wrapper.includes("[System.Text.RegularExpressions.RegexOptions]::CultureInvariant"));
  assert.ok(wrapper.includes("Write-Output $result.Stdout"));
  assert.ok(wrapper.includes("Close-ReadOnlyReleaseTreeLocks -LockSet $releaseLocks"));
  assert.ok(wrapper.includes("REVIEW_EVIDENCE_SET_FAILED: offline review evidence ceremony failed closed"));
  assert.ok(common.includes("private const uint FileShareRead = 0x00000001"));
  assert.ok(common.includes("GetFinalPathNameByHandleW"));
  assert.ok(common.includes("FileInfoByHandleClass.FileIdInfo"));
  assert.ok(common.includes("Open-PinnedReleaseDirectoryPath"));
  assert.ok(common.includes("SameIdentity($bootstrap, $handles[$handles.Count - 1])"));
  assert.ok(common.includes("CanonicalBundleRoot = $canonicalRoot"));
  assert.ok(common.includes("function ConvertFrom-ExactNamedArguments"));
});

test(
  "Windows review wrapper collapses preflight failures without disclosing paths",
  { skip: process.platform !== "win32" },
  async () => {
    const privateParent = await mkdtemp(path.join(os.tmpdir(), "your-wallet-review-wrapper-private-"));
    const missingRoot = path.join(privateParent, "not-present");
    const wrapperPath = path.resolve("scripts/release/review-evidence-set.ps1");
    const expectPrivateFailure = async (argumentsList) => {
      await assert.rejects(
        () => execFileAsync(
          "powershell",
          ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", wrapperPath, ...argumentsList],
          { encoding: "utf8", timeout: 10_000 },
        ),
        (error) => {
          const stderr = error.stderr.replace(/\r\n/gu, "\n");
          assert.ok(error.stdout === "", "wrapper failure stdout must remain empty");
          assert.ok(
            stderr === "REVIEW_EVIDENCE_SET_FAILED: offline review evidence ceremony failed closed\n",
            "wrapper failure stderr must be one fixed category line",
          );
          assert.ok(!stderr.includes(privateParent), "wrapper failure must not disclose supplied paths");
          assert.ok(!stderr.includes(wrapperPath), "wrapper failure must not disclose the script path");
          return true;
        },
      );
    };
    try {
      await expectPrivateFailure([
        "-BundleRoot",
        missingRoot,
        "-OperatorConfirmedNetworkIsolation",
      ]);
      await expectPrivateFailure(["-UnknownPrivateParameter", privateParent]);
      await expectPrivateFailure(["-BundleRoot"]);
    } finally {
      await rm(privateParent, { force: true, recursive: true });
    }
  },
);
