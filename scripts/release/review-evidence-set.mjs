import { createHash } from "node:crypto";
import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  REQUIRED_REVIEWED_EVIDENCE_PATHS,
  REVIEW_EVIDENCE_SUBJECT_SCHEMA,
  ReleaseValidationError,
  canonicalEncode,
  computeReviewedEvidenceSetSha256,
  resolveExactReleasePath,
} from "./release-manifest.mjs";

class ReviewEvidenceSetError extends Error {
  constructor(message) {
    super(message);
    this.name = "ReviewEvidenceSetError";
  }
}

function fail(message) {
  throw new ReviewEvidenceSetError(message);
}

function expectedDirectories() {
  const directories = new Set();
  for (const relativePath of REQUIRED_REVIEWED_EVIDENCE_PATHS) {
    let directory = path.posix.dirname(relativePath);
    while (directory !== "." && directory !== "evidence") {
      directories.add(directory.toLowerCase());
      directory = path.posix.dirname(directory);
    }
  }
  return directories;
}

async function verifyExactEvidenceTree(bundleReal) {
  const evidenceRoot = path.join(bundleReal, "evidence");
  const evidenceStatus = await lstat(evidenceRoot);
  if (!evidenceStatus.isDirectory() || evidenceStatus.isSymbolicLink()) {
    fail("staged evidence root is not a real directory");
  }
  const evidenceReal = await resolveExactReleasePath(evidenceRoot);
  const rootRelative = path.relative(bundleReal, evidenceReal);
  if (rootRelative !== "evidence") fail("staged evidence root is not exact");

  const expectedFiles = new Map(
    REQUIRED_REVIEWED_EVIDENCE_PATHS.map((item) => [item.toLowerCase(), item]),
  );
  const expectedDirs = new Map([...expectedDirectories()].map((item) => [item, item]));
  const seenFiles = new Set();
  const seenDirs = new Set();

  async function visit(absoluteDirectory, relativeDirectory) {
    const entries = await readdir(absoluteDirectory, { withFileTypes: true });
    for (const entry of entries) {
      const relativePath = `${relativeDirectory}/${entry.name}`;
      if (!/^[A-Za-z0-9._/-]+$/u.test(relativePath)) fail("staged evidence contains an invalid path");
      const windowsPathKey = relativePath.toLowerCase();
      const absolutePath = path.join(absoluteDirectory, entry.name);
      const status = await lstat(absolutePath);
      if (status.isSymbolicLink()) fail("staged evidence contains a reparse path");
      if (entry.isDirectory() && status.isDirectory()) {
        if (expectedDirs.get(windowsPathKey) !== relativePath || seenDirs.has(windowsPathKey)) {
          fail("staged evidence contains an unexpected directory");
        }
        seenDirs.add(windowsPathKey);
        await visit(absolutePath, relativePath);
      } else if (entry.isFile() && status.isFile()) {
        if (expectedFiles.get(windowsPathKey) !== relativePath || seenFiles.has(windowsPathKey)) {
          fail("staged evidence contains an unexpected or duplicate file");
        }
        if (status.nlink !== 1) fail("staged evidence contains a hard-linked file");
        seenFiles.add(windowsPathKey);
      } else {
        fail("staged evidence contains a non-regular entry");
      }
    }
  }

  await visit(evidenceReal, "evidence");
  if (seenFiles.size !== expectedFiles.size || [...expectedFiles.keys()].some((item) => !seenFiles.has(item))) {
    fail("staged evidence file set is incomplete");
  }
  if (seenDirs.size !== expectedDirs.size || [...expectedDirs.keys()].some((item) => !seenDirs.has(item))) {
    fail("staged evidence directory set is incomplete");
  }
}

async function exactFilePath(bundleReal, relativePath) {
  let current = bundleReal;
  for (const segment of relativePath.split("/")) {
    current = path.join(current, segment);
    const status = await lstat(current);
    if (status.isSymbolicLink()) fail("staged evidence path traverses a reparse point");
  }
  const resolved = await resolveExactReleasePath(current);
  const relative = path.relative(bundleReal, resolved);
  if (relative.split(path.sep).join("/") !== relativePath) fail("staged evidence path is not exact");
  return resolved;
}

function samePinnedMetadata(left, right) {
  return left.dev === right.dev &&
    left.ino === right.ino &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

const UINT64_MAX = (1n << 64n) - 1n;

function hasSupportedPinnedIdentity(status) {
  return status.ino !== 0n &&
    status.ino !== UINT64_MAX;
}

async function openPinnedFileRecord(bundleReal, relativePath) {
  const resolved = await exactFilePath(bundleReal, relativePath);
  const handle = await open(resolved, "r");
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || !hasSupportedPinnedIdentity(before)) {
      fail("staged evidence file metadata is invalid");
    }
    const hash = createHash("sha256");
    let bytes = 0n;
    const stream = handle.createReadStream({ autoClose: false });
    for await (const chunk of stream) {
      hash.update(chunk);
      bytes += BigInt(chunk.length);
    }
    const after = await handle.stat({ bigint: true });
    if (!samePinnedMetadata(before, after) || bytes !== after.size) {
      fail("staged evidence changed while it was reviewed");
    }
    return {
      handle,
      metadata: after,
      record: { bytes: bytes.toString(), path: relativePath, sha256: hash.digest("hex") },
      relativePath,
    };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function verifyPinnedFilePath(bundleReal, pinned) {
  const resolved = await exactFilePath(bundleReal, pinned.relativePath);
  const pathHandle = await open(resolved, "r");
  try {
    const [pathHandleStatus, pinnedHandleStatus] = await Promise.all([
      pathHandle.stat({ bigint: true }),
      pinned.handle.stat({ bigint: true }),
    ]);
    if (
      !pathHandleStatus.isFile() ||
      pathHandleStatus.nlink !== 1n ||
      !hasSupportedPinnedIdentity(pathHandleStatus) ||
      !samePinnedMetadata(pinned.metadata, pinnedHandleStatus) ||
      !samePinnedMetadata(pinnedHandleStatus, pathHandleStatus)
    ) {
      fail("staged evidence identity changed while it was reviewed");
    }
  } finally {
    await pathHandle.close();
  }
}

export async function collectReviewedEvidenceSetSubject(bundleRoot) {
  const rootStatus = await lstat(bundleRoot);
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) fail("staging root must be a real directory");
  const bundleReal = await resolveExactReleasePath(bundleRoot);
  await verifyExactEvidenceTree(bundleReal);
  const pinnedFiles = [];
  try {
    for (const relativePath of REQUIRED_REVIEWED_EVIDENCE_PATHS) {
      pinnedFiles.push(await openPinnedFileRecord(bundleReal, relativePath));
    }
    await verifyExactEvidenceTree(bundleReal);
    for (const pinned of pinnedFiles) await verifyPinnedFilePath(bundleReal, pinned);
    return {
      reviewedEvidenceSetSha256: computeReviewedEvidenceSetSha256(
        pinnedFiles.map((pinned) => pinned.record),
      ),
      schema: REVIEW_EVIDENCE_SUBJECT_SCHEMA,
    };
  } finally {
    await Promise.all(pinnedFiles.map((pinned) => pinned.handle.close()));
  }
}

function parseArgs(argv) {
  if (argv.length !== 2 || argv[0] !== "--bundle-root" || !argv[1] || argv[1].startsWith("--")) {
    fail("review-evidence-set accepts exactly --bundle-root");
  }
  return argv[1];
}

async function run() {
  const bundleRoot = parseArgs(process.argv.slice(2));
  const subject = await collectReviewedEvidenceSetSubject(bundleRoot);
  process.stdout.write(`${canonicalEncode(subject)}\n`);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  run().catch((error) => {
    const known = error instanceof ReviewEvidenceSetError || error instanceof ReleaseValidationError;
    const message = known ? "staged evidence set is not exact" : "unexpected review evidence-set failure";
    process.stderr.write(`REVIEW_EVIDENCE_SET_FAILED: ${message}\n`);
    process.exitCode = 1;
  });
}
