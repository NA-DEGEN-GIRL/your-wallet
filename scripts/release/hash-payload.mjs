import { lstat, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { canonicalEncode, computeArtifactSetSha256, sha256Hex } from "./release-manifest.mjs";

const ROLE_FILES = Object.freeze({
  "approval-ui-exe": "approval-ui.exe",
  "broker-exe": "broker.exe",
  "dashboard-exe": "dashboard.exe",
  "extension-package": "extension-package.zip",
  installer: "your-wallet-canary.msi",
  "key-agent-exe": "key-agent.exe",
  "native-host-exe": "native-host.exe",
  "secret-input-ui-exe": "secret-input-ui.exe",
});

function fail(message) {
  throw new Error(message);
}

async function run() {
  const argv = process.argv.slice(2);
  if (argv.length !== 4 || argv[0] !== "--payload-root" || argv[2] !== "--output") fail("usage: hash-payload.mjs --payload-root PATH --output PATH");
  const payloadRoot = argv[1];
  const output = argv[3];
  const rootStatus = await lstat(payloadRoot);
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) fail("payload root must be a real directory");
  const rootReal = await realpath(payloadRoot);
  const actual = (await readdir(rootReal)).sort();
  const expected = Object.values(ROLE_FILES).sort();
  if (canonicalEncode(actual) !== canonicalEncode(expected)) fail("payload root must contain exactly the reviewed artifact filenames");

  const artifacts = [];
  for (const [role, fileName] of Object.entries(ROLE_FILES).sort(([left], [right]) => left.localeCompare(right, "en"))) {
    const filePath = path.join(rootReal, fileName);
    const status = await lstat(filePath);
    if (!status.isFile() || status.isSymbolicLink()) fail(`payload is not a regular file: ${fileName}`);
    const bytes = await readFile(filePath);
    artifacts.push({ file: { bytes: status.size.toString(), path: `payload/${fileName}`, sha256: sha256Hex(bytes) }, role });
  }
  const artifactSetSha256 = computeArtifactSetSha256(artifacts);
  const report = { artifactSetSha256, artifacts, schema: "your-wallet-payload-hashes-v1" };
  await writeFile(output, `${canonicalEncode(report)}\n`, { encoding: "utf8", flag: "wx" });
  process.stdout.write(`${artifactSetSha256}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch(() => {
    process.stderr.write("PAYLOAD_HASHING_FAILED\n");
    process.exitCode = 1;
  });
}
