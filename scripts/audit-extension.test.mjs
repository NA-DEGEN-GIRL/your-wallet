import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { auditExtensionRoot } from "./audit-extension.mjs";

const repositoryExtension = path.resolve("extension");

async function withExtensionCopy(callback) {
  const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "your-wallet-extension-audit-"));
  const extensionRoot = path.join(temporaryRoot, "extension");
  try {
    await cp(repositoryExtension, extensionRoot, { recursive: true, filter: (source) => !source.includes(`${path.sep}tests${path.sep}`) && !source.endsWith(`${path.sep}package.json`) && !source.includes(`${path.sep}native-host${path.sep}`) && !source.includes(`${path.sep}test-dapp${path.sep}`) });
    return await callback(extensionRoot);
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}

test("the repository extension passes the release static audit", async () => {
  const result = await auditExtensionRoot(repositoryExtension);
  assert.deepEqual(result.packagedFiles, [
    "manifest.json",
    "src/background-core.js",
    "src/background.js",
    "src/content-core.js",
    "src/content.js",
    "src/provider-main.js",
    "src/shared.js",
  ]);
  const expectedId = (await readFile(path.join(repositoryExtension, "extension-id.txt"), "utf8")).trim();
  assert.match(expectedId, /^[a-p]{32}$/u);
  assert.equal(result.extensionId, expectedId);
});

async function withManifest(mutate, expected) {
  return withExtensionCopy(async (extensionRoot) => {
    const manifestPath = path.join(extensionRoot, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    mutate(manifest);
    await writeFile(manifestPath, JSON.stringify(manifest), "utf8");
    await assert.rejects(auditExtensionRoot(extensionRoot), expected);
  });
}

test("the manifest top-level keys are exactly the ten spec/05 §2.2 keys", async () => {
  await withManifest((manifest) => {
    delete manifest.key;
  }, /extension manifest members must be exactly/u);
  await withManifest((manifest) => {
    manifest.host_permissions = ["https://*/*"];
  }, /extension manifest members must be exactly/u);
  await withManifest((manifest) => {
    manifest.externally_connectable = { matches: ["https://*/*"] };
  }, /extension manifest members must be exactly/u);
});

test("the extension name is exactly Your Wallet", () => withManifest((manifest) => {
  manifest.name = "Your Wallet (dev)";
}, /extension name must be exactly/u));

test("content-script matches are exactly the three spec/05 §2.2 patterns", async () => {
  await withManifest((manifest) => {
    manifest.content_scripts[0].matches = ["https://*/*"];
  }, /MAIN content script\.matches/u);
  await withManifest((manifest) => {
    manifest.content_scripts[1].matches = ["https://*/*", "http://localhost/*", "http://127.0.0.1/*", "http://*/*"];
  }, /ISOLATED content script\.matches/u);
  await withManifest((manifest) => {
    manifest.content_scripts[1].matches = ["http://localhost/*", "https://*/*", "http://127.0.0.1/*"];
  }, /ISOLATED content script\.matches/u);
});

test("a non-canonical manifest key fails closed", () => withManifest((manifest) => {
  manifest.key = `${manifest.key.slice(0, -4)}====`;
}, /extension key/u));

test("unexpected permissions fail closed", async () => withExtensionCopy(async (extensionRoot) => {
  const manifestPath = path.join(extensionRoot, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.permissions.push("tabs");
  await writeFile(manifestPath, JSON.stringify(manifest), "utf8");
  await assert.rejects(auditExtensionRoot(extensionRoot), /extension permissions/u);
}));

test("dynamic code execution fails closed", async () => withExtensionCopy(async (extensionRoot) => {
  const sourcePath = path.join(extensionRoot, "src", "background-core.js");
  await writeFile(sourcePath, `${await readFile(sourcePath, "utf8")}\neval("unsafe");\n`, "utf8");
  await assert.rejects(auditExtensionRoot(extensionRoot), /forbidden eval/u);
}));

test("remote module references fail closed", async () => withExtensionCopy(async (extensionRoot) => {
  const sourcePath = path.join(extensionRoot, "src", "background.js");
  await writeFile(sourcePath, `${await readFile(sourcePath, "utf8")}\nimport "https://example.invalid/code.js";\n`, "utf8");
  await assert.rejects(auditExtensionRoot(extensionRoot), /remote URL/u);
}));

test("SVG data URIs fail closed", async () => withExtensionCopy(async (extensionRoot) => {
  const sourcePath = path.join(extensionRoot, "src", "provider-main.js");
  await writeFile(
    sourcePath,
    `${await readFile(sourcePath, "utf8")}\nconst unsafeIcon = "data:image/svg+xml;base64,PHN2Zy8+";\n`,
    "utf8"
  );
  await assert.rejects(auditExtensionRoot(extensionRoot), /SVG data URI/u);
}));

test("unreferenced executable source fails closed", async () => withExtensionCopy(async (extensionRoot) => {
  await writeFile(path.join(extensionRoot, "src", "surprise.js"), "export const surprise = true;\n", "utf8");
  await assert.rejects(auditExtensionRoot(extensionRoot), /unreferenced executable source/u);
}));
