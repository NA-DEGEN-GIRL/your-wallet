// scripts/extension-key.mjs — Node 22+, zero dependencies (spec/05 §2.3).
// Generates the manifest `key` (public RSA-2048 SPKI, base64) and extension/extension-id.txt.
// The private key is never stored: no CRX is built, so nothing needs it.
// Usage: node scripts/extension-key.mjs generate [--force] | id | check
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const MANIFEST = new URL("../extension/manifest.json", import.meta.url);
const ID_FILE = new URL("../extension/extension-id.txt", import.meta.url);

export function extensionIdFromKey(base64Key) {
  if (typeof base64Key !== "string") throw new Error("invalid key");
  const der = Buffer.from(base64Key, "base64");
  if (der.length < 64 || der.toString("base64") !== base64Key) throw new Error("invalid key");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return Array.from(hex, (c) => String.fromCharCode(0x61 + Number.parseInt(c, 16))).join("");
}

function main(command, flag) {
  const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
  if (command === "generate") {
    if (Object.hasOwn(manifest, "key") && flag !== "--force") throw new Error("manifest already has key");
    const { publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "der" } });
    const key = publicKey.toString("base64");
    const out = {};
    for (const [k, v] of Object.entries(manifest)) {
      if (k === "key") continue;
      out[k] = v;
      if (k === "incognito") out.key = key;
    }
    writeFileSync(MANIFEST, `${JSON.stringify(out, null, 2)}\n`);
    writeFileSync(ID_FILE, `${extensionIdFromKey(key)}\n`);
  } else if (command === "id") {
    process.stdout.write(`${extensionIdFromKey(manifest.key)}\n`);
  } else if (command === "check") {
    const expected = readFileSync(ID_FILE, "utf8").trim();
    if (!/^[a-p]{32}$/u.test(expected) || extensionIdFromKey(manifest.key) !== expected) throw new Error("id mismatch");
  } else throw new Error("usage: extension-key.mjs generate [--force] | id | check");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(process.argv[2], process.argv[3]); } catch (e) { console.error(String(e.message)); process.exit(1); }
}
