import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const root = fileURLToPath(new URL("../", import.meta.url));
const allowedExtensions = new Set([
  ".html",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".ps1",
  ".rs",
  ".toml",
  ".yml",
]);
const ignoredDirectories = new Set([".git", ".vibe-ide-temp", "target", "vendor"]);
const forbidden = [
  { name: "private-key-assignment", expression: /private[_-]?key\s*[:=]\s*["'][0-9a-f]{64}["']/iu },
  { name: "authorization-header", expression: /authorization\s*:\s*bearer\s+[a-z0-9._~-]{12,}/iu },
  { name: "seed-phrase-label", expression: /(?:mnemonic|seed[_ -]?phrase)\s*[:=]\s*["'][a-z]+(?:\s+[a-z]+){11,23}["']/iu },
  { name: "production-secret-marker", expression: /\[(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\]/u },
];

async function* walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else if (entry.isFile() && allowedExtensions.has(extname(entry.name))) yield path;
  }
}

const failures = [];
for await (const path of walk(root)) {
  const text = await readFile(path, "utf8");
  for (const rule of forbidden) {
    if (rule.expression.test(text)) {
      failures.push(`${relative(root, path)}: ${rule.name}`);
    }
  }
}

if (failures.length > 0) {
  process.stderr.write(`Privacy scan failed (${failures.length} finding(s)).\n`);
  for (const failure of failures) process.stderr.write(`- ${failure}\n`);
  process.exitCode = 1;
}
