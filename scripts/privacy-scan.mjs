import { execFile as execFileCallback } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFile = promisify(execFileCallback);
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
const TEST_VECTOR_PATH = /^(?:crates\/[^/]+\/tests\/|crates\/[^/]+\/src\/(?:[^/]+\/)*tests\.rs$|tools\/[^/]+\/tests\/|extension\/tests\/|scripts\/[^/]+\.test\.mjs$|spec\/)/u;
const BIP39_WORDS = new URL("../crates/yw-core/src/bip39/english.txt", import.meta.url); // 스캐너 자신의 저장소에서 읽는다
const forbidden = [
  { name: "private-key-assignment", vectorsAllowed: true, expression: /private[_-]?key\s*[:=]\s*["'][0-9a-f]{64}["']/iu },
  { name: "authorization-header", expression: /authorization\s*:\s*bearer\s+[a-z0-9._~-]{12,}/iu },
  { name: "seed-phrase-label", vectorsAllowed: true, expression: /(?:mnemonic|seed[_ -]?phrase)\s*[:=]\s*["'][a-z]+(?:\s+[a-z]+){11,23}["']/iu },
  { name: "production-secret-marker", expression: /\[(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\]/u },
  { name: "alchemy-key-url", expression: /\.g\.alchemy\.com\/v2\/[A-Za-z0-9_-]{16,}/u },
  { name: "quicknode-url", expression: /\.quiknode\.pro\/[A-Za-z0-9_-]{16,}/u },   // D13 템플릿: https://<이름>.<서브도메인>.quiknode.pro/<토큰>/
  { name: "llm-api-key", expression: /\bsk-[A-Za-z0-9_-]{20,}/u },
  { name: "labeled-private-key-hex", vectorsAllowed: true,
    expression: /(?:priv(?:ate)?|secret|signing)[_ -]?key[^\n]{0,80}?(?<![0-9A-Fa-f])(?:0x)?[0-9A-Fa-f]{64}(?![0-9A-Fa-f])/iu },
  { name: "bip39-word-sequence", vectorsAllowed: true, detect: (text, words) => {
      let run = 0, last = -1;   // 공백·따옴표·쉼표·대괄호로만 이어진 BIP39 단어 12개 이상
      for (const m of text.matchAll(/[a-z]+/gu)) {
        const joined = last >= 0 && /^[\s"',[\]]+$/u.test(text.slice(last, m.index));
        run = words.has(m[0]) ? (joined ? run + 1 : 1) : 0;
        last = m.index + m[0].length;
        if (run >= 12) return true;
      }
      return false; } },
];

const infrastructureDiagnostic =
  "Privacy scan failed: repository inventory or source inspection was unavailable.\n";

class PrivacyScanInfrastructureError extends Error {
  constructor() {
    super("Privacy scan infrastructure failure.");
    this.name = "PrivacyScanInfrastructureError";
  }
}

function infrastructureFailure() {
  return new PrivacyScanInfrastructureError();
}

async function gitSourceInventory(repositoryRoot) {
  let stdout;
  try {
    ({ stdout } = await execFile(
      "git",
      [
        "-C",
        repositoryRoot,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "--deduplicate",
        "-z",
      ],
      {
        encoding: "buffer",
        maxBuffer: 16 * 1024 * 1024,
        timeout: 30_000,
        windowsHide: true,
      },
    ));
  } catch {
    throw infrastructureFailure();
  }

  if (!Buffer.isBuffer(stdout)) throw infrastructureFailure();
  if (stdout.length === 0) return [];
  if (stdout.at(-1) !== 0) throw infrastructureFailure();

  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
  } catch {
    throw infrastructureFailure();
  }

  const paths = decoded.slice(0, -1).split("\0");
  if (paths.some((path) => path.length === 0)) throw infrastructureFailure();
  return paths;
}

function resolveCandidate(repositoryRoot, inventoryPath) {
  if (isAbsolute(inventoryPath)) throw infrastructureFailure();

  const candidate = resolve(repositoryRoot, inventoryPath);
  const repositoryRelativePath = relative(repositoryRoot, candidate);
  if (
    repositoryRelativePath.length === 0 ||
    repositoryRelativePath === ".." ||
    repositoryRelativePath.startsWith(`..${sep}`) ||
    isAbsolute(repositoryRelativePath)
  ) {
    throw infrastructureFailure();
  }
  return candidate;
}

function sameFile(left, right) {
  return (
    left.ino === right.ino &&
    (process.platform === "win32" || left.dev === right.dev)
  );
}

async function readCandidate(candidate) {
  let before;
  try {
    before = await lstat(candidate, { bigint: true });
  } catch (error) {
    // A cached path can legitimately be absent after an unstaged deletion.
    if (error?.code === "ENOENT") return null;
    throw infrastructureFailure();
  }

  if (before.isSymbolicLink()) throw infrastructureFailure();
  if (!before.isFile()) return null;

  let handle;
  try {
    handle = await open(
      candidate,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
  } catch {
    throw infrastructureFailure();
  }

  let text;
  let failure;
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameFile(before, opened)) {
      throw infrastructureFailure();
    }

    text = await handle.readFile({ encoding: "utf8" });

    const after = await lstat(candidate, { bigint: true });
    if (
      after.isSymbolicLink() ||
      !after.isFile() ||
      !sameFile(opened, after)
    ) {
      throw infrastructureFailure();
    }
  } catch {
    failure = infrastructureFailure();
  }

  try {
    await handle.close();
  } catch {
    failure = infrastructureFailure();
  }

  if (failure !== undefined) throw failure;
  return text;
}

async function loadBip39Words() {
  let text;
  try {
    text = await readFile(BIP39_WORDS, { encoding: "utf8" });
  } catch {
    throw infrastructureFailure();
  }
  const list = (text.endsWith("\n") ? text.slice(0, -1) : text).split("\n");
  const words = new Set(list);
  if (words.size !== 2048 || list.length !== 2048 || list.some((word) => !/^[a-z]+$/u.test(word))) {
    throw infrastructureFailure();
  }
  return words;
}

function ruleMatches(rule, text, words) {
  return rule.detect === undefined ? rule.expression.test(text) : rule.detect(text, words);
}

export async function scanRepository(repositoryRoot) {
  const findings = [];
  const words = await loadBip39Words();
  const inventory = await gitSourceInventory(repositoryRoot);

  for (const inventoryPath of inventory) {
    if (!allowedExtensions.has(extname(inventoryPath))) continue;

    const candidate = resolveCandidate(repositoryRoot, inventoryPath);
    const text = await readCandidate(candidate);
    if (text === null) continue;

    const vectorPath = TEST_VECTOR_PATH.test(inventoryPath);
    for (const rule of forbidden) {
      if (rule.vectorsAllowed === true && vectorPath) continue;
      if (ruleMatches(rule, text, words)) findings.push({ rule: rule.name });
    }
  }

  return findings;
}

export function privacyFailureReport(findings) {
  const counts = new Map(forbidden.map((rule) => [rule.name, 0]));
  for (const finding of findings) {
    if (!counts.has(finding.rule)) throw infrastructureFailure();
    counts.set(finding.rule, counts.get(finding.rule) + 1);
  }

  const lines = [`Privacy scan failed (${findings.length} finding(s)).`];
  for (const rule of forbidden) {
    const count = counts.get(rule.name);
    if (count > 0) lines.push(`- ${rule.name}: ${count}`);
  }
  return `${lines.join("\n")}\n`;
}

export async function runPrivacyScan(
  repositoryRoot,
  writeError = (message) => process.stderr.write(message),
) {
  try {
    const findings = await scanRepository(repositoryRoot);
    if (findings.length === 0) return 0;
    writeError(privacyFailureReport(findings));
    return 1;
  } catch {
    writeError(infrastructureDiagnostic);
    return 1;
  }
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  resolve(invokedPath) === resolve(fileURLToPath(import.meta.url))
) {
  process.exitCode = await runPrivacyScan(root);
}
