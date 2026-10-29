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
  ".cmd",
  ".css",
  ".html",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".ps1",
  ".rs",
  ".template",
  ".toml",
  ".txt",
  ".yml",
]);
const TEST_VECTOR_PATH = /^(?:crates\/[^/]+\/tests\/|crates\/[^/]+\/src\/(?:[^/]+\/)*tests\.rs$|tools\/[^/]+\/tests\/|extension\/tests\/|scripts\/[^/]+\.test\.mjs$|spec\/)/u;
const BIP39_WORDS = new URL("../crates/yw-core/src/bip39/english.txt", import.meta.url); // 스캐너 자신의 저장소에서 읽는다

// --- 개인 정보 규칙(이메일·Windows 프로필 경로·RPC 키 쿼리)의 허용 목록 ---
// 규칙 전체를 파일 단위로 끄지 않는다. 각 항목은 (경로, 그 경로에서 잡힌 정확한 값) 한 쌍이다.
// 값은 이 파일 자체가 걸리지 않도록 조각(local/domain, 이름 세그먼트)으로만 적는다.

// 이메일: 실제 사람이 받을 수 없는 주소만 전역 허용.
//  - 커밋 트레일러 `Co-Authored-By: ... <noreply at anthropic.com>`의 그 주소 하나(정확히 일치).
//  - RFC 2606 예약 도메인 example.com·example.org(와 그 서브도메인), 예약 TLD `.example`.
//    (example.net은 저장소에 필요한 곳이 없어 넣지 않았다.)
const EMAIL_ALLOWED_EXACT = new Set([["noreply", "anthropic.com"].join("@")]);
const EMAIL_RESERVED_DOMAIN = /(?:^|\.)example\.(?:com|org)$|\.example$/u;
const EMAIL_FIXTURES = [
  // URL userinfo 거부 테스트(`https://u@<실제 호스트>/api`): 사람 주소가 아니라 userinfo 형태 픽스처
  { path: "crates/yw-app/tests/settings.rs", local: "u", domain: "mempool.space" },
  { path: "spec/04-app-ui.md", local: "u", domain: "mempool.space" },
];

// Windows 프로필 경로 `<드라이브>:\Users\<이름>` (\, \\, / 모두). `<이름>` 세그먼트 허용 목록:
//  - `<...>` 꺾쇠 자리표시자(예: <user>, <name>, <사용자>) — `<` `>`는 Windows 파일 이름에 쓸 수 없어 실명일 수 없다.
//  - 환경 변수 자리표시자: %USERNAME%, $env:USERNAME, ${env:USERNAME}
//  - 포맷 자리표시자: {user}, {name}, {username}
//  - Windows 기본 프로필: Public, Default, Default User, All Users
//  (`%USERPROFILE%\...`·`$env:USERPROFILE\...`는 `X:\Users\` 리터럴이 없어 애초에 걸리지 않는다.)
//  한 글자 이름 같은 그 밖의 값은 자리표시자로 보지 않는다 — 픽스처는 아래에 파일별로 적는다.
const PROFILE_PLACEHOLDERS = new Set([
  "%username%", "$env:username", "${env:username}",
  "{user}", "{name}", "{username}",
  "public", "default", "default user", "all users",
]);
const PROFILE_FIXTURES = [
  { path: "crates/yw-win/src/process.rs", name: "x" },                  // file_name_wide 단위 테스트의 가짜 경로
  { path: "extension/tests/native-contract.test.mjs", name: "Test User" }, // 매니페스트 path 픽스처(공백 포함)
  { path: "extension/tests/native-contract.test.mjs", name: "Test" },   // 매니페스트 path 픽스처
  { path: "scripts/install.test.mjs", name: "Test" },                   // 매니페스트 path 픽스처
  { path: "scripts/install.test.mjs", name: "\uD64D \uAE38\uB3D9" },    // 공백·한글 경로 픽스처("홍 길동")
  { path: "spec/01-repo-build.md", name: "=~" },                        // --remap-path-prefix 값(Users 접두사 + "=~") 설명
];

// 쿼리 값 `api-key=`/`apikey=`/`api_key=` 자리표시자: 빈 값, <...>, ${...}, {...}, YOUR_.../YOUR-..., xxx...
const API_KEY_PLACEHOLDER = /^(?:|<[^<>]*>|\$\{[^{}]*\}|\{[^{}]*\}|your[_-].*|x{3,})$/iu;

function emailAllowed(local, domain, path) {
  const lowerDomain = domain.toLowerCase();
  if (EMAIL_ALLOWED_EXACT.has(`${local.toLowerCase()}@${lowerDomain}`)) return true;
  if (EMAIL_RESERVED_DOMAIN.test(lowerDomain)) return true;
  return EMAIL_FIXTURES.some((entry) => entry.path === path && entry.local === local && entry.domain === domain);
}

function profileNameAllowed(name, path) {
  if (/^<[^<>]*>$/u.test(name)) return true;
  if (PROFILE_PLACEHOLDERS.has(name.toLowerCase())) return true;
  return PROFILE_FIXTURES.some((entry) => entry.path === path && entry.name === name);
}

// 파일 단위 예외(규칙 이름 → 경로): 그 파일이 곧 해당 데이터의 원본인 경우만.
const RULE_EXEMPT_PATHS = new Map([
  ["bip39-word-sequence", new Set(["crates/yw-core/src/bip39/english.txt"])], // BIP39 단어 목록 원본
]);

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
  // Infura 프로젝트 ID: 호스트와 무관하게 `/v3/` 뒤 정확히 32 hex(앞뒤 경계 확인)
  { name: "infura-project-id-url", expression: /\/v3\/[0-9a-fA-F]{32}(?![0-9A-Za-z_-])/u },
  { name: "api-key-query-value", detect: (text) => {
      for (const m of text.matchAll(/(?<![A-Za-z0-9])api[-_]?key=([^\s&#"'`),;\]]*)/giu)) {
        if (!API_KEY_PLACEHOLDER.test(m[1])) return true;
      }
      return false; } },
  { name: "email-address", detect: (text, _words, path) => {
      const expression =
        /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,})(?![A-Za-z0-9-])/gu;
      for (const m of text.matchAll(expression)) {
        if (!emailAllowed(m[1], m[2], path)) return true;
      }
      return false; } },
  { name: "windows-profile-path", detect: (text, _words, path) => {
      // 구분자: \, \\(소스 문자열 이스케이프), \\\\, /. 이름은 다음 구분자·따옴표·줄바꿈 전까지(공백 허용).
      const expression =
        /(?<![A-Za-z])[A-Za-z]:(?:\\{1,4}|\/)users(?:\\{1,4}|\/)(<[^<>\r\n\\/]*>|\$\{?env:[A-Za-z_]+\}?|[^\\/\r\n"'`|?*:<>]+)/giu;
      for (const m of text.matchAll(expression)) {
        const name = m[1].replace(/[\s.,;)\]]+$/u, "");
        if (name.length === 0) continue;
        if (!profileNameAllowed(name, path)) return true;
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

function ruleMatches(rule, text, words, path) {
  if (RULE_EXEMPT_PATHS.get(rule.name)?.has(path) === true) return false;
  return rule.detect === undefined ? rule.expression.test(text) : rule.detect(text, words, path);
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
      if (ruleMatches(rule, text, words, inventoryPath)) findings.push({ rule: rule.name });
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
