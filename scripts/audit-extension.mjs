import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { extensionIdFromKey } from "./extension-key.mjs";
import { decodeUtf8, parseStrictJson } from "./lib/strict-json.mjs";

const MAX_SOURCE_FILE_BYTES = 256 * 1024;
const MAX_PACKAGE_SOURCE_BYTES = 1024 * 1024;
const REQUIRED_PERMISSIONS = ["nativeMessaging", "storage"];
const EXTENSION_NAME = "Your Wallet";
// Exactly the eleven top-level keys of spec/05 §2.2 (including the pinned `key` and the
// compatibility-mode popup `action`, §2.12).
const MANIFEST_KEYS = ["action", "background", "content_scripts", "description", "incognito", "key", "manifest_version", "minimum_chrome_version", "name", "permissions", "version"];
// spec/05 §2.2: both content scripts match exactly these three patterns.
const CONTENT_SCRIPT_MATCHES = ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"];
// spec/05 §2.12: the action popup is one local HTML page plus one local stylesheet.
const POPUP_PAGE = "popup/popup.html";
const POPUP_FILES = ["popup/popup.css", "popup/popup.html"];
const POPUP_STYLESHEET = "popup.css";
// Popup HTML: no inline script/style, no event-handler attributes, no URL schemes or
// protocol-relative references, no embedding or navigation elements (MV3 CSP is the second line).
const FORBIDDEN_POPUP_HTML_PATTERNS = [
  [/\son[a-z]+\s*=/iu, "inline event handler"],
  [/\sstyle\s*=/iu, "inline style attribute"],
  [/<style\b/iu, "inline style element"],
  [/<(?:iframe|frame|frameset|object|embed|applet|portal|base|form|img|video|audio|source|svg|math)\b/iu, "embedding or navigation element"],
  [/<meta\b[^>]*http-equiv/iu, "meta http-equiv"],
  [/[a-z][a-z0-9+.-]*:\/\//iu, "URL with a scheme"],
  [/\b(?:javascript|data|blob|filesystem|chrome|chrome-extension)\s*:/iu, "URL scheme"],
  [/(?:src|href|action|srcset|poster)\s*=\s*["']?\s*\/\//iu, "protocol-relative URL"],
];
const FORBIDDEN_POPUP_CSS_PATTERNS = [
  [/\burl\s*\(/iu, "url() reference"],
  [/@import\b/iu, "@import"],
  [/\bexpression\s*\(/iu, "CSS expression"],
  [/[a-z][a-z0-9+.-]*:\/\//iu, "URL with a scheme"],
];
const FORBIDDEN_SOURCE_PATTERNS = [
  [/\beval\s*\(/u, "eval"],
  [/\bnew\s+Function\b/u, "Function constructor"],
  [/\bFunction\s*\(/u, "Function constructor"],
  [/\bimport\s*\(/u, "dynamic import"],
  [/\bWebAssembly\b/u, "WebAssembly"],
  [/\bdocument\s*\.\s*write\b/u, "document.write"],
  [/\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b/u, "HTML injection sink"],
  [/\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b/u, "direct network API"],
  [/\bnavigator\s*\.\s*sendBeacon\b/u, "sendBeacon"],
  [/\bchrome\s*\.\s*scripting\s*\.\s*executeScript\b/u, "runtime script injection"],
  [/\bset(?:Timeout|Interval)\s*\(\s*["']/u, "string-based timer execution"],
  [/\bdata:image\/svg\+xml\b/iu, "SVG data URI"],
  [/https?:\/\//iu, "remote URL in executable source"],
];

export class ExtensionAuditError extends Error {
  constructor(message) {
    super(message);
    this.name = "ExtensionAuditError";
  }
}

function fail(message) {
  throw new ExtensionAuditError(message);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
    fail(`${label} members must be exactly: ${sortedExpected.join(", ")}`);
  }
}

function exactArray(value, expected, label) {
  if (!Array.isArray(value) || value.length !== expected.length || value.some((item, index) => item !== expected[index])) {
    fail(`${label} must be exactly ${JSON.stringify(expected)}`);
  }
}

function normalizePackagePath(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._/-]+$/u.test(value) || value.includes("\\") || value.startsWith("/")) fail(`${label} is not a safe package path`);
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) fail(`${label} contains a forbidden path segment`);
  return value;
}

async function readRegularFile(rootReal, relativePath) {
  const normalized = normalizePackagePath(relativePath, "extension file path");
  let current = rootReal;
  for (const segment of normalized.split("/")) {
    current = path.join(current, segment);
    const status = await lstat(current);
    if (status.isSymbolicLink()) fail(`extension package source traverses a symbolic link: ${normalized}`);
  }
  const finalPath = await realpath(current);
  const relative = path.relative(rootReal, finalPath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) fail(`extension package source escapes its root: ${normalized}`);
  const status = await lstat(finalPath);
  if (!status.isFile()) fail(`extension package source is not a regular file: ${normalized}`);
  if (status.size > MAX_SOURCE_FILE_BYTES) fail(`extension package source exceeds 256 KiB: ${normalized}`);
  return readFile(finalPath);
}

async function listSourceFiles(rootReal) {
  const sourceRoot = path.join(rootReal, "src");
  const sourceStatus = await lstat(sourceRoot);
  if (!sourceStatus.isDirectory() || sourceStatus.isSymbolicLink()) fail("extension/src must be a real directory");
  const entries = await readdir(sourceRoot, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile() || entry.isSymbolicLink() || !/^[A-Za-z0-9._-]+\.js$/u.test(entry.name)) {
      fail(`extension/src contains a forbidden entry: ${entry.name}`);
    }
    files.push(`src/${entry.name}`);
  }
  return files.sort();
}

function validateManifest(manifest) {
  exactKeys(manifest, MANIFEST_KEYS, "extension manifest");
  if (manifest.manifest_version !== 3) fail("extension must use Manifest V3");
  if (manifest.incognito !== "not_allowed") fail("extension incognito mode must be disabled");
  if (manifest.minimum_chrome_version !== "120") fail("minimum Chrome version must remain explicitly pinned to 120");
  if (manifest.name !== EXTENSION_NAME) fail(`extension name must be exactly "${EXTENSION_NAME}"`);
  if (typeof manifest.description !== "string" || manifest.description.length < 1 || manifest.description.length > 132) fail("extension description is invalid");
  if (typeof manifest.version !== "string" || !/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,3}$/u.test(manifest.version)) fail("extension version is invalid");
  exactArray(manifest.permissions, REQUIRED_PERMISSIONS, "extension permissions");

  exactKeys(manifest.background, ["service_worker", "type"], "extension background");
  if (manifest.background.service_worker !== "src/background.js" || manifest.background.type !== "module") fail("extension background worker contract changed");

  exactKeys(manifest.action, ["default_popup", "default_title"], "extension action");
  if (manifest.action.default_popup !== POPUP_PAGE || manifest.action.default_title !== EXTENSION_NAME) fail("extension action popup contract changed");

  if (!Array.isArray(manifest.content_scripts) || manifest.content_scripts.length !== 2) fail("extension must have the two reviewed content-script declarations");
  const [mainWorld, isolatedWorld] = manifest.content_scripts;
  for (const [entry, label] of [[mainWorld, "MAIN content script"], [isolatedWorld, "ISOLATED content script"]]) {
    exactKeys(entry, ["all_frames", "js", "matches", "run_at", "world"], label);
    exactArray(entry.matches, CONTENT_SCRIPT_MATCHES, `${label}.matches`);
    if (entry.all_frames !== false || entry.run_at !== "document_start") fail(`${label} lifetime contract changed`);
  }
  if (mainWorld.world !== "MAIN") fail("the first content script must run in MAIN world");
  exactArray(mainWorld.js, ["src/provider-main.js"], "MAIN content scripts");
  if (isolatedWorld.world !== "ISOLATED") fail("the second content script must run in ISOLATED world");
  exactArray(isolatedWorld.js, ["src/shared.js", "src/content-core.js", "src/content.js"], "ISOLATED content scripts");
  return manifestExtensionId(manifest.key);
}

// Chrome extension ID: SHA-256 of the base64-decoded DER key, first 16 bytes as hex mapped 0-f -> a-p.
function manifestExtensionId(key) {
  if (typeof key !== "string" || key.length === 0) fail("extension key must be a base64 SubjectPublicKeyInfo string");
  try {
    return extensionIdFromKey(key);
  } catch {
    fail("extension key is not canonical base64 DER");
  }
}

async function listPopupFiles(rootReal) {
  const popupRoot = path.join(rootReal, "popup");
  const popupStatus = await lstat(popupRoot);
  if (!popupStatus.isDirectory() || popupStatus.isSymbolicLink()) fail("extension/popup must be a real directory");
  const entries = await readdir(popupRoot, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile() || entry.isSymbolicLink()) fail(`extension/popup contains a forbidden entry: ${entry.name}`);
    files.push(`popup/${entry.name}`);
  }
  files.sort();
  exactArray(files, POPUP_FILES, "extension/popup files");
  return files;
}

// Returns the package paths (`src/*.js`) of the popup's module scripts.
function auditPopupHtml(source) {
  for (const [pattern, description] of FORBIDDEN_POPUP_HTML_PATTERNS) {
    if (pattern.test(source)) fail(`${POPUP_PAGE} contains forbidden ${description}`);
  }
  const scripts = [];
  const scriptPattern = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/giu;
  for (const match of source.matchAll(scriptPattern)) {
    const attributes = /^\s+type="module"\s+src="\.\.\/(src\/[A-Za-z0-9._-]+\.js)"\s*$/u.exec(match[1]);
    if (attributes === null) fail(`${POPUP_PAGE} script must be exactly type="module" src="../src/<name>.js"`);
    if (match[2].trim() !== "") fail(`${POPUP_PAGE} contains an inline script`);
    scripts.push(normalizePackagePath(attributes[1], `${POPUP_PAGE} script`));
  }
  if ((source.match(/<script\b/giu) ?? []).length !== scripts.length) fail(`${POPUP_PAGE} contains a malformed script element`);
  if (scripts.length === 0) fail(`${POPUP_PAGE} must load its module script`);
  const links = [...source.matchAll(/<link\b([^>]*)>/giu)];
  for (const link of links) {
    if (!/^\s+rel="stylesheet"\s+href="([A-Za-z0-9._-]+\.css)"\s*$/u.test(link[1]) || !link[1].includes(`href="${POPUP_STYLESHEET}"`)) {
      fail(`${POPUP_PAGE} may link only its local stylesheet ${POPUP_STYLESHEET}`);
    }
  }
  if (links.length !== 1) fail(`${POPUP_PAGE} must link exactly one local stylesheet`);
  return scripts;
}

function auditPopupCss(source) {
  for (const [pattern, description] of FORBIDDEN_POPUP_CSS_PATTERNS) {
    if (pattern.test(source)) fail(`popup/${POPUP_STYLESHEET} contains forbidden ${description}`);
  }
}

function staticImports(source) {
  const imports = [];
  const pattern = /\bimport\s+(?:[^"']+?\s+from\s+)?["']([^"']+)["']/gu;
  for (const match of source.matchAll(pattern)) imports.push(match[1]);
  return imports;
}

export async function auditExtensionRoot(extensionRoot) {
  const rootStatus = await lstat(extensionRoot);
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) fail("extension root must be a real directory");
  const rootReal = await realpath(extensionRoot);
  const manifestBytes = await readRegularFile(rootReal, "manifest.json");
  let manifest;
  try {
    manifest = parseStrictJson(decodeUtf8(manifestBytes, "extension manifest"));
  } catch (error) {
    fail(`extension manifest is not strict JSON: ${error instanceof Error ? error.message : "parse failure"}`);
  }
  const extensionId = validateManifest(manifest);

  const popupFiles = await listPopupFiles(rootReal);
  const popupHtmlBytes = await readRegularFile(rootReal, POPUP_PAGE);
  const popupScripts = auditPopupHtml(decodeUtf8(popupHtmlBytes, POPUP_PAGE));
  const popupCssBytes = await readRegularFile(rootReal, `popup/${POPUP_STYLESHEET}`);
  auditPopupCss(decodeUtf8(popupCssBytes, `popup/${POPUP_STYLESHEET}`));

  const sourceFiles = await listSourceFiles(rootReal);
  const expectedFiles = new Set([
    manifest.background.service_worker,
    ...manifest.content_scripts.flatMap((entry) => entry.js),
    ...popupScripts,
  ]);
  let totalBytes = manifestBytes.length + popupHtmlBytes.length + popupCssBytes.length;
  for (const relativePath of sourceFiles) {
    const bytes = await readRegularFile(rootReal, relativePath);
    totalBytes += bytes.length;
    if (totalBytes > MAX_PACKAGE_SOURCE_BYTES) fail("extension package source exceeds 1 MiB");
    const source = decodeUtf8(bytes, relativePath);
    for (const [pattern, description] of FORBIDDEN_SOURCE_PATTERNS) {
      if (pattern.test(source)) fail(`${relativePath} contains forbidden ${description}`);
    }
    for (const imported of staticImports(source)) {
      if (!imported.startsWith("./") || imported.includes("?") || imported.includes("#")) fail(`${relativePath} imports a non-local module`);
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(relativePath), imported));
      normalizePackagePath(resolved, `${relativePath} import`);
      expectedFiles.add(resolved);
    }
  }
  for (const expected of expectedFiles) {
    if (!sourceFiles.includes(expected)) fail(`reviewed extension entry/import is missing: ${expected}`);
  }
  for (const sourceFile of sourceFiles) {
    if (!expectedFiles.has(sourceFile)) fail(`unreferenced executable source is forbidden from the package: ${sourceFile}`);
  }

  return { packagedFiles: ["manifest.json", ...popupFiles, ...sourceFiles], extensionId };
}

function parseArguments(argv) {
  const [command, ...rest] = argv;
  const args = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    if (!rest[index]?.startsWith("--") || rest[index + 1] === undefined) fail("arguments must be --name value pairs");
    if (args.has(rest[index])) fail(`duplicate argument: ${rest[index]}`);
    args.set(rest[index], rest[index + 1]);
  }
  return { args, command };
}

async function runCli() {
  const { args, command } = parseArguments(process.argv.slice(2));
  if (command !== "check") fail("usage: audit-extension.mjs check --extension-root PATH");
  const root = args.get("--extension-root");
  if (!root) fail("--extension-root is required");
  if (args.size !== 1) fail("check accepts only --extension-root");
  const { extensionId } = await auditExtensionRoot(root);
  process.stdout.write(`EXTENSION_STATIC_AUDIT_PASS id=${extensionId}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli().catch((error) => {
    const message = error instanceof ExtensionAuditError ? error.message : "unexpected extension audit failure";
    process.stderr.write(`EXTENSION_AUDIT_FAILED: ${message}\n`);
    process.exitCode = 1;
  });
}
