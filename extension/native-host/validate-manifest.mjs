// Native messaging host manifest validator (spec/05 §9.3).
// Usage: node validate-manifest.mjs <file> [--expect-id <id>]  ->  "OK <id>" (exit 0) | "INVALID" (exit 1)
import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const HOST_NAME = "com.your_wallet.native";
const HOST_EXECUTABLE = "yw-host.exe";
const EXTENSION_ID = /^[a-p]{32}$/u;
const EXTENSION_ORIGIN = /^chrome-extension:\/\/([a-p]{32})\/$/u;
const PLACEHOLDER = /__[A-Z0-9_]+__/u;
const WINDOWS_COMPONENT_FORBIDDEN = /[<>:"/\\|?*\u0000-\u001f]/u;
// Chrome may launch the host through cmd.exe; reject its metacharacters (spec/05 §9.3, §11-5).
const CMD_METACHARACTERS = /[%&^!]/u;
const INVALID = Object.freeze({ valid: false, extensionId: null });

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, expected) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
}

export function validateNativeManifest(value) {
  if (!hasExactKeys(value, ["name", "description", "path", "type", "allowed_origins"])
    || value.name !== HOST_NAME
    || typeof value.description !== "string"
    || value.description.length === 0
    || value.description.length > 128
    || value.type !== "stdio"
    || typeof value.path !== "string"
    || PLACEHOLDER.test(value.path)
    || CMD_METACHARACTERS.test(value.path)
    || !validAbsoluteWindowsExePath(value.path)
    || !Array.isArray(value.allowed_origins)
    || value.allowed_origins.length !== 1
    || typeof value.allowed_origins[0] !== "string"
    || PLACEHOLDER.test(value.allowed_origins[0])) {
    return INVALID;
  }
  const match = EXTENSION_ORIGIN.exec(value.allowed_origins[0]);
  if (match === null) {
    return INVALID;
  }
  return Object.freeze({ valid: true, extensionId: match[1] });
}

function validAbsoluteWindowsExePath(value) {
  if (value.length > 32_767 || !/^[A-Za-z]:\\/u.test(value)) {
    return false;
  }
  const components = value.slice(3).split("\\");
  if (components.length === 0 || components.some((component) => (
    component.length === 0
      || component === "."
      || component === ".."
      || component.endsWith(" ")
      || component.endsWith(".")
      || WINDOWS_COMPONENT_FORBIDDEN.test(component)
  ))) {
    return false;
  }
  return components.at(-1).toLowerCase() === HOST_EXECUTABLE;
}

// Reads the file as strict UTF-8 without BOM and validates it. Returns the same shape as validateNativeManifest.
export function validateNativeManifestFile(filePath, expectedId = null) {
  let bytes;
  try {
    bytes = readFileSync(filePath);
  } catch (_error) {
    return INVALID;
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return INVALID;
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (_error) {
    return INVALID;
  }
  const result = validateNativeManifest(value);
  if (!result.valid || (expectedId !== null && result.extensionId !== expectedId)) {
    return INVALID;
  }
  return result;
}

function runCli(argv) {
  const [file, flag, expectedId, ...rest] = argv;
  const usage = file === undefined
    || rest.length > 0
    || (flag !== undefined && (flag !== "--expect-id" || expectedId === undefined || !EXTENSION_ID.test(expectedId)));
  if (usage) {
    process.stderr.write("usage: node validate-manifest.mjs <file> [--expect-id <32 a-p id>]\n");
    process.stdout.write("INVALID\n");
    return 1;
  }
  const result = validateNativeManifestFile(file, flag === undefined ? null : expectedId);
  if (!result.valid) {
    process.stdout.write("INVALID\n");
    return 1;
  }
  process.stdout.write(`OK ${result.extensionId}\n`);
  return 0;
}

export const NATIVE_HOST_NAME = HOST_NAME;

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  process.exitCode = runCli(process.argv.slice(2));
}
