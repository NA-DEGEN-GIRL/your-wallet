const HOST_NAME = "com.your_wallet.native";
const EXTENSION_ORIGIN = /^chrome-extension:\/\/([a-p]{32})\/$/u;
const PLACEHOLDER = /__[A-Z0-9_]+__/u;
const WINDOWS_COMPONENT_FORBIDDEN = /[<>:"/\\|?*\u0000-\u001f]/u;

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
  return keys.length === expected.length
    && keys.every((key) => expected.includes(key));
}

export function validateReleaseNativeManifest(value) {
  if (!hasExactKeys(value, ["name", "description", "path", "type", "allowed_origins"])
    || value.name !== HOST_NAME
    || typeof value.description !== "string"
    || value.description.length === 0
    || value.description.length > 128
    || value.type !== "stdio"
    || typeof value.path !== "string"
    || PLACEHOLDER.test(value.path)
    || !validAbsoluteWindowsExePath(value.path)
    || !Array.isArray(value.allowed_origins)
    || value.allowed_origins.length !== 1
    || typeof value.allowed_origins[0] !== "string"
    || PLACEHOLDER.test(value.allowed_origins[0])) {
    return Object.freeze({ valid: false, extensionId: null });
  }
  const match = EXTENSION_ORIGIN.exec(value.allowed_origins[0]);
  if (match === null) {
    return Object.freeze({ valid: false, extensionId: null });
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
  return /\.exe$/iu.test(components.at(-1));
}

export const NATIVE_HOST_NAME = HOST_NAME;
