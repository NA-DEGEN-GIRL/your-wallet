const RELEASE_ELIGIBILITY = "not-release-evidence";
const MAX_INVENTORY_RECORDS = 65_536;
const MAX_PATH_LENGTH = 240;
const UINT64_MAX = (1n << 64n) - 1n;
const DECIMAL_RE = /^(?:0|[1-9][0-9]*)$/u;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const PATH_RE = /^[A-Za-z0-9._/-]+$/u;
const WINDOWS_RESERVED_BASENAME_RE = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/iu;
const EXACT_RECORD_KEYS = Object.freeze(["bytes", "path", "sha256"]);

class BuildInventoryError extends Error {
  constructor(message) {
    super(message);
    this.name = "BuildInventoryError";
  }
}

function fail(message) {
  throw new BuildInventoryError(message);
}

function isPlainObject(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function requireExactRecord(value, index) {
  if (!isPlainObject(value)) {
    fail("build inventory record " + index + " must be a plain object");
  }
  const actualKeys = Object.keys(value).sort();
  if (
    actualKeys.length !== EXACT_RECORD_KEYS.length ||
    actualKeys.some((key, keyIndex) => key !== EXACT_RECORD_KEYS[keyIndex])
  ) {
    fail("build inventory records must contain exactly bytes, path, and sha256");
  }

  if (
    typeof value.bytes !== "string" ||
    !DECIMAL_RE.test(value.bytes) ||
    value.bytes.length > 20 ||
    BigInt(value.bytes) > UINT64_MAX
  ) {
    fail("build inventory bytes must be a canonical unsigned 64-bit decimal string");
  }
  if (
    typeof value.sha256 !== "string" ||
    !SHA256_RE.test(value.sha256)
  ) {
    fail("build inventory sha256 must be exactly 64 lowercase hexadecimal characters");
  }
  validateInventoryPath(value.path);

  return Object.freeze({
    bytes: value.bytes,
    path: value.path,
    sha256: value.sha256,
  });
}

function validateInventoryPath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_PATH_LENGTH ||
    !PATH_RE.test(value)
  ) {
    fail("build inventory path must be bounded printable ASCII");
  }
  if (
    value.startsWith("/") ||
    value.startsWith("\\") ||
    value.includes("\\") ||
    value.includes(":")
  ) {
    fail("build inventory path must be a relative forward-slash path without ADS syntax");
  }
  const segments = value.split("/");
  if (
    segments.some(
      (segment) => segment.length === 0 || segment === "." || segment === "..",
    )
  ) {
    fail("build inventory path contains a forbidden segment");
  }
  if (
    segments.some(
      (segment) =>
        segment.endsWith(".") ||
        WINDOWS_RESERVED_BASENAME_RE.test(segment.split(".", 1)[0]),
    )
  ) {
    fail("build inventory path contains a Windows alias or reserved device name");
  }
}

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function validateBuildInventory(value) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > MAX_INVENTORY_RECORDS
  ) {
    fail("build inventory must contain between 1 and 65536 records");
  }

  const validated = [];
  const windowsPathKeys = new Set();
  let previousPath = null;
  for (let index = 0; index < value.length; index += 1) {
    const record = requireExactRecord(value[index], index);
    if (
      previousPath !== null &&
      ordinalCompare(previousPath, record.path) >= 0
    ) {
      fail("build inventory records must use strict ordinal path order");
    }
    const windowsPathKey = record.path.toLowerCase();
    if (windowsPathKeys.has(windowsPathKey)) {
      fail("build inventory paths must be unique under Windows case folding");
    }
    windowsPathKeys.add(windowsPathKey);
    previousPath = record.path;
    validated.push(record);
  }
  return Object.freeze(validated);
}

export function compareBuildInventories(left, right) {
  const validatedLeft = validateBuildInventory(left);
  const validatedRight = validateBuildInventory(right);
  const equal = validatedLeft.length === validatedRight.length &&
    validatedLeft.every((record, index) => {
      const other = validatedRight[index];
      return record.bytes === other.bytes &&
        record.path === other.path &&
        record.sha256 === other.sha256;
    });
  return Object.freeze({
    equal,
    releaseEligibility: RELEASE_ELIGIBILITY,
  });
}
