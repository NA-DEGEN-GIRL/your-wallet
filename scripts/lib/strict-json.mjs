// scripts/lib/strict-json.mjs — strict JSON reader shared by Node tools (spec/01 §4.4, §4.6).
// Moved from archive/spec-v2.4:scripts/release/release-manifest.mjs:98-100,144-150,152-158,160-283
// (error class renamed ReleaseValidationError -> StrictJsonError).

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_NODES = 50_000;

export class StrictJsonError extends Error {
  constructor(message) {
    super(message);
    this.name = "StrictJsonError";
  }
}

function fail(message) {
  throw new StrictJsonError(message);
}

export function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

export function decodeUtf8(bytes, label = "input") {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
}

export function parseStrictJson(text) {
  if (typeof text !== "string") fail("JSON input must be text");
  if (Buffer.byteLength(text, "utf8") > MAX_JSON_BYTES) fail("JSON input exceeds the 1 MiB limit");

  let offset = 0;
  let nodes = 0;

  function bumpNode() {
    nodes += 1;
    if (nodes > MAX_JSON_NODES) fail("JSON node limit exceeded");
  }

  function skipWhitespace() {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset])) offset += 1;
  }

  function parseString() {
    if (text[offset] !== '"') fail(`expected string at byte ${offset}`);
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch {
          fail(`invalid JSON string at byte ${start}`);
        }
      }
      if (character === "\\") {
        offset += 1;
        if (offset >= text.length) fail(`unterminated escape at byte ${start}`);
        if (text[offset] === "u") {
          const digits = text.slice(offset + 1, offset + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(digits)) fail(`invalid Unicode escape at byte ${offset}`);
          offset += 5;
        } else {
          if (!/["\\/bfnrt]/u.test(text[offset])) fail(`invalid escape at byte ${offset}`);
          offset += 1;
        }
        continue;
      }
      if (character.charCodeAt(0) < 0x20) fail(`unescaped control character at byte ${offset}`);
      offset += 1;
    }
    fail(`unterminated string at byte ${start}`);
  }

  function parseValue(depth) {
    if (depth > MAX_JSON_DEPTH) fail("JSON depth limit exceeded");
    skipWhitespace();
    bumpNode();
    const character = text[offset];
    if (character === '"') return parseString();
    if (character === "{") {
      offset += 1;
      const result = {};
      const keys = new Set();
      skipWhitespace();
      if (text[offset] === "}") {
        offset += 1;
        return result;
      }
      while (offset < text.length) {
        skipWhitespace();
        const key = parseString();
        // `result[key] = …` with "__proto__" would replace the object's prototype instead of
        // adding a member; such input has no legitimate use here, so reject it outright.
        if (key === "__proto__") fail("forbidden JSON member: __proto__");
        if (keys.has(key)) fail(`duplicate JSON member: ${key}`);
        keys.add(key);
        skipWhitespace();
        if (text[offset] !== ":") fail(`expected ':' at byte ${offset}`);
        offset += 1;
        result[key] = parseValue(depth + 1);
        skipWhitespace();
        if (text[offset] === "}") {
          offset += 1;
          return result;
        }
        if (text[offset] !== ",") fail(`expected ',' at byte ${offset}`);
        offset += 1;
      }
      fail("unterminated object");
    }
    if (character === "[") {
      offset += 1;
      const result = [];
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return result;
      }
      while (offset < text.length) {
        result.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[offset] === "]") {
          offset += 1;
          return result;
        }
        if (text[offset] !== ",") fail(`expected ',' at byte ${offset}`);
        offset += 1;
      }
      fail("unterminated array");
    }
    for (const [token, value] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(token, offset)) {
        offset += token.length;
        return value;
      }
    }
    const numberMatch = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (numberMatch) {
      offset += numberMatch[0].length;
      const number = Number(numberMatch[0]);
      if (!Number.isFinite(number)) fail("non-finite JSON number");
      return number;
    }
    fail(`invalid JSON value at byte ${offset}`);
  }

  const value = parseValue(0);
  skipWhitespace();
  if (offset !== text.length) fail(`trailing JSON data at byte ${offset}`);
  return value;
}
