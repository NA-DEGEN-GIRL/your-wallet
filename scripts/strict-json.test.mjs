import assert from "node:assert/strict";
import { test } from "node:test";
import { StrictJsonError, decodeUtf8, isPlainObject, parseStrictJson } from "./lib/strict-json.mjs";

test("parses plain objects with Object.prototype", () => {
  const value = parseStrictJson('{"a":[1,true,null,"x"],"constructor":{"prototype":1}}');
  assert.deepEqual(value, { a: [1, true, null, "x"], constructor: { prototype: 1 } });
  assert.ok(isPlainObject(value));
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
  assert.equal(Object.getPrototypeOf(value.constructor), Object.prototype);
});

test("rejects __proto__ members at any depth", () => {
  for (const text of ['{"__proto__":{"polluted":true}}', '{"a":{"__proto__":{}}}', '[{"__proto__":1}]', '{"\\u005f_proto__":{}}']) {
    assert.throws(() => parseStrictJson(text), StrictJsonError, text);
  }
  assert.equal({}.polluted, undefined);
});

test("rejects duplicate keys, trailing data and invalid UTF-8", () => {
  assert.throws(() => parseStrictJson('{"a":1,"a":2}'), StrictJsonError);
  assert.throws(() => parseStrictJson("{} x"), StrictJsonError);
  assert.throws(() => decodeUtf8(Uint8Array.from([0x7b, 0xff, 0x7d])), StrictJsonError);
  assert.deepEqual(parseStrictJson(decodeUtf8(Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))), {});
});
