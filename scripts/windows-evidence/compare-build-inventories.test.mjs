import assert from "node:assert/strict";
import test from "node:test";

import {
  compareBuildInventories,
  validateBuildInventory,
} from "./compare-build-inventories.mjs";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

function record(path, bytes = "1", sha256 = HASH_A) {
  return { bytes, path, sha256 };
}

test("strict path-ordered build inventories validate as immutable copies", () => {
  const input = [
    record("payload/approval-ui.exe", "1"),
    record("payload/key-agent.exe", "20", HASH_B),
  ];
  const validated = validateBuildInventory(input);
  assert.deepEqual(validated, input);
  assert.notEqual(validated, input);
  assert.notEqual(validated[0], input[0]);
  assert.ok(Object.isFrozen(validated));
  assert.ok(validated.every(Object.isFrozen));
});

test("inventory shape is a nonempty bounded array of exact records", () => {
  for (const invalid of [null, {}, "inventory", [], [null], [[]]]) {
    assert.throws(
      () => validateBuildInventory(invalid),
      /inventory|plain object/u,
    );
  }

  for (const invalidRecord of [
    { path: "payload/a.exe", sha256: HASH_A },
    { bytes: "1", path: "payload/a.exe" },
    { bytes: "1", path: "payload/a.exe", sha256: HASH_A, role: "binary" },
  ]) {
    assert.throws(
      () => validateBuildInventory([invalidRecord]),
      /exactly bytes, path, and sha256/u,
    );
  }

  const tooMany = Array.from(
    { length: 65_537 },
    (_, index) =>
      record("files/" + String(index).padStart(5, "0") + ".bin"),
  );
  assert.throws(
    () => validateBuildInventory(tooMany),
    /between 1 and 65536/u,
  );
});

test("byte counts are canonical unsigned 64-bit decimal strings", () => {
  for (const bytes of [
    "",
    "-1",
    "+1",
    "00",
    "01",
    "1.0",
    " 1",
    "18446744073709551616",
    1,
    1n,
  ]) {
    assert.throws(
      () => validateBuildInventory([record("payload/a.exe", bytes)]),
      /unsigned 64-bit decimal/u,
    );
  }
  assert.equal(
    validateBuildInventory([
      record("payload/a.exe", "18446744073709551615"),
    ])[0].bytes,
    "18446744073709551615",
  );
  assert.equal(
    validateBuildInventory([record("payload/a.exe", "0")])[0].bytes,
    "0",
  );
});

test("hashes require exact lowercase SHA-256 hexadecimal form", () => {
  for (const sha256 of [
    "",
    "a".repeat(63),
    "a".repeat(65),
    "A".repeat(64),
    "g".repeat(64),
    7,
  ]) {
    assert.throws(
      () =>
        validateBuildInventory([
          record("payload/a.exe", "1", sha256),
        ]),
      /64 lowercase hexadecimal/u,
    );
  }
});

test("paths reject absolute, traversal, backslash, ADS, and malformed segments", () => {
  for (const invalidPath of [
    "/payload/a.exe",
    "//server/share/a.exe",
    "C:/payload/a.exe",
    "payload\\a.exe",
    "payload/a.exe:stream",
    "../payload/a.exe",
    "payload/../a.exe",
    "./payload/a.exe",
    "payload/./a.exe",
    "payload//a.exe",
    "payload/",
    "payload/trailing./a.exe",
    "payload/con",
    "payload/NUL.txt",
    "payload/com1.exe",
    "payload/lpt9",
    "payload/a file.exe",
    "payload/\u00e9.exe",
  ]) {
    assert.throws(
      () => validateBuildInventory([record(invalidPath)]),
      /path/u,
    );
  }
});

test("paths use strict ordinal order and Windows-casefold uniqueness", () => {
  assert.throws(
    () =>
      validateBuildInventory([
        record("payload/b.exe"),
        record("payload/a.exe"),
      ]),
    /ordinal path order/u,
  );
  assert.throws(
    () =>
      validateBuildInventory([
        record("Payload/a.exe"),
        record("payload/a.exe"),
      ]),
    /Windows case folding/u,
  );
  assert.throws(
    () =>
      validateBuildInventory([
        record("payload/a.exe"),
        record("payload/a.exe"),
      ]),
    /ordinal path order|Windows case folding/u,
  );
});

test("equal inventories remain explicitly ineligible as release evidence", () => {
  const left = [
    record("payload/approval-ui.exe", "100"),
    record("payload/key-agent.exe", "200", HASH_B),
  ];
  const right = left.map((item) => ({ ...item }));
  assert.deepEqual(compareBuildInventories(left, right), {
    equal: true,
    releaseEligibility: "not-release-evidence",
  });
});

test("every record difference is reported unequal without a release claim", () => {
  const baseline = [
    record("payload/a.exe", "100"),
    record("payload/b.exe", "200", HASH_B),
  ];
  const variants = [
    [record("payload/a.exe", "101"), record("payload/b.exe", "200", HASH_B)],
    [record("payload/a.exe", "100", HASH_B), record("payload/b.exe", "200", HASH_B)],
    [record("payload/a.exe", "100")],
    [record("payload/a.exe", "100"), record("payload/c.exe", "200", HASH_B)],
  ];
  for (const candidate of variants) {
    assert.deepEqual(compareBuildInventories(baseline, candidate), {
      equal: false,
      releaseEligibility: "not-release-evidence",
    });
  }
});

test("comparison validates both sides before making any equality statement", () => {
  const valid = [record("payload/a.exe")];
  assert.throws(
    () => compareBuildInventories([], valid),
    /inventory/u,
  );
  assert.throws(
    () => compareBuildInventories(valid, [record("../a.exe")]),
    /path/u,
  );
});
