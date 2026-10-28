// scripts/make-icons.test.mjs — structure of the generated icon files (scripts/make-icons.mjs, spec/04 §1.7,
// spec/05 §2.2). Byte equality with the committed files is check.ps1 step `icons`; this checks the formats.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { APP_ICON_GROUP_ID, EXTENSION_SIZES, ICO_SIZES, OUTPUT_PATHS, PROVIDER_ICON_SIZE, buildOutputs } from "./make-icons.mjs";
import { readPng } from "./lib/png.mjs";

const root = new URL("../", import.meta.url);
const read = (relative) => readFile(new URL(relative, root));

// Width/height of one icon image: PNG IHDR, or a 32-bit BITMAPINFOHEADER with doubled height.
function imageSize(data) {
  if (data.subarray(1, 4).toString("latin1") === "PNG") {
    const png = readPng(data);
    assert.equal(png.colorType, 6);
    return png.width;
  }
  assert.equal(data.readUInt32LE(0), 40, "BITMAPINFOHEADER");
  const size = data.readInt32LE(4);
  assert.equal(data.readInt32LE(8), size * 2, "XOR + AND height");
  assert.equal(data.readUInt16LE(12), 1);
  assert.equal(data.readUInt16LE(14), 32);
  assert.equal(data.readUInt32LE(16), 0, "BI_RGB");
  assert.equal(data.length, 40 + size * size * 4 + Math.ceil(size / 32) * 4 * size);
  return size;
}

test("generation is deterministic", async () => {
  const provider = (await read(OUTPUT_PATHS.provider)).toString("utf8");
  const first = buildOutputs(provider);
  const second = buildOutputs(provider);
  assert.deepEqual([...first.keys()], [...second.keys()]);
  for (const [relative, bytes] of first) assert.ok(bytes.equals(second.get(relative)), relative);
});

test("the .ico lists every size once, in order, with matching image data", async () => {
  const ico = await read(OUTPUT_PATHS.ico);
  assert.deepEqual([ico.readUInt16LE(0), ico.readUInt16LE(2), ico.readUInt16LE(4)], [0, 1, ICO_SIZES.length]);
  let expectedOffset = 6 + 16 * ICO_SIZES.length;
  ICO_SIZES.forEach((size, index) => {
    const entry = 6 + 16 * index;
    assert.equal(ico[entry] || 256, size);
    assert.equal(ico[entry + 1] || 256, size);
    assert.equal(ico.readUInt16LE(entry + 4), 1);
    assert.equal(ico.readUInt16LE(entry + 6), 32);
    const length = ico.readUInt32LE(entry + 8);
    const offset = ico.readUInt32LE(entry + 12);
    assert.equal(offset, expectedOffset);
    assert.equal(imageSize(ico.subarray(offset, offset + length)), size);
    expectedOffset += length;
  });
  assert.equal(expectedOffset, ico.length);
});

test("the .res is a 32-bit resource file with RT_ICON 1..n and RT_GROUP_ICON 1 matching the .ico", async () => {
  const res = await read(OUTPUT_PATHS.res);
  const ico = await read(OUTPUT_PATHS.ico);
  const records = [];
  for (let offset = 0; offset < res.length;) {
    assert.equal(offset % 4, 0, "DWORD-aligned record");
    const dataSize = res.readUInt32LE(offset);
    const headerSize = res.readUInt32LE(offset + 4);
    assert.equal(headerSize, 32, "ordinal type and name");
    assert.equal(res.readUInt16LE(offset + 8), 0xffff);
    assert.equal(res.readUInt16LE(offset + 12), 0xffff);
    records.push({
      type: res.readUInt16LE(offset + 10),
      name: res.readUInt16LE(offset + 14),
      language: res.readUInt16LE(offset + 22),
      data: res.subarray(offset + 32, offset + 32 + dataSize),
    });
    offset += 32 + dataSize + ((4 - (dataSize % 4)) % 4);
  }
  // The leading empty record marks the 32-bit format.
  assert.deepEqual({ ...records[0], data: records[0].data.length }, { type: 0, name: 0, language: 0, data: 0 });
  const icons = records.slice(1, -1);
  const group = records.at(-1);
  assert.deepEqual(icons.map(({ type, name, language }) => [type, name, language]), ICO_SIZES.map((_size, index) => [3, index + 1, 0x0409]));
  assert.deepEqual([group.type, group.name, group.language], [14, APP_ICON_GROUP_ID, 0x0409]);
  assert.deepEqual([group.data.readUInt16LE(0), group.data.readUInt16LE(2), group.data.readUInt16LE(4)], [0, 1, ICO_SIZES.length]);
  assert.equal(group.data.length, 6 + 14 * ICO_SIZES.length);
  ICO_SIZES.forEach((size, index) => {
    const entry = 6 + 14 * index;
    assert.equal(group.data[entry] || 256, size);
    assert.equal(group.data.readUInt16LE(entry + 6), 32);
    assert.equal(group.data.readUInt32LE(entry + 8), icons[index].data.length);
    assert.equal(group.data.readUInt16LE(entry + 12), index + 1);
    // Same image bytes as the .ico entry.
    const icoOffset = ico.readUInt32LE(6 + 16 * index + 12);
    assert.ok(icons[index].data.equals(ico.subarray(icoOffset, icoOffset + icons[index].data.length)), `RT_ICON ${index + 1}`);
  });
});

test("extension icons and the EIP-6963 provider icon are plain RGBA PNGs of their sizes", async () => {
  for (const size of EXTENSION_SIZES) {
    const png = readPng(await read(OUTPUT_PATHS.extension(size)));
    assert.deepEqual([png.width, png.height, png.bitDepth, png.colorType, png.interlace], [size, size, 8, 6, 0]);
    assert.deepEqual(png.chunkTypes, ["IHDR", "IDAT", "IEND"]);
  }
  const provider = (await read(OUTPUT_PATHS.provider)).toString("utf8");
  const uris = [...provider.matchAll(/const PROVIDER_ICON = "data:image\/png;base64,([A-Za-z0-9+/]+={0,2})";/gu)];
  assert.equal(uris.length, 1);
  const png = readPng(Buffer.from(uris[0][1], "base64"));
  assert.deepEqual([png.width, png.height, png.colorType], [PROVIDER_ICON_SIZE, PROVIDER_ICON_SIZE, 6]);
  const preview = readPng(await read(OUTPUT_PATHS.preview));
  assert.equal(preview.colorType, 2);
});
