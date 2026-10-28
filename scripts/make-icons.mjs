// scripts/make-icons.mjs — the Your Wallet icon (spec/04 §1.7, spec/05 §2.2), drawn procedurally.
// Artwork: a rounded-square tile with a deep indigo → teal diagonal gradient and a white wallet
// (rounded body, flap line, strap tab with a round clasp). Sizes up to 32 px are snapped to the
// pixel grid and up to 24 px the strap is reduced to its clasp dot, so the icon reads at 16 px.
//
// Writes (paths from the repository root):
//   crates/yw-app/icons/yw-app.ico          16, 20, 24, 32, 40, 48, 64 (32-bit BMP) and 256 (PNG)
//   crates/yw-app/icons/yw-app.res          compiled Win32 resources: the same images as RT_ICON 1..8
//                                           and RT_GROUP_ICON 1 (linked by crates/yw-app/build.rs)
//   extension/icons/icon-{16,32,48,128}.png manifest `icons` and `action.default_icon`
//   extension/src/provider-main.js          the PROVIDER_ICON line (96 px PNG data URI, EIP-6963)
//   docs/icon-preview.png                   every size on light and dark backgrounds, small ones magnified
//
// Usage: node scripts/make-icons.mjs [--check]
//   --check regenerates everything in memory and compares it byte for byte with the files on disk
//   (nothing is written; scripts/check.ps1 step `icons`).
// Exit: 0 = written / up to date, 1 = --check found a missing or different file, 2 = usage or I/O error.
//
// Node built-ins only. Pixels use only + - * / abs sqrt min max round (no trig or pow), PNGs carry no
// timestamps or text chunks, and deflate uses fixed zlib settings, so the bytes are reproducible
// with the same Node (bundled zlib). If a Node update changes zlib output, re-run without --check.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import { PNG_SIGNATURE, crc32 } from "./lib/png.mjs";

export const ICO_SIZES = [16, 20, 24, 32, 40, 48, 64, 256];
export const EXTENSION_SIZES = [16, 32, 48, 128];
export const PROVIDER_ICON_SIZE = 96;
export const APP_ICON_GROUP_ID = 1;

const RT_ICON = 3;
const RT_GROUP_ICON = 14;
const LANG_EN_US = 0x0409;
// rc.exe memory flags: MOVEABLE | DISCARDABLE (icons), MOVEABLE | PURE | DISCARDABLE (group).
const ICON_MEMORY_FLAGS = 0x1010;
const GROUP_MEMORY_FLAGS = 0x1030;

export const OUTPUT_PATHS = Object.freeze({
  ico: "crates/yw-app/icons/yw-app.ico",
  res: "crates/yw-app/icons/yw-app.res",
  provider: "extension/src/provider-main.js",
  preview: "docs/icon-preview.png",
  extension: (size) => `extension/icons/icon-${size}.png`,
});

const PROVIDER_ICON_LINE = /^( {2}const PROVIDER_ICON = )"data:image\/png;base64,[A-Za-z0-9+/]*={0,2}";$/mu;

// ---------------------------------------------------------------- artwork

const GRADIENT_START = [0x35, 0x2a, 0x9c]; // top-left, deep indigo
const GRADIENT_END = [0x0b, 0x8a, 0x80]; // bottom-right, teal
const GLYPH_COLOR = [0xff, 0xff, 0xff];

// Signed distance (pixels, negative inside) to a rounded rectangle given by its edges.
function roundBox(x, y, left, top, right, bottom, radius) {
  const qx = Math.abs(x - (left + right) / 2) - (right - left) / 2 + radius;
  const qy = Math.abs(y - (top + bottom) / 2) - (bottom - top) / 2 + radius;
  const ox = Math.max(qx, 0);
  const oy = Math.max(qy, 0);
  return Math.sqrt(ox * ox + oy * oy) + Math.min(Math.max(qx, qy), 0) - radius;
}

function circle(x, y, cx, cy, radius) {
  const dx = x - cx;
  const dy = y - cy;
  return Math.sqrt(dx * dx + dy * dy) - radius;
}

// The shapes for one pixel size, in pixels. Sizes up to 32 snap edges to the pixel grid; up to 24
// the strap is reduced to the clasp dot and the tile fills the whole square.
function geometry(size) {
  const hinted = size <= 32;
  const snap = (value) => (hinted ? Math.round(value) : value);
  const pad = size <= 24 ? 0 : snap(size / 32);
  const w = size - 2 * pad;
  const at = (fraction) => pad + fraction * w;
  const gap = hinted ? Math.max(1, Math.round(0.045 * w)) : 0.045 * w;
  const body = { left: snap(at(0.16)), top: snap(at(0.29)), right: snap(at(0.8)), bottom: snap(at(0.76)), radius: Math.max(1.25, 0.085 * w) };
  const flapTop = hinted ? Math.max(snap(at(0.4)), body.top + 2) : at(0.4);
  const flap = { top: flapTop, bottom: flapTop + gap };
  // The strap (and the clasp dot) sit centred in the body part below the flap line.
  const middle = (flap.bottom + body.bottom) / 2;
  const strapHalf = hinted ? Math.max(1.5, Math.round(0.07 * w)) : 0.07 * w;
  const strapTop = snap(middle - strapHalf);
  const strap = size <= 24
    ? null
    : { left: snap(at(0.55)), top: strapTop, right: snap(at(0.86)), bottom: strapTop + 2 * strapHalf, radius: strapHalf };
  const dotRadius = hinted ? 1.15 : 0.038 * w;
  const dot = strap === null
    ? { x: snap(body.right - Math.max(2.4, 0.16 * w)), y: snap(middle), radius: dotRadius }
    : { x: strap.left + strapHalf + (hinted ? 0 : 0.012 * w), y: strap.top + strapHalf, radius: dotRadius };
  return {
    tile: { left: pad, top: pad, right: size - pad, bottom: size - pad, radius: 0.22 * w },
    body,
    flap,
    strap,
    gap,
    dot,
  };
}

// 0 = outside, 1 = tile, 2 = glyph.
function classify(x, y, g) {
  const { tile, body, flap, strap, gap, dot } = g;
  if (roundBox(x, y, tile.left, tile.top, tile.right, tile.bottom, tile.radius) > 0) return 0;
  if (circle(x, y, dot.x, dot.y, dot.radius) <= 0) return 1;
  if (strap !== null) {
    const strapDistance = roundBox(x, y, strap.left, strap.top, strap.right, strap.bottom, strap.radius);
    if (strapDistance <= 0) return 2;
    if (strapDistance <= gap) return 1;
  }
  if (roundBox(x, y, body.left, body.top, body.right, body.bottom, body.radius) > 0) return 1;
  if (y >= flap.top && y < flap.bottom) return 1;
  return 2;
}

/** RGBA (straight alpha) pixels of the icon at `size` × `size`. */
export function renderIcon(size) {
  const g = geometry(size);
  const samples = size <= 64 ? 16 : 8;
  const total = samples * samples;
  const span = g.tile.right - g.tile.left;
  const pixels = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      let tileCount = 0;
      let glyphCount = 0;
      for (let sy = 0; sy < samples; sy += 1) {
        const y = py + (sy + 0.5) / samples;
        for (let sx = 0; sx < samples; sx += 1) {
          const kind = classify(px + (sx + 0.5) / samples, y, g);
          if (kind === 1) tileCount += 1;
          else if (kind === 2) glyphCount += 1;
        }
      }
      const covered = tileCount + glyphCount;
      if (covered === 0) continue;
      const t = Math.min(1, Math.max(0, (px + 0.5 - g.tile.left + (py + 0.5 - g.tile.top)) / (2 * span)));
      const offset = (py * size + px) * 4;
      for (let channel = 0; channel < 3; channel += 1) {
        const tileColor = GRADIENT_START[channel] + (GRADIENT_END[channel] - GRADIENT_START[channel]) * t;
        pixels[offset + channel] = Math.round((tileColor * tileCount + GLYPH_COLOR[channel] * glyphCount) / covered);
      }
      pixels[offset + 3] = Math.round((covered * 255) / total);
    }
  }
  return pixels;
}

// ---------------------------------------------------------------- PNG

function pngChunk(type, data) {
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  chunk.write(type, 4, "ascii");
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(chunk.subarray(4, 8 + data.length)), 8 + data.length);
  return chunk;
}

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

// Each row takes the filter with the smallest sum of absolute signed residuals (ties: lowest type).
function filterRows(width, height, pixels, channels) {
  const stride = width * channels;
  const out = Buffer.alloc((stride + 1) * height);
  const candidate = Buffer.alloc(stride);
  const best = Buffer.alloc(stride);
  for (let y = 0; y < height; y += 1) {
    const row = y * stride;
    let bestType = 0;
    let bestScore = Infinity;
    for (let type = 0; type < 5; type += 1) {
      let score = 0;
      for (let i = 0; i < stride; i += 1) {
        const value = pixels[row + i];
        const left = i >= channels ? pixels[row + i - channels] : 0;
        const up = y > 0 ? pixels[row - stride + i] : 0;
        const upLeft = y > 0 && i >= channels ? pixels[row - stride + i - channels] : 0;
        const predictor = [0, left, up, (left + up) >> 1, paeth(left, up, upLeft)][type];
        const residual = (value - predictor) & 0xff;
        candidate[i] = residual;
        score += residual < 128 ? residual : 256 - residual;
      }
      if (score < bestScore) {
        bestScore = score;
        bestType = type;
        candidate.copy(best);
      }
    }
    out[y * (stride + 1)] = bestType;
    best.copy(out, y * (stride + 1) + 1);
  }
  return out;
}

/** PNG bytes: 8-bit RGBA (`channels` 4) or RGB (3), no ancillary chunks. */
export function encodePng(width, height, pixels, channels = 4) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = channels === 4 ? 6 : 2;
  const compressed = zlib.deflateSync(filterRows(width, height, pixels, channels), {
    level: 9,
    memLevel: 9,
    windowBits: 15,
    strategy: zlib.constants.Z_DEFAULT_STRATEGY,
  });
  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk("IHDR", header),
    pngChunk("IDAT", compressed),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

// ---------------------------------------------------------------- ICO and RES

// A 32-bit icon DIB: BITMAPINFOHEADER (height doubled), bottom-up BGRA, then the 1-bpp AND mask
// (1 = fully transparent).
function iconBitmap(size, pixels) {
  const maskStride = Math.ceil(size / 32) * 4;
  const colorBytes = size * size * 4;
  const out = Buffer.alloc(40 + colorBytes + maskStride * size);
  out.writeUInt32LE(40, 0);
  out.writeInt32LE(size, 4);
  out.writeInt32LE(size * 2, 8);
  out.writeUInt16LE(1, 12);
  out.writeUInt16LE(32, 14);
  out.writeUInt32LE(colorBytes + maskStride * size, 20);
  for (let row = 0; row < size; row += 1) {
    const sourceRow = size - 1 - row;
    for (let x = 0; x < size; x += 1) {
      const source = (sourceRow * size + x) * 4;
      const target = 40 + (row * size + x) * 4;
      out[target] = pixels[source + 2];
      out[target + 1] = pixels[source + 1];
      out[target + 2] = pixels[source];
      out[target + 3] = pixels[source + 3];
      if (pixels[source + 3] === 0) out[40 + colorBytes + row * maskStride + (x >> 3)] |= 0x80 >> (x & 7);
    }
  }
  return out;
}

// ICO/RT_ICON image data: BMP below 256 px (most compatible), PNG at 256 px.
function iconImages(rendered) {
  return ICO_SIZES.map((size) => ({ size, data: size >= 256 ? encodePng(size, size, rendered.get(size)) : iconBitmap(size, rendered.get(size)) }));
}

export function buildIco(images) {
  const header = Buffer.alloc(6 + 16 * images.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length;
  images.forEach(({ size, data }, index) => {
    const entry = 6 + 16 * index;
    header[entry] = size >= 256 ? 0 : size;
    header[entry + 1] = size >= 256 ? 0 : size;
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(data.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...images.map(({ data }) => data)]);
}

// One .res record with ordinal type and name: RESOURCEHEADER (32 bytes) + data, padded to a DWORD.
function resRecord(type, name, data, memoryFlags, language) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(data.length, 0);
  header.writeUInt32LE(32, 4);
  header.writeUInt16LE(0xffff, 8);
  header.writeUInt16LE(type, 10);
  header.writeUInt16LE(0xffff, 12);
  header.writeUInt16LE(name, 14);
  header.writeUInt16LE(memoryFlags, 20);
  header.writeUInt16LE(language, 22);
  return Buffer.concat([header, data, Buffer.alloc((4 - (data.length % 4)) % 4)]);
}

export function buildRes(images) {
  const group = Buffer.alloc(6 + 14 * images.length);
  group.writeUInt16LE(0, 0);
  group.writeUInt16LE(1, 2);
  group.writeUInt16LE(images.length, 4);
  images.forEach(({ size, data }, index) => {
    const entry = 6 + 14 * index;
    group[entry] = size >= 256 ? 0 : size;
    group[entry + 1] = size >= 256 ? 0 : size;
    group.writeUInt16LE(1, entry + 4);
    group.writeUInt16LE(32, entry + 6);
    group.writeUInt32LE(data.length, entry + 8);
    group.writeUInt16LE(index + 1, entry + 12);
  });
  return Buffer.concat([
    resRecord(0, 0, Buffer.alloc(0), 0, 0), // the empty first record that marks a 32-bit .res file
    ...images.map(({ data }, index) => resRecord(RT_ICON, index + 1, data, ICON_MEMORY_FLAGS, LANG_EN_US)),
    resRecord(RT_GROUP_ICON, APP_ICON_GROUP_ID, group, GROUP_MEMORY_FLAGS, LANG_EN_US),
  ]);
}

// ---------------------------------------------------------------- preview

const PREVIEW_BACKGROUNDS = [[0xf3, 0xf4, 0xf6], [0x20, 0x20, 0x20]];
const PREVIEW_ROW = [256, 128, 64, 48, 40, 32, 24, 20, 16];
const PREVIEW_MAGNIFIED = [[16, 8], [20, 6], [24, 5], [32, 4]];
const PREVIEW_MARGIN = 16;

function buildPreview(rendered) {
  const rowWidth = PREVIEW_ROW.reduce((sum, size) => sum + size + PREVIEW_MARGIN, PREVIEW_MARGIN);
  const zoomWidth = PREVIEW_MAGNIFIED.reduce((sum, [size, scale]) => sum + size * scale + PREVIEW_MARGIN, PREVIEW_MARGIN);
  const zoomHeight = Math.max(...PREVIEW_MAGNIFIED.map(([size, scale]) => size * scale));
  const width = Math.max(rowWidth, zoomWidth);
  const panelHeight = PREVIEW_MARGIN * 3 + 256 + zoomHeight;
  const height = panelHeight * PREVIEW_BACKGROUNDS.length;
  const canvas = Buffer.alloc(width * height * 3);
  const blit = (pixels, size, scale, left, top, background) => {
    for (let y = 0; y < size * scale; y += 1) {
      for (let x = 0; x < size * scale; x += 1) {
        const source = (Math.floor(y / scale) * size + Math.floor(x / scale)) * 4;
        const target = ((top + y) * width + left + x) * 3;
        const alpha = pixels[source + 3];
        for (let channel = 0; channel < 3; channel += 1) {
          canvas[target + channel] = Math.round((pixels[source + channel] * alpha + background[channel] * (255 - alpha)) / 255);
        }
      }
    }
  };
  PREVIEW_BACKGROUNDS.forEach((background, panel) => {
    const top = panel * panelHeight;
    for (let y = top; y < top + panelHeight; y += 1) {
      for (let x = 0; x < width; x += 1) background.forEach((value, channel) => { canvas[(y * width + x) * 3 + channel] = value; });
    }
    let left = PREVIEW_MARGIN;
    const baseline = top + PREVIEW_MARGIN + 256;
    for (const size of PREVIEW_ROW) {
      blit(rendered.get(size), size, 1, left, baseline - size, background);
      left += size + PREVIEW_MARGIN;
    }
    left = PREVIEW_MARGIN;
    const zoomTop = baseline + PREVIEW_MARGIN;
    for (const [size, scale] of PREVIEW_MAGNIFIED) {
      blit(rendered.get(size), size, scale, left, zoomTop + zoomHeight - size * scale, background);
      left += size * scale + PREVIEW_MARGIN;
    }
  });
  return encodePng(width, height, canvas, 3);
}

// ---------------------------------------------------------------- outputs

/**
 * Every generated file as `Map<repository-relative path, Buffer>`. `providerSource` is the current
 * text of extension/src/provider-main.js (its PROVIDER_ICON line is replaced).
 */
export function buildOutputs(providerSource) {
  const sizes = new Set([...ICO_SIZES, ...EXTENSION_SIZES, PROVIDER_ICON_SIZE, ...PREVIEW_ROW]);
  const rendered = new Map([...sizes].sort((a, b) => a - b).map((size) => [size, renderIcon(size)]));
  const images = iconImages(rendered);
  const outputs = new Map();
  outputs.set(OUTPUT_PATHS.ico, buildIco(images));
  outputs.set(OUTPUT_PATHS.res, buildRes(images));
  for (const size of EXTENSION_SIZES) outputs.set(OUTPUT_PATHS.extension(size), encodePng(size, size, rendered.get(size)));
  const matches = providerSource.match(new RegExp(PROVIDER_ICON_LINE.source, "gmu")) ?? [];
  if (matches.length !== 1) throw new Error(`${OUTPUT_PATHS.provider} must contain exactly one PROVIDER_ICON data URI line`);
  const dataUri = `data:image/png;base64,${encodePng(PROVIDER_ICON_SIZE, PROVIDER_ICON_SIZE, rendered.get(PROVIDER_ICON_SIZE)).toString("base64")}`;
  outputs.set(OUTPUT_PATHS.provider, Buffer.from(providerSource.replace(PROVIDER_ICON_LINE, (_line, prefix) => `${prefix}"${dataUri}";`), "utf8"));
  outputs.set(OUTPUT_PATHS.preview, buildPreview(rendered));
  return outputs;
}

async function readOptional(file) {
  try {
    return await readFile(file);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function main(argv) {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== "--check")) {
    process.stderr.write("usage: node scripts/make-icons.mjs [--check]\n");
    return 2;
  }
  const check = argv[0] === "--check";
  const root = fileURLToPath(new URL("../", import.meta.url));
  const outputs = buildOutputs(await readFile(path.join(root, OUTPUT_PATHS.provider), "utf8"));
  const stale = [];
  for (const [relative, bytes] of outputs) {
    const file = path.join(root, ...relative.split("/"));
    const current = await readOptional(file);
    if (current !== null && current.equals(bytes)) continue;
    if (check) {
      stale.push(`${relative} (${current === null ? "missing" : "differs"})`);
      continue;
    }
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, bytes);
    process.stdout.write(`make-icons: wrote ${relative} (${bytes.length} bytes)\n`);
  }
  if (check && stale.length > 0) {
    process.stderr.write(`make-icons: FAIL generated icons are out of date; run node scripts/make-icons.mjs\n${stale.map((line) => `  ${line}\n`).join("")}`);
    return 1;
  }
  process.stdout.write(check ? `make-icons: OK ${outputs.size} files up to date\n` : "make-icons: done\n");
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (error) => {
      process.stderr.write(`make-icons: ERROR ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 2;
    },
  );
}
