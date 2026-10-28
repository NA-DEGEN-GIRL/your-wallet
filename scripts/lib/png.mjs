// scripts/lib/png.mjs — PNG helpers shared by scripts/make-icons.mjs (writer) and
// scripts/audit-extension.mjs (icon audit). Node built-ins only.

export const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/** CRC-32 (ISO-HDLC, as used by PNG chunks). */
export function crc32(bytes) {
  let c = 0xffffffff;
  for (const byte of bytes) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Parses PNG structure: signature, chunk lengths and CRCs, IHDR first, IEND last with nothing
 * after it. Returns the IHDR fields and the chunk types in order. Throws `Error` on any violation.
 */
export function readPng(bytes) {
  if (bytes.length < PNG_SIGNATURE.length || !bytes.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
    throw new Error("not a PNG (signature)");
  }
  const chunkTypes = [];
  let header = null;
  let offset = PNG_SIGNATURE.length;
  while (offset < bytes.length) {
    if (offset + 12 > bytes.length) throw new Error("truncated PNG chunk");
    const length = bytes.readUInt32BE(offset);
    const end = offset + 12 + length;
    if (length > 0x7fffffff || end > bytes.length) throw new Error("PNG chunk length out of range");
    const type = bytes.toString("latin1", offset + 4, offset + 8);
    if (!/^[A-Za-z]{4}$/u.test(type)) throw new Error("invalid PNG chunk type");
    if (crc32(bytes.subarray(offset + 4, offset + 8 + length)) !== bytes.readUInt32BE(offset + 8 + length)) {
      throw new Error(`PNG chunk ${type} CRC mismatch`);
    }
    if (chunkTypes.length === 0) {
      if (type !== "IHDR" || length !== 13) throw new Error("PNG must start with a 13-byte IHDR");
      const data = bytes.subarray(offset + 8, offset + 21);
      header = {
        width: data.readUInt32BE(0),
        height: data.readUInt32BE(4),
        bitDepth: data[8],
        colorType: data[9],
        compression: data[10],
        filter: data[11],
        interlace: data[12],
      };
    }
    chunkTypes.push(type);
    offset = end;
    if (type === "IEND") break;
  }
  if (chunkTypes.at(-1) !== "IEND") throw new Error("PNG has no IEND chunk");
  if (offset !== bytes.length) throw new Error("data after PNG IEND chunk");
  return { ...header, chunkTypes };
}
