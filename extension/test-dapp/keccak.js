// Test-only Keccak-256 (Ethereum variant: original Keccak padding 0x01, not SHA3-256's 0x06).
// Used by the test dApp to build ecrecover-precompile eth_call checks and EIP-55 checksums.
// Not constant-time and not for production use.
const MASK = (1n << 64n) - 1n;
const RATE_BYTES = 136;
const ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
];
// Rotation offsets indexed by x + 5 * y.
const ROTATIONS = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14
];

function rotl(value, shift) {
  if (shift === 0) {
    return value;
  }
  return ((value << BigInt(shift)) | (value >> BigInt(64 - shift))) & MASK;
}

function keccakF1600(state) {
  const c = new Array(5);
  const b = new Array(25);
  for (let round = 0; round < 24; round += 1) {
    for (let x = 0; x < 5; x += 1) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x += 1) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) {
        state[y + x] ^= d;
      }
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROTATIONS[x + 5 * y]);
      }
    }
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x += 1) {
        state[y + x] = b[y + x] ^ ((~b[y + ((x + 1) % 5)] & MASK) & b[y + ((x + 2) % 5)]);
      }
    }
    state[0] ^= ROUND_CONSTANTS[round];
  }
}

export function keccak256(input) {
  const bytes = input instanceof Uint8Array ? input : new TextEncoder().encode(String(input));
  const padded = new Uint8Array((Math.floor(bytes.length / RATE_BYTES) + 1) * RATE_BYTES);
  padded.set(bytes);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += RATE_BYTES) {
    for (let lane = 0; lane < RATE_BYTES / 8; lane += 1) {
      let value = 0n;
      for (let byte = 7; byte >= 0; byte -= 1) {
        value = (value << 8n) | BigInt(padded[offset + lane * 8 + byte]);
      }
      state[lane] ^= value;
    }
    keccakF1600(state);
  }
  const out = new Uint8Array(32);
  for (let lane = 0; lane < 4; lane += 1) {
    let value = state[lane];
    for (let byte = 0; byte < 8; byte += 1) {
      out[lane * 8 + byte] = Number(value & 0xffn);
      value >>= 8n;
    }
  }
  return out;
}
