// EasyDrop shared library — used by the browser frontend (as an ES module)
// and by the Node unit tests. Pure functions + an incremental SHA-256.

// ---------------------------------------------------------------------------
// Room codes: format 3-4-3 lowercase letters, e.g. "abc-defg-hij"
// ---------------------------------------------------------------------------

const LETTERS = 'abcdefghijklmnopqrstuvwxyz';
export const ROOM_CODE_RE = /^[a-z]{3}-[a-z]{4}-[a-z]{3}$/;

export function isValidRoomCode(code) {
  return typeof code === 'string' && ROOM_CODE_RE.test(code);
}

// rand: () => float in [0,1) — injectable for tests.
export function generateRoomCode(rand = Math.random) {
  const group = (n) => {
    let s = '';
    for (let i = 0; i < n; i++) s += LETTERS[Math.floor(rand() * 26) % 26];
    return s;
  };
  return `${group(3)}-${group(4)}-${group(3)}`;
}

// Extract a room code from free text: a bare code, or a full room link
// like "https://host/abc-defg-hij#k=..." (optionally also returns the key).
export function parseRoomInput(text) {
  if (typeof text !== 'string') return null;
  const t = text.trim();
  const codeMatch = t.match(/[a-z]{3}-[a-z]{4}-[a-z]{3}/);
  if (!codeMatch) return null;
  const keyMatch = t.match(/#k=([A-Za-z0-9_-]{8,})/);
  return { code: codeMatch[0], key: keyMatch ? keyMatch[1] : null };
}

// Room key: lives ONLY in the URL fragment (#k=...), never sent to the server.
// 16 random bytes -> 22-char base64url string.
export function generateRoomKey() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------------------
// Chunk / resume math for file transfers
// ---------------------------------------------------------------------------

export const CHUNK_SIZE = 64 * 1024; // 64 KB per data-channel message

export function chunkCount(size, chunkSize = CHUNK_SIZE) {
  if (!Number.isFinite(size) || size <= 0) return 0;
  return Math.ceil(size / chunkSize);
}

// Byte range of chunk `index` within a file of `size` bytes.
export function chunkRange(size, index, chunkSize = CHUNK_SIZE) {
  const offset = index * chunkSize;
  if (offset >= size) return { offset: size, length: 0 };
  return { offset, length: Math.min(chunkSize, size - offset) };
}

// When resuming an interrupted transfer, only whole chunks already received
// count — a partial chunk is re-requested. Returns the byte offset to
// resume from given how many bytes were received before the interruption.
export function resumeOffset(receivedBytes, chunkSize = CHUNK_SIZE) {
  if (!Number.isFinite(receivedBytes) || receivedBytes <= 0) return 0;
  return Math.floor(receivedBytes / chunkSize) * chunkSize;
}

// Next chunk to send when starting (or resuming) at a byte offset.
export function nextChunk(size, offset, chunkSize = CHUNK_SIZE) {
  if (offset >= size) return null;
  return { offset, length: Math.min(chunkSize, size - offset) };
}

// ---------------------------------------------------------------------------
// Incremental SHA-256 (FIPS 180-4). Needed because WebCrypto has no
// streaming digest, and EasyDrop hashes files up to 2 GB in slices.
// ---------------------------------------------------------------------------

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

export class Sha256 {
  constructor() {
    this._h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    this._buf = new Uint8Array(64);
    this._bufLen = 0;
    this._total = 0; // total bytes fed so far
    this._w = new Uint32Array(64);
  }

  _block(block, offset) {
    const w = this._w;
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = this._h;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    const H = this._h;
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }

  update(data) {
    if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
    this._total += data.length;
    let i = 0;
    if (this._bufLen > 0) {
      const take = Math.min(64 - this._bufLen, data.length);
      this._buf.set(data.subarray(0, take), this._bufLen);
      this._bufLen += take;
      i = take;
      if (this._bufLen === 64) {
        this._block(this._buf, 0);
        this._bufLen = 0;
      }
    }
    while (i + 64 <= data.length) {
      this._block(data, i);
      i += 64;
    }
    if (i < data.length) {
      this._buf.set(data.subarray(i), 0);
      this._bufLen = data.length - i;
    }
    return this;
  }

  digestHex() {
    // Padding operates on a copy of state so update() could continue after.
    const bitLen = this._total * 8;
    const padLen = this._bufLen < 56 ? 56 - this._bufLen : 120 - this._bufLen;
    const tail = new Uint8Array(this._bufLen + padLen + 8);
    tail.set(this._buf.subarray(0, this._bufLen), 0);
    tail[this._bufLen] = 0x80;
    const hi = Math.floor(bitLen / 0x100000000);
    const lo = bitLen >>> 0;
    const n = tail.length;
    tail[n - 8] = (hi >>> 24) & 0xff; tail[n - 7] = (hi >>> 16) & 0xff;
    tail[n - 6] = (hi >>> 8) & 0xff; tail[n - 5] = hi & 0xff;
    tail[n - 4] = (lo >>> 24) & 0xff; tail[n - 3] = (lo >>> 16) & 0xff;
    tail[n - 2] = (lo >>> 8) & 0xff; tail[n - 1] = lo & 0xff;
    const clone = new Sha256();
    clone._h.set(this._h);
    clone._total = this._total;
    for (let i = 0; i < tail.length; i += 64) clone._block(tail, i);
    let out = '';
    for (const word of clone._h) out += word.toString(16).padStart(8, '0');
    return out;
  }
}

export function sha256Hex(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return new Sha256().update(bytes).digestHex();
}

// ---------------------------------------------------------------------------
// Small formatting helpers (browser UI)
// ---------------------------------------------------------------------------

export function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

export function formatEta(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))}s left`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${String(s).padStart(2, '0')}s left`;
}
