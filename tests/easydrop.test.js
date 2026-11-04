// EasyDrop unit + signaling integration tests. Run: npm test (node --test tests/)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket } from 'ws';

import {
  generateRoomCode, isValidRoomCode, parseRoomInput,
  Sha256, sha256Hex, CHUNK_SIZE, chunkCount, chunkRange, resumeOffset, nextChunk,
} from '../public/js/shared.js';
import { createEasyDropServer } from '../server/server.js';

// ---------------------------------------------------------------------------
// Room codes
// ---------------------------------------------------------------------------

test('room code: generated codes always match the 3-4-3 format', () => {
  for (let i = 0; i < 500; i++) {
    const code = generateRoomCode();
    assert.match(code, /^[a-z]{3}-[a-z]{4}-[a-z]{3}$/);
    assert.equal(isValidRoomCode(code), true);
  }
});

test('room code: validation rejects bad shapes', () => {
  assert.equal(isValidRoomCode('abc-defg-hij'), true);
  assert.equal(isValidRoomCode('abcd-efg-hij'), false);
  assert.equal(isValidRoomCode('ABC-DEFG-HIJ'), false);
  assert.equal(isValidRoomCode('abc-defg-hij-extra'), false);
  assert.equal(isValidRoomCode(''), false);
  assert.equal(isValidRoomCode(null), false);
  assert.equal(isValidRoomCode('ab1-defg-hij'), false);
});

test('room code: generation is driven by the injected RNG', () => {
  assert.equal(generateRoomCode(() => 0), 'aaa-aaaa-aaa');
  assert.equal(generateRoomCode(() => 0.999), 'zzz-zzzz-zzz');
});

test('room input parsing: bare code, full link, junk', () => {
  assert.deepEqual(parseRoomInput('abc-defg-hij'), { code: 'abc-defg-hij', key: null });
  const link = parseRoomInput('https://easydrop.example/abc-defg-hij#k=AbC_123-xyzABC456def');
  assert.equal(link.code, 'abc-defg-hij');
  assert.equal(link.key, 'AbC_123-xyzABC456def');
  assert.equal(parseRoomInput('hello there'), null);
  assert.equal(parseRoomInput(''), null);
});

// ---------------------------------------------------------------------------
// SHA-256 (incremental) — known vectors, including chunked feeding
// ---------------------------------------------------------------------------

test('sha256: empty string vector', () => {
  assert.equal(
    sha256Hex(''),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
});

test('sha256: "abc" vector', () => {
  assert.equal(
    sha256Hex('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});

test('sha256: chunked updates equal one-shot (1,000,000 x "a")', () => {
  const hasher = new Sha256();
  const piece = new Uint8Array(1000).fill(0x61);
  for (let i = 0; i < 1000; i++) hasher.update(piece);
  assert.equal(
    hasher.digestHex(),
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
  );
});

test('sha256: odd-sized slices across block boundaries', () => {
  const data = new TextEncoder().encode('The quick brown fox jumps over the lazy dog'.repeat(37));
  const hasher = new Sha256();
  for (let i = 0; i < data.length; i += 7) hasher.update(data.subarray(i, i + 7));
  assert.equal(hasher.digestHex(), sha256Hex(data));
});

// ---------------------------------------------------------------------------
// Chunk / resume math
// ---------------------------------------------------------------------------

test('chunk math: counts and ranges', () => {
  assert.equal(CHUNK_SIZE, 64 * 1024);
  assert.equal(chunkCount(0), 0);
  assert.equal(chunkCount(1), 1);
  assert.equal(chunkCount(CHUNK_SIZE), 1);
  assert.equal(chunkCount(CHUNK_SIZE + 1), 2);
  assert.equal(chunkCount(2 * 1024 * 1024 * 1024), 32768); // a 2 GiB file
  assert.deepEqual(chunkRange(1000, 0, 300), { offset: 0, length: 300 });
  assert.deepEqual(chunkRange(1000, 3, 300), { offset: 900, length: 100 });
  assert.deepEqual(chunkRange(1000, 4, 300), { offset: 1000, length: 0 });
});

test('chunk math: resume offset only counts whole chunks', () => {
  assert.equal(resumeOffset(0), 0);
  assert.equal(resumeOffset(CHUNK_SIZE - 1), 0);
  assert.equal(resumeOffset(CHUNK_SIZE), CHUNK_SIZE);
  assert.equal(resumeOffset(CHUNK_SIZE + 123), CHUNK_SIZE);
  assert.equal(resumeOffset(3 * CHUNK_SIZE + 999), 3 * CHUNK_SIZE);
});

test('chunk math: nextChunk walks a file to its end', () => {
  const size = CHUNK_SIZE * 2 + 10;
  let offset = 0;
  let seen = 0;
  for (;;) {
    const c = nextChunk(size, offset);
    if (!c) break;
    seen += c.length;
    offset += c.length;
  }
  assert.equal(seen, size);
  assert.equal(nextChunk(size, size), null);
});

// ---------------------------------------------------------------------------
// Signaling server integration — real server on an ephemeral port, ws clients
// ---------------------------------------------------------------------------

let app;
let basePort;

before(async () => {
  app = await createEasyDropServer({});
  basePort = await app.listen(0);
  assert.ok(basePort > 0);
});

after(async () => {
  await app.close();
});

function connectClient() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${basePort}/ws`);
    const inbox = [];
    const waiters = [];
    ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      inbox.push(msg);
      for (let i = waiters.length - 1; i >= 0; i--) {
        if (waiters[i].pred(msg)) { waiters[i].resolve(msg); waiters.splice(i, 1); }
      }
    });
    ws.on('open', () => resolve({
      ws,
      inbox,
      send: (obj) => ws.send(JSON.stringify(obj)),
      waitFor: (pred, timeoutMs = 3000) => new Promise((res, rej) => {
        const found = inbox.find(pred);
        if (found) { res(found); return; }
        const timer = setTimeout(() => rej(new Error('timed out waiting for message')), timeoutMs);
        waiters.push({ pred, resolve: (m) => { clearTimeout(timer); res(m); } });
      }),
      close: () => { try { ws.close(); } catch { /* noop */ } },
    }));
    ws.on('error', reject);
  });
}

test('signaling: create + join, presence, signal relay, leave', async () => {
  const host = await connectClient();
  host.send({ type: 'create', code: 'aaa-bbbb-ccc', name: 'Host' });
  const welcome = await host.waitFor((m) => m.type === 'welcome');
  assert.equal(welcome.isHost, true);
  assert.deepEqual(welcome.peers, []);

  const guest = await connectClient();
  guest.send({ type: 'join', code: 'aaa-bbbb-ccc', name: 'Guest' });
  const gWelcome = await guest.waitFor((m) => m.type === 'welcome');
  assert.equal(gWelcome.isHost, false);
  assert.equal(gWelcome.peers.length, 1);
  assert.equal(gWelcome.peers[0].name, 'Host');
  assert.equal(gWelcome.peers[0].isHost, true);

  const joined = await host.waitFor((m) => m.type === 'peer-joined');
  assert.equal(joined.peerId, gWelcome.peerId);
  assert.equal(joined.name, 'Guest');

  // Signal relay guest -> host carries the sender id and payload untouched.
  guest.send({ type: 'signal', to: welcome.peerId, data: { kind: 'offer', sdp: { type: 'offer', sdp: 'x' } } });
  const relayed = await host.waitFor((m) => m.type === 'signal');
  assert.equal(relayed.from, gWelcome.peerId);
  assert.equal(relayed.data.kind, 'offer');
  assert.equal(relayed.data.sdp.sdp, 'x');

  // Rename broadcasts.
  guest.send({ type: 'rename', name: 'Renamed' });
  const renamed = await host.waitFor((m) => m.type === 'peer-renamed');
  assert.equal(renamed.name, 'Renamed');

  // Guest leaves -> host sees peer-left; room survives with host alone.
  guest.send({ type: 'leave' });
  const left = await host.waitFor((m) => m.type === 'peer-left');
  assert.equal(left.peerId, gWelcome.peerId);

  guest.close();
  host.close();
});

test('signaling: joining a room that does not exist is an honest error', async () => {
  const c = await connectClient();
  c.send({ type: 'join', code: 'zzz-yyyy-xxx', name: 'Nobody' });
  const err = await c.waitFor((m) => m.type === 'error');
  assert.equal(err.error, 'room-not-found');
  c.close();
});

test('signaling: host disconnect closes the room for guests (host-left)', async () => {
  const host = await connectClient();
  host.send({ type: 'create', code: 'ddd-eeee-fff', name: 'Host2' });
  await host.waitFor((m) => m.type === 'welcome');
  const guest = await connectClient();
  guest.send({ type: 'join', code: 'ddd-eeee-fff', name: 'Guest2' });
  await guest.waitFor((m) => m.type === 'welcome');
  host.close();
  const hostLeft = await guest.waitFor((m) => m.type === 'host-left');
  assert.equal(hostLeft.type, 'host-left');
  guest.close();
});

test('signaling: room cap of 8 peers is enforced', async () => {
  const host = await connectClient();
  host.send({ type: 'create', code: 'ggg-hhhh-iii', name: 'CapHost' });
  await host.waitFor((m) => m.type === 'welcome');
  const guests = [];
  for (let i = 0; i < 7; i++) {
    const g = await connectClient();
    g.send({ type: 'join', code: 'ggg-hhhh-iii', name: `G${i}` });
    await g.waitFor((m) => m.type === 'welcome');
    guests.push(g);
  }
  const ninth = await connectClient();
  ninth.send({ type: 'join', code: 'ggg-hhhh-iii', name: 'OneTooMany' });
  const err = await ninth.waitFor((m) => m.type === 'error');
  assert.equal(err.error, 'room-full');
  ninth.close();
  for (const g of guests) g.close();
  host.close();
});

test('signaling: host can expel a peer (wrong-password flow)', async () => {
  const host = await connectClient();
  host.send({ type: 'create', code: 'jjj-kkkk-lll', name: 'Host3' });
  const hw = await host.waitFor((m) => m.type === 'welcome');
  const guest = await connectClient();
  guest.send({ type: 'join', code: 'jjj-kkkk-lll', name: 'BadGuest' });
  const gw = await guest.waitFor((m) => m.type === 'welcome');
  void hw;
  host.send({ type: 'expel', peerId: gw.peerId });
  const expelled = await guest.waitFor((m) => m.type === 'expelled');
  assert.equal(expelled.type, 'expelled');
  guest.close();
  host.close();
});
