// EasyDrop signaling + static server.
//
// HARD RULE: this server NEVER receives, relays or stores file data.
// It only (1) serves the static frontend, (2) introduces peers to each
// other over a WebSocket (rooms, presence, SDP/ICE relay), (3) renders
// QR SVGs for the app's own room links. File bytes travel exclusively
// over direct browser-to-browser WebRTC data channels.

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WebSocketServer } from 'ws';
import QRCode from 'qrcode';
import selfsigned from 'selfsigned';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');

const MAX_PEERS_PER_ROOM = 8;
const MAX_SIGNAL_BYTES = 64 * 1024; // SDP/ICE messages are small; file data never comes here
const RATE_LIMIT = 300;              // messages per window per socket
const RATE_WINDOW_MS = 10_000;
const ROOM_CODE_RE = /^[a-z]{3}-[a-z]{4}-[a-z]{3}$/;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

function iceServersFromEnv(env = process.env) {
  const ice = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' },
  ];
  if (env.EASYDROP_TURN_URL) {
    const turn = { urls: env.EASYDROP_TURN_URL };
    if (env.EASYDROP_TURN_USERNAME) turn.username = env.EASYDROP_TURN_USERNAME;
    if (env.EASYDROP_TURN_PASSWORD) turn.credential = env.EASYDROP_TURN_PASSWORD;
    ice.push(turn);
  }
  return ice;
}

export function createEasyDropServer(env = process.env) {
  // rooms: code -> Map<peerId, { ws, name, isHost }>
  const rooms = new Map();

  function send(ws, obj) {
    if (ws.readyState === ws.OPEN) {
      try { ws.send(JSON.stringify(obj)); } catch { /* socket going away */ }
    }
  }

  function broadcast(room, obj, exceptPeerId = null) {
    for (const [pid, peer] of room) {
      if (pid !== exceptPeerId) send(peer.ws, obj);
    }
  }

  function peerList(room, exceptPeerId = null) {
    const out = [];
    for (const [pid, peer] of room) {
      if (pid !== exceptPeerId) out.push({ peerId: pid, name: peer.name, isHost: peer.isHost });
    }
    return out;
  }

  function removePeer(state, reason) {
    const room = rooms.get(state.code);
    if (!room || !room.has(state.peerId)) return;
    const wasHost = state.isHost;
    room.delete(state.peerId);
    if (wasHost) {
      // Room is dead: tell everyone, then drop their sockets.
      broadcast(room, { type: 'host-left' });
      for (const peer of room.values()) { try { peer.ws.close(1000, 'host left'); } catch { /* noop */ } }
      rooms.delete(state.code);
    } else {
      broadcast(room, { type: 'peer-left', peerId: state.peerId, reason: reason || 'left' });
      if (room.size === 0) rooms.delete(state.code);
    }
  }

  function handleMessage(state, raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg.type !== 'string') return;

    if (msg.type === 'create' || msg.type === 'join') {
      if (state.code) return; // already in a room
      const code = typeof msg.code === 'string' ? msg.code : '';
      if (!ROOM_CODE_RE.test(code)) { send(state.ws, { type: 'error', error: 'bad-code' }); return; }
      const name = String(msg.name || 'Guest').slice(0, 40) || 'Guest';
      if (msg.type === 'create') {
        if (rooms.has(code)) { send(state.ws, { type: 'error', error: 'room-exists' }); return; }
        const room = new Map();
        state.peerId = crypto.randomUUID();
        state.code = code;
        state.isHost = true;
        room.set(state.peerId, { ws: state.ws, name, isHost: true });
        rooms.set(code, room);
        send(state.ws, { type: 'welcome', peerId: state.peerId, isHost: true, peers: [] });
      } else {
        const room = rooms.get(code);
        if (!room) { send(state.ws, { type: 'error', error: 'room-not-found' }); return; }
        if (room.size >= MAX_PEERS_PER_ROOM) { send(state.ws, { type: 'error', error: 'room-full' }); return; }
        state.peerId = crypto.randomUUID();
        state.code = code;
        state.isHost = false;
        const existing = peerList(room);
        room.set(state.peerId, { ws: state.ws, name, isHost: false });
        send(state.ws, { type: 'welcome', peerId: state.peerId, isHost: false, peers: existing });
        broadcast(room, { type: 'peer-joined', peerId: state.peerId, name, isHost: false }, state.peerId);
      }
      return;
    }

    // Everything below requires membership in a room.
    const room = state.code ? rooms.get(state.code) : null;
    if (!room || !state.peerId || !room.has(state.peerId)) return;

    switch (msg.type) {
      case 'signal': {
        // Relay WebRTC SDP/ICE between two named peers in the same room.
        const target = typeof msg.to === 'string' ? room.get(msg.to) : null;
        if (target && msg.data && typeof msg.data === 'object') {
          send(target.ws, { type: 'signal', from: state.peerId, data: msg.data });
        }
        break;
      }
      case 'rename': {
        const name = String(msg.name || '').slice(0, 40);
        if (name) {
          room.get(state.peerId).name = name;
          broadcast(room, { type: 'peer-renamed', peerId: state.peerId, name }, state.peerId);
        }
        break;
      }
      case 'close-room': {
        if (!state.isHost) return;
        broadcast(room, { type: 'room-closed' }, state.peerId);
        for (const [pid, peer] of room) {
          if (pid !== state.peerId) { try { peer.ws.close(1000, 'room closed'); } catch { /* noop */ } }
        }
        rooms.delete(state.code);
        room.clear();
        state.code = null;
        break;
      }
      case 'expel': {
        // Host may drop a peer (e.g. wrong room password).
        if (!state.isHost || typeof msg.peerId !== 'string') return;
        const target = room.get(msg.peerId);
        if (target && msg.peerId !== state.peerId) {
          send(target.ws, { type: 'expelled' });
          try { target.ws.close(1000, 'expelled'); } catch { /* noop */ }
          room.delete(msg.peerId);
          broadcast(room, { type: 'peer-left', peerId: msg.peerId, reason: 'expelled' });
        }
        break;
      }
      case 'leave': {
        removePeer(state, 'left');
        state.code = null;
        break;
      }
      default:
        break; // unknown message types are ignored
    }
  }

  async function requestHandler(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const pathname = decodeURIComponent(url.pathname);

    if (pathname === '/qr') {
      const text = url.searchParams.get('text') || '';
      if (!text || text.length >= 1024) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('QR text missing or too long');
        return;
      }
      try {
        const svg = await QRCode.toString(text, { type: 'svg', margin: 1, width: 240 });
        res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-store' });
        res.end(svg);
      } catch {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('QR generation failed');
      }
      return;
    }

    if (pathname === '/config.js') {
      const body = `window.EASYDROP_ICE = ${JSON.stringify(iceServersFromEnv(env))};\n`;
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(body);
      return;
    }

    if (pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }

    // Static files; room URLs (/<code>) fall back to the app shell.
    let filePath;
    if (pathname === '/' || ROOM_CODE_RE.test(pathname.slice(1))) {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    } else {
      filePath = path.join(PUBLIC_DIR, pathname);
      if (!filePath.startsWith(PUBLIC_DIR)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }
    }
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }
      res.writeHead(200, {
        'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream',
        'Cache-Control': 'no-cache',
      });
      res.end(data);
    });
  }

  let server;
  let scheme = 'http';
  const useHttps = env.EASYDROP_HTTPS === '1';
  if (useHttps) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const certPath = path.join(DATA_DIR, 'cert.pem');
    const keyPath = path.join(DATA_DIR, 'key.pem');
    let cert, key;
    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      cert = fs.readFileSync(certPath, 'utf8');
      key = fs.readFileSync(keyPath, 'utf8');
    } else {
      // selfsigned v5: generate() is async and resolves to { cert, private, ... }
      return selfsigned.generate(
        [{ name: 'commonName', value: 'EasyDrop (self-signed)' }],
        { days: 365, keySize: 2048 },
      ).then((pems) => {
        fs.writeFileSync(certPath, pems.cert);
        fs.writeFileSync(keyPath, pems.private);
        const built = buildHttp(pems.cert, pems.private);
        return built;
      });
    }
    return Promise.resolve(buildHttp(cert, key));
  }
  return Promise.resolve(buildHttp(null, null));

  function buildHttp(cert, key) {
    if (cert && key) {
      server = https.createServer({ cert, key }, requestHandler);
      scheme = 'https';
    } else {
      server = http.createServer(requestHandler);
    }
    const wss = new WebSocketServer({ server, path: '/ws', maxPayload: MAX_SIGNAL_BYTES });

    wss.on('connection', (ws) => {
      const state = { ws, peerId: null, code: null, isHost: false, hits: [] };
      ws.on('message', (data) => {
        // Simple sliding-window rate limit.
        const now = Date.now();
        state.hits = state.hits.filter((t) => now - t < RATE_WINDOW_MS);
        state.hits.push(now);
        if (state.hits.length > RATE_LIMIT) { try { ws.close(1008, 'rate limited'); } catch { /* noop */ } return; }
        if (data.length > MAX_SIGNAL_BYTES) return;
        handleMessage(state, data.toString());
      });
      ws.on('close', () => { if (state.code) removePeer(state, 'disconnected'); });
      ws.on('error', () => { /* close handler cleans up */ });
    });

    return {
      server,
      wss,
      scheme,
      rooms,
      listen(port) {
        return new Promise((resolve) => {
          server.listen(port, () => resolve(server.address().port));
        });
      },
      close() {
        return new Promise((resolve) => {
          for (const client of wss.clients) { try { client.terminate(); } catch { /* noop */ } }
          wss.close(() => server.close(() => resolve()));
        });
      },
    };
  }
}

// Run directly: `node server/server.js`
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 8787);
  createEasyDropServer().then((app) => {
    app.listen(port).then((actual) => {
      console.log(`EasyDrop running at ${app.scheme}://localhost:${actual}`);
      console.log('Files are never uploaded to this server — it only introduces devices to each other.');
      if (app.scheme === 'https') {
        console.log('HTTPS mode: self-signed certificate in ./data — your browser/phone will ask you to accept it once.');
      }
    });
  }).catch((err) => {
    console.error('Failed to start EasyDrop:', err);
    process.exit(1);
  });
}
