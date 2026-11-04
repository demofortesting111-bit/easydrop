// EasyDrop frontend.
//
// Files NEVER touch the server: the WebSocket below carries only room
// presence and WebRTC signaling (SDP/ICE). File bytes and messages move
// over direct browser-to-browser WebRTC data channels, DTLS-encrypted.
// Chat is additionally AES-GCM encrypted with the room key (the part of
// the link after #k=), which is never sent to the server.

import {
  generateRoomCode, generateRoomKey, parseRoomInput, isValidRoomCode,
  Sha256, sha256Hex, CHUNK_SIZE, formatBytes, formatEta,
} from './shared.js';

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const genId = () => `id-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

const NAME_ADJ = ['Swift', 'Sunny', 'Brave', 'Calm', 'Merry', 'Bold', 'Quiet', 'Lucky'];
const NAME_ANIMAL = ['Fox', 'Panda', 'Otter', 'Falcon', 'Koala', 'Tiger', 'Heron', 'Wolf'];
function randomName() {
  return `${NAME_ADJ[Math.floor(Math.random() * NAME_ADJ.length)]} ${NAME_ANIMAL[Math.floor(Math.random() * NAME_ANIMAL.length)]}`;
}

function b64encode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------------------
// Receiver save method (decided once, shown honestly in the room)
// ---------------------------------------------------------------------------

const BLOB_PRACTICAL_LIMIT = 400 * 1024 * 1024; // ~400 MB

function detectSaveMethod() {
  if (typeof window.showSaveFilePicker === 'function') {
    return {
      kind: 'fs', warn: false,
      label: 'Saving on this browser: files stream straight to a file on your disk (File System Access). Memory use stays flat, so 2 GB files are fine — free disk space is the only limit.',
    };
  }
  if (navigator.storage && typeof navigator.storage.getDirectory === 'function') {
    return {
      kind: 'opfs', warn: false,
      label: 'Saving on this browser: files are staged in browser storage (OPFS) as they arrive, then you save them to your device. The limit is this browser\'s storage quota on this device.',
    };
  }
  return {
    kind: 'blob', warn: true,
    label: 'Saving on this browser: legacy in-memory download. The whole file is held in memory before saving — practical limit ≈ 400 MB. Larger files may fail. Use a current Chrome/Edge for 2 GB transfers.',
  };
}
const saveMethod = detectSaveMethod();

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
  view: 'home',
  ws: null,
  wsOpen: false,
  intentionalClose: false,
  code: null,
  key: null,
  keyProof: null,      // sha256 hex of the key, exchanged peer-to-peer only
  peerId: null,
  isHost: false,
  hostPeerId: null,
  name: localStorage.getItem('easydrop-name') || randomName(),
  password: null,      // host only: the room password (memory only)
  passwordHash: null,  // host only: sha256(password + code)
  roomLocked: null,    // null = unknown, true/false once the host says
  myAuthed: false,     // guest: host accepted my password (or room unlocked)
  peers: new Map(),    // peerId -> peer record
  files: new Map(),    // fileId -> file record
  transfers: new Map(),// transferId -> transfer record
  history: [],
  joinTimer: null,
  aesKey: null,        // CryptoKey derived from room key, for chat
};
localStorage.setItem('easydrop-name', state.name);

function iceServers() {
  return Array.isArray(window.EASYDROP_ICE) && window.EASYDROP_ICE.length
    ? window.EASYDROP_ICE
    : [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun.cloudflare.com:3478' }];
}

// ---------------------------------------------------------------------------
// Views, status pill, banners, notices
// ---------------------------------------------------------------------------

function showView(name) {
  state.view = name;
  $('view-home').hidden = name !== 'home';
  $('view-room').hidden = name !== 'room';
  $('view-notice').hidden = name !== 'notice';
}

function setStatus(kind, text) {
  const pill = $('status-pill');
  pill.textContent = text;
  pill.className = `pill ${kind === 'ok' ? 'pill-ok' : kind === 'bad' ? 'pill-bad' : kind === 'wait' ? 'pill-connecting' : 'pill-idle'}`;
}

function connectedPeerCount() {
  let n = 0;
  for (const p of state.peers.values()) if (p.controlOpen) n++;
  return n;
}

function refreshStatus() {
  if (state.view !== 'room') { setStatus('idle', 'Not in a room'); return; }
  if (!state.wsOpen) { setStatus('bad', 'Connection problem — signaling server unreachable'); return; }
  const n = connectedPeerCount();
  const failed = [...state.peers.values()].some((p) => p.iceState === 'failed');
  if (n > 0) setStatus('ok', `Connected to ${n} device${n === 1 ? '' : 's'}`);
  else if (failed) setStatus('bad', 'Connection problem — a device could not be reached');
  else setStatus('wait', state.isHost ? 'In room — waiting for a device' : 'Connecting to the host…');
  $('share-status').textContent = n > 0
    ? `Connected to ${n} device${n === 1 ? '' : 's'}.`
    : 'Waiting for a device to join…';
  $('no-peers-hint').hidden = n > 0;
  const canChat = n > 0;
  $('btn-send-message').disabled = !canChat;
  $('message-note').textContent = canChat ? '' : 'No device connected yet';
  $('message-note').hidden = canChat;
  renderPeople();
}

function showBanner(text) {
  $('error-banner-text').textContent = text;
  $('error-banner').hidden = false;
}
function hideBanner() { $('error-banner').hidden = true; }

function showNotice(title, text, { retry = false, diagnostics = false } = {}) {
  $('notice-title').textContent = title;
  $('notice-text').textContent = text;
  $('btn-notice-retry').hidden = !retry;
  $('btn-notice-diagnostics').hidden = !diagnostics;
  showView('notice');
  setStatus('bad', title);
}

function addHistory(html) {
  state.history.unshift(html);
  const list = $('history-list');
  list.innerHTML = state.history.map((h) => `<li>${h}</li>`).join('');
}

// ---------------------------------------------------------------------------
// Signaling (WebSocket to our own tiny server — presence + SDP/ICE only)
// ---------------------------------------------------------------------------

function signalSend(obj) {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) state.ws.send(JSON.stringify(obj));
}

function connectSignaling(mode) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws`);
  state.ws = ws;
  state.wsOpen = false;

  ws.addEventListener('open', () => {
    state.wsOpen = true;
    signalSend({ type: mode, code: state.code, name: state.name });
    refreshStatus();
  });

  ws.addEventListener('message', (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    handleSignalMessage(msg);
  });

  ws.addEventListener('close', () => {
    state.wsOpen = false;
    if (state.intentionalClose) return;
    if (state.view === 'room') {
      showNotice(
        'Lost the signaling server',
        'The connection to the small EasyDrop server that introduces devices was lost, so this room can no longer work. Check your internet connection and try again.',
        { retry: true },
      );
    }
  });

  ws.addEventListener('error', () => {
    if (!state.wsOpen && state.view === 'room') {
      showBanner('Could not reach the signaling server. Check your connection, then retry.');
    }
  });
}

function handleSignalMessage(msg) {
  switch (msg.type) {
    case 'welcome': {
      state.peerId = msg.peerId;
      state.isHost = msg.isHost;
      if (msg.isHost) {
        state.hostPeerId = msg.peerId;
        state.myAuthed = true;
        state.roomLocked = !!state.passwordHash;
      }
      $('btn-close-room').hidden = !msg.isHost;
      $('btn-password').hidden = !msg.isHost;
      for (const p of msg.peers) {
        const peer = ensurePeer(p.peerId, p.name, p.isHost);
        // The joiner initiates connections to everyone already in the room.
        connectToPeer(peer, true);
      }
      if (!msg.isHost) {
        state.joinTimer = setTimeout(() => {
          if (connectedPeerCount() === 0 && state.view === 'room') {
            showBanner('Still trying to reach the host device. If it does not connect, the two networks may be blocking peer-to-peer traffic — run the connection check.');
          }
        }, 15000);
      }
      refreshStatus();
      break;
    }
    case 'error': {
      if (msg.error === 'room-not-found') {
        state.intentionalClose = true;
        showNotice(
          'Room not found',
          'No open room has that code. The code may be typed wrong, or the host may have closed the room or left the page.',
          {},
        );
      } else if (msg.error === 'room-full') {
        state.intentionalClose = true;
        showNotice('Room is full', 'This room already has the maximum of 8 devices in it.', {});
      } else if (msg.error === 'room-exists') {
        // Astronomically unlikely code collision: pick a fresh code.
        state.code = generateRoomCode();
        updateShareCard();
        signalSend({ type: 'create', code: state.code, name: state.name });
      } else if (msg.error === 'bad-code') {
        showNotice('That room code is not valid', 'Room codes look like abc-defg-hij — three groups of lowercase letters.', {});
      }
      break;
    }
    case 'peer-joined': {
      const peer = ensurePeer(msg.peerId, msg.name, msg.isHost);
      // Existing members wait; the joiner will offer.
      void peer;
      refreshStatus();
      break;
    }
    case 'peer-left': {
      const peer = state.peers.get(msg.peerId);
      if (peer) {
        closePeer(peer);
        state.peers.delete(msg.peerId);
        for (const f of [...state.files.values()]) {
          if (f.ownerId === msg.peerId) state.files.delete(f.id);
        }
        renderFiles();
      }
      refreshStatus();
      break;
    }
    case 'peer-renamed': {
      const peer = state.peers.get(msg.peerId);
      if (peer) { peer.name = msg.name; refreshStatus(); }
      break;
    }
    case 'signal': {
      handlePeerSignal(msg.from, msg.data).catch(() => {});
      break;
    }
    case 'host-left': {
      state.intentionalClose = true;
      showNotice('The host left', 'The device that created this room has left, so the room is closed.', {});
      break;
    }
    case 'room-closed': {
      state.intentionalClose = true;
      showNotice('Room closed', 'The host closed this room for everyone.', {});
      break;
    }
    case 'expelled': {
      state.intentionalClose = true;
      showNotice('Removed from the room', 'The host removed this device — this happens when a room password is not accepted.', {});
      break;
    }
    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// WebRTC peers — one RTCPeerConnection per peer, a "control" data channel
// for chat/metadata/transfer signalling, plus one data channel per transfer.
// ---------------------------------------------------------------------------

function ensurePeer(peerId, name, isHost) {
  let peer = state.peers.get(peerId);
  if (!peer) {
    peer = {
      peerId, name: name || 'Guest', isHost: !!isHost,
      pc: null, control: null, controlOpen: false,
      keyProof: null, verified: false, authed: state.isHost ? !state.passwordHash : false,
      iceState: 'new', pendingIce: [], remoteSet: false,
    };
    state.peers.set(peerId, peer);
    if (peer.isHost) state.hostPeerId = peerId;
  } else if (name) {
    peer.name = name;
  }
  return peer;
}

function createPc(peer) {
  const pc = new RTCPeerConnection({ iceServers: iceServers() });
  peer.pc = pc;
  pc.addEventListener('icecandidate', (ev) => {
    if (ev.candidate) {
      signalSend({ type: 'signal', to: peer.peerId, data: { kind: 'ice', candidate: ev.candidate.toJSON() } });
    }
  });
  pc.addEventListener('connectionstatechange', () => {
    peer.iceState = pc.connectionState;
    if (pc.connectionState === 'failed') {
      showBanner(`Could not establish a direct connection to ${peer.name}. Your networks may be blocking peer-to-peer traffic — run the connection check for details.`);
    }
    refreshStatus();
  });
  pc.addEventListener('datachannel', (ev) => {
    const ch = ev.channel;
    if (ch.label === 'control') setupControlChannel(peer, ch);
    else if (ch.label.startsWith('xfer:')) setupIncomingTransferChannel(peer, ch);
  });
  return pc;
}

async function connectToPeer(peer, initiator) {
  if (!peer.pc) createPc(peer);
  if (initiator) {
    const dc = peer.pc.createDataChannel('control');
    setupControlChannel(peer, dc);
    const offer = await peer.pc.createOffer();
    await peer.pc.setLocalDescription(offer);
    signalSend({ type: 'signal', to: peer.peerId, data: { kind: 'offer', sdp: offer } });
  }
}

async function handlePeerSignal(fromPeerId, data) {
  const peer = ensurePeer(fromPeerId, null, false);
  if (!peer.pc) createPc(peer);
  const pc = peer.pc;
  if (data.kind === 'offer') {
    await pc.setRemoteDescription(data.sdp);
    peer.remoteSet = true;
    for (const c of peer.pendingIce.splice(0)) { try { await pc.addIceCandidate(c); } catch { /* stale */ } }
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    signalSend({ type: 'signal', to: fromPeerId, data: { kind: 'answer', sdp: answer } });
  } else if (data.kind === 'answer') {
    await pc.setRemoteDescription(data.sdp);
    peer.remoteSet = true;
    for (const c of peer.pendingIce.splice(0)) { try { await pc.addIceCandidate(c); } catch { /* stale */ } }
  } else if (data.kind === 'ice' && data.candidate) {
    if (peer.remoteSet) { try { await pc.addIceCandidate(data.candidate); } catch { /* stale */ } }
    else peer.pendingIce.push(data.candidate);
  }
}

function closePeer(peer) {
  try { peer.control?.close(); } catch { /* noop */ }
  try { peer.pc?.close(); } catch { /* noop */ }
  peer.controlOpen = false;
  for (const t of state.transfers.values()) {
    if (t.peerId === peer.peerId && (t.state === 'active' || t.state === 'paused' || t.state === 'starting')) {
      t.state = 'interrupted';
      t.interrupted = true;
    }
  }
  renderTransfers();
}

function setupControlChannel(peer, channel) {
  peer.control = channel;
  channel.addEventListener('open', () => {
    peer.controlOpen = true;
    if (state.joinTimer) { clearTimeout(state.joinTimer); state.joinTimer = null; }
    sendControl(peer, {
      type: 'hello',
      name: state.name,
      isHost: state.isHost,
      keyProof: state.keyProof,
      locked: state.isHost ? !!state.passwordHash : state.roomLocked === true,
    });
    // (Re)announce everything I am sharing to the newly connected peer.
    for (const f of state.files.values()) {
      if (f.ownerId === 'me' && f.state === 'ready') announceFile(peer, f);
    }
    refreshStatus();
  });
  channel.addEventListener('close', () => { peer.controlOpen = false; refreshStatus(); });
  channel.addEventListener('message', (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    handleControlMessage(peer, msg).catch(() => {});
  });
}

function sendControl(peer, obj) {
  if (peer.control && peer.control.readyState === 'open') {
    try { peer.control.send(JSON.stringify(obj)); } catch { /* closing */ }
  }
}

function broadcastControl(obj, exceptPeerId = null) {
  for (const peer of state.peers.values()) {
    if (peer.peerId !== exceptPeerId && peer.controlOpen) sendControl(peer, obj);
  }
}

// Whether I should accept chat/files from this peer under the light lock.
function peerAllowed(peer) {
  if (state.roomLocked !== true) return true;
  if (state.isHost) return peer.authed;
  return peer.authed || peer.peerId === state.hostPeerId;
}

async function handleControlMessage(peer, msg) {
  switch (msg.type) {
    case 'hello': {
      peer.name = msg.name || peer.name;
      peer.isHost = !!msg.isHost;
      if (peer.isHost) state.hostPeerId = peer.peerId;
      peer.keyProof = msg.keyProof || null;
      peer.verified = !!state.keyProof && peer.keyProof === state.keyProof;
      if (peer.isHost) {
        state.roomLocked = !!msg.locked;
        if (!msg.locked) state.myAuthed = true;
        else if (!state.myAuthed) askForPassword();
      }
      if (state.isHost && !state.passwordHash) peer.authed = true;
      if (state.isHost && state.passwordHash && !peer.authed) {
        sendControl(peer, { type: 'auth-required' });
      }
      refreshStatus();
      break;
    }
    case 'auth-required': {
      if (!state.myAuthed) askForPassword();
      break;
    }
    case 'auth': {
      // Guest -> host password check: sha256(password + room code).
      if (!state.isHost || !state.passwordHash) return;
      if (msg.hash === state.passwordHash) {
        peer.authed = true;
        sendControl(peer, { type: 'auth-result', ok: true });
        broadcastControl({ type: 'peer-authed', peerId: peer.peerId }, peer.peerId);
        refreshStatus();
      } else {
        sendControl(peer, { type: 'auth-result', ok: false });
        setTimeout(() => signalSend({ type: 'expel', peerId: peer.peerId }), 400);
      }
      break;
    }
    case 'auth-result': {
      if (msg.ok) {
        state.myAuthed = true;
        closePasswordDialog();
        // Now that the host trusts me, re-announce my files to everyone.
        for (const f of state.files.values()) {
          if (f.ownerId === 'me' && f.state === 'ready') broadcastControl(fileAddMessage(f));
        }
      } else {
        $('password-enter-error').hidden = false;
        const dlg = $('dialog-password-enter');
        if (!dlg.open) dlg.showModal();
      }
      break;
    }
    case 'peer-authed': {
      const p = state.peers.get(msg.peerId);
      if (p) { p.authed = true; refreshStatus(); }
      break;
    }
    case 'chat': {
      if (!peerAllowed(peer)) return;
      let text;
      if (msg.cipher) {
        text = await decryptChat(msg.cipher).catch(() => null);
        if (text === null) text = '[encrypted message — open the room with the full link, including the part after #, to read it]';
      } else {
        text = String(msg.text || '');
      }
      addChatMessage(peer.name, text, false);
      break;
    }
    case 'file-add': {
      if (!peerAllowed(peer)) return;
      const f = msg.file;
      if (!f || !f.id) return;
      state.files.set(f.id, {
        id: f.id, ownerId: peer.peerId, name: String(f.name || 'file'),
        size: Number(f.size) || 0, mime: String(f.mime || ''), hash: f.hash || null,
        blob: null, state: 'ready',
      });
      renderFiles();
      break;
    }
    case 'file-remove': {
      if (state.files.get(msg.fileId)?.ownerId === peer.peerId) {
        state.files.delete(msg.fileId);
        renderFiles();
      }
      break;
    }
    case 'file-request': {
      startOutgoingTransfer(peer, msg).catch(() => {});
      break;
    }
    case 'xfer-ack': {
      const t = state.transfers.get(msg.transferId);
      if (t && t.direction === 'out') { t.acked = Math.max(t.acked, Number(msg.received) || 0); }
      break;
    }
    case 'xfer-pause': {
      const t = state.transfers.get(msg.transferId);
      if (t && t.direction === 'out') pauseOutgoing(t, true);
      break;
    }
    case 'xfer-resume': {
      const t = state.transfers.get(msg.transferId);
      if (t && t.direction === 'out') resumeOutgoing(t, Number(msg.offset) || 0);
      break;
    }
    case 'xfer-cancel': {
      const t = state.transfers.get(msg.transferId);
      if (t) cancelTransfer(t, false);
      break;
    }
    case 'xfer-done': {
      const t = state.transfers.get(msg.transferId);
      if (t && t.direction === 'out') {
        t.state = msg.hashOk ? 'complete' : 'integrity-error';
        addHistory(`${msg.hashOk ? '<span class="ok">Sent</span>' : '<span class="bad">Sent but integrity check failed</span>'} — ${escapeHtml(t.name)} (${formatBytes(t.size)}) to ${escapeHtml(peer.name)}`);
        renderTransfers();
      }
      break;
    }
    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// Chat — AES-GCM with a key derived from the room key when both sides have it
// ---------------------------------------------------------------------------

async function getAesKey() {
  if (!state.key) return null;
  if (state.aesKey) return state.aesKey;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(state.key));
  state.aesKey = await crypto.subtle.importKey('raw', digest, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return state.aesKey;
}

async function encryptChat(text) {
  const key = await getAesKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(text),
  ));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0); out.set(ct, iv.length);
  return b64encode(out);
}

async function decryptChat(b64) {
  const key = await getAesKey();
  if (!key) throw new Error('no key');
  const data = b64decode(b64);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12),
  );
  return new TextDecoder().decode(pt);
}

async function sendChat() {
  const input = $('message-input');
  const text = input.value.trim();
  if (!text) return;
  const targets = [...state.peers.values()].filter((p) => p.controlOpen);
  if (!targets.length) return;
  input.value = '';
  addChatMessage('You', text, true);
  for (const peer of targets) {
    if (state.key && peer.verified) {
      sendControl(peer, { type: 'chat', cipher: await encryptChat(text) });
    } else {
      sendControl(peer, { type: 'chat', text });
    }
  }
}

function addChatMessage(from, text, mine) {
  const li = document.createElement('li');
  if (mine) li.className = 'mine';
  const who = document.createElement('span');
  who.className = 'msg-from';
  who.textContent = from;
  li.appendChild(who);
  li.appendChild(document.createTextNode(text));
  $('messages-list').appendChild(li);
  $('messages-list').scrollTop = $('messages-list').scrollHeight;
}

// ---------------------------------------------------------------------------
// Room password (light lock — host verifies over the data channel)
// ---------------------------------------------------------------------------

function askForPassword() {
  const dlg = $('dialog-password-enter');
  if (!dlg.open) dlg.showModal();
}

function closePasswordDialog() {
  const dlg = $('dialog-password-enter');
  if (dlg.open) dlg.close();
  $('password-enter-error').hidden = true;
}

function setRoomPassword(pw) {
  if (!state.isHost) return;
  state.password = pw || null;
  state.passwordHash = pw ? sha256Hex(pw + state.code) : null;
  state.roomLocked = !!pw;
  $('btn-password').textContent = pw ? 'Room password: ON — change' : 'Set room password';
  // Existing peers must (re)authenticate; brand-new peers are asked on hello.
  for (const peer of state.peers.values()) {
    if (peer.controlOpen) {
      if (pw) {
        peer.authed = false;
        sendControl(peer, { type: 'hello', name: state.name, isHost: true, keyProof: state.keyProof, locked: true });
        sendControl(peer, { type: 'auth-required' });
      } else {
        peer.authed = true;
        sendControl(peer, { type: 'hello', name: state.name, isHost: true, keyProof: state.keyProof, locked: false });
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Files — add, hash, announce, render
// ---------------------------------------------------------------------------

function fileAddMessage(f) {
  return { type: 'file-add', file: { id: f.id, name: f.name, size: f.size, mime: f.mime, hash: f.hash } };
}

function announceFile(peer, f) {
  if (peer.controlOpen) sendControl(peer, fileAddMessage(f));
}

async function hashBlob(blob) {
  const hasher = new Sha256();
  const SLICE = 4 * 1024 * 1024;
  for (let off = 0; off < blob.size; off += SLICE) {
    const buf = await blob.slice(off, Math.min(blob.size, off + SLICE)).arrayBuffer();
    hasher.update(new Uint8Array(buf));
  }
  if (blob.size === 0) hasher.update(new Uint8Array(0));
  return hasher.digestHex();
}

async function addFiles(fileList) {
  for (const file of fileList) {
    const rec = {
      id: genId(), ownerId: 'me',
      name: file.webkitRelativePath || file.name,
      size: file.size, mime: file.type || '',
      hash: null, blob: file, state: 'hashing',
    };
    state.files.set(rec.id, rec);
    renderFiles();
    try {
      rec.hash = await hashBlob(file);
      rec.state = 'ready';
      broadcastControl(fileAddMessage(rec));
    } catch {
      rec.state = 'error';
    }
    renderFiles();
  }
}

function renderPeople() {
  const list = $('people-list');
  const rows = [];
  rows.push(`<li><strong>${escapeHtml(state.name)}</strong> <span class="hint">(You)</span>
    ${state.isHost ? '<span class="badge">Host</span>' : ''}
    ${state.key ? '<span class="verified">key ✓</span>' : ''}</li>`);
  for (const peer of state.peers.values()) {
    rows.push(`<li><strong>${escapeHtml(peer.name)}</strong>
      ${peer.isHost ? '<span class="badge">Host</span>' : ''}
      ${peer.controlOpen ? '' : '<span class="hint">connecting…</span>'}
      ${peer.verified ? '<span class="verified">Verified ✓</span>' : ''}
      ${state.roomLocked === true && !peerAllowed(peer) ? '<span class="badge badge-lock">not authenticated</span>' : ''}
    </li>`);
  }
  list.innerHTML = rows.join('');
  $('people-count').textContent = `(${1 + state.peers.size})`;
}

function renderFiles() {
  const list = $('files-list');
  if (state.files.size === 0) {
    list.innerHTML = '<li class="hint">No files yet. Add one above — it stays on your device until someone downloads it.</li>';
    return;
  }
  list.innerHTML = '';
  for (const f of state.files.values()) {
    const li = document.createElement('li');
    li.dataset.fileId = f.id;
    const ownerName = f.ownerId === 'me' ? 'you' : (state.peers.get(f.ownerId)?.name || 'a device');
    let controls = '';
    if (f.ownerId === 'me') {
      controls = f.state === 'ready'
        ? `<div class="file-controls"><button class="btn btn-small" data-act="remove">Remove</button></div>`
        : '';
    } else {
      controls = `<div class="file-controls" data-role="download-controls"></div>`;
    }
    li.innerHTML = `
      <div class="file-head">
        <span class="file-name">${escapeHtml(f.name)}</span>
        <span class="file-meta">${formatBytes(f.size)} · shared by ${escapeHtml(ownerName)}</span>
      </div>
      <div class="file-status" data-role="status">${
        f.state === 'hashing' ? 'Preparing (checking the file)…'
        : f.state === 'error' ? '<span class="bad">Could not read this file.</span>'
        : f.ownerId === 'me' ? 'Ready — on your device, nothing uploaded anywhere.'
        : ''
      }</div>
      ${controls}
      <div data-role="xfers"></div>`;
    list.appendChild(li);
  }
  // Wire buttons
  for (const li of list.children) {
    const f = state.files.get(li.dataset.fileId);
    if (!f) continue;
    const removeBtn = li.querySelector('[data-act="remove"]');
    if (removeBtn) {
      removeBtn.addEventListener('click', () => {
        state.files.delete(f.id);
        broadcastControl({ type: 'file-remove', fileId: f.id });
        renderFiles();
      });
    }
    const dlBox = li.querySelector('[data-role="download-controls"]');
    if (dlBox && f.ownerId !== 'me') renderDownloadControls(f, dlBox);
  }
  renderTransfers();
}

function incomingTransferFor(fileId) {
  // Prefer a live transfer; otherwise the most recent finished one (so its
  // "Save to device" link stays visible after completion).
  let finished = null;
  for (const t of state.transfers.values()) {
    if (t.fileId !== fileId || t.direction !== 'in') continue;
    if (!['complete', 'cancelled', 'integrity-error'].includes(t.state)) return t;
    finished = t;
  }
  return finished;
}

function renderDownloadControls(f, box) {
  const t = incomingTransferFor(f.id);
  const sig = t ? `${t.id}:${t.state}:${t.saveUrl ? 'save' : ''}` : 'none';
  if (box.dataset.sig === sig) return; // avoid rebuilding buttons mid-click
  box.dataset.sig = sig;
  box.innerHTML = '';
  if (!t) {
    const btn = document.createElement('button');
    btn.className = 'btn btn-primary btn-small';
    btn.textContent = 'Download';
    if (saveMethod.kind === 'blob' && f.size > BLOB_PRACTICAL_LIMIT) {
      btn.addEventListener('click', () => {
        if (confirm(`This file is ${formatBytes(f.size)}. This browser can only save files in memory (practical limit ≈ 400 MB), so this download will probably fail. Try a current Chrome or Edge instead. Download anyway?`)) {
          startDownload(f);
        }
      });
    } else {
      btn.addEventListener('click', () => startDownload(f));
    }
    box.appendChild(btn);
    return;
  }
  const mk = (label, fn) => {
    const b = document.createElement('button');
    b.className = 'btn btn-small';
    b.textContent = label;
    b.addEventListener('click', fn);
    return b;
  };
  if (t.state === 'active' || t.state === 'starting') box.appendChild(mk('Pause', () => pauseIncoming(t)));
  if (t.state === 'paused' || t.state === 'interrupted') box.appendChild(mk('Resume', () => resumeIncoming(t)));
  if (['active', 'paused', 'interrupted', 'starting'].includes(t.state)) {
    box.appendChild(mk('Cancel', () => cancelTransfer(t, true)));
  }
  if (t.state === 'complete' && !t.saveUrl) {
    const s = document.createElement('span');
    s.className = 'verified';
    s.textContent = 'Saved to your device ✓';
    box.appendChild(s);
  }
  if (t.saveUrl) {
    const a = document.createElement('a');
    a.className = 'btn btn-small btn-primary';
    a.href = t.saveUrl;
    a.download = t.name;
    a.textContent = 'Save to device';
    box.appendChild(a);
  }
  if (t.state === 'complete' || t.state === 'cancelled' || t.state === 'integrity-error') {
    box.appendChild(mk('Download again', () => startDownload(f)));
  }
}

// Renders progress for all transfers into their file rows.
function renderTransfers() {
  for (const li of $('files-list').children) {
    const box = li.querySelector('[data-role="xfers"]');
    const status = li.querySelector('[data-role="status"]');
    if (!box) continue;
    const fileId = li.dataset.fileId;
    const f = state.files.get(fileId);
    const mine = [...state.transfers.values()].filter((t) => t.fileId === fileId);
    box.innerHTML = '';
    let statusText = null;
    for (const t of mine) {
      const div = document.createElement('div');
      const progress = document.createElement('progress');
      const done = t.direction === 'out' ? t.acked : t.received;
      progress.max = Math.max(1, t.size);
      progress.value = Math.min(done, t.size);
      const pct = t.size ? Math.floor((done / t.size) * 100) : 100;
      const peerName = state.peers.get(t.peerId)?.name || 'device';
      const arrow = t.direction === 'out' ? `Sending to ${peerName}` : `Receiving from ${peerName}`;
      let line = `${arrow} — ${pct}% · ${formatBytes(t.speed || 0)}/s · ${formatEta(t.speed > 0 ? (t.size - done) / t.speed : Infinity)}`;
      if (t.state === 'paused') line = `${arrow} — paused at ${pct}%`;
      if (t.state === 'interrupted') line = `${arrow} — connection interrupted at ${pct}%. Resume continues from here, not from zero.`;
      if (t.state === 'complete') line = t.direction === 'in'
        ? `${arrow} — complete${t.hashOk ? ' · <span class="ok">Verified ✓</span>' : ''}`
        : `${arrow} — sent`;
      if (t.state === 'integrity-error') line = `${arrow} — <span class="bad">integrity check FAILED — the file did not arrive intact. Try again.</span>`;
      if (t.state === 'cancelled') line = `${arrow} — cancelled`;
      if (t.state === 'starting') line = `${arrow} — starting…`;
      div.innerHTML = `<div class="file-status">${line}</div>`;
      if (!['complete', 'cancelled', 'integrity-error'].includes(t.state)) div.appendChild(progress);
      if (t.direction === 'out' && ['active', 'paused', 'starting'].includes(t.state)) {
        const ctrls = document.createElement('div');
        ctrls.className = 'file-controls';
        if (t.state === 'active') {
          const b = document.createElement('button');
          b.className = 'btn btn-small'; b.textContent = 'Pause';
          b.addEventListener('click', () => pauseOutgoing(t, false));
          ctrls.appendChild(b);
        }
        if (t.state === 'paused') {
          const b = document.createElement('button');
          b.className = 'btn btn-small'; b.textContent = 'Resume';
          b.addEventListener('click', () => resumeOutgoing(t, t.acked));
          ctrls.appendChild(b);
        }
        const c = document.createElement('button');
        c.className = 'btn btn-small'; c.textContent = 'Cancel';
        c.addEventListener('click', () => cancelTransfer(t, true));
        ctrls.appendChild(c);
        div.appendChild(ctrls);
      }
      box.appendChild(div);
      if (t.direction === 'in') statusText = '';
    }
    if (status && f && f.ownerId !== 'me' && statusText === null && !incomingTransferFor(fileId)) {
      // leave default status text as rendered
    }
    // Refresh download buttons (pause/resume availability may have changed)
    const dlBox = li.querySelector('[data-role="download-controls"]');
    if (dlBox && f && f.ownerId !== 'me') renderDownloadControls(f, dlBox);
  }
}

// Speed sampling: every 500 ms compute per-transfer throughput.
setInterval(() => {
  const now = performance.now();
  let changed = false;
  for (const t of state.transfers.values()) {
    if (t.state !== 'active') { t.speed = 0; continue; }
    const current = t.direction === 'out' ? t.acked : t.received;
    if (t._lastT) {
      const dt = (now - t._lastT) / 1000;
      if (dt > 0) t.speed = Math.max(0, (current - t._lastBytes) / dt);
    }
    t._lastT = now;
    t._lastBytes = current;
    changed = true;
  }
  if (changed && state.view === 'room') renderTransfers();
}, 500);

// ---------------------------------------------------------------------------
// Transfers — receiving side
// ---------------------------------------------------------------------------

async function startDownload(f) {
  const peer = state.peers.get(f.ownerId);
  if (!peer || !peer.controlOpen) {
    showBanner('That device is not connected right now.');
    return;
  }
  // Clear any finished attempt for this file so the fresh one takes over the row.
  for (const old of [...state.transfers.values()]) {
    if (old.fileId === f.id && old.direction === 'in' && ['complete', 'cancelled', 'integrity-error'].includes(old.state)) {
      state.transfers.delete(old.id);
    }
  }
  const t = {
    id: genId(), fileId: f.id, peerId: peer.peerId, direction: 'in',
    name: f.name, size: f.size, hash: f.hash,
    received: 0, acked: 0, sent: 0, speed: 0,
    state: 'starting', hasher: new Sha256(),
    sink: null, writeChain: Promise.resolve(), channel: null,
    saveUrl: null, hashOk: false, _lastAck: 0, _lastT: 0, _lastBytes: 0,
  };
  state.transfers.set(t.id, t);
  try {
    t.sink = await openSink(f, t);
  } catch (err) {
    // User cancelled the save picker — silent abort.
    state.transfers.delete(t.id);
    renderTransfers();
    return;
  }
  t.state = 'active';
  sendControl(peer, { type: 'file-request', fileId: f.id, transferId: t.id, offset: 0 });
  renderTransfers();
}

async function openSink(f, t) {
  if (saveMethod.kind === 'fs') {
    const handle = await window.showSaveFilePicker({ suggestedName: f.name }); // may throw AbortError
    const writable = await handle.createWritable();
    return { kind: 'fs', writable };
  }
  if (saveMethod.kind === 'opfs') {
    const root = await navigator.storage.getDirectory();
    const name = `easydrop-${t.id}`;
    try { await root.removeEntry(name); } catch { /* not there */ }
    const fh = await root.getFileHandle(name, { create: true });
    const writable = await fh.createWritable();
    return { kind: 'opfs', writable, root, name, fileHandle: fh };
  }
  return { kind: 'blob', chunks: [] };
}

async function discardSink(t) {
  if (!t.sink) return;
  try {
    if (t.sink.kind === 'fs') await t.sink.writable.abort();
    else if (t.sink.kind === 'opfs') {
      try { await t.sink.writable.abort(); } catch { /* noop */ }
      try { await t.sink.root.removeEntry(t.sink.name); } catch { /* noop */ }
    }
  } catch { /* noop */ }
  t.sink = null;
}

function setupIncomingTransferChannel(peer, channel) {
  const transferId = channel.label.split(':')[1];
  const t = state.transfers.get(transferId);
  if (!t || t.direction !== 'in') { try { channel.close(); } catch { /* noop */ } return; }
  t.channel = channel;
  t.interrupted = false;
  if (t.state === 'interrupted') t.state = 'active';
  channel.addEventListener('message', (ev) => {
    if (typeof ev.data === 'string') {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === 'xfer-header') {
        if (msg.startOffset !== t.received) {
          cancelTransfer(t, true);
          showBanner(`Resume mismatch for ${t.name} — the transfer was restarted for safety.`);
        }
      } else if (msg.type === 'xfer-end') {
        finishIncoming(t).catch(() => {});
      }
      return;
    }
    // Binary chunk
    const bytes = new Uint8Array(ev.data);
    t.hasher.update(bytes);
    t.received += bytes.byteLength;
    if (t.sink?.kind === 'blob') {
      t.sink.chunks.push(bytes);
    } else if (t.sink) {
      const copy = bytes.slice();
      t.writeChain = t.writeChain.then(() => t.sink.writable.write(copy)).catch(() => {});
    }
    const now = performance.now();
    if (t.received - t._lastAck >= 256 * 1024 || now - t._lastT > 300) {
      t._lastAck = t.received;
      sendControl(peer, { type: 'xfer-ack', transferId: t.id, received: t.received });
    }
    if (!t._renderT || now - t._renderT > 250) {
      t._renderT = now;
      renderTransfers();
    }
  });
  channel.addEventListener('close', () => {
    if (t.state === 'active' || t.state === 'paused') {
      t.state = 'interrupted';
      t.interrupted = true;
      renderTransfers();
    }
  });
}

async function finishIncoming(t) {
  const peer = state.peers.get(t.peerId);
  try { await t.writeChain; } catch { /* write errors surface via hash */ }
  if (t.sink && t.sink.kind !== 'blob') {
    try { await t.sink.writable.close(); } catch { /* noop */ }
  }
  const gotHash = t.hasher.digestHex();
  t.hashOk = !!t.hash && gotHash === t.hash;
  if (t.received !== t.size) {
    t.state = 'integrity-error';
  } else if (t.hash && !t.hashOk) {
    t.state = 'integrity-error';
  } else {
    t.state = 'complete';
    if (t.sink?.kind === 'opfs') {
      const file = await t.sink.fileHandle.getFile();
      t.saveUrl = URL.createObjectURL(file);
    } else if (t.sink?.kind === 'blob') {
      t.saveUrl = URL.createObjectURL(new Blob(t.sink.chunks, { type: '' }));
      t.sink.chunks = [];
    }
  }
  if (peer) sendControl(peer, { type: 'xfer-done', transferId: t.id, hashOk: t.state === 'complete' });
  addHistory(t.state === 'complete'
    ? `<span class="ok">Received</span> — ${escapeHtml(t.name)} (${formatBytes(t.size)}) from ${escapeHtml(peer?.name || 'device')}${t.hashOk ? ' · Verified ✓' : ''}${t.sink?.kind === 'fs' ? ' · saved to your device' : ''}`
    : `<span class="bad">Failed integrity check</span> — ${escapeHtml(t.name)} did not arrive intact`);
  renderTransfers();
  renderFiles();
}

function pauseIncoming(t) {
  const peer = state.peers.get(t.peerId);
  t.state = 'paused';
  if (peer) sendControl(peer, { type: 'xfer-pause', transferId: t.id });
  renderTransfers();
}

function resumeIncoming(t) {
  const peer = state.peers.get(t.peerId);
  if (!peer || !peer.pc) { showBanner('That device is not connected right now.'); return; }
  t.state = 'active';
  if (t.channel && t.channel.readyState === 'open') {
    sendControl(peer, { type: 'xfer-resume', transferId: t.id, offset: t.received });
  } else {
    // Channel dropped: re-request from the last received byte offset.
    t.channel = null;
    sendControl(peer, { type: 'file-request', fileId: t.fileId, transferId: t.id, offset: t.received });
  }
  renderTransfers();
}

// ---------------------------------------------------------------------------
// Transfers — sending side
// ---------------------------------------------------------------------------

async function startOutgoingTransfer(peer, msg) {
  const f = state.files.get(msg.fileId);
  if (!f || f.ownerId !== 'me' || !f.blob) return;
  let t = state.transfers.get(msg.transferId);
  if (!t) {
    t = {
      id: msg.transferId, fileId: f.id, peerId: peer.peerId, direction: 'out',
      name: f.name, size: f.size, hash: f.hash,
      received: 0, acked: Number(msg.offset) || 0, sent: Number(msg.offset) || 0, speed: 0,
      state: 'starting', channel: null, paused: false, cancelled: false,
      _lastT: 0, _lastBytes: 0, _wake: null,
    };
    state.transfers.set(t.id, t);
  }
  t.cancelled = false;
  t.paused = false;
  t.offset = Number(msg.offset) || 0;
  t.acked = Math.max(t.acked, t.offset);
  if (!peer.pc) return;
  const attempt = Math.random().toString(36).slice(2, 8);
  const channel = peer.pc.createDataChannel(`xfer:${t.id}:${attempt}`);
  channel.binaryType = 'arraybuffer';
  channel.bufferedAmountLowThreshold = 256 * 1024;
  t.channel = channel;
  t.state = 'active';
  channel.addEventListener('open', () => {
    channel.send(JSON.stringify({
      type: 'xfer-header', transferId: t.id, fileId: f.id,
      name: f.name, size: f.size, hash: f.hash, startOffset: t.offset,
    }));
    pumpOutgoing(t, f).catch(() => { t.state = 'interrupted'; renderTransfers(); });
  });
  channel.addEventListener('close', () => {
    if (!t.cancelled && t.state === 'active') { t.state = 'interrupted'; renderTransfers(); }
  });
  renderTransfers();
}

async function pumpOutgoing(t, f) {
  const channel = t.channel;
  let offset = t.offset;
  while (offset < f.size) {
    if (t.cancelled) return;
    if (t.paused) {
      await new Promise((resolve) => { t._wake = resolve; });
      if (t.cancelled) return;
      offset = t.offset; // resume may reposition (receiver's last received byte)
      continue;
    }
    if (!channel || channel.readyState !== 'open') { t.state = 'interrupted'; renderTransfers(); return; }
    if (channel.bufferedAmount > 4 * 1024 * 1024) {
      await new Promise((resolve) => {
        channel.addEventListener('bufferedamountlow', resolve, { once: true });
        setTimeout(resolve, 1000);
      });
      continue;
    }
    const len = Math.min(CHUNK_SIZE, f.size - offset);
    const buf = await f.blob.slice(offset, offset + len).arrayBuffer();
    if (t.cancelled) return;
    if (t.paused) continue; // re-read at the (possibly new) offset next round
    try {
      channel.send(buf);
    } catch {
      t.state = 'interrupted';
      renderTransfers();
      return;
    }
    offset += len;
    t.sent = offset;
    t.offset = offset;
  }
  if (!t.cancelled && channel && channel.readyState === 'open') {
    try { channel.send(JSON.stringify({ type: 'xfer-end', transferId: t.id, total: f.size })); } catch { /* noop */ }
    t.state = 'sent';
  }
  renderTransfers();
}

function pauseOutgoing(t, byReceiver) {
  t.paused = true;
  if (t.state === 'active') t.state = 'paused';
  if (!byReceiver) { /* sender-side pause is local; receiver sees acks stop */ }
  renderTransfers();
}

function resumeOutgoing(t, offset) {
  if (Number.isFinite(offset)) t.offset = offset;
  t.paused = false;
  if (t.state === 'paused' || t.state === 'interrupted') t.state = 'active';
  if (t._wake) { const wake = t._wake; t._wake = null; wake(); }
  renderTransfers();
}

async function cancelTransfer(t, notifyPeer) {
  const peer = state.peers.get(t.peerId);
  t.cancelled = true;
  if (t._wake) { const wake = t._wake; t._wake = null; wake(); }
  if (notifyPeer && peer) sendControl(peer, { type: 'xfer-cancel', transferId: t.id });
  try { t.channel?.close(); } catch { /* noop */ }
  if (t.direction === 'in') await discardSink(t);
  t.state = 'cancelled';
  addHistory(`<span class="bad">Cancelled</span> — ${escapeHtml(t.name)} (${t.direction === 'out' ? 'sending to' : 'from'} ${escapeHtml(peer?.name || 'device')})`);
  renderTransfers();
  renderFiles();
}

// ---------------------------------------------------------------------------
// Diagnostics — a real STUN/ICE probe in the browser
// ---------------------------------------------------------------------------

async function runDiagnostics() {
  const list = $('diagnostics-results');
  list.innerHTML = '';
  const add = (html) => {
    const li = document.createElement('li');
    li.innerHTML = html;
    list.appendChild(li);
  };
  add(`Signaling server: ${state.wsOpen ? '<strong>reachable ✓</strong>' : '<strong>not reachable ✗</strong>'} — it only introduces devices; it never carries files.`);
  add(`Saving on this browser: ${escapeHtml(saveMethod.label)}`);

  const servers = iceServers();
  add(`Testing peer connection paths (${servers.length} STUN/TURN entr${servers.length === 1 ? 'y' : 'ies'})…`);
  const result = await probeIce(servers, 4000);
  const counts = result.reduce((acc, c) => { acc[c] = (acc[c] || 0) + 1; return acc; }, {});
  const parts = Object.entries(counts).map(([k, v]) => `${v} × ${k}`).join(', ');
  add(`Connection candidates found: <strong>${result.length ? escapeHtml(parts) : 'none'}</strong>.`);
  if (counts.srflx || counts.relay) {
    add('<strong>Looks good ✓</strong> — this browser can be reached by other devices over the internet, so direct transfers should work.');
  } else if (counts.host) {
    add('<strong>Only local-network candidates.</strong> Transfers to devices on the same Wi-Fi/LAN should work, but devices on other networks will likely fail — a TURN relay (see README) fixes that.');
  } else {
    add('<strong>No candidates at all ✗</strong> — this network appears to block peer-to-peer setup entirely (strict firewall/VPN). Try another network.');
  }
}

function probeIce(servers, timeoutMs) {
  return new Promise((resolve) => {
    const types = [];
    let pc;
    try {
      pc = new RTCPeerConnection({ iceServers: servers });
    } catch {
      resolve(types);
      return;
    }
    pc.addEventListener('icecandidate', (ev) => {
      if (ev.candidate) types.push(ev.candidate.type || 'unknown');
    });
    pc.createDataChannel('probe');
    pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(() => {});
    setTimeout(() => { try { pc.close(); } catch { /* noop */ } resolve(types); }, timeoutMs);
  });
}

// ---------------------------------------------------------------------------
// Room entry / exit
// ---------------------------------------------------------------------------

function updateShareCard() {
  const link = `${location.origin}/${state.code}${state.key ? `#k=${state.key}` : ''}`;
  $('share-link').value = link;
  $('room-code-text').textContent = state.code;
  $('qr-img').src = `/qr?text=${encodeURIComponent(link)}`;
}

function enterRoom({ mode, code, key }) {
  state.code = code;
  state.key = key || null;
  state.keyProof = state.key ? sha256Hex(state.key) : null;
  state.aesKey = null;
  showView('room');
  updateShareCard();
  if (mode === 'create') {
    history.replaceState(null, '', `/${code}${key ? `#k=${key}` : ''}`);
  }
  $('save-method-note').textContent = saveMethod.label;
  $('save-method-note').classList.toggle('warn', saveMethod.warn);
  setStatus('wait', 'Connecting…');
  connectSignaling(mode);
  refreshStatus();
}

function leaveRoom() {
  state.intentionalClose = true;
  try { signalSend({ type: 'leave' }); } catch { /* noop */ }
  location.assign('/');
}

function closeRoom() {
  state.intentionalClose = true;
  try { signalSend({ type: 'close-room' }); } catch { /* noop */ }
  location.assign('/');
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function init() {
  // Home
  $('btn-create').addEventListener('click', () => {
    const code = generateRoomCode();
    const key = generateRoomKey();
    enterRoom({ mode: 'create', code, key });
  });
  const doJoin = () => {
    const parsed = parseRoomInput($('join-input').value);
    const err = $('join-error');
    if (!parsed) {
      err.textContent = 'That does not look like a room code or link. Codes look like abc-defg-hij.';
      err.hidden = false;
      return;
    }
    err.hidden = true;
    enterRoom({ mode: 'join', code: parsed.code, key: parsed.key });
  };
  $('btn-join').addEventListener('click', doJoin);
  $('join-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') doJoin(); });

  // Room: share
  $('btn-copy').addEventListener('click', async () => {
    const input = $('share-link');
    try {
      await navigator.clipboard.writeText(input.value);
      $('btn-copy').textContent = 'Copied ✓';
    } catch {
      input.select();
      document.execCommand('copy');
      $('btn-copy').textContent = 'Copied ✓';
    }
    setTimeout(() => { $('btn-copy').textContent = 'Copy'; }, 1600);
  });

  // Room: people / password / leave
  $('btn-rename').addEventListener('click', () => {
    $('rename-input').value = state.name;
    $('dialog-rename').showModal();
  });
  $('btn-rename-save').addEventListener('click', (e) => {
    e.preventDefault();
    const name = $('rename-input').value.trim().slice(0, 40);
    if (name) {
      state.name = name;
      localStorage.setItem('easydrop-name', name);
      signalSend({ type: 'rename', name });
      broadcastControl({ type: 'hello', name, isHost: state.isHost, keyProof: state.keyProof, locked: state.roomLocked === true });
      refreshStatus();
    }
    $('dialog-rename').close();
  });
  $('btn-password').addEventListener('click', () => {
    $('password-set-input').value = '';
    $('dialog-password-set').showModal();
  });
  $('btn-password-save').addEventListener('click', (e) => {
    e.preventDefault();
    setRoomPassword($('password-set-input').value);
    $('dialog-password-set').close();
  });
  $('btn-password-enter-save').addEventListener('click', (e) => {
    e.preventDefault();
    const pw = $('password-enter-input').value;
    const host = state.hostPeerId ? state.peers.get(state.hostPeerId) : null;
    if (host) {
      sendControl(host, { type: 'auth', hash: sha256Hex(pw + state.code) });
      $('password-enter-error').hidden = true;
    }
  });
  $('btn-leave').addEventListener('click', leaveRoom);
  $('btn-close-room').addEventListener('click', () => {
    if (confirm('Close this room for everyone connected?')) closeRoom();
  });

  // Files: pickers, drag & drop, paste
  $('btn-pick-files').addEventListener('click', () => $('file-input').click());
  $('btn-pick-folder').addEventListener('click', () => $('folder-input').click());
  $('file-input').addEventListener('change', (e) => { addFiles([...e.target.files]); e.target.value = ''; });
  $('folder-input').addEventListener('change', (e) => { addFiles([...e.target.files]); e.target.value = ''; });
  let dragDepth = 0;
  window.addEventListener('dragenter', (e) => {
    if (state.view !== 'room') return;
    e.preventDefault();
    dragDepth++;
    $('drop-overlay').hidden = false;
  });
  window.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) $('drop-overlay').hidden = true;
  });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    dragDepth = 0;
    $('drop-overlay').hidden = true;
    if (state.view === 'room' && e.dataTransfer?.files?.length) addFiles([...e.dataTransfer.files]);
  });
  window.addEventListener('paste', (e) => {
    if (state.view !== 'room') return;
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) addFiles(files);
  });

  // Messages
  $('btn-send-message').addEventListener('click', sendChat);
  $('message-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') sendChat(); });

  // Diagnostics
  const openDiagnostics = () => { $('dialog-diagnostics').showModal(); runDiagnostics(); };
  $('btn-diagnostics-1').addEventListener('click', openDiagnostics);
  $('btn-error-diagnostics').addEventListener('click', openDiagnostics);
  $('btn-notice-diagnostics').addEventListener('click', openDiagnostics);
  $('btn-diagnostics-run').addEventListener('click', runDiagnostics);
  $('btn-error-dismiss').addEventListener('click', hideBanner);

  // Notice actions
  $('btn-notice-home').addEventListener('click', () => location.assign('/'));
  $('btn-notice-retry').addEventListener('click', () => location.reload());

  window.addEventListener('beforeunload', () => {
    try { signalSend({ type: 'leave' }); } catch { /* noop */ }
  });

  // Opened from a room link? /<code>#k=<key>
  const pathMatch = location.pathname.match(/^\/([a-z]{3}-[a-z]{4}-[a-z]{3})$/);
  const hashMatch = location.hash.match(/#k=([A-Za-z0-9_-]{8,})/);
  if (pathMatch && isValidRoomCode(pathMatch[1])) {
    enterRoom({ mode: 'join', code: pathMatch[1], key: hashMatch ? hashMatch[1] : null });
  } else {
    showView('home');
    setStatus('idle', 'Not in a room');
  }
}

init();
