# EasyDrop

Send files and messages **directly between your own devices** — phone ↔ laptop,
laptop ↔ phone — with no account and no setup beyond opening a link.

**Files are never uploaded to or stored on the server.** The small Node.js
server in this repo only *introduces* devices to each other (rooms, presence,
and WebRTC connection setup over a WebSocket). File bytes and messages travel
over direct, encrypted browser-to-browser WebRTC connections. When the page
closes, nothing of yours remains anywhere.

## Highlights

- Rooms with a shareable link + QR code. The link carries a secret key after
  `#` — that part is never sent to any server, and devices that share the same
  key are marked **Verified ✓**. (Anyone with the full link can join, so share
  it only with your own devices.)
- Files up to **2 GB**: the receiver streams the file straight to disk, so
  memory use stays flat. SHA-256 is computed on both sides; the receiver shows
  **Verified ✓** only if the file arrived bit-for-bit intact.
- Pause / Resume (resume continues from the last received byte — not from
  zero), Cancel on both sides, live progress, speed and ETA.
- Built-in chat for the room (ephemeral — only people in the room right now
  can see messages; nothing is saved). Chat is additionally AES-GCM encrypted
  with the room key when both sides joined via the full link.
- Optional room password (a light lock the host device checks — it keeps
  casual joiners out; it is not strong authentication).
- Honest status and errors: real connection states, specific failure messages,
  and a built-in **Check connection** diagnostics panel that runs an actual
  STUN/ICE probe in your browser.
- A session history list (this session only — nothing is kept).

## Run it

You need **Node.js LTS (18 or newer)** — the same commands work on Windows,
macOS and Linux.

```bash
npm install
npm start
```

Then open **http://localhost:8787** in your browser, click **Create a room**,
and open the room link (or scan the QR code) on your other device.

Run the tests with:

```bash
npm test
```

## Using it with a phone

WebRTC needs a *secure context* on the phone. `http://localhost` only counts
as secure on the same machine, so for a phone pick one of these:

### Option A — same Wi-Fi, built-in HTTPS (simplest at home)

```bash
# Windows (PowerShell):  $env:EASYDROP_HTTPS="1"; npm start
# macOS / Linux:         EASYDROP_HTTPS=1 npm start
EASYDROP_HTTPS=1 npm start
```

EasyDrop generates a self-signed certificate once (cached in `./data/`) and
serves `https://<your-computer's-LAN-IP>:8787`. The phone's browser will warn
that the certificate is not trusted — accept the warning **once** (it is your
own machine and your own certificate) and the site works normally.

### Option B — different networks (phone on mobile data, etc.)

Put EasyDrop behind any HTTPS tunnel or host — for example a Cloudflare
Tunnel, `ngrok http 8787`, Tailscale, or a small VPS with a reverse proxy
that terminates HTTPS. Run plain `npm start` and point the tunnel at port
8787. Because files never pass through the server, the tunnel only ever
carries the tiny signaling traffic.

> Note: on some strict networks (corporate/school Wi-Fi, some mobile NATs) a
> direct peer connection cannot be established. The **Check connection**
> button in the room explains what your browser found. Adding a TURN relay
> (below) makes connections work on almost any network.

## Optional: your own TURN relay

By default EasyDrop uses two public STUN servers
(`stun.l.google.com:19302`, `stun:stun.cloudflare.com:3478`). STUN is enough
for most home networks. If you run a TURN server (e.g. coturn), add it via
environment variables — the server injects it to browsers as
`window.EASYDROP_ICE`:

```bash
EASYDROP_TURN_URL="turn:turn.example.com:3478" \
EASYDROP_TURN_USERNAME="myuser" \
EASYDROP_TURN_PASSWORD="mypassword" \
npm start
```

## How a file gets from A to B (and where it does *not* go)

1. Device A creates a room; the server remembers only "room code → connected
   devices" while the page is open. No database, nothing on disk.
2. Device B opens the link; the server introduces A and B (WebRTC signaling).
3. A and B open a direct encrypted connection (WebRTC / DTLS). The server
   steps out — it cannot see file bytes, file contents, or chat.
4. B downloads: A announces file metadata (name, size, SHA-256). B picks
   where to save; A streams 64 KB chunks; B writes them as they arrive and
   verifies the hash at the end.

### Receiver save methods (shown in the room, per browser)

| Priority | Method | Practical limit |
|---|---|---|
| 1 | File System Access API — streams to a file you pick (Chrome/Edge desktop & Android) | Free disk space — this is what makes 2 GB work |
| 2 | OPFS staging in browser storage, then a "Save to device" link | The browser's storage quota on that device |
| 3 | In-memory Blob (legacy fallback) | ≈ 400 MB — the UI warns you before you start |

## Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `PORT` | `8787` | Port to listen on |
| `EASYDROP_HTTPS` | *(off)* | `1` = serve HTTPS/WSS with a self-signed cert from `./data/` |
| `EASYDROP_TURN_URL` | *(none)* | Optional TURN server URL |
| `EASYDROP_TURN_USERNAME` / `EASYDROP_TURN_PASSWORD` | *(none)* | TURN credentials |

## Layout

```
server/server.js   signaling + static + /qr + /config.js (never touches file data)
public/            the web app (vanilla JS, no build step, no CDN — works offline from the local server)
public/js/app.js   room UI, WebRTC mesh, transfers, chat, diagnostics
public/js/shared.js room codes, chunk/resume math, incremental SHA-256
tests/             node --test suite (unit + live signaling integration)
```

## Privacy notes

- No accounts, no cookies set by EasyDrop, no analytics, no database.
- The room key lives only in the URL fragment (`#k=…`); browsers never send
  fragments to servers, and EasyDrop's server never logs it.
- Chat and file metadata are visible to people in the room — for personal
  use, treat the room link like a key to your house.
