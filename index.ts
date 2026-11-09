/**
 * HipnoType Relay — mini-service on port 3005.
 *
 * Implements spec §4.3 + §13 (production architecture):
 *  - POST /api/v1/register        (install nonce → serverId + tunnelSecret + token)
 *  - POST /api/v1/rotate          (Bearer tunnelSecret — two-phase token rotation)
 *  - POST /api/v1/deregister      (Bearer tunnelSecret — clean removal)
 *  - WS   /tunnel-socket          (panel tunnel: auth, ping/pong, request/response proxy)
 *  - WS   /server/panel/:token/socket.io/*  (browser WebSocket pass-through — terminal)
 *  - ALL  /server/panel/:token/*  (routes to the matching tunnel; identical generic
 *                                  404 for unknown/rotated/revoked tokens; per-IP
 *                                  rate limiting + temporary bans for repeated 404s)
 *  - GET  /healthz, /metricsz     (health + Prometheus-style metrics)
 *
 * HTML pass-through rewriting (production path, browser → Vercel rewrite → here):
 *  - injects window.__HIPNO_BASE__ + window.__HIPNO_RELAY_ORIGIN__ and sets
 *    __webpack_public_path__ so the panel's API calls and chunks resolve under
 *    /server/panel/<token>/ (the panel is built with no basePath — the token
 *    rotates, so it cannot be baked in).
 *  - rewrites asset URLs ("/_next/…", "/logo.svg", "/favicon…") in HTML and CSS.
 *  - when the request arrives via the sandbox gateway (?XTransformPort=N),
 *    injects window.__HIPNO_PORT__=N so client calls keep using the gateway.
 *
 * Stores only hashes: sha256(token), sha256(tunnelSecret), sha256(nonce).
 * Never stores panel passwords, sessions or request bodies.
 */
import { createServer, IncomingMessage, ServerResponse } from "http";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { Server, Socket } from "socket.io";
import { WebSocket as WsClient, WebSocketServer as WsServerForUpgrades } from "ws";

const PORT = 3005;
const STORE_FILE = path.join(import.meta.dir, "data", "relay-store.json");
/** Public origin of this relay — injected into panel pages for terminal WS routing. */
const RELAY_PUBLIC_ORIGIN = process.env.RELAY_PUBLIC_ORIGIN || "https://hipno-relay.mangocloud.cyou";

interface ServerRecord {
  serverId: string;
  tokenHashes: { hash: string; active: boolean; createdAt: number }[];
  secretHash: string;
  nonceHash: string;
  label: string;
  version: string;
  online: boolean;
  lastSeen: number;
}

interface Store {
  servers: ServerRecord[];
}

function loadStore(): Store {
  try {
    return JSON.parse(fs.readFileSync(STORE_FILE, "utf8")) as Store;
  } catch {
    return { servers: [] };
  }
}

function saveStore() {
  fs.mkdirSync(path.dirname(STORE_FILE), { recursive: true });
  fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2));
}

const store = loadStore();
const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");

// ---------------------------------------------------------------- metrics
const metrics = {
  registrationsTotal: 0,
  rotationsTotal: 0,
  requestsProxiedTotal: 0,
  unknownTokenTotal: 0,
  bannedIpsTotal: 0,
  wsBridgesTotal: 0,
};

// ---------------------------------------------------------------- rate limiting
const RATE_LIMIT_PER_MIN = 60;
const BAN_THRESHOLD_404 = 20;
const BAN_MS = 10 * 60_000;

const rl = new Map<string, { hits: number[]; unknown404: number[]; bannedUntil: number }>();

function rlCheck(ip: string): { allowed: boolean; banned: boolean } {
  const now = Date.now();
  const e = rl.get(ip) || { hits: [], unknown404: [], bannedUntil: 0 };
  if (e.bannedUntil > now) return { allowed: false, banned: true };
  e.hits = e.hits.filter((t) => now - t < 60_000);
  if (e.hits.length >= RATE_LIMIT_PER_MIN) {
    rl.set(ip, e);
    return { allowed: false, banned: false };
  }
  e.hits.push(now);
  rl.set(ip, e);
  return { allowed: true, banned: false };
}

function noteUnknown404(ip: string): boolean {
  const now = Date.now();
  const e = rl.get(ip) || { hits: [], unknown404: [], bannedUntil: 0 };
  e.unknown404 = e.unknown404.filter((t) => now - t < 5 * 60_000);
  e.unknown404.push(now);
  let banned = false;
  if (e.unknown404.length >= BAN_THRESHOLD_404) {
    e.bannedUntil = now + BAN_MS;
    metrics.bannedIpsTotal += 1;
    banned = true;
  }
  rl.set(ip, e);
  return banned;
}

// ---------------------------------------------------------------- helpers
const BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
function randomBase62(len: number): string {
  const out: string[] = [];
  const bytes = crypto.randomBytes(len * 2);
  let i = 0;
  while (out.length < len) {
    if (i >= bytes.length) {
      bytes.copy(crypto.randomBytes(bytes.length), 0);
      i = 0;
    }
    const b = bytes[i++];
    if (b < 256 - (256 % 62)) out.push(BASE62[b % 62]);
  }
  return out.join("");
}

const NOT_FOUND_BODY =
  "<html><head><title>404</title></head><body><h1>404</h1><p>Not found.</p></body></html>";
function sendNotFound(res: ServerResponse, withDelay = true) {
  const send = () => {
    res.writeHead(404, {
      "content-type": "text/html",
      "content-length": String(NOT_FOUND_BODY.length),
    });
    res.end(NOT_FOUND_BODY);
  };
  if (withDelay) setTimeout(send, 35 + Math.floor(Math.random() * 25));
  else send();
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", () => resolve(Buffer.alloc(0)));
  });
}

function bearerSecret(req: IncomingMessage): string | null {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : null;
}

function findServerByTokenHash(tokenHash: string): ServerRecord | null {
  for (const s of store.servers) {
    if (s.tokenHashes.some((t) => t.active && t.hash === tokenHash)) return s;
  }
  return null;
}

// ---------------------------------------------------------------- HTML / CSS rewriting
/**
 * Rewrite a proxied panel response body so asset URLs and client runtime state
 * resolve under the token base path.
 */
function rewriteBody(body: Buffer, base: string, contentType: string, gatewayPort: number | null): Buffer {
  const ct = (contentType || "").toLowerCase();

  if (ct.includes("text/html")) {
    let html = body.toString("utf8");
    // asset URLs (Next emits absolute paths; the quote keeps the match tight)
    html = html.split('"/_next/').join(`"${base}/_next/`);
    html = html.split("'_next/").join(`'${base}/_next/`); // rare inlined variants
    html = html.split('href="/logo.svg"').join(`href="${base}/logo.svg"`);
    html = html.split('href="/favicon').join(`href="${base}/favicon`);
    html = html.split('href="/apple-touch-icon').join(`href="${base}/apple-touch-icon`);
    html = html.split('href="/site.webmanifest"').join(`href="${base}/site.webmanifest`);
    html = html.split('src="/logo.svg"').join(`src="${base}/logo.svg"`);
    // runtime config for the panel client (api base + chunk publicPath + relay WS origin)
    const inject =
      `<script>` +
      `window.__HIPNO_BASE__=${JSON.stringify(base)};` +
      (gatewayPort ? `window.__HIPNO_PORT__=${gatewayPort};` : "") +
      `window.__HIPNO_RELAY_ORIGIN__=${JSON.stringify(RELAY_PUBLIC_ORIGIN)};` +
      `window.__HIPNO_PUBLIC_URL__=${JSON.stringify(RELAY_PUBLIC_ORIGIN)};` +
      `if(typeof __webpack_public_path__!=="undefined"){__webpack_public_path__=${JSON.stringify(base + "/_next/")};}` +
      `</script>`;
    if (html.includes("<head>")) html = html.replace("<head>", `<head>${inject}`);
    else if (html.includes("<head ")) html = html.replace(/<head([^>]*)>/, `<head$1>${inject}`);
    else if (html.includes("<html")) html = html.replace(/<html([^>]*)>/, `<html$1>${inject}`);
    else return body; // not a real HTML page — leave untouched
    return Buffer.from(html, "utf8");
  }

  if (ct.includes("text/css")) {
    // fonts and url() refs inside CSS are emitted as absolute /_next/… paths
    const css = body.toString("utf8").split("/_next/").join(`${base}/_next/`);
    return Buffer.from(css, "utf8");
  }

  return body;
}

// ---------------------------------------------------------------- socket.io tunnel
const httpServer = createServer();
// destroyUpgrade:false — unhandled upgrades (our /server/panel/… WS bridge)
// must survive engine.io's own upgrade listener.
const io = new Server(httpServer, { path: "/tunnel-socket", destroyUpgrade: false, cors: { origin: "*" } });

interface PendingEntry {
  res: ServerResponse;
  timer: NodeJS.Timeout;
  base: string; // "" for non-token routes
  gatewayPort: number | null;
}
const pending = new Map<string, PendingEntry>();
let reqCounter = 0;

io.on("connection", (socket: Socket) => {
  let serverId: string | null = null;

  socket.on("auth", (data: { serverId: string; secret: string }) => {
    const rec = store.servers.find((s) => s.serverId === data.serverId);
    if (!rec || rec.secretHash !== data.secret) {
      socket.emit("auth_failed", { error: "invalid serverId or tunnel secret" });
      return;
    }
    serverId = data.serverId;
    rec.online = true;
    rec.lastSeen = Date.now();
    saveStore();
    socket.join(`server:${serverId}`);
    socket.emit("authenticated", { heartbeatIntervalMs: 15000 });
  });

  socket.on("ping", (_data: unknown, ack?: (resp: unknown) => void) => {
    if (serverId) {
      const rec = store.servers.find((s) => s.serverId === serverId);
      if (rec) rec.lastSeen = Date.now();
    }
    if (ack) ack({ pong: true, ts: Date.now() });
  });

  socket.on(
    "response",
    (data: { id: string; status: number; headers: Record<string, string>; bodyB64: string }) => {
      const entry = pending.get(data.id);
      if (!entry) return;
      pending.delete(data.id);
      clearTimeout(entry.timer);
      let body = Buffer.from(data.bodyB64 || "", "base64");
      const headers = { ...data.headers };
      delete headers["transfer-encoding"];
      delete headers["content-encoding"]; // already decoded by the panel's fetch
      if (entry.base) {
        const ct = headers["content-type"] || headers["Content-Type"] || "";
        if (ct.includes("text/html") || ct.includes("text/css")) {
          try {
            body = rewriteBody(body, entry.base, ct, entry.gatewayPort);
          } catch {
            /* on any rewrite error, serve the original body */
          }
        }
      }
      headers["content-length"] = String(body.length);
      try {
        entry.res.writeHead(data.status, headers);
        entry.res.end(body);
      } catch {
        /* client gone */
      }
    }
  );

  // ---- WebSocket bridge (browser ↔ tunnel ↔ local WS service, e.g. terminal)
  socket.on("wsopened", (data: { id: string; ok: boolean; error?: string }) => {
    console.log(`[hipno-relay] wsopened ${data.id} ok=${data.ok} ${data.error || ""}`);
    const bridge = wsBridges.get(data.id);
    if (!bridge) return;
    if (!data.ok) {
      try { bridge.browserWs.close(1011); } catch {}
      wsBridges.delete(data.id);
      return;
    }
    bridge.panelReady = true;
    // flush frames buffered while the panel side was connecting
    for (const frame of bridge.buffer) bridge.browserWs.send(frame.data, { binary: frame.binary });
    bridge.buffer = [];
  });

  socket.on("wsdata", (data: { id: string; b64: string; binary?: boolean }) => {
    const bridge = wsBridges.get(data.id);
    if (!bridge || bridge.browserWs.readyState !== WsClient.OPEN) {
      console.log(`[hipno-relay] wsdata DROPPED ${data.id} (bridge=${!!bridge}, ready=${bridge?.browserWs.readyState})`);
      return;
    }
    const buf = Buffer.from(data.b64 || "", "base64");
    if (process.env.RELAY_DEBUG) console.log(`[hipno-relay] wsdata →browser ${data.id} ${buf.length}b`);
    try { bridge.browserWs.send(buf, { binary: !!data.binary }); } catch {}
  });

  socket.on("wsclose", (data: { id: string; code?: number }) => {
    const bridge = wsBridges.get(data.id);
    if (!bridge) return;
    wsBridges.delete(data.id);
    try { bridge.browserWs.close(data.code || 1000); } catch {}
  });

  socket.on("disconnect", () => {
    if (serverId) {
      const rec = store.servers.find((s) => s.serverId === serverId);
      if (rec) {
        rec.online = false;
        rec.lastSeen = Date.now();
        saveStore();
      }
    }
    // close any bridges bound to this tunnel
    for (const [id, bridge] of wsBridges) {
      if (bridge.serverId === serverId) {
        wsBridges.delete(id);
        try { bridge.browserWs.close(1011); } catch {}
      }
    }
  });
});

// Heartbeat watchdog: tunnels silent for >45s are considered offline
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const s of store.servers) {
    if (s.online && now - s.lastSeen > 45_000) {
      s.online = false;
      changed = true;
    }
  }
  if (changed) saveStore();
}, 15_000);

// ---------------------------------------------------------------- WS bridge plumbing
/** Browser-side WS connection (via the ws lib — frame-level, protocol-agnostic). */
interface WsBridge {
  id: string;
  serverId: string;
  browserWs: import("ws").WebSocket;
  panelReady: boolean;
  buffer: { data: Buffer; binary: boolean }[];
}
const wsBridges = new Map<string, WsBridge>();
const browserWss = new WsServerForUpgrades({ noServer: true, maxPayload: 4 * 1024 * 1024 });

// ---------------------------------------------------------------- http routing
async function handle(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url || "/", `http://127.0.0.1:${PORT}`);
  const ip = (
    req.headers["x-forwarded-for"]?.toString().split(",")[0] ||
    req.socket.remoteAddress ||
    "unknown"
  ).trim();

  if (url.pathname === "/healthz") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(
      JSON.stringify({
        ok: true,
        servers: store.servers.length,
        online: store.servers.filter((s) => s.online).length,
      })
    );
  }
  if (url.pathname === "/metricsz") {
    const lines = [
      "# TYPE hipno_relay_registrations_total counter",
      `hipno_relay_registrations_total ${metrics.registrationsTotal}`,
      "# TYPE hipno_relay_rotations_total counter",
      `hipno_relay_rotations_total ${metrics.rotationsTotal}`,
      "# TYPE hipno_relay_tunnels_online gauge",
      `hipno_relay_tunnels_online ${store.servers.filter((s) => s.online).length}`,
      "# TYPE hipno_relay_requests_proxied_total counter",
      `hipno_relay_requests_proxied_total ${metrics.requestsProxiedTotal}`,
      "# TYPE hipno_relay_unknown_token_total counter",
      `hipno_relay_unknown_token_total ${metrics.unknownTokenTotal}`,
      "# TYPE hipno_relay_banned_ips_total counter",
      `hipno_relay_banned_ips_total ${metrics.bannedIpsTotal}`,
      "# TYPE hipno_relay_ws_bridges_total counter",
      `hipno_relay_ws_bridges_total ${metrics.wsBridgesTotal}`,
      "",
    ];
    res.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
    return res.end(lines.join("\n"));
  }

  if (url.pathname === "/api/v1/register" && req.method === "POST") {
    const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as {
      nonceHash?: string;
      nonce?: string;
      label?: string;
      version?: string;
    };
    const nonceHash = body.nonceHash || (body.nonce ? sha256(body.nonce) : null);
    if (!nonceHash || !/^[a-f0-9]{64}$/.test(nonceHash)) {
      res.writeHead(400, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "nonceHash required (sha256 hex)" }));
    }
    if (store.servers.some((s) => s.nonceHash === nonceHash)) {
      res.writeHead(409, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "nonce already used" }));
    }
    const serverId = crypto.randomUUID();
    const tunnelSecret = randomBase62(32);
    const token = randomBase62(32);
    store.servers.push({
      serverId,
      tokenHashes: [{ hash: sha256(token), active: true, createdAt: Date.now() }],
      secretHash: sha256(tunnelSecret),
      nonceHash,
      label: body.label || "panel",
      version: body.version || "unknown",
      online: false,
      lastSeen: 0,
    });
    metrics.registrationsTotal += 1;
    saveStore();
    res.writeHead(201, { "content-type": "application/json" });
    return res.end(JSON.stringify({ serverId, tunnelSecret, token }));
  }

  if (url.pathname === "/api/v1/rotate" && req.method === "POST") {
    const secret = bearerSecret(req);
    if (!secret) {
      res.writeHead(401, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "Bearer tunnel secret required" }));
    }
    const rec = store.servers.find((s) => s.secretHash === sha256(secret));
    if (!rec) {
      res.writeHead(401, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "invalid tunnel secret" }));
    }
    const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as {
      currentToken?: string;
      newToken?: string;
      serverId?: string;
    };
    if (!body.currentToken || !body.newToken) {
      res.writeHead(400, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "currentToken and newToken required" }));
    }
    if (rec.serverId !== body.serverId) {
      res.writeHead(403, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "serverId mismatch" }));
    }
    const currentActive = rec.tokenHashes.find(
      (t) => t.active && t.hash === sha256(body.currentToken!)
    );
    if (!currentActive) {
      res.writeHead(409, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "currentToken is not active" }));
    }
    const nt = body.newToken;
    const valid =
      nt.length === 32
        ? /^[A-Za-z0-9]{32}$/.test(nt)
        : nt.length >= 16 && nt.length <= 64 && /^[A-Za-z0-9_-]+$/.test(nt);
    if (!valid) {
      res.writeHead(400, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "newToken format invalid" }));
    }
    const newHash = sha256(nt);
    if (store.servers.some((s) => s.tokenHashes.some((t) => t.hash === newHash))) {
      // generic error — never reveal other slugs (spec §4.4)
      res.writeHead(409, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "unavailable" }));
    }
    currentActive.active = false;
    rec.tokenHashes.push({ hash: newHash, active: true, createdAt: Date.now() });
    metrics.rotationsTotal += 1;
    saveStore();
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ok: true }));
  }

  if (url.pathname === "/api/v1/deregister" && req.method === "POST") {
    const secret = bearerSecret(req);
    if (!secret) {
      res.writeHead(401, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "Bearer tunnel secret required" }));
    }
    const idx = store.servers.findIndex((s) => s.secretHash === sha256(secret));
    if (idx === -1) {
      res.writeHead(401, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "invalid tunnel secret" }));
    }
    store.servers.splice(idx, 1);
    saveStore();
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ok: true }));
  }

  // token-routed panel access: /server/panel/<TOKEN>[/*]
  const m = url.pathname.match(/^\/server\/panel\/([A-Za-z0-9_-]+)(\/.*)?$/);
  if (m) {
    const limit = rlCheck(ip);
    if (!limit.allowed) {
      if (limit.banned) {
        res.writeHead(403, { "content-type": "text/plain" });
        return res.end("Forbidden");
      }
      res.writeHead(429, { "content-type": "text/plain" });
      return res.end("Too many requests");
    }
    const token = m[1];
    const found = findServerByTokenHash(sha256(token));
    if (!found) {
      metrics.unknownTokenTotal += 1;
      const banned = noteUnknown404(ip);
      if (banned) {
        res.writeHead(403, { "content-type": "text/plain" });
        return res.end("Forbidden");
      }
      return sendNotFound(res);
    }
    if (!found.online) {
      res.writeHead(503, { "content-type": "text/html" });
      return res.end("<html><body><h1>503</h1><p>Server tunnel is offline.</p></body></html>");
    }

    const subPath = m[2] || "/";
    const targetPath = subPath + (url.search || "");
    const gatewayPortRaw = url.searchParams.get("XTransformPort");
    const gatewayPort = gatewayPortRaw && /^\d+$/.test(gatewayPortRaw) ? Number(gatewayPortRaw) : null;
    const id = `r${++reqCounter}`;
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (["host", "connection", "content-length", "transfer-encoding"].includes(k)) continue;
      headers[k] = Array.isArray(v) ? v.join(", ") : String(v);
    }
    const body = await readBody(req);
    const timer = setTimeout(() => {
      const entry = pending.get(id);
      if (entry) {
        pending.delete(id);
        try {
          entry.res.writeHead(504, { "content-type": "text/plain" });
          entry.res.end("Tunnel timeout");
        } catch {}
      }
    }, 60_000);
    pending.set(id, { res, timer, base: `/server/panel/${token}`, gatewayPort });
    metrics.requestsProxiedTotal += 1;
    io.to(`server:${found.serverId}`).emit("request", {
      id,
      method: req.method,
      path: targetPath,
      headers,
      bodyB64: body.length ? body.toString("base64") : undefined,
    });
    return;
  }

  sendNotFound(res, false);
}

httpServer.on("request", (req, res) => {
  handle(req, res).catch(() => {
    try {
      sendNotFound(res, false);
    } catch {}
  });
});

// ---------------------------------------------------------------- WS upgrade routing
// Browsers connect (e.g. the panel terminal) to /server/panel/<token>/socket.io/…
// The upgrade is bridged through the panel's tunnel to a local WS service on the
// VPS — a transparent FRAME-level pipe, so any WS protocol passes.
httpServer.on("upgrade", (req, socket, head) => {
  // engine.io (socket.io) claimed /tunnel-socket first — never touch it here.
  const rawPath = (req.url || "/").split("?")[0];
  if (rawPath === "/tunnel-socket" || rawPath.startsWith("/tunnel-socket/")) return;
  console.log(`[hipno-relay] upgrade request: ${req.url}`);

  const url = new URL(req.url || "/", `http://127.0.0.1:${PORT}`);
  const m = url.pathname.match(/^\/server\/panel\/([A-Za-z0-9_-]+)(\/.*)?$/);
  if (!m) {
    socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }
  const ip = (
    req.headers["x-forwarded-for"]?.toString().split(",")[0] ||
    req.socket.remoteAddress ||
    "unknown"
  ).trim();
  const limit = rlCheck(ip);
  if (!limit.allowed) {
    socket.write(`HTTP/1.1 ${limit.banned ? 403 : 429} Forbidden\r\nConnection: close\r\n\r\n`);
    socket.destroy();
    return;
  }
  const token = m[1];
  const found = findServerByTokenHash(sha256(token));
  if (!found) {
    metrics.unknownTokenTotal += 1;
    socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }
  if (!found.online) {
    socket.write("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }

  const subPath = m[2] || "/";
  browserWss.handleUpgrade(req, socket, head, (ws) => {
    const id = `ws${++reqCounter}`;
    const bridge: WsBridge = { id, serverId: found.serverId, browserWs: ws, panelReady: false, buffer: [] };
    wsBridges.set(id, bridge);
    metrics.wsBridgesTotal += 1;

    // ask the panel to open its local WS connection to the service
    io.to(`server:${found.serverId}`).emit("wsopen", {
      id,
      path: subPath + (url.search || ""),
    });

    ws.on("message", (data, isBinary) => {
      if (!wsBridges.has(id)) return;
      if (bridge.panelReady) {
        io.to(`server:${bridge.serverId}`).emit("wsdata", {
          id,
          b64: Buffer.from(data as Buffer).toString("base64"),
          binary: isBinary,
        });
      } else {
        bridge.buffer.push({ data: Buffer.from(data as Buffer), binary: isBinary });
      }
    });
    const closed = () => {
      if (wsBridges.delete(id)) {
        io.to(`server:${bridge.serverId}`).emit("wsclose", { id });
      }
    };
    ws.on("close", closed);
    ws.on("error", closed);
  });
});

httpServer.listen(PORT, "127.0.0.1", () => {
  console.log(`[hipno-relay] listening on 127.0.0.1:${PORT} (public origin: ${RELAY_PUBLIC_ORIGIN})`);
});

process.on("SIGTERM" as string, () => process.exit(0));
process.on("SIGINT" as string, () => process.exit(0));
