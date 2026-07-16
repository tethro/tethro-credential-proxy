/**
 * Tethro Credential Isolation Proxy
 *
 * - Replaces scoped session keys with real provider keys
 * - Persists sessions to disk (survives restart)
 * - Enforces egress allowlist from db/tethro-config.json (CONNECT + absolute URLs)
 */

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { URL } = require("url");
const net = require("net");

const PORT = Number(process.env.PORT || process.env.TETHRO_CRED_PORT || 8787);

const REAL_KEYS = {
  anthropic: process.env.ANTHROPIC_API_KEY || "",
  openai: process.env.OPENAI_API_KEY || "",
};

const STORE_DIR = path.join(os.homedir(), ".tethro");
const STORE_PATH = path.join(STORE_DIR, "cred-sessions.json");

const CONFIG_CANDIDATES = [
  process.env.TETHRO_CONFIG_PATH,
  path.join(process.cwd(), "db", "tethro-config.json"),
  path.join(process.cwd(), "..", "agentic", "db", "tethro-config.json"),
  path.join(os.homedir(), "Desktop", "agentic", "db", "tethro-config.json"),
].filter(Boolean);

let sessionKeys = new Map();
const sessionUsage = new Map();

function log(msg, level = "info") {
  const colors = { info: "\x1b[36m", ok: "\x1b[32m", warn: "\x1b[33m", error: "\x1b[31m", reset: "\x1b[0m" };
  const prefix = { info: "[info]", ok: "[ok]", warn: "[warn]", error: "[error]" };
  console.log(`${colors[level]}${prefix[level]}${colors.reset} [cred-proxy] ${msg}`);
}

function loadSessions() {
  try {
    const raw = JSON.parse(fs.readFileSync(STORE_PATH, "utf8"));
    const map = new Map();
    const now = Date.now();
    for (const [k, v] of Object.entries(raw.sessions || {})) {
      if (v.expiresAt > now) map.set(k, v);
    }
    sessionKeys = map;
    log(`Loaded ${sessionKeys.size} persisted session key(s)`, "ok");
  } catch {
    sessionKeys = new Map();
  }
}

function saveSessions() {
  try {
    fs.mkdirSync(STORE_DIR, { recursive: true });
    const sessions = {};
    for (const [k, v] of sessionKeys.entries()) sessions[k] = v;
    fs.writeFileSync(STORE_PATH, JSON.stringify({ sessions, savedAt: new Date().toISOString() }, null, 2));
  } catch (err) {
    log(`Failed to persist sessions: ${err.message}`, "warn");
  }
}

function loadEgressConfig() {
  for (const p of CONFIG_CANDIDATES) {
    try {
      if (!fs.existsSync(p)) continue;
      const cfg = JSON.parse(fs.readFileSync(p, "utf8"));
      return {
        path: p,
        active: cfg.egressAllowlistActive !== false,
        allow: Array.isArray(cfg.egressAllowlist) ? cfg.egressAllowlist.map(String) : [],
        deny: Array.isArray(cfg.egressDenylist) ? cfg.egressDenylist.map(String) : [],
        dnsFiltering: cfg.dnsFiltering !== false,
      };
    } catch {
      /* try next */
    }
  }
  return { path: null, active: false, allow: [], deny: [], dnsFiltering: false };
}

function isIpLiteral(host) {
  return net.isIP(host) !== 0;
}

function hostAllowed(hostname) {
  const cfg = loadEgressConfig();
  if (!cfg.active) return { ok: true, reason: "egress allowlist inactive" };
  const host = String(hostname || "").toLowerCase();

  // DNS filtering: block raw IP CONNECT (common allowlist bypass) when enabled
  if (cfg.dnsFiltering && isIpLiteral(host)) {
    const builtins = ["127.0.0.1", "::1"];
    if (!builtins.includes(host)) {
      return { ok: false, reason: "dnsFiltering blocks IP-literal CONNECT (use hostname)" };
    }
  }

  for (const d of cfg.deny) {
    const pat = d.toLowerCase();
    if (host === pat || host.endsWith("." + pat) || host.includes(pat)) {
      return { ok: false, reason: `denied by denylist (${d})` };
    }
  }
  // Always allow provider upstreams + localhost
  const builtins = [
    "api.anthropic.com",
    "api.openai.com",
    "127.0.0.1",
    "localhost",
    "host.docker.internal",
  ];
  if (builtins.some((b) => host === b || host.endsWith("." + b))) {
    return { ok: true, reason: "builtin" };
  }
  if (cfg.allow.length === 0) {
    // Active with empty allowlist = deny all non-builtin
    return { ok: false, reason: "egress allowlist active and empty" };
  }
  for (const a of cfg.allow) {
    const pat = a.toLowerCase().replace(/^\*\./, "");
    if (host === pat || host.endsWith("." + pat) || host === a.toLowerCase()) {
      return { ok: true, reason: `allowlist (${a})` };
    }
  }
  return { ok: false, reason: `host ${host} not on allowlist` };
}

function createSessionKey(provider, sessionId) {
  const key = `tethro-session-${sessionId}-${Date.now().toString(36)}`;
  sessionKeys.set(key, {
    provider,
    sessionId,
    createdAt: Date.now(),
    expiresAt: Date.now() + 4 * 60 * 60 * 1000,
  });
  saveSessions();
  return key;
}

function validateSessionKey(key) {
  const session = sessionKeys.get(key);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessionKeys.delete(key);
    saveSessions();
    return null;
  }
  return session;
}

function revokeSessionKey(key) {
  sessionKeys.delete(key);
  saveSessions();
  log(`Session key revoked: ${key.slice(0, 20)}...`, "warn");
}

function revokeBySessionId(sessionId) {
  let n = 0;
  for (const [key, meta] of sessionKeys.entries()) {
    if (meta.sessionId === sessionId || key.includes(sessionId)) {
      sessionKeys.delete(key);
      n++;
    }
  }
  if (n) saveSessions();
  return n;
}

function checkRateLimit(sessionKey) {
  const now = Date.now();
  const usage = sessionUsage.get(sessionKey);
  if (!usage || now > usage.resetTime) {
    sessionUsage.set(sessionKey, { count: 1, resetTime: now + 60_000 });
    return { allowed: true, remaining: 99 };
  }
  if (usage.count >= 100) return { allowed: false, remaining: 0 };
  usage.count++;
  return { allowed: true, remaining: 100 - usage.count };
}

function handleConnect(req, socket, head) {
  const target = req.url || ""; // host:port
  const [host, portStr] = target.split(":");
  const port = Number(portStr || 443);
  const check = hostAllowed(host);
  if (!check.ok) {
    log(`CONNECT blocked ${target}: ${check.reason}`, "warn");
    socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    socket.end();
    return;
  }
  const upstream = net.connect(port, host, () => {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head?.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on("error", () => socket.end());
  socket.on("error", () => upstream.end());
}

function handleProxy(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (req.method === "GET" && url.pathname === "/health") {
    const egress = loadEgressConfig();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ok",
        port: PORT,
        providers: Object.keys(REAL_KEYS).filter((k) => REAL_KEYS[k]),
        activeSessions: sessionKeys.size,
        store: STORE_PATH,
        egress: {
          active: egress.active,
          allowCount: egress.allow.length,
          denyCount: egress.deny.length,
          dnsFiltering: egress.dnsFiltering,
          configPath: egress.path,
        },
      })
    );
    return;
  }

  if (req.method === "GET" && url.pathname === "/egress") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(loadEgressConfig()));
    return;
  }

  if (req.method === "POST" && url.pathname === "/session/create") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        const { provider, sessionId } = JSON.parse(body);
        if (!REAL_KEYS[provider]) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Provider ${provider} not configured` }));
          return;
        }
        const key = createSessionKey(provider, sessionId);
        log(`Session key created for ${sessionId} (${provider})`, "ok");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ sessionKey: key, expiresIn: "4h" }));
      } catch {
        res.writeHead(400);
        res.end("Bad request");
      }
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/session/revoke") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        const { sessionKey, sessionId } = JSON.parse(body);
        let revoked = 0;
        if (sessionKey) {
          revokeSessionKey(sessionKey);
          revoked = 1;
        } else if (sessionId) {
          revoked = revokeBySessionId(sessionId);
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, revoked }));
      } catch {
        res.writeHead(400);
        res.end("Bad request");
      }
    });
    return;
  }

  // Absolute-form HTTP proxy requests (when HTTPS_PROXY points here)
  if (req.url?.startsWith("http://") || req.url?.startsWith("https://")) {
    try {
      const abs = new URL(req.url);
      const check = hostAllowed(abs.hostname);
      if (!check.ok) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "egress denied", detail: check.reason }));
        return;
      }
    } catch {
      /* fall through */
    }
  }

  const pathParts = url.pathname.split("/").filter(Boolean);
  const provider = pathParts[0];

  if (!provider || !REAL_KEYS[provider]) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: `Unknown provider: ${provider}` }));
    return;
  }

  const authHeader = req.headers["authorization"] || "";
  const sessionKey = authHeader.replace(/^Bearer\s+/i, "").replace(/^sk-ant-/, "").replace(/^sk-/, "");
  const session = validateSessionKey(sessionKey) ||
    // Accept placeholder key used by console spawn
    (sessionKey === "tethro-session-proxy"
      ? { provider, sessionId: "proxy-placeholder", createdAt: Date.now(), expiresAt: Date.now() + 3600000 }
      : null);

  if (!session) {
    log(`Rejected request with invalid session key`, "warn");
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid or expired session key" }));
    return;
  }

  const rate = checkRateLimit(sessionKey || "proxy");
  if (!rate.allowed) {
    res.writeHead(429, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Rate limit exceeded (100 req/min)" }));
    return;
  }

  const upstreamHosts = { anthropic: "api.anthropic.com", openai: "api.openai.com" };
  const upstreamHost = upstreamHosts[provider];
  const check = hostAllowed(upstreamHost);
  if (!check.ok) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "egress denied", detail: check.reason }));
    return;
  }

  const upstreamPath = "/" + pathParts.slice(1).join("/") + (url.search || "");
  let reqBody = "";
  req.on("data", (c) => (reqBody += c));
  req.on("end", () => {
    log(`Forwarding ${req.method} ${upstreamPath} for ${session.sessionId}`, "info");
    const upstreamReq = https.request(
      {
        hostname: upstreamHost,
        port: 443,
        path: upstreamPath,
        method: req.method,
        headers: {
          ...req.headers,
          host: upstreamHost,
          authorization: `Bearer ${REAL_KEYS[provider]}`,
          "x-api-key": REAL_KEYS[provider],
          "anthropic-version": req.headers["anthropic-version"] || "2023-06-01",
        },
      },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
        upstreamRes.on("data", (chunk) => res.write(chunk));
        upstreamRes.on("end", () => res.end());
      }
    );
    upstreamReq.on("error", (err) => {
      log(`Upstream error: ${err.message}`, "error");
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Upstream API error", detail: err.message }));
      }
    });
    if (reqBody) upstreamReq.write(reqBody);
    upstreamReq.end();
  });
}

loadSessions();
const server = http.createServer(handleProxy);
server.on("connect", handleConnect);
server.listen(PORT, () => {
  const egress = loadEgressConfig();
  log(`Credential isolation proxy running on port ${PORT}`, "ok");
  log(`Session store: ${STORE_PATH}`, "info");
  log(
    `Egress: ${egress.active ? "active" : "inactive"} (config=${egress.path || "none"}) allow=${egress.allow.length} deny=${egress.deny.length}`,
    "info"
  );
  log(`Providers: ${Object.keys(REAL_KEYS).filter((k) => REAL_KEYS[k]).join(", ") || "none"}`, "info");
});
