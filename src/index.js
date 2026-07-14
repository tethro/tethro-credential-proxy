/**
 * Airlock Credential Isolation Proxy
 *
 * A real HTTP proxy that sits between sandboxed agents and model APIs.
 * Agents see ANTHROPIC_API_KEY=airlock-session-proxy in their environment.
 * This proxy intercepts the request, replaces the proxy key with the real
 * API key (from the host environment), and forwards to the real API.
 *
 * This ensures agents never see the real API key — even a compromised
 * agent can only use the proxy, which can be rate-limited, audited,
 * and revoked per-session.
 *
 * Listens on port 8787.
 */

const http = require("http");
const https = require("https");
const { URL } = require("url");

const PORT = 8787;

// Real API keys from the host environment (never exposed to the sandbox)
const REAL_KEYS = {
  anthropic: process.env.ANTHROPIC_API_KEY || "",
  openai: process.env.OPENAI_API_KEY || "",
};

// Per-session scoped keys (in production: stored in DB with TTL)
const sessionKeys = new Map(); // sessionKey -> { provider, sessionId, createdAt, expiresAt }

// Rate limiting per session
const sessionUsage = new Map(); // sessionKey -> { count, resetTime }

function log(msg, level = "info") {
  const colors = { info: "\x1b[36m", ok: "\x1b[32m", warn: "\x1b[33m", error: "\x1b[31m", reset: "\x1b[0m" };
  const prefix = { info: "[info]", ok: "[ok]", warn: "[warn]", error: "[error]" };
  console.log(`${colors[level]}${prefix[level]}${colors.reset} [cred-proxy] ${msg}`);
}

// ─── Session key management ───

function createSessionKey(provider, sessionId) {
  const key = `airlock-session-${sessionId}-${Date.now().toString(36)}`;
  sessionKeys.set(key, {
    provider,
    sessionId,
    createdAt: Date.now(),
    expiresAt: Date.now() + 4 * 60 * 60 * 1000, // 4 hours
  });
  return key;
}

function validateSessionKey(key) {
  const session = sessionKeys.get(key);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessionKeys.delete(key);
    return null;
  }
  return session;
}

function revokeSessionKey(key) {
  sessionKeys.delete(key);
  log(`Session key revoked: ${key.slice(0, 20)}...`, "warn");
}

// ─── Rate limiting ───

function checkRateLimit(sessionKey) {
  const now = Date.now();
  const usage = sessionUsage.get(sessionKey);

  if (!usage || now > usage.resetTime) {
    sessionUsage.set(sessionKey, { count: 1, resetTime: now + 60_000 });
    return { allowed: true, remaining: 99 };
  }

  if (usage.count >= 100) {
    return { allowed: false, remaining: 0 };
  }

  usage.count++;
  return { allowed: true, remaining: 100 - usage.count };
}

// ─── Proxy handler ───

function handleProxy(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // ─── Health check ───
  if (req.method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "ok",
      port: PORT,
      providers: Object.keys(REAL_KEYS).filter((k) => REAL_KEYS[k]),
      activeSessions: sessionKeys.size,
    }));
    return;
  }

  // ─── Create session key (called by airlock-cli when starting a session) ───
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

  // ─── Revoke session key ───
  if (req.method === "POST" && url.pathname === "/session/revoke") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        const { sessionKey } = JSON.parse(body);
        revokeSessionKey(sessionKey);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400);
        res.end("Bad request");
      }
    });
    return;
  }

  // ─── Forward to provider API ───
  // Path format: /<provider>/v1/...
  const pathParts = url.pathname.split("/").filter(Boolean);
  const provider = pathParts[0];

  if (!provider || !REAL_KEYS[provider]) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: `Unknown provider: ${provider}` }));
    return;
  }

  // Extract session key from Authorization header
  const authHeader = req.headers["authorization"] || "";
  const sessionKey = authHeader.replace("Bearer ", "").replace("sk-ant-", "").replace("sk-", "");

  const session = validateSessionKey(sessionKey);
  if (!session) {
    log(`Rejected request with invalid session key`, "warn");
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid or expired session key" }));
    return;
  }

  // Rate limit
  const rate = checkRateLimit(sessionKey);
  if (!rate.allowed) {
    log(`Rate limit exceeded for ${session.sessionId}`, "warn");
    res.writeHead(429, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Rate limit exceeded (100 req/min)" }));
    return;
  }

  // Build the upstream request
  const upstreamHosts = {
    anthropic: "api.anthropic.com",
    openai: "api.openai.com",
  };

  const upstreamHost = upstreamHosts[provider];
  if (!upstreamHost) {
    res.writeHead(400);
    res.end(JSON.stringify({ error: `No upstream for provider ${provider}` }));
    return;
  }

  // Reconstruct the path (remove the provider prefix)
  const upstreamPath = "/" + pathParts.slice(1).join("/") + (url.search || "");

  // Collect request body
  let reqBody = "";
  req.on("data", (c) => (reqBody += c));
  req.on("end", () => {
    log(`Forwarding ${req.method} ${upstreamPath} for ${session.sessionId} (${rate.remaining} remaining)`, "info");

    // Build upstream request with REAL API key
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
          "x-api-key": REAL_KEYS[provider], // Anthropic uses x-api-key
          "anthropic-version": req.headers["anthropic-version"] || "2023-06-01",
        },
      },
      (upstreamRes) => {
        // Copy status and headers
        res.writeHead(upstreamRes.statusCode, upstreamRes.headers);

        // Stream the response back
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

// ─── Start server ───

const server = http.createServer(handleProxy);

server.listen(PORT, () => {
  log(`Credential isolation proxy running on port ${PORT}`, "ok");
  log(`Providers: ${Object.keys(REAL_KEYS).filter((k) => REAL_KEYS[k]).join(", ") || "none configured"}`, "info");
  log(`Health: http://localhost:${PORT}/health`, "info");
  if (!REAL_KEYS.anthropic && !REAL_KEYS.openai) {
    log(`No API keys found. Set ANTHROPIC_API_KEY and/or OPENAI_API_KEY in the environment.`, "warn");
    log(`The proxy will run but reject all requests until keys are configured.`, "warn");
  }
});
