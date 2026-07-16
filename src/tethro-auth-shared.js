/**
 * Shared bearer auth for Tethro satellite services (cred-proxy, audit-ws, mcp-proxy).
 *
 * Accepted credentials (first match wins):
 * 1. Authorization: Bearer <TETHRO_SERVICE_SECRET>
 * 2. Authorization: Bearer <NEXTAUTH_SECRET>   (same host console secret)
 * 3. Authorization: Bearer <SCIM_BEARER_TOKEN> (enterprise automation)
 * 4. x-tethro-service-secret: <secret>
 *
 * Health endpoints should stay public; protect mutating / admin surfaces.
 */
"use strict";

const crypto = require("crypto");

function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (!a || !b || a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

function serviceSecrets() {
  const secrets = [
    process.env.TETHRO_SERVICE_SECRET,
    process.env.NEXTAUTH_SECRET,
    process.env.SCIM_BEARER_TOKEN,
  ]
    .map((s) => (s || "").trim())
    .filter((s) => s && s !== "scim_dev_token_change_me" && s !== "dev-insecure-secret");
  return [...new Set(secrets)];
}

function extractBearer(headers) {
  if (!headers || typeof headers !== "object") return "";
  const auth = headers.authorization || headers.Authorization || "";
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    return auth.slice(7).trim();
  }
  const hdr =
    headers["x-tethro-service-secret"] ||
    headers["X-Tethro-Service-Secret"] ||
    "";
  return typeof hdr === "string" ? hdr.trim() : "";
}

/** Returns true if request presents a valid service secret. */
function verifyServiceBearer(headers) {
  const presented = extractBearer(headers);
  if (!presented) return false;
  const secrets = serviceSecrets();
  if (secrets.length === 0) {
    // Dev convenience: allow when no secrets configured and not production
    return process.env.NODE_ENV !== "production";
  }
  return secrets.some((s) => timingSafeEqualStr(presented, s));
}

/**
 * Express/Node-style gate. Calls next() or writes 401.
 * @param {import('http').IncomingMessage} req
 * @param {import('http').ServerResponse} res
 * @param {() => void} next
 */
function requireServiceAuth(req, res, next) {
  if (verifyServiceBearer(req.headers)) {
    next();
    return true;
  }
  res.writeHead(401, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Unauthorized — service bearer required" }));
  return false;
}

/** Socket.IO middleware: auth.token | query.token | handshake headers. */
function verifySocketAuth(socket) {
  const token =
    socket.handshake?.auth?.token ||
    socket.handshake?.query?.token ||
    extractBearer(socket.handshake?.headers || {});
  if (!token) {
    return process.env.NODE_ENV !== "production";
  }
  const secrets = serviceSecrets();
  if (secrets.length === 0) return process.env.NODE_ENV !== "production";
  return secrets.some((s) => timingSafeEqualStr(String(token), s));
}

module.exports = {
  timingSafeEqualStr,
  serviceSecrets,
  extractBearer,
  verifyServiceBearer,
  requireServiceAuth,
  verifySocketAuth,
};
