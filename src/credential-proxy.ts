/**
 * Credential Proxy for NanoClaw
 *
 * Intercepts Anthropic API calls from agent containers and injects the real
 * API key at the network layer — the container's address space never receives
 * the actual sk-ant-... value.
 *
 * Architecture (today):
 *   Container  →  http://host.docker.internal:{port}  →  https://api.anthropic.com
 *   Container sends session token as Authorization Bearer
 *   Proxy validates token, swaps in real key from Turnkey vault, forwards request
 *
 * Architecture (TVC upgrade path):
 *   When Turnkey Verifiable Cloud becomes available, this proxy image can be
 *   deployed via `tvc deploy` into a Nitro Enclave. Binary digest is verified,
 *   remote attestation (PCRs) proves the proxy code is unmodified. The Turnkey
 *   API key lives in the parent org's HSM, accessible only to the attested proxy.
 *   Users can cryptographically verify the proxy before trusting it with keys.
 */

import crypto from 'crypto';
import http from 'http';
import https from 'https';

import { logger } from './logger.js';
import { getTurnkeyConfig, getSecretsViaTurnkey } from './turnkey.js';
import { readEnvFile } from './env.js';

const ANTHROPIC_API_HOST = 'api.anthropic.com';

// How long a proxy-issued session token stays valid.
// Set slightly longer than typical container lifetime so tokens don't expire mid-run.
// Revoked explicitly when the container exits regardless.
const DEFAULT_SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

interface Session {
  groupFolder: string;
  createdAt: number;
  ttlMs: number;
}

export interface CredentialProxy {
  port: number;
  /** Issue a session token for a container; returns the opaque token string. */
  registerSession(groupFolder: string, ttlMs?: number): string;
  /** Revoke a session immediately (call when container exits). */
  revokeSession(token: string): void;
  close(): Promise<void>;
}

// Module-level singleton — one proxy serves all containers
let singleton: CredentialProxy | null = null;

/**
 * Start (or return the existing) credential proxy.
 *
 * getApiKey is called on each cache miss to fetch the real Anthropic API key.
 * The proxy maintains its own 5-minute cache so Turnkey is not hammered on
 * every request.
 */
export async function getOrStartCredentialProxy(): Promise<CredentialProxy> {
  if (singleton) return singleton;
  singleton = await startCredentialProxy();
  return singleton;
}

async function fetchApiKey(): Promise<string> {
  const config = getTurnkeyConfig();
  if (config) {
    // Reuse getSecretsViaTurnkey — handles both auth-gate and vault modes,
    // includes its own TTL cache. Use a fixed key since the API key is global.
    const secrets = await getSecretsViaTurnkey('__credential_proxy__', config, () => {});
    const key = secrets.ANTHROPIC_API_KEY || secrets.CLAUDE_CODE_OAUTH_TOKEN;
    if (!key) throw new Error('Turnkey returned no API key for credential proxy');
    return key;
  }
  // Fallback: read from .env (no Turnkey configured)
  const env = readEnvFile(['ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN']);
  const key = env.ANTHROPIC_API_KEY || env.CLAUDE_CODE_OAUTH_TOKEN;
  if (!key) throw new Error('No ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN found');
  return key;
}

// Simple TTL cache for the real API key — avoids Turnkey round-trip per request
let cachedKey: string | null = null;
let cachedKeyAt = 0;
const KEY_CACHE_MS = 5 * 60 * 1000;

async function getKey(): Promise<string> {
  const now = Date.now();
  if (cachedKey && now - cachedKeyAt < KEY_CACHE_MS) return cachedKey;
  cachedKey = await fetchApiKey();
  cachedKeyAt = now;
  return cachedKey;
}

/** Invalidate the cached API key (e.g. after a key rotation). */
export function evictProxyKeyCache(): void {
  cachedKey = null;
  cachedKeyAt = 0;
}

async function startCredentialProxy(): Promise<CredentialProxy> {
  const sessions = new Map<string, Session>();

  const server = http.createServer((req: http.IncomingMessage, res: http.ServerResponse) => {
    handleRequest(req, res, sessions).catch((err) => {
      logger.error({ err }, 'Credential proxy: unhandled error');
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { type: 'api_error', message: 'Internal proxy error' } }));
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve());
    server.once('error', reject);
  });

  const { port } = server.address() as { port: number };
  logger.info({ port }, 'Credential proxy started on 127.0.0.1');

  return {
    port,

    registerSession(groupFolder: string, ttlMs = DEFAULT_SESSION_TTL_MS): string {
      const token = crypto.randomUUID();
      sessions.set(token, { groupFolder, createdAt: Date.now(), ttlMs });
      // Opportunistically reap expired sessions on each registration
      const now = Date.now();
      for (const [t, s] of sessions) {
        if (now - s.createdAt > s.ttlMs) sessions.delete(t);
      }
      logger.debug({ groupFolder, ttlMs }, 'Credential proxy: session registered');
      return token;
    },

    revokeSession(token: string): void {
      if (sessions.delete(token)) {
        logger.debug('Credential proxy: session revoked');
      }
    },

    close(): Promise<void> {
      singleton = null;
      return new Promise((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  sessions: Map<string, Session>,
): Promise<void> {
  // ── 1. Validate session token ──────────────────────────────────────────────

  // Claude SDK sends both x-api-key and Authorization: Bearer
  const sessionToken =
    extractBearer(req.headers.authorization) ||
    (Array.isArray(req.headers['x-api-key'])
      ? req.headers['x-api-key'][0]
      : req.headers['x-api-key']) ||
    '';

  if (!sessionToken) {
    return sendError(res, 401, 'authentication_error', 'Missing session token');
  }

  const session = sessions.get(sessionToken);
  if (!session) {
    return sendError(res, 401, 'authentication_error', 'Invalid session token');
  }

  if (Date.now() - session.createdAt > session.ttlMs) {
    sessions.delete(sessionToken);
    return sendError(res, 401, 'authentication_error', 'Session token expired');
  }

  // ── 2. Fetch the real API key ──────────────────────────────────────────────

  let apiKey: string;
  try {
    apiKey = await getKey();
  } catch (err) {
    logger.error({ err, groupFolder: session.groupFolder }, 'Credential proxy: key fetch failed');
    return sendError(res, 500, 'api_error', 'Failed to retrieve credentials');
  }

  // ── 3. Build upstream headers — swap out session token, inject real key ────

  const upstreamHeaders: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(req.headers)) {
    // Strip credential headers; we'll inject the real key ourselves
    if (k === 'authorization' || k === 'x-api-key') continue;
    // Strip hop-by-hop headers that shouldn't be forwarded
    if (k === 'connection' || k === 'keep-alive' || k === 'transfer-encoding') continue;
    upstreamHeaders[k] = v;
  }
  upstreamHeaders['host'] = ANTHROPIC_API_HOST;
  upstreamHeaders['x-api-key'] = apiKey;

  // ── 4. Forward to Anthropic ────────────────────────────────────────────────

  const upstreamReq = https.request(
    {
      hostname: ANTHROPIC_API_HOST,
      port: 443,
      path: req.url,
      method: req.method,
      headers: upstreamHeaders,
    },
    (upstreamRes) => {
      // Pass through status and all response headers (including SSE content-type)
      res.writeHead(upstreamRes.statusCode ?? 200, upstreamRes.headers);
      upstreamRes.pipe(res, { end: true });
    },
  );

  upstreamReq.on('error', (err) => {
    logger.error({ err, path: req.url }, 'Credential proxy: upstream error');
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { type: 'api_error', message: 'Upstream request failed' } }));
    }
  });

  req.pipe(upstreamReq, { end: true });
}

function extractBearer(header: string | string[] | undefined): string {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value) return '';
  const lower = value.toLowerCase();
  return lower.startsWith('bearer ') ? value.slice(7).trim() : '';
}

function sendError(
  res: http.ServerResponse,
  status: number,
  type: string,
  message: string,
): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: { type, message } }));
}
