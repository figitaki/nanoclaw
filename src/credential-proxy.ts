/**
 * Credential Proxy for NanoClaw
 *
 * Two operating modes, selected by environment configuration:
 *
 * ── Local proxy (default when TURNKEY_* vars set) ────────────────────────────
 *
 *   A lightweight HTTP server starts on 127.0.0.1:{random-port}.
 *   Containers receive ANTHROPIC_BASE_URL pointing at host.docker.internal.
 *   The proxy validates each container's session token, fetches the real key
 *   from Turnkey (TTL-cached in memory), and forwards to api.anthropic.com.
 *   The real sk-ant-... value never enters the container's address space.
 *
 * ── TVC remote proxy (when TURNKEY_PROXY_URL + TURNKEY_PROXY_ADMIN_TOKEN set) ─
 *
 *   Delegates to a pre-deployed Turnkey Verifiable Cloud app — a Nitro Enclave
 *   whose binary digest and container image digest have been cryptographically
 *   approved by the operator manifest set (via `tvc deploy approve`).
 *
 *   NanoClaw calls POST /sessions on the TVC app to register each container
 *   and DELETE /sessions/:token when the container exits.
 *   Containers get ANTHROPIC_BASE_URL=https://app-<UUID>.turnkey.cloud.
 *
 *   This gives the same end-to-end attestation as Turnkey's own wallet
 *   infrastructure — the proxy code is verifiable, and the API key never
 *   leaves the enclave.
 *
 * See tvc-proxy/ for the TVC app source, Dockerfile, and deployment templates.
 */

import crypto from 'crypto';
import http from 'http';
import https from 'https';

import { logger } from './logger.js';
import { getTurnkeyConfig, getSecretsViaTurnkey } from './turnkey.js';
import { readEnvFile } from './env.js';

const ANTHROPIC_API_HOST = 'api.anthropic.com';
const DEFAULT_SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

interface Session {
  groupFolder: string;
  createdAt: number;
  ttlMs: number;
}

export interface CredentialProxy {
  /** Underlying port for local proxy; -1 for remote TVC proxy. */
  port: number;
  /** Value to pass as ANTHROPIC_BASE_URL in container secrets. */
  baseUrl: string;
  /** Issue a short-lived session token for a container. */
  registerSession(groupFolder: string, ttlMs?: number): Promise<string>;
  /** Revoke a session immediately; call when the container exits. */
  revokeSession(token: string): void;
  close(): Promise<void>;
}

let singleton: CredentialProxy | null = null;

/**
 * Return (or start) the credential proxy.
 *
 * Checks .env on first call:
 *  - TURNKEY_PROXY_URL + TURNKEY_PROXY_ADMIN_TOKEN → TVC remote proxy
 *  - Anything else → local proxy
 */
export async function getOrStartCredentialProxy(): Promise<CredentialProxy> {
  if (singleton) return singleton;

  const env = readEnvFile(['TURNKEY_PROXY_URL', 'TURNKEY_PROXY_ADMIN_TOKEN']);
  if (env.TURNKEY_PROXY_URL && env.TURNKEY_PROXY_ADMIN_TOKEN) {
    logger.info({ proxyUrl: env.TURNKEY_PROXY_URL }, 'Using TVC remote credential proxy');
    singleton = createTvcProxy(env.TURNKEY_PROXY_URL, env.TURNKEY_PROXY_ADMIN_TOKEN);
  } else {
    singleton = await startLocalProxy();
  }
  return singleton;
}

// ── TVC remote proxy ──────────────────────────────────────────────────────────

function createTvcProxy(proxyUrl: string, adminToken: string): CredentialProxy {
  const authHeader = `Bearer ${adminToken}`;

  return {
    port: -1,
    baseUrl: proxyUrl,

    async registerSession(groupFolder: string, ttlMs?: number): Promise<string> {
      const resp = await fetch(`${proxyUrl}/sessions`, {
        method: 'POST',
        headers: { Authorization: authHeader, 'Content-Type': 'application/json' },
        body: JSON.stringify({ groupFolder, ttlMs }),
      });
      if (!resp.ok) {
        throw new Error(`TVC session registration failed: HTTP ${resp.status}`);
      }
      const { token } = (await resp.json()) as { token: string };
      logger.debug({ groupFolder, proxyUrl }, 'TVC session registered');
      return token;
    },

    revokeSession(token: string): void {
      fetch(`${proxyUrl}/sessions/${token}`, {
        method: 'DELETE',
        headers: { Authorization: authHeader },
      }).catch((err) => logger.debug({ err }, 'TVC session revoke failed (non-fatal)'));
    },

    close(): Promise<void> {
      singleton = null;
      return Promise.resolve();
    },
  };
}

// ── Local proxy ───────────────────────────────────────────────────────────────

async function fetchApiKey(): Promise<string> {
  const config = getTurnkeyConfig();
  if (config) {
    const secrets = await getSecretsViaTurnkey('__credential_proxy__', config, () => {});
    const key = secrets.ANTHROPIC_API_KEY || secrets.CLAUDE_CODE_OAUTH_TOKEN;
    if (!key) throw new Error('Turnkey returned no API key for credential proxy');
    return key;
  }
  const env = readEnvFile(['ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN']);
  const key = env.ANTHROPIC_API_KEY || env.CLAUDE_CODE_OAUTH_TOKEN;
  if (!key) throw new Error('No ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN found');
  return key;
}

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

export function evictProxyKeyCache(): void {
  cachedKey = null;
  cachedKeyAt = 0;
}

async function startLocalProxy(): Promise<CredentialProxy> {
  const sessions = new Map<string, Session>();

  const server = http.createServer(
    (req: http.IncomingMessage, res: http.ServerResponse): void => {
      handleRequest(req, res, sessions).catch((err) => {
        logger.error({ err }, 'Credential proxy: unhandled error');
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({ error: { type: 'api_error', message: 'Internal proxy error' } }),
          );
        }
      });
    },
  );

  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve());
    server.once('error', reject);
  });

  const { port } = server.address() as { port: number };
  logger.info({ port }, 'Local credential proxy started on 127.0.0.1');

  return {
    port,
    baseUrl: `http://host.docker.internal:${port}`,

    async registerSession(groupFolder: string, ttlMs = DEFAULT_SESSION_TTL_MS): Promise<string> {
      const token = crypto.randomUUID();
      sessions.set(token, { groupFolder, createdAt: Date.now(), ttlMs });
      // Reap expired sessions opportunistically
      const now = Date.now();
      for (const [t, s] of sessions) {
        if (now - s.createdAt > s.ttlMs) sessions.delete(t);
      }
      logger.debug({ groupFolder, ttlMs }, 'Local proxy session registered');
      return token;
    },

    revokeSession(token: string): void {
      if (sessions.delete(token)) logger.debug('Local proxy session revoked');
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
  // ── Validate session token ─────────────────────────────────────────────────

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

  // ── Fetch real API key ─────────────────────────────────────────────────────

  let apiKey: string;
  try {
    apiKey = await getKey();
  } catch (err) {
    logger.error({ err, groupFolder: session.groupFolder }, 'Credential proxy: key fetch failed');
    return sendError(res, 500, 'api_error', 'Failed to retrieve credentials');
  }

  // ── Forward to Anthropic ──────────────────────────────────────────────────

  const upstreamHeaders: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (
      k === 'authorization' ||
      k === 'x-api-key' ||
      k === 'connection' ||
      k === 'keep-alive' ||
      k === 'transfer-encoding'
    ) continue;
    upstreamHeaders[k] = v;
  }
  upstreamHeaders['host'] = ANTHROPIC_API_HOST;
  upstreamHeaders['x-api-key'] = apiKey;

  const upstreamReq = https.request(
    {
      hostname: ANTHROPIC_API_HOST,
      port: 443,
      path: req.url,
      method: req.method,
      headers: upstreamHeaders,
    },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 200, upstreamRes.headers);
      upstreamRes.pipe(res, { end: true });
    },
  );

  upstreamReq.on('error', (err) => {
    logger.error({ err, path: req.url }, 'Credential proxy: upstream error');
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({ error: { type: 'api_error', message: 'Upstream request failed' } }),
      );
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
