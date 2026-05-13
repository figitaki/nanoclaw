/**
 * NanoClaw TVC Credential Proxy
 *
 * Deployed into a Turnkey Verifiable Cloud (Nitro Enclave) via `tvc deploy`.
 * Handles Anthropic API credential injection at the network layer — containers
 * connected to this service never receive the real sk-ant-... key.
 *
 * ── Attestation ──────────────────────────────────────────────────────────────
 *
 *   pivotPath            /usr/local/bin/node
 *   pivotArgs            /app/proxy.cjs
 *   expectedPivotDigest  sha256 of /app/proxy.cjs  (see scripts/build-and-digest.sh)
 *
 *   The container image @sha256 digest proves the application code is unmodified.
 *   The pivot digest proves the specific Node.js version bundled with it.
 *   Together they provide the same attestation guarantee as Turnkey's own wallet
 *   infrastructure — anyone can verify the exact code handling their API keys.
 *
 * ── Architecture ─────────────────────────────────────────────────────────────
 *
 *   NanoClaw orchestrator
 *     POST /sessions  (Bearer ADMIN_TOKEN)  →  { token }
 *     DELETE /sessions/:token               →  204
 *
 *   Agent containers
 *     ANTHROPIC_API_KEY  = session token
 *     ANTHROPIC_BASE_URL = https://app-<UUID>.turnkey.cloud
 *     All Anthropic API calls → TVC proxy → api.anthropic.com
 *
 * ── Environment variables ─────────────────────────────────────────────────────
 *
 *   Required:
 *     ADMIN_TOKEN                    shared secret used by orchestrator
 *
 *   Turnkey auth-gate mode (validates every call, key from env):
 *     TURNKEY_ORGANIZATION_ID
 *     TURNKEY_API_PUBLIC_KEY
 *     TURNKEY_API_PRIVATE_KEY
 *     ANTHROPIC_API_KEY              plaintext key (read once, validated via Turnkey)
 *
 *   Turnkey vault mode (key never stored as plaintext):
 *     TURNKEY_ORGANIZATION_ID
 *     TURNKEY_API_PUBLIC_KEY
 *     TURNKEY_API_PRIVATE_KEY
 *     TURNKEY_LLM_ENCRYPTION_KEY_ID  key ID for AES-256-GCM decryption
 *     TURNKEY_LLM_ENCRYPTED_KEY      JSON ciphertext bundle from setupLlmKeyVault()
 *
 *   Optional:
 *     PORT   (default 3000)
 *     HOST   (default 0.0.0.0)
 */

import crypto from 'crypto';
import http from 'http';
import https from 'https';

import { Turnkey } from '@turnkey/sdk-server';
import { generateP256KeyPair, decryptExportBundle } from '@turnkey/crypto';

// ── Config ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const HOST = process.env.HOST ?? '0.0.0.0';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? '';

const TURNKEY_BASE_URL = 'https://api.turnkey.com';
const ANTHROPIC_HOST = 'api.anthropic.com';

const TURNKEY_ORG_ID = process.env.TURNKEY_ORGANIZATION_ID ?? '';
const TURNKEY_PUB_KEY = process.env.TURNKEY_API_PUBLIC_KEY ?? '';
const TURNKEY_PRIV_KEY = process.env.TURNKEY_API_PRIVATE_KEY ?? '';
const LLM_ENC_KEY_ID = process.env.TURNKEY_LLM_ENCRYPTION_KEY_ID ?? '';
const LLM_ENCRYPTED_KEY = process.env.TURNKEY_LLM_ENCRYPTED_KEY ?? '';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY ?? '';

// ── Startup validation ───────────────────────────────────────────────────────

function assertConfig(): void {
  if (!ADMIN_TOKEN) throw new Error('ADMIN_TOKEN is required');

  const hasTurnkey = TURNKEY_ORG_ID && TURNKEY_PUB_KEY && TURNKEY_PRIV_KEY;
  const hasVault = LLM_ENC_KEY_ID && LLM_ENCRYPTED_KEY;
  const hasFallback = !!ANTHROPIC_API_KEY;

  if (!hasTurnkey && !hasFallback) {
    throw new Error(
      'Must set either TURNKEY_* vars (+ optionally LLM vault vars) or ANTHROPIC_API_KEY',
    );
  }

  const mode = hasVault ? 'vault' : hasTurnkey ? 'auth-gate' : 'env-key';
  console.log(
    JSON.stringify({ level: 'info', msg: 'TVC credential proxy starting', mode, port: PORT }),
  );
}

// ── Turnkey helpers ──────────────────────────────────────────────────────────

function makeTurnkeyClient() {
  return new Turnkey({
    apiBaseUrl: TURNKEY_BASE_URL,
    apiPublicKey: TURNKEY_PUB_KEY,
    apiPrivateKey: TURNKEY_PRIV_KEY,
    defaultOrganizationId: TURNKEY_ORG_ID,
  }).apiClient();
}

async function exportKeyBytes(keyId: string): Promise<Uint8Array> {
  const ephemeral = generateP256KeyPair();
  const client = makeTurnkeyClient();
  const result = await client.exportPrivateKey({
    privateKeyId: keyId,
    targetPublicKey: ephemeral.publicKeyUncompressed,
  });
  const hex = await decryptExportBundle({
    exportBundle: result.exportBundle,
    organizationId: TURNKEY_ORG_ID,
    embeddedKey: ephemeral.privateKey,
    returnMnemonic: false,
  });
  return Buffer.from(hex, 'hex');
}

function aesGcmDecrypt(key: Uint8Array, bundle: string): string {
  const { iv, enc, tag } = JSON.parse(bundle) as { iv: string; enc: string; tag: string };
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key.slice(0, 32),
    Buffer.from(iv, 'hex'),
  );
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(enc, 'hex')), decipher.final()]).toString(
    'utf-8',
  );
}

// ── API key cache ────────────────────────────────────────────────────────────

let cachedKey: string | null = null;
let cachedKeyAt = 0;
const KEY_TTL_MS = 5 * 60 * 1000;

async function getApiKey(): Promise<string> {
  const now = Date.now();
  if (cachedKey && now - cachedKeyAt < KEY_TTL_MS) return cachedKey;

  let key: string;

  if (LLM_ENC_KEY_ID && LLM_ENCRYPTED_KEY) {
    // Vault mode: key never stored as plaintext — export via HPKE, decrypt AES-GCM
    const rawKey = await exportKeyBytes(LLM_ENC_KEY_ID);
    key = aesGcmDecrypt(rawKey, LLM_ENCRYPTED_KEY);
  } else if (TURNKEY_ORG_ID) {
    // Auth-gate mode: validate caller identity with Turnkey, return key from env
    const client = makeTurnkeyClient();
    await client.getOrganization({ organizationId: TURNKEY_ORG_ID });
    if (!ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY required in auth-gate mode');
    key = ANTHROPIC_API_KEY;
  } else {
    // Env-key mode: no Turnkey, plain key from env (still protected by enclave)
    if (!ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY not set');
    key = ANTHROPIC_API_KEY;
  }

  cachedKey = key;
  cachedKeyAt = now;
  return key;
}

// ── Session management ───────────────────────────────────────────────────────

interface Session {
  groupFolder: string;
  createdAt: number;
  ttlMs: number;
}

const sessions = new Map<string, Session>();
const DEFAULT_SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

function createSession(groupFolder: string, ttlMs = DEFAULT_SESSION_TTL_MS): string {
  const token = crypto.randomUUID();
  sessions.set(token, { groupFolder, createdAt: Date.now(), ttlMs });
  // Reap expired sessions opportunistically
  const now = Date.now();
  for (const [t, s] of sessions) {
    if (now - s.createdAt > s.ttlMs) sessions.delete(t);
  }
  return token;
}

function lookupSession(token: string): Session | null {
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() - s.createdAt > s.ttlMs) {
    sessions.delete(token);
    return null;
  }
  return s;
}

// ── HTTP server ──────────────────────────────────────────────────────────────

const server = http.createServer(
  (req: http.IncomingMessage, res: http.ServerResponse): void => {
    dispatch(req, res).catch((err) => {
      console.error(JSON.stringify({ level: 'error', msg: 'Unhandled error', err: String(err) }));
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { type: 'api_error', message: 'Internal proxy error' } }));
      }
    });
  },
);

async function dispatch(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const url = req.url ?? '/';
  const method = (req.method ?? 'GET').toUpperCase();

  // ── Health check (TVC readiness probe) ──────────────────────────────────
  if (url === '/health' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  // ── POST /sessions — register a new container session ───────────────────
  if (url === '/sessions' && method === 'POST') {
    if (!isAdminAuthed(req)) return sendError(res, 401, 'authentication_error', 'Invalid admin token');
    const body = await readBody(req);
    let parsed: { groupFolder?: string; ttlMs?: number };
    try {
      parsed = JSON.parse(body) as { groupFolder?: string; ttlMs?: number };
    } catch {
      return sendError(res, 400, 'invalid_request', 'Invalid JSON body');
    }
    if (!parsed.groupFolder) return sendError(res, 400, 'invalid_request', 'groupFolder required');
    const token = createSession(parsed.groupFolder, parsed.ttlMs);
    console.log(
      JSON.stringify({ level: 'info', msg: 'Session registered', group: parsed.groupFolder }),
    );
    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ token }));
    return;
  }

  // ── DELETE /sessions/:token — revoke a session ───────────────────────────
  const revokeMatch = /^\/sessions\/([^/]+)$/.exec(url);
  if (revokeMatch && method === 'DELETE') {
    if (!isAdminAuthed(req)) return sendError(res, 401, 'authentication_error', 'Invalid admin token');
    sessions.delete(revokeMatch[1]);
    res.writeHead(204);
    res.end();
    return;
  }

  // ── * → proxy to api.anthropic.com ──────────────────────────────────────
  const sessionToken =
    extractBearer(req.headers.authorization) || headerStr(req.headers['x-api-key']) || '';

  if (!sessionToken) return sendError(res, 401, 'authentication_error', 'Missing session token');

  const session = lookupSession(sessionToken);
  if (!session) return sendError(res, 401, 'authentication_error', 'Invalid or expired session token');

  let apiKey: string;
  try {
    apiKey = await getApiKey();
  } catch (err) {
    console.error(
      JSON.stringify({ level: 'error', msg: 'Key fetch failed', err: String(err) }),
    );
    return sendError(res, 500, 'api_error', 'Failed to retrieve credentials');
  }

  // Build upstream headers — strip session token, inject real key
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
  upstreamHeaders['host'] = ANTHROPIC_HOST;
  upstreamHeaders['x-api-key'] = apiKey;

  const upstreamReq = https.request(
    {
      hostname: ANTHROPIC_HOST,
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
    console.error(JSON.stringify({ level: 'error', msg: 'Upstream error', err: String(err) }));
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { type: 'api_error', message: 'Upstream request failed' } }));
    }
  });

  req.pipe(upstreamReq, { end: true });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function isAdminAuthed(req: http.IncomingMessage): boolean {
  return !!ADMIN_TOKEN && extractBearer(req.headers.authorization) === ADMIN_TOKEN;
}

function extractBearer(h: string | string[] | undefined): string {
  const v = Array.isArray(h) ? h[0] : h;
  if (!v) return '';
  return v.toLowerCase().startsWith('bearer ') ? v.slice(7).trim() : '';
}

function headerStr(h: string | string[] | undefined): string {
  return Array.isArray(h) ? h[0] : h ?? '';
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
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

// ── Start ────────────────────────────────────────────────────────────────────

assertConfig();
server.listen(PORT, HOST, () => {
  console.log(
    JSON.stringify({ level: 'info', msg: `Listening on ${HOST}:${PORT}` }),
  );
});
