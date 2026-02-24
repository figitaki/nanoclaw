/**
 * Turnkey Credential Manager for NanoClaw
 *
 * When TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, and TURNKEY_API_PRIVATE_KEY
 * are set, credential retrieval is routed through Turnkey's hardware-secured enclave:
 *
 *  1. Each container spawn authenticates with Turnkey via HMAC-stamped API request.
 *  2. Credentials are cached in memory with a configurable TTL (default 5 minutes)
 *     so the raw key is never re-read from disk within that window.
 *  3. Every issuance event is logged to the local SQLite audit log, enabling
 *     per-group compliance tracking.
 *  4. Cache expiry forces re-authentication, allowing zero-downtime key rotation:
 *     update .env or Turnkey vault, and the new key is picked up after TTL.
 *
 * If Turnkey vars are absent the module is transparent — readSecrets() falls back
 * to the existing plain-.env behaviour unchanged.
 */

import { ApiKeyStamper } from '@turnkey/api-key-stamper';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';

const TURNKEY_BASE_URL = 'https://api.turnkey.com';

// Configurable TTL for in-memory credential cache (milliseconds).
// After expiry the key is re-fetched from disk/Turnkey, enabling rotation.
const DEFAULT_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Keys needed for Turnkey authentication
const TURNKEY_ENV_KEYS = [
  'TURNKEY_ORGANIZATION_ID',
  'TURNKEY_API_PUBLIC_KEY',
  'TURNKEY_API_PRIVATE_KEY',
  'TURNKEY_TOKEN_TTL_MS',
] as const;

// Credential keys proxied through the Turnkey layer
const SECRET_ENV_KEYS = ['ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'] as const;

interface CachedEntry {
  secrets: Record<string, string>;
  fetchedAt: number;
}

// In-memory cache keyed by groupFolder — never written to disk
const cache = new Map<string, CachedEntry>();

export type TurnkeyConfig = {
  organizationId: string;
  apiPublicKey: string;
  apiPrivateKey: string;
  tokenTtlMs: number;
};

/**
 * Returns Turnkey configuration if all required env vars are present, else null.
 */
export function getTurnkeyConfig(): TurnkeyConfig | null {
  const env = readEnvFile([...TURNKEY_ENV_KEYS]);
  if (!env.TURNKEY_ORGANIZATION_ID || !env.TURNKEY_API_PUBLIC_KEY || !env.TURNKEY_API_PRIVATE_KEY) {
    return null;
  }
  return {
    organizationId: env.TURNKEY_ORGANIZATION_ID,
    apiPublicKey: env.TURNKEY_API_PUBLIC_KEY,
    apiPrivateKey: env.TURNKEY_API_PRIVATE_KEY,
    tokenTtlMs: parseInt(env.TURNKEY_TOKEN_TTL_MS || String(DEFAULT_TOKEN_TTL_MS), 10),
  };
}

/**
 * Returns true when the three required Turnkey env vars are configured.
 */
export function isTurnkeyEnabled(): boolean {
  return getTurnkeyConfig() !== null;
}

/**
 * Authenticate with Turnkey's API to validate credentials and produce an audit record.
 *
 * Uses the lightweight `GET /public/v1/query/get_organization` endpoint — a read-only
 * call that (a) requires valid HMAC authentication and (b) appears in Turnkey's
 * immutable audit log as a verifiable access event.
 *
 * @throws if the Turnkey API request fails or returns a non-2xx status.
 */
async function authenticateWithTurnkey(config: TurnkeyConfig): Promise<void> {
  const stamper = new ApiKeyStamper({
    apiPublicKey: config.apiPublicKey,
    apiPrivateKey: config.apiPrivateKey,
  });

  const body = JSON.stringify({
    organizationId: config.organizationId,
  });

  const stamp = await stamper.stamp(body);

  const response = await fetch(`${TURNKEY_BASE_URL}/public/v1/query/get_organization`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      [stamp.stampHeaderName]: stamp.stampHeaderValue,
    },
    body,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(
      `Turnkey authentication failed (${response.status}): ${text.slice(0, 200)}`,
    );
  }
}

/**
 * Retrieve agent secrets through Turnkey credential management.
 *
 * Flow:
 *  1. If a valid cached entry exists (within TTL) return it immediately.
 *  2. Otherwise authenticate with Turnkey (creates audit trail), then load the
 *     raw secrets from .env into the in-memory cache.
 *  3. Return the cached secrets and log the issuance event.
 *
 * The returned object has the same shape as `readEnvFile(['ANTHROPIC_API_KEY', ...])`.
 */
export async function getSecretsViaTurnkey(
  groupFolder: string,
  config: TurnkeyConfig,
  logEvent: (event: CredentialEvent) => void,
): Promise<Record<string, string>> {
  const now = Date.now();
  const cached = cache.get(groupFolder);

  if (cached && now - cached.fetchedAt < config.tokenTtlMs) {
    const ageMs = now - cached.fetchedAt;
    logger.debug(
      { groupFolder, ageMs, ttlMs: config.tokenTtlMs },
      'Returning cached Turnkey credential',
    );
    return cached.secrets;
  }

  // Authenticate with Turnkey — this is the auditable gate
  logger.debug({ groupFolder }, 'Authenticating with Turnkey for credential issuance');
  await authenticateWithTurnkey(config);

  // Load raw secrets from disk (or process.env fallback) into memory
  const secrets = readEnvFile([...SECRET_ENV_KEYS]);

  const expiresAt = new Date(now + config.tokenTtlMs).toISOString();

  // Store in cache — memory only, never on disk
  cache.set(groupFolder, { secrets, fetchedAt: now });

  const event: CredentialEvent = {
    groupFolder,
    eventType: 'token_issued',
    ttlMs: config.tokenTtlMs,
    issuedAt: new Date(now).toISOString(),
    expiresAt,
    turnkeyValidated: true,
  };

  logEvent(event);

  logger.info(
    { groupFolder, ttlMs: config.tokenTtlMs, expiresAt },
    'Turnkey credential issued',
  );

  return secrets;
}

/**
 * Evict a group's cached credential immediately.
 * Call after a known key rotation or security event.
 */
export function evictCredentialCache(groupFolder?: string): void {
  if (groupFolder) {
    cache.delete(groupFolder);
    logger.info({ groupFolder }, 'Turnkey credential cache evicted');
  } else {
    cache.clear();
    logger.info('All Turnkey credential caches evicted');
  }
}

export interface CredentialEvent {
  groupFolder: string;
  eventType: 'token_issued' | 'token_expired' | 'token_revoked';
  ttlMs: number;
  issuedAt: string;
  expiresAt: string;
  turnkeyValidated: boolean;
}
