/**
 * Turnkey Credential & Sub-Org Manager for NanoClaw
 *
 * ──────────────────────────── Architecture ────────────────────────────
 *
 *  ┌─────────────────── Turnkey Root Org (operator) ───────────────────┐
 *  │  • NanoClaw service API key pair (TURNKEY_API_PUBLIC/PRIVATE_KEY) │
 *  │  • Optional: secp256k1 "encryption key" whose raw bytes are used  │
 *  │    as an AES-256-GCM key to encrypt ANTHROPIC_API_KEY at rest     │
 *  │    (TURNKEY_LLM_ENCRYPTION_KEY_ID + TURNKEY_LLM_ENCRYPTED_KEY)    │
 *  └────────────────────────────┬──────────────────────────────────────┘
 *                               │  createSubOrganization()
 *                               ▼
 *  ┌─────────────── Turnkey Sub-Org per Agent Group ────────────────────┐
 *  │  • HD Ethereum wallet (BIP-44 m/44'/60'/0'/0/0)                   │
 *  │  • Wallet address passed to containers for on-chain operations     │
 *  │  • Parent API key controls sub-org — no extra credentials needed  │
 *  └────────────────────────────────────────────────────────────────────┘
 *
 * ──────────────── Credential retrieval modes ──────────────────────────
 *
 *  Mode 1 — Auth-gate (TURNKEY_* set, LLM vault vars absent):
 *    Every container spawn authenticates with Turnkey (HMAC-stamped
 *    `get_organization` request), creating an immutable audit record.
 *    The API key itself still lives in .env, cached in memory with TTL.
 *
 *  Mode 2 — Full vault (TURNKEY_LLM_ENCRYPTION_KEY_ID +
 *                        TURNKEY_LLM_ENCRYPTED_KEY also set):
 *    ANTHROPIC_API_KEY is stored nowhere as plaintext. At runtime the
 *    secp256k1 encryption key is exported from Turnkey via HPKE, the
 *    local ciphertext is decrypted with AES-256-GCM, and the plaintext
 *    key lives only in the in-memory cache for the duration of the TTL.
 *    Rotating the key = re-run the setup command, no restart needed.
 *
 * ──────────────────────────── Setup (Mode 2) ──────────────────────────
 *
 *  1. Run the setup helper (from groups/main or via a one-time script):
 *
 *       import { setupLlmKeyVault } from './src/turnkey.js';
 *       const { encryptionKeyId, encryptedKey } =
 *         await setupLlmKeyVault(config, process.env.ANTHROPIC_API_KEY);
 *
 *  2. Add to .env:
 *       TURNKEY_LLM_ENCRYPTION_KEY_ID=<encryptionKeyId>
 *       TURNKEY_LLM_ENCRYPTED_KEY=<encryptedKey>
 *
 *  3. Remove ANTHROPIC_API_KEY from .env — the key no longer needs to
 *     live on disk at all.
 */

import crypto from 'crypto';

import { Turnkey, DEFAULT_ETHEREUM_ACCOUNTS } from '@turnkey/sdk-server';
import { generateP256KeyPair, decryptExportBundle } from '@turnkey/crypto';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';

const TURNKEY_BASE_URL = 'https://api.turnkey.com';
const DEFAULT_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes

const TURNKEY_ENV_KEYS = [
  'TURNKEY_ORGANIZATION_ID',
  'TURNKEY_API_PUBLIC_KEY',
  'TURNKEY_API_PRIVATE_KEY',
  'TURNKEY_TOKEN_TTL_MS',
  'TURNKEY_LLM_ENCRYPTION_KEY_ID',
  'TURNKEY_LLM_ENCRYPTED_KEY',
] as const;

const SECRET_ENV_KEYS = ['ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'] as const;

// ─── Types ────────────────────────────────────────────────────────────────────

export type TurnkeyConfig = {
  organizationId: string;
  apiPublicKey: string;
  apiPrivateKey: string;
  tokenTtlMs: number;
  /** Turnkey private key ID whose raw bytes are the AES-256-GCM key */
  llmEncryptionKeyId?: string;
  /** JSON bundle produced by aesGcmEncrypt(llmEncryptionKey, ANTHROPIC_API_KEY) */
  llmEncryptedKey?: string;
};

export interface SubOrgProvisionResult {
  subOrgId: string;
  walletId: string;
  /** Ethereum address of the group's HD wallet */
  walletAddress: string;
}

export interface CredentialEvent {
  groupFolder: string;
  eventType: 'token_issued' | 'token_expired' | 'token_revoked';
  ttlMs: number;
  issuedAt: string;
  expiresAt: string;
  /** true when the Turnkey get_organization call succeeded */
  turnkeyValidated: boolean;
}

interface CachedEntry {
  secrets: Record<string, string>;
  fetchedAt: number;
}

// In-memory cache keyed by groupFolder — never written to disk
const cache = new Map<string, CachedEntry>();

// ─── Configuration ────────────────────────────────────────────────────────────

/**
 * Returns Turnkey config if all three required vars are set, else null.
 * Reads .env on every call so hot-rotation is reflected after TTL expiry.
 */
export function getTurnkeyConfig(): TurnkeyConfig | null {
  const env = readEnvFile([...TURNKEY_ENV_KEYS]);
  if (
    !env.TURNKEY_ORGANIZATION_ID ||
    !env.TURNKEY_API_PUBLIC_KEY ||
    !env.TURNKEY_API_PRIVATE_KEY
  ) {
    return null;
  }
  return {
    organizationId: env.TURNKEY_ORGANIZATION_ID,
    apiPublicKey: env.TURNKEY_API_PUBLIC_KEY,
    apiPrivateKey: env.TURNKEY_API_PRIVATE_KEY,
    tokenTtlMs: parseInt(env.TURNKEY_TOKEN_TTL_MS || String(DEFAULT_TOKEN_TTL_MS), 10),
    llmEncryptionKeyId: env.TURNKEY_LLM_ENCRYPTION_KEY_ID || undefined,
    llmEncryptedKey: env.TURNKEY_LLM_ENCRYPTED_KEY || undefined,
  };
}

export function isTurnkeyEnabled(): boolean {
  return getTurnkeyConfig() !== null;
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function makeApiClient(config: TurnkeyConfig, orgId?: string) {
  return new Turnkey({
    apiBaseUrl: TURNKEY_BASE_URL,
    apiPublicKey: config.apiPublicKey,
    apiPrivateKey: config.apiPrivateKey,
    defaultOrganizationId: orgId ?? config.organizationId,
  }).apiClient();
}

/**
 * Authenticate with Turnkey's read-only `get_organization` endpoint.
 * This is the auditable gate: it requires valid HMAC credentials and
 * produces an immutable entry in Turnkey's audit log.
 */
async function authenticateWithTurnkey(config: TurnkeyConfig): Promise<void> {
  // We do a lightweight read call — enough to produce an audit record
  // and verify the API key without triggering any write activity.
  const client = makeApiClient(config);

  // getOrganization is available on the apiClient and uses org-scoped auth
  try {
    await client.getOrganization({ organizationId: config.organizationId });
  } catch (err) {
    throw new Error(
      `Turnkey authentication failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/** AES-256-GCM encrypt a UTF-8 plaintext with a 32-byte raw key. Returns JSON bundle. */
function aesGcmEncrypt(key: Uint8Array, plaintext: string): string {
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key.slice(0, 32), iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    iv: iv.toString('hex'),
    enc: enc.toString('hex'),
    tag: tag.toString('hex'),
  });
}

/** AES-256-GCM decrypt. Inverse of aesGcmEncrypt. */
function aesGcmDecrypt(key: Uint8Array, bundle: string): string {
  const { iv, enc, tag } = JSON.parse(bundle) as { iv: string; enc: string; tag: string };
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key.slice(0, 32),
    Buffer.from(iv, 'hex'),
  );
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(enc, 'hex')),
    decipher.final(),
  ]).toString('utf-8');
}

/**
 * Export a Turnkey private key's raw bytes via the HPKE export ceremony.
 *
 * Generates a one-time ephemeral P-256 key pair on the client side,
 * asks Turnkey to encrypt the stored key to it, then decrypts locally.
 * The private key bytes never leave Turnkey's HSM/TEE unencrypted.
 */
async function exportTurnkeyKeyBytes(
  config: TurnkeyConfig,
  privateKeyId: string,
): Promise<Uint8Array> {
  const ephemeral = generateP256KeyPair();
  const client = makeApiClient(config);

  const result = await client.exportPrivateKey({
    privateKeyId,
    targetPublicKey: ephemeral.publicKeyUncompressed,
  });

  // decryptExportBundle handles the HPKE decryption (P256-HKDF-SHA256 + AES-GCM)
  const decryptedHex = await decryptExportBundle({
    exportBundle: result.exportBundle,
    organizationId: config.organizationId,
    embeddedKey: ephemeral.privateKey,
    returnMnemonic: false,
  });

  return Buffer.from(decryptedHex, 'hex');
}

// ─── LLM Key Vault ────────────────────────────────────────────────────────────

/**
 * One-time setup: create a secp256k1 key inside Turnkey's HSM whose raw bytes
 * will serve as the AES-256-GCM encryption key for the LLM API key.
 *
 * Returns the Turnkey private key ID. Store as TURNKEY_LLM_ENCRYPTION_KEY_ID.
 */
export async function createLlmEncryptionKey(config: TurnkeyConfig): Promise<string> {
  const client = makeApiClient(config);
  const result = await client.createPrivateKeys({
    privateKeys: [
      {
        privateKeyName: `nanoclaw-llm-enc-${Date.now()}`,
        curve: 'CURVE_SECP256K1',
        addressFormats: [], // no on-chain address needed
        privateKeyTags: ['nanoclaw-llm-encryption'],
      },
    ],
  });
  const keyId = result.privateKeys[0]?.privateKeyId;
  if (!keyId) throw new Error('Turnkey createPrivateKeys returned no privateKeyId');
  return keyId;
}

/**
 * One-time setup: encrypt apiKey using the key stored at encKeyId in Turnkey.
 *
 * Returns a JSON bundle (the ciphertext). Store as TURNKEY_LLM_ENCRYPTED_KEY.
 * After this step ANTHROPIC_API_KEY can be removed from .env entirely.
 */
export async function encryptLlmKey(
  config: TurnkeyConfig,
  encKeyId: string,
  apiKey: string,
): Promise<string> {
  const rawKey = await exportTurnkeyKeyBytes(config, encKeyId);
  return aesGcmEncrypt(rawKey, apiKey);
}

/**
 * One-step setup helper: creates the encryption key in Turnkey and encrypts
 * the given API key. Returns both values to add to .env.
 */
export async function setupLlmKeyVault(
  config: TurnkeyConfig,
  apiKey: string,
): Promise<{ encryptionKeyId: string; encryptedKey: string }> {
  const encryptionKeyId = await createLlmEncryptionKey(config);
  const encryptedKey = await encryptLlmKey(config, encryptionKeyId, apiKey);
  return { encryptionKeyId, encryptedKey };
}

/**
 * Runtime: retrieve and decrypt the LLM API key.
 * Exports the encryption key from Turnkey via HPKE on every cache miss,
 * ensuring the decryption key never persists on disk.
 */
export async function retrieveLlmKeyFromTurnkey(config: TurnkeyConfig): Promise<string> {
  if (!config.llmEncryptionKeyId || !config.llmEncryptedKey) {
    throw new Error(
      'Both TURNKEY_LLM_ENCRYPTION_KEY_ID and TURNKEY_LLM_ENCRYPTED_KEY must be set for vault mode',
    );
  }
  const rawKey = await exportTurnkeyKeyBytes(config, config.llmEncryptionKeyId);
  return aesGcmDecrypt(rawKey, config.llmEncryptedKey);
}

// ─── Sub-Org Provisioning ─────────────────────────────────────────────────────

/**
 * Provision a Turnkey sub-organization for an agent group.
 *
 * Creates a child org under the NanoClaw root org with:
 *  - The parent API key as root user (so the orchestrator retains full control)
 *  - An HD Ethereum wallet at m/44'/60'/0'/0/0
 *
 * The returned walletAddress is passed to the agent container so it can
 * receive funds, display its address, and request transaction signing via IPC.
 * Private keys never leave Turnkey's HSM — signing requests go through the
 * orchestrator's Turnkey API key.
 *
 * Call once when registering a new group. Idempotent in practice because the
 * sub-org ID is persisted in the DB and checked before calling.
 */
export async function provisionGroupSubOrg(
  groupFolder: string,
  groupName: string,
  config: TurnkeyConfig,
): Promise<SubOrgProvisionResult> {
  const client = makeApiClient(config);

  const result = await client.createSubOrganization({
    subOrganizationName: `nanoclaw-group-${groupFolder}`,
    rootQuorumThreshold: 1,
    // Use the parent org's existing API key as sub-org root user.
    // No new credentials are created; the orchestrator's key controls the sub-org.
    rootUsers: [
      {
        userName: 'nanoclaw-orchestrator',
        apiKeys: [
          {
            apiKeyName: 'orchestrator',
            publicKey: config.apiPublicKey,
            curveType: 'API_KEY_CURVE_P256',
          },
        ],
        authenticators: [],
        oauthProviders: [],
      },
    ],
    wallet: {
      walletName: `${groupName} Wallet`,
      accounts: DEFAULT_ETHEREUM_ACCOUNTS,
    },
  });

  const subOrgId = result.subOrganizationId;
  const walletId = result.wallet!.walletId;
  const walletAddress = result.wallet!.addresses[0];

  logger.info(
    { groupFolder, subOrgId, walletAddress },
    'Turnkey sub-org provisioned for group',
  );

  return { subOrgId, walletId, walletAddress };
}

// ─── Credential Gate ──────────────────────────────────────────────────────────

/**
 * Retrieve agent secrets through Turnkey credential management.
 *
 * Behaviour depends on which env vars are configured:
 *
 *  Auth-gate mode (TURNKEY_* set, vault vars absent):
 *    Authenticates with Turnkey for audit trail. API key loaded from .env,
 *    cached in memory for tokenTtlMs.
 *
 *  Full vault mode (all TURNKEY_* + LLM vault vars set):
 *    ANTHROPIC_API_KEY is never stored as plaintext. The encryption key is
 *    exported from Turnkey's HSM via HPKE on each cache miss, the local
 *    ciphertext is decrypted, and the plaintext key lives only in cache.
 *
 * In both modes secrets are returned as a plain object to be passed to the
 * container via stdin — they are never written to disk.
 */
export async function getSecretsViaTurnkey(
  groupFolder: string,
  config: TurnkeyConfig,
  logEvent: (event: CredentialEvent) => void,
): Promise<Record<string, string>> {
  const now = Date.now();
  const cached = cache.get(groupFolder);

  if (cached && now - cached.fetchedAt < config.tokenTtlMs) {
    logger.debug(
      { groupFolder, ageMs: now - cached.fetchedAt, ttlMs: config.tokenTtlMs },
      'Returning cached Turnkey credential',
    );
    return cached.secrets;
  }

  logger.debug({ groupFolder }, 'Authenticating with Turnkey for credential issuance');
  await authenticateWithTurnkey(config);

  const secrets: Record<string, string> = {};
  const vaultMode = !!(config.llmEncryptionKeyId && config.llmEncryptedKey);

  if (vaultMode) {
    // Full vault: retrieve encrypted API key via HPKE export + AES-GCM decrypt
    secrets.ANTHROPIC_API_KEY = await retrieveLlmKeyFromTurnkey(config);
    // OAuth token is a session credential that can still live in .env
    const env = readEnvFile(['CLAUDE_CODE_OAUTH_TOKEN']);
    if (env.CLAUDE_CODE_OAUTH_TOKEN) {
      secrets.CLAUDE_CODE_OAUTH_TOKEN = env.CLAUDE_CODE_OAUTH_TOKEN;
    }
  } else {
    // Auth-gate: Turnkey validates access; raw secrets come from .env
    const env = readEnvFile([...SECRET_ENV_KEYS]);
    Object.assign(secrets, env);
  }

  const expiresAt = new Date(now + config.tokenTtlMs).toISOString();
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
    { groupFolder, ttlMs: config.tokenTtlMs, expiresAt, vaultMode },
    'Turnkey credential issued',
  );

  return secrets;
}

/**
 * Evict a group's cached credential immediately.
 * Call after a known key rotation or security event to force re-fetch.
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
