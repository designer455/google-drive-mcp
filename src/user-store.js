/**
 * User and Auth Persistence Store
 * Isolated per-user storage for Google tokens, OAuth state, and MCP tokens.
 * Persists data encrypted at rest with AES-256-GCM via Vercel Private Blob
 * (or local filesystem in development).
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { auditLog } from './audit.js';
import {
  getStorageEncryptionKey,
  encryptData,
  decryptData,
  parseEncryptionKey,
  isEncryptedEnvelope,
  safeReadEncryptedJsonSync,
  safeWriteEncryptedJsonSync,
  getStorageBackend,
  isStorageConfigured,
  getBlobDiagnostics,
  readEncryptedStorage,
  writeEncryptedStorage,
  updateEncryptedStorage,
  deleteEncryptedStorage,
  storageMutex
} from './crypto-storage.js';

export {
  getStorageEncryptionKey,
  encryptData,
  decryptData,
  parseEncryptionKey,
  isEncryptedEnvelope,
  safeReadEncryptedJsonSync,
  safeWriteEncryptedJsonSync,
  getStorageBackend,
  isStorageConfigured,
  getBlobDiagnostics,
  readEncryptedStorage,
  writeEncryptedStorage,
  updateEncryptedStorage,
  deleteEncryptedStorage
};

// Logical filenames under DATA_DIR prefix
export const USERS_STORAGE_FILE = 'users.enc.json';
export const GOOGLE_LINKS_STORAGE_FILE = 'google-links.enc.json';
export const OAUTH_STATE_STORAGE_FILE = 'oauth-state.enc.json';
export const MCP_TOKENS_STORAGE_FILE = 'mcp-tokens.enc.json';

// Resolve DATA_DIR safely with local fallback
function resolveDataDir() {
  if (process.env.DATA_DIR) {
    try {
      if (!fs.existsSync(process.env.DATA_DIR)) {
        fs.mkdirSync(process.env.DATA_DIR, { recursive: true, mode: 0o700 });
      }
      return process.env.DATA_DIR;
    } catch {
      return process.env.DATA_DIR;
    }
  }

  if (process.env.VERCEL) {
    return '/google-drive-mcp-v2';
  }

  const localData = path.resolve(process.cwd(), 'data');
  try {
    if (!fs.existsSync(localData)) {
      fs.mkdirSync(localData, { recursive: true, mode: 0o700 });
    }
  } catch {}
  return localData;
}

export const DATA_DIR = resolveDataDir();

/**
 * Ensure local storage directory exists if filesystem backend is active.
 */
export function ensureDataDir() {
  if (getStorageBackend() === 'filesystem') {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
      } else {
        try { fs.chmodSync(DATA_DIR, 0o700); } catch {}
      }
    } catch {}
  }
}

// -------------------------------------------------------------
// Google User Credentials Management
// -------------------------------------------------------------

/**
 * Retrieve Google credentials for a specific user.
 * STRICT MULTI-USER ISOLATION: Each user receives only their own authenticated credentials.
 *
 * @param {string} userSub - Internal opaque user identifier
 * @returns {Promise<Object|null>} User record or null
 */
export async function getUserGoogleRecord(userSub) {
  if (!userSub) return null;

  // 1. Read from encrypted persistent storage (Vercel Private Blob in prod, filesystem in dev)
  try {
    const { data } = await readEncryptedStorage(USERS_STORAGE_FILE, { users: {} });
    const userRecord = data.users?.[userSub] || null;
    if (userRecord && userRecord.google && (userRecord.google.access_token || userRecord.google.refresh_token)) {
      return userRecord;
    }
  } catch (err) {
    auditLog({
      action: 'store.read_error',
      status: 'failure',
      details: { userSub, error: err.message }
    });
  }

  // 2. SINGLE-USER MODE ONLY (strictly opt-in):
  // Never leak credentials across users in standard multi-user mode.
  if (process.env.SINGLE_USER_MODE === 'true' && process.env.GOOGLE_REFRESH_TOKEN) {
    return {
      google: {
        refresh_token: process.env.GOOGLE_REFRESH_TOKEN.trim(),
        scope: process.env.GOOGLE_DRIVE_SCOPES || undefined
      },
      account: {
        email: process.env.GOOGLE_ACCOUNT_EMAIL || 'Single User Account',
        displayName: 'Primary Account'
      },
      source: 'env'
    };
  }

  return null;
}

/**
 * Save or update Google credentials for a specific user.
 *
 * @param {string} userSub - Internal opaque user identifier
 * @param {Object} tokens - Google token set { access_token, refresh_token, expiry_date, token_type, scope }
 * @param {Object} [accountInfo] - { email, displayName }
 * @returns {Promise<Object>} Updated user record
 */
export async function setUserGoogleTokens(userSub, tokens, accountInfo = null) {
  if (!userSub) throw new Error('userSub is required');
  const now = new Date().toISOString();

  let savedRecord = null;
  await updateEncryptedStorage(USERS_STORAGE_FILE, async (data) => {
    if (!data.users) data.users = {};
    const existing = data.users[userSub] || {};

    // Preserve existing refresh token if new token set didn't include one
    const mergedTokens = {
      ...existing.google,
      ...tokens
    };

    savedRecord = {
      google: mergedTokens,
      account: accountInfo || existing.account || { email: null, displayName: null },
      createdAt: existing.createdAt || now,
      updatedAt: now
    };

    data.users[userSub] = savedRecord;
    return data;
  }, { users: {} });

  return savedRecord;
}

/**
 * Delete Google credentials for a specific user (disconnect).
 *
 * @param {string} userSub
 * @returns {Promise<boolean>} true if user was deleted
 */
export async function deleteUserGoogleRecord(userSub) {
  if (!userSub) return false;
  let existed = false;

  await updateEncryptedStorage(USERS_STORAGE_FILE, async (data) => {
    if (!data.users || !data.users[userSub]) {
      existed = false;
      return data;
    }
    delete data.users[userSub];
    existed = true;
    return data;
  }, { users: {} });

  return existed;
}

// -------------------------------------------------------------
// Google OAuth State Management
// -------------------------------------------------------------

// In-memory replay prevention cache for consumed stateless signatures
const consumedSignatures = new Set();

function markSignatureConsumed(sig) {
  if (consumedSignatures.size > 10000) {
    consumedSignatures.clear();
  }
  consumedSignatures.add(sig);
}

function isSignatureConsumed(sig) {
  return consumedSignatures.has(sig);
}

/**
 * Robust secret resolver: strips enclosing quotes and whitespace.
 */
export function getStatelessSigningSecret(fallback) {
  const rawKey = process.env.STORAGE_ENCRYPTION_KEY || process.env.CHATGPT_OAUTH_CLIENT_SECRET;
  if (rawKey && typeof rawKey === 'string') {
    const cleaned = rawKey.trim().replace(/^["']|["']$/g, '');
    if (cleaned) return cleaned;
  }
  return fallback;
}

/**
 * Candidate secret resolver for seamless cross-container verification.
 */
export function getSecretCandidates(fallback) {
  const candidates = [];
  const rawStorage = process.env.STORAGE_ENCRYPTION_KEY;
  if (rawStorage && typeof rawStorage === 'string') {
    const clean = rawStorage.trim().replace(/^["']|["']$/g, '');
    if (clean) candidates.push(clean);
    if (rawStorage !== clean) candidates.push(rawStorage);
  }
  const rawClient = process.env.CHATGPT_OAUTH_CLIENT_SECRET;
  if (rawClient && typeof rawClient === 'string') {
    const clean = rawClient.trim().replace(/^["']|["']$/g, '');
    if (clean && !candidates.includes(clean)) candidates.push(clean);
    if (rawClient !== clean && !candidates.includes(rawClient)) candidates.push(rawClient);
  }
  if (fallback && !candidates.includes(fallback)) {
    candidates.push(fallback);
  }
  return candidates;
}

/**
 * Generate a cryptographically signed, stateless OAuth state bound to userSub.
 */
export function createSignedGoogleOAuthState(userSub, expiresInMs = 600000) {
  if (!userSub) throw new Error('userSub is required');
  const secret = getStatelessSigningSecret('gstate-secret-key');
  const data = {
    sub: userSub,
    exp: Date.now() + expiresInMs,
    rnd: crypto.randomBytes(16).toString('hex')
  };
  const body = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(`gstate_${body}`).digest('base64url');
  return `gstate_${body}.${sig}`;
}

/**
 * Verify and decode an HMAC-signed Google OAuth state. Returns userSub or throws.
 */
export function verifySignedGoogleOAuthState(stateString) {
  if (!stateString || typeof stateString !== 'string') return null;
  const parts = stateString.split('.');
  if (parts.length !== 2) return null;
  const [prefixAndBody, sig] = parts;
  if (!prefixAndBody.startsWith('gstate_')) return null;

  const bufA = Buffer.from(sig);
  const candidates = getSecretCandidates('gstate-secret-key');
  let matched = false;

  for (const candidateSecret of candidates) {
    const expectedSig = crypto.createHmac('sha256', candidateSecret).update(prefixAndBody).digest('base64url');
    const bufB = Buffer.from(expectedSig);
    if (bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)) {
      matched = true;
      break;
    }
  }

  if (!matched) return null;

  try {
    const bodyStr = prefixAndBody.slice('gstate_'.length);
    const payload = JSON.parse(Buffer.from(bodyStr, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) {
      const err = new Error('OAuth state has expired');
      err.code = 'OAUTH_STATE_EXPIRED';
      throw err;
    }
    return payload.sub || null;
  } catch (err) {
    if (err.code === 'OAUTH_STATE_EXPIRED') throw err;
    return null;
  }
}

/**
 * Save Google OAuth state record bound to a userSub in encrypted persistent storage.
 *
 * @param {string} state - Cryptographically random state string
 * @param {string} userSub - Opaque user ID
 * @param {number} [expiresInMs=600000] - Lifetime in milliseconds
 */
export async function saveGoogleOAuthState(state, userSub, expiresInMs = 600000) {
  const now = Date.now();
  const expiresAt = now + expiresInMs;
  const stateHash = crypto.createHash('sha256').update(state).digest('hex');

  await updateEncryptedStorage(OAUTH_STATE_STORAGE_FILE, async (data) => {
    data.states = data.states || {};

    // Prune expired states
    for (const [s, record] of Object.entries(data.states)) {
      if (record.expiresAt < now || record.used) {
        delete data.states[s];
      }
    }

    data.states[state] = {
      stateHash,
      userSub,
      createdAt: new Date(now).toISOString(),
      expiresAt,
      used: false
    };

    return data;
  }, { states: {} });
}

/**
 * Atomically consume and validate Google OAuth state.
 * Supports both stateless HMAC-signed state and persistent encrypted store.
 * Returns the bound userSub if valid, or throws error.
 *
 * @param {string} state
 * @returns {Promise<string>} Bound userSub
 */
export async function consumeGoogleOAuthState(state) {
  if (!state) {
    const err = new Error('Missing OAuth state parameter');
    err.code = 'OAUTH_STATE_INVALID';
    throw err;
  }

  // Stateless HMAC signed state check (survives container recycling)
  if (typeof state === 'string' && state.startsWith('gstate_') && state.includes('.')) {
    const userSub = verifySignedGoogleOAuthState(state);
    if (!userSub) {
      const err = new Error('Invalid or unknown OAuth state');
      err.code = 'OAUTH_STATE_INVALID';
      throw err;
    }
    const sig = state.split('.')[1];
    if (isSignatureConsumed(sig)) {
      const err = new Error('OAuth state has already been consumed (replay detected)');
      err.code = 'OAUTH_STATE_REPLAY';
      throw err;
    }
    markSignatureConsumed(sig);
    return userSub;
  }

  let boundUserSub = null;
  await updateEncryptedStorage(OAUTH_STATE_STORAGE_FILE, async (data) => {
    data.states = data.states || {};
    const record = data.states[state];

    if (!record) {
      const err = new Error('Invalid or unknown OAuth state');
      err.code = 'OAUTH_STATE_INVALID';
      throw err;
    }

    if (record.used) {
      const err = new Error('OAuth state has already been consumed (replay detected)');
      err.code = 'OAUTH_STATE_REPLAY';
      throw err;
    }

    const now = Date.now();
    if (record.expiresAt < now) {
      delete data.states[state];
      const err = new Error('OAuth state has expired');
      err.code = 'OAUTH_STATE_EXPIRED';
      throw err;
    }

    // Mark as used and delete immediately to enforce single-use
    record.used = true;
    boundUserSub = record.userSub;
    delete data.states[state];

    return data;
  }, { states: {} });

  return boundUserSub;
}

// -------------------------------------------------------------
// Google One-Time Link Token Store
// -------------------------------------------------------------

/**
 * Generate a cryptographically signed, stateless Google link token bound to userSub.
 */
export function createSignedGoogleLinkToken(userSub, expiresInMs = 600000) {
  if (!userSub) throw new Error('userSub is required');
  const secret = getStatelessSigningSecret('glink-secret-key');
  const data = {
    sub: userSub,
    exp: Date.now() + expiresInMs,
    rnd: crypto.randomBytes(16).toString('hex')
  };
  const body = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(`glink_${body}`).digest('base64url');
  return `glink_${body}.${sig}`;
}

/**
 * Verify and decode an HMAC-signed Google link token. Returns userSub or throws.
 */
export function verifySignedGoogleLinkToken(tokenString) {
  if (!tokenString || typeof tokenString !== 'string') return null;
  const parts = tokenString.split('.');
  if (parts.length !== 2) return null;
  const [prefixAndBody, sig] = parts;
  if (!prefixAndBody.startsWith('glink_')) return null;

  const bufA = Buffer.from(sig);
  const candidates = getSecretCandidates('glink-secret-key');
  let matched = false;

  for (const candidateSecret of candidates) {
    const expectedSig = crypto.createHmac('sha256', candidateSecret).update(prefixAndBody).digest('base64url');
    const bufB = Buffer.from(expectedSig);
    if (bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)) {
      matched = true;
      break;
    }
  }

  if (!matched) return null;

  try {
    const bodyStr = prefixAndBody.slice('glink_'.length);
    const payload = JSON.parse(Buffer.from(bodyStr, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) {
      const err = new Error('Google link token has expired');
      err.code = 'GOOGLE_LINK_EXPIRED';
      throw err;
    }
    return payload.sub || null;
  } catch (err) {
    if (err.code === 'GOOGLE_LINK_EXPIRED') throw err;
    return null;
  }
}

/**
 * Save a one-time Google link token securely (hashed) in encrypted persistent storage.
 *
 * @param {string} linkToken - Cryptographically random token (e.g. glink_...)
 * @param {string} userSub - Opaque MCP user ID
 * @param {number} [expiresInMs] - Lifetime in milliseconds
 */
export async function saveGoogleLinkToken(linkToken, userSub, expiresInMs) {
  if (!linkToken || !userSub) {
    throw new Error('linkToken and userSub are required');
  }
  const expirySecs = parseInt(process.env.OAUTH_GOOGLE_LINK_EXPIRY_SECONDS, 10) || 600;
  const durationMs = expiresInMs !== undefined ? expiresInMs : expirySecs * 1000;
  const now = Date.now();
  const expiresAt = now + durationMs;
  const tokenHash = crypto.createHash('sha256').update(linkToken).digest('hex');

  await updateEncryptedStorage(GOOGLE_LINKS_STORAGE_FILE, async (data) => {
    data.tokens = data.tokens || {};

    // Prune expired or used tokens
    for (const [hash, record] of Object.entries(data.tokens)) {
      if (record.expiresAt < now || record.used) {
        delete data.tokens[hash];
      }
    }

    data.tokens[tokenHash] = {
      tokenHash,
      userSub,
      createdAt: new Date(now).toISOString(),
      expiresAt,
      used: false
    };

    return data;
  }, { tokens: {} });
}

/**
 * Atomically consume and validate a one-time Google link token.
 * Supports both stateless HMAC-signed tokens and encrypted persistent store.
 * Returns the bound userSub if valid, or throws error.
 *
 * @param {string} linkToken
 * @returns {Promise<string>} Bound userSub
 */
export async function consumeGoogleLinkToken(linkToken) {
  if (!linkToken) {
    const err = new Error('Missing Google link token');
    err.code = 'GOOGLE_LINK_INVALID';
    throw err;
  }

  // Stateless HMAC signed link token check
  if (typeof linkToken === 'string' && linkToken.startsWith('glink_') && linkToken.includes('.')) {
    const userSub = verifySignedGoogleLinkToken(linkToken);
    if (!userSub) {
      const err = new Error('Invalid or unknown Google link token');
      err.code = 'GOOGLE_LINK_INVALID';
      throw err;
    }
    const sig = linkToken.split('.')[1];
    if (isSignatureConsumed(sig)) {
      const err = new Error('Google link token has already been consumed (replay detected)');
      err.code = 'GOOGLE_LINK_REPLAY';
      throw err;
    }
    markSignatureConsumed(sig);
    return userSub;
  }

  const tokenHash = crypto.createHash('sha256').update(linkToken).digest('hex');
  let boundUserSub = null;

  await updateEncryptedStorage(GOOGLE_LINKS_STORAGE_FILE, async (data) => {
    data.tokens = data.tokens || {};
    const record = data.tokens[tokenHash];

    if (!record) {
      const err = new Error('Invalid or unknown Google link token');
      err.code = 'GOOGLE_LINK_INVALID';
      throw err;
    }

    if (record.used) {
      const err = new Error('Google link token has already been consumed (replay detected)');
      err.code = 'GOOGLE_LINK_REPLAY';
      throw err;
    }

    const now = Date.now();
    if (record.expiresAt < now) {
      delete data.tokens[tokenHash];
      const err = new Error('Google link token has expired');
      err.code = 'GOOGLE_LINK_EXPIRED';
      throw err;
    }

    // Mark as used and delete immediately to enforce single-use
    record.used = true;
    boundUserSub = record.userSub;
    delete data.tokens[tokenHash];

    return data;
  }, { tokens: {} });

  return boundUserSub;
}

// -------------------------------------------------------------
// ChatGPT MCP OAuth Store (Auth Codes, Access Tokens, Refresh Tokens)
// -------------------------------------------------------------

/**
 * Save an MCP authorization code in encrypted persistent storage.
 */
export async function saveMcpAuthCode({
  code,
  clientId,
  redirectUri,
  codeChallenge,
  codeChallengeMethod,
  userSub,
  scope,
  expiresInMs = 300000
}) {
  const now = Date.now();
  await updateEncryptedStorage(MCP_TOKENS_STORAGE_FILE, async (data) => {
    data.codes = data.codes || {};
    data.codes[code] = {
      code,
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      userSub,
      scope,
      createdAt: now,
      expiresAt: now + expiresInMs,
      used: false
    };
    return data;
  }, { codes: {}, tokens: {} });
}

/**
 * Atomically consume and validate an MCP authorization code.
 */
export async function consumeMcpAuthCode(code) {
  if (!code) {
    const err = new Error('Missing authorization code');
    err.code = 'INVALID_GRANT';
    throw err;
  }

  let codeRecord = null;
  await updateEncryptedStorage(MCP_TOKENS_STORAGE_FILE, async (data) => {
    data.codes = data.codes || {};
    const record = data.codes[code];

    if (!record) {
      const err = new Error('Invalid authorization code');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    if (record.used) {
      delete data.codes[code];
      const err = new Error('Authorization code has already been used');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    const now = Date.now();
    if (record.expiresAt < now) {
      delete data.codes[code];
      const err = new Error('Authorization code has expired');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    // Mark used and retain tombstone for replay rejection
    record.used = true;
    codeRecord = { ...record };
    data.codes[code] = {
      used: true,
      expiresAt: record.expiresAt
    };

    return data;
  }, { codes: {}, tokens: {} });

  return codeRecord;
}

/**
 * Save MCP issued tokens in encrypted persistent storage.
 */
export async function saveMcpTokens({
  accessToken,
  refreshToken = null,
  userSub,
  clientId,
  scope,
  accessExpiresInMs = 3600000,
  refreshExpiresInMs = 2592000000 // 30 days
}) {
  const now = Date.now();
  await updateEncryptedStorage(MCP_TOKENS_STORAGE_FILE, async (data) => {
    data.tokens = data.tokens || {};

    // Save access token
    data.tokens[accessToken] = {
      type: 'access',
      token: accessToken,
      userSub,
      clientId,
      scope,
      createdAt: now,
      expiresAt: now + accessExpiresInMs
    };

    // Save refresh token if provided
    if (refreshToken) {
      data.tokens[refreshToken] = {
        type: 'refresh',
        token: refreshToken,
        userSub,
        clientId,
        scope,
        createdAt: now,
        expiresAt: now + refreshExpiresInMs
      };
    }

    return data;
  }, { codes: {}, tokens: {} });
}

/**
 * Mint a self-verifying, HMAC-signed MCP token that survives container recycling.
 */
export function generateSignedMcpToken(prefix, payload, expiresInMs) {
  const secret = getStatelessSigningSecret('mcp-stateless-auth-secret');
  const data = {
    ...payload,
    exp: Date.now() + expiresInMs,
    rnd: crypto.randomBytes(8).toString('hex')
  };
  const body = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(`${prefix}${body}`).digest('base64url');
  return `${prefix}${body}.${sig}`;
}

/**
 * Verify and decode an HMAC-signed MCP token.
 */
export function verifySignedMcpToken(tokenString, expectedPrefix = null) {
  if (!tokenString || typeof tokenString !== 'string') return null;
  const parts = tokenString.split('.');
  if (parts.length !== 2) return null;

  const [prefixAndBody, sig] = parts;
  if (expectedPrefix && !prefixAndBody.startsWith(expectedPrefix)) return null;

  const bufA = Buffer.from(sig);
  const candidates = getSecretCandidates('mcp-stateless-auth-secret');
  let matched = false;

  for (const candidateSecret of candidates) {
    const expectedSig = crypto.createHmac('sha256', candidateSecret).update(prefixAndBody).digest('base64url');
    const bufB = Buffer.from(expectedSig);
    if (bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)) {
      matched = true;
      break;
    }
  }

  if (!matched) return null;

  try {
    const prefix = prefixAndBody.startsWith('mcp_at_') ? 'mcp_at_' : (prefixAndBody.startsWith('mcp_rt_') ? 'mcp_rt_' : '');
    const bodyStr = prefixAndBody.slice(prefix.length);
    const payload = JSON.parse(Buffer.from(bodyStr, 'base64url').toString('utf8'));

    if (payload.exp && Date.now() > payload.exp) {
      return null;
    }

    return {
      type: prefix === 'mcp_rt_' ? 'refresh' : 'access',
      token: tokenString,
      userSub: payload.sub,
      clientId: payload.cid,
      scope: payload.scp,
      createdAt: payload.iat || (payload.exp - 3600000),
      expiresAt: payload.exp
    };
  } catch {
    return null;
  }
}

/**
 * Get and validate an MCP token (access or refresh).
 */
export async function getMcpToken(tokenString) {
  if (!tokenString) return null;

  try {
    const { data } = await readEncryptedStorage(MCP_TOKENS_STORAGE_FILE, { codes: {}, tokens: {} });
    const tokenRecord = data.tokens?.[tokenString];

    if (tokenRecord) {
      if (tokenRecord.expiresAt < Date.now()) {
        // Expired - prune asynchronously
        updateEncryptedStorage(MCP_TOKENS_STORAGE_FILE, async (storeData) => {
          if (storeData.tokens?.[tokenString]) {
            delete storeData.tokens[tokenString];
          }
          return storeData;
        }, { codes: {}, tokens: {} }).catch(() => {});
        return null;
      }
      return tokenRecord;
    }
  } catch (err) {
    auditLog({
      action: 'store.token_read_error',
      status: 'failure',
      details: { error: err.message }
    });
  }

  // Stateless HMAC validation fallback
  const statelessRecord = verifySignedMcpToken(tokenString);
  if (statelessRecord) {
    return statelessRecord;
  }

  return null;
}

/**
 * Revoke an MCP token.
 */
export async function revokeMcpToken(tokenString) {
  if (!tokenString) return;
  await updateEncryptedStorage(MCP_TOKENS_STORAGE_FILE, async (data) => {
    if (data.tokens && data.tokens[tokenString]) {
      delete data.tokens[tokenString];
    }
    return data;
  }, { codes: {}, tokens: {} });
}

/**
 * Initialize storage directory at startup if local filesystem mode.
 */
ensureDataDir();
