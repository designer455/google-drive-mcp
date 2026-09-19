/**
 * User and Auth Persistence Store
 * Isolated per-user storage for Google tokens, OAuth state, and MCP tokens.
 * Persists data outside deployment directories with 0600 file permissions.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { auditLog } from './audit.js';
import {
  safeReadEncryptedJsonSync,
  safeWriteEncryptedJsonSync,
  getStorageEncryptionKey,
  encryptData,
  decryptData,
  parseEncryptionKey,
  isEncryptedEnvelope
} from './crypto-storage.js';

export {
  getStorageEncryptionKey,
  encryptData,
  decryptData,
  parseEncryptionKey,
  isEncryptedEnvelope,
  safeReadEncryptedJsonSync,
  safeWriteEncryptedJsonSync
};

// Resolve DATA_DIR safely with local fallback if configured path is inaccessible
const DEFAULT_HOSTINGER_DATA_DIR = '/home/u142843264/.google-drive-mcp-v2';

function resolveDataDir() {
  if (process.env.DATA_DIR) {
    try {
      if (!fs.existsSync(process.env.DATA_DIR)) {
        fs.mkdirSync(process.env.DATA_DIR, { recursive: true, mode: 0o700 });
      }
      return process.env.DATA_DIR;
    } catch {}
  }

  // If running inside Vercel serverless functions, use os.tmpdir()
  if (process.env.VERCEL) {
    const vercelTmp = path.join(os.tmpdir(), '.google-drive-mcp');
    try {
      if (!fs.existsSync(vercelTmp)) {
        fs.mkdirSync(vercelTmp, { recursive: true, mode: 0o700 });
      }
      return vercelTmp;
    } catch {}
  }

  const configured = process.env.NODE_ENV === 'production' 
    ? DEFAULT_HOSTINGER_DATA_DIR 
    : path.resolve(process.cwd(), 'data');

  try {
    if (!fs.existsSync(configured)) {
      fs.mkdirSync(configured, { recursive: true, mode: 0o700 });
    }
    return configured;
  } catch {
    // If the path cannot be created, fallback to os.tmpdir or local ./data
    const fallback = process.env.VERCEL 
      ? path.join(os.tmpdir(), '.google-drive-mcp') 
      : path.resolve(process.cwd(), 'data');
    if (!fs.existsSync(fallback)) {
      try {
        fs.mkdirSync(fallback, { recursive: true, mode: 0o700 });
      } catch {}
    }
    return fallback;
  }
}

export const DATA_DIR = resolveDataDir();

const USERS_FILE = path.join(DATA_DIR, 'google-users.json');
const OAUTH_STATES_FILE = path.join(DATA_DIR, 'oauth-states.json');
const GOOGLE_LINK_TOKENS_FILE = path.join(DATA_DIR, 'google-link-tokens.json');
const MCP_AUTH_FILE = path.join(DATA_DIR, 'mcp-auth.json');

// Mutex queue to prevent race conditions in concurrent file writes
class Mutex {
  constructor() {
    this._queue = Promise.resolve();
  }

  async runExclusive(fn) {
    let release;
    const next = new Promise(resolve => {
      release = resolve;
    });
    const prev = this._queue;
    this._queue = prev.then(() => next);
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

const fileMutex = new Mutex();

/**
 * Ensure storage directory exists with restricted permissions (0700).
 */
export function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  } else {
    try {
      fs.chmodSync(DATA_DIR, 0o700);
    } catch {
      // Ignore chmod errors on some systems/mounts
    }
  }
}

/**
 * Atomically write a file using a temporary file and atomic rename, with 0600 permissions.
 */
function safeWriteJsonSync(filePath, data) {
  ensureDataDir();
  const dir = path.dirname(filePath);
  const tempPath = path.join(dir, `.tmp_${path.basename(filePath)}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`);
  const content = JSON.stringify(data, null, 2);

  // Write temporary file with 0600 permissions
  fs.writeFileSync(tempPath, content, { mode: 0o600 });
  try {
    fs.chmodSync(tempPath, 0o600);
  } catch {
    // Ignore chmod errors if filesystem restricts it
  }

  // Atomic replace
  fs.renameSync(tempPath, filePath);
}

/**
 * Safely read a JSON file, returning defaultValue if missing or corrupted.
 */
function safeReadJsonSync(filePath, defaultValue) {
  try {
    if (!fs.existsSync(filePath)) {
      return defaultValue;
    }
    const content = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(content);
  } catch (err) {
    auditLog({
      action: 'store.read_error',
      status: 'failure',
      details: { file: path.basename(filePath), error: err.message }
    });
    return defaultValue;
  }
}

// -------------------------------------------------------------
// Google User Credentials Management
// -------------------------------------------------------------

/**
 * Retrieve Google credentials for a specific user.
 *
 * @param {string} userSub - Internal opaque user identifier
 * @returns {Object|null} User record or null
 */
export async function getUserGoogleRecord(userSub) {
  if (!userSub) return null;
  const userRecord = await fileMutex.runExclusive(async () => {
    const data = safeReadEncryptedJsonSync(USERS_FILE, { users: {} }, undefined, safeWriteJsonSync);
    return data.users?.[userSub] || null;
  });

  const envRefreshToken = process.env.GOOGLE_REFRESH_TOKEN ? process.env.GOOGLE_REFRESH_TOKEN.trim() : null;

  if (userRecord && userRecord.google) {
    // If user record exists in store, supplement with env refresh token if missing
    if (!userRecord.google.refresh_token && envRefreshToken) {
      userRecord.google.refresh_token = envRefreshToken;
    }
    if (userRecord.google.access_token || userRecord.google.refresh_token) {
      return userRecord;
    }
  }

  // Solution 1: Fallback to GOOGLE_REFRESH_TOKEN environment variable (permanent connection on Vercel)
  if (envRefreshToken) {
    return {
      google: {
        refresh_token: envRefreshToken,
        scope: process.env.GOOGLE_DRIVE_SCOPES || undefined
      },
      account: {
        email: process.env.GOOGLE_ACCOUNT_EMAIL || 'Connected Google Account',
        displayName: 'Primary Google Account'
      },
      source: 'env'
    };
  }

  return userRecord;
}

/**
 * Save or update Google credentials for a specific user.
 *
 * @param {string} userSub - Internal opaque user identifier
 * @param {Object} tokens - Google token set { access_token, refresh_token, expiry_date, token_type, scope }
 * @param {Object} [accountInfo] - { email, displayName }
 */
export async function setUserGoogleTokens(userSub, tokens, accountInfo = null) {
  if (!userSub) throw new Error('userSub is required');
  return fileMutex.runExclusive(async () => {
    const data = safeReadEncryptedJsonSync(USERS_FILE, { users: {} }, undefined, safeWriteJsonSync);
    if (!data.users) data.users = {};

    const existing = data.users[userSub] || {};
    const now = new Date().toISOString();

    // Preserve existing refresh token if new token set didn't include one
    const mergedTokens = {
      ...existing.google,
      ...tokens
    };

    data.users[userSub] = {
      google: mergedTokens,
      account: accountInfo || existing.account || { email: null, displayName: null },
      createdAt: existing.createdAt || now,
      updatedAt: now
    };

    safeWriteEncryptedJsonSync(USERS_FILE, data, undefined, safeWriteJsonSync);
    return data.users[userSub];
  });
}

/**
 * Delete Google credentials for a specific user (disconnect).
 *
 * @param {string} userSub
 * @returns {boolean} true if user was deleted
 */
export async function deleteUserGoogleRecord(userSub) {
  if (!userSub) return false;
  return fileMutex.runExclusive(async () => {
    const data = safeReadEncryptedJsonSync(USERS_FILE, { users: {} }, undefined, safeWriteJsonSync);
    if (!data.users || !data.users[userSub]) {
      return false;
    }
    delete data.users[userSub];
    safeWriteEncryptedJsonSync(USERS_FILE, data, undefined, safeWriteJsonSync);
    return true;
  });
}

// -------------------------------------------------------------
// Google OAuth State Management
// -------------------------------------------------------------

/**
 * Save Google OAuth state record bound to a userSub.
 *
 * @param {string} state - Cryptographically random state string
 * @param {string} userSub - Opaque user ID
 * @param {number} expiresInMs - Lifetime in milliseconds
 */
export async function saveGoogleOAuthState(state, userSub, expiresInMs = 600000) {
  return fileMutex.runExclusive(async () => {
    const data = safeReadJsonSync(OAUTH_STATES_FILE, { states: {} });
    const now = Date.now();
    const expiresAt = now + expiresInMs;

    // Prune expired states
    for (const [s, record] of Object.entries(data.states || {})) {
      if (record.expiresAt < now || record.used) {
        delete data.states[s];
      }
    }

    const stateHash = crypto.createHash('sha256').update(state).digest('hex');
    data.states = data.states || {};
    data.states[state] = {
      stateHash,
      userSub,
      createdAt: new Date(now).toISOString(),
      expiresAt,
      used: false
    };

    safeWriteJsonSync(OAUTH_STATES_FILE, data);
  });
}

/**
 * Atomically consume and validate Google OAuth state.
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

  return fileMutex.runExclusive(async () => {
    const data = safeReadJsonSync(OAUTH_STATES_FILE, { states: {} });
    const record = data.states?.[state];

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
      safeWriteJsonSync(OAUTH_STATES_FILE, data);
      const err = new Error('OAuth state has expired');
      err.code = 'OAUTH_STATE_EXPIRED';
      throw err;
    }


    // Mark as used and delete immediately to prevent reuse
    record.used = true;
    const userSub = record.userSub;
    delete data.states[state];
    safeWriteJsonSync(OAUTH_STATES_FILE, data);

    return userSub;
  });
}

// -------------------------------------------------------------
// Google One-Time Link Token Store
// -------------------------------------------------------------

/**
 * Save a one-time Google link token securely (hashed).
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

  return fileMutex.runExclusive(async () => {
    const data = safeReadJsonSync(GOOGLE_LINK_TOKENS_FILE, { tokens: {} });
    const now = Date.now();
    const expiresAt = now + durationMs;

    data.tokens = data.tokens || {};
    // Prune expired or used tokens
    for (const [hash, record] of Object.entries(data.tokens)) {
      if (record.expiresAt < now || record.used) {
        delete data.tokens[hash];
      }
    }

    const tokenHash = crypto.createHash('sha256').update(linkToken).digest('hex');
    data.tokens[tokenHash] = {
      tokenHash,
      userSub,
      createdAt: new Date(now).toISOString(),
      expiresAt,
      used: false
    };

    safeWriteJsonSync(GOOGLE_LINK_TOKENS_FILE, data);
  });
}

/**
 * Atomically consume and validate a one-time Google link token.
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

  return fileMutex.runExclusive(async () => {
    const data = safeReadJsonSync(GOOGLE_LINK_TOKENS_FILE, { tokens: {} });
    const tokenHash = crypto.createHash('sha256').update(linkToken).digest('hex');
    const record = data.tokens?.[tokenHash];

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
      safeWriteJsonSync(GOOGLE_LINK_TOKENS_FILE, data);
      const err = new Error('Google link token has expired');
      err.code = 'GOOGLE_LINK_EXPIRED';
      throw err;
    }

    // Mark as used and delete immediately to prevent reuse
    record.used = true;
    const userSub = record.userSub;
    delete data.tokens[tokenHash];
    safeWriteJsonSync(GOOGLE_LINK_TOKENS_FILE, data);

    return userSub;
  });
}

// -------------------------------------------------------------
// ChatGPT MCP OAuth Store (Auth Codes, Access Tokens, Refresh Tokens)
// -------------------------------------------------------------

/**
 * Save an MCP authorization code.
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
  return fileMutex.runExclusive(async () => {
    const data = safeReadEncryptedJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} }, undefined, safeWriteJsonSync);
    const now = Date.now();
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
    safeWriteEncryptedJsonSync(MCP_AUTH_FILE, data, undefined, safeWriteJsonSync);
  });
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

  return fileMutex.runExclusive(async () => {
    const data = safeReadEncryptedJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} }, undefined, safeWriteJsonSync);
    const record = data.codes?.[code];

    if (!record) {
      const err = new Error('Invalid authorization code');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    if (record.used) {
      delete data.codes[code];
      safeWriteEncryptedJsonSync(MCP_AUTH_FILE, data, undefined, safeWriteJsonSync);
      const err = new Error('Authorization code has already been used');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    const now = Date.now();
    if (record.expiresAt < now) {
      delete data.codes[code];
      safeWriteEncryptedJsonSync(MCP_AUTH_FILE, data, undefined, safeWriteJsonSync);
      const err = new Error('Authorization code has expired');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    // Mark used and remove
    record.used = true;
    delete data.codes[code];
    safeWriteEncryptedJsonSync(MCP_AUTH_FILE, data, undefined, safeWriteJsonSync);

    return record;
  });
}

/**
 * Save MCP issued tokens.
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
  return fileMutex.runExclusive(async () => {
    const data = safeReadEncryptedJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} }, undefined, safeWriteJsonSync);
    const now = Date.now();
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

    safeWriteEncryptedJsonSync(MCP_AUTH_FILE, data, undefined, safeWriteJsonSync);
  });
}

/**
 * Mint a self-verifying, HMAC-signed MCP token that survives serverless container restarts.
 */
export function generateSignedMcpToken(prefix, payload, expiresInMs) {
  const secret = process.env.STORAGE_ENCRYPTION_KEY || process.env.CHATGPT_OAUTH_CLIENT_SECRET || 'mcp-stateless-auth-secret';
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

  const secret = process.env.STORAGE_ENCRYPTION_KEY || process.env.CHATGPT_OAUTH_CLIENT_SECRET || 'mcp-stateless-auth-secret';
  const expectedSig = crypto.createHmac('sha256', secret).update(prefixAndBody).digest('base64url');

  try {
    const bufA = Buffer.from(sig);
    const bufB = Buffer.from(expectedSig);
    if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
      return null;
    }

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
  const storedRecord = await fileMutex.runExclusive(async () => {
    const data = safeReadEncryptedJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} }, undefined, safeWriteJsonSync);
    const tokenRecord = data.tokens?.[tokenString];
    if (!tokenRecord) return null;

    if (tokenRecord.expiresAt < Date.now()) {
      delete data.tokens[tokenString];
      safeWriteEncryptedJsonSync(MCP_AUTH_FILE, data, undefined, safeWriteJsonSync);
      return null;
    }

    return tokenRecord;
  });

  if (storedRecord) {
    return storedRecord;
  }

  // Stateless HMAC validation fallback (survives Vercel serverless container recycling)
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
  return fileMutex.runExclusive(async () => {
    const data = safeReadEncryptedJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} }, undefined, safeWriteJsonSync);
    if (data.tokens && data.tokens[tokenString]) {
      delete data.tokens[tokenString];
      safeWriteEncryptedJsonSync(MCP_AUTH_FILE, data, undefined, safeWriteJsonSync);
    }
  });
}

/**
 * Initialize storage directory at startup.
 */
ensureDataDir();
