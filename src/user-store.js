/**
 * User and Auth Persistence Store
 * Isolated per-user storage for Google tokens, OAuth state, and MCP tokens.
 * Persists data outside deployment directories with 0600 file permissions.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { auditLog } from './audit.js';

// Resolve DATA_DIR
const DEFAULT_HOSTINGER_DATA_DIR = '/home/u142843264/.google-drive-mcp-v2';
export const DATA_DIR = process.env.DATA_DIR || 
  (process.env.NODE_ENV === 'production' ? DEFAULT_HOSTINGER_DATA_DIR : path.resolve(process.cwd(), 'data'));

const USERS_FILE = path.join(DATA_DIR, 'google-users.json');
const OAUTH_STATES_FILE = path.join(DATA_DIR, 'oauth-states.json');
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
  return fileMutex.runExclusive(async () => {
    const data = safeReadJsonSync(USERS_FILE, { users: {} });
    return data.users?.[userSub] || null;
  });
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
    const data = safeReadJsonSync(USERS_FILE, { users: {} });
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

    safeWriteJsonSync(USERS_FILE, data);
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
    const data = safeReadJsonSync(USERS_FILE, { users: {} });
    if (!data.users || !data.users[userSub]) {
      return false;
    }
    delete data.users[userSub];
    safeWriteJsonSync(USERS_FILE, data);
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
    const data = safeReadJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} });
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
    safeWriteJsonSync(MCP_AUTH_FILE, data);
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
    const data = safeReadJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} });
    const record = data.codes?.[code];

    if (!record) {
      const err = new Error('Invalid authorization code');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    if (record.used) {
      delete data.codes[code];
      safeWriteJsonSync(MCP_AUTH_FILE, data);
      const err = new Error('Authorization code has already been used');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    const now = Date.now();
    if (record.expiresAt < now) {
      delete data.codes[code];
      safeWriteJsonSync(MCP_AUTH_FILE, data);
      const err = new Error('Authorization code has expired');
      err.code = 'INVALID_GRANT';
      throw err;
    }

    // Mark used and remove
    record.used = true;
    delete data.codes[code];
    safeWriteJsonSync(MCP_AUTH_FILE, data);

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
    const data = safeReadJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} });
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

    safeWriteJsonSync(MCP_AUTH_FILE, data);
  });
}

/**
 * Get and validate an MCP token (access or refresh).
 */
export async function getMcpToken(tokenString) {
  if (!tokenString) return null;
  return fileMutex.runExclusive(async () => {
    const data = safeReadJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} });
    const tokenRecord = data.tokens?.[tokenString];
    if (!tokenRecord) return null;

    if (tokenRecord.expiresAt < Date.now()) {
      delete data.tokens[tokenString];
      safeWriteJsonSync(MCP_AUTH_FILE, data);
      return null;
    }

    return tokenRecord;
  });
}

/**
 * Revoke an MCP token.
 */
export async function revokeMcpToken(tokenString) {
  if (!tokenString) return;
  return fileMutex.runExclusive(async () => {
    const data = safeReadJsonSync(MCP_AUTH_FILE, { codes: {}, tokens: {} });
    if (data.tokens && data.tokens[tokenString]) {
      delete data.tokens[tokenString];
      safeWriteJsonSync(MCP_AUTH_FILE, data);
    }
  });
}

/**
 * Initialize storage directory at startup.
 */
ensureDataDir();
