/**
 * AES-256-GCM Credential Encryption at Rest (SEC-04)
 * Provides authenticated encryption, decryption, envelope serialization,
 * key validation, and automatic backward-compatible migration for credential stores.
 *
 * Implements persistent filesystem-style encrypted JSON storage backed by
 * Vercel Private Blob (@vercel/blob) in production, with local filesystem fallback for development.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { text } from 'node:stream/consumers';
import { get, put, del } from '@vercel/blob';
import { auditLog } from './audit.js';

export const CURRENT_ENCRYPTION_VERSION = 1;
export const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
export const IV_LENGTH_BYTES = 12; // 96-bit nonce standard for GCM
export const KEY_LENGTH_BYTES = 32; // 256-bit key for AES-256
export const AUTH_TAG_LENGTH_BYTES = 16; // 128-bit authentication tag

// Deterministic test key fallback strictly for automated testing when key is unset
const TEST_FALLBACK_KEY = Buffer.alloc(KEY_LENGTH_BYTES, 0x42);

/**
 * Validate and parse a 32-byte encryption key from string or buffer.
 * Supports Base64 (recommended) or 64-character Hex encoding.
 *
 * @param {string|Buffer} keyInput
 * @returns {Buffer} 32-byte Buffer
 */
export function parseEncryptionKey(keyInput) {
  if (Buffer.isBuffer(keyInput)) {
    if (keyInput.length !== KEY_LENGTH_BYTES) {
      throw new Error(`Invalid key length: expected ${KEY_LENGTH_BYTES} bytes, received ${keyInput.length} bytes.`);
    }
    return keyInput;
  }

  if (!keyInput || typeof keyInput !== 'string') {
    const err = new Error('STORAGE_ENCRYPTION_KEY must be a non-empty string.');
    err.code = 'INVALID_KEY';
    throw err;
  }

  const trimmed = keyInput.trim().replace(/^["']|["']$/g, '');
  let keyBuffer = null;

  // Check Base64 encoding (e.g. 44 chars with padding or 43 chars)
  if (/^[A-Za-z0-9+/=_-]+$/.test(trimmed)) {
    try {
      const buf = Buffer.from(trimmed, 'base64');
      if (buf.length === KEY_LENGTH_BYTES) {
        keyBuffer = buf;
      }
    } catch {}
  }

  // Fallback: Check 64-character Hex encoding
  if (!keyBuffer && /^[0-9a-fA-F]{64}$/.test(trimmed)) {
    try {
      const buf = Buffer.from(trimmed, 'hex');
      if (buf.length === KEY_LENGTH_BYTES) {
        keyBuffer = buf;
      }
    } catch {}
  }

  if (!keyBuffer || keyBuffer.length !== KEY_LENGTH_BYTES) {
    const err = new Error(
      `STORAGE_ENCRYPTION_KEY must be exactly ${KEY_LENGTH_BYTES} bytes (256 bits), encoded in Base64 (e.g., from "openssl rand -base64 32") or 64-character Hex.`
    );
    err.code = 'INVALID_KEY';
    throw err;
  }

  return keyBuffer;
}

/**
 * Resolve the active encryption key from process.env or test runner.
 * Fails closed if missing in production or explicitly set to empty string.
 *
 * @param {string|Buffer} [overrideKey]
 * @returns {Buffer}
 */
export function getStorageEncryptionKey(overrideKey) {
  if (overrideKey !== undefined) {
    if (!overrideKey) {
      const err = new Error('STORAGE_ENCRYPTION_KEY is required for credential storage (fail-closed).');
      err.code = 'MISSING_ENCRYPTION_KEY';
      throw err;
    }
    return parseEncryptionKey(overrideKey);
  }

  const envKey = process.env.STORAGE_ENCRYPTION_KEY;
  if (!envKey) {
    // If explicitly set to empty string, fail closed immediately
    if (process.env.STORAGE_ENCRYPTION_KEY === '') {
      const err = new Error('STORAGE_ENCRYPTION_KEY is required for credential storage (fail-closed).');
      err.code = 'MISSING_ENCRYPTION_KEY';
      throw err;
    }

    // Allow deterministic test key only during test execution when key is unset
    const isTestRun = process.env.NODE_ENV === 'test' || process.argv.some(arg => arg.includes('test'));
    if (isTestRun) {
      return TEST_FALLBACK_KEY;
    }

    const err = new Error(
      'STORAGE_ENCRYPTION_KEY is missing. Credential encryption key is required (fail-closed). Generate with: openssl rand -base64 32'
    );
    err.code = 'MISSING_ENCRYPTION_KEY';
    throw err;
  }

  return parseEncryptionKey(envKey);
}

/**
 * Encrypt arbitrary JSON serializable data into an authenticated AES-256-GCM envelope.
 *
 * @param {Object|string} data - Data to encrypt
 * @param {string|Buffer} [key] - Optional key override
 * @returns {Object} Envelope containing version, algorithm, iv, tag, ciphertext
 */
export function encryptData(data, key) {
  const keyBuffer = key !== undefined ? parseEncryptionKey(key) : getStorageEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const plaintext = typeof data === 'string' ? data : JSON.stringify(data);

  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, keyBuffer, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    version: CURRENT_ENCRYPTION_VERSION,
    algorithm: ENCRYPTION_ALGORITHM,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: encrypted.toString('base64')
  };
}

/**
 * Decrypt an AES-256-GCM envelope and return parsed JSON or UTF-8 string.
 *
 * @param {Object} envelope - The encrypted envelope
 * @param {string|Buffer} [key] - Optional key override
 * @param {boolean} [parseJson=true] - Whether to JSON.parse decrypted content
 * @returns {Object|string}
 */
export function decryptData(envelope, key, parseJson = true) {
  if (!envelope || typeof envelope !== 'object') {
    const err = new Error('Invalid encrypted envelope: expected an object.');
    err.code = 'INVALID_ENVELOPE';
    throw err;
  }

  if (envelope.version !== CURRENT_ENCRYPTION_VERSION) {
    const err = new Error(`Unsupported encryption envelope version: ${envelope.version}.`);
    err.code = 'UNSUPPORTED_VERSION';
    throw err;
  }

  if (envelope.algorithm !== ENCRYPTION_ALGORITHM) {
    const err = new Error(`Unsupported encryption algorithm: ${envelope.algorithm}.`);
    err.code = 'UNSUPPORTED_ALGORITHM';
    throw err;
  }

  if (!envelope.iv || !envelope.tag || !envelope.ciphertext) {
    const err = new Error('Invalid encrypted envelope: missing iv, tag, or ciphertext.');
    err.code = 'MALFORMED_ENVELOPE';
    throw err;
  }

  const keyBuffer = key !== undefined ? parseEncryptionKey(key) : getStorageEncryptionKey();
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');

  if (iv.length !== IV_LENGTH_BYTES) {
    const err = new Error(`Invalid IV length: expected ${IV_LENGTH_BYTES} bytes, got ${iv.length}.`);
    err.code = 'INVALID_IV';
    throw err;
  }

  if (tag.length !== AUTH_TAG_LENGTH_BYTES) {
    const err = new Error(`Invalid authentication tag length: expected ${AUTH_TAG_LENGTH_BYTES} bytes, got ${tag.length}.`);
    err.code = 'INVALID_TAG';
    throw err;
  }

  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, keyBuffer, iv);
  decipher.setAuthTag(tag);

  let decryptedText;
  try {
    decryptedText = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch (err) {
    const authErr = new Error('Decryption failed: authentication tag mismatch, wrong key, or corrupted ciphertext.');
    authErr.code = 'DECRYPTION_FAILED';
    throw authErr;
  }

  if (parseJson) {
    try {
      return JSON.parse(decryptedText);
    } catch {
      return decryptedText;
    }
  }

  return decryptedText;
}

/**
 * Check if a parsed JSON object matches the AES-256-GCM envelope schema.
 */
export function isEncryptedEnvelope(obj) {
  return Boolean(
    obj &&
    typeof obj === 'object' &&
    typeof obj.version === 'number' &&
    obj.algorithm === ENCRYPTION_ALGORITHM &&
    typeof obj.iv === 'string' &&
    typeof obj.tag === 'string' &&
    typeof obj.ciphertext === 'string'
  );
}

/**
 * Safely read and decrypt a JSON credential store, automatically migrating legacy plaintext if found.
 * Synchronous version preserved for backwards compatibility and test harnesses.
 *
 * @param {string} filePath - Absolute path to file
 * @param {*} defaultValue - Fallback value if file does not exist
 * @param {string|Buffer} [key] - Optional key override
 * @param {Function} [writeFn] - Atomic write function to persist migrated data
 * @returns {*} Decrypted data
 */
export function safeReadEncryptedJsonSync(filePath, defaultValue, key, writeFn) {
  if (!fs.existsSync(filePath)) {
    return defaultValue;
  }

  let rawContent;
  try {
    rawContent = fs.readFileSync(filePath, 'utf8');
  } catch (readErr) {
    auditLog({
      action: 'store.read_error',
      status: 'failure',
      details: { file: path.basename(filePath), error: readErr.message }
    });
    return defaultValue;
  }

  let parsed;
  try {
    parsed = JSON.parse(rawContent);
  } catch (parseErr) {
    auditLog({
      action: 'store.json_parse_error',
      status: 'failure',
      details: { file: path.basename(filePath), error: parseErr.message }
    });
    return defaultValue;
  }

  // Case 1: File is already encrypted with an envelope
  if (isEncryptedEnvelope(parsed)) {
    try {
      return decryptData(parsed, key, true);
    } catch (decryptErr) {
      auditLog({
        action: 'crypto.decryption_error',
        status: 'failure',
        details: { file: path.basename(filePath), error: decryptErr.message }
      });
      // Do NOT overwrite corrupted/wrong-key files with defaultValue; throw to fail closed!
      throw decryptErr;
    }
  }

  // Case 2: File is legacy plaintext JSON -> Execute backward-compatible atomic migration
  auditLog({
    action: 'crypto.legacy_migration_started',
    status: 'warning',
    details: { file: path.basename(filePath) }
  });

  try {
    const envelope = encryptData(parsed, key);
    if (typeof writeFn === 'function') {
      writeFn(filePath, envelope);
    } else {
      const dir = path.dirname(filePath);
      const tempPath = path.join(dir, `.tmp_${path.basename(filePath)}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`);
      fs.writeFileSync(tempPath, JSON.stringify(envelope, null, 2), { mode: 0o600 });
      try { fs.chmodSync(tempPath, 0o600); } catch {}
      fs.renameSync(tempPath, filePath);
    }

    auditLog({
      action: 'crypto.legacy_migration_success',
      status: 'success',
      details: { file: path.basename(filePath) }
    });

    return parsed;
  } catch (migrationErr) {
    auditLog({
      action: 'crypto.legacy_migration_failed',
      status: 'failure',
      details: { file: path.basename(filePath), error: migrationErr.message }
    });
    throw new Error(`Failed to migrate legacy credential file "${path.basename(filePath)}" to encrypted format: ${migrationErr.message}`);
  }
}

/**
 * Safely encrypt data and write it atomically to disk with restricted permissions.
 * Synchronous version preserved for backwards compatibility and test harnesses.
 *
 * @param {string} filePath - Absolute path to file
 * @param {*} data - Plaintext data to encrypt and write
 * @param {string|Buffer} [key] - Optional key override
 * @param {Function} [writeFn] - Atomic file write function
 */
export function safeWriteEncryptedJsonSync(filePath, data, key, writeFn) {
  const envelope = encryptData(data, key);
  if (typeof writeFn === 'function') {
    writeFn(filePath, envelope);
  } else {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch {}
    }
    const tempPath = path.join(dir, `.tmp_${path.basename(filePath)}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`);
    fs.writeFileSync(tempPath, JSON.stringify(envelope, null, 2), { mode: 0o600 });
    try { fs.chmodSync(tempPath, 0o600); } catch {}
    fs.renameSync(tempPath, filePath);
  }
}

// -------------------------------------------------------------
// Unified Persistent Storage Layer (Vercel Private Blob / Filesystem)
// -------------------------------------------------------------

/**
 * Detect the active storage backend.
 * Production and Vercel environments automatically use 'vercel-blob'.
 * Local dev without Blob credentials defaults to 'filesystem'.
 *
 * @returns {'vercel-blob' | 'filesystem'}
 */
export function getStorageBackend() {
  if (process.env.STORAGE_BACKEND) {
    const override = process.env.STORAGE_BACKEND.trim().toLowerCase();
    if (override === 'vercel-blob' || override === 'blob') return 'vercel-blob';
    if (override === 'filesystem' || override === 'fs') return 'filesystem';
  }

  // If running on Vercel platform or if Blob credentials are configured
  if (
    process.env.VERCEL ||
    process.env.BLOB_READ_WRITE_TOKEN ||
    process.env.BLOB_STORE_ID ||
    process.env.VERCEL_OIDC_TOKEN
  ) {
    return 'vercel-blob';
  }

  return 'filesystem';
}

/**
 * Check if the active storage backend is fully configured.
 *
 * @returns {boolean}
 */
export function isStorageConfigured() {
  const backend = getStorageBackend();
  if (backend === 'vercel-blob') {
    return Boolean(
      process.env.BLOB_READ_WRITE_TOKEN ||
      process.env.BLOB_STORE_ID ||
      (process.env.VERCEL_OIDC_TOKEN && process.env.BLOB_STORE_ID)
    );
  }
  return true;
}

/**
 * Diagnostic status for Vercel Blob store connections.
 */
export function getBlobDiagnostics() {
  return {
    blob_store_id_configured: Boolean(process.env.BLOB_STORE_ID),
    blob_read_write_token_configured: Boolean(process.env.BLOB_READ_WRITE_TOKEN),
    vercel_oidc_available: Boolean(process.env.VERCEL_OIDC_TOKEN),
    data_dir: process.env.DATA_DIR || '/google-drive-mcp-v2'
  };
}

/**
 * Resolve the logical DATA_DIR prefix.
 */
export function getStorageLogicalPrefix() {
  return (process.env.DATA_DIR || '/google-drive-mcp-v2').trim();
}

/**
 * Generate Vercel Blob pathname matching the configured DATA_DIR logical prefix.
 * Enforces removal of leading slashes and prevents double slashes (e.g. "google-drive-mcp-v2/users.enc.json").
 *
 * @param {string} filename
 * @returns {string}
 */
export function getBlobPathname(filename) {
  const prefix = getStorageLogicalPrefix().replace(/^\/+/, '').replace(/\/+$/, '');
  const cleanName = filename.replace(/^\/+/, '');
  return prefix ? `${prefix}/${cleanName}` : cleanName;
}

/**
 * Legacy filename mapping to ensure zero-loss compatibility with local test stores.
 */
function getLegacyFilename(filename) {
  if (filename === 'users.enc.json') return 'google-users.json';
  if (filename === 'google-links.enc.json') return 'google-link-tokens.json';
  if (filename === 'oauth-state.enc.json') return 'oauth-states.json';
  if (filename === 'mcp-tokens.enc.json') return 'mcp-auth.json';
  return null;
}

/**
 * Resolve local filesystem path for development or test environments.
 *
 * @param {string} filename
 * @returns {string}
 */
export function getFilesystemPath(filename) {
  const rawDataDir = process.env.DATA_DIR;
  let baseDir;
  if (rawDataDir) {
    baseDir = path.resolve(rawDataDir);
  } else {
    baseDir = path.resolve(process.cwd(), 'data');
  }

  try {
    if (!fs.existsSync(baseDir)) {
      fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });
    }
  } catch {}

  const cleanName = path.basename(filename);
  return path.join(baseDir, cleanName);
}

// Safe pass-through mutex preserved for API compatibility
export const storageMutex = {
  async runExclusive(fn) {
    return await fn();
  }
};

/**
 * Asynchronously read and decrypt an encrypted JSON store.
 * For Vercel Blob, enforces `access: 'private'` and `useCache: false` to guarantee fresh data directly from origin storage.
 *
 * @param {string} filename - Storage filename (e.g. users.enc.json)
 * @param {*} [defaultValue={}] - Fallback data if file does not exist
 * @param {string|Buffer} [key] - Optional key override
 * @returns {Promise<{ data: *, etag: string|null }>}
 */
export async function readEncryptedStorage(filename, defaultValue = {}, key) {
  const backend = getStorageBackend();

  if (backend === 'vercel-blob') {
    const pathname = getBlobPathname(filename);
    try {
      // Requirement 10, 11, 12: access: 'private', useCache: false to bypass CDN cache
      const res = await get(pathname, {
        access: 'private',
        useCache: false
      });

      if (!res || res.statusCode === 304 || !res.stream) {
        return { data: defaultValue, etag: null };
      }

      const raw = await text(res.stream);
      if (!raw || !raw.trim()) {
        return { data: defaultValue, etag: res.blob?.etag || null };
      }

      const envelope = JSON.parse(raw);
      if (isEncryptedEnvelope(envelope)) {
        const decrypted = decryptData(envelope, key, true);
        return { data: decrypted, etag: res.blob?.etag || null };
      }

      // Legacy fallback if envelope is absent
      return { data: envelope, etag: res.blob?.etag || null };
    } catch (err) {
      if (err.status === 404 || err.name === 'BlobNotFoundError' || err.message?.includes('404')) {
        return { data: defaultValue, etag: null };
      }
      auditLog({
        action: 'storage.blob_read_error',
        status: 'failure',
        details: { filename, error: err.message }
      });
      throw err;
    }
  }

  // Filesystem fallback for local dev & testing
  const filePath = getFilesystemPath(filename);
  if (!fs.existsSync(filePath)) {
    // Check possible legacy name in DATA_DIR
    const legacyName = getLegacyFilename(filename);
    if (legacyName) {
      const legacyPath = getFilesystemPath(legacyName);
      if (fs.existsSync(legacyPath)) {
        const data = safeReadEncryptedJsonSync(legacyPath, defaultValue, key);
        return { data, etag: 'legacy' };
      }
    }
    return { data: defaultValue, etag: null };
  }

  try {
    const stat = fs.statSync(filePath);
    const data = safeReadEncryptedJsonSync(filePath, defaultValue, key);
    return { data, etag: String(stat.mtimeMs) };
  } catch (err) {
    auditLog({
      action: 'storage.fs_read_error',
      status: 'failure',
      details: { filename, error: err.message }
    });
    throw err;
  }
}

/**
 * Asynchronously encrypt and write data to persistent storage.
 * In Vercel Blob mode, stores AES-256-GCM envelope with access: 'private'.
 * Supports `ifMatch` for optimistic concurrency control.
 *
 * @param {string} filename - Storage filename (e.g. users.enc.json)
 * @param {*} data - Plaintext JSON data to encrypt
 * @param {string|Buffer} [key] - Optional key override
 * @param {string} [ifMatchEtag] - ETag from previous read for concurrency check
 * @returns {Promise<{ etag: string }>}
 */
export async function writeEncryptedStorage(filename, data, key, ifMatchEtag = null) {
  const envelope = encryptData(data, key);
  const serialized = JSON.stringify(envelope, null, 2);
  const backend = getStorageBackend();

  if (backend === 'vercel-blob') {
    const pathname = getBlobPathname(filename);
    const putOptions = {
      access: 'private',
      addRandomSuffix: false,
      allowOverwrite: true,
      contentType: 'application/json'
    };
    if (ifMatchEtag && typeof ifMatchEtag === 'string') {
      putOptions.ifMatch = ifMatchEtag;
    }

    const result = await put(pathname, serialized, putOptions);
    return { etag: result.etag };
  }

  // Filesystem mode: atomic write with 0600 mode
  const filePath = getFilesystemPath(filename);
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const tempPath = path.join(dir, `.tmp_${path.basename(filePath)}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`);
  fs.writeFileSync(tempPath, serialized, { mode: 0o600 });
  try { fs.chmodSync(tempPath, 0o600); } catch {}
  fs.renameSync(tempPath, filePath);

  const legacyName = getLegacyFilename(filename);
  if (legacyName) {
    try {
      const legacyPath = getFilesystemPath(legacyName);
      const tempLegacy = path.join(dir, `.tmp_${path.basename(legacyPath)}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`);
      fs.writeFileSync(tempLegacy, serialized, { mode: 0o600 });
      try { fs.chmodSync(tempLegacy, 0o600); } catch {}
      fs.renameSync(tempLegacy, legacyPath);
    } catch {}
  }

  const stat = fs.statSync(filePath);
  return { etag: String(stat.mtimeMs) };
}

/**
 * Safe Read-Modify-Write handler with optimistic concurrency retry loop (Requirement 13).
 * Ensures concurrent requests across separate serverless function invocations
 * do not overwrite each other or corrupt encrypted JSON records.
 *
 * @param {string} filename
 * @param {Function} modifierFn - (data: any) => Promise<any> | any
 * @param {*} [defaultValue={}]
 * @param {string|Buffer} [key]
 * @returns {Promise<any>} The modified data
 */
export async function updateEncryptedStorage(filename, modifierFn, defaultValue = {}, key) {
  return storageMutex.runExclusive(async () => {
    const maxRetries = 5;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const { data, etag } = await readEncryptedStorage(filename, defaultValue, key);
        const modified = await modifierFn(data);
        const writeResult = await writeEncryptedStorage(filename, modified, key, etag);
        return { data: modified, etag: writeResult.etag };
      } catch (err) {
        const isPreconditionFailed = 
          err.name === 'BlobPreconditionFailedError' ||
          err.status === 412 ||
          err.message?.includes('Precondition') ||
          err.message?.includes('precondition');

        if (isPreconditionFailed) {
          if (attempt === maxRetries) {
            const conflictErr = new Error(`Concurrent modification conflict for ${filename} after ${maxRetries} attempts.`);
            conflictErr.code = 'STORAGE_CONFLICT';
            throw conflictErr;
          }
          // Exponential backoff with random jitter (50-250ms)
          const delay = Math.floor(Math.random() * 40) + attempt * 50;
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
        throw err;
      }
    }
  });
}

/**
 * Asynchronously delete an encrypted storage object.
 *
 * @param {string} filename
 * @returns {Promise<boolean>}
 */
export async function deleteEncryptedStorage(filename) {
  const backend = getStorageBackend();
  if (backend === 'vercel-blob') {
    const pathname = getBlobPathname(filename);
    try {
      await del(pathname);
      return true;
    } catch (err) {
      if (err.status === 404 || err.name === 'BlobNotFoundError') return false;
      throw err;
    }
  }

  const filePath = getFilesystemPath(filename);
  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}
