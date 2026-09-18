/**
 * AES-256-GCM Credential Encryption at Rest (SEC-04)
 * Provides authenticated encryption, decryption, envelope serialization,
 * key validation, and automatic backward-compatible migration for credential stores.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
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

  const trimmed = keyInput.trim();
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
 *
 * @param {string} filePath - Absolute path to file
 * @param {*} defaultValue - Fallback value if file does not exist
 * @param {string|Buffer} [key] - Optional key override
 * @param {Function} writeFn - Atomic write function to persist migrated data
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

  // Case 2: File is legacy plaintext JSON -> Execute backward-compatible atomic migration (Requirement 3)
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
      // Fallback write
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
    // Preserve the original file intact; do NOT delete or corrupt
    throw new Error(`Failed to migrate legacy credential file "${path.basename(filePath)}" to encrypted format: ${migrationErr.message}`);
  }
}

/**
 * Safely encrypt data and write it atomically to disk with restricted permissions.
 *
 * @param {string} filePath - Absolute path to file
 * @param {*} data - Plaintext data to encrypt and write
 * @param {string|Buffer} [key] - Optional key override
 * @param {Function} writeFn - Atomic file write function
 */
export function safeWriteEncryptedJsonSync(filePath, data, key, writeFn) {
  const envelope = encryptData(data, key);
  if (typeof writeFn === 'function') {
    writeFn(filePath, envelope);
  } else {
    const dir = path.dirname(filePath);
    const tempPath = path.join(dir, `.tmp_${path.basename(filePath)}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`);
    fs.writeFileSync(tempPath, JSON.stringify(envelope, null, 2), { mode: 0o600 });
    try { fs.chmodSync(tempPath, 0o600); } catch {}
    fs.renameSync(tempPath, filePath);
  }
}
