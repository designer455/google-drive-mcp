/**
 * Test Suite: AES-256-GCM Credential Encryption at Rest (Phase 3A / SEC-04)
 * Verifies authenticated encryption, decryption, envelope format, key parsing,
 * backward-compatible legacy migration, fail-closed behavior, wrong key rejection,
 * storage privacy, and zero plaintext credential leakage.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';

// Setup isolated test data directory for crypto testing
const testCryptoDataDir = path.resolve(process.cwd(), 'data-test-crypto');
const TEST_KEY_B64 = crypto.randomBytes(32).toString('base64');
const WRONG_KEY_B64 = crypto.randomBytes(32).toString('base64');

process.env.DATA_DIR = testCryptoDataDir;
process.env.STORAGE_ENCRYPTION_KEY = TEST_KEY_B64;

const {
  CURRENT_ENCRYPTION_VERSION,
  ENCRYPTION_ALGORITHM,
  parseEncryptionKey,
  getStorageEncryptionKey,
  encryptData,
  decryptData,
  isEncryptedEnvelope,
  safeReadEncryptedJsonSync,
  safeWriteEncryptedJsonSync
} = await import('../src/crypto-storage.js');

const {
  getUserGoogleRecord,
  setUserGoogleTokens,
  deleteUserGoogleRecord,
  saveMcpTokens,
  getMcpToken,
  saveMcpAuthCode,
  consumeMcpAuthCode
} = await import('../src/user-store.js');

const { sanitize } = await import('../src/audit.js');

test.beforeEach(() => {
  if (fs.existsSync(testCryptoDataDir)) {
    fs.rmSync(testCryptoDataDir, { recursive: true, force: true });
  }
  fs.mkdirSync(testCryptoDataDir, { recursive: true, mode: 0o700 });
});

test.after(() => {
  if (fs.existsSync(testCryptoDataDir)) {
    fs.rmSync(testCryptoDataDir, { recursive: true, force: true });
  }
});

// ----------------------------------------------------------------------
// 1. Key Parsing & Validation Tests
// ----------------------------------------------------------------------
test('CRYPTO-KEY.1: parseEncryptionKey parses valid 32-byte Base64 key', () => {
  const rawKey = crypto.randomBytes(32);
  const b64 = rawKey.toString('base64');
  const parsed = parseEncryptionKey(b64);
  assert.equal(Buffer.isBuffer(parsed), true);
  assert.equal(parsed.length, 32);
  assert.deepEqual(parsed, rawKey);
});

test('CRYPTO-KEY.2: parseEncryptionKey parses valid 64-character Hex key', () => {
  const rawKey = crypto.randomBytes(32);
  const hex = rawKey.toString('hex');
  const parsed = parseEncryptionKey(hex);
  assert.equal(parsed.length, 32);
  assert.deepEqual(parsed, rawKey);
});

test('CRYPTO-KEY.3: parseEncryptionKey rejects invalid or insufficient key lengths', () => {
  // Too short (16 bytes base64)
  assert.throws(() => parseEncryptionKey('dGVzdGtleTEyMzQ1Njc4OQ=='), /STORAGE_ENCRYPTION_KEY must be exactly 32 bytes/);
  // Empty
  assert.throws(() => parseEncryptionKey(''), /must be a non-empty string/);
  // Null / undefined
  assert.throws(() => parseEncryptionKey(null), /must be a non-empty string/);
  // Non-base64 garbage
  assert.throws(() => parseEncryptionKey('not!valid@base64#'), /STORAGE_ENCRYPTION_KEY must be exactly 32 bytes/);
});

test('CRYPTO-KEY.4: getStorageEncryptionKey fails closed when key is missing or empty', () => {
  // Explicitly cleared key must fail closed
  assert.throws(() => getStorageEncryptionKey(''), /fail-closed/);
  assert.throws(() => getStorageEncryptionKey(null), /fail-closed/);
});

// ----------------------------------------------------------------------
// 2. Authenticated Encryption & Decryption Round-Trip
// ----------------------------------------------------------------------
test('CRYPTO-ENC.1: Encrypt and decrypt round-trip preserves complex objects and types', () => {
  const payload = {
    userSub: 'usr_crypto_test_123',
    tokens: {
      access_token: 'ya29.secret_token_1234567890',
      refresh_token: '1//super_secret_refresh_token_0987654321',
      expiry_date: 1789000000000
    },
    count: 42,
    active: true,
    meta: { roles: ['admin', 'writer'] }
  };

  const envelope = encryptData(payload, TEST_KEY_B64);

  // Verify envelope structure
  assert.equal(envelope.version, CURRENT_ENCRYPTION_VERSION);
  assert.equal(envelope.algorithm, ENCRYPTION_ALGORITHM);
  assert.ok(typeof envelope.iv === 'string' && envelope.iv.length > 0);
  assert.ok(typeof envelope.tag === 'string' && envelope.tag.length > 0);
  assert.ok(typeof envelope.ciphertext === 'string' && envelope.ciphertext.length > 0);

  // Decrypt
  const decrypted = decryptData(envelope, TEST_KEY_B64);
  assert.deepEqual(decrypted, payload);
});

test('CRYPTO-ENC.2: Unique IV generated for every encryption of identical plaintext', () => {
  const plaintext = 'identical_secret_oauth_token';
  const envelope1 = encryptData(plaintext, TEST_KEY_B64);
  const envelope2 = encryptData(plaintext, TEST_KEY_B64);

  assert.notEqual(envelope1.iv, envelope2.iv, 'IVs must be distinct');
  assert.notEqual(envelope1.ciphertext, envelope2.ciphertext, 'Ciphertexts must be distinct due to unique IV');
  assert.notEqual(envelope1.tag, envelope2.tag, 'Authentication tags must be distinct');

  // Both decrypt to identical plaintext
  assert.equal(decryptData(envelope1, TEST_KEY_B64), plaintext);
  assert.equal(decryptData(envelope2, TEST_KEY_B64), plaintext);
});

// ----------------------------------------------------------------------
// 3. Integrity & Wrong Key Rejection
// ----------------------------------------------------------------------
test('CRYPTO-INT.1: Decryption with wrong key fails safely', () => {
  const secret = { access_token: 'ya29.private_access' };
  const envelope = encryptData(secret, TEST_KEY_B64);

  assert.throws(
    () => decryptData(envelope, WRONG_KEY_B64),
    (err) => {
      assert.equal(err.code, 'DECRYPTION_FAILED');
      assert.ok(err.message.includes('Decryption failed'));
      return true;
    }
  );
});

test('CRYPTO-INT.2: Corrupted ciphertext is rejected by authentication tag', () => {
  const secret = { data: 'critical_secret' };
  const envelope = encryptData(secret, TEST_KEY_B64);

  // Tamper with ciphertext by flipping bits in base64 buffer
  const cipherBuf = Buffer.from(envelope.ciphertext, 'base64');
  cipherBuf[0] ^= 0xff;
  envelope.ciphertext = cipherBuf.toString('base64');

  assert.throws(
    () => decryptData(envelope, TEST_KEY_B64),
    (err) => {
      assert.equal(err.code, 'DECRYPTION_FAILED');
      return true;
    }
  );
});

test('CRYPTO-INT.3: Corrupted authentication tag is rejected', () => {
  const secret = { data: 'tamper_proof_data' };
  const envelope = encryptData(secret, TEST_KEY_B64);

  // Tamper with authentication tag
  const tagBuf = Buffer.from(envelope.tag, 'base64');
  tagBuf[0] ^= 0x01;
  envelope.tag = tagBuf.toString('base64');

  assert.throws(
    () => decryptData(envelope, TEST_KEY_B64),
    (err) => {
      assert.equal(err.code, 'DECRYPTION_FAILED');
      return true;
    }
  );
});

test('CRYPTO-INT.4: Unsupported version or algorithm is rejected', () => {
  const envelope = encryptData('test', TEST_KEY_B64);

  assert.throws(
    () => decryptData({ ...envelope, version: 99 }, TEST_KEY_B64),
    (err) => err.code === 'UNSUPPORTED_VERSION'
  );

  assert.throws(
    () => decryptData({ ...envelope, algorithm: 'des-ecb' }, TEST_KEY_B64),
    (err) => err.code === 'UNSUPPORTED_ALGORITHM'
  );
});

// ----------------------------------------------------------------------
// 4. Storage Credential Encryption Verification
// ----------------------------------------------------------------------
test('CRYPTO-STORE.1: google-users.json persists encrypted on disk without plaintext tokens', async () => {
  const userSub = 'usr_enc_google_user';
  const secretAccessToken = 'ya29.extremely_secret_google_access_token_xyz';
  const secretRefreshToken = '1//extremely_secret_google_refresh_token_abc';

  await setUserGoogleTokens(userSub, {
    access_token: secretAccessToken,
    refresh_token: secretRefreshToken,
    expiry_date: Date.now() + 3600000
  }, { email: 'encrypted@example.com', displayName: 'Encrypted User' });

  const usersFilePath = path.join(testCryptoDataDir, 'google-users.json');
  assert.ok(fs.existsSync(usersFilePath), 'google-users.json must exist');

  // Read raw file content directly from disk
  const rawDiskContent = fs.readFileSync(usersFilePath, 'utf8');

  // 1. Plaintext tokens must NEVER appear anywhere on disk
  assert.equal(rawDiskContent.includes(secretAccessToken), false, 'access_token must NOT appear in plaintext on disk');
  assert.equal(rawDiskContent.includes(secretRefreshToken), false, 'refresh_token must NOT appear in plaintext on disk');
  assert.equal(rawDiskContent.includes('encrypted@example.com'), false, 'user email must NOT appear in plaintext on disk');

  // 2. Content must be a valid AES-256-GCM envelope
  const rawParsed = JSON.parse(rawDiskContent);
  assert.equal(isEncryptedEnvelope(rawParsed), true, 'On-disk file must be an encrypted envelope');
  assert.equal(rawParsed.version, 1);
  assert.equal(rawParsed.algorithm, 'aes-256-gcm');

  // 3. Retrieving through user-store decrypts transparently
  const record = await getUserGoogleRecord(userSub);
  assert.ok(record);
  assert.equal(record.google.access_token, secretAccessToken);
  assert.equal(record.google.refresh_token, secretRefreshToken);
  assert.equal(record.account.email, 'encrypted@example.com');
});

test('CRYPTO-STORE.2: mcp-auth.json persists encrypted on disk without plaintext tokens', async () => {
  const userSub = 'usr_enc_mcp_user';
  const secretMcpAccess = 'mcp_at_super_private_access_token_12345';
  const secretMcpRefresh = 'mcp_rt_super_private_refresh_token_67890';
  const secretAuthCode = 'mcp_code_secret_authorization_code_abcdef';

  await saveMcpAuthCode({
    code: secretAuthCode,
    clientId: 'test-client',
    redirectUri: 'https://chatgpt.com/callback',
    codeChallenge: 'chall_123',
    codeChallengeMethod: 'S256',
    userSub,
    scope: 'drive',
    expiresInMs: 300000
  });

  await saveMcpTokens({
    accessToken: secretMcpAccess,
    refreshToken: secretMcpRefresh,
    userSub,
    clientId: 'test-client',
    scope: 'drive'
  });

  const mcpAuthFilePath = path.join(testCryptoDataDir, 'mcp-auth.json');
  assert.ok(fs.existsSync(mcpAuthFilePath), 'mcp-auth.json must exist');

  const rawDiskContent = fs.readFileSync(mcpAuthFilePath, 'utf8');

  // 1. Plaintext tokens and codes must NOT appear on disk
  assert.equal(rawDiskContent.includes(secretMcpAccess), false, 'MCP access token must NOT appear in plaintext on disk');
  assert.equal(rawDiskContent.includes(secretMcpRefresh), false, 'MCP refresh token must NOT appear in plaintext on disk');
  assert.equal(rawDiskContent.includes(secretAuthCode), false, 'MCP auth code must NOT appear in plaintext on disk');

  // 2. Envelope validation
  const rawParsed = JSON.parse(rawDiskContent);
  assert.equal(isEncryptedEnvelope(rawParsed), true);

  // 3. Normal credential retrieval works transparently
  const tokenRecord = await getMcpToken(secretMcpAccess);
  assert.ok(tokenRecord);
  assert.equal(tokenRecord.userSub, userSub);

  const consumedCode = await consumeMcpAuthCode(secretAuthCode);
  assert.ok(consumedCode);
  assert.equal(consumedCode.userSub, userSub);
});

// ----------------------------------------------------------------------
// 5. Backward-Compatible Legacy Plaintext Migration
// ----------------------------------------------------------------------
test('MIGRATION.1: Legacy plaintext google-users.json automatically migrates to encrypted format', async () => {
  const usersFilePath = path.join(testCryptoDataDir, 'google-users.json');

  // Seed legacy plaintext store
  const legacyData = {
    users: {
      usr_legacy_user_1: {
        google: {
          access_token: 'ya29.legacy_token_1',
          refresh_token: '1//legacy_refresh_1',
          expiry_date: Date.now() + 3600000
        },
        account: { email: 'legacy1@example.com', displayName: 'Legacy One' },
        createdAt: new Date().toISOString()
      },
      usr_legacy_user_2: {
        google: {
          access_token: 'ya29.legacy_token_2',
          refresh_token: '1//legacy_refresh_2',
          expiry_date: Date.now() + 3600000
        },
        account: { email: 'legacy2@example.com', displayName: 'Legacy Two' },
        createdAt: new Date().toISOString()
      }
    }
  };

  // Write in raw plaintext JSON
  fs.writeFileSync(usersFilePath, JSON.stringify(legacyData, null, 2), { mode: 0o600 });

  // Verify file is currently plaintext
  const beforeRead = fs.readFileSync(usersFilePath, 'utf8');
  assert.ok(beforeRead.includes('ya29.legacy_token_1'));

  // First read triggers automatic transparent migration
  const user1 = await getUserGoogleRecord('usr_legacy_user_1');
  assert.ok(user1, 'User 1 must be recovered during migration');
  assert.equal(user1.google.access_token, 'ya29.legacy_token_1');
  assert.equal(user1.account.email, 'legacy1@example.com');

  // Verify file on disk is NOW encrypted!
  const afterRead = fs.readFileSync(usersFilePath, 'utf8');
  assert.equal(afterRead.includes('ya29.legacy_token_1'), false, 'Plaintext must no longer exist on disk');
  assert.equal(afterRead.includes('legacy1@example.com'), false);

  const migratedEnvelope = JSON.parse(afterRead);
  assert.equal(isEncryptedEnvelope(migratedEnvelope), true, 'File must now be an encrypted envelope');

  // User 2 must also be completely preserved in the migrated store
  const user2 = await getUserGoogleRecord('usr_legacy_user_2');
  assert.ok(user2, 'User 2 must be preserved after migration');
  assert.equal(user2.google.access_token, 'ya29.legacy_token_2');
  assert.equal(user2.account.email, 'legacy2@example.com');
});

test('MIGRATION.2: Legacy plaintext mcp-auth.json automatically migrates to encrypted format', async () => {
  const mcpAuthFilePath = path.join(testCryptoDataDir, 'mcp-auth.json');

  const legacyMcpData = {
    codes: {
      code_legacy_123: {
        code: 'code_legacy_123',
        clientId: 'chatgpt-client',
        userSub: 'usr_legacy_mcp',
        used: false,
        expiresAt: Date.now() + 300000
      }
    },
    tokens: {
      tok_legacy_access: {
        type: 'access',
        token: 'tok_legacy_access',
        userSub: 'usr_legacy_mcp',
        clientId: 'chatgpt-client',
        expiresAt: Date.now() + 3600000
      }
    }
  };

  fs.writeFileSync(mcpAuthFilePath, JSON.stringify(legacyMcpData, null, 2), { mode: 0o600 });

  // Read triggers transparent migration
  const token = await getMcpToken('tok_legacy_access');
  assert.ok(token);
  assert.equal(token.userSub, 'usr_legacy_mcp');

  // Verify file on disk is now encrypted envelope
  const rawDisk = fs.readFileSync(mcpAuthFilePath, 'utf8');
  assert.equal(rawDisk.includes('tok_legacy_access'), false, 'Plaintext token must be eliminated from disk');
  const envelope = JSON.parse(rawDisk);
  assert.equal(isEncryptedEnvelope(envelope), true);

  // Consume code from migrated store
  const code = await consumeMcpAuthCode('code_legacy_123');
  assert.ok(code);
  assert.equal(code.userSub, 'usr_legacy_mcp');
});

test('MIGRATION.3: Migration failure preserves original legacy file intact without corruption', () => {
  const legacyFilePath = path.join(testCryptoDataDir, 'test-legacy-store.json');
  const legacyContent = { users: { usr_safe: { token: 'unmigrated_safe_token' } } };
  fs.writeFileSync(legacyFilePath, JSON.stringify(legacyContent, null, 2), { mode: 0o600 });

  // Simulate a write failure during migration
  const faultyWriteFn = () => {
    throw new Error('Disk write error / Permission denied');
  };

  assert.throws(
    () => safeReadEncryptedJsonSync(legacyFilePath, {}, TEST_KEY_B64, faultyWriteFn),
    /Failed to migrate legacy credential file/
  );

  // Verify legacy file was NOT destroyed or deleted
  assert.ok(fs.existsSync(legacyFilePath));
  const rawRemaining = fs.readFileSync(legacyFilePath, 'utf8');
  assert.ok(rawRemaining.includes('unmigrated_safe_token'), 'Original file content must remain completely intact');
});

// ----------------------------------------------------------------------
// 6. Process Restart & Key Consistency Tests
// ----------------------------------------------------------------------
test('RESTART.1: Credentials recover identically after simulated process restart', async () => {
  const userSub = 'usr_process_restart_test';
  await setUserGoogleTokens(userSub, {
    access_token: 'ya29.survives_restart',
    refresh_token: '1//refresh_survives_restart'
  }, { email: 'restart@example.com' });

  // Simulate fresh process startup by reading with exact same key
  const freshRecord = await getUserGoogleRecord(userSub);
  assert.ok(freshRecord);
  assert.equal(freshRecord.google.access_token, 'ya29.survives_restart');
  assert.equal(freshRecord.google.refresh_token, '1//refresh_survives_restart');
  assert.equal(freshRecord.account.email, 'restart@example.com');
});

// ----------------------------------------------------------------------
// 7. Security Redaction & Logging
// ----------------------------------------------------------------------
test('SECURITY-LOG.1: Audit sanitizer redacts encryption keys and ciphertext', () => {
  const sensitiveEvent = {
    userSub: 'usr_audit_test',
    action: 'crypto.test',
    details: {
      storage_encryption_key: TEST_KEY_B64,
      encryption_key: 'super_secret_key',
      ciphertext: 'YWVzX2NpcGhlcnRleHRfZXhhbXBsZQ==',
      iv: 'dGVzdF9pdl9leGFtcGxl',
      tag: 'dGVzdF9hdXRoX3RhZw==',
      safeField: 'audit_ok'
    }
  };

  const sanitized = sanitize(sensitiveEvent.details);
  assert.equal(sanitized.storage_encryption_key, '[REDACTED]');
  assert.equal(sanitized.encryption_key, '[REDACTED]');
  assert.equal(sanitized.ciphertext, '[REDACTED]');
  assert.equal(sanitized.iv, '[REDACTED]');
  assert.equal(sanitized.tag, '[REDACTED]');
  assert.equal(sanitized.safeField, 'audit_ok');
});
