import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';

const testDataDir = path.resolve(process.cwd(), 'data-test-blob');

test.before(() => {
  process.env.NODE_ENV = 'test';
  process.env.DATA_DIR = testDataDir;
  if (!fs.existsSync(testDataDir)) {
    fs.mkdirSync(testDataDir, { recursive: true, mode: 0o700 });
  }
});

test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
  delete process.env.STORAGE_BACKEND;
  delete process.env.BLOB_READ_WRITE_TOKEN;
  delete process.env.BLOB_STORE_ID;
});

test('1. Storage backend detection & configuration diagnostics', async () => {
  const {
    getStorageBackend,
    isStorageConfigured,
    getBlobDiagnostics,
    getBlobPathname
  } = await import('../src/crypto-storage.js');

  // Local dev / test without VERCEL defaults to filesystem
  assert.equal(getStorageBackend(), 'filesystem');
  assert.equal(isStorageConfigured(), true);

  // When STORAGE_BACKEND=vercel-blob is set
  process.env.STORAGE_BACKEND = 'vercel-blob';
  assert.equal(getStorageBackend(), 'vercel-blob');
  assert.equal(isStorageConfigured(), false, 'Unconfigured when tokens are missing');

  process.env.BLOB_READ_WRITE_TOKEN = 'vercel_blob_rw_test123_456';
  assert.equal(isStorageConfigured(), true, 'Configured when BLOB_READ_WRITE_TOKEN is set');

  const diag = getBlobDiagnostics();
  assert.equal(diag.blob_read_write_token_configured, true);
  assert.equal(diag.data_dir, testDataDir);

  // Pathname construction removes leading and double slashes
  process.env.DATA_DIR = '/google-drive-mcp-v2';
  const blobPath = getBlobPathname('/users.enc.json');
  assert.equal(blobPath, 'google-drive-mcp-v2/users.enc.json');
  assert.ok(!blobPath.startsWith('/'));
  assert.ok(!blobPath.includes('//'));

  // Cleanup
  delete process.env.STORAGE_BACKEND;
  delete process.env.BLOB_READ_WRITE_TOKEN;
  process.env.DATA_DIR = testDataDir;
});

test('2. Encrypted storage persistence and per-user isolation', async () => {
  const {
    getUserGoogleRecord,
    setUserGoogleTokens,
    deleteUserGoogleRecord
  } = await import('../src/user-store.js');

  const userA = 'usr_user_a_blob_test';
  const userB = 'usr_user_b_blob_test';

  const tokensA = {
    access_token: 'ya29.user_a_token',
    refresh_token: '1//refresh_token_a',
    expiry_date: Date.now() + 3600000
  };

  const tokensB = {
    access_token: 'ya29.user_b_token',
    refresh_token: '1//refresh_token_b',
    expiry_date: Date.now() + 3600000
  };

  // Save User A
  await setUserGoogleTokens(userA, tokensA, { email: 'userA@example.com', displayName: 'User A' });

  // Save User B
  await setUserGoogleTokens(userB, tokensB, { email: 'userB@example.com', displayName: 'User B' });

  // Verify per-user isolation
  const recordA = await getUserGoogleRecord(userA);
  const recordB = await getUserGoogleRecord(userB);

  assert.ok(recordA);
  assert.ok(recordB);
  assert.equal(recordA.google.refresh_token, '1//refresh_token_a');
  assert.equal(recordA.account.email, 'userA@example.com');
  assert.equal(recordB.google.refresh_token, '1//refresh_token_b');
  assert.equal(recordB.account.email, 'userB@example.com');

  // Verify stored file on disk is encrypted AES-256-GCM (no plaintext tokens)
  const usersFile = path.join(testDataDir, 'users.enc.json');
  assert.ok(fs.existsSync(usersFile));
  const rawContent = fs.readFileSync(usersFile, 'utf8');
  assert.ok(!rawContent.includes('ya29.user_a_token'));
  assert.ok(!rawContent.includes('1//refresh_token_a'));
  assert.ok(!rawContent.includes('userA@example.com'));

  const parsed = JSON.parse(rawContent);
  assert.equal(parsed.algorithm, 'aes-256-gcm');
  assert.ok(parsed.iv);
  assert.ok(parsed.tag);
  assert.ok(parsed.ciphertext);

  // Delete User A only; User B remains intact
  const deleted = await deleteUserGoogleRecord(userA);
  assert.equal(deleted, true);

  const afterDeleteA = await getUserGoogleRecord(userA);
  assert.equal(afterDeleteA, null);

  const afterDeleteB = await getUserGoogleRecord(userB);
  assert.ok(afterDeleteB);
  assert.equal(afterDeleteB.google.refresh_token, '1//refresh_token_b');
});

test('3. Single-use and TTL semantics for OAuth state and link tokens', async () => {
  const {
    saveGoogleOAuthState,
    consumeGoogleOAuthState,
    saveGoogleLinkToken,
    consumeGoogleLinkToken
  } = await import('../src/user-store.js');

  const testUser = 'usr_single_use_tester';

  // State test
  const state = `state_${crypto.randomBytes(16).toString('hex')}`;
  await saveGoogleOAuthState(state, testUser, 60000);

  // Consume state successfully once
  const consumedUser = await consumeGoogleOAuthState(state);
  assert.equal(consumedUser, testUser);

  // Replay of consumed state must fail
  await assert.rejects(
    async () => { await consumeGoogleOAuthState(state); },
    (err) => {
      assert.ok(err.code === 'OAUTH_STATE_INVALID' || err.code === 'OAUTH_STATE_REPLAY');
      return true;
    }
  );

  // Link token test
  const linkToken = `glink_${crypto.randomBytes(16).toString('hex')}`;
  await saveGoogleLinkToken(linkToken, testUser, 60000);

  // Consume link token successfully once
  const consumedLinkUser = await consumeGoogleLinkToken(linkToken);
  assert.equal(consumedLinkUser, testUser);

  // Replay must fail
  await assert.rejects(
    async () => { await consumeGoogleLinkToken(linkToken); },
    (err) => {
      assert.ok(err.code === 'GOOGLE_LINK_INVALID' || err.code === 'GOOGLE_LINK_REPLAY');
      return true;
    }
  );
});

test('4. MCP token store persistence and lifecycle', async () => {
  const {
    saveMcpAuthCode,
    consumeMcpAuthCode,
    saveMcpTokens,
    getMcpToken,
    revokeMcpToken
  } = await import('../src/user-store.js');

  const userSub = 'usr_mcp_lifecycle_user';
  const authCode = `code_${crypto.randomBytes(12).toString('hex')}`;

  // Save auth code
  await saveMcpAuthCode({
    code: authCode,
    clientId: 'chatgpt-client',
    redirectUri: 'https://chatgpt.com/callback',
    codeChallenge: 'challenge123',
    codeChallengeMethod: 'S256',
    userSub,
    scope: 'drive',
    expiresInMs: 60000
  });

  // Consume auth code
  const codeRecord = await consumeMcpAuthCode(authCode);
  assert.ok(codeRecord);
  assert.equal(codeRecord.userSub, userSub);
  assert.equal(codeRecord.clientId, 'chatgpt-client');

  // Replay of auth code must fail
  await assert.rejects(
    async () => { await consumeMcpAuthCode(authCode); },
    (err) => {
      assert.equal(err.code, 'INVALID_GRANT');
      return true;
    }
  );

  // Issue tokens
  const accessToken = `mcp_at_${crypto.randomBytes(16).toString('hex')}`;
  const refreshToken = `mcp_rt_${crypto.randomBytes(16).toString('hex')}`;

  await saveMcpTokens({
    accessToken,
    refreshToken,
    userSub,
    clientId: 'chatgpt-client',
    scope: 'drive',
    accessExpiresInMs: 3600000,
    refreshExpiresInMs: 86400000
  });

  // Validate access token
  const atRecord = await getMcpToken(accessToken);
  assert.ok(atRecord);
  assert.equal(atRecord.userSub, userSub);
  assert.equal(atRecord.type, 'access');

  // Revoke token
  await revokeMcpToken(accessToken);
  const revoked = await getMcpToken(accessToken);
  assert.equal(revoked, null);
});

test('5. Health endpoint diagnostics & persistence verification probe', async () => {
  const { app } = await import('../src/server.js');
  const http = await import('node:http');

  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Basic /health
    const res1 = await fetch(`${baseUrl}/health`);
    assert.equal(res1.status, 200);
    const json1 = await res1.json();
    assert.equal(json1.status, 'ok');
    assert.ok(json1.storage_backend);
    assert.equal(typeof json1.storage_configured, 'boolean');
    assert.ok(json1.env_diagnostics.blob_diagnostics);

    // 2. Storage cycle probe (?verify_storage=1)
    const res2 = await fetch(`${baseUrl}/health?verify_storage=1`);
    assert.equal(res2.status, 200);
    const json2 = await res2.json();
    assert.ok(json2.env_diagnostics.storage_verification);
    assert.equal(json2.env_diagnostics.storage_verification.write, 'PASS');
    assert.equal(json2.env_diagnostics.storage_verification.read, 'PASS');
    assert.equal(json2.env_diagnostics.storage_verification.decrypt, 'PASS');
    assert.equal(json2.env_diagnostics.storage_verification.delete, 'PASS');

    // 3. Cross-invocation persistence simulation (write -> read -> cleanup)
    const probeId = `probe_${Date.now()}`;
    const probeValue = `secret_value_${Date.now()}`;

    // Invocation 1: write
    const resWrite = await fetch(`${baseUrl}/health?verify_persistence=write&probe_id=${probeId}&probe_value=${probeValue}`);
    const jsonWrite = await resWrite.json();
    assert.equal(jsonWrite.env_diagnostics.persistence_verification?.status, 'SUCCESS');

    // Invocation 2: read
    const resRead = await fetch(`${baseUrl}/health?verify_persistence=read&probe_id=${probeId}`);
    const jsonRead = await resRead.json();
    assert.equal(jsonRead.env_diagnostics.persistence_verification?.status, 'SUCCESS');
    assert.equal(jsonRead.env_diagnostics.persistence_verification?.persisted, true);
    assert.equal(jsonRead.env_diagnostics.persistence_verification?.data?.value, probeValue);

    // Invocation 3: cleanup
    const resClean = await fetch(`${baseUrl}/health?verify_persistence=cleanup&probe_id=${probeId}`);
    const jsonClean = await resClean.json();
    assert.equal(jsonClean.env_diagnostics.persistence_verification?.status, 'SUCCESS');

    // Confirm deletion
    const resAfterClean = await fetch(`${baseUrl}/health?verify_persistence=read&probe_id=${probeId}`);
    const jsonAfterClean = await resAfterClean.json();
    assert.equal(jsonAfterClean.env_diagnostics.persistence_verification?.persisted, false);
  } finally {
    server.close();
  }
});
