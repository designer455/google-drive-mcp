/**
 * Test Suite: Vercel Serverless Resilience & Permanent GOOGLE_REFRESH_TOKEN (Solution 1)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';

const testDataDir = path.resolve(process.cwd(), 'data-test-vercel-resilience');
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = testDataDir;

const {
  getUserGoogleRecord,
  getMcpToken,
  saveMcpTokens,
  generateSignedMcpToken,
  verifySignedMcpToken
} = await import('../src/user-store.js');
const { getGoogleAuthClient } = await import('../src/google.js');

test.after(() => {
  delete process.env.GOOGLE_REFRESH_TOKEN;
  delete process.env.GOOGLE_ACCOUNT_EMAIL;
  delete process.env.SINGLE_USER_MODE;
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

test('1. GOOGLE_REFRESH_TOKEN requires SINGLE_USER_MODE=true and never leaks in multi-user mode', async () => {
  const dummyUserSub = 'usr_cold_start_test_1';
  
  // Before setting GOOGLE_REFRESH_TOKEN: returns null
  delete process.env.GOOGLE_REFRESH_TOKEN;
  delete process.env.SINGLE_USER_MODE;
  const before = await getUserGoogleRecord(dummyUserSub);
  assert.equal(before, null);

  // Set GOOGLE_REFRESH_TOKEN without SINGLE_USER_MODE (multi-user mode default)
  process.env.GOOGLE_REFRESH_TOKEN = '1//mock-permanent-refresh-token-12345';
  process.env.GOOGLE_ACCOUNT_EMAIL = 'myaccount@gmail.com';

  // Multi-user safety check: MUST NOT return owner credentials to other users!
  const multiUserResult = await getUserGoogleRecord(dummyUserSub);
  assert.equal(multiUserResult, null, 'Must return null in multi-user mode so other users are not granted owner credentials');

  // Opt-in: When SINGLE_USER_MODE=true is explicitly set
  process.env.SINGLE_USER_MODE = 'true';
  const singleUserResult = await getUserGoogleRecord(dummyUserSub);
  assert.ok(singleUserResult);
  assert.equal(singleUserResult.google.refresh_token, '1//mock-permanent-refresh-token-12345');
  assert.equal(singleUserResult.account.email, 'myaccount@gmail.com');
  assert.equal(singleUserResult.source, 'env');

  // Verify getGoogleAuthClient succeeds in single user mode
  const authClient = await getGoogleAuthClient(dummyUserSub);
  assert.ok(authClient);
  assert.equal(authClient.credentials.refresh_token, '1//mock-permanent-refresh-token-12345');

  // Clean up single user mode for following tests
  delete process.env.SINGLE_USER_MODE;
  delete process.env.GOOGLE_REFRESH_TOKEN;
});

test('2. Stateless signed MCP token validates even if MCP_AUTH_FILE is completely wiped', async () => {
  const userSub = 'usr_resilient_user_99';
  const clientId = 'chatgpt-client';
  const scope = 'drive';

  // Mint signed access token and refresh token
  const token = generateSignedMcpToken('mcp_at_', { sub: userSub, cid: clientId, scp: scope }, 3600000);
  assert.ok(token.startsWith('mcp_at_'));
  assert.ok(token.includes('.'));

  // Verify token validation without saving to disk
  const verified = verifySignedMcpToken(token, 'mcp_at_');
  assert.ok(verified);
  assert.equal(verified.userSub, userSub);
  assert.equal(verified.clientId, clientId);
  assert.equal(verified.scope, scope);
  assert.equal(verified.type, 'access');

  // Remove any auth file if exists
  const authFile = path.join(testDataDir, 'mcp-auth.json');
  if (fs.existsSync(authFile)) {
    fs.rmSync(authFile, { force: true });
  }

  // getMcpToken must still resolve userSub from the signed token statelessly
  const tokenRecord = await getMcpToken(token);
  assert.ok(tokenRecord);
  assert.equal(tokenRecord.userSub, userSub);
  assert.equal(tokenRecord.type, 'access');
});

test('3. Expired or tampered signed MCP token is strictly rejected', async () => {
  // Tampered signature
  const validToken = generateSignedMcpToken('mcp_at_', { sub: 'u1' }, 3600000);
  const tamperedToken = validToken.slice(0, -4) + 'abcd';
  const tamperedRecord = await getMcpToken(tamperedToken);
  assert.equal(tamperedRecord, null);

  // Expired token
  const expiredToken = generateSignedMcpToken('mcp_at_', { sub: 'u2' }, -1000);
  const expiredRecord = await getMcpToken(expiredToken);
  assert.equal(expiredRecord, null);
});

test('4. Stateless signed Google Link Tokens and OAuth States work across container cold starts', async () => {
  const {
    createSignedGoogleLinkToken,
    consumeGoogleLinkToken,
    createSignedGoogleOAuthState,
    consumeGoogleOAuthState
  } = await import('../src/user-store.js');

  const userSub = 'usr_stateless_container_user_42';

  // 1. Create stateless signed link token
  const linkToken = createSignedGoogleLinkToken(userSub, 60000);
  assert.ok(linkToken.startsWith('glink_'));
  assert.ok(linkToken.includes('.'));

  // Consume link token statelessly
  const consumedUser = await consumeGoogleLinkToken(linkToken);
  assert.equal(consumedUser, userSub);

  // Replay of consumed link token must be rejected
  await assert.rejects(
    async () => { await consumeGoogleLinkToken(linkToken); },
    (err) => {
      assert.equal(err.code, 'GOOGLE_LINK_REPLAY');
      return true;
    }
  );

  // 2. Create stateless signed OAuth state
  const oauthState = createSignedGoogleOAuthState(userSub, 60000);
  assert.ok(oauthState.startsWith('gstate_'));
  assert.ok(oauthState.includes('.'));

  // Consume OAuth state statelessly
  const stateUser = await consumeGoogleOAuthState(oauthState);
  assert.equal(stateUser, userSub);

  // Replay of consumed OAuth state must be rejected
  await assert.rejects(
    async () => { await consumeGoogleOAuthState(oauthState); },
    (err) => {
      assert.equal(err.code, 'OAUTH_STATE_REPLAY');
      return true;
    }
  );
});
