/**
 * Test Suite: Multi-User Isolation & Google OAuth Credential Segregation
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';

const testDataDir = path.resolve(process.cwd(), 'data-test-multiuser');
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = testDataDir;
process.env.ALLOWED_HOST = 'mcp.example.com';
process.env.GOOGLE_CLIENT_ID = 'mock-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'mock-google-client-secret';
process.env.GOOGLE_REDIRECT_URI = 'https://mcp.example.com/oauth2callback';

const { app } = await import('../src/server.js');
const {
  getUserGoogleRecord,
  setUserGoogleTokens,
  deleteUserGoogleRecord,
  saveMcpTokens
} = await import('../src/user-store.js');
const { getGoogleAuthClient } = await import('../src/google.js');

test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

function makeRequest({ method = 'GET', path: reqPath, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const payload = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;

      const reqHeaders = {
        Host: 'mcp.example.com',
        ...headers
      };

      if (payload && !reqHeaders['Content-Type']) {
        reqHeaders['Content-Type'] = 'application/json';
        reqHeaders['Content-Length'] = Buffer.byteLength(payload);
      }

      const req = http.request(
        { hostname: '127.0.0.1', port, path: reqPath, method, headers: reqHeaders },
        (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            server.close();
            let json = null;
            try { json = JSON.parse(data); } catch {}
            resolve({ status: res.statusCode, headers: res.headers, body: data, json });
          });
        }
      );

      req.on('error', (err) => {
        server.close();
        reject(err);
      });

      if (payload) req.write(payload);
      req.end();
    });
  });
}

test('1. User A and User B unique subjects and token creation', async () => {
  const userSubA = 'usr_user_a_1111111111111111';
  const userSubB = 'usr_user_b_2222222222222222';
  const tokenA = 'mcp_at_user_a';
  const tokenB = 'mcp_at_user_b';

  assert.notEqual(userSubA, userSubB);

  await saveMcpTokens({ accessToken: tokenA, userSub: userSubA, clientId: 'clientA', scope: 'drive' });
  await saveMcpTokens({ accessToken: tokenB, userSub: userSubB, clientId: 'clientB', scope: 'drive' });
});

test('2. Storing User A credentials isolates them from User B', async () => {
  const userSubA = 'usr_user_a_1111111111111111';
  const userSubB = 'usr_user_b_2222222222222222';

  const credsA = {
    access_token: 'google_token_for_user_a',
    refresh_token: 'google_refresh_for_user_a',
    expiry_date: Date.now() + 3600000,
    token_type: 'Bearer',
    scope: 'https://www.googleapis.com/auth/drive'
  };
  const accountA = { email: 'alice@example.com', displayName: 'Alice A' };

  await setUserGoogleTokens(userSubA, credsA, accountA);

  // User A can load A's credentials
  const recordA = await getUserGoogleRecord(userSubA);
  assert.ok(recordA);
  assert.equal(recordA.google.access_token, 'google_token_for_user_a');
  assert.equal(recordA.account.email, 'alice@example.com');

  // User B attempting to load B credentials gets null
  const recordB = await getUserGoogleRecord(userSubB);
  assert.equal(recordB, null);
});

test('3. Storing User B credentials establishes distinct isolated store', async () => {
  const userSubA = 'usr_user_a_1111111111111111';
  const userSubB = 'usr_user_b_2222222222222222';

  const credsB = {
    access_token: 'google_token_for_user_b',
    refresh_token: 'google_refresh_for_user_b',
    expiry_date: Date.now() + 3600000,
    token_type: 'Bearer',
    scope: 'https://www.googleapis.com/auth/drive'
  };
  const accountB = { email: 'bob@example.com', displayName: 'Bob B' };

  await setUserGoogleTokens(userSubB, credsB, accountB);

  const recordA = await getUserGoogleRecord(userSubA);
  const recordB = await getUserGoogleRecord(userSubB);

  assert.equal(recordA.google.access_token, 'google_token_for_user_a');
  assert.equal(recordB.google.access_token, 'google_token_for_user_b');
  assert.equal(recordA.account.email, 'alice@example.com');
  assert.equal(recordB.account.email, 'bob@example.com');
});

test('4. getGoogleAuthClient returns isolated client per user', async () => {
  const userSubA = 'usr_user_a_1111111111111111';
  const userSubB = 'usr_user_b_2222222222222222';
  const userSubC = 'usr_user_c_unconnected';

  const clientA = await getGoogleAuthClient(userSubA);
  const clientB = await getGoogleAuthClient(userSubB);

  assert.equal(clientA.credentials.access_token, 'google_token_for_user_a');
  assert.equal(clientB.credentials.access_token, 'google_token_for_user_b');

  // Unconnected User C must fail with GOOGLE_NOT_CONNECTED and NEVER fallback to A or B
  await assert.rejects(
    async () => { await getGoogleAuthClient(userSubC); },
    (err) => {
      assert.equal(err.code, 'GOOGLE_NOT_CONNECTED');
      assert.ok(err.message.includes('Google Drive is not connected'));
      return true;
    }
  );
});

test('5. GET /auth/google/status returns accurate connection status per user', async () => {
  const tokenA = 'mcp_at_user_a';
  const tokenB = 'mcp_at_user_b';

  // Unconnected User C
  const userSubC = 'usr_user_c_unconnected';
  const tokenC = 'mcp_at_user_c';
  await saveMcpTokens({ accessToken: tokenC, userSub: userSubC, clientId: 'clientC', scope: 'drive' });

  // Status for User A
  const resA = await makeRequest({
    path: '/auth/google/status',
    headers: { Authorization: `Bearer ${tokenA}` }
  });
  assert.equal(resA.status, 200);
  assert.equal(resA.json.connected, true);
  assert.equal(resA.json.googleAccount.email, 'alice@example.com');
  // Must NOT expose tokens
  assert.equal(resA.json.access_token, undefined);
  assert.equal(resA.json.refresh_token, undefined);

  // Status for User B
  const resB = await makeRequest({
    path: '/auth/google/status',
    headers: { Authorization: `Bearer ${tokenB}` }
  });
  assert.equal(resB.status, 200);
  assert.equal(resB.json.connected, true);
  assert.equal(resB.json.googleAccount.email, 'bob@example.com');

  // Status for User C (Not connected)
  const resC = await makeRequest({
    path: '/auth/google/status',
    headers: { Authorization: `Bearer ${tokenC}` }
  });
  assert.equal(resC.status, 200);
  assert.equal(resC.json.connected, false);
  assert.equal(resC.json.googleAccount, undefined);
});

test('6. POST /auth/google/disconnect disconnects User A only; User B remains unaffected', async () => {
  const userSubA = 'usr_user_a_1111111111111111';
  const userSubB = 'usr_user_b_2222222222222222';
  const tokenA = 'mcp_at_user_a';
  const tokenB = 'mcp_at_user_b';

  // Disconnect User A
  const discResA = await makeRequest({
    method: 'POST',
    path: '/auth/google/disconnect',
    headers: { Authorization: `Bearer ${tokenA}` }
  });
  assert.equal(discResA.status, 200);
  assert.equal(discResA.json.success, true);

  // User A record is gone
  const recordA = await getUserGoogleRecord(userSubA);
  assert.equal(recordA, null);

  // User B record is UNTOUCHED
  const recordB = await getUserGoogleRecord(userSubB);
  assert.ok(recordB);
  assert.equal(recordB.google.access_token, 'google_token_for_user_b');

  // User A now gets GOOGLE_NOT_CONNECTED
  await assert.rejects(
    async () => { await getGoogleAuthClient(userSubA); },
    (err) => err.code === 'GOOGLE_NOT_CONNECTED'
  );

  // User B client still works
  const clientB = await getGoogleAuthClient(userSubB);
  assert.equal(clientB.credentials.access_token, 'google_token_for_user_b');
});

test('7. Token auto-refresh persists new credentials for THAT user only', async () => {
  const userSubB = 'usr_user_b_2222222222222222';
  const clientB = await getGoogleAuthClient(userSubB);

  // Simulate Google token refresh event
  clientB.emit('tokens', {
    access_token: 'google_token_for_user_b_REFRESHED',
    expiry_date: Date.now() + 7200000
  });

  // Small delay for async event handling
  await new Promise(r => setTimeout(r, 50));

  const updatedB = await getUserGoogleRecord(userSubB);
  assert.equal(updatedB.google.access_token, 'google_token_for_user_b_REFRESHED');
  // Refresh token should be preserved
  assert.equal(updatedB.google.refresh_token, 'google_refresh_for_user_b');
});
