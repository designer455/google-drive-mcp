/**
 * Test Suite: One-Time Google Link Token & Connection Flow UX/Security
 * Verifies single-use tokens, expiration, userSub binding, isolation, error responses, and audit redaction.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';

const testDataDir = path.resolve(process.cwd(), 'data-test-google-link');
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = testDataDir;
process.env.ALLOWED_HOST = 'mcp.example.com';
process.env.MCP_PUBLIC_ORIGIN = 'https://mcp.example.com';
process.env.GOOGLE_CLIENT_ID = 'mock-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'mock-google-client-secret';
process.env.GOOGLE_REDIRECT_URI = 'https://mcp.example.com/oauth2callback';

const { app } = await import('../src/server.js');
const {
  saveGoogleLinkToken,
  consumeGoogleLinkToken,
  consumeGoogleOAuthState,
  getUserGoogleRecord,
  setUserGoogleTokens,
  deleteUserGoogleRecord
} = await import('../src/user-store.js');
const {
  createGoogleLinkToken,
  handleGoogleLink
} = await import('../src/google-oauth.js');
const { executeMcpTool } = await import('../src/mcp.js');
const { sanitize } = await import('../src/audit.js');
const { setGoogleClientOverrides } = await import('../src/google.js');

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

      if (payload) {
        req.write(payload);
      }
      req.end();
    });
  });
}

test('1. Authenticated user can create Google link token', async () => {
  const userSub = 'usr_alice_12345';
  const linkUrl = await createGoogleLinkToken(userSub);

  assert.ok(typeof linkUrl === 'string');
  assert.ok(linkUrl.startsWith('https://mcp.example.com/auth/google/link?code=glink_'));
});

test('2. Link token maps to correct userSub', async () => {
  const userSub = 'usr_alice_12345';
  const linkUrl = await createGoogleLinkToken(userSub);
  const parsed = new URL(linkUrl);
  const code = parsed.searchParams.get('code');
  assert.ok(code);

  const resolvedSub = await consumeGoogleLinkToken(code);
  assert.equal(resolvedSub, userSub);
});

test('3. Link token is random and distinct', async () => {
  const userSub = 'usr_alice_12345';
  const url1 = await createGoogleLinkToken(userSub);
  const url2 = await createGoogleLinkToken(userSub);

  const code1 = new URL(url1).searchParams.get('code');
  const code2 = new URL(url2).searchParams.get('code');

  assert.notEqual(code1, code2);
  assert.ok(code1.startsWith('glink_'));
  assert.ok(code2.startsWith('glink_'));
  // Ensure token is at least 64+ random characters
  assert.ok(code1.length >= 70);
});

test('4. Link token expires and cannot be consumed', async () => {
  const userSub = 'usr_bob_67890';
  const token = 'glink_expired_test_token_1234567890123456789012345678901234567890';
  // Save with negative expiry (already expired)
  await saveGoogleLinkToken(token, userSub, -1000);

  await assert.rejects(
    async () => {
      await consumeGoogleLinkToken(token);
    },
    (err) => {
      assert.equal(err.code, 'GOOGLE_LINK_EXPIRED');
      return true;
    }
  );
});

test('5. Link token cannot be replayed (single-use)', async () => {
  const userSub = 'usr_charlie_555';
  const linkUrl = await createGoogleLinkToken(userSub);
  const code = new URL(linkUrl).searchParams.get('code');

  const firstConsume = await consumeGoogleLinkToken(code);
  assert.equal(firstConsume, userSub);

  // Replay attempt must fail
  await assert.rejects(
    async () => {
      await consumeGoogleLinkToken(code);
    },
    (err) => {
      assert.ok(err.code === 'GOOGLE_LINK_INVALID' || err.code === 'GOOGLE_LINK_REPLAY');
      return true;
    }
  );
});

test('6. Link token for A cannot be used as B', async () => {
  const userA = 'usr_user_a_isolation';
  const userB = 'usr_user_b_isolation';

  const urlA = await createGoogleLinkToken(userA);
  const codeA = new URL(urlA).searchParams.get('code');

  // Consuming token A always binds to user A, never user B
  const resolved = await consumeGoogleLinkToken(codeA);
  assert.equal(resolved, userA);
  assert.notEqual(resolved, userB);
});

test('7. Link token tampering fails', async () => {
  const userSub = 'usr_tamper_test';
  const linkUrl = await createGoogleLinkToken(userSub);
  const code = new URL(linkUrl).searchParams.get('code');

  // Tamper with one character
  const tampered = code.slice(0, -1) + (code.slice(-1) === 'a' ? 'b' : 'a');

  await assert.rejects(
    async () => {
      await consumeGoogleLinkToken(tampered);
    },
    (err) => {
      assert.equal(err.code, 'GOOGLE_LINK_INVALID');
      return true;
    }
  );
});

test('8. Anonymous requests cannot create link tokens', async () => {
  await assert.rejects(
    async () => {
      await createGoogleLinkToken(null);
    },
    /required/
  );

  await assert.rejects(
    async () => {
      await createGoogleLinkToken('anonymous');
    },
    /required/
  );
});

test('9. GOOGLE_NOT_CONNECTED produces a one-time connection link', async () => {
  const unconnectedUser = 'usr_unconnected_tester';
  const res = await executeMcpTool('drive_search', { query: "name contains 'Project'" }, unconnectedUser);

  assert.equal(res.isError, true);
  const errorText = res.content[0].text;

  assert.ok(errorText.includes('Google Drive is not connected for your account'));
  assert.ok(errorText.includes('https://mcp.example.com/auth/google/link?code=glink_'));
  assert.ok(errorText.includes('This link expires in 10 minutes and can be used once.'));
  assert.ok(errorText.includes('connects your personal Google account'));
});

test('10. Generated link does NOT contain an MCP bearer token or userSub', async () => {
  const userSub = 'usr_bearer_leak_test';
  const linkUrl = await createGoogleLinkToken(userSub);

  assert.ok(!linkUrl.includes('Bearer'));
  assert.ok(!linkUrl.includes(userSub));
  assert.ok(!linkUrl.includes('access_token'));
  assert.ok(!linkUrl.includes('mcp_token'));
  assert.ok(linkUrl.includes('/auth/google/link?code=glink_'));
});

test('11. GET /auth/google/link redirects (302) to Google OAuth', async () => {
  const userSub = 'usr_browser_redirect_user';
  const linkUrl = await createGoogleLinkToken(userSub);
  const parsed = new URL(linkUrl);

  const res = await makeRequest({
    method: 'GET',
    path: parsed.pathname + parsed.search
  });

  assert.equal(res.status, 302);
  const location = res.headers.location;
  assert.ok(location);
  assert.ok(location.includes('accounts.google.com') || location.includes('google.com'));
  assert.ok(location.includes('state='));
});

test('12. Google OAuth state generated by /auth/google/link is bound to the correct userSub', async () => {
  const userSub = 'usr_state_binding_test';
  const linkUrl = await createGoogleLinkToken(userSub);
  const parsed = new URL(linkUrl);

  const res = await makeRequest({
    method: 'GET',
    path: parsed.pathname + parsed.search
  });

  assert.equal(res.status, 302);
  const redirectUrl = new URL(res.headers.location);
  const state = redirectUrl.searchParams.get('state');
  assert.ok(state);

  // Validate state maps to userSub
  const boundUser = await consumeGoogleOAuthState(state);
  assert.equal(boundUser, userSub);
});

test('13. Replaying /auth/google/link with same code fails with 400', async () => {
  const userSub = 'usr_link_replay_test';
  const linkUrl = await createGoogleLinkToken(userSub);
  const parsed = new URL(linkUrl);

  // First request succeeds and redirects
  const res1 = await makeRequest({
    method: 'GET',
    path: parsed.pathname + parsed.search
  });
  assert.equal(res1.status, 302);

  // Second request fails
  const res2 = await makeRequest({
    method: 'GET',
    path: parsed.pathname + parsed.search
  });
  assert.equal(res2.status, 400);
  assert.ok(res2.body.includes('invalid or expired'));
});

test('14. Direct GET /auth/google without Bearer returns 401 without suggesting ?token=', async () => {
  const res = await makeRequest({
    method: 'GET',
    path: '/auth/google'
  });

  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'unauthorized');
  assert.ok(!res.json.message.includes('?token='));
  assert.ok(res.json.message.includes('one-time connection link'));
});

test('15. Direct GET /auth/google?token=... rejects query token and returns 401', async () => {
  const res = await makeRequest({
    method: 'GET',
    path: '/auth/google?token=some-mcp-bearer-token'
  });

  assert.equal(res.status, 401);
  assert.equal(res.json.error, 'unauthorized');
});

test('16. Multi-user Google connection & isolation (User A vs User B)', async () => {
  const userA = 'usr_multi_alice';
  const userB = 'usr_multi_bob';

  // Link tokens for both
  const urlA = await createGoogleLinkToken(userA);
  const urlB = await createGoogleLinkToken(userB);

  assert.notEqual(urlA, urlB);

  // Set credentials for both independently
  await setUserGoogleTokens(userA, {
    access_token: 'google_token_alice',
    refresh_token: 'google_refresh_alice',
    expiry_date: Date.now() + 3600000
  }, { email: 'alice@example.com', displayName: 'Alice' });

  await setUserGoogleTokens(userB, {
    access_token: 'google_token_bob',
    refresh_token: 'google_refresh_bob',
    expiry_date: Date.now() + 3600000
  }, { email: 'bob@example.com', displayName: 'Bob' });

  const recordA = await getUserGoogleRecord(userA);
  const recordB = await getUserGoogleRecord(userB);

  assert.equal(recordA.account.email, 'alice@example.com');
  assert.equal(recordB.account.email, 'bob@example.com');

  // Disconnect A does not affect B
  await deleteUserGoogleRecord(userA);

  const afterA = await getUserGoogleRecord(userA);
  const afterB = await getUserGoogleRecord(userB);

  assert.equal(afterA, null);
  assert.equal(afterB.account.email, 'bob@example.com');
});

test('17. Audit log sanitizer redacts sensitive fields and tokens', () => {
  const rawDetails = {
    code: 'some_auth_code',
    state: 'secret_oauth_state_123',
    link_token: 'glink_abcdef123456',
    tokenHash: 'abcdeff00112233',
    access_token: 'ya29.sensitive_google_token',
    userMessage: 'glink_999888777666',
    safeField: 'ok_to_log'
  };

  const sanitized = sanitize(rawDetails);

  assert.equal(sanitized.code, '[REDACTED]');
  assert.equal(sanitized.state, '[REDACTED]');
  assert.equal(sanitized.link_token, '[REDACTED]');
  assert.equal(sanitized.tokenHash, '[REDACTED]');
  assert.equal(sanitized.access_token, '[REDACTED]');
  assert.equal(sanitized.userMessage, '[REDACTED]');
  assert.equal(sanitized.safeField, 'ok_to_log');
});

test('18. End-to-End Flow: drive_search -> link token -> connect -> drive_search succeeds', async () => {
  const userSub = 'usr_e2e_journey_user';

  // 1. Initial drive_search before Google connection returns GOOGLE_NOT_CONNECTED with one-time link
  const step1Res = await executeMcpTool('drive_search', { query: "name contains 'Doc'" }, userSub);
  assert.equal(step1Res.isError, true);
  assert.ok(step1Res.content[0].text.includes('/auth/google/link?code=glink_'));

  // 2. Extract link URL from tool response
  const match = step1Res.content[0].text.match(/(https:\/\/[^\s]+auth\/google\/link\?code=[^\s]+)/);
  assert.ok(match, 'One-time link URL must be present in response');
  const linkUrl = new URL(match[1]);

  // 3. User opens the link in browser
  const linkRes = await makeRequest({
    method: 'GET',
    path: linkUrl.pathname + linkUrl.search
  });
  assert.equal(linkRes.status, 302);
  const googleAuthUrl = new URL(linkRes.headers.location);
  const state = googleAuthUrl.searchParams.get('state');
  assert.ok(state);

  // 4. Token is consumed, cannot be opened again
  const replayRes = await makeRequest({
    method: 'GET',
    path: linkUrl.pathname + linkUrl.search
  });
  assert.equal(replayRes.status, 400);

  // 5. State is consumed at callback and credentials stored for userSub
  const boundUser = await consumeGoogleOAuthState(state);
  assert.equal(boundUser, userSub);

  await setUserGoogleTokens(userSub, {
    access_token: 'mock_e2e_token',
    refresh_token: 'mock_e2e_refresh',
    expiry_date: Date.now() + 3600000
  }, { email: 'e2e@example.com', displayName: 'E2E Tester' });

  // Mock Google Drive client for the connected user
  setGoogleClientOverrides({
    getDriveClient: async (sub) => {
      assert.equal(sub, userSub);
      return {
        files: {
          list: async () => ({
            data: {
              files: [
                { id: 'f_e2e_1', name: 'My Document.txt', mimeType: 'text/plain' }
              ]
            }
          })
        }
      };
    }
  });

  // 6. Invoke drive_search again: now it succeeds!
  const step2Res = await executeMcpTool('drive_search', { query: "name contains 'Doc'" }, userSub);
  assert.equal(step2Res.isError, undefined);
  const data = JSON.parse(step2Res.content[0].text);
  assert.equal(data.files.length, 1);
  assert.equal(data.files[0].name, 'My Document.txt');
});
