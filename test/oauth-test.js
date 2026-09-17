/**
 * Test Suite: ChatGPT MCP OAuth (RFC 6749, RFC 7636, RFC 8414, RFC 9470)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';

// Configure test environment before loading app
const testDataDir = path.resolve(process.cwd(), 'data-test-oauth');
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = testDataDir;
process.env.ALLOWED_HOST = 'mcp-v2.digitonsdevelopment.com';
process.env.MCP_PUBLIC_ORIGIN = 'https://mcp-v2.digitonsdevelopment.com';
process.env.MCP_PUBLIC_URL = 'https://mcp-v2.digitonsdevelopment.com/mcp';
process.env.CHATGPT_OAUTH_CLIENT_ID = 'test-chatgpt-client';
process.env.CHATGPT_OAUTH_CLIENT_SECRET = 'test-chatgpt-secret';

const { app } = await import('../src/server.js');
const { computeS256Challenge, verifyCodeChallenge, generateUserSub } = await import('../src/oauth.js');
const { getMcpToken, saveMcpTokens, saveMcpAuthCode } = await import('../src/user-store.js');

// Clean up test data dir
test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

// Helper to make requests to the express app in memory using http
import http from 'node:http';

function makeRequest({ method = 'GET', path: reqPath, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const payload = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;

      const reqHeaders = {
        Host: 'mcp-v2.digitonsdevelopment.com',
        ...headers
      };

      if (payload && !reqHeaders['Content-Type']) {
        reqHeaders['Content-Type'] = 'application/json';
        reqHeaders['Content-Length'] = Buffer.byteLength(payload);
      }

      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: reqPath,
          method,
          headers: reqHeaders
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            server.close();
            let json = null;
            try { json = JSON.parse(data); } catch {}
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: data,
              json
            });
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

test('1. OAuth Discovery: GET /.well-known/oauth-authorization-server', async () => {
  const res = await makeRequest({ path: '/.well-known/oauth-authorization-server' });
  assert.equal(res.status, 200);
  assert.ok(res.json);
  assert.equal(res.json.issuer, 'https://mcp-v2.digitonsdevelopment.com');
  assert.equal(res.json.authorization_endpoint, 'https://mcp-v2.digitonsdevelopment.com/authorize');
  assert.equal(res.json.token_endpoint, 'https://mcp-v2.digitonsdevelopment.com/token');
  assert.deepEqual(res.json.code_challenge_methods_supported, ['S256']);
  assert.ok(res.json.grant_types_supported.includes('authorization_code'));
  assert.ok(res.json.grant_types_supported.includes('refresh_token'));
});

test('2. Protected Resource Metadata: GET /.well-known/oauth-protected-resource', async () => {
  const res = await makeRequest({ path: '/.well-known/oauth-protected-resource' });
  assert.equal(res.status, 200);
  assert.ok(res.json);
  assert.equal(res.json.resource, 'https://mcp-v2.digitonsdevelopment.com/mcp');
  assert.deepEqual(res.json.authorization_servers, ['https://mcp-v2.digitonsdevelopment.com']);
  assert.deepEqual(res.json.bearer_methods_supported, ['header']);
});

test('3. Authorize endpoint: GET /authorize renders consent page', async () => {
  const res = await makeRequest({
    path: '/authorize?response_type=code&client_id=test-chatgpt-client&redirect_uri=https%3A%2F%2Fchatgpt.com%2Faip%2Fcallback&scope=drive&state=state123'
  });
  assert.equal(res.status, 200);
  assert.ok(res.body.includes('Authorize ChatGPT Connection'));
  assert.ok(res.body.includes('drive'));
});

test('4. Authorize endpoint: rejects invalid client_id', async () => {
  const res = await makeRequest({
    path: '/authorize?response_type=code&client_id=wrong-client&redirect_uri=https%3A%2F%2Fchatgpt.com%2Faip%2Fcallback'
  });
  assert.equal(res.status, 400);
  assert.ok(res.body.includes('Invalid client_id'));
});

test('5. PKCE S256 Challenge computation and verification', () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const challenge = computeS256Challenge(verifier);
  assert.ok(challenge);
  assert.equal(verifyCodeChallenge(verifier, challenge, 'S256'), true);
  assert.equal(verifyCodeChallenge('wrong_verifier', challenge, 'S256'), false);
});

test('6. POST /authorize issues code and redirects with unique sub', async () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = computeS256Challenge(verifier);

  const res = await makeRequest({
    method: 'POST',
    path: '/authorize',
    body: {
      client_id: 'test-chatgpt-client',
      redirect_uri: 'https://chatgpt.com/aip/callback',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'chatgpt-state-999'
    }
  });

  assert.equal(res.status, 302);
  const location = res.headers.location;
  assert.ok(location);
  const redirectUrl = new URL(location);
  assert.equal(redirectUrl.origin, 'https://chatgpt.com');
  assert.equal(redirectUrl.searchParams.get('state'), 'chatgpt-state-999');

  const code = redirectUrl.searchParams.get('code');
  assert.ok(code && code.startsWith('mcp_code_'));
});

test('7. POST /token exchanges authorization code with PKCE verifier', async () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = computeS256Challenge(verifier);

  // Mint code
  const authRes = await makeRequest({
    method: 'POST',
    path: '/authorize',
    body: {
      client_id: 'test-chatgpt-client',
      redirect_uri: 'https://chatgpt.com/aip/callback',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    }
  });

  const code = new URL(authRes.headers.location).searchParams.get('code');

  // Exchange code for tokens
  const tokenRes = await makeRequest({
    method: 'POST',
    path: '/token',
    body: {
      grant_type: 'authorization_code',
      code,
      client_id: 'test-chatgpt-client',
      client_secret: 'test-chatgpt-secret',
      redirect_uri: 'https://chatgpt.com/aip/callback',
      code_verifier: verifier
    }
  });

  assert.equal(tokenRes.status, 200);
  assert.ok(tokenRes.json.access_token);
  assert.ok(tokenRes.json.refresh_token);
  assert.equal(tokenRes.json.token_type, 'Bearer');

  // Verify access token is stored and maps to an opaque user sub
  const tokenRecord = await getMcpToken(tokenRes.json.access_token);
  assert.ok(tokenRecord);
  assert.ok(tokenRecord.userSub.startsWith('usr_'));
  assert.notEqual(tokenRecord.userSub, 'test-chatgpt-client');
});

test('8. Authorization code replay is rejected', async () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = computeS256Challenge(verifier);

  const authRes = await makeRequest({
    method: 'POST',
    path: '/authorize',
    body: {
      client_id: 'test-chatgpt-client',
      redirect_uri: 'https://chatgpt.com/aip/callback',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    }
  });

  const code = new URL(authRes.headers.location).searchParams.get('code');

  // First exchange: succeeds
  const tokenRes1 = await makeRequest({
    method: 'POST',
    path: '/token',
    body: {
      grant_type: 'authorization_code',
      code,
      client_id: 'test-chatgpt-client',
      client_secret: 'test-chatgpt-secret',
      redirect_uri: 'https://chatgpt.com/aip/callback',
      code_verifier: verifier
    }
  });
  assert.equal(tokenRes1.status, 200);

  // Replay attempt: must fail
  const tokenRes2 = await makeRequest({
    method: 'POST',
    path: '/token',
    body: {
      grant_type: 'authorization_code',
      code,
      client_id: 'test-chatgpt-client',
      client_secret: 'test-chatgpt-secret',
      redirect_uri: 'https://chatgpt.com/aip/callback',
      code_verifier: verifier
    }
  });
  assert.equal(tokenRes2.status, 400);
  assert.equal(tokenRes2.json.error, 'invalid_grant');
});

test('9. Expired authorization code is rejected', async () => {
  const code = 'mcp_code_expired_test';
  await saveMcpAuthCode({
    code,
    clientId: 'test-chatgpt-client',
    redirectUri: 'https://chatgpt.com/aip/callback',
    codeChallenge: null,
    codeChallengeMethod: null,
    userSub: 'usr_expired_sub',
    scope: 'drive',
    expiresInMs: -1000 // Already expired
  });

  const tokenRes = await makeRequest({
    method: 'POST',
    path: '/token',
    body: {
      grant_type: 'authorization_code',
      code,
      client_id: 'test-chatgpt-client',
      client_secret: 'test-chatgpt-secret',
      redirect_uri: 'https://chatgpt.com/aip/callback'
    }
  });
  assert.equal(tokenRes.status, 400);
  assert.equal(tokenRes.json.error, 'invalid_grant');
});

test('10. Invalid client secret is rejected', async () => {
  const tokenRes = await makeRequest({
    method: 'POST',
    path: '/token',
    body: {
      grant_type: 'authorization_code',
      code: 'any_code',
      client_id: 'test-chatgpt-client',
      client_secret: 'WRONG_SECRET'
    }
  });
  assert.equal(tokenRes.status, 401);
  assert.equal(tokenRes.json.error, 'invalid_client');
});

test('11. Refresh token grant works and rotates tokens', async () => {
  const userSub = generateUserSub();
  const initialRefresh = 'mcp_rt_initial_test';
  const initialAccess = 'mcp_at_initial_test';

  await saveMcpTokens({
    accessToken: initialAccess,
    refreshToken: initialRefresh,
    userSub,
    clientId: 'test-chatgpt-client',
    scope: 'drive'
  });

  const res = await makeRequest({
    method: 'POST',
    path: '/token',
    body: {
      grant_type: 'refresh_token',
      refresh_token: initialRefresh,
      client_id: 'test-chatgpt-client',
      client_secret: 'test-chatgpt-secret'
    }
  });

  assert.equal(res.status, 200);
  assert.ok(res.json.access_token);
  assert.ok(res.json.refresh_token);
  assert.notEqual(res.json.refresh_token, initialRefresh);

  // Old refresh token must now be invalid
  const oldCheck = await getMcpToken(initialRefresh);
  assert.equal(oldCheck, null);

  // New access token must map to the same userSub
  const newCheck = await getMcpToken(res.json.access_token);
  assert.ok(newCheck);
  assert.equal(newCheck.userSub, userSub);
});

test('12. Protected MCP endpoint rejects missing or invalid token', async () => {
  const noTokenRes = await makeRequest({
    method: 'POST',
    path: '/mcp',
    body: { jsonrpc: '2.0', id: 1, method: 'tools/list' }
  });
  assert.equal(noTokenRes.status, 401);

  const badTokenRes = await makeRequest({
    method: 'POST',
    path: '/mcp',
    headers: { Authorization: 'Bearer invalid_token_12345' },
    body: { jsonrpc: '2.0', id: 1, method: 'tools/list' }
  });
  assert.equal(badTokenRes.status, 401);
});
