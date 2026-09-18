/**
 * Test Suite: Regression & Hardening Verification for Audit Findings
 * Tests SEC-01, SEC-02, SEC-03, RAT-01, RAT-02, RAT-03, RAT-04
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';
import crypto from 'node:crypto';

const testDataDir = path.resolve(process.cwd(), 'data-test-hardening');
process.env.NODE_ENV = 'production'; // Production mode to test strict host validation and error sanitization
process.env.MCP_NO_LISTEN = 'true';
process.env.DATA_DIR = testDataDir;
process.env.ALLOWED_HOST = 'mcp-v2.digitonsdevelopment.com';
process.env.MCP_PUBLIC_ORIGIN = 'https://mcp-v2.digitonsdevelopment.com';
process.env.MCP_PUBLIC_URL = 'https://mcp-v2.digitonsdevelopment.com/mcp';
process.env.CHATGPT_OAUTH_CLIENT_ID = 'hardening-test-client';
process.env.CHATGPT_OAUTH_CLIENT_SECRET = 'hardening-test-secret';
process.env.CHATGPT_OAUTH_REDIRECT_URI = 'https://chatgpt.com/connector/oauth/callback';
process.env.MCP_RATE_LIMIT_WINDOW_MS = '60000';

const {
  app,
  rateLimits,
  mcpUserRateLimits,
  cleanupRateLimits
} = await import('../src/server.js');
const {
  validateRedirectUri,
  verifyCodeChallenge,
  computeS256Challenge
} = await import('../src/oauth.js');
const {
  saveMcpTokens,
  setUserGoogleTokens,
  getUserGoogleRecord
} = await import('../src/user-store.js');

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
        Host: 'mcp-v2.digitonsdevelopment.com',
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

// ----------------------------------------------------------------------
// 1. SEC-01: redirect_uri Validation Tests
// ----------------------------------------------------------------------
test('SEC-01.1: validateRedirectUri allows configured CHATGPT_OAUTH_REDIRECT_URI', () => {
  assert.equal(validateRedirectUri('https://chatgpt.com/connector/oauth/callback'), true);
});

test('SEC-01.2: validateRedirectUri rejects attacker-controlled redirect URI', () => {
  assert.equal(validateRedirectUri('https://attacker.com/oauth/callback'), false);
  assert.equal(validateRedirectUri('https://evil-chatgpt.com/callback'), false);
  assert.equal(validateRedirectUri('http://chatgpt.com.attacker.com/callback'), false);
});

test('SEC-01.3: validateRedirectUri rejects missing, empty, or non-string URI', () => {
  assert.equal(validateRedirectUri(null), false);
  assert.equal(validateRedirectUri(undefined), false);
  assert.equal(validateRedirectUri(''), false);
  assert.equal(validateRedirectUri(12345), false);
});

test('SEC-01.4: validateRedirectUri rejects malformed or dangerous protocols', () => {
  assert.equal(validateRedirectUri('javascript:alert(1)'), false);
  assert.equal(validateRedirectUri('data:text/html,<script>alert(1)</script>'), false);
  assert.equal(validateRedirectUri('ftp://chatgpt.com/callback'), false);
  assert.equal(validateRedirectUri('not-a-valid-url'), false);
  assert.equal(validateRedirectUri('http://chatgpt.com/connector/oauth/callback'), false); // Plaintext http rejected in production
});

test('SEC-01.5: GET /authorize rejects unapproved redirect_uri with HTTP 400', async () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = computeS256Challenge(verifier);

  const res = await makeRequest({
    path: `/authorize?response_type=code&client_id=hardening-test-client&redirect_uri=https%3A%2F%2Fevil.com%2Fcallback&code_challenge=${challenge}&code_challenge_method=S256`
  });
  assert.equal(res.status, 400);
  assert.ok(res.body.includes('Invalid or unauthorized redirect_uri'));
});

test('SEC-01.6: POST /authorize rejects unapproved redirect_uri with HTTP 400', async () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = computeS256Challenge(verifier);

  const res = await makeRequest({
    method: 'POST',
    path: '/authorize',
    body: {
      client_id: 'hardening-test-client',
      redirect_uri: 'https://attacker.com/callback',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    }
  });
  assert.equal(res.status, 400);
  assert.equal(res.json?.error, 'invalid_request');
  assert.ok(res.json?.error_description.includes('unauthorized redirect_uri'));
});

// ----------------------------------------------------------------------
// 2. SEC-02 & SEC-03: PKCE S256 Enforcement & Crash Prevention
// ----------------------------------------------------------------------
test('SEC-03.1: GET /authorize rejects missing code_challenge with HTTP 400', async () => {
  const res = await makeRequest({
    path: '/authorize?response_type=code&client_id=hardening-test-client&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector%2Foauth%2Fcallback'
  });
  assert.equal(res.status, 400);
  assert.ok(res.body.includes('Missing code_challenge'));
});

test('SEC-03.2: GET /authorize rejects missing or invalid code_challenge_method with HTTP 400', async () => {
  const resMissingMethod = await makeRequest({
    path: '/authorize?response_type=code&client_id=hardening-test-client&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector%2Foauth%2Fcallback&code_challenge=abc1234567890'
  });
  assert.equal(resMissingMethod.status, 400);
  assert.ok(resMissingMethod.body.includes('code_challenge_method'));

  const resPlainMethod = await makeRequest({
    path: '/authorize?response_type=code&client_id=hardening-test-client&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector%2Foauth%2Fcallback&code_challenge=abc1234567890&code_challenge_method=plain'
  });
  assert.equal(resPlainMethod.status, 400);
  assert.ok(resPlainMethod.body.includes('Only "S256" is supported'));
});

test('SEC-03.3: POST /authorize rejects plain method and missing PKCE with HTTP 400', async () => {
  const resMissingChallenge = await makeRequest({
    method: 'POST',
    path: '/authorize',
    body: {
      client_id: 'hardening-test-client',
      redirect_uri: 'https://chatgpt.com/connector/oauth/callback'
    }
  });
  assert.equal(resMissingChallenge.status, 400);
  assert.equal(resMissingChallenge.json?.error, 'invalid_request');

  const resPlain = await makeRequest({
    method: 'POST',
    path: '/authorize',
    body: {
      client_id: 'hardening-test-client',
      redirect_uri: 'https://chatgpt.com/connector/oauth/callback',
      code_challenge: 'plain_challenge',
      code_challenge_method: 'plain'
    }
  });
  assert.equal(resPlain.status, 400);
  assert.equal(resPlain.json?.error, 'invalid_request');
  assert.ok(resPlain.json?.error_description.includes('Only "S256" is supported'));
});

test('SEC-02.1: verifyCodeChallenge handles malformed challenge length without throwing RangeError', () => {
  const verifier = 'my_test_verifier_string_12345678901234567890';
  const malformedShortChallenge = 'too_short';
  const malformedLongChallenge = 'this_challenge_string_is_way_too_long_and_will_have_unequal_buffer_length_compared_to_sha256';

  assert.doesNotThrow(() => {
    const resultShort = verifyCodeChallenge(verifier, malformedShortChallenge, 'S256');
    assert.equal(resultShort, false);
  });

  assert.doesNotThrow(() => {
    const resultLong = verifyCodeChallenge(verifier, malformedLongChallenge, 'S256');
    assert.equal(resultLong, false);
  });
});

test('SEC-02.2: POST /token with malformed PKCE challenge returns HTTP 400, never HTTP 500', async () => {
  // Authorize with valid S256
  const verifier = crypto.randomBytes(32).toString('base64url');
  const validChallenge = computeS256Challenge(verifier);

  const authRes = await makeRequest({
    method: 'POST',
    path: '/authorize',
    body: {
      client_id: 'hardening-test-client',
      redirect_uri: 'https://chatgpt.com/connector/oauth/callback',
      code_challenge: validChallenge,
      code_challenge_method: 'S256'
    }
  });
  assert.equal(authRes.status, 302);
  const code = new URL(authRes.headers.location).searchParams.get('code');

  // Exchange token with wrong verifier length
  const tokenRes = await makeRequest({
    method: 'POST',
    path: '/token',
    body: {
      grant_type: 'authorization_code',
      code,
      client_id: 'hardening-test-client',
      client_secret: 'hardening-test-secret',
      redirect_uri: 'https://chatgpt.com/connector/oauth/callback',
      code_verifier: 'invalid_short_verifier'
    }
  });

  assert.equal(tokenRes.status, 400);
  assert.equal(tokenRes.json?.error, 'invalid_grant');
  assert.equal(tokenRes.json?.error_description, 'PKCE verification failed');
});

// ----------------------------------------------------------------------
// 3. RAT-01: Express trust proxy & req.ip Resolution
// ----------------------------------------------------------------------
test('RAT-01: Express trust proxy is enabled and resolves X-Forwarded-For', async () => {
  // We can query /health and inspect that trust proxy evaluates headers without error
  const res = await makeRequest({
    path: '/health',
    headers: {
      'X-Forwarded-For': '203.0.113.195, 127.0.0.1',
      'X-Forwarded-Proto': 'https'
    }
  });
  assert.equal(res.status, 200);
  assert.equal(res.json?.status, 'ok');
});

// ----------------------------------------------------------------------
// 4. RAT-04: Limit JSON-RPC Batch Size to 10 Requests
// ----------------------------------------------------------------------
test('RAT-04.1: POST /mcp processes valid batch array up to 10 requests', async () => {
  const userSub = 'usr_batch_test_allowed';
  const token = 'mcp_at_batch_allowed';
  await saveMcpTokens({ accessToken: token, userSub, clientId: 'client', scope: 'drive' });

  const batch10 = Array.from({ length: 10 }, (_, i) => ({
    jsonrpc: '2.0',
    id: i + 1,
    method: 'ping'
  }));

  const res = await makeRequest({
    method: 'POST',
    path: '/mcp',
    headers: { Authorization: `Bearer ${token}` },
    body: batch10
  });

  assert.equal(res.status, 200);
  assert.ok(Array.isArray(res.json));
  assert.equal(res.json.length, 10);
});

test('RAT-04.2: POST /mcp rejects batch array with > 10 requests with HTTP 400', async () => {
  const userSub = 'usr_batch_test_oversize';
  const token = 'mcp_at_batch_oversize';
  await saveMcpTokens({ accessToken: token, userSub, clientId: 'client', scope: 'drive' });

  const batch11 = Array.from({ length: 11 }, (_, i) => ({
    jsonrpc: '2.0',
    id: i + 1,
    method: 'ping'
  }));

  const res = await makeRequest({
    method: 'POST',
    path: '/mcp',
    headers: { Authorization: `Bearer ${token}` },
    body: batch11
  });

  assert.equal(res.status, 400);
  assert.equal(res.json?.error?.code, -32600);
  assert.ok(res.json?.error?.message.includes('Batch size exceeds maximum limit of 10 requests'));
});

// ----------------------------------------------------------------------
// 5. RAT-03: Dedicated Authenticated User Rate Limiting on /mcp
// ----------------------------------------------------------------------
test('RAT-03: /mcp rate limits users independently based on userSub', async () => {
  const userA = 'usr_rat_user_a';
  const userB = 'usr_rat_user_b';
  const tokenA = 'mcp_at_rat_user_a';
  const tokenB = 'mcp_at_rat_user_b';

  await saveMcpTokens({ accessToken: tokenA, userSub: userA, clientId: 'client', scope: 'drive' });
  await saveMcpTokens({ accessToken: tokenB, userSub: userB, clientId: 'client', scope: 'drive' });

  // Pre-seed userA at 59 requests (limit is 60)
  mcpUserRateLimits.set(userA, { count: 59, resetAt: Date.now() + 60000 });
  mcpUserRateLimits.delete(userB);

  // 60th request for User A -> Succeeds (reaches exact limit)
  const res60 = await makeRequest({
    method: 'POST',
    path: '/mcp',
    headers: {
      Authorization: `Bearer ${tokenA}`,
      'x-test-mcp-rate-limit': '1'
    },
    body: { jsonrpc: '2.0', id: 60, method: 'ping' }
  });
  assert.equal(res60.status, 200);

  // 61st request for User A -> Exceeds rate limit -> HTTP 429
  const resExceededA = await makeRequest({
    method: 'POST',
    path: '/mcp',
    headers: {
      Authorization: `Bearer ${tokenA}`,
      'x-test-mcp-rate-limit': '1'
    },
    body: { jsonrpc: '2.0', id: 61, method: 'ping' }
  });
  assert.equal(resExceededA.status, 429);
  assert.equal(resExceededA.json?.error?.code, -32000);
  assert.ok(resExceededA.json?.error?.message.includes('Rate limit exceeded'));

  // User B has not made requests yet -> Must succeed with HTTP 200
  const resUserB = await makeRequest({
    method: 'POST',
    path: '/mcp',
    headers: {
      Authorization: `Bearer ${tokenB}`,
      'x-test-mcp-rate-limit': '1'
    },
    body: { jsonrpc: '2.0', id: 1, method: 'ping' }
  });
  assert.equal(resUserB.status, 200);
  assert.deepEqual(resUserB.json?.result, {});
});

// ----------------------------------------------------------------------
// 6. RAT-02: Rate Limit Map Cleanup & Memory Leak Prevention
// ----------------------------------------------------------------------
test('RAT-02: cleanupRateLimits safely evicts expired entries', () => {
  const now = Date.now();

  // Add expired and active entries
  rateLimits.set('192.0.2.1', { count: 5, resetAt: now - 1000 }); // expired
  rateLimits.set('192.0.2.2', { count: 2, resetAt: now + 60000 }); // active

  mcpUserRateLimits.set('usr_old_expired', { count: 10, resetAt: now - 500 }); // expired
  mcpUserRateLimits.set('usr_current_active', { count: 1, resetAt: now + 60000 }); // active

  assert.equal(rateLimits.has('192.0.2.1'), true);
  assert.equal(mcpUserRateLimits.has('usr_old_expired'), true);

  cleanupRateLimits();

  // Expired should be evicted
  assert.equal(rateLimits.has('192.0.2.1'), false);
  assert.equal(mcpUserRateLimits.has('usr_old_expired'), false);

  // Active must remain
  assert.equal(rateLimits.has('192.0.2.2'), true);
  assert.equal(mcpUserRateLimits.has('usr_current_active'), true);
});

// ----------------------------------------------------------------------
// 7. Security: Production Error Handler Never Exposes Stack Traces
// ----------------------------------------------------------------------
test('SEC-ERR: Production error responses do not leak stack traces or internal paths', async () => {
  // Trigger host rejected error
  const res = await makeRequest({
    path: '/privacy',
    headers: { Host: 'phishing-evil.com' }
  });

  assert.equal(res.status, 403);
  assert.equal(res.json?.error, 'forbidden');
  assert.equal(res.json?.stack, undefined);
  assert.equal(res.body.includes('at '), false); // No stack trace traces like 'at Function.module'
});

// ======================================================================
// PHASE 2 TESTS: ERR-01, Timeout, Retry, Rate-Limit Lifecycle, Error Sanitization
// ======================================================================

const {
  isInvalidGrantError,
  isTransientGoogleError,
  withTimeout,
  executeWithRetry,
  setGoogleClientOverrides
} = await import('../src/google.js');
const {
  executeMcpTool
} = await import('../src/mcp.js');
const {
  deleteUserGoogleRecord
} = await import('../src/user-store.js');
const {
  pruneExcessEntries
} = await import('../src/server.js');

// ----------------------------------------------------------------------
// 8. ERR-01: Google invalid_grant Detection & Recovery Tests
// ----------------------------------------------------------------------
test('ERR-01.1: isInvalidGrantError correctly identifies invalid_grant variations', () => {
  assert.equal(isInvalidGrantError(new Error('invalid_grant')), true);
  assert.equal(isInvalidGrantError(new Error('Token has been expired or revoked.')), true);
  assert.equal(isInvalidGrantError({ response: { data: { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' } } }), true);
  assert.equal(isInvalidGrantError({ response: { data: 'invalid_grant' } }), true);
  assert.equal(isInvalidGrantError({ code: 'invalid_grant' }), true);

  // Normal errors must return false
  assert.equal(isInvalidGrantError(new Error('File not found')), false);
  assert.equal(isInvalidGrantError({ status: 503 }), false);
  assert.equal(isInvalidGrantError({ status: 400, message: 'Invalid argument' }), false);
});

test('ERR-01.2: invalid_grant purges affected user credentials, generates link token, isolates other users', async () => {
  const userA = 'usr_err01_test_a';
  const userB = 'usr_err01_test_b';

  // Seed credentials for User A and User B
  await setUserGoogleTokens(userA, {
    access_token: 'ya29.test_token_a',
    refresh_token: '1//refresh_a',
    expiry_date: Date.now() + 3600000
  });
  await setUserGoogleTokens(userB, {
    access_token: 'ya29.test_token_b',
    refresh_token: '1//refresh_b',
    expiry_date: Date.now() + 3600000
  });

  assert.ok(await getUserGoogleRecord(userA), 'User A must exist in store');
  assert.ok(await getUserGoogleRecord(userB), 'User B must exist in store');

  // Override drive client to simulate invalid_grant for User A
  setGoogleClientOverrides({
    getDriveClient: async (sub) => {
      if (sub === userA) {
        const err = new Error('invalid_grant: Token has been expired or revoked.');
        err.response = { status: 400, data: { error: 'invalid_grant' } };
        throw err;
      }
      return {
        files: {
          list: async () => ({ data: { files: [{ id: 'f1', name: 'User B File' }] } })
        }
      };
    }
  });

  try {
    // User A executes tool -> Must not throw 500; returns controlled GOOGLE_AUTH_REVOKED
    const resA = await executeMcpTool('drive_search', { query: 'test' }, userA);

    assert.equal(resA.isError, true);
    assert.ok(resA.content[0].text.includes('GOOGLE_AUTH_REVOKED'), 'Error code must be GOOGLE_AUTH_REVOKED');
    assert.ok(resA.content[0].text.includes('/auth/google/link?code='), 'Must include reconnect link token');
    assert.ok(!resA.content[0].text.includes('ya29.'), 'Must NOT leak access token');
    assert.ok(!resA.content[0].text.includes('1//'), 'Must NOT leak refresh token');
    assert.ok(!resA.content[0].text.includes('/Users/'), 'Must NOT leak server filesystem paths');

    // User A record must now be purged from store
    const recordA = await getUserGoogleRecord(userA);
    assert.equal(recordA, null, 'User A credentials must be deleted from store');

    // User B must remain completely intact and unaffected (User Isolation invariant)
    const recordB = await getUserGoogleRecord(userB);
    assert.ok(recordB, 'User B record must still exist');
    assert.equal(recordB.google.access_token, 'ya29.test_token_b');

    // User B executes tool successfully
    const resB = await executeMcpTool('drive_search', { query: 'test' }, userB);
    assert.equal(resB.isError, undefined);
    assert.ok(resB.content[0].text.includes('User B File'));
  } finally {
    setGoogleClientOverrides(null);
  }
});

// ----------------------------------------------------------------------
// 9. Centralized Timeout Tests
// ----------------------------------------------------------------------
test('TIMEOUT.1: withTimeout rejects when operation exceeds timeout', async () => {
  const hangingOp = () => new Promise(resolve => setTimeout(resolve, 200));

  await assert.rejects(
    async () => {
      await withTimeout(hangingOp, 50);
    },
    (err) => {
      assert.equal(err.code, 'TIMEOUT');
      assert.equal(err.status, 504);
      assert.ok(err.message.includes('timed out'));
      return true;
    }
  );
});

test('TIMEOUT.2: withTimeout resolves normally when operation completes before timeout', async () => {
  const fastOp = async () => 'completed_in_time';
  const result = await withTimeout(fastOp, 500);
  assert.equal(result, 'completed_in_time');
});

test('TIMEOUT.3: MCP tool execution formats timeout cleanly without stack trace or leak', async () => {
  setGoogleClientOverrides({
    getDriveClient: async () => {
      const err = new Error('Google API request timed out after 30000ms.');
      err.code = 'TIMEOUT';
      err.status = 504;
      throw err;
    }
  });

  try {
    const res = await executeMcpTool('drive_search', { query: 'test' }, 'usr_timeout_test');
    assert.equal(res.isError, true);
    assert.ok(res.content[0].text.includes('Error [TIMEOUT]: Google API request timed out after 30 seconds. Please try again.'));
    assert.ok(!res.content[0].text.includes('at '), 'Must not leak stack trace');
  } finally {
    setGoogleClientOverrides(null);
  }
});

// ----------------------------------------------------------------------
// 10. Transient Failure Retry Tests (503, 429, Non-Retry for 400, 401, 403)
// ----------------------------------------------------------------------
test('RETRY.1: isTransientGoogleError accurately identifies 429 and 503 only', () => {
  assert.equal(isTransientGoogleError({ status: 503 }), true);
  assert.equal(isTransientGoogleError({ status: 429 }), true);
  assert.equal(isTransientGoogleError({ response: { status: 503 } }), true);
  assert.equal(isTransientGoogleError({ response: { status: 429 } }), true);
  assert.equal(isTransientGoogleError({ code: 'ECONNRESET' }), true);
  assert.equal(isTransientGoogleError({ code: 'ETIMEDOUT' }), true);

  // Permanent errors must never be retried
  assert.equal(isTransientGoogleError({ status: 400 }), false);
  assert.equal(isTransientGoogleError({ status: 401 }), false);
  assert.equal(isTransientGoogleError({ status: 403 }), false);
  assert.equal(isTransientGoogleError({ status: 404 }), false);
  assert.equal(isTransientGoogleError({ message: 'invalid_grant' }), false);
  assert.equal(isTransientGoogleError({ code: 'TIMEOUT' }), false);
});

test('RETRY.2: 503 succeeds after retry', async () => {
  let callCount = 0;
  const flakeyFn = async () => {
    callCount++;
    if (callCount === 1) {
      const err = new Error('Service Unavailable');
      err.status = 503;
      throw err;
    }
    return { success: true, callCount };
  };

  const res = await executeWithRetry(flakeyFn, { maxAttempts: 3, baseDelayMs: 5 });
  assert.equal(res.success, true);
  assert.equal(res.callCount, 2);
  assert.equal(callCount, 2);
});

test('RETRY.3: 429 succeeds after retry with exponential backoff', async () => {
  let callCount = 0;
  const rateLimitedFn = async () => {
    callCount++;
    if (callCount < 3) {
      const err = new Error('Too Many Requests');
      err.status = 429;
      throw err;
    }
    return { success: true, callCount };
  };

  const res = await executeWithRetry(rateLimitedFn, { maxAttempts: 3, baseDelayMs: 5 });
  assert.equal(res.success, true);
  assert.equal(res.callCount, 3);
  assert.equal(callCount, 3);
});

test('RETRY.4: Repeated 503 fails after max 3 attempts', async () => {
  let callCount = 0;
  const failingFn = async () => {
    callCount++;
    const err = new Error('Persistent 503 Outage');
    err.status = 503;
    throw err;
  };

  await assert.rejects(
    async () => {
      await executeWithRetry(failingFn, { maxAttempts: 3, baseDelayMs: 5 });
    },
    (err) => {
      assert.equal(err.status, 503);
      assert.equal(callCount, 3, 'Must stop after exactly 3 attempts');
      return true;
    }
  );
});

test('RETRY.5: 400 Bad Request, 401 Unauthorized, 403 Forbidden are NOT retried', async () => {
  for (const status of [400, 401, 403]) {
    let callCount = 0;
    const nonTransientFn = async () => {
      callCount++;
      const err = new Error(`HTTP Error ${status}`);
      err.status = status;
      throw err;
    };

    await assert.rejects(
      async () => {
        await executeWithRetry(nonTransientFn, { maxAttempts: 3, baseDelayMs: 5 });
      },
      (err) => {
        assert.equal(err.status, status);
        assert.equal(callCount, 1, `Must NOT retry HTTP ${status}`);
        return true;
      }
    );
  }
});

test('RETRY.6: invalid_grant is NOT retried', async () => {
  let callCount = 0;
  const invalidGrantFn = async () => {
    callCount++;
    const err = new Error('invalid_grant: Revoked token');
    err.status = 400;
    throw err;
  };

  await assert.rejects(
    async () => {
      await executeWithRetry(invalidGrantFn, { maxAttempts: 3, baseDelayMs: 5 });
    },
    (err) => {
      assert.equal(callCount, 1, 'invalid_grant must NEVER be retried');
      return true;
    }
  );
});

test('RETRY.7: Internal retries do NOT multiply /mcp rate limit accounting', async () => {
  const userSub = 'usr_rat_retry_test_user';
  const token = 'mcp_retry_rat_token_123';

  await saveMcpTokens({ accessToken: token, userSub, clientId: 'hardening-test-client', scope: 'drive' });

  let attempt = 0;
  setGoogleClientOverrides({
    getDriveClient: async () => ({
      files: {
        list: async () => {
          attempt++;
          if (attempt === 1) {
            const err = new Error('Temporary Google 503');
            err.status = 503;
            throw err;
          }
          return { data: { files: [{ id: 'retried_f1', name: 'Retried File' }] } };
        }
      }
    })
  });

  try {
    mcpUserRateLimits.delete(userSub);

    const res = await makeRequest({
      method: 'POST',
      path: '/mcp',
      headers: {
        Authorization: `Bearer ${token}`,
        'x-test-mcp-rate-limit': '1'
      },
      body: {
        jsonrpc: '2.0',
        id: 'retry-test-1',
        method: 'tools/call',
        params: {
          name: 'drive_search',
          arguments: { query: 'test' }
        }
      }
    });

    assert.equal(res.status, 200);
    assert.equal(attempt, 2, 'Underlying handler must have been attempted twice');

    // The rate limit must only be charged once (cost: 1)
    const record = mcpUserRateLimits.get(userSub);
    assert.ok(record);
    assert.equal(record.count, 1, 'Rate limit count must be exactly 1 despite retry');
  } finally {
    setGoogleClientOverrides(null);
  }
});

// ----------------------------------------------------------------------
// 11. Rate-Limit Memory Lifecycle & Capacity Safeguard Tests
// ----------------------------------------------------------------------
test('RAT-CAP: pruneExcessEntries strictly enforces 5000-entry capacity limit', () => {
  const testMap = new Map();

  // Populate 5010 entries
  for (let i = 0; i < 5010; i++) {
    testMap.set(`key_${i}`, { count: 1, resetAt: Date.now() + 60000 });
  }

  assert.equal(testMap.size, 5010);
  pruneExcessEntries(testMap, 5000);
  assert.equal(testMap.size, 5000, 'Must prune to exactly 5000 entries');

  // Verify oldest entries (key_0 to key_9) were evicted
  assert.equal(testMap.has('key_0'), false);
  assert.equal(testMap.has('key_9'), false);
  assert.equal(testMap.has('key_10'), true);
  assert.equal(testMap.has('key_5009'), true);
});

test('RAT-LIFECYCLE: active rate limit windows are strictly preserved during cleanup', () => {
  const now = Date.now();
  const activeUser = 'usr_active_window';
  const expiredUser = 'usr_expired_window';

  mcpUserRateLimits.set(activeUser, { count: 15, resetAt: now + 45000 });
  mcpUserRateLimits.set(expiredUser, { count: 30, resetAt: now - 5000 });

  cleanupRateLimits();

  // Active user must NOT be deleted
  assert.equal(mcpUserRateLimits.has(activeUser), true);
  assert.equal(mcpUserRateLimits.get(activeUser).count, 15);

  // Expired user MUST be deleted
  assert.equal(mcpUserRateLimits.has(expiredUser), false);
});
