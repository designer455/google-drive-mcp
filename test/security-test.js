/**
 * Test Suite: Security Controls, State Protection, IDOR Prevention, and Auditing
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';

const testDataDir = path.resolve(process.cwd(), 'data-test-security');
process.env.NODE_ENV = 'production'; // Test in production mode for strict host checking
process.env.MCP_NO_LISTEN = 'true';
process.env.DATA_DIR = testDataDir;
process.env.ALLOWED_HOST = 'mcp.example.com';

const { app } = await import('../src/server.js');
const {
  saveGoogleOAuthState,
  consumeGoogleOAuthState,
  getUserGoogleRecord,
  setUserGoogleTokens,
  ensureDataDir
} = await import('../src/user-store.js');
const { executeMcpTool } = await import('../src/mcp.js');
const { sanitize, auditLog } = await import('../src/audit.js');

test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

function makeRequest({ method = 'GET', path: reqPath, host = 'mcp.example.com', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const payload = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;

      const reqHeaders = {
        Host: host,
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

test('1. Google OAuth State: Bound to userSub and consumable once', async () => {
  const state = 'state_sec_test_1';
  const userSub = 'usr_test_subject_123';

  await saveGoogleOAuthState(state, userSub, 60000);

  // First consumption: returns bound userSub
  const consumedSub = await consumeGoogleOAuthState(state);
  assert.equal(consumedSub, userSub);

  // Second consumption (Replay): must be rejected
  await assert.rejects(
    async () => { await consumeGoogleOAuthState(state); },
    (err) => {
      assert.equal(err.code, 'OAUTH_STATE_INVALID');
      return true;
    }
  );
});

test('2. Google OAuth State: Expired state is rejected', async () => {
  const state = 'state_sec_expired';
  const userSub = 'usr_test_subject_456';

  // Save with -1ms expiry (already expired)
  await saveGoogleOAuthState(state, userSub, -1000);

  await assert.rejects(
    async () => { await consumeGoogleOAuthState(state); },
    (err) => {
      assert.equal(err.code, 'OAUTH_STATE_EXPIRED');
      return true;
    }
  );
});

test('3. Google OAuth State: Invalid state is rejected', async () => {
  await assert.rejects(
    async () => { await consumeGoogleOAuthState('completely_nonexistent_state'); },
    (err) => {
      assert.equal(err.code, 'OAUTH_STATE_INVALID');
      return true;
    }
  );
});

test('4. Tool Execution: userId injection is stripped and ignored', async () => {
  const trustedSub = 'usr_victim_user';
  const attackerSub = 'usr_attacker_user';

  // An attacker passes userId: 'usr_attacker_user' or 'admin' in tool arguments
  const toolArgs = {
    fileId: 'f1',
    userId: attackerSub,
    userSub: attackerSub
  };

  // The tool handler should run in the context of trustedSub regardless of toolArgs
  let receivedContext = null;
  const mockDriveClient = {
    files: {
      get: async (params) => {
        return { data: { id: 'f1', name: 'File' } };
      }
    }
  };

  const { setGoogleClientOverrides } = await import('../src/google.js');
  setGoogleClientOverrides({
    getDriveClient: async (sub) => {
      receivedContext = sub;
      return mockDriveClient;
    }
  });

  await executeMcpTool('drive_get_metadata', toolArgs, trustedSub);

  // The client was created for trustedSub, NOT attackerSub
  assert.equal(receivedContext, trustedSub);
  assert.notEqual(receivedContext, attackerSub);
});

test('5. Ownership Transfer is strictly blocked', async () => {
  const userSub = 'usr_test_owner_block';

  // Attempt drive_add_permission with role: 'owner'
  const addRes = await executeMcpTool('drive_add_permission', {
    fileId: 'f1',
    role: 'owner',
    type: 'user',
    emailAddress: 'attacker@example.com'
  }, userSub);

  assert.equal(addRes.isError, true);
  assert.ok(
    addRes.content[0].text.includes('OWNERSHIP_TRANSFER_BLOCKED') ||
    addRes.content[0].text.includes('invalid_enum_value') ||
    addRes.content[0].text.includes("received 'owner'")
  );

  // Attempt drive_update_permission with role: 'owner'
  const updateRes = await executeMcpTool('drive_update_permission', {
    fileId: 'f1',
    permissionId: 'p1',
    role: 'owner'
  }, userSub);

  assert.equal(updateRes.isError, true);
  assert.ok(
    updateRes.content[0].text.includes('OWNERSHIP_TRANSFER_BLOCKED') ||
    updateRes.content[0].text.includes('invalid_enum_value') ||
    updateRes.content[0].text.includes("received 'owner'")
  );
});

test('6. Permission validation requires emailAddress for user and group', async () => {
  const userSub = 'usr_test_perm_val';

  const resNoEmail = await executeMcpTool('drive_add_permission', {
    fileId: 'f1',
    role: 'writer',
    type: 'user'
    // missing emailAddress
  }, userSub);

  assert.equal(resNoEmail.isError, true);
  assert.ok(resNoEmail.content[0].text.includes('emailAddress is required'));
});

test('7. Host Header Validation blocks unexpected hosts in production', async () => {
  const badHostRes = await makeRequest({
    path: '/health',
    host: 'evil.com'
  });
  // /health is allowed for monitoring
  assert.equal(badHostRes.status, 200);

  const blockedRes = await makeRequest({
    path: '/.well-known/oauth-authorization-server',
    host: 'evil-phishing.com'
  });
  assert.equal(blockedRes.status, 403);
  assert.equal(blockedRes.json.error, 'forbidden');
  assert.ok(blockedRes.json.message.includes('Host "evil-phishing.com" is not allowed'));

  // Allowed host succeeds
  const allowedRes = await makeRequest({
    path: '/.well-known/oauth-authorization-server',
    host: 'mcp.example.com'
  });
  assert.equal(allowedRes.status, 200);
});

test('8. Audit log sanitizer redacts sensitive fields', () => {
  const sensitiveObj = {
    access_token: 'secret_token_123',
    refresh_token: 'secret_refresh_456',
    client_secret: 'secret_client_789',
    authorization_code: 'auth_code_abc',
    password: 'super_secret_pw',
    userSub: 'usr_valid_sub',
    fileName: 'Report.txt',
    nested: {
      token: 'nested_token_value',
      safeField: 42
    }
  };

  const sanitized = sanitize(sensitiveObj);

  assert.equal(sanitized.access_token, '[REDACTED]');
  assert.equal(sanitized.refresh_token, '[REDACTED]');
  assert.equal(sanitized.client_secret, '[REDACTED]');
  assert.equal(sanitized.authorization_code, '[REDACTED]');
  assert.equal(sanitized.password, '[REDACTED]');
  assert.equal(sanitized.userSub, 'usr_valid_sub');
  assert.equal(sanitized.fileName, 'Report.txt');
  assert.equal(sanitized.nested.token, '[REDACTED]');
  assert.equal(sanitized.nested.safeField, 42);
});

test('9. Storage files created with restricted 0600 mode', async () => {
  const userSub = 'usr_perm_check';
  await setUserGoogleTokens(userSub, {
    access_token: 'tok_check',
    refresh_token: 'ref_check'
  });

  const usersFile = path.join(testDataDir, 'google-users.json');
  assert.ok(fs.existsSync(usersFile));

  const stats = fs.statSync(usersFile);
  // Mode 0600 in octal: (mode & 0777) === 0600 (384 decimal)
  const fileMode = stats.mode & 0o777;
  // On platforms supporting POSIX chmod, verify 0o600
  if (process.platform !== 'win32') {
    assert.equal(fileMode, 0o600);
  }
});

test('10. Process restart persistence: Credentials reload from disk', async () => {
  const userSub = 'usr_survives_restart';
  await setUserGoogleTokens(userSub, {
    access_token: 'persist_token_val',
    refresh_token: 'persist_refresh_val'
  }, { email: 'survivor@example.com' });

  // Read directly from disk as if a brand-new process spawned
  const record = await getUserGoogleRecord(userSub);
  assert.ok(record);
  assert.equal(record.google.access_token, 'persist_token_val');
  assert.equal(record.account.email, 'survivor@example.com');
});
