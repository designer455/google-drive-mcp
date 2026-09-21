import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';

const testDataDir = path.resolve(process.cwd(), 'data-test-kv');

test.before(() => {
  process.env.NODE_ENV = 'test';
  process.env.DATA_DIR = testDataDir;
});

test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
  delete process.env.KV_REST_API_URL;
  delete process.env.KV_REST_API_TOKEN;
});

test('KV Store Integration: writes, reads, and deletes using Upstash command array and REST endpoints', async () => {
  const store = new Map();

  // Create a mock Upstash Redis REST server
  const server = http.createServer((req, res) => {
    const auth = req.headers['authorization'];
    if (auth !== 'Bearer test-token') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const url = req.url;

      // Body-based commands: POST / with ["SET", key, value] or ["GET", key] or ["DEL", key]
      if (req.method === 'POST' && (url === '/' || url === '')) {
        try {
          const cmd = JSON.parse(body);
          if (Array.isArray(cmd)) {
            const [op, key, val] = cmd;
            if (op.toUpperCase() === 'SET') {
              store.set(key, val);
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ result: 'OK' }));
              return;
            }
            if (op.toUpperCase() === 'GET') {
              const val = store.get(key) || null;
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ result: val }));
              return;
            }
            if (op.toUpperCase() === 'DEL') {
              const existed = store.delete(key) ? 1 : 0;
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ result: existed }));
              return;
            }
          }
        } catch {}
      }

      // Path-based commands
      if (url.startsWith('/get/')) {
        const key = decodeURIComponent(url.slice(5));
        const val = store.get(key) || null;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ result: val }));
        return;
      }

      if (url.startsWith('/del/')) {
        const key = decodeURIComponent(url.slice(5));
        const existed = store.delete(key) ? 1 : 0;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ result: existed }));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not Found' }));
    });
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const mockUrl = `http://127.0.0.1:${port}`;

  // Configure environment variables with quotes and whitespace to test sanitization
  process.env.KV_REST_API_URL = ` "${mockUrl}" \n`;
  process.env.KV_REST_API_TOKEN = ' "test-token" ';

  const {
    isKvConfigured,
    kvSetUserGoogleRecord,
    kvGetUserGoogleRecord,
    kvDeleteUserGoogleRecord,
    getUserGoogleRecord,
    setUserGoogleTokens
  } = await import('../src/user-store.js');

  assert.equal(isKvConfigured(), true, 'KV should be detected despite whitespace and quotes');

  const testUserSub = 'usr_kv_test_user_123';
  const testRecord = {
    google: {
      access_token: 'ya29.test_access_token',
      refresh_token: '1//test_refresh_token',
      expiry_date: Date.now() + 3600000
    },
    account: {
      email: 'user@example.com',
      displayName: 'Test User'
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  // 1. Direct KV write
  const writeSuccess = await kvSetUserGoogleRecord(testUserSub, testRecord);
  assert.equal(writeSuccess, true, 'kvSetUserGoogleRecord must succeed');

  // 2. Direct KV read
  const fetched = await kvGetUserGoogleRecord(testUserSub);
  assert.ok(fetched, 'kvGetUserGoogleRecord must return record');
  assert.equal(fetched.google.refresh_token, '1//test_refresh_token');
  assert.equal(fetched.account.email, 'user@example.com');

  // 3. getUserGoogleRecord fetches from KV directly
  const directGet = await getUserGoogleRecord(testUserSub);
  assert.ok(directGet, 'getUserGoogleRecord must read from KV');
  assert.equal(directGet.google.refresh_token, '1//test_refresh_token');

  // 4. Cold-start simulation: wipe local /tmp data dir completely
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }

  // After local file wipe (cold start), getUserGoogleRecord must STILL succeed via KV!
  const coldStartRecord = await getUserGoogleRecord(testUserSub);
  assert.ok(coldStartRecord, 'Cold-start: record must remain available from KV after local storage wiped');
  assert.equal(coldStartRecord.google.refresh_token, '1//test_refresh_token');

  // 5. Delete from KV
  const deleteSuccess = await kvDeleteUserGoogleRecord(testUserSub);
  assert.equal(deleteSuccess, true, 'kvDeleteUserGoogleRecord must succeed');

  const afterDelete = await kvGetUserGoogleRecord(testUserSub);
  assert.equal(afterDelete, null, 'Record must be null after deletion');

  server.close();
});
