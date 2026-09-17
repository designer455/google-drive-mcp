/**
 * Test Suite: Public Informational & Legal Pages (Privacy, Terms, Support, Root)
 * Verifies unauthenticated access, HTTP 200, content accuracy, link integrity, and zero secret/token leakage.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';

const testDataDir = path.resolve(process.cwd(), 'data-test-pages');
process.env.NODE_ENV = 'production'; // Test under production rules for host checking
process.env.MCP_NO_LISTEN = 'true';
process.env.DATA_DIR = testDataDir;
process.env.ALLOWED_HOST = 'mcp-v2.digitonsdevelopment.com';
process.env.SUPPORT_EMAIL = 'support@digitonsdevelopment.com';
process.env.COMPANY_NAME = 'Digitons Development';
process.env.COMPANY_WEBSITE = 'https://www.digitonsdevelopment.com';
process.env.GOOGLE_CLIENT_SECRET = 'super-secret-google-client-secret-xyz';
process.env.CHATGPT_OAUTH_CLIENT_SECRET = 'super-secret-chatgpt-client-secret-abc';
process.env.OPENAI_APPS_CHALLENGE_TOKEN = 'mock-challenge-token-secret-123';

const { app } = await import('../src/server.js');

test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

function makeRequest({ method = 'GET', path: reqPath, host = 'mcp-v2.digitonsdevelopment.com', headers = {} }) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;

      const reqHeaders = {
        Host: host,
        ...headers
      };

      const req = http.request(
        { hostname: '127.0.0.1', port, path: reqPath, method, headers: reqHeaders },
        (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            server.close();
            resolve({ status: res.statusCode, headers: res.headers, body: data });
          });
        }
      );

      req.on('error', (err) => {
        server.close();
        reject(err);
      });

      req.end();
    });
  });
}

test('1. GET /privacy returns 200 and renders complete privacy policy', async () => {
  const res = await makeRequest({ path: '/privacy' });

  assert.equal(res.status, 200);
  assert.ok(res.headers['content-type'].includes('text/html'));
  assert.ok(res.body.includes('Privacy Policy'));
  assert.ok(res.body.includes('Digitons Development'));
  assert.ok(res.body.includes('https://www.googleapis.com/auth/drive'));
  assert.ok(res.body.includes('0600'));
  assert.ok(res.body.includes('not encrypted at rest'));
  assert.ok(res.body.includes('REDACTED'));
  assert.ok(res.body.includes('support@digitonsdevelopment.com'));
  assert.ok(res.body.includes('/terms'));
  assert.ok(res.body.includes('/support'));
});

test('2. GET /terms returns 200 and renders comprehensive terms of service', async () => {
  const res = await makeRequest({ path: '/terms' });

  assert.equal(res.status, 200);
  assert.ok(res.headers['content-type'].includes('text/html'));
  assert.ok(res.body.includes('Terms of Service'));
  assert.ok(res.body.includes('Acceptable Use'));
  assert.ok(res.body.includes('10 MB'));
  assert.ok(res.body.includes('Trash'));
  assert.ok(res.body.includes('Limitation of Liability'));
  assert.ok(res.body.includes('Governing Law'));
  assert.ok(res.body.includes('/privacy'));
  assert.ok(res.body.includes('/support'));
});

test('3. GET /support returns 200 and renders support & troubleshooting guide', async () => {
  const res = await makeRequest({ path: '/support' });

  assert.equal(res.status, 200);
  assert.ok(res.headers['content-type'].includes('text/html'));
  assert.ok(res.body.includes('Support &amp; Help Center') || res.body.includes('Support & Help Center'));
  assert.ok(res.body.includes('How to Connect Your Google Drive'));
  assert.ok(res.body.includes('Troubleshooting'));
  assert.ok(res.body.includes('How to Disconnect'));
  assert.ok(res.body.includes('support@digitonsdevelopment.com'));
  assert.ok(res.body.includes('/privacy'));
  assert.ok(res.body.includes('/terms'));
});

test('4. GET / returns 200 and renders root landing page with exact branding and links', async () => {
  const res = await makeRequest({ path: '/' });

  assert.equal(res.status, 200);
  assert.ok(res.headers['content-type'].includes('text/html'));
  assert.ok(res.body.includes('Digitons Google Drive MCP V2'));
  assert.ok(res.body.includes('<title>Digitons Google Drive MCP V2</title>'));
  assert.ok(res.body.includes('<h1>Digitons Google Drive MCP V2</h1>'));
  assert.ok(res.body.includes('Digitons Google Drive MCP V2 is a secure multi-user remote MCP server that allows ChatGPT and OpenAI Agents to access and manage authorized Google Drive files.'));
  assert.ok(res.body.includes('digitonsdevelopment.com'));
  assert.ok(res.body.includes('/privacy'));
  assert.ok(res.body.includes('/terms'));
  assert.ok(res.body.includes('/support'));
});

test('5. Unauthenticated access works without Authorization header or cookies', async () => {
  const paths = ['/', '/privacy', '/terms', '/support'];

  for (const p of paths) {
    const res = await makeRequest({ path: p, headers: {} });
    assert.equal(res.status, 200, `Expected 200 for ${p} without auth`);
  }
});

test('6. Zero secret or token leakage in rendered HTML pages', async () => {
  const envSecrets = [
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.CHATGPT_OAUTH_CLIENT_SECRET,
    process.env.OPENAI_APPS_CHALLENGE_TOKEN
  ];

  const tokenPatterns = [
    /glink_[a-f0-9]{20,}/i,
    /ya29\.[a-zA-Z0-9_-]{20,}/,
    /Bearer\s+[a-zA-Z0-9_.-]{20,}/i
  ];

  const paths = ['/', '/privacy', '/terms', '/support'];

  for (const p of paths) {
    const res = await makeRequest({ path: p });
    for (const secret of envSecrets) {
      if (secret) {
        assert.ok(
          !res.body.includes(secret),
          `Environment secret "${secret}" exposed on page ${p}`
        );
      }
    }
    for (const pattern of tokenPatterns) {
      assert.ok(
        !pattern.test(res.body),
        `Live token pattern ${pattern} matched on page ${p}`
      );
    }
  }
});

test('7. Host validation protects public pages against unexpected host headers', async () => {
  const res = await makeRequest({
    path: '/privacy',
    host: 'unauthorized-phishing.com'
  });

  assert.equal(res.status, 403);
});
