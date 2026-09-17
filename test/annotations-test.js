/**
 * Test Suite: MCP Tool Annotations & OpenAI Domain Verification Challenge
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';

const testDataDir = path.resolve(process.cwd(), 'data-test-annotations');
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = testDataDir;
process.env.ALLOWED_HOST = 'mcp-v2.digitonsdevelopment.com';
process.env.OPENAI_APPS_CHALLENGE_TOKEN = 'openai_challenge_token_abc123xyz';

const { app } = await import('../src/server.js');
const { listMcpTools } = await import('../src/mcp.js');

test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

function makeRequest({ method = 'GET', path: reqPath, host = 'mcp-v2.digitonsdevelopment.com', headers = {}, body = null }) {
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

test('1. Every registered MCP tool includes all three annotations', () => {
  const tools = listMcpTools();
  assert.equal(tools.length, 23);

  for (const tool of tools) {
    // Top-level hints
    assert.equal(typeof tool.readOnlyHint, 'boolean', `Tool ${tool.name} missing boolean readOnlyHint`);
    assert.equal(typeof tool.openWorldHint, 'boolean', `Tool ${tool.name} missing boolean openWorldHint`);
    assert.equal(typeof tool.destructiveHint, 'boolean', `Tool ${tool.name} missing boolean destructiveHint`);

    // Nested annotations object
    assert.ok(tool.annotations, `Tool ${tool.name} missing annotations object`);
    assert.equal(typeof tool.annotations.readOnlyHint, 'boolean');
    assert.equal(typeof tool.annotations.openWorldHint, 'boolean');
    assert.equal(typeof tool.annotations.destructiveHint, 'boolean');
    assert.equal(tool.annotations.readOnlyHint, tool.readOnlyHint);
    assert.equal(tool.annotations.openWorldHint, tool.openWorldHint);
    assert.equal(tool.annotations.destructiveHint, tool.destructiveHint);
  }
});

test('2. Read-only tools have readOnlyHint: true and destructiveHint: false', () => {
  const readOnlyTools = [
    'drive_search',
    'drive_list_folder',
    'drive_get_metadata',
    'drive_read_file',
    'drive_search_and_read',
    'drive_sheet_read_range',
    'drive_slides_read',
    'drive_list_permissions'
  ];

  const tools = listMcpTools();
  for (const toolName of readOnlyTools) {
    const tool = tools.find(t => t.name === toolName);
    assert.ok(tool, `Tool ${toolName} must be registered`);
    assert.equal(tool.readOnlyHint, true, `Tool ${toolName} must have readOnlyHint: true`);
    assert.equal(tool.openWorldHint, false, `Tool ${toolName} must have openWorldHint: false`);
    assert.equal(tool.destructiveHint, false, `Tool ${toolName} must have destructiveHint: false`);
  }
});

test('3. Creation and addition write tools have readOnlyHint: false and destructiveHint: false', () => {
  const writeTools = [
    'drive_create_file',
    'drive_create_folder',
    'drive_rename_file',
    'drive_move_file',
    'drive_copy_file',
    'drive_sheet_create',
    'drive_sheet_append_rows',
    'drive_slides_create',
    'drive_add_permission'
  ];

  const tools = listMcpTools();
  for (const toolName of writeTools) {
    const tool = tools.find(t => t.name === toolName);
    assert.ok(tool, `Tool ${toolName} must be registered`);
    assert.equal(tool.readOnlyHint, false, `Tool ${toolName} must have readOnlyHint: false`);
    assert.equal(tool.openWorldHint, false, `Tool ${toolName} must have openWorldHint: false`);
    assert.equal(tool.destructiveHint, false, `Tool ${toolName} must have destructiveHint: false`);
  }
});

test('4. Destructive and overwriting tools have readOnlyHint: false and destructiveHint: true', () => {
  const destructiveTools = [
    'drive_update_file',
    'drive_trash_file',
    'drive_sheet_update_range',
    'drive_slides_update',
    'drive_update_permission',
    'drive_remove_permission'
  ];

  const tools = listMcpTools();
  for (const toolName of destructiveTools) {
    const tool = tools.find(t => t.name === toolName);
    assert.ok(tool, `Tool ${toolName} must be registered`);
    assert.equal(tool.readOnlyHint, false, `Tool ${toolName} must have readOnlyHint: false`);
    assert.equal(tool.openWorldHint, false, `Tool ${toolName} must have openWorldHint: false`);
    assert.equal(tool.destructiveHint, true, `Tool ${toolName} must have destructiveHint: true`);
  }
});

test('5. OpenAI Apps Challenge returns plain text token only', async () => {
  const res = await makeRequest({ path: '/.well-known/openai-apps-challenge' });
  assert.equal(res.status, 200);
  assert.ok(res.headers['content-type'].includes('text/plain'));
  assert.equal(res.headers['cache-control'], 'no-store, no-cache, must-revalidate');
  assert.equal(res.body, 'openai_challenge_token_abc123xyz');
  assert.equal(res.json, null, 'Must NOT return JSON');
});

test('6. OpenAI Apps Challenge returns 404 when token is unset or empty', async () => {
  const originalToken = process.env.OPENAI_APPS_CHALLENGE_TOKEN;
  try {
    delete process.env.OPENAI_APPS_CHALLENGE_TOKEN;
    const res = await makeRequest({ path: '/.well-known/openai-apps-challenge' });
    assert.equal(res.status, 404);
    assert.ok(res.body.includes('not configured'));

    // With whitespace-only token
    process.env.OPENAI_APPS_CHALLENGE_TOKEN = '   ';
    const resWhitespace = await makeRequest({ path: '/.well-known/openai-apps-challenge' });
    assert.equal(resWhitespace.status, 404);
  } finally {
    process.env.OPENAI_APPS_CHALLENGE_TOKEN = originalToken;
  }
});

test('7. OpenAI Apps Challenge does not leak other environment variables', async () => {
  const res = await makeRequest({ path: '/.well-known/openai-apps-challenge' });
  assert.equal(res.body, 'openai_challenge_token_abc123xyz');
  assert.equal(res.body.includes('GOOGLE_CLIENT_ID'), false);
  assert.equal(res.body.includes('CHATGPT_OAUTH_CLIENT_SECRET'), false);
  assert.equal(res.body.includes('DATA_DIR'), false);
});
