/**
 * MCP Stdio Transport Entry Point
 * Allows running the MCP server locally over stdin/stdout.
 */

import 'dotenv/config';
import readline from 'node:readline';
import { executeMcpTool, listMcpTools } from './mcp.js';
import { auditLog } from './audit.js';

// For local stdio execution, resolve user identity from environment or default to local developer subject
const stdioUserSub = process.env.STDIO_USER_SUB || 'usr_local_stdio';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const request = JSON.parse(trimmed);
    const response = await handleStdioJsonRpc(request, stdioUserSub);
    if (response) {
      process.stdout.write(JSON.stringify(response) + '\n');
    }
  } catch (err) {
    const errorResponse = {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700, message: 'Parse error: ' + err.message }
    };
    process.stdout.write(JSON.stringify(errorResponse) + '\n');
  }
});

async function handleStdioJsonRpc(reqBody, userSub) {
  const { jsonrpc, id, method, params } = reqBody;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'digitons-google-drive-mcp-v2-stdio', version: '2.0.0' }
      }
    };
  }

  if (method === 'notifications/initialized') {
    return null;
  }

  if (method === 'ping') {
    return { jsonrpc: '2.0', id, result: {} };
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: { tools: listMcpTools() }
    };
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};
    const result = await executeMcpTool(toolName, toolArgs, userSub);
    return { jsonrpc: '2.0', id, result };
  }

  return {
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `Method not found: ${method}` }
  };
}

process.stderr.write('[digitons-google-drive-mcp-v2] stdio transport initialized.\n');
