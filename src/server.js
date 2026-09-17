/**
 * HTTP Server for digitons-google-drive-mcp-v2
 * Express application exposing MCP JSON-RPC endpoints, ChatGPT OAuth, and Google OAuth.
 */

import 'dotenv/config';
import express from 'express';
import {
  handleOAuthMetadata,
  handleProtectedResourceMetadata,
  handleGetAuthorize,
  handlePostAuthorize,
  handlePostToken,
  requireMcpAuth
} from './oauth.js';
import {
  handleGoogleAuthInitiate,
  handleGoogleLink,
  handleGoogleOAuthCallback,
  handleGoogleAuthStatus,
  handleGoogleAuthDisconnect
} from './google-oauth.js';
import { listMcpTools, executeMcpTool } from './mcp.js';
import { auditLog } from './audit.js';

export const app = express();

// Middleware: Body parsing
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// -------------------------------------------------------------
// Host Validation Middleware
// -------------------------------------------------------------
const allowedHost = process.env.ALLOWED_HOST || 'mcp-v2.digitonsdevelopment.com';

app.use((req, res, next) => {
  // Always allow health checks
  if (req.path === '/health') {
    return next();
  }

  const hostHeader = (req.headers.host || '').split(':')[0].toLowerCase();
  const isDevOrTest = process.env.NODE_ENV !== 'production' || process.env.NODE_ENV === 'test';

  if (isDevOrTest) {
    if (hostHeader === 'localhost' || hostHeader === '127.0.0.1' || hostHeader === allowedHost.toLowerCase()) {
      return next();
    }
  }

  if (hostHeader === allowedHost.toLowerCase()) {
    return next();
  }

  auditLog({
    action: 'security.host_rejected',
    status: 'failure',
    details: { hostHeader, allowedHost }
  });

  return res.status(403).json({
    error: 'forbidden',
    message: `Host "${hostHeader}" is not allowed. Expected "${allowedHost}".`
  });
});

// -------------------------------------------------------------
// Simple In-Memory Rate Limiting
// -------------------------------------------------------------
const rateLimits = new Map();
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000;
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100;

function rateLimiter(req, res, next) {
  if (process.env.NODE_ENV === 'test') {
    return next();
  }

  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const now = Date.now();
  const record = rateLimits.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };

  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }

  record.count += 1;
  rateLimits.set(ip, record);

  if (record.count > RATE_LIMIT_MAX) {
    return res.status(429).json({
      error: 'too_many_requests',
      message: 'Rate limit exceeded. Please try again later.'
    });
  }

  next();
}

// -------------------------------------------------------------
// Health Check
// -------------------------------------------------------------
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    server: 'digitons-google-drive-mcp-v2',
    version: '2.0.0',
    timestamp: new Date().toISOString()
  });
});

// -------------------------------------------------------------
// ChatGPT OAuth Endpoints
// -------------------------------------------------------------
app.get('/.well-known/oauth-authorization-server', handleOAuthMetadata);
app.get('/.well-known/openid-configuration', handleOAuthMetadata);
app.get('/.well-known/oauth-protected-resource', handleProtectedResourceMetadata);
app.get('/.well-known/openai-apps-challenge', (req, res) => {
  const token = process.env.OPENAI_APPS_CHALLENGE_TOKEN;
  if (!token || typeof token !== 'string' || !token.trim()) {
    return res.status(404).set({
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache'
    }).send('OpenAI domain verification challenge not configured');
  }

  res.set({
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache'
  });
  return res.send(token.trim());
});
app.get('/authorize', rateLimiter, handleGetAuthorize);
app.post('/authorize', rateLimiter, handlePostAuthorize);
app.post('/token', rateLimiter, handlePostToken);

// -------------------------------------------------------------
// Google Multi-User OAuth Endpoints
// -------------------------------------------------------------
app.get('/auth/google', rateLimiter, handleGoogleAuthInitiate);
app.get('/auth/google/link', rateLimiter, handleGoogleLink);
app.get('/oauth2callback', rateLimiter, handleGoogleOAuthCallback);
app.get('/auth/google/status', requireMcpAuth, handleGoogleAuthStatus);
app.post('/auth/google/disconnect', requireMcpAuth, handleGoogleAuthDisconnect);

// -------------------------------------------------------------
// MCP Streamable HTTP / JSON-RPC Transport (/mcp)
// -------------------------------------------------------------

/**
 * Handle MCP JSON-RPC request.
 */
async function handleJsonRpc(reqBody, userSub) {
  const { jsonrpc, id, method, params } = reqBody;

  if (jsonrpc !== '2.0') {
    return {
      jsonrpc: '2.0',
      id: id || null,
      error: { code: -32600, message: 'Invalid Request: jsonrpc must be "2.0"' }
    };
  }

  // MCP Protocol Methods
  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {
            listChanged: false
          }
        },
        serverInfo: {
          name: 'digitons-google-drive-mcp-v2',
          version: '2.0.0'
        }
      }
    };
  }

  if (method === 'notifications/initialized') {
    // Client notification after initialize
    return null;
  }

  if (method === 'ping') {
    return {
      jsonrpc: '2.0',
      id,
      result: {}
    };
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: listMcpTools()
      }
    };
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};

    const toolResult = await executeMcpTool(toolName, toolArgs, userSub);
    return {
      jsonrpc: '2.0',
      id,
      result: toolResult
    };
  }

  return {
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `Method not found: ${method}` }
  };
}

/**
 * POST /mcp - Streamable HTTP JSON-RPC endpoint for ChatGPT MCP clients.
 */
app.post('/mcp', requireMcpAuth, async (req, res) => {
  try {
    const userSub = req.userSub;

    // Handle batch JSON-RPC or single JSON-RPC
    if (Array.isArray(req.body)) {
      const responses = [];
      for (const item of req.body) {
        const response = await handleJsonRpc(item, userSub);
        if (response) responses.push(response);
      }
      return res.json(responses);
    }

    const response = await handleJsonRpc(req.body, userSub);
    if (!response) {
      // Notification without response
      return res.status(204).end();
    }
    return res.json(response);
  } catch (err) {
    auditLog({
      userSub: req.userSub,
      action: 'mcp.unhandled_error',
      status: 'failure',
      details: { error: err.message }
    });

    return res.status(500).json({
      jsonrpc: '2.0',
      id: req.body?.id || null,
      error: { code: -32603, message: 'Internal JSON-RPC server error' }
    });
  }
});

/**
 * GET /mcp - Server-Sent Events (SSE) support for streaming clients.
 */
app.get('/mcp', requireMcpAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const endpointUrl = `${req.protocol}://${req.get('host')}/mcp`;
  res.write(`event: endpoint\ndata: ${endpointUrl}\n\n`);

  req.on('close', () => {
    res.end();
  });
});

// -------------------------------------------------------------
// Global Error Handler
// -------------------------------------------------------------
app.use((err, req, res, next) => {
  auditLog({
    action: 'server.error',
    status: 'failure',
    details: { message: err.message, stack: err.stack }
  });

  // Never expose stack trace in production HTTP response
  const isProd = process.env.NODE_ENV === 'production';
  res.status(err.status || 500).json({
    error: err.name || 'InternalServerError',
    message: isProd ? 'An internal server error occurred' : err.message
  });
});

// -------------------------------------------------------------
// Server Startup (if started directly)
// -------------------------------------------------------------
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'test' && !process.env.MCP_NO_LISTEN) {
  const server = app.listen(PORT, () => {
    console.log(`[digitons-google-drive-mcp-v2] Server listening on port ${PORT}`);
    console.log(`[digitons-google-drive-mcp-v2] Allowed Host: ${allowedHost}`);
    console.log(`[digitons-google-drive-mcp-v2] MCP Endpoint: ${getPublicOrigin()}/mcp`);
  });

  // Graceful shutdown
  const shutdown = (signal) => {
    console.log(`Received ${signal}, closing server gracefully...`);
    server.close(() => {
      console.log('Server closed successfully.');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

function getPublicOrigin() {
  return process.env.MCP_PUBLIC_ORIGIN || `http://localhost:${PORT}`;
}
