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
import {
  handleRootPage,
  handlePrivacyPage,
  handleTermsPage,
  handleSupportPage
} from './pages.js';
import { listMcpTools, executeMcpTool } from './mcp.js';
import { auditLog } from './audit.js';
import { getStorageEncryptionKey } from './crypto-storage.js';

export const app = express();

// RAT-01: Trust reverse proxy (Hostinger, Nginx, Passenger) for correct req.ip and protocol resolution
app.set('trust proxy', 1);

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
// Rate Limiting & Memory Cleanup (RAT-01, RAT-02, RAT-03, RAT-04)
// -------------------------------------------------------------
export const rateLimits = new Map();
export const mcpUserRateLimits = new Map();

const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000;
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100;

const MCP_RATE_LIMIT_WINDOW_MS = parseInt(process.env.MCP_RATE_LIMIT_WINDOW_MS, 10) || 60000;
const MCP_RATE_LIMIT_MAX = parseInt(process.env.MCP_RATE_LIMIT_MAX_REQUESTS, 10) || 60;

/**
 * Prune oldest entries from a map if it exceeds maximum capacity safeguard.
 */
export function pruneExcessEntries(map, maxCapacity = 5000) {
  if (map.size <= maxCapacity) return;
  const excess = map.size - maxCapacity;
  let count = 0;
  for (const key of map.keys()) {
    if (count >= excess) break;
    map.delete(key);
    count++;
  }
}

/**
 * Clean up expired entries from in-memory rate limit maps to prevent memory leaks (RAT-02).
 */
export function cleanupRateLimits() {
  const now = Date.now();
  for (const [key, record] of rateLimits.entries()) {
    if (now > record.resetAt) {
      rateLimits.delete(key);
    }
  }
  for (const [key, record] of mcpUserRateLimits.entries()) {
    if (now > record.resetAt) {
      mcpUserRateLimits.delete(key);
    }
  }

  // Enforce 5,000-entry capacity safeguard against memory exhaustion
  pruneExcessEntries(rateLimits, 5000);
  pruneExcessEntries(mcpUserRateLimits, 5000);
}

// Periodic cleanup timer (every 5 minutes); unref so it does not block process exit
const rateLimitCleanupTimer = setInterval(cleanupRateLimits, 5 * 60 * 1000);
if (rateLimitCleanupTimer.unref) {
  rateLimitCleanupTimer.unref();
}

/**
 * Public & OAuth endpoint rate limiter (IP-based).
 */
export function rateLimiter(req, res, next) {
  if (process.env.NODE_ENV === 'test' && !req.headers['x-test-rate-limit']) {
    return next();
  }

  // Prevent unbounded growth if high volume of unique IPs
  if (rateLimits.size > 5000) {
    cleanupRateLimits();
  }

  const ip = req.ip || req.connection?.remoteAddress || '127.0.0.1';
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

/**
 * Dedicated authenticated user rate limiter for /mcp (RAT-03).
 * Target: 60 MCP tool calls per user per minute based on authenticated userSub.
 */
export function mcpUserRateLimiter(req, res, next) {
  if (process.env.NODE_ENV === 'test' && !req.headers['x-test-mcp-rate-limit']) {
    return next();
  }

  if (mcpUserRateLimits.size > 5000) {
    cleanupRateLimits();
  }

  const userKey = req.userSub || req.ip || 'unknown';
  const now = Date.now();
  const record = mcpUserRateLimits.get(userKey) || { count: 0, resetAt: now + MCP_RATE_LIMIT_WINDOW_MS };

  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + MCP_RATE_LIMIT_WINDOW_MS;
  }

  // RAT-04: Reject JSON-RPC batch arrays larger than 10 requests before charging rate limit
  if (Array.isArray(req.body) && req.body.length > 10) {
    return res.status(400).json({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32600,
        message: 'Invalid Request: Batch size exceeds maximum limit of 10 requests.'
      }
    });
  }

  // If batch request, increment by batch length; otherwise increment by 1
  const cost = Array.isArray(req.body) ? Math.max(1, req.body.length) : 1;
  record.count += cost;
  mcpUserRateLimits.set(userKey, record);

  if (record.count > MCP_RATE_LIMIT_MAX) {
    auditLog({
      userSub: req.userSub,
      action: 'mcp.rate_limit_exceeded',
      status: 'failure',
      details: { limit: MCP_RATE_LIMIT_MAX, count: record.count }
    });

    return res.status(429).json({
      jsonrpc: '2.0',
      id: req.body?.id || null,
      error: {
        code: -32000,
        message: 'Rate limit exceeded. Maximum 60 requests per minute allowed.'
      }
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
    build: 'v2.0.2-branding-verification-fix',
    timestamp: new Date().toISOString()
  });
});

// -------------------------------------------------------------
// Public Informational & Legal Pages
// -------------------------------------------------------------
app.get('/', rateLimiter, handleRootPage);
app.get('/privacy', rateLimiter, handlePrivacyPage);
app.get('/terms', rateLimiter, handleTermsPage);
app.get('/support', rateLimiter, handleSupportPage);

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
 * Enforces authentication, per-user rate limiting (RAT-03), and batch size cap (RAT-04).
 */
app.post('/mcp', requireMcpAuth, mcpUserRateLimiter, async (req, res) => {
  try {
    const userSub = req.userSub;

    // RAT-04: Reject JSON-RPC batch arrays larger than 10 requests
    if (Array.isArray(req.body)) {
      if (req.body.length > 10) {
        return res.status(400).json({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32600,
            message: 'Invalid Request: Batch size exceeds maximum limit of 10 requests.'
          }
        });
      }

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
  // Validate credential encryption key on startup (SEC-04 fail-closed)
  try {
    getStorageEncryptionKey();
  } catch (keyErr) {
    console.error(`[digitons-google-drive-mcp-v2] Fatal configuration error: ${keyErr.message}`);
    process.exit(1);
  }

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
