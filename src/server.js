/**
 * HTTP Server for google-drive-mcp
 * Express application exposing MCP JSON-RPC endpoints, ChatGPT OAuth, and Google OAuth.
 */

import 'dotenv/config';
import crypto from 'node:crypto';
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
import {
  getStorageEncryptionKey,
  getStorageBackend,
  isStorageConfigured,
  getBlobDiagnostics,
  getBlobPathname,
  readEncryptedStorage,
  writeEncryptedStorage,
  deleteEncryptedStorage
} from './crypto-storage.js';
import {
  saveGoogleOAuthState,
  consumeGoogleOAuthState
} from './user-store.js';

export const app = express();

// RAT-01: Trust reverse proxy (Hostinger, Nginx, Passenger) for correct req.ip and protocol resolution
app.set('trust proxy', 1);

// Middleware: Body parsing
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// -------------------------------------------------------------
// Host Validation Middleware
// -------------------------------------------------------------
const allowedHost = process.env.ALLOWED_HOST || 'mcp.example.com';

app.use((req, res, next) => {
  // Always allow health checks
  if (req.path === '/health') {
    return next();
  }

  const rawHost = req.headers['x-forwarded-host'] || req.headers.host || '';
  const hostHeader = rawHost.split(',')[0].trim().split(':')[0].toLowerCase();
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
app.get('/health', async (req, res) => {
  const cleanKey = (key) => (key || '').trim().replace(/^["']|["']$/g, '');
  const keyHash = (key) => key ? crypto.createHash('sha256').update(key).digest('hex').slice(0, 8) : null;

  const storageKeyRaw = process.env.STORAGE_ENCRYPTION_KEY || '';
  const chatgptSecretRaw = process.env.CHATGPT_OAUTH_CLIENT_SECRET || '';
  const chatgptRedirectRaw = process.env.CHATGPT_OAUTH_REDIRECT_URI || '';
  const chatgptClientIdRaw = process.env.CHATGPT_OAUTH_CLIENT_ID || '';
  const storageBackend = getStorageBackend();
  const storageConfigured = isStorageConfigured();

  // 1. In-invocation storage cycle probe (?verify_storage=1)
  let storageVerification = null;
  if (req.query.verify_storage === '1' || req.query.verify_storage === 'true') {
    const probeId = `probe_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const probeFileName = `probe_${probeId}.enc.json`;
    const probeSecret = `secret_${crypto.randomBytes(8).toString('hex')}`;
    const probePayload = {
      probeId,
      secret: probeSecret,
      createdAt: new Date().toISOString()
    };

    try {
      // Step A: Write encrypted record
      await writeEncryptedStorage(probeFileName, probePayload);
      
      // Step B: Read back bypassing cache (useCache: false)
      const readResult = await readEncryptedStorage(probeFileName, null);
      const readData = readResult?.data;
      const decryptedMatch = Boolean(readData && readData.secret === probeSecret);

      // Step C: Delete probe record
      const deleteSuccess = await deleteEncryptedStorage(probeFileName);

      storageVerification = {
        connectivity: 'PASS',
        write: 'PASS',
        read: readResult ? 'PASS' : 'FAIL',
        decrypt: decryptedMatch ? 'PASS' : 'FAIL',
        delete: deleteSuccess ? 'PASS' : 'FAIL'
      };
    } catch (err) {
      storageVerification = {
        connectivity: 'FAIL',
        write: 'FAIL',
        read: 'FAIL',
        decrypt: 'FAIL',
        delete: 'FAIL',
        error: err.message
      };
    }
  }

  // 2. Cross-invocation persistence verification probe (?verify_persistence=write|read|cleanup)
  let persistenceVerification = null;
  const persistenceAction = (req.query.verify_persistence || '').toLowerCase();
  const rawProbeId = (req.query.probe_id || '').trim();
  const safeProbeId = rawProbeId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);

  if (persistenceAction && safeProbeId) {
    const persistenceFile = `persistence_probe_${safeProbeId}.enc.json`;
    try {
      if (persistenceAction === 'write') {
        const payload = {
          probe_id: safeProbeId,
          value: req.query.probe_value || `value_${Date.now()}`,
          written_at: new Date().toISOString(),
          invocation_pid: process.pid,
          invocation_time: Date.now()
        };
        const writeRes = await writeEncryptedStorage(persistenceFile, payload);
        const blobPathname = getBlobPathname(persistenceFile);
        persistenceVerification = {
          action: 'write',
          probe_id: safeProbeId,
          status: 'SUCCESS',
          blob_pathname: blobPathname,
          etag: writeRes.etag,
          invocation_pid: process.pid,
          invocation_time: payload.invocation_time,
          encryption: {
            algorithm: 'aes-256-gcm',
            access: 'private',
            envelope_stored: true
          }
        };
      } else if (persistenceAction === 'read') {
        const readResult = await readEncryptedStorage(persistenceFile, null);
        const blobPathname = getBlobPathname(persistenceFile);
        if (readResult && readResult.data) {
          persistenceVerification = {
            action: 'read',
            probe_id: safeProbeId,
            status: 'SUCCESS',
            persisted: true,
            blob_pathname: blobPathname,
            etag: readResult.etag,
            use_cache_false: true,
            invocation_pid: process.pid,
            invocation_time: Date.now(),
            data: readResult.data
          };
        } else {
          persistenceVerification = {
            action: 'read',
            probe_id: safeProbeId,
            status: 'FAIL',
            persisted: false,
            blob_pathname: blobPathname,
            reason: 'Record not found in persistent store'
          };
        }
      } else if (persistenceAction === 'cleanup') {
        const deleted = await deleteEncryptedStorage(persistenceFile);
        persistenceVerification = {
          action: 'cleanup',
          probe_id: safeProbeId,
          status: 'SUCCESS',
          deleted
        };
      }
    } catch (err) {
      persistenceVerification = {
        action: persistenceAction,
        probe_id: safeProbeId,
        status: 'FAIL',
        error: err.message
      };
    }
  }

  // 3. Real storage flow probe: save and consume temporary OAuth state
  let oauthFlowVerification = null;
  const oauthAction = (req.query.verify_oauth_flow || '').toLowerCase();
  const rawOAuthState = (req.query.oauth_state || '').trim();
  const safeOAuthState = rawOAuthState.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);

  if (oauthAction && safeOAuthState) {
    try {
      if (oauthAction === 'save') {
        const testSub = req.query.user_sub || `usr_probe_${crypto.randomBytes(4).toString('hex')}`;
        await saveGoogleOAuthState(safeOAuthState, testSub, 60000);
        oauthFlowVerification = {
          action: 'save',
          state: safeOAuthState,
          user_sub: testSub,
          status: 'SUCCESS',
          invocation_pid: process.pid
        };
      } else if (oauthAction === 'consume') {
        const boundSub = await consumeGoogleOAuthState(safeOAuthState);
        oauthFlowVerification = {
          action: 'consume',
          state: safeOAuthState,
          bound_user_sub: boundSub,
          status: 'SUCCESS',
          invocation_pid: process.pid
        };
      }
    } catch (err) {
      oauthFlowVerification = {
        action: oauthAction,
        state: safeOAuthState,
        status: 'REJECTED',
        error_code: err.code || 'UNKNOWN_ERROR',
        error: err.message,
        invocation_pid: process.pid
      };
    }
  }

  res.json({
    status: 'ok',
    server: 'google-drive-mcp',
    version: '2.0.0',
    build: 'v2.1.0-vercel-blob-storage',
    storage_backend: storageBackend,
    storage_configured: storageConfigured,
    timestamp: new Date().toISOString(),
    env_diagnostics: {
      storage_backend: storageBackend,
      storage_configured: storageConfigured,
      single_user_mode: process.env.SINGLE_USER_MODE || 'false',
      storage_key: {
        configured: Boolean(storageKeyRaw),
        length: storageKeyRaw.length,
        has_whitespace: /\s/.test(storageKeyRaw),
        has_quotes: /^["'].*["']$/.test(storageKeyRaw),
        hash_prefix_8: keyHash(cleanKey(storageKeyRaw))
      },
      chatgpt_client_secret: {
        configured: Boolean(chatgptSecretRaw),
        length: chatgptSecretRaw.length,
        has_whitespace: /\s/.test(chatgptSecretRaw),
        has_quotes: /^["'].*["']$/.test(chatgptSecretRaw),
        hash_prefix_8: keyHash(cleanKey(chatgptSecretRaw))
      },
      chatgpt_redirect_uri: {
        configured: Boolean(chatgptRedirectRaw),
        has_whitespace: /\s/.test(chatgptRedirectRaw),
        has_quotes: /^["'].*["']$/.test(chatgptRedirectRaw),
        hash_prefix_8: keyHash(cleanKey(chatgptRedirectRaw))
      },
      blob_diagnostics: {
        ...getBlobDiagnostics(),
        discovered_blob_keys: Object.keys(process.env).filter(k => /blob/i.test(k))
      },
      ...(storageVerification ? { storage_verification: storageVerification } : {}),
      ...(persistenceVerification ? { persistence_verification: persistenceVerification } : {}),
      ...(oauthFlowVerification ? { oauth_flow_verification: oauthFlowVerification } : {})
    }
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
            listChanged: true
          }
        },
        serverInfo: {
          name: 'google-drive-mcp',
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

const isVercel = Boolean(process.env.VERCEL);

if (process.env.NODE_ENV !== 'test' && !process.env.MCP_NO_LISTEN && !isVercel) {
  // Validate credential encryption key on startup (SEC-04 fail-closed)
  try {
    getStorageEncryptionKey();
  } catch (keyErr) {
    console.error(`[google-drive-mcp] Fatal configuration error: ${keyErr.message}`);
    process.exit(1);
  }

  const server = app.listen(PORT, () => {
    console.log(`[google-drive-mcp] Server listening on port ${PORT}`);
    console.log(`[google-drive-mcp] Allowed Host: ${allowedHost}`);
    console.log(`[google-drive-mcp] MCP Endpoint: ${getPublicOrigin()}/mcp`);
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
