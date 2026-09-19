/**
 * OAuth 2.0 Authorization Server for ChatGPT MCP Clients
 * Implements RFC 6749, RFC 7636 (PKCE S256), RFC 8414 (Discovery), and RFC 9470 (Protected Resource).
 */

import crypto from 'node:crypto';
import {
  saveMcpAuthCode,
  consumeMcpAuthCode,
  saveMcpTokens,
  getMcpToken,
  revokeMcpToken
} from './user-store.js';
import { auditLog } from './audit.js';

// Base URLs
export function getPublicOrigin() {
  return process.env.MCP_PUBLIC_ORIGIN || `http://localhost:${process.env.PORT || 3000}`;
}

export function getPublicUrl() {
  return process.env.MCP_PUBLIC_URL || `${getPublicOrigin()}/mcp`;
}

/**
 * Generate a cryptographically secure opaque user subject.
 */
export function generateUserSub() {
  return `usr_${crypto.randomBytes(16).toString('hex')}`;
}

/**
 * Validate redirect_uri against configured CHATGPT_OAUTH_REDIRECT_URI or strict allowlist (SEC-01).
 */
export function validateRedirectUri(redirectUri) {
  if (!redirectUri || typeof redirectUri !== 'string') return false;

  let parsed;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return false;
  }

  // Reject non-http/https protocols (e.g. javascript:, data:, file:)
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return false;
  }

  // In production, reject plaintext HTTP
  if (parsed.protocol === 'http:' && process.env.NODE_ENV === 'production') {
    return false;
  }

  const configured = process.env.CHATGPT_OAUTH_REDIRECT_URI;
  if (configured) {
    const allowed = configured.split(',').map(s => s.trim()).filter(Boolean);
    return allowed.includes(redirectUri);
  }

  // Fallback if CHATGPT_OAUTH_REDIRECT_URI is not explicitly set:
  // Strictly allow only verified chatgpt.com subdomains over https, or localhost in dev/test
  const isDevOrTest = process.env.NODE_ENV !== 'production' || process.env.NODE_ENV === 'test';
  if (parsed.protocol === 'https:' && (parsed.hostname === 'chatgpt.com' || parsed.hostname.endsWith('.chatgpt.com'))) {
    return true;
  }

  if (isDevOrTest && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')) {
    return true;
  }

  return false;
}

/**
 * Helper to compute PKCE S256 code challenge.
 */
export function computeS256Challenge(verifier) {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
}

/**
 * Validate PKCE code_verifier against code_challenge (SEC-02, SEC-03).
 * Strictly requires method 'S256' and guards against RangeError on buffer length mismatch.
 */
export function verifyCodeChallenge(verifier, challenge, method = 'S256') {
  if (!verifier || !challenge) return false;
  // SEC-03: Strictly enforce S256; reject 'plain' or other methods
  if (method !== 'S256') return false;

  try {
    const computed = computeS256Challenge(verifier);
    const bufA = Buffer.from(computed);
    const bufB = Buffer.from(challenge);

    // SEC-02: Verify lengths match before calling timingSafeEqual to avoid RangeError
    if (bufA.length !== bufB.length) {
      return false;
    }

    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Extract client credentials from Authorization header or body.
 */
export function extractClientCredentials(req) {
  // Check client_secret_basic (Authorization: Basic base64(client_id:client_secret))
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const credentials = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      const [clientId, clientSecret] = credentials.split(':');
      if (clientId) {
        return { clientId, clientSecret: clientSecret || '' };
      }
    } catch {
      // Fall through to body check
    }
  }

  // Check client_secret_post
  const clientId = req.body?.client_id || req.query?.client_id;
  const clientSecret = req.body?.client_secret || req.query?.client_secret;

  return { clientId, clientSecret };
}

/**
 * Validate client credentials.
 */
export function validateClientCredentials(clientId, clientSecret) {
  const expectedClientId = process.env.CHATGPT_OAUTH_CLIENT_ID;
  const expectedSecret = process.env.CHATGPT_OAUTH_CLIENT_SECRET;

  // If no specific client credentials are set in environment, require at least non-empty clientId
  if (!expectedClientId) {
    return Boolean(clientId);
  }

  if (clientId !== expectedClientId) {
    return false;
  }

  // If secret is configured, require match
  if (expectedSecret && clientSecret !== expectedSecret) {
    return false;
  }

  return true;
}

// -------------------------------------------------------------
// Metadata Endpoints
// -------------------------------------------------------------

/**
 * RFC 8414 OAuth 2.0 Authorization Server Metadata
 * GET /.well-known/oauth-authorization-server
 */
export function handleOAuthMetadata(req, res) {
  const origin = getPublicOrigin();
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.json({
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    scopes_supported: ['drive', 'offline_access'],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    code_challenge_methods_supported: ['S256'],
    service_documentation: `${origin}/README.md`
  });
}

/**
 * RFC 9470 OAuth 2.0 Protected Resource Metadata
 * GET /.well-known/oauth-protected-resource
 */
export function handleProtectedResourceMetadata(req, res) {
  const origin = getPublicOrigin();
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.json({
    resource: getPublicUrl(),
    authorization_servers: [origin],
    scopes_supported: ['drive'],
    bearer_methods_supported: ['header']
  });
}

// -------------------------------------------------------------
// Authorization Endpoint (/authorize)
// -------------------------------------------------------------

/**
 * GET /authorize - Display consent/approval page for ChatGPT connection.
 */
export function handleGetAuthorize(req, res) {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope = 'drive',
    state,
    code_challenge,
    code_challenge_method
  } = req.query;

  if (response_type !== 'code') {
    return res.status(400).send('Unsupported response_type. Expected "code".');
  }

  if (!client_id || !redirect_uri) {
    return res.status(400).send('Missing client_id or redirect_uri.');
  }

  // If client ID is configured, validate it
  const configuredClient = process.env.CHATGPT_OAUTH_CLIENT_ID;
  if (configuredClient && client_id !== configuredClient) {
    return res.status(400).send('Invalid client_id.');
  }

  // SEC-01: Validate redirect_uri against allowlist / configuration
  if (!validateRedirectUri(redirect_uri)) {
    return res.status(400).send('Invalid or unauthorized redirect_uri.');
  }

  // SEC-03: Enforce PKCE S256
  if (!code_challenge || typeof code_challenge !== 'string' || !code_challenge.trim()) {
    return res.status(400).send('Missing code_challenge. PKCE S256 is required.');
  }

  if (!code_challenge_method) {
    return res.status(400).send('Missing code_challenge_method. Only "S256" is supported.');
  }

  if (code_challenge_method !== 'S256') {
    return res.status(400).send('Invalid code_challenge_method. Only "S256" is supported.');
  }

  // Render HTML authorization consent page
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Connect Google Drive MCP to ChatGPT</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; }
    .card { background: #1e293b; border-radius: 12px; padding: 32px; max-width: 440px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
    h1 { font-size: 20px; margin-top: 0; margin-bottom: 8px; color: #ffffff; }
    p { font-size: 14px; color: #94a3b8; line-height: 1.5; margin-bottom: 20px; }
    .scope-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 24px; }
    .scope-item { font-size: 13px; color: #cbd5e1; display: flex; align-items: center; gap: 8px; }
    .btn { display: block; width: 100%; padding: 12px; background: #2563eb; color: #ffffff; font-weight: 600; border: none; border-radius: 8px; cursor: pointer; text-align: center; font-size: 14px; text-decoration: none; box-sizing: border-box; }
    .btn:hover { background: #1d4ed8; }
    .footer { font-size: 12px; color: #64748b; margin-top: 20px; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize ChatGPT Connection</h1>
    <p>ChatGPT is requesting access to your private Google Drive MCP instance. Each user has dedicated, isolated credentials.</p>
    
    <div class="scope-box">
      <div class="scope-item">🔒 Scope: <strong>${escapeHtml(scope)}</strong></div>
      <div class="scope-item" style="margin-top: 6px;">🛡️ Identity: Isolated opaque subject</div>
    </div>

    <form method="POST" action="/authorize">
      <input type="hidden" name="response_type" value="${escapeHtml(response_type)}">
      <input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
      <input type="hidden" name="scope" value="${escapeHtml(scope)}">
      <input type="hidden" name="state" value="${escapeHtml(state || '')}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge || '')}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method)}">
      
      <button type="submit" class="btn">Authorize & Connect</button>
    </form>
    
    <div class="footer">Google Drive MCP (Isolated Multi-User)</div>
  </div>
</body>
</html>`);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * POST /authorize - Process user approval, mint authorization code.
 */
export async function handlePostAuthorize(req, res) {
  const {
    client_id,
    redirect_uri,
    scope = 'drive',
    state,
    code_challenge,
    code_challenge_method
  } = req.body;

  if (!client_id || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing client_id or redirect_uri' });
  }

  // SEC-01: Validate redirect_uri against allowlist / configuration
  if (!validateRedirectUri(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid or unauthorized redirect_uri' });
  }

  // If client ID is configured, validate it
  const configuredClient = process.env.CHATGPT_OAUTH_CLIENT_ID;
  if (configuredClient && client_id !== configuredClient) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Invalid client_id' });
  }

  // SEC-03: Enforce PKCE S256
  if (!code_challenge || typeof code_challenge !== 'string' || !code_challenge.trim()) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing code_challenge. PKCE S256 is required' });
  }

  if (!code_challenge_method) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing code_challenge_method. Only "S256" is supported' });
  }

  if (code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid code_challenge_method. Only "S256" is supported' });
  }

  // Generate an internal, stable opaque user subject for this MCP user
  const userSub = generateUserSub();
  const code = `mcp_code_${crypto.randomBytes(24).toString('hex')}`;

  await saveMcpAuthCode({
    code,
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    userSub,
    scope,
    expiresInMs: (parseInt(process.env.AUTH_CODE_EXPIRY_SECONDS, 10) || 300) * 1000
  });

  auditLog({
    userSub,
    action: 'auth.mcp_authorize_granted',
    status: 'success',
    details: { clientId: client_id }
  });

  // Redirect back to client with code and original state
  const targetUrl = new URL(redirect_uri);
  targetUrl.searchParams.set('code', code);
  if (state) {
    targetUrl.searchParams.set('state', state);
  }

  return res.redirect(targetUrl.toString());
}

// -------------------------------------------------------------
// Token Endpoint (/token)
// -------------------------------------------------------------

/**
 * POST /token - Exchange authorization code or refresh token.
 */
export async function handlePostToken(req, res) {
  const { clientId, clientSecret } = extractClientCredentials(req);
  const grantType = req.body?.grant_type;

  // Validate client
  if (!validateClientCredentials(clientId, clientSecret)) {
    auditLog({
      action: 'auth.mcp_token_rejected',
      status: 'failure',
      details: { reason: 'invalid_client', clientId }
    });
    return res.status(401).json({ error: 'invalid_client', error_description: 'Client authentication failed' });
  }

  if (grantType === 'authorization_code') {
    const { code, redirect_uri, code_verifier } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Missing code' });
    }

    let codeRecord;
    try {
      codeRecord = await consumeMcpAuthCode(code);
    } catch (err) {
      auditLog({
        action: 'auth.mcp_token_rejected',
        status: 'failure',
        details: { reason: err.message, code: err.code }
      });
      return res.status(400).json({ error: 'invalid_grant', error_description: err.message });
    }

    // SEC-01: Verify redirect_uri matches and is valid
    if (!redirect_uri || !validateRedirectUri(redirect_uri) || (codeRecord.redirectUri && codeRecord.redirectUri !== redirect_uri)) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch or invalid' });
    }

    // SEC-03: Verify PKCE is present and valid
    if (!codeRecord.codeChallenge) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Missing PKCE challenge on authorization code' });
    }

    if (!code_verifier) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Missing code_verifier for PKCE challenge' });
    }

    // SEC-02 & SEC-03: Verify PKCE S256 safely without RangeError
    const valid = verifyCodeChallenge(code_verifier, codeRecord.codeChallenge, codeRecord.codeChallengeMethod || 'S256');
    if (!valid) {
      auditLog({
        userSub: codeRecord.userSub,
        action: 'auth.pkce_verification_failed',
        status: 'failure'
      });
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }

    // Mint access token and refresh token
    const accessToken = `mcp_at_${crypto.randomBytes(32).toString('hex')}`;
    const refreshToken = `mcp_rt_${crypto.randomBytes(32).toString('hex')}`;
    const accessExpiresIn = parseInt(process.env.ACCESS_TOKEN_EXPIRY_SECONDS, 10) || 3600;
    const refreshExpiresIn = parseInt(process.env.REFRESH_TOKEN_EXPIRY_SECONDS, 10) || 2592000;

    await saveMcpTokens({
      accessToken,
      refreshToken,
      userSub: codeRecord.userSub,
      clientId: codeRecord.clientId,
      scope: codeRecord.scope,
      accessExpiresInMs: accessExpiresIn * 1000,
      refreshExpiresInMs: refreshExpiresIn * 1000
    });

    auditLog({
      userSub: codeRecord.userSub,
      action: 'auth.mcp_tokens_issued',
      status: 'success',
      details: { grantType }
    });

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: accessExpiresIn,
      refresh_token: refreshToken,
      scope: codeRecord.scope
    });
  } else if (grantType === 'refresh_token') {
    const { refresh_token } = req.body;
    if (!refresh_token) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Missing refresh_token' });
    }

    const tokenRecord = await getMcpToken(refresh_token);
    if (!tokenRecord || tokenRecord.type !== 'refresh') {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired refresh token' });
    }

    // Rotate refresh token and issue new access token
    await revokeMcpToken(refresh_token);
    const newAccessToken = `mcp_at_${crypto.randomBytes(32).toString('hex')}`;
    const newRefreshToken = `mcp_rt_${crypto.randomBytes(32).toString('hex')}`;
    const accessExpiresIn = parseInt(process.env.ACCESS_TOKEN_EXPIRY_SECONDS, 10) || 3600;
    const refreshExpiresIn = parseInt(process.env.REFRESH_TOKEN_EXPIRY_SECONDS, 10) || 2592000;

    await saveMcpTokens({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      userSub: tokenRecord.userSub,
      clientId: tokenRecord.clientId,
      scope: tokenRecord.scope,
      accessExpiresInMs: accessExpiresIn * 1000,
      refreshExpiresInMs: refreshExpiresIn * 1000
    });

    auditLog({
      userSub: tokenRecord.userSub,
      action: 'auth.mcp_tokens_refreshed',
      status: 'success'
    });

    return res.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: accessExpiresIn,
      refresh_token: newRefreshToken,
      scope: tokenRecord.scope
    });
  }

  return res.status(400).json({ error: 'unsupported_grant_type', error_description: `Unsupported grant_type "${grantType}"` });
}

// -------------------------------------------------------------
// Authentication Middleware (for MCP endpoints & user routes)
// -------------------------------------------------------------

/**
 * Express middleware to validate MCP access token and resolve currentUserSub.
 */
export async function requireMcpAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({
      error: 'unauthorized',
      message: 'Missing or invalid Bearer authorization header'
    });
  }

  const token = authHeader.slice(7).trim();
  const tokenRecord = await getMcpToken(token);

  if (!tokenRecord || tokenRecord.type !== 'access') {
    return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({
      error: 'unauthorized',
      message: 'Invalid or expired access token'
    });
  }

  // Attach verified user subject to request context
  req.userSub = tokenRecord.userSub;
  req.authContext = tokenRecord;
  next();
}
