/**
 * Multi-User Google OAuth Flow Module
 * Handles per-user Google account linking, state validation, callback, status, and disconnect.
 */

import crypto from 'node:crypto';
import { google } from 'googleapis';
import {
  saveGoogleOAuthState,
  consumeGoogleOAuthState,
  saveGoogleLinkToken,
  consumeGoogleLinkToken,
  createSignedGoogleLinkToken,
  createSignedGoogleOAuthState,
  getUserGoogleRecord,
  setUserGoogleTokens,
  deleteUserGoogleRecord,
  getMcpToken
} from './user-store.js';
import { getPublicOrigin } from './oauth.js';
import { auditLog } from './audit.js';

export function getGoogleOAuthClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || 'https://mcp.example.com/oauth2callback';

  return new google.auth.OAuth2(clientId, clientSecret, redirectUri);
}

export function getGoogleScopes() {
  const customScopes = process.env.GOOGLE_DRIVE_SCOPES;
  const defaultScopes = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/documents'
  ];

  const scopes = customScopes
    ? customScopes.split(',').map(s => s.trim()).filter(Boolean)
    : defaultScopes;

  // Always include identity scopes to fetch account email and name for status
  const requiredIdentity = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
  ];

  for (const s of requiredIdentity) {
    if (!scopes.includes(s)) {
      scopes.push(s);
    }
  }

  return scopes;
}

/**
 * Resolve userSub from Authorization: Bearer header for direct API calls.
 * Note: Query parameters (?token=) are strictly NOT accepted to protect credentials.
 */
async function resolveUserSubFromRequest(req) {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  }

  if (!token) {
    return null;
  }

  const record = await getMcpToken(token);
  if (!record || record.type !== 'access') {
    return null;
  }

  return record.userSub;
}

/**
 * Create a secure, short-lived, one-time link token for an authenticated MCP user.
 * Returns the browser-safe connection URL without exposing bearer tokens or userSub.
 * Stateless HMAC signing ensures validation succeeds across any Vercel container.
 *
 * @param {string} userSub - Authenticated MCP user ID
 * @returns {Promise<string>} Browser-safe link URL
 */
export async function createGoogleLinkToken(userSub) {
  if (!userSub || typeof userSub !== 'string' || userSub === 'anonymous') {
    throw new Error('Valid authenticated userSub is required to create a Google link token');
  }

  const expirySecs = parseInt(process.env.OAUTH_GOOGLE_LINK_EXPIRY_SECONDS, 10) || 600;
  const linkToken = createSignedGoogleLinkToken(userSub, expirySecs * 1000);

  // Also save to disk for backward compatibility / local test suites
  try {
    await saveGoogleLinkToken(linkToken, userSub, expirySecs * 1000);
  } catch {}

  const origin = getPublicOrigin();
  return `${origin}/auth/google/link?code=${encodeURIComponent(linkToken)}`;
}

/**
 * GET /auth/google/link - Single-use browser endpoint to initiate Google OAuth.
 * Consumes the one-time link token, recovers the bound userSub, creates Google OAuth state,
 * and redirects to Google's consent screen.
 */
export async function handleGoogleLink(req, res) {
  const code = req.query?.code;
  if (!code || typeof code !== 'string') {
    return res.status(400).send('Missing or invalid link code parameter.');
  }

  let userSub;
  try {
    // Atomically consume link token and retrieve bound userSub
    userSub = await consumeGoogleLinkToken(code.trim());
  } catch (err) {
    auditLog({
      action: 'auth.google_link_rejected',
      status: 'failure',
      details: { error: err.message, code: err.code }
    });
    return res.status(400).send(`Google connection link invalid or expired: ${escapeHtml(err.message)}`);
  }

  // Generate cryptographically signed Google OAuth state (stateless across Vercel containers)
  const stateExpiryMs = (parseInt(process.env.OAUTH_STATE_EXPIRY_SECONDS, 10) || 600) * 1000;
  const state = createSignedGoogleOAuthState(userSub, stateExpiryMs);

  // Also save to local store if available
  try {
    await saveGoogleOAuthState(state, userSub, stateExpiryMs);
  } catch {}

  const oauth2Client = getGoogleOAuthClient();
  const scopes = getGoogleScopes();

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: scopes,
    state
  });

  auditLog({
    userSub,
    action: 'auth.google_link_consumed',
    status: 'success'
  });

  return res.redirect(authUrl);
}

/**
 * GET /auth/google - Direct endpoint to initiate Google OAuth via Bearer header.
 * If unauthenticated, returns 401 advising the user to use the one-time link from ChatGPT.
 */
export async function handleGoogleAuthInitiate(req, res) {
  const userSub = await resolveUserSubFromRequest(req);
  if (!userSub) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Valid MCP authentication required to link Google account. Please use the one-time connection link generated by your ChatGPT MCP session, or supply an Authorization: Bearer header.'
    });
  }

  // Generate cryptographically signed state (stateless across Vercel containers)
  const stateExpiryMs = (parseInt(process.env.OAUTH_STATE_EXPIRY_SECONDS, 10) || 600) * 1000;
  const state = createSignedGoogleOAuthState(userSub, stateExpiryMs);

  // Also save to local store if available
  try {
    await saveGoogleOAuthState(state, userSub, stateExpiryMs);
  } catch {}

  const oauth2Client = getGoogleOAuthClient();
  const scopes = getGoogleScopes();

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent', // Ensure refresh token is issued and user can choose account
    scope: scopes,
    state
  });

  auditLog({
    userSub,
    action: 'auth.google_initiate',
    status: 'success'
  });

  return res.redirect(authUrl);
}

/**
 * GET /oauth2callback - Google OAuth callback handler.
 */
export async function handleGoogleOAuthCallback(req, res) {
  const { code, state, error: googleError } = req.query;

  if (googleError) {
    auditLog({
      action: 'auth.google_callback_error',
      status: 'failure',
      details: { error: googleError }
    });
    return res.status(400).send(`Google authorization failed: ${escapeHtml(googleError)}`);
  }

  if (!code || !state) {
    return res.status(400).send('Missing code or state parameter.');
  }

  let userSub;
  try {
    // Atomically consume state and retrieve bound userSub
    userSub = await consumeGoogleOAuthState(state);
  } catch (err) {
    auditLog({
      action: 'auth.google_state_rejected',
      status: 'failure',
      details: { error: err.message, code: err.code }
    });
    return res.status(400).send(`OAuth state verification failed: ${escapeHtml(err.message)} (${escapeHtml(err.code || 'UNKNOWN')})`);
  }

  try {
    const oauth2Client = getGoogleOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Fetch user profile info for account display
    let accountInfo = { email: null, displayName: null };
    try {
      const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
      const userInfo = await oauth2.userinfo.get();
      accountInfo = {
        email: userInfo.data.email || null,
        displayName: userInfo.data.name || null
      };
    } catch {
      // Fall back if userinfo read fails
    }

    // Persist tokens securely under the user's opaque subject
    await setUserGoogleTokens(userSub, tokens, accountInfo);

    // Log permanent refresh token for single-user deployment
    if (tokens.refresh_token) {
      console.log('\n======================================================');
      console.log('⚡ [Google Drive MCP] SINGLE-USER REFRESH TOKEN (Optional):');
      console.log(`GOOGLE_REFRESH_TOKEN=${tokens.refresh_token}`);
      console.log('For Single-User Mode Only: Set SINGLE_USER_MODE=true and GOOGLE_REFRESH_TOKEN');
      console.log('in Vercel Project Settings if this server is for your private personal use only.');
      console.log('For Multi-User Mode: Each user connects their own account (no shared token).');
      console.log('======================================================\n');
    }

    auditLog({
      userSub,
      action: 'auth.google_connect',
      status: 'success',
      details: { email: accountInfo.email }
    });

    // Render clean success page with copyable Vercel token instructions
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Google Drive Connected</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; }
    .card { background: #1e293b; border-radius: 12px; padding: 32px; max-width: 480px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; text-align: center; }
    .icon { font-size: 48px; margin-bottom: 16px; }
    h1 { font-size: 22px; margin-top: 0; margin-bottom: 8px; color: #34d399; }
    p { font-size: 14px; color: #94a3b8; line-height: 1.5; margin-bottom: 20px; }
    .user-info { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 20px; font-size: 13px; color: #cbd5e1; }
    .token-box { background: #090d16; border: 1px solid #3b82f6; border-radius: 8px; padding: 14px; text-align: left; margin-bottom: 20px; }
    .token-title { font-size: 12px; font-weight: 700; color: #60a5fa; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }
    .token-desc { font-size: 11px; color: #94a3b8; line-height: 1.4; margin-bottom: 10px; }
    .code-block { background: #020617; padding: 10px; border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; word-break: break-all; color: #38bdf8; border: 1px solid #1e293b; user-select: all; cursor: text; }
    .copy-btn { margin-top: 8px; font-size: 11px; padding: 5px 10px; background: #2563eb; color: #ffffff; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; }
    .copy-btn:hover { background: #1d4ed8; }
    .footer { font-size: 12px; color: #64748b; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>Google Drive Connected!</h1>
    <p>Your Google account has been successfully linked to your ChatGPT MCP session.</p>
    
    <div class="user-info">
      <div>Connected Account: <strong>${escapeHtml(accountInfo.email || 'Google Account')}</strong></div>
      ${accountInfo.displayName ? `<div style="margin-top:4px;color:#94a3b8;">${escapeHtml(accountInfo.displayName)}</div>` : ''}
    </div>

    ${tokens.refresh_token ? `
    <div class="token-box">
      <div class="token-title">⚡ Single-User Mode Only (Optional)</div>
      <div class="token-desc">
        If this server is exclusively for your private, single-user use, you can set <code>SINGLE_USER_MODE=true</code> and:
      </div>
      <div class="code-block" id="tokenCode">GOOGLE_REFRESH_TOKEN=${escapeHtml(tokens.refresh_token)}</div>
      <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('tokenCode').innerText); this.innerText='Copied!'; setTimeout(()=>this.innerText='Copy Token', 2000)">Copy Token</button>
      <div style="font-size: 10px; color: #64748b; margin-top: 6px;">For multi-user mode: do NOT set this in Vercel. Each user connects their own isolated Google account.</div>
    </div>
    ` : ''}

    <p style="color:#e2e8f0;font-weight:500;">You can now close this tab and return to ChatGPT.</p>
    <div class="footer">Google Drive MCP</div>
  </div>
</body>
</html>`);
  } catch (err) {
    auditLog({
      userSub,
      action: 'auth.google_connect',
      status: 'failure',
      details: { error: err.message }
    });
    return res.status(500).send(`Failed to complete Google authentication: ${escapeHtml(err.message)}`);
  }
}

/**
 * GET /auth/google/status - Check connection status of current MCP user.
 */
export async function handleGoogleAuthStatus(req, res) {
  const userSub = req.userSub;
  const userRecord = await getUserGoogleRecord(userSub);

  if (!userRecord || !userRecord.google || (!userRecord.google.access_token && !userRecord.google.refresh_token)) {
    return res.json({ connected: false });
  }

  // Split configured scopes for reporting
  const scopes = userRecord.google.scope
    ? userRecord.google.scope.split(' ')
    : getGoogleScopes();

  return res.json({
    connected: true,
    googleAccount: {
      email: userRecord.account?.email || null,
      displayName: userRecord.account?.displayName || null
    },
    scopes
  });
}

/**
 * POST /auth/google/disconnect - Disconnect Google account for current MCP user only.
 */
export async function handleGoogleAuthDisconnect(req, res) {
  const userSub = req.userSub;
  const userRecord = await getUserGoogleRecord(userSub);

  if (!userRecord) {
    return res.json({ success: true, message: 'Account was not connected' });
  }

  // Attempt token revocation with Google if access_token or refresh_token is available
  const tokenToRevoke = userRecord.google?.refresh_token || userRecord.google?.access_token;
  if (tokenToRevoke) {
    try {
      const oauth2Client = getGoogleOAuthClient();
      await oauth2Client.revokeToken(tokenToRevoke);
    } catch (err) {
      // Continue even if revocation request fails (e.g. token already expired)
      auditLog({
        userSub,
        action: 'auth.google_revoke_warning',
        status: 'failure',
        details: { error: err.message }
      });
    }
  }

  // Delete credentials from persistent store
  await deleteUserGoogleRecord(userSub);

  auditLog({
    userSub,
    action: 'auth.google_disconnect',
    status: 'success'
  });

  return res.json({
    success: true,
    message: 'Google Drive account disconnected successfully'
  });
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
