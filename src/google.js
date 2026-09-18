/**
 * Google API Client Factory with Absolute User Isolation
 * Instantiates per-user isolated Google API clients (Drive, Docs, Sheets, Slides).
 * Never shares credentials between users.
 */

import { google } from 'googleapis';
import { getUserGoogleRecord, setUserGoogleTokens } from './user-store.js';
import { getGoogleOAuthClient } from './google-oauth.js';
import { auditLog } from './audit.js';

// Configurable timeout & retries
export const GOOGLE_API_TIMEOUT_MS = parseInt(process.env.GOOGLE_API_TIMEOUT_MS, 10) || 30000;
export const GOOGLE_API_MAX_RETRIES = parseInt(process.env.GOOGLE_API_MAX_RETRIES, 10) || 3;

/**
 * Determine if an error is an invalid_grant / revoked token error (ERR-01).
 */
export function isInvalidGrantError(err) {
  if (!err) return false;
  const msg = (err.message || '').toLowerCase();
  const desc = (err.response?.data?.error_description || '').toLowerCase();
  const errCode = String(err.code || '').toLowerCase();
  const errData = typeof err.response?.data === 'string'
    ? err.response.data.toLowerCase()
    : String(err.response?.data?.error || '').toLowerCase();

  return (
    msg.includes('invalid_grant') ||
    desc.includes('invalid_grant') ||
    errCode === 'invalid_grant' ||
    errData.includes('invalid_grant') ||
    msg.includes('token has been expired or revoked') ||
    desc.includes('token has been expired or revoked')
  );
}

/**
 * Determine if an error is a transient Google API failure eligible for retry.
 * Only HTTP 429 and HTTP 503 are transient.
 * Permanent errors (400, 401, 403, invalid_grant, payload size) must NEVER be retried.
 */
export function isTransientGoogleError(err) {
  if (!err) return false;

  // Never retry invalid_grant or authentication errors
  if (isInvalidGrantError(err)) return false;

  const status = err.status || err.response?.status || err.code;
  const numStatus = typeof status === 'number' ? status : parseInt(status, 10);

  if (numStatus === 429 || numStatus === 503) {
    return true;
  }

  // Network layer transient errors
  const code = String(err.code || '');
  if (code === 'ECONNRESET' || code === 'ETIMEDOUT' || code === 'EAI_AGAIN') {
    return true;
  }

  return false;
}

/**
 * Promise-level timeout wrapper to guarantee Google API requests never hang indefinitely.
 */
export async function withTimeout(fn, timeoutMs = GOOGLE_API_TIMEOUT_MS) {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error(`Google API request timed out after ${timeoutMs}ms.`);
      err.code = 'TIMEOUT';
      err.status = 504;
      reject(err);
    }, timeoutMs);
    if (timer.unref) timer.unref();
  });

  try {
    const actionPromise = typeof fn === 'function' ? fn() : fn;
    if (actionPromise && typeof actionPromise.catch === 'function') {
      actionPromise.catch(() => {});
    }
    return await Promise.race([actionPromise, timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Centralized retry handler with exponential backoff for transient failures (HTTP 429 / 503).
 */
export async function executeWithRetry(fn, options = {}) {
  const maxAttempts = options.maxAttempts || GOOGLE_API_MAX_RETRIES;
  const baseDelayMs = options.baseDelayMs || (process.env.NODE_ENV === 'test' ? 10 : 250);
  const timeoutMs = options.timeoutMs || GOOGLE_API_TIMEOUT_MS;

  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await withTimeout(fn, timeoutMs);
    } catch (err) {
      lastError = err;

      // Only retry if transient and attempts remain
      if (attempt < maxAttempts && isTransientGoogleError(err)) {
        auditLog({
          userSub: options.userSub || 'system',
          action: 'google.api_transient_retry',
          status: 'warning',
          details: {
            attempt,
            maxAttempts,
            errorCode: err.status || err.response?.status || err.code,
            toolName: options.toolName || 'unknown'
          }
        });

        const delay = baseDelayMs * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }

      // Permanent error or attempts exhausted
      throw err;
    }
  }

  throw lastError;
}

let clientOverrides = null;

/**
 * For testing and mocking: override client factories.
 */
export function setGoogleClientOverrides(overrides) {
  clientOverrides = overrides;
}

/**
 * Get an authenticated OAuth2Client strictly bound to the requested userSub.
 *
 * @param {string} userSub - Internal opaque user subject
 * @returns {Promise<google.auth.OAuth2>} Configured OAuth2Client
 */
export async function getGoogleAuthClient(userSub) {
  if (clientOverrides?.getGoogleAuthClient) {
    return clientOverrides.getGoogleAuthClient(userSub);
  }

  if (!userSub) {
    const error = new Error('Authentication required: userSub is missing.');
    error.code = 'UNAUTHORIZED';
    throw error;
  }

  // 1. Load credentials for THAT user only
  const userRecord = await getUserGoogleRecord(userSub);

  if (!userRecord || !userRecord.google || !userRecord.google.access_token) {
    const error = new Error('Google Drive is not connected for this account.');
    error.code = 'GOOGLE_NOT_CONNECTED';
    throw error;
  }

  // 2. Create dedicated OAuth2 client instance
  const oauth2Client = getGoogleOAuthClient();

  // 3. Set credentials
  oauth2Client.setCredentials(userRecord.google);

  // 4. Attach token refresh listener to automatically persist refreshed tokens for THAT user only
  oauth2Client.on('tokens', async (tokens) => {
    try {
      await setUserGoogleTokens(userSub, tokens);
      auditLog({
        userSub,
        action: 'auth.google_tokens_auto_refreshed',
        status: 'success'
      });
    } catch (err) {
      auditLog({
        userSub,
        action: 'auth.google_tokens_auto_refresh_error',
        status: 'failure',
        details: { error: err.message }
      });
    }
  });

  return oauth2Client;
}

/**
 * Get Google Drive API v3 client for a user.
 */
export async function getDriveClient(userSub) {
  if (clientOverrides?.getDriveClient) {
    return clientOverrides.getDriveClient(userSub);
  }
  const auth = await getGoogleAuthClient(userSub);
  return google.drive({ version: 'v3', auth, timeout: GOOGLE_API_TIMEOUT_MS });
}

/**
 * Get Google Docs API v1 client for a user.
 */
export async function getDocsClient(userSub) {
  if (clientOverrides?.getDocsClient) {
    return clientOverrides.getDocsClient(userSub);
  }
  const auth = await getGoogleAuthClient(userSub);
  return google.docs({ version: 'v1', auth, timeout: GOOGLE_API_TIMEOUT_MS });
}

/**
 * Get Google Sheets API v4 client for a user.
 */
export async function getSheetsClient(userSub) {
  if (clientOverrides?.getSheetsClient) {
    return clientOverrides.getSheetsClient(userSub);
  }
  const auth = await getGoogleAuthClient(userSub);
  return google.sheets({ version: 'v4', auth, timeout: GOOGLE_API_TIMEOUT_MS });
}

/**
 * Get Google Slides API v1 client for a user.
 */
export async function getSlidesClient(userSub) {
  if (clientOverrides?.getSlidesClient) {
    return clientOverrides.getSlidesClient(userSub);
  }
  const auth = await getGoogleAuthClient(userSub);
  return google.slides({ version: 'v1', auth, timeout: GOOGLE_API_TIMEOUT_MS });
}
