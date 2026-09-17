/**
 * Google API Client Factory with Absolute User Isolation
 * Instantiates per-user isolated Google API clients (Drive, Docs, Sheets, Slides).
 * Never shares credentials between users.
 */

import { google } from 'googleapis';
import { getUserGoogleRecord, setUserGoogleTokens } from './user-store.js';
import { getGoogleOAuthClient } from './google-oauth.js';
import { auditLog } from './audit.js';

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
  return google.drive({ version: 'v3', auth });
}

/**
 * Get Google Docs API v1 client for a user.
 */
export async function getDocsClient(userSub) {
  if (clientOverrides?.getDocsClient) {
    return clientOverrides.getDocsClient(userSub);
  }
  const auth = await getGoogleAuthClient(userSub);
  return google.docs({ version: 'v1', auth });
}

/**
 * Get Google Sheets API v4 client for a user.
 */
export async function getSheetsClient(userSub) {
  if (clientOverrides?.getSheetsClient) {
    return clientOverrides.getSheetsClient(userSub);
  }
  const auth = await getGoogleAuthClient(userSub);
  return google.sheets({ version: 'v4', auth });
}

/**
 * Get Google Slides API v1 client for a user.
 */
export async function getSlidesClient(userSub) {
  if (clientOverrides?.getSlidesClient) {
    return clientOverrides.getSlidesClient(userSub);
  }
  const auth = await getGoogleAuthClient(userSub);
  return google.slides({ version: 'v1', auth });
}
