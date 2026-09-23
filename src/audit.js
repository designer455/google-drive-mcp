/**
 * Audit Logging Module
 * Structured, safe JSON logging for google-drive-mcp.
 * Never logs tokens, authorization codes, or client secrets.
 */

const SENSITIVE_KEYS = new Set([
  'access_token',
  'refresh_token',
  'authorization_code',
  'client_secret',
  'secret',
  'password',
  'code',
  'token',
  'mcp_access_token',
  'credentials',
  'state',
  'link_token',
  'linktoken',
  'tokenhash',
  'token_hash',
  'encryption_key',
  'storage_encryption_key',
  'ciphertext',
  'key',
  'iv',
  'tag',
  'blob_read_write_token',
  'blob_token',
  'blobtoken',
  'blob_store_id',
  'blob_url',
  'bloburl',
  'oidc_token',
  'vercel_oidc_token'
]);

/**
 * Deep sanitization to ensure sensitive information is never printed to logs.
 */
export function sanitize(data) {
  if (!data || typeof data !== 'object') {
    if (typeof data === 'string') {
      if (data.startsWith('glink_') || data.includes('blob.vercel-storage.com') || data.startsWith('vercel_blob_')) {
        return '[REDACTED]';
      }
    }
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitize(item));
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(data)) {
    const lowerKey = key.toLowerCase();
    if (
      SENSITIVE_KEYS.has(lowerKey) ||
      lowerKey.includes('secret') ||
      lowerKey.includes('token') ||
      lowerKey.includes('state') ||
      lowerKey.includes('blob_url')
    ) {
      sanitized[key] = '[REDACTED]';
    } else if (
      typeof value === 'string' &&
      (value.startsWith('glink_') ||
       value.startsWith('ya29.') ||
       value.includes('blob.vercel-storage.com') ||
       value.startsWith('vercel_blob_'))
    ) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitize(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Log structured audit event.
 *
 * @param {Object} params
 * @param {string} [params.userSub] - Opaque internal user ID
 * @param {string} params.action - The action performed (e.g. drive.search, drive.update_file)
 * @param {string} [params.resourceId] - ID of file, sheet, or permission
 * @param {string} [params.resourceType] - Type of resource (e.g. file, folder, spreadsheet, permission)
 * @param {'success'|'failure'} params.status - Result status
 * @param {Object} [params.details] - Additional non-sensitive context
 */
export function auditLog({
  userSub = 'anonymous',
  action,
  resourceId = null,
  resourceType = null,
  status = 'success',
  details = null
}) {
  const event = {
    timestamp: new Date().toISOString(),
    userSub,
    action,
    resourceId,
    resourceType,
    status,
    ...(details ? { details: sanitize(details) } : {})
  };

  // Structured single-line JSON log
  const output = JSON.stringify(event);
  if (status === 'failure') {
    console.error(output);
  } else {
    console.log(output);
  }
}
