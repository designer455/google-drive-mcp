/**
 * MCP Tools Definition and Dispatcher
 * Implements 23 isolated tools (Read, Write, Sheets, Slides, Permissions).
 * Injects currentUserSub from trusted MCP authentication context.
 */

import { z } from 'zod';
import path from 'node:path';
import { Readable } from 'node:stream';
import {
  getDriveClient,
  getDocsClient,
  getSheetsClient,
  getSlidesClient,
  isInvalidGrantError,
  executeWithRetry
} from './google.js';
import { getPublicOrigin } from './oauth.js';
import { createGoogleLinkToken } from './google-oauth.js';
import { deleteUserGoogleRecord } from './user-store.js';
import { auditLog } from './audit.js';

// Maximum upload/read content size (10 MB)
export const MAX_CONTENT_BYTES = 10 * 1024 * 1024;

/**
 * Helper to determine whether content should be treated as text or binary.
 * Avoids simplistic assumptions, handles Google Workspace exports and common formats,
 * and safely falls back to filename extension or binary defaults.
 *
 * @param {string} [mimeType] - The MIME type string (e.g. 'application/json; charset=utf-8')
 * @param {string} [filename] - The optional filename (e.g. 'notes.md')
 * @returns {boolean} - true if text-compatible, false if binary
 */
export function isTextMimeType(mimeType, filename) {
  const cleanMime = (mimeType || '').split(';')[0].trim().toLowerCase();

  // 1. Explicit known binary types - NEVER treat as text
  const explicitBinaryMimes = new Set([
    'application/pdf',
    'application/zip',
    'application/gzip',
    'application/x-tar',
    'application/x-bzip2',
    'application/x-7z-compressed',
    'application/x-rar-compressed',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // docx
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // xlsx
    'application/vnd.openxmlformats-officedocument.presentationml.presentation', // pptx
    'application/msword',
    'application/vnd.ms-excel',
    'application/vnd.ms-powerpoint',
    'application/epub+zip',
    'application/vnd.oasis.opendocument.text',
    'application/vnd.oasis.opendocument.spreadsheet',
    'application/vnd.oasis.opendocument.presentation'
  ]);

  if (explicitBinaryMimes.has(cleanMime)) {
    return false;
  }

  // Binary media types (except SVG)
  if (
    (cleanMime.startsWith('image/') && cleanMime !== 'image/svg+xml') ||
    cleanMime.startsWith('audio/') ||
    cleanMime.startsWith('video/')
  ) {
    return false;
  }

  // 2. Explicit known text types
  if (cleanMime.startsWith('text/')) {
    return true;
  }

  const explicitTextMimes = new Set([
    'application/json',
    'application/ld+json',
    'application/xml',
    'application/javascript',
    'application/ecmascript',
    'application/x-javascript',
    'application/typescript',
    'application/x-typescript',
    'application/sql',
    'application/graphql',
    'application/yaml',
    'application/x-yaml',
    'application/toml',
    'application/x-sh',
    'application/x-bash',
    'application/x-csh',
    'application/x-zsh',
    'application/x-httpd-php',
    'application/x-latex',
    'application/x-tex',
    'application/postscript',
    'image/svg+xml'
  ]);

  if (explicitTextMimes.has(cleanMime)) {
    return true;
  }

  // 3. Structured text suffixes per RFC 6838 (e.g. +json, +xml, +yaml)
  if (
    cleanMime.endsWith('+json') ||
    cleanMime.endsWith('+xml') ||
    cleanMime.endsWith('+yaml') ||
    cleanMime.endsWith('+yml')
  ) {
    return true;
  }

  // 4. Filename extension fallback for ambiguous or generic MIME types (e.g. application/octet-stream or missing)
  if (filename && typeof filename === 'string') {
    const ext = path.extname(filename).toLowerCase();
    const textExtensions = new Set([
      '.txt', '.csv', '.tsv', '.tab', '.json', '.jsonl', '.ndjson',
      '.md', '.markdown', '.mdown', '.html', '.htm', '.css', '.scss', '.sass', '.less',
      '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
      '.xml', '.svg', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg',
      '.sh', '.bash', '.zsh', '.fish', '.bat', '.ps1',
      '.sql', '.py', '.rb', '.java', '.c', '.cpp', '.cc', '.h', '.hpp',
      '.cs', '.go', '.rs', '.php', '.env', '.log', '.diff', '.patch',
      '.properties', '.rst', '.tex', '.proto'
    ]);

    const binaryExtensions = new Set([
      '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.tiff', '.tif',
      '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z', '.rar',
      '.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt',
      '.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a',
      '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.webm',
      '.exe', '.bin', '.dll', '.so', '.dylib', '.dmg', '.iso'
    ]);

    if (textExtensions.has(ext)) {
      return true;
    }
    if (binaryExtensions.has(ext)) {
      return false;
    }
  }

  // Default safely to false (binary Base64) to prevent any silent corruption of unknown formats
  return false;
}

/**
 * Determine if a MIME type represents a native Google Workspace document/item (DRV-03).
 */
export function isGoogleWorkspaceMimeType(mimeType) {
  return typeof mimeType === 'string' && mimeType.startsWith('application/vnd.google-apps.');
}

/**
 * Guidance message directing users toward dedicated Workspace operations when direct update is blocked.
 */
export function getWorkspaceToolGuidance(mimeType) {
  switch (mimeType) {
    case 'application/vnd.google-apps.spreadsheet':
      return "Direct content overwrite is not supported for native Google Spreadsheets. Use dedicated Google Sheets tools instead: 'drive_sheet_update_range' or 'drive_sheet_append_rows'.";
    case 'application/vnd.google-apps.presentation':
      return "Direct content overwrite is not supported for native Google Slides presentations. Use dedicated Google Slides tools instead: 'drive_slides_update'.";
    case 'application/vnd.google-apps.document':
      return "Direct content overwrite is not supported for native Google Docs. Use dedicated Google Docs tools instead: 'drive_doc_append' (to append text) or 'drive_doc_update' / 'drive_docs_batch_update' (for structural insertions and formatting). To create a new doc with content, use 'drive_doc_create' with 'content'.";
    case 'application/vnd.google-apps.folder':
      return "Cannot update content of a Google Drive folder. Use 'drive_create_folder' or 'drive_move_file' instead.";
    default:
      return `Direct content overwrite is not supported for native Google Workspace items (${mimeType}). Please use the appropriate dedicated Workspace tool or export format.`;
  }
}

/**
 * Helper to read stream with hard memory bound and MIME-aware encoding (DRV-02).
 * Ensures upstream stream destruction on limit violation, independent per-request memory,
 * and immediate buffer release on overflow.
 */
export async function readStreamBounded(stream, maxBytes = MAX_CONTENT_BYTES, isBinary = false) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let totalBytes = 0;
    let settled = false;

    function cleanup() {
      chunks = null;
    }

    stream.on('data', chunk => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.length;

      if (totalBytes > maxBytes) {
        settled = true;
        cleanup();
        if (typeof stream.destroy === 'function') {
          stream.destroy();
        }
        const err = new Error(`Content exceeds maximum allowed size of ${maxBytes} bytes.`);
        err.code = 'PAYLOAD_TOO_LARGE';
        return reject(err);
      }
      chunks.push(buf);
    });

    stream.on('end', () => {
      if (settled) return;
      settled = true;
      try {
        const fullBuffer = Buffer.concat(chunks || []);
        cleanup();
        if (isBinary) {
          resolve({
            content: fullBuffer.toString('base64'),
            size: totalBytes,
            encoding: 'base64'
          });
        } else {
          resolve({
            content: fullBuffer.toString('utf8'),
            size: totalBytes,
            encoding: 'utf8'
          });
        }
      } catch (err) {
        cleanup();
        reject(err);
      }
    });

    stream.on('error', err => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    });
  });
}

/**
 * Backwards-compatible helper to convert stream to string with size limit.
 */
export async function streamToString(stream, maxBytes = MAX_CONTENT_BYTES) {
  const res = await readStreamBounded(stream, maxBytes, false);
  return res.content;
}

/**
 * Safely escape string values for Google Drive API q parameters.
 * Escapes backslashes and single quotes.
 */
export function escapeDriveQueryValue(val) {
  if (typeof val !== 'string') return '';
  return val.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

/**
 * Validate and format ISO date for Google Drive API queries.
 */
export function formatDriveQueryDate(dateInput) {
  if (!dateInput) return null;
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) {
    const err = new Error(`Invalid date format: "${dateInput}". Expected valid ISO-8601 date string (e.g. YYYY-MM-DD or YYYY-MM-DDTHH:mm:ssZ).`);
    err.code = 'INVALID_DATE_FORMAT';
    throw err;
  }
  return d.toISOString();
}

/**
 * Supported export MIME types per Google Workspace native document type.
 */
export const SUPPORTED_WORKSPACE_EXPORTS = {
  'application/vnd.google-apps.document': {
    default: 'text/plain',
    supported: new Set([
      'text/plain',
      'text/html',
      'text/markdown',
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // DOCX
      'application/rtf',
      'application/epub+zip',
      'application/vnd.oasis.opendocument.text' // ODT
    ])
  },
  'application/vnd.google-apps.spreadsheet': {
    default: 'text/csv',
    supported: new Set([
      'text/csv',
      'text/tab-separated-values',
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // XLSX
      'application/vnd.oasis.opendocument.spreadsheet', // ODS
      'application/zip'
    ])
  },
  'application/vnd.google-apps.presentation': {
    default: 'text/plain',
    supported: new Set([
      'text/plain',
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation', // PPTX
      'application/vnd.oasis.opendocument.presentation' // ODP
    ])
  },
  'application/vnd.google-apps.drawing': {
    default: 'image/png',
    supported: new Set([
      'image/svg+xml',
      'image/png',
      'image/jpeg',
      'application/pdf'
    ])
  }
};

/**
 * Validate requested export MIME type for Google Workspace documents.
 */
export function validateWorkspaceExportMime(sourceMime, requestedMime) {
  const config = SUPPORTED_WORKSPACE_EXPORTS[sourceMime];
  if (!config) {
    return requestedMime || 'application/pdf';
  }
  if (!requestedMime) {
    return config.default;
  }
  const cleanRequested = requestedMime.split(';')[0].trim().toLowerCase();
  if (!config.supported.has(cleanRequested)) {
    const supportedList = Array.from(config.supported).join(', ');
    const err = new Error(`Unsupported export MIME type "${requestedMime}" for "${sourceMime}". Supported formats: ${supportedList}`);
    err.code = 'UNSUPPORTED_EXPORT_FORMAT';
    throw err;
  }
  return cleanRequested;
}

/**
 * Build safe Google Drive search query from structured arguments.
 */
export function buildDriveSearchQuery(args) {
  const clauses = [];

  // Exact filename
  if (args.name) {
    clauses.push(`name = '${escapeDriveQueryValue(args.name)}'`);
  }

  // Filename contains
  if (args.name_contains) {
    clauses.push(`name contains '${escapeDriveQueryValue(args.name_contains)}'`);
  }

  // MIME type
  if (args.mime_type) {
    clauses.push(`mimeType = '${escapeDriveQueryValue(args.mime_type)}'`);
  }

  // Owner email
  if (args.owner_email) {
    clauses.push(`'${escapeDriveQueryValue(args.owner_email)}' in owners`);
  }

  // Modified date
  if (args.modified_after) {
    clauses.push(`modifiedTime > '${formatDriveQueryDate(args.modified_after)}'`);
  }
  if (args.modified_before) {
    clauses.push(`modifiedTime < '${formatDriveQueryDate(args.modified_before)}'`);
  }

  // Created date
  if (args.created_after) {
    clauses.push(`createdTime > '${formatDriveQueryDate(args.created_after)}'`);
  }
  if (args.created_before) {
    clauses.push(`createdTime < '${formatDriveQueryDate(args.created_before)}'`);
  }

  // Parent folder
  if (args.parent_id) {
    clauses.push(`'${escapeDriveQueryValue(args.parent_id)}' in parents`);
  }

  // Full-text content
  if (args.full_text) {
    clauses.push(`fullText contains '${escapeDriveQueryValue(args.full_text)}'`);
  }

  // Trashed state
  if (args.trashed !== undefined) {
    clauses.push(`trashed = ${Boolean(args.trashed)}`);
  } else if (!args.query || !args.query.includes('trashed')) {
    // Default to excluding trashed files unless user explicitly asks or included in query
    clauses.push('trashed = false');
  }

  // Combine with raw query if supplied
  if (args.query && typeof args.query === 'string' && args.query.trim()) {
    if (clauses.length > 0) {
      return `(${args.query.trim()}) and ${clauses.join(' and ')}`;
    }
    return args.query.trim();
  }

  return clauses.length > 0 ? clauses.join(' and ') : 'trashed = false';
}

/**
 * Helper to recursively extract plain text from Google Docs structural body elements.
 */
export function extractDocsTextContent(doc) {
  if (!doc?.body?.content) return '';
  let text = '';
  for (const element of doc.body.content) {
    if (element.paragraph?.elements) {
      for (const elem of element.paragraph.elements) {
        if (elem.textRun?.content) {
          text += elem.textRun.content;
        }
      }
    } else if (element.table?.tableRows) {
      for (const row of element.table.tableRows) {
        for (const cell of row.tableCells || []) {
          for (const cellElem of cell.content || []) {
            if (cellElem.paragraph?.elements) {
              for (const elem of cellElem.paragraph.elements) {
                if (elem.textRun?.content) {
                  text += elem.textRun.content;
                }
              }
            }
          }
        }
      }
    }
  }
  return text;
}

/**
 * Accurately calculate the maximum segment end index of a Google Doc body.
 */
export function getDocumentEndIndex(doc) {
  const content = doc?.body?.content;
  if (!content || !Array.isArray(content) || content.length === 0) {
    return 1;
  }
  const lastElement = content[content.length - 1];
  return typeof lastElement?.endIndex === 'number' ? lastElement.endIndex : 1;
}

/**
 * Extract structured structural elements with true Google Docs API UTF-16 segment bounds.
 */
export function extractDocsSegments(doc) {
  const documentEndIndex = getDocumentEndIndex(doc);
  if (!doc?.body?.content) {
    return {
      documentEndIndex,
      validRange: { startIndex: 1, endIndex: documentEndIndex },
      segments: []
    };
  }

  const segments = [];
  for (const element of doc.body.content) {
    if (element.paragraph) {
      const p = element.paragraph;
      const headingType = p.paragraphStyle?.namedStyleType || 'NORMAL_TEXT';
      let paragraphText = '';
      const textRuns = [];

      for (const elem of p.elements || []) {
        if (elem.textRun?.content) {
          paragraphText += elem.textRun.content;
          textRuns.push({
            startIndex: elem.startIndex,
            endIndex: elem.endIndex,
            text: elem.textRun.content,
            style: elem.textRun.textStyle || {}
          });
        }
      }

      if (typeof element.startIndex === 'number' && typeof element.endIndex === 'number') {
        segments.push({
          type: 'paragraph',
          startIndex: element.startIndex,
          endIndex: element.endIndex,
          headingType,
          text: paragraphText,
          textRuns
        });
      }
    } else if (element.table) {
      segments.push({
        type: 'table',
        startIndex: element.startIndex,
        endIndex: element.endIndex,
        rows: element.table.rows,
        columns: element.table.columns
      });
    } else if (element.sectionBreak) {
      segments.push({
        type: 'sectionBreak',
        startIndex: element.startIndex,
        endIndex: element.endIndex
      });
    }
  }

  return {
    documentEndIndex,
    validRange: { startIndex: 1, endIndex: documentEndIndex },
    segments
  };
}

/**
 * Validate batchUpdate request ranges against document segment bounds before calling Google.
 * Prevents raw INVALID_ARGUMENT crashes with clear error diagnostics.
 */
export function validateDocsBatchRequests(requests, documentEndIndex) {
  if (!Array.isArray(requests)) {
    throw new Error('Requests must be an array.');
  }

  for (let i = 0; i < requests.length; i++) {
    const req = requests[i];
    if (!req || typeof req !== 'object') continue;

    const opNames = Object.keys(req);
    const opName = opNames[0] || 'unknown';
    const opPayload = req[opName];

    if (!opPayload || typeof opPayload !== 'object') continue;

    // Check range-based operations (updateTextStyle, updateParagraphStyle, deleteContentRange, etc.)
    const range = opPayload.range || opPayload.tableRange;
    if (range && (!range.segmentId || range.segmentId === '')) {
      const { startIndex, endIndex } = range;
      if (typeof startIndex === 'number' && startIndex < 1) {
        const err = new Error(
          `Google Docs batchUpdate validation failed: Request #${i + 1} (${opName}) specifies startIndex ${startIndex} < 1. Document body indexes start at 1.`
        );
        err.code = 'DOCUMENT_RANGE_OUT_OF_BOUNDS';
        err.details = {
          requestIndex: i,
          operation: opName,
          invalidRange: { startIndex, endIndex },
          validBounds: { startIndex: 1, endIndex: documentEndIndex },
          hint: 'Google Docs body indexes start at 1.'
        };
        throw err;
      }

      if (typeof endIndex === 'number' && endIndex > documentEndIndex) {
        const err = new Error(
          `Google Docs batchUpdate validation failed: Request #${i + 1} (${opName}) specifies endIndex ${endIndex}, which exceeds the document end bound ${documentEndIndex}. (Valid document bounds: [1, ${documentEndIndex}]).`
        );
        err.code = 'DOCUMENT_RANGE_OUT_OF_BOUNDS';
        err.details = {
          requestIndex: i,
          operation: opName,
          invalidRange: { startIndex, endIndex },
          validBounds: { startIndex: 1, endIndex: documentEndIndex },
          hint: 'Use drive_doc_read to obtain exact structural element indexes (startIndex/endIndex), or use drive_doc_format_text to format text by query without index calculation.'
        };
        throw err;
      }

      if (typeof startIndex === 'number' && typeof endIndex === 'number' && startIndex > endIndex) {
        const err = new Error(
          `Google Docs batchUpdate validation failed: Request #${i + 1} (${opName}) specifies startIndex ${startIndex} > endIndex ${endIndex}.`
        );
        err.code = 'DOCUMENT_RANGE_INVALID';
        err.details = {
          requestIndex: i,
          operation: opName,
          invalidRange: { startIndex, endIndex },
          validBounds: { startIndex: 1, endIndex: documentEndIndex }
        };
        throw err;
      }
    }

    // Check location-based insertion operations
    const location = opPayload.location;
    if (location && (!location.segmentId || location.segmentId === '')) {
      const idx = location.index;
      if (typeof idx === 'number') {
        if (idx < 1 || idx > documentEndIndex) {
          const err = new Error(
            `Google Docs batchUpdate validation failed: Request #${i + 1} (${opName}) specifies insertion index ${idx}, which is outside valid bounds [1, ${documentEndIndex}].`
          );
          err.code = 'DOCUMENT_LOCATION_OUT_OF_BOUNDS';
          err.details = {
            requestIndex: i,
            operation: opName,
            invalidIndex: idx,
            validBounds: { startIndex: 1, endIndex: documentEndIndex }
          };
          throw err;
        }
      }
    }
  }
}

/**
 * Convert a hex color string (e.g. #1d4ed8 or #ff0000) into Docs API RgbColor object.
 */
export function parseHexColor(hex) {
  if (!hex || typeof hex !== 'string') return null;
  let clean = hex.replace('#', '').trim();
  if (clean.length === 3) {
    clean = clean.split('').map(c => c + c).join('');
  }
  if (clean.length !== 6) return null;
  const num = parseInt(clean, 16);
  if (isNaN(num)) return null;
  return {
    red: ((num >> 16) & 255) / 255,
    green: ((num >> 8) & 255) / 255,
    blue: (num & 255) / 255
  };
}

/**
 * Format standard successful MCP tool response.
 */
function formatSuccess(data) {
  return {
    content: [
      {
        type: 'text',
        text: typeof data === 'string' ? data : JSON.stringify(data, null, 2)
      }
    ]
  };
}

/**
 * Format standard MCP tool error response.
 */
async function formatError(err, userSub) {
  let message = err.message || 'Unknown error occurred';
  let errorCode = err.code || 'INTERNAL_ERROR';

  // 1. Handle invalid_grant / revoked token (ERR-01)
  if (isInvalidGrantError(err)) {
    errorCode = 'GOOGLE_AUTH_REVOKED';
    try {
      if (userSub && userSub !== 'anonymous') {
        await deleteUserGoogleRecord(userSub);
      }
    } catch (delErr) {
      auditLog({
        userSub,
        action: 'auth.google_record_delete_error',
        status: 'failure',
        details: { error: delErr.message }
      });
    }

    if (userSub && userSub !== 'anonymous') {
      try {
        const linkUrl = await createGoogleLinkToken(userSub);
        message = `Google Drive authorization has been revoked or expired for your account.\nPlease reconnect your Google account using this one-time link:\n${linkUrl}\n\nThis link connects your personal Google account to your ChatGPT MCP session. This link expires in 10 minutes and can be used once.`;
      } catch (tokenErr) {
        message = 'Google Drive authorization has been revoked or expired. Please reconnect your Google account via the OAuth connection link.';
      }
    } else {
      message = 'Google Drive authorization has been revoked or expired and valid user context is missing.';
    }

    auditLog({
      userSub,
      action: 'auth.google_token_revoked',
      status: 'warning',
      details: { code: 'GOOGLE_AUTH_REVOKED', message: 'User Google credentials purged due to invalid_grant' }
    });

    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: `Error [${errorCode}]: ${message}`
        }
      ]
    };
  }

  // 2. Handle Google API Timeout
  if (err.code === 'TIMEOUT') {
    errorCode = 'TIMEOUT';
    message = 'Google API request timed out after 30 seconds. Please try again.';
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: `Error [${errorCode}]: ${message}`
        }
      ]
    };
  }

  // Extract detailed Google API error diagnostics if available
  const googleError = err.response?.data?.error;
  if (googleError) {
    errorCode = googleError.status || googleError.code || err.response?.status || errorCode;
    const detailsList = [];

    if (googleError.message) {
      detailsList.push(`Message: ${googleError.message}`);
    }
    if (googleError.status) {
      detailsList.push(`Status: ${googleError.status}`);
    }
    if (err.response?.status) {
      detailsList.push(`HTTP Status: ${err.response.status}`);
    }
    if (Array.isArray(googleError.errors) && googleError.errors.length > 0) {
      const reasons = googleError.errors
        .map(e => `[${e.domain || 'global'}/${e.reason || 'unknown'}]: ${e.message}`)
        .join('; ');
      detailsList.push(`Reasons: ${reasons}`);
    }
    if (googleError.details && Array.isArray(googleError.details) && googleError.details.length > 0) {
      detailsList.push(`Details: ${JSON.stringify(googleError.details)}`);
    }
    if (err.config?.url) {
      const sanitizedUrl = err.config.url.replace(/([?&](?:access_token|key|secret|code|refresh_token|client_secret)=)[^&]+/gi, '$1[REDACTED]');
      detailsList.push(`Request: ${err.config.method ? err.config.method.toUpperCase() + ' ' : ''}${sanitizedUrl}`);
    }

    if (detailsList.length > 0) {
      message = detailsList.join('\n');
    }
  } else if (Array.isArray(err.errors) && err.errors.length > 0) {
    const reasons = err.errors
      .map(e => `[${e.domain || 'global'}/${e.reason || 'unknown'}]: ${e.message}`)
      .join('; ');
    message = `${message}\nReasons: ${reasons}`;
  } else if (err.response?.data && typeof err.response.data === 'string') {
    message = `${message} - ${err.response.data}`;
  }

  if (errorCode === 'GOOGLE_NOT_CONNECTED') {
    if (userSub && userSub !== 'anonymous') {
      try {
        const linkUrl = await createGoogleLinkToken(userSub);
        message = `Google Drive is not connected for your account.\nOpen this one-time connection link to connect your Google account:\n${linkUrl}\n\nThis link connects your personal Google account to your ChatGPT MCP session. This link expires in 10 minutes and can be used once.`;
      } catch (tokenErr) {
        message = `Google Drive is not connected for your account. Failed to generate secure connection link: ${tokenErr.message}`;
      }
    } else {
      message = 'Google Drive is not connected and valid MCP user authentication context is missing.';
    }
  }

  // Sanitize message to prevent leaking stack traces, filesystem paths, tokens
  message = message.split('\n    at ')[0];
  message = message.replace(/(ya29\.[a-zA-Z0-9_\-]+)/g, '[REDACTED_TOKEN]');
  message = message.replace(/(1\/\/[a-zA-Z0-9_\-]+)/g, '[REDACTED_REFRESH_TOKEN]');
  message = message.replace(/(?:\/(?:Users|home|var|tmp|etc|usr|app)[^\s:)'"]*)/g, '[REDACTED_PATH]');

  auditLog({
    userSub,
    action: 'mcp.tool_error',
    status: 'failure',
    details: { code: errorCode, message }
  });

  return {
    isError: true,
    content: [
      {
        type: 'text',
        text: `Error [${errorCode}]: ${message}`
      }
    ]
  };
}

// -------------------------------------------------------------
// Tool Definitions & Handlers
// -------------------------------------------------------------

export const TOOLS = [
  // ------------------------- READ TOOLS -------------------------
  {
    name: 'drive_search',
    description: 'Search for files in Google Drive matching simple text query or advanced structured filters (name, MIME type, owner, modification date, created date, parent folder, full text, and trash status).',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      query: z.string().optional().describe("Optional raw Drive search query (e.g., \"name contains 'quarterly'\")"),
      name: z.string().optional().describe('Exact filename to match'),
      name_contains: z.string().optional().describe('Text that the filename must contain'),
      mime_type: z.string().optional().describe('MIME type to filter by (e.g. application/pdf, text/plain)'),
      owner_email: z.string().optional().describe('Email address of the file owner'),
      modified_after: z.string().optional().describe('ISO-8601 date string for files modified after this time'),
      modified_before: z.string().optional().describe('ISO-8601 date string for files modified before this time'),
      created_after: z.string().optional().describe('ISO-8601 date string for files created after this time'),
      created_before: z.string().optional().describe('ISO-8601 date string for files created before this time'),
      parent_id: z.string().optional().describe('Parent folder ID to search within'),
      full_text: z.string().optional().describe('Full-text content search term'),
      trashed: z.boolean().optional().describe('Whether to search trashed files (defaults to false)'),
      pageSize: z.number().int().min(1).max(1000).optional().default(20),
      page_size: z.number().int().min(1).max(1000).optional(),
      pageToken: z.string().optional(),
      page_token: z.string().optional(),
      orderBy: z.string().optional().default('modifiedTime desc'),
      order_by: z.string().optional()
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const effectiveQuery = buildDriveSearchQuery(args);
      const effectivePageSize = Math.min(Math.max(args.page_size || args.pageSize || 20, 1), 1000);
      const effectivePageToken = args.page_token || args.pageToken || undefined;
      const effectiveOrderBy = args.order_by || args.orderBy || 'modifiedTime desc';

      const res = await drive.files.list({
        q: effectiveQuery,
        pageSize: effectivePageSize,
        pageToken: effectivePageToken,
        orderBy: effectiveOrderBy,
        fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime, createdTime, parents, trashed, webViewLink)',
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.search',
        status: 'success',
        details: { count: res.data.files?.length }
      });

      return formatSuccess({
        files: res.data.files || [],
        nextPageToken: res.data.nextPageToken || null,
        totalCount: res.data.files?.length || 0
      });
    }
  },
  {
    name: 'drive_advanced_search',
    description: 'Perform advanced structured search for files in Google Drive with filters for filename, MIME type, owner, modification date, creation date, parent folder, and trash state.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      name: z.string().optional().describe('Exact filename to match'),
      name_contains: z.string().optional().describe('Text that the filename must contain'),
      mime_type: z.string().optional().describe('MIME type to filter by (e.g. application/pdf, text/plain)'),
      owner_email: z.string().optional().describe('Email address of the file owner'),
      modified_after: z.string().optional().describe('ISO-8601 date string for files modified after this time'),
      modified_before: z.string().optional().describe('ISO-8601 date string for files modified before this time'),
      created_after: z.string().optional().describe('ISO-8601 date string for files created after this time'),
      created_before: z.string().optional().describe('ISO-8601 date string for files created before this time'),
      parent_id: z.string().optional().describe('Parent folder ID to search within'),
      full_text: z.string().optional().describe('Full-text content search term'),
      trashed: z.boolean().optional().describe('Whether to search trashed files (defaults to false)'),
      query: z.string().optional().describe("Optional raw query to combine with structured filters"),
      pageSize: z.number().int().min(1).max(1000).optional().default(20),
      page_size: z.number().int().min(1).max(1000).optional(),
      pageToken: z.string().optional(),
      page_token: z.string().optional(),
      orderBy: z.string().optional().default('modifiedTime desc'),
      order_by: z.string().optional()
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const effectiveQuery = buildDriveSearchQuery(args);
      const effectivePageSize = Math.min(Math.max(args.page_size || args.pageSize || 20, 1), 1000);
      const effectivePageToken = args.page_token || args.pageToken || undefined;
      const effectiveOrderBy = args.order_by || args.orderBy || 'modifiedTime desc';

      const res = await drive.files.list({
        q: effectiveQuery,
        pageSize: effectivePageSize,
        pageToken: effectivePageToken,
        orderBy: effectiveOrderBy,
        fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime, createdTime, parents, trashed, webViewLink)',
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.advanced_search',
        status: 'success',
        details: { count: res.data.files?.length }
      });

      return formatSuccess({
        files: res.data.files || [],
        nextPageToken: res.data.nextPageToken || null,
        totalCount: res.data.files?.length || 0
      });
    }
  },
  {
    name: 'drive_list_folder',
    description: 'List items inside a specific Google Drive folder with pagination support.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      folderId: z.string().optional().default('root').describe("Folder ID (use 'root' for My Drive root)"),
      pageSize: z.number().int().min(1).max(1000).optional().default(50),
      page_size: z.number().int().min(1).max(1000).optional(),
      pageToken: z.string().optional(),
      page_token: z.string().optional()
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const effectivePageSize = Math.min(Math.max(args.page_size || args.pageSize || 50, 1), 1000);
      const effectivePageToken = args.page_token || args.pageToken || undefined;
      const query = `'${escapeDriveQueryValue(args.folderId)}' in parents and trashed = false`;
      const res = await drive.files.list({
        q: query,
        pageSize: effectivePageSize,
        pageToken: effectivePageToken,
        orderBy: 'folder, name',
        fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime, createdTime, webViewLink)',
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.list_folder',
        resourceId: args.folderId,
        resourceType: 'folder',
        status: 'success'
      });

      return formatSuccess({
        folderId: args.folderId,
        files: res.data.files || [],
        nextPageToken: res.data.nextPageToken || null
      });
    }
  },
  {
    name: 'drive_get_metadata',
    description: 'Get detailed metadata for a file or folder in Google Drive.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder'),
      fields: z.string().optional().default('id, name, mimeType, size, modifiedTime, createdTime, parents, trashed, shared, webViewLink')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const res = await drive.files.get({
        fileId: args.fileId,
        fields: args.fields,
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.get_metadata',
        resourceId: args.fileId,
        status: 'success'
      });

      return formatSuccess(res.data);
    }
  },
  {
    name: 'drive_read_file',
    description: 'Read content of a file from Google Drive (exports Google Docs, Sheets, Slides or downloads text/content).',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file to read'),
      exportMimeType: z.string().optional().describe('Optional export MIME type for Google Docs/Sheets/Slides')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const meta = await drive.files.get({
        fileId: args.fileId,
        fields: 'id, name, mimeType, size',
        supportsAllDrives: true
      });

      const mimeType = meta.data.mimeType;
      let effectiveMime = mimeType;
      let stream;

      if (mimeType === 'application/vnd.google-apps.document') {
        effectiveMime = args.exportMimeType || 'text/plain';
        const res = await drive.files.export(
          { fileId: args.fileId, mimeType: effectiveMime },
          { responseType: 'stream' }
        );
        stream = res.data;
      } else if (mimeType === 'application/vnd.google-apps.spreadsheet') {
        effectiveMime = args.exportMimeType || 'text/csv';
        const res = await drive.files.export(
          { fileId: args.fileId, mimeType: effectiveMime },
          { responseType: 'stream' }
        );
        stream = res.data;
      } else if (mimeType === 'application/vnd.google-apps.presentation') {
        effectiveMime = args.exportMimeType || 'text/plain';
        const res = await drive.files.export(
          { fileId: args.fileId, mimeType: effectiveMime },
          { responseType: 'stream' }
        );
        stream = res.data;
      } else {
        effectiveMime = meta.data.mimeType || 'application/octet-stream';
        const res = await drive.files.get(
          { fileId: args.fileId, alt: 'media', supportsAllDrives: true },
          { responseType: 'stream' }
        );
        stream = res.data;
      }

      const isText = isTextMimeType(effectiveMime, meta.data.name);
      const readResult = await readStreamBounded(stream, MAX_CONTENT_BYTES, !isText);

      auditLog({
        userSub: context.userSub,
        action: 'drive.read_file',
        resourceId: args.fileId,
        status: 'success'
      });

      return formatSuccess({
        fileId: args.fileId,
        name: meta.data.name,
        mimeType: effectiveMime,
        size: readResult.size,
        encoding: readResult.encoding,
        content: readResult.content
      });
    }
  },
  {
    name: 'drive_search_and_read',
    description: 'Search for a file matching a query and immediately return the content of the first matching file.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      query: z.string().describe("Search query to locate the file (e.g., \"name contains 'budget'\")"),
      exportMimeType: z.string().optional()
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const listRes = await drive.files.list({
        q: `${args.query} and trashed = false`,
        pageSize: 1,
        orderBy: 'modifiedTime desc',
        fields: 'files(id, name, mimeType)',
        supportsAllDrives: true,
        includeItemsFromAllDrives: true
      });

      const file = listRes.data.files?.[0];
      if (!file) {
        return formatSuccess({ found: false, message: 'No file matched the search query.' });
      }

      // Delegate reading
      const readResult = await TOOLS.find(t => t.name === 'drive_read_file').handler(
        { fileId: file.id, exportMimeType: args.exportMimeType },
        context
      );

      return readResult;
    }
  },
  {
    name: 'drive_download_file',
    description: 'Download an uploaded file or export a native Google Workspace document (Docs, Sheets, Slides) from Google Drive with MIME-safe encoding.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file to download or export'),
      exportMimeType: z.string().optional().describe('Target export MIME type for Google Workspace documents (e.g. application/pdf, text/csv, application/vnd.openxmlformats-officedocument.wordprocessingml.document)'),
      mimeType: z.string().optional().describe('Alias for exportMimeType')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const meta = await drive.files.get({
        fileId: args.fileId,
        fields: 'id, name, mimeType, size',
        supportsAllDrives: true
      });

      const sourceMime = meta.data.mimeType || 'application/octet-stream';
      const requestedExportMime = args.exportMimeType || args.mimeType;
      let effectiveMime = sourceMime;
      let stream;

      if (isGoogleWorkspaceMimeType(sourceMime)) {
        effectiveMime = validateWorkspaceExportMime(sourceMime, requestedExportMime);
        const res = await drive.files.export(
          { fileId: args.fileId, mimeType: effectiveMime },
          { responseType: 'stream' }
        );
        stream = res.data;
      } else {
        // Normal uploaded file download
        effectiveMime = sourceMime;
        const res = await drive.files.get(
          { fileId: args.fileId, alt: 'media', supportsAllDrives: true },
          { responseType: 'stream' }
        );
        stream = res.data;
      }

      const isText = isTextMimeType(effectiveMime, meta.data.name);
      const readResult = await readStreamBounded(stream, MAX_CONTENT_BYTES, !isText);

      auditLog({
        userSub: context.userSub,
        action: 'drive.download_file',
        resourceId: args.fileId,
        status: 'success'
      });

      return formatSuccess({
        fileId: args.fileId,
        name: meta.data.name,
        sourceMimeType: sourceMime,
        outputMimeType: effectiveMime,
        size: readResult.size,
        encoding: readResult.encoding,
        content: readResult.content
      });
    }
  },

  // ------------------------- WRITE TOOLS -------------------------
  {
    name: 'drive_create_file',
    description: 'Create a new text, data, or Google Workspace file in Google Drive. For native Google Docs (application/vnd.google-apps.document), initial content is automatically populated into the document.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      name: z.string().min(1).describe('Name of the new file'),
      mimeType: z.string().optional().default('text/plain').describe('MIME type (e.g. text/plain, application/json, text/csv, application/vnd.google-apps.document, application/vnd.google-apps.spreadsheet)'),
      content: z.string().optional().default('').describe('Initial text content of the file. For native Google Docs (application/vnd.google-apps.document), content is automatically populated via Docs API; for other Google Workspace types it is ignored.'),
      parentFolderId: z.string().optional().describe('Optional parent folder ID')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const isGoogleAppsType = typeof args.mimeType === 'string' && args.mimeType.startsWith('application/vnd.google-apps.');

      const fileMetadata = {
        name: args.name,
        mimeType: args.mimeType,
        ...(args.parentFolderId ? { parents: [args.parentFolderId] } : {})
      };

      const createParams = {
        requestBody: fileMetadata,
        fields: 'id,name,mimeType,size,createdTime,webViewLink',
        supportsAllDrives: true
      };

      // Only attach media payload for non-Google Workspace files; Google Workspace docs must NOT have media uploaded directly
      if (!isGoogleAppsType) {
        createParams.media = {
          mimeType: args.mimeType,
          body: Readable.from([args.content || ''])
        };
      }

      const res = await drive.files.create(createParams);

      if (args.mimeType === 'application/vnd.google-apps.document' && args.content && typeof args.content === 'string' && args.content.length > 0) {
        const docs = await getDocsClient(context.userSub);
        await docs.documents.batchUpdate({
          documentId: res.data.id,
          requestBody: {
            requests: [
              {
                insertText: {
                  location: { index: 1 },
                  text: args.content
                }
              }
            ]
          }
        });
      }

      auditLog({
        userSub: context.userSub,
        action: 'drive.create_file',
        resourceId: res.data.id,
        resourceType: 'file',
        status: 'success'
      });

      return formatSuccess({
        success: true,
        file: res.data
      });
    }
  },
  {
    name: 'drive_create_folder',
    description: 'Create a new folder in Google Drive.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      name: z.string().min(1).describe('Folder name'),
      parentFolderId: z.string().optional().describe('Optional parent folder ID')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const folderMetadata = {
        name: args.name,
        mimeType: 'application/vnd.google-apps.folder',
        ...(args.parentFolderId ? { parents: [args.parentFolderId] } : {})
      };

      const res = await drive.files.create({
        requestBody: folderMetadata,
        fields: 'id, name, mimeType, createdTime, webViewLink',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.create_folder',
        resourceId: res.data.id,
        resourceType: 'folder',
        status: 'success'
      });

      return formatSuccess({
        success: true,
        folder: res.data
      });
    }
  },
  {
    name: 'drive_update_file',
    description: 'Update/replace the content of an existing text or data file in Google Drive.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file to update'),
      content: z.string().describe('New content to replace the file with'),
      mimeType: z.string().optional().describe('Optional MIME type of the content')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);

      // Pre-flight check: retrieve target file metadata to check mimeType (DRV-03)
      const meta = await drive.files.get({
        fileId: args.fileId,
        fields: 'id, name, mimeType',
        supportsAllDrives: true
      });

      const targetMime = meta.data?.mimeType;
      if (isGoogleWorkspaceMimeType(targetMime)) {
        const err = new Error(getWorkspaceToolGuidance(targetMime));
        err.code = 'WORKSPACE_DOCUMENT_DIRECT_UPDATE_BLOCKED';
        throw err;
      }

      const media = {
        mimeType: args.mimeType || targetMime || 'text/plain',
        body: Readable.from([args.content])
      };

      const res = await drive.files.update({
        fileId: args.fileId,
        media,
        fields: 'id, name, mimeType, size, modifiedTime',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.update_file',
        resourceId: args.fileId,
        resourceType: 'file',
        status: 'success'
      });

      return formatSuccess({
        success: true,
        file: res.data
      });
    }
  },
  {
    name: 'drive_rename_file',
    description: 'Rename an existing file or folder in Google Drive.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder to rename'),
      newName: z.string().min(1).describe('The new name')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const res = await drive.files.update({
        fileId: args.fileId,
        requestBody: { name: args.newName },
        fields: 'id, name, mimeType, modifiedTime',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.rename_file',
        resourceId: args.fileId,
        status: 'success',
        details: { newName: args.newName }
      });

      return formatSuccess({
        success: true,
        file: res.data
      });
    }
  },
  {
    name: 'drive_move_file',
    description: 'Move a file or folder to a different parent folder.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file to move'),
      targetFolderId: z.string().min(1).describe('The ID of the destination folder')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const file = await drive.files.get({
        fileId: args.fileId,
        fields: 'parents',
        supportsAllDrives: true
      });

      const previousParents = (file.data.parents || []).join(',');
      const res = await drive.files.update({
        fileId: args.fileId,
        addParents: args.targetFolderId,
        removeParents: previousParents,
        fields: 'id, name, parents',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.move_file',
        resourceId: args.fileId,
        status: 'success',
        details: { targetFolderId: args.targetFolderId }
      });

      return formatSuccess({
        success: true,
        file: res.data
      });
    }
  },
  {
    name: 'drive_copy_file',
    description: 'Create a copy of an existing file in Google Drive.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file to copy'),
      newName: z.string().optional().describe('Name for the copy (optional)'),
      targetFolderId: z.string().optional().describe('Optional destination folder ID')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const requestBody = {
        ...(args.newName ? { name: args.newName } : {}),
        ...(args.targetFolderId ? { parents: [args.targetFolderId] } : {})
      };

      const res = await drive.files.copy({
        fileId: args.fileId,
        requestBody,
        fields: 'id, name, mimeType, createdTime, webViewLink',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.copy_file',
        resourceId: res.data.id,
        status: 'success',
        details: { originalFileId: args.fileId }
      });

      return formatSuccess({
        success: true,
        copiedFile: res.data
      });
    }
  },
  {
    name: 'drive_trash_file',
    description: 'Move a file or folder to the trash in Google Drive. Does NOT permanently delete.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder to trash')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const res = await drive.files.update({
        fileId: args.fileId,
        requestBody: { trashed: true },
        fields: 'id, name, trashed',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.trash_file',
        resourceId: args.fileId,
        status: 'success'
      });

      return formatSuccess({
        success: true,
        file: res.data
      });
    }
  },
  {
    name: 'drive_restore_file',
    description: 'Restore a previously trashed file or folder in Google Drive back to its active state.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the trashed file or folder to restore')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const res = await drive.files.update({
        fileId: args.fileId,
        requestBody: { trashed: false },
        fields: 'id, name, mimeType, trashed, modifiedTime',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.restore_file',
        resourceId: args.fileId,
        status: 'success'
      });

      return formatSuccess({
        success: true,
        restored: true,
        file: res.data
      });
    }
  },
  {
    name: 'drive_delete_file_permanently',
    description: 'Permanently delete a file or folder from Google Drive. WARNING: This operation is irreversible and bypasses trash. Content cannot be recovered.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder to permanently delete')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      await drive.files.delete({
        fileId: args.fileId,
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.delete_permanently',
        resourceId: args.fileId,
        status: 'success'
      });

      return formatSuccess({
        success: true,
        permanent: true,
        fileId: args.fileId,
        message: 'File permanently deleted.'
      });
    }
  },

  // ------------------------- GOOGLE DOCS -------------------------
  {
    name: 'drive_doc_create',
    description: 'Create a new native Google Doc with optional initial content and optional parent folder.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      title: z.string().min(1).describe('Title of the new Google Doc'),
      content: z.string().optional().describe('Optional initial text content to populate in the new Google Doc'),
      parentFolderId: z.string().optional().describe('Optional parent folder ID')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const res = await drive.files.create({
        requestBody: {
          name: args.title,
          mimeType: 'application/vnd.google-apps.document',
          ...(args.parentFolderId ? { parents: [args.parentFolderId] } : {})
        },
        fields: 'id, name, mimeType, webViewLink, createdTime',
        supportsAllDrives: true
      });

      const doc = res.data;

      if (args.content && typeof args.content === 'string' && args.content.length > 0) {
        const docs = await getDocsClient(context.userSub);
        await docs.documents.batchUpdate({
          documentId: doc.id,
          requestBody: {
            requests: [
              {
                insertText: {
                  location: { index: 1 },
                  text: args.content
                }
              }
            ]
          }
        });
      }

      const webViewLink = doc.webViewLink || `https://docs.google.com/document/d/${doc.id}/edit`;

      auditLog({
        userSub: context.userSub,
        action: 'docs.create',
        resourceId: doc.id,
        resourceType: 'document',
        status: 'success'
      });

      return formatSuccess({
        success: true,
        documentId: doc.id,
        title: doc.name,
        name: doc.name,
        mimeType: doc.mimeType,
        webViewLink,
        createdTime: doc.createdTime
      });
    }
  },
  {
    name: 'drive_doc_read',
    description: 'Read the structure, metadata, full text content, and structural segment index map of an existing Google Doc using the Google Docs API.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to read')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);
      const res = await docs.documents.get({
        documentId: args.documentId
      });

      const docData = res.data;
      const textContent = extractDocsTextContent(docData);
      const { documentEndIndex, validRange, segments } = extractDocsSegments(docData);
      const documentUrl = `https://docs.google.com/document/d/${docData.documentId}/edit`;

      auditLog({
        userSub: context.userSub,
        action: 'docs.read',
        resourceId: docData.documentId,
        resourceType: 'document',
        status: 'success'
      });

      return formatSuccess({
        documentId: docData.documentId,
        title: docData.title,
        documentUrl,
        documentEndIndex,
        validRange,
        segmentsCount: segments.length,
        segments,
        textContent,
        revisionId: docData.revisionId,
        body: docData.body
      });
    }
  },
  {
    name: 'drive_doc_update',
    description: 'Update an existing Google Doc using Google Docs API batchUpdate operations (insertText, replaceAllText, updateTextStyle, formatting, tables, etc.) with automatic range pre-validation.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to update'),
      requests: z.array(z.record(z.any())).min(1).describe('Array of Google Docs API batchUpdate request objects')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);

      // Pre-flight check: read document segment bounds to validate request ranges
      const docRes = await docs.documents.get({
        documentId: args.documentId,
        fields: 'documentId,title,body(content(endIndex))'
      });
      const documentEndIndex = getDocumentEndIndex(docRes.data);

      // Pre-validate all requests against document bounds
      validateDocsBatchRequests(args.requests, documentEndIndex);

      const res = await docs.documents.batchUpdate({
        documentId: args.documentId,
        requestBody: {
          requests: args.requests
        }
      });

      const documentUrl = `https://docs.google.com/document/d/${args.documentId}/edit`;

      auditLog({
        userSub: context.userSub,
        action: 'docs.update',
        resourceId: args.documentId,
        resourceType: 'document',
        status: 'success',
        details: { requestCount: args.requests.length }
      });

      return formatSuccess({
        success: true,
        documentId: args.documentId,
        documentUrl,
        replies: res.data.replies || []
      });
    }
  },
  {
    name: 'drive_docs_batch_update',
    description: 'Batch update an existing Google Doc using Google Docs API batchUpdate operations (insertText, replaceAllText, updateTextStyle, formatting, tables, etc.) with automatic range pre-validation.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to update'),
      requests: z.array(z.record(z.any())).min(1).describe('Array of Google Docs API batchUpdate request objects')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);

      // Pre-flight check: read document segment bounds to validate request ranges
      const docRes = await docs.documents.get({
        documentId: args.documentId,
        fields: 'documentId,title,body(content(endIndex))'
      });
      const documentEndIndex = getDocumentEndIndex(docRes.data);

      // Pre-validate all requests against document bounds
      validateDocsBatchRequests(args.requests, documentEndIndex);

      const res = await docs.documents.batchUpdate({
        documentId: args.documentId,
        requestBody: {
          requests: args.requests
        }
      });

      const documentUrl = `https://docs.google.com/document/d/${args.documentId}/edit`;

      auditLog({
        userSub: context.userSub,
        action: 'docs.update',
        resourceId: args.documentId,
        resourceType: 'document',
        status: 'success',
        details: { requestCount: args.requests.length }
      });

      return formatSuccess({
        success: true,
        documentId: args.documentId,
        documentUrl,
        replies: res.data.replies || []
      });
    }
  },
  {
    name: 'drive_doc_append',
    description: 'Append text to the end of an existing Google Doc.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to append text to'),
      text: z.string().min(1).describe('Text to append at the end of the document')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);
      const docRes = await docs.documents.get({
        documentId: args.documentId
      });

      const content = docRes.data.body?.content || [];
      let insertIndex = 1;
      if (content.length > 0) {
        const lastElement = content[content.length - 1];
        if (lastElement && typeof lastElement.endIndex === 'number') {
          // In Google Docs API, documents always end with a trailing newline at the final index.
          // Inserting at endIndex - 1 appends immediately before the document terminal break.
          insertIndex = Math.max(1, lastElement.endIndex - 1);
        }
      }

      const res = await docs.documents.batchUpdate({
        documentId: args.documentId,
        requestBody: {
          requests: [
            {
              insertText: {
                location: { index: insertIndex },
                text: args.text
              }
            }
          ]
        }
      });

      const documentUrl = `https://docs.google.com/document/d/${args.documentId}/edit`;

      auditLog({
        userSub: context.userSub,
        action: 'docs.append',
        resourceId: args.documentId,
        resourceType: 'document',
        status: 'success',
        details: { textLength: args.text.length, insertIndex }
      });

      return formatSuccess({
        success: true,
        documentId: args.documentId,
        documentUrl,
        insertedAtIndex: insertIndex,
        appendedLength: args.text.length,
        replies: res.data.replies || []
      });
    }
  },
  {
    name: 'drive_doc_format_text',
    description: 'Format text or headings in an existing Google Doc by matching text or heading content, or specifying a validated range, without manual index calculations.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to format'),
      textMatch: z.string().optional().describe('Exact text substring to search for and style'),
      headingMatch: z.string().optional().describe('Text of heading or paragraph to style'),
      range: z.object({
        startIndex: z.number().int().min(1).describe('Start index in document body'),
        endIndex: z.number().int().min(1).describe('End index in document body')
      }).optional().describe('Direct character range to format'),
      matchCase: z.boolean().optional().default(false).describe('Whether text matching should be case-sensitive'),
      occurrence: z.enum(['all', 'first', 'last']).optional().default('all').describe('Which occurrences to format: all, first, or last'),
      textStyle: z.object({
        bold: z.boolean().optional().describe('Bold formatting'),
        italic: z.boolean().optional().describe('Italic formatting'),
        underline: z.boolean().optional().describe('Underline formatting'),
        strikethrough: z.boolean().optional().describe('Strikethrough formatting'),
        fontSize: z.number().optional().describe('Font size in points (e.g. 12, 16, 24)'),
        foregroundColor: z.string().optional().describe('Hex color string (e.g. #1d4ed8 or #ff0000)'),
        linkUrl: z.string().optional().describe('Hyperlink URL')
      }).optional().describe('Character styling to apply'),
      paragraphStyle: z.object({
        namedStyleType: z.enum([
          'NORMAL_TEXT',
          'TITLE',
          'SUBTITLE',
          'HEADING_1',
          'HEADING_2',
          'HEADING_3',
          'HEADING_4',
          'HEADING_5',
          'HEADING_6'
        ]).optional().describe('Heading or paragraph level style'),
        alignment: z.enum(['START', 'CENTER', 'END', 'JUSTIFIED']).optional().describe('Text alignment')
      }).optional().describe('Paragraph-level style to apply')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);
      const res = await docs.documents.get({ documentId: args.documentId });
      const docData = res.data;
      const documentEndIndex = getDocumentEndIndex(docData);

      let targetRanges = [];

      if (args.range) {
        targetRanges.push(args.range);
      } else if (args.headingMatch) {
        const hMatch = args.matchCase ? args.headingMatch : args.headingMatch.toLowerCase();
        for (const element of docData.body?.content || []) {
          if (element.paragraph?.elements) {
            let pText = '';
            for (const elem of element.paragraph.elements) {
              if (elem.textRun?.content) pText += elem.textRun.content;
            }
            const compText = args.matchCase ? pText : pText.toLowerCase();
            if (compText.includes(hMatch)) {
              targetRanges.push({
                startIndex: element.startIndex,
                endIndex: element.endIndex,
                matchedText: pText.trim()
              });
            }
          }
        }
      } else if (args.textMatch) {
        const query = args.matchCase ? args.textMatch : args.textMatch.toLowerCase();
        for (const element of docData.body?.content || []) {
          if (element.paragraph?.elements) {
            for (const elem of element.paragraph.elements) {
              if (elem.textRun?.content) {
                const runContent = elem.textRun.content;
                const compContent = args.matchCase ? runContent : runContent.toLowerCase();
                let offset = 0;
                while (offset < compContent.length) {
                  const foundIdx = compContent.indexOf(query, offset);
                  if (foundIdx === -1) break;
                  const start = elem.startIndex + foundIdx;
                  const end = start + args.textMatch.length;
                  targetRanges.push({
                    startIndex: start,
                    endIndex: end,
                    matchedText: runContent.slice(foundIdx, foundIdx + args.textMatch.length)
                  });
                  offset = foundIdx + Math.max(1, query.length);
                }
              }
            }
          }
        }
      } else {
        throw new Error('At least one of textMatch, headingMatch, or range must be provided.');
      }

      if (targetRanges.length === 0) {
        return formatSuccess({
          success: true,
          documentId: args.documentId,
          message: 'No matching text or headings found to format.',
          formattedMatches: 0,
          modifiedRanges: []
        });
      }

      // Filter by occurrence
      if (args.occurrence === 'first') {
        targetRanges = [targetRanges[0]];
      } else if (args.occurrence === 'last') {
        targetRanges = [targetRanges[targetRanges.length - 1]];
      }

      const requests = [];

      // Build textStyle request
      if (args.textStyle) {
        const textFields = [];
        const styleObj = {};
        if (typeof args.textStyle.bold === 'boolean') {
          textFields.push('bold');
          styleObj.bold = args.textStyle.bold;
        }
        if (typeof args.textStyle.italic === 'boolean') {
          textFields.push('italic');
          styleObj.italic = args.textStyle.italic;
        }
        if (typeof args.textStyle.underline === 'boolean') {
          textFields.push('underline');
          styleObj.underline = args.textStyle.underline;
        }
        if (typeof args.textStyle.strikethrough === 'boolean') {
          textFields.push('strikethrough');
          styleObj.strikethrough = args.textStyle.strikethrough;
        }
        if (typeof args.textStyle.fontSize === 'number') {
          textFields.push('fontSize');
          styleObj.fontSize = { magnitude: args.textStyle.fontSize, unit: 'PT' };
        }
        if (args.textStyle.foregroundColor) {
          const rgb = parseHexColor(args.textStyle.foregroundColor);
          if (rgb) {
            textFields.push('foregroundColor');
            styleObj.foregroundColor = { color: { rgbColor: rgb } };
          }
        }
        if (args.textStyle.linkUrl) {
          textFields.push('link');
          styleObj.link = { url: args.textStyle.linkUrl };
        }

        if (textFields.length > 0) {
          for (const rng of targetRanges) {
            requests.push({
              updateTextStyle: {
                range: {
                  startIndex: rng.startIndex,
                  endIndex: rng.endIndex
                },
                textStyle: styleObj,
                fields: textFields.join(',')
              }
            });
          }
        }
      }

      // Build paragraphStyle request
      if (args.paragraphStyle) {
        const paraFields = [];
        const paraObj = {};
        if (args.paragraphStyle.namedStyleType) {
          paraFields.push('namedStyleType');
          paraObj.namedStyleType = args.paragraphStyle.namedStyleType;
        }
        if (args.paragraphStyle.alignment) {
          paraFields.push('alignment');
          paraObj.alignment = args.paragraphStyle.alignment;
        }

        if (paraFields.length > 0) {
          for (const rng of targetRanges) {
            requests.push({
              updateParagraphStyle: {
                range: {
                  startIndex: rng.startIndex,
                  endIndex: rng.endIndex
                },
                paragraphStyle: paraObj,
                fields: paraFields.join(',')
              }
            });
          }
        }
      }

      if (requests.length === 0) {
        throw new Error('No valid style attributes specified in textStyle or paragraphStyle.');
      }

      // Validate before sending
      validateDocsBatchRequests(requests, documentEndIndex);

      const updateRes = await docs.documents.batchUpdate({
        documentId: args.documentId,
        requestBody: { requests }
      });

      auditLog({
        userSub: context.userSub,
        action: 'docs.format_text',
        resourceId: args.documentId,
        resourceType: 'document',
        status: 'success',
        details: { targetCount: targetRanges.length, requestCount: requests.length }
      });

      return formatSuccess({
        success: true,
        documentId: args.documentId,
        documentUrl: `https://docs.google.com/document/d/${args.documentId}/edit`,
        formattedMatches: targetRanges.length,
        modifiedRanges: targetRanges.map(r => ({
          startIndex: r.startIndex,
          endIndex: r.endIndex,
          text: r.matchedText || undefined
        })),
        replies: updateRes.data.replies || []
      });
    }
  },
  {
    name: 'drive_doc_find_segments',
    description: 'Find exact Google Docs API structural element indexes (startIndex, endIndex) for specific text or headings in a document.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to search'),
      query: z.string().min(1).describe('Text string to search for'),
      matchCase: z.boolean().optional().default(false).describe('Whether search is case-sensitive')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);
      const res = await docs.documents.get({ documentId: args.documentId });
      const docData = res.data;
      const documentEndIndex = getDocumentEndIndex(docData);
      const q = args.matchCase ? args.query : args.query.toLowerCase();

      const matches = [];
      for (const element of docData.body?.content || []) {
        if (element.paragraph?.elements) {
          let fullParagraphText = '';
          for (const el of element.paragraph.elements) {
            if (el.textRun?.content) fullParagraphText += el.textRun.content;
          }

          for (const el of element.paragraph.elements) {
            if (el.textRun?.content) {
              const runContent = el.textRun.content;
              const comp = args.matchCase ? runContent : runContent.toLowerCase();
              let offset = 0;
              while (offset < comp.length) {
                const found = comp.indexOf(q, offset);
                if (found === -1) break;
                matches.push({
                  text: runContent.slice(found, found + args.query.length),
                  startIndex: el.startIndex + found,
                  endIndex: el.startIndex + found + args.query.length,
                  headingType: element.paragraph.paragraphStyle?.namedStyleType || 'NORMAL_TEXT',
                  paragraphSnippet: fullParagraphText.trim().slice(0, 120)
                });
                offset = found + Math.max(1, q.length);
              }
            }
          }
        }
      }

      return formatSuccess({
        documentId: args.documentId,
        title: docData.title,
        documentEndIndex,
        validRange: { startIndex: 1, endIndex: documentEndIndex },
        matchCount: matches.length,
        matches
      });
    }
  },
  {
    name: 'drive_doc_replace_text',
    description: 'Replace all occurrences of a string across an entire Google Doc using Google Docs API native atomic replaceAllText.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to update'),
      findText: z.string().min(1).describe('The text string to find'),
      replaceText: z.string().describe('The replacement text string'),
      matchCase: z.boolean().optional().default(true).describe('Whether search is case-sensitive')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);
      const res = await docs.documents.batchUpdate({
        documentId: args.documentId,
        requestBody: {
          requests: [
            {
              replaceAllText: {
                containsText: {
                  text: args.findText,
                  matchCase: args.matchCase ?? true
                },
                replaceText: args.replaceText
              }
            }
          ]
        }
      });

      const occurrencesChanged = res.data.replies?.[0]?.replaceAllText?.occurrencesChanged || 0;

      auditLog({
        userSub: context.userSub,
        action: 'docs.replace_text',
        resourceId: args.documentId,
        resourceType: 'document',
        status: 'success',
        details: { occurrencesChanged }
      });

      return formatSuccess({
        success: true,
        documentId: args.documentId,
        documentUrl: `https://docs.google.com/document/d/${args.documentId}/edit`,
        occurrencesChanged
      });
    }
  },
  {
    name: 'drive_doc_insert_table',
    description: 'Insert a table into an existing Google Doc at a specified location or end of document.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to update'),
      rows: z.number().int().min(1).max(100).describe('Number of table rows'),
      columns: z.number().int().min(1).max(20).describe('Number of table columns'),
      location: z.union([z.enum(['start', 'end']), z.number().int().min(1)]).optional().default('end').describe('Where to insert: "start", "end", or specific index (default "end")')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);
      const docRes = await docs.documents.get({
        documentId: args.documentId,
        fields: 'body(content(endIndex))'
      });
      const docEnd = getDocumentEndIndex(docRes.data);

      let insertIndex;
      if (args.location === 'start') {
        insertIndex = 1;
      } else if (typeof args.location === 'number') {
        insertIndex = Math.min(docEnd - 1, Math.max(1, args.location));
      } else {
        insertIndex = Math.max(1, docEnd - 1);
      }

      const res = await docs.documents.batchUpdate({
        documentId: args.documentId,
        requestBody: {
          requests: [
            {
              insertTable: {
                rows: args.rows,
                columns: args.columns,
                location: { index: insertIndex }
              }
            }
          ]
        }
      });

      auditLog({
        userSub: context.userSub,
        action: 'docs.insert_table',
        resourceId: args.documentId,
        resourceType: 'document',
        status: 'success',
        details: { rows: args.rows, columns: args.columns, insertIndex }
      });

      return formatSuccess({
        success: true,
        documentId: args.documentId,
        documentUrl: `https://docs.google.com/document/d/${args.documentId}/edit`,
        rows: args.rows,
        columns: args.columns,
        insertedAtIndex: insertIndex,
        replies: res.data.replies || []
      });
    }
  },
  {
    name: 'drive_doc_insert_page_break',
    description: 'Insert a page break into an existing Google Doc at a specified location or end of document.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      documentId: z.string().min(1).describe('The ID of the Google Doc to update'),
      location: z.union([z.enum(['start', 'end']), z.number().int().min(1)]).optional().default('end').describe('Where to insert: "start", "end", or specific index (default "end")')
    }),
    handler: async (args, context) => {
      const docs = await getDocsClient(context.userSub);
      const docRes = await docs.documents.get({
        documentId: args.documentId,
        fields: 'body(content(endIndex))'
      });
      const docEnd = getDocumentEndIndex(docRes.data);

      let insertIndex;
      if (args.location === 'start') {
        insertIndex = 1;
      } else if (typeof args.location === 'number') {
        insertIndex = Math.min(docEnd - 1, Math.max(1, args.location));
      } else {
        insertIndex = Math.max(1, docEnd - 1);
      }

      const res = await docs.documents.batchUpdate({
        documentId: args.documentId,
        requestBody: {
          requests: [
            {
              insertPageBreak: {
                location: { index: insertIndex }
              }
            }
          ]
        }
      });

      auditLog({
        userSub: context.userSub,
        action: 'docs.insert_page_break',
        resourceId: args.documentId,
        resourceType: 'document',
        status: 'success',
        details: { insertIndex }
      });

      return formatSuccess({
        success: true,
        documentId: args.documentId,
        documentUrl: `https://docs.google.com/document/d/${args.documentId}/edit`,
        insertedAtIndex: insertIndex,
        replies: res.data.replies || []
      });
    }
  },

  // ------------------------- GOOGLE SHEETS -------------------------
  {
    name: 'drive_sheet_create',
    description: 'Create a new Google Spreadsheet.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      title: z.string().min(1).describe('Title of the spreadsheet'),
      sheetTitles: z.array(z.string().min(1)).optional().describe('Optional list of initial sheet tab titles')
    }),
    handler: async (args, context) => {
      const sheets = await getSheetsClient(context.userSub);
      const requestBody = {
        properties: {
          title: args.title
        }
      };

      if (args.sheetTitles && args.sheetTitles.length > 0) {
        requestBody.sheets = args.sheetTitles.map(sheetTitle => ({
          properties: {
            title: sheetTitle
          }
        }));
      }

      const res = await sheets.spreadsheets.create({
        requestBody,
        fields: 'spreadsheetId,spreadsheetUrl,properties,sheets.properties'
      });

      const data = res.data;
      const spreadsheetUrl = data.spreadsheetUrl || `https://docs.google.com/spreadsheets/d/${data.spreadsheetId}/edit`;

      auditLog({
        userSub: context.userSub,
        action: 'sheets.create',
        resourceId: data.spreadsheetId,
        resourceType: 'spreadsheet',
        status: 'success'
      });

      return formatSuccess({
        success: true,
        spreadsheetId: data.spreadsheetId,
        spreadsheetUrl,
        properties: data.properties,
        sheets: data.sheets,
        spreadsheet: {
          ...data,
          spreadsheetUrl
        }
      });
    }
  },
  {
    name: 'drive_sheet_read_range',
    description: 'Read values from an A1 range in a Google Spreadsheet.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      spreadsheetId: z.string().min(1).describe('ID of the spreadsheet'),
      range: z.string().min(1).describe("A1 notation range (e.g. 'Sheet1!A1:D10' or 'A1:C')")
    }),
    handler: async (args, context) => {
      const sheets = await getSheetsClient(context.userSub);
      const res = await sheets.spreadsheets.values.get({
        spreadsheetId: args.spreadsheetId,
        range: args.range
      });

      auditLog({
        userSub: context.userSub,
        action: 'sheets.read_range',
        resourceId: args.spreadsheetId,
        status: 'success',
        details: { range: args.range }
      });

      return formatSuccess({
        range: res.data.range,
        values: res.data.values || []
      });
    }
  },
  {
    name: 'drive_sheet_update_range',
    description: 'Update values in an A1 range in a Google Spreadsheet.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      spreadsheetId: z.string().min(1).describe('ID of the spreadsheet'),
      range: z.string().min(1).describe("A1 notation range (e.g. 'Sheet1!A1:B2')"),
      values: z.array(z.array(z.any())).describe('2D array of row values'),
      valueInputOption: z.enum(['USER_ENTERED', 'RAW']).optional().default('USER_ENTERED')
    }),
    handler: async (args, context) => {
      const sheets = await getSheetsClient(context.userSub);
      const res = await sheets.spreadsheets.values.update({
        spreadsheetId: args.spreadsheetId,
        range: args.range,
        valueInputOption: args.valueInputOption,
        requestBody: { values: args.values }
      });

      auditLog({
        userSub: context.userSub,
        action: 'sheets.update_range',
        resourceId: args.spreadsheetId,
        status: 'success',
        details: { range: args.range, updatedCells: res.data.updatedCells }
      });

      return formatSuccess({
        success: true,
        updatedRange: res.data.updatedRange,
        updatedRows: res.data.updatedRows,
        updatedColumns: res.data.updatedColumns,
        updatedCells: res.data.updatedCells
      });
    }
  },
  {
    name: 'drive_sheet_append_rows',
    description: 'Append rows of values to a Google Spreadsheet table/sheet.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      spreadsheetId: z.string().min(1).describe('ID of the spreadsheet'),
      range: z.string().min(1).describe("A1 notation range or sheet name (e.g. 'Sheet1')"),
      values: z.array(z.array(z.any())).describe('2D array of row values to append'),
      valueInputOption: z.enum(['USER_ENTERED', 'RAW']).optional().default('USER_ENTERED')
    }),
    handler: async (args, context) => {
      const sheets = await getSheetsClient(context.userSub);
      const res = await sheets.spreadsheets.values.append({
        spreadsheetId: args.spreadsheetId,
        range: args.range,
        valueInputOption: args.valueInputOption,
        insertDataOption: 'INSERT_ROWS',
        requestBody: { values: args.values }
      });

      auditLog({
        userSub: context.userSub,
        action: 'sheets.append_rows',
        resourceId: args.spreadsheetId,
        status: 'success',
        details: { range: args.range }
      });

      return formatSuccess({
        success: true,
        updates: res.data.updates
      });
    }
  },

  // ------------------------- GOOGLE SLIDES -------------------------
  {
    name: 'drive_slides_create',
    description: 'Create a new Google Slides presentation.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      title: z.string().min(1).describe('Title of the presentation')
    }),
    handler: async (args, context) => {
      const slides = await getSlidesClient(context.userSub);
      const res = await slides.presentations.create({
        requestBody: { title: args.title }
      });

      auditLog({
        userSub: context.userSub,
        action: 'slides.create',
        resourceId: res.data.presentationId,
        resourceType: 'presentation',
        status: 'success'
      });

      return formatSuccess({
        success: true,
        presentationId: res.data.presentationId,
        title: res.data.title
      });
    }
  },
  {
    name: 'drive_slides_read',
    description: 'Read slides structure and metadata of a Google Slides presentation.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      presentationId: z.string().min(1).describe('ID of the presentation')
    }),
    handler: async (args, context) => {
      const slides = await getSlidesClient(context.userSub);
      const res = await slides.presentations.get({
        presentationId: args.presentationId
      });

      auditLog({
        userSub: context.userSub,
        action: 'slides.read',
        resourceId: args.presentationId,
        status: 'success'
      });

      return formatSuccess({
        presentationId: res.data.presentationId,
        title: res.data.title,
        slideCount: res.data.slides?.length || 0,
        slides: res.data.slides || []
      });
    }
  },
  {
    name: 'drive_slides_update',
    description: 'Perform batch updates on a Google Slides presentation (e.g. createSlide, insertText).',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      presentationId: z.string().min(1).describe('ID of the presentation'),
      requests: z.array(z.record(z.any())).describe('Array of Slides API batchUpdate request objects')
    }),
    handler: async (args, context) => {
      const slides = await getSlidesClient(context.userSub);
      const res = await slides.presentations.batchUpdate({
        presentationId: args.presentationId,
        requestBody: { requests: args.requests }
      });

      auditLog({
        userSub: context.userSub,
        action: 'slides.update',
        resourceId: args.presentationId,
        status: 'success',
        details: { requestCount: args.requests.length }
      });

      return formatSuccess({
        success: true,
        presentationId: res.data.presentationId,
        replies: res.data.replies
      });
    }
  },

  // ------------------------- PERMISSIONS TOOLS -------------------------
  {
    name: 'drive_list_permissions',
    description: 'List sharing permissions for a file or folder with pagination support.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder'),
      pageSize: z.number().int().min(1).max(100).optional().default(100),
      page_size: z.number().int().min(1).max(100).optional(),
      pageToken: z.string().optional(),
      page_token: z.string().optional()
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const effectivePageSize = Math.min(Math.max(args.page_size || args.pageSize || 100, 1), 100);
      const effectivePageToken = args.page_token || args.pageToken || undefined;

      const res = await drive.permissions.list({
        fileId: args.fileId,
        pageSize: effectivePageSize,
        pageToken: effectivePageToken,
        fields: 'nextPageToken, permissions(id, type, role, emailAddress, displayName)',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.list_permissions',
        resourceId: args.fileId,
        status: 'success'
      });

      return formatSuccess({
        fileId: args.fileId,
        permissions: res.data.permissions || [],
        nextPageToken: res.data.nextPageToken || null
      });
    }
  },
  {
    name: 'drive_add_permission',
    description: 'Share a file/folder with a user, group, or domain. Ownership transfer and anonymous write are strictly blocked.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder'),
      role: z.enum(['reader', 'commenter', 'writer']).describe("Role to grant: 'reader', 'commenter', or 'writer'"),
      type: z.enum(['user', 'group', 'domain']).describe("Type of recipient: 'user', 'group', or 'domain'"),
      emailAddress: z.string().optional().describe('Email address (required for user and group types)'),
      domain: z.string().optional().describe('Domain name (required for domain type)'),
      sendNotificationEmail: z.boolean().optional().default(false)
    }),
    handler: async (args, context) => {
      // SECURITY GUARD 1: Block ownership transfer
      if (args.role === 'owner') {
        const err = new Error('Ownership transfer is strictly blocked by security policy.');
        err.code = 'OWNERSHIP_TRANSFER_BLOCKED';
        throw err;
      }

      // SECURITY GUARD 2: Type validation
      if ((args.type === 'user' || args.type === 'group') && !args.emailAddress) {
        const err = new Error(`emailAddress is required when permission type is '${args.type}'`);
        err.code = 'INVALID_ARGUMENTS';
        throw err;
      }

      if (args.type === 'domain' && !args.domain) {
        const err = new Error("domain is required when permission type is 'domain'");
        err.code = 'INVALID_ARGUMENTS';
        throw err;
      }

      const drive = await getDriveClient(context.userSub);
      const requestBody = {
        role: args.role,
        type: args.type,
        ...(args.emailAddress ? { emailAddress: args.emailAddress } : {}),
        ...(args.domain ? { domain: args.domain } : {})
      };

      const res = await drive.permissions.create({
        fileId: args.fileId,
        requestBody,
        sendNotificationEmail: args.sendNotificationEmail,
        fields: 'id, type, role, emailAddress',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.add_permission',
        resourceId: args.fileId,
        status: 'success',
        details: { role: args.role, type: args.type, email: args.emailAddress }
      });

      return formatSuccess({
        success: true,
        permission: res.data
      });
    }
  },
  {
    name: 'drive_update_permission',
    description: 'Update the role of an existing permission. Ownership transfer is strictly blocked.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder'),
      permissionId: z.string().min(1).describe('The ID of the permission to update'),
      role: z.enum(['reader', 'commenter', 'writer']).describe("New role: 'reader', 'commenter', or 'writer'")
    }),
    handler: async (args, context) => {
      // SECURITY GUARD: Block ownership transfer
      if (args.role === 'owner') {
        const err = new Error('Ownership transfer is strictly blocked by security policy.');
        err.code = 'OWNERSHIP_TRANSFER_BLOCKED';
        throw err;
      }

      const drive = await getDriveClient(context.userSub);
      const res = await drive.permissions.update({
        fileId: args.fileId,
        permissionId: args.permissionId,
        requestBody: { role: args.role },
        fields: 'id, type, role, emailAddress',
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.update_permission',
        resourceId: args.fileId,
        status: 'success',
        details: { permissionId: args.permissionId, newRole: args.role }
      });

      return formatSuccess({
        success: true,
        permission: res.data
      });
    }
  },
  {
    name: 'drive_remove_permission',
    description: 'Remove a sharing permission from a file or folder.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: true,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder'),
      permissionId: z.string().min(1).describe('The ID of the permission to remove')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      await drive.permissions.delete({
        fileId: args.fileId,
        permissionId: args.permissionId,
        supportsAllDrives: true
      });

      auditLog({
        userSub: context.userSub,
        action: 'drive.remove_permission',
        resourceId: args.fileId,
        status: 'success',
        details: { permissionId: args.permissionId }
      });

      return formatSuccess({
        success: true,
        message: `Permission ${args.permissionId} removed successfully from file ${args.fileId}`
      });
    }
  }
];

/**
 * Execute an MCP tool safely by name with validated userSub.
 */
export async function executeMcpTool(toolName, args, userSub) {
  if (!userSub) {
    const err = new Error('Authentication required: missing user identity.');
    err.code = 'UNAUTHORIZED';
    return await formatError(err, 'anonymous');
  }

  const tool = TOOLS.find(t => t.name === toolName);
  if (!tool) {
    const err = new Error(`Tool "${toolName}" not found.`);
    err.code = 'TOOL_NOT_FOUND';
    return await formatError(err, userSub);
  }

  // Strictly strip any client-supplied userId to prevent injection
  const safeArgs = { ...args };
  delete safeArgs.userId;
  delete safeArgs.userSub;

  try {
    // Validate arguments with Zod schema
    const validatedArgs = tool.schema.parse(safeArgs);
    const retryOptions = {
      userSub,
      toolName,
      ...(tool.destructiveHint ? { maxAttempts: 1 } : {})
    };
    return await executeWithRetry(() => tool.handler(validatedArgs, { userSub }), retryOptions);
  } catch (err) {
    return await formatError(err, userSub);
  }
}

/**
 * Return JSON-RPC tool list metadata for tools/list.
 */
export function listMcpTools() {
  return TOOLS.map(t => {
    // Generate JSON Schema from Zod schema
    return {
      name: t.name,
      description: t.description,
      inputSchema: zodToJsonSchema(t.schema),
      readOnlyHint: t.readOnlyHint,
      openWorldHint: t.openWorldHint,
      destructiveHint: t.destructiveHint,
      annotations: {
        readOnlyHint: t.readOnlyHint,
        openWorldHint: t.openWorldHint,
        destructiveHint: t.destructiveHint
      }
    };
  });
}

/**
 * Convert Zod schema to standard JSON Schema compatible with MCP clients.
 */
function zodToJsonSchema(zodSchema) {
  if (zodSchema instanceof z.ZodObject) {
    const properties = {};
    const required = [];
    const shape = zodSchema.shape;

    for (const [key, propSchema] of Object.entries(shape)) {
      properties[key] = zodPropToJson(propSchema);
      if (!(propSchema instanceof z.ZodOptional) && !(propSchema instanceof z.ZodDefault)) {
        required.push(key);
      }
    }

    return {
      type: 'object',
      properties,
      ...(required.length > 0 ? { required } : {})
    };
  }

  return { type: 'object', properties: {} };
}

function zodPropToJson(prop) {
  if (prop instanceof z.ZodDefault) {
    return zodPropToJson(prop._def.innerType);
  }
  if (prop instanceof z.ZodOptional) {
    return zodPropToJson(prop._def.innerType);
  }
  if (prop instanceof z.ZodString) {
    return { type: 'string', description: prop.description || '' };
  }
  if (prop instanceof z.ZodNumber) {
    return { type: 'number', description: prop.description || '' };
  }
  if (prop instanceof z.ZodBoolean) {
    return { type: 'boolean', description: prop.description || '' };
  }
  if (prop instanceof z.ZodArray) {
    return {
      type: 'array',
      items: zodPropToJson(prop.element),
      description: prop.description || ''
    };
  }
  if (prop instanceof z.ZodEnum) {
    return {
      type: 'string',
      enum: prop._def.values,
      description: prop.description || ''
    };
  }
  if (prop instanceof z.ZodRecord) {
    return { type: 'object', description: prop.description || '' };
  }

  return { type: 'string', description: prop.description || '' };
}
