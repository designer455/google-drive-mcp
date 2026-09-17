/**
 * MCP Tools Definition and Dispatcher
 * Implements 23 isolated tools (Read, Write, Sheets, Slides, Permissions).
 * Injects currentUserSub from trusted MCP authentication context.
 */

import { z } from 'zod';
import { Readable } from 'node:stream';
import {
  getDriveClient,
  getDocsClient,
  getSheetsClient,
  getSlidesClient
} from './google.js';
import { getPublicOrigin } from './oauth.js';
import { createGoogleLinkToken } from './google-oauth.js';
import { auditLog } from './audit.js';

// Maximum upload/read content size (10 MB)
const MAX_CONTENT_BYTES = 10 * 1024 * 1024;

/**
 * Helper to convert stream to string with size limit.
 */
async function streamToString(stream, maxBytes = MAX_CONTENT_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;

    stream.on('data', chunk => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.length;
      if (totalBytes > maxBytes) {
        stream.destroy();
        const err = new Error(`Content exceeds maximum allowed size of ${maxBytes} bytes.`);
        err.code = 'PAYLOAD_TOO_LARGE';
        return reject(err);
      }
      chunks.push(buf);
    });

    stream.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });

    stream.on('error', err => reject(err));
  });
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
    description: 'Search for files in Google Drive matching a query string.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      query: z.string().describe("Drive search query (e.g., \"name contains 'quarterly' and trashed = false\")"),
      pageSize: z.number().int().min(1).max(100).optional().default(20),
      pageToken: z.string().optional(),
      orderBy: z.string().optional().default('modifiedTime desc')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const res = await drive.files.list({
        q: args.query,
        pageSize: args.pageSize,
        pageToken: args.pageToken,
        orderBy: args.orderBy,
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
        nextPageToken: res.data.nextPageToken || null
      });
    }
  },
  {
    name: 'drive_list_folder',
    description: 'List items inside a specific Google Drive folder.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      folderId: z.string().optional().default('root').describe("Folder ID (use 'root' for My Drive root)"),
      pageSize: z.number().int().min(1).max(100).optional().default(50),
      pageToken: z.string().optional()
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const query = `'${args.folderId}' in parents and trashed = false`;
      const res = await drive.files.list({
        q: query,
        pageSize: args.pageSize,
        pageToken: args.pageToken,
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
      let content;

      if (mimeType === 'application/vnd.google-apps.document') {
        const targetMime = args.exportMimeType || 'text/plain';
        const res = await drive.files.export(
          { fileId: args.fileId, mimeType: targetMime },
          { responseType: 'stream' }
        );
        content = await streamToString(res.data);
      } else if (mimeType === 'application/vnd.google-apps.spreadsheet') {
        const targetMime = args.exportMimeType || 'text/csv';
        const res = await drive.files.export(
          { fileId: args.fileId, mimeType: targetMime },
          { responseType: 'stream' }
        );
        content = await streamToString(res.data);
      } else if (mimeType === 'application/vnd.google-apps.presentation') {
        const targetMime = args.exportMimeType || 'text/plain';
        const res = await drive.files.export(
          { fileId: args.fileId, mimeType: targetMime },
          { responseType: 'stream' }
        );
        content = await streamToString(res.data);
      } else {
        const res = await drive.files.get(
          { fileId: args.fileId, alt: 'media', supportsAllDrives: true },
          { responseType: 'stream' }
        );
        content = await streamToString(res.data);
      }

      auditLog({
        userSub: context.userSub,
        action: 'drive.read_file',
        resourceId: args.fileId,
        status: 'success'
      });

      return formatSuccess({
        fileId: args.fileId,
        name: meta.data.name,
        mimeType: meta.data.mimeType,
        content
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

  // ------------------------- WRITE TOOLS -------------------------
  {
    name: 'drive_create_file',
    description: 'Create a new text or data file in Google Drive.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      name: z.string().min(1).describe('Name of the new file'),
      mimeType: z.string().optional().default('text/plain').describe('MIME type (e.g. text/plain, application/json, text/csv)'),
      content: z.string().optional().default('').describe('Initial text content of the file'),
      parentFolderId: z.string().optional().describe('Optional parent folder ID')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const fileMetadata = {
        name: args.name,
        mimeType: args.mimeType,
        ...(args.parentFolderId ? { parents: [args.parentFolderId] } : {})
      };

      const media = {
        mimeType: args.mimeType,
        body: Readable.from([args.content || ''])
      };

      const res = await drive.files.create({
        requestBody: fileMetadata,
        media,
        fields: 'id, name, mimeType, size, createdTime, webViewLink',
        supportsAllDrives: true
      });

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
      const media = {
        mimeType: args.mimeType || 'text/plain',
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

  // ------------------------- GOOGLE SHEETS -------------------------
  {
    name: 'drive_sheet_create',
    description: 'Create a new Google Spreadsheet.',
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      title: z.string().min(1).describe('Title of the spreadsheet'),
      sheetTitles: z.array(z.string()).optional().describe('Optional list of initial sheet tab titles')
    }),
    handler: async (args, context) => {
      const sheets = await getSheetsClient(context.userSub);
      const resource = {
        properties: { title: args.title },
        sheets: args.sheetTitles?.map(title => ({
          properties: { title }
        }))
      };

      const res = await sheets.spreadsheets.create({
        requestBody: resource,
        fields: 'spreadsheetId, properties/title, sheets/properties(sheetId, title)'
      });

      auditLog({
        userSub: context.userSub,
        action: 'sheets.create',
        resourceId: res.data.spreadsheetId,
        resourceType: 'spreadsheet',
        status: 'success'
      });

      return formatSuccess({
        success: true,
        spreadsheet: res.data
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
    description: 'List sharing permissions for a file or folder.',
    readOnlyHint: true,
    openWorldHint: false,
    destructiveHint: false,
    schema: z.object({
      fileId: z.string().min(1).describe('The ID of the file or folder')
    }),
    handler: async (args, context) => {
      const drive = await getDriveClient(context.userSub);
      const res = await drive.permissions.list({
        fileId: args.fileId,
        fields: 'permissions(id, type, role, emailAddress, displayName)',
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
        permissions: res.data.permissions || []
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
    return await tool.handler(validatedArgs, { userSub });
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
