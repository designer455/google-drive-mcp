/**
 * Test Suite: Drive Read, Write, Sheets, Slides, and Permission Tools
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import { Readable } from 'node:stream';

const testDataDir = path.resolve(process.cwd(), 'data-test-tools');
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = testDataDir;

const {
  TOOLS,
  listMcpTools,
  executeMcpTool,
  isTextMimeType,
  isGoogleWorkspaceMimeType,
  readStreamBounded,
  MAX_CONTENT_BYTES
} = await import('../src/mcp.js');
const { setUserGoogleTokens } = await import('../src/user-store.js');
import * as googleModule from '../src/google.js';

test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

test('1. Tool Registry: Verifies all 32 expected tools are registered', () => {
  const registered = listMcpTools();
  assert.equal(registered.length, 32);

  const names = registered.map(t => t.name);

  // 7 Read tools
  assert.ok(names.includes('drive_search'));
  assert.ok(names.includes('drive_advanced_search'));
  assert.ok(names.includes('drive_list_folder'));
  assert.ok(names.includes('drive_get_metadata'));
  assert.ok(names.includes('drive_read_file'));
  assert.ok(names.includes('drive_download_file'));
  assert.ok(names.includes('drive_search_and_read'));

  // 9 Write tools
  assert.ok(names.includes('drive_create_file'));
  assert.ok(names.includes('drive_create_folder'));
  assert.ok(names.includes('drive_update_file'));
  assert.ok(names.includes('drive_rename_file'));
  assert.ok(names.includes('drive_move_file'));
  assert.ok(names.includes('drive_copy_file'));
  assert.ok(names.includes('drive_trash_file'));
  assert.ok(names.includes('drive_restore_file'));
  assert.ok(names.includes('drive_delete_file_permanently'));

  // 5 Docs tools (including drive_docs_batch_update alias)
  assert.ok(names.includes('drive_doc_create'));
  assert.ok(names.includes('drive_doc_read'));
  assert.ok(names.includes('drive_doc_update'));
  assert.ok(names.includes('drive_docs_batch_update'));
  assert.ok(names.includes('drive_doc_append'));

  // 4 Sheets tools
  assert.ok(names.includes('drive_sheet_create'));
  assert.ok(names.includes('drive_sheet_read_range'));
  assert.ok(names.includes('drive_sheet_update_range'));
  assert.ok(names.includes('drive_sheet_append_rows'));

  // 3 Slides tools
  assert.ok(names.includes('drive_slides_create'));
  assert.ok(names.includes('drive_slides_read'));
  assert.ok(names.includes('drive_slides_update'));

  // 4 Permission tools
  assert.ok(names.includes('drive_list_permissions'));
  assert.ok(names.includes('drive_add_permission'));
  assert.ok(names.includes('drive_update_permission'));
  assert.ok(names.includes('drive_remove_permission'));
});

// Setup mock Google clients for functional tool testing
const mockUserSub = 'usr_mock_tool_tester';

// Mock storage
const mockDriveState = {
  files: [
    { id: 'f1', name: 'Document 1', mimeType: 'text/plain', size: '100', parents: ['root'], trashed: false },
    { id: 'folder1', name: 'Reports', mimeType: 'application/vnd.google-apps.folder', parents: ['root'], trashed: false },
    { id: 'doc1', name: 'Google Doc', mimeType: 'application/vnd.google-apps.document', parents: ['root'], trashed: false }
  ],
  permissions: {
    f1: [{ id: 'p1', role: 'reader', type: 'user', emailAddress: 'collaborator@example.com' }]
  },
  docs: {
    doc1: {
      documentId: 'doc1',
      title: 'Google Doc',
      revisionId: 'rev_1',
      body: {
        content: [
          {
            paragraph: {
              elements: [
                {
                  textRun: {
                    content: 'Initial doc content\n',
                    textStyle: {}
                  }
                }
              ]
            },
            endIndex: 20
          }
        ]
      }
    }
  },
  sheets: {
    s1: {
      title: 'Sales 2026',
      values: [['Month', 'Revenue'], ['Jan', '10000'], ['Feb', '12000']]
    }
  },
  slides: {
    p1: {
      title: 'Company Overview',
      slides: [{ slideId: 'slide_1' }]
    }
  }
};

const mockDriveClient = {
  files: {
    list: async (params) => {
      let filtered = [...mockDriveState.files];
      if (params.q) {
        if (params.q.includes('trashed = false')) {
          filtered = filtered.filter(f => !f.trashed);
        } else if (params.q.includes('trashed = true')) {
          filtered = filtered.filter(f => f.trashed);
        }
        if (params.q.includes('in parents')) {
          const match = params.q.match(/'([^']*)' in parents/);
          const folder = match ? match[1] : 'root';
          filtered = filtered.filter(f => f.parents?.includes(folder));
        }
        if (params.q.includes('name = ')) {
          const match = params.q.match(/name = '((?:\\'|[^'])*)'/);
          if (match) filtered = filtered.filter(f => f.name === match[1].replace(/\\'/g, "'"));
        }
        if (params.q.includes('name contains ')) {
          const match = params.q.match(/name contains '((?:\\'|[^'])*)'/);
          if (match) filtered = filtered.filter(f => f.name?.includes(match[1].replace(/\\'/g, "'")));
        }
        if (params.q.includes('mimeType = ')) {
          const match = params.q.match(/mimeType = '((?:\\'|[^'])*)'/);
          if (match) filtered = filtered.filter(f => f.mimeType === match[1]);
        }
        if (params.q.includes('in owners')) {
          const match = params.q.match(/'((?:\\'|[^'])*)' in owners/);
          if (match) filtered = filtered.filter(f => f.owners?.includes(match[1].replace(/\\'/g, "'")) || f.ownerEmail === match[1].replace(/\\'/g, "'"));
        }
        if (params.q.includes('fullText contains ')) {
          const match = params.q.match(/fullText contains '((?:\\'|[^'])*)'/);
          if (match) filtered = filtered.filter(f => (f.content || f.name || '').includes(match[1].replace(/\\'/g, "'")));
        }
        if (params.q.includes('modifiedTime > ')) {
          const match = params.q.match(/modifiedTime > '([^']*)'/);
          if (match) filtered = filtered.filter(f => new Date(f.modifiedTime || 0) > new Date(match[1]));
        }
        if (params.q.includes('modifiedTime < ')) {
          const match = params.q.match(/modifiedTime < '([^']*)'/);
          if (match) filtered = filtered.filter(f => new Date(f.modifiedTime || 0) < new Date(match[1]));
        }
        if (params.q.includes('createdTime > ')) {
          const match = params.q.match(/createdTime > '([^']*)'/);
          if (match) filtered = filtered.filter(f => new Date(f.createdTime || 0) > new Date(match[1]));
        }
        if (params.q.includes('createdTime < ')) {
          const match = params.q.match(/createdTime < '([^']*)'/);
          if (match) filtered = filtered.filter(f => new Date(f.createdTime || 0) < new Date(match[1]));
        }
      } else {
        filtered = filtered.filter(f => !f.trashed);
      }

      // Pagination
      const pageSize = params.pageSize || 100;
      let startIndex = 0;
      if (params.pageToken) {
        startIndex = parseInt(params.pageToken.replace('token_', ''), 10) || 0;
      }
      const pageFiles = filtered.slice(startIndex, startIndex + pageSize);
      const nextIndex = startIndex + pageSize;
      const nextPageToken = nextIndex < filtered.length ? `token_${nextIndex}` : null;

      return { data: { files: pageFiles, nextPageToken } };
    },
    get: async (params) => {
      const file = mockDriveState.files.find(f => f.id === params.fileId);
      if (!file) throw new Error('File not found: ' + params.fileId);
      if (params.alt === 'media') {
        if (file.mediaContent !== undefined) {
          return { data: Readable.from(Array.isArray(file.mediaContent) ? file.mediaContent : [file.mediaContent]) };
        }
        return { data: Readable.from(['Mock file media content']) };
      }
      return { data: { ...file } };
    },
    export: async (params) => {
      const file = mockDriveState.files.find(f => f.id === params.fileId);
      if (file && file.exportContent && file.exportContent[params.mimeType]) {
        return { data: Readable.from([file.exportContent[params.mimeType]]) };
      }
      return { data: Readable.from([`Mock exported document content (${params.mimeType})`]) };
    },
    create: async (params) => {
      mockDriveClient.lastCreateParams = params;
      // Google Drive API rejects media uploads for native Google Workspace documents
      if (params.media && params.requestBody?.mimeType?.startsWith('application/vnd.google-apps.')) {
        const err = new Error('Uploading content is not supported for Google Workspace documents.');
        err.code = 400;
        err.response = {
          status: 400,
          data: {
            error: {
              code: 400,
              message: 'Uploading content is not supported for Google Workspace documents.',
              status: 'INVALID_ARGUMENT'
            }
          }
        };
        throw err;
      }
      const fileId = `file_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
      const newFile = {
        id: fileId,
        name: params.requestBody.name,
        mimeType: params.requestBody.mimeType,
        parents: params.requestBody.parents || ['root'],
        createdTime: new Date().toISOString(),
        webViewLink: `https://docs.google.com/document/d/${fileId}/edit`
      };
      mockDriveState.files.push(newFile);
      if (params.requestBody.mimeType === 'application/vnd.google-apps.document') {
        mockDriveState.docs[newFile.id] = {
          documentId: newFile.id,
          title: newFile.name,
          revisionId: 'rev_1',
          body: {
            content: [
              {
                paragraph: {
                  elements: [
                    {
                      textRun: {
                        content: '\n',
                        textStyle: {}
                      }
                    }
                  ]
                },
                endIndex: 1
              }
            ]
          }
        };
      }
      return { data: newFile };
    },
    update: async (params) => {
      const file = mockDriveState.files.find(f => f.id === params.fileId);
      if (!file) throw new Error('File not found: ' + params.fileId);
      mockDriveClient.lastUpdateParams = params;
      if (params.media && file.mimeType?.startsWith('application/vnd.google-apps.')) {
        throw new Error('FATAL: Direct media update should have been blocked by Workspace guard before calling files.update!');
      }
      if (params.requestBody?.name) file.name = params.requestBody.name;
      if (params.requestBody?.trashed !== undefined) file.trashed = params.requestBody.trashed;
      if (params.addParents) {
        file.parents = [params.addParents];
      }
      return { data: { ...file, modifiedTime: new Date().toISOString() } };
    },
    delete: async (params) => {
      const idx = mockDriveState.files.findIndex(f => f.id === params.fileId);
      if (idx === -1) {
        const err = new Error('File not found: ' + params.fileId);
        err.code = 404;
        throw err;
      }
      mockDriveState.files.splice(idx, 1);
      return { data: {} };
    },
    copy: async (params) => {
      const orig = mockDriveState.files.find(f => f.id === params.fileId);
      const copy = {
        id: `copy_${Date.now()}`,
        name: params.requestBody?.name || `Copy of ${orig.name}`,
        mimeType: orig.mimeType,
        parents: params.requestBody?.parents || orig.parents
      };
      mockDriveState.files.push(copy);
      return { data: copy };
    }
  },
  permissions: {
    list: async (params) => {
      const allPerms = mockDriveState.permissions[params.fileId] || [];
      const pageSize = params.pageSize || 100;
      let startIndex = 0;
      if (params.pageToken) {
        startIndex = parseInt(params.pageToken.replace('ptoken_', ''), 10) || 0;
      }
      const pagePerms = allPerms.slice(startIndex, startIndex + pageSize);
      const nextIndex = startIndex + pageSize;
      const nextPageToken = nextIndex < allPerms.length ? `ptoken_${nextIndex}` : null;
      return { data: { permissions: pagePerms, nextPageToken } };
    },
    create: async (params) => {
      const perm = {
        id: `perm_${Date.now()}`,
        role: params.requestBody.role,
        type: params.requestBody.type,
        emailAddress: params.requestBody.emailAddress
      };
      if (!mockDriveState.permissions[params.fileId]) {
        mockDriveState.permissions[params.fileId] = [];
      }
      mockDriveState.permissions[params.fileId].push(perm);
      return { data: perm };
    },
    update: async (params) => {
      const perms = mockDriveState.permissions[params.fileId] || [];
      const perm = perms.find(p => p.id === params.permissionId);
      if (perm) perm.role = params.requestBody.role;
      return { data: perm };
    },
    delete: async (params) => {
      if (mockDriveState.permissions[params.fileId]) {
        mockDriveState.permissions[params.fileId] = mockDriveState.permissions[params.fileId].filter(p => p.id !== params.permissionId);
      }
      return { data: {} };
    }
  }
};

const mockSheetsClient = {
  spreadsheets: {
    create: async (params) => {
      mockSheetsClient.lastCreateParams = params;
      // Google API rejects resource if passed at top level because it gets serialized into query string
      if (params.resource !== undefined) {
        const err = new Error('Invalid JSON payload received. Unknown name "resource[properties][title]": Cannot bind query parameter.');
        err.code = 400;
        err.response = { status: 400, data: { error: { code: 400, message: 'Invalid JSON payload received. Unknown name "resource[properties][title]": Cannot bind query parameter.', status: 'INVALID_ARGUMENT' } } };
        throw err;
      }
      const requestBody = params.requestBody;
      // Fail if empty sheets array is sent or invalid field mask syntax
      if (requestBody?.sheets && requestBody.sheets.length === 0) {
        const err = new Error('Invalid empty sheets array');
        err.code = 400;
        err.response = { status: 400, data: { error: { code: 400, message: 'Invalid empty sheets array', status: 'INVALID_ARGUMENT' } } };
        throw err;
      }
      if (params.fields && params.fields.includes(', ')) {
        const err = new Error('Field mask must not contain whitespace after commas');
        err.code = 400;
        err.response = { status: 400, data: { error: { code: 400, message: 'Field mask must not contain whitespace', status: 'INVALID_ARGUMENT' } } };
        throw err;
      }

      const spreadsheetId = `sheet_${Date.now()}`;
      const title = requestBody?.properties?.title || 'Untitled';
      const initialSheets = (requestBody?.sheets || [{ properties: { sheetId: 0, title: 'Sheet1' } }]).map((s, idx) => ({
        properties: {
          sheetId: s.properties?.sheetId ?? idx,
          title: s.properties?.title || `Sheet${idx + 1}`
        }
      }));

      mockDriveState.sheets[spreadsheetId] = {
        title,
        values: []
      };

      return {
        data: {
          spreadsheetId,
          spreadsheetUrl: `https://docs.google.com/spreadsheets/d/${spreadsheetId}/edit`,
          properties: { title },
          sheets: initialSheets
        }
      };
    },
    values: {
      get: async (params) => {
        const sheet = mockDriveState.sheets[params.spreadsheetId];
        return { data: { range: params.range, values: sheet ? sheet.values : [] } };
      },
      update: async (params) => {
        const sheet = mockDriveState.sheets[params.spreadsheetId];
        if (sheet) sheet.values = params.requestBody.values;
        return { data: { updatedRange: params.range, updatedCells: params.requestBody.values.flat().length } };
      },
      append: async (params) => {
        const sheet = mockDriveState.sheets[params.spreadsheetId];
        if (sheet) sheet.values.push(...params.requestBody.values);
        return { data: { updates: { updatedRows: params.requestBody.values.length } } };
      }
    }
  }
};

const mockSlidesClient = {
  presentations: {
    create: async (params) => {
      const presentationId = `pres_${Date.now()}`;
      mockDriveState.slides[presentationId] = { title: params.requestBody.title, slides: [] };
      return { data: { presentationId, title: params.requestBody.title } };
    },
    get: async (params) => {
      const pres = mockDriveState.slides[params.presentationId];
      return { data: { presentationId: params.presentationId, title: pres?.title || '', slides: pres?.slides || [] } };
    },
    batchUpdate: async (params) => {
      return { data: { presentationId: params.presentationId, replies: [{}] } };
    }
  }
};

const mockDocsClient = {
  documents: {
    get: async (params) => {
      const doc = mockDriveState.docs[params.documentId];
      if (!doc) {
        const err = new Error(`Document not found: ${params.documentId}`);
        err.code = 404;
        err.response = { status: 404, data: { error: { code: 404, message: `Document not found: ${params.documentId}` } } };
        throw err;
      }
      return { data: JSON.parse(JSON.stringify(doc)) };
    },
    batchUpdate: async (params) => {
      const doc = mockDriveState.docs[params.documentId];
      if (!doc) {
        const err = new Error(`Document not found: ${params.documentId}`);
        err.code = 404;
        err.response = { status: 404, data: { error: { code: 404, message: `Document not found: ${params.documentId}` } } };
        throw err;
      }
      mockDocsClient.lastBatchRequests = params.requestBody?.requests || [];
      const replies = [];

      for (const req of mockDocsClient.lastBatchRequests) {
        if (req.insertText) {
          const text = req.insertText.text || '';
          doc.body.content.push({
            paragraph: {
              elements: [
                {
                  textRun: {
                    content: text,
                    textStyle: {}
                  }
                }
              ]
            },
            endIndex: (doc.body.content[doc.body.content.length - 1]?.endIndex || 1) + text.length
          });
          replies.push({ insertText: {} });
        } else if (req.replaceAllText) {
          const find = req.replaceAllText.containsText?.text;
          const replace = req.replaceAllText.replaceText || '';
          let count = 0;
          for (const elem of doc.body.content) {
            for (const pe of elem.paragraph?.elements || []) {
              if (pe.textRun?.content && find && pe.textRun.content.includes(find)) {
                pe.textRun.content = pe.textRun.content.replaceAll(find, replace);
                count++;
              }
            }
          }
          replies.push({ replaceAllText: { occurrencesChanged: count } });
        } else if (req.updateTextStyle) {
          for (const elem of doc.body.content) {
            for (const pe of elem.paragraph?.elements || []) {
              if (pe.textRun) {
                pe.textRun.textStyle = { ...pe.textRun.textStyle, ...req.updateTextStyle.textStyle };
              }
            }
          }
          replies.push({ updateTextStyle: {} });
        } else {
          replies.push({});
        }
      }

      return { data: { documentId: params.documentId, replies } };
    }
  }
};

const defaultDocsClientOverride = async (userSub) => {
  if (userSub === 'usr_unauthorized_user') {
    return {
      documents: {
        get: async () => {
          const err = new Error('The caller does not have permission');
          err.code = 403;
          throw err;
        },
        batchUpdate: async () => {
          const err = new Error('The caller does not have permission');
          err.code = 403;
          throw err;
        }
      }
    };
  }
  return mockDocsClient;
};

// Use clean override hook
const { setGoogleClientOverrides } = await import('../src/google.js');
setGoogleClientOverrides({
  getDriveClient: async (userSub) => {
    if (userSub === 'usr_unauthorized_user') {
      return {
        ...mockDriveClient,
        files: {
          ...mockDriveClient.files,
          create: async () => {
            const err = new Error('The caller does not have permission');
            err.code = 403;
            throw err;
          }
        }
      };
    }
    return mockDriveClient;
  },
  getDocsClient: defaultDocsClientOverride,
  getSheetsClient: async () => mockSheetsClient,
  getSlidesClient: async () => mockSlidesClient
});

test('2. Read Tools Execution', async () => {
  // drive_search
  const searchRes = await executeMcpTool('drive_search', { query: "name contains 'Doc'" }, mockUserSub);
  assert.equal(searchRes.isError, undefined);
  const searchData = JSON.parse(searchRes.content[0].text);
  assert.ok(searchData.files.length >= 1);

  // drive_list_folder
  const listRes = await executeMcpTool('drive_list_folder', { folderId: 'root' }, mockUserSub);
  const listData = JSON.parse(listRes.content[0].text);
  assert.ok(listData.files.length >= 1);

  // drive_get_metadata
  const metaRes = await executeMcpTool('drive_get_metadata', { fileId: 'f1' }, mockUserSub);
  const metaData = JSON.parse(metaRes.content[0].text);
  assert.equal(metaData.id, 'f1');
  assert.equal(metaData.name, 'Document 1');

  // drive_read_file (regular file)
  const readRes = await executeMcpTool('drive_read_file', { fileId: 'f1' }, mockUserSub);
  const readData = JSON.parse(readRes.content[0].text);
  assert.equal(readData.content, 'Mock file media content');

  // drive_read_file (google doc export)
  const exportRes = await executeMcpTool('drive_read_file', { fileId: 'doc1' }, mockUserSub);
  const exportData = JSON.parse(exportRes.content[0].text);
  assert.ok(exportData.content.includes('Mock exported document content'));

  // drive_search_and_read
  const snrRes = await executeMcpTool('drive_search_and_read', { query: "name contains 'Document 1'" }, mockUserSub);
  assert.ok(snrRes.content[0].text.includes('Mock file media content'));
});

test('3. Drive Write Tools Execution', async () => {
  // drive_create_file
  const createRes = await executeMcpTool('drive_create_file', { name: 'New Note.txt', content: 'Note text' }, mockUserSub);
  const createData = JSON.parse(createRes.content[0].text);
  assert.equal(createData.success, true);
  const newFileId = createData.file.id;

  // drive_create_folder
  const folderRes = await executeMcpTool('drive_create_folder', { name: 'Projects 2026' }, mockUserSub);
  const folderData = JSON.parse(folderRes.content[0].text);
  assert.equal(folderData.success, true);
  assert.equal(folderData.folder.mimeType, 'application/vnd.google-apps.folder');

  // drive_update_file
  const updateRes = await executeMcpTool('drive_update_file', { fileId: newFileId, content: 'Updated note text' }, mockUserSub);
  const updateData = JSON.parse(updateRes.content[0].text);
  assert.equal(updateData.success, true);

  // drive_rename_file
  const renameRes = await executeMcpTool('drive_rename_file', { fileId: newFileId, newName: 'Renamed Note.txt' }, mockUserSub);
  const renameData = JSON.parse(renameRes.content[0].text);
  assert.equal(renameData.file.name, 'Renamed Note.txt');

  // drive_move_file
  const moveRes = await executeMcpTool('drive_move_file', { fileId: newFileId, targetFolderId: folderData.folder.id }, mockUserSub);
  const moveData = JSON.parse(moveRes.content[0].text);
  assert.deepEqual(moveData.file.parents, [folderData.folder.id]);

  // drive_copy_file
  const copyRes = await executeMcpTool('drive_copy_file', { fileId: newFileId, newName: 'Backup of Note.txt' }, mockUserSub);
  const copyData = JSON.parse(copyRes.content[0].text);
  assert.equal(copyData.success, true);
  assert.equal(copyData.copiedFile.name, 'Backup of Note.txt');

  // drive_trash_file
  const trashRes = await executeMcpTool('drive_trash_file', { fileId: newFileId }, mockUserSub);
  const trashData = JSON.parse(trashRes.content[0].text);
  assert.equal(trashData.file.trashed, true);
});

test('4. Google Sheets Tools Execution', async () => {
  // drive_sheet_create
  const createSheet = await executeMcpTool('drive_sheet_create', { title: 'Q1 Forecast' }, mockUserSub);
  const sheetData = JSON.parse(createSheet.content[0].text);
  assert.equal(sheetData.success, true);
  const sheetId = sheetData.spreadsheet.spreadsheetId;

  // drive_sheet_update_range
  const updateRange = await executeMcpTool('drive_sheet_update_range', {
    spreadsheetId: sheetId,
    range: 'Sheet1!A1:B2',
    values: [['Header 1', 'Header 2'], ['Value 1', 'Value 2']]
  }, mockUserSub);
  const updateData = JSON.parse(updateRange.content[0].text);
  assert.equal(updateData.success, true);

  // drive_sheet_append_rows
  const appendRes = await executeMcpTool('drive_sheet_append_rows', {
    spreadsheetId: sheetId,
    range: 'Sheet1!A:B',
    values: [['Value 3', 'Value 4']]
  }, mockUserSub);
  const appendData = JSON.parse(appendRes.content[0].text);
  assert.equal(appendData.success, true);

  // drive_sheet_read_range
  const readRange = await executeMcpTool('drive_sheet_read_range', {
    spreadsheetId: sheetId,
    range: 'Sheet1!A1:B3'
  }, mockUserSub);
  const readData = JSON.parse(readRange.content[0].text);
  assert.equal(readData.values.length, 3);
});

test('5. Google Slides Tools Execution', async () => {
  // drive_slides_create
  const createPres = await executeMcpTool('drive_slides_create', { title: 'Pitch Deck' }, mockUserSub);
  const presData = JSON.parse(createPres.content[0].text);
  assert.equal(presData.success, true);
  const presId = presData.presentationId;

  // drive_slides_read
  const readPres = await executeMcpTool('drive_slides_read', { presentationId: presId }, mockUserSub);
  const readData = JSON.parse(readPres.content[0].text);
  assert.equal(readData.title, 'Pitch Deck');

  // drive_slides_update
  const updatePres = await executeMcpTool('drive_slides_update', {
    presentationId: presId,
    requests: [{ createSlide: {} }]
  }, mockUserSub);
  const updateData = JSON.parse(updatePres.content[0].text);
  assert.equal(updateData.success, true);
});

test('6. Permission Tools Execution & Security Policies', async () => {
  // drive_list_permissions
  const listPerms = await executeMcpTool('drive_list_permissions', { fileId: 'f1' }, mockUserSub);
  const listData = JSON.parse(listPerms.content[0].text);
  assert.equal(listData.permissions.length, 1);

  // drive_add_permission (valid writer)
  const addPerm = await executeMcpTool('drive_add_permission', {
    fileId: 'f1',
    role: 'writer',
    type: 'user',
    emailAddress: 'new_editor@example.com'
  }, mockUserSub);
  const addData = JSON.parse(addPerm.content[0].text);
  assert.equal(addData.success, true);
  assert.equal(addData.permission.role, 'writer');

  // drive_update_permission
  const updatePerm = await executeMcpTool('drive_update_permission', {
    fileId: 'f1',
    permissionId: addData.permission.id,
    role: 'commenter'
  }, mockUserSub);
  const updateData = JSON.parse(updatePerm.content[0].text);
  assert.equal(updateData.permission.role, 'commenter');

  // drive_remove_permission
  const removePerm = await executeMcpTool('drive_remove_permission', {
    fileId: 'f1',
    permissionId: addData.permission.id
  }, mockUserSub);
  const removeData = JSON.parse(removePerm.content[0].text);
  assert.equal(removeData.success, true);
});

test('7. Google Sheets Creation & Generic Workspace Spreadsheet Creation', async () => {
  // Case 1: drive_sheet_create({ title: "Varun" })
  const res1 = await executeMcpTool('drive_sheet_create', { title: 'Varun' }, mockUserSub);
  assert.equal(res1.isError, undefined);
  const data1 = JSON.parse(res1.content[0].text);
  assert.equal(data1.success, true);
  assert.ok(data1.spreadsheetId);
  assert.ok(data1.spreadsheetUrl);
  assert.equal(data1.properties.title, 'Varun');
  assert.equal(data1.spreadsheet.properties.title, 'Varun');

  // Verify requestBody sent to Google Sheets API
  const lastParams1 = mockSheetsClient.lastCreateParams;
  assert.equal(lastParams1.resource, undefined, 'params.resource must be strictly undefined to prevent query string serialization');
  assert.equal(lastParams1.requestBody.properties.title, 'Varun');
  assert.equal(lastParams1.requestBody.sheets, undefined, 'Must NOT send sheets array when sheetTitles is omitted');
  assert.equal(lastParams1.fields, 'spreadsheetId,spreadsheetUrl,properties,sheets.properties');

  // Case 2: drive_sheet_create({ title: "Varun Test", sheetTitles: ["Sheet1"] })
  const res2 = await executeMcpTool('drive_sheet_create', {
    title: 'Varun Test',
    sheetTitles: ['Sheet1']
  }, mockUserSub);
  assert.equal(res2.isError, undefined);
  const data2 = JSON.parse(res2.content[0].text);
  assert.equal(data2.success, true);
  assert.ok(data2.spreadsheetId);
  assert.ok(data2.spreadsheetUrl);
  assert.equal(data2.properties.title, 'Varun Test');
  assert.equal(data2.sheets[0].properties.title, 'Sheet1');

  // Verify requestBody sent to Google Sheets API
  const lastParams2 = mockSheetsClient.lastCreateParams;
  assert.equal(lastParams2.resource, undefined, 'params.resource must be strictly undefined');
  assert.equal(lastParams2.requestBody.properties.title, 'Varun Test');
  assert.deepEqual(lastParams2.requestBody.sheets, [{ properties: { title: 'Sheet1' } }]);

  // Case 3: Generic spreadsheet creation via drive_create_file with application/vnd.google-apps.spreadsheet
  const res3 = await executeMcpTool('drive_create_file', {
    name: 'Varun Generic Sheet',
    mimeType: 'application/vnd.google-apps.spreadsheet'
  }, mockUserSub);
  assert.equal(res3.isError, undefined);
  const data3 = JSON.parse(res3.content[0].text);
  assert.equal(data3.success, true);
  assert.equal(data3.file.name, 'Varun Generic Sheet');
  assert.equal(data3.file.mimeType, 'application/vnd.google-apps.spreadsheet');

  // Verify media payload was NOT attached for Google Workspace MIME type
  const lastDriveParams = mockDriveClient.lastCreateParams;
  assert.equal(lastDriveParams.media, undefined, 'media payload must NOT be passed for Google Workspace document types');
  assert.equal(lastDriveParams.fields, 'id,name,mimeType,size,createdTime,webViewLink');
});

test('8. Google API Error Diagnostics Formatting', async () => {
  // Test that rich error diagnostics from Google API response are preserved
  const originalCreate = mockSheetsClient.spreadsheets.create;
  mockSheetsClient.spreadsheets.create = async () => {
    const error = new Error('Request contains an invalid argument.');
    error.response = {
      status: 400,
      data: {
        error: {
          code: 400,
          message: 'Request contains an invalid argument.',
          status: 'INVALID_ARGUMENT',
          errors: [
            {
              message: 'Invalid field selection',
              domain: 'global',
              reason: 'badRequest'
            }
          ]
        }
      }
    };
    error.config = {
      method: 'post',
      url: 'https://sheets.googleapis.com/v4/spreadsheets?key=secret123&fields=spreadsheetId'
    };
    throw error;
  };

  try {
    const res = await executeMcpTool('drive_sheet_create', { title: 'Failing Sheet' }, mockUserSub);
    assert.equal(res.isError, true);
    const errText = res.content[0].text;
    assert.ok(errText.includes('HTTP Status: 400'), 'Includes HTTP status');
    assert.ok(errText.includes('Status: INVALID_ARGUMENT'), 'Includes Google status');
    assert.ok(errText.includes('Message: Request contains an invalid argument.'), 'Includes Google message');
    assert.ok(errText.includes('[global/badRequest]: Invalid field selection'), 'Includes Google error reason');
    assert.ok(errText.includes('POST https://sheets.googleapis.com/v4/spreadsheets?key=[REDACTED]&fields=spreadsheetId'), 'Includes sanitized request URL');
  } finally {
    mockSheetsClient.spreadsheets.create = originalCreate;
  }
});

test('9. Regression Test: googleapis v146 HTTP Serialization puts spreadsheet in BODY and NOT query string', async () => {
  const { google } = await import('googleapis');
  let capturedRequest = null;

  const realSheetsClient = google.sheets({
    version: 'v4',
    auth: {
      request: async (opts) => {
        capturedRequest = opts;
        return {
          data: {
            spreadsheetId: 'real_sheet_123',
            spreadsheetUrl: 'https://docs.google.com/spreadsheets/d/real_sheet_123/edit',
            properties: { title: opts.data?.properties?.title }
          }
        };
      }
    }
  });

  setGoogleClientOverrides({
    getDriveClient: async () => mockDriveClient,
    getDocsClient: defaultDocsClientOverride,
    getSheetsClient: async () => realSheetsClient,
    getSlidesClient: async () => mockSlidesClient
  });

  try {
    const res = await executeMcpTool('drive_sheet_create', { title: 'Varun' }, mockUserSub);
    assert.equal(res.isError, undefined);
    assert.ok(capturedRequest, 'HTTP request must be captured');

    // 1. Verify HTTP Method is POST
    assert.equal(capturedRequest.method, 'POST');

    // 2. Verify URL is exact Google Sheets endpoint
    assert.equal(capturedRequest.url, 'https://sheets.googleapis.com/v4/spreadsheets');

    // 3. Verify query params contain ONLY fields and NEVER resource[...]
    assert.deepEqual(capturedRequest.params, {
      fields: 'spreadsheetId,spreadsheetUrl,properties,sheets.properties'
    });
    assert.equal(capturedRequest.params.resource, undefined, 'params.resource must NOT be in query string');

    // 4. Verify spreadsheet properties exist strictly inside HTTP JSON request body
    assert.deepEqual(capturedRequest.data, {
      properties: {
        title: 'Varun'
      }
    });
  } finally {
    setGoogleClientOverrides({
      getDriveClient: async () => mockDriveClient,
      getDocsClient: defaultDocsClientOverride,
      getSheetsClient: async () => mockSheetsClient,
      getSlidesClient: async () => mockSlidesClient
    });
  }
});

// =========================================================================
// DRV-01: Binary-Safe Drive File Reading Tests
// =========================================================================

test('DRV-01: isTextMimeType accurately classifies text vs binary formats', () => {
  // 1. Text formats
  assert.equal(isTextMimeType('text/plain'), true);
  assert.equal(isTextMimeType('text/csv'), true);
  assert.equal(isTextMimeType('text/html; charset=utf-8'), true);
  assert.equal(isTextMimeType('text/markdown'), true);
  assert.equal(isTextMimeType('application/json'), true);
  assert.equal(isTextMimeType('application/xml'), true);
  assert.equal(isTextMimeType('application/javascript'), true);
  assert.equal(isTextMimeType('application/sql'), true);
  assert.equal(isTextMimeType('application/yaml'), true);
  assert.equal(isTextMimeType('image/svg+xml'), true);

  // 2. Structured suffixes
  assert.equal(isTextMimeType('application/problem+json'), true);
  assert.equal(isTextMimeType('application/atom+xml'), true);
  assert.equal(isTextMimeType('application/vnd.api+json'), true);

  // 3. Binary formats (NEVER treated as text)
  assert.equal(isTextMimeType('application/pdf'), false);
  assert.equal(isTextMimeType('image/png'), false);
  assert.equal(isTextMimeType('image/jpeg'), false);
  assert.equal(isTextMimeType('image/webp'), false);
  assert.equal(isTextMimeType('audio/mpeg'), false);
  assert.equal(isTextMimeType('video/mp4'), false);
  assert.equal(isTextMimeType('application/zip'), false);
  assert.equal(isTextMimeType('application/gzip'), false);
  assert.equal(isTextMimeType('application/x-tar'), false);
  assert.equal(isTextMimeType('application/vnd.openxmlformats-officedocument.wordprocessingml.document'), false);
  assert.equal(isTextMimeType('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'), false);
  assert.equal(isTextMimeType('application/vnd.openxmlformats-officedocument.presentationml.presentation'), false);
  assert.equal(isTextMimeType('application/msword'), false);
  assert.equal(isTextMimeType('application/vnd.ms-excel'), false);

  // 4. Extension fallback for application/octet-stream or missing MIME
  assert.equal(isTextMimeType('application/octet-stream', 'script.py'), true);
  assert.equal(isTextMimeType('application/octet-stream', 'styles.css'), true);
  assert.equal(isTextMimeType('application/octet-stream', 'data.csv'), true);
  assert.equal(isTextMimeType('application/octet-stream', 'archive.zip'), false);
  assert.equal(isTextMimeType('application/octet-stream', 'photo.png'), false);
  assert.equal(isTextMimeType(undefined, 'document.pdf'), false);
  assert.equal(isTextMimeType(undefined, 'report.docx'), false);
  assert.equal(isTextMimeType(undefined, 'notes.txt'), true);

  // 5. Unknown binary fallback
  assert.equal(isTextMimeType('application/unknown-binary', 'file'), false);
  assert.equal(isTextMimeType('', ''), false);
});

test('DRV-01: drive_read_file returns UTF-8 for text files and Base64 for binary files', async () => {
  // Add test files to mockDriveState
  const pdfBytes = Buffer.from('%PDF-1.4\n%âãÏÓ\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer<</Size 1>>\nstartxref\n%%EOF');
  const pngBytes = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D]);
  const zipBytes = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00]);
  const docxBytes = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x20, 0x00, 0x08, 0x00, 0x00, 0x00]);
  const xlsxBytes = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x20, 0x00, 0x08, 0x00, 0x00, 0x01]);

  mockDriveState.files.push(
    { id: 'f_pdf', name: 'manual.pdf', mimeType: 'application/pdf', size: String(pdfBytes.length), parents: ['root'], trashed: false, mediaContent: pdfBytes },
    { id: 'f_png', name: 'logo.png', mimeType: 'image/png', size: String(pngBytes.length), parents: ['root'], trashed: false, mediaContent: pngBytes },
    { id: 'f_zip', name: 'backup.zip', mimeType: 'application/zip', size: String(zipBytes.length), parents: ['root'], trashed: false, mediaContent: zipBytes },
    { id: 'f_docx', name: 'contract.docx', mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', size: String(docxBytes.length), parents: ['root'], trashed: false, mediaContent: docxBytes },
    { id: 'f_xlsx', name: 'financials.xlsx', mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', size: String(xlsxBytes.length), parents: ['root'], trashed: false, mediaContent: xlsxBytes },
    { id: 'f_txt', name: 'readme.txt', mimeType: 'text/plain', size: '18', parents: ['root'], trashed: false, mediaContent: Buffer.from('Hello text content') }
  );

  // 1. Text file read
  const txtRes = await executeMcpTool('drive_read_file', { fileId: 'f_txt' }, mockUserSub);
  const txtData = JSON.parse(txtRes.content[0].text);
  assert.equal(txtData.fileId, 'f_txt');
  assert.equal(txtData.name, 'readme.txt');
  assert.equal(txtData.mimeType, 'text/plain');
  assert.equal(txtData.encoding, 'utf8');
  assert.equal(txtData.content, 'Hello text content');
  assert.equal(txtData.size, 18);

  // 2. PDF read (must be base64, not utf8 decoded)
  const pdfRes = await executeMcpTool('drive_read_file', { fileId: 'f_pdf' }, mockUserSub);
  const pdfData = JSON.parse(pdfRes.content[0].text);
  assert.equal(pdfData.fileId, 'f_pdf');
  assert.equal(pdfData.name, 'manual.pdf');
  assert.equal(pdfData.mimeType, 'application/pdf');
  assert.equal(pdfData.encoding, 'base64');
  assert.equal(pdfData.content, pdfBytes.toString('base64'));
  assert.deepEqual(Buffer.from(pdfData.content, 'base64'), pdfBytes);

  // 3. PNG read
  const pngRes = await executeMcpTool('drive_read_file', { fileId: 'f_png' }, mockUserSub);
  const pngData = JSON.parse(pngRes.content[0].text);
  assert.equal(pngData.encoding, 'base64');
  assert.deepEqual(Buffer.from(pngData.content, 'base64'), pngBytes);

  // 4. ZIP read
  const zipRes = await executeMcpTool('drive_read_file', { fileId: 'f_zip' }, mockUserSub);
  const zipData = JSON.parse(zipRes.content[0].text);
  assert.equal(zipData.encoding, 'base64');
  assert.deepEqual(Buffer.from(zipData.content, 'base64'), zipBytes);

  // 5. DOCX read
  const docxRes = await executeMcpTool('drive_read_file', { fileId: 'f_docx' }, mockUserSub);
  const docxData = JSON.parse(docxRes.content[0].text);
  assert.equal(docxData.encoding, 'base64');
  assert.deepEqual(Buffer.from(docxData.content, 'base64'), docxBytes);

  // 6. XLSX read
  const xlsxRes = await executeMcpTool('drive_read_file', { fileId: 'f_xlsx' }, mockUserSub);
  const xlsxData = JSON.parse(xlsxRes.content[0].text);
  assert.equal(xlsxData.encoding, 'base64');
  assert.deepEqual(Buffer.from(xlsxData.content, 'base64'), xlsxBytes);

  // 7. Google Doc exported as PDF (binary export)
  const docExportPdfRes = await executeMcpTool('drive_read_file', { fileId: 'doc1', exportMimeType: 'application/pdf' }, mockUserSub);
  const docExportData = JSON.parse(docExportPdfRes.content[0].text);
  assert.equal(docExportData.mimeType, 'application/pdf');
  assert.equal(docExportData.encoding, 'base64');
});

// =========================================================================
// DRV-02: Bounded File Memory Usage Tests
// =========================================================================

test('DRV-02: readStreamBounded enforces strict limit, destroys upstream stream, and releases buffers', async () => {
  // 1. File below limit succeeds
  const underStream = Readable.from(['chunk1', 'chunk2']);
  const underResult = await readStreamBounded(underStream, 50, false);
  assert.equal(underResult.content, 'chunk1chunk2');
  assert.equal(underResult.size, 12);
  assert.equal(underResult.encoding, 'utf8');

  // 2. File exactly at limit boundary succeeds
  const exactStream = Readable.from([Buffer.alloc(50, 'a')]);
  const exactResult = await readStreamBounded(exactStream, 50, false);
  assert.equal(exactResult.size, 50);

  // 3. File exceeding limit fails, destroys stream, and returns PAYLOAD_TOO_LARGE
  let streamDestroyed = false;
  const overStream = new Readable({
    read() {
      this.push(Buffer.alloc(30, 'b'));
      this.push(Buffer.alloc(30, 'c')); // Exceeds limit of 50
    },
    destroy(err, cb) {
      streamDestroyed = true;
      cb(err);
    }
  });

  await assert.rejects(
    async () => {
      await readStreamBounded(overStream, 50, false);
    },
    (err) => {
      assert.equal(err.code, 'PAYLOAD_TOO_LARGE');
      assert.ok(err.message.includes('exceeds maximum allowed size'));
      return true;
    }
  );
  assert.equal(streamDestroyed, true, 'Upstream stream must be destroyed immediately upon limit breach');

  // 4. Verify MAX_CONTENT_BYTES constant is 10 MB
  assert.equal(MAX_CONTENT_BYTES, 10 * 1024 * 1024);
});

test('DRV-02: Concurrent reads have independently bounded memory and do not interfere', async () => {
  // Simulate 5 simultaneous reading operations with varying sizes and formats
  const jobs = [
    readStreamBounded(Readable.from(['concurrent-1']), 1000, false),
    readStreamBounded(Readable.from([Buffer.from([0x01, 0x02, 0x03])]), 1000, true),
    readStreamBounded(Readable.from(['under-limit']), 50, false),
    readStreamBounded(Readable.from([Buffer.alloc(100)]), 20, false).catch(err => err),
    readStreamBounded(Readable.from(['concurrent-2']), 1000, false)
  ];

  const results = await Promise.all(jobs);

  assert.equal(results[0].content, 'concurrent-1');
  assert.equal(results[0].encoding, 'utf8');

  assert.equal(results[1].content, Buffer.from([0x01, 0x02, 0x03]).toString('base64'));
  assert.equal(results[1].encoding, 'base64');

  assert.equal(results[2].content, 'under-limit');

  // The 4th job failed safely with PAYLOAD_TOO_LARGE without affecting jobs 0, 1, 2, or 4
  assert.equal(results[3].code, 'PAYLOAD_TOO_LARGE');

  assert.equal(results[4].content, 'concurrent-2');
});

// =========================================================================
// DRV-03: Native Google Workspace Update Guard Tests
// =========================================================================

test('DRV-03: drive_update_file pre-flight guard blocks updates to native Google Workspace files', async () => {
  // Setup files for Workspace types
  mockDriveState.files.push(
    { id: 'g_doc', name: 'Strategy', mimeType: 'application/vnd.google-apps.document', parents: ['root'], trashed: false },
    { id: 'g_sheet', name: 'Q3 Plan', mimeType: 'application/vnd.google-apps.spreadsheet', parents: ['root'], trashed: false },
    { id: 'g_slide', name: 'Pitch', mimeType: 'application/vnd.google-apps.presentation', parents: ['root'], trashed: false },
    { id: 'g_form', name: 'Feedback', mimeType: 'application/vnd.google-apps.form', parents: ['root'], trashed: false },
    { id: 'normal_txt', name: 'plain.txt', mimeType: 'text/plain', parents: ['root'], trashed: false }
  );

  // 1. Google Doc update blocked
  const docRes = await executeMcpTool('drive_update_file', { fileId: 'g_doc', content: 'new text' }, mockUserSub);
  assert.equal(docRes.isError, true);
  assert.ok(docRes.content[0].text.includes('WORKSPACE_DOCUMENT_DIRECT_UPDATE_BLOCKED'));
  assert.ok(docRes.content[0].text.includes('Google Docs'));

  // 2. Google Sheet update blocked with guidance to drive_sheet_update_range
  const sheetRes = await executeMcpTool('drive_update_file', { fileId: 'g_sheet', content: '1,2,3' }, mockUserSub);
  assert.equal(sheetRes.isError, true);
  assert.ok(sheetRes.content[0].text.includes('WORKSPACE_DOCUMENT_DIRECT_UPDATE_BLOCKED'));
  assert.ok(sheetRes.content[0].text.includes('drive_sheet_update_range'));

  // 3. Google Slide update blocked with guidance to drive_slides_update
  const slideRes = await executeMcpTool('drive_update_file', { fileId: 'g_slide', content: 'slide text' }, mockUserSub);
  assert.equal(slideRes.isError, true);
  assert.ok(slideRes.content[0].text.includes('WORKSPACE_DOCUMENT_DIRECT_UPDATE_BLOCKED'));
  assert.ok(slideRes.content[0].text.includes('drive_slides_update'));

  // 4. Google Form or other application/vnd.google-apps.* blocked
  const formRes = await executeMcpTool('drive_update_file', { fileId: 'g_form', content: 'form data' }, mockUserSub);
  assert.equal(formRes.isError, true);
  assert.ok(formRes.content[0].text.includes('WORKSPACE_DOCUMENT_DIRECT_UPDATE_BLOCKED'));

  // 5. Normal uploaded text/binary file passes through safely and updates
  const normalRes = await executeMcpTool('drive_update_file', { fileId: 'normal_txt', content: 'updated safe text' }, mockUserSub);
  assert.equal(normalRes.isError, undefined);
  const normalData = JSON.parse(normalRes.content[0].text);
  assert.equal(normalData.success, true);
  assert.equal(normalData.file.id, 'normal_txt');
});

// =========================================================================
// 1. Permanent Delete Tests (drive_delete_file_permanently)
// =========================================================================

test('CORE-01: Permanent Delete irreversibly removes file and enforces safeguards', async () => {
  // Setup file for deletion
  const targetId = 'file_to_perm_delete';
  mockDriveState.files.push({
    id: targetId,
    name: 'Obsolete Secret.txt',
    mimeType: 'text/plain',
    trashed: false,
    parents: ['root']
  });

  // 1. Successful authenticated permanent deletion
  const delRes = await executeMcpTool('drive_delete_file_permanently', { fileId: targetId }, mockUserSub);
  assert.equal(delRes.isError, undefined);
  const delData = JSON.parse(delRes.content[0].text);
  assert.equal(delData.success, true);
  assert.equal(delData.permanent, true);
  assert.equal(delData.fileId, targetId);

  // 2. Verify file is completely removed from storage and NOT merely trashed
  const fileInStorage = mockDriveState.files.find(f => f.id === targetId);
  assert.equal(fileInStorage, undefined, 'File must be purged from storage, not marked trashed');

  // 3. Attempting to delete again fails safely with 404
  const secondDel = await executeMcpTool('drive_delete_file_permanently', { fileId: targetId }, mockUserSub);
  assert.equal(secondDel.isError, true);
  assert.ok(secondDel.content[0].text.includes('File not found'));

  // 4. Missing / nonexistent file fails safely
  const nonExistent = await executeMcpTool('drive_delete_file_permanently', { fileId: 'totally_nonexistent_id' }, mockUserSub);
  assert.equal(nonExistent.isError, true);
  assert.ok(nonExistent.content[0].text.includes('File not found'));

  // 5. User identity injection in args is stripped
  mockDriveState.files.push({ id: 'victim_file_1', name: 'Victim.txt', mimeType: 'text/plain', trashed: false });
  const injectedCall = await executeMcpTool('drive_delete_file_permanently', { fileId: 'victim_file_1', userSub: 'attacker', userId: 'attacker' }, mockUserSub);
  assert.equal(injectedCall.isError, undefined);
  assert.equal(mockDriveState.files.find(f => f.id === 'victim_file_1'), undefined);
});

// =========================================================================
// 2. Restore From Trash Tests (drive_restore_file)
// =========================================================================

test('CORE-02: Restore From Trash reactivates trashed files safely', async () => {
  const trashedFileId = 'file_trashed_for_restore';
  mockDriveState.files.push({
    id: trashedFileId,
    name: 'Accidentally Trashed.txt',
    mimeType: 'text/plain',
    trashed: true,
    parents: ['root']
  });

  // 1. Restore previously trashed file
  const restoreRes = await executeMcpTool('drive_restore_file', { fileId: trashedFileId }, mockUserSub);
  assert.equal(restoreRes.isError, undefined);
  const restoreData = JSON.parse(restoreRes.content[0].text);
  assert.equal(restoreData.success, true);
  assert.equal(restoreData.restored, true);
  assert.equal(restoreData.file.trashed, false);

  // Verify in mock storage
  const restoredFile = mockDriveState.files.find(f => f.id === trashedFileId);
  assert.equal(restoredFile.trashed, false);

  // 2. Restoring an already active (non-trashed) file succeeds idempotently
  const activeRes = await executeMcpTool('drive_restore_file', { fileId: trashedFileId }, mockUserSub);
  assert.equal(activeRes.isError, undefined);
  const activeData = JSON.parse(activeRes.content[0].text);
  assert.equal(activeData.file.trashed, false);

  // 3. Restoring a nonexistent file fails safely
  const nonExistent = await executeMcpTool('drive_restore_file', { fileId: 'nonexistent_restore_target' }, mockUserSub);
  assert.equal(nonExistent.isError, true);
  assert.ok(nonExistent.content[0].text.includes('File not found'));
});

// =========================================================================
// 3. Advanced Search Tests (drive_search & drive_advanced_search)
// =========================================================================

test('CORE-03: Advanced Search translates structured filters and escapes special characters', async () => {
  // Populate files for search filter assertions
  const fDateOld = new Date('2025-01-01T00:00:00Z').toISOString();
  const fDateNew = new Date('2026-06-01T00:00:00Z').toISOString();

  mockDriveState.files.push(
    { id: 'search_f1', name: "O'Reilly 2026 Budget.pdf", mimeType: 'application/pdf', ownerEmail: 'audit@example.com', modifiedTime: fDateNew, createdTime: fDateOld, content: 'quarterly financial audit', parents: ['folder_finance'], trashed: false },
    { id: 'search_f2', name: 'Vendor Contract.docx', mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ownerEmail: 'legal@example.com', modifiedTime: fDateOld, createdTime: fDateOld, content: 'quarterly procurement', parents: ['folder_legal'], trashed: false },
    { id: 'search_f3', name: 'Old Strategy.txt', mimeType: 'text/plain', ownerEmail: 'ceo@example.com', modifiedTime: fDateOld, createdTime: fDateOld, content: 'confidential strategy', parents: ['folder_exec'], trashed: true }
  );

  // 1. Exact filename match with single-quote escaping
  const exactRes = await executeMcpTool('drive_search', { name: "O'Reilly 2026 Budget.pdf" }, mockUserSub);
  assert.equal(exactRes.isError, undefined);
  const exactData = JSON.parse(exactRes.content[0].text);
  assert.equal(exactData.files.length, 1);
  assert.equal(exactData.files[0].id, 'search_f1');

  // 2. Filename contains
  const containsRes = await executeMcpTool('drive_search', { name_contains: 'Budget' }, mockUserSub);
  const containsData = JSON.parse(containsRes.content[0].text);
  assert.equal(containsData.files.length, 1);
  assert.equal(containsData.files[0].id, 'search_f1');

  // 3. MIME type filter
  const mimeRes = await executeMcpTool('drive_search', { mime_type: 'application/pdf' }, mockUserSub);
  const mimeData = JSON.parse(mimeRes.content[0].text);
  assert.ok(mimeData.files.some(f => f.id === 'search_f1'));

  // 4. Owner filter
  const ownerRes = await executeMcpTool('drive_search', { owner_email: 'audit@example.com' }, mockUserSub);
  const ownerData = JSON.parse(ownerRes.content[0].text);
  assert.equal(ownerData.files.length, 1);
  assert.equal(ownerData.files[0].id, 'search_f1');

  // 5. Modified date filter (modified after 2026-01-01)
  const modRes = await executeMcpTool('drive_search', { modified_after: '2026-01-01T00:00:00Z' }, mockUserSub);
  const modData = JSON.parse(modRes.content[0].text);
  assert.equal(modData.files.length, 1);
  assert.equal(modData.files[0].id, 'search_f1');

  // 6. Parent folder filter
  const parentRes = await executeMcpTool('drive_search', { parent_id: 'folder_finance' }, mockUserSub);
  const parentData = JSON.parse(parentRes.content[0].text);
  assert.equal(parentData.files.length, 1);
  assert.equal(parentData.files[0].id, 'search_f1');

  // 7. Full-text content search
  const ftRes = await executeMcpTool('drive_search', { full_text: 'procurement' }, mockUserSub);
  const ftData = JSON.parse(ftRes.content[0].text);
  assert.equal(ftData.files.length, 1);
  assert.equal(ftData.files[0].id, 'search_f2');

  // 8. Trashed state filtering
  const trashedRes = await executeMcpTool('drive_search', { trashed: true }, mockUserSub);
  const trashedData = JSON.parse(trashedRes.content[0].text);
  assert.ok(trashedData.files.some(f => f.id === 'search_f3'));

  // 9. Invalid date string rejection
  const invalidDate = await executeMcpTool('drive_search', { modified_after: 'invalid-date-format' }, mockUserSub);
  assert.equal(invalidDate.isError, true);
  assert.ok(invalidDate.content[0].text.includes('INVALID_DATE_FORMAT'));

  // 10. Dedicated drive_advanced_search tool execution
  const advRes = await executeMcpTool('drive_advanced_search', {
    mime_type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    parent_id: 'folder_legal'
  }, mockUserSub);
  assert.equal(advRes.isError, undefined);
  const advData = JSON.parse(advRes.content[0].text);
  assert.equal(advData.files.length, 1);
  assert.equal(advData.files[0].id, 'search_f2');
});

// =========================================================================
// 4. Pagination Everywhere Tests
// =========================================================================

test('CORE-04: Ubiquitous pagination enforces page size bounds and page tokens', async () => {
  // Add 5 files in a dedicated folder for pagination
  for (let i = 1; i <= 5; i++) {
    mockDriveState.files.push({
      id: `pfile_${i}`,
      name: `Paged File ${i}.txt`,
      mimeType: 'text/plain',
      parents: ['folder_page_test'],
      trashed: false
    });
  }

  // 1. Page size: return 2 items with next page token
  const page1Res = await executeMcpTool('drive_list_folder', {
    folderId: 'folder_page_test',
    pageSize: 2
  }, mockUserSub);
  const page1Data = JSON.parse(page1Res.content[0].text);
  assert.equal(page1Data.files.length, 2);
  assert.ok(page1Data.nextPageToken, 'nextPageToken must be provided');

  // 2. Fetch second page using nextPageToken
  const page2Res = await executeMcpTool('drive_list_folder', {
    folderId: 'folder_page_test',
    pageSize: 2,
    pageToken: page1Data.nextPageToken
  }, mockUserSub);
  const page2Data = JSON.parse(page2Res.content[0].text);
  assert.equal(page2Data.files.length, 2);
  assert.notEqual(page2Data.files[0].id, page1Data.files[0].id);

  // 3. Search pagination with page_size / page_token snake_case alias
  const searchPage = await executeMcpTool('drive_search', {
    parent_id: 'folder_page_test',
    page_size: 3
  }, mockUserSub);
  const searchPageData = JSON.parse(searchPage.content[0].text);
  assert.equal(searchPageData.files.length, 3);
  assert.ok(searchPageData.nextPageToken);

  // 4. Page size limit: values above 1000 are clamped safely
  const clampedPage = await executeMcpTool('drive_search', {
    parent_id: 'folder_page_test',
    pageSize: 1000
  }, mockUserSub);
  assert.equal(clampedPage.isError, undefined);

  // 5. List permissions pagination
  mockDriveState.permissions['file_with_many_perms'] = [
    { id: 'perm_1', role: 'reader', type: 'user', emailAddress: 'u1@example.com' },
    { id: 'perm_2', role: 'writer', type: 'user', emailAddress: 'u2@example.com' },
    { id: 'perm_3', role: 'commenter', type: 'user', emailAddress: 'u3@example.com' }
  ];
  const permPage1 = await executeMcpTool('drive_list_permissions', {
    fileId: 'file_with_many_perms',
    pageSize: 2
  }, mockUserSub);
  const permData1 = JSON.parse(permPage1.content[0].text);
  assert.equal(permData1.permissions.length, 2);
  assert.ok(permData1.nextPageToken);

  const permPage2 = await executeMcpTool('drive_list_permissions', {
    fileId: 'file_with_many_perms',
    pageSize: 2,
    pageToken: permData1.nextPageToken
  }, mockUserSub);
  const permData2 = JSON.parse(permPage2.content[0].text);
  assert.equal(permData2.permissions.length, 1);
  assert.equal(permData2.nextPageToken, null);
});

// =========================================================================
// 5. Download / Export Files Tests (drive_download_file)
// =========================================================================

test('CORE-05: drive_download_file handles binary downloads, Workspace exports, and MIME validation', async () => {
  const binaryPdfBytes = Buffer.from('%PDF-1.5 test binary download stream content');
  const normalTxtBytes = Buffer.from('Normal text download file');

  mockDriveState.files.push(
    { id: 'dl_txt', name: 'notes.txt', mimeType: 'text/plain', mediaContent: normalTxtBytes, trashed: false },
    { id: 'dl_pdf', name: 'manual.pdf', mimeType: 'application/pdf', mediaContent: binaryPdfBytes, trashed: false },
    {
      id: 'dl_sheet',
      name: 'Quarterly Numbers',
      mimeType: 'application/vnd.google-apps.spreadsheet',
      exportContent: {
        'text/csv': Buffer.from('Q1,100\nQ2,200'),
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': Buffer.from([0x50, 0x4B, 0x03, 0x04])
      },
      trashed: false
    },
    {
      id: 'dl_doc',
      name: 'Executive Summary',
      mimeType: 'application/vnd.google-apps.document',
      exportContent: {
        'text/plain': Buffer.from('Executive summary text content'),
        'application/pdf': Buffer.from('%PDF-1.4 Google Doc Export')
      },
      trashed: false
    }
  );

  // 1. Download normal text file (UTF-8)
  const txtDl = await executeMcpTool('drive_download_file', { fileId: 'dl_txt' }, mockUserSub);
  assert.equal(txtDl.isError, undefined);
  const txtDlData = JSON.parse(txtDl.content[0].text);
  assert.equal(txtDlData.fileId, 'dl_txt');
  assert.equal(txtDlData.sourceMimeType, 'text/plain');
  assert.equal(txtDlData.outputMimeType, 'text/plain');
  assert.equal(txtDlData.encoding, 'utf8');
  assert.equal(txtDlData.content, 'Normal text download file');

  // 2. Download normal binary file (Base64)
  const pdfDl = await executeMcpTool('drive_download_file', { fileId: 'dl_pdf' }, mockUserSub);
  assert.equal(pdfDl.isError, undefined);
  const pdfDlData = JSON.parse(pdfDl.content[0].text);
  assert.equal(pdfDlData.fileId, 'dl_pdf');
  assert.equal(pdfDlData.sourceMimeType, 'application/pdf');
  assert.equal(pdfDlData.outputMimeType, 'application/pdf');
  assert.equal(pdfDlData.encoding, 'base64');
  assert.equal(pdfDlData.content, binaryPdfBytes.toString('base64'));

  // 3. Export Google Sheet to CSV (default)
  const sheetCsv = await executeMcpTool('drive_download_file', { fileId: 'dl_sheet' }, mockUserSub);
  const sheetCsvData = JSON.parse(sheetCsv.content[0].text);
  assert.equal(sheetCsvData.sourceMimeType, 'application/vnd.google-apps.spreadsheet');
  assert.equal(sheetCsvData.outputMimeType, 'text/csv');
  assert.equal(sheetCsvData.encoding, 'utf8');
  assert.equal(sheetCsvData.content, 'Q1,100\nQ2,200');

  // 4. Export Google Sheet to XLSX (binary)
  const sheetXlsx = await executeMcpTool('drive_download_file', {
    fileId: 'dl_sheet',
    exportMimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  }, mockUserSub);
  const sheetXlsxData = JSON.parse(sheetXlsx.content[0].text);
  assert.equal(sheetXlsxData.outputMimeType, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  assert.equal(sheetXlsxData.encoding, 'base64');

  // 5. Export Google Doc to PDF (binary)
  const docPdf = await executeMcpTool('drive_download_file', {
    fileId: 'dl_doc',
    exportMimeType: 'application/pdf'
  }, mockUserSub);
  const docPdfData = JSON.parse(docPdf.content[0].text);
  assert.equal(docPdfData.outputMimeType, 'application/pdf');
  assert.equal(docPdfData.encoding, 'base64');

  // 6. Unsupported export format rejection
  const invalidExport = await executeMcpTool('drive_download_file', {
    fileId: 'dl_doc',
    exportMimeType: 'image/gif'
  }, mockUserSub);
  assert.equal(invalidExport.isError, true);
  assert.ok(invalidExport.content[0].text.includes('UNSUPPORTED_EXPORT_FORMAT'));
  assert.ok(invalidExport.content[0].text.includes('Supported formats'));
});

test('SEC-05: Destructive tools disable automated retry (maxAttempts: 1), while non-destructive tools retain retry policy', async () => {
  const permTool = TOOLS.find(t => t.name === 'drive_delete_file_permanently');
  assert.ok(permTool);
  assert.equal(permTool.destructiveHint, true);

  const searchTool = TOOLS.find(t => t.name === 'drive_search');
  assert.ok(searchTool);
  assert.equal(searchTool.destructiveHint, false);

  // 1. Verify destructive tool (drive_delete_file_permanently) does NOT retry on transient 503
  let deleteAttempts = 0;
  const originalDelete = mockDriveClient.files.delete;
  mockDriveClient.files.delete = async (params) => {
    deleteAttempts++;
    const err = new Error('Service Unavailable (Transient)');
    err.status = 503;
    throw err;
  };

  try {
    const res = await executeMcpTool('drive_delete_file_permanently', { fileId: 'f1' }, mockUserSub);
    assert.equal(res.isError, true);
    // Crucial check: must have attempted EXACTLY 1 time, no retries
    assert.equal(deleteAttempts, 1, 'Destructive operation must have maxAttempts: 1 (no retries)');
  } finally {
    mockDriveClient.files.delete = originalDelete;
  }

  // 2. Verify non-destructive tool (drive_search) DOES retry on transient 503
  let searchAttempts = 0;
  const originalList = mockDriveClient.files.list;
  mockDriveClient.files.list = async (params) => {
    searchAttempts++;
    if (searchAttempts === 1) {
      const err = new Error('Service Unavailable (Transient)');
      err.status = 503;
      throw err;
    }
    return originalList(params);
  };

  try {
    const res = await executeMcpTool('drive_search', { query: "name contains 'Document'" }, mockUserSub);
    assert.equal(res.isError, undefined);
    // Crucial check: must have retried after the 1st failure and succeeded on attempt 2
    assert.equal(searchAttempts, 2, 'Non-destructive tool must retry on transient error');
    const data = JSON.parse(res.content[0].text);
    assert.ok(Array.isArray(data.files));
  } finally {
    mockDriveClient.files.list = originalList;
  }

  // 3. Verify permanent delete still succeeds normally
  mockDriveState.files.push({ id: 'sec05_file_to_delete', name: 'SEC05 Delete Me', trashed: false });
  const successRes = await executeMcpTool('drive_delete_file_permanently', { fileId: 'sec05_file_to_delete' }, mockUserSub);
  assert.equal(successRes.isError, undefined);
  const successData = JSON.parse(successRes.content[0].text);
  assert.equal(successData.success, true);
  assert.equal(successData.permanent, true);
  assert.equal(mockDriveState.files.some(f => f.id === 'sec05_file_to_delete'), false);
});

test('DOCS-01: Google Docs Tools (create, read, update, append, formatting, multi-user isolation, SEC-05)', async () => {
  // Test 1 — Create: drive_doc_create creates a real native Google Doc
  const createRes = await executeMcpTool('drive_doc_create', { title: 'Varun Docs API Test' }, mockUserSub);
  assert.equal(createRes.isError, undefined);
  const createData = JSON.parse(createRes.content[0].text);
  assert.equal(createData.success, true);
  assert.ok(createData.documentId);
  assert.equal(createData.title, 'Varun Docs API Test');
  assert.equal(createData.mimeType, 'application/vnd.google-apps.document');
  assert.ok(createData.webViewLink.includes(createData.documentId));

  const docId = createData.documentId;

  // Test 2 — Read: drive_doc_read reads the newly created document
  const readRes1 = await executeMcpTool('drive_doc_read', { documentId: docId }, mockUserSub);
  assert.equal(readRes1.isError, undefined);
  const readData1 = JSON.parse(readRes1.content[0].text);
  assert.equal(readData1.documentId, docId);
  assert.equal(readData1.title, 'Varun Docs API Test');
  assert.ok(readData1.documentUrl.includes(docId));
  assert.ok(readData1.body);

  // Test 3 — Insert: insertText "Hello from Google Docs MCP."
  const insertRes = await executeMcpTool('drive_doc_update', {
    documentId: docId,
    requests: [
      {
        insertText: {
          location: { index: 1 },
          text: 'Hello from Google Docs MCP.'
        }
      }
    ]
  }, mockUserSub);
  assert.equal(insertRes.isError, undefined);
  const insertData = JSON.parse(insertRes.content[0].text);
  assert.equal(insertData.success, true);
  assert.equal(insertData.documentId, docId);

  // Verify text was inserted
  const readRes2 = await executeMcpTool('drive_doc_read', { documentId: docId }, mockUserSub);
  const readData2 = JSON.parse(readRes2.content[0].text);
  assert.ok(readData2.textContent.includes('Hello from Google Docs MCP.'));

  // Test 4 — Replace: replace "Hello from Google Docs MCP." with "Updated from ChatGPT."
  const replaceRes = await executeMcpTool('drive_doc_update', {
    documentId: docId,
    requests: [
      {
        replaceAllText: {
          containsText: {
            text: 'Hello from Google Docs MCP.'
          },
          replaceText: 'Updated from ChatGPT.'
        }
      }
    ]
  }, mockUserSub);
  assert.equal(replaceRes.isError, undefined);

  // Verify text was replaced
  const readRes3 = await executeMcpTool('drive_doc_read', { documentId: docId }, mockUserSub);
  const readData3 = JSON.parse(readRes3.content[0].text);
  assert.ok(readData3.textContent.includes('Updated from ChatGPT.'));
  assert.equal(readData3.textContent.includes('Hello from Google Docs MCP.'), false);

  // Test 5 — Formatting: Apply bold formatting
  const formatRes = await executeMcpTool('drive_doc_update', {
    documentId: docId,
    requests: [
      {
        updateTextStyle: {
          range: {
            startIndex: 1,
            endIndex: 21
          },
          textStyle: {
            bold: true
          },
          fields: 'bold'
        }
      }
    ]
  }, mockUserSub);
  assert.equal(formatRes.isError, undefined);
  const formatData = JSON.parse(formatRes.content[0].text);
  assert.equal(formatData.success, true);

  // Test 5b — Formatting via drive_docs_batch_update alias
  const aliasRes = await executeMcpTool('drive_docs_batch_update', {
    documentId: docId,
    requests: [
      {
        updateTextStyle: {
          range: {
            startIndex: 1,
            endIndex: 10
          },
          textStyle: {
            italic: true
          },
          fields: 'italic'
        }
      }
    ]
  }, mockUserSub);
  assert.equal(aliasRes.isError, undefined);
  const aliasData = JSON.parse(aliasRes.content[0].text);
  assert.equal(aliasData.success, true);

  // Test 6 — Append: drive_doc_append adds text at the end
  const appendRes = await executeMcpTool('drive_doc_append', {
    documentId: docId,
    text: 'This content was appended through the MCP.'
  }, mockUserSub);
  assert.equal(appendRes.isError, undefined);
  const appendData = JSON.parse(appendRes.content[0].text);
  assert.equal(appendData.success, true);
  assert.equal(appendData.documentId, docId);
  assert.ok(appendData.insertedAtIndex >= 1);

  // Verify text was appended
  const readRes4 = await executeMcpTool('drive_doc_read', { documentId: docId }, mockUserSub);
  const readData4 = JSON.parse(readRes4.content[0].text);
  assert.ok(readData4.textContent.includes('This content was appended through the MCP.'));

  // Test 7 — Multi-user isolation: Unauthorized user cannot read or update User A's document
  const unauthorizedRead = await executeMcpTool('drive_doc_read', { documentId: docId }, 'usr_unauthorized_user');
  assert.equal(unauthorizedRead.isError, true);
  assert.ok(unauthorizedRead.content[0].text.includes('permission') || unauthorizedRead.content[0].text.includes('403'));

  const unauthorizedUpdate = await executeMcpTool('drive_doc_update', {
    documentId: docId,
    requests: [{ insertText: { location: { index: 1 }, text: 'Hacked' } }]
  }, 'usr_unauthorized_user');
  assert.equal(unauthorizedUpdate.isError, true);

  // Test 8 — SEC-05 Verification: drive_doc_update (destructiveHint: true) receives maxAttempts: 1
  let updateAttempts = 0;
  const originalBatchUpdate = mockDocsClient.documents.batchUpdate;
  mockDocsClient.documents.batchUpdate = async (params) => {
    updateAttempts++;
    const err = new Error('Service Unavailable (Transient)');
    err.status = 503;
    throw err;
  };

  try {
    const transientUpdateRes = await executeMcpTool('drive_doc_update', {
      documentId: docId,
      requests: [{ insertText: { location: { index: 1 }, text: 'Transient test' } }]
    }, mockUserSub);
    assert.equal(transientUpdateRes.isError, true);
    // Crucial check: must have attempted EXACTLY 1 time, no retries
    assert.equal(updateAttempts, 1, 'drive_doc_update must have maxAttempts: 1 (no retries)');
  } finally {
    mockDocsClient.documents.batchUpdate = originalBatchUpdate;
  }
});


