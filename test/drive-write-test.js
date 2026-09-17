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

const { TOOLS, listMcpTools, executeMcpTool } = await import('../src/mcp.js');
const { setUserGoogleTokens } = await import('../src/user-store.js');
import * as googleModule from '../src/google.js';

test.after(() => {
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

test('1. Tool Registry: Verifies all 23 expected tools are registered', () => {
  const registered = listMcpTools();
  assert.equal(registered.length, 23);

  const names = registered.map(t => t.name);

  // 5 Read tools
  assert.ok(names.includes('drive_search'));
  assert.ok(names.includes('drive_list_folder'));
  assert.ok(names.includes('drive_get_metadata'));
  assert.ok(names.includes('drive_read_file'));
  assert.ok(names.includes('drive_search_and_read'));

  // 7 Write tools
  assert.ok(names.includes('drive_create_file'));
  assert.ok(names.includes('drive_create_folder'));
  assert.ok(names.includes('drive_update_file'));
  assert.ok(names.includes('drive_rename_file'));
  assert.ok(names.includes('drive_move_file'));
  assert.ok(names.includes('drive_copy_file'));
  assert.ok(names.includes('drive_trash_file'));

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
      let filtered = mockDriveState.files.filter(f => !f.trashed);
      if (params.q && params.q.includes('in parents')) {
        const match = params.q.match(/'(.*?)' in parents/);
        const folder = match ? match[1] : 'root';
        filtered = filtered.filter(f => f.parents?.includes(folder));
      }
      return { data: { files: filtered } };
    },
    get: async (params) => {
      const file = mockDriveState.files.find(f => f.id === params.fileId);
      if (!file) throw new Error('File not found: ' + params.fileId);
      if (params.alt === 'media') {
        return { data: Readable.from(['Mock file media content']) };
      }
      return { data: { ...file } };
    },
    export: async (params) => {
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
      const newFile = {
        id: `file_${Date.now()}`,
        name: params.requestBody.name,
        mimeType: params.requestBody.mimeType,
        parents: params.requestBody.parents || ['root'],
        createdTime: new Date().toISOString()
      };
      mockDriveState.files.push(newFile);
      return { data: newFile };
    },
    update: async (params) => {
      const file = mockDriveState.files.find(f => f.id === params.fileId);
      if (!file) throw new Error('File not found: ' + params.fileId);
      if (params.requestBody?.name) file.name = params.requestBody.name;
      if (params.requestBody?.trashed !== undefined) file.trashed = params.requestBody.trashed;
      if (params.addParents) {
        file.parents = [params.addParents];
      }
      return { data: { ...file, modifiedTime: new Date().toISOString() } };
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
      return { data: { permissions: mockDriveState.permissions[params.fileId] || [] } };
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
      const resource = params.resource || params.requestBody;
      // Fail if empty sheets array is sent or invalid field mask syntax
      if (resource?.sheets && resource.sheets.length === 0) {
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
      const title = resource?.properties?.title || 'Untitled';
      const initialSheets = (resource?.sheets || [{ properties: { sheetId: 0, title: 'Sheet1' } }]).map((s, idx) => ({
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

// Use clean override hook
const { setGoogleClientOverrides } = await import('../src/google.js');
setGoogleClientOverrides({
  getDriveClient: async () => mockDriveClient,
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

  // Verify resource sent to Google Sheets API
  const lastParams1 = mockSheetsClient.lastCreateParams;
  assert.equal(lastParams1.resource.properties.title, 'Varun');
  assert.equal(lastParams1.resource.sheets, undefined, 'Must NOT send sheets array when sheetTitles is omitted');
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

  // Verify resource sent to Google Sheets API
  const lastParams2 = mockSheetsClient.lastCreateParams;
  assert.equal(lastParams2.resource.properties.title, 'Varun Test');
  assert.deepEqual(lastParams2.resource.sheets, [{ properties: { title: 'Sheet1' } }]);

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

