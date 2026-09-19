/**
 * Test Suite: Google Docs Structural Indexing, Range Pre-Validation & Formatting Suite
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';

const testDataDir = path.resolve(process.cwd(), 'data-test-docs-formatting');
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = testDataDir;

const {
  getDocumentEndIndex,
  extractDocsSegments,
  validateDocsBatchRequests,
  parseHexColor,
  executeMcpTool
} = await import('../src/mcp.js');
const { setUserGoogleTokens } = await import('../src/user-store.js');
const { setGoogleClientOverrides } = await import('../src/google.js');

test.after(() => {
  setGoogleClientOverrides(null);
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }
});

// Mock document representing a multi-section document (similar to the user's merged document)
const mockDocData = {
  documentId: '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew',
  title: 'Merged Product Content — Aarogya Tea, Abhayarishtam, Aloe Vera Shampoo & Beauty Soap',
  body: {
    content: [
      {
        startIndex: 1,
        endIndex: 25,
        paragraph: {
          paragraphStyle: { namedStyleType: 'TITLE' },
          elements: [
            {
              startIndex: 1,
              endIndex: 25,
              textRun: { content: 'Aarogya Tea Overview\n' }
            }
          ]
        }
      },
      {
        startIndex: 25,
        endIndex: 120,
        paragraph: {
          paragraphStyle: { namedStyleType: 'HEADING_1' },
          elements: [
            {
              startIndex: 25,
              endIndex: 120,
              textRun: { content: 'Benefits and Usage Directions for Daily Consumption\n' }
            }
          ]
        }
      },
      {
        startIndex: 120,
        endIndex: 500,
        paragraph: {
          paragraphStyle: { namedStyleType: 'NORMAL_TEXT' },
          elements: [
            {
              startIndex: 120,
              endIndex: 250,
              textRun: { content: 'Aarogya Tea is enriched with organic herbs. ' }
            },
            {
              startIndex: 250,
              endIndex: 500,
              textRun: { content: 'Drink twice daily for optimal digestive wellness.\n' }
            }
          ]
        }
      },
      {
        startIndex: 500,
        endIndex: 1200,
        table: {
          rows: 3,
          columns: 2
        }
      },
      {
        startIndex: 1200,
        endIndex: 37671,
        paragraph: {
          paragraphStyle: { namedStyleType: 'NORMAL_TEXT' },
          elements: [
            {
              startIndex: 1200,
              endIndex: 37671,
              textRun: { content: 'Final product descriptions and laboratory certification.\n' }
            }
          ]
        }
      }
    ]
  }
};

test('1. getDocumentEndIndex: correctly identifies the terminal boundary of the document body', () => {
  const endIndex = getDocumentEndIndex(mockDocData);
  assert.equal(endIndex, 37671);

  // Fallback for empty or missing body
  assert.equal(getDocumentEndIndex({}), 1);
  assert.equal(getDocumentEndIndex({ body: { content: [] } }), 1);
});

test('2. extractDocsSegments: extracts structural element indexes, heading styles, and valid bounds', () => {
  const extracted = extractDocsSegments(mockDocData);
  assert.equal(extracted.documentEndIndex, 37671);
  assert.deepEqual(extracted.validRange, { startIndex: 1, endIndex: 37671 });
  assert.equal(extracted.segments.length, 5);

  // Segment 1: Title
  assert.equal(extracted.segments[0].type, 'paragraph');
  assert.equal(extracted.segments[0].headingType, 'TITLE');
  assert.equal(extracted.segments[0].startIndex, 1);
  assert.equal(extracted.segments[0].endIndex, 25);
  assert.equal(extracted.segments[0].text, 'Aarogya Tea Overview\n');

  // Segment 2: Heading 1
  assert.equal(extracted.segments[1].headingType, 'HEADING_1');
  assert.equal(extracted.segments[1].startIndex, 25);
  assert.equal(extracted.segments[1].endIndex, 120);

  // Segment 4: Table element
  assert.equal(extracted.segments[3].type, 'table');
  assert.equal(extracted.segments[3].startIndex, 500);
  assert.equal(extracted.segments[3].endIndex, 1200);
});

test('3. validateDocsBatchRequests: rejects the user-reported out-of-bounds error (39487 > 37671)', () => {
  const outOfBoundsBatch = [
    {
      updateTextStyle: {
        range: {
          startIndex: 39200,
          endIndex: 39487 // Exceeds actual document end 37671!
        },
        textStyle: { bold: true },
        fields: 'bold'
      }
    }
  ];

  assert.throws(
    () => validateDocsBatchRequests(outOfBoundsBatch, 37671),
    (err) => {
      assert.equal(err.code, 'DOCUMENT_RANGE_OUT_OF_BOUNDS');
      assert.ok(err.message.includes('exceeds the document end bound 37671'));
      assert.ok(err.message.includes('39487'));
      assert.equal(err.details.invalidRange.endIndex, 39487);
      assert.equal(err.details.validBounds.endIndex, 37671);
      assert.equal(err.details.requestIndex, 0);
      assert.equal(err.details.operation, 'updateTextStyle');
      return true;
    }
  );
});

test('4. validateDocsBatchRequests: validates range start boundaries and inverted ranges', () => {
  // startIndex < 1 (Google Docs starts at index 1)
  assert.throws(
    () => validateDocsBatchRequests([{ updateTextStyle: { range: { startIndex: 0, endIndex: 10 } } }], 37671),
    (err) => {
      assert.equal(err.code, 'DOCUMENT_RANGE_OUT_OF_BOUNDS');
      assert.ok(err.message.includes('startIndex 0 < 1'));
      return true;
    }
  );

  // startIndex > endIndex
  assert.throws(
    () => validateDocsBatchRequests([{ updateParagraphStyle: { range: { startIndex: 50, endIndex: 30 } } }], 37671),
    (err) => {
      assert.equal(err.code, 'DOCUMENT_RANGE_INVALID');
      assert.ok(err.message.includes('startIndex 50 > endIndex 30'));
      return true;
    }
  );

  // Insertion location beyond bounds
  assert.throws(
    () => validateDocsBatchRequests([{ insertText: { location: { index: 40000 }, text: 'Hello' } }], 37671),
    (err) => {
      assert.equal(err.code, 'DOCUMENT_LOCATION_OUT_OF_BOUNDS');
      assert.ok(err.message.includes('insertion index 40000'));
      return true;
    }
  );

  // Valid requests pass cleanly
  assert.doesNotThrow(() => {
    validateDocsBatchRequests([
      { updateTextStyle: { range: { startIndex: 1, endIndex: 20 }, textStyle: { bold: true }, fields: 'bold' } },
      { insertText: { location: { index: 100 }, text: 'inserted' } }
    ], 37671);
  });
});

test('5. parseHexColor: converts 6-char and 3-char hex strings into Google Docs RGB fractions', () => {
  // 6-character hex (#ff0000 -> full red)
  const red = parseHexColor('#ff0000');
  assert.deepEqual(red, { red: 1, green: 0, blue: 0 });

  // 6-character hex without hash
  const blue = parseHexColor('0000ff');
  assert.deepEqual(blue, { red: 0, green: 0, blue: 1 });

  // 3-character hex (#0f0 -> full green)
  const green = parseHexColor('#0f0');
  assert.deepEqual(green, { red: 0, green: 1, blue: 0 });

  // Invalid inputs return null
  assert.equal(parseHexColor(null), null);
  assert.equal(parseHexColor(''), null);
  assert.equal(parseHexColor('invalid'), null);
});

test('6. Tool Execution: drive_doc_read returns structural segments and valid bounds', async () => {
  const userSub = 'usr_docs_test_user';
  await setUserGoogleTokens(userSub, {
    access_token: 'mock_docs_at',
    refresh_token: 'mock_docs_rt'
  });

  // Mock getDocsClient via setGoogleClientOverrides
  setGoogleClientOverrides({
    getDocsClient: async () => ({
      documents: {
        get: async () => ({ data: mockDocData })
      }
    })
  });

  const res = await executeMcpTool('drive_doc_read', {
    documentId: '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew'
  }, userSub);

  assert.ok(!res.isError);
  const parsed = JSON.parse(res.content[0].text);
  assert.equal(parsed.documentId, '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew');
  assert.equal(parsed.documentEndIndex, 37671);
  assert.deepEqual(parsed.validRange, { startIndex: 1, endIndex: 37671 });
  assert.ok(parsed.segments.length >= 5);
  assert.ok(parsed.textContent.includes('Aarogya Tea'));
});

test('7. Tool Execution: drive_doc_update pre-validates bounds and blocks out-of-range batch', async () => {
  const userSub = 'usr_docs_test_user';
  let batchUpdateCalled = false;

  setGoogleClientOverrides({
    getDocsClient: async () => ({
      documents: {
        get: async () => ({ data: mockDocData }),
        batchUpdate: async () => {
          batchUpdateCalled = true;
          return { data: { replies: [] } };
        }
      }
    })
  });

  const res = await executeMcpTool('drive_doc_update', {
    documentId: '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew',
    requests: [
      {
        updateTextStyle: {
          range: {
            startIndex: 39200,
            endIndex: 39487 // Out of bounds
          },
          textStyle: { bold: true },
          fields: 'bold'
        }
      }
    ]
  }, userSub);

  assert.equal(res.isError, true);
  assert.ok(res.content[0].text.includes('DOCUMENT_RANGE_OUT_OF_BOUNDS'));
  assert.ok(res.content[0].text.includes('39487'));
  assert.ok(res.content[0].text.includes('37671'));
  assert.equal(batchUpdateCalled, false, 'batchUpdate must not be called when range is invalid');
});

test('8. Tool Execution: drive_doc_format_text styles exact text occurrences without index calculation', async () => {
  const userSub = 'usr_docs_test_user';
  let sentRequests = [];

  setGoogleClientOverrides({
    getDocsClient: async () => ({
      documents: {
        get: async () => ({ data: mockDocData }),
        batchUpdate: async ({ requestBody }) => {
          sentRequests = requestBody.requests;
          return { data: { replies: [{}] } };
        }
      }
    })
  });

  const res = await executeMcpTool('drive_doc_format_text', {
    documentId: '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew',
    textMatch: 'Aarogya Tea',
    textStyle: {
      bold: true,
      fontSize: 16,
      foregroundColor: '#1d4ed8'
    }
  }, userSub);

  assert.ok(!res.isError);
  const parsed = JSON.parse(res.content[0].text);
  assert.equal(parsed.success, true);
  assert.ok(parsed.formattedMatches >= 1);

  // Verify constructed request
  assert.ok(sentRequests.length >= 1);
  const firstReq = sentRequests[0].updateTextStyle;
  assert.ok(firstReq);
  assert.equal(firstReq.textStyle.bold, true);
  assert.equal(firstReq.textStyle.fontSize.magnitude, 16);
  assert.ok(firstReq.textStyle.foregroundColor.color.rgbColor);
  assert.ok(firstReq.fields.includes('bold'));
  assert.ok(firstReq.fields.includes('fontSize'));
  assert.ok(firstReq.fields.includes('foregroundColor'));

  // Range must map directly inside the textRun segment bounds
  assert.equal(firstReq.range.startIndex, 1);
  assert.equal(firstReq.range.endIndex, 1 + 'Aarogya Tea'.length);
});

test('9. Tool Execution: drive_doc_find_segments returns exact segment indexes and snippets', async () => {
  const userSub = 'usr_docs_test_user';

  setGoogleClientOverrides({
    getDocsClient: async () => ({
      documents: {
        get: async () => ({ data: mockDocData })
      }
    })
  });

  const res = await executeMcpTool('drive_doc_find_segments', {
    documentId: '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew',
    query: 'Aarogya Tea'
  }, userSub);

  assert.ok(!res.isError);
  const parsed = JSON.parse(res.content[0].text);
  assert.equal(parsed.matchCount, 2);
  assert.equal(parsed.matches[0].startIndex, 1);
  assert.equal(parsed.matches[0].endIndex, 12);
  assert.equal(parsed.matches[0].headingType, 'TITLE');
  assert.equal(parsed.matches[1].startIndex, 120);
  assert.equal(parsed.matches[1].endIndex, 131);
});

test('10. Tool Execution: drive_doc_replace_text uses atomic replaceAllText', async () => {
  const userSub = 'usr_docs_test_user';
  let capturedBatch = null;

  setGoogleClientOverrides({
    getDocsClient: async () => ({
      documents: {
        batchUpdate: async ({ requestBody }) => {
          capturedBatch = requestBody.requests;
          return { data: { replies: [{ replaceAllText: { occurrencesChanged: 3 } }] } };
        }
      }
    })
  });

  const res = await executeMcpTool('drive_doc_replace_text', {
    documentId: '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew',
    findText: 'Aarogya Tea',
    replaceText: 'Aarogya Organic Herbal Tea'
  }, userSub);

  assert.ok(!res.isError);
  const parsed = JSON.parse(res.content[0].text);
  assert.equal(parsed.occurrencesChanged, 3);
  assert.ok(capturedBatch[0].replaceAllText);
  assert.equal(capturedBatch[0].replaceAllText.containsText.text, 'Aarogya Tea');
  assert.equal(capturedBatch[0].replaceAllText.replaceText, 'Aarogya Organic Herbal Tea');
});

test('11. Tool Execution: drive_doc_insert_table & insert_page_break calculate safe insertion index', async () => {
  const userSub = 'usr_docs_test_user';
  let capturedBatch = [];

  setGoogleClientOverrides({
    getDocsClient: async () => ({
      documents: {
        get: async () => ({ data: mockDocData }),
        batchUpdate: async ({ requestBody }) => {
          capturedBatch.push(requestBody.requests);
          return { data: { replies: [{}] } };
        }
      }
    })
  });

  // Insert Table at end
  const tableRes = await executeMcpTool('drive_doc_insert_table', {
    documentId: '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew',
    rows: 4,
    columns: 3,
    location: 'end'
  }, userSub);

  assert.ok(!tableRes.isError);
  const tableParsed = JSON.parse(tableRes.content[0].text);
  assert.equal(tableParsed.insertedAtIndex, 37670); // documentEndIndex (37671) - 1
  assert.equal(capturedBatch[0][0].insertTable.rows, 4);
  assert.equal(capturedBatch[0][0].insertTable.columns, 3);

  // Insert Page Break at start
  const pageBreakRes = await executeMcpTool('drive_doc_insert_page_break', {
    documentId: '1U3zoEl3BdP_Xj6toDuq8_nyhNm5GNvRWV4x71f7gQew',
    location: 'start'
  }, userSub);

  assert.ok(!pageBreakRes.isError);
  const pageBreakParsed = JSON.parse(pageBreakRes.content[0].text);
  assert.equal(pageBreakParsed.insertedAtIndex, 1);
  assert.equal(capturedBatch[1][0].insertPageBreak.location.index, 1);
});

