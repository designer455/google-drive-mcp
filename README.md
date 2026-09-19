# Digitons Google Drive MCP Server v2

A production-ready, **Multi-User Google Drive Remote Model Context Protocol (MCP)** server engineered for ChatGPT.

This is a completely isolated, standalone v2 architecture. Every authenticated ChatGPT user connects and operates strictly within their **own** Google account with dedicated, cryptographically isolated credentials.

---

## 1. Architecture & Multi-User Isolation

```
User A (ChatGPT)                   User B (ChatGPT)
       │                                  │
       ▼                                  ▼
[ChatGPT OAuth Authz Code + PKCE]   [ChatGPT OAuth Authz Code + PKCE]
       │                                  │
  Bearer Token A                     Bearer Token B
 (sub: usr_a1b2...)                 (sub: usr_c3d4...)
       │                                  │
       ▼                                  ▼
 [Express Server / MCP Streamable HTTP JSON-RPC Endpoint]
       │                                  │
 Resolve currentUserSub = usr_a1b2    Resolve currentUserSub = usr_c3d4
       │                                  │
       ▼                                  ▼
 [UserStore / DATA_DIR/google-users.json (0600 atomic file lock)]
       │                                  │
 Creds A only                        Creds B only
       │                                  │
       ▼                                  ▼
 Google OAuth2Client A              Google OAuth2Client B
       │                                  │
       ▼                                  ▼
 User A Google Drive                User B Google Drive
 (Search, Read, Write)              (Search, Read, Write)
```

### Core Invariants:
1. **Zero Shared Credentials**: There is no global Google token, fallback user, or shared account.
2. **Context-Driven User Resolution**: MCP tool handlers never accept a `userId` or `userSub` from tool parameters. The user's subject is extracted exclusively from the validated Bearer token.
3. **Cryptographically Bound Google OAuth State**: State parameters are single-use, expire after 10 minutes, and are server-side bound to the authenticated `userSub`. Replay, CSRF, and account swapping are strictly prevented.
4. **Ownership Transfer Blocked**: Permission tools strictly prohibit ownership transfers (`role: 'owner'`) and uncontrolled public write access.
5. **Survives Process Restarts & Deployments**: Stored in `DATA_DIR` outside git/deployment directories with restricted `0600` permissions.

---

## 2. MCP Tools Reference (32 Tools)

### Read Tools (7)
- **`drive_search`**: Search files matching a query string (e.g., `name contains 'Report' and trashed = false`). Supports pagination and sorting.
- **`drive_advanced_search`**: Advanced structured search filtering by filename, content, mimeType, owner, date ranges, parent folder, and trashed state.
- **`drive_list_folder`**: List items inside a specific folder ID (default: `'root'`) with pagination support.
- **`drive_get_metadata`**: Retrieve detailed metadata and permissions for a file or folder.
- **`drive_read_file`**: Read text content (exports Google Docs, Sheets, and Slides to text/markdown/csv, or downloads text/data files up to 10MB; binary formats returned as base64).
- **`drive_download_file`**: Download binary files or export Google Workspace documents with specified export MIME types (e.g. PDF, DOCX, XLSX).
- **`drive_search_and_read`**: Search for a file by query and immediately return the content of the first matching file.

### Write Tools (9)
- **`drive_create_file`**: Create a new text or data file with name, MIME type, content, and optional parent folder.
- **`drive_create_folder`**: Create a new folder in My Drive or Shared Drives.
- **`drive_update_file`**: Safely replace the content of an existing text or data file (Workspace native documents are protected from direct stream overwriting).
- **`drive_rename_file`**: Rename an existing file or folder.
- **`drive_move_file`**: Move a file or folder from its existing parents to a new target folder.
- **`drive_copy_file`**: Create a copy of an existing file.
- **`drive_trash_file`**: Safely move a file to the trash (`trashed: true`).
- **`drive_restore_file`**: Restore a trashed file back to active Drive.
- **`drive_delete_file_permanently`**: Permanently and irreversibly delete a file from Drive (SEC-05 protected: automated retries disabled).

### Google Docs Tools (5)
- **`drive_doc_create`**: Create a native Google Docs document (`application/vnd.google-apps.document`).
  - Parameters: `title` (string, required), `parentFolderId` (string, optional).
  - Returns: `documentId`, `title`, `mimeType`, `webViewLink`, `createdTime`.
- **`drive_doc_read`**: Read document structure, metadata, and full text content using Google Docs API `documents.get`.
  - Parameters: `documentId` (string, required).
  - Returns: `documentId`, `title`, `documentUrl`, `textContent`, `revisionId`, and structured `body`.
- **`drive_doc_update`**: Perform batch updates using Google Docs API `documents.batchUpdate` (e.g., `insertText`, `replaceAllText`, `updateTextStyle`, `deleteContentRange`, tables).
  - Parameters: `documentId` (string, required), `requests` (array of batchUpdate objects, required).
  - Safety: Tagged `destructiveHint: true` to enforce SEC-05 single-attempt execution without automated retry on transient errors.
- **`drive_docs_batch_update`**: Dedicated batch update alias matching ChatGPT tool conventions, invoking Google Docs API `documents.batchUpdate`. Identical interface and capabilities as `drive_doc_update`.
- **`drive_doc_append`**: Convenience tool to append text to the end of a Google Doc.
  - Parameters: `documentId` (string, required), `text` (string, required).
  - Automatically calculates insertion index before the terminal document break and updates the document.

### Google Sheets Tools (4)
- **`drive_sheet_create`**: Create a new Google Spreadsheet with a title and optional initial sheet tabs.
- **`drive_sheet_read_range`**: Read values from an A1 notation range (e.g. `'Sheet1!A1:D10'`).
- **`drive_sheet_update_range`**: Update values in an A1 notation range.
- **`drive_sheet_append_rows`**: Append rows of data to a spreadsheet.

### Google Slides Tools (3)
- **`drive_slides_create`**: Create a new Google Slides presentation with a title.
- **`drive_slides_read`**: Inspect slides structure, IDs, and title.
- **`drive_slides_update`**: Execute batch updates (e.g. create slides, insert text).

### Permissions & Sharing Tools (4)
- **`drive_list_permissions`**: List sharing permissions for a file or folder.
- **`drive_add_permission`**: Share a file with a `user`, `group`, or `domain` as `reader`, `commenter`, or `writer`. *Ownership transfer is strictly blocked.*
- **`drive_update_permission`**: Update permission role. *Ownership transfer is strictly blocked.*
- **`drive_remove_permission`**: Remove a sharing permission from a file.

### Tool Annotation Model (OpenAI App Directory Compliance)
Every tool explicitly advertises safety hints both as top-level properties and in the `annotations` object:
- **`readOnlyHint`** (`boolean`): Indicates whether the tool only reads data without modifying server or external state (`true` for search, read, metadata, list tools).
- **`openWorldHint`** (`boolean`): Indicates whether the tool interacts with the open web/external network arbitrarily (`false` for all Drive tools).
- **`destructiveHint`** (`boolean`): Indicates whether the tool performs destructive, overwriting, or trashing operations (`true` for `drive_update_file`, `drive_trash_file`, `drive_delete_file_permanently`, `drive_doc_update`, `drive_sheet_update_range`, `drive_slides_update`, `drive_update_permission`, `drive_remove_permission`). Ensures SEC-05 single-attempt execution.

---

## 3. OAuth Models

### A. ChatGPT MCP OAuth Server
Implements standard OAuth 2.0 specifications:
- **Discovery**: `GET /.well-known/oauth-authorization-server` (RFC 8414)
- **Protected Resource**: `GET /.well-known/oauth-protected-resource` (RFC 9470)
- **Authorization**: `GET /authorize` & `POST /authorize`
- **Tokens**: `POST /token`
- **PKCE**: RFC 7636 S256 (`code_challenge` / `code_verifier`)
- **Grants**: `authorization_code`, `refresh_token`
- **Identity**: Issues an opaque internal `sub` (e.g. `usr_8c2...`) associated with the access token.

### B. Per-User Google OAuth Flow & One-Time Link Token

To prevent exposing MCP access tokens or authorization credentials in browser URLs, the server uses a secure **One-Time Google Link Token** mechanism:

#### User Journey:
1. **Connect MCP**: User connects the MCP server in ChatGPT via OAuth 2.0.
2. **Drive Operation**: User asks ChatGPT to search or manage Drive (e.g. "Search my Google Drive").
3. **Not Connected Response**: Server detects that Google is not connected for this user's MCP identity and responds with a clear prompt and a secure one-time link:
   ```text
   Google Drive is not connected for your account.
   Open this one-time connection link to connect your Google account:
   https://mcp-v2.digitonsdevelopment.com/auth/google/link?code=glink_<random_hash>

   This link connects your personal Google account to your ChatGPT MCP session. This link expires in 10 minutes and can be used once.
   ```
4. **Open Browser Link**: User opens the URL in their browser.
5. **Atomic Single-Use Consumption**: `GET /auth/google/link?code=...` validates and atomically consumes the one-time link token, verifies it hasn't expired, retrieves the bound MCP `userSub`, creates a Google OAuth `state` bound to that `userSub`, and redirects (302) to Google.
6. **Google Authorization**: User selects their Google account and authorizes Drive permissions (`prompt=consent`, `access_type=offline`).
7. **Google Callback**: Google returns authorization code to `GET /oauth2callback`.
8. **Account Linked to MCP Identity**: Server atomically validates and consumes the OAuth `state`, exchanges the Google authorization code for tokens, and securely associates them with the bound `userSub` in `DATA_DIR/google-users.json` (`0600`).
9. **Drive Tools Work**: The user returns to ChatGPT, where all Drive operations now automatically execute against their personal Google Drive account.

#### Security Properties of One-Time Link Tokens:
- **No Bearer Tokens in URLs**: MCP Bearer access tokens, refresh tokens, and client secrets are never exposed in browser URLs, query parameters, HTML, or logs.
- **Cryptographically Random**: Generated using 48 bytes of cryptographically secure randomness (`crypto.randomBytes`).
- **Server-Side Hashed Storage**: Only the SHA-256 hash of the link token is stored on disk in `DATA_DIR/google-link-tokens.json`.
- **Strictly Single-Use**: Consumed atomically inside a mutex lock upon first use; any replay attempt immediately fails.
- **Short-Lived Expiration**: Configurable via `OAUTH_GOOGLE_LINK_EXPIRY_SECONDS` (defaults to 600s / 10 minutes).
- **Strict Identity Binding**: Bound directly to the calling user's authenticated `context.userSub`. Cannot be generated by anonymous requests or altered via browser query parameters (`userId` / `userSub` parameters are rejected).
- **Multi-User Isolation**: Token generated for User A only connects User A; User B cannot claim or hijack User A's token.

### Connection Status & Disconnect
- **`GET /auth/google/status`** (Requires Bearer Token):
  ```json
  {
    "connected": true,
    "googleAccount": {
      "email": "user@example.com",
      "displayName": "User Name"
    },
    "scopes": ["https://www.googleapis.com/auth/drive"]
  }
  ```
- **`POST /auth/google/disconnect`** (Requires Bearer Token):
  Revokes tokens with Google and deletes local credentials for the calling user only. Other users remain unaffected.

---

## 4. Google Cloud Setup & Verification

1. Open [Google Cloud Console](https://console.cloud.google.com/).
2. Create or select your Google Cloud project.
3. **Enable APIs**:
   - Google Drive API
   - Google Docs API
   - Google Sheets API
   - Google Slides API
4. **Configure OAuth Consent Screen**:
   - User Type: **External** (or Internal for Workspace organizations).
   - Scopes: Add `https://www.googleapis.com/auth/drive`, `.../userinfo.email`, `.../userinfo.profile`.
   - Test Users: Add developer/tester Google email addresses while app is in "Testing" mode.
5. **Create OAuth 2.0 Client ID**:
   - Application Type: **Web application**.
   - Authorized Redirect URI: `https://mcp-v2.digitonsdevelopment.com/oauth2callback` (and `http://localhost:3000/oauth2callback` for local testing).
   - Save the **Client ID** and **Client Secret**.

> [!IMPORTANT]
> **Google OAuth Verification**:
> The `https://www.googleapis.com/auth/drive` scope is classified by Google as a **Restricted Scope**. While in "Testing" publishing status, only registered test users can connect. For public multi-tenant production, Google requires OAuth App Verification and a CASA Tier 2/3 security assessment.

---

## 5. ChatGPT MCP Setup

1. In ChatGPT, navigate to **Explore GPTs** -> **Create a GPT** (or Actions configuration).
2. Add an Action pointing to your MCP endpoint:
   - **Authentication Type**: OAuth
   - **Client ID**: Your configured `CHATGPT_OAUTH_CLIENT_ID`
   - **Client Secret**: Your configured `CHATGPT_OAUTH_CLIENT_SECRET`
   - **Authorization URL**: `https://mcp-v2.digitonsdevelopment.com/authorize`
   - **Token URL**: `https://mcp-v2.digitonsdevelopment.com/token`
   - **Scope**: `drive`
   - **Token Exchange Method**: Default / Basic Authorization Header or Request Body
3. Copy the **Redirect URI** provided by ChatGPT and set it in your `.env` as `CHATGPT_OAUTH_REDIRECT_URI`.

---

## 6. Environment Variables

Create `.env` using the template below:

```env
# Server Configuration
PORT=3000
NODE_ENV=production
ALLOWED_HOST=mcp-v2.digitonsdevelopment.com
MCP_PUBLIC_ORIGIN=https://mcp-v2.digitonsdevelopment.com
MCP_PUBLIC_URL=https://mcp-v2.digitonsdevelopment.com/mcp

# Persistent Storage & Encryption (Outside Git & Deployment Directories)
DATA_DIR=/home/u142843264/.google-drive-mcp-v2
STORAGE_ENCRYPTION_KEY=64-char-hex-string-for-aes-256-gcm-storage-encryption

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://mcp-v2.digitonsdevelopment.com/oauth2callback
GOOGLE_DRIVE_SCOPES=https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/documents

# ChatGPT OAuth Configuration
CHATGPT_OAUTH_CLIENT_ID=your-chatgpt-client-id
CHATGPT_OAUTH_CLIENT_SECRET=your-chatgpt-client-secret
CHATGPT_OAUTH_REDIRECT_URI=https://chatgpt.com/aip/.../oauth/callback

# Security & Rate Limiting
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_CODE_EXPIRY_SECONDS=300
ACCESS_TOKEN_EXPIRY_SECONDS=3600
REFRESH_TOKEN_EXPIRY_SECONDS=2592000
OAUTH_STATE_EXPIRY_SECONDS=600
OAUTH_GOOGLE_LINK_EXPIRY_SECONDS=600

# OpenAI Domain Verification Challenge
OPENAI_APPS_CHALLENGE_TOKEN=your-openai-apps-challenge-token

# Publisher & Support Information
SUPPORT_EMAIL=support@digitonsdevelopment.com
COMPANY_NAME=Digitons Development
COMPANY_WEBSITE=https://www.digitonsdevelopment.com
```

---

## 7. OpenAI Domain Verification & Public Submission

### Public Legal & Support URLs
The server provides public, unauthenticated informational and legal pages required for OpenAI Plugin/App Directory submission:
- **Support URL**: `https://mcp-v2.digitonsdevelopment.com/support`
- **Privacy Policy URL**: `https://mcp-v2.digitonsdevelopment.com/privacy`
- **Terms of Service URL**: `https://mcp-v2.digitonsdevelopment.com/terms`
- **Overview / Landing Page**: `https://mcp-v2.digitonsdevelopment.com/`

### Domain Verification Challenge
When submitting your MCP server to the OpenAI Plugin/App Directory, OpenAI requires domain ownership verification:
- Endpoint: `GET /.well-known/openai-apps-challenge`
- Response: Pure plain text (`text/plain; charset=utf-8`) containing only the token.
- Configuration: Set `OPENAI_APPS_CHALLENGE_TOKEN` in `.env`.
- Caching: Responses include `Cache-Control: no-store, no-cache, must-revalidate` to prevent CDN caching issues.
- Fallback: Returns 404 Not Found if `OPENAI_APPS_CHALLENGE_TOKEN` is unset or empty.

### OpenAI Public Submission Checklist
- [x] **Public Support Page**: `GET /support` provides user setup guides, troubleshooting, disconnect instructions, and support contacts.
- [x] **Privacy Policy**: `GET /privacy` accurately details Google Drive data access, restricted file token storage (`0600`/`0700`), single-use hashed link tokens, and token-redacted audit logs.
- [x] **Terms of Service**: `GET /terms` establishes acceptable use, file size boundaries (10MB), non-destructive trash safeguards, and liability limitations.
- [x] **Tool Annotations**: All 23 tools advertise `readOnlyHint`, `openWorldHint`, and `destructiveHint` both at top-level and inside `annotations`.
- [x] **Domain Challenge Endpoint**: `GET /.well-known/openai-apps-challenge` is live and returns plain text.
- [x] **OAuth Discovery Metadata**: `GET /.well-known/oauth-authorization-server` advertises `"code_challenge_methods_supported": ["S256"]` with `Cache-Control: no-store`.
- [x] **OpenID Configuration**: `GET /.well-known/openid-configuration` is supported as an alias for OIDC discovery clients.
- [x] **Strict Host Validation**: Validates `ALLOWED_HOST` (`mcp-v2.digitonsdevelopment.com`) and rejects unexpected hosts.
- [x] **Multi-User Isolation**: Every user connects their own Google account. No global or shared tokens exist.
- [x] **Destructive Action Safeguards**: Overwrite tools have `destructiveHint: true`. Ownership transfer is strictly blocked.
- [x] **Zero Stack Trace Leaks**: Production errors return safe, predictable error codes without stack traces.

---

## 8. Hostinger Deployment Guide

1. **Domain Configuration**:
   Configure DNS for `mcp-v2.digitonsdevelopment.com` pointing to your Hostinger server IP. Ensure SSL is activated.

2. **Persistent Directory**:
   Create the persistent storage directory outside the webroot / deployment directories:
   ```bash
   mkdir -p /home/u142843264/.google-drive-mcp-v2
   chmod 700 /home/u142843264/.google-drive-mcp-v2
   ```

3. **Node.js Setup (Passenger or PM2)**:
   - Node.js version: **22.x** or higher.
   - Application Root: `/home/u142843264/public_html/mcp-v2` (or Hostinger application path).
   - Startup File: `src/server.js`.
   - Environment: `NODE_ENV=production`.

4. **Process Restart & Startup Compatibility**:
   - `src/server.js` contains **no top-level await** in the startup path.
   - Gracefully handles `SIGTERM` and `SIGINT` signals.

---

## 9. Local Setup & Testing

### Install Dependencies
```bash
npm install
```

### Syntax Validation
```bash
npm run check
```

### Run Automated Test Suite
```bash
npm test
```

The test suite runs 130 comprehensive automated tests across 8 suites:
- `test/pages-test.js`: Public informational and legal pages (`/privacy`, `/terms`, `/support`, `/`), unauthenticated access, content completeness, link integrity, and zero secret/token leakage.
- `test/google-link-test.js`: One-time Google link token generation, single-use atomic consumption, expiration, replay rejection, User A vs User B isolation, direct Bearer requirement, error messaging, audit sanitization, and full end-to-end connect journey.
- `test/oauth-test.js`: RFC discovery, PKCE S256 verification, token rotation, code replay, OpenID alias, and expiry checks.
- `test/multi-user-test.js`: User A vs User B credential isolation, disconnect isolation, per-user token refresh.
- `test/drive-write-test.js`: All 31 tools (Read, Write, Docs, Sheets, Slides, Permissions, Core deletions & restorations, SEC-05 single retry rules).
- `test/security-test.js`: State replay/expiry/CSRF, IDOR prevention, ownership transfer blocking, host validation, log sanitization, and `0600` file permissions.
- `test/annotations-test.js`: All 31 tool hints (`readOnlyHint`, `openWorldHint`, `destructiveHint`) and OpenAI domain verification challenge tests.
- `test/crypto-storage-test.js`: AES-256-GCM authenticated encryption at rest, key derivation, tampering resistance, migration, and key-rotation safeguards.

---

## 10. Limitations & Best Practices

- **File Size**: Upload and text export are capped at 10MB to prevent memory exhaustion and excessive latency.
- **Trash vs Permanent Delete**: Permanent file deletion is disabled by design. Files are moved to Google Drive Trash (`trashed: true`) to safeguard against accidental data destruction.
- **Ownership Transfer**: Transferring file ownership via permissions API is strictly blocked.
