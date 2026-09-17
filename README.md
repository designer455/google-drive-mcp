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

## 2. MCP Tools Reference (23 Tools)

### Read Tools (5)
- **`drive_search`**: Search files matching a query string (e.g., `name contains 'Report' and trashed = false`). Supports pagination and sorting.
- **`drive_list_folder`**: List items inside a specific folder ID (default: `'root'`).
- **`drive_get_metadata`**: Retrieve detailed metadata for a file or folder.
- **`drive_read_file`**: Read file contents (exports Google Docs, Sheets, and Slides to text/csv, or downloads text/data files up to 10MB).
- **`drive_search_and_read`**: Search for a file by query and immediately return the content of the first matching file.

### Write Tools (7)
- **`drive_create_file`**: Create a new text or data file with name, MIME type, content, and optional parent folder.
- **`drive_create_folder`**: Create a new folder in My Drive or Shared Drives.
- **`drive_update_file`**: Safely replace the content of an existing text or data file.
- **`drive_rename_file`**: Rename an existing file or folder.
- **`drive_move_file`**: Move a file or folder from its existing parents to a new target folder.
- **`drive_copy_file`**: Create a copy of an existing file.
- **`drive_trash_file`**: Safely move a file to the trash (`trashed: true`). Never permanently deletes.

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

### B. Per-User Google OAuth Flow
1. User connects MCP server to ChatGPT.
2. User asks ChatGPT to perform a Drive operation.
3. If Google account is not connected, the server returns a `GOOGLE_NOT_CONNECTED` response with a link:
   `https://mcp-v2.digitonsdevelopment.com/auth/google`
4. User clicks link, visits Google OAuth consent screen with `prompt=consent` and `access_type=offline`.
5. Google returns authorization code to `GET /oauth2callback`.
6. Server atomically consumes state, associates credentials with the user's `sub`, and stores tokens in `DATA_DIR/google-users.json` (`0600`).
7. Subsequent Drive operations automatically use that user's Google OAuth client.

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

# Persistent Storage (Outside Git & Deployment Directories)
DATA_DIR=/home/u142843264/.google-drive-mcp-v2

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://mcp-v2.digitonsdevelopment.com/oauth2callback
GOOGLE_DRIVE_SCOPES=https://www.googleapis.com/auth/drive

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
```

---

## 7. Hostinger Deployment Guide

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

## 8. Local Setup & Testing

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

The test suite runs 35 comprehensive automated tests across 4 suites:
- `test/oauth-test.js`: RFC discovery, PKCE S256 verification, token rotation, code replay and expiry checks.
- `test/multi-user-test.js`: User A vs User B credential isolation, disconnect isolation, per-user token refresh.
- `test/drive-write-test.js`: All 23 tools (Read, Write, Sheets, Slides, Permissions).
- `test/security-test.js`: State replay/expiry/CSRF, IDOR prevention, ownership transfer blocking, host validation, log sanitization, and `0600` file permissions.

---

## 9. Limitations & Best Practices

- **File Size**: Upload and text export are capped at 10MB to prevent memory exhaustion and excessive latency.
- **Trash vs Permanent Delete**: Permanent file deletion is disabled by design. Files are moved to Google Drive Trash (`trashed: true`) to safeguard against accidental data destruction.
- **Ownership Transfer**: Transferring file ownership via permissions API is strictly blocked.
