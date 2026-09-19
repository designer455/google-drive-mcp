# Vercel Deployment & Configuration Guide

This guide details how to deploy this replicated multi-user Google Drive MCP server to **Vercel** (`https://google-drive-mcp-six.vercel.app`).

---

## 1. Architecture on Vercel

- **Runtime**: Vercel Serverless Function (Node.js 22.x).
- **Entrypoint**: `api/index.js` routed via `vercel.json` rewrites.
- **Data Persistence**: Uses ephemeral `/tmp/.google-drive-mcp` on serverless instances, with AES-256-GCM encryption at rest.

---

## 2. Google Cloud Console Setup

1. Open [Google Cloud Console](https://console.cloud.google.com/).
2. Go to **APIs & Services** → **Credentials**.
3. Edit your OAuth 2.0 Client ID (Web application).
4. Under **Authorized redirect URIs**, add the Vercel callback URL:
   ```text
   https://google-drive-mcp-six.vercel.app/oauth2callback
   ```
5. Click **Save**.

---

## 3. Vercel Project Configuration

1. In [Vercel Dashboard](https://vercel.com/dashboard), click **Add New...** → **Project**.
2. Import the Git repository: `designer455/google-drive-mcp`.
3. In **Build and Output Settings**:
   - Framework Preset: **Other**
   - Root Directory: `./`
   - Build Command: Leave blank / default
   - Output Directory: Leave blank / default
4. In **Environment Variables**, add the following:

| Variable | Recommended Value for Vercel | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `production` | Production mode |
| `ALLOWED_HOST` | `google-drive-mcp-six.vercel.app` | Prevents Host Header injection |
| `MCP_PUBLIC_ORIGIN` | `https://google-drive-mcp-six.vercel.app` | Base public URL |
| `MCP_PUBLIC_URL` | `https://google-drive-mcp-six.vercel.app/mcp` | MCP endpoint |
| `GOOGLE_REDIRECT_URI` | `https://google-drive-mcp-six.vercel.app/oauth2callback` | Google OAuth callback |
| `GOOGLE_CLIENT_ID` | `your-google-client-id.apps.googleusercontent.com` | From Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | `your-google-client-secret` | From Google Cloud Console |
| `GOOGLE_DRIVE_SCOPES` | `https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/documents` | Scopes for Drive & Docs |
| `CHATGPT_OAUTH_CLIENT_ID` | `your-chatgpt-client-id` | Custom secret / hex string for ChatGPT |
| `CHATGPT_OAUTH_CLIENT_SECRET` | `your-chatgpt-client-secret` | Custom secret / hex string for ChatGPT |
| `CHATGPT_OAUTH_REDIRECT_URI` | `https://chatgpt.com/connector/oauth/...` | Provided by ChatGPT connector |
| `STORAGE_ENCRYPTION_KEY` | `64-character hex string` (e.g. from `openssl rand -hex 32`) | AES-256-GCM encryption key |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window (ms) |
| `RATE_LIMIT_MAX_REQUESTS` | `100` | Max requests per window |

5. Click **Deploy**.

---

## 4. ChatGPT Connector Setup for Vercel

1. In ChatGPT, navigate to **Settings** → **Connected apps** (or **Explore GPTs** → **Create/Edit GPT**).
2. Add a new MCP Action/Connector:
   - **MCP URL**: `https://google-drive-mcp-six.vercel.app/mcp`
   - **Authentication Type**: OAuth
   - **Client ID**: Your `CHATGPT_OAUTH_CLIENT_ID`
   - **Client Secret**: Your `CHATGPT_OAUTH_CLIENT_SECRET`
   - **Authorization URL**: `https://google-drive-mcp-six.vercel.app/authorize`
   - **Token URL**: `https://google-drive-mcp-six.vercel.app/token`
   - **Scope**: `drive`
3. Copy the **Redirect URI** provided by ChatGPT and ensure it matches `CHATGPT_OAUTH_REDIRECT_URI` in Vercel.
