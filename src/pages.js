/**
 * Public Informational Pages Module
 * Renders Privacy Policy, Terms of Service, Support, and Landing pages for digitons-google-drive-mcp-v2.
 * Clean, modern, self-contained HTML accessible without authentication.
 */

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getBaseLayout({ title, activeNav, content, description }) {
  const companyName = escapeHtml(process.env.COMPANY_NAME || 'Digitons Development');
  const companyWebsite = escapeHtml(process.env.COMPANY_WEBSITE || 'https://www.digitonsdevelopment.com');
  const supportEmail = escapeHtml(process.env.SUPPORT_EMAIL || 'support@digitonsdevelopment.com');

  const pageTitle = activeNav === 'home'
    ? 'Digitons Google Drive MCP V2'
    : `${escapeHtml(title)} - Digitons Google Drive MCP V2`;

  const metaDescription = description || (activeNav === 'home'
    ? 'Digitons Google Drive MCP V2 is a secure multi-user remote MCP server that allows ChatGPT and OpenAI Agents to access and manage authorized Google Drive files.'
    : `${escapeHtml(title)} for Digitons Google Drive MCP V2.`);

  const canonicalUrl = `https://mcp-v2.digitonsdevelopment.com${activeNav === 'home' ? '/' : '/' + activeNav}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${pageTitle}</title>
  <meta name="description" content="${escapeHtml(metaDescription)}">
  <link rel="canonical" href="${canonicalUrl}">
  <meta property="og:title" content="${pageTitle}">
  <meta property="og:description" content="${escapeHtml(metaDescription)}">
  <meta property="og:type" content="website">
  <meta property="og:url" content="${canonicalUrl}">
  <meta property="og:site_name" content="Digitons Google Drive MCP V2">
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --primary: #38bdf8;
      --primary-hover: #0284c7;
      --accent: #34d399;
      --accent-dim: rgba(52, 211, 153, 0.1);
      --font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--font-family);
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      display: flex;
      flex-direction: column;
      min-height: 100vh;
      padding: 0;
    }
    header {
      border-bottom: 1px solid var(--card-border);
      background: rgba(15, 23, 42, 0.8);
      backdrop-filter: blur(8px);
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .nav-container {
      max-width: 960px;
      margin: 0 auto;
      padding: 16px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }
    .brand {
      font-size: 18px;
      font-weight: 700;
      color: var(--text);
      text-decoration: none;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    nav {
      display: flex;
      gap: 18px;
      align-items: center;
    }
    nav a {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      transition: color 0.15s ease;
    }
    nav a:hover, nav a.active {
      color: var(--primary);
    }
    main {
      flex: 1;
      max-width: 960px;
      width: 100%;
      margin: 0 auto;
      padding: 40px 24px 60px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 36px;
      margin-bottom: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
    }
    h1 {
      font-size: 30px;
      font-weight: 800;
      color: #fff;
      margin-bottom: 8px;
      letter-spacing: -0.5px;
    }
    .page-subtitle {
      font-size: 15px;
      color: var(--text-muted);
      margin-bottom: 32px;
    }
    h2 {
      font-size: 20px;
      font-weight: 700;
      color: #e2e8f0;
      margin-top: 32px;
      margin-bottom: 12px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--card-border);
    }
    h3 {
      font-size: 16px;
      font-weight: 600;
      color: var(--primary);
      margin-top: 20px;
      margin-bottom: 8px;
    }
    p {
      color: #cbd5e1;
      font-size: 15px;
      margin-bottom: 16px;
    }
    ul, ol {
      margin-left: 24px;
      margin-bottom: 20px;
      color: #cbd5e1;
      font-size: 15px;
    }
    li {
      margin-bottom: 8px;
    }
    code {
      background: #0f172a;
      border: 1px solid #334155;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 13px;
      color: #38bdf8;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .badge {
      display: inline-block;
      font-size: 12px;
      padding: 3px 10px;
      border-radius: 6px;
      font-weight: 600;
    }
    .badge-success {
      background: var(--accent-dim);
      color: var(--accent);
      border: 1px solid rgba(52, 211, 153, 0.3);
    }
    .info-box {
      background: #0f172a;
      border-left: 4px solid var(--primary);
      padding: 16px 20px;
      border-radius: 0 8px 8px 0;
      margin: 20px 0;
      font-size: 14px;
      color: #cbd5e1;
    }
    .step-card {
      background: #0f172a;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
    }
    .step-number {
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 6px;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    footer {
      border-top: 1px solid var(--card-border);
      background: #090d16;
      padding: 28px 24px;
      color: var(--text-dim);
      font-size: 13px;
    }
    .footer-container {
      max-width: 960px;
      margin: 0 auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }
    .footer-links {
      display: flex;
      gap: 18px;
    }
    .footer-links a {
      color: var(--text-muted);
      text-decoration: none;
      transition: color 0.15s ease;
    }
    .footer-links a:hover {
      color: var(--primary);
    }
    a.btn {
      display: inline-block;
      background: #0284c7;
      color: #fff;
      padding: 10px 18px;
      border-radius: 8px;
      text-decoration: none;
      font-size: 14px;
      font-weight: 600;
      transition: background 0.15s ease;
    }
    a.btn:hover {
      background: #0369a1;
    }
    @media (max-width: 640px) {
      .card { padding: 24px; }
      h1 { font-size: 24px; }
      .nav-container { flex-direction: column; align-items: flex-start; }
      nav { flex-wrap: wrap; }
      .footer-container { flex-direction: column; align-items: flex-start; }
    }
  </style>
</head>
<body>
  <header>
    <div class="nav-container">
      <a href="/" class="brand">
        📁 Digitons Google Drive MCP V2
      </a>
      <nav>
        <a href="/" ${activeNav === 'home' ? 'class="active"' : ''}>Overview</a>
        <a href="/support" ${activeNav === 'support' ? 'class="active"' : ''}>Support</a>
        <a href="/privacy" ${activeNav === 'privacy' ? 'class="active"' : ''}>Privacy Policy</a>
        <a href="/terms" ${activeNav === 'terms' ? 'class="active"' : ''}>Terms of Service</a>
      </nav>
    </div>
  </header>

  <main>
    ${content}
  </main>

  <footer>
    <div class="footer-container">
      <div>© ${new Date().getFullYear()} ${companyName}. All rights reserved. • Hosted on digitonsdevelopment.com</div>
      <div class="footer-links">
        <a href="/">Overview</a>
        <a href="/support">Support</a>
        <a href="/privacy">Privacy Policy</a>
        <a href="/terms">Terms of Service</a>
        <a href="${companyWebsite}" target="_blank" rel="noopener">Publisher Website</a>
      </div>
    </div>
  </footer>
</body>
</html>`;
}

/**
 * GET / - Public landing / overview page
 */
export function handleRootPage(req, res) {
  const supportEmail = escapeHtml(process.env.SUPPORT_EMAIL || 'support@digitonsdevelopment.com');
  const companyName = escapeHtml(process.env.COMPANY_NAME || 'Digitons Development');
  const companyWebsite = escapeHtml(process.env.COMPANY_WEBSITE || 'https://www.digitonsdevelopment.com');

  const content = `
    <div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <span class="badge badge-success">Production Ready</span>
        <span style="font-size:13px;color:#94a3b8;">Universal Model Context Protocol Server</span>
      </div>
      <h1>Digitons Google Drive MCP V2</h1>
      <p class="page-subtitle">Multi-User Remote MCP Server for ChatGPT & OpenAI Agents</p>

      <p>
        <strong>Digitons Google Drive MCP V2</strong> is a secure, production-ready remote Model Context Protocol (MCP) server developed and operated by <strong>${companyName}</strong>. It seamlessly connects ChatGPT and OpenAI Agents with the user's authorized Google Drive, allowing AI assistants to search, read, create, and organize files and Workspace documents directly from conversational prompts.
      </p>

      <div class="info-box">
        <strong>Multi-User Remote Architecture:</strong> Every connected user authenticates their own individual Google account through isolated, per-user Google OAuth 2.0. There are no shared service accounts, master credentials, or cross-tenant data access.
      </div>

      <h2>What the Application Does</h2>
      <p>
        <strong>Digitons Google Drive MCP V2</strong> translates conversational instructions from ChatGPT and OpenAI Agents into authorized Google Drive API operations in real time:
      </p>
      <ul>
        <li><strong>Search & Read:</strong> Query Google Drive with semantic keywords, browse folders, read plain-text and binary files, export Google Docs/Sheets/Slides, and inspect detailed file metadata.</li>
        <li><strong>Create & Organize:</strong> Create new folders, upload text/data files, move items between folders, rename documents, copy files, and safely move unwanted files to Trash.</li>
        <li><strong>Google Sheets & Workspace:</strong> Create new Google Spreadsheets, read cell ranges in A1 notation, update tabular data, append rows, and generate presentation slide decks.</li>
        <li><strong>Access Governance:</strong> List file sharing permissions and audit who has access to your items.</li>
      </ul>

      <h2>Verified Publisher & Hosting Information</h2>
      <p>
        This service is officially developed and operated by <strong>${companyName}</strong>, hosted at <code>https://mcp-v2.digitonsdevelopment.com</code> under the verified parent domain <strong><a href="${companyWebsite}" target="_blank" rel="noopener" style="color:#38bdf8;">digitonsdevelopment.com</a></strong>. All OAuth 2.0 authorizations are conducted directly and securely between your client, this server, and Google APIs.
      </p>

      <h2>Quick Links & Legal Documentation</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:16px;margin-top:16px;">
        <div class="step-card">
          <div class="step-number">Help & Setup</div>
          <h3 style="margin-top:0;"><a href="/support" style="color:#38bdf8;text-decoration:none;">Support Center →</a></h3>
          <p style="font-size:13px;margin-bottom:0;">Step-by-step setup guide, connection instructions, and troubleshooting tips.</p>
        </div>
        <div class="step-card">
          <div class="step-number">Privacy</div>
          <h3 style="margin-top:0;"><a href="/privacy" style="color:#38bdf8;text-decoration:none;">Privacy Policy →</a></h3>
          <p style="font-size:13px;margin-bottom:0;">Full disclosure of data protection, credential isolation, and Google API User Data Policy compliance.</p>
        </div>
        <div class="step-card">
          <div class="step-number">Terms</div>
          <h3 style="margin-top:0;"><a href="/terms" style="color:#38bdf8;text-decoration:none;">Terms of Service →</a></h3>
          <p style="font-size:13px;margin-bottom:0;">Acceptable use guidelines, operational limits, safety safeguards, and legal terms.</p>
        </div>
      </div>
    </div>
  `;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(getBaseLayout({
    title: 'Overview',
    activeNav: 'home',
    content
  }));
}

/**
 * GET /privacy - Public Privacy Policy page
 */
export function handlePrivacyPage(req, res) {
  const companyName = escapeHtml(process.env.COMPANY_NAME || 'Digitons Development');
  const supportEmail = escapeHtml(process.env.SUPPORT_EMAIL || 'support@digitonsdevelopment.com');

  const content = `
    <div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <span class="badge badge-success">Legal Document</span>
        <span style="font-size:13px;color:#94a3b8;">Last Updated: September 2026</span>
      </div>
      <h1>Privacy Policy</h1>
      <p class="page-subtitle">How Digitons Google Drive MCP V2 handles and protects your data</p>

      <h2>1. Overview & Service Identity</h2>
      <p>
        This Privacy Policy explains how <strong>Digitons Google Drive MCP V2</strong> ("the Service"), developed and operated by <strong>${companyName}</strong>, collects, processes, stores, and protects user data when connecting ChatGPT and OpenAI Agents to Google Drive.
      </p>

      <h2>2. Multi-User Architecture & Zero Shared Credentials</h2>
      <p>
        The Service is built on an isolated multi-user architecture:
      </p>
      <ul>
        <li>Each user connects their own personal or organizational Google account.</li>
        <li>There is no global Google service account, master user, or shared credential.</li>
        <li>User A cannot view, access, or modify files belonging to User B.</li>
        <li>MCP tool handlers never trust client-supplied user identifiers; all operations are bound cryptographically to the authenticated user identity.</li>
      </ul>

      <h2>3. Data Accessed & Handled</h2>
      <p>
        When you invoke Google Drive tools through ChatGPT, the Service accesses the following data strictly on an on-demand basis:
      </p>
      <ul>
        <li><strong>Google Drive Files & Metadata:</strong> File names, IDs, MIME types, folder structures, and file contents requested explicitly during your ChatGPT conversation.</li>
        <li><strong>Google Account Identity:</strong> Email address and profile display name retrieved from Google's userinfo endpoint to verify and display connection status.</li>
        <li><strong>OAuth Authentication Tokens:</strong> Google OAuth 2.0 access and refresh tokens necessary to maintain authorized API communication.</li>
      </ul>
      <p>
        We do <em>not</em> perform background harvesting, bulk indexing, or training of machine learning models on your Google Drive files.
      </p>

      <h2>4. Google Scopes Requested</h2>
      <p>
        The Service requests authorization for:
      </p>
      <ul>
        <li><code>https://www.googleapis.com/auth/drive</code>: Permits searching, reading, creating, and updating Google Drive files as instructed by you in ChatGPT.</li>
        <li><code>https://www.googleapis.com/auth/userinfo.email</code>: Identifies the connected Google account for connection status reporting.</li>
        <li><code>https://www.googleapis.com/auth/userinfo.profile</code>: Displays your account name on the connection confirmation page.</li>
      </ul>
      <p>
        The Service's use and transfer of information received from Google APIs to any other app will adhere to the <a href="https://developers.google.com/terms/api-services-user-data-policy" target="_blank" rel="noopener" style="color:#38bdf8;">Google API Services User Data Policy</a>, including the Limited Use requirements.
      </p>

      <h2>5. Server Storage & Security Safeguards</h2>
      <p>
        We implement technical and organizational measures to safeguard your credentials and session state:
      </p>
      <ul>
        <li><strong>File System Permissions:</strong> Persistent credential storage files (e.g., <code>google-users.json</code>) are stored outside web-accessible deployment directories and protected with strict POSIX file permissions (mode <code>0600</code>, readable and writable only by the process owner). Parent directories are restricted with mode <code>0700</code>.</li>
        <li><strong>Storage Classification:</strong> Data is protected via operating system access controls, filesystem permissions, and process isolation. Data files are not encrypted at rest.</li>
        <li><strong>One-Time Link Tokens:</strong> Linking your Google account uses cryptographically random link tokens (<code>glink_...</code>). Only a SHA-256 hash of the token is stored on the server. Tokens expire in 10 minutes (<code>OAUTH_GOOGLE_LINK_EXPIRY_SECONDS=600</code>) and are atomically deleted upon first use to prevent replay.</li>
        <li><strong>No Tokens in URLs:</strong> MCP Bearer access tokens are never placed into browser URLs, query parameters, HTML, or responses.</li>
        <li><strong>Host Header Validation:</strong> Strict host verification enforces communication through <code>mcp-v2.digitonsdevelopment.com</code>.</li>
      </ul>

      <h2>6. Audit Logging & Token Redaction</h2>
      <p>
        The Service records structured audit logs to ensure system reliability and investigate operational issues. Logs record timestamps, user subjects, tool action names, and status codes.
      </p>
      <div class="info-box">
        <strong>Strict Token Redaction:</strong> All authentication tokens, authorization codes, client secrets, Google OAuth states, and link tokens are automatically filtered and redacted (<code>[REDACTED]</code>) prior to logging.
      </div>

      <h2>7. Third-Party Services Used</h2>
      <p>
        The Service interfaces with:
      </p>
      <ul>
        <li><strong>Google APIs:</strong> Google Drive, Docs, Sheets, and Slides APIs to execute requested operations.</li>
        <li><strong>OpenAI / ChatGPT:</strong> Receives Model Context Protocol (MCP) requests initiated by the user.</li>
      </ul>

      <h2>8. Data Retention & Account Disconnection</h2>
      <p>
        Google tokens are retained only as long as you maintain your connection with the Service. You can disconnect and revoke access at any time:
      </p>
      <ul>
        <li><strong>Via MCP:</strong> Issue a disconnect request in ChatGPT (executes <code>POST /auth/google/disconnect</code>), which immediately revokes tokens with Google and permanently purges local records.</li>
        <li><strong>Via Google Account Settings:</strong> Revoke access directly under <a href="https://myaccount.google.com/permissions" target="_blank" rel="noopener" style="color:#38bdf8;">Google Third-Party Apps & Services</a>.</li>
      </ul>

      <h2>9. Contact & Inquiries</h2>
      <p>
        For questions or requests concerning your privacy, please contact our team:
      </p>
      <p>
        <strong>Email:</strong> <a href="mailto:${supportEmail}" style="color:#38bdf8;">${supportEmail}</a><br>
        <strong>Publisher:</strong> ${companyName}
      </p>
    </div>
  `;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(getBaseLayout({
    title: 'Privacy Policy',
    activeNav: 'privacy',
    content
  }));
}

/**
 * GET /terms - Public Terms of Service page
 */
export function handleTermsPage(req, res) {
  const companyName = escapeHtml(process.env.COMPANY_NAME || 'Digitons Development');
  const supportEmail = escapeHtml(process.env.SUPPORT_EMAIL || 'support@digitonsdevelopment.com');

  const content = `
    <div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <span class="badge badge-success">Legal Agreement</span>
        <span style="font-size:13px;color:#94a3b8;">Last Updated: September 2026</span>
      </div>
      <h1>Terms of Service</h1>
      <p class="page-subtitle">Terms governing the use of Digitons Google Drive MCP V2</p>

      <h2>1. Acceptance of Terms</h2>
      <p>
        By connecting to or using <strong>Digitons Google Drive MCP V2</strong> ("the Service"), provided by <strong>${companyName}</strong> ("we," "us," or "our"), you agree to be bound by these Terms of Service. If you do not agree to these Terms, do not connect or use the Service.
      </p>

      <h2>2. Description of Service</h2>
      <p>
        The Service is a remote Model Context Protocol (MCP) server that enables AI clients (such as OpenAI's ChatGPT) to interact with your Google Drive account upon your explicit authorization. The Service translates user instructions into Google Drive API operations (search, read, write, organize, and export).
      </p>

      <h2>3. User Responsibilities & Google Authorizations</h2>
      <ul>
        <li>You must possess an active, valid Google account with authority to access and manage the Drive files requested.</li>
        <li>You are solely responsible for reviewing and confirming actions executed by ChatGPT on your Drive files.</li>
        <li>You agree to keep your ChatGPT and Google credentials secure and not share authorization links with unauthorized parties.</li>
      </ul>

      <h2>4. Acceptable Use Policy</h2>
      <p>You agree not to use the Service to:</p>
      <ul>
        <li>Violate any local, national, or international law or regulation.</li>
        <li>Attempt unauthorized access to our servers, infrastructure, or other users' storage.</li>
        <li>Bypass or attempt to bypass rate limiting, token expiration, or security controls.</li>
        <li>Store or transmit malicious software, viruses, or harmful code.</li>
        <li>Infringe upon the intellectual property or privacy rights of any party.</li>
      </ul>

      <h2>5. Safety Safeguards & Operational Limits</h2>
      <p>To protect user data and maintain service availability, the following technical restrictions apply:</p>
      <ul>
        <li><strong>Trash Overwrite Safety:</strong> Permanent file deletion is disabled. Files requested to be deleted are moved to Google Drive Trash (<code>trashed: true</code>).</li>
        <li><strong>Ownership Transfer Restriction:</strong> Transferring ownership of files to external accounts via permission APIs is prohibited.</li>
        <li><strong>File Size Threshold:</strong> File uploads and text exports are capped at 10 MB per operation.</li>
        <li><strong>Rate Limiting:</strong> Endpoints are rate-limited to preserve service stability.</li>
      </ul>

      <h2>6. Third-Party Services & Dependencies</h2>
      <p>
        The Service relies on third-party infrastructure and platforms, including Google LLC (Google APIs) and OpenAI, Inc. (ChatGPT). We do not control and are not responsible for the performance, availability, or policies of these third parties.
      </p>

      <h2>7. Disclaimer of Warranties</h2>
      <p>
        THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT. WE DO NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED, ERROR-FREE, OR COMPLETELY SECURE.
      </p>

      <h2>8. Limitation of Liability</h2>
      <p>
        TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL ${companyName.toUpperCase()}, ITS DIRECTORS, EMPLOYEES, OR AGENTS BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS, DATA, USE, OR GOODWILL ARISING OUT OF OR IN CONNECTION WITH YOUR ACCESS OR USE OF THE SERVICE.
      </p>

      <h2>9. Suspension & Termination</h2>
      <p>
        We reserve the right to suspend or terminate access to the Service for any user who violates these Terms or engages in abusive activity. You may terminate your use of the Service at any time by disconnecting your Google account and removing the MCP server from your ChatGPT settings.
      </p>

      <h2>10. Governing Law</h2>
      <p>
        These Terms shall be governed by and construed in accordance with the laws of the jurisdiction in which ${companyName} is registered, without regard to its conflict of law principles.
      </p>

      <h2>11. Contact Information</h2>
      <p>
        For inquiries regarding these Terms, please contact:
      </p>
      <p>
        <strong>Email:</strong> <a href="mailto:${supportEmail}" style="color:#38bdf8;">${supportEmail}</a>
      </p>
    </div>
  `;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(getBaseLayout({
    title: 'Terms of Service',
    activeNav: 'terms',
    content
  }));
}

/**
 * GET /support - Public Support and Help Center page
 */
export function handleSupportPage(req, res) {
  const companyName = escapeHtml(process.env.COMPANY_NAME || 'Digitons Development');
  const supportEmail = escapeHtml(process.env.SUPPORT_EMAIL || 'support@digitonsdevelopment.com');

  const content = `
    <div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <span class="badge badge-success">Help Center</span>
        <span style="font-size:13px;color:#94a3b8;">Digitons Google Drive MCP V2</span>
      </div>
      <h1>Support & Help Center</h1>
      <p class="page-subtitle">Guides, troubleshooting, and contact for Digitons Google Drive MCP V2</p>

      <h2>How to Connect Your Google Drive</h2>
      <div class="step-card">
        <div class="step-number">Step 1</div>
        <h3>Install the Connector</h3>
        <p>Add the MCP server URL in ChatGPT (<strong>Settings → Connected Apps / MCP</strong>):</p>
        <code>https://mcp-v2.digitonsdevelopment.com/mcp</code>
      </div>

      <div class="step-card">
        <div class="step-number">Step 2</div>
        <h3>Ask ChatGPT to Access Drive</h3>
        <p>Ask ChatGPT to perform any Drive task, such as:</p>
        <code>"Search my Google Drive for Q3 Financials"</code>
      </div>

      <div class="step-card">
        <div class="step-number">Step 3</div>
        <h3>Open the Secure One-Time Link</h3>
        <p>ChatGPT will reply with a secure connection link unique to your session:</p>
        <code>https://mcp-v2.digitonsdevelopment.com/auth/google/link?code=glink_...</code>
        <p style="font-size:13px;color:#94a3b8;margin-top:8px;">This link is single-use, expires in 10 minutes, and binds your Google account directly to your ChatGPT identity.</p>
      </div>

      <div class="step-card">
        <div class="step-number">Step 4</div>
        <h3>Grant Google Permissions</h3>
        <p>Select your Google account on the Google consent screen and grant Drive permissions. After authorizing, you will see a confirmation screen.</p>
      </div>

      <div class="step-card">
        <div class="step-number">Step 5</div>
        <h3>Return to ChatGPT</h3>
        <p>Close the browser tab and return to ChatGPT. Your queries will now execute against your personal Google Drive account.</p>
      </div>

      <h2>Troubleshooting Common Issues</h2>

      <h3>1. "Connection Link Expired or Invalid"</h3>
      <p>
        Connection links expire after 10 minutes or upon their first click. If a link expires, simply ask ChatGPT to perform a Drive search again; a fresh, valid link will be generated automatically.
      </p>

      <h3>2. "Wrong Google Account Connected"</h3>
      <p>
        If you connected the wrong Google account, disconnect it first (see instructions below) and open a new link while logged into your preferred Google account.
      </p>

      <h3>3. "File Too Large"</h3>
      <p>
        The Service enforces a 10 MB per-file upload and read threshold to prevent timeouts and optimize model response speed.
      </p>

      <h3>4. "Rate Limit Exceeded"</h3>
      <p>
        To preserve stability, endpoints enforce request rate limits. If exceeded, wait 60 seconds and retry.
      </p>

      <h2>How to Disconnect Google Drive</h2>
      <p>You can disconnect your Google Drive at any time through either of these methods:</p>
      <ul>
        <li><strong>Through ChatGPT:</strong> Ask ChatGPT to disconnect your Google Drive account, which calls <code>POST /auth/google/disconnect</code>. This revokes the tokens with Google and immediately purges local credentials.</li>
        <li><strong>Through Google Account:</strong> Visit <a href="https://myaccount.google.com/permissions" target="_blank" rel="noopener" style="color:#38bdf8;">Google Third-Party Apps & Services</a> and click <em>Remove Access</em> for Digitons Google Drive MCP V2.</li>
      </ul>

      <h2>Contact Support</h2>
      <p>Need assistance or found an issue? Reach out directly to our engineering support:</p>
      <div class="info-box">
        <strong>Email Support:</strong> <a href="mailto:${supportEmail}" style="color:#38bdf8;font-weight:600;">${supportEmail}</a><br>
        <strong>Publisher:</strong> ${companyName}<br>
        <strong>Hours:</strong> Mon - Fri, 9:00 AM - 6:00 PM EST
      </div>

      <h2>Documentation Links</h2>
      <p>
        Review our full legal policies:
      </p>
      <ul>
        <li><a href="/privacy" style="color:#38bdf8;">Privacy Policy</a></li>
        <li><a href="/terms" style="color:#38bdf8;">Terms of Service</a></li>
      </ul>
    </div>
  `;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(getBaseLayout({
    title: 'Support',
    activeNav: 'support',
    content
  }));
}
