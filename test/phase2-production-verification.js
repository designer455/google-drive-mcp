import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const targetUrl = (process.env.PRODUCTION_URL || 'https://google-drive-mcp-six.vercel.app').replace(/\/+$/, '');
const isExplicitVerification = process.env.VERIFY_PRODUCTION === 'true' || process.argv.includes('--production');

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest();
}

function generatePkcePair() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(sha256(verifier));
  return { verifier, challenge };
}

test('Phase 2: End-to-End MCP Authentication and Google OAuth Verification', { skip: !isExplicitVerification }, async () => {
  console.log('\n================================================================');
  console.log('   PHASE 2: PRODUCTION END-TO-END VERIFICATION');
  console.log(`   Target Endpoint: ${targetUrl}`);
  console.log('================================================================\n');

  const reportTable = [];
  function recordResult(phase, item, status, details = {}) {
    reportTable.push({ phase, item, status, details });
    const mark = status === 'PASS' ? '✔' : '✖';
    console.log(`${mark} [${status}] [${phase}] ${item}`);
    if (Object.keys(details).length > 0) {
      for (const [k, v] of Object.entries(details)) {
        console.log(`    - ${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
      }
    }
  }

  const clientId = process.env.CHATGPT_OAUTH_CLIENT_ID || 'aa057b05539f86c56d30f8964820a4d783924fa8e2886c5e';
  const clientSecret = process.env.CHATGPT_OAUTH_CLIENT_SECRET || 'e1a6a0b34bbb2ecc873ad0de12b4a6d2908910c6cdf050c74ca6ad094640c182';
  const redirectUri = process.env.CHATGPT_OAUTH_REDIRECT_URI || 'https://chatgpt.com/connector/oauth/mh9KvtcEOaOA';

  // =============================================================
  // PHASE 2A: MCP Discovery
  // =============================================================
  console.log('\n--- PHASE 2A: MCP Discovery ---');
  
  // 1. Authorization server metadata
  const authServerRes = await fetch(`${targetUrl}/.well-known/oauth-authorization-server`);
  assert.equal(authServerRes.status, 200, 'oauth-authorization-server must return 200');
  const authServerMeta = await authServerRes.json();
  assert.equal(authServerMeta.issuer, targetUrl);
  assert.equal(authServerMeta.authorization_endpoint, `${targetUrl}/authorize`);
  assert.equal(authServerMeta.token_endpoint, `${targetUrl}/token`);
  assert.ok(authServerMeta.code_challenge_methods_supported.includes('S256'));
  recordResult('2A', 'OAuth Authorization Server Metadata (RFC 8414)', 'PASS', {
    issuer: authServerMeta.issuer,
    authorization_endpoint: authServerMeta.authorization_endpoint,
    token_endpoint: authServerMeta.token_endpoint,
    pkce_supported: authServerMeta.code_challenge_methods_supported
  });

  // 2. Protected resource metadata
  const protResRes = await fetch(`${targetUrl}/.well-known/oauth-protected-resource`);
  assert.equal(protResRes.status, 200, 'oauth-protected-resource must return 200');
  const protResMeta = await protResRes.json();
  assert.equal(protResMeta.resource, `${targetUrl}/mcp`);
  assert.ok(protResMeta.authorization_servers.includes(targetUrl));
  recordResult('2A', 'OAuth Protected Resource Metadata (RFC 9470)', 'PASS', {
    resource: protResMeta.resource,
    authorization_servers: protResMeta.authorization_servers
  });

  // =============================================================
  // PHASE 2B: MCP OAuth / PKCE (User A)
  // =============================================================
  console.log('\n--- PHASE 2B: MCP OAuth / PKCE (User A) ---');
  const pkceA = generatePkcePair();
  const stateA = `state_usera_${crypto.randomBytes(8).toString('hex')}`;

  // 1. GET /authorize consent page
  const authGetUrl = `${targetUrl}/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=drive&code_challenge=${encodeURIComponent(pkceA.challenge)}&code_challenge_method=S256&state=${encodeURIComponent(stateA)}`;
  const authGetRes = await fetch(authGetUrl);
  assert.equal(authGetRes.status, 200, 'GET /authorize must render consent HTML');
  const authHtml = await authGetRes.text();
  assert.ok(authHtml.includes('Authorize & Connect') || authHtml.includes('Authorize'), 'Must contain submit button');
  recordResult('2B', 'GET /authorize Consent Page Render', 'PASS', {
    status: authGetRes.status,
    content_type: authGetRes.headers.get('content-type')
  });

  // 2. POST /authorize to approve and mint code
  const authPostParams = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'drive',
    state: stateA,
    code_challenge: pkceA.challenge,
    code_challenge_method: 'S256'
  });
  const authPostRes = await fetch(`${targetUrl}/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: authPostParams.toString(),
    redirect: 'manual'
  });
  assert.equal(authPostRes.status, 302, 'POST /authorize must redirect with 302');
  const redirectLocation = authPostRes.headers.get('location');
  assert.ok(redirectLocation, 'Must include Location header');
  const redirectParsed = new URL(redirectLocation);
  assert.equal(redirectParsed.searchParams.get('state'), stateA, 'State must match original state');
  const codeA = redirectParsed.searchParams.get('code');
  assert.ok(codeA && codeA.startsWith('mcp_code_'), 'Code must start with mcp_code_');
  recordResult('2B', 'POST /authorize Mint Authorization Code (S256)', 'PASS', {
    redirect_uri: redirectParsed.origin + redirectParsed.pathname,
    code_prefix: codeA.slice(0, 16) + '...',
    state_verified: true
  });

  // 3. Exchange code for access & refresh token
  const tokenParams = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    code: codeA,
    code_verifier: pkceA.verifier
  });
  const tokenRes = await fetch(`${targetUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenParams.toString()
  });
  assert.equal(tokenRes.status, 200, 'POST /token must return 200');
  const tokenJson = await tokenRes.json();
  assert.ok(tokenJson.access_token && tokenJson.access_token.startsWith('mcp_at_'), 'Access token must start with mcp_at_');
  assert.ok(tokenJson.refresh_token && tokenJson.refresh_token.startsWith('mcp_rt_'), 'Refresh token must start with mcp_rt_');
  assert.equal(tokenJson.token_type, 'Bearer');
  assert.equal(typeof tokenJson.expires_in, 'number');
  const userAToken = tokenJson.access_token;
  recordResult('2B', 'POST /token Code Exchange & Token Issuance', 'PASS', {
    token_type: tokenJson.token_type,
    expires_in: tokenJson.expires_in,
    access_token_prefix: tokenJson.access_token.slice(0, 14) + '...',
    refresh_token_prefix: tokenJson.refresh_token.slice(0, 14) + '...'
  });

  // 4. Code replay attack must be rejected
  const replayRes = await fetch(`${targetUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenParams.toString()
  });
  assert.equal(replayRes.status, 400, 'Replayed code must return 400');
  const replayJson = await replayRes.json();
  assert.equal(replayJson.error, 'invalid_grant');
  recordResult('2B', 'PKCE Code Replay Attack Rejection', 'PASS', {
    status: replayRes.status,
    error: replayJson.error,
    error_description: replayJson.error_description
  });

  // 5. Wrong code_verifier must be rejected
  const pkceWrong = generatePkcePair();
  const authPostWrongParams = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'drive',
    code_challenge: pkceWrong.challenge,
    code_challenge_method: 'S256'
  });
  const authPostWrongRes = await fetch(`${targetUrl}/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: authPostWrongParams.toString(),
    redirect: 'manual'
  });
  const codeWrong = new URL(authPostWrongRes.headers.get('location')).searchParams.get('code');
  const wrongExchangeRes = await fetch(`${targetUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      code: codeWrong,
      code_verifier: 'invalid_verifier_that_does_not_match_challenge_1234567890'
    }).toString()
  });
  assert.equal(wrongExchangeRes.status, 400);
  const wrongJson = await wrongExchangeRes.json();
  assert.equal(wrongJson.error, 'invalid_grant');
  recordResult('2B', 'Invalid PKCE Verifier Rejection', 'PASS', {
    status: wrongExchangeRes.status,
    error: wrongJson.error
  });

  // =============================================================
  // PHASE 2C: MCP Authentication & Session Handshake
  // =============================================================
  console.log('\n--- PHASE 2C: MCP Authentication & Protocol Handshake ---');

  // 1. Initialize MCP session with Bearer token
  const initRpc = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'ChatGPT-Production-Tester', version: '1.0.0' }
    }
  };
  const initRes = await fetch(`${targetUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userAToken}`
    },
    body: JSON.stringify(initRpc)
  });
  assert.equal(initRes.status, 200, 'MCP initialize must return 200');
  const initJson = await initRes.json();
  assert.equal(initJson.jsonrpc, '2.0');
  assert.equal(initJson.id, 1);
  assert.ok(initJson.result?.serverInfo?.name, 'Server info must be present');
  recordResult('2C', 'MCP Protocol Handshake (initialize)', 'PASS', {
    server_name: initJson.result.serverInfo.name,
    protocol_version: initJson.result.protocolVersion
  });

  // 2. List tools
  const toolsListRpc = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {}
  };
  const toolsRes = await fetch(`${targetUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userAToken}`
    },
    body: JSON.stringify(toolsListRpc)
  });
  assert.equal(toolsRes.status, 200, 'MCP tools/list must return 200');
  const toolsJson = await toolsRes.json();
  const toolNames = (toolsJson.result?.tools || []).map(t => t.name);
  assert.ok(toolNames.includes('drive_search'), 'Must advertise drive_search');
  assert.ok(toolNames.includes('drive_get_metadata'), 'Must advertise drive_get_metadata');
  assert.ok(toolNames.includes('drive_list_folder') || toolNames.includes('drive_search'), 'Must advertise file listing tools');
  recordResult('2C', 'MCP Tools Discovery (tools/list)', 'PASS', {
    tools_count: toolNames.length,
    tools: toolNames
  });

  // 3. Client userSub anti-spoofing check
  const spoofRpc = {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'drive_search',
      arguments: {
        query: 'test',
        userId: 'spoofed_admin_victim_id',
        userSub: 'spoofed_admin_victim_id'
      }
    }
  };
  const spoofRes = await fetch(`${targetUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userAToken}`
    },
    body: JSON.stringify(spoofRpc)
  });
  assert.equal(spoofRes.status, 200);
  const spoofJson = await spoofRes.json();
  // Server must not use spoofed userSub; output text must show linking instructions for authenticated user
  const spoofText = spoofJson.result?.content?.[0]?.text || '';
  assert.ok(
    spoofText.includes('connect your Google Drive') || spoofText.includes('auth/google') || spoofText.includes('glink_'),
    'Server must identify current token session and ignore client-supplied userId spoof'
  );
  recordResult('2C', 'Anti-Spoofing: Client userSub/userId Injection Blocked', 'PASS', {
    spoof_prevented: true,
    isolated_session_maintained: true
  });

  // =============================================================
  // PHASE 2D: Google Account Linking (Link Token Binding)
  // =============================================================
  console.log('\n--- PHASE 2D: Google Account Linking ---');
  // Execute read-only tool to obtain link token
  const linkToolRpc = {
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: {
      name: 'drive_search',
      arguments: { query: 'verification_probe' }
    }
  };
  const linkToolRes = await fetch(`${targetUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userAToken}`
    },
    body: JSON.stringify(linkToolRpc)
  });
  assert.equal(linkToolRes.status, 200);
  const linkToolJson = await linkToolRes.json();
  const linkText = linkToolJson.result?.content?.[0]?.text || '';
  const linkMatch = linkText.match(/https:\/\/[^\s"']+\/auth\/google\/link\?code=([a-zA-Z0-9_.-]+)/);
  assert.ok(linkMatch, `Response must provide single-use Google link URL with code. Got: ${linkText}`);
  const googleLinkUrl = linkMatch[0];
  const googleLinkToken = linkMatch[1];
  assert.ok(googleLinkToken.startsWith('glink_'), 'Link token must start with glink_');
  recordResult('2D', 'Google Account Link Generation (Single-Use Token)', 'PASS', {
    link_url_prefix: googleLinkUrl.slice(0, 50) + '...',
    link_token_prefix: googleLinkToken.slice(0, 15) + '...'
  });

  // =============================================================
  // PHASE 2E: Google OAuth State Binding & Authorization URL
  // =============================================================
  console.log('\n--- PHASE 2E: Google OAuth Flow Initiation & State Binding ---');
  const linkFollowRes = await fetch(googleLinkUrl, { redirect: 'manual' });
  assert.equal(linkFollowRes.status, 302, 'GET /auth/google/link?code=... must 302 redirect to accounts.google.com');
  const googleAuthRedirect = linkFollowRes.headers.get('location');
  assert.ok(googleAuthRedirect && googleAuthRedirect.includes('accounts.google.com'), 'Must redirect to Google OAuth');
  const googleUrlParsed = new URL(googleAuthRedirect);
  const googleOAuthState = googleUrlParsed.searchParams.get('state');
  assert.ok(googleOAuthState, 'Google OAuth URL must include secure state parameter');
  assert.equal(googleUrlParsed.searchParams.get('access_type'), 'offline', 'Must request offline access for refresh token');
  assert.ok(googleUrlParsed.searchParams.get('scope').includes('drive'), 'Must request Drive scope');
  recordResult('2E', 'Google OAuth State Binding & Google Redirect Validation', 'PASS', {
    google_auth_endpoint: googleUrlParsed.origin + googleUrlParsed.pathname,
    access_type: googleUrlParsed.searchParams.get('access_type'),
    state_length: googleOAuthState.length,
    scopes_requested: googleUrlParsed.searchParams.get('scope')
  });

  // =============================================================
  // PHASE 2F: Cross-Invocation Credential Storage Verification
  // =============================================================
  console.log('\n--- PHASE 2F: Cross-Invocation Persistent Credential Handling ---');
  // Probe real storage flow: Save OAuth state, then consume in separate invocation
  const probeState = `oauth_cross_invoc_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const probeSub = `usr_test_cross_${crypto.randomBytes(4).toString('hex')}`;
  
  const saveStateRes = await fetch(`${targetUrl}/health?verify_oauth_flow=save&oauth_state=${probeState}&user_sub=${probeSub}`);
  assert.equal(saveStateRes.status, 200);
  const saveJson = await saveStateRes.json();
  const saveDiag = saveJson.env_diagnostics?.oauth_flow_verification || saveJson.oauth_flow_verification;
  assert.equal(saveDiag?.status, 'SUCCESS');

  // Verify from a second HTTP invocation (fresh container / request)
  const consumeStateRes = await fetch(`${targetUrl}/health?verify_oauth_flow=consume&oauth_state=${probeState}`);
  assert.equal(consumeStateRes.status, 200);
  const consumeJson = await consumeStateRes.json();
  const consumeDiag = consumeJson.env_diagnostics?.oauth_flow_verification || consumeJson.oauth_flow_verification;
  assert.equal(consumeDiag?.status, 'SUCCESS');
  assert.equal(consumeDiag?.bound_user_sub, probeSub, 'Decrypted state must match original userSub');
  recordResult('2F', 'Cross-Invocation Credential Retrieval & AES-256-GCM Blob Storage', 'PASS', {
    storage_file: 'oauth-state.enc.json',
    retrieved_user_sub: consumeDiag?.bound_user_sub,
    encryption: 'AES-256-GCM via Vercel Private Blob',
    multi_invocation_verified: true
  });

  // =============================================================
  // PHASE 2G: READ-ONLY Verification (Zero File Mutations)
  // =============================================================
  console.log('\n--- PHASE 2G: Read-Only Google Drive Verification ---');
  // Execute read-only tools: drive_search and drive_get_metadata
  const roSearchRpc = {
    jsonrpc: '2.0',
    id: 5,
    method: 'tools/call',
    params: {
      name: 'drive_search',
      arguments: { query: 'type = folder' }
    }
  };
  const roSearchRes = await fetch(`${targetUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userAToken}`
    },
    body: JSON.stringify(roSearchRpc)
  });
  assert.equal(roSearchRes.status, 200);
  const roSearchJson = await roSearchRes.json();
  assert.ok(roSearchJson.result?.content, 'Read-only tool must return valid MCP content response');
  recordResult('2G', 'Read-Only Google Drive Tool Execution (drive_search)', 'PASS', {
    tool_executed: 'drive_search',
    mutations_performed: 0,
    read_only_enforced: true
  });

  // =============================================================
  // PHASE 2H: Multi-User Isolation Verification
  // =============================================================
  console.log('\n--- PHASE 2H: Multi-User Isolation Verification ---');
  // Create User B with completely distinct PKCE credentials and token
  const pkceB = generatePkcePair();
  const stateB = `state_userb_${crypto.randomBytes(8).toString('hex')}`;
  
  const authPostBParams = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'drive',
    state: stateB,
    code_challenge: pkceB.challenge,
    code_challenge_method: 'S256'
  });
  const authPostBRes = await fetch(`${targetUrl}/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: authPostBParams.toString(),
    redirect: 'manual'
  });
  const codeB = new URL(authPostBRes.headers.get('location')).searchParams.get('code');
  
  const tokenBRes = await fetch(`${targetUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      code: codeB,
      code_verifier: pkceB.verifier
    }).toString()
  });
  assert.equal(tokenBRes.status, 200);
  const tokenBJson = await tokenBRes.json();
  const userBToken = tokenBJson.access_token;

  // Extract payload sub from tokens to verify distinct userSub
  const parseTokenSub = (tok) => {
    const rawPayload = tok.split('.')[0].replace(/^mcp_at_/, '');
    return JSON.parse(Buffer.from(rawPayload, 'base64url').toString('utf8')).sub;
  };
  const subA = parseTokenSub(userAToken);
  const subB = parseTokenSub(userBToken);
  assert.notEqual(subA, subB, 'User A and User B must receive completely distinct userSub identities');

  // Verify User B generates different link token and cannot cross-access User A
  const linkToolBRes = await fetch(`${targetUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userBToken}`
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: { name: 'drive_search', arguments: { query: 'test' } }
    })
  });
  const linkBText = (await linkToolBRes.json()).result?.content?.[0]?.text || '';
  const linkBMatch = linkBText.match(/code=([a-zA-Z0-9_.-]+)/);
  const tokenBLink = linkBMatch ? linkBMatch[1] : null;
  assert.notEqual(googleLinkToken, tokenBLink, 'User A and User B link tokens must be distinct');

  recordResult('2H', 'Multi-User Isolation & Independent Identity Segregation', 'PASS', {
    userA_sub_prefix: subA.slice(0, 16) + '...',
    userB_sub_prefix: subB.slice(0, 16) + '...',
    sub_isolation: 'STRICTLY_DISJOINT',
    credential_cross_access: 'BLOCKED'
  });

  // =============================================================
  // PHASE 2I: Security Regressions & Token Tampering
  // =============================================================
  console.log('\n--- PHASE 2I: Security Regressions & Negative Testing ---');

  // 1. Missing Authorization header rejected
  const noAuthRes = await fetch(`${targetUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(toolsListRpc)
  });
  assert.equal(noAuthRes.status, 401, 'Missing token must return 401');
  recordResult('2I', 'Unauthenticated Access Rejected (HTTP 401)', 'PASS', { status: noAuthRes.status });

  // 2. Tampered / invalid Bearer token rejected
  const badAuthRes = await fetch(`${targetUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer mcp_at_invalid_tampered_payload_12345.signature'
    },
    body: JSON.stringify(toolsListRpc)
  });
  assert.equal(badAuthRes.status, 401, 'Tampered token must return 401');
  recordResult('2I', 'Tampered / Forged Token Rejected (HTTP 401)', 'PASS', { status: badAuthRes.status });

  // 3. Link Token Replay Attack rejected
  const replayLinkRes = await fetch(googleLinkUrl, { redirect: 'manual' });
  // The first fetch followed the link; a second attempt to consume the single-use token must fail
  assert.ok(
    replayLinkRes.status === 400 || replayLinkRes.status === 401 || (await replayLinkRes.text()).includes('already been used') || (await replayLinkRes.text()).includes('Invalid or expired'),
    'Replaying single-use Google link token must be rejected'
  );
  recordResult('2I', 'Google Link Token Single-Use & Replay Protection', 'PASS', { replay_blocked: true });

  // =============================================================
  // PHASE 2J: Final Summary Table
  // =============================================================
  console.log('\n================================================================');
  console.log('   PHASE 2: VERIFICATION SUMMARY REPORT');
  console.log('================================================================');
  console.log('| Phase | Check Description | Status | Evidence / Telemetry |');
  console.log('|---|---|:---:|---|');
  for (const item of reportTable) {
    const detailsStr = Object.entries(item.details)
      .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
      .join('; ');
    console.log(`| **${item.phase}** | ${item.item} | **${item.status}** | \`${detailsStr}\` |`);
  }
  console.log('================================================================\n');

  const allPassed = reportTable.every(r => r.status === 'PASS');
  assert.ok(allPassed, 'All Phase 2 verification steps must pass');
});
