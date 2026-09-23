import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const targetUrl = (process.env.PRODUCTION_URL || 'https://google-drive-mcp-six.vercel.app').replace(/\/+$/, '');
const isExplicitVerification = process.env.VERIFY_PRODUCTION === 'true' || process.argv.includes('--production');

test('Production Persistence Verification: Vercel Private Blob cross-invocation persistence', { skip: !isExplicitVerification }, async () => {
  console.log('\n================================================================');
  console.log('   PRODUCTION VERCEL BLOB PERSISTENCE VERIFICATION');
  console.log(`   Target Endpoint: ${targetUrl}`);
  console.log('================================================================\n');

  const results = [];
  function recordStep(name, status, details = {}) {
    results.push({ name, status, details });
    const mark = status === 'PASS' ? '✔' : '✖';
    console.log(`${mark} [${status}] ${name}`);
    if (Object.keys(details).length > 0) {
      for (const [k, v] of Object.entries(details)) {
        console.log(`    - ${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
      }
    }
  }

  // -------------------------------------------------------------
  // Step 1: Health & Diagnostics Verification
  // -------------------------------------------------------------
  console.log('--- Step 1: Environment & Storage Diagnostics ---');
  const healthRes = await fetch(`${targetUrl}/health`);
  assert.equal(healthRes.status, 200, `Health check failed on ${targetUrl}`);
  const healthJson = await healthRes.json();
  const envDiag = healthJson.env_diagnostics || {};

  assert.equal(healthJson.storage_backend, 'vercel-blob');
  assert.equal(healthJson.storage_configured, true);
  assert.equal(envDiag.single_user_mode, 'false');
  assert.equal(envDiag.storage_key?.configured, true);
  assert.equal(envDiag.blob_diagnostics?.blob_store_id_configured, true);
  assert.equal(envDiag.blob_diagnostics?.blob_read_write_token_configured, true);

  recordStep('Production Storage Configuration Diagnostics', 'PASS', {
    storage_backend: healthJson.storage_backend,
    storage_configured: healthJson.storage_configured,
    data_dir: envDiag.blob_diagnostics?.data_dir,
    discovered_keys: envDiag.blob_diagnostics?.discovered_blob_keys
  });

  // -------------------------------------------------------------
  // Step 2: Invocation 1 - Write Encrypted Record to Private Blob
  // -------------------------------------------------------------
  console.log('\n--- Step 2: Invocation 1 - Write Encrypted Record ---');
  const probeId = `probe_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
  const secretPayload = `secret_value_${crypto.randomBytes(16).toString('hex')}`;

  const writeRes = await fetch(
    `${targetUrl}/health?verify_persistence=write&probe_id=${probeId}&probe_value=${encodeURIComponent(secretPayload)}`
  );
  assert.equal(writeRes.status, 200);
  const writeJson = await writeRes.json();
  const writeDiag = writeJson.env_diagnostics?.persistence_verification;

  assert.equal(writeDiag?.status, 'SUCCESS');
  assert.equal(writeDiag?.encryption?.algorithm, 'aes-256-gcm');
  assert.equal(writeDiag?.encryption?.access, 'private');
  assert.equal(writeDiag?.encryption?.envelope_stored, true);

  recordStep('Invocation 1: Write Encrypted Record to Vercel Private Blob', 'PASS', {
    probe_id: probeId,
    blob_pathname: writeDiag.blob_pathname,
    etag: writeDiag.etag,
    encryption_algorithm: writeDiag.encryption?.algorithm,
    blob_access: writeDiag.encryption?.access,
    invocation_pid: writeDiag.invocation_pid,
    invocation_timestamp: writeDiag.invocation_time
  });

  // Wait 1.5 seconds between invocations to ensure separation
  await new Promise(r => setTimeout(r, 1500));

  // -------------------------------------------------------------
  // Step 3: Invocation 2 - Read & Decrypt from Separate Invocation
  // -------------------------------------------------------------
  console.log('\n--- Step 3: Invocation 2 - Read & Decrypt Record ---');
  const readRes = await fetch(`${targetUrl}/health?verify_persistence=read&probe_id=${probeId}`);
  assert.equal(readRes.status, 200);
  const readJson = await readRes.json();
  const readDiag = readJson.env_diagnostics?.persistence_verification;

  assert.equal(readDiag?.status, 'SUCCESS');
  assert.equal(readDiag?.persisted, true);
  assert.equal(readDiag?.use_cache_false, true);
  assert.equal(readDiag?.data?.value, secretPayload, 'Decrypted value must match original plaintext');

  recordStep('Invocation 2: Read & Decrypt Record from Origin (useCache: false)', 'PASS', {
    persisted: readDiag.persisted,
    use_cache_false: readDiag.use_cache_false,
    payload_matched: Boolean(readDiag.data?.value === secretPayload),
    invocation_pid: readDiag.invocation_pid,
    invocation_timestamp: readDiag.invocation_time,
    time_delta_ms: (readDiag.invocation_time - writeDiag.invocation_time)
  });

  // -------------------------------------------------------------
  // Step 4: Invocation 3 - Cleanup Probe Record
  // -------------------------------------------------------------
  console.log('\n--- Step 4: Invocation 3 - Delete Probe Record ---');
  const cleanRes = await fetch(`${targetUrl}/health?verify_persistence=cleanup&probe_id=${probeId}`);
  assert.equal(cleanRes.status, 200);
  const cleanJson = await cleanRes.json();
  const cleanDiag = cleanJson.env_diagnostics?.persistence_verification;

  assert.equal(cleanDiag?.status, 'SUCCESS');
  assert.equal(cleanDiag?.deleted, true);

  // Confirm deletion in a separate read
  const confirmRes = await fetch(`${targetUrl}/health?verify_persistence=read&probe_id=${probeId}`);
  const confirmJson = await confirmRes.json();
  assert.equal(confirmJson.env_diagnostics?.persistence_verification?.persisted, false);

  recordStep('Invocation 3: Delete & Confirm Cleanup of Probe Record', 'PASS', {
    deleted: cleanDiag.deleted,
    confirmed_absent: true
  });

  // -------------------------------------------------------------
  // Step 5: Real Storage Flow - OAuth State Lifecycle (Save -> Consume -> Replay Rejection)
  // -------------------------------------------------------------
  console.log('\n--- Step 5: Real Storage Flow - Encrypted OAuth State ---');
  const testState = `oauth_probe_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
  const testUserSub = `usr_test_${crypto.randomBytes(4).toString('hex')}`;

  // Step 5a: Save OAuth state (persists into oauth-state.enc.json in Vercel Private Blob)
  const saveStateRes = await fetch(
    `${targetUrl}/health?verify_oauth_flow=save&oauth_state=${testState}&user_sub=${testUserSub}`
  );
  assert.equal(saveStateRes.status, 200);
  const saveStateJson = await saveStateRes.json();
  const saveDiag = saveStateJson.env_diagnostics?.oauth_flow_verification;
  assert.equal(saveDiag?.status, 'SUCCESS');

  recordStep('Real Storage Flow: Save OAuth State into oauth-state.enc.json', 'PASS', {
    state: testState,
    bound_user: testUserSub,
    storage_file: 'oauth-state.enc.json'
  });

  // Wait 1.5 seconds before consuming from separate invocation
  await new Promise(r => setTimeout(r, 1500));

  // Step 5b: Consume OAuth state (reads, decrypts, validates, and marks used in Vercel Blob)
  const consumeRes = await fetch(
    `${targetUrl}/health?verify_oauth_flow=consume&oauth_state=${testState}`
  );
  assert.equal(consumeRes.status, 200);
  const consumeJson = await consumeRes.json();
  const consumeDiag = consumeJson.env_diagnostics?.oauth_flow_verification;
  assert.equal(consumeDiag?.status, 'SUCCESS');
  assert.equal(consumeDiag?.bound_user_sub, testUserSub);

  recordStep('Real Storage Flow: Consume OAuth State across separate invocation', 'PASS', {
    consumed_user: consumeDiag.bound_user_sub,
    matched: Boolean(consumeDiag.bound_user_sub === testUserSub)
  });

  // Step 5c: Replay Attempt - Must be strictly rejected
  const replayRes = await fetch(
    `${targetUrl}/health?verify_oauth_flow=consume&oauth_state=${testState}`
  );
  assert.equal(replayRes.status, 200);
  const replayJson = await replayRes.json();
  const replayDiag = replayJson.env_diagnostics?.oauth_flow_verification;
  assert.equal(replayDiag?.status, 'REJECTED');
  assert.ok(
    replayDiag?.error_code === 'OAUTH_STATE_REPLAY' || replayDiag?.error_code === 'OAUTH_STATE_INVALID',
    `Expected replay rejection error code, received: ${replayDiag?.error_code}`
  );

  recordStep('Real Storage Flow: Replay of Consumed OAuth State Strictly Rejected', 'PASS', {
    replay_status: replayDiag.status,
    rejection_error_code: replayDiag.error_code
  });

  // -------------------------------------------------------------
  // Final Summary Report
  // -------------------------------------------------------------
  console.log('\n================================================================');
  console.log('   PERSISTENCE VERIFICATION SUMMARY REPORT');
  console.log('================================================================');
  const allPassed = results.every(r => r.status === 'PASS');
  console.log(`Total Checks: ${results.length}`);
  console.log(`Passed: ${results.filter(r => r.status === 'PASS').length}`);
  console.log(`Failed: ${results.filter(r => r.status === 'FAIL').length}`);
  console.log(`Overall Result: ${allPassed ? 'ALL CHECKS PASSED (PRODUCTION PROVEN)' : 'FAILED'}`);
  console.log('================================================================\n');

  assert.equal(allPassed, true);
});
