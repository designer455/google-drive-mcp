import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const targetUrl = (process.env.PRODUCTION_URL || 'https://google-drive-mcp-six.vercel.app').replace(/\/+$/, '');
const isExplicitVerification = process.env.VERIFY_PRODUCTION === 'true' || process.argv.includes('--production');

test('Production Persistence Verification: record written in one invocation can be read in a separate invocation', { skip: !isExplicitVerification }, async () => {
  const probeId = `prod_test_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const secretPayload = `persistent_secret_${crypto.randomBytes(16).toString('hex')}`;

  console.log(`[Production Verification] Testing against: ${targetUrl}`);
  console.log(`[Production Verification] Probe ID: ${probeId}`);

  // Step 1: Health check & diagnostics verification
  const healthRes = await fetch(`${targetUrl}/health`);
  assert.equal(healthRes.status, 200, `Health check failed on ${targetUrl}`);
  const healthJson = await healthRes.json();
  console.log(`[Production Verification] Status: ${healthJson.status}, Storage Backend: ${healthJson.storage_backend}, Storage Configured: ${healthJson.storage_configured}`);
  assert.equal(healthJson.storage_backend, 'vercel-blob', 'storage_backend must be "vercel-blob" in production');

  // Step 2: Separate Invocation 1 - Write encrypted record
  console.log('[Production Verification] Invocation 1: Writing encrypted record...');
  const writeRes = await fetch(`${targetUrl}/health?verify_persistence=write&probe_id=${probeId}&probe_value=${encodeURIComponent(secretPayload)}`);
  assert.equal(writeRes.status, 200);
  const writeJson = await writeRes.json();
  const writeStatus = writeJson.env_diagnostics?.persistence_verification;
  assert.equal(writeStatus?.status, 'SUCCESS', `Write step failed: ${JSON.stringify(writeStatus)}`);

  // Allow short pause so separate request is routed independently
  await new Promise(r => setTimeout(r, 1000));

  // Step 3: Separate Invocation 2 - Read back and verify decrypted record
  console.log('[Production Verification] Invocation 2: Reading back encrypted record...');
  const readRes = await fetch(`${targetUrl}/health?verify_persistence=read&probe_id=${probeId}`);
  assert.equal(readRes.status, 200);
  const readJson = await readRes.json();
  const readStatus = readJson.env_diagnostics?.persistence_verification;
  assert.equal(readStatus?.status, 'SUCCESS', `Read step failed: ${JSON.stringify(readStatus)}`);
  assert.equal(readStatus?.persisted, true, 'Record was not persisted across invocations');
  assert.equal(readStatus?.data?.value, secretPayload, 'Decrypted payload did not match written value');
  console.log('[Production Verification] Invocation 2: Verification SUCCESS! Decrypted data matches.');

  // Step 4: Separate Invocation 3 - Cleanup
  console.log('[Production Verification] Invocation 3: Cleaning up probe record...');
  const cleanRes = await fetch(`${targetUrl}/health?verify_persistence=cleanup&probe_id=${probeId}`);
  assert.equal(cleanRes.status, 200);
  const cleanJson = await cleanRes.json();
  const cleanStatus = cleanJson.env_diagnostics?.persistence_verification;
  assert.equal(cleanStatus?.status, 'SUCCESS', 'Cleanup failed');

  // Step 5: Separate Invocation 4 - Confirm deleted
  const confirmRes = await fetch(`${targetUrl}/health?verify_persistence=read&probe_id=${probeId}`);
  const confirmJson = await confirmRes.json();
  assert.equal(confirmJson.env_diagnostics?.persistence_verification?.persisted, false, 'Probe record was not deleted');
  console.log('[Production Verification] Invocation 4: Confirmed probe record cleaned up. All checks PASSED!');
});
