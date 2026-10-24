// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

const assert = require('assert');
const { EngineClient } = require('../out/engineClient');

async function runTests() {
  console.log('Running Cyravell VS Code Extension client tests...');

  // Test 1: Initial state is DISCONNECTED
  const client = new EngineClient('/tmp/nonexistent-cyravell-test.sock');
  assert.strictEqual(client.getConnectionState(), 'DISCONNECTED', 'Initial state must be DISCONNECTED');
  console.log('  ✓ Initial state is DISCONNECTED');

  // Test 2: Connecting to non-existent socket fails safely and stays DISCONNECTED
  const connected = await client.connect();
  assert.strictEqual(connected, false, 'Connect to missing socket should return false');
  assert.strictEqual(client.getConnectionState(), 'DISCONNECTED', 'State must remain DISCONNECTED after failed connect');
  console.log('  ✓ Safe failure when socket is unavailable (never displays green or active)');

  // Test 3: Disconnect cleanup
  client.disconnect();
  assert.strictEqual(client.getConnectionState(), 'DISCONNECTED', 'State remains DISCONNECTED after disconnect()');
  console.log('  ✓ Disconnect cleans up cleanly');

  // Test 4: Default socket path resolution
  const defaultClient = new EngineClient();
  assert.ok(defaultClient.getSocketPath().includes('cyravell.sock'), 'Default socket path should include cyravell.sock');
  console.log('  ✓ Socket path resolved accurately: ' + defaultClient.getSocketPath());

  // Test 5: analyzeCommand throws if engine is disconnected
  try {
    await client.analyzeCommand('echo hello');
    assert.fail('Expected error when analyzing command while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ analyzeCommand fails safely when disconnected');
  }

  // Test 6: evaluateGate throws if engine is disconnected
  try {
    await client.evaluateGate('echo hello');
    assert.fail('Expected error when evaluating gate while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ evaluateGate fails safely when disconnected');
  }

  // Test 7: getPendingApprovals throws if engine is disconnected
  try {
    await client.getPendingApprovals();
    assert.fail('Expected error when getting pending approvals while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ getPendingApprovals fails safely when disconnected');
  }

  // Test 8: decideApproval throws if engine is disconnected
  try {
    await client.decideApproval('appr-test-1', 'Approve');
    assert.fail('Expected error when deciding approval while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ decideApproval fails safely when disconnected');
  }

  // Test 9: dispatchAuthorized throws if engine is disconnected
  try {
    await client.dispatchAuthorized('appr-test-1', 'sess-1', 'ls', 'cyr-auth-fake');
    assert.fail('Expected error when dispatching authorized command while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ dispatchAuthorized fails safely when disconnected');
  }

  // Test 10: createBaseline throws if engine is disconnected
  try {
    await client.createBaseline('/tmp/test-workspace');
    assert.fail('Expected error when creating baseline while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ createBaseline fails safely when disconnected');
  }

  // Test 11: getBaseline throws if engine is disconnected
  try {
    await client.getBaseline('/tmp/test-workspace');
    assert.fail('Expected error when getting baseline while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ getBaseline fails safely when disconnected');
  }

  // Test 12: detectDrift throws if engine is disconnected
  try {
    await client.detectDrift('/tmp/test-workspace');
    assert.fail('Expected error when detecting drift while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ detectDrift fails safely when disconnected');
  }

  // Test 13: verifyPostOperation throws if engine is disconnected
  try {
    await client.verifyPostOperation('/tmp/test-workspace', 'npm install', 0);
    assert.fail('Expected error when verifying post-operation while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ verifyPostOperation fails safely when disconnected');
  }

  // Test 14: monitorWorkspace throws if engine is disconnected
  try {
    await client.monitorWorkspace('/tmp/test-workspace', true);
    assert.fail('Expected error when monitoring workspace while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ monitorWorkspace fails safely when disconnected');
  }

  // Test 15: getAdvisoryStatus throws if engine is disconnected
  try {
    await client.getAdvisoryStatus();
    assert.fail('Expected error when getting advisory status while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ getAdvisoryStatus fails safely when disconnected');
  }

  // Test 16: inspectAdvisoryBundle throws if engine is disconnected
  try {
    await client.inspectAdvisoryBundle('/tmp/test-bundle.json');
    assert.fail('Expected error when inspecting advisory bundle while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ inspectAdvisoryBundle fails safely when disconnected');
  }

  // Test 17: importAdvisoryBundle throws if engine is disconnected
  try {
    await client.importAdvisoryBundle('/tmp/test-bundle.json', false);
    assert.fail('Expected error when importing advisory bundle while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ importAdvisoryBundle fails safely when disconnected');
  }

  // Test 18: requestRollbackAuthorization throws if engine is disconnected
  try {
    await client.requestRollbackAuthorization('/tmp/test-bundle.json', '1.0.0', 'Rollback due to emergency fix');
    assert.fail('Expected error when requesting rollback authorization while disconnected');
  } catch (e) {
    assert.ok(e.message.includes('not connected'), 'Must throw not connected error');
    console.log('  ✓ requestRollbackAuthorization fails safely when disconnected');
  }

  console.log('✓ All extension client tests passed successfully!');
}

runTests().catch((err) => {
  console.error('Extension test failed:', err);
  process.exit(1);
});
