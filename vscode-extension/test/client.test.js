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

  console.log('✓ All extension client tests passed successfully!');
}

runTests().catch((err) => {
  console.error('Extension test failed:', err);
  process.exit(1);
});
