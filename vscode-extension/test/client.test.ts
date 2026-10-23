// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

import * as assert from 'assert';
import { EngineClient } from '../src/engineClient';

async function runTests() {
  console.log('Running Cyravell VS Code Extension unit tests...');

  // Test 1: Initial state is DISCONNECTED
  const client = new EngineClient('/tmp/nonexistent-cyravell-test.sock');
  assert.strictEqual(client.getConnectionState(), 'DISCONNECTED', 'Initial state must be DISCONNECTED');
  console.log('✓ Initial state is DISCONNECTED');

  // Test 2: Connecting to non-existent socket fails safely and stays DISCONNECTED
  const connected = await client.connect();
  assert.strictEqual(connected, false, 'Connect to missing socket should return false');
  assert.strictEqual(client.getConnectionState(), 'DISCONNECTED', 'State must remain DISCONNECTED after failed connect');
  console.log('✓ Safe failure when socket is unavailable');

  // Test 3: Disconnect cleanup
  client.disconnect();
  assert.strictEqual(client.getConnectionState(), 'DISCONNECTED', 'State remains DISCONNECTED after disconnect()');
  console.log('✓ Disconnect cleans up cleanly');

  console.log('All extension client tests passed successfully!');
}

runTests().catch((err) => {
  console.error('Extension test failed:', err);
  process.exit(1);
});

