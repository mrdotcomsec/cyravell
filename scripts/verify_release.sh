#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RELEASE_DIR="${1:-${ROOT_DIR}/dist/release-v0.1.0}"
EXPECTED_VERSION="${2:-}"
EXPECTED_COMMIT="${3:-}"

echo "══════════════════════════════════════════════════════════════"
echo "           Cyravell Release Package Verification Tool         "
echo "══════════════════════════════════════════════════════════════"
echo "  Target Release Directory: ${RELEASE_DIR}"

if [ ! -d "${RELEASE_DIR}" ]; then
  echo "Error: Release directory '${RELEASE_DIR}' does not exist!"
  exit 1
fi

MANIFEST="${RELEASE_DIR}/release_manifest.json"
if [ ! -f "${MANIFEST}" ]; then
  echo "Error: Release manifest '${MANIFEST}' not found!"
  exit 1
fi

KEYS_FILE="${ROOT_DIR}/rules/release_signing_keys.json"
if [ ! -f "${KEYS_FILE}" ]; then
  echo "Warning: Local release signing keys file not found; using embedded fallback keys"
fi

# Locate or build cyravell-engine
ENGINE_BIN="${ROOT_DIR}/target/release/cyravell-engine"
if [ ! -f "${ENGINE_BIN}" ]; then
  ENGINE_BIN="${RELEASE_DIR}/cyravell-engine-x86_64-unknown-linux-gnu"
fi

if [ ! -f "${ENGINE_BIN}" ]; then
  echo "Building cyravell-engine for verification..."
  (cd "${ROOT_DIR}" && cargo build --release -p cyravell-engine)
  ENGINE_BIN="${ROOT_DIR}/target/release/cyravell-engine"
fi

# Build verify command
VERIFY_CMD=("${ENGINE_BIN}" "verify-release" "--manifest" "${MANIFEST}" "--artifacts-dir" "${RELEASE_DIR}")
if [ -f "${KEYS_FILE}" ]; then
  VERIFY_CMD+=("--keys-file" "${KEYS_FILE}")
fi
if [ -n "${EXPECTED_VERSION}" ]; then
  VERIFY_CMD+=("--expected-version" "${EXPECTED_VERSION}")
fi
if [ -n "${EXPECTED_COMMIT}" ]; then
  VERIFY_CMD+=("--expected-commit" "${EXPECTED_COMMIT}")
fi

echo ""
echo "Running cryptographic and digest verification..."
if "${VERIFY_CMD[@]}"; then
  echo ""
  echo "  ✓ CRYPTOGRAPHIC AND BIT-FOR-BIT VERIFICATION PASSED"
else
  echo ""
  echo "  ✗ RELEASE VERIFICATION FAILED!"
  echo "  DO NOT INSTALL OR EXECUTE ARTIFACTS FROM THIS RELEASE DIRECTORY."
  exit 1
fi

# Check detached signature match if present
if [ -f "${MANIFEST}.sig" ]; then
  SIG_DETACHED=$(tr -d ' \n\r' < "${MANIFEST}.sig")
  SIG_EMBEDDED=$(python3 -c "import json; print(json.load(open('${MANIFEST}')).get('signature', ''))")
  if [ "${SIG_DETACHED}" = "${SIG_EMBEDDED}" ]; then
    echo "  ✓ Detached signature matches manifest signature block"
  else
    echo "  ✗ Error: Detached signature '${MANIFEST}.sig' does not match manifest signature!"
    exit 1
  fi
fi

# Check SHA256SUMS file consistency if present
if [ -f "${RELEASE_DIR}/SHA256SUMS" ]; then
  echo ""
  echo "Checking SHA256SUMS file consistency..."
  (cd "${RELEASE_DIR}" && sha256sum --check --status SHA256SUMS 2>/dev/null || sha256sum -c SHA256SUMS)
  echo "  ✓ SHA256SUMS consistency verified"
fi

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  INSTALLATION INSTRUCTIONS (Verified Artifacts):"
echo "  1. Engine Binary:"
echo "     sudo install -m 755 ${RELEASE_DIR}/cyravell-engine-x86_64-unknown-linux-gnu /usr/local/bin/cyravell-engine"
echo "  2. Rules Bundle:"
echo "     tar -xzf ${RELEASE_DIR}/cyravell-rules-bundle.tar.gz -C /usr/local/share/cyravell/"
echo "  3. VS Code Extension:"
echo "     code --install-extension ${RELEASE_DIR}/cyravell-*.vsix"
echo "══════════════════════════════════════════════════════════════"
