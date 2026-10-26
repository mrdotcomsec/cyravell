#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default parameter handling
RELEASE_DIR="${ROOT_DIR}/dist/release-v0.1.0"
EXPECTED_VERSION=""
EXPECTED_COMMIT=""
ALLOW_DEV_KEYS=""
KEYS_FILE="${ROOT_DIR}/rules/release_signing_keys.json"

# Parse command-line flags or positional arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir|--release-dir)
      RELEASE_DIR="$2"
      shift 2
      ;;
    --expected-version)
      EXPECTED_VERSION="$2"
      shift 2
      ;;
    --expected-commit)
      EXPECTED_COMMIT="$2"
      shift 2
      ;;
    --keys-file)
      KEYS_FILE="$2"
      shift 2
      ;;
    --allow-dev-keys|--dev)
      ALLOW_DEV_KEYS="--allow-dev-keys"
      shift
      ;;
    -*)
      echo "Unknown option: $1"
      exit 1
      ;;
    *)
      if [ -z "${EXPECTED_VERSION}" ] && [ "${RELEASE_DIR}" != "$1" ] && [ "$RELEASE_DIR" = "${ROOT_DIR}/dist/release-v0.1.0" ]; then
        RELEASE_DIR="$1"
      elif [ -z "${EXPECTED_VERSION}" ]; then
        EXPECTED_VERSION="$1"
      elif [ -z "${EXPECTED_COMMIT}" ]; then
        EXPECTED_COMMIT="$1"
      fi
      shift
      ;;
  esac
done

echo "══════════════════════════════════════════════════════════════"
echo "           Cyravell Release Package Verification Tool         "
echo "══════════════════════════════════════════════════════════════"
echo "  Target Release Directory: ${RELEASE_DIR}"
if [ -n "${EXPECTED_VERSION}" ]; then
  echo "  Expected Version:         ${EXPECTED_VERSION}"
fi
if [ -n "${EXPECTED_COMMIT}" ]; then
  echo "  Expected Commit:          ${EXPECTED_COMMIT}"
fi
echo "  Mode:                     $([ -n "${ALLOW_DEV_KEYS}" ] && echo "Development / Test Allowed" || echo "Strict Official Keys Required")"
echo "──────────────────────────────────────────────────────────────"

if [ ! -d "${RELEASE_DIR}" ]; then
  echo "✗ Error: Release directory '${RELEASE_DIR}' does not exist!"
  exit 1
fi

MANIFEST="${RELEASE_DIR}/release_manifest.json"
if [ ! -f "${MANIFEST}" ]; then
  echo "✗ Error: Release manifest '${MANIFEST}' not found!"
  exit 1
fi

# Step 1: Execute Independent Standalone Verifier
# CRITICAL SECURITY INVARIANT:
# This verification is performed BEFORE executing any binary from the release package.
# It uses standard Python 3 / OpenSSL and NEVER executes downloaded binaries.
echo ""
echo "[Step 1/2] Independent trust-chain verification (zero downloaded binary execution)..."
STANDALONE_CMD=("python3" "${SCRIPT_DIR}/standalone_verify.py" "--manifest" "${MANIFEST}" "--artifacts-dir" "${RELEASE_DIR}")

if [ -f "${KEYS_FILE}" ]; then
  STANDALONE_CMD+=("--keys-file" "${KEYS_FILE}")
fi
if [ -n "${EXPECTED_VERSION}" ]; then
  STANDALONE_CMD+=("--expected-version" "${EXPECTED_VERSION}")
fi
if [ -n "${EXPECTED_COMMIT}" ]; then
  STANDALONE_CMD+=("--expected-commit" "${EXPECTED_COMMIT}")
fi
if [ -n "${ALLOW_DEV_KEYS}" ]; then
  STANDALONE_CMD+=("${ALLOW_DEV_KEYS}")
fi

if ! "${STANDALONE_CMD[@]}"; then
  echo ""
  echo "✗ STANDALONE INDEPENDENT VERIFICATION FAILED."
  echo "CRITICAL: Do not install or run any software from this release."
  exit 1
fi

# Step 2: Engine Cross-Verification (only if trusted local engine binary exists from source build or system PATH)
# Note: We NEVER run ${RELEASE_DIR}/cyravell-engine-... here to verify itself!
echo ""
echo "[Step 2/2] Authoritative engine cross-verification..."
ENGINE_BIN=""

if [ -x "${ROOT_DIR}/target/release/cyravell-engine" ]; then
  ENGINE_BIN="${ROOT_DIR}/target/release/cyravell-engine"
elif command -v cyravell-engine >/dev/null 2>&1; then
  ENGINE_BIN="$(command -v cyravell-engine)"
fi

if [ -n "${ENGINE_BIN}" ]; then
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
  if [ -n "${ALLOW_DEV_KEYS}" ]; then
    VERIFY_CMD+=("--allow-dev-keys")
  fi

  if "${VERIFY_CMD[@]}"; then
    echo "  ✓ Engine cross-verification passed using trusted local binary: ${ENGINE_BIN}"
  else
    echo "✗ Authoritative engine cross-verification failed!"
    exit 1
  fi
else
  echo "  ℹ Local trusted engine binary not found; independent verification in Step 1 is sufficient."
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
echo "  ✓ ALL VERIFICATION CHECKS PASSED!"
echo "  The release package is authentic, untampered, and ready for deployment."
echo ""
echo "  INSTALLATION INSTRUCTIONS (Verified Artifacts):"
echo "  1. Engine Binary:"
echo "     sudo install -m 755 ${RELEASE_DIR}/cyravell-engine-x86_64-unknown-linux-gnu /usr/local/bin/cyravell-engine"
echo "  2. Rules Bundle:"
echo "     tar -xzf ${RELEASE_DIR}/cyravell-rules-bundle.tar.gz -C /usr/local/share/cyravell/"
echo "  3. VS Code Extension:"
echo "     code --install-extension ${RELEASE_DIR}/cyravell-*.vsix"
echo "══════════════════════════════════════════════════════════════"
