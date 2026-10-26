#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default settings
COMMAND="install"
RELEASE_DIR="${ROOT_DIR}/dist/release-v0.1.0"
PREFIX=""
USER_MODE=false
SYSTEM_MODE=false
ALLOW_DEV_KEYS=false
ALLOW_DOWNGRADE=false
OPERATOR_REASON=""
EXPECTED_VERSION=""
EXPECTED_COMMIT=""
PURGE_DATA=false
JSON_OUTPUT=false

# Print header
print_header() {
  echo "══════════════════════════════════════════════════════════════"
  echo "         Cyravell Secure Installer & Lifecycle Manager        "
  echo "══════════════════════════════════════════════════════════════"
}

# Print usage
usage() {
  print_header
  cat <<EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
  install (default)   Verify and securely install or update Cyravell
  status              Display current installation state and version
  rollback            Revert to the last known-good installation
  uninstall           Remove Cyravell executables, rules, and metadata

Options:
  --release-dir <DIR>  Path to release package directory (default: dist/release-v0.1.0)
  --prefix <PATH>      Target installation prefix (default: ~/.local or /usr/local)
  --user               Install in unprivileged user mode (~/.local)
  --system             Install in system mode (/usr/local, requires root/sudo)
  --allow-dev-keys     Permit non-official development/testing signing keys
  --allow-downgrade    Permit authorized downgrade to older release version
  --reason <STR>       Required justification reason for rollback or downgrade (min 8 chars)
  --expected-version <VER> Expected SemVer release version (e.g. 0.1.0)
  --expected-commit <SHA>  Expected source Git commit SHA
  --purge-data         Purge all user security data and audit logs during uninstall
  --json               Output machine-readable JSON format
  -h, --help           Show this help message

EOF
  exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    install|status|rollback|uninstall)
      COMMAND="$1"
      shift
      ;;
    --release-dir)
      RELEASE_DIR="$2"
      shift 2
      ;;
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --user)
      USER_MODE=true
      shift
      ;;
    --system)
      SYSTEM_MODE=true
      shift
      ;;
    --allow-dev-keys)
      ALLOW_DEV_KEYS=true
      shift
      ;;
    --allow-downgrade)
      ALLOW_DOWNGRADE=true
      shift
      ;;
    --reason)
      OPERATOR_REASON="$2"
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
    --purge-data)
      PURGE_DATA=true
      shift
      ;;
    --json)
      JSON_OUTPUT=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      if [ -d "$1" ]; then
        RELEASE_DIR="$1"
      else
        echo "Unknown option or argument: $1"
        usage
      fi
      shift
      ;;
  esac
done

# Resolve effective UID and default prefix
IS_ROOT=false
if [ "$(id -u)" -eq 0 ]; then
  IS_ROOT=true
fi

if [ -z "${PREFIX}" ]; then
  if [ "${SYSTEM_MODE}" = true ]; then
    PREFIX="/usr/local"
  elif [ "${USER_MODE}" = true ] || [ "${IS_ROOT}" = false ]; then
    USER_MODE=true
    PREFIX="${HOME}/.local"
  else
    PREFIX="/usr/local"
  fi
fi

# Privilege boundary validation
if [ "${PREFIX}" = "/usr/local" ] || [ "${PREFIX}" = "/usr" ] || [ "${SYSTEM_MODE}" = true ]; then
  if [ "${IS_ROOT}" = false ]; then
    echo "✗ Privilege Boundary Error: System installation to '${PREFIX}' requires root privileges."
    echo "  Please re-run with sudo or use '--user' for unprivileged installation to ~/.local."
    exit 1
  fi
fi

# Route commands
case "${COMMAND}" in
  status)
    if [ ! "${JSON_OUTPUT}" = true ]; then
      print_header
      echo "  Checking installation status at: ${PREFIX}"
      echo "──────────────────────────────────────────────────────────────"
    fi

    STATE_FILE="${PREFIX}/share/cyravell/install_state.json"
    if [ ! -f "${STATE_FILE}" ]; then
      if [ "${JSON_OUTPUT}" = true ]; then
        echo '{"installed": false, "error": "No installation found"}'
      else
        echo "✗ No active Cyravell installation found at '${PREFIX}'"
      fi
      exit 1
    fi

    # Locate an engine binary to query status
    ENGINE_BIN="${PREFIX}/bin/cyravell-engine"
    if [ ! -x "${ENGINE_BIN}" ]; then
      ENGINE_BIN="${ROOT_DIR}/target/release/cyravell-engine"
    fi
    if [ ! -x "${ENGINE_BIN}" ]; then
      ENGINE_BIN="${ROOT_DIR}/target/debug/cyravell-engine"
    fi

    if [ -x "${ENGINE_BIN}" ]; then
      ARGS=("install-status" "--prefix" "${PREFIX}")
      if [ "${USER_MODE}" = true ]; then ARGS+=("--user"); fi
      if [ "${JSON_OUTPUT}" = true ]; then ARGS+=("--json"); fi
      "${ENGINE_BIN}" "${ARGS[@]}"
    else
      # Direct Python fallback to read state file
      python3 -c "
import json, sys
state = json.load(open('${STATE_FILE}'))
if '${JSON_OUTPUT}' == 'true':
    print(json.dumps(state, indent=2))
else:
    print('Active Version:    ' + state.get('active_version', 'unknown'))
    print('Source Commit:     ' + state.get('active_commit', 'unknown'))
    print('Official Release:  ' + str(state.get('is_official', False)))
    print('Signing Key ID:    ' + state.get('signing_key_id', 'unknown'))
    print('Prefix:            ' + state.get('install_prefix', 'unknown'))
    print('Last Operation:    ' + state.get('last_operation', 'unknown'))
"
    fi
    exit 0
    ;;

  rollback)
    if [ -z "${OPERATOR_REASON}" ]; then
      echo "✗ Error: Rollback requires an operator justification reason (min 8 chars)."
      echo "  Example: $0 rollback --reason \"Reverting after pipeline disruption\""
      exit 1
    fi

    if [ ! "${JSON_OUTPUT}" = true ]; then
      print_header
      echo "  Initiating authorized rollback at: ${PREFIX}"
      echo "  Operator Reason: ${OPERATOR_REASON}"
      echo "──────────────────────────────────────────────────────────────"
    fi

    ENGINE_BIN="${PREFIX}/bin/cyravell-engine"
    if [ ! -x "${ENGINE_BIN}" ]; then
      ENGINE_BIN="${PREFIX}/share/cyravell/.backup/cyravell-engine"
    fi
    if [ ! -x "${ENGINE_BIN}" ]; then
      ENGINE_BIN="${ROOT_DIR}/target/release/cyravell-engine"
    fi
    if [ ! -x "${ENGINE_BIN}" ]; then
      ENGINE_BIN="${ROOT_DIR}/target/debug/cyravell-engine"
    fi

    if [ ! -x "${ENGINE_BIN}" ]; then
      echo "✗ Error: Could not locate a trusted engine binary to execute rollback."
      exit 1
    fi

    ARGS=("rollback" "--prefix" "${PREFIX}" "--reason" "${OPERATOR_REASON}")
    if [ "${USER_MODE}" = true ]; then ARGS+=("--user"); fi
    if [ "${JSON_OUTPUT}" = true ]; then ARGS+=("--json"); fi

    "${ENGINE_BIN}" "${ARGS[@]}"
    exit 0
    ;;

  uninstall)
    if [ ! "${JSON_OUTPUT}" = true ]; then
      print_header
      echo "  Uninstalling Cyravell from: ${PREFIX}"
      echo "  Purge User Security Data: ${PURGE_DATA}"
      echo "──────────────────────────────────────────────────────────────"
    fi

    ENGINE_BIN="${PREFIX}/bin/cyravell-engine"
    if [ ! -x "${ENGINE_BIN}" ]; then
      ENGINE_BIN="${ROOT_DIR}/target/release/cyravell-engine"
    fi
    if [ ! -x "${ENGINE_BIN}" ]; then
      ENGINE_BIN="${ROOT_DIR}/target/debug/cyravell-engine"
    fi

    if [ -x "${ENGINE_BIN}" ]; then
      ARGS=("uninstall" "--prefix" "${PREFIX}")
      if [ "${USER_MODE}" = true ]; then ARGS+=("--user"); fi
      if [ "${PURGE_DATA}" = true ]; then ARGS+=("--purge-data"); fi
      if [ -n "${OPERATOR_REASON}" ]; then ARGS+=("--reason" "${OPERATOR_REASON}"); fi
      if [ "${JSON_OUTPUT}" = true ]; then ARGS+=("--json"); fi
      "${ENGINE_BIN}" "${ARGS[@]}"
    else
      # Direct removal
      rm -f "${PREFIX}/bin/cyravell-engine" "${PREFIX}/bin/cyravell-test-harness"
      rm -rf "${PREFIX}/share/cyravell/rules" "${PREFIX}/share/cyravell/.backup" "${PREFIX}/share/cyravell/install_state.json"
      if [ "${PURGE_DATA}" = true ]; then
        rm -rf "${PREFIX}/share/cyravell/data"
      fi
      echo "✓ Cyravell files removed from ${PREFIX}"
    fi
    exit 0
    ;;

  install)
    if [ ! "${JSON_OUTPUT}" = true ]; then
      print_header
      echo "  Target Release Package:  ${RELEASE_DIR}"
      echo "  Installation Prefix:     ${PREFIX}"
      echo "  Mode:                    $([ "${USER_MODE}" = true ] && echo "User Mode (~/.local)" || echo "System Mode (/usr/local)")"
      echo "  Official Keys Required:  $([ "${ALLOW_DEV_KEYS}" = true ] && echo "False (Dev keys permitted)" || echo "True (Strict official keys)")"
      echo "──────────────────────────────────────────────────────────────"
    fi

    if [ ! -d "${RELEASE_DIR}" ]; then
      if [ -f "${ROOT_DIR}/install.sh" ]; then
        echo "  ℹ Pre-packaged release directory '${RELEASE_DIR}' not found."
        echo "  Running one-command source installer..."
        exec "${ROOT_DIR}/install.sh" "$@"
      else
        echo "✗ Error: Release directory '${RELEASE_DIR}' does not exist!"
        exit 1
      fi
    fi

    # Step 1: Zero-Binary-Execution Pre-Verification
    # CRITICAL: We NEVER execute any binary from RELEASE_DIR before verifying it!
    echo ""
    echo "[Step 1/3] Independent trust-chain verification (zero downloaded binary execution)..."
    VERIFY_ARGS=(
      "python3" "${SCRIPT_DIR}/standalone_verify.py"
      "--manifest" "${RELEASE_DIR}/release_manifest.json"
      "--artifacts-dir" "${RELEASE_DIR}"
    )
    if [ -f "${ROOT_DIR}/rules/release_signing_keys.json" ]; then
      VERIFY_ARGS+=("--keys-file" "${ROOT_DIR}/rules/release_signing_keys.json")
    fi
    if [ -n "${EXPECTED_VERSION}" ]; then
      VERIFY_ARGS+=("--expected-version" "${EXPECTED_VERSION}")
    fi
    if [ -n "${EXPECTED_COMMIT}" ]; then
      VERIFY_ARGS+=("--expected-commit" "${EXPECTED_COMMIT}")
    fi
    if [ "${ALLOW_DEV_KEYS}" = true ]; then
      VERIFY_ARGS+=("--allow-dev-keys")
    fi

    if ! "${VERIFY_ARGS[@]}"; then
      echo ""
      echo "✗ PRE-INSTALLATION VERIFICATION FAILED."
      echo "CRITICAL: The package is untrusted or corrupted. Halting installation."
      exit 1
    fi

    echo ""
    echo "[Step 2/3] Performing transactional staging, backup, and atomic activation..."

    # Locate or establish an execution engine for installation
    # Priority:
    # 1. Trusted already-installed engine on prefix/PATH
    # 2. Local verified build from source target/release
    # 3. Authenticated binary in RELEASE_DIR (ONLY because Step 1 verified its SHA-256 and signature bit-for-bit!)
    ENGINE_RUNNER=""
    if [ -x "${PREFIX}/bin/cyravell-engine" ]; then
      ENGINE_RUNNER="${PREFIX}/bin/cyravell-engine"
    elif [ -x "${ROOT_DIR}/target/release/cyravell-engine" ]; then
      ENGINE_RUNNER="${ROOT_DIR}/target/release/cyravell-engine"
    elif [ -x "${ROOT_DIR}/target/debug/cyravell-engine" ]; then
      ENGINE_RUNNER="${ROOT_DIR}/target/debug/cyravell-engine"
    elif [ -x "${RELEASE_DIR}/cyravell-engine-x86_64-unknown-linux-gnu" ]; then
      ENGINE_RUNNER="${RELEASE_DIR}/cyravell-engine-x86_64-unknown-linux-gnu"
    fi

    if [ -z "${ENGINE_RUNNER}" ]; then
      echo "✗ Error: No suitable engine binary found to execute installation."
      exit 1
    fi

    INSTALL_ARGS=(
      "install"
      "--release-dir" "${RELEASE_DIR}"
      "--prefix" "${PREFIX}"
    )
    if [ "${USER_MODE}" = true ]; then INSTALL_ARGS+=("--user"); fi
    if [ "${ALLOW_DEV_KEYS}" = true ]; then INSTALL_ARGS+=("--allow-dev-keys"); fi
    if [ "${ALLOW_DOWNGRADE}" = true ]; then INSTALL_ARGS+=("--allow-downgrade"); fi
    if [ -n "${OPERATOR_REASON}" ]; then INSTALL_ARGS+=("--reason" "${OPERATOR_REASON}"); fi
    if [ -n "${EXPECTED_VERSION}" ]; then INSTALL_ARGS+=("--expected-version" "${EXPECTED_VERSION}"); fi
    if [ -n "${EXPECTED_COMMIT}" ]; then INSTALL_ARGS+=("--expected-commit" "${EXPECTED_COMMIT}"); fi
    if [ "${JSON_OUTPUT}" = true ]; then INSTALL_ARGS+=("--json"); fi

    "${ENGINE_RUNNER}" "${INSTALL_ARGS[@]}"

    # Step 3: Install VS Code Extension (if 'code' command is present)
    echo ""
    echo "[Step 3/3] Optional editor integration..."
    VSIX_FILE="$(find "${RELEASE_DIR}" -maxdepth 1 -name "cyravell-*.vsix" | head -n 1 || true)"
    if [ -n "${VSIX_FILE}" ] && command -v code >/dev/null 2>&1; then
      echo "  Installing VS Code extension: ${VSIX_FILE}..."
      if code --install-extension "${VSIX_FILE}" --force >/dev/null 2>&1; then
        echo "  ✓ VS Code extension installed successfully."
      else
        echo "  ℹ VS Code extension installation skipped or needs manual install: code --install-extension ${VSIX_FILE}"
      fi
    else
      echo "  ℹ VS Code CLI ('code') not found or extension omitted; extension install skipped."
    fi

    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  ✓ CYRAVELL INSTALLATION & LIFECYCLE INITIALIZED SUCCESSFULLY!"
    echo "    Installed to: ${PREFIX}/bin/cyravell-engine"
    echo "    Rules path:   ${PREFIX}/share/cyravell/rules"
    echo "══════════════════════════════════════════════════════════════"
    ;;
esac
