#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "══════════════════════════════════════════════════════════════"
echo "           Cyravell Software Supply-Chain & Dependency Audit   "
echo "══════════════════════════════════════════════════════════════"

ERRORS=0

# 1. Lockfile Presence and Git Tracking Check
echo "[1/6] Verifying committed lockfiles..."
if [ ! -f "${ROOT_DIR}/Cargo.lock" ]; then
  echo "  ✗ Error: Root Cargo.lock is missing!"
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ Cargo.lock is present"
fi

if [ ! -f "${ROOT_DIR}/vscode-extension/package-lock.json" ]; then
  echo "  ✗ Error: vscode-extension/package-lock.json is missing!"
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ vscode-extension/package-lock.json is present"
fi

# 2. Deterministic Rust Dependency Resolution (--locked)
echo ""
echo "[2/6] Verifying deterministic Rust dependency resolution..."
if (cd "${ROOT_DIR}" && cargo check --locked --workspace > /dev/null 2>&1); then
  echo "  ✓ cargo check --locked succeeded (zero floating dependency drift)"
else
  echo "  ✗ Error: cargo check --locked failed! Dependencies differ from Cargo.lock"
  ERRORS=$((ERRORS + 1))
fi

# 3. Rust Dependency Sources & Registry Security
echo ""
echo "[3/6] Inspecting Cargo.lock sources for mutable git or unvetted dependencies..."
UNEXPECTED_SOURCES=$(python3 - <<EOF
import tomllib
with open("${ROOT_DIR}/Cargo.lock", "rb") as f:
    data = tomllib.load(f)
packages = data.get("package", [])
unexpected = []
for p in packages:
    source = p.get("source", "")
    name = p.get("name")
    if name in ["cyravell-engine", "cyravell-test-harness"]:
        continue
    # Crates must originate from crates.io registry
    if not source.startswith("registry+https://github.com/rust-lang/crates.io-index"):
        unexpected.append(f"{name} ({source})")
if unexpected:
    print("\n".join(unexpected))
EOF
)

if [ -n "${UNEXPECTED_SOURCES}" ]; then
  echo "  ✗ Error: Found dependencies from unexpected external sources:"
  echo "${UNEXPECTED_SOURCES}"
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ All Cargo dependencies originate from official crates.io registry"
fi

# Check for floating wildcard versions in Cargo.toml
FLOATING_DEPS=$(grep -rn 'version = "\*"' "${ROOT_DIR}"/Cargo.toml "${ROOT_DIR}"/*/Cargo.toml 2>/dev/null || true)
if [ -n "${FLOATING_DEPS}" ]; then
  echo "  ✗ Error: Found floating wildcard dependency versions in Cargo.toml:"
  echo "${FLOATING_DEPS}"
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ Zero floating wildcard versions in Cargo.toml files"
fi

# 4. JavaScript Dependency Security & Audit
echo ""
echo "[4/6] Running JavaScript dependency audit (npm audit)..."
if (cd "${ROOT_DIR}/vscode-extension" && npm audit --audit-level=low > /tmp/npm-audit.log 2>&1); then
  echo "  ✓ npm audit reported 0 vulnerabilities"
else
  echo "  ✗ Error: npm audit detected dependency vulnerabilities:"
  cat /tmp/npm-audit.log
  ERRORS=$((ERRORS + 1))
fi

# 5. Build Scripts and Install Hooks Audit
echo ""
echo "[5/6] Inspecting package.json scripts and lifecycle install hooks..."
HOOKS=$(python3 - <<EOF
import json
with open("${ROOT_DIR}/vscode-extension/package.json") as f:
    pkg = json.load(f)
scripts = pkg.get("scripts", {})
suspicious = []
for hook in ["preinstall", "postinstall", "install"]:
    if hook in scripts:
        suspicious.append(f"{hook}: {scripts[hook]}")
if suspicious:
    print("\n".join(suspicious))
EOF
)

if [ -n "${HOOKS}" ]; then
  echo "  ✗ Warning/Error: Found automated install hooks in extension package.json:"
  echo "${HOOKS}"
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ Zero dangerous automated pre/postinstall lifecycle hooks in package.json"
fi

# 6. Verify against Cyravell Package Advisories Database
echo ""
echo "[6/6] Cross-referencing dependencies with Cyravell's advisory database..."
ADVISORY_CHECK=$(python3 - <<EOF
import json, tomllib
with open("${ROOT_DIR}/rules/package_advisories.json") as f:
    adv_data = json.load(f)
advisories = adv_data if isinstance(adv_data, list) else adv_data.get("advisories", [])

# Cargo deps
with open("${ROOT_DIR}/Cargo.lock", "rb") as f:
    cargo_data = tomllib.load(f)
cargo_pkgs = {p["name"]: p["version"] for p in cargo_data.get("package", [])}

# npm deps
with open("${ROOT_DIR}/vscode-extension/package-lock.json") as f:
    npm_data = json.load(f)
npm_pkgs = {}
for p, info in npm_data.get("packages", {}).items():
    if p.startswith("node_modules/"):
        name = p.replace("node_modules/", "")
        npm_pkgs[name] = info.get("version")

hits = []
for a in advisories:
    eco = a.get("ecosystem", "").upper()
    pkg_name = a.get("package_name")
    if eco == "CARGO" and pkg_name in cargo_pkgs:
        hits.append(f"CARGO: {pkg_name}@{cargo_pkgs[pkg_name]} matches advisory {a.get('id')}")
    elif eco == "NPM" and pkg_name in npm_pkgs:
        hits.append(f"NPM: {pkg_name}@{npm_pkgs[pkg_name]} matches advisory {a.get('id')}")

if hits:
    print("\n".join(hits))
EOF
)

if [ -n "${ADVISORY_CHECK}" ]; then
  echo "  ✗ Error: Active dependencies match security advisory:"
  echo "${ADVISORY_CHECK}"
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ Zero dependencies match known Cyravell package security advisories"
fi

echo ""
echo "══════════════════════════════════════════════════════════════"
if [ "${ERRORS}" -eq 0 ]; then
  echo "  ✓ SOFTWARE SUPPLY-CHAIN AUDIT PASSED (0 issues found)"
  echo "══════════════════════════════════════════════════════════════"
  exit 0
else
  echo "  ✗ SOFTWARE SUPPLY-CHAIN AUDIT FAILED (${ERRORS} issues found)"
  echo "══════════════════════════════════════════════════════════════"
  exit 1
fi
