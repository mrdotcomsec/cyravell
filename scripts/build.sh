#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PATH="${HOME}/.cargo/bin:${PATH}"

echo "══════════════════════════════════════════════════════════════"
echo "               Building Cyravell Components                    "
echo "══════════════════════════════════════════════════════════════"

# 1. Build Rust Engine and Test Harness
echo "[1/2] Building Rust engine and test harness..."
cd "${ROOT_DIR}"
cargo build --workspace

# 2. Build VS Code Extension
echo "[2/2] Building VS Code extension..."
cd "${ROOT_DIR}/vscode-extension"
if [ ! -d "node_modules" ]; then
    npm install
fi
npm run compile

echo ""
echo "✓ All Cyravell components built successfully!"
echo "  - Engine binary:       ${ROOT_DIR}/target/debug/cyravell-engine"
echo "  - Test Harness binary: ${ROOT_DIR}/target/debug/cyravell-test-harness"
echo "  - Extension output:    ${ROOT_DIR}/vscode-extension/out/"

