#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
#
# One-command installer for Cyravell (Local-First Security Engine for AI Coding Agents)
# Usage:
#   ./install.sh          # Unprivileged user install to ~/.local (default)
#   sudo ./install.sh     # System-wide install to /usr/local

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}"

export PATH="${HOME}/.cargo/bin:${PATH}"

# Detect execution privileges and target prefix
IS_ROOT=false
if [ "$(id -u)" -eq 0 ]; then
  IS_ROOT=true
fi

USER_MODE=false
SYSTEM_MODE=false
PREFIX=""
START_DAEMON=true
INSTALL_EXTENSION=true

usage() {
  cat <<EOF
══════════════════════════════════════════════════════════════
               Cyravell One-Command Installer                  
══════════════════════════════════════════════════════════════
Usage: $0 [OPTIONS]

Options:
  --user              Install for current user only (~/.local, default if non-root)
  --system            Install system-wide (/usr/local, default if root/sudo)
  --prefix <PATH>     Custom installation prefix directory
  --no-daemon         Skip configuring/starting background systemd service
  --no-extension      Skip installing VS Code extension
  -h, --help          Show this help message

Examples:
  ./install.sh                # Easiest: installs everything in user mode
  sudo ./install.sh           # Installs system-wide for all users
EOF
  exit 0
}

# Parse options
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      USER_MODE=true
      shift
      ;;
    --system)
      SYSTEM_MODE=true
      shift
      ;;
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --no-daemon)
      START_DAEMON=false
      shift
      ;;
    --no-extension)
      INSTALL_EXTENSION=false
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1"
      echo "Run '$0 --help' for usage."
      exit 1
      ;;
  esac
done

# Resolve prefix
if [ -z "${PREFIX}" ]; then
  if [ "${SYSTEM_MODE}" = true ] || [ "${IS_ROOT}" = true ]; then
    PREFIX="/usr/local"
    SYSTEM_MODE=true
  else
    PREFIX="${HOME}/.local"
    USER_MODE=true
  fi
fi

echo "══════════════════════════════════════════════════════════════"
echo "           Cyravell Easy One-Command Installer                "
echo "══════════════════════════════════════════════════════════════"
echo "  Target Prefix:   ${PREFIX}"
echo "  Mode:            $([ "${SYSTEM_MODE}" = true ] && echo "System Mode (/usr/local)" || echo "User Mode (~/.local)")"
echo "  Start Daemon:    ${START_DAEMON}"
echo "  Install Editor:  ${INSTALL_EXTENSION}"
echo "──────────────────────────────────────────────────────────────"

# 1. Verify Prerequisites
echo ""
echo "[1/5] Checking prerequisites..."
if ! command -v cargo >/dev/null 2>&1; then
  echo "✗ Error: Rust toolchain (cargo) is not found!"
  echo "  Cyravell requires Rust to build its authoritative security engine."
  echo "  Please install Rust with:"
  echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "  Then reload your shell and re-run ./install.sh"
  exit 1
fi
echo "  ✓ Rust toolchain found: $(cargo --version)"

HAS_NODE=false
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  HAS_NODE=true
  echo "  ✓ Node.js & npm found: $(node --version)"
else
  echo "  ℹ Node.js/npm not found. Extension will not be built from source."
fi

# 2. Build or Locate Release Binaries
echo ""
echo "[2/5] Building Cyravell security engine..."
cd "${ROOT_DIR}"
cargo build --release --workspace
echo "  ✓ Compiled cyravell-engine [optimized]"
echo "  ✓ Compiled cyravell-test-harness [optimized]"

# 3. Build & Package VS Code Extension
echo ""
echo "[3/5] Preparing VS Code extension..."
VSIX_PATH="${ROOT_DIR}/vscode-extension/cyravell-0.1.0.vsix"
if [ "${HAS_NODE}" = true ]; then
  (
    cd "${ROOT_DIR}/vscode-extension"
    if [ ! -d "node_modules" ]; then
      npm ci --ignore-scripts --silent 2>/dev/null || npm install --silent
    fi
    npm run compile --silent
  )

  # Package deterministic .vsix if not present or freshly compiled
  VSIX_STAGING="$(mktemp -d /tmp/cyravell-vsix-pkg-XXXXXX)"
  mkdir -p "${VSIX_STAGING}/extension"
  cp -r "${ROOT_DIR}/vscode-extension/out" "${VSIX_STAGING}/extension/"
  cp -r "${ROOT_DIR}/vscode-extension/media" "${VSIX_STAGING}/extension/"
  cp "${ROOT_DIR}/vscode-extension/package.json" "${VSIX_STAGING}/extension/"
  if [ -f "${ROOT_DIR}/vscode-extension/README.md" ]; then
    cp "${ROOT_DIR}/vscode-extension/README.md" "${VSIX_STAGING}/extension/"
  fi

  cat <<'EOF' > "${VSIX_STAGING}/[Content_Types].xml"
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json" />
  <Default Extension="vsixmanifest" ContentType="text/xml" />
  <Default Extension="js" ContentType="application/javascript" />
  <Default Extension="svg" ContentType="image/svg+xml" />
  <Default Extension="png" ContentType="image/png" />
  <Default Extension="md" ContentType="text/markdown" />
</Types>
EOF

  cat <<EOF > "${VSIX_STAGING}/extension.vsixmanifest"
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Id="cyravell" Version="0.1.0" Language="en-US" Publisher="cyravell" />
    <DisplayName>Cyravell</DisplayName>
    <Description xml:space="preserve">Local-first security monitoring system for AI coding agents</Description>
    <Categories>Security,Other</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.80.0" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
      <Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.EnabledApiProposals" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExecutesCode" Value="true" />
      <Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />
      <Property Id="Microsoft.VisualStudio.Services.Content.Pricing" Value="Free" />
    </Properties>
    <Icon>extension/media/icon.png</Icon>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Icons.Default" Path="extension/media/icon.png" Addressable="true" />
  </Assets>
</PackageManifest>
EOF

  find "${VSIX_STAGING}" -exec touch -d "2026-01-01 00:00:00 UTC" {} +
  (cd "${VSIX_STAGING}" && find . -type f | LC_ALL=C sort | zip -q -X -9 "${VSIX_PATH}" -@)
  rm -rf "${VSIX_STAGING}"
  echo "  ✓ Packaged VS Code extension: ${VSIX_PATH}"
else
  if [ -f "${VSIX_PATH}" ]; then
    echo "  ✓ Using existing packaged extension: ${VSIX_PATH}"
  fi
fi

# 4. Install Binaries and Security Rules
echo ""
echo "[4/5] Installing Cyravell files to ${PREFIX}..."
mkdir -p "${PREFIX}/bin"
mkdir -p "${PREFIX}/share/cyravell/rules"
mkdir -p "${PREFIX}/share/cyravell/data"

install -m 755 "${ROOT_DIR}/target/release/cyravell-engine" "${PREFIX}/bin/cyravell-engine"
install -m 755 "${ROOT_DIR}/target/release/cyravell-test-harness" "${PREFIX}/bin/cyravell-test-harness"
cp -r "${ROOT_DIR}/rules/"* "${PREFIX}/share/cyravell/rules/"
chmod -R 644 "${PREFIX}/share/cyravell/rules/"* 2>/dev/null || true

# Write install state metadata
INSTALL_STATE="${PREFIX}/share/cyravell/install_state.json"
cat <<EOF > "${INSTALL_STATE}"
{
  "installed_version": "0.1.0",
  "install_prefix": "${PREFIX}",
  "is_user_mode": $([ "${USER_MODE}" = true ] && echo "true" || echo "false"),
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "  ✓ Installed cyravell-engine -> ${PREFIX}/bin/cyravell-engine"
echo "  ✓ Installed cyravell-test-harness -> ${PREFIX}/bin/cyravell-test-harness"
echo "  ✓ Installed security rules -> ${PREFIX}/share/cyravell/rules"

# Install VS Code extension if 'code' is available
if [ "${INSTALL_EXTENSION}" = true ] && [ -f "${VSIX_PATH}" ]; then
  if command -v code >/dev/null 2>&1; then
    echo "  Installing extension into VS Code..."
    if code --install-extension "${VSIX_PATH}" --force >/dev/null 2>&1; then
      echo "  ✓ VS Code extension installed successfully."
    else
      echo "  ℹ VS Code extension installation skipped (try manually: code --install-extension ${VSIX_PATH})"
    fi
  else
    echo "  ℹ 'code' CLI not found. To install later in VS Code:"
    echo "    code --install-extension ${VSIX_PATH}"
  fi
fi

# 5. Configure & Start Background Service
echo ""
echo "[5/5] Configuring and starting Cyravell engine daemon..."
if [ "${START_DAEMON}" = true ]; then
  SERVICE_STARTED=false

  if [ "${USER_MODE}" = true ]; then
    SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${SYSTEMD_USER_DIR}"
    cat <<EOF > "${SYSTEMD_USER_DIR}/cyravell.service"
[Unit]
Description=Cyravell Local Security Engine Daemon
Documentation=https://github.com/mrdotcomsec/cyravell
After=default.target

[Service]
Type=simple
ExecStart=${PREFIX}/bin/cyravell-engine start
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF

    if systemctl --user list-units >/dev/null 2>&1; then
      systemctl --user daemon-reload
      systemctl --user enable --now cyravell.service >/dev/null 2>&1 || true
      echo "  ✓ Systemd user service enabled and started: cyravell.service"
      SERVICE_STARTED=true
    fi
  elif [ "${SYSTEM_MODE}" = true ] && [ "${IS_ROOT}" = true ]; then
    cat <<EOF > "/etc/systemd/system/cyravell.service"
[Unit]
Description=Cyravell Local Security Engine Daemon
Documentation=https://github.com/mrdotcomsec/cyravell
After=network.target

[Service]
Type=simple
ExecStart=${PREFIX}/bin/cyravell-engine start
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now cyravell.service >/dev/null 2>&1 || true
    echo "  ✓ Systemd system service enabled and started: cyravell.service"
    SERVICE_STARTED=true
  fi

  # Fallback daemon launch if systemd user session is inactive (e.g. WSL, Docker, headless SSH)
  if [ "${SERVICE_STARTED}" = false ]; then
    if ! "${PREFIX}/bin/cyravell-engine" status >/dev/null 2>&1; then
      nohup "${PREFIX}/bin/cyravell-engine" start > "${PREFIX}/share/cyravell/data/engine.log" 2>&1 &
      echo "  ✓ Started engine daemon in background (PID $!)"
    else
      echo "  ✓ Engine daemon is already running."
    fi
  fi

  # Health check: wait up to 3 seconds for socket readiness
  sleep 1
  if "${PREFIX}/bin/cyravell-engine" status >/dev/null 2>&1; then
    echo "  ✓ Engine daemon is active and responding to status queries."
  fi
fi

# PATH check notice
PATH_OK=true
case ":${PATH}:" in
  *":${PREFIX}/bin:"*) ;;
  *) PATH_OK=false ;;
esac

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✓ CYRAVELL INSTALLED SUCCESSFULLY!"
echo "══════════════════════════════════════════════════════════════"
echo "  Engine Binary:     ${PREFIX}/bin/cyravell-engine"
echo "  Rules Directory:   ${PREFIX}/share/cyravell/rules"
echo "  Daemon Service:    cyravell.service (Active & Listening)"
if [ -f "${VSIX_PATH}" ]; then
echo "  VS Code Extension: ${VSIX_PATH}"
fi
echo "──────────────────────────────────────────────────────────────"

if [ "${PATH_OK}" = false ]; then
  echo ""
  echo "⚠️  NOTE: ${PREFIX}/bin is not in your current PATH!"
  echo "   Add it now with:"
  echo "     export PATH=\"${PREFIX}/bin:\$PATH\""
  echo "   To make it permanent, add to ~/.bashrc or ~/.zshrc:"
  echo "     echo 'export PATH=\"${PREFIX}/bin:\$PATH\"' >> ~/.bashrc"
fi

echo ""
echo "  QUICK START:"
echo "  1. Check engine status:      cyravell-engine status"
echo "  2. Launch protected shell:   cyravell-engine shell"
echo "  3. In VS Code:               Click the Cyravell shield in the Activity Bar"
echo "══════════════════════════════════════════════════════════════"

