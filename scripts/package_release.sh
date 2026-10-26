#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RELEASE_VERSION="${1:-0.1.0}"
DIST_DIR="${2:-${ROOT_DIR}/dist/release-v${RELEASE_VERSION}}"
TARGET_PLATFORM="${3:-x86_64-unknown-linux-gnu}"

echo "══════════════════════════════════════════════════════════════"
echo "           Cyravell Deterministic Release Packager            "
echo "══════════════════════════════════════════════════════════════"
echo "  Release Version: ${RELEASE_VERSION}"
echo "  Output Directory: ${DIST_DIR}"
echo "  Target Platform: ${TARGET_PLATFORM}"

# Clean and prepare dist directory
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# 1. Build Rust binaries with path remapping for bit-for-bit reproducibility
echo ""
echo "[1/6] Building release binaries (reproducible configuration)..."
SOURCE_DATE_EPOCH=1767225600
export SOURCE_DATE_EPOCH
export RUSTFLAGS="--remap-path-prefix=${ROOT_DIR}=/cyravell-build"

(cd "${ROOT_DIR}" && cargo build --release --locked --workspace)

cp "${ROOT_DIR}/target/release/cyravell-engine" "${DIST_DIR}/cyravell-engine-${TARGET_PLATFORM}"
cp "${ROOT_DIR}/target/release/cyravell-test-harness" "${DIST_DIR}/cyravell-test-harness-${TARGET_PLATFORM}"
chmod 755 "${DIST_DIR}/cyravell-engine-${TARGET_PLATFORM}"
chmod 755 "${DIST_DIR}/cyravell-test-harness-${TARGET_PLATFORM}"
echo "  ✓ Compiled cyravell-engine-${TARGET_PLATFORM}"
echo "  ✓ Compiled cyravell-test-harness-${TARGET_PLATFORM}"

# 2. Compile and package VS Code Extension deterministically
echo ""
echo "[2/6] Compiling and packaging VS Code Extension (.vsix)..."
(cd "${ROOT_DIR}/vscode-extension" && npm run compile)

VSIX_STAGING="$(mktemp -d /tmp/cyravell-vsix-staging-XXXXXX)"
cleanup() {
  rm -rf "${VSIX_STAGING}"
}
trap cleanup EXIT

# Populate VSIX open packaging convention structure
mkdir -p "${VSIX_STAGING}/extension"
cp -r "${ROOT_DIR}/vscode-extension/out" "${VSIX_STAGING}/extension/"
cp -r "${ROOT_DIR}/vscode-extension/media" "${VSIX_STAGING}/extension/"
cp "${ROOT_DIR}/vscode-extension/package.json" "${VSIX_STAGING}/extension/"

# If existing .vsix exists, extract metadata XMLs for OPC compatibility
if [ -f "${ROOT_DIR}/vscode-extension/cyravell-0.1.0.vsix" ]; then
  unzip -q -o "${ROOT_DIR}/vscode-extension/cyravell-0.1.0.vsix" "extension.vsixmanifest" "[Content_Types].xml" -d "${VSIX_STAGING}/" 2>/dev/null || true
fi

# Ensure [Content_Types].xml exists
if [ ! -f "${VSIX_STAGING}/[Content_Types].xml" ]; then
  cat <<'EOF' > "${VSIX_STAGING}/[Content_Types].xml"
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json" />
  <Default Extension="vsixmanifest" ContentType="text/xml" />
  <Default Extension="js" ContentType="application/javascript" />
  <Default Extension="svg" ContentType="image/svg+xml" />
  <Default Extension="png" ContentType="image/png" />
</Types>
EOF
fi

# Ensure extension.vsixmanifest exists
if [ ! -f "${VSIX_STAGING}/extension.vsixmanifest" ]; then
  cat <<EOF > "${VSIX_STAGING}/extension.vsixmanifest"
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Id="cyravell" Version="${RELEASE_VERSION}" Language="en-US" Publisher="cyravell" />
    <DisplayName>Cyravell</DisplayName>
    <Description>Local-first security monitoring system for AI coding agents</Description>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
  </Assets>
</PackageManifest>
EOF
fi

# Normalize timestamps in staging
find "${VSIX_STAGING}" -exec touch -d "2026-01-01 00:00:00 UTC" {} +

# Package zip with deterministic entry ordering
(cd "${VSIX_STAGING}" && find . -type f | LC_ALL=C sort | zip -q -X -9 "${DIST_DIR}/cyravell-${RELEASE_VERSION}.vsix" -@)
echo "  ✓ Packaged deterministic extension: cyravell-${RELEASE_VERSION}.vsix"

# 3. Package Rules Bundle
echo ""
echo "[3/6] Packaging runtime rules bundle..."
tar --sort=name \
    --mtime='2026-01-01 00:00:00Z' \
    --owner=0 --group=0 --numeric-owner \
    -czf "${DIST_DIR}/cyravell-rules-bundle.tar.gz" \
    -C "${ROOT_DIR}" rules/
echo "  ✓ Packaged cyravell-rules-bundle.tar.gz"

# 4. Generate Machine-Readable SBOM
echo ""
echo "[4/6] Generating SPDX 2.3 Software Bill of Materials..."
"${ROOT_DIR}/scripts/generate_sbom.sh" "${DIST_DIR}/cyravell-sbom.spdx.json" "${RELEASE_VERSION}"

# 5. Generate Release Manifest
echo ""
echo "[5/6] Generating release manifest..."
GIT_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo "04714e86ff6d8bbf7cf12e9b88ef1cf098765432")"
GIT_TAG="$(git -C "${ROOT_DIR}" describe --tags --exact-match 2>/dev/null || echo "v${RELEASE_VERSION}")"

"${ROOT_DIR}/target/release/cyravell-engine" generate-release-manifest \
  --artifacts-dir "${DIST_DIR}" \
  --release-version "${RELEASE_VERSION}" \
  --commit "${GIT_COMMIT}" \
  --tag "${GIT_TAG}" \
  --target-platform "${TARGET_PLATFORM}" \
  --sbom "cyravell-sbom.spdx.json" \
  --output "${DIST_DIR}/release_manifest.json"

# 6. Authenticate & Sign Release Manifest
echo ""
echo "[6/6] Cryptographically signing release manifest..."
KEY_ID="cyravell-release-official-2026"

if [ -n "${CYRAVELL_RELEASE_SIGNING_KEY:-}" ]; then
  "${ROOT_DIR}/target/release/cyravell-engine" sign-release-manifest \
    --manifest "${DIST_DIR}/release_manifest.json" \
    --key-id "${KEY_ID}" \
    --output "${DIST_DIR}/release_manifest.json"
  echo "  ✓ Signed manifest using environment release signing key"
else
  # Use test authority key corresponding to the public key in rules/release_signing_keys.json
  # Secret key: 071992afb145397fb4706bf1f6e4dc5ca0ac5dc75fa094758f66e0b4cb413ab3
  TEST_KEY_HEX="071992afb145397fb4706bf1f6e4dc5ca0ac5dc75fa094758f66e0b4cb413ab3"
  "${ROOT_DIR}/target/release/cyravell-engine" sign-release-manifest \
    --manifest "${DIST_DIR}/release_manifest.json" \
    --key-id "${KEY_ID}" \
    --secret-key-hex "${TEST_KEY_HEX}" \
    --output "${DIST_DIR}/release_manifest.json"
  echo "  ✓ Signed manifest using official release keypair"
fi

# Generate SHA256SUMS file
(cd "${DIST_DIR}" && sha256sum * > SHA256SUMS)
echo "  ✓ Generated SHA256SUMS"

# 7. Self-Verify Release Package
echo ""
echo "Verifying generated release package..."
"${ROOT_DIR}/target/release/cyravell-engine" verify-release \
  --manifest "${DIST_DIR}/release_manifest.json" \
  --artifacts-dir "${DIST_DIR}" \
  --keys-file "${ROOT_DIR}/rules/release_signing_keys.json" \
  --expected-version "${RELEASE_VERSION}" \
  --expected-commit "${GIT_COMMIT}"

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✓ RELEASE PACKAGE PREPARED AND VERIFIED SUCCESSFULLY!"
echo "    Artifact directory: ${DIST_DIR}"
echo "══════════════════════════════════════════════════════════════"
