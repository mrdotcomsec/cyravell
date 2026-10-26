#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RELEASE_VERSION="0.1.0"
DIST_DIR=""
TARGET_PLATFORM="x86_64-unknown-linux-gnu"
BUILD_MODE="official"
ALLOW_DIRTY=false

# Parse arguments and flags
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      BUILD_MODE="$2"
      shift 2
      ;;
    --dev|--development)
      BUILD_MODE="development"
      shift
      ;;
    --official)
      BUILD_MODE="official"
      shift
      ;;
    --allow-dirty)
      ALLOW_DIRTY=true
      shift
      ;;
    --platform)
      TARGET_PLATFORM="$2"
      shift 2
      ;;
    --dist)
      DIST_DIR="$2"
      shift 2
      ;;
    -*)
      echo "Unknown option: $1"
      exit 1
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [ ${#POSITIONAL[@]} -gt 0 ]; then
  RELEASE_VERSION="${POSITIONAL[0]}"
fi
if [ ${#POSITIONAL[@]} -gt 1 ]; then
  DIST_DIR="${POSITIONAL[1]}"
fi
if [ ${#POSITIONAL[@]} -gt 2 ]; then
  TARGET_PLATFORM="${POSITIONAL[2]}"
fi

if [ -z "${DIST_DIR}" ]; then
  DIST_DIR="${ROOT_DIR}/dist/release-v${RELEASE_VERSION}"
fi

echo "══════════════════════════════════════════════════════════════"
echo "           Cyravell Deterministic Release Packager            "
echo "══════════════════════════════════════════════════════════════"
echo "  Release Version:  ${RELEASE_VERSION}"
echo "  Build Mode:       ${BUILD_MODE}"
echo "  Output Directory: ${DIST_DIR}"
echo "  Target Platform:  ${TARGET_PLATFORM}"
echo "──────────────────────────────────────────────────────────────"

# 0. Git state and repository integrity checks
if ! git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "✗ Error: Repository root '${ROOT_DIR}' is not a valid Git repository."
  exit 1
fi

GIT_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
GIT_DIRTY=false
if [ -n "$(git -C "${ROOT_DIR}" status --porcelain)" ]; then
  GIT_DIRTY=true
fi

# Version consistency checks across manifests
ENGINE_CARGO_VERSION="$(grep -m1 '^version =' "${ROOT_DIR}/engine/Cargo.toml" | cut -d '"' -f2)"
EXT_PKG_VERSION="$(grep -m1 '"version":' "${ROOT_DIR}/vscode-extension/package.json" | cut -d '"' -f4)"

if [ "${ENGINE_CARGO_VERSION}" != "${RELEASE_VERSION}" ]; then
  echo "✗ Error: Version mismatch! Cargo.toml defines '${ENGINE_CARGO_VERSION}', requested '${RELEASE_VERSION}'"
  exit 1
fi
if [ "${EXT_PKG_VERSION}" != "${RELEASE_VERSION}" ]; then
  echo "✗ Error: Version mismatch! vscode-extension/package.json defines '${EXT_PKG_VERSION}', requested '${RELEASE_VERSION}'"
  exit 1
fi

if [ "${BUILD_MODE}" = "official" ]; then
  # Strict official release validation
  if [ "${GIT_DIRTY}" = true ] && [ "${ALLOW_DIRTY}" = false ]; then
    echo "✗ CRITICAL ERROR: Git working tree is dirty!"
    echo "  Official production releases MUST be packaged from a clean, committed Git working tree."
    echo "  Uncommitted files detected:"
    git -C "${ROOT_DIR}" status --porcelain | head -n 20
    echo "  Please commit or stash your changes before creating an official release."
    echo "  (For local development/testing builds, pass --dev or --allow-dirty)."
    exit 1
  fi

  # Verify git tag exists and points exactly to HEAD
  EXPECTED_TAG="v${RELEASE_VERSION}"
  TAG_COMMIT="$(git -C "${ROOT_DIR}" rev-list -n 1 "${EXPECTED_TAG}" 2>/dev/null || true)"
  if [ -z "${TAG_COMMIT}" ]; then
    echo "✗ CRITICAL ERROR: Release tag '${EXPECTED_TAG}' does not exist!"
    echo "  Official releases require an annotated or lightweight Git tag pointing to HEAD (${GIT_COMMIT})."
    echo "  Create the tag first: git tag -a ${EXPECTED_TAG} -m \"Release ${EXPECTED_TAG}\""
    exit 1
  elif [ "${TAG_COMMIT}" != "${GIT_COMMIT}" ]; then
    echo "✗ CRITICAL ERROR: Tag '${EXPECTED_TAG}' points to commit ${TAG_COMMIT}, but HEAD is at ${GIT_COMMIT}!"
    echo "  Release tag must match the current checkout HEAD."
    exit 1
  fi
  GIT_TAG="${EXPECTED_TAG}"

  # Require production signing key in environment
  if [ -z "${CYRAVELL_RELEASE_SIGNING_KEY:-}" ]; then
    echo "✗ CRITICAL ERROR: CYRAVELL_RELEASE_SIGNING_KEY environment variable is not set!"
    echo "  Official production releases MUST be cryptographically authenticated using the"
    echo "  authoritative publisher private key. Private keys are never hardcoded or committed."
    echo "  For local testing or development builds, pass --dev."
    exit 1
  fi
  KEY_ID="cyravell-release-official-2026"
  SIGNING_MODE="official"
else
  # Development / test build mode
  echo "  ℹ Packaging in DEVELOPMENT mode."
  if [ "${GIT_DIRTY}" = true ]; then
    GIT_COMMIT="${GIT_COMMIT}-dirty"
    echo "  ℹ Working tree is dirty; commit labeled as '${GIT_COMMIT}'"
  fi
  GIT_TAG="$(git -C "${ROOT_DIR}" describe --tags --exact-match 2>/dev/null || echo "v${RELEASE_VERSION}-dev")"
  KEY_ID="cyravell-dev-test-2026"
  SIGNING_MODE="development"
fi

# Clean and prepare dist directory
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# 1. Build Rust binaries with path remapping for bit-for-bit reproducibility
# LEAST PRIVILEGE: Run build step with CYRAVELL_RELEASE_SIGNING_KEY unset
echo ""
echo "[1/6] Building release binaries (isolated environment, reproducible configuration)..."
SOURCE_DATE_EPOCH=1767225600
export SOURCE_DATE_EPOCH
export RUSTFLAGS="--remap-path-prefix=${ROOT_DIR}=/cyravell-build"

(cd "${ROOT_DIR}" && env -u CYRAVELL_RELEASE_SIGNING_KEY cargo build --release --locked --workspace)

cp "${ROOT_DIR}/target/release/cyravell-engine" "${DIST_DIR}/cyravell-engine-${TARGET_PLATFORM}"
cp "${ROOT_DIR}/target/release/cyravell-test-harness" "${DIST_DIR}/cyravell-test-harness-${TARGET_PLATFORM}"
chmod 755 "${DIST_DIR}/cyravell-engine-${TARGET_PLATFORM}"
chmod 755 "${DIST_DIR}/cyravell-test-harness-${TARGET_PLATFORM}"
echo "  ✓ Compiled cyravell-engine-${TARGET_PLATFORM}"
echo "  ✓ Compiled cyravell-test-harness-${TARGET_PLATFORM}"

# 2. Compile and package VS Code Extension deterministically
# LEAST PRIVILEGE: Run npm compile with CYRAVELL_RELEASE_SIGNING_KEY unset
echo ""
echo "[2/6] Compiling and packaging VS Code Extension (.vsix)..."
(cd "${ROOT_DIR}/vscode-extension" && env -u CYRAVELL_RELEASE_SIGNING_KEY npm run compile)

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
env -u CYRAVELL_RELEASE_SIGNING_KEY "${ROOT_DIR}/scripts/generate_sbom.sh" "${DIST_DIR}/cyravell-sbom.spdx.json" "${RELEASE_VERSION}"

# 5. Generate Release Manifest
echo ""
echo "[5/6] Generating release manifest..."
"${ROOT_DIR}/target/release/cyravell-engine" generate-release-manifest \
  --artifacts-dir "${DIST_DIR}" \
  --release-version "${RELEASE_VERSION}" \
  --commit "${GIT_COMMIT}" \
  --tag "${GIT_TAG}" \
  --target-platform "${TARGET_PLATFORM}" \
  --sbom "cyravell-sbom.spdx.json" \
  --signing-mode "${SIGNING_MODE}" \
  --output "${DIST_DIR}/release_manifest.json"

# 6. Authenticate & Sign Release Manifest
# ISOLATION: Key is only injected into this discrete step
echo ""
echo "[6/6] Cryptographically signing release manifest..."
if [ "${BUILD_MODE}" = "official" ]; then
  "${ROOT_DIR}/target/release/cyravell-engine" sign-release-manifest \
    --manifest "${DIST_DIR}/release_manifest.json" \
    --key-id "${KEY_ID}" \
    --signing-mode "${SIGNING_MODE}" \
    --output "${DIST_DIR}/release_manifest.json"
  echo "  ✓ Signed manifest using official publisher key from environment"
else
  DEV_TEST_KEY_HEX="1008694a11eaa7aeed52e7e6ba15d21385cbbf51cc2ed6fe1ef620d028e296c4"
  "${ROOT_DIR}/target/release/cyravell-engine" sign-release-manifest \
    --manifest "${DIST_DIR}/release_manifest.json" \
    --key-id "${KEY_ID}" \
    --secret-key-hex "${DEV_TEST_KEY_HEX}" \
    --signing-mode "${SIGNING_MODE}" \
    --output "${DIST_DIR}/release_manifest.json"
  echo "  ✓ Signed manifest using development/test keypair"
fi

# Extract and generate detached signature (.sig)
python3 -c "
import json
m = json.load(open('${DIST_DIR}/release_manifest.json'))
sig = m.get('signature', '')
with open('${DIST_DIR}/release_manifest.json.sig', 'w') as f:
    f.write(sig + '\n')
"
echo "  ✓ Generated detached signature: release_manifest.json.sig"

# Generate SHA256SUMS file
(cd "${DIST_DIR}" && sha256sum * > SHA256SUMS)
echo "  ✓ Generated SHA256SUMS"

# 7. Pre-Installation Release Verification
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Running Pre-Installation Verification on Generated Package..."
echo "══════════════════════════════════════════════════════════════"

VERIFY_FLAGS=("--release-dir" "${DIST_DIR}" "--expected-version" "${RELEASE_VERSION}" "--expected-commit" "${GIT_COMMIT}")
if [ "${BUILD_MODE}" != "official" ]; then
  VERIFY_FLAGS+=("--allow-dev-keys")
fi

"${ROOT_DIR}/scripts/verify_release.sh" "${VERIFY_FLAGS[@]}"

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✓ RELEASE PACKAGE PREPARED AND VERIFIED SUCCESSFULLY!"
echo "    Mode:             ${BUILD_MODE}"
echo "    Version:          ${RELEASE_VERSION}"
echo "    Commit:           ${GIT_COMMIT}"
echo "    Tag:              ${GIT_TAG}"
echo "    Artifact dir:     ${DIST_DIR}"
echo "══════════════════════════════════════════════════════════════"
