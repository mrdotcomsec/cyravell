#!/usr/bin/env bash
# Copyright 2026 Cyravell Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_FILE="${1:-${ROOT_DIR}/cyravell-sbom.spdx.json}"
RELEASE_VERSION="${2:-0.1.0}"

echo "Generating SPDX 2.3 Software Bill of Materials (SBOM)..."
echo "  Target: ${OUTPUT_FILE}"
echo "  Release Version: ${RELEASE_VERSION}"

python3 - <<EOF
import os
import sys
import json
import tomllib
import hashlib
from datetime import datetime, timezone

root_dir = "${ROOT_DIR}"
output_path = "${OUTPUT_FILE}"
release_version = "${RELEASE_VERSION}"

# 1. Parse Cargo.lock
cargo_lock_path = os.path.join(root_dir, "Cargo.lock")
if not os.path.exists(cargo_lock_path):
    print(f"Error: Cargo.lock not found at {cargo_lock_path}", file=sys.stderr)
    sys.exit(1)

with open(cargo_lock_path, "rb") as f:
    cargo_data = tomllib.load(f)

# 2. Parse vscode-extension/package-lock.json
npm_lock_path = os.path.join(root_dir, "vscode-extension", "package-lock.json")
if not os.path.exists(npm_lock_path):
    print(f"Error: package-lock.json not found at {npm_lock_path}", file=sys.stderr)
    sys.exit(1)

with open(npm_lock_path, "r", encoding="utf-8") as f:
    npm_data = json.load(f)

spdx_packages = []
relationships = []

# Primary packages
spdx_packages.append({
    "name": "cyravell-engine",
    "SPDXID": "SPDXRef-Package-Cyravell-Engine",
    "versionInfo": release_version,
    "downloadLocation": "https://github.com/cyravell/cyravell",
    "filesAnalyzed": False,
    "licenseConcluded": "Apache-2.0",
    "licenseDeclared": "Apache-2.0",
    "supplier": "Organization: Cyravell Contributors",
    "description": "Deterministic local-first security engine for AI coding agents",
    "externalRefs": [{
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": f"pkg:github/cyravell/cyravell-engine@{release_version}"
    }]
})
relationships.append({
    "spdxElementId": "SPDXRef-DOCUMENT",
    "relatedSpdxElement": "SPDXRef-Package-Cyravell-Engine",
    "relationshipType": "DESCRIBES"
})

spdx_packages.append({
    "name": "cyravell-vscode-extension",
    "SPDXID": "SPDXRef-Package-Cyravell-Extension",
    "versionInfo": release_version,
    "downloadLocation": "https://github.com/cyravell/cyravell",
    "filesAnalyzed": False,
    "licenseConcluded": "Apache-2.0",
    "licenseDeclared": "Apache-2.0",
    "supplier": "Organization: Cyravell Contributors",
    "description": "Cyravell VS Code Extension for secure terminal execution",
    "externalRefs": [{
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": f"pkg:npm/cyravell@{release_version}"
    }]
})
relationships.append({
    "spdxElementId": "SPDXRef-DOCUMENT",
    "relatedSpdxElement": "SPDXRef-Package-Cyravell-Extension",
    "relationshipType": "DESCRIBES"
})

def safe_id(val):
    return val.replace("@", "").replace("/", "-").replace("_", "-").replace(".", "-")

# Enumerate Cargo packages
seen_cargo = set()
for pkg in cargo_data.get("package", []):
    name = pkg.get("name")
    version = pkg.get("version")
    if not name or not version:
        continue
    if name in ["cyravell-engine", "cyravell-test-harness"]:
        continue
    
    key = (name, version)
    if key in seen_cargo:
        continue
    seen_cargo.add(key)

    pkg_id = f"SPDXRef-Package-cargo-{safe_id(name)}-{safe_id(version)}"
    checksum = pkg.get("checksum")

    pkg_entry = {
        "name": name,
        "SPDXID": pkg_id,
        "versionInfo": version,
        "downloadLocation": f"https://crates.io/crates/{name}/{version}",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "supplier": "NOASSERTION",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": f"pkg:cargo/{name}@{version}"
        }]
    }

    if checksum:
        pkg_entry["checksums"] = [{
            "algorithm": "SHA256",
            "checksumValue": checksum
        }]

    spdx_packages.append(pkg_entry)
    relationships.append({
        "spdxElementId": "SPDXRef-Package-Cyravell-Engine",
        "relatedSpdxElement": pkg_id,
        "relationshipType": "DEPENDS_ON"
    })

# Enumerate npm packages
seen_npm = set()
for pkg_path, pkg_info in npm_data.get("packages", {}).items():
    if not pkg_path or pkg_path == "":
        continue
    # Name from path: node_modules/@types/node -> @types/node
    name = pkg_path.replace("node_modules/", "")
    version = pkg_info.get("version")
    if not name or not version:
        continue

    key = (name, version)
    if key in seen_npm:
        continue
    seen_npm.add(key)

    pkg_id = f"SPDXRef-Package-npm-{safe_id(name)}-{safe_id(version)}"
    download_loc = pkg_info.get("resolved", f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz")

    pkg_entry = {
        "name": name,
        "SPDXID": pkg_id,
        "versionInfo": version,
        "downloadLocation": download_loc,
        "filesAnalyzed": False,
        "licenseConcluded": pkg_info.get("license", "NOASSERTION"),
        "supplier": "NOASSERTION",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": f"pkg:npm/{name}@{version}"
        }]
    }

    integrity = pkg_info.get("integrity")
    if integrity and integrity.startswith("sha512-"):
        # standard npm integrity
        pkg_entry["checksums"] = [{
            "algorithm": "SHA512",
            "checksumValue": integrity.replace("sha512-", "")
        }]

    spdx_packages.append(pkg_entry)
    relationships.append({
        "spdxElementId": "SPDXRef-Package-Cyravell-Extension",
        "relatedSpdxElement": pkg_id,
        "relationshipType": "DEPENDS_ON"
    })

# Build complete SPDX document
sbom_doc = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"Cyravell-{release_version}-SBOM",
    "documentNamespace": f"https://github.com/cyravell/cyravell/spdxdocs/cyravell-{release_version}-{hashlib.sha256(release_version.encode()).hexdigest()[:8]}",
    "creationInfo": {
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "creators": [
            "Tool: Cyravell-SBOM-Generator-1.0",
            "Organization: Cyravell Contributors"
        ]
    },
    "packages": spdx_packages,
    "relationships": relationships
}

# Ensure output directory exists
out_dir = os.path.dirname(os.path.abspath(output_path))
if not os.path.exists(out_dir):
    os.makedirs(out_dir, exist_ok=True)

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(sbom_doc, f, indent=2)

print(f"  ✓ SPDX 2.3 SBOM generated successfully: {output_path}")
print(f"  ✓ Total packages cataloged: {len(spdx_packages)} (Rust crates: {len(seen_cargo)}, npm packages: {len(seen_npm)}, primary: 2)")
EOF

chmod +x "${OUTPUT_FILE}" 2>/dev/null || true
