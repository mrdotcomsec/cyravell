# Cyravell Release Security & Software Supply-Chain Architecture

**Document Version:** 1.2.0  
**Phase:** Phase 3.2 (Secure Installation, Updates, and Recovery)  
**Classification:** Public Engineering & Security Documentation  

---

## 1. Executive Summary

Cyravell is an open-source, local-first security monitoring system for AI coding agents. Because Cyravell intercepts terminal execution and governs package-manager operations, the integrity and provenance of Cyravell's own release artifacts are critical. A compromised security monitor would undermine the security boundary of developer workstations.

Phase 3.0 established release manifest signing, SBOM generation, and CI automation. Phase 3.1 hardened the release trust chain and independent verification path. **Phase 3.2 establishes a complete, secure lifecycle for installing, updating, and recovering Cyravell**, ensuring that:
- Verified releases are safely installed without pre-verification binary execution.
- Pure Python fallback (RFC 8032 Ed25519) allows verification on clean machines with **zero** external pip package dependencies.
- Staging, backups, and atomic replacement guarantee transactional updates.
- Post-activation sanity checks initiate automatic rollback if newly installed binaries fail health checks.
- Unintended downgrades are strictly rejected, and high-water marks and security tombstones are monotonically preserved.
- Existing user audit logs and persistent package-security states are never overwritten or lost across installations or updates.

---

## 2. Release Trust Model & Key Separation

Cyravell strictly separates cryptographic authorities according to operational scope and lifecycle requirements:

| Authority Scope | Key Configuration File | Trusted Key ID | Official Publisher? | Primary Purpose | Algorithm |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Official Release Authority** | `rules/release_signing_keys.json` | `cyravell-release-official-2026` | **Yes (`is_official: true`)** | Production releases published for end users | Ed25519 (RFC 8032) |
| **Development & Test Authority** | `rules/release_signing_keys.json` | `cyravell-dev-test-2026` | **No (`is_official: false`)** | Local development, CI test runs, non-production packaging | Ed25519 (RFC 8032) |
| **Package Advisory Authority** | `rules/trusted_keys.json` | `cyravell-sec-official-2026` | Dedicated Scope | Package threat intelligence & vulnerability advisories | Ed25519 (RFC 8032) |
| **Runtime Audit Chain** | Local engine state | Genesis SHA-256 | Internal State | Tamper-evident local event ledger | SHA-256 Merkle chain |

### Strict Domain & Role Separation
- **Official vs. Development Key Enforcement:** By default, release verification requires an official publisher key (`is_official: true`). Manifests signed by development/test keys are rejected with `ReleaseStatus::UntrustedKey` unless `--allow-dev-keys` is explicitly provided.
- **Release keys cannot sign advisory bundles:** The `AdvisoryUpdater` strictly consults `TrustedKeyStore` which rejects release keys.
- **Advisory keys cannot sign releases:** The `ReleaseKeyStore` strictly consults `rules/release_signing_keys.json` and rejects advisory publisher keys.
- **Cross-Role Confusion Immunity:** Both keystores validate key ID membership and algorithm type before checking signatures.

### Key Lifecycle Management & Provisioning
1. **Public Key Distribution:** Trusted public keys are committed to `rules/release_signing_keys.json` and compiled into the engine binary as an embedded immutable fallback (`ReleaseKeyStore::load_embedded`).
2. **Private Key Protection:** Official private signing keys are **NEVER** committed to version control. In release environments, the private key is provisioned via an encrypted CI secret or hardware security module (HSM) and passed via the `CYRAVELL_RELEASE_SIGNING_KEY` environment variable.
3. **Revocation & Expiration:** Release keys support explicit revocation (`"is_active": false`) and cryptographic expiration timestamps (`"expires_at": "..."`). Any key past expiration or marked inactive fails closed (`ReleaseStatus::InvalidSignature`).

---

## 3. Cryptographic Release Manifest & Artifact Inventory

Every release produces a canonical `release_manifest.json` inventory cataloging all deliverable artifacts.

### Manifest Schema (`schema_version: "1.0.0"`)
- `schema_version`: Manifest schema version ("1.0.0").
- `product_name`: "cyravell".
- `release_version`: Strict SemVer release version (e.g., "0.1.0").
- `source_commit`: Exact 40-character Git commit SHA.
- `source_tag`: Git release tag (e.g., "v0.1.0").
- `build_timestamp`: UTC ISO-8601 build timestamp.
- `engine_version`: Cyravell engine version.
- `extension_version`: Cyravell VS Code extension version.
- `signing_mode`: Manifest tier (`"official"` or `"development"`).
- `target_platforms`: Supported platform triples (e.g., `["x86_64-unknown-linux-gnu"]`).
- `artifacts`: Map of filename to `ReleaseArtifact`:
  - `filename`: Base name of the file (path traversal sequences and symlinks rejected).
  - `size_bytes`: Exact byte length computed from final artifact.
  - `sha256`: Hexadecimal SHA-256 digest computed from final artifact.
  - `artifact_type`: Categorization (`binary`, `extension`, `archive`, `sbom`).
  - `target_platform`: Specific platform triple if applicable.
- `required_runtime_components`: List of essential runtime support files (e.g., rules).
- `build_metadata`: Toolchain provenance (`rustc_version`, `cargo_version`, `node_version`, `build_profile`, `source_date_epoch`).
- `sbom`: Reference to the machine-readable SBOM (`filename`, `sha256`, `format`).
- `signing_key_id`: Key ID used for authentication.
- `signature`: 64-byte Ed25519 signature in hex format.

### Deterministic Canonical Serialization for Signing
To eliminate nondeterministic JSON serialization issues (key ordering, whitespace differences, escaping), Cyravell defines a canonical byte format (`canonical_signing_bytes`):
```text
CYRAVELL-RELEASE-MANIFEST-V1
product_name:<product_name>
release_version:<release_version>
source_commit:<source_commit>
source_tag:<source_tag>
build_timestamp:<build_timestamp>
engine_version:<engine_version>
extension_version:<extension_version>
signing_mode:<signing_mode>
target_platforms:<p1>,<p2>,...
artifacts:
<filename>:<size_bytes>:<sha256_lower>:<artifact_type>:<platform>
... (lexicographically sorted by filename)
required_runtime_components:
<path>
... (lexicographically sorted)
sbom:<filename>:<sha256_lower>:<format>
```
The signature is verified against these canonical bytes. A detached signature file (`release_manifest.json.sig`) is also generated alongside the manifest.

---

## 4. Software Bill of Materials (SBOM)

Cyravell produces a machine-readable Software Bill of Materials conforming to the **SPDX 2.3 JSON specification** (`cyravell-sbom.spdx.json`).

### Scope and Generation
The SBOM is generated deterministically by `scripts/generate_sbom.sh`:
- **Rust Dependencies:** Parsed from `Cargo.lock` (96 external crates), recording package name, version, crates.io download URL, package purl (`pkg:cargo/<name>@<version>`), and SHA-256 crate checksum.
- **npm Dependencies:** Parsed from `vscode-extension/package-lock.json` (4 external packages), recording package name, version, registry URL, npm purl (`pkg:npm/<name>@<version>`), and SHA-512 integrity digest.
- **Primary Deliverables:** Cataloged with license declaration (`Apache-2.0`), supplier, and `DESCRIBES` relationships.
- **Dependency Relationships:** Explicit `DEPENDS_ON` relationships linking primary packages to all transitive runtime dependencies.

---

## 5. Build Provenance & Binary Reproducibility

### Empirical Reproducibility Assessment
- **Path Remapping:** Setting `RUSTFLAGS="--remap-path-prefix=${ROOT_DIR}=/cyravell-build"` eliminates host-specific directory paths from debug symbols and panic backtraces.
- **Timestamp Normalization:** Setting `SOURCE_DATE_EPOCH=1767225600` (2026-01-01T00:00:00Z) normalizes build timestamps.
- **Extension Packaging (.vsix):** Normalized timestamps and lexicographically sorted entries inside the OPC zip archive prevent packaging jitter.

---

## 6. Hardened Packaging Workflow (`scripts/package_release.sh`)

Official packaging enforces strict security and repository integrity preconditions:
1. **Clean Working Tree Requirement:** Rejects packaging if `git status --porcelain` is non-empty. Official releases must come from committed code.
2. **Exact Tag Matching:** Verifies that tag `v${RELEASE_VERSION}` exists and points exactly to `HEAD`.
3. **Version Consistency:** Asserts that `engine/Cargo.toml`, `vscode-extension/package.json`, and requested release version match.
4. **Secret Isolation:** Compilation (`cargo build`) and extension bundling (`npm run compile`) execute in an isolated environment where `CYRAVELL_RELEASE_SIGNING_KEY` is explicitly unset.
5. **Private Key Presence:** In official mode, fails closed if `CYRAVELL_RELEASE_SIGNING_KEY` is missing from the environment.
6. **Development Flag:** Developers can pass `--dev` (or `--allow-dirty`) for testing, which signs with `cyravell-dev-test-2026` and marks `signing_mode: "development"`.

---

## 7. Independent Standalone Verification Path

### Eliminating Pre-Installation Binary Execution
Prior release processes fell back to executing the downloaded binary (`cyravell-engine verify-release`) to verify itself if no engine was pre-installed. This created a bootstrap vulnerability: executing untrusted binaries before verifying them.

Phase 3.1 and Phase 3.2 eliminate this chicken-and-egg vulnerability with **`scripts/standalone_verify.py`**:
- **Zero Binary Execution:** Evaluates SHA-256 digests and file metadata without executing *any* downloaded executable.
- **Pure-Python Standard Library Guarantee (RFC 8032):** Includes complete, self-contained pure-Python Ed25519 curve arithmetic (`_edwards_add`, `_scalarmult`, `_decodepoint`). If the accelerated C/Rust `cryptography` package is available, it is leveraged for performance; otherwise, verification executes seamlessly using **pure standard Python 3 with ZERO external pip dependencies**.
- Usable by any developer or automation pipeline on a pristine machine before installing Cyravell.
- `scripts/install.sh` executes `standalone_verify.py` as Step 1 before any binary is installed or executed.

### Filesystem & Anti-Tamper Hardening
Both the standalone verifier and the Rust engine reject:
- **Symbolic Links:** Any artifact that is a symlink triggers immediate `SecurityCheckFailed`.
- **Non-Regular Files:** FIFOs, sockets, device nodes, and directories listed as artifacts trigger `SecurityCheckFailed`.
- **Path Traversal:** Filenames containing `..`, leading `/`, backslashes, or null bytes trigger `SecurityCheckFailed`.
- **Unlisted Executables:** Extraneous `.sh`, `.bin`, `.py`, `.exe`, or `.so` files in the release directory trigger `SecurityCheckFailed`.
- **Duplicate JSON Keys:** Malformed JSON manifests with duplicate keys are rejected.

---

## 8. User Verification & Installation Instructions

### One-Command Secure Installation (`scripts/install.sh`)
The recommended, authoritative installation mechanism is `scripts/install.sh`:
```bash
# User-mode installation (~/.local, no sudo required):
./scripts/install.sh install --release-dir path/to/release --user

# System-wide installation (/usr/local, requires sudo):
sudo ./scripts/install.sh install --release-dir path/to/release --system
```
`install.sh` automatically performs:
1. Pure-Python / accelerated cryptographic pre-verification of all artifacts against `release_manifest.json`.
2. Concurrency locking on `.install.lock`.
3. Safe staging in `.staging-<uuid>`.
4. Last known-good backup in `.backup/`.
5. Atomic replacement of binaries and rules.
6. Post-activation sanity checks (with automatic rollback on failure).
7. Editor integration (installs `.vsix` extension if `code` CLI is present).

### Manual Verification
```bash
# 1. Standalone Verification (Zero binary execution, standard Python 3):
python3 scripts/standalone_verify.py \
  --manifest path/to/release/release_manifest.json \
  --artifacts-dir path/to/release

# 2. Or using the verify_release wrapper:
./scripts/verify_release.sh --release-dir path/to/release --expected-version 0.1.0

# 3. Or directly via a trusted local engine (if already installed):
cyravell-engine verify-release \
  --manifest path/to/release/release_manifest.json \
  --artifacts-dir path/to/release \
  --expected-version 0.1.0
```

### Installation Lifecycle & Maintenance Commands
```bash
# Query installation status and active versions:
./scripts/install.sh status [--json]

# Rollback to the previous known-good version (requires justification):
./scripts/install.sh rollback --reason "Incident #402: regression in terminal parsing"

# Uninstall Cyravell (preserves user audit logs and persistent security state):
./scripts/install.sh uninstall

# Complete purge uninstall (removes binaries, rules, and user security logs):
./scripts/install.sh uninstall --purge-data
```

### Detecting & Responding to Verification Failures

| Status | Cause | Mandatory Response |
| :--- | :--- | :--- |
| `TamperedArtifact` | File content or byte size does not match signed digest | **DO NOT INSTALL.** Delete directory; re-download from official channels. |
| `InvalidSignature` | Manifest altered after signing, corrupted signature, or expired key | **DO NOT INSTALL.** Reject package; verify publisher trust material. |
| `UntrustedKey` | Manifest was signed by a development/test key (`is_official: false`) | **DO NOT INSTALL IN PRODUCTION.** Official releases require official publisher key. |
| `MissingArtifact` | Required component (binary, SBOM, vsix) missing from release | Re-download release archive; package is incomplete. |
| `SecurityCheckFailed` | Symbolic link, path traversal, or unlisted executable detected | **HIGH SECURITY ALERT.** Potential active attack; inspect provenance immediately. |

---

## 9. CI/CD Release Workflow Hardening (`.github/workflows/release.yml`)

1. **Least-Privilege Permissions:** Default workflow permissions scoped to `contents: read`. No broad write permissions.
2. **Tag-to-Commit Binding:** Validates that the git tag matches `v${VERSION}` and points directly to `GITHUB_SHA`.
3. **Commit Continuity:** Confirms `GITHUB_SHA` is an ancestor of the `main` or `master` branch.
4. **Isolated Signing Secret:** Secret `CYRAVELL_RELEASE_SIGNING_KEY` is isolated to the signing step and never exposed to build or test jobs.
5. **Pre-Publish Verification:** Executes `./scripts/verify_release.sh` against the built artifacts before any artifact upload.

---

## 10. Secure Installation Architecture, Anti-Downgrade & Recovery (Phase 3.2)

### 1. Invariants & Trust Hierarchy
The installation subsystem (`engine/src/install.rs` and `scripts/install.sh`) maintains strict invariants:
- **Zero Unverified Binary Execution:** Downloaded binaries are NEVER executed prior to passing bit-for-bit cryptographic verification against the signed manifest.
- **Transactional Staging:** New binaries and unpacked rules are staged in `.staging-<uuid>` on the destination filesystem before touching active installation paths.
- **Fail-Closed Concurrency Control:** A lockfile (`share/cyravell/.install.lock`) created with `O_CREAT | O_EXCL` prevents concurrent installations, upgrades, or rollbacks.
- **Automatic Health Check & Rollback:** The newly installed engine executes a self-test (`--version`). If the test fails, Cyravell immediately rolls back active files to the `.backup/` snapshot.
- **Monotonic High-Water Mark:** An older release cannot be installed over a newer release without `--allow-downgrade` and a descriptive operator reason (minimum 8 characters). Even under an authorized application downgrade, the persistent security state and advisory high-water mark are NEVER decreased.
- **Persistent State Preservation:** User security logs (`data/audit.log`), advisory database states (`data/advisory_security_state.json`), and project baselines (`data/baselines.json`) are preserved across upgrades, rollbacks, and standard uninstalls. Only an explicit `--purge-data` flag removes user state.

### 2. Installation State Schema (`share/cyravell/install_state.json`)
The installation subsystem durably records active and backup installation state:
```json
{
  "schema_version": "1.0.0",
  "active_version": "0.1.0",
  "active_commit": "651dd92b6067e7af5468b05911a351c45e6319bb",
  "active_tag": "v0.1.0",
  "installed_at": "2026-10-26T11:14:28Z",
  "installed_by_uid": 1000,
  "signing_key_id": "cyravell-release-official-2026",
  "is_official": true,
  "install_prefix": "/home/user/.local",
  "is_user_install": true,
  "installed_files": {
    "bin/cyravell-engine": {
      "relative_path": "bin/cyravell-engine",
      "size_bytes": 14502800,
      "sha256": "...",
      "mode": 493
    }
  },
  "backup_version": null,
  "backup_files": {},
  "high_water_version": "0.1.0",
  "last_operation": "install",
  "last_operation_timestamp": "2026-10-26T11:14:28Z"
}
```

### 3. Authorized Recovery Workflow
If an upgrade causes unanticipated issues in a developer environment, the operator can invoke the authorized rollback path:
```bash
./scripts/install.sh rollback --reason "Incident 402: terminal emulator hang with zsh 5.9"
```
Before restoring any file from `.backup/`, the rollback engine:
1. Re-computes the SHA-256 digest of every backup file.
2. Compares the digest against `install_state.json.backup_files`.
3. Rejects rollback with `SecurityViolation` if any backup artifact was altered, tampered with, or corrupted.
4. Atomically restores the verified files and updates `install_state.json`.
