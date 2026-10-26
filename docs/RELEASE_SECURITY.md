# Cyravell Release Security & Software Supply-Chain Architecture

**Document Version:** 1.0.0  
**Phase:** Phase 3.0 (Release Integrity and Software Supply-Chain Security)  
**Classification:** Public Engineering & Security Documentation  

---

## 1. Executive Summary

Cyravell is an open-source, local-first security monitoring system for AI coding agents. Because Cyravell intercepts terminal execution and governs package-manager operations, the integrity and provenance of Cyravell's own release artifacts are critical. A compromised security monitor would undermine the security boundary of developer workspaces.

Phase 3.0 establishes an end-to-end, cryptographically verifiable release process that protects users against:
- Compromised or drifting third-party dependencies.
- Accidental release of untested code or failing security gates.
- Artifact substitution and man-in-the-middle distribution attacks.
- Ambiguity regarding whether an installed binary corresponds to a reviewed source revision.

---

## 2. Release Trust Model & Key Separation

Cyravell strictly separates cryptographic authorities according to operational scope and lifecycle requirements:

| Authority Scope | Key Configuration File | Trusted Key ID | Primary Purpose | Cryptographic Algorithm |
| :--- | :--- | :--- | :--- | :--- |
| **Release Signing Authority** | `rules/release_signing_keys.json` | `cyravell-release-official-2026` | Authenticating distributed deliverables (engine, test harness, `.vsix`, rules bundle, SBOM) | Ed25519 (RFC 8032) |
| **Package Advisory Authority** | `rules/trusted_keys.json` | `cyravell-sec-official-2026` | Authenticating threat intelligence and package vulnerability bundles | Ed25519 (RFC 8032) |
| **Runtime Audit Chain** | Local engine state | Genesis SHA-256 | Tamper-evident local event ledger | SHA-256 Merkle chain |

### Strict Domain Separation
- **Release keys cannot sign advisory bundles:** The `AdvisoryUpdater` strictly consults `TrustedKeyStore` which rejects release keys.
- **Advisory keys cannot sign releases:** The `ReleaseKeyStore` strictly consults `rules/release_signing_keys.json` and rejects advisory publisher keys.
- **Cross-Role Confusion Immunity:** Both keystores validate key ID membership and algorithm type before checking signatures.

### Key Lifecycle Management & Provisioning
1. **Public Key Distribution:** Trusted public keys are committed to `rules/release_signing_keys.json` and compiled into the engine binary as an embedded immutable fallback (`ReleaseKeyStore::load_embedded`).
2. **Private Key Protection:** Private signing keys are **NEVER** committed to version control. In release environments, the private key is provisioned via an encrypted CI secret or hardware security module (HSM) and passed via the `CYRAVELL_RELEASE_SIGNING_KEY` environment variable.
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
- `target_platforms`: Supported platform triples (e.g., `["x86_64-unknown-linux-gnu"]`).
- `artifacts`: Map of filename to `ReleaseArtifact`:
  - `filename`: Base name of the file (path traversal sequences rejected).
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

### SBOM Validation & Invariants
- Generated SBOMs must contain valid SPDX 2.3 identifiers, document namespaces, and creator tags.
- The SBOM's SHA-256 digest is embedded in `release_manifest.json` and validated during release verification.
- **Security Limitation:** An SBOM is an inventory, not proof that components are bug-free or vulnerability-free.

---

## 5. Build Provenance & Binary Reproducibility

### Empirical Reproducibility Assessment
During Phase 3.0, independent clean builds of `cyravell-engine` were evaluated across isolated build directories.
- **Rust Compiler Flags:** Setting `RUSTFLAGS="--remap-path-prefix=${ROOT_DIR}=/cyravell-build"` eliminates host-specific directory paths from debug symbols and panic backtraces.
- **Timestamp Normalization:** Setting `SOURCE_DATE_EPOCH=1767225600` (2026-01-01T00:00:00Z) normalizes build timestamps.
- **Evidence:** Two independent clean release builds produced bit-for-bit identical SHA-256 digests:
  - Run 1: `1ddc8562564d3a06ba9355ac4cf380aec331e3388716ef1c59cb84184a400469`
  - Run 2: `1ddc8562564d3a06ba9355ac4cf380aec331e3388716ef1c59cb84184a400469`
  - Status: Bit-for-bit identical (`Identical: True`).

### Extension Packaging Reproducibility (.vsix)
The VS Code extension (`cyravell-0.1.0.vsix`) is an Open Packaging Conventions (OPC) ZIP archive. Because default zip tools record current timestamps and nondeterministic directory traversals:
1. `scripts/package_release.sh` normalizes all staging file timestamps to `2026-01-01 00:00:00 UTC`.
2. Staging entries are sorted lexicographically (`find . -type f | LC_ALL=C sort | zip -X -9 ...`).
3. Output `.vsix` packages achieve consistent checksums across packaging runs on equivalent toolchains.

### Known Limitations
- Toolchain differences (different `rustc`, `node`, or libc versions) may produce different binary outputs.
- Future native C dependencies or build scripts executing host commands could reintroduce nondeterminism unless strictly constrained.

---

## 6. Dependency and Build-Input Security

The dependency audit script (`scripts/audit_dependencies.sh`) runs both locally and as a mandatory CI gate:

1. **Lockfile Enforcement:** Verifies `Cargo.lock` and `vscode-extension/package-lock.json` are committed and tracked in Git.
2. **Deterministic Resolution:** Executes `cargo check --locked --workspace`. Any unreviewed dependency update causes immediate failure.
3. **Registry Conformance:** Scans `Cargo.lock` ensuring all third-party crates originate from the official `crates.io` registry. Rejects unreviewed Git repositories or unpinned mutable tags.
4. **Zero Wildcard Versions:** Scans all `Cargo.toml` files to reject wildcard versions (`version = "*"`).
5. **npm Security Audit:** Runs `npm audit` against the extension dependency tree, enforcing 0 vulnerabilities.
6. **Lifecycle Hook Inspection:** Inspects `package.json` for dangerous install hooks (`preinstall`, `postinstall`, `install`).
7. **Advisory Database Cross-Referencing:** Cross-checks active workspace dependencies against Cyravell's own package security advisory database (`rules/package_advisories.json`).

---

## 7. Automated Security Verification (CI/CD)

CI workflows (`.github/workflows/ci.yml` and `.github/workflows/release.yml`) automate verification:

### Pinned Actions Policy
To prevent supply-chain compromise of CI workflows, all third-party GitHub Actions are pinned to immutable 40-character commit SHAs:
- `actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11` (# v4.1.1)
- `actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8` (# v4.0.2)
- `dtolnay/rust-toolchain@7b7640457d930a38d9bda16020914e66cf17f65a` (# master 2024-03)
- `actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3` (# v4.3.1)

### CI Verification Order
1. Dependency and supply-chain audit (`scripts/audit_dependencies.sh`).
2. Rust code formatting check (`cargo fmt --check`).
3. Rust compilation check with locked dependencies (`cargo check --locked --workspace`).
4. Static linting with zero warnings (`cargo clippy --workspace -- -D warnings`).
5. Complete unit and subsystem tests (`cargo test --workspace`).
6. Extension TypeScript compilation and unit tests (`npm run compile && npm test`).
7. End-to-end vertical slice, daemon IPC, controlled gate, package interception, and adversarial tests (`scripts/test.sh`).

---

## 8. User Verification & Installation Workflow

Users must verify release integrity before executing binaries or installing the extension.

### Verification Command
```bash
# Verify release directory against release_manifest.json and trusted public keys
./scripts/verify_release.sh /path/to/cyravell-release-v0.1.0 0.1.0
```
Or directly via the engine CLI:
```bash
cyravell-engine verify-release \
  --manifest /path/to/cyravell-release-v0.1.0/release_manifest.json \
  --artifacts-dir /path/to/cyravell-release-v0.1.0 \
  --expected-version 0.1.0
```

### Verification Checks Performed
1. **Manifest Integrity:** Verifies JSON syntax, schema compliance, and absence of duplicate keys.
2. **Cryptographic Signature:** Computes canonical signing bytes and verifies the Ed25519 signature against `rules/release_signing_keys.json`.
3. **Artifact Digests:** Measures byte length and SHA-256 digest of every listed artifact (`cyravell-engine`, `cyravell-test-harness`, `cyravell-*.vsix`, `cyravell-rules-bundle.tar.gz`, `cyravell-sbom.spdx.json`).
4. **Path Traversal Defense:** Confirms no artifact name contains `..`, leading `/`, backslashes, or null bytes.
5. **Completeness & Foreign Files:** Identifies any missing required components or unlisted extraneous binaries.

### What to Do When Verification Fails
If verification returns non-zero (`TamperedArtifact`, `InvalidSignature`, `MissingArtifact`, `SecurityCheckFailed`):
1. **STOP IMMEDIATELY:** Do not execute the engine binary or install the `.vsix`.
2. Inspect the failure details:
   - If `TamperedArtifact`: The binary or archive does not match the publisher's signed digest.
   - If `InvalidSignature`: The manifest has been modified or signed by an unrecognized key.
   - If `MissingArtifact`: One or more deliverables were dropped during transport.
3. Re-download from official distribution channels or build from verified source tags.

---

## 9. Threat Analysis & Residual Risks

### Conceptual Distinctions
- **Source Review:** Confirms that source code behavior matches developer intentions.
- **Artifact Integrity:** Confirms that a binary has not been modified after compilation.
- **Publisher Authenticity:** Confirms that the release manifest was signed by an authorized key holder.
- **Build Provenance:** Links an artifact to the build environment and source commit that produced it.

### Residual Threats & Attack Vectors
| Threat Scenario | Impact | Mitigation in Place |
| :--- | :--- | :--- |
| **Compromised Build Environment (Runner)** | Malicious code injected into binary prior to signing | Reproducible build configuration allows independent verification; pinned action SHAs prevent runner script modification. |
| **Compromised Release Signing Key** | Attacker publishes signed malicious update | Keys stored outside repository; cryptographic expiration timestamps; separate advisory key prevents intelligence hijacking. |
| **Upstream Registry Dependency Takeover** | Malicious code in third-party crate or npm package | Locked dependency files; zero wildcards; offline-first runtime model; pre-installation gate blocks malicious packages. |
| **Compromised Local Root User** | Attacker with root replaces `/usr/local/bin/cyravell-engine` | Operating-system privilege boundaries; kernel protections; Cyravell does not claim protection against local root attackers. |

> [!IMPORTANT]
> A passing CI workflow and valid signature do **NOT** guarantee software is completely free of vulnerabilities. They verify that the artifact faithfully represents reviewed source code from authorized maintainers.
