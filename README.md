# Cyravell

**Deterministic Local-First Security Monitoring System for AI Coding Agents**

Cyravell is an open-source, local-first security platform engineered to protect developer workstations when running autonomous AI coding agents (Claude Engineer, Devin, AutoGPT, Copilot Workspace, OpenHands, etc.).

Cyravell intercepts and assesses terminal commands before execution, inspects package manager operations, detects dependency drift, maintains an immutable cryptographic audit ledger, and enforces secure release provenance.

---

## Key Capabilities

- **Authoritative Rust Security Engine:** Sub-millisecond deterministic AST parser, threat classification, secret redaction, and policy evaluation.
- **Fail-Closed Terminal Execution Gate:** Controlled PTY terminal session (`cyravell-engine shell`) intercepting commands prior to dispatch. If the engine daemon is offline, execution safely fails closed.
- **Package Security Enforcement:** Pre-installation inspection for npm, pip, and cargo package commands; hard-blocks malicious packages and requires human approval for known vulnerabilities.
- **Dependency Drift & Baseline Reconciliation:** Local project baselining and continuous monitoring for unexpected post-installation dependency drift.
- **Cryptographically Authenticated Advisory Updates:** Offline-first, signed Ed25519 advisory bundles with two-phase tokenized anti-rollback protection.
- **Privilege Boundaries & Local IPC Access Control:** `SO_PEERCRED` kernel-level client authentication, role-based operation tiers (`ReadOnly`, `Standard`, `Privileged`, `Rollback`), and directory hardening.
- **Release Integrity & Independent Verification (Phase 3.0 & Phase 3.1):**
  - Canonical signed release manifest (`release_manifest.json`) cataloging deliverables with exact SHA-256 digests.
  - Dedicated `ReleaseKeyStore` with cryptographic domain separation and official vs dev key tier enforcement.
  - Independent standalone pre-installation verifier (`scripts/standalone_verify.py`) requiring **zero downloaded binary execution**.
  - Filesystem defenses rejecting symlinks, non-regular files, directory traversal, and unlisted executables.
  - Machine-readable SPDX 2.3 JSON Software Bill of Materials (SBOM) for Rust and npm ecosystems.
  - Reproducible builds with path remapping and normalized packaging timestamps.
  - Pinned CI/CD actions to immutable 40-character commit SHAs with secret-isolated signing steps.

---

## Architecture Overview

```text
┌────────────────────────────────────────────────────────┐
│               Developer Workstation / IDE              │
│                                                        │
│   ┌────────────────────┐      ┌────────────────────┐   │
│   │ AI Coding Agent    │      │ VS Code Extension  │   │
│   │ (Autonomous CLI)   │      │ (Status & Approval)│   │
│   └─────────┬──────────┘      └─────────┬──────────┘   │
│             │                           │              │
│             ▼                           │              │
│   ┌────────────────────┐                │              │
│   │ Controlled Shell   │                │              │
│   │ (Interception Gate)│                │              │
│   └─────────┬──────────┘                │              │
│             │ Unix Domain Socket        │              │
│             │ (SO_PEERCRED Auth)        │              │
│             ▼                           ▼              │
│   ┌────────────────────────────────────────────────┐   │
│   │         Cyravell Engine Daemon (Rust)          │   │
│   │                                                │   │
│   │  • Command AST Analyzer   • Package Assessor   │   │
│   │  • Policy Engine          • Drift Detector     │   │
│   │  • Approval State Machine • Advisory Database  │   │
│   │  • Cryptographic Audit    • Release Verifier   │   │
│   └────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. One-Command Installation (Recommended)
```bash
# Builds components, installs engine, rules, VS Code extension, and starts daemon:
./install.sh

# Or install system-wide with sudo:
sudo ./install.sh
```

### 2. Build and Run Tests
```bash
# Compile Rust engine and run complete test pipeline
cargo test --workspace

# Run complete end-to-end integration and adversarial suite
./scripts/test.sh
```

### 2. Software Supply-Chain & Dependency Audit
```bash
# Audits lockfiles, unpinned inputs, crates.io registries, and npm dependencies
./scripts/audit_dependencies.sh
```

### 3. Generate SPDX 2.3 SBOM
```bash
# Generates machine-readable SPDX 2.3 SBOM for release deliverables
./scripts/generate_sbom.sh cyravell-sbom.spdx.json 0.1.0
```

### 4. Package Deterministic Release Deliverables
```bash
# Builds reproducible binaries, packages .vsix, generates SBOM, and signs manifest
./scripts/package_release.sh 0.1.0
```

### 5. Verify Release Package Before Installation
```bash
# Cryptographically verifies release manifest, Ed25519 signature, and bit-for-bit file digests
# (Zero downloaded binary execution; standard Python 3 RFC 8032 fallback)
./scripts/verify_release.sh dist/release-v0.1.0 0.1.0
```

### 6. Secure Installation, Status, and Recovery
```bash
# Securely install or update Cyravell in user mode (~/.local, no sudo required):
./scripts/install.sh install --release-dir dist/release-v0.1.0 --user

# Query installation status:
./scripts/install.sh status

# Revert to last known-good installation if needed:
./scripts/install.sh rollback --reason "Incident 402: regression recovery"

# Safe uninstall (preserves user audit trail & security state):
./scripts/install.sh uninstall
```

---

## Documentation

- [Release Security & Supply-Chain Guide](docs/RELEASE_SECURITY.md)
- [System Architecture](docs/ARCHITECTURE.md)
- [Threat Model & Boundary Analysis](docs/THREAT_MODEL.md)
- [Setup & Troubleshooting](docs/SETUP_AND_TROUBLESHOOTING.md)
- [IPC Protocol Specification](docs/IPC_PROTOCOL.md)
- [Event Schema Specification](docs/EVENT_SCHEMA.md)

---

## License

Copyright 2026 Cyravell Contributors. Licensed under the Apache License, Version 2.0.

