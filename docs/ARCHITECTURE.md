# Cyravell — Architecture Specification

**Version:** 1.0.0 (Phase 1)  
**Status:** Approved  
**Author:** Cyravell Security Architecture Team  

---

## 1. System Overview

Cyravell is an editor-independent, local-first security monitoring system designed to observe, evaluate, and prevent unsafe actions by AI coding agents.

Rather than trusting an AI agent to self-moderate or running security logic inside the fragile context of an IDE plugin thread, Cyravell enforces a strict architectural boundary:
1. **Core Security Engine (`cyravell-engine`):** A standalone, unprivileged Rust daemon running natively on the host workstation. It is the sole authority for policy evaluation, cryptographic audit logging, and integrity verification.
2. **Editor Extension (`vscode-extension`):** A lightweight client running inside Visual Studio Code (and in future editors) that communicates with the engine over local IPC, presents status and alerts, and enables developer inspection.
3. **Synthetic Event Test Harness (`test-harness`):** A reproducible integration harness for simulating security events, verifying end-to-end event flows, and executing audit tampering tests safely without endangering developer environments.

---

## 2. Component Architecture

```
+---------------------------------------------------------------------------------------+
|                                    CYRAVELL ARCHITECTURE                               |
|                                                                                       |
|  +---------------------------+                         +----------------------------+ |
|  |     VS Code Extension     |                         |    Test Harness / CLI      | |
|  |  - Connection Manager     |                         |  - Synthetic Scenarios     | |
|  |  - Tree View Provider     |                         |  - Tamper Verification     | |
|  |  - Status Bar Indicator   |                         |  - Benchmark & Validation  | |
|  |  - Event Details Webview  |                         +--------------+-------------+ |
|  +-------------+-------------+                                        |               |
|                |                                                      |               |
|                +--------------------------+---------------------------+               |
|                                           |                                           |
|                     Unix Domain Socket (IPC Line-Delimited JSON)                      |
|                                           |                                           |
|  =========================================v=========================================  |
|                         CYRAVELL ENGINE (Rust Daemon)                                 |
|                                                                                       |
|   +-------------------------------------------------------------------------------+   |
|   | Local IPC Server (UnixListener, 0600 socket permissions, 1MB frame limit)     |   |
|   +---------------------------------------+---------------------------------------+   |
|                                           |                                           |
|                                    Parsed Requests                                    |
|                                           v                                           |
|   +-------------------------------------------------------------------------------+   |
|   | Request Dispatcher & Validation Subsystem                                     |   |
|   | - Schema Version Validation                                                   |   |
|   | - Handshake / Capabilities Negotiation                                        |   |
|   +-------------------+-------------------+-------------------+-------------------+   |
|                       |                   |                   |                       |
|                       v                   v                   v                       |
|   +----------------------+  +----------------------+  +---------------------------+   |
|   | Deterministic Policy |  | Cryptographic Audit  |  | Integrity Verification    |   |
|   | Engine               |  | Subsystem            |  | Engine                    |   |
|   | - Baseline Rules     |  | - SHA-256 Hash Chain |  | - Release Manifest Check  |   |
|   | - Risk Assessment    |  | - Append-Only Storage|  | - Canonical File Hashes   |   |
|   | - Rule Engine Trait  |  | - Tamper Detection   |  | - Trust Anchor Separation |   |
|   +----------------------+  +----------------------+  +---------------------------+   |
+---------------------------------------------------------------------------------------+
```

---

## 3. Subsystem Breakdown

### 3.1 `cyravell-engine` (Rust Core)
- **`analysis` Module (Phase 2.1):** Deterministic, explainable command security analysis pipeline:
  - **`lexer`:** Syntax-aware tokenizer distinguishing shell operators (`;`, `|`, `&&`, `||`, `>`, `>>`, `<`, `2>`, `&>`) from quoted strings (`'...'`, `"..."`), escaped characters (`\`), command substitutions (`$(...)`, \`...\`), and environment expansions.
  - **`ast`:** Structures commands into atomic units (`program`, `arguments`, `redirections`, `env_assignments`, `command_substitutions`), pipelines (`|`), and conditional chains (`&&`, `||`, `;`).
  - **`detector`:** Evaluates risk across 7 categories:
    1. *Destructive filesystem operations:* recursive deletion of root/home/system paths, disk format (`mkfs`, `wipefs`), raw block write (`dd`), fork bombs.
    2. *Privilege and security changes:* interactive root shells (`sudo su`, `su -`), dangerous permissions (`chmod 777`, SUID), security control disabling (`ufw disable`, `setenforce 0`, `iptables -F`).
    3. *Credential and secret access:* private keys (`id_rsa`, `id_ed25519`), cloud credentials (`.aws`), shadow passwords, environment secret dumping.
    4. *Remote code execution:* download-and-execute pipelines (`curl ... | bash`), dynamic evaluation (`eval "$(curl ...)"`).
    5. *Persistence and system modification:* cron jobs (`crontab`), shell startup files (`.bashrc`, `.profile`), systemd units.
    6. *Network and data transfer:* reverse shells (`nc -e`, `socat exec`), credential exfiltration via remote POST.
    7. *Obfuscation and indirect execution:* base64/hex decode to interpreter (`base64 -d | sh`), nested interpreters, complex chains.
- **`ipc` Module:** Handles Unix domain socket lifecycle, listener binding, client connection pools, frame delimitation, buffer limits, timeouts, and error serialization.
- **`model` Module:** Strongly typed definitions for events, requests, responses, risk assessments, severity levels, execution statuses, and audit records using `serde`.
- **`policy` Module:** Deterministic evaluation pipeline integrating `CommandAnalyzer`. Calculates severity, confidence, evidence markers, potential impact, and remediation recommendations.
- **`audit` Module:** Cryptographic hash-chained append-only log. Ensures each record references the SHA-256 hash of the preceding record, providing immediate mathematical detection of record alteration, deletion, or reordering.
- **`integrity` Module:** Validates engine and asset file integrity against a trusted release manifest, isolating trust anchors from the files being measured.

### 3.2 `vscode-extension` (VS Code Integration)
- **`connection` Module:** Manages the lifecycle of the Unix socket connection, heartbeat pings, reconnect backoff, and state transitions (`Connected`, `Disconnected`, `Degraded`).
- **`views` Module:** Exposes an Activity Bar container with a dedicated TreeDataProvider showing Engine Health, Integrity Status, and Recent Events.
- **`commands` Module:** Registered editor commands:
  - `cyravell.refreshStatus`
  - `cyravell.inspectEvent`
  - `cyravell.verifyAuditLog`
  - `cyravell.disconnect`
  - `cyravell.connect`
- **Degraded-State Safety:** Explicitly forbids presenting a "green / protected" status when disconnected, unverified, or degraded.

### 3.3 `test-harness` (Verification & Scenarios)
- Generates reproducible synthetic events (e.g., simulated `rm -rf /` commands, fake credential access).
- Verifies that events flow from emission, through IPC validation, policy assessment, and audit persistence, to client query.
- Executes controlled audit log tampering tests on isolated test copies to verify tamper detection.

---

## 4. End-to-End Event Lifecycle

```
[Agent / Harness Activity]
          |
          | 1. Submit Event via IPC (JsonEvent)
          v
[IPC Server (`cyravell.sock`)]
          |
          | 2. Framed Read & Byte Limit Check (<1MB)
          v
[Request Deserializer]
          |
          | 3. Schema Check (Schema Version == 1)
          v
[Deterministic Policy Engine]
          |
          | 4. Match against Rules (e.g., DestructiveCommandRule)
          |    -> RiskAssessment (Critical, High Confidence, Evidence)
          v
[Audit Subsystem]
          |
          | 5. Compute H_n = SHA256(H_{n-1} + Timestamp + EventData + Assessment)
          |    Append to audit.log
          v
[IPC Response Formatter]
          |
          | 6. Return Evaluation & Audit Sequence ID
          v
[VS Code Client / Subscriber]
          |
          | 7. Tree View & Event Inspector Update
          v
[Developer UI Notification]
```

---

## 5. Security & Privacy Guarantees

1. **No Outbound Network Traffic:** Cyravell operates 100% offline. Zero telemetry, zero analytics, zero external API calls.
2. **Local User Isolation:** Sockets and log directories are owned by the developer user and enforced with `0700` directory and `0600` file permissions.
3. **No Execution of Payload Commands:** The engine never runs commands received in events. Commands are treated strictly as read-only data strings for analysis.
4. **Deterministic Gatekeeping:** Security decisions are reproducible, rule-based, and auditable. AI outputs cannot override baseline rules.

---

## 6. Command Security Analysis Pipeline (Phase 2.1)

### 6.1 Analysis Architecture & Data Flow
The command analysis pipeline operates purely on input strings without invoking shell interpreters, subshells, or system calls:
1. **Input Validation:** Enforces payload length limit (64 KiB), checks UTF-8 validity, rejects null bytes (`\0`), and handles empty/whitespace inputs gracefully.
2. **Syntax-Aware Lexing:** The lexer distinguishes operators (`;`, `&&`, `||`, `|`, redirections) from inside quoted strings (`"..."`, `'...'`) and handles backslash escapes. Unclosed quotes or command substitutions downgrade `AnalysisCompleteness` to `Partial` or `Inconclusive`.
3. **AST Construction:** Builds atomic commands with programs, unquoted arguments, redirections, environment assignments, and command substitutions.
4. **Multi-Category Detection:** Matches against the 7 defined risk categories:
   - Destructive filesystem actions
   - Privilege & security modifications
   - Credential access
   - Remote code execution pipelines
   - Persistence changes
   - Network exfiltration
   - Obfuscated execution
5. **Deterministic Classification:** The highest matching severity is selected (`Critical > High > Medium > Low > Info`), all matching rule IDs are preserved, evidence items are aggregated, and potential impact is detailed.
6. **Secret Redaction:** Commands are scrubbed of sensitive inline tokens (`password=`, `token=`, `bearer `, `api_key=`) before being recorded to audit logs.

### 6.2 Adding a New Deterministic Rule
1. Add the declarative rule definition to `rules/baseline_rules.json` with a unique ID (`RULE-...`), severity, description, and recommended action.
2. Implement or update the detector logic in `engine/src/analysis/detector.rs` matching the AST program, arguments, pipeline, or redirection pattern.
3. Add a corresponding unit test in `engine/src/analysis/mod.rs`.
4. Recompute the SHA-256 digest of `rules/baseline_rules.json` and update `rules/cyravell_manifest.json`.

### 6.3 Limitations & Boundary Statement
- **Analysis Only:** Phase 2.1 analyzes and classifies command risks. It **does not** intercept commands before execution or claim OS-level blocking.
- **Static Approximation:** Shell analysis is an approximation. Highly obfuscated dynamic evaluation (e.g. multi-stage eval of remote network streams) cannot be fully resolved statically without dynamic tracing (reserved for future phases).
- **Not Proof of Malice:** A critical rule match indicates potential impact and risk, not malicious intent; legitimate system administration commands may trigger alerts.

---

## 7. Controlled Terminal Interception Foundation (Phase 2.2)

### 7.1 Architecture of the Pre-Execution Gate
Phase 2.2 introduces the **Execution Gate (`engine/src/gate/`)**, a controlled interception boundary on Linux that captures commands *before* execution dispatch and enforces deterministic policy decisions.

```
Captured Command String
          │
          ▼
   [ExecutionGate]
          │
          ├───► 1. Input Validation (Empty check, null byte check, >64KB limit)
          │
          ├───► 2. Static Analysis & Policy Evaluation (via IPC or In-Process Engine)
          │
          ├───► 3. Decision Gating:
          │        ├─ GateDecision::Allow ────────► Backend.execute() ──► ExecutionOutcome::Dispatched
          │        ├─ GateDecision::RequireApproval ─► [WITHHELD] ─────► ExecutionOutcome::PendingApproval
          │        ├─ GateDecision::Block ──────────► [BLOCKED] ──────► ExecutionOutcome::BlockedByPolicy
          │        └─ GateDecision::AnalysisFailed ──► [FAIL-CLOSED] ──► ExecutionOutcome::FailedClosed
          │
          └───► 4. Audit Recording (Redacted Command + Enforceable Outcome + SHA-256 Hash Chain)
```

### 7.2 Component Separation & Anti-Recursion
- **`ExecutionBackend` Trait:** Decouples the security gate from the execution mechanism.
  - `OsExecutionBackend`: Spawns authorized commands via `/bin/bash -c <cmd>`, setting `CYRAVELL_INTERCEPT_DISABLED=1` to prevent accidental recursive interception.
  - `MockExecutionBackend`: Strictly records invocations to mathematically assert that blocked and pending commands never reach the execution backend.
- **`ControlledShell`:** Interactive and non-interactive (`-c`) terminal wrapper. Provides the `cyravell-engine shell` session.
- **Fail-Closed Guarantees:** If the daemon is unreachable, the IPC connection is reset, or analysis fails, `fail_closed: true` ensures that commands are blocked with outcome `FAILED_CLOSED`.
- **VS Code Extension Integration:** The extension surfaces an opt-in `Cyravell Protected Terminal` command. It clearly distinguishes between protected controlled sessions and ordinary unprotected sessions.

### 7.3 Interception Scope & Limitations
- **Controlled Shell Scope:** Protection is guaranteed only within sessions launched via `cyravell-engine shell` or the VS Code `Cyravell Protected Terminal` profile.
- **Ordinary Terminals Unprotected:** Standard VS Code integrated terminals running directly in bash/zsh bypass the pre-execution gate. This is explicitly reported in the extension status tree view.
- **Child Subprocesses of Permitted Commands:** If a permitted command (e.g. `python script.py`) spawns subprocesses internally via OS syscalls, those internal subprocesses do not pass through the shell wrapper gate.
- **Approval Workflow:** Interactive user approval and single-use cryptographic authorization are fully realized and hardened in Phase 2.4.

---

## 8. Execution-Gate Hardening and Adversarial Validation (Phase 2.4)

### 8.1 Hardened Approval State Machine
Phase 2.4 introduces an in-memory, race-safe `ApprovalManager` (`engine/src/gate/approval.rs`) that manages pending approvals, enforces strict state transitions, and issues cryptographically unpredictable authorization tokens:
- **Approval Status Lifecycle:**
  `Pending -> Approved | Denied | Cancelled | Expired -> Consumed`
- **State Invariants:**
  - Once decided (`Approved`, `Denied`, `Cancelled`), a request cannot be re-decided or flipped. Duplicate decision requests return `ApprovalError::InvalidStateTransition`.
  - A request that exceeds its TTL transitions to `Expired` and can no longer be decided or dispatched.
  - Hard-blocked commands (`Severity::Critical`, `RULE-TERM-001`) cannot be approved. Attempting to approve a hard-block returns `ApprovalError::HardBlockPolicyViolation`.

### 8.2 Single-Use Cryptographic Authorization Tokens
- When an approval request is approved, the engine issues a unique, high-entropy cryptographic token (`cyr-auth-<uuid>-<uuid>`).
- **Token Invariants:**
  1. **Strictly Single-Use:** The token is consumed atomically *before* the backend `execute()` call. Replaying the token returns `ApprovalError::AlreadyConsumed`.
  2. **Session Binding:** Tokens are bound to the specific `session_id` that initiated the request. Presenting a token from another session fails with `ApprovalError::SessionMismatch`.
  3. **Exact Command Binding:** Tokens are bound character-for-character to the approved command string. Modifying, prepending, or appending commands (TOCTOU attacks) fails with `ApprovalError::CommandMismatch`.
  4. **Bounded Window:** Tokens expire alongside the underlying approval request. Presenting an expired token fails with `ApprovalError::Expired`.
  5. **Ephemeral Storage:** Tokens are stored exclusively in engine daemon memory; restarting the engine invalidates all prior tokens.

### 8.3 Hard-Block Policy Re-evaluation Guard
Even if an attacker bypasses user interaction, steals a token, or manipulates IPC state:
At the moment of `gate.dispatch_authorized`, the engine independently re-analyzes the command string against current security policy. If policy classifies the command as `BLOCK_AND_ALERT` (hard block), dispatch is immediately rejected (`ApprovalError::HardBlockPolicyViolation`), the incident is recorded in the cryptographic audit log (`GATE_HARD_BLOCK_ENFORCED_AFTER_APPROVAL`), and the backend is never called.

### 8.4 Authoritative Verification Framework
- `MockExecutionBackend` provides strict assertion helpers:
  - `assert_zero_invocations()`: Mathematically verifies backend was never called.
  - `assert_invoked_exactly(n)`: Verifies exact execution count.
  - `assert_command_executed(cmd)` and `assert_command_never_executed(cmd)`.
- Adversarial Security Test Suite (`engine/src/gate/adversarial.rs`):
  - **Category A (Approval Bypass):** Direct execution bypass, missing token, fabricated token, expired token, session tampering, command tampering (TOCTOU), hard-block override.
  - **Category B (Replay & Deduplication):** Token reuse replay, duplicate decision, serial dispatch deduplication.
  - **Category C (Race Conditions & Concurrency):** Approve vs Deny race, Approve vs Cancel race, concurrent dispatches using `std::sync::Barrier` (8 threads racing for 1 token: exactly 1 dispatches, 7 fail with `AlreadyConsumed`, backend invoked exactly once).
  - **Category D (Failure & Recovery):** Engine restart token invalidation, backend spawn failure handling (token consumed to prevent retries, audit recorded), fail-closed offline enforcement.
  - **Category E (Input & Boundary Validation):** Null bytes in commands/IDs rejected, oversized commands (>64KB) rejected, empty commands rejected.

### 8.5 Scope & Non-Claims
- **Controlled Terminal Boundary:** Execution gate guarantees apply strictly to commands submitted through the Cyravell controlled terminal (`cyravell-engine shell`, `exec`, or VS Code Protected Terminal).
- **In-Memory Token Lifetime:** Authorization tokens do not survive engine restarts.
- **Root-Level Compromise:** If an attacker obtains root access on the host, they can kill the engine daemon or modify memory; Cyravell operates under the standard Unix unprivileged developer security model.

---

## 9. Pre-Installation Package Security Enforcement (Phase 2.5)

### 9.1 Architectural Overview
Phase 2.5 extends the authoritative Rust execution gate with pre-installation package security analysis (`engine/src/package/`). Before any package-manager command is dispatched, the gate statically parses the package invocation, inspects project manifests and lockfiles, queries a deterministic local advisory database, and enforces security policies without executing untrusted package scripts or build code.

```
Package Manager Command (e.g. npm install flatmap-stream@0.1.1)
                            │
                            ▼
              1. AST Package Command Detector
                 - Extracts ecosystem (npm, pnpm, yarn, pip, cargo)
                 - Extracts operation (InstallAll, Add, Update, RunPackage)
                 - Extracts package specifications and version constraints
                 - Unwraps command wrappers (sudo, env, doas)
                            │
                            ▼
              2. Manifest & Lockfile Inspector
                 - Parses package.json, package-lock.json, Cargo.toml, Cargo.lock, requirements.txt
                 - Computes SHA-256 fingerprint over manifest and lockfile
                 - Validates lockfile integrity format (e.g. sha512-, sha256-)
                 - Detects manifest-lockfile mismatches (unpinned or missing dependencies)
                            │
                            ▼
              3. Local Advisory Database Evaluation
                 - Offline, embedded fallback (`rules/package_advisories.json`)
                 - SemVer & compound version range comparator (`>= 4.0.0, < 4.17.21`)
                 - Queries direct requested packages and lockfile resolved dependencies
                            │
                            ▼
              4. Authoritative Gate Policy Decision
                 ├── MaliciousPackageFound ────► [HARD BLOCK] ────► Zero Backend Invocations (Non-overridable)
                 ├── VulnerabilitiesFound ─────► [REQUIRE APPROVAL]
                 ├── IntegrityMismatch ────────► [REQUIRE APPROVAL]
                 ├── ManifestMismatch ─────────► [REQUIRE APPROVAL]
                 ├── AssessmentFailed ─────────► [REQUIRE APPROVAL] (Fail-closed)
                 └── CleanNoMatches ───────────► Proceed to Standard Command Policy (Does not imply "proven safe")
                            │
                            ▼
              5. TOCTOU Protection at Dispatch
                 - Recomputes manifest fingerprint before backend execute()
                 - Fails closed if manifest or lockfile modified between approval and dispatch
```

### 9.2 Supported Package Managers and Manifest Formats
- **npm / npx:** `package.json`, `package-lock.json` (v1, v2, v3).
- **pnpm:** `pnpm-lock.yaml`.
- **Yarn:** `yarn.lock`.
- **pip / pip3 / python -m pip:** `requirements.txt` (including `-r` flags and PEP 440 constraints).
- **Cargo:** `Cargo.toml`, `Cargo.lock` (including workspace root and member resolution).

### 9.3 Local Advisory Database and Offline Guarantees
- **Zero Network Dependency:** Package assessment runs completely offline using a local advisory database (`rules/package_advisories.json`) with an embedded compile-time fallback.
- **Coverage Transparency:** Evaluates confirmed malicious packages (`flatmap-stream`, `cross-env.js`, `node-ipc`, `electorn`, `reqeusts`, etc.) and high-severity CVE vulnerabilities.
- **No False Safety Claims:** A status of `CleanNoMatches` honestly conveys "no known match in local checked data", never presenting packages as "proven safe".

### 9.4 TOCTOU Protection
When an approval request is generated for a package operation requiring review, Cyravell computes and binds a SHA-256 `manifest_fingerprint` across the project manifest and lockfile. At the moment of `dispatch_authorized`, the gate re-evaluates the fingerprint: if project files were modified between approval and dispatch, the request is rejected immediately (`ApprovalError::InvalidStateTransition`).

---

## 10. Post-Installation Package Integrity & Dependency-Drift Monitoring (Phase 2.6)

### 10.1 System Overview
Phase 2.6 extends Cyravell from pre-installation gate checks to continuous post-installation verification, dependency-state baselining, and local drift detection (`engine/src/package/`). It establishes an authoritative local baseline of project dependencies, verifies project integrity immediately after controlled package operations, and continuously monitors the workspace for stealth modifications or background tampering.

```
                    Controlled Package Operation Dispatched (Phase 2.5)
                                          │
                                          ▼
                                   Backend Execution
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
             Exit Code != 0                       Exit Code == 0
                   │                                       │
                   ▼                                       ▼
    PostOperationVerification:             PostOperationVerification:
    Status: EXECUTION_FAILED               - Computes Post-Op Baseline
    - Preserves Pre-Op Baseline            - Compares against Pre-Op State
    - Does NOT record success              - Checks Manifest/Lockfile Consistency
    - Audit Trail: Recorded                - Runs Local Advisory Inspection
                                                           │
                                                           ▼
                                            Verification Outcome:
                                            ├── Clean Changes ──► Status: VERIFIED
                                            ├── Unmatched ─────► Status: UNEXPECTED_CHANGES
                                            ├── Malicious ─────► Status: ASSESSMENT_FAILED
                                            └── Corrupted ─────► Status: INCONCLUSIVE
                                                           │
                                                           ▼
                                            Baseline Trust State Transition
                                            (POST_OPERATION_OBSERVED or REVIEW_REQUIRED)
```

### 10.2 Deterministic Baseline Model & Invariant Trust Boundaries
A `DependencyBaseline` captures the complete dependency topology of a workspace:
- **Ecosystem & Package Manager:** Detected ecosystem (`npm`, `pnpm`, `yarn`, `pip`, `cargo`).
- **Canonical Dependency Sets:** Direct, resolved, and transitive dependencies stored in canonical `BTreeMap` key order.
- **Integrity Metadata:** Cryptographic hashes of lockfiles and package integrity checksums.
- **Deterministic Baseline Fingerprint:** SHA-256 digest computed across canonical dependency sets, manifest fingerprints, and lockfile hashes. Volatile fields (such as `created_at` timestamps) are strictly excluded so identical project configurations yield identical digests across time and machines.

#### Baseline Trust States
The baseline lifecycle is governed by a four-tier trust model (`BaselineTrust`):
1. **`VERIFIED_APPROVED`:** Explicitly reviewed and approved by the developer or created through an authorized, clean, verified package operation.
2. **`POST_OPERATION_OBSERVED`:** Captured automatically after an authorized controlled package operation with clean verification.
3. **`REVIEW_REQUIRED`:** Captured after an operation or background change with unexpected modifications, unverified dependencies, or advisory warnings.
4. **`UNVERIFIED_INITIAL`:** Initial automatic baseline snapshot before developer review.

#### Trust Invariant Boundary
The `BaselineStore` enforces a strict trust boundary:
- An unverified snapshot (`UNVERIFIED_INITIAL` or `REVIEW_REQUIRED`) **cannot** overwrite or downgrade an existing `VERIFIED_APPROVED` baseline without explicit developer approval.
- Attempts to overwrite a verified baseline without approval fail deterministically (`attempt_replace_baseline(..., false)` returns `false`), preserving audit integrity.

### 10.3 Post-Operation Verification
Package manager exit codes are inherently untrusted indicators of project safety: an installer that successfully pulls a malicious dependency exits with code `0`. Cyravell's `PostOperationVerifier` performs deterministic post-execution verification:
1. **Execution Failure Handling:** If `exit_code != 0`, immediately records `EXECUTION_FAILED`, retains pre-operation baseline, and records audit trail.
2. **Post-Op Snapshot Comparison:** Captures post-operation dependency state and diffs against the pre-operation baseline.
3. **Advisory Database Scrutiny:** Re-evaluates all newly introduced direct and transitive dependencies against the offline advisory database.
4. **Verification Statuses:**
   - `VERIFIED`: Operation completed cleanly, expected dependencies installed, zero advisories.
   - `UNEXPECTED_CHANGES`: Dependencies modified beyond the scope of the issued command.
   - `ASSESSMENT_FAILED`: Malicious packages or critical vulnerabilities introduced.
   - `INCONCLUSIVE`: Manifest or lockfile unparseable or corrupted.

### 10.4 Deterministic Drift Detection
The `DriftDetector` evaluates current workspace state against the active baseline, classifying changes into 10 deterministic drift types:
1. `UnexpectedAddition`: Dependency added without a corresponding recorded operation.
2. `VersionDrift`: Installed or resolved dependency version differs from baseline.
3. `UnexpectedRemoval`: Previously baseline-recorded dependency was deleted.
4. `TransitiveDrift`: Transitive dependency modified while direct dependencies appear unchanged.
5. `LockfileOnlyDrift`: Lockfile modified without manifest modification.
6. `ManifestOnlyDrift`: Manifest modified without corresponding lockfile update.
7. `IntegrityDrift`: Lockfile checksums or hash integrity attributes changed.
8. `MaliciousPackageDetected`: Known malicious package found in active project state.
9. `VulnerabilityDetected`: Package matching known security vulnerability introduced.
10. `MetadataCorrupted`: Malformed, unparseable, or truncated manifest/lockfile detected.

### 10.5 Active Gate Hard-Block Enforcement
Active dependency drift directly impacts subsequent command dispatch at the authoritative execution gate:
- **Active Malicious Drift:** If a workspace contains an unaddressed `MaliciousPackageDetected` finding, all subsequent command execution requests in that workspace are **hard-blocked** (`GateDecision::Deny`, non-overridable, exit code 126).
- **Active Vulnerability Drift:** If a workspace contains high-severity vulnerability drift, subsequent command execution requests require developer approval.
- **Fail-Closed:** The gate checks active workspace drift synchronously during `evaluate_with_session`.

### 10.6 Bounded Local Workspace Monitoring
The `WorkspaceMonitor` provides continuous, resource-bounded observation of project manifest and lockfile changes:
- **Bounded Target List:** Monitors only authoritative project definition files (`package.json`, `package-lock.json`, `Cargo.toml`, `Cargo.lock`, `requirements.txt`, etc.).
- **Deduplication:** Debounces rapid successive disk events using a thread-safe timestamp and hash cache.
- **Atomic Write Reconciliation:** Gracefully reconciles atomic replacement patterns (write to temp file, rename over target) common in package managers and editors.
- **Clean Shutdown:** Monitors run as bounded background workers that terminate cleanly when the engine shuts down.

### 10.7 Advisory Provenance & Synthetic Isolation
- All advisory records (`AdvisoryRecord`) include a mandatory `provenance` string indicating source origin.
- Advisories support an explicit `is_synthetic: bool` flag to cleanly partition synthetic test fixtures from production vulnerability data.
- Manifest signatures (`rules/cyravell_manifest.json`) cryptographically bind the advisory database to the engine binary.

### 10.8 Attribution Transparency & Credential Redaction
- **Honest Attribution:** Filesystem monitoring detects *that* files changed, but cannot authoritatively prove *which* process modified them without a synchronized execution context. Cyravell explicitly labels background reconciliation events as `"Observed via local filesystem reconciliation (unattributed background change)"`.
- **Credential Redaction:** The engine analyzer and audit logger scrub secret tokens, password flags (`--password=`, `token=`), and URL userinfo credentials (`https://user:secret@registry.npmjs.org/`) before persisting audit records or presenting notifications.

---

## 11. Secure Advisory Intelligence Updates & Rollback Protection (Phase 2.7)

Cyravell Phase 2.7 implements cryptographic authentication, schema validation, atomic activation, and rollback protection for package vulnerability and malicious package intelligence while strictly preserving local-first, offline operating principles.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Advisory Update Architecture                          │
└─────────────────────────────────────────────────────────────────────────────┘
  [ Signed Bundle ] ───► [ TrustedKeyStore ] (Ed25519 Verify)
         │                         │
         ▼                         ▼
  [ Payload Digest ] ──► [ Anti-Rollback Check ] (Candidate > Active Version)
         │                         │
         ▼                         ▼
  [ Schema Validation ] ─► [ Safe Transaction ] (Tempfile Sync + Rename)
         │                         │
         ▼                         ▼
  [ In-Memory Swap ] ────► [ Atomic Assessor RwLock ] (Zero Reader Downtime)
         │                         │
         ▼                         ▼
  [ Baseline Re-scan ] ──► [ Active Drift / Gate Hard-Block ]
         │                         │
         ▼                         ▼
  [ Audit Record ] ─────► [ SHA-256 Tamper-Evident Chain ]
```

### 11.1 Versioned Advisory Bundle Format
Advisory intelligence is distributed in standardized, cryptographically bound JSON bundles (`AdvisoryBundle`):
- `bundle_format_version`: Format standard identifier (currently `"1.0"`).
- `database_version`: Monotonically incrementing calendar version (`YYYY.MM.DD` or SemVer).
- `created_at`: RFC 3339 UTC timestamp.
- `publisher`: Publisher entity name.
- `key_id`: Cryptographic identifier of the signing key.
- `min_cyravell_version`: Minimum supported engine version.
- `supported_ecosystems`: Array of package ecosystems covered.
- `payload_digest`: SHA-256 digest over the canonical serialization of all advisory records sorted deterministically by `(ecosystem, package_name, id)`.
- `signature`: Hex-encoded Ed25519 signature over domain-separated canonical signing bytes (`CYRAVELL-ADVISORY-BUNDLE-V1\n...`).
- `advisories`: Array of `AdvisoryRecord` objects.

### 11.2 Ed25519 Cryptographic Trust Model
- **Public-Key Trust Store:** Managed via `rules/trusted_keys.json` and `TrustedKeyStore`. Private keys are never embedded in the repository or binary.
- **Strict Signature Verification:** Bundles must be signed with a known, active, non-expired public key. Ordinary SHA-256 digests are never accepted as proof of publisher identity.
- **Signature Domain Separation:** Canonical signing string prepends `CYRAVELL-ADVISORY-BUNDLE-V1\n` with line-delimited key-value metadata to prevent cross-protocol signature substitution.

### 11.3 Safe Update Transactions & Atomic Activation
The update workflow implemented in `AdvisoryUpdater` guarantees atomic all-or-nothing activation:
1. **Validation & Authentication:** Before touching disk or memory, the candidate bundle's format, engine compatibility, payload digest, signature, and record integrity are fully verified.
2. **Atomic Disk Persistence:** The new database is written to a unique temporary file (`advisories.json.tmp.<uuid>`), synced to physical storage (`file.sync_all()`), and atomically renamed over the active destination file.
3. **In-Memory Atomic Swap:** `PackageSecurityAssessor` maintains its database behind an `Arc<RwLock<AdvisoryDatabase>>`. Update activation writes the new database in a brief write lock, allowing concurrent readers (`query`, `is_malicious_package`) to transition cleanly with zero downtime or partial state reads.
4. **Failure Preservation:** If any validation, signature, or disk write step fails, the previous active database remains 100% functional and completely unchanged.

### 11.4 Rollback Protection Invariant
- **Monotonic Version Comparison:** The candidate `database_version` is parsed into numerical segments and compared against the currently active database version.
- **Rollback Rejection:** Updates where `candidate <= active` are rejected by default with `BundleValidationError::RollbackRejected`.
- **Authorized Rollback Override:** Developer can explicitly pass `--allow-rollback` via CLI or set `allow_rollback: true` over IPC.
- **Hard-Block Preservation:** Rollback never weakens active hard blocks: existing `MaliciousPackageDetected` active drift findings in monitored workspaces are retained and cannot be cleared by rolling back the advisory database.

### 11.5 Baseline Reassessment & Pending Approval Invalidation
- **Automatic Baseline Reassessment:** Upon successful bundle activation, `AdvisoryUpdater` automatically re-evaluates all registered workspace baselines against the updated intelligence.
- **Immediate Hard-Block Registration:** If an active project contains a package newly flagged as malicious, an active drift finding (`MaliciousPackageDetected`) is registered immediately, triggering gate hard-blocks on subsequent commands.
- **Pending Approval Invalidation:** Any pending command approval or execution authorization for commands involving newly flagged malicious packages is invalidated.

### 11.6 Embedded Fallback & Offline Resilience
- **Offline Intelligence:** The system does not contact remote servers or download data automatically. Bundles are imported locally and explicitly.
- **Embedded Clean Fallback:** If the external persistent database file is corrupted, truncated, or unreadable, `AdvisoryDatabase::load_with_fallback` automatically activates the embedded clean intelligence bundled inside the engine binary.
- **Distinction Between Authenticity and Accuracy:** A verified Ed25519 signature proves the bundle was published by a trusted authority; Cyravell treats advisory intelligence as defense-in-depth risk heuristics rather than infallible proofs of complete software safety.

---

## 12. Adversarial Trust, Rollback, and Recovery Validation (Phase 2.8)

Cyravell Phase 2.8 hardens the signed advisory update system against adversarial inputs, filesystem attacks, concurrency races, interrupted operations, and trust compromise.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Phase 2.8 Hardened Trust Architecture                    │
└─────────────────────────────────────────────────────────────────────────────┘
  [ Candidate Bundle ] ──► [ Strict JSON Checker ] (Rejects Duplicate Keys)
          │
          ▼
  [ TrustedKeyStore ]  ──► [ Filesystem Guard ] (Rejects Symlinks & World-Writable)
          │                 (Explicit Unsafe Status on Corruption, No Silent Fallback)
          ▼
  [ Signature Verify ] ──► [ Full Metadata Binding ] (Format, DB, Created, Publisher,
          │                 Key, Engine Min, Supported Ecosystems, Payload Digest)
          ▼
  [ Rollback Guard ]   ──► [ Persistent High-Water Mark ] (Survives Restarts & Deletions)
          │                 (IPC Rollback Requires Explicit Confirmation Token)
          ▼
  [ Approval Guard ]   ──► [ Pending & Token Revocation ] (Destroys Unconsumed Tokens)
          │
          ▼
  [ Tombstone State ]  ──► [ Irreversible Malicious Registry ] (Survives DB Rollback)
          │
          ▼
  [ Atomic Storage ]   ──► [ O_EXCL / 0600 Temp File ] + Atomic Rename + Directory Sync
```

### 12.1 Strict JSON Parsing & Duplicate Key Rejection
- **The Ambiguity Vulnerability:** Standard JSON parsers typically overwrite duplicate keys, allowing attackers to construct payloads that differ between verification and execution.
- **Strict Verification (`strict_json.rs`):** A recursive deserializer visitor inspects candidate bundles and trust store files before deserialization. Any document containing duplicate keys at any nesting level is immediately rejected with an explicit error.

### 12.2 Hardened Trust-Store Integrity & Explicit Failure
- **Symlink & Permission Enforcement:** `TrustedKeyStore::load_from_path` inspects `symlink_metadata()`. If the file is a symbolic link, or world-writable (`mode & 0o002 != 0`), loading is aborted with `KeyStoreError::SymlinkForbidden` or `KeyStoreError::InsecurePermissions`.
- **No Silent Fallback on Corruption:** If `rules/trusted_keys.json` is present on disk but corrupted, tampered with, or malformed, `load_default()` transitions the keystore to `TrustStoreStatus::Corrupted`. The engine marks trust configuration as unavailable and fails closed on all signature verifications, preventing silent fallback to embedded defaults.
- **Publisher Identity Binding:** The bundle publisher must strictly match the publisher identity bound to the key in the trust store. A valid signature from Key A cannot authenticate a bundle claiming to be from Publisher B.

### 12.3 Monotonic Anti-Rollback High-Water Mark
- **Durable Version Barrier (`advisory_security_state.json`):** A separate, hardened state store records the highest activated database version.
- **Restart & Deletion Resilience:** If an attacker wipes `advisories.json`, the active database falls back to embedded defaults, but `high_water_version` persists in the security state. Attempting to import an intermediate older bundle is rejected by default.
- **Numeric & Deterministic Comparison:** Version strings are strictly validated: 1 to 4 ASCII numeric segments (`u64`), rejecting ambiguous formats, negative integers, or non-numeric tokens.
- **Privileged IPC Authorization:** Rollback overrides cannot be triggered casually over IPC. Calls with `allow_rollback: true` require `rollback_confirmation_token: Some("CONFIRM_ADVISORY_ROLLBACK")`. Unauthorized attempts trigger high-severity audit logging and return JSON-RPC error code `-32008`.

### 12.4 Irreversible Malicious Package Tombstones
- **Rollback Invariant:** If a package is ever classified as confirmed malicious in any activated bundle, it is permanently recorded in `malicious_tombstones`.
- **Survives Rollback and DB Deletion:** Even if the advisory database is rolled back to an older version (which lacked the finding), or the external database is removed, the engine's `PackageSecurityAssessor` retains the tombstone. Any command or manifest referencing that package remains hard-blocked.

### 12.5 Approval Invalidation and Token Revocation
- **Replay Prevention:** When newly imported intelligence classifies a package as malicious:
  1. Any matching `Pending` approval request is immediately transitioned to `Denied`.
  2. Any matching `Approved` request whose single-use token was not yet consumed has its token destroyed (`authorization_token = None`) and its status transitioned to `Denied`.
  3. Attempting to call `gate.dispatch_authorized` with the previously issued token fails immediately.

### 12.6 Atomic Staging, Directory Sync, and Failure Recovery
- **Collision & Symlink Protection:** Temporary files are created in the parent directory with `create_new(true)` (`O_EXCL` semantics) and restricted Unix permissions `0600`.
- **Durability & Crash Consistency:** The file is flushed and synced (`file.sync_all()`), atomically renamed, and the parent directory is synced (`dir_file.sync_all()`).
- **Fail-Safe Recovery:** If any error occurs during write, sync, or rename, temporary files are cleaned up and the previous active database and memory state remain 100% untouched.

---

## 13. Phase 2.9: IPC Authorization, Local Access Control, and Privilege Boundary Hardening

Phase 2.9 establishes strict local privilege separation and peer authorization across Cyravell's Unix domain socket IPC interface. Rather than treating local connections as implicitly trusted or relying on client-side confirmation strings, authorization is anchored directly in the operating system kernel.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 Phase 2.9 IPC Privilege Boundary Architecture              │
└─────────────────────────────────────────────────────────────────────────────┘
  [ Local Client Process ] 
          │
     Unix Socket Connect
          │
          ▼
  [ SO_PEERCRED Extraction ] ──► Kernel-Attested (PID, UID, GID)
          │                      (Client identity headers in body ignored)
          ▼
  [ Peer Policy Evaluation ] ──► SameUserOnly / Explicit UID Allowlist
          │                      (Unauthorized UID -> Drop & Audit IPC_ACCESS_DENIED)
          ▼
  [ JSON Frame Sanitizer ]   ──► Max Frame Limit (1 MiB) + Strict JSON (No Duplicate Keys)
          │
          ▼
  [ Tiered Operation Gate ]  ──► Method Authorization Matrix:
          │                      • ReadOnly   (Status, Health, Analyze, Baselines)
          │                      • Standard   (Evaluate, Record, Create Baseline)
          │                      • Privileged (Approval Decide, Dispatch, Shutdown)
          │                      • Rollback   (Two-Phase Authenticated Rollback)
          ▼
  [ Rollback Auth Manager ]  ──► Two-Phase Tokenized Rollback:
                                 Phase 1: `package.request_rollback_authorization`
                                          (Validates bundle signature, reason >= 8 chars,
                                           confirmation phrase -> issues 60s single-use token)
                                 Phase 2: `package.import_advisory_bundle`
                                          (Consumes token atomically; enforces exact peer UID,
                                           target version, and payload digest matching)
```

### 13.1 Kernel-Attested Peer Authentication (`SO_PEERCRED`)
- **Unforgeable Identity:** On Linux, client identity is resolved through the `SO_PEERCRED` socket option (`libc::getsockopt`), returning the kernel-attested `(pid, uid, gid)`.
- **Spoofing Resistance:** Any client-supplied claims in the request body (such as `user_id`, `claimed_uid`, or `source_user`) are strictly ignored during authentication and authorization checks.
- **Fail-Closed Verification:** If peer credentials cannot be extracted from the socket, the connection is immediately terminated with JSON-RPC error code `-32003`.

### 13.2 Operation-Level Authorization Tiers
Methods are mapped into four distinct privilege tiers:
1. **`ReadOnly`:** Querying health, handshake, integrity, command analysis, pending approvals, event history, audit verification, dependency baselines, drift detection, and inspecting advisory bundles.
2. **`Standard`:** Gate command evaluation, recording execution outcomes, submitting security events, baseline creation, post-operation verification, and registering workspace monitoring.
3. **`Privileged`:** Approval decisions (`approval.decide`), gated command dispatch (`gate.dispatch_authorized`), advisory bundle import (`package.import_advisory_bundle`), requesting rollback authorization (`package.request_rollback_authorization`), and engine shutdown (`engine.shutdown`).
4. **`Rollback`:** Restricted to two-phase tokenized rollback override workflows.

When non-owner peers connect under multi-user configurations (`allow_read_only_for_other_users`), attempts to invoke operations above their permitted tier fail with `-32003` and generate high-severity `IPC_OPERATION_DENIED` audit events.

### 13.3 Two-Phase Tokenized Rollback Authorization
A static confirmation phrase like `CONFIRM_ADVISORY_ROLLBACK` alone is human acknowledgment, not identity authorization. Phase 2.9 replaces single-step overrides with a secure two-phase workflow:
1. **Authorization Request (`package.request_rollback_authorization`):**
   - The authenticated peer must belong to the `Privileged` tier.
   - The candidate bundle must pass cryptographic signature verification against the engine's `TrustedKeyStore`.
   - The caller must submit an operator reason of at least 8 characters and the exact phrase `"CONFIRM_ADVISORY_ROLLBACK"`.
   - The engine issues a single-use, 60-second time-to-live (TTL) token cryptographically bound to `(peer.uid, target_version, payload_digest, reason)`.
   - An audit record `PACKAGE_ADVISORY_ROLLBACK_REQUESTED` is appended without exposing the token secret.
2. **Atomic Token Consumption (`package.import_advisory_bundle`):**
   - When `allow_rollback: true` is presented, a valid `rollback_authorization_token` is strictly mandatory.
   - The engine atomically verifies and consumes the token under mutex synchronization:
     - Replay attempts immediately fail with `AlreadyConsumed`.
     - Presentation by a different local UID fails with `PeerUidMismatch`.
     - Bundle version tampering fails with `TargetVersionMismatch`.
     - Swapping bundle payload fails with `PayloadDigestMismatch`.
     - Expired tokens fail with `Expired`.
   - The token cannot be used again; subsequent calls require requesting a new token.

### 13.4 Local Filesystem Hardening & Stale Socket Protection
- **Socket Directory (`0700`):** Parent directory must be owned by the engine's effective UID, must not be a symbolic link, and must not be world-writable.
- **Socket Permissions (`0600`):** Newly bound sockets are set to mode `0600` and verified against symlinks and non-owner UIDs.
- **Safe Stale Socket Reclamation:** If an existing socket path exists:
  - It is verified to be a socket (`S_IFSOCK`), not a symlink, and owned by the current EUID.
  - An active connection check confirms no live engine is listening (`connect()` fails).
  - Regular files, symlinks, active sockets, or paths owned by other users are never unlinked.
- **Security State File Hardening:** `AuditLog`, `TrustedKeyStore`, and advisory databases reject world-writable files (`mode & 0o002 != 0`) and symbolic links during initialization and append operations.





