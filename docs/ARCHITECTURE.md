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


