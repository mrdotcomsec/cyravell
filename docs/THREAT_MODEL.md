# Cyravell — Threat Model

**Version:** 2.7.0 (Phase 2.7: Secure Advisory Intelligence Updates & Rollback Protection)  
**Status:** Approved  
**Classification:** Public / Open Source  

---

## 1. Executive Summary & Purpose

Cyravell is an open-source, local-first security monitoring system designed to independently observe development activity, evaluate security risks, and progressively prevent malicious or unsafe actions executed by AI coding agents.

Modern AI coding agents (such as autonomous CLI agents, IDE copilots, and code generation assistants) typically run with the developer's user privileges. A compromised agent, hallucinating model, or one influenced by indirect prompt injection possesses the ability to read private keys, delete critical files, inject backdoors, modify CI pipelines, or exfiltrate source code.

This document establishes the initial threat model for Cyravell. It defines protected assets, threat actors, security assumptions, trust boundaries, attack surfaces, out-of-scope threats, known limitations, and the planned roadmap for mitigations.

---

## 2. Assets to Protect

The primary assets Cyravell is designed to safeguard include:

1. **Developer Workstations & Local Environment:**
   - Filesystem integrity (preventing unauthorized deletions, overwrites, or modifications outside authorized directories).
   - Local secrets and credentials (`.env`, `~/.ssh`, `~/.aws`, `~/.gnupg`, keystores, API tokens, browser session databases).
   - Shell and process runtime (preventing arbitrary command execution, reverse shells, background miners, and unauthorized daemon creation).
2. **Source Code & Supply Chain Integrity:**
   - Git repository integrity (preventing hidden backdoors, unauthorized commits, history alteration).
   - Dependency manifests (`package.json`, `Cargo.toml`, `requirements.txt`, etc.) from malicious package injection or dependency confusion attacks.
3. **Security Engine & Audit Integrity:**
   - Cyravell engine binaries, runtime configurations, rulesets, and trust anchors.
   - The cryptographic audit trail (preventing silent log alteration, truncation, or history rewrites).
   - IPC communication channels between the IDE/editor extension and the security engine.

---

## 3. Threat Actors

We classify potential threat actors into the following tiers:

| Actor ID | Description | Capabilities | Motivation |
|---|---|---|---|
| **TA-1: Prompt-Injected Coding Agent** | An AI coding assistant influenced by untrusted external content (e.g., in a README, issue description, scraped webpage, or malicious code comment) | Operates within developer's unprivileged shell and IDE context; can issue shell commands and edit code. | Execute attacker's goals (credential exfiltration, persistence, sabotage). |
| **TA-2: Malicious Dependency / Supply Chain Actor** | An untrusted third-party package or build script invoked during agent-directed dependency installation | Runs pre/post-install hooks (`npm postinstall`, `build.rs`, `setup.py`) under developer privileges. | Supply chain compromise, lateral movement, token theft. |
| **TA-3: Rogue / Hallucinating Agent** | An uncompromised agent behaving erratically due to model errors, context confusion, or excessive tool-use loops | Generates destructive commands (e.g., `rm -rf /`, `chmod -R 777`) or invalid modifications. | Unintentional developer damage. |
| **TA-4: Local Co-Resident Unprivileged Process** | Another unprivileged process running on the same workstation under the same or different local user | Can attempt to connect to Cyravell's Unix domain socket or read local files if permissions are loose. | Interfere with security monitoring or forge events. |
| **TA-5: Compromised Root / Host OS (Out of Scope)** | An attacker with `root`/`sudo` or kernel execution privileges | Complete control over kernel memory, filesystem permissions, process tracing, and system storage. | Full system takeover. |

---

## 4. Trust Boundaries

```
 +-------------------------------------------------------------------------+
 |                                Host Machine                             |
 |                                                                         |
 |  +--------------------------+             +--------------------------+  |
 |  |    Untrusted / Monitored  |             |      VS Code Extension   |  |
 |  |       AI Agent / Shell    |             |       (Cyravell Client)  |  |
 |  +-------------+------------+             +------------+-------------+  |
 |                |                                       |                |
 |                | Activity / Synthetic Events           | IPC Requests   |
 |                v                                       v                |
 |  =================== Trust Boundary 1 (IPC / Socket) =================  |
 |                |                                       |                |
 |                +-------------------+-------------------+                |
 |                                    |                                    |
 |                                    v                                    |
 |                         +----------------------+                        |
 |                         |   Cyravell Engine    |                        |
 |                         |    (Rust Daemon)     |                        |
 |                         +----------+-----------+                        |
 |                                    |                                    |
 |  =================== Trust Boundary 2 (Persistence) ================== |
 |                                    |                                    |
 |                                    v                                    |
 |                         +----------------------+                        |
 |                         | Cryptographic Audit  |                        |
 |                         |  Log & Trust Anchor  |                        |
 |                         +----------------------+                        |
 +-------------------------------------------------------------------------+
```

### Trust Boundary 1: Local IPC Socket
- **Boundary:** Unix Domain Socket located in a user-restricted directory (`$XDG_RUNTIME_DIR/cyravell/cyravell.sock` or `~/.local/share/cyravell/cyravell.sock`).
- **Enforcement:** Filesystem permissions restricted to `0700` for the parent directory and `0600` for the socket itself. Only processes running as the authentic user can connect.
- **Protocol:** Strict JSON-RPC style framed messages with maximum payload size enforcement (1 MB default), schema validation, and handshake negotiation.

### Trust Boundary 2: Audit Storage & Trust Anchors
- **Boundary:** Append-only cryptographic hash-chained audit storage on the local filesystem (`$XDG_DATA_HOME/cyravell/audit/` with `0700`/`0600` permissions).
- **Enforcement:** Each record includes SHA-256 hash chaining `H_n = Hash(H_{n-1} || Record_n)`. Verification detects insertion, modification, deletion, and truncation.

### Trust Boundary 3: Policy Evaluation vs. Execution
- The policy engine evaluates risk deterministically. It **never** dynamically executes arbitrary shell code, downloads unverified scripts, or relies on untrusted AI outputs to downgrade critical security alerts.

---

## 5. Attack Surfaces & Threats

### 5.1 Terminal & Shell Commands
- **Threat:** AI agent executes destructive or exfiltrating shell commands (`rm -rf`, `curl ... | bash`, `nc -e`, `printenv > exfil`).
- **Phase 2.1 Status:** Implemented deterministic, explainable static command security analysis pipeline with shell operator and pipeline awareness (`CommandAnalyzer`). Recognizes 7 threat categories: destructive filesystem operations, privilege escalation, credential access, remote code execution pipelines, persistence, network exfiltration, and encoded execution.
- **Phase 2.2 Status:** Implemented controlled terminal pre-execution interception foundation (`ExecutionGate` and `ControlledShell`). Captures commands before shell dispatch, evaluates policy via IPC, and enforces decisions:
  - `ALLOW_AND_MONITOR` -> Dispatched to execution backend.
  - `ALERT_AND_CONFIRM` -> Held undispatched with outcome `PENDING_APPROVAL` (Phase 2.3 deferred).
  - `BLOCK_AND_ALERT` -> Dispatched prevented with outcome `BLOCKED_BY_POLICY`.
  - Engine failure / socket down -> Prevented with outcome `FAILED_CLOSED`.
- **Phase 2.2 Boundary & Limitation:** Interception is active for sessions run under the controlled shell (`cyravell-engine shell` or VS Code `Cyravell Protected Terminal`). Commands entered into ordinary uninstrumented terminal sessions run directly and bypass the pre-execution gate. Interactive user approval dialogs and bypass testing are deferred to Phase 2.3 and 2.4.
- **Classification vs Maliciousness:** Command risk classification reflects potential operational impact, not definitive proof of malicious intent. Unvetted or obfuscated commands may be flagged as high severity even if invoked by a developer in a test setting.

### 5.2 Local IPC Exposure & Message Poisoning
- **Threat:** Malicious process sends malformed, deeply nested, or oversized JSON payloads to crash or exhaust memory in `cyravell-engine`.
- **Mitigation:**
  - Read limits: Maximum message size enforced (1 MiB).
  - Strongly typed serde deserialization with bounded buffers.
  - Rejection of unknown schema versions and malformed fields.
  - Immediate connection termination upon protocol violation.

### 5.3 Audit Log Tampering
- **Threat:** Malicious process modifies or deletes audit logs to hide evidence of unauthorized behavior.
- **Mitigation:**
  - Sequential ID tracking and cryptographic hash chaining (SHA-256).
  - Explicit tamper detection verification command. Any mismatch marks the audit log as `COMPROMISED` and preserves existing evidence.

### 5.4 Binary & Manifest Spoofing
- **Threat:** Attacker substitutes Cyravell binaries or rulesets with malicious alternatives.
- **Mitigation:**
  - Release integrity manifest defining canonical relative paths and SHA-256 hashes.
  - Strict separation of trust anchors from monitored files.

### 5.5 Execution Gate Bypass & Authorization Forgery (Phase 2.4 Hardening)
- **Threat:** Malicious AI agent or local co-resident script attempts to dispatch unapproved or destructive commands by bypassing the authorization gate, forging approval tokens, replaying consumed tokens, or modifying commands between approval and execution (TOCTOU).
- **Mitigation:**
  - **Single-Use Cryptographic Tokens:** High-entropy authorization tokens (`cyr-auth-<uuid>-<uuid>`) stored in memory, invalid after single use or engine restart.
  - **Atomic Consumption Before Dispatch:** The token is validated and consumed *before* the backend `execute()` call, preventing concurrent replay attacks.
  - **Exact Command & Session Binding:** Tokens are bound character-for-character to the approved command string and session ID. Modifying, prepending, or appending commands fails with `CommandMismatch` or `SessionMismatch`.
  - **Hard-Block Re-evaluation Guard:** At the moment of dispatch, the engine independently re-evaluates the command against policy. Hard-blocked commands (`Severity::Critical`) can never be dispatched even if a token was presented.
  - **Fail-Closed Execution:** Any error, disconnection, or unhandled case withholds execution and records the event in the audit chain.

### 5.6 Package Security, Supply Chain Attacks, & TOCTOU Manifest Alterations (Phase 2.5)
- **Threat:** Malicious AI agent attempts to install backdoored packages, protestware, typosquatted dependencies, packages with critical known CVEs, or tamper with project manifests (`package.json`, `Cargo.toml`, `requirements.txt`) or lockfiles between security review and execution.
- **Mitigation:**
  - **Pre-Installation Command Detection:** Authoritative detection across `npm`, `pnpm`, `Yarn`, `pip`, `pip3`, `python -m pip`, `npx`, `Cargo`, unwrapping execution wrappers (`sudo`, `env`).
  - **Authoritative Gate Hard-Block for Known Malicious Packages:** Packages marked malicious (`is_malicious: true`) in the advisory database are hard-blocked at the gate with zero backend execution calls; this block cannot be overridden by user approval tokens.
  - **Manifest & Lockfile Integrity Analysis:** Static inspection detects manifest-lockfile mismatches (declared dependencies missing from lockfile or unpinned), lockfile integrity format errors, and parse failures, requiring human approval before dispatch.
  - **TOCTOU Manifest Fingerprinting:** The gate computes a SHA-256 fingerprint over manifest and lockfile during evaluation and binds it to any approval request. At `dispatch_authorized`, the fingerprint is recomputed; if files were modified after approval, execution is immediately aborted (`ApprovalError::InvalidStateTransition`).
  - **Deterministic Offline Advisories:** Advisory matching is performed completely locally (`rules/package_advisories.json` + compiled fallback) without external network telemetry.
- **Threat Model Boundaries & Non-Claims:**
  - **Static Pre-Exec Limitation:** Cyravell inspects commands and project files before execution. It does not inspect dynamically downloaded binary blobs or child processes spawned by uninstrumented package manager sub-scripts unless run in the controlled terminal.
  - **Advisory Database Scope:** Cyravell detects known malicious packages and advisories present in its local database. Clean status (`CleanNoMatches`) conveys "no matches found in verified local database", not proof of absolute safety against unknown zero-days.

### 5.7 Post-Installation Integrity, Dependency Drift, & Stealth Modifications (Phase 2.6)
- **Threat:**
  - **Out-of-band File Tampering:** An agent or script modifies manifests (`package.json`, `Cargo.toml`) or lockfiles directly on disk without running a package manager CLI command, slipping malicious packages past pre-execution checks.
  - **Post-Install Stealth Infection:** A package manager successfully finishes with exit code `0` while introducing unexpected transitive dependencies or known vulnerable/malicious packages.
  - **Lockfile Integrity / Hash Drift:** An attacker modifies lockfile integrity checksums or replaces registry URLs with private malicious registries (`npm_config_registry`, etc.).
  - **Metadata Corruption Evasion:** An attacker intentionally corrupts lockfile syntax so parsers fail open or fail to detect dependencies.
- **Mitigation:**
  - **Deterministic Dependency Baselining:** Engine computes a canonical SHA-256 fingerprint over direct, resolved, and transitive dependency sets (excluding non-deterministic fields like timestamps).
  - **Invariant Trust Boundaries:** An unverified baseline snapshot (`UNVERIFIED_INITIAL` or `REVIEW_REQUIRED`) cannot overwrite an existing `VERIFIED_APPROVED` baseline without explicit developer approval.
  - **Post-Operation Verification:** Immediately upon completion of a controlled package command, Cyravell independently inspects the filesystem to verify that only expected changes occurred, re-evaluates all dependencies against the advisory database, and records the outcome in the audit chain.
  - **Active Drift Hard-Block:** If active malicious drift (`MaliciousPackageDetected`) is present in the workspace, the execution gate immediately hard-blocks all subsequent command dispatches in that workspace (exit code 126).
  - **Bounded Continuous Monitoring:** Background monitor debounces and reconciles atomic file replacements on authoritative project configuration files, logging changes honestly as `"Observed via local filesystem reconciliation (unattributed background change)"`.
  - **Credential Redaction:** Strips auth tokens and registry credentials from command lines, URLs, and audit logs.
- **Threat Model Boundaries & Non-Claims:**
  - **Filesystem Event Attribution:** Filesystem monitoring proves *that* a file changed, not *which* process initiated the write. Cyravell refuses to fabricate process attribution for background file events without verified execution context.
  - **Scope of Continuous Monitoring:** Cyravell monitors authoritative project manifest and lockfile targets, not every file in `node_modules/` or arbitrary workspace directories, avoiding I/O exhaustion.

### 5.8 Advisory Intelligence Poisoning, Rollback Attacks, & Unauthenticated Bundle Injection (Phase 2.7)
- **Threat:**
  - **Advisory Poisoning:** An attacker or rogue entity crafts a fraudulent advisory bundle to delete malicious package indicators or inject false security claims.
  - **Rollback Attacks:** An attacker forces Cyravell to revert to an older, obsolete advisory database version where recently discovered malware was not yet classified as malicious, unblocking hostile dependencies.
  - **Signature Bypass / Key Forgery:** An attacker provides an unauthenticated or self-signed bundle or tampers with the advisory payload while leaving the signature header intact.
  - **Partial Write / Atomic Activation Failure:** A crash or filesystem interruption during bundle update leaves a partially written or corrupted advisory database on disk.
  - **TOCTOU Approval Bypass:** A pending command awaiting developer review targets a package newly identified as malicious in an updated bundle.
- **Mitigation:**
  - **Asymmetric Ed25519 Cryptographic Signatures:** Every advisory bundle is cryptographically verified against pinned public keys in `rules/trusted_keys.json`. Ordinary SHA-256 digests are never accepted as proof of origin.
  - **Canonical Payload Digest Binding:** A canonical SHA-256 digest binds the exact sorted advisory set to the signed bundle header, preventing payload substitution or record injection.
  - **Strict Monotonic Versioning & Anti-Rollback Invariant:** Candidate bundles with `candidate_version <= active_version` are rejected by default with `RollbackRejected`. Rollback overrides require explicit `--allow-rollback` authorization, and rollback can never clear or weaken active hard blocks in monitored workspaces.
  - **Safe Atomic Transactions:** Updates stage to a unique temporary file (`.tmp.<uuid>`), execute `sync_all()`, and atomically overwrite destination storage via atomic rename, followed by thread-safe `RwLock` in-memory database replacement.
  - **Embedded Fallback Resiliency:** Corrupted, truncated, or unreadable external database files automatically trigger clean fallback to the embedded runtime database.
  - **Dynamic Invalidation & Reassessment:** Importing updated advisories automatically triggers full re-evaluation of all registered workspace dependency baselines and immediate hard-block enforcement for newly detected malicious packages.
- **Threat Model Boundaries & Non-Claims:**
  - **Signature Authenticity vs. Advisory Accuracy:** A valid cryptographic signature proves that a bundle originated from a trusted publisher with an authenticated private key. It does *not* prove that every advisory record is complete, bug-free, or exhaustive against all real-world malware.

---

## 6. Security Assumptions

1. **Host Operating System:** The underlying Linux kernel, glibc, and core OS primitives are functioning correctly.
2. **User Boundary:** The attacker initially operates as an unprivileged agent process.
3. **Local Clock:** The local system clock is monotonic or reasonably synchronized for sequential timestamping.

---

## 7. Out-of-Scope Threats (Phase 1)

1. **Root / Kernel Compromise:** If an attacker has obtained root privileges or installed a rootkit, local protections and kernel socket controls can be bypassed.
2. **Direct Hardware / Physical Attacks:** Memory probing or physical storage extraction.
3. **Denial of Service via OS Resource Exhaustion:** A runaway process consuming all CPU/RAM before the engine can process events.

---

## 8. Known Limitations (Phase 2.6)

- **Static Classification vs. Real-Time Blocking:** The execution gate blocks commands initiated through Cyravell's controlled terminal (`cyravell-engine shell`, `exec`, or VS Code Protected Terminal). Commands entered into unmonitored external shells run directly without gate interception.
- **Audit Tamper Evident, Not Tamper Proof:** A local user with write access to the filesystem can theoretically rewrite the log and recompute a fraudulent hash chain if they possess all trust material. True non-repudiation requires remote append-only anchoring (Phase 3).
- **Package Advisory Scope:** Cyravell checks against the local advisory database. It does not perform live network queries to npm/PyPI/crates.io (to protect developer privacy and air-gap integrity). A clean check indicates no matches in the local database, not an absence of risk.
- **Attribution Transparency:** Out-of-band file modifications observed by workspace monitoring indicate filesystem state changes; without active PTY session context, they cannot be attributed to a specific process or PID. Cyravell honestly reports these as background file reconciliation events.
- **Parser Approximations:** Pure static analysis cannot fully resolve dynamic multi-stage variable expansions or remote runtime code strings without execution. Complex or unclosed constructs are honestly flagged as `PARTIAL` or `INCONCLUSIVE`.

---

## 9. Planned Mitigations (Phase 2 & Beyond)

- **Phase 2:** PTY / Pre-exec shell interception wrappers and eBPF file monitor adapters.
- **Phase 3:** Ed25519-signed audit checkpoints and optional external tamper-evident notarization.
- **Phase 4:** Sandboxed AI secondary risk analyzer isolated behind deterministic safety gates.
