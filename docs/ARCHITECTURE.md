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

