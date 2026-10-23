 # Cyravell — Threat Model

**Version:** 1.0.0 (Phase 1: Foundation & Vertical Slice)  
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

## 8. Known Limitations (Phase 2.1)

- **Static Classification vs. Real-Time Blocking:** Phase 2.1 implements static command security analysis and risk classification. It does not claim real-time OS-level command interception or process blocking. Real command interception requires subsequent PTY or eBPF layers.
- **Audit Tamper Evident, Not Tamper Proof:** A local user with write access to the filesystem can theoretically rewrite the log and recompute a fraudulent hash chain if they possess all trust material. True non-repudiation requires remote append-only anchoring (Phase 3).
- **Parser Approximations:** Pure static analysis cannot fully resolve dynamic multi-stage variable expansions or remote runtime code strings without execution. Complex or unclosed constructs are honestly flagged as `PARTIAL` or `INCONCLUSIVE`.

---

## 9. Planned Mitigations (Phase 2 & Beyond)

- **Phase 2:** PTY / Pre-exec shell interception wrappers and eBPF file monitor adapters.
- **Phase 3:** Ed25519-signed audit checkpoints and optional external tamper-evident notarization.
- **Phase 4:** Sandboxed AI secondary risk analyzer isolated behind deterministic safety gates.
