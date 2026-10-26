# Cyravell for Visual Studio Code

**Local-first security monitoring system for AI coding agents.**

Cyravell protects your development workstation and repositories when running autonomous AI coding agents (Claude Engineer, Devin, AutoGPT, Copilot Workspace, OpenHands, etc.).

The extension communicates over a local Unix domain socket with the authoritative Cyravell Rust Security Engine (`cyravell-engine`), giving you real-time visibility, security alerts, and interactive control over terminal execution and package installations.

---

## Features

### 🛡️ Live Security Status & Engine Health
- **Status Bar Integration:** Displays real-time engine connectivity, uptime, and processed events count (`$(shield) Cyravell: Active`).
- **Engine Status View:** Inspect engine state, active rule counts, release integrity, and local daemon health at a glance.

### 🚨 Real-Time Security Alerts & Event Feed
- **Pre-Execution Alerts:** Receive immediate VS Code toast notifications whenever the execution gate intercepts a dangerous or policy-violating operation.
- **Security Events Explorer:** Browse recent terminal and package evaluations with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Deep Event Inspection Panel:** Open the interactive event inspection webview to review matched rules, risk rationale, full command details, operator AST analysis, and Merkle audit sequence hashes.

### ✋ Interactive Human-in-the-Loop Approvals
- **Pending Approvals Review:** Easily review and decide on commands requiring operator confirmation (e.g., packages with known vulnerabilities, network-piped shell scripts).
- **Single-Use Cryptographic Tokens:** Approvals issue atomic, single-use authorization tokens bound strictly to the evaluated command and working directory.

### 💻 Controlled Protected Terminal
- **One-Click Launch:** Open a Cyravell-protected terminal (`cyravell-engine shell`) directly from the status view or command palette.
- **Pre-Execution Interception:** Commands entered into the protected terminal are intercepted and evaluated before execution dispatch.
- **Fail-Closed Protection:** If the security daemon is unreachable, commands safely fail closed.

### 📦 Dependency Baselines & Drift Detection
- **Baseline Creation:** Snapshot trusted project dependencies (npm, pip, cargo) directly from the IDE.
- **Drift Reconciliation:** Identify unexpected transitive alterations, unpinned version shifts, or tampering introduced by AI agents during development sessions.

### 📜 Tamper-Evident Audit Verification
- **One-Click Audit Verification:** Cryptographically verify the local SHA-256 Merkle audit chain (`audit.verify`) to ensure log records have not been tampered with or truncated.

---

## Getting Started

### 1. Prerequisites
Cyravell is a local-first security monitor. Ensure the Cyravell engine daemon is installed and running on your workstation:

```bash
# Check engine daemon status
systemctl --user status cyravell
# or start directly in user mode
cyravell-engine start
```

### 2. Connect the Extension
The extension automatically connects to the engine socket at startup. You can also manually connect or disconnect at any time:
- Press `Ctrl+Shift+P` (or `Cmd+Shift+P`) and run **`Cyravell: Connect Engine`**.
- Click the Cyravell status item in the bottom status bar.

---

## Extension Commands

| Command | Title | Description |
| :--- | :--- | :--- |
| `cyravell.connect` | Connect Engine | Connect to the local Cyravell daemon socket. |
| `cyravell.disconnect` | Disconnect Engine | Disconnect monitoring from the engine socket. |
| `cyravell.refreshStatus` | Refresh Status | Force a refresh of engine health, integrity, and recent events. |
| `cyravell.openControlledTerminal` | Open Protected Terminal | Launch an interactive protected shell session. |
| `cyravell.reviewApprovals` | Review Pending Approvals | Open dialog to review, approve, or deny gated commands. |
| `cyravell.verifyAudit` | Verify Audit Chain | Cryptographically verify the Merkle audit chain integrity. |
| `cyravell.createBaseline` | Create Dependency Baseline | Snapshot the active workspace dependency state. |
| `cyravell.reconcileDrift` | Check Dependency Drift | Check current project dependencies against baseline. |
| `cyravell.inspectAdvisories` | Inspect Advisory Bundle | Cryptographically verify an offline advisory bundle. |
| `cyravell.importAdvisories` | Import Advisory Bundle | Activate signed security advisory updates. |

---

## Configuration Settings

| Setting | Default | Description |
| :--- | :--- | :--- |
| `cyravell.socketPath` | `""` (auto-detect) | Custom path to the engine Unix domain socket. Defaults to `$XDG_RUNTIME_DIR/cyravell/cyravell.sock`. |
| `cyravell.autoConnect` | `true` | Automatically connect to the security engine on VS Code startup. |
| `cyravell.controlledTerminal.enabled` | `true` | Enable launching the protected terminal. |
| `cyravell.controlledTerminal.engineBinary` | `cyravell-engine` | Binary path used to launch the protected terminal. |
| `cyravell.controlledTerminal.failClosed` | `true` | Fail closed and prevent command execution if the daemon is offline. |

---

## Local-First Architecture & Privacy

- **Local-first design:** Cyravell is designed to perform security policy evaluation locally through its Rust engine.
- **Local IPC:** The VS Code extension communicates with the engine through a local Unix domain socket.
- **Protected command execution:** The engine evaluates commands against configured policies before dispatch through Cyravell's controlled execution path.
- **Human-in-the-loop authorization:** Approval tokens are single-use and bound to the request parameters validated by the engine.

---

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
