# Cyravell — Local IPC Protocol Specification

**Protocol Version:** `1.0`  
**Transport:** Unix Domain Stream Socket (`AF_UNIX`)  
**Framing:** Newline-delimited JSON (`\n`)  
**Default Socket Path:** `$XDG_RUNTIME_DIR/cyravell/cyravell.sock` (fallback: `~/.local/share/cyravell/cyravell.sock` or `/tmp/cyravell-$UID/cyravell.sock`)  

---

## 1. Transport & Security Model

1. **Local Only:** Cyravell operates exclusively over Unix domain sockets. No network interfaces (TCP/UDP) are bound or exposed.
2. **Access Control:**
   - Socket directory permissions: `0700` (`rwx------`)
   - Socket node permissions: `0600` (`rw-------`)
   - Owned by the executing user ID (`UID`).
3. **Framing & Limits:**
   - Messages are single lines of valid UTF-8 JSON terminated by `\n` (LF) or `\r\n` (CRLF).
   - Maximum allowed request frame size: **1,048,576 bytes (1 MiB)**. Connections sending frames exceeding this limit are immediately terminated.
   - Connection idle read timeout: **30 seconds**.
4. **Security Assumptions & Boundaries:**
   - File permissions prevent access by distinct local user accounts.
   - Note: Socket permissions *do not* protect against compromised processes running under the *same* user ID. Integrity relies on protocol validation, cryptographic hash-chaining, and separation of privileges.

---

## 2. Message Envelope

All communications follow a structured Request-Response model. Every request includes a client-specified `id` for correlation.

### 2.1 Request Envelope
```json
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "method": "<method_name>",
  "params": { ... }
}
```

### 2.2 Response Envelope
```json
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "result": { ... }
}
```

### 2.3 Error Envelope
```json
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "error": {
    "code": -32600,
    "message": "Invalid Request",
    "details": "Unsupported protocol or schema version"
  }
}
```

Standard Error Codes:
- `-32700`: Parse error (invalid JSON)
- `-32600`: Invalid request (missing required fields or oversized frame)
- `-32601`: Method not found
- `-32602`: Invalid params (schema version mismatch, validation error)
- `-32603`: Internal engine error
- `-32001`: Policy evaluation failure
- `-32002`: Audit verification failure
- `-32004`: Hard block violation (confirmed malicious package cannot be approved or dispatched)
- `-32005`: Manifest modified after approval (TOCTOU integrity check failed)
- `-32006`: Active drift block or unverified baseline transition denied

---

## 3. Supported Methods

### 3.1 `engine.handshake`
Negotiates protocol version and client identity.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "engine.handshake",
  "params": {
    "client_name": "vscode-cyravell",
    "client_version": "0.1.0",
    "protocol_version": "1.0"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "status": "ready",
    "engine_name": "cyravell-engine",
    "engine_version": "0.1.0",
    "protocol_version": "1.0",
    "capabilities": [
      "event_submission",
      "deterministic_policy",
      "audit_verification",
      "integrity_check"
    ]
  }
}
```

---

### 3.2 `engine.get_health`
Returns current engine status, uptime, and system state.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "2",
  "method": "engine.get_health",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "2",
  "result": {
    "status": "healthy",
    "uptime_seconds": 128,
    "events_processed": 14,
    "audit_records_count": 14,
    "degraded_reasons": []
  }
}
```

---

### 3.3 `engine.get_integrity`
Returns release integrity verification status.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "3",
  "method": "engine.get_integrity",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "3",
  "result": {
    "status": "verified",
    "manifest_version": "1.0",
    "verified_files_count": 6,
    "details": "All release files matched trust manifest SHA-256 hashes"
  }
}
```

---

### 3.4 `command.analyze` (Phase 2.1)
Performs static security analysis on a command string without execution and without appending to the persistent audit log.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "4",
  "method": "command.analyze",
  "params": {
    "command": "git status && rm -rf /",
    "working_directory": "/workspace"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "4",
  "result": {
    "analysis_completeness": "COMPLETE",
    "risk_assessment": {
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "rule_id": "RULE-TERM-001",
      "matched_rules": ["RULE-TERM-001"],
      "reason": "Potentially catastrophic recursive deletion of root, home, or system path detected",
      "evidence": [
        "Command: rm (recursive=true, force=true)",
        "Target path: /"
      ],
      "potential_impact": "Permanent loss of operating system files or developer home directory data",
      "recommended_action": "BLOCK_AND_ALERT",
      "analysis_completeness": "COMPLETE",
      "evaluated_at": "2026-10-23T14:30:00Z",
      "analysis_details": {
        "raw_command": "git status && rm -rf /",
        "sanitized_command": "git status && rm -rf /",
        "atomic_commands_count": 2,
        "command_names": ["git", "rm"],
        "operators_detected": ["&&"],
        "potential_impact": "Permanent loss of operating system files or developer home directory data",
        "analysis_notes": ["Working directory: /workspace"]
      }
    }
  }
}
```

---

### 3.5 `event.submit`
Submits a security event for evaluation and audit recording.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "4",
  "method": "event.submit",
  "params": {
    "event": {
      "id": "evt-7f8e3a2b",
      "schema_version": 1,
      "timestamp": "2026-10-23T12:00:00Z",
      "event_type": "TERMINAL_COMMAND",
      "source_adapter": "test-harness",
      "origin": "SIMULATED",
      "execution_status": "OBSERVED",
      "enforcement_capability": "NONE",
      "command": "rm -rf /home/user/project",
      "working_dir": "/home/user/project",
      "metadata": {
        "agent_name": "synthetic-test-agent"
      }
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "4",
  "result": {
    "event_id": "evt-7f8e3a2b",
    "risk_assessment": {
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "rule_id": "RULE-TERM-001",
      "reason": "Potentially destructive recursive deletion command detected",
      "evidence": ["Matched pattern: rm -rf", "Target path includes user directory"],
      "recommended_action": "BLOCK_AND_ALERT",
      "evaluated_at": "2026-10-23T12:00:00.050Z"
    },
    "audit_sequence": 15,
    "audit_record_hash": "a1b2c3d4e5f6...",
    "recorded": true
  }
}
```

---

### 3.5 `event.get_recent`
Retrieves recent security events for the extension feed.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "5",
  "method": "event.get_recent",
  "params": {
    "limit": 50
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "5",
  "result": {
    "events": [
      {
        "event_id": "evt-7f8e3a2b",
        "timestamp": "2026-10-23T12:00:00Z",
        "event_type": "TERMINAL_COMMAND",
        "origin": "SIMULATED",
        "execution_status": "OBSERVED",
        "risk_assessment": {
          "severity": "CRITICAL",
          "reason": "Potentially destructive recursive deletion command detected"
        }
      }
    ]
  }
}
```

---

### 3.6 `event.get_details`
Retrieves comprehensive details and audit trail for a specific event.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "6",
  "method": "event.get_details",
  "params": {
    "event_id": "evt-7f8e3a2b"
  }
}
```

---

### 3.7 `audit.verify`
Verifies the cryptographic integrity of the local append-only audit hash chain.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "7",
  "method": "audit.verify",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "7",
  "result": {
    "status": "VALID",
    "total_records": 15,
    "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "latest_hash": "a1b2c3d4e5f6...",
    "corrupted_sequence": null,
    "message": "Audit chain cryptographic integrity verified successfully"
  }
}
```

---

### 3.8 `gate.evaluate` (Phase 2.2 / Phase 2.4 / Phase 2.5)
Evaluates a command string against security policy prior to terminal dispatch, returning a gate decision (`ALLOW`, `REQUIRE_APPROVAL`, `BLOCK`, `ANALYSIS_FAILED`).

In Phase 2.5, if the command is a package manager invocation (`npm`, `pnpm`, `yarn`, `pip`, `pip3`, `python -m pip`, `npx`, `cargo`), the response includes an authoritative `package_assessment` containing parsed operations, inspected lockfiles/manifests, manifest SHA-256 fingerprint, and any vulnerability/malice findings from the local advisory database. If a confirmed malicious package is detected, `decision` is `BLOCK`, `allow_dispatch` is `false`, and `request_id` is `null` (strictly non-overridable).

**Request (Package Install):**
```json
{
  "jsonrpc": "2.0",
  "id": "8",
  "method": "gate.evaluate",
  "params": {
    "command": "npm install lodash@4.17.20",
    "session_id": "session-1234",
    "working_directory": "/workspace/project",
    "fail_closed": true
  }
}
```

**Response (Package Assessment with Advisory Finding):**
```json
{
  "jsonrpc": "2.0",
  "id": "8",
  "result": {
    "decision": "REQUIRE_APPROVAL",
    "outcome": "PENDING_APPROVAL",
    "allow_dispatch": false,
    "request_id": "appr-40712ae9-881c-4a4c-add9-00571e50bd47",
    "session_id": "session-1234",
    "risk_assessment": {
      "severity": "HIGH",
      "confidence": "HIGH",
      "rule_id": "RULE-PKG-002",
      "reason": "Package security finding: 1 known vulnerabilities detected",
      "matched_rules": ["RULE-PKG-002"],
      "potential_impact": "Supply chain vulnerability exposure"
    },
    "package_assessment": {
      "ecosystem": "Npm",
      "operation": "Install",
      "packages": ["lodash@4.17.20"],
      "status": "Vulnerable",
      "findings": [
        {
          "package_name": "lodash",
          "affected_version": "4.17.20",
          "severity": "High",
          "advisory_id": "GHSA-p6mc-m468-83gw",
          "description": "Prototype Pollution in lodash",
          "is_malicious": false,
          "recommendation": "Upgrade lodash to >= 4.17.21"
        }
      ],
      "manifest_fingerprint": "a3f5b7c891e234567890abcdef1234567890abcdef1234567890abcdef123456",
      "lockfile_present": true,
      "mismatches": []
    },
    "analysis_completeness": "COMPLETE",
    "audit_sequence": 14,
    "audit_record_hash": "031ececbe3f0e139e14566a1b4c062ff3ccffa6cbf2c97aa8b5ef3ad65635a46",
    "reason": "Package security finding: 1 known vulnerabilities detected"
  }
}
```

---

### 3.9 `gate.record_outcome` (Phase 2.2)
Records the terminal execution outcome (`DISPATCHED`, `BLOCKED_BY_POLICY`, `PENDING_APPROVAL`, `DENIED_BY_USER`, `CANCELLED_BY_USER`, `EXPIRED_APPROVAL`, `FAILED_CLOSED`, `EXECUTION_FAILED`) with the actual exit code in the tamper-evident audit log.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "9",
  "method": "gate.record_outcome",
  "params": {
    "command": "cargo check",
    "decision": "ALLOW",
    "outcome": "DISPATCHED",
    "exit_code": 0,
    "working_directory": "/workspace/project"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "9",
  "result": {
    "recorded": true,
    "audit_sequence": 15,
    "audit_record_hash": "d42ad807c6f5a30333c9e95e79082c801b992a1a8234f78134e3008efb99d712"
  }
}
```

---

### 3.10 `approval.decide` (Phase 2.4)
Records a user approval decision (`APPROVE`, `DENY`, `CANCEL`) for a pending approval request. When approved, generates a single-use cryptographically unpredictable authorization token. Once decided, further state transitions are rejected.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "10",
  "method": "approval.decide",
  "params": {
    "request_id": "appr-40712ae9-881c-4a4c-add9-00571e50bd47",
    "decision": "APPROVE",
    "reason": "Developer verified install script signature"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "10",
  "result": {
    "request_id": "appr-40712ae9-881c-4a4c-add9-00571e50bd47",
    "status": "APPROVED",
    "authorization_token": "cyr-auth-b2e1f4a9-8d1c-4b3e-9f0a-112233445566-a1b2c3d4",
    "audit_sequence": 16,
    "message": "Decision APPROVE recorded successfully"
  }
}
```

---

### 3.11 `approval.get_pending` (Phase 2.4 / Phase 2.5)
Lists all currently active, non-expired pending approval requests, optionally filtered by `session_id`.

In Phase 2.5, pending requests generated from package manager commands also include `manifest_fingerprint` (the SHA-256 fingerprint of the manifest and lockfile) and `package_details` (summary of ecosystem, operation, affected packages, and vulnerability findings).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "11",
  "method": "approval.get_pending",
  "params": {
    "session_id": "session-1234"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "11",
  "result": {
    "pending_requests": [
      {
        "request_id": "appr-40712ae9-881c-4a4c-add9-00571e50bd47",
        "session_id": "session-1234",
        "command": "npm install lodash@4.17.20",
        "working_directory": "/workspace/project",
        "rule_id": "RULE-PKG-002",
        "severity": "HIGH",
        "reason": "Package security finding: 1 known vulnerabilities detected",
        "created_at": "2026-10-24T09:30:00Z",
        "expires_at": "2026-10-24T09:31:00Z",
        "status": "PENDING",
        "manifest_fingerprint": "a3f5b7c891e234567890abcdef1234567890abcdef1234567890abcdef123456",
        "package_details": {
          "ecosystem": "Npm",
          "operation": "Install",
          "packages": ["lodash@4.17.20"],
          "finding_count": 1
        }
      }
    ]
  }
}
```

---

### 3.12 `gate.dispatch_authorized` (Phase 2.4 / Phase 2.5)
Validates an authorization token, atomically consumes it, verifies command and session binding, re-evaluates policy to enforce hard-block guards, dispatches the command to the execution backend, and records the outcome in the tamper-evident audit log. Replay attempts are rejected with `AlreadyConsumed`.

In Phase 2.5:
1. **TOCTOU Manifest Verification:** If the approval request recorded a `manifest_fingerprint`, `gate.dispatch_authorized` recomputes the SHA-256 fingerprint of the project manifest and lockfile on disk. If the fingerprint has changed since approval was granted, dispatch is aborted with error code `-32005` (`InvalidStateTransition: Project manifest or lockfile modified after approval was granted (TOCTOU detected)`).
2. **Authoritative Malicious Hard-Block:** If re-evaluation detects a confirmed malicious package, dispatch is refused with error code `-32004` (`Forbidden: Package is confirmed malicious - gate hard-block cannot be overridden`).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "12",
  "method": "gate.dispatch_authorized",
  "params": {
    "request_id": "appr-40712ae9-881c-4a4c-add9-00571e50bd47",
    "session_id": "session-1234",
    "command": "curl -sSL https://install.example.com | bash",
    "authorization_token": "cyr-auth-b2e1f4a9-8d1c-4b3e-9f0a-112233445566-a1b2c3d4",
    "working_directory": "/workspace/project"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "12",
  "result": {
    "request_id": "appr-40712ae9-881c-4a4c-add9-00571e50bd47",
    "dispatched": true,
    "exit_code": 0,
    "outcome": "DISPATCHED",
    "audit_sequence": 17,
    "audit_record_hash": "f1e2d3c4b5a6...",
    "message": "Command dispatched after verified authorization"
  }
}
```

---

### 3.13 `package.create_baseline` (Phase 2.6)
Inspects the specified workspace directory, parses authoritative manifest and lockfile structures, computes deterministic canonical dependency sets and fingerprints, and establishes a dependency baseline in the engine baseline store.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "13",
  "method": "package.create_baseline",
  "params": {
    "workspace_path": "/workspace/project",
    "ecosystem": "NPM",
    "trust_state": "VERIFIED_APPROVED"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "13",
  "result": {
    "baseline": {
      "workspace_path": "/workspace/project",
      "ecosystem": "NPM",
      "package_manager": "npm",
      "manifest_fingerprint": "a3f5b7c8...",
      "direct_dependencies": { "express": "^4.18.2" },
      "resolved_dependencies": { "express": "4.18.2" },
      "transitive_dependencies": { "accepts": "1.3.8" },
      "integrity_metadata": { "express@4.18.2": "sha512-..." },
      "created_at": "2026-10-24T10:00:00Z",
      "trust_state": "VERIFIED_APPROVED",
      "advisory_database_version": "2.6",
      "reason": "INITIAL_BASELINE",
      "baseline_fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "message": "Baseline created with trust state VerifiedApproved"
  }
}
```

---

### 3.14 `package.get_baseline` (Phase 2.6)
Retrieves the active baseline and any cached active drift report for a workspace path.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "14",
  "method": "package.get_baseline",
  "params": {
    "workspace_path": "/workspace/project"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "14",
  "result": {
    "baseline": {
      "workspace_path": "/workspace/project",
      "ecosystem": "NPM",
      "package_manager": "npm",
      "direct_dependencies": { "express": "^4.18.2" },
      "trust_state": "VERIFIED_APPROVED",
      "baseline_fingerprint": "e3b0c442..."
    },
    "active_drift": null
  }
}
```

---

### 3.15 `package.detect_drift` (Phase 2.6)
Performs deterministic drift detection by comparing the current workspace filesystem state against the stored trusted baseline. Optionally performs filesystem reconciliation. If malicious drift is detected, active drift is registered and blocks subsequent execution gates.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "15",
  "method": "package.detect_drift",
  "params": {
    "workspace_path": "/workspace/project",
    "reconcile": true
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "15",
  "result": {
    "drift_report": {
      "workspace_path": "/workspace/project",
      "ecosystem": "NPM",
      "trusted_baseline_fingerprint": "e3b0c442...",
      "current_fingerprint": "7a8b9c...",
      "has_drift": true,
      "findings": [
        {
          "finding_id": "drift-find-001",
          "ecosystem": "NPM",
          "package_name": "flatmap-stream",
          "current_version": "0.1.1",
          "change_type": "MALICIOUS_PACKAGE_DETECTED",
          "evidence": ["Known malicious package detected in current dependencies: flatmap-stream@0.1.1"],
          "applicable_rules": ["RULE-PKG-MALICIOUS-001"],
          "status": "CONFIRMED",
          "recommended_action": "Immediately remove flatmap-stream",
          "is_malicious": true,
          "severity": "CRITICAL"
        }
      ],
      "evaluated_at": "2026-10-24T10:05:00Z",
      "summary": "1 dependency drift findings detected across NPM dependencies"
    },
    "baseline_trust": "REVIEW_REQUIRED"
  }
}
```

---

### 3.16 `package.verify_post_operation` (Phase 2.6)
Verifies project state immediately after execution of a package operation. Disentangles command exit code from verification safety. Compares against pre-operation baseline and scans new dependencies against the local advisory database.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "16",
  "method": "package.verify_post_operation",
  "params": {
    "workspace_path": "/workspace/project",
    "command": "npm install lodash@4.17.21",
    "exit_code": 0
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "16",
  "result": {
    "verification": {
      "process_outcome": "Process exited with code 0",
      "exit_code": 0,
      "verification_status": "VERIFIED",
      "pre_operation_fingerprint": "e3b0c442...",
      "post_operation_fingerprint": "9f8e7d6c...",
      "drift_report": {
        "workspace_path": "/workspace/project",
        "ecosystem": "NPM",
        "has_drift": false,
        "findings": [],
        "evaluated_at": "2026-10-24T10:10:00Z",
        "summary": "No dependency drift detected"
      },
      "notes": ["Post-operation verification completed with status VERIFIED"]
    },
    "audit_sequence": 24
  }
}
```

---

### 3.17 `package.monitor_workspace` (Phase 2.6)
Registers or unregisters a workspace directory for continuous, resource-bounded manifest and lockfile monitoring.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "17",
  "method": "package.monitor_workspace",
  "params": {
    "workspace_path": "/workspace/project",
    "register": true
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "17",
  "result": {
    "monitored": true,
    "active_files": [
      "/workspace/project/package.json",
      "/workspace/project/package-lock.json"
    ],
    "message": "Workspace registered for continuous bounded dependency monitoring"
  }
}
```

---

### 3.18 `package.get_advisory_status` (Phase 2.7)
Queries active package vulnerability and malicious package intelligence database status, provenance, version, record counts, and engine compatibility.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "18",
  "method": "package.get_advisory_status",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "18",
  "result": {
    "status": {
      "database_version": "2026.04.1",
      "source": "EMBEDDED",
      "source_name": "embedded_fallback",
      "publisher": "Cyravell Core",
      "key_id": "cyravell-sec-official-2026",
      "fingerprint": "a3f5c7...",
      "records_count": 16,
      "malicious_count": 10,
      "vulnerabilities_count": 6,
      "last_updated": "2026-04-01T00:00:00Z",
      "verification_status": "AUTHENTICATED",
      "min_cyravell_version": "0.1.0"
    }
  }
}
```

---

### 3.19 `package.inspect_advisory_bundle` (Phase 2.7)
Inspects a local advisory bundle file without applying it. Performs Ed25519 cryptographic signature authentication, schema verification, payload digest verification, and calculates differences against the active database.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "19",
  "method": "package.inspect_advisory_bundle",
  "params": {
    "bundle_path": "/tmp/advisory-bundle-2026.05.01.json",
    "keys_path": null
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "19",
  "result": {
    "bundle_format_version": "1.0",
    "database_version": "2026.05.01",
    "created_at": "2026-05-01T12:00:00Z",
    "publisher": "Cyravell Security Intelligence Team",
    "key_id": "cyravell-sec-official-2026",
    "is_valid": true,
    "signature_valid": true,
    "candidate_version": "2026.05.01",
    "active_version": "2026.04.1",
    "would_rollback": false,
    "records_count": 25,
    "malicious_count": 15,
    "vulnerabilities_count": 10,
    "new_records": ["CYR-MAL-NPM-101 (malicious-miner-x)"],
    "updated_records": ["CYR-VULN-NPM-001 (lodash)"],
    "removed_records": [],
    "summary": "Candidate v2026.05.01 by 'Cyravell Security Intelligence Team': 25 records (1 new, 1 updated, 0 removed, 15 malicious). Valid: true, Would rollback: false"
  }
}
```

---

### 3.20 `package.import_advisory_bundle` (Phase 2.7)
Authenticates, validates, atomically persists, and activates an advisory update bundle. Atomically swaps the active in-memory database, records a tamper-evident audit record, and automatically re-evaluates dependency baselines across all monitored workspaces. Enforces anti-rollback unless `allow_rollback: true` is explicitly authorized.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "20",
  "method": "package.import_advisory_bundle",
  "params": {
    "bundle_path": "/tmp/advisory-bundle-2026.05.01.json",
    "allow_rollback": false,
    "keys_path": null
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "20",
  "result": {
    "success": true,
    "previous_version": "2026.04.1",
    "new_version": "2026.05.01",
    "publisher": "Cyravell Security Intelligence Team",
    "key_id": "cyravell-sec-official-2026",
    "records_count": 25,
    "malicious_count": 15,
    "fingerprint": "b78d2...",
    "affected_workspaces": ["/workspace/project"],
    "rollback_authorized": false,
    "audit_sequence": 29,
    "message": "Advisory bundle v2026.05.01 successfully imported and activated"
  }
}
```


