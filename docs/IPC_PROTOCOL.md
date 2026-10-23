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

### 3.8 `gate.evaluate` (Phase 2.2)
Evaluates a command string against security policy prior to terminal dispatch, returning a gate decision (`ALLOW`, `REQUIRE_APPROVAL`, `BLOCK`, `ANALYSIS_FAILED`). Blocked and pending commands are immediately committed to the cryptographic audit log.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "8",
  "method": "gate.evaluate",
  "params": {
    "command": "rm -rf /",
    "working_directory": "/workspace/project",
    "fail_closed": true
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "8",
  "result": {
    "decision": "BLOCK",
    "outcome": "BLOCKED_BY_POLICY",
    "allow_dispatch": false,
    "risk_assessment": {
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "rule_id": "RULE-TERM-001",
      "reason": "Potentially catastrophic recursive deletion of root, home, or system path detected",
      "matched_rules": ["RULE-TERM-001"],
      "potential_impact": "Permanent loss of operating system files or developer home directory data"
    },
    "analysis_completeness": "COMPLETE",
    "audit_sequence": 14,
    "audit_record_hash": "031ececbe3f0e139e14566a1b4c062ff3ccffa6cbf2c97aa8b5ef3ad65635a46",
    "reason": "Potentially catastrophic recursive deletion of root, home, or system path detected"
  }
}
```

---

### 3.9 `gate.record_outcome` (Phase 2.2)
Records the terminal execution outcome (`DISPATCHED`, `BLOCKED_BY_POLICY`, `PENDING_APPROVAL`, `FAILED_CLOSED`, `EXECUTION_FAILED`) with the actual exit code in the tamper-evident audit log.

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

