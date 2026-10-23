# Cyravell — Event Schema Specification

**Schema Version:** `1`  
**Status:** Stable (Phase 1)  

---

## 1. Event Model Overview

Every security observation or synthetic simulation in Cyravell conforms to the strongly typed `SecurityEvent` schema.

Events are immutable once ingested. Secret redaction must take place before events are persisted to the cryptographic audit log.

---

## 2. JSON Schema Definition

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "SecurityEvent",
  "type": "object",
  "required": [
    "id",
    "schema_version",
    "timestamp",
    "event_type",
    "source_adapter",
    "origin",
    "execution_status",
    "enforcement_capability",
    "payload"
  ],
  "properties": {
    "id": {
      "type": "string",
      "description": "Globally unique event identifier (e.g. UUIDv4 or 'evt-xxxx')"
    },
    "schema_version": {
      "type": "integer",
      "minimum": 1,
      "maximum": 1,
      "description": "Schema version (must be 1 in Phase 1)"
    },
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of event creation"
    },
    "event_type": {
      "type": "string",
      "enum": [
        "TERMINAL_COMMAND",
        "FILE_MODIFICATION",
        "DEPENDENCY_INSTALL",
        "CREDENTIAL_ACCESS",
        "SECURITY_POLICY_CHANGE",
        "INTEGRITY_CHECK",
        "CUSTOM"
      ]
    },
    "source_adapter": {
      "type": "string",
      "description": "Identifier of the monitoring source (e.g., 'test-harness', 'pty-interceptor', 'fs-watcher')"
    },
    "origin": {
      "type": "string",
      "enum": [
        "SIMULATED",
        "OBSERVED"
      ],
      "description": "Indicates whether the event is synthetic/test or observed live"
    },
    "execution_status": {
      "type": "string",
      "enum": [
        "SIMULATED",
        "OBSERVED",
        "PENDING_APPROVAL",
        "INTERCEPTED",
        "BLOCKED_CONFIRMED",
        "ALREADY_EXECUTED",
        "NOT_INTERCEPTABLE",
        "UNKNOWN"
      ],
      "description": "Actual operational execution state of the monitored action"
    },
    "enforcement_capability": {
      "type": "string",
      "enum": [
        "NONE",
        "PRE_EXEC_BLOCK",
        "POST_EXEC_ALERT"
      ],
      "description": "Enforcement power available to the emitter at event emission time"
    },
    "payload": {
      "type": "object",
      "properties": {
        "command": { "type": "string" },
        "working_directory": { "type": "string" },
        "target_paths": {
          "type": "array",
          "items": { "type": "string" }
        },
        "environment_keys": {
          "type": "array",
          "items": { "type": "string" }
        },
        "metadata": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        }
      }
    }
  }
}
```

---

## 3. Secret Redaction Policy

Before an event is appended to the audit log:
1. Environment variable values are never stored; only keys are recorded in `environment_keys`.
2. Commands are scanned for common inline secret patterns (`--password`, `token=`, `Bearer `, `PRIVATE KEY`). Detected patterns are replaced with `[REDACTED]`.
3. File contents are never captured in the event payload.

---

## 4. Risk Assessment & Command Analysis Schema (Phase 2.1)

```json
{
  "title": "RiskAssessment",
  "type": "object",
  "required": [
    "severity",
    "confidence",
    "rule_id",
    "reason",
    "evidence",
    "recommended_action",
    "evaluated_at"
  ],
  "properties": {
    "severity": {
      "type": "string",
      "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    },
    "confidence": {
      "type": "string",
      "enum": ["LOW", "MEDIUM", "HIGH"]
    },
    "rule_id": { "type": "string" },
    "matched_rules": {
      "type": "array",
      "items": { "type": "string" }
    },
    "reason": { "type": "string" },
    "evidence": {
      "type": "array",
      "items": { "type": "string" }
    },
    "potential_impact": { "type": "string" },
    "recommended_action": { "type": "string" },
    "analysis_completeness": {
      "type": "string",
      "enum": ["COMPLETE", "PARTIAL", "INCONCLUSIVE"]
    },
    "analysis_details": {
      "type": "object",
      "properties": {
        "raw_command": { "type": "string" },
        "sanitized_command": { "type": "string" },
        "atomic_commands_count": { "type": "integer" },
        "operators_detected": {
          "type": "array",
          "items": { "type": "string" }
        },
        "command_names": {
          "type": "array",
          "items": { "type": "string" }
        },
        "potential_impact": { "type": "string" },
        "analysis_notes": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "evaluated_at": { "type": "string", "format": "date-time" }
  }
}
```

---

## 4. Execution Gate & Outcome Schemas (Phase 2.2)

### 4.1 `GateDecision` Enum
Represents the deterministic policy decision produced by the execution gate before command dispatch:
- `ALLOW`: Permitted by policy for execution dispatch.
- `REQUIRE_APPROVAL`: Gated; requires explicit user approval (withheld in Phase 2.2).
- `BLOCK`: Prohibited by policy; dispatch denied.
- `ANALYSIS_FAILED`: Security engine offline or evaluation failed; dispatch denied under fail-closed mode.

### 4.2 `ExecutionOutcome` Enum
Enforceable outcome recorded in the cryptographic audit chain:
- `DISPATCHED`: Command was authorized and passed to the execution backend.
- `BLOCKED_BY_POLICY`: Execution prevented because command triggered a blocking policy rule.
- `PENDING_APPROVAL`: Execution withheld pending interactive user approval.
- `FAILED_CLOSED`: Execution prevented because the security engine was unreachable or evaluation failed.
- `EXECUTION_FAILED`: Command was authorized, but the OS process spawn failed.

