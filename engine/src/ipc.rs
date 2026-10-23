// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::audit::AuditLog;
use crate::integrity::{verify_manifest, IntegrityStatus};
use crate::model::*;
use crate::policy::PolicyEngine;

pub struct EngineState {
    pub start_time: Instant,
    pub events_processed: AtomicU64,
    pub recent_events: Mutex<VecDeque<EvaluatedEventRecord>>,
    pub policy: PolicyEngine,
    pub audit: AuditLog,
    pub manifest_path: Option<PathBuf>,
    pub base_dir: PathBuf,
    pub shutdown_requested: AtomicBool,
}

pub struct IpcServer {
    socket_path: PathBuf,
    state: Arc<EngineState>,
}

impl IpcServer {
    pub fn new<P: AsRef<Path>>(
        socket_path: P,
        data_dir: P,
        manifest_path: Option<PathBuf>,
        base_dir: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let socket_path = socket_path.as_ref().to_path_buf();
        let data_dir = data_dir.as_ref().to_path_buf();

        let audit_path = data_dir.join("audit.log");
        let audit = AuditLog::open(&audit_path)?;

        let state = Arc::new(EngineState {
            start_time: Instant::now(),
            events_processed: AtomicU64::new(0),
            recent_events: Mutex::new(VecDeque::with_capacity(100)),
            policy: PolicyEngine::new(),
            audit,
            manifest_path,
            base_dir,
            shutdown_requested: AtomicBool::new(false),
        });

        Ok(Self { socket_path, state })
    }

    /// Prepares socket file, removing stale socket if present, or aborting if active.
    pub fn bind_listener(&self) -> Result<UnixListener, Box<dyn std::error::Error>> {
        if self.socket_path.exists() {
            // Check if existing socket is active
            if UnixStream::connect(&self.socket_path).is_ok() {
                return Err(format!(
                    "Another Cyravell engine instance is already active on socket: {}",
                    self.socket_path.display()
                )
                .into());
            } else {
                // Stale socket: safe to remove
                std::fs::remove_file(&self.socket_path)?;
            }
        }

        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;

        Ok(listener)
    }

    /// Runs the IPC listener loop until shutdown is signaled.
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = self.bind_listener()?;

        while !self.state.shutdown_requested.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    let state_clone = Arc::clone(&self.state);
                    std::thread::spawn(move || {
                        handle_client(stream, state_clone);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    eprintln!("Cyravell IPC accept error: {}", e);
                }
            }
        }

        // Clean up socket file on orderly exit
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        Ok(())
    }

    pub fn shutdown(&self) {
        self.state.shutdown_requested.store(true, Ordering::SeqCst);
    }
}

fn handle_client(mut stream: UnixStream, state: Arc<EngineState>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut reader = BufReader::new(stream.try_clone().expect("Failed to clone socket stream"));
    let mut line_buffer = String::new();

    loop {
        line_buffer.clear();
        match reader.read_line(&mut line_buffer) {
            Ok(0) => break, // Client disconnected
            Ok(bytes_read) => {
                if bytes_read > MAX_FRAME_SIZE_BYTES {
                    let err_resp = JsonRpcResponse::error(
                        serde_json::Value::Null,
                        -32600,
                        "Frame size exceeds 1 MiB limit".to_string(),
                        None,
                    );
                    let _ = send_response(&mut stream, &err_resp);
                    break;
                }

                let trimmed = line_buffer.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let request: Result<JsonRpcRequest, _> = serde_json::from_str(trimmed);
                let response = match request {
                    Ok(req) => dispatch_request(req, &state),
                    Err(e) => JsonRpcResponse::error(
                        serde_json::Value::Null,
                        -32700,
                        "Parse error: invalid JSON".to_string(),
                        Some(e.to_string()),
                    ),
                };

                if let Err(e) = send_response(&mut stream, &response) {
                    eprintln!("Failed to write IPC response: {}", e);
                    break;
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Keep-alive or timeout check
                if state.shutdown_requested.load(Ordering::SeqCst) {
                    break;
                }
            }
            Err(_) => break, // Connection terminated or reset
        }
    }
}

fn send_response(stream: &mut UnixStream, response: &JsonRpcResponse) -> std::io::Result<()> {
    let json_bytes = serde_json::to_vec(response)?;
    stream.write_all(&json_bytes)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn dispatch_request(req: JsonRpcRequest, state: &Arc<EngineState>) -> JsonRpcResponse {
    let id = req.id.clone();
    match req.method.as_str() {
        "engine.handshake" => {
            let res = HandshakeResult {
                status: "ready".to_string(),
                engine_name: "cyravell-engine".to_string(),
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: "1.0".to_string(),
                capabilities: vec![
                    "event_submission".to_string(),
                    "deterministic_policy".to_string(),
                    "audit_verification".to_string(),
                    "integrity_check".to_string(),
                    "execution_gate".to_string(),
                ],
            };
            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
        }

        "engine.get_health" => {
            let uptime = state.start_time.elapsed().as_secs();
            let count = state.events_processed.load(Ordering::SeqCst);
            let audit_count = state.audit.total_records();

            let res = HealthResult {
                status: "healthy".to_string(),
                uptime_seconds: uptime,
                events_processed: count,
                audit_records_count: audit_count,
                degraded_reasons: vec![],
            };
            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
        }

        "engine.get_integrity" => {
            let report = match &state.manifest_path {
                Some(p) => verify_manifest(p, &state.base_dir),
                None => crate::integrity::IntegrityVerificationReport {
                    status: IntegrityStatus::Degraded,
                    manifest_version: "none".to_string(),
                    release_version: "none".to_string(),
                    verified_files_count: 0,
                    mismatched_files: vec![],
                    missing_files: vec!["manifest path not configured".to_string()],
                    authentication_status: "UNCONFIGURED".to_string(),
                    details: "No integrity manifest specified for engine".to_string(),
                },
            };

            let status_str = match report.status {
                IntegrityStatus::Verified => "verified",
                IntegrityStatus::Degraded => "degraded",
                IntegrityStatus::Corrupted => "corrupted",
                IntegrityStatus::Failed => "failed",
            };

            let res = IntegrityResult {
                status: status_str.to_string(),
                manifest_version: report.manifest_version,
                verified_files_count: report.verified_files_count,
                details: report.details,
            };
            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
        }

        "command.analyze" => {
            let params = match req.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Missing params for command.analyze".to_string(),
                        None,
                    )
                }
            };

            let analyze_params: CommandAnalyzeParams = match serde_json::from_value(params) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Invalid command.analyze params format".to_string(),
                        Some(e.to_string()),
                    )
                }
            };

            let assessment = state.policy.analyze_command_string(
                &analyze_params.command,
                analyze_params.working_directory.as_deref(),
            );

            let res = CommandAnalyzeResult {
                analysis_completeness: assessment.analysis_completeness,
                risk_assessment: assessment,
            };
            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
        }

        "gate.evaluate" => {
            let params = match req.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Missing params for gate.evaluate".to_string(),
                        None,
                    )
                }
            };

            let eval_params: GateEvaluateParams = match serde_json::from_value(params) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Invalid gate.evaluate params format".to_string(),
                        Some(e.to_string()),
                    )
                }
            };

            let raw_cmd = &eval_params.command;
            // 1. Input Validation
            if raw_cmd.trim().is_empty() {
                let res = GateEvaluateResult {
                    decision: GateDecision::Block,
                    outcome: ExecutionOutcome::BlockedByPolicy,
                    risk_assessment: RiskAssessment {
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        rule_id: "RULE-EMPTY".to_string(),
                        reason: "Empty command string".to_string(),
                        evidence: vec![],
                        recommended_action: "BLOCK_AND_ALERT".to_string(),
                        evaluated_at: chrono::Utc::now(),
                        matched_rules: vec!["RULE-EMPTY".to_string()],
                        potential_impact: None,
                        analysis_completeness: AnalysisCompleteness::Complete,
                        analysis_details: None,
                    },
                    analysis_completeness: AnalysisCompleteness::Complete,
                    audit_sequence: None,
                    audit_record_hash: None,
                    reason: "Empty command string".to_string(),
                    allow_dispatch: false,
                };
                return JsonRpcResponse::success(id, serde_json::to_value(res).unwrap());
            }

            if raw_cmd.contains('\0') {
                let res = GateEvaluateResult {
                    decision: GateDecision::Block,
                    outcome: ExecutionOutcome::BlockedByPolicy,
                    risk_assessment: RiskAssessment {
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        rule_id: "RULE-NULL-BYTE".to_string(),
                        reason: "Command contains illegal null byte".to_string(),
                        evidence: vec!["Null byte (0x00) detected".to_string()],
                        recommended_action: "BLOCK_AND_ALERT".to_string(),
                        evaluated_at: chrono::Utc::now(),
                        matched_rules: vec!["RULE-NULL-BYTE".to_string()],
                        potential_impact: Some(
                            "Attempted command injection or binary corruption".to_string(),
                        ),
                        analysis_completeness: AnalysisCompleteness::Complete,
                        analysis_details: None,
                    },
                    analysis_completeness: AnalysisCompleteness::Complete,
                    audit_sequence: None,
                    audit_record_hash: None,
                    reason: "Command contains illegal null byte".to_string(),
                    allow_dispatch: false,
                };
                return JsonRpcResponse::success(id, serde_json::to_value(res).unwrap());
            }

            // 2. Secret Redaction
            let sanitized = crate::analysis::redact_command(raw_cmd);

            // 3. Deterministic Policy Evaluation
            let assessment = state
                .policy
                .analyze_command_string(&sanitized, eval_params.working_directory.as_deref());

            let (decision, outcome, allow_dispatch) = match assessment.recommended_action.as_str() {
                "ALLOW_AND_MONITOR" => (GateDecision::Allow, ExecutionOutcome::Dispatched, true),
                "ALERT_AND_CONFIRM" => (
                    GateDecision::RequireApproval,
                    ExecutionOutcome::PendingApproval,
                    false,
                ),
                "BLOCK_AND_ALERT" => (
                    GateDecision::Block,
                    ExecutionOutcome::BlockedByPolicy,
                    false,
                ),
                _ => (
                    GateDecision::Block,
                    ExecutionOutcome::BlockedByPolicy,
                    false,
                ),
            };

            // If command is blocked or pending approval, record it immediately in the audit chain
            let (audit_seq, audit_hash) = if !allow_dispatch {
                let action = format!("GATE_{:?}", outcome);
                let rationale = format!(
                    "Rule: {}, Reason: {}",
                    assessment.rule_id, assessment.reason
                );
                if let Ok(rec) = state.audit.append(
                    &format!("gate-{}", uuid::Uuid::new_v4()),
                    &action,
                    &rationale,
                    assessment.severity,
                ) {
                    (Some(rec.sequence_number), Some(rec.current_record_hash))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            let res = GateEvaluateResult {
                decision,
                outcome,
                risk_assessment: assessment.clone(),
                analysis_completeness: assessment.analysis_completeness,
                audit_sequence: audit_seq,
                audit_record_hash: audit_hash,
                reason: assessment.reason.clone(),
                allow_dispatch,
            };
            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
        }

        "gate.record_outcome" => {
            let params = match req.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Missing params for gate.record_outcome".to_string(),
                        None,
                    )
                }
            };

            let record_params: GateRecordOutcomeParams = match serde_json::from_value(params) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Invalid gate.record_outcome params format".to_string(),
                        Some(e.to_string()),
                    )
                }
            };

            let sanitized = crate::analysis::redact_command(&record_params.command);
            let action = format!("GATE_{:?}", record_params.outcome);
            let rationale = format!(
                "Command: {}, Decision: {:?}, ExitCode: {:?}, Detail: {}",
                sanitized,
                record_params.decision,
                record_params.exit_code,
                record_params
                    .error_message
                    .unwrap_or_else(|| "none".to_string())
            );

            let severity = match record_params.outcome {
                ExecutionOutcome::BlockedByPolicy => Severity::Critical,
                ExecutionOutcome::PendingApproval => Severity::High,
                ExecutionOutcome::FailedClosed => Severity::High,
                ExecutionOutcome::ExecutionFailed => Severity::Medium,
                ExecutionOutcome::Dispatched => Severity::Low,
            };

            match state.audit.append(
                &format!("gate-{}", uuid::Uuid::new_v4()),
                &action,
                &rationale,
                severity,
            ) {
                Ok(rec) => {
                    let res = GateRecordOutcomeResult {
                        recorded: true,
                        audit_sequence: rec.sequence_number,
                        audit_record_hash: rec.current_record_hash,
                    };
                    JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
                }
                Err(e) => JsonRpcResponse::error(
                    id,
                    -32002,
                    "Failed to append gate outcome to audit log".to_string(),
                    Some(e.to_string()),
                ),
            }
        }

        "event.submit" => {
            let params = match req.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Missing params for event.submit".to_string(),
                        None,
                    )
                }
            };

            let submit_params: EventSubmitParams = match serde_json::from_value(params) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Invalid event payload format".to_string(),
                        Some(e.to_string()),
                    )
                }
            };

            let mut event = submit_params.event;

            // 1. Schema Validation
            if let Err(err_msg) = event.validate() {
                return JsonRpcResponse::error(
                    id,
                    -32602,
                    "Event schema validation failed".to_string(),
                    Some(err_msg),
                );
            }

            // 2. Secret Redaction Boundary
            state.policy.redact_event(&mut event);

            // 3. Deterministic Policy Evaluation
            let assessment = state.policy.evaluate(&event);

            // 4. Append to Cryptographic Audit Log
            let audit_record = match state.audit.append(
                &event.id,
                &assessment.recommended_action,
                &assessment.reason,
                assessment.severity,
            ) {
                Ok(rec) => rec,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        -32002,
                        "Failed to append to cryptographic audit log".to_string(),
                        Some(e.to_string()),
                    )
                }
            };

            state.events_processed.fetch_add(1, Ordering::SeqCst);

            let evaluated_record = EvaluatedEventRecord {
                event: event.clone(),
                assessment: assessment.clone(),
                audit_sequence: audit_record.sequence_number,
                audit_hash: audit_record.current_record_hash.clone(),
            };

            // Store in in-memory recent ring buffer
            {
                let mut recent = state.recent_events.lock().unwrap();
                if recent.len() >= 100 {
                    recent.pop_front();
                }
                recent.push_back(evaluated_record);
            }

            let res = EventSubmitResult {
                event_id: event.id,
                risk_assessment: assessment,
                audit_sequence: audit_record.sequence_number,
                audit_record_hash: audit_record.current_record_hash,
                recorded: true,
            };

            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
        }

        "event.get_recent" => {
            let limit = req
                .params
                .and_then(|p| serde_json::from_value::<RecentEventsParams>(p).ok())
                .map(|p| p.limit)
                .unwrap_or(50);

            let recent = state.recent_events.lock().unwrap();
            let events_vec: Vec<EvaluatedEventRecord> =
                recent.iter().rev().take(limit).cloned().collect();

            let res = RecentEventsResult { events: events_vec };
            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
        }

        "event.get_details" => {
            let event_id = match req
                .params
                .and_then(|p| serde_json::from_value::<EventDetailsParams>(p).ok())
            {
                Some(p) => p.event_id,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Missing event_id in params".to_string(),
                        None,
                    )
                }
            };

            let recent = state.recent_events.lock().unwrap();
            let found = recent.iter().find(|r| r.event.id == event_id).cloned();

            match found {
                Some(record) => JsonRpcResponse::success(id, serde_json::to_value(record).unwrap()),
                None => JsonRpcResponse::error(
                    id,
                    -32602,
                    format!("Event not found in recent history: {}", event_id),
                    None,
                ),
            }
        }

        "audit.verify" => {
            let verify_res = state.audit.verify();
            JsonRpcResponse::success(id, serde_json::to_value(verify_res).unwrap())
        }

        "engine.shutdown" => {
            state.shutdown_requested.store(true, Ordering::SeqCst);
            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "status": "shutting_down",
                    "message": "Engine received shutdown request"
                }),
            )
        }

        _ => JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", req.method),
            None,
        ),
    }
}
