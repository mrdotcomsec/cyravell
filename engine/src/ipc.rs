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
use crate::gate::approval::ApprovalManager;
use crate::gate::backend::{ExecutionBackend, OsExecutionBackend};
use crate::integrity::{verify_manifest, IntegrityStatus};
use crate::model::*;
use crate::package::{summarize_assessment, PackageSecurityAssessor};
use crate::policy::PolicyEngine;

pub struct EngineState {
    pub start_time: Instant,
    pub events_processed: AtomicU64,
    pub recent_events: Mutex<VecDeque<EvaluatedEventRecord>>,
    pub policy: PolicyEngine,
    pub audit: AuditLog,
    pub approval_manager: Arc<ApprovalManager>,
    pub package_assessor: Arc<PackageSecurityAssessor>,
    pub backend: Arc<dyn ExecutionBackend>,
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
        Self::with_approval_and_backend(
            socket_path,
            data_dir,
            manifest_path,
            base_dir,
            Arc::new(ApprovalManager::default()),
            Arc::new(OsExecutionBackend::new(None)),
        )
    }

    pub fn with_approval_and_backend<P: AsRef<Path>>(
        socket_path: P,
        data_dir: P,
        manifest_path: Option<PathBuf>,
        base_dir: PathBuf,
        approval_manager: Arc<ApprovalManager>,
        backend: Arc<dyn ExecutionBackend>,
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
            approval_manager,
            package_assessor: Arc::new(PackageSecurityAssessor::default()),
            backend,
            manifest_path,
            base_dir,
            shutdown_requested: AtomicBool::new(false),
        });

        Ok(Self { socket_path, state })
    }

    pub fn state(&self) -> &Arc<EngineState> {
        &self.state
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
                    request_id: None,
                    session_id: eval_params.session_id.clone(),
                    audit_sequence: None,
                    audit_record_hash: None,
                    reason: "Empty command string".to_string(),
                    allow_dispatch: false,
                    package_assessment: None,
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
                    request_id: None,
                    session_id: eval_params.session_id.clone(),
                    audit_sequence: None,
                    audit_record_hash: None,
                    reason: "Command contains illegal null byte".to_string(),
                    allow_dispatch: false,
                    package_assessment: None,
                };
                return JsonRpcResponse::success(id, serde_json::to_value(res).unwrap());
            }

            // 2. Secret Redaction
            let sanitized = crate::analysis::redact_command(raw_cmd);

            // 2.5. Package Security Assessment
            let working_path = eval_params
                .working_directory
                .as_deref()
                .map(Path::new)
                .unwrap_or_else(|| Path::new("."));

            let mut attached_package_assessment = None;
            if state.package_assessor.config().enabled {
                if let Some(pkg_res) = state
                    .package_assessor
                    .assess_command_string(&sanitized, working_path)
                {
                    match pkg_res.status {
                        AssessmentStatus::MaliciousPackageFound => {
                            let names: Vec<String> = pkg_res
                                .findings
                                .iter()
                                .filter(|f| f.is_malicious)
                                .map(|f| f.package_name.clone())
                                .collect();
                            let rule_ids: Vec<String> = pkg_res
                                .findings
                                .iter()
                                .filter(|f| f.is_malicious)
                                .map(|f| f.advisory_id.clone())
                                .collect();
                            let evidence: Vec<String> = pkg_res
                                .findings
                                .iter()
                                .filter(|f| f.is_malicious)
                                .map(|f| format!("{}: {}", f.package_name, f.title))
                                .collect();

                            let risk = RiskAssessment {
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                rule_id: "RULE-PACKAGE-MALICIOUS".to_string(),
                                reason: format!(
                                    "Blocked: Known malicious package(s) detected: {}",
                                    names.join(", ")
                                ),
                                evidence,
                                recommended_action: "BLOCK_AND_ALERT".to_string(),
                                evaluated_at: chrono::Utc::now(),
                                matched_rules: if rule_ids.is_empty() {
                                    vec!["RULE-PACKAGE-MALICIOUS".to_string()]
                                } else {
                                    rule_ids
                                },
                                potential_impact: Some(
                                    "Supply chain malware execution or credential theft"
                                        .to_string(),
                                ),
                                analysis_completeness: AnalysisCompleteness::Complete,
                                analysis_details: None,
                            };

                            let (seq, hash) = match state.audit.append(
                                &format!("gate-{}", uuid::Uuid::new_v4()),
                                "GATE_BlockedByPolicy",
                                &format!(
                                    "Command: {}, Package: Malicious package(s) {}",
                                    sanitized,
                                    names.join(", ")
                                ),
                                Severity::Critical,
                            ) {
                                Ok(rec) => {
                                    (Some(rec.sequence_number), Some(rec.current_record_hash))
                                }
                                Err(_) => (None, None),
                            };

                            let res = GateEvaluateResult {
                                decision: GateDecision::Block,
                                outcome: ExecutionOutcome::BlockedByPolicy,
                                risk_assessment: risk,
                                analysis_completeness: AnalysisCompleteness::Complete,
                                request_id: None,
                                session_id: eval_params.session_id.clone(),
                                audit_sequence: seq,
                                audit_record_hash: hash,
                                reason: format!(
                                    "Blocked by package security enforcement: known malicious package(s) {}",
                                    names.join(", ")
                                ),
                                allow_dispatch: false,
                                package_assessment: Some(pkg_res),
                            };
                            return JsonRpcResponse::success(
                                id,
                                serde_json::to_value(res).unwrap(),
                            );
                        }

                        AssessmentStatus::VulnerabilitiesFound => {
                            let has_critical = pkg_res
                                .findings
                                .iter()
                                .any(|f| f.severity == Severity::Critical);
                            if has_critical
                                && state.package_assessor.config().hard_block_critical_vulns
                            {
                                let risk = RiskAssessment {
                                    severity: Severity::Critical,
                                    confidence: Confidence::High,
                                    rule_id: "RULE-PACKAGE-CRITICAL-VULN-BLOCKED".to_string(),
                                    reason: format!(
                                        "Blocked: Critical package vulnerability detected under hard-block policy ({} findings)",
                                        pkg_res.findings.len()
                                    ),
                                    evidence: pkg_res
                                        .findings
                                        .iter()
                                        .map(|f| format!("{}: {}", f.package_name, f.title))
                                        .collect(),
                                    recommended_action: "BLOCK_AND_ALERT".to_string(),
                                    evaluated_at: chrono::Utc::now(),
                                    matched_rules: pkg_res
                                        .findings
                                        .iter()
                                        .map(|f| f.advisory_id.clone())
                                        .collect(),
                                    potential_impact: Some("Vulnerable package exploitation".to_string()),
                                    analysis_completeness: AnalysisCompleteness::Complete,
                                    analysis_details: None,
                                };

                                let (seq, hash) = match state.audit.append(
                                    &format!("gate-{}", uuid::Uuid::new_v4()),
                                    "GATE_BlockedByPolicy",
                                    &format!(
                                        "Command: {}, Critical vulnerabilities detected",
                                        sanitized
                                    ),
                                    Severity::Critical,
                                ) {
                                    Ok(rec) => {
                                        (Some(rec.sequence_number), Some(rec.current_record_hash))
                                    }
                                    Err(_) => (None, None),
                                };

                                let res = GateEvaluateResult {
                                    decision: GateDecision::Block,
                                    outcome: ExecutionOutcome::BlockedByPolicy,
                                    risk_assessment: risk,
                                    analysis_completeness: AnalysisCompleteness::Complete,
                                    request_id: None,
                                    session_id: eval_params.session_id.clone(),
                                    audit_sequence: seq,
                                    audit_record_hash: hash,
                                    reason: "Blocked: Critical package vulnerability detected"
                                        .to_string(),
                                    allow_dispatch: false,
                                    package_assessment: Some(pkg_res),
                                };
                                return JsonRpcResponse::success(
                                    id,
                                    serde_json::to_value(res).unwrap(),
                                );
                            } else {
                                let max_sev = pkg_res
                                    .findings
                                    .iter()
                                    .map(|f| f.severity)
                                    .max()
                                    .unwrap_or(Severity::High);
                                let s_id = eval_params
                                    .session_id
                                    .clone()
                                    .unwrap_or_else(|| "default-session".to_string());
                                let summary = summarize_assessment(&pkg_res);
                                let appr_req =
                                    state.approval_manager.create_request_with_package_details(
                                        s_id.clone(),
                                        raw_cmd.to_string(),
                                        eval_params.working_directory.clone(),
                                        "RULE-PACKAGE-VULNERABILITY".to_string(),
                                        max_sev,
                                        format!(
                                            "Package review required: {} vulnerability finding(s)",
                                            pkg_res.findings.len()
                                        ),
                                        None,
                                        Some(summary),
                                        pkg_res.manifest_fingerprint.clone(),
                                    );

                                let (seq, hash) = match state.audit.append(
                                    &format!("gate-{}", uuid::Uuid::new_v4()),
                                    "GATE_PendingApproval",
                                    &format!(
                                        "Command: {}, Package vulnerabilities requiring approval",
                                        sanitized
                                    ),
                                    max_sev,
                                ) {
                                    Ok(rec) => {
                                        (Some(rec.sequence_number), Some(rec.current_record_hash))
                                    }
                                    Err(_) => (None, None),
                                };

                                let risk = RiskAssessment {
                                    severity: max_sev,
                                    confidence: Confidence::High,
                                    rule_id: "RULE-PACKAGE-VULNERABILITY".to_string(),
                                    reason: format!(
                                        "Known package vulnerabilities detected ({} findings)",
                                        pkg_res.findings.len()
                                    ),
                                    evidence: pkg_res
                                        .findings
                                        .iter()
                                        .map(|f| format!("{}: {}", f.package_name, f.title))
                                        .collect(),
                                    recommended_action: "ALERT_AND_CONFIRM".to_string(),
                                    evaluated_at: chrono::Utc::now(),
                                    matched_rules: pkg_res
                                        .findings
                                        .iter()
                                        .map(|f| f.advisory_id.clone())
                                        .collect(),
                                    potential_impact: Some(
                                        "Security exposure from vulnerable package versions"
                                            .to_string(),
                                    ),
                                    analysis_completeness: AnalysisCompleteness::Complete,
                                    analysis_details: None,
                                };

                                let res = GateEvaluateResult {
                                    decision: GateDecision::RequireApproval,
                                    outcome: ExecutionOutcome::PendingApproval,
                                    risk_assessment: risk,
                                    analysis_completeness: AnalysisCompleteness::Complete,
                                    request_id: Some(appr_req.request_id),
                                    session_id: Some(s_id),
                                    audit_sequence: seq,
                                    audit_record_hash: hash,
                                    reason: format!(
                                        "Approval required: Package security findings detected ({} findings)",
                                        pkg_res.findings.len()
                                    ),
                                    allow_dispatch: false,
                                    package_assessment: Some(pkg_res),
                                };
                                return JsonRpcResponse::success(
                                    id,
                                    serde_json::to_value(res).unwrap(),
                                );
                            }
                        }

                        AssessmentStatus::IntegrityMismatch
                        | AssessmentStatus::ManifestMismatch => {
                            let is_integ = pkg_res.status == AssessmentStatus::IntegrityMismatch;
                            let rule_id = if is_integ {
                                "RULE-PACKAGE-INTEGRITY-MISMATCH".to_string()
                            } else {
                                "RULE-PACKAGE-MANIFEST-MISMATCH".to_string()
                            };
                            let reason_str = if is_integ {
                                "Package lockfile integrity format mismatch or invalid checksum"
                                    .to_string()
                            } else {
                                "Mismatch detected between project manifest and lockfile dependencies".to_string()
                            };

                            let s_id = eval_params
                                .session_id
                                .clone()
                                .unwrap_or_else(|| "default-session".to_string());
                            let summary = summarize_assessment(&pkg_res);
                            let appr_req =
                                state.approval_manager.create_request_with_package_details(
                                    s_id.clone(),
                                    raw_cmd.to_string(),
                                    eval_params.working_directory.clone(),
                                    rule_id.clone(),
                                    Severity::High,
                                    reason_str.clone(),
                                    None,
                                    Some(summary),
                                    pkg_res.manifest_fingerprint.clone(),
                                );

                            let (seq, hash) = match state.audit.append(
                                &format!("gate-{}", uuid::Uuid::new_v4()),
                                "GATE_PendingApproval",
                                &format!("Command: {}, {}", sanitized, reason_str),
                                Severity::High,
                            ) {
                                Ok(rec) => {
                                    (Some(rec.sequence_number), Some(rec.current_record_hash))
                                }
                                Err(_) => (None, None),
                            };

                            let risk = RiskAssessment {
                                severity: Severity::High,
                                confidence: Confidence::High,
                                rule_id: rule_id.clone(),
                                reason: reason_str.clone(),
                                evidence: pkg_res.notes.clone(),
                                recommended_action: "ALERT_AND_CONFIRM".to_string(),
                                evaluated_at: chrono::Utc::now(),
                                matched_rules: vec![rule_id],
                                potential_impact: Some(
                                    "Tampered lockfile or unpinned dependency alteration"
                                        .to_string(),
                                ),
                                analysis_completeness: AnalysisCompleteness::Complete,
                                analysis_details: None,
                            };

                            let res = GateEvaluateResult {
                                decision: GateDecision::RequireApproval,
                                outcome: ExecutionOutcome::PendingApproval,
                                risk_assessment: risk,
                                analysis_completeness: AnalysisCompleteness::Complete,
                                request_id: Some(appr_req.request_id),
                                session_id: Some(s_id),
                                audit_sequence: seq,
                                audit_record_hash: hash,
                                reason: reason_str,
                                allow_dispatch: false,
                                package_assessment: Some(pkg_res),
                            };
                            return JsonRpcResponse::success(
                                id,
                                serde_json::to_value(res).unwrap(),
                            );
                        }

                        AssessmentStatus::AssessmentFailed => {
                            let s_id = eval_params
                                .session_id
                                .clone()
                                .unwrap_or_else(|| "default-session".to_string());
                            let summary = summarize_assessment(&pkg_res);
                            let appr_req =
                                state.approval_manager.create_request_with_package_details(
                                    s_id.clone(),
                                    raw_cmd.to_string(),
                                    eval_params.working_directory.clone(),
                                    "RULE-PACKAGE-PARSE-FAILED".to_string(),
                                    Severity::High,
                                    "Package manifest or lockfile parsing failed; review required"
                                        .to_string(),
                                    None,
                                    Some(summary),
                                    pkg_res.manifest_fingerprint.clone(),
                                );

                            let (seq, hash) = match state.audit.append(
                                &format!("gate-{}", uuid::Uuid::new_v4()),
                                "GATE_PendingApproval",
                                &format!("Command: {}, Manifest parsing failed", sanitized),
                                Severity::High,
                            ) {
                                Ok(rec) => {
                                    (Some(rec.sequence_number), Some(rec.current_record_hash))
                                }
                                Err(_) => (None, None),
                            };

                            let risk = RiskAssessment {
                                severity: Severity::High,
                                confidence: Confidence::High,
                                rule_id: "RULE-PACKAGE-PARSE-FAILED".to_string(),
                                reason:
                                    "Package manifest inspection failed under fail-closed policy"
                                        .to_string(),
                                evidence: pkg_res.notes.clone(),
                                recommended_action: "ALERT_AND_CONFIRM".to_string(),
                                evaluated_at: chrono::Utc::now(),
                                matched_rules: vec!["RULE-PACKAGE-PARSE-FAILED".to_string()],
                                potential_impact: Some(
                                    "Uninspected malformed manifest execution".to_string(),
                                ),
                                analysis_completeness: AnalysisCompleteness::Inconclusive,
                                analysis_details: None,
                            };

                            let res = GateEvaluateResult {
                                decision: GateDecision::RequireApproval,
                                outcome: ExecutionOutcome::PendingApproval,
                                risk_assessment: risk,
                                analysis_completeness: AnalysisCompleteness::Inconclusive,
                                request_id: Some(appr_req.request_id),
                                session_id: Some(s_id),
                                audit_sequence: seq,
                                audit_record_hash: hash,
                                reason: "Package manifest parsing failed under fail-closed policy"
                                    .to_string(),
                                allow_dispatch: false,
                                package_assessment: Some(pkg_res),
                            };
                            return JsonRpcResponse::success(
                                id,
                                serde_json::to_value(res).unwrap(),
                            );
                        }

                        AssessmentStatus::CleanNoMatches
                        | AssessmentStatus::InsufficientData
                        | AssessmentStatus::UnsupportedEcosystem => {
                            attached_package_assessment = Some(pkg_res);
                        }
                    }
                }
            }

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

            // If RequireApproval, register with ApprovalManager
            let (req_id, sess_id) = if decision == GateDecision::RequireApproval {
                let s_id = eval_params
                    .session_id
                    .clone()
                    .unwrap_or_else(|| "default-session".to_string());
                let appr_req = state.approval_manager.create_request(
                    s_id.clone(),
                    raw_cmd.to_string(),
                    eval_params.working_directory.clone(),
                    assessment.rule_id.clone(),
                    assessment.severity,
                    assessment.reason.clone(),
                    None,
                );
                (Some(appr_req.request_id), Some(s_id))
            } else {
                (None, eval_params.session_id.clone())
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
                request_id: req_id,
                session_id: sess_id,
                audit_sequence: audit_seq,
                audit_record_hash: audit_hash,
                reason: assessment.reason.clone(),
                allow_dispatch,
                package_assessment: attached_package_assessment,
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
                ExecutionOutcome::DeniedByUser => Severity::Medium,
                ExecutionOutcome::CancelledByUser => Severity::Low,
                ExecutionOutcome::ExpiredApproval => Severity::Low,
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

        "approval.decide" => {
            let params = match req.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Missing params for approval.decide".to_string(),
                        None,
                    )
                }
            };

            let decide_params: ApprovalDecideParams = match serde_json::from_value(params) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Invalid approval.decide params format".to_string(),
                        Some(e.to_string()),
                    )
                }
            };

            match state.approval_manager.decide(
                &decide_params.request_id,
                decide_params.decision,
                decide_params.reason.clone(),
            ) {
                Ok((status, token)) => {
                    let action = match status {
                        ApprovalStatus::Approved => "APPROVAL_GRANTED",
                        ApprovalStatus::Denied => "APPROVAL_DENIED",
                        ApprovalStatus::Cancelled => "APPROVAL_CANCELLED",
                        _ => "APPROVAL_DECIDED",
                    };
                    let rationale = format!(
                        "Request: {}, Decision: {:?}, Reason: {:?}",
                        decide_params.request_id, decide_params.decision, decide_params.reason
                    );
                    let seq = match state.audit.append(
                        &format!("approval-{}", uuid::Uuid::new_v4()),
                        action,
                        &rationale,
                        Severity::Medium,
                    ) {
                        Ok(rec) => Some(rec.sequence_number),
                        Err(_) => None,
                    };

                    let res = ApprovalDecideResult {
                        request_id: decide_params.request_id,
                        status,
                        authorization_token: token,
                        audit_sequence: seq,
                        message: format!(
                            "Decision {:?} recorded successfully",
                            decide_params.decision
                        ),
                    };
                    JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
                }
                Err(e) => JsonRpcResponse::error(
                    id,
                    -32003,
                    format!("Approval decision failed: {}", e),
                    None,
                ),
            }
        }

        "approval.get_pending" => {
            let session_id = if let Some(params) = req.params {
                let p: Result<ApprovalGetPendingParams, _> = serde_json::from_value(params);
                p.ok().and_then(|val| val.session_id)
            } else {
                None
            };

            let requests = state.approval_manager.get_pending(session_id.as_deref());
            let res = ApprovalGetPendingResult {
                pending_requests: requests,
            };
            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
        }

        "gate.dispatch_authorized" => {
            let params = match req.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Missing params for gate.dispatch_authorized".to_string(),
                        None,
                    )
                }
            };

            let dispatch_params: GateDispatchAuthorizedParams = match serde_json::from_value(params)
            {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        "Invalid gate.dispatch_authorized params format".to_string(),
                        Some(e.to_string()),
                    )
                }
            };

            // Input and boundary validation
            if dispatch_params.command.trim().is_empty() {
                return JsonRpcResponse::error(
                    id,
                    -32602,
                    "Command cannot be empty".to_string(),
                    None,
                );
            }
            if dispatch_params.command.contains('\0') {
                return JsonRpcResponse::error(
                    id,
                    -32602,
                    "Command cannot contain null bytes".to_string(),
                    None,
                );
            }
            if dispatch_params.command.len() > 65536 {
                return JsonRpcResponse::error(
                    id,
                    -32602,
                    "Command exceeds 64KB limit".to_string(),
                    None,
                );
            }
            if dispatch_params.request_id.contains('\0')
                || dispatch_params.session_id.contains('\0')
                || dispatch_params.authorization_token.contains('\0')
            {
                return JsonRpcResponse::error(
                    id,
                    -32602,
                    "Identifiers cannot contain null bytes".to_string(),
                    None,
                );
            }

            // Atomically validate and consume authorization token
            let approved_req = match state.approval_manager.consume_authorization(
                &dispatch_params.request_id,
                &dispatch_params.session_id,
                &dispatch_params.command,
                &dispatch_params.authorization_token,
            ) {
                Ok(r) => r,
                Err(e) => {
                    let sanitized = crate::analysis::redact_command(&dispatch_params.command);
                    let _ = state.audit.append(
                        &format!("gate-unauth-{}", uuid::Uuid::new_v4()),
                        "GATE_UNAUTHORIZED_DISPATCH_ATTEMPT",
                        &format!(
                            "Request: {}, Error: {}, Command: {}",
                            dispatch_params.request_id, e, sanitized
                        ),
                        Severity::High,
                    );
                    return JsonRpcResponse::error(
                        id,
                        -32001,
                        format!("Authorization rejected: {}", e),
                        None,
                    );
                }
            };

            // Hard-block re-evaluation guard
            let working_path = dispatch_params.working_directory.as_deref().map(Path::new);
            let sanitized = crate::analysis::redact_command(&dispatch_params.command);
            let assessment = state
                .policy
                .analyze_command_string(&sanitized, dispatch_params.working_directory.as_deref());
            if assessment.recommended_action == "BLOCK_AND_ALERT" {
                let _ = state.audit.append(
                    &format!("gate-hardblock-{}", uuid::Uuid::new_v4()),
                    "GATE_HARD_BLOCK_ENFORCED_AFTER_APPROVAL",
                    &format!(
                        "Request: {}, Command: {}, Reason: Hard-block policy cannot be bypassed",
                        dispatch_params.request_id, sanitized
                    ),
                    Severity::Critical,
                );
                return JsonRpcResponse::error(
                    id,
                    -32004,
                    "Policy violation: Command matches hard-block policy and cannot be dispatched"
                        .to_string(),
                    None,
                );
            }

            // TOCTOU Manifest Fingerprint Verification
            if let Some(ref orig_fp) = approved_req.manifest_fingerprint {
                let working_dir = working_path.unwrap_or_else(|| Path::new("."));
                if let Some(current_pkg) = state
                    .package_assessor
                    .assess_command_string(&sanitized, working_dir)
                {
                    if let Some(ref current_fp) = current_pkg.manifest_fingerprint {
                        if current_fp != orig_fp {
                            let _ = state.audit.append(
                                &format!("gate-toctou-{}", uuid::Uuid::new_v4()),
                                "GATE_TOCTOU_FINGERPRINT_MISMATCH",
                                &format!(
                                    "Request: {}, Manifest/lockfile changed after approval: expected {}, found {}",
                                    dispatch_params.request_id, orig_fp, current_fp
                                ),
                                Severity::Critical,
                            );
                            return JsonRpcResponse::error(
                                id,
                                -32005,
                                "Project manifest or lockfile modified after approval (TOCTOU violation)".to_string(),
                                None,
                            );
                        }
                    }
                }
            }

            // Dispatch to backend
            let (dispatched, exit_code, outcome, error_msg) = match state
                .backend
                .execute(&dispatch_params.command, working_path)
            {
                Ok(code) => (true, Some(code), ExecutionOutcome::Dispatched, None),
                Err(e) => (
                    false,
                    Some(127),
                    ExecutionOutcome::ExecutionFailed,
                    Some(e.to_string()),
                ),
            };

            // Record outcome in cryptographic audit log
            let action = if dispatched {
                "GATE_DISPATCHED_AFTER_APPROVAL"
            } else {
                "GATE_DISPATCH_FAILED_AFTER_APPROVAL"
            };
            let detail = format!(
                "Request: {}, Session: {}, ExitCode: {:?}, Detail: {}",
                dispatch_params.request_id,
                dispatch_params.session_id,
                exit_code,
                error_msg.as_deref().unwrap_or("none")
            );
            let (seq, hash) = match state.audit.append(
                &format!("gate-auth-{}", uuid::Uuid::new_v4()),
                action,
                &format!("Command: {}, {}", sanitized, detail),
                approved_req.severity,
            ) {
                Ok(rec) => (rec.sequence_number, rec.current_record_hash),
                Err(_) => (0, "UNRECORDED".to_string()),
            };

            let res = GateDispatchAuthorizedResult {
                request_id: dispatch_params.request_id,
                dispatched,
                exit_code,
                outcome,
                audit_sequence: seq,
                audit_record_hash: hash,
                message: if dispatched {
                    "Command dispatched after verified authorization".to_string()
                } else {
                    format!("Dispatch failed: {}", error_msg.unwrap_or_default())
                },
            };
            JsonRpcResponse::success(id, serde_json::to_value(res).unwrap())
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
