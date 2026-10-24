// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Current schema version supported by Phase 1.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Maximum payload size permitted for IPC frames (1 MiB).
pub const MAX_FRAME_SIZE_BYTES: usize = 1024 * 1024;

/// Genesis hash for the initial link in the audit chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    TerminalCommand,
    FileModification,
    DependencyInstall,
    CredentialAccess,
    SecurityPolicyChange,
    IntegrityCheck,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Origin {
    Simulated,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    Simulated,
    Observed,
    PendingApproval,
    Intercepted,
    BlockedConfirmed,
    AlreadyExecuted,
    NotInterceptable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionOutcome {
    Dispatched,
    BlockedByPolicy,
    PendingApproval,
    DeniedByUser,
    CancelledByUser,
    ExpiredApproval,
    FailedClosed,
    ExecutionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateDecision {
    Allow,
    RequireApproval,
    Block,
    AnalysisFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Consumed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalUserDecision {
    Approve,
    Deny,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementCapability {
    None,
    PreExecBlock,
    PostExecAlert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnalysisCompleteness {
    Complete,
    Partial,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAnalysisDetails {
    pub raw_command: String,
    pub sanitized_command: String,
    pub atomic_commands_count: usize,
    pub operators_detected: Vec<String>,
    pub command_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub potential_impact: Option<String>,
    pub analysis_notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPayload {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub target_paths: Vec<String>,
    #[serde(default)]
    pub environment_keys: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub schema_version: u32,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub source_adapter: String,
    pub origin: Origin,
    pub execution_status: ExecutionStatus,
    pub enforcement_capability: EnforcementCapability,
    pub payload: EventPayload,
}

impl SecurityEvent {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported schema_version: {}. Engine supports version {}",
                self.schema_version, CURRENT_SCHEMA_VERSION
            ));
        }
        if self.id.trim().is_empty() {
            return Err("Event id cannot be empty".to_string());
        }
        if self.source_adapter.trim().is_empty() {
            return Err("source_adapter cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub severity: Severity,
    pub confidence: Confidence,
    pub rule_id: String,
    pub reason: String,
    pub evidence: Vec<String>,
    pub recommended_action: String,
    pub evaluated_at: DateTime<Utc>,
    #[serde(default)]
    pub matched_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub potential_impact: Option<String>,
    #[serde(default = "default_completeness")]
    pub analysis_completeness: AnalysisCompleteness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_details: Option<CommandAnalysisDetails>,
}

fn default_completeness() -> AnalysisCompleteness {
    AnalysisCompleteness::Complete
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence_number: u64,
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
    pub action_recorded: String,
    pub decision_rationale: String,
    pub risk_severity: Severity,
    pub previous_record_hash: String,
    pub current_record_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatedEventRecord {
    pub event: SecurityEvent,
    pub assessment: RiskAssessment,
    pub audit_sequence: u64,
    pub audit_hash: String,
}

// -----------------------------------------------------------------------------
// JSON-RPC Envelopes & Protocol Messages
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(
        id: serde_json::Value,
        code: i32,
        message: String,
        details: Option<String>,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                details,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeParams {
    pub client_name: String,
    pub client_version: String,
    pub protocol_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResult {
    pub status: String,
    pub engine_name: String,
    pub engine_version: String,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResult {
    pub status: String,
    pub uptime_seconds: u64,
    pub events_processed: u64,
    pub audit_records_count: u64,
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityResult {
    pub status: String,
    pub manifest_version: String,
    pub verified_files_count: usize,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubmitParams {
    pub event: SecurityEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubmitResult {
    pub event_id: String,
    pub risk_assessment: RiskAssessment,
    pub audit_sequence: u64,
    pub audit_record_hash: String,
    pub recorded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEventsParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEventsResult {
    pub events: Vec<EvaluatedEventRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDetailsParams {
    pub event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerifyResult {
    pub status: String,
    pub total_records: u64,
    pub genesis_hash: String,
    pub latest_hash: String,
    pub corrupted_sequence: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAnalyzeParams {
    pub command: String,
    #[serde(default)]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAnalyzeResult {
    pub risk_assessment: RiskAssessment,
    pub analysis_completeness: AnalysisCompleteness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateEvaluateParams {
    pub command: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default = "default_fail_closed")]
    pub fail_closed: bool,
}

fn default_fail_closed() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateEvaluateResult {
    pub decision: GateDecision,
    pub outcome: ExecutionOutcome,
    pub risk_assessment: RiskAssessment,
    pub analysis_completeness: AnalysisCompleteness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_record_hash: Option<String>,
    pub reason: String,
    pub allow_dispatch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRecordOutcomeParams {
    pub command: String,
    pub decision: GateDecision,
    pub outcome: ExecutionOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRecordOutcomeResult {
    pub recorded: bool,
    pub audit_sequence: u64,
    pub audit_record_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub session_id: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    pub rule_id: String,
    pub severity: Severity,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecideParams {
    pub request_id: String,
    pub decision: ApprovalUserDecision,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecideResult {
    pub request_id: String,
    pub status: ApprovalStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_token: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_sequence: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalGetPendingParams {
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalGetPendingResult {
    pub pending_requests: Vec<ApprovalRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDispatchAuthorizedParams {
    pub request_id: String,
    pub session_id: String,
    pub command: String,
    pub authorization_token: String,
    #[serde(default)]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDispatchAuthorizedResult {
    pub request_id: String,
    pub dispatched: bool,
    pub exit_code: Option<i32>,
    pub outcome: ExecutionOutcome,
    pub audit_sequence: u64,
    pub audit_record_hash: String,
    pub message: String,
}
