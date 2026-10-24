// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::audit::AuditLog;
use crate::gate::{ApprovalError, ExecutionGate, MockExecutionBackend};
use crate::model::*;
use crate::PolicyEngine;
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_workspace_cargo_build_clean() {
    let assessor = PackageSecurityAssessor::default();
    let res = assessor.assess_command_string("cargo build --workspace", std::path::Path::new("."));
    assert!(res.is_some());
    assert_eq!(res.unwrap().status, AssessmentStatus::CleanNoMatches);
}

// ============================================================================
// Requirement 1: Package-manager detection and invocation variants
// ============================================================================
#[test]
fn test_req1_package_manager_detection_and_variants() {
    let assessor = PackageSecurityAssessor::default();
    let dir = tempdir().unwrap();

    // npm variants
    let res = assessor.assess_command_string("npm install lodash@4.17.20", dir.path());
    assert!(res.is_some());
    let r = res.unwrap();
    assert_eq!(r.package_manager, PackageEcosystem::Npm);
    assert_eq!(r.operation, PackageOperation::Add);

    let res = assessor.assess_command_string("npm i", dir.path()).unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Npm);
    assert_eq!(res.operation, PackageOperation::InstallAll);

    // pnpm
    let res = assessor
        .assess_command_string("pnpm add express", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Pnpm);
    assert_eq!(res.operation, PackageOperation::Add);

    // yarn
    let res = assessor
        .assess_command_string("yarn add react", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Yarn);
    assert_eq!(res.operation, PackageOperation::Add);

    // pip & pip3
    let res = assessor
        .assess_command_string("pip install flask", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Pip);
    assert_eq!(res.operation, PackageOperation::Add);

    let res = assessor
        .assess_command_string("pip3 install urllib3>=1.26.0", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Pip);

    // python -m pip
    let res = assessor
        .assess_command_string("python -m pip install requests==2.28.1", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Pip);

    let res = assessor
        .assess_command_string("python3 -m pip install -r requirements.txt", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Pip);
    assert_eq!(res.operation, PackageOperation::InstallAll);

    // npx
    let res = assessor
        .assess_command_string("npx eslint .", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Npm);
    assert_eq!(res.operation, PackageOperation::RunPackage);

    // cargo
    let res = assessor
        .assess_command_string("cargo add serde", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Cargo);
    assert_eq!(res.operation, PackageOperation::Add);

    let res = assessor
        .assess_command_string("cargo update", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Cargo);
    assert_eq!(res.operation, PackageOperation::Update);

    // wrappers: sudo, env
    let res = assessor
        .assess_command_string("sudo npm install", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Npm);

    let res = assessor
        .assess_command_string("env CI=true pip install requests", dir.path())
        .unwrap();
    assert_eq!(res.package_manager, PackageEcosystem::Pip);
}

// ============================================================================
// Requirement 2: Malformed manifests and lockfiles
// ============================================================================
#[test]
fn test_req2_malformed_manifests_fail_closed() {
    let dir = tempdir().unwrap();
    // Corrupted package.json
    fs::write(dir.path().join("package.json"), "{ invalid json: true, ").unwrap();

    let assessor = PackageSecurityAssessor::default();
    let res = assessor
        .assess_command_string("npm install", dir.path())
        .unwrap();
    assert_eq!(res.status, AssessmentStatus::AssessmentFailed);
    assert!(res.notes[0].contains("Failed to parse project manifest"));
}

// ============================================================================
// Requirement 3: Manifest-lockfile mismatch detection
// ============================================================================
#[test]
fn test_req3_manifest_lockfile_mismatch() {
    let dir = tempdir().unwrap();
    // package.json requests 'express'
    let pkg_json = r#"{
      "name": "test-proj",
      "dependencies": {
        "express": "^4.18.0"
      }
    }"#;
    fs::write(dir.path().join("package.json"), pkg_json).unwrap();

    // package-lock.json has NO 'express'
    let lock_json = r#"{
      "name": "test-proj",
      "lockfileVersion": 2,
      "packages": {}
    }"#;
    fs::write(dir.path().join("package-lock.json"), lock_json).unwrap();

    let assessor = PackageSecurityAssessor::default();
    let res = assessor
        .assess_command_string("npm install", dir.path())
        .unwrap();
    assert_eq!(res.status, AssessmentStatus::ManifestMismatch);
    assert!(res
        .notes
        .iter()
        .any(|n| n.contains("is missing from package-lock.json")));
}

// ============================================================================
// Requirement 4: Direct and transitive dependency resolution where supported
// ============================================================================
#[test]
fn test_req4_transitive_dependency_resolution() {
    let dir = tempdir().unwrap();
    // Project manifest declares a wrapper package
    let pkg_json = r#"{
      "name": "test-proj",
      "dependencies": {
        "my-wrapper": "1.0.0"
      }
    }"#;
    fs::write(dir.path().join("package.json"), pkg_json).unwrap();

    // Lockfile contains vulnerable transitive dependency 'lodash@4.17.20'
    let lock_json = r#"{
      "name": "test-proj",
      "lockfileVersion": 2,
      "packages": {
        "node_modules/my-wrapper": {
          "version": "1.0.0",
          "integrity": "sha512-validHash123=="
        },
        "node_modules/lodash": {
          "version": "4.17.20",
          "integrity": "sha512-validHash456=="
        }
      }
    }"#;
    fs::write(dir.path().join("package-lock.json"), lock_json).unwrap();

    let assessor = PackageSecurityAssessor::default();
    let res = assessor
        .assess_command_string("npm install", dir.path())
        .unwrap();
    assert_eq!(res.status, AssessmentStatus::VulnerabilitiesFound);
    assert!(res.findings.iter().any(|f| f.package_name == "lodash"));
}

// ============================================================================
// Requirement 5: Vulnerability matching at affected-version boundaries
// ============================================================================
#[test]
fn test_req5_vulnerability_version_boundary_matching() {
    let db = AdvisoryDatabase::load_embedded();

    // lodash: CVE-2021-23337 affected range: ">= 4.0.0, < 4.17.21"
    let match_affected = db.query(PackageEcosystem::Npm, "lodash", Some("4.17.20"));
    assert!(
        !match_affected.is_empty(),
        "4.17.20 must match affected range"
    );

    let match_fixed = db.query(PackageEcosystem::Npm, "lodash", Some("4.17.21"));
    assert!(
        match_fixed.is_empty(),
        "4.17.21 must NOT match affected range"
    );

    let match_outside = db.query(PackageEcosystem::Npm, "lodash", Some("3.10.1"));
    assert!(match_outside.is_empty(), "3.10.1 is below 4.0.0");
}

// ============================================================================
// Requirement 6: Known malicious-package indicators
// ============================================================================
#[test]
fn test_req6_known_malicious_package_indicators() {
    let dir = tempdir().unwrap();
    let assessor = PackageSecurityAssessor::default();

    // flatmap-stream is a confirmed malicious package
    let res = assessor
        .assess_command_string("npm install flatmap-stream@0.1.1", dir.path())
        .unwrap();
    assert_eq!(res.status, AssessmentStatus::MaliciousPackageFound);
    assert!(res.findings.iter().any(|f| f.is_malicious));

    // cross-env.js is a known malicious typosquat
    let res2 = assessor
        .assess_command_string("npm install cross-env.js", dir.path())
        .unwrap();
    assert_eq!(res2.status, AssessmentStatus::MaliciousPackageFound);
    assert!(res2.findings.iter().any(|f| f.is_malicious));

    // PyPI typosquat: reqeusts
    let res3 = assessor
        .assess_command_string("pip install reqeusts", dir.path())
        .unwrap();
    assert_eq!(res3.status, AssessmentStatus::MaliciousPackageFound);
}

// ============================================================================
// Requirement 7: Integrity mismatch handling
// ============================================================================
#[test]
fn test_req7_integrity_mismatch_detection() {
    let dir = tempdir().unwrap();
    let pkg_json = r#"{"name":"test","dependencies":{"express":"4.18.0"}}"#;
    fs::write(dir.path().join("package.json"), pkg_json).unwrap();

    // Invalid integrity format (not sha512-, sha256-, sha384-, or sha1-)
    let lock_json = r#"{
      "name": "test",
      "packages": {
        "node_modules/express": {
          "version": "4.18.0",
          "integrity": "corrupted_non_base64_integrity_string"
        }
      }
    }"#;
    fs::write(dir.path().join("package-lock.json"), lock_json).unwrap();

    let assessor = PackageSecurityAssessor::default();
    let res = assessor
        .assess_command_string("npm install", dir.path())
        .unwrap();
    assert_eq!(res.status, AssessmentStatus::IntegrityMismatch);
    assert!(res
        .notes
        .iter()
        .any(|n| n.contains("invalid integrity format")));
}

// ============================================================================
// Requirement 8: Unsupported ecosystems and insufficient data
// ============================================================================
#[test]
fn test_req8_unsupported_ecosystems_and_insufficient_data() {
    let dir = tempdir().unwrap();
    let assessor = PackageSecurityAssessor::default();

    // Unknown package manager command (e.g. brew or apt) returns None from package detector
    let res = assessor.assess_command_string("apt-get install nginx", dir.path());
    assert!(res.is_none());
}

// ============================================================================
// Requirement 9: Offline mode and embedded fallback
// ============================================================================
#[test]
fn test_req9_offline_mode_and_advisory_source() {
    let db = AdvisoryDatabase::load_embedded();
    assert!(db.is_offline());
    assert!(db.all_advisories().len() >= 10);
    assert_eq!(db.source_name(), "embedded:package_advisories.json");
}

// ============================================================================
// Requirement 10: Assessment failures and fail-closed policy
// ============================================================================
#[test]
fn test_req10_assessment_failure_fail_closed_gate() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("package.json"), "NOT VALID JSON").unwrap();

    let mock_backend = Arc::new(MockExecutionBackend::new());
    let gate = ExecutionGate::new(
        mock_backend.clone(),
        None,
        Some(PolicyEngine::new()),
        None,
        true, // fail-closed = true
    );

    let res = gate.execute_gated_with_session("npm install", None, Some(dir.path()));
    assert_eq!(res.decision, GateDecision::RequireApproval);
    assert_eq!(res.outcome, ExecutionOutcome::PendingApproval);
    mock_backend.assert_zero_invocations();
}

// ============================================================================
// Requirement 11: Hard-block enforcement with ZERO backend invocations
// ============================================================================
#[test]
fn test_req11_hard_block_malicious_zero_backend_invocations() {
    let dir = tempdir().unwrap();
    let mock_backend = Arc::new(MockExecutionBackend::new());
    let audit_path = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_path).unwrap());

    let gate = ExecutionGate::new(
        mock_backend.clone(),
        None,
        Some(PolicyEngine::new()),
        Some(audit),
        true,
    );

    // Attempt to install known malicious package
    let res = gate.execute_gated_with_session(
        "npm install flatmap-stream@0.1.1",
        Some("session-1"),
        Some(dir.path()),
    );

    assert_eq!(res.decision, GateDecision::Block);
    assert_eq!(res.outcome, ExecutionOutcome::BlockedByPolicy);
    // CRITICAL: Prove backend was NEVER invoked!
    mock_backend.assert_zero_invocations();

    // Verify non-overridable: Attempt to dispatch via dispatch_authorized fails
    let fake_dispatch = GateDispatchAuthorizedParams {
        request_id: "fake-req".to_string(),
        session_id: "session-1".to_string(),
        command: "npm install flatmap-stream@0.1.1".to_string(),
        authorization_token: "fake-token".to_string(),
        working_directory: Some(dir.path().display().to_string()),
    };

    let dispatch_res = gate.dispatch_authorized(fake_dispatch);
    assert!(dispatch_res.is_err());
    mock_backend.assert_zero_invocations();
}

// ============================================================================
// Requirement 12: Approval-required operations remaining undispatched
// ============================================================================
#[test]
fn test_req12_approval_required_workflow_authorized_dispatch() {
    let dir = tempdir().unwrap();
    // Vulnerable lodash package triggers RequireApproval
    let mock_backend = Arc::new(MockExecutionBackend::new());
    let audit_path = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_path).unwrap());

    let gate = ExecutionGate::new(
        mock_backend.clone(),
        None,
        Some(PolicyEngine::new()),
        Some(audit),
        true,
    );

    // 1. Initial execution attempt
    let res = gate.execute_gated_with_session(
        "npm install lodash@4.17.20",
        Some("sess-approval"),
        Some(dir.path()),
    );

    assert_eq!(res.decision, GateDecision::RequireApproval);
    assert_eq!(res.outcome, ExecutionOutcome::PendingApproval);
    mock_backend.assert_zero_invocations();

    // 2. User approves through ApprovalManager
    let pending = gate.approval_manager().get_pending(None);
    assert_eq!(pending.len(), 1);
    let req = &pending[0];
    assert_eq!(req.rule_id, "RULE-PACKAGE-VULNERABILITY");
    assert!(req.package_details.is_some());

    let (_status, auth_token_opt) = gate
        .approval_manager()
        .decide(
            &req.request_id,
            ApprovalUserDecision::Approve,
            Some("Approved for security testing".to_string()),
        )
        .unwrap();

    let auth_token = auth_token_opt.unwrap();

    // 3. Dispatch authorized
    let dispatch_params = GateDispatchAuthorizedParams {
        request_id: req.request_id.clone(),
        session_id: req.session_id.clone(),
        command: req.command.clone(),
        authorization_token: auth_token,
        working_directory: Some(dir.path().display().to_string()),
    };

    let dispatch_res = gate.dispatch_authorized(dispatch_params).unwrap();
    assert!(dispatch_res.dispatched);
    // Backend was invoked exactly ONCE now!
    mock_backend.assert_invoked_exactly(1);
}

// ============================================================================
// Requirement 13: Reassessment when project files change (TOCTOU protection)
// ============================================================================
#[test]
fn test_req13_toctou_manifest_modification_detected() {
    let dir = tempdir().unwrap();
    let pkg_file = dir.path().join("package.json");
    fs::write(
        &pkg_file,
        r#"{"name":"test","dependencies":{"express":"4.18.0"}}"#,
    )
    .unwrap();

    let mock_backend = Arc::new(MockExecutionBackend::new());
    let audit_path = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_path).unwrap());

    let gate = ExecutionGate::new(
        mock_backend.clone(),
        None,
        Some(PolicyEngine::new()),
        Some(audit),
        true,
    );

    // Evaluation creates approval request with original fingerprint
    let eval = gate.evaluate_with_session("npm install", Some("sess-toctou"), Some(dir.path()));
    assert!(eval.package_assessment.is_some());
    let orig_fp = eval
        .package_assessment
        .unwrap()
        .manifest_fingerprint
        .unwrap();

    let appr = gate.approval_manager().create_request_with_package_details(
        "sess-toctou".to_string(),
        "npm install".to_string(),
        Some(dir.path().display().to_string()),
        "RULE-PACKAGE-VULNERABILITY".to_string(),
        Severity::High,
        "Review needed".to_string(),
        None,
        None,
        Some(orig_fp),
    );

    // User approves
    let (_status, token_opt) = gate
        .approval_manager()
        .decide(&appr.request_id, ApprovalUserDecision::Approve, None)
        .unwrap();
    let token = token_opt.unwrap();

    // ATTACK: Project manifest is modified AFTER approval!
    fs::write(
        &pkg_file,
        r#"{"name":"test","dependencies":{"flatmap-stream":"0.1.1"}}"#,
    )
    .unwrap();

    // Attempt dispatch: must detect fingerprint mismatch and fail closed!
    let dispatch_res = gate.dispatch_authorized(GateDispatchAuthorizedParams {
        request_id: appr.request_id,
        session_id: "sess-toctou".to_string(),
        command: "npm install".to_string(),
        authorization_token: token,
        working_directory: Some(dir.path().display().to_string()),
    });

    assert!(dispatch_res.is_err());
    match dispatch_res.err().unwrap() {
        ApprovalError::InvalidStateTransition(msg) => {
            assert!(msg.contains("TOCTOU violation"));
        }
        other => panic!("Expected TOCTOU InvalidStateTransition, got {:?}", other),
    }

    mock_backend.assert_zero_invocations();
}

// ============================================================================
// Requirement 14: Audit-event accuracy and secret redaction
// ============================================================================
#[test]
fn test_req14_audit_accuracy_and_credential_redaction() {
    let dir = tempdir().unwrap();
    let mock_backend = Arc::new(MockExecutionBackend::new());
    let audit_path = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_path).unwrap());

    let gate = ExecutionGate::new(
        mock_backend.clone(),
        None,
        Some(PolicyEngine::new()),
        Some(audit.clone()),
        true,
    );

    // Command containing sensitive auth tokens
    let sensitive_cmd = "npm install --registry=https://registry.npmjs.org/ --//registry.npmjs.org/:_authToken=secret_token_12345 flatmap-stream@0.1.1";

    gate.execute_gated_with_session(sensitive_cmd, Some("sess-audit"), Some(dir.path()));

    let records = audit.read_all_records().unwrap();
    assert!(!records.is_empty());
    for rec in records {
        // Assert credentials never appear in plain text in audit trail
        assert!(!rec.decision_rationale.contains("secret_token_12345"));
        assert!(!rec.action_recorded.contains("secret_token_12345"));
    }
}
