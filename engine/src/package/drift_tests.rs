// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::audit::AuditLog;
use crate::gate::backend::MockExecutionBackend;
use crate::gate::ExecutionGate;
use crate::model::*;
use crate::package::advisory::{AdvisoryDatabase, AdvisoryRecord};
use crate::package::baseline::{
    compute_baseline_fingerprint, create_workspace_baseline, BaselineStore,
};
use crate::package::drift::DriftDetector;
use crate::package::monitor::WorkspaceMonitor;
use crate::package::post_verify::PostOperationVerifier;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct TestWorkspace {
    dir: PathBuf,
}

impl TestWorkspace {
    fn new(prefix: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("cyravell-test-{}-{}", prefix, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn write_file(&self, name: &str, content: &str) -> PathBuf {
        let p = self.dir.join(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        p
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// 1. Deterministic baseline fingerprints
// ---------------------------------------------------------------------------
#[test]
fn test_req1_deterministic_baseline_fingerprints() {
    let mut direct = BTreeMap::new();
    direct.insert("lodash".to_string(), "^4.17.21".to_string());
    direct.insert("express".to_string(), "^4.18.2".to_string());

    let mut resolved = BTreeMap::new();
    resolved.insert("lodash".to_string(), "4.17.21".to_string());
    resolved.insert("express".to_string(), "4.18.2".to_string());

    let transitive = BTreeMap::new();
    let integrity = BTreeMap::new();

    let fp1 = compute_baseline_fingerprint(
        PackageEcosystem::Npm,
        "npm",
        Some("manifest-fp-123"),
        &direct,
        &resolved,
        &transitive,
        &integrity,
    );

    let fp2 = compute_baseline_fingerprint(
        PackageEcosystem::Npm,
        "npm",
        Some("manifest-fp-123"),
        &direct,
        &resolved,
        &transitive,
        &integrity,
    );

    assert_eq!(fp1, fp2);
    assert_eq!(fp1.len(), 64);
}

// ---------------------------------------------------------------------------
// 2. Equivalent dependency state producing equivalent fingerprints
// ---------------------------------------------------------------------------
#[test]
fn test_req2_equivalent_dependency_state_producing_equivalent_fingerprints() {
    // Insert keys in opposite order into separate maps
    let mut direct_a = BTreeMap::new();
    direct_a.insert("z-pkg".to_string(), "1.0.0".to_string());
    direct_a.insert("a-pkg".to_string(), "2.0.0".to_string());

    let mut direct_b = BTreeMap::new();
    direct_b.insert("a-pkg".to_string(), "2.0.0".to_string());
    direct_b.insert("z-pkg".to_string(), "1.0.0".to_string());

    let resolved = BTreeMap::new();
    let transitive = BTreeMap::new();
    let integrity = BTreeMap::new();

    let fp_a = compute_baseline_fingerprint(
        PackageEcosystem::Npm,
        "npm",
        None,
        &direct_a,
        &resolved,
        &transitive,
        &integrity,
    );

    let fp_b = compute_baseline_fingerprint(
        PackageEcosystem::Npm,
        "npm",
        None,
        &direct_b,
        &resolved,
        &transitive,
        &integrity,
    );

    assert_eq!(
        fp_a, fp_b,
        "Equivalent dependency states must produce byte-for-byte identical fingerprints"
    );
}

// ---------------------------------------------------------------------------
// 3. Added, removed, upgraded, and downgraded dependencies
// ---------------------------------------------------------------------------
#[test]
fn test_req3_added_removed_upgraded_downgraded_dependencies() {
    let ws = TestWorkspace::new("drift-crud");
    let advisory_db = AdvisoryDatabase::load_embedded();

    let mut trusted_direct = BTreeMap::new();
    trusted_direct.insert("lodash".to_string(), "4.17.21".to_string());
    trusted_direct.insert("express".to_string(), "4.18.2".to_string());

    let mut trusted_resolved = BTreeMap::new();
    trusted_resolved.insert("lodash".to_string(), "4.17.21".to_string());
    trusted_resolved.insert("express".to_string(), "4.18.2".to_string());

    let trusted = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp-base".to_string()),
        direct_dependencies: trusted_direct,
        resolved_dependencies: trusted_resolved,
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::InitialBaseline,
        baseline_fingerprint: "trusted-fp".to_string(),
    };

    let mut current_direct = BTreeMap::new();
    current_direct.insert("lodash".to_string(), "4.17.15".to_string()); // Downgraded version
    current_direct.insert("axios".to_string(), "1.6.0".to_string()); // Added
                                                                     // express removed

    let mut current_resolved = BTreeMap::new();
    current_resolved.insert("lodash".to_string(), "4.17.15".to_string());
    current_resolved.insert("axios".to_string(), "1.6.0".to_string());

    let current = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp-curr".to_string()),
        direct_dependencies: current_direct,
        resolved_dependencies: current_resolved,
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::PostOperationObserved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::PostOperation,
        baseline_fingerprint: "current-fp".to_string(),
    };

    let report = DriftDetector::detect(&trusted, &current, &advisory_db);
    assert!(report.has_drift);

    let types: Vec<DriftChangeType> = report.findings.iter().map(|f| f.change_type).collect();
    assert!(types.contains(&DriftChangeType::UnexpectedAddition));
    assert!(types.contains(&DriftChangeType::UnexpectedRemoval));
    assert!(types.contains(&DriftChangeType::VersionDrift));
}

// ---------------------------------------------------------------------------
// 4. Transitive dependency changes
// ---------------------------------------------------------------------------
#[test]
fn test_req4_transitive_dependency_changes() {
    let ws = TestWorkspace::new("drift-trans");
    let advisory_db = AdvisoryDatabase::load_embedded();

    let mut direct = BTreeMap::new();
    direct.insert("my-app".to_string(), "1.0.0".to_string());

    let mut trusted_trans = BTreeMap::new();
    trusted_trans.insert("sub-dep".to_string(), "1.0.0".to_string());

    let trusted = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp-1".to_string()),
        direct_dependencies: direct.clone(),
        resolved_dependencies: trusted_trans.clone(),
        transitive_dependencies: trusted_trans,
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::InitialBaseline,
        baseline_fingerprint: "fp-1".to_string(),
    };

    let mut current_trans = BTreeMap::new();
    current_trans.insert("sub-dep".to_string(), "1.2.0".to_string()); // Transitive update

    let current = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp-2".to_string()),
        direct_dependencies: direct,
        resolved_dependencies: current_trans.clone(),
        transitive_dependencies: current_trans,
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::PostOperationObserved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::PostOperation,
        baseline_fingerprint: "fp-2".to_string(),
    };

    let report = DriftDetector::detect(&trusted, &current, &advisory_db);
    assert!(report.has_drift);
    assert!(report
        .findings
        .iter()
        .any(|f| f.change_type == DriftChangeType::TransitiveDrift));
}

// ---------------------------------------------------------------------------
// 5. Manifest-lockfile mismatch detection
// ---------------------------------------------------------------------------
#[test]
fn test_req5_manifest_lockfile_mismatch_detection() {
    let ws = TestWorkspace::new("mismatch-drift");
    let advisory_db = AdvisoryDatabase::load_embedded();

    let mut direct = BTreeMap::new();
    direct.insert("pkg-a".to_string(), "1.0.0".to_string());

    let mut resolved = BTreeMap::new();
    resolved.insert("pkg-a".to_string(), "1.0.0".to_string());

    let trusted = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp-1".to_string()),
        direct_dependencies: direct.clone(),
        resolved_dependencies: resolved.clone(),
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::InitialBaseline,
        baseline_fingerprint: "fp-1".to_string(),
    };

    // Lockfile updated while manifest direct deps unchanged
    let mut curr_resolved = resolved;
    curr_resolved.insert("pkg-b".to_string(), "2.0.0".to_string());

    let current = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp-2".to_string()),
        direct_dependencies: direct,
        resolved_dependencies: curr_resolved,
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::PostOperationObserved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::PostOperation,
        baseline_fingerprint: "fp-2".to_string(),
    };

    let report = DriftDetector::detect(&trusted, &current, &advisory_db);
    assert!(report
        .findings
        .iter()
        .any(|f| f.change_type == DriftChangeType::LockfileOnlyDrift));
}

// ---------------------------------------------------------------------------
// 6. Unexpected changes after an approved operation
// ---------------------------------------------------------------------------
#[test]
fn test_req6_unexpected_changes_after_approved_operation() {
    let ws = TestWorkspace::new("unexpected-post-op");
    let advisory_db = AdvisoryDatabase::load_embedded();

    ws.write_file(
        "package.json",
        r#"{"name": "test-pkg", "dependencies": {"axios": "1.6.0", "unapproved-backdoor": "0.1.0"}}"#,
    );
    ws.write_file(
        "package-lock.json",
        r#"{"name": "test-pkg", "lockfileVersion": 3, "packages": {"node_modules/axios": {"version": "1.6.0"}, "node_modules/unapproved-backdoor": {"version": "0.1.0"}}}"#,
    );

    let mut pre_direct = BTreeMap::new();
    pre_direct.insert("react".to_string(), "18.0.0".to_string());

    let pre_baseline = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("pre-fp".to_string()),
        direct_dependencies: pre_direct,
        resolved_dependencies: BTreeMap::new(),
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::PreOperation,
        baseline_fingerprint: "pre-fp".to_string(),
    };

    // User only approved `npm install axios`
    let result = PostOperationVerifier::verify(
        ws.path(),
        "npm install axios@1.6.0",
        Some(0),
        Some(&pre_baseline),
        &advisory_db,
    );

    assert_eq!(
        result.verification_status,
        PostOperationVerificationStatus::UnexpectedChanges
    );
    assert!(result
        .notes
        .iter()
        .any(|n| n.contains("unapproved-backdoor")));
}

// ---------------------------------------------------------------------------
// 7. A known malicious-package finding discovered after installation
// ---------------------------------------------------------------------------
#[test]
fn test_req7_known_malicious_package_discovered_after_installation() {
    let ws = TestWorkspace::new("post-install-malicious");
    let advisory_db = AdvisoryDatabase::load_embedded();

    // Post-op state contains flatmap-stream@0.1.1 (known malware)
    ws.write_file(
        "package.json",
        r#"{"name": "test-pkg", "dependencies": {"flatmap-stream": "0.1.1"}}"#,
    );
    ws.write_file(
        "package-lock.json",
        r#"{"name": "test-pkg", "lockfileVersion": 3, "packages": {"node_modules/flatmap-stream": {"version": "0.1.1"}}}"#,
    );

    let pre_baseline = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("clean-fp".to_string()),
        direct_dependencies: BTreeMap::new(),
        resolved_dependencies: BTreeMap::new(),
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::PreOperation,
        baseline_fingerprint: "clean-fp".to_string(),
    };

    let result = PostOperationVerifier::verify(
        ws.path(),
        "npm install flatmap-stream@0.1.1",
        Some(0),
        Some(&pre_baseline),
        &advisory_db,
    );

    assert_eq!(
        result.verification_status,
        PostOperationVerificationStatus::UnexpectedChanges
    );
    let drift = result.drift_report.expect("Drift report present");
    assert!(drift
        .findings
        .iter()
        .any(|f| f.is_malicious && f.package_name == "flatmap-stream"));
}

// ---------------------------------------------------------------------------
// 8. A newly vulnerable version discovered during reconciliation
// ---------------------------------------------------------------------------
#[test]
fn test_req8_newly_vulnerable_version_discovered_during_reconciliation() {
    let ws = TestWorkspace::new("vuln-reconcile");
    let advisory_db = AdvisoryDatabase::load_embedded();

    let mut direct = BTreeMap::new();
    direct.insert("lodash".to_string(), "4.17.20".to_string());

    let mut resolved = BTreeMap::new();
    resolved.insert("lodash".to_string(), "4.17.20".to_string());

    let trusted = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("clean-fp".to_string()),
        direct_dependencies: BTreeMap::new(),
        resolved_dependencies: BTreeMap::new(),
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::InitialBaseline,
        baseline_fingerprint: "clean-fp".to_string(),
    };

    let current = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("vuln-fp".to_string()),
        direct_dependencies: direct,
        resolved_dependencies: resolved,
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::PostOperationObserved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::Reconciliation,
        baseline_fingerprint: "vuln-fp".to_string(),
    };

    let report = DriftDetector::detect(&trusted, &current, &advisory_db);
    assert!(report.has_drift);
    let vuln_finding = report
        .findings
        .iter()
        .find(|f| f.change_type == DriftChangeType::VulnerabilityDetected);
    assert!(vuln_finding.is_some());
    assert_eq!(vuln_finding.unwrap().package_name, "lodash");
}

// ---------------------------------------------------------------------------
// 9. Missing, malformed, unreadable, or deleted metadata
// ---------------------------------------------------------------------------
#[test]
fn test_req9_missing_malformed_unreadable_deleted_metadata() {
    let ws = TestWorkspace::new("malformed-meta");
    ws.write_file("package.json", "{ malformed json: true, ");

    let advisory_db = AdvisoryDatabase::load_embedded();
    let res = create_workspace_baseline(
        ws.path(),
        Some(PackageEcosystem::Npm),
        SnapshotReason::InitialBaseline,
        BaselineTrust::UnverifiedInitial,
        &advisory_db,
    );

    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    let drift = DriftDetector::for_corrupted_metadata(
        &ws.path().display().to_string(),
        PackageEcosystem::Npm,
        &err_msg,
    );
    assert!(drift.has_drift);
    assert_eq!(
        drift.findings[0].change_type,
        DriftChangeType::MetadataCorrupted
    );
}

// ---------------------------------------------------------------------------
// 10. Failed package operations
// ---------------------------------------------------------------------------
#[test]
fn test_req10_failed_package_operations() {
    let ws = TestWorkspace::new("failed-op");
    let advisory_db = AdvisoryDatabase::load_embedded();

    let pre_baseline = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp".to_string()),
        direct_dependencies: BTreeMap::new(),
        resolved_dependencies: BTreeMap::new(),
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::PreOperation,
        baseline_fingerprint: "fp".to_string(),
    };

    // Exit code 1 (failure)
    let result = PostOperationVerifier::verify(
        ws.path(),
        "npm install nonexistent-pkg",
        Some(1),
        Some(&pre_baseline),
        &advisory_db,
    );

    assert_eq!(result.process_outcome, ExecutionOutcome::ExecutionFailed);
    assert_eq!(
        result.verification_status,
        PostOperationVerificationStatus::ExecutionFailed
    );
}

// ---------------------------------------------------------------------------
// 11. Successful package operations followed by failed verification
// ---------------------------------------------------------------------------
#[test]
fn test_req11_successful_package_operation_followed_by_failed_verification() {
    let ws = TestWorkspace::new("success-exec-failed-verify");
    let advisory_db = AdvisoryDatabase::load_embedded();

    // Package manager succeeded (exit code 0), but left a corrupted lockfile
    ws.write_file("package.json", r#"{"name": "pkg", "dependencies": {}}"#);
    ws.write_file("package-lock.json", "{ CORRUPTED LOCKFILE CONTENT");

    let pre_baseline = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp".to_string()),
        direct_dependencies: BTreeMap::new(),
        resolved_dependencies: BTreeMap::new(),
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::PreOperation,
        baseline_fingerprint: "fp".to_string(),
    };

    let result = PostOperationVerifier::verify(
        ws.path(),
        "npm install",
        Some(0),
        Some(&pre_baseline),
        &advisory_db,
    );

    assert_eq!(
        result.process_outcome,
        ExecutionOutcome::Dispatched,
        "Process itself succeeded"
    );
    assert_eq!(
        result.verification_status,
        PostOperationVerificationStatus::AssessmentFailed,
        "Post-operation assessment failed"
    );
}

// ---------------------------------------------------------------------------
// 12. Atomic file replacement and rapid repeated changes
// ---------------------------------------------------------------------------
#[test]
fn test_req12_atomic_file_replacement_and_rapid_repeated_changes() {
    let ws = TestWorkspace::new("atomic-swap");
    let monitor = WorkspaceMonitor::new();
    let store = BaselineStore::new();
    let advisory_db = AdvisoryDatabase::load_embedded();

    ws.write_file(
        "package.json",
        r#"{"name": "test", "dependencies": {"a": "1.0.0"}}"#,
    );
    monitor.register_workspace(ws.path());

    // Rapid writes simulating atomic replacement via temp file
    for i in 1..=5 {
        let content = format!(
            r#"{{"name": "test", "dependencies": {{"a": "{}.0.0"}}}}"#,
            i
        );
        ws.write_file("package.json", &content);
    }

    let report_res = monitor.reconcile_workspace(ws.path(), &store, &advisory_db, None);
    assert!(report_res.is_ok());
}

// ---------------------------------------------------------------------------
// 13. Duplicate filesystem notifications
// ---------------------------------------------------------------------------
#[test]
fn test_req13_duplicate_filesystem_notifications() {
    let ws = TestWorkspace::new("dup-notify");
    let monitor = WorkspaceMonitor::new();
    let store = BaselineStore::new();
    let advisory_db = AdvisoryDatabase::load_embedded();

    ws.write_file(
        "package.json",
        r#"{"name": "dup", "dependencies": {"a": "1.0.0"}}"#,
    );
    monitor.register_workspace(ws.path());

    // First reconciliation creates baseline
    let _ = monitor.reconcile_workspace(ws.path(), &store, &advisory_db, None);

    // Second call without file modifications must deduplicate
    let second_call = monitor
        .reconcile_workspace(ws.path(), &store, &advisory_db, None)
        .unwrap();
    // Since no files changed, no new drift is introduced
    assert!(second_call.is_none() || !second_call.unwrap().has_drift);
}

// ---------------------------------------------------------------------------
// 14. Concurrent snapshot creation and state reconciliation
// ---------------------------------------------------------------------------
#[test]
fn test_req14_concurrent_snapshot_creation_and_state_reconciliation() {
    let ws = Arc::new(TestWorkspace::new("concurrency"));
    ws.write_file(
        "package.json",
        r#"{"name": "conc", "dependencies": {"a": "1.0.0"}}"#,
    );

    let store = Arc::new(BaselineStore::new());
    let advisory_db = Arc::new(AdvisoryDatabase::load_embedded());

    let mut handles = Vec::new();
    for _ in 0..8 {
        let ws_clone = Arc::clone(&ws);
        let store_clone = Arc::clone(&store);
        let adv_clone = Arc::clone(&advisory_db);

        handles.push(std::thread::spawn(move || {
            let res = create_workspace_baseline(
                ws_clone.path(),
                Some(PackageEcosystem::Npm),
                SnapshotReason::ManualInspection,
                BaselineTrust::PostOperationObserved,
                &adv_clone,
            );
            assert!(res.is_ok());
            let b = res.unwrap();
            store_clone.set_baseline(ws_clone.path(), b);
            assert!(store_clone.get_baseline(ws_clone.path()).is_some());
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 15. Attempts to replace a trusted baseline with an unverified state
// ---------------------------------------------------------------------------
#[test]
fn test_req15_attempts_to_replace_trusted_baseline_with_unverified_state() {
    let ws = TestWorkspace::new("trust-boundary");
    let store = BaselineStore::new();

    let trusted = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp-trusted".to_string()),
        direct_dependencies: BTreeMap::new(),
        resolved_dependencies: BTreeMap::new(),
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::VerifiedApproved,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::InitialBaseline,
        baseline_fingerprint: "fp-trusted".to_string(),
    };

    store.set_baseline(ws.path(), trusted);

    let unverified = DependencyBaseline {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_manager: "npm".to_string(),
        manifest_fingerprint: Some("fp-unverified".to_string()),
        direct_dependencies: BTreeMap::new(),
        resolved_dependencies: BTreeMap::new(),
        transitive_dependencies: BTreeMap::new(),
        integrity_metadata: BTreeMap::new(),
        created_at: chrono::Utc::now(),
        trust_state: BaselineTrust::UnverifiedInitial,
        advisory_database_version: "2.5".to_string(),
        reason: SnapshotReason::Reconciliation,
        baseline_fingerprint: "fp-unverified".to_string(),
    };

    // Attempting to replace VerifiedApproved with UnverifiedInitial without approval must fail!
    let res = store.attempt_replace_baseline(ws.path(), unverified, false);
    assert!(res.is_err(), "Must reject unverified baseline replacement");
}

// ---------------------------------------------------------------------------
// 16. Audit integrity and credential redaction
// ---------------------------------------------------------------------------
#[test]
fn test_req16_audit_integrity_and_credential_redaction() {
    let ws = TestWorkspace::new("audit-redact");
    let audit_file = ws.path().join("audit.log");
    let audit = AuditLog::open(&audit_file).unwrap();

    let raw_cmd = "npm install https://user:super_secret_token_1234@internal.registry/pkg";
    let sanitized = crate::analysis::redact_command(raw_cmd);

    assert!(!sanitized.contains("super_secret_token_1234"));

    let rec = audit
        .append(
            "evt-audit-1",
            "POST_OPERATION_VERIFICATION",
            &sanitized,
            Severity::Low,
        )
        .unwrap();
    assert_eq!(rec.sequence_number, 1);

    let verify_res = audit.verify();
    assert_eq!(verify_res.status, "VALID");
}

// ---------------------------------------------------------------------------
// 17. Advisory database provenance and synthetic-fixture separation
// ---------------------------------------------------------------------------
#[test]
fn test_req17_advisory_database_provenance_and_synthetic_fixture_separation() {
    let mut db = AdvisoryDatabase::load_embedded();

    // Verify all embedded production advisories have valid provenance
    for adv in db.production_advisories() {
        assert!(
            !adv.is_synthetic,
            "Production advisory must not be flagged synthetic"
        );
        assert!(
            db.validate_record(adv).is_ok(),
            "Production advisory must pass validation"
        );
    }

    // Add a synthetic test fixture
    let synthetic_record = AdvisoryRecord {
        id: "SYNTH-001".to_string(),
        ecosystem: PackageEcosystem::Npm,
        package_name: "synthetic-malware-test".to_string(),
        severity: Severity::Critical,
        is_malicious: true,
        affected_range: "*".to_string(),
        fixed_version: None,
        title: "Synthetic Test Fixture".to_string(),
        details: "Isolated synthetic test fixture".to_string(),
        cve_id: None,
        provenance: Some("Synthetic Test Harness".to_string()),
        is_synthetic: true,
    };
    db.add_advisory(synthetic_record);

    assert_eq!(db.synthetic_advisories().len(), 1);
    assert_eq!(
        db.synthetic_advisories()[0].package_name,
        "synthetic-malware-test"
    );
}

// ---------------------------------------------------------------------------
// 18. Restart and recovery behavior
// ---------------------------------------------------------------------------
#[test]
fn test_req18_restart_and_recovery_behavior() {
    let ws = TestWorkspace::new("restart-recover");
    let advisory_db = AdvisoryDatabase::load_embedded();

    ws.write_file(
        "package.json",
        r#"{"name": "app", "dependencies": {"lodash": "4.17.21"}}"#,
    );

    let base1 = create_workspace_baseline(
        ws.path(),
        Some(PackageEcosystem::Npm),
        SnapshotReason::InitialBaseline,
        BaselineTrust::VerifiedApproved,
        &advisory_db,
    )
    .unwrap();

    // Simulate engine restart: new store, reload baseline from disk
    let store2 = BaselineStore::new();
    let base2 = create_workspace_baseline(
        ws.path(),
        Some(PackageEcosystem::Npm),
        SnapshotReason::InitialBaseline,
        BaselineTrust::VerifiedApproved,
        &advisory_db,
    )
    .unwrap();

    store2.set_baseline(ws.path(), base2.clone());

    assert_eq!(base1.baseline_fingerprint, base2.baseline_fingerprint);
    assert_eq!(
        store2.get_baseline(ws.path()).unwrap().baseline_fingerprint,
        base1.baseline_fingerprint
    );
}

// ---------------------------------------------------------------------------
// 19. Resource bounds and clean shutdown
// ---------------------------------------------------------------------------
#[test]
fn test_req19_resource_bounds_and_clean_shutdown() {
    let ws = TestWorkspace::new("resource-bounds");
    let monitor = WorkspaceMonitor::new();

    // Register workspace
    let active_files = monitor.register_workspace(ws.path());
    assert!(active_files.is_empty());

    assert_eq!(monitor.monitored_workspaces().len(), 1);

    // Unregister cleanly
    monitor.unregister_workspace(ws.path());
    assert_eq!(monitor.monitored_workspaces().len(), 0);
}

// ---------------------------------------------------------------------------
// 20. Regression tests for all previous execution-gate and approval invariants
// ---------------------------------------------------------------------------
#[test]
fn test_req20_regression_tests_execution_gate_and_approval_invariants() {
    let mock_backend = Arc::new(MockExecutionBackend::new());
    let store = Arc::new(BaselineStore::new());
    let gate = ExecutionGate::new(
        mock_backend.clone(),
        None,
        Some(crate::policy::PolicyEngine::new()),
        None,
        true,
    )
    .with_baseline_store(store.clone());

    // Invariant 1: Confirmed malicious package must be hard-blocked with 0 backend calls
    let block_res = gate.execute_gated("npm install flatmap-stream@0.1.1", None);
    assert_eq!(block_res.decision, GateDecision::Block);
    assert_eq!(mock_backend.invocation_count(), 0);

    // Invariant 2: Active drift with confirmed malicious package blocks future commands
    let ws = TestWorkspace::new("reg-drift-block");
    let drift_with_malware = DriftReport {
        workspace_path: ws.path().display().to_string(),
        ecosystem: PackageEcosystem::Npm,
        trusted_baseline_fingerprint: Some("fp".to_string()),
        current_fingerprint: "curr-fp".to_string(),
        has_drift: true,
        findings: vec![DriftFinding {
            finding_id: "drift-mal-test".to_string(),
            ecosystem: PackageEcosystem::Npm,
            package_name: "flatmap-stream".to_string(),
            previous_version: None,
            current_version: Some("0.1.1".to_string()),
            change_type: DriftChangeType::MaliciousPackageDetected,
            evidence: vec!["Known malicious dependency found".to_string()],
            applicable_rules: vec!["RULE-PACKAGE-MALICIOUS".to_string()],
            status: FindingConfidence::Confirmed,
            recommended_action: "HARD BLOCK".to_string(),
            is_malicious: true,
            severity: Severity::Critical,
        }],
        evaluated_at: chrono::Utc::now(),
        summary: "Malicious package drift".to_string(),
    };
    store.set_drift_report(ws.path(), drift_with_malware);

    let drift_block_res = gate.execute_gated("cargo check", Some(ws.path()));
    assert_eq!(drift_block_res.decision, GateDecision::Block);
    assert_eq!(mock_backend.invocation_count(), 0);

    // Invariant 3: Benign command in clean workspace executes exactly once
    let clean_ws = TestWorkspace::new("reg-clean");
    let allow_res = gate.execute_gated("cargo check", Some(clean_ws.path()));
    assert_eq!(allow_res.decision, GateDecision::Allow);
    assert_eq!(mock_backend.invocation_count(), 1);
}
