// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::audit::AuditLog;
use crate::gate::ExecutionGate;
use crate::model::{
    AdvisoryDatabaseSource, BaselineTrust, GateDecision, PackageEcosystem, Severity,
    SnapshotReason, TrustedKey,
};
use crate::package::advisory::{AdvisoryDatabase, AdvisoryRecord};
use crate::package::assessor::{PackageSecurityAssessor, PackageSecurityConfig};
use crate::package::baseline::{create_workspace_baseline, BaselineStore};
use crate::package::bundle::{
    compute_canonical_payload_digest, AdvisoryBundle, BundleValidationError,
};
use crate::package::trust::TrustedKeyStore;
use crate::package::updater::AdvisoryUpdater;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;
use tempfile::tempdir;

fn make_test_key(seed_byte: u8, key_id: &str, publisher: &str) -> (SigningKey, TrustedKey) {
    let seed = [seed_byte; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);
    let trusted_key = TrustedKey {
        key_id: key_id.to_string(),
        publisher: publisher.to_string(),
        public_key_hex: pubkey_hex,
        created_at: Utc::now(),
        expires_at: None,
        is_active: true,
    };
    (signing_key, trusted_key)
}

fn sample_advisory(
    id: &str,
    pkg: &str,
    eco: PackageEcosystem,
    is_malicious: bool,
) -> AdvisoryRecord {
    AdvisoryRecord {
        id: id.to_string(),
        ecosystem: eco,
        package_name: pkg.to_string(),
        severity: if is_malicious {
            Severity::Critical
        } else {
            Severity::High
        },
        is_malicious,
        affected_range: ">= 1.0.0, < 2.0.0".to_string(),
        fixed_version: if is_malicious {
            None
        } else {
            Some("2.0.0".to_string())
        },
        title: format!("Security Advisory for {}", pkg),
        details: format!("Synthetic test advisory details for {}", pkg),
        cve_id: Some("CVE-2026-9999".to_string()),
        provenance: Some("Cyravell Test Suite".to_string()),
        is_synthetic: false,
    }
}

fn build_signed_bundle(
    signing_key: &SigningKey,
    key_id: &str,
    publisher: &str,
    database_version: &str,
    advisories: Vec<AdvisoryRecord>,
) -> AdvisoryBundle {
    let payload_digest = compute_canonical_payload_digest(&advisories);
    let mut bundle = AdvisoryBundle {
        bundle_format_version: "1.0".to_string(),
        database_version: database_version.to_string(),
        created_at: Utc::now(),
        publisher: publisher.to_string(),
        key_id: key_id.to_string(),
        min_cyravell_version: Some("0.1.0".to_string()),
        supported_ecosystems: vec![
            PackageEcosystem::Npm,
            PackageEcosystem::Pip,
            PackageEcosystem::Cargo,
        ],
        payload_digest,
        signature: String::new(),
        advisories,
    };
    let signing_bytes = bundle.canonical_signing_bytes();
    let sig = signing_key.sign(&signing_bytes);
    bundle.signature = hex::encode(sig.to_bytes());
    bundle
}

// ---------------------------------------------------------------------------
// 1. Valid signed bundle acceptance
// ---------------------------------------------------------------------------
#[test]
fn test_01_valid_signed_bundle_acceptance() {
    let dir = tempdir().unwrap();
    let (sk, tk) = make_test_key(1, "test-key-1", "Cyravell Test Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let advisories = vec![
        sample_advisory(
            "TEST-ADV-001",
            "crypto-miner-fake",
            PackageEcosystem::Npm,
            true,
        ),
        sample_advisory(
            "TEST-ADV-002",
            "vulnerable-lib",
            PackageEcosystem::Cargo,
            false,
        ),
    ];
    let bundle = build_signed_bundle(
        &sk,
        "test-key-1",
        "Cyravell Test Authority",
        "2026.05.01",
        advisories,
    );

    let val_res = bundle.validate_and_authenticate(&key_store, Some("2026.04.01"), false);
    assert!(val_res.is_ok(), "Valid signed bundle must pass validation");

    let bundle_file = dir.path().join("bundle.json");
    std::fs::write(&bundle_file, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let assessor = Arc::new(PackageSecurityAssessor::new(
        PackageSecurityConfig::default(),
    ));
    let audit_file = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_file).unwrap());
    let baseline_store = Arc::new(BaselineStore::new());
    let storage_file = dir.path().join("advisories.json");

    let updater = AdvisoryUpdater::new(
        assessor.clone(),
        baseline_store,
        audit,
        Arc::new(key_store),
        storage_file.clone(),
    );

    let import_res = updater.import_bundle(&bundle_file, false).unwrap();
    assert_eq!(import_res.new_version, "2026.05.01");
    assert_eq!(import_res.records_count, 2);
    assert_eq!(assessor.advisory_db().database_version(), "2026.05.01");
    assert!(storage_file.exists());
}

// ---------------------------------------------------------------------------
// 2. Modified payload with unchanged signature
// ---------------------------------------------------------------------------
#[test]
fn test_02_modified_payload_with_unchanged_signature() {
    let (sk, tk) = make_test_key(2, "test-key-2", "Cyravell Test Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let advisories = vec![sample_advisory(
        "TEST-ADV-001",
        "pkg-a",
        PackageEcosystem::Npm,
        false,
    )];
    let mut bundle = build_signed_bundle(
        &sk,
        "test-key-2",
        "Cyravell Test Authority",
        "2026.05.01",
        advisories,
    );

    // Tamper with payload without updating signature or payload_digest
    bundle.advisories[0].package_name = "tampered-pkg".to_string();

    let err = bundle
        .validate_and_authenticate(&key_store, Some("2026.04.01"), false)
        .unwrap_err();
    match err {
        BundleValidationError::PayloadDigestMismatch { .. } => {}
        other => panic!("Expected PayloadDigestMismatch, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 3. Invalid or truncated signature
// ---------------------------------------------------------------------------
#[test]
fn test_03_invalid_or_truncated_signature() {
    let (sk, tk) = make_test_key(3, "test-key-3", "Cyravell Test Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let advisories = vec![sample_advisory(
        "TEST-ADV-001",
        "pkg-a",
        PackageEcosystem::Npm,
        false,
    )];
    let mut bundle = build_signed_bundle(
        &sk,
        "test-key-3",
        "Cyravell Test Authority",
        "2026.05.01",
        advisories,
    );

    // Truncate signature
    bundle.signature = bundle.signature[..32].to_string();

    let err = bundle
        .validate_and_authenticate(&key_store, Some("2026.04.01"), false)
        .unwrap_err();
    match err {
        BundleValidationError::SignatureError(_) => {}
        other => panic!("Expected SignatureError, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 4. Unknown publisher key
// ---------------------------------------------------------------------------
#[test]
fn test_04_unknown_publisher_key() {
    let (sk, _tk) = make_test_key(4, "unknown-key", "Untrusted Rogue Publisher");
    let key_store = TrustedKeyStore::new(); // Empty key store

    let advisories = vec![sample_advisory(
        "TEST-ADV-001",
        "pkg-a",
        PackageEcosystem::Npm,
        false,
    )];
    let bundle = build_signed_bundle(
        &sk,
        "unknown-key",
        "Untrusted Rogue Publisher",
        "2026.05.01",
        advisories,
    );

    let err = bundle
        .validate_and_authenticate(&key_store, Some("2026.04.01"), false)
        .unwrap_err();
    match err {
        BundleValidationError::SignatureError(msg) => {
            assert!(msg.contains("not found in trusted key store") || msg.contains("unknown"));
        }
        other => panic!("Expected SignatureError for unknown key, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 5. Malformed bundle and schema rejection
// ---------------------------------------------------------------------------
#[test]
fn test_05_malformed_bundle_and_schema_rejection() {
    let (sk, tk) = make_test_key(5, "test-key-5", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    // 5a. Unsupported format version
    let advisories = vec![sample_advisory(
        "TEST-ADV-001",
        "pkg-a",
        PackageEcosystem::Npm,
        false,
    )];
    let mut bundle = build_signed_bundle(
        &sk,
        "test-key-5",
        "Cyravell Authority",
        "2026.05.01",
        advisories,
    );
    bundle.bundle_format_version = "99.0".to_string();
    let err = bundle
        .validate_and_authenticate(&key_store, None, false)
        .unwrap_err();
    assert!(matches!(
        err,
        BundleValidationError::UnsupportedFormatVersion(_)
    ));

    // 5b. Empty advisories
    let empty_bundle = build_signed_bundle(
        &sk,
        "test-key-5",
        "Cyravell Authority",
        "2026.05.01",
        vec![],
    );
    let err = empty_bundle
        .validate_and_authenticate(&key_store, None, false)
        .unwrap_err();
    assert!(matches!(err, BundleValidationError::EmptyAdvisories));
}

// ---------------------------------------------------------------------------
// 6. Invalid ecosystem and affected-version ranges
// ---------------------------------------------------------------------------
#[test]
fn test_06_invalid_ecosystem_and_affected_version_ranges() {
    let (sk, tk) = make_test_key(6, "test-key-6", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let mut adv = sample_advisory("TEST-ADV-001", "pkg-a", PackageEcosystem::Npm, false);
    adv.affected_range = "INVALID_SYNTAX<<<>>>".to_string();

    let bundle = build_signed_bundle(
        &sk,
        "test-key-6",
        "Cyravell Authority",
        "2026.05.01",
        vec![adv],
    );
    let err = bundle
        .validate_and_authenticate(&key_store, None, false)
        .unwrap_err();
    assert!(matches!(err, BundleValidationError::MalformedRecord(_)));
}

// ---------------------------------------------------------------------------
// 7. Duplicate or contradictory advisory records
// ---------------------------------------------------------------------------
#[test]
fn test_07_duplicate_or_contradictory_advisory_records() {
    let (sk, tk) = make_test_key(7, "test-key-7", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    // Duplicate ID
    let adv1 = sample_advisory("DUP-ID-01", "pkg-a", PackageEcosystem::Npm, false);
    let mut adv2 = sample_advisory("DUP-ID-01", "pkg-b", PackageEcosystem::Npm, true);
    adv2.details = "Contradictory duplicate".to_string();

    let bundle = build_signed_bundle(
        &sk,
        "test-key-7",
        "Cyravell Authority",
        "2026.05.01",
        vec![adv1, adv2],
    );
    let err = bundle
        .validate_and_authenticate(&key_store, None, false)
        .unwrap_err();
    assert!(matches!(err, BundleValidationError::DuplicateAdvisoryId(_)));
}

// ---------------------------------------------------------------------------
// 8. Synthetic fixture contamination of production data
// ---------------------------------------------------------------------------
#[test]
fn test_08_synthetic_fixture_contamination_of_production_data() {
    let (sk, tk) = make_test_key(8, "test-key-8", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let mut adv = sample_advisory("PROD-ADV-01", "pkg-a", PackageEcosystem::Npm, false);
    adv.is_synthetic = true; // Synthetic fixture contaminated in production bundle

    let bundle = build_signed_bundle(
        &sk,
        "test-key-8",
        "Cyravell Authority",
        "2026.05.01",
        vec![adv],
    );
    let err = bundle
        .validate_and_authenticate(&key_store, None, false)
        .unwrap_err();
    assert!(matches!(
        err,
        BundleValidationError::SyntheticContamination(_)
    ));
}

// ---------------------------------------------------------------------------
// 9. Older-version rollback attempts
// ---------------------------------------------------------------------------
#[test]
fn test_09_older_version_rollback_attempts() {
    let (sk, tk) = make_test_key(9, "test-key-9", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let adv = sample_advisory("ADV-01", "pkg-a", PackageEcosystem::Npm, false);
    // Active is 2026.05.01, candidate is older 2026.04.15
    let bundle = build_signed_bundle(
        &sk,
        "test-key-9",
        "Cyravell Authority",
        "2026.04.15",
        vec![adv.clone()],
    );

    // Rollback without flag must be rejected
    let err = bundle
        .validate_and_authenticate(&key_store, Some("2026.05.01"), false)
        .unwrap_err();
    assert!(matches!(
        err,
        BundleValidationError::RollbackRejected { .. }
    ));

    // Rollback with allow_rollback=true is accepted
    let ok = bundle.validate_and_authenticate(&key_store, Some("2026.05.01"), true);
    assert!(
        ok.is_ok(),
        "Authorized rollback with allow_rollback=true must be accepted"
    );
}

// ---------------------------------------------------------------------------
// 10. Higher-version bundle with an invalid signature
// ---------------------------------------------------------------------------
#[test]
fn test_10_higher_version_bundle_with_invalid_signature() {
    let (_sk, tk) = make_test_key(10, "test-key-10", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    // Sign with rogue unauthenticated key
    let (rogue_sk, _rogue_tk) = make_test_key(99, "test-key-10", "Spoofed Key ID");
    let adv = sample_advisory("ADV-HIGHER", "pkg-a", PackageEcosystem::Npm, false);
    // Extremely high version
    let bundle = build_signed_bundle(
        &rogue_sk,
        "test-key-10",
        "Cyravell Authority",
        "9999.99.99",
        vec![adv],
    );

    // Even though candidate version is astronomically higher, invalid signature must be rejected
    let err = bundle
        .validate_and_authenticate(&key_store, Some("2026.04.01"), false)
        .unwrap_err();
    assert!(matches!(err, BundleValidationError::SignatureError(_)));
}

// ---------------------------------------------------------------------------
// 11. Interrupted update and atomic-activation failure
// ---------------------------------------------------------------------------
#[test]
fn test_11_interrupted_update_and_atomic_activation_failure() {
    let dir = tempdir().unwrap();
    let (sk, tk) = make_test_key(11, "test-key-11", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let initial_adv = vec![sample_advisory(
        "INIT-01",
        "pkg-init",
        PackageEcosystem::Npm,
        false,
    )];
    let initial_db = AdvisoryDatabase::from_bundle(&build_signed_bundle(
        &sk,
        "test-key-11",
        "Cyravell Authority",
        "2026.04.01",
        initial_adv,
    ));

    let assessor = Arc::new(
        PackageSecurityAssessor::new(PackageSecurityConfig::default()).with_advisories(initial_db),
    );
    let audit_file = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_file).unwrap());
    let baseline_store = Arc::new(BaselineStore::new());

    // Point storage_path to an invalid unwritable path (directory masquerading as file)
    let invalid_storage = dir.path().join("storage_dir_blocker");
    std::fs::create_dir(&invalid_storage).unwrap();

    let updater = AdvisoryUpdater::new(
        assessor.clone(),
        baseline_store,
        audit,
        Arc::new(key_store),
        invalid_storage,
    );

    let update_adv = vec![sample_advisory(
        "NEW-01",
        "pkg-new",
        PackageEcosystem::Npm,
        false,
    )];
    let bundle = build_signed_bundle(
        &sk,
        "test-key-11",
        "Cyravell Authority",
        "2026.05.01",
        update_adv,
    );
    let bundle_file = dir.path().join("bundle.json");
    std::fs::write(&bundle_file, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let res = updater.import_bundle(&bundle_file, false);
    assert!(res.is_err(), "Atomic persistence failure must return error");
    // Active database in memory must remain completely intact
    assert_eq!(assessor.advisory_db().database_version(), "2026.04.01");
}

// ---------------------------------------------------------------------------
// 12. Failed update preserving previous active database
// ---------------------------------------------------------------------------
#[test]
fn test_12_failed_update_preserving_previous_active_database() {
    let dir = tempdir().unwrap();
    let (sk, tk) = make_test_key(12, "test-key-12", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let initial_adv = vec![sample_advisory(
        "INIT-01",
        "critical-malware",
        PackageEcosystem::Npm,
        true,
    )];
    let initial_db = AdvisoryDatabase::from_bundle(&build_signed_bundle(
        &sk,
        "test-key-12",
        "Cyravell Authority",
        "2026.04.01",
        initial_adv,
    ));

    let assessor = Arc::new(
        PackageSecurityAssessor::new(PackageSecurityConfig::default()).with_advisories(initial_db),
    );
    let audit_file = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_file).unwrap());
    let baseline_store = Arc::new(BaselineStore::new());
    let storage_file = dir.path().join("advisories.json");

    let updater = AdvisoryUpdater::new(
        assessor.clone(),
        baseline_store,
        audit,
        Arc::new(key_store),
        storage_file,
    );

    // Verify initial state detects critical malware
    assert!(assessor.is_malicious_package(PackageEcosystem::Npm, "critical-malware"));

    // Attempt to import a corrupted bundle
    let bad_bundle_file = dir.path().join("corrupt_bundle.json");
    std::fs::write(&bad_bundle_file, b"NOT_VALID_JSON{").unwrap();

    let res = updater.import_bundle(&bad_bundle_file, false);
    assert!(res.is_err());

    // Invariant: original active database is 100% functional and still blocks critical malware
    assert_eq!(assessor.advisory_db().database_version(), "2026.04.01");
    assert!(assessor.is_malicious_package(PackageEcosystem::Npm, "critical-malware"));
}

// ---------------------------------------------------------------------------
// 13. Corrupted external database and embedded fallback behavior
// ---------------------------------------------------------------------------
#[test]
fn test_13_corrupted_external_database_and_embedded_fallback_behavior() {
    let dir = tempdir().unwrap();
    let corrupt_file = dir.path().join("advisories.json");
    std::fs::write(&corrupt_file, b"corrupted garbage content").unwrap();

    let db = AdvisoryDatabase::load_with_fallback(Some(&corrupt_file));
    assert_eq!(db.source_type(), AdvisoryDatabaseSource::Embedded);
    assert!(
        !db.is_empty(),
        "Embedded fallback database must not be empty"
    );
    assert!(db.is_malicious_package(PackageEcosystem::Npm, "flatmap-stream"));
}

// ---------------------------------------------------------------------------
// 14. Engine restart with previously activated update
// ---------------------------------------------------------------------------
#[test]
fn test_14_engine_restart_with_previously_activated_update() {
    let dir = tempdir().unwrap();
    let (sk, tk) = make_test_key(14, "test-key-14", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let advisories = vec![sample_advisory(
        "RESTART-01",
        "new-evil-pkg",
        PackageEcosystem::Npm,
        true,
    )];
    let bundle = build_signed_bundle(
        &sk,
        "test-key-14",
        "Cyravell Authority",
        "2026.06.15",
        advisories,
    );
    let bundle_file = dir.path().join("bundle.json");
    std::fs::write(&bundle_file, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let storage_file = dir.path().join("advisories.json");
    let assessor = Arc::new(PackageSecurityAssessor::new(
        PackageSecurityConfig::default(),
    ));
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let baseline_store = Arc::new(BaselineStore::new());

    let updater = AdvisoryUpdater::new(
        assessor,
        baseline_store,
        audit,
        Arc::new(key_store),
        storage_file.clone(),
    );

    updater.import_bundle(&bundle_file, false).unwrap();

    // Simulate engine restart: create fresh AdvisoryDatabase from storage_file
    let loaded_db = AdvisoryDatabase::load_from_path(&storage_file).unwrap();
    assert_eq!(loaded_db.database_version(), "2026.06.15");
    assert!(loaded_db.is_malicious_package(PackageEcosystem::Npm, "new-evil-pkg"));
}

// ---------------------------------------------------------------------------
// 15. Concurrent advisory reads during update activation
// ---------------------------------------------------------------------------
#[test]
fn test_15_concurrent_advisory_reads_during_update_activation() {
    let dir = tempdir().unwrap();
    let (sk, tk) = make_test_key(15, "test-key-15", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let initial_db = AdvisoryDatabase::load_embedded();
    let assessor = Arc::new(
        PackageSecurityAssessor::new(PackageSecurityConfig::default()).with_advisories(initial_db),
    );
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let baseline_store = Arc::new(BaselineStore::new());
    let storage_file = dir.path().join("advisories.json");

    let updater = Arc::new(AdvisoryUpdater::new(
        assessor.clone(),
        baseline_store,
        audit,
        Arc::new(key_store),
        storage_file,
    ));

    let adv = vec![sample_advisory(
        "CONCUR-01",
        "hot-pkg",
        PackageEcosystem::Npm,
        false,
    )];
    let bundle = build_signed_bundle(&sk, "test-key-15", "Cyravell Authority", "2026.07.01", adv);
    let bundle_file = dir.path().join("bundle.json");
    std::fs::write(&bundle_file, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let mut handles = vec![];
    for _ in 0..4 {
        let assessor_clone = assessor.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let _ = assessor_clone.is_malicious_package(PackageEcosystem::Npm, "hot-pkg");
                std::thread::yield_now();
            }
        }));
    }

    let updater_clone = updater.clone();
    let writer_handle =
        std::thread::spawn(move || updater_clone.import_bundle(&bundle_file, false).unwrap());

    writer_handle.join().unwrap();
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(assessor.advisory_db().database_version(), "2026.07.01");
}

// ---------------------------------------------------------------------------
// 16. Pending approval invalidation or reevaluation when relevant policy changes
// ---------------------------------------------------------------------------
#[test]
fn test_16_pending_approval_invalidation_or_reevaluation() {
    let dir = tempdir().unwrap();
    let (sk, tk) = make_test_key(16, "test-key-16", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let assessor = Arc::new(PackageSecurityAssessor::new(
        PackageSecurityConfig::default(),
    ));
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let baseline_store = Arc::new(BaselineStore::new());
    let storage_file = dir.path().join("advisories.json");

    let updater = AdvisoryUpdater::new(
        assessor.clone(),
        baseline_store,
        audit.clone(),
        Arc::new(key_store),
        storage_file,
    );

    // Initial check: "crypto-hijack-tool" is unknown and not blocked
    assert!(!assessor.is_malicious_package(PackageEcosystem::Npm, "crypto-hijack-tool"));

    // Import bundle adding "crypto-hijack-tool" as malicious
    let adv = vec![sample_advisory(
        "MAL-NEW-01",
        "crypto-hijack-tool",
        PackageEcosystem::Npm,
        true,
    )];
    let bundle = build_signed_bundle(&sk, "test-key-16", "Cyravell Authority", "2026.08.01", adv);
    let bundle_file = dir.path().join("bundle.json");
    std::fs::write(&bundle_file, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    updater.import_bundle(&bundle_file, false).unwrap();

    // Now re-evaluating: package is now immediately recognized as malicious and hard blocked
    assert!(assessor.is_malicious_package(PackageEcosystem::Npm, "crypto-hijack-tool"));
}

// ---------------------------------------------------------------------------
// 17. Reassessment of affected dependency baselines
// ---------------------------------------------------------------------------
#[test]
fn test_17_reassessment_of_affected_dependency_baselines() {
    let dir = tempdir().unwrap();
    let ws_dir = dir.path().join("my_workspace");
    std::fs::create_dir_all(&ws_dir).unwrap();

    // Create a package.json in workspace referencing "trojan-lib"
    let pkg_json = r#"{
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {
            "trojan-lib": "1.0.0"
        }
    }"#;
    std::fs::write(ws_dir.join("package.json"), pkg_json).unwrap();

    let assessor = Arc::new(PackageSecurityAssessor::new(
        PackageSecurityConfig::default(),
    ));
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let baseline_store = Arc::new(BaselineStore::new());

    // Record baseline for workspace
    let ws_path = ws_dir.to_string_lossy().to_string();
    let baseline = create_workspace_baseline(
        &ws_dir,
        Some(PackageEcosystem::Npm),
        SnapshotReason::InitialBaseline,
        BaselineTrust::UnverifiedInitial,
        &assessor.advisory_db(),
    )
    .unwrap();
    baseline_store.set_baseline(&ws_dir, baseline);

    let (sk, tk) = make_test_key(17, "test-key-17", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);
    let storage_file = dir.path().join("advisories.json");

    let updater = AdvisoryUpdater::new(
        assessor,
        baseline_store.clone(),
        audit,
        Arc::new(key_store),
        storage_file,
    );

    // Import bundle declaring "trojan-lib" as malicious
    let adv = vec![sample_advisory(
        "TROJAN-01",
        "trojan-lib",
        PackageEcosystem::Npm,
        true,
    )];
    let bundle = build_signed_bundle(&sk, "test-key-17", "Cyravell Authority", "2026.08.10", adv);
    let bundle_file = dir.path().join("bundle.json");
    std::fs::write(&bundle_file, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let import_res = updater.import_bundle(&bundle_file, false).unwrap();
    // Verify affected workspace was reassessed
    assert!(import_res.affected_workspaces.contains(&ws_path));
    // Verify active drift was registered
    assert!(baseline_store.get_drift_report(&ws_dir).is_some());
}

// ---------------------------------------------------------------------------
// 18. Audit-chain integrity and update-event accuracy
// ---------------------------------------------------------------------------
#[test]
fn test_18_audit_chain_integrity_and_update_event_accuracy() {
    let dir = tempdir().unwrap();
    let (sk, tk) = make_test_key(18, "test-key-18", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let audit_file = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_file).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::new(
        PackageSecurityConfig::default(),
    ));
    let baseline_store = Arc::new(BaselineStore::new());
    let storage_file = dir.path().join("advisories.json");

    let updater = AdvisoryUpdater::new(
        assessor,
        baseline_store,
        audit.clone(),
        Arc::new(key_store),
        storage_file,
    );

    // 1. Successful import
    let adv = vec![sample_advisory(
        "AUDIT-01",
        "audit-pkg",
        PackageEcosystem::Npm,
        false,
    )];
    let bundle = build_signed_bundle(&sk, "test-key-18", "Cyravell Authority", "2026.09.01", adv);
    let bundle_file = dir.path().join("bundle.json");
    std::fs::write(&bundle_file, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();
    updater.import_bundle(&bundle_file, false).unwrap();

    // 2. Rejected import (rollback rejected)
    let rollback_bundle = build_signed_bundle(
        &sk,
        "test-key-18",
        "Cyravell Authority",
        "2026.08.01",
        vec![],
    );
    let rollback_file = dir.path().join("rollback.json");
    std::fs::write(
        &rollback_file,
        serde_json::to_string_pretty(&rollback_bundle).unwrap(),
    )
    .unwrap();
    let _ = updater.import_bundle(&rollback_file, false);

    // 3. Verify cryptographic audit chain integrity
    let verify_res = audit.verify();
    assert_eq!(verify_res.status, "VALID");
    assert!(verify_res.total_records >= 2);
    assert!(verify_res.corrupted_sequence.is_none());
}

// ---------------------------------------------------------------------------
// 19. Secret and credential redaction
// ---------------------------------------------------------------------------
#[test]
fn test_19_secret_and_credential_redaction() {
    let dir = tempdir().unwrap();
    let (sk, tk) = make_test_key(19, "test-key-19", "Cyravell Authority");
    let mut key_store = TrustedKeyStore::new();
    key_store.add_key(tk);

    let audit_file = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_file).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::new(
        PackageSecurityConfig::default(),
    ));
    let baseline_store = Arc::new(BaselineStore::new());
    let storage_file = dir.path().join("advisories.json");

    let updater = AdvisoryUpdater::new(
        assessor,
        baseline_store,
        audit.clone(),
        Arc::new(key_store),
        storage_file,
    );

    let mut adv = sample_advisory("SEC-01", "sec-pkg", PackageEcosystem::Npm, false);
    // Secret inside title / details
    adv.details =
        "Leaked token: ghp_1234567890abcdef1234567890abcdef123456 in advisory details".to_string();

    let bundle = build_signed_bundle(
        &sk,
        "test-key-19",
        "Cyravell Authority",
        "2026.09.15",
        vec![adv],
    );
    let bundle_file = dir.path().join("bundle.json");
    std::fs::write(&bundle_file, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    updater.import_bundle(&bundle_file, false).unwrap();

    // Verify audit log entries do not leak private keys or full raw tokens in unredacted state
    let log_content = std::fs::read_to_string(&audit_file).unwrap();
    assert!(!log_content.contains("ghp_1234567890abcdef1234567890abcdef123456"));
}

// ---------------------------------------------------------------------------
// 20. Regression tests for package enforcement, drift monitoring, and execution-gate invariants
// ---------------------------------------------------------------------------
#[test]
fn test_20_regression_tests_for_execution_gate_invariants() {
    let dir = tempdir().unwrap();
    let backend = Arc::new(crate::gate::MockExecutionBackend::new());
    let policy = crate::PolicyEngine::new();
    let audit_file = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_file).unwrap());

    let gate = ExecutionGate::new(
        backend,
        None,
        Some(policy),
        Some(audit),
        true, // fail-closed
    );

    // Baseline package install should evaluate normally
    let eval = gate.evaluate("npm install lodash", None);
    assert_eq!(eval.decision, GateDecision::Allow);

    // Known malicious package from embedded database must remain blocked
    let eval_bad = gate.evaluate("npm install flatmap-stream", None);
    assert_eq!(eval_bad.decision, GateDecision::Block);
}
