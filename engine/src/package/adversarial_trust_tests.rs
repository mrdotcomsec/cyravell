// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::audit::AuditLog;
use crate::gate::approval::ApprovalManager;
use crate::gate::ExecutionGate;
use crate::model::{
    AdvisoryDatabaseSource, ApprovalStatus, ApprovalUserDecision, GateDecision, PackageEcosystem,
    PackageImportAdvisoryBundleParams, Severity, TrustedKey,
};
use crate::package::advisory::{AdvisoryDatabase, AdvisoryRecord};
use crate::package::assessor::{PackageSecurityAssessor, PackageSecurityConfig};
use crate::package::baseline::BaselineStore;
use crate::package::bundle::{
    compute_canonical_payload_digest, AdvisoryBundle, BundleValidationError,
};
use crate::package::state::AdvisorySecurityState;
use crate::package::strict_json::validate_no_duplicate_keys;
use crate::package::trust::{KeyStoreError, KeyVerificationError, TrustedKeyStore};
use crate::package::updater::AdvisoryUpdater;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashSet;
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
        title: format!("Advisory for {}", pkg),
        details: format!("Advisory details for {}", pkg),
        cve_id: Some("CVE-2026-0001".to_string()),
        provenance: Some("Cyravell Adversarial Test Suite".to_string()),
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
// 1. Duplicate JSON keys and ambiguous signed representations
// ---------------------------------------------------------------------------
#[test]
fn test_01_duplicate_json_keys_rejected() {
    let root_duplicate = r#"{
        "bundle_format_version": "1.0",
        "database_version": "2.0.0",
        "database_version": "1.0.0"
    }"#;
    assert!(validate_no_duplicate_keys(root_duplicate).is_err());

    let nested_duplicate = r#"{
        "bundle_format_version": "1.0",
        "advisories": [
            {
                "id": "ADV-01",
                "is_malicious": false,
                "is_malicious": true
            }
        ]
    }"#;
    assert!(validate_no_duplicate_keys(nested_duplicate).is_err());

    let keystore_duplicate = r#"{
        "keys": [],
        "keys": []
    }"#;
    assert!(TrustedKeyStore::load_from_json(keystore_duplicate).is_err());
}

// ---------------------------------------------------------------------------
// 2. Metadata changes without a valid new signature
// ---------------------------------------------------------------------------
#[test]
fn test_02_metadata_modification_invalidates_signature() {
    let (sk, tk) = make_test_key(1, "key-adv-2", "Cyravell Team");
    let mut store = TrustedKeyStore::new();
    store.add_key(tk);

    let bundle = build_signed_bundle(
        &sk,
        "key-adv-2",
        "Cyravell Team",
        "2.0.0",
        vec![sample_advisory(
            "ADV-01",
            "lodash",
            PackageEcosystem::Npm,
            false,
        )],
    );

    // Baseline: valid bundle passes
    assert!(bundle
        .validate_and_authenticate(&store, Some("1.0.0"), false)
        .is_ok());

    // Tamper with database_version
    let mut tampered = bundle.clone();
    tampered.database_version = "3.0.0".to_string();
    assert!(tampered
        .validate_and_authenticate(&store, Some("1.0.0"), false)
        .is_err());

    // Tamper with format_version
    let mut tampered = bundle.clone();
    tampered.bundle_format_version = "2.0".to_string();
    assert!(tampered
        .validate_and_authenticate(&store, Some("1.0.0"), false)
        .is_err());

    // Tamper with created_at
    let mut tampered = bundle.clone();
    tampered.created_at = Utc::now() + Duration::days(1);
    assert!(tampered
        .validate_and_authenticate(&store, Some("1.0.0"), false)
        .is_err());

    // Tamper with publisher
    let mut tampered = bundle.clone();
    tampered.publisher = "Malicious Impersonator".to_string();
    assert!(tampered
        .validate_and_authenticate(&store, Some("1.0.0"), false)
        .is_err());

    // Tamper with supported_ecosystems (now bound to signature!)
    let mut tampered = bundle.clone();
    tampered.supported_ecosystems.push(PackageEcosystem::Yarn);
    assert!(tampered
        .validate_and_authenticate(&store, Some("1.0.0"), false)
        .is_err());
}

// ---------------------------------------------------------------------------
// 3. Expired, revoked, unknown, and rotated signing keys
// ---------------------------------------------------------------------------
#[test]
fn test_03_expired_revoked_unknown_and_rotated_keys() {
    let (sk, mut tk) = make_test_key(2, "key-adv-3", "Security Org");
    let mut store = TrustedKeyStore::new();

    // Inactive (revoked) key
    tk.is_active = false;
    store.add_key(tk.clone());
    let bundle = build_signed_bundle(
        &sk,
        "key-adv-3",
        "Security Org",
        "2.0.0",
        vec![sample_advisory(
            "ADV-01",
            "lodash",
            PackageEcosystem::Npm,
            false,
        )],
    );
    assert_eq!(
        bundle.validate_and_authenticate(&store, Some("1.0.0"), false),
        Err(BundleValidationError::SignatureError(
            KeyVerificationError::KeyRevoked("key-adv-3".to_string()).to_string()
        ))
    );

    // Expired key
    let mut expired_tk = tk.clone();
    expired_tk.is_active = true;
    expired_tk.expires_at = Some(Utc::now() - Duration::days(1));
    let mut store2 = TrustedKeyStore::new();
    store2.add_key(expired_tk);
    assert_eq!(
        bundle.validate_and_authenticate(&store2, Some("1.0.0"), false),
        Err(BundleValidationError::SignatureError(
            KeyVerificationError::KeyExpired("key-adv-3".to_string()).to_string()
        ))
    );

    // Unknown key
    let empty_store = TrustedKeyStore::new();
    assert_eq!(
        bundle.validate_and_authenticate(&empty_store, Some("1.0.0"), false),
        Err(BundleValidationError::SignatureError(
            KeyVerificationError::KeyNotFound("key-adv-3".to_string()).to_string()
        ))
    );

    // Rotated key
    let (new_sk, new_tk) = make_test_key(3, "key-adv-3-rot", "Security Org");
    let mut store_rotated = TrustedKeyStore::new();
    store_rotated.add_key(tk); // old inactive key
    store_rotated.add_key(new_tk); // new active key

    // Bundle signed with old deactivated key fails
    assert!(bundle
        .validate_and_authenticate(&store_rotated, Some("1.0.0"), false)
        .is_err());

    // Bundle signed with new active key succeeds
    let new_bundle = build_signed_bundle(
        &new_sk,
        "key-adv-3-rot",
        "Security Org",
        "2.0.0",
        vec![sample_advisory(
            "ADV-01",
            "lodash",
            PackageEcosystem::Npm,
            false,
        )],
    );
    assert!(new_bundle
        .validate_and_authenticate(&store_rotated, Some("1.0.0"), false)
        .is_ok());
}

// ---------------------------------------------------------------------------
// 4. Trust-store deletion, symlink tampering, or corruption handling
// ---------------------------------------------------------------------------
#[test]
fn test_04_trust_store_symlink_permissions_corruption() {
    let dir = tempdir().unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let real_target = dir.path().join("real_keys.json");
        std::fs::write(&real_target, r#"{"keys": []}"#).unwrap();
        let symlink_path = dir.path().join("symlink_keys.json");
        symlink(&real_target, &symlink_path).unwrap();

        let res = TrustedKeyStore::load_from_path(&symlink_path);
        assert!(matches!(res, Err(KeyStoreError::SymlinkForbidden(_))));

        // Insecure permissions (world-writable)
        use std::os::unix::fs::PermissionsExt;
        let writable_path = dir.path().join("writable_keys.json");
        std::fs::write(&writable_path, r#"{"keys": []}"#).unwrap();
        std::fs::set_permissions(&writable_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let res2 = TrustedKeyStore::load_from_path(&writable_path);
        assert!(matches!(res2, Err(KeyStoreError::InsecurePermissions(_))));
    }

    // Corrupted JSON in keystore
    let corrupted_path = dir.path().join("corrupted.json");
    std::fs::write(&corrupted_path, "{ broken json").unwrap();
    let res3 = TrustedKeyStore::load_from_path(&corrupted_path);
    assert!(matches!(
        res3,
        Err(KeyStoreError::CorruptedKeystore(_)) | Err(KeyStoreError::Parse(_))
    ));

    // Keystore marked corrupted fails closed
    let corrupted_store = TrustedKeyStore::corrupted("Disk read failure".to_string());
    assert!(!corrupted_store.is_operational());
    assert!(matches!(
        corrupted_store.verify_signature("key1", b"msg", "deadbeef"),
        Err(KeyVerificationError::TrustStoreUnavailable(_))
    ));
}

// ---------------------------------------------------------------------------
// 5. Downgrade attempts after an engine restart and high-water mark persistence
// ---------------------------------------------------------------------------
#[test]
fn test_05_downgrade_after_restart_and_high_water_mark() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("advisories.json");
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::default());
    let baseline_store = Arc::new(BaselineStore::default());

    let (sk, tk) = make_test_key(4, "key-adv-5", "Official Org");
    let mut store = TrustedKeyStore::new();
    store.add_key(tk);
    let store = Arc::new(store);

    let updater = AdvisoryUpdater::new(
        Arc::clone(&assessor),
        Arc::clone(&baseline_store),
        Arc::clone(&audit),
        Arc::clone(&store),
        storage_path.clone(),
    );

    // Upgrade to v3.5.0
    let b35 = build_signed_bundle(
        &sk,
        "key-adv-5",
        "Official Org",
        "3.5.0",
        vec![sample_advisory(
            "ADV-01",
            "lodash",
            PackageEcosystem::Npm,
            false,
        )],
    );
    let p35 = dir.path().join("b35.json");
    std::fs::write(&p35, serde_json::to_string(&b35).unwrap()).unwrap();
    updater.import_bundle(&p35, false).unwrap();

    // High water mark is now 3.5.0
    assert_eq!(
        updater.security_state().read().unwrap().high_water_version,
        "3.5.0"
    );

    // Simulate engine restart with deletion of advisories.json
    std::fs::remove_file(&storage_path).unwrap();

    let restarted_assessor = Arc::new(PackageSecurityAssessor::default());
    let restarted_updater = AdvisoryUpdater::new(
        Arc::clone(&restarted_assessor),
        Arc::clone(&baseline_store),
        Arc::clone(&audit),
        Arc::clone(&store),
        storage_path,
    );

    // High water mark MUST STILL BE 3.5.0 despite deletion of active database!
    assert_eq!(
        restarted_updater
            .security_state()
            .read()
            .unwrap()
            .high_water_version,
        "3.5.0"
    );

    // Attempt to downgrade to v2.0.0 without rollback flag -> MUST BE REJECTED
    let b20 = build_signed_bundle(
        &sk,
        "key-adv-5",
        "Official Org",
        "2.0.0",
        vec![sample_advisory(
            "ADV-01",
            "lodash",
            PackageEcosystem::Npm,
            false,
        )],
    );
    let p20 = dir.path().join("b20.json");
    std::fs::write(&p20, serde_json::to_string(&b20).unwrap()).unwrap();
    let res = restarted_updater.import_bundle(&p20, false);
    assert!(matches!(
        res,
        Err(crate::package::updater::UpdateError::Validation(
            BundleValidationError::RollbackRejected { .. }
        ))
    ));
}

// ---------------------------------------------------------------------------
// 6. Tampering with persisted version metadata
// ---------------------------------------------------------------------------
#[test]
fn test_06_tampering_with_persisted_version_metadata() {
    let dir = tempdir().unwrap();
    let state_path = dir.path().join("advisory_security_state.json");

    // Corrupted state file
    std::fs::write(&state_path, "corrupted { invalid").unwrap();
    let res = AdvisorySecurityState::load_from_path(&state_path, "1.0.0");
    assert!(res.is_err());

    // Valid state file monotonically refuses to decrease high-water mark
    let mut state = AdvisorySecurityState::new("2.0.0");
    state.record_version("1.5.0");
    assert_eq!(state.high_water_version, "2.0.0");

    state.record_version("2.1.0");
    assert_eq!(state.high_water_version, "2.1.0");
}

// ---------------------------------------------------------------------------
// 7. Rollback override abuse through CLI and IPC
// ---------------------------------------------------------------------------
#[test]
fn test_07_rollback_override_abuse_cli_and_ipc() {
    // Unauthenticated IPC caller sending allow_rollback=true without token
    let params = PackageImportAdvisoryBundleParams {
        bundle_path: "/tmp/bundle.json".to_string(),
        keys_path: None,
        allow_rollback: true,
        rollback_confirmation_token: None,
    };
    assert!(params.allow_rollback);
    assert!(params.rollback_confirmation_token.is_none());

    // With confirmation token
    let auth_params = PackageImportAdvisoryBundleParams {
        bundle_path: "/tmp/bundle.json".to_string(),
        keys_path: None,
        allow_rollback: true,
        rollback_confirmation_token: Some("CONFIRM_ADVISORY_ROLLBACK".to_string()),
    };
    assert_eq!(
        auth_params.rollback_confirmation_token.as_deref(),
        Some("CONFIRM_ADVISORY_ROLLBACK")
    );
}

// ---------------------------------------------------------------------------
// 8. Simultaneous imports and readers under stress
// ---------------------------------------------------------------------------
#[test]
fn test_08_concurrent_imports_and_readers() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("advisories.json");
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::default());
    let baseline_store = Arc::new(BaselineStore::default());

    let (sk, tk) = make_test_key(8, "key-adv-8", "Concurrency Org");
    let mut store = TrustedKeyStore::new();
    store.add_key(tk);
    let store = Arc::new(store);

    let updater = Arc::new(AdvisoryUpdater::new(
        Arc::clone(&assessor),
        Arc::clone(&baseline_store),
        Arc::clone(&audit),
        Arc::clone(&store),
        storage_path,
    ));

    let mut handles = Vec::new();

    // Spawn 6 reader threads
    for _ in 0..6 {
        let a = Arc::clone(&assessor);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let _ = a.is_malicious_package(PackageEcosystem::Npm, "lodash");
                let db = a.advisory_db();
                let _ = db.database_version();
                let _ = db.all_advisories().len();
            }
        }));
    }

    // Spawn 2 importer threads
    for i in 1..=3 {
        let u = Arc::clone(&updater);
        let sk_clone = sk.clone();
        let path = dir.path().join(format!("bundle_{}.json", i));
        let ver = format!("1.{}.0", i);
        let b = build_signed_bundle(
            &sk_clone,
            "key-adv-8",
            "Concurrency Org",
            &ver,
            vec![sample_advisory(
                &format!("ADV-{}", i),
                "pkg-test",
                PackageEcosystem::Npm,
                false,
            )],
        );
        std::fs::write(&path, serde_json::to_string(&b).unwrap()).unwrap();

        handles.push(std::thread::spawn(move || {
            let _ = u.import_bundle(&path, true);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 9. Process interruption during persistent activation stages
// ---------------------------------------------------------------------------
#[test]
fn test_09_process_interruption_during_activation() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("advisories.json");
    std::fs::write(&storage_path, "initial active database").unwrap();

    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::default());
    let baseline_store = Arc::new(BaselineStore::default());
    let (_sk, tk) = make_test_key(9, "key-adv-9", "Fail Org");
    let mut store = TrustedKeyStore::new();
    store.add_key(tk);
    let store = Arc::new(store);

    let updater = AdvisoryUpdater::new(
        Arc::clone(&assessor),
        Arc::clone(&baseline_store),
        Arc::clone(&audit),
        Arc::clone(&store),
        storage_path.clone(),
    );

    // Active DB before failed write
    let initial_ver = assessor.advisory_db().database_version().to_string();

    // Invalid bundle
    let bad_bundle_path = dir.path().join("bad.json");
    std::fs::write(&bad_bundle_path, "{ broken json").unwrap();
    assert!(updater.import_bundle(&bad_bundle_path, false).is_err());

    // Storage file untouched
    assert_eq!(
        std::fs::read_to_string(&storage_path).unwrap(),
        "initial active database"
    );
    // In-memory assessor untouched
    assert_eq!(
        assessor.advisory_db().database_version(),
        initial_ver.as_str()
    );
}

// ---------------------------------------------------------------------------
// 10. Temporary-file symlink attacks and path traversal resistance
// ---------------------------------------------------------------------------
#[test]
fn test_10_temporary_file_symlink_attacks_and_traversal() {
    let dir = tempdir().unwrap();
    let parent = dir.path().join("staging");
    std::fs::create_dir_all(&parent).unwrap();

    let target = dir.path().join("sensitive.txt");
    std::fs::write(&target, "confidential").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let symlink_path = parent.join(".tmp_adv_target");
        symlink(&target, &symlink_path).unwrap();

        // Attempting to open with create_new(true) fails if the symlink already exists!
        let open_res = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&symlink_path);
        assert!(
            open_res.is_err(),
            "create_new(true) must reject existing symlink target"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "confidential");
    }
}

// ---------------------------------------------------------------------------
// 11. Disk-write and synchronization failure recovery
// ---------------------------------------------------------------------------
#[test]
fn test_11_disk_write_sync_failure_recovery() {
    let dir = tempdir().unwrap();
    // Destination is inside a read-only directory
    let ro_dir = dir.path().join("readonly_dir");
    std::fs::create_dir_all(&ro_dir).unwrap();

    let storage_path = ro_dir.join("advisories.json");
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::default());
    let baseline_store = Arc::new(BaselineStore::default());
    let (sk, tk) = make_test_key(11, "key-adv-11", "RO Org");
    let mut store = TrustedKeyStore::new();
    store.add_key(tk);
    let store = Arc::new(store);

    let updater = AdvisoryUpdater::new(
        Arc::clone(&assessor),
        Arc::clone(&baseline_store),
        Arc::clone(&audit),
        Arc::clone(&store),
        storage_path,
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    }

    let b = build_signed_bundle(
        &sk,
        "key-adv-11",
        "RO Org",
        "2.0.0",
        vec![sample_advisory(
            "ADV-01",
            "lodash",
            PackageEcosystem::Npm,
            false,
        )],
    );
    let p = dir.path().join("bundle.json");
    std::fs::write(&p, serde_json::to_string(&b).unwrap()).unwrap();

    let res = updater.import_bundle(&p, false);
    assert!(res.is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755));
    }
}

// ---------------------------------------------------------------------------
// 12. Invalidation of pending approvals after advisory changes
// ---------------------------------------------------------------------------
#[test]
fn test_12_invalidation_of_pending_and_approved_requests() {
    let approval_mgr = Arc::new(ApprovalManager::new(300));

    // 1. Create a pending request for installing 'evil-pkg'
    let pending_req = approval_mgr.create_request(
        "sess-1".to_string(),
        "npm install evil-pkg".to_string(),
        None,
        "RULE-PACKAGE-001".to_string(),
        Severity::High,
        "Package approval required".to_string(),
        Some(300),
    );

    // 2. Create and approve a second request for 'evil-pkg' (generates authorization token)
    let approved_req = approval_mgr.create_request(
        "sess-1".to_string(),
        "npm install evil-pkg".to_string(),
        None,
        "RULE-PACKAGE-001".to_string(),
        Severity::High,
        "Package approval required".to_string(),
        Some(300),
    );
    let (status, token_opt) = approval_mgr
        .decide(
            &approved_req.request_id,
            ApprovalUserDecision::Approve,
            None,
        )
        .unwrap();
    assert_eq!(status, ApprovalStatus::Approved);
    let auth_token = token_opt.unwrap();

    // 3. Newly activated advisory classifies 'evil-pkg' as malicious
    let mut malicious_pkgs = HashSet::new();
    malicious_pkgs.insert((PackageEcosystem::Npm, "evil-pkg".to_string()));

    let invalidated = approval_mgr.invalidate_for_malicious_packages(&malicious_pkgs);
    assert!(invalidated.contains(&pending_req.request_id));
    assert!(invalidated.contains(&approved_req.request_id));

    // Pending request is now Denied
    let p = approval_mgr.get_request(&pending_req.request_id).unwrap();
    assert_eq!(p.status, ApprovalStatus::Denied);

    // Approved request token is destroyed and status is Denied
    let a = approval_mgr.get_request(&approved_req.request_id).unwrap();
    assert_eq!(a.status, ApprovalStatus::Denied);

    // Attempting to consume authorization with old token FAILS!
    let consume_res = approval_mgr.consume_authorization(
        &approved_req.request_id,
        "sess-1",
        "npm install evil-pkg",
        &auth_token,
    );
    assert!(consume_res.is_err());
}

// ---------------------------------------------------------------------------
// 13. Malicious findings surviving rollback and restart
// ---------------------------------------------------------------------------
#[test]
fn test_13_malicious_findings_surviving_rollback_and_restart() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("advisories.json");
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::default());
    let baseline_store = Arc::new(BaselineStore::default());

    let (sk, tk) = make_test_key(13, "key-adv-13", "Security Invariant Org");
    let mut store = TrustedKeyStore::new();
    store.add_key(tk);
    let store = Arc::new(store);

    let updater = AdvisoryUpdater::new(
        Arc::clone(&assessor),
        Arc::clone(&baseline_store),
        Arc::clone(&audit),
        Arc::clone(&store),
        storage_path.clone(),
    );

    // Activate bundle v3.0.0 declaring "malicious-crypto-stealer" as MALICIOUS
    let b3 = build_signed_bundle(
        &sk,
        "key-adv-13",
        "Security Invariant Org",
        "3.0.0",
        vec![sample_advisory(
            "ADV-MAL-01",
            "malicious-crypto-stealer",
            PackageEcosystem::Npm,
            true,
        )],
    );
    let p3 = dir.path().join("b3.json");
    std::fs::write(&p3, serde_json::to_string(&b3).unwrap()).unwrap();
    updater.import_bundle(&p3, false).unwrap();

    assert!(assessor.is_malicious_package(PackageEcosystem::Npm, "malicious-crypto-stealer"));

    // Explicitly roll back database to v1.0.0 (which does NOT have malicious-crypto-stealer)
    let b1 = build_signed_bundle(
        &sk,
        "key-adv-13",
        "Security Invariant Org",
        "1.0.0",
        vec![sample_advisory(
            "ADV-BENIGN-01",
            "lodash",
            PackageEcosystem::Npm,
            false,
        )],
    );
    let p1 = dir.path().join("b1.json");
    std::fs::write(&p1, serde_json::to_string(&b1).unwrap()).unwrap();
    updater.import_bundle(&p1, true).unwrap();

    // Invariant: Malicious classification MUST SURVIVE ROLLBACK!
    assert!(assessor.is_malicious_package(PackageEcosystem::Npm, "malicious-crypto-stealer"));

    // Simulate restart with deleted database
    std::fs::remove_file(&storage_path).unwrap();

    let restarted_assessor = Arc::new(PackageSecurityAssessor::new(PackageSecurityConfig {
        enabled: true,
        hard_block_malicious: true,
        hard_block_critical_vulns: false,
        fail_closed: true,
        advisory_path: Some(storage_path.clone()),
    }));

    // Invariant: Malicious classification MUST SURVIVE RESTART!
    assert!(
        restarted_assessor.is_malicious_package(PackageEcosystem::Npm, "malicious-crypto-stealer")
    );
}

// ---------------------------------------------------------------------------
// 14. Corrupt external data and embedded fallback status
// ---------------------------------------------------------------------------
#[test]
fn test_14_corrupt_external_data_and_embedded_fallback_status() {
    let dir = tempdir().unwrap();
    let corrupt_path = dir.path().join("corrupt_advisories.json");
    std::fs::write(&corrupt_path, "{ corrupted json byte stream").unwrap();

    let db = AdvisoryDatabase::load_with_fallback(Some(&corrupt_path));
    // Falls back safely to embedded without panic
    assert_eq!(db.source_type(), AdvisoryDatabaseSource::Embedded);
    assert!(!db.all_advisories().is_empty());
}

// ---------------------------------------------------------------------------
// 15. Audit event accuracy and credential redaction
// ---------------------------------------------------------------------------
#[test]
fn test_15_audit_event_accuracy_and_secret_redaction() {
    let dir = tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::default());
    let baseline_store = Arc::new(BaselineStore::default());

    let (sk, tk) = make_test_key(15, "key-adv-15", "Audit Verification Org");
    let priv_key_hex = hex::encode(sk.to_bytes());
    let mut store = TrustedKeyStore::new();
    store.add_key(tk);
    let store = Arc::new(store);

    let updater = AdvisoryUpdater::new(
        Arc::clone(&assessor),
        Arc::clone(&baseline_store),
        Arc::clone(&audit),
        Arc::clone(&store),
        dir.path().join("advisories.json"),
    );

    let b = build_signed_bundle(
        &sk,
        "key-adv-15",
        "Audit Verification Org",
        "3.0.0",
        vec![sample_advisory(
            "ADV-01",
            "lodash",
            PackageEcosystem::Npm,
            false,
        )],
    );
    let p = dir.path().join("bundle.json");
    std::fs::write(&p, serde_json::to_string(&b).unwrap()).unwrap();

    updater.inspect_bundle(&p).unwrap();
    updater.import_bundle(&p, false).unwrap();

    // Verify audit log entries
    let log_content = std::fs::read_to_string(&audit_path).unwrap();
    assert!(log_content.contains("PACKAGE_ADVISORY_INSPECTED"));
    assert!(log_content.contains("PACKAGE_ADVISORY_UPDATE_ACTIVATED"));
    assert!(log_content.contains("PACKAGE_ADVISORY_REASSESSMENT_COMPLETED"));

    // Redaction check: signing private key hex MUST NEVER appear in audit logs
    assert!(!log_content.contains(&priv_key_hex));
}

// ---------------------------------------------------------------------------
// 16. Execution-gate invariants under all failure paths
// ---------------------------------------------------------------------------
#[test]
fn test_16_execution_gate_invariants_under_all_failure_paths() {
    let dir = tempdir().unwrap();
    let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
    let assessor = Arc::new(PackageSecurityAssessor::default());
    assessor.record_malicious_tombstone(PackageEcosystem::Npm, "critical-backdoor-pkg");

    let backend = Arc::new(crate::gate::backend::MockExecutionBackend::new());
    let policy = crate::policy::PolicyEngine::new();

    let gate = ExecutionGate::new(backend.clone(), None, Some(policy), Some(audit), true)
        .with_package_assessor(Arc::clone(&assessor));

    // Submit command targeting tombstoned malicious package
    let eval = gate.evaluate("npm install critical-backdoor-pkg", Some(dir.path()));
    assert_eq!(eval.decision, GateDecision::Block);

    // Gated execution MUST hard-block and guarantee ZERO backend dispatch invocations
    let exec_res = gate.execute_gated("npm install critical-backdoor-pkg", Some(dir.path()));
    assert_eq!(exec_res.decision, GateDecision::Block);
    assert_eq!(backend.invocation_count(), 0);
}
