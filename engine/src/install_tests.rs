// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::install::*;
use crate::release::{
    compute_sha256, BuildMetadata, CyravellReleaseManifest, ReleaseArtifact, ReleaseKey,
    ReleaseKeyStore, SbomReference,
};
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn generate_test_key(
    seed_byte: u8,
    key_id: &str,
    active: bool,
    expired: bool,
    is_official: bool,
) -> (SigningKey, ReleaseKey) {
    let seed = [seed_byte; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pub_hex = hex::encode(verifying_key.to_bytes());

    let expires_at = if expired {
        Some((Utc::now() - Duration::days(1)).to_rfc3339())
    } else {
        Some((Utc::now() + Duration::days(365)).to_rfc3339())
    };

    let rel_key = ReleaseKey {
        key_id: key_id.to_string(),
        publisher: format!("Publisher for {}", key_id),
        public_key_hex: pub_hex,
        algorithm: "ed25519".to_string(),
        created_at: Utc::now().to_rfc3339(),
        expires_at,
        is_active: active,
        is_official,
    };

    (signing_key, rel_key)
}

fn create_test_release_package(
    release_dir: &Path,
    version: &str,
    commit: &str,
    signing_key: &SigningKey,
    key_id: &str,
    failing_binary: bool,
) -> CyravellReleaseManifest {
    fs::create_dir_all(release_dir).expect("create release_dir");

    // 1. Create engine binary
    let engine_path = release_dir.join("cyravell-engine-x86_64-unknown-linux-gnu");
    let script_content = if failing_binary {
        "#!/bin/sh\nexit 1\n"
    } else {
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\necho \"cyravell-engine 0.1.0\"\nexit 0\nfi\nexit 0\n"
    };
    fs::write(&engine_path, script_content).expect("write engine bin");
    fs::set_permissions(&engine_path, fs::Permissions::from_mode(0o755)).expect("chmod engine");

    let engine_sha = compute_sha256(&engine_path).expect("engine sha");
    let engine_meta = fs::metadata(&engine_path).expect("engine meta");

    // 2. Create harness binary
    let harness_path = release_dir.join("cyravell-test-harness-x86_64-unknown-linux-gnu");
    fs::write(&harness_path, "#!/bin/sh\nexit 0\n").expect("write harness bin");
    fs::set_permissions(&harness_path, fs::Permissions::from_mode(0o755)).expect("chmod harness");

    let harness_sha = compute_sha256(&harness_path).expect("harness sha");
    let harness_meta = fs::metadata(&harness_path).expect("harness meta");

    // 3. Create rules bundle tar.gz
    let rules_temp = release_dir.join("temp_rules_src");
    let rules_sub = rules_temp.join("rules");
    fs::create_dir_all(&rules_sub).expect("create rules sub");
    fs::write(
        rules_sub.join("baseline_rules.json"),
        b"{\"rules\": [\"test\"]}",
    )
    .expect("write rule");

    let tar_path = release_dir.join("cyravell-rules-bundle.tar.gz");
    let tar_status = Command::new("tar")
        .arg("-czf")
        .arg(&tar_path)
        .arg("-C")
        .arg(&rules_temp)
        .arg("rules")
        .status()
        .expect("run tar");
    assert!(tar_status.success(), "tar creation failed");
    let _ = fs::remove_dir_all(&rules_temp);

    let tar_sha = compute_sha256(&tar_path).expect("tar sha");
    let tar_meta = fs::metadata(&tar_path).expect("tar meta");

    // 4. Create SBOM file
    let sbom_path = release_dir.join("cyravell-sbom.spdx.json");
    fs::write(&sbom_path, b"{\"spdxVersion\":\"SPDX-2.3\"}").expect("write sbom");
    let sbom_sha = compute_sha256(&sbom_path).expect("sbom sha");

    // 5. Assemble artifacts map
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "cyravell-engine-x86_64-unknown-linux-gnu".to_string(),
        ReleaseArtifact {
            filename: "cyravell-engine-x86_64-unknown-linux-gnu".to_string(),
            size_bytes: engine_meta.len(),
            sha256: engine_sha,
            artifact_type: "binary".to_string(),
            target_platform: Some("x86_64-unknown-linux-gnu".to_string()),
        },
    );
    artifacts.insert(
        "cyravell-test-harness-x86_64-unknown-linux-gnu".to_string(),
        ReleaseArtifact {
            filename: "cyravell-test-harness-x86_64-unknown-linux-gnu".to_string(),
            size_bytes: harness_meta.len(),
            sha256: harness_sha,
            artifact_type: "binary".to_string(),
            target_platform: Some("x86_64-unknown-linux-gnu".to_string()),
        },
    );
    artifacts.insert(
        "cyravell-rules-bundle.tar.gz".to_string(),
        ReleaseArtifact {
            filename: "cyravell-rules-bundle.tar.gz".to_string(),
            size_bytes: tar_meta.len(),
            sha256: tar_sha,
            artifact_type: "rules".to_string(),
            target_platform: None,
        },
    );

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: version.to_string(),
        source_commit: commit.to_string(),
        source_tag: Some(format!("v{}", version)),
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: version.to_string(),
        extension_version: version.to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec!["rules/baseline_rules.json".to_string()],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: Some("v18.19.1".to_string()),
            build_profile: "release".to_string(),
            source_date_epoch: Some(1767225600),
        },
        sbom: SbomReference {
            filename: "cyravell-sbom.spdx.json".to_string(),
            format: "SPDX-2.3".to_string(),
            sha256: sbom_sha,
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    manifest.sign(signing_key, key_id);

    let manifest_path = release_dir.join("release_manifest.json");
    let json_bytes = serde_json::to_vec_pretty(&manifest).expect("serialize manifest");
    fs::write(&manifest_path, json_bytes).expect("write manifest");

    manifest
}

#[test]
fn test_01_simple_semver_comparisons_and_parsing() {
    let v1 = SimpleSemVer::parse("0.1.0").expect("parse 0.1.0");
    let v2 = SimpleSemVer::parse("v0.2.0").expect("parse v0.2.0");
    let v3 = SimpleSemVer::parse("1.0.0").expect("parse 1.0.0");
    let v_pre = SimpleSemVer::parse("1.0.0-rc1").expect("parse 1.0.0-rc1");

    assert!(v1 < v2);
    assert!(v2 < v3);
    assert!(v_pre < v3);
    assert_eq!(v1, SimpleSemVer::parse("0.1.0").unwrap());

    assert!(SimpleSemVer::parse("invalid").is_err());
    assert!(SimpleSemVer::parse("1.0").is_err());
    assert!(SimpleSemVer::parse("1.0.0.0").is_err());
}

#[test]
fn test_02_successful_clean_installation() {
    let temp = tempdir().expect("tempdir");
    let rel_dir = temp.path().join("release");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(10, "cyravell-official-test", true, false, true);
    create_test_release_package(
        &rel_dir,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let options = InstallOptions {
        release_dir: rel_dir,
        install_prefix: install_prefix.clone(),
        is_user_mode: true,
        allow_dev_keys: false,
        allow_downgrade: false,
        operator_reason: None,
        expected_version: Some("0.1.0".to_string()),
        expected_commit: None,
        skip_post_install_test: false,
        custom_keystore: Some(keystore),
    };

    let report = install_or_update(&options).expect("install_or_update failed");
    assert!(report.success);
    assert_eq!(report.operation, "install");
    assert_eq!(report.active_version, Some("0.1.0".to_string()));

    // Verify binary permissions and existence
    let active_bin = install_prefix.join("bin/cyravell-engine");
    assert!(active_bin.exists());
    let bin_mode = fs::metadata(&active_bin).unwrap().permissions().mode() & 0o777;
    assert_eq!(bin_mode, 0o755);

    // Verify harness
    let active_harness = install_prefix.join("bin/cyravell-test-harness");
    assert!(active_harness.exists());

    // Verify rules
    let active_rule = install_prefix.join("share/cyravell/rules/baseline_rules.json");
    assert!(active_rule.exists());
    let rule_mode = fs::metadata(&active_rule).unwrap().permissions().mode() & 0o777;
    assert_eq!(rule_mode, 0o644);

    // Verify install state
    let state_file = install_prefix.join("share/cyravell/install_state.json");
    let state = InstallState::load_from_path(&state_file).expect("load state");
    assert_eq!(state.active_version, "0.1.0");
    assert_eq!(state.high_water_version, "0.1.0");
    assert!(state.is_official);
    assert_eq!(state.backup_version, None);
}

#[test]
fn test_03_tampered_release_artifact_rejected_before_install() {
    let temp = tempdir().expect("tempdir");
    let rel_dir = temp.path().join("release");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(11, "cyravell-official-test", true, false, true);
    create_test_release_package(
        &rel_dir,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    // Tamper with binary after signing
    let bin_path = rel_dir.join("cyravell-engine-x86_64-unknown-linux-gnu");
    let mut f = fs::OpenOptions::new().append(true).open(&bin_path).unwrap();
    f.write_all(b"\n# Tampered payload").unwrap();
    drop(f);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let options = InstallOptions {
        release_dir: rel_dir,
        install_prefix: install_prefix.clone(),
        is_user_mode: true,
        allow_dev_keys: false,
        allow_downgrade: false,
        operator_reason: None,
        expected_version: None,
        expected_commit: None,
        skip_post_install_test: false,
        custom_keystore: Some(keystore),
    };

    let result = install_or_update(&options);
    assert!(result.is_err());
    match result.unwrap_err() {
        InstallError::ReleaseVerificationFailed(_) => {}
        err => panic!("Expected ReleaseVerificationFailed, got: {:?}", err),
    }

    // Ensure zero files were installed
    assert!(!install_prefix.join("bin/cyravell-engine").exists());
    assert!(!install_prefix
        .join("share/cyravell/install_state.json")
        .exists());
}

#[test]
fn test_04_untrusted_dev_key_rejected_in_official_mode() {
    let temp = tempdir().expect("tempdir");
    let rel_dir = temp.path().join("release");
    let install_prefix = temp.path().join("installed");

    // Dev key with is_official = false
    let (dev_signing, dev_rel_key) = generate_test_key(12, "cyravell-dev-test", true, false, false);
    create_test_release_package(
        &rel_dir,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &dev_signing,
        &dev_rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(dev_rel_key);

    let mut options = InstallOptions {
        release_dir: rel_dir.clone(),
        install_prefix: install_prefix.clone(),
        is_user_mode: true,
        allow_dev_keys: false, // Disallow dev keys
        allow_downgrade: false,
        operator_reason: None,
        expected_version: None,
        expected_commit: None,
        skip_post_install_test: false,
        custom_keystore: Some(keystore.clone()),
    };

    let result = install_or_update(&options);
    assert!(result.is_err());
    match result.unwrap_err() {
        InstallError::UntrustedKey(_) => {}
        err => panic!("Expected UntrustedKey, got: {:?}", err),
    }

    // Now allow dev keys: installation must succeed
    options.allow_dev_keys = true;
    let report = install_or_update(&options).expect("install with dev key allowed");
    assert!(report.success);
}

#[test]
fn test_05_downgrade_rejected_without_authorization() {
    let temp = tempdir().expect("tempdir");
    let rel_dir_v2 = temp.path().join("release_v2");
    let rel_dir_v1 = temp.path().join("release_v1");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(13, "cyravell-official-test", true, false, true);

    create_test_release_package(
        &rel_dir_v2,
        "0.2.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    create_test_release_package(
        &rel_dir_v1,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    // 1. Install 0.2.0
    let mut opts_v2 = InstallOptions::default();
    opts_v2.release_dir = rel_dir_v2;
    opts_v2.install_prefix = install_prefix.clone();
    opts_v2.custom_keystore = Some(keystore.clone());
    install_or_update(&opts_v2).expect("install 0.2.0");

    // 2. Attempt downgrade to 0.1.0 without --allow-downgrade
    let mut opts_v1 = InstallOptions::default();
    opts_v1.release_dir = rel_dir_v1;
    opts_v1.install_prefix = install_prefix.clone();
    opts_v1.allow_downgrade = false;
    opts_v1.custom_keystore = Some(keystore);

    let err = install_or_update(&opts_v1).unwrap_err();
    match err {
        InstallError::DowngradeRejected { active, candidate } => {
            assert_eq!(active, "0.2.0");
            assert_eq!(candidate, "0.1.0");
        }
        _ => panic!("Expected DowngradeRejected, got {:?}", err),
    }

    // Verify active installation remains 0.2.0
    let state_file = install_prefix.join("share/cyravell/install_state.json");
    let state = InstallState::load_from_path(&state_file).unwrap();
    assert_eq!(state.active_version, "0.2.0");
}

#[test]
fn test_06_authorized_downgrade_succeeds_and_preserves_high_water_mark() {
    let temp = tempdir().expect("tempdir");
    let rel_dir_v2 = temp.path().join("release_v2");
    let rel_dir_v1 = temp.path().join("release_v1");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(14, "cyravell-official-test", true, false, true);

    create_test_release_package(
        &rel_dir_v2,
        "0.2.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    create_test_release_package(
        &rel_dir_v1,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    // Install 0.2.0
    let mut opts = InstallOptions::default();
    opts.release_dir = rel_dir_v2;
    opts.install_prefix = install_prefix.clone();
    opts.custom_keystore = Some(keystore.clone());
    install_or_update(&opts).expect("install 0.2.0");

    // Authorized downgrade to 0.1.0 with sufficient reason
    let mut down_opts = InstallOptions::default();
    down_opts.release_dir = rel_dir_v1;
    down_opts.install_prefix = install_prefix.clone();
    down_opts.allow_downgrade = true;
    down_opts.operator_reason =
        Some("Emergency incident rollback to 0.1.0 due to regression".to_string());
    down_opts.custom_keystore = Some(keystore);

    let report = install_or_update(&down_opts).expect("downgrade should succeed");
    assert!(report.success);
    assert_eq!(report.active_version, Some("0.1.0".to_string()));

    // Verify high-water mark remains 0.2.0
    let state_file = install_prefix.join("share/cyravell/install_state.json");
    let state = InstallState::load_from_path(&state_file).unwrap();
    assert_eq!(state.active_version, "0.1.0");
    assert_eq!(state.high_water_version, "0.2.0");
}

#[test]
fn test_07_invalid_downgrade_reason_rejected() {
    let temp = tempdir().expect("tempdir");
    let rel_dir_v2 = temp.path().join("release_v2");
    let rel_dir_v1 = temp.path().join("release_v1");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(15, "cyravell-official-test", true, false, true);

    create_test_release_package(
        &rel_dir_v2,
        "0.2.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    create_test_release_package(
        &rel_dir_v1,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let mut opts = InstallOptions::default();
    opts.release_dir = rel_dir_v2;
    opts.install_prefix = install_prefix.clone();
    opts.custom_keystore = Some(keystore.clone());
    install_or_update(&opts).expect("install 0.2.0");

    let mut down_opts = InstallOptions::default();
    down_opts.release_dir = rel_dir_v1;
    down_opts.install_prefix = install_prefix;
    down_opts.allow_downgrade = true;
    down_opts.operator_reason = Some("short".to_string()); // < 8 characters
    down_opts.custom_keystore = Some(keystore);

    let err = install_or_update(&down_opts).unwrap_err();
    match err {
        InstallError::InvalidDowngradeReason(_) => {}
        _ => panic!("Expected InvalidDowngradeReason, got {:?}", err),
    }
}

#[test]
fn test_08_symlink_destination_attack_rejected() {
    let temp = tempdir().expect("tempdir");
    let rel_dir = temp.path().join("release");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(16, "cyravell-official-test", true, false, true);

    create_test_release_package(
        &rel_dir,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    // Pre-create bin directory with a malicious symlink pointing to an arbitrary file
    let bin_dir = install_prefix.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let victim_target = temp.path().join("victim.txt");
    fs::write(&victim_target, b"original content").unwrap();

    let symlink_path = bin_dir.join("cyravell-engine");
    std::os::unix::fs::symlink(&victim_target, &symlink_path).unwrap();

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let mut opts = InstallOptions::default();
    opts.release_dir = rel_dir;
    opts.install_prefix = install_prefix;
    opts.custom_keystore = Some(keystore);

    let err = install_or_update(&opts).unwrap_err();
    match err {
        InstallError::SecurityViolation(msg) => {
            assert!(msg.contains("symbolic link"));
        }
        _ => panic!("Expected SecurityViolation, got {:?}", err),
    }

    // Ensure victim file was NOT overwritten
    assert_eq!(fs::read(&victim_target).unwrap(), b"original content");
}

#[test]
fn test_09_path_traversal_in_rules_bundle_rejected() {
    let temp = tempdir().expect("tempdir");
    let malicious_tar = temp.path().join("malicious.tar.gz");
    let extract_dir = temp.path().join("extracted");

    // Create a tarball containing an entry with "../"
    let dummy_src = temp.path().join("dummy.txt");
    fs::write(&dummy_src, b"evil").unwrap();

    // Use python to create a tarfile with path traversal entry
    let py_script = format!(
        "import tarfile\nwith tarfile.open('{}', 'w:gz') as tar:\n    tar.add('{}', arcname='../evil.txt')",
        malicious_tar.display(),
        dummy_src.display()
    );

    let status = Command::new("python3")
        .arg("-c")
        .arg(&py_script)
        .status()
        .expect("create malicious tar");
    assert!(status.success());

    let res = safe_unpack_rules_bundle(&malicious_tar, &extract_dir);
    assert!(res.is_err());
    match res.unwrap_err() {
        InstallError::SecurityViolation(msg) => {
            assert!(msg.contains("traversal"));
        }
        err => panic!("Expected SecurityViolation, got {:?}", err),
    }
}

#[test]
fn test_10_concurrency_lock_prevents_simultaneous_install() {
    let temp = tempdir().expect("tempdir");
    let rel_dir = temp.path().join("release");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(17, "cyravell-official-test", true, false, true);
    create_test_release_package(
        &rel_dir,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let share_dir = install_prefix.join("share/cyravell");
    // Manually acquire lock guard
    let guard = InstallLockGuard::acquire(&share_dir).expect("acquire initial lock");

    let mut opts = InstallOptions::default();
    opts.release_dir = rel_dir;
    opts.install_prefix = install_prefix;
    opts.custom_keystore = Some(keystore);

    // Attempt second install while lock is held
    let err = install_or_update(&opts).unwrap_err();
    match err {
        InstallError::LockBusy(_) => {}
        _ => panic!("Expected LockBusy, got {:?}", err),
    }

    // Drop lock guard: subsequent install succeeds
    drop(guard);
    let report = install_or_update(&opts).expect("install should succeed after lock dropped");
    assert!(report.success);
}

#[test]
fn test_11_post_install_sanity_failure_triggers_automatic_rollback() {
    let temp = tempdir().expect("tempdir");
    let rel_dir_v1 = temp.path().join("release_v1");
    let rel_dir_v2_broken = temp.path().join("release_v2_broken");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(18, "cyravell-official-test", true, false, true);

    // Good v1.0.0
    create_test_release_package(
        &rel_dir_v1,
        "1.0.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    // Broken v2.0.0 that exits 1 on --version
    create_test_release_package(
        &rel_dir_v2_broken,
        "2.0.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        true, // failing binary
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    // Install v1.0.0
    let mut opts_v1 = InstallOptions::default();
    opts_v1.release_dir = rel_dir_v1;
    opts_v1.install_prefix = install_prefix.clone();
    opts_v1.custom_keystore = Some(keystore.clone());
    install_or_update(&opts_v1).expect("install v1");

    // Attempt upgrade to broken v2.0.0
    let mut opts_v2 = InstallOptions::default();
    opts_v2.release_dir = rel_dir_v2_broken;
    opts_v2.install_prefix = install_prefix.clone();
    opts_v2.skip_post_install_test = false;
    opts_v2.custom_keystore = Some(keystore);

    let err = install_or_update(&opts_v2).unwrap_err();
    match err {
        InstallError::SanityCheckFailed(_) => {}
        _ => panic!("Expected SanityCheckFailed, got {:?}", err),
    }

    // Verify automatic rollback restored v1.0.0
    let state_file = install_prefix.join("share/cyravell/install_state.json");
    let state = InstallState::load_from_path(&state_file).unwrap();
    assert_eq!(state.active_version, "1.0.0");
}

#[test]
fn test_12_manual_rollback_restores_verified_previous_version() {
    let temp = tempdir().expect("tempdir");
    let rel_dir_v1 = temp.path().join("release_v1");
    let rel_dir_v2 = temp.path().join("release_v2");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(19, "cyravell-official-test", true, false, true);

    create_test_release_package(
        &rel_dir_v1,
        "1.0.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );
    create_test_release_package(
        &rel_dir_v2,
        "1.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    // Install 1.0.0
    let mut opts_v1 = InstallOptions::default();
    opts_v1.release_dir = rel_dir_v1;
    opts_v1.install_prefix = install_prefix.clone();
    opts_v1.custom_keystore = Some(keystore.clone());
    install_or_update(&opts_v1).unwrap();

    // Upgrade to 1.1.0
    let mut opts_v2 = InstallOptions::default();
    opts_v2.release_dir = rel_dir_v2;
    opts_v2.install_prefix = install_prefix.clone();
    opts_v2.custom_keystore = Some(keystore);
    install_or_update(&opts_v2).unwrap();

    // Verify state active is 1.1.0 and backup is 1.0.0
    let state_file = install_prefix.join("share/cyravell/install_state.json");
    let state = InstallState::load_from_path(&state_file).unwrap();
    assert_eq!(state.active_version, "1.1.0");
    assert_eq!(state.backup_version, Some("1.0.0".to_string()));

    // Execute manual rollback
    let rollback_rep = rollback_installation(
        &install_prefix,
        "Operator rollback after discovering regression",
        false,
    )
    .expect("rollback failed");

    assert!(rollback_rep.success);
    assert_eq!(rollback_rep.active_version, Some("1.0.0".to_string()));
    assert_eq!(rollback_rep.previous_version, Some("1.1.0".to_string()));

    // Verify state active is 1.0.0
    let state_after = InstallState::load_from_path(&state_file).unwrap();
    assert_eq!(state_after.active_version, "1.0.0");
    assert_eq!(state_after.last_operation, "rollback");
}

#[test]
fn test_13_corrupted_backup_manifest_rejects_rollback() {
    let temp = tempdir().expect("tempdir");
    let rel_dir_v1 = temp.path().join("release_v1");
    let rel_dir_v2 = temp.path().join("release_v2");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(20, "cyravell-official-test", true, false, true);

    create_test_release_package(
        &rel_dir_v1,
        "1.0.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );
    create_test_release_package(
        &rel_dir_v2,
        "1.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let mut opts_v1 = InstallOptions::default();
    opts_v1.release_dir = rel_dir_v1;
    opts_v1.install_prefix = install_prefix.clone();
    opts_v1.custom_keystore = Some(keystore.clone());
    install_or_update(&opts_v1).unwrap();

    let mut opts_v2 = InstallOptions::default();
    opts_v2.release_dir = rel_dir_v2;
    opts_v2.install_prefix = install_prefix.clone();
    opts_v2.custom_keystore = Some(keystore);
    install_or_update(&opts_v2).unwrap();

    // Tamper with backup file
    let backup_bin = install_prefix.join("share/cyravell/.backup/cyravell-engine");
    assert!(backup_bin.exists());
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(&backup_bin)
        .unwrap();
    f.write_all(b"\n# Injected malicious modification").unwrap();
    drop(f);

    // Attempt rollback: must fail because sha256 mismatch detected
    let err = rollback_installation(
        &install_prefix,
        "Operator rollback attempt with corrupted backup",
        false,
    )
    .unwrap_err();

    match err {
        InstallError::SecurityViolation(msg) => {
            assert!(msg.contains("tampered with or corrupted"));
        }
        _ => panic!("Expected SecurityViolation, got {:?}", err),
    }
}

#[test]
fn test_14_uninstall_preserves_user_security_data() {
    let temp = tempdir().expect("tempdir");
    let rel_dir = temp.path().join("release");
    let install_prefix = temp.path().join("installed");

    let (signing_key, rel_key) = generate_test_key(21, "cyravell-official-test", true, false, true);
    create_test_release_package(
        &rel_dir,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        &signing_key,
        &rel_key.key_id,
        false,
    );

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let mut opts = InstallOptions::default();
    opts.release_dir = rel_dir;
    opts.install_prefix = install_prefix.clone();
    opts.custom_keystore = Some(keystore);
    install_or_update(&opts).unwrap();

    // Simulate persistent user security data in share/cyravell/data
    let data_dir = install_prefix.join("share/cyravell/data");
    fs::create_dir_all(&data_dir).unwrap();
    let audit_log = data_dir.join("audit.log");
    fs::write(&audit_log, b"2026-01-01 critical security audit entry\n").unwrap();
    let advisory_state = data_dir.join("advisory_security_state.json");
    fs::write(&advisory_state, b"{\"high_water_timestamp\": 100}").unwrap();

    // Standard uninstall without purge
    let rep = uninstall(&install_prefix, false, None).expect("uninstall failed");
    assert!(rep.success);

    // Binaries and install_state removed
    assert!(!install_prefix.join("bin/cyravell-engine").exists());
    assert!(!install_prefix
        .join("share/cyravell/install_state.json")
        .exists());
    assert!(!install_prefix.join("share/cyravell/rules").exists());

    // Persistent security data MUST BE PRESERVED
    assert!(audit_log.exists());
    assert_eq!(
        fs::read(&audit_log).unwrap(),
        b"2026-01-01 critical security audit entry\n"
    );
    assert!(advisory_state.exists());

    // Now uninstall with purge_data = true
    let purge_rep = uninstall(&install_prefix, true, None).expect("purge uninstall failed");
    assert!(purge_rep.success);
    assert!(!data_dir.exists());
}
