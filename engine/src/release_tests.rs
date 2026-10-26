// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::release::{
    generate_release_manifest, verify_release_package, BuildMetadata, CyravellReleaseManifest,
    ReleaseArtifact, ReleaseKey, ReleaseKeyStore, ReleaseStatus, SbomReference,
};
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
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

fn create_sample_artifact(dir: &std::path::Path, name: &str, content: &[u8]) -> ReleaseArtifact {
    let file_path = dir.join(name);
    let mut f = File::create(&file_path).expect("Failed to create test artifact file");
    f.write_all(content).expect("Failed to write artifact file");
    f.flush().expect("Failed to flush artifact file");

    let digest = crate::release::compute_sha256(&file_path).expect("Compute sha256");

    ReleaseArtifact {
        filename: name.to_string(),
        size_bytes: content.len() as u64,
        sha256: digest,
        artifact_type: if name.ends_with(".vsix") {
            "extension".to_string()
        } else if name.ends_with(".json") {
            "sbom".to_string()
        } else {
            "binary".to_string()
        },
        target_platform: Some("x86_64-unknown-linux-gnu".to_string()),
    }
}

#[test]
fn test_01_valid_signed_release_manifest_verification() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let bin_art = create_sample_artifact(&art_dir, "cyravell-engine", b"#!/bin/bash\necho test\n");
    let vsix_art = create_sample_artifact(&art_dir, "cyravell-0.1.0.vsix", b"PK\x03\x04extension");
    let sbom_art = create_sample_artifact(
        &art_dir,
        "cyravell-sbom.spdx.json",
        b"{\"spdxVersion\":\"SPDX-2.3\"}",
    );

    let mut artifacts = BTreeMap::new();
    artifacts.insert(bin_art.filename.clone(), bin_art);
    artifacts.insert(vsix_art.filename.clone(), vsix_art);
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        source_tag: Some("v0.1.0".to_string()),
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
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
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (signing_key, rel_key) =
        generate_test_key(1, "cyravell-release-test-key", true, false, true);
    manifest.sign(&signing_key, &rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let report = verify_release_package(
        &manifest_path,
        &art_dir,
        &keystore,
        Some("0.1.0"),
        Some("0123456789abcdef0123456789abcdef01234567"),
        true,
    );

    assert_eq!(report.status, ReleaseStatus::Verified);
    assert_eq!(report.verified_artifacts_count, 3);
    assert!(report.mismatched_artifacts.is_empty());
    assert!(report.missing_artifacts.is_empty());
    assert_eq!(
        report.signing_key_id.as_deref(),
        Some("cyravell-release-test-key")
    );
    assert!(report.is_official);
    assert_eq!(report.signing_mode.as_deref(), Some("official"));
}

#[test]
fn test_02_tampered_artifact_content_detected() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let bin_art = create_sample_artifact(&art_dir, "cyravell-engine", b"original content");
    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"{\"spdx\": true}");

    let mut artifacts = BTreeMap::new();
    artifacts.insert(bin_art.filename.clone(), bin_art);
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "abc123commit".to_string(),
        source_tag: None,
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (signing_key, rel_key) = generate_test_key(2, "test-key-tamper", true, false, true);
    manifest.sign(&signing_key, &rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Adversarially tamper with cyravell-engine binary file on disk
    std::fs::write(
        art_dir.join("cyravell-engine"),
        b"tampered malicious content!",
    )
    .unwrap();

    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::TamperedArtifact);
    assert_eq!(
        report.mismatched_artifacts,
        vec!["cyravell-engine".to_string()]
    );
}

#[test]
fn test_03_missing_artifact_detected() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let bin_art = create_sample_artifact(&art_dir, "cyravell-engine", b"engine binary");
    let vsix_art = create_sample_artifact(&art_dir, "cyravell-0.1.0.vsix", b"extension vsix");
    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom content");

    let mut artifacts = BTreeMap::new();
    artifacts.insert(bin_art.filename.clone(), bin_art);
    artifacts.insert(vsix_art.filename.clone(), vsix_art);
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "abc123commit".to_string(),
        source_tag: None,
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (signing_key, rel_key) = generate_test_key(3, "test-key-missing", true, false, true);
    manifest.sign(&signing_key, &rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Adversarially delete cyravell-0.1.0.vsix
    std::fs::remove_file(art_dir.join("cyravell-0.1.0.vsix")).unwrap();

    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::MissingArtifact);
    assert_eq!(
        report.missing_artifacts,
        vec!["cyravell-0.1.0.vsix".to_string()]
    );
}

#[test]
fn test_04_tampered_manifest_payload_fails_signature() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let bin_art = create_sample_artifact(&art_dir, "cyravell-engine", b"engine binary");
    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom content");

    let mut artifacts = BTreeMap::new();
    artifacts.insert(bin_art.filename.clone(), bin_art);
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "original-commit-sha".to_string(),
        source_tag: None,
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (signing_key, rel_key) = generate_test_key(4, "test-key-sig", true, false, true);
    manifest.sign(&signing_key, &rel_key.key_id);

    // Tamper with manifest fields (e.g. source_commit changed) without re-signing
    manifest.source_commit = "attacker-modified-commit-sha".to_string();

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::InvalidSignature);
}

#[test]
fn test_05_unrecognized_or_untrusted_signing_key_rejected() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom");
    let mut artifacts = BTreeMap::new();
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "abc123commit".to_string(),
        source_tag: None,
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (untrusted_key, _) = generate_test_key(5, "untrusted-attacker-key", true, false, true);
    manifest.sign(&untrusted_key, "untrusted-attacker-key");

    let keystore = ReleaseKeyStore::new(); // empty keystore

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::InvalidSignature);
}

#[test]
fn test_06_revoked_or_expired_release_key_rejected() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom");
    let mut artifacts = BTreeMap::new();
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "abc123commit".to_string(),
        source_tag: None,
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    // Test Revoked Key
    let (revoked_signing, revoked_rel_key) =
        generate_test_key(6, "revoked-key", false, false, true);
    manifest.sign(&revoked_signing, &revoked_rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(revoked_rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::InvalidSignature);

    // Test Expired Key
    let (expired_signing, expired_rel_key) = generate_test_key(7, "expired-key", true, true, true);
    manifest.sign(&expired_signing, &expired_rel_key.key_id);

    let mut keystore2 = ReleaseKeyStore::new();
    keystore2.add_key(expired_rel_key);

    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let report2 = verify_release_package(&manifest_path, &art_dir, &keystore2, None, None, true);
    assert_eq!(report2.status, ReleaseStatus::InvalidSignature);
}

#[test]
fn test_07_path_traversal_in_artifact_filename_rejected() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom");
    let mut artifacts = BTreeMap::new();
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    // Adversarially inject path traversal into artifacts map
    let traversal_art = ReleaseArtifact {
        filename: "../../../etc/shadow".to_string(),
        size_bytes: 100,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        artifact_type: "binary".to_string(),
        target_platform: None,
    };
    artifacts.insert("../../../etc/shadow".to_string(), traversal_art);

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "abc123commit".to_string(),
        source_tag: None,
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (signing_key, rel_key) = generate_test_key(8, "test-key-path", true, false, true);
    manifest.sign(&signing_key, &rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::SecurityCheckFailed);
    assert!(report.details.contains("Path traversal"));
}

#[test]
fn test_08_duplicate_keys_in_manifest_rejected() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let manifest_path = art_dir.join("release_manifest.json");
    let malformed_json = r#"{
        "schema_version": "1.0.0",
        "product_name": "cyravell",
        "release_version": "0.1.0",
        "release_version": "0.2.0-duplicate",
        "source_commit": "abc",
        "build_timestamp": "2026-01-01T00:00:00Z",
        "engine_version": "0.1.0",
        "extension_version": "0.1.0",
        "target_platforms": [],
        "artifacts": {},
        "required_runtime_components": [],
        "build_metadata": {
            "rustc_version": "1.99",
            "cargo_version": "1.99",
            "build_profile": "release"
        },
        "sbom": {
            "filename": "sbom.json",
            "sha256": "abc",
            "format": "SPDX-2.3"
        }
    }"#;
    std::fs::write(&manifest_path, malformed_json).unwrap();

    let keystore = ReleaseKeyStore::new();
    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::MalformedManifest);
    assert!(report.details.contains("Duplicate key"));
}

#[test]
fn test_09_generate_release_manifest_accurately_catalogs_artifacts() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    create_sample_artifact(
        &art_dir,
        "cyravell-engine-x86_64-unknown-linux-gnu",
        b"binary content",
    );
    create_sample_artifact(&art_dir, "cyravell-0.1.0.vsix", b"extension zip content");
    create_sample_artifact(
        &art_dir,
        "cyravell-sbom.spdx.json",
        b"spdx 2.3 json content",
    );

    let manifest = generate_release_manifest(
        &art_dir,
        "0.1.0",
        "1234567890abcdef1234567890abcdef12345678",
        Some("v0.1.0"),
        "x86_64-unknown-linux-gnu",
        "cyravell-sbom.spdx.json",
        Some("official"),
    )
    .expect("generate release manifest");

    assert_eq!(manifest.release_version, "0.1.0");
    assert_eq!(
        manifest.source_commit,
        "1234567890abcdef1234567890abcdef12345678"
    );
    assert_eq!(manifest.source_tag.as_deref(), Some("v0.1.0"));
    assert_eq!(manifest.artifacts.len(), 3);
    assert_eq!(manifest.sbom.filename, "cyravell-sbom.spdx.json");
    assert_eq!(manifest.signing_mode.as_deref(), Some("official"));

    let bin_entry = manifest
        .artifacts
        .get("cyravell-engine-x86_64-unknown-linux-gnu")
        .unwrap();
    assert_eq!(bin_entry.size_bytes, 14);
    assert_eq!(bin_entry.artifact_type, "binary");
    assert_eq!(
        bin_entry.target_platform.as_deref(),
        Some("x86_64-unknown-linux-gnu")
    );

    let vsix_entry = manifest.artifacts.get("cyravell-0.1.0.vsix").unwrap();
    assert_eq!(vsix_entry.size_bytes, 21);
    assert_eq!(vsix_entry.artifact_type, "extension");
}

#[test]
fn test_10_version_and_commit_expectation_mismatch() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom");
    let mut artifacts = BTreeMap::new();
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "commit-actual-111".to_string(),
        source_tag: None,
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (signing_key, rel_key) = generate_test_key(9, "test-key-ver", true, false, true);
    manifest.sign(&signing_key, &rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Verify expecting version 0.2.0 (mismatch)
    let report = verify_release_package(
        &manifest_path,
        &art_dir,
        &keystore,
        Some("0.2.0"),
        Some("commit-actual-111"),
        true,
    );
    assert_ne!(report.status, ReleaseStatus::Verified);
    assert!(report
        .errors
        .iter()
        .any(|e| e.contains("Release version mismatch")));

    // Verify expecting commit-expected-222 (mismatch)
    let report2 = verify_release_package(
        &manifest_path,
        &art_dir,
        &keystore,
        Some("0.1.0"),
        Some("commit-expected-222"),
        true,
    );
    assert_ne!(report2.status, ReleaseStatus::Verified);
    assert!(report2
        .errors
        .iter()
        .any(|e| e.contains("Source commit mismatch")));
}

#[test]
fn test_11_symlink_artifact_rejected() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    // Create target file outside or inside, and create symlink inside art_dir
    let outside_file = temp.path().join("secret_target.txt");
    std::fs::write(&outside_file, b"secret data").unwrap();

    let symlink_path = art_dir.join("cyravell-engine");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_file, &symlink_path).unwrap();

    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom");
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "cyravell-engine".to_string(),
        ReleaseArtifact {
            filename: "cyravell-engine".to_string(),
            size_bytes: 11,
            sha256: crate::release::compute_sha256(&outside_file).unwrap(),
            artifact_type: "binary".to_string(),
            target_platform: Some("x86_64-unknown-linux-gnu".to_string()),
        },
    );
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        source_tag: Some("v0.1.0".to_string()),
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (signing_key, rel_key) = generate_test_key(11, "test-key-symlink", true, false, true);
    manifest.sign(&signing_key, &rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::SecurityCheckFailed);
    assert!(
        report.details.contains("symbolic link")
            || report.errors.iter().any(|e| e.contains("symbolic link"))
    );
}

#[test]
fn test_12_non_official_dev_key_rejected_when_official_required() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom");
    let mut artifacts = BTreeMap::new();
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        source_tag: Some("v0.1.0".to_string()),
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("development".to_string()),
        signing_key_id: None,
        signature: None,
    };

    // Generate development key (is_official = false)
    let (dev_signing_key, dev_rel_key) =
        generate_test_key(12, "cyravell-dev-key", true, false, false);
    manifest.sign(&dev_signing_key, &dev_rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(dev_rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // 1. With require_official = true -> MUST FAIL with UntrustedKey
    let report_strict =
        verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report_strict.status, ReleaseStatus::UntrustedKey);
    assert!(report_strict
        .details
        .contains("official production release signing key is required"));

    // 2. With require_official = false -> MUST PASS
    let report_dev = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, false);
    assert_eq!(report_dev.status, ReleaseStatus::Verified);
    assert!(!report_dev.is_official);
    assert_eq!(report_dev.signing_mode.as_deref(), Some("development"));
}

#[test]
fn test_13_unlisted_executable_in_release_dir_rejected() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let sbom_art = create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom");
    let mut artifacts = BTreeMap::new();
    artifacts.insert(sbom_art.filename.clone(), sbom_art.clone());

    let mut manifest = CyravellReleaseManifest {
        schema_version: "1.0.0".to_string(),
        product_name: "cyravell".to_string(),
        release_version: "0.1.0".to_string(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        source_tag: Some("v0.1.0".to_string()),
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: "0.1.0".to_string(),
        extension_version: "0.1.0".to_string(),
        target_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
        artifacts,
        required_runtime_components: vec![],
        build_metadata: BuildMetadata {
            rustc_version: "rustc 1.99.1".to_string(),
            cargo_version: "cargo 1.99.1".to_string(),
            node_version: None,
            build_profile: "release".to_string(),
            source_date_epoch: None,
        },
        sbom: SbomReference {
            filename: sbom_art.filename,
            sha256: sbom_art.sha256,
            format: "SPDX-2.3".to_string(),
        },
        signing_mode: Some("official".to_string()),
        signing_key_id: None,
        signature: None,
    };

    let (signing_key, rel_key) = generate_test_key(13, "test-key-exec", true, false, true);
    manifest.sign(&signing_key, &rel_key.key_id);

    let mut keystore = ReleaseKeyStore::new();
    keystore.add_key(rel_key);

    let manifest_path = art_dir.join("release_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Adversarially drop an unlisted executable script into the artifacts dir
    std::fs::write(
        art_dir.join("malicious_install.sh"),
        b"#!/bin/bash\nrm -rf /\n",
    )
    .unwrap();

    let report = verify_release_package(&manifest_path, &art_dir, &keystore, None, None, true);
    assert_eq!(report.status, ReleaseStatus::SecurityCheckFailed);
    assert!(report
        .details
        .to_lowercase()
        .contains("unlisted executable file"));
}

#[test]
fn test_14_symlink_rejected_during_manifest_generation() {
    let temp = tempdir().expect("tempdir");
    let art_dir = temp.path().join("artifacts");
    std::fs::create_dir_all(&art_dir).expect("create art_dir");

    let outside_file = temp.path().join("outside.bin");
    std::fs::write(&outside_file, b"outside content").unwrap();

    let symlink_path = art_dir.join("cyravell-engine");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_file, &symlink_path).unwrap();

    create_sample_artifact(&art_dir, "cyravell-sbom.spdx.json", b"sbom content");

    let result = generate_release_manifest(
        &art_dir,
        "0.1.0",
        "0123456789abcdef0123456789abcdef01234567",
        Some("v0.1.0"),
        "x86_64-unknown-linux-gnu",
        "cyravell-sbom.spdx.json",
        Some("official"),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("symbolic link"));
}
