// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub manifest_version: String,
    pub release_version: String,
    pub created_at: DateTime<Utc>,
    pub files: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityStatus {
    Verified,
    Degraded,
    Corrupted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityVerificationReport {
    pub status: IntegrityStatus,
    pub manifest_version: String,
    pub release_version: String,
    pub verified_files_count: usize,
    pub mismatched_files: Vec<String>,
    pub missing_files: Vec<String>,
    pub authentication_status: String,
    pub details: String,
}

/// Computes SHA-256 for a given file path.
pub fn compute_file_sha256<P: AsRef<Path>>(path: P) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Verifies all files enumerated in the manifest against their hashes relative to `base_dir`.
pub fn verify_manifest<P: AsRef<Path>, B: AsRef<Path>>(
    manifest_path: P,
    base_dir: B,
) -> IntegrityVerificationReport {
    let manifest_file_path = manifest_path.as_ref();
    let base = base_dir.as_ref();

    if !manifest_file_path.exists() {
        return IntegrityVerificationReport {
            status: IntegrityStatus::Degraded,
            manifest_version: "unknown".to_string(),
            release_version: "unknown".to_string(),
            verified_files_count: 0,
            mismatched_files: vec![],
            missing_files: vec![manifest_file_path.display().to_string()],
            authentication_status: "MANIFEST_NOT_FOUND".to_string(),
            details: "Release integrity manifest file does not exist".to_string(),
        };
    }

    let content = match std::fs::read_to_string(manifest_file_path) {
        Ok(c) => c,
        Err(e) => {
            return IntegrityVerificationReport {
                status: IntegrityStatus::Failed,
                manifest_version: "unknown".to_string(),
                release_version: "unknown".to_string(),
                verified_files_count: 0,
                mismatched_files: vec![],
                missing_files: vec![],
                authentication_status: "READ_ERROR".to_string(),
                details: format!("Failed to read manifest: {}", e),
            };
        }
    };

    let manifest: ReleaseManifest = match serde_json::from_str(&content) {
        Ok(m) => m,
        Err(e) => {
            return IntegrityVerificationReport {
                status: IntegrityStatus::Corrupted,
                manifest_version: "malformed".to_string(),
                release_version: "malformed".to_string(),
                verified_files_count: 0,
                mismatched_files: vec![],
                missing_files: vec![],
                authentication_status: "INVALID_JSON".to_string(),
                details: format!("Failed to parse release manifest JSON: {}", e),
            };
        }
    };

    let mut verified_count = 0;
    let mut mismatched = Vec::new();
    let mut missing = Vec::new();

    for (rel_path, expected_hash) in &manifest.files {
        // Enforce safe relative path resolution (no escaping base directory)
        if rel_path.starts_with('/') || rel_path.contains("..") {
            mismatched.push(format!(
                "Illegal path traversal detected in manifest: {}",
                rel_path
            ));
            continue;
        }

        let target_path: PathBuf = base.join(rel_path);

        if !target_path.exists() {
            missing.push(rel_path.clone());
            continue;
        }

        match compute_file_sha256(&target_path) {
            Ok(actual_hash) => {
                if actual_hash.eq_ignore_ascii_case(expected_hash) {
                    verified_count += 1;
                } else {
                    mismatched.push(format!(
                        "{} (expected {}, computed {})",
                        rel_path, expected_hash, actual_hash
                    ));
                }
            }
            Err(e) => {
                mismatched.push(format!("{} (read error: {})", rel_path, e));
            }
        }
    }

    let status = if !mismatched.is_empty() || !missing.is_empty() {
        IntegrityStatus::Corrupted
    } else {
        IntegrityStatus::Verified
    };

    IntegrityVerificationReport {
        status,
        manifest_version: manifest.manifest_version,
        release_version: manifest.release_version,
        verified_files_count: verified_count,
        mismatched_files: mismatched,
        missing_files: missing,
        // Document Phase 1 limitation: unauthenticated hash-only manifest
        authentication_status: "UNSIGNED_HASH_VERIFICATION_ONLY".to_string(),
        details: "File integrity computed against local release manifest. Cryptographic signature check reserved for Phase 2.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_valid_manifest_verification() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let file_path = base_path.join("file1.txt");
        std::fs::write(&file_path, "Hello Cyravell").unwrap();
        let hash = compute_file_sha256(&file_path).unwrap();

        let mut files = HashMap::new();
        files.insert("file1.txt".to_string(), hash);

        let manifest = ReleaseManifest {
            manifest_version: "1.0".to_string(),
            release_version: "0.1.0".to_string(),
            created_at: Utc::now(),
            files,
        };

        let manifest_path = base_path.join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

        let report = verify_manifest(&manifest_path, base_path);
        assert_eq!(report.status, IntegrityStatus::Verified);
        assert_eq!(report.verified_files_count, 1);
        assert!(report.mismatched_files.is_empty());
        assert!(report.missing_files.is_empty());
    }

    #[test]
    fn test_mismatched_file_hash() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let file_path = base_path.join("file1.txt");
        std::fs::write(&file_path, "Original content").unwrap();

        let mut files = HashMap::new();
        files.insert(
            "file1.txt".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let manifest = ReleaseManifest {
            manifest_version: "1.0".to_string(),
            release_version: "0.1.0".to_string(),
            created_at: Utc::now(),
            files,
        };

        let manifest_path = base_path.join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

        let report = verify_manifest(&manifest_path, base_path);
        assert_eq!(report.status, IntegrityStatus::Corrupted);
        assert_eq!(report.mismatched_files.len(), 1);
    }

    #[test]
    fn test_missing_file() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let mut files = HashMap::new();
        files.insert("missing.txt".to_string(), "abcdef".to_string());

        let manifest = ReleaseManifest {
            manifest_version: "1.0".to_string(),
            release_version: "0.1.0".to_string(),
            created_at: Utc::now(),
            files,
        };

        let manifest_path = base_path.join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

        let report = verify_manifest(&manifest_path, base_path);
        assert_eq!(report.status, IntegrityStatus::Corrupted);
        assert_eq!(report.missing_files, vec!["missing.txt"]);
    }

    #[test]
    fn test_illegal_path_traversal() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let mut files = HashMap::new();
        files.insert("../outside.txt".to_string(), "abcdef".to_string());

        let manifest = ReleaseManifest {
            manifest_version: "1.0".to_string(),
            release_version: "0.1.0".to_string(),
            created_at: Utc::now(),
            files,
        };

        let manifest_path = base_path.join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

        let report = verify_manifest(&manifest_path, base_path);
        assert_eq!(report.status, IntegrityStatus::Corrupted);
        assert!(report.mismatched_files[0].contains("Illegal path traversal"));
    }
}
