// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cyravell Secure Installation, Update, and Recovery Subsystem (Phase 3.2).
//!
//! Provides transactional, fail-closed installation, updates, and recovery
//! with strict cryptographic release verification, symlink defense,
//! least-privilege scoping, anti-downgrade high-water mark protection,
//! and atomic state management.

use crate::release::{compute_sha256, verify_release_package, ReleaseKeyStore, ReleaseStatus};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

/// Lightweight, deterministic SemVer parser for version ordering without external dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleSemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre_release: Option<String>,
}

impl SimpleSemVer {
    pub fn parse(s: &str) -> Result<Self, String> {
        let clean = s.trim().strip_prefix('v').unwrap_or(s.trim());
        let (ver_part, pre_part) = match clean.split_once('-') {
            Some((v, p)) => (v, Some(p.to_string())),
            None => (clean, None),
        };

        let parts: Vec<&str> = ver_part.split('.').collect();
        if parts.len() != 3 {
            return Err(format!(
                "Invalid SemVer string '{}': expected major.minor.patch",
                s
            ));
        }

        let major = parts[0]
            .parse::<u64>()
            .map_err(|_| format!("Invalid major version '{}'", parts[0]))?;
        let minor = parts[1]
            .parse::<u64>()
            .map_err(|_| format!("Invalid minor version '{}'", parts[1]))?;
        let patch = parts[2]
            .parse::<u64>()
            .map_err(|_| format!("Invalid patch version '{}'", parts[2]))?;

        Ok(Self {
            major,
            minor,
            patch,
            pre_release: pre_part,
        })
    }
}

impl PartialOrd for SimpleSemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for SimpleSemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.major.cmp(&other.major) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // If versions are equal, a pre-release version is lower than release (None)
        match (&self.pre_release, &other.pre_release) {
            (None, None) => std::cmp::Ordering::Equal,
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl std::fmt::Display for SimpleSemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref pre) = self.pre_release {
            write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, pre)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

/// Record of an installed file tracked by the installation state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledFileRecord {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub mode: u32,
}

/// Durable installation state tracked in `share/cyravell/install_state.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallState {
    pub schema_version: String,
    pub active_version: String,
    pub active_commit: String,
    pub active_tag: Option<String>,
    pub installed_at: String,
    pub installed_by_uid: u32,
    pub signing_key_id: String,
    pub is_official: bool,
    pub install_prefix: PathBuf,
    pub is_user_install: bool,
    pub installed_files: BTreeMap<String, InstalledFileRecord>,
    pub backup_version: Option<String>,
    pub backup_files: BTreeMap<String, InstalledFileRecord>,
    pub high_water_version: String,
    pub last_operation: String,
    pub last_operation_timestamp: String,
}

impl InstallState {
    pub fn new(
        version: &str,
        commit: &str,
        tag: Option<&str>,
        signing_key_id: &str,
        is_official: bool,
        prefix: &Path,
        is_user: bool,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        let uid = unsafe { libc::geteuid() };
        Self {
            schema_version: "1.0.0".to_string(),
            active_version: version.to_string(),
            active_commit: commit.to_string(),
            active_tag: tag.map(|t| t.to_string()),
            installed_at: now.clone(),
            installed_by_uid: uid,
            signing_key_id: signing_key_id.to_string(),
            is_official,
            install_prefix: prefix.to_path_buf(),
            is_user_install: is_user,
            installed_files: BTreeMap::new(),
            backup_version: None,
            backup_files: BTreeMap::new(),
            high_water_version: version.to_string(),
            last_operation: "install".to_string(),
            last_operation_timestamp: now,
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, InstallError> {
        if !path.exists() {
            return Err(InstallError::StateNotFound(format!(
                "Install state not found at '{}'",
                path.display()
            )));
        }

        // Must be a regular file, not a symlink
        let meta = fs::symlink_metadata(path).map_err(|e| {
            InstallError::SecurityViolation(format!(
                "Failed to stat install state '{}': {}",
                path.display(),
                e
            ))
        })?;

        if meta.file_type().is_symlink() {
            return Err(InstallError::SecurityViolation(format!(
                "Install state at '{}' is an unsafe symbolic link",
                path.display()
            )));
        }

        let content = fs::read_to_string(path).map_err(|e| {
            InstallError::Io(format!(
                "Failed to read install state '{}': {}",
                path.display(),
                e
            ))
        })?;

        serde_json::from_str(&content).map_err(|e| {
            InstallError::StateCorrupted(format!(
                "Corrupted install state JSON in '{}': {}",
                path.display(),
                e
            ))
        })
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), InstallError> {
        let parent = path.parent().ok_or_else(|| {
            InstallError::Io(format!("Invalid install state path '{}'", path.display()))
        })?;

        safe_create_dir_all(parent)?;

        let tmp_path = parent.join(format!(".install_state.tmp-{}", Uuid::new_v4()));
        let json_str = serde_json::to_string_pretty(self)
            .map_err(|e| InstallError::Io(format!("Failed to serialize install state: {}", e)))?;

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| {
                    InstallError::Io(format!(
                        "Failed to create temp install state '{}': {}",
                        tmp_path.display(),
                        e
                    ))
                })?;
            file.write_all(json_str.as_bytes()).map_err(|e| {
                InstallError::Io(format!(
                    "Failed to write temp install state '{}': {}",
                    tmp_path.display(),
                    e
                ))
            })?;
            file.flush().map_err(|e| {
                InstallError::Io(format!(
                    "Failed to flush temp install state '{}': {}",
                    tmp_path.display(),
                    e
                ))
            })?;
        }

        fs::rename(&tmp_path, path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            InstallError::Io(format!(
                "Failed to atomically activate install state at '{}': {}",
                path.display(),
                e
            ))
        })?;

        Ok(())
    }
}

/// Installation configuration parameters.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub release_dir: PathBuf,
    pub install_prefix: PathBuf,
    pub is_user_mode: bool,
    pub allow_dev_keys: bool,
    pub allow_downgrade: bool,
    pub operator_reason: Option<String>,
    pub expected_version: Option<String>,
    pub expected_commit: Option<String>,
    pub skip_post_install_test: bool,
    pub custom_keystore: Option<ReleaseKeyStore>,
}

impl Default for InstallOptions {
    fn default() -> Self {
        let is_root = unsafe { libc::geteuid() == 0 };
        let prefix = if is_root {
            PathBuf::from("/usr/local")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".local")
        };

        Self {
            release_dir: PathBuf::new(),
            install_prefix: prefix,
            is_user_mode: !is_root,
            allow_dev_keys: false,
            allow_downgrade: false,
            operator_reason: None,
            expected_version: None,
            expected_commit: None,
            skip_post_install_test: false,
            custom_keystore: None,
        }
    }
}

/// Structured report of an installation, update, or recovery operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallReport {
    pub success: bool,
    pub operation: String,
    pub previous_version: Option<String>,
    pub active_version: Option<String>,
    pub install_prefix: PathBuf,
    pub files_installed: Vec<String>,
    pub backup_created: bool,
    pub details: String,
    pub errors: Vec<String>,
}

/// Comprehensive installation lifecycle errors.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallError {
    ReleaseVerificationFailed(String),
    UntrustedKey(String),
    DowngradeRejected { active: String, candidate: String },
    InvalidDowngradeReason(String),
    SecurityViolation(String),
    InsufficientPermissions(String),
    StagingFailed(String),
    ActivationFailed(String),
    SanityCheckFailed(String),
    RollbackFailed(String),
    StateNotFound(String),
    StateCorrupted(String),
    LockBusy(String),
    Io(String),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReleaseVerificationFailed(msg) => {
                write!(f, "Release verification failed: {}", msg)
            }
            Self::UntrustedKey(msg) => write!(f, "Untrusted signing key: {}", msg),
            Self::DowngradeRejected { active, candidate } => write!(
                f,
                "Downgrade rejected: Active version is '{}', candidate version is older '{}'. Pass --allow-downgrade --reason <REASON> to authorize.",
                active, candidate
            ),
            Self::InvalidDowngradeReason(msg) => write!(f, "Invalid downgrade reason: {}", msg),
            Self::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            Self::InsufficientPermissions(msg) => {
                write!(f, "Insufficient filesystem permissions: {}", msg)
            }
            Self::StagingFailed(msg) => write!(f, "Staging failed: {}", msg),
            Self::ActivationFailed(msg) => write!(f, "Activation failed: {}", msg),
            Self::SanityCheckFailed(msg) => write!(f, "Sanity check failed: {}", msg),
            Self::RollbackFailed(msg) => write!(f, "Rollback failed: {}", msg),
            Self::StateNotFound(msg) => write!(f, "Install state not found: {}", msg),
            Self::StateCorrupted(msg) => write!(f, "Install state corrupted: {}", msg),
            Self::LockBusy(msg) => write!(f, "Installation lock is busy: {}", msg),
            Self::Io(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for InstallError {}

/// RAII lock guard to prevent concurrent install, upgrade, or rollback processes.
pub struct InstallLockGuard {
    lock_path: PathBuf,
}

impl InstallLockGuard {
    pub fn acquire(share_dir: &Path) -> Result<Self, InstallError> {
        safe_create_dir_all(share_dir)?;
        let lock_path = share_dir.join(".install.lock");
        let my_pid = std::process::id();

        // Check for existing lock
        if lock_path.exists() {
            if let Ok(meta) = fs::symlink_metadata(&lock_path) {
                if meta.file_type().is_symlink() {
                    return Err(InstallError::SecurityViolation(format!(
                        "Lock file '{}' is an unsafe symbolic link",
                        lock_path.display()
                    )));
                }
            }

            if let Ok(content) = fs::read_to_string(&lock_path) {
                if let Ok(existing_pid) = content.trim().parse::<u32>() {
                    // Check if existing_pid is running
                    let is_alive = unsafe { libc::kill(existing_pid as i32, 0) == 0 };
                    if is_alive {
                        return Err(InstallError::LockBusy(format!(
                            "Another Cyravell installation operation is running with PID {}",
                            existing_pid
                        )));
                    }
                }
            }
            let _ = fs::remove_file(&lock_path);
        }

        // Open with O_CREAT | O_EXCL
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| {
                InstallError::LockBusy(format!(
                    "Failed to acquire install lock '{}': {}",
                    lock_path.display(),
                    e
                ))
            })?;

        let _ = write!(f, "{}", my_pid);
        let _ = f.flush();

        Ok(Self { lock_path })
    }
}

impl Drop for InstallLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// Safely creates directory hierarchy ensuring NO component in the path is a symlink.
pub fn safe_create_dir_all(path: &Path) -> Result<(), InstallError> {
    let mut current = PathBuf::new();
    for comp in path.components() {
        current.push(comp);
        if current.exists() {
            let meta = fs::symlink_metadata(&current).map_err(|e| {
                InstallError::SecurityViolation(format!(
                    "Failed to stat directory component '{}': {}",
                    current.display(),
                    e
                ))
            })?;
            if meta.file_type().is_symlink() {
                return Err(InstallError::SecurityViolation(format!(
                    "Path component '{}' is an unsafe symbolic link",
                    current.display()
                )));
            }
        } else {
            fs::create_dir(&current).map_err(|e| {
                InstallError::Io(format!(
                    "Failed to create directory '{}': {}",
                    current.display(),
                    e
                ))
            })?;
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&current, fs::Permissions::from_mode(0o755));
            }
        }
    }
    Ok(())
}

/// Safely copies a file using atomic write-to-temp and rename, verifying symlinks.
pub fn safe_copy_file(src: &Path, dst: &Path, mode: u32) -> Result<u64, InstallError> {
    let src_meta = fs::symlink_metadata(src).map_err(|e| {
        InstallError::Io(format!(
            "Failed to stat source file '{}': {}",
            src.display(),
            e
        ))
    })?;

    if src_meta.file_type().is_symlink() {
        return Err(InstallError::SecurityViolation(format!(
            "Source file '{}' is an unsafe symbolic link",
            src.display()
        )));
    }
    if !src_meta.file_type().is_file() {
        return Err(InstallError::SecurityViolation(format!(
            "Source file '{}' is not a regular file",
            src.display()
        )));
    }

    let parent = dst
        .parent()
        .ok_or_else(|| InstallError::Io(format!("Invalid destination path '{}'", dst.display())))?;
    safe_create_dir_all(parent)?;

    if dst.exists() {
        let dst_meta = fs::symlink_metadata(dst).map_err(|e| {
            InstallError::Io(format!(
                "Failed to stat destination file '{}': {}",
                dst.display(),
                e
            ))
        })?;
        if dst_meta.file_type().is_symlink() {
            return Err(InstallError::SecurityViolation(format!(
                "Destination file '{}' is an unsafe symbolic link",
                dst.display()
            )));
        }
    }

    let tmp_dst = parent.join(format!(".tmp-copy-{}", Uuid::new_v4()));
    let bytes_copied = fs::copy(src, &tmp_dst).map_err(|e| {
        InstallError::Io(format!(
            "Failed to copy from '{}' to '{}': {}",
            src.display(),
            tmp_dst.display(),
            e
        ))
    })?;

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(&tmp_dst, fs::Permissions::from_mode(mode));
    }

    fs::rename(&tmp_dst, dst).map_err(|e| {
        let _ = fs::remove_file(&tmp_dst);
        InstallError::Io(format!(
            "Failed to rename temp file to '{}': {}",
            dst.display(),
            e
        ))
    })?;

    Ok(bytes_copied)
}

/// Safely unpacks the rules bundle tar.gz with directory traversal and symlink validation.
pub fn safe_unpack_rules_bundle(
    tar_path: &Path,
    target_rules_dir: &Path,
) -> Result<BTreeMap<String, InstalledFileRecord>, InstallError> {
    if !tar_path.exists() {
        return Err(InstallError::Io(format!(
            "Rules bundle tar file not found at '{}'",
            tar_path.display()
        )));
    }

    safe_create_dir_all(target_rules_dir)?;

    // Inspect tar contents before unpacking using tar -tzf
    let list_output = Command::new("tar")
        .arg("-tzf")
        .arg(tar_path)
        .output()
        .map_err(|e| {
            InstallError::Io(format!(
                "Failed to execute tar to inspect '{}': {}",
                tar_path.display(),
                e
            ))
        })?;

    if !list_output.status.success() {
        return Err(InstallError::SecurityViolation(format!(
            "Tar archive '{}' is corrupt or cannot be read: {}",
            tar_path.display(),
            String::from_utf8_lossy(&list_output.stderr)
        )));
    }

    let entries_str = String::from_utf8_lossy(&list_output.stdout);
    for line in entries_str.lines() {
        let entry = line.trim();
        if entry.is_empty() {
            continue;
        }
        if entry.contains("..")
            || entry.starts_with('/')
            || entry.contains('\\')
            || entry.contains('\0')
        {
            return Err(InstallError::SecurityViolation(format!(
                "Rules bundle archive contains illegal path traversal entry '{}'",
                entry
            )));
        }
    }

    // Extract tarball safely into target_rules_dir
    let extract_output = Command::new("tar")
        .arg("--no-same-owner")
        .arg("--no-same-permissions")
        .arg("-xzf")
        .arg(tar_path)
        .arg("-C")
        .arg(target_rules_dir)
        .output()
        .map_err(|e| {
            InstallError::Io(format!(
                "Failed to extract rules bundle '{}': {}",
                tar_path.display(),
                e
            ))
        })?;

    if !extract_output.status.success() {
        return Err(InstallError::Io(format!(
            "Failed to unpack rules bundle: {}",
            String::from_utf8_lossy(&extract_output.stderr)
        )));
    }

    // The tar unpacks into a rules/ subfolder or directly. Find the actual rules files.
    let base_rules_path = if target_rules_dir.join("rules").is_dir() {
        target_rules_dir.join("rules")
    } else {
        target_rules_dir.to_path_buf()
    };

    let mut records = BTreeMap::new();
    let entries = fs::read_dir(&base_rules_path).map_err(|e| {
        InstallError::Io(format!(
            "Failed to read extracted rules dir '{}': {}",
            base_rules_path.display(),
            e
        ))
    })?;

    for entry in entries.flatten() {
        let p = entry.path();
        let sym_meta = fs::symlink_metadata(&p).map_err(|e| {
            InstallError::SecurityViolation(format!(
                "Failed to stat extracted rule file '{}': {}",
                p.display(),
                e
            ))
        })?;

        if sym_meta.file_type().is_symlink() {
            return Err(InstallError::SecurityViolation(format!(
                "Extracted rule file '{}' is an unsafe symbolic link",
                p.display()
            )));
        }

        if !sym_meta.file_type().is_file() {
            continue;
        }

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o644));
        }

        let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let digest = compute_sha256(&p).map_err(|e| {
            InstallError::Io(format!(
                "Failed to compute SHA-256 for rule file '{}': {}",
                p.display(),
                e
            ))
        })?;

        records.insert(
            format!("rules/{}", fname),
            InstalledFileRecord {
                relative_path: format!("rules/{}", fname),
                size_bytes: sym_meta.len(),
                sha256: digest,
                mode: 0o644,
            },
        );
    }

    Ok(records)
}

/// Executes a transactional installation or upgrade of Cyravell.
pub fn install_or_update(options: &InstallOptions) -> Result<InstallReport, InstallError> {
    if !options.release_dir.exists() {
        return Err(InstallError::Io(format!(
            "Release directory '{}' does not exist",
            options.release_dir.display()
        )));
    }

    let manifest_path = options.release_dir.join("release_manifest.json");
    if !manifest_path.exists() {
        return Err(InstallError::ReleaseVerificationFailed(format!(
            "Manifest '{}' not found",
            manifest_path.display()
        )));
    }

    // Acquire concurrency lock on install_prefix/share/cyravell
    let share_dir = options.install_prefix.join("share/cyravell");
    let _lock = InstallLockGuard::acquire(&share_dir)?;

    // Step 1: Pre-Verification of Release Package
    let default_keystore = ReleaseKeyStore::load_default();
    let keystore = options
        .custom_keystore
        .as_ref()
        .unwrap_or(&default_keystore);
    let report = verify_release_package(
        &manifest_path,
        &options.release_dir,
        keystore,
        options.expected_version.as_deref(),
        options.expected_commit.as_deref(),
        !options.allow_dev_keys,
    );

    if report.status != ReleaseStatus::Verified {
        if report.status == ReleaseStatus::UntrustedKey {
            return Err(InstallError::UntrustedKey(report.details));
        }
        return Err(InstallError::ReleaseVerificationFailed(report.details));
    }

    let cand_semver = SimpleSemVer::parse(&report.release_version).map_err(|e| {
        InstallError::ReleaseVerificationFailed(format!("Invalid release version SemVer: {}", e))
    })?;

    // Step 2: Check Existing State & Downgrade Prevention
    let state_file = share_dir.join("install_state.json");
    let existing_state = if state_file.exists() {
        Some(InstallState::load_from_path(&state_file)?)
    } else {
        None
    };

    let previous_version = existing_state.as_ref().map(|s| s.active_version.clone());
    let mut high_water_version = report.release_version.clone();

    if let Some(ref prev) = existing_state {
        let prev_semver = SimpleSemVer::parse(&prev.active_version)
            .unwrap_or(SimpleSemVer::parse("0.0.0").unwrap());
        let hw_semver = SimpleSemVer::parse(&prev.high_water_version)
            .unwrap_or(SimpleSemVer::parse("0.0.0").unwrap());

        if cand_semver < prev_semver || cand_semver < hw_semver {
            if !options.allow_downgrade {
                return Err(InstallError::DowngradeRejected {
                    active: prev.active_version.clone(),
                    candidate: report.release_version.clone(),
                });
            }

            // Downgrade requested: validate operator reason
            let reason = options.operator_reason.as_deref().unwrap_or("").trim();
            if reason.len() < 8 {
                return Err(InstallError::InvalidDowngradeReason(
                    "Authorized downgrade requires a descriptive reason of at least 8 characters"
                        .to_string(),
                ));
            }
            // Preserve high-water mark across downgrades
            high_water_version = prev.high_water_version.clone();
        } else if cand_semver > hw_semver {
            high_water_version = report.release_version.clone();
        } else {
            high_water_version = prev.high_water_version.clone();
        }
    }

    // Step 3: Transactional Staging
    let staging_id = Uuid::new_v4();
    let staging_dir = share_dir.join(format!(".staging-{}", staging_id));
    safe_create_dir_all(&staging_dir)?;

    let cleanup_staging = |dir: &Path| {
        let _ = fs::remove_dir_all(dir);
    };

    // Locate binary artifacts
    let bin_src = options
        .release_dir
        .join("cyravell-engine-x86_64-unknown-linux-gnu");
    let harness_src = options
        .release_dir
        .join("cyravell-test-harness-x86_64-unknown-linux-gnu");
    let rules_tar = options.release_dir.join("cyravell-rules-bundle.tar.gz");

    if !bin_src.exists() {
        cleanup_staging(&staging_dir);
        return Err(InstallError::StagingFailed(format!(
            "Missing engine binary at '{}'",
            bin_src.display()
        )));
    }
    if !rules_tar.exists() {
        cleanup_staging(&staging_dir);
        return Err(InstallError::StagingFailed(format!(
            "Missing rules bundle at '{}'",
            rules_tar.display()
        )));
    }

    let staged_bin = staging_dir.join("cyravell-engine");
    safe_copy_file(&bin_src, &staged_bin, 0o755).inspect_err(|_| {
        cleanup_staging(&staging_dir);
    })?;

    let staged_harness = staging_dir.join("cyravell-test-harness");
    let has_harness = if harness_src.exists() {
        safe_copy_file(&harness_src, &staged_harness, 0o755).inspect_err(|_| {
            cleanup_staging(&staging_dir);
        })?;
        true
    } else {
        false
    };

    let staged_rules_dir = staging_dir.join("rules_extracted");
    let unpacked_rules =
        safe_unpack_rules_bundle(&rules_tar, &staged_rules_dir).inspect_err(|_| {
            cleanup_staging(&staging_dir);
        })?;

    // Step 4: Backup Active Installation (Last Known-Good)
    let backup_dir = share_dir.join(".backup");
    let active_bin_dir = options.install_prefix.join("bin");
    let active_rules_dir = share_dir.join("rules");
    let mut backup_created = false;
    let mut backup_records = BTreeMap::new();

    if existing_state.is_some() {
        safe_create_dir_all(&backup_dir)?;
        let active_engine = active_bin_dir.join("cyravell-engine");
        if active_engine.exists() {
            let b_engine = backup_dir.join("cyravell-engine");
            if let Ok(bytes) = safe_copy_file(&active_engine, &b_engine, 0o755) {
                if let Ok(sha) = compute_sha256(&b_engine) {
                    backup_records.insert(
                        "bin/cyravell-engine".to_string(),
                        InstalledFileRecord {
                            relative_path: "bin/cyravell-engine".to_string(),
                            size_bytes: bytes,
                            sha256: sha,
                            mode: 0o755,
                        },
                    );
                }
            }
        }

        let active_harness = active_bin_dir.join("cyravell-test-harness");
        if active_harness.exists() {
            let b_harness = backup_dir.join("cyravell-test-harness");
            if let Ok(bytes) = safe_copy_file(&active_harness, &b_harness, 0o755) {
                if let Ok(sha) = compute_sha256(&b_harness) {
                    backup_records.insert(
                        "bin/cyravell-test-harness".to_string(),
                        InstalledFileRecord {
                            relative_path: "bin/cyravell-test-harness".to_string(),
                            size_bytes: bytes,
                            sha256: sha,
                            mode: 0o755,
                        },
                    );
                }
            }
        }

        // Backup existing rules
        let b_rules_dir = backup_dir.join("rules");
        safe_create_dir_all(&b_rules_dir)?;
        if active_rules_dir.exists() {
            if let Ok(entries) = fs::read_dir(&active_rules_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() && !p.is_symlink() {
                        let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        let b_file = b_rules_dir.join(fname);
                        if let Ok(bytes) = safe_copy_file(&p, &b_file, 0o644) {
                            if let Ok(sha) = compute_sha256(&b_file) {
                                backup_records.insert(
                                    format!("rules/{}", fname),
                                    InstalledFileRecord {
                                        relative_path: format!("rules/{}", fname),
                                        size_bytes: bytes,
                                        sha256: sha,
                                        mode: 0o644,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }

        // Backup existing state
        let _ = safe_copy_file(&state_file, &backup_dir.join("install_state.json"), 0o600);
        backup_created = true;
    }

    // Step 5: Atomic Activation
    safe_create_dir_all(&active_bin_dir)?;
    safe_create_dir_all(&active_rules_dir)?;

    let target_engine = active_bin_dir.join("cyravell-engine");
    if let Err(e) = safe_copy_file(&staged_bin, &target_engine, 0o755) {
        cleanup_staging(&staging_dir);
        return Err(match e {
            InstallError::SecurityViolation(msg) => InstallError::SecurityViolation(msg),
            other => InstallError::ActivationFailed(format!(
                "Failed to activate engine binary: {}",
                other
            )),
        });
    }

    if has_harness {
        let target_harness = active_bin_dir.join("cyravell-test-harness");
        if let Err(e) = safe_copy_file(&staged_harness, &target_harness, 0o755) {
            cleanup_staging(&staging_dir);
            return Err(match e {
                InstallError::SecurityViolation(msg) => InstallError::SecurityViolation(msg),
                other => InstallError::ActivationFailed(format!(
                    "Failed to activate harness binary: {}",
                    other
                )),
            });
        }
    }

    // Activate rules
    let base_staged_rules = if staged_rules_dir.join("rules").is_dir() {
        staged_rules_dir.join("rules")
    } else {
        staged_rules_dir.clone()
    };

    if let Ok(entries) = fs::read_dir(&base_staged_rules) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let dst_rule = active_rules_dir.join(fname);
                if let Err(e) = safe_copy_file(&p, &dst_rule, 0o644) {
                    cleanup_staging(&staging_dir);
                    return Err(match e {
                        InstallError::SecurityViolation(msg) => {
                            InstallError::SecurityViolation(msg)
                        }
                        other => InstallError::ActivationFailed(format!(
                            "Failed to activate rule file '{}': {}",
                            fname, other
                        )),
                    });
                }
            }
        }
    }

    // Step 6: Post-Activation Sanity Check (Health verification)
    if !options.skip_post_install_test {
        let sanity = Command::new(&target_engine).arg("--version").output();

        let passed = match sanity {
            Ok(out) => out.status.success(),
            Err(_) => false,
        };

        if !passed {
            // AUTOMATIC ROLLBACK to last known good
            eprintln!("Critical: Newly activated engine binary failed post-install sanity check! Initiating automatic rollback...");
            if backup_created {
                let _ = restore_from_backup(
                    &backup_dir,
                    &active_bin_dir,
                    &active_rules_dir,
                    &state_file,
                );
            }
            cleanup_staging(&staging_dir);
            return Err(InstallError::SanityCheckFailed(
                "Activated binary failed health check; rolled back to previous version".to_string(),
            ));
        }
    }

    // Step 7: Record Updated State
    let mut installed_files = BTreeMap::new();
    if let Ok(meta) = fs::metadata(&target_engine) {
        if let Ok(sha) = compute_sha256(&target_engine) {
            installed_files.insert(
                "bin/cyravell-engine".to_string(),
                InstalledFileRecord {
                    relative_path: "bin/cyravell-engine".to_string(),
                    size_bytes: meta.len(),
                    sha256: sha,
                    mode: 0o755,
                },
            );
        }
    }

    for (k, v) in unpacked_rules {
        installed_files.insert(k, v);
    }

    let mut new_state = InstallState::new(
        &report.release_version,
        &report.source_commit,
        report.signing_key_id.as_deref(),
        report.signing_key_id.as_deref().unwrap_or("unknown"),
        report.is_official,
        &options.install_prefix,
        options.is_user_mode,
    );

    new_state.installed_files = installed_files;
    new_state.backup_version = previous_version.clone();
    new_state.backup_files = backup_records;
    new_state.high_water_version = high_water_version;
    new_state.last_operation = if previous_version.is_some() {
        "update".to_string()
    } else {
        "install".to_string()
    };
    new_state.last_operation_timestamp = Utc::now().to_rfc3339();

    new_state.save_atomic(&state_file)?;

    cleanup_staging(&staging_dir);

    Ok(InstallReport {
        success: true,
        operation: new_state.last_operation.clone(),
        previous_version,
        active_version: Some(report.release_version),
        install_prefix: options.install_prefix.clone(),
        files_installed: new_state.installed_files.keys().cloned().collect(),
        backup_created,
        details: format!(
            "Successfully installed Cyravell {} to '{}'",
            new_state.active_version,
            options.install_prefix.display()
        ),
        errors: Vec::new(),
    })
}

/// Restores files from the .backup directory into active target paths.
fn restore_from_backup(
    backup_dir: &Path,
    active_bin_dir: &Path,
    active_rules_dir: &Path,
    state_file: &Path,
) -> Result<(), InstallError> {
    let b_engine = backup_dir.join("cyravell-engine");
    if b_engine.exists() {
        safe_copy_file(&b_engine, &active_bin_dir.join("cyravell-engine"), 0o755)?;
    }

    let b_harness = backup_dir.join("cyravell-test-harness");
    if b_harness.exists() {
        let _ = safe_copy_file(
            &b_harness,
            &active_bin_dir.join("cyravell-test-harness"),
            0o755,
        );
    }

    let b_rules = backup_dir.join("rules");
    if b_rules.exists() {
        if let Ok(entries) = fs::read_dir(&b_rules) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    let _ = safe_copy_file(&p, &active_rules_dir.join(fname), 0o644);
                }
            }
        }
    }

    let b_state = backup_dir.join("install_state.json");
    if b_state.exists() {
        let _ = safe_copy_file(&b_state, state_file, 0o600);
    }

    Ok(())
}

/// Executes an authorized, manual rollback to the previous known-good installation.
pub fn rollback_installation(
    install_prefix: &Path,
    reason: &str,
    skip_post_test: bool,
) -> Result<InstallReport, InstallError> {
    if reason.trim().len() < 8 {
        return Err(InstallError::InvalidDowngradeReason(
            "Rollback requires an operator reason of at least 8 characters".to_string(),
        ));
    }

    let share_dir = install_prefix.join("share/cyravell");
    let state_file = share_dir.join("install_state.json");
    let backup_dir = share_dir.join(".backup");

    let _lock = InstallLockGuard::acquire(&share_dir)?;

    let mut state = InstallState::load_from_path(&state_file)?;
    let prev_version = match state.backup_version {
        Some(ref v) => v.clone(),
        None => {
            return Err(InstallError::RollbackFailed(
                "No previous version backup exists in install state".to_string(),
            ));
        }
    };

    if !backup_dir.exists() {
        return Err(InstallError::RollbackFailed(
            "Backup directory .backup does not exist".to_string(),
        ));
    }

    let active_bin_dir = install_prefix.join("bin");
    let active_rules_dir = share_dir.join("rules");

    // Verify backup files integrity before restoring
    for (rel_path, record) in &state.backup_files {
        let backup_file = if rel_path.starts_with("bin/") {
            let fname = rel_path.strip_prefix("bin/").unwrap();
            backup_dir.join(fname)
        } else if rel_path.starts_with("rules/") {
            let fname = rel_path.strip_prefix("rules/").unwrap();
            backup_dir.join("rules").join(fname)
        } else {
            backup_dir.join(rel_path)
        };

        if !backup_file.exists() {
            return Err(InstallError::RollbackFailed(format!(
                "Required backup file '{}' is missing from backup directory",
                backup_file.display()
            )));
        }

        let sha = compute_sha256(&backup_file).map_err(|e| {
            InstallError::RollbackFailed(format!(
                "Failed to verify backup file digest '{}': {}",
                backup_file.display(),
                e
            ))
        })?;

        if sha.to_lowercase() != record.sha256.to_lowercase() {
            return Err(InstallError::SecurityViolation(format!(
                "Backup file '{}' has been tampered with or corrupted! Expected {}, got {}",
                backup_file.display(),
                record.sha256,
                sha
            )));
        }
    }

    restore_from_backup(&backup_dir, &active_bin_dir, &active_rules_dir, &state_file)?;

    // Sanity check restored binary
    let restored_engine = active_bin_dir.join("cyravell-engine");
    if !skip_post_test {
        let sanity = Command::new(&restored_engine).arg("--version").output();

        let passed = match sanity {
            Ok(out) => out.status.success(),
            Err(_) => false,
        };

        if !passed {
            return Err(InstallError::SanityCheckFailed(
                "Restored engine binary failed sanity check!".to_string(),
            ));
        }
    }

    // Update state recording rollback
    let old_active = state.active_version.clone();
    state.active_version = prev_version.clone();
    state.last_operation = "rollback".to_string();
    state.last_operation_timestamp = Utc::now().to_rfc3339();
    state.save_atomic(&state_file)?;

    Ok(InstallReport {
        success: true,
        operation: "rollback".to_string(),
        previous_version: Some(old_active),
        active_version: Some(prev_version.clone()),
        install_prefix: install_prefix.to_path_buf(),
        files_installed: state.installed_files.keys().cloned().collect(),
        backup_created: false,
        details: format!(
            "Successfully rolled back Cyravell to version '{}' (Reason: {})",
            prev_version, reason
        ),
        errors: Vec::new(),
    })
}

/// Safely uninstalls Cyravell, preserving persistent user security data unless purge_data is true.
pub fn uninstall(
    install_prefix: &Path,
    purge_data: bool,
    _reason: Option<&str>,
) -> Result<InstallReport, InstallError> {
    let share_dir = install_prefix.join("share/cyravell");
    let bin_dir = install_prefix.join("bin");
    let state_file = share_dir.join("install_state.json");

    let _lock = if share_dir.exists() {
        Some(InstallLockGuard::acquire(&share_dir)?)
    } else {
        None
    };

    let previous_version = if state_file.exists() {
        InstallState::load_from_path(&state_file)
            .ok()
            .map(|s| s.active_version)
    } else {
        None
    };

    // Remove installed executables
    let engine_bin = bin_dir.join("cyravell-engine");
    if engine_bin.exists() && !engine_bin.is_symlink() {
        let _ = fs::remove_file(&engine_bin);
    }
    let harness_bin = bin_dir.join("cyravell-test-harness");
    if harness_bin.exists() && !harness_bin.is_symlink() {
        let _ = fs::remove_file(&harness_bin);
    }

    // Remove rules directory
    let rules_dir = share_dir.join("rules");
    if rules_dir.exists() && !rules_dir.is_symlink() {
        let _ = fs::remove_dir_all(&rules_dir);
    }

    // Remove backup directory
    let backup_dir = share_dir.join(".backup");
    if backup_dir.exists() && !backup_dir.is_symlink() {
        let _ = fs::remove_dir_all(&backup_dir);
    }

    // Remove install_state.json
    if state_file.exists() && !state_file.is_symlink() {
        let _ = fs::remove_file(&state_file);
    }

    // If purge_data is requested, remove user data dir as well
    if purge_data {
        let data_dir = share_dir.join("data");
        if data_dir.exists() && !data_dir.is_symlink() {
            let _ = fs::remove_dir_all(&data_dir);
        }
    }

    Ok(InstallReport {
        success: true,
        operation: "uninstall".to_string(),
        previous_version,
        active_version: None,
        install_prefix: install_prefix.to_path_buf(),
        files_installed: Vec::new(),
        backup_created: false,
        details: format!(
            "Successfully uninstalled Cyravell from '{}' (User data purged: {})",
            install_prefix.display(),
            purge_data
        ),
        errors: Vec::new(),
    })
}
