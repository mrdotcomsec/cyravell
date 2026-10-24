// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::PackageEcosystem;
use crate::package::bundle::compare_db_versions;
use crate::package::strict_json::validate_no_duplicate_keys;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
pub enum StateError {
    Io(std::io::Error),
    Corrupted(String),
    SymlinkForbidden(String),
    InsecurePermissions(String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error in security state: {}", e),
            Self::Corrupted(msg) => write!(f, "Security state file corrupted: {}", msg),
            Self::SymlinkForbidden(msg) => {
                write!(f, "Symlinks forbidden for security state: {}", msg)
            }
            Self::InsecurePermissions(msg) => {
                write!(f, "Insecure permissions for security state: {}", msg)
            }
        }
    }
}

impl std::error::Error for StateError {}

impl From<std::io::Error> for StateError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Durable, tamper-resistant anti-rollback and security state.
/// Persists the monotonic database version high-water mark and irreversible
/// malicious package tombstones across engine restarts, database deletions, and rollbacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisorySecurityState {
    pub high_water_version: String,
    pub malicious_tombstones: HashSet<String>,
    pub last_updated: DateTime<Utc>,
}

impl AdvisorySecurityState {
    pub fn new(initial_version: &str) -> Self {
        Self {
            high_water_version: initial_version.to_string(),
            malicious_tombstones: HashSet::new(),
            last_updated: Utc::now(),
        }
    }

    pub fn load_from_path(path: &Path, fallback_version: &str) -> Result<Self, StateError> {
        if !path.exists() {
            return Ok(Self::new(fallback_version));
        }

        #[cfg(unix)]
        {
            let meta = std::fs::symlink_metadata(path)?;
            if meta.file_type().is_symlink() {
                return Err(StateError::SymlinkForbidden(format!(
                    "Path '{}' is a symbolic link",
                    path.display()
                )));
            }
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                return Err(StateError::InsecurePermissions(format!(
                    "Path '{}' is world-writable ({:o})",
                    path.display(),
                    mode
                )));
            }
        }

        let content = std::fs::read_to_string(path)?;
        if let Err(e) = validate_no_duplicate_keys(&content) {
            return Err(StateError::Corrupted(format!(
                "Duplicate key in security state: {}",
                e
            )));
        }

        let state: AdvisorySecurityState = serde_json::from_str(&content)
            .map_err(|e| StateError::Corrupted(format!("Failed to parse security state: {}", e)))?;

        Ok(state)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), StateError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }

        let tmp_path = parent.join(format!(".tmp_state_{}", uuid::Uuid::new_v4()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        let json =
            serde_json::to_string_pretty(self).map_err(|e| StateError::Corrupted(e.to_string()))?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(&tmp_path, path)?;

        #[cfg(unix)]
        {
            if let Ok(dir_file) = std::fs::File::open(parent) {
                let _ = dir_file.sync_all();
            }
        }

        Ok(())
    }

    /// Monotonically advances the high-water version mark.
    /// Never allows downgrading or resetting to a lower version.
    pub fn record_version(&mut self, version: &str) {
        if compare_db_versions(version, &self.high_water_version) == Ok(Ordering::Greater) {
            self.high_water_version = version.to_string();
            self.last_updated = Utc::now();
        }
    }

    /// Irreversibly records a confirmed malicious package.
    pub fn record_malicious_package(&mut self, ecosystem: PackageEcosystem, package_name: &str) {
        let key = format!("{}:{}", ecosystem.as_str(), package_name.to_lowercase());
        if self.malicious_tombstones.insert(key) {
            self.last_updated = Utc::now();
        }
    }

    /// Checks if a package is recorded as confirmed malicious in persistent security state.
    pub fn is_malicious(&self, ecosystem: PackageEcosystem, package_name: &str) -> bool {
        let key = format!("{}:{}", ecosystem.as_str(), package_name.to_lowercase());
        self.malicious_tombstones.contains(&key)
    }
}
