// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::audit::AuditLog;
use crate::model::{BaselineTrust, DriftReport, PackageEcosystem, Severity, SnapshotReason};
use crate::package::advisory::AdvisoryDatabase;
use crate::package::baseline::{create_workspace_baseline, BaselineStore};
use crate::package::drift::DriftDetector;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedFileState {
    modified: SystemTime,
    size: u64,
    content_hash: String,
}

pub struct WorkspaceMonitor {
    workspaces: Mutex<HashSet<PathBuf>>,
    file_cache: Mutex<HashMap<PathBuf, CachedFileState>>,
}

impl Default for WorkspaceMonitor {
    fn default() -> Self {
        Self {
            workspaces: Mutex::new(HashSet::new()),
            file_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl WorkspaceMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Known dependency file relative paths inspected during bounded monitoring.
    const MONITORED_FILENAMES: &'static [&'static str] = &[
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "Cargo.toml",
        "Cargo.lock",
        "requirements.txt",
    ];

    fn canonical_path(p: &Path) -> PathBuf {
        p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
    }

    /// Registers a workspace for bounded monitoring.
    /// Returns the list of detected dependency files currently present.
    pub fn register_workspace(&self, workspace: &Path) -> Vec<String> {
        let canonical = Self::canonical_path(workspace);
        let mut found_files = Vec::new();

        for filename in Self::MONITORED_FILENAMES {
            let file_path = canonical.join(filename);
            if file_path.exists() && file_path.is_file() {
                found_files.push(filename.to_string());
                if let Ok(meta) = std::fs::metadata(&file_path) {
                    if let Ok(content) = std::fs::read(&file_path) {
                        let hash = format!("{:x}", Sha256::digest(&content));
                        if let Ok(mut cache) = self.file_cache.lock() {
                            cache.insert(
                                file_path,
                                CachedFileState {
                                    modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                                    size: meta.len(),
                                    content_hash: hash,
                                },
                            );
                        }
                    }
                }
            }
        }

        if let Ok(mut ws) = self.workspaces.lock() {
            ws.insert(canonical);
        }

        found_files
    }

    /// Unregisters a workspace from monitoring.
    pub fn unregister_workspace(&self, workspace: &Path) {
        let canonical = Self::canonical_path(workspace);
        if let Ok(mut ws) = self.workspaces.lock() {
            ws.remove(&canonical);
        }
    }

    /// Lists currently registered workspaces.
    pub fn monitored_workspaces(&self) -> Vec<PathBuf> {
        self.workspaces
            .lock()
            .map(|ws| ws.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Performs bounded reconciliation across a registered workspace.
    /// Checks if monitored dependency files were modified, added, or deleted.
    /// If changes occurred, computes a fresh snapshot, compares with the trusted baseline,
    /// and records forensic events in the audit log.
    pub fn reconcile_workspace(
        &self,
        workspace: &Path,
        baseline_store: &BaselineStore,
        advisory_db: &AdvisoryDatabase,
        audit: Option<&AuditLog>,
    ) -> Result<Option<DriftReport>, String> {
        let canonical = Self::canonical_path(workspace);

        let mut changes_detected = false;
        let mut changed_files = Vec::new();

        let mut current_file_states = HashMap::new();

        for filename in Self::MONITORED_FILENAMES {
            let file_path = canonical.join(filename);
            if file_path.exists() && file_path.is_file() {
                // Handle potential atomic writes / temporary truncation with brief retry
                let mut attempts = 0;
                let mut content = Vec::new();
                let mut meta_opt = None;

                while attempts < 3 {
                    if let Ok(m) = std::fs::metadata(&file_path) {
                        if m.len() > 0 || attempts == 2 {
                            if let Ok(bytes) = std::fs::read(&file_path) {
                                content = bytes;
                                meta_opt = Some(m);
                                break;
                            }
                        }
                    }
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }

                if let Some(meta) = meta_opt {
                    let hash = format!("{:x}", Sha256::digest(&content));
                    let state = CachedFileState {
                        modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                        size: meta.len(),
                        content_hash: hash,
                    };
                    current_file_states.insert(file_path.clone(), state);
                }
            }
        }

        // Compare against cached file states
        if let Ok(mut cache) = self.file_cache.lock() {
            for (path, current_st) in &current_file_states {
                match cache.get(path) {
                    Some(cached_st) => {
                        if cached_st.content_hash != current_st.content_hash {
                            changes_detected = true;
                            changed_files.push(path.display().to_string());
                        }
                    }
                    None => {
                        changes_detected = true;
                        changed_files.push(path.display().to_string());
                    }
                }
            }

            // Check for deleted monitored files
            for cached_path in cache.keys() {
                if cached_path.starts_with(&canonical)
                    && !current_file_states.contains_key(cached_path)
                {
                    changes_detected = true;
                    changed_files.push(format!("(deleted) {}", cached_path.display()));
                }
            }

            // Update cache
            for (path, st) in current_file_states {
                cache.insert(path, st);
            }
        }

        // If no file changes detected and a drift report is already active, return it
        if !changes_detected {
            return Ok(baseline_store.get_drift_report(&canonical));
        }

        // File changes detected: Re-evaluate dependency baseline and drift
        let current_snapshot = match create_workspace_baseline(
            &canonical,
            None,
            SnapshotReason::Reconciliation,
            BaselineTrust::PostOperationObserved,
            advisory_db,
        ) {
            Ok(b) => b,
            Err(e) => {
                let report = DriftDetector::for_corrupted_metadata(
                    &canonical.display().to_string(),
                    PackageEcosystem::Npm,
                    &e.to_string(),
                );
                baseline_store.set_drift_report(&canonical, report.clone());

                if let Some(a) = audit {
                    let _ = a.append(
                        &format!("drift-corrupt-{}", uuid::Uuid::new_v4()),
                        "MISSING_CORRUPTED_METADATA",
                        &format!(
                            "Workspace: {}, Files: {}, Error: {}",
                            canonical.display(),
                            changed_files.join(", "),
                            e
                        ),
                        Severity::High,
                    );
                }

                return Ok(Some(report));
            }
        };

        let trusted_baseline = match baseline_store.get_baseline(&canonical) {
            Some(b) => b,
            None => {
                // No prior baseline: establish unverified initial baseline
                let mut initial = current_snapshot;
                initial.trust_state = BaselineTrust::UnverifiedInitial;
                initial.reason = SnapshotReason::InitialBaseline;
                baseline_store.set_baseline(&canonical, initial.clone());

                if let Some(a) = audit {
                    let _ = a.append(
                        &format!("baseline-init-{}", uuid::Uuid::new_v4()),
                        "BASELINE_CREATED",
                        &format!(
                            "Workspace: {}, Fingerprint: {}, Trust: UNVERIFIED_INITIAL",
                            canonical.display(),
                            initial.baseline_fingerprint
                        ),
                        Severity::Low,
                    );
                }

                return Ok(None);
            }
        };

        // Detect drift against trusted baseline
        let drift_report = DriftDetector::detect(&trusted_baseline, &current_snapshot, advisory_db);
        baseline_store.set_drift_report(&canonical, drift_report.clone());

        if drift_report.has_drift {
            if let Some(a) = audit {
                let finding_summary: Vec<String> = drift_report
                    .findings
                    .iter()
                    .map(|f| format!("{}: {:?}", f.package_name, f.change_type))
                    .collect();

                let max_sev = drift_report
                    .findings
                    .iter()
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Medium);

                let _ = a.append(
                    &format!("drift-reconcile-{}", uuid::Uuid::new_v4()),
                    "DEPENDENCY_DRIFT_DETECTED",
                    &format!(
                        "Workspace: {}, ChangedFiles: {}, Findings: {}, Attribution: Observed via local filesystem reconciliation (unattributed background change)",
                        canonical.display(),
                        changed_files.join(", "),
                        finding_summary.join("; ")
                    ),
                    max_sev,
                );
            }
        }

        Ok(Some(drift_report))
    }
}
