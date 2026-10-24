// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::{BaselineTrust, DependencyBaseline, PackageEcosystem, SnapshotReason};
use crate::package::advisory::AdvisoryDatabase;
use crate::package::manifest::{ManifestError, ManifestInspector};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Computes a deterministic SHA-256 fingerprint for a dependency state.
/// Excludes creation timestamp and volatile metadata so equivalent states produce identical fingerprints.
pub fn compute_baseline_fingerprint(
    ecosystem: PackageEcosystem,
    package_manager: &str,
    manifest_fingerprint: Option<&str>,
    direct: &BTreeMap<String, String>,
    resolved: &BTreeMap<String, String>,
    transitive: &BTreeMap<String, String>,
    integrity: &BTreeMap<String, String>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", ecosystem).as_bytes());
    hasher.update(package_manager.as_bytes());
    if let Some(mfp) = manifest_fingerprint {
        hasher.update(b"|mfp:");
        hasher.update(mfp.as_bytes());
    }
    hasher.update(b"|direct:");
    for (k, v) in direct {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(b";");
    }
    hasher.update(b"|resolved:");
    for (k, v) in resolved {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(b";");
    }
    hasher.update(b"|transitive:");
    for (k, v) in transitive {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(b";");
    }
    hasher.update(b"|integrity:");
    for (k, v) in integrity {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(b";");
    }
    format!("{:x}", hasher.finalize())
}

/// Detects the package ecosystem and package manager for a given workspace path.
pub fn detect_workspace_ecosystem(workspace_path: &Path) -> Option<(PackageEcosystem, String)> {
    if workspace_path.join("package.json").exists() {
        if workspace_path.join("pnpm-lock.yaml").exists() {
            Some((PackageEcosystem::Pnpm, "pnpm".to_string()))
        } else if workspace_path.join("yarn.lock").exists() {
            Some((PackageEcosystem::Yarn, "yarn".to_string()))
        } else {
            Some((PackageEcosystem::Npm, "npm".to_string()))
        }
    } else if workspace_path.join("Cargo.toml").exists() {
        Some((PackageEcosystem::Cargo, "cargo".to_string()))
    } else if workspace_path.join("requirements.txt").exists() {
        Some((PackageEcosystem::Pip, "pip".to_string()))
    } else {
        None
    }
}

/// Creates a dependency baseline snapshot for a workspace.
pub fn create_workspace_baseline(
    workspace_path: &Path,
    ecosystem_hint: Option<PackageEcosystem>,
    reason: SnapshotReason,
    trust_state: BaselineTrust,
    advisory_db: &AdvisoryDatabase,
) -> Result<DependencyBaseline, ManifestError> {
    let canonical = workspace_path
        .canonicalize()
        .unwrap_or_else(|_| workspace_path.to_path_buf());

    let (ecosystem, pm_name) = match ecosystem_hint {
        Some(eco) => {
            let name = match eco {
                PackageEcosystem::Npm => "npm",
                PackageEcosystem::Pnpm => "pnpm",
                PackageEcosystem::Yarn => "yarn",
                PackageEcosystem::Pip => "pip",
                PackageEcosystem::Cargo => "cargo",
            };
            (eco, name.to_string())
        }
        None => detect_workspace_ecosystem(&canonical)
            .unwrap_or((PackageEcosystem::Npm, "npm".to_string())),
    };

    let scan = ManifestInspector::inspect(ecosystem, &canonical, None)?;

    let mut direct_dependencies = BTreeMap::new();
    for (k, v) in &scan.declared_dependencies {
        direct_dependencies.insert(k.clone(), v.clone());
    }

    let mut resolved_dependencies = BTreeMap::new();
    let mut transitive_dependencies = BTreeMap::new();
    let mut integrity_metadata = BTreeMap::new();

    for dep in &scan.resolved_dependencies {
        resolved_dependencies.insert(dep.name.clone(), dep.version.clone());
        if !dep.is_direct {
            transitive_dependencies.insert(dep.name.clone(), dep.version.clone());
        }
        if let Some(ref integ) = dep.integrity {
            integrity_metadata.insert(dep.name.clone(), integ.clone());
        }
    }

    let baseline_fingerprint = compute_baseline_fingerprint(
        ecosystem,
        &pm_name,
        scan.fingerprint.as_deref(),
        &direct_dependencies,
        &resolved_dependencies,
        &transitive_dependencies,
        &integrity_metadata,
    );

    Ok(DependencyBaseline {
        workspace_path: canonical.display().to_string(),
        ecosystem,
        package_manager: pm_name,
        manifest_fingerprint: scan.fingerprint,
        direct_dependencies,
        resolved_dependencies,
        transitive_dependencies,
        integrity_metadata,
        created_at: chrono::Utc::now(),
        trust_state,
        advisory_database_version: advisory_db.fingerprint(),
        reason,
        baseline_fingerprint,
    })
}

/// Thread-safe in-memory store for trusted dependency baselines and active drift reports.
#[derive(Debug, Default)]
pub struct BaselineStore {
    baselines: RwLock<HashMap<PathBuf, DependencyBaseline>>,
    drift_reports: RwLock<HashMap<PathBuf, crate::model::DriftReport>>,
}

impl BaselineStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalizes path for canonical index lookup.
    fn canonical_key(path: &Path) -> PathBuf {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    }

    /// Retrieves current baseline for workspace.
    pub fn get_baseline(&self, workspace: &Path) -> Option<DependencyBaseline> {
        let key = Self::canonical_key(workspace);
        self.baselines.read().ok()?.get(&key).cloned()
    }

    /// Sets or replaces the baseline, enforcing security trust boundaries:
    /// A VerifiedApproved baseline cannot be overwritten by an unverified or review-required state
    /// unless explicitly forced or approved.
    pub fn attempt_replace_baseline(
        &self,
        workspace: &Path,
        new_baseline: DependencyBaseline,
        allow_unverified_override: bool,
    ) -> Result<(), &'static str> {
        let key = Self::canonical_key(workspace);
        let mut store = self.baselines.write().map_err(|_| "Lock poisoned")?;

        if let Some(existing) = store.get(&key) {
            if existing.trust_state == BaselineTrust::VerifiedApproved
                && new_baseline.trust_state != BaselineTrust::VerifiedApproved
                && !allow_unverified_override
            {
                return Err("Cannot replace VerifiedApproved baseline with an unverified or review-required state without explicit approval");
            }
        }

        store.insert(key, new_baseline);
        Ok(())
    }

    /// Stores a freshly created initial baseline.
    pub fn set_baseline(&self, workspace: &Path, baseline: DependencyBaseline) {
        let key = Self::canonical_key(workspace);
        if let Ok(mut store) = self.baselines.write() {
            store.insert(key, baseline);
        }
    }

    /// Retrieves current drift report for workspace.
    pub fn get_drift_report(&self, workspace: &Path) -> Option<crate::model::DriftReport> {
        let key = Self::canonical_key(workspace);
        self.drift_reports.read().ok()?.get(&key).cloned()
    }

    /// Updates active drift report for workspace.
    pub fn set_drift_report(&self, workspace: &Path, report: crate::model::DriftReport) {
        let key = Self::canonical_key(workspace);
        if let Ok(mut store) = self.drift_reports.write() {
            store.insert(key, report);
        }
    }

    /// Clears drift report for workspace (e.g. after review or reconciliation).
    pub fn clear_drift_report(&self, workspace: &Path) {
        let key = Self::canonical_key(workspace);
        if let Ok(mut store) = self.drift_reports.write() {
            store.remove(&key);
        }
    }
}
