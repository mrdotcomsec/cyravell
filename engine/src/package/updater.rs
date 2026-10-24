// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::audit::AuditLog;
use crate::model::{
    BundleImportResult, BundleInspectionResult, DriftChangeType, DriftFinding, DriftReport,
    FindingConfidence, Severity,
};
use crate::package::advisory::{AdvisoryDatabase, AdvisoryRecord};
use crate::package::assessor::PackageSecurityAssessor;
use crate::package::baseline::BaselineStore;
use crate::package::bundle::{compare_db_versions, AdvisoryBundle, BundleValidationError};
use crate::package::trust::TrustedKeyStore;
use chrono::Utc;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug)]
pub enum UpdateError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    Validation(BundleValidationError),
    AtomicActivationFailed(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error during advisory update: {}", e),
            Self::Parse(e) => write!(f, "JSON parse error in advisory bundle: {}", e),
            Self::Validation(e) => write!(f, "Advisory bundle validation rejected: {}", e),
            Self::AtomicActivationFailed(msg) => {
                write!(f, "Atomic database activation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for UpdateError {}

impl From<std::io::Error> for UpdateError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for UpdateError {
    fn from(e: serde_json::Error) -> Self {
        Self::Parse(e)
    }
}

impl From<BundleValidationError> for UpdateError {
    fn from(e: BundleValidationError) -> Self {
        Self::Validation(e)
    }
}

pub struct AdvisoryUpdater {
    assessor: Arc<PackageSecurityAssessor>,
    baseline_store: Arc<BaselineStore>,
    audit_logger: Arc<AuditLog>,
    trusted_keys: Arc<TrustedKeyStore>,
    storage_path: PathBuf,
}

impl AdvisoryUpdater {
    pub fn new(
        assessor: Arc<PackageSecurityAssessor>,
        baseline_store: Arc<BaselineStore>,
        audit_logger: Arc<AuditLog>,
        trusted_keys: Arc<TrustedKeyStore>,
        storage_path: PathBuf,
    ) -> Self {
        Self {
            assessor,
            baseline_store,
            audit_logger,
            trusted_keys,
            storage_path,
        }
    }

    pub fn assessor(&self) -> &Arc<PackageSecurityAssessor> {
        &self.assessor
    }

    pub fn trusted_keys(&self) -> &Arc<TrustedKeyStore> {
        &self.trusted_keys
    }

    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }

    /// Inspects an advisory bundle without activating it.
    /// Performs cryptographic signature verification, format checks, and computes diff.
    pub fn inspect_bundle(
        &self,
        bundle_path: &Path,
    ) -> Result<BundleInspectionResult, UpdateError> {
        let content = std::fs::read_to_string(bundle_path)?;
        let bundle: AdvisoryBundle = serde_json::from_str(&content)?;

        let active_db = self.assessor.advisory_db();
        let active_ver = active_db.database_version();

        let ord = compare_db_versions(&bundle.database_version, active_ver);
        let would_rollback = ord != Ordering::Greater;

        // Perform validation check without throwing early on rollback (inspection should report it)
        let validation_res =
            bundle.validate_and_authenticate(&self.trusted_keys, Some(active_ver), true);
        let is_valid = validation_res.is_ok();
        let signature_valid = !matches!(
            validation_res,
            Err(BundleValidationError::SignatureError(_))
                | Err(BundleValidationError::PayloadDigestMismatch { .. })
        );

        // Compute diff against active database records
        let active_map: HashSet<String> = active_db
            .all_advisories()
            .iter()
            .map(|a| a.id.clone())
            .collect();
        let candidate_map: HashSet<String> =
            bundle.advisories.iter().map(|a| a.id.clone()).collect();

        let new_records: Vec<String> = bundle
            .advisories
            .iter()
            .filter(|a| !active_map.contains(&a.id))
            .map(|a| format!("{} ({} {})", a.id, a.ecosystem, a.package_name))
            .collect();

        let removed_records: Vec<String> = active_db
            .all_advisories()
            .iter()
            .filter(|a| !candidate_map.contains(&a.id))
            .map(|a| format!("{} ({} {})", a.id, a.ecosystem, a.package_name))
            .collect();

        let updated_records: Vec<String> = bundle
            .advisories
            .iter()
            .filter(|cand| {
                if let Some(existing) = active_db.all_advisories().iter().find(|a| a.id == cand.id)
                {
                    existing != *cand
                } else {
                    false
                }
            })
            .map(|a| format!("{} ({} {})", a.id, a.ecosystem, a.package_name))
            .collect();

        let malicious_count = bundle.advisories.iter().filter(|a| a.is_malicious).count();
        let vulns_count = bundle.advisories.iter().filter(|a| !a.is_malicious).count();

        let summary = format!(
            "Candidate v{} by '{}': {} records ({} new, {} updated, {} removed, {} malicious). Valid: {}, Would rollback: {}",
            bundle.database_version,
            bundle.publisher,
            bundle.advisories.len(),
            new_records.len(),
            updated_records.len(),
            removed_records.len(),
            malicious_count,
            is_valid,
            would_rollback
        );

        Ok(BundleInspectionResult {
            bundle_format_version: bundle.bundle_format_version,
            database_version: bundle.database_version.clone(),
            created_at: bundle.created_at,
            publisher: bundle.publisher,
            key_id: bundle.key_id,
            is_valid,
            signature_valid,
            candidate_version: bundle.database_version,
            active_version: active_ver.to_string(),
            would_rollback,
            records_count: bundle.advisories.len(),
            malicious_count,
            vulnerabilities_count: vulns_count,
            new_records,
            updated_records,
            removed_records,
            summary,
        })
    }

    /// Atomically validates, verifies, and activates an advisory bundle.
    /// On failure: the previous active database remains 100% usable and unaffected.
    /// On success: activates the database, writes atomic persistence, updates audit chain,
    /// and reassesses affected dependency baselines.
    pub fn import_bundle(
        &self,
        bundle_path: &Path,
        allow_rollback: bool,
    ) -> Result<BundleImportResult, UpdateError> {
        let content = std::fs::read_to_string(bundle_path)?;
        let bundle: AdvisoryBundle = serde_json::from_str(&content)?;

        let previous_version = self.assessor.advisory_db().database_version().to_string();

        // 1. Authenticate and validate candidate bundle
        if let Err(err) = bundle.validate_and_authenticate(
            &self.trusted_keys,
            Some(&previous_version),
            allow_rollback,
        ) {
            // Log rejection to tamper-evident audit trail
            let _ = self.audit_logger.append(
                &format!("adv-reject-{}", uuid::Uuid::new_v4()),
                "PACKAGE_ADVISORY_UPDATE_REJECTED",
                &format!(
                    "Rejected advisory bundle v{} from publisher '{}' (key: '{}'): {}",
                    bundle.database_version, bundle.publisher, bundle.key_id, err
                ),
                Severity::High,
            );
            return Err(UpdateError::Validation(err));
        }

        // 2. Safe transaction: atomic write to persistence file
        if let Some(parent) = self.storage_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp_path = self
            .storage_path
            .with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        let persisted = crate::package::advisory::PersistedAdvisoryDb {
            database_version: bundle.database_version.clone(),
            format_version: bundle.bundle_format_version.clone(),
            publisher: Some(bundle.publisher.clone()),
            key_id: Some(bundle.key_id.clone()),
            last_updated: Some(bundle.created_at),
            advisories: bundle.advisories.clone(),
        };
        let write_res = (|| -> Result<(), std::io::Error> {
            let mut file = std::fs::File::create(&tmp_path)?;
            let json = serde_json::to_string_pretty(&persisted)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&tmp_path, &self.storage_path)?;
            Ok(())
        })();

        if let Err(e) = write_res {
            let _ = std::fs::remove_file(&tmp_path);
            let err_msg = format!("Failed atomic storage write: {}", e);
            let _ = self.audit_logger.append(
                &format!("adv-reject-{}", uuid::Uuid::new_v4()),
                "PACKAGE_ADVISORY_UPDATE_REJECTED",
                &format!(
                    "Rejected advisory bundle v{} during atomic file persistence: {}",
                    bundle.database_version, err_msg
                ),
                Severity::High,
            );
            return Err(UpdateError::AtomicActivationFailed(err_msg));
        }

        // 3. Atomic in-memory activation
        let new_db = AdvisoryDatabase::from_bundle(&bundle);
        let fingerprint = new_db.fingerprint();
        let records_count = new_db.all_advisories().len();
        let malicious_count = new_db
            .all_advisories()
            .iter()
            .filter(|a| a.is_malicious)
            .count();

        self.assessor.update_advisory_db(new_db);

        // 4. Reassessment of monitored workspace dependency baselines
        let mut affected_workspaces = Vec::new();
        let newly_malicious: Vec<&AdvisoryRecord> = bundle
            .advisories
            .iter()
            .filter(|a| a.is_malicious)
            .collect();

        for (ws_path, baseline) in self.baseline_store.all_baselines() {
            let mut new_malicious_findings = Vec::new();

            // Check direct, resolved, and transitive dependencies
            let all_deps = baseline
                .direct_dependencies
                .iter()
                .chain(baseline.resolved_dependencies.iter())
                .chain(baseline.transitive_dependencies.iter());

            for (pkg_name, version) in all_deps {
                for mal_adv in &newly_malicious {
                    if mal_adv.ecosystem == baseline.ecosystem
                        && mal_adv.package_name.to_lowercase() == pkg_name.to_lowercase()
                        && (version.trim().is_empty()
                            || crate::package::advisory::version_matches_range(
                                version,
                                &mal_adv.affected_range,
                            ))
                    {
                        new_malicious_findings.push(DriftFinding {
                            finding_id: format!("drift-adv-{}", mal_adv.id),
                            ecosystem: baseline.ecosystem,
                            package_name: pkg_name.clone(),
                            previous_version: None,
                            current_version: Some(version.clone()),
                            change_type: DriftChangeType::MaliciousPackageDetected,
                            evidence: vec![format!(
                                "Newly activated advisory {} classifies {}@{} as MALICIOUS: {}",
                                mal_adv.id, pkg_name, version, mal_adv.title
                            )],
                            applicable_rules: vec![mal_adv.id.clone()],
                            status: FindingConfidence::Confirmed,
                            recommended_action: format!(
                                "Immediately remove or isolate confirmed malicious package {}",
                                pkg_name
                            ),
                            is_malicious: true,
                            severity: Severity::Critical,
                        });
                    }
                }
            }

            if !new_malicious_findings.is_empty() {
                let ws_str = ws_path.display().to_string();
                affected_workspaces.push(ws_str.clone());

                let report = DriftReport {
                    workspace_path: ws_str.clone(),
                    ecosystem: baseline.ecosystem,
                    trusted_baseline_fingerprint: Some(baseline.baseline_fingerprint.clone()),
                    current_fingerprint: baseline.baseline_fingerprint.clone(),
                    has_drift: true,
                    findings: new_malicious_findings,
                    evaluated_at: Utc::now(),
                    summary: format!(
                        "Reassessment after advisory update v{}: confirmed malicious package(s) detected in workspace",
                        bundle.database_version
                    ),
                };

                // Register active drift so authoritative execution gate hard-blocks this workspace
                self.baseline_store.set_drift_report(&ws_path, report);

                let _ = self.audit_logger.append(
                    &format!("drift-adv-{}", uuid::Uuid::new_v4()),
                    "PACKAGE_DRIFT_DETECTED",
                    &format!(
                        "Advisory update v{} triggered active malicious drift for workspace '{}'",
                        bundle.database_version, ws_str
                    ),
                    Severity::Critical,
                );
            }
        }

        // 5. Record successful activation in audit trail
        let audit_record = self.audit_logger.append(
            &format!("adv-update-{}", uuid::Uuid::new_v4()),
            "PACKAGE_ADVISORY_UPDATE_ACTIVATED",
            &format!(
                "Advisory database updated: v{} -> v{} (publisher: '{}', key: '{}', records: {}, malicious: {}, rollback: {})",
                previous_version,
                bundle.database_version,
                bundle.publisher,
                bundle.key_id,
                records_count,
                malicious_count,
                allow_rollback
            ),
            Severity::Info,
        );
        let audit_seq = audit_record.map(|r| r.sequence_number).unwrap_or(0);

        let message = format!(
            "Successfully imported and activated advisory database v{} ({} records, {} confirmed malicious). Previous version: v{}.",
            bundle.database_version, records_count, malicious_count, previous_version
        );

        Ok(BundleImportResult {
            previous_version,
            new_version: bundle.database_version,
            publisher: bundle.publisher,
            key_id: bundle.key_id,
            records_count,
            malicious_count,
            fingerprint,
            affected_workspaces,
            rollback_authorized: allow_rollback,
            audit_sequence: audit_seq,
            message,
        })
    }
}
