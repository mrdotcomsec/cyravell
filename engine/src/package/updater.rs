// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::audit::AuditLog;
use crate::gate::approval::ApprovalManager;
use crate::model::{
    BundleImportResult, BundleInspectionResult, DriftChangeType, DriftFinding, DriftReport,
    FindingConfidence, PackageEcosystem, Severity,
};
use crate::package::advisory::{AdvisoryDatabase, AdvisoryRecord};
use crate::package::assessor::PackageSecurityAssessor;
use crate::package::baseline::BaselineStore;
use crate::package::bundle::{compare_db_versions, AdvisoryBundle, BundleValidationError};
use crate::package::state::AdvisorySecurityState;
use crate::package::strict_json::validate_no_duplicate_keys;
use crate::package::trust::TrustedKeyStore;
use chrono::Utc;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

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
    security_state: Arc<RwLock<AdvisorySecurityState>>,
    approval_manager: Option<Arc<ApprovalManager>>,
}

impl AdvisoryUpdater {
    pub fn new(
        assessor: Arc<PackageSecurityAssessor>,
        baseline_store: Arc<BaselineStore>,
        audit_logger: Arc<AuditLog>,
        trusted_keys: Arc<TrustedKeyStore>,
        storage_path: PathBuf,
    ) -> Self {
        let active_ver = assessor.advisory_db().database_version().to_string();
        let state_path = storage_path.with_file_name("advisory_security_state.json");
        let initial_state = AdvisorySecurityState::load_from_path(&state_path, &active_ver)
            .unwrap_or_else(|_| AdvisorySecurityState::new(&active_ver));

        // Sync persistent tombstones into in-memory assessor
        for tomb in &initial_state.malicious_tombstones {
            if let Some((eco_str, pkg_name)) = tomb.split_once(':') {
                if let Ok(eco) = eco_str.parse::<PackageEcosystem>() {
                    assessor.record_malicious_tombstone(eco, pkg_name);
                }
            }
        }

        Self {
            assessor,
            baseline_store,
            audit_logger,
            trusted_keys,
            storage_path,
            security_state: Arc::new(RwLock::new(initial_state)),
            approval_manager: None,
        }
    }

    pub fn with_approval_manager(mut self, manager: Arc<ApprovalManager>) -> Self {
        self.approval_manager = Some(manager);
        self
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

    pub fn security_state(&self) -> &Arc<RwLock<AdvisorySecurityState>> {
        &self.security_state
    }

    /// Inspects an advisory bundle without activating it.
    /// Performs cryptographic signature verification, format checks, and computes diff.
    pub fn inspect_bundle(
        &self,
        bundle_path: &Path,
    ) -> Result<BundleInspectionResult, UpdateError> {
        let content = std::fs::read_to_string(bundle_path)?;
        validate_no_duplicate_keys(&content)
            .map_err(|e| UpdateError::Validation(BundleValidationError::MalformedRecord(e)))?;
        let bundle: AdvisoryBundle = serde_json::from_str(&content)?;

        let active_db = self.assessor.advisory_db();
        let active_ver = active_db.database_version().to_string();
        let high_water = self
            .security_state
            .read()
            .unwrap()
            .high_water_version
            .clone();

        let effective_active = if compare_db_versions(&active_ver, &high_water)
            .unwrap_or(Ordering::Equal)
            == Ordering::Greater
        {
            active_ver.clone()
        } else {
            high_water.clone()
        };

        let ord = compare_db_versions(&bundle.database_version, &effective_active)
            .unwrap_or(Ordering::Less);
        let would_rollback = ord != Ordering::Greater;

        // Perform validation check without throwing early on rollback (inspection should report it)
        let validation_res =
            bundle.validate_and_authenticate(&self.trusted_keys, Some(&effective_active), true);
        let is_valid = validation_res.is_ok();
        let signature_valid = !matches!(
            validation_res,
            Err(BundleValidationError::SignatureError(_))
                | Err(BundleValidationError::PayloadDigestMismatch { .. })
                | Err(BundleValidationError::PublisherMismatch { .. })
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

        // Record inspection in audit trail
        let _ = self.audit_logger.append(
            &format!("adv-insp-{}", uuid::Uuid::new_v4()),
            "PACKAGE_ADVISORY_INSPECTED",
            &format!(
                "Inspected advisory bundle v{} from publisher '{}' (records: {}, valid: {}, would_rollback: {})",
                bundle.database_version, bundle.publisher, bundle.advisories.len(), is_valid, would_rollback
            ),
            Severity::Info,
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
            active_version: active_ver,
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
    /// invalidates pending approvals, and reassesses affected dependency baselines.
    pub fn import_bundle(
        &self,
        bundle_path: &Path,
        allow_rollback: bool,
    ) -> Result<BundleImportResult, UpdateError> {
        let content = std::fs::read_to_string(bundle_path)?;
        validate_no_duplicate_keys(&content)
            .map_err(|e| UpdateError::Validation(BundleValidationError::MalformedRecord(e)))?;
        let bundle: AdvisoryBundle = serde_json::from_str(&content)?;

        let previous_version = self.assessor.advisory_db().database_version().to_string();
        let high_water = self
            .security_state
            .read()
            .unwrap()
            .high_water_version
            .clone();

        let effective_active = if compare_db_versions(&previous_version, &high_water)
            .unwrap_or(Ordering::Equal)
            == Ordering::Greater
        {
            previous_version.clone()
        } else {
            high_water.clone()
        };

        // 1. Authenticate and validate candidate bundle against monotonic high-water mark
        if let Err(err) = bundle.validate_and_authenticate(
            &self.trusted_keys,
            Some(&effective_active),
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

        if allow_rollback {
            let _ = self.audit_logger.append(
                &format!("adv-rb-auth-{}", uuid::Uuid::new_v4()),
                "PACKAGE_ADVISORY_ROLLBACK_AUTHORIZED",
                &format!(
                    "Advisory database rollback authorized: candidate v{} replaces effective v{}",
                    bundle.database_version, effective_active
                ),
                Severity::High,
            );
        }

        // 2. Safe transaction: atomic write to persistence file with isolated temporary storage
        let parent = self.storage_path.parent().unwrap_or_else(|| Path::new("."));
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }

        let tmp_path = parent.join(format!(".tmp_adv_{}", uuid::Uuid::new_v4()));
        let persisted = crate::package::advisory::PersistedAdvisoryDb {
            database_version: bundle.database_version.clone(),
            format_version: bundle.bundle_format_version.clone(),
            publisher: Some(bundle.publisher.clone()),
            key_id: Some(bundle.key_id.clone()),
            last_updated: Some(bundle.created_at),
            advisories: bundle.advisories.clone(),
        };

        let write_res = (|| -> Result<(), std::io::Error> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            let json = serde_json::to_string_pretty(&persisted)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp_path, &self.storage_path)?;
            #[cfg(unix)]
            {
                if let Ok(dir_file) = std::fs::File::open(parent) {
                    let _ = dir_file.sync_all();
                }
            }
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

        // 4. Update durable security state (high-water mark and irreversible malicious tombstones)
        {
            let mut state = self.security_state.write().unwrap();
            state.record_version(&bundle.database_version);
            for adv in &bundle.advisories {
                if adv.is_malicious {
                    state.record_malicious_package(adv.ecosystem, &adv.package_name);
                    self.assessor
                        .record_malicious_tombstone(adv.ecosystem, &adv.package_name);
                }
            }
            let state_path = self
                .storage_path
                .with_file_name("advisory_security_state.json");
            let _ = state.save_to_path(&state_path);
        }

        // 5. Invalidate pending or approved requests targeting newly confirmed malicious packages
        let mut malicious_pkgs = HashSet::new();
        for adv in &bundle.advisories {
            if adv.is_malicious {
                malicious_pkgs.insert((adv.ecosystem, adv.package_name.to_lowercase()));
            }
        }

        if let Some(ref mgr) = self.approval_manager {
            let invalidated = mgr.invalidate_for_malicious_packages(&malicious_pkgs);
            for req_id in invalidated {
                let _ = self.audit_logger.append(
                    &format!("inv-appr-{}", uuid::Uuid::new_v4()),
                    "PACKAGE_APPROVAL_INVALIDATED",
                    &format!(
                        "Pending approval request '{}' invalidated and hard-blocked: package identified as malicious by newly activated advisory intelligence",
                        req_id
                    ),
                    Severity::Critical,
                );
            }
        }

        // 6. Reassessment of monitored workspace dependency baselines
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

        // 7. Record successful activation in audit trail
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

        let _ = self.audit_logger.append(
            &format!("adv-reassess-{}", uuid::Uuid::new_v4()),
            "PACKAGE_ADVISORY_REASSESSMENT_COMPLETED",
            &format!(
                "Reassessment completed after update v{}: {} workspace(s) affected by newly activated findings",
                bundle.database_version, affected_workspaces.len()
            ),
            Severity::Info,
        );

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
