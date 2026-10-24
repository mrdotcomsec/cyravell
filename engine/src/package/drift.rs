// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::{
    DependencyBaseline, DriftChangeType, DriftFinding, DriftReport, FindingConfidence,
    PackageEcosystem, Severity,
};
use crate::package::advisory::AdvisoryDatabase;

pub struct DriftDetector;

impl DriftDetector {
    /// Compares a trusted baseline against the currently observed state and checks against advisories.
    pub fn detect(
        trusted: &DependencyBaseline,
        current: &DependencyBaseline,
        advisory_db: &AdvisoryDatabase,
    ) -> DriftReport {
        let mut findings = Vec::new();

        // 1. Check Direct Dependencies (Additions, Removals, Version Changes)
        for (pkg_name, curr_ver) in &current.direct_dependencies {
            match trusted.direct_dependencies.get(pkg_name) {
                Some(prev_ver) => {
                    if prev_ver != curr_ver {
                        findings.push(DriftFinding {
                            finding_id: format!("drift-ver-{}", uuid::Uuid::new_v4()),
                            ecosystem: current.ecosystem,
                            package_name: pkg_name.clone(),
                            previous_version: Some(prev_ver.clone()),
                            current_version: Some(curr_ver.clone()),
                            change_type: DriftChangeType::VersionDrift,
                            evidence: vec![format!(
                                "Direct dependency '{}' version changed from '{}' to '{}'",
                                pkg_name, prev_ver, curr_ver
                            )],
                            applicable_rules: vec!["RULE-DRIFT-001".to_string()],
                            status: FindingConfidence::Confirmed,
                            recommended_action:
                                "Review version change for compatibility and security".to_string(),
                            is_malicious: false,
                            severity: Severity::Medium,
                        });
                    }
                }
                None => {
                    findings.push(DriftFinding {
                        finding_id: format!("drift-add-{}", uuid::Uuid::new_v4()),
                        ecosystem: current.ecosystem,
                        package_name: pkg_name.clone(),
                        previous_version: None,
                        current_version: Some(curr_ver.clone()),
                        change_type: DriftChangeType::UnexpectedAddition,
                        evidence: vec![format!(
                            "Direct dependency '{}@{}' was added without recorded baseline authorization",
                            pkg_name, curr_ver
                        )],
                        applicable_rules: vec!["RULE-DRIFT-002".to_string()],
                        status: FindingConfidence::Confirmed,
                        recommended_action: "Review added dependency provenance and purpose".to_string(),
                        is_malicious: false,
                        severity: Severity::Medium,
                    });
                }
            }
        }

        for (pkg_name, prev_ver) in &trusted.direct_dependencies {
            if !current.direct_dependencies.contains_key(pkg_name) {
                findings.push(DriftFinding {
                    finding_id: format!("drift-rem-{}", uuid::Uuid::new_v4()),
                    ecosystem: current.ecosystem,
                    package_name: pkg_name.clone(),
                    previous_version: Some(prev_ver.clone()),
                    current_version: None,
                    change_type: DriftChangeType::UnexpectedRemoval,
                    evidence: vec![format!(
                        "Direct dependency '{}@{}' was removed from workspace manifest",
                        pkg_name, prev_ver
                    )],
                    applicable_rules: vec!["RULE-DRIFT-003".to_string()],
                    status: FindingConfidence::Confirmed,
                    recommended_action: "Confirm intended dependency removal".to_string(),
                    is_malicious: false,
                    severity: Severity::Low,
                });
            }
        }

        // 2. Check Transitive Dependencies (Transitive drift while direct is unchanged)
        for (pkg_name, curr_ver) in &current.transitive_dependencies {
            match trusted.transitive_dependencies.get(pkg_name) {
                Some(prev_ver) => {
                    if prev_ver != curr_ver {
                        findings.push(DriftFinding {
                            finding_id: format!("drift-trans-{}", uuid::Uuid::new_v4()),
                            ecosystem: current.ecosystem,
                            package_name: pkg_name.clone(),
                            previous_version: Some(prev_ver.clone()),
                            current_version: Some(curr_ver.clone()),
                            change_type: DriftChangeType::TransitiveDrift,
                            evidence: vec![format!(
                                "Transitive dependency '{}' resolved version drifted from '{}' to '{}'",
                                pkg_name, prev_ver, curr_ver
                            )],
                            applicable_rules: vec!["RULE-DRIFT-004".to_string()],
                            status: FindingConfidence::Confirmed,
                            recommended_action: "Inspect lockfile resolution changes".to_string(),
                            is_malicious: false,
                            severity: Severity::Medium,
                        });
                    }
                }
                None => {
                    // New transitive dependency introduced
                    if !current.direct_dependencies.contains_key(pkg_name) {
                        findings.push(DriftFinding {
                            finding_id: format!("drift-trans-add-{}", uuid::Uuid::new_v4()),
                            ecosystem: current.ecosystem,
                            package_name: pkg_name.clone(),
                            previous_version: None,
                            current_version: Some(curr_ver.clone()),
                            change_type: DriftChangeType::TransitiveDrift,
                            evidence: vec![format!(
                                "New transitive dependency '{}@{}' introduced into lockfile",
                                pkg_name, curr_ver
                            )],
                            applicable_rules: vec!["RULE-DRIFT-004".to_string()],
                            status: FindingConfidence::Confirmed,
                            recommended_action: "Verify sub-dependency chain".to_string(),
                            is_malicious: false,
                            severity: Severity::Low,
                        });
                    }
                }
            }
        }

        // 3. Check Integrity Metadata Drift
        for (pkg_name, curr_hash) in &current.integrity_metadata {
            if let Some(prev_hash) = trusted.integrity_metadata.get(pkg_name) {
                if prev_hash != curr_hash {
                    let prev_ver = trusted.resolved_dependencies.get(pkg_name).cloned();
                    let curr_ver = current.resolved_dependencies.get(pkg_name).cloned();
                    // If version is identical but integrity changed, that is highly suspicious!
                    let is_suspicious = prev_ver == curr_ver;
                    findings.push(DriftFinding {
                        finding_id: format!("drift-integ-{}", uuid::Uuid::new_v4()),
                        ecosystem: current.ecosystem,
                        package_name: pkg_name.clone(),
                        previous_version: prev_ver,
                        current_version: curr_ver,
                        change_type: DriftChangeType::IntegrityDrift,
                        evidence: vec![format!(
                            "Integrity hash for '{}' changed from '{}' to '{}'",
                            pkg_name, prev_hash, curr_hash
                        )],
                        applicable_rules: vec!["RULE-DRIFT-005".to_string()],
                        status: if is_suspicious {
                            FindingConfidence::Confirmed
                        } else {
                            FindingConfidence::Suspicious
                        },
                        recommended_action:
                            "Verify package registry integrity to rule out package tampering"
                                .to_string(),
                        is_malicious: false,
                        severity: if is_suspicious {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                    });
                }
            }
        }

        // 4. Check Manifest vs Lockfile Disconnect (LockfileOnlyDrift or ManifestOnlyDrift)
        let manifest_changed = trusted.direct_dependencies != current.direct_dependencies;
        let lockfile_changed = trusted.resolved_dependencies != current.resolved_dependencies;

        if lockfile_changed && !manifest_changed {
            findings.push(DriftFinding {
                finding_id: format!("drift-lockonly-{}", uuid::Uuid::new_v4()),
                ecosystem: current.ecosystem,
                package_name: "workspace-lockfile".to_string(),
                previous_version: None,
                current_version: None,
                change_type: DriftChangeType::LockfileOnlyDrift,
                evidence: vec![
                    "Lockfile dependencies modified without any changes to project manifest dependencies"
                        .to_string(),
                ],
                applicable_rules: vec!["RULE-DRIFT-006".to_string()],
                status: FindingConfidence::Confirmed,
                recommended_action: "Review lockfile diff to verify origin of dependency updates".to_string(),
                is_malicious: false,
                severity: Severity::Medium,
            });
        } else if manifest_changed && !lockfile_changed && !current.resolved_dependencies.is_empty()
        {
            findings.push(DriftFinding {
                finding_id: format!("drift-manonly-{}", uuid::Uuid::new_v4()),
                ecosystem: current.ecosystem,
                package_name: "workspace-manifest".to_string(),
                previous_version: None,
                current_version: None,
                change_type: DriftChangeType::ManifestOnlyDrift,
                evidence: vec![
                    "Manifest dependencies changed without corresponding lockfile reconciliation"
                        .to_string(),
                ],
                applicable_rules: vec!["RULE-DRIFT-007".to_string()],
                status: FindingConfidence::Confirmed,
                recommended_action: "Run package lockfile reconciliation (e.g. npm install --package-lock-only or cargo check)".to_string(),
                is_malicious: false,
                severity: Severity::Medium,
            });
        }

        // 5. Evaluate Advisory Database against all currently resolved dependencies
        for (pkg_name, ver) in &current.resolved_dependencies {
            let matches = advisory_db.query(current.ecosystem, pkg_name, Some(ver));
            for adv in matches {
                if adv.is_malicious {
                    findings.push(DriftFinding {
                        finding_id: format!("drift-mal-{}", uuid::Uuid::new_v4()),
                        ecosystem: current.ecosystem,
                        package_name: pkg_name.clone(),
                        previous_version: trusted.resolved_dependencies.get(pkg_name).cloned(),
                        current_version: Some(ver.clone()),
                        change_type: DriftChangeType::MaliciousPackageDetected,
                        evidence: vec![
                            format!("Advisory ID: {}", adv.id),
                            format!("Malicious package detected: {}", adv.title),
                            format!("Details: {}", adv.details),
                            format!("Affected range: {}", adv.affected_range),
                        ],
                        applicable_rules: vec![adv.id.clone()],
                        status: FindingConfidence::Confirmed,
                        recommended_action: "HARD BLOCK: Immediately remove this malicious dependency from the project".to_string(),
                        is_malicious: true,
                        severity: Severity::Critical,
                    });
                } else {
                    findings.push(DriftFinding {
                        finding_id: format!("drift-vuln-{}", uuid::Uuid::new_v4()),
                        ecosystem: current.ecosystem,
                        package_name: pkg_name.clone(),
                        previous_version: trusted.resolved_dependencies.get(pkg_name).cloned(),
                        current_version: Some(ver.clone()),
                        change_type: DriftChangeType::VulnerabilityDetected,
                        evidence: vec![
                            format!("Advisory ID: {}", adv.id),
                            format!("Vulnerability detected: {}", adv.title),
                            format!("Affected range: {}", adv.affected_range),
                            format!("Fixed version: {:?}", adv.fixed_version),
                        ],
                        applicable_rules: vec![adv.id.clone()],
                        status: FindingConfidence::Confirmed,
                        recommended_action: format!(
                            "Upgrade '{}' to version {:?}",
                            pkg_name, adv.fixed_version
                        ),
                        is_malicious: false,
                        severity: adv.severity,
                    });
                }
            }
        }

        let has_drift = !findings.is_empty();
        let summary = if has_drift {
            let mal_count = findings.iter().filter(|f| f.is_malicious).count();
            let vuln_count = findings
                .iter()
                .filter(|f| f.change_type == DriftChangeType::VulnerabilityDetected)
                .count();
            format!(
                "Dependency drift detected: {} finding(s) ({} malicious, {} vulnerable)",
                findings.len(),
                mal_count,
                vuln_count
            )
        } else {
            "Dependency state matches trusted baseline cleanly".to_string()
        };

        DriftReport {
            workspace_path: current.workspace_path.clone(),
            ecosystem: current.ecosystem,
            trusted_baseline_fingerprint: Some(trusted.baseline_fingerprint.clone()),
            current_fingerprint: current.baseline_fingerprint.clone(),
            has_drift,
            findings,
            evaluated_at: chrono::Utc::now(),
            summary,
        }
    }

    /// Generates a drift report when metadata is corrupted, missing, or unparseable.
    pub fn for_corrupted_metadata(
        workspace_path: &str,
        ecosystem: PackageEcosystem,
        error_message: &str,
    ) -> DriftReport {
        let finding = DriftFinding {
            finding_id: format!("drift-corrupt-{}", uuid::Uuid::new_v4()),
            ecosystem,
            package_name: "metadata".to_string(),
            previous_version: None,
            current_version: None,
            change_type: DriftChangeType::MetadataCorrupted,
            evidence: vec![format!(
                "Failed to parse dependency metadata: {}",
                error_message
            )],
            applicable_rules: vec!["RULE-DRIFT-CORRUPTED".to_string()],
            status: FindingConfidence::Confirmed,
            recommended_action: "Restore or repair corrupted manifest/lockfile files".to_string(),
            is_malicious: false,
            severity: Severity::High,
        };

        DriftReport {
            workspace_path: workspace_path.to_string(),
            ecosystem,
            trusted_baseline_fingerprint: None,
            current_fingerprint: "UNPARSEABLE".to_string(),
            has_drift: true,
            findings: vec![finding],
            evaluated_at: chrono::Utc::now(),
            summary: format!("Dependency metadata corrupted: {}", error_message),
        }
    }
}
