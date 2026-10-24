// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::analysis::ast::AtomicCommand;
use crate::model::{
    AssessmentStatus, PackageAssessmentResult, PackageAssessmentSummary, PackageSecurityFinding,
    Severity,
};
use crate::package::advisory::AdvisoryDatabase;
use crate::package::detector::{detect_package_command, DetectedPackageCommand};
use crate::package::manifest::ManifestInspector;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PackageSecurityConfig {
    pub enabled: bool,
    pub hard_block_malicious: bool,
    pub hard_block_critical_vulns: bool,
    pub fail_closed: bool,
    pub advisory_path: Option<std::path::PathBuf>,
}

impl Default for PackageSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hard_block_malicious: true,
            hard_block_critical_vulns: false,
            fail_closed: true,
            advisory_path: None,
        }
    }
}

pub struct PackageSecurityAssessor {
    config: PackageSecurityConfig,
    advisory_db: AdvisoryDatabase,
}

impl Default for PackageSecurityAssessor {
    fn default() -> Self {
        Self::new(PackageSecurityConfig::default())
    }
}

impl PackageSecurityAssessor {
    pub fn new(config: PackageSecurityConfig) -> Self {
        let advisory_db = AdvisoryDatabase::load_with_fallback(config.advisory_path.as_deref());
        Self {
            config,
            advisory_db,
        }
    }

    pub fn with_advisories(mut self, db: AdvisoryDatabase) -> Self {
        self.advisory_db = db;
        self
    }

    pub fn advisory_db_mut(&mut self) -> &mut AdvisoryDatabase {
        &mut self.advisory_db
    }

    pub fn config(&self) -> &PackageSecurityConfig {
        &self.config
    }

    /// Assess an atomic command in a working directory.
    pub fn assess_command(
        &self,
        cmd: &AtomicCommand,
        raw_cmd: &str,
        working_dir: &Path,
    ) -> Option<PackageAssessmentResult> {
        let detected = detect_package_command(cmd, raw_cmd)?;
        Some(self.assess_detected(&detected, working_dir))
    }

    /// Assess a raw command string (handling pipelines, chains, etc.) in a working directory.
    pub fn assess_command_string(
        &self,
        command: &str,
        working_dir: &Path,
    ) -> Option<PackageAssessmentResult> {
        let chain = crate::analysis::ast::parse_command(command);
        let atomic_cmds = chain.all_atomic_commands();
        let mut results = Vec::new();
        for cmd in atomic_cmds {
            if let Some(res) = self.assess_command(cmd, command, working_dir) {
                results.push(res);
            }
        }
        if results.is_empty() {
            return None;
        }

        // Prioritize findings by severity/threat level
        if let Some(malicious) = results
            .iter()
            .find(|r| r.status == AssessmentStatus::MaliciousPackageFound)
        {
            return Some(malicious.clone());
        }
        if let Some(integ) = results
            .iter()
            .find(|r| r.status == AssessmentStatus::IntegrityMismatch)
        {
            return Some(integ.clone());
        }
        if let Some(mismatch) = results
            .iter()
            .find(|r| r.status == AssessmentStatus::ManifestMismatch)
        {
            return Some(mismatch.clone());
        }
        if let Some(vuln) = results
            .iter()
            .find(|r| r.status == AssessmentStatus::VulnerabilitiesFound)
        {
            return Some(vuln.clone());
        }
        if let Some(failed) = results
            .iter()
            .find(|r| r.status == AssessmentStatus::AssessmentFailed)
        {
            return Some(failed.clone());
        }

        results.into_iter().next()
    }

    pub fn assess_detected(
        &self,
        detected: &DetectedPackageCommand,
        working_dir: &Path,
    ) -> PackageAssessmentResult {
        let mut inspected_files = Vec::new();
        let mut notes = Vec::new();
        let mut findings = Vec::new();

        // 1. Inspect manifests and lockfiles
        let manifest_scan = ManifestInspector::inspect(
            detected.package_manager,
            working_dir,
            detected.manifest_override.as_deref(),
        );

        let (scan_result, parse_failure) = match manifest_scan {
            Ok(scan) => {
                if let Some(ref m) = scan.manifest_path {
                    inspected_files.push(m.display().to_string());
                }
                if let Some(ref l) = scan.lockfile_path {
                    inspected_files.push(l.display().to_string());
                }
                (Some(scan), None)
            }
            Err(err) => {
                notes.push(format!("Manifest inspection error: {}", err));
                (None, Some(err))
            }
        };

        if let Some(err) = parse_failure {
            return PackageAssessmentResult {
                package_manager: detected.package_manager,
                operation: detected.operation,
                status: AssessmentStatus::AssessmentFailed,
                direct_packages: detected
                    .requested_packages
                    .iter()
                    .map(|p| p.name.clone())
                    .collect(),
                total_dependencies_scanned: 0,
                findings: Vec::new(),
                manifest_fingerprint: None,
                inspected_files,
                assessment_source: self.advisory_db.source_name().to_string(),
                offline_mode: self.advisory_db.is_offline(),
                notes: vec![format!("Failed to parse project manifest: {}", err)],
            };
        }

        let scan = scan_result.unwrap();

        // 2. Scan directly requested packages
        let mut scanned_count = 0;
        let direct_names: Vec<String> = detected
            .requested_packages
            .iter()
            .map(|p| p.name.clone())
            .collect();

        for pkg in &detected.requested_packages {
            scanned_count += 1;
            let matches = self.advisory_db.query(
                detected.package_manager,
                &pkg.name,
                pkg.version_constraint.as_deref(),
            );

            for adv in matches {
                findings.push(PackageSecurityFinding {
                    package_name: pkg.name.clone(),
                    version: pkg.version_constraint.clone(),
                    advisory_id: adv.id.clone(),
                    title: adv.title.clone(),
                    severity: adv.severity,
                    is_malicious: adv.is_malicious,
                    affected_range: adv.affected_range.clone(),
                    fixed_version: adv.fixed_version.clone(),
                    details: adv.details.clone(),
                });
            }
        }

        // 3. Scan resolved lockfile dependencies if present
        for dep in &scan.resolved_dependencies {
            scanned_count += 1;
            let matches =
                self.advisory_db
                    .query(detected.package_manager, &dep.name, Some(&dep.version));

            for adv in matches {
                // Avoid duplicating direct package findings
                if !findings
                    .iter()
                    .any(|f| f.package_name == dep.name && f.advisory_id == adv.id)
                {
                    findings.push(PackageSecurityFinding {
                        package_name: dep.name.clone(),
                        version: Some(dep.version.clone()),
                        advisory_id: adv.id.clone(),
                        title: adv.title.clone(),
                        severity: adv.severity,
                        is_malicious: adv.is_malicious,
                        affected_range: adv.affected_range.clone(),
                        fixed_version: adv.fixed_version.clone(),
                        details: adv.details.clone(),
                    });
                }
            }
        }

        // 4. Determine AssessmentStatus
        let has_malicious = findings.iter().any(|f| f.is_malicious);
        let has_vulns = !findings.is_empty();
        let has_integrity_issues = !scan.integrity_issues.is_empty();
        let has_mismatches = !scan.mismatches.is_empty();
        let has_parse_errors = !scan.parse_errors.is_empty();

        if has_parse_errors {
            notes.extend(scan.parse_errors.clone());
        }
        if has_mismatches {
            notes.extend(scan.mismatches.clone());
        }
        if has_integrity_issues {
            notes.extend(scan.integrity_issues.clone());
        }

        let status = if has_malicious {
            AssessmentStatus::MaliciousPackageFound
        } else if has_integrity_issues {
            AssessmentStatus::IntegrityMismatch
        } else if has_mismatches {
            AssessmentStatus::ManifestMismatch
        } else if has_vulns {
            AssessmentStatus::VulnerabilitiesFound
        } else if has_parse_errors {
            AssessmentStatus::AssessmentFailed
        } else {
            AssessmentStatus::CleanNoMatches
        };

        if status == AssessmentStatus::CleanNoMatches {
            notes.push(
                "No known vulnerabilities or malicious packages identified in local database."
                    .to_string(),
            );
        }

        PackageAssessmentResult {
            package_manager: detected.package_manager,
            operation: detected.operation,
            status,
            direct_packages: direct_names,
            total_dependencies_scanned: scanned_count,
            findings,
            manifest_fingerprint: scan.fingerprint,
            inspected_files,
            assessment_source: self.advisory_db.source_name().to_string(),
            offline_mode: self.advisory_db.is_offline(),
            notes,
        }
    }
}

pub fn summarize_assessment(result: &PackageAssessmentResult) -> PackageAssessmentSummary {
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut malicious_count = 0;

    for f in &result.findings {
        if f.is_malicious {
            malicious_count += 1;
        }
        match f.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => high_count += 1,
            _ => {}
        }
    }

    PackageAssessmentSummary {
        package_manager: result.package_manager,
        operation: result.operation,
        status: result.status,
        findings_count: result.findings.len(),
        critical_count,
        high_count,
        malicious_count,
        findings: result.findings.clone(),
        manifest_fingerprint: result.manifest_fingerprint.clone(),
    }
}
