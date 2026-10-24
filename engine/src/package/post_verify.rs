// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::{
    BaselineTrust, DependencyBaseline, ExecutionOutcome, PostOperationVerificationResult,
    PostOperationVerificationStatus, SnapshotReason,
};
use crate::package::advisory::AdvisoryDatabase;
use crate::package::baseline::{create_workspace_baseline, detect_workspace_ecosystem};
use crate::package::detector::{detect_package_command_from_raw, DetectedPackageCommand};
use crate::package::drift::DriftDetector;
use std::path::Path;

pub struct PostOperationVerifier;

impl PostOperationVerifier {
    /// Verifies the resulting workspace state after a controlled package-manager command completes.
    pub fn verify(
        workspace_path: &Path,
        command_str: &str,
        exit_code: Option<i32>,
        pre_op_baseline: Option<&DependencyBaseline>,
        advisory_db: &AdvisoryDatabase,
    ) -> PostOperationVerificationResult {
        let mut notes = Vec::new();

        // 1. Determine process outcome
        let process_outcome = match exit_code {
            Some(0) => ExecutionOutcome::Dispatched,
            Some(_) => ExecutionOutcome::ExecutionFailed,
            None => ExecutionOutcome::ExecutionFailed,
        };

        let pre_op_fp = pre_op_baseline.map(|b| b.baseline_fingerprint.clone());

        // Detect package command to understand expected changes
        let detected_cmd: Option<DetectedPackageCommand> =
            detect_package_command_from_raw(command_str);
        if let Some(ref det) = detected_cmd {
            notes.push(format!(
                "Detected operation: {:?} on package manager {:?}",
                det.operation, det.package_manager
            ));
            let pkgs: Vec<String> = det
                .requested_packages
                .iter()
                .map(|p| p.name.clone())
                .collect();
            if !pkgs.is_empty() {
                notes.push(format!("Target package spec(s): {}", pkgs.join(", ")));
            }
        }

        // 2. If process execution failed, we record ExecutionFailed before resulting state could be verified
        if process_outcome == ExecutionOutcome::ExecutionFailed {
            notes.push(format!(
                "Command exited with non-zero status ({:?}); post-operation state cannot be verified as intended",
                exit_code
            ));
            return PostOperationVerificationResult {
                process_outcome,
                exit_code,
                verification_status: PostOperationVerificationStatus::ExecutionFailed,
                pre_operation_fingerprint: pre_op_fp,
                post_operation_fingerprint: None,
                drift_report: None,
                notes,
            };
        }

        // 3. Reinspect relevant manifests and lockfiles
        let ecosystem_hint = detected_cmd
            .as_ref()
            .map(|d| d.package_manager)
            .or_else(|| pre_op_baseline.map(|b| b.ecosystem))
            .or_else(|| detect_workspace_ecosystem(workspace_path).map(|(eco, _)| eco));

        let current_baseline = match create_workspace_baseline(
            workspace_path,
            ecosystem_hint,
            SnapshotReason::PostOperation,
            BaselineTrust::PostOperationObserved,
            advisory_db,
        ) {
            Ok(b) => b,
            Err(e) => {
                notes.push(format!(
                    "Post-operation manifest/lockfile inspection failed: {}",
                    e
                ));
                let drift = DriftDetector::for_corrupted_metadata(
                    &workspace_path.display().to_string(),
                    ecosystem_hint.unwrap_or(crate::model::PackageEcosystem::Npm),
                    &e.to_string(),
                );
                return PostOperationVerificationResult {
                    process_outcome,
                    exit_code,
                    verification_status: PostOperationVerificationStatus::AssessmentFailed,
                    pre_operation_fingerprint: pre_op_fp,
                    post_operation_fingerprint: None,
                    drift_report: Some(drift),
                    notes,
                };
            }
        };

        let post_op_fp = Some(current_baseline.baseline_fingerprint.clone());

        // 4. Compare with pre-execution snapshot (or determine if inconclusive)
        let pre_ref = match pre_op_baseline {
            Some(b) => b,
            None => {
                notes.push(
                    "No pre-execution snapshot was provided; state comparison is inconclusive"
                        .to_string(),
                );
                return PostOperationVerificationResult {
                    process_outcome,
                    exit_code,
                    verification_status: PostOperationVerificationStatus::Inconclusive,
                    pre_operation_fingerprint: None,
                    post_operation_fingerprint: post_op_fp,
                    drift_report: None,
                    notes,
                };
            }
        };

        // 5. Detect drift and reassess against advisory database
        let drift_report = DriftDetector::detect(pre_ref, &current_baseline, advisory_db);

        // Filter drift findings against approved operation context:
        // Did the command add unexpected packages beyond what was declared in detected_cmd?
        let mut unexpected_changes = false;
        let mut has_malicious = false;
        let mut has_vulnerabilities = false;

        let expected_packages: Vec<String> = detected_cmd
            .as_ref()
            .map(|d| {
                d.requested_packages
                    .iter()
                    .map(|p| p.name.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        for finding in &drift_report.findings {
            if finding.is_malicious {
                has_malicious = true;
                notes.push(format!(
                    "CRITICAL: Resulting state contains confirmed malicious package '{}'",
                    finding.package_name
                ));
            } else if finding.change_type == crate::model::DriftChangeType::VulnerabilityDetected {
                has_vulnerabilities = true;
                notes.push(format!(
                    "WARNING: Resulting state contains vulnerable package '{}'",
                    finding.package_name
                ));
            } else if finding.change_type == crate::model::DriftChangeType::UnexpectedAddition {
                // If package was not among expected target packages, mark as unexpected
                if !expected_packages.contains(&finding.package_name.to_lowercase()) {
                    unexpected_changes = true;
                    notes.push(format!(
                        "Unexpected dependency added: '{}'",
                        finding.package_name
                    ));
                }
            } else if finding.change_type == crate::model::DriftChangeType::IntegrityDrift {
                unexpected_changes = true;
                notes.push(format!(
                    "Integrity hash drift detected for '{}'",
                    finding.package_name
                ));
            }
        }

        // 6. Formulate verification status
        let verification_status = if has_malicious || unexpected_changes || has_vulnerabilities {
            PostOperationVerificationStatus::UnexpectedChanges
        } else {
            PostOperationVerificationStatus::Verified
        };

        PostOperationVerificationResult {
            process_outcome,
            exit_code,
            verification_status,
            pre_operation_fingerprint: pre_op_fp,
            post_operation_fingerprint: post_op_fp,
            drift_report: Some(drift_report),
            notes,
        }
    }
}
