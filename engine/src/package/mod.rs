// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod advisory;
pub mod assessor;
pub mod baseline;
pub mod bundle;
pub mod detector;
pub mod drift;
pub mod manifest;
pub mod monitor;
pub mod post_verify;
pub mod state;
pub mod strict_json;
pub mod trust;
pub mod updater;

#[cfg(test)]
pub mod tests;

#[cfg(test)]
pub mod drift_tests;

#[cfg(test)]
pub mod update_tests;

#[cfg(test)]
pub mod adversarial_trust_tests;

pub use advisory::{AdvisoryDatabase, AdvisoryRecord};
pub use assessor::{summarize_assessment, PackageSecurityAssessor, PackageSecurityConfig};
pub use baseline::{
    compute_baseline_fingerprint, create_workspace_baseline, detect_workspace_ecosystem,
    BaselineStore,
};
pub use bundle::{
    compare_db_versions, compute_canonical_payload_digest, is_engine_compatible,
    parse_strict_version, AdvisoryBundle, BundleValidationError, CYRAVELL_ENGINE_VERSION,
    SUPPORTED_BUNDLE_FORMAT,
};
pub use detector::{
    detect_package_command, detect_package_command_from_raw, DetectedPackageCommand, PackageSpec,
};
pub use drift::DriftDetector;
pub use manifest::{ManifestInspector, ManifestScanResult, ResolvedDependency};
pub use monitor::WorkspaceMonitor;
pub use post_verify::PostOperationVerifier;
pub use state::AdvisorySecurityState;
pub use trust::{KeyVerificationError, TrustedKeyStore};
pub use updater::{AdvisoryUpdater, UpdateError};
