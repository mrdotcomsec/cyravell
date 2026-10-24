// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod advisory;
pub mod assessor;
pub mod detector;
pub mod manifest;

#[cfg(test)]
pub mod tests;

pub use advisory::{AdvisoryDatabase, AdvisoryRecord};
pub use assessor::{summarize_assessment, PackageSecurityAssessor, PackageSecurityConfig};
pub use detector::{detect_package_command, DetectedPackageCommand, PackageSpec};
pub use manifest::{ManifestInspector, ManifestScanResult, ResolvedDependency};
