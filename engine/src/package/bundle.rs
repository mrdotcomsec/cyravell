// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::PackageEcosystem;
use crate::package::advisory::{validate_version_range, AdvisoryRecord};
use crate::package::trust::{KeyVerificationError, TrustedKeyStore};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::path::Path;

pub const CYRAVELL_ENGINE_VERSION: &str = "0.2.7";
pub const SUPPORTED_BUNDLE_FORMAT: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisoryBundle {
    pub bundle_format_version: String,
    pub database_version: String,
    pub created_at: DateTime<Utc>,
    pub publisher: String,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_cyravell_version: Option<String>,
    pub supported_ecosystems: Vec<PackageEcosystem>,
    pub payload_digest: String,
    pub signature: String,
    pub advisories: Vec<AdvisoryRecord>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BundleValidationError {
    UnsupportedFormatVersion(String),
    IncompatibleEngineVersion { required: String, current: String },
    PayloadDigestMismatch { expected: String, computed: String },
    SignatureError(String),
    PublisherMismatch { expected: String, claimed: String },
    MalformedVersion(String),
    RollbackRejected { candidate: String, active: String },
    EmptyAdvisories,
    MalformedRecord(String),
    SyntheticContamination(String),
    DuplicateAdvisoryId(String),
    ConflictingAdvisoryRecord(String),
}

impl std::fmt::Display for BundleValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFormatVersion(v) => write!(
                f,
                "Unsupported bundle format version '{}' (expected '{}')",
                v, SUPPORTED_BUNDLE_FORMAT
            ),
            Self::IncompatibleEngineVersion { required, current } => write!(
                f,
                "Bundle requires engine version >= {} (current engine is {})",
                required, current
            ),
            Self::PayloadDigestMismatch { expected, computed } => write!(
                f,
                "Advisory payload digest mismatch: bundle claims {} but computed {}",
                expected, computed
            ),
            Self::SignatureError(msg) => write!(f, "Signature validation error: {}", msg),
            Self::PublisherMismatch { expected, claimed } => write!(
                f,
                "Publisher identity mismatch: key belongs to '{}' but bundle claims '{}'",
                expected, claimed
            ),
            Self::MalformedVersion(msg) => write!(f, "Malformed database version string: {}", msg),
            Self::RollbackRejected { candidate, active } => write!(
                f,
                "Rollback rejected: candidate database version {} is not strictly newer than active version {} (specify --allow-rollback to override)",
                candidate, active
            ),
            Self::EmptyAdvisories => write!(f, "Advisory bundle contains zero advisory records"),
            Self::MalformedRecord(msg) => write!(f, "Malformed advisory record: {}", msg),
            Self::SyntheticContamination(id) => write!(
                f,
                "Synthetic test fixture contamination detected: record '{}' has is_synthetic=true in production bundle",
                id
            ),
            Self::DuplicateAdvisoryId(id) => {
                write!(f, "Duplicate advisory identifier detected in bundle: '{}'", id)
            }
            Self::ConflictingAdvisoryRecord(msg) => write!(f, "Conflicting advisory record: {}", msg),
        }
    }
}

impl std::error::Error for BundleValidationError {}

impl From<KeyVerificationError> for BundleValidationError {
    fn from(e: KeyVerificationError) -> Self {
        match e {
            KeyVerificationError::PublisherMismatch { expected, actual } => {
                Self::PublisherMismatch {
                    expected,
                    claimed: actual,
                }
            }
            other => Self::SignatureError(other.to_string()),
        }
    }
}

pub fn compute_canonical_payload_digest(advisories: &[AdvisoryRecord]) -> String {
    let mut sorted = advisories.to_vec();
    sorted.sort_by(|a, b| {
        a.ecosystem
            .as_str()
            .cmp(b.ecosystem.as_str())
            .then_with(|| a.package_name.cmp(&b.package_name))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut hasher = Sha256::new();
    for adv in &sorted {
        hasher.update(adv.id.as_bytes());
        hasher.update(b"\n");
        hasher.update(adv.ecosystem.as_str().as_bytes());
        hasher.update(b"\n");
        hasher.update(adv.package_name.to_lowercase().as_bytes());
        hasher.update(b"\n");
        hasher.update(adv.severity.as_str().as_bytes());
        hasher.update(b"\n");
        hasher.update(if adv.is_malicious {
            &b"malicious:true\n"[..]
        } else {
            &b"malicious:false\n"[..]
        });
        hasher.update(adv.affected_range.trim().as_bytes());
        hasher.update(b"\n");
        if let Some(ref fix) = adv.fixed_version {
            hasher.update(fix.trim().as_bytes());
        }
        hasher.update(b"\n");
        hasher.update(adv.title.trim().as_bytes());
        hasher.update(b"\n");
        hasher.update(adv.details.trim().as_bytes());
        hasher.update(b"\n");
        if let Some(ref cve) = adv.cve_id {
            hasher.update(cve.trim().as_bytes());
        }
        hasher.update(b"\n");
        if let Some(ref prov) = adv.provenance {
            hasher.update(prov.trim().as_bytes());
        }
        hasher.update(b"\n");
        hasher.update(if adv.is_synthetic {
            &b"synthetic:true\n"[..]
        } else {
            &b"synthetic:false\n"[..]
        });
        hasher.update(b"\n--RECORD--\n");
    }
    format!("{:x}", hasher.finalize())
}

pub fn parse_strict_version(v: &str) -> Result<Vec<u64>, BundleValidationError> {
    let cleaned = v.trim().trim_start_matches('v');
    if cleaned.is_empty() {
        return Err(BundleValidationError::MalformedVersion(
            "Version string cannot be empty".to_string(),
        ));
    }
    let parts: Vec<&str> = cleaned.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err(BundleValidationError::MalformedVersion(format!(
            "Invalid version format '{}': expected 1 to 4 numeric segments",
            v
        )));
    }
    let mut parsed = Vec::new();
    for seg in parts {
        if seg.is_empty() || !seg.chars().all(|c| c.is_ascii_digit()) {
            return Err(BundleValidationError::MalformedVersion(format!(
                "Invalid version segment '{}' in version '{}': must contain only ASCII digits",
                seg, v
            )));
        }
        let n = seg.parse::<u64>().map_err(|e| {
            BundleValidationError::MalformedVersion(format!(
                "Failed to parse numeric segment '{}' in version '{}': {}",
                seg, v, e
            ))
        })?;
        parsed.push(n);
    }
    Ok(parsed)
}

pub fn compare_db_versions(
    candidate: &str,
    active: &str,
) -> Result<Ordering, BundleValidationError> {
    let c_parts = parse_strict_version(candidate)?;
    let a_parts = parse_strict_version(active)?;

    let max_len = std::cmp::max(c_parts.len(), a_parts.len());
    for i in 0..max_len {
        let c_val = *c_parts.get(i).unwrap_or(&0);
        let a_val = *a_parts.get(i).unwrap_or(&0);
        match c_val.cmp(&a_val) {
            Ordering::Equal => continue,
            other => return Ok(other),
        }
    }
    Ok(Ordering::Equal)
}

pub fn is_engine_compatible(min_cyravell: &str, current_engine: &str) -> bool {
    let min_parts = match parse_strict_version(min_cyravell) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let cur_parts = match parse_strict_version(current_engine) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let max_len = std::cmp::max(min_parts.len(), cur_parts.len());
    for i in 0..max_len {
        let m = *min_parts.get(i).unwrap_or(&0);
        let c = *cur_parts.get(i).unwrap_or(&0);
        if c > m {
            return true;
        } else if c < m {
            return false;
        }
    }
    true
}

impl AdvisoryBundle {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, BundleValidationError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| BundleValidationError::MalformedRecord(e.to_string()))?;
        crate::package::strict_json::validate_no_duplicate_keys(&content)
            .map_err(BundleValidationError::MalformedRecord)?;
        let bundle: Self = serde_json::from_str(&content)
            .map_err(|e| BundleValidationError::MalformedRecord(e.to_string()))?;
        Ok(bundle)
    }

    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut sorted_ecosystems = self.supported_ecosystems.clone();
        sorted_ecosystems.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let ecosystems_str = sorted_ecosystems
            .iter()
            .map(|e| e.as_str())
            .collect::<Vec<_>>()
            .join(",");

        let msg = format!(
            "CYRAVELL-ADVISORY-BUNDLE-V1\nformat_version:{}\ndatabase_version:{}\ncreated_at:{}\npublisher:{}\nkey_id:{}\nmin_cyravell_version:{}\nsupported_ecosystems:{}\npayload_digest:{}\n",
            self.bundle_format_version.trim(),
            self.database_version.trim(),
            self.created_at.to_rfc3339(),
            self.publisher.trim(),
            self.key_id.trim(),
            self.min_cyravell_version.as_deref().unwrap_or("").trim(),
            ecosystems_str,
            self.payload_digest.trim()
        );
        msg.into_bytes()
    }

    pub fn validate_and_authenticate(
        &self,
        key_store: &TrustedKeyStore,
        active_db_version: Option<&str>,
        allow_rollback: bool,
    ) -> Result<(), BundleValidationError> {
        // 1. Format version
        if self.bundle_format_version.trim() != SUPPORTED_BUNDLE_FORMAT {
            return Err(BundleValidationError::UnsupportedFormatVersion(
                self.bundle_format_version.clone(),
            ));
        }

        // 2. Strict candidate database version validation
        parse_strict_version(&self.database_version)?;

        // 3. Engine compatibility
        if let Some(ref min_ver) = self.min_cyravell_version {
            if !is_engine_compatible(min_ver, CYRAVELL_ENGINE_VERSION) {
                return Err(BundleValidationError::IncompatibleEngineVersion {
                    required: min_ver.clone(),
                    current: CYRAVELL_ENGINE_VERSION.to_string(),
                });
            }
        }

        // 4. Payload digest verification
        let computed_digest = compute_canonical_payload_digest(&self.advisories);
        if computed_digest != self.payload_digest.trim().to_lowercase() {
            return Err(BundleValidationError::PayloadDigestMismatch {
                expected: self.payload_digest.clone(),
                computed: computed_digest,
            });
        }

        // 5. Publisher identity and cryptographic signature verification
        let key = key_store
            .get_key(&self.key_id)
            .ok_or_else(|| KeyVerificationError::KeyNotFound(self.key_id.clone()))?;

        if key.publisher.trim() != self.publisher.trim() {
            return Err(BundleValidationError::PublisherMismatch {
                expected: key.publisher.clone(),
                claimed: self.publisher.clone(),
            });
        }

        let signing_msg = self.canonical_signing_bytes();
        key_store
            .verify_signature(&self.key_id, &signing_msg, &self.signature)
            .map_err(BundleValidationError::from)?;

        // 6. Anti-rollback enforcement
        if let Some(active) = active_db_version {
            let ord = compare_db_versions(&self.database_version, active)?;
            if ord != Ordering::Greater && !allow_rollback {
                return Err(BundleValidationError::RollbackRejected {
                    candidate: self.database_version.clone(),
                    active: active.to_string(),
                });
            }
        }

        // 7. Content validation
        if self.advisories.is_empty() {
            return Err(BundleValidationError::EmptyAdvisories);
        }

        let mut seen_ids = HashSet::new();
        for adv in &self.advisories {
            if adv.id.trim().is_empty() {
                return Err(BundleValidationError::MalformedRecord(
                    "Advisory ID cannot be empty".to_string(),
                ));
            }
            if !seen_ids.insert(adv.id.as_str()) {
                return Err(BundleValidationError::DuplicateAdvisoryId(adv.id.clone()));
            }

            if adv.package_name.trim().is_empty() || adv.package_name.contains(char::is_whitespace)
            {
                return Err(BundleValidationError::MalformedRecord(format!(
                    "Invalid package name in advisory '{}': '{}'",
                    adv.id, adv.package_name
                )));
            }

            if adv.affected_range.trim().is_empty() {
                return Err(BundleValidationError::MalformedRecord(format!(
                    "Affected range cannot be empty in advisory '{}'",
                    adv.id
                )));
            }

            if !self.supported_ecosystems.contains(&adv.ecosystem) {
                return Err(BundleValidationError::MalformedRecord(format!(
                    "Ecosystem '{:?}' in advisory '{}' is not declared in bundle supported_ecosystems",
                    adv.ecosystem, adv.id
                )));
            }

            if let Err(e) = validate_version_range(&adv.affected_range) {
                return Err(BundleValidationError::MalformedRecord(format!(
                    "Invalid affected_range in advisory '{}': {}",
                    adv.id, e
                )));
            }

            if adv
                .provenance
                .as_ref()
                .map(|p| p.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(BundleValidationError::MalformedRecord(format!(
                    "Advisory '{}' is missing mandatory provenance source metadata",
                    adv.id
                )));
            }

            if adv.is_synthetic {
                return Err(BundleValidationError::SyntheticContamination(
                    adv.id.clone(),
                ));
            }

            if adv.is_malicious && (adv.title.trim().is_empty() || adv.details.trim().is_empty()) {
                return Err(BundleValidationError::MalformedRecord(format!(
                    "Malicious advisory '{}' requires explicit non-empty title and details",
                    adv.id
                )));
            }
        }

        Ok(())
    }
}
