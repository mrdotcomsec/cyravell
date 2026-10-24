// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::{AdvisoryDatabaseSource, AdvisoryStatus, PackageEcosystem, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisoryRecord {
    pub id: String,
    pub ecosystem: PackageEcosystem,
    pub package_name: String,
    pub severity: Severity,
    pub is_malicious: bool,
    pub affected_range: String,
    pub fixed_version: Option<String>,
    pub title: String,
    pub details: String,
    pub cve_id: Option<String>,
    #[serde(default = "default_provenance")]
    pub provenance: Option<String>,
    #[serde(default)]
    pub is_synthetic: bool,
}

fn default_provenance() -> Option<String> {
    Some("Curated Local Intelligence".to_string())
}

#[derive(Debug)]
pub enum AdvisoryError {
    Io(std::io::Error),
    Parse(serde_json::Error),
}

impl std::fmt::Display for AdvisoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Parse(e) => write!(f, "Failed to parse advisory database JSON: {}", e),
        }
    }
}

impl std::error::Error for AdvisoryError {}

impl From<std::io::Error> for AdvisoryError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for AdvisoryError {
    fn from(e: serde_json::Error) -> Self {
        Self::Parse(e)
    }
}

#[derive(Debug, Clone)]
pub struct AdvisoryDatabase {
    advisories: Vec<AdvisoryRecord>,
    source_name: String,
    source_type: AdvisoryDatabaseSource,
    database_version: String,
    publisher: Option<String>,
    key_id: Option<String>,
    last_updated: Option<DateTime<Utc>>,
    is_offline: bool,
}

impl Default for AdvisoryDatabase {
    fn default() -> Self {
        Self::load_embedded()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedAdvisoryDb {
    pub database_version: String,
    pub format_version: String,
    pub publisher: Option<String>,
    pub key_id: Option<String>,
    pub last_updated: Option<DateTime<Utc>>,
    pub advisories: Vec<AdvisoryRecord>,
}

impl AdvisoryDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_from_path(path: &Path) -> Result<Self, AdvisoryError> {
        let content = std::fs::read_to_string(path)?;
        if let Ok(persisted) = serde_json::from_str::<PersistedAdvisoryDb>(&content) {
            return Ok(Self {
                advisories: persisted.advisories,
                source_name: path.display().to_string(),
                source_type: AdvisoryDatabaseSource::ImportedBundle,
                database_version: persisted.database_version,
                publisher: persisted.publisher,
                key_id: persisted.key_id,
                last_updated: persisted.last_updated,
                is_offline: true,
            });
        }
        let advisories: Vec<AdvisoryRecord> = serde_json::from_str(&content)?;
        Ok(Self {
            advisories,
            source_name: path.display().to_string(),
            source_type: AdvisoryDatabaseSource::LocalFile,
            database_version: "2026.04.1".to_string(),
            publisher: Some("Local Advisory File".to_string()),
            key_id: None,
            last_updated: None,
            is_offline: true,
        })
    }

    pub fn load_embedded() -> Self {
        const EMBEDDED_JSON: &str = include_str!("../../../rules/package_advisories.json");
        let advisories: Vec<AdvisoryRecord> =
            serde_json::from_str(EMBEDDED_JSON).unwrap_or_default();
        Self {
            advisories,
            source_name: "embedded:package_advisories.json".to_string(),
            source_type: AdvisoryDatabaseSource::Embedded,
            database_version: "2.7.0".to_string(),
            publisher: Some("Cyravell Embedded Baseline".to_string()),
            key_id: None,
            last_updated: None,
            is_offline: true,
        }
    }

    pub fn from_bundle(bundle: &crate::package::bundle::AdvisoryBundle) -> Self {
        Self {
            advisories: bundle.advisories.clone(),
            source_name: format!("imported:bundle:{}", bundle.key_id),
            source_type: AdvisoryDatabaseSource::ImportedBundle,
            database_version: bundle.database_version.clone(),
            publisher: Some(bundle.publisher.clone()),
            key_id: Some(bundle.key_id.clone()),
            last_updated: Some(bundle.created_at),
            is_offline: true,
        }
    }

    pub fn load_default(data_dir: &Path) -> Self {
        let p = data_dir.join("advisories.json");
        Self::load_with_fallback(Some(&p))
    }

    pub fn load_with_fallback(path: Option<&Path>) -> Self {
        if let Some(p) = path {
            if p.exists() {
                if let Ok(db) = Self::load_from_path(p) {
                    return db;
                }
            }
        }
        Self::load_embedded()
    }

    pub fn database_version(&self) -> &str {
        &self.database_version
    }

    pub fn set_database_version(&mut self, version: String) {
        self.database_version = version;
    }

    pub fn source_type(&self) -> AdvisoryDatabaseSource {
        self.source_type
    }

    pub fn publisher(&self) -> Option<&str> {
        self.publisher.as_deref()
    }

    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    pub fn last_updated(&self) -> Option<DateTime<Utc>> {
        self.last_updated
    }

    pub fn status(&self) -> AdvisoryStatus {
        let malicious_count = self.advisories.iter().filter(|a| a.is_malicious).count();
        let vulns_count = self.advisories.iter().filter(|a| !a.is_malicious).count();
        let verification_status = match self.source_type {
            AdvisoryDatabaseSource::ImportedBundle => "VERIFIED_AUTHENTIC".to_string(),
            AdvisoryDatabaseSource::Embedded => "UNAUTHENTICATED_EMBEDDED".to_string(),
            AdvisoryDatabaseSource::LocalFile => "UNAUTHENTICATED_LOCAL_FILE".to_string(),
        };

        AdvisoryStatus {
            database_version: self.database_version.clone(),
            source: self.source_type,
            source_name: self.source_name.clone(),
            publisher: self.publisher.clone(),
            key_id: self.key_id.clone(),
            fingerprint: self.fingerprint(),
            records_count: self.advisories.len(),
            malicious_count,
            vulnerabilities_count: vulns_count,
            last_updated: self.last_updated,
            verification_status,
            min_cyravell_version: None,
        }
    }

    pub fn add_advisory(&mut self, adv: AdvisoryRecord) {
        self.advisories.push(adv);
    }

    pub fn all_advisories(&self) -> &[AdvisoryRecord] {
        &self.advisories
    }

    pub fn production_advisories(&self) -> Vec<&AdvisoryRecord> {
        self.advisories.iter().filter(|a| !a.is_synthetic).collect()
    }

    pub fn synthetic_advisories(&self) -> Vec<&AdvisoryRecord> {
        self.advisories.iter().filter(|a| a.is_synthetic).collect()
    }

    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for adv in &self.advisories {
            hasher.update(adv.id.as_bytes());
            hasher.update(adv.package_name.as_bytes());
            hasher.update(adv.affected_range.as_bytes());
            if let Some(ref prov) = adv.provenance {
                hasher.update(prov.as_bytes());
            }
            if adv.is_synthetic {
                hasher.update(b"synthetic");
            }
        }
        format!("{:x}", hasher.finalize())
    }

    pub fn validate_record(&self, record: &AdvisoryRecord) -> Result<(), String> {
        if record.id.trim().is_empty() {
            return Err("Advisory ID cannot be empty".to_string());
        }
        if record.package_name.trim().is_empty()
            || record.package_name.contains(char::is_whitespace)
        {
            return Err(format!("Invalid package name: '{}'", record.package_name));
        }
        if record.affected_range.trim().is_empty() {
            return Err("Affected range cannot be empty".to_string());
        }
        if record
            .provenance
            .as_ref()
            .map(|p| p.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(format!("Missing provenance for advisory '{}'", record.id));
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    pub fn is_malicious_package(&self, eco: PackageEcosystem, name: &str) -> bool {
        self.query(eco, name, None).iter().any(|a| a.is_malicious)
    }

    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    pub fn is_offline(&self) -> bool {
        self.is_offline
    }

    pub fn query(
        &self,
        ecosystem: PackageEcosystem,
        package_name: &str,
        version: Option<&str>,
    ) -> Vec<&AdvisoryRecord> {
        let normalized_pkg = package_name.to_lowercase();
        self.advisories
            .iter()
            .filter(|adv| {
                if adv.ecosystem != ecosystem {
                    return false;
                }
                if adv.package_name.to_lowercase() != normalized_pkg {
                    return false;
                }

                match version {
                    Some(ver) => version_matches_range(ver, &adv.affected_range),
                    None => {
                        // When no specific version constraint is given by user (e.g. `npm install flatmap-stream`)
                        // If the package is known malicious, match it regardless!
                        // If it's a vulnerability with affected_range "*", match it.
                        adv.is_malicious || adv.affected_range == "*"
                    }
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl PartialOrd for SimpleVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SimpleVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                non_eq => non_eq,
            },
            non_eq => non_eq,
        }
    }
}

impl SimpleVersion {
    pub fn parse(s: &str) -> Option<Self> {
        let clean = s
            .trim()
            .trim_start_matches('v')
            .trim_start_matches('=')
            .trim();

        // Split off prerelease / build info, e.g. 1.2.3-alpha.1
        let core = clean.split(['-', '+']).next()?;

        let parts: Vec<&str> = core.split('.').collect();
        let major = parts.first()?.parse::<u64>().ok()?;
        let minor = if parts.len() > 1 {
            parts[1].parse::<u64>().unwrap_or(0)
        } else {
            0
        };
        let patch = if parts.len() > 2 {
            parts[2].parse::<u64>().unwrap_or(0)
        } else {
            0
        };

        Some(SimpleVersion {
            major,
            minor,
            patch,
        })
    }
}

pub fn version_matches_range(version_str: &str, range_str: &str) -> bool {
    let range_str = range_str.trim();
    if range_str == "*" || range_str == "all" || range_str.is_empty() {
        return true;
    }

    let parsed_ver = match SimpleVersion::parse(version_str) {
        Some(v) => v,
        None => return false,
    };

    // Range can be compound: ">= 4.0.0, < 4.17.21" or ">= 9.2.2, <= 11.0.0"
    let clauses: Vec<&str> = if range_str.contains(',') {
        range_str.split(',').map(|s| s.trim()).collect()
    } else {
        vec![range_str]
    };

    for clause in clauses {
        if !match_single_clause(&parsed_ver, clause) {
            return false;
        }
    }

    true
}

pub fn validate_version_range(range_str: &str) -> Result<(), String> {
    let range_str = range_str.trim();
    if range_str == "*" || range_str == "all" || range_str.is_empty() {
        return Ok(());
    }

    let clauses: Vec<&str> = if range_str.contains(',') {
        range_str.split(',').map(|s| s.trim()).collect()
    } else {
        vec![range_str]
    };

    for clause in clauses {
        let clause = clause.trim();
        if clause == "*" || clause == "all" {
            continue;
        }
        let (_op, target_str) = extract_op_and_version(clause);
        if target_str.is_empty() {
            return Err(format!("Empty target version in clause '{}'", clause));
        }
        if SimpleVersion::parse(target_str).is_none() {
            return Err(format!(
                "Unparseable version '{}' in clause '{}'",
                target_str, clause
            ));
        }
    }

    Ok(())
}

fn match_single_clause(ver: &SimpleVersion, clause: &str) -> bool {
    let clause = clause.trim();
    if clause == "*" || clause == "all" {
        return true;
    }

    let (op, target_str) = extract_op_and_version(clause);
    let target = match SimpleVersion::parse(target_str) {
        Some(v) => v,
        None => return false,
    };

    match op {
        "=" | "==" => ver == &target,
        "!=" => ver != &target,
        ">" => ver > &target,
        ">=" => ver >= &target,
        "<" => ver < &target,
        "<=" => ver <= &target,
        "^" => {
            // Caret range: ^1.2.3 -> >= 1.2.3, < 2.0.0
            // ^0.2.3 -> >= 0.2.3, < 0.3.0
            // ^0.0.3 -> == 0.0.3
            if ver < &target {
                return false;
            }
            if target.major > 0 {
                ver.major == target.major
            } else if target.minor > 0 {
                ver.major == 0 && ver.minor == target.minor
            } else {
                ver == &target
            }
        }
        "~" | "~=" => {
            // Tilde range: ~1.2.3 -> >= 1.2.3, < 1.3.0
            if ver < &target {
                return false;
            }
            ver.major == target.major && ver.minor == target.minor
        }
        _ => ver == &target,
    }
}

fn extract_op_and_version(clause: &str) -> (&str, &str) {
    let ops = ["==", ">=", "<=", "~=", "!=", "<", ">", "=", "^", "~"];
    for op in ops {
        if let Some(rest) = clause.strip_prefix(op) {
            return (op, rest.trim());
        }
    }
    ("=", clause)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        assert_eq!(
            SimpleVersion::parse("1.2.3"),
            Some(SimpleVersion {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
        assert_eq!(
            SimpleVersion::parse("v0.1.1"),
            Some(SimpleVersion {
                major: 0,
                minor: 1,
                patch: 1
            })
        );
        assert_eq!(
            SimpleVersion::parse("2"),
            Some(SimpleVersion {
                major: 2,
                minor: 0,
                patch: 0
            })
        );
    }

    #[test]
    fn test_range_matching_exact() {
        assert!(version_matches_range("0.1.1", "= 0.1.1"));
        assert!(!version_matches_range("0.1.2", "= 0.1.1"));
        assert!(version_matches_range("1.4.1", "1.4.1"));
    }

    #[test]
    fn test_range_matching_compound() {
        assert!(version_matches_range("4.17.20", ">= 4.0.0, < 4.17.21"));
        assert!(!version_matches_range("4.17.21", ">= 4.0.0, < 4.17.21"));
        assert!(!version_matches_range("3.9.9", ">= 4.0.0, < 4.17.21"));

        assert!(version_matches_range("9.2.2", ">= 9.2.2, <= 11.0.0"));
        assert!(version_matches_range("10.0.0", ">= 9.2.2, <= 11.0.0"));
        assert!(version_matches_range("11.0.0", ">= 9.2.2, <= 11.0.0"));
        assert!(!version_matches_range("11.0.1", ">= 9.2.2, <= 11.0.0"));
    }

    #[test]
    fn test_range_wildcard() {
        assert!(version_matches_range("1.0.0", "*"));
        assert!(version_matches_range("99.99.99", "*"));
    }
}
