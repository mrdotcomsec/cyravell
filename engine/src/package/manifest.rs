// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::PackageEcosystem;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDependency {
    pub name: String,
    pub version: String,
    pub integrity: Option<String>,
    pub is_direct: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestScanResult {
    pub ecosystem: PackageEcosystem,
    pub manifest_path: Option<PathBuf>,
    pub lockfile_path: Option<PathBuf>,
    pub fingerprint: Option<String>,
    pub declared_dependencies: HashMap<String, String>,
    pub resolved_dependencies: Vec<ResolvedDependency>,
    pub mismatches: Vec<String>,
    pub integrity_issues: Vec<String>,
    pub parse_errors: Vec<String>,
}

#[derive(Debug)]
pub enum ManifestError {
    Io(std::io::Error),
    MalformedJson { path: String, message: String },
    MalformedSyntax { path: String, message: String },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error reading manifest/lockfile: {}", e),
            Self::MalformedJson { path, message } => {
                write!(f, "Malformed JSON in {}: {}", path, message)
            }
            Self::MalformedSyntax { path, message } => {
                write!(f, "Malformed manifest syntax in {}: {}", path, message)
            }
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<std::io::Error> for ManifestError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct ManifestInspector;

impl ManifestInspector {
    pub fn inspect(
        ecosystem: PackageEcosystem,
        working_dir: &Path,
        manifest_override: Option<&str>,
    ) -> Result<ManifestScanResult, ManifestError> {
        match ecosystem {
            PackageEcosystem::Npm | PackageEcosystem::Pnpm | PackageEcosystem::Yarn => {
                Self::inspect_npm(ecosystem, working_dir, manifest_override)
            }
            PackageEcosystem::Cargo => Self::inspect_cargo(working_dir, manifest_override),
            PackageEcosystem::Pip => Self::inspect_pip(working_dir, manifest_override),
        }
    }

    fn inspect_npm(
        ecosystem: PackageEcosystem,
        working_dir: &Path,
        manifest_override: Option<&str>,
    ) -> Result<ManifestScanResult, ManifestError> {
        let manifest_filename = manifest_override.unwrap_or("package.json");
        let manifest_path = working_dir.join(manifest_filename);

        let lockfile_name = match ecosystem {
            PackageEcosystem::Npm => "package-lock.json",
            PackageEcosystem::Pnpm => "pnpm-lock.yaml",
            PackageEcosystem::Yarn => "yarn.lock",
            _ => "package-lock.json",
        };
        let lockfile_path = working_dir.join(lockfile_name);

        let mut declared_dependencies = HashMap::new();
        let mut resolved_dependencies = Vec::new();
        let mut mismatches = Vec::new();
        let mut integrity_issues = Vec::new();
        let mut parse_errors = Vec::new();
        let mut hasher = Sha256::new();
        let mut has_files = false;

        let has_manifest = manifest_path.exists() && manifest_path.is_file();
        let has_lockfile = lockfile_path.exists() && lockfile_path.is_file();

        if has_manifest {
            has_files = true;
            let content = match std::fs::read_to_string(&manifest_path) {
                Ok(c) => c,
                Err(e) => return Err(ManifestError::Io(e)),
            };
            hasher.update(content.as_bytes());

            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(json) => {
                    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
                        for (k, v) in deps {
                            if let Some(ver) = v.as_str() {
                                declared_dependencies.insert(k.clone(), ver.to_string());
                            }
                        }
                    }
                    if let Some(dev_deps) = json.get("devDependencies").and_then(|d| d.as_object())
                    {
                        for (k, v) in dev_deps {
                            if let Some(ver) = v.as_str() {
                                declared_dependencies.insert(k.clone(), ver.to_string());
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(ManifestError::MalformedJson {
                        path: manifest_path.display().to_string(),
                        message: e.to_string(),
                    });
                }
            }
        }

        if has_lockfile && ecosystem == PackageEcosystem::Npm {
            has_files = true;
            let content = match std::fs::read_to_string(&lockfile_path) {
                Ok(c) => c,
                Err(e) => return Err(ManifestError::Io(e)),
            };
            hasher.update(content.as_bytes());

            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(json) => {
                    let mut lock_packages = HashMap::new();

                    // Check npm v2/v3 packages map
                    if let Some(pkgs) = json.get("packages").and_then(|p| p.as_object()) {
                        for (pkg_key, pkg_val) in pkgs {
                            if pkg_key.is_empty() {
                                continue; // Root project
                            }
                            let name = if let Some(last_nm) = pkg_key.rfind("node_modules/") {
                                &pkg_key[last_nm + 13..]
                            } else {
                                pkg_key.as_str()
                            };

                            let version = pkg_val
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            let integrity = pkg_val
                                .get("integrity")
                                .and_then(|i| i.as_str())
                                .map(|s| s.to_string());

                            if let Some(ref integ) = integrity {
                                if !is_valid_integrity_format(integ) {
                                    integrity_issues.push(format!(
                                        "Package '{}' has invalid integrity format: '{}'",
                                        name, integ
                                    ));
                                }
                            }

                            if !name.is_empty() && !version.is_empty() {
                                lock_packages.insert(
                                    name.to_string(),
                                    ResolvedDependency {
                                        name: name.to_string(),
                                        version,
                                        integrity,
                                        is_direct: declared_dependencies.contains_key(name),
                                    },
                                );
                            }
                        }
                    }

                    // Check npm v1 dependencies map if packages was empty or as fallback
                    if lock_packages.is_empty() {
                        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
                            parse_v1_npm_dependencies(
                                deps,
                                &declared_dependencies,
                                &mut lock_packages,
                                &mut integrity_issues,
                            );
                        }
                    }

                    // Detect mismatches: declared in package.json but missing in lockfile
                    if has_manifest {
                        for dep_name in declared_dependencies.keys() {
                            if !lock_packages.contains_key(dep_name) {
                                mismatches.push(format!(
                                    "Package '{}' declared in {} is missing from {}",
                                    dep_name, manifest_filename, lockfile_name
                                ));
                            }
                        }
                    }

                    resolved_dependencies = lock_packages.into_values().collect();
                }
                Err(e) => {
                    return Err(ManifestError::MalformedJson {
                        path: lockfile_path.display().to_string(),
                        message: e.to_string(),
                    });
                }
            }
        } else if has_lockfile {
            // Yarn or pnpm lockfile
            let content = match std::fs::read_to_string(&lockfile_path) {
                Ok(c) => c,
                Err(e) => return Err(ManifestError::Io(e)),
            };
            hasher.update(content.as_bytes());
            has_files = true;
            // Lightweight line-based parse for yarn.lock / pnpm-lock.yaml
            let (deps, errs) = parse_yarn_or_pnpm_lock(&content, &declared_dependencies);
            resolved_dependencies = deps;
            parse_errors.extend(errs);
        }

        let fingerprint = if has_files {
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        };

        Ok(ManifestScanResult {
            ecosystem,
            manifest_path: if has_manifest {
                Some(manifest_path)
            } else {
                None
            },
            lockfile_path: if has_lockfile {
                Some(lockfile_path)
            } else {
                None
            },
            fingerprint,
            declared_dependencies,
            resolved_dependencies,
            mismatches,
            integrity_issues,
            parse_errors,
        })
    }

    fn inspect_cargo(
        working_dir: &Path,
        manifest_override: Option<&str>,
    ) -> Result<ManifestScanResult, ManifestError> {
        let manifest_filename = manifest_override.unwrap_or("Cargo.toml");
        let manifest_path = working_dir.join(manifest_filename);
        let lockfile_path = working_dir.join("Cargo.lock");

        let mut declared_dependencies = HashMap::new();
        let mut resolved_dependencies = Vec::new();
        let mut mismatches = Vec::new();
        let integrity_issues = Vec::new();
        let parse_errors = Vec::new();
        let mut hasher = Sha256::new();
        let mut has_files = false;

        let has_manifest = manifest_path.exists() && manifest_path.is_file();
        let has_lockfile = lockfile_path.exists() && lockfile_path.is_file();

        if has_manifest {
            has_files = true;
            let content = match std::fs::read_to_string(&manifest_path) {
                Ok(c) => c,
                Err(e) => return Err(ManifestError::Io(e)),
            };
            hasher.update(content.as_bytes());

            match parse_cargo_toml(&content) {
                Ok(mut deps) => {
                    // If workspace root has no dependencies, check workspace members
                    if deps.is_empty() && content.contains("[workspace]") {
                        for member in &["engine", "test-harness"] {
                            let member_toml = working_dir.join(member).join("Cargo.toml");
                            if member_toml.exists() {
                                if let Ok(member_content) = std::fs::read_to_string(&member_toml) {
                                    if let Ok(member_deps) = parse_cargo_toml(&member_content) {
                                        deps.extend(member_deps);
                                    }
                                }
                            }
                        }
                    }
                    declared_dependencies = deps;
                }
                Err(err) => {
                    return Err(ManifestError::MalformedSyntax {
                        path: manifest_path.display().to_string(),
                        message: err,
                    });
                }
            }
        }

        if has_lockfile {
            has_files = true;
            let content = match std::fs::read_to_string(&lockfile_path) {
                Ok(c) => c,
                Err(e) => return Err(ManifestError::Io(e)),
            };
            hasher.update(content.as_bytes());

            match parse_cargo_lock(&content, &declared_dependencies) {
                Ok(resolved) => {
                    let lock_map: HashMap<String, String> = resolved
                        .iter()
                        .map(|d| (d.name.clone(), d.version.clone()))
                        .collect();

                    if has_manifest {
                        for dep_name in declared_dependencies.keys() {
                            if !lock_map.contains_key(dep_name) {
                                mismatches.push(format!(
                                    "Package '{}' declared in Cargo.toml is missing from Cargo.lock",
                                    dep_name
                                ));
                            }
                        }
                    }

                    resolved_dependencies = resolved;
                }
                Err(err) => {
                    return Err(ManifestError::MalformedSyntax {
                        path: lockfile_path.display().to_string(),
                        message: err,
                    });
                }
            }
        }

        let fingerprint = if has_files {
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        };

        Ok(ManifestScanResult {
            ecosystem: PackageEcosystem::Cargo,
            manifest_path: if has_manifest {
                Some(manifest_path)
            } else {
                None
            },
            lockfile_path: if has_lockfile {
                Some(lockfile_path)
            } else {
                None
            },
            fingerprint,
            declared_dependencies,
            resolved_dependencies,
            mismatches,
            integrity_issues,
            parse_errors,
        })
    }

    fn inspect_pip(
        working_dir: &Path,
        manifest_override: Option<&str>,
    ) -> Result<ManifestScanResult, ManifestError> {
        let manifest_filename = manifest_override.unwrap_or("requirements.txt");
        let manifest_path = working_dir.join(manifest_filename);

        let mut declared_dependencies = HashMap::new();
        let mut resolved_dependencies = Vec::new();
        let mismatches = Vec::new();
        let integrity_issues = Vec::new();
        let mut parse_errors = Vec::new();
        let mut hasher = Sha256::new();
        let mut has_files = false;

        let has_manifest = manifest_path.exists() && manifest_path.is_file();

        if has_manifest {
            has_files = true;
            let content = match std::fs::read_to_string(&manifest_path) {
                Ok(c) => c,
                Err(e) => return Err(ManifestError::Io(e)),
            };
            hasher.update(content.as_bytes());

            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
                    continue;
                }

                // Check for operators: ==, >=, <=, ~=, <, >
                let mut found_op = false;
                for op in &["==", ">=", "<=", "~=", "!=", "<", ">"] {
                    if let Some((name, ver)) = trimmed.split_once(op) {
                        let pkg_name = name.trim().to_string();
                        let ver_str = ver.trim().to_string();
                        declared_dependencies
                            .insert(pkg_name.clone(), format!("{}{}", op, ver_str));
                        if *op == "==" {
                            resolved_dependencies.push(ResolvedDependency {
                                name: pkg_name,
                                version: ver_str,
                                integrity: None,
                                is_direct: true,
                            });
                        }
                        found_op = true;
                        break;
                    }
                }

                if !found_op {
                    // Just a bare package name without version
                    if trimmed
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
                    {
                        declared_dependencies.insert(trimmed.to_string(), "*".to_string());
                    } else {
                        parse_errors.push(format!(
                            "Unrecognized requirements specification on line {}: '{}'",
                            idx + 1,
                            trimmed
                        ));
                    }
                }
            }
        }

        let fingerprint = if has_files {
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        };

        Ok(ManifestScanResult {
            ecosystem: PackageEcosystem::Pip,
            manifest_path: if has_manifest {
                Some(manifest_path)
            } else {
                None
            },
            lockfile_path: None,
            fingerprint,
            declared_dependencies,
            resolved_dependencies,
            mismatches,
            integrity_issues,
            parse_errors,
        })
    }
}

fn is_valid_integrity_format(integrity: &str) -> bool {
    // Valid npm integrity starts with sha512-, sha384-, sha256-, or sha1-
    // followed by valid base64 chars
    if let Some((algo, hash)) = integrity.split_once('-') {
        let valid_algo = matches!(algo, "sha512" | "sha384" | "sha256" | "sha1");
        if !valid_algo || hash.is_empty() {
            return false;
        }
        hash.chars()
            .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '_')
    } else {
        false
    }
}

fn parse_v1_npm_dependencies(
    deps: &serde_json::Map<String, serde_json::Value>,
    declared: &HashMap<String, String>,
    out: &mut HashMap<String, ResolvedDependency>,
    integrity_issues: &mut Vec<String>,
) {
    for (name, val) in deps {
        let version = val
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let integrity = val
            .get("integrity")
            .and_then(|i| i.as_str())
            .map(|s| s.to_string());

        if let Some(ref integ) = integrity {
            if !is_valid_integrity_format(integ) {
                integrity_issues.push(format!(
                    "Package '{}' has invalid integrity format: '{}'",
                    name, integ
                ));
            }
        }

        if !version.is_empty() {
            out.insert(
                name.clone(),
                ResolvedDependency {
                    name: name.clone(),
                    version,
                    integrity,
                    is_direct: declared.contains_key(name),
                },
            );
        }

        if let Some(sub_deps) = val.get("dependencies").and_then(|d| d.as_object()) {
            parse_v1_npm_dependencies(sub_deps, declared, out, integrity_issues);
        }
    }
}

fn parse_yarn_or_pnpm_lock(
    content: &str,
    declared: &HashMap<String, String>,
) -> (Vec<ResolvedDependency>, Vec<String>) {
    let mut resolved = Vec::new();
    let errors = Vec::new();

    // Simplified parser for yarn.lock
    // Format:
    // "lodash@^4.17.20":
    //   version "4.17.21"
    let mut current_name: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            // New package spec: "lodash@^4.17.20": or lodash@^4.17.20:
            let spec = trimmed.trim_end_matches(':').trim_matches('"');
            if let Some((name, _)) = spec.split_once('@') {
                current_name = Some(name.to_string());
            } else {
                current_name = Some(spec.to_string());
            }
        } else if let Some(ref name) = current_name {
            if trimmed.starts_with("version ") || trimmed.starts_with("version:") {
                let ver_part = trimmed
                    .trim_start_matches("version")
                    .trim_start_matches(':')
                    .trim()
                    .trim_matches('"');
                resolved.push(ResolvedDependency {
                    name: name.clone(),
                    version: ver_part.to_string(),
                    integrity: None,
                    is_direct: declared.contains_key(name),
                });
                current_name = None;
            }
        }
    }

    (resolved, errors)
}

fn parse_cargo_toml(content: &str) -> Result<HashMap<String, String>, String> {
    let mut deps = HashMap::new();
    let mut in_dependencies = false;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = trimmed.trim_matches(|c| c == '[' || c == ']').trim();
            in_dependencies = section == "dependencies"
                || section == "dev-dependencies"
                || section == "build-dependencies"
                || section.ends_with(".dependencies");
            continue;
        }

        if in_dependencies {
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                let val = val.trim();

                // val could be "1.0.0" or { version = "1.0.0", features = [...] }
                let version = if val.starts_with('"') && val.ends_with('"') {
                    val.trim_matches('"').to_string()
                } else if val.starts_with('{') && val.ends_with('}') {
                    // Extract version = "..."
                    if let Some(v_idx) = val.find("version") {
                        let after_v = &val[v_idx + 7..];
                        if let Some(eq_idx) = after_v.find('=') {
                            let after_eq = after_v[eq_idx + 1..].trim();
                            if let Some(quote_start) = after_eq.find('"') {
                                let after_quote = &after_eq[quote_start + 1..];
                                if let Some(quote_end) = after_quote.find('"') {
                                    after_quote[..quote_end].to_string()
                                } else {
                                    return Err(format!(
                                        "Unclosed quote in Cargo.toml at line {}",
                                        idx + 1
                                    ));
                                }
                            } else {
                                "*".to_string()
                            }
                        } else {
                            "*".to_string()
                        }
                    } else {
                        "*".to_string()
                    }
                } else {
                    val.to_string()
                };

                deps.insert(key.to_string(), version);
            }
        }
    }

    Ok(deps)
}

fn parse_cargo_lock(
    content: &str,
    declared: &HashMap<String, String>,
) -> Result<Vec<ResolvedDependency>, String> {
    let mut resolved = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_checksum: Option<String> = None;
    let mut in_array = false;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if in_array {
            if trimmed.contains(']') {
                in_array = false;
            }
            continue;
        }

        if trimmed == "[[package]]" {
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                resolved.push(ResolvedDependency {
                    is_direct: declared.contains_key(&name),
                    name,
                    version,
                    integrity: current_checksum.take(),
                });
            }
            continue;
        }

        if let Some((key, val)) = trimmed.split_once('=') {
            let key = key.trim();
            let val = val.trim();

            if val.starts_with('[') && !val.contains(']') {
                in_array = true;
                continue;
            }

            let val_clean = val.trim_matches('"');
            match key {
                "name" => current_name = Some(val_clean.to_string()),
                "version" => current_version = Some(val_clean.to_string()),
                "checksum" => current_checksum = Some(val_clean.to_string()),
                _ => {}
            }
        } else if trimmed == "]" {
            in_array = false;
        } else if !trimmed.starts_with('[') {
            return Err(format!(
                "Malformed line in Cargo.lock at line {}: '{}'",
                idx + 1,
                trimmed
            ));
        }
    }

    if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
        resolved.push(ResolvedDependency {
            is_direct: declared.contains_key(&name),
            name,
            version,
            integrity: current_checksum.take(),
        });
    }

    Ok(resolved)
}
