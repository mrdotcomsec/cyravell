// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::package::strict_json::validate_no_duplicate_keys;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub const RELEASE_MANIFEST_SCHEMA_VERSION: &str = "1.0.0";
pub const PRODUCT_NAME: &str = "cyravell";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseArtifact {
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub artifact_type: String, // "binary", "extension", "sbom", "rules_bundle", "archive"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildMetadata {
    pub rustc_version: String,
    pub cargo_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_version: Option<String>,
    pub build_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_date_epoch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomReference {
    pub filename: String,
    pub sha256: String,
    pub format: String, // "SPDX-2.3"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CyravellReleaseManifest {
    pub schema_version: String,
    pub product_name: String,
    pub release_version: String,
    pub source_commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_tag: Option<String>,
    pub build_timestamp: String,
    pub engine_version: String,
    pub extension_version: String,
    #[serde(
        default = "default_signing_mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_mode: Option<String>,
    pub target_platforms: Vec<String>,
    pub artifacts: BTreeMap<String, ReleaseArtifact>,
    pub required_runtime_components: Vec<String>,
    pub build_metadata: BuildMetadata,
    pub sbom: SbomReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn default_signing_mode() -> Option<String> {
    Some("official".to_string())
}

impl CyravellReleaseManifest {
    /// Computes deterministic canonical signing bytes for Ed25519 authentication.
    /// Excludes the signature and signing_key_id fields.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("CYRAVELL-RELEASE-MANIFEST-V1\n");
        out.push_str(&format!("product_name:{}\n", self.product_name));
        out.push_str(&format!("release_version:{}\n", self.release_version));
        out.push_str(&format!("source_commit:{}\n", self.source_commit));
        out.push_str(&format!(
            "source_tag:{}\n",
            self.source_tag.as_deref().unwrap_or("")
        ));
        out.push_str(&format!("build_timestamp:{}\n", self.build_timestamp));
        out.push_str(&format!("engine_version:{}\n", self.engine_version));
        out.push_str(&format!("extension_version:{}\n", self.extension_version));
        out.push_str(&format!(
            "signing_mode:{}\n",
            self.signing_mode.as_deref().unwrap_or("official")
        ));
        out.push_str("target_platforms:");
        for (i, tp) in self.target_platforms.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(tp);
        }
        out.push('\n');

        out.push_str("artifacts:\n");
        for (name, art) in &self.artifacts {
            out.push_str(&format!(
                "{}:{}:{}:{}:{}\n",
                name,
                art.size_bytes,
                art.sha256.to_lowercase(),
                art.artifact_type,
                art.target_platform.as_deref().unwrap_or("")
            ));
        }

        out.push_str("required_runtime_components:\n");
        let mut sorted_reqs = self.required_runtime_components.clone();
        sorted_reqs.sort();
        for req in sorted_reqs {
            out.push_str(&format!("{}\n", req));
        }

        out.push_str(&format!(
            "sbom:{}:{}:{}\n",
            self.sbom.filename,
            self.sbom.sha256.to_lowercase(),
            self.sbom.format
        ));

        out.into_bytes()
    }

    /// Sign the manifest canonical bytes with the provided Ed25519 signing key.
    pub fn sign(&mut self, key: &SigningKey, key_id: &str) {
        let canonical_bytes = self.canonical_signing_bytes();
        let sig = key.sign(&canonical_bytes);
        self.signing_key_id = Some(key_id.to_string());
        self.signature = Some(hex::encode(sig.to_bytes()));
    }
}

/// Computes SHA-256 hex digest of a file.
pub fn compute_sha256<P: AsRef<Path>>(path: P) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseKey {
    pub key_id: String,
    pub publisher: String,
    pub public_key_hex: String,
    pub algorithm: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub is_active: bool,
    #[serde(default = "default_is_official")]
    pub is_official: bool,
}

fn default_is_official() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct ReleaseKeyStore {
    keys: BTreeMap<String, ReleaseKey>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseKeyError {
    KeyNotFound(String),
    KeyRevoked(String),
    KeyExpired(String),
    InvalidPublicKey(String),
    InvalidSignature(String),
    UnsupportedAlgorithm(String),
    CorruptedKeystore(String),
    Io(String),
}

impl std::fmt::Display for ReleaseKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotFound(id) => write!(f, "Release signing key '{}' is not recognized", id),
            Self::KeyRevoked(id) => write!(
                f,
                "Release signing key '{}' has been revoked or deactivated",
                id
            ),
            Self::KeyExpired(id) => write!(f, "Release signing key '{}' has expired", id),
            Self::InvalidPublicKey(msg) => write!(f, "Invalid public key in keystore: {}", msg),
            Self::InvalidSignature(msg) => {
                write!(f, "Invalid cryptographic release signature: {}", msg)
            }
            Self::UnsupportedAlgorithm(alg) => write!(
                f,
                "Unsupported signing algorithm '{}': only ed25519 is accepted",
                alg
            ),
            Self::CorruptedKeystore(msg) => write!(f, "Corrupted release keystore: {}", msg),
            Self::Io(msg) => write!(f, "Release keystore I/O error: {}", msg),
        }
    }
}

impl std::error::Error for ReleaseKeyError {}

impl Default for ReleaseKeyStore {
    fn default() -> Self {
        Self::load_default()
    }
}

impl ReleaseKeyStore {
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    pub fn load_embedded() -> Self {
        const EMBEDDED: &str = include_str!("../../rules/release_signing_keys.json");
        Self::load_from_json(EMBEDDED).unwrap_or_else(|_| Self::new())
    }

    pub fn load_default() -> Self {
        let p = Path::new("rules/release_signing_keys.json");
        if p.exists() {
            Self::load_from_path(p).unwrap_or_else(|_| Self::load_embedded())
        } else {
            Self::load_embedded()
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, ReleaseKeyError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::symlink_metadata(path)
                .map_err(|e| ReleaseKeyError::Io(format!("Failed to read metadata: {}", e)))?;
            if meta.file_type().is_symlink() {
                return Err(ReleaseKeyError::CorruptedKeystore(format!(
                    "Symlinks forbidden for release keystore: {}",
                    path.display()
                )));
            }
            let mode = meta.mode();
            if mode & 0o002 != 0 {
                return Err(ReleaseKeyError::CorruptedKeystore(format!(
                    "Insecure permissions (world-writable) for release keystore: {:o}",
                    mode
                )));
            }
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| ReleaseKeyError::Io(format!("Failed to read keystore file: {}", e)))?;
        Self::load_from_json(&content)
    }

    pub fn load_from_json(json: &str) -> Result<Self, ReleaseKeyError> {
        if let Err(e) = validate_no_duplicate_keys(json) {
            return Err(ReleaseKeyError::CorruptedKeystore(e));
        }

        #[derive(Deserialize)]
        struct RawKeystore {
            keys: Vec<ReleaseKey>,
        }

        let raw: RawKeystore = serde_json::from_str(json)
            .map_err(|e| ReleaseKeyError::CorruptedKeystore(format!("JSON parse error: {}", e)))?;

        let mut store = Self::new();
        let mut seen = HashSet::new();

        for key in raw.keys {
            if key.key_id.trim().is_empty() {
                return Err(ReleaseKeyError::CorruptedKeystore(
                    "Empty key_id in release keystore".to_string(),
                ));
            }
            if !seen.insert(key.key_id.clone()) {
                return Err(ReleaseKeyError::CorruptedKeystore(format!(
                    "Duplicate key_id in release keystore: '{}'",
                    key.key_id
                )));
            }
            if key.algorithm.to_lowercase() != "ed25519" {
                return Err(ReleaseKeyError::UnsupportedAlgorithm(key.algorithm));
            }

            let pk_bytes = hex::decode(key.public_key_hex.trim()).map_err(|e| {
                ReleaseKeyError::InvalidPublicKey(format!(
                    "Invalid public key hex for '{}': {}",
                    key.key_id, e
                ))
            })?;
            if pk_bytes.len() != 32 {
                return Err(ReleaseKeyError::InvalidPublicKey(format!(
                    "Public key for '{}' must be 32 bytes (got {})",
                    key.key_id,
                    pk_bytes.len()
                )));
            }
            // Ensure bytes form a valid Ed25519 verifying key
            let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| {
                ReleaseKeyError::InvalidPublicKey("Invalid slice length".to_string())
            })?;
            VerifyingKey::from_bytes(&pk_arr).map_err(|e| {
                ReleaseKeyError::InvalidPublicKey(format!("Not a valid Ed25519 point: {}", e))
            })?;

            store.keys.insert(key.key_id.clone(), key);
        }

        Ok(store)
    }

    pub fn add_key(&mut self, key: ReleaseKey) {
        self.keys.insert(key.key_id.clone(), key);
    }

    pub fn get_key(&self, key_id: &str) -> Option<&ReleaseKey> {
        self.keys.get(key_id)
    }

    /// Verifies an Ed25519 signature over `message` using the trusted key named `key_id`.
    pub fn verify_signature(
        &self,
        key_id: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<&ReleaseKey, ReleaseKeyError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| ReleaseKeyError::KeyNotFound(key_id.to_string()))?;

        if !key.is_active {
            return Err(ReleaseKeyError::KeyRevoked(key_id.to_string()));
        }

        if let Some(ref exp_str) = key.expires_at {
            if let Ok(exp) = DateTime::parse_from_rfc3339(exp_str) {
                if Utc::now() > exp.with_timezone(&Utc) {
                    return Err(ReleaseKeyError::KeyExpired(key_id.to_string()));
                }
            }
        }

        let sig_bytes = hex::decode(signature_hex.trim())
            .map_err(|e| ReleaseKeyError::InvalidSignature(format!("Hex decode error: {}", e)))?;
        if sig_bytes.len() != 64 {
            return Err(ReleaseKeyError::InvalidSignature(format!(
                "Signature must be 64 bytes (got {})",
                sig_bytes.len()
            )));
        }
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| ReleaseKeyError::InvalidSignature("Invalid slice".to_string()))?;
        let signature = Signature::from_bytes(&sig_arr);

        let pk_bytes = hex::decode(key.public_key_hex.trim())
            .map_err(|e| ReleaseKeyError::InvalidPublicKey(e.to_string()))?;
        let pk_arr: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| ReleaseKeyError::InvalidPublicKey("Invalid slice".to_string()))?;
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| ReleaseKeyError::InvalidPublicKey(e.to_string()))?;

        vk.verify(message, &signature).map_err(|_| {
            ReleaseKeyError::InvalidSignature("Signature does not match public key".to_string())
        })?;

        Ok(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseStatus {
    Verified,
    InvalidSignature,
    TamperedArtifact,
    MissingArtifact,
    UntrustedKey,
    MalformedManifest,
    SecurityCheckFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseVerificationReport {
    pub status: ReleaseStatus,
    pub product_name: String,
    pub release_version: String,
    pub source_commit: String,
    pub signing_key_id: Option<String>,
    pub publisher: Option<String>,
    pub is_official: bool,
    pub signing_mode: Option<String>,
    pub verified_artifacts_count: usize,
    pub mismatched_artifacts: Vec<String>,
    pub missing_artifacts: Vec<String>,
    pub unlisted_artifacts: Vec<String>,
    pub errors: Vec<String>,
    pub details: String,
}

/// Verifies a complete Cyravell release package against its manifest and release keystore.
pub fn verify_release_package(
    manifest_path: &Path,
    artifacts_dir: &Path,
    keystore: &ReleaseKeyStore,
    expected_version: Option<&str>,
    expected_commit: Option<&str>,
    require_official: bool,
) -> ReleaseVerificationReport {
    let mut errors = Vec::new();

    if !manifest_path.exists() {
        return ReleaseVerificationReport {
            status: ReleaseStatus::MissingArtifact,
            product_name: PRODUCT_NAME.to_string(),
            release_version: "unknown".to_string(),
            source_commit: "unknown".to_string(),
            signing_key_id: None,
            publisher: None,
            is_official: false,
            signing_mode: None,
            verified_artifacts_count: 0,
            mismatched_artifacts: Vec::new(),
            missing_artifacts: vec![manifest_path.display().to_string()],
            unlisted_artifacts: Vec::new(),
            errors: vec!["Release manifest file does not exist".to_string()],
            details: format!("Manifest path '{}' not found", manifest_path.display()),
        };
    }

    let content = match std::fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(e) => {
            return ReleaseVerificationReport {
                status: ReleaseStatus::MalformedManifest,
                product_name: PRODUCT_NAME.to_string(),
                release_version: "unknown".to_string(),
                source_commit: "unknown".to_string(),
                signing_key_id: None,
                publisher: None,
                is_official: false,
                signing_mode: None,
                verified_artifacts_count: 0,
                mismatched_artifacts: Vec::new(),
                missing_artifacts: Vec::new(),
                unlisted_artifacts: Vec::new(),
                errors: vec![format!("Failed to read manifest: {}", e)],
                details: "Unreadable manifest file".to_string(),
            };
        }
    };

    if let Err(e) = validate_no_duplicate_keys(&content) {
        return ReleaseVerificationReport {
            status: ReleaseStatus::MalformedManifest,
            product_name: PRODUCT_NAME.to_string(),
            release_version: "unknown".to_string(),
            source_commit: "unknown".to_string(),
            signing_key_id: None,
            publisher: None,
            is_official: false,
            signing_mode: None,
            verified_artifacts_count: 0,
            mismatched_artifacts: Vec::new(),
            missing_artifacts: Vec::new(),
            unlisted_artifacts: Vec::new(),
            errors: vec![format!("Duplicate JSON keys in manifest: {}", e)],
            details: "Duplicate key violation in release manifest".to_string(),
        };
    }

    let manifest: CyravellReleaseManifest = match serde_json::from_str(&content) {
        Ok(m) => m,
        Err(e) => {
            return ReleaseVerificationReport {
                status: ReleaseStatus::MalformedManifest,
                product_name: PRODUCT_NAME.to_string(),
                release_version: "unknown".to_string(),
                source_commit: "unknown".to_string(),
                signing_key_id: None,
                publisher: None,
                is_official: false,
                signing_mode: None,
                verified_artifacts_count: 0,
                mismatched_artifacts: Vec::new(),
                missing_artifacts: Vec::new(),
                unlisted_artifacts: Vec::new(),
                errors: vec![format!("Manifest JSON parse error: {}", e)],
                details: "Invalid release manifest schema structure".to_string(),
            };
        }
    };

    // Check product name
    if manifest.product_name != PRODUCT_NAME {
        errors.push(format!(
            "Unexpected product_name '{}' (expected '{}')",
            manifest.product_name, PRODUCT_NAME
        ));
    }

    // Check expected version if specified
    if let Some(exp_ver) = expected_version {
        if manifest.release_version != exp_ver {
            errors.push(format!(
                "Release version mismatch: manifest has '{}', expected '{}'",
                manifest.release_version, exp_ver
            ));
        }
    }

    // Check expected commit if specified
    if let Some(exp_commit) = expected_commit {
        if manifest.source_commit != exp_commit {
            errors.push(format!(
                "Source commit mismatch: manifest has '{}', expected '{}'",
                manifest.source_commit, exp_commit
            ));
        }
    }

    // Check signing mode
    if require_official && manifest.signing_mode.as_deref() == Some("development") {
        errors.push("Manifest specifies development signing mode; official verification requires official mode".to_string());
    }

    // Verify cryptographic signature
    let (signing_key_id, publisher, is_official_key) = match (
        &manifest.signing_key_id,
        &manifest.signature,
    ) {
        (Some(key_id), Some(sig_hex)) => {
            let canonical_bytes = manifest.canonical_signing_bytes();
            match keystore.verify_signature(key_id, &canonical_bytes, sig_hex) {
                Ok(key) => {
                    if require_official && !key.is_official {
                        errors.push(format!(
                            "Untrusted key role: Key '{}' is designated as development/test only; official production release signing key is required",
                            key_id
                        ));
                    }
                    (
                        Some(key_id.clone()),
                        Some(key.publisher.clone()),
                        key.is_official,
                    )
                }
                Err(err) => {
                    errors.push(format!("Signature verification failure: {}", err));
                    (Some(key_id.clone()), None, false)
                }
            }
        }
        (None, _) | (_, None) => {
            errors.push("Release manifest is unsigned or missing key ID".to_string());
            (None, None, false)
        }
    };

    // Path traversal check on all artifact filenames
    for filename in manifest.artifacts.keys() {
        if filename.contains("..")
            || filename.starts_with('/')
            || filename.contains('\\')
            || filename.contains('\0')
        {
            errors.push(format!(
                "Security violation: artifact filename '{}' contains directory traversal sequence",
                filename
            ));
            return ReleaseVerificationReport {
                status: ReleaseStatus::SecurityCheckFailed,
                product_name: manifest.product_name,
                release_version: manifest.release_version,
                source_commit: manifest.source_commit,
                signing_key_id,
                publisher,
                is_official: is_official_key,
                signing_mode: manifest.signing_mode,
                verified_artifacts_count: 0,
                mismatched_artifacts: Vec::new(),
                missing_artifacts: Vec::new(),
                unlisted_artifacts: Vec::new(),
                errors,
                details: "Path traversal detected in release artifact name".to_string(),
            };
        }
    }

    let mut verified_count = 0;
    let mut missing_artifacts = Vec::new();
    let mut mismatched_artifacts = Vec::new();

    // Verify each declared artifact
    for (name, artifact) in &manifest.artifacts {
        let art_path = artifacts_dir.join(&artifact.filename);
        if !art_path.exists() {
            missing_artifacts.push(artifact.filename.clone());
            continue;
        }

        // Symlink and special file check using symlink_metadata
        let sym_meta = match std::fs::symlink_metadata(&art_path) {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!("Failed to stat artifact '{}': {}", name, e));
                mismatched_artifacts.push(artifact.filename.clone());
                continue;
            }
        };

        if sym_meta.file_type().is_symlink() {
            errors.push(format!(
                "Security violation: artifact '{}' is a symbolic link",
                name
            ));
            return ReleaseVerificationReport {
                status: ReleaseStatus::SecurityCheckFailed,
                product_name: manifest.product_name,
                release_version: manifest.release_version,
                source_commit: manifest.source_commit,
                signing_key_id,
                publisher,
                is_official: is_official_key,
                signing_mode: manifest.signing_mode,
                verified_artifacts_count: verified_count,
                mismatched_artifacts: vec![artifact.filename.clone()],
                missing_artifacts,
                unlisted_artifacts: Vec::new(),
                errors,
                details: format!("Security violation: artifact '{}' is a symbolic link", name),
            };
        }

        if !sym_meta.file_type().is_file() {
            errors.push(format!(
                "Security violation: artifact '{}' is not a regular file",
                name
            ));
            return ReleaseVerificationReport {
                status: ReleaseStatus::SecurityCheckFailed,
                product_name: manifest.product_name,
                release_version: manifest.release_version,
                source_commit: manifest.source_commit,
                signing_key_id,
                publisher,
                is_official: is_official_key,
                signing_mode: manifest.signing_mode,
                verified_artifacts_count: verified_count,
                mismatched_artifacts: vec![artifact.filename.clone()],
                missing_artifacts,
                unlisted_artifacts: Vec::new(),
                errors,
                details: format!(
                    "Security violation: artifact '{}' is not a regular file",
                    name
                ),
            };
        }

        if sym_meta.len() != artifact.size_bytes {
            errors.push(format!(
                "Artifact size mismatch for '{}': manifest expects {} bytes, file is {} bytes",
                name,
                artifact.size_bytes,
                sym_meta.len()
            ));
            mismatched_artifacts.push(artifact.filename.clone());
            continue;
        }

        // Check SHA-256
        match compute_sha256(&art_path) {
            Ok(digest) => {
                if digest.to_lowercase() != artifact.sha256.to_lowercase() {
                    errors.push(format!(
                        "SHA-256 mismatch for '{}': manifest expects {}, file is {}",
                        name, artifact.sha256, digest
                    ));
                    mismatched_artifacts.push(artifact.filename.clone());
                } else {
                    verified_count += 1;
                }
            }
            Err(e) => {
                errors.push(format!("Failed to hash artifact '{}': {}", name, e));
                mismatched_artifacts.push(artifact.filename.clone());
            }
        }
    }

    // Verify SBOM artifact specifically
    let sbom_path = artifacts_dir.join(&manifest.sbom.filename);
    if !sbom_path.exists() {
        if !missing_artifacts.contains(&manifest.sbom.filename) {
            missing_artifacts.push(manifest.sbom.filename.clone());
        }
        errors.push(format!("SBOM file '{}' is missing", manifest.sbom.filename));
    } else {
        let sbom_sym_meta = match std::fs::symlink_metadata(&sbom_path) {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!(
                    "Failed to stat SBOM '{}': {}",
                    manifest.sbom.filename, e
                ));
                return ReleaseVerificationReport {
                    status: ReleaseStatus::SecurityCheckFailed,
                    product_name: manifest.product_name,
                    release_version: manifest.release_version,
                    source_commit: manifest.source_commit,
                    signing_key_id,
                    publisher,
                    is_official: is_official_key,
                    signing_mode: manifest.signing_mode,
                    verified_artifacts_count: verified_count,
                    mismatched_artifacts,
                    missing_artifacts,
                    unlisted_artifacts: Vec::new(),
                    errors,
                    details: "SBOM metadata failure".to_string(),
                };
            }
        };

        if sbom_sym_meta.file_type().is_symlink() || !sbom_sym_meta.file_type().is_file() {
            errors.push(format!(
                "Security violation: SBOM '{}' is a symbolic link or non-regular file",
                manifest.sbom.filename
            ));
            mismatched_artifacts.push(manifest.sbom.filename.clone());
        } else {
            match compute_sha256(&sbom_path) {
                Ok(digest) => {
                    if digest.to_lowercase() != manifest.sbom.sha256.to_lowercase() {
                        if !mismatched_artifacts.contains(&manifest.sbom.filename) {
                            mismatched_artifacts.push(manifest.sbom.filename.clone());
                        }
                        errors.push(format!(
                            "SBOM SHA-256 mismatch: manifest expects {}, file is {}",
                            manifest.sbom.sha256, digest
                        ));
                    }
                }
                Err(e) => {
                    errors.push(format!(
                        "Failed to hash SBOM '{}': {}",
                        manifest.sbom.filename, e
                    ));
                }
            }
        }
    }

    // Check for extraneous / unlisted artifacts in artifacts_dir
    let mut unlisted_artifacts = Vec::new();
    if let Ok(entries) = std::fs::read_dir(artifacts_dir) {
        let manifest_filename = manifest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("release_manifest.json");

        for entry in entries.flatten() {
            let p = entry.path();
            let is_sym = p.is_symlink();
            if let Some(name) = entry.file_name().to_str() {
                // Skip manifest, detached signature, and sha256 checksum files
                if name == manifest_filename
                    || name.ends_with(".sig")
                    || name.ends_with(".sha256")
                    || name == "SHA256SUMS"
                    || name == "SHA256SUMS.sig"
                {
                    continue;
                }
                if !manifest.artifacts.contains_key(name) && name != manifest.sbom.filename {
                    unlisted_artifacts.push(name.to_string());
                    if is_sym {
                        errors.push(format!(
                            "Security violation: unlisted symbolic link '{}' in release directory",
                            name
                        ));
                    } else if name.ends_with(".sh")
                        || name.ends_with(".bin")
                        || name.ends_with(".py")
                        || name.ends_with(".exe")
                        || name.ends_with(".so")
                    {
                        errors.push(format!("Security violation: unlisted executable file '{}' found in release directory", name));
                    } else if require_official {
                        errors.push(format!(
                            "Security violation: unlisted file '{}' in official release directory",
                            name
                        ));
                    }
                }
            }
        }
    }

    // Determine final status
    let status = if !missing_artifacts.is_empty() {
        ReleaseStatus::MissingArtifact
    } else if !mismatched_artifacts.is_empty() {
        ReleaseStatus::TamperedArtifact
    } else if signing_key_id.is_none() || publisher.is_none() {
        ReleaseStatus::InvalidSignature
    } else if require_official && !is_official_key {
        ReleaseStatus::UntrustedKey
    } else if !errors.is_empty() {
        ReleaseStatus::SecurityCheckFailed
    } else {
        ReleaseStatus::Verified
    };

    let details = match status {
        ReleaseStatus::Verified => {
            let mode_desc = if is_official_key {
                "OFFICIAL RELEASE"
            } else {
                "DEVELOPMENT / TEST BUILD (NON-PRODUCTION)"
            };
            format!(
                "All {} artifacts verified bit-for-bit against release manifest. Authenticated by publisher '{}' ({}) [{}]",
                verified_count,
                publisher.as_deref().unwrap_or("unknown"),
                signing_key_id.as_deref().unwrap_or("none"),
                mode_desc
            )
        }
        ReleaseStatus::TamperedArtifact => format!(
            "Digest or size mismatch detected in {} artifact(s): {:?}",
            mismatched_artifacts.len(),
            mismatched_artifacts
        ),
        ReleaseStatus::MissingArtifact => format!(
            "{} required artifact(s) missing from release directory: {:?}",
            missing_artifacts.len(),
            missing_artifacts
        ),
        ReleaseStatus::InvalidSignature => format!(
            "Release signature invalid, missing, or key untrusted: {}",
            errors.join("; ")
        ),
        ReleaseStatus::UntrustedKey => format!(
            "Publisher signing key untrusted for requested verification tier: {}",
            errors.join("; ")
        ),
        ReleaseStatus::MalformedManifest => "Malformed manifest file".to_string(),
        ReleaseStatus::SecurityCheckFailed => {
            format!("Security validation checks failed: {}", errors.join("; "))
        }
    };

    ReleaseVerificationReport {
        status,
        product_name: manifest.product_name,
        release_version: manifest.release_version,
        source_commit: manifest.source_commit,
        signing_key_id,
        publisher,
        is_official: is_official_key,
        signing_mode: manifest.signing_mode,
        verified_artifacts_count: verified_count,
        mismatched_artifacts,
        missing_artifacts,
        unlisted_artifacts,
        errors,
        details,
    }
}

/// Helper to generate a release manifest by scanning artifacts in `artifacts_dir`.
pub fn generate_release_manifest(
    artifacts_dir: &Path,
    release_version: &str,
    source_commit: &str,
    source_tag: Option<&str>,
    target_platform: &str,
    sbom_filename: &str,
    signing_mode: Option<&str>,
) -> Result<CyravellReleaseManifest, String> {
    if !artifacts_dir.exists() {
        return Err(format!(
            "Artifacts directory '{}' does not exist",
            artifacts_dir.display()
        ));
    }

    let mut artifacts = BTreeMap::new();
    let entries = std::fs::read_dir(artifacts_dir)
        .map_err(|e| format!("Failed to read artifacts directory: {}", e))?;

    let mut sbom_found = None;

    for entry in entries.flatten() {
        let p = entry.path();
        let fname = match p.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if fname == "release_manifest.json"
            || fname.ends_with(".sig")
            || fname.ends_with(".sha256")
            || fname == "SHA256SUMS"
            || fname == "SHA256SUMS.sig"
        {
            continue;
        }

        let sym_meta = std::fs::symlink_metadata(&p)
            .map_err(|e| format!("Failed to stat '{}': {}", fname, e))?;

        if sym_meta.file_type().is_symlink() {
            return Err(format!(
                "Security violation: artifact '{}' is a symbolic link",
                fname
            ));
        }

        if !sym_meta.file_type().is_file() {
            continue;
        }

        let size_bytes = sym_meta.len();
        let digest = compute_sha256(&p)
            .map_err(|e| format!("Failed to compute SHA-256 for '{}': {}", fname, e))?;

        let artifact_type = if fname.ends_with(".vsix") {
            "extension"
        } else if fname.ends_with(".tar.gz") || fname.ends_with(".tgz") || fname.ends_with(".zip") {
            "archive"
        } else if fname.ends_with(".spdx.json") || fname.ends_with(".sbom.json") {
            "sbom"
        } else {
            "binary"
        };

        let target_plat = if artifact_type == "binary" {
            Some(target_platform.to_string())
        } else {
            None
        };

        if fname == sbom_filename || (artifact_type == "sbom" && sbom_found.is_none()) {
            sbom_found = Some(SbomReference {
                filename: fname.clone(),
                sha256: digest.clone(),
                format: "SPDX-2.3".to_string(),
            });
        }

        artifacts.insert(
            fname.clone(),
            ReleaseArtifact {
                filename: fname,
                size_bytes,
                sha256: digest,
                artifact_type: artifact_type.to_string(),
                target_platform: target_plat,
            },
        );
    }

    let sbom = match sbom_found {
        Some(s) => s,
        None => {
            return Err(format!(
                "Required SBOM file '{}' not found in artifacts directory",
                sbom_filename
            ));
        }
    };

    let build_metadata = BuildMetadata {
        rustc_version: "rustc 1.99.1".to_string(),
        cargo_version: "cargo 1.99.1".to_string(),
        node_version: Some("v18.19.1".to_string()),
        build_profile: "release".to_string(),
        source_date_epoch: Some(1767225600), // 2026-01-01T00:00:00Z
    };

    let manifest = CyravellReleaseManifest {
        schema_version: RELEASE_MANIFEST_SCHEMA_VERSION.to_string(),
        product_name: PRODUCT_NAME.to_string(),
        release_version: release_version.to_string(),
        source_commit: source_commit.to_string(),
        source_tag: source_tag.map(|s| s.to_string()),
        build_timestamp: Utc::now().to_rfc3339(),
        engine_version: release_version.to_string(),
        extension_version: release_version.to_string(),
        signing_mode: Some(signing_mode.unwrap_or("official").to_string()),
        target_platforms: vec![target_platform.to_string()],
        artifacts,
        required_runtime_components: vec![
            "rules/baseline_rules.json".to_string(),
            "rules/package_advisories.json".to_string(),
            "rules/release_signing_keys.json".to_string(),
            "rules/schema.json".to_string(),
            "rules/trusted_keys.json".to_string(),
        ],
        build_metadata,
        sbom,
        signing_key_id: None,
        signature: None,
    };

    Ok(manifest)
}
