// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::TrustedKey;
use crate::package::strict_json::validate_no_duplicate_keys;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyVerificationError {
    KeyNotFound(String),
    KeyRevoked(String),
    KeyExpired(String),
    InvalidPublicKey(String),
    InvalidSignatureFormat(String),
    SignatureVerificationFailed,
    TrustStoreUnavailable(String),
    PublisherMismatch { expected: String, actual: String },
}

impl std::fmt::Display for KeyVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotFound(id) => write!(f, "Publisher signing key '{}' is not trusted", id),
            Self::KeyRevoked(id) => write!(
                f,
                "Publisher signing key '{}' has been revoked or deactivated",
                id
            ),
            Self::KeyExpired(id) => write!(f, "Publisher signing key '{}' has expired", id),
            Self::InvalidPublicKey(msg) => write!(f, "Invalid public key format: {}", msg),
            Self::InvalidSignatureFormat(msg) => write!(f, "Invalid signature format: {}", msg),
            Self::SignatureVerificationFailed => write!(
                f,
                "Cryptographic signature verification failed: signature does not match message and publisher public key"
            ),
            Self::TrustStoreUnavailable(reason) => {
                write!(f, "Trust store is corrupted or unavailable: {}", reason)
            }
            Self::PublisherMismatch { expected, actual } => write!(
                f,
                "Publisher identity mismatch: key belongs to '{}' but bundle claims '{}'",
                expected, actual
            ),
        }
    }
}

impl std::error::Error for KeyVerificationError {}

#[derive(Debug)]
pub enum KeyStoreError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    CorruptedKeystore(String),
    SymlinkForbidden(String),
    InsecurePermissions(String),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Failed to read trusted keys file: {}", e),
            Self::Parse(e) => write!(f, "Failed to parse trusted keys JSON: {}", e),
            Self::CorruptedKeystore(msg) => write!(f, "Corrupted trust store: {}", msg),
            Self::SymlinkForbidden(msg) => write!(f, "Symlinks forbidden for trust store: {}", msg),
            Self::InsecurePermissions(msg) => {
                write!(f, "Insecure permissions for trust store: {}", msg)
            }
        }
    }
}

impl std::error::Error for KeyStoreError {}

impl From<std::io::Error> for KeyStoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for KeyStoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Parse(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStoreStatus {
    Operational,
    Corrupted(String),
}

#[derive(Debug, Clone)]
pub struct TrustedKeyStore {
    keys: HashMap<String, TrustedKey>,
    status: TrustStoreStatus,
}

impl Default for TrustedKeyStore {
    fn default() -> Self {
        Self::load_embedded()
    }
}

impl TrustedKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            status: TrustStoreStatus::Operational,
        }
    }

    pub fn corrupted(reason: String) -> Self {
        Self {
            keys: HashMap::new(),
            status: TrustStoreStatus::Corrupted(reason),
        }
    }

    pub fn status(&self) -> &TrustStoreStatus {
        &self.status
    }

    pub fn is_operational(&self) -> bool {
        matches!(self.status, TrustStoreStatus::Operational)
    }

    pub fn load_default() -> Self {
        let disk_path = Path::new("rules/trusted_keys.json");
        if disk_path.exists() {
            match Self::load_from_path(disk_path) {
                Ok(store) => store,
                Err(e) => Self::corrupted(format!(
                    "Local trust store '{}' is corrupted or insecure: {}",
                    disk_path.display(),
                    e
                )),
            }
        } else {
            Self::load_embedded()
        }
    }

    pub fn load_embedded() -> Self {
        const EMBEDDED_KEYS: &str = include_str!("../../../rules/trusted_keys.json");
        Self::load_from_json(EMBEDDED_KEYS)
            .unwrap_or_else(|e| Self::corrupted(format!("Embedded keys parse error: {}", e)))
    }

    pub fn load_from_json(json: &str) -> Result<Self, KeyStoreError> {
        if let Err(e) = validate_no_duplicate_keys(json) {
            return Err(KeyStoreError::CorruptedKeystore(e));
        }

        #[derive(serde::Deserialize)]
        struct RawKeys {
            keys: Vec<TrustedKey>,
        }
        let raw: RawKeys = serde_json::from_str(json).map_err(KeyStoreError::Parse)?;
        let mut store = Self::new();
        let mut seen_ids = HashSet::new();

        for k in raw.keys {
            if k.key_id.trim().is_empty() {
                return Err(KeyStoreError::CorruptedKeystore(
                    "Trusted key cannot have an empty key_id".to_string(),
                ));
            }
            if !seen_ids.insert(k.key_id.clone()) {
                return Err(KeyStoreError::CorruptedKeystore(format!(
                    "Duplicate key_id in trust store: '{}'",
                    k.key_id
                )));
            }

            let key_bytes = hex::decode(k.public_key_hex.trim()).map_err(|e| {
                KeyStoreError::CorruptedKeystore(format!(
                    "Invalid public key hex for key '{}': {}",
                    k.key_id, e
                ))
            })?;
            if key_bytes.len() != 32 {
                return Err(KeyStoreError::CorruptedKeystore(format!(
                    "Public key for key '{}' must be 32 bytes (got {})",
                    k.key_id,
                    key_bytes.len()
                )));
            }

            store.add_key(k);
        }
        Ok(store)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, KeyStoreError> {
        #[cfg(unix)]
        {
            let meta = std::fs::symlink_metadata(path).map_err(KeyStoreError::Io)?;
            if meta.file_type().is_symlink() {
                return Err(KeyStoreError::SymlinkForbidden(format!(
                    "Trust store path '{}' is a symbolic link",
                    path.display()
                )));
            }
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                return Err(KeyStoreError::InsecurePermissions(format!(
                    "Trust store path '{}' is world-writable ({:o})",
                    path.display(),
                    mode
                )));
            }
        }

        let content = std::fs::read_to_string(path).map_err(KeyStoreError::Io)?;
        Self::load_from_json(&content)
    }

    pub fn add_key(&mut self, key: TrustedKey) {
        self.keys.insert(key.key_id.clone(), key);
    }

    pub fn get_key(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.get(key_id)
    }

    pub fn all_keys(&self) -> Vec<&TrustedKey> {
        self.keys.values().collect()
    }

    pub fn verify_signature(
        &self,
        key_id: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<(), KeyVerificationError> {
        if let TrustStoreStatus::Corrupted(ref reason) = self.status {
            return Err(KeyVerificationError::TrustStoreUnavailable(reason.clone()));
        }

        let trusted_key = self
            .get_key(key_id)
            .ok_or_else(|| KeyVerificationError::KeyNotFound(key_id.to_string()))?;

        if !trusted_key.is_active {
            return Err(KeyVerificationError::KeyRevoked(key_id.to_string()));
        }

        if let Some(expires_at) = trusted_key.expires_at {
            if Utc::now() > expires_at {
                return Err(KeyVerificationError::KeyExpired(key_id.to_string()));
            }
        }

        let pubkey_bytes = hex::decode(&trusted_key.public_key_hex).map_err(|e| {
            KeyVerificationError::InvalidPublicKey(format!("Hex decode failed: {}", e))
        })?;

        if pubkey_bytes.len() != 32 {
            return Err(KeyVerificationError::InvalidPublicKey(format!(
                "Expected 32 bytes for Ed25519 public key, got {}",
                pubkey_bytes.len()
            )));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr).map_err(|e| {
            KeyVerificationError::InvalidPublicKey(format!("Malformed Ed25519 public key: {}", e))
        })?;

        let sig_bytes = hex::decode(signature_hex.trim()).map_err(|e| {
            KeyVerificationError::InvalidSignatureFormat(format!("Hex decode failed: {}", e))
        })?;

        if sig_bytes.len() != 64 {
            return Err(KeyVerificationError::InvalidSignatureFormat(format!(
                "Expected 64 bytes for Ed25519 signature, got {}",
                sig_bytes.len()
            )));
        }

        let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
            KeyVerificationError::InvalidSignatureFormat(format!(
                "Malformed Ed25519 signature: {}",
                e
            ))
        })?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| KeyVerificationError::SignatureVerificationFailed)?;

        Ok(())
    }
}
