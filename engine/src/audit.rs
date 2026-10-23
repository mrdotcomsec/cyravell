// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::model::{AuditRecord, AuditVerifyResult, Severity, GENESIS_HASH};

#[derive(Debug)]
pub enum AuditError {
    Io(std::io::Error),
    Json(serde_json::Error),
    VerificationFailure { sequence: u64, reason: String },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Json(e) => write!(f, "JSON serialization error: {}", e),
            Self::VerificationFailure { sequence, reason } => {
                write!(f, "Audit verification failure at sequence {}: {}", sequence, reason)
            }
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::VerificationFailure { .. } => None,
        }
    }
}

impl From<std::io::Error> for AuditError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

pub struct AuditLog {
    file_path: PathBuf,
    state: Mutex<AuditState>,
}

struct AuditState {
    last_sequence: u64,
    last_hash: String,
}

impl AuditLog {
    /// Opens or creates the append-only audit log file with restrictive permissions.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        // Initialize state by scanning existing log if present
        let mut last_seq = 0;
        let mut last_h = GENESIS_HASH.to_string();

        if path.exists() {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for line_res in reader.lines() {
                let line = line_res?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let rec: AuditRecord = serde_json::from_str(trimmed)?;
                last_seq = rec.sequence_number;
                last_h = rec.current_record_hash;
            }
        }

        Ok(Self {
            file_path: path,
            state: Mutex::new(AuditState {
                last_sequence: last_seq,
                last_hash: last_h,
            }),
        })
    }

    /// Appends a new event decision to the cryptographic hash chain.
    pub fn append(
        &self,
        event_id: &str,
        action: &str,
        rationale: &str,
        severity: Severity,
    ) -> Result<AuditRecord, AuditError> {
        let mut state = self.state.lock().unwrap();
        let next_seq = state.last_sequence + 1;
        let timestamp = Utc::now();
        let prev_hash = state.last_hash.clone();

        let current_hash = compute_record_hash(
            next_seq,
            &timestamp,
            event_id,
            action,
            rationale,
            severity,
            &prev_hash,
        );

        let record = AuditRecord {
            sequence_number: next_seq,
            timestamp,
            event_id: event_id.to_string(),
            action_recorded: action.to_string(),
            decision_rationale: rationale.to_string(),
            risk_severity: severity,
            previous_record_hash: prev_hash,
            current_record_hash: current_hash.clone(),
        };

        // Write record as single line JSON to log file with mode 0600 on creation
        let serialized = serde_json::to_string(&record)?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }

        let mut file = options.open(&self.file_path)?;
        writeln!(file, "{}", serialized)?;
        file.flush()?;

        // Update in-memory state
        state.last_sequence = next_seq;
        state.last_hash = current_hash;

        Ok(record)
    }

    /// Verifies the cryptographic integrity of the entire audit chain.
    pub fn verify(&self) -> AuditVerifyResult {
        if !self.file_path.exists() {
            return AuditVerifyResult {
                status: "VALID".to_string(),
                total_records: 0,
                genesis_hash: GENESIS_HASH.to_string(),
                latest_hash: GENESIS_HASH.to_string(),
                corrupted_sequence: None,
                message: "Audit log is empty; genesis state valid".to_string(),
            };
        }

        let file = match File::open(&self.file_path) {
            Ok(f) => f,
            Err(e) => {
                return AuditVerifyResult {
                    status: "ERROR".to_string(),
                    total_records: 0,
                    genesis_hash: GENESIS_HASH.to_string(),
                    latest_hash: GENESIS_HASH.to_string(),
                    corrupted_sequence: None,
                    message: format!("Failed to open audit log for reading: {}", e),
                };
            }
        };

        let reader = BufReader::new(file);
        let mut expected_seq = 1;
        let mut expected_prev_hash = GENESIS_HASH.to_string();
        let mut total_records = 0;

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(e) => {
                    return AuditVerifyResult {
                        status: "CORRUPTED".to_string(),
                        total_records,
                        genesis_hash: GENESIS_HASH.to_string(),
                        latest_hash: expected_prev_hash.clone(),
                        corrupted_sequence: Some(expected_seq),
                        message: format!("IO reading line at sequence {}: {}", expected_seq, e),
                    };
                }
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let record: AuditRecord = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    return AuditVerifyResult {
                        status: "CORRUPTED".to_string(),
                        total_records,
                        genesis_hash: GENESIS_HASH.to_string(),
                        latest_hash: expected_prev_hash.clone(),
                        corrupted_sequence: Some(expected_seq),
                        message: format!("Malformed record JSON at sequence {}: {}", expected_seq, e),
                    };
                }
            };

            // 1. Verify sequence order
            if record.sequence_number != expected_seq {
                return AuditVerifyResult {
                    status: "CORRUPTED".to_string(),
                    total_records,
                    genesis_hash: GENESIS_HASH.to_string(),
                    latest_hash: expected_prev_hash.clone(),
                    corrupted_sequence: Some(record.sequence_number),
                    message: format!(
                        "Sequence break: expected {}, found {}",
                        expected_seq, record.sequence_number
                    ),
                };
            }

            // 2. Verify previous hash chaining
            if record.previous_record_hash != expected_prev_hash {
                return AuditVerifyResult {
                    status: "CORRUPTED".to_string(),
                    total_records,
                    genesis_hash: GENESIS_HASH.to_string(),
                    latest_hash: expected_prev_hash.clone(),
                    corrupted_sequence: Some(record.sequence_number),
                    message: format!(
                        "Hash chain break at sequence {}: previous_record_hash {} does not match expected {}",
                        record.sequence_number, record.previous_record_hash, expected_prev_hash
                    ),
                };
            }

            // 3. Verify record's own SHA-256 hash
            let computed_hash = compute_record_hash(
                record.sequence_number,
                &record.timestamp,
                &record.event_id,
                &record.action_recorded,
                &record.decision_rationale,
                record.risk_severity,
                &record.previous_record_hash,
            );

            if record.current_record_hash != computed_hash {
                return AuditVerifyResult {
                    status: "CORRUPTED".to_string(),
                    total_records,
                    genesis_hash: GENESIS_HASH.to_string(),
                    latest_hash: expected_prev_hash.clone(),
                    corrupted_sequence: Some(record.sequence_number),
                    message: format!(
                        "Tampered record content at sequence {}: current_record_hash {} does not match computed {}",
                        record.sequence_number, record.current_record_hash, computed_hash
                    ),
                };
            }

            expected_prev_hash = record.current_record_hash;
            expected_seq += 1;
            total_records += 1;
        }

        AuditVerifyResult {
            status: "VALID".to_string(),
            total_records,
            genesis_hash: GENESIS_HASH.to_string(),
            latest_hash: expected_prev_hash,
            corrupted_sequence: None,
            message: "Cryptographic hash chain verified successfully".to_string(),
        }
    }

    pub fn total_records(&self) -> u64 {
        self.state.lock().unwrap().last_sequence
    }
}

/// Computes the deterministic SHA-256 hash for an audit record.
pub fn compute_record_hash(
    sequence: u64,
    timestamp: &DateTime<Utc>,
    event_id: &str,
    action: &str,
    rationale: &str,
    severity: Severity,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    let canonical = format!(
        "{}:{}:{}:{}:{}:{:?}:{}",
        sequence,
        timestamp.to_rfc3339(),
        event_id,
        action,
        rationale,
        severity,
        prev_hash
    );
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_audit_chain_append_and_verify() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.log");

        let audit = AuditLog::open(&log_path).unwrap();
        assert_eq!(audit.total_records(), 0);

        let rec1 = audit.append("evt-1", "BLOCK", "Destructive command", Severity::Critical).unwrap();
        assert_eq!(rec1.sequence_number, 1);
        assert_eq!(rec1.previous_record_hash, GENESIS_HASH);

        let rec2 = audit.append("evt-2", "ALLOW", "Safe operation", Severity::Low).unwrap();
        assert_eq!(rec2.sequence_number, 2);
        assert_eq!(rec2.previous_record_hash, rec1.current_record_hash);

        let verify_res = audit.verify();
        assert_eq!(verify_res.status, "VALID");
        assert_eq!(verify_res.total_records, 2);
        assert!(verify_res.corrupted_sequence.is_none());
    }

    #[test]
    fn test_audit_tampering_detection() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("tamper_test.log");

        let audit = AuditLog::open(&log_path).unwrap();
        audit.append("evt-1", "BLOCK", "Initial block", Severity::Critical).unwrap();
        audit.append("evt-2", "ALERT", "Second alert", Severity::High).unwrap();

        // Verify valid first
        let initial_check = audit.verify();
        assert_eq!(initial_check.status, "VALID");

        // Intentionally tamper with record 1 in the file
        let content = std::fs::read_to_string(&log_path).unwrap();
        let tampered_content = content.replace("Initial block", "Tampered innocent text");
        std::fs::write(&log_path, tampered_content).unwrap();

        // Verify tampering is immediately detected
        let tamper_check = audit.verify();
        assert_eq!(tamper_check.status, "CORRUPTED");
        assert_eq!(tamper_check.corrupted_sequence, Some(1));
        assert!(tamper_check.message.contains("Tampered record content"));
    }

    #[test]
    fn test_audit_deletion_detection() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("deletion_test.log");

        let audit = AuditLog::open(&log_path).unwrap();
        audit.append("evt-1", "BLOCK", "First", Severity::Critical).unwrap();
        audit.append("evt-2", "ALERT", "Second", Severity::High).unwrap();
        audit.append("evt-3", "ALLOW", "Third", Severity::Low).unwrap();

        // Delete the middle line (sequence 2)
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let new_content = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&log_path, new_content).unwrap();

        let check = audit.verify();
        assert_eq!(check.status, "CORRUPTED");
        assert_eq!(check.corrupted_sequence, Some(3));
    }
}

