// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use uuid::Uuid;

use crate::model::{
    ApprovalRequest, ApprovalStatus, ApprovalUserDecision, PackageEcosystem, Severity,
};

#[derive(Debug, PartialEq, Eq)]
pub enum ApprovalError {
    NotFound(String),
    Expired,
    Denied,
    Cancelled,
    NotApproved(ApprovalStatus),
    AlreadyConsumed,
    SessionMismatch { expected: String, actual: String },
    CommandMismatch,
    InvalidToken,
    InvalidStateTransition(String),
    HardBlockPolicyViolation,
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalError::NotFound(id) => write!(f, "Approval request '{}' not found", id),
            ApprovalError::Expired => write!(f, "Approval request has expired"),
            ApprovalError::Denied => write!(f, "Approval request was denied"),
            ApprovalError::Cancelled => write!(f, "Approval request was cancelled"),
            ApprovalError::NotApproved(st) => {
                write!(
                    f,
                    "Approval request has not been approved (current status: {:?})",
                    st
                )
            }
            ApprovalError::AlreadyConsumed => {
                write!(
                    f,
                    "Authorization token has already been consumed (replay prevented)"
                )
            }
            ApprovalError::SessionMismatch { expected, actual } => {
                write!(
                    f,
                    "Session mismatch: token was issued for session '{}', but presented by '{}'",
                    expected, actual
                )
            }
            ApprovalError::CommandMismatch => {
                write!(
                    f,
                    "Command mismatch: command content modified after approval"
                )
            }
            ApprovalError::InvalidToken => write!(f, "Invalid or unknown authorization token"),
            ApprovalError::InvalidStateTransition(msg) => {
                write!(f, "Invalid approval state transition: {}", msg)
            }
            ApprovalError::HardBlockPolicyViolation => {
                write!(
                    f,
                    "Policy violation: Command matches hard-block policy and cannot be approved"
                )
            }
        }
    }
}

impl std::error::Error for ApprovalError {}

#[derive(Debug, Clone)]
struct StoredApproval {
    request: ApprovalRequest,
    authorization_token: Option<String>,
    consumed_at: Option<DateTime<Utc>>,
}

pub struct ApprovalManager {
    requests: Mutex<HashMap<String, StoredApproval>>,
    default_ttl_seconds: i64,
}

impl ApprovalManager {
    pub fn new(default_ttl_seconds: i64) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            default_ttl_seconds,
        }
    }

    /// Creates a new pending approval request in thread-safe memory.
    #[allow(clippy::too_many_arguments)]
    pub fn create_request(
        &self,
        session_id: String,
        command: String,
        working_directory: Option<String>,
        rule_id: String,
        severity: Severity,
        reason: String,
        ttl_seconds: Option<i64>,
    ) -> ApprovalRequest {
        self.create_request_with_package_details(
            session_id,
            command,
            working_directory,
            rule_id,
            severity,
            reason,
            ttl_seconds,
            None,
            None,
        )
    }

    /// Creates a new pending approval request with optional package assessment details.
    #[allow(clippy::too_many_arguments)]
    pub fn create_request_with_package_details(
        &self,
        session_id: String,
        command: String,
        working_directory: Option<String>,
        rule_id: String,
        severity: Severity,
        reason: String,
        ttl_seconds: Option<i64>,
        package_details: Option<crate::model::PackageAssessmentSummary>,
        manifest_fingerprint: Option<String>,
    ) -> ApprovalRequest {
        let request_id = format!("appr-{}", Uuid::new_v4());
        let now = Utc::now();
        let ttl = ttl_seconds.unwrap_or(self.default_ttl_seconds);
        let expires_at = now + Duration::seconds(ttl);

        let request = ApprovalRequest {
            request_id: request_id.clone(),
            session_id,
            command,
            working_directory,
            rule_id,
            severity,
            reason,
            created_at: now,
            expires_at,
            status: ApprovalStatus::Pending,
            decision_reason: None,
            package_details,
            manifest_fingerprint,
        };

        let stored = StoredApproval {
            request: request.clone(),
            authorization_token: None,
            consumed_at: None,
        };

        let mut lock = self.requests.lock().unwrap();
        lock.insert(request_id, stored);

        request
    }

    /// Evaluates user decision (Approve, Deny, Cancel) with atomic race-safe state transitions.
    pub fn decide(
        &self,
        request_id: &str,
        decision: ApprovalUserDecision,
        user_reason: Option<String>,
    ) -> Result<(ApprovalStatus, Option<String>), ApprovalError> {
        let mut lock = self.requests.lock().unwrap();
        let stored = lock
            .get_mut(request_id)
            .ok_or_else(|| ApprovalError::NotFound(request_id.to_string()))?;

        let now = Utc::now();

        // Check expiration
        if now > stored.request.expires_at && stored.request.status == ApprovalStatus::Pending {
            stored.request.status = ApprovalStatus::Expired;
            return Err(ApprovalError::Expired);
        }

        // Only Pending requests can be decided
        if stored.request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::InvalidStateTransition(format!(
                "Cannot decide request currently in status {:?}",
                stored.request.status
            )));
        }

        match decision {
            ApprovalUserDecision::Approve => {
                // Hard blocks can never be approved
                if stored.request.severity == Severity::Critical
                    && stored.request.rule_id == "RULE-TERM-001"
                {
                    stored.request.status = ApprovalStatus::Denied;
                    stored.request.decision_reason =
                        Some("Cannot approve command flagged as Critical hard-block".to_string());
                    return Err(ApprovalError::HardBlockPolicyViolation);
                }

                stored.request.status = ApprovalStatus::Approved;
                stored.request.decision_reason = user_reason;

                // Generate single-use cryptographic token
                let token = format!("cyr-auth-{}-{}", Uuid::new_v4(), Uuid::new_v4());
                stored.authorization_token = Some(token.clone());

                Ok((ApprovalStatus::Approved, Some(token)))
            }
            ApprovalUserDecision::Deny => {
                stored.request.status = ApprovalStatus::Denied;
                stored.request.decision_reason = user_reason;
                stored.authorization_token = None;
                Ok((ApprovalStatus::Denied, None))
            }
            ApprovalUserDecision::Cancel => {
                stored.request.status = ApprovalStatus::Cancelled;
                stored.request.decision_reason = user_reason;
                stored.authorization_token = None;
                Ok((ApprovalStatus::Cancelled, None))
            }
        }
    }

    /// Atomically consumes authorization token before dispatch.
    /// Strictly guarantees single-use token consumption and parameter binding.
    pub fn consume_authorization(
        &self,
        request_id: &str,
        session_id: &str,
        command: &str,
        token: &str,
    ) -> Result<ApprovalRequest, ApprovalError> {
        let mut lock = self.requests.lock().unwrap();
        let stored = lock
            .get_mut(request_id)
            .ok_or_else(|| ApprovalError::NotFound(request_id.to_string()))?;

        let now = Utc::now();

        // Expired check
        if now > stored.request.expires_at && stored.request.status != ApprovalStatus::Consumed {
            stored.request.status = ApprovalStatus::Expired;
            stored.authorization_token = None;
            return Err(ApprovalError::Expired);
        }

        // Verify status
        match stored.request.status {
            ApprovalStatus::Consumed => return Err(ApprovalError::AlreadyConsumed),
            ApprovalStatus::Denied => return Err(ApprovalError::Denied),
            ApprovalStatus::Cancelled => return Err(ApprovalError::Cancelled),
            ApprovalStatus::Expired => return Err(ApprovalError::Expired),
            ApprovalStatus::Pending => {
                return Err(ApprovalError::NotApproved(ApprovalStatus::Pending))
            }
            ApprovalStatus::Approved => {}
        }

        // Verify session binding
        if stored.request.session_id != session_id {
            return Err(ApprovalError::SessionMismatch {
                expected: stored.request.session_id.clone(),
                actual: session_id.to_string(),
            });
        }

        // Verify exact command binding (character-by-character)
        if stored.request.command != command {
            return Err(ApprovalError::CommandMismatch);
        }

        // Verify token match
        match &stored.authorization_token {
            Some(expected_token) if expected_token == token => {
                // TOKEN VALIDATED: ATOMICALLY CONSUME TOKEN
                stored.request.status = ApprovalStatus::Consumed;
                stored.consumed_at = Some(now);
                stored.authorization_token = None; // Invalidate token immediately
                Ok(stored.request.clone())
            }
            _ => Err(ApprovalError::InvalidToken),
        }
    }

    /// Query request status
    pub fn get_request(&self, request_id: &str) -> Option<ApprovalRequest> {
        let mut lock = self.requests.lock().unwrap();
        let stored = lock.get_mut(request_id)?;

        // Auto-expire
        if Utc::now() > stored.request.expires_at
            && stored.request.status == ApprovalStatus::Pending
        {
            stored.request.status = ApprovalStatus::Expired;
            stored.authorization_token = None;
        }

        Some(stored.request.clone())
    }

    /// Query pending requests, optionally filtered by session
    pub fn get_pending(&self, session_id: Option<&str>) -> Vec<ApprovalRequest> {
        let mut lock = self.requests.lock().unwrap();
        let now = Utc::now();
        let mut pending = Vec::new();

        for stored in lock.values_mut() {
            if now > stored.request.expires_at && stored.request.status == ApprovalStatus::Pending {
                stored.request.status = ApprovalStatus::Expired;
                stored.authorization_token = None;
            }

            if stored.request.status == ApprovalStatus::Pending {
                if let Some(sid) = session_id {
                    if stored.request.session_id == sid {
                        pending.push(stored.request.clone());
                    }
                } else {
                    pending.push(stored.request.clone());
                }
            }
        }

        pending
    }

    /// Invalidates pending and approved requests targeting newly confirmed malicious packages.
    /// Crucially destroys unconsumed single-use authorization tokens so approval cannot be replayed.
    pub fn invalidate_for_malicious_packages(
        &self,
        malicious_pkgs: &HashSet<(PackageEcosystem, String)>,
    ) -> Vec<String> {
        let mut lock = self.requests.lock().unwrap();
        let mut invalidated = Vec::new();

        for stored in lock.values_mut() {
            // Only Pending or Approved (unconsumed) requests can be invalidated
            if stored.request.status != ApprovalStatus::Pending
                && stored.request.status != ApprovalStatus::Approved
            {
                continue;
            }

            let mut matches_malicious = false;

            // Check if package details explicitly contain a malicious package
            if let Some(ref details) = stored.request.package_details {
                for finding in &details.findings {
                    if malicious_pkgs
                        .contains(&(details.package_manager, finding.package_name.to_lowercase()))
                    {
                        matches_malicious = true;
                        break;
                    }
                }
            }

            // Also check command text for package names
            if !matches_malicious {
                for (_, mal_name) in malicious_pkgs {
                    if stored.request.command.to_lowercase().contains(mal_name) {
                        matches_malicious = true;
                        break;
                    }
                }
            }

            if matches_malicious {
                stored.request.status = ApprovalStatus::Denied;
                stored.request.decision_reason = Some(
                    "Invalidated: package identified as confirmed malicious by newly activated advisory intelligence"
                        .to_string(),
                );
                // DESTROY TOKEN IMMEDIATELY TO PREVENT REPLAY
                stored.authorization_token = None;
                invalidated.push(stored.request.request_id.clone());
            }
        }

        invalidated
    }
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self::new(60)
    }
}
