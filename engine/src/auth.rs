// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(target_os = "linux")]
pub fn get_peer_credentials(stream: &UnixStream) -> std::io::Result<PeerCredentials> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len as *mut _ as *mut libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        pid: ucred.pid,
        uid: ucred.uid,
        gid: ucred.gid,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn get_peer_credentials(_stream: &UnixStream) -> std::io::Result<PeerCredentials> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let pid = unsafe { libc::getpid() };
    Ok(PeerCredentials { pid, uid, gid })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAccessRule {
    SameUserOnly,
    ExplicitUids(HashSet<u32>),
    AllowAllSameMachineWithRestrictions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationTier {
    ReadOnly,
    Standard,
    Privileged,
    Rollback,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    PeerNotAllowed(u32),
    PrivilegeRequired { method: String, peer_uid: u32 },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerNotAllowed(uid) => {
                write!(
                    f,
                    "Peer UID {} is not permitted to connect to this engine",
                    uid
                )
            }
            Self::PrivilegeRequired { method, peer_uid } => {
                write!(
                    f,
                    "Operation '{}' requires privileged authorization; peer UID {} lacks required privilege",
                    method, peer_uid
                )
            }
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Debug, Clone)]
pub struct IpcAuthPolicy {
    pub rule: PeerAccessRule,
    pub owner_uid: u32,
    pub allow_read_only_for_other_users: bool,
}

impl Default for IpcAuthPolicy {
    fn default() -> Self {
        let owner_uid = unsafe { libc::geteuid() };
        Self {
            rule: PeerAccessRule::SameUserOnly,
            owner_uid,
            allow_read_only_for_other_users: false,
        }
    }
}

impl IpcAuthPolicy {
    pub fn new(
        rule: PeerAccessRule,
        owner_uid: u32,
        allow_read_only_for_other_users: bool,
    ) -> Self {
        Self {
            rule,
            owner_uid,
            allow_read_only_for_other_users,
        }
    }

    pub fn same_user_only() -> Self {
        Self::default()
    }

    pub fn is_peer_allowed(&self, peer: &PeerCredentials) -> bool {
        match &self.rule {
            PeerAccessRule::SameUserOnly => peer.uid == self.owner_uid,
            PeerAccessRule::ExplicitUids(uids) => uids.contains(&peer.uid),
            PeerAccessRule::AllowAllSameMachineWithRestrictions => true,
        }
    }

    pub fn get_operation_tier(method: &str) -> OperationTier {
        match method {
            "engine.handshake"
            | "engine.get_health"
            | "engine.get_integrity"
            | "command.analyze"
            | "approval.get_pending"
            | "event.get_recent"
            | "event.get_details"
            | "audit.verify"
            | "package.get_baseline"
            | "package.detect_drift"
            | "package.get_advisory_status"
            | "package.inspect_advisory_bundle" => OperationTier::ReadOnly,

            "gate.evaluate"
            | "gate.record_outcome"
            | "event.submit"
            | "package.create_baseline"
            | "package.verify_post_operation"
            | "package.monitor_workspace" => OperationTier::Standard,

            "approval.decide"
            | "gate.dispatch_authorized"
            | "package.import_advisory_bundle"
            | "package.request_rollback_authorization"
            | "engine.shutdown" => OperationTier::Privileged,

            _ => OperationTier::Privileged,
        }
    }

    pub fn authorize_operation(
        &self,
        method: &str,
        peer: &PeerCredentials,
    ) -> Result<(), AuthError> {
        if !self.is_peer_allowed(peer) {
            return Err(AuthError::PeerNotAllowed(peer.uid));
        }

        let tier = Self::get_operation_tier(method);

        // Owner UID has full access to all operation tiers
        if peer.uid == self.owner_uid {
            return Ok(());
        }

        // For non-owner peers:
        match tier {
            OperationTier::ReadOnly => {
                if self.allow_read_only_for_other_users {
                    Ok(())
                } else {
                    Err(AuthError::PrivilegeRequired {
                        method: method.to_string(),
                        peer_uid: peer.uid,
                    })
                }
            }
            OperationTier::Standard | OperationTier::Privileged | OperationTier::Rollback => {
                Err(AuthError::PrivilegeRequired {
                    method: method.to_string(),
                    peer_uid: peer.uid,
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RollbackAuthorization {
    pub token: String,
    pub authorized_peer_uid: u32,
    pub target_version: String,
    pub bundle_payload_digest: String,
    pub reason: String,
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RollbackAuthError {
    TokenNotFound,
    AlreadyConsumed,
    Expired,
    PeerUidMismatch { expected: u32, actual: u32 },
    TargetVersionMismatch { expected: String, actual: String },
    PayloadDigestMismatch,
    InvalidReason(String),
    InvalidConfirmationPhrase,
}

impl std::fmt::Display for RollbackAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenNotFound => write!(f, "Rollback authorization token not found or invalid"),
            Self::AlreadyConsumed => write!(
                f,
                "Rollback authorization token has already been consumed (replay prevented)"
            ),
            Self::Expired => write!(f, "Rollback authorization token has expired"),
            Self::PeerUidMismatch { expected, actual } => write!(
                f,
                "Peer UID mismatch: token authorized for UID {} but presented by UID {}",
                expected, actual
            ),
            Self::TargetVersionMismatch { expected, actual } => write!(
                f,
                "Target version mismatch: token authorized for v{} but bundle claims v{}",
                expected, actual
            ),
            Self::PayloadDigestMismatch => write!(
                f,
                "Payload digest mismatch: bundle content does not match authorized digest"
            ),
            Self::InvalidReason(r) => write!(f, "Invalid rollback reason: {}", r),
            Self::InvalidConfirmationPhrase => write!(
                f,
                "Invalid confirmation phrase (must match 'CONFIRM_ADVISORY_ROLLBACK')"
            ),
        }
    }
}

impl std::error::Error for RollbackAuthError {}

pub struct RollbackAuthorizationManager {
    tokens: Mutex<HashMap<String, RollbackAuthorization>>,
}

impl Default for RollbackAuthorizationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RollbackAuthorizationManager {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue_token(
        &self,
        peer_uid: u32,
        target_version: String,
        bundle_payload_digest: String,
        reason: String,
        ttl_seconds: i64,
    ) -> String {
        let token = format!("cyr-rollback-{}-{}", Uuid::new_v4(), Uuid::new_v4());
        let expires_at = Utc::now() + Duration::seconds(ttl_seconds);
        let auth = RollbackAuthorization {
            token: token.clone(),
            authorized_peer_uid: peer_uid,
            target_version,
            bundle_payload_digest,
            reason,
            expires_at,
            consumed: false,
        };
        let mut lock = self.tokens.lock().unwrap();
        lock.insert(token.clone(), auth);
        token
    }

    pub fn consume_token(
        &self,
        token: &str,
        peer_uid: u32,
        target_version: &str,
        bundle_payload_digest: &str,
    ) -> Result<RollbackAuthorization, RollbackAuthError> {
        let mut lock = self.tokens.lock().unwrap();
        let auth = lock
            .get_mut(token)
            .ok_or(RollbackAuthError::TokenNotFound)?;

        if auth.consumed {
            return Err(RollbackAuthError::AlreadyConsumed);
        }

        if Utc::now() > auth.expires_at {
            return Err(RollbackAuthError::Expired);
        }

        if auth.authorized_peer_uid != peer_uid {
            return Err(RollbackAuthError::PeerUidMismatch {
                expected: auth.authorized_peer_uid,
                actual: peer_uid,
            });
        }

        if auth.target_version != target_version {
            return Err(RollbackAuthError::TargetVersionMismatch {
                expected: auth.target_version.clone(),
                actual: target_version.to_string(),
            });
        }

        if auth.bundle_payload_digest != bundle_payload_digest {
            return Err(RollbackAuthError::PayloadDigestMismatch);
        }

        auth.consumed = true;
        Ok(auth.clone())
    }
}

#[derive(Debug)]
pub enum SocketSecurityError {
    Io(std::io::Error),
    SymlinkForbidden(String),
    InsecureParentPermissions(String),
    ParentNotOwnedByCurrentUser(String),
    StaleSocketNotASocket(String),
    StaleSocketOwnedByOtherUser(String),
    SocketPermissionsVerificationFailed(String),
}

impl std::fmt::Display for SocketSecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error in socket security check: {}", e),
            Self::SymlinkForbidden(msg) => write!(f, "Symlinks forbidden: {}", msg),
            Self::InsecureParentPermissions(msg) => {
                write!(f, "Insecure directory permissions: {}", msg)
            }
            Self::ParentNotOwnedByCurrentUser(msg) => {
                write!(f, "Parent directory not owned by current user: {}", msg)
            }
            Self::StaleSocketNotASocket(msg) => write!(f, "Stale path is not a socket: {}", msg),
            Self::StaleSocketOwnedByOtherUser(msg) => {
                write!(f, "Stale path owned by other user: {}", msg)
            }
            Self::SocketPermissionsVerificationFailed(msg) => {
                write!(f, "Socket permissions verification failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for SocketSecurityError {}

impl From<std::io::Error> for SocketSecurityError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub fn verify_and_prepare_socket_path(socket_path: &Path) -> Result<(), SocketSecurityError> {
    let current_euid = unsafe { libc::geteuid() };

    // 1. Verify parent directory
    if let Some(parent) = socket_path.parent() {
        match std::fs::symlink_metadata(parent) {
            Ok(parent_meta) => {
                if parent_meta.file_type().is_symlink() {
                    return Err(SocketSecurityError::SymlinkForbidden(format!(
                        "Parent directory '{}' is a symbolic link",
                        parent.display()
                    )));
                }

                let mode = parent_meta.mode();
                if mode & 0o002 != 0 {
                    return Err(SocketSecurityError::InsecureParentPermissions(format!(
                        "Parent directory '{}' is world-writable (mode {:o})",
                        parent.display(),
                        mode
                    )));
                }

                if parent_meta.uid() != current_euid {
                    return Err(SocketSecurityError::ParentNotOwnedByCurrentUser(format!(
                        "Parent directory '{}' is owned by UID {} (expected {})",
                        parent.display(),
                        parent_meta.uid(),
                        current_euid
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(parent)?;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
            Err(e) => return Err(SocketSecurityError::Io(e)),
        }
    }

    // 2. Safely verify existing stale socket path before removing
    if let Ok(meta) = std::fs::symlink_metadata(socket_path) {
        if meta.file_type().is_symlink() {
            return Err(SocketSecurityError::SymlinkForbidden(format!(
                "Path '{}' is a symbolic link",
                socket_path.display()
            )));
        }

        // Must be a socket (S_IFSOCK)
        if meta.mode() & libc::S_IFMT != libc::S_IFSOCK {
            return Err(SocketSecurityError::StaleSocketNotASocket(format!(
                "Path '{}' is not a socket file (mode {:o})",
                socket_path.display(),
                meta.mode()
            )));
        }

        if meta.uid() != current_euid {
            return Err(SocketSecurityError::StaleSocketOwnedByOtherUser(format!(
                "Path '{}' is owned by UID {} (expected {})",
                socket_path.display(),
                meta.uid(),
                current_euid
            )));
        }

        // Test if active
        if UnixStream::connect(socket_path).is_ok() {
            return Err(SocketSecurityError::Io(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!(
                    "Another Cyravell engine instance is already active on socket: {}",
                    socket_path.display()
                ),
            )));
        }

        // Safe stale socket removal
        std::fs::remove_file(socket_path)?;
    }

    Ok(())
}

pub fn verify_bound_socket(socket_path: &Path) -> Result<(), SocketSecurityError> {
    let current_euid = unsafe { libc::geteuid() };
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    let meta = std::fs::symlink_metadata(socket_path)?;
    if meta.file_type().is_symlink() {
        return Err(SocketSecurityError::SymlinkForbidden(format!(
            "Newly bound socket '{}' is a symlink",
            socket_path.display()
        )));
    }

    let mode = meta.mode() & 0o777;
    if mode != 0o600 {
        return Err(SocketSecurityError::SocketPermissionsVerificationFailed(
            format!("Newly bound socket mode is {:o} (expected 0600)", mode),
        ));
    }

    if meta.uid() != current_euid {
        return Err(SocketSecurityError::SocketPermissionsVerificationFailed(
            format!(
                "Newly bound socket owned by UID {} (expected {})",
                meta.uid(),
                current_euid
            ),
        ));
    }

    Ok(())
}
