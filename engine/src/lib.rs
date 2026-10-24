// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod analysis;
pub mod audit;
pub mod auth;
pub mod gate;
pub mod integrity;
pub mod ipc;
pub mod model;
pub mod package;
pub mod policy;

#[cfg(test)]
mod ipc_auth_tests;

pub use analysis::CommandAnalyzer;
pub use audit::AuditLog;
pub use auth::{
    get_peer_credentials, IpcAuthPolicy, OperationTier, PeerAccessRule, PeerCredentials,
    RollbackAuthError, RollbackAuthorization, RollbackAuthorizationManager,
};
pub use gate::{
    ControlledShell, ExecutionBackend, ExecutionError, ExecutionGate, GateEngineClient,
    MockExecutionBackend, OsExecutionBackend,
};
pub use integrity::{compute_file_sha256, verify_manifest, IntegrityStatus};
pub use ipc::IpcServer;
pub use model::*;
pub use package::{
    AdvisoryBundle, AdvisoryUpdater, BaselineStore, DriftDetector, PackageSecurityAssessor,
    PackageSecurityConfig, PostOperationVerifier, TrustedKeyStore, WorkspaceMonitor,
};
pub use policy::PolicyEngine;
