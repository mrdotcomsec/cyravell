// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use cyravell_engine::{
    audit::AuditLog,
    integrity::verify_manifest,
    ipc::IpcServer,
    model::{
        AdvisoryStatus, BundleImportResult, BundleInspectionResult, JsonRpcRequest,
        JsonRpcResponse, PackageGetAdvisoryStatusResult, PackageImportAdvisoryBundleParams,
        PackageInspectAdvisoryBundleParams, PackageRequestRollbackAuthorizationParams,
        PackageRequestRollbackAuthorizationResult,
    },
    package::{
        AdvisoryBundle, AdvisoryDatabase, AdvisoryUpdater, BaselineStore, PackageSecurityAssessor,
        TrustedKeyStore,
    },
    release::{
        generate_release_manifest, verify_release_package, CyravellReleaseManifest,
        ReleaseKeyStore, ReleaseStatus,
    },
};
use ed25519_dalek::SigningKey;

#[derive(Parser)]
#[command(name = "cyravell-engine")]
#[command(author = "Cyravell Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Deterministic local-first security monitoring engine for AI coding agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short, long, global = true)]
    socket_path: Option<PathBuf>,

    #[arg(short, long, global = true)]
    data_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Cyravell security engine IPC daemon (default)
    Start {
        #[arg(long)]
        manifest_path: Option<PathBuf>,

        #[arg(long)]
        base_dir: Option<PathBuf>,
    },
    /// Verify the cryptographic integrity of an audit log
    VerifyAudit {
        #[arg(short, long)]
        audit_file: PathBuf,
    },
    /// Verify file integrity against a release manifest
    VerifyIntegrity {
        #[arg(short, long)]
        manifest: PathBuf,

        #[arg(short, long)]
        base_dir: PathBuf,
    },
    /// Verify a complete Cyravell release package against release manifest and trusted keys
    VerifyRelease {
        #[arg(short, long)]
        manifest: PathBuf,

        #[arg(short, long)]
        artifacts_dir: PathBuf,

        #[arg(short, long)]
        keys_file: Option<PathBuf>,

        #[arg(long)]
        expected_version: Option<String>,

        #[arg(long)]
        expected_commit: Option<String>,

        /// Allow non-official development/test keys (by default only official release keys are accepted)
        #[arg(long, default_value_t = false)]
        allow_dev_keys: bool,

        #[arg(long)]
        json: bool,
    },
    /// Generate a release manifest by inspecting build deliverables in artifacts directory
    GenerateReleaseManifest {
        #[arg(short, long)]
        artifacts_dir: PathBuf,

        #[arg(short, long)]
        release_version: String,

        #[arg(short, long)]
        commit: String,

        #[arg(short, long)]
        tag: Option<String>,

        #[arg(long, default_value = "x86_64-unknown-linux-gnu")]
        target_platform: String,

        #[arg(long, default_value = "cyravell-sbom.spdx.json")]
        sbom: String,

        #[arg(long, default_value = "official")]
        signing_mode: String,

        #[arg(short, long)]
        output: PathBuf,
    },
    /// Cryptographically sign a release manifest with an Ed25519 signing key
    SignReleaseManifest {
        #[arg(short, long)]
        manifest: PathBuf,

        #[arg(short, long)]
        key_id: String,

        /// 32-byte Ed25519 secret key in hex format (or set CYRAVELL_RELEASE_SIGNING_KEY)
        #[arg(short, long)]
        secret_key_hex: Option<String>,

        #[arg(long, default_value = "official")]
        signing_mode: String,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Query status of a running engine instance
    Status,
    /// Send shutdown signal to a running engine instance
    Stop,
    /// Perform static security analysis on a command string without executing it
    Analyze {
        #[arg(short, long)]
        command: String,

        #[arg(short, long)]
        working_dir: Option<String>,
    },
    /// Launch a Cyravell controlled terminal session with active pre-execution interception
    Shell {
        /// Execute single command and exit (like bash -c)
        #[arg(short = 'c', long)]
        command: Option<String>,

        /// Path to underlying shell (default: /bin/bash)
        #[arg(long)]
        backend_shell: Option<String>,

        /// Whether to fail closed when the security engine is offline
        #[arg(long, default_value_t = true)]
        fail_closed: bool,
    },
    /// Execute a command through the Cyravell pre-execution gate
    Exec {
        #[arg(short, long)]
        command: String,

        #[arg(short, long)]
        working_dir: Option<String>,

        #[arg(long, default_value_t = true)]
        fail_closed: bool,
    },
    /// Evaluate execution gate decision for a command without dispatching
    GateEval {
        #[arg(short, long)]
        command: String,

        #[arg(short, long)]
        working_dir: Option<String>,

        #[arg(long, default_value_t = true)]
        fail_closed: bool,
    },
    /// Manage package security advisories and update intelligence
    Advisory {
        #[command(subcommand)]
        subcommand: AdvisoryCommands,
    },
    /// Securely install or upgrade Cyravell from a verified release directory
    Install {
        /// Path to release directory containing release_manifest.json and deliverables
        #[arg(short, long)]
        release_dir: PathBuf,

        /// Installation prefix (default: /usr/local for root, ~/.local for non-root)
        #[arg(short, long)]
        prefix: Option<PathBuf>,

        /// Install in user mode (~/.local) without requiring root privileges
        #[arg(long, default_value_t = false)]
        user: bool,

        /// Allow non-official development/test keys
        #[arg(long, default_value_t = false)]
        allow_dev_keys: bool,

        /// Allow authorized downgrade to an older release version
        #[arg(long, default_value_t = false)]
        allow_downgrade: bool,

        /// Required operator justification reason for authorized downgrade
        #[arg(long)]
        reason: Option<String>,

        /// Expected release version (e.g. 0.1.0)
        #[arg(long)]
        expected_version: Option<String>,

        /// Expected source git commit SHA
        #[arg(long)]
        expected_commit: Option<String>,

        /// Output report in JSON format
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Rollback to the previous known-good Cyravell installation
    Rollback {
        /// Installation prefix (default: /usr/local for root, ~/.local for non-root)
        #[arg(short, long)]
        prefix: Option<PathBuf>,

        /// User mode installation prefix (~/.local)
        #[arg(long, default_value_t = false)]
        user: bool,

        /// Required operator justification reason for rollback
        #[arg(short, long)]
        reason: String,

        /// Output report in JSON format
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Uninstall Cyravell executables, rules, and installation state
    Uninstall {
        /// Installation prefix (default: /usr/local for root, ~/.local for non-root)
        #[arg(short, long)]
        prefix: Option<PathBuf>,

        /// User mode installation prefix (~/.local)
        #[arg(long, default_value_t = false)]
        user: bool,

        /// Purge all user data, configuration, and audit logs as well
        #[arg(long, default_value_t = false)]
        purge_data: bool,

        /// Optional operator reason
        #[arg(short, long)]
        reason: Option<String>,

        /// Output report in JSON format
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Query the current installation and version state
    InstallStatus {
        /// Installation prefix (default: /usr/local for root, ~/.local for non-root)
        #[arg(short, long)]
        prefix: Option<PathBuf>,

        /// User mode installation prefix (~/.local)
        #[arg(long, default_value_t = false)]
        user: bool,

        /// Output in JSON format
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AdvisoryCommands {
    /// Show current advisory database status
    Status,
    /// Inspect an advisory bundle without importing
    Inspect {
        /// Path to the advisory bundle JSON file
        bundle: PathBuf,
    },
    /// Verify bundle cryptographic signature against trusted keys
    Verify {
        /// Path to the advisory bundle JSON file
        bundle: PathBuf,
        /// Path to trusted keys JSON file (optional)
        #[arg(long)]
        keys: Option<PathBuf>,
    },
    /// Display differences between bundle and active advisory database
    Diff {
        /// Path to the advisory bundle JSON file
        bundle: PathBuf,
    },
    /// Import, validate, and atomically activate an advisory bundle
    Import {
        /// Path to the advisory bundle JSON file
        bundle: PathBuf,
        /// Path to trusted keys JSON file (optional)
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Allow rollback to an older or equal version
        #[arg(long)]
        allow_rollback: bool,
    },
}

fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir)
            .join("cyravell")
            .join("cyravell.sock")
    } else {
        let uid = unsafe { libc_uid() };
        PathBuf::from(format!("/tmp/cyravell-{}/cyravell.sock", uid))
    }
}

fn default_data_dir() -> PathBuf {
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(data_home).join("cyravell")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("cyravell")
    } else {
        PathBuf::from("/tmp/cyravell-data")
    }
}

unsafe fn libc_uid() -> u32 {
    // POSIX getuid
    extern "C" {
        fn getuid() -> u32;
    }
    getuid()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let socket_path = cli.socket_path.unwrap_or_else(default_socket_path);
    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);

    match cli.command.unwrap_or(Commands::Start {
        manifest_path: None,
        base_dir: None,
    }) {
        Commands::Start {
            manifest_path,
            base_dir,
        } => {
            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║              Cyravell Security Engine v0.1.0             ║");
            println!("║          Local-First Deterministic Security Core         ║");
            println!("╚══════════════════════════════════════════════════════════╝");
            println!("Socket path: {}", socket_path.display());
            println!("Data directory: {}", data_dir.display());

            let base = base_dir.unwrap_or_else(|| PathBuf::from("."));
            let server = IpcServer::new(&socket_path, &data_dir, manifest_path, base)?;

            println!("Listening for IPC connections (permissions 0600)...");
            server.run()?;
            println!("Cyravell engine shut down cleanly.");
        }

        Commands::VerifyAudit { audit_file } => {
            println!(
                "Verifying cryptographic audit log: {}",
                audit_file.display()
            );
            let audit = AuditLog::open(&audit_file)?;
            let result = audit.verify();

            println!("Status: {}", result.status);
            println!("Total records verified: {}", result.total_records);
            println!("Genesis hash: {}", result.genesis_hash);
            println!("Latest hash:  {}", result.latest_hash);
            if let Some(corrupted_seq) = result.corrupted_sequence {
                eprintln!("TAMPERING DETECTED at sequence: {}", corrupted_seq);
                eprintln!("Details: {}", result.message);
                std::process::exit(1);
            } else {
                println!("Message: {}", result.message);
            }
        }

        Commands::VerifyIntegrity { manifest, base_dir } => {
            println!("Verifying release integrity: {}", manifest.display());
            let report = verify_manifest(&manifest, &base_dir);

            println!("Status: {:?}", report.status);
            println!("Manifest Version: {}", report.manifest_version);
            println!("Verified Files: {}", report.verified_files_count);
            println!("Authentication: {}", report.authentication_status);
            println!("Details: {}", report.details);

            if !report.mismatched_files.is_empty() {
                eprintln!("Mismatched files:");
                for m in &report.mismatched_files {
                    eprintln!("  - {}", m);
                }
                std::process::exit(1);
            }

            if !report.missing_files.is_empty() {
                eprintln!("Missing files:");
                for m in &report.missing_files {
                    eprintln!("  - {}", m);
                }
                std::process::exit(1);
            }
        }

        Commands::VerifyRelease {
            manifest,
            artifacts_dir,
            keys_file,
            expected_version,
            expected_commit,
            allow_dev_keys,
            json,
        } => {
            let keystore = match keys_file {
                Some(ref kpath) => match ReleaseKeyStore::load_from_path(kpath) {
                    Ok(ks) => ks,
                    Err(e) => {
                        eprintln!(
                            "Failed to load release keys from {}: {}",
                            kpath.display(),
                            e
                        );
                        std::process::exit(1);
                    }
                },
                None => ReleaseKeyStore::load_default(),
            };

            let require_official = !allow_dev_keys;
            let report = verify_release_package(
                &manifest,
                &artifacts_dir,
                &keystore,
                expected_version.as_deref(),
                expected_commit.as_deref(),
                require_official,
            );

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("══════════════════════════════════════════════════════════════");
                println!("             Cyravell Release Package Verification            ");
                println!("══════════════════════════════════════════════════════════════");
                println!("Status:                 {:?}", report.status);
                println!("Product:                {}", report.product_name);
                println!("Release Version:        {}", report.release_version);
                println!("Source Commit:          {}", report.source_commit);
                println!(
                    "Signing Key ID:         {}",
                    report.signing_key_id.as_deref().unwrap_or("none")
                );
                println!(
                    "Publisher:              {}",
                    report.publisher.as_deref().unwrap_or("unauthenticated")
                );
                println!(
                    "Verified Artifacts:     {}",
                    report.verified_artifacts_count
                );
                println!("Details:                {}", report.details);

                if !report.mismatched_artifacts.is_empty() {
                    eprintln!("\nTampered / Mismatched Artifacts:");
                    for m in &report.mismatched_artifacts {
                        eprintln!("  ✗ {}", m);
                    }
                }

                if !report.missing_artifacts.is_empty() {
                    eprintln!("\nMissing Artifacts:");
                    for m in &report.missing_artifacts {
                        eprintln!("  ✗ {}", m);
                    }
                }

                if !report.unlisted_artifacts.is_empty() {
                    println!("\nUnlisted Files in Release Directory (Informational):");
                    for u in &report.unlisted_artifacts {
                        println!("  ? {}", u);
                    }
                }

                if !report.errors.is_empty() {
                    eprintln!("\nVerification Errors:");
                    for e in &report.errors {
                        eprintln!("  ✗ {}", e);
                    }
                }
                println!("══════════════════════════════════════════════════════════════");
            }

            if report.status != ReleaseStatus::Verified {
                std::process::exit(1);
            }
        }

        Commands::GenerateReleaseManifest {
            artifacts_dir,
            release_version,
            commit,
            tag,
            target_platform,
            sbom,
            signing_mode,
            output,
        } => {
            let manifest = match generate_release_manifest(
                &artifacts_dir,
                &release_version,
                &commit,
                tag.as_deref(),
                &target_platform,
                &sbom,
                Some(&signing_mode),
            ) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Failed to generate release manifest: {}", e);
                    std::process::exit(1);
                }
            };

            let json_str = serde_json::to_string_pretty(&manifest)?;
            std::fs::write(&output, json_str)?;
            println!(
                "Successfully generated release manifest: {} ({} artifacts enumerated, mode: '{}')",
                output.display(),
                manifest.artifacts.len(),
                signing_mode
            );
        }

        Commands::SignReleaseManifest {
            manifest,
            key_id,
            secret_key_hex,
            signing_mode,
            output,
        } => {
            let key_hex = match secret_key_hex {
                Some(k) => k,
                None => match std::env::var("CYRAVELL_RELEASE_SIGNING_KEY") {
                    Ok(k) => k,
                    Err(_) => {
                        eprintln!("Error: Secret key must be provided via --secret-key-hex or CYRAVELL_RELEASE_SIGNING_KEY environment variable");
                        std::process::exit(1);
                    }
                },
            };

            let key_bytes = match hex::decode(key_hex.trim()) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Invalid secret key hex encoding: {}", e);
                    std::process::exit(1);
                }
            };

            if key_bytes.len() != 32 {
                eprintln!(
                    "Secret key must be 32 bytes (got {} bytes)",
                    key_bytes.len()
                );
                std::process::exit(1);
            }

            let key_arr: [u8; 32] = match key_bytes.try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    eprintln!("Slice conversion error for secret key");
                    std::process::exit(1);
                }
            };

            let signing_key = SigningKey::from_bytes(&key_arr);

            // Verify key identity against keystore to prevent key ID spoofing
            let keystore = ReleaseKeyStore::load_default();
            if let Some(expected_key) = keystore.get_key(&key_id) {
                let computed_pub = hex::encode(signing_key.verifying_key().to_bytes());
                if computed_pub.to_lowercase() != expected_key.public_key_hex.to_lowercase() {
                    eprintln!(
                        "Error: The provided signing key does not correspond to key ID '{}' (public key mismatch)",
                        key_id
                    );
                    std::process::exit(1);
                }
            } else {
                eprintln!(
                    "Warning: Key ID '{}' is not present in local trusted keystore",
                    key_id
                );
            }

            let content = std::fs::read_to_string(&manifest)?;
            let mut rel_manifest: CyravellReleaseManifest = serde_json::from_str(&content)?;

            rel_manifest.signing_mode = Some(signing_mode);
            rel_manifest.sign(&signing_key, &key_id);

            let out_path = output.unwrap_or(manifest);
            let updated_json = serde_json::to_string_pretty(&rel_manifest)?;
            std::fs::write(&out_path, &updated_json)?;

            // Also write detached signature file
            let sig_file = PathBuf::from(format!("{}.sig", out_path.display()));
            if let Some(ref sig) = rel_manifest.signature {
                std::fs::write(&sig_file, format!("{}\n", sig))?;
            }

            println!(
                "Successfully signed release manifest: {} (Key ID: '{}', Detached signature: {})",
                out_path.display(),
                key_id,
                sig_file.display()
            );
        }

        Commands::Status => {
            let mut stream = match UnixStream::connect(&socket_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "Cyravell engine is NOT running on {}: {}",
                        socket_path.display(),
                        e
                    );
                    std::process::exit(2);
                }
            };

            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: serde_json::json!(1),
                method: "engine.get_health".to_string(),
                params: None,
            };

            let req_bytes = serde_json::to_vec(&req)?;
            stream.write_all(&req_bytes)?;
            stream.write_all(b"\n")?;
            stream.flush()?;

            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line)?;

            let resp: JsonRpcResponse = serde_json::from_str(&line)?;
            if let Some(result) = resp.result {
                println!("Engine Status: {}", serde_json::to_string_pretty(&result)?);
            } else if let Some(err) = resp.error {
                eprintln!("Error querying engine: {:?}", err);
                std::process::exit(1);
            }
        }

        Commands::Stop => {
            let mut stream = match UnixStream::connect(&socket_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "Cyravell engine is NOT running on {}: {}",
                        socket_path.display(),
                        e
                    );
                    std::process::exit(2);
                }
            };

            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: serde_json::json!(1),
                method: "engine.shutdown".to_string(),
                params: None,
            };

            let req_bytes = serde_json::to_vec(&req)?;
            stream.write_all(&req_bytes)?;
            stream.write_all(b"\n")?;
            stream.flush()?;

            println!("Sent shutdown signal to Cyravell engine.");
        }

        Commands::Analyze {
            command,
            working_dir,
        } => {
            println!("Analyzing command: {}", command);
            let policy = cyravell_engine::PolicyEngine::new();
            let assessment = policy.analyze_command_string(&command, working_dir.as_deref());

            println!("Severity:     {:?}", assessment.severity);
            println!("Confidence:   {:?}", assessment.confidence);
            println!("Primary Rule: {}", assessment.rule_id);
            println!("All Matched:  {:?}", assessment.matched_rules);
            println!("Completeness: {:?}", assessment.analysis_completeness);
            println!("Reason:       {}", assessment.reason);
            if let Some(impact) = assessment.potential_impact {
                println!("Impact:       {}", impact);
            }
            println!("Action:       {}", assessment.recommended_action);
            println!("Evidence:");
            for ev in &assessment.evidence {
                println!("  - {}", ev);
            }
        }

        Commands::Shell {
            command,
            backend_shell,
            fail_closed,
        } => {
            let backend =
                std::sync::Arc::new(cyravell_engine::OsExecutionBackend::new(backend_shell));
            let ipc_client = Some(std::sync::Arc::new(cyravell_engine::GateEngineClient::new(
                &socket_path,
            )));
            let in_process_policy = if !fail_closed {
                Some(cyravell_engine::PolicyEngine::new())
            } else {
                None
            };
            let audit_path = data_dir.join("audit.log");
            let in_process_audit = cyravell_engine::AuditLog::open(&audit_path)
                .ok()
                .map(std::sync::Arc::new);

            let gate = std::sync::Arc::new(cyravell_engine::ExecutionGate::new(
                backend,
                ipc_client,
                in_process_policy,
                in_process_audit,
                fail_closed,
            ));

            let shell = cyravell_engine::ControlledShell::new(gate, None);

            if let Some(cmd) = command {
                let code = shell.run_command(&cmd);
                std::process::exit(code);
            } else {
                shell.run_interactive()?;
            }
        }

        Commands::Exec {
            command,
            working_dir,
            fail_closed,
        } => {
            let backend = std::sync::Arc::new(cyravell_engine::OsExecutionBackend::new(None));
            let ipc_client = Some(std::sync::Arc::new(cyravell_engine::GateEngineClient::new(
                &socket_path,
            )));
            let in_process_policy = if !fail_closed {
                Some(cyravell_engine::PolicyEngine::new())
            } else {
                None
            };
            let audit_path = data_dir.join("audit.log");
            let in_process_audit = cyravell_engine::AuditLog::open(&audit_path)
                .ok()
                .map(std::sync::Arc::new);

            let gate = std::sync::Arc::new(cyravell_engine::ExecutionGate::new(
                backend,
                ipc_client,
                in_process_policy,
                in_process_audit,
                fail_closed,
            ));

            let dir = working_dir.map(std::path::PathBuf::from);
            let shell = cyravell_engine::ControlledShell::new(gate, dir);
            let code = shell.run_command(&command);
            std::process::exit(code);
        }

        Commands::GateEval {
            command,
            working_dir,
            fail_closed,
        } => {
            let backend = std::sync::Arc::new(cyravell_engine::MockExecutionBackend::new());
            let ipc_client = Some(std::sync::Arc::new(cyravell_engine::GateEngineClient::new(
                &socket_path,
            )));
            let in_process_policy = if !fail_closed {
                Some(cyravell_engine::PolicyEngine::new())
            } else {
                None
            };
            let gate = cyravell_engine::ExecutionGate::new(
                backend,
                ipc_client,
                in_process_policy,
                None,
                fail_closed,
            );

            let dir = working_dir.as_ref().map(std::path::Path::new);
            let eval = gate.evaluate(&command, dir);

            println!("Gate Decision:     {:?}", eval.decision);
            println!("Execution Outcome: {:?}", eval.outcome);
            println!("Allow Dispatch:    {}", eval.allow_dispatch);
            println!("Severity:          {:?}", eval.risk_assessment.severity);
            println!("Primary Rule:      {}", eval.risk_assessment.rule_id);
            println!(
                "Matched Rules:     {:?}",
                eval.risk_assessment.matched_rules
            );
            println!("Completeness:      {:?}", eval.analysis_completeness);
            println!("Reason:            {}", eval.reason);
            if let Some(ref impact) = eval.risk_assessment.potential_impact {
                println!("Potential Impact:  {}", impact);
            }
        }

        Commands::Advisory { subcommand } => match subcommand {
            AdvisoryCommands::Status => {
                let ipc_res = (|| -> Result<AdvisoryStatus, Box<dyn std::error::Error>> {
                    let mut stream = UnixStream::connect(&socket_path)?;
                    let req = JsonRpcRequest {
                        jsonrpc: "2.0".to_string(),
                        id: serde_json::json!(1),
                        method: "package.get_advisory_status".to_string(),
                        params: None,
                    };
                    stream.write_all(&serde_json::to_vec(&req)?)?;
                    stream.write_all(b"\n")?;
                    stream.flush()?;
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line)?;
                    let resp: JsonRpcResponse = serde_json::from_str(&line)?;
                    if let Some(res) = resp.result {
                        let status_res: PackageGetAdvisoryStatusResult =
                            serde_json::from_value(res)?;
                        return Ok(status_res.status);
                    }
                    Err(format!("{:?}", resp.error).into())
                })();

                let status = match ipc_res {
                    Ok(st) => st,
                    Err(_) => {
                        let db = AdvisoryDatabase::load_default(&data_dir);
                        db.status()
                    }
                };

                println!("╔══════════════════════════════════════════════════════════╗");
                println!("║          Cyravell Package Advisory Intelligence          ║");
                println!("╚══════════════════════════════════════════════════════════╝");
                println!("Active Version:     {}", status.database_version);
                println!(
                    "Source:             {:?} ({})",
                    status.source, status.source_name
                );
                println!(
                    "Publisher:          {}",
                    status.publisher.as_deref().unwrap_or("Cyravell Core")
                );
                println!(
                    "Signing Key ID:     {}",
                    status.key_id.as_deref().unwrap_or("none")
                );
                println!(
                    "Last Updated:       {}",
                    status
                        .last_updated
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| "N/A".to_string())
                );
                println!("Fingerprint:        {}", status.fingerprint);
                println!("Verification:       {}", status.verification_status);
                if let Some(min_ver) = &status.min_cyravell_version {
                    println!("Min Engine Version: {}", min_ver);
                }
                println!("Advisories Total:   {}", status.records_count);
                println!("Malicious Packages: {}", status.malicious_count);
                println!("Vulnerabilities:    {}", status.vulnerabilities_count);
            }

            AdvisoryCommands::Inspect { bundle } => {
                let bundle_path_str = bundle.to_string_lossy().to_string();
                let ipc_res = (|| -> Result<BundleInspectionResult, Box<dyn std::error::Error>> {
                    let mut stream = UnixStream::connect(&socket_path)?;
                    let req = JsonRpcRequest {
                        jsonrpc: "2.0".to_string(),
                        id: serde_json::json!(1),
                        method: "package.inspect_advisory_bundle".to_string(),
                        params: Some(serde_json::to_value(PackageInspectAdvisoryBundleParams {
                            bundle_path: bundle_path_str.clone(),
                            keys_path: None,
                        })?),
                    };
                    stream.write_all(&serde_json::to_vec(&req)?)?;
                    stream.write_all(b"\n")?;
                    stream.flush()?;
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line)?;
                    let resp: JsonRpcResponse = serde_json::from_str(&line)?;
                    if let Some(res) = resp.result {
                        let inspect_res: BundleInspectionResult = serde_json::from_value(res)?;
                        return Ok(inspect_res);
                    }
                    Err(format!("{:?}", resp.error).into())
                })();

                let inspect_res = match ipc_res {
                    Ok(res) => res,
                    Err(_) => {
                        let active_db = AdvisoryDatabase::load_default(&data_dir);
                        let trusted_keys = TrustedKeyStore::load_default();
                        let assessor = std::sync::Arc::new(
                            PackageSecurityAssessor::new(Default::default())
                                .with_advisories(active_db),
                        );
                        let audit_path = data_dir.join("audit.log");
                        let audit =
                            std::sync::Arc::new(AuditLog::open(&audit_path).unwrap_or_else(|_| {
                                let _ = std::fs::create_dir_all(&data_dir);
                                AuditLog::open(&audit_path).expect("failed to open audit log")
                            }));
                        let baseline_store = std::sync::Arc::new(BaselineStore::new());
                        let updater = AdvisoryUpdater::new(
                            assessor,
                            baseline_store,
                            audit,
                            std::sync::Arc::new(trusted_keys),
                            data_dir.join("advisories.json"),
                        );
                        updater.inspect_bundle(&bundle)?
                    }
                };

                println!("╔══════════════════════════════════════════════════════════╗");
                println!("║          Advisory Bundle Inspection Report               ║");
                println!("╚══════════════════════════════════════════════════════════╝");
                println!("Bundle File:        {}", bundle.display());
                println!("Database Version:   {}", inspect_res.database_version);
                println!("Format Version:     {}", inspect_res.bundle_format_version);
                println!("Publisher:          {}", inspect_res.publisher);
                println!("Key ID:             {}", inspect_res.key_id);
                println!(
                    "Created At:         {}",
                    inspect_res.created_at.to_rfc3339()
                );
                println!(
                    "Signature Valid:    {}",
                    if inspect_res.signature_valid {
                        "YES (Authenticated)"
                    } else {
                        "NO (UNAUTHENTICATED)"
                    }
                );
                println!(
                    "Overall Valid:      {}",
                    if inspect_res.is_valid {
                        "YES"
                    } else {
                        "NO (Rejected)"
                    }
                );
                println!("Active Version:     {}", inspect_res.active_version);
                println!(
                    "Rollback Warning:   {}",
                    if inspect_res.would_rollback {
                        "YES (Older or equal version)"
                    } else {
                        "No (Progressive upgrade)"
                    }
                );
                println!("Total Advisories:   {}", inspect_res.records_count);
                println!("Malicious Packages: {}", inspect_res.malicious_count);
                println!("Vulnerabilities:    {}", inspect_res.vulnerabilities_count);
                println!("Added Records:      {}", inspect_res.new_records.len());
                println!("Updated Records:    {}", inspect_res.updated_records.len());
                println!("Removed Records:    {}", inspect_res.removed_records.len());
                println!("\nSummary: {}", inspect_res.summary);
            }

            AdvisoryCommands::Verify { bundle, keys } => {
                let content = std::fs::read_to_string(&bundle)?;
                let parsed_bundle: AdvisoryBundle = serde_json::from_str(&content)?;
                let key_store = if let Some(kpath) = keys {
                    TrustedKeyStore::load_from_path(&kpath)?
                } else {
                    TrustedKeyStore::load_default()
                };

                match parsed_bundle.validate_and_authenticate(&key_store, None, true) {
                    Ok(_) => {
                        println!(
                            "Signature VALID: authenticated by publisher '{}' with key '{}'",
                            parsed_bundle.publisher, parsed_bundle.key_id
                        );
                        println!("Payload digest:  {}", parsed_bundle.payload_digest);
                        println!(
                            "Advisories:      {} records",
                            parsed_bundle.advisories.len()
                        );
                        println!(
                            "Target database: version {}",
                            parsed_bundle.database_version
                        );
                    }
                    Err(e) => {
                        eprintln!("Verification FAILED: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            AdvisoryCommands::Diff { bundle } => {
                let active_db = AdvisoryDatabase::load_default(&data_dir);
                let trusted_keys = TrustedKeyStore::load_default();
                let assessor = std::sync::Arc::new(
                    PackageSecurityAssessor::new(Default::default()).with_advisories(active_db),
                );
                let audit_path = data_dir.join("audit.log");
                let audit = std::sync::Arc::new(AuditLog::open(&audit_path).unwrap_or_else(|_| {
                    let _ = std::fs::create_dir_all(&data_dir);
                    AuditLog::open(&audit_path).expect("failed to open audit log")
                }));
                let baseline_store = std::sync::Arc::new(BaselineStore::new());
                let updater = AdvisoryUpdater::new(
                    assessor,
                    baseline_store,
                    audit,
                    std::sync::Arc::new(trusted_keys),
                    data_dir.join("advisories.json"),
                );
                let inspect_res = updater.inspect_bundle(&bundle)?;

                println!(
                    "Advisory Database Diff (Active v{} -> Candidate v{}):",
                    inspect_res.active_version, inspect_res.database_version
                );
                if inspect_res.new_records.is_empty()
                    && inspect_res.updated_records.is_empty()
                    && inspect_res.removed_records.is_empty()
                {
                    println!("No differences found.");
                } else {
                    for add in &inspect_res.new_records {
                        println!("  + ADD   {}", add);
                    }
                    for upd in &inspect_res.updated_records {
                        println!("  ~ MOD   {}", upd);
                    }
                    for rem in &inspect_res.removed_records {
                        println!("  - DEL   {}", rem);
                    }
                }
            }

            AdvisoryCommands::Import {
                bundle,
                keys: _,
                allow_rollback,
            } => {
                let bundle_path_str = bundle.to_string_lossy().to_string();
                let ipc_res = (|| -> Result<BundleImportResult, Box<dyn std::error::Error>> {
                    let mut stream = UnixStream::connect(&socket_path)?;
                    let mut reader = BufReader::new(stream.try_clone()?);

                    let mut rollback_auth_token = None;
                    if allow_rollback {
                        let content = std::fs::read_to_string(&bundle)?;
                        let val: serde_json::Value = serde_json::from_str(&content)?;
                        let target_version = val
                            .get("database_version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        let req_token = JsonRpcRequest {
                            jsonrpc: "2.0".to_string(),
                            id: serde_json::json!(0),
                            method: "package.request_rollback_authorization".to_string(),
                            params: Some(serde_json::to_value(
                                PackageRequestRollbackAuthorizationParams {
                                    bundle_path: bundle_path_str.clone(),
                                    target_version,
                                    reason:
                                        "CLI administrative advisory rollback requested by operator"
                                            .to_string(),
                                    confirmation_phrase: "CONFIRM_ADVISORY_ROLLBACK".to_string(),
                                },
                            )?),
                        };
                        stream.write_all(&serde_json::to_vec(&req_token)?)?;
                        stream.write_all(b"\n")?;
                        stream.flush()?;
                        let mut line = String::new();
                        reader.read_line(&mut line)?;
                        let resp: JsonRpcResponse = serde_json::from_str(&line)?;
                        if let Some(res) = resp.result {
                            let auth_res: PackageRequestRollbackAuthorizationResult =
                                serde_json::from_value(res)?;
                            rollback_auth_token = Some(auth_res.rollback_authorization_token);
                        } else if let Some(err) = resp.error {
                            return Err(
                                format!("Rollback authorization failed: {}", err.message).into()
                            );
                        }
                    }

                    let req = JsonRpcRequest {
                        jsonrpc: "2.0".to_string(),
                        id: serde_json::json!(1),
                        method: "package.import_advisory_bundle".to_string(),
                        params: Some(serde_json::to_value(PackageImportAdvisoryBundleParams {
                            bundle_path: bundle_path_str.clone(),
                            keys_path: None,
                            allow_rollback,
                            rollback_authorization_token: rollback_auth_token,
                            rollback_confirmation_token: if allow_rollback {
                                Some("CONFIRM_ADVISORY_ROLLBACK".to_string())
                            } else {
                                None
                            },
                        })?),
                    };
                    stream.write_all(&serde_json::to_vec(&req)?)?;
                    stream.write_all(b"\n")?;
                    stream.flush()?;
                    let mut line = String::new();
                    reader.read_line(&mut line)?;
                    let resp: JsonRpcResponse = serde_json::from_str(&line)?;
                    if let Some(res) = resp.result {
                        let import_res: BundleImportResult = serde_json::from_value(res)?;
                        return Ok(import_res);
                    }
                    if let Some(err) = resp.error {
                        return Err(err.message.into());
                    }
                    Err("Empty response from engine".into())
                })();

                let import_res = match ipc_res {
                    Ok(res) => res,
                    Err(e) => {
                        if UnixStream::connect(&socket_path).is_ok() {
                            eprintln!("Import failed: {}", e);
                            std::process::exit(1);
                        }
                        let active_db = AdvisoryDatabase::load_default(&data_dir);
                        let trusted_keys = TrustedKeyStore::load_default();
                        let assessor = std::sync::Arc::new(
                            PackageSecurityAssessor::new(Default::default())
                                .with_advisories(active_db),
                        );
                        let audit_path = data_dir.join("audit.log");
                        let audit =
                            std::sync::Arc::new(AuditLog::open(&audit_path).unwrap_or_else(|_| {
                                let _ = std::fs::create_dir_all(&data_dir);
                                AuditLog::open(&audit_path).expect("failed to open audit log")
                            }));
                        let baseline_store = std::sync::Arc::new(BaselineStore::new());
                        let updater = AdvisoryUpdater::new(
                            assessor,
                            baseline_store,
                            audit,
                            std::sync::Arc::new(trusted_keys),
                            data_dir.join("advisories.json"),
                        );
                        match updater.import_bundle(&bundle, allow_rollback) {
                            Ok(res) => res,
                            Err(err) => {
                                eprintln!("Import failed: {}", err);
                                std::process::exit(1);
                            }
                        }
                    }
                };

                println!("╔══════════════════════════════════════════════════════════╗");
                println!("║          Advisory Bundle Imported Successfully           ║");
                println!("╚══════════════════════════════════════════════════════════╝");
                println!("New Active Version: {}", import_res.new_version);
                println!("Publisher:          {}", import_res.publisher);
                println!("Key ID:             {}", import_res.key_id);
                println!("Total Advisories:   {}", import_res.records_count);
                println!("Malicious Packages: {}", import_res.malicious_count);
                println!("Payload Digest:     {}", import_res.fingerprint);
                println!("Audit Sequence:     #{}", import_res.audit_sequence);
                println!("Rollback Override:  {}", import_res.rollback_authorized);
                println!(
                    "Affected Baselines: {}",
                    import_res.affected_workspaces.len()
                );
                for ws in &import_res.affected_workspaces {
                    println!("  - Workspace re-scanned: {}", ws);
                }
                println!("\nStatus: {}", import_res.message);
            }
        },

        Commands::Install {
            release_dir,
            prefix,
            user,
            allow_dev_keys,
            allow_downgrade,
            reason,
            expected_version,
            expected_commit,
            json,
        } => {
            let is_root = unsafe { libc::geteuid() == 0 };
            let install_prefix = if let Some(p) = prefix {
                p
            } else if user || !is_root {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".local")
            } else {
                PathBuf::from("/usr/local")
            };

            let opts = cyravell_engine::install::InstallOptions {
                release_dir,
                install_prefix,
                is_user_mode: user || !is_root,
                allow_dev_keys,
                allow_downgrade,
                operator_reason: reason,
                expected_version,
                expected_commit,
                skip_post_install_test: false,
                custom_keystore: None,
            };

            match cyravell_engine::install::install_or_update(&opts) {
                Ok(report) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        println!("══════════════════════════════════════════════════════════════");
                        println!("             Cyravell Installation Successful                 ");
                        println!("══════════════════════════════════════════════════════════════");
                        println!("Operation:         {}", report.operation);
                        println!(
                            "Active Version:    {}",
                            report.active_version.as_deref().unwrap_or("unknown")
                        );
                        println!(
                            "Previous Version:  {}",
                            report.previous_version.as_deref().unwrap_or("none")
                        );
                        println!("Prefix:            {}", report.install_prefix.display());
                        println!("Files Installed:   {}", report.files_installed.len());
                        println!("Backup Created:    {}", report.backup_created);
                        println!("Details:           {}", report.details);
                        println!("══════════════════════════════════════════════════════════════");
                    }
                }
                Err(err) => {
                    eprintln!("✗ Installation failed: {}", err);
                    std::process::exit(1);
                }
            }
        }

        Commands::Rollback {
            prefix,
            user,
            reason,
            json,
        } => {
            let is_root = unsafe { libc::geteuid() == 0 };
            let install_prefix = if let Some(p) = prefix {
                p
            } else if user || !is_root {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".local")
            } else {
                PathBuf::from("/usr/local")
            };

            match cyravell_engine::install::rollback_installation(&install_prefix, &reason, false) {
                Ok(report) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        println!("══════════════════════════════════════════════════════════════");
                        println!("               Cyravell Rollback Successful                   ");
                        println!("══════════════════════════════════════════════════════════════");
                        println!(
                            "Active Version:    {}",
                            report.active_version.as_deref().unwrap_or("unknown")
                        );
                        println!(
                            "Rolled Back From:  {}",
                            report.previous_version.as_deref().unwrap_or("none")
                        );
                        println!("Details:           {}", report.details);
                        println!("══════════════════════════════════════════════════════════════");
                    }
                }
                Err(err) => {
                    eprintln!("✗ Rollback failed: {}", err);
                    std::process::exit(1);
                }
            }
        }

        Commands::Uninstall {
            prefix,
            user,
            purge_data,
            reason,
            json,
        } => {
            let is_root = unsafe { libc::geteuid() == 0 };
            let install_prefix = if let Some(p) = prefix {
                p
            } else if user || !is_root {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".local")
            } else {
                PathBuf::from("/usr/local")
            };

            match cyravell_engine::install::uninstall(
                &install_prefix,
                purge_data,
                reason.as_deref(),
            ) {
                Ok(report) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        println!("══════════════════════════════════════════════════════════════");
                        println!("             Cyravell Uninstalled Successfully                ");
                        println!("══════════════════════════════════════════════════════════════");
                        println!("Prefix:            {}", report.install_prefix.display());
                        println!("Details:           {}", report.details);
                        println!("══════════════════════════════════════════════════════════════");
                    }
                }
                Err(err) => {
                    eprintln!("✗ Uninstallation failed: {}", err);
                    std::process::exit(1);
                }
            }
        }

        Commands::InstallStatus { prefix, user, json } => {
            let is_root = unsafe { libc::geteuid() == 0 };
            let install_prefix = if let Some(p) = prefix {
                p
            } else if user || !is_root {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".local")
            } else {
                PathBuf::from("/usr/local")
            };

            let state_file = install_prefix.join("share/cyravell/install_state.json");
            match cyravell_engine::install::InstallState::load_from_path(&state_file) {
                Ok(state) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&state)?);
                    } else {
                        println!("══════════════════════════════════════════════════════════════");
                        println!("                Cyravell Installation Status                 ");
                        println!("══════════════════════════════════════════════════════════════");
                        println!("Active Version:    {}", state.active_version);
                        println!("Source Commit:     {}", state.active_commit);
                        println!(
                            "Source Tag:        {}",
                            state.active_tag.as_deref().unwrap_or("none")
                        );
                        println!("Official Release:  {}", state.is_official);
                        println!("Signing Key ID:    {}", state.signing_key_id);
                        println!("Installed At:      {}", state.installed_at);
                        println!("Installed By UID:  {}", state.installed_by_uid);
                        println!("Prefix:            {}", state.install_prefix.display());
                        println!(
                            "Mode:              {}",
                            if state.is_user_install {
                                "User (~/.local)"
                            } else {
                                "System (/usr/local)"
                            }
                        );
                        println!("High-Water Mark:   {}", state.high_water_version);
                        println!(
                            "Backup Version:    {}",
                            state.backup_version.as_deref().unwrap_or("none")
                        );
                        println!(
                            "Last Operation:    {} ({})",
                            state.last_operation, state.last_operation_timestamp
                        );
                        println!("Tracked Files:     {} files", state.installed_files.len());
                        println!("══════════════════════════════════════════════════════════════");
                    }
                }
                Err(err) => {
                    eprintln!(
                        "No active Cyravell installation found at '{}': {}",
                        install_prefix.display(),
                        err
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
