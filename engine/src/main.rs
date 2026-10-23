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
    model::{JsonRpcRequest, JsonRpcResponse},
};

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
    }

    Ok(())
}
