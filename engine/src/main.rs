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
}

fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("cyravell").join("cyravell.sock")
    } else {
        let uid = unsafe { libc_uid() };
        PathBuf::from(format!("/tmp/cyravell-{}/cyravell.sock", uid))
    }
}

fn default_data_dir() -> PathBuf {
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(data_home).join("cyravell")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local").join("share").join("cyravell")
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
            println!("Verifying cryptographic audit log: {}", audit_file.display());
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
                    eprintln!("Cyravell engine is NOT running on {}: {}", socket_path.display(), e);
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
                    eprintln!("Cyravell engine is NOT running on {}: {}", socket_path.display(), e);
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
    }

    Ok(())
}

