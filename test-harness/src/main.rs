// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use chrono::Utc;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use tempfile::tempdir;
use uuid::Uuid;

use cyravell_engine::{
    audit::AuditLog,
    model::{
        EnforcementCapability, EventPayload, EventSubmitParams, ExecutionStatus,
        JsonRpcRequest, JsonRpcResponse, Origin, SecurityEvent, Severity,
    },
};

#[derive(Parser)]
#[command(name = "cyravell-test-harness")]
#[command(author = "Cyravell Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Synthetic event generator and validation harness for Cyravell")]
struct Cli {
    #[arg(short, long)]
    socket_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Submit a synthetic destructive command event (never executed)
    SubmitDestructive {
        #[arg(default_value = "rm -rf /")]
        command: String,
    },
    /// Submit a synthetic credential access event
    SubmitCredential {
        #[arg(default_value = "cat ~/.ssh/id_rsa")]
        command: String,
    },
    /// Submit a synthetic benign event
    SubmitBenign {
        #[arg(default_value = "cargo check")]
        command: String,
    },
    /// Test invalid schema version rejection
    TestInvalidSchema,
    /// Test oversized payload (> 1MB) rejection
    TestOversizedPayload,
    /// Test audit log tamper detection on an isolated disposable log
    TestTamperDetection,
    /// Run comprehensive automated integration test suite
    RunSuite,
}

fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("cyravell").join("cyravell.sock")
    } else {
        let uid = unsafe { libc_uid() };
        PathBuf::from(format!("/tmp/cyravell-{}/cyravell.sock", uid))
    }
}

unsafe fn libc_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    getuid()
}

fn send_rpc(socket_path: &PathBuf, method: &str, params: Option<serde_json::Value>) -> Result<JsonRpcResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: serde_json::json!(Uuid::new_v4().to_string()),
        method: method.to_string(),
        params,
    };

    let req_bytes = serde_json::to_vec(&req)?;
    stream.write_all(&req_bytes)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let resp: JsonRpcResponse = serde_json::from_str(&line)?;
    Ok(resp)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let socket_path = cli.socket_path.unwrap_or_else(default_socket_path);

    match cli.command {
        Commands::SubmitDestructive { command } => {
            let event = SecurityEvent {
                id: format!("evt-sim-{}", &Uuid::new_v4().to_string()[..8]),
                schema_version: 1,
                timestamp: Utc::now(),
                event_type: cyravell_engine::model::EventType::TerminalCommand,
                source_adapter: "test-harness".to_string(),
                origin: Origin::Simulated,
                execution_status: ExecutionStatus::Simulated,
                enforcement_capability: EnforcementCapability::None,
                payload: EventPayload {
                    command: Some(command.clone()),
                    working_directory: Some("/test/sandbox".to_string()),
                    target_paths: vec!["/".to_string()],
                    environment_keys: vec!["PATH".to_string()],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("simulation".to_string(), "true".to_string());
                        m.insert("note".to_string(), "Synthetic destructive test. NEVER EXECUTED.".to_string());
                        m
                    },
                },
            };

            println!("Submitting synthetic event to Cyravell engine: {}", event.id);
            println!("Simulated Command: {}", command);
            let resp = send_rpc(&socket_path, "event.submit", Some(serde_json::to_value(EventSubmitParams { event })?))?;

            if let Some(res) = resp.result {
                println!("Response:\n{}", serde_json::to_string_pretty(&res)?);
            } else if let Some(err) = resp.error {
                eprintln!("Engine Error: {:?}", err);
            }
        }

        Commands::SubmitCredential { command } => {
            let event = SecurityEvent {
                id: format!("evt-cred-{}", &Uuid::new_v4().to_string()[..8]),
                schema_version: 1,
                timestamp: Utc::now(),
                event_type: cyravell_engine::model::EventType::CredentialAccess,
                source_adapter: "test-harness".to_string(),
                origin: Origin::Simulated,
                execution_status: ExecutionStatus::Simulated,
                enforcement_capability: EnforcementCapability::None,
                payload: EventPayload {
                    command: Some(command.clone()),
                    working_directory: Some("/home/user".to_string()),
                    target_paths: vec!["~/.ssh/id_rsa".to_string()],
                    environment_keys: vec![],
                    metadata: HashMap::new(),
                },
            };

            println!("Submitting synthetic credential access event: {}", event.id);
            let resp = send_rpc(&socket_path, "event.submit", Some(serde_json::to_value(EventSubmitParams { event })?))?;
            println!("Result:\n{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::SubmitBenign { command } => {
            let event = SecurityEvent {
                id: format!("evt-benign-{}", &Uuid::new_v4().to_string()[..8]),
                schema_version: 1,
                timestamp: Utc::now(),
                event_type: cyravell_engine::model::EventType::TerminalCommand,
                source_adapter: "test-harness".to_string(),
                origin: Origin::Simulated,
                execution_status: ExecutionStatus::Simulated,
                enforcement_capability: EnforcementCapability::None,
                payload: EventPayload {
                    command: Some(command.clone()),
                    working_directory: Some("/workspace".to_string()),
                    target_paths: vec![],
                    environment_keys: vec![],
                    metadata: HashMap::new(),
                },
            };

            println!("Submitting synthetic benign event: {}", event.id);
            let resp = send_rpc(&socket_path, "event.submit", Some(serde_json::to_value(EventSubmitParams { event })?))?;
            println!("Result:\n{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::TestInvalidSchema => {
            println!("Testing engine rejection of invalid schema version (schema_version = 99)...");
            let raw_event = serde_json::json!({
                "id": "evt-invalid-schema",
                "schema_version": 99,
                "timestamp": Utc::now().to_rfc3339(),
                "event_type": "TERMINAL_COMMAND",
                "source_adapter": "test-harness",
                "origin": "SIMULATED",
                "execution_status": "SIMULATED",
                "enforcement_capability": "NONE",
                "payload": {
                    "command": "echo test"
                }
            });

            let resp = send_rpc(&socket_path, "event.submit", Some(serde_json::json!({ "event": raw_event })))?;
            println!("Response:\n{}", serde_json::to_string_pretty(&resp)?);
            assert!(resp.error.is_some(), "Expected rejection error for unsupported schema version");
            println!("✓ Engine correctly rejected unsupported schema version!");
        }

        Commands::TestOversizedPayload => {
            println!("Testing engine rejection of oversized frame (> 1 MiB)...");
            let mut stream = UnixStream::connect(&socket_path)?;
            let oversized_data = "A".repeat(1024 * 1024 + 100);
            let raw_msg = format!("{{\"jsonrpc\":\"2.0\",\"id\":\"oversized\",\"method\":\"test\",\"params\":\"{}\"}}\n", oversized_data);

            stream.write_all(raw_msg.as_bytes())?;
            stream.flush()?;

            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);

            println!("Response from oversized frame: {}", line.trim());
            assert!(line.contains("Frame size exceeds 1 MiB limit") || line.is_empty(), "Expected frame limit rejection");
            println!("✓ Engine correctly rejected oversized frame!");
        }

        Commands::TestTamperDetection => {
            println!("Testing cryptographic audit log tamper detection on disposable log...");
            let dir = tempdir()?;
            let log_path = dir.path().join("audit_tamper_test.log");

            let audit = AuditLog::open(&log_path)?;
            audit.append("evt-1", "BLOCK", "Synthetic destructive delete", Severity::Critical)?;
            audit.append("evt-2", "ALLOW", "Synthetic compile task", Severity::Low)?;
            audit.append("evt-3", "ALERT", "Synthetic remote script", Severity::High)?;

            let pristine_check = audit.verify();
            assert_eq!(pristine_check.status, "VALID");
            println!("✓ Pristine audit log with 3 records verified successfully.");

            // Tamper with record 2 in the file
            let contents = std::fs::read_to_string(&log_path)?;
            let tampered = contents.replace("Synthetic compile task", "Altered by attacker");
            std::fs::write(&log_path, tampered)?;

            let tamper_check = audit.verify();
            assert_eq!(tamper_check.status, "CORRUPTED");
            assert_eq!(tamper_check.corrupted_sequence, Some(2));
            println!("✓ Tampering detected at sequence 2 as expected: {}", tamper_check.message);
        }

        Commands::RunSuite => {
            println!("══════════════════════════════════════════════════════════════");
            println!("             Cyravell Phase 1 Integration Suite               ");
            println!("══════════════════════════════════════════════════════════════");

            // 1. Handshake
            println!("\n[1/6] Testing engine handshake...");
            let hs_resp = send_rpc(&socket_path, "engine.handshake", Some(serde_json::json!({
                "client_name": "test-harness",
                "client_version": "0.1.0",
                "protocol_version": "1.0"
            })))?;
            assert!(hs_resp.result.is_some(), "Handshake failed");
            println!("  ✓ Handshake successful: {:?}", hs_resp.result.unwrap());

            // 2. Health Check
            println!("\n[2/6] Testing engine health query...");
            let health_resp = send_rpc(&socket_path, "engine.get_health", None)?;
            assert!(health_resp.result.is_some(), "Health check failed");
            println!("  ✓ Health query successful: {:?}", health_resp.result.unwrap());

            // 3. Synthetic Destructive Command Evaluation
            println!("\n[3/6] Testing synthetic destructive command evaluation...");
            let event = SecurityEvent {
                id: format!("evt-sim-{}", &Uuid::new_v4().to_string()[..8]),
                schema_version: 1,
                timestamp: Utc::now(),
                event_type: cyravell_engine::model::EventType::TerminalCommand,
                source_adapter: "test-harness".to_string(),
                origin: Origin::Simulated,
                execution_status: ExecutionStatus::Simulated,
                enforcement_capability: EnforcementCapability::None,
                payload: EventPayload {
                    command: Some("rm -rf /".to_string()),
                    working_directory: Some("/test".to_string()),
                    target_paths: vec!["/".to_string()],
                    environment_keys: vec![],
                    metadata: HashMap::new(),
                },
            };
            let submit_resp = send_rpc(&socket_path, "event.submit", Some(serde_json::to_value(EventSubmitParams { event: event.clone() })?))?;
            let submit_result = submit_resp.result.expect("Event submission failed");
            assert_eq!(submit_result["risk_assessment"]["severity"], "CRITICAL");
            assert_eq!(submit_result["risk_assessment"]["rule_id"], "RULE-TERM-001");
            println!("  ✓ Destructive command correctly assessed as CRITICAL: {}", submit_result["risk_assessment"]["reason"]);

            // 4. Audit Chain Verification
            println!("\n[4/6] Verifying engine audit chain...");
            let audit_resp = send_rpc(&socket_path, "audit.verify", None)?;
            let audit_result = audit_resp.result.expect("Audit verification failed");
            assert_eq!(audit_result["status"], "VALID");
            println!("  ✓ Audit chain valid: total records = {}", audit_result["total_records"]);

            // 5. Query Recent Events
            println!("\n[5/6] Querying recent events feed...");
            let recent_resp = send_rpc(&socket_path, "event.get_recent", Some(serde_json::json!({ "limit": 10 })))?;
            let recent_result = recent_resp.result.expect("Recent events query failed");
            let events_array = recent_result["events"].as_array().expect("Expected array");
            assert!(!events_array.is_empty(), "Recent events should not be empty");
            println!("  ✓ Successfully retrieved {} recent events", events_array.len());

            // 6. Disposable Tamper Test
            println!("\n[6/6] Testing audit tamper detection on disposable log...");
            let dir = tempdir()?;
            let log_path = dir.path().join("suite_tamper.log");
            let audit = AuditLog::open(&log_path)?;
            audit.append("evt-1", "BLOCK", "Initial", Severity::Critical)?;
            audit.append("evt-2", "ALLOW", "Second", Severity::Low)?;
            let contents = std::fs::read_to_string(&log_path)?;
            let tampered = contents.replace("Second", "Malicious Modification");
            std::fs::write(&log_path, tampered)?;
            let check = audit.verify();
            assert_eq!(check.status, "CORRUPTED");
            println!("  ✓ Audit tampering detected immediately at sequence {:?}", check.corrupted_sequence);

            println!("\n══════════════════════════════════════════════════════════════");
            println!("  ALL INTEGRATION TESTS PASSED (6/6)");
            println!("══════════════════════════════════════════════════════════════");
        }
    }

    Ok(())
}

