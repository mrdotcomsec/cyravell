// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crate::gate::{ExecutionGate, GateResult};
use crate::model::ExecutionOutcome;

pub struct ControlledShell {
    gate: Arc<ExecutionGate>,
    working_dir: std::sync::Mutex<PathBuf>,
}

impl ControlledShell {
    pub fn new(gate: Arc<ExecutionGate>, initial_dir: Option<PathBuf>) -> Self {
        let dir = initial_dir
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        Self {
            gate,
            working_dir: std::sync::Mutex::new(dir),
        }
    }

    pub fn current_working_dir(&self) -> PathBuf {
        self.working_dir.lock().unwrap().clone()
    }

    pub fn set_working_dir(&self, dir: PathBuf) {
        *self.working_dir.lock().unwrap() = dir;
    }

    /// Run a single command through the execution gate.
    /// Returns the command's exit code, or 126 if prevented/withheld.
    pub fn run_command(&self, command: &str) -> i32 {
        let dir = self.current_working_dir();
        let result = self.gate.execute_gated(command, Some(&dir));
        self.print_gate_notice(&result, command);
        result.exit_code.unwrap_or(126)
    }

    /// Run an interactive controlled shell session.
    pub fn run_interactive(&self) -> io::Result<()> {
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║             Cyravell Controlled Terminal Session             ║");
        println!("║  Execution Gate: ACTIVE (Pre-Execution Interception Active)  ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!("Type 'exit' to terminate session. All commands are evaluated before dispatch.\n");

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        loop {
            let current_dir = self.current_working_dir();
            let dir_display = current_dir
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| current_dir.display().to_string());

            print!("cyravell [{}]> ", dir_display);
            stdout.flush()?;

            let mut line = String::new();
            let bytes = stdin.lock().read_line(&mut line)?;
            if bytes == 0 {
                // EOF (Ctrl+D)
                println!("\nSession terminated.");
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed == "exit" || trimmed == "quit" {
                println!("Exiting Cyravell controlled session.");
                break;
            }

            // Handle shell built-in cd
            if trimmed == "cd" || trimmed.starts_with("cd ") {
                self.handle_cd(trimmed);
                continue;
            }

            // Dispatch command through the Execution Gate
            let result = self.gate.execute_gated(trimmed, Some(&current_dir));
            self.print_gate_notice(&result, trimmed);
        }

        Ok(())
    }

    fn handle_cd(&self, cmd: &str) {
        let target = cmd.strip_prefix("cd").unwrap().trim();
        let target_path = if target.is_empty() || target == "~" {
            std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
        } else {
            let cur = self.current_working_dir();
            cur.join(target)
        };

        match std::fs::canonicalize(&target_path) {
            Ok(canon) => {
                if canon.is_dir() {
                    self.set_working_dir(canon);
                } else {
                    eprintln!("cd: not a directory: {}", target);
                }
            }
            Err(e) => {
                eprintln!("cd: {}: {}", target, e);
            }
        }
    }

    fn print_gate_notice(&self, result: &GateResult, command: &str) {
        match result.outcome {
            ExecutionOutcome::Dispatched => {
                // Command executed normally, no security warning needed
            }
            ExecutionOutcome::BlockedByPolicy => {
                eprintln!("\n┌─────────────────────────────────────────────────────────────┐");
                eprintln!("│ [CYRAVELL EXECUTION GATE] COMMAND BLOCKED                   │");
                eprintln!("└─────────────────────────────────────────────────────────────┘");
                eprintln!("  Command: {}", command);
                eprintln!("  Reason:  {}", result.reason);
                eprintln!("  Rules:   {:?}", result.matched_rules);
                eprintln!("  Action:  PREVENTED DISPATCH (Execution backend not called)");
                if let Some(ref impact) = result.potential_impact {
                    eprintln!("  Impact:  {}", impact);
                }
                eprintln!();
            }
            ExecutionOutcome::PendingApproval => {
                eprintln!("\n┌─────────────────────────────────────────────────────────────┐");
                eprintln!("│ [CYRAVELL EXECUTION GATE] APPROVAL REQUIRED                 │");
                eprintln!("└─────────────────────────────────────────────────────────────┘");
                eprintln!("  Command: {}", command);
                eprintln!("  Reason:  {}", result.reason);
                eprintln!("  Rules:   {:?}", result.matched_rules);
                eprintln!("  Action:  WITHHELD (Interactive approval workflow is Phase 2.3)");
                eprintln!("  Status:  Execution prevented until explicit approval capability");
                if let Some(ref impact) = result.potential_impact {
                    eprintln!("  Impact:  {}", impact);
                }
                eprintln!();
            }
            ExecutionOutcome::FailedClosed => {
                eprintln!("\n┌─────────────────────────────────────────────────────────────┐");
                eprintln!("│ [CYRAVELL EXECUTION GATE] FAIL-CLOSED ENFORCED              │");
                eprintln!("└─────────────────────────────────────────────────────────────┘");
                eprintln!("  Command: {}", command);
                eprintln!("  Reason:  {}", result.reason);
                eprintln!("  Action:  DISPATCH DENIED (Engine offline or analysis failed)");
                eprintln!(
                    "  Status:  Fail-closed policy protects system from unmonitored commands"
                );
                eprintln!();
            }
            ExecutionOutcome::ExecutionFailed => {
                eprintln!(
                    "[CYRAVELL EXECUTION GATE] Dispatch error: {}",
                    result.reason
                );
            }
        }
    }
}
