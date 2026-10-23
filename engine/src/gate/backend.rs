// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Debug)]
pub enum ExecutionError {
    Io(std::io::Error),
    SpawnFailed(String),
    TerminatedBySignal(i32),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionError::Io(e) => write!(f, "I/O error during command execution: {}", e),
            ExecutionError::SpawnFailed(s) => write!(f, "Failed to spawn process: {}", s),
            ExecutionError::TerminatedBySignal(sig) => {
                write!(f, "Command terminated by signal: {}", sig)
            }
        }
    }
}

impl std::error::Error for ExecutionError {}

impl From<std::io::Error> for ExecutionError {
    fn from(err: std::io::Error) -> Self {
        ExecutionError::Io(err)
    }
}

/// Abstract interface for command execution.
/// Separates the policy decision gate from the actual execution mechanism.
pub trait ExecutionBackend: Send + Sync {
    fn execute(&self, command: &str, working_dir: Option<&Path>) -> Result<i32, ExecutionError>;
}

/// Real OS execution backend running commands in a subprocess shell.
pub struct OsExecutionBackend {
    shell_path: String,
}

impl OsExecutionBackend {
    pub fn new(shell_path: Option<String>) -> Self {
        Self {
            shell_path: shell_path.unwrap_or_else(|| "/bin/bash".to_string()),
        }
    }
}

impl Default for OsExecutionBackend {
    fn default() -> Self {
        Self::new(None)
    }
}

impl ExecutionBackend for OsExecutionBackend {
    fn execute(&self, command: &str, working_dir: Option<&Path>) -> Result<i32, ExecutionError> {
        let mut cmd = std::process::Command::new(&self.shell_path);
        cmd.arg("-c").arg(command);

        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }

        // Prevent recursive interception by setting marker in child environment
        cmd.env("CYRAVELL_INTERCEPT_DISABLED", "1");
        cmd.env("CYRAVELL_INTERCEPT_PARENT", std::process::id().to_string());

        // Inherit standard I/O so interactive commands and pipes work normally
        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());

        let mut child = cmd
            .spawn()
            .map_err(|e| ExecutionError::SpawnFailed(e.to_string()))?;

        let status = child.wait()?;

        if let Some(code) = status.code() {
            Ok(code)
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = status.signal() {
                    return Err(ExecutionError::TerminatedBySignal(sig));
                }
            }
            Ok(1)
        }
    }
}

/// Mock execution backend for testing.
/// Strictly records all invocations to verify that blocked or pending commands
/// never reach the execution backend.
pub struct MockExecutionBackend {
    invocations: Mutex<Vec<MockInvocation>>,
    default_exit_code: i32,
    call_count: AtomicUsize,
    should_fail_spawn: Mutex<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockInvocation {
    pub command: String,
    pub working_dir: Option<String>,
}

impl MockExecutionBackend {
    pub fn new() -> Self {
        Self {
            invocations: Mutex::new(Vec::new()),
            default_exit_code: 0,
            call_count: AtomicUsize::new(0),
            should_fail_spawn: Mutex::new(None),
        }
    }

    pub fn with_exit_code(code: i32) -> Self {
        Self {
            invocations: Mutex::new(Vec::new()),
            default_exit_code: code,
            call_count: AtomicUsize::new(0),
            should_fail_spawn: Mutex::new(None),
        }
    }

    pub fn with_spawn_failure(error_msg: &str) -> Self {
        Self {
            invocations: Mutex::new(Vec::new()),
            default_exit_code: 1,
            call_count: AtomicUsize::new(0),
            should_fail_spawn: Mutex::new(Some(error_msg.to_string())),
        }
    }

    pub fn invocation_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    pub fn was_called(&self) -> bool {
        self.invocation_count() > 0
    }

    pub fn invocations(&self) -> Vec<MockInvocation> {
        self.invocations.lock().unwrap().clone()
    }

    pub fn commands_executed(&self) -> Vec<String> {
        self.invocations
            .lock()
            .unwrap()
            .iter()
            .map(|i| i.command.clone())
            .collect()
    }

    pub fn clear(&self) {
        self.invocations.lock().unwrap().clear();
        self.call_count.store(0, Ordering::SeqCst);
    }
}

impl Default for MockExecutionBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionBackend for MockExecutionBackend {
    fn execute(&self, command: &str, working_dir: Option<&Path>) -> Result<i32, ExecutionError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let mut list = self.invocations.lock().unwrap();
        list.push(MockInvocation {
            command: command.to_string(),
            working_dir: working_dir.map(|p| p.display().to_string()),
        });

        if let Some(ref err) = *self.should_fail_spawn.lock().unwrap() {
            return Err(ExecutionError::SpawnFailed(err.clone()));
        }

        Ok(self.default_exit_code)
    }
}
