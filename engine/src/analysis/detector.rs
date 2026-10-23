// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::analysis::ast::{AtomicCommand, CommandChain};
use crate::model::{Confidence, Severity};

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub reason: String,
    pub evidence: Vec<String>,
    pub potential_impact: String,
    pub recommended_action: String,
}

pub struct DetectionEngine;

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, chain: &CommandChain, raw_input: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        // Check each atomic command
        for cmd in chain.all_atomic_commands() {
            self.detect_atomic(cmd, &mut matches);
        }

        // Check pipeline relationships (e.g. curl ... | bash)
        for (pipeline, _) in &chain.pipelines {
            self.detect_pipeline(pipeline, &mut matches);
        }

        // Check global chain patterns (fork bombs, raw signatures, command substitutions)
        self.detect_chain_level(chain, raw_input, &mut matches);

        matches
    }

    fn detect_atomic(&self, cmd: &AtomicCommand, matches: &mut Vec<RuleMatch>) {
        let prog = cmd.program.to_lowercase();
        let prog_base = prog.rsplit('/').next().unwrap_or(&prog);

        // --- Category 1: Destructive Filesystem Operations ---
        if prog_base == "rm" || prog_base == "rmdir" {
            let has_recursive = cmd.arguments.iter().any(|arg| {
                arg.starts_with('-')
                    && (arg.contains('r') || arg.contains('R') || arg == "--recursive")
            });
            let has_force = cmd
                .arguments
                .iter()
                .any(|arg| arg.starts_with('-') && (arg.contains('f') || arg == "--force"));

            if has_recursive {
                let targets: Vec<&str> = cmd
                    .arguments
                    .iter()
                    .filter(|arg| !arg.starts_with('-'))
                    .map(|s| s.as_str())
                    .collect();

                let catastrophic_targets = [
                    "/", "/*", "~", "~/*", "$home", "$home/*", "/etc", "/usr", "/var", "/bin",
                    "/boot", "/dev", "/lib", "/sys", "..", "/home",
                ];

                let mut matched_target = None;
                for target in &targets {
                    let target_lower = target.to_lowercase();
                    for ct in &catastrophic_targets {
                        if target_lower == *ct || target_lower.starts_with(&format!("{}/", ct)) {
                            matched_target = Some(target.to_string());
                            break;
                        }
                    }
                    if matched_target.is_some() {
                        break;
                    }
                }

                if let Some(target) = matched_target {
                    matches.push(RuleMatch {
                        rule_id: "RULE-TERM-001".to_string(),
                        name: "Destructive Recursive Deletion".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        reason: "Potentially catastrophic recursive deletion of root, home, or system path detected".to_string(),
                        evidence: vec![
                            format!("Command: rm (recursive={}, force={})", has_recursive, has_force),
                            format!("Target path: {}", target),
                        ],
                        potential_impact: "Permanent loss of operating system files or developer home directory data".to_string(),
                        recommended_action: "BLOCK_AND_ALERT".to_string(),
                    });
                } else if targets.iter().any(|t| *t == "*" || *t == ".*") {
                    matches.push(RuleMatch {
                        rule_id: "RULE-TERM-005".to_string(),
                        name: "Broad Wildcard Deletion".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        reason: "Recursive deletion targeting broad wildcard pattern detected"
                            .to_string(),
                        evidence: vec![
                            format!("Command: rm (recursive={})", has_recursive),
                            format!("Targets: {:?}", targets),
                        ],
                        potential_impact:
                            "Unintended deletion of all files in current or parent directory"
                                .to_string(),
                        recommended_action: "ALERT_AND_CONFIRM".to_string(),
                    });
                }
            }
        }

        // Disk wiping / formatting utilities
        if prog_base == "mkfs"
            || prog_base.starts_with("mkfs.")
            || prog_base == "wipefs"
            || prog_base == "fdisk"
            || prog_base == "parted"
        {
            matches.push(RuleMatch {
                rule_id: "RULE-TERM-003".to_string(),
                name: "Raw Disk and Filesystem Format".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                reason:
                    "Direct filesystem formatting or partition table manipulation utility invoked"
                        .to_string(),
                evidence: vec![format!("Utility: {}", prog_base)],
                potential_impact:
                    "Destruction of disk partition structures and irrecoverable filesystem loss"
                        .to_string(),
                recommended_action: "BLOCK_AND_ALERT".to_string(),
            });
        }

        // DD writing to device
        if prog_base == "dd" {
            let has_zero_or_urandom = cmd
                .arguments
                .iter()
                .any(|a| a.starts_with("if=/dev/zero") || a.starts_with("if=/dev/urandom"));
            let targets_disk = cmd.arguments.iter().any(|a| {
                a.starts_with("of=/dev/sd")
                    || a.starts_with("of=/dev/nvme")
                    || a.starts_with("of=/dev/vd")
            });

            if has_zero_or_urandom || targets_disk {
                matches.push(RuleMatch {
                    rule_id: "RULE-TERM-003".to_string(),
                    name: "Raw Disk Wiping via DD".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    reason: "Low-level block device overwriting detected via dd utility"
                        .to_string(),
                    evidence: vec![format!("Arguments: {:?}", cmd.arguments)],
                    potential_impact: "Direct raw sector overwrite destroying storage volumes"
                        .to_string(),
                    recommended_action: "BLOCK_AND_ALERT".to_string(),
                });
            }
        }

        // --- Category 2: Privilege and Security Changes ---
        if prog_base == "sudo" || prog_base == "su" || prog_base == "pkexec" || prog_base == "doas"
        {
            let is_interactive_root = cmd.arguments.is_empty()
                || cmd
                    .arguments
                    .iter()
                    .any(|a| a == "su" || a == "-i" || a == "-s" || a == "bash" || a == "sh");

            if is_interactive_root {
                matches.push(RuleMatch {
                    rule_id: "RULE-PRIV-001".to_string(),
                    name: "Unrestricted Privilege Escalation Request".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    reason: "Interactive root shell or unrestricted privilege escalation requested"
                        .to_string(),
                    evidence: vec![format!("Elevator: {} {:?}", prog_base, cmd.arguments)],
                    potential_impact:
                        "Agent acquires full root privileges outside developer sandbox".to_string(),
                    recommended_action: "ALERT_AND_CONFIRM".to_string(),
                });
            }

            // If sudo executes an inner command, analyze inner command
            if !cmd.arguments.is_empty() {
                let inner_prog = &cmd.arguments[0];
                if !inner_prog.starts_with('-') {
                    let mut inner_cmd = AtomicCommand::new();
                    inner_cmd.program = inner_prog.clone();
                    inner_cmd.arguments = cmd.arguments[1..].to_vec();
                    self.detect_atomic(&inner_cmd, matches);
                }
            }
        }

        // Chmod / Chown dangerous permissions
        if prog_base == "chmod" {
            let is_777 = cmd
                .arguments
                .iter()
                .any(|a| a == "777" || a == "0777" || a == "a+rwx" || a == "+s" || a == "u+s");
            let is_recursive = cmd
                .arguments
                .iter()
                .any(|a| a == "-R" || a == "--recursive");

            if is_777 {
                matches.push(RuleMatch {
                    rule_id: "RULE-PRIV-002".to_string(),
                    name: "Dangerous Global Permission Modification".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    reason: "Global world-writable permissions (777) or SUID bit application detected".to_string(),
                    evidence: vec![format!("Arguments: {:?} (recursive={})", cmd.arguments, is_recursive)],
                    potential_impact: "Allows arbitrary local processes to tamper with sensitive files or escalate privileges".to_string(),
                    recommended_action: "ALERT_AND_CONFIRM".to_string(),
                });
            }
        }

        // Security control deactivation (ufw, iptables, setenforce, auditd)
        if prog_base == "setenforce" && cmd.arguments.iter().any(|a| a == "0" || a == "Permissive")
        {
            matches.push(RuleMatch {
                rule_id: "RULE-SEC-001".to_string(),
                name: "Security Control Deactivation".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                reason: "SELinux enforcement mode disabled".to_string(),
                evidence: vec!["setenforce 0".to_string()],
                potential_impact: "Kernel Mandatory Access Control disabled".to_string(),
                recommended_action: "BLOCK_AND_ALERT".to_string(),
            });
        }

        if (prog_base == "ufw" && cmd.arguments.iter().any(|a| a == "disable" || a == "reset"))
            || (prog_base == "iptables"
                && cmd.arguments.iter().any(|a| a == "-F" || a == "--flush"))
        {
            matches.push(RuleMatch {
                rule_id: "RULE-SEC-001".to_string(),
                name: "Firewall Control Deactivation".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                reason: "Local firewall protections flushed or disabled".to_string(),
                evidence: vec![format!("Command: {} {:?}", prog_base, cmd.arguments)],
                potential_impact:
                    "Host network boundary exposed to unauthenticated inbound connections"
                        .to_string(),
                recommended_action: "BLOCK_AND_ALERT".to_string(),
            });
        }

        // --- Category 3: Credential and Secret Access ---
        let sensitive_file_patterns = [
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/id_ecdsa",
            ".ssh/id_dsa",
            ".ssh/authorized_keys",
            ".aws/credentials",
            ".aws/config",
            ".gnupg",
            "/etc/shadow",
            "/etc/gshadow",
            ".kube/config",
            ".docker/config.json",
            ".netrc",
            "id_rsa",
            "id_ed25519",
        ];

        let inspection_tools = [
            "cat", "head", "tail", "less", "more", "grep", "awk", "cp", "base64", "xxd",
        ];
        let is_inspection = inspection_tools.contains(&prog_base);

        for arg in &cmd.arguments {
            let lower_arg = arg.to_lowercase();
            for pattern in &sensitive_file_patterns {
                if lower_arg.contains(pattern) && is_inspection {
                    matches.push(RuleMatch {
                        rule_id: "RULE-CRED-001".to_string(),
                        name: "Direct Private Credential Access".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        reason: "Attempt to read or inspect private keys, shadow file, or credential vaults".to_string(),
                        evidence: vec![
                            format!("Tool: {}", prog_base),
                            format!("Target path: {}", arg),
                        ],
                        potential_impact: "Compromise of SSH private identity keys, cloud credentials, or password hashes".to_string(),
                        recommended_action: "BLOCK_AND_ALERT".to_string(),
                    });
                    break;
                }
            }
        }

        // Secret variable dumping (printenv > exfil.txt)
        if prog_base == "printenv" || prog_base == "env" {
            let has_redirect = !cmd.redirections.is_empty();
            if has_redirect {
                matches.push(RuleMatch {
                    rule_id: "RULE-CRED-002".to_string(),
                    name: "Environment and Secret Variable Dumping".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    reason: "Environment variables dumped to file or redirection stream".to_string(),
                    evidence: vec![format!("Redirection target: {:?}", cmd.redirections[0].target)],
                    potential_impact: "Exposes active API keys, session secrets, and database credentials in environment".to_string(),
                    recommended_action: "ALERT_AND_CONFIRM".to_string(),
                });
            }
        }

        // --- Category 5: Persistence and System Modification ---
        if prog_base == "crontab" {
            let has_edit = cmd
                .arguments
                .iter()
                .any(|a| a == "-e" || a == "-r" || !a.starts_with('-'));
            if has_edit {
                matches.push(RuleMatch {
                    rule_id: "RULE-PERS-001".to_string(),
                    name: "Scheduled Task Persistence Modification".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    reason: "Crontab scheduled task configuration modified".to_string(),
                    evidence: vec![format!("crontab arguments: {:?}", cmd.arguments)],
                    potential_impact:
                        "Installs recurring automated background execution surviving process death"
                            .to_string(),
                    recommended_action: "ALERT_AND_CONFIRM".to_string(),
                });
            }
        }

        let startup_files = [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            "/etc/profile",
            "/etc/rc.local",
        ];
        for redir in &cmd.redirections {
            let target_lower = redir.target.to_lowercase();
            for sf in &startup_files {
                if target_lower.contains(sf) {
                    matches.push(RuleMatch {
                        rule_id: "RULE-PERS-001".to_string(),
                        name: "Shell Profile Persistence Modification".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        reason: "Redirection modifying user or system shell startup script".to_string(),
                        evidence: vec![format!("Target file: {}", redir.target)],
                        potential_impact: "Injects commands that run automatically whenever a developer opens a terminal".to_string(),
                        recommended_action: "ALERT_AND_CONFIRM".to_string(),
                    });
                }
            }
        }

        // --- Category 6: Network and Data Transfer Behavior ---
        if prog_base == "nc" || prog_base == "netcat" || prog_base == "ncat" || prog_base == "socat"
        {
            let has_exec = cmd
                .arguments
                .iter()
                .any(|a| a == "-e" || a == "-c" || a.starts_with("exec:"));
            if has_exec {
                matches.push(RuleMatch {
                    rule_id: "RULE-NET-001".to_string(),
                    name: "Reverse Shell or Network Execution Pipe".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    reason: "Network utility invoked with execution flag (-e / exec)".to_string(),
                    evidence: vec![format!("Command: {} {:?}", prog_base, cmd.arguments)],
                    potential_impact: "Opens a reverse shell granting interactive remote access to developer machine".to_string(),
                    recommended_action: "BLOCK_AND_ALERT".to_string(),
                });
            }
        }

        if prog_base == "curl" || prog_base == "wget" {
            let mut posts_credential = false;
            for (i, a) in cmd.arguments.iter().enumerate() {
                let lower = a.to_lowercase();
                let is_data_flag = lower == "-d"
                    || lower == "--data"
                    || lower == "--data-binary"
                    || lower == "-t"
                    || lower == "--upload-file";
                let target = if is_data_flag && i + 1 < cmd.arguments.len() {
                    cmd.arguments[i + 1].to_lowercase()
                } else if lower.starts_with("-d@")
                    || lower.starts_with("--data-binary=@")
                    || lower.starts_with("-t")
                {
                    lower.clone()
                } else {
                    String::new()
                };

                if !target.is_empty() && sensitive_file_patterns.iter().any(|p| target.contains(p))
                {
                    posts_credential = true;
                    break;
                }
            }

            if posts_credential {
                matches.push(RuleMatch {
                    rule_id: "RULE-NET-002".to_string(),
                    name: "Credential Exfiltration via Remote POST".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    reason: "Network utility configured to upload local private key or credential file to remote endpoint".to_string(),
                    evidence: vec![format!("Arguments: {:?}", cmd.arguments)],
                    potential_impact: "Direct exfiltration of developer secrets to remote attacker".to_string(),
                    recommended_action: "BLOCK_AND_ALERT".to_string(),
                });
            }
        }
    }

    fn detect_pipeline(
        &self,
        pipeline: &crate::analysis::ast::Pipeline,
        matches: &mut Vec<RuleMatch>,
    ) {
        if pipeline.commands.len() < 2 {
            return;
        }

        let download_tools = ["curl", "wget", "fetch", "http"];
        let interpreters = [
            "sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby", "node",
        ];

        for i in 0..pipeline.commands.len() - 1 {
            let left = &pipeline.commands[i];
            let right = &pipeline.commands[i + 1];

            let left_prog = left
                .program
                .rsplit('/')
                .next()
                .unwrap_or(&left.program)
                .to_lowercase();
            let right_prog = right
                .program
                .rsplit('/')
                .next()
                .unwrap_or(&right.program)
                .to_lowercase();

            // Category 4: Download-and-execute pipeline (curl ... | bash)
            if download_tools.contains(&left_prog.as_str())
                && (interpreters.contains(&right_prog.as_str()) || right_prog == "sudo")
            {
                matches.push(RuleMatch {
                    rule_id: "RULE-TERM-002".to_string(),
                    name: "Unsafe Remote Script Execution".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    reason: "Direct pipe of unverified remote network payload into shell interpreter execution".to_string(),
                    evidence: vec![
                        format!("Download: {} {:?}", left.program, left.arguments),
                        format!("Interpreter: {} {:?}", right.program, right.arguments),
                    ],
                    potential_impact: "Execution of unvetted, unauthenticated code pulled over network".to_string(),
                    recommended_action: "ALERT_AND_CONFIRM".to_string(),
                });
            }

            // Category 7: Encoded command execution (base64 -d | sh)
            if ((left_prog == "base64"
                && left.arguments.iter().any(|a| a == "-d" || a == "--decode"))
                || (left_prog == "xxd" && left.arguments.iter().any(|a| a == "-r")))
                && interpreters.contains(&right_prog.as_str())
            {
                matches.push(RuleMatch {
                    rule_id: "RULE-OBFS-001".to_string(),
                    name: "Obfuscated / Encoded Command Execution".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    reason: "Decoding utility piped directly into shell interpreter for execution".to_string(),
                    evidence: vec![
                        format!("Decoder: {} {:?}", left.program, left.arguments),
                        format!("Interpreter: {}", right.program),
                    ],
                    potential_impact: "Execution of concealed or obfuscated shell payloads bypassing simple pattern matching".to_string(),
                    recommended_action: "ALERT_AND_CONFIRM".to_string(),
                });
            }
        }
    }

    fn detect_chain_level(
        &self,
        chain: &CommandChain,
        raw_input: &str,
        matches: &mut Vec<RuleMatch>,
    ) {
        // Fork bomb signature
        if raw_input.contains(":(){ :|:& };:")
            || raw_input.contains("bomb() { bomb | bomb & }; bomb")
        {
            matches.push(RuleMatch {
                rule_id: "RULE-TERM-004".to_string(),
                name: "Denial of Service Fork Bomb".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                reason: "Self-replicating shell fork-bomb signature detected".to_string(),
                evidence: vec!["Signature: :(){ :|:& };:".to_string()],
                potential_impact: "Host process table exhaustion causing immediate system lockup"
                    .to_string(),
                recommended_action: "BLOCK_AND_ALERT".to_string(),
            });
        }

        // Dynamic evaluation of command substitution (eval "$(curl ...)")
        for cmd in chain.all_atomic_commands() {
            if cmd.program == "eval" {
                for sub in &cmd.command_substitutions {
                    let sub_lower = sub.to_lowercase();
                    if sub_lower.contains("curl ") || sub_lower.contains("wget ") {
                        matches.push(RuleMatch {
                            rule_id: "RULE-RCE-001".to_string(),
                            name: "Dynamic Evaluation of Remote Fetch".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            reason: "eval used on command substitution containing remote download utility".to_string(),
                            evidence: vec![format!("Subshell payload: {}", sub)],
                            potential_impact: "Evaluates unverified remote script in current shell context".to_string(),
                            recommended_action: "ALERT_AND_CONFIRM".to_string(),
                        });
                    }
                }
            }
        }
    }
}
