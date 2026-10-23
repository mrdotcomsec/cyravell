// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::analysis::lexer::{tokenize, TokenKind};
use crate::model::AnalysisCompleteness;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectOp {
    Output,
    Append,
    Input,
    Error,
    ErrorAppend,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirection {
    pub op: RedirectOp,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicCommand {
    pub program: String,
    pub arguments: Vec<String>,
    pub raw_arguments: Vec<String>,
    pub redirections: Vec<Redirection>,
    pub env_assignments: Vec<(String, String)>,
    pub command_substitutions: Vec<String>,
}

impl AtomicCommand {
    pub fn new() -> Self {
        Self {
            program: String::new(),
            arguments: Vec::new(),
            raw_arguments: Vec::new(),
            redirections: Vec::new(),
            env_assignments: Vec::new(),
            command_substitutions: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.program.is_empty()
            && self.arguments.is_empty()
            && self.env_assignments.is_empty()
            && self.command_substitutions.is_empty()
    }
}

impl Default for AtomicCommand {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub commands: Vec<AtomicCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainOperator {
    Semicolon,
    AndIf,
    OrIf,
    Ampersand,
}

impl std::fmt::Display for ChainOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Semicolon => write!(f, ";"),
            Self::AndIf => write!(f, "&&"),
            Self::OrIf => write!(f, "||"),
            Self::Ampersand => write!(f, "&"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandChain {
    pub pipelines: Vec<(Pipeline, Option<ChainOperator>)>,
    pub operators_detected: Vec<String>,
    pub completeness: AnalysisCompleteness,
    pub notes: Vec<String>,
}

impl CommandChain {
    pub fn all_atomic_commands(&self) -> Vec<&AtomicCommand> {
        let mut list = Vec::new();
        for (pipeline, _) in &self.pipelines {
            for cmd in &pipeline.commands {
                if !cmd.is_empty() {
                    list.push(cmd);
                }
            }
        }
        list
    }

    pub fn all_program_names(&self) -> Vec<String> {
        self.all_atomic_commands()
            .into_iter()
            .map(|c| c.program.clone())
            .filter(|p| !p.is_empty())
            .collect()
    }
}

pub fn parse_command(input: &str) -> CommandChain {
    let lex_res = tokenize(input);
    let mut completeness = lex_res.completeness;
    let mut notes = lex_res.notes;
    let mut operators_detected = Vec::new();

    let mut pipelines: Vec<(Pipeline, Option<ChainOperator>)> = Vec::new();
    let mut current_pipeline_commands: Vec<AtomicCommand> = Vec::new();
    let mut current_command = AtomicCommand::new();

    let mut tokens_iter = lex_res.tokens.into_iter().peekable();

    while let Some(token) = tokens_iter.next() {
        match token.kind {
            TokenKind::Word { raw, unquoted, .. } => {
                // Check if this is an environment assignment at the start of command (e.g. KEY=VAL)
                if current_command.program.is_empty()
                    && unquoted.contains('=')
                    && !unquoted.starts_with('=')
                {
                    let parts: Vec<&str> = unquoted.splitn(2, '=').collect();
                    if parts.len() == 2 && is_valid_ident(parts[0]) {
                        current_command
                            .env_assignments
                            .push((parts[0].to_string(), parts[1].to_string()));
                        continue;
                    }
                }

                if current_command.program.is_empty() {
                    current_command.program = unquoted;
                } else {
                    current_command.arguments.push(unquoted);
                    current_command.raw_arguments.push(raw);
                }
            }

            TokenKind::CommandSubstitution { content, .. } => {
                current_command.command_substitutions.push(content.clone());
                // Treat substitution as an argument or program if empty
                if current_command.program.is_empty() {
                    current_command.program = format!("$({})", content);
                } else {
                    current_command.arguments.push(format!("$({})", content));
                }
            }

            TokenKind::VariableExpansion(var) => {
                current_command.arguments.push(format!("${}", var));
            }

            TokenKind::RedirectOut(_)
            | TokenKind::RedirectAppend(_)
            | TokenKind::RedirectIn(_)
            | TokenKind::RedirectErr(_)
            | TokenKind::RedirectErrAppend(_)
            | TokenKind::RedirectAll(_) => {
                let op = match token.kind {
                    TokenKind::RedirectOut(_) => RedirectOp::Output,
                    TokenKind::RedirectAppend(_) => RedirectOp::Append,
                    TokenKind::RedirectIn(_) => RedirectOp::Input,
                    TokenKind::RedirectErr(_) => RedirectOp::Error,
                    TokenKind::RedirectErrAppend(_) => RedirectOp::ErrorAppend,
                    _ => RedirectOp::All,
                };

                let target = match tokens_iter.peek() {
                    Some(next_tok) => match &next_tok.kind {
                        TokenKind::Word { unquoted, .. } => unquoted.clone(),
                        _ => String::new(),
                    },
                    None => String::new(),
                };

                if !target.is_empty() {
                    tokens_iter.next(); // consume target word
                }

                operators_detected.push(format!("{:?}", op));
                current_command
                    .redirections
                    .push(Redirection { op, target });
            }

            TokenKind::Pipe => {
                operators_detected.push("|".to_string());
                if !current_command.is_empty() {
                    current_pipeline_commands.push(current_command);
                    current_command = AtomicCommand::new();
                }
            }

            TokenKind::Semicolon | TokenKind::AndIf | TokenKind::OrIf | TokenKind::Ampersand => {
                let op = match token.kind {
                    TokenKind::Semicolon => {
                        operators_detected.push(";".to_string());
                        ChainOperator::Semicolon
                    }
                    TokenKind::AndIf => {
                        operators_detected.push("&&".to_string());
                        ChainOperator::AndIf
                    }
                    TokenKind::OrIf => {
                        operators_detected.push("||".to_string());
                        ChainOperator::OrIf
                    }
                    TokenKind::Ampersand => {
                        operators_detected.push("&".to_string());
                        ChainOperator::Ampersand
                    }
                    _ => unreachable!(),
                };

                if !current_command.is_empty() {
                    current_pipeline_commands.push(current_command);
                    current_command = AtomicCommand::new();
                }

                if !current_pipeline_commands.is_empty() {
                    pipelines.push((
                        Pipeline {
                            commands: current_pipeline_commands,
                        },
                        Some(op),
                    ));
                    current_pipeline_commands = Vec::new();
                }
            }
        }
    }

    if !current_command.is_empty() {
        current_pipeline_commands.push(current_command);
    }
    if !current_pipeline_commands.is_empty() {
        pipelines.push((
            Pipeline {
                commands: current_pipeline_commands,
            },
            None,
        ));
    }

    // Check complexity
    let total_commands = pipelines
        .iter()
        .map(|(p, _)| p.commands.len())
        .sum::<usize>();
    if total_commands > 8 {
        completeness = AnalysisCompleteness::Partial;
        notes.push(format!(
            "High complexity command chain ({} atomic commands); reduced analysis certainty",
            total_commands
        ));
    }

    CommandChain {
        pipelines,
        operators_detected,
        completeness,
        notes,
    }
}

fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_parsing() {
        let chain = parse_command("curl -fsSL https://example.com/install.sh | bash");
        assert_eq!(chain.pipelines.len(), 1);
        let pipeline = &chain.pipelines[0].0;
        assert_eq!(pipeline.commands.len(), 2);
        assert_eq!(pipeline.commands[0].program, "curl");
        assert_eq!(
            pipeline.commands[0].arguments,
            vec!["-fsSL", "https://example.com/install.sh"]
        );
        assert_eq!(pipeline.commands[1].program, "bash");
    }

    #[test]
    fn test_conditional_chain_parsing() {
        let chain = parse_command("git status && npm test || echo failed");
        assert_eq!(chain.pipelines.len(), 3);
        assert_eq!(chain.pipelines[0].0.commands[0].program, "git");
        assert_eq!(chain.pipelines[0].1, Some(ChainOperator::AndIf));
        assert_eq!(chain.pipelines[1].0.commands[0].program, "npm");
        assert_eq!(chain.pipelines[1].1, Some(ChainOperator::OrIf));
        assert_eq!(chain.pipelines[2].0.commands[0].program, "echo");
        assert_eq!(chain.pipelines[2].1, None);
    }

    #[test]
    fn test_redirection_parsing() {
        let chain = parse_command("echo secret > /tmp/out.txt");
        assert_eq!(chain.pipelines.len(), 1);
        let cmd = &chain.pipelines[0].0.commands[0];
        assert_eq!(cmd.program, "echo");
        assert_eq!(cmd.arguments, vec!["secret"]);
        assert_eq!(cmd.redirections.len(), 1);
        assert_eq!(cmd.redirections[0].op, RedirectOp::Output);
        assert_eq!(cmd.redirections[0].target, "/tmp/out.txt");
    }
}
