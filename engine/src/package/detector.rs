// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::analysis::ast::AtomicCommand;
use crate::model::{PackageEcosystem, PackageOperation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSpec {
    pub name: String,
    pub version_constraint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedPackageCommand {
    pub package_manager: PackageEcosystem,
    pub operation: PackageOperation,
    pub requested_packages: Vec<PackageSpec>,
    pub manifest_override: Option<String>,
    pub flags: Vec<String>,
    pub raw_command: String,
}

/// Detects package manager commands from an AtomicCommand.
pub fn detect_package_command(cmd: &AtomicCommand, raw: &str) -> Option<DetectedPackageCommand> {
    // 1. Unwrap command wrappers like sudo, env, etc.
    let (effective_prog, effective_args) = unwrap_wrappers(&cmd.program, &cmd.arguments);

    let prog_name = extract_base_program(&effective_prog);

    match prog_name.as_str() {
        "npm" => parse_npm_command(&effective_args, PackageEcosystem::Npm, raw),
        "pnpm" => parse_npm_command(&effective_args, PackageEcosystem::Pnpm, raw),
        "yarn" => parse_yarn_command(&effective_args, raw),
        "pip" | "pip3" => parse_pip_command(&effective_args, raw),
        "python" | "python3" => {
            // Check for `python -m pip ...`
            if effective_args.len() >= 2
                && effective_args[0] == "-m"
                && (effective_args[1] == "pip" || effective_args[1] == "pip3")
            {
                let pip_args = &effective_args[2..];
                parse_pip_command(pip_args, raw)
            } else {
                None
            }
        }
        "npx" => parse_npx_command(&effective_args, PackageEcosystem::Npm, raw),
        "cargo" => parse_cargo_command(&effective_args, raw),
        _ => None,
    }
}

fn unwrap_wrappers<'a>(prog: &'a str, args: &'a [String]) -> (String, Vec<String>) {
    let base = extract_base_program(prog);
    if (base == "sudo" || base == "env" || base == "doas") && !args.is_empty() {
        // Skip any flags to sudo/env (like -u, -E, -i, VAR=VAL)
        let mut idx = 0;
        while idx < args.len() {
            let arg = &args[idx];
            if arg.starts_with('-') {
                idx += 1;
                // If it's -u or similar that takes an argument, skip the argument too
                if (arg == "-u" || arg == "-g") && idx < args.len() {
                    idx += 1;
                }
            } else if arg.contains('=') && base == "env" {
                // env VAR=VAL
                idx += 1;
            } else {
                break;
            }
        }

        if idx < args.len() {
            let inner_prog = args[idx].clone();
            let inner_args = args[idx + 1..].to_vec();
            return (inner_prog, inner_args);
        }
    }

    (prog.to_string(), args.to_vec())
}

fn extract_base_program(prog: &str) -> String {
    std::path::Path::new(prog)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| prog.to_string())
        .to_lowercase()
}

fn parse_npm_command(
    args: &[String],
    ecosystem: PackageEcosystem,
    raw: &str,
) -> Option<DetectedPackageCommand> {
    if args.is_empty() {
        return Some(DetectedPackageCommand {
            package_manager: ecosystem,
            operation: PackageOperation::InstallAll,
            requested_packages: Vec::new(),
            manifest_override: None,
            flags: Vec::new(),
            raw_command: raw.to_string(),
        });
    }

    let subcmd = &args[0];
    let rest = &args[1..];

    match subcmd.as_str() {
        "install" | "i" | "add" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            let operation = if packages.is_empty() {
                PackageOperation::InstallAll
            } else {
                PackageOperation::Add
            };

            Some(DetectedPackageCommand {
                package_manager: ecosystem,
                operation,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "update" | "up" | "upgrade" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: ecosystem,
                operation: PackageOperation::Update,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "run" | "run-script" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: ecosystem,
                operation: PackageOperation::ExecuteScript,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "dlx" | "exec" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: ecosystem,
                operation: PackageOperation::RunPackage,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        _ => None,
    }
}

fn parse_yarn_command(args: &[String], raw: &str) -> Option<DetectedPackageCommand> {
    if args.is_empty() {
        return Some(DetectedPackageCommand {
            package_manager: PackageEcosystem::Yarn,
            operation: PackageOperation::InstallAll,
            requested_packages: Vec::new(),
            manifest_override: None,
            flags: Vec::new(),
            raw_command: raw.to_string(),
        });
    }

    let subcmd = &args[0];
    let rest = &args[1..];

    match subcmd.as_str() {
        "install" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Yarn,
                operation: PackageOperation::InstallAll,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "add" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Yarn,
                operation: PackageOperation::Add,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "upgrade" | "up" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Yarn,
                operation: PackageOperation::Update,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "run" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Yarn,
                operation: PackageOperation::ExecuteScript,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "dlx" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Yarn,
                operation: PackageOperation::RunPackage,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        _ if subcmd.starts_with('-') => {
            // e.g. yarn --frozen-lockfile (defaults to install)
            let (packages, flags) = extract_packages_and_flags(args);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Yarn,
                operation: PackageOperation::InstallAll,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        _ => None,
    }
}

fn parse_pip_command(args: &[String], raw: &str) -> Option<DetectedPackageCommand> {
    if args.is_empty() {
        return None;
    }

    let subcmd = &args[0];
    let rest = &args[1..];

    if subcmd == "install" {
        let mut packages = Vec::new();
        let mut flags = Vec::new();
        let mut req_file = None;

        let mut idx = 0;
        while idx < rest.len() {
            let arg = &rest[idx];
            if arg == "-r" || arg == "--requirement" {
                if idx + 1 < rest.len() {
                    req_file = Some(rest[idx + 1].clone());
                    idx += 2;
                    continue;
                }
            } else if arg.starts_with("-r=") || arg.starts_with("--requirement=") {
                let parts: Vec<&str> = arg.splitn(2, '=').collect();
                if parts.len() == 2 {
                    req_file = Some(parts[1].to_string());
                }
                idx += 1;
                continue;
            } else if arg.starts_with('-') {
                flags.push(arg.clone());
                // Handle flags with separate value
                if (arg == "-i" || arg == "--index-url" || arg == "--extra-index-url")
                    && idx + 1 < rest.len()
                {
                    flags.push(rest[idx + 1].clone());
                    idx += 1;
                }
            } else {
                packages.push(parse_pip_package_spec(arg));
            }
            idx += 1;
        }

        let operation = if req_file.is_some() || packages.is_empty() {
            PackageOperation::InstallAll
        } else {
            PackageOperation::Add
        };

        Some(DetectedPackageCommand {
            package_manager: PackageEcosystem::Pip,
            operation,
            requested_packages: packages,
            manifest_override: req_file,
            flags,
            raw_command: raw.to_string(),
        })
    } else {
        None
    }
}

fn parse_npx_command(
    args: &[String],
    ecosystem: PackageEcosystem,
    raw: &str,
) -> Option<DetectedPackageCommand> {
    if args.is_empty() {
        return None;
    }

    let (packages, flags) = extract_packages_and_flags(args);
    if packages.is_empty() {
        None
    } else {
        Some(DetectedPackageCommand {
            package_manager: ecosystem,
            operation: PackageOperation::RunPackage,
            requested_packages: packages,
            manifest_override: None,
            flags,
            raw_command: raw.to_string(),
        })
    }
}

fn parse_cargo_command(args: &[String], raw: &str) -> Option<DetectedPackageCommand> {
    if args.is_empty() {
        return None;
    }

    let subcmd = &args[0];
    let rest = &args[1..];

    match subcmd.as_str() {
        "add" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Cargo,
                operation: PackageOperation::Add,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "install" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Cargo,
                operation: PackageOperation::Add,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "update" => {
            let (packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Cargo,
                operation: PackageOperation::Update,
                requested_packages: packages,
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        "build" | "check" => {
            let (_packages, flags) = extract_packages_and_flags(rest);
            Some(DetectedPackageCommand {
                package_manager: PackageEcosystem::Cargo,
                operation: PackageOperation::InstallAll,
                requested_packages: Vec::new(),
                manifest_override: None,
                flags,
                raw_command: raw.to_string(),
            })
        }
        _ => None,
    }
}

fn extract_packages_and_flags(args: &[String]) -> (Vec<PackageSpec>, Vec<String>) {
    let mut packages = Vec::new();
    let mut flags = Vec::new();

    let mut idx = 0;
    while idx < args.len() {
        let arg = &args[idx];
        if arg.starts_with('-') {
            flags.push(arg.clone());
            // If option requires a parameter, e.g. --registry <url>, capture next
            if (arg == "--registry" || arg == "-w" || arg == "--workspace") && idx + 1 < args.len()
            {
                flags.push(args[idx + 1].clone());
                idx += 1;
            }
        } else {
            packages.push(parse_package_spec(arg));
        }
        idx += 1;
    }

    (packages, flags)
}

/// Parses npm/yarn package spec like `lodash@4.17.20` or `@scope/pkg@^1.0.0` or `express`
fn parse_package_spec(raw: &str) -> PackageSpec {
    if let Some(stripped) = raw.strip_prefix('@') {
        // Scoped package e.g. @scope/pkg@1.0.0
        if let Some(at_idx) = stripped.find('@') {
            let scope_and_pkg = &raw[..at_idx + 1];
            let version = &stripped[at_idx + 1..];
            return PackageSpec {
                name: scope_and_pkg.to_string(),
                version_constraint: Some(version.to_string()),
            };
        } else {
            return PackageSpec {
                name: raw.to_string(),
                version_constraint: None,
            };
        }
    }

    if let Some((name, version)) = raw.split_once('@') {
        PackageSpec {
            name: name.to_string(),
            version_constraint: Some(version.to_string()),
        }
    } else {
        PackageSpec {
            name: raw.to_string(),
            version_constraint: None,
        }
    }
}

/// Parses pip package spec like `requests==2.28.1` or `urllib3>=1.26.0` or `flask`
fn parse_pip_package_spec(raw: &str) -> PackageSpec {
    for op in &["==", ">=", "<=", "~=", "!=", "<", ">"] {
        if let Some((name, version)) = raw.split_once(op) {
            return PackageSpec {
                name: name.trim().to_string(),
                version_constraint: Some(format!("{}{}", op, version.trim())),
            };
        }
    }

    PackageSpec {
        name: raw.trim().to_string(),
        version_constraint: None,
    }
}
