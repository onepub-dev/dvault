mod context;
mod doctor;
mod env;
mod files;
mod help;
mod keys;
mod output;
mod recovery;
mod vault;
mod visualize;

use clap::ArgMatches;
use context::{Access, CliResult};
use lockbox_core::{Error, SecretVec, WorkerPolicy};
use std::env as std_env;

pub(crate) fn run() -> CliResult<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("__agent") {
        return Ok(lockbox_vault::serve_agent()?);
    }
    if args.first().map(String::as_str) == Some("__agent_security_check") {
        return Ok(lockbox_vault::verify_agent_transport_security()?);
    }

    let verbose_help = args.iter().any(|arg| arg == "--verbose");
    if args.is_empty() || is_top_level_help(&args) {
        help::usage(verbose_help);
        return Ok(());
    }
    let command = help::command(verbose_help);
    let matches =
        match command.try_get_matches_from(std::iter::once("lockbox".to_string()).chain(args)) {
            Ok(matches) => matches,
            Err(err) if err.kind() == clap::error::ErrorKind::DisplayHelp => {
                err.print()?;
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };

    let (command, command_matches) = matches
        .subcommand()
        .ok_or_else(|| Error::InvalidInput("missing command".to_string()))?;
    let access = read_access(&matches, command)?;

    match command {
        "create" => keys::create(&create_args(command_matches), &access)?,
        "doctor" => doctor::run()?,
        "unlock" => keys::unlock(&unlock_args(command_matches))?,
        "lock" => keys::lock(&lock_args(command_matches))?,
        "keygen" => keys::keygen(&two_args(command_matches, "private-key", "public-key"))?,
        "unlock-key" => keys::unlock_key(&unlock_key_args(command_matches))?,
        "access" => keys::access(&access_args(command_matches)?, &access)?,
        "vault" => vault::run(&vault_args(command_matches)?)?,
        "add" => files::add(
            &add_args(command_matches),
            &access,
            read_worker_policy(command_matches)?,
        )?,
        "extract" => files::extract(&extract_args(command_matches)?, &access)?,
        "cat" => files::cat(
            &two_args(command_matches, "lockbox", "lockbox-path"),
            &access,
        )?,
        "list" => files::list(&list_args(command_matches), &access)?,
        "rm" => files::remove(&remove_args(command_matches), &access)?,
        "rename" => files::rename(
            &three_args(command_matches, "lockbox", "from", "to"),
            &access,
        )?,
        "env" => env::run(&env_args(command_matches)?, &access)?,
        "recover" => recovery::run(&recover_args(command_matches)?, &access)?,
        "visualize" => visualize::run(&one_arg(command_matches, "lockbox"), &access)?,
        _ => return Err(Error::InvalidInput(format!("unknown command: {command}")).into()),
    }

    Ok(())
}

fn read_access(matches: &ArgMatches, command: &str) -> CliResult<Access> {
    if let Some(key) = matches.get_one::<String>("key") {
        return Ok(Access::ContentKey(SecretVec::try_from_vec(
            key.clone().into_bytes(),
        )?));
    }
    if let Ok(key) = std_env::var("LOCKBOX_KEY") {
        return Ok(Access::ContentKey(SecretVec::try_from_vec(
            key.into_bytes(),
        )?));
    }
    if command == "create" {
        Ok(Access::PromptPassword)
    } else {
        Ok(Access::CacheOnly)
    }
}

fn is_top_level_help(args: &[String]) -> bool {
    args.iter()
        .filter(|arg| arg.as_str() != "--verbose")
        .all(|arg| matches!(arg.as_str(), "--help" | "-h"))
}

fn read_worker_policy(matches: &ArgMatches) -> CliResult<WorkerPolicy> {
    let Some(value) = matches.get_one::<String>("jobs") else {
        return Ok(WorkerPolicy::Auto);
    };
    match value.as_str() {
        "auto" => Ok(WorkerPolicy::Auto),
        "1" => Ok(WorkerPolicy::Single),
        _ => {
            let jobs = value.parse::<usize>().map_err(|_| {
                Error::InvalidInput("--jobs must be auto, 1, or a positive integer".to_string())
            })?;
            if jobs == 0 {
                return Err(Error::InvalidInput(
                    "--jobs must be auto, 1, or a positive integer".to_string(),
                )
                .into());
            }
            Ok(WorkerPolicy::Threads(jobs))
        }
    }
}

fn create_args(matches: &ArgMatches) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(recipient) = matches.get_one::<String>("for") {
        args.push("--recipient".to_string());
        args.push(recipient.clone());
    }
    args.push(value(matches, "lockbox"));
    args
}

fn lock_args(matches: &ArgMatches) -> Vec<String> {
    if matches.get_flag("all") {
        vec!["--all".to_string()]
    } else {
        one_arg(matches, "lockbox")
    }
}

fn unlock_args(matches: &ArgMatches) -> Vec<String> {
    let mut args = one_arg(matches, "lockbox");
    push_option(&mut args, matches, "duration", "--duration");
    push_option(&mut args, matches, "password-env", "--password-env");
    push_option(&mut args, matches, "password-file", "--password-file");
    push_flag(&mut args, matches, "password-stdin", "--password-stdin");
    args
}

fn recover_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let mut args = one_arg(matches, "lockbox");
    push_option(&mut args, matches, "output", "--output");
    push_flag(&mut args, matches, "overwrite", "--overwrite");
    if matches.get_flag("report") || matches.get_flag("dry-run") {
        args.push("--report".to_string());
    }
    push_option(&mut args, matches, "format", "--format");
    Ok(args)
}

fn add_args(matches: &ArgMatches) -> Vec<String> {
    let mut args = two_args(matches, "lockbox", "source");
    if let Some(path) = matches.get_one::<String>("lockbox-path") {
        args.push(path.clone());
    }
    args
}

fn unlock_key_args(matches: &ArgMatches) -> Vec<String> {
    let mut args = one_arg(matches, "lockbox");
    if let Some(key) = matches.get_one::<String>("vault-key") {
        args.push(key.clone());
    }
    args
}

fn extract_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let mut args = one_arg(matches, "lockbox");
    if let Some(destination) = matches.get_one::<String>("to") {
        args.push("--to".to_string());
        args.push(destination.clone());
        push_flag(&mut args, matches, "overwrite", "--overwrite");
        push_flag(&mut args, matches, "restore-symlinks", "--restore-symlinks");
        push_flag(
            &mut args,
            matches,
            "restore-permissions",
            "--restore-permissions",
        );
        return Ok(args);
    }
    args.push(value(matches, "lockbox-path"));
    args.push(value(matches, "destination"));
    push_flag(&mut args, matches, "overwrite", "--overwrite");
    Ok(args)
}

fn list_args(matches: &ArgMatches) -> Vec<String> {
    let mut args = one_arg(matches, "lockbox");
    push_option(&mut args, matches, "format", "--format");
    push_flag(&mut args, matches, "recursive", "--recursive");
    if let Some(path) = matches.get_one::<String>("path") {
        args.push(path.clone());
    }
    args
}

fn remove_args(matches: &ArgMatches) -> Vec<String> {
    let mut args = two_args(matches, "lockbox", "lockbox-path");
    push_flag(&mut args, matches, "force", "--force");
    args
}

fn env_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let (command, sub) = matches
        .subcommand()
        .ok_or_else(|| Error::InvalidInput("missing env command".to_string()))?;
    let mut args = vec![command.to_string(), value(sub, "lockbox")];
    match command {
        "set" => {
            push_flag(&mut args, sub, "secret", "-s");
            args.push(value(sub, "name"));
            if let Some(value) = sub.get_one::<String>("positional-value") {
                args.push(value.clone());
            }
            push_flag(&mut args, sub, "interactive", "-i");
            push_flag(&mut args, sub, "stdin", "-t");
            push_option(&mut args, sub, "value", "-v");
            push_option(&mut args, sub, "file", "-f");
            push_option(&mut args, sub, "from-env", "-e");
        }
        "get" => {
            push_flag(&mut args, sub, "secret", "-s");
            push_option(&mut args, sub, "output", "--output");
            push_flag(&mut args, sub, "overwrite", "--overwrite");
            args.push(value(sub, "name"));
        }
        "list" | "ls" => push_option(&mut args, sub, "format", "--format"),
        "export" => push_option(&mut args, sub, "format", "--format"),
        "rm" | "remove" => args.push(value(sub, "name")),
        _ => return Err(Error::InvalidInput(format!("unknown env command: {command}")).into()),
    }
    Ok(args)
}

fn vault_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let (command, sub) = matches
        .subcommand()
        .ok_or_else(|| Error::InvalidInput("missing vault command".to_string()))?;
    let mut args = vec![command.to_string()];
    match command {
        "init" => {
            push_flag(&mut args, sub, "verify", "--verify");
            push_flag(&mut args, sub, "overwrite", "--overwrite");
        }
        "path" => {}
        "sessions" => {
            if let Some((session_command, session_sub)) = sub.subcommand() {
                args.push(session_command.to_string());
                match session_command {
                    "lock" => args.push(value(session_sub, "lockbox")),
                    "lock-all" | "stop" => {}
                    "auto-unlock" => {
                        let (auto_command, auto_sub) =
                            session_sub.subcommand().unwrap_or(("status", session_sub));
                        args.push(auto_command.to_string());
                        if auto_command == "status" {
                            push_option(&mut args, auto_sub, "format", "--format");
                        }
                    }
                    _ => {
                        return Err(Error::InvalidInput(format!(
                            "unknown vault sessions command: {session_command}"
                        ))
                        .into())
                    }
                }
            } else {
                push_option(&mut args, sub, "format", "--format");
            }
        }
        "identity" => {
            let (identity_command, identity_sub) = sub
                .subcommand()
                .ok_or_else(|| Error::InvalidInput("missing vault identity command".to_string()))?;
            args.push(identity_command.to_string());
            match identity_command {
                "create" => {
                    push_flag(&mut args, identity_sub, "overwrite", "--overwrite");
                    push_optional(&mut args, identity_sub, "name");
                    push_optional(&mut args, identity_sub, "public-key-output");
                }
                "list" | "ls" => push_option(&mut args, identity_sub, "format", "--format"),
                "import" => {
                    args.push(value(identity_sub, "name"));
                    args.push(value(identity_sub, "private-key"));
                    push_optional(&mut args, identity_sub, "public-key-output");
                }
                "export" | "export-public" => {
                    push_option(&mut args, identity_sub, "format", "--format");
                    push_many(&mut args, identity_sub, "args");
                }
                "remove" | "rm" => {
                    push_flag(&mut args, identity_sub, "force", "--force");
                    push_optional(&mut args, identity_sub, "name");
                }
                _ => {
                    return Err(Error::InvalidInput(format!(
                        "unknown vault identity command: {identity_command}"
                    ))
                    .into())
                }
            }
        }
        "contact" => {
            if let Some((contact_command, contact_sub)) = sub.subcommand() {
                args.push(contact_command.to_string());
                match contact_command {
                    "add" => {
                        push_flag(&mut args, contact_sub, "overwrite", "--overwrite");
                        args.push(value(contact_sub, "name"));
                        args.push(value(contact_sub, "public-key"));
                    }
                    "list" | "ls" => push_option(&mut args, contact_sub, "format", "--format"),
                    "remove" | "rm" => args.push(value(contact_sub, "name")),
                    _ => {
                        return Err(Error::InvalidInput(format!(
                            "unknown vault contact command: {contact_command}"
                        ))
                        .into())
                    }
                }
            } else {
                return Err(Error::InvalidInput(
                    "missing vault contact command; use `lockbox vault contact list`, `lockbox vault contact add <name> <public-key>`, or `lockbox vault contact remove <name>`"
                        .to_string(),
                )
                .into());
            }
        }
        "remove" | "rm" => args.push(value(sub, "name")),
        _ => return Err(Error::InvalidInput(format!("unknown vault command: {command}")).into()),
    }
    Ok(args)
}

fn access_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let (command, sub) = matches
        .subcommand()
        .ok_or_else(|| Error::InvalidInput("missing access command".to_string()))?;
    let mut args = vec![command.to_string(), value(sub, "lockbox")];
    match command {
        "add" => args.push(value(sub, "identity-or-contact")),
        "list" | "ls" => push_option(&mut args, sub, "format", "--format"),
        "remove" | "rm" => args.push(value(sub, "slot-id")),
        _ => return Err(Error::InvalidInput(format!("unknown access command: {command}")).into()),
    }
    Ok(args)
}

fn one_arg(matches: &ArgMatches, name: &str) -> Vec<String> {
    vec![value(matches, name)]
}

fn two_args(matches: &ArgMatches, first: &str, second: &str) -> Vec<String> {
    vec![value(matches, first), value(matches, second)]
}

fn three_args(matches: &ArgMatches, first: &str, second: &str, third: &str) -> Vec<String> {
    vec![
        value(matches, first),
        value(matches, second),
        value(matches, third),
    ]
}

fn value(matches: &ArgMatches, name: &str) -> String {
    matches
        .get_one::<String>(name)
        .unwrap_or_else(|| panic!("clap did not provide required argument {name}"))
        .clone()
}

fn push_optional(args: &mut Vec<String>, matches: &ArgMatches, name: &str) {
    if let Some(value) = matches.get_one::<String>(name) {
        args.push(value.clone());
    }
}

fn push_many(args: &mut Vec<String>, matches: &ArgMatches, name: &str) {
    if let Some(values) = matches.get_many::<String>(name) {
        args.extend(values.cloned());
    }
}

fn push_option(args: &mut Vec<String>, matches: &ArgMatches, name: &str, flag: &str) {
    if let Some(value) = matches.get_one::<String>(name) {
        args.push(flag.to_string());
        args.push(value.clone());
    }
}

fn push_flag(args: &mut Vec<String>, matches: &ArgMatches, name: &str, flag: &str) {
    if matches.get_flag(name) {
        args.push(flag.to_string());
    }
}
