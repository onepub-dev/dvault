mod context;
mod doctor;
mod env;
mod files;
mod form;
mod help;
mod keys;
mod output;
mod recovery;
mod vault;
mod visualize;

use clap::ArgMatches;
use context::{Access, CliResult};
use lockbox_core::{Error, SecretVec, WorkerPolicy};
use lockbox_vault::SecretActivityKind;
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
    let _secret_activity = command_secret_activity(command)
        .map(lockbox_vault::begin_secret_activity)
        .transpose()?;
    let access = read_access(&matches, command)?;

    match command {
        "create" => keys::create(&create_args(command_matches), &access)?,
        "doctor" => doctor::run(&one_optional_arg(command_matches, "lockbox"))?,
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
        "form" => form::run(&form_args(command_matches)?, &access)?,
        "recover" => recovery::run(&recover_args(command_matches)?, &access)?,
        "visualize" => visualize::run(&one_arg(command_matches, "lockbox"), &access)?,
        _ => return Err(Error::InvalidInput(format!("unknown command: {command}")).into()),
    }

    Ok(())
}

fn command_secret_activity(command: &str) -> Option<SecretActivityKind> {
    match command {
        "unlock" => Some(SecretActivityKind::Unlock),
        "add" | "extract" | "cat" | "list" | "rm" | "rename" | "visualize" => {
            Some(SecretActivityKind::Open)
        }
        "env" => Some(SecretActivityKind::Env),
        "form" => Some(SecretActivityKind::Form),
        "recover" => Some(SecretActivityKind::Recovery),
        "access" | "unlock-key" => Some(SecretActivityKind::Vault),
        _ => None,
    }
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
    push_flag(&mut args, matches, "recursive", "--recursive");
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
        "list" | "ls" => {
            push_option(&mut args, sub, "format", "--format");
            push_optional(&mut args, sub, "pattern");
        }
        "export" => {
            push_option(&mut args, sub, "format", "--format");
            push_optional(&mut args, sub, "path");
        }
        "rm" | "remove" => args.push(value(sub, "name")),
        _ => return Err(Error::InvalidInput(format!("unknown env command: {command}")).into()),
    }
    Ok(args)
}

fn form_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let (command, sub) = matches
        .subcommand()
        .ok_or_else(|| Error::InvalidInput("missing form command".to_string()))?;
    let mut args = vec![command.to_string(), value(sub, "lockbox")];
    match command {
        "define" => {
            push_optional(&mut args, sub, "alias");
            push_option(&mut args, sub, "name", "--name");
            push_option(&mut args, sub, "definition-id", "--definition-id");
            if let Some(fields) = sub.get_many::<String>("field") {
                for field in fields {
                    args.push("--field".to_string());
                    args.push(field.clone());
                }
            }
        }
        "definitions" | "types" => {
            push_option(&mut args, sub, "format", "--format");
        }
        "add" => {
            args.push(value(sub, "path"));
            push_option(&mut args, sub, "type", "--type");
            push_option(&mut args, sub, "name", "--name");
            if let Some(assignments) = sub.get_many::<String>("set") {
                for assignment in assignments {
                    args.push("--set".to_string());
                    args.push(assignment.clone());
                }
            }
            push_flag(&mut args, sub, "interactive", "--interactive");
        }
        "edit" => {
            args.push(value(sub, "path"));
            if let Some(assignments) = sub.get_many::<String>("set") {
                for assignment in assignments {
                    args.push("--set".to_string());
                    args.push(assignment.clone());
                }
            }
            push_flag(&mut args, sub, "interactive", "--interactive");
        }
        "set" => {
            args.push(value(sub, "path"));
            args.push(value(sub, "field"));
            push_flag(&mut args, sub, "secret", "--secret");
            push_flag(&mut args, sub, "interactive", "--interactive");
            push_flag(&mut args, sub, "stdin", "--stdin");
            push_option(&mut args, sub, "explicit-value", "--value");
            push_option(&mut args, sub, "file", "--file");
            push_option(&mut args, sub, "from-env", "--from-env");
            if let Some(value) = sub.get_one::<String>("value") {
                args.push(value.clone());
            }
        }
        "get" => {
            args.push(value(sub, "path"));
            args.push(value(sub, "field"));
            push_flag(&mut args, sub, "secret", "--secret");
            push_option(&mut args, sub, "output", "--output");
            push_flag(&mut args, sub, "overwrite", "--overwrite");
        }
        "show" => {
            args.push(value(sub, "path"));
        }
        "list" => {
            push_option(&mut args, sub, "format", "--format");
            push_optional(&mut args, sub, "pattern");
        }
        "rm" => {
            args.push(value(sub, "path"));
        }
        _ => return Err(Error::InvalidInput(format!("unknown form command: {command}")).into()),
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
        "backup" => {
            push_flag(&mut args, sub, "overwrite", "--overwrite");
            args.push(value(sub, "output"));
        }
        "restore" => {
            push_flag(&mut args, sub, "overwrite", "--overwrite");
            args.push(value(sub, "backup"));
        }
        "path" => {}
        "publish" => {
            push_share_publish_options(&mut args, sub);
            push_optional(&mut args, sub, "identity");
        }
        "receive" | "recieve" | "fetch" => {
            push_share_transport_options(&mut args, sub);
            push_option(&mut args, sub, "fingerprint", "--fingerprint");
            push_flag(&mut args, sub, "overwrite", "--overwrite");
            args.push(value(sub, "share-code"));
            push_optional(&mut args, sub, "contact-name");
        }
        "remove" | "delete" => {
            push_share_transport_options(&mut args, sub);
            args.push(value(sub, "share-code"));
            args.push(value(sub, "delete-token"));
        }
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
                }
                "history" => {
                    push_option(&mut args, identity_sub, "format", "--format");
                    push_optional(&mut args, identity_sub, "name");
                }
                "list" | "ls" => push_option(&mut args, identity_sub, "format", "--format"),
                "email" => {
                    push_many(&mut args, identity_sub, "args");
                }
                "import" => {
                    args.push(value(identity_sub, "name"));
                    args.push(value(identity_sub, "private-key"));
                    push_optional(&mut args, identity_sub, "public-key-output");
                }
                "export" | "export-private" => {
                    push_option(&mut args, identity_sub, "format", "--format");
                    push_many(&mut args, identity_sub, "args");
                }
                "remove" | "rm" => {
                    push_flag(&mut args, identity_sub, "force", "--force");
                    push_optional(&mut args, identity_sub, "name");
                }
                "rotate" => push_optional(&mut args, identity_sub, "name"),
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
        "share" => {
            if let Some((share_command, share_sub)) = sub.subcommand() {
                args.push(share_command.to_string());
                match share_command {
                    "publish" => {
                        push_share_publish_options(&mut args, share_sub);
                        push_optional(&mut args, share_sub, "identity");
                    }
                    "receive" | "recieve" | "fetch" => {
                        push_share_transport_options(&mut args, share_sub);
                        push_option(&mut args, share_sub, "fingerprint", "--fingerprint");
                        push_flag(&mut args, share_sub, "overwrite", "--overwrite");
                        args.push(value(share_sub, "share-code"));
                        push_optional(&mut args, share_sub, "contact-name");
                    }
                    "remove" | "rm" | "delete" => {
                        push_share_transport_options(&mut args, share_sub);
                        args.push(value(share_sub, "share-code"));
                        args.push(value(share_sub, "delete-token"));
                    }
                    _ => {
                        return Err(Error::InvalidInput(format!(
                            "unknown vault share command: {share_command}"
                        ))
                        .into())
                    }
                }
            } else {
                return Err(Error::InvalidInput(
                    "missing vault share command; use `lockbox vault share publish`, `lockbox vault share receive`, or `lockbox vault share remove`"
                        .to_string(),
                )
                .into());
            }
        }
        "lockbox" => {
            if let Some((lockbox_command, lockbox_sub)) = sub.subcommand() {
                args.push(lockbox_command.to_string());
                match lockbox_command {
                    "list" | "ls" => push_option(&mut args, lockbox_sub, "format", "--format"),
                    "forget" => args.push(value(lockbox_sub, "lockbox")),
                    _ => {
                        return Err(Error::InvalidInput(format!(
                            "unknown vault lockbox command: {lockbox_command}"
                        ))
                        .into())
                    }
                }
            } else {
                return Err(Error::InvalidInput(
                    "missing vault lockbox command; use `lockbox vault lockbox list` or `lockbox vault lockbox forget <lockbox>`"
                        .to_string(),
                )
                .into());
            }
        }
        _ => return Err(Error::InvalidInput(format!("unknown vault command: {command}")).into()),
    }
    Ok(args)
}

fn push_share_transport_options(args: &mut Vec<String>, matches: &ArgMatches) {
    push_option(args, matches, "server", "--server");
    push_option(args, matches, "topology-url", "--topology-url");
}

fn push_share_publish_options(args: &mut Vec<String>, matches: &ArgMatches) {
    push_share_transport_options(args, matches);
    push_option(args, matches, "ttl", "--ttl");
    push_option(args, matches, "max-fetches", "--max-fetches");
}

fn access_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let (command, sub) = matches
        .subcommand()
        .ok_or_else(|| Error::InvalidInput("missing access command".to_string()))?;
    let mut args = vec![command.to_string()];
    match command {
        "add" => {
            args.push(value(sub, "lockbox"));
            args.push(value(sub, "identity-or-contact"));
            if let Some(public_key) = sub.get_one::<String>("public-key") {
                args.push(public_key.clone());
            }
        }
        "list" | "ls" => {
            args.push(value(sub, "lockbox"));
            push_option(&mut args, sub, "format", "--format");
        }
        "refresh" => {
            if sub.get_flag("all") {
                args.push("--all".to_string());
            }
            push_many(&mut args, sub, "args");
            push_flag(&mut args, sub, "dry-run", "--dry-run");
            push_flag(&mut args, sub, "yes", "--yes");
        }
        "remove" | "rm" => {
            args.push(value(sub, "lockbox"));
            args.push(value(sub, "slot-id"));
        }
        _ => return Err(Error::InvalidInput(format!("unknown access command: {command}")).into()),
    }
    Ok(args)
}

fn one_arg(matches: &ArgMatches, name: &str) -> Vec<String> {
    vec![value(matches, name)]
}

fn one_optional_arg(matches: &ArgMatches, name: &str) -> Vec<String> {
    matches
        .get_one::<String>(name)
        .map(|value| vec![value.clone()])
        .unwrap_or_default()
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
