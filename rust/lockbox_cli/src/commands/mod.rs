mod context;
mod doctor;
mod files;
mod form;
mod help;
mod keys;
mod output;
mod recovery;
mod session;
mod variables;
mod vault;
mod visualize;

use clap::ArgMatches;
use context::{cli_error, ensure_lockbox_path_accessible, Access, CliResult};
use lockbox_core::{Error, SecretVec, WorkerPolicy};
use lockbox_vault::SecretActivityKind;
use std::env as std_env;
use std::path::Path;

pub(crate) fn run() -> CliResult<()> {
    let args: Vec<String> = normalize_form_define_separator(std::env::args().skip(1).collect());
    if args.first().map(String::as_str) == Some("__agent") {
        return Ok(lockbox_vault::serve_agent()?);
    }
    if args.first().map(String::as_str) == Some("__agent_security_check") {
        return Ok(lockbox_vault::verify_agent_transport_security()?);
    }
    reject_variables_set_single_dash_secret(&args)?;

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
        "open" => keys::open(&open_args(command_matches)?)?,
        "close" => keys::close(&close_args(command_matches)?)?,
        "keygen" => keys::keygen(&two_args(command_matches, "private-key", "public-key"))?,
        "open-key" => keys::open_key(&open_key_args(command_matches)?)?,
        "session" => session::run(&session_args(command_matches)?)?,
        "access" => keys::access(&access_args(command_matches)?, &access)?,
        "vault" => vault::run(&vault_args(command_matches)?)?,
        "add" => files::add(
            &add_args(command_matches)?,
            &access,
            read_worker_policy(command_matches)?,
        )?,
        "extract" => files::extract(&extract_args(command_matches)?, &access)?,
        "cat" => files::cat(&cat_args(command_matches)?, &access)?,
        "list" => files::list(&list_args(command_matches)?, &access)?,
        "rm" => files::remove(&remove_args(command_matches)?, &access)?,
        "rename" => files::rename(&rename_args(command_matches)?, &access)?,
        "variables" => variables::run(&variables_args(command_matches)?, &access)?,
        "form" => form::run(&form_args(command_matches)?, &access)?,
        "recover" => recovery::run(&recover_args(command_matches)?, &access)?,
        "visualize" => visualize::run(&visualize_args(command_matches)?, &access)?,
        _ => return Err(Error::InvalidInput(format!("unknown command: {command}")).into()),
    }

    Ok(())
}

fn normalize_form_define_separator(mut args: Vec<String>) -> Vec<String> {
    if args.first().map(String::as_str) != Some("form")
        || args.get(1).map(String::as_str) != Some("define")
    {
        return args;
    }
    args.retain(|arg| arg != "--");
    args
}

fn reject_variables_set_single_dash_secret(args: &[String]) -> CliResult<()> {
    if matches!(args.first().map(String::as_str), Some("variables" | "var"))
        && args.get(1).map(String::as_str) == Some("set")
        && args.iter().skip(2).any(|arg| arg == "-secret")
    {
        return Err(cli_error("unknown option: -secret. Use --secret."));
    }
    Ok(())
}

fn command_secret_activity(command: &str) -> Option<SecretActivityKind> {
    match command {
        "open" => Some(SecretActivityKind::Unlock),
        "add" | "extract" | "cat" | "list" | "rm" | "rename" | "visualize" => {
            Some(SecretActivityKind::Open)
        }
        "variables" => Some(SecretActivityKind::Variables),
        "form" => Some(SecretActivityKind::Form),
        "recover" => Some(SecretActivityKind::Recovery),
        "access" | "open-key" | "session" => Some(SecretActivityKind::Vault),
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
    if matches.get_flag("password") {
        args.push("--password".to_string());
    }
    if let Some(recipient) = matches.get_one::<String>("for") {
        args.push("--recipient".to_string());
        args.push(recipient.clone());
    }
    args.push(value(matches, "lockbox"));
    args
}

fn close_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    Ok(vec![optional_lockbox_value(matches, "lockbox")?])
}

fn open_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let mut args = vec![optional_lockbox_value(matches, "lockbox")?];
    push_option(&mut args, matches, "duration", "--duration");
    push_option(&mut args, matches, "password-env", "--password-env");
    push_option(&mut args, matches, "password-file", "--password-file");
    push_flag(&mut args, matches, "password-stdin", "--password-stdin");
    Ok(args)
}

fn recover_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let mut args = vec![optional_lockbox_value(matches, "lockbox")?];
    push_option(&mut args, matches, "output", "--output");
    push_flag(&mut args, matches, "overwrite", "--overwrite");
    if matches.get_flag("report") || matches.get_flag("dry-run") {
        args.push("--report".to_string());
    }
    push_option(&mut args, matches, "format", "--format");
    Ok(args)
}

fn add_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let first = value(matches, "lockbox-or-source");
    let second = matches.get_one::<String>("source-or-lockbox-path").cloned();
    let third = matches.get_one::<String>("lockbox-path").cloned();
    let mut args = match (second, third) {
        (None, None) => vec![active_lockbox_for_add()?, first],
        (Some(second), None) => {
            if looks_like_lockbox_path(&first) {
                vec![first, second]
            } else {
                vec![active_lockbox_for_add()?, first, second]
            }
        }
        (Some(second), Some(third)) => vec![first, second, third],
        (None, Some(_)) => unreachable!("clap does not provide third positional without second"),
    };
    push_flag(&mut args, matches, "recursive", "--recursive");
    Ok(args)
}

fn active_lockbox_for_add() -> CliResult<String> {
    active_lockbox_for_add_if_set()?
        .ok_or_else(|| cli_error("missing lockbox; pass a .lbox path or activate a lockbox"))
}

fn active_lockbox_for_add_if_set() -> CliResult<Option<String>> {
    let Some(active) = session::active_lockbox_or_none()? else {
        return Ok(None);
    };
    ensure_lockbox_path_accessible(&active)
        .map_err(|_| cli_error(format!("active lockbox not found: {active}")))?;
    Ok(Some(active))
}

fn optional_lockbox_value(matches: &ArgMatches, name: &str) -> CliResult<String> {
    match matches.get_one::<String>(name) {
        Some(value) => Ok(value.clone()),
        None => active_lockbox_for_command(),
    }
}

fn optional_lockbox_positionals(
    mut values: Vec<String>,
    required_after_lockbox: usize,
) -> CliResult<Vec<String>> {
    if values
        .first()
        .is_some_and(|value| looks_like_lockbox_path(value))
    {
        if values.len() < required_after_lockbox + 1 {
            return Err(cli_error("missing argument after lockbox"));
        }
        return Ok(values);
    }
    if values.len() < required_after_lockbox {
        return Err(cli_error("missing required argument"));
    }
    values.insert(0, active_lockbox_for_command()?);
    Ok(values)
}

fn active_lockbox_for_command() -> CliResult<String> {
    active_lockbox_for_add_if_set()?
        .ok_or_else(|| cli_error("missing lockbox; pass a .lbox path or activate a lockbox"))
}

fn looks_like_lockbox_path(value: &str) -> bool {
    value.ends_with(".lbox")
        || Path::new(value)
            .extension()
            .is_some_and(|ext| ext == "lbox")
}

fn positional_values(matches: &ArgMatches, name: &str) -> Vec<String> {
    matches
        .get_many::<String>(name)
        .map(|values| values.cloned().collect())
        .unwrap_or_default()
}

fn open_key_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let values = positional_values(matches, "args");
    let args = match values.as_slice() {
        [] => vec![active_lockbox_for_command()?],
        [first] if looks_like_lockbox_path(first) => vec![first.clone()],
        [key] => vec![active_lockbox_for_command()?, key.clone()],
        [lockbox, key] if looks_like_lockbox_path(lockbox) => vec![lockbox.clone(), key.clone()],
        [lockbox, _] => {
            return Err(cli_error(format!(
                "lockbox path must end with .lbox: {lockbox}"
            )))
        }
        _ => unreachable!("clap limits open-key positional arguments"),
    };
    Ok(args)
}

fn extract_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    if let Some(destination) = matches.get_one::<String>("to") {
        let values = positional_values(matches, "args");
        if values.len() > 1 {
            return Err(cli_error("extract --to accepts at most one lockbox path"));
        }
        let mut args = if let Some(lockbox) = values.first() {
            vec![lockbox.clone()]
        } else {
            vec![active_lockbox_for_command()?]
        };
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
    let args = positional_values(matches, "args");
    let mut args = optional_lockbox_positionals(args, 2)?;
    push_flag(&mut args, matches, "overwrite", "--overwrite");
    Ok(args)
}

fn cat_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    optional_lockbox_positionals(positional_values(matches, "args"), 1)
}

fn list_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let mut args = optional_lockbox_positionals(positional_values(matches, "args"), 0)?;
    push_option(&mut args, matches, "format", "--format");
    push_flag(&mut args, matches, "recursive", "--recursive");
    Ok(args)
}

fn remove_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let mut args = optional_lockbox_positionals(positional_values(matches, "args"), 1)?;
    push_flag(&mut args, matches, "force", "--force");
    Ok(args)
}

fn rename_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    optional_lockbox_positionals(positional_values(matches, "args"), 2)
}

fn visualize_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    Ok(vec![optional_lockbox_value(matches, "lockbox")?])
}

fn variables_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let (command, sub) = matches
        .subcommand()
        .ok_or_else(|| Error::InvalidInput("missing variables command".to_string()))?;
    let mut args = vec![command.to_string()];
    match command {
        "set" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
            push_flag(&mut args, sub, "secret", "-s");
            push_flag(&mut args, sub, "interactive", "-i");
            push_flag(&mut args, sub, "stdin", "-t");
            push_option(&mut args, sub, "value", "-v");
            push_option(&mut args, sub, "file", "-f");
            push_option(&mut args, sub, "from-env", "-e");
        }
        "get" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
            push_flag(&mut args, sub, "secret", "-s");
            push_option(&mut args, sub, "output", "--output");
            push_flag(&mut args, sub, "overwrite", "--overwrite");
        }
        "list" | "ls" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                0,
            )?);
            push_option(&mut args, sub, "format", "--format");
        }
        "export" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                0,
            )?);
            push_option(&mut args, sub, "format", "--format");
        }
        "rm" | "remove" => args.extend(optional_lockbox_positionals(
            positional_values(sub, "args"),
            1,
        )?),
        _ => {
            return Err(Error::InvalidInput(format!("unknown variables command: {command}")).into())
        }
    }
    Ok(args)
}

fn form_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let (command, sub) = matches
        .subcommand()
        .ok_or_else(|| Error::InvalidInput("missing form command".to_string()))?;
    let mut args = vec![command.to_string()];
    match command {
        "define" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                0,
            )?);
            push_option(&mut args, sub, "name", "--name");
            push_option(&mut args, sub, "definition-id", "--definition-id");
            if let Some(fields) = sub.get_many::<String>("field") {
                for field in fields {
                    args.push("--field".to_string());
                    args.push(field.clone());
                }
            }
        }
        "definitions" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                0,
            )?);
            push_option(&mut args, sub, "format", "--format");
        }
        "use" => {
            args.push(value(sub, "form"));
            match sub.get_one::<String>("lockbox") {
                Some(lockbox) => args.push(lockbox.clone()),
                None => args.push(active_lockbox_for_command()?),
            }
        }
        "capture" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
        }
        "add" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
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
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
            if let Some(assignments) = sub.get_many::<String>("set") {
                for assignment in assignments {
                    args.push("--set".to_string());
                    args.push(assignment.clone());
                }
            }
            push_flag(&mut args, sub, "interactive", "--interactive");
        }
        "set" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                2,
            )?);
            push_flag(&mut args, sub, "secret", "--secret");
            push_flag(&mut args, sub, "interactive", "--interactive");
            push_flag(&mut args, sub, "stdin", "--stdin");
            push_option(&mut args, sub, "explicit-value", "--value");
            push_option(&mut args, sub, "file", "--file");
            push_option(&mut args, sub, "from-env", "--from-env");
        }
        "get" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                2,
            )?);
            push_flag(&mut args, sub, "secret", "--secret");
            push_option(&mut args, sub, "output", "--output");
            push_flag(&mut args, sub, "overwrite", "--overwrite");
        }
        "show" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
        }
        "list" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                0,
            )?);
            push_option(&mut args, sub, "format", "--format");
        }
        "remove" | "rm" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
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
        "passphrase" => {}
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
                    push_option(&mut args, identity_sub, "public", "--public");
                    push_option(&mut args, identity_sub, "private", "--private");
                    args.push(value(identity_sub, "name"));
                }
                "export" => {
                    push_option(&mut args, identity_sub, "format", "--format");
                    push_option(&mut args, identity_sub, "public", "--public");
                    push_option(&mut args, identity_sub, "private", "--private");
                    push_optional(&mut args, identity_sub, "name");
                }
                "remove" | "rm" => {
                    push_flag(&mut args, identity_sub, "force", "--force");
                    push_optional(&mut args, identity_sub, "name");
                }
                "rotate" => push_optional(&mut args, identity_sub, "name"),
                "publish" => {
                    push_share_publish_options(&mut args, identity_sub);
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
                    "import" => {
                        push_flag(&mut args, contact_sub, "overwrite", "--overwrite");
                        push_option(&mut args, contact_sub, "fingerprint", "--fingerprint");
                        push_option(
                            &mut args,
                            contact_sub,
                            "fingerprint-channel",
                            "--fingerprint-channel",
                        );
                        args.push(value(contact_sub, "name"));
                        args.push(value(contact_sub, "public-key"));
                    }
                    "list" | "ls" => push_option(&mut args, contact_sub, "format", "--format"),
                    "receive" => {
                        push_share_transport_options(&mut args, contact_sub);
                        push_option(&mut args, contact_sub, "fingerprint", "--fingerprint");
                        push_option(
                            &mut args,
                            contact_sub,
                            "fingerprint-channel",
                            "--fingerprint-channel",
                        );
                        push_flag(&mut args, contact_sub, "overwrite", "--overwrite");
                        args.push(value(contact_sub, "share-code"));
                        push_optional(&mut args, contact_sub, "contact-name");
                    }
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
                    "missing vault contact command; use `lockbox vault contact list`, `lockbox vault contact import <name> <public-key>`, or `lockbox vault contact remove <name>`"
                        .to_string(),
                )
                .into());
            }
        }
        "form" => {
            if let Some((form_command, form_sub)) = sub.subcommand() {
                args.push(form_command.to_string());
                match form_command {
                    "define" => {
                        push_optional(&mut args, form_sub, "alias");
                        push_option(&mut args, form_sub, "name", "--name");
                        push_option(&mut args, form_sub, "definition-id", "--definition-id");
                        if let Some(fields) = form_sub.get_many::<String>("field") {
                            for field in fields {
                                args.push("--field".to_string());
                                args.push(field.clone());
                            }
                        }
                    }
                    "definitions" => {
                        push_option(&mut args, form_sub, "format", "--format");
                    }
                    _ => {
                        return Err(Error::InvalidInput(format!(
                            "unknown vault form command: {form_command}"
                        ))
                        .into())
                    }
                }
            } else {
                return Err(Error::InvalidInput(
                    "missing vault form command; use `lockbox vault form define` or `lockbox vault form definitions`"
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

fn session_args(matches: &ArgMatches) -> CliResult<Vec<String>> {
    let mut args = Vec::new();
    if let Some((command, sub)) = matches.subcommand() {
        args.push(command.to_string());
        match command {
            "activate" => args.push(value(sub, "lockbox")),
            "deactivate" | "close-all" | "stop" => {}
            "auto-open" => {
                if let Some((auto_command, auto_sub)) = sub.subcommand() {
                    args.push(auto_command.to_string());
                    if auto_command == "status" {
                        push_option(&mut args, auto_sub, "format", "--format");
                    } else if auto_command == "off" {
                        push_flag(&mut args, auto_sub, "yes", "--yes");
                    }
                } else {
                    args.push("status".to_string());
                }
            }
            _ => {
                return Err(
                    Error::InvalidInput(format!("unknown session command: {command}")).into(),
                )
            }
        }
    } else {
        push_option(&mut args, matches, "format", "--format");
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
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
        }
        "list" | "ls" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                0,
            )?);
            push_option(&mut args, sub, "format", "--format");
        }
        "refresh" => {
            if sub.get_flag("all") {
                args.push("--all".to_string());
                push_many(&mut args, sub, "args");
            } else {
                args.extend(optional_lockbox_positionals(
                    positional_values(sub, "args"),
                    1,
                )?);
            }
            push_flag(&mut args, sub, "dry-run", "--dry-run");
            push_flag(&mut args, sub, "yes", "--yes");
        }
        "remove" | "rm" => {
            args.extend(optional_lockbox_positionals(
                positional_values(sub, "args"),
                1,
            )?);
        }
        _ => return Err(Error::InvalidInput(format!("unknown access command: {command}")).into()),
    }
    Ok(args)
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
