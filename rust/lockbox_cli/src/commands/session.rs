use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use lockbox_core::Error;
use lockbox_vault::{
    get_platform_vault_password, list as list_open_lockboxes, local_vault,
    platform_secret_store_status, put_platform_vault_password, set_auto_open_scope,
    stop as stop_agent, verify_agent_transport_security, AutoOpenScope, VaultDirectory,
};

use super::context::{ensure_lockbox_path_accessible, read_vault_password, require_arg, CliResult};
use super::output::{output_format_from_args, print_records};

pub(crate) fn run(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("activate") => activate(&args[1..]),
        Some("deactivate") => {
            clear_active_lockbox()?;
            println!("Active lockbox cleared.");
            Ok(())
        }
        Some("close-all") => {
            local_vault().lock_all()?;
            clear_active_lockbox()?;
            println!("All lockbox sessions closed.");
            Ok(())
        }
        Some("stop") => {
            stop_agent()?;
            clear_active_lockbox()?;
            println!("Session agent stopped.");
            Ok(())
        }
        Some("auto-open") => auto_open(&args[1..]),
        _ => list_sessions(args),
    }
}

fn activate(args: &[String]) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    ensure_lockbox_path_accessible(lockbox_path)?;
    let lockbox_path = fs::canonicalize(lockbox_path)?;
    let lockbox_path = lockbox_path.to_string_lossy().into_owned();
    write_active_lockbox(&lockbox_path)?;
    println!("Active lockbox: {lockbox_path}");
    Ok(())
}

fn list_sessions(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let agent_enabled = agent_enabled();
    let agent_running = lockbox_vault::is_running();
    let auto_open = platform_secret_store_status()?;
    let vault_pass_phrase_stored = platform_vault_pass_phrase_stored();
    if !matches!(format, super::output::OutputFormat::Table) {
        let active = active_lockbox()?;
        let mut rows = Vec::new();
        rows.push(vec![
            "agent".to_string(),
            "enabled".to_string(),
            yes_no(agent_enabled).to_string(),
            String::new(),
            String::new(),
        ]);
        rows.push(vec![
            "agent".to_string(),
            "running".to_string(),
            yes_no(agent_running).to_string(),
            String::new(),
            String::new(),
        ]);
        rows.push(vec![
            "auto-open".to_string(),
            "scope".to_string(),
            auto_open.scope.as_str().to_string(),
            String::new(),
            String::new(),
        ]);
        rows.push(vec![
            "auto-open".to_string(),
            "vault pass phrase stored".to_string(),
            yes_no(vault_pass_phrase_stored).to_string(),
            String::new(),
            String::new(),
        ]);
        rows.push(vec![
            "lockbox".to_string(),
            "active".to_string(),
            if active.is_some() { "yes" } else { "no" }.to_string(),
            active.clone().unwrap_or_default(),
            String::new(),
        ]);
        for lockbox in list_open_lockboxes()? {
            let path = lockbox.path.unwrap_or_default();
            rows.push(vec![
                "lockbox".to_string(),
                "open".to_string(),
                if active.as_deref() == Some(path.as_str()) {
                    "yes".to_string()
                } else {
                    "no".to_string()
                },
                path,
                lockbox.id,
            ]);
        }
        print_records(&["kind", "state", "value", "path", "uuid"], rows, format)?;
        return Ok(());
    }

    println!("Session agent:");
    println!("  enabled: {}", yes_no(agent_enabled));
    println!("  running: {}", yes_no(agent_running));
    println!();
    println!("Auto-open:");
    println!("  scope: {}", auto_open.scope.as_str());
    println!(
        "  vault pass phrase stored: {}",
        yes_no(vault_pass_phrase_stored)
    );
    println!();
    println!("Active lockbox:");
    match active_lockbox()? {
        Some(path) => println!("  {path}"),
        None => println!("  none"),
    }
    println!();
    println!("Open lockboxes:");
    let open = list_open_lockboxes()?;
    if open.is_empty() {
        println!("  none");
    } else {
        for lockbox in open {
            println!("  {}", lockbox.path.unwrap_or(lockbox.id));
        }
    }
    Ok(())
}

fn auto_open(args: &[String]) -> CliResult<()> {
    let command = args.first().map(String::as_str).unwrap_or("status");
    match command {
        "status" => auto_open_status(&args[1..]),
        "off" => {
            if !confirm_auto_open_off(&args[1..])? {
                println!("Auto-open not disabled.");
                return Ok(());
            }
            set_auto_open_scope(AutoOpenScope::Off)?;
            local_vault().lock_all()?;
            clear_active_lockbox()?;
            auto_open_status(&[])
        }
        "vault" => {
            let password = read_vault_password("Vault pass phrase: ")?;
            VaultDirectory::unlock_or_create_default(&password)?;
            set_auto_open_scope(AutoOpenScope::Vault)?;
            let _ = put_platform_vault_password(&password);
            local_vault().lock_all()?;
            auto_open_status(&[])
        }
        "lockboxes" => {
            let password = read_vault_password("Vault pass phrase: ")?;
            VaultDirectory::unlock_or_create_default(&password)?;
            set_auto_open_scope(AutoOpenScope::Lockboxes)?;
            let _ = put_platform_vault_password(&password);
            local_vault().lock_all()?;
            auto_open_status(&[])
        }
        _ => {
            Err(Error::InvalidInput(format!("unknown session auto-open command: {command}")).into())
        }
    }
}

fn confirm_auto_open_off(args: &[String]) -> CliResult<bool> {
    let yes = args.iter().any(|arg| arg == "--yes");
    let unexpected = args
        .iter()
        .find(|arg| !matches!(arg.as_str(), "--yes"))
        .map(String::as_str);
    if let Some(arg) = unexpected {
        return Err(
            Error::InvalidInput(format!("unknown session auto-open off option: {arg}")).into(),
        );
    }
    if yes {
        return Ok(true);
    }

    eprintln!("Disable auto-open?");
    eprintln!("The stored vault pass phrase will be removed from the OS key store.");
    eprintln!("All open lockbox sessions will be closed.");
    eprint!("Type 'yes' to disable auto-open: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}

fn auto_open_status(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let status = platform_secret_store_status()?;
    let stored = platform_vault_pass_phrase_stored();
    print_records(
        &["property", "value"],
        vec![
            vec![
                "supported".to_string(),
                yes_no(status.supported).to_string(),
            ],
            vec!["scope".to_string(), status.scope.as_str().to_string()],
            vec![
                "vault pass phrase stored".to_string(),
                yes_no(stored).to_string(),
            ],
            vec!["backend".to_string(), status.backend.to_string()],
            vec!["vault".to_string(), status.item],
        ],
        format,
    )?;
    Ok(())
}

fn agent_enabled() -> bool {
    verify_agent_transport_security().is_ok()
}

fn platform_vault_pass_phrase_stored() -> bool {
    get_platform_vault_password()
        .map(|password| password.is_some())
        .unwrap_or(false)
}

fn active_lockbox() -> CliResult<Option<String>> {
    let path = active_lockbox_path()?;
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value.trim_end_matches('\n').to_string())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub(crate) fn clear_active_lockbox() -> CliResult<()> {
    match fs::remove_file(active_lockbox_path()?) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

fn write_active_lockbox(lockbox_path: &str) -> CliResult<()> {
    let path = active_lockbox_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{lockbox_path}\n"))?;
    Ok(())
}

fn active_lockbox_path() -> CliResult<PathBuf> {
    Ok(lockbox_vault::default_vault_dir()?.join(".active-lockbox"))
}

pub(crate) fn active_lockbox_or_none() -> CliResult<Option<String>> {
    active_lockbox()
}

pub(crate) fn deactivate_if_active(path: &str) -> CliResult<()> {
    let Some(active) = active_lockbox()? else {
        return Ok(());
    };
    if active == path || canonical_path_matches(&active, path) {
        clear_active_lockbox()?;
    }
    Ok(())
}

fn canonical_path_matches(active: &str, path: &str) -> bool {
    fs::canonicalize(path)
        .map(|path| path == Path::new(active))
        .unwrap_or(false)
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
