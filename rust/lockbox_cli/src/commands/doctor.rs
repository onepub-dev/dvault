use super::context::{cli_error, require_arg, CliResult};
use lockbox_core::{Error, Lockbox, LockboxFileInspection, LockboxKeySlotProtection};
use lockbox_vault::{
    agent_log_destination, default_vault_path, get_platform_vault_password, is_running, list,
    local_vault, platform_secret_store_disabled, platform_secret_store_status,
    verify_agent_transport_security, SecretString, VaultDirectory,
};
use std::fs::OpenOptions;
use std::path::Path;

pub(crate) fn run(args: &[String]) -> CliResult<()> {
    if args.is_empty() {
        return run_global();
    }
    if args.len() > 1 {
        return Err(cli_error("doctor accepts at most one lockbox path"));
    }
    run_lockbox(require_arg(args, 0, "lockbox")?)
}

fn run_global() -> CliResult<()> {
    let vault_path = default_vault_path()?;
    println!("reVault");
    println!("  version: {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Local vault");
    println!("  path: {}", vault_path.display());
    println!("  exists: {}", yes_no(vault_path.exists()));
    println!(
        "  readable: {}",
        yes_no(std::fs::File::open(&vault_path).is_ok())
    );
    println!(
        "  writable: {}",
        yes_no(if vault_path.exists() {
            OpenOptions::new().append(true).open(&vault_path).is_ok()
        } else {
            vault_path
                .parent()
                .and_then(|parent| parent.metadata().ok())
                .map(|metadata| !metadata.permissions().readonly())
                .unwrap_or(false)
        })
    );
    println!();
    let auto_unlock = platform_secret_store_status()?;
    println!("Auto-unlock");
    println!("  supported: {}", yes_no(auto_unlock.supported));
    println!("  enabled: {}", yes_no(!auto_unlock.disabled));
    println!("  backend: {}", auto_unlock.backend);
    println!();
    println!("Session agent");
    println!(
        "  transport security: {}",
        if verify_agent_transport_security().is_ok() {
            "ok"
        } else {
            "unsupported"
        }
    );
    println!("  running: {}", yes_no(is_running()));
    println!("  log: {}", agent_log_destination());
    println!();
    println!("Known lockboxes");
    match default_vault_noninteractive() {
        Ok(Some(vault)) => {
            let known = vault.list_known_lockboxes()?;
            let mut present = 0usize;
            let mut missing = Vec::new();
            let mut inaccessible = Vec::new();
            for lockbox in known {
                match std::fs::metadata(&lockbox.path) {
                    Ok(_) => present += 1,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        missing.push(lockbox.path)
                    }
                    Err(_) => inaccessible.push(lockbox.path),
                }
            }
            println!("  present: {present}");
            println!("  missing: {}", missing.len());
            println!("  inaccessible: {}", inaccessible.len());
            if !missing.is_empty() {
                println!("  missing paths:");
                for path in missing {
                    println!("    {path}");
                    println!("      run: lockbox vault lockbox forget {path}");
                }
            }
        }
        Ok(None) => {
            println!("  not checked: vault is locked");
        }
        Err(err) => {
            println!("  not checked: {err}");
        }
    }
    Ok(())
}

fn run_lockbox(lockbox_path: &str) -> CliResult<()> {
    let path = Path::new(lockbox_path);
    let metadata = std::fs::metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            cli_error(format!("lockbox not found: {lockbox_path}"))
        } else if err.kind() == std::io::ErrorKind::PermissionDenied {
            cli_error(format!("permission denied reading lockbox: {lockbox_path}"))
        } else {
            cli_error(format!("cannot access lockbox {lockbox_path}: {err}"))
        }
    })?;
    if metadata.is_dir() {
        return Err(cli_error(format!(
            "lockbox path is a directory: {lockbox_path}"
        )));
    }

    let inspection = Lockbox::inspect_file(path)?;
    println!("Lockbox");
    println!("  path: {lockbox_path}");
    println!("  readable: {}", yes_no(std::fs::File::open(path).is_ok()));
    println!("  size: {} bytes", metadata.len());
    println!("  id: {}", inspection.lockbox_id);
    println!("  header: {}", header_status(&inspection));
    println!();
    print_access_methods(&inspection);
    println!();
    print_lockbox_session(&inspection);
    println!();
    print_lockbox_vault(&inspection);
    println!();
    print_open_checks(path, lockbox_path);
    Ok(())
}

fn print_access_methods(inspection: &LockboxFileInspection) {
    let password_count = inspection
        .key_slots
        .iter()
        .filter(|slot| slot.protection == LockboxKeySlotProtection::Password)
        .count();
    let recipient_count = inspection
        .key_slots
        .iter()
        .filter(|slot| slot.protection == LockboxKeySlotProtection::Recipient)
        .count();
    println!("Access methods");
    println!("  pass phrase slots: {password_count}");
    println!("  recipient-key slots: {recipient_count}");
    println!(
        "  key directory: {}",
        if inspection.key_directory_copy_count == 0 {
            "not found".to_string()
        } else {
            format!(
                "generation {}, {} readable copy/copies",
                inspection.key_directory_generation, inspection.key_directory_copy_count
            )
        }
    );
    if !inspection.key_slots.is_empty() {
        println!("  slots:");
        for slot in &inspection.key_slots {
            println!(
                "    {}: {} {}",
                slot.id,
                slot_protection(slot.protection),
                slot.name.as_deref().unwrap_or("-")
            );
        }
    }
}

fn print_lockbox_session(inspection: &LockboxFileInspection) {
    println!("Session");
    match list() {
        Ok(lockboxes) => {
            let cached = lockboxes
                .iter()
                .find(|lockbox| lockbox.id == inspection.lockbox_id.to_string());
            println!("  unlocked: {}", yes_no(cached.is_some()));
            if let Some(cached) = cached.and_then(|lockbox| lockbox.path.as_deref()) {
                println!("  cached path: {cached}");
            }
        }
        Err(err) => {
            println!("  unlocked: unknown");
            println!("  session check: {err}");
        }
    }
}

fn print_lockbox_vault(inspection: &LockboxFileInspection) {
    println!("Local vault");
    match default_vault_noninteractive() {
        Ok(Some(vault)) => {
            println!("  unlocked: yes");
            println!(
                "  key-directory backup: {}",
                yes_no(
                    vault
                        .load_key_directory_backup(inspection.lockbox_id)
                        .is_ok()
                )
            );
            match vault.list_private_keys() {
                Ok(keys) => println!("  identities: {}", keys.len()),
                Err(err) => println!("  identities: not checked: {err}"),
            }
        }
        Ok(None) => {
            println!("  unlocked: no");
            println!("  key-directory backup: not checked");
        }
        Err(err) => {
            println!("  unlocked: no");
            println!("  key-directory backup: not checked: {err}");
        }
    }
}

fn print_open_checks(path: &Path, lockbox_path: &str) {
    println!("Open checks");
    match local_vault().open_lockbox(path) {
        Ok(lockbox) => {
            let inspector = lockbox.inspector();
            println!("  unlocked: yes");
            match inspector.storage_len() {
                Ok(len) => println!("  storage length: {len} bytes"),
                Err(err) => println!("  storage length: not checked: {err}"),
            }
            match inspector.inspect_pages() {
                Ok(pages) => println!("  pages: {}", pages.len()),
                Err(err) => println!("  pages: not checked: {err}"),
            }
            let report = inspector.recovery_report();
            println!("  intact files: {}", report.intact_file_count);
            println!("  partial files: {}", report.partial_files);
        }
        Err(Error::VaultUnavailable(message)) if message.contains("no cached content key") => {
            println!("  unlocked: no");
            println!("  additional checks require an unlocked lockbox.");
            println!("  run: lockbox unlock {lockbox_path}");
            println!("  then: lockbox doctor {lockbox_path}");
        }
        Err(err) => {
            println!("  unlocked: no");
            println!("  additional checks unavailable: {err}");
            println!("  run after unlocking: lockbox doctor {lockbox_path}");
        }
    }
}

fn header_status(inspection: &LockboxFileInspection) -> &'static str {
    if inspection.header_readable {
        "ok"
    } else {
        "corrupt; recovered key-directory metadata"
    }
}

fn slot_protection(protection: LockboxKeySlotProtection) -> &'static str {
    match protection {
        LockboxKeySlotProtection::Password => "pass phrase",
        LockboxKeySlotProtection::Recipient => "recipient key",
        _ => "unknown",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn default_vault_noninteractive() -> Result<Option<VaultDirectory>, Box<dyn std::error::Error>> {
    if let Some(password) = SecretString::try_from_env("LOCKBOX_VAULT_PASSWORD")? {
        return Ok(Some(VaultDirectory::unlock_or_create_default(&password)?));
    }
    if !platform_secret_store_disabled()? {
        if let Ok(Some(password)) = get_platform_vault_password() {
            return Ok(Some(VaultDirectory::unlock_or_create_default(&password)?));
        }
    }
    Ok(None)
}
