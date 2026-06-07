use super::context::CliResult;
use lockbox_vault::{
    agent_log_destination, default_vault_path, get_platform_vault_password, is_running,
    platform_secret_store_disabled, platform_secret_store_status, verify_agent_transport_security,
    SecretString, VaultDirectory,
};
use std::fs::OpenOptions;

pub(crate) fn run() -> CliResult<()> {
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
