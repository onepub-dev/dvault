use super::context::CliResult;
use lockbox_vault::{
    default_vault_path, is_running, platform_secret_store_status, verify_agent_transport_security,
};
use std::fs::OpenOptions;

pub(crate) fn run() -> CliResult<()> {
    let vault_path = default_vault_path()?;
    println!("Lockbox");
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
    println!("  vault: {}", auto_unlock.item);
    println!();
    println!("Agent");
    println!(
        "  transport security: {}",
        if verify_agent_transport_security().is_ok() {
            "ok"
        } else {
            "unsupported"
        }
    );
    println!("  running: {}", yes_no(is_running()));
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
