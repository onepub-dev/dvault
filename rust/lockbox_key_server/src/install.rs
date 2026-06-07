use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::server_log::server_log_destination;

const UNIT_PATH: &str = "/etc/systemd/system/lockbox_key_server.service";
const CONFIG_DIR: &str = "/etc/lockbox";
const CONFIG_PATH: &str = "/etc/lockbox/key-server.toml";
const STATE_DIR: &str = "/var/lib/lockbox-key-server";
const CACHE_DIR: &str = "/var/cache/lockbox-key-server";
const LOG_DIR: &str = "/var/log/lockbox-key-server";
const LOG_FILE: &str = "/var/log/lockbox-key-server/server.log";
const USER: &str = "lockbox-share";

pub fn install_systemd(force_config: bool) -> Result<(), Box<dyn std::error::Error>> {
    require_root()?;
    ensure_user()?;
    fs::create_dir_all(CONFIG_DIR)?;
    fs::create_dir_all(STATE_DIR)?;
    fs::create_dir_all(CACHE_DIR)?;
    fs::create_dir_all(LOG_DIR)?;
    set_dir_permissions(CONFIG_DIR, 0o755)?;
    set_dir_permissions(STATE_DIR, 0o750)?;
    set_dir_permissions(CACHE_DIR, 0o750)?;
    set_dir_permissions(LOG_DIR, 0o750)?;
    chown_path(STATE_DIR)?;
    chown_path(CACHE_DIR)?;
    chown_path(LOG_DIR)?;
    if force_config || !Path::new(CONFIG_PATH).exists() {
        fs::write(CONFIG_PATH, default_config())?;
        set_file_permissions(CONFIG_PATH, 0o640)?;
    }
    fs::write(
        UNIT_PATH,
        unit_file(&std::env::current_exe()?.display().to_string()),
    )?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "lockbox_key_server.service"])?;
    run("systemctl", &["restart", "lockbox_key_server.service"])?;
    println!("installed lockbox_key_server systemd service");
    Ok(())
}

pub fn uninstall_systemd(purge_data: bool) -> Result<(), Box<dyn std::error::Error>> {
    require_root()?;
    let _ = run("systemctl", &["stop", "lockbox_key_server.service"]);
    let _ = run("systemctl", &["disable", "lockbox_key_server.service"]);
    if Path::new(UNIT_PATH).exists() {
        fs::remove_file(UNIT_PATH)?;
    }
    run("systemctl", &["daemon-reload"])?;
    if purge_data {
        let _ = fs::remove_dir_all(STATE_DIR);
        let _ = fs::remove_dir_all(CACHE_DIR);
        let _ = fs::remove_dir_all(LOG_DIR);
        let _ = fs::remove_file(CONFIG_PATH);
    }
    println!("uninstalled lockbox_key_server systemd service");
    Ok(())
}

pub fn print_status() -> Result<(), Box<dyn std::error::Error>> {
    println!("unit_path={UNIT_PATH}");
    println!("unit_installed={}", Path::new(UNIT_PATH).exists());
    println!(
        "unit_enabled={}",
        systemctl_value(&["is-enabled", "lockbox_key_server.service"])
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "unit_active={}",
        systemctl_value(&["is-active", "lockbox_key_server.service"])
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("config_path={CONFIG_PATH}");
    println!("config_exists={}", Path::new(CONFIG_PATH).exists());
    println!("state_path={STATE_DIR}");
    println!("state_exists={}", Path::new(STATE_DIR).exists());
    println!("service_log={LOG_FILE}");
    println!("foreground_log={}", server_log_destination());
    println!(
        "unit_exec_start={}",
        systemctl_value(&[
            "show",
            "lockbox_key_server.service",
            "--property=ExecStart",
            "--value"
        ])
        .unwrap_or_else(|| "unknown".to_string())
    );
    std::io::stdout().flush()?;
    Ok(())
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc_geteuid() } != 0 {
        return Err("install/uninstall must be run as root".into());
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(not(unix))]
unsafe fn libc_geteuid() -> u32 {
    1
}

fn ensure_user() -> Result<(), Box<dyn std::error::Error>> {
    if Command::new("id").arg("-u").arg(USER).status()?.success() {
        return Ok(());
    }
    run(
        "useradd",
        &[
            "--system",
            "--home-dir",
            STATE_DIR,
            "--shell",
            "/usr/sbin/nologin",
            USER,
        ],
    )
}

fn run(command: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(command).args(args).status()?;
    if !status.success() {
        return Err(format!("{command} failed with {status}").into());
    }
    Ok(())
}

fn systemctl_value(args: &[&str]) -> Option<String> {
    let output = Command::new("systemctl").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn chown_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    run("chown", &[&format!("{USER}:{USER}"), path])
}

#[cfg(unix)]
fn set_dir_permissions(path: &str, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &str, _mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &str, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &str, _mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn default_config() -> &'static str {
    "bind_addr = \"0.0.0.0:8089\"\n\
state_dir = \"/var/lib/lockbox-key-server\"\n\
server_id = 0\n\
cluster_id = \"default\"\n\
public_url = \"https://keyshare.onepub.dev/v1/share\"\n\
topology_version = 1\n\
topology_server = \"0=https://keyshare.onepub.dev/v1/share,active\"\n\
route = \"0=0\"\n\
origin_epoch = 1\n\
default_ttl_seconds = 900\n\
max_ttl_seconds = 900\n\
max_payload_bytes = 8192\n\
max_fetches_per_share = 8\n\
rate_limit_per_minute = 120\n\
rate_limit_burst = 40\n\
verification_email_command = \"\"\n\
verification_email_rate_limit_per_hour = 5\n\
verification_email_ip_rate_limit_per_hour = 30\n"
}

fn unit_file(binary: &str) -> String {
    format!(
        "[Unit]
Description=reVault Key Rendezvous Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={USER}
Group={USER}
ExecStart={binary} run --config {CONFIG_PATH}
Restart=always
RestartSec=2
Environment=LOCKBOX_KEY_SERVER_LOG={LOG_FILE}
StandardOutput=append:{LOG_FILE}
StandardError=append:{LOG_FILE}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths={STATE_DIR} {CACHE_DIR} {LOG_DIR}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"
    )
}

#[cfg(test)]
mod tests {
    use super::{default_config, unit_file, CONFIG_PATH, LOG_FILE};

    #[test]
    fn unit_runs_from_config_and_restarts_on_boot_failures() {
        let unit = unit_file("/usr/local/bin/lockbox_key_server");
        assert!(unit.contains("ExecStart=/usr/local/bin/lockbox_key_server run --config "));
        assert!(unit.contains(CONFIG_PATH));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains(&format!("Environment=LOCKBOX_KEY_SERVER_LOG={LOG_FILE}")));
        assert!(unit.contains(&format!("StandardOutput=append:{LOG_FILE}")));
        assert!(unit.contains(&format!("StandardError=append:{LOG_FILE}")));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(!unit.contains("--state-dir"));
    }

    #[test]
    fn default_config_includes_public_single_server_topology() {
        let config = default_config();
        assert!(config.contains("server_id = 0"));
        assert!(config.contains("public_url = \"https://keyshare.onepub.dev/v1/share\""));
        assert!(
            config.contains("topology_server = \"0=https://keyshare.onepub.dev/v1/share,active\"")
        );
        assert!(config.contains("route = \"0=0\""));
    }
}
