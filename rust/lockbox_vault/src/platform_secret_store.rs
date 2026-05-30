use lockbox_core::{Error, Result, SecretString};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::vault_directory::{default_vault_dir, default_vault_path};

const SERVICE: &str = "dev.onepub.lockbox.vault";
const DISABLED_MARKER: &str = ".platform-secret-store-disabled";
const MODE_ENV: &str = "LOCKBOX_PLATFORM_SECRET_STORE";

/// Current platform secret-store state for the default local vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformSecretStoreStatus {
    /// Whether the current target has a compiled platform secret-store backend.
    pub supported: bool,
    /// Whether platform secret-store use is disabled by environment or marker.
    pub disabled: bool,
    /// Human-readable backend label.
    pub backend: &'static str,
    /// Default local vault item key used in the platform store.
    pub item: String,
}

/// Returns the platform secret-store status for the default local vault.
pub fn platform_secret_store_status() -> Result<PlatformSecretStoreStatus> {
    Ok(PlatformSecretStoreStatus {
        supported: platform_supported(),
        disabled: platform_secret_store_disabled()?,
        backend: platform_backend_name(),
        item: vault_item_name()?,
    })
}

/// Enables platform secret-store lookup for the default local vault.
pub fn enable_platform_secret_store() -> Result<()> {
    remove_disabled_marker()
}

/// Disables platform secret-store lookup for the default local vault.
///
/// The stored vault unlock secret is removed before the disable marker is
/// written.
pub fn disable_platform_secret_store() -> Result<()> {
    let _ = forget_platform_vault_password();
    write_disabled_marker()
}

/// Returns true when platform secret-store lookup should not be attempted.
pub fn platform_secret_store_disabled() -> Result<bool> {
    if let Ok(value) = env::var(MODE_ENV) {
        return parse_disabled_mode(&value);
    }
    Ok(disabled_marker_path()?.exists())
}

/// Loads the default local vault password from the platform secret store.
pub fn get_platform_vault_password() -> Result<Option<SecretString>> {
    if platform_secret_store_disabled()? || !platform_supported() {
        return Ok(None);
    }
    platform_get_vault_password()
}

/// Stores the default local vault password in the platform secret store.
pub fn put_platform_vault_password(password: &SecretString) -> Result<()> {
    if platform_secret_store_disabled()? || !platform_supported() {
        return Ok(());
    }
    platform_put_vault_password(password)
}

/// Removes the default local vault password from the platform secret store.
pub fn forget_platform_vault_password() -> Result<()> {
    if !platform_supported() {
        return Ok(());
    }
    platform_forget_vault_password()
}

fn parse_disabled_mode(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "auto" | "enabled" | "enable" | "1" | "true" | "yes" | "on" => Ok(false),
        "disabled" | "disable" | "0" | "false" | "no" | "off" => Ok(true),
        other => Err(Error::Configuration(format!(
            "{MODE_ENV} must be auto or disabled, got {other}"
        ))),
    }
}

fn disabled_marker_path() -> Result<PathBuf> {
    Ok(default_vault_dir()?.join(DISABLED_MARKER))
}

fn write_disabled_marker() -> Result<()> {
    let path = disabled_marker_path()?;
    create_private_dir(path.parent().expect("marker has a parent"))?;
    fs::write(path, b"disabled\n").map_err(|err| Error::Io(err.to_string()))
}

fn remove_disabled_marker() -> Result<()> {
    let path = disabled_marker_path()?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::Io(err.to_string())),
    }
}

fn vault_item_name() -> Result<String> {
    let path = absolute_vault_path()?;
    Ok(path.to_string_lossy().into_owned())
}

fn absolute_vault_path() -> Result<PathBuf> {
    let path = default_vault_path()?;
    if path.is_absolute() {
        Ok(path)
    } else {
        env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|err| Error::Io(err.to_string()))
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|err| Error::Io(err.to_string()))?;
    set_private_dir_permissions(path)
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| Error::Io(err.to_string()))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn platform_supported() -> bool {
    true
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_supported() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn platform_backend_name() -> &'static str {
    "Secret Service/libsecret"
}

#[cfg(target_os = "macos")]
fn platform_backend_name() -> &'static str {
    "macOS Keychain"
}

#[cfg(target_os = "windows")]
fn platform_backend_name() -> &'static str {
    "Windows Credential Manager"
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_backend_name() -> &'static str {
    "unsupported"
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn platform_get_vault_password() -> Result<Option<SecretString>> {
    let entry = keyring_entry()?;
    match entry.get_secret() {
        Ok(secret) => SecretString::try_from_utf8(secret)
            .map(Some)
            .map_err(|err| Error::InvalidKeyMaterial(err.to_string())),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(platform_error(err)),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_get_vault_password() -> Result<Option<SecretString>> {
    Ok(None)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn platform_put_vault_password(password: &SecretString) -> Result<()> {
    let entry = keyring_entry()?;
    password
        .with_bytes(|bytes| entry.set_secret(bytes))
        .map_err(|err| Error::InvalidKeyMaterial(err.to_string()))?
        .map_err(platform_error)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_put_vault_password(_password: &SecretString) -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn platform_forget_vault_password() -> Result<()> {
    let entry = keyring_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(platform_error(err)),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_forget_vault_password() -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn keyring_entry() -> Result<keyring::Entry> {
    let item = vault_item_name()?;
    keyring::Entry::new(SERVICE, &item).map_err(platform_error)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn platform_error(err: keyring::Error) -> Error {
    Error::VaultUnavailable(format!("platform secret store is unavailable: {err}"))
}

#[cfg(test)]
mod tests {
    use super::parse_disabled_mode;

    #[test]
    fn platform_secret_store_mode_parses_disabled_values() {
        assert!(parse_disabled_mode("disabled").unwrap());
        assert!(parse_disabled_mode("off").unwrap());
        assert!(parse_disabled_mode("0").unwrap());
        assert!(!parse_disabled_mode("auto").unwrap());
        assert!(!parse_disabled_mode("enabled").unwrap());
    }

    #[test]
    fn platform_secret_store_mode_rejects_unknown_values() {
        assert!(parse_disabled_mode("maybe").is_err());
    }
}
