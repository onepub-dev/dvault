use crate::secret_prompt::prompt_secret;
use lockbox_core::vault_bridge::VaultUnlock;
use lockbox_core::{
    Error, Lockbox, LockboxProtection, LockboxUnlock, RecipientKeyPair, RecipientPublicKey,
    SecretVec,
};
use lockbox_vault::{
    auto_open_scope, default_vault_path, forget_platform_vault_password,
    get_platform_vault_password, import_public_key, local_vault, platform_secret_store_disabled,
    put_platform_vault_password, AutoOpenScope, NoopStore, SecretString, Vault, VaultDirectory,
};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

pub(crate) type CliResult<T> = Result<T, Box<dyn std::error::Error>>;
const MIN_VAULT_PASS_PHRASE_CHARS: usize = 15;

#[derive(Debug)]
struct CliMessage(String);

impl fmt::Display for CliMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliMessage {}

pub(crate) fn cli_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(CliMessage(message.into()))
}

pub(crate) enum Access {
    ContentKey(SecretVec),
    PromptPassword,
    CacheOnly,
}

pub(crate) fn open_existing(path: &str, access: &Access) -> CliResult<Lockbox> {
    ensure_lockbox_path_accessible(path)?;
    match access {
        Access::ContentKey(key) => Ok(Vault::new(NoopStore)
            .unlock_lockbox(path, LockboxUnlock::ContentKey(key.try_clone()?))?),
        Access::PromptPassword => Err(cli_error(
            "password prompting is only used when creating a new lockbox; pass --key or open through the local vault",
        )),
        Access::CacheOnly => match local_vault().open_lockbox(path) {
            Ok(lockbox) => Ok(lockbox),
            Err(Error::VaultUnavailable(message)) if message.contains("no cached content key") => {
                match auto_open_lockbox(path) {
                    Ok(lockbox) => Ok(lockbox),
                    Err(AutoOpenLockboxError::Disabled) => Err(cli_error(format!(
                        "lockbox is closed: {path}. Run `lockbox open {path}` first."
                    ))),
                    Err(AutoOpenLockboxError::Unavailable(reason)) => Err(cli_error(format!(
                        "lockbox is closed: {path}. Auto-open could not open it: {reason}. Run `lockbox open {path}` first."
                    ))),
                }
            }
            Err(err) => Err(err.into()),
        },
    }
}

enum AutoOpenLockboxError {
    Disabled,
    Unavailable(String),
}

fn auto_open_lockbox(path: &str) -> Result<Lockbox, AutoOpenLockboxError> {
    let scope =
        auto_open_scope().map_err(|err| AutoOpenLockboxError::Unavailable(err.to_string()))?;
    if scope != AutoOpenScope::Lockboxes {
        return Err(AutoOpenLockboxError::Disabled);
    }
    let password = lockbox_core::SecretString::try_from_env("LOCKBOX_VAULT_PASSWORD")
        .map_err(|err| AutoOpenLockboxError::Unavailable(err.to_string()))?
        .or(match get_platform_vault_password() {
            Ok(password) => password,
            Err(_) => None,
        })
        .ok_or_else(|| {
            AutoOpenLockboxError::Unavailable(
                "vault pass phrase is not stored for auto-open".to_string(),
            )
        })?;
    let vault = VaultDirectory::unlock_or_create_default(&password)
        .map_err(|err| AutoOpenLockboxError::Unavailable(err.to_string()))?;
    let lockbox_id = VaultUnlock::read_lockbox_id(Path::new(path))
        .map_err(|err| AutoOpenLockboxError::Unavailable(err.to_string()))?;
    if let Some(lockbox_password) = vault
        .remembered_lockbox_password(lockbox_id)
        .map_err(|err| AutoOpenLockboxError::Unavailable(err.to_string()))?
    {
        if let Ok(lockbox) =
            Vault::new(NoopStore).unlock_lockbox_with_password(path, &lockbox_password)
        {
            let _ = local_vault().unlock_lockbox_with_password(path, &lockbox_password);
            return Ok(lockbox);
        }
    }
    let identities = vault
        .list_private_keys()
        .map_err(|err| AutoOpenLockboxError::Unavailable(err.to_string()))?;
    for identity in identities {
        let Ok(keypair) = vault.load_private_key(&identity) else {
            continue;
        };
        if let Ok(lockbox) =
            Vault::new(NoopStore).unlock_lockbox(path, LockboxUnlock::RecipientKeyPair(keypair))
        {
            if let Ok(cache_keypair) = vault.load_private_key(&identity) {
                let _ = local_vault()
                    .unlock_lockbox(path, LockboxUnlock::RecipientKeyPair(cache_keypair));
            }
            return Ok(lockbox);
        }
    }
    Err(AutoOpenLockboxError::Unavailable(
        "no remembered pass phrase or vault identity could open it".to_string(),
    ))
}

pub(crate) fn open_or_create(path: &str, access: &Access) -> CliResult<Lockbox> {
    if Path::new(path).exists() {
        open_existing(path, access)
    } else {
        match access {
            Access::ContentKey(key) => {
                let lockbox = Vault::new(NoopStore)
                    .create_lockbox(path, LockboxProtection::ContentKey(key.try_clone()?))?;
                mirror_key_directory(&lockbox, path)?;
                Ok(lockbox)
            }
            Access::PromptPassword => {
                let password = read_new_password().map_err(|err| Error::Io(err.to_string()))?;
                let lockbox = local_vault().create_lockbox_with_password(path, &password)?;
                mirror_key_directory(&lockbox, path)?;
                Ok(lockbox)
            }
            Access::CacheOnly => Err(cli_error(
                "lockbox does not exist and no creation open method was supplied",
            )),
        }
    }
}

pub(crate) fn ensure_lockbox_path_accessible(path: &str) -> CliResult<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            Err(cli_error(format!("lockbox path is a directory: {path}")))
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Err(cli_error(format!("lockbox not found: {path}")))
        }
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Err(cli_error(format!(
            "permission denied reading lockbox: {path}"
        ))),
        Err(err) => Err(cli_error(format!("cannot access lockbox {path}: {err}"))),
    }
}

pub(crate) fn require_arg<'a>(args: &'a [String], index: usize, name: &str) -> CliResult<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| Error::InvalidInput(format!("missing {name}")).into())
}

pub(crate) fn read_password(prompt: &str) -> CliResult<SecretString> {
    if let Some(password) = SecretString::try_from_env("LOCKBOX_PASSWORD")? {
        return Ok(password);
    }
    Ok(prompt_secret(prompt)?)
}

pub(crate) fn read_new_password() -> CliResult<SecretString> {
    if let Some(password) = SecretString::try_from_env("LOCKBOX_PASSWORD")? {
        return Ok(password);
    }
    let password = prompt_secret("New password: ")?;
    let mut confirm = prompt_secret("Confirm password: ")?;
    if password != confirm {
        confirm.zeroize()?;
        return Err(Error::InvalidInput("passwords do not match".to_string()).into());
    }
    confirm.zeroize()?;
    Ok(password)
}

pub(crate) fn read_vault_password(prompt: &str) -> CliResult<SecretString> {
    if let Some(password) = SecretString::try_from_env("LOCKBOX_VAULT_PASSWORD")? {
        return Ok(password);
    }
    Ok(prompt_secret(prompt)?)
}

pub(crate) fn read_new_vault_password() -> CliResult<SecretString> {
    if let Some(password) = SecretString::try_from_env("LOCKBOX_VAULT_PASSWORD")? {
        validate_new_vault_pass_phrase(&password)?;
        return Ok(password);
    }
    let password = prompt_secret("New vault pass phrase (minimum 15 characters): ")?;
    validate_new_vault_pass_phrase(&password)?;
    let mut confirm = prompt_secret("Confirm vault pass phrase: ")?;
    if password != confirm {
        confirm.zeroize()?;
        return Err(Error::InvalidInput("pass phrases do not match".to_string()).into());
    }
    confirm.zeroize()?;
    Ok(password)
}

fn validate_new_vault_pass_phrase(password: &SecretString) -> CliResult<()> {
    let chars = password.with_str(|text| text.chars().count())?;
    if chars < MIN_VAULT_PASS_PHRASE_CHARS {
        return Err(Error::InvalidInput(format!(
            "vault pass phrase must be at least {MIN_VAULT_PASS_PHRASE_CHARS} characters"
        ))
        .into());
    }
    Ok(())
}

pub(crate) fn remember_default_vault_password(password: &SecretString) -> Result<(), Error> {
    if !platform_secret_store_disabled()? {
        let _ = put_platform_vault_password(password);
    }
    Ok(())
}

pub(crate) fn default_vault() -> Result<VaultDirectory, Error> {
    if let Some(password) = SecretString::try_from_env("LOCKBOX_VAULT_PASSWORD")? {
        return VaultDirectory::unlock_or_create_default(&password);
    }

    let platform_enabled = !platform_secret_store_disabled()?;
    if platform_enabled {
        if let Ok(Some(password)) = get_platform_vault_password() {
            match VaultDirectory::unlock_or_create_default(&password) {
                Ok(vault) => return Ok(vault),
                Err(_) => {
                    let _ = forget_platform_vault_password();
                }
            }
        }
    }

    let password =
        prompt_secret("Vault pass phrase: ").map_err(|err| Error::Io(err.to_string()))?;
    let vault = VaultDirectory::unlock_or_create_default(&password)?;
    if platform_enabled {
        let _ = put_platform_vault_password(&password);
    }
    Ok(vault)
}

pub(crate) fn ensure_default_vault_initialized() -> Result<(), Error> {
    if default_vault_path()?.exists() {
        return Ok(());
    }
    Err(Error::VaultUnavailable(
        "local vault is not initialized; run `lockbox vault init` first".to_string(),
    ))
}

pub(crate) fn mirror_key_directory(lockbox: &Lockbox, path: impl AsRef<Path>) -> Result<(), Error> {
    if lockbox.list_key_slots().is_empty() {
        return Ok(());
    }
    ensure_default_vault_initialized()?;
    let vault = default_vault()?;
    let backup = VaultUnlock::export_key_directory_backup(lockbox)?;
    vault.store_key_directory_backup(lockbox.lockbox_id(), &backup)?;
    vault.remember_known_lockbox(lockbox.lockbox_id(), path)?;
    Ok(())
}

pub(crate) fn load_private_key_from_arg(arg: Option<&str>) -> CliResult<RecipientKeyPair> {
    let vault = default_vault()?;
    let name_or_path = arg.unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    Ok(vault.load_private_key(name_or_path)?)
}

pub(crate) struct ResolvedRecipient {
    pub(crate) name: Option<String>,
    pub(crate) public_key: RecipientPublicKey,
}

pub(crate) fn load_recipient_file(name: &str, path: &str) -> CliResult<ResolvedRecipient> {
    Ok(ResolvedRecipient {
        name: Some(name.to_string()),
        public_key: import_public_key(&std::fs::read(path)?)?,
    })
}

pub(crate) fn load_recipient_from_arg(arg: &str) -> CliResult<ResolvedRecipient> {
    if std::path::Path::new(arg).exists() {
        return Ok(ResolvedRecipient {
            name: None,
            public_key: import_public_key(&std::fs::read(arg)?)?,
        });
    }
    let vault = default_vault()?;
    if let Some(name) = arg.strip_prefix("identity:") {
        if name.is_empty() {
            return Err(cli_error("missing identity name after identity:"));
        }
        return Ok(ResolvedRecipient {
            name: Some(name.to_string()),
            public_key: vault.load_private_key(name)?.public_key(),
        });
    }
    if let Some(name) = arg.strip_prefix("contact:") {
        if name.is_empty() {
            return Err(cli_error("missing contact name after contact:"));
        }
        return Ok(ResolvedRecipient {
            name: Some(name.to_string()),
            public_key: vault.load_trusted_recipient(name)?,
        });
    }
    let is_identity = vault.private_key_exists(arg)?;
    let is_contact = vault.trusted_recipient_exists(arg)?;
    match (is_identity, is_contact) {
        (true, true) => Err(cli_error(format!(
            "ambiguous access target: {arg} matches both an identity and a contact. Use identity:{arg} or contact:{arg}."
        ))),
        (true, false) => Ok(ResolvedRecipient {
            name: Some(arg.to_string()),
            public_key: vault.load_private_key(arg)?.public_key(),
        }),
        (false, true) => Ok(ResolvedRecipient {
            name: Some(arg.to_string()),
            public_key: vault.load_trusted_recipient(arg)?,
        }),
        (false, false) => Err(cli_error(format!(
            "identity or contact not found: {arg}. Use a saved identity, saved contact, or pass a name with a public key file."
        ))),
    }
}
