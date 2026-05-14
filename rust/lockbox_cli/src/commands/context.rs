use crate::secret_prompt::prompt_secret;
use lockbox_core::{Error, Lockbox, LockboxCreate, LockboxUnlock, MlKemKeyPair, MlKemRecipientKey};
use lockbox_vault::{
    import_public_key, local_vault, NoopStore, SecretString, Vault, VaultDirectory,
};
use std::env;
use std::path::Path;

pub(crate) type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(crate) enum Access {
    RawKey(Vec<u8>),
    PromptPassword,
    CacheOnly,
}

pub(crate) fn read_access(args: &mut Vec<String>) -> CliResult<Access> {
    if args.first().map(String::as_str) == Some("--key") {
        if args.len() < 2 {
            return Err("missing --key value".into());
        }
        args.remove(0);
        return Ok(Access::RawKey(args.remove(0).into_bytes()));
    }
    env::var("LOCKBOX_KEY")
        .map(|key| Access::RawKey(key.into_bytes()))
        .or_else(|_| {
            if args.first().map(String::as_str) == Some("create") {
                Ok(Access::PromptPassword)
            } else {
                Ok(Access::CacheOnly)
            }
        })
}

pub(crate) fn open_existing(path: &str, access: &Access) -> Result<Lockbox, Error> {
    match access {
        Access::RawKey(key) => {
            Vault::new(NoopStore).unlock_lockbox(path, LockboxUnlock::RawKey(key.clone()))
        }
        Access::PromptPassword => Err(Error::InvalidKey),
        Access::CacheOnly => local_vault().open_lockbox(path),
    }
}

pub(crate) fn open_or_create(path: &str, access: &Access) -> Result<Lockbox, Error> {
    if Path::new(path).exists() {
        open_existing(path, access)
    } else {
        match access {
            Access::RawKey(key) => {
                let lockbox = Vault::new(NoopStore)
                    .create_lockbox(path, LockboxCreate::RawKey(key.clone()))?;
                mirror_key_directory(&lockbox)?;
                Ok(lockbox)
            }
            Access::PromptPassword => {
                let password = read_new_password().map_err(|err| Error::Io(err.to_string()))?;
                let lockbox = local_vault().create_lockbox_with_password(path, &password)?;
                mirror_key_directory(&lockbox)?;
                Ok(lockbox)
            }
            Access::CacheOnly => Err(Error::InvalidKey),
        }
    }
}

pub(crate) fn require_arg<'a>(args: &'a [String], index: usize, name: &str) -> CliResult<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}").into())
}

pub(crate) fn remove_global_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(index) = args.iter().position(|arg| arg == flag) {
        args.remove(index);
        true
    } else {
        false
    }
}

pub(crate) fn read_password(prompt: &str) -> CliResult<SecretString> {
    if let Ok(password) = env::var("LOCKBOX_PASSWORD") {
        return Ok(SecretString::from_bytes(password.into_bytes()));
    }
    Ok(prompt_secret(prompt)?)
}

pub(crate) fn read_vault_password() -> CliResult<SecretString> {
    if let Ok(password) = env::var("LOCKBOX_VAULT_PASSWORD") {
        return Ok(SecretString::from_bytes(password.into_bytes()));
    }
    Ok(prompt_secret("Vault password: ")?)
}

pub(crate) fn read_new_password() -> CliResult<SecretString> {
    if let Ok(password) = env::var("LOCKBOX_PASSWORD") {
        return Ok(SecretString::from_bytes(password.into_bytes()));
    }
    let password = prompt_secret("New password: ")?;
    let mut confirm = prompt_secret("Confirm password: ")?;
    if password.expose_bytes() != confirm.expose_bytes() {
        confirm.zeroize();
        return Err("passwords do not match".into());
    }
    confirm.zeroize();
    Ok(password)
}

pub(crate) fn default_vault() -> Result<VaultDirectory, Error> {
    let password = read_vault_password().map_err(|err| Error::Io(err.to_string()))?;
    VaultDirectory::open_default(&password)
}

pub(crate) fn mirror_key_directory(lockbox: &Lockbox) -> Result<(), Error> {
    if lockbox.list_key_slots().is_empty() {
        return Ok(());
    }
    let vault = default_vault()?;
    vault.store_key_directory_backup(
        lockbox.lockbox_id(),
        &lockbox.export_key_directory_backup()?,
    )
}

pub(crate) fn load_private_key_from_arg(arg: Option<&str>) -> CliResult<MlKemKeyPair> {
    let vault = default_vault()?;
    let name_or_path = arg.unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    Ok(vault.load_private_key(name_or_path)?)
}

pub(crate) fn load_recipient_from_arg(arg: &str) -> CliResult<MlKemRecipientKey> {
    if std::path::Path::new(arg).exists() {
        return Ok(import_public_key(&std::fs::read(arg)?)?);
    }
    let vault = default_vault()?;
    if let Ok(recipient) = vault.load_trusted_recipient(arg) {
        return Ok(recipient);
    }
    Ok(vault.load_private_key(arg)?.recipient_key())
}
