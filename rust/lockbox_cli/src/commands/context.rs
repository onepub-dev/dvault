use crate::secret_prompt::prompt_secret;
use lockbox_core::{Error, Lockbox, LockboxCreate, LockboxUnlock};
use lockbox_vault::{decode_hex, local_vault, NoopStore, SecretString, Vault};
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
                Vault::new(NoopStore).create_lockbox(path, LockboxCreate::RawKey(key.clone()))
            }
            Access::PromptPassword => {
                let password = read_new_password().map_err(|err| Error::Io(err.to_string()))?;
                local_vault().create_lockbox_with_password(path, &password)
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

pub(crate) fn read_hex_file(path: &str) -> CliResult<Vec<u8>> {
    let text = std::fs::read_to_string(path)?;
    Ok(decode_hex(text.trim())?)
}
