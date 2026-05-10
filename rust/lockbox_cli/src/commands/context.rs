use crate::cache;
use lockbox_core::{Error, Lockbox, LockboxCreate, LockboxUnlock};
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
        Access::RawKey(key) => Lockbox::open_file(path, LockboxUnlock::RawKey(key.clone())),
        Access::PromptPassword => Err(Error::InvalidKey),
        Access::CacheOnly => {
            let lockbox_id = Lockbox::read_lockbox_id_path(path)?;
            let Some(key) = cache::get(lockbox_id).map_err(|err| Error::Io(err.to_string()))?
            else {
                return Err(Error::InvalidKey);
            };
            Lockbox::open_file(path, LockboxUnlock::RawKey(key))
        }
    }
}

pub(crate) fn open_or_create(path: &str, access: &Access) -> Result<Lockbox, Error> {
    if Path::new(path).exists() {
        open_existing(path, access)
    } else {
        match access {
            Access::RawKey(key) => Lockbox::create_file(path, LockboxCreate::RawKey(key.clone())),
            Access::PromptPassword => {
                let password = read_new_password().map_err(|err| Error::Io(err.to_string()))?;
                Lockbox::create_file(path, LockboxCreate::Password(password.into_bytes()))
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

pub(crate) fn read_password(prompt: &str) -> CliResult<String> {
    if let Ok(password) = env::var("LOCKBOX_PASSWORD") {
        return Ok(password);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

pub(crate) fn read_new_password() -> CliResult<String> {
    if let Ok(password) = env::var("LOCKBOX_PASSWORD") {
        return Ok(password);
    }
    let password = rpassword::prompt_password("New password: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err("passwords do not match".into());
    }
    Ok(password)
}

pub(crate) fn read_hex_file(path: &str) -> CliResult<Vec<u8>> {
    let text = std::fs::read_to_string(path)?;
    Ok(cache::decode_hex(text.trim())?)
}
