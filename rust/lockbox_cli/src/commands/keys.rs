use super::context::open_existing;
use super::context::{
    read_hex_file, read_new_password, read_password, require_arg, Access, CliResult,
};
use crate::cache;
use lockbox_core::{Lockbox, LockboxCreate, MlKemKeyPair, MlKemRecipientKey};
use std::fs;

pub(crate) fn create(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let (lb, password) = match access {
        Access::RawKey(key) => (
            Lockbox::create_file(lockbox_path, LockboxCreate::RawKey(key.clone()))?,
            None,
        ),
        Access::PromptPassword => {
            let password = read_new_password()?;
            (
                Lockbox::create_file(
                    lockbox_path,
                    LockboxCreate::Password(password.as_bytes().to_vec()),
                )?,
                Some(password),
            )
        }
        Access::CacheOnly => return Err("create requires an unlock method".into()),
    };
    match (access, password) {
        (Access::RawKey(key), _) => cache::put(lb.lockbox_id(), key)?,
        (_, Some(password)) => {
            let unlocked = Lockbox::unlock_path_with_password(lockbox_path, password.as_bytes())?;
            cache::put(unlocked.lockbox_id, unlocked.key())?;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn open(args: &[String]) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let password = read_password("Password: ")?;
    let unlocked = Lockbox::unlock_path_with_password(lockbox_path, password.as_bytes())?;
    cache::put(unlocked.lockbox_id, unlocked.key())?;
    Ok(())
}

pub(crate) fn lock(args: &[String]) -> CliResult<()> {
    if args.first().map(String::as_str) == Some("--all") {
        cache::forget_all()?;
    } else {
        let lockbox_path = require_arg(args, 0, "lockbox")?;
        cache::forget(Lockbox::read_lockbox_id_path(lockbox_path)?)?;
    }
    Ok(())
}

pub(crate) fn keygen(args: &[String]) -> CliResult<()> {
    let private_path = require_arg(args, 0, "private key path")?;
    let public_path = require_arg(args, 1, "public key path")?;
    let keypair = MlKemKeyPair::generate();
    write_private_key(private_path, &keypair.to_seed_bytes())?;
    fs::write(
        public_path,
        cache::encode_hex(&keypair.recipient_key().to_bytes()),
    )?;
    Ok(())
}

pub(crate) fn open_key(args: &[String]) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let private_path = require_arg(args, 1, "private key path")?;
    let keypair = MlKemKeyPair::from_seed_bytes(&read_hex_file(private_path)?)?;
    let unlocked = Lockbox::unlock_path_with_recipient(lockbox_path, &keypair)?;
    cache::put(unlocked.lockbox_id, unlocked.key())?;
    Ok(())
}

pub(crate) fn add_recipient(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let public_path = require_arg(args, 1, "public key path")?;
    let recipient = MlKemRecipientKey::from_bytes(&read_hex_file(public_path)?)?;
    let mut lb = open_existing(lockbox_path, access)?;
    lb.add_recipient_key(&recipient)?;
    lb.commit()?;
    Ok(())
}

pub(crate) fn list_keys(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let lb = open_existing(lockbox_path, access)?;
    for slot in lb.list_key_slots() {
        println!("{}\t{:?}\t{}", slot.id, slot.kind, slot.algorithm);
    }
    Ok(())
}

pub(crate) fn remove_key(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let slot_id = require_arg(args, 1, "slot id")?.parse::<u64>()?;
    let mut lb = open_existing(lockbox_path, access)?;
    lb.delete_key_slot(slot_id)?;
    lb.commit()?;
    Ok(())
}

fn write_private_key(path: &str, bytes: &[u8]) -> CliResult<()> {
    fs::write(path, cache::encode_hex(bytes))?;
    set_private_key_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_key_permissions(path: &str) -> CliResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_key_permissions(_path: &str) -> CliResult<()> {
    Ok(())
}
