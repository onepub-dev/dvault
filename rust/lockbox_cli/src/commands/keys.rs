use super::context::open_existing;
use super::context::{
    read_hex_file, read_new_password, read_password, require_arg, Access, CliResult,
};
use lockbox_core::{LockboxCreate, LockboxUnlock, MlKemKeyPair, MlKemRecipientKey};
use lockbox_vault::{encode_hex, local_vault, NoopStore, Vault};
use std::fs;

pub(crate) fn create(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    match access {
        Access::RawKey(key) => {
            Vault::new(NoopStore)
                .create_lockbox(lockbox_path, LockboxCreate::RawKey(key.clone()))?;
        }
        Access::PromptPassword => {
            let password = read_new_password()?;
            local_vault().create_lockbox_with_password(lockbox_path, &password)?;
        }
        Access::CacheOnly => return Err("create requires an unlock method".into()),
    }
    Ok(())
}

pub(crate) fn open(args: &[String]) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let password = read_password("Password: ")?;
    local_vault().unlock_lockbox_with_password(lockbox_path, &password)?;
    Ok(())
}

pub(crate) fn lock(args: &[String]) -> CliResult<()> {
    if args.first().map(String::as_str) == Some("--all") {
        local_vault().lock_all()?;
    } else {
        let lockbox_path = require_arg(args, 0, "lockbox")?;
        local_vault().lock_lockbox(lockbox_path)?;
    }
    Ok(())
}

pub(crate) fn keygen(args: &[String]) -> CliResult<()> {
    let private_path = require_arg(args, 0, "private key path")?;
    let public_path = require_arg(args, 1, "public key path")?;
    let keypair = MlKemKeyPair::generate();
    write_private_key(private_path, &keypair.to_seed_bytes())?;
    fs::write(public_path, encode_hex(&keypair.recipient_key().to_bytes()))?;
    Ok(())
}

pub(crate) fn open_key(args: &[String]) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let private_path = require_arg(args, 1, "private key path")?;
    let keypair = MlKemKeyPair::from_seed_bytes(&read_hex_file(private_path)?)?;
    local_vault().unlock_lockbox(lockbox_path, LockboxUnlock::RecipientKey(keypair))?;
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
    lb.delete_key_slot_and_compact(slot_id)?;
    lb.commit()?;
    Ok(())
}

fn write_private_key(path: &str, bytes: &[u8]) -> CliResult<()> {
    fs::write(path, encode_hex(bytes))?;
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
