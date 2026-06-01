use super::context::{
    default_vault, ensure_default_vault_initialized, load_private_key_from_arg,
    load_recipient_from_arg, mirror_key_directory, open_existing, read_new_password, read_password,
    require_arg, Access, CliResult,
};
use lockbox_core::vault_bridge::VaultUnlock;
use lockbox_core::{Error, LockboxProtection, LockboxUnlock, RecipientKeyPair};
use lockbox_vault::{
    encode_hex, export_private_key, list as list_open_lockboxes, local_vault, KeyFormat, NoopStore,
    SecretVec, Vault,
};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn create(args: &[String], access: &Access) -> CliResult<()> {
    if args.first().map(String::as_str) == Some("--recipient") {
        let recipient_name = require_arg(args, 1, "recipient")?;
        let lockbox_path = create_path(require_arg(args, 2, "lockbox")?)?;
        ensure_new_lockbox_path(&lockbox_path)?;
        ensure_default_vault_initialized()?;
        let _vault = default_vault()?;
        let recipient = load_recipient_from_arg(recipient_name)?;
        println!("Creating lockbox: {}", lockbox_path.display());
        let lb = Vault::new(NoopStore).create_lockbox(
            &lockbox_path,
            LockboxProtection::RecipientPublicKey(recipient),
        )?;
        mirror_key_directory(&lb)?;
        return Ok(());
    }
    let lockbox_path = create_path(require_arg(args, 0, "lockbox")?)?;
    ensure_new_lockbox_path(&lockbox_path)?;
    println!("Creating lockbox: {}", lockbox_path.display());
    match access {
        Access::ContentKey(key) => {
            let lb = Vault::new(NoopStore).create_lockbox(
                &lockbox_path,
                LockboxProtection::ContentKey(key.try_clone()?),
            )?;
            mirror_key_directory(&lb)?;
        }
        Access::PromptPassword => {
            ensure_default_vault_initialized()?;
            let _vault = default_vault()?;
            let password = read_new_password()?;
            let lb = local_vault().create_lockbox_with_password(&lockbox_path, &password)?;
            mirror_key_directory(&lb)?;
        }
        Access::CacheOnly => {
            return Err(Error::InvalidInput("create requires an unlock method".to_string()).into());
        }
    }
    Ok(())
}

pub(crate) fn open(args: &[String]) -> CliResult<()> {
    if args.first().map(String::as_str) == Some("--list") {
        list_open()?;
        return Ok(());
    }
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let password = read_password("Password: ")?;
    let lb = local_vault().unlock_lockbox_with_password(lockbox_path, &password)?;
    mirror_key_directory(&lb)?;
    println!("Lockbox opened: {lockbox_path}");
    Ok(())
}

pub(crate) fn lock(args: &[String]) -> CliResult<()> {
    if args.first().map(String::as_str) == Some("--all") {
        local_vault().lock_all()?;
        println!("All lockboxes closed.");
    } else {
        let lockbox_path = require_arg(args, 0, "lockbox")?;
        let was_open = lockbox_is_open(lockbox_path);
        local_vault().lock_lockbox(lockbox_path)?;
        if was_open {
            println!("Lockbox closed: {lockbox_path}");
        } else {
            println!("Lockbox was already closed: {lockbox_path}");
        }
    }
    Ok(())
}

fn lockbox_is_open(lockbox_path: &str) -> bool {
    let Ok(lockbox_id) = VaultUnlock::read_lockbox_id(Path::new(lockbox_path)) else {
        return false;
    };
    list_open_lockboxes()
        .map(|ids| ids.iter().any(|id| id == &lockbox_id.to_string()))
        .unwrap_or(false)
}

pub(crate) fn list_open() -> CliResult<()> {
    let ids = list_open_lockboxes()?;
    if ids.is_empty() {
        println!("empty");
    } else {
        for id in ids {
            println!("open\t{id}");
        }
    }
    Ok(())
}

pub(crate) fn keygen(args: &[String]) -> CliResult<()> {
    let private_path = require_arg(args, 0, "private key path")?;
    let public_path = require_arg(args, 1, "public key path")?;
    let keypair = RecipientKeyPair::generate()?;
    write_private_key(
        private_path,
        &export_private_key(&keypair, KeyFormat::RawHex)?,
    )?;
    fs::write(public_path, encode_hex(&keypair.public_key().to_bytes()))?;
    Ok(())
}

pub(crate) fn open_key(args: &[String]) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let keypair = load_private_key_from_arg(args.get(1).map(String::as_str))?;
    let lb =
        local_vault().unlock_lockbox(lockbox_path, LockboxUnlock::RecipientKeyPair(keypair))?;
    mirror_key_directory(&lb)?;
    Ok(())
}

pub(crate) fn add_recipient(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let recipient_arg = require_arg(args, 1, "recipient")?;
    let recipient = load_recipient_from_arg(recipient_arg)?;
    let mut lb = open_existing(lockbox_path, access)?;
    lb.add_recipient(&recipient)?;
    lb.commit()?;
    mirror_key_directory(&lb)?;
    Ok(())
}

pub(crate) fn list_keys(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let lb = open_existing(lockbox_path, access)?;
    for slot in lb.list_key_slots() {
        println!("{}\t{:?}\t{}", slot.id, slot.protection, slot.algorithm);
    }
    Ok(())
}

pub(crate) fn remove_key(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let slot_id = require_arg(args, 1, "slot id")?.parse::<u64>()?;
    let mut lb = open_existing(lockbox_path, access)?;
    lb.delete_key(slot_id)?;
    lb.commit()?;
    mirror_key_directory(&lb)?;
    Ok(())
}

pub(crate) fn recipient(args: &[String], access: &Access) -> CliResult<()> {
    let command = require_arg(args, 0, "recipient command")?;
    match command {
        "add" => add_recipient(&args[1..], access),
        "list" | "ls" => list_keys(&args[1..], access),
        "remove" | "rm" => remove_key(&args[1..], access),
        _ => Err(Error::InvalidInput(format!("unknown recipient command: {command}")).into()),
    }
}

fn write_private_key(path: &str, bytes: &SecretVec) -> CliResult<()> {
    use std::io::Write;

    let mut file = create_private_key_file(path)?;
    bytes.with_bytes(|bytes| file.write_all(bytes))??;
    Ok(())
}

fn create_path(path: &str) -> CliResult<PathBuf> {
    let mut path = PathBuf::from(path);
    if path.extension().is_none() {
        path.set_extension("lbox");
    }
    Ok(path)
}

fn ensure_new_lockbox_path(path: &Path) -> CliResult<()> {
    if path.exists() {
        return Err(Error::AlreadyExists(path.display().to_string()).into());
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_key_file(path: &str) -> CliResult<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    set_private_key_permissions(path)?;
    Ok(file)
}

#[cfg(not(unix))]
fn create_private_key_file(path: &str) -> CliResult<fs::File> {
    fs::File::create(path).map_err(Into::into)
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
