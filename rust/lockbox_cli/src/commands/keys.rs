use super::context::{
    cli_error, default_vault, ensure_default_vault_initialized, load_private_key_from_arg,
    load_recipient_file, load_recipient_from_arg, mirror_key_directory, open_existing,
    read_new_password, read_password, require_arg, Access, CliResult,
};
use super::output::{output_format_from_args, print_records};
use lockbox_core::vault_bridge::VaultUnlock;
use lockbox_core::{
    Error, Lockbox, LockboxKeySlotProtection, LockboxProtection, LockboxUnlock, RecipientKeyPair,
    RecipientPublicKey,
};
use lockbox_vault::{
    encode_hex, export_private_key, list as list_open_lockboxes, local_vault, KeyFormat, NoopStore,
    SecretVec, Vault,
};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
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
            LockboxProtection::RecipientPublicKey {
                name: recipient.name,
                recipient: recipient.public_key,
            },
        )?;
        mirror_key_directory(&lb, &lockbox_path)?;
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
            mirror_key_directory(&lb, &lockbox_path)?;
        }
        Access::PromptPassword => {
            ensure_default_vault_initialized()?;
            let _vault = default_vault()?;
            let password = read_new_password()?;
            let lb = local_vault().create_lockbox_with_password(&lockbox_path, &password)?;
            mirror_key_directory(&lb, &lockbox_path)?;
        }
        Access::CacheOnly => {
            return Err(Error::InvalidInput("create requires an unlock method".to_string()).into());
        }
    }
    Ok(())
}

pub(crate) fn unlock(args: &[String]) -> CliResult<()> {
    let options = OpenOptions::parse(args)?;
    let password = options.read_password()?;
    let lb = if let Some(ttl_seconds) = options.ttl_seconds {
        local_vault().unlock_lockbox_with_password_for_duration(
            &options.lockbox_path,
            &password,
            ttl_seconds,
        )?
    } else {
        local_vault().unlock_lockbox_with_password(&options.lockbox_path, &password)?
    };
    mirror_key_directory(&lb, &options.lockbox_path)?;
    println!("Lockbox unlocked: {}", options.lockbox_path);
    Ok(())
}

pub(crate) fn lock(args: &[String]) -> CliResult<()> {
    if args.first().map(String::as_str) == Some("--all") {
        local_vault().lock_all()?;
        println!("All lockboxes locked.");
    } else {
        let lockbox_path = require_arg(args, 0, "lockbox")?;
        let was_open = lockbox_is_open(lockbox_path);
        local_vault().lock_lockbox(lockbox_path)?;
        if was_open {
            println!("Lockbox locked: {lockbox_path}");
        } else {
            println!("Lockbox was already locked: {lockbox_path}");
        }
    }
    Ok(())
}

fn lockbox_is_open(lockbox_path: &str) -> bool {
    let Ok(lockbox_id) = VaultUnlock::read_lockbox_id(Path::new(lockbox_path)) else {
        return false;
    };
    list_open_lockboxes()
        .map(|lockboxes| {
            lockboxes
                .iter()
                .any(|lockbox| lockbox.id == lockbox_id.to_string())
        })
        .unwrap_or(false)
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

pub(crate) fn unlock_key(args: &[String]) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let keypair = load_private_key_from_arg(args.get(1).map(String::as_str))?;
    let lb =
        local_vault().unlock_lockbox(lockbox_path, LockboxUnlock::RecipientKeyPair(keypair))?;
    mirror_key_directory(&lb, lockbox_path)?;
    Ok(())
}

pub(crate) fn add_access(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let recipient_arg = require_arg(args, 1, "identity or contact")?;
    let recipient = if let Some(public_key_path) = args.get(2) {
        load_recipient_file(recipient_arg, public_key_path)?
    } else {
        if Path::new(recipient_arg).exists() {
            return Err(cli_error(
                "public key files require a contact name: lockbox access add <lockbox> <name> <public-key>",
            ));
        }
        load_recipient_from_arg(recipient_arg)?
    };
    let name = recipient.name.ok_or_else(|| {
        cli_error(
            "access entries require a name; use lockbox access add <lockbox> <name> <public-key>",
        )
    })?;
    let mut lb = open_existing(lockbox_path, access)?;
    lb.add_recipient_named(name, &recipient.public_key)?;
    lb.commit()?;
    mirror_key_directory(&lb, lockbox_path)?;
    Ok(())
}

pub(crate) fn list_keys(args: &[String], access: &Access) -> CliResult<()> {
    let (args, format) = output_format_from_args(args)?;
    let lockbox_path = require_arg(&args, 0, "lockbox")?;
    let lb = open_existing(lockbox_path, access)?;
    let mut rows = Vec::new();
    for slot in lb.list_key_slots() {
        rows.push(vec![
            slot.id.to_string(),
            slot.name.unwrap_or_else(|| "-".to_string()),
            format!("{:?}", slot.protection),
            slot.algorithm.to_string(),
        ]);
    }
    print_records(&["slot", "name", "protection", "algorithm"], rows, format)?;
    Ok(())
}

pub(crate) fn remove_access(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let slot_id = require_arg(args, 1, "slot id")?.parse::<u64>()?;
    let mut lb = open_existing(lockbox_path, access)?;
    if let Err(err) = lb.delete_key(slot_id) {
        if matches!(
            &err,
            Error::SecurityLimitExceeded(message)
                if message == "refusing to remove the last key slot"
        ) {
            return Err(cli_error(
                "cannot remove the last access entry; add another identity or contact before removing this access entry",
            ));
        }
        return Err(err.into());
    }
    lb.commit()?;
    mirror_key_directory(&lb, lockbox_path)?;
    Ok(())
}

pub(crate) fn access(args: &[String], access: &Access) -> CliResult<()> {
    let command = require_arg(args, 0, "access command")?;
    match command {
        "add" => add_access(&args[1..], access),
        "list" | "ls" => list_keys(&args[1..], access),
        "refresh" => refresh_access(&args[1..], access),
        "remove" | "rm" => remove_access(&args[1..], access),
        _ => Err(Error::InvalidInput(format!("unknown access command: {command}")).into()),
    }
}

pub(crate) fn refresh_access(args: &[String], access: &Access) -> CliResult<()> {
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    let yes = args.iter().any(|arg| arg == "--yes");
    let positional = args
        .iter()
        .filter(|arg| !matches!(arg.as_str(), "--dry-run" | "--yes"))
        .cloned()
        .collect::<Vec<_>>();
    if positional.first().map(String::as_str) == Some("--all") {
        if positional.len() > 2 {
            return Err(cli_error(
                "access refresh --all accepts at most one identity argument",
            ));
        }
        let identity = positional.get(1).map(String::as_str);
        let vault = default_vault()?;
        let identities = match identity {
            Some(identity) => vec![identity.to_string()],
            None => vault.list_private_keys()?,
        };
        if identities.is_empty() {
            return Err(cli_error("no vault identities found to refresh"));
        }
        let known = vault.list_known_lockboxes()?;
        let mut missing = Vec::new();
        let mut inaccessible = Vec::new();
        let mut targets = Vec::new();
        for lockbox in &known {
            match fs::metadata(&lockbox.path) {
                Ok(metadata) if metadata.is_dir() => {
                    inaccessible.push((
                        lockbox.path.clone(),
                        "lockbox path is a directory".to_string(),
                    ));
                    continue;
                }
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    missing.push(lockbox.path.clone());
                    continue;
                }
                Err(err) => {
                    inaccessible.push((lockbox.path.clone(), err.to_string()));
                    continue;
                }
            }
            match refresh_targets_for_lockbox(&lockbox.path, &identities, access) {
                Ok(found) => targets.extend(found),
                Err(err) => inaccessible.push((lockbox.path.clone(), err.to_string())),
            }
        }
        print_refresh_plan(
            if identity.is_some() { identity } else { None },
            Some(known.len()),
            &targets,
            &missing,
            &inaccessible,
            dry_run,
            yes,
        );
        apply_refresh_plan(&targets, access, dry_run, yes)?;
        return Ok(());
    }

    let lockbox_path = require_arg(&positional, 0, "lockbox")?;
    let identity = require_arg(&positional, 1, "identity")?;
    if positional.len() > 2 {
        return Err(cli_error(
            "access refresh requires lockbox and identity arguments",
        ));
    }
    let identities = vec![identity.to_string()];
    let targets = refresh_targets_for_lockbox(lockbox_path, &identities, access)?;
    print_refresh_plan(Some(identity), None, &targets, &[], &[], dry_run, yes);
    apply_refresh_plan(&targets, access, dry_run, yes)?;
    Ok(())
}

#[derive(Debug, Clone)]
struct RefreshTarget {
    lockbox_path: String,
    identity: String,
    slot_count: usize,
}

fn refresh_targets_for_lockbox(
    lockbox_path: &str,
    identities: &[String],
    access: &Access,
) -> CliResult<Vec<RefreshTarget>> {
    let lb = open_existing(lockbox_path, access)?;
    let mut targets = Vec::new();
    for identity in identities {
        let slot_count = matching_recipient_slot_ids(&lb, identity).len();
        if slot_count > 0 {
            targets.push(RefreshTarget {
                lockbox_path: lockbox_path.to_string(),
                identity: identity.clone(),
                slot_count,
            });
        }
    }
    Ok(targets)
}

fn matching_recipient_slot_ids(lockbox: &Lockbox, identity: &str) -> Vec<u64> {
    lockbox
        .list_key_slots()
        .into_iter()
        .filter(|slot| {
            slot.protection == LockboxKeySlotProtection::Recipient
                && slot.name.as_deref() == Some(identity)
        })
        .map(|slot| slot.id)
        .collect()
}

fn print_refresh_plan(
    identity: Option<&str>,
    known_count: Option<usize>,
    targets: &[RefreshTarget],
    missing: &[String],
    inaccessible: &[(String, String)],
    dry_run: bool,
    yes: bool,
) {
    println!("Refresh plan:");
    match identity {
        Some(identity) => println!("  identity: {identity}"),
        None => println!("  identity: all"),
    }
    if let Some(known_count) = known_count {
        println!("  known lockboxes: {known_count}");
    }
    println!("  matching lockbox/identity pairs: {}", targets.len());
    println!(
        "  matching access entries: {}",
        targets
            .iter()
            .map(|target| target.slot_count)
            .sum::<usize>()
    );
    println!("  dry run: {}", if dry_run { "yes" } else { "no" });
    println!("  apply without prompt: {}", if yes { "yes" } else { "no" });
    println!("  missing: {}", missing.len());
    println!("  inaccessible: {}", inaccessible.len());
    if !targets.is_empty() {
        println!();
        println!("Refresh targets:");
        for target in targets {
            println!(
                "  {} {} ({} access entries)",
                target.lockbox_path, target.identity, target.slot_count
            );
        }
    }
    if !missing.is_empty() {
        println!();
        println!("Missing known lockboxes:");
        for path in missing {
            println!("  {path}");
        }
    }
    if !inaccessible.is_empty() {
        println!();
        println!("Inaccessible known lockboxes:");
        for (path, reason) in inaccessible {
            println!("  {path}: {reason}");
        }
    }
}

fn apply_refresh_plan(
    targets: &[RefreshTarget],
    access: &Access,
    dry_run: bool,
    yes: bool,
) -> CliResult<()> {
    if dry_run {
        println!();
        println!("No access entries were changed.");
        return Ok(());
    }
    if targets.is_empty() {
        println!();
        println!("No matching access entries found.");
        return Ok(());
    }
    if !yes && !confirm_access_refresh(targets.len())? {
        println!();
        println!("No access entries were changed.");
        return Ok(());
    }
    let public_keys = load_refresh_public_keys(targets)?;
    let mut updated = 0usize;
    for target in targets {
        let public_key = public_keys.get(&target.identity).ok_or_else(|| {
            cli_error(format!(
                "vault identity {} was not loaded for refresh",
                target.identity
            ))
        })?;
        if refresh_lockbox_identity(&target.lockbox_path, &target.identity, public_key, access)? {
            updated += 1;
        }
    }
    println!();
    println!("Refreshed access for {updated} lockbox/identity pairs.");
    Ok(())
}

fn load_refresh_public_keys(
    targets: &[RefreshTarget],
) -> CliResult<BTreeMap<String, RecipientPublicKey>> {
    let vault = default_vault()?;
    let mut public_keys = BTreeMap::new();
    for target in targets {
        if public_keys.contains_key(&target.identity) {
            continue;
        }
        public_keys.insert(
            target.identity.clone(),
            vault.load_private_key(&target.identity)?.public_key(),
        );
    }
    Ok(public_keys)
}

fn refresh_lockbox_identity(
    lockbox_path: &str,
    identity: &str,
    public_key: &RecipientPublicKey,
    access: &Access,
) -> CliResult<bool> {
    let mut lb = open_existing(lockbox_path, access)?;
    let old_slot_ids = matching_recipient_slot_ids(&lb, identity);
    if old_slot_ids.is_empty() {
        return Ok(false);
    }
    let new_slot_id = lb.add_recipient_named(identity.to_string(), public_key)?;
    for slot_id in old_slot_ids {
        if slot_id != new_slot_id {
            lb.delete_key(slot_id)?;
        }
    }
    lb.commit()?;
    mirror_key_directory(&lb, lockbox_path)?;
    Ok(true)
}

fn confirm_access_refresh(target_count: usize) -> CliResult<bool> {
    eprintln!("Refresh access for {target_count} lockbox/identity pairs?");
    eprint!("Type 'yes' to apply: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}

fn write_private_key(path: &str, bytes: &SecretVec) -> CliResult<()> {
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

struct OpenOptions {
    lockbox_path: String,
    ttl_seconds: Option<u64>,
    password_source: PasswordSource,
}

enum PasswordSource {
    Prompt,
    Env(String),
    File(String),
    Stdin,
}

impl OpenOptions {
    fn parse(args: &[String]) -> CliResult<Self> {
        let mut positional = Vec::new();
        let mut ttl_seconds = None;
        let mut password_source = PasswordSource::Prompt;
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--duration" => {
                    index += 1;
                    let Some(value) = args.get(index).map(String::as_str) else {
                        return Err(
                            Error::InvalidInput("missing --duration value".to_string()).into()
                        );
                    };
                    ttl_seconds = Some(parse_duration(value)?);
                }
                "--password-env" => {
                    ensure_prompt_password_source(&password_source)?;
                    index += 1;
                    let Some(value) = args.get(index) else {
                        return Err(Error::InvalidInput(
                            "missing --password-env value".to_string(),
                        )
                        .into());
                    };
                    password_source = PasswordSource::Env(value.clone());
                }
                "--password-file" => {
                    ensure_prompt_password_source(&password_source)?;
                    index += 1;
                    let Some(value) = args.get(index) else {
                        return Err(Error::InvalidInput(
                            "missing --password-file value".to_string(),
                        )
                        .into());
                    };
                    password_source = PasswordSource::File(value.clone());
                }
                "--password-stdin" => {
                    ensure_prompt_password_source(&password_source)?;
                    password_source = PasswordSource::Stdin;
                }
                value => positional.push(value.to_string()),
            }
            index += 1;
        }
        let lockbox_path = positional
            .first()
            .cloned()
            .ok_or_else(|| Error::InvalidInput("missing lockbox".to_string()))?;
        if positional.len() > 1 {
            return Err(Error::InvalidInput(format!(
                "unexpected unlock argument: {}",
                positional[1]
            ))
            .into());
        }
        if ttl_seconds.is_none() {
            ttl_seconds = default_session_duration()?;
        }
        Ok(Self {
            lockbox_path,
            ttl_seconds,
            password_source,
        })
    }

    fn read_password(&self) -> CliResult<lockbox_vault::SecretString> {
        match &self.password_source {
            PasswordSource::Prompt => read_password("Password: "),
            PasswordSource::Env(name) => {
                let value = env::var(name).map_err(|_| {
                    Error::InvalidInput(format!("environment variable is not set: {name}"))
                })?;
                lockbox_vault::SecretString::try_from_bytes(value.into_bytes()).map_err(Into::into)
            }
            PasswordSource::File(path) => secret_from_bytes(
                fs::read(path)
                    .map_err(|err| Error::Io(format!("read password file {path}: {err}")))?,
            ),
            PasswordSource::Stdin => {
                let mut bytes = Vec::new();
                io::stdin().read_to_end(&mut bytes)?;
                secret_from_bytes(bytes)
            }
        }
    }
}

fn ensure_prompt_password_source(source: &PasswordSource) -> CliResult<()> {
    if matches!(source, PasswordSource::Prompt) {
        Ok(())
    } else {
        Err(
            Error::InvalidInput("choose only one password source for lockbox unlock".to_string())
                .into(),
        )
    }
}

fn secret_from_bytes(mut bytes: Vec<u8>) -> CliResult<lockbox_vault::SecretString> {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    lockbox_vault::SecretString::try_from_bytes(bytes).map_err(Into::into)
}

fn default_session_duration() -> CliResult<Option<u64>> {
    if let Ok(value) = env::var("LOCKBOX_UNLOCK_DURATION") {
        return Ok(Some(parse_duration(&value)?));
    }
    let Some(path) = session_config_path() else {
        return Ok(None);
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(None);
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if matches!(key.trim(), "unlock_duration" | "session_duration") {
            let value = value.trim().trim_matches('"').trim_matches('\'');
            return Ok(Some(parse_duration(value)?));
        }
    }
    Ok(None)
}

fn session_config_path() -> Option<PathBuf> {
    if let Ok(path) = env::var("LOCKBOX_CONFIG") {
        return Some(PathBuf::from(path));
    }
    #[cfg(target_os = "macos")]
    {
        return env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join("Library/Application Support/Lockbox/config.yaml"));
    }
    #[cfg(target_os = "windows")]
    {
        return env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Lockbox").join("config.yaml"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
            return Some(PathBuf::from(path).join("lockbox").join("config.yaml"));
        }
        return env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".config/lockbox/config.yaml"));
    }
    #[allow(unreachable_code)]
    None
}

fn parse_duration(value: &str) -> CliResult<u64> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidInput("duration cannot be empty".to_string()).into());
    }
    let split_at = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split_at);
    let amount = number
        .parse::<u64>()
        .map_err(|_| Error::InvalidInput(format!("invalid duration: {value}")))?;
    if amount == 0 {
        return Err(Error::InvalidInput("duration must be greater than zero".to_string()).into());
    }
    let multiplier = match unit {
        "" | "s" | "sec" | "secs" => 1,
        "m" | "min" | "mins" => 60,
        "h" | "hr" | "hrs" => 60 * 60,
        "d" | "day" | "days" => 24 * 60 * 60,
        _ => return Err(Error::InvalidInput(format!("invalid duration unit: {unit}")).into()),
    };
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| Error::InvalidInput(format!("duration is too large: {value}")).into())
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
