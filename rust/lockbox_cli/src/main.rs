mod cache;

use lockbox_core::{
    Error, ExtractPolicy, ListOptions, Lockbox, MlKemKeyPair, MlKemRecipientKey,
    RecoveryReportOptions,
};
use std::env;
use std::fs::{self, File};
use std::io;
use std::path::Path;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("__agent") {
        return Ok(cache::serve_agent()?);
    }
    let verbose_help =
        remove_global_flag(&mut args, "--verbose") || remove_global_flag(&mut args, "-v");
    if remove_global_flag(&mut args, "--help") || remove_global_flag(&mut args, "-h") {
        usage(verbose_help);
        return Ok(());
    }
    if args.is_empty() {
        usage(verbose_help);
        return Ok(());
    }
    let access = read_access(&mut args)?;
    let Some(command) = args.first().cloned() else {
        usage(verbose_help);
        return Ok(());
    };
    args.remove(0);

    match command.as_str() {
        "create" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let (mut lb, password) = match &access {
                Access::RawKey(key) => (Lockbox::create(key), None),
                Access::PromptPassword => {
                    let password = read_new_password()?;
                    (
                        Lockbox::create_with_password(password.as_bytes())?,
                        Some(password),
                    )
                }
                Access::CacheOnly => return Err("create requires an unlock method".into()),
            };
            lb.commit()?;
            match (&access, password) {
                (Access::RawKey(key), _) => cache::put(lb.lockbox_id(), key)?,
                (_, Some(password)) => {
                    let unlocked =
                        Lockbox::unlock_with_password(&lb.to_bytes(), password.as_bytes())?;
                    cache::put(unlocked.lockbox_id, unlocked.key())?;
                }
                _ => {}
            }
            fs::write(lockbox_path, lb.to_bytes())?;
        }
        "open" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let bytes = fs::read(lockbox_path)?;
            let password = read_password("Password: ")?;
            let unlocked = Lockbox::unlock_with_password(&bytes, password.as_bytes())?;
            cache::put(unlocked.lockbox_id, unlocked.key())?;
        }
        "lock" => {
            if args.first().map(String::as_str) == Some("--all") {
                cache::forget_all()?;
            } else {
                let lockbox_path = require_arg(&args, 0, "lockbox")?;
                let bytes = fs::read(lockbox_path)?;
                cache::forget(Lockbox::read_lockbox_id(&bytes)?)?;
            }
        }
        "keygen" => {
            let private_path = require_arg(&args, 0, "private key path")?;
            let public_path = require_arg(&args, 1, "public key path")?;
            let keypair = MlKemKeyPair::generate();
            write_private_key(private_path, &keypair.to_seed_bytes())?;
            fs::write(
                public_path,
                cache::encode_hex(&keypair.recipient_key().to_bytes()),
            )?;
        }
        "open-key" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let private_path = require_arg(&args, 1, "private key path")?;
            let bytes = fs::read(lockbox_path)?;
            let keypair = MlKemKeyPair::from_seed_bytes(&read_hex_file(private_path)?)?;
            let unlocked = Lockbox::unlock_with_recipient(&bytes, &keypair)?;
            cache::put(unlocked.lockbox_id, unlocked.key())?;
        }
        "add-recipient" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let public_path = require_arg(&args, 1, "public key path")?;
            let recipient = MlKemRecipientKey::from_bytes(&read_hex_file(public_path)?)?;
            let mut lb = open_existing(lockbox_path, &access)?;
            lb.add_recipient_key(&recipient)?;
            lb.commit()?;
            fs::write(lockbox_path, lb.to_bytes())?;
        }
        "list-keys" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let lb = open_existing(lockbox_path, &access)?;
            for slot in lb.list_key_slots() {
                println!("{}\t{:?}\t{}", slot.id, slot.kind, slot.algorithm);
            }
        }
        "remove-key" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let slot_id = require_arg(&args, 1, "slot id")?.parse::<u64>()?;
            let mut lb = open_existing(lockbox_path, &access)?;
            lb.remove_key_slot_and_compact(slot_id)?;
            fs::write(lockbox_path, lb.to_bytes())?;
        }
        "add" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let source = require_arg(&args, 1, "source")?;
            let path = require_arg(&args, 2, "lockbox path")?;
            let mut lb = open_or_create(lockbox_path, &access)?;
            add_source_path(&mut lb, Path::new(source), path)?;
            lb.commit()?;
            fs::write(lockbox_path, lb.to_bytes())?;
        }
        "extract" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let lb = open_existing(lockbox_path, &access)?;
            if args.get(1).map(String::as_str) == Some("--to") {
                let dest = require_arg(&args, 2, "destination")?;
                let policy = extract_policy_from_args(&args[3..]);
                lb.extract_to_directory(dest, &policy)?;
            } else {
                let path = require_arg(&args, 1, "lockbox path")?;
                let dest = require_arg(&args, 2, "destination")?;
                let mut file = File::create(dest)?;
                lb.write_file_to(path, &mut file)?;
            }
        }
        "cat" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let path = require_arg(&args, 1, "lockbox path")?;
            let lb = open_existing(lockbox_path, &access)?;
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            lb.write_file_to(path, &mut lock)?;
        }
        "list" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let path = args.get(1).map(String::as_str).unwrap_or("/");
            let lb = open_existing(lockbox_path, &access)?;
            for entry in lb.list_iter(ListOptions::new(path))? {
                let entry = entry?;
                println!("{}\t{}\t{}", kind_name(&entry.kind), entry.len, entry.path);
            }
        }
        "rm" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let path = require_arg(&args, 1, "lockbox path")?;
            let mut lb = open_existing(lockbox_path, &access)?;
            lb.delete(path)?;
            lb.commit()?;
            fs::write(lockbox_path, lb.to_bytes())?;
        }
        "rename" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let from = require_arg(&args, 1, "from")?;
            let to = require_arg(&args, 2, "to")?;
            let mut lb = open_existing(lockbox_path, &access)?;
            lb.rename(from, to)?;
            lb.commit()?;
            fs::write(lockbox_path, lb.to_bytes())?;
        }
        "env" => run_env(&args, &access)?,
        "recover" => {
            let lockbox_path = require_arg(&args, 0, "lockbox")?;
            let bytes = fs::read(lockbox_path)?;
            let report = match &access {
                Access::RawKey(key) => Lockbox::recover(bytes, key),
                Access::CacheOnly => open_existing(lockbox_path, &access)?.recover_current(),
                Access::PromptPassword => return Err("recover requires an unlocked lockbox".into()),
            };
            print!("{}", report.render(&RecoveryReportOptions::default()));
        }
        _ => usage(verbose_help),
    }
    Ok(())
}

fn run_env(args: &[String], access: &Access) -> CliResult<()> {
    let subcommand = require_arg(args, 0, "env command")?;
    let lockbox_path = require_arg(args, 1, "lockbox")?;
    match subcommand {
        "set" => {
            let name = require_arg(args, 2, "name")?;
            let value = require_arg(args, 3, "value")?;
            let mut lb = open_or_create(lockbox_path, access)?;
            lb.set_env(name, value)?;
            lb.commit()?;
            fs::write(lockbox_path, lb.to_bytes())?;
        }
        "get" => {
            let name = require_arg(args, 2, "name")?;
            let lb = open_existing(lockbox_path, access)?;
            if let Some(value) = lb.get_env(name)? {
                println!("{value}");
            }
        }
        "list" => {
            let lb = open_existing(lockbox_path, access)?;
            for name in lb.list_env() {
                println!("{name}");
            }
        }
        "export" => {
            let lb = open_existing(lockbox_path, access)?;
            for (name, value) in lb.get_all_env() {
                println!("{name}={}", shell_quote(&value));
            }
        }
        "rm" => {
            let name = require_arg(args, 2, "name")?;
            let mut lb = open_existing(lockbox_path, access)?;
            lb.remove_env(name)?;
            lb.commit()?;
            fs::write(lockbox_path, lb.to_bytes())?;
        }
        _ => usage(false),
    }
    Ok(())
}

enum Access {
    RawKey(Vec<u8>),
    PromptPassword,
    CacheOnly,
}

fn read_access(args: &mut Vec<String>) -> CliResult<Access> {
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

fn create_lockbox(access: &Access) -> Result<Lockbox, Error> {
    match access {
        Access::RawKey(key) => Ok(Lockbox::create(key)),
        Access::PromptPassword => {
            let password = read_new_password().map_err(|err| Error::Io(err.to_string()))?;
            Lockbox::create_with_password(password.as_bytes())
        }
        Access::CacheOnly => Err(Error::InvalidKey),
    }
}

fn open_existing(path: &str, access: &Access) -> Result<Lockbox, Error> {
    let bytes = fs::read(path).map_err(|err| Error::Io(err.to_string()))?;
    match access {
        Access::RawKey(key) => Lockbox::open(bytes, key),
        Access::PromptPassword => Err(Error::InvalidKey),
        Access::CacheOnly => {
            let lockbox_id = Lockbox::read_lockbox_id(&bytes)?;
            let Some(key) = cache::get(lockbox_id).map_err(|err| Error::Io(err.to_string()))?
            else {
                return Err(Error::InvalidKey);
            };
            Lockbox::open(bytes, key)
        }
    }
}

fn open_or_create(path: &str, access: &Access) -> Result<Lockbox, Error> {
    if Path::new(path).exists() {
        open_existing(path, access)
    } else {
        create_lockbox(access)
    }
}

fn require_arg<'a>(args: &'a [String], index: usize, name: &str) -> CliResult<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}").into())
}

fn remove_global_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(index) = args.iter().position(|arg| arg == flag) {
        args.remove(index);
        true
    } else {
        false
    }
}

fn read_password(prompt: &str) -> CliResult<String> {
    if let Ok(password) = env::var("LOCKBOX_PASSWORD") {
        return Ok(password);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

fn read_new_password() -> CliResult<String> {
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

fn kind_name(kind: &lockbox_core::EntryKind) -> &'static str {
    match kind {
        lockbox_core::EntryKind::File => "file",
        lockbox_core::EntryKind::Symlink => "symlink",
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn read_hex_file(path: &str) -> CliResult<Vec<u8>> {
    let text = fs::read_to_string(path)?;
    Ok(cache::decode_hex(text.trim())?)
}

fn extract_policy_from_args(args: &[String]) -> ExtractPolicy {
    let mut policy = ExtractPolicy::default();
    for arg in args {
        match arg.as_str() {
            "--overwrite" => policy.overwrite = true,
            "--restore-symlinks" => policy.restore_symlinks = true,
            "--restore-permissions" => policy.restore_permissions = true,
            _ => {}
        }
    }
    policy
}

fn add_source_path(lockbox: &mut Lockbox, source: &Path, lockbox_root: &str) -> CliResult<()> {
    if source.is_file() {
        let file = File::open(source)?;
        lockbox.put_file_from_reader(lockbox_root, file)?;
        return Ok(());
    }
    if source.is_dir() {
        add_directory(lockbox, source, source, lockbox_root)?;
        return Ok(());
    }
    Err(format!("unsupported source path: {}", source.display()).into())
}

fn add_directory(
    lockbox: &mut Lockbox,
    root: &Path,
    current: &Path,
    lockbox_root: &str,
) -> CliResult<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            add_directory(lockbox, root, &path, lockbox_root)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root)?;
            let logical_path = join_logical_path(lockbox_root, relative)?;
            let file = File::open(&path)?;
            lockbox.put_file_from_reader(&logical_path, file)?;
        }
    }
    Ok(())
}

fn join_logical_path(lockbox_root: &str, relative: &Path) -> CliResult<String> {
    let mut out = lockbox_root.trim_end_matches('/').to_string();
    if out.is_empty() {
        out.push('/');
    }
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err("unsupported source path component".into());
        };
        let Some(part) = part.to_str() else {
            return Err("source path is not valid UTF-8".into());
        };
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(part);
    }
    Ok(out)
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

fn usage(verbose: bool) {
    eprintln!(
        "usage:
  lockbox create <lockbox>
  lockbox open <lockbox>
  lockbox add <lockbox> <source> <lockbox-path>
  lockbox extract <lockbox> <lockbox-path> <destination>
  lockbox extract <lockbox> --to <destination> [--overwrite] [--restore-permissions]
  lockbox cat <lockbox> <lockbox-path>
  lockbox list <lockbox> [path]
  lockbox rm <lockbox> <lockbox-path>
  lockbox rename <lockbox> <from> <to>
  lockbox env set|get|list|export|rm ...
  lockbox recover <lockbox>
  lockbox lock <lockbox>
  lockbox lock --all
  lockbox keygen <private-key> <public-key>
  lockbox open-key <lockbox> <private-key>
  lockbox add-recipient <lockbox> <public-key>
  lockbox list-keys <lockbox>
  lockbox remove-key <lockbox> <slot-id>"
    );

    if verbose {
        eprintln!(
            "
developer/testing:
  lockbox --key <raw-content-key> <command> ...
  LOCKBOX_KEY=<raw-content-key> lockbox <command> ...
  LOCKBOX_PASSWORD=<password> lockbox open <lockbox>
  LOCKBOX_CACHE_DIR=<dir> lockbox <command> ...

help:
  lockbox --help --verbose"
        );
    } else {
        eprintln!(
            "
Use --help --verbose to show developer and less common options."
        );
    }
}
