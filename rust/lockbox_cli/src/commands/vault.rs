use super::context::{
    cli_error, default_vault, read_new_vault_password, read_vault_password,
    remember_default_vault_password, require_arg, CliResult,
};
use super::output::{output_format_from_args, print_records};
use lockbox_core::{Error, RecipientKeyPair};
use lockbox_vault::{
    default_vault_dir, default_vault_path, disable_platform_secret_store,
    enable_platform_secret_store, export_private_key, export_public_key,
    forget_platform_vault_password, import_private_key_file, import_public_key,
    list as list_open_lockboxes, local_vault, platform_secret_store_status, stop as stop_agent,
    KeyFormat, VaultDirectory,
};
use std::fs;
use std::io::{self, Write};

pub(crate) fn run(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault command")?;
    match command {
        "init" => init(&args[1..]),
        "path" => path(),
        "identity" => identity_command(&args[1..]),
        "contact" => contact_command(&args[1..]),
        "sessions" => sessions(&args[1..]),
        _ => Err(Error::InvalidInput(format!("unknown vault command: {command}")).into()),
    }
}

fn identity_command(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault identity command")?;
    match command {
        "list" | "ls" => list_identities(&args[1..]),
        "create" | "gen" | "generate" => keygen(&args[1..]),
        "import" => import_key(&args[1..]),
        "export" => export_key(&args[1..]),
        "export-public" => export_public(&args[1..]),
        "remove" | "rm" => remove_key(&args[1..]),
        _ => Err(Error::InvalidInput(format!("unknown vault identity command: {command}")).into()),
    }
}

fn contact_command(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("list" | "ls") => list_contacts(&args[1..]),
        Some("add") => contact_add(&args[1..]),
        Some("remove" | "rm") => remove_contact(&args[1..]),
        _ => Err(Error::InvalidInput(
            "missing vault contact command; use `lockbox vault contact list`, `lockbox vault contact add <name> <public-key>`, or `lockbox vault contact remove <name>`"
                .to_string(),
        )
        .into()),
    }
}

fn auto_unlock(args: &[String]) -> CliResult<()> {
    let command = args.first().map(String::as_str).unwrap_or("status");
    match command {
        "status" => auto_unlock_status(&args[1..]),
        "enable" => {
            enable_platform_secret_store()?;
            auto_unlock_status(&[])
        }
        "disable" => {
            disable_platform_secret_store()?;
            auto_unlock_status(&[])
        }
        "forget" => {
            forget_platform_vault_password()?;
            Ok(())
        }
        _ => Err(Error::InvalidInput(format!(
            "unknown vault sessions auto-unlock command: {command}"
        ))
        .into()),
    }
}

fn auto_unlock_status(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let status = platform_secret_store_status()?;
    print_records(
        &["property", "value"],
        vec![
            vec![
                "supported".to_string(),
                yes_no(status.supported).to_string(),
            ],
            vec!["enabled".to_string(), yes_no(!status.disabled).to_string()],
            vec!["backend".to_string(), status.backend.to_string()],
            vec!["vault".to_string(), status.item],
        ],
        format,
    )?;
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn init(args: &[String]) -> CliResult<()> {
    let overwrite = args.iter().any(|arg| arg == "--overwrite");
    let verify = args.iter().any(|arg| arg == "--verify");
    if overwrite && verify {
        return Err(Error::InvalidInput(
            "--overwrite and --verify cannot be used together".to_string(),
        )
        .into());
    }

    let path = default_vault_path()?;
    let existed = path.exists();
    if existed {
        let _ = forget_platform_vault_password();
        println!("Local vault already exists.");
        println!("Path: {}", path.display());
        if overwrite {
            println!("WARNING: replacing it will remove identities, contacts,");
            println!("and key-directory backups stored only in this vault.");
            let password = read_new_vault_password()?;
            fs::remove_file(&path)?;
            let vault = VaultDirectory::unlock_or_create_default(&password)?;
            let generated = ensure_default_private_key(&vault)?;
            remember_default_vault_password(&password)?;
            println!("Vault replaced successfully.");
            if generated {
                println!(
                    "Created default identity: {}",
                    VaultDirectory::DEFAULT_KEY_NAME
                );
            }
            return Ok(());
        }
        if verify {
            let password = read_vault_password("Vault password: ")?;
            match VaultDirectory::unlock_or_create_default(&password) {
                Ok(_) => {}
                Err(Error::InvalidKey) => {
                    return Err(cli_error(
                        "vault unlock failed: check the vault password. If the password is correct, the local vault file may be damaged",
                    ));
                }
                Err(err) => return Err(err.into()),
            };
            remember_default_vault_password(&password)?;
            println!("Vault unlocked successfully.");
            return Ok(());
        }
        println!("No changes made. Use `lockbox vault init --verify` to validate it.");
        println!("Use `lockbox vault init --overwrite` only when replacing the vault.");
        return Ok(());
    } else {
        println!("This will create the local Lockbox vault.");
        println!("Path: {}", path.display());
        println!();
        println!("The vault stores identities, contacts, and");
        println!("key-directory backups for lockboxes you create or share.");
        println!();
        println!("Choose a vault password you can back up safely. If you lose it,");
        println!("Lockbox cannot recover the private keys stored in this vault.");
    }
    let password = read_new_vault_password()?;
    let vault = VaultDirectory::unlock_or_create_default(&password)?;
    let generated = ensure_default_private_key(&vault)?;
    remember_default_vault_password(&password)?;
    println!("Vault created successfully.");
    if generated {
        println!(
            "Created default identity: {}",
            VaultDirectory::DEFAULT_KEY_NAME
        );
    }
    println!("Back up your vault password before storing important keys.");
    println!("Directory: {}", vault.root().display());
    Ok(())
}

fn path() -> CliResult<()> {
    println!("{}", default_vault_dir()?.display());
    Ok(())
}

fn keygen(args: &[String]) -> CliResult<()> {
    let (args, format) = parse_format(args)?;
    let overwrite = args.iter().any(|arg| arg == "--overwrite");
    let args = args
        .iter()
        .filter(|arg| arg.as_str() != "--overwrite")
        .cloned()
        .collect::<Vec<_>>();
    let defaulted_name = args.first().is_none();
    let name = args
        .first()
        .map(String::as_str)
        .unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    let public_path = args.get(1).map(String::as_str);
    let vault = default_vault()?;
    if vault.private_key_exists(name)? && !overwrite {
        return Err(Error::AlreadyExists(format!("vault identity {name}")).into());
    }

    let keypair = RecipientKeyPair::generate()?;
    vault.store_private_key(name, &keypair)?;
    if let Some(path) = public_path {
        fs::write(path, export_public_key(&keypair.public_key(), format)?)?;
    }
    if defaulted_name {
        println!("Using default identity name: {name}");
    }
    println!("Created vault identity: {name}");
    if let Some(path) = public_path {
        println!("Public key written: {path}");
    } else {
        println!(
            "Export its public key with: lockbox vault identity export-public {name} <public-key-output>"
        );
    }
    Ok(())
}

fn contact_add(args: &[String]) -> CliResult<()> {
    let overwrite = args.iter().any(|arg| arg == "--overwrite");
    let args = args
        .iter()
        .filter(|arg| arg.as_str() != "--overwrite")
        .cloned()
        .collect::<Vec<_>>();
    let name = require_arg(&args, 0, "contact name")?;
    let public_path = require_arg(&args, 1, "public key path")?;
    let vault = default_vault()?;
    if vault.trusted_recipient_exists(name)? && !overwrite {
        return Err(Error::AlreadyExists(format!("contact {name}")).into());
    }
    let recipient = import_public_key(&fs::read(public_path)?)?;
    vault.store_trusted_recipient(name, &recipient)?;
    Ok(())
}

fn import_key(args: &[String]) -> CliResult<()> {
    let name = require_arg(args, 0, "identity name")?;
    let private_path = require_arg(args, 1, "private key path")?;
    let public_path = args.get(2).map(String::as_str);
    let vault = default_vault()?;
    if vault.private_key_exists(name)? {
        return Err(Error::AlreadyExists(format!("vault identity {name}")).into());
    }
    let keypair = import_private_key_file(private_path)?;
    vault.store_private_key(name, &keypair)?;
    if let Some(path) = public_path {
        fs::write(
            path,
            export_public_key(&keypair.public_key(), KeyFormat::LockboxPem)?,
        )?;
    }
    Ok(())
}

fn remove_key(args: &[String]) -> CliResult<()> {
    let force = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--force" | "--noask"));
    let args = args
        .iter()
        .filter(|arg| !matches!(arg.as_str(), "--force" | "--noask"))
        .cloned()
        .collect::<Vec<_>>();
    let name = args
        .first()
        .map(String::as_str)
        .unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    if !force && !confirm_private_key_removal(name)? {
        println!("Vault identity not removed: {name}");
        return Ok(());
    }
    default_vault()?.delete_private_key(name)?;
    println!("Vault identity removed: {name}");
    Ok(())
}

fn remove_contact(args: &[String]) -> CliResult<()> {
    let name = require_arg(args, 0, "contact name")?;
    default_vault()?.delete_trusted_recipient(name)?;
    Ok(())
}

fn list_identities(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let vault = default_vault()?;
    let mut rows = Vec::new();
    for name in vault.list_private_keys()? {
        rows.push(vec![name]);
    }
    print_records(&["name"], rows, format)?;
    Ok(())
}

fn list_contacts(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let vault = default_vault()?;
    let mut rows = Vec::new();
    for recipient in vault.list_trusted_recipients()? {
        rows.push(vec![recipient.name]);
    }
    print_records(&["name"], rows, format)?;
    Ok(())
}

fn sessions(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("lock") => {
            let lockbox_path = require_arg(args, 1, "lockbox")?;
            local_vault().lock_lockbox(lockbox_path)?;
            println!("Lockbox session locked: {lockbox_path}");
            return Ok(());
        }
        Some("lock-all") => {
            local_vault().lock_all()?;
            println!("All lockbox sessions locked.");
            return Ok(());
        }
        Some("stop") => {
            stop_agent()?;
            println!("Session agent stopped.");
            return Ok(());
        }
        Some("auto-unlock") => return auto_unlock(&args[1..]),
        _ => {}
    }
    let (_, format) = output_format_from_args(args)?;
    let ids = list_open_lockboxes()?;
    let rows = ids
        .into_iter()
        .map(|lockbox| {
            vec![
                "unlocked".to_string(),
                lockbox.path.unwrap_or_default(),
                lockbox.id,
            ]
        })
        .collect::<Vec<_>>();
    print_records(&["state", "path", "uuid"], rows, format)?;
    Ok(())
}

fn ensure_default_private_key(vault: &VaultDirectory) -> CliResult<bool> {
    if vault.private_key_exists(VaultDirectory::DEFAULT_KEY_NAME)? {
        return Ok(false);
    }
    vault.store_private_key(
        VaultDirectory::DEFAULT_KEY_NAME,
        &RecipientKeyPair::generate()?,
    )?;
    Ok(true)
}

fn export_public(args: &[String]) -> CliResult<()> {
    let (args, format) = parse_format(args)?;
    let vault = default_vault()?;
    let (name, destination) = match args.as_slice() {
        [destination] => {
            if vault.private_key_exists(destination)? {
                return Err(Error::InvalidInput(format!(
                    "missing public key output path for identity {destination}"
                ))
                .into());
            }
            (VaultDirectory::DEFAULT_KEY_NAME, destination.as_str())
        }
        [name, destination, ..] => (name.as_str(), destination.as_str()),
        [] => return Err(Error::InvalidInput("missing public key path".to_string()).into()),
    };
    let keypair = vault.load_private_key(name)?;
    fs::write(
        destination,
        export_public_key(&keypair.public_key(), format)?,
    )?;
    Ok(())
}

fn export_key(args: &[String]) -> CliResult<()> {
    let (args, format) = parse_format(args)?;
    let vault = default_vault()?;
    let (name, destination) = match args.as_slice() {
        [destination] => {
            if vault.private_key_exists(destination)? {
                return Err(Error::InvalidInput(format!(
                    "missing private key output path for identity {destination}"
                ))
                .into());
            }
            (VaultDirectory::DEFAULT_KEY_NAME, destination.as_str())
        }
        [name, destination, ..] => (name.as_str(), destination.as_str()),
        [] => return Err(Error::InvalidInput("missing private key path".to_string()).into()),
    };
    let keypair = vault.load_private_key(name)?;
    write_private_key(destination, &export_private_key(&keypair, format)?)?;
    Ok(())
}

fn confirm_private_key_removal(name: &str) -> CliResult<bool> {
    eprintln!("Remove vault identity '{name}'?");
    eprintln!(
        "Lockboxes that only this private key can unlock may become inaccessible from this vault."
    );
    eprint!("Type 'yes' to remove it: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}

fn parse_format(args: &[String]) -> CliResult<(Vec<String>, KeyFormat)> {
    let mut format = KeyFormat::LockboxPem;
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == "--format" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| Error::InvalidInput("missing --format value".to_string()))?
                .as_str();
            format = KeyFormat::parse(value)?;
            index += 2;
        } else {
            out.push(args[index].clone());
            index += 1;
        }
    }
    Ok((out, format))
}

fn write_private_key(path: &str, bytes: &lockbox_vault::SecretVec) -> CliResult<()> {
    let mut file = create_private_key_file(path)?;
    bytes.with_bytes(|bytes| file.write_all(bytes))??;
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
