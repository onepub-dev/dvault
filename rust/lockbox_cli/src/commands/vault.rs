use super::context::{
    default_vault, read_new_vault_password, read_vault_password, remember_default_vault_password,
    require_arg, CliResult,
};
use lockbox_core::{Error, RecipientKeyPair};
use lockbox_vault::{
    default_vault_dir, default_vault_path, disable_platform_secret_store,
    enable_platform_secret_store, export_private_key, export_public_key,
    forget_platform_vault_password, import_private_key_file, import_public_key,
    platform_secret_store_status, KeyFormat, VaultDirectory,
};
use std::fs;
use std::io::Write;

pub(crate) fn run(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault command")?;
    match command {
        "init" => init(&args[1..]),
        "path" => path(),
        "keygen" => keygen(&args[1..]),
        "import-key" => import_key(&args[1..]),
        "trust" => trust(&args[1..]),
        "remove-key" => remove_key(&args[1..]),
        "remove-trusted" => remove_trusted(&args[1..]),
        "platform-store" => platform_store(&args[1..]),
        "list" => list(),
        "export-key" => export_key(&args[1..]),
        "export-public" => export_public(&args[1..]),
        _ => Err(Error::InvalidInput(format!("unknown vault command: {command}")).into()),
    }
}

fn platform_store(args: &[String]) -> CliResult<()> {
    let command = args.first().map(String::as_str).unwrap_or("status");
    match command {
        "status" => platform_store_status(),
        "enable" => {
            enable_platform_secret_store()?;
            platform_store_status()
        }
        "disable" => {
            disable_platform_secret_store()?;
            platform_store_status()
        }
        "forget" => {
            forget_platform_vault_password()?;
            Ok(())
        }
        _ => Err(
            Error::InvalidInput(format!("unknown vault platform-store command: {command}")).into(),
        ),
    }
}

fn platform_store_status() -> CliResult<()> {
    let status = platform_secret_store_status()?;
    println!("backend\t{}", status.backend);
    println!("supported\t{}", yes_no(status.supported));
    println!("disabled\t{}", yes_no(status.disabled));
    println!("item\t{}", status.item);
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
            println!("WARNING: replacing it will remove local private keys, trusted public keys,");
            println!("and key-directory backups stored only in this vault.");
            let password = read_new_vault_password()?;
            fs::remove_file(&path)?;
            let vault = VaultDirectory::open_default(&password)?;
            let generated = ensure_default_private_key(&vault)?;
            remember_default_vault_password(&password)?;
            println!("Vault replaced successfully.");
            if generated {
                println!(
                    "Generated default private/public key: {}",
                    VaultDirectory::DEFAULT_KEY_NAME
                );
            }
            return Ok(());
        }
        if verify {
            let password = read_vault_password("Vault password: ")?;
            let vault = VaultDirectory::open_default(&password)?;
            remember_default_vault_password(&password)?;
            println!("Vault opened successfully.");
            println!("Directory: {}", vault.root().display());
            return Ok(());
        }
        println!("No changes made. Use `lockbox vault init --verify` to validate it.");
        println!("Use `lockbox vault init --overwrite` only when replacing the vault.");
        return Ok(());
    } else {
        println!("This will create the local Lockbox vault.");
        println!("Path: {}", path.display());
        println!();
        println!("The vault stores your private keys, trusted public keys, and");
        println!("key-directory backups for lockboxes you create or share.");
        println!();
        println!("Choose a vault password you can back up safely. If you lose it,");
        println!("Lockbox cannot recover the private keys stored in this vault.");
    }
    let password = read_new_vault_password()?;
    let vault = VaultDirectory::open_default(&password)?;
    let generated = ensure_default_private_key(&vault)?;
    remember_default_vault_password(&password)?;
    println!("Vault created successfully.");
    if generated {
        println!(
            "Generated default private/public key: {}",
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
        return Err(Error::AlreadyExists(format!("vault private key {name}")).into());
    }

    let keypair = RecipientKeyPair::generate()?;
    vault.store_private_key(name, &keypair)?;
    if let Some(path) = public_path {
        fs::write(path, export_public_key(&keypair.public_key(), format)?)?;
    }
    if defaulted_name {
        println!("Using default vault key name: {name}");
    }
    println!("Generated vault private key: {name}");
    if let Some(path) = public_path {
        println!("Public key written: {path}");
    } else {
        println!(
            "Export the public key with: lockbox vault export-public {name} <public-key-output>"
        );
    }
    Ok(())
}

fn trust(args: &[String]) -> CliResult<()> {
    let overwrite = args.iter().any(|arg| arg == "--overwrite");
    let args = args
        .iter()
        .filter(|arg| arg.as_str() != "--overwrite")
        .cloned()
        .collect::<Vec<_>>();
    let name = require_arg(&args, 0, "recipient name")?;
    let public_path = require_arg(&args, 1, "public key path")?;
    let vault = default_vault()?;
    if vault.trusted_recipient_exists(name)? && !overwrite {
        return Err(Error::AlreadyExists(format!("trusted recipient {name}")).into());
    }
    let recipient = import_public_key(&fs::read(public_path)?)?;
    vault.store_trusted_recipient(name, &recipient)?;
    Ok(())
}

fn import_key(args: &[String]) -> CliResult<()> {
    let name = require_arg(args, 0, "key name")?;
    let private_path = require_arg(args, 1, "private key path")?;
    let public_path = args.get(2).map(String::as_str);
    let vault = default_vault()?;
    if vault.private_key_exists(name)? {
        return Err(Error::AlreadyExists(format!("vault private key {name}")).into());
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
    let name = args
        .first()
        .map(String::as_str)
        .unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    default_vault()?.delete_private_key(name)?;
    Ok(())
}

fn remove_trusted(args: &[String]) -> CliResult<()> {
    let name = require_arg(args, 0, "recipient name")?;
    default_vault()?.delete_trusted_recipient(name)?;
    Ok(())
}

fn list() -> CliResult<()> {
    let vault = default_vault()?;
    let mut printed = false;
    for name in vault.list_private_keys()? {
        println!("private\t{name}");
        println!("public\t{name}");
        printed = true;
    }
    for recipient in vault.list_trusted_recipients()? {
        println!("trusted\t{}", recipient.name);
        printed = true;
    }
    if !printed {
        println!("empty");
    }
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
    let (name, destination) = match args.as_slice() {
        [destination] => (VaultDirectory::DEFAULT_KEY_NAME, destination.as_str()),
        [name, destination, ..] => (name.as_str(), destination.as_str()),
        [] => return Err(Error::InvalidInput("missing public key path".to_string()).into()),
    };
    let keypair = default_vault()?.load_private_key(name)?;
    fs::write(
        destination,
        export_public_key(&keypair.public_key(), format)?,
    )?;
    Ok(())
}

fn export_key(args: &[String]) -> CliResult<()> {
    let (args, format) = parse_format(args)?;
    let (name, destination) = match args.as_slice() {
        [destination] => (VaultDirectory::DEFAULT_KEY_NAME, destination.as_str()),
        [name, destination, ..] => (name.as_str(), destination.as_str()),
        [] => return Err(Error::InvalidInput("missing private key path".to_string()).into()),
    };
    let keypair = default_vault()?.load_private_key(name)?;
    write_private_key(destination, &export_private_key(&keypair, format)?)?;
    Ok(())
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
