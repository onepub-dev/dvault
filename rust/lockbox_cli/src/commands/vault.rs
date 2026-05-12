use super::context::{default_vault, require_arg, CliResult};
use lockbox_core::MlKemKeyPair;
use lockbox_vault::{
    default_vault_dir, export_private_key, export_public_key, import_private_key,
    import_public_key, KeyFormat, VaultDirectory,
};
use std::fs;

pub(crate) fn run(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault command")?;
    match command {
        "init" => init(),
        "path" => path(),
        "keygen" => keygen(&args[1..]),
        "import-key" => import_key(&args[1..]),
        "trust" => trust(&args[1..]),
        "remove-key" => remove_key(&args[1..]),
        "remove-trusted" => remove_trusted(&args[1..]),
        "list" => list(),
        "export-key" => export_key(&args[1..]),
        "export-public" => export_public(&args[1..]),
        _ => Err(format!("unknown vault command: {command}").into()),
    }
}

fn init() -> CliResult<()> {
    let vault = default_vault()?;
    println!("{}", vault.root().display());
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
    let name = args
        .first()
        .map(String::as_str)
        .unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    let public_path = args.get(1).map(String::as_str);
    let vault = default_vault()?;
    if vault.private_key_exists(name)? && !overwrite {
        return Err(format!("vault private key already exists: {name}").into());
    }

    let keypair = MlKemKeyPair::generate();
    vault.store_private_key(name, &keypair)?;
    if let Some(path) = public_path {
        fs::write(path, export_public_key(&keypair.recipient_key(), format)?)?;
    }
    println!("{name}");
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
        return Err(format!("trusted recipient already exists: {name}").into());
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
        return Err(format!("vault private key already exists: {name}").into());
    }
    let keypair = import_private_key(&fs::read(private_path)?)?;
    vault.store_private_key(name, &keypair)?;
    if let Some(path) = public_path {
        fs::write(
            path,
            export_public_key(&keypair.recipient_key(), KeyFormat::LockboxPem)?,
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
    for name in vault.list_private_keys()? {
        println!("private\t{name}");
    }
    for recipient in vault.list_trusted_recipients()? {
        println!("trusted\t{}", recipient.name);
    }
    Ok(())
}

fn export_public(args: &[String]) -> CliResult<()> {
    let (args, format) = parse_format(args)?;
    let (name, destination) = match args.as_slice() {
        [destination] => (VaultDirectory::DEFAULT_KEY_NAME, destination.as_str()),
        [name, destination, ..] => (name.as_str(), destination.as_str()),
        [] => return Err("missing public key path".into()),
    };
    let keypair = default_vault()?.load_private_key(name)?;
    fs::write(
        destination,
        export_public_key(&keypair.recipient_key(), format)?,
    )?;
    Ok(())
}

fn export_key(args: &[String]) -> CliResult<()> {
    let (args, format) = parse_format(args)?;
    let (name, destination) = match args.as_slice() {
        [destination] => (VaultDirectory::DEFAULT_KEY_NAME, destination.as_str()),
        [name, destination, ..] => (name.as_str(), destination.as_str()),
        [] => return Err("missing private key path".into()),
    };
    let keypair = default_vault()?.load_private_key(name)?;
    fs::write(destination, export_private_key(&keypair, format)?)?;
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
                .ok_or("missing --format value")?
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
