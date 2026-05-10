use super::context::{
    default_vault, read_hex_file, read_private_key_password, require_arg, CliResult,
};
use lockbox_core::{MlKemKeyPair, MlKemRecipientKey};
use lockbox_vault::{default_vault_dir, encode_hex, VaultDirectory};
use std::fs;

pub(crate) fn run(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault command")?;
    match command {
        "init" => init(),
        "path" => path(),
        "keygen" => keygen(&args[1..]),
        "trust" => trust(&args[1..]),
        "remove-key" => remove_key(&args[1..]),
        "remove-trusted" => remove_trusted(&args[1..]),
        "list" => list(),
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
    let password = read_private_key_password()?;
    vault.store_private_key(name, &keypair, &password)?;
    if let Some(path) = public_path {
        fs::write(path, encode_hex(&keypair.recipient_key().to_bytes()))?;
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
    let recipient = MlKemRecipientKey::from_bytes(&read_hex_file(public_path)?)?;
    vault.store_trusted_recipient(name, &recipient)?;
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
    let (name, destination) = match args {
        [destination] => (VaultDirectory::DEFAULT_KEY_NAME, destination.as_str()),
        [name, destination, ..] => (name.as_str(), destination.as_str()),
        [] => return Err("missing public key path".into()),
    };
    let password = read_private_key_password()?;
    let keypair = default_vault()?.load_private_key(name, &password)?;
    fs::write(destination, encode_hex(&keypair.recipient_key().to_bytes()))?;
    Ok(())
}
