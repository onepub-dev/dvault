use super::context::{default_vault, read_hex_file, require_arg, CliResult};
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
    let name = args
        .first()
        .map(String::as_str)
        .unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    let public_path = args.get(1).map(String::as_str);
    let vault = default_vault()?;
    if vault.private_key_exists(name)? {
        return Err(format!("vault private key already exists: {name}").into());
    }

    let keypair = MlKemKeyPair::generate();
    vault.store_private_key(name, &keypair)?;
    if let Some(path) = public_path {
        fs::write(path, encode_hex(&keypair.recipient_key().to_bytes()))?;
    }
    println!("{name}");
    Ok(())
}

fn trust(args: &[String]) -> CliResult<()> {
    let name = require_arg(args, 0, "recipient name")?;
    let public_path = require_arg(args, 1, "public key path")?;
    let recipient = MlKemRecipientKey::from_bytes(&read_hex_file(public_path)?)?;
    default_vault()?.store_trusted_recipient(name, &recipient)?;
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
    let keypair = default_vault()?.load_private_key(name)?;
    fs::write(destination, encode_hex(&keypair.recipient_key().to_bytes()))?;
    Ok(())
}
