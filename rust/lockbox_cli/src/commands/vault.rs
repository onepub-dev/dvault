use super::context::{
    cli_error, default_vault, read_new_vault_password, read_replacement_vault_password,
    read_vault_password, remember_default_vault_password, require_arg, CliResult,
};
use super::form::{parse_field_spec, print_form_definition_saved};
use super::output::{output_format_from_args, print_records, OutputFormat};
use lockbox_core::{Error, Lockbox, OwnerSigningPublicKey, RecipientKeyPair, RecipientPublicKey};
use lockbox_share_protocol::{
    contact_fingerprint, normalize_contact_email, ContactShare, ShareClientPool,
    CONTACT_FINGERPRINT_LEN,
};
use lockbox_vault::{
    backup_default_vault, default_vault_dir, default_vault_path, encode_hex, export_private_key,
    export_public_key, forget_platform_vault_password, import_private_key_file, import_public_key,
    public_key_fingerprint, restore_default_vault, set_auto_open_scope, AutoOpenScope,
    IdentityGenerationStatus, KeyFormat, VaultDirectory,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SHARE_RECEIVE_VERIFICATION_ADVICE: &str = concat!(
    "verify the fingerprint by asking the publisher over a trusted channel you initiated; ",
    "if the publisher sends you the fingerprint before you ask, do not accept it"
);
const SHARE_FINGERPRINT_SECURITY_NOTE: &str = concat!(
    "use the full fingerprint; short PINs are only accidental-error checks ",
    "and are too small to authenticate a public key against substitution"
);
const FINGERPRINT_CHANNEL_PROMPT: &str = concat!(
    "How did you receive the fingerprint?\n",
    "  1) email\n",
    "  2) phone call from the key owner\n",
    "  3) phone call to the key owner\n",
    "  4) text/SMS message from the key owner\n",
    "  5) text/SMS message to the key owner\n",
    "  6) in person"
);

pub(crate) fn run(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault command")?;
    match command {
        "init" => init(&args[1..]),
        "passphrase" => change_passphrase(&args[1..]),
        "backup" => backup(&args[1..]),
        "restore" => restore(&args[1..]),
        "identity" => identity_command(&args[1..]),
        "contact" => contact_command(&args[1..]),
        "form" => form_command(&args[1..]),
        "lockbox" => lockbox_command(&args[1..]),
        _ => Err(Error::InvalidInput(format!("unknown vault command: {command}")).into()),
    }
}

fn change_passphrase(args: &[String]) -> CliResult<()> {
    if !args.is_empty() {
        return Err(
            Error::InvalidInput("vault passphrase does not accept arguments".to_string()).into(),
        );
    }
    let path = default_vault_path()?;
    if !path.exists() {
        return Err(Error::VaultUnavailable(
            "local vault is not initialized; run `lockbox vault init` first".to_string(),
        )
        .into());
    }

    let old_password = read_vault_password("Current vault pass phrase: ")?;
    match VaultDirectory::unlock_or_create_default(&old_password) {
        Ok(_) => {}
        Err(Error::InvalidKey) => {
            return Err(cli_error(
                "vault open failed: check the current vault pass phrase",
            ));
        }
        Err(err) => return Err(err.into()),
    }

    let backup_path = passphrase_change_backup_path()?;
    backup_default_vault(&backup_path, false)?;
    let new_password = read_replacement_vault_password()?;
    VaultDirectory::change_default_password(&old_password, &new_password)?;
    remember_default_vault_password(&new_password)?;

    println!("Vault pass phrase changed successfully.");
    println!("Backup:");
    println!("  {}", backup_path.display());
    Ok(())
}

fn identity_command(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault identity command")?;
    match command {
        "list" | "ls" => list_identities(&args[1..]),
        "create" | "gen" | "generate" => keygen(&args[1..]),
        "email" => identity_email(&args[1..]),
        "history" => identity_history(&args[1..]),
        "import" => import_key(&args[1..]),
        "export" => export_public(&args[1..]),
        "remove" | "rm" => remove_key(&args[1..]),
        "rotate" => rotate_key(&args[1..]),
        "publish" => share_publish(&args[1..]),
        _ => Err(Error::InvalidInput(format!("unknown vault identity command: {command}")).into()),
    }
}

fn contact_command(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("list" | "ls") => list_contacts(&args[1..]),
        Some("import") => contact_import(&args[1..]),
        Some("receive") => share_receive(&args[1..]),
        Some("remove" | "rm") => remove_contact(&args[1..]),
        _ => Err(Error::InvalidInput(
            "missing vault contact command; use `lockbox vault contact list`, `lockbox vault contact import <name> <public-key>`, `lockbox vault contact receive <share-code>`, or `lockbox vault contact remove <name>`"
                .to_string(),
        )
        .into()),
    }
}

fn lockbox_command(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("list" | "ls") => list_known_lockboxes(&args[1..]),
        Some("forget") => forget_known_lockbox(&args[1..]),
        _ => Err(Error::InvalidInput(
            "missing vault lockbox command; use `lockbox vault lockbox list` or `lockbox vault lockbox forget <lockbox>`"
                .to_string(),
        )
        .into()),
    }
}

fn form_command(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("define") => form_define(&args[1..]),
        Some("definitions") => form_definitions(&args[1..]),
        Some(command) => Err(Error::InvalidInput(format!("unknown vault form command: {command}")).into()),
        None => Err(Error::InvalidInput(
            "missing vault form command; use `lockbox vault form define` or `lockbox vault form definitions`"
                .to_string(),
        )
        .into()),
    }
}

fn form_define(args: &[String]) -> CliResult<()> {
    let mut alias = None;
    let mut name = None;
    let mut type_id = None;
    let mut fields = Vec::new();
    let mut index = 0;
    if let Some(value) = args.get(index).filter(|value| !value.starts_with("--")) {
        alias = Some(value.clone());
        name = Some(value.clone());
        index += 1;
    }
    while index < args.len() {
        match args[index].as_str() {
            "--name" => {
                index += 1;
                name = Some(require_arg(args, index, "--name value")?.to_string());
            }
            "--definition-id" | "--type-id" => {
                index += 1;
                type_id = Some(lockbox_core::FormTypeId::new(require_arg(
                    args,
                    index,
                    "--definition-id value",
                )?)?);
            }
            "--field" => {
                index += 1;
                fields.push(parse_field_spec(require_arg(
                    args,
                    index,
                    "--field value",
                )?)?);
            }
            value => {
                return Err(Error::InvalidInput(format!(
                    "unexpected vault form define argument: {value}"
                ))
                .into());
            }
        }
        index += 1;
    }
    let name = name.ok_or_else(|| {
        Error::InvalidInput("vault form define requires an alias or --name".to_string())
    })?;
    let alias = alias.unwrap_or_else(|| name.clone());
    let vault = default_vault()?;
    let definition = if let Some(type_id) = type_id {
        vault.define_form_with_type_id(type_id, &alias, &name, fields)?
    } else {
        vault.define_form(&alias, &name, fields)?
    };
    print_form_definition_saved(&definition);
    Ok(())
}

fn form_definitions(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let rows = default_vault()?
        .list_form_definitions()?
        .into_iter()
        .map(|definition| {
            vec![
                definition.alias,
                definition.type_id.to_string(),
                definition.revision.to_string(),
                definition.name,
                definition.fields.len().to_string(),
            ]
        })
        .collect::<Vec<_>>();
    print_records(
        &["alias", "definition_id", "revision", "name", "fields"],
        rows,
        format,
    )?;
    Ok(())
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
            let vault = VaultDirectory::replace_default(&password)?;
            let generated = ensure_default_private_key(&vault)?;
            let default_forms = vault.seed_default_form_definitions()?;
            set_auto_open_scope(AutoOpenScope::Lockboxes)?;
            remember_default_vault_password(&password)?;
            println!("Vault replaced successfully.");
            if generated {
                println!(
                    "Created default identity: {}",
                    VaultDirectory::DEFAULT_KEY_NAME
                );
            }
            if default_forms > 0 {
                println!("Default forms: {default_forms}");
            }
            return Ok(());
        }
        if verify {
            let password = read_vault_password("Vault pass phrase: ")?;
            match VaultDirectory::unlock_or_create_default(&password) {
                Ok(_) => {}
                Err(Error::InvalidKey) => {
                    return Err(cli_error(
                        "vault open failed: check the vault pass phrase. If the pass phrase is correct, the local vault file may be damaged",
                    ));
                }
                Err(err) => return Err(err.into()),
            };
            remember_default_vault_password(&password)?;
            println!("Vault opened successfully.");
            return Ok(());
        }
        println!("No changes made. Use `lockbox vault init --verify` to validate it.");
        println!("Use `lockbox vault init --overwrite` only when replacing the vault.");
        return Ok(());
    } else {
        println!("Create the local reVault vault.");
        println!();
        println!("Stores:");
        println!("  - identities and contacts");
        println!("  - key-directory backups for shared lockboxes");
        println!();
    }
    let password = read_new_vault_password()?;
    let vault = VaultDirectory::unlock_or_create_default(&password)?;
    let generated = ensure_default_private_key(&vault)?;
    let default_forms = vault.seed_default_form_definitions()?;
    set_auto_open_scope(AutoOpenScope::Lockboxes)?;
    remember_default_vault_password(&password)?;
    println!("Vault created successfully.");
    println!();
    println!("Directory:");
    println!("  {}", vault.root().display());
    if generated {
        println!();
        println!("Identity: {}", VaultDirectory::DEFAULT_KEY_NAME);
    }
    if default_forms > 0 {
        println!("Default forms: {default_forms}");
    }
    println!();
    println!("Pass phrase reminder:");
    println!("  Store the vault pass phrase somewhere safe.");
    println!("  If it is lost, reVault cannot recover this vault.");
    Ok(())
}

fn backup(args: &[String]) -> CliResult<()> {
    let overwrite = args.iter().any(|arg| arg == "--overwrite");
    let args = args
        .iter()
        .filter(|arg| arg.as_str() != "--overwrite")
        .cloned()
        .collect::<Vec<_>>();
    let output = require_arg(&args, 0, "backup output")?;
    let _manifest = backup_default_vault(output, overwrite)?;
    println!("Backup completed successfully.");
    println!(
        "Vault path: {}",
        absolute_path(&default_vault_path()?)?.display()
    );
    println!(
        "Backup path: {}",
        absolute_path(&PathBuf::from(output))?.display()
    );
    Ok(())
}

fn absolute_path(path: &std::path::Path) -> CliResult<PathBuf> {
    if let Ok(path) = fs::canonicalize(path) {
        return Ok(path);
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn passphrase_change_backup_path() -> CliResult<PathBuf> {
    Ok(default_vault_dir()?.join(format!(
        "local-vault-before-passphrase-change-{}.lockbox-backup",
        unix_ms_now()
    )))
}

fn restore(args: &[String]) -> CliResult<()> {
    let overwrite = args.iter().any(|arg| arg == "--overwrite");
    let args = args
        .iter()
        .filter(|arg| arg.as_str() != "--overwrite")
        .cloned()
        .collect::<Vec<_>>();
    let input = require_arg(&args, 0, "backup input")?;
    let manifest = restore_default_vault(input, overwrite)?;
    let _ = forget_platform_vault_password();
    println!("restored={input}");
    println!("vault_file={}", manifest.vault_file_name);
    println!("vault_size={}", manifest.vault_size);
    println!("vault_sha256={}", manifest.vault_sha256);
    println!("Vault restored successfully.");
    Ok(())
}

fn keygen(args: &[String]) -> CliResult<()> {
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
    let vault = default_vault()?;
    if vault.private_key_exists(name)? && !overwrite {
        return Err(Error::AlreadyExists(format!("vault identity {name}")).into());
    }

    let keypair = RecipientKeyPair::generate()?;
    vault.store_private_key(name, &keypair)?;
    if defaulted_name {
        println!("Using default identity name: {name}");
    }
    println!("Created vault identity: {name}");
    println!(
        "Export its public key with: lockbox vault identity export {name} --public <public-key-output>"
    );
    Ok(())
}

fn contact_import(args: &[String]) -> CliResult<()> {
    let options = ContactImportOptions::parse(args)?;
    let name = require_arg(&options.positionals, 0, "contact name")?;
    let public_path = require_arg(&options.positionals, 1, "public key path")?;
    let vault = default_vault()?;
    if vault.contact_exists(name)? && !options.overwrite {
        return Err(Error::AlreadyExists(format!("contact {name}")).into());
    }
    let recipient = import_public_key(&fs::read(public_path)?)?;
    let expected_fingerprint = options
        .fingerprint
        .clone()
        .map(Ok)
        .unwrap_or_else(|| prompt_line("Public key fingerprint from key owner: "))?;
    let expected_fingerprint = decode_fingerprint_hex(&expected_fingerprint)?;
    let fingerprint_channel = verify_fingerprint_channel(options.fingerprint_channel.as_deref())?;
    let computed_fingerprint = public_key_fingerprint(&recipient);
    if expected_fingerprint != computed_fingerprint {
        return Err(Error::InvalidInput(format!(
            "public key fingerprint mismatch for {name}; expected {}, computed {}",
            format_hex_pairs(&expected_fingerprint),
            format_hex_pairs(&computed_fingerprint)
        ))
        .into());
    }
    vault.store_contact(name, &recipient)?;
    println!("contact={name}");
    println!(
        "public_key_fingerprint={}",
        format_hex_pairs(&computed_fingerprint)
    );
    println!("fingerprint_verified=yes");
    println!("fingerprint_channel={fingerprint_channel}");
    Ok(())
}

#[derive(Default)]
struct ContactImportOptions {
    overwrite: bool,
    fingerprint: Option<String>,
    fingerprint_channel: Option<String>,
    positionals: Vec<String>,
}

impl ContactImportOptions {
    fn parse(args: &[String]) -> CliResult<Self> {
        let mut options = ContactImportOptions::default();
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--overwrite" => options.overwrite = true,
                "--fingerprint" => {
                    index += 1;
                    options.fingerprint =
                        Some(require_arg(args, index, "--fingerprint value")?.to_string());
                }
                "--fingerprint-channel" => {
                    index += 1;
                    options.fingerprint_channel =
                        Some(require_arg(args, index, "--fingerprint-channel value")?.to_string());
                }
                other if other.starts_with('-') => {
                    return Err(Error::InvalidInput(format!(
                        "unknown contact import option: {other}"
                    ))
                    .into());
                }
                value => options.positionals.push(value.to_string()),
            }
            index += 1;
        }
        Ok(options)
    }
}

fn share_publish(args: &[String]) -> CliResult<()> {
    let options = ShareCliOptions::parse(args)?;
    let identity = options
        .positionals
        .first()
        .map(String::as_str)
        .unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    let vault = default_vault()?;
    let keypair = vault.load_private_key(identity)?;
    let public_key = keypair.public_key().to_bytes();
    let signing_public_key = vault
        .load_owner_signing_key(identity)?
        .public_key()
        .to_bytes();
    let now = unix_ms_now();
    let ttl_seconds = options.ttl_seconds.unwrap_or(900);
    let expires_at = now.saturating_add(ttl_seconds as u64 * 1000);
    let nonce = share_nonce(identity, &public_key, now);
    if options.email.is_some() {
        return Err(Error::InvalidInput(
            "set the identity email with `lockbox vault identity email [identity] <email>` before publishing".to_string(),
        )
        .into());
    }
    let email = vault.identity_email(identity)?.ok_or_else(|| {
        cli_error(format!(
            "You may not publish a public key for an Identity that does not have an email address.\nThe identity `{identity}` has no email address.\nRun `lockbox vault identity email {identity} <email>`.\nThen run this command again."
        ))
    })?;
    let email = normalize_contact_email(&email)
        .map_err(|_| Error::InvalidInput("invalid identity email address".to_string()))?;
    let fingerprint = contact_fingerprint(&email, &public_key, &signing_public_key)
        .map_err(|_| Error::InvalidInput("invalid contact fingerprint fields".to_string()))?;
    let pool = share_client_pool(&options)?;
    let result = pool.share_contact(
        ttl_seconds,
        options.max_fetches.unwrap_or(1),
        ContactShare {
            identity,
            public_key: &public_key,
            signing_public_key: &signing_public_key,
            fingerprint: &fingerprint,
            share_nonce: &nonce,
            created_at_unix_ms: now,
            expires_at_unix_ms: expires_at,
            verification_email: Some(&email),
        },
    )?;
    println!("published=yes");
    println!("share_code={}", result.share_code);
    println!("email={email}");
    println!("contact_fingerprint={}", format_hex_pairs(&fingerprint));
    println!(
        "fingerprint_purpose=do not send this fingerprint; ask the receiver to call you to obtain it"
    );
    println!("fingerprint_security={SHARE_FINGERPRINT_SECURITY_NOTE}");
    if let Some(url) = &result.verification_url {
        println!("verification_url={url}");
    }
    println!("verification_advice=check the inbox for {email} and click the verification link");
    println!(
        "expires_at_utc={}",
        format_unix_ms_utc(result.expires_at_unix_ms)
    );
    println!("expires_at_unix_ms={}", result.expires_at_unix_ms);
    Ok(())
}

fn share_receive(args: &[String]) -> CliResult<()> {
    let options = ShareCliOptions::parse(args)?;
    let share_code = options
        .positionals
        .first()
        .cloned()
        .ok_or_else(|| Error::InvalidInput("missing share code".to_string()))?;
    let expected_fingerprint = options
        .fingerprint
        .clone()
        .map(Ok)
        .unwrap_or_else(|| prompt_line("Full fingerprint from trusted second channel: "))?;
    let expected_fingerprint = decode_fingerprint_hex(&expected_fingerprint)?;
    let fingerprint_channel = verify_fingerprint_channel(options.fingerprint_channel.as_deref())?;
    let pool = share_client_pool(&options)?;
    let fetched = pool.fetch(&share_code)?;
    let verification = fetched.email_verification.as_ref().ok_or_else(|| {
        Error::InvalidInput("publisher email has not been verified by the key server".to_string())
    })?;
    if !verification.verified {
        return Err(Error::InvalidInput(
            "publisher email has not been verified by the key server".to_string(),
        )
        .into());
    }
    let contact = lockbox_share_protocol::decode_contact_share(&fetched.payload)?;
    let computed_fingerprint = contact_fingerprint(
        &verification.email,
        &contact.public_key,
        &contact.signing_public_key,
    )
    .map_err(|_| Error::InvalidInput("invalid contact fingerprint fields".to_string()))?;
    if expected_fingerprint != computed_fingerprint {
        return Err(Error::InvalidInput(format!(
            "contact fingerprint mismatch for {}; expected {}, computed {}",
            verification.email,
            format_hex_pairs(&expected_fingerprint),
            format_hex_pairs(&computed_fingerprint)
        ))
        .into());
    }
    let contact_name = options
        .positionals
        .get(1)
        .cloned()
        .unwrap_or_else(|| contact_name_from_email(&verification.email));
    let recipient = RecipientPublicKey::from_bytes(&contact.public_key)?;
    let signing_public = OwnerSigningPublicKey::from_bytes(&contact.signing_public_key)?;
    let vault = default_vault()?;
    if vault.contact_exists(&contact_name)? && !options.overwrite {
        return Err(Error::AlreadyExists(format!("contact {contact_name}")).into());
    }
    vault.store_contact(&contact_name, &recipient)?;
    vault.store_contact_signing_key(&contact_name, &signing_public)?;
    println!("contact={contact_name}");
    println!("identity={}", contact.identity);
    println!("share_code={share_code}");
    println!("email={}", verification.email);
    println!(
        "contact_fingerprint={}",
        format_hex_pairs(&computed_fingerprint)
    );
    println!("fingerprint_verified=yes");
    println!("fingerprint_channel={fingerprint_channel}");
    println!("fingerprint_security={SHARE_FINGERPRINT_SECURITY_NOTE}");
    println!("email_verification_email={}", verification.email);
    println!("email_verification_status=verified");
    println!(
        "email_verified_at_utc={}",
        format_unix_ms_utc(verification.verified_at_unix_ms)
    );
    println!(
        "email_verification_attestation={}",
        encode_hex(&verification.attestation)
    );
    println!("verification_advice={SHARE_RECEIVE_VERIFICATION_ADVICE}");
    Ok(())
}

#[derive(Default)]
struct ShareCliOptions {
    server: Option<String>,
    topology_url: Option<String>,
    ttl_seconds: Option<u32>,
    max_fetches: Option<u16>,
    email: Option<String>,
    fingerprint: Option<String>,
    fingerprint_channel: Option<String>,
    overwrite: bool,
    positionals: Vec<String>,
}

impl ShareCliOptions {
    fn parse(args: &[String]) -> CliResult<Self> {
        let mut options = ShareCliOptions::default();
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--server" => {
                    index += 1;
                    options.server = Some(require_arg(args, index, "--server value")?.to_string());
                }
                "--topology-url" => {
                    index += 1;
                    options.topology_url =
                        Some(require_arg(args, index, "--topology-url value")?.to_string());
                }
                "--ttl" => {
                    index += 1;
                    options.ttl_seconds = Some(require_arg(args, index, "--ttl value")?.parse()?);
                }
                "--max-fetches" => {
                    index += 1;
                    options.max_fetches =
                        Some(require_arg(args, index, "--max-fetches value")?.parse()?);
                }
                "--email" | "--verification-email" => {
                    index += 1;
                    options.email = Some(require_arg(args, index, "--email value")?.to_string());
                }
                "--fingerprint" => {
                    index += 1;
                    options.fingerprint =
                        Some(require_arg(args, index, "--fingerprint value")?.to_string());
                }
                "--fingerprint-channel" => {
                    index += 1;
                    options.fingerprint_channel =
                        Some(require_arg(args, index, "--fingerprint-channel value")?.to_string());
                }
                "--overwrite" => options.overwrite = true,
                other => options.positionals.push(other.to_string()),
            }
            index += 1;
        }
        Ok(options)
    }
}

fn share_client_pool(options: &ShareCliOptions) -> CliResult<ShareClientPool> {
    if let Some(topology_url) = &options.topology_url {
        return Ok(ShareClientPool::discover(&normalize_topology_url(
            topology_url,
        ))?);
    }
    if let Some(server) = &options.server {
        return Ok(ShareClientPool::new([normalize_share_url(server)])?);
    }
    let config = read_share_config()?;
    if let Some(topology_url) = config.topology_url {
        return Ok(ShareClientPool::discover(&normalize_topology_url(
            &topology_url,
        ))?);
    }
    Ok(ShareClientPool::new([normalize_share_url(
        config.server.as_deref().unwrap_or("keyshare.onepub.dev"),
    )])?)
}

#[derive(Default)]
struct ShareConfig {
    server: Option<String>,
    topology_url: Option<String>,
}

fn read_share_config() -> CliResult<ShareConfig> {
    let path = std::env::var("LOCKBOX_SHARE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or(default_vault_dir()?.join("config.yaml"));
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(ShareConfig::default()),
        Err(err) => return Err(err.into()),
    };
    let mut in_share = false;
    let mut config = ShareConfig::default();
    for raw_line in text.lines() {
        let line = raw_line
            .split_once('#')
            .map(|(value, _)| value)
            .unwrap_or(raw_line);
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_share = line.trim() == "share:";
            continue;
        }
        if !in_share {
            continue;
        }
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "server" => config.server = Some(value),
            "topology_url" => config.topology_url = Some(value),
            _ => {}
        }
    }
    Ok(config)
}

fn normalize_share_url(value: &str) -> String {
    let value = value.trim();
    if value.starts_with("http://") || value.starts_with("https://") {
        value.to_string()
    } else {
        format!("http://{value}/v1/share")
    }
}

fn normalize_topology_url(value: &str) -> String {
    let value = value.trim();
    if value.starts_with("http://") || value.starts_with("https://") {
        value.to_string()
    } else {
        format!("http://{value}/v1/topology")
    }
}

fn share_nonce(identity: &str, public_key: &[u8], now: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(identity.as_bytes());
    hasher.update(public_key);
    hasher.update(now.to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hasher.finalize()[..24].to_vec()
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn format_unix_ms_utc(unix_ms: u64) -> String {
    let seconds = (unix_ms / 1000) as i64;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    format!("{year:04}/{month:02}/{day:02} {hour:02}:{minute:02} UTC")
}

fn contact_name_from_email(email: &str) -> String {
    let mut name = String::with_capacity(email.len());
    let mut last_underscore = false;
    for ch in email.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            name.push(ch.to_ascii_lowercase());
            last_underscore = false;
        } else {
            if !last_underscore && !name.is_empty() {
                name.push('_');
            }
            last_underscore = true;
        }
    }
    while name.ends_with('_') {
        name.pop();
    }
    name
}

fn prompt_line(prompt: &str) -> CliResult<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

fn format_hex_pairs(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            out.push(' ');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_fingerprint_hex(value: &str) -> CliResult<Vec<u8>> {
    let compact = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b':' && *byte != b'-')
        .collect::<Vec<_>>();
    let compact = String::from_utf8(compact)
        .map_err(|_| Error::InvalidInput("fingerprint is not valid UTF-8".to_string()))?;
    let fingerprint = decode_hex(&compact)?;
    if fingerprint.len() != CONTACT_FINGERPRINT_LEN {
        return Err(Error::InvalidInput(format!(
            "fingerprint must contain {CONTACT_FINGERPRINT_LEN} two-digit hex groups; short PINs are too small to authenticate a public key"
        ))
        .into());
    }
    Ok(fingerprint)
}

fn verify_fingerprint_channel(value: Option<&str>) -> CliResult<&'static str> {
    let selected = match value {
        Some(value) => value.to_string(),
        None => {
            println!("{FINGERPRINT_CHANNEL_PROMPT}");
            prompt_line("Fingerprint channel: ")?
        }
    };
    let normalized = selected
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '_', '/'], "-");
    match normalized.as_str() {
        "1" | "email" | "e-mail" => Err(Error::InvalidInput(
            "fingerprint channel rejected: email cannot be used because publisher email is already verified by the key server".to_string(),
        )
        .into()),
        "2" | "phone-call-from-owner" | "call-from-owner" | "owner-called"
        | "phone-call-from-key-owner" => Err(Error::InvalidInput(
            "fingerprint channel rejected: the receiver must initiate the fingerprint check"
                .to_string(),
        )
        .into()),
        "3" | "phone-call-to-owner" | "call-to-owner" | "called-owner"
        | "phone-call-to-key-owner" => Ok("phone-call-to-owner"),
        "4" | "text-from-owner" | "sms-from-owner" | "text-message-from-owner"
        | "sms-message-from-owner" | "text-from-key-owner" | "sms-from-key-owner" => {
            Err(Error::InvalidInput(
                "fingerprint channel rejected: the receiver must initiate the fingerprint check"
                    .to_string(),
            )
            .into())
        }
        "5" | "text-to-owner" | "sms-to-owner" | "text-message-to-owner"
        | "sms-message-to-owner" | "text-to-key-owner" | "sms-to-key-owner" => {
            Ok("sms-to-owner")
        }
        "6" | "in-person" | "inperson" | "face-to-face" => Ok("in-person"),
        _ => Err(Error::InvalidInput(format!(
            "unknown fingerprint channel: {selected}; use phone-call-to-owner, sms-to-owner, or in-person"
        ))
        .into()),
    }
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn decode_hex(value: &str) -> CliResult<Vec<u8>> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        return Err(Error::InvalidInput("hex value has odd length".to_string()).into());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let high = hex_digit(bytes[index])?;
        let low = hex_digit(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> CliResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidInput("hex value contains non-hex digits".to_string()).into()),
    }
}

fn import_key(args: &[String]) -> CliResult<()> {
    let options = parse_identity_import_args(args)?;
    let vault = default_vault()?;
    if vault.private_key_exists(&options.name)? {
        return Err(Error::AlreadyExists(format!("vault identity {}", options.name)).into());
    }
    let keypair = import_private_key_file(&options.private_path)?;
    let public_key = import_public_key(&fs::read(&options.public_path)?)?;
    if keypair.public_key() != public_key {
        return Err(
            Error::InvalidInput("public key does not match private key".to_string()).into(),
        );
    }
    vault.store_private_key(&options.name, &keypair)?;
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

fn rotate_key(args: &[String]) -> CliResult<()> {
    let name = args
        .first()
        .map(String::as_str)
        .unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    let history = default_vault()?.rotate_private_key(name)?;
    println!("Rotated vault identity: {name}");
    println!("Active generation: {}", history.active_generation);
    println!(
        "Run `lockbox access refresh --all {name}` to update remembered lockboxes that use this identity."
    );
    Ok(())
}

fn remove_contact(args: &[String]) -> CliResult<()> {
    let name = require_arg(args, 0, "contact name")?;
    default_vault()?.delete_contact(name)?;
    Ok(())
}

fn list_identities(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let vault = default_vault()?;
    let mut rows = Vec::new();
    for name in vault.list_private_keys()? {
        let email = vault
            .identity_email(&name)?
            .unwrap_or_else(|| "-".to_string());
        rows.push(vec![name, email]);
    }
    print_records(&["name", "email"], rows, format)?;
    Ok(())
}

fn identity_email(args: &[String]) -> CliResult<()> {
    let (name, email) = match args {
        [email] => (VaultDirectory::DEFAULT_KEY_NAME, email.as_str()),
        [name, email, ..] => (name.as_str(), email.as_str()),
        [] => {
            return Err(Error::InvalidInput("missing identity email address".to_string()).into());
        }
    };
    let email = normalize_contact_email(email)
        .map_err(|_| Error::InvalidInput("invalid identity email address".to_string()))?;
    default_vault()?.store_identity_email(name, &email)?;
    println!("identity={name}");
    println!("email={email}");
    Ok(())
}

fn identity_history(args: &[String]) -> CliResult<()> {
    let (args, format) = output_format_from_args(args)?;
    let name = args
        .first()
        .map(String::as_str)
        .unwrap_or(VaultDirectory::DEFAULT_KEY_NAME);
    let history = default_vault()?.list_identity_generations(name)?;
    let rows = history
        .generations
        .into_iter()
        .map(|generation| {
            vec![
                history.name.clone(),
                generation.index.to_string(),
                identity_generation_status(generation.status).to_string(),
                encode_hex(&generation.recipient_fingerprint),
                generation.created_at_unix_ms.to_string(),
                generation
                    .retired_at_unix_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect::<Vec<_>>();
    print_records(
        &[
            "identity",
            "generation",
            "status",
            "fingerprint",
            "created_at_unix_ms",
            "retired_at_unix_ms",
        ],
        rows,
        format,
    )?;
    Ok(())
}

fn list_contacts(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let vault = default_vault()?;
    let mut rows = Vec::new();
    for recipient in vault.list_contacts()? {
        rows.push(vec![recipient.name]);
    }
    print_records(&["name"], rows, format)?;
    Ok(())
}

fn list_known_lockboxes(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let vault = default_vault()?;
    let mut rows = Vec::<KnownLockboxListRow>::new();
    for lockbox in vault.list_known_lockboxes()? {
        rows.push(known_lockbox_list_row(&lockbox));
    }
    match format {
        OutputFormat::Table => print_known_lockbox_table(&rows),
        OutputFormat::Tsv | OutputFormat::Json => {
            let rows = rows
                .into_iter()
                .map(|row| {
                    vec![
                        row.name,
                        row.state,
                        row.owner,
                        row.size,
                        row.lockbox_id,
                        row.path,
                    ]
                })
                .collect::<Vec<_>>();
            print_records(
                &["name", "state", "owner", "size", "lockbox_id", "path"],
                rows,
                format,
            )?;
        }
    }
    Ok(())
}

struct KnownLockboxListRow {
    name: String,
    state: String,
    owner: String,
    size: String,
    lockbox_id: String,
    path: String,
}

fn known_lockbox_list_row(lockbox: &lockbox_vault::KnownLockbox) -> KnownLockboxListRow {
    let path = Path::new(&lockbox.path);
    let mut owner = "-".to_string();
    let mut size = "-".to_string();
    let state = match fs::metadata(path) {
        Ok(metadata) => {
            size = human_size(metadata.len());
            if let Ok(inspection) = Lockbox::inspect_file(path) {
                owner = if inspection.owner_signed {
                    "signed".to_string()
                } else {
                    "unsigned".to_string()
                };
            }
            "present"
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => "missing",
        Err(_) => "inaccessible",
    }
    .to_string();
    KnownLockboxListRow {
        name: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(lockbox.path.as_str())
            .to_string(),
        state,
        owner,
        size,
        lockbox_id: lockbox.lockbox_id.to_string(),
        path: lockbox.path.clone(),
    }
}

fn print_known_lockbox_table(rows: &[KnownLockboxListRow]) {
    if rows.is_empty() {
        println!("empty");
        return;
    }
    let name_width = column_width("name", rows.iter().map(|row| row.name.as_str()));
    let state_width = column_width("state", rows.iter().map(|row| row.state.as_str()));
    let owner_width = column_width("owner", rows.iter().map(|row| row.owner.as_str()));
    let size_width = column_width("size", rows.iter().map(|row| row.size.as_str()));
    let id_width = column_width("lockbox_id", rows.iter().map(|row| row.lockbox_id.as_str()));
    println!(
        "{:<name_width$}  {:<state_width$}  {:<owner_width$}  {:>size_width$}  {:<id_width$}  path",
        "name", "state", "owner", "size", "lockbox_id"
    );
    for row in rows {
        println!(
            "{:<name_width$}  {:<state_width$}  {:<owner_width$}  {:>size_width$}  {:<id_width$}  {}",
            row.name, row.state, row.owner, row.size, row.lockbox_id, row.path
        );
    }
}

fn column_width<'a>(header: &str, values: impl Iterator<Item = &'a str>) -> usize {
    values.fold(header.len(), |width, value| width.max(value.len()))
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "K", "M", "G", "T", "P", "E"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        return format!("{bytes}B");
    }
    if value >= 100.0 {
        format!("{value:.0}{}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.2}{}", UNITS[unit])
    }
}

fn forget_known_lockbox(args: &[String]) -> CliResult<()> {
    let path = require_arg(args, 0, "lockbox")?;
    default_vault()?.forget_known_lockbox(path)?;
    println!("Forgot known lockbox: {path}");
    Ok(())
}

fn identity_generation_status(status: IdentityGenerationStatus) -> &'static str {
    match status {
        IdentityGenerationStatus::Active => "active",
        IdentityGenerationStatus::Retired => "retired",
        IdentityGenerationStatus::Compromised => "compromised",
    }
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
    let options = parse_identity_export_args(&args)?;
    let vault = default_vault()?;
    let keypair = vault.load_private_key(&options.name)?;
    if let Some(destination) = options.private_path.as_deref() {
        write_private_key(destination, &export_private_key(&keypair, format)?)?;
    }
    if let Some(destination) = options.public_path.as_deref() {
        let public_key = keypair.public_key();
        let fingerprint = public_key_fingerprint(&public_key);
        fs::write(destination, export_public_key(&public_key, format)?)?;
        println!("identity={}", options.name);
        println!("public_key_fingerprint={}", format_hex_pairs(&fingerprint));
    }
    Ok(())
}

fn confirm_private_key_removal(name: &str) -> CliResult<bool> {
    eprintln!("Remove vault identity '{name}'?");
    eprintln!(
        "Lockboxes that only this private key can open may become inaccessible from this vault."
    );
    eprint!("Type 'yes' to remove it: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}

struct IdentityImportArgs {
    name: String,
    public_path: String,
    private_path: String,
}

struct IdentityExportArgs {
    name: String,
    public_path: Option<String>,
    private_path: Option<String>,
}

fn parse_identity_import_args(args: &[String]) -> CliResult<IdentityImportArgs> {
    let mut public_path = None;
    let mut private_path = None;
    let mut positionals = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--public" => {
                public_path = Some(require_arg(args, index + 1, "--public path")?.to_string());
                index += 2;
            }
            "--private" => {
                private_path = Some(require_arg(args, index + 1, "--private path")?.to_string());
                index += 2;
            }
            value => {
                positionals.push(value.to_string());
                index += 1;
            }
        }
    }
    if positionals.len() > 1 {
        return Err(Error::InvalidInput(
            "identity import accepts exactly one identity name".to_string(),
        )
        .into());
    }
    let name = positionals
        .pop()
        .ok_or_else(|| Error::InvalidInput("missing identity name".to_string()))?;
    let public_path =
        public_path.ok_or_else(|| Error::InvalidInput("missing --public path".to_string()))?;
    let private_path =
        private_path.ok_or_else(|| Error::InvalidInput("missing --private path".to_string()))?;
    Ok(IdentityImportArgs {
        name,
        public_path,
        private_path,
    })
}

fn parse_identity_export_args(args: &[String]) -> CliResult<IdentityExportArgs> {
    let mut public_path = None;
    let mut private_path = None;
    let mut positionals = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--public" => {
                public_path = Some(require_arg(args, index + 1, "--public path")?.to_string());
                index += 2;
            }
            "--private" => {
                private_path = Some(require_arg(args, index + 1, "--private path")?.to_string());
                index += 2;
            }
            value => {
                positionals.push(value.to_string());
                index += 1;
            }
        }
    }
    if public_path.is_none() && private_path.is_none() {
        return Err(Error::InvalidInput(
            "identity export requires --public, --private, or both".to_string(),
        )
        .into());
    }
    if positionals.len() > 1 {
        return Err(Error::InvalidInput(
            "identity export accepts at most one identity name".to_string(),
        )
        .into());
    }
    let name = positionals
        .pop()
        .unwrap_or_else(|| VaultDirectory::DEFAULT_KEY_NAME.to_string());
    Ok(IdentityExportArgs {
        name,
        public_path,
        private_path,
    })
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

#[cfg(test)]
mod tests {
    use super::{
        contact_name_from_email, decode_fingerprint_hex, format_hex_pairs, format_unix_ms_utc,
        verify_fingerprint_channel, SHARE_RECEIVE_VERIFICATION_ADVICE,
    };

    #[test]
    fn share_expiry_uses_human_readable_utc_time() {
        assert_eq!(format_unix_ms_utc(0), "1970/01/01 00:00 UTC");
        assert_eq!(
            format_unix_ms_utc(1_783_032_923_000),
            "2026/07/02 22:55 UTC"
        );
    }

    #[test]
    fn share_receive_advice_requires_recipient_initiated_trusted_channel() {
        assert!(SHARE_RECEIVE_VERIFICATION_ADVICE.contains("trusted channel"));
        assert!(SHARE_RECEIVE_VERIFICATION_ADVICE.contains("you initiated"));
        assert!(SHARE_RECEIVE_VERIFICATION_ADVICE.contains("do not accept it"));
    }

    #[test]
    fn contact_fingerprint_hex_uses_lowercase_pairs() {
        let bytes = [
            0x00, 0x01, 0x0a, 0x0b, 0x10, 0x11, 0x7f, 0x80, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
            0xfe, 0xff,
        ];
        let formatted = format_hex_pairs(&bytes);
        assert_eq!(formatted, "00 01 0a 0b 10 11 7f 80 ab bc cd de ef f0 fe ff");
        assert_eq!(decode_fingerprint_hex(&formatted).unwrap(), bytes);
        assert_eq!(
            decode_fingerprint_hex("00:01:0A:0B:10:11:7F:80:AB:BC:CD:DE:EF:F0:FE:FF").unwrap(),
            bytes
        );
        let short = decode_fingerprint_hex("123456").unwrap_err().to_string();
        assert!(short.contains("short PINs"));
        assert!(short.contains("authenticate a public key"));
    }

    #[test]
    fn fingerprint_channel_requires_receiver_initiated_second_channel() {
        assert_eq!(
            verify_fingerprint_channel(Some("phone-call-to-owner")).unwrap(),
            "phone-call-to-owner"
        );
        assert_eq!(
            verify_fingerprint_channel(Some("5")).unwrap(),
            "sms-to-owner"
        );
        assert_eq!(
            verify_fingerprint_channel(Some("in person")).unwrap(),
            "in-person"
        );

        let email = verify_fingerprint_channel(Some("email"))
            .unwrap_err()
            .to_string();
        assert!(email.contains("email cannot be used"));

        let owner_initiated = verify_fingerprint_channel(Some("sms-from-owner"))
            .unwrap_err()
            .to_string();
        assert!(owner_initiated.contains("receiver must initiate"));
    }

    #[test]
    fn contact_name_defaults_from_email() {
        assert_eq!(
            contact_name_from_email("alice.publisher@example.test"),
            "alice_publisher_example_test"
        );
    }
}
