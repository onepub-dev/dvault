use super::context::{
    cli_error, default_vault, read_new_vault_password, read_vault_password,
    remember_default_vault_password, require_arg, CliResult,
};
use super::output::{output_format_from_args, print_records};
use lockbox_core::{Error, OwnerSigningPublicKey, RecipientKeyPair, RecipientPublicKey};
use lockbox_share_protocol::{ContactShare, ShareClientPool};
use lockbox_vault::{
    default_vault_dir, default_vault_path, disable_platform_secret_store,
    enable_platform_secret_store, encode_hex, export_private_key, export_public_key,
    forget_platform_vault_password, import_private_key_file, import_public_key,
    list as list_open_lockboxes, local_vault, platform_secret_store_status, stop as stop_agent,
    IdentityGenerationStatus, KeyFormat, VaultDirectory,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn run(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault command")?;
    match command {
        "init" => init(&args[1..]),
        "path" => path(),
        "identity" => identity_command(&args[1..]),
        "contact" => contact_command(&args[1..]),
        "share" => share_command(&args[1..]),
        "lockbox" => lockbox_command(&args[1..]),
        "sessions" => sessions(&args[1..]),
        _ => Err(Error::InvalidInput(format!("unknown vault command: {command}")).into()),
    }
}

fn share_command(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("publish") => share_publish(&args[1..]),
        Some("receive") | Some("fetch") => share_receive(&args[1..]),
        Some("delete") | Some("rm") => share_delete(&args[1..]),
        _ => Err(Error::InvalidInput(
            "missing vault share command; use `lockbox vault share publish`, `lockbox vault share receive`, or `lockbox vault share delete`"
                .to_string(),
        )
        .into()),
    }
}

fn identity_command(args: &[String]) -> CliResult<()> {
    let command = require_arg(args, 0, "vault identity command")?;
    match command {
        "list" | "ls" => list_identities(&args[1..]),
        "create" | "gen" | "generate" => keygen(&args[1..]),
        "history" => identity_history(&args[1..]),
        "import" => import_key(&args[1..]),
        "export" => export_public(&args[1..]),
        "export-private" => export_key(&args[1..]),
        "remove" | "rm" => remove_key(&args[1..]),
        "rotate" => rotate_key(&args[1..]),
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
        println!("This will create the local reVault vault.");
        println!("Path: {}", path.display());
        println!();
        println!("The vault stores identities, contacts, and");
        println!("key-directory backups for lockboxes you create or share.");
        println!();
        println!("Choose a vault password you can back up safely. If you lose it,");
        println!("reVault cannot recover the private keys stored in this vault.");
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
        "Export its public key with: lockbox vault identity export {name} <public-key-output>"
    );
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
    let fingerprint = public_key_fingerprint(&public_key);
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
        },
    )?;
    println!("share_code={}", result.share_code);
    println!("delete_token={}", encode_hex(&result.delete_token));
    println!("expires_at_unix_ms={}", result.expires_at_unix_ms);
    Ok(())
}

fn share_receive(args: &[String]) -> CliResult<()> {
    let options = ShareCliOptions::parse(args)?;
    let share_code = options
        .positionals
        .first()
        .ok_or_else(|| Error::InvalidInput("missing share code".to_string()))?;
    let contact_name = options
        .positionals
        .get(1)
        .ok_or_else(|| Error::InvalidInput("missing contact name".to_string()))?;
    let pool = share_client_pool(&options)?;
    let fetched = pool.fetch(share_code)?;
    let contact = lockbox_share_protocol::decode_contact_share(&fetched.payload)?;
    let recipient = RecipientPublicKey::from_bytes(&contact.public_key)?;
    let signing_public = OwnerSigningPublicKey::from_bytes(&contact.signing_public_key)?;
    let vault = default_vault()?;
    if vault.trusted_recipient_exists(contact_name)? && !options.overwrite {
        return Err(Error::AlreadyExists(format!("contact {contact_name}")).into());
    }
    vault.store_trusted_recipient(contact_name, &recipient)?;
    vault.store_trusted_recipient_signing_key(contact_name, &signing_public)?;
    println!("contact={contact_name}");
    println!("identity={}", contact.identity);
    println!("fingerprint={}", encode_hex(&contact.fingerprint));
    println!(
        "signing_fingerprint={}",
        encode_hex(&public_key_fingerprint(&contact.signing_public_key))
    );
    Ok(())
}

fn share_delete(args: &[String]) -> CliResult<()> {
    let options = ShareCliOptions::parse(args)?;
    let share_code = options
        .positionals
        .first()
        .ok_or_else(|| Error::InvalidInput("missing share code".to_string()))?;
    let delete_token = options
        .positionals
        .get(1)
        .ok_or_else(|| Error::InvalidInput("missing delete token".to_string()))?;
    let delete_token = decode_hex(delete_token)?;
    let deleted = share_client_pool(&options)?.delete(share_code, &delete_token)?;
    println!("deleted={}", if deleted { "yes" } else { "no" });
    Ok(())
}

#[derive(Default)]
struct ShareCliOptions {
    server: Option<String>,
    topology_url: Option<String>,
    ttl_seconds: Option<u32>,
    max_fetches: Option<u16>,
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

fn public_key_fingerprint(public_key: &[u8]) -> Vec<u8> {
    Sha256::digest(public_key).to_vec()
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
    for recipient in vault.list_trusted_recipients()? {
        rows.push(vec![recipient.name]);
    }
    print_records(&["name"], rows, format)?;
    Ok(())
}

fn list_known_lockboxes(args: &[String]) -> CliResult<()> {
    let (_, format) = output_format_from_args(args)?;
    let vault = default_vault()?;
    let mut rows = Vec::new();
    for lockbox in vault.list_known_lockboxes()? {
        rows.push(vec![
            lockbox.path.clone(),
            known_lockbox_state(&lockbox.path).to_string(),
            lockbox.lockbox_id.to_string(),
            lockbox.last_seen_unix_ms.to_string(),
        ]);
    }
    print_records(
        &["path", "state", "lockbox_id", "last_seen_unix_ms"],
        rows,
        format,
    )?;
    Ok(())
}

fn forget_known_lockbox(args: &[String]) -> CliResult<()> {
    let path = require_arg(args, 0, "lockbox")?;
    default_vault()?.forget_known_lockbox(path)?;
    println!("Forgot known lockbox: {path}");
    Ok(())
}

fn known_lockbox_state(path: &str) -> &'static str {
    match fs::metadata(path) {
        Ok(_) => "present",
        Err(err) if err.kind() == io::ErrorKind::NotFound => "missing",
        Err(_) => "inaccessible",
    }
}

fn identity_generation_status(status: IdentityGenerationStatus) -> &'static str {
    match status {
        IdentityGenerationStatus::Active => "active",
        IdentityGenerationStatus::Retired => "retired",
        IdentityGenerationStatus::Compromised => "compromised",
    }
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
