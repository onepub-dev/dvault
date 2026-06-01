use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[test]
fn help_is_grouped_and_commands_have_specific_help() {
    let bin = env!("CARGO_BIN_EXE_lockbox");

    let help = run_output(bin, &["--help"]);
    assert_success(&help);
    let help = String::from_utf8_lossy(&help.stderr);
    assert!(help.contains(
        "Create encrypted file archives, store secrets safely, and share access with public keys."
    ));
    assert!(help.contains("Usage: lockbox <command> [arguments]"));
    assert!(help.contains("Available commands:"));
    assert!(help.contains("Archives"));
    assert!(help.contains("Files"));
    assert!(help.contains("Vault"));
    assert!(help.contains("recipient"));
    assert!(!help.contains("--jobs auto|1|N"));

    let add_help = run_output(bin, &["add", "--help"]);
    assert_success(&add_help);
    let add_help = String::from_utf8_lossy(&add_help.stdout);
    assert!(add_help.contains("Usage: lockbox add"));
    assert!(add_help.contains("<lockbox>"));
    assert!(add_help.contains("<source>"));
    assert!(add_help.contains("[lockbox-path]"));
    assert!(!add_help.contains("--jobs"));

    let add_verbose_help = run_output(bin, &["add", "--help", "--verbose"]);
    assert_success(&add_verbose_help);
    let add_verbose_help = String::from_utf8_lossy(&add_verbose_help.stdout);
    assert!(add_verbose_help.contains("--jobs <auto|1|N>"));
    assert!(add_verbose_help.contains("--key <RAW_CONTENT_KEY>"));

    let env_help = run_output(bin, &["env", "set", "--help"]);
    assert_success(&env_help);
    let env_help = String::from_utf8_lossy(&env_help.stdout);
    assert!(env_help.contains("-v, --value <VALUE>"));

    let env_help = run_output(bin, &["env", "--help"]);
    assert_success(&env_help);
    let env_help = String::from_utf8_lossy(&env_help.stdout);
    assert!(env_help.contains("Print one stored environment value by name."));
    assert!(env_help.contains("Print all non-secret environment values in an importable format."));
    assert!(env_help.contains("Normal values are printed by `env get`"));
    assert!(env_help.contains("Secret values are encrypted the same way"));
    assert!(env_help.contains("require `env get --secret` to print"));

    let env_get_help = run_output(bin, &["env", "get", "--help"]);
    assert_success(&env_get_help);
    let env_get_help = String::from_utf8_lossy(&env_get_help.stdout);
    assert!(env_get_help.contains("lockbox env get secrets.lbox APP_MODE"));
    assert!(env_get_help.contains("lockbox env get --secret secrets.lbox API_TOKEN"));
    assert!(env_get_help.contains("--output <FILE>"));
    assert!(env_get_help.contains("lockbox env get --secret --output api-token.txt"));

    let env_export_help = run_output(bin, &["env", "export", "--help"]);
    assert_success(&env_export_help);
    let env_export_help = String::from_utf8_lossy(&env_export_help.stdout);
    assert!(env_export_help.contains("--format <posix|powershell|cmd|json>"));
    assert!(env_export_help.contains("eval \"$(lockbox env export secrets.lbox)\""));
    assert!(env_export_help.contains("Use shell redirection to write it to a file."));

    let vault_init_help = run_output(bin, &["vault", "init", "--help"]);
    assert_success(&vault_init_help);
    let vault_init_help = String::from_utf8_lossy(&vault_init_help.stdout);
    assert!(vault_init_help.contains("A new vault also gets a default recipient key."));
    assert!(vault_init_help.contains("--verify"));
    assert!(vault_init_help.contains("--overwrite"));

    let vault_keygen_help = run_output(bin, &["vault", "keygen", "--help"]);
    assert_success(&vault_keygen_help);
    let vault_keygen_help = String::from_utf8_lossy(&vault_keygen_help.stdout);
    assert!(vault_keygen_help.contains("Vault recipient keys let you create and open lockboxes"));
    assert!(vault_keygen_help.contains("uses the default key name: default"));

    let vault_key_help = run_output(bin, &["vault", "key", "--help"]);
    assert_success(&vault_key_help);
    let vault_key_help = String::from_utf8_lossy(&vault_key_help.stdout);
    assert!(vault_key_help.contains("Manage vault recipient keys."));
    assert!(vault_key_help.contains("create"));
    assert!(vault_key_help.contains("export"));

    let recipient_help = run_output(bin, &["recipient", "--help"]);
    assert_success(&recipient_help);
    let recipient_help = String::from_utf8_lossy(&recipient_help.stdout);
    assert!(recipient_help.contains("Manage recipient access for a lockbox."));
    assert!(recipient_help.contains("add"));
    assert!(recipient_help.contains("remove"));
}

#[test]
fn clap_errors_are_not_double_prefixed() {
    let bin = env!("CARGO_BIN_EXE_lockbox");

    let output = run_output(bin, &["vault", "create"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error: unrecognized subcommand 'create'"));
    assert!(!stderr.contains("error: error:"));
}

#[test]
fn top_level_help_pins_command_groups_and_hidden_commands() {
    let bin = env!("CARGO_BIN_EXE_lockbox");

    let help = run_output(bin, &["--help"]);
    assert_success(&help);
    let help = String::from_utf8_lossy(&help.stderr);
    assert_contains_in_order(
        &help,
        &[
            "Archives",
            "  create",
            "  open",
            "Files",
            "  add",
            "  extract",
            "Environment",
            "  env",
            "Sharing",
            "  recipient",
            "Vault",
            "  vault",
        ],
    );
    assert!(!help.contains("keygen          Generate raw recipient key files."));
    assert!(!help.contains("LOCKBOX_KEY=<raw-content-key>"));

    let verbose_help = run_output(bin, &["--help", "--verbose"]);
    assert_success(&verbose_help);
    let verbose_help = String::from_utf8_lossy(&verbose_help.stderr);
    assert!(verbose_help.contains("Advanced global options:"));
    assert!(verbose_help.contains("keygen          Generate raw recipient key files."));
    assert!(verbose_help.contains("LOCKBOX_KEY=<raw-content-key>"));
}

#[test]
fn file_env_and_developer_aliases_execute_real_flows() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("command-aliases");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("aliases.lbox");
    let source = dir.join("source.txt");
    fs::write(&source, "alpha").unwrap();

    run(
        bin,
        &[
            "add",
            lockbox.to_str().unwrap(),
            source.to_str().unwrap(),
            "/docs/a.txt",
        ],
    );
    run(
        bin,
        &[
            "mv",
            lockbox.to_str().unwrap(),
            "/docs/a.txt",
            "/docs/b.txt",
        ],
    );

    let cat = run_output(bin, &["cat", lockbox.to_str().unwrap(), "/docs/b.txt"]);
    assert_success(&cat);
    assert_eq!(String::from_utf8_lossy(&cat.stdout), "alpha");

    run(bin, &["remove", lockbox.to_str().unwrap(), "/docs/b.txt"]);
    let listing = run_output(bin, &["ls", lockbox.to_str().unwrap()]);
    assert_success(&listing);
    assert_eq!(String::from_utf8_lossy(&listing.stdout).trim(), "empty");

    run(
        bin,
        &["env", "set", lockbox.to_str().unwrap(), "APP_MODE", "prod"],
    );
    let env_list = run_output(bin, &["env", "ls", lockbox.to_str().unwrap()]);
    assert_success(&env_list);
    assert!(String::from_utf8_lossy(&env_list.stdout).contains("APP_MODE"));

    run(
        bin,
        &["env", "remove", lockbox.to_str().unwrap(), "APP_MODE"],
    );
    let env_list = run_output(bin, &["env", "list", lockbox.to_str().unwrap()]);
    assert_success(&env_list);
    assert!(!String::from_utf8_lossy(&env_list.stdout).contains("APP_MODE"));

    let visualize = run_output(bin, &["visualise", lockbox.to_str().unwrap()]);
    assert_success(&visualize);
    assert!(String::from_utf8_lossy(&visualize.stdout).contains("Lockbox"));
}

#[test]
fn vault_command_aliases_and_noask_execute_real_flows() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-aliases");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let public_key = dir.join("alias.pub");
    let exported_public_key = dir.join("alias-export.pub");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &[
            "vault",
            "key",
            "create",
            "alias",
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    run_without_content_key(
        bin,
        &[
            "vault",
            "key",
            "export-public",
            "alias",
            exported_public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    assert!(
        String::from_utf8_lossy(&fs::read(&exported_public_key).unwrap())
            .contains("BEGIN LOCKBOX PUBLIC KEY")
    );

    run_without_content_key(
        bin,
        &[
            "vault",
            "trust",
            "add",
            "friend",
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    let list = run_output_without_content_key(bin, &["vault", "ls"], &vault_root, &agent_root);
    assert_success(&list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("trusted\tfriend"));

    run_without_content_key(
        bin,
        &["vault", "trust", "rm", "friend"],
        &vault_root,
        &agent_root,
    );
    run_without_content_key(
        bin,
        &["vault", "key", "rm", "--noask", "alias"],
        &vault_root,
        &agent_root,
    );
    let list = run_output_without_content_key(bin, &["vault", "list"], &vault_root, &agent_root);
    assert_success(&list);
    let list = String::from_utf8_lossy(&list.stdout);
    assert!(!list.contains("trusted\tfriend"));
    assert!(!list.contains("private\talias"));
}

#[test]
fn negative_cli_errors_remain_specific() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("negative-cli-errors");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("negative.lbox");
    let source = dir.join("source.txt");
    fs::write(&source, "alpha").unwrap();

    let invalid_jobs = run_output(
        bin,
        &[
            "add",
            "--jobs",
            "0",
            lockbox.to_str().unwrap(),
            source.to_str().unwrap(),
        ],
    );
    assert!(!invalid_jobs.status.success());
    assert!(String::from_utf8_lossy(&invalid_jobs.stderr)
        .contains("--jobs must be auto, 1, or a positive integer"));

    let invalid_env_set = run_output(
        bin,
        &[
            "env",
            "set",
            lockbox.to_str().unwrap(),
            "APP_MODE",
            "prod",
            "--value",
            "other",
        ],
    );
    assert!(!invalid_env_set.status.success());
    assert!(String::from_utf8_lossy(&invalid_env_set.stderr)
        .contains("env set requires exactly one value source"));

    let invalid_export = run_output(
        bin,
        &[
            "env",
            "export",
            "--format",
            "fish",
            lockbox.to_str().unwrap(),
        ],
    );
    assert!(!invalid_export.status.success());
    assert!(String::from_utf8_lossy(&invalid_export.stderr)
        .contains("unsupported env export format: fish"));
}

#[test]
fn cli_env_rename_and_visualize_flow() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir();
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("test.lbox");
    let source = dir.join("source.txt");
    fs::write(&source, "alpha").unwrap();

    run(
        bin,
        &[
            "add",
            lockbox.to_str().unwrap(),
            source.to_str().unwrap(),
            "/docs/a.txt",
        ],
    );
    run(
        bin,
        &[
            "rename",
            lockbox.to_str().unwrap(),
            "/docs",
            "/archive/docs",
        ],
    );
    run(
        bin,
        &[
            "env",
            "set",
            lockbox.to_str().unwrap(),
            "DATABASE_URL",
            "postgres://localhost/app",
        ],
    );

    let listing = run_output(bin, &["list", lockbox.to_str().unwrap(), "/archive/docs"]);
    assert_success(&listing);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("/archive/docs/a.txt"));
    assert!(!listing.contains("DATABASE_URL"));

    let env_get = run_output(
        bin,
        &["env", "get", lockbox.to_str().unwrap(), "DATABASE_URL"],
    );
    assert_success(&env_get);
    assert_eq!(
        String::from_utf8_lossy(&env_get.stdout).trim(),
        "postgres://localhost/app"
    );

    let visualize = run_output(bin, &["visualize", lockbox.to_str().unwrap()]);
    assert_success(&visualize);
    let visualize = String::from_utf8_lossy(&visualize.stdout);
    assert!(visualize.contains("Lockbox"));
    assert!(visualize.contains("summary:"));
    assert!(visualize.contains("files: 1"));
    assert!(visualize.contains("env vars: 1"));
    assert!(visualize.contains("pages:"));
    assert!(visualize.contains("----------------------------------------"));
    assert!(!visualize.contains("DATABASE_URL"));
    assert!(!visualize.contains("/archive/docs/a.txt"));
    assert!(visualize.contains("recovery scan:"));

    let vault_public = dir.join("default.pub");
    run(
        bin,
        &["vault", "keygen", "default", vault_public.to_str().unwrap()],
    );
    run(
        bin,
        &["vault", "trust", "default", vault_public.to_str().unwrap()],
    );
    let vault_list = run_output(bin, &["vault", "list"]);
    assert_success(&vault_list);
    let vault_list = String::from_utf8_lossy(&vault_list.stdout);
    assert!(vault_list.contains("private\tdefault"));
    assert!(vault_list.contains("trusted\tdefault"));

    let vault_file = unique_dir().join("vault").join("local-vault.lbox");
    let vault_bytes = fs::read(vault_file).unwrap();
    assert!(!String::from_utf8_lossy(&vault_bytes).contains("test-key"));

    let public_export = dir.join("exported.pub");
    run(
        bin,
        &[
            "vault",
            "export-public",
            "default",
            public_export.to_str().unwrap(),
        ],
    );
    assert!(public_export.exists());
    assert!(String::from_utf8_lossy(&fs::read(&public_export).unwrap())
        .contains("BEGIN LOCKBOX PUBLIC KEY"));

    let public_jwk = dir.join("exported.jwk");
    run(
        bin,
        &[
            "vault",
            "export-public",
            "--format",
            "jwk",
            "default",
            public_jwk.to_str().unwrap(),
        ],
    );
    let public_jwk_text = String::from_utf8_lossy(&fs::read(&public_jwk).unwrap()).to_string();
    assert!(public_jwk_text.contains("\"alg\": \"ML-KEM-1024\""));

    run(bin, &["vault", "remove-trusted", "default"]);
    run(bin, &["vault", "remove-key", "--force", "default"]);
    let vault_list = run_output(bin, &["vault", "list"]);
    assert_success(&vault_list);
    assert!(!String::from_utf8_lossy(&vault_list.stdout).contains("default"));

    let doctor = run_output(bin, &["doctor"]);
    assert_success(&doctor);
    let doctor = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor.contains("Local vault"));
    assert!(doctor.contains("local-vault.lbox"));
}

#[test]
fn content_key_create_does_not_mirror_empty_key_directory() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("raw-create");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("raw.lbox");
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_in(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );

    assert!(lockbox.exists());
    let listing = run_output_in(
        bin,
        &["list", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&listing);
    assert_eq!(String::from_utf8_lossy(&listing.stdout).trim(), "empty");
    assert!(!vault_root.join("local-vault.lbox").exists());
}

#[test]
fn create_refuses_to_overwrite_existing_lockbox() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("create-no-overwrite");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("safe.lbox");

    run(bin, &["create", lockbox.to_str().unwrap()]);
    let original = fs::read(&lockbox).unwrap();
    let output = run_output(bin, &["create", lockbox.to_str().unwrap()]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert_eq!(fs::read(&lockbox).unwrap(), original);
}

#[test]
fn create_defaults_lbox_extension_and_reports_before_prompting() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("create-extension");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);

    let requested = dir.join("project");
    let created = dir.join("project.lbox");
    let output = run_output_without_content_key(
        bin,
        &["create", requested.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&output);
    assert!(created.exists());
    assert!(!requested.exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Creating lockbox:"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("project.lbox"));

    let original = fs::read(&created).unwrap();
    let duplicate = run_output_without_content_key(
        bin,
        &["create", requested.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));
    assert!(!String::from_utf8_lossy(&duplicate.stdout).contains("Creating lockbox"));
    assert_eq!(fs::read(&created).unwrap(), original);
}

#[test]
fn add_can_default_destination_and_list_recursively() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("add-default-path");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("files.lbox");
    let source_file = dir.join("alpha.txt");
    fs::write(&source_file, "alpha").unwrap();
    let source_dir = dir.join("src");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("one.txt"), "one").unwrap();
    fs::write(source_dir.join("two.txt"), "two").unwrap();

    run(
        bin,
        &[
            "add",
            lockbox.to_str().unwrap(),
            source_file.to_str().unwrap(),
        ],
    );
    run(
        bin,
        &[
            "add",
            lockbox.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            "/copy",
        ],
    );

    let listing = run_output(bin, &["ls", lockbox.to_str().unwrap()]);
    assert_success(&listing);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("/alpha.txt"));
    assert!(listing.contains("/copy/one.txt"));
    assert!(listing.contains("/copy/two.txt"));
}

#[test]
fn recipient_subcommand_aliases_manage_lockbox_access() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("recipient-subcommand");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("share.lbox");
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let source = dir.join("source.txt");
    let public_key = dir.join("recipient.pub");
    let second_public_key = dir.join("recipient2.pub");
    fs::write(&source, "alpha").unwrap();

    run_in(
        bin,
        &["add", lockbox.to_str().unwrap(), source.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "vault",
            "key",
            "create",
            "sharee",
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "vault",
            "key",
            "create",
            "sharee2",
            second_public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "recipient",
            "add",
            lockbox.to_str().unwrap(),
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "recipient",
            "add",
            lockbox.to_str().unwrap(),
            second_public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );

    let recipients = run_output_in(
        bin,
        &["recipient", "ls", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&recipients);
    let recipients = String::from_utf8_lossy(&recipients.stdout);
    assert!(recipients.lines().any(|line| !line.trim().is_empty()));

    let slot_id = recipients
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.split('\t').next())
        .expect("recipient slot id");
    run_in(
        bin,
        &["recipient", "rm", lockbox.to_str().unwrap(), slot_id],
        &vault_root,
        &agent_root,
    );
}

#[test]
fn password_create_requires_explicit_vault_init() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("create-vault-init");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("password.lbox");

    let create_without_vault = run_output_without_content_key(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(!create_without_vault.status.success());
    assert!(String::from_utf8_lossy(&create_without_vault.stderr)
        .contains("local vault is not initialized"));
    assert!(!lockbox.exists());

    let init = run_output_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    assert_success(&init);
    let init = String::from_utf8_lossy(&init.stdout);
    assert!(init.contains("This will create the local Lockbox vault."));
    assert!(init.contains("Vault created successfully."));
    assert!(init.contains("Generated default private/public key: default"));
    assert!(vault_root.join("local-vault.lbox").exists());

    let vault_list =
        run_output_without_content_key(bin, &["vault", "list"], &vault_root, &agent_root);
    assert_success(&vault_list);
    let vault_list = String::from_utf8_lossy(&vault_list.stdout);
    assert!(vault_list.contains("private\tdefault"));
    assert!(vault_list.contains("public\tdefault"));

    run_without_content_key(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(lockbox.exists());
}

#[test]
fn vault_init_existing_is_noop_unless_verify_is_requested() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-init-existing");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);

    let existing =
        run_output_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    assert_success(&existing);
    let existing = String::from_utf8_lossy(&existing.stdout);
    assert!(existing.contains("Local vault already exists."));
    assert!(existing.contains("Path:"));
    assert!(existing.contains("No changes made."));
    assert!(existing.contains("Use `lockbox vault init --verify`"));
    assert!(!existing.contains("Vault opened successfully."));
    assert!(!existing.contains("Directory:"));

    let verified = run_output_without_content_key(
        bin,
        &["vault", "init", "--verify"],
        &vault_root,
        &agent_root,
    );
    assert_success(&verified);
    let verified = String::from_utf8_lossy(&verified.stdout);
    assert!(verified.contains("Local vault already exists."));
    assert!(verified.contains("Vault opened successfully."));
    assert!(verified.contains("Directory:"));
}

#[test]
fn vault_init_overwrite_replaces_existing_vault_with_warning() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-init-overwrite");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(bin, &["vault", "keygen", "extra"], &vault_root, &agent_root);

    let before = run_output_without_content_key(bin, &["vault", "list"], &vault_root, &agent_root);
    assert_success(&before);
    assert!(String::from_utf8_lossy(&before.stdout).contains("private\textra"));

    let overwritten = run_output_without_content_key(
        bin,
        &["vault", "init", "--overwrite"],
        &vault_root,
        &agent_root,
    );
    assert_success(&overwritten);
    let overwritten = String::from_utf8_lossy(&overwritten.stdout);
    assert!(overwritten.contains("WARNING: replacing it will remove"));
    assert!(overwritten.contains("Vault replaced successfully."));
    assert!(overwritten.contains("Generated default private/public key: default"));

    let after = run_output_without_content_key(bin, &["vault", "list"], &vault_root, &agent_root);
    assert_success(&after);
    let after = String::from_utf8_lossy(&after.stdout);
    assert!(after.contains("private\tdefault"));
    assert!(after.contains("public\tdefault"));
    assert!(!after.contains("extra"));
}

#[test]
fn vault_keygen_output_names_default_and_public_key_path() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-keygen-output");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    let output =
        run_output_without_content_key(bin, &["vault", "keygen"], &vault_root, &agent_root);
    assert_success(&output);
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("Using default vault key name: default"));
    assert!(output.contains("Generated vault private key: default"));
    assert!(output.contains("lockbox vault export-public default <public-key-output>"));

    let public_key = dir.join("named.pub");
    let named = run_output_without_content_key(
        bin,
        &["vault", "keygen", "named", public_key.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&named);
    let named = String::from_utf8_lossy(&named.stdout);
    assert!(named.contains("Generated vault private key: named"));
    assert!(named.contains(&format!("Public key written: {}", public_key.display())));
}

#[test]
fn vault_key_remove_requires_confirmation_and_force_bypasses_it() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-key-remove-confirm");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["vault", "key", "create", "temp"],
        &vault_root,
        &agent_root,
    );

    let refused = run_output_without_content_key_with_stdin(
        bin,
        &["vault", "key", "remove", "temp"],
        &vault_root,
        &agent_root,
        "no\n",
    );
    assert_success(&refused);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("Remove vault private key 'temp'?"));
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("Vault private key not removed: temp")
    );

    let list = run_output_without_content_key(bin, &["vault", "ls"], &vault_root, &agent_root);
    assert_success(&list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("private\ttemp"));

    let forced = run_output_without_content_key(
        bin,
        &["vault", "key", "remove", "--force", "temp"],
        &vault_root,
        &agent_root,
    );
    assert_success(&forced);
    assert!(String::from_utf8_lossy(&forced.stdout).contains("Vault private key removed: temp"));
}

#[test]
fn vault_key_export_reports_missing_output_for_named_key() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-key-export-error");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["vault", "key", "create", "take-two"],
        &vault_root,
        &agent_root,
    );

    let output = run_output_without_content_key(
        bin,
        &["vault", "key", "export", "take-two"],
        &vault_root,
        &agent_root,
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("missing private key output path for vault key take-two"));
}

#[test]
fn open_list_and_lock_report_empty_cache_and_already_closed_state() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("open-list-lock");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("state.lbox");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    let open_list =
        run_output_without_content_key(bin, &["open", "--list"], &vault_root, &agent_root);
    assert_success(&open_list);
    assert_eq!(String::from_utf8_lossy(&open_list.stdout).trim(), "empty");

    let closed = run_output_without_content_key(
        bin,
        &["close", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&closed);
    assert!(String::from_utf8_lossy(&closed.stdout).contains("already closed"));

    let listing = run_output_without_content_key(
        bin,
        &["list", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(!listing.status.success());
    assert!(String::from_utf8_lossy(&listing.stderr).contains("lockbox is closed"));
    assert!(!String::from_utf8_lossy(&listing.stderr).contains("Unlock the lockbox"));
    assert!(!String::from_utf8_lossy(&listing.stderr).contains("use the API intended"));
}

#[test]
fn add_accepts_jobs_option_for_large_files() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("jobs-add");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("jobs.lbox");
    let source = dir.join("large.bin");
    let extracted = dir.join("extracted.bin");
    let mut data = Vec::with_capacity(3 * 1024 * 1024);
    for i in 0..(3 * 1024 * 1024) {
        data.push((i % 251) as u8);
    }
    fs::write(&source, &data).unwrap();

    run(
        bin,
        &[
            "add",
            "--jobs",
            "2",
            lockbox.to_str().unwrap(),
            source.to_str().unwrap(),
            "/large.bin",
        ],
    );
    run(
        bin,
        &[
            "extract",
            lockbox.to_str().unwrap(),
            "/large.bin",
            extracted.to_str().unwrap(),
        ],
    );

    assert_eq!(fs::read(extracted).unwrap(), data);
}

#[test]
fn cli_secret_env_requires_explicit_source_and_redacts_export() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("secret-env");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("env.lbox");
    let secret_file = dir.join("secret.txt");
    fs::write(&secret_file, "file-secret").unwrap();

    run(
        bin,
        &[
            "env",
            "set",
            lockbox.to_str().unwrap(),
            "APP_MODE",
            "-v",
            "prod",
        ],
    );
    run(
        bin,
        &[
            "env",
            "set",
            lockbox.to_str().unwrap(),
            "-s",
            "API_TOKEN",
            "-f",
            secret_file.to_str().unwrap(),
        ],
    );

    let listing = run_output(bin, &["env", "list", lockbox.to_str().unwrap()]);
    assert_success(&listing);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("APP_MODE"));
    assert!(listing.contains("API_TOKEN\tsecret"));

    let export = run_output(bin, &["env", "export", lockbox.to_str().unwrap()]);
    assert_success(&export);
    let export = String::from_utf8_lossy(&export.stdout);
    assert!(export.contains("APP_MODE='prod'"));
    assert!(!export.contains("API_TOKEN"));
    assert!(!export.contains("file-secret"));

    let powershell_export = run_output(
        bin,
        &[
            "env",
            "export",
            "--format",
            "powershell",
            lockbox.to_str().unwrap(),
        ],
    );
    assert_success(&powershell_export);
    let powershell_export = String::from_utf8_lossy(&powershell_export.stdout);
    assert!(powershell_export.contains("$env:APP_MODE = 'prod'"));

    let cmd_export = run_output(
        bin,
        &[
            "env",
            "export",
            "--format",
            "cmd",
            lockbox.to_str().unwrap(),
        ],
    );
    assert_success(&cmd_export);
    let cmd_export = String::from_utf8_lossy(&cmd_export.stdout);
    assert!(cmd_export.contains("set \"APP_MODE=prod\""));

    let json_export = run_output(
        bin,
        &[
            "env",
            "export",
            "--format",
            "json",
            lockbox.to_str().unwrap(),
        ],
    );
    assert_success(&json_export);
    let json_export = String::from_utf8_lossy(&json_export.stdout);
    assert!(json_export.contains("{\"name\":\"APP_MODE\",\"value\":\"prod\"}"));

    let secret_get = run_output(
        bin,
        &["env", "get", lockbox.to_str().unwrap(), "-s", "API_TOKEN"],
    );
    assert_success(&secret_get);
    assert_eq!(
        String::from_utf8_lossy(&secret_get.stdout).trim(),
        "file-secret"
    );

    let token_output = dir.join("api-token.txt");
    run(
        bin,
        &[
            "env",
            "get",
            "--secret",
            "--output",
            token_output.to_str().unwrap(),
            lockbox.to_str().unwrap(),
            "API_TOKEN",
        ],
    );
    assert_eq!(fs::read(&token_output).unwrap(), b"file-secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(&token_output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let rejected_output = run_output(
        bin,
        &[
            "env",
            "get",
            "--secret",
            "--output",
            token_output.to_str().unwrap(),
            lockbox.to_str().unwrap(),
            "API_TOKEN",
        ],
    );
    assert!(!rejected_output.status.success());
    assert_eq!(fs::read(&token_output).unwrap(), b"file-secret");

    run(
        bin,
        &[
            "env",
            "get",
            "--secret",
            "--output",
            token_output.to_str().unwrap(),
            "--overwrite",
            lockbox.to_str().unwrap(),
            "API_TOKEN",
        ],
    );
    assert_eq!(fs::read(&token_output).unwrap(), b"file-secret");

    let rejected = run_output(
        bin,
        &[
            "env",
            "set",
            lockbox.to_str().unwrap(),
            "API_TOKEN",
            "positional-secret",
        ],
    );
    assert!(!rejected.status.success());

    let rejected_value = run_output(
        bin,
        &[
            "env",
            "set",
            lockbox.to_str().unwrap(),
            "-s",
            "OTHER_TOKEN",
            "--value",
            "argument-secret",
        ],
    );
    assert!(!rejected_value.status.success());
}

#[test]
fn vault_key_import_export_formats_are_accepted_by_cli() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("key-formats");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let public_default = dir.join("default.pub");
    run_in(
        bin,
        &[
            "vault",
            "keygen",
            "default",
            public_default.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );

    let private_exports = [
        ("pem", None, "BEGIN LOCKBOX PRIVATE KEY"),
        ("jwk", Some("jwk"), "\"alg\": \"ML-KEM-1024\""),
        ("jwks", Some("jwks"), "\"keys\""),
        ("raw", Some("raw-hex"), ""),
    ];
    for (name, format, expected) in private_exports {
        let path = dir.join(format!("private-{name}.key"));
        let mut args = vec!["vault", "export-key"];
        if let Some(format) = format {
            args.extend(["--format", format]);
        }
        args.extend(["default", path.to_str().unwrap()]);
        run_in(bin, &args, &vault_root, &agent_root);

        let text = String::from_utf8_lossy(&fs::read(&path).unwrap()).to_string();
        if !expected.is_empty() {
            assert!(text.contains(expected), "{name} private export: {text}");
        }

        run_in(
            bin,
            &[
                "vault",
                "import-key",
                &format!("imported-{name}"),
                path.to_str().unwrap(),
            ],
            &vault_root,
            &agent_root,
        );
    }

    let public_exports = [
        ("pem", None, "BEGIN LOCKBOX PUBLIC KEY"),
        ("jwk", Some("jwk"), "\"alg\": \"ML-KEM-1024\""),
        ("jwks", Some("jwks"), "\"keys\""),
        ("raw", Some("raw-hex"), ""),
    ];
    for (name, format, expected) in public_exports {
        let path = dir.join(format!("public-{name}.key"));
        let mut args = vec!["vault", "export-public"];
        if let Some(format) = format {
            args.extend(["--format", format]);
        }
        args.extend(["default", path.to_str().unwrap()]);
        run_in(bin, &args, &vault_root, &agent_root);

        let text = String::from_utf8_lossy(&fs::read(&path).unwrap()).to_string();
        if !expected.is_empty() {
            assert!(text.contains(expected), "{name} public export: {text}");
        }

        run_in(
            bin,
            &[
                "vault",
                "trust",
                &format!("trusted-{name}"),
                path.to_str().unwrap(),
            ],
            &vault_root,
            &agent_root,
        );
    }

    let invalid_private = dir.join("invalid-private.key");
    fs::write(&invalid_private, "not a key").unwrap();
    let output = run_output_in(
        bin,
        &[
            "vault",
            "import-key",
            "invalid",
            invalid_private.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    assert!(!output.status.success());

    let invalid_public = dir.join("invalid-public.key");
    fs::write(&invalid_public, "not a public key").unwrap();
    let output = run_output_in(
        bin,
        &[
            "vault",
            "trust",
            "invalid",
            invalid_public.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    assert!(!output.status.success());

    let vault_list = run_output_in(bin, &["vault", "list"], &vault_root, &agent_root);
    assert_success(&vault_list);
    let vault_list = String::from_utf8_lossy(&vault_list.stdout);
    for name in ["pem", "jwk", "jwks", "raw"] {
        assert!(vault_list.contains(&format!("private\timported-{name}")));
        assert!(vault_list.contains(&format!("trusted\ttrusted-{name}")));
    }
}

fn run(bin: &str, args: &[&str]) {
    let output = run_output(bin, args);
    assert_success(&output);
}

fn run_in(bin: &str, args: &[&str], vault_root: &PathBuf, agent_root: &PathBuf) {
    let output = run_output_in(bin, args, vault_root, agent_root);
    assert_success(&output);
}

fn run_without_content_key(bin: &str, args: &[&str], vault_root: &PathBuf, agent_root: &PathBuf) {
    let output = run_output_without_content_key(bin, args, vault_root, agent_root);
    assert_success(&output);
}

fn run_output(bin: &str, args: &[&str]) -> Output {
    run_output_in(
        bin,
        args,
        &unique_dir().join("vault"),
        &unique_dir().join("agent"),
    )
}

fn run_output_in(bin: &str, args: &[&str], vault_root: &PathBuf, agent_root: &PathBuf) -> Output {
    Command::new(bin)
        .args(args)
        .env("LOCKBOX_KEY", "test-key")
        .env("LOCKBOX_VAULT_PASSWORD", "test-vault-password")
        .env("LOCKBOX_AGENT_DIR", agent_root)
        .env("LOCKBOX_VAULT_DIR", vault_root)
        .output()
        .unwrap()
}

fn run_output_without_content_key(
    bin: &str,
    args: &[&str],
    vault_root: &PathBuf,
    agent_root: &PathBuf,
) -> Output {
    Command::new(bin)
        .args(args)
        .env("LOCKBOX_PASSWORD", "test-lockbox-password")
        .env("LOCKBOX_VAULT_PASSWORD", "test-vault-password")
        .env("LOCKBOX_AGENT_DIR", agent_root)
        .env("LOCKBOX_VAULT_DIR", vault_root)
        .output()
        .unwrap()
}

fn run_output_without_content_key_with_stdin(
    bin: &str,
    args: &[&str],
    vault_root: &PathBuf,
    agent_root: &PathBuf,
    stdin: &str,
) -> Output {
    let mut child = Command::new(bin)
        .args(args)
        .env("LOCKBOX_PASSWORD", "test-lockbox-password")
        .env("LOCKBOX_VAULT_PASSWORD", "test-vault-password")
        .env("LOCKBOX_AGENT_DIR", agent_root)
        .env("LOCKBOX_VAULT_DIR", vault_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_contains_in_order(text: &str, needles: &[&str]) {
    let mut start = 0;
    for needle in needles {
        let Some(index) = text[start..].find(needle) else {
            panic!("missing {needle:?} after byte {start} in:\n{text}");
        };
        start += index + needle.len();
    }
}

fn unique_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!(
            "lockbox-cli-flow-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
}

fn unique_dir_named(label: &str) -> PathBuf {
    let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!("lockbox-{label}-{}-{counter}", std::process::id()))
}
