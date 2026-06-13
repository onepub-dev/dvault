use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use lockbox_core::{Lockbox, LockboxUnlock};
use lockbox_vault::import_private_key_file;

static TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[test]
fn lbx_binary_is_alias_for_lockbox_cli() {
    let bin = env!("CARGO_BIN_EXE_lbx");

    let help = run_output(bin, &["--help"]);
    assert_success(&help);
    let help = String::from_utf8_lossy(&help.stderr);
    assert!(help.contains("Usage: lockbox <command> [arguments]"));
    assert!(help.contains("Available commands:"));
}

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
    assert!(help.contains("access"));
    assert!(!help.contains("--jobs auto|1|N"));

    let add_help = run_output(bin, &["add", "--help"]);
    assert_success(&add_help);
    let add_help = String::from_utf8_lossy(&add_help.stdout);
    assert!(add_help.contains("Usage: lockbox add"));
    assert!(add_help.contains("-r, --recursive"));
    assert!(add_help.contains("<lockbox-or-source>"));
    assert!(add_help.contains("[source-or-lockbox-path]"));
    assert!(add_help.contains("[lockbox-path]"));
    assert!(!add_help.contains("--jobs"));

    let add_verbose_help = run_output(bin, &["add", "--help", "--verbose"]);
    assert_success(&add_verbose_help);
    let add_verbose_help = String::from_utf8_lossy(&add_verbose_help.stdout);
    assert!(add_verbose_help.contains("--jobs <auto|1|N>"));
    assert!(add_verbose_help.contains("--key <RAW_CONTENT_KEY>"));
    assert!(add_verbose_help.contains("Context:"));
    assert!(add_verbose_help.contains("Pass --recursive when the source is a directory"));
    assert_contains_in_order(
        &add_verbose_help,
        &[
            "Add a file or directory to a lockbox.",
            "Context:",
            "Usage: lockbox add",
        ],
    );

    let env_help = run_output(bin, &["variables", "set", "--help"]);
    assert_success(&env_help);
    let env_help = String::from_utf8_lossy(&env_help.stdout);
    assert!(env_help.contains("-v, --value <VALUE>"));
    assert!(env_help.contains("not accepted with --secret"));
    assert!(!env_help.contains("Context:"));

    let env_help = run_output(bin, &["variables", "--help"]);
    assert_success(&env_help);
    let env_help = String::from_utf8_lossy(&env_help.stdout);
    assert!(env_help.contains("Print one stored variable value by name."));
    assert!(env_help.contains("Print all non-secret variable values in an importable format."));
    assert!(!env_help.contains("Normal values are printed by `variables get`"));

    let env_verbose_help = run_output(bin, &["variables", "--help", "--verbose"]);
    assert_success(&env_verbose_help);
    let env_verbose_help = String::from_utf8_lossy(&env_verbose_help.stdout);
    assert!(env_verbose_help.contains("Context:"));
    assert!(env_verbose_help.contains("Normal values are printed by `variables get`"));
    assert!(env_verbose_help.contains("Secret values are encrypted the same way"));
    assert!(env_verbose_help.contains("require `variables get --secret` to print"));

    let form_help = run_output(bin, &["form", "--help"]);
    assert_success(&form_help);
    let form_help = String::from_utf8_lossy(&form_help.stdout);
    assert!(form_help.contains("Manage typed multi-field form records."));
    assert!(form_help.contains("define"));
    assert!(form_help.contains("definitions"));
    assert!(form_help.contains("add"));
    assert!(form_help.contains("show"));
    assert!(form_help.contains("rm"));

    let form_define_help = run_output(bin, &["form", "define", "--help"]);
    assert_success(&form_define_help);
    let form_define_help = String::from_utf8_lossy(&form_define_help.stdout);
    assert!(form_define_help.contains("--definition-id <DEFINITION_ID>"));
    assert!(form_define_help.contains("--field <NAME[:KIND[:required[:LABEL]]]>"));
    assert!(!form_define_help.contains("--type-id"));

    let form_define_verbose_help = run_output(bin, &["form", "define", "--help", "--verbose"]);
    assert_success(&form_define_verbose_help);
    let form_define_verbose_help = String::from_utf8_lossy(&form_define_verbose_help.stdout);
    assert!(form_define_verbose_help.contains("NAME[:KIND[:required[:LABEL]]]"));
    assert!(!form_define_verbose_help.contains("otp"));

    let form_define_error = run_output(bin, &["form", "define", "test.lbox"]);
    assert!(!form_define_error.status.success());
    let form_define_error = String::from_utf8_lossy(&form_define_error.stderr);
    assert!(form_define_error.contains("Example:"));
    assert!(form_define_error.contains("lockbox form define secrets.lbox login"));
    assert!(form_define_error.contains("[alias]"));

    let form_otp_error = run_output(
        bin,
        &[
            "form",
            "define",
            "test.lbox",
            "login",
            "--field",
            "code:otp",
        ],
    );
    assert!(!form_otp_error.status.success());
    assert!(String::from_utf8_lossy(&form_otp_error.stderr)
        .contains("unsupported form field kind: otp"));

    let dir = unique_dir_named("form-define-separator");
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("forms.lbox");
    let form_define_with_separator = run_output(
        bin,
        &[
            "form",
            "define",
            lockbox.to_str().unwrap(),
            "login",
            "--",
            "--field",
            "username:text",
            "--field",
            "password:secret",
        ],
    );
    assert_success(&form_define_with_separator);
    assert!(String::from_utf8_lossy(&form_define_with_separator.stdout).contains("fields: 2"));

    let form_set_help = run_output(bin, &["form", "set", "--help"]);
    assert_success(&form_set_help);
    let form_set_help = String::from_utf8_lossy(&form_set_help.stdout);
    assert!(form_set_help.contains("-v, --value <VALUE>"));
    assert!(form_set_help.contains("-f, --file <FILE>"));
    assert!(form_set_help.contains("-e, --from-env <NAME>"));
    assert!(form_set_help.contains("-i, --interactive"));

    let env_set_verbose_help = run_output(bin, &["variables", "set", "--help", "--verbose"]);
    assert_success(&env_set_verbose_help);
    let env_set_verbose_help = String::from_utf8_lossy(&env_set_verbose_help.stdout);
    assert!(env_set_verbose_help.contains("Context:"));
    assert!(env_set_verbose_help.contains("Choose one value source"));
    assert!(env_set_verbose_help.contains("Secret values cannot use --value"));

    let env_get_help = run_output(bin, &["variables", "get", "--help"]);
    assert_success(&env_get_help);
    let env_get_help = String::from_utf8_lossy(&env_get_help.stdout);
    assert!(env_get_help.contains("lockbox variables get secrets.lbox APP_MODE"));
    assert!(env_get_help.contains("lockbox variables get --secret secrets.lbox API_TOKEN"));
    assert!(env_get_help.contains("--output <FILE>"));
    assert!(env_get_help.contains("lockbox variables get --secret --output api-token.txt"));

    let form_get_help = run_output(bin, &["form", "get", "--help"]);
    assert_success(&form_get_help);
    let form_get_help = String::from_utf8_lossy(&form_get_help.stdout);
    assert!(form_get_help.contains("lockbox form get secrets.lbox /work/github username"));
    assert!(form_get_help.contains("lockbox form get --secret"));
    assert!(form_get_help.contains("--output <FILE>"));
    assert!(form_get_help.contains("--overwrite"));

    let env_export_help = run_output(bin, &["variables", "export", "--help"]);
    assert_success(&env_export_help);
    let env_export_help = String::from_utf8_lossy(&env_export_help.stdout);
    assert!(env_export_help.contains("--format <posix|powershell|cmd|json>"));
    assert!(env_export_help.contains("eval \"$(lockbox variables export secrets.lbox)\""));
    assert!(env_export_help.contains("Use shell redirection to write it to a file."));

    let vault_init_help = run_output(bin, &["vault", "init", "--help"]);
    assert_success(&vault_init_help);
    let vault_init_help = String::from_utf8_lossy(&vault_init_help.stdout);
    assert!(!vault_init_help.contains("A new vault also gets a default identity."));
    assert!(vault_init_help.contains("--verify"));
    assert!(vault_init_help.contains("--overwrite"));

    let vault_init_verbose_help = run_output(bin, &["vault", "init", "--help", "--verbose"]);
    assert_success(&vault_init_verbose_help);
    let vault_init_verbose_help = String::from_utf8_lossy(&vault_init_verbose_help.stdout);
    assert!(vault_init_verbose_help.contains("Context:"));
    assert!(vault_init_verbose_help.contains("A new vault also gets a default identity."));

    let vault_identity_create_help = run_output(bin, &["vault", "identity", "create", "--help"]);
    assert_success(&vault_identity_create_help);
    let vault_identity_create_help = String::from_utf8_lossy(&vault_identity_create_help.stdout);
    assert!(vault_identity_create_help.contains("Create one of your identities."));
    assert!(!vault_identity_create_help.contains("creates the `default` identity"));
    assert!(
        vault_identity_create_help.contains("lockbox vault identity export laptop ./laptop.pub")
    );

    let vault_share_help = run_output(bin, &["vault", "share", "--help"]);
    assert_success(&vault_share_help);
    let vault_share_help = String::from_utf8_lossy(&vault_share_help.stdout);
    assert!(vault_share_help.contains("remove"));
    assert!(vault_share_help.contains("lockbox vault share remove"));
    assert!(!vault_identity_create_help.contains("export-public"));
    assert!(vault_identity_create_help.contains("lockbox vault identity create laptop\n"));
    assert!(!vault_identity_create_help.contains("[public-key-output]"));

    let vault_identity_create_verbose_help =
        run_output(bin, &["vault", "identity", "create", "--help", "--verbose"]);
    assert_success(&vault_identity_create_verbose_help);
    let vault_identity_create_verbose_help =
        String::from_utf8_lossy(&vault_identity_create_verbose_help.stdout);
    assert!(vault_identity_create_verbose_help.contains("Context:"));
    assert!(vault_identity_create_verbose_help.contains("creates the `default` identity"));

    let vault_identity_help = run_output(bin, &["vault", "identity", "--help"]);
    assert_success(&vault_identity_help);
    let vault_identity_help = String::from_utf8_lossy(&vault_identity_help.stdout);
    assert!(vault_identity_help.contains("Manage your lockbox open identities."));
    assert!(!vault_identity_help.contains("has a public key and a private key"));
    assert!(!vault_identity_help.contains("lockbox vault contact add"));
    assert!(!vault_identity_help.contains("on this machine"));
    assert!(vault_identity_help.contains("list"));
    assert!(vault_identity_help.contains("create"));
    assert!(vault_identity_help.contains("export"));
    assert!(vault_identity_help.contains("export-private"));
    assert!(!vault_identity_help.contains("export-public"));
    assert!(!vault_identity_help.contains("  help"));

    let vault_identity_verbose_help =
        run_output(bin, &["vault", "identity", "--help", "--verbose"]);
    assert_success(&vault_identity_verbose_help);
    let vault_identity_verbose_help = String::from_utf8_lossy(&vault_identity_verbose_help.stdout);
    assert!(vault_identity_verbose_help.contains("Context:"));
    assert!(vault_identity_verbose_help.contains("has a public key and a private key"));
    assert!(vault_identity_verbose_help.contains("Share the public key"));
    assert!(vault_identity_verbose_help.contains("keep the private key secret"));
    assert!(vault_identity_verbose_help.contains("lockbox vault contact add"));
    assert!(!vault_identity_verbose_help.contains("on this machine"));
    assert_contains_in_order(
        &vault_identity_verbose_help,
        &[
            "Manage your lockbox open identities.",
            "Context:",
            "Usage: lockbox vault identity",
        ],
    );

    let export_public_help = run_output(bin, &["vault", "identity", "export-public", "--help"]);
    assert!(!export_public_help.status.success());
    assert!(String::from_utf8_lossy(&export_public_help.stderr).contains("unrecognized subcommand"));

    let vault_contact_help = run_output(bin, &["vault", "contact", "--help"]);
    assert_success(&vault_contact_help);
    let vault_contact_help = String::from_utf8_lossy(&vault_contact_help.stdout);
    assert!(vault_contact_help.contains("Manage contacts that can be given access to a lockbox."));
    assert!(!vault_contact_help.contains("Contacts are saved public keys"));
    assert!(!vault_contact_help.contains("on this machine"));
    assert!(vault_contact_help.contains("list"));
    assert!(vault_contact_help.contains("add"));
    assert!(vault_contact_help.contains("remove"));

    let vault_contact_verbose_help = run_output(bin, &["vault", "contact", "--help", "--verbose"]);
    assert_success(&vault_contact_verbose_help);
    let vault_contact_verbose_help = String::from_utf8_lossy(&vault_contact_verbose_help.stdout);
    assert!(vault_contact_verbose_help.contains("Context:"));
    assert!(vault_contact_verbose_help.contains("Contacts are saved public keys"));
    assert!(vault_contact_verbose_help.contains("opening requires the matching private identity"));
    assert!(!vault_contact_verbose_help.contains("on this machine"));

    let access_help = run_output(bin, &["access", "--help"]);
    assert_success(&access_help);
    let access_help = String::from_utf8_lossy(&access_help.stdout);
    assert!(access_help.contains("Manage who can open a lockbox."));
    assert!(access_help.contains("add"));
    assert!(access_help.contains("remove"));
    assert!(!access_help.contains("  help"));

    let access_add_verbose_help = run_output(bin, &["access", "add", "--help", "--verbose"]);
    assert_success(&access_add_verbose_help);
    let access_add_verbose_help = String::from_utf8_lossy(&access_add_verbose_help.stdout);
    assert!(access_add_verbose_help.contains("identity:name or contact:name"));
    assert!(access_add_verbose_help.contains("lockbox access add secrets.lbox identity:alice"));
    assert!(access_add_verbose_help.contains("lockbox access add secrets.lbox alice ./alice.pub"));
    assert!(access_add_verbose_help.contains("Identity name, contact name, identity:name"));
    assert!(access_add_verbose_help.contains("Public key path."));

    let vault_help = run_output(bin, &["vault", "--help"]);
    assert_success(&vault_help);
    let vault_help = String::from_utf8_lossy(&vault_help.stdout);
    assert!(vault_help.contains("Manage identities and contacts."));
    assert!(!vault_help.contains("sessions"));
    assert!(!vault_help.contains("doctor"));
    assert!(vault_help.contains("identity"));
    assert!(vault_help.contains("contact"));
    assert!(!vault_help.contains("  key"));
    assert!(!vault_help.contains("trust"));
    assert!(!vault_help.contains("credentials"));
    assert!(!vault_help.contains("platform-store"));
    assert!(!vault_help.contains("  open"));
    assert!(!vault_help.contains("  help"));

    let sessions_help = run_output(bin, &["session", "--help"]);
    assert_success(&sessions_help);
    let sessions_help = String::from_utf8_lossy(&sessions_help.stdout);
    assert!(sessions_help.contains("Manage active and open lockbox sessions."));
    assert!(sessions_help.contains("activate"));
    assert!(sessions_help.contains("deactivate"));
    assert!(sessions_help.contains("close-all"));
    assert!(sessions_help.contains("auto-open"));
    assert!(sessions_help.contains("stop"));

    let auto_open_help = run_output(bin, &["session", "auto-open", "--help"]);
    assert_success(&auto_open_help);
    let auto_open_help = String::from_utf8_lossy(&auto_open_help.stdout);
    assert!(auto_open_help.contains("Allow reVault to use your OS login"));
    assert!(auto_open_help.contains("status"));
    assert!(auto_open_help.contains("off"));
    assert!(auto_open_help.contains("vault"));
    assert!(auto_open_help.contains("lockboxes"));

    let doctor_help = run_output(bin, &["doctor", "--help"]);
    assert_success(&doctor_help);
    let doctor_help = String::from_utf8_lossy(&doctor_help.stdout);
    assert!(doctor_help.contains("Show vault, agent, or lockbox diagnostics."));
    assert!(doctor_help.contains("lockbox doctor secrets.lbox"));

    let unlock_help = run_output(bin, &["open", "--help"]);
    assert_success(&unlock_help);
    let unlock_help = String::from_utf8_lossy(&unlock_help.stdout);
    assert!(unlock_help.contains("--duration <DURATION>"));
    assert!(unlock_help.contains("--password-env <NAME>"));
    assert!(unlock_help.contains("--password-file <FILE>"));
    assert!(unlock_help.contains("--password-stdin"));
    assert!(!unlock_help.contains("--list"));
}

#[test]
fn form_definitions_and_records_flow() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("forms-flow");
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("forms.lbox");
    let lockbox = lockbox.to_string_lossy().to_string();

    let define = run_output(
        bin,
        &[
            "form",
            "define",
            &lockbox,
            "login",
            "--name",
            "Login",
            "--field",
            "username:text:required:Username",
            "--field",
            "password:secret:required:Password",
            "--field",
            "site:url",
        ],
    );
    assert_success(&define);
    let define = String::from_utf8_lossy(&define.stdout);
    assert!(define.contains("Form definition saved."));
    assert!(define.contains("alias: login"));
    assert!(define.contains("definition_id:"));
    assert!(define.contains("revision: 1"));
    assert!(define.contains("fields: 3"));

    let aliasless_lockbox = dir.join("aliasless.lbox");
    let aliasless_lockbox = aliasless_lockbox.to_string_lossy().to_string();
    let aliasless_define = run_output(
        bin,
        &[
            "form",
            "define",
            &aliasless_lockbox,
            "--name",
            "Token",
            "--field",
            "value:secret",
        ],
    );
    assert_success(&aliasless_define);
    let aliasless_define = String::from_utf8_lossy(&aliasless_define.stdout);
    assert!(aliasless_define.contains("alias: Token"));
    assert!(aliasless_define.contains("name: Token"));
    run(
        bin,
        &[
            "form",
            "add",
            &lockbox,
            "/work/github",
            "--type",
            "login",
            "--name",
            "GitHub",
            "--set",
            "username=bsutton",
            "--set",
            "site=https://github.com",
        ],
    );
    let secret_set = run_output_with_stdin(
        bin,
        &[
            "form",
            "set",
            "--secret",
            "--stdin",
            &lockbox,
            "/work/github",
            "password",
        ],
        "correct horse\n",
    );
    assert_success(&secret_set);
    assert_eq!(
        String::from_utf8_lossy(&secret_set.stdout),
        "/work/github\tpassword\tupdated\n"
    );

    let username = run_output(bin, &["form", "get", &lockbox, "/work/github", "username"]);
    assert_success(&username);
    assert_eq!(String::from_utf8_lossy(&username.stdout), "bsutton\n");

    run(
        bin,
        &[
            "form",
            "set",
            "--value",
            "alice",
            &lockbox,
            "/work/github",
            "username",
        ],
    );
    let username = run_output(bin, &["form", "get", &lockbox, "/work/github", "username"]);
    assert_success(&username);
    assert_eq!(String::from_utf8_lossy(&username.stdout), "alice\n");

    let site_file = dir.join("site.txt");
    fs::write(&site_file, "https://example.com\n").unwrap();
    run(
        bin,
        &[
            "form",
            "set",
            "--file",
            site_file.to_str().unwrap(),
            &lockbox,
            "/work/github",
            "site",
        ],
    );
    let site = run_output(bin, &["form", "get", &lockbox, "/work/github", "site"]);
    assert_success(&site);
    assert_eq!(
        String::from_utf8_lossy(&site.stdout),
        "https://example.com\n"
    );

    let password_file = dir.join("form-password.txt");
    fs::write(&password_file, "file horse\n").unwrap();
    run(
        bin,
        &[
            "form",
            "set",
            "--secret",
            "--file",
            password_file.to_str().unwrap(),
            &lockbox,
            "/work/github",
            "password",
        ],
    );
    let password = run_output(
        bin,
        &[
            "form",
            "get",
            "--secret",
            &lockbox,
            "/work/github",
            "password",
        ],
    );
    assert_success(&password);
    assert_eq!(String::from_utf8_lossy(&password.stdout), "file horse\n");

    let refused = run_output(bin, &["form", "get", &lockbox, "/work/github", "password"]);
    assert!(!refused.status.success());
    let refused = String::from_utf8_lossy(&refused.stderr);
    assert!(refused.contains("pass --secret"));
    assert!(!refused.contains("Check the supplied value"));

    let password = run_output(
        bin,
        &[
            "form",
            "get",
            "--secret",
            &lockbox,
            "/work/github",
            "password",
        ],
    );
    assert_success(&password);
    assert_eq!(String::from_utf8_lossy(&password.stdout), "file horse\n");

    let password_output = dir.join("password.txt");
    let password_file = run_output(
        bin,
        &[
            "form",
            "get",
            "--secret",
            "--output",
            password_output.to_str().unwrap(),
            &lockbox,
            "/work/github",
            "password",
        ],
    );
    assert_success(&password_file);
    assert!(password_file.stdout.is_empty());
    assert_eq!(fs::read(&password_output).unwrap(), b"file horse");

    let rejected_password_file = run_output(
        bin,
        &[
            "form",
            "get",
            "--secret",
            "--output",
            password_output.to_str().unwrap(),
            &lockbox,
            "/work/github",
            "password",
        ],
    );
    assert!(!rejected_password_file.status.success());
    assert_eq!(fs::read(&password_output).unwrap(), b"file horse");

    run(
        bin,
        &[
            "form",
            "get",
            "--output",
            password_output.to_str().unwrap(),
            "--overwrite",
            &lockbox,
            "/work/github",
            "username",
        ],
    );
    assert_eq!(fs::read(&password_output).unwrap(), b"alice");

    let inspect = run_output(bin, &["form", "show", &lockbox, "/work/github"]);
    assert_success(&inspect);
    let inspect = String::from_utf8_lossy(&inspect.stdout);
    assert!(inspect.contains("definition_id\t"));
    assert!(!inspect.contains("type_id\t"));
    assert!(inspect.contains("field\tusername\tUsername\talice"));
    assert!(inspect.contains("field\tpassword\tPassword\t<secret>"));
    assert!(!inspect.contains("file horse"));

    let list = run_output(bin, &["form", "list", &lockbox, "/work"]);
    assert_success(&list);
    let list = String::from_utf8_lossy(&list.stdout);
    assert!(list.lines().next().unwrap_or("").contains("definition_id"));
    assert!(!list.lines().next().unwrap_or("").contains("type_id"));
    assert!(list.contains("/work/github"));
    assert!(list.contains("GitHub"));

    let definitions = run_output(bin, &["form", "definitions", &lockbox]);
    assert_success(&definitions);
    let definitions = String::from_utf8_lossy(&definitions.stdout);
    assert!(definitions
        .lines()
        .next()
        .unwrap_or("")
        .contains("definition_id"));
    assert!(!definitions.lines().next().unwrap_or("").contains("type_id"));
    assert!(definitions.contains("login"));
    assert!(definitions.contains("Login"));

    let legacy_types = run_output(bin, &["form", "types", &lockbox]);
    assert_success(&legacy_types);
    assert!(String::from_utf8_lossy(&legacy_types.stdout).contains("login"));

    let interactive = run_output_with_stdin(
        bin,
        &[
            "form",
            "add",
            &lockbox,
            "/work/gitlab",
            "--type",
            "login",
            "--interactive",
        ],
        "alice\ninteractive secret\n\n",
    );
    assert_success(&interactive);
    let interactive_show = run_output(bin, &["form", "show", &lockbox, "/work/gitlab"]);
    assert_success(&interactive_show);
    let interactive_show = String::from_utf8_lossy(&interactive_show.stdout);
    assert!(interactive_show.contains("name\tgitlab"));
    assert!(interactive_show.contains("field\tusername\tUsername\talice"));
    assert!(interactive_show.contains("field\tpassword\tPassword\t<secret>"));
    assert!(!interactive_show.contains("interactive secret"));

    run(
        bin,
        &[
            "form",
            "add",
            &lockbox,
            "/work/remove-me",
            "--type",
            "login",
        ],
    );
    run(bin, &["form", "rm", &lockbox, "/work/remove-me"]);
    let removed = run_output(bin, &["form", "show", &lockbox, "/work/remove-me"]);
    assert!(!removed.status.success());

    run(
        bin,
        &["variables", "set", &lockbox, "/prod/API_KEY", "normal-key"],
    );
    let visualize = run_output(bin, &["visualize", &lockbox]);
    assert_success(&visualize);
    let visualize = String::from_utf8_lossy(&visualize.stdout);
    assert!(visualize.contains("variables: 1"));
    assert!(visualize.contains("form definitions: 1"));
    assert!(visualize.contains("form records: 2"));
    assert!(visualize.contains("variables recovered: true"));
    assert!(visualize.contains("forms recovered: true"));

    let report = run_output(bin, &["recover", "--report", &lockbox]);
    assert_success(&report);
    let report = String::from_utf8_lossy(&report.stdout);
    assert!(report.contains("variables_recovered"));
    assert!(report.contains("forms_recovered"));
    assert!(report.contains("form_record_count"));
}

#[test]
fn form_interactive_edit_handles_definition_history_and_mismatched_record() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("forms-history-interactive");
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("forms.lbox");
    let lockbox = lockbox.to_string_lossy().to_string();

    run(
        bin,
        &[
            "form",
            "define",
            &lockbox,
            "login",
            "--name",
            "Login",
            "--field",
            "username:text:required:Username",
            "--field",
            "legacy:text:required:Legacy",
        ],
    );
    run(
        bin,
        &[
            "form",
            "add",
            &lockbox,
            "/work/history",
            "--type",
            "login",
            "--name",
            "History",
            "--set",
            "username=alice",
            "--set",
            "legacy=old",
        ],
    );
    run(
        bin,
        &[
            "form",
            "define",
            &lockbox,
            "login",
            "--name",
            "Login",
            "--field",
            "username:text:required:Username",
            "--field",
            "password:secret:required:Password",
            "--field",
            "site:url",
        ],
    );

    let edit = run_output_with_stdin(
        bin,
        &["form", "edit", &lockbox, "/work/history", "--interactive"],
        "\nrevision secret\n\n",
    );
    assert_success(&edit);
    assert!(String::from_utf8_lossy(&edit.stdout).contains("Username [alice]:"));

    let show = run_output(bin, &["form", "show", &lockbox, "/work/history"]);
    assert_success(&show);
    let show = String::from_utf8_lossy(&show.stdout);
    assert!(show.contains("field\tusername\tUsername\talice"));
    assert!(show.contains("field\tpassword\tPassword\t<secret>"));
    assert!(show.contains("unknown-field\tlegacy\tLegacy"));
    assert!(!show.contains("revision secret"));

    let password = run_output(
        bin,
        &[
            "form",
            "get",
            "--secret",
            &lockbox,
            "/work/history",
            "password",
        ],
    );
    assert_success(&password);
    assert_eq!(
        String::from_utf8_lossy(&password.stdout),
        "revision secret\n"
    );

    let edit_existing = run_output_with_stdin(
        bin,
        &["form", "edit", &lockbox, "/work/history", "--interactive"],
        "bob\n\nhttps://example.com\n",
    );
    assert_success(&edit_existing);
    let edit_existing = String::from_utf8_lossy(&edit_existing.stdout);
    assert!(edit_existing.contains("Username [alice]:"));
    assert!(!edit_existing.contains("revision secret"));

    let show = run_output(bin, &["form", "show", &lockbox, "/work/history"]);
    assert_success(&show);
    let show = String::from_utf8_lossy(&show.stdout);
    assert!(show.contains("field\tusername\tUsername\tbob"));
    assert!(show.contains("field\tsite\tsite\thttps://example.com"));

    let password = run_output(
        bin,
        &[
            "form",
            "get",
            "--secret",
            &lockbox,
            "/work/history",
            "password",
        ],
    );
    assert_success(&password);
    assert_eq!(
        String::from_utf8_lossy(&password.stdout),
        "revision secret\n"
    );
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
fn unlock_list_flag_is_not_supported() {
    let bin = env!("CARGO_BIN_EXE_lockbox");

    let output = run_output(bin, &["open", "--list"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--list'"));
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
            "Data",
            "  variables",
            "Sharing",
            "  access",
            "Vault",
            "  doctor",
            "  vault",
        ],
    );
    assert!(!help.contains("keygen          Generate raw keypair files."));
    assert!(!help.contains("add-recipient   Share a lockbox with another public key."));
    assert!(!help.contains("list-keys       List keys that can open a lockbox."));
    assert!(!help.contains("remove-key      Remove a key from a lockbox."));
    assert!(!help.contains("LOCKBOX_KEY=<raw-content-key>"));

    let verbose_help = run_output(bin, &["--help", "--verbose"]);
    assert_success(&verbose_help);
    let verbose_help = String::from_utf8_lossy(&verbose_help.stderr);
    assert!(verbose_help.contains("Advanced global options:"));
    assert!(!verbose_help.contains("add-recipient   Share a lockbox with another public key."));
    assert!(!verbose_help.contains("list-keys       List keys that can open a lockbox."));
    assert!(!verbose_help.contains("remove-key      Remove a key from a lockbox."));
    assert!(verbose_help.contains("keygen          Generate raw keypair files."));
    assert!(verbose_help.contains("LOCKBOX_KEY=<raw-content-key>"));
    assert!(verbose_help.contains("LOCKBOX_SESSION_AGENT_DIR=<dir>"));

    for removed in ["add-recipient", "list-keys", "remove-key", "recipient"] {
        let output = run_output(bin, &[removed, "--help"]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
    }

    for removed in ["key", "trust", "list", "ls", "doctor"] {
        let output = run_output(bin, &["vault", removed, "--help"]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
    }
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

    run(
        bin,
        &[
            "remove",
            "--force",
            lockbox.to_str().unwrap(),
            "/docs/b.txt",
        ],
    );
    let listing = run_output(bin, &["ls", lockbox.to_str().unwrap()]);
    assert_success(&listing);
    assert_eq!(String::from_utf8_lossy(&listing.stdout).trim(), "empty");

    run(
        bin,
        &[
            "variables",
            "set",
            lockbox.to_str().unwrap(),
            "APP_MODE",
            "prod",
        ],
    );
    let env_list = run_output(bin, &["variables", "ls", lockbox.to_str().unwrap()]);
    assert_success(&env_list);
    assert!(String::from_utf8_lossy(&env_list.stdout).contains("APP_MODE"));

    run(
        bin,
        &["variables", "remove", lockbox.to_str().unwrap(), "APP_MODE"],
    );
    let env_list = run_output(bin, &["variables", "list", lockbox.to_str().unwrap()]);
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
        &["vault", "identity", "create", "alias"],
        &vault_root,
        &agent_root,
    );
    run_without_content_key(
        bin,
        &[
            "vault",
            "identity",
            "export",
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
            "identity",
            "export",
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
            "contact",
            "add",
            "friend",
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    let list = run_output_without_content_key(
        bin,
        &["vault", "contact", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("friend"));

    run_without_content_key(
        bin,
        &["vault", "contact", "rm", "friend"],
        &vault_root,
        &agent_root,
    );
    run_without_content_key(
        bin,
        &["vault", "identity", "rm", "--noask", "alias"],
        &vault_root,
        &agent_root,
    );
    let list = run_output_without_content_key(
        bin,
        &["vault", "identity", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&list);
    let list = String::from_utf8_lossy(&list.stdout);
    assert!(!list.contains("alias"));

    let contacts = run_output_without_content_key(
        bin,
        &["vault", "contact", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&contacts);
    assert!(!String::from_utf8_lossy(&contacts.stdout).contains("friend"));
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
            "variables",
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
        .contains("variables set requires exactly one value source"));

    let invalid_secret_flag = run_output(
        bin,
        &[
            "var",
            "set",
            "-secret",
            lockbox.to_str().unwrap(),
            "/product/API_KEY",
            "yyyyy",
        ],
    );
    assert!(!invalid_secret_flag.status.success());
    let invalid_secret_flag = String::from_utf8_lossy(&invalid_secret_flag.stderr);
    assert!(invalid_secret_flag.contains("unknown option: -secret"));
    assert!(invalid_secret_flag.contains("Use --secret"));
    assert!(!invalid_secret_flag.contains("variables set requires exactly one value source"));

    let invalid_export = run_output(
        bin,
        &[
            "variables",
            "export",
            "--format",
            "fish",
            lockbox.to_str().unwrap(),
        ],
    );
    assert!(!invalid_export.status.success());
    assert!(String::from_utf8_lossy(&invalid_export.stderr)
        .contains("unsupported variables export format: fish"));
}

#[test]
fn remove_requires_confirmation_and_reports_count() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("remove-confirmation");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("remove.lbox");
    let source = dir.join("remove.txt");
    fs::write(&source, "delete me").unwrap();
    let root_source = dir.join("perf.data");
    fs::write(&root_source, "root delete").unwrap();

    run(
        bin,
        &[
            "add",
            lockbox.to_str().unwrap(),
            source.to_str().unwrap(),
            "/docs/remove.txt",
        ],
    );

    let refused = run_output_with_stdin(
        bin,
        &["rm", lockbox.to_str().unwrap(), "/docs/remove.txt"],
        "no\n",
    );
    assert_success(&refused);
    assert!(String::from_utf8_lossy(&refused.stderr)
        .contains("Remove lockbox entry '/docs/remove.txt'? Type y or yes to confirm:"));
    assert!(String::from_utf8_lossy(&refused.stdout).contains("No entries removed."));

    let listing = run_output(bin, &["list", "--recursive", lockbox.to_str().unwrap()]);
    assert_success(&listing);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("/docs/remove.txt"));

    let removed = run_output_with_stdin(
        bin,
        &["rm", lockbox.to_str().unwrap(), "/docs/remove.txt"],
        "y\n",
    );
    assert_success(&removed);
    assert!(String::from_utf8_lossy(&removed.stdout).contains("Removed 1 file"));
    assert!(String::from_utf8_lossy(&removed.stdout).contains("/docs/remove.txt"));

    run(
        bin,
        &[
            "add",
            lockbox.to_str().unwrap(),
            root_source.to_str().unwrap(),
        ],
    );
    let root_removed =
        run_output_with_stdin(bin, &["rm", lockbox.to_str().unwrap(), "perf.data"], "y\n");
    assert_success(&root_removed);
    assert!(String::from_utf8_lossy(&root_removed.stdout).contains("/perf.data"));

    let listing = run_output(bin, &["list", lockbox.to_str().unwrap()]);
    assert_success(&listing);
    assert_eq!(String::from_utf8_lossy(&listing.stdout).trim(), "empty");
}

#[test]
fn missing_lockbox_errors_are_cli_specific() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("missing-lockbox");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let missing = dir.join("missing.lbox");
    let source = dir.join("source.txt");
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    fs::write(&source, "missing lockbox source").unwrap();

    let output = run_output(bin, &["visualize", missing.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("lockbox not found:"));
    assert!(!stderr.contains("os error 2"));
    assert!(!stderr.contains("another process is using the file"));

    let add_missing = run_output_without_content_key(
        bin,
        &["add", missing.to_str().unwrap(), source.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(!add_missing.status.success());
    let stderr = String::from_utf8_lossy(&add_missing.stderr);
    assert!(stderr.contains(&format!("lockbox not found: {}", missing.display())));
    assert!(!stderr.contains("no creation open method"));
}

#[test]
fn removing_last_lockbox_key_has_cli_guidance() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("last-key-message");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("last-key.lbox");
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let source = dir.join("source.txt");
    let private_key = dir.join("access.key");
    let public_key = dir.join("access.pub");
    fs::write(&source, "alpha").unwrap();

    run_in(bin, &["vault", "init"], &vault_root, &agent_root);
    run_in(
        bin,
        &[
            "keygen",
            private_key.to_str().unwrap(),
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "add",
            lockbox.to_str().unwrap(),
            source.to_str().unwrap(),
            "/alpha.txt",
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "access",
            "add",
            lockbox.to_str().unwrap(),
            "access_key",
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );

    let keys = run_output_in(
        bin,
        &[
            "access",
            "list",
            "--format",
            "tsv",
            lockbox.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    assert_success(&keys);
    let slot_id = String::from_utf8_lossy(&keys.stdout)
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.split('\t').next())
        .expect("key slot id")
        .to_string();

    let output = run_output_in(
        bin,
        &["access", "remove", lockbox.to_str().unwrap(), &slot_id],
        &vault_root,
        &agent_root,
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot remove the last access entry"));
    assert!(stderr.contains("add another identity or contact"));
    assert!(!stderr.contains("security limit exceeded"));
    assert!(!stderr.contains("Reduce the input size"));
}

#[test]
fn doctor_and_session_report_agent_state() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("agent-reporting");
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    let doctor = run_output_in(bin, &["doctor"], &vault_root, &agent_root);
    assert_success(&doctor);
    let doctor = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor.contains("Session agent"));
    assert!(doctor.contains("running: no"));
    assert!(doctor.contains("open lockboxes:"));
    assert!(doctor.contains("log:"));
    assert!(doctor.contains(agent_root.to_str().unwrap()));
    assert_contains_in_order(
        &doctor,
        &[
            "Auto-open",
            "supported:",
            "scope:",
            "backend:",
            "Session agent",
        ],
    );
    assert!(!doctor.contains("  vault:"));
    assert!(!doctor.contains("running: unknown"));

    let open = run_output_in(bin, &["session"], &vault_root, &agent_root);
    assert_success(&open);
    let open = String::from_utf8_lossy(&open.stdout);
    assert!(open.contains("Session agent:"));
    assert!(open.contains("  enabled:"));
    assert!(open.contains("  running:"));
    assert!(open.contains("Auto-open:"));
    assert!(open.contains("  scope:"));
    assert!(open.contains("Active lockbox:"));
    assert!(open.contains("Open lockboxes:"));
    assert!(open.contains("none"));

    let stop = run_output_in(bin, &["session", "stop"], &vault_root, &agent_root);
    assert_success(&stop);
    assert!(String::from_utf8_lossy(&stop.stdout).contains("Session agent stopped"));

    let auto_open = run_output_in(
        bin,
        &["session", "auto-open", "status", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&auto_open);
    let auto_open = String::from_utf8_lossy(&auto_open.stdout);
    assert_contains_in_order(
        &auto_open,
        &[
            "supported\t",
            "scope\t",
            "vault pass phrase stored\t",
            "backend\t",
            "vault\t",
        ],
    );

    let auto_open_default = run_output_in(bin, &["session", "auto-open"], &vault_root, &agent_root);
    assert_success(&auto_open_default);
    let auto_open_default = String::from_utf8_lossy(&auto_open_default.stdout);
    assert!(auto_open_default.contains("supported"));
    assert!(auto_open_default.contains("scope"));
}

#[test]
fn doctor_lockbox_reports_closed_metadata_and_unlock_guidance() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("doctor-lockbox-closed");
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("closed.lbox");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["create", "--password", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    run_without_content_key(bin, &["close", "--all"], &vault_root, &agent_root);

    let doctor = run_output_without_lockbox_password(
        bin,
        &["doctor", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    )
    .output()
    .unwrap();
    assert_success(&doctor);
    let doctor = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor.contains("Lockbox"));
    assert!(doctor.contains(lockbox.to_str().unwrap()));
    assert!(doctor.contains("header: ok"));
    assert!(doctor.contains("Access methods"));
    assert!(doctor.contains("pass phrase slots: 1"));
    assert!(doctor.contains("recipient-key slots: 0"));
    assert!(doctor.contains("Open checks"));
    assert!(doctor.contains("additional checks"));
}

#[test]
fn doctor_lockbox_adds_open_checks_when_unlocked() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("doctor-lockbox-open");
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("open.lbox");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    let open = run_output_without_content_key(
        bin,
        &["open", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    if is_session_agent_unavailable(&open) {
        eprintln!("skipping doctor open checks: lockbox session agent unavailable");
        return;
    }
    assert_success(&open);

    let doctor = run_output_without_lockbox_password(
        bin,
        &["doctor", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    )
    .output()
    .unwrap();
    assert_success(&doctor);
    let doctor = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor.contains("Open checks"));
    assert!(doctor.contains("open: yes"));
    assert!(doctor.contains("pages:"));
    assert!(doctor.contains("intact files:"));

    let global_doctor =
        run_output_without_lockbox_password(bin, &["doctor"], &vault_root, &agent_root)
            .output()
            .unwrap();
    assert_success(&global_doctor);
    let global_doctor = String::from_utf8_lossy(&global_doctor.stdout);
    assert!(global_doctor.contains("open lockboxes: 1"));
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
            "var",
            "set",
            lockbox.to_str().unwrap(),
            "DATABASE_URL",
            "postgres://localhost/app",
        ],
    );

    let listing = run_output(bin, &["list", lockbox.to_str().unwrap(), "/archive/docs"]);
    assert_success(&listing);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("a.txt"));
    assert!(!listing.contains("/archive/docs/a.txt"));
    assert!(!listing.contains("DATABASE_URL"));

    let env_get = run_output(
        bin,
        &["var", "get", lockbox.to_str().unwrap(), "DATABASE_URL"],
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
    assert!(visualize.contains("variables: 1"));
    assert!(visualize.contains("pages:"));
    assert!(visualize.contains("----------------------------------------"));
    assert!(!visualize.contains("DATABASE_URL"));
    assert!(!visualize.contains("/archive/docs/a.txt"));
    assert!(visualize.contains("recovery scan:"));

    let vault_public = dir.join("default.pub");
    run(bin, &["vault", "identity", "create", "default"]);
    run(
        bin,
        &[
            "vault",
            "identity",
            "export",
            "default",
            vault_public.to_str().unwrap(),
        ],
    );
    run(
        bin,
        &[
            "vault",
            "contact",
            "add",
            "default",
            vault_public.to_str().unwrap(),
        ],
    );
    let identity_list = run_output(bin, &["vault", "identity", "list", "--format", "tsv"]);
    assert_success(&identity_list);
    assert!(String::from_utf8_lossy(&identity_list.stdout).contains("default"));
    let contact_list = run_output(bin, &["vault", "contact", "list", "--format", "tsv"]);
    assert_success(&contact_list);
    assert!(String::from_utf8_lossy(&contact_list.stdout).contains("default"));

    let vault_file = unique_dir().join("vault").join("local-vault.lbox");
    let vault_bytes = fs::read(vault_file).unwrap();
    assert!(!String::from_utf8_lossy(&vault_bytes).contains("test-key"));

    let public_export = dir.join("exported.pub");
    run(
        bin,
        &[
            "vault",
            "identity",
            "export",
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
            "identity",
            "export",
            "--format",
            "jwk",
            "default",
            public_jwk.to_str().unwrap(),
        ],
    );
    let public_jwk_text = String::from_utf8_lossy(&fs::read(&public_jwk).unwrap()).to_string();
    assert!(public_jwk_text.contains("\"alg\": \"X25519-ML-KEM-768\""));

    run(bin, &["vault", "contact", "remove", "default"]);
    run(bin, &["vault", "identity", "remove", "--force", "default"]);
    let identity_list = run_output(bin, &["vault", "identity", "list"]);
    assert_success(&identity_list);
    assert!(!String::from_utf8_lossy(&identity_list.stdout).contains("default"));
    let contact_list = run_output(bin, &["vault", "contact", "list"]);
    assert_success(&contact_list);
    assert!(!String::from_utf8_lossy(&contact_list.stdout).contains("default"));

    let doctor = run_output(bin, &["doctor"]);
    assert_success(&doctor);
    let doctor = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor.contains("Local vault"));
    assert!(doctor.contains("Auto-open"));
    assert!(doctor.contains("local-vault.lbox"));
}

#[test]
fn list_commands_support_table_tsv_and_json_formats() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("output-formats");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("formats.lbox");
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

    let table = run_output(bin, &["list", lockbox.to_str().unwrap()]);
    assert_success(&table);
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(table.lines().next().unwrap_or("").contains("kind"));
    assert!(table.lines().next().unwrap_or("").contains("name"));
    assert!(table.contains("docs/"));
    assert!(!table.contains("/docs/a.txt"));

    let recursive = run_output(bin, &["list", "--recursive", lockbox.to_str().unwrap()]);
    assert_success(&recursive);
    let recursive = String::from_utf8_lossy(&recursive.stdout);
    assert!(recursive.lines().next().unwrap_or("").contains("path"));
    assert!(recursive.contains("/docs/a.txt"));

    let glob = run_output(bin, &["list", lockbox.to_str().unwrap(), "/docs/*.txt"]);
    assert_success(&glob);
    let glob = String::from_utf8_lossy(&glob.stdout);
    assert!(glob.lines().next().unwrap_or("").contains("path"));
    assert!(glob.contains("/docs/a.txt"));

    let tsv = run_output(bin, &["list", "--format", "tsv", lockbox.to_str().unwrap()]);
    assert_success(&tsv);
    assert!(String::from_utf8_lossy(&tsv.stdout).contains("directory\t-\tdocs/"));

    let json = run_output(
        bin,
        &["list", "--format", "json", lockbox.to_str().unwrap()],
    );
    assert_success(&json);
    assert!(String::from_utf8_lossy(&json.stdout)
        .contains("{\"kind\":\"directory\",\"len\":\"-\",\"name\":\"docs/\"}"));

    let recursive_json = run_output(
        bin,
        &[
            "list",
            "--recursive",
            "--format",
            "json",
            lockbox.to_str().unwrap(),
        ],
    );
    assert_success(&recursive_json);
    assert!(String::from_utf8_lossy(&recursive_json.stdout)
        .contains("{\"kind\":\"file\",\"len\":\"5\",\"path\":\"/docs/a.txt\"}"));
}

#[test]
fn recover_reports_and_writes_recovered_lockbox() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("recover-write");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let damaged = dir.join("damaged.lbox");
    let recovered = dir.join("recovered.lbox");
    let source = dir.join("source.txt");
    fs::write(&source, "alpha").unwrap();

    run(
        bin,
        &[
            "add",
            damaged.to_str().unwrap(),
            source.to_str().unwrap(),
            "/docs/a.txt",
        ],
    );
    let mut bytes = fs::read(&damaged).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&damaged, bytes).unwrap();

    let report = run_output(
        bin,
        &[
            "recover",
            "--report",
            "--format",
            "json",
            damaged.to_str().unwrap(),
        ],
    );
    assert_success(&report);
    assert!(String::from_utf8_lossy(&report.stdout).contains("\"field\":\"intact_file_count\""));

    let output = run_output(
        bin,
        &[
            "recover",
            damaged.to_str().unwrap(),
            "--output",
            recovered.to_str().unwrap(),
            "--format",
            "tsv",
        ],
    );
    assert_success(&output);
    assert!(recovered.exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("output\t"));

    let listing = run_output(
        bin,
        &[
            "list",
            "--recursive",
            "--format",
            "tsv",
            recovered.to_str().unwrap(),
        ],
    );
    assert_success(&listing);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("/docs/a.txt"));
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

    let listing = run_output_without_lockbox_password(
        bin,
        &["list", created.to_str().unwrap()],
        &vault_root,
        &agent_root,
    )
    .output()
    .unwrap();
    if is_session_agent_unavailable(&listing) {
        eprintln!("skipping create extension listing assertion: session agent unavailable");
        return;
    }
    assert_success(&listing);
    assert_eq!(String::from_utf8_lossy(&listing.stdout).trim(), "empty");

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
            source_file.to_str().unwrap(),
            "/some/path",
        ],
    );
    let directory_without_recursive = run_output(
        bin,
        &[
            "add",
            lockbox.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            "/copy",
        ],
    );
    assert!(!directory_without_recursive.status.success());
    assert!(String::from_utf8_lossy(&directory_without_recursive.stderr).contains("--recursive"));

    run(
        bin,
        &[
            "add",
            "--recursive",
            lockbox.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            "/copy",
        ],
    );

    let listing = run_output(bin, &["ls", lockbox.to_str().unwrap()]);
    assert_success(&listing);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("alpha.txt"));
    assert!(listing.contains("copy/"));
    assert!(!listing.contains("/copy/one.txt"));

    let recursive = run_output(bin, &["ls", "--recursive", lockbox.to_str().unwrap()]);
    assert_success(&recursive);
    let recursive = String::from_utf8_lossy(&recursive.stdout);
    assert!(recursive.contains("/alpha.txt"));
    assert!(recursive.contains("/some/path/alpha.txt"));
    assert!(recursive.contains("/copy/one.txt"));
    assert!(recursive.contains("/copy/two.txt"));

    let nested = run_output(bin, &["ls", lockbox.to_str().unwrap(), "/some/path"]);
    assert_success(&nested);
    assert!(String::from_utf8_lossy(&nested.stdout).contains("alpha.txt"));
}

#[test]
fn access_subcommand_aliases_manage_lockbox_access() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("access-subcommand");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("share.lbox");
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let source = dir.join("source.txt");
    let public_key = dir.join("access.pub");
    let second_public_key = dir.join("access2.pub");
    fs::write(&source, "alpha").unwrap();

    run_in(
        bin,
        &["add", lockbox.to_str().unwrap(), source.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &["vault", "identity", "create", "sharee"],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "vault",
            "identity",
            "export",
            "sharee",
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &["vault", "identity", "create", "sharee2"],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "vault",
            "identity",
            "export",
            "sharee2",
            second_public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "vault",
            "contact",
            "add",
            "sharee",
            second_public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    let ambiguous = run_output_in(
        bin,
        &["access", "add", lockbox.to_str().unwrap(), "sharee"],
        &vault_root,
        &agent_root,
    );
    assert!(!ambiguous.status.success());
    let ambiguous = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(ambiguous.contains("ambiguous access target: sharee"));
    assert!(ambiguous.contains("identity:sharee"));
    assert!(ambiguous.contains("contact:sharee"));

    let path_only = run_output_in(
        bin,
        &[
            "access",
            "add",
            lockbox.to_str().unwrap(),
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    assert!(!path_only.status.success());
    assert!(String::from_utf8_lossy(&path_only.stderr)
        .contains("public key files require a contact name"));

    run_in(
        bin,
        &[
            "access",
            "add",
            lockbox.to_str().unwrap(),
            "external",
            public_key.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "access",
            "add",
            lockbox.to_str().unwrap(),
            "identity:sharee",
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &["access", "add", lockbox.to_str().unwrap(), "contact:sharee"],
        &vault_root,
        &agent_root,
    );

    let access = run_output_in(
        bin,
        &["access", "ls", "--format", "tsv", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&access);
    let access = String::from_utf8_lossy(&access.stdout);
    assert!(access.lines().any(|line| !line.trim().is_empty()));
    assert!(access.contains("\texternal\tRecipient\t"));
    assert!(access.contains("\tsharee\tRecipient\t"));

    let access_json = run_output_in(
        bin,
        &[
            "access",
            "ls",
            "--format",
            "json",
            lockbox.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    assert_success(&access_json);
    let access_json = String::from_utf8_lossy(&access_json.stdout);
    assert!(access_json.contains("\"name\":\"external\""));

    let slot_id = access
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.split('\t').next())
        .expect("access slot id");
    run_in(
        bin,
        &["access", "rm", lockbox.to_str().unwrap(), slot_id],
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
        &["create", "--password", lockbox.to_str().unwrap()],
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
    assert!(init.contains("Create the local reVault vault."));
    assert!(init.contains("Stores:\n  - identities and contacts"));
    assert!(init.contains("  - key-directory backups for shared lockboxes\n\n"));
    assert!(!init.contains("Set a vault password."));
    assert!(!init.contains("The vault stores identities, contacts, and"));
    assert!(!init.contains("Choose a vault password you can remember or store securely."));
    assert!(!init.contains("Choose a vault password you can back up safely."));
    assert!(init.contains("Vault created successfully."));
    assert!(init.contains("Directory:\n  "));
    assert!(init.contains("Identity: default"));
    assert!(init.contains(
        "Pass phrase reminder:\n  Store the vault pass phrase somewhere safe.\n  If it is lost, reVault cannot recover this vault."
    ));
    assert!(!init.contains("Path:"));
    assert!(!init.contains("Default identity:\n  default"));
    assert!(!init.contains("Created default identity: default"));
    assert!(!init.contains("Password reminder:"));
    assert!(!init.contains("Store the vault password somewhere safe."));
    assert!(!init.contains("Keep the vault password somewhere safe."));
    assert!(!init.contains("Record your vault password in a secure place"));
    assert!(!init.contains("Back up your vault password before storing important keys."));
    assert_contains_in_order(
        &init,
        &[
            "Create the local reVault vault.",
            "Vault created successfully.",
            "Directory:",
            "Identity: default",
            "Pass phrase reminder:",
            "If it is lost, reVault cannot recover this vault.",
        ],
    );
    assert!(vault_root.join("local-vault.lbox").exists());

    let auto_open = run_output_without_content_key(
        bin,
        &["session", "auto-open", "status", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&auto_open);
    assert!(String::from_utf8_lossy(&auto_open.stdout).contains("scope\tlockboxes"));

    let vault_list = run_output_without_content_key(
        bin,
        &["vault", "identity", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&vault_list);
    let vault_list = String::from_utf8_lossy(&vault_list.stdout);
    assert!(vault_list.contains("default"));

    run_without_content_key(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(lockbox.exists());
}

#[test]
fn vault_init_rejects_blank_pass_phrase() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("blank-vault-pass-phrase");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    let output = Command::new(bin)
        .args(["vault", "init"])
        .env("LOCKBOX_PASSWORD", "test-lockbox-password")
        .env("LOCKBOX_VAULT_PASSWORD", "")
        .env("LOCKBOX_SESSION_AGENT_DIR", &agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(&agent_root))
        .env("LOCKBOX_VAULT_DIR", &vault_root)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vault pass phrase must be at least 15 characters"));
    assert!(!vault_root.join("local-vault.lbox").exists());
}

#[test]
fn vault_publish_without_identity_email_is_actionable() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("publish-missing-email");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    let publish =
        run_output_without_content_key(bin, &["vault", "publish"], &vault_root, &agent_root);
    assert!(!publish.status.success());
    let stderr = String::from_utf8_lossy(&publish.stderr);
    assert!(stderr.contains(
        "You may not publish a public key for an Identity that does not have an email address."
    ));
    assert!(stderr.contains("The identity `default` has no email address."));
    assert!(stderr.contains("Run `lockbox vault identity email default <email>`."));
    assert!(stderr.contains("Then run this command again."));
    assert!(!stderr.contains("invalid input"));
    assert!(!stderr.contains("Check the supplied value"));
}

#[test]
fn vault_init_prompt_mentions_minimum_pass_phrase_length() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-pass-phrase-prompt");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    let mut child = Command::new(bin)
        .args(["vault", "init"])
        .env("LOCKBOX_PASSWORD", "test-lockbox-password")
        .env_remove("LOCKBOX_VAULT_PASSWORD")
        .env("LOCKBOX_SESSION_AGENT_DIR", &agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(&agent_root))
        .env("LOCKBOX_VAULT_DIR", &vault_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"2\n\n\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Vault pass phrase:"));
    assert!(stdout.contains("1. Generate a strong pass phrase"));
    assert!(stdout.contains("2. Enter my own pass phrase"));
    assert!(stdout.contains("New vault pass phrase (minimum 15 characters):"));
    assert!(stderr.contains("vault pass phrase must be at least 15 characters"));
    assert!(!vault_root.join("local-vault.lbox").exists());
}

#[test]
fn vault_init_generated_pass_phrase_requires_stored_confirmation() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-pass-phrase-generated");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    let mut child = Command::new(bin)
        .args(["vault", "init"])
        .env("LOCKBOX_PASSWORD", "test-lockbox-password")
        .env_remove("LOCKBOX_VAULT_PASSWORD")
        .env("LOCKBOX_SESSION_AGENT_DIR", &agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(&agent_root))
        .env("LOCKBOX_VAULT_DIR", &vault_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"\n\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Generated vault pass phrase:"));
    assert!(stdout.contains("Store this in your password manager before continuing."));
    assert!(stdout.contains("Continue after storing it? [y/N]:"));
    assert!(stderr.contains("vault pass phrase was not confirmed as stored"));
    assert!(!vault_root.join("local-vault.lbox").exists());
}

#[test]
fn vault_init_generated_pass_phrase_accepts_stored_confirmation() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-pass-phrase-generated-yes");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    let mut child = Command::new(bin)
        .args(["vault", "init"])
        .env("LOCKBOX_PASSWORD", "test-lockbox-password")
        .env_remove("LOCKBOX_VAULT_PASSWORD")
        .env("LOCKBOX_SESSION_AGENT_DIR", &agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(&agent_root))
        .env("LOCKBOX_VAULT_DIR", &vault_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"\ny\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Generated vault pass phrase:"));
    assert!(stdout.contains("Continue after storing it? [y/N]:"));
    assert!(stdout.contains("Vault created successfully."));
    assert!(vault_root.join("local-vault.lbox").exists());
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
    assert!(!existing.contains("Vault open successfully."));
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
    assert!(!verified.contains("Directory:"));
}

#[test]
fn vault_init_verify_wrong_password_reports_vault_specific_error() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-init-wrong-password");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);

    let output = Command::new(bin)
        .args(["vault", "init", "--verify"])
        .env("LOCKBOX_PASSWORD", "test-lockbox-password")
        .env("LOCKBOX_VAULT_PASSWORD", "wrong-vault-password")
        .env("LOCKBOX_SESSION_AGENT_DIR", &agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(&agent_root))
        .env("LOCKBOX_VAULT_DIR", &vault_root)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vault open failed: check the vault pass phrase"));
    assert!(stderr.contains("local vault file may be damaged"));
    assert!(!stderr.contains("content key"));
    assert!(!stderr.contains("recipient keypair"));
    assert!(!stderr.contains("local vault open state"));
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
    run_without_content_key(
        bin,
        &["vault", "identity", "create", "extra"],
        &vault_root,
        &agent_root,
    );

    let before = run_output_without_content_key(
        bin,
        &["vault", "identity", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&before);
    assert!(String::from_utf8_lossy(&before.stdout).contains("extra"));

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
    assert!(overwritten.contains("Created default identity: default"));

    let after = run_output_without_content_key(
        bin,
        &["vault", "identity", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&after);
    let after = String::from_utf8_lossy(&after.stdout);
    assert!(after.contains("default"));
    assert!(!after.contains("extra"));
}

#[test]
fn vault_backup_and_restore_round_trip_encrypted_vault() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-backup-restore");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let backup = dir.join("vault.lockbox-backup");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["vault", "identity", "create", "extra"],
        &vault_root,
        &agent_root,
    );

    let backed_up = run_output_without_content_key(
        bin,
        &["vault", "backup", backup.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&backed_up);
    let backed_up = String::from_utf8_lossy(&backed_up.stdout);
    assert!(backed_up.contains("Backup completed successfully."));
    assert!(backed_up.contains("Vault path: "));
    assert!(backed_up.contains("local-vault.lbox"));
    assert!(backed_up.contains("Backup path: "));
    assert!(backup.exists());
    let backup_path = backup.canonicalize().unwrap();
    assert!(backed_up.contains(backup_path.to_str().unwrap()));
    assert!(!backed_up.contains("backup="));
    assert!(!backed_up.contains("vault_sha256="));
    assert!(!backed_up.contains("created_at_utc="));

    fs::remove_file(vault_root.join("local-vault.lbox")).unwrap();

    let restored = run_output_without_content_key(
        bin,
        &["vault", "restore", backup.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&restored);
    assert!(String::from_utf8_lossy(&restored.stdout).contains("Vault restored successfully."));

    let after_restore = run_output_without_content_key(
        bin,
        &["vault", "identity", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&after_restore);
    let after_restore = String::from_utf8_lossy(&after_restore.stdout);
    assert!(after_restore.contains("default"));
    assert!(after_restore.contains("extra"));

    let refused = run_output_without_content_key(
        bin,
        &["vault", "restore", backup.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("pass --overwrite"));

    let overwritten = run_output_without_content_key(
        bin,
        &["vault", "restore", "--overwrite", backup.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&overwritten);
}

#[test]
fn vault_identity_create_names_default_and_rejects_public_key_output() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-identity-output");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    let output = run_output_without_content_key(
        bin,
        &["vault", "identity", "create"],
        &vault_root,
        &agent_root,
    );
    assert_success(&output);
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("Using default identity name: default"));
    assert!(output.contains("Created vault identity: default"));
    assert!(output.contains("lockbox vault identity export default <public-key-output>"));

    let named = run_output_without_content_key(
        bin,
        &["vault", "identity", "create", "named"],
        &vault_root,
        &agent_root,
    );
    assert_success(&named);
    let named = String::from_utf8_lossy(&named.stdout);
    assert!(named.contains("Created vault identity: named"));
    assert!(named.contains("lockbox vault identity export named <public-key-output>"));

    let refused_public_output = run_output_without_content_key(
        bin,
        &["vault", "identity", "create", "other", "other.pub"],
        &vault_root,
        &agent_root,
    );
    assert!(!refused_public_output.status.success());
    assert!(String::from_utf8_lossy(&refused_public_output.stderr).contains("unexpected argument"));
}

#[test]
fn vault_identity_remove_requires_confirmation_and_force_bypasses_it() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-identity-remove-confirm");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["vault", "identity", "create", "temp"],
        &vault_root,
        &agent_root,
    );

    let refused = run_output_without_content_key_with_stdin(
        bin,
        &["vault", "identity", "remove", "temp"],
        &vault_root,
        &agent_root,
        "no\n",
    );
    assert_success(&refused);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("Remove vault identity 'temp'?"));
    assert!(String::from_utf8_lossy(&refused.stdout).contains("Vault identity not removed: temp"));

    let list = run_output_without_content_key(
        bin,
        &["vault", "identity", "ls", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("temp"));

    let forced = run_output_without_content_key(
        bin,
        &["vault", "identity", "remove", "--force", "temp"],
        &vault_root,
        &agent_root,
    );
    assert_success(&forced);
    assert!(String::from_utf8_lossy(&forced.stdout).contains("Vault identity removed: temp"));
}

#[test]
fn vault_identity_rotate_history_and_access_refresh_flow() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = short_target_dir("identity-refresh");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("shared.lbox");
    let current_private = dir.join("current.private");

    run_in(bin, &["vault", "init"], &vault_root, &agent_root);
    run_in(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &["access", "add", lockbox.to_str().unwrap(), "default"],
        &vault_root,
        &agent_root,
    );

    let rotated = run_output_in(
        bin,
        &["vault", "identity", "rotate", "default"],
        &vault_root,
        &agent_root,
    );
    assert_success(&rotated);
    let rotated = String::from_utf8_lossy(&rotated.stdout);
    assert!(rotated.contains("Rotated vault identity: default"));
    assert!(rotated.contains("Active generation: 2"));

    let history = run_output_in(
        bin,
        &["vault", "identity", "history", "default", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&history);
    let history = String::from_utf8_lossy(&history.stdout);
    assert!(history.contains("\t1\tretired\t"));
    assert!(history.contains("\t2\tactive\t"));

    run_in(
        bin,
        &[
            "vault",
            "identity",
            "export-private",
            "default",
            current_private.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    let current_key = import_private_key_file(&current_private).unwrap();
    assert!(Lockbox::open_file(&lockbox, LockboxUnlock::RecipientKeyPair(current_key)).is_err());

    let dry_run = run_output_in(
        bin,
        &[
            "access",
            "refresh",
            lockbox.to_str().unwrap(),
            "default",
            "--dry-run",
        ],
        &vault_root,
        &agent_root,
    );
    assert_success(&dry_run);
    let dry_run = String::from_utf8_lossy(&dry_run.stdout);
    assert!(dry_run.contains("matching access entries: 1"));
    assert!(dry_run.contains("No access entries were changed."));

    let refreshed = run_output_in(
        bin,
        &[
            "access",
            "refresh",
            lockbox.to_str().unwrap(),
            "default",
            "--yes",
        ],
        &vault_root,
        &agent_root,
    );
    assert_success(&refreshed);
    assert!(String::from_utf8_lossy(&refreshed.stdout)
        .contains("Refreshed access for 1 lockbox/identity pairs."));

    let current_key = import_private_key_file(&current_private).unwrap();
    Lockbox::open_file(&lockbox, LockboxUnlock::RecipientKeyPair(current_key)).unwrap();
}

#[test]
fn vault_identity_export_reports_missing_output_for_named_identity() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("vault-key-export-error");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["vault", "identity", "create", "take-two"],
        &vault_root,
        &agent_root,
    );

    let output = run_output_without_content_key(
        bin,
        &["vault", "identity", "export-private", "take-two"],
        &vault_root,
        &agent_root,
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("missing private key output path for identity take-two"));
}

#[test]
fn session_and_close_report_empty_cache_and_already_closed_state() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("open-list-close");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("state.lbox");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["create", "--password", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    let unlock_list = run_output_without_content_key(bin, &["session"], &vault_root, &agent_root);
    assert_success(&unlock_list);
    let unlock_list = String::from_utf8_lossy(&unlock_list.stdout);
    assert!(unlock_list.contains("Active lockbox:"));
    assert!(unlock_list.contains("Open lockboxes:"));
    assert!(unlock_list.contains("none"));

    run_without_content_key(
        bin,
        &["session", "activate", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    let closed = run_output_without_content_key(bin, &["close"], &vault_root, &agent_root);
    assert_success(&closed);
    assert!(String::from_utf8_lossy(&closed.stdout).contains("already closed"));

    let closed = run_output_without_content_key(
        bin,
        &["close", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&closed);
    assert!(String::from_utf8_lossy(&closed.stdout).contains("already closed"));

    let lock_all =
        run_output_without_content_key(bin, &["session", "close-all"], &vault_root, &agent_root);
    assert_success(&lock_all);
    assert!(String::from_utf8_lossy(&lock_all.stdout).contains("sessions closed"));

    let auto_open_off = run_output_without_content_key(
        bin,
        &["session", "auto-open", "off"],
        &vault_root,
        &agent_root,
    );
    assert_success(&auto_open_off);

    let listing = run_output_without_content_key(
        bin,
        &["list", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(!listing.status.success());
    assert!(String::from_utf8_lossy(&listing.stderr).contains("lockbox is closed"));
    assert!(!String::from_utf8_lossy(&listing.stderr).contains("Open the lockbox"));
    assert!(!String::from_utf8_lossy(&listing.stderr).contains("use the API intended"));
}

#[test]
fn session_activate_sets_default_lockbox_for_commands() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = short_target_dir("active");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("active.lbox");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["create", "--password", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    let activate = run_output_without_content_key(
        bin,
        &["session", "activate", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&activate);

    let session = run_output_without_content_key(bin, &["session"], &vault_root, &agent_root);
    assert_success(&session);
    let session = String::from_utf8_lossy(&session.stdout);
    let active_lockbox = lockbox.canonicalize().unwrap();
    assert!(session.contains("Active lockbox:"));
    assert!(session.contains(active_lockbox.to_str().unwrap()));

    let listing = run_output_without_content_key(bin, &["list"], &vault_root, &agent_root);
    assert_success(&listing);

    let missing_add = run_output_without_content_key(
        bin,
        &["add", dir.join("missing.md").to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(!missing_add.status.success());
    assert!(String::from_utf8_lossy(&missing_add.stderr).contains("file not found:"));
    assert!(!String::from_utf8_lossy(&missing_add.stderr).contains("unsupported host path"));

    let source = dir.join("readme.md");
    fs::write(&source, "active lockbox add\n").unwrap();
    let add = run_output_without_content_key(
        bin,
        &["add", source.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&add);

    let listing = run_output_without_content_key(bin, &["list"], &vault_root, &agent_root);
    assert_success(&listing);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("readme.md"));

    let explicit = dir.join("explicit.lbox");
    run_without_content_key(
        bin,
        &["create", "--password", explicit.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    let explicit_source = dir.join("explicit.txt");
    fs::write(&explicit_source, "explicit lockbox add\n").unwrap();
    let explicit_add = run_output_without_content_key(
        bin,
        &[
            "add",
            explicit.to_str().unwrap(),
            explicit_source.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    assert_success(&explicit_add);

    let explicit_listing = run_output_without_content_key(
        bin,
        &["list", explicit.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_success(&explicit_listing);
    assert!(String::from_utf8_lossy(&explicit_listing.stdout).contains("explicit.txt"));

    fs::remove_file(&lockbox).unwrap();
    let missing_active = run_output_without_content_key(
        bin,
        &["add", source.to_str().unwrap(), "/after-delete.md"],
        &vault_root,
        &agent_root,
    );
    assert!(!missing_active.status.success());
    let stderr = String::from_utf8_lossy(&missing_active.stderr);
    assert!(stderr.contains(&format!(
        "active lockbox not found: {}",
        active_lockbox.display()
    )));
    assert!(!stderr.contains("Check the supplied value"));
}

#[test]
fn session_active_lockbox_applies_to_lockbox_argument_variants() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = short_target_dir("active-variants");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("active.lbox");

    run_in(bin, &["vault", "init"], &vault_root, &agent_root);
    run_in(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &["session", "activate", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );

    let source = dir.join("a.txt");
    fs::write(&source, "alpha").unwrap();
    run_in(
        bin,
        &["add", source.to_str().unwrap(), "/docs/a.txt"],
        &vault_root,
        &agent_root,
    );

    let listing = run_output_in(
        bin,
        &["list", "--recursive", "--format", "tsv", "/docs"],
        &vault_root,
        &agent_root,
    );
    assert_success(&listing);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("/docs/a.txt"));

    let cat = run_output_in(bin, &["cat", "/docs/a.txt"], &vault_root, &agent_root);
    assert_success(&cat);
    assert_eq!(String::from_utf8_lossy(&cat.stdout), "alpha");

    let extracted = dir.join("extracted.txt");
    run_in(
        bin,
        &["extract", "/docs/a.txt", extracted.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_eq!(fs::read_to_string(&extracted).unwrap(), "alpha");

    let restored = dir.join("restore");
    run_in(
        bin,
        &["extract", "--to", restored.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert_eq!(
        fs::read_to_string(restored.join("docs").join("a.txt")).unwrap(),
        "alpha"
    );

    run_in(
        bin,
        &["rename", "/docs/a.txt", "/docs/b.txt"],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &["rm", "--force", "/docs/b.txt"],
        &vault_root,
        &agent_root,
    );

    run_in(
        bin,
        &["var", "set", "/prod/API_KEY", "normal-key"],
        &vault_root,
        &agent_root,
    );
    let value = run_output_in(
        bin,
        &["variables", "get", "/prod/API_KEY"],
        &vault_root,
        &agent_root,
    );
    assert_success(&value);
    assert_eq!(String::from_utf8_lossy(&value.stdout), "normal-key\n");

    let variables = run_output_in(
        bin,
        &["variables", "list", "--format", "tsv", "/prod"],
        &vault_root,
        &agent_root,
    );
    assert_success(&variables);
    assert!(String::from_utf8_lossy(&variables.stdout).contains("/prod/API_KEY"));

    let exported = run_output_in(
        bin,
        &["variables", "export", "--format", "json", "/prod"],
        &vault_root,
        &agent_root,
    );
    assert_success(&exported);
    assert!(String::from_utf8_lossy(&exported.stdout)
        .contains("{\"name\":\"API_KEY\",\"value\":\"normal-key\"}"));
    run_in(
        bin,
        &["variables", "rm", "/prod/API_KEY"],
        &vault_root,
        &agent_root,
    );

    run_in(
        bin,
        &[
            "form",
            "define",
            "login",
            "--field",
            "username:text",
            "--field",
            "password:secret",
        ],
        &vault_root,
        &agent_root,
    );
    let definitions = run_output_in(
        bin,
        &["form", "definitions", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&definitions);
    assert!(String::from_utf8_lossy(&definitions.stdout).contains("login"));

    run_in(
        bin,
        &[
            "form",
            "add",
            "/work/github",
            "--type",
            "login",
            "--set",
            "username=bsutton",
        ],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &["form", "set", "/work/github", "username", "alice"],
        &vault_root,
        &agent_root,
    );
    let username = run_output_in(
        bin,
        &["form", "get", "/work/github", "username"],
        &vault_root,
        &agent_root,
    );
    assert_success(&username);
    assert_eq!(String::from_utf8_lossy(&username.stdout), "alice\n");

    let shown = run_output_in(
        bin,
        &["form", "show", "/work/github"],
        &vault_root,
        &agent_root,
    );
    assert_success(&shown);
    assert!(String::from_utf8_lossy(&shown.stdout).contains("field\tusername"));

    let forms = run_output_in(
        bin,
        &["form", "list", "--format", "tsv", "/work"],
        &vault_root,
        &agent_root,
    );
    assert_success(&forms);
    assert!(String::from_utf8_lossy(&forms.stdout).contains("/work/github"));

    run_in(
        bin,
        &["form", "edit", "/work/github", "--set", "username=bob"],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &["form", "rm", "/work/github"],
        &vault_root,
        &agent_root,
    );

    let visualize = run_output_in(bin, &["visualize"], &vault_root, &agent_root);
    assert_success(&visualize);
    assert!(String::from_utf8_lossy(&visualize.stdout).contains("Lockbox"));

    let report = run_output_in(
        bin,
        &["recover", "--report", "--format", "json"],
        &vault_root,
        &agent_root,
    );
    assert_success(&report);
    assert!(String::from_utf8_lossy(&report.stdout).contains("file_count"));

    run_in(bin, &["access", "add", "default"], &vault_root, &agent_root);
    let access = run_output_in(
        bin,
        &["access", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&access);
    let access = String::from_utf8_lossy(&access.stdout);
    assert!(access.contains("\tdefault\tRecipient\t"));
    let default_slot = access
        .lines()
        .find(|line| line.contains("\tdefault\tRecipient\t"))
        .and_then(|line| line.split('\t').next())
        .expect("default access slot");

    let refresh = run_output_in(
        bin,
        &["access", "refresh", "default", "--dry-run"],
        &vault_root,
        &agent_root,
    );
    assert_success(&refresh);
    assert!(String::from_utf8_lossy(&refresh.stdout).contains("matching access entries"));

    let remove_access = run_output_in(
        bin,
        &["access", "rm", default_slot],
        &vault_root,
        &agent_root,
    );
    assert!(!remove_access.status.success());
    let remove_access = String::from_utf8_lossy(&remove_access.stderr);
    assert!(remove_access.contains("cannot remove the last access entry"));
    assert!(!remove_access.contains("missing lockbox"));

    run_in(bin, &["session", "deactivate"], &vault_root, &agent_root);
}

#[test]
fn auto_open_lockboxes_uses_remembered_password() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = short_target_dir("autolbx");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("remembered.lbox");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    let auto = run_output_without_content_key(
        bin,
        &["session", "auto-open", "lockboxes"],
        &vault_root,
        &agent_root,
    );
    assert_success(&auto);
    assert!(String::from_utf8_lossy(&auto.stdout).contains("lockboxes"));

    run_without_content_key(
        bin,
        &["create", "--password", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    let close = run_output_without_lockbox_password(
        bin,
        &["close", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    )
    .output()
    .unwrap();
    if is_session_agent_unavailable(&close) {
        eprintln!("skipping auto-open lockbox assertions: session agent unavailable");
        return;
    }
    assert_success(&close);

    let listing = run_output_without_lockbox_password(
        bin,
        &["list", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    )
    .output()
    .unwrap();
    assert_success(&listing);
}

#[test]
fn auto_open_lockboxes_with_vault_identity_allows_first_add() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = short_target_dir("autoidentity");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("mystuff.lbox");
    let source = dir.join("test.md");
    fs::write(&source, "hello issue\n").unwrap();

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["session", "auto-open", "lockboxes"],
        &vault_root,
        &agent_root,
    );
    run_without_content_key(
        bin,
        &["create", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    run_without_content_key(
        bin,
        &["session", "activate", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );

    let add = run_output_without_lockbox_password(
        bin,
        &["add", source.to_str().unwrap()],
        &vault_root,
        &agent_root,
    )
    .output()
    .unwrap();
    if is_session_agent_unavailable(&add) {
        eprintln!("skipping auto-open identity assertions: session agent unavailable");
        return;
    }
    assert_success(&add);
    assert!(!String::from_utf8_lossy(&add.stderr).contains("recipient-opened lockboxes"));

    let listing = run_output_without_lockbox_password(
        bin,
        &["list", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    )
    .output()
    .unwrap();
    assert_success(&listing);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("test.md"));
}

#[test]
fn unlock_accepts_password_sources_and_session_duration() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = short_target_dir("unlockpw");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let lockbox = dir.join("session.lbox");
    let lockbox_without_extension = dir.join("session");

    run_without_content_key(bin, &["vault", "init"], &vault_root, &agent_root);
    run_without_content_key(
        bin,
        &["create", "--password", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    run_without_content_key(bin, &["close", "--all"], &vault_root, &agent_root);

    let env_unlock = run_output_without_lockbox_password(
        bin,
        &[
            "open",
            "--password-env",
            "LBX_TEST_PASSWORD",
            lockbox_without_extension.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    )
    .env("LBX_TEST_PASSWORD", "test-lockbox-password")
    .output()
    .unwrap();
    if is_session_agent_unavailable(&env_unlock) {
        eprintln!("skipping session agent assertions: lockbox session agent unavailable");
        return;
    }
    assert_success(&env_unlock);
    run_without_content_key(
        bin,
        &["close", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );

    let password_file = dir.join("password.txt");
    fs::write(&password_file, "test-lockbox-password\n").unwrap();
    let file_unlock = run_output_without_lockbox_password(
        bin,
        &[
            "open",
            "--password-file",
            password_file.to_str().unwrap(),
            lockbox.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    )
    .output()
    .unwrap();
    assert_success(&file_unlock);
    run_without_content_key(
        bin,
        &["close", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );

    let stdin_unlock = run_output_without_lockbox_password_with_stdin(
        bin,
        &[
            "open",
            "--password-stdin",
            "--duration",
            "1s",
            lockbox.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
        "test-lockbox-password\n",
    );
    assert_success(&stdin_unlock);

    let sessions = run_output_without_content_key(
        bin,
        &["session", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    if is_session_agent_unavailable(&sessions) {
        eprintln!("skipping session agent assertions: lockbox session agent unavailable");
        return;
    }
    assert_success(&sessions);
    assert!(String::from_utf8_lossy(&sessions.stdout).contains(lockbox.to_str().unwrap()));

    thread::sleep(Duration::from_secs(2));
    let listing = run_output_without_content_key(
        bin,
        &["list", lockbox.to_str().unwrap()],
        &vault_root,
        &agent_root,
    );
    assert!(!listing.status.success());
    assert!(String::from_utf8_lossy(&listing.stderr).contains("lockbox is closed"));
}

fn is_session_agent_unavailable(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout.contains("lockbox session agent did not start")
        || stderr.contains("lockbox session agent did not start")
        || stdout.contains("lockbox session agent is not supported on this platform")
        || stderr.contains("lockbox session agent is not supported on this platform")
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
fn cli_secret_variables_require_explicit_source_and_redact_export() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("secret-variables");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let lockbox = dir.join("variables.lbox");
    let secret_file = dir.join("secret.txt");
    fs::write(&secret_file, "file-secret").unwrap();

    run(
        bin,
        &[
            "variables",
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
            "variables",
            "set",
            lockbox.to_str().unwrap(),
            "EMPTY_VALUE",
            "-v",
            "",
        ],
    );
    run(
        bin,
        &[
            "variables",
            "set",
            lockbox.to_str().unwrap(),
            "-s",
            "API_TOKEN",
            "-f",
            secret_file.to_str().unwrap(),
        ],
    );
    run(
        bin,
        &[
            "variables",
            "set",
            lockbox.to_str().unwrap(),
            "/production/APP_MODE",
            "-v",
            "prod-path",
        ],
    );
    run(
        bin,
        &[
            "variables",
            "set",
            lockbox.to_str().unwrap(),
            "/production/database/DATABASE_URL",
            "-v",
            "postgres://localhost/app",
        ],
    );
    run(
        bin,
        &[
            "variables",
            "set",
            lockbox.to_str().unwrap(),
            "/staging/APP_MODE",
            "-v",
            "staging-path",
        ],
    );

    let listing = run_output(
        bin,
        &[
            "variables",
            "list",
            "--format",
            "tsv",
            lockbox.to_str().unwrap(),
        ],
    );
    assert_success(&listing);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("/APP_MODE"));
    assert!(listing.contains("/EMPTY_VALUE"));
    assert!(listing.contains("/API_TOKEN\tsecret"));
    assert!(listing.contains("/production/APP_MODE"));

    let production_listing = run_output(
        bin,
        &[
            "variables",
            "list",
            "--format",
            "tsv",
            lockbox.to_str().unwrap(),
            "/production",
        ],
    );
    assert_success(&production_listing);
    let production_listing = String::from_utf8_lossy(&production_listing.stdout);
    assert!(production_listing.contains("/production/APP_MODE"));
    assert!(production_listing.contains("/production/database/DATABASE_URL"));
    assert!(!production_listing.contains("/staging/APP_MODE"));

    let app_mode_listing = run_output(
        bin,
        &[
            "variables",
            "list",
            "--format",
            "tsv",
            lockbox.to_str().unwrap(),
            "**/APP_MODE",
        ],
    );
    assert_success(&app_mode_listing);
    let app_mode_listing = String::from_utf8_lossy(&app_mode_listing.stdout);
    assert!(app_mode_listing.contains("/APP_MODE"));
    assert!(app_mode_listing.contains("/production/APP_MODE"));
    assert!(app_mode_listing.contains("/staging/APP_MODE"));
    assert!(!app_mode_listing.contains("/API_TOKEN"));

    let export = run_output(bin, &["variables", "export", lockbox.to_str().unwrap()]);
    assert_success(&export);
    let export = String::from_utf8_lossy(&export.stdout);
    assert!(export.contains("APP_MODE='prod'"));
    assert!(export.contains("production_APP_MODE='prod-path'"));
    assert!(export.contains("production_database_DATABASE_URL='postgres://localhost/app'"));
    assert!(export.contains("staging_APP_MODE='staging-path'"));
    assert!(!export.contains("API_TOKEN"));
    assert!(!export.contains("file-secret"));

    let production_export = run_output(
        bin,
        &[
            "variables",
            "export",
            lockbox.to_str().unwrap(),
            "/production",
        ],
    );
    assert_success(&production_export);
    let production_export = String::from_utf8_lossy(&production_export.stdout);
    assert!(production_export.contains("APP_MODE='prod-path'"));
    assert!(!production_export.contains("DATABASE_URL"));
    assert!(!production_export.contains("staging-path"));

    let powershell_export = run_output(
        bin,
        &[
            "variables",
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
            "variables",
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
            "variables",
            "export",
            "--format",
            "json",
            lockbox.to_str().unwrap(),
        ],
    );
    assert_success(&json_export);
    let json_export = String::from_utf8_lossy(&json_export.stdout);
    assert!(json_export.contains("{\"name\":\"APP_MODE\",\"value\":\"prod\"}"));
    assert!(json_export.contains("{\"name\":\"production_APP_MODE\",\"value\":\"prod-path\"}"));

    let secret_get = run_output(
        bin,
        &[
            "variables",
            "get",
            lockbox.to_str().unwrap(),
            "-s",
            "API_TOKEN",
        ],
    );
    assert_success(&secret_get);
    assert_eq!(
        String::from_utf8_lossy(&secret_get.stdout).trim(),
        "file-secret"
    );

    let empty_get = run_output(
        bin,
        &["variables", "get", lockbox.to_str().unwrap(), "EMPTY_VALUE"],
    );
    assert_success(&empty_get);
    assert_eq!(String::from_utf8_lossy(&empty_get.stdout), "\n");

    let missing_get = run_output(
        bin,
        &["variables", "get", lockbox.to_str().unwrap(), "MISSING"],
    );
    assert!(!missing_get.status.success());
    assert!(String::from_utf8_lossy(&missing_get.stderr).contains("not found"));

    let missing_secret_get = run_output(
        bin,
        &[
            "variables",
            "get",
            lockbox.to_str().unwrap(),
            "--secret",
            "MISSING",
        ],
    );
    assert!(!missing_secret_get.status.success());
    assert!(String::from_utf8_lossy(&missing_secret_get.stderr).contains("not found"));

    let report = run_output(
        bin,
        &[
            "recover",
            "--report",
            "--format",
            "tsv",
            lockbox.to_str().unwrap(),
        ],
    );
    assert_success(&report);
    let report = String::from_utf8_lossy(&report.stdout);
    assert!(report.contains("variables_recovered\ttrue"));
    assert!(report.contains("variable_count\t6"));

    let token_output = dir.join("api-token.txt");
    run(
        bin,
        &[
            "variables",
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
            "variables",
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
            "variables",
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
            "variables",
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
            "variables",
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
fn vault_identity_import_export_formats_are_accepted_by_cli() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir_named("key-formats");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let vault_root = dir.join("vault");
    let agent_root = dir.join("agent");
    let public_default = dir.join("default.pub");
    run_in(
        bin,
        &["vault", "identity", "create", "default"],
        &vault_root,
        &agent_root,
    );
    run_in(
        bin,
        &[
            "vault",
            "identity",
            "export",
            "default",
            public_default.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );

    let private_exports = [
        ("pem", None, "BEGIN LOCKBOX PRIVATE KEY"),
        ("jwk", Some("jwk"), "\"alg\": \"X25519-ML-KEM-768\""),
        ("jwks", Some("jwks"), "\"keys\""),
        ("raw", Some("raw-hex"), ""),
    ];
    for (name, format, expected) in private_exports {
        let path = dir.join(format!("private-{name}.key"));
        let mut args = vec!["vault", "identity", "export-private"];
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
                "identity",
                "import",
                &format!("imported-{name}"),
                path.to_str().unwrap(),
            ],
            &vault_root,
            &agent_root,
        );
    }

    let public_exports = [
        ("pem", None, "BEGIN LOCKBOX PUBLIC KEY"),
        ("jwk", Some("jwk"), "\"alg\": \"X25519-ML-KEM-768\""),
        ("jwks", Some("jwks"), "\"keys\""),
        ("raw", Some("raw-hex"), ""),
    ];
    for (name, format, expected) in public_exports {
        let path = dir.join(format!("public-{name}.key"));
        let mut args = vec!["vault", "identity", "export"];
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
                "contact",
                "add",
                &format!("contact-{name}"),
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
            "identity",
            "import",
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
            "contact",
            "add",
            "invalid",
            invalid_public.to_str().unwrap(),
        ],
        &vault_root,
        &agent_root,
    );
    assert!(!output.status.success());

    let identity_list = run_output_in(
        bin,
        &["vault", "identity", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&identity_list);
    let identity_list = String::from_utf8_lossy(&identity_list.stdout);
    let contact_list = run_output_in(
        bin,
        &["vault", "contact", "list", "--format", "tsv"],
        &vault_root,
        &agent_root,
    );
    assert_success(&contact_list);
    let contact_list = String::from_utf8_lossy(&contact_list.stdout);
    for name in ["pem", "jwk", "jwks", "raw"] {
        assert!(identity_list.contains(&format!("imported-{name}")));
        assert!(contact_list.contains(&format!("contact-{name}")));
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
        .env("LOCKBOX_SESSION_AGENT_DIR", agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(agent_root))
        .env("LOCKBOX_VAULT_DIR", vault_root)
        .output()
        .unwrap()
}

fn run_output_with_stdin(bin: &str, args: &[&str], stdin: &str) -> Output {
    run_output_in_with_stdin(
        bin,
        args,
        &unique_dir().join("vault"),
        &unique_dir().join("agent"),
        stdin,
    )
}

fn run_output_in_with_stdin(
    bin: &str,
    args: &[&str],
    vault_root: &PathBuf,
    agent_root: &PathBuf,
    stdin: &str,
) -> Output {
    let mut child = Command::new(bin)
        .args(args)
        .env("LOCKBOX_KEY", "test-key")
        .env("LOCKBOX_VAULT_PASSWORD", "test-vault-password")
        .env("LOCKBOX_SESSION_AGENT_DIR", agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(agent_root))
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
        .env("LOCKBOX_SESSION_AGENT_DIR", agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(agent_root))
        .env("LOCKBOX_VAULT_DIR", vault_root)
        .output()
        .unwrap()
}

fn run_output_without_lockbox_password(
    bin: &str,
    args: &[&str],
    vault_root: &PathBuf,
    agent_root: &PathBuf,
) -> Command {
    let mut command = Command::new(bin);
    command
        .args(args)
        .env("LOCKBOX_VAULT_PASSWORD", "test-vault-password")
        .env("LOCKBOX_SESSION_AGENT_DIR", agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(agent_root))
        .env("LOCKBOX_VAULT_DIR", vault_root);
    command
}

fn run_output_without_lockbox_password_with_stdin(
    bin: &str,
    args: &[&str],
    vault_root: &PathBuf,
    agent_root: &PathBuf,
    stdin: &str,
) -> Output {
    let mut child = run_output_without_lockbox_password(bin, args, vault_root, agent_root)
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
        .env("LOCKBOX_SESSION_AGENT_DIR", agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(agent_root))
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

fn agent_log_path(agent_root: &PathBuf) -> PathBuf {
    agent_root.join("agent.log")
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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!(
            "lockbox-{label}-{}-{counter}-{nanos}",
            std::process::id()
        ))
}

fn short_target_dir(label: &str) -> PathBuf {
    let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/t")
        .join(format!("lb-{label}-{}-{counter}", std::process::id()))
}
