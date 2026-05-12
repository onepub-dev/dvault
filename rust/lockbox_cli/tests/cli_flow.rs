use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

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
    run(bin, &["vault", "remove-key", "default"]);
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

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn unique_dir() -> PathBuf {
    unique_dir_named("cli-flow")
}

fn unique_dir_named(label: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!("lockbox-{label}-{}", std::process::id()))
}
