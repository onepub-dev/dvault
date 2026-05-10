use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

#[test]
#[ignore = "requires local IPC support; disabled in sandboxed test runners"]
fn open_populates_cache_and_lock_clears_it() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir();
    fs::create_dir_all(&dir).unwrap();
    let vault = dir.join("test.lbox");
    let source = dir.join("source.txt");
    let agent_dir = dir.join("agent");
    let vault_dir = dir.join("vault");
    fs::create_dir_all(&agent_dir).unwrap();
    fs::create_dir_all(&vault_dir).unwrap();
    fs::write(&source, "alpha").unwrap();

    run(
        bin,
        &agent_dir,
        &vault_dir,
        &["create", vault.to_str().unwrap()],
    );
    run(
        bin,
        &agent_dir,
        &vault_dir,
        &[
            "add",
            vault.to_str().unwrap(),
            source.to_str().unwrap(),
            "/docs/a.txt",
        ],
    );

    let output = run_output(
        bin,
        &agent_dir,
        &vault_dir,
        &["list", vault.to_str().unwrap(), "/docs"],
    );
    assert!(
        output.status.success(),
        "command failed: {bin} list {} /docs\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        vault.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("/docs/a.txt"));

    run(
        bin,
        &agent_dir,
        &vault_dir,
        &["lock", vault.to_str().unwrap()],
    );
    let output = run_output(
        bin,
        &agent_dir,
        &vault_dir,
        &["list", vault.to_str().unwrap(), "/docs"],
    );
    assert!(!output.status.success());
}

fn run(bin: &str, agent_dir: &PathBuf, vault_dir: &PathBuf, args: &[&str]) {
    let status = run_status(bin, agent_dir, vault_dir, args);
    assert!(
        status.success(),
        "command failed: {bin} {}\nstatus: {}",
        args.join(" "),
        status
    );
}

fn run_status(bin: &str, agent_dir: &PathBuf, vault_dir: &PathBuf, args: &[&str]) -> ExitStatus {
    let mut command = command(bin, agent_dir, vault_dir, args);
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let command_line = format!("{bin} {}", args.join(" "));
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("command timed out after {COMMAND_TIMEOUT:?}: {command_line}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn run_output(bin: &str, agent_dir: &PathBuf, vault_dir: &PathBuf, args: &[&str]) -> Output {
    let mut command = command(bin, agent_dir, vault_dir, args);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let command_line = format!("{bin} {}", args.join(" "));
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("command timed out after {COMMAND_TIMEOUT:?}: {command_line}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn command(bin: &str, agent_dir: &PathBuf, vault_dir: &PathBuf, args: &[&str]) -> Command {
    let mut command = Command::new(bin);
    command
        .args(args)
        .env("LOCKBOX_PASSWORD", "test-password")
        .env("LOCKBOX_AGENT_DIR", agent_dir)
        .env("LOCKBOX_VAULT_DIR", vault_dir);
    command
}

fn unique_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!("lockbox-agent-flow-{}", std::process::id()))
}
