use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "requires local IPC support; disabled in sandboxed test runners"]
fn open_populates_cache_and_lock_clears_it() {
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let dir = unique_dir();
    fs::create_dir_all(&dir).unwrap();
    let vault = dir.join("test.lbox");
    let source = dir.join("source.txt");
    let agent_dir = dir.join("agent");
    fs::write(&source, "alpha").unwrap();

    run(bin, &agent_dir, &["create", vault.to_str().unwrap()]);
    run(
        bin,
        &agent_dir,
        &[
            "add",
            vault.to_str().unwrap(),
            source.to_str().unwrap(),
            "/docs/a.txt",
        ],
    );

    let output = command(bin, &agent_dir, &["list", vault.to_str().unwrap(), "/docs"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("/docs/a.txt"));

    run(bin, &agent_dir, &["lock", vault.to_str().unwrap()]);
    let output = command(bin, &agent_dir, &["list", vault.to_str().unwrap(), "/docs"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

fn run(bin: &str, agent_dir: &PathBuf, args: &[&str]) {
    let output = command(bin, agent_dir, args).output().unwrap();
    assert!(
        output.status.success(),
        "command failed: {bin} {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn command(bin: &str, agent_dir: &PathBuf, args: &[&str]) -> Command {
    let mut command = Command::new(bin);
    command
        .args(args)
        .env("LOCKBOX_PASSWORD", "test-password")
        .env("LOCKBOX_AGENT_DIR", agent_dir);
    command
}

fn unique_dir() -> PathBuf {
    std::env::temp_dir().join(format!("lockbox-agent-flow-{}", std::process::id()))
}
