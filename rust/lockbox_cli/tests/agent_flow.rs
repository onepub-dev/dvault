use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
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
    fs::create_dir_all(&agent_dir).unwrap();
    fs::write(&source, "alpha").unwrap();
    eprintln!("agent_flow: work dir {}", dir.display());
    eprintln!("agent_flow: agent log {}", agent_log(&agent_dir).display());

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

    let output = run_output(bin, &agent_dir, &["list", vault.to_str().unwrap(), "/docs"]);
    assert!(
        output.status.success(),
        "command failed: {bin} list {} /docs\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        vault.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("/docs/a.txt"));

    run(bin, &agent_dir, &["lock", vault.to_str().unwrap()]);
    let output = run_output(bin, &agent_dir, &["list", vault.to_str().unwrap(), "/docs"]);
    assert!(!output.status.success());
}

fn run(bin: &str, agent_dir: &PathBuf, args: &[&str]) {
    let status = run_status(bin, agent_dir, args);
    assert!(
        status.success(),
        "command failed: {bin} {}\nstatus: {}\nagent log:\n{}",
        args.join(" "),
        status,
        read_agent_log(agent_dir)
    );
}

fn run_status(bin: &str, agent_dir: &PathBuf, args: &[&str]) -> ExitStatus {
    let mut command = command(bin, agent_dir, args);
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let command_line = format!("{bin} {}", args.join(" "));
    eprintln!("agent_flow: starting {command_line}");
    let mut child = command.spawn().unwrap();
    eprintln!("agent_flow: spawned {command_line} pid={}", child.id());
    let done = spawn_watchdog(agent_dir, &command_line);
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            let status = child.wait().unwrap();
            done.store(true, Ordering::SeqCst);
            eprintln!("agent_flow: finished {command_line} with {status}");
            return status;
        }
        if Instant::now() >= deadline {
            eprintln!("agent_flow: killing timed out command {command_line}");
            done.store(true, Ordering::SeqCst);
            let _ = child.kill();
            panic!(
                "command timed out after {:?}: {command_line}\nagent log:\n{}",
                COMMAND_TIMEOUT,
                read_agent_log(agent_dir),
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn run_output(bin: &str, agent_dir: &PathBuf, args: &[&str]) -> Output {
    let mut command = command(bin, agent_dir, args);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let command_line = format!("{bin} {}", args.join(" "));
    eprintln!("agent_flow: starting {command_line}");
    let mut child = command.spawn().unwrap();
    eprintln!("agent_flow: spawned {command_line} pid={}", child.id());
    let done = spawn_watchdog(agent_dir, &command_line);
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            done.store(true, Ordering::SeqCst);
            eprintln!("agent_flow: finished {command_line} with {}", output.status);
            return output;
        }
        if Instant::now() >= deadline {
            eprintln!("agent_flow: killing timed out command {command_line}");
            done.store(true, Ordering::SeqCst);
            let _ = child.kill();
            panic!(
                "command timed out after {:?}: {command_line}\nagent log:\n{}",
                COMMAND_TIMEOUT,
                read_agent_log(agent_dir),
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn spawn_watchdog(agent_dir: &Path, command_line: &str) -> Arc<AtomicBool> {
    let done = Arc::new(AtomicBool::new(false));
    let watchdog_done = Arc::clone(&done);
    let watchdog_agent_dir = agent_dir.to_path_buf();
    let watchdog_command_line = command_line.to_string();
    thread::spawn(move || {
        thread::sleep(COMMAND_TIMEOUT);
        if watchdog_done.load(Ordering::SeqCst) {
            return;
        }
        eprintln!(
            "agent_flow: watchdog timeout after {:?}: {}",
            COMMAND_TIMEOUT, watchdog_command_line
        );
        eprintln!(
            "agent_flow: watchdog agent log:\n{}",
            read_agent_log(&watchdog_agent_dir)
        );
        std::process::exit(101);
    });
    done
}

fn command(bin: &str, agent_dir: &PathBuf, args: &[&str]) -> Command {
    let mut command = Command::new(bin);
    command
        .args(args)
        .env("LOCKBOX_PASSWORD", "test-password")
        .env("LOCKBOX_AGENT_DIR", agent_dir)
        .env("LOCKBOX_AGENT_TRACE", agent_log(agent_dir));
    command
}

fn agent_log(agent_dir: &Path) -> PathBuf {
    agent_dir.join("agent.log")
}

fn read_agent_log(agent_dir: &Path) -> String {
    fs::read_to_string(agent_log(agent_dir))
        .unwrap_or_else(|err| format!("<unable to read {}: {err}>", agent_log(agent_dir).display()))
}

fn unique_dir() -> PathBuf {
    std::env::temp_dir().join(format!("lockbox-agent-flow-{}", std::process::id()))
}
