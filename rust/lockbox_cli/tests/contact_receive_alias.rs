use std::process::{Command, Output};

#[test]
fn contact_receive_no_longer_accepts_fetch_alias() {
    let bin = env!("CARGO_BIN_EXE_lockbox");

    let receive_help = run_output(bin, &["vault", "contact", "receive", "--help"]);
    assert_success(&receive_help);

    let fetch_help = run_output(bin, &["vault", "contact", "fetch", "--help"]);
    assert!(!fetch_help.status.success());
    let stderr = String::from_utf8_lossy(&fetch_help.stderr);
    assert!(stderr.contains("unrecognized subcommand"));
    assert!(stderr.contains("fetch"));
}

fn run_output(bin: &str, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .env("LOCKBOX_TEST_MODE", "1")
        .env("LOCKBOX_DEVELOPER", "1")
        .output()
        .unwrap_or_else(|error| panic!("failed to run {bin}: {error}"))
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
