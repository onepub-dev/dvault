use std::process::{Command, Output};

#[test]
fn open_key_help_says_it_opens_a_lockbox() {
    let bin = env!("CARGO_BIN_EXE_lockbox");

    let command_help = run_output(bin, &["open-key", "--help"]);
    assert_success(&command_help);
    let command_help = String::from_utf8_lossy(&command_help.stdout);
    assert!(command_help.contains("Open a lockbox using a vault private key."));

    let top_level_help = run_output(bin, &["--help", "--verbose"]);
    assert_success(&top_level_help);
    let top_level_help = String::from_utf8_lossy(&top_level_help.stderr);
    assert!(top_level_help.contains("open-key        Open a lockbox using a vault private key."));
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
