#!/usr/bin/env bash
set -euo pipefail

# Keep this list in sync with production crates. New Rust crates should be
# added here once they are intended to be part of the supported build.
cargo fmt -p lockbox_secure -p lockbox_core -p lockbox_cli -p lockbox_vault --check
cargo clippy -p lockbox_secure -p lockbox_core -p lockbox_cli -p lockbox_vault --all-targets -- -D warnings
cargo test -p lockbox_secure
cargo test -p lockbox_core
cargo test -p lockbox_cli
cargo test -p lockbox_vault
