#!/usr/bin/env bash
set -euo pipefail

# Keep this list in sync with production crates. New Rust crates should be
# added here once they are intended to be part of the supported build.
cargo clippy -p lockbox_core -p lockbox_cli -p lockbox_vault --all-targets -- \
  -W clippy::pedantic \
  -W clippy::nursery \
  -W clippy::cargo \
  -A clippy::redundant_pub_crate \
  -A clippy::cargo_common_metadata \
  -A clippy::multiple_crate_versions \
  -A clippy::use_self
