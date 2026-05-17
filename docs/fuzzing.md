# Fuzzing

The Rust implementation includes `cargo-fuzz` scaffolding under `rust/fuzz`.

Targets:

- `header`: fixed-header and lockbox-id parsing.
- `key_directory`: password-slot/key-directory open path.
- `pages_recovery`: page scanning, recovery, and salvage.
- `paths`: logical path, symlink, and listing API inputs.

Run locally with:

```bash
cd rust/fuzz
cargo fuzz run header
cargo fuzz run key_directory
cargo fuzz run pages_recovery
cargo fuzz run paths
```

Next steps:

- Add seed corpora from valid small vaults, corrupted headers, corrupted
  TOCs, and path edge cases.
- Add CI/nightly fuzz smoke jobs with short time limits.
- Add dedicated TOC and payload decoder targets if those internals become
  public to the fuzz crate or move behind a fuzzing feature.
