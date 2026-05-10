# Rust Idioms Review

This review covers the current Rust implementation shape.

## Good Direction

- The core and CLI are separate packages.
- Public API names are mostly filesystem-like and simple.
- Format internals are split into small modules rather than one large file.
- Fallible operations return `Result` and avoid panics in normal parsing paths.
- Secret material is wrapped in types that redact debug output and zeroize on
  drop.
- Platform-specific agent transports are isolated behind `cfg` modules.

## Cleanup Needed

- `Lockbox::create` currently panics if the system random source fails while
  generating a lockbox UUID. Prefer `try_create` or make `create` return
  `Result<Self>` before stabilizing the public API.
- CLI command behavior now lives under `lockbox_cli/src/commands/`, with
  `main.rs` kept as the binary entrypoint. The command module can still be split
  further by command family as the CLI grows.
- Agent request handling is duplicated between Unix and Windows. The shared
  parser is now factored out, but response handling can be shared further.
- The core has raw-key APIs for test/developer use. Consider naming them
  `create_with_raw_key`/`open_with_raw_key` and making the password/recipient
  APIs the obvious default.
- `to_bytes()` clones the whole lockbox. That is fine for tests but should not be
  the main production persistence API.
- Several APIs still return `Vec<u8>` for convenience. Keep them, but add
  stream-first alternatives as the primary path in language bindings.
- The CLI should move from hand-rolled argument parsing to `clap` once command
  syntax stabilizes.

## Suggested Near-Term Refactors

- Root-level core files have been moved into domain subdirectories:
  `format/` for header, page, payload, commit root, key directory, and codecs;
  `paths/` for logical and host paths; `keys/` for derivation, wrapping, slots,
  secret bytes, and crypto; `toc/` for manifest entries/codecs and BTree code;
  `storage/` for storage, page cache, free space, free index, cache options, and
  memory pressure; and `model/` for public data structs and shared record
  metadata.
- Keep `lockbox/` as the public operation facade, but consider grouping its
  modules as `lockbox/io.rs`, `lockbox/mutate.rs`, `lockbox/extract.rs`,
  `lockbox/recover.rs`, and `lockbox/keys.rs` once the API names settle.
- Split `lockbox_cli/src/commands/mod.rs` into command-family modules once the
  syntax stabilizes further. The current move keeps behavior unchanged while
  removing command handling from `main.rs`.
- Move agent cache state and request execution into shared code used by both
  transports.
- Introduce `LockboxBuilder` or explicit constructors before API stabilization.
- Add `#[must_use]` where useful on builder/options types.
