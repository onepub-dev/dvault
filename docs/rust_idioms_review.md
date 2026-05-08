# Rust Idioms Review

This review covers the current Rust prototype shape.

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
  generating a vault UUID. Prefer `try_create` or make `create` return
  `Result<Self>` before stabilizing the public API.
- Some CLI behavior still lives in a single `main.rs`. Move commands into
  separate modules once the command set settles.
- Agent request handling is duplicated between Unix and Windows. The shared
  parser is now factored out, but response handling can be shared further.
- The core has raw-key APIs for test/developer use. Consider naming them
  `create_with_raw_key`/`open_with_raw_key` and making the password/recipient
  APIs the obvious default.
- `to_bytes()` clones the whole vault. That is fine for tests but should not be
  the main production persistence API.
- Several APIs still return `Vec<u8>` for convenience. Keep them, but add
  stream-first alternatives as the primary path in language bindings.
- The CLI should move from hand-rolled argument parsing to `clap` once command
  syntax stabilizes.

## Suggested Near-Term Refactors

- Add storage traits for file-backed operation.
- Add `commands/` modules for CLI commands.
- Move agent cache state and request execution into shared code used by both
  transports.
- Introduce `LockboxBuilder` or explicit constructors before API stabilization.
- Add `#[must_use]` where useful on builder/options types.
