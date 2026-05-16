# Rust Development Guidance

This project follows local security and storage invariants first, then general
Rust idioms.

## References

Use these as the baseline:

- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Clippy documentation: https://doc.rust-lang.org/clippy/
- Clippy lint list: https://rust-lang.github.io/rust-clippy/master/

For a published skill-style reference, use the OpenClaw Rust skill as a light
checklist for ownership, borrowing, strings, errors, iterators, concurrency, and
unsafe pitfalls:

- https://playbooks.com/skills/openclaw/skills/rust

Do not import a generic implementation skill wholesale. It will miss project
rules around page-cache ownership, secret ownership, COW redaction, and recovery.

## Required Checks

Run from `rust/`:

```text
bash tools/check_required.sh
```

This script runs formatting, hard Clippy, and tests for the active Rust crates:
`lockbox_core`, `lockbox_cli`, and `lockbox_vault`.

When a new Rust crate becomes part of the supported build, add it to
`tools/check_required.sh`, `tools/clippy_advisory.sh`, and the CI workflow.

Hard Clippy means:

```text
cargo clippy -p lockbox_core -p lockbox_cli -p lockbox_vault --all-targets -- -D warnings
```

That treats Clippy's default lint groups as errors. It is required, but it is
not the strongest possible Clippy policy.

## API Docs

Generate the public `lockbox_core` API docs from `rust/`:

```text
bash tools/generate_api_docs.sh
```

The generated entry point is `rust/target/doc/lockbox_core/index.html`. The
generated HTML is build output and is not committed.

## Advisory Clippy

Run from `rust/`:

```text
bash tools/clippy_advisory.sh
```

This enables `clippy::pedantic`, `clippy::nursery`, and `clippy::cargo` as
warnings, with noisy metadata/visibility lints disabled. Treat the output as
review input, especially for public API, parser, crypto, page-cache, unsafe, and
compression work.

Do not require the advisory pass to be warning-free yet. Current useful warning
categories include unchecked integer casts, unnecessary `Result` wrappers,
large stack arrays in tests, missing public API error docs, and some avoidable
clones. Current noisy categories include style preferences such as `const fn`
candidates and long test functions.

Do not enable `clippy::restriction` wholesale. It is a collection of policy
lints, not an idiomatic-Rust profile. Cherry-pick restriction lints only when
they encode an actual project rule.

## Local Rules

- All normal page reads and writes go through the page cache.
- Passwords are owned and passed as `SecretString`.
- Long-lived secret bytes use `SecretVec` or a more specific secret wrapper.
- Keep `unsafe` blocks tiny, documented, and behind safe wrappers.
- Avoid `unwrap()`/`expect()` in production code unless the invariant is local
  and explicit.
- Public API changes need direct API tests, not only CLI coverage.
