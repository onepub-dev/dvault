# Design Discussion

This document captures open design directions that affect performance,
security, and operational ergonomics. It is intentionally decision-oriented:
each section separates the current state from proposed work.

## Async Writes

Current state: writes are synchronous and page-cache owned. A commit stages
decoded pages, asks the page cache to encode/encrypt/checksum/flush dirty
pages, then publishes the fixed header.

Recommendation: do not make the core page cache itself async first. Add an
async CLI/library facade only after the synchronous commit path has a clear
work queue boundary. The page cache should remain the single owner of page
encoding, COW redaction, and dirty-page publication.

Useful shape:

- Build file frames and metadata objects on worker tasks.
- Send ready page objects to one page-cache writer.
- Keep header publication single-threaded and last.
- Keep recovery and compaction using the same page-cache write APIs.

Main risk: async writes can make crash-consistency reasoning harder. The
ordering rule must remain explicit: no header publish until every dirty page
and every redaction page has reached durable storage.

## Multi-Threaded Pipeline

Current state: extraction can parallelize file extraction in selected
file-backed cases, but import and commit are mostly single-threaded.

Recommendation: use a bounded pipeline, not unbounded per-file tasks.

Proposed pipeline:

1. Reader workers load source bytes and validate paths/permissions.
2. Codec workers compress or decide to store uncompressed.
3. Page-object packers group encoded objects into pages.
4. A single page-cache writer assigns offsets, stages pages, flushes, redacts,
   and publishes the commit.

Backpressure should be byte-based, not file-count-based, so a directory full of
large files cannot queue unbounded memory. The writer remains serialized
because it owns free-space reuse, COW, and commit ordering.

## Passkeys

Passkeys are FIDO/WebAuthn credentials. Their normal operation authenticates a
user by signing a challenge; it does not directly release a decryption key. The
WebAuthn PRF extension changes that for supported authenticators by returning a
deterministic per-credential secret during an authentication ceremony.

Recommendation: passkey support is feasible, but it should be a new unlock
slot type, not a replacement for passwords or recipient slots.

Candidate design:

- Register a WebAuthn credential and store its credential id and public key in
  a key slot.
- If PRF is supported, derive a wrapping key from the PRF output and wrap the
  content key.
- Require a recovery path because not every platform/authenticator supports
  PRF consistently.
- Treat passkeys without PRF as authentication-only; they can authorize release
  from an external service but cannot locally decrypt without another wrapped
  key.

Open issues:

- Native CLI support needs CTAP2/WebAuthn client libraries and platform
  ceremony UX.
- Synced passkeys improve recovery but alter the threat model because the
  credential may be recoverable through a platform account.
- Hardware-bound credentials are stronger for local compromise, but recovery is
  harder.

## GPG Interop

Supporting encrypted `.gpg` files is practical as an interoperability feature,
but it is a separate file format and trust model.

Two useful modes:

- Import/export: decrypt a `.gpg` file with GnuPG, then write plaintext into a
  lockbox; or extract a lockbox file and encrypt it with GnuPG.
- Key management helper: use our CLI to organize recipients, backups, and
  workflow around GnuPG keys without reimplementing the OpenPGP stack.

Recommendation: prefer invoking `gpg` as an external tool for interop, with
strict streaming and temp-file hygiene, before considering native OpenPGP
parsing. Do not mix GPG keys into the lockbox key directory until there is a
clear mapping from OpenPGP recipient identities to lockbox recipient slots.

GPG helper ideas:

- `lockbox gpg import file.gpg /path/in/lockbox`
- `lockbox gpg export /path/in/lockbox file.gpg --recipient <key>`
- `lockbox gpg recipients` to inspect usable public keys.
- A migration report showing which GPG recipients correspond to lockbox
  recipient keys.

Security notes:

- Avoid writing decrypted GPG plaintext to disk.
- Do not cache GPG passphrases ourselves.
- Surface exactly which GPG binary and home directory are used.

## OS Keyring

OS keyrings can improve secret storage for local agent material, but they do
not replace the lockbox format.

Recommendation: support OS keyrings as an optional backend for cached content
keys or local vault unlock helpers, not as the only place where lockbox access
is recoverable.

Tradeoffs:

- macOS Keychain, Windows Credential Manager, and Linux Secret Service/libsecret
  integrate with user login/session protections and platform prompts.
- OS keyrings are not portable and can be hard to use in headless automation,
  containers, and remote shells.
- Attributes/metadata may be searchable or less protected than the secret
  value itself; never store sensitive path names or env names as keyring
  attributes.
- A compromised logged-in user session can often request the same keyring item
  unless platform access controls require user presence.

Likely design:

- Keep `local-vault.lbox` as the portable encrypted store.
- Add `ContentKeyStore` implementations for platform keyrings.
- Keep the current agent as the default minimal backend on unsupported or
  headless platforms.
- Store only content keys or vault-unlock helper keys, not raw passwords.

## Profiling, zlib, and Unsafe Code

Current compression uses `oxiarc-zstd`; the workspace lockfile does not include
zlib/libz/flate dependencies for the lockbox crates. Earlier benchmark notes
also record the move away from a C zstd backend.

Recommendation: stay off zlib unless a benchmark proves a specific workload
needs it. A C compression dependency adds FFI and supply-chain surface. If we
need a faster backend, evaluate safe Rust alternatives first, then explicitly
audit any FFI boundary.

Current unsafe code exists, but it is constrained:

- `lockbox_core`: `mlock`/`munlock` and `VirtualLock`/`VirtualUnlock`.
- `lockbox_cli`: Unix terminal echo control and Windows console input.
- `lockbox_vault`: Windows named-pipe, token, SID, and handle APIs.

The crates now deny unsafe operations inside unsafe functions and deny unsafe
blocks without safety comments. Further reduction options:

- Keep OS calls behind tiny wrapper types.
- Prefer established crates for terminal and credential handling if they reduce
  local unsafe without weakening password handling.
- Avoid adding compression FFI unless profiling leaves no reasonable Rust path.

## Compaction Disk Usage

Current compaction creates a replacement lockbox, writes current state through the
normal page-cache APIs, commits it, then swaps the backing storage. This is
simple and preserves page-cache invariants, but peak disk usage can approach
old lockbox size plus new lockbox size.

Recommendation: keep replacement-file compaction as the default safe mode.

Potential mitigations:

- Preflight available disk space and report expected peak usage.
- Add `--compact-to <path>` so users can compact onto another filesystem.
- Add `--dry-run` with current bytes, stale bytes, and estimated output size.
- Consider future in-place compaction only if we can prove COW, redaction, and
  crash recovery remain simple. It should not move physical pages behind the
  page cache.

## Private Key Handling

Current state:

- `RecipientKeyPair` stores the long-lived private decapsulation seed in
  `SecretVec`.
- `RecipientKeyPair::generate()` and `to_seed_secure()` are fallible because secure
  storage can fail.
- Vault private-key storage uses scoped secret access instead of cloning the
  seed into an ordinary buffer.
- Import paths still parse encoded private-key material through normal
  text/JSON/base64/hex buffers, then zeroize decoded seed buffers after loading.

Remaining caution:

- Private-key export is explicitly plaintext output requested by the caller.
  Exported PEM/JWK/raw files are outside mlock and outside the secret store,
  and cannot provide zeroization guarantees once handed to the OS or another
  process.

The local vault password path is now better: passwords are owned as
`SecretString`, prompt input appends directly into `SecretString`, and env-var
passwords use `SecretString::try_from_env` rather than first allocating a Rust
`String`.

## Bombs and Malformed Lockboxes

Current protections:

- Page-body decode checks declared decompressed page size before allocation.
- File-frame decode verifies decoded length equals TOC length.
- Extraction policies enforce max single-file bytes, total bytes, and file
  count.
- TOC and TOC decoders reject impossible counts, malformed paths,
  traversal, unsorted entries, duplicates, and corrupt checksums.
- Recovery skips corrupt records and has tests for partial files, corrupt
  headers, corrupt TOCs, and truncated tails.
- Page reads validate page header checksums and either AEAD authentication or
  clear-text page checksums before decoding objects.

Remaining risks to test or harden:

- Zstd file-frame decompression does not currently pre-limit allocation before
  `decode_all`; it validates after decode. The expected length is known, so a
  bounded decoder or preflight limit should be added.
- Recovery scans over arbitrary damaged bytes can be CPU-heavy. Add scan byte
  limits, progress callbacks, or user-confirmed recovery mode for huge inputs.
- Object/page counts should continue to be bounded before allocation at every
  decoded layer.
- Path-backed extraction should preflight disk output size and fail before
  writing when policy limits would be exceeded.
- Compaction should preflight disk headroom.
- Key-directory scan should cap the number of candidate directories evaluated
  from malformed input.
- Password unlock may run Argon2 for every password slot. The key-directory
  maximum bounds this indirectly, but we should add an explicit key-slot count
  cap and a malformed-vault test.

Additional tests to add:

- Malformed zstd file frame with a tiny expected length and huge compressed
  expansion must fail without large allocation.
- Lockbox with many bogus page magic sequences must not cause unbounded
  recovery CPU or memory.
- Key directory with many wrong password slots must stay under a configured
  unlock work limit.
- Extraction to disk with many files must fail preflight without partial output
  when limits are exceeded.
- Compaction should fail early when a disk-space preflight hook reports
  insufficient space.

## References

- FIDO Alliance passkey overview: https://fidoalliance.org/passkeys/
- FIDO passkey implementation overview: https://fidoalliance.org/implement-passkeys-overview/
- W3C WebAuthn specification: https://www.w3.org/TR/webauthn/
- WebAuthn PRF extension explainer: https://github.com/w3c/webauthn/wiki/Explainer:-PRF-extension
- GnuPG manual: https://gnupg.org/documentation/manuals/gnupg/
- GnuPG operational commands: https://gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html
- Apple Keychain Services: https://developer.apple.com/documentation/Security/keychain-services
- Microsoft CredWrite API: https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritea
- Freedesktop Secret Service API: https://specifications.freedesktop.org/secret-service-spec/latest-single/
- GNOME libsecret simple API: https://gnome.pages.gitlab.gnome.org/libsecret/libsecret-simple-api.html
- zlib manual: https://www.zlib.net/manual.html
