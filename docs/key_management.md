# Key Management Design

Lockbox uses a hybrid key model. Each lockbox has one random content key for
encrypting content. Access methods wrap that content key.

Terminology follows [terminology.md](terminology.md): a **lockbox** is the
portable `.lbox` encrypted container, while a **vault** is the user's local
private store on their own computer.

## Design Intent

The intended sharing model is narrow and practical:

- A user normally has one long-lived public/private recipient keypair.
- A lockbox can be unlocked with the user's private key.
- A lockbox can also be shared with a one-time password.
- A lockbox may contain both access methods at the same time.
- The public API and CLI should hide the content key from normal users.
- A lockbox must not store human recipient labels, email addresses, vault
  aliases, or stable recipient fingerprints that let observers correlate
  membership across independent lockboxes or local vaults.

This preserves the original Lockbox sharing idea:

```text
lockbox share important.txt
```

The sender creates a lockbox protected by a one-time passphrase, sends the
`.lbox` file, and gives the passphrase to the recipient through a separate
channel. The recipient does not need a Lockbox keypair for that use case.

## Use Cases

### Personal Lockboxes

The user creates a lockbox and unlocks it with their private key:

```text
recipient private key -> unwrap content key -> open lockbox
```

The same recipient keypair can unlock many lockboxes. The user does not need a
new keypair per lockbox.

### Password Sharing

The user creates or updates a lockbox with a password slot:

```text
password -> Argon2id -> unwrap content key -> open lockbox
```

This is for simple sharing where a recipient does not have a public key yet.
The password should be one-time or lockbox-specific, not the sender's normal
private-key passphrase.

### Public-Key Sharing

The user adds a recipient public key to the lockbox:

```text
recipient public key -> ML-KEM-1024 wraps content key
recipient private key -> ML-KEM-1024 unwraps content key
```

This is preferred for ongoing sharing because the recipient does not need to
know a shared password.

## Key Slots

A key slot is metadata that can unlock the content key.

Supported slot types:

- `password`: Argon2id parameters, salt, and encrypted content key.
- `recipient`: ML-KEM-1024 encapsulation data and encrypted content key.

The default metadata should be minimal:

```text
slot id
slot type
algorithm
parameters needed to unwrap the content key
encrypted content key
```

Human-readable labels are intentionally not part of the default model. Labels can
leak names, devices, email addresses, or organization structure. If labels are
added later, they should be optional and treated as public metadata unless
explicitly encrypted.

Recipient slots must also avoid stable recipient identifiers. The local vault
may use names such as `alice`, `prod-team`, or an email address to help the
local user manage trusted public keys, but those names are local-only. Adding a
trusted recipient to a lockbox resolves the local name to a public key and
writes only the slot material needed for unlock. The shared lockbox must not
receive the vault alias.

ML-KEM recipient slots store encapsulation ciphertext and the encrypted content
key. Encapsulation must be freshly randomized when a slot is created, so two
lockboxes shared with the same recipient should not contain the same recipient
slot bytes unless a serialized slot was deliberately copied. The format should
not add public-key fingerprints as convenience metadata, because fingerprints
would create a stable cross-lockbox membership correlation handle.

## Key Directory

Key slots are stored in clear-text key-directory metadata pages inside the
lockbox. The fixed header stores the byte offset of the current primary key
directory page. When key slots change, the current directory is written three
times through the page cache: a primary copy and two mirrors. The commit root
records the mirror offsets and key-directory generation. Ordinary file, env,
symlink, and TOC commits keep referencing the existing key-directory pages.
Because the key directory is a clear-text page class, password and recipient
unlock should read current key-directory pages through the page-cache
read/decode boundary. Raw byte scanning is reserved for damaged-header or
missing-root recovery.

The key directory is cleartext framing metadata, but it must not contain paths,
file names, environment variable names, or file contents. It contains only:

- slot count
- slot id
- slot type
- algorithm-specific public unwrap data
- encrypted/wrapped content key bytes

Password salts and ML-KEM ciphertexts are visible metadata. The content key
itself is never stored in cleartext.

The key directory is intentionally not a recipient directory. It must not store
recipient names, local vault aliases, email addresses, public keys, public-key
fingerprints, or other stable identity hints. A user who can open multiple
lockboxes should not be able to prove that the same named recipient has access
to each lockbox from key-directory metadata alone.

The key-directory payload header includes the lockbox UUID, generation, and copy
index. Integrity for the clear-text key-directory page is owned by the page
format: the page cache writes and validates the page checksum. If the fixed
header or primary key-directory copy is damaged, the library can scan the
lockbox for mirror pages, validate page checksums, try the password or
recipient key against those slots, recover the lockbox UUID and content key,
and then scan encrypted pages for the latest valid commit root.

The Rust implementation caps the encoded key directory at 1 MiB. That is enough
for thousands of slots, while preventing a corrupt or hostile lockbox from
forcing unbounded metadata allocation. A larger directory is rejected as a
security
limit violation.

## Slot Selection

The user does not need to know which slot belongs to them.

When opening with a password, the library reads the key directory and tries each
password slot until one decrypts and authenticates the wrapped content key. When
opening with a private recipient key, it tries each ML-KEM-1024 slot until one
decapsulates and authenticates. If none work, opening fails with an invalid-key
error.

This avoids labels as a required concept and keeps the default UX simple:

```rust
let password = SecretString::try_from_bytes(b"shared password".to_vec())?;
let lockbox = Lockbox::open_file(path, LockboxUnlock::Password(&password))?;
let lockbox = Lockbox::open_file(path, LockboxUnlock::RecipientKeyPair(my_private_key))?;
```

Labels or fingerprints can be added later as optional hints, but they are not
needed for correctness.

## Unlock Cache

The CLI uses an agent model for sudo-like unlock caching. The core library does
not cache passwords or keys.

```text
lockbox open secrets.lbox
  -> prompt for password/private-key passphrase
  -> unwrap the content key
  -> store the unwrapped content key in a per-user agent

lockbox list secrets.lbox
  -> read the public lockbox UUID from the header
  -> ask the agent for that content key
  -> extend the TTL on successful use

lockbox lock secrets.lbox
  -> remove that content key from the agent
```

The cache key is the current OS user plus the lockbox UUID. The lockbox UUID is
public header metadata and is generated randomly when the lockbox is created.
It is not derived from paths, file names, content, or recipients.

The cached value is the unwrapped content key, not the password and not the
private-key passphrase. It lives only in the agent process memory. There is no
session token or bearer key written to disk; a stored token would just become a
different secret that releases the content key.

The native vault API uses `SecretString`/secret byte wrappers for passwords and
cached content keys. These wrappers are implemented once in `lockbox_core` and
re-exported by `lockbox_vault`. They zeroize memory on drop, redact debug
output, and try to pin the backing allocation with `mlock` on Unix or
`VirtualLock` on Windows. Secure construction and mutation are fallible because
pinning, page protection, and corruption checks can fail.

Interactive CLI prompting reads bytes directly into `SecretString` rather than
building a password `String`. Language bindings should do the same where the
host platform allows it: accept a byte buffer, pass it over FFI/WASM as bytes,
and construct `SecretString::try_from_bytes` immediately on the Rust side. If a host
language can only provide immutable strings, that should be documented as a
weaker interop path because the host runtime may retain extra copies outside
Rust's control.

Passwords supplied through process environment variables may also exist in
OS/process environment storage outside the wrapper, so env-based passwords
remain a testing and automation escape hatch rather than the preferred
interactive path. Rust code that supports those variables must use
`SecretString::try_from_env` rather than first materializing the value as a normal
`String`.

Core key handling follows the same rule. Long-lived content keys and unlocked
content-key return values are stored in a secret wrapper that zeroizes memory on
drop and redacts debug output. Temporary derived content/wrapping keys are also
zeroized after use where the Rust APIs allow it. This is hardening against
accidental disclosure and simple memory reuse; it is not a complete defense
against malicious code running as the same OS user.

The TTL is sliding. Each successful cache lookup extends the expiry. The
current default is 15 minutes.

Transport requirements:

- Linux/macOS: Unix domain socket in a user-private runtime directory.
- Windows: named pipe with current-user SID validation. The production version
  should also set an explicit current-user-only DACL on the pipe.
- No TCP localhost listener by default.
- The agent should validate the caller's OS identity where the platform exposes
  peer credentials.

The reusable Rust implementation lives in the `lockbox_vault` crate. It exposes
a high-level `LocalVault` API for native CLIs and bindings, plus the lower-level
agent protocol helpers needed by alternate front ends. The Rust CLI uses that
crate rather than owning agent transport code itself.

`lockbox_vault` currently has Unix-domain-socket and Windows named-pipe
transport implementations. The Windows pipe is created with an owner-only DACL
and the server still validates the connecting client's SID against the agent
process user SID after connection. The dedicated Agent IPC GitHub Action runs
the smoke test on Linux, macOS, and Windows.

The persistent local vault is a password-encrypted `local-vault.lbox` file
stored in the platform-specific vault directory. It can store:

- the user's long-lived ML-KEM private key seed
- trusted recipient public keys
- local key-directory backups keyed by lockbox UUID

The vault is itself an ordinary lockbox, but `lockbox_vault::VaultDirectory`
uses a fixed internal record layout:

```text
local-vault.lbox
  secret env LOCKBOX_VAULT_PRIVATE_KEY_<HEX_NAME>
      Hex encoded ML-KEM private seed stored in secure env pages.
      <HEX_NAME> is the upper-case hex encoding of the user-visible key name.

  /trusted_recipients/<name>.pub
      Trusted recipient public key bytes.

  /key_directories/<lockbox-id>.keydir
      Encrypted key-directory backup for the referenced lockbox UUID.
```

The private-key records intentionally use the secure env-page path rather than
ordinary file records. Loading a vault private key therefore asks the page cache
for a secure page and materializes the seed into `SecretVec`, not `Vec<u8>`.
Trusted recipient keys and key-directory backups are not private-key seed
material, so they remain normal lockbox file records.

Vault record names are local user metadata. They are encrypted inside the local
vault, but they must not be copied into shared lockboxes. Two users may use
different local names for the same recipient key without affecting the portable
lockbox format.

These records are local recovery and convenience data. They are not required for
a password-shared lockbox to be portable, and they are not the canonical copy of
lockbox metadata.

Local vault private keys are protected by the vault lockbox password. The CLI
prompts for that password interactively, or reads `LOCKBOX_VAULT_PASSWORD` for
automation. Trusted public keys and key-directory backups are records inside
the vault lockbox.

When loaded, the long-lived ML-KEM private seed is held in `SecretVec`.
Unlock/export operations derive the ML-KEM decapsulation key only for the
duration of the operation. Export remains explicit plaintext output and is not
protected after it is written to a caller-owned buffer or file.

## Key File Formats

The default import/export format is native Lockbox PEM. It is text armored,
contains explicit `ML-KEM-1024` metadata, and is intended for CLI users:

```text
-----BEGIN LOCKBOX PRIVATE KEY-----
...
-----END LOCKBOX PRIVATE KEY-----
```

The CLI also supports JWK and JWKS using a Lockbox ML-KEM-1024 profile for web
and service integrations. Raw hex remains supported for developer/testing
compatibility, but should not be the default user-facing format.

Supported `--format` values:

- `lockbox-pem`
- `jwk`
- `jwks`
- `raw-hex`

## CLI Shape

Current/target commands:

```bash
lockbox create secrets.lbox
lockbox open secrets.lbox
lockbox list secrets.lbox
lockbox lock secrets.lbox

lockbox list-keys secrets.lbox
lockbox add-recipient secrets.lbox recipient.pub
lockbox remove-key secrets.lbox <slot-id>
```

The current Rust CLI prompts for passwords on `create` and `open`. It also
exposes `--key <raw-content-key>` as a developer/testing escape hatch for
low-level format tests and recovery work, but hides that option from normal help
output. Run `lockbox --help --verbose` to see developer and less common
options. Normal users should not type or manage raw content keys.

## Format Requirements

- The content key must be random and unique per lockbox.
- Content pages must be encrypted with keys derived from the content key.
- Passwords must never be used directly as content keys.
- Password slots must use Argon2id with stored parameters and salt.
- Public-key slots should use ML-KEM-1024 for post-quantum key wrapping.
- Removing a key slot must compact the lockbox so stale key-directory history is
  not left behind for the removed credential. Compaction is a logical rewrite
  into a replacement lockbox through the normal page-cache APIs, followed by a
  backing-storage swap.
- Rotating the content key should rewrite/wrap a new content key and eventually
  re-encrypt content.

## Non-Goals

- One keypair per lockbox by default.
- User-visible page or chunk management.
- Required labels for key slots.
- Broad user-selectable crypto modes.
