# Key Management Design

Lockbox uses a hybrid key model. Each vault has one random vault key for
encrypting content. Access methods wrap that vault key.

## Design Intent

The intended sharing model is narrow and practical:

- A user normally has one long-lived public/private recipient keypair.
- A vault can be unlocked with the user's private key.
- A vault can also be shared with a one-time password.
- A vault may contain both access methods at the same time.
- The public API and CLI should hide the vault key from normal users.

This preserves the original Lockbox sharing idea:

```text
lockbox share important.txt
```

The sender creates a lockbox protected by a one-time passphrase, sends the
`.lbox` file, and gives the passphrase to the recipient through a separate
channel. The recipient does not need a Lockbox keypair for that use case.

## Use Cases

### Personal Vaults

The user creates a vault and unlocks it with their private key:

```text
recipient private key -> unwrap vault key -> open vault
```

The same recipient keypair can unlock many vaults. The user does not need a new
keypair per vault.

### Password Sharing

The user creates or updates a vault with a password slot:

```text
password -> Argon2id -> unwrap vault key -> open vault
```

This is for simple sharing where a recipient does not have a public key yet.
The password should be one-time or vault-specific, not the sender's normal
private-key passphrase.

### Public-Key Sharing

The user adds a recipient public key to the vault:

```text
recipient public key -> ML-KEM-1024 wraps vault key
recipient private key -> ML-KEM-1024 unwraps vault key
```

This is preferred for ongoing sharing because the recipient does not need to
know a shared password.

## Key Slots

A key slot is metadata that can unlock the vault key.

Supported slot types:

- `password`: Argon2id parameters, salt, and encrypted vault key.
- `recipient`: ML-KEM-1024 encapsulation data and encrypted vault key.

The default metadata should be minimal:

```text
slot id
slot type
algorithm
parameters needed to unwrap the vault key
encrypted vault key
```

Human-readable labels are intentionally not part of the default model. Labels can
leak names, devices, email addresses, or organization structure. If labels are
added later, they should be optional and treated as public metadata unless
explicitly encrypted.

## Key Directory

Key slots are stored in a key directory block inside the vault. The fixed header
stores the byte offset of the current key directory. On each commit the current
directory is appended and the header is updated to point at it.

The key directory is cleartext framing metadata, but it must not contain paths,
file names, environment variable names, or file contents. It contains only:

- slot count
- slot id
- slot type
- algorithm-specific public unwrap data
- encrypted/wrapped vault key bytes

Password salts and ML-KEM ciphertexts are visible metadata. The vault key itself
is never stored in cleartext.

The Rust implementation caps the encoded key directory at 1 MiB. That is enough
for thousands of slots, while preventing a corrupt or hostile vault from forcing
unbounded metadata allocation. A larger directory is rejected as a security
limit violation.

## Slot Selection

The user does not need to know which slot belongs to them.

When opening with a password, the library reads the key directory and tries each
password slot until one decrypts and authenticates the wrapped vault key. When
opening with a private recipient key, it tries each ML-KEM-1024 slot until one
decapsulates and authenticates. If none work, opening fails with an invalid-key
error.

This avoids labels as a required concept and keeps the default UX simple:

```rust
let vault = Lockbox::open_with_password(bytes, b"shared password")?;
let vault = Lockbox::open_with_recipient(bytes, &my_private_key)?;
```

Labels or fingerprints can be added later as optional hints, but they are not
needed for correctness.

## Unlock Cache

The CLI uses an agent model for sudo-like unlock caching. The core library does
not cache passwords or keys.

```text
lockbox open vault.lbox
  -> prompt for password/private-key passphrase
  -> unwrap the vault key
  -> store the unwrapped vault key in a per-user agent

lockbox list vault.lbox
  -> read the public vault UUID from the header
  -> ask the agent for that vault key
  -> extend the TTL on successful use

lockbox lock vault.lbox
  -> remove that vault key from the agent
```

The cache key is the current OS user plus the vault UUID. The vault UUID is
public header metadata and is generated randomly when the vault is created. It
is not derived from paths, file names, content, or recipients.

The cached value is the unwrapped vault key, not the password and not the
private-key passphrase. It lives only in the agent process memory. There is no
session token or bearer key written to disk; a stored token would just become a
different secret that releases the vault key.

Core key handling follows the same rule. Long-lived vault keys and unlocked
vault-key return values are stored in a secret wrapper that zeroizes memory on
drop and redacts debug output. Temporary derived content/wrapping keys are also
zeroized after use where the Rust APIs allow it. This is hardening against
accidental disclosure and simple memory reuse; it is not a complete defense
against malicious code running as the same OS user.

The TTL is sliding. Each successful cache lookup extends the expiry. The
prototype default is 15 minutes.

Transport requirements:

- Linux/macOS: Unix domain socket in a user-private runtime directory.
- Windows: named pipe with current-user SID validation. The production version
  should also set an explicit current-user-only DACL on the pipe.
- No TCP localhost listener by default.
- The agent should validate the caller's OS identity where the platform exposes
  peer credentials.

The current Rust CLI has Unix-domain-socket and Windows named-pipe transport
implementations behind the same cache module boundary. The Windows code
validates the connecting client's SID against the agent process user SID, but
still needs a real Windows CI/smoke pass and explicit pipe DACL hardening before
it should be considered validated.

## CLI Shape

Current/target commands:

```bash
lockbox create vault.lbox
lockbox open vault.lbox
lockbox list vault.lbox
lockbox lock vault.lbox

lockbox keys list vault.lbox
lockbox keys add-password vault.lbox
lockbox keys add-recipient vault.lbox recipient.pub
lockbox keys remove vault.lbox <slot-id>
```

The current Rust CLI prompts for passwords on `create` and `open`. It also
exposes `--key <raw-vault-key>` as a developer/testing escape hatch for
low-level format tests and recovery work, but hides that option from normal help
output. Run `lockbox --help --verbose` to see developer and less common
options. Normal users should not type or manage raw vault keys.

## Format Requirements

- The vault key must be random and unique per vault.
- Content segments must be encrypted with the vault key.
- Passwords must never be used directly as content keys.
- Password slots must use Argon2id with stored parameters and salt.
- Public-key slots should use ML-KEM-1024 for post-quantum key wrapping.
- Removing a key slot revokes that unlock method for future users who only have
  that slot.
- Rotating the vault key should rewrite/wrap a new vault key and eventually
  re-encrypt content.

## Non-Goals

- One keypair per vault by default.
- User-visible segment or chunk management.
- Required labels for key slots.
- Broad user-selectable crypto modes.
