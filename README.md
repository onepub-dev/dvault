# Lockbox

Lockbox stores files, symlinks, and environment values in an encrypted `.lbox`
container. The Rust implementation provides:

- `lockbox`, a CLI for everyday use.
- `lockbox_core`, the portable storage library.
- `lockbox_vault`, the native vault and open-cache layer for desktop/server
  tools.

Terminology is explicit:

- A **lockbox** is the portable `.lbox` container.
- A **vault** is the user's local private store. It may contain private keys,
  trusted recipient keys, key-directory backups, and local open-cache state.

See [docs/terminology.md](docs/terminology.md) for the canonical definitions.

> Status: the Rust implementation under `rust/` is the production direction for
> the first Lockbox format release. The format is still pre-1.0, so breaking
> changes are allowed while the design is finalized. Third-party cryptographic
> review is still a release blocker.

## CLI Quick Start

Create a lockbox:

```bash
lockbox create secrets.lbox
```

Open it for normal commands:

```bash
lockbox open secrets.lbox
```

The open is cached in a per-user in-memory agent for a short sliding TTL. Lock
it when you are done:

```bash
lockbox close secrets.lbox
```

Add files:

```bash
lockbox add secrets.lbox ./project
lockbox add-file secrets.lbox ./generated.env /secrets/prod.env
```

List and extract:

```bash
lockbox ls secrets.lbox /
lockbox ls secrets.lbox /project --glob '**/*.rs'
lockbox extract secrets.lbox /project/README.md ./out/README.md
```

See [docs/cli_how_to.md](docs/cli_how_to.md) for command-focused examples.

## Keys And Sharing

Create a local vault key:

```bash
lockbox vault keygen default ./default.pub
```

Trust someone else's public key:

```bash
lockbox vault trust alice ./alice.pub
```

Vault names such as `alice` are local aliases. They are not copied into shared
lockboxes when you add a recipient, so lockboxes do not publish recipient names
or email addresses as membership metadata.

Create a lockbox for a recipient:

```bash
lockbox create --recipient alice shared.lbox
```

Export your public key:

```bash
lockbox vault identity export default ./default.pub
```

Exporting a private key is supported for backup and migration, but treat the
output as a secret:

```bash
lockbox vault identity export-private --format lockbox-pem default ./default-private.pem
```

Private vault keys are stored inside the local vault as secret variable records, not
as normal files in the vault lockbox. See
[docs/key_management.md](docs/key_management.md) for the key and vault model.

## Variables

Variables are encrypted metadata, not files. They do not appear in
file listings and are loaded only when variables commands or APIs request them.

Plain variables are for values that are useful configuration but not high-value
secrets:

```bash
lockbox variables set secrets.lbox DATABASE_URL --value 'postgres://localhost/app'
lockbox variables get secrets.lbox DATABASE_URL
```

Secret variables are for passwords, API tokens, signing keys, and similar
material. They use secure-memory handling in the variable path and must be provided
through an explicit source:

```bash
lockbox variables set secrets.lbox --secret API_TOKEN --interactive
lockbox variables set secrets.lbox --secret API_TOKEN --file ./api-token.txt
lockbox variables set secrets.lbox --secret API_TOKEN --stdin
lockbox variables set secrets.lbox --secret API_TOKEN --from-env API_TOKEN
```

Avoid passing secrets as command-line arguments. Shell history and process
inspection can expose argv. Prefer `--interactive`, `--stdin`, `--file`, or
`--from-env`.

Sensitivity is chosen when a variable is created. Updating the value preserves
that sensitivity. To change plain to secret, or secret to plain, delete and
recreate the variable.

## Avoiding Leaks

Use these defaults unless you have a specific reason not to:

- Use `lockbox open` and the local agent instead of repeatedly passing
  passwords or private keys.
- Use secret variables for credentials and tokens.
- Do not store secrets as normal files when variable semantics are appropriate.
- Do not pass secret values on the command line.
- Keep private key exports offline, short-lived, and permission-restricted.
- Prefer recipient keys over shared passwords for team access.
- Run `lockbox close secrets.lbox` when an open should no longer be cached.
- Use `lockbox visualize secrets.lbox` for diagnostics; it intentionally avoids
  printing file paths, file contents, variable names, or variable values.

Lockbox protects data inside the container. It cannot protect a secret after you
write it to a normal terminal, shell history, clipboard, exported file, build
log, or process environment controlled by other tooling.

## Rust Library Quick Start

Use `lockbox_core` when you need the portable storage engine:

```rust
use lockbox_core::{VariableName, Lockbox, LockboxPath, LockboxProtection, LockboxUnlock, SecretVec};
use std::path::Path;

let key = SecretVec::try_from_slice(b"correct horse battery staple")?;
let mut lockbox = Lockbox::create_file(
    Path::new("secrets.lbox"),
    LockboxProtection::ContentKey(key.try_clone()?),
)?;

lockbox.add_file(&LockboxPath::new("/docs/a.txt")?, b"alpha", false)?;
lockbox.add_file(&LockboxPath::new("/docs/b.txt")?, b"bravo", false)?;
lockbox.set_variable(&VariableName::new("DATABASE_URL")?, "postgres://localhost/app")?;
lockbox.commit()?;

let reopened = Lockbox::open_file(
    Path::new("secrets.lbox"),
    LockboxUnlock::ContentKey(key),
)?;
let file = reopened.get_file(&LockboxPath::new("/docs/a.txt")?)?;
let value = reopened.get_variable(&VariableName::new("DATABASE_URL")?)?;
```

Use `lockbox_vault` for native applications that want the local vault and
open-cache behavior:

```rust
use lockbox_vault::{local_vault, SecretString};

let vault = local_vault();
let password = SecretString::try_from_bytes(b"pw".to_vec())?;

vault.create_lockbox_with_password("secrets.lbox", &password)?;
vault.unlock_lockbox_with_password("secrets.lbox", &password)?;

let mut lockbox = vault.open_lockbox("secrets.lbox")?;
lockbox.add_file("notes.txt", "/notes.txt")?;
lockbox.commit()?;

vault.lock_lockbox("secrets.lbox")?;
```

## Documentation

- [CLI how-to](docs/cli_how_to.md): command examples.
- [Key management](docs/key_management.md): vaults, keys, recipients, and
  open caching.
- [Lockbox Session Agent](docs/lockbox_session_agent.md): local open cache
  lifecycle, protocol, and security model.
- [Security audit](docs/security_audit.md): security analysis and release
  blockers.
- [File formats](docs/file_formats.md): lockbox/vault format details and page
  layout.
- [Implementation overview](docs/implementation_overview.md): architecture,
  page cache, recovery, browser access, and development notes.
- [Rust development](docs/rust_development.md): build, test, and API docs.
- [Terminology](docs/terminology.md): canonical naming.

## Development

Run the Rust checks:

```bash
cd rust
cargo fmt --all
cargo check --workspace --all-targets --all-features
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Generate Rust API docs:

```bash
cd rust
tools/generate_api_docs.sh
```

## License

Dvault Source Available License 1.0 - see [LICENSE](LICENSE).

The source remains available for inspection, modification, and redistribution.
Derivative works must publish their corresponding source code in a publicly
accessible repository such as GitHub or a similar service. The license also
restricts third parties from offering dvault, modified dvault, or substantially
similar dvault-derived functionality as a hosted, managed, or
network-accessible service without a separate written license.
