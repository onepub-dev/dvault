# Lockbox CLI How-To

This guide describes the intended Lockbox CLI user experience for the first
format release. Some commands are still being hardened, but the examples define
the target behavior.

## Path Model

Lockbox stores logical archive paths, not host filesystem paths.

Good archive paths:

```text
/docs/readme.md
/project/src/main.rs
/myapp/config.yaml
```

Host absolute paths are not stored in the lockbox. Paths such as `/etc/passwd`,
`C:\Users\bob\file.txt`, `\\server\share\file.txt`, and paths containing `..`
are rejected as unsafe archive entries.

## Add Files

Open a lockbox before normal operations:

```bash
lockbox open secrets.lbox
```

The open is cached in a per-user in-memory agent for a short sliding TTL.
Clear the cached open explicitly when done:

```bash
lockbox close secrets.lbox
```

Create a lockbox and cache open access:

```bash
lockbox create secrets.lbox
```

Add a directory under its own name:

```bash
lockbox add secrets.lbox ./project
```

Example stored paths:

```text
/project/README.md
/project/src/main.rs
```

Add only the directory contents:

```bash
lockbox add secrets.lbox ./project \
  --strip-prefix ./project \
  --dest /
```

Example stored paths:

```text
/README.md
/src/main.rs
```

Add a directory under a logical destination prefix:

```bash
lockbox add secrets.lbox ./project \
  --strip-prefix ./project \
  --dest /backups/project-2026
```

Example stored paths:

```text
/backups/project-2026/README.md
/backups/project-2026/src/main.rs
```

## Add One File With A New Name

Use an explicit source and destination when adding a single file:

```bash
lockbox add-file secrets.lbox ./generated.env /secrets/prod.env
```

Stored path:

```text
/secrets/prod.env
```

## Variables

Lockbox can store environment variables in encrypted variable pages. They are not
file entries, do not appear in `ls`, and should only be loaded when variables commands
or APIs request them.

Set a variable:

```bash
lockbox variables set secrets.lbox DATABASE_URL 'postgres://localhost/app'
lockbox variables set secrets.lbox DATABASE_URL --value 'postgres://localhost/app'
```

Set a secret variable with an explicit value source:

```bash
lockbox variables set secrets.lbox --secret API_TOKEN --interactive
lockbox variables set secrets.lbox --secret API_TOKEN --file ./api-token.txt
lockbox variables set secrets.lbox --secret API_TOKEN --stdin
lockbox variables set secrets.lbox --secret API_TOKEN --from-env API_TOKEN
lockbox variables set secrets.lbox --secret API_TOKEN --value "$API_TOKEN"
```

Short forms are also supported:

```bash
lockbox variables set secrets.lbox -s API_TOKEN -i
lockbox variables set secrets.lbox -s API_TOKEN -f ./api-token.txt
lockbox variables set secrets.lbox -s API_TOKEN -t
lockbox variables set secrets.lbox -s API_TOKEN -e API_TOKEN
lockbox variables set secrets.lbox -s API_TOKEN -v "$API_TOKEN"
```

Sensitivity is declared when a variable is created. Updating the value preserves
that sensitivity. To change a variable from secret to non-secret, or the other
way around, delete it and recreate it.

Get a variable:

```bash
lockbox variables get secrets.lbox DATABASE_URL
lockbox variables get secrets.lbox --secret API_TOKEN
```

List variable names:

```bash
lockbox variables list secrets.lbox
```

Export variables for shell use:

```bash
lockbox variables export secrets.lbox
```

Remove a variable:

```bash
lockbox variables rm secrets.lbox DATABASE_URL
```

Environment variable names should use portable shell-style names:

```text
DATABASE_URL
FEATURE_FLAG
_PRIVATE_TOKEN
```

Names that start with a number or contain spaces, dashes, dots, NUL bytes, or
other unsafe characters are rejected. Values are encrypted and bounded; NUL and
control characters are rejected.

## Visualize A Lockbox

Use `visualize` when developing, diagnosing corruption, or checking what a
lockbox contains without extracting it:

```bash
lockbox visualize secrets.lbox
```

The command is intentionally hidden from normal help; use
`lockbox --help --verbose` to show it.

The command prints public lockbox identity, summary counts for files, symlinks,
environment variables, key slots, logical file bytes, per-page metadata, page
object kinds, and a recovery-scan summary. It does not print file paths, file
contents, environment variable names, or environment variable values. Use
`lockbox list` and `lockbox variables list` for those details.

## List Files

List a directory:

```bash
lockbox ls secrets.lbox /
lockbox ls secrets.lbox /docs
```

Filter with a glob:

```bash
lockbox ls secrets.lbox /docs --glob '*.pdf'
lockbox ls secrets.lbox /docs --glob '**/*.pdf'
```

The glob is applied to logical Lockbox paths. It does not access the host
filesystem.

## Extract Files

Extract one file:

```bash
lockbox extract secrets.lbox /docs/a.txt ./out/a.txt
```

Extract into a selected directory:

```bash
lockbox extract secrets.lbox --to ./out --restore-permissions
```

Example mapping:

```text
/docs/a.txt -> ./out/docs/a.txt
```

Extraction must verify that every destination remains inside the chosen output
directory. Existing files should not be overwritten unless the user explicitly
passes `--overwrite`.

## Logical Roots

Some backups need to restore different groups of files to different host
locations. Lockbox should support this with logical roots, not absolute archive
paths.

Add application config files into a `config` root:

```bash
lockbox add secrets.lbox ./etc/myapp \
  --strip-prefix ./etc \
  --root config \
  --dest /myapp
```

Add application data files into a `data` root:

```bash
lockbox add secrets.lbox ./var/lib/myapp \
  --strip-prefix ./var/lib \
  --root data \
  --dest /myapp
```

Stored logical entries:

```text
config:/myapp/config.yaml
data:/myapp/state.db
```

List roots:

```bash
lockbox roots secrets.lbox
```

Example output:

```text
default
config
data
```

List within a root:

```bash
lockbox ls secrets.lbox --root config /myapp
```

Extract multi-root archives by explicitly mapping each logical root:

```bash
lockbox extract secrets.lbox \
  --map-root config=./restore/etc \
  --map-root data=./restore/var/lib
```

Example output mapping:

```text
config:/myapp/config.yaml -> ./restore/etc/myapp/config.yaml
data:/myapp/state.db      -> ./restore/var/lib/myapp/state.db
```

If the archive contains an unmapped root, extraction should fail closed and ask
the user to provide a mapping.

## Symlinks

Symlinks are not restored by default:

```bash
lockbox extract secrets.lbox --to ./out
```

To restore symlinks explicitly:

```bash
lockbox extract secrets.lbox --to ./out --restore-symlinks
```

Lockbox still validates both the symlink path and target as safe logical paths.
Symlinks with `..`, host absolute paths, Windows drive paths, UNC paths,
backslashes, NUL bytes, or control characters are rejected.

## Permissions

Ignore archive permissions and use safe defaults:

```bash
lockbox extract secrets.lbox --to ./out --no-restore-permissions
```

Restore stored permissions where supported:

```bash
lockbox extract secrets.lbox --to ./out --restore-permissions
```

The format stores only basic permission bits. Special bits and platform-specific
metadata should be rejected or ignored unless explicitly supported later.

## Recovery

Inspect a damaged lockbox:

```bash
lockbox recover --report damaged.lbox
```

`recover --report` is read-only. It scans the lockbox and reports what can be
read without writing a new file. Use `--format table` or `--format json` when
you need machine-readable output.

```text
field                value
intact_files         128442
partial_files        3
corrupt_records      7
toc_recovered        false
env_recovered        true
env_count            12
forms_recovered      true
form_definitions     4
form_records         38
```

Write a clean lockbox containing recovered entries:

```bash
lockbox recover damaged.lbox --output recovered.lbox
```

Use `--overwrite` only when replacing an existing recovery output:

```bash
lockbox recover damaged.lbox --output recovered.lbox --overwrite
```

The recovered lockbox is a new valid lockbox with the same content key. It
contains only path-bearing entries whose payloads can be fully read: complete
files, symlinks whose targets can be decoded, plus variable values and form metadata
when the latest commit root is recoverable. Partial files are reported by count
and are skipped rather than written as shortened files.

Recovery can scan fixed-size encrypted pages and encrypted metadata even when
the fixed header or latest TOC is damaged. File content without recoverable path
metadata is not written to the output lockbox, because the current format does
not create unnamed placeholder files during recovery.

## Recipient Keys

Initialize the local vault lockbox:

```bash
lockbox vault init
```

This creates `local-vault.lbox` in the platform-specific vault directory and
prompts for the vault password. For automation, `LOCKBOX_VAULT_PASSWORD` can
supply that password.

Generate the default local recipient keypair and export its public key:

```bash
lockbox vault keygen default alice.pub
```

The default key file format is native Lockbox PEM:

```text
-----BEGIN LOCKBOX PUBLIC KEY-----
...
-----END LOCKBOX PUBLIC KEY-----
```

Private keys are stored inside the encrypted local vault lockbox. There is no
separate private-key password layer.

Import an existing private key file into the vault:

```bash
lockbox vault import-key legacy alice.key alice.pub
```

Export a vault-managed private key:

```bash
lockbox vault identity export-private legacy legacy.key
```

Supported key file formats:

- `lockbox-pem`: default text format with `BEGIN LOCKBOX PRIVATE KEY` or
  `BEGIN LOCKBOX PUBLIC KEY` armor.
- `jwk`: JSON Web Key using the Lockbox ML-KEM-1024 profile.
- `jwks`: JSON Web Key Set containing one key.
- `raw-hex`: legacy/developer hex encoding of the raw ML-KEM seed or recipient
  key.

Select an export format with `--format`:

```bash
lockbox vault identity export --format jwk default alice.jwk
lockbox vault identity export-private --format lockbox-pem legacy legacy.key
```

Imports auto-detect native Lockbox PEM, JWK, JWKS, and raw hex.

Trust another recipient public key in the local vault:

```bash
lockbox vault trust bob bob.pub
```

List local vault records:

```bash
lockbox vault list
```

Remove local vault records:

```bash
lockbox vault remove-key default
lockbox vault remove-trusted bob
```

The default vault location is platform-specific and can be overridden:

```bash
LOCKBOX_VAULT_DIR=/secure/local/vault lockbox vault init
```

Create a lockbox for one of your vault keys:

```bash
lockbox create --recipient default secrets.lbox
```

Add a recipient public key or trusted recipient name to an opened lockbox:

```bash
lockbox add-recipient secrets.lbox alice.pub
lockbox add-recipient secrets.lbox bob
```

List key slots:

```bash
lockbox list-keys secrets.lbox
```

Remove a key slot:

```bash
lockbox remove-key secrets.lbox 2
```

Removing a key is a compaction operation. The CLI rewrites the current lockbox state
so stale key-directory history is not left behind as an easy way for the removed
credential to keep opening the lockbox.

Open with a private key:

```bash
lockbox open-key secrets.lbox default
```

If no key name is supplied, `open-key` uses the default private key in the local
vault:

```bash
lockbox open-key secrets.lbox
```

The CLI uses vault-managed private keys by name. External private key files
should be imported into the vault before use rather than loaded directly.

Commands that create, open, or change lockbox key slots mirror the current
key directory into the local vault as a recovery aid. The lockbox remains the
portable source of truth; the local mirror is user-local convenience state.
When the lockbox header is intact but embedded key-directory copies are damaged,
`open` and `open-key` can use the local mirror to unwrap the content key.

## Safety Summary

The CLI should reject or fail closed on:

- `..` path components,
- host absolute paths in archive entries,
- Windows drive paths,
- UNC paths,
- backslashes in archive paths,
- unsafe symlinks,
- extraction outside the selected output directory or mapped root,
- overwriting existing files unless `--overwrite` is explicit,
- extraction that exceeds configured file count or byte limits.

The mental model is:

```text
Archive stores logical paths and logical roots.
The CLI maps logical roots to real disk locations only at extraction time.
```
