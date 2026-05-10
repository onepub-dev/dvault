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

Unlock a lockbox before normal operations:

```bash
lockbox open secrets.lbox
```

The unlock is cached in a per-user in-memory agent for a short sliding TTL.
Clear the cached unlock explicitly when done:

```bash
lockbox lock secrets.lbox
```

Create a lockbox and cache its unlock:

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

## Environment Variables

Lockbox can store environment variables in encrypted env pages. They are not
file entries, do not appear in `ls`, and should only be loaded when env commands
or APIs request them.

Set a variable:

```bash
lockbox env set secrets.lbox DATABASE_URL 'postgres://localhost/app'
```

Get a variable:

```bash
lockbox env get secrets.lbox DATABASE_URL
```

List variable names:

```bash
lockbox env list secrets.lbox
```

Export variables for shell use:

```bash
lockbox env export secrets.lbox
```

Remove a variable:

```bash
lockbox env rm secrets.lbox DATABASE_URL
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
`lockbox list` and `lockbox env list` for those details.

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
lockbox recover damaged.lbox
```

`recover` is a read-only inspection command. It should report the state of what
it found without implying that files have already been copied out.

Default output should be concise. It should count intact files and focus detail
on damaged items:

```text
Recovery report for damaged.lbox

Summary:
  Intact files: 128442
  Partial files: 3
  Metadata-only files: 1
  Corrupt pages: 7
  Latest manifest: damaged

Partial:
  /photos/c.jpg
    missing or corrupt chunks

Metadata only:
  /archive/old.bin
    file name and size found, payload missing

Corrupt:
  page at offset 184320
  latest manifest
```

Use verbose output when the user really wants to list intact files:

```bash
lockbox recover damaged.lbox --verbose
```

Verbose output may still be bounded:

```bash
lockbox recover damaged.lbox --verbose --limit 1000
```

Example verbose section:

```text
Intact:
  /docs/a.txt
  /docs/b.txt
  /src/main.rs
  ... 127439 more intact files omitted
```

Salvage intact files into a clean lockbox:

```bash
lockbox salvage damaged.lbox clean.lbox
```

`salvage` runs recovery and writes intact files into a new valid lockbox. It
should skip partial or corrupt files by default and include them in the report.

Recovery scans fixed-size encrypted pages and encrypted metadata. It
should identify intact files even if the latest manifest is damaged.

## Recipient Keys

Initialize the local vault directory:

```bash
lockbox vault init
```

Generate the default local recipient keypair and export its public key:

```bash
lockbox vault keygen default alice.pub
```

Trust another recipient public key in the local vault:

```bash
lockbox vault trust bob bob.pub
```

List local vault records:

```bash
lockbox vault list
```

The default vault location is platform-specific and can be overridden:

```bash
LOCKBOX_VAULT_DIR=/secure/local/vault lockbox vault init
```

Generate a recipient keypair:

```bash
lockbox keygen alice.key alice.pub
```

Add a recipient public key to an unlocked lockbox:

```bash
lockbox add-recipient secrets.lbox alice.pub
```

List key slots:

```bash
lockbox list-keys secrets.lbox
```

Remove a key slot:

```bash
lockbox remove-key secrets.lbox 2
```

Removing a key is a compaction operation. The CLI rewrites the live lockbox state
so stale key-directory history is not left behind as an easy way for the removed
credential to keep opening the lockbox.

Unlock with a private key:

```bash
lockbox open-key secrets.lbox alice.key
```

If no private key path is supplied, `open-key` uses the default private key in
the local vault:

```bash
lockbox open-key secrets.lbox
```

The current Rust CLI stores key files as hex-encoded ML-KEM seed/public-key
material. Private-key file encryption is still planned.

Commands that create, unlock, or change lockbox key slots mirror the current
key directory into the local vault as a recovery aid. The lockbox remains the
portable source of truth; the local mirror is user-local convenience state.

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
