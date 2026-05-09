# Terminology

Lockbox uses these terms consistently:

## Vault

A vault is the user's local private security store on their own machine. It may
contain the user's private key, trusted public keys, local key-directory
backups, preferences, and other user-local state.

The vault is not the portable archive file. It is controlled by the local user
and should be protected with OS facilities such as Keychain, DPAPI, Secret
Service, file permissions, or equivalent platform storage.

The CLI may use the vault for convenience features such as:

- storing the user's long-term private key
- caching trusted public keys
- retaining local backups of lockbox key directories
- remembering lockbox-specific preferences

The vault must not be required to read a lockbox shared by password only.

## Lockbox

A lockbox is the portable `.lbox` file format. It stores compressed and
encrypted data, encrypted metadata, key slots, the TOC, recovery data, and the
free-space index.

A lockbox is designed to be copied, uploaded, downloaded, emailed, backed up, or
served by a web service. It should contain enough unlock metadata for intended
recipients to open it using a password slot, public-key recipient slot, or other
supported access method.

## Lockbox ID

Each lockbox has a public random UUID in its header. The UUID identifies the
lockbox for cache lookup and local vault records. It is not derived from paths,
contents, passwords, keys, or recipients.

## Content Key

Each lockbox has a random content-encryption key. Segment pages are encrypted
with keys derived from that content key. Password slots and recipient slots wrap
the content key.

Use "content key" for this concept in code, APIs, and documentation.

## Key Directory

The key directory is lockbox metadata containing key slots and wrapping
parameters needed to unwrap the lockbox content key. It lives inside the
lockbox, and critical copies may also be retained in the user's local vault as a
CLI recovery feature.

Local vault backups are recovery aids, not the canonical format. A lockbox
should remain self-describing for the access methods intentionally embedded in
it.
