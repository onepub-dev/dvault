# reVault Share CLI and Vault Design

## Purpose

This document defines the client-side sharing, verification, contact storage,
and key replacement flows for the reVault key server.

The key server is only a rendezvous store. It does not verify identity, key
ownership, key continuity, or trust. Those decisions belong in the CLI and the
local vault.

```text
share/import/fetch -> candidate key
verification code -> user-confirmed candidate key
vault contact record -> remembered trust state
key replacement -> verified contact plus optional pending replacement
```

## Scope

This design covers:

```text
lockbox vault share
lockbox vault contact add --share-code
lockbox vault contact update --share-code
lockbox vault contact update --accept
lockbox vault contact update --reject
lockbox vault identity rotate
lockbox vault identity history
lockbox access refresh
lockbox vault lockbox list
lockbox vault lockbox forget
key server URL configuration
binary vault contact records
signed and unsigned key replacement
old lockbox access after identity rotation
```

The contact subcommand remains under `vault`.

## Command Summary

New and amended commands:

```text
lockbox vault share [identity] [--key-index N] [--server URL] [--ttl 15m] [--max-fetches 1]

lockbox vault contact add <identity> --share-code CODE [--server URL]
lockbox vault contact add <identity> <public-key-file>

lockbox vault contact update <identity> --share-code CODE [--server URL]
lockbox vault contact update <identity> <public-key-file>
lockbox vault contact update <identity> --accept
lockbox vault contact update <identity> --reject

lockbox vault identity rotate [identity]
lockbox vault identity history [identity]

lockbox access refresh <lockbox> <identity>
lockbox access refresh --all <identity>
lockbox access refresh --all

lockbox vault lockbox list
lockbox vault lockbox forget <lockbox>
```

`contact add` is only for creating a new contact. If a contact already exists,
it must fail and direct the user to `contact update`. Do not keep `--overwrite`
for contacts; it hides whether the user is creating first trust or changing an
existing trust relationship.

`contact update` is the only command that changes an existing contact key. It
handles both signed and unsigned replacement payloads and direct offline public
key files.

`vault identity rotate` is local-only. It does not contact the key server.
After rotation, the user can call `lockbox vault share` to share either the
active key or a retired key generation.

`access refresh` updates lockbox access entries from retired identity
generations to active identity generations. It is the user-facing command for
the underlying key-directory update operation.

`vault lockbox forget` removes a missing or unwanted lockbox reference from the
vault's known-lockbox list. It does not modify the lockbox file itself.

## Worked Examples

### Initial Share Through The Server

Alice shares her active identity:

```bash
lockbox vault share alice@example.com
```

Alice sees:

```text
Share code: 0123456789012
Verification code: 71-44-92
Expires: 15 minutes
```

Alice gives both codes to Bob over an independent channel.

Bob adds Alice:

```bash
lockbox vault contact add alice@example.com --share-code 0123456789012
```

Bob is prompted:

```text
Enter verification code from alice@example.com:
```

If Bob enters `71-44-92`, the contact is stored as verified.

### Initial Offline Contact Add

Alice exports a public contact file:

```bash
lockbox vault identity export alice@example.com alice.lockbox-contact
```

Bob imports and verifies it:

```bash
lockbox vault contact add alice@example.com alice.lockbox-contact
```

The CLI computes the same verification code from the file payload and asks Bob
to enter the code received from Alice. The contact is stored only if the code
matches.

### Signed Key Replacement

Alice rotates her local identity:

```bash
lockbox vault identity rotate alice@example.com
```

This creates a new active key generation and keeps the old generation retired.
It does not upload anything.

Alice shares a replacement for Bob:

```bash
lockbox vault share alice@example.com
```

Because Alice has an old retired signing key, the CLI builds a
`signed_key_replacement_v1` payload for contacts that know the previous key.

Bob updates Alice:

```bash
lockbox vault contact update alice@example.com --share-code 0123456789012
```

If the signature verifies against Alice's current verified contact key, Bob's
contact record is promoted to the new key and remains verified.

### Unsigned Key Replacement

Alice lost her old vault and cannot sign with the previous key. She creates a
new identity with the same public identity string and shares it:

```bash
lockbox vault share alice@example.com --unsigned-replacement
```

Bob updates Alice:

```bash
lockbox vault contact update alice@example.com --share-code 0123456789012
```

The CLI detects `unsigned_key_replacement_v1`, computes the replacement
verification code, and asks Bob to enter the code from Alice. If it matches,
Bob may accept the replacement. If verification is deferred, the replacement is
stored as pending and every use of Alice's old key warns.

### Using A Retired Identity Key

Alice lists identity generations:

```bash
lockbox vault identity history alice@example.com
```

Then shares a retired key because a third party needs access to an old archive:

```bash
lockbox vault share alice@example.com --key-index 1
```

The CLI must warn that a retired key is being shared.

### Rewrapping An Old Lockbox

Alice rotates her identity and then refreshes an old lockbox so it no longer
depends on the retired key:

```bash
lockbox access refresh project.lbox alice@example.com
```

The CLI unlocks with any available generation, adds the active generation, then
removes the retired generation.

Alice refreshes every known lockbox for every identity:

```bash
lockbox access refresh --all
```

The CLI first prints a plan:

```text
Scanning known lockboxes...

Refresh plan:
  3 lockboxes need updates
  8 lockboxes already current
  1 lockbox is missing
  1 lockbox could not be checked

Updates:
  project.lbox
    alice@example.com: key #1 retired -> key #3 active

Missing:
  old-project.lbox
    file does not exist

Could not check:
  client.lbox
    cannot unlock with any vault identity

Apply these updates? [y/N]
```

Missing lockboxes are errors for explicit refresh requests and reported
problems for `--all`. They are never silently ignored.

## Server URL Configuration

The CLI must resolve the key server URL in this order:

```text
1 command line: --server URL
2 environment: LOCKBOX_KEY_SERVER
3 YAML config: share.server
4 built-in default: https://keyshare.onepub.dev/v1/share
```

The YAML config path should reuse the existing CLI config path logic:

```text
LOCKBOX_CONFIG
platform config.yaml path
```

Config shape:

```yaml
share:
  server: "https://keyshare.onepub.dev/v1/share"
```

The config parser should be small and strict. Unknown top-level fields can be
ignored for forward compatibility, but malformed `share.server` must be a clear
configuration error.

## Shared Protocol Crate

`lockbox_share_protocol` is the only crate that owns the share wire protocol
and typed share payload encoding.

It provides:

```text
binary request and response envelope codecs
operation body versioning
typed payload envelope validation
contact share payload encoder
signed replacement payload encoder
unsigned replacement payload encoder
blocking ShareClient
transport trait for tests and future TLS support
```

The CLI must depend on `lockbox_share_protocol`; it must not duplicate protocol
parsing or manually build key server request bytes.

## Verification Code

The verification code is derived from the fetched payload. It detects server
substitution. It does not prove the human identity by itself.

For initial contact shares:

```text
hash("lockbox contact verify v1" || identity || public_key || share_nonce)
```

For replacements:

```text
hash("lockbox contact replacement verify v1"
     || identity
     || old_public_key_fingerprint
     || new_public_key
     || new_public_key_fingerprint
     || replacement_nonce)
```

The receiver should not merely see the computed verification code. The receiver
must enter the code obtained from the sender through an independent channel.

Interactive flow:

```text
Enter verification code from alice@example.com:
```

Non-interactive flow:

```text
--verification-code 71-44-92
```

If the entered code does not match the locally computed code, the CLI must not
store or update the contact record.

## Contact Storage

Use binary contact records, not JSON.

No compatibility is required for the existing `/trusted_recipients/*.pub`
records because the project is pre-release. Replace the old trusted-recipient
record model with a single binary contact record per contact:

```text
/contacts/<name>.lbc
```

The contact record should be versioned:

```text
ContactRecord {
    magic: "LBCR"
    version: u16
    identity: utf8_string
    contact_status: u16
    current_public_key: bytes
    current_fingerprint: bytes
    current_signing_public_key: bytes
    verified_at_unix_ms: optional u64
    updated_at_unix_ms: u64
    pending_replacement: optional PendingReplacement
    history: [ContactHistoryEntry]
}
```

Contact status values:

```text
1 verified
2 unverified
3 revoked
```

Do not model `replacement_pending` as the whole contact state. A contact with a
pending replacement can still have a verified current key.

The meaningful combinations are:

```text
verified, no pending replacement
verified, pending replacement
unverified, no pending replacement
revoked
```

`access add` must only use the current key when `contact_status == verified`.
If the contact also has `pending_replacement`, it should still use the current
verified key but must warn every time:

```text
WARNING: alice@example.com has a pending key replacement.
Using the currently verified old key.
Run: lockbox vault contact update alice@example.com --accept
```

The warning is important because a pending replacement is evidence that the
contact may have moved to a new key, but it is not enough to discard trust in
the old key.

## Pending Replacement

Pending replacements are stored inside the contact record:

```text
PendingReplacement {
    replacement_kind: u16
    received_at_unix_ms: u64
    old_fingerprint: bytes
    new_public_key: bytes
    new_fingerprint: bytes
    new_signing_public_key: bytes
    replacement_nonce: bytes
    signature_by_old_key: optional bytes
    verification_code_hash: bytes
}
```

Replacement kinds:

```text
1 signed_by_previous_key
2 unsigned
```

A signed replacement can be accepted automatically only if the signature is
valid against the current verified signing public key. An unsigned replacement
requires explicit verification-code entry.

## Contact History

History is audit data, not state.

Store it inside the contact record as binary entries:

```text
ContactHistoryEntry {
    event_type: u16
    occurred_at_unix_ms: u64
    old_fingerprint: optional bytes
    new_fingerprint: optional bytes
    verification_method: u16
    continuity: u16
}
```

Event types:

```text
1 initial_verified
2 signed_replacement_received
3 signed_replacement_accepted
4 unsigned_replacement_received
5 unsigned_replacement_accepted
6 replacement_rejected
7 revoked
```

Verification methods:

```text
0 none
1 verification_code
2 signature_by_previous_key
```

Continuity:

```text
0 none
1 user_verified_code
2 signed_by_previous_key
```

History lets the user answer questions such as:

```text
when did this contact's key change?
was the change signed by the previous verified key?
did I manually verify an unsigned replacement?
what fingerprint did I previously trust?
```

## CLI Commands

### Share Vault Identity

```bash
lockbox vault share [identity] [--key-index N] [--server URL] [--ttl 15m] [--max-fetches 1]
```

This shares a vault identity's public contact material. If `identity` is
omitted, use the vault default identity.

Publicly shared identity strings should be email addresses. The CLI should
strongly encourage this and may require an email-like value for identities that
are shared through the server. Email addresses provide a natural globally
unique contact key for other users' vaults.

Local aliases can still exist, but they should not be the identity string in a
share payload. If a local identity has alias `default`, the vault share command
should either use the email identity stored in that identity record or require:

```bash
lockbox vault share default --as alice@example.com
```

`--key-index` selects a historical identity generation. Omitting it shares the
active generation. Sharing a retired generation must print a warning.

Output:

```text
Share code: 0123456789012
Verification code: 71-44-92
Expires: 15 minutes
```

The `share` command must:

```text
load the identity record from the vault
select the active or requested key generation
build a contact_share_v1, signed_key_replacement_v1, or unsigned_key_replacement_v1 payload
upload it through ShareClient
compute the verification code locally
print the share code and verification code
```

When the identity has retired generations, the CLI decides the payload type:

```text
no known previous contact context -> contact_share_v1
active generation with prior retired signing key -> signed_key_replacement_v1
explicit --unsigned-replacement -> unsigned_key_replacement_v1
retired --key-index N -> contact_share_v1 for that retired key
```

The key server does not decide whether a payload is signed. It only validates
the submitted payload structure.

### Add Contact By Share Code

```bash
lockbox vault contact add alice@example.com \
  --share-code 0123456789012 \
  [--server URL] \
  [--verification-code 71-44-92]
```

The command must:

```text
fetch the share payload
require PayloadType::ContactShare
decode the contact payload
verify the payload identity matches the requested contact name
compute the verification code
prompt for or read --verification-code
store the contact as verified only if the code matches
```

The command should reject overwriting an existing contact unless an explicit
replace/update flow is used.

### Receive Replacement By Share Code

```bash
lockbox vault contact update alice@example.com \
  --share-code 0123456789012 \
  [--server URL] \
  [--verification-code 71-44-92]
```

The command must:

```text
load the existing contact record
fetch the share payload
dispatch on PayloadType
require signed or unsigned key replacement payload
verify payload identity matches contact name
verify old fingerprint matches the current contact key
store or apply the replacement according to replacement type
```

For signed replacements:

```text
verify signature with current verified signing public key
if valid, promote new key to current key
clear pending_replacement
append signed_replacement_accepted history
remain verified
```

For unsigned replacements:

```text
compute replacement verification code
prompt for or read --verification-code
if code matches, promote new key to current key
clear pending_replacement
append unsigned_replacement_accepted history
remain verified
```

If an unsigned replacement is fetched but verification is deferred, store it as
`pending_replacement` and warn on use of the old key.

### Accept Or Reject Pending Replacement

```bash
lockbox vault contact update alice@example.com --accept
lockbox vault contact update alice@example.com --reject
```

`--accept` promotes a pending replacement only if its continuity requirements
have already been met:

```text
signed replacement: valid signature was recorded
unsigned replacement: verification code was confirmed
```

`--reject` clears `pending_replacement` and appends a
`replacement_rejected` history entry.

## Identity Records And Signing

Current `RecipientKeyPair` material is used for key wrapping. It is not a
signing identity. In the current code it is hybrid X25519 + ML-KEM recipient
material. X25519 performs key agreement and ML-KEM performs key encapsulation;
neither component is a digital signature algorithm.

Signed replacement requires signature-capable key material. This does not mean
the user needs a second logical identity. It means each vault identity
generation needs to contain the key material required for the jobs that
generation performs:

```text
recipient key material: unwrap lockbox content keys
signing key material: sign identity replacement claims
```

The old identity generation signs the replacement claim with its old signing
private key. Contacts verify that claim with the old signing public key they
already trust. If a future identity key type can both unwrap and sign safely,
the record format can encode that as one cryptographic keypair. The current
hybrid recipient key cannot do that, so a signing component is required inside
the same identity generation.

Vault identities should become versioned binary identity records:

```text
IdentityRecord {
    magic: "LBIR"
    version: u16
    name: utf8_string
    active_generation: u16
    generations: [IdentityGeneration]
}

IdentityGeneration {
    index: u16
    recipient_keypair: secret bytes
    signing_keypair: secret bytes
    status: u16
    created_at_unix_ms: u64
    retired_at_unix_ms: optional u64
    recipient_fingerprint: bytes
    signing_public_key: bytes
}
```

Generation status values:

```text
1 active
2 retired
3 compromised
```

The signing component is generated with each identity generation and included
in contact share payloads as the public signing key. Signed key replacement
signs the canonical replacement body with the old generation's signing private
key. The replacement payload carries the new generation's recipient public key
and new signing public key.

The key server does not create or verify signatures. It only validates that a
signed replacement payload has the correct typed structure.

## Identity Rotation

Identity rotation is a local vault action. It should not take `--server` and it
should not upload anything.

```bash
lockbox vault identity rotate [identity]
```

Default behavior:

```text
generate a new recipient keypair
generate a new signing keypair
keep the old identity key material
mark the previous active generation as retired
make the new generation active
print a warning that existing lockboxes may still depend on retired keys
suggest lockbox vault share to notify contacts
suggest access refresh to migrate old lockboxes
```

The user then shares the new active generation with one or more third parties:

```bash
lockbox vault share alice@example.com
```

The user can share a retired generation when another party needs to access an
old archive:

```bash
lockbox vault share alice@example.com --key-index 1
```

The CLI must warn whenever it uses a retired identity generation, including for
unlocking, sharing, or refreshing access. The warning should include the
generation index and fingerprint.

Identity history lists addressable generations:

```bash
lockbox vault identity history [identity]
```

Output columns:

```text
index
status
recipient_fingerprint
signing_fingerprint
created
retired
known_lockboxes
```

`known_lockboxes` is optional at first. If the vault does not yet track which
lockboxes used each generation, print `unknown`.

If a user lost their old vault, they cannot produce a signed replacement. In
that case they create or import a new identity and share an unsigned
replacement:

```bash
lockbox vault share alice@example.com --unsigned-replacement
```

The receiver must verify by code before accepting it.

## Existing Lockboxes After Identity Rotation

Identity rotation does not automatically update old lockboxes.

Any lockbox encrypted to the old recipient public key remains unlockable only
with the matching old private key until its access entries are refreshed to the
new active key.

Therefore:

```text
do not delete old private key material during rotation
keep old identity generations in the vault as retired
warn users that old lockboxes still depend on retired keys
provide a separate lockbox access refresh command
```

Refresh one lockbox from any retired generation to the active generation:

```bash
lockbox access refresh <lockbox> <identity>
```

Refresh known lockboxes for one identity:

```bash
lockbox access refresh --all <identity>
```

Refresh known lockboxes for every identity:

```bash
lockbox access refresh --all
```

Preview changes without writing:

```bash
lockbox access refresh --all --dry-run
```

Apply without prompting:

```bash
lockbox access refresh --all --yes
```

For one explicit lockbox, a missing path is an error:

```text
error: lockbox not found: project.lbox
```

For `--all`, missing known lockboxes are reported in the plan and summary. The
command should not apply updates until the user confirms despite the missing
entries.

List old key generations first:

```bash
lockbox vault identity history <identity>
```

The refresh flow must:

```text
unlock the lockbox using any available current or retired identity generation
add access for the new identity public key
remove access for the retired identity public key
commit the lockbox
update key-directory backup in the vault
```

If a lockbox cannot be unlocked with any available generation, report it and
leave it unchanged.

Deleting retired private key material should require an explicit command and a
strong warning because unmigrated lockboxes may become inaccessible.

## Known Lockboxes

The vault should track lockboxes it has created, unlocked, or modified through
access operations. Each known-lockbox record should be binary and contain:

```text
KnownLockbox {
    magic: "LBKL"
    version: u16
    lockbox_id: bytes
    path: utf8_string
    last_seen_unix_ms: u64
    last_known_access_fingerprints: [bytes]
}
```

Known lockbox records let `lockbox access refresh --all` build a plan without
scanning the filesystem.

Users need a way to remove stale records:

```bash
lockbox vault lockbox list
lockbox vault lockbox forget <lockbox>
```

`vault lockbox list` should show:

```text
path
state: present | missing | inaccessible
lockbox_id
last_seen
```

`vault lockbox forget <lockbox>` removes the known-lockbox record only. It must
not delete or modify the lockbox file.

## Doctor Checks

`lockbox doctor` should report known-lockbox health:

```text
Known lockboxes:
  present: 8
  missing: 1
  inaccessible: 1
```

For missing lockboxes, doctor should print the paths and suggested cleanup:

```text
Missing known lockboxes:
  /home/alice/old-project.lbox
    run: lockbox vault lockbox forget /home/alice/old-project.lbox
```

Doctor should not remove records automatically. It only reports and suggests
the explicit forget command.

## Binary Codec Rules

All new vault records should use explicit binary codecs:

```text
magic bytes
u16 version
u16 enum fields
u32 length-prefixed byte strings
u64 timestamps
optional fields encoded with a u8 presence flag
arrays encoded with u16 or u32 count
big-endian integers
strict trailing-byte rejection
```

Do not use JSON for contact, history, identity, or replacement records.

## Implementation Order

1. Add CLI config module with `share.server` YAML support and default
   `keyshare.onepub.dev`.
2. Add binary contact record codec to `lockbox_vault`.
3. Replace trusted-recipient vault APIs with contact-record APIs.
4. Update access resolution to load only verified contact current keys and warn
   on pending replacement.
5. Add binary identity records with signing key material.
6. Add verification-code helpers and canonical signing body helpers to the
   shared protocol or a small contact-sharing module.
7. Implement `lockbox vault share` publish/receive/delete.
8. Implement `lockbox vault contact add --share-code`.
9. Implement `lockbox vault identity rotate`.
10. Implement signed and unsigned `lockbox vault contact update --share-code`.
11. Implement `--accept` and `--reject` pending replacement handling.
12. Implement lockbox access refresh commands for retired identity generations.
13. Track known lockboxes in the vault.
14. Add `lockbox vault lockbox list` and `lockbox vault lockbox forget`.

Implemented in the current key-server pass:

- `lockbox vault share publish`
- `lockbox vault share receive`
- `lockbox vault share delete`
- `share.server` and `share.topology_url` YAML-style config lookup
- `--server` and `--topology-url` command overrides
- TLS-capable HTTP transport for `https://` key servers

Remaining CLI/contact work:

- verification-code interaction for received contacts
- contact replacement pending/accept/reject commands
- binary contact history records beyond the existing trusted-recipient record
15. Update `lockbox doctor` to report missing known lockboxes.

## Open Engineering Notes

The exact signing algorithm should be chosen before implementing identity
records. Ed25519 is a pragmatic choice because it is small, fast, and widely
understood, but this should be decided deliberately and exposed as a versioned
signing-key type in the binary identity and contact records.

The current `ShareClient` supports both `http://` and `https://` endpoints.
Plain HTTP remains useful for local tests and private reverse-proxy deployments;
the public default service uses HTTPS.
