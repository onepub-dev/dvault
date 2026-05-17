# Lockbox Format Notes

This document records the intended pre-1.0 production format. All on-disk
numeric fields are little-endian unless stated otherwise.

Implementations must not serialize on-disk structures with native-endian
conversions, memory transmutation, or raw struct layout. Every numeric field
must be encoded and decoded with an explicit byte order. Language bindings
should expose parsed APIs rather than asking callers to reinterpret raw lockbox
bytes.

The CI workflow `.github/workflows/endian-interop.yml` verifies this contract
by transferring lockbox fixtures between Linux x64, Linux arm64, macOS arm64,
and an emulated big-endian `s390x` environment. The big-endian job reads a
little-endian-created fixture and emits a fixture that Linux x64 reads back.

The physical unit of the lockbox is a fixed-size encrypted page selected from a
small set of page classes. Metadata pages are 128 KiB. File-data pages are
8 MiB. Higher level structures such as TOC nodes, file chunks, environment
variables, key directories, free-space indexes, and commit roots are encoded as
objects inside pages. Public APIs must not expose page management.

## Fixed Header

The fixed header is 96 bytes and is the only mutable fixed-location structure in
the file.

```text
offset  size  field
0       8     magic: "LBX2HDR\0"
8       2     version: 3
10      2     header flags
12      4     header length: 96
16      8     latest commit-root page offset, or 0
24      8     latest commit sequence
32      8     latest public key-directory offset, or 0
40      16    public lockbox UUID
56      8     reserved
64      32    SHA-256 checksum over bytes 0..64
```

The lockbox UUID is public metadata. It exists so tools can identify a lockbox
even if the file is renamed or moved. It must not be derived from file names,
content, recipients, or passwords.

The header checksum is a domain-separated SHA-256 digest. It detects torn or
malformed header updates. It is not a security boundary. Security decisions must
be based on authenticated pages and authenticated commit roots.

The key-directory pointer remains in the fixed header because users need the key
directory before the content key is unlocked. The key directory stores only
unlock metadata and must not contain private file metadata.

## Pages

Every page has a fixed physical size for its page class. Metadata pages are
128 KiB. File-data pages are 8 MiB. Implementations may read and write whole
pages for native storage, but page headers also expose the stored body length
so readers can authenticate an intact page without requiring trailing padding.
Browser/WASM clients may fetch page ranges over HTTP using the TOC offsets, but
decryption still authenticates a whole page body.

```text
offset  size  field
0       8     magic: "LBX2PAG\0"
8       2     page header version: 2
10      2     public flags
12      4     header length
16      8     page id
24      8     commit sequence that wrote this page
32      12    AEAD nonce, or zero for clear-text pages
44      4     stored body length
48      16    reserved header extension
64      32    SHA-256 checksum over bytes 0..64
H       m     stored body
H+m     p     zero padding to the physical page size
```

The nonce is generated per page write and must be unique for the content key. It
must not be derived only from record kind, object kind, or commit sequence.

Most page bodies are encrypted with ChaCha20-Poly1305. Encrypted pages store
the AEAD nonce in the page header and the ciphertext plus authentication tag in
the stored body. The AEAD tag authenticates the page body and the associated
data listed below.

Some page classes are clear-text pages. Clear-text pages set public flag
`0x0001`, store a zero nonce, and store `SHA-256(body) || body` as the stored
body. Clear-text pages are not content-key encrypted, but the page cache/page
codec still validates their checksum before returning decoded objects. The key
directory is currently a clear-text page class because unlock metadata must be
read before the content key is available.

For encrypted pages, only the page header is public. Object kinds, object
lengths, logical paths, symlink targets, environment variable names,
permissions, compression selection, and file contents are inside the encrypted
body. For clear-text pages, object headers and payloads are public and must not
contain private file metadata.

Page public-header checksums are generated and verified at the page
cache/page-codec boundary. Higher-level TOC, file, recovery, and extraction code
must not bypass the page cache for normal page reads or writes.

Page AEAD associated data includes:

- lockbox format domain string
- fixed header version
- lockbox UUID
- page id
- commit sequence
- public flags
- stored body length

## Page Body

The decoded page body is an object container. For encrypted pages this is the
decrypted AEAD plaintext. For clear-text pages this is the checksummed body
after the checksum prefix has been validated and removed.

```text
offset  size  field
0       1     page body version: 1
1       1     compression algorithm
2       1     compression profile
3       1     reserved
4       8     uncompressed object-stream length
12      4     reserved
16      n     compressed or uncompressed object stream
```

Compression is chosen by the core per page body:

- default writes try zstd with the normal profile
- if compression is larger or not useful, the body is stored uncompressed
- compaction may use a higher-ratio internal zstd profile
- the chosen algorithm and profile are stored inside encrypted metadata

The public API should not expose many compression modes. Normal callers get the
default policy. Maintenance commands such as compaction may choose the archival
profile internally.

## Compressed File Extents

The production file-data layout is page-packed compressed extents, not one
compressed object per physical page. A fixed 8 MiB file-data page is a container.
Its encrypted body may contain:

- many complete compressed small files
- many compressed chunks from one or more files
- one fragment of a large compressed chunk
- a mix of complete chunks and fragments, as long as the page body fits

Large files are compressed as independent bounded frames rather than one
whole-file solid stream. A frame may span multiple physical pages, but it remains
independently decompressible once its page fragments have been fetched and
decrypted. TOC chunk entries identify the logical file offset, logical length,
compressed length, compression algorithm, frame id, and ordered physical page
fragments needed to reassemble that frame. Each physical fragment reference
contains the page offset, fixed page length, encrypted object id, compressed
frame offset, and fragment length.

This gives browser and web-service clients fast random access at frame
granularity:

1. fetch the TOC pages
2. decrypt the TOC
3. locate the compressed frame or frames for the requested file/range
4. request only the physical pages containing those frame fragments
5. decrypt the pages, reassemble the compressed frame bytes, and decompress

Recovery does not depend solely on the TOC. File fragment metadata is inside
encrypted page bodies and includes path, permissions, optional final file length,
logical frame offset, frame length, compression algorithm, frame id, compressed
frame length, compressed fragment offset, and fragment length. Streaming writes
may store `0` for the final file length because the final length is not known
when early frames are written; the TOC is authoritative when available, and
recovery can still infer a best-effort length from intact frames.

Paths remain private because both TOC entries and fragment metadata are inside
encrypted page bodies. They are exposed only after the caller has
unlocked the content key.

## Page Cache Boundary

Encryption policy, clear-text page checksums, dirty tracking, and physical page
writes are owned by the page cache. Higher layers construct or consume decoded
page objects and are otherwise oblivious to whether the page is encrypted or
clear-text. On read, the cache loads fixed page bytes from storage, validates
the page header checksum, authenticates encrypted pages or verifies clear-text
page checksums, decodes the page body once, then caches the decoded page. On
write, callers submit decoded page objects; the cache encodes, compresses,
encrypts or checksums according to page policy, writes one fixed page to
storage, and stores the decoded page in cache.

Raw page encode/decode helpers are format primitives. Production read/write
paths should route through the cache boundary. Direct raw decoding is reserved
for recovery scans and low-level format tests, where the caller starts from
untrusted bytes rather than from an opened lockbox.

Unlock is part of the cache boundary, not an exception to it. Key-directory
pages are clear-text page-cache pages, so password and recipient unlock should
read the current key-directory page through the page-cache read/decode path.
Raw byte scanning is only a fallback for damaged headers, missing roots, or
recovery-style mirror discovery.

The fixed header is the direct-access bootstrap record. It may be read directly
before any page roots are known, and it may be written directly when publishing
a commit. Other page classes, including clear-text key-directory pages, use the
page-cache read/write boundary.

Compaction is a logical rewrite rather than an in-place page defragmenter. The
implementation reads the current TOC/env/key state, creates a fresh
lockbox with the same lockbox id and content key, writes each current object
through the normal page-cache APIs, commits that replacement, then swaps the
backing storage. It does not move encrypted or clear-text pages into free slots
inside the existing file, because that would require layout-specific rewrites of
every physical reference type and would bypass the normal COW/redaction rules.

## Objects

The object stream contains typed objects. Object headers are private on
encrypted pages because they are part of the encrypted page body. Object headers
are public on clear-text pages, so clear-text page classes must be limited to
public metadata.

```text
offset  size  field
0       1     object kind
1       1     object header version
2       2     object flags
4       8     object id
12      8     object payload length
20      n     object payload
```

Object ids are stable references used by TOC entries and indexes. A logical file
may reference one or more file-data objects. Multiple small logical files may be
packed into one file-pack object.

Symlinks are current TOC entries that reference symlink metadata objects. The current
TOC stores the symlink node kind plus the metadata page offset, object length,
and object id. It does not store the symlink target. The target is stored only
inside the referenced symlink object, and many symlink objects may be packed into
one metadata page.

Object kinds:

```text
1       commit root
2       TOC leaf node
3       TOC internal node
4       file data
5       packed file data
6       symlink
7       reserved legacy env set; not emitted by the current format
8       reserved legacy env delete; not emitted by the current format
9       key directory
10      free-space index leaf
11      free-space index internal
12      reserved legacy delete marker; not emitted by the current format
13      env leaf node
14      env internal node
```

## Commit Root

The fixed header points to the latest commit-root page offset. The
commit root is an encrypted object inside that page.

The commit root payload contains:

```text
field
commit-root payload version: 3
commit sequence
TOC root object reference
environment root object reference, or zero
free-space index root object reference
primary key-directory offset, or zero
key-directory mirror offset A, or zero
key-directory mirror offset B, or zero
key-directory generation
previous commit-root reference, or zero
commit flags
```

Opening a lockbox reads the header, decrypts the commit-root page, validates
the commit root, then opens the referenced TOC and free-space indexes. If the
header is corrupt or stale, recovery may scan pages for valid commit
roots and choose the highest valid sequence.

Rollback attacks on a standalone copied file cannot be fully prevented without an
external freshness anchor. Lockbox detects internal corruption; it cannot prove
that an attacker has not replaced the entire file with an older valid copy.

An external freshness anchor is state outside the lockbox that records the
latest known version, generation, hash, or signed timestamp. Examples include a
server-side object generation number, transparency log entry, signed TOC,
append-only audit log, or application database row. Lockbox can reject stale
internal metadata within one file by choosing the highest authenticated
generation; only an external anchor can detect replacement of the whole file
with an older but internally valid lockbox.

## Table Of Contents

The TOC is a current-entry copy-on-write BTree. Tombstones are not stored in the
current TOC. Deletes remove entries from the current TOC, redact the referenced
payload or metadata object through the page cache, and return old object/page
references to the free-space index once they are no longer referenced. Deleted
files and symlinks are not discoverable during recovery after their metadata has
been redacted.

Leaf payloads contain sorted TOC entries. Internal payloads contain sorted
child separators and child object references.

Decode rules are intentionally strict:

- leaf entries must be strictly sorted by logical path
- duplicate leaf paths are corrupt
- internal children must be strictly sorted by separator path
- duplicate separators are corrupt
- child references must resolve to valid TOC objects
- every stored path must pass logical path validation
- missing or corrupt child objects make the TOC corrupt

Updating a file rewrites the touched TOC leaf and changed ancestors. Unchanged
TOC pages remain referenced by the previous and current commit roots until
compaction reclaims unreachable history.

## Environment Variables

Environment variables are encrypted metadata, not files. They must not appear in
file listings, file recovery listings, visualizations, or unauthenticated public
metadata.

The committed env namespace stores only current entries, like the TOC. It must contain only the
current value for each env name. Old env values are secret material; they must
not remain decryptable in old COW pages after `set_env`, `delete_env`, or
recipient changes are committed. This is required because adding a recipient
grants access to the lockbox content key, and that recipient could otherwise
decrypt stale env pages containing secrets that are still valid elsewhere.

The env structure is commit-root referenced. The commit root points to an env
root object, or zero when no env vars exist. Env entries are packed into
encrypted env leaf pages so many small env vars share a page. Env internal pages
contain only sorted routing names and child page offsets; env values exist only
in env leaves.

Each env leaf entry stores its sensitivity bit. Sensitivity is declared when the
env var is created, updates preserve it, and changing sensitivity requires
delete plus recreate. All env values are encrypted at rest. In memory, normal
values use ordinary string access and secret values use secure string storage
and scoped access. Normal `get_env`, `list_env`, and scoped `visit_env`
operations load from the env root and must not discover env vars by scanning the
whole lockbox; `visit_env` includes both normal and secret values, yielding
secret entries as `SecretString` references so plaintext access still goes
through the secret value's scoped callback.

Env pages must not embed forward or backward linked-list pointers as the primary
structure. Page-embedded linked lists interact poorly with copy-on-write: when a
middle page changes, every link that reaches it may need to be rewritten, and a
tail/head mutation can force extra page rewrites. Use a root-referenced
directory/tree or other immutable index structure. The current pre-1.0
implementation writes a packed env BTree from the current namespace on env commits
and reuses the same encoded-size grouping and routing-child codec as the TOC.

An env update follows the same secret-redaction rule as file replacement:

1. read the current env directory
2. build replacement env page(s) containing only current env entries
3. stage sanitized replacements for old env tree pages through the page cache
4. publish the new env root in the next commit root
5. add the old env tree page slots to the committed free-space index

Appending a tombstone or replacement record without redacting the old value is
not acceptable for env vars. Such a log can be useful for non-secret audit data,
but env vars are encrypted active configuration values and may include declared
secrets.

No backwards-compatible env-history scan is supported. The format is still
pre-release and there are no existing production vaults to migrate.

## Free-Space Index

Reusable physical pages and reusable free regions are tracked by a transactional
free-space index committed with the same commit root as the TOC.

The index is maintained in two logical orders:

- by offset/page id, for coalescing adjacent free ranges
- by size, for best-fit allocation

The free-space index is a performance and space-reuse structure, not the source
of user-visible truth. If it is corrupt, tools may rebuild it by scanning valid
pages and comparing reachable objects from the latest valid TOC and
commit root.

The root object may be either a `free index leaf` or a `free index internal`
object. Leaf payloads contain sorted non-overlapping `(offset, length)` free
ranges. Internal payloads contain sorted child references:

```text
offset  size  field
0       1     free-index version: 1
1       1     node kind: 0 = leaf, 1 = internal
2       2     reserved
4       4     entry count
8       n     leaf ranges or internal children
```

Leaf entries are `(free_offset, free_length)`. Internal entries are
`(first_free_offset, child_page_offset)`. Children must be strictly sorted by
`first_free_offset`. Free-index pages are append-only during commit so the
published index never lists the page that stores the index itself.

## Key Directory

The key directory is public unlock metadata referenced by the fixed header and
mirrored in the commit root. It stores only slot ids, slot kinds,
salts/ciphertexts, public recipient wrapping data, and encrypted content-key
bytes.
It must not store paths, file names, environment variable names, or file
contents.

It also must not store recipient identities. Recipient names, email addresses,
local vault aliases, public recipient keys, and stable public-key fingerprints
would let a holder of one lockbox correlate membership with another lockbox or
another user's vault. The format stores only the slot material needed to attempt
unlock. ML-KEM encapsulation data must be freshly generated per slot creation
so the same recipient key does not produce a reusable cross-lockbox identifier.

The key directory is intentionally readable before the content key is available,
so it is stored as a page-cache-managed clear-text metadata page. Its wrapped
content-key values are authenticated by their wrapping algorithms. The page
format owns integrity for the clear-text page by adding and validating the page
body checksum. The key-directory payload itself is length-limited and contains
only enough structure to parse the key slots.

Every key-directory payload has this public header inside the key-directory
page object:

```text
offset  size  field
0       8     magic: "LBX2KEY\0"
8       2     key-directory version: 4
10      2     flags
12      4     header length: 64
16      8     total key-directory length
24      8     key-directory generation
32      16    lockbox UUID
48      4     copy index
52      12    reserved
64      n     key-slot payload
```

The lockbox writes three copies of the key directory for every key-directory
generation: a primary copy referenced by the fixed header, plus two mirror
copies referenced by the commit root. Key-directory generation changes only
when key slots are created, updated, or removed; ordinary file, symlink, env, or
TOC commits keep referencing the existing key-directory pages.

Recovery can also scan the raw lockbox for clear-text key-directory pages,
validate the page checksums, group decoded key-directory payloads by lockbox
UUID, and use the highest generation that successfully unwraps the content key.

The fixed header is therefore a fast path, not the only path. If the header is
corrupt, password/public-key unlock can recover the lockbox UUID and content key
from a scanned key-directory mirror, then use those values to authenticate and
decrypt pages while scanning for the latest valid commit root.

Removing a password or recipient is not just a metadata delete. Because old COW
history may contain old key directories or data pages, the CLI must treat key
removal as a conservative maintenance operation:

1. remove the key slot from the current key directory
2. logically rewrite reachable files, symlinks, env vars, TOC nodes, free-space
   metadata, and key-directory pages through the page cache into a replacement
   lockbox
3. commit the replacement lockbox
4. swap the replacement backing storage over the old one

## Page Cache

The core uses a unified page cache for reads and writes. Clean decoded pages
are held in a weighted LRU cache. Normal dirty pages stay in the cache and are
visible to reads from the same opened lockbox, but they are not written to the
backing store until `commit()` flushes them and publishes a new commit root.
Secure env pages are appended through the cache's secure write path, which
encodes and writes the encrypted page and caches a secure-backed `DecodedPage`.
There is no background writer.

The cache is given explicit workload policy by the caller-facing lockbox layer.
It does not infer that a page is insert-only from page contents or offsets. In
the default `Interactive` profile, dirty pages are retained after flush. In the
`BulkImport` profile, newly appended file-data pages may be flushed as
discard-after-flush pages so large initial imports do not keep every written
data page resident. Metadata pages, redaction writes, TOC nodes, env tree nodes,
free-index pages, key-directory pages, and commit roots remain on the normal
commit-time path.

Copy-on-write happens at commit time. This allows the same dirty page to absorb
multiple logical mutations before the library allocates and writes replacement
pages.

When a file, symlink, or environment variable is deleted or replaced, the commit
path must redact the physical page that held the old encrypted object. If the
old page also contains current objects, those objects are relocated to a new
page first; then the old physical page is overwritten with zeros and removed
from the decoded-page cache. This is required because old COW pages may still
contain decryptable ciphertext even after the current TOC or env root no longer
references them.

`CacheLimit::Auto` is page-aware:

- minimum native cache: max of sixty-four metadata pages or 64 MiB
- native target: about 15% of currently available/reclaimable memory
- native cap: 4 GiB by default
- WASM default: 64 MiB unless the embedder supplies an explicit limit

The cache is a performance mechanism, not a correctness requirement. TOC
traversal, recovery, and extraction must all work when the cache is disabled.

## Recovery

Recovery scans pages from after the fixed header. It does not require a
valid fixed header, TOC, or free-space index.

Recovery can:

- authenticate and decrypt intact pages independently
- locate valid commit roots
- rebuild a best-effort current view from the highest valid commit root
- salvage file objects whose metadata can still be associated with paths
- report intact, corrupt, and lost counts

Recovery is not an undelete guarantee. Once freed pages or free regions have
been overwritten, the old objects are no longer recoverable.
