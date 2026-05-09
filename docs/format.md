# Lockbox Format Notes

This document records the intended pre-1.0 production format. Numeric fields are
little endian unless stated otherwise.

The physical unit of the vault is a fixed-size encrypted segment page. Higher
level structures such as TOC nodes, file chunks, environment variables, key
directories, free-space indexes, and commit roots are encoded as objects inside
segment pages. Public APIs must not expose segment-page management.

## Fixed Header

The fixed header is 64 bytes and is the only mutable fixed-location structure in
the file.

```text
offset  size  field
0       8     magic: "LBX2HDR\0"
8       2     version: 2
10      2     header flags
12      4     header length: 64
16      8     latest commit-root segment page offset, or 0
24      8     latest commit sequence
32      8     latest public key-directory offset, or 0
40      16    public vault UUID
56      4     reserved
60      4     checksum over bytes 0..60
```

The vault UUID is public metadata. It exists so tools can identify a vault even
if the file is renamed or moved. It must not be derived from file names,
content, recipients, or passwords.

The header checksum detects torn or malformed header updates. It is not a
security boundary. Security decisions must be based on authenticated segment
pages and authenticated commit roots.

The key-directory pointer remains in the fixed header because users need the key
directory before the vault key is unlocked. The key directory stores only unlock
metadata and must not contain private file metadata.

## Segment Pages

Every segment page has the same physical size. The default page size is 8 MiB.
Implementations may read and write whole pages for native storage. Browser/WASM
clients may fetch page ranges over HTTP using the TOC offsets, but decryption
still authenticates a whole page.

```text
offset  size  field
0       8     magic: "LBX2SEG\0"
8       2     segment header version: 1
10      2     public flags
12      4     header length
16      8     page id
24      8     commit sequence that wrote this page
32      12    AEAD nonce
44      4     encrypted body length
48      4     header checksum
52      n     reserved header extension
H       m     encrypted body
H+m     p     zero padding to the fixed page size
```

The nonce is generated per page write and must be unique for the vault key. It
must not be derived only from record kind, object kind, or commit sequence.

Only the segment page header is public. Object kinds, object lengths, logical
paths, symlink targets, environment variable names, permissions, compression
selection, and file contents are inside the encrypted body.

Segment page AEAD associated data includes:

- vault format domain string
- fixed header version
- vault UUID
- page id
- commit sequence
- public flags
- encrypted body length

## Segment Body

The decrypted segment body is an object container.

```text
offset  size  field
0       1     segment body version: 1
1       1     compression algorithm
2       1     compression profile
3       1     reserved
4       8     uncompressed object-stream length
12      4     reserved
16      n     compressed or uncompressed object stream
```

Compression is chosen by the core per segment body:

- default writes try zstd with the normal profile
- if compression is larger or not useful, the body is stored uncompressed
- compaction may use a higher-ratio internal zstd profile
- the chosen algorithm and profile are stored inside encrypted metadata

The public API should not expose many compression modes. Normal callers get the
default policy. Maintenance commands such as compaction may choose the archival
profile internally.

## Objects

The object stream contains typed objects. Object headers are encrypted because
they are part of the segment body.

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

Initial object kinds:

```text
1       commit root
2       TOC leaf node
3       TOC internal node
4       file data
5       packed file data
6       symlink
7       env set
8       env delete
9       key directory
10      free-space index leaf
11      free-space index internal
```

## Commit Root

The fixed header points to the latest commit-root segment page offset. The
commit root is an encrypted object inside that page.

The commit root payload contains:

```text
field
commit sequence
vault UUID
format parameter set id
TOC root object reference
free-space index root object reference
key directory offset, or zero
previous commit-root reference, or zero
commit creation timestamp, optional and coarse
commit flags
```

Opening a vault reads the header, decrypts the commit-root page, validates the
commit root, then opens the referenced TOC and free-space indexes. If the header
is corrupt or stale, recovery may scan segment pages for valid commit roots and
choose the highest valid sequence.

Rollback attacks on a standalone copied file cannot be fully prevented without an
external freshness anchor. Lockbox detects internal corruption; it cannot prove
that an attacker has not replaced the entire file with an older valid copy.

## Table Of Contents

The TOC is a live-only copy-on-write BTree. Tombstones are not stored in the
current TOC. Deletes remove entries from the live TOC and return old object/page
references to the free-space index once they are no longer referenced.

Leaf payloads contain sorted manifest entries. Internal payloads contain sorted
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

## Free-Space Index

Reusable physical pages and reusable free regions are tracked by a transactional
free-space index committed with the same commit root as the TOC.

The index is maintained in two logical orders:

- by offset/page id, for coalescing adjacent free ranges
- by size, for best-fit allocation

The free-space index is a performance and space-reuse structure, not the source
of user-visible truth. If it is corrupt, tools may rebuild it by scanning valid
segment pages and comparing reachable objects from the latest valid TOC and
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
salts/ciphertexts, public recipient wrapping data, and encrypted vault-key bytes.
It must not store paths, file names, environment variable names, or file
contents.

The key directory is intentionally readable before the vault key is available.
Its wrapped vault-key values are authenticated by their wrapping algorithms; its
outer structure is length-limited and checksummed so tools can reject malformed
metadata early.

Removing a password or recipient is not just a metadata delete. Because old COW
history may contain old key directories or data pages, the CLI must treat key
removal as a conservative maintenance operation:

1. remove the key slot from the live key directory
2. rewrite reachable encrypted pages as needed under the retained vault key or a
   new vault key
3. compact unreachable old pages
4. commit the new key directory and free-space index

## Segment Page Cache

The core uses a unified segment-page cache for reads and dirty writes. Clean
decoded pages are held in a weighted LRU cache. Dirty pages are not visible to
readers until `commit()` writes them and publishes a new commit root.

`CacheLimit::Auto` is segment-aware:

- minimum native cache: max of eight segment pages or 64 MiB
- native target: about 15% of currently available/reclaimable memory
- native cap: 4 GiB by default
- WASM default: 64 MiB unless the embedder supplies an explicit limit

The cache is a performance mechanism, not a correctness requirement. TOC
traversal, recovery, and extraction must all work when the cache is disabled.

## Recovery

Recovery scans segment pages from after the fixed header. It does not require a
valid fixed header, TOC, or free-space index.

Recovery can:

- authenticate and decrypt intact segment pages independently
- locate valid commit roots
- rebuild a best-effort live view from the highest valid commit root
- salvage file objects whose metadata can still be associated with paths
- report intact, corrupt, and lost counts

Recovery is not an undelete guarantee. Once freed pages or free regions have
been overwritten, the old objects are no longer recoverable.
