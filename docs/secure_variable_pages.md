# Secure variable pages

Vault environment variables are stored in the encrypted variable tree. Secret
environment values must not be decoded into ordinary heap memory after the page
is read from disk.

The variable tree uses internal names to separate storage classes:

- `.plain/<name>` for normal environment variables
- `.secret/<name>` for secret environment variables

Leaf grouping keeps storage classes from sharing leaf pages. Variable tree reads use
the encrypted variable tree metadata to know that the requested page is variable-related
before the page body is decrypted. Variable pages are read from storage with
`read_at_secure` into `SecureVec`, decrypted in place, and decoded through the
secure single object page path.

Variable tree pages are inserted into the decoded page cache only when requested with
the secure page policy. The cache stores one `DecodedPage` type, but each page
object payload has a storage class. Normal pages use ordinary `Vec<u8>`
payloads; secure variable pages use `SecureVec` payloads.

Every variable read and write must pass through this decoded page cache path. Reads
must request the secure variable page policy before decoding, and writes must use the
page-cache append path so old variable pages are sanitized/redacted and cache entries
are invalidated consistently. Variable code must not bypass the cache by scanning raw
pages or by writing ad hoc variable records directly to storage.

`PageBuffer` is the shared decoder buffer contract for in-place page-body
decoding. It is intentionally narrower than `Vec`: it provides read access,
mutable access, truncation, and secure range cloning. Building page payloads
still uses explicit `Vec` or `SecureVec` APIs so call sites must choose the
storage class deliberately. Secure variable writes go through the page cache append
path, which owns secure page encoding, storage append, and secure decoded-page
cache insertion.

Inspection and recovery scans must not decode variable pages through the normal page
decoder. Current variable pages are single-object secure pages, so scan/inspection
first attempts secure variable metadata decoding and skips normal decoding for variable objects
leaf/internal pages.
