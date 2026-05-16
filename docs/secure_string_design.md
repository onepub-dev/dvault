# Secure String Storage Design

## Goal

Lockbox needs secure in-memory storage for passwords, passphrases, and content
keys without paying one locked OS page per small value. Existing secure string
crates provide useful API patterns, but most allocate and protect each value
independently. That gives strong per-allocation isolation but wastes locked
memory when the process holds many small secrets.

The design here keeps the security primitives conventional and keeps the custom
code focused on storage policy:

- use OS page ownership for locked memory;
- lock each secure arena once with `mlock`/`VirtualLock` where available;
- protect idle pages with `mprotect(PROT_NONE)`/`VirtualProtect(PAGE_NOACCESS)`;
- allocate many small secure buffers from the same locked arena;
- zeroize slots on clear, reallocation, and drop;
- expose secrets only through scoped access.

## Memory Layout

Each arena owns a page-aligned virtual memory region:

```text
[ guard page ][ locked secure data pages ][ guard page ]
```

The guard pages are never accessible. The data pages are locked into RAM where
the OS allows it and are protected as no-access when idle. Allocator metadata is
ordinary Rust state outside the locked arena and must not contain secret bytes.
Each slot also has before/after canaries inside the locked arena so slot-local
overrun or underrun corruption is detected before read, write, zeroize, or free
operations continue.

Small allocations use size classes so many secrets can share one arena. The
default arena data chunk is 64 KiB and can be configured for future arenas:

```text
64, 128, 256, 512, 1024, 2048, 4096 byte slots
```

Large allocations receive a dedicated arena-sized slot rounded to page size.

## Access Model

Page protection is process-wide and page-granular. A borrowed `&[u8]` or `&str`
cannot safely escape while the implementation also promises to re-protect the
page afterwards. For that reason, direct long-lived expose APIs are replaced by
scoped access:

```rust
secret.with_bytes(|bytes| {
    use_secret(bytes);
})?;

lockbox_secure::read_access(|access| {
    access.with_bytes(&secret_a, |a| {
        access.with_bytes(&secret_b, |b| {
            use_two_secrets(a, b);
        })
    })
})??;
```

Entering a read-access scope does not unprotect anything. Pages are unprotected
lazily when a value is touched. The scope records touched pages and re-protects
them when the outermost read scope exits, including during unwinding. Nested
read scopes on the same thread reuse the active scope.

For repeated operations, callers should use one read-access scope. That pays the
page-protection syscall cost once per touched page rather than once per secret.
Mutation, allocation, and clone return `Error::ReadAccessActive` while read
access is active on the same thread, so callers can retry instead of
deadlocking. Drops inside a read-access scope are deferred until the outermost
scope exits.

Construction and mutation are fallible. `SecureVec::try_from_vec`,
`SecureString::try_from_bytes`, `try_push_byte`, and related methods return
`Result` because secure allocation, memory locking, page protection, and canary
checks can fail. APIs that copy secret bytes into an ordinary `Vec` or `String`
are intentionally not part of the secure storage API; callers should keep work
inside scoped access wherever possible.

Canaries are derived from allocation metadata and a random per-process seed.
The seed is generated once from the OS RNG on first use, so the steady-state
cost is one cached integer read plus the existing canary derivation.

## Weakened Allocation

The default allocator fails closed if hardened memory cannot be created. On
Unix and Windows that means locked pages, guard pages, and page protection must
be available. On Linux the data pages are also marked `MADV_DONTDUMP` and
`MADV_DONTFORK`.

Applications that knowingly run on non-hardened targets can explicitly opt in
to weakened allocation with `set_weakened_allocation_allowed(true)`. In that
mode allocation may fall back to zeroizing ordinary memory without locking,
guard pages, or page protection. `secure_memory_capabilities()` reports the
platform capability set so applications can decide whether weakened allocation
is acceptable for their deployment.

## Threading

The first implementation uses one thread-safe global pool guarded by a mutex.
Only one active read-access scope exists for the pool at a time, with nested
same-thread scopes reusing the outer scope. This avoids races where one scope
re-protects a page while another scope still has a borrowed slice into it.

A future local pool can be added for single-threaded applications:

```text
LocalSecurePool:
  !Send + !Sync, Cell/RefCell state, no mutex

ThreadSafeSecurePool:
  Send + Sync, mutex state, one active guard
```

The pool owns the concurrency policy because page protection is a heap/page
property, not a property of an individual string.

## UTF-8

`SecureString` stores UTF-8 bytes. CLI input can append raw bytes on Unix and
UTF-8 encoded characters on Windows. String access validates UTF-8 at the
boundary. The implementation does not silently normalize Unicode because that
would change the exact password bytes users entered.

## Non-Goals

- This is not a complete defense against malicious code running in the same
  process or as the same OS user.
- Page protection is not per-string isolation. If two secrets share a page,
  accessing one temporarily makes the whole page accessible until the access
  guard drops.
- Legacy APIs that return raw borrowed secret slices without a guard are
  incompatible with automatic page re-protection.
