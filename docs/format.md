# Lockbox Format Notes

This document records the current prototype layout. Numeric fields are little
endian unless stated otherwise.

## Fixed Header

The fixed header is 64 bytes.

```text
offset  size  field
0       8     magic: "LBX2HDR\0"
8       2     version: 2
10      6     reserved
16      8     latest manifest record offset
24      8     latest sequence
32      8     latest key directory offset, or 0
40      16    public vault UUID
56      4     reserved
60      4     checksum over bytes 0..60
```

The vault UUID is public metadata. It exists so tools can identify a vault even
if the file is renamed or moved. It must not be derived from file names,
content, recipients, or passwords.

## Key Directory

The key directory is an append-only metadata block. The header points at the
current directory. Older directories may remain in the file until compaction.

```text
offset  size  field
0       8     magic: "LBX2KEY\0"
8       8     total directory length
16      4     payload checksum
20      4     header checksum over bytes 0..20
24      n     encoded key slots
```

The encoded key directory is capped at 1 MiB. It stores only unlock metadata:
slot ids, slot kinds, salts/ciphertexts, and encrypted vault-key bytes. It must
not store paths, file names, environment variable names, or file contents.

## Record Frame

Records are scanner-friendly frames with encrypted private bodies.

```text
offset  size  field
0       8     magic: "LBX2REC\0"
8       1     record kind
9       7     reserved
16      8     sequence
24      8     encrypted body length
32      8     total record length
40      4     encrypted body checksum
44      4     header checksum over bytes 0..44
48      n     encrypted body
```

Record body encryption is per record. Compression is also per record body, not
whole-archive solid compression, so range reads and partial recovery remain
practical.

## Recovery

Recovery scans record frames from after the fixed header. It does not require a
valid header or valid manifest. If the header and manifest survive, recovery can
use the manifest for the current view. If not, it can rebuild a best-effort view
from intact encrypted records.
