# Lockbox Share Server Benchmarks

Benchmarks were run on the local development host with the release binary.
HTTP benchmarks use one binary `POST /v1/share` per TCP connection because the
expected client model is a single CLI request rather than a long-lived
keep-alive session.

## Store Benchmark

Command:

```bash
/usr/bin/time -v target/release/lockbox-share-server \
  bench-store \
  --state-dir /tmp/lockbox-share-store-bench-200k-compact-001 \
  --requests 200000 \
  --payload-bytes 512
```

Result:

```text
store_create_rps=216805
store_fetch_rps=302815
live=200000
max_rss_kb=52436
```

This keeps 200k live shares with 512-byte payloads below the 100 MB memory
target. Payloads are persisted in append-only segment files; the live in-memory
index stores hashes, offsets, lengths, expiry, and fetch state.

## HTTP Benchmark

Command:

```bash
/usr/bin/time -v target/release/lockbox-share-server \
  bench-http \
  --state-dir /tmp/lockbox-share-http-bench-compact-001 \
  --requests 50000 \
  --payload-bytes 512 \
  --concurrency 128
```

Result:

```text
http_single_request_share_rps=54179
requests=50000
concurrency=128
live=50000
max_rss_kb=18292
```

The HTTP path handles tens of thousands of single-request shares per second
while staying well under the 100 MB target.

## HTTP Fetch Benchmark

Command:

```bash
/usr/bin/time -v target/release/lockbox-share-server \
  bench-http-fetch \
  --state-dir /tmp/lockbox-share-http-fetch-bench-001 \
  --requests 50000 \
  --payload-bytes 512 \
  --concurrency 128
```

Result:

```text
http_single_request_fetch_rps=58846
requests=50000
concurrency=128
live=0
max_rss_kb=20616
```

This preloads 50k single-use shares, then fetches them over HTTP using one TCP
connection per request. `live=0` verifies that successful single-use fetches
consume and tombstone the pending shares.

## HTTP End-to-End Flow Benchmark

Command:

```bash
/usr/bin/time -v target/release/lockbox-share-server \
  bench-http-flow \
  --state-dir /tmp/lockbox-share-http-flow-bench-001 \
  --requests 50000 \
  --payload-bytes 512 \
  --concurrency 128
```

Result:

```text
http_single_request_flow_rps=25782
http_single_request_total_rps=51564
flows=50000
concurrency=128
preloaded=0
live=0
max_rss_kb=13284
```

Each flow performs two separate TCP connections: one `SHARE` request followed
by one `FETCH` request. This is the closest benchmark to the expected CLI
usage pattern. `live=0` confirms single-use shares are consumed after receipt.

## HTTP End-to-End Flow With 1M Preloaded Shares

Command:

```bash
/usr/bin/time -v target/release/lockbox-share-server \
  bench-http-flow \
  --state-dir target/lockbox-share-http-flow-preload-1m-bucket-002 \
  --share-code-digits 12 \
  --preload-shares 1000000 \
  --requests 50000 \
  --payload-bytes 512 \
  --concurrency 128
```

Result:

```text
http_single_request_flow_rps=25254
http_single_request_total_rps=50508
flows=50000
concurrency=128
preloaded=1000000
live=1000000
max_rss_kb=82376
```

This preloads one million pending shares before timing the end-to-end flow.
The result stays below the 100 MB memory target by using compact disk bucket
index files plus a bounded in-memory recent-share cache. This benchmark uses
12-digit share codes because 8-digit codes have too much collision pressure at
one million live shares.

Benchmarks disable the per-IP rate limiter so they measure server throughput.
Production defaults enable a per-IP token bucket.

## Compaction

Single-use shares are tombstoned immediately after successful fetch. Background
compaction rewrites shard segment files when they contain enough dead bytes,
and explicit `compact()` tests prove tombstoned single-use backlogs can shrink
back to zero segment bytes when no live shares remain.

## Indexing

Payloads are stored in append-only segment files. Live lookup metadata is
stored in compact fixed-size disk bucket records keyed by the share-code hash.
The process keeps only a bounded recent-share cache in memory. This avoids
retaining every pending share in RAM while preserving single-key lookup without
scanning the full store.

## Share Code Space

The production default is one server routing digit plus a 12 digit random body.
Six random body digits are still supported for smaller deployments, but they
are not appropriate for sustained high-rate pending-share populations because
the live code space is capped at one million per server id. The server clamps
configurable random body length to 6..12 digits.

## Abuse Controls

Production defaults are intentionally bounded:

```text
payload_cap=8 KiB
default_ttl=15 minutes
max_ttl=15 minutes
max_fetches_per_share=8
rate_limit_per_ip=120 requests/minute
rate_limit_burst=40
```

The server validates typed, versioned Lockbox share payloads before storing
them, so arbitrary blobs are rejected. The remaining controls reduce usefulness
as a store-and-forward relay by limiting payload size, lifetime, fan-out, and
request rate for syntactically valid but still untrusted share messages.

## CPU Profile

Command:

```bash
perf stat \
  -e cycles,instructions,context-switches,cpu-migrations,page-faults \
  target/release/lockbox-share-server \
  bench-http \
  --state-dir /tmp/lockbox-share-http-perf-002 \
  --requests 50000 \
  --payload-bytes 512 \
  --concurrency 128
```

Result:

```text
http_single_request_share_rps=70819
cycles=39657318266
instructions=20756037342
context_switches=87850
cpu_migrations=23410
page_faults=4964
elapsed_seconds=0.759955423
user_seconds=0.555298
sys_seconds=9.250256
```

Fetch-path counter command:

```bash
perf stat \
  -e cycles,instructions,context-switches,cpu-migrations,page-faults \
  target/release/lockbox-share-server \
  bench-http-fetch \
  --state-dir /tmp/lockbox-share-http-fetch-perf-001 \
  --requests 50000 \
  --payload-bytes 512 \
  --concurrency 128
```

Fetch-path result:

```text
http_single_request_fetch_rps=70551
cycles=40298295480
instructions=21396337648
context_switches=86477
cpu_migrations=22371
page_faults=5472
elapsed_seconds=0.978261193
user_seconds=0.622768
sys_seconds=9.316255
```

End-to-end flow counter command:

```bash
perf stat \
  -e cycles,instructions,context-switches,cpu-migrations,page-faults \
  target/release/lockbox-share-server \
  bench-http-flow \
  --state-dir /tmp/lockbox-share-http-flow-perf-001 \
  --requests 50000 \
  --payload-bytes 512 \
  --concurrency 128
```

End-to-end flow result:

```text
http_single_request_flow_rps=30149
http_single_request_total_rps=60298
cycles=95370493307
instructions=49265979596
context_switches=169530
cpu_migrations=39103
page_faults=3092
elapsed_seconds=1.711987716
user_seconds=1.126379
sys_seconds=22.379968
```

Sampled `perf record` data showed most samples in kernel space. Kernel symbol
resolution was restricted on the benchmark host, but the high system time and
context-switch count are consistent with the intentional benchmark shape:
single HTTP request per TCP connection.

## Persistence Tests

The test suite covers:

```text
live share replay after store reopen
fetch count replay after store reopen
exhausted share tombstone replay
single-use share removal on successful fetch
20k-record persistent store replay
compaction removes tombstoned single-use backlog
compaction preserves live records
```

Run:

```bash
cargo test -p lockbox_share_server
```

Current result:

```text
12 passed
```
