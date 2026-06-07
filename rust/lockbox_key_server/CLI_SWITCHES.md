# lockbox_key_server command line switches

## Quick usage

Build and run with defaults:

```bash
cargo build -p lockbox_key_server --release
./target/release/lockbox_key_server run
```

Run as a system service:

```bash
sudo ./target/release/lockbox_key_server install
sudo ./target/release/lockbox_key_server status
```

Useful one-off flags:

```bash
./target/release/lockbox_key_server run --bind 0.0.0.0:8089 --state-dir /tmp/lockbox-key-server
./target/release/lockbox_key_server install --force-config
./target/release/lockbox_key_server uninstall --purge-data
./target/release/lockbox_key_server resync-peer --peer-url https://peer.example/v1/replicate
```

Config file bootstrap:

```bash
./target/release/lockbox_key_server run --config /etc/lockbox/key-server.toml
```

## Command forms

- `lockbox_key_server`  
  Equivalent to `lockbox_key_server run`.
- `lockbox_key_server run [options]`
- `lockbox_key_server install [--force-config]`
- `lockbox_key_server uninstall [--purge-data]`
- `lockbox_key_server status`
- `lockbox_key_server resync-peer --peer-url URL [options]`
- `lockbox_key_server bench-store [options]`
- `lockbox_key_server bench-http [options]`
- `lockbox_key_server bench-http-fetch [options]`
- `lockbox_key_server bench-http-flow [options]`
- `lockbox_key_server help`
- `lockbox_key_server --help` / `-h`

## Global flags

- `--help`, `-h`  
  Print help and exit immediately.

## `run` options (also shared by commands that call `config_from_args`)

All options below are parsed for `run`, `bench-*`, `resync-peer` (indirectly), and are applied from `ServerConfig`.

### Core server configuration

| Switch | Type | Default | Description |
| --- | --- | --- | --- |
| `--config PATH` | string | — | Load options from file first (`key = value`, `#` comments supported). Can be repeated. |
| `--bind ADDR` | string | `127.0.0.1:8089` | Bind address for the HTTP server (e.g. `0.0.0.0:8089`). |
| `--state-dir PATH` | path | `/var/lib/lockbox-key-server` | Directory used for persisted share store state. |
| `--developer` | flag | false | Enables developer mode and switches state dir to a temp directory. |
| `--server-id N` | integer | `0` | Routing server id. Must be 0..35 (0..9, a..z). |
| `--cluster-id ID` | string | `"default"` | Public topology cluster id. |
| `--public-url URL` | string | derived from `--bind` | Public `/v1/share` base URL for this server. |

### Topology

| Switch | Type | Default | Description |
| --- | --- | --- | --- |
| `--topology-version N` | integer | `1` | Public topology version. |
| `--topology-server ID=URL[,STATUS]` | string | none | Add topology entry. `STATUS` is `active` (default), `standby`, `promoted`, or `disabled`. |
| `--route OWNER=PRIMARY[,FAILOVER...]` | string | none | Add owner routing rule. At least one primary server id is required. |
| `--promoted-owner N` | integer | none | Add promoted owner id. Can be repeated. |

### Replication

| Switch | Type | Default | Description |
| --- | --- | --- | --- |
| `--replication-token TOKEN` | string | none | Shared replication token. |
| `--replication-peer-url URL` | string | none | Allowed peer replication URLs. Can be repeated. |
| `--origin-epoch N` | integer | current epoch millis | Origin epoch for replication conflict resolution. |

### Benchmarking

| Switch | Type | Default | Description |
| --- | --- | --- | --- |
| `--requests N` | integer | `50000` | Number of requests for benchmark commands. |
| `--payload-bytes N` | integer | `512` | Payload size for benchmarking. |
| `--concurrency N` | integer | `0` | Concurrency for benchmarking. |
| `--preload-shares N` | integer | `0` | Live shares to create before timing. |

### Storage and limits

| Switch | Type | Default | Description |
| --- | --- | --- | --- |
| `--compact-min-bytes N` | integer | `67108864` | Bytes in storage before background compaction runs. |
| `--rate-limit-per-minute N` | integer | `120` | Per-IP request limit. `0` disables rate limiting. |
| `--rate-limit-burst N` | integer | `40` | Per-IP rate limit burst capacity. |
| `--verification-email-command PATH` | path | none | Invoked as `<command> <email> <url>`. |
| `--verification-email-rate-limit-per-hour N` | integer | `5` | Per-email verification email rate limit (per hour). |
| `--verification-email-ip-rate-limit-per-hour N` | integer | `30` | Per-source-IP verification email rate limit (per hour). |

## `install`, `uninstall`, `status`

### `install [--force-config]`

- `--force-config`  
  Re-write `/etc/lockbox/key-server.toml` during install even when it already exists.

### `uninstall [--purge-data]`

- `--purge-data`  
  Remove persisted data/cache/config paths on uninstall:
  - `/var/lib/lockbox-key-server`
  - `/var/cache/lockbox-key-server`
  - `/var/log/lockbox-key-server`
  - `/etc/lockbox/key-server.toml`

### `status`

- No switches. Prints unit/config/state/log status.

## `resync-peer`

- `--peer-url URL`  
  Required. Target peer `/v1/replicate` endpoint.
- Other options: any `run` config option above (except `--peer-url`) may be passed and are parsed as part of configuration.

## Notes

- Unrecognized options cause an error.
- `--topology-server` and `--route` can be provided multiple times.
- `--replication-peer-url` and `--promoted-owner` can be provided multiple times.
- The parser is not using `clap`; flags are manually processed.
