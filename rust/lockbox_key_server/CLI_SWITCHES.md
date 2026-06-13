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
./target/release/lockbox_key_server run --bind 0.0.0.0:8089
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
- `lockbox_key_server bench-store --dev [options]`
- `lockbox_key_server bench-http --dev [options]`
- `lockbox_key_server bench-http-fetch --dev [options]`
- `lockbox_key_server bench-http-flow --dev [options]`
- `lockbox_key_server help`
- `lockbox_key_server --help` / `-h`

## Global flags

- `--help`, `-h`  
  Print help and exit immediately.

## Public `run` options

Most server configuration belongs in the TOML config file. The public command
line surface is intentionally small:

- `--config PATH`
- `--bind ADDR`
- `--dev`
- `--peer-url URL` for `resync-peer`

Use `lockbox_key_server --help --dev` to show test and benchmark overrides.

## Config file keys

These keys are read from `--config PATH` as `key = value` lines.

### Core server configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `bind_addr` | string | `127.0.0.1:8089` | Bind address for the HTTP server. |
| `state_dir` | path | `/var/lib/lockbox-key-server` | Directory used for persisted share store state. |
| `developer_mode` | bool | false | Enables developer mode and switches state dir to a temp directory. |
| `server_id` | integer | `0` | Routing server id. Must be 0..35 (0..9, a..z). |
| `cluster_id` | string | `"default"` | Public topology cluster id. |
| `public_url` | string | derived from `bind_addr` | Public `/v1/share` base URL for this server. |

### Topology

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `topology_version` | integer | `1` | Public topology version. |
| `topology_server` | string | none | Add topology entry. `STATUS` is `active` (default), `standby`, `promoted`, or `disabled`. |
| `route` | string | none | Add owner routing rule. At least one primary server id is required. |
| `promoted_owner` | integer | none | Add promoted owner id. Can be repeated. |

### Replication

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `replication_token` | string | none | Shared replication token. |
| `replication_peer_url` | string | none | Allowed peer replication URLs. Can be repeated. |
| `origin_epoch` | integer | current epoch millis | Origin epoch for replication conflict resolution. |

### Benchmarking

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--requests N` | integer | `50000` | Number of requests for benchmark commands. Requires `--dev`. |
| `--payload-bytes N` | integer | `512` | Payload size for benchmarking. Requires `--dev`. |
| `--concurrency N` | integer | `0` | Concurrency for benchmarking. Requires `--dev`. |
| `--preload-shares N` | integer | `0` | Live shares to create before timing. Requires `--dev`. |

### Storage and limits

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `compact_min_bytes` | integer | `67108864` | Bytes in storage before background compaction runs. |
| `rate_limit_per_minute` | integer | `120` | Per-IP request limit. `0` disables rate limiting. |
| `rate_limit_burst` | integer | `40` | Per-IP rate limit burst capacity. |
| `verification_email_command` | path | none | Invoked as `<command> <email> <url>`. |
| `verification_email_rate_limit_per_hour` | integer | `5` | Per-email verification email rate limit (per hour). |
| `verification_email_ip_rate_limit_per_hour` | integer | `30` | Per-source-IP verification email rate limit (per hour). |

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
- Other options: pass `--config PATH` for server configuration. Direct
  config overrides require `--dev`.

## Notes

- Unrecognized options cause an error.
- Developer/test overrides cause an error unless `--dev` is present.
- `topology_server` and `route` can be provided multiple times in config files.
- `replication_peer_url` and `promoted_owner` can be provided multiple times.
- The parser is not using `clap`; flags are manually processed.
