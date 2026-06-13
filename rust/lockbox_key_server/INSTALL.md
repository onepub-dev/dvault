# Install the reVault key server

This package builds one system binary: `lockbox_key_server`.

Production operation of this binary requires a separate commercial license from
OnePub IP Pty Ltd. See `LICENSE`.

## 1) Build the binary

```bash
cd /home/bsutton/git/revault/rust
cargo build -p lockbox_key_server --release
```

## 2) Install as a system service

The release binary is configured as a systemd service named
`lockbox_key_server.service`.

```bash
sudo ./target/release/lockbox_key_server install
```

`--force-config` rewrites `/etc/lockbox/key-server.toml` only if you want a new
bootstrap config.

```bash
sudo ./target/release/lockbox_key_server install --force-config
```

## 3) Verify service status

```bash
sudo ./target/release/lockbox_key_server status
```

## 4) Start/stop service manually (if needed)

```bash
sudo systemctl start lockbox_key_server
sudo systemctl stop lockbox_key_server
sudo systemctl restart lockbox_key_server
sudo systemctl status lockbox_key_server
```

## 5) Remove service

```bash
sudo ./target/release/lockbox_key_server uninstall
```

Use `--purge-data` only if you also want to remove persisted state, cache,
and config:

```bash
sudo ./target/release/lockbox_key_server uninstall --purge-data
```

## Notes

- Default config path: `/etc/lockbox/key-server.toml`
- Default data paths:
  - `/var/lib/lockbox-key-server`
  - `/var/cache/lockbox-key-server`
  - `/var/log/lockbox-key-server`
