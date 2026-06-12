# Lockbox Session Agent

The Lockbox session agent caches unlocked lockbox content keys in-memory for the
duration of an interactive session. It is a local, per-user process that avoids
re-prompting for passphrases while reducing exposure of decrypted keys on disk.

Product name: **Lockbox Session Agent**.

## What it does

- Stores temporary cache entries for lockbox content keys.
- Returns cached keys to subsequent commands.
- Evicts entries automatically by TTL or on inactivity.
- Clears all cached entries when the machine is suspending.
- Provides diagnostics for running sessions and explicit lock operations.

## Design

The feature is implemented in `lockbox_vault`:

- `lockbox_vault::get` / `put` / `forget` / `forget_all` / `list` / `stop`
  call into a platform client module.
- Client calls are made through local IPC transport:
  - Unix: Unix-domain socket.
  - Windows: named pipe.
- The agent process can run in-process (same binary) when started with
  `__agent`.
- CLI startup code dispatches `__agent` and `__agent_security_check` internally
  before normal subcommand parsing.

## Transport + protocol

Requests share a compact binary frame with:

- Header: 9 bytes (`LBX2` magic + message type + u32 payload length LE).
- Maximum message size: 128 KiB.

### Cache operations

Cache messages:

- `get` → `cache-miss` / `cache-key` / protocol errors.
- `put` → store a key with optional path and TTL.
- `forget` / `forget-all` → remove one or all cached entries.
- `stop` → clear all cached entries and terminate agent.
- `list` → list cached lockboxes for diagnostics.

The key payload stores:

- lockbox id
- key length + key bytes
- optional path string for diagnostics
- TTL in seconds

TTL defaults to 15 minutes when omitted. A `get` hit extends the expiry time
(sliding TTL).

### Control path (sleep behavior)

The same transport also supports control messages to track command activity:

- register secret activity (`pid`, `kind`) and returns a token
- unregister activity (`pid`, `token`)

`SecretActivityKind` values currently include:

- `unlock`
- `open`
- `env`
- `form`
- `recovery`
- `vault`

The control path is used by high-level commands that perform secret
operations to keep the machine awake for sensitive work and optionally terminate
those processes if suspend is requested.

## Lifecycle

- On first cache operation, client code ensures an agent is running.
- If absent, the client starts the current binary with `__agent` and waits briefly
  for the endpoint to become available.
- Server loop runs until:
  - an explicit `stop` request arrives, or
  - 10 minutes of inactivity are observed with no cached secrets and no active
    secret operations.

## TTL and inactivity behavior

- Default TTL: 15 minutes.
- TTL is validated as positive.
- Inactive cache entries are pruned on accept loop and when servicing requests.
- Cache-hit extends expiry by another TTL period.
- `lockbox vault sessions lock-all` clears all cached entries from the CLI side.
- `lockbox vault sessions lock <lockbox>` clears one path from the CLI side.

## Platform notes

- Unix
  - Socket directory defaults to:
    - `LOCKBOX_SESSION_AGENT_DIR` (if set), else
    - `${XDG_RUNTIME_DIR}/lockbox`, else
    - a temporary per-user fallback in `std::env::temp_dir()`.
  - Socket is created as `agent.sock`.
  - Parent directory permissions are set to `0700`.
- Windows
  - Named pipe is `\\.\pipe\lockbox-agent-<scope>`.
  - Scope includes user and, when `LOCKBOX_SESSION_AGENT_DIR` is set, a hash of
    that value to avoid cross-profile collisions.
  - Pipe ACL is owner-only.

## Sleep and security behavior

Configuration (defaults are true):

- `agent.prevent_sleep` / `agent.suspend_inhibit` (config file)
- `agent.terminate_on_suspend` (config file)
- `LOCKBOX_AGENT_PREVENT_SLEEP` (environment override)
- `LOCKBOX_AGENT_TERMINATE_ON_SUSPEND` (environment override)

Configuration source order:

- `LOCKBOX_AGENT_CONFIG` if set.
- else `LOCKBOX_CONFIG`.
- else platform default:
  - macOS: `~/Library/Application Support/reVault/config.toml`
  - Windows: `%APPDATA%\reVault\config.toml` or `%LOCALAPPDATA%`
  - Linux/Unix: `$XDG_CONFIG_HOME/lockbox/config.toml` or `~/.config/lockbox/config.toml`

Behavior:

- If prevent-sleep is enabled and there is at least one active secret activity,
  the agent acquires a platform-specific sleep inhibitor.
- On suspend request, cached keys are always cleared.
- If terminate-on-suspend is enabled, registered active secret processes are
  terminated; otherwise they are kept in memory but no longer protected by a sleep
  inhibitor.

## Logging

`LOCKBOX_SESSION_AGENT_LOG` can point to a file path for explicit agent logging.
Without it, platform logging is used with a file fallback:

- Unix: platform logs (syslog) with fallback under local state cache.
- Windows: Event Log source `reVault Agent`.

## CLI surface

The user-facing session controls live under `lockbox vault sessions`:

- `lockbox vault sessions` — list currently unlocked sessions.
- `lockbox vault sessions lock <lockbox>` — lock one lockbox.
- `lockbox vault sessions lock-all` — lock everything.
- `lockbox vault sessions stop` — stop the agent process.

Session-related metadata is also exposed under `lockbox vault sessions auto-unlock`
for password-helper integration (`status`, `enable`, `disable`, `forget`).

`lockbox doctor` includes session-agent diagnostics and can help when auto-unlock
or transport behavior looks wrong.

## Security notes

- Secrets are stored in-memory in process memory and never intentionally written
  to disk by the agent cache.
- The transport is local-only and process-user scoped (`agent` process identity
  checks are used on Windows).
- Control requests are plain binary frames; cache requests use secure frame
  encoding to reduce secret lifetime in transit.
- The protocol intentionally returns explicit errors for malformed frames, invalid
  message sizes, and unsupported message types.

## Naming

Primary name: **Lockbox Session Agent**

Alternative names:

- Lockbox Key Relay
- Lockbox Session Guard
- reVault Cache Sentinel
- unlock Cache Sentinel
