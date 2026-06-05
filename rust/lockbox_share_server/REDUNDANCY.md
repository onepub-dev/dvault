# Redundant Share Server Design

## Goals

The share service must start as a simple single-server deployment while keeping
the wire format and share codes compatible with a future redundant deployment.

The redundancy design must:

- keep standalone mode as the default
- avoid DNS round-robin sending fetches to the wrong server
- support more than two servers later
- provide a clear standby and recovery path
- avoid replication storms
- preserve single-use share semantics

## Phase 0: Single Server

The first production deployment runs one server:

```text
server_id: 0
url: https://keyshare.onepub.dev/v1/share
```

The server still generates self-routing share codes:

```text
0 123456789012
^ ^^^^^^^^^^^^
| random code body
server routing digit
```

The first digit is the server id. The remaining digits are the random
rendezvous code body. With the default body length of 12 digits, the displayed
code is 13 decimal digits.

Using the routing digit from day one means existing pending shares remain
compatible when extra servers are added later.

## Server Ids

Server ids are decimal digits from `0` to `9`.

This intentionally limits the first routing design to ten public owner slots.
That is enough for the first deployment and keeps manually entered codes
decimal-only. If we need more owner slots later, we can add a new code format
version rather than overloading existing codes.

The server id is stable operational configuration, not a random instance id.
A replacement machine for server `3` must run with `server_id = 3` when it is
serving shares owned by that id.

## Client Routing

Users should not have to configure failover pairs. Failover topology belongs on
the servers.

For an organization running its own share service, clients should be configured
with a discovery base URL or topology URL:

```yaml
share_topology_url: https://share.example.com/v1/topology
```

The topology endpoint returns public routing metadata as a binary document:

```text
TopologyDocument {
  magic: "LBST"
  version: u16
  cluster_id: utf8_string
  topology_version: u64
  server_count: u16
  servers: TopologyServer[server_count]
  route_count: u16
  routes: TopologyRoute[route_count]
}

TopologyServer {
  id: u8
  status: u8
  url: utf8_string
}

TopologyRoute {
  owner_id: u8
  primary_id: u8
  failover_count: u16
  failover_ids: u8[failover_count]
}
```

The server operator configures this topology on the share servers:

```yaml
share_servers:
  - id: 0
    url: https://keyshare0.onepub.dev/v1/share
  - id: 1
    url: https://keyshare1.onepub.dev/v1/share
  - id: 2
    url: https://keyshare2.onepub.dev/v1/share
```

For `SHARE`, the CLI may choose a configured server randomly or by health. The
selected server generates a code prefixed with its own id.

For `FETCH` and `DELETE`, the CLI reads the first digit and sends the request
to the primary endpoint for that owner id first. It then tries the failover
list from topology. If the topology is missing or stale, the client may try
every endpoint in the same discovered cluster.

Trying every server is acceptable as a fallback within one trusted cluster. It
must not spray share codes across unrelated public services.

DNS may still be used for normal host resolution and coarse failover, but DNS
round-robin is not the primary routing mechanism. Without self-routing codes or
replicated state, DNS round-robin can randomly send fetches to a server that
does not own the share.

## Standby Replication

The first redundancy step after standalone mode is paired or ring standby
replication.

Two servers:

```text
0 -> 1
1 -> 0
```

Three servers:

```text
0 -> 1
1 -> 2
2 -> 0
```

Each server is authoritative for its own prefixed codes. It streams state
events to its standby peer. The standby stores those events as replica state for
the original owner id.

The standby does not normally serve replicated shares. It serves them only when
it is explicitly promoted for that owner id.

## Replication Events

Replication must be based on append-log events, not on replaying client HTTP
requests.

The required event types are:

```text
put_share
fetch_count
consume_share
delete_share
expire_share
```

The replication envelope must include:

```text
origin_server_id
origin_epoch
origin_sequence
event_type
event_body
message_authentication
```

The idempotency key is:

```text
(origin_server_id, origin_epoch, origin_sequence)
```

Each standby tracks the last applied sequence per origin. Replayed or duplicate
events are ignored.

## No Replication Storms

Client and replication traffic must be separate operations:

```text
POST /v1/share
POST /v1/replicate
```

Rules:

- client-originated share events are appended locally and queued for replication
- peer-originated replication events are applied idempotently
- replicated events are not re-replicated by default
- chain replication is out of scope for the first redundant version

This prevents a two-server pair from bouncing the same event forever and
prevents a ring from amplifying each share into a storm.

The current implementation sends `put_share`, `fetch_count`, and `delete`
tombstone events to configured peers. The standby applies peer events through
`/v1/replicate` and does not enqueue those peer events for replication again.
Expired shares are still rejected by timestamp when a standby is promoted, but
active expiry purge events are not yet replicated as first-class events.

## Failover

Only one server may be authoritative for a server id at a time.

If server `2` fails:

1. Its standby is promoted for owner id `2`.
2. The topology endpoint maps owner id `2` to the promoted standby.
3. The old server `2`, if it returns, starts non-authoritative.
4. The old server resyncs from the promoted node before serving owner id `2`.

Automatic dual-serving is not allowed in the first redundant design because it
can duplicate single-use fetches during partial network failures.

## Recovery

A promoted standby must persist:

- the replicated share records
- consumed/deleted tombstones
- the origin epoch and sequence position

When an old primary returns, recovery is a controlled operator action:

```text
stop old primary serving owner id N
copy or stream missing events from promoted standby
verify sequence continuity
switch authority back only after sync is complete
```

If sequence continuity cannot be proven, the safe recovery path is to keep the
promoted standby authoritative until all pending shares for that owner id have
expired.

## Why Not Hot/Hot First

Hot/hot serving is harder because `FETCH` mutates state. A single-use share must
not be returned by two servers during a race.

A future hot/hot design should use deterministic ownership:

```text
owner = first share-code digit
```

Any server may accept the HTTP connection, but mutating operations for owner
`N` must be executed by the authoritative node for `N` or by a promoted standby
for `N`.

Until that routing/proxy layer exists, standby replication plus explicit
promotion is the safer design.

## Implementation Status

Implemented:

- server id configuration, defaulting to `0`
- generated share codes include the server id prefix
- default random body length remains 12 digits
- client pool support can prefer the server encoded in the first digit
- public topology model and binary codec
- `GET /v1/topology`
- server CLI topology flags
- client pool construction from discovered topology
- client-side binary topology cache helpers
- share client pool selection across configured/discovered servers
- `/v1/replicate`
- signed peer replication using a configured shared secret
- local origin epoch and monotonically increasing origin sequence numbers
- standby idempotency tracking persisted across restarts
- promotion gating through configured promoted owner ids
- replication storm avoidance by separating client and peer operations
- self-installing systemd service support with boot enablement
- CLI YAML topology URL/default public service config
- vault CLI publish/receive/delete wiring through `ShareClientPool`
- durable outbound replication outbox with retry
- expiry/exhaustion tombstones queued for replication
- binary `/v1/status` replication lag/status reporting
- `resync-peer` operator tooling for live-share replay to a peer
- signed replication envelopes
- TLS-capable client transport for the public default service

Remaining work:

- durable per-peer acknowledgements when more than one replication peer is
  configured
- full old-primary handback workflow around `resync-peer`
- mTLS support for peer authentication in addition to signed envelopes
- end-to-end operator tests for failover promotion and recovery flows
