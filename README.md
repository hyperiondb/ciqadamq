# ciqadamq

Clustered MQTT broker built on [RMQTT](https://github.com/rmqtt/rmqtt) (embedded as a library) with a built-in REST API for user management. Designed as a drop-in replacement for the RabbitMQ MQTT setup.

Status: **in production**

## Features

- MQTT 3.1 / 3.1.1 / 5.0 over TCP (`1883`) and WebSocket (`8083`, path-agnostic, e.g. `ws://host:8083/mqtt`)
- 3-node clustering via the official `rmqtt-cluster-raft` plugin (subscription table replicated by raft, publishes forwarded only to nodes with matching subscribers)
- Username/password auth
- Per-user topic ACL mirroring the RabbitMQ permission regexes
- REST API to create/delete users (bearer token)
- Messages queued for offline persistent sessions expire after 20 minutes (configurable)
- No TLS — run behind HAProxy
- Configurable auth, message persistence

## Performance

**Local** PC data. Beware, it takes long time.

![CiqadaMQ performance](https://github.com/hyperiondb/ciqadamq/blob/main/perf-results.svg?raw=true)

![CiqadaMQ idle resource usage](https://github.com/hyperiondb/ciqadamq/blob/main/perf-resources.svg?raw=true)

![CiqadaMQ idle resource usage per 1k users](https://github.com/hyperiondb/ciqadamq/blob/main/perf-resources-peruser.svg?raw=true)

![CiqadaMQ resource usage, 10 msg/s QoS 1](https://github.com/hyperiondb/ciqadamq/blob/main/perf-resources-qos1.svg?raw=true)

![CiqadaMQ resource usage per 1k users, 10 msg/s QoS 1](https://github.com/hyperiondb/ciqadamq/blob/main/perf-resources-qos1-peruser.svg?raw=true)

![CiqadaMQ resource usage, 10 msg/s QoS 2](https://github.com/hyperiondb/ciqadamq/blob/main/perf-resources-qos2.svg?raw=true)

![CiqadaMQ resource usage per 1k users, 10 msg/s QoS 2](https://github.com/hyperiondb/ciqadamq/blob/main/perf-resources-qos2-peruser.svg?raw=true)

## Identity model (matches server-backend)

| Concept | Meaning |
|---|---|
| `username` | per-user MQTT login token (random, e.g. `getToken(24)` hex), created via REST API |
| `userid` | the application user id (Mongo ObjectId) — appears in topics |
| `clientid` | per-connection id chosen by the device |
| `superuser` | backend service account; bypasses all ACL |
| `admin` | may subscribe to `adminfanout/...` |

## Topics and ACL

Non-superuser clients may:

- subscribe to any topic whose **second** segment is their own `userid`: `chat/{userid}/m/all`, `update/{userid}/{device}/all`, `+/{userid}/#` …
- subscribe to `fanout/...` (everyone) and `adminfanout/...` (admins)
- publish only to `chatsync` and `updates` (configurable allowlist)

Superusers (the backend) may publish/subscribe anywhere. ACL decisions for publishing are cached per connection (`X-Cache: -1`).

Fanout works exactly like the RabbitMQ setup: one publish to `chat/{userid}/m/all` reaches every device of that user subscribed to it; `fanout/all` reaches everyone. Optionally `fanout.auto_subscribe = true` makes the broker subscribe every connecting client to `+/{userid}/#` plus the fanout topics server-side (leave off if clients subscribe themselves, or they will receive duplicates).

## REST API

`Authorization: Bearer <token>` (config `api.token` / env `API_TOKEN`). Any node of the cluster can serve these.

| Method | Path | Body |
|---|---|---|
| POST | `/api/v1/users` | `{"username", "userid", "password", "superuser"?: bool, "admin"?: bool}` → `201`/`409` |
| DELETE | `/api/v1/users/{username}` | → `204`/`404` |
| GET | `/api/v1/users` | → `{"users": [{username, userid, superuser, admin}]}` |
| GET | `/health` | no auth |

## Running

```
cargo run --release             # uses ./config.toml
```

3-node cluster

```
docker compose up -d --build
```

Node N is reachable at MQTT `188(2+N)`, WS `808(2+N)`, i.e. node1: 1883/8083/8090, node2: 1884/8084, node3: 1885/8085. Internal ports 5363 (gRPC forwarding) and 6003 (raft) stay on the compose network. Point HAProxy at the three MQTT/WS ports.

Note: building needs `protoc` (`apt install protobuf-compiler`, or `winget install Google.Protobuf` + `PROTOC` env var on Windows).

## Tests

```
cargo test                        # local single-broker e2e (auth, ACL, fanout, ws, expiry)
scripts\cluster-e2e.ps1           # compose up -> cross-node e2e -> compose down (KEEP_CLUSTER=1 to keep it)
```

## Performance tests

Note. 100% cpu = 1 core. 256 bytes payload.

```bash
docker compose up -d --build
cargo run --release --features perf --bin perf
```

Sweeps subscriber counts (`PERF_SUBS`, default `100,500,1000,2500,5000`), publishing `PERF_MSGS` (default 10000) messages round-robin to the users' `chat/{userid}/m/all` topics (`PERF_DEVICES_PER_USER` devices each, spread across all 3 nodes), and measures messages/sec delivered to end users plus p50/p95/p99 end-to-end latency. Writes `perf-results.svg` (chart) and `perf-results.csv`.

Resource usage as subscribers scale, measured idle and under per-subscriber publish load (64 bytes payload):

```bash
docker compose up -d --build
cargo run --release --features perf --bin perf-resources
```

Ramps connected-and-subscribed clients through `PERF_RES_SUBS` (default `0,1000,2500,5000,7500,10000`, spread across all 3 nodes), and at each level measures broker resource usage under three workloads over the same connections: idle (no publishing), each subscriber publishing `PERF_RES_MSG_RATE` (default 10) QoS 1 messages/sec to its own `chat/{userid}/m/all` topic, and the same at QoS 2 (`PERF_RES_PAYLOAD`-byte payloads, default 64). Each measurement waits `PERF_SETTLE_SECS` (default 10) and averages `PERF_SAMPLES` (default 3) `docker stats` readings of the broker containers (`PERF_SERVICES`, default `node1,node2,node3`). Provisioned users are superusers so each may publish to its own topic. Writes one chart per workload, each with the same per-node + total CPU % and memory MB layout vs subscriber count: `perf-resources.svg` (idle), `perf-resources-qos1.svg`, and `perf-resources-qos2.svg`, plus matching `.csv` files.

Flamegraph (needs elevated prompt):

```bash
.\flamegraph.ps1
```

## Configuration

See `config.toml` (single node) and `docker/cluster.toml` (cluster). Env overrides: `API_TOKEN`, `DB_URL`, `NODE_ID`, `RUST_LOG`.

Notes:

- message expiry applies to messages queued for offline persistent sessions (`clean_session=false`); sessions themselves persist 2h (rmqtt default)
- offline queues live in broker memory: they survive reconnects and migrate between nodes on session takeover, but not a node crash (add rmqtt-session/message-storage with Redis if that matters)
- retained messages are not enabled (cluster-wide retain requires the Redis retainer plugin)
