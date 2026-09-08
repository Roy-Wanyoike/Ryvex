# ryvex-agent

The **Ryvex data-plane node agent** — a small Tokio binary that makes a
machine a first-class citizen of the Ryvex control plane. It enrolls
its `Node` resource on start, heartbeats on a fixed interval with
CAS-safe upserts, self-heals when its resource vanishes, and marks
itself `draining` on SIGINT/SIGTERM.

## Quickstart

```bash
# 1. Control plane (any ryvexd)
ryvexd serve --http :8080 --dev-auth --seed

# 2. Build the agent
cargo build --release

# 3. Enroll this machine
./target/release/ryvex-agent \
  --api http://127.0.0.1:8080 \
  --token ryk_local_dev \
  --name smoke-node --cluster prod-eu1

# 4. Watch it appear and converge
curl -s localhost:8080/v1/acme/core/prod/nodes/smoke-node \
  -H "Authorization: Bearer ryk_local_dev"
```

## Configuration

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--api` | `RYVEX_AGENT_API` | `http://127.0.0.1:8080` | Control plane base URL |
| `--token` | `RYVEX_AGENT_TOKEN` | — (required) | Bearer API key (`ryk_…`) |
| `--interval` | `RYVEX_AGENT_INTERVAL` | `10` | Heartbeat seconds (clamped ≥ 5) |
| `--spec-refresh-secs` | `RYVEX_AGENT_SPEC_REFRESH_SECS` | `300` | Min seconds between `spec.last_seen` refreshes (heartbeat spec-throttle) |
| `--name` | `RYVEX_AGENT_NAME` | hostname | Node resource name; a `localhost` fallback is refused |
| `--cluster` | `RYVEX_AGENT_CLUSTER` | `unassigned` | Cluster label + spec |
| `--org` | `RYVEX_AGENT_ORG` | `acme` | Scope: org |
| `--project` | `RYVEX_AGENT_PROJECT` | `core` | Scope: project |
| `--env` | `RYVEX_AGENT_ENV` | `prod` | Scope: env |

Logs honor `RUST_LOG` (default `info`; use `debug` for per-heartbeat lines).

## Behavior

- **Enroll**: `GET /healthz` (log version + fleet size), then a CAS-safe
  `PUT /v1/{org}/{project}/{env}/nodes/{name}` upsert — creates on
  404, updates with the observed `generation` otherwise, retries a
  bounded 3 attempts on `409 conflict` with the fresh generation; if
  contention persists it backs off and retries next tick instead of
  crashing.
- **Heartbeat**: every tick the agent PUTs its node document, but
  `spec.last_seen` (RFC3339 UTC) is refreshed at most once per
  `--spec-refresh-secs` (default 300s). Between refreshes the previous
  timestamp is re-sent, so the document is identical to the stored one
  and the control plane answers `200` **without advancing the
  generation or emitting an `updated` event** (see
  `internal/api/handlers.go` → `state.Store.UpdateResource`). Before
  the throttle, every tick bumped the generation — an event storm that
  flooded the replay ring, filled audit, and CAS-lose human edits. A
  dedicated server-side `POST /heartbeat` liveness endpoint (so agents
  need no PUT at all between spec refreshes) is future work — see
  Roadmap.
- **Node naming**: the effective name comes from `--name` /
  `RYVEX_AGENT_NAME`, else the `HOSTNAME` env var, else the kernel
  hostname (`/proc/sys/kernel/hostname`, no libc dependency). A
  `localhost` result is refused at startup rather than colliding
  fleet-wide, and the effective name is logged on start. Names are
  percent-encoded into the scope path, so spaces and non-ASCII are
  safe.
- **Self-heal**: node deleted out from under a running agent? The next
  tick re-creates it.
- **Resilience**: transport errors and 5xx back off exponentially
  (1s → 2s → 4s … capped at 30s, symmetric ±20% jitter) and recover
  without restarts.
- **Shutdown**: SIGINT/SIGTERM writes one best-effort
  `status_message: "draining"` and exits 0.

## Verification

```bash
cargo build --release
cargo test        # unit + golden-contract tests
cargo clippy -- -D warnings
```

Live E2E (run in CI-adjacent scripts, all verified):

1. Agent enrolls against `ryvexd --seed` → node visible at its scope path
2. Generation advances per heartbeat; node count stays at one
3. `DELETE` the node mid-run → agent re-creates it within one tick
4. SIGTERM → `status_message: "draining"` observable via the API

## Roadmap

- Drift detection: compare declared spec vs live machine state
- Exec hooks: reconcile decisions executed as local actions
- mTLS + scoped RBAC keys minted at enrollment
- Server-side `POST /heartbeat` liveness endpoint: agents report
  liveness without PUTting spec at all (completes the spec-throttle
  design; the agent side is already throttled)
- Streaming heartbeats over webhooks/events for sub-second liveness
