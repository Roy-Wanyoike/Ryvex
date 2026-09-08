# Ryvex Architecture

> Ryvex is the programmable operating system for infrastructure: a cloud
> control plane where every piece of infrastructure is declarative state,
> continuously converged by a reconciler, and observable in real time.

## System overview

```
                        ┌───────────────────────────────┐
                        │            ryvexd             │
   ┌────────────┐       │  ┌─────────────────────────┐  │
   │  ryvex CLI │──────▶│  │       REST API /v1      │  │
   └────────────┘       │  │  auth · errors · CORS   │  │
   ┌────────────┐       │  └───────────┬─────────────┘  │
   │   Web      │──────▶│              │                │
   │  Console   │ CORS  │  ┌───────────▼─────────────┐  │
   └────────────┘       │  │        State Store      │  │
                        │  │  resources · audit log  │  │
   ┌────────────┐       │  └───────────┬─────────────┘  │
   │  SDKs &    │──────▶│              │                │
   │  Automation│       │  ┌───────────▼─────────────┐  │
   └────────────┘       │  │       Event Bus         │  │
                        │  │ ryvex.resource.*        │  │
                        │  └───────────┬─────────────┘  │
                        │  ┌───────────▼─────────────┐  │
                        │  │       Reconciler        │  │
                        │  │ Pending→Provisioning→   │  │
                        │  │ Ready, per generation   │  │
                        │  └─────────────────────────┘  │
                        └───────────────────────────────┘
```

`ryvexd` is a single Go binary that hosts all four control-plane
components. Everything is in-process for the reference deployment; the
interfaces (`state.Backend`, `bus.BusI`) are contracts, so durable backends
(Postgres, NATS) can replace the in-memory implementations without
touching the API or the reconciler.

## Core loop: declare → converge → observe

1. **Declare.** Clients (CLI, console, SDK, CI) POST/PUT a *resource* —
   a JSON document with an identity (`org/project/env/kind/name`), a
   `spec` written by the user, and a `status` owned by the system.
2. **Persist.** The store validates the document, assigns an opaque ID
   and a monotonically increasing `generation`, records the mutation in
   the append-only audit log, and publishes an event.
3. **Converge.** The reconciler scans for resources whose
   `status.observed_generation` lags their `generation` (or whose phase
   is Pending/Provisioning) and drives them toward the declared spec,
   stamping observed state as it goes.
4. **Observe.** Every mutation and transition is a typed event on the
   bus (`ryvex.resource.{org}.{kind}.{event}`) — the console, webhooks
   and the node agent subscribe to exactly the slice they care about.

## Components

### State store (`internal/state`)

- **Model.** 13 kinds: Project, Environment, Application, Deployment,
  Cluster, Node, Database, Cache, Bucket, Policy, Secret,
  Subscription (webhook subscriptions) and APIKey (managed keys).
- **Identity.** Logical address `org/project/env/kind/name` (unique) +
  opaque ID `r-<hex>` (stable handle). Managed API keys live in the
  reserved namespace `ryvex/system/system`, which is unreachable for
  every other kind.
- **Concurrency.** Mutex-guarded (in-memory) or SQL-backed (Postgres);
  updates take an optional `ExpectedGeneration` for compare-and-swap —
  stale writers get `409`.
- **Governance.** Every create/update/delete/status-change lands in the
  audit log with actor + reason.
- **Backends.** In-memory by default; `--store postgres` swaps in the
  durable backend (see [Durable state](#durable-state-postgres)) with
  parity-tested semantics — both pass the same state suite.

### Event bus (`internal/bus`)

- NATS-style subjects with `*` (one segment) and `>` (tail) wildcards.
- Synchronous fan-out with subscriber panic isolation.
- 1024-event replay ring (in-memory) powering `GET /v1/{org}/events`;
  the JetStream backend replays from the stream and adds the
  `?from=` sequence cursor (see below).

### Reconciler (`internal/reconcile`)

- Fixed-interval scan + out-of-band `Trigger(id)` (used by
  `POST /v1/{org}/reconcile/{id}`).
- Bounded worker pool (configurable concurrency).
- Reference policy converges `Pending → Provisioning → Ready` and
  stamps `observed_generation`; the `evaluate` hook is the seam where
  real controllers plug in.

### REST API (`internal/api`)

- stdlib-only HTTP stack: request-ID → recover → security headers →
  logging → CORS → auth → routes. Auth is bearer-only, or org/project-
  scoped RBAC when the authorizer is enabled (the `serve` default).
- Manual `/v1` dispatcher because the path space
  (`/v1/resources/{id}` vs `/v1/{org}/events`) is ambiguous to pattern
  routers.
- Hardening: conservative response headers (`X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` on
  `/v1`), production server timeouts (30s read / 10s read-header /
  60s write / 120s idle, 1 MiB header cap) and a 1 MiB JSON body cap
  that answers `413 payload_too_large` instead of a misleading `400`.
- Frozen error envelope and status mapping (see
  [api-contracts.md](./api-contracts.md)).

### Daemon (`cmd/ryvexd`)

```
ryvexd serve --http :8080 --dev-auth --seed --cors-origins http://localhost:3100
```

| Flag | Env | Meaning |
|------|-----|---------|
| `--http` | `RYVEX_HTTP_ADDR` | Listen address (`:8080`) |
| `--store` | | State backend: `memory` (default) or `postgres` (needs `--dsn`) |
| `--dsn` | `RYVEX_DATABASE_URL` | Postgres DSN when `--store postgres` |
| `--bus` | | Event bus backend: `memory` (default) or `nats` (see below) |
| `--nats-url` | `RYVEX_NATS_URL` | NATS URL when `--bus nats` |
| `--dev-auth` | | Accept any well-formed `ryk_` token (dev only; see guard below) |
| `--api-keys` | `RYVEX_API_KEYS` | Static keys `name=token,…` (bootstrapped as admin keys) |
| `--cors-origins` | `RYVEX_CORS_ORIGINS` | Browser origins allowed cross-origin |
| `--webhook-secret` | `RYVEX_WEBHOOK_SECRET` | HMAC key for webhook signatures (random per boot when unset) |
| `--metrics-addr` | `RYVEX_METRICS_ADDR` | Dedicated `/metrics` sidecar address (empty disables) |
| `--seed` | | Load the 15-resource demo dataset |
| `--log-level` | | `debug` … `error` |

Graceful shutdown: SIGINT/SIGTERM stops the listener, drains the HTTP
server (and the metrics sidecar), cancels the reconciler and webhook
dispatcher, and waits for workers.

Boot guard: `--dev-auth` combined with a durable backend (`--store
postgres` or `--bus nats`) is refused at boot — any well-formed `ryk_`
token would get full admin over durable state. Set
`RYVEX_ALLOW_DEV_AUTH=1` to override deliberately; a non-loopback
`--http` address under dev-auth logs a loud warning either way.

Webhook egress guard: `Subscription` webhook targets on loopback,
link-local, RFC1918/ULA, CGNAT, multicast or unresolvable hosts are
refused at spec validation *and* re-checked at dispatch time (DNS
rebinding defense); redirects are never followed. On-prem deployments
that genuinely deliver internally can opt out with
`RYVEX_ALLOW_PRIVATE_WEBHOOKS=1`.

## Web console (`console/`)

Next.js 15 + React 19 + Tailwind 4. A read **and write** client of the
REST API: the resource drawer edits specs and labels with CAS-aware
saves (a stale `generation` comes back as `409` with an inline
reload), and resources can be deleted. Reads refresh on a 15s loop
and carry truthful health: in live mode a failed fetch is shown as
`degraded` (last good snapshot) or `error` — it never masquerades as
demo data. With no daemon configured the console renders an embedded
demo snapshot so the UI is always presentable. Views: Overview,
Resources, Topology, Events, Audit, plus a Settings view for
API/token/scope configuration.

## Design principles

1. **Declarative first.** Users state intent (`spec`); the system owns
   reality (`status`).
2. **Everything is audited.** If state changed, you can answer who,
   what, when, and why.
3. **Events are the product.** The bus subjects form a public contract
   that any tool can subscribe to.
4. **Boring, explicit infrastructure.** stdlib HTTP, no magic, clean
   seams for durable backends.
5. **Frozen wire contracts.** Error envelope, status codes and subjects
   are versioned and never broken casually.

## Durable events (NATS JetStream)

The event bus is swappable. `internal/bus` defines the contract and the
in-memory implementation (ring replay, 1024 events); `internal/bus/natsbus`
implements the same `bus.BusI` surface on NATS JetStream so the event log
survives daemon restarts (issue #15). Both backends pass the same parity
suite (`internal/bus/bustest`) — subject grammar, wildcards, cancel, panic
containment and `Recent` semantics are identical.

```
ryvexd serve --bus nats --nats-url nats://127.0.0.1:4222
RYVEX_NATS_URL=nats://127.0.0.1:4222 ryvexd serve --bus nats ...
```

| Flag | Env | Meaning |
|------|-----|---------|
| `--bus` | | Event bus backend: `memory` (default) or `nats` |
| `--nats-url` | `RYVEX_NATS_URL` | NATS server URL when `--bus=nats` (default `nats://127.0.0.1:4222`) |

How it works:

- **Stream.** A JetStream stream `RYVEX` captures `ryvex.resource.>` with a
  24h max-age retention (file storage by default, so events also survive a
  nats-server restart). The stream is created on boot if missing; an existing
  stream is reused untouched. Subject grammar is shared 1:1 with the memory
  bus (`*` = one segment, trailing `>` = tail).
- **Publish.** Events are JSON-marshalled onto their canonical subject; the
  publish is acknowledged by the server before `Publish` returns
  (at-least-once). Failures are logged, never fatal to the request path.
- **Subscribe.** Live deliveries ride core NATS subscriptions (no replay on
  subscribe, matching memory-bus semantics). Handler panics are contained and
  `Cancel()` stops delivery immediately.
- **Recent / RecentFrom.** `Recent(org, limit)` replays the newest events from
  the stream (server-side filtered per org, newest first, scans capped at 5000
  messages for safety). `RecentFrom(org, limit, from)` is the sequence-cursor
  replay exposed on `GET /v1/{org}/events?from=<seq>`: it returns events after
  `from` together with `last_seq` so callers can resume without gaps or
  duplicates. The in-memory bus does not implement the cursor (the `from`
  parameter is simply ignored there); `last_seq` appears in the response only
  on the JetStream backend.

Boot semantics: with `--bus nats` a failed connection is a fatal boot error —
the daemon refuses to silently degrade to the in-memory bus. The memory bus
is used when `--bus` is unset (or `--bus memory`).

## Durable state (Postgres)

The state store is swappable in the same spirit. `internal/state` defines
the backend contract and the in-memory implementation; `internal/state/pgstore`
implements the same surface on Postgres so resources, generations and the
audit log survive daemon restarts (issue #14). Both backends run the same
behavioral suite (`internal/state/statetest`) — validation, CAS semantics,
pagination cursors and audit behavior are identical.

```
ryvexd serve --store postgres --dsn postgres://postgres:postgres@127.0.0.1:5432/ryvex?sslmode=disable
RYVEX_DATABASE_URL=postgres://… ryvexd serve --store postgres ...
```

| Flag | Env | Meaning |
|------|-----|---------|
| `--store` | | State backend: `memory` (default) or `postgres` |
| `--dsn` | `RYVEX_DATABASE_URL` | Postgres DSN; **required** when `--store postgres` |

For local development, `docker-compose.yml` starts a Postgres 16 container
with matching credentials:

```
docker compose up -d
ryvexd serve --store postgres \
    --dsn postgres://postgres:postgres@127.0.0.1:5432/ryvex?sslmode=disable
```

How it works:

- **Boot.** `--store postgres` without a DSN is a boot error
  (`--dsn` / `RYVEX_DATABASE_URL` must be set). A failed connection is fatal —
  there is never a silent fallback to the in-memory store, mirroring the NATS
  bus boot semantics. Note the guard: `--dev-auth` plus `--store postgres` is
  refused unless `RYVEX_ALLOW_DEV_AUTH=1` (see the boot guard above).
- **Migrations.** The schema ships inside the binary as embedded SQL
  (`go:embed` of `internal/state/pgstore/migrations/*.sql`). On boot the
  daemon brings the database up to date: each migration runs exactly once,
  inside a transaction that also records its version in `schema_migrations`.
  Migration is idempotent — safe to run on every boot — and bounded by a
  30-second timeout; a failure aborts boot. Migrations are append-only:
  applied steps are never edited, new steps are added as new files.
- **Persistence.** Resources (including `generation` counters), audit entries
  and managed API keys live in Postgres, so a restarted daemon resumes with
  the exact state it had — including CAS generations that in-flight writers
  depend on.
- **Parity testing.** The pgstore suite runs the shared behavioral suite
  against a live database when `RYVEX_TEST_PG_DSN` is provided
  (`RYVEX_TEST_PG_DSN=… go test ./internal/state/...`).
