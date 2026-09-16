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
   ┌────────────┐       │  │ ryvex.resource.*        │  │
   │ Node agent │──────▶│  └───────────┬─────────────┘  │
   │  GET/PUT   │       │  ┌───────────▼─────────────┐  │
   └────────────┘       │  │       Reconciler        │  │
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
   bus (`ryvex.resource.{org}.{kind}.{event}`). Webhook subscriptions
   subscribe to exactly the slice they care about; the console and CLI
   poll the replay API (`GET /v1/{org}/events`) instead. The Rust node
   agent never subscribes — it talks plain GET/PUT to the REST API
   (fetch its node document, upsert enrollment/heartbeat state).

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
  `?from=` sequence cursor (see [Durable events](#durable-events-nats-jetstream))
  plus durable consumers and a dead-letter queue (below).

### Reconciler (`internal/reconcile`)

- Fixed-interval scan + out-of-band `Trigger(id)` (used by
  `POST /v1/{org}/reconcile/{id}`).
- Bounded worker pool (configurable concurrency).
- Status-only kinds (no actuator) converge `Pending → Provisioning →
  Ready` and stamp `observed_generation`; the `evaluate` hook is the
  seam where real controllers plug in. This is the exact flow every
  kind had before the provider SPI — it is unchanged for kinds without
  an actuator.
- **Provider SPI (issue #80, [ADR-0002](adr/0002-provider-spi.md)).**
  `internal/provider` defines the actuator contract — one `Actuator`
  per kind (`Kind`, pure `Plan`, idempotent `Apply`, `Inspect`,
  `Capabilities`), an optional `FieldMapper` capability behind drift
  detection, and a three-class error taxonomy (`Transient` /
  `Permanent` / `Unavailable`, mirroring the node agent's `Outcome`
  classes). Actuators live in a per-daemon registry; the reconciler
  keeps every piece of control-plane policy: phases, retry/backoff,
  drift comparison, audit, events, metrics. The reference provider is
  a stdlib Docker Engine actuator behind the `docker` build tag
  (`internal/provider/docker`), enabled with `--enable-docker-actuator`
  (a binary built without the tag degrades honestly: loud warning,
  status-only convergence; a dead engine on a tagged binary refuses
  boot, same posture as `--bus nats`).
- **Retry/backoff (issue #80).** Classified-Transient/Unavailable
  failures retry per kind (`RetryPolicy`: default 4 attempts, 1s base,
  ×2 growth, 30s cap, per resource per generation episode, in-memory).
  The resource sits **Degraded** between attempts and lands **Failed**
  when the budget is exhausted (or immediately on a Permanent
  failure); both phases are reachable and audited. `Failed` is
  terminal for the current generation — a new spec re-opens
  convergence.
- **Drift detection (issue #80).** A dedicated pass (default every
  60s, `--drift-interval`) inspects `Ready` resources of drift-capable
  actuated kinds and compares desired spec fields against observed
  external state. Drift never mutates anything directly: the resource
  is annotated (`Drifted: …`, phase stays `Ready`), audited
  (`drift_detected`), published on the bus with the drifted field
  list, counted in `ryvex_reconciler_drifts_total` — and corrected by
  re-running the same Plan→Apply path as ordinary convergence.

### REST API (`internal/api`)

- stdlib-only HTTP stack: request-ID → recover → security headers →
  logging → CORS → auth → routes. Auth is bearer-only, or org/project-
  scoped RBAC when the authorizer is enabled (the `serve` default).
- Manual `/v1` dispatcher because the path space
  (`/v1/resources/{id}` vs `/v1/{org}/events`) is ambiguous to pattern
  routers.
- Probes (issue #71): `/healthz` reports liveness with an honest body
  (`"status": "degraded"` + per-dependency states when the store or
  bus is down, still HTTP 200) and `/readyz` answers 503 until both
  dependencies answer a real query — a dead-Postgres pod leaves the
  Service rotation instead of serving errors. Contract details in
  [api-contracts.md](./api-contracts.md).
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
| `--audit-cap` | `RYVEX_AUDIT_CAP` | Max audit entries kept by the **memory** backend, oldest evicted first (default 10000; ignored with `--store postgres`, issue #85) |
| `--metrics-addr` | `RYVEX_METRICS_ADDR` | Dedicated `/metrics` sidecar address (empty disables) |
| `--otlp-endpoint` | `RYVEX_OTLP_ENDPOINT` | OTLP/HTTP trace export endpoint `host:port` (e.g. `localhost:4318`); **empty disables tracing** (issue #83). An `http://` prefix forces plain HTTP |
| `--otlp-insecure` | `RYVEX_OTLP_INSECURE` | Export traces without TLS (also implied by an `http://` endpoint) |
| `--tracing-sample-ratio` | `RYVEX_TRACING_SAMPLE_RATIO` | Parent-based trace sample ratio when tracing is enabled (default 1.0, issue #83) |
| `--enable-docker-actuator` | | Actuate Application resources against a Docker Engine (needs a binary built with `-tags docker`, issue #80) |
| `--docker-socket` | `RYVEX_DOCKER_SOCKET` | Docker Engine unix socket when `--enable-docker-actuator` is set |
| `--drift-interval` | | Cadence of the drift-detection pass for actuated kinds (default 60s, issue #80) |
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
  (at-least-once). Failures are logged, never fatal to the request path —
  and since issue #81 they are not silent either: every failed publish
  increments `ryvex_bus_publish_failures_total`, and callers that must
  observe the outcome use `PublishErr` (same bus, error returned after the
  count).
- **Subscribe.** Live deliveries ride core NATS subscriptions (no replay on
  subscribe, matching memory-bus semantics). Handler panics are contained and
  `Cancel()` stops delivery immediately.
- **Durable consumers (issue #81).** `SubscribeDurable(name,
  pattern, handler)` attaches a named, restart-idempotent JetStream pull
  consumer: at-least-once delivery with explicit acks, redelivery of
  failed handlers (the handler returns `bus.ErrEventRetry`, `nil`, or
  `bus.ErrEventPoison`) bounded by the consumer's `MaxDeliver` (default 5
  deliveries, `AckWait` 30s), and consumer-config drift reconciled on
  subscribe. A consumer created for the first time starts at the stream
  tail, so the first boot does not flood receivers with old events; from
  then on the consumer's own cursor provides resume-after-restart
  redelivery. Rolling deploys are safe — multiple fetchers on one durable
  name split the work. The webhook dispatcher runs as the durable
  consumer `RYVEX_DISPATCHER`, so webhook events published while the
  daemon was down are delivered when it comes back; buses without the
  capability (in-memory) fall back to plain best-effort `Subscribe`.
- **Recent / RecentFrom.** `Recent(org, limit)` replays the newest events from
  the stream (server-side filtered per org, newest first, scans capped at 5000
  messages for safety). `RecentFrom(org, limit, from)` is the sequence-cursor
  replay exposed on `GET /v1/{org}/events?from=<seq>`: it returns events after
  `from` together with `last_seq` so callers can resume without gaps or
  duplicates. The in-memory bus does not implement the cursor (the `from`
  parameter is simply ignored there); `last_seq` appears in the response only
  on the JetStream backend.
- **Dead-letter queue (issue #81).** A second JetStream stream,
  `RYVEX_DLQ` on `ryvex.dlq.>` (7-day retention), retains dead-lettered
  events: handler failures marked `bus.ErrEventPoison` (or undecodable
  payloads) immediately, and exhausted `MaxDeliver` budgets otherwise.
  The original payload is republished verbatim on
  `ryvex.dlq.<stream-sequence>` with failure headers
  (`X-Ryvex-DLQ-Reason: poison|max_deliver`, cause, original stream
  sequence, consumer name), the delivery is terminated, and
  `ryvex_bus_dlq_total{reason}` increments. Operators inspect and
  re-drive the DLQ stream directly with any NATS tooling.

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

## Node agent packaging (issue #76)

The Rust agent ships as a first-class deployable, not a build-it-yourself
crate:

- **Images.** `ghcr.io/roy-wanyoike/ryvex-agent` (static musl binary,
  UID 10002, alpine) is published by the release workflow on `v*` tags,
  alongside `ghcr.io/roy-wanyoike/ryvexd`. The agent image builds from
  `Dockerfile.agent` (context trimmed by `Dockerfile.agent.dockerignore`,
  pinned `rust:1.98-alpine` toolchain, `--locked` against `Cargo.lock`).
- **Compose.** The `agent` profile adds the node agent next to
  postgres + ryvexd (and the `nats` profile's JetStream bus); it needs a
  real `RYVEX_AGENT_TOKEN` and opens no listen port — it is a pure
  GET/PUT client of the REST API (fetch its node document, upsert
  enrollment/heartbeat state).
- **Kubernetes.** `deploy/k8s/07-ryvex-agent.yaml` runs one agent per node
  as a non-root DaemonSet (`RYVEX_AGENT_NAME` from `spec.nodeName`, so
  each node stays one stable `Node` resource across pod reschedules);
  `deploy/k8s/kustomization.yaml` parameterizes both image tags so a
  release roll is a `kustomize edit set image` away.

The full self-hosting walkthrough — image provenance, the fail-closed
secrets contract, network-policy assumptions, Postgres sslmode and
probe budgets — lives in [deploy.md](./deploy.md).
