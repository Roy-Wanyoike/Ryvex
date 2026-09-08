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
interfaces (`state.Store`, `bus.Bus`) are contracts, so durable backends
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
   and future agents subscribe to exactly the slice they care about.

## Components

### State store (`internal/state`)

- **Model.** 11 kinds: Project, Environment, Application, Deployment,
  Cluster, Node, Database, Cache, Bucket, Policy, Secret.
- **Identity.** Logical address `org/project/env/kind/name` (unique) +
  opaque ID `r-<hex>` (stable handle).
- **Concurrency.** Mutex-guarded; updates take an optional
  `ExpectedGeneration` for compare-and-swap — stale writers get `409`.
- **Governance.** Every create/update/delete/status-change lands in the
  audit log with actor + reason.

### Event bus (`internal/bus`)

- NATS-style subjects with `*` (one segment) and `>` (tail) wildcards.
- Synchronous fan-out with subscriber panic isolation.
- 1024-event replay ring powering `GET /v1/{org}/events`.

### Reconciler (`internal/reconcile`)

- Fixed-interval scan + out-of-band `Trigger(id)` (used by
  `POST /v1/{org}/reconcile/{id}`).
- Bounded worker pool (configurable concurrency).
- Reference policy converges `Pending → Provisioning → Ready` and
  stamps `observed_generation`; the `evaluate` hook is the seam where
  real controllers plug in.

### REST API (`internal/api`)

- stdlib-only HTTP stack: request-ID → recover → logging → CORS →
  bearer auth → routes.
- Manual `/v1` dispatcher because the path space
  (`/v1/resources/{id}` vs `/v1/{org}/events`) is ambiguous to pattern
  routers.
- Frozen error envelope and status mapping (see
  [api-contracts.md](./api-contracts.md)).

### Daemon (`cmd/ryvexd`)

```
ryvexd serve --http :8080 --dev-auth --seed --cors-origins http://localhost:3100
```

| Flag | Env | Meaning |
|------|-----|---------|
| `--http` | `RYVEX_HTTP_ADDR` | Listen address (`:8080`) |
| `--store` | | Backend (`memory`) |
| `--dev-auth` | | Accept any well-formed `ryk_` token (dev only) |
| `--api-keys` | `RYVEX_API_KEYS` | Static keys `name=token,…` |
| `--cors-origins` | `RYVEX_CORS_ORIGINS` | Browser origins allowed cross-origin |
| `--seed` | | Load the 15-resource demo dataset |
| `--log-level` | | `debug` … `error` |

Graceful shutdown: SIGINT/SIGTERM stops the listener, drains the HTTP
server, cancels the reconciler and waits for workers.

## Web console (`console/`)

Next.js 15 + React 19 + Tailwind 4. Read-only client of the REST API
with a 15s refresh loop; degrades to an embedded demo snapshot when no
daemon is configured, so the UI is always presentable. Five views:
Overview, Resources, Topology, Events, Audit.

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
