# Ryvex Metrics

Ryvex ships a dependency-free Prometheus integration (issue #17). There is no
`prometheus/client_golang` in the module: `internal/metrics` implements a
thread-safe registry of counters, gauges and histograms and renders the
Prometheus **text exposition format v0.0.4** by hand. The daemon serves it on
a dedicated, optional listen address so scrape traffic never touches the REST
face.

## Enabling the endpoint

The metrics endpoint is disabled by default. Turn it on with a flag or an env
variable:

```sh
ryvexd serve --metrics-addr 127.0.0.1:9102 ...
RYVEX_METRICS_ADDR=127.0.0.1:9102 ryvexd serve ...
```

When set, ryvexd runs a tiny separate HTTP server on that address with two
routes:

| Route      | Description                                                        |
| ---------- | ------------------------------------------------------------------ |
| `/metrics` | Prometheus scrape target (`text/plain; version=0.0.4; charset=utf-8`) |
| `/healthz` | Status-only passthrough (`ok`, HTTP 200) for load-balancer checks   |

The sidecar shuts down alongside the main server on SIGINT/SIGTERM. A bind
failure on the metrics address is logged but does not stop the control plane.

## Scraping

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: ryvex
    scrape_interval: 15s
    static_configs:
      - targets: ["ryvexd.internal:9102"]
```

Quick check with curl:

```sh
curl -s http://127.0.0.1:9102/metrics | head
# HELP ryvex_bus_events_delivered_total Event deliveries to subscriber handlers (one increment per handler invocation).
# TYPE ryvex_bus_events_delivered_total counter
...
```

Families are rendered in sorted name order and series within a family in
sorted label order, so output is stable across scrapes. Registered families
announce `# HELP` / `# TYPE` even before they carry samples; a series appears
on its first update (label vectors create series lazily, like
`client_golang`).

## Metric families

### HTTP face (`internal/api`)

Recorded in `LogMiddleware`, which sees every request (including 401s and
404s) with its final status and duration.

| Family | Type | Labels | Description |
| ------ | ---- | ------ | ----------- |
| `ryvex_http_requests_total` | counter | `route`, `method`, `status` | Requests handled, by normalized route bucket, HTTP method and numeric response status. |
| `ryvex_http_request_duration_seconds` | histogram | `route`, `method` | Request duration in seconds. Buckets: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5 (+Inf implied). |

The `route` label is a **low-cardinality bucket**, not a raw path. It mirrors
the `routeV1` dispatcher and replaces parameters with placeholders:

| Route bucket | Matches |
| ------------ | ------- |
| `healthz` | `/healthz` |
| `index` | `/`, `/v1`, `/v1/` |
| `resources` | `/v1/resources` (list/create) |
| `resources/{id}` | `/v1/resources/{id}` |
| `org/events` | `/v1/{org}/events` |
| `org/audit` | `/v1/{org}/audit` |
| `org/reconcile/{id}` | `/v1/{org}/reconcile/{id}` |
| `scope/{kind}` | `/v1/{org}/{project}/{env}/{kind}` |
| `scope/{kind}/{name}` | `/v1/{org}/{project}/{env}/{kind}/{name}` |
| `other` | anything else |

Organizations, projects, kinds and IDs never appear in labels, so cardinality
is bounded by the route table, the HTTP method set and the status codes the
server actually returns.

### Store inventory (`internal/state` + `internal/reconcile`)

| Family | Type | Labels | Description |
| ------ | ---- | ------ | ----------- |
| `ryvex_resources` | gauge | `kind`, `phase` | Resources tracked in the store, by kind and lifecycle phase (Pending, Provisioning, Ready, ...). |

This is a **periodic snapshot**, not per-mutation bookkeeping: every
reconciler scan calls `metrics.ReconcileMetrics(store)` (backed by
`Store.CountByKindPhase`), so the gauge lags mutations by at most one scan
interval (30s with the stock `serve` flags, or the next scan after a manual
trigger burst). Kind/phase pairs that disappear from the snapshot are set to
`0` (series are kept, values zeroed).

### Reconciler (`internal/reconcile`)

| Family | Type | Labels | Description |
| ------ | ---- | ------ | ----------- |
| `ryvex_reconciler_scans_total` | counter | — | Store scans performed (initial scan + one per interval tick). |
| `ryvex_reconciler_scan_seconds` | histogram | — | Whole-scan duration. Buckets: 0.001 … 1 (see `instruments.go`). |
| `ryvex_reconciler_converge_seconds` | histogram | — | Per-resource reconcile pass (`reconcileOne`) duration. Buckets: 0.001 … 2.5. |
| `ryvex_reconciler_queue_depth` | gauge | — | Trigger queue length (`len(triggers)`), sampled immediately after each scan. Sustained growth means the reconciler cannot keep up with the change rate. |

### Event bus (`internal/bus`)

| Family | Type | Labels | Description |
| ------ | ---- | ------ | ----------- |
| `ryvex_bus_events_published_total` | counter | `type` | Events published, by type (`created`, `updated`, `deleted`, `status_changed`; `unknown` when a publish omits the type). |
| `ryvex_bus_events_delivered_total` | counter | — | Handler invocations: one increment per event handed to a subscriber. Publishes without matching subscribers do not increment it. |

Both bus counters are fed by whichever backend is active: the in-memory bus
and the JetStream bus (`--bus nats`, issue #15) increment the same families,
so dashboards do not change when durability is switched on.

## Instrumentation notes

- **Zero overhead when idle.** Updates are a mutex-guarded float op per
  family; there are no background goroutines and no allocation on the hot
  path once a series exists. Work only happens when a scrape calls `Gather`.
- **Thread safety.** Every mutation is guarded by the family mutex, so
  instruments are safe to call from the API worker goroutines, reconciler
  workers and bus publishers concurrently (verified under `go test -race`).
- **No dependencies.** `internal/metrics` imports only the standard library;
  `go.mod` stays dependency-free. The exposition writer handles label-value
  escaping (`\`, `"`, newline), `NaN`/`±Inf` literals and cumulative
  histogram buckets with the implied `+Inf` bucket.
- **Reusing the registry.** `metrics.Default` holds all predefined
  instruments; `metrics.Handler()` is a ready-to-mount `http.Handler`. New
  families can be registered on any `metrics.Registry` at startup.
