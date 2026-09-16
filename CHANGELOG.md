# Changelog

All notable changes to Ryvex are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are reconstructed from the git history and the shipped ledger in
`docs/roadmap.md` — every line below links back to a real change.

## [Unreleased]

### Added

- `ryvex list` pagination and CAS-guarded `ryvex apply --generation` (#51)
- TypeScript SDK: request timeouts, `AbortSignal` support, `forbidden` /
  `transport_error` error codes, CJS type declarations (#52)
- Packaging: multi-stage Dockerfile and complete compose stack — Postgres +
  ryvexd (+ NATS profile), non-root image with healthcheck (#35 → #58)
- Onboarding artifacts: four example manifests, `.env.example`, k8s
  manifests, CONTRIBUTING / SECURITY / CODEOWNERS, dependabot config,
  pinned bun.lock (#48 → #60)
- QA report: GA-readiness assessment — audit ledger, quality gates,
  onboarding verdict (verdict later superseded by the 2026-09-16 audit
  in `docs/audit/`; see #78) (#67 → #68)
- Deploy: publishable images (`ghcr.io/roy-wanyoike/ryvexd` +
  `ryvex-agent`, release workflow spec on `v*` tags), agent Dockerfile
  + compose `agent` profile, k8s DaemonSet for the node agent, and tag
  parameterization via `deploy/k8s/kustomization.yaml` (#76)
- k8s hardening: startupProbe on `/readyz` (migrations no longer race
  liveness), NetworkPolicy (default-deny both ways around ryvexd),
  PDB (`minAvailable: 1`), non-root Postgres StatefulSet (UID 999,
  fsGroup, caps dropped), configurable DSN sslmode
  (`RYVEX_PG_SSLMODE`, `verify-full` example), agent DaemonSet + all 9
  `RYVEX_AGENT_*` vars in `.env.example`, `docs/deploy.md` (#76)
- Dependency-aware health: `/readyz` answers 503 until the store and
  the bus both answer a real query (dead-Postgres pods leave the
  Service rotation), `/healthz` reports `"status": "degraded"` with
  per-dependency states instead of a lying 200, and failed store/audit
  queries surface `500` envelopes instead of empty success bodies (#71)
- Provider SPI (ADR-0002): per-kind actuator interface (`Plan` / `Apply`
  / `Inspect` / `Capabilities` + optional `FieldMapper`), drift
  detection pass (`Drifted:` annotations, `drift_detected` events and
  audit entries, `ryvex_reconciler_drifts_total`), per-kind
  retry/backoff with reachable `Degraded`/`Failed` phases and
  `ryvex_reconciler_actuations_total`, and a stdlib Docker Engine
  reference actuator behind `-tags docker` (`--enable-docker-actuator`,
  `--docker-socket`, `--drift-interval`) (#80)
- JetStream durability: named restart-idempotent durable pull
  consumers (the webhook dispatcher runs as `RYVEX_DISPATCHER`,
  at-least-once with explicit acks), a dead-letter stream `RYVEX_DLQ`
  (poison / max_deliver reasons, 7-day retention, failure headers),
  and publish-failure surfacing via `PublishErr` plus the
  `ryvex_bus_publish_failures_total` and `ryvex_bus_dlq_total`
  instruments (#81)
- Bounded audit retention for the memory state backend:
  `--audit-cap` / `RYVEX_AUDIT_CAP` (default 10000, oldest evicted
  first; Postgres keeps its own durable history) (#85)
- Console: events/audit load-more pagination, code-split demo
  snapshot, scoped aria-live announcements (#86)
- ADR-0001: durable workflow engine — the design record for the
  lease/claim seam and the workflow step client (#82)
- Repository audit series: git archaeology, feature baseline,
  architecture evolution, regressions, dead code, gap analysis, test
  coverage, issue reconciliation and recommended issues
  (`docs/audit/`) (PR #88)
- Console test harness: `bun test` suite guarding the truth-in-UI
  logic (live vs demo states, health reporting) (#77)
- OpenTelemetry traces across the `/v1` face (issue #83): OTLP/HTTP
  exporter via `--otlp-endpoint` / `RYVEX_OTLP_ENDPOINT` (+
  `--otlp-insecure`, `--tracing-sample-ratio`; off by default — the
  no-op provider costs nothing when unset), W3C tracecontext
  propagation with parent-based sampling, route-labeled server spans
  per request (`X-Ryvex-Trace-Id` echoed only when tracing is on),
  `store.*` child spans for API store writes, `reconcile.scan` /
  `reconcile.resource` spans for reconcile passes, `webhook.deliver`
  spans with an outgoing W3C `traceparent` on deliveries, and the
  request-ID audit bridge: `request_id` rides the server span as a
  span attribute and the access log carries both IDs
- Events/audit feed cursors: `GET /v1/{org}/events` and
  `GET /v1/{org}/audit` accept `?cursor=` and answer `next_cursor`
  (empty string when exhausted) with the exact wire contract of the
  resources listing, so the console Load-more reaches long feed tails
  instead of the plane truncating at page one. `from` + `cursor` are
  mutually exclusive (400), a malformed cursor is a 400
  `bad_request`, and a stale/evicted cursor clamps to a clean empty
  page (#107)

### Changed

- Docs truth sync: Postgres durability section, `/v1/keys` + 13 kinds +
  `?from=` in the frozen contract, kind-count and console read/write
  contradictions resolved, roadmap ledger made truthful (#47 → #64)
- Bootstrap `--api-keys` entries are seeded as ordinary `APIKey`
  resources: they are revocable, demotable and disableable through the
  `/v1/keys` lifecycle, and authentication derives only from the live
  key-resource view — no static digest fallback, no restart to take
  effect (#73)
- Docs truth batch 2: audit-verified contradiction fixes across the
  doc set (#78)
- Bus metric contract: `ryvex_bus_events_published_total` counts one
  increment per bus-accepted publish on every backend — the memory bus
  counts at Publish (pre-fanout, its existing test-pinned meaning),
  natsbus keeps its JetStream persist-ack gate with refused publishes
  on `ryvex_bus_publish_failures_total` — pinned by a parity test;
  `gofmt` drift in `natsbus.go` cleaned up (`gofmt -l internal/ cmd/`
  empty) (#109)
- Docs truth batch 3: wave-2 surfaces verified against source — metric
  families and bus-instrument contracts (`docs/metrics.md`),
  dependency-health wire shapes and the provider-SPI/drift semantics
  (`docs/api-contracts.md`, `docs/architecture.md`), plus CHANGELOG
  backfill (#110)

### Fixed

- `ryvexd`: helper unit tests, seed idempotency, boot-flag validation (#50)
- API hardening: cursor propagation, 405/413 handling, server timeouts,
  security headers, dev-auth guard, constant-time static-key comparison,
  version plumbing into `/healthz` and the `/v1` index (#54)
- Console: truthful Live/Demo states, configurable org, error boundary,
  pagination, request timeouts, refresh control (#55)
- Rust node agent: panic path, hostname reporting, heartbeat churn,
  client-state coverage (#56)
- Python SDK: `403` modeled as `forbidden`; `transport_error` documented
  as the cross-SDK standard (#45 → #57)
- Reconciler: cursor-paged scan past the 200-resource list ceiling, with
  a stuck-cursor guard (#37 → #59)
- NATS bus: publish metric counts only server-acknowledged successes
  (#40 → #61)
- State store: 64-bit pagination cursors (legacy-decodable), bounded
  Postgres pool, ListAudit SQL and swallowed-error fixes, parity cases
  (#39 → #62)
- Console: accessibility (drawer focus trap, ARIA), responsive tables,
  token hygiene (no baked default token), clipboard buttons, data-driven
  kind chips, topology scoping (#42 → #63)
- Webhook test flake: wait for the audit trail, not the wire, before
  asserting attempts (TOCTOU under `-race`) (#65 → #66)
- Bus: `Subscription.Cancel` removed the wrong element when several
  subscribers matched one pattern; multi-subscriber cancel is
  parity-covered in `bustest` (#69)
- API: no-op heartbeat PUTs — byte-identical spec/labels re-sent by
  the node agent — keep `200` and the unchanged generation but no
  longer publish `updated` events, write audit entries or fan out
  webhook deliveries (#72)
- API: scope-list rejects non-GET methods with `405` + `Allow`;
  error-status mapping uses `errors.Is`/`errors.As` so wrapped
  sentinel errors keep their codes; client-supplied `X-Request-Id` is
  constrained to a safe charset/length; CORS matrix coverage (#84)
- Rust node agent: PUT 5xx treated as transient — exponential
  backoff with jitter instead of a tight retry loop (#75)
- SDKs: TypeScript `ResourceKind` parity with the server registry;
  token hygiene in `.env.example` (#79)
- Tests: `TestEventsAndAudit` made deterministic against the async
  reconciler (#70)
- API polish batch 2: a no-change key PATCH — empty body or one that
  restates the current roles/scopes/active — no longer publishes an
  `updated` key event (same churn class as #72's heartbeat gating);
  store no-op updates leave `UpdatedAt` untouched so heartbeat PUT
  responses stay byte-identical end to end; disallowed-origin CORS
  responses carry `Vary: Origin` and their preflights get an explicit
  403 instead of a free pre-auth 204; `Cache-Control: no-store`
  matches the `/v1` segment boundary exactly (no more `/v1x` false
  positives); error-envelope `details` always serializes as `[]`
  (#108)
- pgstore: no-op updates preserve `UpdatedAt` exactly like the memory
  store — byte-identical no-op responses across backends, pinned by a
  suite case (#115)

### Security

- Webhook SSRF egress guard: private/loopback/CGNAT range blocking,
  dispatch-time DNS revalidation, redirect denial (#36 → #53)

## [1.1.0] — 2026-09-08

### Added

- TypeScript SDK for the `/v1` API face — ESM + CJS, typed, zero runtime
  dependencies (#20)
- `ryvex` CLI: `apply`, `get`, `delete`, `events`, `audit`, `reconcile`,
  `health` (#21)
- Console writes: resource editor, CAS-aware saves, settings, toasts (#22)
- Durable webhook subscriptions with signed, retried, audited deliveries (#23)
- Prometheus metrics sidecar: HTTP, reconciler, bus, and resource
  instruments (#24)
- Python SDK with typed dataclass models — stdlib-only runtime (#25)
- Postgres state backend with parity-tested semantics against the
  in-memory store (#26)
- NATS JetStream event bus backend with durable replay across restarts (#27)
- Org/project-scoped RBAC with managed `ryk_` API keys (#30)
- Rust data-plane node agent: enrollment, heartbeats, self-healing (#31)
- Roadmap shipped ledger and README project map (#32)

### Fixed

- Reconciler shutdown race and `DeepCopy` spec-map aliasing found by the
  race detector (#29)

## [1.0.0] — 2026-09-08

### Added

- Control plane core: CAS state store with audit trail, in-memory event
  bus, reconciler loop, REST API (`/v1`), and the `ryvexd` daemon (#1)
- Web console: Overview / Resources / Topology / Events / Audit views,
  live and demo modes (#3)
- Architecture notes and the frozen REST API contract (`docs/`) (#5)
- Project README with console screenshots, Apache-2.0 license (#7)

[Unreleased]: https://github.com/Roy-Wanyoike/Ryvex/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Roy-Wanyoike/Ryvex/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Roy-Wanyoike/Ryvex/releases/tag/v1.0.0
