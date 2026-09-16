# Ryvex Roadmap

Tracking happens in GitHub Issues — each item below links to an issue,
each landed feature ships as its own PR. This file is the map; the
issue tracker is the truth.

## ✅ Shipped

| Feature | Where | Issue |
|---------|-------|-------|
| Control plane core: state store (CAS + audit), event bus, reconciler, REST API, `ryvexd` daemon | `internal/*`, `cmd/ryvexd` | #1 |
| Web console: Overview / Resources / Topology / Events / Audit, live + demo modes | `console/` | #3 |
| Frozen API contract + architecture docs | `docs/` | #5 |
| Recruiter README + Apache-2.0 | `README.md` | #7 |
| TypeScript SDK (ESM+CJS, typed, zero runtime deps) | `sdk/ryvex-ts` | #10 |
| Python SDK (dataclasses, stdlib-only runtime) | `sdk/ryvex-py` | #11 |
| `ryvex` CLI (apply/get/list/delete/events/audit/reconcile/health, pagination + CAS `apply --generation`) | `cmd/ryvex` | #12, #46 |
| Webhook subscriptions (signed, retried, audited deliveries) | `internal/webhook` | #13 |
| Webhook SSRF egress guard (private-range blocking, dispatch-time revalidation, `RYVEX_ALLOW_PRIVATE_WEBHOOKS=1` opt-in) | `internal/webhook`, `internal/state` | #36 |
| Postgres state backend (parity-tested suite, restart persistence) | `internal/state/pgstore` | #14 |
| NATS JetStream event bus (durable replay across restarts) | `internal/bus/natsbus` | #15 |
| Org/project-scoped RBAC with managed `ryk_` keys | `internal/authz`, `internal/api` | #16 |
| Prometheus metrics sidecar (HTTP, reconciler, bus, resources) | `internal/metrics` | #17 |
| Console writes: resource editor, CAS-aware saves, settings | `console/` | #18 |
| Console operator trust: truthful Live/Degraded/Error states, error boundary, timeouts | `console/` | #41 |
| Rust data-plane node agent (enroll, heartbeat, self-heal) | `agent/ryvex-agent` | #19 |
| Race-hardening: reconciler shutdown + DeepCopy aliasing fix | `internal/*` | #28 |
| TS SDK hardening: per-request timeout + `AbortSignal`, `forbidden`/`transport_error` codes | `sdk/ryvex-ts` | #44 |
| API hardening: security headers, `413 payload_too_large`, auth-tiered `/healthz`, server timeouts, dev-auth boot guard, version plumbing | `internal/api`, `cmd/ryvexd` | #38 |
| `ryvexd` test hardening: helper units, seed idempotency, boot flag validation | `cmd/ryvexd` | #49 |

### Shipped — the waves since (audit backlog → #117)

The table above stops at the v1.1.0 ledger; everything shipped since,
one row per issue (issues already rowed above — #36, #38, #41, #44,
#46, #49 — are not repeated). Issue → one-line outcome, with the PR
that landed it:

| Issue | Outcome |
|-------|---------|
| #35 | Packaging: multi-stage Dockerfile + complete compose stack (Postgres + ryvexd + NATS profile), non-root with healthcheck (PR #58) |
| #37 | Reconciler scan pages past the 200-resource list ceiling, with a stuck-cursor guard (PR #59) |
| #39 | 64-bit pagination cursors (legacy-decodable), bounded Postgres pool, ListAudit SQL/error fixes (PR #62) |
| #40 | NATS publish metric counts only server-acknowledged successes (PR #61) |
| #42 | Console accessibility, responsive tables, token hygiene, topology scoping (PR #63) |
| #43 | Rust agent correctness: panic path, hostname reporting, heartbeat spec-throttle, client-state suite (PR #56) |
| #45 | Python SDK: `403` modeled as `forbidden`; `transport_error` documented as the cross-SDK standard (PR #57) |
| #47 | Docs truth sync: Postgres durability, `/v1/keys` + 13 kinds, roadmap ledger made truthful (PR #64) |
| #48 | Onboarding artifacts: example manifests, `.env.example`, k8s manifests, governance files, CHANGELOG (PR #60) |
| #65 | Webhook test flake: wait for the audit trail, not the wire (TOCTOU under `-race`) (PR #66) |
| #67 | QA report — GA-readiness assessment; verdict superseded by the audit in `docs/audit/` (PR #68) |
| #69 | Bus: `Subscription.Cancel` removed the wrong element under multi-subscriber patterns; parity-covered (PR #95) |
| #70 | `TestEventsAndAudit` made deterministic against the async reconciler (PR #92) |
| #71 | Dependency-aware health: `/readyz` 503 rotation gate, honest `degraded` `/healthz`, 500 error envelopes (PR #99) |
| #72 | No-op heartbeat PUTs stay silent: byte-identical spec/labels → no `updated` event, no audit entry, no webhook (PR #103) |
| #73 | Bootstrap `--api-keys` seeded as ordinary, revocable `APIKey` resources (PR #97) |
| #75 | Agent treats PUT 5xx as transient: exponential backoff with jitter (PR #93) |
| #76 | Deploy packaging: publishable-image spec, agent Dockerfile + compose profile, k8s hardening, `docs/deploy.md` (PR #102) |
| #77 | Console `bun test` harness guarding the truth-in-UI logic (PR #96) |
| #78 | Docs truth batch 2: audit-verified contradiction fixes across the doc set (PR #94) |
| #79 | TypeScript `ResourceKind` parity with the server registry; `.env.example` token hygiene (PR #91) |
| #80 | Provider SPI (ADR-0002): per-kind actuators, drift detection, retry/backoff, reachable `Degraded`/`Failed`, Docker reference actuator ([docs/adr/0002](./adr/0002-provider-spi.md), PR #106) |
| #81 | JetStream durability: durable pull consumers, `RYVEX_DLQ`, `ryvex_bus_publish_failures_total` (PR #105) |
| #82 | ADR-0001: durable workflow engine decision — lease/claim seam, workflow step client ([docs/adr/0001](./adr/0001-durable-workflow-engine.md), PR #90) |
| #83 | OpenTelemetry traces across the `/v1` face: OTLP/HTTP export, server + child spans, request-ID bridge (PR #117) |
| #84 | API polish: 405 on scope-list, `errors.Is` status mapping, request-id hardening, CORS matrix coverage (PR #100) |
| #85 | Bounded audit retention for the memory backend: `--audit-cap` / `RYVEX_AUDIT_CAP` (PR #101) |
| #86 | Console events/audit load-more pagination (PR #104) |
| #87 | Repository audit series: reports 01–09 under `docs/audit/` (PR #88) |
| #107 | Events/audit feed cursors: `?cursor=` + `next_cursor` with the resources-listing wire contract (console Load-more parity) (PR #114) |
| #108 | API polish 2: key-event churn, `UpdatedAt` no-op, CORS hygiene, error-path cleanups (PR #113) |
| #109 | `ryvex_bus_events_published_total` semantics aligned across backends + gofmt (PR #111) |
| #110 | Docs truth batch 3: metrics, health contracts, provider SPI, changelog (PR #112) |
| #115 | pgstore preserves `UpdatedAt` on no-op updates — backend parity (PR #116) |

## 🔜 Active

- [ ] **CI pipeline** — enforce the five verification stacks per PR and run the durable-backend parity suites on service containers (spec #34/#74; open as PR #98)

- [ ] **Server-side heartbeat endpoint** — ingest agent heartbeats in the control plane so node liveness is a first-class resource signal (agents heartbeat client-side today)
- [ ] **Key rotation UX** — rotate `ryk_` keys without downtime; overlap windows; console management view for keys
- [ ] **Deployment controller** — real rollout strategies (rolling / blue-green) for Application kind, plugging into `reconcile.evaluate`
- [ ] **Drift detection** — agents compare declared spec vs live machine state; drift surfaced as events + console badges

## 🧭 Next

- [ ] **Durable workflow execution (ADR-0001)** — Postgres-backed in-process step durability for multi-step operations; decision and first workflow (Application deploy) in [docs/adr/0001](./adr/0001-durable-workflow-engine.md), which builds on the shipped provider SPI ([ADR-0002](./adr/0002-provider-spi.md)) — a workflow step calls the actuator seam it defines
- [ ] **Go SDK** — a third client alongside `sdk/ryvex-ts` and `sdk/ryvex-py` (does not exist yet)
- [ ] **Terraform / OpenTofu provider** — manage Ryvex resources from HCL
- [ ] **Policy-as-code packs** — reusable governance bundles (CIS, cost guardrails) evaluated at admission
- [ ] **Multi-region control planes** — federation + failover between ryvexd instances
- [ ] **Cost intelligence** — per-resource cost attribution and budgets wired into the console
- [ ] **Agent exec hooks** — reconcile decisions executed as local actions on nodes

## Contributing

1. Pick (or create) an issue and claim it.
2. Branch from `main` as `feat/<slug>`, `fix/<slug>` or `chore/<slug>`.
3. Every PR must close an issue (`Fixes #N`) and pass the verification
   suite (a hosted CI workflow is not wired up yet — run it locally):
   - Go: `go build ./... && go vet ./... && go test ./...` (durable backends: parity suites against Postgres/NATS when the DSNs are provided)
   - Console: `bun run build && bun run lint`
   - Agent: `cargo build --release && cargo test && cargo clippy -- -D warnings`
4. Ship complete, tested features only — a PR is a promise kept.
