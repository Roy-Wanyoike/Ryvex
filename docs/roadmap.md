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

## 🔜 Active

- [ ] **Server-side heartbeat endpoint** — ingest agent heartbeats in the control plane so node liveness is a first-class resource signal (agents heartbeat client-side today)
- [ ] **Key rotation UX** — rotate `ryk_` keys without downtime; overlap windows; console management view for keys
- [ ] **Deployment controller** — real rollout strategies (rolling / blue-green) for Application kind, plugging into `reconcile.evaluate`
- [ ] **Drift detection** — agents compare declared spec vs live machine state; drift surfaced as events + console badges

## 🧭 Next

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
