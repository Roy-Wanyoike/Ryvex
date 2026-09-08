# Ryvex Roadmap

Tracking happens in GitHub Issues — each item below links to an issue,
each landed feature ships as its own PR. This file is the map; the
issue tracker is the truth.

## ✅ Shipped

| Feature | Where |
|---------|-------|
| Control plane core: state store (CAS + audit), event bus, reconciler, REST API, `ryvexd` daemon | `internal/*`, `cmd/ryvexd` |
| Web console: Overview / Resources / Topology / Events / Audit, live + demo modes | `console/` |
| Frozen API contract + architecture docs | `docs/` |
| Demo dataset (`ryvexd --seed`): 15 realistic resources | `cmd/ryvexd/seed.go` |

## 🔜 Active

- [ ] **TypeScript SDK** (`sdk/ryvex-ts`) — typed client for the full `/v1` face, works in Node & browsers, published to npm
- [ ] **Python SDK** (`sdk/ryvex-py`) — same contract, typed with dataclasses/pydantic, on PyPI
- [ ] **Go SDK** (`sdk/ryvex-go`) — idiomatic client with resource builders

## 🧭 Next

- [ ] **`ryvex` CLI** — `apply/get/desc/delete/events/audit` against `/v1`, scriptable, completions
- [ ] **Webhook subscriptions** — durable subscriptions to `ryvex.resource.*` subjects with retries and signing
- [ ] **Durable state backend** — Postgres implementation of `state.Store` behind the existing interface
- [ ] **Durable event stream** — NATS JetStream behind `bus.Bus`, replay for any offset
- [ ] **Real controllers** — Application rollout controller (rolling/blue-green) and Database provisioning controller plugging into `reconcile.evaluate`
- [ ] **RBAC** — org/project-scoped roles bound to `ryk_` keys; audit every authorization decision
- [ ] **Metrics & health** — Prometheus `/metrics` on ryvexd (API latency, reconciler lag, bus throughput)
- [ ] **Drift detection** — compare declared spec against live infrastructure, surface + reconcile drift events

## 🌌 Later

- [ ] **Rust data-plane agent** (`agent/`) — node agent enrolling clusters, executing reconciler decisions, streaming heartbeats
- [ ] **Terraform / OpenTofu provider** — manage Ryvex resources from HCL
- [ ] **Policy-as-code packs** — reusable governance bundles (CIS, cost guardrails) evaluated at admission
- [ ] **Multi-region control planes** — federation + failover between ryvexd instances
- [ ] **Cost intelligence** — per-resource cost attribution and budgets wired into the console

## Contributing

1. Pick (or create) an issue and claim it.
2. Branch from `main` as `feat/<slug>` or `fix/<slug>`.
3. Every PR must close an issue (`Fixes #N`) and keep CI green:
   `go build ./... && go vet ./... && go test ./...` for Go,
   `bun run build && bun run lint` for the console.
4. Ship complete, tested features only — a PR is a promise kept.
