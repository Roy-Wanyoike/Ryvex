# 02 — Feature Baseline

**Status vocabulary:** NEVER_IMPLEMENTED · DOCUMENTED_ONLY · PROTOTYPE · PARTIAL · IMPLEMENTED · IMPLEMENTED_UNVERIFIED · REMOVED · REPLACED · BROKEN · PRODUCTION_READY. Evidence is file:line at `main @ 0108c20` plus commit hashes where historical context matters.

## Master counts

| Status | Count |
|---|---|
| Production ready | **0** |
| Implemented (functional, tested, with caveats below) | 14 |
| Implemented, unverified | 1 (Rust agent compile) |
| Partial | 9 |
| Prototype | 1 (reconciliation engine) |
| Documented only | 3 |
| Never implemented | 12 |
| Removed / Replaced / Broken | 0 / 0 / 0 |

## Control plane

| Capability | Status | Evidence & caveats |
|---|---|---|
| REST API `/v1` | IMPLEMENTED | 13 kinds, error envelope, request IDs, CORS allowlist, cursor pagination, 405/413, server timeouts (`internal/api/server.go`, `errors.go`, `middleware.go`); hardening batch `ee51f56`. Residuals: 4-segment route accepts any method, CORS untested, request-id unbounded → #84 |
| Authentication (API keys) | IMPLEMENTED | sha256-hashed keys, constant-time compare, plaintext shown once (`internal/api/keys.go:21-100`, `authz.go:171`, `middleware.go:211-246`). Residual: bootstrap keys irrevocable → #73 |
| Authorization (RBAC) | IMPLEMENTED | 3 roles × org/project scopes, enforced in `AuthZMiddleware` (`internal/authz/middleware.go:375-438`), admin-managed key lifecycle via `/v1/keys`, denial audit. No OIDC/IdP by design for v1 |
| Organizations / projects / environments | PARTIAL | Namespaces enforced in routing + scopes; not first-class managed entities (no org settings, quotas, or membership model) |
| Users / tenancy | NEVER_IMPLEMENTED | Only API-key identities exist |
| Resource registry | IMPLEMENTED | 13 kinds, CAS `generation`, spec/status split, DeepCopy defenses, 26-case parity suite across memory+PG (`internal/state/`) |
| Desired state | PARTIAL | `spec` IS desired state and is CAS-protected; no plan/diff surface |
| Actual state | PARTIAL | `status.observedGeneration` stamped by reconciler only; nothing observes real infrastructure |
| Reconciliation engine | PROTOTYPE | Converges every kind to Ready unconditionally (`internal/reconcile/reconcile.go:229-234`); no actuators, no drift, no backoff; Degraded/Failed/Terminating unreachable. Correctness of the loop itself is solid (paginated scan `7718e34`, race fix `0c0d0df`) |
| Drift detection | NEVER_IMPLEMENTED | `ObservedGen < Generation` is the only "drift"; → #80 |
| Scheduling / orchestration | NEVER_IMPLEMENTED | No scheduler beyond the 30s reconciler ticker (serve.go:128-132) |
| Resource graph / dependencies | PARTIAL | Console Topology view derives cluster→node/app groupings client-side from `spec.cluster` (`console/app/views.tsx:307-367`); no backend graph model, no impact analysis |
| Event bus (memory) | IMPLEMENTED | Wildcards `*`/`>`, 1024-ring replay, parity-tested (`internal/bus/`). **Confirmed defect:** `Cancel` wrong-element delete (`bus.go:106`) → #69 |
| Event bus (NATS JetStream) | PARTIAL | Publish persistence + pull replay (`internal/bus/natsbus/`); live path is core NATS: no durable consumers, no DLQ, outage publishes dropped invisibly → #81 |
| Audit trail | IMPLEMENTED | Append-only, org/kind filters, persisted in PG (`internal/state/`). Residual: PG audit errors swallowed → #71; memory backend unbounded → #85 |
| Secrets management | PARTIAL | `Secret` kind is stored plaintext in the resource store; no encryption-at-rest, no write-only semantics; webhook signing secret random per boot (`internal/webhook/dispatcher.go:242-245`) |
| Configuration management | PARTIAL | 8 env vars + flags, boot-validated, dev-auth guard (`cmd/ryvexd/serve.go:34-97`); no dynamic config |
| Health / readiness | PARTIAL | `/healthz` exists but never checks dependencies; no `/readyz` → #71 |

## Providers

| Capability | Status | Evidence |
|---|---|---|
| Provider interface (SPI) | NEVER_IMPLEMENTED | No abstraction exists in any commit |
| Kubernetes / Docker / AWS / GCP / Azure / bare metal | NEVER_IMPLEMENTED | k8s manifests exist only to *host* ryvexd itself (`deploy/k8s/`), not to manage external clusters |
| DNS / TLS / load balancing / storage providers | NEVER_IMPLEMENTED | — |

## Workflow & events

| Capability | Status | Evidence |
|---|---|---|
| Temporal | DOCUMENTED_ONLY | Pickaxe: 0 commits ever. Architecture docs name it as future direction only |
| Durable workflows | NEVER_IMPLEMENTED | Longest-running op = webhook retry loop (max 10 retries, in-process) |
| Webhook deliveries | IMPLEMENTED | HMAC-SHA256 signatures, exponential backoff, per-attempt audit, SSRF egress guard with dispatch-time re-resolution + redirect denial (`internal/webhook/`) — the strongest package in the repo |
| Durable consumers / DLQ | NEVER_IMPLEMENTED | → #81 |

## Policy & security

| Capability | Status | Evidence |
|---|---|---|
| Policy engine (OPA) | DOCUMENTED_ONLY | `Policy` is an inert resource kind; no evaluation anywhere |
| SSRF protection | IMPLEMENTED | Private-range blocking, DNS-rebinding defense, redirect denial (`internal/webhook/egress.go`, `state/subscription.go:77-172`) |
| RBAC | IMPLEMENTED | see above |
| Secrets encryption | NEVER_IMPLEMENTED | — |
| Compliance/audit | PARTIAL | Trail exists; silent-failure mode undermines it → #71 |

## Data plane (Rust)

| Capability | Status | Evidence |
|---|---|---|
| ryvex-agent | IMPLEMENTED_UNVERIFIED | Real crate: reqwest/rustls/tokio, enrollment (GET node → PUT upsert), 10s heartbeat with spec-throttle, 404 self-heal, CAS 3-attempt loop, 26 tests, protocol cross-checked endpoint-by-endpoint against the Go API (all 3 routes match). **UNVERIFIED: the crate has never been compiled anywhere** — no cargo in any environment, no CI (`agent/ryvex-agent/`) |
| eBPF / WASM / secure execution / container ops / system inspection | NEVER_IMPLEMENTED | Zero code; Cargo.lock `wasm-bindgen` is transitive only |
| Go↔Rust protocol | IMPLEMENTED | HTTP/JSON over `/healthz` + scope node routes (no gRPC); one semantic mismatch: agent claims no-event heartbeats, server publishes on every PUT → #72 |

## Observability

| Capability | Status | Evidence |
|---|---|---|
| Prometheus metrics | IMPLEMENTED | Hand-rolled registry, http/reconciler/bus/resource instruments, `--metrics-addr` sidecar (`internal/metrics/`); docs match code |
| Tracing (OTel) | NEVER_IMPLEMENTED | → #83 |
| Log aggregation / Loki / Grafana / Tempo | NEVER_IMPLEMENTED | Structured logs + request IDs only |
| Alerting | NEVER_IMPLEMENTED | — |

## AI

| Capability | Status | Evidence |
|---|---|---|
| AI assistant / LLM anything | NEVER_IMPLEMENTED | Zero commits across all refs |

## Developer surfaces

| Capability | Status | Evidence |
|---|---|---|
| CLI `ryvex` | IMPLEMENTED | 8 commands (apply/list/get/delete/events/audit/reconcile/health), CAS `--generation`, table output, env/flag config; 47 Go tests incl. in-process e2e (`cmd/ryvex/`) |
| TypeScript SDK | IMPLEMENTED | Full /v1 face, timeout/AbortSignal, forbidden/transport_error model, CJS+ESM types, pagination; 43 pass/1 skip (`sdk/ryvex-ts/`) |
| Python SDK | IMPLEMENTED | stdlib-only, typed models, py.typed, parity errors; 51 pass/2 skip (`sdk/ryvex-py/`) |
| Web console | IMPLEMENTED | 6 views + resource drawer, CAS-aware writes with 409 reload, truthful Live/Demo badge (verified `2d8ac01`), token never in localStorage, a11y pass; **zero tests**, demo snapshot ships in live bundle (`console/`) |
| gRPC API | NEVER_IMPLEMENTED | — |
| SDK kind-contract parity | PARTIAL | TS union lists 11 kinds vs server's 13 → #79 |

## Database & deployment

| Capability | Status | Evidence |
|---|---|---|
| PostgreSQL persistence | IMPLEMENTED | Embedded idempotent migrations, parity-tested semantics, bounded pool, 64-bit cursors (`internal/state/pgstore/`) |
| Schema evolution | PARTIAL | Single migration `0001_init.sql`; no migration tooling beyond embedded runner |
| Dockerfile (control plane) | IMPLEMENTED | Multi-stage, static, non-root, healthcheck (`Dockerfile`) |
| docker-compose | PARTIAL | postgres + ryvexd + optional nats profile; no console service; port comment drift |
| Kubernetes manifests | PARTIAL | Coherent StatefulSet/Deployment/ConfigMap/Secret; **ships an unpublished image ref** (`04-ryvexd.yaml:34`), `sslmode=disable`, no NetworkPolicy/PDB/startupProbe → #76 |
| Agent packaging | NEVER_IMPLEMENTED | No agent Dockerfile/DaemonSet/env docs → #76 |
| Helm / Terraform / GitOps | DOCUMENTED_ONLY | Named in `docs/architecture.md` as future direction; zero artifacts |
| CI/CD | NEVER_IMPLEMENTED | `.github/` = dependabot.yml only; issue #34 open; → #74 |

## Testing

| Capability | Status | Evidence |
|---|---|---|
| Go unit + integration | IMPLEMENTED | ~116 test functions; `-race` clean except one flake (→ #70); coverage 51–94% (see 07) |
| Live-dependency suites (PG/NATS) | IMPLEMENTED_UNVERIFIED | Present and well-built; skipped by default (pgstore 7.1%, natsbus 18.4% local coverage); never run by any CI |
| SDK suites | IMPLEMENTED | 44 TS + 53 Py tests, executed in this audit, green |
| Console tests | NEVER_IMPLEMENTED | → #77 |
| Rust tests | IMPLEMENTED_UNVERIFIED | 26 tests exist; never compiled/run anywhere |
| E2E against real daemon | PARTIAL | Go e2e boots an in-process stack (tag `integration`); nothing tests the actual `ryvexd` binary or Docker image |
