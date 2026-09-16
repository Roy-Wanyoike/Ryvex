# 03 — Architecture Evolution: Intended vs Current

## The intended architecture (product thesis)

```text
                    RYVEX
                      │
             ┌────────┴────────┐
       CONTROL PLANE       DATA PLANE
            Go                 Rust
      Intent / State        Execution
      Policy  Workflow      Networking
      Graph    Scheduling   eBPF / Telemetry
             │                 │
             └────────┬────────┘
                      │
               Infrastructure (orchestrated, not replaced)
```

Intended stack: Go + Rust · Next.js · PostgreSQL · NATS JetStream · Temporal · OPA · OpenTelemetry/Prometheus/Loki/Tempo · gRPC+REST · Helm/Terraform/GitOps · Keycloak.

## The current architecture (verified at `main @ 0108c20`)

```text
                 ryvexd (single Go binary, v1.1.0)
   ┌──────────────────────────────────────────────────┐
   │ internal/api        REST /v1, RBAC, hardening    │
   │ internal/state      memory | Postgres (parity)   │
   │ internal/bus        memory | NATS JetStream*     │
   │ internal/reconcile  30s ticker → status machine  │
   │ internal/webhook    signed deliveries + SSRF guard│
   │ internal/metrics    Prometheus sidecar :9090     │
   └──────────────────────────────────────────────────┘
        │ REST                │ REST
   console (Next.js,      ryvex CLI (Go)      ryvex-agent (Rust:
   static export)         + TS/Py SDKs        heartbeat client only)
        └── demo snapshot fallback (no-config mode)
```
*JetStream used for persistence+replay; live subscriptions are core NATS.

## Conformance table

| Intended component | Current state | Conformance verdict |
|---|---|---|
| Go control plane | ryvexd, 7 internal packages | ✅ Conforms (the strongest part of the thesis) |
| Resource model (kind-agnostic registry) | 13 kinds, generic registry, CAS | ✅ Conforms — genuinely provider-agnostic metadata layer |
| Desired → reconcile → actual loop | Status machine only; evaluate() returns Ready for everything | ⚠️ **Divergent** — the loop exists but reconciles nothing real (#80) |
| Rust data plane (execution, networking, eBPF, runtime) | Heartbeat/enrollment client that maintains its own Node record | ⚠️ **Divergent** — present but not a data plane; label honestly |
| Go↔Rust protocol | HTTP/JSON (3 routes, verified matching) | ⚠️ Partial — works, but gRPC intent never started |
| Temporal durable workflows | Absent (0 commits ever) | ❌ Missing — the webhook retry loop is the only durable-ish operation |
| NATS JetStream backbone | Publish persistence + replay only; no durable consumers/DLQ | ⚠️ Partial (#81) |
| OPA policy gate | Absent; `Policy` kind inert | ❌ Missing — mutations gated only by RBAC |
| OpenTelemetry | Absent (false-positive in bun.lock) | ❌ Missing — request-ID correlation only (#83) |
| PostgreSQL | Implemented, parity-tested | ✅ Conforms |
| gRPC API | Absent | ❌ Missing (REST-only; acceptable if ADR records the decision) |
| Helm/Terraform/GitOps | Absent; compose + raw k8s manifests | ⚠️ Partial (#76) |
| Keycloak / OIDC | Absent | ⚠️ Partial — hand-rolled RBAC with API keys is coherent for v1; document the identity ADR |
| AI operator (intent → plan → policy → approval) | Absent | ❌ Missing (correctly absent per phase plan) |

## Architectural violations & drift (specific)

1. **Synchronous in-process operations that should be durable workflows** — webhook delivery retry chains live in process memory (`internal/webhook/dispatcher.go`); a crash loses retry state. This is the exact class the Temporal decision (#82) must address.
2. **Provider-specific logic leaking into core** — none found (clean); the *opposite* problem: no provider logic exists at all.
3. **AI bypassing control-plane safeguards** — N/A (no AI).
4. **Contract drift between surfaces** — agent/event semantics mismatch (#72), TS SDK kind-union drift (#79), console version chip drift — three separate cases where two surfaces disagree about "the truth". This is the drift class a generated-schema pipeline would prevent (part of #78/#79 scope).
5. **Duplicated responsibilities** — `newID/newAuditID/eventTypeLabel/hasRole/specLabelsEqual` re-implemented across `state`, `pgstore`, `bus`, `natsbus`; `Version` declared twice (`internal/api/server.go:19`, `cmd/ryvexd/main.go:11`). Not harmful today; will diverge silently (see 05).
6. **Unbounded in-process state** — memory audit ring (#85), webhook audit growth — memory leak vectors in the only HA-absent deployment mode.
7. **Health/readiness decoupled from reality** — k8s probes assert health of a process whose dependencies may be dead (#71); architectural, not just tactical.
8. **Single-replica assumptions baked in** — no leader election; two replicas would double-reconcile and double-dispatch webhooks. Must be an explicit constraint or fixed (#80 ADR).

## What the architecture got right (credit)

- Single static binary, dependency-minimal `go.mod` (lib/pq, nats.go — no dependency cosplay).
- Spec/status separation with CAS `generation` is consistent across store, API, CLI, SDKs, console — the core abstraction is coherent end-to-end.
- The memory↔Postgres and memory↔NATS backend duality with parity suites is exactly the right seam for future providers.
- Security posture is unusually strong for v1: hashed keys, constant-time compares, SSRF egress guard with rebinding defense, dev-auth guard, bounded bodies/timeouts.
