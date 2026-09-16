# 06 — Gap Analysis: Reaching the Intended Ryvex Architecture

Ordered by dependency, not priority alone. Each gap cites the evidence and the tracking issue.

## Gap 0 — Enforcement of truth (everything else depends on it)

**The project's quality claims are currently unauditable.** No CI exists in any ref; the QA report's gates were run locally by their author; live-dependency suites (PG/NATS), SDK integration tests, console build, and the entire Rust agent have never been exercised by automation. Until CI lands, every other gap's "done" is unverifiable.
→ **#74** (CI spec, supersedes #34) · **#70** (must-fix flake before CI) · **#77** (console harness)

## Gap 1 — Make the control plane *control* something

The reconciler is a status state machine: `evaluate()` returns Ready for every kind; no actuator touches infrastructure; drift detection does not exist; failure modes are unreachable. This is the gap between "declarative metadata store" and "infrastructure control plane" — the product thesis itself.
→ **#80**: provider SPI ADR → Docker reference provider → drift detection → reachable failure phases → single-actor/leader-election guarantee.

## Gap 2 — Durable execution for long-running operations

Infrastructure operations outlive processes. Today the only multi-attempt operation (webhook retries, ≤10 attempts) keeps state in process memory. The intended Temporal integration has zero commits (pickaxe-verified). Before code: a decision record weighing Temporal vs Postgres-backed in-process durability vs deferral, with the first concrete workflow (Application deploy) as the acceptance vehicle.
→ **#82** (ADR-0001)

## Gap 3 — Event backbone that survives failure

JetStream is used for publish persistence and replay, but live subscribers (webhook dispatcher included) ride core NATS: no durable consumers, no ack/redelivery, no DLQ, and publishes during an outage vanish without an error or metric.
→ **#81**

## Gap 4 — Truthful operational surfaces

- Health: `/healthz` never checks dependencies; no `/readyz`; pgstore swallows errors; k8s probes therefore lie under dependency failure.
- Deployment: k8s manifests reference an image no pipeline ever published; the agent has zero packaging; `sslmode=disable`; no NetworkPolicy/PDB/startupProbe.
→ **#71** · **#76**

## Gap 5 — Security lifecycle completion

Strong v1 posture (hashed keys, constant-time compares, SSRF guard) with two lifecycle holes: bootstrap keys are permanently admin and irrevocable through the API; secrets are stored plaintext with no encryption-at-rest story.
→ **#73** · secrets-at-rest (follows #80's storage work; not yet tracked — file after ADR)

## Gap 6 — Cross-surface contract integrity

Three verified drifts (agent event semantics #72, TS kind union #79, docs claims #78) plus duplicated helpers and version constants (05). Root cause: contracts are prose, not generated artifacts.
→ **#72** · **#75** · **#79** · **#78**; structural fix (generated schemas/contract tests) rides the CI epic #74.

## Gap 7 — Observability beyond metrics

Metrics are real; traces do not exist (OTel false-positive only). The "why is this unhealthy" thesis needs cross-request causality and resource-aware correlation.
→ **#83**

## Gap 8 — Everything else in the intended stack (deliberately deferred, must be recorded as such)

gRPC API, eBPF telemetry, WASM plugin runtime, Keycloak/OIDC, Helm/Terraform/GitOps, AI operator. None has ever existed (01). The roadmap already lists most as future; the ADR series (#82, #80) should convert each from "intended" to "decided/deferred with rationale" so the README's silence about them stays honest.

## Sequencing

```text
#74 CI (+ #70 flake, #77 console tests)          ← everything verifiable depends on this
   → #69/#71/#72/#73 correctness & lifecycle batch
   → #75/#76/#78/#79 contract & packaging batch
   → #80 provider SPI ADR → implementation        ← thesis-defining
   → #82 workflow ADR → #81 durable consumers
   → #83 traces, #84 API polish, #85 retention, #86 console depth
```
