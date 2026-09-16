# 08 — Issue Reconciliation

**Remote state at audit time:** 68 issues (67 closed, #34 open), 33 merged PRs. Classification performed against the verified implementation state (02), not against issue prose. Per audit rules, **nothing was closed automatically**; residuals below were filed as new issues (#69–#86).

## Classification summary

| Class | Count | Notes |
|---|---|---|
| CLOSED + VERIFIED | 62 | Implementation located in `main` via merged PR commits; spot-verified by three parallel code audits + test runs |
| OPEN + STILL VALID | 1 | **#34** (CI) — the audit's single highest-leverage confirmation; full spec added via comment + #74 |
| CLOSED + PARTIALLY IMPLEMENTED | 5 | #15/#27 (NATS), #26 (PG), #41/#55 (console trust), #65 (flake class) — residuals below |
| CLOSED + DUPLICATE (by design) | 8 pairs | Issue + PR-tracking pairs (#1/#2, #3/#4, #5/#6, #7/#8, #18/#22, #19/#31, #32/#33, #67/#68) — one track each, no stale duplicates |
| CLOSED + SUPERSEDED | 0 | — |
| CLOSED + IMPLEMENTATION MISSING | 0 | Every closed issue's artifact was found in the tree |
| CLOSED + REGRESSED | 0 | No regressions in history (04) |

## Closed issues with residuals (verified gaps → new tracking)

| Closed issue | Verified residual | New tracking |
|---|---|---|
| #15/#27 NATS JetStream bus | Live path is core NATS: no durable consumers, no DLQ, outage publishes dropped silently | **#81** |
| #26 Postgres store | Audit/count DB errors swallowed → empty-success semantics; readiness lies | **#71** |
| #41/#55 console trust | Badge truthful now (verified); but demo snapshot still ships in live bundle; `.env.example` still templates a baked token | **#86** / **#79** |
| #65 webhook audit-retry flake | Fixed for webhooks; same race class still present in `TestEventsAndAudit` | **#70** |
| #30/#16 RBAC | Solid, but bootstrap keys bypass the lifecycle (static digest index always-admin) | **#73** |
| #31/#19 Rust agent | Real crate, protocol verified — but never compiled anywhere; 5xx handling contradicts docs | **#75** + cargo CI job in **#74** |
| #32/#33 v1.1.0 ledger | CHANGELOG omits batches #57–#68 | **#78** |
| #17 Prometheus metrics | Verified complete (docs match code) | none |
| #59 reconciler pagination | Verified fixed (250-resource test) | none (limitation of scope → #80) |

## New issues created by this audit

**P0-blocker:** #69 (bus.Cancel defect), #70 (flaky test), #71 (dependency-aware health), #72 (heartbeat event contract), #73 (revocable bootstrap keys), #74 (CI pipeline) ·
**P1-core:** #75 (agent backoff+docs), #76 (image publication + agent packaging + k8s hardening), #77 (console test harness), #78 (docs truth batch 2), #79 (SDK kind drift + env template) ·
**P2-platform:** #80 (provider SPI + drift), #81 (durable consumers + DLQ), #82 (workflow engine ADR), #83 (OTel traces), #84 (API polish), #85 (audit retention), #86 (console pagination + demo code-split).
