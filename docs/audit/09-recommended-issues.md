# 09 — Recommended Implementation Backlog

Produced from the audit findings; all items are filed as issues. Sequencing follows 06-gap-analysis. **No implementation was performed during the audit** — this backlog is the hand-off.

## Wave 1 — Enforcement & correctness (P0) — do first, in order

| # | Issue | Why first |
|---|---|---|
| #70 | Deflake `TestEventsAndAudit` | Blocks trustworthy CI |
| #69 | Fix `bus.Cancel` wrong-element delete | Confirmed correctness defect in the founding commit |
| #74 | CI pipeline (Go+race+PG/NATS services, console, TS/Py, **first-ever cargo job**) | Makes every other claim verifiable; supersedes #34 |
| #71 | `/readyz` + dependency health + stop swallowing store errors | k8s readiness is a lie under DB failure today |
| #72 | Suppress no-op heartbeat events (or `POST /heartbeat`) | Event-storm contract break between agent and server |
| #73 | Revocable bootstrap keys | Security lifecycle hole (always-admin static path) |

## Wave 2 — Contract truth & packaging (P1)

| # | Issue |
|---|---|
| #75 | Agent 5xx backoff + doc alignment |
| #76 | Publish images, package agent (Dockerfile+DaemonSet+env docs), k8s hardening |
| #77 | Console test harness (badge/fallback/envelope) |
| #78 | Docs truth batch 2 (10 verified contradictions) |
| #79 | TS kind-union parity + `.env.example` token removal |

## Wave 3 — Platform depth (P2, thesis work)

| # | Issue |
|---|---|
| #80 | Provider SPI ADR → Docker reference provider → drift detection → reachable failure phases |
| #82 | ADR-0001: durable workflow engine (Temporal evaluation) |
| #81 | JetStream durable consumers + DLQ |
| #83 | OpenTelemetry traces |

## Wave 4 — Polish

| # | Issue |
|---|---|
| #84 | API polish (405, CORS tests, request-id cap, errors.Is) |
| #85 | Bounded audit retention (memory backend) |
| #86 | Console events/audit pagination + demo code-split |

## Definition of done for the whole backlog

All waves merged via issue-linked PRs; CI green including live PG/NATS jobs and the first cargo run; a **new** QA report issued (superseding `docs/qa-report.md`) whose verdict is derived from CI evidence, not local runs. Only then does "production ready / onboarding-ready" become an enforceable statement.
