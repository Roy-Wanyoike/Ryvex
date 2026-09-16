# 04 — Regression Report

## Historical regressions (feature worked → refactor → broke)

**None found.** The history is strictly additive (34 commits, zero deletions, zero reverts, zero renames — evidence in 01). No capability that ever worked was subsequently lost. `git log --all --diff-filter=D` is empty and every PR merged into a superset of its base.

## Diseases present since the founding commit (found by this audit)

These are not regressions in the git sense — they shipped in `af95b95` and survived every commit since — but they are latent breakage that review never caught:

| Defect | Since | Why it survived | Tracking |
|---|---|---|---|
| `bus.Subscription.Cancel` wrong-element delete — canceling one of two same-pattern subscribers kills the other and leaves a nil-handler zombie (recovered panics per event, inflated `ryvex_bus_events_delivered_total`) | `af95b95` (founding commit, `internal/bus/bus.go:106`) | Parity suite never exercises multi-subscriber cancel (`internal/bus/bustest/suite.go:169-189`) | **#69** (empirically confirmed via overlay test during this audit) |
| `TestEventsAndAudit` asserts audit-head ordering against the async reconciler — intermittent failure under `-race` | Found at audit time (failed once in verification, passed on re-run) | Single-run CI-less "quality gates"; same class as #65 which *was* fixed for webhooks (`ff6a99d`) | **#70** |
| Reconciler converges all kinds to Ready unconditionally; Degraded/Failed/Terminating unreachable | `af95b95` | The loop's *correctness* was tested; its *honesty* was never questioned | #80 |
| pgstore swallows audit/count DB errors (empty-success behavior) | `bfe9f3e` (PG introduction) | Error paths untested without a live DB; live suites skip by default | #71 |

## Contract regressions (surfaces disagree about truth)

| Drift | Evidence | Tracking |
|---|---|---|
| Agent claims throttled heartbeats emit no `updated` event; server publishes `EventUpdated` on every successful PUT | `agent/ryvex-agent/src/client.rs:62-65` + `client_state.rs:395-397` vs `internal/api/handlers.go:166-172` | **#72** |
| TS SDK `ResourceKind` closed union of 11 vs server registry of 13 | `sdk/ryvex-ts/src/types.ts:15-26` vs `internal/state/resource.go:14-37` | **#79** |
| Docs claim CI branch `feat/34-ci-pipeline` ready; no such ref exists; QA "gates ✅" unenforceable | `docs/qa-report.md:14` vs empty `git log --all -- .github/workflows` | **#74/#78** |
| Agent README claims 5xx PUT backs off exponentially; server-side 5xx maps to `Outcome::Rejected` (fixed-tick retry, no backoff) | `agent/README.md:74-76` vs `client.rs:176` | **#75** |

## Fixed-in-history (regressions *prevented* — the review process worked)

These were caught and fixed within the audited window and verified green in this audit's `-race` runs: reconciler shutdown race + `DeepCopy` spec-map aliasing (`0c0d0df`), agent CAS-contention `unreachable!()` panic (`0f82f9c`), webhook SSRF hole (`ab08c70`), 200-resource scan ceiling (`7718e34`), 2-byte cursor wrap + unbounded PG pool (`e98f861`), webhook audit-retry flake (`ff6a99d`), demo-data-under-Live-badge trust violation (`2d8ac01`).

**Verdict:** no historical regressions; one confirmed latent bug (#69), one confirmed flake (#70), and four documented contract drifts — all tracked with acceptance criteria.
