# 07 — Test Coverage Gap

All numbers below were **produced by this audit's own runs** on `main @ 0108c20` (Go 1.24.5, `go test -race -count=1`, `-cover`; bun test; pytest). "Local" means without live dependencies.

## Go coverage (statements)

| Package | Coverage | Test functions | Notes |
|---|---|---|---|
| internal/bus | 94.3% | 8 | Best in repo; yet the Cancel bug hid outside its coverage (multi-subscriber cancel untested) |
| internal/metrics | 88.8% | 13 | Includes concurrency race test + exposition validation |
| internal/authz | 81.2% | 6 | Role matrix, refresh, denial audit |
| internal/webhook | 83.7% | 14 (+TestMain) | Full SSRF/DNS-rebinding/redirect matrix, goroutine-leak check |
| internal/api | 77.3% | 31 | RBAC + hardening batches; **zero CORS tests** |
| internal/reconcile | 73.3% | 6 | Includes 250-resource pagination proof |
| internal/state | 67.4% | 11 | 26-case parity suite runs against both backends |
| cmd/ryvex | 65.8% | 47 | Unit + in-process e2e (5 behind `integration` tag) |
| cmd/ryvexd | 51.0% | 15 | Seed idempotency, boot guards |
| internal/bus/natsbus | **18.4% local** | 7 | 5 of 7 suites skip without `RYVEX_TEST_NATS_URL` |
| internal/state/pgstore | **7.1% local** | 5 | Live-DB suites skip without `RYVEX_TEST_PG_DSN` |

**Headline:** the local numbers are respectable *because the hard suites skip*. The store and bus — the two components the whole plane rests on — are the least-verified in default runs. CI with service containers fixes this mechanically (#74).

## Verified green in this audit

- `go build ./...` ✓ · `go vet ./...` ✓ · `go test -race` ✓ (after the one flake re-run, see below)
- Console: `bun install --frozen-lockfile` ✓ · ESLint clean ✓ · `next build` ✓ (static, 121 kB first load)
- TS SDK: 43 pass / 1 skip / 0 fail (137 assertions, includes real-socket timeout/abort tests) ✓
- Py SDK: 51 pass / 2 skip / 0 fail ✓

## Gaps, ranked

1. **Nothing runs in CI** — every number above is reproducible only by hand; the QA report's gates were never automated (#74).
2. **Flaky test found**: `TestEventsAndAudit` failed once under `-race` (audit-head raced the async reconciler's `status_changed` audit), passed on re-run — deterministic 20× green required before CI (#70). Same class as the #65/#66 webhook flake.
3. **Console: zero tests** — the truth-in-UI logic (Live/Demo badge, degraded fallback) most likely to regress silently is unguarded (#77).
4. **Integration suites never run by default anywhere** — Go e2e behind a build tag; TS integration requires `RYVEX_INTEGRATION=1` + a hand-started daemon; Py likewise. Nothing tests the actual `ryvexd` binary, Docker image, or compose stack end-to-end.
5. **Rust agent never compiled anywhere** — 26 tests exist (10 unit + 16 client-state against a hand-rolled HTTP mock); no cargo in any environment, no CI job. All agent claims are IMPLEMENTED_UNVERIFIED (#74 cargo job).
6. **CORS: zero tests** despite being security middleware; OPTIONS+Origin returns 204 pre-auth for disallowed origins (#84).
7. **Coverage blind spots with real defects behind them**: multi-subscriber cancel (hid #69); dependency-down health paths (hid #71); NATS outage publish path (untested + unmeasured, #81).
8. **QA-report count drift**: it reports "44 pass/1 skip" (TS) and "53 pass/2 skip" (Py) — the skipped tests are exactly the live-integration ones; the report counts skipped-as-passed adjacent. Minor, but emblematic (#78).

## Quality of the tests that do exist

High: assertions are behavioral (HTTP envelopes, phase transitions, HMAC signatures, egress refusals, goroutine leaks) — not trivial smoke. Parity-suite pattern (one suite, two backends) is the repo's best testing idea and should extend to the future provider SPI (#80).
