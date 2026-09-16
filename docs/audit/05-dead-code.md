# 05 — Dead Code Report

Compiled from cross-reference of exported symbols, struct fields, and constants against all call sites at `main @ 0108c20`. Reachability, not compilation, is the criterion.

## Unreachable / unread code (Go)

| Item | Location | Why dead | Disposition |
|---|---|---|---|
| `reconcile.Options.Scopes`, `.Namespaces` | `internal/reconcile/reconcile.go:23-24` | Written by constructors, never read by scan or workers | Remove or wire into the future provider SPI (#80) |
| Phases `Degraded`, `Failed`, `Terminating` | `internal/state/resource.go:40-47` | No code path assigns them; `evaluate()` returns Ready unconditionally (`reconcile.go:229-234`) | Dead constants today; become live with #80 |
| `api.ConstantTimeEqual` | `internal/api/middleware.go:351` | Exported, never called (authz uses its own `subtle.ConstantTimeCompare`) | Delete |
| `state.Store.seq` | `internal/state/store.go:329,350` | Write-only counter (in-memory audit IDs use random IDs) | Delete |
| Static-key digest index built twice per server | `internal/api/server.go:76` + `middleware.go:310,377` | Same index constructed on two paths | Consolidate (and fix its irrevocability, #73) |
| `Version` duplicated | `internal/api/server.go:19` vs `cmd/ryvexd/main.go:11` | Two constants to bump on release | Single source |

## Duplicated helpers (same logic, multiple homes — silent divergence risk)

`newID`/`newAuditID` (state, pgstore, authz) · `eventTypeLabel` (bus, natsbus) · `hasRole` (authz, middleware) · `specLabelsEqual` (store.go:220-228, pgstore.go:422-426). None harmful today; consolidate when touched.

## Frontend / other stacks

| Item | Location | Note |
|---|---|---|
| `console/go.mod` | `console/go.mod` | Module declaration with zero `.go` files — historical artifact of a node_modules scan workaround; harmless but confusing |
| `safeText` | `sdk/ryvex-ts/src/client.ts:438-444` | Exported, never called |
| Demo snapshot in live bundle | `console/lib/demo.ts` (181 lines) statically imported by `api.ts:1` | Inert when an API base is configured, but ships in every production chunk — code-split (#86) |
| `.env.example` console token template | `.env.example:54-57` | Not dead code but a dead *invitation* to bake credentials — remove (#79) |

## Duplicate implementations of the same concern

Only one found at the *architecture* level: **memory vs NATS bus** and **memory vs Postgres store** — but these are deliberate backend duality behind interfaces with parity suites, not legacy competition. No `ResourceManager`/`ResourceService`-style duplicate hierarchies exist. The founding-commit history is clean of replacement archaeology (nothing was ever replaced — see 01).

## Verdict

Dead code volume is **low and honest** — the codebase does not carry significant abandoned implementations. The two dead-code findings with real blast radius are the unreachable phases (they make the status model look richer than it is) and the duplicated bootstrap-key index (tied to the irrevocability defect #73).
