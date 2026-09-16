# ADR-0002: Provider SPI — actuator interface, drift detection, retry taxonomy

- **Status:** Accepted
- **Date:** 2026-09-17
- **Deciders:** Ryvex maintainers (issue [#80](https://github.com/Roy-Wanyoike/Ryvex/issues/80))
- **Supersedes:** nothing. Complements [ADR-0001](0001-durable-workflow-engine.md)
  (durable workflow engine): the actuator defined here is the seam a
  workflow *step* will call; this ADR does not implement workflows.

## Context

The reconciler (`internal/reconcile/reconcile.go`) is a fixed-interval
scan + bounded worker pool whose `evaluate` hook converges **every**
kind to `Ready` via `UpdateStatus`. Pickaxe-level facts that motivate
this decision:

- No infrastructure is ever touched: "control plane" is currently a
  status convention, not an actuation loop.
- The only drift signal is `ObservedGeneration < Generation` — i.e.
  *our* spec changed. Nothing compares the world outside the store to
  the declared spec.
- `Degraded`, `Failed` and `Terminating` are unreachable dead
  constants: `evaluate` cannot fail, there is no retry/backoff policy,
  and the delete path never reaches the reconciler.
- The webhook dispatcher (in-process retry, 1s→60s exponential
  backoff) and the agent (`agent/ryvex-agent`, `Outcome::Transient /
  Rejected / Missing` classes) already embody the failure taxonomy this
  SPI formalizes — but each ad hoc.

Issue #80 asks for a provider SPI, a real reference actuator, drift
detection, retry/backoff, and reachable `Failed`/`Degraded` — without
regressing the status-only convergence parity that all existing tests
pin down.

## Requirements

1. **Small interface.** An actuator is one kind's hands: plan, apply,
   inspect, capabilities. Everything else (retry, drift comparison,
   phase transitions, audit, events, metrics) is reconciler-owned so
   provider authors write business logic, not control-plane plumbing.
2. **Error taxonomy.** Providers classify their failures; the
   reconciler decides what a class means for phase/retry. Classes must
   mirror the agent's `Outcome` vocabulary (Transient / Permanent /
   Unavailable) so operators learn one mental model.
3. **Drift is a first-class signal, not a phase.** The phase set
   (`Pending/Provisioning/Ready/Degraded/Failed/Terminating`) is frozen
   and shared with the API contract; a drifted-but-running Application
   must not lie as `Degraded`. Drift surfaces as a status annotation
   (`Drifted: …` message prefix), an audit entry (`drift_detected`) and
   a bus event (`ryvex.resource.<org>.<kind>.drift_detected`).
4. **Re-Apply, never hand-mutation.** Drift correction goes through the
   same `Plan → Apply` path as convergence. The reconciler never edits
   external state except via an actuator.
5. **Parity.** Kinds without a registered actuator keep today's exact
   flow and messages; existing reconcile tests stay green unmodified.
6. **Zero new dependencies.** The reference provider speaks the Docker
   Engine API over its unix socket with `net/http` + `encoding/json`,
   hand-rolled, behind the `docker` build tag.
7. **Honest degradation.** `--enable-docker-actuator` on a binary built
   without `-tags docker` warns loudly and converges status-only — the
   store/bus/boot honesty convention (ADR-0001 requirement 4).

## Options considered

### Option A — Fat provider interface (k8s-controller-style)

Actuators get the full controller surface: informers/ watches, status
writers, event recorders, finalizers, their own retry loops.

| Dimension | Assessment |
|---|---|
| Fit to repo | Overkill: no watches exist; the scan+trigger loop is the only delivery mechanism; finalizers would touch the store contract (parallel-owned) |
| Provider authoring cost | High: every provider re-implements transitions, audit, metrics |
| Risk | Duplicates control-plane policy N times; drift semantics would fork per provider |

### Option B — Thin actuator SPI, reconciler-owned control loop (decided)

`internal/provider` defines a five-method `Actuator` plus an optional
`FieldMapper` capability. The reconciler keeps scan/trigger/worker
plumbing and owns phases, retry/backoff, drift comparison, audit,
events and metrics. Providers: `Plan`/`Apply`/`Inspect`/`Capabilities`
(+ `DesiredFields` when drift detection is wanted).

| Dimension | Assessment |
|---|---|
| Fit to repo | Drop-in to the existing loop; `evaluate` hook becomes the actuated branch; no store/bus changes |
| Provider authoring cost | Minimal: pure functions over `state.Resource`; Plan/Apply are unit-testable without any daemon |
| Testability | Plan is pure; Inspect/Apply testable against an `httptest` unix-socket fake; transitions testable with fake actuators |
| Risk | Providers cannot stream watches (fine: periodic inspect) or own exotic state machines (fine until a workflow engine exists) |

### Option C — Keep `evaluate`, add ad-hoc docker calls in reconcile

No SPI; hard-code Docker calls in `reconcileOne`.

| Dimension | Assessment |
|---|---|
| Fit to repo | Fastest, but re-couples the loop to one vendor; every future provider (agent-based Node management, cloud DBs) edits the hot path |
| Testability | Reconcile tests would need a docker daemon or seam anyway |
| Verdict | Rejected: the SPI *is* the seam; ad-hoc calls hide it |

## Decision

**Option B.** The SPI lives in `internal/provider`; the reference
Docker provider in `internal/provider/docker` behind `//go:build
docker`; the reconciler grows the actuated branch, retry book and drift
pass in `internal/reconcile`.

### SPI shape

```go
type Actuator interface {
    Kind() string // resource kind it actuates ("Application", ...)
    // Plan is PURE: derive the operation from two resource snapshots.
    // current == nil means the external object does not exist (or the
    // caller wants a fresh create plan). Implementations normalize
    // spec fields through DesiredFields, so diffing is field-accurate.
    Plan(current, desired *state.Resource) (Plan, error)
    // Apply executes a Plan. Must be idempotent: retries replay the
    // same plan (e.g. create-after-crash must tolerate the object
    // already existing).
    Apply(ctx context.Context, plan Plan) (Result, error)
    // Inspect reads external state. 404-style absence is NOT an error:
    // return Observed{Exists: false}, nil.
    Inspect(ctx context.Context, ref Ref) (Observed, error)
    Capabilities() Caps
}

// Optional capability required for drift detection:
type FieldMapper interface {
    // DesiredFields maps a desired spec to the same normalized field
    // keys Inspect reports in Observed.Fields.
    DesiredFields(spec map[string]any) (map[string]string, error)
}
```

Supporting types: `Plan{Kind, Action, Changes, Desired}` with
`Action ∈ {noop, create, update}`; `Result{Action, ExternalID,
Message}`; `Observed{Exists, ExternalID, State, Ready, Fields}`;
`Caps{DriftDetection, Name}`; `Ref` (derived via `RefFor`).

**Error taxonomy** (mirrors the agent's `Outcome` classes):

| Class | Meaning | Reconciler behavior |
|---|---|---|
| `Transient` | Provider answered, operation may succeed later (5xx, throttles, transient conflicts) | retry with per-kind exponential backoff; phase `Degraded` between attempts; `Failed` when the budget is exhausted |
| `Permanent` | Deterministic rejection (invalid spec, unsupported field); retrying is lying | `Failed` immediately, no retry, message says "permanently" |
| `Unavailable` | The provider/backend is unreachable (dial errors, socket gone) | same mechanics as Transient — `Degraded` + backoff — but the class is preserved in messages/metrics because the fix is operational, not in the spec |

Unclassified errors default to `Transient` (retry-then-fail; the
budget still bounds the loop, and the message records the assumption).
`Plan` errors are controller input errors and surface as `Permanent`.

### Reconcile contract (actuated kinds)

- `Pending → Provisioning` exactly as today (same message, same event).
- Convergence pass: `Inspect` → object missing ⇒ `Plan(nil, desired)`
  (create); object present ⇒ synthesize a pseudo-current resource from
  `Observed.Fields` (`provider.FieldsToSpec`) and `Plan(current,
  desired)` → `update` or `noop`. `Apply` runs only for create/update.
  Success ⇒ `Ready` with an actuation message; failure ⇒ retry path.
- A fresh spec generation re-converges the same way (the pseudo-current
  diff naturally yields `update` only when actuated fields changed;
  label-only bumps collapse to `noop` and still stamp Ready).
- Retry/backoff: per-kind `RetryPolicy{MaxAttempts, BaseDelay,
  MaxDelay}` — defaults **4 attempts, 1s base, ×2 growth, 30s cap**
  (delays 1s, 2s, 4s…). Budget is per resource per generation episode,
  kept in memory (a daemon restart restarts the episode; durable
  retry bookkeeping is explicitly the workflow engine's job per
  ADR-0001). `Failed` is terminal for the current generation; the next
  spec update re-opens convergence.

### Drift semantics (actuated kinds with `Caps.DriftDetection` + `FieldMapper`)

- A dedicated pass (default every 60s, `--drift-interval`-shapable via
  `Options.DriftInterval`) inspects `Ready` resources of actuated kinds
  and compares `DesiredFields(spec)` vs `Observed.Fields` with
  `provider.CompareFields`. Only keys declared in the desired spec are
  compared: provider-side additions (e.g. Docker injecting `PATH`) are
  out-of-band and never flap; deletions of declared keys are drift.
- Drift found ⇒ **status annotation** (phase stays `Ready`, message
  becomes `Drifted: <fields>`), audit entry (action `drift_detected`,
  reason = field list), bus event `drift_detected` with the field list
  in `Data`, and a `ryvex_reconciler_drifts_total` increment — then the
  loop **re-applies through the actuator** (Plan → Apply → verify on
  the next pass). No direct mutation, ever.
- `Inspect` errors during a drift pass are advisory: logged, never
  flapping a `Ready` resource into `Degraded` (a down provider must not
  invent drift). Drift *re-apply* failures DO go through the normal
  retry/failure path.
- When a later pass observes convergence again, a stale `Drifted:`
  annotation is cleared (`drift resolved…` message) — only on
  transition, so steady state writes nothing.

### First concrete provider: Docker (reference)

`internal/provider/docker`, entirely stdlib: an `http.Client` whose
transport dials the Docker Engine unix socket (`DialContext`), hand
written Engine-API calls (`/containers/create`, `/containers/{id}/start`,
`/containers/{id}`, `/containers/{id}/stop`, `/containers/{id}/remove`,
`/_ping`). Application → one managed container:

- name: `ryvex-{org}-{project}-{env}-{name}` (logical-key uniqueness
  guarantees a 1:1 mapping; scope validation already constrains the
  charset);
- desired fields: `image` (required) and `env`, expanded to one
  normalized field per variable (`env.<KEY>`); the Engine merges
  image-defined variables (PATH and friends) into a container's env,
  and per-key fields let drift comparison ignore undeclared extras
  instead of flapping forever. `replicas`/rollouts are deliberately
  not modeled (workflow-engine territory, ADR-0001);
- `update` = recreate (stop → remove → create → start), the honest
  primitive for immutable container configs;
- classification: transport errors ⇒ `Unavailable`; Engine 4xx ⇒
  `Permanent`; 5xx ⇒ `Transient`; 404 on inspect ⇒ `Exists:false`;
  create-after-crash 409 falls back to start (idempotent Apply).

Build/enable: `-tags docker` compiles the actuator (only the actuator
file is tagged; `client.go`/`spec.go` stay tag-free so the pure logic
— spec parsing, plan diffing, classification — is covered by the
default test gates without a daemon);
`--enable-docker-actuator --docker-socket /var/run/docker.sock` wires
it. A dead engine fails the boot explicitly (same posture as
`--bus=nats` on a failed dial); the flag on a binary built without the
tag warns loudly and converges status-only (requirement 7).

### Coordinator safety: single-actor guarantee

The reconciler is an **in-process, single worker pool**: one daemon
process owns its store; within a process, per-resource in-flight
claims (`tryClaim`) prevent the drift pass and the workers from
actuating the same resource concurrently, and the scan is single
threaded. This is a *single-actor guarantee by deployment topology*,
not by protocol: **running two `ryvexd` replicas against one store
without a lease would double-actuate** (both would Apply — idempotent
but wasteful, and drift events would interleave). Leader election /
lease-based claiming is a deliberate non-goal here; the seam is the
same lease model ADR-0001 specifies for workflow run claims.

## Non-goals (explicit)

1. **Leader election / leases / Raft.** Documented seam only (above).
   Single-replica deployments are the supported posture for this PR.
2. **Workflows.** ADR-0001 owns multi-step durable execution. The
   actuator is the future *step client*; nothing here schedules
   workflows, compensations or rollout strategies.
3. **Terminating / teardown.** The delete path (`DELETE /v1/...`) does
   not notify the reconciler, so `Terminating` stays unreachable.
   External state of deleted resources is orphaned by design for now
   (tracked as adjacent gap in the PR; cheap fix needs a store-side
   delete hook or a tombstone scan — both touch parallel-owned
   packages).
4. **Secret material handling.** Providers receive spec as-is; Secret
   kind has no actuator and the Docker provider never reads Secret
   resources. Env values are not redacted by the SPI (providers own
   their logging hygiene; the docker provider logs container IDs, never
   env contents).
5. **Auto-mutation without Apply.** Even "obvious" fixes (restart an
   exited container) go through Plan/Apply. There is no side-channel.
6. **Multi-provider orchestration, priorities, dependencies** between
   resources. One kind ↔ one actuator; the workflow engine layers
   ordering on top later.
7. **Watches/informers.** Polling (scan + drift pass) is the delivery
   mechanism; a watch-based feed would be a new ADR.

## Consequences

**Positive**

- `Degraded` and `Failed` are reachable and tested; phases tell the
  truth about actuation.
- Drift is observable (annotation + audit + event + metric) and
  self-healing through one audited Apply path.
- Provider authors write ~200 lines of pure logic; control-plane
  policy stays in one place.
- Zero dependencies; the Docker client is auditable stdlib.

**Negative**

- Retry book is in-memory: a daemon restart forgets attempt counts and
  backoff schedules (documented above; durable bookkeeping awaits the
  ADR-0001 engine).
- Polling inspect costs one Engine round trip per actuated Ready
  resource per drift interval — fine at reference scale, a re-evaluation
  trigger at larger scale.
- Recreate-on-update means a brief downtime per spec change of an
  actuated Application; rolling updates are workflow territory.
- Two status surfaces now change for actuated kinds (phase by the
  worker, message annotation by the drift pass) — bounded by the
  transition-only rule for annotations.

**Neutral**

- The webhook dispatcher keeps its private retry loop; migrating it
  onto this taxonomy is a later, mechanical issue.
- `Caps.Name` gives status messages/metrics a stable provider label;
  future providers register alongside it in the same registry.

## Re-evaluation triggers

Re-open this ADR when any of these becomes true:

1. A second replica of `ryvexd` must run against one store → implement
   the lease/leader-election seam (ADR-0001's claim machinery).
2. Any actuator needs watches, finalizers or cross-resource ordering
   → the thin SPI is no longer sufficient.
3. Drift passes dominate Engine/API load (measure `Inspect` latency ×
   actuated Ready count vs interval) → event-driven drift or sharded
   drift workers.
4. A provider needs non-JSON specs or binary payloads → extend `Plan`
   explicitly rather than smuggling bytes through `map[string]any`.

## References

- Issue #80 — provider SPI + real actuators + drift detection
- [ADR-0001](0001-durable-workflow-engine.md) — durable workflow engine
  (the lease seam and the workflow step client)
- `internal/reconcile/reconcile.go` — scan + worker pool + evaluate hook
- `internal/provider/provider.go` — the SPI as implemented
- `internal/provider/docker/` — reference provider (tag `docker`)
- `agent/ryvex-agent/src/client.rs` — `Outcome` taxonomy this ADR aligns with
