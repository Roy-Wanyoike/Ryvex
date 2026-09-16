# ADR-0001: Durable workflow engine — in-process durable execution on Postgres

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** Ryvex maintainers (issue [#82](https://github.com/Roy-Wanyoike/Ryvex/issues/82))
- **Supersedes:** nothing. This is the first ADR; it closes a gap the
  architecture docs named ("Temporal") without ever deciding it.

## Context

Ryvex is a cloud control plane whose thesis is *durable infrastructure
operations*: every piece of infrastructure is declarative state, continuously
converged. The intended architecture (docs/audit/03-architecture-evolution.md)
names **Temporal** for durable infrastructure workflows — multi-step
provisioning, retries, compensation, rollback.

The reality, pickaxe-verified across every ref
(docs/audit/01-git-archaeology.md):

- `git log --all -S temporal` → **0 commits ever**. Not even an abandoned
  experiment. Temporal is a documentation claim, not a codebase fact.
- The longest-running operation in the system today is the webhook
  dispatcher's **in-process retry loop**
  (`internal/webhook/dispatcher.go`): per-subscription bounded queue
  (256), exponential backoff 1s→2s→4s… capped at 60s, up to `max_retries`
  attempts, 5s per-attempt timeout. All retry state — queue contents,
  attempt counters, backoff position — lives in process memory. A daemon
  crash loses every pending delivery; the audit log remembers the
  attempts but nothing resumes them.
- The reconciler (`internal/reconcile/reconcile.go`) is a fixed-interval
  scan (30s default) with a bounded worker pool. It advances
  `Pending → Provisioning → Ready` one phase per scan pass. Crash safety
  comes from re-scanning state, not from durable progress: multi-step
  side effects *between* status writes have no record and no resume.

So the actual execution reality is: **short in-process loops with no
durability across restarts**, in a **single Go binary** whose only durable
backends are **Postgres** (state store, embedded migrations, parity-tested)
and **NATS JetStream** (event bus, optional). Deployment story:
`ryvexd serve` — one process, optionally one Postgres, optionally one NATS.

Before any workflow code exists, the decision must be written down.

## Requirements

What "durable workflow execution" must mean for Ryvex, concretely:

1. **Operation duration ranges.** Operations split into three bands:
   - **Sub-second** (status stamping, CAS writes, event publish): in-request,
     no durability machinery needed — today's behavior is correct.
   - **Seconds to ~15 minutes** (the first real workflows: application
     deploy, database provision, webhook delivery chains): must survive
     daemon restarts, resume from the last completed step, respect
     per-step timeouts and an overall deadline.
   - **15 minutes to hours/days** (long rollouts, migrations, interactive
     approvals): not a day-one requirement; a re-evaluation trigger below.
2. **Failure recovery.** A crash, deploy or OOM-kill mid-workflow must
   leave a persisted record such that, on next boot, the run resumes at
   the right step — at-least-once step execution, with idempotency making
   redelivery harmless. Every attempt and transition audited (design
   principle: "everything is audited").
3. **Worker lifecycle.** Workers are goroutines today; they die with the
   process. Durable execution needs work *claims* that outlive workers:
   a run claimed transactionally, heartbeat/lease to detect abandoned
   runs, and a boot sweep that reclaims interrupted runs.
4. **Operational cost for single-binary deployments.** The product's
   deployment floor is one binary. Any engine that adds a mandatory
   cluster (or a mandatory second datastore) breaks the floor. Dev mode
   (in-memory store) must degrade explicitly and honestly, the same way
   the state store and bus already do — never silently.
5. **Ecosystem fit.** Go-only codebase, stdlib-first ethos ("boring,
   explicit infrastructure"), two direct dependencies in go.mod
   (`lib/pq`, `nats.go`). The engine must be auditable in-repo and
   testable with the existing parity-suite convention.

## Options considered

### Option A — Temporal

Adopt Temporal: embed its Go SDK, run (or require) a Temporal service,
execute workflows as replayable goroutine code on Temporal workers.

| Dimension | Assessment |
|---|---|
| Durability guarantees | Best-in-class: event-sourced history, replayable workflows, durable timers/signals, at-least-once activities with built-in dedupe |
| Recovery | Automatic resume from history; crash of worker or server both survivable |
| Worker lifecycle | Separate worker fleet concept; task queues, worker versioning — real machinery, but more concepts to operate |
| Operational cost (single binary) | **Disqualifying today.** Minimum viable footprint is a Temporal server plus its datastore (Postgres/MySQL/Cassandra), typically + UI, plus our worker process — 2–4 extra long-running components. The "one binary + optional Postgres" floor becomes "one binary + mandatory distributed system" |
| Ecosystem fit | Mature Go SDK, excellent engine — but Ryvex *is* a control plane; running a second control plane to be a control plane inverts the product. Adds a heavy dependency to a 3-dependency repo |
| Fit to current scale | Overkill: zero workflows exist; first workflows are ≤ 5 steps, minutes-scale |

### Option B — In-process durable execution on Postgres (decided)

A small `internal/workflow` package: a workflow is a named sequence of
idempotent steps; a *run* is a persisted row (state machine: Pending →
Running step N → Done/Failed/Canceled); steps execute on the existing
reconciler-style worker pool; all progress lives in Postgres via the
existing store/migration conventions. Durability rides the existing
`--store postgres` flag; memory mode is explicitly best-effort (dev only),
mirroring today's store/bus boot semantics.

| Dimension | Assessment |
|---|---|
| Durability guarantees | At-least-once step execution; run/step state transactional in Postgres; exactly-once effects achieved per-step via idempotency keys (run ID + step + generation). No event-sourced replay — state, not history, is the source of truth (the audit log covers the history) |
| Recovery | Boot sweep resumes interrupted runs; lease/heartbeat expiry detects abandoned claims; per-step retry with backoff under an overall deadline |
| Worker lifecycle | Claims are rows, not goroutine state: crash-safe, and the lease model extends to multi-replica later without a redesign |
| Operational cost (single binary) | **Zero new processes** when Postgres is already enabled; memory mode degrades exactly like the store/bus already do. Engine is in-repo, auditable, ~one package |
| Ecosystem fit | Uses shipped primitives: embedded migrations, CAS generations, append-only audit log, bounded worker pool, bus events. Stdlib-style code the repo already tests with parity suites |
| Fit to current scale | Matches the actual band: seconds-to-minutes, low concurrency, ≤ ~30 steps |

### Option C — Deferred

Decide nothing; keep building features on ad-hoc loops (the webhook
pattern) until a workflow need "forces" the question.

| Dimension | Assessment |
|---|---|
| Durability guarantees | None beyond the audit log; retry state dies with the process |
| Recovery | None: crash = lost work (webhook deliveries pending at crash are gone) |
| Worker lifecycle | Status quo: goroutines + in-memory queues |
| Operational cost (single binary) | Zero now, growing later: every multi-step feature re-implements durability badly |
| Ecosystem fit | Compatible with everything, commits to nothing |
| Fit to current scale | Fine for today, but issue #82 exists precisely because the *next* feature (deployment controller, rollout strategies) is a multi-step workflow |

## Decision

**Option B — in-process durable execution, backed by Postgres.**

Rationale, in one line each:

1. **The footprint rules Temporal out today.** Ryvex's deployment floor is
   one binary; Temporal's floor is a cluster. A product whose thesis is
   *being* the durable control plane cannot make another control plane a
   mandatory dependency for its first workflow.
2. **Postgres already exists and already carries the hard parts.** Embedded
   migrations, CAS generations, an append-only audit log and a
   parity-tested store backend are exactly the primitives a
   step-durability engine needs; the reconciler's worker-pool + scan +
   `evaluate`-hook shape is already the right executor skeleton.
3. **The actual workload fits.** Every operation in the repo today is
   seconds-to-minutes with bounded concurrency. At-least-once steps +
   idempotency keys + leases cover that band honestly; anything beyond it
   trips explicit re-evaluation triggers (below), not vibes.

This decision does **not** delete or rewrite anything: the webhook
dispatcher's in-memory retry loop stays as-is until a later issue
migrates it onto the engine (that migration must preserve the frozen
webhook wire contract and egress guard). The deployment controller in the
roadmap (rolling / blue-green for Application kind) is the engine's first
client, and the workflow below is its acceptance vehicle.

## First concrete workflow: Application deploy

The acceptance vehicle for the engine. Trigger: an Application resource
whose `status.observed_generation < generation` (the reconciler's existing
convergence signal). Run identity = `(resource ID, generation)` — at most
one run per generation, which is also the global idempotency key.

Steps (each must be idempotent and resumable):

| # | Step | Effect | Per-step timeout | Retry | On exhaustion |
|---|------|--------|------------------|-------|---------------|
| 1 | `pre-checks` | Validate spec; verify referenced resources exist and are Ready (Environment, Cluster, Database); enforce quota/policy | 30s | 3 attempts, 10s base backoff (2×) | Run → `Failed` (fatal: validation errors are not retried at all) |
| 2 | `provision` | Allocate/mutate dependencies (create/update Database resource, request agent action); all writes CAS'd on generation | 5 min | 3 attempts, 10s base backoff (2×), capped 2 min | Run → `Failed`; compensation runs |
| 3 | `verify` | Poll readiness (dependency phase Ready / agent heartbeat / health probe) until success or deadline | 10 min overall | Poll loop (15s interval) inside the step; store error → 3 attempts | Run → `Failed` (deadline) with audit reason |
| 4 | `mark-ready` | CAS `UpdateStatus(Ready, observed_generation = generation)` | 30s | 3 attempts; CAS `409` → re-read: generation moved → abandon run as `Superseded` (a newer run owns the resource), audit | Run → `Failed` |

**Overall run deadline:** 20 minutes (configurable per workflow kind).
Exceeded → cancel in-flight step, run compensation, run → `Failed`
(`deadline_exceeded`).

**Failure semantics:**

- **Retry.** Per-step exponential backoff; only transient errors (store
  unreachable, dependency not-yet-converged) retry. Deterministic errors
  (validation, missing reference) fail fast — retrying them is lying.
- **Timeout.** Per-step timeout and overall deadline both enforced from
  the durable run record (recomputed on resume, not left in memory).
- **Compensation.** Steps declare an undo; on run failure, undos execute
  in reverse order over completed steps, best-effort, each audited.
  Compensation failure leaves the run `Failed (compensation_incomplete)`
  plus audit entries — never silent, never half-denied.
- **Idempotency.** Every step re-execution first checks its effect keyed
  by `(run ID, step, generation)`; a completed step is a no-op on resume.
  External effects carry the run ID as their idempotency handle.
- **Cancellation.** User cancellation (resource delete / explicit cancel)
  writes `Canceled` to the run row; every step checks run state before
  and after its work; in-flight external calls receive context
  cancellation, the step is marked `Interrupted`, and compensation runs.
  Daemon shutdown behaves identically (the existing graceful-shutdown
  path cancels workers); the boot sweep resumes `Interrupted` runs.
- **Claiming & leases.** A run step is claimed with a transactional
  conditional update (compare-and-set on run state + lease timestamp);
  a heartbeat refreshes the lease; a boot sweep reclaims runs whose
  lease expired — which is also the seam for multi-replica execution
  later.
- **Observability.** Every step transition publishes a bus event
  (`ryvex.workflow.*`, same grammar as resources) and appends an audit
  entry. The console can watch a deploy step-by-step for free.

## Consequences

**Positive**

- The single-binary deployment story is preserved; durable workflows
  require nothing beyond the existing `--store postgres` opt-in.
- Durability is built from primitives the repo already ships, tests and
  documents (embedded migrations, parity suites, audit log, CAS) — the
  engine is small and auditable in-repo.
- The reconciler's `evaluate` hook becomes the natural integration seam;
  the deployment controller (roadmap, Active) gets a real substrate
  instead of ad-hoc loop #2.
- Honest degradation: memory mode is explicitly non-durable, matching the
  established store/bus boot semantics rather than inventing a new rule.

**Negative**

- Hand-rolled means hand-maintained: no event-sourced replay, no durable
  push-based timers/signals, no cross-language workflow authoring. Waits
  are poll-based against Postgres; that burns cheap cycles but does not
  scale to thousands of concurrent long runs.
- Compensation logic is per-workflow and hand-written; Temporal would
  still not write it for us, but its signal/child-workflow machinery
  makes complex graphs easier.
- One more state machine to test — mitigated by the repo's parity-suite
  convention (memory vs Postgres behavior identical).
- Webhook delivery durability remains a known gap until the migration
  issue lands; this ADR only requires the engine be able to express it.

**Neutral**

- NATS stays optional and unrelated to workflow durability: the engine
  depends only on the store. #81 (JetStream durable consumers/DLQ) is
  complementary event-log work, not an alternative to this decision.

## Re-evaluation triggers

Re-open this ADR (and seriously re-evaluate Temporal or an equivalent)
when **any** of these becomes true — measured, not predicted:

1. Any production workflow regularly exceeds **15 minutes** wall-clock or
   needs **more than ~30 steps** in a single run.
2. **Complex compensation graphs** are required — conditional rollback
   across more than two dependent resources, or cross-workflow
   coordination (signals, interactive approvals that push rather than
   poll).
3. Sustained concurrency beyond **~100 concurrent runs** or fan-out where
   Postgres polling cost measurably dominates step execution.
4. A **multi-replica HA control plane** ships and lease-based claiming
   proves insufficient for distribution — Temporal's task queues would
   provide distribution for free at exactly that point.
5. Workflow authoring is needed from **a second language** or by
   external users (Temporal's polyglot SDKs become the cheap path).

## References

- Issue #82 — this decision (durable workflow engine ADR)
- docs/audit/01-git-archaeology.md — Temporal pickaxe evidence (0 commits)
- docs/audit/03-architecture-evolution.md, 06-gap-analysis.md — the gap
- `internal/reconcile/reconcile.go` — current execution model (scan +
  worker pool + `evaluate` hook)
- `internal/webhook/dispatcher.go` — the in-process retry loop this ADR
  must eventually absorb
- Issue #81 — JetStream durable consumers (complementary, not alternative)
