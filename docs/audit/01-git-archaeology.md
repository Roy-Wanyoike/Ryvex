# 01 — Git Archaeology Report

**Audit date:** 2026-09-16 · **Auditor:** autonomous engineering audit team · **Repo:** https://github.com/Roy-Wanyoike/Ryvex · **HEAD at audit:** `main @ 0108c20b`

## 1. Method

The complete ref space was recovered and inspected: `main` plus every PR head (`refs/pull/*/head`, 35 refs total). Evidence gathering used `git log --all --graph`, `--name-status`, `--diff-filter=D`, rename detection (`-M`), pickaxe searches (`-S` across every commit), `git grep` over `git rev-list --all`, `git fsck --lost-found`, reflog, tag and stash enumeration. No repository state was modified during discovery.

> **Environment note (disclosed per audit rules):** the previous local workspace was lost to an environment reset between sessions. The repository was recovered by cloning the GitHub remote, which preserved the entire history and all PR refs — nothing in the Git record was lost. All statements below are derived from the recovered Git objects, not from memory.

## 2. Repository shape

- **34 commits** on `main`, **all authored on 2026-09-08** (first `af95b95` 08:54:54 UTC, last `0108c20b` 16:31:31 UTC) — the entire project was built in a single day through an issue → branch → PR pipeline (33 PRs, all merge-committed, all issue-linked).
- **Zero deleted files, zero renames, zero tags, zero stashes, zero dangling objects** (`git fsck` clean; `--diff-filter=D` empty; `-M` summary empty). The history is strictly additive: nothing was ever removed, reverted, or replaced. There is no "lost feature" to recover — every capability that ever existed still exists at HEAD.
- No branch other than `main` survives as a ref (PR heads are archival pointers, their content is fully contained in `main` via merge commits).

## 3. Commit timeline (verified via `git log --reverse`)

| # | Commit | UTC time | Subject (PR) |
|---|--------|----------|--------------|
| 1 | `af95b95` | 08:54 | feat(control-plane): state store, event bus, reconciler, REST API, ryvexd daemon (#1) |
| 2 | `11ab642` | 12:40 | feat(console): web console + CORS middleware (#4) |
| 3 | `cd301e8` | 12:40 | docs: architecture, frozen REST API contract, issue-driven roadmap (#6) |
| 4 | `2bbfeab` | 12:40 | docs: recruiter-facing README + Apache-2.0 (#8) |
| 5 | `1652ec4` | 12:56 | [ImgBot] Optimize images (#9) |
| 6 | `2dd7408` | 13:10 | feat(sdk): TypeScript client for the /v1 face (#20) |
| 7 | `1d5b881` | 13:10 | feat(cli): ryvex apply/get/delete/events/audit/reconcile/health (#21) |
| 8 | `a82ca71` | 13:42 | feat(console): resource editor, CAS-aware writes, settings + toasts (#22) |
| 9 | `227c11d` | 13:42 | feat(webhooks): durable subscriptions, signed deliveries, retries (#23) |
| 10 | `86bcedb` | 13:44 | feat(metrics): Prometheus exposition (#24) |
| 11 | `423646c` | 14:16 | feat(sdk): Python client, stdlib-only runtime (#25) |
| 12 | `bfe9f3e` | 14:28 | feat(store): Postgres backend, parity-tested (#26) |
| 13 | `3b58a75` | 14:31 | feat(bus): NATS JetStream backend, durable replay (#27) |
| 14 | `0c0d0df` | 15:12 | fix(race): reconciler shutdown race + DeepCopy aliasing (#29) |
| 15 | `d099185` | 15:13 | feat(authz): org/project-scoped RBAC, managed API keys (#30) |
| 16 | `934f53e` | 15:23 | feat(agent): Rust node agent — enrollment, heartbeats, self-healing (#31) |
| 17 | `79c54f0` | 15:24 | chore: v1.1.0 — shipped ledger, project map, version bump (#32) |
| 18 | `ea325a0` | 19:00 | test(ryvexd): helper units, seed idempotency, boot validation (#50) |
| 19 | `ebd4f11` | 19:00 | feat(cli): list + CAS apply --generation (#51) |
| 20 | `4a924c5` | 19:00 | feat(sdk-ts): timeout/AbortSignal, forbidden/transport_error, CJS types (#52) |
| 21 | `2d8ac01` | 19:00 | fix(console): operator trust — truthful Live/Demo, org config, error boundary (#55) |
| 22 | `ab08c70` | 19:00 | fix(security): webhook SSRF egress guard (#53) |
| 23 | `ee51f56` | 19:00 | fix(api): hardening batch — 11 findings (#54) |
| 24 | `0f82f9c` | 19:04 | fix(agent): correctness batch — panic path, hostname, heartbeat churn (#56) |
| 25 | `eccd06d` | 19:23 | fix(sdk-py): 403 forbidden + transport_error parity (#57) |
| 26 | `7718e34` | 19:23 | fix(reconcile): page the scan past the 200-resource limit (#59) |
| 27 | `737f560` | 19:23 | fix(natsbus): truthful publish metric (#61) |
| 28 | `e98f861` | 19:23 | fix(state): 64-bit cursors, bounded PG pool, ListAudit fixes (#62) |
| 29 | `245788c` | 19:23 | fix(console): a11y, responsive, token hygiene, clipboard (#63) |
| 30 | `d988b80` | 19:23 | feat(packaging): Dockerfile + compose stack (#58) |
| 31 | `c7a3c4a` | 19:23 | docs: truth sync — postgres, /v1/keys + 13 kinds (#64) |
| 32 | `30a7a4a` | 19:23 | feat(onboarding): examples, env template, k8s manifests, governance (#60) |
| 33 | `ff6a99d` | 19:27 | test(webhook): de-flake audit-retry assertions under -race (#66) |
| 34 | `0108c20` | 19:31 | docs(qa): GA-readiness report (#68) |

## 4. Pickaxe results (intended-stack components vs any commit, all refs)

| Term | Commits containing it (content match) | Verdict |
|---|---|---|
| `temporal` | **0** | never existed, not even as an abandoned experiment |
| `grpc` / `protobuf` | **0** | never existed |
| `keycloak` / `oidc` | **0** | never existed |
| `ebpf` | **0** | never existed |
| `opa` | 27 | **false positive** — matches "propagation/propagates"; no OPA engine anywhere |
| `opentelemetry` | 2 | **false positive** — Next.js optional peer dependency inside `console/bun.lock` only |
| `wasm` | 4 | **false positive** — transitive `wasm-bindgen` entries in `agent/ryvex-agent/Cargo.lock` (reqwest build targets), not a WASM runtime |
| `scheduler` | 2 | **false positive** — React's internal `scheduler` package in bun.lock |
| `nats` / `postgres` / `rust` | 25 / 25 / 20 | real implementations (see 02-feature-baseline) |
| `terraform` / `opentofu` / `helm` / `argocd` | 2 (docs commit `cd301e8` only) | mentioned in architecture docs as future; never implemented |

## 5. Findings

1. **The history is young, additive, and complete.** There are no removed, reverted, or replaced features; archaeology found no buried implementations. The interesting discoveries are *absences* (Temporal, gRPC, OPA, OTel, eBPF never existed in any commit) and *diseases present since the founding commit* (e.g. the `bus.Subscription.Cancel` wrong-element delete ships in `af95b95`, the founding commit, and survived every later commit — see 04-regressions).
2. **The development process is real and visible**: 33 PRs, each linked to issues, each merge-committing a reviewable unit, with a self-correction wave (commits 18–33) that fixed races, panics, SSRF, metric truthfulness, and flaky tests discovered by internal review.
3. **The final commit is a claim, not a gate.** `0108c20` adds `docs/qa-report.md` asserting GA-readiness whose load-bearing artifacts (a CI workflow on branch `feat/34-ci-pipeline`, a first agent compile, a published `v1.1.0` image) are absent from every ref. The audit re-verified every gate independently (see 07).
