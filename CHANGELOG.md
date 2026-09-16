# Changelog

All notable changes to Ryvex are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are reconstructed from the git history and the shipped ledger in
`docs/roadmap.md` — every line below links back to a real change.

## [Unreleased]

### Added

- `ryvex list` pagination and CAS-guarded `ryvex apply --generation` (#51)
- TypeScript SDK: request timeouts, `AbortSignal` support, `forbidden` /
  `transport_error` error codes, CJS type declarations (#52)
- Packaging: multi-stage Dockerfile and complete compose stack — Postgres +
  ryvexd (+ NATS profile), non-root image with healthcheck (#35 → #58)
- Onboarding artifacts: four example manifests, `.env.example`, k8s
  manifests, CONTRIBUTING / SECURITY / CODEOWNERS, dependabot config,
  pinned bun.lock (#48 → #60)
- QA report: GA-readiness assessment — audit ledger, quality gates,
  onboarding verdict (verdict later superseded by the 2026-09-16 audit
  in `docs/audit/`; see #78) (#67 → #68)
- Deploy: publishable images (`ghcr.io/roy-wanyoike/ryvexd` +
  `ryvex-agent`, release workflow spec on `v*` tags), agent Dockerfile
  + compose `agent` profile, k8s DaemonSet for the node agent, and tag
  parameterization via `deploy/k8s/kustomization.yaml` (#76)
- k8s hardening: startupProbe on `/readyz` (migrations no longer race
  liveness), NetworkPolicy (default-deny both ways around ryvexd),
  PDB (`minAvailable: 1`), non-root Postgres StatefulSet (UID 999,
  fsGroup, caps dropped), configurable DSN sslmode
  (`RYVEX_PG_SSLMODE`, `verify-full` example), agent DaemonSet + all 9
  `RYVEX_AGENT_*` vars in `.env.example`, `docs/deploy.md` (#76)

### Changed

- Docs truth sync: Postgres durability section, `/v1/keys` + 13 kinds +
  `?from=` in the frozen contract, kind-count and console read/write
  contradictions resolved, roadmap ledger made truthful (#47 → #64)

### Fixed

- `ryvexd`: helper unit tests, seed idempotency, boot-flag validation (#50)
- API hardening: cursor propagation, 405/413 handling, server timeouts,
  security headers, dev-auth guard, constant-time static-key comparison,
  version plumbing into `/healthz` and the `/v1` index (#54)
- Console: truthful Live/Demo states, configurable org, error boundary,
  pagination, request timeouts, refresh control (#55)
- Rust node agent: panic path, hostname reporting, heartbeat churn,
  client-state coverage (#56)
- Python SDK: `403` modeled as `forbidden`; `transport_error` documented
  as the cross-SDK standard (#45 → #57)
- Reconciler: cursor-paged scan past the 200-resource list ceiling, with
  a stuck-cursor guard (#37 → #59)
- NATS bus: publish metric counts only server-acknowledged successes
  (#40 → #61)
- State store: 64-bit pagination cursors (legacy-decodable), bounded
  Postgres pool, ListAudit SQL and swallowed-error fixes, parity cases
  (#39 → #62)
- Console: accessibility (drawer focus trap, ARIA), responsive tables,
  token hygiene (no baked default token), clipboard buttons, data-driven
  kind chips, topology scoping (#42 → #63)
- Webhook test flake: wait for the audit trail, not the wire, before
  asserting attempts (TOCTOU under `-race`) (#65 → #66)

### Security

- Webhook SSRF egress guard: private/loopback/CGNAT range blocking,
  dispatch-time DNS revalidation, redirect denial (#36 → #53)

## [1.1.0] — 2026-09-08

### Added

- TypeScript SDK for the `/v1` API face — ESM + CJS, typed, zero runtime
  dependencies (#20)
- `ryvex` CLI: `apply`, `get`, `delete`, `events`, `audit`, `reconcile`,
  `health` (#21)
- Console writes: resource editor, CAS-aware saves, settings, toasts (#22)
- Durable webhook subscriptions with signed, retried, audited deliveries (#23)
- Prometheus metrics sidecar: HTTP, reconciler, bus, and resource
  instruments (#24)
- Python SDK with typed dataclass models — stdlib-only runtime (#25)
- Postgres state backend with parity-tested semantics against the
  in-memory store (#26)
- NATS JetStream event bus backend with durable replay across restarts (#27)
- Org/project-scoped RBAC with managed `ryk_` API keys (#30)
- Rust data-plane node agent: enrollment, heartbeats, self-healing (#31)
- Roadmap shipped ledger and README project map (#32)

### Fixed

- Reconciler shutdown race and `DeepCopy` spec-map aliasing found by the
  race detector (#29)

## [1.0.0] — 2026-09-08

### Added

- Control plane core: CAS state store with audit trail, in-memory event
  bus, reconciler loop, REST API (`/v1`), and the `ryvexd` daemon (#1)
- Web console: Overview / Resources / Topology / Events / Audit views,
  live and demo modes (#3)
- Architecture notes and the frozen REST API contract (`docs/`) (#5)
- Project README with console screenshots, Apache-2.0 license (#7)

[Unreleased]: https://github.com/Roy-Wanyoike/Ryvex/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Roy-Wanyoike/Ryvex/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Roy-Wanyoike/Ryvex/releases/tag/v1.0.0
