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

### Fixed

- `ryvexd`: helper unit tests, seed idempotency, boot-flag validation (#50)
- API hardening: cursor propagation, 405/413 handling, server timeouts,
  security headers, dev-auth guard, constant-time static-key comparison,
  version plumbing into `/healthz` and the `/v1` index (#54)
- Console: truthful Live/Demo states, configurable org, error boundary,
  pagination, request timeouts, refresh control (#55)
- Rust node agent: panic path, hostname reporting, heartbeat churn,
  client-state coverage (#56)

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
