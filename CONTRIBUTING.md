# Contributing to Ryvex

Thanks for helping build Ryvex. This document covers the development
environment, the build/test commands per surface, and the workflow rules
that keep concurrent contributions from colliding.

## Development environment

| Tool | Version | Needed for |
|------|---------|------------|
| Go | 1.24 | control plane (`cmd/ryvexd`), CLI (`cmd/ryvex`), all `internal/*` |
| Bun | latest stable | console toolchain (`console/`) and TS SDK tests (`sdk/ryvex-ts`) — **bun is the mandated console toolchain** |
| Node | 20+ | console runtime under Next.js |
| Rust | stable | node agent (`agent/ryvex-agent`) |
| Python | 3.10+ | Python SDK tests (`sdk/ryvex-py`, pytest) |
| Docker (optional) | — | `docker-compose.yml` starts the Postgres used by `--store postgres` |

## Quickstart (first clone)

```bash
git clone https://github.com/Roy-Wanyoike/Ryvex && cd Ryvex

go build ./... && go vet ./... && go test ./... -race -count=1   # control plane + CLI
cd console && bun install --frozen-lockfile && bun run build && cd ..   # console
cd sdk/ryvex-ts && bun install && bun test && cd ../..           # TS SDK
cd sdk/ryvex-py && pip install -e '.[dev]' && pytest -q && cd ../..  # Python SDK
cd agent/ryvex-agent && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test  # Rust agent
```

No services are required for the above — durable-backend parity suites
activate only when the DSNs below are exported.

## Build & test commands per surface

**Control plane + CLI (Go, repo root):**

```bash
go build ./... && go vet ./... && go test ./...
go run ./cmd/ryvexd serve --dev-auth --seed   # local daemon on :8080 (loopback only)
go run ./cmd/ryvex --help                     # CLI
```

Durable backends have parity suites that activate when the DSNs are
provided (see `internal/state/pgstore` and `internal/bus/natsbus`):

```bash
# with docker compose running the repo stack (postgres profile optional):
RYVEX_TEST_PG_DSN='postgres://postgres:postgres@127.0.0.1:5432/ryvex?sslmode=disable' \
RYVEX_TEST_NATS_URL='nats://127.0.0.1:4222' \
    go test ./internal/state/pgstore/... ./internal/bus/natsbus/... -race -count=1 -v
```

**Console (Next.js, `console/`):**

```bash
cd console && bun install && bun run build && bun run lint
```

**TypeScript SDK (`sdk/ryvex-ts/`):**

```bash
cd sdk/ryvex-ts && bun install && bun run build && bun test
```

**Python SDK (`sdk/ryvex-py/`):**

```bash
cd sdk/ryvex-py && pip install -e '.[dev]' && python3 -m pytest
```

**Node agent (Rust, `agent/ryvex-agent/`):**

```bash
cd agent/ryvex-agent && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

## Continuous integration — required checks

`.github/workflows/ci.yml` runs on **every push to `main` and every pull
request**; a newer push to the same ref cancels the stale run. Branch
protection on `main` requires all five jobs to pass — the required
status checks are the job names:

| Required check | Stack | What it runs |
|---|---|---|
| `go` | Control plane + CLI (Go) | `go build ./...`, `go vet ./...`, `go test ./... -race -count=1` with coverage artifact |
| `console` | Next.js console | `bun install --frozen-lockfile`, `next lint`, `tsc --noEmit`, `next build` |
| `sdk-ts` | TypeScript SDK | `bun install`, `bun test` |
| `sdk-py` | Python SDK | `pip install -e ".[dev]"`, `pytest -q` |
| `agent` | Rust node agent | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` |

The `go` job also runs the **live-backend parity suites**: it starts
`postgres:16` and `nats:2` (JetStream) service containers and exports
`RYVEX_TEST_PG_DSN` / `RYVEX_TEST_NATS_URL`, the exact env vars read by
`internal/state/pgstore/pgstore_test.go` and
`internal/bus/natsbus/natsbus_test.go`. A dedicated CI step fails the job
if those suites skip instead of run. The SDK live-daemon integration
tests (`RYVEX_INTEGRATION=1`) keep skipping cleanly in CI — they need a
running `ryvexd` and stay opt-in.

A failing required check blocks merge; fix forward (or explicitly
revert) rather than bypassing CI.

## Workflow: issues first, then branch, then PR

1. **Pick or open an issue.** Every change starts in the GitHub issue
   tracker — the roadmap in `docs/roadmap.md` is a map, the tracker is
   the truth. Claim the issue before you start.
2. **Branch from `main`** as `feat/<slug>`, `fix/<slug>` or
   `chore/<slug>`.
3. **Open a PR that closes the issue** with `Fixes #N` in the body.
   Include what changed, how you validated it, and any deviations.
4. **Keep CI green.** Every PR runs the per-surface commands above;
   ship complete, tested features only — a PR is a promise kept.

## Bounded-context ownership etiquette

Issues declare the exact files they own under a **Bounded context**
heading (see issue #48 for an example). This is how the project lets
multiple contributors work in parallel without stepping on each other:

- **Stay inside your issue's bounded context.** Files listed there are
  yours to create/edit; everything else is someone else's in-flight work.
- **Treat "Do NOT touch" lists as hard boundaries.** If your change
  genuinely requires a file outside your context, say so in the issue
  and coordinate with its owner first — don't surprise-edit.
- **Check `git log` / open PRs before starting** so you don't duplicate
  or conflict with work that is already landing.
- **Shared contracts** (`docs/api-contracts.md`, resource kinds in
  `internal/state`) are frozen or owner-gated; consumers adapt, they
  don't amend.

## Questions

Open a GitHub issue with the `question` label, or start a Discussion.
