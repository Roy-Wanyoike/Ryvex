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

## Build & test commands per surface

**Control plane + CLI (Go, repo root):**

```bash
go build ./... && go vet ./... && go test ./...
go run ./cmd/ryvexd serve --dev-auth --seed   # local daemon on :8080 (loopback only)
go run ./cmd/ryvex --help                     # CLI
```

Durable backends have parity suites that activate when the DSNs are
provided (see `internal/state/pgstore` and `internal/bus/natsbus`).

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
cd agent/ryvex-agent && cargo build --release && cargo test && cargo clippy -- -D warnings
```

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
