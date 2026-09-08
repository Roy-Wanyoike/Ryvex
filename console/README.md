# Ryvex Console

The web console for the [Ryvex](https://github.com/Roy-Wanyoike/Ryvex) cloud
control plane — a real-time control surface over `ryvexd`, the declarative
infrastructure daemon.

![Ryvex Console](https://img.shields.io/badge/Next.js-15-black) ![Tailwind](https://img.shields.io/badge/Tailwind-4-38bdf8) ![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6)

## Views

| View | What it shows |
|------|---------------|
| **Overview** | Fleet KPIs, phase-distribution donut, live event feed |
| **Resources** | Every declarative resource, searchable and filterable by kind |
| **Topology** | Cluster → nodes / applications / data services map |
| **Events** | The `ryvex.resource.*` bus stream as it happens |
| **Audit** | Every mutation, attributed to the actor that made it |
| **Settings** | API base URL, token and scope (org/project/env), with a connection test |

## Modes

The console runs in two modes:

- **Live** — set `NEXT_PUBLIC_RYVEX_API` (and optionally
  `NEXT_PUBLIC_RYVEX_TOKEN`) at build time, or configure base URL,
  token and scope at runtime in the Settings view, and the console
  talks to a running `ryvexd` over its `/v1` REST API, refreshing
  every 15s. Health badges are truthful: a failed read shows
  `degraded` (last good snapshot) or `error` — never a fake "Live".
- **Demo** — with no API configured it renders an embedded snapshot
  that mirrors the `ryvexd --seed` dataset, so the UI is always
  reviewable. Demo mode is read-only; mutations surface an info toast.

```bash
# live against a local daemon (daemon needs --cors-origins http://localhost:3100)
NEXT_PUBLIC_RYVEX_API=http://127.0.0.1:8080 bun run build
bun run start          # http://localhost:3100

# demo snapshot
bun run dev
```

## Development

```bash
bun install
bun run dev      # http://localhost:3100
bun run build    # production build (includes lint + type check)
bun run lint
```

## Stack

- **Next.js 15** (App Router) + **React 19**
- **Tailwind CSS 4**
- **TypeScript strict**

The console reads **and writes** through the Ryvex REST API (see
`docs/api-contracts.md`) like any other client — with bearer `ryk_`
keys. The resource drawer edits specs and labels with CAS-aware saves
(the PUT echoes the `generation` it read, so a stale writer gets `409`
with an inline reload), and resources can be deleted. Reads are
paginated (up to 1,000 resources) and every request is bounded by a
10s timeout.
