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

## Modes

The console runs in two modes:

- **Live** — set `NEXT_PUBLIC_RYVEX_API` (and optionally
  `NEXT_PUBLIC_RYVEX_TOKEN`) at build time and the console talks to a
  running `ryvexd` over its `/v1` REST API, refreshing every 15s.
- **Demo** — with no API configured it renders an embedded snapshot that
  mirrors the `ryvexd --seed` dataset, so the UI is always reviewable.

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

The console is read-only by design: writes go through the Ryvex REST API
(see `docs/api-contracts.md`), which the console consumes like any other
client — with bearer `ryk_` keys.
