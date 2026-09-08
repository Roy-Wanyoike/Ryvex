# ryvex (TypeScript SDK)

Official TypeScript client for the **Ryvex control plane REST API** — the
`/v1` face documented in [`docs/api-contracts.md`](../../docs/api-contracts.md)
(frozen contract). Works in Node 18+, Bun, Deno and browsers. Ships ESM +
CommonJS builds with full TypeScript types.

## Install

```bash
bun add ryvex        # or: npm install ryvex
```

## Quickstart

```ts
import { Ryvex, RyvexError } from "ryvex";

const ryvex = new Ryvex({
  baseUrl: "http://127.0.0.1:8080", // ryvexd listen address
  token: process.env.RYVEX_TOKEN!,  // bearer key, ryk_…
});

// Liveness (no auth required server-side)
const health = await ryvex.health();          // { status: "ok", version: "v1.0.0", … }

// Declarative create — the reconciler takes it from there
const app = await ryvex.createResource({
  kind: "Application",
  org: "acme",
  project: "core",
  env: "prod",
  name: "checkout",
  labels: { team: "payments" },
  spec: { image: "registry.acme.io/checkout:1.42.0", replicas: 4 },
});
console.log(app.id, app.status.phase);        // r-…  Pending → Ready

// Fetch by handle or by logical address
await ryvex.getResource(app.id);
await ryvex.getInScope("acme", "core", "prod", "applications", "checkout");
```

Every request carries `Authorization: Bearer <token>` and
`Content-Type: application/json`. Custom runtimes can inject their own
transport via `new Ryvex({ baseUrl, token, fetch })`.

## Client options

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `baseUrl` | `string` | — (required) | Root of the daemon, e.g. `http://127.0.0.1:8080`. The `/v1` prefix is appended per call. |
| `token` | `string` | — (required) | Bearer token (`ryk_…`). |
| `fetch` | `typeof fetch` | `globalThis.fetch` | Custom transport (required on Node < 18). |
| `timeoutMs` | `number` | `15000` | Per-request timeout in milliseconds. Uses `AbortSignal.timeout` with an `AbortController` fallback on older runtimes. `0` disables the client-side timeout. |

Every public method also accepts a trailing `{ signal }` object for
per-call cancellation — see [Timeouts & cancellation](#timeouts--cancellation).

## Optimistic concurrency (CAS)

`status` and `generation` are **server-owned**. `generation` increments
only when `spec`/`labels` actually change. Include the generation you
last read in a scope-addressed PUT to fail instead of clobbering:

```ts
const current = await ryvex.getInScope("acme", "core", "prod", "applications", "checkout");

// wins: stored generation still matches what we read
const updated = await ryvex.putInScope(
  "acme", "core", "prod", "applications", "checkout",
  { generation: current.generation, spec: { ...current.spec, replicas: 5 } },
);
console.log(updated.generation); // +1

// loses: someone wrote first → RyvexError 409 "conflict"
try {
  await ryvex.putInScope(
    "acme", "core", "prod", "applications", "checkout",
    { generation: current.generation, spec: { replicas: 6 } }, // stale
  );
} catch (err) {
  if (RyvexError.is(err) && err.code === "conflict") {
    console.error(`lost the race (status ${err.status}), re-read and retry`);
  }
}
```

Omit `generation` for last-writer-wins semantics.

## Pagination

`listResources` returns one cursor page (`next_cursor === ""` marks the
end); `listAll` walks every page lazily as an async generator — one HTTP
request per `for await` turn:

```ts
// one page at a time
const page = await ryvex.listResources({ org: "acme", kind: "applications", limit: 100 });
for (const r of page.items) console.log(r.id);
if (page.next_cursor) { /* fetch the next page with cursor: page.next_cursor */ }

// or stream everything
for await (const r of ryvex.listAll({ org: "acme", env: "prod" })) {
  console.log(`${r.kind}/${r.name} gen=${r.generation}`);
}
```

## Timeouts & cancellation

Every request is bounded by the client's `timeoutMs` (default **15 s**
— Node's fetch can otherwise stall for minutes) and by an optional
per-call `AbortSignal`; whichever fires first cancels the request.
Cancellations reject with a `RyvexError` of `code: "timeout"`,
`status: 0`, distinguishable from connection-level failures
(`code: "transport_error"`):

```ts
const ryvex = new Ryvex({ baseUrl, token, timeoutMs: 10_000 }); // per-client default

// per-call cancellation
const ac = new AbortController();
const timer = setTimeout(() => ac.abort(), 5_000);   // give up after 5 s
try {
  const page = await ryvex.listResources({ org: "acme" }, { signal: ac.signal });
} catch (err) {
  if (RyvexError.is(err) && err.code === "timeout") {
    console.error("cancelled:", err.message);        // "… was aborted by the caller"
  } else {
    throw err;
  }
} finally {
  clearTimeout(timer);
}
```

Compatibility notes: on runtimes without `AbortSignal.timeout`
(Node < 17.3, older browsers) the SDK falls back to an
`AbortController` + timer; where `AbortSignal.any` is missing, the
caller's signal is relayed with event listeners. No polyfill is needed
and there are zero runtime dependencies.

## Error handling

All non-2xx responses throw a `RyvexError` parsed from the frozen
envelope `{"error":{code,message,request_id,details}}`. If the body
isn't the envelope (proxy HTML, empty body), the code is inferred from
the HTTP status so you can always branch on it:

| HTTP | `err.code` |
| ---- | ---------- |
| 0 (no response) | `timeout` (client timeout / caller abort) or `transport_error` (connection failed) |
| 400  | `validation_failed` / `bad_request` |
| 401  | `unauthorized`         |
| 403  | `forbidden`            |
| 404  | `not_found`            |
| 405  | `method_not_allowed`   |
| 409  | `already_exists` / `conflict` |
| 500  | `internal_error`       |

```ts
import { RyvexError } from "ryvex";

try {
  await ryvex.deleteResource("r-does-not-exist");
} catch (err) {
  if (RyvexError.is(err)) {
    console.error(`${err.status} ${err.code}: ${err.message}`);
    console.error(`request id: ${err.requestId}`);   // quote this in bug reports
    if (err.details.length > 0) console.error("details:", err.details);
  } else {
    throw err;
  }
}
```

Transport failures (DNS, refused connections, socket resets) are wrapped
as `RyvexError` with `status: 0` and `code: "transport_error"` — the
same code the Python SDK uses. Timeouts and caller-initiated aborts are
reported as `code: "timeout"`. One error type to catch everywhere.

## API surface

| Method | Endpoint touched | SDK call |
| ------ | ---------------- | -------- |
| GET | `/healthz` | `health()` |
| GET | `/v1` | `index()` |
| POST | `/v1/resources` | `createResource(doc)` |
| GET | `/v1/resources?org=&…` | `listResources(opts)` / `listAll(opts)` |
| GET | `/v1/resources/{id}` | `getResource(id)` |
| DELETE | `/v1/resources/{id}` | `deleteResource(id)` |
| GET | `/v1/{org}/{project}/{env}/{kind}/{name}` | `getInScope(…)` |
| PUT | `/v1/{org}/{project}/{env}/{kind}/{name}` | `putInScope(…, doc)` |
| DELETE | `/v1/{org}/{project}/{env}/{kind}/{name}` | `deleteInScope(…)` |
| GET | `/v1/{org}/events?limit=` | `events(org, { limit })` |
| GET | `/v1/{org}/audit?kind=&limit=` | `audit(org, { kind, limit })` |
| POST | `/v1/{org}/reconcile/{id}` | `triggerReconcile(org, id)` |

Every method takes an optional trailing `{ signal: AbortSignal }` for
per-call cancellation.

## Development

```bash
bun install          # install devDependencies
bun run typecheck    # tsc --noEmit
bun test             # unit tests (mocked fetch, no network)
bun run build        # ESM + CJS into dist/

# live integration test against a local daemon
go build -o /tmp/ryvexd ./cmd/ryvexd   # from the repo root
/tmp/ryvexd serve --http 127.0.0.1:18201 --dev-auth --seed --log-level error &
RYVEX_INTEGRATION=1 RYVEX_TEST_API=http://127.0.0.1:18201 \
  RYVEX_TEST_TOKEN=ryk_local_dev bun test test/integration.test.ts
```

Apache-2.0 — see [LICENSE](../../LICENSE).
