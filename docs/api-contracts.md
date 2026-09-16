# Ryvex REST API Contract (`/v1`)

> **Status: FROZEN for v1.** "Frozen" covers the wire shapes that
> already shipped: the error envelope and status-code mapping below,
> the resource document, the events/audit faces and the subject
> grammar. Additions are allowed (and have happened: key management
> under `/v1/keys`, the `?from=` event cursor); breaking changes
> require a new major version of the API surface.

## Conventions

- **Base path:** `/v1` on the `ryvexd` listen address.
- **Auth:** `Authorization: Bearer ryk_…` on every `/v1` route.
  `/healthz` is open but auth-tiered (see [Service](#service)).
- **Content type:** `application/json` everywhere. Request bodies are
  capped at **1 MiB**; larger bodies get `413 payload_too_large`.
- **Tracing:** every response carries `X-Request-Id`. A client-supplied
  ID is honored only when it is 1–64 characters of `[A-Za-z0-9._-]`;
  anything else — too long, whitespace, control bytes, quotes — is
  discarded and replaced with a fresh server-generated 12-hex-char id,
  so the value echoed into logs and error envelopes is always safe to
  interpolate (issue #84).
- **Trace IDs:** when the daemon runs with `--otlp-endpoint` set
  (OpenTelemetry tracing, issue #83), every response also carries
  `X-Ryvex-Trace-Id` — the W3C trace ID of that request's server span
  — and an incoming `traceparent` header continues the caller's trace
  instead of starting a root. `X-Request-Id` stays the audit
  correlation key: it rides the server span as the `request_id`
  attribute (so an audit entry's request ID locates its trace in any
  trace backend) and the access log carries both IDs. When tracing is
  disabled — the default — the header is absent, never empty, and
  `X-Request-Id` behaves exactly as below.
- **Security headers:** responses carry `X-Content-Type-Options:
  nosniff` and `X-Frame-Options: DENY`; `/v1` responses add
  `Cache-Control: no-store`.
- **Errors** always use the envelope:

```json
{
  "error": {
    "code": "conflict",
    "message": "generation conflict: resource was modified concurrently",
    "request_id": "e3b0c44298fc",
    "details": []
  }
}
```

| HTTP | `code` | When |
|------|--------|------|
| 400 | `validation_failed` | Resource/schema invalid (message names the field) |
| 400 | `bad_request` | Malformed cursor or query value |
| 401 | `unauthorized` | Missing/invalid bearer token |
| 403 | `forbidden` | RBAC denial (scope or admin-role check failed) |
| 404 | `not_found` | Unknown resource or route |
| 405 | `method_not_allowed` | Method not supported (sets `Allow`) |
| 409 | `already_exists` | Logical address already taken |
| 409 | `conflict` | CAS generation mismatch |
| 413 | `payload_too_large` | Request body exceeds the 1 MiB cap |
| 500 | `internal_error` | Bug or backend failure |

Status mapping is **`errors.Is`-based** (issue #84): the store's
sentinel errors (`ErrNotFound`, `ErrAlreadyExists`, `ErrConflict`,
`ErrBadRequest`, `ErrValidation`) are matched through their wrap chain,
and validation is matched with `errors.As` against
`*state.ValidationError`. An intermediate layer wrapping a sentinel —
`fmt.Errorf("pg insert: %w", err)` — still lands on the correct status
and code instead of falling through to a misleading `500
internal_error`. The `message` of a validation or bad-request error is
the wrapped error's text (it names the offending field); the other
mappings use fixed, non-leaking messages.

## Resource document

```json
{
  "id": "r-00b52b6eb859f432",
  "kind": "Application",
  "org": "acme", "project": "core", "env": "prod", "name": "checkout",
  "generation": 7,
  "labels": {"managed-by": "ryvex", "team": "payments"},
  "spec": {"image": "registry.acme.io/checkout:1.42.0", "replicas": 4},
  "status": {
    "phase": "Ready",
    "message": "converged to desired spec",
    "observed_generation": 7,
    "updated_at": "2026-09-08T09:00:00Z"
  },
  "created_at": "…", "updated_at": "…"
}
```

Rules:

- `kind` ∈ {Project, Environment, Application, Deployment, Cluster,
  Node, Database, Cache, Bucket, Policy, Secret, Subscription, APIKey}
  — **13 kinds**. `Subscription` models a signed webhook subscription
  (`spec.url`, `spec.subjects` patterns, `spec.active`, `spec.max_retries`
  0–10, default 5); `APIKey` is reserved for managed keys created
  through `/v1/keys`.
- `org` / `project` / `env` / `name`: 1–63 chars, `[a-z0-9-]`, must
  start and end alphanumeric. The org `ryvex` is reserved for managed
  API keys (they live only at `ryvex/system/system`); every other kind
  rejects it.
- Label keys/values: 1–63 chars, `[A-Za-z0-9._-]`.
- `spec` is required, JSON object, ≤ 64 KiB.
- `status` is **server-owned** (reconciler); client writes are ignored.
- `generation` increments only when `spec`/`labels` actually change.
- Kind matching in paths/queries is case-insensitive; simple plurals
  (`applications`) and `policies` are accepted.

## Endpoints

### Service

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness + version + dependency states (no auth required) |
| GET | `/readyz` | Readiness: `200 ready` only when store **and** bus answer a real query, else `503 unavailable` (issue #71) |
| GET | `/v1` | API index (machine-readable endpoint list) |

`/healthz` is **auth-tiered**. Anonymous callers — load balancers, k8s
probes, `ryvex health` without a token — get `status`, `service`,
`version`, `time` and the `dependencies` map; resource counts do not
leak without a key. A valid bearer token additionally returns
`resources` (store count) and `authenticated_as` (the principal):

```json
{ "status": "ok", "service": "ryvexd", "version": "v1.1.0", "time": "…",
  "dependencies": { "store": "ok", "bus": "ok" } }
```

```json
{ "status": "ok", "service": "ryvexd", "version": "v1.1.0", "time": "…",
  "dependencies": { "store": "ok", "bus": "ok" },
  "resources": 15, "authenticated_as": "ops" }
```

- **`status` is honest, not optimistic** (issue #71): when a
  dependency check fails the body says `"status": "degraded"` and the
  offending entry flips to `"unavailable"` — but the HTTP code stays
  **200**, because a restart cannot fix a dead Postgres. Liveness owns
  restarts; readiness owns rotation.
- Each dependency check is bounded by a 2s timeout so a wedged backend
  cannot stall a probe past the k8s probe timeout.

`/readyz` (issue #71) is the rotation gate. It runs the same two checks
— `Store.Ping` (a genuine round trip on the Postgres backend) and the
bus health check — and answers **503** the moment either fails, so a
dead-dependency pod leaves the Service rotation instead of serving
errors. The 503 body has the same shape, with `"status":
"unavailable"`:

```json
{ "status": "unavailable", "service": "ryvexd", "version": "v1.1.0",
  "time": "…", "dependencies": { "store": "unavailable", "bus": "ok" } }
```

Error details stay in the server log — the anonymous probe body never
leaks them. Both routes are unauthenticated by design: they expose no
resource data.

### Resources (handle-addressed)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/resources` | Create. `201` with stored document |
| GET | `/v1/resources?org=&project=&env=&kind=&limit=&cursor=` | Filtered page. `200` `{items, next_cursor}` |
| GET | `/v1/resources/{id}` | Fetch by opaque ID |
| DELETE | `/v1/resources/{id}` | Delete. `204` |

Pagination: `limit` default 50 (max 200); pass `next_cursor` from the
previous page until it comes back `""`.

### Resources (scope-addressed)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/{org}/{project}/{env}/{kind}?limit=&cursor=` | List kind in scope. `200` `{items, next_cursor}` |
| GET | `/v1/{org}/{project}/{env}/{kind}/{name}` | Fetch by logical address |
| PUT | `/v1/{org}/{project}/{env}/{kind}/{name}` | **Upsert.** Creates (`201`) at a fresh address; updates (`200`) at an existing one |
| DELETE | `/v1/{org}/{project}/{env}/{kind}/{name}` | Delete. `204` |

**Optimistic concurrency (CAS):** include `"generation": N` in the PUT
body to fail with `409 conflict` if the stored generation is no longer
`N`. Omit it for last-writer-wins.

**Method enforcement on the list route (#84):** the scope list is a
read-only collection. Any non-GET method on
`/v1/{org}/{project}/{env}/{kind}` — including POST and PUT, which
previously fell through to the list handler — is rejected with `405
method_not_allowed` carrying an `Allow: GET` header and the standard
error envelope. (PUT/DELETE belong to the `{name}` routes below.)

**No-op heartbeats are silent (#72):** a PUT whose spec **and** labels
are byte-identical to the stored document answers `200` with the
unchanged `generation` — but publishes no `updated` event and writes no
audit entry. The node agent re-sends identical heartbeat PUTs between
spec refreshes specifically to avoid event churn, so event publication
is gated on the same spec/labels comparison that decides the generation
bump. A real spec/labels change keeps the full `200` + event + audit
behavior.

### Key management (`/v1/keys`)

Managed API keys back the org/project-scoped RBAC face. All four
routes are **admin-only** — operators and viewers get `403 forbidden`
("admin role required for key management"). Keys live as `APIKey`
resources in the reserved namespace `ryvex/system/system`; the token
is a `ryk_…` string whose sha256 digest is stored and never served.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/keys` | Mint a key. `201` with the plaintext token — **shown exactly once** |
| GET | `/v1/keys` | List keys. `200` `{keys: [KeyView], count}` — hashes redacted |
| PUT | `/v1/keys/{id}` | Patch roles/scope/active state. `200` with the updated KeyView |
| DELETE | `/v1/keys/{id}` | Revoke immediately. `204` |

Create body — either `scopes` or `org` is required (admin keys may
omit both and default to `org/*`):

```json
{ "principal": "ci-bot", "org": "acme", "project": "core",
  "roles": ["operator"], "scopes": [] }
```

- With `scopes` empty, the scope is derived as `org/<org>` (plus
  `/project/<project>` when given); with `org` empty it defaults to
  the org of `scopes[0]`. Scope grammar: `org/<org>` or
  `org/<org>/project/<project>`; `org/*` denotes admin.
- Update body fields are all optional and patch-style:
  `{"roles": […], "scopes": […], "active": false}`.
- KeyView (the shape of every returned key):

```json
{ "id": "r-…", "principal": "ci-bot", "roles": ["operator"],
  "scopes": ["org/acme/project/core"], "active": true,
  "created_at": "…", "updated_at": "…" }
```

Revocation is immediate: the authorizer's key cache is refreshed on
every create/update/delete.

**Bootstrap keys are governed by this lifecycle (#73).** Static keys
supplied via `--api-keys` / `RYVEX_API_KEYS` are seeded at boot as
`APIKey` resources (principal = name, `roles: ["admin"]`, `scopes:
["org/*"]`) in the reserved namespace — they appear in `GET /v1/keys`
like any managed key. Authentication is derived **only** from the live
`APIKey` resource view; there is no separate boot-time digest fallback.
Consequences:

- **Revocable and demotable.** DELETE (revoke), PUT (`active: false`,
  role/scope changes) on a bootstrap key take effect on the next
  authorizer refresh — no daemon restart. A revoked bootstrap token
  simply stops authenticating (fail closed).
- **Conditional admin.** Admin rights come from the resource's current
  roles, not from the flag: demote the resource to `operator` and the
  token loses key-management and cross-org reach immediately.
- Recreating a revoked bootstrap key requires re-seeding (restart with
  the flag, or mint a managed replacement via `POST /v1/keys`).

### Observability & control

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/{org}/events?limit=&from=&cursor=` | Recent bus events for an org (newest first) |
| GET | `/v1/{org}/audit?kind=&limit=&cursor=` | Audit entries for an org (newest first) |
| POST | `/v1/{org}/reconcile/{id}` | Trigger an immediate reconcile. `202` |

**Event cursor (`?from=`):** on the NATS JetStream bus, pass
`from=<stream sequence>` to replay events *after* that sequence; the
response then carries `last_seq` alongside `events`/`count` so callers
can resume without gaps or duplicates. A non-integer `from` is a `400`
validation error. The in-memory bus does not implement the cursor —
`from` is ignored there and `last_seq` is absent.

**Feed pagination (`cursor` + `next_cursor`):** both feed faces — events
and audit — are cursor-paginated with the exact wire contract of the
resources listing ([#107](https://github.com/Roy-Wanyoike/Ryvex/issues/107),
merged via PR #114): pass `?cursor=`, receive `next_cursor` at the same
envelope position, and pass it back until it comes back
**empty (`""`)**, which means the feed is exhausted.

- **Envelopes.** `GET /v1/{org}/events?limit=&cursor=` answers
  `{events, count, next_cursor}`; `GET
  /v1/{org}/audit?kind=&limit=&cursor=` answers `{entries, count,
  next_cursor}`. The key is always present — `""` when the feed is
  exhausted.
- **Page size.** `limit` defaults to 100 and is capped at 500;
  out-of-range values (≤ 0 or > 500) clamp back to 100.
- **Events cursors are sequence-based.** Every bus backend stamps a
  monotonic publish sequence into the event ID (`evt-<n>`); a cursor is
  that sequence encoded in the shared v2 cursor-token format and means
  *"everything strictly older than the oldest event already
  delivered"*. Pages advance newest→oldest and the minted sequence
  strictly decreases per page, so a walk terminates and can never loop.
  A well-formed cursor **above** every retained sequence serves the
  whole feed (everything is older than it); on the JetStream backend a
  walk beyond the bounded scan window (#15) clamps to an empty page,
  like a stale cursor — never an error.
- **Audit cursors reuse the store's offset-cursor machinery** (the #85
  semantics: the shared v2 token; offsets past the retained window
  clamp to an empty page). Entries evicted from the audit retention
  ring mid-walk neither error nor loop the walk.
- **Stale or evicted cursor** (either face) clamps to a clean
  **empty page with `next_cursor: ""`** — never an error.
- **Malformed cursor → `400 bad_request`** — the same mapping as the
  resources listing, on both feeds.
- **`from` and `cursor` are mutually exclusive** on the events feed:
  passing both is a `400 bad_request`, not a silent precedence rule.
  `?from=` alone keeps the frozen replay contract above; on a bus
  without sequence replay (the in-memory ring) `from` is ignored — the
  request lands on the newest-first pagination path and the response
  carries the additive `next_cursor` key (always `""`) while `last_seq`
  stays absent.

## Event subjects

```
ryvex.resource.{org}.{kind}.{event}

kind  ∈ project, environment, application, deployment, cluster,
        node, database, cache, bucket, policy, secret, subscription,
        apikey                                                       (lowercase)
event ∈ created | updated | deleted | status_changed | drift_detected
```

Example: `ryvex.resource.acme.application.status_changed`. Managed key
events publish under the reserved org, e.g.
`ryvex.resource.ryvex.apikey.created`. `drift_detected` (issue #80) is
published when a drift pass observes an actuated resource diverging
from its declared spec; `data.fields` carries the drifted field names
and the resource's phase stays `Ready` (drift is an annotation, not a
phase).

Subject matching is available to in-process subscribers with `*`
(one segment) and `>` (remaining segments) wildcards; the same grammar
powers `Subscription` webhook filters (`spec.subjects`, up to 16
patterns per subscription).

## curl tour

```bash
export RYVEX=http://127.0.0.1:8080
export AUTH="Authorization: Bearer ryk_local_dev"

curl -s $RYVEX/healthz
curl -s -X POST $RYVEX/v1/resources -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"kind":"Application","org":"acme","project":"core","env":"prod",
       "name":"payments","spec":{"image":"payments:2.0.1","replicas":3}}'
curl -s "$RYVEX/v1/resources?org=acme&kind=applications" -H "$AUTH"
curl -s $RYVEX/v1/acme/core/prod/applications/payments -H "$AUTH"
curl -s -X PUT $RYVEX/v1/acme/core/prod/applications/payments -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"Application","org":"acme","project":"core","env":"prod",
       "name":"payments","generation":2,"spec":{"image":"payments:2.0.2","replicas":5}}'
curl -s -X POST $RYVEX/v1/acme/reconcile/r-00b52b6eb859f432 -H "$AUTH"
curl -s "$RYVEX/v1/acme/events?limit=10" -H "$AUTH"
curl -s "$RYVEX/v1/acme/audit?limit=10" -H "$AUTH"

# Key management (admin keys only — the static bootstrap key above is admin)
curl -s -X POST $RYVEX/v1/keys -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"principal":"ci-bot","org":"acme","roles":["operator"]}'
curl -s $RYVEX/v1/keys -H "$AUTH"
```

## Versioning

- The `/v1` prefix is the compatibility boundary.
- New fields may be added to responses at any time; clients must
  tolerate unknown fields. (Recent additions that did exactly this:
  `/v1/keys`, the `?from=` event cursor + `last_seq`, `forbidden` and
  `payload_too_large` error codes, the authenticated `/healthz` fields.)
- Breaking changes ship under `/v2` with the old face kept for one
  minor release.
