# Ryvex REST API Contract (`/v1`)

> **Status: FROZEN for v1.** Additions are allowed; breaking changes
> require a new major version of the API surface.

## Conventions

- **Base path:** `/v1` on the `ryvexd` listen address.
- **Auth:** `Authorization: Bearer ryk_…` on every `/v1` route.
  `/healthz` is unauthenticated.
- **Content type:** `application/json` everywhere.
- **Tracing:** every response carries `X-Request-Id` (client-supplied
  IDs are honored).
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
| 404 | `not_found` | Unknown resource or route |
| 405 | `method_not_allowed` | Method not supported (sets `Allow`) |
| 409 | `already_exists` | Logical address already taken |
| 409 | `conflict` | CAS generation mismatch |
| 500 | `internal_error` | Bug or backend failure |

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
  Node, Database, Cache, Bucket, Policy, Secret}.
- `org` / `project` / `env` / `name`: 1–63 chars, `[a-z0-9-]`, must
  start and end alphanumeric.
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
| GET | `/healthz` | Liveness + version + resource count (no auth) |
| GET | `/v1` | API index (machine-readable endpoint list) |

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
| GET | `/v1/{org}/{project}/{env}/{kind}` | List kind in scope |
| GET | `/v1/{org}/{project}/{env}/{kind}/{name}` | Fetch by logical address |
| PUT | `/v1/{org}/{project}/{env}/{kind}/{name}` | **Upsert.** Creates (`201`) at a fresh address; updates (`200`) at an existing one |
| DELETE | `/v1/{org}/{project}/{env}/{kind}/{name}` | Delete. `204` |

**Optimistic concurrency (CAS):** include `"generation": N` in the PUT
body to fail with `409 conflict` if the stored generation is no longer
`N`. Omit it for last-writer-wins.

### Observability & control

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/{org}/events?limit=` | Recent bus events for an org (newest first) |
| GET | `/v1/{org}/audit?kind=&limit=` | Audit entries for an org (newest first) |
| POST | `/v1/{org}/reconcile/{id}` | Trigger an immediate reconcile. `202` |

## Event subjects

```
ryvex.resource.{org}.{kind}.{event}

kind  ∈ project, environment, application, deployment, cluster,
        node, database, cache, bucket, policy, secret   (lowercase)
event ∈ created | updated | deleted | status_changed
```

Example: `ryvex.resource.acme.application.status_changed`

Subject matching is available to in-process subscribers with `*`
(one segment) and `>` (remaining segments) wildcards; the same grammar
will apply to future webhook filters.

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
```

## Versioning

- The `/v1` prefix is the compatibility boundary.
- New fields may be added to responses at any time; clients must
  tolerate unknown fields.
- Breaking changes ship under `/v2` with the old face kept for one
  minor release.
