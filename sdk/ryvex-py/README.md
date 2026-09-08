# ryvex (Python SDK)

Official Python client for the **Ryvex control plane REST API** — the
`/v1` face documented in [`docs/api-contracts.md`](../../docs/api-contracts.md)
(frozen contract). Requires Python 3.10+. **Zero runtime
dependencies**: everything rides on the standard library
(`urllib.request`, `json`, `dataclasses`), so it drops into any
environment untouched. Fully typed (ships a `py.typed` marker).

## Install

```bash
pip install ryvex          # once published
# or from a checkout of this repo:
pip install ./sdk/ryvex-py
```

## Quickstart

```python
import os
from ryvex import Ryvex, RyvexError

ryvex = Ryvex(
    base_url="http://127.0.0.1:8080",  # ryvexd listen address
    token=os.environ["RYVEX_TOKEN"],   # bearer key, ryk_…
)

# Liveness (no auth required server-side)
health = ryvex.health()                # HealthInfo(status="ok", version="v1.0.0", …)

# Declarative create — the reconciler takes it from there
app = ryvex.create_resource({
    "kind": "Application",
    "org": "acme",
    "project": "core",
    "env": "prod",
    "name": "checkout",
    "labels": {"team": "payments"},
    "spec": {"image": "registry.acme.io/checkout:1.42.0", "replicas": 4},
})
print(app.id, app.status.phase)        # r-…  Pending → Ready

# Fetch by handle or by logical address
ryvex.get_resource(app.id)
ryvex.get_in_scope("acme", "core", "prod", "applications", "checkout")
```

Every request carries `Authorization: Bearer <token>`,
`Content-Type: application/json` and `Accept: application/json`. Pass
`timeout=` (seconds, default 15) to bound slow daemons. All path
segments are URL-quoted; unknown keys in response documents are
ignored by the typed models, per the contract's tolerance rule.

## Optimistic concurrency (CAS)

`status` and `generation` are **server-owned**. `generation` increments
only when `spec`/`labels` actually change. Include the generation you
last read in a scope-addressed PUT to fail instead of clobbering:

```python
current = ryvex.get_in_scope("acme", "core", "prod", "applications", "checkout")

# wins: stored generation still matches what we read
updated = ryvex.put_in_scope(
    "acme", "core", "prod", "applications", "checkout",
    {"generation": current.generation, "spec": {**(current.spec or {}), "replicas": 5}},
)
print(updated.generation)  # +1

# loses: someone wrote first → RyvexError 409 "conflict"
try:
    ryvex.put_in_scope(
        "acme", "core", "prod", "applications", "checkout",
        {"generation": current.generation, "spec": {"replicas": 6}},  # stale
    )
except RyvexError as err:
    if err.code == "conflict":
        print(f"lost the race (status {err.status}), re-read and retry")
```

Omit `generation` for last-writer-wins semantics.

## Pagination

`list_resources` returns one cursor `Page` (`next_cursor == ""` marks
the end); `list_all` walks every page lazily as a generator — one HTTP
request per `for` turn:

```python
# one page at a time
page = ryvex.list_resources(org="acme", kind="applications", limit=100)
for r in page.items:
    print(r.id)
if page.next_cursor:
    ...  # fetch the next page with cursor=page.next_cursor

# or stream everything
for r in ryvex.list_all(org="acme", env="prod"):
    print(f"{r.kind}/{r.name} gen={r.generation}")
```

## Error handling

All non-2xx responses raise a `RyvexError` parsed from the frozen
envelope `{"error":{code,message,request_id,details}}`. If the body
isn't the envelope (proxy HTML, empty body), the code is inferred from
the HTTP status so you can always branch on it. Transport failures
(DNS, refused connections, timeouts) raise the same type with
`status = 0` — one error type to catch everywhere.

| HTTP | `err.code`             |
| ---- | ---------------------- |
| 0 (transport) | `transport_error` |
| 400  | `validation_failed` / `bad_request` |
| 401  | `unauthorized`         |
| 404  | `not_found`            |
| 405  | `method_not_allowed`   |
| 409  | `already_exists` / `conflict` |
| 500  | `internal_error`       |

```python
try:
    ryvex.delete_resource("r-does-not-exist")
except RyvexError as err:
    print(f"{err.status} {err.code}: {err.message}")
    print(f"request id: {err.request_id}")     # quote this in bug reports
    if err.details:
        print("details:", err.details)
print(str(err))
# ryvex: resource not found (status=404, code=not_found, request_id=req-…)
```

## API surface

| Method | Endpoint touched | SDK call |
| ------ | ---------------- | -------- |
| GET | `/healthz` | `health()` |
| GET | `/v1` | `index()` |
| POST | `/v1/resources` | `create_resource(doc)` |
| GET | `/v1/resources?org=&…` | `list_resources(**filters)` / `list_all(**filters)` |
| GET | `/v1/resources/{id}` | `get_resource(resource_id)` |
| DELETE | `/v1/resources/{id}` | `delete_resource(resource_id)` |
| GET | `/v1/{org}/{project}/{env}/{kind}/{name}` | `get_in_scope(…)` |
| PUT | `/v1/{org}/{project}/{env}/{kind}/{name}` | `put_in_scope(…, doc)` |
| DELETE | `/v1/{org}/{project}/{env}/{kind}/{name}` | `delete_in_scope(…)` |
| GET | `/v1/{org}/events?limit=` | `events(org, limit=100)` |
| GET | `/v1/{org}/audit?kind=&limit=` | `audit(org, limit=100, kind=None)` |
| POST | `/v1/{org}/reconcile/{id}` | `trigger_reconcile(org, resource_id)` |

Typed models: `Resource`, `ResourceStatus`, `RyvexEvent`, `AuditEntry`,
`Page`, `EventsPage`, `AuditPage`, `ReconcileAck`, `HealthInfo`,
`ApiIndex` — each with a tolerant `from_dict` constructor.

## Development

```bash
python3 -m pytest tests/test_client.py -q        # unit tests (fake transport, no network)

# live integration test against a local daemon
go build -o /tmp/ryvexd ./cmd/ryvexd               # from the repo root
/tmp/ryvexd serve --http 127.0.0.1:18246 --dev-auth --seed --log-level error &
RYVEX_INTEGRATION=1 RYVEX_TEST_API=http://127.0.0.1:18246 \
  RYVEX_TEST_TOKEN=ryk_py_agent python3 -m pytest tests/test_integration.py -q
```

Apache-2.0 — see [LICENSE](../../LICENSE).
