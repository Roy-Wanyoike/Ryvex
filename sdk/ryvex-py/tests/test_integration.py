"""Live integration tests for the Ryvex Python SDK against a real daemon.

Skipped unless ``RYVEX_INTEGRATION=1``. Boot ryvexd first (from the repo
root, with the Go toolchain on PATH):

    go build -o /tmp/ryvexd ./cmd/ryvexd
    /tmp/ryvexd serve --http 127.0.0.1:18246 --dev-auth --seed --log-level error &

Then:

    RYVEX_INTEGRATION=1 RYVEX_TEST_API=http://127.0.0.1:18246 \\
      RYVEX_TEST_TOKEN=ryk_py_agent python3 -m pytest tests/test_integration.py -q

Isolation: the suite uses its own org ("pysdkint") and timestamped
resource names, so it never collides with --seed data (org "acme") or
concurrent agents.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

from ryvex import Ryvex, RyvexError

pytestmark = pytest.mark.skipif(
    os.environ.get("RYVEX_INTEGRATION") != "1",
    reason="set RYVEX_INTEGRATION=1 with a running ryvexd to run live tests",
)

API = os.environ.get("RYVEX_TEST_API", "http://127.0.0.1:18246")
TOKEN = os.environ.get("RYVEX_TEST_TOKEN", "ryk_py_agent")

ORG = "pysdkint"
PROJECT = "core"
ENV = "prod"
KIND_PLURAL = "applications"


@pytest.fixture(scope="module")
def client() -> Ryvex:
    return Ryvex(API, TOKEN, timeout=10.0)


def _wait_for_phase(
    ryvex: Ryvex,
    name: str,
    phase: str,
    timeout: float = 15.0,
):
    """Poll until the named scope resource reaches `phase` (or timeout)."""
    deadline = time.monotonic() + timeout
    doc = None
    while time.monotonic() < deadline:
        doc = ryvex.get_in_scope(ORG, PROJECT, ENV, KIND_PLURAL, name)
        if doc.status is not None and doc.status.phase == phase:
            return doc
        time.sleep(0.2)
    return doc


def _converge_to_ready(ryvex: Ryvex, resource_id: str, name: str, timeout: float = 20.0):
    """Drive the resource to Ready with manual reconcile triggers.

    Each trigger advances exactly one lifecycle step (Pending ->
    Provisioning -> Ready) and the background scan only runs every 30s,
    so a client that wants fast convergence re-triggers while polling.
    """
    deadline = time.monotonic() + timeout
    doc = None
    while time.monotonic() < deadline:
        doc = ryvex.get_in_scope(ORG, PROJECT, ENV, KIND_PLURAL, name)
        if doc.status is not None and doc.status.phase == "Ready":
            return doc
        ryvex.trigger_reconcile(ORG, resource_id)
        time.sleep(0.3)
    return doc


def test_index_and_health(client: Ryvex) -> None:
    health = client.health()
    assert health.status == "ok"
    assert health.service == "ryvexd"
    assert health.resources > 0  # --seed data

    index = client.index()
    assert index.name == "Ryvex Control Plane API"
    assert any("POST" in endpoint for endpoint in index.endpoints)


def test_full_lifecycle(client: Ryvex) -> None:
    """create -> get -> list -> CAS put 1->2 -> stale put 409 -> reconcile
    -> events -> audit -> delete -> 404, against the live daemon."""
    name = "py-" + uuid.uuid4().hex[:12]

    # ---- create ----
    doc = client.create_resource(
        {
            "kind": "Application",
            "org": ORG,
            "project": PROJECT,
            "env": ENV,
            "name": name,
            "labels": {"team": "pysdk"},
            "spec": {"image": "registry.pysdk.io/demo:1.0.0", "replicas": 1},
        }
    )
    assert doc.id.startswith("r-")
    assert doc.kind == "Application"
    assert doc.name == name
    assert doc.generation == 1
    resource_id = doc.id

    try:
        # ---- get (by handle and by scope) ----
        got = client.get_resource(resource_id)
        assert got.id == resource_id
        assert got.labels == {"team": "pysdk"}
        scoped = client.get_in_scope(ORG, PROJECT, ENV, KIND_PLURAL, name)
        assert scoped.id == resource_id

        # ---- list (page + generator) ----
        page = client.list_resources(org=ORG, kind=KIND_PLURAL)
        assert resource_id in [item.id for item in page.items]
        everything = [item.id for item in client.list_all(org=ORG)]
        assert resource_id in everything

        # ---- CAS put: generation 1 -> 2 ----
        updated = client.put_in_scope(
            ORG, PROJECT, ENV, KIND_PLURAL, name,
            {
                "generation": got.generation,
                "spec": {"image": "registry.pysdk.io/demo:1.1.0", "replicas": 3},
            },
        )
        assert updated.generation == 2
        assert updated.spec == {"image": "registry.pysdk.io/demo:1.1.0", "replicas": 3}

        # ---- stale put: 409 conflict ----
        with pytest.raises(RyvexError) as excinfo:
            client.put_in_scope(
                ORG, PROJECT, ENV, KIND_PLURAL, name,
                {
                    "generation": 1,  # stale: stored generation is 2 now
                    "spec": {"image": "registry.pysdk.io/demo:0.9.0", "replicas": 9},
                },
            )
        conflict = excinfo.value
        assert conflict.status == 409
        assert conflict.code == "conflict"
        assert conflict.request_id  # server always stamps one

        # ---- reconcile (manual trigger; the background scan is 30s) ----
        ack = client.trigger_reconcile(ORG, resource_id)
        assert ack.status == "accepted"
        assert ack.resource_id == resource_id

        # each trigger advances one lifecycle step (Pending ->
        # Provisioning -> Ready), so keep nudging until converged
        ready = _converge_to_ready(client, resource_id, name)
        assert ready is not None and ready.status is not None
        assert ready.status.phase == "Ready"
        assert ready.status.observed_generation == 2
        assert ready.generation == 2  # status changes do not bump generation

        # ---- events ----
        events = client.events(ORG, limit=100)
        mine = [e for e in events.events if e.resource_id == resource_id]
        event_types = {e.type for e in mine}
        assert {"created", "updated", "status_changed"} <= event_types
        for event in mine:
            assert event.subject.startswith(f"ryvex.resource.{ORG}.application.")

        # ---- audit ----
        audit = client.audit(ORG, limit=100)
        mine_audits = [a for a in audit.entries if a.resource_id == resource_id]
        actions = {a.action for a in mine_audits}
        assert "created" in actions
        assert "updated" in actions
        assert all(a.logical_key.startswith(f"{ORG}/{PROJECT}/{ENV}/") for a in mine_audits)

        # kind filter (server-side, case-insensitive plural)
        audit_kind = client.audit(ORG, kind=KIND_PLURAL, limit=100)
        assert audit_kind.entries
        assert all(a.kind == "Application" for a in audit_kind.entries)
        assert any(a.resource_id == resource_id for a in audit_kind.entries)

        # ---- delete (handle-addressed, 204) ----
        assert client.delete_resource(resource_id) is None

        # ---- 404 afterwards (scope + handle) ----
        with pytest.raises(RyvexError) as excinfo:
            client.get_in_scope(ORG, PROJECT, ENV, KIND_PLURAL, name)
        assert excinfo.value.status == 404
        assert excinfo.value.code == "not_found"

        with pytest.raises(RyvexError) as excinfo:
            client.get_resource(resource_id)
        assert excinfo.value.status == 404
        assert excinfo.value.code == "not_found"
    finally:
        # cleanup: tolerate a double delete (404) if the happy path
        # already removed the resource or an assertion aborted early
        try:
            client.delete_in_scope(ORG, PROJECT, ENV, KIND_PLURAL, name)
        except RyvexError as exc:
            if exc.status != 404:
                raise
