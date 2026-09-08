"""Unit tests for the Ryvex Python client.

All HTTP traffic goes through a fake ``urlopen`` monkeypatched into
``ryvex.client`` — no network. Each test asserts the method, URL,
headers and (when present) body the client produced, mirroring the
frozen /v1 contract (docs/api-contracts.md).
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
from typing import Any

import pytest

import ryvex.client as ryvex_client
from ryvex import Ryvex, RyvexError
from ryvex.types import AuditEntry, Page, Resource, ResourceStatus, RyvexEvent

BASE = "http://ryvex.test:8080"
TOKEN = "ryk_test"


# ---- fakes ----


class FakeResponse:
    """Minimal stand-in for urllib's HTTPResponse."""

    def __init__(self, status: int = 200, body: bytes = b"") -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class FakeTransport:
    """Queue-based fake for urllib.request.urlopen.

    Queue items: dict/bytes (200 JSON/raw), (status, body) tuples,
    FakeResponse instances, or Exception instances to raise.
    """

    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: float | None = None) -> FakeResponse:
        self.requests.append(request)
        if not self.responses:
            return FakeResponse(200, b"{}")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, FakeResponse):
            return item
        if isinstance(item, tuple):
            return FakeResponse(item[0], item[1])
        if isinstance(item, bytes):
            return FakeResponse(200, item)
        return FakeResponse(200, json.dumps(item).encode("utf-8"))


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> FakeTransport:
    fake = FakeTransport()
    monkeypatch.setattr(ryvex_client, "urlopen", fake)
    return fake


@pytest.fixture
def client() -> Ryvex:
    return Ryvex(BASE + "/", TOKEN)


# ---- inspection helpers ----


def hdr(request: Any, name: str) -> str | None:
    for key, value in request.headers.items():
        if key.lower() == name.lower():
            return value
    return None


def query_of(request: Any) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)


def path_of(request: Any) -> str:
    return urllib.parse.urlparse(request.full_url).path


def body_json(request: Any) -> dict[str, Any]:
    return json.loads(request.data.decode("utf-8"))


def http_error(status: int, body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(f"{BASE}/x", status, "err", {}, io.BytesIO(body))


def resource_doc(n: int) -> dict[str, Any]:
    return {
        "id": f"r-{n:016x}",
        "kind": "Application",
        "org": "acme",
        "project": "core",
        "env": "prod",
        "name": f"app-{n}",
        "generation": n,
        "labels": {"team": "payments"},
        "spec": {"replicas": n},
        "status": {
            "phase": "Ready",
            "message": "converged to desired spec",
            "observed_generation": n,
            "updated_at": "2026-09-08T09:00:00Z",
        },
        "created_at": "2026-09-08T08:00:00Z",
        "updated_at": "2026-09-08T09:00:00Z",
        "a_future_field": {"nested": True},  # unknown fields must be tolerated
    }


# ---- constructor ----


class TestConstructor:
    def test_strips_trailing_slashes(self) -> None:
        assert Ryvex(BASE + "/", TOKEN).base_url == BASE
        assert Ryvex(BASE + "///", TOKEN).base_url == BASE

    @pytest.mark.parametrize("kwargs", [{}, {"token": TOKEN}, {"base_url": BASE}])
    def test_requires_base_url_and_token(self, kwargs: dict[str, str]) -> None:
        with pytest.raises(TypeError):
            Ryvex(**kwargs)  # type: ignore[arg-type]

    def test_rejects_empty_strings(self) -> None:
        with pytest.raises(TypeError):
            Ryvex("", TOKEN)
        with pytest.raises(TypeError):
            Ryvex(BASE, "")

    def test_default_timeout(self) -> None:
        assert Ryvex(BASE, TOKEN).timeout == 15.0


# ---- service ----


class TestService:
    def test_health(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [
            {
                "status": "ok",
                "service": "ryvexd",
                "version": "v1.0.0",
                "resources": 15,
                "time": "2026-09-08T09:00:00Z",
            }
        ]
        info = client.health()
        req = transport.requests[0]
        assert req.get_method() == "GET"
        assert req.full_url == f"{BASE}/healthz"
        assert info.status == "ok"
        assert info.version == "v1.0.0"
        assert info.resources == 15

    def test_index(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [
            {
                "name": "Ryvex Control Plane API",
                "version": "v1.0.0",
                "endpoints": ["GET /healthz", "POST /v1/resources"],
                "docs": "docs/api-contracts.md",
            }
        ]
        index = client.index()
        req = transport.requests[0]
        assert req.get_method() == "GET"
        assert path_of(req) == "/v1"
        assert index.name == "Ryvex Control Plane API"
        assert index.endpoints == ["GET /healthz", "POST /v1/resources"]


# ---- headers on every request ----


class TestHeaders:
    def test_bearer_and_content_type_on_get_without_body(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"status": "ok"}]
        client.health()
        req = transport.requests[0]
        assert hdr(req, "Authorization") == f"Bearer {TOKEN}"
        assert hdr(req, "Content-Type") == "application/json"
        assert hdr(req, "Accept") == "application/json"

    def test_bearer_and_content_type_on_post_with_body(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [resource_doc(1)]
        client.create_resource({"kind": "Application", "spec": {}})
        req = transport.requests[0]
        assert hdr(req, "Authorization") == f"Bearer {TOKEN}"
        assert hdr(req, "Content-Type") == "application/json"


# ---- resources (handle-addressed) ----


class TestHandleAddressed:
    def test_create_resource(self, client: Ryvex, transport: FakeTransport) -> None:
        doc = resource_doc(1)
        transport.responses = [doc]
        created = client.create_resource(
            {
                "kind": "Application",
                "org": "acme",
                "project": "core",
                "env": "prod",
                "name": "app-1",
                "labels": {"team": "payments"},
                "spec": {"replicas": 1},
            }
        )
        req = transport.requests[0]
        assert req.get_method() == "POST"
        assert path_of(req) == "/v1/resources"
        sent = body_json(req)
        assert sent["kind"] == "Application"
        assert sent["spec"] == {"replicas": 1}
        assert isinstance(created, Resource)
        assert created.id == doc["id"]
        assert created.status is not None
        assert created.status.phase == "Ready"
        assert created.labels == {"team": "payments"}

    def test_get_resource(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [resource_doc(7)]
        got = client.get_resource("r-0000000000000007")
        req = transport.requests[0]
        assert req.get_method() == "GET"
        assert path_of(req) == "/v1/resources/r-0000000000000007"
        assert got.name == "app-7"
        assert got.generation == 7

    def test_get_resource_quotes_id(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [resource_doc(1)]
        client.get_resource("r-1/2 3")
        assert path_of(transport.requests[0]) == "/v1/resources/r-1%2F2%203"

    def test_delete_resource_returns_none_on_204(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [FakeResponse(204, b"")]
        assert client.delete_resource("r-1") is None
        req = transport.requests[0]
        assert req.get_method() == "DELETE"
        assert path_of(req) == "/v1/resources/r-1"

    def test_delete_resource_404_raises(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [
            http_error(
                404,
                json.dumps(
                    {
                        "error": {
                            "code": "not_found",
                            "message": "resource not found",
                            "request_id": "req-d1",
                        }
                    }
                ).encode(),
            )
        ]
        with pytest.raises(RyvexError) as excinfo:
            client.delete_resource("r-missing")
        assert excinfo.value.status == 404
        assert excinfo.value.code == "not_found"
        assert excinfo.value.request_id == "req-d1"


# ---- list + pagination ----


class TestListResources:
    def test_builds_query_and_drops_empty(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"items": [], "next_cursor": ""}]
        client.list_resources(org="acme", kind="applications", limit=50, cursor="c1")
        params = query_of(transport.requests[0])
        assert params == {
            "org": ["acme"],
            "kind": ["applications"],
            "limit": ["50"],
            "cursor": ["c1"],
        }

    def test_none_and_empty_filters_dropped(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"items": [], "next_cursor": ""}]
        client.list_resources(org="acme", project="", env=None)
        assert query_of(transport.requests[0]) == {"org": ["acme"]}

    def test_zero_limit_is_kept(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [{"items": [], "next_cursor": ""}]
        client.list_resources(limit=0)
        assert query_of(transport.requests[0])["limit"] == ["0"]

    def test_extra_filters_forwarded(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"items": [], "next_cursor": ""}]
        client.list_resources(org="acme", future_filter="x")
        assert query_of(transport.requests[0])["future_filter"] == ["x"]

    def test_parses_items_into_resources(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"items": [resource_doc(1), resource_doc(2)], "next_cursor": "n"}]
        page = client.list_resources(org="acme")
        assert isinstance(page, Page)
        assert all(isinstance(item, Resource) for item in page.items)
        assert [item.name for item in page.items] == ["app-1", "app-2"]
        assert page.next_cursor == "n"

    def test_normalizes_missing_or_null_fields(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"items": None}]
        page = client.list_resources()
        assert page.items == []
        assert page.next_cursor == ""


class TestListAll:
    def test_follows_pagination_sequence(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [
            {"items": [resource_doc(1)], "next_cursor": "c1"},
            {"items": [resource_doc(2)], "next_cursor": "c2"},
            {"items": [resource_doc(3)], "next_cursor": ""},
        ]
        items = list(client.list_all(org="acme"))
        assert [item.name for item in items] == ["app-1", "app-2", "app-3"]
        assert len(transport.requests) == 3
        # "" cursor is dropped from the first request, then c1, c2.
        assert "cursor" not in query_of(transport.requests[0])
        assert query_of(transport.requests[1])["cursor"] == ["c1"]
        assert query_of(transport.requests[2])["cursor"] == ["c2"]

    def test_stops_on_repeated_cursor(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [
            {"items": [resource_doc(1)], "next_cursor": "stuck"},
            {"items": [resource_doc(2)], "next_cursor": "stuck"},
        ]
        items = list(client.list_all())
        assert [item.name for item in items] == ["app-1", "app-2"]
        assert len(transport.requests) == 2  # loop guard kicked in

    def test_forwards_filters_to_every_page(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [
            {"items": [resource_doc(1)], "next_cursor": "c1"},
            {"items": [], "next_cursor": ""},
        ]
        list(client.list_all(org="acme", env="prod", limit=10))
        for req in transport.requests:
            params = query_of(req)
            assert params["org"] == ["acme"]
            assert params["env"] == ["prod"]
            assert params["limit"] == ["10"]

    def test_honors_starting_cursor(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"items": [resource_doc(9)], "next_cursor": ""}]
        items = list(client.list_all(cursor="resumed"))
        assert query_of(transport.requests[0])["cursor"] == ["resumed"]
        assert [item.name for item in items] == ["app-9"]


# ---- resources (scope-addressed) ----


class TestScopeAddressed:
    def test_get_in_scope(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [resource_doc(1)]
        got = client.get_in_scope("acme", "core", "prod", "applications", "app-1")
        req = transport.requests[0]
        assert req.get_method() == "GET"
        assert path_of(req) == "/v1/acme/core/prod/applications/app-1"
        assert got.id == "r-0000000000000001"

    def test_scope_segments_are_quoted(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [resource_doc(1)]
        client.get_in_scope("a b", "c/d", "e", "applications", "n me")
        assert path_of(transport.requests[0]) == "/v1/a%20b/c%2Fd/e/applications/n%20me"

    def test_put_in_scope_cas_body_contains_generation(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [resource_doc(2)]
        updated = client.put_in_scope(
            "acme", "core", "prod", "applications", "app-1",
            {"generation": 1, "spec": {"replicas": 2}},
        )
        req = transport.requests[0]
        assert req.get_method() == "PUT"
        assert path_of(req) == "/v1/acme/core/prod/applications/app-1"
        sent = body_json(req)
        assert sent["generation"] == 1  # CAS token travels in the body
        assert sent["spec"] == {"replicas": 2}
        assert updated.generation == 2

    def test_put_in_scope_without_generation_is_last_writer_wins(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [resource_doc(2)]
        client.put_in_scope(
            "acme", "core", "prod", "applications", "app-1", {"spec": {"replicas": 5}}
        )
        assert "generation" not in body_json(transport.requests[0])

    def test_delete_in_scope(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [FakeResponse(204, b"")]
        assert client.delete_in_scope("acme", "core", "prod", "applications", "app-1") is None
        req = transport.requests[0]
        assert req.get_method() == "DELETE"
        assert path_of(req) == "/v1/acme/core/prod/applications/app-1"


# ---- observability & control ----


class TestObservability:
    def test_events_default_limit_and_count_fallback(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"events": [{"id": "e1", "type": "created", "subject": "s"}]}]
        page = client.events("acme")
        req = transport.requests[0]
        assert req.get_method() == "GET"
        assert path_of(req) == "/v1/acme/events"
        assert query_of(req) == {"limit": ["100"]}
        assert isinstance(page.events[0], RyvexEvent)
        assert page.events[0].type == "created"
        assert page.count == 1  # falls back to len(events)

    def test_events_custom_limit(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [{"events": [], "count": 0}]
        client.events("acme", limit=5)
        assert query_of(transport.requests[0]) == {"limit": ["5"]}

    def test_audit_default_and_kind_filter(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [{"entries": [], "count": 0}]
        client.audit("acme")
        assert query_of(transport.requests[0]) == {"limit": ["100"]}

        transport.responses = [{"entries": [], "count": 0}]
        client.audit("acme", limit=10, kind="databases")
        assert query_of(transport.requests[1]) == {"kind": ["databases"], "limit": ["10"]}

    def test_audit_parses_entries(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [
            {
                "entries": [
                    {
                        "id": "a1",
                        "time": "2026-09-08T09:00:00Z",
                        "actor": "ryk_test",
                        "action": "created",
                        "resource_id": "r-1",
                        "kind": "Application",
                        "logical_key": "acme/core/prod/Application/app-1",
                        "generation": 1,
                        "reason": "api put",
                        "future_field": 1,
                    }
                ],
                "count": 1,
            }
        ]
        page = client.audit("acme")
        assert isinstance(page.entries[0], AuditEntry)
        assert page.entries[0].action == "created"
        assert page.entries[0].logical_key.endswith("Application/app-1")
        assert page.count == 1

    def test_trigger_reconcile(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [
            {"status": "accepted", "resource_id": "r-1", "reason": "manual reconcile trigger"}
        ]
        ack = client.trigger_reconcile("acme", "r-1")
        req = transport.requests[0]
        assert req.get_method() == "POST"
        assert path_of(req) == "/v1/acme/reconcile/r-1"
        assert ack.status == "accepted"
        assert ack.resource_id == "r-1"


# ---- error handling ----


class TestErrors:
    def test_envelope_404_not_found(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [
            http_error(
                404,
                json.dumps(
                    {
                        "error": {
                            "code": "not_found",
                            "message": "resource not found",
                            "request_id": "req-404",
                            "details": ["id"],
                        }
                    }
                ).encode(),
            )
        ]
        with pytest.raises(RyvexError) as excinfo:
            client.get_resource("r-missing")
        err = excinfo.value
        assert err.status == 404
        assert err.code == "not_found"
        assert err.message == "resource not found"
        assert err.request_id == "req-404"
        assert err.details == ["id"]
        assert "status=404" in str(err)
        assert "code=not_found" in str(err)

    def test_envelope_409_conflict(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [
            http_error(
                409,
                json.dumps(
                    {
                        "error": {
                            "code": "conflict",
                            "message": "generation conflict: resource was modified concurrently",
                            "request_id": "e3b0c44298fc",
                        }
                    }
                ).encode(),
            )
        ]
        with pytest.raises(RyvexError) as excinfo:
            client.put_in_scope(
                "acme", "core", "prod", "applications", "app-1", {"generation": 1}
            )
        err = excinfo.value
        assert err.status == 409
        assert err.code == "conflict"
        assert err.request_id == "e3b0c44298fc"
        assert err.details == []
        assert "generation conflict" in str(err)

    def test_non_json_body_falls_back_to_status_code(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [http_error(502, b"<html>bad gateway</html>")]
        with pytest.raises(RyvexError) as excinfo:
            client.health()
        err = excinfo.value
        assert err.status == 502
        assert err.code == "internal_error"  # status not in map -> default
        assert err.message == "request failed with status 502"  # HTML snippet withheld
        assert err.request_id is None

    def test_empty_body_uses_status_fallback(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [http_error(404, b"")]
        with pytest.raises(RyvexError) as excinfo:
            client.get_resource("r-x")
        assert excinfo.value.status == 404
        assert excinfo.value.code == "not_found"
        assert excinfo.value.message == "not found"

    def test_plain_text_body_snippet_included(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [http_error(500, b"boom: disk on fire")]
        with pytest.raises(RyvexError) as excinfo:
            client.get_resource("r-x")
        err = excinfo.value
        assert err.code == "internal_error"
        assert "boom: disk on fire" in err.message

    def test_envelope_with_wrong_types_tolerated(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [
            http_error(400, json.dumps({"error": {"code": 7, "message": None}}).encode())
        ]
        with pytest.raises(RyvexError) as excinfo:
            client.get_resource("r-x")
        err = excinfo.value
        assert err.code == "bad_request"  # non-string code -> fallback
        assert err.message == "bad request"  # non-string message -> fallback

    def test_invalid_json_in_2xx_body(self, client: Ryvex, transport: FakeTransport) -> None:
        transport.responses = [FakeResponse(200, b"<not json>")]
        with pytest.raises(RyvexError) as excinfo:
            client.health()
        err = excinfo.value
        assert err.status == 200
        assert err.code == "internal_error"
        assert "invalid JSON in response from /healthz" in err.message

    def test_transport_error_wrapped(self, client: Ryvex, transport: FakeTransport) -> None:
        cause = OSError(111, "Connection refused")
        transport.responses = [urllib.error.URLError(cause)]
        with pytest.raises(RyvexError) as excinfo:
            client.health()
        err = excinfo.value
        assert err.status == 0
        assert err.code == "transport_error"
        assert "Connection refused" in err.message
        assert err.request_id is None
        assert isinstance(err.__cause__, OSError)

    def test_timeout_wrapped_as_transport(
        self, client: Ryvex, transport: FakeTransport
    ) -> None:
        transport.responses = [TimeoutError("timed out")]
        with pytest.raises(RyvexError) as excinfo:
            client.get_resource("r-x")
        err = excinfo.value
        assert err.status == 0
        assert err.code == "transport_error"

    def test_str_is_readable(self) -> None:
        err = RyvexError(409, "conflict", "lost the race", request_id="rid-1", details=["spec"])
        text = str(err)
        assert text == "ryvex: lost the race (status=409, code=conflict, request_id=rid-1, details=[spec])"

    def test_transport_error_str(self) -> None:
        err = RyvexError.from_transport(OSError("no route"), "http://x/healthz")
        assert str(err) == "ryvex: request to http://x/healthz failed: no route (status=0, code=transport_error)"


# ---- types ----


class TestTypes:
    def test_resource_from_dict_tolerates_unknown_fields(self) -> None:
        resource = Resource.from_dict(resource_doc(3))
        assert resource.id == "r-0000000000000003"
        assert isinstance(resource.status, ResourceStatus)
        assert resource.status.observed_generation == 3
        assert not hasattr(resource, "a_future_field")

    def test_resource_from_dict_defaults(self) -> None:
        empty = Resource.from_dict({})
        assert empty.id == ""
        assert empty.generation == 0
        assert empty.status is None
        assert Resource.from_dict(None).id == ""
        assert Resource.from_dict("nope").id == ""

    def test_event_and_audit_from_dict_tolerate_nulls(self) -> None:
        event = RyvexEvent.from_dict({"id": "e1", "generation": "not-a-number"})
        assert event.id == "e1"
        assert event.generation == 0
        entry = AuditEntry.from_dict({"id": "a1", "reason": "api delete"})
        assert entry.reason == "api delete"
        assert entry.actor == ""

    def test_page_from_dict_with_factory(self) -> None:
        page = Page.from_dict(
            {"items": [{"id": "r-1"}, {"id": "r-2"}], "next_cursor": "c"}, Resource.from_dict
        )
        assert [item.id for item in page.items] == ["r-1", "r-2"]
        assert page.next_cursor == "c"
        raw_page = Page.from_dict({"items": [1, 2], "next_cursor": None})
        assert raw_page.items == [1, 2]
        assert raw_page.next_cursor == ""
