"""Ryvex — Python client for the Ryvex control plane REST API.

Mirrors the TypeScript SDK (sdk/ryvex-ts) method for method (snake_case
aside): same URL shapes, same headers, same error envelope handling.
The frozen contract lives in docs/api-contracts.md.

Every request carries ``Authorization: Bearer <token>``,
``Content-Type: application/json`` and ``Accept: application/json``.
Non-2xx responses and transport failures raise
:class:`~ryvex.errors.RyvexError` (``status=0`` for transport errors).

Runtime dependencies: none — everything rides on the standard library
(:mod:`urllib.request`).
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.parse
from collections.abc import Iterator, Mapping
from urllib.request import Request, urlopen

from .errors import RyvexError
from .types import (
    ApiIndex,
    AuditPage,
    CreateResourceInput,
    EventsPage,
    HealthInfo,
    Page,
    ReconcileAck,
    Resource,
    UpsertResourceInput,
)

__all__ = ["Ryvex"]

# Transport-level failures: URLError (incl. HTTPError, handled before
# this tuple applies), low-level http.client breakage, and raw
# OSError / socket timeouts.
_TRANSPORT_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError)


def _seg(value: str) -> str:
    """URL-quote a single path segment ('/' and friends become %XX)."""
    return urllib.parse.quote(str(value), safe="")


class Ryvex:
    """Client for the Ryvex ``/v1`` REST face.

    Example:
        ryvex = Ryvex("http://127.0.0.1:8080", "ryk_local_dev")
        health = ryvex.health()
        app = ryvex.create_resource({
            "kind": "Application", "org": "acme", "project": "core",
            "env": "prod", "name": "checkout",
            "spec": {"image": "checkout:1.42.0", "replicas": 4},
        })
    """

    def __init__(self, base_url: str, token: str, timeout: float = 15.0) -> None:
        if not isinstance(base_url, str) or not base_url:
            raise TypeError("ryvex: base_url is required")
        if not isinstance(token, str) or not token:
            raise TypeError("ryvex: token is required")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # ---- service ----

    def health(self) -> HealthInfo:
        """Liveness probe. GET /healthz (unauthenticated on the server)."""
        return HealthInfo.from_dict(self._request_json("GET", "/healthz"))

    def index(self) -> ApiIndex:
        """Machine-readable endpoint list. GET /v1."""
        return ApiIndex.from_dict(self._request_json("GET", "/v1"))

    # ---- resources (handle-addressed) ----

    def create_resource(self, doc: CreateResourceInput) -> Resource:
        """Create a resource at a fresh address. POST /v1/resources -> 201."""
        return Resource.from_dict(self._request_json("POST", "/v1/resources", body=doc))

    def get_resource(self, resource_id: str) -> Resource:
        """Fetch a resource by opaque ID. GET /v1/resources/{id}."""
        return Resource.from_dict(
            self._request_json("GET", f"/v1/resources/{_seg(resource_id)}")
        )

    def delete_resource(self, resource_id: str) -> None:
        """Delete a resource by opaque ID. DELETE /v1/resources/{id} -> 204."""
        self._send("DELETE", f"/v1/resources/{_seg(resource_id)}")

    def list_resources(
        self,
        *,
        org: str | None = None,
        project: str | None = None,
        env: str | None = None,
        kind: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        **extra_filters: object,
    ) -> Page[Resource]:
        """Fetch one filtered page.

        GET /v1/resources?org=&project=&env=&kind=&limit=&cursor=.
        ``next_cursor`` is "" on the last page. ``kind`` is
        case-insensitive; simple plurals ("applications") are accepted.
        Unknown keyword filters are forwarded as query parameters.
        """
        query: dict[str, object] = {
            "org": org,
            "project": project,
            "env": env,
            "kind": kind,
            "limit": limit,
            "cursor": cursor,
            **extra_filters,
        }
        data = self._request_json("GET", "/v1/resources", query=query)
        return Page.from_dict(data, Resource.from_dict)

    def list_all(
        self,
        *,
        org: str | None = None,
        project: str | None = None,
        env: str | None = None,
        kind: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        **extra_filters: object,
    ) -> Iterator[Resource]:
        """Iterate every matching resource across all pages.

        Follows the ``next_cursor`` chain until it is "" — lazily
        fetched, so each ``for`` turn issues at most one HTTP request.
        A repeated cursor (server-side loop) ends the iteration.
        """
        seen: set[str] = set()
        cursor = cursor or ""
        while True:
            seen.add(cursor)
            page = self.list_resources(
                org=org,
                project=project,
                env=env,
                kind=kind,
                limit=limit,
                cursor=cursor or None,
                **extra_filters,
            )
            yield from page.items
            next_cursor = page.next_cursor
            if next_cursor == "" or next_cursor in seen:
                return
            cursor = next_cursor

    # ---- resources (scope-addressed) ----

    def get_in_scope(
        self, org: str, project: str, env: str, kind: str, name: str
    ) -> Resource:
        """Fetch by logical address. GET /v1/{org}/{project}/{env}/{kind}/{name}."""
        return Resource.from_dict(
            self._request_json("GET", self._scope_path(org, project, env, kind, name))
        )

    def put_in_scope(
        self,
        org: str,
        project: str,
        env: str,
        kind: str,
        name: str,
        doc: UpsertResourceInput,
    ) -> Resource:
        """Upsert by logical address. PUT /v1/{org}/{project}/{env}/{kind}/{name}.

        Returns the 201's stored doc when the address was fresh
        (created) and the 200's when it already existed (updated).

        Optimistic concurrency (CAS): pass ``doc["generation"]`` — the
        value you previously read — to fail with a 409 ``conflict``
        :class:`~ryvex.errors.RyvexError` if the stored generation
        moved. Omit it for last-writer-wins.
        """
        return Resource.from_dict(
            self._request_json(
                "PUT", self._scope_path(org, project, env, kind, name), body=doc
            )
        )

    def delete_in_scope(
        self, org: str, project: str, env: str, kind: str, name: str
    ) -> None:
        """Delete by logical address.

        DELETE /v1/{org}/{project}/{env}/{kind}/{name} -> 204.
        """
        self._send("DELETE", self._scope_path(org, project, env, kind, name))

    # ---- observability & control ----

    def events(self, org: str, limit: int = 100) -> EventsPage:
        """Recent bus events for an org, newest first. GET /v1/{org}/events?limit=."""
        return EventsPage.from_dict(
            self._request_json("GET", f"/v1/{_seg(org)}/events", query={"limit": limit})
        )

    def audit(self, org: str, limit: int = 100, kind: str | None = None) -> AuditPage:
        """Audit entries for an org, newest first. GET /v1/{org}/audit?kind=&limit=."""
        return AuditPage.from_dict(
            self._request_json(
                "GET", f"/v1/{_seg(org)}/audit", query={"kind": kind, "limit": limit}
            )
        )

    def trigger_reconcile(self, org: str, resource_id: str) -> ReconcileAck:
        """Trigger an immediate reconcile. POST /v1/{org}/reconcile/{id} -> 202."""
        return ReconcileAck.from_dict(
            self._request_json("POST", f"/v1/{_seg(org)}/reconcile/{_seg(resource_id)}")
        )

    # ---- internals ----

    @staticmethod
    def _scope_path(org: str, project: str, env: str, kind: str, name: str) -> str:
        return f"/v1/{_seg(org)}/{_seg(project)}/{_seg(env)}/{_seg(kind)}/{_seg(name)}"

    def _build_url(self, path: str, query: Mapping[str, object] | None = None) -> str:
        url = f"{self.base_url}{path}"
        params = [
            (key, str(value))
            for key, value in (query or {}).items()
            if value is not None and value != ""
        ]
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return url

    def _send(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, object] | None = None,
        query: Mapping[str, object] | None = None,
    ) -> tuple[int, bytes]:
        """Issue one request, returning ``(http_status, raw_body)``.

        Raises :class:`RyvexError` for transport failures and non-2xx
        replies (parsed from the frozen error envelope).
        """
        url = self._build_url(path, query)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            response = urlopen(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read()
            except OSError:
                raw = b""
            finally:
                exc.close()
            raise RyvexError.from_response(exc.code, raw) from None
        except _TRANSPORT_ERRORS as exc:
            raise RyvexError.from_transport(exc, url) from exc
        try:
            with response:
                return response.status, response.read()
        except _TRANSPORT_ERRORS as exc:
            raise RyvexError.from_transport(exc, url) from exc

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, object] | None = None,
        query: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """Like :meth:`_send` but JSON-decodes a non-empty 2xx body."""
        status, raw = self._send(method, path, body=body, query=query)
        if not raw:
            # 204 / empty 2xx — hand back a permissive empty document.
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RyvexError(
                status, "internal_error", f"invalid JSON in response from {path}"
            ) from exc
