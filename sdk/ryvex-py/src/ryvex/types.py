"""Wire types for the Ryvex control plane REST API (the ``/v1`` face).

These mirror the Go types in ``internal/state`` and ``internal/bus``
one to one (JSON tags are the source of truth). Timestamps stay
ISO-8601 strings so callers pick their own parsing strategy; the
server always emits UTC RFC3339.

Per the frozen contract (docs/api-contracts.md): new fields may be
added to responses at any time. The ``from_dict`` constructors
therefore ignore unknown keys and default missing ones instead of
raising — treat these shapes as minimums, not exhaustive.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Generic, TypedDict, TypeVar

T = TypeVar("T")

__all__ = [
    "ApiIndex",
    "AuditEntry",
    "AuditPage",
    "CreateResourceInput",
    "EventsPage",
    "HealthInfo",
    "Page",
    "ReconcileAck",
    "Resource",
    "ResourceStatus",
    "RyvexEvent",
    "UpsertResourceInput",
]


# ---- coercion helpers (tolerant by design) ----


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _as_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return int(value)


def _as_dict(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, Mapping) else None


# ---- resource documents ----


@dataclass
class ResourceStatus:
    """Observed state, owned exclusively by the reconciler."""

    phase: str = ""
    message: str = ""
    observed_generation: int = 0
    updated_at: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "ResourceStatus":
        if not isinstance(data, Mapping):
            return cls()
        return cls(
            phase=_as_str(data.get("phase")),
            message=_as_str(data.get("message")),
            observed_generation=_as_int(data.get("observed_generation")),
            updated_at=_as_str(data.get("updated_at")),
        )


@dataclass
class Resource:
    """A stored resource document, exactly as the API returns it.

    ``status`` and ``generation`` are server-owned: client writes to
    ``status`` are ignored, and ``generation`` increments only when
    ``spec``/``labels`` actually change.
    """

    id: str = ""
    kind: str = ""
    org: str = ""
    project: str = ""
    env: str = ""
    name: str = ""
    generation: int = 0
    labels: dict[str, str] | None = None
    spec: dict[str, Any] | None = None
    status: ResourceStatus | None = None
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "Resource":
        """Build from a wire document; unknown keys are ignored."""
        if not isinstance(data, Mapping):
            return cls()
        status = data.get("status")
        return cls(
            id=_as_str(data.get("id")),
            kind=_as_str(data.get("kind")),
            org=_as_str(data.get("org")),
            project=_as_str(data.get("project")),
            env=_as_str(data.get("env")),
            name=_as_str(data.get("name")),
            generation=_as_int(data.get("generation")),
            labels=_as_dict(data.get("labels")),
            spec=_as_dict(data.get("spec")),
            status=ResourceStatus.from_dict(status) if isinstance(status, Mapping) else None,
            created_at=_as_str(data.get("created_at")),
            updated_at=_as_str(data.get("updated_at")),
        )


class CreateResourceInput(TypedDict, total=False):
    """Body for ``POST /v1/resources`` (create at a fresh address)."""

    kind: str
    org: str
    project: str
    env: str
    name: str
    labels: dict[str, str]
    spec: dict[str, Any]


class UpsertResourceInput(TypedDict, total=False):
    """Body for ``PUT /v1/{org}/{project}/{env}/{kind}/{name}`` (upsert).

    Identity comes from the path; the server only consumes ``spec``,
    ``labels`` and ``generation`` from this document. Include
    ``generation: N`` for optimistic concurrency (CAS): the write fails
    with a 409 ``conflict`` error if the stored generation is no longer
    N. Omit it for last-writer-wins.
    """

    kind: str
    org: str
    project: str
    env: str
    name: str
    generation: int
    labels: dict[str, str]
    spec: dict[str, Any]


# ---- pagination ----


@dataclass
class Page(Generic[T]):
    """One cursor-paginated page. ``next_cursor`` is "" on the last page."""

    items: list[T] = field(default_factory=list)
    next_cursor: str = ""

    @classmethod
    def from_dict(cls, data: Any, item_factory: Callable[[Any], T] | None = None) -> "Page[T]":
        """Build from a wire page; unknown keys are ignored."""
        if not isinstance(data, Mapping):
            return cls()
        raw = data.get("items")
        raw = raw if isinstance(raw, list) else []
        items = [item_factory(x) if item_factory is not None else x for x in raw]
        return cls(items=items, next_cursor=_as_str(data.get("next_cursor")))


# ---- events ----


@dataclass
class RyvexEvent:
    """A bus event (``ryvex.resource.{org}.{kind}.{event}``).

    ``type`` is one of created | updated | deleted | status_changed.
    """

    id: str = ""
    time: str = ""
    type: str = ""
    subject: str = ""
    org: str = ""
    project: str = ""
    env: str = ""
    kind: str = ""
    name: str = ""
    resource_id: str = ""
    generation: int = 0
    phase: str = ""
    actor: str = ""
    data: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: Any) -> "RyvexEvent":
        if not isinstance(data, Mapping):
            return cls()
        return cls(
            id=_as_str(data.get("id")),
            time=_as_str(data.get("time")),
            type=_as_str(data.get("type")),
            subject=_as_str(data.get("subject")),
            org=_as_str(data.get("org")),
            project=_as_str(data.get("project")),
            env=_as_str(data.get("env")),
            kind=_as_str(data.get("kind")),
            name=_as_str(data.get("name")),
            resource_id=_as_str(data.get("resource_id")),
            generation=_as_int(data.get("generation")),
            phase=_as_str(data.get("phase")),
            actor=_as_str(data.get("actor")),
            data=_as_dict(data.get("data")),
        )


@dataclass
class EventsPage:
    """Response of ``GET /v1/{org}/events``."""

    events: list[RyvexEvent] = field(default_factory=list)
    count: int = 0

    @classmethod
    def from_dict(cls, data: Any) -> "EventsPage":
        if not isinstance(data, Mapping):
            return cls()
        raw = data.get("events")
        events = (
            [RyvexEvent.from_dict(e) for e in raw] if isinstance(raw, list) else []
        )
        count = data.get("count")
        return cls(events=events, count=_as_int(count) if count is not None else len(events))


# ---- audit ----


@dataclass
class AuditEntry:
    """A single state-mutation record from the audit trail.

    ``action`` is one of created | updated | deleted | status_changed.
    """

    id: str = ""
    time: str = ""
    actor: str = ""
    action: str = ""
    resource_id: str = ""
    kind: str = ""
    logical_key: str = ""
    generation: int = 0
    reason: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "AuditEntry":
        if not isinstance(data, Mapping):
            return cls()
        return cls(
            id=_as_str(data.get("id")),
            time=_as_str(data.get("time")),
            actor=_as_str(data.get("actor")),
            action=_as_str(data.get("action")),
            resource_id=_as_str(data.get("resource_id")),
            kind=_as_str(data.get("kind")),
            logical_key=_as_str(data.get("logical_key")),
            generation=_as_int(data.get("generation")),
            reason=_as_str(data.get("reason")),
        )


@dataclass
class AuditPage:
    """Response of ``GET /v1/{org}/audit``."""

    entries: list[AuditEntry] = field(default_factory=list)
    count: int = 0

    @classmethod
    def from_dict(cls, data: Any) -> "AuditPage":
        if not isinstance(data, Mapping):
            return cls()
        raw = data.get("entries")
        entries = (
            [AuditEntry.from_dict(e) for e in raw] if isinstance(raw, list) else []
        )
        count = data.get("count")
        return cls(entries=entries, count=_as_int(count) if count is not None else len(entries))


# ---- misc ----


@dataclass
class ReconcileAck:
    """Response of ``POST /v1/{org}/reconcile/{id}`` (202)."""

    status: str = ""
    resource_id: str = ""
    reason: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "ReconcileAck":
        if not isinstance(data, Mapping):
            return cls()
        return cls(
            status=_as_str(data.get("status")),
            resource_id=_as_str(data.get("resource_id")),
            reason=_as_str(data.get("reason")),
        )


@dataclass
class HealthInfo:
    """Response of ``GET /healthz`` (unauthenticated)."""

    status: str = ""
    service: str = ""
    version: str = ""
    resources: int = 0
    time: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "HealthInfo":
        if not isinstance(data, Mapping):
            return cls()
        return cls(
            status=_as_str(data.get("status")),
            service=_as_str(data.get("service")),
            version=_as_str(data.get("version")),
            resources=_as_int(data.get("resources")),
            time=_as_str(data.get("time")),
        )


@dataclass
class ApiIndex:
    """Machine-readable endpoint list served at ``GET /v1``."""

    name: str = ""
    version: str = ""
    endpoints: list[str] = field(default_factory=list)
    docs: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "ApiIndex":
        if not isinstance(data, Mapping):
            return cls()
        raw = data.get("endpoints")
        endpoints = [str(e) for e in raw] if isinstance(raw, list) else []
        return cls(
            name=_as_str(data.get("name")),
            version=_as_str(data.get("version")),
            endpoints=endpoints,
            docs=_as_str(data.get("docs")),
        )
