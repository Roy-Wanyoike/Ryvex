"""ryvex — Official Python client for the Ryvex control plane REST API.

The ``/v1`` face, contract frozen in docs/api-contracts.md. Stdlib-only
runtime (urllib.request); the only import cost is your own patience.

    from ryvex import Ryvex, RyvexError

    ryvex = Ryvex("http://127.0.0.1:8080", "ryk_local_dev")
    health = ryvex.health()
"""

from .client import Ryvex
from .errors import RyvexError
from .types import (
    ApiIndex,
    AuditEntry,
    AuditPage,
    CreateResourceInput,
    EventsPage,
    HealthInfo,
    Page,
    ReconcileAck,
    Resource,
    ResourceStatus,
    RyvexEvent,
    UpsertResourceInput,
)

__version__ = "1.0.0"

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
    "Ryvex",
    "RyvexError",
    "RyvexEvent",
    "UpsertResourceInput",
    "__version__",
]
