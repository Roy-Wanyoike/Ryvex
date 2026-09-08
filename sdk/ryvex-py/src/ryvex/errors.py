"""Error handling for the Ryvex REST API.

Every non-2xx response carries the frozen error envelope
(docs/api-contracts.md):

    {"error": {"code": "conflict", "message": "...", "request_id": "...", "details": []}}

:class:`RyvexError` parses it and exposes the parts as typed fields.
When the body is not the expected envelope (proxy HTML, empty body,
plain text), the error still constructs with a code inferred from the
HTTP status, so callers can always branch on ``code`` / ``status``.
Transport-level failures (DNS, connection refused, timeout) raise the
same type with ``status=0`` and ``code="transport_error"`` — one error
type to catch everywhere. ``transport_error`` is the cross-SDK
standard: the TypeScript SDK aligned to the same code (also with
``status=0``) in v0.2.0.
"""

from __future__ import annotations

import json
from typing import Any, Union

__all__ = ["DEFAULT_CODE_BY_STATUS", "TRANSPORT_ERROR", "RyvexError"]

#: Code used for transport-level failures (no HTTP status involved).
#: Cross-SDK standard: the TypeScript SDK (sdk/ryvex-ts) normalized its
#: transport failures to this same code (with ``status=0``) in v0.2.0 —
#: keep both SDKs in lockstep when touching this value.
TRANSPORT_ERROR = "transport_error"

#: Default error code for a given HTTP status, used when the response
#: body is not a parseable envelope.
DEFAULT_CODE_BY_STATUS: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    500: "internal_error",
}


def _fallback_message(status: int) -> str:
    return {
        400: "bad request",
        401: "unauthorized: missing or invalid bearer token",
        403: "forbidden: token lacks permission for this operation",
        404: "not found",
        405: "method not allowed",
        409: "conflict",
        500: "internal error",
    }.get(status, f"request failed with status {status}")


class RyvexError(Exception):
    """A failed Ryvex API call (HTTP error or transport failure).

    Attributes:
        status: HTTP status of the failed response, ``0`` for
            transport-level failures.
        code: Wire error code from the envelope (status-derived
            fallback if the body was not the envelope).
        message: Human-readable message.
        request_id: Server-side request id — quote it when filing bug
            reports.
        details: Optional structured details (e.g. offending fields).
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        request_id: str | None = None,
        details: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id
        self.details = list(details) if details else []

    def __str__(self) -> str:
        parts = [f"status={self.status}", f"code={self.code}"]
        if self.request_id:
            parts.append(f"request_id={self.request_id}")
        if self.details:
            parts.append(f"details=[{', '.join(self.details)}]")
        return f"ryvex: {self.message} ({', '.join(parts)})"

    # ---- constructors ----

    @classmethod
    def from_response(cls, status: int, body: Union[bytes, str, None]) -> "RyvexError":
        """Build an error from a raw (non-2xx) HTTP response body.

        Parses the frozen envelope when possible; falls back to a
        status-derived code otherwise.
        """
        if isinstance(body, bytes):
            text = body.decode("utf-8", errors="replace")
        else:
            text = body or ""
        fallback = DEFAULT_CODE_BY_STATUS.get(status, "internal_error")

        parsed: Any = None
        if text.strip():
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None

        detail = parsed.get("error") if isinstance(parsed, dict) else None
        if isinstance(detail, dict):
            code = detail.get("code")
            message = detail.get("message")
            request_id = detail.get("request_id")
            raw_details = detail.get("details")
            return cls(
                status,
                code if isinstance(code, str) and code else fallback,
                message if isinstance(message, str) and message else _fallback_message(status),
                request_id=request_id if isinstance(request_id, str) and request_id else None,
                details=[str(x) for x in raw_details] if isinstance(raw_details, list) else None,
            )

        snippet = text.strip()[:200]
        if snippet and not snippet.startswith("<"):
            message = f"{_fallback_message(status)}: {snippet}"
        else:
            message = _fallback_message(status)
        return cls(status, fallback, message)

    @classmethod
    def from_transport(cls, cause: BaseException, url: str) -> "RyvexError":
        """Wrap a transport-level failure (DNS, connection refused, abort)."""
        reason = str(cause) or cause.__class__.__name__
        return cls(0, TRANSPORT_ERROR, f"request to {url} failed: {reason}")
