"""Safe API error type.

Every failure that is deliberately surfaced to a client is an ``ApiError`` with
an HTTP status and a short, non-secret detail string. Anything else is turned
into a generic 500 by the HTTP layer, so tracebacks and internal state never
reach the wire.
"""

from __future__ import annotations

from typing import Mapping

# Statuses the relay is allowed to emit for API failures.
ALLOWED_STATUSES = frozenset({400, 401, 404, 405, 409, 413, 429, 500})


class ApiError(Exception):
    """An error that maps directly onto a JSON error response."""

    def __init__(
        self,
        status: int,
        detail: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"unsupported API status: {status}")
        detail = str(detail).strip() or "request failed"
        if len(detail) > 200:
            detail = detail[:200]
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.headers = dict(headers or {})
