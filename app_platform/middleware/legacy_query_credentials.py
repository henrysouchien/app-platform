"""Keep legacy query authentication functional without exposing it to access logs."""

from __future__ import annotations

import logging
from urllib.parse import parse_qsl

from starlette.types import ASGIApp, Receive, Scope, Send


ACCESS_LOG_REDACTED_QUERY = b"key=%5BREDACTED%5D"
LOGGER = logging.getLogger(__name__)


def _contains_legacy_key(query_string: bytes) -> bool:
    """Recognize the exact retained ``key`` query contract and fail closed."""
    try:
        query_string.decode("ascii", errors="strict")
        return any(
            name == b"key"
            for name, _value in parse_qsl(query_string, keep_blank_values=True)
        )
    except (UnicodeDecodeError, ValueError):
        LOGGER.error(
            "legacy_query_credential_redaction_parse_failed failure_count=1"
        )
        return True


class LegacyQueryCredentialAccessLogMiddleware:
    """Give the app the original query while Uvicorn observes a redacted scope."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        query_string = scope.get("query_string", b"")
        if not query_string or not _contains_legacy_key(query_string):
            await self.app(scope, receive, send)
            return

        downstream_scope = dict(scope)
        downstream_scope["query_string"] = query_string
        scope["query_string"] = ACCESS_LOG_REDACTED_QUERY
        await self.app(downstream_scope, receive, send)


__all__ = [
    "ACCESS_LOG_REDACTED_QUERY",
    "LegacyQueryCredentialAccessLogMiddleware",
]
