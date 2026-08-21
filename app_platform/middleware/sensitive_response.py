"""Cache prevention for exact sensitive HTTP response paths."""

from __future__ import annotations

from collections.abc import Collection

from starlette.types import ASGIApp, Receive, Scope, Send


DEFAULT_NO_STORE_PATHS = frozenset(
    {
        "/api/billing/checkout-sessions",
        "/api/connectors/claude/tokens",
        "/api/csrf-token",
        "/api/internal/google/sheets-access-token",
        "/api/internal/google/sheets-broker-session",
        "/api/internal/resolve-credential",
        "/api/snaptrade/create-connection-url",
        "/auth/google",
        "/generate_key",
        "/plaid/create_link_token",
        "/plaid/create_update_link_token",
        "/plaid/exchange_public_token",
        "/plaid/poll_completion",
    }
)


class SensitiveResponseNoStoreMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        paths: Collection[str] = DEFAULT_NO_STORE_PATHS,
    ) -> None:
        self.app = app
        self.paths = frozenset(paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") not in self.paths:
            await self.app(scope, receive, send)
            return

        async def no_store_send(message):
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in {b"cache-control", b"pragma"}
                ]
                headers.extend(
                    (
                        (b"cache-control", b"private, no-store"),
                        (b"pragma", b"no-cache"),
                    )
                )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, no_store_send)


__all__ = ["DEFAULT_NO_STORE_PATHS", "SensitiveResponseNoStoreMiddleware"]
