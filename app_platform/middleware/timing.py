"""Request timing middleware."""

from __future__ import annotations

import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app_platform.logging.core import log_timing_event


class RequestTimingMiddleware:
    """Pure ASGI middleware for full request lifecycle timing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()
        status_code = 500
        is_streaming = False

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, is_streaming

            if message["type"] == "http.response.start":
                status_code = message.get("status", 500)
                await send(message)
                return

            if (
                message["type"] == "http.response.body"
                and message.get("more_body", False)
            ):
                is_streaming = True

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            method = scope.get("method", "?")
            path = scope.get("path", "?")

            log_timing_event(
                kind="request",
                name=f"{method} {path}",
                duration_ms=duration_ms,
                status=status_code,
                streaming=is_streaming,
            )


__all__ = ["RequestTimingMiddleware"]
