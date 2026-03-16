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
        buffered_start: Message | None = None

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, is_streaming, buffered_start

            if message["type"] == "http.response.start":
                status_code = message.get("status", 500)
                buffered_start = message
                return

            if buffered_start is not None:
                if message["type"] == "http.response.body":
                    more_body = message.get("more_body", False)
                    is_streaming = more_body

                    if not is_streaming:
                        duration_ms = (time.perf_counter() - start) * 1000
                        raw_headers = list(buffered_start.get("headers", []))
                        raw_headers.append(
                            (b"x-request-duration-ms", f"{duration_ms:.1f}".encode())
                        )
                        buffered_start = {**buffered_start, "headers": raw_headers}

                await send(buffered_start)
                buffered_start = None

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            method = scope.get("method", "?")
            path = scope.get("path", "?")
            query = scope.get("query_string", b"").decode()

            log_timing_event(
                kind="request",
                name=f"{method} {path}",
                duration_ms=duration_ms,
                status=status_code,
                streaming=is_streaming,
                query=query if query else None,
            )


__all__ = ["RequestTimingMiddleware"]
