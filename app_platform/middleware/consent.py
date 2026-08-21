"""Server-side consent boundary for authenticated session API traffic."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


DEFAULT_ALLOWED_PATHS = frozenset(
    {
        "/api/csrf-token",
        "/api/legal/consents/current",
        "/api/legal/consents/accept",
    }
)


class ConsentEnforcementMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        auth_service: Any | None = None,
        session_factory: Callable[[], Any] | None = None,
        consent_checker: Callable[..., bool] | None = None,
    ) -> None:
        self.app = app
        if auth_service is None:
            from services.auth_service import auth_service as default_auth_service

            auth_service = default_auth_service
        if session_factory is None:
            from database import get_db_session

            session_factory = get_db_session
        if consent_checker is None:
            from services.user_consents import GENERAL_DOCUMENT_TYPES, has_current_consent

            def consent_checker(conn: Any, *, user_id: int) -> bool:
                return all(
                    has_current_consent(conn, user_id=user_id, document_type=document_type)
                    for document_type in GENERAL_DOCUMENT_TYPES
                )

        self.auth_service = auth_service
        self.session_factory = session_factory
        self.consent_checker = consent_checker

    @staticmethod
    def _is_allowed(scope: Scope) -> bool:
        method = str(scope.get("method") or "GET").upper()
        path = str(scope.get("path") or "")
        if method == "OPTIONS" or not path.startswith("/api/"):
            return True
        return (
            path in DEFAULT_ALLOWED_PATHS
            or path.startswith("/auth/")
            or path == "/health"
            or path.startswith("/health/")
            or path.startswith("/api/health")
        )

    def _has_required_consent(self, user_id: int) -> bool:
        with self.session_factory() as conn:
            try:
                return bool(self.consent_checker(conn, user_id=user_id))
            finally:
                conn.rollback()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self._is_allowed(scope):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        session_id = request.cookies.get("session_id")
        if not session_id:
            await self.app(scope, receive, send)
            return
        user = await run_in_threadpool(self.auth_service.get_user_by_session, session_id)
        if not user:
            await self.app(scope, receive, send)
            return
        raw_user_id = user.get("user_id", user.get("id"))
        try:
            user_id = int(raw_user_id)
        except (TypeError, ValueError):
            await self.app(scope, receive, send)
            return
        if await run_in_threadpool(self._has_required_consent, user_id):
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            status_code=428,
            content={
                "detail": {
                    "error": "consent_required",
                    "message": "Current Terms and Privacy Policy acceptance is required.",
                    "consent_url": "/api/legal/consents/current",
                }
            },
            headers={"Cache-Control": "private, no-store"},
        )
        await response(scope, receive, send)


__all__ = ["ConsentEnforcementMiddleware", "DEFAULT_ALLOWED_PATHS"]
