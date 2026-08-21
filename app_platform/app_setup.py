"""FastAPI application setup helpers."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Sequence
from logging import Logger
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from app_platform.middleware import (
    CSRF_HEADER_NAME,
    ConsentEnforcementMiddleware,
    CsrfProtectionMiddleware,
    LegacyQueryCredentialAccessLogMiddleware,
    SecurityHeadersMiddleware,
    SensitiveResponseNoStoreMiddleware,
    create_csrf_token_response,
    resolve_session_secret,
)
from app_platform.middleware.error_handlers import (
    SENSITIVE_PATHS,
    add_validation_error_handler,
)
from app_platform.middleware.timing import RequestTimingMiddleware

PUBLIC_5XX_DETAILS = {
    500: "Internal server error",
    502: "Upstream service error",
    503: "Service temporarily unavailable",
    504: "Upstream service timed out",
}


def build_http_exception_handler(*, is_production: bool):
    async def http_exception_handler(request: Request, exc: HTTPException):
        del request
        detail = exc.detail
        if is_production and exc.status_code >= 500:
            detail = PUBLIC_5XX_DETAILS.get(exc.status_code, "Server error")
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": detail},
            headers=exc.headers,
        )

    return http_exception_handler


def build_session_lookup_error_handler():
    async def session_lookup_error_handler(request: Request, exc: Exception):
        del request, exc
        return JSONResponse(
            status_code=503,
            content={"detail": "Session service temporarily unavailable"},
            headers={"Retry-After": "2"},
        )

    return session_lookup_error_handler


def configure_exception_handlers(
    app: FastAPI,
    *,
    is_production: bool,
    validation_logger: Logger,
) -> None:
    from app_platform.db.exceptions import (
        ConnectionError,
        PoolExhaustionError,
        SessionLookupError,
    )
    from app_platform.db.handlers import db_connection_error_handler
    from database import DatabaseUnavailableError

    app.add_exception_handler(PoolExhaustionError, db_connection_error_handler)
    app.add_exception_handler(ConnectionError, db_connection_error_handler)
    app.add_exception_handler(DatabaseUnavailableError, db_connection_error_handler)
    app.add_exception_handler(
        HTTPException,
        build_http_exception_handler(is_production=is_production),
    )
    app.add_exception_handler(
        SessionLookupError,
        build_session_lookup_error_handler(),
    )
    add_validation_error_handler(
        app,
        log_details=True,
        logger=validation_logger,
        expose_details=not is_production,
        log_request_body=False,
        sensitive_paths=SENSITIVE_PATHS,
    )


def add_csrf_token_route(
    app: FastAPI,
    *,
    session_secret: str,
    secure_cookie: bool,
) -> None:
    @app.get("/api/csrf-token")
    async def get_csrf_token(request: Request):
        return create_csrf_token_response(
            request,
            secret_key=session_secret,
            secure_cookie=secure_cookie,
        )


def configure_core_middleware(
    app: FastAPI,
    *,
    session_secret: str,
    is_production: bool,
    cors_origins: Sequence[str],
) -> None:
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        https_only=is_production,
        same_site="lax",
    )
    app.add_middleware(CsrfProtectionMiddleware, secret_key=session_secret)
    app.add_middleware(ConsentEnforcementMiddleware)
    app.add_middleware(RequestTimingMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "Authorization",
            "X-API-Key",
            "X-Admin-Token",
            CSRF_HEADER_NAME,
            "X-Requested-With",
            "Accept",
            "Origin",
        ],
    )
    app.add_middleware(SecurityHeadersMiddleware, is_production=is_production)
    app.add_middleware(SensitiveResponseNoStoreMiddleware)
    # Added last so the server-owned scope observed by Uvicorn is redacted,
    # while a copied downstream scope preserves the retained legacy auth form.
    app.add_middleware(LegacyQueryCredentialAccessLogMiddleware)


def bind_dev_monitor_loop(
    *,
    get_env_fn: Callable[[str, str], str | None] = os.getenv,
    init_monitor_fn: Callable[[], Any] | None = None,
    get_running_loop_fn: Callable[[], asyncio.AbstractEventLoop] = (
        asyncio.get_running_loop
    ),
) -> None:
    if get_env_fn("DEV_MONITOR_ENABLED", "true").strip().lower() != "true":
        return

    if init_monitor_fn is None:
        from utils.dev_monitor import init_monitor

        init_monitor_fn = init_monitor

    hub = init_monitor_fn()
    try:
        hub.set_loop(get_running_loop_fn())
    except RuntimeError:
        pass


def configure_app_platform(
    app: FastAPI,
    *,
    is_production: bool,
    cors_origins: Sequence[str],
    validation_logger: Logger,
) -> str:
    configure_exception_handlers(
        app,
        is_production=is_production,
        validation_logger=validation_logger,
    )
    session_secret = resolve_session_secret(
        environment="production" if is_production else "development"
    )
    add_csrf_token_route(
        app,
        session_secret=session_secret,
        secure_cookie=is_production,
    )
    configure_core_middleware(
        app,
        session_secret=session_secret,
        is_production=is_production,
        cors_origins=cors_origins,
    )
    bind_dev_monitor_loop()
    return session_secret


__all__ = [
    "PUBLIC_5XX_DETAILS",
    "add_csrf_token_route",
    "bind_dev_monitor_loop",
    "build_http_exception_handler",
    "build_session_lookup_error_handler",
    "configure_app_platform",
    "configure_core_middleware",
    "configure_exception_handlers",
]
