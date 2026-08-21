"""FastAPI app factory assembly for the API platform."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from typing import Any

from fastapi import FastAPI

from app_platform.app_setup import configure_app_platform
from app_platform.lifecycle import create_app_lifespan


def create_app_instance(
    *,
    is_production: bool,
    cors_origins: Sequence[str],
    validation_logger: Any,
    lifespan_logger: Any,
    log_critical_alert_fn: Callable[[str, str, str, str], Any],
    configure_app_platform_fn: Callable[..., Any] = configure_app_platform,
    create_app_lifespan_fn: Callable[..., Any] = create_app_lifespan,
    get_env_fn: Callable[[str], str | None] = os.getenv,
) -> FastAPI:
    """Create and configure the FastAPI application instance."""

    if not get_env_fn("DATABASE_URL"):
        log_critical_alert_fn(
            "missing_database_url",
            "high",
            "DATABASE_URL environment variable is not set",
            "Set DATABASE_URL environment variable for database connectivity",
        )

    if not get_env_fn("FMP_API_KEY"):
        log_critical_alert_fn(
            "missing_fmp_api_key",
            "high",
            "FMP_API_KEY environment variable is not set",
            "Set FMP_API_KEY environment variable for market data access",
        )

    app = FastAPI(
        title="Risk Module API",
        version="2.0",
        description="Portfolio risk analysis and optimization API",
        lifespan=create_app_lifespan_fn(logger=lifespan_logger),
        docs_url=None if is_production else "/docs",
        redoc_url=None if is_production else "/redoc",
        openapi_url=None if is_production else "/openapi.json",
    )

    configure_app_platform_fn(
        app,
        is_production=is_production,
        cors_origins=cors_origins,
        validation_logger=validation_logger,
    )

    return app


__all__ = ["create_app_instance"]
