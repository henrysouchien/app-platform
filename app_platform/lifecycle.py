"""FastAPI application lifecycle helpers."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _env_flag(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in _TRUE_VALUES


def _strict_security_flag(name: str, default: str) -> bool:
    value = os.getenv(name, default).strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise RuntimeError(
        f"{name} must be one of: 1, true, yes, on, 0, false, no, off"
    )


def create_app_lifespan(*, logger: Any):
    """Create the FastAPI lifespan context for startup probes and shutdown."""

    @asynccontextmanager
    async def _lifespan(app: Any) -> AsyncIterator[None]:
        del app
        startup_probes = _env_flag("STARTUP_PROBES", "true")
        private_vault_rls_required = _strict_security_flag(
            "PRIVATE_VAULT_RLS_REQUIRED",
            "false",
        )
        if startup_probes:
            from database import is_db_available, reset_db_availability

            reset_db_availability()
            if not is_db_available():
                logger.critical(
                    "Database unreachable at startup. Possible causes: "
                    "pgbouncer not running (port 6432), PostgreSQL down, "
                    "DATABASE_URL misconfigured, or pool error. "
                    "Check pgbouncer and PostgreSQL, then restart."
                )
                raise RuntimeError("Database unreachable at startup")
            logger.info("Database reachable")

            if _env_flag("CELERY_ENABLED", "false"):
                from workers.celery_security import (
                    CeleryTransportSecurityError,
                    resolve_celery_transport_config,
                )

                try:
                    broker_url = resolve_celery_transport_config().broker_url
                except CeleryTransportSecurityError as exc:
                    logger.critical(
                        "Celery broker configuration rejected: %s. Redis liveness "
                        "was not tested. Configure an authenticated broker URL, or "
                        "set CELERY_ENABLED=false to run without the queue.",
                        exc,
                    )
                    raise RuntimeError(
                        "Celery broker configuration invalid at startup"
                    ) from exc

                try:
                    import redis

                    redis.Redis.from_url(
                        broker_url,
                        socket_connect_timeout=2,
                        socket_timeout=2,
                    ).ping()
                except Exception as exc:
                    logger.critical(
                        "Celery broker unreachable — is redis running? "
                        "Start redis before risk_module. Error: %s",
                        exc,
                    )
                    raise RuntimeError(
                        "Celery broker unreachable at startup"
                    ) from exc
                logger.info("Celery broker reachable")
        if private_vault_rls_required:
            from app_platform.db.private_vault import (
                PrivateVaultMaintenanceError,
                assert_private_vault_runtime_connection,
            )
            from database import get_db_session

            try:
                with get_db_session() as conn:
                    try:
                        runtime_role = assert_private_vault_runtime_connection(conn)
                    finally:
                        rollback = getattr(conn, "rollback", None)
                        if callable(rollback):
                            rollback()
            except PrivateVaultMaintenanceError as exc:
                logger.critical("Private-vault RLS readiness failed: %s", exc)
                raise RuntimeError("Private-vault RLS readiness check failed") from exc
            logger.info("Private-vault RLS ready for runtime role %s", runtime_role)
        from app_platform.api_budget.config import get_budget_config
        from app_platform.commercial.flags import get_commercial_flags

        get_budget_config(refresh=True)
        get_commercial_flags(refresh=True)
        try:
            yield
        finally:
            try:
                from workers.celery_app import app as celery_app

                celery_app.close()
            except Exception:
                pass
            from app_platform.db.pool import close_pool

            close_pool()

    return _lifespan


__all__ = ["create_app_lifespan"]
