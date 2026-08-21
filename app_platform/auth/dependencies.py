"""FastAPI dependency helpers for app_platform.auth."""

from __future__ import annotations

import re
import logging
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import HTTPException, Request

from .service import AuthServiceBase

TIER_ORDER = {"public": 0, "registered": 1, "paid": 2, "business": 3}
logger = logging.getLogger(__name__)


def create_auth_dependency(
    auth_service: AuthServiceBase,
    cookie_name: str = "session_id",
) -> Callable[[Request], dict[str, Any]]:
    """Return a FastAPI dependency that resolves the current user from a cookie."""

    def get_current_user(request: Request) -> dict[str, Any]:
        session_id = request.cookies.get(cookie_name)
        user = auth_service.get_user_by_session(session_id)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        return user

    return get_current_user


def create_api_key_dependency(
    public_key: str = "public_key",
    get_public_key_fn: Callable[[], str] | None = None,
) -> Callable[[Request], str]:
    """Return a FastAPI dependency that resolves API keys from header or query."""

    def get_api_key(request: Request) -> str:
        return (
            request.headers.get("X-API-Key")
            or request.query_params.get("key")
            or (
                get_public_key_fn()
                if get_public_key_fn is not None
                else public_key
            )
        )

    return get_api_key


def create_tier_dependency(
    auth_service: AuthServiceBase,
    minimum_tier: str = "paid",
    cookie_name: str = "session_id",
    *,
    compatibility_route_code: str,
) -> Callable[[Request], dict[str, Any]]:
    """Return a FastAPI dependency that requires authentication and a minimum tier."""

    normalized_minimum_tier = str(minimum_tier or "paid").strip().lower() or "paid"
    if normalized_minimum_tier not in TIER_ORDER:
        raise ValueError(f"Unknown tier: {minimum_tier}")
    if not re.fullmatch(r"[a-z][a-z0-9._:-]{0,127}", compatibility_route_code):
        raise ValueError("compatibility_route_code must be a stable bounded code")

    get_current_user = create_auth_dependency(auth_service, cookie_name=cookie_name)

    def require_tier(request: Request) -> dict[str, Any]:
        from app_platform.commercial.tier_compatibility import (
            TierCompatibilityMode,
            evaluate_tier_compatibility,
            log_tier_parity,
            resolve_canonical_tier_projection,
        )
        from app_platform.commercial.flags import get_commercial_flags
        from app_platform.db.session import get_db_session

        user = get_current_user(request)
        user_tier = (
            str(user.get("tier") or "registered").strip().lower()
            or "registered"
        )
        canonical_projection = None
        mode = TierCompatibilityMode.LEGACY
        try:
            flags = get_commercial_flags()
            raw_user_id = user.get("id", user.get("user_id"))
            if (
                flags.commercial_tier_compatibility_shadow_enabled
                and raw_user_id is not None
            ):
                with get_db_session() as connection:
                    try:
                        canonical_projection = resolve_canonical_tier_projection(
                            connection,
                            user_id=int(raw_user_id),
                            evaluated_at=datetime.now(timezone.utc),
                        )
                    finally:
                        if not getattr(connection, "autocommit", False):
                            connection.rollback()
                mode = TierCompatibilityMode.SHADOW
        except Exception:
            logger.exception("Commercial tier parity observation failed safely")
        compatibility = evaluate_tier_compatibility(
            route_code=compatibility_route_code,
            mode=mode,
            legacy_tier=user_tier,
            canonical_projection=canonical_projection,
            minimum_legacy_tier=normalized_minimum_tier,
            parity_sink=(
                log_tier_parity
                if mode == TierCompatibilityMode.SHADOW
                else lambda _event: None
            ),
        )
        if not compatibility.allowed:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "upgrade_required",
                    "message": (
                        f"This feature requires a {normalized_minimum_tier} "
                        "subscription."
                    ),
                    "tier_required": normalized_minimum_tier,
                    "tier_current": user_tier,
                },
            )
        return user

    return require_tier


__all__ = [
    "TIER_ORDER",
    "create_api_key_dependency",
    "create_auth_dependency",
    "create_tier_dependency",
]
