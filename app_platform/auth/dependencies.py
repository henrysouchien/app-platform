"""FastAPI dependency helpers for app_platform.auth."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import HTTPException, Request

from .service import AuthServiceBase

TIER_ORDER = {"public": 0, "registered": 1, "paid": 2, "business": 3}


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


def create_tier_dependency(
    auth_service: AuthServiceBase,
    minimum_tier: str = "paid",
    cookie_name: str = "session_id",
) -> Callable[[Request], dict[str, Any]]:
    """Return a FastAPI dependency that requires authentication and a minimum tier."""

    normalized_minimum_tier = str(minimum_tier or "paid").strip().lower() or "paid"
    if normalized_minimum_tier not in TIER_ORDER:
        raise ValueError(f"Unknown tier: {minimum_tier}")

    get_current_user = create_auth_dependency(auth_service, cookie_name=cookie_name)

    def require_tier(request: Request) -> dict[str, Any]:
        user = get_current_user(request)
        user_tier = str(user.get("tier") or "registered").strip().lower() or "registered"
        if TIER_ORDER.get(user_tier, 0) < TIER_ORDER[normalized_minimum_tier]:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "upgrade_required",
                    "message": f"This feature requires a {normalized_minimum_tier} subscription.",
                    "tier_required": normalized_minimum_tier,
                    "tier_current": user_tier,
                },
            )
        return user

    return require_tier


__all__ = ["TIER_ORDER", "create_auth_dependency", "create_tier_dependency"]
