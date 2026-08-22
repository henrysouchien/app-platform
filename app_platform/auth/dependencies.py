"""FastAPI dependency helpers for app_platform.auth."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable

from fastapi import HTTPException, Request

from .service import AuthServiceBase

TIER_ORDER = {"public": 0, "registered": 1, "paid": 2, "business": 3}


def resolve_user_tier(user: Mapping[str, Any]) -> str:
    """Return the access tier recorded on a user record, normalized.

    The auth service produces the user record, so the shape of that record --
    including which field carries the tier -- is decided here. Callers that
    gate on tier take the value from this function; they do not read the field
    themselves.
    """

    return str(user.get("tier") or "registered").strip().lower() or "registered"


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


__all__ = [
    "TIER_ORDER",
    "create_api_key_dependency",
    "create_auth_dependency",
    "resolve_user_tier",
]
