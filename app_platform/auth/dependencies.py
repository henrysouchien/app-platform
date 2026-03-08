"""FastAPI dependency helpers for app_platform.auth."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import HTTPException, Request

from .service import AuthServiceBase


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


__all__ = ["create_auth_dependency"]
