"""Session middleware helpers."""

from __future__ import annotations

import os

from starlette.middleware.sessions import SessionMiddleware

DEFAULT_SESSION_SECRET = ""


def resolve_session_secret(secret_key: str = "", *, environment: str = "") -> str:
    if secret_key:
        return secret_key
    env_key = os.getenv("FLASK_SECRET_KEY", "")
    if not env_key and environment == "production":
        raise RuntimeError(
            "FLASK_SECRET_KEY must be set in production. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return env_key or "dev-only-not-for-production"


def configure_sessions(app, secret_key: str = ""):
    app.add_middleware(
        SessionMiddleware,
        secret_key=resolve_session_secret(secret_key),
    )
    return app


__all__ = ["DEFAULT_SESSION_SECRET", "configure_sessions", "resolve_session_secret"]
