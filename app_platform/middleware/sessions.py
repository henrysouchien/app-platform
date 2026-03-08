"""Session middleware helpers."""

from __future__ import annotations

import os

from starlette.middleware.sessions import SessionMiddleware

DEFAULT_SESSION_SECRET = "dev-secret-key-change-in-production"


def resolve_session_secret(secret_key: str = "") -> str:
    if secret_key:
        return secret_key
    return os.getenv("FLASK_SECRET_KEY", DEFAULT_SESSION_SECRET)


def configure_sessions(app, secret_key: str = ""):
    app.add_middleware(
        SessionMiddleware,
        secret_key=resolve_session_secret(secret_key),
    )
    return app


__all__ = ["DEFAULT_SESSION_SECRET", "configure_sessions", "resolve_session_secret"]
