"""CORS middleware helpers."""

from __future__ import annotations

from fastapi.middleware.cors import CORSMiddleware

DEFAULT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
DEFAULT_HEADERS = [
    "Content-Type",
    "Authorization",
    "X-API-Key",
    "X-Admin-Token",
    "X-Requested-With",
    "X-Conversation-ID",
    "X-Request-ID",
    "Accept",
    "Origin",
]


def configure_cors(
    app,
    origins,
    credentials: bool = True,
    methods=None,
    headers=None,
):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(origins or []),
        allow_credentials=credentials,
        allow_methods=list(methods or DEFAULT_METHODS),
        allow_headers=list(headers or DEFAULT_HEADERS),
    )
    return app


__all__ = ["DEFAULT_HEADERS", "DEFAULT_METHODS", "configure_cors"]
