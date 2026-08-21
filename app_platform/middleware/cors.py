"""CORS middleware helpers."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi.middleware.cors import CORSMiddleware

DEFAULT_CORS_ALLOWED_ORIGINS = (
    "http://localhost:3000,"
    "http://127.0.0.1:3000,"
    "http://localhost:5173,"
    "http://127.0.0.1:5173,"
    "https://localhost:8000"
)
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


def parse_cors_origins(raw_origins: str | None) -> list[str]:
    """Parse the comma-separated CORS origin environment setting."""
    if raw_origins is None:
        raw_origins = DEFAULT_CORS_ALLOWED_ORIGINS
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


def validate_cors_origins(
    origins: list[str] | tuple[str, ...],
    *,
    is_production: bool,
) -> list[str]:
    """Validate CORS origins, enforcing exact HTTPS origins in production."""
    parsed_origins = list(origins or [])
    if not is_production:
        return parsed_origins

    if not parsed_origins:
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS must include at least one exact HTTPS production "
            "origin in production."
        )

    if "*" in parsed_origins:
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS must not contain '*' in production. Set exact "
            "HTTPS domain origins instead."
        )

    localhost_origins: list[str] = []
    invalid_origins: list[str] = []
    non_https_origins: list[str] = []

    for origin in parsed_origins:
        parsed = urlparse(origin)
        hostname = parsed.hostname or ""
        has_origin_shape = (
            parsed.scheme
            and parsed.netloc
            and not parsed.params
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        )
        if not has_origin_shape:
            invalid_origins.append(origin)
            continue
        if parsed.scheme != "https":
            non_https_origins.append(origin)
        if hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} or hostname.endswith(
            ".localhost"
        ):
            localhost_origins.append(origin)

    if invalid_origins:
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS must contain exact origins without paths, "
            f"queries, or fragments in production: {invalid_origins}"
        )
    if localhost_origins:
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS contains localhost/loopback origins in "
            f"production: {localhost_origins}. Set exact production domain origins."
        )
    if non_https_origins:
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS must use HTTPS origins in production: "
            f"{non_https_origins}"
        )

    return parsed_origins


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


__all__ = [
    "DEFAULT_CORS_ALLOWED_ORIGINS",
    "DEFAULT_HEADERS",
    "DEFAULT_METHODS",
    "configure_cors",
    "parse_cors_origins",
    "validate_cors_origins",
]
