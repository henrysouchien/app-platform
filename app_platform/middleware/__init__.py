"""Middleware exports for app_platform."""

from __future__ import annotations

from dataclasses import dataclass, field

from slowapi import Limiter

from .cors import DEFAULT_HEADERS, DEFAULT_METHODS, configure_cors
from .error_handlers import add_rate_limit_handler, add_validation_error_handler
from .rate_limiter import ApiKeyRegistry, RateLimitConfig, create_limiter
from .sessions import DEFAULT_SESSION_SECRET, configure_sessions, resolve_session_secret
from .timing import RequestTimingMiddleware


@dataclass
class MiddlewareConfig:
    cors_origins: list[str] = field(default_factory=list)
    cors_credentials: bool = True
    session_secret: str = ""
    rate_limiter: Limiter | None = None
    validation_error_logging: bool = False


def configure_middleware(app, config: MiddlewareConfig | None = None):
    config = config or MiddlewareConfig()
    if config.rate_limiter is not None:
        app.state.limiter = config.rate_limiter

    configure_cors(
        app,
        config.cors_origins,
        credentials=config.cors_credentials,
    )
    configure_sessions(app, config.session_secret)
    add_validation_error_handler(
        app,
        log_details=config.validation_error_logging,
    )
    add_rate_limit_handler(
        app,
        dev_mode=bool(
            config.rate_limiter is not None
            and not getattr(config.rate_limiter, "enabled", True)
        ),
    )
    # Added last so it wraps outermost.
    app.add_middleware(RequestTimingMiddleware)
    return app


__all__ = [
    "ApiKeyRegistry",
    "DEFAULT_HEADERS",
    "DEFAULT_METHODS",
    "DEFAULT_SESSION_SECRET",
    "MiddlewareConfig",
    "RateLimitConfig",
    "RequestTimingMiddleware",
    "add_rate_limit_handler",
    "add_validation_error_handler",
    "configure_cors",
    "configure_middleware",
    "configure_sessions",
    "create_limiter",
    "resolve_session_secret",
]
