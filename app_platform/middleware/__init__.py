"""Middleware exports for app_platform."""

from __future__ import annotations

from dataclasses import dataclass, field

from slowapi import Limiter

from .cors import (
    DEFAULT_CORS_ALLOWED_ORIGINS,
    DEFAULT_HEADERS,
    DEFAULT_METHODS,
    configure_cors,
    parse_cors_origins,
    validate_cors_origins,
)
from .consent import ConsentEnforcementMiddleware
from .csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    DEFAULT_CSRF_EXEMPT_PATHS,
    DEFAULT_CSRF_MAX_AGE_SECONDS,
    CsrfProtectionMiddleware,
    create_csrf_token_response,
    sign_csrf_token,
    validate_csrf_token,
)
from .error_handlers import add_rate_limit_handler, add_validation_error_handler
from .legacy_query_credentials import LegacyQueryCredentialAccessLogMiddleware
from .rate_limiter import ApiKeyRegistry, RateLimitConfig, create_limiter
from .security_headers import (
    BASE_SECURITY_HEADERS,
    DEFAULT_CONTENT_SECURITY_POLICY,
    SecurityHeadersMiddleware,
    SOURCE_HTML_CONTENT_SECURITY_POLICY,
    SOURCE_HTML_PATH_PREFIX,
    SOURCE_HTML_SECURITY_HEADERS,
)
from .sessions import DEFAULT_SESSION_SECRET, configure_sessions, resolve_session_secret
from .sensitive_response import (
    DEFAULT_NO_STORE_PATHS,
    SensitiveResponseNoStoreMiddleware,
)
from .timing import RequestTimingMiddleware


@dataclass
class MiddlewareConfig:
    cors_origins: list[str] = field(default_factory=list)
    cors_credentials: bool = True
    session_secret: str = ""
    rate_limiter: Limiter | None = None
    validation_error_logging: bool = False
    validation_error_expose_details: bool = True
    validation_error_log_request_body: bool = True


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
        expose_details=config.validation_error_expose_details,
        log_request_body=config.validation_error_log_request_body,
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
    "BASE_SECURITY_HEADERS",
    "CSRF_COOKIE_NAME",
    "CSRF_HEADER_NAME",
    "DEFAULT_CORS_ALLOWED_ORIGINS",
    "DEFAULT_CSRF_EXEMPT_PATHS",
    "DEFAULT_CSRF_MAX_AGE_SECONDS",
    "DEFAULT_CONTENT_SECURITY_POLICY",
    "DEFAULT_HEADERS",
    "DEFAULT_METHODS",
    "DEFAULT_NO_STORE_PATHS",
    "DEFAULT_SESSION_SECRET",
    "CsrfProtectionMiddleware",
    "ConsentEnforcementMiddleware",
    "MiddlewareConfig",
    "LegacyQueryCredentialAccessLogMiddleware",
    "RateLimitConfig",
    "RequestTimingMiddleware",
    "SecurityHeadersMiddleware",
    "SensitiveResponseNoStoreMiddleware",
    "SOURCE_HTML_CONTENT_SECURITY_POLICY",
    "SOURCE_HTML_PATH_PREFIX",
    "SOURCE_HTML_SECURITY_HEADERS",
    "add_rate_limit_handler",
    "add_validation_error_handler",
    "configure_cors",
    "configure_middleware",
    "configure_sessions",
    "create_limiter",
    "create_csrf_token_response",
    "parse_cors_origins",
    "resolve_session_secret",
    "sign_csrf_token",
    "validate_cors_origins",
    "validate_csrf_token",
]
