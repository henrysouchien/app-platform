"""Generic FastAPI middleware exception handlers."""

from __future__ import annotations

import logging
from collections.abc import Callable, Collection, Mapping
from typing import Any

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded


PUBLIC_VALIDATION_ERROR_RESPONSE = {
    "detail": "Request validation failed",
    "message": "Request validation failed",
    "error_code": "request_validation_failed",
}

REDACTED_INPUT_VALUE = "[REDACTED]"
SENSITIVE_PATHS = frozenset(
    {
        "/auth/google/sheets/connect",
        "/api/internal/google/sheets-broker-session",
        "/api/internal/google/sheets-access-token",
        "/api/billing/webhooks/stripe",
        "/api/billing/checkout-sessions",
    }
)


def _build_validation_details(
    exc: RequestValidationError,
    *,
    include_input_value: bool = True,
    redact_input_value: bool = False,
) -> list[dict[str, object]]:
    details = []
    for error in exc.errors():
        field_path = ".".join(str(loc) for loc in error.get("loc", ()))
        detail = {
            "field": field_path,
            "error_type": error.get("type"),
            "message": error.get("msg"),
        }
        if include_input_value:
            detail["input_value"] = (
                REDACTED_INPUT_VALUE
                if redact_input_value
                else error.get("input", "N/A")
            )
        details.append(detail)
    return details


def _redact_validation_inputs(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                REDACTED_INPUT_VALUE
                if key == "input"
                else _redact_validation_inputs(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_validation_inputs(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_validation_inputs(item) for item in value)
    return value


def build_validation_error_handler(
    *,
    log_details: bool = False,
    logger: logging.Logger | None = None,
    expose_details: bool = True,
    log_request_body: bool = True,
    sensitive_paths: Collection[str] = (),
):
    logger = logger or logging.getLogger(__name__)
    del sensitive_paths

    async def validation_exception_handler(request, exc: RequestValidationError):
        validation_details = _build_validation_details(
            exc,
            include_input_value=expose_details,
            redact_input_value=True,
        )
        raw_body_logged = False

        if log_details:
            try:
                logger.error(
                    "Validation error on %s %s",
                    request.method,
                    request.url.path,
                )
                for error in validation_details:
                    logger.error(
                        "Field '%s': %s (type: %s)",
                        error["field"],
                        error["message"],
                        error["error_type"],
                    )
                if log_request_body:
                    logger.error(
                        "Request header names: %s",
                        sorted(request.headers.keys()),
                    )
            except Exception:  # pragma: no cover - logging must never break handler
                logger.error(
                    "validation_error_observability_failed failure_count=1"
                )

        if not expose_details:
            return JSONResponse(
                status_code=422,
                content=PUBLIC_VALIDATION_ERROR_RESPONSE,
            )

        return JSONResponse(
            status_code=422,
            content=jsonable_encoder(
                {
                    "detail": _redact_validation_inputs(exc.errors()),
                    "message": (
                        "Request validation failed - check field names and "
                        "structure"
                    ),
                    "validation_details": validation_details,
                    "endpoint": str(request.url.path),
                    "method": request.method,
                    "raw_body_logged": raw_body_logged,
                }
            ),
        )

    return validation_exception_handler


def add_validation_error_handler(
    app,
    *,
    log_details: bool = False,
    logger: logging.Logger | None = None,
    expose_details: bool = True,
    log_request_body: bool = True,
    sensitive_paths: Collection[str] = (),
):
    handler = build_validation_error_handler(
        log_details=log_details,
        logger=logger,
        expose_details=expose_details,
        log_request_body=log_request_body,
        sensitive_paths=sensitive_paths,
    )
    app.add_exception_handler(RequestValidationError, handler)
    return handler


def build_rate_limit_handler(
    *,
    dev_mode: bool = False,
    get_dev_mode_fn: Callable[[], bool] | None = None,
    public_key: str = "public_key",
    tier_map: Mapping[str, str] | None = None,
    get_public_key_fn: Callable[[], str] | None = None,
    get_tier_map_fn: Callable[[], Mapping[str, str]] | None = None,
    get_current_user_fn: Callable[[Any], Mapping[str, Any] | None] | None = None,
    log_rate_limit_hit_fn: Callable[..., Any] | None = None,
):
    async def rate_limit_handler(request, exc: RateLimitExceeded):
        resolved_dev_mode = (
            get_dev_mode_fn() if get_dev_mode_fn is not None else dev_mode
        )
        if resolved_dev_mode:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Development mode - rate limiting disabled",
                    "message": "This error should not occur in development mode",
                    "type": "dev_mode_error",
                },
            )

        if log_rate_limit_hit_fn is not None:
            try:
                resolved_public_key = (
                    get_public_key_fn() if get_public_key_fn is not None else public_key
                )
                resolved_tier_map = (
                    get_tier_map_fn() if get_tier_map_fn is not None else tier_map
                )
                user_key = (
                    request.headers.get("X-API-Key")
                    or request.query_params.get("key", resolved_public_key)
                )
                user_tier = (resolved_tier_map or {}).get(user_key, "public")
                user_id = None
                if get_current_user_fn is not None:
                    try:
                        user = get_current_user_fn(request)
                        user_id = user.get("user_id") if user else None
                    except HTTPException:
                        user_id = None

                log_rate_limit_hit_fn(
                    user_id=user_id,
                    endpoint=str(request.url.path),
                    limit_type="daily",
                    retry_after=None,
                    user_tier=user_tier,
                )
            except Exception as log_error:
                print(f"Rate limit logging error: {log_error}")

        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "message": str(exc.detail),
                "type": "rate_limit_exceeded",
            },
        )

    return rate_limit_handler


def add_rate_limit_handler(
    app,
    *,
    dev_mode: bool = False,
    get_dev_mode_fn: Callable[[], bool] | None = None,
    public_key: str = "public_key",
    tier_map: Mapping[str, str] | None = None,
    get_public_key_fn: Callable[[], str] | None = None,
    get_tier_map_fn: Callable[[], Mapping[str, str]] | None = None,
    get_current_user_fn: Callable[[Any], Mapping[str, Any] | None] | None = None,
    log_rate_limit_hit_fn: Callable[..., Any] | None = None,
):
    handler = build_rate_limit_handler(
        dev_mode=dev_mode,
        get_dev_mode_fn=get_dev_mode_fn,
        public_key=public_key,
        tier_map=tier_map,
        get_public_key_fn=get_public_key_fn,
        get_tier_map_fn=get_tier_map_fn,
        get_current_user_fn=get_current_user_fn,
        log_rate_limit_hit_fn=log_rate_limit_hit_fn,
    )
    app.add_exception_handler(RateLimitExceeded, handler)
    return handler


__all__ = [
    "SENSITIVE_PATHS",
    "add_rate_limit_handler",
    "add_validation_error_handler",
    "build_rate_limit_handler",
    "build_validation_error_handler",
]
