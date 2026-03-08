"""Generic FastAPI middleware exception handlers."""

from __future__ import annotations

import logging

from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded


def _build_validation_details(exc: RequestValidationError) -> list[dict[str, object]]:
    details = []
    for error in exc.errors():
        field_path = ".".join(str(loc) for loc in error.get("loc", ()))
        details.append(
            {
                "field": field_path,
                "error_type": error.get("type"),
                "message": error.get("msg"),
                "input_value": error.get("input", "N/A"),
            }
        )
    return details


def build_validation_error_handler(
    *,
    log_details: bool = False,
    logger: logging.Logger | None = None,
):
    logger = logger or logging.getLogger(__name__)

    async def validation_exception_handler(request, exc: RequestValidationError):
        validation_details = _build_validation_details(exc)
        raw_body_logged = False

        if log_details:
            try:
                raw_body = await request.body()
                raw_body_logged = True
                logger.error(
                    "Validation error on %s %s",
                    request.method,
                    request.url.path,
                )
                logger.error(
                    "Raw request body: %s",
                    raw_body.decode("utf-8", errors="replace"),
                )
                for error in validation_details:
                    logger.error(
                        "Field '%s': %s (type: %s)",
                        error["field"],
                        error["message"],
                        error["error_type"],
                    )
                logger.error("Request headers: %s", dict(request.headers))
            except Exception:  # pragma: no cover - logging must never break handler
                logger.exception("Failed while logging validation error details")

        return JSONResponse(
            status_code=422,
            content=jsonable_encoder(
                {
                    "detail": exc.errors(),
                    "message": "Request validation failed - check field names and structure",
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
):
    handler = build_validation_error_handler(log_details=log_details, logger=logger)
    app.add_exception_handler(RequestValidationError, handler)
    return handler


def build_rate_limit_handler(*, dev_mode: bool = False):
    async def rate_limit_handler(request, exc: RateLimitExceeded):
        if dev_mode:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Development mode - rate limiting disabled",
                    "message": "This error should not occur in development mode",
                    "type": "dev_mode_error",
                },
            )

        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "message": str(exc.detail),
                "type": "rate_limit_exceeded",
            },
        )

    return rate_limit_handler


def add_rate_limit_handler(app, *, dev_mode: bool = False):
    handler = build_rate_limit_handler(dev_mode=dev_mode)
    app.add_exception_handler(RateLimitExceeded, handler)
    return handler


__all__ = [
    "add_rate_limit_handler",
    "add_validation_error_handler",
    "build_rate_limit_handler",
    "build_validation_error_handler",
]
