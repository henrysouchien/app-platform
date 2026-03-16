"""HTTP handlers for database connection failures."""

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


async def db_connection_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "Database connection error on %s %s: %s",
        request.method,
        request.url.path,
        exc,
    )
    return JSONResponse(
        status_code=503,
        content={
            "error": "Service temporarily unavailable",
            "message": "Database connection unavailable. Please retry shortly.",
            "type": "database_error",
        },
    )
