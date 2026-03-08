"""Generic database exceptions and helpers for app_platform."""

import logging
from functools import wraps
from typing import Optional


class DatabaseError(Exception):
    """Base exception for all database-related errors."""

    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        operation: Optional[str] = None,
    ):
        self.message = message
        self.original_error = original_error
        self.operation = operation

        full_message = f"Database Error: {message}"
        if operation:
            full_message = f"Database Error in {operation}: {message}"
        if original_error:
            full_message += f" (Original: {original_error})"

        super().__init__(full_message)

    def __str__(self):
        return self.message


class ConnectionError(DatabaseError):
    """Raised when database connection fails."""

    def __init__(
        self,
        message: str = "Failed to connect to database",
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, original_error, "connection")


class PoolExhaustionError(DatabaseError):
    """Raised when the connection pool is exhausted."""

    def __init__(
        self,
        message: str = "Connection pool exhausted",
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, original_error, "connection_pool")


class TimeoutError(DatabaseError):
    """Raised when a database operation times out."""

    def __init__(
        self,
        message: str = "Database operation timed out",
        timeout_seconds: Optional[float] = None,
        original_error: Optional[Exception] = None,
    ):
        if timeout_seconds is not None:
            message = f"Database operation timed out after {timeout_seconds}s"
        super().__init__(message, original_error, "timeout")


class TransactionError(DatabaseError):
    """Raised when a database transaction fails."""

    def __init__(
        self,
        message: str = "Database transaction failed",
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, original_error, "transaction")


class ValidationError(DatabaseError):
    """Raised when data validation fails."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        original_error: Optional[Exception] = None,
    ):
        self.field = field
        if field:
            message = f"Validation failed for field '{field}': {message}"
        super().__init__(message, original_error, "validation")


class MigrationError(DatabaseError):
    """Raised when a database migration fails."""

    def __init__(
        self,
        message: str,
        migration_step: Optional[str] = None,
        original_error: Optional[Exception] = None,
    ):
        self.migration_step = migration_step
        if migration_step:
            message = f"Migration failed at step '{migration_step}': {message}"
        super().__init__(message, original_error, "migration")


class SchemaError(DatabaseError):
    """Raised when the database schema is invalid or missing."""

    def __init__(
        self,
        message: str,
        table: Optional[str] = None,
        original_error: Optional[Exception] = None,
    ):
        self.table = table
        if table:
            message = f"Schema error in table '{table}': {message}"
        super().__init__(message, original_error, "schema")


class DataConsistencyError(DatabaseError):
    """Raised when data consistency checks fail."""

    def __init__(
        self,
        message: str,
        table: Optional[str] = None,
        original_error: Optional[Exception] = None,
    ):
        self.table = table
        if table:
            message = f"Data consistency error in table '{table}': {message}"
        super().__init__(message, original_error, "data_consistency")


class DatabasePermissionError(DatabaseError):
    """Raised when database permissions are insufficient."""

    def __init__(
        self,
        message: str = "Database permission denied",
        operation: Optional[str] = None,
        original_error: Optional[Exception] = None,
    ):
        if operation:
            message = f"Permission denied for operation '{operation}': {message}"
        super().__init__(message, original_error, "permission")


class AuthenticationError(DatabaseError):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, original_error, "authentication")


class SessionNotFoundError(DatabaseError):
    """Raised when a session is not found."""

    def __init__(
        self,
        session_id: str,
        original_error: Optional[Exception] = None,
    ):
        self.session_id = session_id
        super().__init__(f"Session not found: {session_id}", original_error, "session_lookup")


class NotFoundError(DatabaseError):
    """Generic base for resource-specific database not-found errors."""

    def __init__(
        self,
        message: str,
        original_error: Optional[Exception] = None,
        operation: Optional[str] = "not_found",
    ):
        super().__init__(message, original_error, operation or "not_found")


def handle_database_error(func):
    """Decorator that wraps unexpected exceptions in DatabaseError."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except DatabaseError:
            raise
        except Exception as exc:
            logger = logging.getLogger(__name__)
            logger.error("Unexpected error in %s: %s", func.__name__, exc)
            raise DatabaseError(
                f"Unexpected error in {func.__name__}",
                original_error=exc,
                operation=func.__name__,
            ) from exc

    return wrapper


def is_recoverable_error(error: Exception) -> bool:
    """Return True if the error should be considered retry/fallback safe."""

    recoverable_errors = (
        ConnectionError,
        PoolExhaustionError,
        TimeoutError,
        TransactionError,
    )
    return isinstance(error, recoverable_errors)


def log_database_error(error: DatabaseError, logger: logging.Logger):
    """Log a database error at warning/error level with structured context."""

    error_context = {
        "error_type": type(error).__name__,
        "message": error.message,
        "operation": error.operation,
        "original_error": (
            str(error.original_error) if error.original_error is not None else None
        ),
    }

    if is_recoverable_error(error):
        logger.warning("Recoverable database error: %s", error_context)
    else:
        logger.error("Database error: %s", error_context)


__all__ = [
    "AuthenticationError",
    "ConnectionError",
    "DataConsistencyError",
    "DatabaseError",
    "DatabasePermissionError",
    "MigrationError",
    "NotFoundError",
    "PoolExhaustionError",
    "SchemaError",
    "SessionNotFoundError",
    "TimeoutError",
    "TransactionError",
    "ValidationError",
    "handle_database_error",
    "is_recoverable_error",
    "log_database_error",
]
