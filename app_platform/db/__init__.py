"""Database exports for the app_platform package."""

from .client_base import DatabaseClientBase
from .exceptions import (
    AuthenticationError,
    ConnectionError,
    DataConsistencyError,
    DatabaseError,
    DatabasePermissionError,
    MigrationError,
    NotFoundError,
    PoolExhaustionError,
    SchemaError,
    SessionNotFoundError,
    TimeoutError,
    TransactionError,
    ValidationError,
    handle_database_error,
    is_recoverable_error,
    log_database_error,
)
from .migration import run_migration, run_migrations_dir
from .pool import PoolManager, get_pool
from .session import SessionManager, get_db_session

__all__ = [
    "AuthenticationError",
    "ConnectionError",
    "DataConsistencyError",
    "DatabaseClientBase",
    "DatabaseError",
    "DatabasePermissionError",
    "MigrationError",
    "NotFoundError",
    "PoolExhaustionError",
    "PoolManager",
    "SchemaError",
    "SessionManager",
    "SessionNotFoundError",
    "TimeoutError",
    "TransactionError",
    "ValidationError",
    "get_db_session",
    "get_pool",
    "handle_database_error",
    "is_recoverable_error",
    "log_database_error",
    "run_migration",
    "run_migrations_dir",
]
