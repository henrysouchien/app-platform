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
from .private_vault import (
    PRIVATE_VAULT_POLICIES,
    PRIVATE_VAULT_TABLES,
    PrivateVaultMaintenanceError,
    assert_private_vault_maintenance_connection,
    assert_private_vault_runtime_connection,
    verify_private_vault_connections,
)
from .session import SessionManager, get_db_session
from .user_scope import (
    MAX_POSTGRES_INTEGER,
    USER_ID_SETTING,
    bind_user_scope,
    normalize_db_user_id,
    user_scoped_db_session,
)

__all__ = [
    "AuthenticationError",
    "ConnectionError",
    "DataConsistencyError",
    "DatabaseClientBase",
    "DatabaseError",
    "DatabasePermissionError",
    "MigrationError",
    "NotFoundError",
    "MAX_POSTGRES_INTEGER",
    "PoolExhaustionError",
    "PoolManager",
    "PRIVATE_VAULT_POLICIES",
    "PRIVATE_VAULT_TABLES",
    "PrivateVaultMaintenanceError",
    "SchemaError",
    "SessionManager",
    "SessionNotFoundError",
    "TimeoutError",
    "TransactionError",
    "USER_ID_SETTING",
    "ValidationError",
    "assert_private_vault_maintenance_connection",
    "assert_private_vault_runtime_connection",
    "bind_user_scope",
    "get_db_session",
    "get_pool",
    "handle_database_error",
    "is_recoverable_error",
    "log_database_error",
    "normalize_db_user_id",
    "run_migration",
    "run_migrations_dir",
    "user_scoped_db_session",
    "verify_private_vault_connections",
]
