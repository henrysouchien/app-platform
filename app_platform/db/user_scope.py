"""Transaction-local PostgreSQL identity for user-owned rows."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, ContextManager, Iterator, Protocol


USER_ID_SETTING = "app.user_id"
MAX_POSTGRES_INTEGER = 2_147_483_647


class SessionFactory(Protocol):
    def __call__(self) -> ContextManager[Any]: ...


def normalize_db_user_id(user_id: int | str) -> int:
    """Return a positive integer identity suitable for a database policy."""

    if isinstance(user_id, bool):
        raise ValueError("user_id must be a positive integer")
    normalized = str(user_id).strip()
    if not normalized.isascii() or not normalized.isdecimal():
        raise ValueError("user_id must be a positive integer")
    significant_digits = normalized.lstrip("0") or "0"
    if len(significant_digits) > 10:
        raise ValueError("user_id must be a positive PostgreSQL INTEGER")
    resolved = int(normalized)
    if resolved <= 0 or resolved > MAX_POSTGRES_INTEGER:
        raise ValueError("user_id must be a positive PostgreSQL INTEGER")
    return resolved


def bind_user_scope(conn: Any, *, user_id: int | str) -> int:
    """Bind one positive user id to the connection's current transaction."""

    resolved = normalize_db_user_id(user_id)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT set_config(%s, %s, true)",
            (USER_ID_SETTING, str(resolved)),
        )
    finally:
        close = getattr(cursor, "close", None)
        if callable(close):
            close()
    return resolved


@contextmanager
def user_scoped_db_session(
    *,
    user_id: int | str,
    session_factory: SessionFactory,
) -> Iterator[Any]:
    """Yield one transaction-local user session and clear it before pool return.

    Successful read-only operations are rolled back on exit to end their transaction.
    Durable writers must commit explicitly before leaving the context; the final rollback
    is then a harmless cleanup and ensures a later pooled borrower cannot inherit state.
    """

    resolved = normalize_db_user_id(user_id)
    with session_factory() as conn:
        if bool(getattr(conn, "autocommit", False)):
            raise RuntimeError("user-scoped database sessions require autocommit disabled")
        rollback = getattr(conn, "rollback", None)
        if not callable(rollback):
            raise RuntimeError("user-scoped database connection must support rollback")
        try:
            bind_user_scope(conn, user_id=resolved)
            yield conn
        finally:
            rollback()


__all__ = [
    "MAX_POSTGRES_INTEGER",
    "USER_ID_SETTING",
    "bind_user_scope",
    "normalize_db_user_id",
    "user_scoped_db_session",
]
