"""Tuple-cursor adapter for commercial services behind the application's RealDict pool."""

from __future__ import annotations

from typing import Any

from psycopg2.extensions import cursor as TupleCursor


class PostgresTupleCursorConnection:
    """Delegate connection behavior while forcing positional cursor rows."""

    def __init__(self, connection: object) -> None:
        self._connection = connection

    def cursor(self, *args: Any, **kwargs: Any) -> object:
        kwargs["cursor_factory"] = TupleCursor
        return self._connection.cursor(  # type: ignore[attr-defined,no-any-return]
            *args, **kwargs
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


__all__ = ["PostgresTupleCursorConnection"]
