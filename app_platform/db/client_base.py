"""Stdlib-only database client base helpers."""

import logging
import time

logger = logging.getLogger(__name__)


class _ConnectionContext:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, exc_type, exc, tb):
        return False


class DatabaseClientBase:
    """Minimal DB client base with connection access and slow-query timing."""

    def __init__(self, conn):
        self.conn = conn

    def get_connection(self):
        return _ConnectionContext(self.conn)

    def is_connection_healthy(self, conn):
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            return True
        except Exception:
            return False

    def execute_with_timing(
        self,
        cursor,
        query,
        params=None,
        context=None,
        slow_ms=200,
    ):
        start = time.time()
        cursor.execute(query, params or ())
        duration = (time.time() - start) * 1000
        if duration > slow_ms:
            logger.warning(
                "SLOW QUERY: %s params=%s duration=%.1fms context=%s",
                query,
                params,
                duration,
                context,
            )
        return cursor

    _execute_with_timing = execute_with_timing


__all__ = ["DatabaseClientBase"]
