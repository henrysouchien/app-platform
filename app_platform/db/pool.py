"""Connection pool manager for app_platform."""

import os
import threading

import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool


class PoolManager:
    """Lazily manages a psycopg2 connection pool."""

    _default_manager = None
    _default_lock = threading.Lock()

    def __init__(
        self,
        database_url=None,
        min_connections=None,
        max_connections=None,
    ):
        self._database_url = database_url
        self._min_connections = min_connections
        self._max_connections = max_connections
        self._pool = None
        self._pool_lock = threading.Lock()

    @property
    def database_url(self):
        if self._database_url:
            return self._database_url
        return os.getenv("DATABASE_URL", "")

    @property
    def min_connections(self):
        value = self._min_connections
        if value is None:
            value = os.getenv("DB_POOL_MIN", "5")
        return int(value)

    @property
    def max_connections(self):
        value = self._max_connections
        if value is None:
            value = os.getenv("DB_POOL_MAX", "20")
        return int(value)

    def get_pool(self):
        if self._pool is None:
            with self._pool_lock:
                if self._pool is None:
                    database_url = self.database_url
                    if not database_url:
                        raise ValueError("DATABASE_URL is not set")

                    min_connections = self.min_connections
                    max_connections = self.max_connections
                    if min_connections > max_connections:
                        raise ValueError(
                            "DB_POOL_MIN cannot be greater than DB_POOL_MAX"
                        )

                    self._pool = ThreadedConnectionPool(
                        min_connections,
                        max_connections,
                        database_url,
                        cursor_factory=psycopg2.extras.RealDictCursor,
                    )
        return self._pool

    def close(self):
        with self._pool_lock:
            if self._pool is not None:
                self._pool.closeall()
                self._pool = None

    @classmethod
    def _get_default_manager(cls):
        if cls._default_manager is None:
            with cls._default_lock:
                if cls._default_manager is None:
                    cls._default_manager = cls()
        return cls._default_manager

    @classmethod
    def _reset_for_tests(cls):
        with cls._default_lock:
            if cls._default_manager is not None:
                cls._default_manager.close()
            cls._default_manager = None


def get_pool():
    """Return the process-global default connection pool."""

    return PoolManager._get_default_manager().get_pool()


__all__ = ["PoolManager", "get_pool"]
