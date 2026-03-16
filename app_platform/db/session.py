"""Session manager for pooled database connections."""

import collections
import logging
import threading
from contextlib import contextmanager

import psycopg2
from psycopg2.pool import PoolError

from . import pool as pool_module
from .exceptions import ConnectionError, PoolExhaustionError

_METRICS = collections.Counter()
_M_LOCK = threading.Lock()
get_pool = pool_module.get_pool
logger = logging.getLogger(__name__)


class SessionManager:
    """Handles checkout and return of pooled DB connections."""

    _default_manager = None
    _default_lock = threading.Lock()

    def __init__(self, pool_manager=None, pool_getter=None, on_pool_error=None):
        if pool_manager is not None and pool_getter is not None:
            raise ValueError("Provide either pool_manager or pool_getter, not both")
        self._pool_manager = pool_manager
        self._pool_getter = pool_getter
        self._on_pool_error = on_pool_error

    def _get_pool(self):
        if self._pool_getter is not None:
            return self._pool_getter()
        if self._pool_manager is not None:
            return self._pool_manager.get_pool()
        return get_pool()

    def _fire_pool_error(self, exc):
        if self._on_pool_error is None:
            return
        try:
            self._on_pool_error(exc)
        except Exception:
            pass

    @contextmanager
    def get_db_session(self):
        try:
            pool = self._get_pool()
            conn = pool.getconn()
        except PoolError as exc:
            logger.error("Connection pool exhausted: %s", exc)
            self._fire_pool_error(exc)
            raise PoolExhaustionError(
                "Connection pool exhausted - all connections in use",
                original_error=exc,
            ) from exc
        except psycopg2.OperationalError as exc:
            logger.error("Connection acquisition failed: %s", exc)
            self._fire_pool_error(exc)
            raise ConnectionError(
                f"Cannot acquire database connection: {exc}",
                original_error=exc,
            ) from exc
        with _M_LOCK:
            _METRICS["active"] += 1
            _METRICS["total"] += 1
        try:
            yield conn
        finally:
            try:
                pool.putconn(conn)
            except PoolError as exc:
                logger.warning("putconn() failed (likely shutdown race): %s", exc)
            finally:
                with _M_LOCK:
                    _METRICS["active"] -= 1

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
            cls._default_manager = None


def get_db_session():
    """Return a context manager for the process-global default DB session."""

    return SessionManager._get_default_manager().get_db_session()


__all__ = ["SessionManager", "get_db_session", "get_pool", "_METRICS"]
