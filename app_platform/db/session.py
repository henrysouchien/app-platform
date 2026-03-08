"""Session manager for pooled database connections."""

import collections
import threading
from contextlib import contextmanager

from . import pool as pool_module

_METRICS = collections.Counter()
_M_LOCK = threading.Lock()
get_pool = pool_module.get_pool


class SessionManager:
    """Handles checkout and return of pooled DB connections."""

    _default_manager = None
    _default_lock = threading.Lock()

    def __init__(self, pool_manager=None, pool_getter=None):
        if pool_manager is not None and pool_getter is not None:
            raise ValueError("Provide either pool_manager or pool_getter, not both")
        self._pool_manager = pool_manager
        self._pool_getter = pool_getter

    def _get_pool(self):
        if self._pool_getter is not None:
            return self._pool_getter()
        if self._pool_manager is not None:
            return self._pool_manager.get_pool()
        return get_pool()

    @contextmanager
    def get_db_session(self):
        pool = self._get_pool()
        conn = pool.getconn()
        with _M_LOCK:
            _METRICS["active"] += 1
            _METRICS["total"] += 1
        try:
            yield conn
        finally:
            pool.putconn(conn)
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
