"""Session manager for pooled database connections."""

import collections
import inspect
import logging
import os
import threading
import time
from contextlib import contextmanager

import psycopg2
from psycopg2.pool import PoolError

from . import pool as pool_module
from .exceptions import ConnectionError, PoolExhaustionError

_METRICS = collections.Counter()
_M_LOCK = threading.Lock()
get_pool = pool_module.get_pool
logger = logging.getLogger(__name__)


def _pool_acquire_timeout_seconds() -> float:
    raw_value = str(os.getenv("DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "2.0")).strip()
    try:
        return max(0.0, float(raw_value))
    except (TypeError, ValueError):
        return 2.0


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

    def _get_connection_with_wait(self, pool):
        timeout_seconds = _pool_acquire_timeout_seconds()
        deadline = time.monotonic() + timeout_seconds

        while True:
            try:
                return pool.getconn()
            except PoolError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    with _M_LOCK:
                        _METRICS["pool_exhausted"] += 1
                    raise
                with _M_LOCK:
                    _METRICS["pool_waits"] += 1
                time.sleep(min(0.05, remaining))

    def _reset_connection_state(self, conn):
        cursor_factory = getattr(conn, "cursor", None)
        if not callable(cursor_factory):
            return

        cursor = cursor_factory()
        try:
            cursor.execute("SET search_path TO public")
            commit = getattr(conn, "commit", None)
            if callable(commit) and not getattr(conn, "autocommit", False):
                commit()
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()

    def _is_broken_connection_error(self, exc):
        return isinstance(
            exc,
            (
                BrokenPipeError,
                ConnectionResetError,
            ),
        )

    def _connection_is_closed(self, conn):
        try:
            return bool(getattr(conn, "closed", 0))
        except Exception:
            return False

    def _rollback_after_body_error(self, conn, exc):
        rollback = getattr(conn, "rollback", None)
        if not callable(rollback):
            return None

        try:
            rollback()
        except psycopg2.Error as rollback_exc:
            logger.warning("Connection rollback failed after session error: %s", rollback_exc)
            return rollback_exc
        except OSError as rollback_exc:
            logger.warning("Connection rollback failed after session error: %s", rollback_exc)
            return rollback_exc
        except Exception:
            logger.exception("Unexpected rollback failure after session error")
            return exc
        return None

    def _pool_putconn_accepts_close(self, pool):
        try:
            parameters = inspect.signature(pool.putconn).parameters
        except (TypeError, ValueError):
            return True
        return "close" in parameters or any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )

    def _close_connection(self, conn):
        close = getattr(conn, "close", None)
        if callable(close):
            close()

    def _return_connection(self, pool, conn, *, close=False):
        if self._pool_putconn_accepts_close(pool):
            pool.putconn(conn, close=close)
            return

        if close:
            self._close_connection(conn)
        pool.putconn(conn)

    @contextmanager
    def get_db_session(self):
        try:
            pool = self._get_pool()
            conn = self._get_connection_with_wait(pool)
        except PoolError as exc:
            logger.error("Connection pool exhausted: %s", exc)
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
        try:
            self._reset_connection_state(conn)
        except psycopg2.Error as exc:
            rollback = getattr(conn, "rollback", None)
            if callable(rollback):
                rollback()
            try:
                pool.putconn(conn)
            except PoolError as put_exc:
                logger.warning("putconn() failed after state reset error: %s", put_exc)
            logger.error("Connection state reset failed: %s", exc)
            self._fire_pool_error(exc)
            raise ConnectionError(
                f"Cannot reset database connection state: {exc}",
                original_error=exc,
            ) from exc
        with _M_LOCK:
            _METRICS["active"] += 1
            _METRICS["total"] += 1
        discard_connection = False
        try:
            yield conn
        except Exception as exc:
            discard_connection = self._is_broken_connection_error(exc)
            rollback_error = self._rollback_after_body_error(conn, exc)
            if rollback_error is not None:
                discard_connection = True
            if self._connection_is_closed(conn):
                discard_connection = True
            if discard_connection:
                self._fire_pool_error(rollback_error or exc)
            raise
        finally:
            try:
                self._return_connection(pool, conn, close=discard_connection)
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
