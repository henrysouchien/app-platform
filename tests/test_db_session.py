import collections
import importlib
from unittest.mock import Mock

import psycopg2
import pytest
from psycopg2.pool import PoolError

from app_platform.db.exceptions import ConnectionError, PoolExhaustionError


class FakeConnection:
    def __init__(self, *, rollback_error=None, closed=0):
        self.rollbacks = 0
        self.rollback_error = rollback_error
        self.closed = closed
        self.close_calls = 0

    def rollback(self):
        self.rollbacks += 1
        if self.rollback_error is not None:
            raise self.rollback_error

    def close(self):
        self.close_calls += 1
        self.closed = 1


class SearchPathCursor:
    def __init__(self, conn):
        self.conn = conn
        self.closed = False

    def execute(self, query):
        self.conn.queries.append(query)

    def close(self):
        self.closed = True


class SearchPathConnection:
    autocommit = False

    def __init__(self):
        self.queries = []
        self.commits = 0

    def cursor(self):
        return SearchPathCursor(self)

    def commit(self):
        self.commits += 1


class FakePool:
    def __init__(self, conn=None, getconn_error=None, putconn_error=None):
        self.conn = conn
        self.getconn_error = getconn_error
        self.putconn_error = putconn_error
        self.getconn_calls = 0
        self.putconn_calls = []
        self.putconn_close_flags = []

    def getconn(self):
        self.getconn_calls += 1
        if self.getconn_error is not None:
            raise self.getconn_error
        return self.conn

    def putconn(self, conn, close=False):
        self.putconn_calls.append(conn)
        self.putconn_close_flags.append(close)
        if self.putconn_error is not None:
            raise self.putconn_error


class LegacyPutconnPool(FakePool):
    def putconn(self, conn):
        self.putconn_calls.append(conn)


@pytest.fixture(autouse=True)
def _reset_session_state():
    session_module = importlib.import_module("app_platform.db.session")
    session_module.SessionManager._reset_for_tests()
    session_module._METRICS = collections.Counter()
    yield
    session_module.SessionManager._reset_for_tests()
    session_module._METRICS = collections.Counter()


def test_session_manager_yields_connection_and_returns_it(monkeypatch):
    session_module = importlib.import_module("app_platform.db.session")
    conn = FakeConnection()
    fake_pool = FakePool(conn)
    monkeypatch.setattr(session_module, "get_pool", lambda: fake_pool)

    manager = session_module.SessionManager()
    with manager.get_db_session() as active_conn:
        assert active_conn is conn
        assert fake_pool.getconn_calls == 1
        assert session_module._METRICS["active"] == 1
        assert session_module._METRICS["total"] == 1

    assert fake_pool.putconn_calls == [conn]
    assert session_module._METRICS["active"] == 0
    assert session_module._METRICS["total"] == 1


def test_get_db_session_resets_search_path_on_checkout():
    session_module = importlib.import_module("app_platform.db.session")
    conn = SearchPathConnection()
    fake_pool = FakePool(conn)

    manager = session_module.SessionManager(pool_getter=lambda: fake_pool)
    with manager.get_db_session() as active_conn:
        assert active_conn is conn

    assert conn.queries == ["SET search_path TO public"]
    assert conn.commits == 1
    assert fake_pool.putconn_calls == [conn]


def test_module_get_db_session_delegates_to_default_manager(monkeypatch):
    session_module = importlib.import_module("app_platform.db.session")
    conn = FakeConnection()
    fake_pool = FakePool(conn)
    monkeypatch.setattr(session_module, "get_pool", lambda: fake_pool)

    with session_module.get_db_session() as active_conn:
        assert active_conn is conn

    assert fake_pool.getconn_calls == 1
    assert fake_pool.putconn_calls == [conn]


def test_get_db_session_catches_pool_error_and_raises_exhaustion(monkeypatch):
    session_module = importlib.import_module("app_platform.db.session")
    monkeypatch.setenv("DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "0")
    pool_error = PoolError("all slots busy")
    fake_pool = FakePool(getconn_error=pool_error)

    manager = session_module.SessionManager(pool_getter=lambda: fake_pool)

    with pytest.raises(PoolExhaustionError) as exc_info:
        with manager.get_db_session():
            pass

    assert exc_info.value.original_error is pool_error
    assert fake_pool.putconn_calls == []


def test_get_db_session_waits_for_transient_pool_exhaustion(monkeypatch):
    session_module = importlib.import_module("app_platform.db.session")
    monkeypatch.setenv("DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "0.2")
    monkeypatch.setattr(session_module.time, "sleep", lambda _seconds: None)

    conn = FakeConnection()
    pool_error = PoolError("all slots busy")
    attempts = {"count": 0}

    class FlakyPool:
        putconn_calls = []

        def getconn(self):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise pool_error
            return conn

        def putconn(self, active_conn):
            self.putconn_calls.append(active_conn)

    fake_pool = FlakyPool()
    manager = session_module.SessionManager(pool_getter=lambda: fake_pool)

    with manager.get_db_session() as active_conn:
        assert active_conn is conn

    assert attempts["count"] == 2
    assert fake_pool.putconn_calls == [conn]
    assert session_module._METRICS["pool_waits"] == 1


def test_get_db_session_catches_operational_error_and_raises_connection_error():
    session_module = importlib.import_module("app_platform.db.session")
    callback = Mock()
    operational_error = psycopg2.OperationalError("too many clients already")
    fake_pool = FakePool(getconn_error=operational_error)

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=callback,
    )

    with pytest.raises(ConnectionError) as exc_info:
        with manager.get_db_session():
            pass

    assert exc_info.value.original_error is operational_error
    callback.assert_called_once_with(operational_error)


def test_get_db_session_catches_pool_creation_operational_error():
    session_module = importlib.import_module("app_platform.db.session")
    callback = Mock()
    conn = FakeConnection()
    fake_pool = FakePool(conn)
    operational_error = psycopg2.OperationalError("too many clients already")
    attempts = {"count": 0}

    def pool_getter():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise operational_error
        return fake_pool

    manager = session_module.SessionManager(
        pool_getter=pool_getter,
        on_pool_error=callback,
    )

    with pytest.raises(ConnectionError):
        with manager.get_db_session():
            pass

    callback.assert_called_once_with(operational_error)

    with manager.get_db_session() as active_conn:
        assert active_conn is conn

    assert fake_pool.putconn_calls == [conn]


def test_get_db_session_pool_error_does_not_fire_callback(monkeypatch):
    session_module = importlib.import_module("app_platform.db.session")
    monkeypatch.setenv("DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "0")
    callback = Mock()
    pool_error = PoolError("all slots busy")
    fake_pool = FakePool(getconn_error=pool_error)

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=callback,
    )

    with pytest.raises(PoolExhaustionError):
        with manager.get_db_session():
            pass

    callback.assert_not_called()


def test_get_db_session_callback_failure_does_not_suppress_error(monkeypatch):
    session_module = importlib.import_module("app_platform.db.session")
    monkeypatch.setenv("DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "0")
    pool_error = PoolError("all slots busy")
    fake_pool = FakePool(getconn_error=pool_error)

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=Mock(side_effect=RuntimeError("callback failed")),
    )

    with pytest.raises(PoolExhaustionError) as exc_info:
        with manager.get_db_session():
            pass

    assert exc_info.value.original_error is pool_error


def test_putconn_pool_error_is_tolerated_and_metrics_are_decremented(caplog):
    session_module = importlib.import_module("app_platform.db.session")
    conn = FakeConnection()
    fake_pool = FakePool(conn=conn, putconn_error=PoolError("pool already closed"))

    manager = session_module.SessionManager(pool_getter=lambda: fake_pool)

    with manager.get_db_session() as active_conn:
        assert active_conn is conn
        assert session_module._METRICS["active"] == 1

    assert fake_pool.putconn_calls == [conn]
    assert session_module._METRICS["active"] == 0
    assert "putconn() failed" in caplog.text


def test_body_broken_pipe_discards_connection_and_marks_pool_error():
    session_module = importlib.import_module("app_platform.db.session")
    callback = Mock()
    conn = FakeConnection()
    fake_pool = FakePool(conn=conn)
    broken_pipe_error = BrokenPipeError("server closed the connection unexpectedly")

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=callback,
    )

    with pytest.raises(BrokenPipeError):
        with manager.get_db_session() as active_conn:
            assert active_conn is conn
            raise broken_pipe_error

    assert conn.rollbacks == 1
    assert fake_pool.putconn_calls == [conn]
    assert fake_pool.putconn_close_flags == [True]
    callback.assert_called_once_with(broken_pipe_error)
    assert session_module._METRICS["active"] == 0


def test_body_operational_error_rolls_back_without_discarding_connection():
    session_module = importlib.import_module("app_platform.db.session")
    callback = Mock()
    conn = FakeConnection()
    fake_pool = FakePool(conn=conn)
    operational_error = psycopg2.OperationalError("canceling statement due to statement timeout")

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=callback,
    )

    with pytest.raises(psycopg2.OperationalError):
        with manager.get_db_session() as active_conn:
            assert active_conn is conn
            raise operational_error

    assert conn.rollbacks == 1
    assert fake_pool.putconn_calls == [conn]
    assert fake_pool.putconn_close_flags == [False]
    callback.assert_not_called()
    assert session_module._METRICS["active"] == 0


def test_body_interface_error_rolls_back_without_discarding_connection():
    session_module = importlib.import_module("app_platform.db.session")
    callback = Mock()
    conn = FakeConnection()
    fake_pool = FakePool(conn=conn)
    interface_error = psycopg2.InterfaceError("cursor already closed")

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=callback,
    )

    with pytest.raises(psycopg2.InterfaceError):
        with manager.get_db_session() as active_conn:
            assert active_conn is conn
            raise interface_error

    assert conn.rollbacks == 1
    assert fake_pool.putconn_calls == [conn]
    assert fake_pool.putconn_close_flags == [False]
    callback.assert_not_called()
    assert session_module._METRICS["active"] == 0


def test_body_sql_error_rolls_back_without_discarding_connection():
    session_module = importlib.import_module("app_platform.db.session")
    callback = Mock()
    conn = FakeConnection()
    fake_pool = FakePool(conn=conn)
    integrity_error = psycopg2.IntegrityError("duplicate key")

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=callback,
    )

    with pytest.raises(psycopg2.IntegrityError):
        with manager.get_db_session() as active_conn:
            assert active_conn is conn
            raise integrity_error

    assert conn.rollbacks == 1
    assert fake_pool.putconn_calls == [conn]
    assert fake_pool.putconn_close_flags == [False]
    callback.assert_not_called()
    assert session_module._METRICS["active"] == 0


def test_rollback_failure_discards_connection_and_reports_rollback_error_once():
    session_module = importlib.import_module("app_platform.db.session")
    callback = Mock()
    rollback_error = psycopg2.InterfaceError("connection already closed")
    conn = FakeConnection(rollback_error=rollback_error)
    fake_pool = FakePool(conn=conn)
    integrity_error = psycopg2.IntegrityError("duplicate key")

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=callback,
    )

    with pytest.raises(psycopg2.IntegrityError):
        with manager.get_db_session() as active_conn:
            assert active_conn is conn
            raise integrity_error

    assert conn.rollbacks == 1
    assert fake_pool.putconn_calls == [conn]
    assert fake_pool.putconn_close_flags == [True]
    callback.assert_called_once_with(rollback_error)
    assert session_module._METRICS["active"] == 0


def test_discard_with_legacy_pool_closes_connection_before_return():
    session_module = importlib.import_module("app_platform.db.session")
    callback = Mock()
    conn = FakeConnection()
    fake_pool = LegacyPutconnPool(conn=conn)
    broken_pipe_error = BrokenPipeError("server closed the connection unexpectedly")

    manager = session_module.SessionManager(
        pool_getter=lambda: fake_pool,
        on_pool_error=callback,
    )

    with pytest.raises(BrokenPipeError):
        with manager.get_db_session() as active_conn:
            assert active_conn is conn
            raise broken_pipe_error

    assert conn.close_calls == 1
    assert fake_pool.putconn_calls == [conn]
    callback.assert_called_once_with(broken_pipe_error)
    assert session_module._METRICS["active"] == 0


def test_putconn_non_pool_error_propagates_and_metrics_are_decremented():
    session_module = importlib.import_module("app_platform.db.session")
    conn = FakeConnection()
    fake_pool = FakePool(conn=conn, putconn_error=RuntimeError("unexpected return failure"))

    manager = session_module.SessionManager(pool_getter=lambda: fake_pool)

    with pytest.raises(RuntimeError, match="unexpected return failure"):
        with manager.get_db_session() as active_conn:
            assert active_conn is conn
            assert session_module._METRICS["active"] == 1

    assert fake_pool.putconn_calls == [conn]
    assert session_module._METRICS["active"] == 0
