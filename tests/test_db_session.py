import collections
import importlib
from unittest.mock import Mock

import psycopg2
import pytest
from psycopg2.pool import PoolError

from app_platform.db.exceptions import ConnectionError, PoolExhaustionError


class FakeConnection:
    pass


class FakePool:
    def __init__(self, conn=None, getconn_error=None, putconn_error=None):
        self.conn = conn
        self.getconn_error = getconn_error
        self.putconn_error = putconn_error
        self.getconn_calls = 0
        self.putconn_calls = []

    def getconn(self):
        self.getconn_calls += 1
        if self.getconn_error is not None:
            raise self.getconn_error
        return self.conn

    def putconn(self, conn):
        self.putconn_calls.append(conn)
        if self.putconn_error is not None:
            raise self.putconn_error


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


def test_module_get_db_session_delegates_to_default_manager(monkeypatch):
    session_module = importlib.import_module("app_platform.db.session")
    conn = FakeConnection()
    fake_pool = FakePool(conn)
    monkeypatch.setattr(session_module, "get_pool", lambda: fake_pool)

    with session_module.get_db_session() as active_conn:
        assert active_conn is conn

    assert fake_pool.getconn_calls == 1
    assert fake_pool.putconn_calls == [conn]


def test_get_db_session_catches_pool_error_and_raises_exhaustion():
    session_module = importlib.import_module("app_platform.db.session")
    pool_error = PoolError("all slots busy")
    fake_pool = FakePool(getconn_error=pool_error)

    manager = session_module.SessionManager(pool_getter=lambda: fake_pool)

    with pytest.raises(PoolExhaustionError) as exc_info:
        with manager.get_db_session():
            pass

    assert exc_info.value.original_error is pool_error
    assert fake_pool.putconn_calls == []


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


def test_get_db_session_pool_error_fires_callback():
    session_module = importlib.import_module("app_platform.db.session")
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

    callback.assert_called_once_with(pool_error)


def test_get_db_session_callback_failure_does_not_suppress_error():
    session_module = importlib.import_module("app_platform.db.session")
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
