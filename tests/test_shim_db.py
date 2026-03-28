import importlib

import pytest


class FakeConnection:
    pass


class FakePool:
    def __init__(self, connections):
        self._connections = list(connections)
        self.getconn_calls = 0
        self.putconn_calls = []

    def getconn(self):
        self.getconn_calls += 1
        return self._connections.pop(0)

    def putconn(self, conn):
        self.putconn_calls.append(conn)


@pytest.fixture(autouse=True)
def _reset_shim_state():
    database_session_module = importlib.import_module("database.session")
    platform_session_module = importlib.import_module("app_platform.db.session")
    database_session_module._session_manager = None
    platform_session_module.SessionManager._reset_for_tests()
    yield
    database_session_module._session_manager = None
    platform_session_module.SessionManager._reset_for_tests()


def test_legacy_database_imports_resolve_to_platform_exports(monkeypatch):
    database_module = importlib.import_module("database")
    platform_session_module = importlib.import_module("app_platform.db.session")
    from app_platform.db import get_db_session as platform_get_db_session
    from app_platform.db import get_pool as platform_get_pool
    from database.pool import get_pool

    shim_conn = FakeConnection()
    platform_conn = FakeConnection()
    fake_pool = FakePool([shim_conn, platform_conn])
    monkeypatch.setattr(platform_session_module, "get_pool", lambda: fake_pool)

    with database_module.get_db_session() as active_conn:
        assert active_conn is shim_conn

    with platform_get_db_session() as active_conn:
        assert active_conn is platform_conn

    assert get_pool is platform_get_pool
    assert fake_pool.putconn_calls == [shim_conn, platform_conn]


def test_database_session_direct_module_import(monkeypatch):
    database_session_module = importlib.import_module("database.session")
    platform_session_module = importlib.import_module("app_platform.db.session")
    conn = FakeConnection()
    fake_pool = FakePool([conn])
    monkeypatch.setattr(platform_session_module, "get_pool", lambda: fake_pool)

    with database_session_module.get_db_session() as active_conn:
        assert active_conn is conn

    assert fake_pool.putconn_calls == [conn]


def test_legacy_exception_imports_preserve_aliases_and_hierarchy():
    from app_platform.db.exceptions import DatabasePermissionError
    from inputs.exceptions import DatabaseError, PermissionError, UserNotFoundError

    assert PermissionError is DatabasePermissionError
    assert issubclass(UserNotFoundError, DatabaseError)
