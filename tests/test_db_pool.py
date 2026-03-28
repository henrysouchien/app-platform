import importlib
import threading
import time

import pytest


class FakeConnectionPool:
    created = []

    def __init__(self, minconn, maxconn, dsn, **kwargs):
        self.minconn = minconn
        self.maxconn = maxconn
        self.dsn = dsn
        self.kwargs = kwargs
        self.closed = False
        FakeConnectionPool.created.append(self)

    def closeall(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_pool_state():
    pool_module = importlib.import_module("app_platform.db.pool")
    pool_module.PoolManager._reset_for_tests()
    FakeConnectionPool.created.clear()
    yield
    pool_module.PoolManager._reset_for_tests()
    FakeConnectionPool.created.clear()


def test_pool_manager_uses_constructor_args(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", FakeConnectionPool)
    monkeypatch.setenv("DATABASE_URL", "postgresql://env/db")
    monkeypatch.setenv("DB_POOL_MIN", "3")
    monkeypatch.setenv("DB_POOL_MAX", "9")

    manager = pool_module.PoolManager(
        database_url="postgresql://explicit/db",
        min_connections=4,
        max_connections=7,
    )

    pool = manager.get_pool()

    assert pool is FakeConnectionPool.created[0]
    assert pool.minconn == 4
    assert pool.maxconn == 7
    assert pool.dsn == "postgresql://explicit/db"
    assert "cursor_factory" in pool.kwargs


def test_pool_manager_reads_environment_defaults(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", FakeConnectionPool)
    monkeypatch.setenv("DATABASE_URL", "postgresql://env/default")
    monkeypatch.setenv("DB_POOL_MIN", "5")
    monkeypatch.setenv("DB_POOL_MAX", "11")

    manager = pool_module.PoolManager()
    pool = manager.get_pool()

    assert pool.minconn == 5
    assert pool.maxconn == 11
    assert pool.dsn == "postgresql://env/default"


def test_get_pool_is_thread_safe_singleton(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    pool_module.PoolManager._reset_for_tests()
    monkeypatch.setenv("DATABASE_URL", "postgresql://threaded/db")
    monkeypatch.setenv("DB_POOL_MIN", "1")
    monkeypatch.setenv("DB_POOL_MAX", "2")

    class SlowFakePool(FakeConnectionPool):
        def __init__(self, *args, **kwargs):
            time.sleep(0.02)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", SlowFakePool)

    results = []
    errors = []

    def load_pool():
        try:
            results.append(pool_module.get_pool())
        except Exception as exc:  # pragma: no cover - safety net for threads
            errors.append(exc)

    threads = [threading.Thread(target=load_pool) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    assert len(SlowFakePool.created) == 1
    assert len(results) == 8
    assert all(pool is results[0] for pool in results)


def test_close_shuts_down_pool_and_allows_recreation(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", FakeConnectionPool)

    manager = pool_module.PoolManager(
        database_url="postgresql://close/db",
        min_connections=1,
        max_connections=2,
    )

    first_pool = manager.get_pool()
    manager.close()
    second_pool = manager.get_pool()

    assert first_pool.closed is True
    assert second_pool is not first_pool
    assert len(FakeConnectionPool.created) == 2


def test_reset_for_tests_replaces_default_pool(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", FakeConnectionPool)
    monkeypatch.setenv("DATABASE_URL", "postgresql://reset/db")

    first_pool = pool_module.get_pool()
    pool_module.PoolManager._reset_for_tests()
    second_pool = pool_module.get_pool()

    assert first_pool is not second_pool
    assert first_pool.closed is True
    assert len(FakeConnectionPool.created) == 2


def test_close_pool_no_default_manager_is_safe():
    pool_module = importlib.import_module("app_platform.db.pool")

    pool_module.close_pool()

    assert pool_module.PoolManager._default_manager is None


def test_close_pool_closes_and_nulls_default_manager(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", FakeConnectionPool)
    monkeypatch.setenv("DATABASE_URL", "postgresql://global-close/db")

    first_pool = pool_module.get_pool()
    first_manager = pool_module.PoolManager._default_manager

    pool_module.close_pool()

    assert first_pool.closed is True
    assert first_manager is not None
    assert pool_module.PoolManager._default_manager is None

    second_pool = pool_module.get_pool()

    assert second_pool is not first_pool
    assert pool_module.PoolManager._default_manager is not first_manager
    assert len(FakeConnectionPool.created) == 2


def test_pool_manager_defaults_to_safe_pool_sizes(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    monkeypatch.delenv("DB_POOL_MIN", raising=False)
    monkeypatch.delenv("DB_POOL_MAX", raising=False)

    manager = pool_module.PoolManager()

    assert manager.min_connections == 2
    assert manager.max_connections == 10


def test_pool_manager_uses_threaded_connection_pool(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", FakeConnectionPool)
    monkeypatch.setenv("DATABASE_URL", "postgresql://threaded-class/db")

    pool = pool_module.PoolManager().get_pool()

    assert pool is FakeConnectionPool.created[0]
