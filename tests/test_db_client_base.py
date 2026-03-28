import importlib
import logging
from pathlib import Path


class FakeCursor:
    def __init__(self, should_raise=False):
        self.should_raise = should_raise
        self.executed = []

    def execute(self, query, params=()):
        if self.should_raise:
            raise RuntimeError("cursor failure")
        self.executed.append((query, params))

    def fetchone(self):
        return 1


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor


def test_client_base_source_has_no_platform_logging_dependency():
    client_base_module = importlib.import_module("app_platform.db.client_base")
    source = Path(client_base_module.__file__).read_text()

    assert "app_platform.logging" not in source
    assert "utils.logging" not in source


def test_get_connection_yields_injected_connection():
    client_base_module = importlib.import_module("app_platform.db.client_base")
    conn = object()
    client = client_base_module.DatabaseClientBase(conn)

    with client.get_connection() as active_conn:
        assert active_conn is conn


def test_is_connection_healthy_true_and_false():
    client_base_module = importlib.import_module("app_platform.db.client_base")

    healthy_client = client_base_module.DatabaseClientBase(FakeConnection(FakeCursor()))
    unhealthy_client = client_base_module.DatabaseClientBase(
        FakeConnection(FakeCursor(should_raise=True))
    )

    assert healthy_client.is_connection_healthy(healthy_client.conn) is True
    assert unhealthy_client.is_connection_healthy(unhealthy_client.conn) is False


def test_execute_with_timing_logs_slow_queries(monkeypatch, caplog):
    client_base_module = importlib.import_module("app_platform.db.client_base")
    cursor = FakeCursor()
    client = client_base_module.DatabaseClientBase(FakeConnection(cursor))
    timeline = iter([10.0, 10.35])

    monkeypatch.setattr(client_base_module.time, "time", lambda: next(timeline))

    with caplog.at_level(logging.WARNING):
        result = client._execute_with_timing(
            cursor,
            "SELECT 1",
            params=("value",),
            context="unit-test",
            slow_ms=200,
        )

    assert result is cursor
    assert cursor.executed == [("SELECT 1", ("value",))]
    assert "SLOW QUERY" in caplog.text
