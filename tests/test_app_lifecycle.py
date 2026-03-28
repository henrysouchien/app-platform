import asyncio
import importlib
from unittest.mock import Mock

from fastapi.testclient import TestClient


def test_fastapi_lifespan_closes_pool_on_shutdown(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    close_pool = Mock()
    monkeypatch.setattr(pool_module, "close_pool", close_pool)
    monkeypatch.setenv("DATABASE_URL", "postgresql://lifespan/db")
    monkeypatch.setenv("FMP_API_KEY", "test-key")

    app_module = importlib.import_module("app")
    app = app_module.create_app()

    with TestClient(app):
        close_pool.assert_not_called()

    close_pool.assert_called_once_with()


def test_mcp_lifespan_stops_order_watcher_before_closing_pool(monkeypatch):
    mcp_module = importlib.import_module("mcp_server")
    pool_module = importlib.import_module("app_platform.db.pool")
    events = []

    class FakeWatcher:
        def stop(self):
            events.append("stop")

    monkeypatch.setattr(mcp_module, "_order_watcher", FakeWatcher())
    monkeypatch.setattr(pool_module, "close_pool", lambda: events.append("close_pool"))

    async def _exercise_lifespan():
        async with mcp_module.pool_cleanup(mcp_module.mcp):
            events.append("running")

    asyncio.run(_exercise_lifespan())

    assert events == ["running", "stop", "close_pool"]
