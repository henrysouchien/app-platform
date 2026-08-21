import asyncio
import importlib
import os
from unittest.mock import Mock

import pytest
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


def test_fastapi_lifespan_closes_pool_when_context_raises(monkeypatch):
    pool_module = importlib.import_module("app_platform.db.pool")
    close_pool = Mock()
    monkeypatch.setattr(pool_module, "close_pool", close_pool)
    monkeypatch.setenv("DATABASE_URL", "postgresql://lifespan/db")
    monkeypatch.setenv("FMP_API_KEY", "test-key")

    app_module = importlib.import_module("app")
    app = app_module.create_app()

    try:
        with TestClient(app):
            raise RuntimeError("boom")
    except RuntimeError:
        pass

    close_pool.assert_called_once_with()


def test_fastapi_lifespan_rejects_unsafe_commercial_flag_combination(monkeypatch):
    monkeypatch.setenv("STARTUP_PROBES", "false")
    monkeypatch.setenv("COMMERCIAL_CONTROL_ENABLED", "false")
    monkeypatch.setenv("COMMERCIAL_USAGE_INGEST_ENABLED", "true")

    app_module = importlib.import_module("app")
    app = app_module.create_app()

    with pytest.raises(ValueError, match="COMMERCIAL_CONTROL_ENABLED is required"):
        with TestClient(app):
            pass


def test_fastapi_lifespan_accepts_default_off_commercial_flags(monkeypatch):
    monkeypatch.setenv("STARTUP_PROBES", "false")
    for name in (
        "COMMERCIAL_CONTROL_ENABLED",
        "COMMERCIAL_ENTITLEMENT_PROJECTION_ENABLED",
        "COMMERCIAL_USAGE_INGEST_ENABLED",
        "COMMERCIAL_USAGE_SHADOW_MODE",
        "COMMERCIAL_BUDGET_SHADOW_MODE",
        "COMMERCIAL_BUDGET_ENFORCEMENT_ENABLED",
        "MCP_EXTERNAL_AUTH_ENABLED",
        "STRIPE_BILLING_ENABLED",
        "STRIPE_LIVE_MODE_ENABLED",
        "INVITE_TRIAL_ENABLED",
        "SELF_SERVE_CHECKOUT_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)

    app_module = importlib.import_module("app")
    app = app_module.create_app()

    with TestClient(app):
        pass


def test_mcp_lifespan_stops_order_watcher_before_closing_pool(monkeypatch):
    mcp_module = importlib.import_module("mcp_server_research")
    lifecycle_module = importlib.import_module("mcp_lifecycle")
    pool_module = importlib.import_module("app_platform.db.pool")
    events = []

    class FakeWatcher:
        def stop(self):
            events.append("stop")

    monkeypatch.setattr(lifecycle_module, "_order_watcher", FakeWatcher())
    monkeypatch.setattr(pool_module, "close_pool", lambda: events.append("close_pool"))

    async def _exercise_lifespan():
        async with mcp_module.pool_cleanup(mcp_module.mcp_research):
            events.append("running")

    asyncio.run(_exercise_lifespan())

    assert events == ["running", "stop", "close_pool"]


def test_mcp_process_db_pool_defaults_are_low_footprint(monkeypatch):
    lifecycle_module = importlib.import_module("mcp_lifecycle")
    monkeypatch.delenv("DB_POOL_MIN", raising=False)
    monkeypatch.delenv("DB_POOL_MAX", raising=False)
    monkeypatch.delenv("DB_APPLICATION_NAME", raising=False)
    monkeypatch.delenv("MCP_DB_POOL_MIN", raising=False)
    monkeypatch.delenv("MCP_DB_POOL_MAX", raising=False)

    lifecycle_module.configure_mcp_process_db_pool("portfolio-reads-mcp")

    assert os.environ["DB_POOL_MIN"] == "0"
    assert os.environ["DB_POOL_MAX"] == "3"
    assert os.environ["DB_APPLICATION_NAME"].startswith("risk_module:portfolio-reads-mcp:")


def test_mcp_process_db_pool_overrides_generic_pool_env(monkeypatch):
    lifecycle_module = importlib.import_module("mcp_lifecycle")
    monkeypatch.setenv("DB_POOL_MIN", "2")
    monkeypatch.setenv("DB_POOL_MAX", "10")
    monkeypatch.setenv("DB_APPLICATION_NAME", "custom-app")
    monkeypatch.delenv("MCP_DB_POOL_MIN", raising=False)
    monkeypatch.delenv("MCP_DB_POOL_MAX", raising=False)

    lifecycle_module.configure_mcp_process_db_pool("research mcp")

    assert os.environ["DB_POOL_MIN"] == "0"
    assert os.environ["DB_POOL_MAX"] == "3"
    assert os.environ["DB_APPLICATION_NAME"].startswith("risk_module:research-mcp:")


def test_mcp_process_db_pool_uses_mcp_overrides(monkeypatch):
    lifecycle_module = importlib.import_module("mcp_lifecycle")
    monkeypatch.delenv("DB_POOL_MIN", raising=False)
    monkeypatch.delenv("DB_POOL_MAX", raising=False)
    monkeypatch.delenv("DB_APPLICATION_NAME", raising=False)
    monkeypatch.setenv("MCP_DB_POOL_MIN", "1")
    monkeypatch.setenv("MCP_DB_POOL_MAX", "4")

    lifecycle_module.configure_mcp_process_db_pool("research mcp")

    assert os.environ["DB_POOL_MIN"] == "1"
    assert os.environ["DB_POOL_MAX"] == "4"
    assert os.environ["DB_APPLICATION_NAME"].startswith("risk_module:research-mcp:")
