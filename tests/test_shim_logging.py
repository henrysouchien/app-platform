import importlib
import logging
from pathlib import Path

import pytest


def _flush_legacy(module):
    manager = module.get_logging_manager()
    assert manager is not None
    for logger in (
        logging.getLogger(),
        manager.error_event_logger,
        manager.usage_event_logger,
        manager.frontend_event_logger,
    ):
        for handler in logger.handlers:
            handler.flush()


@pytest.fixture
def legacy_logging(monkeypatch, tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    core.LoggingManager._reset_for_tests()
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("ENVIRONMENT", "development")

    module = importlib.import_module("utils.logging")
    module = importlib.reload(module)

    yield module

    core.LoggingManager._reset_for_tests()


def test_legacy_logging_import_paths_and_aliases_work(legacy_logging):
    namespace = {}
    exec(
        "from utils.logging import get_logger, log_event, log_errors, portfolio_logger, log_sql_query",
        namespace,
    )

    assert callable(namespace["get_logger"])
    assert callable(namespace["log_event"])
    assert callable(namespace["log_errors"])
    assert namespace["portfolio_logger"].name == "risk_module.portfolio"

    namespace["log_sql_query"]("SELECT 1", source="shim_test")
    legacy_logging.log_event("audit", "legacy import works")
    _flush_legacy(legacy_logging)

    assert Path(legacy_logging.APP_LOG_PATH).exists()


def test_legacy_logging___all___still_resolves(legacy_logging):
    namespace = {}
    exec("from utils.logging import *", namespace)

    missing = [name for name in legacy_logging.__all__ if name not in namespace]
    assert not missing

    for name in legacy_logging.__all__:
        assert getattr(legacy_logging, name) is namespace[name]


def test_legacy_import_still_configures_logging_at_module_import(legacy_logging):
    assert legacy_logging.LOG_DIR.endswith("logs")
    assert legacy_logging.ENVIRONMENT == "development"
    assert legacy_logging.IS_PRODUCTION is False

    legacy_logging.api_logger.info("legacy module import configured logging")
    _flush_legacy(legacy_logging)

    assert Path(legacy_logging.APP_LOG_PATH).exists()
    assert Path(legacy_logging.DEBUG_LOG_PATH).exists()
