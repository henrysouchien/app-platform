import asyncio
import importlib
import json
import logging
from pathlib import Path

import pytest


def _read_jsonl(path: Path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _flush_manager(manager):
    for logger in (
        logging.getLogger(),
        manager.error_event_logger,
        manager.usage_event_logger,
        manager.frontend_event_logger,
    ):
        for handler in logger.handlers:
            handler.flush()


@pytest.fixture(autouse=True)
def _reset_logging_state():
    core = importlib.import_module("app_platform.logging.core")
    core.LoggingManager._reset_for_tests()
    yield
    core.LoggingManager._reset_for_tests()


def test_log_errors_reraises_and_logs_structured_error(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    decorators = importlib.import_module("app_platform.logging.decorators")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    @decorators.log_errors("high")
    async def failing_async():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(failing_async())

    _flush_manager(manager)
    rows = _read_jsonl(Path(manager.errors_log_path))
    assert any(row["message"] == "failing_async failed: RuntimeError: boom" for row in rows)
    assert rows[-1]["severity"] == "high"


def test_log_timing_logs_slow_operations(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    decorators = importlib.import_module("app_platform.logging.decorators")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    @decorators.log_timing(0.0)
    def timed_function():
        return "ok"

    assert timed_function() == "ok"

    _flush_manager(manager)
    app_log_text = Path(manager.app_log_path).read_text()
    assert "[slow_operation]" in app_log_text
    assert "timed_function" in app_log_text


def test_log_operation_logs_start_and_finish(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    decorators = importlib.import_module("app_platform.logging.decorators")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    @decorators.log_operation("rebuild_cache")
    def rebuild_cache():
        return "done"

    assert rebuild_cache() == "done"

    _flush_manager(manager)
    app_log_text = Path(manager.app_log_path).read_text()
    assert "[operation_start] rebuild_cache started" in app_log_text
    assert "[operation_end] rebuild_cache finished" in app_log_text


def test_log_operation_logs_error_before_reraising(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    decorators = importlib.import_module("app_platform.logging.decorators")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    @decorators.log_operation("sync_positions")
    def sync_positions():
        raise ValueError("bad positions")

    with pytest.raises(ValueError, match="bad positions"):
        sync_positions()

    _flush_manager(manager)
    rows = _read_jsonl(Path(manager.errors_log_path))
    assert any(row["message"] == "sync_positions failed" for row in rows)
