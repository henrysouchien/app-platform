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
        manager.timing_event_logger,
    ):
        for handler in logger.handlers:
            handler.flush()


@pytest.fixture(autouse=True)
def _reset_logging_state():
    core = importlib.import_module("app_platform.logging.core")
    core.LoggingManager._reset_for_tests()
    yield
    core.LoggingManager._reset_for_tests()


def test_log_timing_event_writes_to_timing_jsonl(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    core.log_timing_event(
        kind="dependency",
        name="fmp:quote",
        duration_ms=12.345,
        status=200,
        ticker="AAPL",
    )
    _flush_manager(manager)

    rows = _read_jsonl(Path(manager.timing_log_path))
    assert rows == [
        {
            "ts": rows[0]["ts"],
            "kind": "dependency",
            "name": "fmp:quote",
            "duration_ms": 12.35,
            "status": 200,
            "details": {"ticker": "AAPL"},
        }
    ]


def test_log_timing_always_record_true_writes_below_threshold(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    decorators = importlib.import_module("app_platform.logging.decorators")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    @decorators.log_timing(999.0, always_record=True)
    async def always_recorded_function():
        return "ok"

    assert asyncio.run(always_recorded_function()) == "ok"

    _flush_manager(manager)
    rows = _read_jsonl(Path(manager.timing_log_path))
    assert len(rows) == 1
    assert rows[0]["kind"] == "step"
    assert rows[0]["name"].endswith(".always_recorded_function")
    assert rows[0]["duration_ms"] >= 0


def test_log_timing_default_does_not_write_below_threshold(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    decorators = importlib.import_module("app_platform.logging.decorators")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    @decorators.log_timing(999.0)
    def threshold_only_function():
        return "ok"

    assert threshold_only_function() == "ok"

    _flush_manager(manager)
    assert _read_jsonl(Path(manager.timing_log_path)) == []


def test_workflow_timer_writes_step_breakdown(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    workflow = importlib.import_module("app_platform.logging.workflow_timing")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    with workflow.workflow_timer("positions_holdings_workflow", endpoint="/api/positions/holdings") as timer:
        with timer.step("get_all_positions"):
            pass
        with timer.step("enrich_positions_with_risk"):
            pass

    _flush_manager(manager)
    rows = _read_jsonl(Path(manager.timing_log_path))
    assert len(rows) == 1
    assert rows[0]["kind"] == "step"
    assert rows[0]["name"] == "positions_holdings_workflow"
    assert rows[0]["details"]["endpoint"] == "/api/positions/holdings"
    assert set(rows[0]["details"]["steps"]) == {
        "get_all_positions",
        "enrich_positions_with_risk",
        "total",
    }
