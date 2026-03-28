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


def test_logging_manager_configures_paths_and_prefixed_loggers(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    manager = core.LoggingManager(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="production",
    )

    logger = manager.get_logger("service")
    logger.info("hello from the service logger")
    _flush_manager(manager)

    assert logger.name == "platform_app.service"
    assert manager.get_logger("platform_app.explicit").name == "platform_app.explicit"
    assert manager.context_var_name == "log_context"
    assert manager.is_production is True
    assert Path(manager.app_log_path).exists()
    assert not Path(manager.debug_log_path).exists()

    manager.close()


def test_core_json_emission_uses_context_and_text_sink(tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    core.set_log_context(correlation_id="corr-123")
    core.log_event("audit", "user login", user_id=42)
    core.log_error(
        "auth",
        "token invalid",
        exc=ValueError("bad token"),
        user_id=42,
        details={"step": "decode"},
    )
    _flush_manager(manager)

    rows = _read_jsonl(Path(manager.errors_log_path))
    assert rows[-1]["message"] == "token invalid"
    assert rows[-1]["correlation_id"] == "corr-123"
    assert rows[-1]["details"]["step"] == "decode"
    assert rows[-1]["exception_type"] == "ValueError"

    app_log_text = Path(manager.app_log_path).read_text()
    assert "[audit] user login" in app_log_text
    assert "[auth] token invalid" in app_log_text

    core.clear_log_context()


def test_log_alert_deduplicates_and_rolls_up_after_window(tmp_path, monkeypatch):
    core = importlib.import_module("app_platform.logging.core")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    class _Clock:
        def __init__(self):
            self.current = 1_700_000_000.0

        def time(self):
            return self.current

    clock = _Clock()
    monkeypatch.setattr(core.time, "time", clock.time)

    core.log_alert("service_unavailable", "high", "Service unavailable")
    core.log_alert("service_unavailable", "high", "Service unavailable")
    core.log_alert("service_unavailable", "high", "Service unavailable")

    clock.current += manager.dedup_window_s + 1
    core.log_alert("service_unavailable", "high", "Service unavailable")
    _flush_manager(manager)

    rows = _read_jsonl(Path(manager.errors_log_path))
    assert len(rows) == 2
    assert rows[0]["suppressed_count"] == 0
    assert rows[1]["suppressed_count"] == 2


def test_get_logger_lazy_auto_configures_with_warning(monkeypatch, tmp_path):
    core = importlib.import_module("app_platform.logging.core")
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "lazy-logs"))
    monkeypatch.setenv("ENVIRONMENT", "development")

    logger = core.get_logger("lazy")
    logger.info("lazy logger initialized")

    manager = core.get_logging_manager(auto_configure=False)
    assert manager is not None
    assert manager.app_name == "app"
    assert manager.log_dir == str(tmp_path / "lazy-logs")
    assert logger.name == "app.lazy"

    _flush_manager(manager)
    app_log_text = Path(manager.app_log_path).read_text()
    assert "auto-configured with defaults" in app_log_text
