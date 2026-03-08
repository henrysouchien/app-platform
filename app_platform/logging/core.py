"""Structured logging manager and convenience helpers."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import traceback
from contextvars import ContextVar
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

APP_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
JSON_LOG_FORMAT = "%(message)s"

SLOW_OPERATION_THRESHOLD = 1.0
VERY_SLOW_OPERATION_THRESHOLD = 5.0

DEDUP_WINDOW_S = 300
MAX_DEDUP_KEYS = 500


def _json_default(value: Any) -> Any:
    """JSON serializer fallback for non-serializable objects."""
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _safe_dict(value: Any) -> dict[str, Any]:
    """Return a safe dictionary representation for structured log fields."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    return {"value": value}


def _compact_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        default=_json_default,
        separators=(",", ":"),
    )


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _has_file_handler(logger: logging.Logger, file_path: str) -> bool:
    """Check whether a logger already has a FileHandler for the given path."""
    abs_target = os.path.abspath(file_path)
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            existing = getattr(handler, "baseFilename", None)
            if existing and os.path.abspath(existing) == abs_target:
                return True
    return False


def _build_json_logger(
    logger_name: str,
    file_path: str,
    *,
    rotating: bool,
    json_log_format: str = JSON_LOG_FORMAT,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
) -> tuple[logging.Logger, logging.Handler | None]:
    """Create a dedicated JSON-lines logger with idempotent handler wiring."""
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if _has_file_handler(logger, file_path):
        return logger, None

    if rotating:
        handler: logging.FileHandler = RotatingFileHandler(
            file_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
    else:
        handler = logging.FileHandler(file_path, encoding="utf-8")

    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(json_log_format))
    logger.addHandler(handler)
    return logger, handler


def _emit_json(logger: logging.Logger, payload: dict[str, Any]) -> None:
    logger.info(_compact_json(payload))


def _format_details_for_text(details: dict[str, Any]) -> str:
    if not details:
        return ""
    return f" | {_compact_json(details)}"


def _check_dedup(manager: "LoggingManager", key: str) -> tuple[bool, int]:
    """Return (should_log, suppressed_count) for alert deduplication."""
    now = time.time()
    with manager._dedup_lock:
        if key in manager._recent_alerts:
            last_ts, count = manager._recent_alerts[key]
            if (now - last_ts) < manager.dedup_window_s:
                manager._recent_alerts[key] = (last_ts, count + 1)
                return False, 0

            manager._recent_alerts[key] = (now, 0)
            return True, count

        manager._recent_alerts[key] = (now, 0)
        if len(manager._recent_alerts) > manager.max_dedup_keys:
            oldest_key = min(
                manager._recent_alerts,
                key=lambda item: manager._recent_alerts[item][0],
            )
            del manager._recent_alerts[oldest_key]
        return True, 0


def _normalize_exc(
    exc: Any,
    details: dict[str, Any],
) -> tuple[str | None, str | None, str | None]:
    """Normalize exception payload for structured error events."""
    if isinstance(exc, BaseException):
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return str(exc), type(exc).__name__, tb

    if exc is not None:
        details.setdefault("context", exc)
        return str(exc), None, None

    return None, None, None


def _normalize_details(details: dict[str, Any]) -> dict[str, Any]:
    """Flatten nested details payload and return JSON-safe dict."""
    normalized = dict(details)
    nested = normalized.pop("details", None)
    if isinstance(nested, dict):
        merged = dict(nested)
        merged.update(normalized)
        return merged
    if nested is not None:
        normalized["details"] = nested
    return normalized


def _extract_correlation_id(
    manager: "LoggingManager",
    data: dict[str, Any] | None = None,
    fallback: str | None = None,
) -> str | None:
    """Get correlation id from common key names used across integrations."""
    payload = data or {}
    context_payload = manager.get_log_context()
    return (
        payload.get("correlation_id")
        or payload.get("request_id")
        or payload.get("plaid_req_id")
        or context_payload.get("correlation_id")
        or context_payload.get("request_id")
        or context_payload.get("plaid_req_id")
        or fallback
    )


class LoggingManager:
    """Configures process logging and exposes structured event helpers."""

    _default_manager: "LoggingManager | None" = None
    _default_lock = threading.Lock()

    def __init__(
        self,
        app_name: str = "app",
        log_dir: str | None = None,
        environment: str | None = None,
        enable_debug_log: bool | None = None,
        slow_operation_threshold_s: float = SLOW_OPERATION_THRESHOLD,
        very_slow_operation_threshold_s: float = VERY_SLOW_OPERATION_THRESHOLD,
        dedup_window_s: int = DEDUP_WINDOW_S,
        max_dedup_keys: int = MAX_DEDUP_KEYS,
        context_var_name: str = "log_context",
        app_log_format: str = APP_LOG_FORMAT,
        json_log_format: str = JSON_LOG_FORMAT,
    ) -> None:
        self.app_name = (app_name or "app").strip() or "app"
        self.environment = (environment or os.getenv("ENVIRONMENT", "development")).lower()
        self.is_production = self.environment == "production"
        if log_dir:
            resolved_log_dir = log_dir
        else:
            resolved_log_dir = os.getenv("LOG_DIR") or os.path.join(os.getcwd(), "logs")
        self.log_dir = str(Path(resolved_log_dir))
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)

        self.enable_debug_log = (
            not self.is_production if enable_debug_log is None else bool(enable_debug_log)
        )
        self.slow_operation_threshold_s = slow_operation_threshold_s
        self.very_slow_operation_threshold_s = very_slow_operation_threshold_s
        self.dedup_window_s = dedup_window_s
        self.max_dedup_keys = max_dedup_keys
        self.context_var_name = context_var_name or "log_context"
        self.app_log_format = app_log_format
        self.json_log_format = json_log_format

        self.app_log_path = os.path.join(self.log_dir, "app.log")
        self.debug_log_path = os.path.join(self.log_dir, "debug.log")
        self.errors_log_path = os.path.join(self.log_dir, "errors.jsonl")
        self.usage_log_path = os.path.join(self.log_dir, "usage.jsonl")
        self.frontend_log_path = os.path.join(self.log_dir, "frontend.jsonl")

        self.errors_logger_name = f"{self.app_name}.errors_json"
        self.usage_logger_name = f"{self.app_name}.usage_json"
        self.frontend_logger_name = f"{self.app_name}.frontend_json"

        self._managed_handlers: list[tuple[logging.Logger, logging.Handler]] = []
        self._dedup_lock = threading.Lock()
        self._recent_alerts: dict[str, tuple[float, int]] = {}
        self._log_context: ContextVar[dict[str, Any]] = ContextVar(
            self.context_var_name,
            default={},
        )

        self._configure_root_logger()
        self.error_event_logger = self._create_json_logger(
            self.errors_logger_name,
            self.errors_log_path,
            rotating=True,
            max_bytes=5 * 1024 * 1024,
            backup_count=5,
        )
        self.usage_event_logger = self._create_json_logger(
            self.usage_logger_name,
            self.usage_log_path,
            rotating=False,
        )
        self.frontend_event_logger = self._create_json_logger(
            self.frontend_logger_name,
            self.frontend_log_path,
            rotating=True,
            max_bytes=5 * 1024 * 1024,
            backup_count=5,
        )

    def _configure_root_logger(self) -> None:
        """Attach app/debug handlers to the true root logger once."""
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        if not _has_file_handler(root_logger, self.app_log_path):
            app_handler = RotatingFileHandler(
                self.app_log_path,
                maxBytes=10 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            app_handler.setLevel(logging.INFO)
            app_handler.setFormatter(logging.Formatter(self.app_log_format))
            root_logger.addHandler(app_handler)
            self._managed_handlers.append((root_logger, app_handler))

        if self.enable_debug_log and not _has_file_handler(root_logger, self.debug_log_path):
            debug_handler = RotatingFileHandler(
                self.debug_log_path,
                maxBytes=10 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            debug_handler.setLevel(logging.DEBUG)
            debug_handler.setFormatter(logging.Formatter(self.app_log_format))
            root_logger.addHandler(debug_handler)
            self._managed_handlers.append((root_logger, debug_handler))

    def _create_json_logger(
        self,
        logger_name: str,
        file_path: str,
        *,
        rotating: bool,
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 5,
    ) -> logging.Logger:
        logger, handler = _build_json_logger(
            logger_name,
            file_path,
            rotating=rotating,
            json_log_format=self.json_log_format,
            max_bytes=max_bytes,
            backup_count=backup_count,
        )
        if handler is not None:
            self._managed_handlers.append((logger, handler))
        return logger

    def close(self) -> None:
        """Remove and close handlers managed by this instance."""
        for logger, handler in reversed(self._managed_handlers):
            try:
                logger.removeHandler(handler)
            except Exception:
                pass
            try:
                handler.close()
            except Exception:
                pass
        self._managed_handlers.clear()

    def get_logger(self, name: str) -> logging.Logger:
        """Return a logger under the manager's app namespace."""
        if name == self.app_name or name.startswith(f"{self.app_name}."):
            return logging.getLogger(name)
        if name:
            return logging.getLogger(f"{self.app_name}.{name}")
        return logging.getLogger(self.app_name)

    def set_log_context(self, **fields: Any) -> None:
        """Attach transient structured context for the current async/thread context."""
        ctx = self.get_log_context()
        ctx.update(fields)
        self._log_context.set(ctx)

    def clear_log_context(self) -> None:
        """Clear transient structured context for the current async/thread context."""
        self._log_context.set({})

    def get_log_context(self) -> dict[str, Any]:
        return dict(self._log_context.get())

    def log_event(self, event_type: str, message: str, **details: Any) -> dict[str, Any]:
        """Log structured operational event into app.log."""
        payload = _normalize_details(details)
        logger = self.get_logger("events")
        logger.info(
            "[%s] %s%s",
            event_type,
            message,
            _format_details_for_text(payload),
        )
        return {
            "ts": _now_iso(),
            "event_type": event_type,
            "message": message,
            "details": payload,
        }

    def log_slow_operation(
        self,
        operation: str,
        duration_s: float,
        **details: Any,
    ) -> dict[str, Any]:
        """Log slow operation warnings into app.log."""
        payload = _normalize_details(details)
        payload["duration_s"] = duration_s
        logger = self.get_logger("performance")
        logger.warning(
            "[slow_operation] %s took %.3fs%s",
            operation,
            duration_s,
            _format_details_for_text(payload),
        )
        return {
            "ts": _now_iso(),
            "operation": operation,
            "duration_s": duration_s,
            "details": payload,
        }

    def log_error(
        self,
        source: str,
        message: str,
        exc: Any = None,
        **details: Any,
    ) -> dict[str, Any]:
        """Write structured errors to errors.jsonl and concise error text to app.log."""
        payload_details = _normalize_details(details)

        correlation_id = _extract_correlation_id(self, payload_details)
        user_id = payload_details.pop("user_id", None)
        tier = payload_details.pop("tier", None)
        endpoint = payload_details.pop("endpoint", None)
        recovery = payload_details.pop("recovery", None)
        severity = payload_details.pop("severity", "high")

        error_type = payload_details.pop("type", None)
        if not error_type:
            normalized_source = (
                str(source)
                .replace("/", "_")
                .replace(":", "_")
                .replace(" ", "_")
                .lower()
            )
            error_type = f"{normalized_source}_error"

        error_text, exception_type, tb = _normalize_exc(exc, payload_details)

        record = {
            "ts": _now_iso(),
            "level": "ERROR",
            "type": error_type,
            "severity": severity,
            "message": message,
            "source": source,
            "error": error_text,
            "exception_type": exception_type,
            "traceback": tb,
            "correlation_id": correlation_id,
            "user_id": user_id,
            "tier": tier,
            "endpoint": endpoint,
            "recovery": recovery,
            "details": _safe_dict(payload_details),
            "dedup_key": None,
            "suppressed_count": 0,
        }

        _emit_json(self.error_event_logger, record)
        self.get_logger("errors").error(
            "[%s] %s%s",
            source,
            message,
            _format_details_for_text(_safe_dict(payload_details)),
        )
        return record

    def log_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        **details: Any,
    ) -> dict[str, Any] | None:
        """Write deduplicated alerts to errors.jsonl."""
        payload_details = _normalize_details(details)
        dedup_key = payload_details.pop("dedup_key", f"{alert_type}:{severity}:{message}")

        should_log, suppressed_count = _check_dedup(self, dedup_key)
        if not should_log:
            return None

        correlation_id = _extract_correlation_id(self, payload_details)
        user_id = payload_details.pop("user_id", None)
        tier = payload_details.pop("tier", None)
        endpoint = payload_details.pop("endpoint", None)
        recovery = payload_details.pop("recovery", None)
        source = payload_details.pop("source", "alert")

        error_text, exception_type, tb = _normalize_exc(
            payload_details.pop("exc", None),
            payload_details,
        )

        record = {
            "ts": _now_iso(),
            "level": "ALERT",
            "type": alert_type,
            "severity": severity,
            "message": message,
            "source": source,
            "error": error_text,
            "exception_type": exception_type,
            "traceback": tb,
            "correlation_id": correlation_id,
            "user_id": user_id,
            "tier": tier,
            "endpoint": endpoint,
            "recovery": recovery,
            "details": _safe_dict(payload_details),
            "dedup_key": dedup_key,
            "suppressed_count": suppressed_count,
        }

        _emit_json(self.error_event_logger, record)

        logger = self.get_logger("alerts")
        if severity.lower() in {"high", "critical"}:
            logger.error(
                "[%s] %s%s",
                alert_type,
                message,
                _format_details_for_text(_safe_dict(payload_details)),
            )
        else:
            logger.warning(
                "[%s] %s%s",
                alert_type,
                message,
                _format_details_for_text(_safe_dict(payload_details)),
            )

        return record

    def log_service_status(
        self,
        service: str,
        status: str,
        **details: Any,
    ) -> dict[str, Any] | None:
        """Log service status transitions; suppress healthy noise by default."""
        normalized_status = str(status).strip().lower()
        if normalized_status in {"healthy", "ok", "up", "success"}:
            return None

        severity = "medium"
        if normalized_status in {"down", "error", "failed", "unavailable"}:
            severity = "high"

        payload = _normalize_details(details)
        payload.setdefault("service", service)
        payload.setdefault("status", status)

        return self.log_alert(
            alert_type=f"{service.lower()}_status",
            severity=severity,
            message=f"{service} status: {status}",
            **payload,
        )

    @classmethod
    def _configure_default(cls, **kwargs: Any) -> "LoggingManager":
        with cls._default_lock:
            if cls._default_manager is not None:
                cls._default_manager.close()
                cls._default_manager = None
            cls._default_manager = cls(**kwargs)
            return cls._default_manager

    @classmethod
    def _get_default_manager(
        cls,
        *,
        auto_configure: bool = True,
    ) -> "LoggingManager | None":
        if cls._default_manager is None and auto_configure:
            with cls._default_lock:
                if cls._default_manager is None:
                    cls._default_manager = cls()
                    cls._default_manager.get_logger("logging").warning(
                        "LoggingManager auto-configured with defaults because "
                        "configure_logging() was not called first"
                    )
        return cls._default_manager

    @classmethod
    def _reset_for_tests(cls) -> None:
        with cls._default_lock:
            if cls._default_manager is not None:
                cls._default_manager.close()
            cls._default_manager = None


def configure_logging(**kwargs: Any) -> LoggingManager:
    """Create and install the process-global default logging manager."""
    return LoggingManager._configure_default(**kwargs)


def get_logging_manager(*, auto_configure: bool = True) -> LoggingManager | None:
    """Return the default logging manager, auto-configuring if needed."""
    return LoggingManager._get_default_manager(auto_configure=auto_configure)


def get_logger(name: str) -> logging.Logger:
    """Return a logger from the process-global default manager."""
    manager = LoggingManager._get_default_manager()
    assert manager is not None
    return manager.get_logger(name)


def set_log_context(**fields: Any) -> None:
    """Attach transient structured context to the default manager."""
    manager = LoggingManager._get_default_manager()
    assert manager is not None
    manager.set_log_context(**fields)


def clear_log_context() -> None:
    """Clear transient structured context from the default manager."""
    manager = LoggingManager._get_default_manager()
    assert manager is not None
    manager.clear_log_context()


def log_event(event_type: str, message: str, **details: Any) -> dict[str, Any]:
    """Log a structured operational event via the default manager."""
    manager = LoggingManager._get_default_manager()
    assert manager is not None
    return manager.log_event(event_type, message, **details)


def log_slow_operation(
    operation: str,
    duration_s: float,
    **details: Any,
) -> dict[str, Any]:
    """Log a slow operation via the default manager."""
    manager = LoggingManager._get_default_manager()
    assert manager is not None
    return manager.log_slow_operation(operation, duration_s, **details)


def log_error(source: str, message: str, exc: Any = None, **details: Any) -> dict[str, Any]:
    """Log a structured error via the default manager."""
    manager = LoggingManager._get_default_manager()
    assert manager is not None
    return manager.log_error(source, message, exc=exc, **details)


def log_alert(
    alert_type: str,
    severity: str,
    message: str,
    **details: Any,
) -> dict[str, Any] | None:
    """Log a deduplicated alert via the default manager."""
    manager = LoggingManager._get_default_manager()
    assert manager is not None
    return manager.log_alert(alert_type, severity, message, **details)


def log_service_status(service: str, status: str, **details: Any) -> dict[str, Any] | None:
    """Log a service-status transition via the default manager."""
    manager = LoggingManager._get_default_manager()
    assert manager is not None
    return manager.log_service_status(service, status, **details)


__all__ = [
    "APP_LOG_FORMAT",
    "JSON_LOG_FORMAT",
    "SLOW_OPERATION_THRESHOLD",
    "VERY_SLOW_OPERATION_THRESHOLD",
    "DEDUP_WINDOW_S",
    "MAX_DEDUP_KEYS",
    "LoggingManager",
    "clear_log_context",
    "configure_logging",
    "get_logger",
    "get_logging_manager",
    "log_alert",
    "log_error",
    "log_event",
    "log_service_status",
    "log_slow_operation",
    "set_log_context",
]
