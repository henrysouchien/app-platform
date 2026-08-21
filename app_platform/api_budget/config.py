"""Configuration parsing and validation for the API budget guard."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import threading
from typing import Any

WINDOW_KINDS = ("daily", "monthly")
SCOPE_ALIASES = {
    "global": "global",
    "user": "user",
    "per_user": "user",
}

_CONFIG_LOCK = threading.Lock()
_CONFIG_CACHE: "BudgetConfig | None" = None


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return int(raw.strip())


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return float(raw.strip())


def _normalize_limit(value: Any, *, provider: str, path: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(
            f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at {path}: "
            "boolean values are not allowed for warn/limit"
        )
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at {path}: "
            f"expected integer or null, got {value!r}"
        ) from exc
    if normalized < 0:
        raise ValueError(
            f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at {path}: "
            "thresholds must be >= 0"
        )
    return normalized


@dataclass(frozen=True)
class Threshold:
    warn: int | None = None
    limit: int | None = None

    def as_dict(self) -> dict[str, int | None]:
        return {"warn": self.warn, "limit": self.limit}


@dataclass(frozen=True)
class ProviderThresholds:
    default: dict[str, dict[str, Threshold]] = field(default_factory=dict)
    operations: dict[str, dict[str, dict[str, Threshold]]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "default": {
                scope: {
                    window: threshold.as_dict()
                    for window, threshold in sorted(windows.items())
                }
                for scope, windows in sorted(self.default.items())
            },
            "operations": {
                operation: {
                    scope: {
                        window: threshold.as_dict()
                        for window, threshold in sorted(windows.items())
                    }
                    for scope, windows in sorted(scopes.items())
                }
                for operation, scopes in sorted(self.operations.items())
            },
        }


def _normalize_window_block(
    provider: str,
    path: str,
    payload: Any,
) -> dict[str, Threshold]:
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError(
            f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at {path}: "
            "expected object or null"
        )

    result: dict[str, Threshold] = {}
    for window_kind, threshold_payload in payload.items():
        window_key = str(window_kind or "").strip().lower()
        if window_key not in WINDOW_KINDS:
            raise ValueError(
                f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at "
                f"{path}.{window_kind}: unknown window kind"
            )
        if threshold_payload is None:
            continue
        if not isinstance(threshold_payload, dict):
            raise ValueError(
                f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at "
                f"{path}.{window_key}: expected object or null"
            )
        result[window_key] = Threshold(
            warn=_normalize_limit(
                threshold_payload.get("warn"),
                provider=provider,
                path=f"{path}.{window_key}.warn",
            ),
            limit=_normalize_limit(
                threshold_payload.get("limit"),
                provider=provider,
                path=f"{path}.{window_key}.limit",
            ),
        )
    return result


def _normalize_scope_block(
    provider: str,
    path: str,
    payload: Any,
) -> dict[str, dict[str, Threshold]]:
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError(
            f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at {path}: "
            "expected object or null"
        )

    result: dict[str, dict[str, Threshold]] = {}
    for scope_name, window_payload in payload.items():
        scope_key = SCOPE_ALIASES.get(str(scope_name or "").strip().lower())
        if scope_key is None:
            raise ValueError(
                f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at "
                f"{path}.{scope_name}: unknown scope"
            )
        result[scope_key] = _normalize_window_block(
            provider,
            f"{path}.{scope_name}",
            window_payload,
        )
    return result


def _normalize_provider_thresholds(provider: str, payload: Any) -> ProviderThresholds:
    if payload is None:
        return ProviderThresholds()
    if not isinstance(payload, dict):
        raise ValueError(
            f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}': "
            "provider entry must be an object or null"
        )

    default_block = _normalize_scope_block(provider, "default", payload.get("default"))

    operations_payload = payload.get("operations") or {}
    if not isinstance(operations_payload, dict):
        raise ValueError(
            f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}' at operations: "
            "expected object"
        )

    operations: dict[str, dict[str, dict[str, Threshold]]] = {}
    for operation, operation_payload in operations_payload.items():
        operation_name = str(operation or "").strip()
        if not operation_name:
            raise ValueError(
                f"API_BUDGET_THRESHOLDS_JSON invalid for provider '{provider}': "
                "operation names must be non-empty strings"
            )
        operations[operation_name] = _normalize_scope_block(
            provider,
            f"operations.{operation_name}",
            operation_payload,
        )

    return ProviderThresholds(default=default_block, operations=operations)


@dataclass(frozen=True)
class BudgetConfig:
    enabled: bool
    dry_run: bool
    fail_open: bool
    redis_url: str
    sample_log_pct: float
    snapshot_interval_seconds: int
    log_retention_days: int
    alert_dedup_seconds: int
    telegram_bot_token: str
    telegram_chat_id: str
    raw_thresholds: dict[str, Any]
    providers: dict[str, ProviderThresholds]

    @classmethod
    def from_env(cls) -> "BudgetConfig":
        raw_json = os.getenv("API_BUDGET_THRESHOLDS_JSON", "").strip()
        if not raw_json:
            thresholds_payload: dict[str, Any] = {"providers": {}}
        else:
            try:
                loaded = json.loads(raw_json)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"API_BUDGET_THRESHOLDS_JSON is not valid JSON: {exc.msg} "
                    f"(line {exc.lineno}, column {exc.colno})"
                ) from exc
            if not isinstance(loaded, dict):
                raise ValueError("API_BUDGET_THRESHOLDS_JSON must be a JSON object")
            thresholds_payload = loaded

        providers_payload = thresholds_payload.get("providers") or {}
        if not isinstance(providers_payload, dict):
            raise ValueError("API_BUDGET_THRESHOLDS_JSON.providers must be an object")

        providers: dict[str, ProviderThresholds] = {}
        for provider_name, provider_payload in providers_payload.items():
            provider_key = str(provider_name or "").strip().lower()
            if not provider_key:
                raise ValueError("API_BUDGET_THRESHOLDS_JSON contains an empty provider name")
            providers[provider_key] = _normalize_provider_thresholds(provider_key, provider_payload)

        config = cls(
            enabled=_env_flag("API_BUDGET_ENABLED", True),
            dry_run=_env_flag("API_BUDGET_DRY_RUN", True),
            fail_open=_env_flag("API_BUDGET_FAIL_OPEN", True),
            redis_url=os.getenv("API_BUDGET_REDIS_URL", "redis://localhost:6379/2").strip(),
            sample_log_pct=max(0.0, min(100.0, _env_float("API_BUDGET_SAMPLE_LOG_PCT", 10.0))),
            snapshot_interval_seconds=max(
                1,
                _env_int("API_BUDGET_SNAPSHOT_INTERVAL_SECONDS", 60),
            ),
            log_retention_days=max(1, _env_int("API_BUDGET_LOG_RETENTION_DAYS", 30)),
            alert_dedup_seconds=max(1, _env_int("API_BUDGET_ALERT_DEDUP_SECONDS", 600)),
            telegram_bot_token=(
                os.getenv("API_BUDGET_TELEGRAM_BOT_TOKEN", "")
                or os.getenv("TELEGRAM_BOT_TOKEN", "")
            ).strip(),
            telegram_chat_id=(
                os.getenv("API_BUDGET_TELEGRAM_CHAT_ID", "")
                or os.getenv("TELEGRAM_CHAT_ID", "")
            ).strip(),
            raw_thresholds=thresholds_payload,
            providers=providers,
        )
        config.validate()
        return config

    def validate(self) -> None:
        for provider_name, provider_thresholds in self.providers.items():
            for operation, scope_map in provider_thresholds.operations.items():
                for scope in ("global", "user"):
                    for window_kind in WINDOW_KINDS:
                        op_limit = (
                            scope_map.get(scope, {})
                            .get(window_kind, Threshold())
                            .limit
                        )
                        default_limit = (
                            provider_thresholds.default.get(scope, {})
                            .get(window_kind, Threshold())
                            .limit
                        )
                        if (
                            op_limit is not None
                            and default_limit is not None
                            and op_limit < default_limit
                        ):
                            raise ValueError(
                                "API_BUDGET_THRESHOLDS_JSON invalid: "
                                f"provider='{provider_name}', operation='{operation}', "
                                f"scope='{scope}', window='{window_kind}', "
                                f"op_limit={op_limit} is below default_limit={default_limit}"
                            )

    def get_default_threshold(
        self,
        provider: str,
        scope: str,
        window_kind: str,
    ) -> Threshold:
        provider_key = str(provider or "").strip().lower()
        scope_key = SCOPE_ALIASES.get(str(scope or "").strip().lower(), str(scope or "").strip().lower())
        window_key = str(window_kind or "").strip().lower()
        return (
            self.providers.get(provider_key, ProviderThresholds())
            .default.get(scope_key, {})
            .get(window_key, Threshold())
        )

    def get_operation_threshold(
        self,
        provider: str,
        operation: str,
        scope: str,
        window_kind: str,
    ) -> Threshold:
        provider_key = str(provider or "").strip().lower()
        operation_key = str(operation or "").strip()
        scope_key = SCOPE_ALIASES.get(str(scope or "").strip().lower(), str(scope or "").strip().lower())
        window_key = str(window_kind or "").strip().lower()
        provider_thresholds = self.providers.get(provider_key, ProviderThresholds())
        default_threshold = provider_thresholds.default.get(scope_key, {}).get(window_key, Threshold())
        override_threshold = (
            provider_thresholds.operations.get(operation_key, {})
            .get(scope_key, {})
            .get(window_key)
        )
        if override_threshold is None:
            return default_threshold
        return Threshold(
            warn=override_threshold.warn
            if override_threshold.warn is not None
            else default_threshold.warn,
            limit=override_threshold.limit
            if override_threshold.limit is not None
            else default_threshold.limit,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "dry_run": self.dry_run,
            "fail_open": self.fail_open,
            "redis_url": self.redis_url,
            "sample_log_pct": self.sample_log_pct,
            "snapshot_interval_seconds": self.snapshot_interval_seconds,
            "log_retention_days": self.log_retention_days,
            "alert_dedup_seconds": self.alert_dedup_seconds,
            "providers": {
                provider: thresholds.as_dict()
                for provider, thresholds in sorted(self.providers.items())
            },
        }


def get_budget_config(*, refresh: bool = False) -> BudgetConfig:
    global _CONFIG_CACHE
    if refresh:
        with _CONFIG_LOCK:
            _CONFIG_CACHE = BudgetConfig.from_env()
            return _CONFIG_CACHE

    if _CONFIG_CACHE is None:
        with _CONFIG_LOCK:
            if _CONFIG_CACHE is None:
                _CONFIG_CACHE = BudgetConfig.from_env()
    assert _CONFIG_CACHE is not None
    return _CONFIG_CACHE


__all__ = [
    "BudgetConfig",
    "ProviderThresholds",
    "Threshold",
    "WINDOW_KINDS",
    "get_budget_config",
]
