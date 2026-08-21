"""Redis-backed counter storage for the API budget guard."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from importlib import resources
import json
import threading
from typing import Any

from database.session import get_db_session

try:
    import redis
    from redis.exceptions import NoScriptError, RedisError
except Exception:  # pragma: no cover - optional dependency
    redis = None  # type: ignore[assignment]

    class RedisError(Exception):
        """Fallback Redis error when the dependency is unavailable."""

    class NoScriptError(RedisError):
        """Fallback NOSCRIPT error when the dependency is unavailable."""

from .config import BudgetConfig, Threshold, get_budget_config
from .exceptions import BudgetGuardUnavailable

_REDIS_LOCK = threading.Lock()
_REDIS_CLIENT: "redis.Redis | None" = None
_SCRIPT_LOCK = threading.Lock()
_SCRIPT_SHA: str | None = None
_SCRIPT_TEXT: str | None = None


def _require_redis() -> None:
    if redis is None:  # pragma: no cover - exercised only without dependency installed
        raise RuntimeError("redis package is required; install app-platform[api-budget]")


def get_redis_client(*, refresh: bool = False) -> "redis.Redis":
    global _REDIS_CLIENT
    global _SCRIPT_SHA
    _require_redis()

    if refresh:
        with _REDIS_LOCK:
            _SCRIPT_SHA = None
            _REDIS_CLIENT = redis.Redis.from_url(
                get_budget_config(refresh=True).redis_url,
                decode_responses=True,
            )
            return _REDIS_CLIENT

    if _REDIS_CLIENT is None:
        with _REDIS_LOCK:
            if _REDIS_CLIENT is None:
                _REDIS_CLIENT = redis.Redis.from_url(
                    get_budget_config().redis_url,
                    decode_responses=True,
                )
    assert _REDIS_CLIENT is not None
    return _REDIS_CLIENT


def _load_lua_script() -> str:
    global _SCRIPT_TEXT
    if _SCRIPT_TEXT is None:
        with _SCRIPT_LOCK:
            if _SCRIPT_TEXT is None:
                script_path = resources.files("app_platform.api_budget").joinpath(
                    "lua/budget_incr.lua"
                )
                _SCRIPT_TEXT = script_path.read_text(encoding="utf-8")
    assert _SCRIPT_TEXT is not None
    return _SCRIPT_TEXT


def _load_script_sha(client: "redis.Redis") -> str:
    global _SCRIPT_SHA
    if _SCRIPT_SHA is None:
        with _SCRIPT_LOCK:
            if _SCRIPT_SHA is None:
                _SCRIPT_SHA = client.script_load(_load_lua_script())
    assert _SCRIPT_SHA is not None
    return _SCRIPT_SHA


def _period_start(window_kind: str, *, now: datetime | None = None) -> datetime:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if window_kind == "daily":
        return current.replace(hour=0, minute=0, second=0, microsecond=0)
    if window_kind == "monthly":
        return current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"Unsupported window kind: {window_kind}")


def _current_billing_month(*, now: datetime | None = None) -> date:
    """First-of-month UTC. Mirrors _period_start convention."""
    current = (now or datetime.now(UTC)).astimezone(UTC)
    return current.replace(day=1, hour=0, minute=0, second=0, microsecond=0).date()


def _next_period_start(window_kind: str, *, now: datetime | None = None) -> datetime:
    start = _period_start(window_kind, now=now)
    if window_kind == "daily":
        return start + timedelta(days=1)
    if start.month == 12:
        return start.replace(year=start.year + 1, month=1)
    return start.replace(month=start.month + 1)


def _ttl_seconds(window_kind: str, *, now: datetime | None = None) -> int:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    window_end = _next_period_start(window_kind, now=current)
    return max(1, int((window_end - current).total_seconds()) + 86400)


def _encode_window_start(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def _decode_window_start(value: str) -> datetime:
    return datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


def _counter_key(
    *,
    provider: str,
    operation: str,
    scope: str,
    window_kind: str,
    window_start: datetime,
    user_id: int | None = None,
) -> str:
    provider_key = str(provider or "").strip().lower()
    operation_key = str(operation or "").strip()
    encoded_start = _encode_window_start(window_start)
    if scope == "global":
        return f"budget:counter:{provider_key}:{operation_key}:global:{window_kind}:{encoded_start}"
    return (
        f"budget:counter:{provider_key}:{operation_key}:user:{int(user_id)}:"
        f"{window_kind}:{encoded_start}"
    )


def build_counter_key_specs(
    provider: str,
    operation: str,
    *,
    budget_user_id: int | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []

    for scope, key_kind in (
        ("global", "op"),
        ("global", "agg"),
        ("user", "op"),
        ("user", "agg"),
    ):
        if scope == "user" and budget_user_id is None:
            continue
        user_id = int(budget_user_id) if scope == "user" and budget_user_id is not None else None
        op_name = operation if key_kind == "op" else "_all_"
        for window_kind in ("daily", "monthly"):
            specs.append(
                {
                    "scope": scope,
                    "key_kind": key_kind,
                    "window_kind": window_kind,
                    "window_start": _period_start(window_kind, now=now),
                    "ttl_seconds": _ttl_seconds(window_kind, now=now),
                    "user_id": user_id,
                    "operation": op_name,
                    "key": _counter_key(
                        provider=provider,
                        operation=op_name,
                        scope=scope,
                        user_id=user_id,
                        window_kind=window_kind,
                        window_start=_period_start(window_kind, now=now),
                    ),
                }
            )
    return specs


def _threshold_for_spec(
    config: BudgetConfig,
    provider: str,
    operation: str,
    spec: dict[str, Any],
) -> Threshold:
    if spec["key_kind"] == "agg":
        return config.get_default_threshold(provider, spec["scope"], spec["window_kind"])
    return config.get_operation_threshold(provider, operation, spec["scope"], spec["window_kind"])


def incr_counter(
    provider: str,
    operation: str,
    *,
    budget_user_id: int | None = None,
    amount: int = 1,
    config: BudgetConfig | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    active_config = config or get_budget_config()
    client = get_redis_client()
    specs = build_counter_key_specs(
        provider,
        operation,
        budget_user_id=budget_user_id,
        now=now,
    )
    keys = [spec["key"] for spec in specs]
    argv: list[str] = [str(int(amount))]
    for spec in specs:
        threshold = _threshold_for_spec(active_config, provider, operation, spec)
        argv.extend(
            [
                str(threshold.limit if threshold.limit is not None else -1),
                str(threshold.warn if threshold.warn is not None else -1),
                str(int(spec["ttl_seconds"])),
            ]
        )

    script_text = _load_lua_script()
    try:
        script_sha = _load_script_sha(client)
        raw_result = client.evalsha(script_sha, len(keys), *keys, *argv)
    except NoScriptError:
        raw_result = client.eval(script_text, len(keys), *keys, *argv)
    except Exception as exc:
        raise BudgetGuardUnavailable(f"Budget Redis unavailable: {exc}") from exc

    payload = json.loads(raw_result)
    payload["keys"] = keys
    return payload


def record_item_subscription_charge_if_first(
    *, provider: str, operation: str, item_id: str,
    billing_month: date, monthly_rate: Decimal,
) -> Decimal:
    """Atomically record a Plaid per-Item-per-op-per-month subscription charge."""
    rate = Decimal(monthly_rate)
    with get_db_session() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO api_item_subscription_charges
                    (provider, operation, item_id, billing_month, charged_amount, charged_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (provider, operation, item_id, billing_month) DO NOTHING
                RETURNING id
                """,
                (
                    str(provider).strip().lower(),
                    str(operation).strip(),
                    str(item_id).strip(),
                    billing_month,
                    rate,
                ),
            )
            row = cursor.fetchone()
            conn.commit()
            return rate if row is not None else Decimal("0")
        except Exception:
            rollback = getattr(conn, "rollback", None)
            if callable(rollback):
                rollback()
            raise
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()


def record_connected_user_subscription_charge_if_first(
    *, provider: str, user_id: int,
    billing_month: date, monthly_rate: Decimal,
) -> Decimal:
    """Atomically record a SnapTrade per-Connected-User-per-month charge."""
    rate = Decimal(monthly_rate)
    with get_db_session() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO api_connected_user_subscription_charges
                    (provider, user_id, billing_month, charged_amount, charged_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (provider, user_id, billing_month) DO NOTHING
                RETURNING id
                """,
                (
                    str(provider).strip().lower(),
                    int(user_id),
                    billing_month,
                    rate,
                ),
            )
            row = cursor.fetchone()
            conn.commit()
            return rate if row is not None else Decimal("0")
        except Exception:
            rollback = getattr(conn, "rollback", None)
            if callable(rollback):
                rollback()
            raise
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()


def parse_counter_key(key: str) -> dict[str, Any] | None:
    parts = str(key or "").split(":")
    if len(parts) not in {7, 8} or parts[:2] != ["budget", "counter"]:
        return None

    provider = parts[2]
    operation = parts[3]
    scope = parts[4]
    if scope == "global" and len(parts) == 7:
        window_kind = parts[5]
        window_start = parts[6]
        user_id = None
    elif scope == "user" and len(parts) == 8:
        user_id = int(parts[5])
        window_kind = parts[6]
        window_start = parts[7]
    else:
        return None

    return {
        "provider": provider,
        "operation": operation,
        "scope": scope,
        "user_id": user_id,
        "window_kind": window_kind,
        "window_start": _decode_window_start(window_start),
    }


def scan_counter_entries(
    *,
    provider: str | None = None,
    client: "redis.Redis | None" = None,
) -> list[dict[str, Any]]:
    redis_client = client or get_redis_client()
    provider_key = str(provider or "").strip().lower()
    pattern = f"budget:counter:{provider_key}:*" if provider_key else "budget:counter:*"

    cursor = 0
    entries: list[dict[str, Any]] = []
    while True:
        cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=500)
        if keys:
            values = redis_client.mget(keys)
            for key, value in zip(keys, values):
                if value is None:
                    continue
                parsed = parse_counter_key(key)
                if parsed is None:
                    continue
                parsed["call_count"] = int(value)
                parsed["redis_key"] = key
                entries.append(parsed)
        if cursor == 0:
            break

    entries.sort(
        key=lambda item: (
            item["provider"],
            item["operation"],
            item["scope"],
            item["user_id"] if item["user_id"] is not None else -1,
            item["window_kind"],
            item["window_start"],
        )
    )
    return entries


def reset_counter(
    provider: str,
    *,
    window: str,
    budget_user_id: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    redis_client = get_redis_client()
    provider_key = str(provider or "").strip().lower()
    window_key = str(window or "").strip().lower()
    scope = "user" if budget_user_id is not None else "global"
    window_start = _encode_window_start(_period_start(window_key, now=now))

    if scope == "global":
        pattern = f"budget:counter:{provider_key}:*:global:{window_key}:{window_start}"
    else:
        pattern = (
            f"budget:counter:{provider_key}:*:user:{int(budget_user_id)}:"
            f"{window_key}:{window_start}"
        )

    deleted = 0
    cursor = 0
    while True:
        cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=500)
        if keys:
            deleted += int(redis_client.delete(*keys) or 0)
        if cursor == 0:
            break

    return {
        "provider": provider_key,
        "scope": scope,
        "user_id": int(budget_user_id) if budget_user_id is not None else None,
        "window_kind": window_key,
        "window_start": _decode_window_start(window_start),
        "deleted": deleted,
    }


def redis_state() -> str:
    try:
        return "ok" if get_redis_client().ping() else "unavailable"
    except Exception:
        return "unavailable"


__all__ = [
    "build_counter_key_specs",
    "get_redis_client",
    "incr_counter",
    "parse_counter_key",
    "record_connected_user_subscription_charge_if_first",
    "record_item_subscription_charge_if_first",
    "redis_state",
    "reset_counter",
    "scan_counter_entries",
]
