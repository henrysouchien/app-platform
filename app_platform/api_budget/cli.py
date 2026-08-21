"""CLI for the API budget guard."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import sys
from typing import Any

from database import DatabaseUnavailableError
from database.session import get_db_session
from utils.logging import log_event

from .config import get_budget_config
from .exceptions import BudgetGuardUnavailable
from .snapshot import snapshot_to_postgres
from .store import redis_state, reset_counter, scan_counter_entries

DEFAULT_REQUIRED_PROVIDERS = (
    "plaid",
    "snaptrade",
    "schwab",
    "ibkr",
    "fmp",
    "fmp_estimates",
    "openai",
    "anthropic",
)
DEFAULT_ALLOWED_UNCAPPED_PROVIDERS = ("fmp",)
REQUIRED_TABLES = (
    "api_call_counters",
    "api_call_log",
    "api_connected_user_subscription_charges",
    "api_item_subscription_charges",
)


def _db_rows(
    query: str,
    params: tuple[Any, ...] = (),
    *,
    operation: str,
) -> list[dict[str, Any]]:
    try:
        with get_db_session() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, params)
                return list(cursor.fetchall() or [])
            finally:
                close = getattr(cursor, "close", None)
                if callable(close):
                    close()
    except Exception as exc:
        raise DatabaseUnavailableError(
            f"Database unavailable for API budget status {operation}"
        ) from exc


def _has_any_threshold(provider_thresholds: Any) -> bool:
    def threshold_is_set(threshold: Any) -> bool:
        return (
            getattr(threshold, "warn", None) is not None
            or getattr(threshold, "limit", None) is not None
        )

    for scope_map in getattr(provider_thresholds, "default", {}).values():
        for threshold in scope_map.values():
            if threshold_is_set(threshold):
                return True
    for operation_map in getattr(provider_thresholds, "operations", {}).values():
        for scope_map in operation_map.values():
            for threshold in scope_map.values():
                if threshold_is_set(threshold):
                    return True
    return False


def _check(name: str, ok: bool, detail: str, **data: Any) -> dict[str, Any]:
    payload = {"name": name, "ok": bool(ok), "detail": detail}
    if data:
        payload["data"] = data
    return payload


def _age_seconds(value: Any) -> int | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return max(0, int((datetime.now(UTC) - value.astimezone(UTC)).total_seconds()))


def _rollout_check_payload(
    *,
    required_providers: list[str],
    allowed_uncapped_providers: list[str],
    min_observation_days: int,
    max_snapshot_age_seconds: int,
    require_live: bool,
    require_telegram: bool,
) -> dict[str, Any]:
    config = get_budget_config()
    checks: list[dict[str, Any]] = []

    checks.append(
        _check(
            "enabled",
            bool(config.enabled),
            "API budget guard is enabled" if config.enabled else "API budget guard is disabled",
        )
    )
    checks.append(
        _check(
            "live_mode",
            (not config.dry_run) if require_live else True,
            (
                "API_BUDGET_DRY_RUN=false"
                if not config.dry_run
                else "API_BUDGET_DRY_RUN=true; prerequisites can be checked before the flip"
            ),
            dry_run=bool(config.dry_run),
            require_live=bool(require_live),
        )
    )
    checks.append(
        _check(
            "fail_open_policy",
            True,
            "API_BUDGET_FAIL_OPEN=true" if config.fail_open else "API_BUDGET_FAIL_OPEN=false",
            fail_open=bool(config.fail_open),
        )
    )

    provider_names = {provider.lower() for provider in config.providers}
    required = [provider.strip().lower() for provider in required_providers if provider.strip()]
    allowed_uncapped = {
        provider.strip().lower()
        for provider in allowed_uncapped_providers
        if provider.strip()
    }
    missing_providers = [provider for provider in required if provider not in provider_names]
    unprotected_providers = [
        provider
        for provider in required
        if provider in provider_names
        and provider not in allowed_uncapped
        and not _has_any_threshold(config.providers[provider])
    ]
    thresholds_ok = not missing_providers and not unprotected_providers
    checks.append(
        _check(
            "threshold_policy",
            thresholds_ok,
            (
                "Required provider threshold policy is configured"
                if thresholds_ok
                else "Required provider threshold policy is incomplete"
            ),
            configured_providers=sorted(provider_names),
            required_providers=required,
            allowed_uncapped_providers=sorted(allowed_uncapped),
            missing_providers=missing_providers,
            unprotected_providers=unprotected_providers,
        )
    )

    telegram_ok = bool(config.telegram_bot_token and config.telegram_chat_id)
    checks.append(
        _check(
            "telegram_config",
            telegram_ok if require_telegram else True,
            (
                "Telegram alert env is configured"
                if telegram_ok
                else "Telegram alert env is missing"
            ),
            require_telegram=bool(require_telegram),
        )
    )

    state = redis_state()
    checks.append(
        _check(
            "redis",
            state == "ok",
            f"Redis state is {state}",
            redis_state=state,
            redis_url=config.redis_url,
        )
    )

    table_rows = _db_rows(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN (
            'api_call_counters',
            'api_call_log',
            'api_connected_user_subscription_charges',
            'api_item_subscription_charges'
          )
        """,
        operation="schema tables",
    )
    present_tables = {str(row.get("table_name")) for row in table_rows}
    missing_tables = [table for table in REQUIRED_TABLES if table not in present_tables]
    checks.append(
        _check(
            "schema",
            not missing_tables,
            "API budget schema tables are present" if not missing_tables else "API budget schema tables are missing",
            present_tables=sorted(present_tables),
            missing_tables=missing_tables,
        )
    )

    observation_rows = _db_rows(
        """
        SELECT
          COUNT(*) AS rows,
          COUNT(DISTINCT ts::date) AS active_days,
          MIN(ts) AS first_ts,
          MAX(ts) AS last_ts
        FROM api_call_log
        WHERE ts > NOW() - (%s::int * INTERVAL '1 day')
        """,
        (min_observation_days,),
        operation="observation logs",
    )
    observation = observation_rows[0] if observation_rows else {}
    active_days = int(observation.get("active_days") or 0)
    log_rows = int(observation.get("rows") or 0)
    observation_ok = log_rows > 0 and active_days >= min_observation_days
    checks.append(
        _check(
            "observation_window",
            observation_ok,
            (
                f"Observed {active_days} active log days"
                if observation_ok
                else f"Only {active_days} active log days observed"
            ),
            rows=log_rows,
            active_days=active_days,
            min_observation_days=min_observation_days,
            first_ts=observation.get("first_ts"),
            last_ts=observation.get("last_ts"),
        )
    )

    snapshot_rows = _db_rows(
        """
        SELECT
          COUNT(*) AS rows,
          COUNT(DISTINCT window_start::date) FILTER (WHERE window_kind = 'daily') AS daily_windows,
          MAX(updated_at) AS latest_snapshot
        FROM api_call_counters
        WHERE scope = 'global'
          AND operation = '_all_'
          AND updated_at > NOW() - (%s::int * INTERVAL '1 day')
        """,
        (min_observation_days,),
        operation="counter snapshots",
    )
    snapshot = snapshot_rows[0] if snapshot_rows else {}
    snapshot_count = int(snapshot.get("rows") or 0)
    daily_windows = int(snapshot.get("daily_windows") or 0)
    latest_snapshot = snapshot.get("latest_snapshot")
    latest_snapshot_age_seconds = _age_seconds(latest_snapshot)
    snapshot_fresh = (
        latest_snapshot_age_seconds is not None
        and latest_snapshot_age_seconds <= max_snapshot_age_seconds
    )
    snapshots_ok = (
        snapshot_count > 0
        and daily_windows >= min_observation_days
        and snapshot_fresh
    )
    checks.append(
        _check(
            "counter_snapshots",
            snapshots_ok,
            (
                "Counter snapshots are populated and fresh"
                if snapshots_ok
                else "Counter snapshots are missing, too sparse, or stale"
            ),
            rows=snapshot_count,
            daily_windows=daily_windows,
            min_observation_days=min_observation_days,
            latest_snapshot=latest_snapshot,
            latest_snapshot_age_seconds=latest_snapshot_age_seconds,
            max_snapshot_age_seconds=max_snapshot_age_seconds,
        )
    )

    threshold_event_rows = _db_rows(
        """
        SELECT
          COALESCE(SUM(CASE WHEN decision = 'blocked' AND dry_run THEN 1 ELSE 0 END), 0) AS dry_run_blocked,
          COALESCE(SUM(CASE WHEN decision = 'warned' AND dry_run THEN 1 ELSE 0 END), 0) AS dry_run_warned
        FROM api_call_log
        WHERE ts > NOW() - (%s::int * INTERVAL '1 day')
        """,
        (min_observation_days,),
        operation="threshold events",
    )
    threshold_events = threshold_event_rows[0] if threshold_event_rows else {}
    dry_run_blocked = int(threshold_events.get("dry_run_blocked") or 0)
    dry_run_warned = int(threshold_events.get("dry_run_warned") or 0)
    checks.append(
        _check(
            "dry_run_blockers",
            dry_run_blocked == 0,
            (
                "No dry-run blocked calls observed"
                if dry_run_blocked == 0
                else "Dry-run blocked calls were observed; live mode would raise"
            ),
            dry_run_blocked=dry_run_blocked,
            dry_run_warned=dry_run_warned,
            min_observation_days=min_observation_days,
        )
    )

    ok = all(check["ok"] for check in checks)
    return {
        "ok": ok,
        "required_providers": required,
        "allowed_uncapped_providers": sorted(allowed_uncapped),
        "min_observation_days": min_observation_days,
        "max_snapshot_age_seconds": max_snapshot_age_seconds,
        "checks": checks,
    }


def _status_payload(provider: str | None) -> dict[str, Any]:
    config = get_budget_config()
    recent_logs_query = """
        SELECT *
        FROM api_call_log
        WHERE (%s IS NULL OR provider = %s)
        ORDER BY ts DESC
        LIMIT 25
    """
    cost_query = """
        SELECT provider, COALESCE(SUM(estimated_cost_usd), 0) AS total_cost_usd
        FROM api_call_log
        WHERE ts > NOW() - INTERVAL '1 day'
          AND (%s IS NULL OR provider = %s)
        GROUP BY provider
        ORDER BY provider
    """
    try:
        live_counters = scan_counter_entries(provider=provider)
    except Exception as exc:
        raise BudgetGuardUnavailable(
            f"API budget live counters unavailable: {exc}"
        ) from exc

    return {
        "provider": provider,
        "redis_state": redis_state(),
        "threshold_config": config.as_dict(),
        "live_counters": live_counters,
        "recent_log_rows": _db_rows(
            recent_logs_query,
            (provider, provider),
            operation="recent logs",
        ),
        "today_cost_by_provider": _db_rows(
            cost_query,
            (provider, provider),
            operation="today cost",
        ),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app_platform.api_budget")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status", help="Show budget counters and logs")
    status_parser.add_argument("--provider", default=None)

    reset_parser = subparsers.add_parser("reset", help="Reset current-window counters")
    reset_parser.add_argument("provider")
    reset_parser.add_argument("--window", choices=["daily", "monthly"], required=True)
    reset_parser.add_argument("--user-id", type=int, default=None)

    snapshot_parser = subparsers.add_parser(
        "snapshot",
        help="Snapshot live Redis budget counters to Postgres",
    )
    snapshot_parser.add_argument("--provider", default=None)

    rollout_parser = subparsers.add_parser(
        "rollout-check",
        help="Validate prerequisites before disabling API_BUDGET_DRY_RUN",
    )
    rollout_parser.add_argument(
        "--required-provider",
        action="append",
        default=None,
        help="Provider that must have threshold policy configured; repeatable. Defaults to production providers.",
    )
    rollout_parser.add_argument(
        "--allow-uncapped-provider",
        action="append",
        default=None,
        help="Required provider allowed to be configured without warn/limit thresholds; repeatable. Defaults to fmp.",
    )
    rollout_parser.add_argument("--min-observation-days", type=int, default=7)
    rollout_parser.add_argument("--max-snapshot-age-seconds", type=int, default=300)
    rollout_parser.add_argument(
        "--require-live",
        action="store_true",
        help="Fail unless API_BUDGET_DRY_RUN=false.",
    )
    rollout_parser.add_argument(
        "--skip-telegram",
        action="store_true",
        help="Do not fail if Telegram alert env is missing.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "status":
        try:
            payload = _status_payload(args.provider)
        except (BudgetGuardUnavailable, DatabaseUnavailableError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(payload, default=str, indent=2, sort_keys=True))
        return 0

    if args.command == "rollout-check":
        try:
            payload = _rollout_check_payload(
                required_providers=args.required_provider
                if args.required_provider is not None
                else list(DEFAULT_REQUIRED_PROVIDERS),
                allowed_uncapped_providers=args.allow_uncapped_provider
                if args.allow_uncapped_provider is not None
                else list(DEFAULT_ALLOWED_UNCAPPED_PROVIDERS),
                min_observation_days=max(1, int(args.min_observation_days)),
                max_snapshot_age_seconds=max(1, int(args.max_snapshot_age_seconds)),
                require_live=bool(args.require_live),
                require_telegram=not bool(args.skip_telegram),
            )
        except (BudgetGuardUnavailable, DatabaseUnavailableError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(payload, default=str, indent=2, sort_keys=True))
        return 0 if payload["ok"] else 1

    if args.command == "snapshot":
        try:
            result = snapshot_to_postgres(provider=args.provider)
        except Exception as exc:
            print(f"error: API budget snapshot failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, default=str, indent=2, sort_keys=True))
        return 0

    if args.command == "reset":
        result = reset_counter(
            args.provider,
            window=args.window,
            budget_user_id=args.user_id,
        )
        log_event(
            "api_budget_reset",
            "API budget counter reset",
            provider=result["provider"],
            window_kind=result["window_kind"],
            user_id=result["user_id"],
            deleted=result["deleted"],
        )
        print(json.dumps(result, default=str, indent=2, sort_keys=True))
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


__all__ = ["main"]
