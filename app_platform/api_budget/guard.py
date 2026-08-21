"""Core guard wrapper for API budget enforcement."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
import random
import time
from uuid import uuid4
from typing import Any, Literal

from config.api_budget_costs import get_cost_model_and_rate
from database.session import get_db_session
from utils.logging import get_logging_manager, log_alert, portfolio_logger
from app_platform.commercial.usage.direct import (
    assert_bound_direct_provider,
    get_direct_commercial_usage_binding,
)
from app_platform.commercial.usage.direct_budget import (
    api_budget_cost_provenance,
    api_budget_failure_state,
    canonical_budget_operation,
    emit_api_budget_direct_usage,
    is_api_budget_rate_configured,
)

from .alerts import send_alert
from .config import get_budget_config
from .exceptions import BudgetExceededError, BudgetGuardUnavailable
from .llm_cost import LLMUsage, estimate_cost_usd
from .store import (
    _current_billing_month,
    build_counter_key_specs,
    get_redis_client,
    incr_counter,
    record_connected_user_subscription_charge_if_first,
    record_item_subscription_charge_if_first,
)

_FAIL_OPEN_ALERTS: dict[str, float] = {}
_FAIL_OPEN_ALERT_TTL_SECONDS = 60.0
_LLM_PROVIDERS = {"openai", "anthropic"}
_PHASE_3_ENFORCED = True  # Flipped 2026-04-26 (P3) - preflight now hard-errors on missing subject identifier.


def _current_task_id() -> str | None:
    try:
        from celery import current_task

        request = getattr(current_task, "request", None)
        task_id = getattr(request, "id", None)
        return str(task_id) if task_id else None
    except Exception:
        return None


def _current_trace_id() -> str | None:
    manager = get_logging_manager(auto_configure=False)
    if manager is None:
        return None
    context = getattr(manager, "_context_var", None)
    if context is None:
        return None
    try:
        payload = context.get()
    except Exception:
        return None
    if not isinstance(payload, Mapping):
        return None
    trace_id = payload.get("trace_id") or payload.get("correlation_id")
    return str(trace_id) if trace_id else None


def _round_cost(value: Decimal | float | int | str | None) -> Decimal | None:
    if value is None:
        return None
    decimal_value = Decimal(str(value))
    return decimal_value.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)


def _estimate_cost(
    *,
    response: Any,
    cost_fn: Callable[[Any], Any] | None,
    cost_per_call: Decimal | float | int | str | None,
) -> Decimal | None:
    if cost_per_call is not None:
        return _round_cost(cost_per_call)
    if cost_fn is None:
        return None

    cost_value = cost_fn(response)
    if isinstance(cost_value, LLMUsage):
        return estimate_cost_usd(cost_value)
    return _round_cost(cost_value)


def _compute_cost_for_log(
    *,
    provider_key: str,
    operation_key: str,
    cost_model: Literal[
        "per_call", "per_item_month", "per_connected_user_month", "per_token"
    ],
    rate: Decimal | None,
    item_key: str | None,
    budget_user_id: int | None,
    result: Any,
    cost_fn: Callable[[Any], Any] | None,
    cost_per_call: Decimal | float | int | str | None,
    billing_month: date,
    call_succeeded: bool = False,
) -> tuple[Decimal | None, str, dict[str, Any] | None]:
    """Returns (estimated_cost, effective_cost_model, token_telemetry)."""
    if result is None and not call_succeeded:
        return (None, cost_model, None)

    if cost_model == "per_item_month":
        if item_key is None:
            return (_round_cost(rate), cost_model, None)
        try:
            charged = record_item_subscription_charge_if_first(
                provider=provider_key,
                operation=operation_key,
                item_id=item_key,
                billing_month=billing_month,
                monthly_rate=rate,
            )
            return (_round_cost(charged), cost_model, None)
        except Exception as exc:
            portfolio_logger.warning(
                "item subscription charge dedup failed provider=%s op=%s item=%s: %s "
                "(falling back to monthly_rate; api_call_log will over-attribute)",
                provider_key,
                operation_key,
                item_key,
                exc,
            )
            return (_round_cost(rate), cost_model, None)

    if cost_model == "per_connected_user_month":
        if budget_user_id is None:
            return (_round_cost(rate), cost_model, None)
        try:
            charged = record_connected_user_subscription_charge_if_first(
                provider=provider_key,
                user_id=int(budget_user_id),
                billing_month=billing_month,
                monthly_rate=rate,
            )
            return (_round_cost(charged), cost_model, None)
        except Exception as exc:
            portfolio_logger.warning(
                "connected-user subscription charge dedup failed provider=%s op=%s user=%s: %s "
                "(falling back to monthly_rate; api_call_log will over-attribute)",
                provider_key,
                operation_key,
                budget_user_id,
                exc,
            )
            return (_round_cost(rate), cost_model, None)

    if cost_model == "per_token":
        if cost_fn is None or result is None:
            return (None, cost_model, None)
        cost_value = cost_fn(result)
        if not isinstance(cost_value, LLMUsage):
            return (_round_cost(cost_value), cost_model, None)
        telemetry = {
            "input_tokens": int(cost_value.input_tokens),
            "output_tokens": int(cost_value.output_tokens),
            "cache_creation_tokens": cost_value.cache_creation_tokens,
            "cache_read_tokens": cost_value.cache_read_tokens,
            "is_batch": cost_value.is_batch,
        }
        return (estimate_cost_usd(cost_value), cost_model, telemetry)

    return (
        _estimate_cost(
            response=result,
            cost_fn=cost_fn,
            cost_per_call=(
                cost_per_call
                if cost_per_call is not None
                else (rate if cost_fn is None else None)
            ),
        ),
        cost_model,
        None,
    )


def _daily_count(
    counts: list[dict[str, Any]], *, scope: str, key_kind: str
) -> tuple[int | None, int | None]:
    for entry in counts:
        if (
            entry.get("scope") == scope
            and entry.get("key_kind") == key_kind
            and entry.get("window_kind") == "daily"
        ):
            return int(entry.get("before", 0)), int(entry.get("after", 0))
    return None, None


def _should_write_log(
    provider: str,
    decision: str,
    sample_log_pct: float,
    *,
    cost_model: str | None = None,
) -> bool:
    provider_key = str(provider or "").strip().lower()
    if provider_key in _LLM_PROVIDERS:
        return True
    if decision != "ok":
        return True
    # V4a-tail: subscription cost-models must always log so today_cost_by_provider
    # captures the first-of-month full-rate write that the dedup helper just
    # produced. Sampling them out causes the admin rollup to under-report.
    if cost_model is not None and cost_model != "per_call":
        return True
    return random.random() < (sample_log_pct / 100.0)


def _write_api_call_log(row: dict[str, Any]) -> None:
    with get_db_session() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO api_call_log (
                    provider,
                    operation,
                    caller,
                    user_id,
                    account_id,
                    item_id,
                    cost_model,
                    task_id,
                    trace_id,
                    duration_ms,
                    estimated_cost_usd,
                    input_tokens,
                    output_tokens,
                    cache_creation_tokens,
                    cache_read_tokens,
                    is_batch,
                    commercial_source_product,
                    commercial_source_event_id,
                    commercial_execution_context_id,
                    commercial_usage_state,
                    decision,
                    blocked_scope,
                    blocked_key_kind,
                    blocked_window_kind,
                    blocked_threshold,
                    blocked_count,
                    count_before_global,
                    count_after_global,
                    count_before_user,
                    count_after_user,
                    dry_run,
                    redis_state
                )
                VALUES (
                    %(provider)s,
                    %(operation)s,
                    %(caller)s,
                    %(user_id)s,
                    %(account_id)s,
                    %(item_id)s,
                    %(cost_model)s,
                    %(task_id)s,
                    %(trace_id)s,
                    %(duration_ms)s,
                    %(estimated_cost_usd)s,
                    %(input_tokens)s,
                    %(output_tokens)s,
                    %(cache_creation_tokens)s,
                    %(cache_read_tokens)s,
                    %(is_batch)s,
                    %(commercial_source_product)s,
                    %(commercial_source_event_id)s,
                    %(commercial_execution_context_id)s,
                    %(commercial_usage_state)s,
                    %(decision)s,
                    %(blocked_scope)s,
                    %(blocked_key_kind)s,
                    %(blocked_window_kind)s,
                    %(blocked_threshold)s,
                    %(blocked_count)s,
                    %(count_before_global)s,
                    %(count_after_global)s,
                    %(count_before_user)s,
                    %(count_after_user)s,
                    %(dry_run)s,
                    %(redis_state)s
                )
                """,
                row,
            )
            conn.commit()
        except Exception:
            rollback = getattr(conn, "rollback", None)
            if callable(rollback):
                rollback()
            raise
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()


def _maybe_write_api_call_log(
    *,
    provider: str,
    operation: str,
    caller: str | None,
    budget_user_id: int | None,
    account_id: str | None,
    duration_ms: int | None,
    estimated_cost_usd: Decimal | None,
    decision: str,
    blocked_scope: str | None,
    blocked_key_kind: str | None,
    blocked_window_kind: str | None,
    blocked_threshold: int | None,
    blocked_count: int | None,
    counts: list[dict[str, Any]],
    dry_run: bool,
    redis_state: str,
    item_id: str | None = None,
    cost_model: str | None = None,
    token_telemetry: dict[str, Any] | None = None,
    commercial_source_event_id: str | None = None,
    commercial_execution_context_id: str | None = None,
    commercial_usage_state: Literal[
        "succeeded", "failed_billable", "failed_unbilled", "canceled"
    ]
    | None = None,
) -> None:
    config = get_budget_config()
    if commercial_source_event_id is None and not _should_write_log(
        provider, decision, config.sample_log_pct, cost_model=cost_model
    ):
        return

    before_global, after_global = _daily_count(counts, scope="global", key_kind="agg")
    before_user, after_user = _daily_count(counts, scope="user", key_kind="agg")
    try:
        _write_api_call_log(
            {
                "provider": str(provider or "").strip().lower(),
                "operation": (
                    canonical_budget_operation(operation)
                    if commercial_source_event_id is not None
                    else str(operation or "").strip()
                ),
                "caller": caller,
                "user_id": int(budget_user_id) if budget_user_id is not None else None,
                "account_id": account_id,
                "item_id": item_id,
                "cost_model": cost_model,
                "task_id": _current_task_id(),
                "trace_id": _current_trace_id(),
                "duration_ms": duration_ms,
                "estimated_cost_usd": estimated_cost_usd,
                "input_tokens": None,
                "output_tokens": None,
                "cache_creation_tokens": None,
                "cache_read_tokens": None,
                "is_batch": None,
                "commercial_source_product": (
                    "risk-module-direct"
                    if commercial_source_event_id is not None
                    else None
                ),
                "commercial_source_event_id": commercial_source_event_id,
                "commercial_execution_context_id": commercial_execution_context_id,
                "commercial_usage_state": commercial_usage_state,
                "decision": decision,
                "blocked_scope": blocked_scope,
                "blocked_key_kind": blocked_key_kind,
                "blocked_window_kind": blocked_window_kind,
                "blocked_threshold": blocked_threshold,
                "blocked_count": blocked_count,
                "count_before_global": before_global,
                "count_after_global": after_global,
                "count_before_user": before_user,
                "count_after_user": after_user,
                "dry_run": bool(dry_run),
                "redis_state": redis_state,
                **(token_telemetry or {}),
            }
        )
    except Exception as exc:
        portfolio_logger.warning(
            "Failed to write api_call_log provider=%s operation=%s: %s",
            provider,
            operation,
            exc,
        )


def _log_fail_open_alert(provider: str, operation: str, exc: Exception) -> None:
    provider_key = str(provider or "").strip().lower()
    dedup_key = f"{provider_key}:{str(operation or '').strip()}"
    now = time.monotonic()
    cutoff = _FAIL_OPEN_ALERTS.get(dedup_key, 0.0)
    if now < cutoff:
        return
    _FAIL_OPEN_ALERTS[dedup_key] = now + _FAIL_OPEN_ALERT_TTL_SECONDS
    log_alert(
        "api_budget_guard_unavailable",
        "high",
        f"API budget guard unavailable for {provider_key}/{operation}; failing open",
        source="api_budget",
        provider=provider_key,
        error=str(exc),
    )


def _safe_send_alert(severity: str, provider: str, message: str, **details) -> None:
    try:
        send_alert(severity, provider, message, **details)
    except Exception as exc:
        portfolio_logger.warning(
            "Budget alert delivery failed provider=%s severity=%s: %s",
            provider,
            severity,
            exc,
        )


def guard_call(
    *,
    provider: str,
    operation: str,
    fn: Callable[..., Any],
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
    budget_user_id: int | None = None,
    account_id: str | None = None,
    caller: str | None = None,
    cost_fn: Callable[[Any], Any] | None = None,
    cost_per_call: Decimal | float | int | str | None = None,
    item_id: str | None = None,
    commercial_failure_state: Literal["failed_billable", "failed_unbilled", "canceled"]
    | None = None,
) -> Any:
    provider_key = str(provider or "").strip().lower()
    operation_key = str(operation or "").strip()
    direct_binding = get_direct_commercial_usage_binding()
    if direct_binding is not None:
        assert_bound_direct_provider(provider_key)
    direct_source_event_id = (
        f"direct:{uuid4()}"
        if direct_binding is not None and provider_key not in _LLM_PROVIDERS
        else None
    )
    direct_execution_context_id = (
        str(direct_binding.context.execution_context_id)
        if direct_source_event_id is not None
        else None
    )
    explicit_failure_state = commercial_failure_state is not None
    if direct_source_event_id is not None:
        canonical_budget_operation(operation_key)
        commercial_failure_state = commercial_failure_state or api_budget_failure_state(
            provider_key,
            operation_key,
        )
        if commercial_failure_state is None:
            raise ValueError(
                "guard_call: direct commercial non-LLM operation has no reviewed "
                "failure policy; pass commercial_failure_state explicitly"
            )

    def emit_direct(
        estimated_cost: Decimal | None,
        usage_state: Literal[
            "succeeded", "failed_billable", "failed_unbilled", "canceled"
        ] = "succeeded",
        *,
        provenance_cost_fn: Callable[[Any], Any] | None = cost_fn,
    ) -> None:
        if direct_source_event_id is not None:
            emit_api_budget_direct_usage(
                source_event_id=direct_source_event_id,
                provider=provider_key,
                operation=operation_key,
                estimated_cost_usd=estimated_cost,
                usage_state=usage_state,
                producer_rate_version=api_budget_cost_provenance(
                    provider=provider_key,
                    operation=operation_key,
                    estimated_cost_usd=estimated_cost,
                    cost_per_call=cost_per_call,
                    cost_fn=provenance_cost_fn,
                    cost_model=cost_model,
                ),
            )

    config = get_budget_config()
    cost_model, rate = get_cost_model_and_rate(provider_key, operation_key)
    item_key = str(item_id or "").strip() or None
    configured_rate = is_api_budget_rate_configured(provider_key, operation_key) or (
        explicit_failure_state and cost_per_call is not None
    )
    if direct_source_event_id is not None and not configured_rate:
        if direct_binding.context.raw_billing_mode == "metered":
            raise ValueError(
                "guard_call: metered provider operation has no configured cost: "
                f"{provider_key}/{operation_key}"
            )
        # The legacy budget guard treats unknown operations as free. Commercial
        # evidence must instead preserve the distinction between unknown and zero.
        rate = None

    missing_subject = (cost_model == "per_item_month" and item_key is None) or (
        cost_model == "per_connected_user_month" and budget_user_id is None
    )
    if missing_subject and (config.enabled or direct_source_event_id is not None):
        subject_kind = "item_id" if cost_model == "per_item_month" else "budget_user_id"
        if _PHASE_3_ENFORCED:
            raise ValueError(
                f"guard_call: subscription op {provider_key}/{operation_key} "
                f"requires {subject_kind} (preflight)"
            )
        portfolio_logger.warning(
            "guard_call subscription op without %s provider=%s op=%s "
            "(falling back to full rate; Phase 3 will hard-error preflight)",
            subject_kind,
            provider_key,
            operation_key,
        )

    def compute_cost(result: Any, *, succeeded: bool) -> Decimal | None:
        return _compute_cost_for_log(
            provider_key=provider_key,
            operation_key=operation_key,
            cost_model=cost_model,
            rate=rate,
            item_key=item_key,
            budget_user_id=budget_user_id,
            result=result,
            cost_fn=cost_fn,
            cost_per_call=cost_per_call,
            billing_month=_current_billing_month(),
            call_succeeded=succeeded,
        )[0]

    def emit_failure(provider_error: BaseException) -> Decimal | None:
        if direct_source_event_id is None:
            return None
        try:
            failure_state = commercial_failure_state
            if failure_state == "failed_billable":
                if cost_model in {"per_item_month", "per_connected_user_month"}:
                    failure_cost = compute_cost(None, succeeded=True)
                else:
                    failure_cost = _round_cost(
                        cost_per_call if cost_per_call is not None else rate
                    )
            else:
                failure_cost = None
            emit_direct(  # type: ignore[arg-type]
                failure_cost,
                failure_state,
                provenance_cost_fn=None,
            )
            return failure_cost
        except BaseException as emission_error:
            raise BaseExceptionGroup(
                "provider call and commercial failure accounting both failed",
                [provider_error, emission_error],
            ) from None

    if not config.enabled:
        if direct_source_event_id is None:
            return fn(*args, **(kwargs or {}))
        started = time.monotonic()
        result: Any = None
        call_succeeded = False
        failure_cost: Decimal | None = None
        try:
            result = fn(*args, **(kwargs or {}))
            call_succeeded = True
            return result
        except BaseException as provider_error:
            failure_cost = emit_failure(provider_error)
            raise
        finally:
            duration_ms = max(0, int(round((time.monotonic() - started) * 1000)))
            estimated_cost, effective_model, token_telemetry = _compute_cost_for_log(
                provider_key=provider_key,
                operation_key=operation_key,
                cost_model=cost_model,
                rate=rate,
                item_key=item_key,
                budget_user_id=budget_user_id,
                result=result,
                cost_fn=cost_fn,
                cost_per_call=cost_per_call,
                billing_month=_current_billing_month(),
                call_succeeded=call_succeeded,
            )
            if not call_succeeded and direct_source_event_id is not None:
                estimated_cost = failure_cost
                token_telemetry = None
            _maybe_write_api_call_log(
                provider=provider_key,
                operation=operation_key,
                caller=caller,
                budget_user_id=budget_user_id,
                account_id=account_id,
                item_id=item_key,
                cost_model=effective_model,
                duration_ms=duration_ms,
                estimated_cost_usd=estimated_cost,
                token_telemetry=token_telemetry,
                decision="ok" if call_succeeded else "error",
                blocked_scope=None,
                blocked_key_kind=None,
                blocked_window_kind=None,
                blocked_threshold=None,
                blocked_count=None,
                counts=[],
                dry_run=bool(getattr(config, "dry_run", False)),
                redis_state="ok",
                commercial_source_event_id=direct_source_event_id,
                commercial_execution_context_id=direct_execution_context_id,
                commercial_usage_state=(
                    "succeeded" if call_succeeded else commercial_failure_state
                ),
            )
            if call_succeeded:
                emit_direct(estimated_cost)

    try:
        counter_state = incr_counter(
            provider_key,
            operation_key,
            budget_user_id=budget_user_id,
            config=config,
        )
        redis_state = "ok"
    except Exception as exc:
        if not config.fail_open:
            raise BudgetGuardUnavailable(str(exc)) from exc
        _log_fail_open_alert(provider_key, operation_key, exc)
        started = time.monotonic()
        result: Any = None
        call_succeeded = False
        failure_cost: Decimal | None = None
        try:
            result = fn(*args, **(kwargs or {}))
            call_succeeded = True
            return result
        except BaseException as provider_error:
            failure_cost = emit_failure(provider_error)
            raise
        finally:
            duration_ms = max(0, int(round((time.monotonic() - started) * 1000)))
            estimated_cost = _compute_cost_for_log(
                provider_key=provider_key,
                operation_key=operation_key,
                cost_model=cost_model,
                rate=rate,
                item_key=item_key,
                budget_user_id=budget_user_id,
                result=result,
                cost_fn=cost_fn,
                cost_per_call=cost_per_call,
                billing_month=_current_billing_month(),
                call_succeeded=call_succeeded,
            )
            estimated_cost_usd, effective_model, token_telemetry = estimated_cost
            if not call_succeeded and direct_source_event_id is not None:
                estimated_cost_usd = failure_cost
                token_telemetry = None
            _maybe_write_api_call_log(
                provider=provider_key,
                operation=operation_key,
                caller=caller,
                budget_user_id=budget_user_id,
                account_id=account_id,
                item_id=item_key,
                cost_model=effective_model,
                duration_ms=duration_ms,
                estimated_cost_usd=estimated_cost_usd,
                token_telemetry=token_telemetry,
                decision="error",
                blocked_scope=None,
                blocked_key_kind=None,
                blocked_window_kind=None,
                blocked_threshold=None,
                blocked_count=None,
                counts=[],
                dry_run=config.dry_run,
                redis_state="unavailable",
                commercial_source_event_id=direct_source_event_id,
                commercial_execution_context_id=direct_execution_context_id,
                commercial_usage_state=(
                    "succeeded" if call_succeeded else commercial_failure_state
                ),
            )
            if call_succeeded:
                emit_direct(estimated_cost_usd)

    decision = str(counter_state.get("decision") or "ok")
    blocked_scope = counter_state.get("blocked_scope")
    blocked_key_kind = counter_state.get("blocked_key_kind")
    blocked_window_kind = counter_state.get("blocked_window_kind")
    blocked_threshold = counter_state.get("blocked_threshold")
    blocked_count = counter_state.get("blocked_count")
    counts = list(counter_state.get("counts") or [])
    crossings = list(counter_state.get("crossings") or [])

    if decision == "warned":
        _safe_send_alert(
            "medium",
            provider_key,
            f"API budget warning for {provider_key}/{operation_key}",
            operation=operation_key,
            crossings=crossings,
        )
    elif decision == "blocked" and config.dry_run:
        _safe_send_alert(
            "high",
            provider_key,
            f"API budget would block {provider_key}/{operation_key} (dry-run)",
            operation=operation_key,
            crossings=crossings,
            note="would_block",
        )
    elif decision == "blocked":
        _safe_send_alert(
            "critical",
            provider_key,
            f"API budget blocked {provider_key}/{operation_key}",
            operation=operation_key,
            crossings=crossings,
        )
        _maybe_write_api_call_log(
            provider=provider_key,
            operation=operation_key,
            caller=caller,
            budget_user_id=budget_user_id,
            account_id=account_id,
            item_id=item_key,
            cost_model=cost_model,
            duration_ms=0,
            estimated_cost_usd=None,
            decision="blocked",
            blocked_scope=blocked_scope,
            blocked_key_kind=blocked_key_kind,
            blocked_window_kind=blocked_window_kind,
            blocked_threshold=blocked_threshold,
            blocked_count=blocked_count,
            counts=counts,
            dry_run=config.dry_run,
            redis_state=redis_state,
        )
        raise BudgetExceededError(
            provider=provider_key,
            operation=operation_key,
            blocked_scope=blocked_scope,
            blocked_key_kind=blocked_key_kind,
            blocked_window_kind=blocked_window_kind,
            blocked_threshold=blocked_threshold,
            blocked_count=blocked_count,
        )

    started = time.monotonic()
    result: Any = None
    call_succeeded = False
    failure_cost: Decimal | None = None
    try:
        result = fn(*args, **(kwargs or {}))
        call_succeeded = True
        return result
    except BaseException as provider_error:
        failure_cost = emit_failure(provider_error)
        raise
    finally:
        duration_ms = max(0, int(round((time.monotonic() - started) * 1000)))
        estimated_cost, effective_model, token_telemetry = _compute_cost_for_log(
            provider_key=provider_key,
            operation_key=operation_key,
            cost_model=cost_model,
            rate=rate,
            item_key=item_key,
            budget_user_id=budget_user_id,
            result=result,
            cost_fn=cost_fn,
            cost_per_call=cost_per_call,
            billing_month=_current_billing_month(),
            call_succeeded=call_succeeded,
        )
        if not call_succeeded and direct_source_event_id is not None:
            estimated_cost = failure_cost
            token_telemetry = None
        _maybe_write_api_call_log(
            provider=provider_key,
            operation=operation_key,
            caller=caller,
            budget_user_id=budget_user_id,
            account_id=account_id,
            item_id=item_key,
            cost_model=effective_model,
            duration_ms=duration_ms,
            estimated_cost_usd=estimated_cost,
            token_telemetry=token_telemetry,
            decision=decision,
            blocked_scope=blocked_scope,
            blocked_key_kind=blocked_key_kind,
            blocked_window_kind=blocked_window_kind,
            blocked_threshold=blocked_threshold,
            blocked_count=blocked_count,
            counts=counts,
            dry_run=config.dry_run,
            redis_state=redis_state,
            commercial_source_event_id=direct_source_event_id,
            commercial_execution_context_id=direct_execution_context_id,
            commercial_usage_state=(
                "succeeded" if call_succeeded else commercial_failure_state
            ),
        )
        if call_succeeded:
            emit_direct(estimated_cost)


def is_provider_over_budget(
    provider: str,
    budget_user_id: int | None = None,
) -> tuple[bool, str | None]:
    config = get_budget_config()
    provider_key = str(provider or "").strip().lower()
    global_daily = config.get_default_threshold(provider_key, "global", "daily").limit
    global_monthly = config.get_default_threshold(
        provider_key, "global", "monthly"
    ).limit
    user_daily = config.get_default_threshold(provider_key, "user", "daily").limit
    user_monthly = config.get_default_threshold(provider_key, "user", "monthly").limit

    specs = [
        spec
        for spec in build_counter_key_specs(
            provider_key,
            "_all_",
            budget_user_id=budget_user_id,
        )
        if spec["key_kind"] == "agg"
    ]
    try:
        values = get_redis_client().mget([spec["key"] for spec in specs])
    except Exception:
        return False, "redis_unavailable"

    for spec, raw_value in zip(specs, values):
        count = int(raw_value or 0)
        limit = None
        if spec["scope"] == "global" and spec["window_kind"] == "daily":
            limit = global_daily
        elif spec["scope"] == "global" and spec["window_kind"] == "monthly":
            limit = global_monthly
        elif spec["scope"] == "user" and spec["window_kind"] == "daily":
            limit = user_daily
        elif spec["scope"] == "user" and spec["window_kind"] == "monthly":
            limit = user_monthly
        if limit is not None and count >= limit:
            scope_label = "per-user" if spec["scope"] == "user" else "global"
            return (
                True,
                f"{scope_label} {spec['window_kind']} aggregate limit {limit} reached at count {count}",
            )
    return False, None


__all__ = ["guard_call", "is_provider_over_budget"]
