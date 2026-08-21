"""Adapt successful non-LLM API-budget calls into canonical direct usage."""

from __future__ import annotations

from datetime import datetime, timezone
from collections.abc import Callable
from decimal import Decimal
from typing import Any, Literal

from config.api_budget_costs import (
    COST_PER_CALL,
    PROVIDER_WIDE_PER_CALL_RATES,
    SNAPTRADE_PER_CONNECTED_USER_MONTH_RATE,
    SNAPTRADE_SUBSCRIPTION_OPS,
    SUBSCRIPTION_COSTS_PER_ITEM_MONTH,
)

from ..models import canonical_sha256
from .direct import DirectUsageObservation, emit_bound_direct_usage


_LEGACY_OPERATION_CODES = {
    "cancelMktData": "cancel_mkt_data",
    "cancelOrder": "cancel_order",
    "cancelPnL": "cancel_pnl",
    "cancelPnLSingle": "cancel_pnl_single",
    "placeOrder": "place_order",
    "qualifyContracts": "qualify_contracts",
    "reqAccountUpdates": "req_account_updates",
    "reqPositions": "req_positions",
    "reqAccountSummary": "req_account_summary",
    "reqCompletedOrders": "req_completed_orders",
    "reqContractDetails": "req_contract_details",
    "reqHistoricalData": "req_historical_data",
    "reqMktData": "req_mkt_data",
    "reqPnL": "req_pnl",
    "reqPnLSingle": "req_pnl_single",
    "reqSecDefOptParams": "req_sec_def_opt_params",
    "whatIfOrder": "what_if_order",
}


def canonical_budget_operation(operation: str) -> str:
    raw = str(operation or "").strip()
    mapped = _LEGACY_OPERATION_CODES.get(raw, raw)
    if (
        not mapped
        or len(mapped) > 128
        or not mapped[0].isalpha()
        or any(
            char not in "abcdefghijklmnopqrstuvwxyz0123456789._:-" for char in mapped
        )
    ):
        raise ValueError("API budget operation has no approved commercial code mapping")
    return mapped


def api_budget_rate_version() -> str:
    payload = {
        "per_call": {
            f"{provider}:{operation}": str(rate)
            for (provider, operation), rate in sorted(COST_PER_CALL.items())
        },
        "provider_wide_per_call": {
            provider: str(rate)
            for provider, rate in sorted(PROVIDER_WIDE_PER_CALL_RATES.items())
        },
        "per_item_month": {
            f"{provider}:{operation}": str(rate)
            for (provider, operation), rate in sorted(
                SUBSCRIPTION_COSTS_PER_ITEM_MONTH.items()
            )
        },
        "snaptrade_connected_user_month": {
            "rate": str(SNAPTRADE_PER_CONNECTED_USER_MONTH_RATE),
            "operations": sorted(SNAPTRADE_SUBSCRIPTION_OPS),
        },
    }
    return "api-budget:" + canonical_sha256(payload)


def is_api_budget_rate_configured(provider: str, operation: str) -> bool:
    """Return true for configured rates, including intentional zero rates."""
    key = (str(provider or "").strip().lower(), str(operation or "").strip())
    return (
        key in COST_PER_CALL
        or key[0] in PROVIDER_WIDE_PER_CALL_RATES
        or key in SUBSCRIPTION_COSTS_PER_ITEM_MONTH
        or (key[0] == "snaptrade" and key[1] in SNAPTRADE_SUBSCRIPTION_OPS)
    )


def api_budget_failure_state(
    provider: str,
    operation: str,
) -> Literal["failed_billable", "failed_unbilled"] | None:
    """Resolve the reviewed failure policy for an exact priced operation.

    Positive per-call and monthly costs are treated conservatively as possibly
    billable after dispatch. Intentional zero-cost operations are unbilled.
    Unknown operations require an explicit caller decision.
    """
    provider_key = str(provider or "").strip().lower()
    operation_key = str(operation or "").strip()
    key = (provider_key, operation_key)
    if key in SUBSCRIPTION_COSTS_PER_ITEM_MONTH:
        return "failed_billable"
    if provider_key == "snaptrade" and operation_key in SNAPTRADE_SUBSCRIPTION_OPS:
        return "failed_billable"
    if key in COST_PER_CALL:
        return "failed_billable" if COST_PER_CALL[key] > 0 else "failed_unbilled"
    if provider_key in PROVIDER_WIDE_PER_CALL_RATES:
        return (
            "failed_billable"
            if PROVIDER_WIDE_PER_CALL_RATES[provider_key] > 0
            else "failed_unbilled"
        )
    return None


def api_budget_cost_provenance(
    *,
    provider: str,
    operation: str,
    estimated_cost_usd: Decimal | None,
    cost_per_call: Decimal | float | int | str | None = None,
    cost_fn: Callable[[Any], Any] | None = None,
    cost_model: str | None = None,
) -> str | None:
    """Identify the exact pricing input used for a producer estimate."""
    if estimated_cost_usd is None:
        return None
    if cost_model in {"per_item_month", "per_connected_user_month"}:
        return api_budget_rate_version()
    if cost_per_call is None and cost_fn is None:
        return api_budget_rate_version()
    if cost_per_call is not None:
        source = {
            "kind": "caller_cost_per_call",
            "value": str(Decimal(str(cost_per_call))),
        }
    else:
        source = {
            "kind": "caller_cost_fn",
            "module": getattr(cost_fn, "__module__", "<unknown>"),
            "qualname": getattr(cost_fn, "__qualname__", repr(cost_fn)),
        }
    return "api-budget-override:" + canonical_sha256(
        {
            "provider": str(provider or "").strip().lower(),
            "operation": canonical_budget_operation(operation),
            "estimated_cost_usd": str(estimated_cost_usd),
            "source": source,
        }
    )


def emit_api_budget_direct_usage(
    *,
    source_event_id: str,
    provider: str,
    operation: str,
    estimated_cost_usd: Decimal | None,
    usage_state: Literal[
        "succeeded", "failed_billable", "failed_unbilled", "canceled"
    ] = "succeeded",
    producer_rate_version: str | None = None,
) -> None:
    monetary_observation = estimated_cost_usd is not None
    emit_bound_direct_usage(
        DirectUsageObservation(
            source_event_id=source_event_id,
            occurred_at=datetime.now(timezone.utc),
            provider=str(provider or "").strip().lower(),
            operation=canonical_budget_operation(operation),
            usage_state=usage_state,
            provider_units=(
                Decimal("1")
                if usage_state in {"succeeded", "failed_billable"}
                else None
            ),
            producer_estimated_cost_usd=estimated_cost_usd,
            cost_observation_kind=(
                "producer_estimate" if monetary_observation else "unknown"
            ),
            producer_rate_version=(
                producer_rate_version if monetary_observation else None
            ),
        )
    )


__all__ = [
    "api_budget_rate_version",
    "api_budget_cost_provenance",
    "api_budget_failure_state",
    "canonical_budget_operation",
    "emit_api_budget_direct_usage",
    "is_api_budget_rate_configured",
]
