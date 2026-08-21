"""LLM usage adapters and cost estimation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class LLMUsage:
    input_tokens: int
    output_tokens: int
    model: str
    cache_creation_tokens: Optional[int] = None
    cache_read_tokens: Optional[int] = None
    is_batch: Optional[bool] = None


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def openai_usage(response: Any) -> LLMUsage:
    usage = getattr(response, "usage", None)
    return LLMUsage(
        input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
        output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
        model=str(getattr(response, "model", None) or ""),
    )


def anthropic_usage(response: Any) -> LLMUsage:
    """Extract Anthropic Message usage; batch callers must pass the inner Message."""
    usage = getattr(response, "usage", None)
    return LLMUsage(
        input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
        output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        model=str(getattr(response, "model", None) or ""),
        cache_creation_tokens=_safe_int(getattr(usage, "cache_creation_input_tokens", None)),
        cache_read_tokens=_safe_int(getattr(usage, "cache_read_input_tokens", None)),
        is_batch=(getattr(usage, "service_tier", None) == "batch"),
    )


def _default_llm_prices() -> Mapping[str, Mapping[str, float]]:
    from config.api_budget_costs import LLM_PRICES

    return LLM_PRICES


def lookup_model_pricing(
    model_name: str | None,
    prices: Mapping[str, Mapping[str, float]] | None = None,
) -> Mapping[str, float] | None:
    normalized_name = str(model_name or "").strip().lower()
    if not normalized_name:
        return None

    price_map = prices or _default_llm_prices()
    if normalized_name in price_map:
        return price_map[normalized_name]

    for candidate in sorted(price_map, key=len, reverse=True):
        if normalized_name.startswith(candidate.lower()):
            return price_map[candidate]
    return None


def estimate_cost_usd(
    usage: LLMUsage,
    prices: Mapping[str, Mapping[str, float]] | None = None,
) -> Decimal | None:
    pricing = lookup_model_pricing(usage.model, prices=prices)
    if pricing is None:
        return None

    cost = _calculate_cost_usd(usage, pricing)
    return cost.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)


def estimate_commercial_cost_usd(
    usage: LLMUsage,
    prices: Mapping[str, Mapping[str, float]] | None = None,
) -> Decimal | None:
    """Estimate at the commercial ledger's 8-decimal precision.

    Legacy API-budget reporting intentionally remains rounded to four decimals.
    """

    pricing = lookup_model_pricing(usage.model, prices=prices)
    if pricing is None:
        return None
    return _calculate_cost_usd(usage, pricing).quantize(
        Decimal("0.00000001"), rounding=ROUND_HALF_UP
    )


def _calculate_cost_usd(
    usage: LLMUsage, pricing: Mapping[str, float]
) -> Decimal:
    input_rate = Decimal(str(pricing["input_per_1m_tokens"]))
    output_rate = Decimal(str(pricing["output_per_1m_tokens"]))
    per_million = Decimal(1_000_000)
    cache_create = usage.cache_creation_tokens or 0
    cache_read = usage.cache_read_tokens or 0
    plain_input = usage.input_tokens
    cost = (
        Decimal(plain_input) / per_million * input_rate
        + Decimal(cache_create) / per_million * input_rate * Decimal("1.25")
        + Decimal(cache_read) / per_million * input_rate * Decimal("0.10")
        + Decimal(usage.output_tokens) / per_million * output_rate
    )
    if usage.is_batch:
        cost *= Decimal("0.5")
    return cost


__all__ = [
    "LLMUsage",
    "anthropic_usage",
    "estimate_commercial_cost_usd",
    "estimate_cost_usd",
    "lookup_model_pricing",
    "openai_usage",
]
