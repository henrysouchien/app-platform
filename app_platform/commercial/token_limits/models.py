"""Canonical entitlement-backed token-limit policy."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated
from uuid import UUID

from pydantic import Field, StrictInt

from ..entitlements import CanonicalEntitlementFact
from ..models import StrictCommercialModel


PositiveLimit = Annotated[StrictInt, Field(gt=0, le=2**52 - 1)]
_KEYS = {
    "limit:requests-per-minute": "requests_per_minute",
    "limit:requests-per-day": "requests_per_day",
    "limit:concurrent-workflows": "concurrent_workflows",
}


class TokenLimitPolicy(StrictCommercialModel):
    requests_per_minute: PositiveLimit
    requests_per_day: PositiveLimit
    concurrent_workflows: PositiveLimit


def resolve_token_limit_policy(
    facts: Iterable[CanonicalEntitlementFact], *, token_id: UUID
) -> TokenLimitPolicy:
    values: dict[str, int] = {}
    for fact in facts:
        field = _KEYS.get(fact.entitlement_key)
        if field is None:
            continue
        if fact.subject_mcp_token_id != token_id:
            continue
        if (
            fact.subject_kind != "mcp_token"
            or fact.effect != "limit"
            or isinstance(fact.value, bool)
            or not isinstance(fact.value, int)
            or fact.value <= 0
            or field in values
        ):
            raise ValueError("token limit authority is missing, duplicated, or malformed")
        values[field] = fact.value
    if set(values) != set(_KEYS.values()):
        raise ValueError("every token request and concurrency limit is required")
    return TokenLimitPolicy(**values)


__all__ = ["TokenLimitPolicy", "resolve_token_limit_policy"]
