"""Canonical cost semantics without conflating estimates, cash, or shadow values."""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum

from pydantic import field_validator, model_validator

from .models import StrictCommercialModel
from .payer import PayerClass
from .rates import PricingState, validate_rate_decimal


_ZERO = Decimal("0")


class CostObservationKind(StrEnum):
    """Primary observation provenance; independent amount fields may coexist."""

    PRODUCER_ESTIMATE = "producer_estimate"
    PROVIDER_RESPONSE = "provider_response"
    UNKNOWN = "unknown"


class CostSemanticsInput(StrictCommercialModel):
    """Independent monetary observations used to derive reporting cost fields.

    ``cost_observation_kind`` identifies the primary event observation and therefore
    implies its matching amount. It does not claim other independently observed
    amounts are absent.
    """

    payer_class: PayerClass
    pricing_state: PricingState
    producer_estimated_cost_usd: Decimal | None = None
    provider_reported_cost_usd: Decimal | None = None
    cost_observation_kind: CostObservationKind = CostObservationKind.UNKNOWN
    direct_provider_origin_cost_usd: Decimal | None = None
    allocated_flat_provider_cash_cost_usd: Decimal | None = None
    normalized_shadow_cost_usd: Decimal | None = None

    @field_validator(
        "producer_estimated_cost_usd",
        "provider_reported_cost_usd",
        "direct_provider_origin_cost_usd",
        "allocated_flat_provider_cash_cost_usd",
        "normalized_shadow_cost_usd",
        mode="before",
    )
    @classmethod
    def _money_is_decimal(cls, value: object) -> Decimal | None:
        if value is None:
            return None
        return validate_rate_decimal(value, label="cost amount")

    @model_validator(mode="after")
    def _coherent_sources(self) -> "CostSemanticsInput":
        if (
            self.direct_provider_origin_cost_usd is not None
            and self.allocated_flat_provider_cash_cost_usd is not None
        ):
            raise ValueError("actual cash cost cannot have both direct and allocated sources")
        if (
            self.cost_observation_kind is CostObservationKind.PRODUCER_ESTIMATE
            and self.producer_estimated_cost_usd is None
        ):
            raise ValueError("producer estimate observation requires its monetary amount")
        if (
            self.cost_observation_kind is CostObservationKind.PROVIDER_RESPONSE
            and self.provider_reported_cost_usd is None
        ):
            raise ValueError("provider response observation requires its monetary amount")
        if self.pricing_state is PricingState.PRICED:
            if self.normalized_shadow_cost_usd is None:
                raise ValueError("priced usage requires normalized shadow cost")
        elif self.normalized_shadow_cost_usd is not None:
            raise ValueError("unknown-rate usage cannot assert normalized shadow cost")
        return self


class CanonicalCostSemantics(StrictCommercialModel):
    """Separated cost facts and the policy-derived bases used by controls and reports."""

    payer_class: PayerClass
    pricing_state: PricingState
    producer_estimated_cost_usd: Decimal | None
    provider_reported_cost_usd: Decimal | None
    cost_observation_kind: CostObservationKind
    actual_hank_cash_cost_usd: Decimal | None
    normalized_shadow_cost_usd: Decimal | None
    customer_cost_context_usd: Decimal | None
    management_model_cost_basis_usd: Decimal | None
    recognized_model_cogs_usd: Decimal


def calculate_cost_semantics(facts: CostSemanticsInput) -> CanonicalCostSemantics:
    """Apply the immutable payer and pricing rules from the commercial design."""

    actual = (
        facts.direct_provider_origin_cost_usd
        if facts.direct_provider_origin_cost_usd is not None
        else facts.allocated_flat_provider_cash_cost_usd
    )
    hank_responsible = facts.payer_class is not PayerClass.CUSTOMER_PAID

    if facts.pricing_state is PricingState.UNKNOWN_RATE:
        customer_context = None
        management_basis = None
    elif facts.payer_class is PayerClass.CUSTOMER_PAID:
        customer_context = facts.normalized_shadow_cost_usd
        management_basis = _ZERO
    else:
        customer_context = _ZERO
        management_basis = max(actual or _ZERO, facts.normalized_shadow_cost_usd or _ZERO)

    return CanonicalCostSemantics(
        payer_class=facts.payer_class,
        pricing_state=facts.pricing_state,
        producer_estimated_cost_usd=facts.producer_estimated_cost_usd,
        provider_reported_cost_usd=facts.provider_reported_cost_usd,
        cost_observation_kind=facts.cost_observation_kind,
        actual_hank_cash_cost_usd=actual,
        normalized_shadow_cost_usd=facts.normalized_shadow_cost_usd,
        customer_cost_context_usd=customer_context,
        management_model_cost_basis_usd=management_basis,
        recognized_model_cogs_usd=(actual or _ZERO) if hank_responsible else _ZERO,
    )
