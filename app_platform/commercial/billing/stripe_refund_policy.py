"""Pure Stripe Refund-to-signed-cash-movement policy."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from ..models import MAX_SIGNED_BIGINT, SignedBigInt, StrictCommercialModel
from .stripe_projection_provider import StripeRefundSnapshot


STRIPE_REFUND_EFFECT_POLICY_VERSION = "stripe-refund-effect.v1"
PositiveBigInt = Annotated[StrictInt, Field(gt=0, le=MAX_SIGNED_BIGINT)]


class StripeRefundPolicyError(ValueError):
    """Refund authority cannot safely produce a financial effect."""


class StripeRefundPaymentEvidence(StrictCommercialModel):
    external_payment_intent_id: str = Field(pattern=r"^pi_[A-Za-z0-9]+$")
    external_charge_id: str = Field(pattern=r"^ch_[A-Za-z0-9]+$")
    amount_paid_cents: PositiveBigInt
    currency: Literal["USD"]
    paid_at: AwareDatetime


class StripePriorRefundMovement(StrictCommercialModel):
    external_refund_id: str = Field(pattern=r"^re_[A-Za-z0-9]+$")
    external_payment_intent_id: str = Field(pattern=r"^pi_[A-Za-z0-9]+$")
    external_charge_id: str = Field(pattern=r"^ch_[A-Za-z0-9]+$")
    signed_amount_cents: SignedBigInt = Field(lt=0)
    currency: Literal["USD"]
    occurred_at: AwareDatetime


class StripeRefundEffectDecision(StrictCommercialModel):
    append_refund_movement: StrictBool
    signed_amount_cents: SignedBigInt | None = Field(default=None, lt=0)
    occurred_at: AwareDatetime | None = None
    policy_version: Literal["stripe-refund-effect.v1"] = (
        STRIPE_REFUND_EFFECT_POLICY_VERSION
    )
    reason_code: Literal[
        "stripe.refund.pending",
        "stripe.refund.requires_action",
        "stripe.refund.failed",
        "stripe.refund.canceled",
        "stripe.refund.succeeded",
    ]

    @model_validator(mode="after")
    def _coherent(self) -> "StripeRefundEffectDecision":
        carries_effect = (
            self.signed_amount_cents is not None and self.occurred_at is not None
        )
        if self.append_refund_movement != carries_effect:
            raise ValueError("Refund decision effect evidence is incomplete")
        if self.append_refund_movement != (
            self.reason_code == "stripe.refund.succeeded"
        ):
            raise ValueError("Refund decision does not match its reason")
        return self


def _noop(status: Literal["pending", "requires_action", "failed", "canceled"]):
    return StripeRefundEffectDecision(
        append_refund_movement=False,
        reason_code=f"stripe.refund.{status}",
    )


def validate_stripe_refund_evaluation(
    snapshot: StripeRefundSnapshot, evaluated_at: datetime
) -> None:
    """Validate time-local authority before any new or aliased Refund effect."""

    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise StripeRefundPolicyError("Refund evaluation time must be aware")
    if snapshot.authoritative_fetched_at > evaluated_at:
        raise StripeRefundPolicyError("Refund authority follows evaluation time")


def decide_stripe_refund_effect(
    *,
    snapshot: StripeRefundSnapshot,
    payment: StripeRefundPaymentEvidence,
    prior_refunds: tuple[StripePriorRefundMovement, ...],
    evaluated_at: datetime,
) -> StripeRefundEffectDecision:
    """Authorize one immutable negative cash movement for a succeeded Refund."""

    validate_stripe_refund_evaluation(snapshot, evaluated_at)
    if (
        snapshot.external_payment_intent_id != payment.external_payment_intent_id
        or snapshot.external_charge_id != payment.external_charge_id
        or snapshot.currency != payment.currency
    ):
        raise StripeRefundPolicyError("Refund payment lineage does not match")
    if payment.paid_at > snapshot.provider_created_at:
        raise StripeRefundPolicyError("Refund predates its payment")
    if snapshot.amount_cents > MAX_SIGNED_BIGINT:
        raise StripeRefundPolicyError("Refund amount exceeds signed BIGINT")

    seen_refunds: set[str] = set()
    refunded_cents = 0
    for prior in prior_refunds:
        if prior.external_refund_id == snapshot.external_object_id:
            raise StripeRefundPolicyError("Current Refund already has a movement")
        if prior.external_refund_id in seen_refunds:
            raise StripeRefundPolicyError("Prior Refund evidence is duplicated")
        seen_refunds.add(prior.external_refund_id)
        if (
            prior.external_payment_intent_id != payment.external_payment_intent_id
            or prior.external_charge_id != payment.external_charge_id
            or prior.currency != payment.currency
            or prior.occurred_at < payment.paid_at
            or prior.occurred_at > evaluated_at
        ):
            raise StripeRefundPolicyError("Prior Refund payment lineage does not match")
        refunded_cents += -prior.signed_amount_cents

    if refunded_cents > payment.amount_paid_cents:
        raise StripeRefundPolicyError("Prior Refunds exceed the payment")
    if snapshot.status != "succeeded":
        return _noop(snapshot.status)
    if refunded_cents + snapshot.amount_cents > payment.amount_paid_cents:
        raise StripeRefundPolicyError("Refund total exceeds the payment")
    return StripeRefundEffectDecision(
        append_refund_movement=True,
        signed_amount_cents=-snapshot.amount_cents,
        occurred_at=snapshot.provider_created_at,
        reason_code="stripe.refund.succeeded",
    )


__all__ = [
    "STRIPE_REFUND_EFFECT_POLICY_VERSION",
    "StripePriorRefundMovement",
    "StripeRefundEffectDecision",
    "StripeRefundPaymentEvidence",
    "StripeRefundPolicyError",
    "decide_stripe_refund_effect",
    "validate_stripe_refund_evaluation",
]
