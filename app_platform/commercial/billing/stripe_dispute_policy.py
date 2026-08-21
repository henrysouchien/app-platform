"""Pure Stripe Dispute cash-hold and access-suspension policy."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from ..agreements import AgreementState
from ..models import MAX_SIGNED_BIGINT, SignedBigInt, StrictCommercialModel
from .stripe_projection_provider import StripeDisputeSnapshot


STRIPE_DISPUTE_EFFECT_POLICY_VERSION = "stripe-dispute-effect.v1"
PositiveBigInt = Annotated[StrictInt, Field(gt=0, le=MAX_SIGNED_BIGINT)]
DisputeMovementKind = Literal["dispute_hold", "dispute_release"]
DisputeEventType = Literal[
    "charge.dispute.created",
    "charge.dispute.updated",
    "charge.dispute.closed",
    "charge.dispute.funds_withdrawn",
    "charge.dispute.funds_reinstated",
]
DisputeStatus = Literal[
    "lost",
    "needs_response",
    "prevented",
    "under_review",
    "warning_closed",
    "warning_needs_response",
    "warning_under_review",
    "won",
]


class StripeDisputePolicyError(ValueError):
    """Dispute authority cannot safely drive cash or access effects."""


class StripeDisputePaymentEvidence(StrictCommercialModel):
    external_payment_intent_id: str = Field(pattern=r"^pi_[A-Za-z0-9]+$")
    external_charge_id: str = Field(pattern=r"^ch_[A-Za-z0-9]+$")
    amount_paid_cents: PositiveBigInt
    currency: Literal["USD"]
    paid_at: AwareDatetime


class StripePriorDisputeMovement(StrictCommercialModel):
    movement_kind: DisputeMovementKind
    signed_amount_cents: SignedBigInt
    occurred_at: AwareDatetime

    @model_validator(mode="after")
    def _signed_kind(self) -> "StripePriorDisputeMovement":
        if (self.movement_kind == "dispute_hold") != (self.signed_amount_cents < 0):
            raise ValueError("Dispute movement sign does not match its kind")
        if self.signed_amount_cents == 0:
            raise ValueError("Dispute movement cannot be zero")
        return self


class StripeDisputeEffectDecision(StrictCommercialModel):
    event_type: DisputeEventType
    provider_status: DisputeStatus
    movement_kind: DisputeMovementKind | None = None
    signed_amount_cents: SignedBigInt | None = None
    occurred_at: AwareDatetime | None = None
    target_state: AgreementState | None = None
    reproject_entitlements: StrictBool
    operator_review_required: StrictBool
    policy_version: Literal["stripe-dispute-effect.v1"] = (
        STRIPE_DISPUTE_EFFECT_POLICY_VERSION
    )
    reason_code: Literal[
        "stripe.dispute.observed",
        "stripe.dispute.review_required",
        "stripe.dispute.access_suspended",
        "stripe.dispute.funds_withdrawn",
        "stripe.dispute.funds_reinstated",
        "stripe.dispute.won",
        "stripe.dispute.lost",
        "stripe.dispute.warning_closed",
    ]

    @model_validator(mode="after")
    def _coherent(self) -> "StripeDisputeEffectDecision":
        movement_values = (
            self.movement_kind,
            self.signed_amount_cents,
            self.occurred_at,
        )
        has_any_movement = any(value is not None for value in movement_values)
        has_all_movement = all(value is not None for value in movement_values)
        if has_any_movement != has_all_movement:
            raise ValueError("Dispute decision movement evidence is incomplete")
        if (
            has_all_movement
            and self.movement_kind == "dispute_hold"
            and self.signed_amount_cents >= 0
        ):
            raise ValueError("Dispute hold must be negative")
        if (
            has_all_movement
            and self.movement_kind == "dispute_release"
            and self.signed_amount_cents <= 0
        ):
            raise ValueError("Dispute release must be positive")
        if (self.target_state is not None) != self.reproject_entitlements:
            raise ValueError("Dispute access decision is incomplete")
        allowed_targets = {
            "lost": {None, AgreementState.PAUSED},
            "needs_response": {None, AgreementState.PAUSED},
            "prevented": {None, AgreementState.ACTIVE},
            "under_review": {None, AgreementState.PAUSED},
            "warning_closed": {None},
            "warning_needs_response": {None, AgreementState.PAUSED},
            "warning_under_review": {None, AgreementState.PAUSED},
            "won": {None, AgreementState.ACTIVE},
        }[self.provider_status]
        if self.target_state not in allowed_targets:
            raise ValueError("Dispute target state does not match provider status")
        expected_review = (
            self.provider_status in _ACTIVE_REVIEW_STATUSES
            or self.provider_status == "lost"
        )
        if self.operator_review_required != expected_review:
            raise ValueError("Dispute review flag does not match provider status")
        expected_reason = {
            "dispute_hold": "stripe.dispute.funds_withdrawn",
            "dispute_release": "stripe.dispute.funds_reinstated",
        }.get(self.movement_kind)
        if expected_reason is None:
            if self.target_state == AgreementState.PAUSED:
                expected_reason = "stripe.dispute.access_suspended"
            elif self.target_state == AgreementState.ACTIVE:
                expected_reason = "stripe.dispute.won"
            elif self.provider_status == "lost":
                expected_reason = "stripe.dispute.lost"
            elif self.provider_status == "warning_closed":
                expected_reason = "stripe.dispute.warning_closed"
            elif expected_review:
                expected_reason = "stripe.dispute.review_required"
            else:
                expected_reason = "stripe.dispute.observed"
        if self.reason_code != expected_reason:
            raise ValueError("Dispute decision does not match its reason")
        if (
            self.movement_kind == "dispute_hold"
            and self.event_type != "charge.dispute.funds_withdrawn"
        ):
            raise ValueError("Dispute hold event does not match")
        if (
            self.movement_kind == "dispute_release"
            and self.event_type != "charge.dispute.funds_reinstated"
        ):
            raise ValueError("Dispute release event does not match")
        return self


_ACTIVE_REVIEW_STATUSES = frozenset(
    {
        "needs_response",
        "under_review",
        "warning_needs_response",
        "warning_under_review",
    }
)
_SUSPENDABLE_STATES = frozenset(
    {
        AgreementState.ACTIVE,
        AgreementState.PAST_DUE,
        AgreementState.GRACE,
    }
)
_EVENT_TYPES = frozenset(
    {
        "charge.dispute.created",
        "charge.dispute.updated",
        "charge.dispute.closed",
        "charge.dispute.funds_withdrawn",
        "charge.dispute.funds_reinstated",
    }
)


def decide_stripe_dispute_effect(
    *,
    local_state: AgreementState,
    event_type: DisputeEventType,
    event_created_at: datetime,
    snapshot: StripeDisputeSnapshot,
    payment: StripeDisputePaymentEvidence,
    prior_movements: tuple[StripePriorDisputeMovement, ...],
    paused_by_this_dispute: bool,
    evaluated_at: datetime,
) -> StripeDisputeEffectDecision:
    """Authorize one cash transition and conservative access transition."""

    if not isinstance(paused_by_this_dispute, bool):
        raise StripeDisputePolicyError("Dispute pause provenance must be boolean")
    if event_type not in _EVENT_TYPES:
        raise StripeDisputePolicyError("Dispute event type is unsupported")
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise StripeDisputePolicyError("Dispute evaluation time must be aware")
    if event_created_at.tzinfo is None or event_created_at.utcoffset() is None:
        raise StripeDisputePolicyError("Dispute event time must be aware")
    if snapshot.authoritative_fetched_at > evaluated_at:
        raise StripeDisputePolicyError("Dispute authority follows evaluation time")
    if snapshot.amount_cents > MAX_SIGNED_BIGINT:
        raise StripeDisputePolicyError("Dispute amount exceeds signed BIGINT")
    if (
        snapshot.external_payment_intent_id != payment.external_payment_intent_id
        or snapshot.external_charge_id != payment.external_charge_id
        or snapshot.currency != payment.currency
    ):
        raise StripeDisputePolicyError("Dispute payment lineage does not match")
    if payment.paid_at > snapshot.provider_created_at:
        raise StripeDisputePolicyError("Dispute predates its payment")
    if not (
        snapshot.provider_created_at
        <= event_created_at
        <= snapshot.authoritative_fetched_at
        <= evaluated_at
    ):
        raise StripeDisputePolicyError("Dispute event chronology is invalid")
    if snapshot.amount_cents > payment.amount_paid_cents:
        raise StripeDisputePolicyError("Dispute amount exceeds the payment")

    holds = tuple(
        item for item in prior_movements if item.movement_kind == "dispute_hold"
    )
    releases = tuple(
        item for item in prior_movements if item.movement_kind == "dispute_release"
    )
    if len(holds) > 1 or len(releases) > 1:
        raise StripeDisputePolicyError("Dispute movement evidence is duplicated")
    if any(
        item.occurred_at < snapshot.provider_created_at
        or item.occurred_at < payment.paid_at
        or item.occurred_at > evaluated_at
        for item in prior_movements
    ):
        raise StripeDisputePolicyError("Dispute movement chronology is invalid")
    if releases and not holds:
        raise StripeDisputePolicyError("Dispute release lacks a prior hold")
    if holds and -holds[0].signed_amount_cents != snapshot.amount_cents:
        raise StripeDisputePolicyError("Dispute hold amount does not match")
    if releases and releases[0].signed_amount_cents != snapshot.amount_cents:
        raise StripeDisputePolicyError("Dispute release amount does not match")
    if holds and releases and releases[0].occurred_at < holds[0].occurred_at:
        raise StripeDisputePolicyError("Dispute release predates its hold")

    movement_kind = None
    signed_amount_cents = None
    reason_code = "stripe.dispute.observed"
    if event_type == "charge.dispute.funds_withdrawn" and not holds:
        movement_kind = "dispute_hold"
        signed_amount_cents = -snapshot.amount_cents
        reason_code = "stripe.dispute.funds_withdrawn"
    elif event_type == "charge.dispute.funds_reinstated" and not releases:
        if not holds:
            raise StripeDisputePolicyError("Dispute reinstatement lacks a hold")
        if holds[0].occurred_at > event_created_at:
            raise StripeDisputePolicyError("Dispute reinstatement predates its hold")
        movement_kind = "dispute_release"
        signed_amount_cents = snapshot.amount_cents
        reason_code = "stripe.dispute.funds_reinstated"

    target_state = None
    review_required = (
        snapshot.status in _ACTIVE_REVIEW_STATUSES or snapshot.status == "lost"
    )
    if (
        snapshot.status in _ACTIVE_REVIEW_STATUSES | {"lost"}
        and local_state in _SUSPENDABLE_STATES
    ):
        target_state = AgreementState.PAUSED
        if movement_kind is None:
            reason_code = "stripe.dispute.access_suspended"
    elif snapshot.status in {"won", "prevented"} and (
        local_state == AgreementState.PAUSED and paused_by_this_dispute
    ):
        target_state = AgreementState.ACTIVE
        if movement_kind is None:
            reason_code = "stripe.dispute.won"
    elif snapshot.status in {"lost", "warning_closed"} and movement_kind is None:
        reason_code = (
            "stripe.dispute.lost"
            if snapshot.status == "lost"
            else "stripe.dispute.warning_closed"
        )
    elif review_required and movement_kind is None:
        reason_code = "stripe.dispute.review_required"

    return StripeDisputeEffectDecision(
        event_type=event_type,
        provider_status=snapshot.status,
        movement_kind=movement_kind,
        signed_amount_cents=signed_amount_cents,
        occurred_at=event_created_at if movement_kind is not None else None,
        target_state=target_state,
        reproject_entitlements=target_state is not None,
        operator_review_required=review_required,
        reason_code=reason_code,
    )


__all__ = [
    "STRIPE_DISPUTE_EFFECT_POLICY_VERSION",
    "StripeDisputeEffectDecision",
    "StripeDisputePaymentEvidence",
    "StripeDisputePolicyError",
    "StripePriorDisputeMovement",
    "decide_stripe_dispute_effect",
]
