"""Pure Stripe Subscription-to-commercial lifecycle policy."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, model_validator

from ..agreements import AgreementState
from ..models import StrictCommercialModel
from .stripe_projection_provider import StripeSubscriptionSnapshot


class StripeSubscriptionLifecycleError(ValueError):
    """A normalized Subscription fact cannot safely drive local lifecycle."""


class StripeSubscriptionLifecycleDecision(StrictCommercialModel):
    target_state: AgreementState | None
    reconcile_period: bool
    cancel_at_period_end: bool | None = None
    current_period_start_at: AwareDatetime | None = None
    current_period_end_at: AwareDatetime | None = None
    trial_end_at: AwareDatetime | None = None
    canceled_at: AwareDatetime | None = None
    reproject_entitlements: bool
    reason_code: Literal[
        "stripe.subscription.noop",
        "stripe.subscription.trial_started",
        "stripe.subscription.period_reconciled",
        "stripe.subscription.degraded",
        "stripe.subscription.unpaid",
        "stripe.subscription.paused",
        "stripe.subscription.terminal",
        "stripe.subscription.awaiting_payment",
    ]

    @model_validator(mode="after")
    def _coherent_authority(self) -> "StripeSubscriptionLifecycleDecision":
        period_values = (
            self.cancel_at_period_end,
            self.current_period_start_at,
            self.current_period_end_at,
        )
        if self.reconcile_period != all(value is not None for value in period_values):
            raise ValueError("Lifecycle period authority is incomplete")
        if not self.reconcile_period and any(
            value is not None for value in (*period_values, self.trial_end_at)
        ):
            raise ValueError("Non-reconciling decision carries period authority")
        if (self.target_state == AgreementState.CANCELED) != (self.canceled_at is not None):
            raise ValueError("Canceled lifecycle decision requires its boundary")
        if self.reason_code in {
            "stripe.subscription.noop",
            "stripe.subscription.awaiting_payment",
        } and (
            self.target_state is not None
            or self.reconcile_period
            or self.reproject_entitlements
        ):
            raise ValueError("Non-authorizing lifecycle decision has side effects")
        return self


_TERMINAL = frozenset({AgreementState.CANCELED, AgreementState.EXPIRED})
_ENTITLEMENT_BEARING = frozenset(
    {
        AgreementState.TRIALING,
        AgreementState.ACTIVE,
        AgreementState.PAST_DUE,
        AgreementState.GRACE,
        AgreementState.PAUSED,
    }
)
def _decision(
    *,
    target_state: AgreementState | None,
    snapshot: StripeSubscriptionSnapshot,
    reconcile_period: bool,
    reason_code: str,
    reproject_entitlements: bool,
) -> StripeSubscriptionLifecycleDecision:
    return StripeSubscriptionLifecycleDecision(
        target_state=target_state,
        reconcile_period=reconcile_period,
        cancel_at_period_end=(snapshot.cancel_at_period_end if reconcile_period else None),
        current_period_start_at=(snapshot.current_period_start_at if reconcile_period else None),
        current_period_end_at=(snapshot.current_period_end_at if reconcile_period else None),
        trial_end_at=(snapshot.trial_end if reconcile_period else None),
        canceled_at=(
            snapshot.canceled_at or snapshot.ended_at
            if target_state == AgreementState.CANCELED
            else None
        ),
        reproject_entitlements=reproject_entitlements,
        reason_code=reason_code,
    )


def decide_stripe_subscription_lifecycle(
    *,
    local_state: AgreementState,
    snapshot: StripeSubscriptionSnapshot,
    evaluated_at: datetime,
) -> StripeSubscriptionLifecycleDecision:
    """Map provider state without ever treating ``active`` as payment evidence."""

    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise StripeSubscriptionLifecycleError("Lifecycle evaluation time must be aware")
    if snapshot.authoritative_fetched_at > evaluated_at:
        raise StripeSubscriptionLifecycleError("Subscription fact follows evaluation time")
    if local_state in _TERMINAL:
        return _decision(
            target_state=None, snapshot=snapshot, reconcile_period=False,
            reason_code="stripe.subscription.noop", reproject_entitlements=False,
        )

    provider_state = snapshot.status
    if snapshot.collection_paused and provider_state in {
        "active", "trialing", "past_due", "paused"
    }:
        provider_state = "paused"
    if provider_state in {"active", "trialing", "past_due", "unpaid", "paused"} and (
        snapshot.current_period_start_at > evaluated_at
        or snapshot.current_period_end_at <= evaluated_at
    ):
        raise StripeSubscriptionLifecycleError(
            "Subscription service period does not contain evaluation time"
        )
    if provider_state == "trialing":
        if (
            snapshot.trial_start is None
            or snapshot.trial_start > evaluated_at
            or snapshot.trial_end is None
            or snapshot.trial_end <= evaluated_at
        ):
            raise StripeSubscriptionLifecycleError("Subscription trial boundary is invalid")
        target = (
            AgreementState.TRIALING
            if local_state == AgreementState.PENDING_PAYMENT
            else None
        )
        reconcile = local_state == AgreementState.TRIALING or target is not None
        return _decision(
            target_state=target, snapshot=snapshot, reconcile_period=reconcile,
            reason_code="stripe.subscription.trial_started" if target else "stripe.subscription.period_reconciled",
            reproject_entitlements=target is not None or reconcile,
        )

    if provider_state == "active":
        # Subscription activity is not proof that the invoice/payment succeeded.
        if local_state != AgreementState.ACTIVE:
            return _decision(
                target_state=None, snapshot=snapshot, reconcile_period=False,
                reason_code="stripe.subscription.awaiting_payment",
                reproject_entitlements=False,
            )
        return _decision(
            target_state=None, snapshot=snapshot, reconcile_period=True,
            reason_code="stripe.subscription.period_reconciled",
            reproject_entitlements=True,
        )

    if provider_state == "past_due":
        target = (
            AgreementState.PAST_DUE
            if local_state == AgreementState.ACTIVE
            else AgreementState.EXPIRED
            if local_state == AgreementState.TRIALING
            else None
        )
        reconcile = local_state in _ENTITLEMENT_BEARING
        return _decision(
            target_state=target, snapshot=snapshot, reconcile_period=reconcile,
            reason_code="stripe.subscription.degraded",
            reproject_entitlements=target is not None or reconcile,
        )

    if provider_state == "unpaid":
        if local_state in {
            AgreementState.PENDING_PAYMENT,
            AgreementState.TRIALING,
            AgreementState.DRAFT,
        }:
            target = AgreementState.EXPIRED
        elif local_state in {
            AgreementState.ACTIVE,
            AgreementState.PAST_DUE,
            AgreementState.GRACE,
        }:
            target = AgreementState.PAUSED
        else:
            target = None
        return _decision(
            target_state=target, snapshot=snapshot, reconcile_period=False,
            reason_code="stripe.subscription.unpaid",
            reproject_entitlements=local_state in _ENTITLEMENT_BEARING,
        )

    if provider_state == "paused":
        target = (
            AgreementState.PAUSED
            if local_state in {
                AgreementState.ACTIVE,
                AgreementState.PAST_DUE,
                AgreementState.GRACE,
            }
            else AgreementState.EXPIRED
            if local_state == AgreementState.TRIALING
            else None
        )
        reconcile = local_state in _ENTITLEMENT_BEARING
        return _decision(
            target_state=target, snapshot=snapshot, reconcile_period=reconcile,
            reason_code="stripe.subscription.paused",
            reproject_entitlements=target is not None or reconcile,
        )

    if provider_state in {"canceled", "incomplete_expired"}:
        target = (
            AgreementState.EXPIRED
            if local_state == AgreementState.PENDING_PAYMENT
            or provider_state == "incomplete_expired"
            else AgreementState.CANCELED
        )
        if target == AgreementState.CANCELED and (
            snapshot.canceled_at is None and snapshot.ended_at is None
        ):
            raise StripeSubscriptionLifecycleError(
                "Canceled Subscription boundary is missing"
            )
        terminal_boundary = snapshot.canceled_at or snapshot.ended_at
        if terminal_boundary is not None and terminal_boundary > evaluated_at:
            raise StripeSubscriptionLifecycleError(
                "Canceled Subscription boundary follows evaluation time"
            )
        return _decision(
            target_state=target, snapshot=snapshot, reconcile_period=True,
            reason_code="stripe.subscription.terminal",
            reproject_entitlements=local_state in _ENTITLEMENT_BEARING,
        )

    if provider_state == "incomplete":
        return _decision(
            target_state=None, snapshot=snapshot, reconcile_period=False,
            reason_code="stripe.subscription.awaiting_payment",
            reproject_entitlements=False,
        )
    raise StripeSubscriptionLifecycleError("Subscription status is unsupported")


__all__ = [
    "StripeSubscriptionLifecycleDecision",
    "StripeSubscriptionLifecycleError",
    "decide_stripe_subscription_lifecycle",
]
