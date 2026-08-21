"""Pure paid-activation and payment-failure policy for Stripe invoice authority."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from ..agreements import AgreementState
from ..models import StrictCommercialModel
from .stripe_projection_provider import (
    StripeInvoiceSnapshot,
    StripeSubscriptionSnapshot,
)


class StripeInvoiceLifecycleError(ValueError):
    """Invoice/subscription facts cannot safely drive agreement lifecycle."""


class StripeInvoiceCashReceiptEvidence(StrictCommercialModel):
    invoice_effect_id: int = Field(gt=0)
    external_invoice_id: str = Field(pattern=r"^in_[A-Za-z0-9]+$")
    external_invoice_payment_id: str = Field(min_length=5, max_length=255)
    external_payment_intent_id: str = Field(pattern=r"^pi_[A-Za-z0-9]+$")
    amount_paid_cents: int = Field(gt=0)
    paid_at: AwareDatetime
    snapshot_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class StripeInvoiceLifecycleDecision(StrictCommercialModel):
    target_state: AgreementState | None
    reconcile_subscription_period: bool
    reproject_entitlements: bool
    reason_code: Literal[
        "stripe.invoice.noop",
        "stripe.invoice.awaiting_cash",
        "stripe.invoice.activated",
        "stripe.invoice.period_reconciled",
        "stripe.invoice.payment_failed",
        "stripe.invoice.failure_superseded",
    ]

    @model_validator(mode="after")
    def _coherent(self) -> "StripeInvoiceLifecycleDecision":
        expected = {
            "stripe.invoice.noop": (None, False, False),
            "stripe.invoice.awaiting_cash": (None, False, False),
            "stripe.invoice.failure_superseded": (None, False, False),
            "stripe.invoice.activated": (AgreementState.ACTIVE, True, True),
            "stripe.invoice.period_reconciled": (None, True, True),
            "stripe.invoice.payment_failed": (AgreementState.PAST_DUE, False, True),
        }[self.reason_code]
        if (
            self.target_state,
            self.reconcile_subscription_period,
            self.reproject_entitlements,
        ) != expected:
            raise ValueError("invoice lifecycle decision does not match its reason")
        return self


_TERMINAL = frozenset({AgreementState.CANCELED, AgreementState.EXPIRED})
_ACTIVATABLE = frozenset({
    AgreementState.PENDING_PAYMENT,
    AgreementState.TRIALING,
    AgreementState.PAST_DUE,
    AgreementState.GRACE,
    AgreementState.PAUSED,
})


def _noop(reason_code="stripe.invoice.noop"):
    return StripeInvoiceLifecycleDecision(
        target_state=None,
        reconcile_subscription_period=False,
        reproject_entitlements=False,
        reason_code=reason_code,
    )


def _validate_lineage(
    invoice: StripeInvoiceSnapshot,
    subscription: StripeSubscriptionSnapshot,
) -> None:
    if (
        invoice.environment != subscription.environment
        or invoice.external_subscription_id != subscription.external_object_id
        or invoice.external_customer_id != subscription.external_customer_id
        or invoice.commercial_account_public_id
        != subscription.commercial_account_public_id
        or invoice.agreement_public_id != subscription.agreement_public_id
        or invoice.subscription_price_code != subscription.price_code
        or subscription.latest_invoice_id != invoice.external_object_id
    ):
        raise StripeInvoiceLifecycleError(
            "Invoice and Subscription authority lineage does not match"
        )


def _require_current_active_subscription(
    subscription: StripeSubscriptionSnapshot, evaluated_at: datetime
) -> None:
    if (
        subscription.status != "active"
        or subscription.collection_paused
        or subscription.current_period_start_at > evaluated_at
        or subscription.current_period_end_at <= evaluated_at
    ):
        raise StripeInvoiceLifecycleError(
            "Paid activation requires a current active Subscription"
        )


def decide_stripe_invoice_lifecycle(
    *,
    local_state: AgreementState,
    invoice_event_type: str,
    invoice: StripeInvoiceSnapshot,
    subscription: StripeSubscriptionSnapshot,
    expected_invoice_effect_id: int,
    cash_receipts: tuple[StripeInvoiceCashReceiptEvidence, ...],
    evaluated_at: datetime,
) -> StripeInvoiceLifecycleDecision:
    """Authorize paid activation or immediate payment-failure degradation."""

    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise StripeInvoiceLifecycleError("Invoice evaluation time must be aware")
    if isinstance(expected_invoice_effect_id, bool) or expected_invoice_effect_id <= 0:
        raise StripeInvoiceLifecycleError("Invoice effect identity is invalid")
    if (
        invoice.authoritative_fetched_at > evaluated_at
        or subscription.authoritative_fetched_at > evaluated_at
    ):
        raise StripeInvoiceLifecycleError("Provider authority follows evaluation time")
    _validate_lineage(invoice, subscription)
    if local_state in _TERMINAL:
        return _noop()

    if invoice_event_type == "invoice.paid":
        if invoice.status != "paid":
            raise StripeInvoiceLifecycleError("Paid event lacks paid Invoice authority")
        normalized_cash = any(
            payment.status == "paid" and (payment.amount_paid_cents or 0) > 0
            for payment in invoice.payments
        )
        if not cash_receipts or not normalized_cash:
            return _noop("stripe.invoice.awaiting_cash")
        normalized = {
            (
                payment.external_invoice_payment_id,
                payment.external_payment_intent_id,
                payment.amount_paid_cents,
                payment.paid_at,
            )
            for payment in invoice.payments
            if payment.status == "paid" and (payment.amount_paid_cents or 0) > 0
        }
        durable = {
            (
                receipt.external_invoice_payment_id,
                receipt.external_payment_intent_id,
                receipt.amount_paid_cents,
                receipt.paid_at,
            )
            for receipt in cash_receipts
        }
        if (
            len(durable) != len(cash_receipts)
            or normalized != durable
            or any(
                receipt.external_invoice_id != invoice.external_object_id
                or receipt.snapshot_sha256 != invoice.snapshot_sha256
                or receipt.invoice_effect_id != expected_invoice_effect_id
                or receipt.paid_at > invoice.authoritative_fetched_at
                or receipt.paid_at > evaluated_at
                for receipt in cash_receipts
            )
        ):
            raise StripeInvoiceLifecycleError(
                "Durable cash receipt does not match Invoice authority"
            )
        _require_current_active_subscription(subscription, evaluated_at)
        if local_state in _ACTIVATABLE:
            return StripeInvoiceLifecycleDecision(
                target_state=AgreementState.ACTIVE,
                reconcile_subscription_period=True,
                reproject_entitlements=True,
                reason_code="stripe.invoice.activated",
            )
        if local_state == AgreementState.ACTIVE:
            return StripeInvoiceLifecycleDecision(
                target_state=None,
                reconcile_subscription_period=True,
                reproject_entitlements=True,
                reason_code="stripe.invoice.period_reconciled",
            )
        return _noop()

    if invoice_event_type in {
        "invoice.payment_failed",
        "invoice.payment_action_required",
    }:
        if invoice.status != "open":
            return _noop("stripe.invoice.failure_superseded")
        if cash_receipts:
            raise StripeInvoiceLifecycleError(
                "Open failed Invoice conflicts with durable cash receipt"
            )
        if local_state == AgreementState.ACTIVE:
            return StripeInvoiceLifecycleDecision(
                target_state=AgreementState.PAST_DUE,
                reconcile_subscription_period=False,
                reproject_entitlements=True,
                reason_code="stripe.invoice.payment_failed",
            )
        return _noop()

    return _noop()


__all__ = [
    "StripeInvoiceCashReceiptEvidence",
    "StripeInvoiceLifecycleDecision",
    "StripeInvoiceLifecycleError",
    "decide_stripe_invoice_lifecycle",
]
