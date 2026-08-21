"""Authoritative Stripe Checkout/subscription fetch and normalization boundary."""

from __future__ import annotations

from datetime import datetime, timezone
import re
import threading
from typing import Annotated, Any, Callable, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictInt, model_validator

from ..models import (
    MAX_SIGNED_BIGINT,
    NonNegativeBigInt,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)
from .checkout import BillingEnvironment
from .stripe_config import StripeDeploymentManifest


_CUSTOMER_ID = re.compile(r"^cus_[A-Za-z0-9]{6,250}$")
_CHECKOUT_ID = re.compile(r"^cs_(test|live)_[A-Za-z0-9]{1,247}$")
_SUBSCRIPTION_ID = re.compile(r"^sub_[A-Za-z0-9]{4,251}$")
_INVOICE_ID = re.compile(r"^in_[A-Za-z0-9]{5,252}$")
_INVOICE_LINE_ID = re.compile(r"^il_[A-Za-z0-9]{4,252}$")
_PAYMENT_INTENT_ID = re.compile(r"^pi_[A-Za-z0-9]{4,252}$")
_INVOICE_PAYMENT_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,254}$")
_REFUND_ID = re.compile(r"^re_[A-Za-z0-9]{4,252}$")
_CHARGE_ID = re.compile(r"^ch_[A-Za-z0-9]{4,252}$")
_DISPUTE_ID = re.compile(r"^dp_[A-Za-z0-9]{4,252}$")
_CREDIT_NOTE_ID = re.compile(r"^cn_[A-Za-z0-9]{4,252}$")
_CREDIT_NOTE_LINE_ID = re.compile(r"^cnli_[A-Za-z0-9]{4,250}$")
_CUSTOMER_BALANCE_TRANSACTION_ID = re.compile(r"^cbtxn_[A-Za-z0-9]{4,248}$")
PositiveBigInt = Annotated[StrictInt, Field(gt=0, le=MAX_SIGNED_BIGINT)]


class StripeProjectionProviderError(RuntimeError):
    """Safe normalization failure with no raw provider detail or exception chain."""


class StripeProjectionExpectation(StrictCommercialModel):
    environment: BillingEnvironment
    commercial_account_public_id: UUID
    agreement_public_id: UUID
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    price_code: StableCode


class StripeCheckoutSnapshot(StrictCommercialModel):
    object_type: Literal["checkout_session"] = "checkout_session"
    external_object_id: str = Field(pattern=r"^cs_(test|live)_[A-Za-z0-9]{1,247}$")
    environment: BillingEnvironment
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    external_subscription_id: str | None = Field(
        default=None, pattern=r"^sub_[A-Za-z0-9]{4,251}$"
    )
    commercial_account_public_id: UUID
    agreement_public_id: UUID
    price_code: StableCode
    stripe_price_id: str = Field(pattern=r"^price_[A-Za-z0-9]+$")
    status: Literal["open", "complete", "expired"]
    payment_status: Literal["no_payment_required", "paid", "unpaid"]
    provider_created_at: AwareDatetime
    checkout_expires_at: AwareDatetime
    authoritative_fetched_at: AwareDatetime
    snapshot_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _digest_matches(self) -> "StripeCheckoutSnapshot":
        if self.snapshot_sha256 != canonical_sha256(self.digest_body()):
            raise ValueError("Checkout snapshot digest does not match")
        if self.checkout_expires_at <= self.provider_created_at:
            raise ValueError("Checkout expiry must follow creation")
        if self.provider_created_at > self.authoritative_fetched_at:
            raise ValueError("Checkout creation follows authoritative fetch")
        return self

    def digest_body(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python",
            exclude={"snapshot_sha256", "authoritative_fetched_at"},
        )


class StripeSubscriptionSnapshot(StrictCommercialModel):
    object_type: Literal["subscription"] = "subscription"
    external_object_id: str = Field(pattern=r"^sub_[A-Za-z0-9]{4,251}$")
    environment: BillingEnvironment
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    commercial_account_public_id: UUID
    agreement_public_id: UUID
    price_code: StableCode
    stripe_price_id: str = Field(pattern=r"^price_[A-Za-z0-9]+$")
    status: Literal[
        "active",
        "canceled",
        "incomplete",
        "incomplete_expired",
        "past_due",
        "paused",
        "trialing",
        "unpaid",
    ]
    collection_method: Literal["charge_automatically"]
    cancel_at_period_end: bool
    cancel_at: AwareDatetime | None = None
    canceled_at: AwareDatetime | None = None
    ended_at: AwareDatetime | None = None
    trial_start: AwareDatetime | None = None
    trial_end: AwareDatetime | None = None
    current_period_start_at: AwareDatetime
    current_period_end_at: AwareDatetime
    latest_invoice_id: str | None = Field(
        default=None, pattern=r"^in_[A-Za-z0-9]{5,252}$"
    )
    collection_paused: bool
    provider_created_at: AwareDatetime
    authoritative_fetched_at: AwareDatetime
    snapshot_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _valid_snapshot(self) -> "StripeSubscriptionSnapshot":
        if self.snapshot_sha256 != canonical_sha256(self.digest_body()):
            raise ValueError("subscription snapshot digest does not match")
        if self.current_period_end_at <= self.current_period_start_at:
            raise ValueError("subscription period is invalid")
        if self.provider_created_at > self.authoritative_fetched_at:
            raise ValueError("subscription creation follows authoritative fetch")
        if (self.trial_start is None) != (self.trial_end is None):
            raise ValueError("subscription trial range is incomplete")
        if self.trial_end is not None and self.trial_end <= self.trial_start:
            raise ValueError("subscription trial range is invalid")
        return self

    def digest_body(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python",
            exclude={"snapshot_sha256", "authoritative_fetched_at"},
        )


class StripeInvoiceLineSnapshot(StrictCommercialModel):
    external_line_id: str = Field(pattern=r"^il_[A-Za-z0-9]{4,252}$")
    price_code: StableCode
    stripe_price_id: str = Field(pattern=r"^price_[A-Za-z0-9]+$")
    quantity: StrictInt = Field(gt=0)
    subtotal_cents: StrictInt
    discount_cents: StrictInt = Field(ge=0)
    pretax_credit_cents: StrictInt = Field(ge=0)
    net_consideration_ex_tax_cents: StrictInt
    tax_cents: StrictInt = Field(ge=0)
    service_period_start_at: AwareDatetime
    service_period_end_at: AwareDatetime
    parent_type: Literal["invoice_item_details", "subscription_item_details"]
    external_subscription_item_id: str | None = Field(
        default=None, pattern=r"^si_[A-Za-z0-9]{4,252}$"
    )
    proration: bool
    credited_invoice_id: str | None = Field(
        default=None, pattern=r"^in_[A-Za-z0-9]{5,252}$"
    )
    credited_line_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _valid_line(self) -> "StripeInvoiceLineSnapshot":
        if self.service_period_end_at < self.service_period_start_at:
            raise ValueError("invoice line service period is invalid")
        if self.pretax_credit_cents < self.discount_cents:
            raise ValueError("invoice line pretax credits omit discounts")
        if (
            self.net_consideration_ex_tax_cents
            != self.subtotal_cents - self.pretax_credit_cents
        ):
            raise ValueError("invoice line consideration does not reconcile")
        if self.parent_type == "subscription_item_details" and (
            self.external_subscription_item_id is None
        ):
            raise ValueError("subscription invoice line is missing its item identity")
        if (self.credited_invoice_id is None) != (not self.credited_line_ids):
            raise ValueError("credited line lineage is incomplete")
        if any(
            not _INVOICE_LINE_ID.fullmatch(value) for value in self.credited_line_ids
        ):
            raise ValueError("credited line identity is invalid")
        return self


class StripeInvoicePaymentSnapshot(StrictCommercialModel):
    external_invoice_payment_id: str = Field(min_length=5, max_length=255)
    external_payment_intent_id: str = Field(pattern=r"^pi_[A-Za-z0-9]{4,252}$")
    external_charge_id: str | None = Field(
        default=None, pattern=r"^ch_[A-Za-z0-9]{4,252}$"
    )
    status: Literal["open", "paid", "canceled"]
    amount_requested_cents: StrictInt = Field(ge=0)
    amount_paid_cents: StrictInt | None = Field(default=None, ge=0)
    provider_created_at: AwareDatetime
    paid_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _valid_payment(self) -> "StripeInvoicePaymentSnapshot":
        if self.status == "paid":
            if (
                self.amount_paid_cents is None
                or self.paid_at is None
                or self.external_charge_id is None
            ):
                raise ValueError("paid invoice payment lacks settlement evidence")
        elif (
            self.amount_paid_cents is not None
            or self.paid_at is not None
            or self.external_charge_id is not None
        ):
            raise ValueError("unpaid invoice payment carries settlement evidence")
        if (
            self.amount_paid_cents is not None
            and self.amount_paid_cents > self.amount_requested_cents
        ):
            raise ValueError("invoice payment exceeds its requested amount")
        return self


class StripeInvoiceSnapshot(StrictCommercialModel):
    object_type: Literal["invoice"] = "invoice"
    external_object_id: str = Field(pattern=r"^in_[A-Za-z0-9]{5,252}$")
    environment: BillingEnvironment
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    external_subscription_id: str = Field(pattern=r"^sub_[A-Za-z0-9]{4,251}$")
    commercial_account_public_id: UUID
    agreement_public_id: UUID
    subscription_price_code: StableCode
    status: Literal["draft", "open", "paid", "uncollectible", "void"]
    billing_reason: Literal[
        "subscription_create",
        "subscription_cycle",
        "subscription_threshold",
        "subscription_update",
    ]
    collection_method: Literal["charge_automatically"]
    currency: Literal["USD"]
    subtotal_cents: StrictInt
    discount_cents: StrictInt = Field(ge=0)
    pretax_credit_cents: StrictInt = Field(ge=0)
    net_consideration_ex_tax_cents: StrictInt
    tax_cents: StrictInt = Field(ge=0)
    total_cents: StrictInt
    amount_due_cents: StrictInt = Field(ge=0)
    amount_paid_cents: StrictInt = Field(ge=0)
    amount_remaining_cents: StrictInt = Field(ge=0)
    pre_payment_credit_note_cents: StrictInt = Field(ge=0)
    post_payment_credit_note_cents: StrictInt = Field(ge=0)
    lines: tuple[StripeInvoiceLineSnapshot, ...]
    payments: tuple[StripeInvoicePaymentSnapshot, ...]
    provider_created_at: AwareDatetime
    finalized_at: AwareDatetime | None = None
    paid_at: AwareDatetime | None = None
    voided_at: AwareDatetime | None = None
    marked_uncollectible_at: AwareDatetime | None = None
    authoritative_fetched_at: AwareDatetime
    snapshot_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _valid_invoice(self) -> "StripeInvoiceSnapshot":
        if self.snapshot_sha256 != canonical_sha256(self.digest_body()):
            raise ValueError("invoice snapshot digest does not match")
        if not self.lines or len({line.external_line_id for line in self.lines}) != len(
            self.lines
        ):
            raise ValueError("invoice lines are empty or duplicated")
        if len(
            {payment.external_invoice_payment_id for payment in self.payments}
        ) != len(self.payments):
            raise ValueError("invoice payments are duplicated")
        if len(
            {payment.external_payment_intent_id for payment in self.payments}
        ) != len(self.payments):
            raise ValueError("invoice payment intents are duplicated")
        if self.pretax_credit_cents < self.discount_cents:
            raise ValueError("invoice pretax credits omit discounts")
        if self.total_cents != self.net_consideration_ex_tax_cents + self.tax_cents:
            raise ValueError("invoice total does not reconcile")
        if (
            sum(line.net_consideration_ex_tax_cents for line in self.lines)
            != self.net_consideration_ex_tax_cents
        ):
            raise ValueError("invoice line consideration does not reconcile")
        if sum(line.discount_cents for line in self.lines) != self.discount_cents:
            raise ValueError("invoice line discounts do not reconcile")
        if (
            sum(line.pretax_credit_cents for line in self.lines)
            != self.pretax_credit_cents
        ):
            raise ValueError("invoice line pretax credits do not reconcile")
        if sum(line.tax_cents for line in self.lines) != self.tax_cents:
            raise ValueError("invoice line tax does not reconcile")
        if self.amount_remaining_cents != max(
            self.amount_due_cents - self.amount_paid_cents, 0
        ):
            raise ValueError("invoice balance does not reconcile")
        if self.provider_created_at > self.authoritative_fetched_at:
            raise ValueError("invoice creation follows authoritative fetch")
        if any(
            payment.provider_created_at > self.authoritative_fetched_at
            or payment.paid_at is not None
            and (
                payment.paid_at < payment.provider_created_at
                or payment.paid_at > self.authoritative_fetched_at
            )
            for payment in self.payments
        ):
            raise ValueError("invoice payment chronology is invalid")
        if any(
            value is not None and value > self.authoritative_fetched_at
            for value in (
                self.finalized_at,
                self.paid_at,
                self.voided_at,
                self.marked_uncollectible_at,
            )
        ):
            raise ValueError("invoice transition follows authoritative fetch")
        if (
            self.finalized_at is not None
            and self.finalized_at < self.provider_created_at
        ):
            raise ValueError("invoice finalization predates creation")
        if self.finalized_at is not None and any(
            value is not None and value < self.finalized_at
            for value in (
                self.paid_at,
                self.voided_at,
                self.marked_uncollectible_at,
            )
        ):
            raise ValueError("invoice terminal transition predates finalization")
        if self.finalized_at is not None and any(
            payment.provider_created_at < self.finalized_at for payment in self.payments
        ):
            raise ValueError("invoice payment predates finalization")
        settled_at = tuple(
            payment.paid_at
            for payment in self.payments
            if payment.status == "paid" and payment.paid_at is not None
        )
        if self.paid_at is not None and settled_at and self.paid_at < max(settled_at):
            raise ValueError("invoice paid transition predates payment settlement")
        terminal_transitions = {
            "paid": self.paid_at,
            "void": self.voided_at,
            "uncollectible": self.marked_uncollectible_at,
        }
        expected_transition = terminal_transitions.get(self.status)
        if self.status in terminal_transitions and expected_transition is None:
            raise ValueError("terminal invoice lacks matching transition evidence")
        if self.status == "paid" and self.amount_remaining_cents != 0:
            raise ValueError("paid invoice retains an outstanding balance")
        if (
            sum(
                payment.amount_paid_cents or 0
                for payment in self.payments
                if payment.status == "paid"
            )
            > self.amount_paid_cents
        ):
            raise ValueError("invoice payment allocations exceed paid amount")
        if self.status in {"draft", "open"} and any(terminal_transitions.values()):
            raise ValueError("nonterminal invoice carries terminal transition evidence")
        if self.status != "draft" and self.finalized_at is None:
            raise ValueError("finalized invoice lacks finalization evidence")
        return self

    def digest_body(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python", exclude={"snapshot_sha256", "authoritative_fetched_at"}
        )


class StripeRefundSnapshot(StrictCommercialModel):
    object_type: Literal["refund"] = "refund"
    external_object_id: str = Field(pattern=r"^re_[A-Za-z0-9]{4,252}$")
    environment: BillingEnvironment
    external_payment_intent_id: str = Field(pattern=r"^pi_[A-Za-z0-9]{4,252}$")
    external_charge_id: str = Field(pattern=r"^ch_[A-Za-z0-9]{4,252}$")
    amount_cents: StrictInt = Field(gt=0)
    currency: Literal["USD"]
    status: Literal["pending", "requires_action", "succeeded", "failed", "canceled"]
    reason: (
        Literal[
            "duplicate",
            "fraudulent",
            "requested_by_customer",
            "expired_uncaptured_charge",
        ]
        | None
    ) = None
    provider_created_at: AwareDatetime
    authoritative_fetched_at: AwareDatetime
    snapshot_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _valid_refund(self) -> "StripeRefundSnapshot":
        if self.snapshot_sha256 != canonical_sha256(self.digest_body()):
            raise ValueError("refund snapshot digest does not match")
        if self.provider_created_at > self.authoritative_fetched_at:
            raise ValueError("refund creation follows authoritative fetch")
        return self

    def digest_body(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python", exclude={"snapshot_sha256", "authoritative_fetched_at"}
        )


class StripeDisputeSnapshot(StrictCommercialModel):
    object_type: Literal["dispute"] = "dispute"
    external_object_id: str = Field(pattern=r"^dp_[A-Za-z0-9]{4,252}$")
    environment: BillingEnvironment
    external_payment_intent_id: str = Field(pattern=r"^pi_[A-Za-z0-9]{4,252}$")
    external_charge_id: str = Field(pattern=r"^ch_[A-Za-z0-9]{4,252}$")
    amount_cents: StrictInt = Field(gt=0)
    currency: Literal["USD"]
    status: Literal[
        "lost",
        "needs_response",
        "prevented",
        "under_review",
        "warning_closed",
        "warning_needs_response",
        "warning_under_review",
        "won",
    ]
    reason: Literal[
        "bank_cannot_process",
        "check_returned",
        "credit_not_processed",
        "customer_initiated",
        "debit_not_authorized",
        "duplicate",
        "fraudulent",
        "general",
        "incorrect_account_details",
        "insufficient_funds",
        "noncompliant",
        "product_not_received",
        "product_unacceptable",
        "subscription_canceled",
        "unrecognized",
    ]
    provider_created_at: AwareDatetime
    authoritative_fetched_at: AwareDatetime
    snapshot_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _valid_dispute(self) -> "StripeDisputeSnapshot":
        if self.snapshot_sha256 != canonical_sha256(self.digest_body()):
            raise ValueError("dispute snapshot digest does not match")
        if self.provider_created_at > self.authoritative_fetched_at:
            raise ValueError("dispute creation follows authoritative fetch")
        return self

    def digest_body(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python", exclude={"snapshot_sha256", "authoritative_fetched_at"}
        )


class StripeCreditNoteLineSnapshot(StrictCommercialModel):
    external_line_id: str = Field(pattern=r"^cnli_[A-Za-z0-9]{4,250}$")
    credited_invoice_line_id: str = Field(pattern=r"^il_[A-Za-z0-9]{4,252}$")
    quantity: PositiveBigInt
    gross_ex_tax_cents: NonNegativeBigInt
    discount_cents: NonNegativeBigInt
    pretax_credit_cents: NonNegativeBigInt
    net_ex_tax_cents: NonNegativeBigInt
    tax_cents: NonNegativeBigInt

    @model_validator(mode="after")
    def _reconciles(self) -> "StripeCreditNoteLineSnapshot":
        if self.pretax_credit_cents < self.discount_cents:
            raise ValueError("credit note line pretax credits omit discounts")
        if self.net_ex_tax_cents != self.gross_ex_tax_cents - self.pretax_credit_cents:
            raise ValueError("credit note line consideration does not reconcile")
        return self


class StripeCreditNoteRefundSnapshot(StrictCommercialModel):
    external_refund_id: str = Field(pattern=r"^re_[A-Za-z0-9]{4,252}$")
    amount_cents: PositiveBigInt


class StripeCreditNoteSnapshot(StrictCommercialModel):
    object_type: Literal["credit_note"] = "credit_note"
    external_object_id: str = Field(pattern=r"^cn_[A-Za-z0-9]{4,252}$")
    environment: BillingEnvironment
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    external_invoice_id: str = Field(pattern=r"^in_[A-Za-z0-9]{5,252}$")
    status: Literal["issued", "void"]
    credit_type: Literal["mixed", "post_payment", "pre_payment"]
    reason: (
        Literal["duplicate", "fraudulent", "order_change", "product_unsatisfactory"]
        | None
    ) = None
    currency: Literal["USD"]
    subtotal_cents: NonNegativeBigInt
    discount_cents: NonNegativeBigInt
    total_ex_tax_cents: NonNegativeBigInt
    tax_cents: NonNegativeBigInt
    total_cents: PositiveBigInt
    pre_payment_cents: NonNegativeBigInt
    post_payment_cents: NonNegativeBigInt
    out_of_band_cents: NonNegativeBigInt
    customer_balance_credit_cents: NonNegativeBigInt
    external_customer_balance_transaction_id: str | None = Field(
        default=None, pattern=r"^cbtxn_[A-Za-z0-9]{4,248}$"
    )
    refunds: tuple[StripeCreditNoteRefundSnapshot, ...]
    lines: tuple[StripeCreditNoteLineSnapshot, ...]
    provider_created_at: AwareDatetime
    effective_at: AwareDatetime
    voided_at: AwareDatetime | None = None
    authoritative_fetched_at: AwareDatetime
    snapshot_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _valid_credit_note(self) -> "StripeCreditNoteSnapshot":
        if self.snapshot_sha256 != canonical_sha256(self.digest_body()):
            raise ValueError("credit note snapshot digest does not match")
        if not self.lines or len({item.external_line_id for item in self.lines}) != len(
            self.lines
        ):
            raise ValueError("credit note lines are empty or duplicated")
        if len({item.external_refund_id for item in self.refunds}) != len(self.refunds):
            raise ValueError("credit note Refunds are duplicated")
        if (
            self.provider_created_at > self.authoritative_fetched_at
            or self.effective_at > self.authoritative_fetched_at
        ):
            raise ValueError("credit note chronology is invalid")
        if (self.status == "void") != (self.voided_at is not None):
            raise ValueError("credit note void boundary is incomplete")
        if (
            self.voided_at is not None
            and not self.provider_created_at
            <= self.voided_at
            <= self.authoritative_fetched_at
        ):
            raise ValueError("credit note void boundary is invalid")
        refund_cents = sum(item.amount_cents for item in self.refunds)
        aggregates = (
            refund_cents,
            sum(item.gross_ex_tax_cents for item in self.lines),
            sum(item.discount_cents for item in self.lines),
            sum(item.net_ex_tax_cents for item in self.lines),
            sum(item.tax_cents for item in self.lines),
        )
        if any(value > MAX_SIGNED_BIGINT for value in aggregates):
            raise ValueError("credit note aggregate exceeds signed BIGINT")
        if (
            self.customer_balance_credit_cents
            != self.post_payment_cents - refund_cents - self.out_of_band_cents
        ):
            raise ValueError("credit note post-payment disposition does not reconcile")
        if (self.customer_balance_credit_cents > 0) != (
            self.external_customer_balance_transaction_id is not None
        ):
            raise ValueError("credit note customer-balance evidence is incomplete")
        if self.pre_payment_cents + self.post_payment_cents != self.total_cents:
            raise ValueError("credit note payment split does not reconcile")
        if self.total_ex_tax_cents + self.tax_cents != self.total_cents:
            raise ValueError("credit note tax does not reconcile")
        if sum(item.gross_ex_tax_cents for item in self.lines) != self.subtotal_cents:
            raise ValueError("credit note line subtotal does not reconcile")
        if sum(item.discount_cents for item in self.lines) != self.discount_cents:
            raise ValueError("credit note line discounts do not reconcile")
        if sum(item.net_ex_tax_cents for item in self.lines) != self.total_ex_tax_cents:
            raise ValueError("credit note line consideration does not reconcile")
        if sum(item.tax_cents for item in self.lines) != self.tax_cents:
            raise ValueError("credit note line tax does not reconcile")
        return self

    def digest_body(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python", exclude={"snapshot_sha256", "authoritative_fetched_at"}
        )


class StripeProjectionProvider:
    def __init__(
        self,
        client: Any,
        *,
        deployment: StripeDeploymentManifest,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._client = client
        self._deployment = deployment
        self._environment = deployment.billing_environment
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._attestation_lock = threading.Lock()
        self._account_attested = False

    def fetch_checkout_session(
        self,
        session_id: str,
        *,
        expected: StripeProjectionExpectation,
    ) -> StripeCheckoutSnapshot:
        return self._safe_normalize(
            lambda: self._fetch_checkout_session(session_id, expected=expected),
            "Stripe Checkout normalization failed",
        )

    def _fetch_checkout_session(
        self,
        session_id: str,
        *,
        expected: StripeProjectionExpectation,
    ) -> StripeCheckoutSnapshot:
        self._require_expectation(expected)
        self._require_checkout_id(session_id)
        self._attest_account()
        raw = self._safe_call(
            lambda: self._client.v1.checkout.sessions.retrieve(
                session_id,
                params={"expand": ["line_items.data.price"]},
            ),
            "Stripe Checkout fetch failed",
        )
        fetched_at = self._clock()
        self._validate_environment(raw)
        self._require_equal(self._field(raw, "id"), session_id, "Checkout identity")
        self._require_equal(
            self._identity(self._field(raw, "customer")),
            expected.external_customer_id,
            "Checkout customer",
        )
        if self._field(raw, "mode") != "subscription":
            raise StripeProjectionProviderError("Checkout mode is invalid")
        self._validate_metadata(raw, expected)
        item = self._only_item(self._field(raw, "line_items"), "Checkout")
        price_id = self._identity(self._field(item, "price"))
        self._require_price(expected, price_id)
        quantity = self._field(item, "quantity")
        if quantity != 1:
            raise StripeProjectionProviderError("Checkout item quantity is invalid")
        subscription_id = self._optional_identity(self._field(raw, "subscription"))
        if subscription_id is not None and not _SUBSCRIPTION_ID.fullmatch(
            subscription_id
        ):
            raise StripeProjectionProviderError(
                "Checkout subscription identity is invalid"
            )
        payload = {
            "external_object_id": session_id,
            "environment": self._environment,
            "external_customer_id": expected.external_customer_id,
            "external_subscription_id": subscription_id,
            "commercial_account_public_id": expected.commercial_account_public_id,
            "agreement_public_id": expected.agreement_public_id,
            "price_code": expected.price_code,
            "stripe_price_id": price_id,
            "status": self._field(raw, "status"),
            "payment_status": self._field(raw, "payment_status"),
            "provider_created_at": self._timestamp(
                self._field(raw, "created"), "Checkout creation"
            ),
            "checkout_expires_at": self._timestamp(
                self._field(raw, "expires_at"), "Checkout expiry"
            ),
            "authoritative_fetched_at": fetched_at,
        }
        payload["snapshot_sha256"] = canonical_sha256(
            StripeCheckoutSnapshot.model_construct(
                **payload, snapshot_sha256="sha256:" + "0" * 64
            ).digest_body()
        )
        try:
            return StripeCheckoutSnapshot.model_validate(payload)
        except ValueError:
            raise StripeProjectionProviderError(
                "Stripe Checkout snapshot is invalid"
            ) from None

    def fetch_subscription(
        self,
        subscription_id: str,
        *,
        expected: StripeProjectionExpectation,
    ) -> StripeSubscriptionSnapshot:
        return self._safe_normalize(
            lambda: self._fetch_subscription(subscription_id, expected=expected),
            "Stripe subscription normalization failed",
        )

    def _fetch_subscription(
        self,
        subscription_id: str,
        *,
        expected: StripeProjectionExpectation,
    ) -> StripeSubscriptionSnapshot:
        self._require_expectation(expected)
        if not _SUBSCRIPTION_ID.fullmatch(subscription_id):
            raise StripeProjectionProviderError("subscription identity is invalid")
        self._attest_account()
        raw = self._safe_call(
            lambda: self._client.v1.subscriptions.retrieve(
                subscription_id,
                params={"expand": ["items.data.price", "latest_invoice"]},
            ),
            "Stripe subscription fetch failed",
        )
        fetched_at = self._clock()
        self._validate_environment(raw)
        self._require_equal(
            self._field(raw, "id"), subscription_id, "subscription identity"
        )
        self._require_equal(
            self._identity(self._field(raw, "customer")),
            expected.external_customer_id,
            "subscription customer",
        )
        self._validate_metadata(raw, expected)
        item = self._only_item(self._field(raw, "items"), "subscription")
        price_id = self._identity(self._field(item, "price"))
        self._require_price(expected, price_id)
        if self._field(item, "quantity") != 1:
            raise StripeProjectionProviderError("subscription item quantity is invalid")
        currency = self._field(raw, "currency")
        if (
            currency != "usd"
            or self._field(raw, "collection_method") != "charge_automatically"
        ):
            raise StripeProjectionProviderError("subscription billing shape is invalid")
        latest_invoice_id = self._optional_identity(self._field(raw, "latest_invoice"))
        if latest_invoice_id is not None and not _INVOICE_ID.fullmatch(
            latest_invoice_id
        ):
            raise StripeProjectionProviderError(
                "subscription invoice identity is invalid"
            )
        payload = {
            "external_object_id": subscription_id,
            "environment": self._environment,
            "external_customer_id": expected.external_customer_id,
            "commercial_account_public_id": expected.commercial_account_public_id,
            "agreement_public_id": expected.agreement_public_id,
            "price_code": expected.price_code,
            "stripe_price_id": price_id,
            "status": self._field(raw, "status"),
            "collection_method": self._field(raw, "collection_method"),
            "cancel_at_period_end": self._field(raw, "cancel_at_period_end"),
            "cancel_at": self._optional_timestamp(
                self._field(raw, "cancel_at"), "cancel_at"
            ),
            "canceled_at": self._optional_timestamp(
                self._field(raw, "canceled_at"), "canceled_at"
            ),
            "ended_at": self._optional_timestamp(
                self._field(raw, "ended_at"), "ended_at"
            ),
            "trial_start": self._optional_timestamp(
                self._field(raw, "trial_start"), "trial_start"
            ),
            "trial_end": self._optional_timestamp(
                self._field(raw, "trial_end"), "trial_end"
            ),
            "current_period_start_at": self._timestamp(
                self._field(item, "current_period_start"), "subscription period start"
            ),
            "current_period_end_at": self._timestamp(
                self._field(item, "current_period_end"), "subscription period end"
            ),
            "latest_invoice_id": latest_invoice_id,
            "collection_paused": self._field(raw, "pause_collection") is not None,
            "provider_created_at": self._timestamp(
                self._field(raw, "created"), "subscription creation"
            ),
            "authoritative_fetched_at": fetched_at,
        }
        payload["snapshot_sha256"] = canonical_sha256(
            StripeSubscriptionSnapshot.model_construct(
                **payload, snapshot_sha256="sha256:" + "0" * 64
            ).digest_body()
        )
        try:
            return StripeSubscriptionSnapshot.model_validate(payload)
        except ValueError:
            raise StripeProjectionProviderError(
                "Stripe subscription snapshot is invalid"
            ) from None

    def fetch_invoice(
        self,
        invoice_id: str,
        *,
        expected: StripeProjectionExpectation,
        expected_subscription_id: str,
    ) -> StripeInvoiceSnapshot:
        return self._safe_normalize(
            lambda: self._fetch_invoice(
                invoice_id,
                expected=expected,
                expected_subscription_id=expected_subscription_id,
            ),
            "Stripe invoice normalization failed",
        )

    def _fetch_invoice(
        self,
        invoice_id: str,
        *,
        expected: StripeProjectionExpectation,
        expected_subscription_id: str,
    ) -> StripeInvoiceSnapshot:
        self._require_expectation(expected)
        if not _INVOICE_ID.fullmatch(invoice_id):
            raise StripeProjectionProviderError("invoice identity is invalid")
        if not _SUBSCRIPTION_ID.fullmatch(expected_subscription_id):
            raise StripeProjectionProviderError(
                "invoice subscription identity is invalid"
            )
        self._attest_account()
        raw = self._safe_call(
            lambda: self._client.v1.invoices.retrieve(
                invoice_id,
                params={
                    "expand": [
                        "lines.data.pricing.price_details.price",
                        "payments.data.payment.payment_intent.latest_charge",
                    ]
                },
            ),
            "Stripe invoice fetch failed",
        )
        fetched_at = self._clock()
        self._validate_environment(raw)
        self._require_equal(self._field(raw, "id"), invoice_id, "invoice identity")
        self._require_equal(
            self._identity(self._field(raw, "customer")),
            expected.external_customer_id,
            "invoice customer",
        )
        parent = self._field(raw, "parent")
        if self._field(parent, "type") != "subscription_details":
            raise StripeProjectionProviderError("invoice parent is invalid")
        subscription_details = self._field(parent, "subscription_details")
        self._require_equal(
            self._identity(self._field(subscription_details, "subscription")),
            expected_subscription_id,
            "invoice subscription",
        )
        self._validate_metadata(subscription_details, expected)
        if (
            self._field(raw, "currency") != "usd"
            or self._field(raw, "collection_method") != "charge_automatically"
            or self._field(raw, "amount_shipping") != 0
            or self._field(raw, "amount_overpaid") != 0
            or self._field(raw, "amount_paid_off_stripe") not in (None, 0)
        ):
            raise StripeProjectionProviderError("invoice billing shape is invalid")
        lines = tuple(
            sorted(
                self._normalize_invoice_lines(
                    raw, invoice_id, expected, expected_subscription_id
                ),
                key=lambda item: item.external_line_id,
            )
        )
        payments = tuple(
            sorted(
                self._normalize_invoice_payments(raw, invoice_id),
                key=lambda item: item.external_invoice_payment_id,
            )
        )
        discount_cents = self._sum_amounts(
            self._field(raw, "total_discount_amounts"), "invoice discounts"
        )
        pretax_credit_cents = self._sum_amounts(
            self._field(raw, "total_pretax_credit_amounts"), "invoice pretax credits"
        )
        tax_cents = self._sum_amounts(self._field(raw, "total_taxes"), "invoice taxes")
        transitions = self._field(raw, "status_transitions")
        payload = {
            "external_object_id": invoice_id,
            "environment": self._environment,
            "external_customer_id": expected.external_customer_id,
            "external_subscription_id": expected_subscription_id,
            "commercial_account_public_id": expected.commercial_account_public_id,
            "agreement_public_id": expected.agreement_public_id,
            "subscription_price_code": expected.price_code,
            "status": self._field(raw, "status"),
            "billing_reason": self._field(raw, "billing_reason"),
            "collection_method": self._field(raw, "collection_method"),
            "currency": "USD",
            "subtotal_cents": self._integer(
                self._field(raw, "subtotal"), "invoice subtotal"
            ),
            "discount_cents": discount_cents,
            "pretax_credit_cents": pretax_credit_cents,
            "net_consideration_ex_tax_cents": self._integer(
                self._field(raw, "total_excluding_tax"), "invoice total excluding tax"
            ),
            "tax_cents": tax_cents,
            "total_cents": self._integer(self._field(raw, "total"), "invoice total"),
            "amount_due_cents": self._integer(
                self._field(raw, "amount_due"), "invoice amount due"
            ),
            "amount_paid_cents": self._integer(
                self._field(raw, "amount_paid"), "invoice amount paid"
            ),
            "amount_remaining_cents": self._integer(
                self._field(raw, "amount_remaining"), "invoice amount remaining"
            ),
            "pre_payment_credit_note_cents": self._integer(
                self._field(raw, "pre_payment_credit_notes_amount"),
                "invoice pre-payment credits",
            ),
            "post_payment_credit_note_cents": self._integer(
                self._field(raw, "post_payment_credit_notes_amount"),
                "invoice post-payment credits",
            ),
            "lines": lines,
            "payments": payments,
            "provider_created_at": self._timestamp(
                self._field(raw, "created"), "invoice creation"
            ),
            "finalized_at": self._optional_timestamp(
                self._field(transitions, "finalized_at"), "invoice finalization"
            ),
            "paid_at": self._optional_timestamp(
                self._field(transitions, "paid_at"), "invoice paid transition"
            ),
            "voided_at": self._optional_timestamp(
                self._field(transitions, "voided_at"), "invoice void transition"
            ),
            "marked_uncollectible_at": self._optional_timestamp(
                self._field(transitions, "marked_uncollectible_at"),
                "invoice uncollectible transition",
            ),
            "authoritative_fetched_at": fetched_at,
        }
        payload["snapshot_sha256"] = canonical_sha256(
            StripeInvoiceSnapshot.model_construct(
                **payload, snapshot_sha256="sha256:" + "0" * 64
            ).digest_body()
        )
        try:
            return StripeInvoiceSnapshot.model_validate(payload)
        except ValueError:
            raise StripeProjectionProviderError(
                "Stripe invoice snapshot is invalid"
            ) from None

    def _normalize_invoice_lines(
        self,
        raw: Any,
        invoice_id: str,
        expected: StripeProjectionExpectation,
        expected_subscription_id: str,
    ) -> tuple[StripeInvoiceLineSnapshot, ...]:
        values = self._complete_items(self._field(raw, "lines"), "invoice lines")
        normalized = []
        for value in values:
            line_id = self._field(value, "id")
            if not isinstance(line_id, str) or not _INVOICE_LINE_ID.fullmatch(line_id):
                raise StripeProjectionProviderError("invoice line identity is invalid")
            self._validate_environment(value)
            self._require_equal(
                self._field(value, "invoice"), invoice_id, "invoice line parent"
            )
            if self._field(value, "currency") != "usd":
                raise StripeProjectionProviderError("invoice line currency is invalid")
            pricing = self._field(value, "pricing")
            if self._field(pricing, "type") != "price_details":
                raise StripeProjectionProviderError("invoice line pricing is invalid")
            details = self._field(pricing, "price_details")
            price_id = self._identity(self._field(details, "price"))
            price_code = self._price_code_for_id(price_id)
            quantity = self._integer(
                self._field(value, "quantity"), "invoice line quantity"
            )
            parent = self._field(value, "parent")
            parent_type = self._field(parent, "type")
            parent_details = (
                self._field(parent, parent_type)
                if isinstance(parent_type, str)
                else None
            )
            self._require_equal(
                self._optional_identity(self._field(parent_details, "subscription")),
                expected_subscription_id,
                "invoice line subscription",
            )
            proration_details = self._field(parent_details, "proration_details")
            credited = self._field(proration_details, "credited_items")
            credited_invoice_id = None
            credited_line_ids: tuple[str, ...] = ()
            if credited is not None:
                credited_invoice_id = self._field(credited, "invoice")
                raw_ids = self._field(credited, "invoice_line_items")
                if not isinstance(raw_ids, (list, tuple)):
                    raise StripeProjectionProviderError(
                        "invoice credited lines are invalid"
                    )
                credited_line_ids = tuple(sorted(raw_ids))
            period = self._field(value, "period")
            subtotal = self._integer(
                self._field(value, "subtotal"), "invoice line subtotal"
            )
            discount = self._sum_amounts(
                self._field(value, "discount_amounts"), "invoice line discounts"
            )
            pretax_credit = self._sum_amounts(
                self._field(value, "pretax_credit_amounts"),
                "invoice line pretax credits",
            )
            tax = self._sum_amounts(self._field(value, "taxes"), "invoice line taxes")
            try:
                normalized.append(
                    StripeInvoiceLineSnapshot.model_validate(
                        {
                            "external_line_id": line_id,
                            "price_code": price_code,
                            "stripe_price_id": price_id,
                            "quantity": quantity,
                            "subtotal_cents": subtotal,
                            "discount_cents": discount,
                            "pretax_credit_cents": pretax_credit,
                            "net_consideration_ex_tax_cents": subtotal - pretax_credit,
                            "tax_cents": tax,
                            "service_period_start_at": self._timestamp(
                                self._field(period, "start"),
                                "invoice line period start",
                            ),
                            "service_period_end_at": self._timestamp(
                                self._field(period, "end"), "invoice line period end"
                            ),
                            "parent_type": parent_type,
                            "external_subscription_item_id": self._field(
                                parent_details, "subscription_item"
                            ),
                            "proration": self._field(parent_details, "proration"),
                            "credited_invoice_id": credited_invoice_id,
                            "credited_line_ids": credited_line_ids,
                        }
                    )
                )
            except ValueError:
                raise StripeProjectionProviderError(
                    "Stripe invoice line is invalid"
                ) from None
        return tuple(normalized)

    def _normalize_invoice_payments(
        self, raw: Any, invoice_id: str
    ) -> tuple[StripeInvoicePaymentSnapshot, ...]:
        container = self._field(raw, "payments")
        if container is None:
            return ()
        values = self._complete_items(container, "invoice payments")
        normalized = []
        for value in values:
            payment_id = self._field(value, "id")
            if not isinstance(payment_id, str) or not _INVOICE_PAYMENT_ID.fullmatch(
                payment_id
            ):
                raise StripeProjectionProviderError(
                    "invoice payment identity is invalid"
                )
            self._validate_environment(value)
            self._require_equal(
                self._identity(self._field(value, "invoice")),
                invoice_id,
                "invoice payment parent",
            )
            if self._field(value, "currency") != "usd":
                raise StripeProjectionProviderError(
                    "invoice payment currency is invalid"
                )
            payment = self._field(value, "payment")
            if self._field(payment, "type") != "payment_intent":
                raise StripeProjectionProviderError("invoice payment type is invalid")
            payment_intent_id = self._identity(self._field(payment, "payment_intent"))
            if not _PAYMENT_INTENT_ID.fullmatch(payment_intent_id):
                raise StripeProjectionProviderError(
                    "payment intent identity is invalid"
                )
            payment_intent = self._field(payment, "payment_intent")
            status = self._field(value, "status")
            raw_charge = self._field(payment_intent, "latest_charge")
            charge_id = self._identity(raw_charge) if raw_charge is not None else None
            if charge_id is not None and not _CHARGE_ID.fullmatch(charge_id):
                raise StripeProjectionProviderError(
                    "invoice payment Charge identity is invalid"
                )
            transitions = self._field(value, "status_transitions")
            try:
                normalized.append(
                    StripeInvoicePaymentSnapshot.model_validate(
                        {
                            "external_invoice_payment_id": payment_id,
                            "external_payment_intent_id": payment_intent_id,
                            "external_charge_id": charge_id,
                            "status": status,
                            "amount_requested_cents": self._integer(
                                self._field(value, "amount_requested"),
                                "invoice payment requested amount",
                            ),
                            "amount_paid_cents": self._optional_integer(
                                self._field(value, "amount_paid"),
                                "invoice payment paid amount",
                            ),
                            "provider_created_at": self._timestamp(
                                self._field(value, "created"),
                                "invoice payment creation",
                            ),
                            "paid_at": self._optional_timestamp(
                                self._field(transitions, "paid_at"),
                                "invoice payment paid transition",
                            ),
                        }
                    )
                )
            except ValueError:
                raise StripeProjectionProviderError(
                    "Stripe invoice payment is invalid"
                ) from None
        return tuple(normalized)

    def fetch_refund(
        self,
        refund_id: str,
        *,
        expected_payment_intent_id: str,
        expected_charge_id: str,
    ) -> StripeRefundSnapshot:
        return self._safe_normalize(
            lambda: self._fetch_refund(
                refund_id,
                expected_payment_intent_id=expected_payment_intent_id,
                expected_charge_id=expected_charge_id,
            ),
            "Stripe refund normalization failed",
        )

    def _fetch_refund(
        self,
        refund_id: str,
        *,
        expected_payment_intent_id: str,
        expected_charge_id: str,
    ) -> StripeRefundSnapshot:
        if not _REFUND_ID.fullmatch(refund_id):
            raise StripeProjectionProviderError("refund identity is invalid")
        if not _PAYMENT_INTENT_ID.fullmatch(expected_payment_intent_id):
            raise StripeProjectionProviderError(
                "refund PaymentIntent identity is invalid"
            )
        if not _CHARGE_ID.fullmatch(expected_charge_id):
            raise StripeProjectionProviderError("refund Charge identity is invalid")
        self._attest_account()
        raw = self._safe_call(
            lambda: self._client.v1.refunds.retrieve(refund_id),
            "Stripe refund fetch failed",
        )
        fetched_at = self._clock()
        self._validate_environment(raw)
        if self._field(raw, "object") != "refund":
            raise StripeProjectionProviderError("refund object type is invalid")
        self._require_equal(self._field(raw, "id"), refund_id, "refund identity")
        self._require_equal(
            self._identity(self._field(raw, "payment_intent")),
            expected_payment_intent_id,
            "refund PaymentIntent",
        )
        self._require_equal(
            self._identity(self._field(raw, "charge")),
            expected_charge_id,
            "refund Charge",
        )
        if self._field(raw, "currency") != "usd":
            raise StripeProjectionProviderError("refund currency is invalid")
        payload = {
            "external_object_id": refund_id,
            "environment": self._environment,
            "external_payment_intent_id": expected_payment_intent_id,
            "external_charge_id": expected_charge_id,
            "amount_cents": self._integer(self._field(raw, "amount"), "refund amount"),
            "currency": "USD",
            "status": self._field(raw, "status"),
            "reason": self._field(raw, "reason"),
            "provider_created_at": self._timestamp(
                self._field(raw, "created"), "refund creation"
            ),
            "authoritative_fetched_at": fetched_at,
        }
        payload["snapshot_sha256"] = canonical_sha256(
            StripeRefundSnapshot.model_construct(
                **payload, snapshot_sha256="sha256:" + "0" * 64
            ).digest_body()
        )
        try:
            return StripeRefundSnapshot.model_validate(payload)
        except ValueError:
            raise StripeProjectionProviderError(
                "Stripe refund snapshot is invalid"
            ) from None

    def fetch_dispute(
        self,
        dispute_id: str,
        *,
        expected_payment_intent_id: str,
        expected_charge_id: str,
    ) -> StripeDisputeSnapshot:
        return self._safe_normalize(
            lambda: self._fetch_dispute(
                dispute_id,
                expected_payment_intent_id=expected_payment_intent_id,
                expected_charge_id=expected_charge_id,
            ),
            "Stripe dispute normalization failed",
        )

    def _fetch_dispute(
        self,
        dispute_id: str,
        *,
        expected_payment_intent_id: str,
        expected_charge_id: str,
    ) -> StripeDisputeSnapshot:
        if not _DISPUTE_ID.fullmatch(dispute_id):
            raise StripeProjectionProviderError("dispute identity is invalid")
        if not _PAYMENT_INTENT_ID.fullmatch(expected_payment_intent_id):
            raise StripeProjectionProviderError(
                "dispute PaymentIntent identity is invalid"
            )
        if not _CHARGE_ID.fullmatch(expected_charge_id):
            raise StripeProjectionProviderError("dispute Charge identity is invalid")
        self._attest_account()
        raw = self._safe_call(
            lambda: self._client.v1.disputes.retrieve(dispute_id),
            "Stripe dispute fetch failed",
        )
        fetched_at = self._clock()
        self._validate_environment(raw)
        if self._field(raw, "object") != "dispute":
            raise StripeProjectionProviderError("dispute object type is invalid")
        self._require_equal(self._field(raw, "id"), dispute_id, "dispute identity")
        self._require_equal(
            self._identity(self._field(raw, "payment_intent")),
            expected_payment_intent_id,
            "dispute PaymentIntent",
        )
        self._require_equal(
            self._identity(self._field(raw, "charge")),
            expected_charge_id,
            "dispute Charge",
        )
        if self._field(raw, "currency") != "usd":
            raise StripeProjectionProviderError("dispute currency is invalid")
        payload = {
            "external_object_id": dispute_id,
            "environment": self._environment,
            "external_payment_intent_id": expected_payment_intent_id,
            "external_charge_id": expected_charge_id,
            "amount_cents": self._integer(self._field(raw, "amount"), "dispute amount"),
            "currency": "USD",
            "status": self._field(raw, "status"),
            "reason": self._field(raw, "reason"),
            "provider_created_at": self._timestamp(
                self._field(raw, "created"), "dispute creation"
            ),
            "authoritative_fetched_at": fetched_at,
        }
        payload["snapshot_sha256"] = canonical_sha256(
            StripeDisputeSnapshot.model_construct(
                **payload, snapshot_sha256="sha256:" + "0" * 64
            ).digest_body()
        )
        try:
            return StripeDisputeSnapshot.model_validate(payload)
        except ValueError:
            raise StripeProjectionProviderError(
                "Stripe dispute snapshot is invalid"
            ) from None

    def fetch_credit_note(
        self,
        credit_note_id: str,
        *,
        expected_invoice_id: str,
        expected_customer_id: str,
    ) -> StripeCreditNoteSnapshot:
        return self._safe_normalize(
            lambda: self._fetch_credit_note(
                credit_note_id,
                expected_invoice_id=expected_invoice_id,
                expected_customer_id=expected_customer_id,
            ),
            "Stripe credit note normalization failed",
        )

    def _fetch_credit_note(
        self,
        credit_note_id: str,
        *,
        expected_invoice_id: str,
        expected_customer_id: str,
    ) -> StripeCreditNoteSnapshot:
        if not _CREDIT_NOTE_ID.fullmatch(credit_note_id):
            raise StripeProjectionProviderError("credit note identity is invalid")
        if not _INVOICE_ID.fullmatch(expected_invoice_id):
            raise StripeProjectionProviderError(
                "credit note Invoice identity is invalid"
            )
        if not _CUSTOMER_ID.fullmatch(expected_customer_id):
            raise StripeProjectionProviderError(
                "credit note Customer identity is invalid"
            )
        self._attest_account()
        raw = self._safe_call(
            lambda: self._client.v1.credit_notes.retrieve(credit_note_id),
            "Stripe credit note fetch failed",
        )
        fetched_at = self._clock()
        self._validate_environment(raw)
        if self._field(raw, "object") != "credit_note":
            raise StripeProjectionProviderError("credit note object type is invalid")
        self._require_equal(
            self._field(raw, "id"), credit_note_id, "credit note identity"
        )
        self._require_equal(
            self._identity(self._field(raw, "invoice")),
            expected_invoice_id,
            "credit note Invoice",
        )
        self._require_equal(
            self._identity(self._field(raw, "customer")),
            expected_customer_id,
            "credit note Customer",
        )
        if self._field(raw, "currency") != "usd":
            raise StripeProjectionProviderError("credit note currency is invalid")
        if (
            self._integer(self._field(raw, "amount_shipping"), "credit note shipping")
            != 0
        ):
            raise StripeProjectionProviderError("credit note shipping is unsupported")
        lines = tuple(
            self._normalize_credit_note_line(item)
            for item in self._complete_items(
                self._field(raw, "lines"), "credit note lines"
            )
        )
        document_pretax, document_discount = self._normalize_pretax_credit_amounts(
            self._field(raw, "pretax_credit_amounts"),
            "credit note pretax credits",
        )
        if document_pretax != sum(item.pretax_credit_cents for item in lines):
            raise StripeProjectionProviderError(
                "credit note pretax credits do not match lines"
            )
        raw_refunds = self._field(raw, "refunds")
        if not isinstance(raw_refunds, (list, tuple)):
            raise StripeProjectionProviderError("credit note Refunds are invalid")
        refunds = []
        for item in raw_refunds:
            if self._field(item, "type") != "refund":
                raise StripeProjectionProviderError(
                    "credit note payment-record Refunds are unsupported"
                )
            refunds.append(
                StripeCreditNoteRefundSnapshot(
                    external_refund_id=self._identity(self._field(item, "refund")),
                    amount_cents=self._integer(
                        self._field(item, "amount_refunded"),
                        "credit note Refund amount",
                    ),
                )
            )
        refunds = tuple(refunds)
        post_payment = self._integer(
            self._field(raw, "post_payment_amount"), "credit note post-payment amount"
        )
        out_of_band = (
            self._optional_integer(
                self._field(raw, "out_of_band_amount"), "credit note out-of-band amount"
            )
            or 0
        )
        customer_balance_id = self._optional_identity(
            self._field(raw, "customer_balance_transaction")
        )
        if (
            customer_balance_id is not None
            and not _CUSTOMER_BALANCE_TRANSACTION_ID.fullmatch(customer_balance_id)
        ):
            raise StripeProjectionProviderError(
                "credit note customer-balance identity is invalid"
            )
        if document_discount != self._integer(
            self._field(raw, "discount_amount"), "credit note discount"
        ):
            raise StripeProjectionProviderError(
                "credit note discount provenance does not reconcile"
            )
        payload = {
            "external_object_id": credit_note_id,
            "environment": self._environment,
            "external_customer_id": expected_customer_id,
            "external_invoice_id": expected_invoice_id,
            "status": self._field(raw, "status"),
            "credit_type": self._field(raw, "type"),
            "reason": self._field(raw, "reason"),
            "currency": "USD",
            "subtotal_cents": self._integer(
                self._field(raw, "subtotal"), "credit note subtotal"
            ),
            "discount_cents": self._integer(
                self._field(raw, "discount_amount"), "credit note discount"
            ),
            "total_ex_tax_cents": self._integer(
                self._field(raw, "total_excluding_tax"), "credit note ex-tax total"
            ),
            "tax_cents": self._sum_amounts(
                self._field(raw, "total_taxes"), "credit note taxes"
            ),
            "total_cents": self._integer(
                self._field(raw, "total"), "credit note total"
            ),
            "pre_payment_cents": self._integer(
                self._field(raw, "pre_payment_amount"), "credit note pre-payment amount"
            ),
            "post_payment_cents": post_payment,
            "out_of_band_cents": out_of_band,
            "customer_balance_credit_cents": post_payment
            - sum(item.amount_cents for item in refunds)
            - out_of_band,
            "external_customer_balance_transaction_id": customer_balance_id,
            "refunds": refunds,
            "lines": lines,
            "provider_created_at": self._timestamp(
                self._field(raw, "created"), "credit note creation"
            ),
            "effective_at": self._timestamp(
                self._field(raw, "created")
                if self._field(raw, "effective_at") is None
                else self._field(raw, "effective_at"),
                "credit note effective time",
            ),
            "voided_at": self._optional_timestamp(
                self._field(raw, "voided_at"), "credit note void time"
            ),
            "authoritative_fetched_at": fetched_at,
        }
        payload["snapshot_sha256"] = canonical_sha256(
            StripeCreditNoteSnapshot.model_construct(
                **payload, snapshot_sha256="sha256:" + "0" * 64
            ).digest_body()
        )
        try:
            return StripeCreditNoteSnapshot.model_validate(payload)
        except ValueError:
            raise StripeProjectionProviderError(
                "Stripe credit note snapshot is invalid"
            ) from None

    def _normalize_credit_note_line(self, raw: Any) -> StripeCreditNoteLineSnapshot:
        self._validate_environment(raw)
        if self._field(raw, "object") != "credit_note_line_item":
            raise StripeProjectionProviderError(
                "credit note line object type is invalid"
            )
        if self._field(raw, "type") != "invoice_line_item":
            raise StripeProjectionProviderError(
                "credit note custom lines are unsupported"
            )
        line_id = self._field(raw, "id")
        invoice_line_id = self._field(raw, "invoice_line_item")
        if not isinstance(line_id, str) or not _CREDIT_NOTE_LINE_ID.fullmatch(line_id):
            raise StripeProjectionProviderError("credit note line identity is invalid")
        if not isinstance(invoice_line_id, str) or not _INVOICE_LINE_ID.fullmatch(
            invoice_line_id
        ):
            raise StripeProjectionProviderError(
                "credited Invoice line identity is invalid"
            )
        gross = self._integer(self._field(raw, "amount"), "credit note line amount")
        pretax, pretax_discount = self._normalize_pretax_credit_amounts(
            self._field(raw, "pretax_credit_amounts"),
            "credit note line pretax credits",
        )
        line_discount = self._integer(
            self._field(raw, "discount_amount"), "credit note line discount"
        )
        if pretax_discount != line_discount:
            raise StripeProjectionProviderError(
                "credit note line discount provenance does not reconcile"
            )
        try:
            return StripeCreditNoteLineSnapshot(
                external_line_id=line_id,
                credited_invoice_line_id=invoice_line_id,
                quantity=self._integer(
                    self._field(raw, "quantity"), "credit note quantity"
                ),
                gross_ex_tax_cents=gross,
                discount_cents=line_discount,
                pretax_credit_cents=pretax,
                net_ex_tax_cents=gross - pretax,
                tax_cents=self._sum_amounts(
                    self._field(raw, "taxes"), "credit note line taxes"
                ),
            )
        except ValueError:
            raise StripeProjectionProviderError(
                "Stripe credit note line is invalid"
            ) from None

    def _normalize_pretax_credit_amounts(
        self, values: Any, label: str
    ) -> tuple[int, int]:
        if not isinstance(values, (list, tuple)):
            raise StripeProjectionProviderError(f"{label} are invalid")
        total = 0
        discount_total = 0
        for item in values:
            amount = self._integer(self._field(item, "amount"), label)
            if amount < 0 or amount > MAX_SIGNED_BIGINT - total:
                raise StripeProjectionProviderError(f"{label} are invalid")
            item_type = self._field(item, "type")
            if item_type == "discount":
                if self._optional_identity(self._field(item, "discount")) is None:
                    raise StripeProjectionProviderError(
                        f"{label} discount lineage is invalid"
                    )
                discount_total += amount
            elif item_type == "credit_balance_transaction":
                identity = self._optional_identity(
                    self._field(item, "credit_balance_transaction")
                )
                if identity is None or not _CUSTOMER_BALANCE_TRANSACTION_ID.fullmatch(
                    identity
                ):
                    raise StripeProjectionProviderError(
                        f"{label} credit-balance lineage is invalid"
                    )
            else:
                raise StripeProjectionProviderError(f"{label} type is invalid")
            total += amount
        return total, discount_total

    def _require_expectation(self, expected: StripeProjectionExpectation) -> None:
        if expected.environment != self._environment:
            raise StripeProjectionProviderError(
                "Stripe projection environment is invalid"
            )

    def _validate_environment(self, raw: Any) -> None:
        value = self._field(raw, "livemode")
        if not isinstance(value, bool) or value != (self._environment == "live"):
            raise StripeProjectionProviderError("Stripe object environment mismatch")

    def _validate_metadata(
        self, raw: Any, expected: StripeProjectionExpectation
    ) -> None:
        metadata = self._mapping(self._field(raw, "metadata"))
        required = {
            "hank_commercial_account_id": str(expected.commercial_account_public_id),
            "hank_agreement_id": str(expected.agreement_public_id),
            "hank_price_code": expected.price_code,
            "hank_environment": expected.environment,
        }
        if any(metadata.get(key) != value for key, value in required.items()):
            raise StripeProjectionProviderError("Stripe metadata identity mismatch")

    def _require_price(
        self, expected: StripeProjectionExpectation, price_id: str
    ) -> None:
        try:
            binding = self._deployment.resolve_price(expected.price_code)
        except Exception:
            raise StripeProjectionProviderError(
                "Stripe Price mapping is unavailable"
            ) from None
        if price_id != binding.price_id:
            raise StripeProjectionProviderError("Stripe Price identity mismatch")

    def _price_code_for_id(self, price_id: str) -> str:
        matches = [
            price_code
            for price_code, binding in self._deployment.prices.items()
            if binding.price_id == price_id
        ]
        if len(matches) != 1:
            raise StripeProjectionProviderError("Stripe Price mapping is unavailable")
        return matches[0]

    def _require_checkout_id(self, value: str) -> None:
        match = _CHECKOUT_ID.fullmatch(value)
        if match is None or match.group(1) != self._environment:
            raise StripeProjectionProviderError("Checkout identity is invalid")

    @classmethod
    def _only_item(cls, container: Any, label: str) -> Any:
        data = cls._field(container, "data")
        has_more = cls._field(container, "has_more")
        if (
            has_more is not False
            or not isinstance(data, (list, tuple))
            or len(data) != 1
        ):
            raise StripeProjectionProviderError(
                f"{label} must contain exactly one item"
            )
        return data[0]

    def _complete_items(self, container: Any, label: str) -> tuple[Any, ...]:
        data = self._field(container, "data")
        has_more = self._field(container, "has_more")
        if not isinstance(data, (list, tuple)) or not isinstance(has_more, bool):
            raise StripeProjectionProviderError(f"{label} pagination is incomplete")
        if has_more:
            iterator = getattr(container, "auto_paging_iter", None)
            if not callable(iterator):
                raise StripeProjectionProviderError(f"{label} pagination is incomplete")
            values = self._safe_call(
                lambda: tuple(iterator()), f"Stripe {label} fetch failed"
            )
            if len(values) <= len(data):
                raise StripeProjectionProviderError(f"{label} pagination is incomplete")
            return values
        return tuple(data)

    @staticmethod
    def _integer(value: Any, label: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise StripeProjectionProviderError(f"{label} is invalid")
        return value

    @classmethod
    def _optional_integer(cls, value: Any, label: str) -> int | None:
        return None if value is None else cls._integer(value, label)

    @classmethod
    def _sum_amounts(cls, values: Any, label: str) -> int:
        if values is None:
            return 0
        if not isinstance(values, (list, tuple)):
            raise StripeProjectionProviderError(f"{label} are invalid")
        total = 0
        for value in values:
            amount = cls._integer(cls._field(value, "amount"), label)
            if amount < 0 or amount > MAX_SIGNED_BIGINT - total:
                raise StripeProjectionProviderError(f"{label} are invalid")
            total += amount
        return total

    def _attest_account(self) -> None:
        if self._account_attested:
            return
        with self._attestation_lock:
            if self._account_attested:
                return
            account = self._safe_call(
                lambda: self._client.v1.accounts.retrieve_current(),
                "Stripe account attestation failed",
            )
            if self._field(account, "id") != self._deployment.stripe_account_id:
                raise StripeProjectionProviderError(
                    "Stripe account attestation mismatch"
                )
            self._account_attested = True

    @staticmethod
    def _timestamp(value: Any, label: str) -> datetime:
        if isinstance(value, bool) or not isinstance(value, int):
            raise StripeProjectionProviderError(f"{label} is invalid")
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError):
            raise StripeProjectionProviderError(f"{label} is invalid") from None

    @classmethod
    def _optional_timestamp(cls, value: Any, label: str) -> datetime | None:
        return None if value is None else cls._timestamp(value, label)

    @classmethod
    def _identity(cls, value: Any) -> str:
        result = cls._optional_identity(value)
        if result is None:
            raise StripeProjectionProviderError("Stripe expandable identity is missing")
        return result

    @classmethod
    def _optional_identity(cls, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        result = cls._field(value, "id")
        return result if isinstance(result, str) else None

    @staticmethod
    def _require_equal(value: Any, expected: Any, label: str) -> None:
        if value != expected:
            raise StripeProjectionProviderError(f"{label} mismatch")

    @staticmethod
    def _field(value: Any, name: str) -> Any:
        return (
            value.get(name) if isinstance(value, dict) else getattr(value, name, None)
        )

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        try:
            return dict(value)
        except (TypeError, ValueError):
            return {}

    @staticmethod
    def _safe_call(operation, message: str) -> Any:
        failed = False
        result = None
        try:
            result = operation()
        except Exception:
            failed = True
        if failed:
            raise StripeProjectionProviderError(message)
        return result

    @staticmethod
    def _safe_normalize(operation, message: str) -> Any:
        failed = False
        result = None
        try:
            result = operation()
        except StripeProjectionProviderError:
            raise
        except Exception:
            failed = True
        if failed:
            raise StripeProjectionProviderError(message)
        return result


__all__ = [
    "StripeCheckoutSnapshot",
    "StripeCreditNoteLineSnapshot",
    "StripeCreditNoteRefundSnapshot",
    "StripeCreditNoteSnapshot",
    "StripeDisputeSnapshot",
    "StripeInvoiceLineSnapshot",
    "StripeInvoicePaymentSnapshot",
    "StripeInvoiceSnapshot",
    "StripeProjectionExpectation",
    "StripeProjectionProvider",
    "StripeProjectionProviderError",
    "StripeRefundSnapshot",
    "StripeSubscriptionSnapshot",
]
