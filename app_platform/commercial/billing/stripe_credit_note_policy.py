"""Pure Stripe Credit Note revenue and disposition policy."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from ..models import MAX_SIGNED_BIGINT, StrictCommercialModel
from ..revenue_allocation import DailyCentsPeriod, allocate_daily_cents
from .stripe_projection_provider import StripeCreditNoteSnapshot


STRIPE_CREDIT_NOTE_EFFECT_POLICY_VERSION = "stripe-credit-note-effect.v1"
NonNegativeBigInt = Annotated[StrictInt, Field(ge=0, le=MAX_SIGNED_BIGINT)]
PositiveBigInt = Annotated[StrictInt, Field(gt=0, le=MAX_SIGNED_BIGINT)]


class StripeCreditNotePolicyError(ValueError):
    """Credit Note authority cannot safely produce a financial effect."""


class StripeCreditNoteInvoiceLineEvidence(StrictCommercialModel):
    external_invoice_line_id: str = Field(pattern=r"^il_[A-Za-z0-9]+$")
    net_consideration_ex_tax_cents: NonNegativeBigInt
    tax_cents: NonNegativeBigInt
    service_period_start_at: AwareDatetime
    service_period_end_at: AwareDatetime

    @model_validator(mode="after")
    def _valid_period(self) -> "StripeCreditNoteInvoiceLineEvidence":
        if self.service_period_end_at <= self.service_period_start_at:
            raise ValueError("Invoice line service period is empty")
        return self


class StripePriorCreditNoteLineEvidence(StrictCommercialModel):
    external_credit_note_id: str = Field(pattern=r"^cn_[A-Za-z0-9]+$")
    external_credit_note_line_id: str = Field(pattern=r"^cnli_[A-Za-z0-9]+$")
    credited_invoice_line_id: str = Field(pattern=r"^il_[A-Za-z0-9]+$")
    net_credit_ex_tax_cents: NonNegativeBigInt
    tax_credit_cents: NonNegativeBigInt
    status: Literal["issued"] = "issued"


class StripeCreditNoteRefundEvidence(StrictCommercialModel):
    external_refund_id: str = Field(pattern=r"^re_[A-Za-z0-9]+$")
    external_invoice_id: str = Field(pattern=r"^in_[A-Za-z0-9]+$")
    amount_cents: PositiveBigInt
    signed_movement_cents: Annotated[StrictInt, Field(lt=0, ge=-MAX_SIGNED_BIGINT)]
    currency: Literal["USD"]
    status: Literal["succeeded"] = "succeeded"
    occurred_at: AwareDatetime

    @model_validator(mode="after")
    def _exact_movement(self) -> "StripeCreditNoteRefundEvidence":
        if self.signed_movement_cents != -self.amount_cents:
            raise ValueError("Refund movement does not match its amount")
        return self


class StripeCreditNoteLineDecision(StrictCommercialModel):
    external_credit_note_line_id: str = Field(pattern=r"^cnli_[A-Za-z0-9]+$")
    credited_invoice_line_id: str = Field(pattern=r"^il_[A-Za-z0-9]+$")
    signed_net_consideration_ex_tax_cents: Annotated[
        StrictInt, Field(le=0, ge=-MAX_SIGNED_BIGINT)
    ]
    tax_credit_cents: NonNegativeBigInt
    service_period_start_at: AwareDatetime
    service_period_end_at: AwareDatetime
    periods: tuple[DailyCentsPeriod, ...]

    @model_validator(mode="after")
    def _reconciles(self) -> "StripeCreditNoteLineDecision":
        if not self.periods:
            raise ValueError("Credit Note line requires a revenue schedule")
        if self.periods[0].period_start_at != self.service_period_start_at:
            raise ValueError("Credit Note schedule starts outside the service period")
        if self.periods[-1].period_end_at != self.service_period_end_at:
            raise ValueError("Credit Note schedule ends outside the service period")
        if any(
            item.period_end_at <= item.period_start_at for item in self.periods
        ) or any(
            previous.period_end_at != current.period_start_at
            for previous, current in zip(self.periods, self.periods[1:], strict=False)
        ):
            raise ValueError("Credit Note schedule is not contiguous")
        if sum(item.signed_cents for item in self.periods) != (
            self.signed_net_consideration_ex_tax_cents
        ):
            raise ValueError("Credit Note revenue schedule does not reconcile")
        return self


class StripeCreditNoteEffectDecision(StrictCommercialModel):
    create_document: StrictBool
    append_status: StrictBool
    document_status: Literal["issued", "void"]
    revenue_active: StrictBool
    lines: tuple[StripeCreditNoteLineDecision, ...]
    append_out_of_band_credit_movement: StrictBool
    signed_credit_movement_cents: (
        Annotated[StrictInt, Field(lt=0, ge=-MAX_SIGNED_BIGINT)] | None
    ) = None
    credit_movement_occurred_at: AwareDatetime | None = None
    policy_version: Literal["stripe-credit-note-effect.v1"] = (
        STRIPE_CREDIT_NOTE_EFFECT_POLICY_VERSION
    )
    reason_code: Literal[
        "stripe.credit_note.issued",
        "stripe.credit_note.void",
        "stripe.credit_note.unchanged",
    ]

    @model_validator(mode="after")
    def _coherent(self) -> "StripeCreditNoteEffectDecision":
        carries_movement = (
            self.signed_credit_movement_cents is not None
            and self.credit_movement_occurred_at is not None
        )
        if self.append_out_of_band_credit_movement != carries_movement:
            raise ValueError("Credit Note movement evidence is incomplete")
        if self.create_document != bool(self.lines):
            raise ValueError("Credit Note document lines are incomplete")
        if self.create_document and not self.append_status:
            raise ValueError("New Credit Note document omits its status")
        if self.revenue_active != (self.document_status == "issued"):
            raise ValueError("Credit Note revenue status is incoherent")
        if self.reason_code == "stripe.credit_note.unchanged" and (
            self.create_document
            or self.append_status
            or self.append_out_of_band_credit_movement
        ):
            raise ValueError("Unchanged Credit Note carries a new effect")
        if self.reason_code != "stripe.credit_note.unchanged" and (
            not self.append_status
            or self.reason_code != f"stripe.credit_note.{self.document_status}"
        ):
            raise ValueError("Credit Note reason does not match its status effect")
        if self.append_out_of_band_credit_movement and not self.create_document:
            raise ValueError("Credit Note movement is detached from document creation")
        return self


def validate_stripe_credit_note_evaluation(
    snapshot: StripeCreditNoteSnapshot, evaluated_at: datetime
) -> None:
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise StripeCreditNotePolicyError("Credit Note evaluation time must be aware")
    if snapshot.authoritative_fetched_at > evaluated_at:
        raise StripeCreditNotePolicyError(
            "Credit Note authority follows evaluation time"
        )


def decide_stripe_credit_note_effect(
    *,
    snapshot: StripeCreditNoteSnapshot,
    invoice_lines: tuple[StripeCreditNoteInvoiceLineEvidence, ...],
    prior_active_credit_lines: tuple[StripePriorCreditNoteLineEvidence, ...],
    linked_refunds: tuple[StripeCreditNoteRefundEvidence, ...],
    prior_document_status: Literal["issued", "void"] | None,
    evaluated_at: datetime,
) -> StripeCreditNoteEffectDecision:
    """Authorize one bounded negative revenue document and explicit disposition."""

    validate_stripe_credit_note_evaluation(snapshot, evaluated_at)
    if prior_document_status == "void" and snapshot.status != "void":
        raise StripeCreditNotePolicyError("Void Credit Note cannot become issued")
    originals: dict[str, StripeCreditNoteInvoiceLineEvidence] = {}
    for line in invoice_lines:
        if line.external_invoice_line_id in originals:
            raise StripeCreditNotePolicyError("Invoice line evidence is duplicated")
        originals[line.external_invoice_line_id] = line
    requested_ids = {line.credited_invoice_line_id for line in snapshot.lines}
    if requested_ids != set(originals):
        raise StripeCreditNotePolicyError(
            "Credit Note Invoice line evidence is incomplete"
        )

    prior_keys: set[tuple[str, str]] = set()
    prior_net: dict[str, int] = {}
    prior_tax: dict[str, int] = {}
    for prior in prior_active_credit_lines:
        if prior.external_credit_note_id == snapshot.external_object_id:
            raise StripeCreditNotePolicyError(
                "Current Credit Note already has active lines"
            )
        key = (prior.external_credit_note_id, prior.external_credit_note_line_id)
        if key in prior_keys:
            raise StripeCreditNotePolicyError(
                "Prior Credit Note evidence is duplicated"
            )
        prior_keys.add(key)
        if prior.credited_invoice_line_id not in originals:
            raise StripeCreditNotePolicyError(
                "Prior Credit Note line crosses the Invoice"
            )
        prior_net[prior.credited_invoice_line_id] = (
            prior_net.get(prior.credited_invoice_line_id, 0)
            + prior.net_credit_ex_tax_cents
        )
        prior_tax[prior.credited_invoice_line_id] = (
            prior_tax.get(prior.credited_invoice_line_id, 0) + prior.tax_credit_cents
        )

    current_net: dict[str, int] = {}
    current_tax: dict[str, int] = {}
    for line in snapshot.lines:
        line_id = line.credited_invoice_line_id
        current_net[line_id] = current_net.get(line_id, 0) + line.net_ex_tax_cents
        current_tax[line_id] = current_tax.get(line_id, 0) + line.tax_cents
    for line_id, original in originals.items():
        active_net = prior_net.get(line_id, 0)
        active_tax = prior_tax.get(line_id, 0)
        if snapshot.status == "issued":
            active_net += current_net.get(line_id, 0)
            active_tax += current_tax.get(line_id, 0)
        if current_net.get(line_id, 0) > original.net_consideration_ex_tax_cents:
            raise StripeCreditNotePolicyError(
                "Credit Note consideration exceeds the Invoice line"
            )
        if current_tax.get(line_id, 0) > original.tax_cents:
            raise StripeCreditNotePolicyError(
                "Credit Note tax exceeds the Invoice line"
            )
        if active_net > (original.net_consideration_ex_tax_cents):
            raise StripeCreditNotePolicyError(
                "Cumulative Credit Note consideration exceeds the Invoice line"
            )
        if active_tax > original.tax_cents:
            raise StripeCreditNotePolicyError(
                "Cumulative Credit Note tax exceeds the Invoice line"
            )

    expected_refunds = {
        item.external_refund_id: item.amount_cents for item in snapshot.refunds
    }
    observed_refunds: dict[str, int] = {}
    for refund in linked_refunds:
        if refund.external_refund_id in observed_refunds:
            raise StripeCreditNotePolicyError("Linked Refund evidence is duplicated")
        if (
            refund.external_invoice_id != snapshot.external_invoice_id
            or refund.currency != snapshot.currency
            or refund.occurred_at < snapshot.provider_created_at
            or refund.occurred_at > evaluated_at
        ):
            raise StripeCreditNotePolicyError("Linked Refund evidence is invalid")
        observed_refunds[refund.external_refund_id] = refund.amount_cents
    if observed_refunds != expected_refunds:
        raise StripeCreditNotePolicyError("Linked Refund evidence is incomplete")

    if prior_document_status == snapshot.status:
        return StripeCreditNoteEffectDecision(
            create_document=False,
            append_status=False,
            document_status=snapshot.status,
            revenue_active=snapshot.status == "issued",
            lines=(),
            append_out_of_band_credit_movement=False,
            reason_code="stripe.credit_note.unchanged",
        )

    create_document = prior_document_status is None
    line_decisions = ()
    if create_document:
        line_decisions = tuple(
            StripeCreditNoteLineDecision(
                external_credit_note_line_id=line.external_line_id,
                credited_invoice_line_id=line.credited_invoice_line_id,
                signed_net_consideration_ex_tax_cents=-line.net_ex_tax_cents,
                tax_credit_cents=line.tax_cents,
                service_period_start_at=originals[
                    line.credited_invoice_line_id
                ].service_period_start_at,
                service_period_end_at=originals[
                    line.credited_invoice_line_id
                ].service_period_end_at,
                periods=allocate_daily_cents(
                    -line.net_ex_tax_cents,
                    originals[line.credited_invoice_line_id].service_period_start_at,
                    originals[line.credited_invoice_line_id].service_period_end_at,
                ),
            )
            for line in snapshot.lines
        )
    append_credit = prior_document_status is None and snapshot.out_of_band_cents > 0
    return StripeCreditNoteEffectDecision(
        create_document=create_document,
        append_status=True,
        document_status=snapshot.status,
        revenue_active=snapshot.status == "issued",
        lines=line_decisions,
        append_out_of_band_credit_movement=append_credit,
        signed_credit_movement_cents=(
            -snapshot.out_of_band_cents if append_credit else None
        ),
        credit_movement_occurred_at=snapshot.effective_at if append_credit else None,
        reason_code=f"stripe.credit_note.{snapshot.status}",
    )


__all__ = [
    "STRIPE_CREDIT_NOTE_EFFECT_POLICY_VERSION",
    "StripeCreditNoteEffectDecision",
    "StripeCreditNoteInvoiceLineEvidence",
    "StripeCreditNotePolicyError",
    "StripeCreditNoteRefundEvidence",
    "StripePriorCreditNoteLineEvidence",
    "decide_stripe_credit_note_effect",
    "validate_stripe_credit_note_evaluation",
]
