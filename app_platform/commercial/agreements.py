"""Typed immutable agreement, effective-terms, and line-item contracts."""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from .models import (
    NonEmptyStr,
    NonNegativeBigInt,
    SignedBigInt,
    StableCode,
    StrictCommercialModel,
)


class AgreementChannel(StrEnum):
    SELF_SERVE = "self_serve"
    INVITE_TRIAL = "invite_trial"
    PILOT = "pilot"
    MANAGED = "managed"
    ADMIN_TEST = "admin_test"


class BillingProvider(StrEnum):
    STRIPE = "stripe"
    MANUAL = "manual"
    NONE = "none"


class AgreementState(StrEnum):
    DRAFT = "draft"
    PENDING_PAYMENT = "pending_payment"
    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    GRACE = "grace"
    PAUSED = "paused"
    CANCELED = "canceled"
    EXPIRED = "expired"


class AgreementItemKind(StrEnum):
    RECURRING = "recurring"
    ONBOARDING = "onboarding"
    IMPLEMENTATION = "implementation"
    DISCOUNT = "discount"
    CREDIT = "credit"
    INCLUDED_ALLOWANCE = "included_allowance"


class CommercialAgreementCreate(StrictCommercialModel):
    public_id: UUID = Field(default_factory=uuid4)
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    surface_code: StableCode
    channel: AgreementChannel
    billing_provider: BillingProvider
    billing_environment: Literal["test", "live"] | None = None
    state: AgreementState = AgreementState.DRAFT
    currency: Annotated[StrictStr, Field(pattern=r"^[A-Z]{3}$")] = "USD"
    service_start_at: AwareDatetime | None = None
    service_end_at: AwareDatetime | None = None
    current_period_start_at: AwareDatetime | None = None
    current_period_end_at: AwareDatetime | None = None
    trial_end_at: AwareDatetime | None = None
    grace_end_at: AwareDatetime | None = None
    pending_expires_at: AwareDatetime | None = None
    cancel_at_period_end: StrictBool = False
    canceled_at: AwareDatetime | None = None
    external_subscription_id: NonEmptyStr | None = None
    external_contract_id: NonEmptyStr | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_lifecycle_shape(self) -> "CommercialAgreementCreate":
        if (self.billing_provider == BillingProvider.STRIPE) != (
            self.billing_environment is not None
        ):
            raise ValueError(
                "Stripe agreements require a billing environment and non-Stripe agreements forbid it"
            )
        if (
            self.external_subscription_id is not None
            and self.billing_provider != BillingProvider.STRIPE
        ):
            raise ValueError("external subscriptions require Stripe billing")
        for start, end, label in (
            (self.service_start_at, self.service_end_at, "service"),
            (
                self.current_period_start_at,
                self.current_period_end_at,
                "current period",
            ),
        ):
            if end is not None and (start is None or end <= start):
                raise ValueError(f"{label} end must follow its start")
        if self.canceled_at is not None and self.state not in {
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }:
            raise ValueError("canceled_at requires a terminal agreement state")
        return self


class CommercialAgreementRecord(CommercialAgreementCreate):
    id: Annotated[StrictInt, Field(gt=0)]
    version: Annotated[StrictInt, Field(gt=0)]
    state_effective_at: AwareDatetime
    created_at: AwareDatetime
    updated_at: AwareDatetime


class CommercialAgreementTermsCreate(StrictCommercialModel):
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    revision: Annotated[StrictInt, Field(gt=0)]
    offer_code: StableCode
    price_code: StableCode | None = None
    catalog_policy_id: Annotated[StrictInt, Field(gt=0)]
    entitlement_policy_id: Annotated[StrictInt, Field(gt=0)]
    payer_policy_id: Annotated[StrictInt, Field(gt=0)]
    budget_policy_id: Annotated[StrictInt, Field(gt=0)]
    contracted_service_period_cents: NonNegativeBigInt
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None = None
    source_event_id: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _valid_range(self) -> "CommercialAgreementTermsCreate":
        if (
            self.effective_until is not None
            and self.effective_until <= self.effective_from
        ):
            raise ValueError(
                "agreement terms effective_until must follow effective_from"
            )
        return self


class CommercialAgreementTermsRecord(CommercialAgreementTermsCreate):
    id: Annotated[StrictInt, Field(gt=0)]
    created_at: AwareDatetime
    sealed_at: AwareDatetime
    terminal_closed_at: AwareDatetime | None = None
    terminal_command_id: UUID | None = None
    voided_at: AwareDatetime | None = None
    void_command_id: UUID | None = None


class CommercialAgreementItemCreate(StrictCommercialModel):
    item_code: StableCode
    item_kind: AgreementItemKind
    price_code: StableCode | None = None
    quantity: Annotated[Decimal, Field(gt=0, max_digits=12, decimal_places=4)] = (
        Decimal("1")
    )
    unit_amount_cents: SignedBigInt
    billing_interval: Literal["one_time", "month", "year", "fixed_term"] | None = None
    service_start_at: AwareDatetime | None = None
    service_end_at: AwareDatetime | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_sign_and_service_range(self) -> "CommercialAgreementItemCreate":
        if self.item_kind in {AgreementItemKind.DISCOUNT, AgreementItemKind.CREDIT}:
            if self.unit_amount_cents >= 0:
                raise ValueError(
                    "discount and credit items require a negative signed amount"
                )
        elif self.unit_amount_cents < 0:
            raise ValueError(
                "service and allowance items require a non-negative amount"
            )
        if self.service_end_at is not None and (
            self.service_start_at is None
            or self.service_end_at <= self.service_start_at
        ):
            raise ValueError("item service end must follow its start")
        return self


class CommercialAgreementItemRecord(CommercialAgreementItemCreate):
    id: Annotated[StrictInt, Field(gt=0)]
    agreement_terms_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    created_at: AwareDatetime


class CommercialAgreementTermsBundle(StrictCommercialModel):
    terms: CommercialAgreementTermsRecord
    items: tuple[CommercialAgreementItemRecord, ...]


__all__ = [
    "AgreementChannel",
    "AgreementItemKind",
    "AgreementState",
    "BillingProvider",
    "CommercialAgreementCreate",
    "CommercialAgreementItemCreate",
    "CommercialAgreementItemRecord",
    "CommercialAgreementRecord",
    "CommercialAgreementTermsBundle",
    "CommercialAgreementTermsCreate",
    "CommercialAgreementTermsRecord",
]
