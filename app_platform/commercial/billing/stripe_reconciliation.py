"""Normalized, bounded Stripe evidence for provider reconciliation."""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
import re
import secrets
from typing import Any, Callable, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, PrivateAttr, model_validator

from ..models import StableCode, StrictCommercialModel, canonical_sha256
from .stripe_config import StripeDeploymentManifest
from .stripe_projection_provider import (
    StripeInvoiceSnapshot,
    StripeProjectionExpectation,
    StripeProjectionProvider,
)


_PROVIDER_ATTESTATION_KEY = secrets.token_bytes(32)
_PROVIDER_ATTESTATION_CAPABILITY = object()


class StripeReconciliationProviderError(RuntimeError):
    """Provider evidence could not be fetched or normalized safely."""


class StripeReconciliationExpectation(StrictCommercialModel):
    commercial_account_public_id: UUID
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    environment: Literal["test", "live"]


class StripeRemoteSubscription(StrictCommercialModel):
    external_subscription_id: str = Field(pattern=r"^sub_[A-Za-z0-9]{4,251}$")
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    status: Literal[
        "active", "canceled", "incomplete", "incomplete_expired", "past_due",
        "paused", "trialing", "unpaid",
    ]
    price_code: StableCode
    cancel_at_period_end: bool
    current_period_start_at: AwareDatetime
    current_period_end_at: AwareDatetime


class StripeAccountObservation(StrictCommercialModel):
    environment: Literal["test", "live"]
    commercial_account_public_id: UUID
    expected_external_customer_id: str
    matching_external_customer_ids: tuple[str, ...]
    subscriptions: tuple[StripeRemoteSubscription, ...]
    observed_at: AwareDatetime
    content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class StripeInvoiceLineObservation(StrictCommercialModel):
    external_line_id: str = Field(min_length=1, max_length=255)
    price_code: StableCode
    net_consideration_ex_tax_cents: int
    tax_cents: int = Field(ge=0)
    service_period_start_at: AwareDatetime
    service_period_end_at: AwareDatetime


class StripeInvoiceReconciliationObservation(StrictCommercialModel):
    external_invoice_id: str = Field(pattern=r"^in_[A-Za-z0-9]{5,252}$")
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    external_subscription_id: str = Field(pattern=r"^sub_[A-Za-z0-9]{4,251}$")
    status: Literal["draft", "open", "paid", "uncollectible", "void"]
    currency: Literal["USD"]
    net_consideration_ex_tax_cents: int
    tax_cents: int = Field(ge=0)
    amount_paid_cents: int = Field(ge=0)
    snapshot_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    lines: tuple[StripeInvoiceLineObservation, ...]

    @model_validator(mode="after")
    def _exact_lines(self):
        if (
            not self.lines
            or len({item.external_line_id for item in self.lines}) != len(self.lines)
            or sum(item.net_consideration_ex_tax_cents for item in self.lines)
               != self.net_consideration_ex_tax_cents
            or sum(item.tax_cents for item in self.lines) != self.tax_cents
        ):
            raise ValueError("Stripe invoice reconciliation lines do not balance")
        return self


class StripeMoneyMovementObservation(StrictCommercialModel):
    external_invoice_id: str = Field(pattern=r"^in_[A-Za-z0-9]{5,252}$")
    external_object_type: Literal[
        "payment_intent", "refund", "dispute", "balance_transaction"
    ]
    external_object_id: str = Field(min_length=5, max_length=255)
    movement_kind: Literal[
        "cash_receipt", "refund", "dispute_hold", "dispute_release", "processor_fee"
    ]
    signed_amount_cents: int
    currency: Literal["USD"]
    occurred_at: AwareDatetime
    external_invoice_payment_id: str | None = Field(
        default=None, min_length=5, max_length=255
    )
    external_payment_intent_id: str | None = Field(
        default=None, pattern=r"^pi_[A-Za-z0-9]{4,252}$"
    )
    external_charge_id: str | None = Field(
        default=None, pattern=r"^ch_[A-Za-z0-9]{4,252}$"
    )

    @model_validator(mode="after")
    def _signed_kind(self):
        positive = self.movement_kind in {"cash_receipt", "dispute_release"}
        if self.signed_amount_cents == 0 or (
            self.movement_kind != "processor_fee"
            and positive != (self.signed_amount_cents > 0)
        ):
            raise ValueError("Stripe movement reconciliation sign is invalid")
        expected_type = {
            "cash_receipt": "payment_intent", "refund": "refund",
            "dispute_hold": "dispute", "dispute_release": "dispute",
            "processor_fee": "balance_transaction",
        }[self.movement_kind]
        if self.external_object_type != expected_type:
            raise ValueError("Stripe movement reconciliation type is invalid")
        lineage = (
            self.external_invoice_payment_id,
            self.external_payment_intent_id,
            self.external_charge_id,
        )
        if any(value is not None for value in lineage) and any(
            value is None for value in lineage
        ):
            raise ValueError("Stripe movement payment lineage is incomplete")
        if (
            self.movement_kind == "cash_receipt"
            and self.external_payment_intent_id is not None
            and self.external_object_id != self.external_payment_intent_id
        ):
            raise ValueError("Stripe cash movement payment identity is invalid")
        return self


class StripeMonetaryObservation(StrictCommercialModel):
    environment: Literal["test", "live"]
    commercial_account_public_id: UUID
    invoices: tuple[StripeInvoiceReconciliationObservation, ...]
    movements: tuple[StripeMoneyMovementObservation, ...]
    evidence_completeness: Literal["partial", "complete"] = "partial"
    observed_at: AwareDatetime
    content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    _provider_attestation: str | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _unique_evidence(self):
        invoice_ids = [item.external_invoice_id for item in self.invoices]
        movement_ids = [
            (item.external_object_type, item.external_object_id, item.movement_kind)
            for item in self.movements
        ]
        if len(set(invoice_ids)) != len(invoice_ids) or len(set(movement_ids)) != len(
            movement_ids
        ):
            raise ValueError("Stripe monetary reconciliation evidence is duplicated")
        if invoice_ids != sorted(invoice_ids) or movement_ids != sorted(movement_ids):
            raise ValueError("Stripe monetary reconciliation evidence is not canonical")
        expected = canonical_sha256(
            self.model_dump(
                mode="json", exclude={"content_sha256", "observed_at"}
            )
        )
        if self.content_sha256 != "sha256:" + "0" * 64 and self.content_sha256 != expected:
            raise ValueError("Stripe monetary reconciliation digest mismatch")
        return self

    @classmethod
    def create(
        cls, *, environment: Literal["test", "live"],
        commercial_account_public_id: UUID, invoices, movements,
        observed_at: datetime,
    ) -> "StripeMonetaryObservation":
        candidate = cls(
            environment=environment,
            commercial_account_public_id=commercial_account_public_id,
            invoices=tuple(sorted(invoices, key=lambda item: item.external_invoice_id)),
            movements=tuple(sorted(movements, key=lambda item: (
                item.external_object_type, item.external_object_id, item.movement_kind
            ))),
            evidence_completeness="partial",
            observed_at=observed_at, content_sha256="sha256:" + "0" * 64,
        )
        return candidate.model_copy(update={
            "content_sha256": canonical_sha256(candidate.model_dump(
                mode="json", exclude={"content_sha256", "observed_at"}
            ))
        })

    @classmethod
    def _create_provider_complete(
        cls, *, environment: Literal["test", "live"],
        commercial_account_public_id: UUID, invoices, movements,
        observed_at: datetime, capability: object,
    ) -> "StripeMonetaryObservation":
        if capability is not _PROVIDER_ATTESTATION_CAPABILITY:
            raise StripeReconciliationProviderError(
                "Stripe complete evidence authority is invalid"
            )
        if any(
            item.external_invoice_payment_id is None
            or item.external_payment_intent_id is None
            or item.external_charge_id is None
            for item in movements
        ):
            raise StripeReconciliationProviderError(
                "Stripe complete movement payment lineage is incomplete"
            )
        candidate = cls(
            environment=environment,
            commercial_account_public_id=commercial_account_public_id,
            invoices=tuple(sorted(invoices, key=lambda item: item.external_invoice_id)),
            movements=tuple(sorted(movements, key=lambda item: (
                item.external_object_type, item.external_object_id, item.movement_kind
            ))),
            evidence_completeness="complete", observed_at=observed_at,
            content_sha256="sha256:" + "0" * 64,
        )
        candidate = candidate.model_copy(update={
            "content_sha256": canonical_sha256(candidate.model_dump(
                mode="json", exclude={"content_sha256", "observed_at"}
            ))
        })
        candidate._provider_attestation = hmac.digest(
            _PROVIDER_ATTESTATION_KEY, candidate._attestation_body(), "sha256"
        ).hex()
        return candidate

    def has_provider_attestation(self) -> bool:
        expected = hmac.digest(
            _PROVIDER_ATTESTATION_KEY, self._attestation_body(), "sha256"
        ).hex()
        return (
            self.evidence_completeness == "complete"
            and self._provider_attestation is not None
            and hmac.compare_digest(self._provider_attestation, expected)
        )

    def _attestation_body(self) -> bytes:
        return (
            f"{self.content_sha256}|{self.observed_at.isoformat()}"
        ).encode("ascii")


def assemble_stripe_monetary_observation(
    *, environment: Literal["test", "live"],
    commercial_account_public_id: UUID,
    expected_external_customer_id: str,
    invoices: tuple[StripeInvoiceSnapshot, ...],
    supplemental_movements: tuple[StripeMoneyMovementObservation, ...],
    observed_at: datetime,
) -> StripeMonetaryObservation:
    """Build partial evidence without claiming bounded provider completeness."""

    if any(
        invoice.environment != environment
        or invoice.commercial_account_public_id != commercial_account_public_id
        or invoice.external_customer_id != expected_external_customer_id
        for invoice in invoices
    ):
        raise StripeReconciliationProviderError(
            "Stripe monetary invoice authority mismatch"
        )
    invoice_ids = {invoice.external_object_id for invoice in invoices}
    if any(item.external_invoice_id not in invoice_ids for item in supplemental_movements):
        raise StripeReconciliationProviderError(
            "Stripe monetary movement invoice linkage mismatch"
        )

    normalized_invoices = tuple(
        StripeInvoiceReconciliationObservation(
            external_invoice_id=invoice.external_object_id,
            external_customer_id=invoice.external_customer_id,
            external_subscription_id=invoice.external_subscription_id,
            status=invoice.status, currency=invoice.currency,
            net_consideration_ex_tax_cents=invoice.net_consideration_ex_tax_cents,
            tax_cents=invoice.tax_cents,
            amount_paid_cents=invoice.amount_paid_cents,
            snapshot_sha256=invoice.snapshot_sha256,
            lines=tuple(StripeInvoiceLineObservation(
                external_line_id=line.external_line_id,
                price_code=line.price_code,
                net_consideration_ex_tax_cents=line.net_consideration_ex_tax_cents,
                tax_cents=line.tax_cents,
                service_period_start_at=line.service_period_start_at,
                service_period_end_at=line.service_period_end_at,
            ) for line in invoice.lines),
        ) for invoice in invoices
    )
    payment_movements = tuple(
        StripeMoneyMovementObservation(
            external_invoice_id=invoice.external_object_id,
            external_object_type="payment_intent",
            external_object_id=payment.external_payment_intent_id,
            movement_kind="cash_receipt",
            signed_amount_cents=payment.amount_paid_cents,
            currency=invoice.currency,
            occurred_at=payment.paid_at,
            external_invoice_payment_id=payment.external_invoice_payment_id,
            external_payment_intent_id=payment.external_payment_intent_id,
            external_charge_id=payment.external_charge_id,
        )
        for invoice in invoices
        for payment in invoice.payments
        if payment.status == "paid"
        and payment.amount_paid_cents is not None
        and payment.paid_at is not None
    )
    return StripeMonetaryObservation.create(
        environment=environment,
        commercial_account_public_id=commercial_account_public_id,
        invoices=normalized_invoices,
        movements=payment_movements + supplemental_movements,
        observed_at=observed_at,
    )


class StripeMonetaryReconciliationExpectation(StrictCommercialModel):
    environment: Literal["test", "live"]
    commercial_account_public_id: UUID
    external_customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    subscriptions: tuple[StripeProjectionExpectation, ...]

    @model_validator(mode="after")
    def _bound_subscriptions(self):
        if not self.subscriptions:
            raise ValueError("Stripe monetary subscriptions are empty")
        subscription_keys = [item.agreement_public_id for item in self.subscriptions]
        if len(set(subscription_keys)) != len(subscription_keys) or any(
            item.environment != self.environment
            or item.commercial_account_public_id != self.commercial_account_public_id
            or item.external_customer_id != self.external_customer_id
            for item in self.subscriptions
        ):
            raise ValueError("Stripe monetary subscription authority is invalid")
        return self


class StripeReconciliationAuthority(StrictCommercialModel):
    account: StripeReconciliationExpectation
    monetary: StripeMonetaryReconciliationExpectation | None = None
    subscription_ids_by_agreement: dict[UUID, str]


def load_stripe_reconciliation_authority(
    connection: Any, *, commercial_account_id: int,
    environment: Literal["test", "live"],
) -> StripeReconciliationAuthority:
    """Load one immutable local authority snapshot before any provider calls."""

    cursor = connection.cursor()
    try:
        cursor.execute(
            """SELECT account.public_id, customer.external_customer_id
                 FROM commercial_accounts account
                 JOIN billing_provider_customers customer
                   ON customer.commercial_account_id = account.id
                  AND customer.provider = 'stripe' AND customer.environment = %s
                WHERE account.id = %s""",
            (environment, commercial_account_id),
        )
        account = cursor.fetchone()
        if account is None:
            raise StripeReconciliationProviderError(
                "Stripe reconciliation account authority is missing"
            )
        cursor.execute(
            """SELECT agreement.public_id, agreement.external_subscription_id,
                      terms.price_code
                 FROM commercial_agreements agreement
                 JOIN commercial_agreement_terms terms
                   ON terms.agreement_id = agreement.id
                  AND terms.effective_until IS NULL
                WHERE agreement.commercial_account_id = %s
                  AND agreement.billing_provider = 'stripe'
                  AND agreement.billing_environment = %s
                  AND agreement.external_subscription_id IS NOT NULL
             ORDER BY agreement.public_id""",
            (commercial_account_id, environment),
        )
        agreements = tuple(cursor.fetchall())
    finally:
        cursor.close()
    account_public_id = UUID(str(account[0]))
    customer_id = str(account[1])
    subscriptions = tuple(
        StripeProjectionExpectation(
            environment=environment,
            commercial_account_public_id=account_public_id,
            agreement_public_id=UUID(str(row[0])),
            external_customer_id=customer_id,
            price_code=str(row[2]),
        )
        for row in agreements
    )
    return StripeReconciliationAuthority(
        account=StripeReconciliationExpectation(
            commercial_account_public_id=account_public_id,
            external_customer_id=customer_id, environment=environment,
        ),
        monetary=(
            StripeMonetaryReconciliationExpectation(
                environment=environment,
                commercial_account_public_id=account_public_id,
                external_customer_id=customer_id, subscriptions=subscriptions,
            ) if subscriptions else None
        ),
        subscription_ids_by_agreement={
            UUID(str(row[0])): str(row[1]) for row in agreements
        },
    )


class StripeSdkMonetaryReconciliationProvider:
    """Enumerate bounded account money evidence and fail closed on incompleteness."""

    _LIMIT = 100

    def __init__(
        self, client: Any, *, projection_provider: StripeProjectionProvider,
        deployment: StripeDeploymentManifest,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._client = client
        self._projection = projection_provider
        self._deployment = deployment
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def observe(
        self, expected: StripeMonetaryReconciliationExpectation,
        *, subscription_ids_by_agreement: dict[UUID, str],
    ) -> StripeMonetaryObservation:
        try:
            return self._observe(
                expected,
                subscription_ids_by_agreement=subscription_ids_by_agreement,
            )
        except StripeReconciliationProviderError:
            raise
        except Exception:
            raise StripeReconciliationProviderError(
                "Stripe monetary normalization failed"
            ) from None

    def observe_invoice_repair(
        self,
        expected: StripeMonetaryReconciliationExpectation,
        *,
        subscription_ids_by_agreement: dict[UUID, str],
        external_invoice_id: str,
    ) -> tuple[StripeMonetaryObservation, StripeInvoiceSnapshot]:
        """Return complete account evidence and its exact selected Invoice snapshot."""
        try:
            observation, invoices = self._observe_with_snapshots(
                expected,
                subscription_ids_by_agreement=subscription_ids_by_agreement,
            )
        except StripeReconciliationProviderError:
            raise
        except Exception:
            raise StripeReconciliationProviderError(
                "Stripe monetary normalization failed"
            ) from None
        matching = tuple(
            invoice
            for invoice in invoices
            if invoice.external_object_id == external_invoice_id
        )
        if len(matching) != 1:
            raise StripeReconciliationProviderError(
                "Stripe invoice repair snapshot is unavailable"
            )
        return observation, matching[0]

    def _observe(
        self, expected: StripeMonetaryReconciliationExpectation,
        *, subscription_ids_by_agreement: dict[UUID, str],
    ) -> StripeMonetaryObservation:
        observation, _invoices = self._observe_with_snapshots(
            expected,
            subscription_ids_by_agreement=subscription_ids_by_agreement,
        )
        return observation

    def _observe_with_snapshots(
        self,
        expected: StripeMonetaryReconciliationExpectation,
        *,
        subscription_ids_by_agreement: dict[UUID, str],
    ) -> tuple[StripeMonetaryObservation, tuple[StripeInvoiceSnapshot, ...]]:
        if expected.environment != self._deployment.billing_environment:
            raise StripeReconciliationProviderError(
                "Stripe monetary reconciliation environment mismatch"
            )
        expected_by_subscription = {}
        for projection_expectation in expected.subscriptions:
            subscription_id = subscription_ids_by_agreement.get(
                projection_expectation.agreement_public_id
            )
            if (
                not isinstance(subscription_id, str)
                or not re.fullmatch(r"sub_[A-Za-z0-9]{4,251}", subscription_id)
                or subscription_id in expected_by_subscription
            ):
                raise StripeReconciliationProviderError(
                    "Stripe monetary subscription mapping is invalid"
                )
            expected_by_subscription[subscription_id] = projection_expectation
        if len(expected_by_subscription) != len(expected.subscriptions):
            raise StripeReconciliationProviderError(
                "Stripe monetary subscription mapping is incomplete"
            )
        invoice_rows = self._bounded_list(
            lambda: self._client.v1.invoices.list(params={
                "customer": expected.external_customer_id, "limit": self._LIMIT,
            }),
            "invoice",
        )
        invoices = []
        movements = []
        for row in invoice_rows:
            invoice_id = _identity(row)
            parent = _field(row, "parent")
            subscription_details = _field(parent, "subscription_details")
            subscription_id = _identity(
                _field(subscription_details, "subscription")
            )
            projection_expectation = expected_by_subscription.get(subscription_id)
            if projection_expectation is None:
                raise StripeReconciliationProviderError(
                    "Stripe invoice subscription is outside reconciliation scope"
                )
            invoice = self._projection.fetch_invoice(
                invoice_id, expected=projection_expectation,
                expected_subscription_id=subscription_id,
            )
            invoices.append(invoice)
            for payment in invoice.payments:
                if payment.status != "paid":
                    continue
                if payment.external_charge_id is None:
                    raise StripeReconciliationProviderError(
                        "Stripe paid invoice charge is missing"
                    )
                movements.extend(self._charge_movements(
                    invoice, payment.external_payment_intent_id,
                    payment.external_charge_id,
                    payment.external_invoice_payment_id,
                    payment.amount_paid_cents,
                    expected.external_customer_id,
                ))
        partial = assemble_stripe_monetary_observation(
            environment=expected.environment,
            commercial_account_public_id=expected.commercial_account_public_id,
            expected_external_customer_id=expected.external_customer_id,
            invoices=tuple(invoices), supplemental_movements=tuple(movements),
            observed_at=self._clock(),
        )
        observation = StripeMonetaryObservation._create_provider_complete(
            environment=partial.environment,
            commercial_account_public_id=partial.commercial_account_public_id,
            invoices=partial.invoices, movements=partial.movements,
            observed_at=partial.observed_at,
            capability=_PROVIDER_ATTESTATION_CAPABILITY,
        )
        return observation, tuple(invoices)

    def _charge_movements(
        self, invoice: StripeInvoiceSnapshot, payment_intent_id: str,
        charge_id: str, invoice_payment_id: str, payment_amount_cents: int,
        customer_id: str,
    ) -> list[StripeMoneyMovementObservation]:
        charge = self._safe_call(
            lambda: self._client.v1.charges.retrieve(
                charge_id, params={"expand": ["balance_transaction"]}
            ), "charge",
        )
        _validate_livemode(charge, self._deployment.billing_environment)
        if (
            _identity(charge) != charge_id
            or _identity(_field(charge, "customer")) != customer_id
            or _identity(_field(charge, "payment_intent")) != payment_intent_id
            or _identity(_field(charge, "invoice")) != invoice.external_object_id
            or _field(charge, "currency") != "usd"
            or _field(charge, "paid") is not True
            or _field(charge, "amount") != payment_amount_cents
        ):
            raise StripeReconciliationProviderError("Stripe charge authority mismatch")
        result = []
        balance = _field(charge, "balance_transaction")
        if isinstance(balance, str):
            balance = self._safe_call(
                lambda: self._client.v1.balance_transactions.retrieve(balance),
                "balance transaction",
            )
        _validate_livemode(balance, self._deployment.billing_environment)
        fee = _field(balance, "fee")
        balance_id = _identity(balance)
        if (
            not isinstance(fee, int) or isinstance(fee, bool) or fee < 0
            or not balance_id or _field(balance, "currency") != "usd"
            or _identity(_field(balance, "source")) != charge_id
            or _field(balance, "type") != "charge"
        ):
            raise StripeReconciliationProviderError("Stripe charge fee is invalid")
        if fee:
            result.append(StripeMoneyMovementObservation(
                external_invoice_id=invoice.external_object_id,
                external_object_type="balance_transaction",
                external_object_id=balance_id, movement_kind="processor_fee",
                signed_amount_cents=-fee, currency="USD",
                occurred_at=_timestamp(_field(balance, "created")),
                external_invoice_payment_id=invoice_payment_id,
                external_payment_intent_id=payment_intent_id,
                external_charge_id=charge_id,
            ))
        refunds = self._bounded_list(
            lambda: self._client.v1.refunds.list(params={
                "charge": charge_id, "limit": self._LIMIT,
            }), "refund",
        )
        for row in refunds:
            refund = self._projection.fetch_refund(
                _identity(row), expected_payment_intent_id=payment_intent_id,
                expected_charge_id=charge_id,
            )
            if refund.status == "succeeded":
                balance = _field(row, "balance_transaction")
                if isinstance(balance, str):
                    balance = self._safe_call(
                        lambda balance=balance: self._client.v1.balance_transactions.retrieve(
                            balance
                        ), "refund balance transaction",
                    )
                _validate_livemode(balance, self._deployment.billing_environment)
                refund_amount = _field(balance, "amount")
                if (
                    _identity(_field(balance, "source")) != refund.external_object_id
                    or _field(balance, "currency") != "usd"
                    or _field(balance, "type") not in {"refund", "payment_refund"}
                    or refund_amount != -refund.amount_cents
                ):
                    raise StripeReconciliationProviderError(
                        "Stripe refund balance authority mismatch"
                    )
                result.append(StripeMoneyMovementObservation(
                    external_invoice_id=invoice.external_object_id,
                    external_object_type="refund",
                    external_object_id=refund.external_object_id,
                    movement_kind="refund", signed_amount_cents=-refund.amount_cents,
                    currency=refund.currency, occurred_at=refund.provider_created_at,
                    external_invoice_payment_id=invoice_payment_id,
                    external_payment_intent_id=payment_intent_id,
                    external_charge_id=charge_id,
                ))
                fee_movement = self._fee_movement(
                    invoice.external_object_id, balance,
                    invoice_payment_id=invoice_payment_id,
                    payment_intent_id=payment_intent_id,
                    charge_id=charge_id,
                )
                if fee_movement is not None:
                    result.append(fee_movement)
        disputes = self._bounded_list(
            lambda: self._client.v1.disputes.list(params={
                "charge": charge_id, "limit": self._LIMIT,
            }), "dispute",
        )
        for row in disputes:
            dispute_id = _identity(row)
            self._projection.fetch_dispute(
                dispute_id, expected_payment_intent_id=payment_intent_id,
                expected_charge_id=charge_id,
            )
            transactions = self._bounded_list(
                lambda dispute_id=dispute_id: self._client.v1.balance_transactions.list(
                    params={"source": dispute_id, "limit": self._LIMIT}
                ), "dispute balance transaction",
            )
            for transaction in transactions:
                _validate_livemode(transaction, self._deployment.billing_environment)
                amount = _field(transaction, "amount")
                if (
                    not isinstance(amount, int) or isinstance(amount, bool) or amount == 0
                    or _field(transaction, "currency") != "usd"
                    or _identity(_field(transaction, "source")) != dispute_id
                    or _field(transaction, "type") != "adjustment"
                ):
                    raise StripeReconciliationProviderError(
                        "Stripe dispute balance amount is invalid"
                    )
                result.append(StripeMoneyMovementObservation(
                    external_invoice_id=invoice.external_object_id,
                    external_object_type="dispute", external_object_id=dispute_id,
                    movement_kind="dispute_release" if amount > 0 else "dispute_hold",
                    signed_amount_cents=amount, currency="USD",
                    occurred_at=_timestamp(_field(transaction, "created")),
                    external_invoice_payment_id=invoice_payment_id,
                    external_payment_intent_id=payment_intent_id,
                    external_charge_id=charge_id,
                ))
                fee_movement = self._fee_movement(
                    invoice.external_object_id, transaction,
                    invoice_payment_id=invoice_payment_id,
                    payment_intent_id=payment_intent_id,
                    charge_id=charge_id,
                )
                if fee_movement is not None:
                    result.append(fee_movement)
        return result

    def _fee_movement(
        self, invoice_id: str, balance: Any, *, invoice_payment_id: str,
        payment_intent_id: str, charge_id: str,
    ) -> StripeMoneyMovementObservation | None:
        fee = _field(balance, "fee")
        if not isinstance(fee, int) or isinstance(fee, bool):
            raise StripeReconciliationProviderError(
                "Stripe balance transaction fee is invalid"
            )
        if fee == 0:
            return None
        balance_id = _identity(balance)
        if not isinstance(balance_id, str):
            raise StripeReconciliationProviderError(
                "Stripe fee balance identity is invalid"
            )
        return StripeMoneyMovementObservation(
            external_invoice_id=invoice_id,
            external_object_type="balance_transaction",
            external_object_id=balance_id, movement_kind="processor_fee",
            signed_amount_cents=-fee, currency="USD",
            occurred_at=_timestamp(_field(balance, "created")),
            external_invoice_payment_id=invoice_payment_id,
            external_payment_intent_id=payment_intent_id,
            external_charge_id=charge_id,
        )

    def _bounded_list(self, operation: Callable[[], Any], label: str) -> tuple[Any, ...]:
        response = self._safe_call(operation, f"{label} list")
        values = _data(response)
        if _field(response, "has_more") is not False or len(values) > self._LIMIT:
            raise StripeReconciliationProviderError(
                f"Stripe {label} enumeration is incomplete"
            )
        return values

    @staticmethod
    def _safe_call(operation: Callable[[], Any], label: str) -> Any:
        try:
            return operation()
        except StripeReconciliationProviderError:
            raise
        except Exception:
            raise StripeReconciliationProviderError(
                f"Stripe {label} fetch failed"
            ) from None
class StripeSdkAccountReconciliationProvider:
    """Fetch one bounded account observation without retaining raw Stripe objects."""

    _CUSTOMER = re.compile(r"^cus_[A-Za-z0-9]{6,250}$")
    _SUBSCRIPTION = re.compile(r"^sub_[A-Za-z0-9]{4,251}$")

    def __init__(self, client: Any, *, deployment: StripeDeploymentManifest) -> None:
        self._client = client
        self._deployment = deployment
        self._price_codes = {
            binding.price_id: price_code
            for price_code, binding in deployment.prices.items()
        }

    def observe(self, expected: StripeReconciliationExpectation) -> StripeAccountObservation:
        if expected.environment != self._deployment.billing_environment:
            raise StripeReconciliationProviderError("Stripe reconciliation environment mismatch")
        try:
            customer = self._client.v1.customers.retrieve(expected.external_customer_id)
            self._validate_customer(customer, expected)
            matches = self._matching_customers(expected)
            subscriptions = self._subscriptions(expected)
        except StripeReconciliationProviderError:
            raise
        except Exception as exc:
            raise StripeReconciliationProviderError(
                "Stripe reconciliation provider operation failed"
            ) from exc
        observed_at = datetime.now(timezone.utc)
        body = {
            "environment": expected.environment,
            "commercial_account_public_id": str(expected.commercial_account_public_id),
            "expected_external_customer_id": expected.external_customer_id,
            "matching_external_customer_ids": matches,
            "subscriptions": [item.model_dump(mode="json") for item in subscriptions],
            "observed_at": observed_at.isoformat(),
        }
        candidate = StripeAccountObservation(
            **body, content_sha256="sha256:" + "0" * 64
        )
        digest = canonical_sha256(
            candidate.model_dump(
                mode="json", exclude={"content_sha256", "observed_at"}
            )
        )
        return candidate.model_copy(update={"content_sha256": digest})

    def _matching_customers(self, expected: StripeReconciliationExpectation) -> tuple[str, ...]:
        query = (
            f"metadata['hank_commercial_account_id']:'{expected.commercial_account_public_id}' "
            f"AND metadata['hank_environment']:'{expected.environment}'"
        )
        result = self._client.v1.customers.search(params={"query": query, "limit": 100})
        if bool(_field(result, "has_more")):
            raise StripeReconciliationProviderError("Stripe customer search exceeded bound")
        data = _data(result)
        identities: list[str] = []
        for customer in data:
            self._validate_livemode(customer)
            customer_id = _field(customer, "id")
            metadata = _field(customer, "metadata")
            if (
                not isinstance(customer_id, str)
                or not self._CUSTOMER.fullmatch(customer_id)
                or not isinstance(metadata, dict)
                or metadata.get("hank_commercial_account_id")
                   != str(expected.commercial_account_public_id)
                or metadata.get("hank_environment") != expected.environment
            ):
                raise StripeReconciliationProviderError("Stripe customer search result mismatch")
            identities.append(customer_id)
        if len(set(identities)) != len(identities):
            raise StripeReconciliationProviderError("Stripe customer search duplicated identity")
        return tuple(sorted(identities))

    def _subscriptions(
        self, expected: StripeReconciliationExpectation
    ) -> tuple[StripeRemoteSubscription, ...]:
        result = self._client.v1.subscriptions.list(params={
            "customer": expected.external_customer_id, "status": "all", "limit": 100,
            "expand": ["data.items.data.price"],
        })
        if bool(_field(result, "has_more")):
            raise StripeReconciliationProviderError("Stripe subscription list exceeded bound")
        normalized: list[StripeRemoteSubscription] = []
        for subscription in _data(result):
            self._validate_livemode(subscription)
            subscription_id = _field(subscription, "id")
            customer_id = _identity(_field(subscription, "customer"))
            item_data = _data(_field(subscription, "items"))
            if (
                not isinstance(subscription_id, str)
                or not self._SUBSCRIPTION.fullmatch(subscription_id)
                or customer_id != expected.external_customer_id
                or len(item_data) != 1
                or _field(item_data[0], "quantity") != 1
            ):
                raise StripeReconciliationProviderError("Stripe subscription identity mismatch")
            price_id = _identity(_field(item_data[0], "price"))
            price_code = self._price_codes.get(price_id)
            if price_code is None:
                raise StripeReconciliationProviderError("Stripe subscription price is unmapped")
            normalized.append(StripeRemoteSubscription(
                external_subscription_id=subscription_id,
                external_customer_id=customer_id,
                status=_field(subscription, "status"),
                price_code=price_code,
                cancel_at_period_end=_field(subscription, "cancel_at_period_end"),
                current_period_start_at=_timestamp(_field(subscription, "current_period_start")),
                current_period_end_at=_timestamp(_field(subscription, "current_period_end")),
            ))
        identities = [item.external_subscription_id for item in normalized]
        if len(set(identities)) != len(identities):
            raise StripeReconciliationProviderError("Stripe subscription list duplicated identity")
        return tuple(sorted(normalized, key=lambda item: item.external_subscription_id))

    def _validate_customer(self, value: Any, expected: StripeReconciliationExpectation) -> None:
        self._validate_livemode(value)
        metadata = _field(value, "metadata")
        if (
            _field(value, "id") != expected.external_customer_id
            or not isinstance(metadata, dict)
            or metadata.get("hank_commercial_account_id")
               != str(expected.commercial_account_public_id)
            or metadata.get("hank_environment") != expected.environment
            or bool(_field(value, "deleted"))
        ):
            raise StripeReconciliationProviderError("Stripe customer authority mismatch")

    def _validate_livemode(self, value: Any) -> None:
        livemode = _field(value, "livemode")
        if not isinstance(livemode, bool) or livemode != (
            self._deployment.billing_environment == "live"
        ):
            raise StripeReconciliationProviderError("Stripe object environment mismatch")


def _field(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, dict) else getattr(value, name, None)


def _identity(value: Any) -> Any:
    return value if isinstance(value, str) else _field(value, "id")


def _data(value: Any) -> tuple[Any, ...]:
    data = _field(value, "data")
    if not isinstance(data, (list, tuple)):
        raise StripeReconciliationProviderError("Stripe list response is invalid")
    return tuple(data)


def _timestamp(value: Any) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise StripeReconciliationProviderError("Stripe timestamp is invalid")
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _validate_livemode(value: Any, environment: str) -> None:
    livemode = _field(value, "livemode")
    if not isinstance(livemode, bool) or livemode != (environment == "live"):
        raise StripeReconciliationProviderError("Stripe object environment mismatch")


__all__ = [
    "assemble_stripe_monetary_observation",
    "load_stripe_reconciliation_authority",
    "StripeAccountObservation", "StripeReconciliationExpectation",
    "StripeInvoiceLineObservation", "StripeInvoiceReconciliationObservation",
    "StripeMonetaryObservation", "StripeMoneyMovementObservation",
    "StripeMonetaryReconciliationExpectation",
    "StripeReconciliationProviderError", "StripeRemoteSubscription",
    "StripeReconciliationAuthority",
    "StripeSdkAccountReconciliationProvider",
    "StripeSdkMonetaryReconciliationProvider",
]
