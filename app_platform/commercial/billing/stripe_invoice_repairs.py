"""Approved, attested recovery of one fully missing Stripe Invoice graph."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
import json
import secrets
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, PrivateAttr, StrictBool

from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..authority import CommercialRole, record_change_execution
from ..authority_store import PostgresChangeRequestStore, load_named_operator
from ..flags import CommercialFlags
from ..models import Sha256Digest, StrictCommercialModel
from .stripe_invoice_allocation import (
    STRIPE_INVOICE_ALLOCATION_POLICY_VERSION,
    allocate_stripe_invoice_line,
)
from .stripe_projection_provider import StripeInvoiceSnapshot
from .stripe_reconciliation import (
    StripeMonetaryObservation,
    StripeMonetaryReconciliationExpectation,
    StripeReconciliationAuthority,
    load_stripe_reconciliation_authority,
)


_PROCESS_ATTESTATION_KEY = secrets.token_bytes(32)
_PROCESS_ATTESTATION_CAPABILITY = object()


class StripeInvoiceRepairError(RuntimeError):
    """Approved Invoice repair authority is absent, stale, or unsafe."""


class StripeInvoiceRepairPreparation(StrictCommercialModel):
    request_id: UUID
    intent_id: UUID
    source_finding_id: UUID
    authority_sha256: Sha256Digest
    environment: Literal["dev", "staging", "prod"]
    billing_environment: Literal["test", "live"]
    commercial_account_id: int = Field(gt=0)
    external_invoice_id: str = Field(pattern=r"^in_[A-Za-z0-9]{5,252}$")
    expected_snapshot_sha256: Sha256Digest
    monetary_expectation: StripeMonetaryReconciliationExpectation
    subscription_ids_by_agreement: dict[UUID, str]


class StripeInvoiceRepairObservation(StrictCommercialModel):
    provider_observation: StripeMonetaryObservation
    invoice_snapshot: StripeInvoiceSnapshot
    database_attestation_document: dict
    database_attestation_key_id: UUID
    database_attestation_sha256: Sha256Digest
    _process_attestation: str | None = PrivateAttr(default=None)

    @classmethod
    def _from_provider(
        cls,
        *,
        provider_observation: StripeMonetaryObservation,
        invoice_snapshot: StripeInvoiceSnapshot,
        database_attestation_document: dict,
        database_attestation_key_id: UUID,
        database_attestation_sha256: str,
        capability: object,
    ) -> "StripeInvoiceRepairObservation":
        if capability is not _PROCESS_ATTESTATION_CAPABILITY:
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair provider authority is invalid"
            )
        result = cls(
            provider_observation=provider_observation,
            invoice_snapshot=invoice_snapshot,
            database_attestation_document=database_attestation_document,
            database_attestation_key_id=database_attestation_key_id,
            database_attestation_sha256=database_attestation_sha256,
        )
        result._process_attestation = hmac.digest(
            _PROCESS_ATTESTATION_KEY, result._attestation_body(), "sha256"
        ).hex()
        return result

    def has_provider_attestation(self) -> bool:
        expected = hmac.digest(
            _PROCESS_ATTESTATION_KEY, self._attestation_body(), "sha256"
        ).hex()
        return self._process_attestation is not None and hmac.compare_digest(
            self._process_attestation, expected
        )

    def _attestation_body(self) -> bytes:
        return (
            f"{self.provider_observation.content_sha256}|"
            f"{self.invoice_snapshot.external_object_id}|"
            f"{self.invoice_snapshot.snapshot_sha256}|"
            f"{self.provider_observation.observed_at.isoformat()}"
        ).encode("ascii")


class StripeInvoiceRepairResult(StrictCommercialModel):
    execution_id: UUID
    request_id: UUID
    intent_id: UUID
    commercial_account_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    document_id: int = Field(gt=0)
    allocation_run_id: int = Field(gt=0)
    status_event_id: int = Field(gt=0)
    money_movement_ids: tuple[int, ...]
    audit_event_id: UUID
    durable_replayed: StrictBool = False


class StripeInvoiceRepairProvider:
    """Fetch a complete account observation and its exact full Invoice snapshot."""

    def __init__(
        self,
        provider: Any,
        *,
        connection: Any,
        attestation_connection: Any,
    ) -> None:
        self._provider = provider
        self._connection = connection
        self._attestation_connection = attestation_connection

    def observe(
        self, preparation: StripeInvoiceRepairPreparation
    ) -> StripeInvoiceRepairObservation:
        self._require_idle_connections()
        provider_observation, invoice = self._provider.observe_invoice_repair(
            preparation.monetary_expectation,
            subscription_ids_by_agreement=preparation.subscription_ids_by_agreement,
            external_invoice_id=preparation.external_invoice_id,
        )
        matching = tuple(
            item
            for item in provider_observation.invoices
            if item.external_invoice_id == preparation.external_invoice_id
        )
        if (
            provider_observation.evidence_completeness != "complete"
            or not provider_observation.has_provider_attestation()
            or provider_observation.environment != preparation.billing_environment
            or provider_observation.commercial_account_public_id
            != preparation.monetary_expectation.commercial_account_public_id
            or len(matching) != 1
            or matching[0].snapshot_sha256 != invoice.snapshot_sha256
            or invoice.snapshot_sha256 != preparation.expected_snapshot_sha256
            or invoice.status == "draft"
        ):
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair provider evidence changed"
            )
        provider_json = provider_observation.model_dump(mode="json")
        invoice_json = invoice.model_dump(mode="json")
        evidence_json = {
            "provider_observation": provider_json,
            "invoice_snapshot": invoice_json,
        }
        document = {
            "schema": "commercial.stripe-invoice-repair-attestation.v1",
            "request_id": str(preparation.request_id),
            "intent_id": str(preparation.intent_id),
            "source_finding_id": str(preparation.source_finding_id),
            "authority_sha256": preparation.authority_sha256,
            "runtime_environment": preparation.environment,
            "billing_environment": preparation.billing_environment,
            "commercial_account_id": preparation.commercial_account_id,
            "external_invoice_id": invoice.external_object_id,
            "invoice_snapshot_sha256": invoice.snapshot_sha256,
            "observation_content_sha256": provider_observation.content_sha256,
            "observed_at": provider_json["observed_at"],
        }
        cursor = self._attestation_connection.cursor()
        try:
            cursor.execute(
                """SELECT attestation_document, key_id, attestation_sha256
                     FROM commercial_attest_stripe_repair_snapshot(
                         %s::jsonb, %s::jsonb
                     )""",
                (json.dumps(document, sort_keys=True), json.dumps(evidence_json)),
            )
            attestation = cursor.fetchone()
        finally:
            cursor.close()
        if attestation is None:
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair database attestation is unavailable"
            )
        return StripeInvoiceRepairObservation._from_provider(
            provider_observation=provider_observation,
            invoice_snapshot=invoice,
            database_attestation_document=attestation[0],
            database_attestation_key_id=UUID(str(attestation[1])),
            database_attestation_sha256=str(attestation[2]),
            capability=_PROCESS_ATTESTATION_CAPABILITY,
        )

    def _require_idle_connections(self) -> None:
        status = getattr(self._connection, "get_transaction_status", None)
        attestation_status = getattr(
            self._attestation_connection, "get_transaction_status", None
        )
        if status is None or status() != 0:
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair provider I/O requires an idle connection"
            )
        if (
            attestation_status is None
            or attestation_status() != 0
            or not bool(getattr(self._attestation_connection, "autocommit", False))
        ):
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair attestation requires an idle connection"
            )


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class StripeInvoiceRepairService:
    """Create one approved missing Invoice graph exactly once."""

    def __init__(self, connection: Any, *, flags: CommercialFlags, clock=None) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not (
            flags.commercial_control_enabled
            and flags.commercial_reconciliation_enabled
            and flags.stripe_billing_enabled
        ):
            raise StripeInvoiceRepairError("Stripe Invoice repair is disabled")

    @_atomic
    def load_replay_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
    ) -> StripeInvoiceRepairResult | None:
        """Return a prior durable execution after rechecking operator authority."""

        self._require_operator(operator_user_id, runtime_environment, step_up_event_id)
        result = self._load_execution(
            request_id,
            environment=runtime_environment,
            billing_environment=self._billing_environment(),
        )
        return (
            result.model_copy(update={"durable_replayed": True})
            if result is not None
            else None
        )

    @_atomic
    def prepare_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
    ) -> StripeInvoiceRepairPreparation:
        self._require_operator(operator_user_id, runtime_environment, step_up_event_id)
        row = self._load_authority(request_id, runtime_environment, lock=True)
        if row is None or row[2] != "approved" or row[5] <= self._clock():
            raise StripeInvoiceRepairError(
                "Approved Stripe Invoice repair is unavailable"
            )
        authority = load_stripe_reconciliation_authority(
            self._connection,
            commercial_account_id=int(row[9]),
            environment=row[22],
        )
        return self._preparation(row, authority)

    @_atomic
    def execute_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
        observation: StripeInvoiceRepairObservation,
    ) -> StripeInvoiceRepairResult:
        operator = self._require_operator(
            operator_user_id, runtime_environment, step_up_event_id
        )
        billing_environment = self._billing_environment()
        replay = self._load_execution(
            request_id,
            environment=runtime_environment,
            billing_environment=billing_environment,
        )
        if replay is not None:
            return replay.model_copy(update={"durable_replayed": True})
        now = self._clock()
        try:
            provider_observation = StripeMonetaryObservation.model_validate(
                observation.provider_observation.model_dump(mode="python")
            )
            invoice = StripeInvoiceSnapshot.model_validate(
                observation.invoice_snapshot.model_dump(mode="python")
            )
        except Exception:
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair observation is invalid"
            ) from None
        if (
            not observation.has_provider_attestation()
            or provider_observation.observed_at < now - timedelta(minutes=15)
            or provider_observation.observed_at > now + timedelta(minutes=5)
            or provider_observation.evidence_completeness != "complete"
        ):
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair observation is not fresh"
            )
        row = self._load_authority(request_id, runtime_environment, lock=True)
        if row is not None and row[2] == "executed":
            replay = self._load_execution(
                request_id,
                environment=runtime_environment,
                billing_environment=billing_environment,
            )
            if replay is not None:
                return replay.model_copy(update={"durable_replayed": True})
        if row is None or row[2] != "approved" or row[5] <= now:
            raise StripeInvoiceRepairError(
                "Approved Stripe Invoice repair is unavailable"
            )
        authority = load_stripe_reconciliation_authority(
            self._connection,
            commercial_account_id=int(row[9]),
            environment=row[22],
        )
        preparation = self._preparation(row, authority)
        self._validate_observation(preparation, provider_observation, invoice)
        agreement_id = self._lock_agreement(preparation, invoice)
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT id FROM commercial_billing_documents
                    WHERE provider = 'stripe' AND environment = %s
                      AND external_document_id = %s FOR UPDATE""",
                (billing_environment, invoice.external_object_id),
            )
            if cursor.fetchone() is not None:
                raise StripeInvoiceRepairError(
                    "Stripe Invoice repair document already exists"
                )
        finally:
            cursor.close()
        execution_id = uuid4()
        (
            document_id,
            allocation_run_id,
            status_event_id,
            line_results,
            payment_results,
        ) = self._create_graph(
            preparation=preparation,
            invoice=invoice,
            agreement_id=agreement_id,
            execution_id=execution_id,
        )
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=preparation.commercial_account_id,
                agreement_id=agreement_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.stripe_invoice_repair.execute",
                target_type="commercial_stripe_repair_intent",
                target_id=str(preparation.intent_id),
                reason_code=row[4],
                after={
                    "account_id": preparation.commercial_account_id,
                    "agreement_id": agreement_id,
                    "content_sha256": invoice.snapshot_sha256,
                    "request_id": str(request_id),
                    "result_code": "applied",
                },
                request_id=str(request_id),
            ),
        )
        provider_json = provider_observation.model_dump(mode="json")
        invoice_json = invoice.model_dump(mode="json")
        movement_ids = tuple(item[0] for item in payment_results)
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_stripe_invoice_repair_executions (
                       execution_id, request_id, intent_id, source_finding_id,
                       commercial_account_id, agreement_id, document_id,
                       allocation_run_id, status_event_id, money_movement_ids,
                       environment, billing_environment, external_invoice_id,
                       invoice_snapshot_json, invoice_snapshot_sha256,
                       provider_observation_json, observation_content_sha256,
                       provider_observed_at, provider_attestation_document,
                       provider_attestation_key_id, provider_attestation_sha256,
                       actor_user_id, executor_step_up_event_id, audit_event_id
                   ) VALUES (
                       %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                       %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                   )""",
                (
                    str(execution_id),
                    str(request_id),
                    str(preparation.intent_id),
                    str(preparation.source_finding_id),
                    preparation.commercial_account_id,
                    agreement_id,
                    document_id,
                    allocation_run_id,
                    status_event_id,
                    list(movement_ids),
                    runtime_environment,
                    billing_environment,
                    invoice.external_object_id,
                    json.dumps(invoice_json),
                    invoice.snapshot_sha256,
                    json.dumps(provider_json),
                    provider_observation.content_sha256,
                    provider_observation.observed_at,
                    json.dumps(observation.database_attestation_document),
                    str(observation.database_attestation_key_id),
                    observation.database_attestation_sha256,
                    operator_user_id,
                    str(step_up_event_id),
                    str(audit_event_id),
                ),
            )
            for line_id, line, allocation in line_results:
                cursor.execute(
                    """INSERT INTO commercial_stripe_invoice_repair_line_evidence (
                           repair_execution_id, billing_line_id,
                           external_line_id, line_snapshot_json,
                           service_period_start_at, service_period_end_at
                       ) VALUES (%s,%s,%s,%s,%s,%s)""",
                    (
                        str(execution_id),
                        line_id,
                        line.external_line_id,
                        json.dumps(line.model_dump(mode="json")),
                        allocation.service_period_start_at,
                        allocation.service_period_end_at,
                    ),
                )
                for period in allocation.periods:
                    cursor.execute(
                        """INSERT INTO
                               commercial_stripe_invoice_repair_allocation_evidence (
                                   repair_execution_id, allocation_run_id,
                                   billing_line_id, period_start_at, period_end_at,
                                   recognized_revenue_cents
                               ) VALUES (%s,%s,%s,%s,%s,%s)""",
                        (
                            str(execution_id),
                            allocation_run_id,
                            line_id,
                            period.period_start_at,
                            period.period_end_at,
                            period.signed_cents,
                        ),
                    )
            for movement_id, payment in payment_results:
                cursor.execute(
                    """INSERT INTO commercial_stripe_invoice_repair_payment_evidence (
                           repair_execution_id, money_movement_id,
                           external_invoice_payment_id,
                           external_payment_intent_id, external_charge_id,
                           amount_paid_cents, paid_at
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        str(execution_id),
                        movement_id,
                        payment.external_invoice_payment_id,
                        payment.external_payment_intent_id,
                        payment.external_charge_id,
                        payment.amount_paid_cents,
                        payment.paid_at,
                    ),
                )
        finally:
            cursor.close()
        record_change_execution(
            request_id,
            store=PostgresChangeRequestStore(self._connection),
            operator=operator,
            succeeded=True,
            result_code="applied",
            audit_event_id=audit_event_id,
            now=now,
        )
        return StripeInvoiceRepairResult(
            execution_id=execution_id,
            request_id=request_id,
            intent_id=preparation.intent_id,
            commercial_account_id=preparation.commercial_account_id,
            agreement_id=agreement_id,
            document_id=document_id,
            allocation_run_id=allocation_run_id,
            status_event_id=status_event_id,
            money_movement_ids=movement_ids,
            audit_event_id=audit_event_id,
        )

    def _create_graph(
        self,
        *,
        preparation: StripeInvoiceRepairPreparation,
        invoice: StripeInvoiceSnapshot,
        agreement_id: int,
        execution_id: UUID,
    ):
        issued_at = invoice.finalized_at or invoice.provider_created_at
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_billing_documents (
                       event_id, provider, environment, external_document_id,
                       agreement_id, commercial_account_id, document_kind,
                       currency, issued_at, metadata
                   ) VALUES (%s,'stripe',%s,%s,%s,%s,'invoice','USD',%s,
                       jsonb_build_object(
                           'repair_execution_id', %s,
                           'repair_request_id', %s,
                           'snapshot_sha256', %s,
                           'allocation_policy', %s
                       )) RETURNING id""",
                (
                    str(uuid4()),
                    preparation.billing_environment,
                    invoice.external_object_id,
                    agreement_id,
                    preparation.commercial_account_id,
                    issued_at,
                    str(execution_id),
                    str(preparation.request_id),
                    invoice.snapshot_sha256,
                    STRIPE_INVOICE_ALLOCATION_POLICY_VERSION,
                ),
            )
            document_id = int(cursor.fetchone()[0])
            line_results = []
            for line in invoice.lines:
                allocation = allocate_stripe_invoice_line(line)
                terms_id = self._resolve_terms(
                    cursor,
                    preparation.commercial_account_id,
                    agreement_id,
                    line.price_code,
                    allocation.service_period_start_at,
                    allocation.service_period_end_at,
                )
                cursor.execute(
                    """INSERT INTO commercial_billing_lines (
                           event_id, document_id, agreement_id,
                           commercial_account_id, external_line_id,
                           agreement_terms_id, price_code,
                           net_consideration_ex_tax_cents, tax_cents,
                           service_period_start_at, service_period_end_at, metadata
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                           jsonb_build_object(
                               'repair_execution_id', %s,
                               'snapshot_sha256', %s,
                               'provider_period_was_instant', %s,
                               'stripe_price_id', %s,
                               'proration', %s
                           )) RETURNING id""",
                    (
                        str(uuid4()),
                        document_id,
                        agreement_id,
                        preparation.commercial_account_id,
                        line.external_line_id,
                        terms_id,
                        line.price_code,
                        line.net_consideration_ex_tax_cents,
                        line.tax_cents,
                        allocation.service_period_start_at,
                        allocation.service_period_end_at,
                        str(execution_id),
                        invoice.snapshot_sha256,
                        allocation.provider_period_was_instant,
                        line.stripe_price_id,
                        line.proration,
                    ),
                )
                line_results.append((int(cursor.fetchone()[0]), line, allocation))
            cursor.execute(
                """INSERT INTO commercial_revenue_allocation_runs (
                       event_id, document_id, version, state
                   ) VALUES (%s,%s,1,'draft') RETURNING id""",
                (str(uuid4()), document_id),
            )
            allocation_run_id = int(cursor.fetchone()[0])
            for line_id, _line, allocation in line_results:
                for period in allocation.periods:
                    cursor.execute(
                        """INSERT INTO commercial_revenue_allocations (
                               allocation_run_id, document_id, billing_line_id,
                               period_start_at, period_end_at,
                               recognized_revenue_cents
                           ) VALUES (%s,%s,%s,%s,%s,%s)""",
                        (
                            allocation_run_id,
                            document_id,
                            line_id,
                            period.period_start_at,
                            period.period_end_at,
                            period.signed_cents,
                        ),
                    )
            cursor.execute(
                """UPDATE commercial_revenue_allocation_runs
                      SET state = 'final' WHERE id = %s""",
                (allocation_run_id,),
            )
            effective_at = {
                "open": invoice.finalized_at,
                "paid": invoice.paid_at,
                "void": invoice.voided_at,
                "uncollectible": invoice.marked_uncollectible_at,
            }.get(invoice.status)
            if effective_at is None:
                raise StripeInvoiceRepairError(
                    "Stripe Invoice repair status evidence is incomplete"
                )
            cursor.execute(
                """INSERT INTO commercial_billing_document_status_events (
                       event_id, document_id, provider, environment,
                       source_event_id, status, effective_at, metadata
                   ) VALUES (%s,%s,'stripe',%s,%s,%s,%s,
                       jsonb_build_object(
                           'repair_execution_id', %s,
                           'snapshot_sha256', %s
                       )) RETURNING id""",
                (
                    str(uuid4()),
                    document_id,
                    preparation.billing_environment,
                    f"repair:{execution_id}",
                    invoice.status,
                    effective_at,
                    str(execution_id),
                    invoice.snapshot_sha256,
                ),
            )
            status_event_id = int(cursor.fetchone()[0])
            payment_results = []
            for payment in invoice.payments:
                if payment.status != "paid" or not payment.amount_paid_cents:
                    continue
                cursor.execute(
                    """INSERT INTO commercial_money_movements (
                           event_id, provider, environment, agreement_id,
                           commercial_account_id, document_id,
                           external_object_type, external_object_id,
                           movement_kind, signed_amount_cents, currency,
                           occurred_at, metadata
                       ) VALUES (%s,'stripe',%s,%s,%s,%s,'payment_intent',%s,
                           'cash_receipt',%s,'USD',%s,
                           jsonb_build_object(
                               'invoice_repair_execution_id', %s,
                               'repair_request_id', %s,
                               'invoice_payment_id', %s,
                               'payment_intent_id', %s,
                               'charge_id', %s,
                               'snapshot_sha256', %s
                           )) RETURNING id""",
                    (
                        str(uuid4()),
                        preparation.billing_environment,
                        agreement_id,
                        preparation.commercial_account_id,
                        document_id,
                        payment.external_payment_intent_id,
                        payment.amount_paid_cents,
                        payment.paid_at,
                        str(execution_id),
                        str(preparation.request_id),
                        payment.external_invoice_payment_id,
                        payment.external_payment_intent_id,
                        payment.external_charge_id,
                        invoice.snapshot_sha256,
                    ),
                )
                payment_results.append((int(cursor.fetchone()[0]), payment))
        finally:
            cursor.close()
        return (
            document_id,
            allocation_run_id,
            status_event_id,
            tuple(line_results),
            tuple(payment_results),
        )

    @staticmethod
    def _resolve_terms(cursor, account_id, agreement_id, price_code, start, end):
        cursor.execute(
            """SELECT terms.id
                 FROM commercial_agreement_terms terms
                WHERE terms.agreement_id = %s
                  AND terms.commercial_account_id = %s
                  AND terms.sealed_at IS NOT NULL
                  AND terms.effective_from <= %s
                  AND (terms.effective_until IS NULL
                       OR terms.effective_until >= %s)
                  AND EXISTS (
                      SELECT 1 FROM commercial_agreement_items item
                       WHERE item.agreement_terms_id = terms.id
                         AND item.agreement_id = terms.agreement_id
                         AND item.commercial_account_id =
                             terms.commercial_account_id
                         AND item.price_code = %s
                  )
                FOR SHARE OF terms""",
            (agreement_id, account_id, start, end, price_code),
        )
        rows = cursor.fetchall()
        if len(rows) != 1:
            raise StripeInvoiceRepairError(
                "Stripe Invoice line agreement terms are unavailable"
            )
        return int(rows[0][0])

    def _preparation(
        self, row: tuple, authority: StripeReconciliationAuthority
    ) -> StripeInvoiceRepairPreparation:
        observed = row[20]
        if (
            authority.monetary is None
            or row[10] != "stripe.invoice_missing_local"
            or row[12] != "stripe_monetary.v1"
            or row[19] != {"present": False, "digest": None}
            or set(observed) != {"present", "digest"}
            or observed.get("present") is not True
            or not isinstance(observed.get("digest"), str)
        ):
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair source evidence is invalid"
            )
        return StripeInvoiceRepairPreparation(
            request_id=row[0],
            intent_id=row[6],
            source_finding_id=row[7],
            authority_sha256=row[8],
            environment=row[21],
            billing_environment=row[22],
            commercial_account_id=int(row[9]),
            external_invoice_id=row[11],
            expected_snapshot_sha256=observed["digest"],
            monetary_expectation=authority.monetary,
            subscription_ids_by_agreement=authority.subscription_ids_by_agreement,
        )

    @staticmethod
    def _validate_observation(
        preparation: StripeInvoiceRepairPreparation,
        provider_observation: StripeMonetaryObservation,
        invoice: StripeInvoiceSnapshot,
    ) -> None:
        matching = tuple(
            item
            for item in provider_observation.invoices
            if item.external_invoice_id == preparation.external_invoice_id
        )
        if (
            len(matching) != 1
            or matching[0].snapshot_sha256 != invoice.snapshot_sha256
            or provider_observation.environment != preparation.billing_environment
            or provider_observation.commercial_account_public_id
            != preparation.monetary_expectation.commercial_account_public_id
            or invoice.external_object_id != preparation.external_invoice_id
            or invoice.snapshot_sha256 != preparation.expected_snapshot_sha256
            or invoice.environment != preparation.billing_environment
            or invoice.commercial_account_public_id
            != preparation.monetary_expectation.commercial_account_public_id
            or invoice.status == "draft"
            or invoice.currency != "USD"
        ):
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair observation authority changed"
            )

    def _lock_agreement(
        self,
        preparation: StripeInvoiceRepairPreparation,
        invoice: StripeInvoiceSnapshot,
    ) -> int:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT agreement.id
                     FROM commercial_agreements agreement
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id =
                          agreement.commercial_account_id
                      AND customer.provider = 'stripe'
                      AND customer.environment = agreement.billing_environment
                     JOIN commercial_checkout_attempts attempt
                       ON attempt.agreement_id = agreement.id
                      AND attempt.commercial_account_id =
                          agreement.commercial_account_id
                      AND attempt.environment = agreement.billing_environment
                      AND attempt.state = 'session_created'
                    WHERE agreement.public_id = %s
                      AND agreement.commercial_account_id = %s
                      AND agreement.billing_provider = 'stripe'
                      AND agreement.billing_environment = %s
                      AND agreement.currency = 'USD'
                      AND agreement.external_subscription_id = %s
                      AND customer.external_customer_id = %s
                      AND attempt.external_customer_id = %s
                    FOR UPDATE OF agreement, attempt, customer""",
                (
                    str(invoice.agreement_public_id),
                    preparation.commercial_account_id,
                    preparation.billing_environment,
                    invoice.external_subscription_id,
                    invoice.external_customer_id,
                    invoice.external_customer_id,
                ),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if len(rows) != 1:
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair agreement lineage is invalid"
            )
        return int(rows[0][0])

    def _load_authority(self, request_id: UUID, environment: str, *, lock: bool):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT request.request_id, request.target_id, request.state,
                          request.payload_sha256, request.reason_code,
                          request.expires_at, intent.intent_id,
                          intent.source_finding_id, intent.authority_sha256,
                          intent.commercial_account_id, intent.finding_code,
                          intent.subject_id, intent.suite_code,
                          intent.fingerprint_sha256, intent.expected_sha256,
                          intent.observed_sha256, intent.source_last_seen_at,
                          finding.finding_id, finding.resolution_state,
                          finding.expected, finding.observed,
                          request.environment, customer.environment
                     FROM commercial_change_requests request
                     JOIN commercial_stripe_repair_intents intent
                       ON intent.intent_id::TEXT = request.target_id
                      AND intent.environment = request.environment
                     JOIN commercial_reconciliation_current_findings finding
                       ON finding.finding_id = intent.source_finding_id
                      AND finding.environment = intent.environment
                      AND finding.commercial_account_id =
                          intent.commercial_account_id
                      AND finding.fingerprint_sha256 = intent.fingerprint_sha256
                      AND finding.last_seen_at = intent.source_last_seen_at
                      AND finding.resolution_state = 'open'
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id =
                          intent.commercial_account_id
                      AND customer.provider = 'stripe'
                    WHERE request.request_id = %s
                      AND request.environment = %s
                      AND request.action = 'live_stripe_repair'
                      AND request.target_type =
                          'commercial_stripe_repair_intent'
                      AND request.payload_sha256 = intent.authority_sha256
                      AND request.state IN ('approved', 'executed')
                      AND intent.suite_code = 'stripe_monetary.v1'
                      AND intent.finding_code = 'stripe.invoice_missing_local'
                      AND intent.repair_code =
                          'stripe.invoice_projection_repair'
                      AND intent.subject_type = 'stripe_invoice'
                      AND customer.environment = %s"""
                + (" FOR UPDATE OF request" if lock else ""),
                (str(request_id), environment, self._billing_environment()),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _require_operator(self, user_id: int, environment: str, step_up_event_id: UUID):
        if environment != self._flags.environment:
            raise StripeInvoiceRepairError("Stripe Invoice repair environment mismatch")
        operator = load_named_operator(
            self._connection,
            user_id=user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        if CommercialRole.BILLING_OPERATOR not in operator.roles:
            raise StripeInvoiceRepairError(
                "Stripe Invoice repair operator is unauthorized"
            )
        return operator

    def _billing_environment(self) -> Literal["test", "live"]:
        return "live" if self._flags.stripe_live_mode_enabled else "test"

    def _load_execution(self, request_id, *, environment, billing_environment):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT execution_id, request_id, intent_id,
                          commercial_account_id, agreement_id, document_id,
                          allocation_run_id, status_event_id,
                          money_movement_ids, audit_event_id
                     FROM commercial_stripe_invoice_repair_executions
                    WHERE request_id = %s AND environment = %s
                      AND billing_environment = %s""",
                (str(request_id), environment, billing_environment),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        return StripeInvoiceRepairResult(
            execution_id=row[0],
            request_id=row[1],
            intent_id=row[2],
            commercial_account_id=int(row[3]),
            agreement_id=int(row[4]),
            document_id=int(row[5]),
            allocation_run_id=int(row[6]),
            status_event_id=int(row[7]),
            money_movement_ids=tuple(row[8]),
            audit_event_id=row[9],
        )

    def _run_atomic(self, operation):
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Invoice repairs require a transaction")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_stripe_invoice_repair")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_stripe_invoice_repair")
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_invoice_repair")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_invoice_repair")
            return result
        finally:
            cursor.close()


__all__ = [
    "StripeInvoiceRepairError",
    "StripeInvoiceRepairObservation",
    "StripeInvoiceRepairPreparation",
    "StripeInvoiceRepairProvider",
    "StripeInvoiceRepairResult",
    "StripeInvoiceRepairService",
]
