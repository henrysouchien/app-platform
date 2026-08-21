"""Atomic financial-ledger effects for persisted Stripe Invoice authority."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import Field

from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..flags import CommercialFlags
from ..models import StrictCommercialModel
from .stripe_invoice_allocation import (
    STRIPE_INVOICE_ALLOCATION_POLICY_VERSION,
    allocate_stripe_invoice_line,
)
from .stripe_projection_provider import StripeInvoiceSnapshot


class StripeInvoiceEffectError(RuntimeError):
    """Safe rejection at the local Invoice-effect authority boundary."""


class StripeInvoiceEffectResult(StrictCommercialModel):
    effect_id: int = Field(gt=0)
    projection_event_id: int = Field(gt=0)
    document_id: int = Field(gt=0)
    allocation_run_id: int | None = Field(default=None, gt=0)
    status_event_id: int | None = Field(default=None, gt=0)
    money_movement_ids: tuple[int, ...]
    document_created: bool
    durable_replayed: bool = False


class PostgresStripeInvoiceEffectApplier:
    """Apply one current Invoice projection without changing agreement access."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._flags = flags
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def apply(
        self, *, projection_event_id: int, snapshot: StripeInvoiceSnapshot
    ) -> StripeInvoiceEffectResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Invoice effects require a transaction")
        if not self._flags.stripe_billing_enabled:
            raise StripeInvoiceEffectError("Stripe billing is disabled")
        if snapshot.status == "draft":
            raise StripeInvoiceEffectError("Draft Invoice has no financial effect")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_stripe_invoice_effect")
            try:
                result = self._apply(cursor, projection_event_id, snapshot)
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_stripe_invoice_effect")
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_invoice_effect")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_invoice_effect")
            return result
        finally:
            cursor.close()

    def _apply(self, cursor, projection_event_id, snapshot):
        cursor.execute(
            """SELECT projection.external_event_id, projection.environment,
                      projection.external_object_id,
                      projection.observed_snapshot_sha256,
                      projection.disposition,
                      object.snapshot_sha256, object.commercial_account_id,
                      object.agreement_id
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s AND projection.object_type = 'invoice'
                  AND projection.disposition IN ('applied', 'unchanged', 'superseded')""",
            (projection_event_id,),
        )
        authority = cursor.fetchone()
        if authority is None or (
            authority[1] != snapshot.environment
            or authority[2] != snapshot.external_object_id
            or authority[3] != snapshot.snapshot_sha256
        ):
            raise StripeInvoiceEffectError("Invoice projection lineage is invalid")
        account_id, agreement_id = int(authority[6]), int(authority[7])
        cursor.execute(
            "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
            (account_id,),
        )
        if cursor.fetchone() is None:
            raise StripeInvoiceEffectError("Invoice account is missing")
        cursor.execute(
            """SELECT attempt.command_id
                 FROM commercial_checkout_attempts attempt
                 JOIN billing_provider_customers customer
                   ON customer.commercial_account_id = attempt.commercial_account_id
                  AND customer.provider = 'stripe'
                  AND customer.environment = attempt.environment
                WHERE attempt.commercial_account_id = %s
                  AND attempt.agreement_id = %s
                  AND attempt.state = 'session_created'
                  AND customer.external_customer_id = %s
                FOR UPDATE OF attempt, customer""",
            (account_id, agreement_id, snapshot.external_customer_id),
        )
        if cursor.fetchone() is None:
            raise StripeInvoiceEffectError("Invoice tenant lineage is invalid")
        cursor.execute(
            """SELECT version, external_subscription_id, currency
                 FROM commercial_agreements
                WHERE id = %s AND commercial_account_id = %s
                  AND billing_provider = 'stripe' AND billing_environment = %s
                FOR UPDATE""",
            (agreement_id, account_id, snapshot.environment),
        )
        agreement = cursor.fetchone()
        if (
            agreement is None
            or agreement[1] != snapshot.external_subscription_id
            or agreement[2] != snapshot.currency
        ):
            raise StripeInvoiceEffectError("Invoice agreement lineage is stale")
        cursor.execute(
            """SELECT projection.observed_snapshot_sha256, object.snapshot_sha256
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s
                FOR UPDATE OF projection, object""",
            (projection_event_id,),
        )
        locked = cursor.fetchone()
        if locked is None or locked[0] != snapshot.snapshot_sha256:
            raise StripeInvoiceEffectError("Invoice projection lineage is invalid")
        cursor.execute(
            """SELECT id, document_id, allocation_run_id, status_event_id,
                      money_movement_ids, document_created
                 FROM commercial_stripe_invoice_effects
                WHERE projection_event_id = %s""",
            (projection_event_id,),
        )
        replay = cursor.fetchone()
        if replay is not None:
            return StripeInvoiceEffectResult(
                effect_id=int(replay[0]), projection_event_id=projection_event_id,
                document_id=int(replay[1]), allocation_run_id=replay[2],
                status_event_id=replay[3], money_movement_ids=tuple(replay[4]),
                document_created=bool(replay[5]), durable_replayed=True,
            )
        is_current = locked[1] == snapshot.snapshot_sha256
        cursor.execute(
            """SELECT id FROM commercial_billing_documents
                WHERE provider = 'stripe' AND environment = %s
                  AND external_document_id = %s
                FOR UPDATE""",
            (snapshot.environment, snapshot.external_object_id),
        )
        existing = cursor.fetchone()
        if existing is None and not is_current:
            raise StripeInvoiceEffectError("Superseded Invoice has no durable document")
        document_created = existing is None
        allocation_run_id = None
        line_effects = ()
        if document_created:
            document_id, allocation_run_id, line_effects = self._create_document(
                cursor, account_id, agreement_id, snapshot
            )
        else:
            document_id = int(existing[0])
            self._validate_document(cursor, document_id, account_id, agreement_id, snapshot)
        status_event_id = None
        payment_effects: tuple[tuple[int, object], ...] = ()
        if is_current:
            status_event_id = self._append_status(
                cursor, document_id, authority[0], snapshot
            )
            payment_effects = self._append_payments(
                cursor, document_id, account_id, agreement_id, snapshot
            )
        movement_ids = tuple(item[0] for item in payment_effects)
        disposition = "applied" if (
            document_created or status_event_id is not None or movement_ids
        ) else "unchanged"
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id,
                commercial_account_id=account_id,
                agreement_id=agreement_id,
                actor_type="stripe",
                actor_id=authority[0],
                action="commercial.billing.stripe_invoice_effect",
                target_type="commercial_billing_document",
                target_id=str(document_id),
                reason_code="stripe.invoice.projected",
                after={
                    "account_id": account_id,
                    "agreement_id": agreement_id,
                    "content_sha256": snapshot.snapshot_sha256,
                    "result_code": "applied",
                },
            ),
        )
        cursor.execute(
            """INSERT INTO commercial_stripe_invoice_effects (
                   projection_event_id, commercial_account_id, agreement_id,
                   environment, external_invoice_id, snapshot_sha256,
                   invoice_status, disposition, document_id, document_created, allocation_run_id,
                   status_event_id, money_movement_ids, audit_event_id
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id""",
            (projection_event_id, account_id, agreement_id, snapshot.environment,
             snapshot.external_object_id, snapshot.snapshot_sha256, snapshot.status,
             disposition,
             document_id, document_created, allocation_run_id, status_event_id,
             list(movement_ids), str(audit_id)),
        )
        effect_id = int(cursor.fetchone()[0])
        for line_id, line, allocation in line_effects:
            cursor.execute(
                """INSERT INTO commercial_stripe_invoice_line_effects (
                       invoice_effect_id, billing_line_id, external_line_id,
                       price_code, net_consideration_ex_tax_cents, tax_cents,
                       service_period_start_at, service_period_end_at,
                       snapshot_sha256
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (effect_id, line_id, line.external_line_id, line.price_code,
                 line.net_consideration_ex_tax_cents, line.tax_cents,
                 allocation.service_period_start_at,
                 allocation.service_period_end_at, snapshot.snapshot_sha256),
            )
        for movement_id, payment in payment_effects:
            cursor.execute(
                """INSERT INTO commercial_stripe_invoice_payment_effects (
                       invoice_effect_id, money_movement_id,
                       external_invoice_payment_id, external_payment_intent_id,
                       external_charge_id,
                       amount_paid_cents, paid_at, snapshot_sha256
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (effect_id, movement_id, payment.external_invoice_payment_id,
                 payment.external_payment_intent_id, payment.external_charge_id,
                 payment.amount_paid_cents, payment.paid_at,
                 snapshot.snapshot_sha256),
            )
        return StripeInvoiceEffectResult(
            effect_id=effect_id, projection_event_id=projection_event_id,
            document_id=document_id, allocation_run_id=allocation_run_id,
            status_event_id=status_event_id, money_movement_ids=movement_ids,
            document_created=document_created,
        )

    def _create_document(self, cursor, account_id, agreement_id, snapshot):
        issued_at = snapshot.finalized_at or snapshot.provider_created_at
        cursor.execute(
            """INSERT INTO commercial_billing_documents (
                   event_id, provider, environment, external_document_id,
                   agreement_id, commercial_account_id, document_kind,
                   currency, issued_at, metadata
               ) VALUES (%s, 'stripe', %s, %s, %s, %s, 'invoice', %s, %s,
                   jsonb_build_object('snapshot_sha256', %s,
                                      'allocation_policy', %s))
            RETURNING id""",
            (str(uuid4()), snapshot.environment, snapshot.external_object_id,
             agreement_id, account_id, snapshot.currency, issued_at,
             snapshot.snapshot_sha256, STRIPE_INVOICE_ALLOCATION_POLICY_VERSION),
        )
        document_id = int(cursor.fetchone()[0])
        line_results = []
        for line in snapshot.lines:
            allocation = allocate_stripe_invoice_line(line)
            terms_id = self._resolve_terms(
                cursor, account_id, agreement_id, line.price_code,
                allocation.service_period_start_at,
                allocation.service_period_end_at,
            )
            cursor.execute(
                """INSERT INTO commercial_billing_lines (
                       event_id, document_id, agreement_id, commercial_account_id,
                       external_line_id, agreement_terms_id, price_code,
                       net_consideration_ex_tax_cents, tax_cents,
                       service_period_start_at, service_period_end_at, metadata
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       jsonb_build_object('provider_period_was_instant', %s,
                                          'stripe_price_id', %s,
                                          'proration', %s))
                RETURNING id""",
                (str(uuid4()), document_id, agreement_id, account_id,
                 line.external_line_id, terms_id, line.price_code,
                 line.net_consideration_ex_tax_cents, line.tax_cents,
                 allocation.service_period_start_at, allocation.service_period_end_at,
                 allocation.provider_period_was_instant, line.stripe_price_id,
                 line.proration),
            )
            line_results.append((int(cursor.fetchone()[0]), line, allocation))
        cursor.execute(
            """INSERT INTO commercial_revenue_allocation_runs (
                   event_id, document_id, version, state
               ) VALUES (%s, %s, 1, 'draft') RETURNING id""",
            (str(uuid4()), document_id),
        )
        allocation_run_id = int(cursor.fetchone()[0])
        for line_id, _line, allocation in line_results:
            for period in allocation.periods:
                cursor.execute(
                    """INSERT INTO commercial_revenue_allocations (
                           allocation_run_id, document_id, billing_line_id,
                           period_start_at, period_end_at, recognized_revenue_cents
                       ) VALUES (%s, %s, %s, %s, %s, %s)""",
                    (allocation_run_id, document_id, line_id,
                     period.period_start_at, period.period_end_at,
                     period.signed_cents),
                )
        cursor.execute(
            "UPDATE commercial_revenue_allocation_runs SET state = 'final' WHERE id = %s",
            (allocation_run_id,),
        )
        return document_id, allocation_run_id, tuple(line_results)

    @staticmethod
    def _resolve_terms(cursor, account_id, agreement_id, price_code, start, end):
        cursor.execute(
            """SELECT terms.id
                 FROM commercial_agreement_terms terms
                WHERE terms.agreement_id = %s
                  AND terms.commercial_account_id = %s
                  AND terms.sealed_at IS NOT NULL
                  AND terms.effective_from <= %s
                  AND (terms.effective_until IS NULL OR terms.effective_until >= %s)
                  AND EXISTS (
                      SELECT 1 FROM commercial_agreement_items item
                       WHERE item.agreement_terms_id = terms.id
                         AND item.agreement_id = terms.agreement_id
                         AND item.commercial_account_id = terms.commercial_account_id
                         AND item.price_code = %s
                  )
                FOR SHARE OF terms""",
            (agreement_id, account_id, start, end, price_code),
        )
        rows = cursor.fetchall()
        if len(rows) != 1:
            raise StripeInvoiceEffectError("Invoice line agreement terms are unavailable")
        return int(rows[0][0])

    @staticmethod
    def _validate_document(cursor, document_id, account_id, agreement_id, snapshot):
        cursor.execute(
            """SELECT currency FROM commercial_billing_documents
                WHERE id = %s AND agreement_id = %s AND commercial_account_id = %s
                  AND provider = 'stripe' AND environment = %s
                  AND external_document_id = %s""",
            (document_id, agreement_id, account_id, snapshot.environment,
             snapshot.external_object_id),
        )
        row = cursor.fetchone()
        if row is None or row[0] != snapshot.currency:
            raise StripeInvoiceEffectError("Invoice document lineage is invalid")
        cursor.execute(
            """SELECT external_line_id, price_code, net_consideration_ex_tax_cents,
                      tax_cents, service_period_start_at, service_period_end_at,
                      metadata->>'stripe_price_id',
                      (metadata->>'proration')::BOOLEAN,
                      (metadata->>'provider_period_was_instant')::BOOLEAN
                 FROM commercial_billing_lines WHERE document_id = %s""",
            (document_id,),
        )
        local = {row[0]: row[1:] for row in cursor.fetchall()}
        expected = {}
        for line in snapshot.lines:
            allocation = allocate_stripe_invoice_line(line)
            expected[line.external_line_id] = (
                line.price_code, line.net_consideration_ex_tax_cents, line.tax_cents,
                allocation.service_period_start_at, allocation.service_period_end_at,
                line.stripe_price_id, line.proration,
                allocation.provider_period_was_instant,
            )
        if local != expected:
            raise StripeInvoiceEffectError("Invoice immutable lines changed")

    @staticmethod
    def _status(snapshot):
        return snapshot.status

    def _append_status(self, cursor, document_id, external_event_id, snapshot):
        status = self._status(snapshot)
        effective_at = {
            "open": snapshot.finalized_at,
            "paid": snapshot.paid_at,
            "void": snapshot.voided_at,
            "uncollectible": snapshot.marked_uncollectible_at,
        }.get(status)
        if effective_at is None:
            raise StripeInvoiceEffectError("Invoice status transition is incomplete")
        cursor.execute(
            """SELECT status FROM commercial_billing_document_status_events
                WHERE document_id = %s
                ORDER BY effective_at DESC, received_at DESC, id DESC LIMIT 1""",
            (document_id,),
        )
        current = cursor.fetchone()
        if current is not None and current[0] == status:
            return None
        cursor.execute(
            """INSERT INTO commercial_billing_document_status_events (
                   event_id, document_id, provider, environment,
                   source_event_id, status, effective_at,
                   metadata
               ) VALUES (%s, %s, 'stripe', %s, %s, %s, %s,
                         jsonb_build_object('snapshot_sha256', %s))
            RETURNING id""",
            (str(uuid4()), document_id, snapshot.environment, external_event_id,
             status, effective_at, snapshot.snapshot_sha256),
        )
        return int(cursor.fetchone()[0])

    @staticmethod
    def _append_payments(cursor, document_id, account_id, agreement_id, snapshot):
        movement_ids = []
        for payment in snapshot.payments:
            if payment.status != "paid" or not payment.amount_paid_cents:
                continue
            cursor.execute(
                """SELECT id, signed_amount_cents, occurred_at, document_id,
                          agreement_id, commercial_account_id, currency,
                          metadata->>'invoice_payment_id',
                          metadata->>'charge_id'
                     FROM commercial_money_movements
                    WHERE provider = 'stripe' AND environment = %s
                      AND external_object_type = 'payment_intent'
                      AND external_object_id = %s
                      AND movement_kind = 'cash_receipt'
                    FOR UPDATE""",
                (snapshot.environment, payment.external_payment_intent_id),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing[1:] != (
                    payment.amount_paid_cents, payment.paid_at, document_id,
                    agreement_id, account_id, snapshot.currency,
                    payment.external_invoice_payment_id,
                    payment.external_charge_id,
                ):
                    raise StripeInvoiceEffectError("Invoice payment movement changed")
                continue
            cursor.execute(
                """INSERT INTO commercial_money_movements (
                       event_id, provider, environment, agreement_id,
                       commercial_account_id, document_id, external_object_type,
                       external_object_id, movement_kind, signed_amount_cents,
                       currency, occurred_at,
                       metadata
                   ) VALUES (%s, 'stripe', %s, %s, %s, %s, 'payment_intent',
                             %s, 'cash_receipt', %s, %s, %s,
                             jsonb_build_object('invoice_payment_id', %s,
                                                'charge_id', %s,
                                                'snapshot_sha256', %s))
                RETURNING id""",
                (str(uuid4()), snapshot.environment, agreement_id, account_id,
                 document_id, payment.external_payment_intent_id,
                 payment.amount_paid_cents, snapshot.currency, payment.paid_at,
                 payment.external_invoice_payment_id, payment.external_charge_id,
                 snapshot.snapshot_sha256),
            )
            movement_ids.append((int(cursor.fetchone()[0]), payment))
        return tuple(movement_ids)


__all__ = [
    "PostgresStripeInvoiceEffectApplier",
    "StripeInvoiceEffectError",
    "StripeInvoiceEffectResult",
]
