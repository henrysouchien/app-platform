"""Atomic billing, revenue, and disposition effects for Stripe Credit Notes."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import Field

from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..flags import CommercialFlags
from ..models import StrictCommercialModel
from .stripe_credit_note_policy import (
    StripeCreditNoteInvoiceLineEvidence,
    StripeCreditNoteRefundEvidence,
    StripePriorCreditNoteLineEvidence,
    decide_stripe_credit_note_effect,
)
from .stripe_projection_provider import StripeCreditNoteSnapshot


class StripeCreditNoteEffectError(RuntimeError):
    """Safe rejection at the Credit Note-effect authority boundary."""


class StripeCreditNoteEffectResult(StrictCommercialModel):
    effect_id: int = Field(gt=0)
    projection_event_id: int = Field(gt=0)
    document_id: int = Field(gt=0)
    allocation_run_id: int | None = Field(default=None, gt=0)
    status_event_id: int | None = Field(default=None, gt=0)
    money_movement_id: int | None = Field(default=None, gt=0)
    disposition: str
    reason_code: str
    document_created: bool
    durable_replayed: bool = False


class PostgresStripeCreditNoteEffectApplier:
    """Apply one current Credit Note projection without changing access."""

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
        self, *, projection_event_id: int, snapshot: StripeCreditNoteSnapshot
    ) -> StripeCreditNoteEffectResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Credit Note effects require a transaction")
        if not self._flags.stripe_billing_enabled:
            raise StripeCreditNoteEffectError("Stripe billing is disabled")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_stripe_credit_note_effect")
            try:
                result = self._apply(cursor, projection_event_id, snapshot)
            except BaseException:
                cursor.execute(
                    "ROLLBACK TO SAVEPOINT commercial_stripe_credit_note_effect"
                )
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_credit_note_effect")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_credit_note_effect")
            return result
        finally:
            cursor.close()

    def _apply(self, cursor, projection_event_id, snapshot):
        cursor.execute(
            """SELECT projection.external_event_id, projection.environment,
                      projection.external_object_id,
                      projection.observed_snapshot_sha256,
                      projection.disposition, object.commercial_account_id,
                      object.agreement_id, object.snapshot_sha256,
                      object.external_customer_id
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s
                  AND projection.object_type = 'credit_note'""",
            (projection_event_id,),
        )
        authority = cursor.fetchone()
        if authority is None or (
            authority[1] != snapshot.environment
            or authority[2] != snapshot.external_object_id
            or authority[3] != snapshot.snapshot_sha256
            or authority[8] != snapshot.external_customer_id
        ):
            raise StripeCreditNoteEffectError(
                "Credit Note projection lineage is invalid"
            )
        replay = self._read_replay(cursor, projection_event_id, snapshot)
        if replay is not None:
            return replay
        account_id, agreement_id = int(authority[5]), int(authority[6])
        cursor.execute(
            "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
            (account_id,),
        )
        if cursor.fetchone() is None:
            raise StripeCreditNoteEffectError("Credit Note account is missing")
        replay = self._read_replay(cursor, projection_event_id, snapshot)
        if replay is not None:
            return replay
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
            raise StripeCreditNoteEffectError("Credit Note tenant lineage is invalid")
        cursor.execute(
            """SELECT version, currency FROM commercial_agreements
                WHERE id = %s AND commercial_account_id = %s
                  AND billing_provider = 'stripe' AND billing_environment = %s
                FOR UPDATE""",
            (agreement_id, account_id, snapshot.environment),
        )
        agreement = cursor.fetchone()
        if agreement is None or agreement[1] != snapshot.currency:
            raise StripeCreditNoteEffectError(
                "Credit Note agreement lineage is invalid"
            )

        cursor.execute(
            """SELECT effect.document_id
                 FROM commercial_stripe_invoice_effects effect
                 JOIN commercial_billing_documents document
                   ON document.id = effect.document_id
                  AND document.agreement_id = effect.agreement_id
                  AND document.commercial_account_id = effect.commercial_account_id
                  AND document.provider = 'stripe'
                  AND document.environment = effect.environment
                  AND document.external_document_id = effect.external_invoice_id
                  AND document.document_kind = 'invoice'
                WHERE effect.environment = %s
                  AND effect.external_invoice_id = %s
                  AND effect.commercial_account_id = %s
                  AND effect.agreement_id = %s
                  AND effect.document_created
                FOR UPDATE OF effect, document""",
            (
                snapshot.environment,
                snapshot.external_invoice_id,
                account_id,
                agreement_id,
            ),
        )
        invoice_rows = cursor.fetchall()
        if len(invoice_rows) != 1:
            raise StripeCreditNoteEffectError(
                "Credit Note Invoice lineage is missing or ambiguous"
            )
        invoice_document_id = int(invoice_rows[0][0])
        credited_ids = tuple(line.credited_invoice_line_id for line in snapshot.lines)
        cursor.execute(
            """SELECT effect_line.external_line_id,
                      effect_line.net_consideration_ex_tax_cents,
                      effect_line.tax_cents,
                      effect_line.service_period_start_at,
                      effect_line.service_period_end_at,
                      effect_line.billing_line_id, billing_line.agreement_terms_id,
                      billing_line.price_code
                 FROM commercial_stripe_invoice_line_effects effect_line
                 JOIN commercial_stripe_invoice_effects effect
                   ON effect.id = effect_line.invoice_effect_id
                  AND effect.document_id = %s AND effect.document_created
                 JOIN commercial_billing_lines billing_line
                   ON billing_line.id = effect_line.billing_line_id
                  AND billing_line.document_id = effect.document_id
                WHERE effect_line.external_line_id = ANY(%s)
                ORDER BY effect_line.external_line_id
                FOR UPDATE OF effect_line, effect, billing_line""",
            (invoice_document_id, list(credited_ids)),
        )
        original_rows = cursor.fetchall()
        original_by_external = {str(row[0]): row for row in original_rows}
        if set(original_by_external) != set(credited_ids):
            raise StripeCreditNoteEffectError("Credit Note line lineage is invalid")
        invoice_line_evidence = tuple(
            StripeCreditNoteInvoiceLineEvidence(
                external_invoice_line_id=row[0],
                net_consideration_ex_tax_cents=row[1],
                tax_cents=row[2],
                service_period_start_at=row[3],
                service_period_end_at=row[4],
            )
            for row in original_rows
        )

        cursor.execute(
            """SELECT id FROM commercial_billing_documents
                WHERE provider = 'stripe' AND environment = %s
                  AND external_document_id = %s FOR UPDATE""",
            (snapshot.environment, snapshot.external_object_id),
        )
        existing_document = cursor.fetchone()
        document_id = int(existing_document[0]) if existing_document else None
        prior_document_status = None
        if document_id is not None:
            cursor.execute(
                """SELECT status FROM commercial_billing_current_document_status
                    WHERE document_id = %s""",
                (document_id,),
            )
            prior_status_row = cursor.fetchone()
            if prior_status_row is None or prior_status_row[0] not in (
                "credited",
                "void",
            ):
                raise StripeCreditNoteEffectError(
                    "Credit Note document status is invalid"
                )
            prior_document_status = (
                "issued" if prior_status_row[0] == "credited" else "void"
            )

        cursor.execute(
            """SELECT effect.external_credit_note_id,
                      line.external_credit_note_line_id,
                      line.credited_invoice_line_id,
                      -line.signed_net_consideration_ex_tax_cents,
                      line.tax_credit_cents
                 FROM commercial_stripe_credit_note_line_effects line
                 JOIN commercial_stripe_credit_note_effects effect
                   ON effect.id = line.credit_note_effect_id
                 JOIN commercial_billing_current_document_status status
                   ON status.document_id = effect.document_id
                  AND status.status = 'credited'
                WHERE effect.environment = %s
                  AND effect.invoice_document_id = %s
                  AND effect.external_credit_note_id <> %s
                ORDER BY effect.external_credit_note_id,
                         line.external_credit_note_line_id
                FOR UPDATE OF effect, line""",
            (
                snapshot.environment,
                invoice_document_id,
                snapshot.external_object_id,
            ),
        )
        prior_active_lines = tuple(
            StripePriorCreditNoteLineEvidence(
                external_credit_note_id=row[0],
                external_credit_note_line_id=row[1],
                credited_invoice_line_id=row[2],
                net_credit_ex_tax_cents=row[3],
                tax_credit_cents=row[4],
            )
            for row in cursor.fetchall()
        )

        refund_ids = tuple(item.external_refund_id for item in snapshot.refunds)
        linked_refunds, refund_effect_ids = self._load_refunds(
            cursor, snapshot, invoice_document_id, refund_ids
        )
        if document_id is not None:
            self._validate_creation_effect(cursor, document_id, snapshot)
        cursor.execute(
            """SELECT projection.observed_snapshot_sha256,
                      object.snapshot_sha256, projection.disposition
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s FOR UPDATE OF projection, object""",
            (projection_event_id,),
        )
        locked = cursor.fetchone()
        if (
            locked is None
            or locked[0] != snapshot.snapshot_sha256
            or locked[1] != snapshot.snapshot_sha256
            or locked[2] == "superseded"
        ):
            raise StripeCreditNoteEffectError("Credit Note projection is not current")
        decision = decide_stripe_credit_note_effect(
            snapshot=snapshot,
            invoice_lines=invoice_line_evidence,
            prior_active_credit_lines=prior_active_lines,
            linked_refunds=linked_refunds,
            prior_document_status=prior_document_status,
            evaluated_at=self._clock(),
        )
        document_created = decision.create_document
        allocation_run_id = None
        line_results = ()
        if document_created:
            document_id, allocation_run_id, line_results = self._create_document(
                cursor,
                account_id,
                agreement_id,
                snapshot,
                decision,
                original_by_external,
            )
        elif document_id is None:
            raise StripeCreditNoteEffectError("Credit Note document is missing")
        else:
            self._validate_document(
                cursor,
                document_id,
                account_id,
                agreement_id,
                snapshot,
                decision,
                original_by_external,
            )
        status_event_id = self._append_status(
            cursor, document_id, authority[0], snapshot, decision
        )
        movement_id = self._apply_out_of_band_movement(
            cursor, document_id, account_id, agreement_id, snapshot, decision
        )
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id,
                commercial_account_id=account_id,
                agreement_id=agreement_id,
                actor_type="stripe",
                actor_id=authority[0],
                action="commercial.billing.stripe_credit_note_effect",
                target_type="commercial_billing_document",
                target_id=str(document_id),
                reason_code=decision.reason_code,
                after={
                    "account_id": account_id,
                    "agreement_id": agreement_id,
                    "content_sha256": snapshot.snapshot_sha256,
                    "result_code": "applied",
                },
            ),
        )
        disposition = (
            "applied"
            if (
                document_created
                or status_event_id is not None
                or decision.append_out_of_band_credit_movement
            )
            else "unchanged"
        )
        cursor.execute(
            """INSERT INTO commercial_stripe_credit_note_effects (
                   projection_event_id, commercial_account_id, agreement_id,
                   invoice_document_id, document_id, environment,
                   external_credit_note_id, external_invoice_id, snapshot_sha256,
                   credit_note_status, credit_type, credit_reason,
                   pre_payment_cents, post_payment_cents,
                   out_of_band_cents, customer_balance_credit_cents,
                   linked_refund_cents, external_refund_ids,
                   linked_refund_amounts, provider_created_at,
                   effective_at, status_effective_at,
                   disposition, reason_code, policy_version,
                   document_created, allocation_run_id, status_event_id,
                   money_movement_id, refund_effect_ids, audit_event_id
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (
                projection_event_id,
                account_id,
                agreement_id,
                invoice_document_id,
                document_id,
                snapshot.environment,
                snapshot.external_object_id,
                snapshot.external_invoice_id,
                snapshot.snapshot_sha256,
                snapshot.status,
                snapshot.credit_type,
                snapshot.reason,
                snapshot.pre_payment_cents,
                snapshot.post_payment_cents,
                snapshot.out_of_band_cents,
                snapshot.customer_balance_credit_cents,
                sum(item.amount_cents for item in snapshot.refunds),
                [
                    item.external_refund_id
                    for item in sorted(
                        snapshot.refunds, key=lambda item: item.external_refund_id
                    )
                ],
                [
                    item.amount_cents
                    for item in sorted(
                        snapshot.refunds, key=lambda item: item.external_refund_id
                    )
                ],
                snapshot.provider_created_at,
                snapshot.effective_at,
                snapshot.effective_at
                if snapshot.status == "issued"
                else snapshot.voided_at,
                disposition,
                decision.reason_code,
                decision.policy_version,
                document_created,
                allocation_run_id,
                status_event_id,
                movement_id,
                list(refund_effect_ids),
                str(audit_id),
            ),
        )
        effect_id = int(cursor.fetchone()[0])
        for billing_line_id, original_billing_line_id, line in line_results:
            cursor.execute(
                """INSERT INTO commercial_stripe_credit_note_line_effects (
                       credit_note_effect_id, billing_line_id,
                       original_billing_line_id, external_credit_note_line_id,
                       credited_invoice_line_id,
                       signed_net_consideration_ex_tax_cents, tax_credit_cents,
                       snapshot_sha256
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    effect_id,
                    billing_line_id,
                    original_billing_line_id,
                    line.external_credit_note_line_id,
                    line.credited_invoice_line_id,
                    line.signed_net_consideration_ex_tax_cents,
                    line.tax_credit_cents,
                    snapshot.snapshot_sha256,
                ),
            )
        for refund_effect_id in refund_effect_ids:
            cursor.execute(
                """INSERT INTO commercial_stripe_credit_note_refund_effects (
                       credit_note_effect_id, refund_effect_id
                   ) VALUES (%s, %s)""",
                (effect_id, refund_effect_id),
            )
        return StripeCreditNoteEffectResult(
            effect_id=effect_id,
            projection_event_id=projection_event_id,
            document_id=document_id,
            allocation_run_id=allocation_run_id,
            status_event_id=status_event_id,
            money_movement_id=movement_id,
            disposition=disposition,
            reason_code=decision.reason_code,
            document_created=document_created,
        )

    @staticmethod
    def _validate_creation_effect(cursor, document_id, snapshot):
        cursor.execute(
            """SELECT credit_type, credit_reason, pre_payment_cents,
                      post_payment_cents, out_of_band_cents,
                      customer_balance_credit_cents, linked_refund_cents,
                      external_refund_ids, linked_refund_amounts,
                      provider_created_at, effective_at
                 FROM commercial_stripe_credit_note_effects
                WHERE document_id = %s AND document_created FOR UPDATE""",
            (document_id,),
        )
        creation = cursor.fetchone()
        ordered_refunds = sorted(
            snapshot.refunds, key=lambda item: item.external_refund_id
        )
        expected = (
            snapshot.credit_type,
            snapshot.reason,
            snapshot.pre_payment_cents,
            snapshot.post_payment_cents,
            snapshot.out_of_band_cents,
            snapshot.customer_balance_credit_cents,
            sum(item.amount_cents for item in ordered_refunds),
            [item.external_refund_id for item in ordered_refunds],
            [item.amount_cents for item in ordered_refunds],
            snapshot.provider_created_at,
            snapshot.effective_at,
        )
        if creation != expected:
            raise StripeCreditNoteEffectError(
                "Credit Note immutable disposition changed"
            )

    @staticmethod
    def _load_refunds(cursor, snapshot, invoice_document_id, refund_ids):
        if not refund_ids:
            return (), ()
        cursor.execute(
            """SELECT effect.id, effect.external_refund_id, effect.amount_cents,
                      movement.signed_amount_cents, movement.currency,
                      movement.occurred_at
                 FROM commercial_stripe_refund_effects effect
                 JOIN commercial_money_movements movement
                   ON movement.id = effect.money_movement_id
                WHERE effect.environment = %s
                  AND effect.external_refund_id = ANY(%s)
                  AND effect.document_id = %s
                  AND effect.refund_status = 'succeeded'
                  AND effect.disposition = 'applied'
                ORDER BY effect.external_refund_id, effect.id DESC
                FOR UPDATE OF effect, movement""",
            (snapshot.environment, list(refund_ids), invoice_document_id),
        )
        rows = []
        seen = set()
        for row in cursor.fetchall():
            if row[1] not in seen:
                rows.append(row)
                seen.add(row[1])
        if {str(row[1]) for row in rows} != set(refund_ids):
            raise StripeCreditNoteEffectError(
                "Credit Note linked Refund effects are incomplete"
            )
        return (
            tuple(
                StripeCreditNoteRefundEvidence(
                    external_refund_id=row[1],
                    external_invoice_id=snapshot.external_invoice_id,
                    amount_cents=row[2],
                    signed_movement_cents=row[3],
                    currency=row[4],
                    occurred_at=row[5],
                )
                for row in rows
            ),
            tuple(int(row[0]) for row in rows),
        )

    @staticmethod
    def _create_document(
        cursor, account_id, agreement_id, snapshot, decision, original_by_external
    ):
        cursor.execute(
            """INSERT INTO commercial_billing_documents (
                   event_id, provider, environment, external_document_id,
                   agreement_id, commercial_account_id, document_kind,
                   currency, issued_at, metadata
               ) VALUES (%s, 'stripe', %s, %s, %s, %s, 'credit_note',
                         %s, %s, jsonb_build_object(
                             'created_snapshot_sha256', %s,
                             'policy_version', %s,
                             'external_invoice_id', %s)) RETURNING id""",
            (
                str(uuid4()),
                snapshot.environment,
                snapshot.external_object_id,
                agreement_id,
                account_id,
                snapshot.currency,
                snapshot.effective_at,
                snapshot.snapshot_sha256,
                decision.policy_version,
                snapshot.external_invoice_id,
            ),
        )
        document_id = int(cursor.fetchone()[0])
        line_results = []
        cursor.execute(
            """INSERT INTO commercial_revenue_allocation_runs (
                   event_id, document_id, version, state
               ) VALUES (%s, %s, 1, 'draft') RETURNING id""",
            (str(uuid4()), document_id),
        )
        allocation_run_id = int(cursor.fetchone()[0])
        for line in decision.lines:
            original = original_by_external[line.credited_invoice_line_id]
            cursor.execute(
                """INSERT INTO commercial_billing_lines (
                       event_id, document_id, agreement_id, commercial_account_id,
                       external_line_id, agreement_terms_id, price_code,
                       net_consideration_ex_tax_cents, tax_cents,
                       service_period_start_at, service_period_end_at, metadata
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       jsonb_build_object('credited_invoice_line_id', %s,
                                          'original_billing_line_id', %s))
                RETURNING id""",
                (
                    str(uuid4()),
                    document_id,
                    agreement_id,
                    account_id,
                    line.external_credit_note_line_id,
                    original[6],
                    original[7],
                    line.signed_net_consideration_ex_tax_cents,
                    line.tax_credit_cents,
                    line.service_period_start_at,
                    line.service_period_end_at,
                    line.credited_invoice_line_id,
                    original[5],
                ),
            )
            billing_line_id = int(cursor.fetchone()[0])
            for period in line.periods:
                cursor.execute(
                    """INSERT INTO commercial_revenue_allocations (
                           allocation_run_id, document_id, billing_line_id,
                           period_start_at, period_end_at,
                           recognized_revenue_cents
                       ) VALUES (%s, %s, %s, %s, %s, %s)""",
                    (
                        allocation_run_id,
                        document_id,
                        billing_line_id,
                        period.period_start_at,
                        period.period_end_at,
                        period.signed_cents,
                    ),
                )
            line_results.append((billing_line_id, int(original[5]), line))
        cursor.execute(
            "UPDATE commercial_revenue_allocation_runs SET state = 'final' WHERE id = %s",
            (allocation_run_id,),
        )
        return document_id, allocation_run_id, tuple(line_results)

    @staticmethod
    def _validate_document(
        cursor,
        document_id,
        account_id,
        agreement_id,
        snapshot,
        decision,
        original_by_external,
    ):
        cursor.execute(
            """SELECT currency, metadata->>'external_invoice_id'
                 FROM commercial_billing_documents
                WHERE id = %s AND agreement_id = %s
                  AND commercial_account_id = %s AND provider = 'stripe'
                  AND environment = %s AND external_document_id = %s
                  AND document_kind = 'credit_note'""",
            (
                document_id,
                agreement_id,
                account_id,
                snapshot.environment,
                snapshot.external_object_id,
            ),
        )
        document = cursor.fetchone()
        if document != (snapshot.currency, snapshot.external_invoice_id):
            raise StripeCreditNoteEffectError("Credit Note immutable document changed")
        cursor.execute(
            """SELECT external_line_id, net_consideration_ex_tax_cents,
                      tax_cents, service_period_start_at, service_period_end_at,
                      metadata->>'credited_invoice_line_id',
                      (metadata->>'original_billing_line_id')::BIGINT
                 FROM commercial_billing_lines WHERE document_id = %s""",
            (document_id,),
        )
        local = {str(row[0]): row[1:] for row in cursor.fetchall()}
        expected = {}
        snapshot_by_id = {line.external_line_id: line for line in snapshot.lines}
        for external_line_id, line in snapshot_by_id.items():
            original = original_by_external[line.credited_invoice_line_id]
            expected[external_line_id] = (
                -line.net_ex_tax_cents,
                line.tax_cents,
                original[3],
                original[4],
                line.credited_invoice_line_id,
                int(original[5]),
            )
        if local != expected:
            raise StripeCreditNoteEffectError("Credit Note immutable lines changed")

    @staticmethod
    def _append_status(cursor, document_id, external_event_id, snapshot, decision):
        if not decision.append_status:
            return None
        local_status = "credited" if snapshot.status == "issued" else "void"
        effective_at = (
            snapshot.effective_at if snapshot.status == "issued" else snapshot.voided_at
        )
        if effective_at is None:
            raise StripeCreditNoteEffectError("Credit Note status time is incomplete")
        cursor.execute(
            """INSERT INTO commercial_billing_document_status_events (
                   event_id, document_id, provider, environment,
                   source_event_id, status, effective_at, metadata
               ) VALUES (%s, %s, 'stripe', %s, %s, %s, %s,
                         jsonb_build_object('snapshot_sha256', %s,
                                            'policy_version', %s))
            RETURNING id""",
            (
                str(uuid4()),
                document_id,
                snapshot.environment,
                external_event_id,
                local_status,
                effective_at,
                snapshot.snapshot_sha256,
                decision.policy_version,
            ),
        )
        return int(cursor.fetchone()[0])

    @staticmethod
    def _apply_out_of_band_movement(
        cursor, document_id, account_id, agreement_id, snapshot, decision
    ):
        cursor.execute(
            """SELECT id, signed_amount_cents, occurred_at, document_id,
                      agreement_id, commercial_account_id, currency,
                      metadata->>'snapshot_sha256', metadata->>'policy_version',
                      metadata->>'external_invoice_id'
                 FROM commercial_money_movements
                WHERE provider = 'stripe' AND environment = %s
                  AND external_object_type = 'credit_note'
                  AND external_object_id = %s AND movement_kind = 'credit'
                FOR UPDATE""",
            (snapshot.environment, snapshot.external_object_id),
        )
        existing = cursor.fetchone()
        if snapshot.out_of_band_cents == 0:
            if existing is not None:
                raise StripeCreditNoteEffectError(
                    "Credit Note unexpected credit movement exists"
                )
            return None
        expected = (
            -snapshot.out_of_band_cents,
            snapshot.effective_at,
            document_id,
            agreement_id,
            account_id,
            snapshot.currency,
        )
        if existing is not None:
            if existing[1:7] != expected or existing[8:] != (
                decision.policy_version,
                snapshot.external_invoice_id,
            ):
                raise StripeCreditNoteEffectError("Credit Note movement changed")
            return int(existing[0])
        if not decision.append_out_of_band_credit_movement:
            raise StripeCreditNoteEffectError("Credit Note movement is missing")
        cursor.execute(
            """INSERT INTO commercial_money_movements (
                   event_id, provider, environment, agreement_id,
                   commercial_account_id, document_id, external_object_type,
                   external_object_id, movement_kind, signed_amount_cents,
                   currency, occurred_at, metadata
               ) VALUES (%s, 'stripe', %s, %s, %s, %s, 'credit_note', %s,
                         'credit', %s, %s, %s,
                         jsonb_build_object('snapshot_sha256', %s,
                                            'policy_version', %s,
                                            'external_invoice_id', %s))
            RETURNING id""",
            (
                str(uuid4()),
                snapshot.environment,
                agreement_id,
                account_id,
                document_id,
                snapshot.external_object_id,
                decision.signed_credit_movement_cents,
                snapshot.currency,
                decision.credit_movement_occurred_at,
                snapshot.snapshot_sha256,
                decision.policy_version,
                snapshot.external_invoice_id,
            ),
        )
        return int(cursor.fetchone()[0])

    @staticmethod
    def _read_replay(cursor, projection_event_id, snapshot):
        cursor.execute(
            """SELECT id, document_id, allocation_run_id, status_event_id,
                      money_movement_id, disposition, reason_code,
                      document_created, snapshot_sha256, external_invoice_id
                 FROM commercial_stripe_credit_note_effects
                WHERE projection_event_id = %s""",
            (projection_event_id,),
        )
        replay = cursor.fetchone()
        if replay is None:
            return None
        if replay[8:] != (snapshot.snapshot_sha256, snapshot.external_invoice_id):
            raise StripeCreditNoteEffectError("Credit Note effect replay changed")
        return StripeCreditNoteEffectResult(
            effect_id=int(replay[0]),
            projection_event_id=projection_event_id,
            document_id=int(replay[1]),
            allocation_run_id=replay[2],
            status_event_id=replay[3],
            money_movement_id=replay[4],
            disposition=str(replay[5]),
            reason_code=str(replay[6]),
            document_created=bool(replay[7]),
            durable_replayed=True,
        )


__all__ = [
    "PostgresStripeCreditNoteEffectApplier",
    "StripeCreditNoteEffectError",
    "StripeCreditNoteEffectResult",
]
