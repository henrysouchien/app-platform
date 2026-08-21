"""Atomic signed-cash effects for persisted Stripe Refund authority."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import Field

from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..flags import CommercialFlags
from ..models import StrictCommercialModel
from .stripe_projection_provider import StripeRefundSnapshot
from .stripe_refund_policy import (
    StripePriorRefundMovement,
    StripeRefundEffectDecision,
    StripeRefundPaymentEvidence,
    decide_stripe_refund_effect,
    validate_stripe_refund_evaluation,
)


class StripeRefundEffectError(RuntimeError):
    """Safe rejection at the Refund-effect authority boundary."""


class StripeRefundEffectResult(StrictCommercialModel):
    effect_id: int = Field(gt=0)
    projection_event_id: int = Field(gt=0)
    money_movement_id: int | None = Field(default=None, gt=0)
    disposition: str
    reason_code: str
    durable_replayed: bool = False


class PostgresStripeRefundEffectApplier:
    """Apply one current Refund projection without changing revenue or access."""

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
        self, *, projection_event_id: int, snapshot: StripeRefundSnapshot
    ) -> StripeRefundEffectResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Refund effects require a transaction")
        if not self._flags.stripe_billing_enabled:
            raise StripeRefundEffectError("Stripe billing is disabled")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_stripe_refund_effect")
            try:
                result = self._apply(cursor, projection_event_id, snapshot)
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_stripe_refund_effect")
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_refund_effect")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_refund_effect")
            return result
        finally:
            cursor.close()

    def _apply(self, cursor, projection_event_id, snapshot):
        cursor.execute(
            """SELECT projection.external_event_id, projection.environment,
                      projection.external_object_id,
                      projection.observed_snapshot_sha256,
                      projection.disposition, object.commercial_account_id,
                      object.agreement_id, object.snapshot_sha256
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s AND projection.object_type = 'refund'""",
            (projection_event_id,),
        )
        authority = cursor.fetchone()
        if authority is None or (
            authority[1] != snapshot.environment
            or authority[2] != snapshot.external_object_id
            or authority[3] != snapshot.snapshot_sha256
        ):
            raise StripeRefundEffectError("Refund projection lineage is invalid")
        replay = self._read_replay(cursor, projection_event_id, snapshot)
        if replay is not None:
            return replay
        account_id, agreement_id = int(authority[5]), int(authority[6])
        cursor.execute(
            "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
            (account_id,),
        )
        if cursor.fetchone() is None:
            raise StripeRefundEffectError("Refund account is missing")
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
                  AND customer.external_customer_id = (
                      SELECT external_customer_id
                        FROM commercial_stripe_projection_objects
                       WHERE environment = %s AND object_type = 'refund'
                         AND external_object_id = %s)
                FOR UPDATE OF attempt, customer""",
            (account_id, agreement_id, snapshot.environment,
             snapshot.external_object_id),
        )
        if cursor.fetchone() is None:
            raise StripeRefundEffectError("Refund tenant lineage is invalid")
        cursor.execute(
            """SELECT version FROM commercial_agreements
                WHERE id = %s AND commercial_account_id = %s
                  AND billing_provider = 'stripe' AND billing_environment = %s
                FOR UPDATE""",
            (agreement_id, account_id, snapshot.environment),
        )
        if cursor.fetchone() is None:
            raise StripeRefundEffectError("Refund agreement lineage is invalid")
        cursor.execute(
            "SELECT to_regclass('commercial_stripe_payment_lineage') IS NOT NULL"
        )
        payment_lineage = (
            "commercial_stripe_payment_lineage"
            if cursor.fetchone()[0]
            else "commercial_stripe_invoice_payment_effects"
        )
        cursor.execute(
            f"""SELECT movement.id, movement.document_id,
                      movement.signed_amount_cents, movement.currency,
                      movement.occurred_at, payment.external_charge_id
                 FROM commercial_money_movements movement
                 JOIN {payment_lineage} payment
                   ON payment.money_movement_id = movement.id
                  AND payment.external_payment_intent_id = %s
                  AND payment.external_charge_id = %s
                WHERE movement.provider = 'stripe' AND movement.environment = %s
                  AND movement.external_object_type = 'payment_intent'
                  AND movement.external_object_id = %s
                  AND movement.movement_kind = 'cash_receipt'
                  AND movement.commercial_account_id = %s
                  AND movement.agreement_id = %s
                FOR UPDATE OF movement""",
            (snapshot.external_payment_intent_id, snapshot.external_charge_id,
             snapshot.environment, snapshot.external_payment_intent_id,
             account_id, agreement_id),
        )
        payment = cursor.fetchone()
        if payment is None or payment[1] is None:
            raise StripeRefundEffectError("Refund payment lineage is invalid")
        payment_movement_id, document_id = int(payment[0]), int(payment[1])
        cursor.execute(
            """SELECT external_object_id, signed_amount_cents, occurred_at,
                      metadata->>'payment_intent_id', metadata->>'charge_id'
                 FROM commercial_money_movements
                WHERE provider = 'stripe' AND environment = %s
                  AND movement_kind = 'refund'
                  AND metadata->>'payment_intent_id' = %s
                ORDER BY id FOR UPDATE""",
            (snapshot.environment, snapshot.external_payment_intent_id),
        )
        prior_refunds = tuple(
            StripePriorRefundMovement(
                external_refund_id=row[0],
                external_payment_intent_id=row[3],
                external_charge_id=row[4],
                signed_amount_cents=row[1], currency=payment[3], occurred_at=row[2],
            )
            for row in cursor.fetchall()
        )
        cursor.execute(
            """SELECT projection.observed_snapshot_sha256, object.snapshot_sha256,
                      projection.disposition
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
            raise StripeRefundEffectError("Refund projection is not current")
        cursor.execute(
            """SELECT money_movement_id FROM commercial_stripe_refund_effects
                WHERE environment = %s AND external_refund_id = %s
                  AND external_payment_intent_id = %s AND external_charge_id = %s
                  AND snapshot_sha256 = %s AND refund_status = 'succeeded'
                  AND amount_cents = %s AND money_movement_id IS NOT NULL
                ORDER BY id LIMIT 1""",
            (snapshot.environment, snapshot.external_object_id,
             snapshot.external_payment_intent_id, snapshot.external_charge_id,
             snapshot.snapshot_sha256, snapshot.amount_cents),
        )
        prior_exact = cursor.fetchone()
        repaired_exact = None
        if payment_lineage == "commercial_stripe_payment_lineage":
            cursor.execute(
                """SELECT movement.id
                     FROM commercial_money_movements movement
                     JOIN commercial_stripe_movement_repair_executions execution
                       ON execution.money_movement_id = movement.id
                      AND execution.movement_kind = 'refund'
                      AND execution.external_object_id = %s
                      AND execution.external_payment_intent_id = %s
                      AND execution.external_charge_id = %s
                    WHERE movement.provider = 'stripe'
                      AND movement.environment = %s
                      AND movement.external_object_type = 'refund'
                      AND movement.external_object_id = %s
                      AND movement.movement_kind = 'refund'
                      AND movement.signed_amount_cents = %s
                      AND movement.occurred_at = %s
                    FOR UPDATE OF movement""",
                (
                    snapshot.external_object_id,
                    snapshot.external_payment_intent_id,
                    snapshot.external_charge_id,
                    snapshot.environment,
                    snapshot.external_object_id,
                    -snapshot.amount_cents,
                    snapshot.provider_created_at,
                ),
            )
            repaired_exact = cursor.fetchone()
        exact = prior_exact or repaired_exact
        movement_id = int(exact[0]) if exact is not None else None
        evaluated_at = self._clock()
        validate_stripe_refund_evaluation(snapshot, evaluated_at)
        if movement_id is not None:
            decision = StripeRefundEffectDecision(
                append_refund_movement=True,
                signed_amount_cents=-snapshot.amount_cents,
                occurred_at=snapshot.provider_created_at,
                reason_code="stripe.refund.succeeded",
            )
        else:
            decision = decide_stripe_refund_effect(
                snapshot=snapshot,
                payment=StripeRefundPaymentEvidence(
                    external_payment_intent_id=snapshot.external_payment_intent_id,
                    external_charge_id=payment[5], amount_paid_cents=payment[2],
                    currency=payment[3], paid_at=payment[4],
                ),
                prior_refunds=prior_refunds,
                evaluated_at=evaluated_at,
            )
        if decision.append_refund_movement and movement_id is None:
            cursor.execute(
                """INSERT INTO commercial_money_movements (
                       event_id, provider, environment, agreement_id,
                       commercial_account_id, document_id, external_object_type,
                       external_object_id, movement_kind, signed_amount_cents,
                       currency, occurred_at, metadata
                   ) VALUES (%s, 'stripe', %s, %s, %s, %s, 'refund', %s,
                       'refund', %s, 'USD', %s,
                       jsonb_build_object('payment_intent_id', %s, 'charge_id', %s,
                                          'payment_movement_id', %s,
                                          'snapshot_sha256', %s,
                                          'policy_version', %s)) RETURNING id""",
                (str(uuid4()), snapshot.environment, agreement_id, account_id,
                 document_id, snapshot.external_object_id,
                 decision.signed_amount_cents, decision.occurred_at,
                 snapshot.external_payment_intent_id, snapshot.external_charge_id,
                 payment_movement_id, snapshot.snapshot_sha256,
                 decision.policy_version),
            )
            movement_id = int(cursor.fetchone()[0])
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id, commercial_account_id=account_id,
                agreement_id=agreement_id, actor_type="stripe", actor_id=authority[0],
                action="commercial.billing.stripe_refund_effect",
                target_type="commercial_money_movement",
                target_id=str(movement_id or snapshot.external_object_id),
                reason_code=decision.reason_code,
                after={"account_id": account_id, "agreement_id": agreement_id,
                       "content_sha256": snapshot.snapshot_sha256,
                       "result_code": "applied"},
            ),
        )
        disposition = "applied" if movement_id is not None else "unchanged"
        cursor.execute(
            """INSERT INTO commercial_stripe_refund_effects (
                   projection_event_id, commercial_account_id, agreement_id,
                   document_id, environment, external_refund_id,
                   external_payment_intent_id, external_charge_id, snapshot_sha256,
                   refund_status, amount_cents, disposition, reason_code,
                   policy_version, money_movement_id, audit_event_id
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s) RETURNING id""",
            (projection_event_id, account_id, agreement_id, document_id,
             snapshot.environment, snapshot.external_object_id,
             snapshot.external_payment_intent_id, snapshot.external_charge_id,
             snapshot.snapshot_sha256, snapshot.status, snapshot.amount_cents,
             disposition, decision.reason_code, decision.policy_version,
             movement_id, str(audit_id)),
        )
        return StripeRefundEffectResult(
            effect_id=int(cursor.fetchone()[0]),
            projection_event_id=projection_event_id,
            money_movement_id=movement_id, disposition=disposition,
            reason_code=decision.reason_code,
        )

    @staticmethod
    def _read_replay(cursor, projection_event_id, snapshot):
        cursor.execute(
            """SELECT id, money_movement_id, disposition, reason_code,
                      snapshot_sha256, external_payment_intent_id, external_charge_id
                 FROM commercial_stripe_refund_effects
                WHERE projection_event_id = %s""",
            (projection_event_id,),
        )
        replay = cursor.fetchone()
        if replay is None:
            return None
        if replay[4:] != (
            snapshot.snapshot_sha256,
            snapshot.external_payment_intent_id,
            snapshot.external_charge_id,
        ):
            raise StripeRefundEffectError("Refund effect replay does not match")
        return StripeRefundEffectResult(
            effect_id=int(replay[0]), projection_event_id=projection_event_id,
            money_movement_id=replay[1], disposition=str(replay[2]),
            reason_code=str(replay[3]), durable_replayed=True,
        )


__all__ = [
    "PostgresStripeRefundEffectApplier",
    "StripeRefundEffectError",
    "StripeRefundEffectResult",
]
