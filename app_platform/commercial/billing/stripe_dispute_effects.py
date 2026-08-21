"""Atomic cash and access effects for persisted Stripe Dispute authority."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import Field

from ..agreements import AgreementState
from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..entitlement_store import AccountProjectionRequest, persist_account_entitlements
from ..flags import CommercialFlags
from ..models import StrictCommercialModel
from .stripe_dispute_policy import (
    StripeDisputePaymentEvidence,
    StripePriorDisputeMovement,
    decide_stripe_dispute_effect,
)
from .stripe_projection_provider import StripeDisputeSnapshot


class StripeDisputeEffectError(RuntimeError):
    """Safe rejection at the Dispute-effect authority boundary."""


class StripeDisputeEffectResult(StrictCommercialModel):
    effect_id: int = Field(gt=0)
    projection_event_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    agreement_state: AgreementState
    agreement_version: int = Field(gt=0)
    money_movement_id: int | None = Field(default=None, gt=0)
    entitlement_revision: int | None = Field(default=None, gt=0)
    agreement_changed: bool
    entitlement_changed: bool
    durable_replayed: bool = False


class PostgresStripeDisputeEffectApplier:
    """Apply current Dispute cash/access authority in the caller transaction."""

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
        self, *, projection_event_id: int, snapshot: StripeDisputeSnapshot
    ) -> StripeDisputeEffectResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Dispute effects require a transaction")
        if not self._flags.stripe_billing_enabled:
            raise StripeDisputeEffectError("Stripe billing is disabled")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_stripe_dispute_effect")
            try:
                result = self._apply(cursor, projection_event_id, snapshot)
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_stripe_dispute_effect")
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_dispute_effect")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_dispute_effect")
            return result
        finally:
            cursor.close()

    def _apply(self, cursor, projection_event_id, snapshot):
        cursor.execute(
            """SELECT projection.external_event_id, projection.environment,
                      projection.external_object_id, projection.observed_snapshot_sha256,
                      projection.disposition, object.commercial_account_id,
                      object.agreement_id, object.external_customer_id,
                      webhook.event_type, webhook.event_created_at
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                 JOIN commercial_webhook_events webhook
                   ON webhook.id = projection.webhook_event_id
                WHERE projection.id = %s AND projection.object_type = 'dispute'""",
            (projection_event_id,),
        )
        authority = cursor.fetchone()
        if authority is None or (
            authority[1] != snapshot.environment
            or authority[2] != snapshot.external_object_id
            or authority[3] != snapshot.snapshot_sha256
        ):
            raise StripeDisputeEffectError("Dispute projection lineage is invalid")
        replay = self._read_replay(cursor, projection_event_id, snapshot)
        if replay is not None:
            return replay
        account_id, agreement_id = int(authority[5]), int(authority[6])
        cursor.execute(
            "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE", (account_id,)
        )
        if cursor.fetchone() is None:
            raise StripeDisputeEffectError("Dispute account is missing")
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
            (account_id, agreement_id, authority[7]),
        )
        if cursor.fetchone() is None:
            raise StripeDisputeEffectError("Dispute tenant lineage is invalid")
        cursor.execute(
            """SELECT public_id, state, version, state_effective_at
                 FROM commercial_agreements
                WHERE id = %s AND commercial_account_id = %s
                  AND billing_provider = 'stripe' AND billing_environment = %s
                FOR UPDATE""",
            (agreement_id, account_id, snapshot.environment),
        )
        before = cursor.fetchone()
        if before is None:
            raise StripeDisputeEffectError("Dispute agreement lineage is invalid")
        cursor.execute(
            "SELECT to_regclass('commercial_stripe_payment_lineage') IS NOT NULL"
        )
        payment_lineage = (
            "commercial_stripe_payment_lineage"
            if cursor.fetchone()[0]
            else "commercial_stripe_invoice_payment_effects"
        )
        cursor.execute(
            f"""SELECT movement.id, movement.document_id, movement.signed_amount_cents,
                      movement.currency, movement.occurred_at,
                      payment.external_charge_id
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
            (
                snapshot.external_payment_intent_id,
                snapshot.external_charge_id,
                snapshot.environment,
                snapshot.external_payment_intent_id,
                account_id,
                agreement_id,
            ),
        )
        payment = cursor.fetchone()
        if payment is None or payment[1] is None:
            raise StripeDisputeEffectError("Dispute payment lineage is invalid")
        payment_movement_id, document_id = int(payment[0]), int(payment[1])
        cursor.execute(
            """SELECT id, movement_kind, signed_amount_cents, occurred_at
                 FROM commercial_money_movements
                WHERE provider = 'stripe' AND environment = %s
                  AND external_object_type = 'dispute' AND external_object_id = %s
                  AND movement_kind IN ('dispute_hold', 'dispute_release')
                ORDER BY id FOR UPDATE""",
            (snapshot.environment, snapshot.external_object_id),
        )
        movement_rows = cursor.fetchall()
        prior_movements = tuple(
            StripePriorDisputeMovement(
                movement_kind=row[1], signed_amount_cents=row[2], occurred_at=row[3]
            )
            for row in movement_rows
        )
        movement_ids = {row[1]: int(row[0]) for row in movement_rows}
        cursor.execute(
            """SELECT EXISTS (
                   SELECT 1 FROM commercial_stripe_dispute_effects
                    WHERE environment = %s AND external_dispute_id = %s
                      AND commercial_account_id = %s AND agreement_id = %s
                      AND result_state = 'paused' AND prior_state <> 'paused'
                      AND result_version = %s
               )""",
            (
                snapshot.environment,
                snapshot.external_object_id,
                account_id,
                agreement_id,
                before[2],
            ),
        )
        paused_by_this_dispute = bool(cursor.fetchone()[0])
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
            raise StripeDisputeEffectError("Dispute projection is not current")
        evaluated_at = self._clock()
        decision = decide_stripe_dispute_effect(
            local_state=AgreementState(before[1]),
            event_type=authority[8],
            event_created_at=authority[9],
            snapshot=snapshot,
            payment=StripeDisputePaymentEvidence(
                external_payment_intent_id=snapshot.external_payment_intent_id,
                external_charge_id=payment[5],
                amount_paid_cents=payment[2],
                currency=payment[3],
                paid_at=payment[4],
            ),
            prior_movements=prior_movements,
            paused_by_this_dispute=paused_by_this_dispute,
            evaluated_at=evaluated_at,
        )
        required_movement_kind = {
            "charge.dispute.funds_withdrawn": "dispute_hold",
            "charge.dispute.funds_reinstated": "dispute_release",
        }.get(authority[8])
        movement_id = movement_ids.get(decision.movement_kind or required_movement_kind)
        if decision.movement_kind is not None and movement_id is None:
            cursor.execute(
                """INSERT INTO commercial_money_movements (
                       event_id, provider, environment, agreement_id,
                       commercial_account_id, document_id, external_object_type,
                       external_object_id, movement_kind, signed_amount_cents,
                       currency, occurred_at, metadata)
                    VALUES (%s, 'stripe', %s, %s, %s, %s, 'dispute', %s, %s,
                            %s, 'USD', %s,
                            jsonb_build_object('payment_intent_id', %s, 'charge_id', %s,
                                               'payment_movement_id', %s,
                                               'snapshot_sha256', %s,
                                               'policy_version', %s)) RETURNING id""",
                (
                    str(uuid4()),
                    snapshot.environment,
                    agreement_id,
                    account_id,
                    document_id,
                    snapshot.external_object_id,
                    decision.movement_kind,
                    decision.signed_amount_cents,
                    decision.occurred_at,
                    snapshot.external_payment_intent_id,
                    snapshot.external_charge_id,
                    payment_movement_id,
                    snapshot.snapshot_sha256,
                    decision.policy_version,
                ),
            )
            movement_id = int(cursor.fetchone()[0])
        result_state = decision.target_state or AgreementState(before[1])
        state_effective_at = evaluated_at if decision.target_state else before[3]
        changed = result_state.value != before[1]
        result_version = int(before[2])
        if changed:
            cursor.execute(
                """UPDATE commercial_agreements
                      SET state = %s, state_effective_at = %s,
                          version = version + 1, updated_at = clock_timestamp()
                    WHERE id = %s AND version = %s RETURNING version""",
                (result_state.value, state_effective_at, agreement_id, before[2]),
            )
            row = cursor.fetchone()
            if row is None:
                raise StripeDisputeEffectError("Dispute agreement version changed")
            result_version = int(row[0])
        entitlement_revision = None
        entitlement_changed = False
        if decision.reproject_entitlements:
            if not self._flags.commercial_entitlement_projection_enabled:
                raise StripeDisputeEffectError("Entitlement projection is disabled")
            projection = persist_account_entitlements(
                self._connection,
                flags=self._flags,
                request=AccountProjectionRequest(
                    commercial_account_id=account_id,
                    projected_at=evaluated_at,
                ),
            )
            entitlement_changed = projection.changed
            if projection.changed:
                entitlement_revision = projection.revision
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id,
                commercial_account_id=account_id,
                agreement_id=agreement_id,
                actor_type="stripe",
                actor_id=authority[0],
                action="commercial.agreement.stripe_dispute_effect",
                target_type="commercial_agreement",
                target_id=str(before[0]),
                reason_code=decision.reason_code,
                before={
                    "account_id": account_id,
                    "agreement_id": agreement_id,
                    "state": before[1],
                    "version": before[2],
                },
                after={
                    "account_id": account_id,
                    "agreement_id": agreement_id,
                    "state": result_state.value,
                    "version": result_version,
                    "content_sha256": snapshot.snapshot_sha256,
                    "result_code": "applied",
                },
            ),
        )
        disposition = "applied" if changed or movement_id is not None else "unchanged"
        cursor.execute(
            """INSERT INTO commercial_stripe_dispute_effects (
                   projection_event_id, commercial_account_id, agreement_id, document_id,
                   environment, external_dispute_id, external_payment_intent_id,
                   external_charge_id, snapshot_sha256, dispute_status, dispute_event_type,
                   event_created_at, amount_cents, disposition, reason_code, policy_version,
                   money_movement_id, operator_review_required, paused_by_this_dispute,
                   prior_state, prior_version, result_state, result_version,
                   result_state_effective_at, resulting_entitlement_revision, audit_event_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id""",
            (
                projection_event_id,
                account_id,
                agreement_id,
                document_id,
                snapshot.environment,
                snapshot.external_object_id,
                snapshot.external_payment_intent_id,
                snapshot.external_charge_id,
                snapshot.snapshot_sha256,
                snapshot.status,
                authority[8],
                authority[9],
                snapshot.amount_cents,
                disposition,
                decision.reason_code,
                decision.policy_version,
                movement_id,
                decision.operator_review_required,
                paused_by_this_dispute,
                before[1],
                before[2],
                result_state.value,
                result_version,
                state_effective_at,
                entitlement_revision,
                str(audit_id),
            ),
        )
        return StripeDisputeEffectResult(
            effect_id=int(cursor.fetchone()[0]),
            projection_event_id=projection_event_id,
            agreement_id=agreement_id,
            agreement_state=result_state,
            agreement_version=result_version,
            money_movement_id=movement_id,
            entitlement_revision=entitlement_revision,
            agreement_changed=changed,
            entitlement_changed=entitlement_changed,
        )

    @staticmethod
    def _read_replay(cursor, projection_event_id, snapshot):
        cursor.execute(
            """SELECT id, agreement_id, result_state, result_version,
                      money_movement_id, resulting_entitlement_revision, disposition,
                      prior_state, snapshot_sha256,
                      external_payment_intent_id, external_charge_id
                 FROM commercial_stripe_dispute_effects
                WHERE projection_event_id = %s""",
            (projection_event_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        if row[8:] != (
            snapshot.snapshot_sha256,
            snapshot.external_payment_intent_id,
            snapshot.external_charge_id,
        ):
            raise StripeDisputeEffectError("Dispute effect replay does not match")
        return StripeDisputeEffectResult(
            effect_id=int(row[0]),
            projection_event_id=projection_event_id,
            agreement_id=int(row[1]),
            agreement_state=AgreementState(row[2]),
            agreement_version=int(row[3]),
            money_movement_id=row[4],
            entitlement_revision=row[5],
            agreement_changed=row[2] != row[7],
            entitlement_changed=False,
            durable_replayed=True,
        )


__all__ = [
    "PostgresStripeDisputeEffectApplier",
    "StripeDisputeEffectError",
    "StripeDisputeEffectResult",
]
