"""Atomic agreement/entitlement effects for paid or failed Stripe invoices."""

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
from .stripe_invoice_lifecycle import (
    StripeInvoiceCashReceiptEvidence,
    decide_stripe_invoice_lifecycle,
)
from .stripe_projection_provider import StripeInvoiceSnapshot, StripeSubscriptionSnapshot


class StripeInvoiceLifecycleEffectError(RuntimeError):
    """Safe rejection at the Invoice lifecycle-effect boundary."""


class StripeInvoiceLifecycleEffectResult(StrictCommercialModel):
    effect_id: int = Field(gt=0)
    invoice_effect_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    agreement_state: AgreementState
    agreement_version: int = Field(gt=0)
    entitlement_revision: int | None = Field(default=None, gt=0)
    agreement_changed: bool
    entitlement_changed: bool
    durable_replayed: bool = False


class PostgresStripeInvoiceLifecycleEffectApplier:
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
        self,
        *,
        invoice_effect_id: int,
        subscription_projection_event_id: int,
        invoice: StripeInvoiceSnapshot,
        subscription: StripeSubscriptionSnapshot,
    ) -> StripeInvoiceLifecycleEffectResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Invoice lifecycle effects require a transaction")
        if not self._flags.stripe_billing_enabled:
            raise StripeInvoiceLifecycleEffectError("Stripe billing is disabled")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_stripe_invoice_lifecycle_effect")
            try:
                result = self._apply(
                    cursor, invoice_effect_id, subscription_projection_event_id,
                    invoice, subscription,
                )
            except BaseException:
                cursor.execute(
                    "ROLLBACK TO SAVEPOINT commercial_stripe_invoice_lifecycle_effect"
                )
                cursor.execute(
                    "RELEASE SAVEPOINT commercial_stripe_invoice_lifecycle_effect"
                )
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_invoice_lifecycle_effect")
            return result
        finally:
            cursor.close()

    def _apply(self, cursor, invoice_effect_id, subscription_projection_event_id,
               invoice, subscription):
        cursor.execute(
            """SELECT effect.commercial_account_id, effect.agreement_id,
                      effect.environment, effect.external_invoice_id,
                      effect.snapshot_sha256, projection.external_event_id,
                      webhook.event_type, projection.id, projection.projection_object_id
                 FROM commercial_stripe_invoice_effects effect
                 JOIN commercial_stripe_projection_events projection
                   ON projection.id = effect.projection_event_id
                 JOIN commercial_webhook_events webhook
                   ON webhook.id = projection.webhook_event_id
                WHERE effect.id = %s""",
            (invoice_effect_id,),
        )
        invoice_authority = cursor.fetchone()
        if invoice_authority is None or (
            invoice_authority[2] != invoice.environment
            or invoice_authority[3] != invoice.external_object_id
            or invoice_authority[4] != invoice.snapshot_sha256
        ):
            raise StripeInvoiceLifecycleEffectError("Invoice effect lineage is invalid")
        account_id, agreement_id = int(invoice_authority[0]), int(invoice_authority[1])
        invoice_event_type = str(invoice_authority[6])
        cursor.execute(
            """SELECT projection.environment, projection.external_object_id,
                      projection.observed_snapshot_sha256,
                      object.commercial_account_id, object.agreement_id
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s AND projection.object_type = 'subscription'""",
            (subscription_projection_event_id,),
        )
        subscription_authority = cursor.fetchone()
        if subscription_authority is None or (
            subscription_authority[0] != subscription.environment
            or subscription_authority[1] != subscription.external_object_id
            or subscription_authority[2] != subscription.snapshot_sha256
            or int(subscription_authority[3]) != account_id
            or int(subscription_authority[4]) != agreement_id
        ):
            raise StripeInvoiceLifecycleEffectError(
                "Subscription projection lineage is invalid"
            )
        cursor.execute(
            """SELECT id, result_state, result_version,
                      resulting_entitlement_revision, disposition,
                      invoice_snapshot_sha256, subscription_snapshot_sha256,
                      subscription_projection_event_id, external_invoice_id,
                      external_subscription_id
                 FROM commercial_stripe_invoice_lifecycle_effects
                WHERE invoice_effect_id = %s""",
            (invoice_effect_id,),
        )
        replay = cursor.fetchone()
        if replay is not None:
            if (
                replay[5] != invoice.snapshot_sha256
                or replay[6] != subscription.snapshot_sha256
                or int(replay[7]) != subscription_projection_event_id
                or replay[8] != invoice.external_object_id
                or replay[9] != subscription.external_object_id
            ):
                raise StripeInvoiceLifecycleEffectError(
                    "Invoice lifecycle replay does not match authority"
                )
            return StripeInvoiceLifecycleEffectResult(
                effect_id=int(replay[0]), invoice_effect_id=invoice_effect_id,
                agreement_id=agreement_id, agreement_state=AgreementState(replay[1]),
                agreement_version=int(replay[2]), entitlement_revision=replay[3],
                agreement_changed=replay[4] == "applied",
                entitlement_changed=False, durable_replayed=True,
            )
        cursor.execute(
            "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
            (account_id,),
        )
        if cursor.fetchone() is None:
            raise StripeInvoiceLifecycleEffectError("Invoice account is missing")
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
            (account_id, agreement_id, invoice.external_customer_id),
        )
        if cursor.fetchone() is None:
            raise StripeInvoiceLifecycleEffectError("Invoice tenant lineage is invalid")
        cursor.execute(
            """SELECT public_id, state, version, state_effective_at,
                      current_period_start_at, current_period_end_at, grace_end_at,
                      cancel_at_period_end, external_subscription_id
                 FROM commercial_agreements
                WHERE id = %s AND commercial_account_id = %s
                  AND billing_provider = 'stripe' AND billing_environment = %s
                FOR UPDATE""",
            (agreement_id, account_id, invoice.environment),
        )
        before = cursor.fetchone()
        if before is None or before[8] != subscription.external_object_id:
            raise StripeInvoiceLifecycleEffectError("Invoice agreement lineage is stale")
        cursor.execute(
            """SELECT projection.observed_snapshot_sha256, object.snapshot_sha256
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s AND projection.object_type = 'invoice'
                FOR UPDATE OF projection, object""",
            (int(invoice_authority[7]),),
        )
        locked_invoice = cursor.fetchone()
        if locked_invoice is None or locked_invoice != (
            invoice.snapshot_sha256, invoice.snapshot_sha256
        ):
            raise StripeInvoiceLifecycleEffectError("Invoice authority was superseded")
        cursor.execute(
            """SELECT projection.observed_snapshot_sha256, object.snapshot_sha256
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s AND projection.object_type = 'subscription'
                FOR UPDATE OF projection, object""",
            (subscription_projection_event_id,),
        )
        locked_subscription = cursor.fetchone()
        if locked_subscription is None or locked_subscription != (
            subscription.snapshot_sha256, subscription.snapshot_sha256
        ):
            raise StripeInvoiceLifecycleEffectError("Subscription authority was superseded")
        cursor.execute(
            """SELECT payment.external_invoice_payment_id,
                      payment.external_payment_intent_id,
                      payment.amount_paid_cents, payment.paid_at,
                      payment.snapshot_sha256
                 FROM commercial_stripe_invoice_payment_effects payment
                WHERE payment.invoice_effect_id = %s
                ORDER BY payment.external_invoice_payment_id
                FOR KEY SHARE""",
            (invoice_effect_id,),
        )
        cash_receipts = tuple(
            StripeInvoiceCashReceiptEvidence(
                invoice_effect_id=invoice_effect_id,
                external_invoice_id=invoice.external_object_id,
                external_invoice_payment_id=row[0],
                external_payment_intent_id=row[1], amount_paid_cents=int(row[2]),
                paid_at=row[3], snapshot_sha256=row[4],
            ) for row in cursor.fetchall()
        )
        evaluated_at = self._clock()
        decision = decide_stripe_invoice_lifecycle(
            local_state=AgreementState(before[1]),
            invoice_event_type=invoice_event_type,
            invoice=invoice,
            subscription=subscription,
            expected_invoice_effect_id=invoice_effect_id,
            cash_receipts=cash_receipts,
            evaluated_at=evaluated_at,
        )
        result_state = decision.target_state or AgreementState(before[1])
        state_effective_at = evaluated_at if decision.target_state else before[3]
        period_start = (
            subscription.current_period_start_at
            if decision.reconcile_subscription_period else before[4]
        )
        period_end = (
            subscription.current_period_end_at
            if decision.reconcile_subscription_period else before[5]
        )
        grace_end = None if result_state == AgreementState.ACTIVE else before[6]
        cancel_at_period_end = (
            subscription.cancel_at_period_end
            if decision.reconcile_subscription_period else before[7]
        )
        changed = (
            result_state.value != before[1]
            or state_effective_at != before[3]
            or period_start != before[4]
            or period_end != before[5]
            or grace_end != before[6]
            or cancel_at_period_end != before[7]
        )
        result_version = int(before[2])
        if changed:
            cursor.execute(
                """UPDATE commercial_agreements
                      SET state = %s, state_effective_at = %s,
                          current_period_start_at = %s, current_period_end_at = %s,
                          grace_end_at = %s, cancel_at_period_end = %s,
                          version = version + 1, updated_at = clock_timestamp()
                    WHERE id = %s AND version = %s RETURNING version""",
                (result_state.value, state_effective_at, period_start, period_end,
                 grace_end, cancel_at_period_end, agreement_id, before[2]),
            )
            row = cursor.fetchone()
            if row is None:
                raise StripeInvoiceLifecycleEffectError("Invoice agreement version changed")
            result_version = int(row[0])
        entitlement_revision = None
        entitlement_changed = False
        if decision.reproject_entitlements:
            if not self._flags.commercial_entitlement_projection_enabled:
                raise StripeInvoiceLifecycleEffectError("Entitlement projection is disabled")
            projection = persist_account_entitlements(
                self._connection, flags=self._flags,
                request=AccountProjectionRequest(
                    commercial_account_id=account_id, projected_at=evaluated_at,
                ),
            )
            entitlement_changed = projection.changed
            if projection.changed:
                entitlement_revision = projection.revision
        disposition = "applied" if changed else "unchanged"
        cursor.execute(
            """SELECT commercial_stripe_invoice_lifecycle_effect_sha256(
                   %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
               )""",
            (disposition, decision.reason_code, before[1], before[2],
             result_state.value, result_version, state_effective_at,
             period_start, period_end, grace_end, cancel_at_period_end,
             entitlement_revision, invoice.snapshot_sha256,
             subscription.snapshot_sha256),
        )
        effect_sha256 = cursor.fetchone()[0]
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id, commercial_account_id=account_id,
                agreement_id=agreement_id, actor_type="stripe",
                actor_id=invoice_authority[5],
                action="commercial.agreement.stripe_invoice_effect",
                target_type="commercial_agreement", target_id=str(before[0]),
                reason_code=decision.reason_code,
                before={"account_id": account_id, "agreement_id": agreement_id,
                        "state": before[1], "version": before[2]},
                after={"account_id": account_id, "agreement_id": agreement_id,
                       "state": result_state.value, "version": result_version,
                       "content_sha256": effect_sha256,
                       "result_code": "applied"},
            ),
        )
        cursor.execute(
            """INSERT INTO commercial_stripe_invoice_lifecycle_effects (
                   invoice_effect_id, subscription_projection_event_id,
                   commercial_account_id, agreement_id, environment,
                   external_invoice_id, external_subscription_id,
                   invoice_snapshot_sha256, subscription_snapshot_sha256,
                   invoice_event_type, disposition, reason_code,
                   prior_state, prior_version, result_state, result_version,
                   result_state_effective_at, result_current_period_start_at,
                   result_current_period_end_at, result_grace_end_at,
                   result_cancel_at_period_end, resulting_entitlement_revision,
                   audit_event_id
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id""",
            (invoice_effect_id, subscription_projection_event_id, account_id,
             agreement_id, invoice.environment, invoice.external_object_id,
             subscription.external_object_id, invoice.snapshot_sha256,
             subscription.snapshot_sha256, invoice_event_type, disposition,
             decision.reason_code, before[1], before[2], result_state.value,
             result_version, state_effective_at, period_start, period_end,
             grace_end, cancel_at_period_end, entitlement_revision, str(audit_id)),
        )
        return StripeInvoiceLifecycleEffectResult(
            effect_id=int(cursor.fetchone()[0]), invoice_effect_id=invoice_effect_id,
            agreement_id=agreement_id, agreement_state=result_state,
            agreement_version=result_version,
            entitlement_revision=entitlement_revision,
            agreement_changed=changed, entitlement_changed=entitlement_changed,
        )


__all__ = [
    "PostgresStripeInvoiceLifecycleEffectApplier",
    "StripeInvoiceLifecycleEffectError",
    "StripeInvoiceLifecycleEffectResult",
]
