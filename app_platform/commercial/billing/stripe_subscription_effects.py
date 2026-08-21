"""Atomic application of reviewed Stripe Subscription lifecycle effects."""

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
from .stripe_projection_provider import StripeSubscriptionSnapshot
from .stripe_subscription_lifecycle import decide_stripe_subscription_lifecycle


class StripeSubscriptionEffectError(RuntimeError):
    """Safe rejection at the local Subscription-effect authority boundary."""


class StripeSubscriptionEffectResult(StrictCommercialModel):
    effect_id: int = Field(gt=0)
    projection_event_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    agreement_state: AgreementState
    agreement_version: int = Field(gt=0)
    entitlement_revision: int | None = Field(default=None, gt=0)
    agreement_changed: bool
    entitlement_changed: bool
    durable_replayed: bool = False


class PostgresStripeSubscriptionEffectApplier:
    """Apply one persisted Subscription fact inside the caller transaction."""

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
        projection_event_id: int,
        snapshot: StripeSubscriptionSnapshot,
    ) -> StripeSubscriptionEffectResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Subscription effects require a transaction")
        if not self._flags.stripe_billing_enabled:
            raise StripeSubscriptionEffectError("Stripe billing is disabled")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_stripe_subscription_effect")
            try:
                result = self._apply(cursor, projection_event_id, snapshot)
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_stripe_subscription_effect")
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_subscription_effect")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_subscription_effect")
            return result
        finally:
            cursor.close()

    def _apply(self, cursor, projection_event_id, snapshot):
        cursor.execute(
            """SELECT projection.id, projection.external_event_id,
                      projection.environment, projection.external_object_id,
                      projection.observed_snapshot_sha256,
                      projection.resulting_agreement_version,
                      object.commercial_account_id, object.agreement_id
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s
                  AND projection.object_type = 'subscription'
                  AND projection.disposition IN ('applied', 'unchanged', 'superseded')
                """,
            (projection_event_id,),
        )
        provider = cursor.fetchone()
        if provider is None:
            raise StripeSubscriptionEffectError("Subscription projection is missing")
        if (
            provider[2] != snapshot.environment
            or provider[3] != snapshot.external_object_id
            or provider[4] != snapshot.snapshot_sha256
            or provider[5] is None
        ):
            raise StripeSubscriptionEffectError("Subscription projection lineage is invalid")
        account_id, agreement_id = int(provider[6]), int(provider[7])
        cursor.execute(
            "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
            (account_id,),
        )
        if cursor.fetchone() is None:
            raise StripeSubscriptionEffectError("Subscription account is missing")
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
            raise StripeSubscriptionEffectError("Subscription tenant lineage is invalid")
        cursor.execute(
            """SELECT public_id, state, version, state_effective_at,
                      current_period_start_at, current_period_end_at, trial_end_at,
                      cancel_at_period_end, canceled_at, external_subscription_id
                 FROM commercial_agreements
                WHERE id = %s AND commercial_account_id = %s
                  AND billing_provider = 'stripe' AND billing_environment = %s
                FOR UPDATE""",
            (agreement_id, account_id, snapshot.environment),
        )
        before = cursor.fetchone()
        if (
            before is None
            or before[9] != snapshot.external_object_id
            or str(before[0]) != str(snapshot.agreement_public_id)
        ):
            raise StripeSubscriptionEffectError("Subscription agreement lineage is stale")
        cursor.execute(
            """SELECT projection.resulting_agreement_version,
                      projection.observed_snapshot_sha256,
                      object.snapshot_sha256
                 FROM commercial_stripe_projection_events projection
                 JOIN commercial_stripe_projection_objects object
                   ON object.id = projection.projection_object_id
                WHERE projection.id = %s AND projection.object_type = 'subscription'
                FOR UPDATE OF projection, object""",
            (projection_event_id,),
        )
        locked_provider = cursor.fetchone()
        if locked_provider is None or locked_provider[1] != snapshot.snapshot_sha256:
            raise StripeSubscriptionEffectError("Subscription projection lineage is invalid")
        cursor.execute(
            """SELECT effect.id, effect.agreement_id, effect.result_state,
                      effect.result_version, effect.resulting_entitlement_revision,
                      effect.disposition
                 FROM commercial_stripe_subscription_effects effect
                WHERE effect.projection_event_id = %s""",
            (projection_event_id,),
        )
        replay = cursor.fetchone()
        if replay is not None:
            return StripeSubscriptionEffectResult(
                effect_id=int(replay[0]), projection_event_id=projection_event_id,
                agreement_id=int(replay[1]), agreement_state=AgreementState(replay[2]),
                agreement_version=int(replay[3]), entitlement_revision=replay[4],
                agreement_changed=replay[5] == "applied",
                entitlement_changed=False, durable_replayed=True,
            )
        if int(locked_provider[0]) != int(before[2]):
            raise StripeSubscriptionEffectError("Subscription agreement lineage is stale")
        if locked_provider[2] != snapshot.snapshot_sha256:
            raise StripeSubscriptionEffectError("Subscription projection was superseded")
        evaluated_at = self._clock()
        decision = decide_stripe_subscription_lifecycle(
            local_state=AgreementState(before[1]), snapshot=snapshot,
            evaluated_at=evaluated_at,
        )
        result_state = decision.target_state or AgreementState(before[1])
        state_effective_at = before[3]
        if decision.target_state is not None:
            candidate = (
                decision.canceled_at
                if decision.target_state == AgreementState.CANCELED
                else snapshot.trial_start
                if decision.target_state == AgreementState.TRIALING
                else snapshot.ended_at or evaluated_at
                if decision.target_state == AgreementState.EXPIRED
                else evaluated_at
            )
            if candidate is None or candidate <= before[3]:
                raise StripeSubscriptionEffectError(
                    "Subscription state boundary is not monotonic"
                )
            state_effective_at = candidate
        period_start = (
            decision.current_period_start_at
            if decision.reconcile_period else before[4]
        )
        period_end = (
            decision.current_period_end_at
            if decision.reconcile_period else before[5]
        )
        trial_end = decision.trial_end_at if decision.reconcile_period else before[6]
        cancel_at_period_end = (
            bool(decision.cancel_at_period_end)
            if decision.reconcile_period else bool(before[7])
        )
        canceled_at = (
            decision.canceled_at
            if decision.target_state == AgreementState.CANCELED
            else before[8]
        )
        if result_state in {AgreementState.CANCELED, AgreementState.EXPIRED}:
            cancel_at_period_end = False
        changed = (
            result_state.value != before[1]
            or state_effective_at != before[3]
            or period_start != before[4]
            or period_end != before[5]
            or trial_end != before[6]
            or cancel_at_period_end != before[7]
            or canceled_at != before[8]
        )
        result_version = int(before[2])
        if changed:
            cursor.execute(
                """UPDATE commercial_agreements
                      SET state = %s, state_effective_at = %s,
                          current_period_start_at = %s, current_period_end_at = %s,
                          trial_end_at = %s, cancel_at_period_end = %s,
                          canceled_at = %s, version = version + 1,
                          updated_at = clock_timestamp()
                    WHERE id = %s AND version = %s
                RETURNING version""",
                (result_state.value, state_effective_at, period_start, period_end,
                 trial_end, cancel_at_period_end, canceled_at, agreement_id, before[2]),
            )
            row = cursor.fetchone()
            if row is None:
                raise StripeSubscriptionEffectError("Subscription agreement version changed")
            result_version = int(row[0])

        entitlement_revision = None
        entitlement_changed = False
        if decision.reproject_entitlements:
            if not self._flags.commercial_entitlement_projection_enabled:
                raise StripeSubscriptionEffectError("Entitlement projection is disabled")
            projection = persist_account_entitlements(
                self._connection,
                flags=self._flags,
                request=AccountProjectionRequest(
                    commercial_account_id=account_id, projected_at=evaluated_at,
                ),
            )
            entitlement_changed = projection.changed
            if projection.changed:
                entitlement_revision = projection.revision

        cursor.execute(
            """SELECT commercial_stripe_subscription_effect_sha256(
                   %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
               )""",
            ("applied" if changed else "unchanged", decision.reason_code,
             before[1], before[2], result_state.value, result_version,
             state_effective_at, period_start, period_end, trial_end,
             cancel_at_period_end, canceled_at, entitlement_revision),
        )
        effect_sha256 = cursor.fetchone()[0]
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id, commercial_account_id=account_id,
                agreement_id=agreement_id, actor_type="stripe", actor_id=provider[1],
                action="commercial.agreement.stripe_subscription_effect",
                target_type="commercial_agreement", target_id=str(before[0]),
                reason_code=decision.reason_code,
                before={"account_id": account_id, "agreement_id": agreement_id,
                        "state": before[1], "version": before[2]},
                after={"account_id": account_id, "agreement_id": agreement_id,
                       "state": result_state.value, "version": result_version,
                       "result_code": "applied", "content_sha256": effect_sha256},
            ),
        )
        cursor.execute(
            """INSERT INTO commercial_stripe_subscription_effects (
                   projection_event_id, commercial_account_id, agreement_id,
                   environment, external_subscription_id, snapshot_sha256,
                   disposition, reason_code, prior_state, prior_version,
                   result_state, result_version, result_state_effective_at,
                   result_current_period_start_at, result_current_period_end_at,
                   result_trial_end_at, result_cancel_at_period_end,
                   result_canceled_at, resulting_entitlement_revision, audit_event_id
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id""",
            (projection_event_id, account_id, agreement_id, snapshot.environment,
             snapshot.external_object_id, snapshot.snapshot_sha256,
             "applied" if changed else "unchanged", decision.reason_code,
             before[1], before[2], result_state.value, result_version,
             state_effective_at, period_start, period_end, trial_end,
             cancel_at_period_end, canceled_at, entitlement_revision, str(audit_id)),
        )
        effect_id = int(cursor.fetchone()[0])
        return StripeSubscriptionEffectResult(
            effect_id=effect_id, projection_event_id=projection_event_id,
            agreement_id=agreement_id, agreement_state=result_state,
            agreement_version=result_version,
            entitlement_revision=entitlement_revision,
            agreement_changed=changed, entitlement_changed=entitlement_changed,
        )


__all__ = [
    "PostgresStripeSubscriptionEffectApplier",
    "StripeSubscriptionEffectError",
    "StripeSubscriptionEffectResult",
]
