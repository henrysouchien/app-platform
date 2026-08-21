"""Authoritative Checkout and Subscription webhook projection routes."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Literal

from pydantic import Field

from ..flags import CommercialFlags
from ..models import StrictCommercialModel
from .stripe_checkout_projection import PostgresStripeCheckoutProjector
from .stripe_config import StripeDeploymentManifest
from .stripe_credit_note_effects import PostgresStripeCreditNoteEffectApplier
from .stripe_credit_note_projection import PostgresStripeCreditNoteProjector
from .stripe_dispute_effects import PostgresStripeDisputeEffectApplier
from .stripe_dispute_projection import PostgresStripeDisputeProjector
from .stripe_invoice_effects import PostgresStripeInvoiceEffectApplier
from .stripe_invoice_lifecycle_effects import (
    PostgresStripeInvoiceLifecycleEffectApplier,
)
from .stripe_invoice_projection import PostgresStripeInvoiceProjector
from .stripe_projection_provider import (
    StripeProjectionExpectation,
    StripeProjectionProvider,
)
from .stripe_refund_effects import PostgresStripeRefundEffectApplier
from .stripe_refund_projection import PostgresStripeRefundProjector
from .stripe_subscription_effects import PostgresStripeSubscriptionEffectApplier
from .stripe_subscription_projection import PostgresStripeSubscriptionProjector
from .webhook_worker import ClaimedStripeWebhook


class StripeWebhookRouteError(RuntimeError):
    """A claimed webhook cannot be mapped to authoritative local lineage."""


class StripeWebhookRouteResult(StrictCommercialModel):
    webhook_event_id: int = Field(gt=0)
    object_type: Literal[
        "checkout_session",
        "subscription",
        "invoice",
        "refund",
        "dispute",
        "credit_note",
    ]
    disposition: str
    projection_event_id: int | None = Field(default=None, gt=0)
    effect_id: int | None = Field(default=None, gt=0)
    lifecycle_effect_id: int | None = Field(default=None, gt=0)


class StripeCheckoutSubscriptionWebhookRouter:
    """Re-fetch and atomically project the first two Stripe event families."""

    CHECKOUT_EVENT = "checkout.session.completed"
    SUBSCRIPTION_EVENTS = frozenset(
        {
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
        }
    )
    INVOICE_EVENTS = frozenset(
        {
            "invoice.created",
            "invoice.finalized",
            "invoice.paid",
            "invoice.payment_failed",
            "invoice.payment_action_required",
            "invoice.voided",
            "invoice.marked_uncollectible",
        }
    )
    INVOICE_LIFECYCLE_EVENTS = frozenset(
        {
            "invoice.paid",
            "invoice.payment_failed",
            "invoice.payment_action_required",
        }
    )
    REFUND_EVENTS = frozenset({"refund.created", "refund.updated", "refund.failed"})
    DISPUTE_EVENTS = frozenset(
        {
            "charge.dispute.created",
            "charge.dispute.updated",
            "charge.dispute.closed",
            "charge.dispute.funds_withdrawn",
            "charge.dispute.funds_reinstated",
        }
    )
    CREDIT_NOTE_EVENTS = frozenset(
        {"credit_note.created", "credit_note.updated", "credit_note.voided"}
    )
    SUPPORTED_EVENTS = (
        frozenset({CHECKOUT_EVENT})
        | SUBSCRIPTION_EVENTS
        | INVOICE_EVENTS
        | REFUND_EVENTS
        | DISPUTE_EVENTS
        | CREDIT_NOTE_EVENTS
    )

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        deployment: StripeDeploymentManifest,
        provider: StripeProjectionProvider,
        expectation_session_factory: Callable[[], object],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._flags = flags
        self._deployment = deployment
        self._provider = provider
        self._expectation_session_factory = expectation_session_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def route(self, claim: ClaimedStripeWebhook) -> StripeWebhookRouteResult:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.stripe_billing_enabled
        ):
            raise StripeWebhookRouteError("Stripe webhook projection is disabled")
        if claim.environment != self._deployment.billing_environment:
            raise StripeWebhookRouteError(
                "Stripe webhook environment is outside deployment authority"
            )
        if claim.event_type == self.CHECKOUT_EVENT:
            return self._checkout(claim)
        if claim.event_type in self.SUBSCRIPTION_EVENTS:
            return self._subscription(claim)
        if claim.event_type in self.INVOICE_EVENTS:
            return self._invoice(claim)
        if claim.event_type in self.REFUND_EVENTS:
            return self._refund(claim)
        if claim.event_type in self.DISPUTE_EVENTS:
            return self._dispute(claim)
        if claim.event_type in self.CREDIT_NOTE_EVENTS:
            return self._credit_note(claim)
        raise StripeWebhookRouteError("Stripe webhook event type is not routed")

    def _checkout(self, claim: ClaimedStripeWebhook) -> StripeWebhookRouteResult:
        expected = self._expectation(claim, object_type="checkout")
        snapshot = self._provider.fetch_checkout_session(
            claim.external_object_id,
            expected=expected,
        )
        result = self._run_atomic(
            "checkout",
            lambda: PostgresStripeCheckoutProjector(self._connection).project(
                webhook_event_id=claim.webhook_event_id,
                external_event_id=claim.external_event_id,
                worker_lease_token=claim.lease_token,
                snapshot=snapshot,
            ),
        )
        return StripeWebhookRouteResult(
            webhook_event_id=claim.webhook_event_id,
            object_type="checkout_session",
            disposition=result.disposition,
        )

    def _subscription(self, claim: ClaimedStripeWebhook) -> StripeWebhookRouteResult:
        expected = self._expectation(claim, object_type="subscription")
        snapshot = self._provider.fetch_subscription(
            claim.external_object_id,
            expected=expected,
        )
        return self._run_atomic(
            "subscription",
            lambda: self._project_subscription(claim, snapshot),
        )

    def _project_subscription(self, claim, snapshot) -> StripeWebhookRouteResult:
        result = PostgresStripeSubscriptionProjector(
            self._connection,
            deployment=self._deployment,
        ).project(
            webhook_event_id=claim.webhook_event_id,
            external_event_id=claim.external_event_id,
            worker_lease_token=claim.lease_token,
            snapshot=snapshot,
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT id FROM commercial_stripe_projection_events
                 WHERE webhook_event_id = %s AND object_type = 'subscription'
                """,
                (claim.webhook_event_id,),
            )
            event = cursor.fetchone()
            if event is None:
                raise StripeWebhookRouteError(
                    "Stripe Subscription projection evidence is missing"
                )
            projection_event_id = int(event[0])
        finally:
            cursor.close()
        if result.disposition == "superseded":
            return StripeWebhookRouteResult(
                webhook_event_id=claim.webhook_event_id,
                object_type="subscription",
                disposition=result.disposition,
                projection_event_id=projection_event_id,
            )
        effect = PostgresStripeSubscriptionEffectApplier(
            self._connection,
            flags=self._flags,
            clock=self._clock,
        ).apply(
            projection_event_id=projection_event_id,
            snapshot=snapshot,
        )
        return StripeWebhookRouteResult(
            webhook_event_id=claim.webhook_event_id,
            object_type="subscription",
            disposition=result.disposition,
            projection_event_id=projection_event_id,
            effect_id=effect.effect_id,
        )

    def _invoice(self, claim: ClaimedStripeWebhook) -> StripeWebhookRouteResult:
        expected, subscription_id = self._invoice_expectation(claim)
        invoice = self._provider.fetch_invoice(
            claim.external_object_id,
            expected=expected,
            expected_subscription_id=subscription_id,
        )
        subscription = None
        if claim.event_type in self.INVOICE_LIFECYCLE_EVENTS:
            subscription = self._provider.fetch_subscription(
                subscription_id,
                expected=expected,
            )
        return self._run_atomic(
            "invoice",
            lambda: self._project_invoice(claim, invoice, subscription),
        )

    def _project_invoice(
        self, claim, invoice, subscription
    ) -> StripeWebhookRouteResult:
        projection = PostgresStripeInvoiceProjector(
            self._connection,
            deployment=self._deployment,
        ).project(
            webhook_event_id=claim.webhook_event_id,
            external_event_id=claim.external_event_id,
            worker_lease_token=claim.lease_token,
            snapshot=invoice,
        )
        base = {
            "webhook_event_id": claim.webhook_event_id,
            "object_type": "invoice",
            "disposition": projection.disposition,
            "projection_event_id": projection.projection_event_id,
        }
        if projection.disposition == "superseded" or invoice.status == "draft":
            return StripeWebhookRouteResult(**base)
        financial = PostgresStripeInvoiceEffectApplier(
            self._connection,
            flags=self._flags,
            clock=self._clock,
        ).apply(
            projection_event_id=projection.projection_event_id,
            snapshot=invoice,
        )
        lifecycle_effect_id = None
        if subscription is not None:
            subscription_projection_id = self._subscription_projection_id(subscription)
            lifecycle = PostgresStripeInvoiceLifecycleEffectApplier(
                self._connection,
                flags=self._flags,
                clock=self._clock,
            ).apply(
                invoice_effect_id=financial.effect_id,
                subscription_projection_event_id=subscription_projection_id,
                invoice=invoice,
                subscription=subscription,
            )
            lifecycle_effect_id = lifecycle.effect_id
        return StripeWebhookRouteResult(
            **base,
            effect_id=financial.effect_id,
            lifecycle_effect_id=lifecycle_effect_id,
        )

    def _subscription_projection_id(self, snapshot) -> int:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT projection.id
                  FROM commercial_stripe_projection_objects object
                  JOIN commercial_stripe_projection_events projection
                    ON projection.projection_object_id = object.id
                   AND projection.observed_snapshot_sha256 = object.snapshot_sha256
                 WHERE object.environment = %s
                   AND object.object_type = 'subscription'
                   AND object.external_object_id = %s
                   AND object.snapshot_sha256 = %s
                   AND projection.disposition IN ('applied', 'unchanged')
                 ORDER BY projection.id DESC LIMIT 1
                """,
                (
                    snapshot.environment,
                    snapshot.external_object_id,
                    snapshot.snapshot_sha256,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise StripeWebhookRouteError(
                "Current Stripe Subscription projection is unavailable"
            )
        return int(row[0])

    def _refund(self, claim: ClaimedStripeWebhook) -> StripeWebhookRouteResult:
        payment_intent_id, charge_id = self._payment_expectation(claim)
        snapshot = self._provider.fetch_refund(
            claim.external_object_id,
            expected_payment_intent_id=payment_intent_id,
            expected_charge_id=charge_id,
        )
        return self._run_atomic(
            "refund",
            lambda: self._project_refund(claim, snapshot),
        )

    def _project_refund(self, claim, snapshot) -> StripeWebhookRouteResult:
        projection = PostgresStripeRefundProjector(self._connection).project(
            webhook_event_id=claim.webhook_event_id,
            external_event_id=claim.external_event_id,
            worker_lease_token=claim.lease_token,
            snapshot=snapshot,
        )
        effect_id = None
        if projection.disposition != "superseded":
            effect = PostgresStripeRefundEffectApplier(
                self._connection,
                flags=self._flags,
                clock=self._clock,
            ).apply(
                projection_event_id=projection.projection_event_id,
                snapshot=snapshot,
            )
            effect_id = effect.effect_id
        return StripeWebhookRouteResult(
            webhook_event_id=claim.webhook_event_id,
            object_type="refund",
            disposition=projection.disposition,
            projection_event_id=projection.projection_event_id,
            effect_id=effect_id,
        )

    def _dispute(self, claim: ClaimedStripeWebhook) -> StripeWebhookRouteResult:
        payment_intent_id, charge_id = self._payment_expectation(claim)
        snapshot = self._provider.fetch_dispute(
            claim.external_object_id,
            expected_payment_intent_id=payment_intent_id,
            expected_charge_id=charge_id,
        )
        return self._run_atomic(
            "dispute",
            lambda: self._project_dispute(claim, snapshot),
        )

    def _project_dispute(self, claim, snapshot) -> StripeWebhookRouteResult:
        projection = PostgresStripeDisputeProjector(self._connection).project(
            webhook_event_id=claim.webhook_event_id,
            external_event_id=claim.external_event_id,
            worker_lease_token=claim.lease_token,
            snapshot=snapshot,
        )
        effect_id = None
        if projection.disposition != "superseded":
            effect = PostgresStripeDisputeEffectApplier(
                self._connection,
                flags=self._flags,
                clock=self._clock,
            ).apply(
                projection_event_id=projection.projection_event_id,
                snapshot=snapshot,
            )
            effect_id = effect.effect_id
        return StripeWebhookRouteResult(
            webhook_event_id=claim.webhook_event_id,
            object_type="dispute",
            disposition=projection.disposition,
            projection_event_id=projection.projection_event_id,
            effect_id=effect_id,
        )

    def _credit_note(self, claim: ClaimedStripeWebhook) -> StripeWebhookRouteResult:
        invoice_id, customer_id = self._credit_note_expectation(claim)
        snapshot = self._provider.fetch_credit_note(
            claim.external_object_id,
            expected_invoice_id=invoice_id,
            expected_customer_id=customer_id,
        )
        return self._run_atomic(
            "credit_note",
            lambda: self._project_credit_note(claim, snapshot),
        )

    def _project_credit_note(self, claim, snapshot) -> StripeWebhookRouteResult:
        projection = PostgresStripeCreditNoteProjector(self._connection).project(
            webhook_event_id=claim.webhook_event_id,
            external_event_id=claim.external_event_id,
            worker_lease_token=claim.lease_token,
            snapshot=snapshot,
        )
        effect_id = None
        if projection.disposition != "superseded":
            effect = PostgresStripeCreditNoteEffectApplier(
                self._connection,
                flags=self._flags,
                clock=self._clock,
            ).apply(
                projection_event_id=projection.projection_event_id,
                snapshot=snapshot,
            )
            effect_id = effect.effect_id
        return StripeWebhookRouteResult(
            webhook_event_id=claim.webhook_event_id,
            object_type="credit_note",
            disposition=projection.disposition,
            projection_event_id=projection.projection_event_id,
            effect_id=effect_id,
        )

    def _expectation(
        self,
        claim: ClaimedStripeWebhook,
        *,
        object_type: Literal["checkout", "subscription"],
    ) -> StripeProjectionExpectation:
        with self._expectation_connection() as expectation_connection:
            cursor = expectation_connection.cursor()  # type: ignore[attr-defined]
            try:
                if object_type == "checkout":
                    cursor.execute(
                        """
                    SELECT attempt.account_public_id, attempt.agreement_public_id,
                           customer.external_customer_id, attempt.price_code
                      FROM commercial_checkout_attempts attempt
                      JOIN billing_provider_customers customer
                        ON customer.commercial_account_id =
                           attempt.commercial_account_id
                       AND customer.provider = 'stripe'
                       AND customer.environment = attempt.environment
                     WHERE attempt.environment = %s
                       AND attempt.external_checkout_session_id = %s
                       AND attempt.state = 'session_created'
                    """,
                        (claim.environment, claim.external_object_id),
                    )
                else:
                    cursor.execute(
                        """
                    SELECT attempt.account_public_id, attempt.agreement_public_id,
                           customer.external_customer_id, attempt.price_code
                      FROM commercial_agreements agreement
                      JOIN commercial_checkout_attempts attempt
                        ON attempt.agreement_id = agreement.id
                       AND attempt.commercial_account_id =
                           agreement.commercial_account_id
                       AND attempt.state = 'session_created'
                      JOIN billing_provider_customers customer
                        ON customer.commercial_account_id =
                           agreement.commercial_account_id
                       AND customer.provider = 'stripe'
                       AND customer.environment = agreement.billing_environment
                     WHERE agreement.billing_provider = 'stripe'
                       AND agreement.billing_environment = %s
                       AND agreement.external_subscription_id = %s
                    """,
                        (claim.environment, claim.external_object_id),
                    )
                rows = cursor.fetchall()
            finally:
                cursor.close()
        if len(rows) != 1:
            raise StripeWebhookRouteError(
                "Stripe webhook local projection lineage is not unambiguous"
            )
        return StripeProjectionExpectation(
            environment=claim.environment,
            commercial_account_public_id=rows[0][0],
            agreement_public_id=rows[0][1],
            external_customer_id=rows[0][2],
            price_code=rows[0][3],
        )

    def _invoice_expectation(
        self, claim: ClaimedStripeWebhook
    ) -> tuple[StripeProjectionExpectation, str]:
        with self._expectation_connection() as expectation_connection:
            cursor = expectation_connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute(
                    """
                SELECT attempt.account_public_id, attempt.agreement_public_id,
                       customer.external_customer_id, attempt.price_code,
                       agreement.external_subscription_id
                  FROM commercial_webhook_events webhook
                  JOIN commercial_agreements agreement
                    ON agreement.billing_provider = 'stripe'
                   AND agreement.billing_environment = webhook.environment
                   AND agreement.external_subscription_id =
                       webhook.payload_json #>>
                       '{data,object,parent,subscription_details,subscription}'
                  JOIN commercial_checkout_attempts attempt
                    ON attempt.agreement_id = agreement.id
                   AND attempt.commercial_account_id =
                       agreement.commercial_account_id
                   AND attempt.state = 'session_created'
                  JOIN billing_provider_customers customer
                    ON customer.commercial_account_id =
                       agreement.commercial_account_id
                   AND customer.provider = 'stripe'
                   AND customer.environment = agreement.billing_environment
                 WHERE webhook.id = %s
                   AND webhook.provider = 'stripe'
                   AND webhook.integrity_state = 'verified'
                   AND webhook.environment = %s
                   AND webhook.external_event_id = %s
                   AND webhook.event_type = %s
                   AND webhook.payload_json->'data'->'object'->>'id' = %s
                   AND webhook.payload_json->'data'->'object'->>'customer' =
                       customer.external_customer_id
                """,
                    (
                        claim.webhook_event_id,
                        claim.environment,
                        claim.external_event_id,
                        claim.event_type,
                        claim.external_object_id,
                    ),
                )
                rows = cursor.fetchall()
            finally:
                cursor.close()
        if len(rows) != 1:
            raise StripeWebhookRouteError(
                "Stripe Invoice local projection lineage is not unambiguous"
            )
        return (
            StripeProjectionExpectation(
                environment=claim.environment,
                commercial_account_public_id=rows[0][0],
                agreement_public_id=rows[0][1],
                external_customer_id=rows[0][2],
                price_code=rows[0][3],
            ),
            str(rows[0][4]),
        )

    def _payment_expectation(self, claim: ClaimedStripeWebhook) -> tuple[str, str]:
        with self._expectation_connection() as expectation_connection:
            cursor = expectation_connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute(
                    """
                SELECT payment_effect.external_payment_intent_id,
                       payment_effect.external_charge_id
                  FROM commercial_webhook_events webhook
                  JOIN commercial_stripe_invoice_payment_effects payment_effect
                    ON payment_effect.external_payment_intent_id =
                       webhook.payload_json->'data'->'object'->>'payment_intent'
                   AND payment_effect.external_charge_id =
                       webhook.payload_json->'data'->'object'->>'charge'
                  JOIN commercial_money_movements movement
                    ON movement.id = payment_effect.money_movement_id
                   AND movement.provider = 'stripe'
                   AND movement.environment = webhook.environment
                   AND movement.external_object_type = 'payment_intent'
                   AND movement.external_object_id =
                       payment_effect.external_payment_intent_id
                   AND movement.movement_kind = 'cash_receipt'
                 WHERE webhook.id = %s
                   AND webhook.provider = 'stripe'
                   AND webhook.integrity_state = 'verified'
                   AND webhook.environment = %s
                   AND webhook.external_event_id = %s
                   AND webhook.event_type = %s
                   AND webhook.payload_json->'data'->'object'->>'id' = %s
                """,
                    (
                        claim.webhook_event_id,
                        claim.environment,
                        claim.external_event_id,
                        claim.event_type,
                        claim.external_object_id,
                    ),
                )
                rows = cursor.fetchall()
            finally:
                cursor.close()
        if len(rows) != 1 or rows[0][1] is None:
            raise StripeWebhookRouteError(
                "Stripe payment local projection lineage is not unambiguous"
            )
        return str(rows[0][0]), str(rows[0][1])

    @contextmanager
    def _expectation_connection(self):
        resource = self._expectation_session_factory()
        if hasattr(resource, "__enter__") and hasattr(resource, "__exit__"):
            with resource as connection:
                try:
                    yield connection
                finally:
                    connection.rollback()
            return
        try:
            yield resource
        finally:
            resource.rollback()  # type: ignore[attr-defined]
            resource.close()  # type: ignore[attr-defined]

    def _credit_note_expectation(self, claim: ClaimedStripeWebhook) -> tuple[str, str]:
        with self._expectation_connection() as expectation_connection:
            cursor = expectation_connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute(
                    """
                SELECT effect.external_invoice_id, object.external_customer_id
                  FROM commercial_webhook_events webhook
                  JOIN commercial_stripe_invoice_effects effect
                    ON effect.environment = webhook.environment
                   AND effect.external_invoice_id =
                       webhook.payload_json->'data'->'object'->>'invoice'
                   AND effect.document_created
                  JOIN commercial_stripe_projection_events projection
                    ON projection.id = effect.projection_event_id
                   AND projection.object_type = 'invoice'
                   AND projection.external_object_id = effect.external_invoice_id
                  JOIN commercial_stripe_projection_objects object
                    ON object.id = projection.projection_object_id
                   AND object.environment = effect.environment
                   AND object.object_type = 'invoice'
                   AND object.external_object_id = effect.external_invoice_id
                  JOIN commercial_billing_documents document
                    ON document.id = effect.document_id
                   AND document.provider = 'stripe'
                   AND document.environment = effect.environment
                   AND document.external_document_id = effect.external_invoice_id
                 WHERE webhook.id = %s
                   AND webhook.provider = 'stripe'
                   AND webhook.integrity_state = 'verified'
                   AND webhook.environment = %s
                   AND webhook.external_event_id = %s
                   AND webhook.event_type = %s
                   AND webhook.payload_json->'data'->'object'->>'id' = %s
                   AND webhook.payload_json->'data'->'object'->>'customer' =
                       object.external_customer_id
                    """,
                    (
                        claim.webhook_event_id,
                        claim.environment,
                        claim.external_event_id,
                        claim.event_type,
                        claim.external_object_id,
                    ),
                )
                rows = cursor.fetchall()
            finally:
                cursor.close()
        if len(rows) != 1:
            raise StripeWebhookRouteError(
                "Stripe Credit Note local Invoice lineage is not unambiguous"
            )
        return str(rows[0][0]), str(rows[0][1])

    def _run_atomic(self, label: str, operation):
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        savepoint = f"commercial_stripe_webhook_route_{label}"
        try:
            cursor.execute(f"SAVEPOINT {savepoint}")
            try:
                result = operation()
            except BaseException:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                cursor.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            cursor.execute(f"RELEASE SAVEPOINT {savepoint}")
            return result
        finally:
            cursor.close()


__all__ = [
    "StripeCheckoutSubscriptionWebhookRouter",
    "StripeWebhookRouteError",
    "StripeWebhookRouteResult",
]
