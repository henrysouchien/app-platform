"""Fenced, order-tolerant persistence of authoritative Stripe subscriptions."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from .stripe_projection_provider import StripeSubscriptionSnapshot
from .stripe_config import StripeDeploymentManifest


class StripeSubscriptionProjectionError(RuntimeError):
    """Safe failure at the Subscription projection authority boundary."""


@dataclass(frozen=True, slots=True)
class StripeSubscriptionProjectionResult:
    projection_object_id: int
    object_revision: int
    agreement_version: int
    disposition: str
    durable_replayed: bool = False


class PostgresStripeSubscriptionProjector:
    """Persist a normalized subscription without changing access or lifecycle.

    First application requires the current inbox lease. Terminal replay is
    lease-free only after exact event/object/snapshot evidence is revalidated.
    """

    EVENT_TYPES = frozenset(
        {
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
        }
    )

    def __init__(
        self, connection: object, *, deployment: StripeDeploymentManifest
    ) -> None:
        self._connection = connection
        self._deployment = deployment

    def project(
        self,
        *,
        webhook_event_id: int,
        external_event_id: str,
        worker_lease_token: UUID,
        snapshot: StripeSubscriptionSnapshot,
    ) -> StripeSubscriptionProjectionResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Subscription projection requires a transaction")
        binding = self._deployment.prices.get(snapshot.price_code)
        if (
            snapshot.environment != self._deployment.billing_environment
            or binding is None
            or binding.price_id != snapshot.stripe_price_id
        ):
            raise StripeSubscriptionProjectionError(
                "Subscription Price is outside deployment authority"
            )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT set_config('app.commercial_webhook_lease_token', %s, TRUE)",
                (str(worker_lease_token),),
            )
            cursor.execute(
                """SELECT environment, event_type, event_created_at,
                          payload_json->'data'->'object'->>'id',
                          payload_json->'data'->'object'->>'customer',
                          processing_state, worker_lease_token,
                          worker_lease_expires_at > statement_timestamp()
                     FROM commercial_webhook_events
                    WHERE id = %s AND provider = 'stripe'
                      AND external_event_id = %s
                      AND integrity_state = 'verified'
                    FOR UPDATE""",
                (webhook_event_id, external_event_id),
            )
            webhook = cursor.fetchone()
            if webhook is None or webhook[1] not in self.EVENT_TYPES:
                raise StripeSubscriptionProjectionError("Webhook identity is invalid")
            (environment, _event_type, event_created_at, event_object_id,
             event_customer_id, processing_state, active_lease,
             lease_unexpired) = webhook
            if _event_type == "customer.subscription.deleted" and snapshot.status != "canceled":
                raise StripeSubscriptionProjectionError(
                    "Deleted Subscription event is not terminal"
                )
            if (
                environment != snapshot.environment
                or event_object_id != snapshot.external_object_id
                or event_customer_id != snapshot.external_customer_id
            ):
                raise StripeSubscriptionProjectionError(
                    "Webhook subscription lineage is invalid"
                )
            cursor.execute(
                """SELECT projection_object_id, resulting_object_revision,
                          resulting_agreement_version, disposition,
                          external_event_id, external_object_id,
                          observed_snapshot_sha256
                     FROM commercial_stripe_projection_events
                    WHERE webhook_event_id = %s""",
                (webhook_event_id,),
            )
            replay = cursor.fetchone()
            if replay is not None:
                if (
                    processing_state != "applied"
                    or replay[4] != external_event_id
                    or replay[5] != snapshot.external_object_id
                    or replay[6] != snapshot.snapshot_sha256
                ):
                    raise StripeSubscriptionProjectionError(
                        "Subscription replay does not match authority"
                    )
                return StripeSubscriptionProjectionResult(
                    projection_object_id=int(replay[0]),
                    object_revision=int(replay[1]),
                    agreement_version=int(replay[2]),
                    disposition=str(replay[3]),
                    durable_replayed=True,
                )
            if (
                processing_state != "processing"
                or str(active_lease) != str(worker_lease_token)
                or not lease_unexpired
            ):
                raise StripeSubscriptionProjectionError("Webhook lease is invalid")

            cursor.execute(
                """SELECT attempt.commercial_account_id, attempt.agreement_id,
                          attempt.account_public_id, attempt.agreement_public_id,
                          customer.external_customer_id
                     FROM commercial_checkout_attempts attempt
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id = attempt.commercial_account_id
                      AND customer.provider = 'stripe'
                      AND customer.environment = attempt.environment
                    WHERE attempt.environment = %s
                      AND attempt.agreement_public_id = %s
                      AND attempt.state = 'session_created'
                    FOR UPDATE OF attempt, customer""",
                (environment, str(snapshot.agreement_public_id)),
            )
            lineage = cursor.fetchone()
            if lineage is None:
                raise StripeSubscriptionProjectionError(
                    "Subscription agreement lineage is missing"
                )
            account_id, agreement_id = int(lineage[0]), int(lineage[1])
            if (
                str(lineage[2]) != str(snapshot.commercial_account_public_id)
                or str(lineage[3]) != str(snapshot.agreement_public_id)
                or lineage[4] != snapshot.external_customer_id
            ):
                raise StripeSubscriptionProjectionError(
                    "Subscription authority does not match snapshot"
                )
            cursor.execute(
                """SELECT version
                     FROM commercial_agreements
                    WHERE id = %s AND commercial_account_id = %s
                      AND public_id = %s AND billing_provider = 'stripe'
                      AND billing_environment = %s
                      AND external_subscription_id = %s
                    FOR UPDATE""",
                (agreement_id, account_id, str(snapshot.agreement_public_id),
                 environment, snapshot.external_object_id),
            )
            agreement = cursor.fetchone()
            if agreement is None:
                raise StripeSubscriptionProjectionError(
                    "Subscription agreement lineage is missing"
                )
            agreement_version = int(agreement[0])

            cursor.execute(
                """SELECT id, snapshot_sha256, revision, authoritative_fetched_at
                     FROM commercial_stripe_projection_objects
                    WHERE environment = %s AND object_type = 'subscription'
                      AND external_object_id = %s
                    FOR UPDATE""",
                (environment, snapshot.external_object_id),
            )
            authority = cursor.fetchone()
            if authority is None:
                cursor.execute(
                    """INSERT INTO commercial_stripe_projection_objects (
                           environment, object_type, external_object_id,
                           external_customer_id, commercial_account_id, agreement_id,
                           object_state, snapshot_sha256, provider_created_at,
                           authoritative_fetched_at, highest_event_created_at,
                           last_webhook_event_id, revision
                       ) VALUES (%s, 'subscription', %s, %s, %s, %s, 'current',
                                 %s, %s, %s, %s, %s, 1)
                    RETURNING id, revision""",
                    (environment, snapshot.external_object_id,
                     snapshot.external_customer_id, account_id, agreement_id,
                     snapshot.snapshot_sha256, snapshot.provider_created_at,
                     snapshot.authoritative_fetched_at, event_created_at,
                     webhook_event_id),
                )
                projection_object_id, object_revision = map(int, cursor.fetchone())
                disposition = "applied"
            elif authority[1] == snapshot.snapshot_sha256:
                projection_object_id, object_revision = int(authority[0]), int(authority[2])
                disposition = "unchanged"
            elif snapshot.authoritative_fetched_at < authority[3]:
                projection_object_id, object_revision = int(authority[0]), int(authority[2])
                disposition = "superseded"
            else:
                cursor.execute(
                    """UPDATE commercial_stripe_projection_objects
                          SET object_state = 'current', snapshot_sha256 = %s,
                              authoritative_fetched_at = GREATEST(authoritative_fetched_at, %s),
                              highest_event_created_at = GREATEST(highest_event_created_at, %s),
                              last_webhook_event_id = %s, revision = revision + 1
                        WHERE id = %s RETURNING revision""",
                    (snapshot.snapshot_sha256, snapshot.authoritative_fetched_at,
                     event_created_at, webhook_event_id, int(authority[0])),
                )
                projection_object_id = int(authority[0])
                object_revision = int(cursor.fetchone()[0])
                disposition = "applied"
            cursor.execute(
                """INSERT INTO commercial_stripe_projection_events (
                       webhook_event_id, environment, external_event_id,
                       projection_object_id, object_type, external_object_id,
                       observed_snapshot_sha256, disposition,
                       resulting_object_revision, resulting_agreement_version
                   ) VALUES (%s, %s, %s, %s, 'subscription', %s, %s, %s, %s, %s)""",
                (webhook_event_id, environment, external_event_id,
                 projection_object_id, snapshot.external_object_id,
                 snapshot.snapshot_sha256, disposition, object_revision,
                 agreement_version),
            )
            cursor.execute(
                """UPDATE commercial_webhook_events
                      SET processing_state = 'applied', processed_at = statement_timestamp(),
                          processing_started_at = NULL, worker_lease_token = NULL,
                          worker_lease_expires_at = NULL,
                          last_transition_lease_token = %s
                    WHERE id = %s""",
                (str(worker_lease_token), webhook_event_id),
            )
            if cursor.rowcount != 1:
                raise StripeSubscriptionProjectionError("Webhook completion failed")
            return StripeSubscriptionProjectionResult(
                projection_object_id=projection_object_id,
                object_revision=object_revision,
                agreement_version=agreement_version,
                disposition=disposition,
            )
        finally:
            cursor.close()


__all__ = [
    "PostgresStripeSubscriptionProjector",
    "StripeSubscriptionProjectionError",
    "StripeSubscriptionProjectionResult",
]
