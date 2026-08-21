"""Fenced projection of a completed Stripe Checkout session."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import NAMESPACE_URL, UUID, uuid5

from .stripe_projection_provider import StripeCheckoutSnapshot


class StripeCheckoutProjectionError(RuntimeError):
    """Safe failure at the Checkout projection authority boundary."""


@dataclass(frozen=True, slots=True)
class StripeCheckoutProjectionResult:
    projection_object_id: int
    object_revision: int
    agreement_version: int
    disposition: str
    durable_replayed: bool = False


class PostgresStripeCheckoutProjector:
    """Apply verified Checkout linkage in the caller-owned transaction.

    A first application requires the current claim lease. A terminal durable replay
    is lease-free after exact webhook/object/snapshot evidence is revalidated.
    This projector deliberately ignores ``payment_status`` and never activates an
    agreement or writes entitlements.
    """

    EVENT_TYPE = "checkout.session.completed"

    def __init__(self, connection: object) -> None:
        self._connection = connection

    def project(
        self,
        *,
        webhook_event_id: int,
        external_event_id: str,
        worker_lease_token: UUID,
        snapshot: StripeCheckoutSnapshot,
    ) -> StripeCheckoutProjectionResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Checkout projection requires a transaction")
        if snapshot.status != "complete":
            raise StripeCheckoutProjectionError("Checkout session is not complete")

        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT set_config('app.commercial_webhook_lease_token', %s, TRUE)",
                (str(worker_lease_token),),
            )
            cursor.execute(
                """SELECT environment, event_created_at,
                          payload_json->'data'->'object'->>'id',
                          payload_json->'data'->'object'->>'customer',
                          processing_state, worker_lease_token,
                          worker_lease_expires_at > statement_timestamp()
                     FROM commercial_webhook_events
                    WHERE id = %s AND provider = 'stripe'
                      AND external_event_id = %s
                      AND event_type = %s
                      AND integrity_state = 'verified'
                    FOR UPDATE""",
                (webhook_event_id, external_event_id, self.EVENT_TYPE),
            )
            webhook = cursor.fetchone()
            if webhook is None:
                raise StripeCheckoutProjectionError("Webhook identity is invalid")
            (environment, event_created_at, event_object_id, event_customer_id,
             processing_state, active_lease, lease_unexpired) = webhook
            if (
                environment != snapshot.environment
                or event_object_id != snapshot.external_object_id
                or event_customer_id != snapshot.external_customer_id
            ):
                raise StripeCheckoutProjectionError("Webhook object lineage is invalid")
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
                    raise StripeCheckoutProjectionError("Projection replay does not match authority")
                return StripeCheckoutProjectionResult(
                    projection_object_id=int(replay[0]),
                    object_revision=int(replay[1]),
                    agreement_version=int(replay[2]),
                    disposition=str(replay[3]), durable_replayed=True,
                )
            if (
                processing_state != "processing"
                or str(active_lease) != str(worker_lease_token)
                or not lease_unexpired
            ):
                raise StripeCheckoutProjectionError("Webhook lease is invalid")

            cursor.execute(
                """SELECT attempt.commercial_account_id, attempt.agreement_id,
                          attempt.account_public_id, attempt.agreement_public_id,
                          attempt.price_code, attempt.stripe_price_id,
                          customer.external_customer_id
                     FROM commercial_checkout_attempts attempt
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id = attempt.commercial_account_id
                      AND customer.provider = 'stripe'
                      AND customer.environment = attempt.environment
                    WHERE attempt.environment = %s
                      AND attempt.external_checkout_session_id = %s
                      AND attempt.state = 'session_created'
                    FOR UPDATE OF attempt, customer""",
                (environment, snapshot.external_object_id),
            )
            lineage = cursor.fetchone()
            if lineage is None:
                raise StripeCheckoutProjectionError("Checkout attempt lineage is missing")
            account_id, agreement_id = int(lineage[0]), int(lineage[1])
            if (
                str(lineage[2]) != str(snapshot.commercial_account_public_id)
                or str(lineage[3]) != str(snapshot.agreement_public_id)
                or lineage[4] != snapshot.price_code
                or lineage[5] != snapshot.stripe_price_id
                or lineage[6] != snapshot.external_customer_id
            ):
                raise StripeCheckoutProjectionError("Checkout authority does not match snapshot")

            cursor.execute(
                """SELECT version, state, external_subscription_id
                     FROM commercial_agreements
                    WHERE id = %s AND commercial_account_id = %s
                      AND public_id = %s AND billing_provider = 'stripe'
                      AND billing_environment = %s
                    FOR UPDATE""",
                (agreement_id, account_id, str(snapshot.agreement_public_id), environment),
            )
            agreement = cursor.fetchone()
            if agreement is None:
                raise StripeCheckoutProjectionError("Checkout agreement is missing")
            existing_subscription_id = agreement[2]
            if (
                existing_subscription_id is not None
                and existing_subscription_id != snapshot.external_subscription_id
            ):
                raise StripeCheckoutProjectionError("Agreement subscription identity conflicts")
            agreement_version = int(agreement[0])
            if agreement[1] != "pending_payment":
                if (
                    snapshot.external_subscription_id is None
                    or existing_subscription_id != snapshot.external_subscription_id
                ):
                    raise StripeCheckoutProjectionError(
                        "Advanced agreement subscription identity is not reconciled"
                    )
            elif snapshot.external_subscription_id is not None and existing_subscription_id is None:
                prior_version = agreement_version
                cursor.execute(
                    """UPDATE commercial_agreements
                          SET external_subscription_id = %s,
                              version = version + 1,
                              updated_at = statement_timestamp()
                        WHERE id = %s
                    RETURNING version""",
                    (snapshot.external_subscription_id, agreement_id),
                )
                agreement_version = int(cursor.fetchone()[0])
                command_id = uuid5(
                    NAMESPACE_URL, f"hank:stripe:provider-link:{external_event_id}"
                )
                audit_event_id = uuid5(
                    NAMESPACE_URL, f"hank:stripe:provider-link:audit:{external_event_id}"
                )
                cursor.execute(
                    """INSERT INTO commercial_audit_log (
                           event_id, commercial_account_id, agreement_id, actor_type,
                           actor_id, action, target_type, target_id, reason_code,
                           before_json, after_json
                       ) VALUES (%s, %s, %s, 'stripe', %s,
                           'commercial.agreement.provider_link', 'commercial_agreement',
                           %s, 'stripe.checkout.subscription_linked',
                           jsonb_build_object('account_id', %s, 'agreement_id', %s,
                                              'state', 'pending_payment', 'version', %s),
                           jsonb_build_object('account_id', %s, 'agreement_id', %s,
                                              'state', 'pending_payment', 'version', %s))""",
                    (str(audit_event_id), account_id, agreement_id, external_event_id,
                     str(snapshot.agreement_public_id), account_id, agreement_id,
                     prior_version, account_id, agreement_id, agreement_version),
                )
                cursor.execute(
                    """INSERT INTO commercial_agreement_provider_links (
                           command_id, commercial_account_id, agreement_id, provider,
                           environment, external_event_id, external_subscription_id,
                           payload_sha256, prior_version, result_version, audit_event_id
                       ) VALUES (%s, %s, %s, 'stripe', %s, %s, %s, %s, %s, %s, %s)""",
                    (str(command_id), account_id, agreement_id, environment,
                     external_event_id, snapshot.external_subscription_id,
                     snapshot.snapshot_sha256, prior_version, agreement_version,
                     str(audit_event_id)),
                )

            cursor.execute(
                """SELECT id, snapshot_sha256, revision,
                          highest_event_created_at, authoritative_fetched_at
                     FROM commercial_stripe_projection_objects
                    WHERE environment = %s AND object_type = 'checkout_session'
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
                       ) VALUES (%s, 'checkout_session', %s, %s, %s, %s, 'current',
                                 %s, %s, %s, %s, %s, 1)
                    RETURNING id, revision""",
                    (environment, snapshot.external_object_id, snapshot.external_customer_id,
                     account_id, agreement_id, snapshot.snapshot_sha256,
                     snapshot.provider_created_at, snapshot.authoritative_fetched_at,
                     event_created_at, webhook_event_id),
                )
                projection_object_id, object_revision = map(int, cursor.fetchone())
                disposition = "applied"
            elif authority[1] == snapshot.snapshot_sha256:
                projection_object_id, object_revision = int(authority[0]), int(authority[2])
                disposition = "unchanged"
            elif snapshot.authoritative_fetched_at < authority[4]:
                projection_object_id, object_revision = int(authority[0]), int(authority[2])
                disposition = "superseded"
            else:
                cursor.execute(
                    """UPDATE commercial_stripe_projection_objects
                          SET object_state = 'current', snapshot_sha256 = %s,
                              authoritative_fetched_at = GREATEST(authoritative_fetched_at, %s),
                              highest_event_created_at = GREATEST(highest_event_created_at, %s),
                              last_webhook_event_id = %s, revision = revision + 1
                        WHERE id = %s
                    RETURNING revision""",
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
                   ) VALUES (%s, %s, %s, %s, 'checkout_session', %s, %s, %s, %s, %s)""",
                (webhook_event_id, environment, external_event_id,
                 projection_object_id, snapshot.external_object_id,
                 snapshot.snapshot_sha256, disposition, object_revision, agreement_version),
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
                raise StripeCheckoutProjectionError("Webhook completion failed")
            return StripeCheckoutProjectionResult(
                projection_object_id=projection_object_id,
                object_revision=object_revision,
                agreement_version=agreement_version,
                disposition=disposition,
            )
        finally:
            cursor.close()


__all__ = [
    "PostgresStripeCheckoutProjector",
    "StripeCheckoutProjectionError",
    "StripeCheckoutProjectionResult",
]
