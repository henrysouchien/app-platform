"""Fenced, order-tolerant persistence of authoritative Stripe Disputes."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from .stripe_projection_provider import StripeDisputeSnapshot


class StripeDisputeProjectionError(RuntimeError):
    """Safe failure at the Dispute projection authority boundary."""


@dataclass(frozen=True, slots=True)
class StripeDisputeProjectionResult:
    projection_object_id: int
    projection_event_id: int
    object_revision: int
    agreement_version: int
    disposition: str
    durable_replayed: bool = False


class PostgresStripeDisputeProjector:
    """Persist normalized Dispute authority without financial/access effects."""

    EVENT_TYPES = frozenset(
        {
            "charge.dispute.created",
            "charge.dispute.updated",
            "charge.dispute.closed",
            "charge.dispute.funds_withdrawn",
            "charge.dispute.funds_reinstated",
        }
    )

    def __init__(self, connection: object) -> None:
        self._connection = connection

    def project(
        self,
        *,
        webhook_event_id: int,
        external_event_id: str,
        worker_lease_token: UUID,
        snapshot: StripeDisputeSnapshot,
    ) -> StripeDisputeProjectionResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Dispute projection requires a transaction")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT set_config('app.commercial_webhook_lease_token', %s, TRUE)",
                (str(worker_lease_token),),
            )
            cursor.execute(
                """SELECT environment, event_type, event_created_at,
                          payload_json->'data'->'object'->>'id',
                          processing_state, worker_lease_token,
                          worker_lease_expires_at > statement_timestamp()
                     FROM commercial_webhook_events
                    WHERE id = %s AND provider = 'stripe'
                      AND external_event_id = %s
                      AND integrity_state = 'verified' FOR UPDATE""",
                (webhook_event_id, external_event_id),
            )
            webhook = cursor.fetchone()
            if webhook is None or webhook[1] not in self.EVENT_TYPES:
                raise StripeDisputeProjectionError("Webhook identity is invalid")
            (
                environment,
                event_type,
                event_created_at,
                event_object_id,
                processing_state,
                active_lease,
                lease_unexpired,
            ) = webhook
            if event_type == "charge.dispute.closed" and snapshot.status not in {
                "lost",
                "prevented",
                "warning_closed",
                "won",
            }:
                raise StripeDisputeProjectionError(
                    "Closed Dispute event is not authoritatively terminal"
                )
            if (
                environment != snapshot.environment
                or event_object_id != snapshot.external_object_id
            ):
                raise StripeDisputeProjectionError("Webhook Dispute lineage is invalid")
            cursor.execute(
                """SELECT id, projection_object_id, resulting_object_revision,
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
                    or replay[5] != external_event_id
                    or replay[6] != snapshot.external_object_id
                    or replay[7] != snapshot.snapshot_sha256
                ):
                    raise StripeDisputeProjectionError(
                        "Dispute replay does not match authority"
                    )
                return StripeDisputeProjectionResult(
                    projection_event_id=int(replay[0]),
                    projection_object_id=int(replay[1]),
                    object_revision=int(replay[2]),
                    agreement_version=int(replay[3]),
                    disposition=str(replay[4]),
                    durable_replayed=True,
                )
            if (
                processing_state != "processing"
                or str(active_lease) != str(worker_lease_token)
                or not lease_unexpired
            ):
                raise StripeDisputeProjectionError("Webhook lease is invalid")
            cursor.execute(
                "SELECT to_regclass('commercial_stripe_payment_lineage') IS NOT NULL"
            )
            payment_lineage = (
                "commercial_stripe_payment_lineage"
                if cursor.fetchone()[0]
                else "commercial_stripe_invoice_payment_effects"
            )
            cursor.execute(
                f"""SELECT movement.commercial_account_id, movement.agreement_id,
                          movement.document_id, customer.external_customer_id
                     FROM commercial_money_movements movement
                     JOIN {payment_lineage} payment_effect
                       ON payment_effect.money_movement_id = movement.id
                      AND payment_effect.external_payment_intent_id = %s
                      AND payment_effect.external_charge_id = %s
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id = movement.commercial_account_id
                      AND customer.provider = 'stripe'
                      AND customer.environment = movement.environment
                    WHERE movement.provider = 'stripe' AND movement.environment = %s
                      AND movement.external_object_type = 'payment_intent'
                      AND movement.external_object_id = %s
                      AND movement.movement_kind = 'cash_receipt'""",
                (
                    snapshot.external_payment_intent_id,
                    snapshot.external_charge_id,
                    environment,
                    snapshot.external_payment_intent_id,
                ),
            )
            lineage = cursor.fetchone()
            if lineage is None or lineage[2] is None:
                raise StripeDisputeProjectionError("Dispute payment lineage is missing")
            account_id, agreement_id, document_id = map(int, lineage[:3])
            external_customer_id = str(lineage[3])
            cursor.execute(
                "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
                (account_id,),
            )
            if cursor.fetchone() is None:
                raise StripeDisputeProjectionError("Dispute account lineage is missing")
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
                (account_id, agreement_id, external_customer_id),
            )
            if cursor.fetchone() is None:
                raise StripeDisputeProjectionError("Dispute tenant lineage is missing")
            cursor.execute(
                """SELECT agreement.version
                     FROM commercial_agreements agreement
                     JOIN commercial_billing_documents document
                       ON document.id = %s
                      AND document.agreement_id = agreement.id
                      AND document.commercial_account_id = agreement.commercial_account_id
                      AND document.provider = 'stripe'
                      AND document.environment = agreement.billing_environment
                    WHERE agreement.id = %s
                      AND agreement.commercial_account_id = %s
                      AND agreement.billing_provider = 'stripe'
                      AND agreement.billing_environment = %s FOR UPDATE OF agreement""",
                (document_id, agreement_id, account_id, environment),
            )
            agreement = cursor.fetchone()
            if agreement is None:
                raise StripeDisputeProjectionError(
                    "Dispute agreement lineage is missing"
                )
            agreement_version = int(agreement[0])
            cursor.execute(
                f"""SELECT movement.id FROM commercial_money_movements movement
                    JOIN {payment_lineage} payment_effect
                      ON payment_effect.money_movement_id = movement.id
                     AND payment_effect.external_payment_intent_id = %s
                     AND payment_effect.external_charge_id = %s
                   WHERE movement.provider = 'stripe' AND movement.environment = %s
                     AND movement.external_object_type = 'payment_intent'
                     AND movement.external_object_id = %s
                     AND movement.movement_kind = 'cash_receipt'
                     AND movement.commercial_account_id = %s
                     AND movement.agreement_id = %s AND movement.document_id = %s
                   FOR UPDATE OF movement""",
                (
                    snapshot.external_payment_intent_id,
                    snapshot.external_charge_id,
                    environment,
                    snapshot.external_payment_intent_id,
                    account_id,
                    agreement_id,
                    document_id,
                ),
            )
            if cursor.fetchone() is None:
                raise StripeDisputeProjectionError("Dispute payment lineage changed")
            cursor.execute(
                """SELECT id, snapshot_sha256, revision, authoritative_fetched_at
                     FROM commercial_stripe_projection_objects
                    WHERE environment = %s AND object_type = 'dispute'
                      AND external_object_id = %s FOR UPDATE""",
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
                       ) VALUES (%s, 'dispute', %s, %s, %s, %s, 'current',
                                 %s, %s, %s, %s, %s, 1) RETURNING id, revision""",
                    (
                        environment,
                        snapshot.external_object_id,
                        external_customer_id,
                        account_id,
                        agreement_id,
                        snapshot.snapshot_sha256,
                        snapshot.provider_created_at,
                        snapshot.authoritative_fetched_at,
                        event_created_at,
                        webhook_event_id,
                    ),
                )
                projection_object_id, object_revision = map(int, cursor.fetchone())
                disposition = "applied"
            elif authority[1] == snapshot.snapshot_sha256:
                projection_object_id, object_revision = (
                    int(authority[0]),
                    int(authority[2]),
                )
                disposition = "unchanged"
                if snapshot.authoritative_fetched_at > authority[3]:
                    cursor.execute(
                        """UPDATE commercial_stripe_projection_objects
                              SET authoritative_fetched_at = %s,
                                  highest_event_created_at = GREATEST(
                                      highest_event_created_at, %s),
                                  last_webhook_event_id = %s, revision = revision + 1
                            WHERE id = %s RETURNING revision""",
                        (
                            snapshot.authoritative_fetched_at,
                            event_created_at,
                            webhook_event_id,
                            projection_object_id,
                        ),
                    )
                    object_revision = int(cursor.fetchone()[0])
            elif snapshot.authoritative_fetched_at < authority[3]:
                projection_object_id, object_revision = (
                    int(authority[0]),
                    int(authority[2]),
                )
                disposition = "superseded"
            elif snapshot.authoritative_fetched_at == authority[3]:
                projection_object_id, object_revision = (
                    int(authority[0]),
                    int(authority[2]),
                )
                disposition = "superseded"
            else:
                cursor.execute(
                    """UPDATE commercial_stripe_projection_objects
                          SET snapshot_sha256 = %s, authoritative_fetched_at = %s,
                              highest_event_created_at = GREATEST(highest_event_created_at, %s),
                              last_webhook_event_id = %s, revision = revision + 1
                        WHERE id = %s RETURNING revision""",
                    (
                        snapshot.snapshot_sha256,
                        snapshot.authoritative_fetched_at,
                        event_created_at,
                        webhook_event_id,
                        int(authority[0]),
                    ),
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
                   ) VALUES (%s, %s, %s, %s, 'dispute', %s, %s, %s, %s, %s)
                RETURNING id""",
                (
                    webhook_event_id,
                    environment,
                    external_event_id,
                    projection_object_id,
                    snapshot.external_object_id,
                    snapshot.snapshot_sha256,
                    disposition,
                    object_revision,
                    agreement_version,
                ),
            )
            projection_event_id = int(cursor.fetchone()[0])
            cursor.execute(
                """UPDATE commercial_webhook_events
                      SET processing_state = 'applied', processed_at = statement_timestamp(),
                          processing_started_at = NULL, worker_lease_token = NULL,
                          worker_lease_expires_at = NULL,
                          last_transition_lease_token = %s WHERE id = %s""",
                (str(worker_lease_token), webhook_event_id),
            )
            if cursor.rowcount != 1:
                raise StripeDisputeProjectionError("Webhook completion failed")
            return StripeDisputeProjectionResult(
                projection_object_id=projection_object_id,
                projection_event_id=projection_event_id,
                object_revision=object_revision,
                agreement_version=agreement_version,
                disposition=disposition,
            )
        finally:
            cursor.close()


__all__ = [
    "PostgresStripeDisputeProjector",
    "StripeDisputeProjectionError",
    "StripeDisputeProjectionResult",
]
