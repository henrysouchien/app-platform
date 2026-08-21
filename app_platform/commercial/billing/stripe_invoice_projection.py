"""Fenced, order-tolerant persistence of authoritative Stripe invoices."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from .stripe_config import StripeDeploymentManifest
from .stripe_projection_provider import StripeInvoiceSnapshot


class StripeInvoiceProjectionError(RuntimeError):
    """Safe failure at the Invoice projection authority boundary."""


@dataclass(frozen=True, slots=True)
class StripeInvoiceProjectionResult:
    projection_object_id: int
    projection_event_id: int
    object_revision: int
    agreement_version: int
    disposition: str
    durable_replayed: bool = False


class PostgresStripeInvoiceProjector:
    """Persist normalized Invoice authority without ledger or access effects."""

    EVENT_TYPES = frozenset({
        "invoice.created",
        "invoice.finalized",
        "invoice.paid",
        "invoice.payment_failed",
        "invoice.payment_action_required",
        "invoice.voided",
        "invoice.marked_uncollectible",
    })
    TERMINAL_EVENT_STATUS = {
        "invoice.paid": "paid",
        "invoice.voided": "void",
        "invoice.marked_uncollectible": "uncollectible",
    }

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
        snapshot: StripeInvoiceSnapshot,
    ) -> StripeInvoiceProjectionResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Invoice projection requires a transaction")
        self._validate_deployment(snapshot)
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
                raise StripeInvoiceProjectionError("Webhook identity is invalid")
            (environment, event_type, event_created_at, event_object_id,
             event_customer_id, processing_state, active_lease,
             lease_unexpired) = webhook
            required_status = self.TERMINAL_EVENT_STATUS.get(event_type)
            if required_status is not None and snapshot.status != required_status:
                raise StripeInvoiceProjectionError(
                    "Invoice event does not match authoritative status"
                )
            if event_type == "invoice.finalized" and snapshot.status == "draft":
                raise StripeInvoiceProjectionError("Finalized Invoice remains draft")
            if (
                environment != snapshot.environment
                or event_object_id != snapshot.external_object_id
                or event_customer_id != snapshot.external_customer_id
            ):
                raise StripeInvoiceProjectionError("Webhook invoice lineage is invalid")

            cursor.execute(
                """SELECT projection.id, projection.projection_object_id,
                          projection.resulting_object_revision,
                          projection.resulting_agreement_version,
                          projection.disposition, projection.external_event_id,
                          projection.external_object_id,
                          projection.observed_snapshot_sha256
                     FROM commercial_stripe_projection_events projection
                    WHERE projection.webhook_event_id = %s""",
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
                    raise StripeInvoiceProjectionError(
                        "Invoice replay does not match authority"
                    )
                return StripeInvoiceProjectionResult(
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
                raise StripeInvoiceProjectionError("Webhook lease is invalid")

            account_id, agreement_id, agreement_version = self._lock_lineage(
                cursor, snapshot
            )
            cursor.execute(
                """SELECT id, snapshot_sha256, revision, authoritative_fetched_at
                     FROM commercial_stripe_projection_objects
                    WHERE environment = %s AND object_type = 'invoice'
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
                       ) VALUES (%s, 'invoice', %s, %s, %s, %s, 'current',
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
            elif snapshot.authoritative_fetched_at < authority[3]:
                projection_object_id, object_revision = int(authority[0]), int(authority[2])
                disposition = "superseded"
            elif authority[1] == snapshot.snapshot_sha256:
                projection_object_id, object_revision = int(authority[0]), int(authority[2])
                disposition = "unchanged"
                if snapshot.authoritative_fetched_at > authority[3]:
                    cursor.execute(
                        """UPDATE commercial_stripe_projection_objects
                              SET authoritative_fetched_at = %s,
                                  highest_event_created_at = GREATEST(
                                      highest_event_created_at, %s
                                  ),
                                  last_webhook_event_id = %s,
                                  revision = revision + 1
                            WHERE id = %s RETURNING revision""",
                        (snapshot.authoritative_fetched_at, event_created_at,
                         webhook_event_id, projection_object_id),
                    )
                    object_revision = int(cursor.fetchone()[0])
            elif snapshot.authoritative_fetched_at == authority[3]:
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
                   ) VALUES (%s, %s, %s, %s, 'invoice', %s, %s, %s, %s, %s)
                RETURNING id""",
                (webhook_event_id, environment, external_event_id,
                 projection_object_id, snapshot.external_object_id,
                 snapshot.snapshot_sha256, disposition, object_revision,
                 agreement_version),
            )
            projection_event_id = int(cursor.fetchone()[0])
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
                raise StripeInvoiceProjectionError("Webhook completion failed")
            return StripeInvoiceProjectionResult(
                projection_object_id=projection_object_id,
                projection_event_id=projection_event_id,
                object_revision=object_revision,
                agreement_version=agreement_version,
                disposition=disposition,
            )
        finally:
            cursor.close()

    def _validate_deployment(self, snapshot: StripeInvoiceSnapshot) -> None:
        expected = {
            price_code: binding.price_id
            for price_code, binding in self._deployment.prices.items()
        }
        if (
            snapshot.environment != self._deployment.billing_environment
            or expected.get(snapshot.subscription_price_code) is None
            or any(expected.get(line.price_code) != line.stripe_price_id for line in snapshot.lines)
        ):
            raise StripeInvoiceProjectionError(
                "Invoice Price is outside deployment authority"
            )

    @staticmethod
    def _lock_lineage(cursor, snapshot: StripeInvoiceSnapshot) -> tuple[int, int, int]:
        cursor.execute(
            """SELECT account.id
                 FROM commercial_accounts account
                WHERE account.public_id = %s
                FOR UPDATE""",
            (str(snapshot.commercial_account_public_id),),
        )
        account = cursor.fetchone()
        if account is None:
            raise StripeInvoiceProjectionError("Invoice account lineage is missing")
        account_id = int(account[0])
        cursor.execute(
            """SELECT attempt.agreement_id
                 FROM commercial_checkout_attempts attempt
                 JOIN billing_provider_customers customer
                   ON customer.commercial_account_id = attempt.commercial_account_id
                  AND customer.provider = 'stripe'
                  AND customer.environment = attempt.environment
                WHERE attempt.commercial_account_id = %s
                  AND attempt.agreement_public_id = %s
                  AND attempt.state = 'session_created'
                  AND attempt.environment = %s
                  AND customer.external_customer_id = %s
                FOR UPDATE OF attempt, customer""",
            (account_id, str(snapshot.agreement_public_id), snapshot.environment,
             snapshot.external_customer_id),
        )
        row = cursor.fetchone()
        if row is None:
            raise StripeInvoiceProjectionError("Invoice tenant lineage is missing")
        agreement_id = int(row[0])
        cursor.execute(
            """SELECT version
                 FROM commercial_agreements
                WHERE id = %s AND commercial_account_id = %s
                  AND public_id = %s AND billing_provider = 'stripe'
                  AND billing_environment = %s
                  AND external_subscription_id = %s
                FOR UPDATE""",
            (agreement_id, account_id, str(snapshot.agreement_public_id),
             snapshot.environment, snapshot.external_subscription_id),
        )
        agreement = cursor.fetchone()
        if agreement is None:
            raise StripeInvoiceProjectionError("Invoice agreement lineage is missing")
        return account_id, agreement_id, int(agreement[0])


__all__ = [
    "PostgresStripeInvoiceProjector",
    "StripeInvoiceProjectionError",
    "StripeInvoiceProjectionResult",
]
