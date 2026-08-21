"""Fenced, order-tolerant persistence of authoritative Stripe Credit Notes."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from .stripe_projection_provider import StripeCreditNoteSnapshot


class StripeCreditNoteProjectionError(RuntimeError):
    """Safe failure at the Credit Note projection authority boundary."""


@dataclass(frozen=True, slots=True)
class StripeCreditNoteProjectionResult:
    projection_object_id: int
    projection_event_id: int
    object_revision: int
    agreement_version: int
    disposition: str
    durable_replayed: bool = False


class PostgresStripeCreditNoteProjector:
    """Persist normalized Credit Note authority without financial/access effects."""

    EVENT_TYPES = frozenset(
        {"credit_note.created", "credit_note.updated", "credit_note.voided"}
    )

    def __init__(self, connection: object) -> None:
        self._connection = connection

    def project(
        self,
        *,
        webhook_event_id: int,
        external_event_id: str,
        worker_lease_token: UUID,
        snapshot: StripeCreditNoteSnapshot,
    ) -> StripeCreditNoteProjectionResult:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe Credit Note projection requires a transaction")
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
                          payload_json->'data'->'object'->>'invoice',
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
                raise StripeCreditNoteProjectionError("Webhook identity is invalid")
            (
                environment,
                event_type,
                event_created_at,
                event_object_id,
                event_customer_id,
                event_invoice_id,
                processing_state,
                active_lease,
                lease_unexpired,
            ) = webhook
            if event_type == "credit_note.voided" and snapshot.status != "void":
                raise StripeCreditNoteProjectionError(
                    "Voided Credit Note event is not authoritatively void"
                )
            if (
                environment != snapshot.environment
                or event_object_id != snapshot.external_object_id
                or event_customer_id != snapshot.external_customer_id
                or event_invoice_id != snapshot.external_invoice_id
            ):
                raise StripeCreditNoteProjectionError(
                    "Webhook Credit Note lineage is invalid"
                )
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
                    raise StripeCreditNoteProjectionError(
                        "Credit Note replay does not match authority"
                    )
                return StripeCreditNoteProjectionResult(
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
                raise StripeCreditNoteProjectionError("Webhook lease is invalid")

            cursor.execute(
                """SELECT effect.commercial_account_id, effect.agreement_id,
                          effect.document_id, object.external_customer_id
                     FROM commercial_stripe_invoice_effects effect
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
                      AND document.commercial_account_id = effect.commercial_account_id
                      AND document.agreement_id = effect.agreement_id
                      AND document.provider = 'stripe'
                      AND document.environment = effect.environment
                      AND document.external_document_id = effect.external_invoice_id
                    WHERE effect.environment = %s
                      AND effect.external_invoice_id = %s
                      AND effect.document_created""",
                (environment, snapshot.external_invoice_id),
            )
            lineage_rows = cursor.fetchall()
            if len(lineage_rows) != 1:
                raise StripeCreditNoteProjectionError(
                    "Credit Note Invoice lineage is missing or ambiguous"
                )
            account_id, agreement_id, document_id = map(int, lineage_rows[0][:3])
            external_customer_id = str(lineage_rows[0][3])
            if external_customer_id != snapshot.external_customer_id:
                raise StripeCreditNoteProjectionError(
                    "Credit Note customer lineage is invalid"
                )

            cursor.execute(
                "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
                (account_id,),
            )
            if cursor.fetchone() is None:
                raise StripeCreditNoteProjectionError(
                    "Credit Note account lineage is missing"
                )
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
                raise StripeCreditNoteProjectionError(
                    "Credit Note tenant lineage is missing"
                )
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
                      AND agreement.billing_environment = %s
                    FOR UPDATE OF agreement, document""",
                (document_id, agreement_id, account_id, environment),
            )
            agreement = cursor.fetchone()
            if agreement is None:
                raise StripeCreditNoteProjectionError(
                    "Credit Note agreement lineage is missing"
                )
            agreement_version = int(agreement[0])
            credited_line_ids = tuple(
                line.credited_invoice_line_id for line in snapshot.lines
            )
            cursor.execute(
                """SELECT line.external_line_id
                     FROM commercial_stripe_invoice_line_effects line
                     JOIN commercial_stripe_invoice_effects effect
                       ON effect.id = line.invoice_effect_id
                    WHERE effect.environment = %s
                      AND effect.external_invoice_id = %s
                      AND effect.document_created
                      AND effect.document_id = %s
                      AND line.external_line_id = ANY(%s)
                    FOR UPDATE OF line, effect""",
                (
                    environment,
                    snapshot.external_invoice_id,
                    document_id,
                    list(credited_line_ids),
                ),
            )
            matched_line_ids = {str(row[0]) for row in cursor.fetchall()}
            if matched_line_ids != set(credited_line_ids):
                raise StripeCreditNoteProjectionError(
                    "Credit Note line lineage is invalid"
                )

            cursor.execute(
                """SELECT id, snapshot_sha256, revision, authoritative_fetched_at
                     FROM commercial_stripe_projection_objects
                    WHERE environment = %s AND object_type = 'credit_note'
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
                       ) VALUES (%s, 'credit_note', %s, %s, %s, %s, 'current',
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
                projection_object_id = int(authority[0])
                object_revision = int(authority[2])
                disposition = "unchanged"
                if snapshot.authoritative_fetched_at > authority[3]:
                    cursor.execute(
                        """UPDATE commercial_stripe_projection_objects
                              SET authoritative_fetched_at = %s,
                                  highest_event_created_at = GREATEST(
                                      highest_event_created_at, %s),
                                  last_webhook_event_id = %s,
                                  revision = revision + 1
                            WHERE id = %s RETURNING revision""",
                        (
                            snapshot.authoritative_fetched_at,
                            event_created_at,
                            webhook_event_id,
                            projection_object_id,
                        ),
                    )
                    object_revision = int(cursor.fetchone()[0])
            elif snapshot.authoritative_fetched_at <= authority[3]:
                projection_object_id = int(authority[0])
                object_revision = int(authority[2])
                disposition = "superseded"
            else:
                cursor.execute(
                    """UPDATE commercial_stripe_projection_objects
                          SET snapshot_sha256 = %s,
                              authoritative_fetched_at = %s,
                              highest_event_created_at = GREATEST(
                                  highest_event_created_at, %s),
                              last_webhook_event_id = %s,
                              revision = revision + 1
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
                   ) VALUES (%s, %s, %s, %s, 'credit_note', %s, %s, %s, %s, %s)
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
                      SET processing_state = 'applied',
                          processed_at = statement_timestamp(),
                          processing_started_at = NULL, worker_lease_token = NULL,
                          worker_lease_expires_at = NULL,
                          last_transition_lease_token = %s WHERE id = %s""",
                (str(worker_lease_token), webhook_event_id),
            )
            if cursor.rowcount != 1:
                raise StripeCreditNoteProjectionError("Webhook completion failed")
            return StripeCreditNoteProjectionResult(
                projection_object_id=projection_object_id,
                projection_event_id=projection_event_id,
                object_revision=object_revision,
                agreement_version=agreement_version,
                disposition=disposition,
            )
        finally:
            cursor.close()


__all__ = [
    "PostgresStripeCreditNoteProjector",
    "StripeCreditNoteProjectionError",
    "StripeCreditNoteProjectionResult",
]
