"""Durable lease and failure authority for Stripe webhook workers."""

from __future__ import annotations

from datetime import datetime
import re
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictInt, StrictStr, StringConstraints

from ..models import StrictCommercialModel


PositiveInt = Annotated[StrictInt, Field(gt=0)]
StripeEventType = Annotated[
    StrictStr,
    StringConstraints(min_length=1, max_length=255, pattern=r"^[a-z][a-z0-9._]*$"),
]
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")


class StripeWebhookWorkerError(RuntimeError):
    """Webhook work could not make a valid fenced state transition."""


class ClaimedStripeWebhook(StrictCommercialModel):
    webhook_event_id: PositiveInt
    environment: Literal["test", "live"]
    external_event_id: str
    event_type: StripeEventType
    external_object_id: str
    lease_token: UUID
    lease_expires_at: AwareDatetime
    attempt_count: PositiveInt


class StripeWebhookFailureResult(StrictCommercialModel):
    webhook_event_id: PositiveInt
    processing_state: Literal["retryable", "dead"]
    attempt_count: PositiveInt


class PostgresStripeWebhookWorkerStore:
    """Claim verified inbox rows and fence every non-projector transition."""

    MAX_ATTEMPTS = 5

    def __init__(self, connection: object) -> None:
        self._connection = connection

    def claim_due(
        self, *, limit: int, lease_seconds: int
    ) -> tuple[ClaimedStripeWebhook, ...]:
        self._validate(limit, lease_seconds)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            now = self._database_now(cursor)
            cursor.execute(
                """
                SELECT id, environment, external_event_id, event_type,
                       payload_json->'data'->'object'->>'id', processing_state,
                       attempt_count, worker_lease_token, worker_lease_expires_at
                  FROM commercial_webhook_events
                 WHERE integrity_state = 'verified'
                   AND payload_json IS NOT NULL
                   AND (
                       processing_state = 'received'
                       OR (processing_state = 'retryable' AND next_attempt_at <= %s)
                       OR (processing_state = 'processing'
                           AND worker_lease_expires_at <= %s)
                   )
                 ORDER BY attempt_count,
                          COALESCE(next_attempt_at, received_at), received_at, id
                 LIMIT %s
                 FOR UPDATE SKIP LOCKED
                """,
                (now, now, limit),
            )
            rows = cursor.fetchall()
            claimed = []
            for row in rows:
                state = str(row[5])
                attempt_count = int(row[6])
                if state == "processing":
                    self._present(cursor, UUID(str(row[7])))
                    terminal = attempt_count >= self.MAX_ATTEMPTS
                    cursor.execute(
                        """
                        UPDATE commercial_webhook_events
                           SET processing_state = %s,
                               processing_started_at = NULL,
                               worker_lease_token = NULL,
                               worker_lease_expires_at = NULL,
                               next_attempt_at = CASE WHEN %s THEN NULL
                                   ELSE statement_timestamp() END,
                               last_error_code = 'webhook_worker_lease_expired'
                         WHERE id = %s AND processing_state = 'processing'
                        """,
                        (
                            "dead" if terminal else "retryable",
                            terminal,
                            row[0],
                        ),
                    )
                    if terminal:
                        continue
                token = uuid4()
                cursor.execute(
                    """
                    UPDATE commercial_webhook_events
                       SET processing_state = 'processing',
                           attempt_count = attempt_count + 1,
                           worker_lease_token = %s,
                           worker_lease_expires_at = statement_timestamp()
                               + make_interval(secs => %s)
                     WHERE id = %s
                       AND processing_state IN ('received', 'retryable')
                    RETURNING attempt_count, worker_lease_expires_at
                    """,
                    (str(token), lease_seconds, row[0]),
                )
                result = cursor.fetchone()
                if result is None:
                    continue
                object_id = row[4]
                if not isinstance(object_id, str) or not object_id:
                    self._present(cursor, token)
                    cursor.execute(
                        """
                        UPDATE commercial_webhook_events
                           SET processing_state = 'dead',
                               processing_started_at = NULL,
                               worker_lease_token = NULL,
                               worker_lease_expires_at = NULL,
                               last_error_code = 'webhook_object_identity_invalid'
                         WHERE id = %s AND processing_state = 'processing'
                           AND worker_lease_token = %s
                        """,
                        (row[0], str(token)),
                    )
                    if cursor.rowcount != 1:
                        raise StripeWebhookWorkerError(
                            "Stripe webhook invalid-object dead letter failed"
                        )
                    continue
                claimed.append(
                    ClaimedStripeWebhook(
                        webhook_event_id=row[0],
                        environment=row[1],
                        external_event_id=row[2],
                        event_type=row[3],
                        external_object_id=object_id,
                        lease_token=token,
                        lease_expires_at=result[1],
                        attempt_count=result[0],
                    )
                )
            self._connection.commit()  # type: ignore[attr-defined]
            return tuple(claimed)
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    def renew(
        self, *, webhook_event_id: int, lease_token: UUID, lease_seconds: int
    ) -> bool:
        self._validate(1, lease_seconds)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            self._present(cursor, lease_token)
            cursor.execute(
                """
                UPDATE commercial_webhook_events
                   SET worker_lease_expires_at = statement_timestamp()
                       + make_interval(secs => %s)
                 WHERE id = %s AND processing_state = 'processing'
                   AND worker_lease_token = %s
                   AND worker_lease_expires_at > statement_timestamp()
                """,
                (
                    lease_seconds,
                    webhook_event_id,
                    str(lease_token),
                ),
            )
            renewed = cursor.rowcount == 1
            self._connection.commit()  # type: ignore[attr-defined]
            return renewed
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    def ignore(self, *, webhook_event_id: int, lease_token: UUID) -> bool:
        return self._finish(
            webhook_event_id=webhook_event_id,
            lease_token=lease_token,
            processing_state="ignored",
            error_code=None,
            next_attempt_at=None,
        )

    def fail(
        self,
        *,
        webhook_event_id: int,
        lease_token: UUID,
        error_code: str,
        retry_delay_seconds: int,
    ) -> StripeWebhookFailureResult | None:
        if not _ERROR_CODE.fullmatch(error_code):
            raise StripeWebhookWorkerError("Stripe webhook error code is invalid")
        if (
            type(retry_delay_seconds) is not int
            or not 1 <= retry_delay_seconds <= 86_400
        ):
            raise StripeWebhookWorkerError("Stripe webhook retry delay is invalid")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT attempt_count FROM commercial_webhook_events
                 WHERE id = %s AND processing_state = 'processing'
                   AND worker_lease_token = %s FOR UPDATE
                """,
                (webhook_event_id, str(lease_token)),
            )
            row = cursor.fetchone()
            if row is None:
                self._connection.rollback()  # type: ignore[attr-defined]
                return None
            attempt_count = int(row[0])
            terminal = attempt_count >= self.MAX_ATTEMPTS
            self._present(cursor, lease_token)
            cursor.execute(
                """
                UPDATE commercial_webhook_events
                   SET processing_state = %s,
                       processing_started_at = NULL,
                       worker_lease_token = NULL,
                       worker_lease_expires_at = NULL,
                       next_attempt_at = CASE WHEN %s THEN NULL
                           ELSE statement_timestamp() + make_interval(secs => %s) END,
                       last_error_code = %s
                 WHERE id = %s AND processing_state = 'processing'
                   AND worker_lease_token = %s
                """,
                (
                    "dead" if terminal else "retryable",
                    terminal,
                    retry_delay_seconds,
                    error_code,
                    webhook_event_id,
                    str(lease_token),
                ),
            )
            if cursor.rowcount != 1:
                raise StripeWebhookWorkerError("Stripe webhook failure fence was lost")
            self._connection.commit()  # type: ignore[attr-defined]
            return StripeWebhookFailureResult(
                webhook_event_id=webhook_event_id,
                processing_state="dead" if terminal else "retryable",
                attempt_count=attempt_count,
            )
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    def _finish(
        self,
        *,
        webhook_event_id: int,
        lease_token: UUID,
        processing_state: str,
        error_code: str | None,
        next_attempt_at: datetime | None,
    ) -> bool:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            self._present(cursor, lease_token)
            cursor.execute(
                """
                UPDATE commercial_webhook_events
                   SET processing_state = %s,
                       processing_started_at = NULL,
                       worker_lease_token = NULL,
                       worker_lease_expires_at = NULL,
                       next_attempt_at = %s,
                       last_error_code = %s
                 WHERE id = %s AND processing_state = 'processing'
                   AND worker_lease_token = %s
                """,
                (
                    processing_state,
                    next_attempt_at,
                    error_code,
                    webhook_event_id,
                    str(lease_token),
                ),
            )
            finished = cursor.rowcount == 1
            self._connection.commit()  # type: ignore[attr-defined]
            return finished
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    @staticmethod
    def _present(cursor, lease_token: UUID) -> None:
        cursor.execute(
            "SELECT set_config('app.commercial_webhook_lease_token', %s, TRUE)",
            (str(lease_token),),
        )

    @staticmethod
    def _validate(limit: int, lease_seconds: int) -> None:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise StripeWebhookWorkerError("Stripe webhook claim limit is invalid")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 900:
            raise StripeWebhookWorkerError("Stripe webhook lease is invalid")

    @staticmethod
    def _database_now(cursor) -> datetime:
        cursor.execute("SELECT statement_timestamp()")
        now = cursor.fetchone()[0]
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise StripeWebhookWorkerError("Stripe webhook database clock is invalid")
        return now


__all__ = [
    "ClaimedStripeWebhook",
    "PostgresStripeWebhookWorkerStore",
    "StripeWebhookFailureResult",
    "StripeWebhookWorkerError",
]
