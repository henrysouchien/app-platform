"""Durable, fair worker claims for expired budget reservations."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictInt

from ..models import StrictCommercialModel


PositiveInt = Annotated[StrictInt, Field(gt=0)]


class BudgetReaperClaimError(RuntimeError):
    """Budget reaper claim authority is invalid or unavailable."""


class ClaimedBudgetReaperCandidate(StrictCommercialModel):
    reservation_id: UUID
    claim_token: UUID
    lease_version: PositiveInt
    heartbeat_at: AwareDatetime
    expires_at: AwareDatetime
    attempt_count: PositiveInt


class PostgresBudgetReaperClaimStore:
    WORK_KIND = "budget_reservation_reaper"

    def __init__(self, connection: object, *, clock) -> None:
        self._connection = connection
        self._clock = clock

    def claim_due(
        self, *, limit: int, lease_seconds: int
    ) -> tuple[ClaimedBudgetReaperCandidate, ...]:
        self._validate(limit=limit, lease_seconds=lease_seconds)
        now = self._now()
        lease_expires_at = now + timedelta(seconds=lease_seconds)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT reservation.id, reservation.lease_version,
                          reservation.heartbeat_at, reservation.expires_at,
                          COALESCE(claim.attempt_count, 0)
                     FROM commercial_budget_reservations reservation
                     LEFT JOIN commercial_workflow_runs workflow
                       ON workflow.id = reservation.workflow_run_id
                     LEFT JOIN commercial_worker_claims claim
                       ON claim.work_kind = %s AND claim.subject_id = reservation.id
                    WHERE (
                          reservation.state IN ('reserved', 'partially_settled')
                          OR (
                              reservation.state = 'overdrawn'
                              AND COALESCE((
                                  SELECT event.metadata @>
                                         '{"finalize_reservation": false}'::jsonb
                                    FROM commercial_budget_settlements settlement
                                    JOIN commercial_budget_events event
                                      ON event.event_id = settlement.event_id
                                   WHERE settlement.reservation_id = reservation.id
                                     AND settlement.cost_revision = 0
                                   ORDER BY settlement.id DESC LIMIT 1
                              ), FALSE)
                          )
                      )
                      AND reservation.expires_at <= %s
                      AND (workflow.id IS NULL OR workflow.state <> 'started')
                      AND (claim.subject_id IS NULL OR (
                          claim.lease_expires_at <= %s
                          AND claim.next_attempt_at <= %s
                      ))
                      AND NOT EXISTS (
                          SELECT 1 FROM commercial_budget_settlement_attempts attempt
                           WHERE attempt.reservation_id = reservation.id
                             AND NOT EXISTS (
                                 SELECT 1 FROM commercial_budget_settlements settlement
                                  WHERE settlement.usage_event_id = attempt.usage_event_id
                                    AND settlement.cost_revision = attempt.cost_revision
                             )
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM commercial_usage_events usage
                           WHERE usage.reservation_id = reservation.id
                             AND usage.payer_class = 'hank_paid'
                             AND usage.pricing_state = 'priced'
                             AND usage.usage_state IN ('succeeded', 'failed_billable')
                             AND NOT EXISTS (
                                 SELECT 1 FROM commercial_budget_settlements settlement
                                  WHERE settlement.usage_event_id = usage.id
                                    AND settlement.cost_revision = 0
                             )
                      )
                    ORDER BY COALESCE(claim.attempt_count, 0),
                             reservation.expires_at, reservation.id
                    LIMIT %s FOR UPDATE OF reservation SKIP LOCKED""",
                (self.WORK_KIND, now, now, now, limit),
            )
            selected = cursor.fetchall()
            claims = []
            for row in selected:
                token = uuid4()
                attempt_count = int(row[4]) + 1
                cursor.execute(
                    """INSERT INTO commercial_worker_claims (
                           work_kind, subject_id, lease_token, observed_version,
                           observed_heartbeat_at, observed_expires_at, attempt_count,
                           claimed_at, lease_expires_at, next_attempt_at
                       ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (work_kind, subject_id) DO UPDATE SET
                           lease_token = EXCLUDED.lease_token,
                           observed_version = EXCLUDED.observed_version,
                           observed_heartbeat_at = EXCLUDED.observed_heartbeat_at,
                           observed_expires_at = EXCLUDED.observed_expires_at,
                           attempt_count = commercial_worker_claims.attempt_count + 1,
                           claimed_at = EXCLUDED.claimed_at,
                           lease_expires_at = EXCLUDED.lease_expires_at,
                           next_attempt_at = EXCLUDED.next_attempt_at
                         WHERE commercial_worker_claims.lease_expires_at <= %s
                           AND commercial_worker_claims.next_attempt_at <= %s
                       RETURNING attempt_count""",
                    (
                        self.WORK_KIND,
                        str(row[0]),
                        str(token),
                        row[1],
                        row[2],
                        row[3],
                        attempt_count,
                        now,
                        lease_expires_at,
                        lease_expires_at,
                        now,
                        now,
                    ),
                )
                claimed = cursor.fetchone()
                if claimed is None:
                    continue
                claims.append(
                    ClaimedBudgetReaperCandidate(
                        reservation_id=row[0],
                        claim_token=token,
                        lease_version=row[1],
                        heartbeat_at=row[2],
                        expires_at=row[3],
                        attempt_count=claimed[0],
                    )
                )
            self._connection.commit()  # type: ignore[attr-defined]
            return tuple(claims)
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    def renew(
        self, *, reservation_id: UUID, claim_token: UUID, lease_seconds: int
    ) -> bool:
        self._validate(limit=1, lease_seconds=lease_seconds)
        now = self._now()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """UPDATE commercial_worker_claims
                      SET claimed_at = %s, lease_expires_at = %s,
                          next_attempt_at = %s
                    WHERE work_kind = %s AND subject_id = %s AND lease_token = %s""",
                (
                    now,
                    now + timedelta(seconds=lease_seconds),
                    now + timedelta(seconds=lease_seconds),
                    self.WORK_KIND,
                    str(reservation_id),
                    str(claim_token),
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

    def complete(self, *, reservation_id: UUID, claim_token: UUID) -> bool:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """DELETE FROM commercial_worker_claims
                    WHERE work_kind = %s AND subject_id = %s AND lease_token = %s""",
                (self.WORK_KIND, str(reservation_id), str(claim_token)),
            )
            completed = cursor.rowcount == 1
            self._connection.commit()  # type: ignore[attr-defined]
            return completed
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    @staticmethod
    def _validate(*, limit: int, lease_seconds: int) -> None:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise BudgetReaperClaimError("budget reaper claim limit is invalid")
        if type(lease_seconds) is not int or not 60 <= lease_seconds <= 3600:
            raise BudgetReaperClaimError("budget reaper claim lease is invalid")

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise BudgetReaperClaimError("budget reaper claim clock must be aware")
        return now


__all__ = [
    "BudgetReaperClaimError",
    "ClaimedBudgetReaperCandidate",
    "PostgresBudgetReaperClaimStore",
]
