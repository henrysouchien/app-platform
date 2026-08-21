"""Fenced PostgreSQL/Redis protocol for abandoned reservation expiry."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Annotated, Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, StrictInt

from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .reaper_store import BudgetReaperRedisCommand, CommercialBudgetReaperRedisStore
from .redis_store import CommercialReservationRedisError


PositiveSafeInt = Annotated[StrictInt, Field(gt=0, le=2**52 - 1)]
_REDIS_REPAIR_GRACE_SECONDS = 86_400
_MAX_REDIS_TTL_SECONDS = 31_536_000
_POLICY_BUCKETS = ("model", "technical")


class BudgetReaperProtocolError(RuntimeError):
    """An abandoned reservation could not be expired safely."""


class BudgetReaperCandidate(StrictCommercialModel):
    reservation_id: UUID
    lease_version: PositiveSafeInt
    heartbeat_at: AwareDatetime
    expires_at: AwareDatetime


class BudgetReaperCommand(StrictCommercialModel):
    reservation_id: UUID
    observed_lease_version: PositiveSafeInt
    observed_heartbeat_at: AwareDatetime
    observed_expires_at: AwareDatetime
    reason_code: StableCode = "budget.expired"


class BudgetReaperResult(StrictCommercialModel):
    reservation_id: UUID
    state: Literal["expired"]
    lease_version: PositiveSafeInt
    redis_generation: PositiveSafeInt
    expired_at: AwareDatetime
    redis_replayed: bool
    durable_replayed: bool


class _ReaperSnapshot(StrictCommercialModel):
    budget_period_id: PositiveSafeInt
    agreement_terms_id: PositiveSafeInt
    lease_token: UUID
    lease_version: PositiveSafeInt
    redis_generation: PositiveSafeInt
    late_child_accept_until: AwareDatetime
    buckets: tuple[StableCode, ...]
    current_holds: tuple[tuple[StableCode, StrictInt, StrictInt], ...]
    payload_sha256: Sha256Digest


class BudgetReaperProtocol:
    def __init__(
        self,
        connection: Any,
        redis_store: CommercialBudgetReaperRedisStore,
        *,
        flags: CommercialFlags,
        clock,
    ) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise BudgetReaperProtocolError(
                "budget reaper requires transactional PostgreSQL"
            )
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
        ):
            raise BudgetReaperProtocolError("budget reaper requires enforcement mode")
        self._connection = connection
        self._redis = redis_store
        self._clock = clock

    def scan_due(self, *, limit: int = 100) -> tuple[BudgetReaperCandidate, ...]:
        self._require_idle()
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise BudgetReaperProtocolError("budget reaper scan limit is invalid")
        now = self._now()
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT reservation.id, reservation.lease_version,
                           reservation.heartbeat_at, reservation.expires_at
                      FROM commercial_budget_reservations reservation
                      LEFT JOIN commercial_workflow_runs workflow ON workflow.id = reservation.workflow_run_id
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
                     ORDER BY reservation.expires_at, reservation.id LIMIT %s
                    """,
                    (now, limit),
                )
                rows = cursor.fetchall()
            self._connection.rollback()
        except Exception:
            self._connection.rollback()
            raise
        return tuple(
            BudgetReaperCandidate(
                reservation_id=row[0],
                lease_version=row[1],
                heartbeat_at=row[2],
                expires_at=row[3],
            )
            for row in rows
        )

    def expire(self, command: BudgetReaperCommand) -> BudgetReaperResult:
        try:
            raw = (
                command.model_dump()
                if isinstance(command, StrictCommercialModel)
                else command
            )
            command = BudgetReaperCommand.model_validate(raw)
        except Exception as error:
            raise BudgetReaperProtocolError(
                "budget reaper command is invalid"
            ) from error
        self._require_idle()
        now = self._now()
        try:
            snapshot, existing = self._lock_snapshot(command, now=now)
            if existing is not None:
                self._connection.commit()
                return existing
            redis_command = self._redis_command(command, snapshot, now=now)
            decision = self._redis.expire(
                agreement_terms_id=snapshot.agreement_terms_id,
                period_id=snapshot.budget_period_id,
                command=redis_command,
            )
        except CommercialReservationRedisError as error:
            self._connection.rollback()
            raise BudgetReaperProtocolError(
                "Redis reaper is unavailable; retry the identical command"
            ) from error
        except Exception:
            self._connection.rollback()
            raise
        if decision.decision != "allow":
            self._connection.rollback()
            raise BudgetReaperProtocolError(
                f"Redis reaper rejected reservation: {decision.reason_code}; generation rebuild may be required"
            )
        try:
            return self._record(command, snapshot, decision, now=now)
        except Exception as error:
            self._connection.rollback()
            if isinstance(error, BudgetReaperProtocolError):
                raise
            raise BudgetReaperProtocolError(
                "Redis expiry succeeded but durable journaling failed; retry the identical reaper command"
            ) from error

    def _lock_snapshot(self, command, *, now):
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"budget-settlement-reservation:{command.reservation_id}",),
            )
            cursor.execute(
                """
                SELECT reservation.budget_period_id, reservation.agreement_terms_id,
                       reservation.lease_token, reservation.lease_version,
                       reservation.redis_generation, reservation.state,
                       reservation.heartbeat_at, reservation.expires_at,
                       reservation.late_child_accept_until, workflow.state,
                       ARRAY(
                           SELECT budget_bucket FROM commercial_budget_hold_events initial
                            WHERE initial.reservation_id = reservation.id
                              AND initial.hold_revision = 0 AND initial.hold_kind = 'reserve'
                            ORDER BY budget_bucket
                       ),
                       COALESCE((
                           SELECT event.metadata @>
                                  '{"finalize_reservation": false}'::jsonb
                             FROM commercial_budget_settlements settlement
                             JOIN commercial_budget_events event
                               ON event.event_id = settlement.event_id
                            WHERE settlement.reservation_id = reservation.id
                              AND settlement.cost_revision = 0
                            ORDER BY settlement.id DESC LIMIT 1
                       ), FALSE),
                       period.redis_generation
                  FROM commercial_budget_reservations reservation
                  LEFT JOIN commercial_workflow_runs workflow ON workflow.id = reservation.workflow_run_id
                  JOIN commercial_budget_periods period
                    ON period.id = reservation.budget_period_id
                 WHERE reservation.id = %s FOR UPDATE OF reservation
                """,
                (str(command.reservation_id),),
            )
            row = cursor.fetchone()
            cursor.execute(
                """
                SELECT lease_version, occurred_at, metadata, reason_code
                  FROM commercial_budget_events
                 WHERE reservation_id = %s AND event_kind = 'expire'
                   AND metadata->>'reaper_idempotency_key' = %s
                 ORDER BY id DESC LIMIT 1
                """,
                (str(command.reservation_id), self._idempotency_key(command)),
            )
            event = cursor.fetchone()
        if row is None or row[4] is None:
            raise BudgetReaperProtocolError(
                "budget reaper reservation authority is missing"
            )
        if int(row[4]) != int(row[12]):
            raise BudgetReaperProtocolError(
                "budget reaper generation conflicts with its budget period"
            )
        if tuple(row[10]) not in {("technical",), _POLICY_BUCKETS}:
            raise BudgetReaperProtocolError(
                "budget reaper reservation bucket authority is unsupported"
            )
        if event is not None:
            metadata = event[2]
            if (
                row[5] != "expired"
                or int(row[3]) != command.observed_lease_version + 1
                or int(event[0]) != command.observed_lease_version + 1
                or event[3] != command.reason_code
                or not self._metadata_matches(metadata, command)
            ):
                raise BudgetReaperProtocolError(
                    "budget reaper replay conflicts with durable evidence"
                )
            return None, BudgetReaperResult(
                reservation_id=command.reservation_id,
                state="expired",
                lease_version=int(event[0]),
                redis_generation=int(metadata["redis_generation"]),
                expired_at=event[1],
                redis_replayed=False,
                durable_replayed=True,
            )
        active_overdrawn = row[5] == "overdrawn" and bool(row[11])
        if (
            (row[5] not in {"reserved", "partially_settled"} and not active_overdrawn)
            or int(row[3]) != command.observed_lease_version
            or row[6] != command.observed_heartbeat_at
            or row[7] != command.observed_expires_at
        ):
            raise BudgetReaperProtocolError(
                "budget reaper observed lease or heartbeat is stale"
            )
        if row[7] > now:
            raise BudgetReaperProtocolError("budget reaper lease has not expired")
        if row[9] == "started":
            raise BudgetReaperProtocolError(
                "budget reaper reservation still has an active workflow owner"
            )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM commercial_budget_settlement_attempts attempt
                 WHERE attempt.reservation_id = %s AND NOT EXISTS (
                       SELECT 1 FROM commercial_budget_settlements settlement
                        WHERE settlement.usage_event_id = attempt.usage_event_id
                          AND settlement.cost_revision = attempt.cost_revision)
                 LIMIT 1
                """,
                (str(command.reservation_id),),
            )
            if cursor.fetchone() is not None:
                raise BudgetReaperProtocolError(
                    "budget reaper is blocked by an unresolved settlement attempt"
                )
            cursor.execute(
                """
                SELECT 1 FROM commercial_usage_events usage
                 WHERE usage.reservation_id = %s AND usage.payer_class = 'hank_paid'
                   AND usage.pricing_state = 'priced'
                   AND usage.usage_state IN ('succeeded', 'failed_billable')
                   AND NOT EXISTS (
                       SELECT 1 FROM commercial_budget_settlements settlement
                        WHERE settlement.usage_event_id = usage.id AND settlement.cost_revision = 0)
                 LIMIT 1
                """,
                (str(command.reservation_id),),
            )
            if cursor.fetchone() is not None:
                raise BudgetReaperProtocolError(
                    "budget reaper is blocked by unsettled accepted usage"
                )
            cursor.execute(
                "SELECT budget_bucket, current_hold_microusd, current_revision "
                "FROM commercial_budget_current_holds WHERE reservation_id = %s ORDER BY budget_bucket",
                (str(command.reservation_id),),
            )
            holds = tuple(
                (item[0], int(item[1]), int(item[2])) for item in cursor.fetchall()
            )
        if any(
            bucket not in _POLICY_BUCKETS or amount <= 0 for bucket, amount, _ in holds
        ):
            raise BudgetReaperProtocolError("budget reaper durable holds are invalid")
        payload = self._payload(command, row, holds)
        return _ReaperSnapshot(
            budget_period_id=row[0],
            agreement_terms_id=row[1],
            lease_token=row[2],
            lease_version=row[3],
            redis_generation=row[4],
            late_child_accept_until=row[8],
            buckets=_POLICY_BUCKETS,
            current_holds=holds,
            payload_sha256=payload,
        ), None

    def _redis_command(self, command, snapshot, *, now):
        ttl = (
            int((snapshot.late_child_accept_until - now).total_seconds())
            + 1
            + _REDIS_REPAIR_GRACE_SECONDS
        )
        if ttl <= 0 or ttl > _MAX_REDIS_TTL_SECONDS:
            raise BudgetReaperProtocolError(
                "budget reaper requires Redis generation rebuild"
            )
        return BudgetReaperRedisCommand(
            reservation_id=command.reservation_id,
            idempotency_key=self._idempotency_key(command),
            payload_sha256=snapshot.payload_sha256,
            lease_token=snapshot.lease_token,
            lease_version=snapshot.lease_version,
            generation=snapshot.redis_generation,
            ttl_seconds=ttl,
            reason_code=command.reason_code,
            buckets=snapshot.buckets,
            expected_holds_by_bucket_microusd=tuple(
                {
                    "budget_bucket": bucket,
                    "amount_microusd": next(
                        (
                            amount
                            for held_bucket, amount, _ in snapshot.current_holds
                            if held_bucket == bucket
                        ),
                        0,
                    ),
                }
                for bucket in snapshot.buckets
            ),
        )

    def _record(self, command, snapshot, decision, *, now):
        committed = command.observed_lease_version + 1
        if decision.lease_version != committed:
            raise BudgetReaperProtocolError(
                "budget reaper Redis fence did not advance exactly once"
            )
        expected_holds = dict.fromkeys(snapshot.buckets, 0)
        expected_holds.update(
            {bucket: amount for bucket, amount, _revision in snapshot.current_holds}
        )
        actual_holds = {
            item.budget_bucket: item.amount_microusd
            for item in decision.holds_by_bucket_microusd
        }
        if actual_holds != expected_holds:
            raise BudgetReaperProtocolError(
                "budget reaper Redis and durable holds diverged"
            )
        with self._connection.cursor() as cursor:
            for bucket, amount, revision in snapshot.current_holds:
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_hold_events (
                        event_id, reservation_id, budget_period_id, budget_bucket,
                        hold_revision, hold_kind, amount_delta_microusd, lease_version,
                        idempotency_key, reason_code, actor_type
                    ) VALUES (%s, %s, %s, %s, %s, 'release', %s, %s, %s,
                              'budget.expired_hold_release', 'reaper')
                    """,
                    (
                        str(
                            uuid5(
                                NAMESPACE_URL,
                                f"budget-reaper:{command.reservation_id}:{command.observed_lease_version}:{bucket}",
                            )
                        ),
                        str(command.reservation_id),
                        snapshot.budget_period_id,
                        bucket,
                        revision + 1,
                        -amount,
                        command.observed_lease_version,
                        f"reaper:{command.observed_lease_version}:{bucket}",
                    ),
                )
            metadata = {
                "reaper_idempotency_key": self._idempotency_key(command),
                "payload_sha256": snapshot.payload_sha256,
                "input_lease_version": command.observed_lease_version,
                "observed_heartbeat_at": command.observed_heartbeat_at.astimezone(
                    timezone.utc
                ).isoformat(),
                "observed_expires_at": command.observed_expires_at.astimezone(
                    timezone.utc
                ).isoformat(),
                "redis_generation": snapshot.redis_generation,
            }
            event_id = uuid5(
                NAMESPACE_URL,
                f"budget-reaper:{command.reservation_id}:{command.observed_lease_version}:expire",
            )
            cursor.execute(
                """
                INSERT INTO commercial_budget_events (
                    event_id, budget_period_id, reservation_id, event_kind,
                    amount_microusd, lease_version, reason_code, occurred_at, actor_type, metadata
                ) VALUES (%s, %s, %s, 'expire', 0, %s, %s, %s, 'reaper', %s::jsonb)
                """,
                (
                    str(event_id),
                    snapshot.budget_period_id,
                    str(command.reservation_id),
                    committed,
                    command.reason_code,
                    now,
                    json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                ),
            )
            cursor.execute(
                """
                UPDATE commercial_budget_reservations
                   SET state = 'expired', lease_version = %s, settled_at = %s
                 WHERE id = %s AND lease_version = %s AND heartbeat_at = %s AND expires_at = %s
                """,
                (
                    committed,
                    now,
                    str(command.reservation_id),
                    command.observed_lease_version,
                    command.observed_heartbeat_at,
                    command.observed_expires_at,
                ),
            )
            if cursor.rowcount != 1:
                raise BudgetReaperProtocolError(
                    "budget reaper lost its durable lease fence"
                )
        self._connection.commit()
        return BudgetReaperResult(
            reservation_id=command.reservation_id,
            state="expired",
            lease_version=committed,
            redis_generation=snapshot.redis_generation,
            expired_at=now,
            redis_replayed=decision.replayed,
            durable_replayed=False,
        )

    @staticmethod
    def _idempotency_key(command):
        digest = canonical_sha256(
            {
                "reservation_id": str(command.reservation_id),
                "observed_lease_version": command.observed_lease_version,
            }
        ).split(":", 1)[1]
        return f"expire.{digest}"

    @staticmethod
    def _payload(command, row, holds):
        return canonical_sha256(
            {
                "schema": "commercial.budget.reaper.v1",
                "reservation_id": str(command.reservation_id),
                "budget_period_id": int(row[0]),
                "agreement_terms_id": int(row[1]),
                "lease_token": str(row[2]),
                "lease_version": command.observed_lease_version,
                "redis_generation": int(row[4]),
                "observed_heartbeat_at": command.observed_heartbeat_at,
                "observed_expires_at": command.observed_expires_at,
                "late_child_accept_until": row[8],
                "reason_code": command.reason_code,
                "buckets": _POLICY_BUCKETS,
                "current_holds": holds,
            }
        )

    @staticmethod
    def _metadata_matches(metadata, command):
        if not isinstance(metadata, dict):
            return False
        try:
            observed_heartbeat_at = datetime.fromisoformat(
                metadata["observed_heartbeat_at"]
            )
            observed_expires_at = datetime.fromisoformat(
                metadata["observed_expires_at"]
            )
        except (KeyError, TypeError, ValueError):
            return False
        return (
            metadata.get("reaper_idempotency_key")
            == BudgetReaperProtocol._idempotency_key(command)
            and metadata.get("input_lease_version") == command.observed_lease_version
            and observed_heartbeat_at.astimezone(timezone.utc)
            == command.observed_heartbeat_at.astimezone(timezone.utc)
            and observed_expires_at.astimezone(timezone.utc)
            == command.observed_expires_at.astimezone(timezone.utc)
            and isinstance(metadata.get("redis_generation"), int)
            and isinstance(metadata.get("payload_sha256"), str)
        )

    def _now(self):
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise BudgetReaperProtocolError(
                "budget reaper clock must be timezone-aware"
            )
        return now

    def _require_idle(self):
        reader = getattr(self._connection, "get_transaction_status", None)
        if reader is None or reader() != 0:
            raise BudgetReaperProtocolError(
                "budget reaper requires an idle dedicated PostgreSQL connection"
            )
