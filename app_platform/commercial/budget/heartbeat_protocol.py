"""Recoverable cross-store heartbeat protocol for active budget reservations."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Annotated, Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, StrictInt

from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .heartbeat_store import (
    BudgetHeartbeatRedisCommand,
    CommercialBudgetHeartbeatRedisStore,
)
from .redis_store import CommercialReservationRedisError


PositiveSafeInt = Annotated[StrictInt, Field(gt=0, le=2**52 - 1)]
_REDIS_REPAIR_GRACE_SECONDS = 86_400
_MAX_REDIS_TTL_SECONDS = 31_536_000
_POLICY_BUCKETS = ("model", "technical")


class BudgetHeartbeatProtocolError(RuntimeError):
    """The reservation heartbeat could not be safely committed in both stores."""


class BudgetHeartbeatCommand(StrictCommercialModel):
    reservation_id: UUID
    idempotency_key: StableCode
    lease_token: UUID
    lease_version: PositiveSafeInt
    requested_expires_at: AwareDatetime
    reason_code: StableCode = "budget.heartbeat"


class BudgetHeartbeatResult(StrictCommercialModel):
    reservation_id: UUID
    lease_version: PositiveSafeInt
    redis_generation: PositiveSafeInt
    heartbeat_at: AwareDatetime
    expires_at: AwareDatetime
    redis_replayed: bool
    durable_replayed: bool


class _HeartbeatSnapshot(StrictCommercialModel):
    budget_period_id: PositiveSafeInt
    agreement_terms_id: PositiveSafeInt
    redis_generation: PositiveSafeInt
    state: Literal["reserved", "partially_settled", "overdrawn"]
    current_heartbeat_at: AwareDatetime
    current_expires_at: AwareDatetime
    late_child_accept_until: AwareDatetime
    buckets: tuple[StableCode, ...]
    payload_sha256: Sha256Digest
    recovery_only: bool


class BudgetHeartbeatProtocol:
    """Advance one live lease while holding its durable fence across Redis."""

    def __init__(
        self,
        connection: Any,
        redis_store: CommercialBudgetHeartbeatRedisStore,
        *,
        flags: CommercialFlags,
        clock,
    ) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat requires transactional PostgreSQL"
            )
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
        ):
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat requires enforcement mode"
            )
        self._connection = connection
        self._redis = redis_store
        self._clock = clock

    def heartbeat(self, command: BudgetHeartbeatCommand) -> BudgetHeartbeatResult:
        try:
            raw = (
                command.model_dump()
                if isinstance(command, StrictCommercialModel)
                else command
            )
            command = BudgetHeartbeatCommand.model_validate(raw)
        except Exception as error:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat command is invalid"
            ) from error
        self._require_idle()
        now = self._now()
        try:
            snapshot, existing = self._lock_authority(command, now=now)
            if existing is not None:
                self._connection.commit()
                return existing
            redis_command = self._redis_command(command, snapshot, now=now)
            decision = self._redis.heartbeat(
                agreement_terms_id=snapshot.agreement_terms_id,
                period_id=snapshot.budget_period_id,
                command=redis_command,
            )
        except CommercialReservationRedisError as error:
            self._connection.rollback()
            raise BudgetHeartbeatProtocolError(
                "Redis heartbeat is unavailable; retry the identical command"
            ) from error
        except Exception:
            self._connection.rollback()
            raise
        if decision.decision != "allow":
            self._connection.rollback()
            raise BudgetHeartbeatProtocolError(
                f"Redis heartbeat rejected reservation: {decision.reason_code}; "
                "generation rebuild may be required"
            )
        try:
            return self._record(command, snapshot, decision, now=now)
        except Exception as error:
            self._connection.rollback()
            if isinstance(error, BudgetHeartbeatProtocolError):
                raise
            raise BudgetHeartbeatProtocolError(
                "Redis heartbeat succeeded but durable journaling failed; "
                "retry the identical command"
            ) from error

    def _lock_authority(self, command, *, now):
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"budget-settlement-reservation:{command.reservation_id}",),
            )
            cursor.execute(
                """
                SELECT reservation.budget_period_id,
                       reservation.agreement_terms_id,
                       reservation.redis_generation, reservation.state,
                       reservation.lease_token, reservation.lease_version,
                       reservation.heartbeat_at, reservation.expires_at,
                       reservation.late_child_accept_until,
                       reservation.workflow_run_id, workflow.state,
                       ARRAY(
                           SELECT budget_bucket
                             FROM commercial_budget_hold_events initial
                            WHERE initial.reservation_id = reservation.id
                              AND initial.hold_revision = 0
                              AND initial.hold_kind = 'reserve'
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
                  LEFT JOIN commercial_workflow_runs workflow
                    ON workflow.id = reservation.workflow_run_id
                  JOIN commercial_budget_periods period
                    ON period.id = reservation.budget_period_id
                 WHERE reservation.id = %s
                 FOR UPDATE OF reservation
                """,
                (str(command.reservation_id),),
            )
            row = cursor.fetchone()
            cursor.execute(
                """
                SELECT event.lease_version, event.occurred_at, event.metadata,
                       event.reason_code
                  FROM commercial_budget_events event
                 WHERE event.reservation_id = %s
                   AND event.event_kind = 'heartbeat'
                   AND event.metadata->>'heartbeat_idempotency_key' = %s
                 ORDER BY event.id DESC LIMIT 1
                """,
                (str(command.reservation_id), command.idempotency_key),
            )
            event = cursor.fetchone()
            cursor.execute(
                """
                SELECT 1 FROM commercial_budget_settlement_attempts attempt
                 WHERE attempt.reservation_id = %s
                   AND NOT EXISTS (
                       SELECT 1 FROM commercial_budget_settlements settlement
                        WHERE settlement.usage_event_id = attempt.usage_event_id
                          AND settlement.cost_revision = attempt.cost_revision
                   )
                 LIMIT 1
                """,
                (str(command.reservation_id),),
            )
            unresolved_settlement = cursor.fetchone()
        if row is None or row[2] is None:
            raise BudgetHeartbeatProtocolError(
                "active reservation heartbeat authority is missing"
            )
        if UUID(str(row[4])) != command.lease_token:
            raise BudgetHeartbeatProtocolError("budget heartbeat lease token conflicts")
        if int(row[2]) != int(row[13]):
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat generation conflicts with its budget period"
            )
        initial_buckets = tuple(row[11])
        if initial_buckets not in {("technical",), _POLICY_BUCKETS}:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat bucket authority is unsupported"
            )
        if event is not None:
            return self._historical_replay(command, row, event)
        if unresolved_settlement is not None:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat is blocked by an unresolved settlement attempt"
            )
        active_overdrawn = row[3] == "overdrawn" and bool(row[12])
        if row[3] not in {"reserved", "partially_settled"} and not active_overdrawn:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat reservation is not active"
            )
        recovery_only = now >= row[7]
        if not recovery_only and (row[9] is None or row[10] != "started"):
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat reservation has no active workflow owner"
            )
        if int(row[5]) != command.lease_version:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat reservation fence is stale"
            )
        current_lease_duration = row[7] - row[6]
        if current_lease_duration.total_seconds() <= 0:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat durable lease duration is invalid"
            )
        max_extension = min(row[7] + current_lease_duration, row[8])
        if not row[7] <= command.requested_expires_at <= max_extension:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat expiry exceeds the durable lease extension bound"
            )
        payload = self._payload_digest(
            command,
            redis_generation=int(row[2]),
            buckets=_POLICY_BUCKETS,
        )
        return _HeartbeatSnapshot(
            budget_period_id=row[0],
            agreement_terms_id=row[1],
            redis_generation=row[2],
            state=row[3],
            current_heartbeat_at=row[6],
            current_expires_at=row[7],
            late_child_accept_until=row[8],
            buckets=_POLICY_BUCKETS,
            payload_sha256=payload,
            recovery_only=recovery_only,
        ), None

    def _historical_replay(self, command, row, event):
        metadata = event[2]
        try:
            generation = int(metadata["redis_generation"])
            buckets = tuple(metadata["buckets"])
            requested_expires_at = datetime.fromisoformat(
                metadata["requested_expires_at"]
            )
        except (KeyError, TypeError, ValueError) as error:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat durable replay metadata is invalid"
            ) from error
        payload = self._payload_digest(
            command,
            redis_generation=generation,
            buckets=buckets,
        )
        if (
            int(event[0]) != command.lease_version + 1
            or int(row[5]) < int(event[0])
            or event[3] != command.reason_code
            or buckets != _POLICY_BUCKETS
            or metadata.get("payload_sha256") != payload
            or metadata.get("input_lease_version") != command.lease_version
            or requested_expires_at.astimezone(timezone.utc)
            != command.requested_expires_at.astimezone(timezone.utc)
        ):
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat replay conflicts with durable evidence"
            )
        return None, BudgetHeartbeatResult(
            reservation_id=command.reservation_id,
            lease_version=int(event[0]),
            redis_generation=generation,
            heartbeat_at=event[1],
            expires_at=requested_expires_at,
            redis_replayed=False,
            durable_replayed=True,
        )

    def _redis_command(self, command, snapshot, *, now):
        ttl = (
            int((snapshot.late_child_accept_until - now).total_seconds())
            + 1
            + _REDIS_REPAIR_GRACE_SECONDS
        )
        if ttl <= 0 or ttl > _MAX_REDIS_TTL_SECONDS:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat Redis retention is unsafe; generation rebuild required"
            )
        marker = canonical_sha256(
            {
                "reservation_id": str(command.reservation_id),
                "idempotency_key": command.idempotency_key,
            }
        ).split(":", 1)[1]
        return BudgetHeartbeatRedisCommand(
            reservation_id=command.reservation_id,
            idempotency_key=f"heartbeat.{marker}",
            payload_sha256=snapshot.payload_sha256,
            lease_token=command.lease_token,
            lease_version=command.lease_version,
            generation=snapshot.redis_generation,
            ttl_seconds=ttl,
            heartbeat_at=now,
            recovery_only=snapshot.recovery_only,
            buckets=snapshot.buckets,
        )

    def _record(self, command, snapshot, decision, *, now):
        committed = command.lease_version + 1
        if decision.lease_version != committed:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat Redis fence did not advance exactly once"
            )
        if not (
            snapshot.current_heartbeat_at
            < decision.heartbeat_at
            <= command.requested_expires_at
        ):
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat Redis timestamp is outside the durable lease"
            )
        event_id = uuid5(
            NAMESPACE_URL,
            f"budget-heartbeat:{command.reservation_id}:{command.idempotency_key}",
        )
        normalized_expiry = command.requested_expires_at.astimezone(
            timezone.utc
        ).isoformat()
        metadata = {
            "heartbeat_idempotency_key": command.idempotency_key,
            "payload_sha256": snapshot.payload_sha256,
            "requested_expires_at": normalized_expiry,
            "input_lease_version": command.lease_version,
            "redis_generation": snapshot.redis_generation,
            "buckets": list(snapshot.buckets),
        }
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO commercial_budget_events (
                    event_id, budget_period_id, reservation_id, event_kind,
                    amount_microusd, lease_version, reason_code, occurred_at,
                    actor_type, metadata
                ) VALUES (%s, %s, %s, 'heartbeat', 0, %s, %s, %s,
                          'service', %s::jsonb)
                """,
                (
                    str(event_id),
                    snapshot.budget_period_id,
                    str(command.reservation_id),
                    committed,
                    command.reason_code,
                    decision.heartbeat_at,
                    json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                ),
            )
            cursor.execute(
                """
                UPDATE commercial_budget_reservations
                   SET lease_version = %s, heartbeat_at = %s, expires_at = %s
                 WHERE id = %s AND lease_version = %s
                   AND heartbeat_at = %s AND expires_at = %s
                """,
                (
                    committed,
                    decision.heartbeat_at,
                    command.requested_expires_at,
                    str(command.reservation_id),
                    command.lease_version,
                    snapshot.current_heartbeat_at,
                    snapshot.current_expires_at,
                ),
            )
            if cursor.rowcount != 1:
                raise BudgetHeartbeatProtocolError(
                    "budget heartbeat lost its durable update fence"
                )
        self._connection.commit()
        return BudgetHeartbeatResult(
            reservation_id=command.reservation_id,
            lease_version=committed,
            redis_generation=snapshot.redis_generation,
            heartbeat_at=decision.heartbeat_at,
            expires_at=command.requested_expires_at,
            redis_replayed=decision.replayed,
            durable_replayed=False,
        )

    @staticmethod
    def _payload_digest(command, *, redis_generation, buckets) -> str:
        return canonical_sha256(
            {
                "schema": "commercial.budget.heartbeat.v2",
                "reservation_id": str(command.reservation_id),
                "idempotency_key": command.idempotency_key,
                "lease_token": str(command.lease_token),
                "lease_version": command.lease_version,
                "redis_generation": redis_generation,
                "requested_expires_at": command.requested_expires_at,
                "reason_code": command.reason_code,
                "buckets": buckets,
            }
        )

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat clock must be timezone-aware"
            )
        return now

    def _require_idle(self) -> None:
        reader = getattr(self._connection, "get_transaction_status", None)
        if reader is None or reader() != 0:
            raise BudgetHeartbeatProtocolError(
                "budget heartbeat requires an idle dedicated PostgreSQL connection"
            )
