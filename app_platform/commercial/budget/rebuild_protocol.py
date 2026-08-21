"""PostgreSQL-authoritative Redis budget generation rebuild protocol."""

from __future__ import annotations

from datetime import datetime
import json
from typing import Annotated, Any
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, StrictInt

from ..flags import CommercialFlags
from ..models import StableCode, StrictCommercialModel, canonical_sha256
from .rebuild_store import (
    BudgetGenerationBuildCommand,
    CommercialBudgetRebuildRedisStore,
    RebuildBucket,
    RebuildReservation,
)
from .redis_store import MAX_SAFE_REDIS_INTEGER, CommercialReservationRedisError


SafePositiveInt = Annotated[StrictInt, Field(gt=0, le=MAX_SAFE_REDIS_INTEGER)]
_REDIS_REPAIR_GRACE_SECONDS = 86_400
_MAX_REDIS_TTL_SECONDS = 31_536_000
_POLICY_BUCKETS = ("model", "technical")


class BudgetRebuildProtocolError(RuntimeError):
    """A Redis generation could not be rebuilt and cut over safely."""


class BudgetRebuildCommand(StrictCommercialModel):
    budget_period_id: SafePositiveInt
    idempotency_key: StableCode
    reason_code: StableCode = "budget.rebuild"


class BudgetRebuildResult(StrictCommercialModel):
    budget_period_id: SafePositiveInt
    agreement_terms_id: SafePositiveInt
    expected_generation: SafePositiveInt
    target_generation: SafePositiveInt
    snapshot_sha256: str
    reservation_count: Annotated[StrictInt, Field(ge=0)]
    active_reservations: Annotated[StrictInt, Field(ge=0)]
    redis_replayed: bool
    durable_replayed: bool


class BudgetRebuildProtocol:
    def __init__(
        self,
        connection: Any,
        redis_store: CommercialBudgetRebuildRedisStore,
        *,
        flags: CommercialFlags,
        clock,
    ) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise BudgetRebuildProtocolError(
                "budget rebuild requires transactional PostgreSQL"
            )
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
        ):
            raise BudgetRebuildProtocolError("budget rebuild requires enforcement mode")
        self._connection = connection
        self._redis = redis_store
        self._clock = clock

    def rebuild(self, command: BudgetRebuildCommand) -> BudgetRebuildResult:
        try:
            raw = (
                command.model_dump()
                if isinstance(command, StrictCommercialModel)
                else command
            )
            command = BudgetRebuildCommand.model_validate(raw)
        except Exception as error:
            raise BudgetRebuildProtocolError(
                "budget rebuild command is invalid"
            ) from error
        self._require_idle()
        now = self._now()
        try:
            authority = self._lock_authority(command, now=now)
            if isinstance(authority, BudgetRebuildResult):
                self._connection.commit()
                return authority
            return self._rebuild_from_locked_authority(
                command, authority, now=now
            )
        except CommercialReservationRedisError as error:
            self._connection.rollback()
            raise BudgetRebuildProtocolError(
                "budget generation Redis operation is unavailable; retry"
            ) from error
        except Exception:
            self._connection.rollback()
            raise

    def _rebuild_from_locked_authority(
        self,
        command,
        authority,
        *,
        now,
        commit=True,
    ):
        """Rebuild while the caller retains the authority transaction locks.

        A composed protocol may defer the PostgreSQL commit so its own durable
        evidence is written in the same transaction as the rebuild event and
        generation updates. Redis CAS still occurs before those writes.
        """

        expected_generation = authority["expected_generation"]
        pointer_generation, _pointer_digest = self._redis.current_generation(
            agreement_terms_id=authority["agreement_terms_id"],
            period_id=command.budget_period_id,
        )
        pointer_generation = pointer_generation or expected_generation
        target_generation = max(expected_generation, pointer_generation) + 1
        build_command = None
        build_decision = None
        for _attempt in range(16):
            build_command = self._build_command(
                command,
                authority,
                expected_generation=expected_generation,
                target_generation=target_generation,
                now=now,
            )
            build_decision = self._redis.build(build_command)
            if build_decision.decision == "allow":
                break
            if build_decision.reason_code not in {
                "budget.rebuild_conflict",
                "budget.rebuild_orphan_keys",
            }:
                raise BudgetRebuildProtocolError(
                    f"Redis generation build rejected: {build_decision.reason_code}"
                )
            target_generation += 1
        else:
            raise BudgetRebuildProtocolError(
                "budget rebuild exhausted safe target generations"
            )
        assert build_command is not None and build_decision is not None
        cas_decision = self._redis.compare_and_set(
            agreement_terms_id=authority["agreement_terms_id"],
            period_id=command.budget_period_id,
            expected_generation=pointer_generation,
            target_generation=target_generation,
            snapshot_sha256=build_command.snapshot_sha256,
            reservation_ids=tuple(
                reservation.reservation_id
                for reservation in build_command.reservations
            ),
        )
        if cas_decision.decision != "allow":
            raise BudgetRebuildProtocolError(
                f"Redis generation CAS rejected: {cas_decision.reason_code}"
            )
        return self._record(
            command,
            authority,
            build_command,
            redis_replayed=build_decision.replayed or cas_decision.replayed,
            now=now,
            commit=commit,
        )

    def _lock_authority(
        self,
        command,
        *,
        now,
        allow_blockers: bool = False,
        check_replay: bool = True,
    ):
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"budget-rebuild-period:{command.budget_period_id}",),
            )
            cursor.execute(
                """
                SELECT agreement_terms_id, budget_policy_id,
                       model_limit_microusd, technical_limit_microusd,
                       max_concurrent_reservations,
                       max_unreserved_delta_microusd,
                       late_child_allowance_microusd,
                       max_period_overdraft_microusd,
                       late_child_consumed_microusd, redis_generation
                  FROM commercial_budget_periods
                 WHERE id = %s
                 FOR UPDATE
                """,
                (command.budget_period_id,),
            )
            period = cursor.fetchone()
            existing = None
            if check_replay:
                cursor.execute(
                    """
                    SELECT metadata, reason_code
                      FROM commercial_budget_events
                     WHERE budget_period_id = %s
                       AND reservation_id IS NULL
                       AND event_kind = 'rebuild'
                       AND metadata->>'rebuild_idempotency_key' = %s
                     ORDER BY id DESC LIMIT 1
                    """,
                    (command.budget_period_id, command.idempotency_key),
                )
                existing = cursor.fetchone()
        if period is None:
            raise BudgetRebuildProtocolError(
                "budget rebuild period authority is missing"
            )
        if existing is not None:
            metadata = existing[0]
            if existing[1] != command.reason_code:
                raise BudgetRebuildProtocolError(
                    "budget rebuild replay conflicts with durable evidence"
                )
            try:
                return BudgetRebuildResult(
                    budget_period_id=command.budget_period_id,
                    agreement_terms_id=period[0],
                    expected_generation=metadata["expected_generation"],
                    target_generation=metadata["target_generation"],
                    snapshot_sha256=metadata["snapshot_sha256"],
                    reservation_count=metadata["reservation_count"],
                    active_reservations=metadata["active_reservations"],
                    redis_replayed=False,
                    durable_replayed=True,
                )
            except Exception as error:
                raise BudgetRebuildProtocolError(
                    "budget rebuild durable replay evidence is malformed"
                ) from error
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT reservation.id, reservation.request_payload_sha256,
                       reservation.lease_token, reservation.lease_version,
                       reservation.state, reservation.late_child_accept_until,
                       reservation.redis_generation,
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
                       ), FALSE)
                  FROM commercial_budget_reservations reservation
                 WHERE reservation.budget_period_id = %s
                 ORDER BY reservation.id
                 FOR UPDATE OF reservation
                """,
                (command.budget_period_id,),
            )
            reservations = cursor.fetchall()
            cursor.execute(
                """
                SELECT 1
                  FROM commercial_budget_settlement_attempts attempt
                 WHERE attempt.budget_period_id = %s
                   AND NOT EXISTS (
                       SELECT 1 FROM commercial_budget_settlements settlement
                        WHERE settlement.usage_event_id = attempt.usage_event_id
                          AND settlement.cost_revision = attempt.cost_revision
                   )
                 LIMIT 1
                """,
                (command.budget_period_id,),
            )
            unresolved = cursor.fetchone()
            cursor.execute(
                """
                SELECT reservation_id, budget_bucket, current_hold_microusd
                  FROM commercial_budget_current_holds
                 WHERE budget_period_id = %s
                 ORDER BY reservation_id, budget_bucket
                """,
                (command.budget_period_id,),
            )
            holds = cursor.fetchall()
            cursor.execute(
                """
                WITH initial_buckets AS (
                    SELECT DISTINCT initial.reservation_id, initial.budget_bucket
                      FROM commercial_budget_hold_events initial
                     WHERE initial.budget_period_id = %s
                       AND initial.hold_revision = 0
                       AND initial.hold_kind = 'reserve'
                )
                SELECT initial.budget_bucket,
                       COALESCE(SUM(settlement.amount_delta_microusd), 0)::BIGINT
                  FROM initial_buckets initial
                  LEFT JOIN commercial_budget_settlements settlement
                    ON settlement.reservation_id = initial.reservation_id
                 GROUP BY initial.budget_bucket
                 ORDER BY initial.budget_bucket
                """,
                (command.budget_period_id,),
            )
            actuals = cursor.fetchall()
        if unresolved is not None and not allow_blockers:
            raise BudgetRebuildProtocolError(
                "budget rebuild is blocked by an unresolved settlement attempt"
            )
        pending_reservations = tuple(
            UUID(str(row[0])) for row in reservations if row[4] == "pending"
        )
        if pending_reservations and not allow_blockers:
            raise BudgetRebuildProtocolError(
                "budget rebuild is blocked by a pending reservation"
            )
        expected_generation = int(period[9])
        for row in reservations:
            active = row[4] in {"reserved", "partially_settled"} or (
                row[4] == "overdrawn" and bool(row[8])
            )
            if active and (row[6] is None or int(row[6]) != expected_generation):
                raise BudgetRebuildProtocolError(
                    "active reservation generation conflicts with its budget period"
                )
        return {
            "budget_period_id": command.budget_period_id,
            "agreement_terms_id": int(period[0]),
            "budget_policy_id": int(period[1]),
            "limits": {"model": int(period[2]), "technical": int(period[3])},
            "max_concurrency": int(period[4]),
            "max_unreserved_delta": int(period[5]),
            "late_allowance": int(period[6]),
            "max_overdraft": int(period[7]),
            "late_consumed": int(period[8]),
            "expected_generation": expected_generation,
            "reservations": reservations,
            "holds": holds,
            "actuals": actuals,
            "has_unresolved_settlement_attempt": unresolved is not None,
            "pending_reservation_ids": pending_reservations,
            "now": now,
        }

    def _build_command(
        self,
        command,
        authority,
        *,
        expected_generation,
        target_generation,
        now,
    ):
        limits = authority["limits"]
        holds = {
            (UUID(str(reservation_id)), bucket): int(amount)
            for reservation_id, bucket, amount in authority["holds"]
        }
        hold_totals = dict.fromkeys(_POLICY_BUCKETS, 0)
        for (_reservation_id, bucket), amount in holds.items():
            if bucket not in hold_totals or amount < 0:
                raise BudgetRebuildProtocolError("durable rebuild holds are invalid")
            hold_totals[bucket] += amount
        actual_totals = dict.fromkeys(_POLICY_BUCKETS, 0)
        for bucket, amount in authority["actuals"]:
            if bucket not in actual_totals:
                raise BudgetRebuildProtocolError("durable rebuild actuals are invalid")
            actual_totals[bucket] = int(amount)
        counter_totals = {
            bucket: actual_totals[bucket] + hold_totals[bucket]
            for bucket in _POLICY_BUCKETS
        }
        if any(
            amount < 0 or amount > MAX_SAFE_REDIS_INTEGER
            for amount in counter_totals.values()
        ):
            raise BudgetRebuildProtocolError(
                "durable rebuild counters exceed exact Redis bounds"
            )
        reservations = []
        active_count = 0
        for row in authority["reservations"]:
            initial_buckets = tuple(row[7])
            if initial_buckets not in {("technical",), _POLICY_BUCKETS}:
                raise BudgetRebuildProtocolError(
                    "durable rebuild reservation buckets are unsupported"
                )
            active = row[4] in {"reserved", "partially_settled"} or (
                row[4] == "overdrawn" and bool(row[8])
            )
            active_count += int(active)
            lease_version = int(row[3]) + (1 if active else 0)
            ttl = int((row[5] - now).total_seconds()) + 1 + _REDIS_REPAIR_GRACE_SECONDS
            ttl = max(_REDIS_REPAIR_GRACE_SECONDS, ttl)
            if ttl > _MAX_REDIS_TTL_SECONDS:
                raise BudgetRebuildProtocolError(
                    "durable rebuild reservation retention is unsafe"
                )
            reservation_holds = []
            for bucket in _POLICY_BUCKETS:
                amount = holds.get((UUID(str(row[0])), bucket), 0)
                if bucket not in initial_buckets and amount != 0:
                    raise BudgetRebuildProtocolError(
                        "durable rebuild hold lacks initial bucket authority"
                    )
                if not active and amount != 0:
                    raise BudgetRebuildProtocolError(
                        "terminal rebuild reservation retains a hold"
                    )
                reservation_holds.append(
                    RebuildBucket(
                        budget_bucket=bucket,
                        amount_microusd=amount,
                        limit_microusd=limits[bucket],
                    )
                )
            reservations.append(
                RebuildReservation(
                    reservation_id=row[0],
                    payload_sha256=row[1],
                    lease_token=row[2],
                    lease_version=lease_version,
                    state=row[4],
                    active=active,
                    ttl_seconds=ttl,
                    holds_by_bucket_microusd=tuple(reservation_holds),
                )
            )
        if active_count > authority["max_concurrency"]:
            raise BudgetRebuildProtocolError(
                "durable active reservations exceed the policy limit"
            )
        snapshot_body = {
            "schema": "commercial.budget.rebuild.v1",
            "budget_period_id": command.budget_period_id,
            "agreement_terms_id": authority["agreement_terms_id"],
            "expected_generation": expected_generation,
            "target_generation": target_generation,
            "budget_policy_id": authority["budget_policy_id"],
            "max_concurrency": authority["max_concurrency"],
            "max_unreserved_delta": authority["max_unreserved_delta"],
            "late_allowance": authority["late_allowance"],
            "late_consumed": authority["late_consumed"],
            "max_overdraft": authority["max_overdraft"],
            "counters": counter_totals,
            "reservations": [item.model_dump(mode="json") for item in reservations],
        }
        digest = canonical_sha256(snapshot_body)
        return BudgetGenerationBuildCommand(
            agreement_terms_id=authority["agreement_terms_id"],
            budget_period_id=command.budget_period_id,
            expected_generation=expected_generation,
            target_generation=target_generation,
            snapshot_sha256=digest,
            budget_policy_id=authority["budget_policy_id"],
            max_concurrent_reservations=authority["max_concurrency"],
            max_unreserved_delta_microusd=authority["max_unreserved_delta"],
            late_child_allowance_microusd=authority["late_allowance"],
            late_child_consumed_microusd=authority["late_consumed"],
            max_period_overdraft_microusd=authority["max_overdraft"],
            active_reservations=active_count,
            buckets=tuple(
                RebuildBucket(
                    budget_bucket=bucket,
                    amount_microusd=counter_totals[bucket],
                    limit_microusd=limits[bucket],
                )
                for bucket in _POLICY_BUCKETS
            ),
            reservations=tuple(reservations),
        )

    def _record(
        self,
        command,
        authority,
        build_command,
        *,
        redis_replayed,
        now,
        commit=True,
    ):
        metadata = {
            "rebuild_idempotency_key": command.idempotency_key,
            "snapshot_sha256": build_command.snapshot_sha256,
            "expected_generation": build_command.expected_generation,
            "target_generation": build_command.target_generation,
            "reservation_count": len(build_command.reservations),
            "active_reservations": build_command.active_reservations,
        }
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO commercial_budget_events (
                    event_id, budget_period_id, event_kind, amount_microusd,
                    reason_code, occurred_at, actor_type, metadata
                ) VALUES (%s, %s, 'rebuild', 0, %s, %s, 'reconciler', %s::jsonb)
                """,
                (
                    str(
                        uuid5(
                            NAMESPACE_URL,
                            f"budget-rebuild:{command.budget_period_id}:"
                            f"{command.idempotency_key}",
                        )
                    ),
                    command.budget_period_id,
                    command.reason_code,
                    now,
                    json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                ),
            )
            active = {
                reservation.reservation_id: reservation
                for reservation in build_command.reservations
                if reservation.active
            }
            for reservation_id, reservation in active.items():
                event_metadata = {
                    **metadata,
                    "input_lease_version": reservation.lease_version - 1,
                }
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_events (
                        event_id, budget_period_id, reservation_id, event_kind,
                        amount_microusd, lease_version, reason_code, occurred_at,
                        actor_type, metadata
                    ) VALUES (%s, %s, %s, 'rebuild', 0, %s, %s, %s,
                              'reconciler', %s::jsonb)
                    """,
                    (
                        str(
                            uuid5(
                                NAMESPACE_URL,
                                f"budget-rebuild:{command.budget_period_id}:"
                                f"{command.idempotency_key}:{reservation_id}",
                            )
                        ),
                        command.budget_period_id,
                        str(reservation_id),
                        reservation.lease_version,
                        command.reason_code,
                        now,
                        json.dumps(
                            event_metadata,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    ),
                )
                cursor.execute(
                    """
                    UPDATE commercial_budget_reservations
                       SET redis_generation = %s, lease_version = %s
                     WHERE id = %s AND redis_generation = %s
                       AND lease_version = %s
                    """,
                    (
                        build_command.target_generation,
                        reservation.lease_version,
                        str(reservation_id),
                        build_command.expected_generation,
                        reservation.lease_version - 1,
                    ),
                )
                if cursor.rowcount != 1:
                    raise BudgetRebuildProtocolError(
                        "budget rebuild lost an active reservation fence"
                    )
            cursor.execute(
                """
                UPDATE commercial_budget_periods
                   SET redis_generation = %s
                 WHERE id = %s AND redis_generation = %s
                """,
                (
                    build_command.target_generation,
                    command.budget_period_id,
                    build_command.expected_generation,
                ),
            )
            if cursor.rowcount != 1:
                raise BudgetRebuildProtocolError(
                    "budget rebuild lost its period generation CAS"
                )
        if commit:
            self._connection.commit()
        return BudgetRebuildResult(
            budget_period_id=command.budget_period_id,
            agreement_terms_id=authority["agreement_terms_id"],
            expected_generation=build_command.expected_generation,
            target_generation=build_command.target_generation,
            snapshot_sha256=build_command.snapshot_sha256,
            reservation_count=len(build_command.reservations),
            active_reservations=build_command.active_reservations,
            redis_replayed=redis_replayed,
            durable_replayed=False,
        )

    def _now(self):
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise BudgetRebuildProtocolError(
                "budget rebuild clock must be timezone-aware"
            )
        return now

    def _require_idle(self):
        reader = getattr(self._connection, "get_transaction_status", None)
        if reader is None or reader() != 0:
            raise BudgetRebuildProtocolError(
                "budget rebuild requires an idle dedicated PostgreSQL connection"
            )
