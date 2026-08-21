"""Ledger-first recoverable protocol for final commercial budget settlement."""

from __future__ import annotations

from decimal import Decimal, ROUND_CEILING
import json
from typing import Annotated, Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .redis_store import BucketLimit, CommercialReservationRedisError
from .settlement_store import (
    BudgetSettlementRedisCommand,
    CommercialBudgetSettlementRedisStore,
    SettlementBucketAmount,
)


PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
SignedSafeInt = Annotated[StrictInt, Field(ge=-(2**52 - 1), le=2**52 - 1)]
_REDIS_REPAIR_GRACE_SECONDS = 86_400
_MAX_REDIS_TTL_SECONDS = 31_536_000


class BudgetSettlementProtocolError(RuntimeError):
    """Canonical usage could not be safely reconciled to both budget stores."""


class BudgetUsageSettlementCommand(StrictCommercialModel):
    usage_event_id: PositiveInt
    cost_revision: NonNegativeInt = 0
    cost_adjustment_id: UUID | None = None
    reason_code: StableCode = "budget.settled"
    actor_type: Literal["service", "provider", "admin", "reconciler"] = "service"
    actor_id: str | None = None
    finalize_reservation: StrictBool = True

    @model_validator(mode="after")
    def _revision_authority(self) -> "BudgetUsageSettlementCommand":
        if (self.cost_revision == 0) is not (self.cost_adjustment_id is None):
            raise ValueError(
                "cost revisions require one canonical cost adjustment authority"
            )
        if self.cost_revision > 0 and not self.finalize_reservation:
            raise ValueError("cost revisions are post-final accounting operations")
        return self


class BudgetUsageSettlementResult(StrictCommercialModel):
    reservation_id: UUID
    usage_event_id: PositiveInt
    cost_revision: NonNegativeInt
    state: Literal["partially_settled", "settled", "overdrawn"]
    lease_version: PositiveInt
    reason_code: StableCode
    redis_replayed: bool
    durable_replayed: bool
    settled_at: AwareDatetime


class _Snapshot(StrictCommercialModel):
    reservation_id: UUID
    budget_period_id: PositiveInt
    agreement_terms_id: PositiveInt
    source_product: StableCode
    source_event_id: str
    usage_occurred_at: AwareDatetime
    reservation_state: Literal[
        "pending",
        "reserved",
        "partially_settled",
        "settled",
        "released",
        "expired",
        "overdrawn",
    ]
    lease_token: UUID
    lease_version: PositiveInt
    redis_generation: PositiveInt
    expires_at: AwareDatetime
    late_child_accept_until: AwareDatetime
    budget_policy_id: PositiveInt
    model_limit_microusd: PositiveInt
    technical_limit_microusd: PositiveInt
    late_child_allowance_microusd: Annotated[StrictInt, Field(ge=0)]
    management_cost_microusd: SignedSafeInt
    settlement_payload_sha256: Sha256Digest
    reservation_active: StrictBool
    cost_adjustment_id: UUID | None = None
    is_late_child: StrictBool
    actuals: tuple[SettlementBucketAmount, ...]
    limits: tuple[BucketLimit, ...]


class BudgetSettlementProtocol:
    """Settle canonical usage in Redis, then append its durable fenced journal."""

    def __init__(
        self,
        connection: Any,
        redis_store: CommercialBudgetSettlementRedisStore,
        *,
        flags: CommercialFlags,
        clock,
    ) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise BudgetSettlementProtocolError(
                "budget settlement protocol requires transactional PostgreSQL"
            )
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
        ):
            raise BudgetSettlementProtocolError(
                "budget settlement protocol requires enforcement mode"
            )
        self._connection = connection
        self._redis = redis_store
        self._clock = clock

    def settle(
        self, command: BudgetUsageSettlementCommand
    ) -> BudgetUsageSettlementResult:
        command = BudgetUsageSettlementCommand.model_validate(command.model_dump())
        self._require_idle_connection()
        snapshot = self._load_attempt(command)
        if snapshot is None:
            snapshot = self._load_snapshot(command)
        existing = self._load_existing(command, snapshot)
        if (
            existing is not None
            and self._current_period_generation(snapshot.budget_period_id)
            != snapshot.redis_generation
        ):
            return existing
        if existing is None:
            snapshot = self._ensure_attempt(command, snapshot)
        redis_snapshot = snapshot
        if existing is not None:
            redis_fence = existing.lease_version
            if command.cost_revision == 0 and snapshot.reservation_active:
                redis_fence -= 1
            if redis_fence <= 0:
                raise BudgetSettlementProtocolError(
                    "durable settlement has an invalid prospective fence"
                )
            redis_snapshot = snapshot.model_copy(update={"lease_version": redis_fence})
        try:
            redis_command = self._redis_command(command, redis_snapshot)
            if not self._generation_ready(redis_snapshot):
                raise BudgetSettlementProtocolError(
                    "Redis generation is not ready before settlement execution"
                )
        except Exception:
            self._connection.rollback()
            raise
        try:
            decision = self._redis.settle(
                agreement_terms_id=snapshot.agreement_terms_id,
                period_id=snapshot.budget_period_id,
                command=redis_command,
            )
        except CommercialReservationRedisError as error:
            self._commit_attempt()
            raise BudgetSettlementProtocolError(
                "Redis settlement is unavailable; canonical usage remains durable for retry"
            ) from error
        if decision.decision != "allow":
            self._connection.rollback()
            raise BudgetSettlementProtocolError(
                f"Redis settlement rejected canonical usage: {decision.reason_code}"
            )
        self._commit_attempt()
        if existing is not None:
            if not decision.replayed:
                raise BudgetSettlementProtocolError(
                    "durable settlement exists without matching Redis replay evidence"
                )
            return existing.model_copy(update={"redis_replayed": True})
        if decision.state not in {"partially_settled", "settled", "overdrawn"}:
            raise BudgetSettlementProtocolError(
                "final Redis settlement did not reach a final accounting state"
            )
        try:
            return self._record_durable(command, snapshot, decision)
        except Exception as error:
            self._connection.rollback()
            if isinstance(error, BudgetSettlementProtocolError):
                raise
            raise BudgetSettlementProtocolError(
                "Redis settlement succeeded but durable journaling failed; retry from canonical usage"
            ) from error

    def _load_snapshot(self, command: BudgetUsageSettlementCommand) -> _Snapshot:
        usage_event_id = command.usage_event_id
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT reservation.id, reservation.budget_period_id,
                           reservation.agreement_terms_id,
                           usage.source_product, usage.source_event_id,
                           usage.occurred_at, reservation.state,
                           reservation.lease_token, reservation.lease_version,
                           reservation.redis_generation, reservation.expires_at,
                           reservation.late_child_accept_until,
                           period.budget_policy_id,
                           period.model_limit_microusd,
                           period.technical_limit_microusd,
                           period.late_child_allowance_microusd,
                           usage.payer_class, usage.pricing_state,
                           usage.normalized_shadow_cost_usd,
                           usage.provider_reported_cost_usd,
                           usage.usage_state, usage.source_payload_sha256,
                           (
                               SELECT event.metadata->>'finalize_reservation'
                                 FROM commercial_budget_settlements prior
                                JOIN commercial_budget_events event
                                  ON event.event_id = prior.event_id
                                WHERE prior.reservation_id = reservation.id
                                  AND prior.cost_revision = 0
                                ORDER BY prior.id DESC LIMIT 1
                           ) AS latest_finalize_reservation,
                           period.redis_generation
                      FROM commercial_usage_events usage
                      JOIN commercial_budget_reservations reservation
                        ON reservation.id = usage.reservation_id
                       AND reservation.execution_context_id = usage.execution_context_id
                      JOIN commercial_budget_periods period
                        ON period.id = reservation.budget_period_id
                       AND period.agreement_terms_id = reservation.agreement_terms_id
                     WHERE usage.id = %s
                    """,
                    (usage_event_id,),
                )
                row = cursor.fetchone()
            adjustment_row = None
            if command.cost_revision > 0:
                with self._connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT adjustment.usage_event_id,
                               adjustment.agreement_terms_id,
                               adjustment.adjustment_kind,
                               adjustment.amount_usd, adjustment.reason_code,
                               adjustment.actor_type, adjustment.actor_id,
                               previous.cost_revision,
                               previous.is_late_child
                          FROM commercial_cost_adjustments adjustment
                          LEFT JOIN commercial_budget_settlements previous
                            ON previous.reservation_id = %s
                           AND previous.usage_event_id = adjustment.usage_event_id
                           AND previous.cost_revision = %s
                         WHERE adjustment.adjustment_id = %s
                        """,
                        (
                            str(row[0]) if row is not None else None,
                            command.cost_revision - 1,
                            str(command.cost_adjustment_id),
                        ),
                    )
                    adjustment_row = cursor.fetchone()
            initial_hold_rows = []
            if row is not None:
                with self._connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT budget_bucket
                          FROM commercial_budget_hold_events
                         WHERE reservation_id = %s
                           AND hold_revision = 0 AND hold_kind = 'reserve'
                         ORDER BY budget_bucket
                        """,
                        (str(row[0]),),
                    )
                    initial_hold_rows = cursor.fetchall()
            self._connection.rollback()
        except Exception:
            self._connection.rollback()
            raise
        if row is None:
            raise BudgetSettlementProtocolError(
                "canonical usage has no exact durable budget reservation lineage"
            )
        if row[9] is None:
            raise BudgetSettlementProtocolError(
                "canonical usage reservation has no Redis generation"
            )
        if row[16] != "hank_paid" or row[17] != "priced" or row[18] is None:
            raise BudgetSettlementProtocolError(
                "canonical usage is not eligible priced Hank-funded usage"
            )
        if row[20] not in {"succeeded", "failed_billable"}:
            raise BudgetSettlementProtocolError(
                "canonical usage state is not eligible for budget settlement"
            )
        if command.cost_revision == 0:
            normalized = Decimal(row[18])
            provider_reported = Decimal(row[19]) if row[19] is not None else Decimal(0)
            management_usd = max(normalized, provider_reported)
            management_microusd = int(
                (management_usd * Decimal(1_000_000)).to_integral_value(
                    rounding=ROUND_CEILING
                )
            )
        else:
            if adjustment_row is None:
                raise BudgetSettlementProtocolError(
                    "canonical cost adjustment authority is missing"
                )
            if adjustment_row[3] is None:
                raise BudgetSettlementProtocolError(
                    "canonical cost adjustment has no monetary delta"
                )
            adjustment_microusd = Decimal(adjustment_row[3]) * Decimal(1_000_000)
            if (
                int(adjustment_row[0]) != usage_event_id
                or int(adjustment_row[1]) != int(row[2])
                or adjustment_row[2] != "actual_cost"
                or adjustment_microusd != adjustment_microusd.to_integral_value()
                or adjustment_row[4] != command.reason_code
                or adjustment_row[5] != command.actor_type
                or adjustment_row[6] != command.actor_id
                or adjustment_row[7] != command.cost_revision - 1
            ):
                raise BudgetSettlementProtocolError(
                    "canonical cost adjustment authority conflicts or revision is not contiguous"
                )
            management_microusd = int(adjustment_microusd)
        initial_buckets = tuple(item[0] for item in initial_hold_rows)
        if initial_buckets not in {("technical",), ("model", "technical")}:
            raise BudgetSettlementProtocolError(
                "durable reservation has an unsupported settlement bucket allocation"
            )
        limit_map = {"model": int(row[13]), "technical": int(row[14])}
        policy_buckets = ("model", "technical")
        actuals = tuple(
            SettlementBucketAmount(
                budget_bucket=bucket,
                amount_microusd=(
                    management_microusd if bucket in initial_buckets else 0
                ),
            )
            for bucket in policy_buckets
        )
        limits = tuple(
            BucketLimit(budget_bucket=bucket, limit_microusd=limit_map[bucket])
            for bucket in policy_buckets
        )
        digest = canonical_sha256(
            {
                "usage_event_id": usage_event_id,
                "reservation_id": str(row[0]),
                "source_product": row[3],
                "source_event_id": row[4],
                "source_payload_sha256": row[21],
                "cost_revision": command.cost_revision,
                "cost_adjustment_id": (
                    str(command.cost_adjustment_id)
                    if command.cost_adjustment_id is not None
                    else None
                ),
                "pricing_state": row[17],
                "management_cost_microusd": management_microusd,
            }
        )
        reservation_active = row[6] in {"reserved", "partially_settled"}
        if row[6] == "overdrawn":
            reservation_active = row[22] == "false"
        period_generation = int(row[23])
        if reservation_active and int(row[9]) != period_generation:
            raise BudgetSettlementProtocolError(
                "active reservation generation conflicts with its budget period"
            )
        is_late_child = (
            row[5] >= row[10] if command.cost_revision == 0 else bool(adjustment_row[8])
        )
        return _Snapshot(
            reservation_id=row[0],
            budget_period_id=row[1],
            agreement_terms_id=row[2],
            source_product=row[3],
            source_event_id=row[4],
            usage_occurred_at=row[5],
            reservation_state=row[6],
            lease_token=row[7],
            lease_version=row[8],
            redis_generation=period_generation,
            expires_at=row[10],
            late_child_accept_until=row[11],
            budget_policy_id=row[12],
            model_limit_microusd=row[13],
            technical_limit_microusd=row[14],
            late_child_allowance_microusd=row[15],
            management_cost_microusd=management_microusd,
            settlement_payload_sha256=digest,
            reservation_active=reservation_active,
            cost_adjustment_id=command.cost_adjustment_id,
            is_late_child=is_late_child,
            actuals=actuals,
            limits=limits,
        )

    def _load_existing(self, command, snapshot):
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT settlement.reservation_id, settlement.amount_delta_microusd,
                       settlement.settlement_payload_sha256,
                       settlement.reason_code, settlement.actor_type,
                       settlement.actor_id, settlement.lease_version,
                       reservation.state, settlement.created_at,
                       settlement.is_late_child, event.metadata
                  FROM commercial_budget_settlements settlement
                  JOIN commercial_budget_reservations reservation
                    ON reservation.id = settlement.reservation_id
                  JOIN commercial_budget_events event
                    ON event.event_id = settlement.event_id
                 WHERE settlement.usage_event_id = %s
                   AND settlement.cost_revision = %s
                """,
                (command.usage_event_id, command.cost_revision),
            )
            row = cursor.fetchone()
        self._connection.rollback()
        if row is None:
            return None
        technical = snapshot.management_cost_microusd
        if (
            UUID(str(row[0])) != snapshot.reservation_id
            or int(row[1]) != technical
            or row[2] != self._payload_digest(command, snapshot)
            or row[3] != command.reason_code
            or row[4] != command.actor_type
            or row[5] != command.actor_id
            or not self._metadata_matches(row[10], command, row[6])
        ):
            conflicts = [
                name
                for name, failed in (
                    ("reservation", UUID(str(row[0])) != snapshot.reservation_id),
                    ("amount", int(row[1]) != technical),
                    ("payload", row[2] != self._payload_digest(command, snapshot)),
                    ("reason", row[3] != command.reason_code),
                    ("actor_type", row[4] != command.actor_type),
                    ("actor_id", row[5] != command.actor_id),
                    ("metadata", not self._metadata_matches(row[10], command, row[6])),
                )
                if failed
            ]
            raise BudgetSettlementProtocolError(
                "canonical usage settlement replay conflicts with durable evidence: "
                + ",".join(conflicts)
            )
        return BudgetUsageSettlementResult(
            reservation_id=snapshot.reservation_id,
            usage_event_id=command.usage_event_id,
            cost_revision=command.cost_revision,
            state=row[10]["result_state"],
            lease_version=row[6],
            reason_code=command.reason_code,
            redis_replayed=False,
            durable_replayed=True,
            settled_at=row[8],
        )

    def _load_attempt(self, command) -> _Snapshot | None:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT attempt.reservation_id, attempt.budget_period_id,
                           attempt.agreement_terms_id, attempt.source_product,
                           attempt.source_event_id, usage.occurred_at,
                           reservation.state, attempt.lease_token,
                           attempt.lease_version, attempt.redis_generation,
                           attempt.expires_at_snapshot,
                           attempt.late_child_accept_until,
                           attempt.budget_policy_id,
                           period.model_limit_microusd,
                           period.technical_limit_microusd,
                           attempt.late_child_allowance_microusd,
                           attempt.amount_delta_microusd,
                           attempt.settlement_payload_sha256,
                           attempt.reservation_active,
                           attempt.cost_adjustment_id,
                           attempt.is_late_child, attempt.actuals_json,
                           attempt.limits_json, attempt.reason_code,
                           attempt.actor_type, attempt.actor_id,
                           attempt.finalize_reservation
                      FROM commercial_budget_settlement_attempts attempt
                      JOIN commercial_usage_events usage
                        ON usage.id = attempt.usage_event_id
                      JOIN commercial_budget_reservations reservation
                        ON reservation.id = attempt.reservation_id
                      JOIN commercial_budget_periods period
                        ON period.id = attempt.budget_period_id
                     WHERE attempt.usage_event_id = %s
                       AND attempt.cost_revision = %s
                    """,
                    (command.usage_event_id, command.cost_revision),
                )
                row = cursor.fetchone()
            self._connection.rollback()
        except Exception:
            self._connection.rollback()
            raise
        if row is None:
            return None
        adjustment_id = UUID(str(row[19])) if row[19] is not None else None
        if (
            adjustment_id != command.cost_adjustment_id
            or row[23] != command.reason_code
            or row[24] != command.actor_type
            or row[25] != command.actor_id
            or bool(row[26]) is not command.finalize_reservation
        ):
            raise BudgetSettlementProtocolError(
                "durable settlement attempt conflicts with prior authority"
            )
        return _Snapshot(
            reservation_id=row[0],
            budget_period_id=row[1],
            agreement_terms_id=row[2],
            source_product=row[3],
            source_event_id=row[4],
            usage_occurred_at=row[5],
            reservation_state=row[6],
            lease_token=row[7],
            lease_version=row[8],
            redis_generation=row[9],
            expires_at=row[10],
            late_child_accept_until=row[11],
            budget_policy_id=row[12],
            model_limit_microusd=row[13],
            technical_limit_microusd=row[14],
            late_child_allowance_microusd=row[15],
            management_cost_microusd=row[16],
            settlement_payload_sha256=row[17],
            reservation_active=row[18],
            cost_adjustment_id=adjustment_id,
            is_late_child=row[20],
            actuals=tuple(
                SettlementBucketAmount.model_validate(item) for item in row[21]
            ),
            limits=tuple(BucketLimit.model_validate(item) for item in row[22]),
        )

    def _ensure_attempt(self, command, snapshot) -> _Snapshot:
        actuals = [item.model_dump(mode="json") for item in snapshot.actuals]
        limits = [item.model_dump(mode="json") for item in snapshot.limits]
        values = (
            command.usage_event_id,
            command.cost_revision,
            str(snapshot.reservation_id),
            snapshot.budget_period_id,
            snapshot.agreement_terms_id,
            snapshot.budget_policy_id,
            snapshot.late_child_allowance_microusd,
            snapshot.source_product,
            snapshot.source_event_id,
            snapshot.settlement_payload_sha256,
            command.reason_code,
            command.actor_type,
            command.actor_id,
            str(command.cost_adjustment_id)
            if command.cost_adjustment_id is not None
            else None,
            str(snapshot.lease_token),
            snapshot.lease_version,
            snapshot.redis_generation,
            snapshot.expires_at,
            snapshot.late_child_accept_until,
            snapshot.is_late_child,
            snapshot.reservation_active,
            command.finalize_reservation,
            snapshot.management_cost_microusd,
            json.dumps(actuals, sort_keys=True, separators=(",", ":")),
            json.dumps(limits, sort_keys=True, separators=(",", ":")),
        )
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"budget-settlement-reservation:{snapshot.reservation_id}",),
                )
                cursor.execute(
                    """
                    SELECT reservation.state, reservation.lease_token,
                           reservation.lease_version,
                           reservation.redis_generation,
                           reservation.expires_at,
                           reservation.late_child_accept_until,
                           period.redis_generation
                      FROM commercial_budget_reservations reservation
                      JOIN commercial_budget_periods period
                        ON period.id = reservation.budget_period_id
                     WHERE reservation.id = %s
                     FOR SHARE OF reservation, period
                    """,
                    (str(snapshot.reservation_id),),
                )
                fence = cursor.fetchone()
                if fence is None or (
                    fence[0] != snapshot.reservation_state
                    or UUID(str(fence[1])) != snapshot.lease_token
                    or int(fence[2]) != snapshot.lease_version
                    or (
                        snapshot.reservation_active
                        and int(fence[3]) != snapshot.redis_generation
                    )
                    or int(fence[6]) != snapshot.redis_generation
                    or fence[4] != snapshot.expires_at
                    or fence[5] != snapshot.late_child_accept_until
                ):
                    raise BudgetSettlementProtocolError(
                        "reservation fence changed before durable settlement attempt"
                    )
                if not self._generation_ready(snapshot):
                    raise BudgetSettlementProtocolError(
                        "Redis generation is not ready before durable settlement attempt"
                    )
                cursor.execute(
                    """
                    SELECT 1
                     FROM commercial_budget_settlement_attempts attempt
                     WHERE attempt.reservation_id = %s
                       AND (attempt.usage_event_id, attempt.cost_revision)
                           <> (%s, %s)
                       AND NOT EXISTS (
                           SELECT 1
                             FROM commercial_budget_settlements settlement
                            WHERE settlement.usage_event_id = attempt.usage_event_id
                              AND settlement.cost_revision = attempt.cost_revision
                       )
                     LIMIT 1
                    """,
                    (
                        str(snapshot.reservation_id),
                        command.usage_event_id,
                        command.cost_revision,
                    ),
                )
                if cursor.fetchone() is not None:
                    raise BudgetSettlementProtocolError(
                        "reservation has another unresolved settlement attempt"
                    )
                if command.cost_adjustment_id is not None:
                    cursor.execute(
                        """
                        SELECT 1
                          FROM commercial_budget_settlement_attempts
                         WHERE cost_adjustment_id = %s
                           AND (usage_event_id, cost_revision) <> (%s, %s)
                        UNION ALL
                        SELECT 1
                          FROM commercial_budget_settlements
                         WHERE cost_adjustment_id = %s
                           AND (usage_event_id, cost_revision) <> (%s, %s)
                         LIMIT 1
                        """,
                        (
                            str(command.cost_adjustment_id),
                            command.usage_event_id,
                            command.cost_revision,
                            str(command.cost_adjustment_id),
                            command.usage_event_id,
                            command.cost_revision,
                        ),
                    )
                    if cursor.fetchone() is not None:
                        raise BudgetSettlementProtocolError(
                            "canonical cost adjustment authority was already consumed"
                        )
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_settlement_attempts (
                        usage_event_id, cost_revision, reservation_id,
                        budget_period_id, agreement_terms_id, budget_policy_id,
                        late_child_allowance_microusd, source_product,
                        source_event_id, settlement_payload_sha256, reason_code,
                        actor_type, actor_id, cost_adjustment_id, lease_token,
                        lease_version, redis_generation, expires_at_snapshot,
                        late_child_accept_until, is_late_child,
                        reservation_active, finalize_reservation,
                        amount_delta_microusd, actuals_json, limits_json
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb
                    ) ON CONFLICT (usage_event_id, cost_revision) DO NOTHING
                    """,
                    values,
                )
                cursor.execute(
                    """
                    SELECT reservation_id, budget_period_id, agreement_terms_id,
                           budget_policy_id, late_child_allowance_microusd,
                           source_product, source_event_id,
                           settlement_payload_sha256, reason_code, actor_type,
                           actor_id, cost_adjustment_id, lease_token,
                           lease_version, redis_generation, expires_at_snapshot,
                           late_child_accept_until, is_late_child,
                           reservation_active, finalize_reservation,
                           amount_delta_microusd, actuals_json, limits_json
                      FROM commercial_budget_settlement_attempts
                     WHERE usage_event_id = %s AND cost_revision = %s
                    """,
                    (command.usage_event_id, command.cost_revision),
                )
                row = cursor.fetchone()
            expected = values[2:]
            normalized = (
                str(row[0]),
                *row[1:11],
                str(row[11]) if row[11] is not None else None,
                str(row[12]),
                *row[13:21],
                json.dumps(row[21], sort_keys=True, separators=(",", ":")),
                json.dumps(row[22], sort_keys=True, separators=(",", ":")),
            )
            if normalized != expected:
                raise BudgetSettlementProtocolError(
                    "durable settlement attempt conflicts with prior authority"
                )
            return snapshot
        except Exception:
            self._connection.rollback()
            raise

    def _generation_ready(self, snapshot) -> bool:
        try:
            return self._redis.generation_ready(
                agreement_terms_id=snapshot.agreement_terms_id,
                period_id=snapshot.budget_period_id,
                generation=snapshot.redis_generation,
                reservation_id=snapshot.reservation_id,
                buckets=tuple(item.budget_bucket for item in snapshot.actuals),
            )
        except CommercialReservationRedisError as error:
            raise BudgetSettlementProtocolError(
                "Redis generation readiness is unavailable before durable settlement attempt"
            ) from error

    def _commit_attempt(self) -> None:
        try:
            self._connection.commit()
        except Exception as error:
            self._connection.rollback()
            raise BudgetSettlementProtocolError(
                "durable settlement attempt commit outcome is unknown; retry from canonical usage"
            ) from error

    def _current_period_generation(self, budget_period_id: int) -> int:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    "SELECT redis_generation FROM commercial_budget_periods WHERE id = %s",
                    (budget_period_id,),
                )
                row = cursor.fetchone()
            if row is None:
                raise BudgetSettlementProtocolError(
                    "budget settlement period authority is missing"
                )
            return int(row[0])
        finally:
            self._connection.rollback()

    def _redis_command(self, command, snapshot):
        now = self._clock()
        ttl_seconds = (
            int((snapshot.late_child_accept_until - now).total_seconds())
            + 1
            + _REDIS_REPAIR_GRACE_SECONDS
        )
        if ttl_seconds <= 0 or ttl_seconds > _MAX_REDIS_TTL_SECONDS:
            raise BudgetSettlementProtocolError(
                "durable settlement attempt requires Redis generation rebuild; "
                "its retry window is no longer representable"
            )
        return BudgetSettlementRedisCommand(
            reservation_id=snapshot.reservation_id,
            source_product=snapshot.source_product,
            source_event_id=snapshot.source_event_id,
            cost_revision=command.cost_revision,
            actor_type=command.actor_type,
            actor_id=command.actor_id,
            cost_adjustment_id=command.cost_adjustment_id,
            reason_code=command.reason_code,
            payload_sha256=self._payload_digest(command, snapshot),
            lease_token=snapshot.lease_token,
            lease_version=snapshot.lease_version,
            generation=snapshot.redis_generation,
            budget_policy_id=snapshot.budget_policy_id,
            ttl_seconds=ttl_seconds,
            is_late_child=snapshot.is_late_child,
            finalize_reservation=command.finalize_reservation,
            late_child_allowance_microusd=snapshot.late_child_allowance_microusd,
            actuals=snapshot.actuals,
            limits=snapshot.limits,
        )

    def _record_durable(self, command, snapshot, decision):
        now = self._clock()
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (
                    f"budget-settlement:{snapshot.reservation_id}:"
                    f"{snapshot.source_event_id}:{command.cost_revision}",
                ),
            )
            cursor.execute(
                """
                SELECT reservation.state, reservation.lease_token,
                       reservation.lease_version,
                       reservation.redis_generation,
                       reservation.budget_period_id, period.redis_generation
                  FROM commercial_budget_reservations reservation
                  JOIN commercial_budget_periods period
                    ON period.id = reservation.budget_period_id
                 WHERE reservation.id = %s
                 FOR UPDATE OF reservation
                """,
                (str(snapshot.reservation_id),),
            )
            row = cursor.fetchone()
            if row is None:
                raise BudgetSettlementProtocolError(
                    "durable reservation disappeared after Redis settlement"
                )
            (
                state,
                lease_token,
                lease_version,
                generation,
                period_id,
                period_generation,
            ) = row
            is_late_child = snapshot.is_late_child
            active_primary = (
                command.cost_revision == 0
                and snapshot.reservation_active
                and state
                in {
                    "reserved",
                    "partially_settled",
                    "overdrawn",
                }
            )
            final_late_child = is_late_child and state in {"settled", "overdrawn"}
            final_revision = command.cost_revision > 0 and state in {
                "settled",
                "overdrawn",
            }
            if (
                not (active_primary or final_late_child or final_revision)
                or UUID(str(lease_token)) != snapshot.lease_token
                or int(lease_version) != snapshot.lease_version
                or (
                    snapshot.reservation_active
                    and int(generation) != snapshot.redis_generation
                )
                or int(period_generation) != snapshot.redis_generation
                or int(period_id) != snapshot.budget_period_id
            ):
                existing = self._existing_locked(cursor, command, snapshot)
                if existing is not None:
                    self._connection.commit()
                    return existing.model_copy(
                        update={"redis_replayed": decision.replayed}
                    )
                raise BudgetSettlementProtocolError(
                    "durable reservation fence changed after Redis settlement"
                )
            committed_lease = (
                snapshot.lease_version + 1 if active_primary else snapshot.lease_version
            )
            if active_primary:
                self._release_holds(cursor, command, snapshot, decision)
            event_id = self._event_id(snapshot, command)
            technical = snapshot.management_cost_microusd
            cursor.execute(
                """
                INSERT INTO commercial_budget_events (
                    event_id, budget_period_id, reservation_id, usage_event_id,
                    budget_bucket, event_kind, amount_microusd, cost_revision,
                    lease_version, reason_code, occurred_at, actor_type, actor_id,
                    cost_adjustment_id, metadata
                ) VALUES (%s, %s, %s, %s, 'technical', %s, %s, %s, %s,
                          %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    str(event_id),
                    snapshot.budget_period_id,
                    str(snapshot.reservation_id),
                    command.usage_event_id,
                    "settle" if command.cost_revision == 0 else "adjust",
                    technical,
                    command.cost_revision,
                    committed_lease,
                    command.reason_code,
                    now,
                    command.actor_type,
                    command.actor_id,
                    str(command.cost_adjustment_id)
                    if command.cost_adjustment_id is not None
                    else None,
                    json.dumps(
                        {
                            "settlement_protocol_version": 1,
                            "finalize_reservation": command.finalize_reservation,
                            "result_state": decision.state,
                            "redis_input_lease_version": snapshot.lease_version,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            cursor.execute(
                """
                INSERT INTO commercial_budget_settlements (
                    event_id, reservation_id, budget_period_id, usage_event_id,
                    source_product, source_event_id, budget_bucket,
                    lease_version, cost_revision, amount_delta_microusd,
                    settlement_payload_sha256, reason_code, actor_type, actor_id
                    , cost_adjustment_id
                ) VALUES (%s, %s, %s, %s, %s, %s, 'technical', %s, %s, %s,
                          %s, %s, %s, %s, %s)
                """,
                (
                    str(event_id),
                    str(snapshot.reservation_id),
                    snapshot.budget_period_id,
                    command.usage_event_id,
                    snapshot.source_product,
                    snapshot.source_event_id,
                    committed_lease,
                    command.cost_revision,
                    technical,
                    self._payload_digest(command, snapshot),
                    command.reason_code,
                    command.actor_type,
                    command.actor_id,
                    str(command.cost_adjustment_id)
                    if command.cost_adjustment_id is not None
                    else None,
                ),
            )
            next_state = decision.state
            if next_state == "overdrawn" and not is_late_child:
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_events (
                        event_id, budget_period_id, reservation_id, usage_event_id,
                        budget_bucket, event_kind, amount_microusd, cost_revision,
                        lease_version, reason_code, occurred_at, actor_type
                    ) VALUES (%s, %s, %s, %s, 'technical', 'overdraw', %s, %s,
                              %s, 'budget.overdrawn', %s, 'service')
                    """,
                    (
                        str(uuid5(NAMESPACE_URL, f"{event_id}:overdraw")),
                        snapshot.budget_period_id,
                        str(snapshot.reservation_id),
                        command.usage_event_id,
                        technical,
                        command.cost_revision,
                        committed_lease,
                        now,
                    ),
                )
            if active_primary:
                cursor.execute(
                    """
                    UPDATE commercial_budget_reservations
                       SET state = %s, lease_version = %s,
                           heartbeat_at = heartbeat_at + INTERVAL '1 microsecond',
                           settled_at = CASE WHEN %s = 'settled' THEN %s ELSE NULL END
                     WHERE id = %s AND lease_version = %s
                    """,
                    (
                        next_state,
                        committed_lease,
                        next_state,
                        now,
                        str(snapshot.reservation_id),
                        snapshot.lease_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise BudgetSettlementProtocolError(
                        "durable settlement lost its reservation fence"
                    )
        self._connection.commit()
        return BudgetUsageSettlementResult(
            reservation_id=snapshot.reservation_id,
            usage_event_id=command.usage_event_id,
            cost_revision=command.cost_revision,
            state="overdrawn" if is_late_child else decision.state,
            lease_version=committed_lease,
            reason_code=command.reason_code,
            redis_replayed=decision.replayed,
            durable_replayed=False,
            settled_at=now,
        )

    def _existing_locked(self, cursor, command, snapshot):
        cursor.execute(
            """
            SELECT settlement.amount_delta_microusd,
                   settlement.settlement_payload_sha256,
                   settlement.reason_code, settlement.actor_type,
                   settlement.actor_id, settlement.lease_version,
                   reservation.state, settlement.created_at,
                   settlement.is_late_child, event.metadata
              FROM commercial_budget_settlements settlement
              JOIN commercial_budget_reservations reservation
                ON reservation.id = settlement.reservation_id
              JOIN commercial_budget_events event
                ON event.event_id = settlement.event_id
             WHERE settlement.usage_event_id = %s
               AND settlement.cost_revision = %s
             FOR SHARE OF settlement
            """,
            (command.usage_event_id, command.cost_revision),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        technical = snapshot.management_cost_microusd
        if (
            int(row[0]) != technical
            or row[1] != self._payload_digest(command, snapshot)
            or row[2] != command.reason_code
            or row[3] != command.actor_type
            or row[4] != command.actor_id
            or not self._metadata_matches(row[9], command, row[5])
        ):
            raise BudgetSettlementProtocolError(
                "concurrent durable settlement conflicts with canonical usage"
            )
        return BudgetUsageSettlementResult(
            reservation_id=snapshot.reservation_id,
            usage_event_id=command.usage_event_id,
            cost_revision=command.cost_revision,
            state=row[9]["result_state"],
            lease_version=row[5],
            reason_code=command.reason_code,
            redis_replayed=True,
            durable_replayed=True,
            settled_at=row[7],
        )

    def _release_holds(self, cursor, command, snapshot, decision):
        targets = {
            item.budget_bucket: item.amount_microusd
            for item in decision.holds_by_bucket_microusd
        }
        cursor.execute(
            """
            SELECT budget_bucket, current_hold_microusd, current_revision
              FROM commercial_budget_current_holds
             WHERE reservation_id = %s
             ORDER BY budget_bucket
            """,
            (str(snapshot.reservation_id),),
        )
        rows = cursor.fetchall()
        current = {row[0]: (int(row[1]), int(row[2])) for row in rows}
        if not set(current).issubset(targets) or any(
            bucket not in current and int(target) != 0
            for bucket, target in targets.items()
        ):
            raise BudgetSettlementProtocolError(
                "durable and Redis settlement hold buckets diverge"
            )
        for bucket, (amount, revision) in current.items():
            target = int(targets[bucket])
            if target < 0 or target > amount:
                raise BudgetSettlementProtocolError(
                    "durable and Redis settlement hold amounts diverge"
                )
            delta = target - amount
            if delta == 0:
                continue
            cursor.execute(
                """
                INSERT INTO commercial_budget_hold_events (
                    event_id, reservation_id, budget_period_id, budget_bucket,
                    hold_revision, hold_kind, amount_delta_microusd,
                    lease_version, idempotency_key, reason_code, actor_type
                ) VALUES (%s, %s, %s, %s, %s, 'release', %s, %s, %s,
                          'budget.settlement_release', 'service')
                """,
                (
                    str(
                        uuid5(
                            NAMESPACE_URL,
                            f"{self._event_id(snapshot, command)}:hold:{bucket}",
                        )
                    ),
                    str(snapshot.reservation_id),
                    snapshot.budget_period_id,
                    bucket,
                    revision + 1,
                    delta,
                    snapshot.lease_version,
                    f"settlement:{snapshot.source_event_id}:"
                    f"{command.cost_revision}:{bucket}",
                ),
            )

    def _require_idle_connection(self) -> None:
        get_status = getattr(self._connection, "get_transaction_status", None)
        if get_status is None or get_status() != 0:
            raise BudgetSettlementProtocolError(
                "budget settlement protocol requires an idle dedicated PostgreSQL connection"
            )

    @staticmethod
    def _payload_digest(command, snapshot) -> str:
        return canonical_sha256(
            {
                "canonical_cost_payload_sha256": snapshot.settlement_payload_sha256,
                "cost_revision": command.cost_revision,
                "cost_adjustment_id": (
                    str(command.cost_adjustment_id)
                    if command.cost_adjustment_id is not None
                    else None
                ),
                "reason_code": command.reason_code,
                "actor_type": command.actor_type,
                "actor_id": command.actor_id,
                "finalize_reservation": command.finalize_reservation,
                "is_late_child": snapshot.is_late_child,
                "actuals": sorted(
                    (item.budget_bucket, item.amount_microusd)
                    for item in snapshot.actuals
                ),
                "limits": sorted(
                    (item.budget_bucket, item.limit_microusd)
                    for item in snapshot.limits
                ),
            }
        )

    @staticmethod
    def _metadata_matches(metadata, command, settlement_lease_version) -> bool:
        if not isinstance(metadata, dict):
            return False
        result_state = metadata.get("result_state")
        input_lease = metadata.get("redis_input_lease_version")
        if (
            metadata.get("settlement_protocol_version") != 1
            or metadata.get("finalize_reservation") is not command.finalize_reservation
            or type(input_lease) is not int
            or input_lease <= 0
            or int(settlement_lease_version) not in {input_lease, input_lease + 1}
            or result_state not in {"partially_settled", "settled", "overdrawn"}
        ):
            return False
        if command.finalize_reservation:
            return result_state in {"settled", "overdrawn"}
        return result_state in {"partially_settled", "overdrawn"}

    @staticmethod
    def _event_id(snapshot, command):
        return uuid5(
            NAMESPACE_URL,
            f"budget-settlement:{snapshot.reservation_id}:"
            f"{snapshot.source_product}:{snapshot.source_event_id}:"
            f"{command.cost_revision}",
        )
