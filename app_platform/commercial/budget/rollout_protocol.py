"""Audited shadow evaluation and single-pilot enforcement promotion."""

from __future__ import annotations

from datetime import timedelta
import json
from typing import Annotated, Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, StrictStr, model_validator

from ..flags import CommercialFlags
from ..models import StableCode, StrictCommercialModel, canonical_sha256
from .estimator import ReservationEstimate
from .redis_store import MAX_SAFE_REDIS_INTEGER


SafePositiveInt = Annotated[StrictInt, Field(gt=0, le=MAX_SAFE_REDIS_INTEGER)]
SafeNonNegativeInt = Annotated[StrictInt, Field(ge=0, le=MAX_SAFE_REDIS_INTEGER)]
_SLOT_KEY = "initial_pilot"


class BudgetRolloutProtocolError(RuntimeError):
    """Rollout evidence or a guarded transition could not be trusted."""


class BudgetRolloutBindCommand(StrictCommercialModel):
    agreement_terms_id: SafePositiveInt
    environment: Literal["dev", "staging", "prod"]
    idempotency_key: StableCode
    reason_code: StableCode
    actor_id: Annotated[StrictStr, Field(min_length=1, max_length=255)]
    occurred_at: AwareDatetime


class BudgetRolloutObservationCommand(StrictCommercialModel):
    agreement_terms_id: SafePositiveInt
    budget_period_id: SafePositiveInt
    idempotency_key: StableCode
    request_id: Annotated[StrictStr, Field(min_length=1, max_length=255)]
    estimate: ReservationEstimate
    usage_event_id: SafePositiveInt | None = None
    synthetic: StrictBool = False
    synthetic_model_microusd: SafeNonNegativeInt | None = None
    synthetic_technical_microusd: SafeNonNegativeInt | None = None
    occurred_at: AwareDatetime

    @model_validator(mode="after")
    def _synthetic_authority(self):
        supplied = (
            self.synthetic_model_microusd is not None
            and self.synthetic_technical_microusd is not None
        )
        if self.synthetic is not supplied or (self.synthetic and self.usage_event_id):
            raise ValueError("synthetic rollout observations require exact synthetic totals")
        return self


class BudgetRolloutReadinessCommand(StrictCommercialModel):
    agreement_terms_id: SafePositiveInt
    budget_period_id: SafePositiveInt
    idempotency_key: StableCode
    window_start_at: AwareDatetime
    window_end_at: AwareDatetime
    reconciliation_evidence_id: UUID
    actor_id: Annotated[StrictStr, Field(min_length=1, max_length=255)]
    occurred_at: AwareDatetime

    @model_validator(mode="after")
    def _window(self):
        if self.window_end_at <= self.window_start_at:
            raise ValueError("rollout readiness window must be positive")
        return self


class BudgetRolloutTransitionCommand(StrictCommercialModel):
    agreement_terms_id: SafePositiveInt
    mode: Literal["shadow", "enforce", "stopped"]
    idempotency_key: StableCode
    reason_code: StableCode
    actor_id: Annotated[StrictStr, Field(min_length=1, max_length=255)]
    occurred_at: AwareDatetime
    readiness_evidence_id: UUID | None = None
    reconciliation_evidence_id: UUID | None = None

    @model_validator(mode="after")
    def _evidence(self):
        supplied = (
            self.readiness_evidence_id is not None
            and self.reconciliation_evidence_id is not None
        )
        if (self.mode == "enforce") is not supplied:
            raise ValueError("enforcement transition requires readiness and reconciliation")
        return self


class BudgetRolloutObservationResult(StrictCommercialModel):
    observation_id: UUID
    expected_decision: Literal["allow", "block"]
    reason_code: StableCode
    action_code: Literal[
        "record_forecast",
        "operator_alert",
        "lower_cost_or_byok",
        "block_new_hank_work",
    ]
    model_utilization_bps: SafeNonNegativeInt
    technical_utilization_bps: SafeNonNegativeInt
    actual_coverage: Literal["covered", "uncovered", "byok", "not_observed"]
    authorizes_work: Literal[False] = False
    durable_replayed: StrictBool


class BudgetRolloutReadinessResult(StrictCommercialModel):
    evidence_id: UUID
    status: Literal["passed", "failed"]
    observation_count: SafeNonNegativeInt
    eligible_usage_count: SafeNonNegativeInt
    observed_usage_count: SafeNonNegativeInt
    covered_reservation_count: SafeNonNegativeInt
    exact_usage_coverage: StrictBool
    real_shadow_duration_passed: StrictBool
    conflict_count: SafeNonNegativeInt
    threshold_75_passed: StrictBool
    threshold_90_passed: StrictBool
    threshold_100_passed: StrictBool
    durable_replayed: StrictBool


class BudgetRolloutTransitionResult(StrictCommercialModel):
    event_id: UUID
    rollout_revision: SafePositiveInt
    mode: Literal["shadow", "enforce", "stopped"]
    durable_replayed: StrictBool


class BudgetRolloutProtocol:
    """Persist non-authorizing evidence and gate one pilot's promotion."""

    def __init__(self, connection: Any, *, flags: CommercialFlags) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise BudgetRolloutProtocolError("budget rollout requires transactional PostgreSQL")
        if not (
            flags.commercial_control_enabled
            and (
                flags.commercial_budget_shadow_mode
                or flags.commercial_budget_enforcement_enabled
            )
        ):
            raise BudgetRolloutProtocolError("budget rollout controls are disabled")
        self._connection = connection
        self._flags = flags

    def bind_shadow(self, command: BudgetRolloutBindCommand) -> BudgetRolloutTransitionResult:
        command = BudgetRolloutBindCommand.model_validate(command)
        self._require_idle()
        if not self._flags.commercial_budget_shadow_mode:
            raise BudgetRolloutProtocolError("initial rollout binding requires shadow mode")
        if command.environment != self._flags.environment:
            raise BudgetRolloutProtocolError("rollout slot environment does not match runtime")
        digest = self._digest("bind-command.v1", command)
        event_id = self._event_id(command.agreement_terms_id, command.idempotency_key)
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    ("commercial-budget-rollout:initial_pilot",),
                )
                existing = self._load_transition(cursor, command.idempotency_key, digest)
                if existing:
                    self._connection.commit()
                    return existing
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_rollout_slots (
                        slot_key, environment, agreement_terms_id, actor_id,
                        reason_code
                    ) VALUES ('initial_pilot', %s, %s, %s, %s)
                    ON CONFLICT (slot_key) DO NOTHING
                    """,
                    (
                        command.environment,
                        command.agreement_terms_id,
                        command.actor_id,
                        command.reason_code,
                    ),
                )
                cursor.execute(
                    "SELECT environment, agreement_terms_id "
                    "FROM commercial_budget_rollout_slots "
                    "WHERE slot_key = 'initial_pilot' FOR UPDATE"
                )
                slot = cursor.fetchone()
                if slot != (command.environment, command.agreement_terms_id):
                    raise BudgetRolloutProtocolError(
                        "initial pilot slot conflicts with prior binding"
                    )
                self._insert_transition(
                    cursor,
                    event_id=event_id,
                    terms_id=command.agreement_terms_id,
                    revision=1,
                    mode="shadow",
                    idempotency_key=command.idempotency_key,
                    command_sha256=digest,
                    reason_code=command.reason_code,
                    actor_id=command.actor_id,
                    occurred_at=command.occurred_at,
                )
            self._connection.commit()
            return BudgetRolloutTransitionResult(
                event_id=event_id,
                rollout_revision=1,
                mode="shadow",
                durable_replayed=False,
            )
        except Exception:
            self._connection.rollback()
            raise

    def observe(
        self,
        command: BudgetRolloutObservationCommand,
    ) -> BudgetRolloutObservationResult:
        command = BudgetRolloutObservationCommand.model_validate(command)
        self._require_idle()
        digest = self._digest("observation-command.v1", command)
        observation_id = uuid5(
            NAMESPACE_URL,
            f"budget-rollout-observation:{command.agreement_terms_id}:"
            f"{command.idempotency_key}",
        )
        try:
            with self._connection.cursor() as cursor:
                mode, shadow_revision = self._assert_slot(
                    cursor, command.agreement_terms_id
                )
                if mode != "shadow":
                    raise BudgetRolloutProtocolError(
                        "rollout observations require current shadow mode"
                    )
                replay = self._load_observation(cursor, command.idempotency_key, digest)
                if replay:
                    self._connection.commit()
                    return replay
                period = self._load_period(cursor, command)
                current = self._current_totals(cursor, command, period)
                holds = {
                    item.budget_bucket: item.amount_microusd
                    for item in command.estimate.holds_by_bucket_microusd
                }
                after = {
                    bucket: current[bucket] + holds.get(bucket, 0)
                    for bucket in ("model", "technical")
                }
                blocked = (
                    any(after[bucket] > period["limits"][bucket] for bucket in after)
                    or any(amount > period["max_single"] for amount in holds.values())
                    or period["active"] >= period["max_concurrency"]
                )
                utilization = {
                    bucket: (after[bucket] * 10_000) // period["limits"][bucket]
                    for bucket in after
                }
                maximum = max(utilization.values())
                action = self._action(maximum)
                coverage = self._coverage(cursor, command)
                decision = "block" if blocked else "allow"
                reason = "budget.shadow_would_block" if blocked else "budget.shadow_would_allow"
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_rollout_observations (
                        observation_id, slot_key, agreement_terms_id,
                        budget_period_id, shadow_revision, usage_event_id,
                        idempotency_key,
                        command_sha256, estimator_profile_version, workflow_code,
                        request_id, expected_decision, reason_code, action_code,
                        model_current_microusd, technical_current_microusd,
                        model_hold_microusd, technical_hold_microusd,
                        model_limit_microusd, technical_limit_microusd,
                        active_reservations, max_concurrent_reservations,
                        max_single_reservation_microusd,
                        model_utilization_bps, technical_utilization_bps,
                        actual_coverage, synthetic, occurred_at, metadata
                    ) VALUES (%s, 'initial_pilot', %s, %s, %s, %s, %s, %s, %s,
                              %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                              %s, %s, %s, %s, %s, %s, %s, %s, %s,
                              %s::jsonb)
                    """,
                    (
                        str(observation_id),
                        command.agreement_terms_id,
                        command.budget_period_id,
                        shadow_revision,
                        command.usage_event_id,
                        command.idempotency_key,
                        digest,
                        command.estimate.profile_version,
                        command.estimate.workflow_code,
                        command.request_id,
                        decision,
                        reason,
                        action,
                        current["model"],
                        current["technical"],
                        holds.get("model", 0),
                        holds.get("technical", 0),
                        period["limits"]["model"],
                        period["limits"]["technical"],
                        period["active"],
                        period["max_concurrency"],
                        period["max_single"],
                        utilization["model"],
                        utilization["technical"],
                        coverage,
                        command.synthetic,
                        command.occurred_at,
                        json.dumps(
                            {"schema": "commercial.budget.rollout-observation.v1"},
                            separators=(",", ":"),
                        ),
                    ),
                )
            self._connection.commit()
            return BudgetRolloutObservationResult(
                observation_id=observation_id,
                expected_decision=decision,
                reason_code=reason,
                action_code=action,
                model_utilization_bps=utilization["model"],
                technical_utilization_bps=utilization["technical"],
                actual_coverage=coverage,
                durable_replayed=False,
            )
        except Exception:
            self._connection.rollback()
            raise

    def build_readiness(
        self,
        command: BudgetRolloutReadinessCommand,
    ) -> BudgetRolloutReadinessResult:
        command = BudgetRolloutReadinessCommand.model_validate(command)
        self._require_idle()
        digest = self._digest("readiness-command.v1", command)
        evidence_id = uuid5(
            NAMESPACE_URL,
            f"budget-rollout-readiness:{command.agreement_terms_id}:"
            f"{command.idempotency_key}",
        )
        try:
            with self._connection.cursor() as cursor:
                mode, shadow_revision = self._assert_slot(
                    cursor, command.agreement_terms_id
                )
                if mode != "shadow":
                    raise BudgetRolloutProtocolError(
                        "rollout readiness requires current shadow mode"
                    )
                replay = self._load_readiness(cursor, command.idempotency_key, digest)
                if replay:
                    self._connection.commit()
                    return replay
                totals = self._readiness_totals(cursor, command, shadow_revision)
                passed = (
                    command.window_end_at - command.window_start_at >= timedelta(days=14)
                    and totals["observation_count"] >= 100
                    and totals["exact_usage_coverage"]
                    and totals["real_shadow_duration_passed"]
                    and totals["eligible_usage_count"] == totals["observed_usage_count"]
                    and totals["conflict_count"] == 0
                    and totals["threshold_75_passed"]
                    and totals["threshold_90_passed"]
                    and totals["threshold_100_passed"]
                )
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_rollout_readiness_evidence (
                        evidence_id, slot_key, agreement_terms_id, idempotency_key,
                        budget_period_id, shadow_revision, command_sha256,
                        window_start_at, window_end_at,
                        observation_count, eligible_usage_count,
                        observed_usage_count, covered_reservation_count,
                        exact_usage_coverage, real_shadow_duration_passed,
                        conflict_count,
                        threshold_75_passed, threshold_90_passed,
                        threshold_100_passed, reconciliation_evidence_id,
                        status, actor_id, occurred_at, metadata
                    ) VALUES (%s, 'initial_pilot', %s, %s, %s, %s, %s, %s, %s,
                              %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                              %s, %s, %s,
                              %s::jsonb)
                    """,
                    (
                        str(evidence_id),
                        command.agreement_terms_id,
                        command.idempotency_key,
                        command.budget_period_id,
                        shadow_revision,
                        digest,
                        command.window_start_at,
                        command.window_end_at,
                        totals["observation_count"],
                        totals["eligible_usage_count"],
                        totals["observed_usage_count"],
                        totals["covered_reservation_count"],
                        totals["exact_usage_coverage"],
                        totals["real_shadow_duration_passed"],
                        totals["conflict_count"],
                        totals["threshold_75_passed"],
                        totals["threshold_90_passed"],
                        totals["threshold_100_passed"],
                        str(command.reconciliation_evidence_id),
                        "passed" if passed else "failed",
                        command.actor_id,
                        command.occurred_at,
                        json.dumps(
                            {"schema": "commercial.budget.rollout-readiness.v1"},
                            separators=(",", ":"),
                        ),
                    ),
                )
            self._connection.commit()
            return BudgetRolloutReadinessResult(
                evidence_id=evidence_id,
                status="passed" if passed else "failed",
                durable_replayed=False,
                **totals,
            )
        except Exception:
            self._connection.rollback()
            raise

    def transition(
        self,
        command: BudgetRolloutTransitionCommand,
    ) -> BudgetRolloutTransitionResult:
        command = BudgetRolloutTransitionCommand.model_validate(command)
        self._require_idle()
        if command.mode == "enforce" and not (
            self._flags.commercial_budget_enforcement_enabled
            and self._flags.commercial_budget_rollout_guard_enabled
        ):
            raise BudgetRolloutProtocolError("enforcement promotion requires rollout guard")
        digest = self._digest("transition-command.v1", command)
        event_id = self._event_id(command.agreement_terms_id, command.idempotency_key)
        try:
            with self._connection.cursor() as cursor:
                self._assert_slot(cursor, command.agreement_terms_id, for_update=True)
                replay = self._load_transition(cursor, command.idempotency_key, digest)
                if replay:
                    self._connection.commit()
                    return replay
                cursor.execute(
                    "SELECT COALESCE(MAX(rollout_revision), 0) "
                    "FROM commercial_budget_rollout_events WHERE slot_key = %s",
                    (_SLOT_KEY,),
                )
                revision = int(cursor.fetchone()[0]) + 1
                self._insert_transition(
                    cursor,
                    event_id=event_id,
                    terms_id=command.agreement_terms_id,
                    revision=revision,
                    mode=command.mode,
                    idempotency_key=command.idempotency_key,
                    command_sha256=digest,
                    reason_code=command.reason_code,
                    actor_id=command.actor_id,
                    occurred_at=command.occurred_at,
                    readiness_evidence_id=command.readiness_evidence_id,
                    reconciliation_evidence_id=command.reconciliation_evidence_id,
                )
            self._connection.commit()
            return BudgetRolloutTransitionResult(
                event_id=event_id,
                rollout_revision=revision,
                mode=command.mode,
                durable_replayed=False,
            )
        except Exception:
            self._connection.rollback()
            raise

    def _assert_slot(
        self, cursor, terms_id: int, *, for_update: bool = False
    ) -> tuple[str, int]:
        cursor.execute(
            """
            SELECT current.mode, current.rollout_revision, slot.environment
              FROM commercial_budget_rollout_slots slot
              JOIN LATERAL (
                  SELECT event.mode, event.rollout_revision
                    FROM commercial_budget_rollout_events event
                   WHERE event.slot_key = slot.slot_key
                   ORDER BY event.rollout_revision DESC LIMIT 1
              ) current ON TRUE
             WHERE slot.slot_key = 'initial_pilot'
               AND slot.agreement_terms_id = %s
            """ + (" FOR UPDATE OF slot" if for_update else " FOR SHARE OF slot"),
            (terms_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise BudgetRolloutProtocolError("agreement terms are not the initial pilot")
        if row[2] != self._flags.environment:
            raise BudgetRolloutProtocolError("rollout slot environment does not match runtime")
        return row[0], int(row[1])

    @staticmethod
    def _load_period(cursor, command):
        cursor.execute(
            """
            SELECT model_limit_microusd, technical_limit_microusd,
                   max_single_reservation_microusd, max_concurrent_reservations,
                   (SELECT COUNT(*) FROM commercial_budget_reservations reservation
                     WHERE reservation.budget_period_id = period.id
                       AND (
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
                       )), state, period_start_at, period_end_at
              FROM commercial_budget_periods period
             WHERE id = %s AND agreement_terms_id = %s
             FOR SHARE OF period
            """,
            (command.budget_period_id, command.agreement_terms_id),
        )
        row = cursor.fetchone()
        if row is None:
            raise BudgetRolloutProtocolError("rollout period lineage is invalid")
        if (
            row[5] not in {"open", "soft_limited"}
            or command.occurred_at < row[6]
            or command.occurred_at >= row[7]
        ):
            raise BudgetRolloutProtocolError(
                "rollout observation is outside the active budget period"
            )
        return {
            "limits": {"model": int(row[0]), "technical": int(row[1])},
            "max_single": int(row[2]),
            "max_concurrency": int(row[3]),
            "active": int(row[4]),
        }

    @staticmethod
    def _current_totals(cursor, command, period):
        if command.synthetic:
            return {
                "model": command.synthetic_model_microusd,
                "technical": command.synthetic_technical_microusd,
            }
        cursor.execute(
            """
            WITH initial_buckets AS (
                SELECT DISTINCT reservation_id, budget_bucket
                  FROM commercial_budget_hold_events
                 WHERE budget_period_id = %s AND hold_revision = 0
                   AND hold_kind = 'reserve'
            ), actuals AS (
                SELECT initial.budget_bucket,
                       COALESCE(SUM(settlement.amount_delta_microusd), 0)::BIGINT amount
                  FROM initial_buckets initial
                  LEFT JOIN commercial_budget_settlements settlement
                    ON settlement.reservation_id = initial.reservation_id
                 GROUP BY initial.budget_bucket
            ), holds AS (
                SELECT budget_bucket, COALESCE(SUM(current_hold_microusd), 0)::BIGINT amount
                  FROM commercial_budget_current_holds
                 WHERE budget_period_id = %s GROUP BY budget_bucket
            )
            SELECT bucket.name,
                   COALESCE(actuals.amount, 0) + COALESCE(holds.amount, 0)
              FROM (VALUES ('model'), ('technical')) bucket(name)
              LEFT JOIN actuals ON actuals.budget_bucket = bucket.name
              LEFT JOIN holds ON holds.budget_bucket = bucket.name
             ORDER BY bucket.name
            """,
            (command.budget_period_id, command.budget_period_id),
        )
        totals = {bucket: int(amount) for bucket, amount in cursor.fetchall()}
        if any(value < 0 or value > MAX_SAFE_REDIS_INTEGER for value in totals.values()):
            raise BudgetRolloutProtocolError("rollout durable totals are unsafe")
        return totals

    @staticmethod
    def _coverage(cursor, command):
        if command.usage_event_id is None:
            return "not_observed"
        cursor.execute(
            """
            SELECT context.agreement_terms_id, usage.payer_class, usage.reservation_id
              FROM commercial_usage_events usage
              JOIN commercial_execution_contexts context
                ON context.id = usage.execution_context_id
             WHERE usage.id = %s FOR SHARE OF usage, context
            """,
            (command.usage_event_id,),
        )
        row = cursor.fetchone()
        if row is None or int(row[0]) != command.agreement_terms_id:
            raise BudgetRolloutProtocolError("rollout usage lineage is invalid")
        if row[1] == "customer_paid":
            return "byok"
        return "covered" if row[2] is not None else "uncovered"

    @staticmethod
    def _action(utilization_bps: int) -> str:
        if utilization_bps >= 10_000:
            return "block_new_hank_work"
        if utilization_bps >= 9_000:
            return "lower_cost_or_byok"
        if utilization_bps >= 7_500:
            return "operator_alert"
        return "record_forecast"

    @staticmethod
    def _readiness_totals(cursor, command, shadow_revision):
        cursor.execute(
            """
            SELECT period_start_at, period_end_at
              FROM commercial_budget_periods
             WHERE id = %s AND agreement_terms_id = %s
             FOR UPDATE
            """,
            (command.budget_period_id, command.agreement_terms_id),
        )
        period = cursor.fetchone()
        if (
            period is None
            or command.window_start_at < period[0]
            or command.window_end_at > period[1]
        ):
            raise BudgetRolloutProtocolError(
                "rollout readiness window is outside its budget period"
            )
        cursor.execute(
            """
            SELECT COUNT(*)::BIGINT,
                   COUNT(DISTINCT usage_event_id)
                       FILTER (WHERE actual_coverage IN ('covered', 'uncovered'))::BIGINT,
                   COUNT(DISTINCT usage_event_id)
                       FILTER (WHERE actual_coverage = 'covered')::BIGINT,
                   COALESCE(BOOL_OR(GREATEST(model_utilization_bps,
                       technical_utilization_bps) BETWEEN 7500 AND 8999
                       AND action_code = 'operator_alert'), FALSE),
                   COALESCE(BOOL_OR(GREATEST(model_utilization_bps,
                       technical_utilization_bps) BETWEEN 9000 AND 9999
                       AND action_code = 'lower_cost_or_byok'), FALSE),
                   COALESCE(BOOL_OR(GREATEST(model_utilization_bps,
                       technical_utilization_bps) >= 10000
                       AND action_code = 'block_new_hank_work'
                       AND expected_decision = 'block'), FALSE)
             FROM commercial_budget_rollout_observations
             WHERE slot_key = 'initial_pilot' AND agreement_terms_id = %s
               AND budget_period_id = %s
               AND shadow_revision = %s
               AND occurred_at >= %s AND occurred_at < %s
            """,
            (
                command.agreement_terms_id,
                command.budget_period_id,
                shadow_revision,
                command.window_start_at,
                command.window_end_at,
            ),
        )
        observation = cursor.fetchone()
        cursor.execute(
            """
            SELECT COUNT(*)::BIGINT
              FROM commercial_usage_events usage
              JOIN commercial_execution_contexts context
                ON context.id = usage.execution_context_id
              JOIN commercial_budget_periods period
                ON period.id = %s
               AND usage.occurred_at >= period.period_start_at
               AND usage.occurred_at < period.period_end_at
             WHERE context.agreement_terms_id = %s
               AND usage.occurred_at >= %s AND usage.occurred_at < %s
               AND usage.payer_class = 'hank_paid'
               AND usage.usage_state IN ('succeeded', 'failed_billable')
            """,
            (
                command.budget_period_id,
                command.agreement_terms_id,
                command.window_start_at,
                command.window_end_at,
            ),
        )
        eligible = int(cursor.fetchone()[0])
        cursor.execute(
            """
            SELECT NOT EXISTS (
                (
                    SELECT usage.id
                      FROM commercial_usage_events usage
                      JOIN commercial_execution_contexts context
                        ON context.id = usage.execution_context_id
                      JOIN commercial_budget_periods period
                        ON period.id = %s
                       AND usage.occurred_at >= period.period_start_at
                       AND usage.occurred_at < period.period_end_at
                     WHERE context.agreement_terms_id = %s
                       AND usage.occurred_at >= %s AND usage.occurred_at < %s
                       AND usage.payer_class = 'hank_paid'
                       AND usage.usage_state IN ('succeeded', 'failed_billable')
                    EXCEPT
                    SELECT observation.usage_event_id
                      FROM commercial_budget_rollout_observations observation
                     WHERE observation.slot_key = 'initial_pilot'
                       AND observation.agreement_terms_id = %s
                       AND observation.budget_period_id = %s
                       AND observation.shadow_revision = %s
                       AND observation.occurred_at >= %s
                       AND observation.occurred_at < %s
                       AND observation.actual_coverage IN ('covered', 'uncovered')
                ) UNION ALL (
                    SELECT observation.usage_event_id
                      FROM commercial_budget_rollout_observations observation
                     WHERE observation.slot_key = 'initial_pilot'
                       AND observation.agreement_terms_id = %s
                       AND observation.budget_period_id = %s
                       AND observation.shadow_revision = %s
                       AND observation.occurred_at >= %s
                       AND observation.occurred_at < %s
                       AND observation.actual_coverage IN ('covered', 'uncovered')
                    EXCEPT
                    SELECT usage.id
                      FROM commercial_usage_events usage
                      JOIN commercial_execution_contexts context
                        ON context.id = usage.execution_context_id
                      JOIN commercial_budget_periods period
                        ON period.id = %s
                       AND usage.occurred_at >= period.period_start_at
                       AND usage.occurred_at < period.period_end_at
                     WHERE context.agreement_terms_id = %s
                       AND usage.occurred_at >= %s AND usage.occurred_at < %s
                       AND usage.payer_class = 'hank_paid'
                       AND usage.usage_state IN ('succeeded', 'failed_billable')
                )
            )
            """,
            (
                command.budget_period_id,
                command.agreement_terms_id,
                command.window_start_at,
                command.window_end_at,
                command.agreement_terms_id,
                command.budget_period_id,
                shadow_revision,
                command.window_start_at,
                command.window_end_at,
                command.agreement_terms_id,
                command.budget_period_id,
                shadow_revision,
                command.window_start_at,
                command.window_end_at,
                command.budget_period_id,
                command.agreement_terms_id,
                command.window_start_at,
                command.window_end_at,
            ),
        )
        exact_usage_coverage = bool(cursor.fetchone()[0])
        cursor.execute(
            """
            SELECT COUNT(*)::BIGINT
              FROM commercial_usage_ingest_conflicts conflict
              JOIN commercial_usage_events usage
                ON usage.id = conflict.canonical_usage_event_id
              JOIN commercial_execution_contexts context
                ON context.id = usage.execution_context_id
              JOIN commercial_budget_periods period
                ON period.id = %s
               AND usage.occurred_at >= period.period_start_at
               AND usage.occurred_at < period.period_end_at
             WHERE context.agreement_terms_id = %s
               AND usage.occurred_at >= %s AND usage.occurred_at < %s
               AND conflict.received_at <= commercial_budget_rollout_clock()
            """,
            (
                command.budget_period_id,
                command.agreement_terms_id,
                command.window_start_at,
                command.window_end_at,
            ),
        )
        conflict_count = int(cursor.fetchone()[0])
        cursor.execute(
            """
            SELECT commercial_budget_rollout_clock() >=
                   event.recorded_at + INTERVAL '14 days'
             FROM commercial_budget_rollout_events event
             WHERE event.slot_key = 'initial_pilot' AND event.mode = 'shadow'
               AND event.rollout_revision = %s
             FOR SHARE
            """,
            (shadow_revision,),
        )
        duration_row = cursor.fetchone()
        return {
            "observation_count": int(observation[0]),
            "eligible_usage_count": eligible,
            "observed_usage_count": int(observation[1]),
            "covered_reservation_count": int(observation[2]),
            "exact_usage_coverage": exact_usage_coverage,
            "real_shadow_duration_passed": bool(duration_row and duration_row[0]),
            "conflict_count": conflict_count,
            "threshold_75_passed": bool(observation[3]),
            "threshold_90_passed": bool(observation[4]),
            "threshold_100_passed": bool(observation[5]),
        }

    @staticmethod
    def _insert_transition(
        cursor,
        *,
        event_id,
        terms_id,
        revision,
        mode,
        idempotency_key,
        command_sha256,
        reason_code,
        actor_id,
        occurred_at,
        readiness_evidence_id=None,
        reconciliation_evidence_id=None,
    ):
        cursor.execute(
            """
            INSERT INTO commercial_budget_rollout_events (
                event_id, slot_key, agreement_terms_id, rollout_revision,
                mode, readiness_evidence_id, reconciliation_evidence_id,
                idempotency_key, command_sha256, reason_code, actor_id,
                occurred_at
            ) VALUES (%s, 'initial_pilot', %s, %s, %s, %s, %s, %s, %s,
                      %s, %s, %s)
            """,
            (
                str(event_id),
                terms_id,
                revision,
                mode,
                str(readiness_evidence_id) if readiness_evidence_id else None,
                str(reconciliation_evidence_id) if reconciliation_evidence_id else None,
                idempotency_key,
                command_sha256,
                reason_code,
                actor_id,
                occurred_at,
            ),
        )

    @staticmethod
    def _load_transition(cursor, key, digest):
        cursor.execute(
            "SELECT event_id, rollout_revision, mode, command_sha256 "
            "FROM commercial_budget_rollout_events "
            "WHERE slot_key = 'initial_pilot' AND idempotency_key = %s",
            (key,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        if row[3] != digest:
            raise BudgetRolloutProtocolError("rollout transition replay conflicts")
        return BudgetRolloutTransitionResult(
            event_id=row[0], rollout_revision=row[1], mode=row[2], durable_replayed=True
        )

    @staticmethod
    def _load_observation(cursor, key, digest):
        cursor.execute(
            """
            SELECT observation_id, expected_decision, reason_code, action_code,
                   model_utilization_bps, technical_utilization_bps,
                   actual_coverage, command_sha256
              FROM commercial_budget_rollout_observations
             WHERE slot_key = 'initial_pilot' AND idempotency_key = %s
            """,
            (key,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        if row[7] != digest:
            raise BudgetRolloutProtocolError("rollout observation replay conflicts")
        return BudgetRolloutObservationResult(
            observation_id=row[0],
            expected_decision=row[1],
            reason_code=row[2],
            action_code=row[3],
            model_utilization_bps=row[4],
            technical_utilization_bps=row[5],
            actual_coverage=row[6],
            durable_replayed=True,
        )

    @staticmethod
    def _load_readiness(cursor, key, digest):
        cursor.execute(
            """
            SELECT evidence_id, status, observation_count, eligible_usage_count,
                   observed_usage_count, covered_reservation_count,
                   exact_usage_coverage, real_shadow_duration_passed,
                   conflict_count,
                   threshold_75_passed, threshold_90_passed,
                   threshold_100_passed, command_sha256
              FROM commercial_budget_rollout_readiness_evidence
             WHERE slot_key = 'initial_pilot' AND idempotency_key = %s
            """,
            (key,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        if row[12] != digest:
            raise BudgetRolloutProtocolError("rollout readiness replay conflicts")
        return BudgetRolloutReadinessResult(
            evidence_id=row[0],
            status=row[1],
            observation_count=row[2],
            eligible_usage_count=row[3],
            observed_usage_count=row[4],
            covered_reservation_count=row[5],
            exact_usage_coverage=row[6],
            real_shadow_duration_passed=row[7],
            conflict_count=row[8],
            threshold_75_passed=row[9],
            threshold_90_passed=row[10],
            threshold_100_passed=row[11],
            durable_replayed=True,
        )

    @staticmethod
    def _digest(schema, command):
        return canonical_sha256(
            {"schema": f"commercial.budget.rollout-{schema}", "command": command.model_dump(mode="python")}
        )

    @staticmethod
    def _event_id(terms_id, key):
        return uuid5(NAMESPACE_URL, f"budget-rollout:{terms_id}:{key}")

    def _require_idle(self):
        reader = getattr(self._connection, "get_transaction_status", None)
        if reader is not None and reader() != 0:
            raise BudgetRolloutProtocolError("budget rollout requires an idle connection")
