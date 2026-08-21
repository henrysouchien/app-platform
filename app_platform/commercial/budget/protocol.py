"""Recoverable PostgreSQL/Redis protocol for commercial budget reservations."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, StrictInt, model_validator

from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .estimator import ReservationEstimate
from .redis_store import (
    BucketLimit,
    CommercialReservationRedisError,
    CommercialReservationRedisStore,
    ReservationRedisCommand,
)


PositiveInt = Annotated[StrictInt, Field(gt=0)]
_REDIS_REPAIR_GRACE_SECONDS = 86_400
_MAX_REDIS_TTL_SECONDS = 31_536_000


class BudgetReservationProtocolError(RuntimeError):
    """Reservation cannot safely authorize provider work."""


class _PostgresCommitOutcomeUnknown(RuntimeError):
    pass


class BudgetReservationCommand(StrictCommercialModel):
    reservation_id: UUID
    idempotency_key: StableCode
    request_payload_sha256: Sha256Digest
    budget_period_id: PositiveInt
    agreement_terms_id: PositiveInt
    execution_context_id: UUID
    workflow_run_id: UUID | None = None
    request_id: StableCode
    estimate: ReservationEstimate
    lease_token: UUID
    lease_version: PositiveInt = 1
    redis_generation: PositiveInt
    authorized_work_start_deadline: AwareDatetime
    expires_at: AwareDatetime
    late_child_accept_until: AwareDatetime

    @model_validator(mode="after")
    def _time_and_estimate_invariants(self) -> "BudgetReservationCommand":
        if not (
            self.authorized_work_start_deadline
            <= self.expires_at
            <= self.late_child_accept_until
        ):
            raise ValueError("reservation authorization windows are invalid")
        holds = {
            hold.budget_bucket: hold.amount_microusd
            for hold in self.estimate.holds_by_bucket_microusd
        }
        if "technical" not in holds or any(amount <= 0 for amount in holds.values()):
            raise ValueError("reservation estimate requires a positive technical hold")
        if not set(holds).issubset({"model", "technical"}):
            raise ValueError(
                "this protocol version supports only model and technical buckets"
            )
        return self


class BudgetReservationResult(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: StableCode
    reservation_id: UUID
    state: Literal["reserved", "released"]
    lease_version: PositiveInt
    redis_generation: PositiveInt | None
    replayed: bool


class BudgetReservationProtocol:
    """Authorize work only after the durable journal and Redis agree."""

    def __init__(
        self,
        connection: Any,
        redis_store: CommercialReservationRedisStore,
        *,
        flags: CommercialFlags,
        clock,
    ) -> None:
        flags.validate()
        if bool(getattr(connection, "autocommit", False)):
            raise BudgetReservationProtocolError(
                "budget reservation protocol requires transactional PostgreSQL"
            )
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
        ):
            raise BudgetReservationProtocolError(
                "budget reservation protocol requires enforcement mode"
            )
        self._connection = connection
        self._redis = redis_store
        self._flags = flags
        self._clock = clock

    def reserve(self, command: BudgetReservationCommand) -> BudgetReservationResult:
        self._assert_idle_connection()
        now = self._clock()
        existing, pending_existed = self._ensure_pending(command, now=now)
        if existing is not None:
            if existing.decision == "block":
                return existing
            if now > command.authorized_work_start_deadline:
                return existing.model_copy(
                    update={
                        "decision": "block",
                        "reason_code": "budget.work_start_expired",
                    }
                )
            try:
                redis_replay = self._reserve_in_redis(command)
            except CommercialReservationRedisError as error:
                raise BudgetReservationProtocolError(
                    "durable reserved replay cannot verify Redis authority"
                ) from error
            if redis_replay.decision != "allow" or not redis_replay.replayed:
                raise BudgetReservationProtocolError(
                    "durable reserved replay lacks matching Redis authority"
                )
            return existing

        if now > command.authorized_work_start_deadline:
            if pending_existed:
                return self._expire_pending(command)
            raise BudgetReservationProtocolError(
                "reservation work-start authorization has expired"
            )

        redis_command = self._redis_command(command)
        try:
            redis_decision = self._reserve_in_redis(
                command, redis_command=redis_command
            )
        except CommercialReservationRedisError as error:
            raise BudgetReservationProtocolError(
                "Redis reserve is unavailable; provider work is not authorized"
            ) from error

        if redis_decision.decision == "block":
            try:
                return self._record_block(
                    command, reason_code=redis_decision.reason_code
                )
            except BudgetReservationProtocolError:
                self._rollback_best_effort()
                raise
            except Exception as error:
                self._rollback_best_effort()
                raise BudgetReservationProtocolError(
                    "Redis block could not be durably journaled"
                ) from error

        try:
            return self._record_reserved(
                command, now=now, replayed=redis_decision.replayed
            )
        except _PostgresCommitOutcomeUnknown as outcome_error:
            self._rollback_best_effort()
            raise BudgetReservationProtocolError(
                "PostgreSQL reservation commit outcome is unknown; Redis hold is retained "
                "for reconciliation and provider work is not authorized"
            ) from outcome_error
        except Exception as finalize_error:
            self._rollback_best_effort()
            compensation = self._compensation_command(command, redis_command)
            try:
                compensated = self._compensate_pending(
                    command,
                    compensation=compensation,
                    finalize_error=finalize_error,
                )
            except Exception as compensation_error:
                self._rollback_best_effort()
                raise BudgetReservationProtocolError(
                    "PostgreSQL finalization and Redis compensation both failed; "
                    "reservation remains pending for repair"
                ) from compensation_error
            if not compensated:
                raise BudgetReservationProtocolError(
                    "PostgreSQL finalization lost exact pending ownership; Redis hold "
                    "is retained for reconciliation"
                ) from finalize_error
            raise BudgetReservationProtocolError(
                "PostgreSQL finalization failed; Redis reservation was compensated"
            ) from finalize_error

    def abandon(
        self,
        command: BudgetReservationCommand,
        *,
        reason_code: StableCode = "budget.abandoned_before_work",
    ) -> BudgetReservationResult:
        """Idempotently release a committed reservation before work is exposed."""

        self._assert_idle_connection()
        redis_command = self._redis_command(command, recovery=True)
        compensation = self._compensation_command(command, redis_command)
        try:
            with self._connection.cursor() as cursor:
                self._lock_command(cursor, command)
                cursor.execute(
                    """
                    SELECT state, request_payload_sha256, lease_token, lease_version,
                           redis_generation, workflow_run_id, execution_context_id
                      FROM commercial_budget_reservations
                     WHERE id = %s AND idempotency_key = %s
                     FOR UPDATE
                    """,
                    (str(command.reservation_id), command.idempotency_key),
                )
                row = cursor.fetchone()
                if row is None:
                    self._commit()
                    return BudgetReservationResult(
                        decision="block",
                        reason_code=reason_code,
                        reservation_id=command.reservation_id,
                        state="released",
                        lease_version=command.lease_version,
                        redis_generation=None,
                        replayed=False,
                    )
                (
                    state,
                    digest,
                    lease_token,
                    lease_version,
                    generation,
                    workflow_run_id,
                    execution_context_id,
                ) = row
                if (
                    digest != self._authority_sha256(command)
                    or UUID(str(lease_token)) != command.lease_token
                    or (
                        generation is not None
                        and int(generation) != command.redis_generation
                    )
                ):
                    raise BudgetReservationProtocolError(
                        "reservation abandonment identity differs"
                    )
                if state == "released":
                    released_lease_version = int(lease_version)
                    cursor.execute(
                        """
                        SELECT 1 FROM commercial_budget_events
                         WHERE reservation_id = %s AND event_kind = 'release'
                           AND reason_code = %s AND lease_version = %s
                        """,
                        (
                            str(command.reservation_id),
                            reason_code,
                            released_lease_version,
                        ),
                    )
                    if cursor.fetchone() is None:
                        raise BudgetReservationProtocolError(
                            "released reservation has different abandonment evidence"
                        )
                    self._commit()
                    return BudgetReservationResult(
                        decision="block",
                        reason_code=reason_code,
                        reservation_id=command.reservation_id,
                        state="released",
                        lease_version=released_lease_version,
                        redis_generation=None,
                        replayed=True,
                    )
                expected_lease_version = (
                    command.lease_version
                    if state == "pending"
                    else self._committed_lease_version(command)
                )
                if state not in {"pending", "reserved"} or (
                    int(lease_version) != expected_lease_version
                ):
                    raise BudgetReservationProtocolError(
                        "only an unstarted reserved workflow may be abandoned"
                    )
                cursor.execute(
                    """
                    SELECT 1 FROM commercial_usage_events
                     WHERE reservation_id = %s LIMIT 1
                    """,
                    (str(command.reservation_id),),
                )
                if cursor.fetchone() is not None:
                    raise BudgetReservationProtocolError(
                        "reservation with accepted usage cannot be abandoned"
                    )
                self._assert_workflow_unexposed(
                    cursor,
                    workflow_run_id=workflow_run_id,
                    execution_context_id=execution_context_id,
                    reservation_id=command.reservation_id,
                )
                released = self._redis.release(
                    agreement_terms_id=command.agreement_terms_id,
                    period_id=command.budget_period_id,
                    command=compensation,
                )
                if released.decision != "allow" and not (
                    state == "pending"
                    and released.reason_code == "budget.reservation_missing"
                ):
                    raise BudgetReservationProtocolError(
                        "Redis reservation abandonment was rejected"
                    )
                occurred_at = self._clock()
                if state == "pending":
                    self._transition_pending_to_released(
                        command,
                        reason_code=reason_code,
                        occurred_at=occurred_at,
                    )
                    self._mark_workflow_abandoned(
                        cursor,
                        workflow_run_id=workflow_run_id,
                        execution_context_id=execution_context_id,
                        occurred_at=occurred_at,
                    )
                    self._commit()
                    return BudgetReservationResult(
                        decision="block",
                        reason_code=reason_code,
                        reservation_id=command.reservation_id,
                        state="released",
                        lease_version=self._committed_lease_version(command),
                        redis_generation=None,
                        replayed=False,
                    )
                released_lease_version = self._committed_lease_version(command) + 1
                self._release_durable_holds(
                    cursor,
                    command,
                    reason_code=reason_code,
                    occurred_at=occurred_at,
                    lease_version=self._committed_lease_version(command),
                )
                cursor.execute(
                    """
                    UPDATE commercial_budget_reservations
                       SET state = 'released', settled_at = %s,
                           lease_version = %s,
                           heartbeat_at = heartbeat_at + INTERVAL '1 microsecond'
                     WHERE id = %s AND state = 'reserved'
                       AND lease_version = %s
                    """,
                    (
                        occurred_at,
                        released_lease_version,
                        str(command.reservation_id),
                        self._committed_lease_version(command),
                    ),
                )
                if cursor.rowcount != 1:
                    raise BudgetReservationProtocolError(
                        "reservation abandonment lost its durable fence"
                    )
                self._mark_workflow_abandoned(
                    cursor,
                    workflow_run_id=workflow_run_id,
                    execution_context_id=execution_context_id,
                    occurred_at=occurred_at,
                )
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_events (
                        event_id, budget_period_id, reservation_id, event_kind,
                        amount_microusd, lease_version, reason_code, occurred_at
                    ) VALUES (%s, %s, %s, 'release', 0, %s, %s, %s)
                    """,
                    (
                        str(self._event_id(command.reservation_id, "release", reason_code)),
                        command.budget_period_id,
                        str(command.reservation_id),
                        released_lease_version,
                        reason_code,
                        occurred_at,
                    ),
                )
            self._commit()
        except CommercialReservationRedisError as error:
            self._rollback_best_effort()
            raise BudgetReservationProtocolError(
                "Redis reservation abandonment is unavailable; hold requires repair"
            ) from error
        except Exception:
            self._rollback_best_effort()
            raise
        return BudgetReservationResult(
            decision="block",
            reason_code=reason_code,
            reservation_id=command.reservation_id,
            state="released",
            lease_version=self._committed_lease_version(command) + 1,
            redis_generation=None,
            replayed=False,
        )

    @staticmethod
    def _assert_workflow_unexposed(
        cursor,
        *,
        workflow_run_id,
        execution_context_id,
        reservation_id,
    ) -> None:
        if workflow_run_id is None:
            return
        cursor.execute(
            """
            SELECT workflow.state, workflow.execution_context_id,
                   lineage.source_product
              FROM commercial_workflow_runs workflow
              JOIN commercial_workflow_attempt_lineage lineage
                ON lineage.workflow_run_id = workflow.id
               AND lineage.execution_context_id = workflow.execution_context_id
             WHERE workflow.id = %s
             FOR UPDATE OF workflow, lineage
            """,
            (str(workflow_run_id),),
        )
        workflow = cursor.fetchone()
        if workflow is None or (
            workflow[0] != "started"
            or UUID(str(workflow[1])) != UUID(str(execution_context_id))
            or workflow[2] != "hank-agent-gateway"
        ):
            raise BudgetReservationProtocolError(
                "only an unexposed started gateway workflow may be abandoned"
            )
        cursor.execute(
            "SELECT to_regclass('commercial_work_start_authorizations')"
        )
        if cursor.fetchone()[0] is None:
            raise BudgetReservationProtocolError(
                "work authorization evidence is unavailable for abandonment"
            )
        cursor.execute(
            """
            SELECT 1 FROM commercial_work_start_authorizations
             WHERE workflow_run_id = %s OR reservation_id = %s LIMIT 1
            """,
            (str(workflow_run_id), str(reservation_id)),
        )
        if cursor.fetchone() is not None:
            raise BudgetReservationProtocolError(
                "work-authorized reservation cannot be abandoned"
            )

    @staticmethod
    def _mark_workflow_abandoned(
        cursor,
        *,
        workflow_run_id,
        execution_context_id,
        occurred_at,
    ) -> None:
        if workflow_run_id is None:
            return
        cursor.execute(
            """
            UPDATE commercial_workflow_runs
               SET state = 'abandoned', completed_at = %s,
                   artifact_count = 0, success_evidence = '{}'::jsonb
             WHERE id = %s AND execution_context_id = %s AND state = 'started'
            """,
            (occurred_at, str(workflow_run_id), str(execution_context_id)),
        )
        if cursor.rowcount != 1:
            raise BudgetReservationProtocolError(
                "workflow abandonment lost its durable state"
            )

    def _ensure_pending(
        self, command: BudgetReservationCommand, *, now: datetime
    ) -> tuple[BudgetReservationResult | None, bool]:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"budget:idempotency:{command.idempotency_key}",),
                )
                cursor.execute(
                    """
                    SELECT id, request_payload_sha256, budget_period_id,
                           agreement_terms_id, execution_context_id,
                           workflow_run_id, request_id, estimator_profile_version,
                           estimated_cost_microusd, lease_token, lease_version,
                           redis_generation, state,
                           authorized_work_start_deadline, expires_at,
                           late_child_accept_until
                      FROM commercial_budget_reservations
                     WHERE idempotency_key = %s
                     FOR UPDATE
                    """,
                    (command.idempotency_key,),
                )
                row = cursor.fetchone()
                if row is not None:
                    result = self._classify_existing(cursor, command, row)
                    self._commit()
                    return result, True
                if now > command.authorized_work_start_deadline:
                    raise BudgetReservationProtocolError(
                        "reservation work-start authorization has expired"
                    )
                period = self._load_period(cursor, command, now=now)
                hold_map = self._hold_map(command)
                estimated_cost = hold_map["technical"]
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_reservations (
                        id, idempotency_key, request_payload_sha256,
                        budget_period_id, agreement_terms_id, execution_context_id,
                        workflow_run_id, request_id, estimator_profile_version,
                        estimated_cost_microusd, lease_token, lease_version, state,
                        authorized_work_start_deadline, expires_at,
                        late_child_accept_until, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                              'pending', %s, %s, %s, %s)
                    """,
                    (
                        str(command.reservation_id),
                        command.idempotency_key,
                        self._authority_sha256(command),
                        command.budget_period_id,
                        command.agreement_terms_id,
                        str(command.execution_context_id),
                        str(command.workflow_run_id)
                        if command.workflow_run_id
                        else None,
                        command.request_id,
                        command.estimate.profile_version,
                        estimated_cost,
                        str(command.lease_token),
                        command.lease_version,
                        command.authorized_work_start_deadline,
                        command.expires_at,
                        command.late_child_accept_until,
                        now,
                    ),
                )
                for bucket, amount in sorted(hold_map.items()):
                    if bucket not in period["limits"]:
                        raise BudgetReservationProtocolError(
                            f"budget period has no limit for bucket {bucket}"
                        )
                    self._record_initial_hold(
                        cursor, command, budget_bucket=bucket, amount=amount
                    )
            self._commit()
            return None, False
        except Exception:
            self._rollback_best_effort()
            raise

    def _load_period(self, cursor, command, *, now, recovery: bool = False):
        if self._flags.commercial_budget_rollout_guard_enabled and not recovery:
            self._require_rollout_enforcement(cursor, command)
        if command.workflow_run_id is not None:
            cursor.execute(
                """
                SELECT workflow_code, execution_context_id
                  FROM commercial_workflow_runs
                 WHERE id = %s
                 FOR SHARE
                """,
                (str(command.workflow_run_id),),
            )
            workflow_row = cursor.fetchone()
            if workflow_row is None or (
                workflow_row[0] != command.estimate.workflow_code
                or UUID(str(workflow_row[1])) != command.execution_context_id
            ):
                raise BudgetReservationProtocolError(
                    "reservation estimator profile does not match durable workflow"
                )
        cursor.execute(
            """
            SELECT period.agreement_terms_id, period.budget_policy_id,
                   period.model_limit_microusd, period.technical_limit_microusd,
                   period.max_concurrent_reservations, period.state,
                   context.budget_policy_id, context.status,
                   context.authorized_work_start_deadline,
                   context.usage_accept_until, period.period_start_at,
                   period.period_end_at, period.max_single_reservation_microusd,
                   period.top_up_quantum_microusd,
                   period.max_unreserved_delta_microusd,
                   period.late_child_allowance_microusd,
                   period.max_period_overdraft_microusd,
                   COALESCE(
                       (to_jsonb(period)->>'redis_generation')::BIGINT,
                       1
                   ) AS redis_generation,
                   NOT EXISTS (
                       SELECT 1
                         FROM commercial_budget_reservations existing
                        WHERE existing.budget_period_id = period.id
                          AND existing.state <> 'pending'
                   )
                   AND NOT EXISTS (
                       SELECT 1
                         FROM commercial_budget_events event
                        WHERE event.budget_period_id = period.id
                   ) AS generation_bootstrap_allowed
              FROM commercial_budget_periods period
              JOIN commercial_execution_contexts context
                ON context.id = %s
               AND context.agreement_terms_id = period.agreement_terms_id
             WHERE period.id = %s AND period.agreement_terms_id = %s
             FOR SHARE OF period, context
            """,
            (
                str(command.execution_context_id),
                command.budget_period_id,
                command.agreement_terms_id,
            ),
        )
        row = cursor.fetchone()
        if row is None:
            raise BudgetReservationProtocolError(
                "budget period and execution context lineage do not match"
            )
        (
            terms_id,
            policy_id,
            model_limit,
            technical_limit,
            concurrency,
            state,
            context_policy,
            context_status,
            context_start_deadline,
            context_usage_until,
            period_start,
            period_end,
            max_single_reservation,
            top_up_quantum,
            max_unreserved_delta,
            late_child_allowance,
            max_period_overdraft,
            redis_generation,
            generation_bootstrap_allowed,
        ) = row
        if (
            policy_id != context_policy
            or int(redis_generation) != command.redis_generation
            or command.authorized_work_start_deadline > context_start_deadline
            or command.late_child_accept_until > context_usage_until
        ):
            raise BudgetReservationProtocolError("budget period policy is not active")
        if not recovery and (
            state not in {"open", "soft_limited"}
            or context_status != "active"
            or now < period_start
            or now >= period_end
            or now > command.authorized_work_start_deadline
        ):
            raise BudgetReservationProtocolError("budget period policy is not active")
        if (
            any(
                amount > max_single_reservation
                for amount in self._hold_map(command).values()
            )
            or command.estimate.top_up_threshold_microusd != top_up_quantum
            or command.estimate.max_unreserved_delta_microusd != max_unreserved_delta
        ):
            raise BudgetReservationProtocolError(
                "reservation estimate does not match active period safety policy"
            )
        return {
            "budget_policy_id": int(policy_id),
            "max_concurrency": int(concurrency),
            "max_unreserved_delta": int(max_unreserved_delta),
            "late_child_allowance": int(late_child_allowance),
            "max_period_overdraft": int(max_period_overdraft),
            "limits": {"model": int(model_limit), "technical": int(technical_limit)},
            "generation_bootstrap_allowed": bool(generation_bootstrap_allowed),
        }

    def _require_rollout_enforcement(self, cursor, command) -> None:
        cursor.execute(
            """
            SELECT current.mode, slot.environment, latest_reconciliation.status
              FROM commercial_budget_rollout_slots slot
              LEFT JOIN LATERAL (
                  SELECT event.mode, event.readiness_evidence_id
                    FROM commercial_budget_rollout_events event
                   WHERE event.slot_key = slot.slot_key
                   ORDER BY event.rollout_revision DESC
                   LIMIT 1
              ) current ON TRUE
              LEFT JOIN commercial_budget_rollout_readiness_evidence readiness
                ON readiness.evidence_id = current.readiness_evidence_id
               AND readiness.budget_period_id = %s
              LEFT JOIN LATERAL (
                  SELECT evidence.status
                    FROM commercial_budget_reconciliation_evidence evidence
                   WHERE evidence.budget_period_id = readiness.budget_period_id
                   ORDER BY evidence.recorded_sequence DESC
                   LIMIT 1
              ) latest_reconciliation ON TRUE
             WHERE slot.slot_key = 'initial_pilot'
               AND slot.agreement_terms_id = %s
             FOR SHARE OF slot
            """,
            (command.budget_period_id, command.agreement_terms_id),
        )
        row = cursor.fetchone()
        if row in {
            ("enforce", self._flags.environment, "green"),
            ("enforce", self._flags.environment, "repaired"),
        }:
            return
        if self._has_invite_trial_budget_authority(cursor, command):
            return
        raise BudgetReservationProtocolError(
            "agreement terms are not allowlisted for budget enforcement"
        )

    def _has_invite_trial_budget_authority(self, cursor, command) -> bool:
        """Accept the bounded per-activation trial authority, never a shared slot."""

        cursor.execute("SELECT to_regclass('commercial_trial_token_issuances')")
        if cursor.fetchone()[0] is None:
            return False
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT 1
                  FROM commercial_trial_token_issuances issuance
                  JOIN commercial_trial_activations activation
                    ON activation.activation_id = issuance.activation_id
                  JOIN commercial_agreements agreement
                    ON agreement.id = issuance.agreement_id
                  JOIN commercial_budget_periods period
                    ON period.id = issuance.budget_period_id
                  JOIN mcp_tokens token ON token.id = issuance.token_id
                  JOIN commercial_execution_contexts context
                    ON context.id = %s
                 WHERE issuance.agreement_id = agreement.id
                   AND activation.agreement_terms_id = %s
                   AND issuance.budget_period_id = %s
                   AND activation.environment = %s
                   AND agreement.channel = 'invite_trial'
                   AND agreement.state = 'trialing'
                   AND activation.trial_expires_at > transaction_timestamp()
                   AND context.status = 'active'
                   AND context.agreement_id = issuance.agreement_id
                   AND context.agreement_terms_id = activation.agreement_terms_id
                   AND context.commercial_account_id = issuance.commercial_account_id
                   AND context.mcp_token_id = issuance.token_id
                   AND context.effective_scopes =
                       ARRAY['scope:read','scope:trade-preview']::TEXT[]
                   AND token.status = 'active'
                   AND token.expires_at = activation.trial_expires_at
                   AND issuance.generation = (
                       SELECT MAX(current.generation)
                         FROM commercial_trial_token_issuances current
                        WHERE current.activation_id = issuance.activation_id
                   )
                   AND issuance.requests_per_minute = 60
                   AND issuance.requests_per_day = 1000
                   AND issuance.concurrent_workflows = 2
                   AND issuance.model_cap_microusd = 2000000
                   AND issuance.technical_cap_microusd = 19800000
                   AND period.model_limit_microusd = 2000000
                   AND period.technical_limit_microusd = 19800000
                   AND period.non_model_reserve_microusd = 17800000
                   AND period.max_single_reservation_microusd = 2000000
                   AND period.top_up_quantum_microusd = 50000
                   AND period.max_unreserved_delta_microusd = 10000
                   AND period.late_child_allowance_microusd = 100000
                   AND period.max_concurrent_reservations = 2
                   AND period.max_period_overdraft_microusd = 120000
                   AND period.state IN ('open', 'soft_limited')
            )
            """,
            (
                str(command.execution_context_id),
                command.agreement_terms_id,
                command.budget_period_id,
                self._flags.environment,
            ),
        )
        return bool(cursor.fetchone()[0])

    def _classify_existing(self, cursor, command, row):
        (
            reservation_id,
            digest,
            period_id,
            terms_id,
            execution_context_id,
            workflow_run_id,
            request_id,
            profile_version,
            estimated_cost,
            lease_token,
            lease_version,
            generation,
            state,
            authorized_work_start_deadline,
            expires_at,
            late_child_accept_until,
        ) = row
        expected_workflow_id = (
            str(command.workflow_run_id) if command.workflow_run_id else None
        )
        expected_lease_version = (
            command.lease_version
            if state == "pending"
            else self._committed_lease_version(command)
        )
        if (
            UUID(str(lease_token)) != command.lease_token
            or int(lease_version) != expected_lease_version
        ):
            raise BudgetReservationProtocolError(
                "budget reservation replay fence conflicts"
            )
        if state == "reserved" and int(generation) != command.redis_generation:
            raise BudgetReservationProtocolError(
                "budget reservation generation conflicts"
            )
        if (
            UUID(str(reservation_id)) != command.reservation_id
            or digest != self._authority_sha256(command)
            or int(period_id) != command.budget_period_id
            or int(terms_id) != command.agreement_terms_id
            or UUID(str(execution_context_id)) != command.execution_context_id
            or (str(workflow_run_id) if workflow_run_id else None)
            != expected_workflow_id
            or request_id != command.request_id
            or profile_version != command.estimate.profile_version
            or int(estimated_cost) != self._hold_map(command)["technical"]
            or authorized_work_start_deadline != command.authorized_work_start_deadline
            or expires_at != command.expires_at
            or late_child_accept_until != command.late_child_accept_until
            or self._load_initial_holds(cursor, command.reservation_id)
            != self._hold_map(command)
        ):
            raise BudgetReservationProtocolError(
                "budget reservation idempotency key conflicts with prior request"
            )
        if state == "reserved":
            return BudgetReservationResult(
                decision="allow",
                reason_code="budget.reserved_replay",
                reservation_id=command.reservation_id,
                state="reserved",
                lease_version=self._committed_lease_version(command),
                redis_generation=command.redis_generation,
                replayed=True,
            )
        if state == "pending":
            return None
        terminal_reason = "budget.reservation_terminal"
        if state == "released":
            cursor.execute(
                """
                SELECT reason_code
                  FROM commercial_budget_events
                 WHERE reservation_id = %s AND event_kind = 'release'
                 ORDER BY id DESC LIMIT 1
                """,
                (str(command.reservation_id),),
            )
            reason_row = cursor.fetchone()
            if reason_row is not None:
                terminal_reason = reason_row[0]
        return BudgetReservationResult(
            decision="block",
            reason_code=terminal_reason,
            reservation_id=command.reservation_id,
            state="released",
            lease_version=self._committed_lease_version(command),
            redis_generation=int(generation) if generation is not None else None,
            replayed=True,
        )

    def _redis_command(self, command, *, recovery: bool = False):
        now = self._clock()
        try:
            with self._connection.cursor() as cursor:
                period = self._load_period(cursor, command, now=now, recovery=recovery)
        except Exception:
            self._rollback_best_effort()
            raise
        try:
            self._rollback()
        except Exception as error:
            raise BudgetReservationProtocolError(
                "budget reservation PostgreSQL authority could not be released"
            ) from error
        ttl_seconds = (
            int((command.late_child_accept_until - now).total_seconds())
            + 1
            + _REDIS_REPAIR_GRACE_SECONDS
        )
        if recovery:
            ttl_seconds = max(1, min(ttl_seconds, _MAX_REDIS_TTL_SECONDS))
        elif (
            ttl_seconds <= _REDIS_REPAIR_GRACE_SECONDS
            or ttl_seconds > _MAX_REDIS_TTL_SECONDS
        ):
            raise BudgetReservationProtocolError(
                "durable reservation window cannot be represented by Redis retention"
            )
        return ReservationRedisCommand(
            reservation_id=command.reservation_id,
            idempotency_key=command.idempotency_key,
            payload_sha256=self._authority_sha256(command),
            lease_token=command.lease_token,
            lease_version=self._committed_lease_version(command),
            generation=command.redis_generation,
            budget_policy_id=period["budget_policy_id"],
            ttl_seconds=ttl_seconds,
            max_concurrent_reservations=period["max_concurrency"],
            max_unreserved_delta_microusd=period["max_unreserved_delta"],
            late_child_allowance_microusd=period["late_child_allowance"],
            max_period_overdraft_microusd=period["max_period_overdraft"],
            allow_generation_bootstrap=period["generation_bootstrap_allowed"],
            holds=command.estimate.holds_by_bucket_microusd,
            limits=tuple(
                BucketLimit(budget_bucket=bucket, limit_microusd=limit)
                for bucket, limit in sorted(period["limits"].items())
            ),
        )

    def _reserve_in_redis(self, command, *, redis_command=None):
        return self._redis.reserve(
            agreement_terms_id=command.agreement_terms_id,
            period_id=command.budget_period_id,
            command=redis_command or self._redis_command(command),
        )

    def _expire_pending(self, command) -> BudgetReservationResult:
        redis_command = self._redis_command(command, recovery=True)
        compensation = self._compensation_command(command, redis_command)
        try:
            with self._connection.cursor() as cursor:
                self._lock_command(cursor, command)
                cursor.execute(
                    """
                    SELECT id, request_payload_sha256, budget_period_id,
                           agreement_terms_id, execution_context_id,
                           workflow_run_id, request_id, estimator_profile_version,
                           estimated_cost_microusd, lease_token, lease_version,
                           redis_generation, state,
                           authorized_work_start_deadline, expires_at,
                           late_child_accept_until
                      FROM commercial_budget_reservations
                     WHERE idempotency_key = %s
                     FOR UPDATE
                    """,
                    (command.idempotency_key,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise BudgetReservationProtocolError(
                        "expired pending reservation disappeared"
                    )
                existing = self._classify_existing(cursor, command, row)
                if existing is not None:
                    self._commit()
                    if existing.decision == "allow":
                        return existing.model_copy(
                            update={
                                "decision": "block",
                                "reason_code": "budget.work_start_expired",
                            }
                        )
                    return existing
                released = self._redis.release(
                    agreement_terms_id=command.agreement_terms_id,
                    period_id=command.budget_period_id,
                    command=compensation,
                )
                if released.decision == "allow":
                    reason_code = "budget.work_start_expired_compensated"
                elif released.reason_code == "budget.reservation_missing":
                    reason_code = "budget.work_start_expired_no_redis"
                else:
                    raise BudgetReservationProtocolError(
                        "expired pending Redis authority is unsafe to release; "
                        "reservation remains pending for repair"
                    )
                self._transition_pending_to_released(
                    command, reason_code=reason_code, occurred_at=self._clock()
                )
            self._commit()
        except CommercialReservationRedisError as error:
            self._rollback_best_effort()
            raise BudgetReservationProtocolError(
                "expired pending Redis authority is unavailable; reservation remains "
                "pending for repair"
            ) from error
        except Exception:
            self._rollback_best_effort()
            raise
        return BudgetReservationResult(
            decision="block",
            reason_code=reason_code,
            reservation_id=command.reservation_id,
            state="released",
            lease_version=self._committed_lease_version(command),
            redis_generation=None,
            replayed=True,
        )

    def _record_reserved(self, command, *, now, replayed):
        with self._connection.cursor() as cursor:
            self._lock_command(cursor, command)
            cursor.execute(
                """
                SELECT state, request_payload_sha256, lease_token, lease_version,
                       redis_generation
                  FROM commercial_budget_reservations
                 WHERE id = %s
                 FOR UPDATE
                """,
                (str(command.reservation_id),),
            )
            row = cursor.fetchone()
            if row is None:
                raise BudgetReservationProtocolError(
                    "durable pending reservation disappeared"
                )
            state, digest, lease_token, lease_version, generation = row
            expected_lease_version = (
                self._committed_lease_version(command)
                if state == "reserved"
                else command.lease_version
            )
            if (
                digest != self._authority_sha256(command)
                or UUID(str(lease_token)) != command.lease_token
                or int(lease_version) != expected_lease_version
            ):
                raise BudgetReservationProtocolError(
                    "durable pending reservation identity changed"
                )
            if state == "reserved" and int(generation) == command.redis_generation:
                self._commit()
                return BudgetReservationResult(
                    decision="allow",
                    reason_code="budget.reserved_replay",
                    reservation_id=command.reservation_id,
                    state="reserved",
                    lease_version=self._committed_lease_version(command),
                    redis_generation=command.redis_generation,
                    replayed=True,
                )
            if state != "pending":
                raise BudgetReservationProtocolError(
                    "durable reservation is no longer pending"
                )
            finalized_at = self._clock()
            self._load_period(cursor, command, now=finalized_at)
            committed_lease_version = self._committed_lease_version(command)
            cursor.execute(
                """
                UPDATE commercial_budget_reservations
                   SET state = 'reserved', reserved_at = %s, heartbeat_at = %s,
                       redis_generation = %s, lease_version = %s
                 WHERE id = %s AND state = 'pending'
                """,
                (
                    finalized_at,
                    finalized_at,
                    command.redis_generation,
                    committed_lease_version,
                    str(command.reservation_id),
                ),
            )
            if cursor.rowcount != 1:
                raise BudgetReservationProtocolError(
                    "durable reservation finalization lost pending state"
                )
            for bucket, amount in sorted(self._hold_map(command).items()):
                cursor.execute(
                    """
                    INSERT INTO commercial_budget_events (
                        event_id, budget_period_id, reservation_id, budget_bucket,
                        event_kind, amount_microusd, lease_version, reason_code,
                        occurred_at
                    ) VALUES (%s, %s, %s, %s, 'reserve', %s, %s,
                              'budget.reserved', %s)
                    """,
                    (
                        str(self._event_id(command.reservation_id, "reserve", bucket)),
                        command.budget_period_id,
                        str(command.reservation_id),
                        bucket,
                        amount,
                        committed_lease_version,
                        finalized_at,
                    ),
                )
        try:
            self._commit()
        except Exception as error:
            raise _PostgresCommitOutcomeUnknown(
                "reservation finalization commit outcome is unknown"
            ) from error
        return BudgetReservationResult(
            decision="allow",
            reason_code="budget.reserved",
            reservation_id=command.reservation_id,
            state="reserved",
            lease_version=self._committed_lease_version(command),
            redis_generation=command.redis_generation,
            replayed=replayed,
        )

    def _record_block(self, command, *, reason_code):
        with self._connection.cursor() as cursor:
            self._lock_command(cursor, command)
            cursor.execute(
                """
                SELECT state, request_payload_sha256, lease_token, lease_version
                  FROM commercial_budget_reservations
                 WHERE id = %s
                 FOR UPDATE
                """,
                (str(command.reservation_id),),
            )
            row = cursor.fetchone()
            if row is None:
                raise BudgetReservationProtocolError(
                    "blocked reservation disappeared before journaling"
                )
            state, digest, lease_token, lease_version = row
            if (
                digest != self._authority_sha256(command)
                or UUID(str(lease_token)) != command.lease_token
                or int(lease_version) != command.lease_version
            ):
                raise BudgetReservationProtocolError(
                    "blocked reservation identity changed"
                )
            if state == "released":
                cursor.execute(
                    """
                    SELECT 1 FROM commercial_budget_events
                     WHERE event_id = %s AND reservation_id = %s
                       AND event_kind = 'release' AND reason_code = %s
                    """,
                    (
                        str(
                            self._event_id(
                                command.reservation_id, "release", reason_code
                            )
                        ),
                        str(command.reservation_id),
                        reason_code,
                    ),
                )
                if cursor.fetchone() is None:
                    raise BudgetReservationProtocolError(
                        "released reservation has different terminal evidence"
                    )
                self._commit()
                return BudgetReservationResult(
                    decision="block",
                    reason_code=reason_code,
                    reservation_id=command.reservation_id,
                    state="released",
                    lease_version=self._committed_lease_version(command),
                    redis_generation=None,
                    replayed=True,
                )
            if state != "pending":
                raise BudgetReservationProtocolError(
                    "blocked reservation is no longer pending"
                )
            self._transition_pending_to_released(
                command, reason_code=reason_code, occurred_at=self._clock()
            )
        self._commit()
        return BudgetReservationResult(
            decision="block",
            reason_code=reason_code,
            reservation_id=command.reservation_id,
            state="released",
            lease_version=self._committed_lease_version(command),
            redis_generation=None,
            replayed=False,
        )

    def _compensate_pending(self, command, *, compensation, finalize_error):
        with self._connection.cursor() as cursor:
            self._lock_command(cursor, command)
            cursor.execute(
                """
                SELECT state, request_payload_sha256, lease_token, lease_version
                  FROM commercial_budget_reservations
                 WHERE id = %s
                 FOR UPDATE
                """,
                (str(command.reservation_id),),
            )
            row = cursor.fetchone()
            if row is None:
                self._rollback_best_effort()
                return False
            state, digest, lease_token, lease_version = row
            expected_lease_version = (
                command.lease_version
                if state == "pending"
                else self._committed_lease_version(command)
            )
            if (
                state not in {"pending", "released", "expired"}
                or digest != self._authority_sha256(command)
                or UUID(str(lease_token)) != command.lease_token
                or int(lease_version) != expected_lease_version
            ):
                self._rollback_best_effort()
                return False
            released = self._redis.release(
                agreement_terms_id=command.agreement_terms_id,
                period_id=command.budget_period_id,
                command=compensation,
            )
            if released.decision != "allow" and not (
                state in {"released", "expired"}
                and released.reason_code == "budget.reservation_missing"
            ):
                self._rollback_best_effort()
                raise BudgetReservationProtocolError(
                    "Redis compensation was rejected; reservation remains pending"
                ) from finalize_error
            if state == "pending":
                self._transition_pending_to_released(
                    command,
                    reason_code="budget.finalization_compensated",
                    occurred_at=self._clock(),
                )
        self._commit()
        return True

    def _transition_pending_to_released(self, command, *, reason_code, occurred_at):
        with self._connection.cursor() as cursor:
            self._release_durable_holds(
                cursor, command, reason_code=reason_code, occurred_at=occurred_at
            )
            committed_lease_version = self._committed_lease_version(command)
            cursor.execute(
                """
                UPDATE commercial_budget_reservations
                   SET state = 'released', settled_at = %s, lease_version = %s,
                       heartbeat_at = CASE
                           WHEN heartbeat_at IS NULL THEN NULL
                           ELSE heartbeat_at + INTERVAL '1 microsecond'
                       END
                 WHERE id = %s AND state = 'pending'
                """,
                (
                    occurred_at,
                    committed_lease_version,
                    str(command.reservation_id),
                ),
            )
            if cursor.rowcount != 1:
                raise BudgetReservationProtocolError(
                    "pending reservation release was lost"
                )
            cursor.execute(
                """
                INSERT INTO commercial_budget_events (
                    event_id, budget_period_id, reservation_id, event_kind,
                    amount_microusd, lease_version, reason_code, occurred_at
                ) VALUES (%s, %s, %s, 'release', 0, %s, %s, %s)
                """,
                (
                    str(self._event_id(command.reservation_id, "release", reason_code)),
                    command.budget_period_id,
                    str(command.reservation_id),
                    committed_lease_version,
                    reason_code,
                    occurred_at,
                ),
            )

    def _record_initial_hold(self, cursor, command, *, budget_bucket, amount):
        if not self._uses_hold_journal(cursor):
            cursor.execute(
                """
                INSERT INTO commercial_budget_reservation_holds (
                    reservation_id, budget_period_id, budget_bucket,
                    reserved_microusd
                ) VALUES (%s, %s, %s, %s)
                """,
                (
                    str(command.reservation_id),
                    command.budget_period_id,
                    budget_bucket,
                    amount,
                ),
            )
            return
        cursor.execute(
            """
            INSERT INTO commercial_budget_hold_events (
                event_id, reservation_id, budget_period_id, budget_bucket,
                hold_revision, hold_kind, amount_delta_microusd,
                lease_version, idempotency_key, reason_code, actor_type
            ) VALUES (%s, %s, %s, %s, 0, 'reserve', %s, %s, %s,
                      'budget.initial_reserve', 'service')
            """,
            (
                str(self._event_id(command.reservation_id, "hold", budget_bucket)),
                str(command.reservation_id),
                command.budget_period_id,
                budget_bucket,
                amount,
                command.lease_version,
                f"initial:{budget_bucket}",
            ),
        )

    def _load_initial_holds(self, cursor, reservation_id: UUID) -> dict[str, int]:
        if not self._uses_hold_journal(cursor):
            cursor.execute(
                """
                SELECT budget_bucket, reserved_microusd
                  FROM commercial_budget_reservation_holds
                 WHERE reservation_id = %s
                 ORDER BY budget_bucket
                """,
                (str(reservation_id),),
            )
        else:
            cursor.execute(
                """
                SELECT budget_bucket, amount_delta_microusd
                  FROM commercial_budget_hold_events
                 WHERE reservation_id = %s
                   AND hold_revision = 0 AND hold_kind = 'reserve'
                 ORDER BY budget_bucket
                """,
                (str(reservation_id),),
            )
        return {bucket: int(amount) for bucket, amount in cursor.fetchall()}

    def _release_durable_holds(
        self,
        cursor,
        command,
        *,
        reason_code,
        occurred_at,
        lease_version=None,
    ):
        del occurred_at  # Hold events carry their own append timestamp.
        if not self._uses_hold_journal(cursor):
            return
        cursor.execute(
            """
            SELECT budget_bucket, current_hold_microusd, current_revision
              FROM commercial_budget_current_holds
             WHERE reservation_id = %s
             ORDER BY budget_bucket
            """,
            (str(command.reservation_id),),
        )
        holds = cursor.fetchall()
        for bucket, amount, revision in holds:
            cursor.execute(
                """
                INSERT INTO commercial_budget_hold_events (
                    event_id, reservation_id, budget_period_id, budget_bucket,
                    hold_revision, hold_kind, amount_delta_microusd,
                    lease_version, idempotency_key, reason_code, actor_type
                ) VALUES (%s, %s, %s, %s, %s, 'release', %s, %s, %s, %s,
                          'service')
                """,
                (
                    str(self._event_id(command.reservation_id, "hold-release", bucket)),
                    str(command.reservation_id),
                    command.budget_period_id,
                    bucket,
                    int(revision) + 1,
                    -int(amount),
                    lease_version or command.lease_version,
                    f"terminal-release:{bucket}",
                    reason_code,
                ),
            )

    @staticmethod
    def _uses_hold_journal(cursor) -> bool:
        cursor.execute(
            "SELECT to_regclass('commercial_budget_hold_events') IS NOT NULL"
        )
        return bool(cursor.fetchone()[0])

    @staticmethod
    def _committed_lease_version(command) -> int:
        return command.lease_version + 1

    @staticmethod
    def _hold_map(command):
        return {
            hold.budget_bucket: hold.amount_microusd
            for hold in command.estimate.holds_by_bucket_microusd
        }

    @staticmethod
    def _authority_sha256(command: BudgetReservationCommand) -> str:
        return canonical_sha256(
            {
                "schema": "commercial.budget.reservation.authority.v1",
                "command": command.model_dump(mode="python"),
            }
        )

    @staticmethod
    def _event_id(reservation_id, operation, suffix):
        return uuid5(NAMESPACE_URL, f"budget:{reservation_id}:{operation}:{suffix}")

    def _compensation_command(self, command, redis_command):
        payload = {
            "reservation_id": str(command.reservation_id),
            "operation": "release",
            "lease_version": command.lease_version,
            "generation": command.redis_generation,
        }
        return redis_command.model_copy(
            update={
                "idempotency_key": f"compensate.{command.reservation_id.hex}",
                "payload_sha256": canonical_sha256(payload),
            }
        )

    @staticmethod
    def _lock_command(cursor, command) -> None:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"budget:idempotency:{command.idempotency_key}",),
        )

    def _assert_idle_connection(self) -> None:
        status_reader = getattr(self._connection, "get_transaction_status", None)
        if callable(status_reader) and status_reader() != 0:
            raise BudgetReservationProtocolError(
                "budget reservation protocol requires a dedicated idle PostgreSQL "
                "connection"
            )
        info = getattr(self._connection, "info", None)
        status = getattr(info, "transaction_status", 0) if info is not None else 0
        if not callable(status_reader) and status != 0:
            raise BudgetReservationProtocolError(
                "budget reservation protocol requires a dedicated idle PostgreSQL "
                "connection"
            )

    def _commit(self) -> None:
        self._connection.commit()

    def _rollback(self) -> None:
        self._connection.rollback()

    def _rollback_best_effort(self) -> None:
        try:
            self._rollback()
        except Exception:
            pass
