"""Deterministic, append-only allocation of flat provider cash-cost pools."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, DecimalException, ROUND_DOWN, localcontext
import re
from typing import Iterable, Literal, Mapping
from uuid import UUID, NAMESPACE_URL, uuid4, uuid5

from ..models import canonical_sha256


_COST_QUANTUM = Decimal("0.00000001")
_COST_MAX = Decimal("9999999999.99999999")
_ZERO = Decimal("0")
_STABLE_CODE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_REASON_CODE = _STABLE_CODE
ALLOCATOR_POLICY_VERSION = "cost-allocation.v1"
_ELIGIBLE_PAYER_CLASSES = ("hank_paid", "hank_shadow_priced")
_ELIGIBLE_USAGE_STATES = ("succeeded", "failed_billable")


class CostAllocationError(ValueError):
    """A cost pool or allocation run violates a commercial invariant."""


@dataclass(frozen=True)
class AllocationWeight:
    usage_event_id: int
    weight: Decimal


@dataclass(frozen=True)
class AllocationLine:
    target_kind: Literal["usage_event", "unattributed"]
    allocated_actual_cash_cost_usd: Decimal
    usage_event_id: int | None = None
    unattributed_reason: str | None = None


@dataclass(frozen=True)
class CostPoolInput:
    provider: str
    source_invoice_id: str
    currency: str
    cash_cost_usd: Decimal
    period_start_at: datetime
    period_end_at: datetime
    allocation_method: Literal["direct", "shadow_weighted", "unit_weighted", "manual"]
    source_revision: int = 1
    supersedes_cost_pool_id: int | None = None


def _ledger_cost(value: Decimal, *, label: str) -> Decimal:
    if not value.is_finite() or value < _ZERO:
        raise CostAllocationError(f"{label} must be finite and non-negative")
    try:
        with localcontext() as context:
            context.prec = 96
            rounded = value.quantize(_COST_QUANTUM)
    except DecimalException as exc:
        raise CostAllocationError(f"{label} is not representable") from exc
    if rounded != value:
        raise CostAllocationError(f"{label} exceeds ledger precision")
    if value > _COST_MAX:
        raise CostAllocationError(f"{label} exceeds ledger bounds")
    return rounded


def allocate_cost_pool(
    cash_cost_usd: Decimal,
    weights: Iterable[AllocationWeight],
    *,
    unattributed_reason: str = "allocation.no_positive_weight",
) -> tuple[AllocationLine, ...]:
    """Allocate every ledger quantum using stable largest-remainder ordering."""
    try:
        with localcontext() as context:
            context.prec = 96
            total = _ledger_cost(cash_cost_usd, label="cash cost")
            ordered = sorted(weights, key=lambda row: row.usage_event_id)
            ids = [row.usage_event_id for row in ordered]
            if any(value <= 0 for value in ids) or len(ids) != len(set(ids)):
                raise CostAllocationError("usage event ids must be positive and unique")
            for row in ordered:
                if not row.weight.is_finite() or row.weight < _ZERO:
                    raise CostAllocationError(
                        "allocation weights must be finite and non-negative"
                    )
            positive = [row for row in ordered if row.weight > _ZERO]
            if not positive:
                if not unattributed_reason:
                    raise CostAllocationError(
                        "unattributed allocation requires a reason"
                    )
                return (
                    AllocationLine(
                        target_kind="unattributed",
                        allocated_actual_cash_cost_usd=total,
                        unattributed_reason=unattributed_reason,
                    ),
                )

            weight_total = sum((row.weight for row in positive), _ZERO)
            exact = {
                row.usage_event_id: total * row.weight / weight_total
                for row in positive
            }
            allocated = {
                event_id: amount.quantize(_COST_QUANTUM, rounding=ROUND_DOWN)
                for event_id, amount in exact.items()
            }
            remainder_quanta = int(
                (total - sum(allocated.values(), _ZERO)) / _COST_QUANTUM
            )
            remainder_order = sorted(
                positive,
                key=lambda row: (
                    -(exact[row.usage_event_id] - allocated[row.usage_event_id]),
                    row.usage_event_id,
                ),
            )
            for row in remainder_order[:remainder_quanta]:
                allocated[row.usage_event_id] += _COST_QUANTUM
            lines = tuple(
                AllocationLine(
                    target_kind="usage_event",
                    usage_event_id=row.usage_event_id,
                    allocated_actual_cash_cost_usd=allocated[row.usage_event_id],
                )
                for row in positive
            )
            if (
                sum((line.allocated_actual_cash_cost_usd for line in lines), _ZERO)
                != total
            ):
                raise AssertionError("deterministic allocation did not balance")
            return lines
    except DecimalException as exc:
        raise CostAllocationError("allocation arithmetic is not representable") from exc


class PostgresCostAllocationService:
    """Create reviewed draft runs and atomically finalize balanced allocations."""

    def __init__(self, connection) -> None:
        self._connection = connection
        if bool(getattr(connection, "autocommit", False)):
            raise RuntimeError("cost allocation requires an explicit transaction")

    def create_pool(self, value: CostPoolInput) -> tuple[int, bool]:
        provider = value.provider.strip().lower()
        invoice_id = value.source_invoice_id.strip()
        if not _STABLE_CODE.fullmatch(provider):
            raise CostAllocationError("provider must be a stable code")
        if not 1 <= len(invoice_id) <= 255:
            raise CostAllocationError("source invoice id length is invalid")
        if value.currency != "USD":
            raise CostAllocationError("V1 cost pools require normalized USD cash cost")
        if value.allocation_method == "manual":
            raise CostAllocationError(
                "manual allocation is not supported by the V1 service"
            )
        if value.source_revision <= 0 or (value.source_revision == 1) is not (
            value.supersedes_cost_pool_id is None
        ):
            raise CostAllocationError("cost pool source revision lineage is invalid")
        cash_cost = _ledger_cost(value.cash_cost_usd, label="cash cost")
        if (
            value.period_start_at.tzinfo is None
            or value.period_end_at.tzinfo is None
            or value.period_end_at <= value.period_start_at
        ):
            raise CostAllocationError("cost pool service period is empty")
        identity = f"{provider}:{invoice_id}:{value.source_revision}"
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (identity,)
            )
            cursor.execute(
                """
                SELECT id, currency, cash_cost_usd, period_start_at, period_end_at,
                       allocation_method, source_revision, supersedes_cost_pool_id
                  FROM commercial_cost_pools
                 WHERE provider = %s AND source_invoice_id = %s
                   AND source_revision = %s
                 FOR SHARE
                """,
                (provider, invoice_id, value.source_revision),
            )
            existing = cursor.fetchone()
            expected = (
                value.currency,
                cash_cost,
                value.period_start_at,
                value.period_end_at,
                value.allocation_method,
                value.source_revision,
                value.supersedes_cost_pool_id,
            )
            if existing is not None:
                row = (
                    tuple(existing.values())
                    if isinstance(existing, Mapping)
                    else existing
                )
                if tuple(row[1:]) != expected:
                    raise CostAllocationError("cost pool invoice identity conflicts")
                return int(row[0]), True
            cursor.execute(
                """
                INSERT INTO commercial_cost_pools (
                    provider, source_invoice_id, currency, cash_cost_usd,
                    period_start_at, period_end_at, allocation_method, state,
                    source_revision, supersedes_cost_pool_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'draft', %s, %s)
                RETURNING id
                """,
                (
                    provider,
                    invoice_id,
                    value.currency,
                    cash_cost,
                    value.period_start_at,
                    value.period_end_at,
                    value.allocation_method,
                    value.source_revision,
                    value.supersedes_cost_pool_id,
                ),
            )
            return int(cursor.fetchone()[0]), False

    def create_draft(
        self, *, cost_pool_id: int, idempotency_key: str
    ) -> tuple[int, tuple[AllocationLine, ...]]:
        if not 1 <= len(idempotency_key) <= 255:
            raise CostAllocationError("allocation idempotency key length is invalid")
        pool = self._lock_pool(cost_pool_id)
        weights = self._eligible_weights(pool)
        lines = allocate_cost_pool(pool["cash_cost_usd"], weights)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, input_sha256, reopen_transition_id
                  FROM commercial_cost_allocation_runs
                 WHERE cost_pool_id = %s AND idempotency_key = %s
                 FOR SHARE
                """,
                (cost_pool_id, idempotency_key),
            )
            existing = cursor.fetchone()
            if pool["state"] not in {"draft", "reopened"}:
                if existing is None:
                    raise CostAllocationError(
                        "cost pool is not ready for a new draft allocation"
                    )
            reopen_transition_id = existing[2] if existing is not None else None
            if pool["state"] == "reopened" and existing is None:
                cursor.execute(
                    """
                    SELECT transition_id
                      FROM commercial_cost_pool_transitions transition
                     WHERE cost_pool_id = %s
                       AND NOT EXISTS (
                           SELECT 1 FROM commercial_cost_allocation_runs run
                            WHERE run.reopen_transition_id = transition.transition_id
                              AND run.state <> 'discarded'
                       )
                     FOR UPDATE
                    """,
                    (cost_pool_id,),
                )
                transition = cursor.fetchone()
                if transition is None:
                    raise CostAllocationError(
                        "reopened pool lacks an unused transition binding"
                    )
                reopen_transition_id = transition[0]
            input_sha256 = canonical_sha256(
                {
                    "allocator_policy_version": ALLOCATOR_POLICY_VERSION,
                    "provider": pool["provider"],
                    "cash_cost_usd": pool["cash_cost_usd"],
                    "period_start_at": pool["period_start_at"],
                    "period_end_at": pool["period_end_at"],
                    "allocation_method": pool["allocation_method"],
                    "weight_source": self._weight_source(
                        str(pool["allocation_method"])
                    ),
                    "eligible_payer_classes": _ELIGIBLE_PAYER_CLASSES,
                    "eligible_usage_states": _ELIGIBLE_USAGE_STATES,
                    "reopen_transition_id": reopen_transition_id,
                    "lines": [
                        {
                            "kind": line.target_kind,
                            "usage_event_id": line.usage_event_id,
                            "unattributed_reason": line.unattributed_reason,
                            "amount": line.allocated_actual_cash_cost_usd,
                        }
                        for line in lines
                    ],
                }
            )
            if existing is not None:
                if existing[1] != input_sha256:
                    raise CostAllocationError("allocation idempotency key conflicts")
                return int(existing[0]), self._load_lines(int(existing[0]))
            cursor.execute(
                """
                SELECT COALESCE(MAX(version), 0) + 1
                  FROM commercial_cost_allocation_runs
                 WHERE cost_pool_id = %s
                """,
                (cost_pool_id,),
            )
            version = int(cursor.fetchone()[0])
            cursor.execute(
                """
                INSERT INTO commercial_cost_allocation_runs (
                    cost_pool_id, version, state, idempotency_key, input_sha256,
                    reopen_transition_id, allocation_method_snapshot,
                    allocator_policy_version
                ) VALUES (%s, %s, 'draft', %s, %s, %s, %s, %s) RETURNING id
                """,
                (
                    cost_pool_id,
                    version,
                    idempotency_key,
                    input_sha256,
                    reopen_transition_id,
                    pool["allocation_method"],
                    ALLOCATOR_POLICY_VERSION,
                ),
            )
            run_id = int(cursor.fetchone()[0])
            for line in lines:
                cursor.execute(
                    """
                    INSERT INTO commercial_cost_allocations (
                        allocation_run_id, target_kind, usage_event_id,
                        unattributed_reason, allocated_actual_cash_cost_usd
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        run_id,
                        line.target_kind,
                        line.usage_event_id,
                        line.unattributed_reason,
                        line.allocated_actual_cash_cost_usd,
                    ),
                )
            cursor.execute(
                "UPDATE commercial_cost_pools SET state = 'allocated' WHERE id = %s",
                (cost_pool_id,),
            )
        return run_id, lines

    def load_run(
        self, *, cost_pool_id: int, allocation_run_id: int
    ) -> tuple[AllocationLine, ...]:
        """Load durable allocation output without re-evaluating mutable weights."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1
                  FROM commercial_cost_allocation_runs
                 WHERE id = %s AND cost_pool_id = %s AND state = 'draft'
                 FOR SHARE
                """,
                (allocation_run_id, cost_pool_id),
            )
            if cursor.fetchone() is None:
                raise CostAllocationError("reviewable draft allocation run not found")
        return self._load_lines(allocation_run_id)

    def reopen(
        self,
        *,
        cost_pool_id: int,
        idempotency_key: str,
        reason_code: str,
        actor_type: Literal["admin", "service", "reconciler"],
        actor_id: str | None,
    ) -> tuple[UUID, bool]:
        if not 1 <= len(idempotency_key) <= 255:
            raise CostAllocationError("reopen idempotency key length is invalid")
        if not _REASON_CODE.fullmatch(reason_code):
            raise CostAllocationError("reopen reason must be a stable code")
        if actor_type == "admin" and not actor_id:
            raise CostAllocationError("admin reopen requires a named actor")
        pool = self._lock_pool(cost_pool_id)
        payload_sha256 = canonical_sha256(
            {
                "cost_pool_id": cost_pool_id,
                "from_state": "final",
                "to_state": "reopened",
                "reason_code": reason_code,
                "actor_type": actor_type,
                "actor_id": actor_id,
            }
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT transition_id, payload_sha256
                  FROM commercial_cost_pool_transitions
                 WHERE cost_pool_id = %s AND idempotency_key = %s
                 FOR SHARE
                """,
                (cost_pool_id, idempotency_key),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing[1] != payload_sha256:
                    raise CostAllocationError("reopen idempotency key conflicts")
                return UUID(str(existing[0])), True
            if pool["state"] != "final":
                raise CostAllocationError("only a final cost pool can be reopened")
            cursor.execute(
                """
                SELECT id
                  FROM commercial_cost_allocation_runs
                 WHERE cost_pool_id = %s AND state = 'final'
                 FOR UPDATE
                """,
                (cost_pool_id,),
            )
            prior = cursor.fetchone()
            if prior is None:
                raise CostAllocationError(
                    "final cost pool lacks a final allocation run"
                )
            prior_run_id = int(prior[0])
            transition_id = uuid4()
            cursor.execute(
                """
                INSERT INTO commercial_cost_pool_transitions (
                    transition_id, cost_pool_id, idempotency_key, payload_sha256,
                    from_state, to_state, reason_code, actor_type, actor_id,
                    prior_allocation_run_id
                ) VALUES (%s, %s, %s, %s, 'final', 'reopened', %s, %s, %s, %s)
                """,
                (
                    str(transition_id),
                    cost_pool_id,
                    idempotency_key,
                    payload_sha256,
                    reason_code,
                    actor_type,
                    actor_id,
                    prior_run_id,
                ),
            )
            cursor.execute(
                "UPDATE commercial_cost_pools SET state = 'reopened' WHERE id = %s",
                (cost_pool_id,),
            )
            return transition_id, False

    def discard_draft(
        self,
        *,
        allocation_run_id: int,
        reason_code: str,
        actor_type: Literal["admin", "service", "reconciler"],
        actor_id: str | None,
    ) -> None:
        if not _REASON_CODE.fullmatch(reason_code):
            raise CostAllocationError("discard reason must be a stable code")
        if actor_type == "admin" and not actor_id:
            raise CostAllocationError("admin discard requires a named actor")
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT cost_pool_id FROM commercial_cost_allocation_runs WHERE id = %s",
                (allocation_run_id,),
            )
            identity = cursor.fetchone()
        if identity is None:
            raise CostAllocationError("allocation run not found")
        cost_pool_id = int(identity[0])
        pool = self._lock_pool(cost_pool_id)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT cost_pool_id, state, reopen_transition_id,
                       discard_reason_code, discard_actor_type, discard_actor_id
                  FROM commercial_cost_allocation_runs
                 WHERE id = %s
                 FOR UPDATE
                """,
                (allocation_run_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise CostAllocationError("allocation run not found")
            (
                locked_pool_id,
                state,
                reopen_transition_id,
                stored_reason,
                stored_actor_type,
                stored_actor_id,
            ) = row
            if int(locked_pool_id) != cost_pool_id:
                raise CostAllocationError("allocation run pool identity changed")
            if state == "discarded":
                if (stored_reason, stored_actor_type, stored_actor_id) != (
                    reason_code,
                    actor_type,
                    actor_id,
                ):
                    raise CostAllocationError("discard retry payload conflicts")
                return
            if state != "draft":
                raise CostAllocationError("only a draft allocation can be discarded")
            if pool["state"] != "allocated":
                raise CostAllocationError("draft pool is not allocated for review")
            cursor.execute(
                """
                UPDATE commercial_cost_allocation_runs
                   SET state = 'discarded', discarded_at = NOW(),
                       discard_reason_code = %s, discard_actor_type = %s,
                       discard_actor_id = %s
                 WHERE id = %s AND state = 'draft'
                """,
                (reason_code, actor_type, actor_id, allocation_run_id),
            )
            next_pool_state = (
                "reopened" if reopen_transition_id is not None else "draft"
            )
            cursor.execute(
                "UPDATE commercial_cost_pools SET state = %s WHERE id = %s",
                (next_pool_state, cost_pool_id),
            )

    def finalize(self, *, allocation_run_id: int) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT cost_pool_id FROM commercial_cost_allocation_runs WHERE id = %s",
                (allocation_run_id,),
            )
            identity = cursor.fetchone()
        if identity is None:
            raise CostAllocationError("allocation run not found")
        cost_pool_id = int(identity[0])
        pool = self._lock_pool(cost_pool_id)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT cost_pool_id, state, reopen_transition_id
                  FROM commercial_cost_allocation_runs
                 WHERE id = %s
                 FOR UPDATE
                """,
                (allocation_run_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise CostAllocationError("allocation run not found")
            locked_pool_id, run_state, reopen_transition_id = row
            if int(locked_pool_id) != cost_pool_id:
                raise CostAllocationError("allocation run pool identity changed")
            if run_state == "final":
                return
            if run_state != "draft" or pool["state"] != "allocated":
                raise CostAllocationError("allocation run is not reviewable")
            cursor.execute(
                """
                SELECT COALESCE(SUM(allocated_actual_cash_cost_usd), 0), COUNT(*)
                  FROM commercial_cost_allocations
                 WHERE allocation_run_id = %s
                """,
                (allocation_run_id,),
            )
            allocated, count = cursor.fetchone()
            if count <= 0 or Decimal(allocated) != Decimal(pool["cash_cost_usd"]):
                raise CostAllocationError(
                    "allocation run does not balance to pool cash cost"
                )
            if reopen_transition_id is not None:
                cursor.execute(
                    """
                    SELECT prior_allocation_run_id
                      FROM commercial_cost_pool_transitions
                     WHERE transition_id = %s AND cost_pool_id = %s
                     FOR UPDATE
                    """,
                    (str(reopen_transition_id), cost_pool_id),
                )
                prior = cursor.fetchone()
                if prior is None:
                    raise CostAllocationError("replacement run transition is missing")
                self._record_reallocation_adjustments(
                    cursor,
                    cost_pool_id=int(cost_pool_id),
                    transition_id=UUID(str(reopen_transition_id)),
                    prior_run_id=int(prior[0]),
                    replacement_run_id=allocation_run_id,
                )
                cursor.execute(
                    """
                    UPDATE commercial_cost_allocation_runs
                       SET state = 'superseded'
                     WHERE id = %s AND cost_pool_id = %s AND state = 'final'
                    """,
                    (int(prior[0]), cost_pool_id),
                )
            cursor.execute(
                """
                UPDATE commercial_cost_allocation_runs
                   SET state = 'final', finalized_at = NOW()
                 WHERE id = %s AND state = 'draft'
                """,
                (allocation_run_id,),
            )
            cursor.execute(
                "UPDATE commercial_cost_pools SET state = 'final' WHERE id = %s",
                (cost_pool_id,),
            )
            if pool["supersedes_cost_pool_id"] is not None:
                cursor.execute(
                    """
                    UPDATE commercial_cost_pools
                       SET state = 'superseded'
                     WHERE id = %s AND state = 'final'
                    """,
                    (int(pool["supersedes_cost_pool_id"]),),
                )
                if cursor.rowcount != 1:
                    raise CostAllocationError(
                        "corrected cost pool predecessor is not current final"
                    )

    def _record_reallocation_adjustments(
        self,
        cursor,
        *,
        cost_pool_id: int,
        transition_id: UUID,
        prior_run_id: int,
        replacement_run_id: int,
    ) -> None:
        cursor.execute(
            """
            SELECT actor_type, actor_id
              FROM commercial_cost_pool_transitions
             WHERE transition_id = %s AND cost_pool_id = %s
               AND prior_allocation_run_id = %s
             FOR UPDATE
            """,
            (str(transition_id), cost_pool_id, prior_run_id),
        )
        transition = cursor.fetchone()
        if transition is None:
            raise CostAllocationError("replacement allocation lacks reopen transition")
        actor_type, actor_id = transition
        cursor.execute(
            """
            WITH prior AS (
                SELECT usage_event_id, allocated_actual_cash_cost_usd AS amount
                  FROM commercial_cost_allocations
                 WHERE allocation_run_id = %s AND usage_event_id IS NOT NULL
            ), replacement AS (
                SELECT usage_event_id, allocated_actual_cash_cost_usd AS amount
                  FROM commercial_cost_allocations
                 WHERE allocation_run_id = %s AND usage_event_id IS NOT NULL
            )
            SELECT COALESCE(replacement.usage_event_id, prior.usage_event_id),
                   COALESCE(replacement.amount, 0) - COALESCE(prior.amount, 0),
                   context.agreement_terms_id
              FROM prior FULL OUTER JOIN replacement USING (usage_event_id)
              JOIN commercial_usage_events usage
                ON usage.id = COALESCE(replacement.usage_event_id, prior.usage_event_id)
              JOIN commercial_execution_contexts context
                ON context.id = usage.execution_context_id
             WHERE COALESCE(replacement.amount, 0) <> COALESCE(prior.amount, 0)
             ORDER BY 1
            """,
            (prior_run_id, replacement_run_id),
        )
        event_deltas = cursor.fetchall()
        cursor.execute(
            """
            SELECT
              COALESCE((SELECT SUM(allocated_actual_cash_cost_usd)
                          FROM commercial_cost_allocations
                         WHERE allocation_run_id = %s AND target_kind = 'unattributed'), 0)
              -
              COALESCE((SELECT SUM(allocated_actual_cash_cost_usd)
                          FROM commercial_cost_allocations
                         WHERE allocation_run_id = %s AND target_kind = 'unattributed'), 0)
            """,
            (replacement_run_id, prior_run_id),
        )
        unattributed_delta = Decimal(cursor.fetchone()[0])
        event_delta_total = sum((Decimal(row[1]) for row in event_deltas), _ZERO)
        if event_delta_total + unattributed_delta != _ZERO:
            raise CostAllocationError("reallocation signed deltas do not balance")
        cursor.execute(
            """
            INSERT INTO commercial_cost_allocation_transition_facts (
                transition_id, cost_pool_id, prior_allocation_run_id,
                replacement_allocation_run_id, unattributed_delta_usd
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            (
                str(transition_id),
                cost_pool_id,
                prior_run_id,
                replacement_run_id,
                unattributed_delta,
            ),
        )
        for usage_event_id, delta, agreement_terms_id in event_deltas:
            adjustment_id = uuid5(
                NAMESPACE_URL,
                f"hank-cost-allocation:{transition_id}:{usage_event_id}",
            )
            cursor.execute(
                """
                INSERT INTO commercial_cost_adjustments (
                    adjustment_id, usage_event_id, agreement_terms_id,
                    adjustment_kind, amount_usd, reason_code, actor_type, actor_id,
                    allocation_transition_id, prior_allocation_run_id,
                    replacement_allocation_run_id, cost_pool_id, application_mode
                ) VALUES (
                    %s, %s, %s, 'actual_cost', %s, 'cost_pool.reallocation',
                    %s, %s, %s, %s, %s, %s, 'allocation_transition_embodied'
                )
                ON CONFLICT (allocation_transition_id, usage_event_id)
                WHERE allocation_transition_id IS NOT NULL AND usage_event_id IS NOT NULL
                DO NOTHING
                RETURNING adjustment_id
                """,
                (
                    str(adjustment_id),
                    usage_event_id,
                    agreement_terms_id,
                    delta,
                    actor_type,
                    actor_id,
                    str(transition_id),
                    prior_run_id,
                    replacement_run_id,
                    cost_pool_id,
                ),
            )
            if cursor.fetchone() is None:
                cursor.execute(
                    """
                    SELECT adjustment_id, agreement_terms_id, amount_usd, actor_type,
                           actor_id, prior_allocation_run_id,
                           replacement_allocation_run_id, cost_pool_id, application_mode,
                           adjustment_kind, reason_code
                      FROM commercial_cost_adjustments
                     WHERE allocation_transition_id = %s AND usage_event_id = %s
                     FOR SHARE
                    """,
                    (str(transition_id), usage_event_id),
                )
                existing = cursor.fetchone()
                actual = (
                    (
                        str(existing[0]),
                        int(existing[1]),
                        Decimal(existing[2]),
                        *existing[3:],
                    )
                    if existing is not None
                    else None
                )
                expected = (
                    str(adjustment_id),
                    int(agreement_terms_id),
                    Decimal(delta),
                    actor_type,
                    actor_id,
                    prior_run_id,
                    replacement_run_id,
                    cost_pool_id,
                    "allocation_transition_embodied",
                    "actual_cost",
                    "cost_pool.reallocation",
                )
                if actual != expected:
                    raise CostAllocationError(
                        "cost allocation adjustment replay conflicts"
                    )

    def _load_lines(self, allocation_run_id: int) -> tuple[AllocationLine, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT target_kind, allocated_actual_cash_cost_usd,
                       usage_event_id, unattributed_reason
                  FROM commercial_cost_allocations
                 WHERE allocation_run_id = %s
                 ORDER BY usage_event_id NULLS LAST, id
                """,
                (allocation_run_id,),
            )
            return tuple(
                AllocationLine(
                    target_kind=row[0],
                    allocated_actual_cash_cost_usd=Decimal(row[1]),
                    usage_event_id=row[2],
                    unattributed_reason=row[3],
                )
                for row in cursor.fetchall()
            )

    def _lock_pool(self, cost_pool_id: int) -> Mapping[str, object]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, provider, cash_cost_usd, period_start_at, period_end_at,
                       allocation_method, state, source_revision,
                       supersedes_cost_pool_id
                  FROM commercial_cost_pools
                 WHERE id = %s
                 FOR UPDATE
                """,
                (cost_pool_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise CostAllocationError("cost pool not found")
            if isinstance(row, Mapping):
                return row
            keys = (
                "id",
                "provider",
                "cash_cost_usd",
                "period_start_at",
                "period_end_at",
                "allocation_method",
                "state",
                "source_revision",
                "supersedes_cost_pool_id",
            )
            return dict(zip(keys, row))

    def _eligible_weights(
        self, pool: Mapping[str, object]
    ) -> tuple[AllocationWeight, ...]:
        method = str(pool["allocation_method"])
        if method not in {"direct", "shadow_weighted", "unit_weighted"}:
            raise CostAllocationError(
                "automatic allocation does not support this pool method"
            )
        weight_column = self._weight_source(method)
        with self._connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT usage.id, COALESCE(usage.{weight_column}, 0)
                  FROM commercial_usage_events usage
                  JOIN commercial_usage_operational_eligibility eligibility
                    ON eligibility.usage_event_id = usage.id
                 WHERE usage.provider = %s
                   AND usage.environment = (
                       SELECT environment
                         FROM commercial_deployment_context
                        WHERE singleton
                   )
                   AND usage.occurred_at >= %s AND usage.occurred_at < %s
                   AND usage.payer_class IN ('hank_paid', 'hank_shadow_priced')
                   AND usage.usage_state IN ('succeeded', 'failed_billable')
                 ORDER BY usage.id
                """,
                (
                    pool["provider"],
                    pool["period_start_at"],
                    pool["period_end_at"],
                ),
            )
            return tuple(
                AllocationWeight(int(event_id), Decimal(weight))
                for event_id, weight in cursor.fetchall()
            )

    @staticmethod
    def _weight_source(method: str) -> str:
        return {
            "direct": "provider_reported_cost_usd",
            "shadow_weighted": "normalized_shadow_cost_usd",
            "unit_weighted": "provider_units",
        }.get(method, "manual_reviewed_lines")


__all__ = [
    "AllocationLine",
    "AllocationWeight",
    "ALLOCATOR_POLICY_VERSION",
    "CostAllocationError",
    "CostPoolInput",
    "PostgresCostAllocationService",
    "allocate_cost_pool",
]
