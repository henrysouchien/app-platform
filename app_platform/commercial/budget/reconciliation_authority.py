"""Independent accepted-usage and current-cost audit for budget reconciliation."""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Any

from pydantic import Field, StrictInt

from ..models import StableCode, StrictCommercialModel
from .redis_store import MAX_SAFE_REDIS_INTEGER


class BudgetCostAuthorityAnomaly(StrictCommercialModel):
    code: StableCode
    path: str
    expected: str | int | bool | None
    observed: str | int | bool | None


class BudgetCostAuthorityAudit(StrictCommercialModel):
    eligible_usage_count: Annotated[StrictInt, Field(ge=0)]
    current_management_total_microusd: StrictInt
    applied_settlement_total_microusd: StrictInt
    late_child_total_microusd: StrictInt
    anomalies: tuple[BudgetCostAuthorityAnomaly, ...]


def audit_budget_cost_authority(
    connection: Any,
    *,
    budget_period_id: int,
    agreement_terms_id: int,
) -> BudgetCostAuthorityAudit:
    """Audit commercial truth independently of the Redis/rebuild projection."""

    with connection.cursor() as cursor:
        # These locks freeze every FK insertion that could change accepted usage,
        # bindings, adjustments, allocations, or settlements for this period.
        cursor.execute(
            """
            SELECT usage.id
              FROM commercial_budget_reservations reservation
              JOIN commercial_usage_events usage
                ON usage.reservation_id = reservation.id
               AND usage.execution_context_id = reservation.execution_context_id
             WHERE reservation.budget_period_id = %s
             ORDER BY usage.id
             FOR UPDATE OF usage
            """,
            (budget_period_id,),
        )
        cursor.fetchall()
        cursor.execute(
            """
            SELECT run.id
              FROM commercial_cost_allocation_runs run
             WHERE EXISTS (
                   SELECT 1
                     FROM commercial_cost_allocations allocation
                     JOIN commercial_usage_events usage
                       ON usage.id = allocation.usage_event_id
                     JOIN commercial_budget_reservations reservation
                       ON reservation.id = usage.reservation_id
                      AND reservation.execution_context_id =
                          usage.execution_context_id
                    WHERE allocation.allocation_run_id = run.id
                      AND reservation.budget_period_id = %s
             )
             ORDER BY run.id
             FOR UPDATE OF run
            """,
            (budget_period_id,),
        )
        cursor.fetchall()
        cursor.execute(
            """
            SELECT pool.id
              FROM commercial_cost_pools pool
             WHERE EXISTS (
                   SELECT 1
                     FROM commercial_cost_allocation_runs run
                     JOIN commercial_cost_allocations allocation
                       ON allocation.allocation_run_id = run.id
                     JOIN commercial_usage_events usage
                       ON usage.id = allocation.usage_event_id
                     JOIN commercial_budget_reservations reservation
                       ON reservation.id = usage.reservation_id
                      AND reservation.execution_context_id =
                          usage.execution_context_id
                    WHERE run.cost_pool_id = pool.id
                      AND reservation.budget_period_id = %s
             )
             ORDER BY pool.id
             FOR UPDATE OF pool
            """,
            (budget_period_id,),
        )
        cursor.fetchall()
        cursor.execute(
            """
            SELECT gate.environment
              FROM commercial_usage_cutover_gates gate
             WHERE EXISTS (
                   SELECT 1
                     FROM commercial_usage_events usage
                     JOIN commercial_budget_reservations reservation
                       ON reservation.id = usage.reservation_id
                      AND reservation.execution_context_id =
                          usage.execution_context_id
                    WHERE reservation.budget_period_id = %s
                      AND usage.environment = gate.environment
             )
             ORDER BY gate.environment
             FOR SHARE OF gate
            """,
            (budget_period_id,),
        )
        cursor.fetchall()
        cursor.execute(
            "SELECT id FROM commercial_agreement_terms WHERE id = %s FOR UPDATE",
            (agreement_terms_id,),
        )
        if cursor.fetchone() is None:
            raise ValueError("budget reconciliation agreement terms are missing")
        cursor.execute(
            """
            WITH usage_facts AS (
                SELECT usage.id AS usage_event_id,
                       usage.event_id,
                       usage.reservation_id,
                       usage.payer_class,
                       usage.pricing_state,
                       usage.usage_state,
                       usage.normalized_shadow_cost_usd,
                       usage.provider_reported_cost_usd,
                       binding.id AS binding_id,
                       binding.reservation_id AS binding_reservation_id,
                       binding.pricing_state AS binding_pricing_state,
                       binding.normalized_cost_usd AS binding_cost_usd,
                       binding.settlement_state,
                       current_cost.current_actual_cash_cost_usd,
                       current_cost.usage_event_id AS current_cost_usage_event_id,
                       (
                           usage.payer_class = 'hank_paid'
                           AND usage.pricing_state = 'priced'
                           AND usage.normalized_shadow_cost_usd IS NOT NULL
                           AND usage.usage_state IN ('succeeded', 'failed_billable')
                       ) AS eligible,
                       CASE WHEN usage.payer_class = 'hank_paid'
                                  AND usage.pricing_state = 'priced'
                                  AND usage.normalized_shadow_cost_usd IS NOT NULL
                                  AND usage.usage_state IN (
                                      'succeeded', 'failed_billable'
                                  )
                            THEN CEIL(GREATEST(
                                usage.normalized_shadow_cost_usd,
                                COALESCE(usage.provider_reported_cost_usd, 0)
                            ) * 1000000)
                       END AS revision_zero_expected,
                       CASE WHEN usage.payer_class = 'hank_paid'
                                  AND usage.pricing_state = 'priced'
                                  AND usage.normalized_shadow_cost_usd IS NOT NULL
                                  AND usage.usage_state IN (
                                      'succeeded', 'failed_billable'
                                  )
                                  AND current_cost.usage_event_id IS NOT NULL
                            THEN CEIL(GREATEST(
                                usage.normalized_shadow_cost_usd,
                                current_cost.current_actual_cash_cost_usd
                            ) * 1000000)
                       END AS current_management_expected
                  FROM commercial_budget_reservations reservation
                  JOIN commercial_usage_events usage
                    ON usage.reservation_id = reservation.id
                   AND usage.execution_context_id = reservation.execution_context_id
                  JOIN commercial_usage_operational_eligibility eligibility
                    ON eligibility.usage_event_id = usage.id
                  LEFT JOIN commercial_usage_settlement_bindings binding
                    ON binding.usage_event_id = usage.event_id
                  LEFT JOIN commercial_usage_current_actual_cost current_cost
                    ON current_cost.usage_event_id = usage.id
                 WHERE reservation.budget_period_id = %s
            ), adjustment_facts AS (
                SELECT adjustment.usage_event_id,
                       COUNT(*) FILTER (
                           WHERE adjustment.adjustment_kind = 'actual_cost'
                       ) AS actual_count,
                       COUNT(*) FILTER (
                           WHERE adjustment.adjustment_kind = 'actual_cost'
                             AND adjustment.amount_usd IS NOT NULL
                             AND adjustment.amount_usd * 1000000
                                 = TRUNC(adjustment.amount_usd * 1000000)
                       ) AS valid_actual_count,
                       COALESCE(SUM(adjustment.amount_usd * 1000000) FILTER (
                           WHERE adjustment.adjustment_kind = 'actual_cost'
                             AND adjustment.amount_usd IS NOT NULL
                             AND adjustment.amount_usd * 1000000
                                 = TRUNC(adjustment.amount_usd * 1000000)
                       ), 0) AS valid_delta,
                       COALESCE(ARRAY_AGG(
                           adjustment.adjustment_id ORDER BY adjustment.adjustment_id
                       ) FILTER (
                           WHERE adjustment.adjustment_kind = 'actual_cost'
                             AND adjustment.amount_usd IS NOT NULL
                             AND adjustment.amount_usd * 1000000
                                 = TRUNC(adjustment.amount_usd * 1000000)
                       ), ARRAY[]::UUID[]) AS authority_ids,
                       COUNT(*) FILTER (
                           WHERE adjustment.adjustment_kind =
                                 'payer_reclassification'
                              OR (
                                  adjustment.adjustment_kind = 'actual_cost'
                                  AND (
                                      adjustment.amount_usd IS NULL
                                      OR adjustment.amount_usd * 1000000
                                         <> TRUNC(
                                             adjustment.amount_usd * 1000000
                                         )
                                  )
                              )
                       ) AS unsupported_count
                  FROM commercial_cost_adjustments adjustment
                  JOIN usage_facts usage
                    ON usage.usage_event_id = adjustment.usage_event_id
                 GROUP BY adjustment.usage_event_id
            ), settlement_facts AS (
                SELECT settlement.usage_event_id,
                       COUNT(*) AS settlement_count,
                       MIN(settlement.cost_revision) AS min_revision,
                       MAX(settlement.cost_revision) AS max_revision,
                       COUNT(*) FILTER (
                           WHERE settlement.cost_revision = 0
                       ) AS revision_zero_count,
                       MAX(settlement.amount_delta_microusd) FILTER (
                           WHERE settlement.cost_revision = 0
                       ) AS revision_zero_amount,
                       COALESCE(SUM(settlement.amount_delta_microusd), 0)
                           AS applied_total,
                       COUNT(DISTINCT settlement.is_late_child)
                           AS late_flag_count,
                       COALESCE(ARRAY_AGG(
                           settlement.cost_adjustment_id
                           ORDER BY settlement.cost_adjustment_id
                       ) FILTER (
                           WHERE settlement.cost_revision > 0
                       ), ARRAY[]::UUID[]) AS consumed_ids
                  FROM commercial_budget_settlements settlement
                  JOIN usage_facts usage
                    ON usage.usage_event_id = settlement.usage_event_id
                 WHERE settlement.budget_period_id = %s
                 GROUP BY settlement.usage_event_id
            )
            SELECT usage.*,
                   COALESCE(adjustment.actual_count, 0) AS actual_count,
                   COALESCE(adjustment.valid_actual_count, 0) AS valid_actual_count,
                   COALESCE(adjustment.valid_delta, 0) AS valid_delta,
                   COALESCE(adjustment.authority_ids, ARRAY[]::UUID[])
                       AS authority_ids,
                   COALESCE(adjustment.unsupported_count, 0) AS unsupported_count,
                   COALESCE(settlement.settlement_count, 0) AS settlement_count,
                   settlement.min_revision,
                   settlement.max_revision,
                   COALESCE(settlement.revision_zero_count, 0)
                       AS revision_zero_count,
                   settlement.revision_zero_amount,
                   COALESCE(settlement.applied_total, 0) AS applied_total,
                   COALESCE(settlement.late_flag_count, 0) AS late_flag_count,
                   COALESCE(settlement.consumed_ids, ARRAY[]::UUID[])
                       AS consumed_ids
              FROM usage_facts usage
              LEFT JOIN adjustment_facts adjustment USING (usage_event_id)
              LEFT JOIN settlement_facts settlement USING (usage_event_id)
             ORDER BY usage.usage_event_id
            """,
            (budget_period_id, budget_period_id),
        )
        columns = tuple(item.name for item in cursor.description)
        usage_rows = [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]
        cursor.execute(
            """
            SELECT COUNT(*)
              FROM commercial_budget_settlements settlement
              LEFT JOIN commercial_cost_adjustments adjustment
                ON adjustment.adjustment_id = settlement.cost_adjustment_id
              JOIN commercial_budget_reservations reservation
                ON reservation.id = settlement.reservation_id
             WHERE settlement.budget_period_id = %s
               AND settlement.cost_revision > 0
               AND (
                   adjustment.adjustment_id IS NULL
                   OR adjustment.usage_event_id IS DISTINCT FROM
                      settlement.usage_event_id
                   OR adjustment.agreement_terms_id IS DISTINCT FROM
                      reservation.agreement_terms_id
                   OR adjustment.adjustment_kind <> 'actual_cost'
                   OR adjustment.amount_usd IS NULL
                   OR adjustment.amount_usd * 1000000 IS DISTINCT FROM
                      settlement.amount_delta_microusd::NUMERIC
                   OR adjustment.reason_code IS DISTINCT FROM settlement.reason_code
                   OR adjustment.actor_type IS DISTINCT FROM settlement.actor_type
                   OR adjustment.actor_id IS DISTINCT FROM settlement.actor_id
               )
            """,
            (budget_period_id,),
        )
        adjustment_mismatch_count = int(cursor.fetchone()[0])
        cursor.execute(
            """
            SELECT COUNT(*)
              FROM commercial_budget_settlements settlement
              LEFT JOIN commercial_budget_events event
                ON event.event_id = settlement.event_id
             WHERE settlement.budget_period_id = %s
               AND (
                   event.id IS NULL
                   OR event.event_kind IS DISTINCT FROM CASE
                       WHEN settlement.cost_revision = 0 THEN 'settle'
                       ELSE 'adjust'
                   END
                   OR ROW(
                       event.budget_period_id, event.reservation_id,
                       event.usage_event_id, event.budget_bucket,
                       event.cost_revision, event.lease_version,
                       event.amount_microusd, event.reason_code,
                       event.actor_type, event.actor_id, event.cost_adjustment_id
                   ) IS DISTINCT FROM ROW(
                       settlement.budget_period_id, settlement.reservation_id,
                       settlement.usage_event_id, settlement.budget_bucket,
                       settlement.cost_revision, settlement.lease_version,
                       settlement.amount_delta_microusd, settlement.reason_code,
                       settlement.actor_type, settlement.actor_id,
                       settlement.cost_adjustment_id
                   )
               )
            """,
            (budget_period_id,),
        )
        event_mismatch_count = int(cursor.fetchone()[0])
        cursor.execute(
            """
            SELECT COUNT(*)
              FROM commercial_budget_events event
              LEFT JOIN commercial_budget_settlements settlement
                ON settlement.event_id = event.event_id
             WHERE event.budget_period_id = %s
               AND event.usage_event_id IS NOT NULL
               AND event.event_kind IN ('settle', 'adjust')
               AND settlement.id IS NULL
            """,
            (budget_period_id,),
        )
        orphan_event_count = int(cursor.fetchone()[0])
        cursor.execute(
            """
            SELECT period.late_child_consumed_microusd,
                   COALESCE(SUM(settlement.amount_delta_microusd) FILTER (
                       WHERE settlement.is_late_child
                   ), 0) AS settlement_late_total
              FROM commercial_budget_periods period
              LEFT JOIN commercial_budget_settlements settlement
                ON settlement.budget_period_id = period.id
             WHERE period.id = %s
             GROUP BY period.id
            """,
            (budget_period_id,),
        )
        late_row = cursor.fetchone()

    anomalies: list[BudgetCostAuthorityAnomaly] = []
    eligible_count = 0
    current_total = 0
    applied_total = 0
    for row in usage_rows:
        path = f"durable.usage.{row['usage_event_id']}"
        binding_ok = (
            row["binding_id"] is not None
            and str(row["binding_reservation_id"]) == str(row["reservation_id"])
            and row["binding_pricing_state"] == row["pricing_state"]
            and row["binding_cost_usd"] == row["normalized_shadow_cost_usd"]
            and row["settlement_state"]
            == f"pending_{row['pricing_state']}"
        )
        if not binding_ok:
            anomalies.append(
                _anomaly(
                    "budget.usage_binding_mismatch",
                    f"{path}.settlement_binding",
                    "exact",
                    "missing_or_mismatched",
                )
            )
        settled_count = int(row["settlement_count"])
        if not row["eligible"]:
            expected_exclusion = (
                row["usage_state"] in {"failed_unbilled", "canceled"}
                and settled_count == 0
            )
            if row["payer_class"] == "hank_paid" and not expected_exclusion:
                anomalies.append(
                    _anomaly(
                        "budget.usage_cost_unresolved",
                        f"{path}.pricing",
                        "eligible_priced_or_unbilled",
                        f"{row['pricing_state']}:{row['usage_state']}",
                    )
                )
            if settled_count != 0:
                anomalies.append(
                    _anomaly(
                        "budget.ineligible_usage_settled",
                        f"{path}.settlements",
                        0,
                        settled_count,
                    )
                )
            continue

        eligible_count += 1
        base = _safe_exact(row["revision_zero_expected"])
        current = _safe_exact(row["current_management_expected"])
        delta = _safe_exact(row["valid_delta"], signed=True)
        applied = _safe_exact(row["applied_total"])
        if None in {base, current, delta, applied}:
            anomalies.append(
                _anomaly(
                    "budget.usage_cost_out_of_bounds",
                    f"{path}.management_cost",
                    "exact_redis_integer",
                    "invalid_or_oversized",
                )
            )
            continue
        current_total += current
        applied_total += applied
        authority_ids = tuple(str(item) for item in row["authority_ids"])
        consumed_ids = tuple(str(item) for item in row["consumed_ids"])
        invariants = (
            ("revision_zero_count", int(row["revision_zero_count"]), 1),
            ("revision_zero_amount", row["revision_zero_amount"], base),
            ("adjustment_validity", int(row["valid_actual_count"]), int(row["actual_count"])),
            ("unsupported_adjustments", int(row["unsupported_count"]), 0),
            ("revision_count", settled_count, 1 + int(row["valid_actual_count"])),
            ("min_revision", row["min_revision"], 0),
            ("max_revision", row["max_revision"], settled_count - 1),
            ("adjustment_authorities", consumed_ids, authority_ids),
            ("applied_authority_total", applied, base + delta),
            ("current_management_total", applied, current),
            ("late_flag_consistency", int(row["late_flag_count"]), 1),
        )
        for name, observed, expected in invariants:
            if observed != expected:
                anomalies.append(
                    _anomaly(
                        "budget.usage_settlement_mismatch",
                        f"{path}.{name}",
                        _evidence_value(expected),
                        _evidence_value(observed),
                    )
                )

    if adjustment_mismatch_count:
        anomalies.append(
            _anomaly(
                "budget.adjustment_settlement_mismatch",
                "durable.adjustment_settlements",
                0,
                adjustment_mismatch_count,
            )
        )
    if event_mismatch_count or orphan_event_count:
        anomalies.append(
            _anomaly(
                "budget.settlement_event_mismatch",
                "durable.settlement_events",
                0,
                event_mismatch_count + orphan_event_count,
            )
        )
    durable_late = _safe_exact(late_row[0]) if late_row is not None else None
    settlement_late = _safe_exact(late_row[1], signed=True) if late_row else None
    if durable_late is None or settlement_late is None or durable_late != settlement_late:
        anomalies.append(
            _anomaly(
                "budget.late_child_total_mismatch",
                "durable.late_child_consumed_microusd",
                _evidence_value(settlement_late),
                _evidence_value(durable_late),
            )
        )
    if (
        abs(current_total) > MAX_SAFE_REDIS_INTEGER
        or abs(applied_total) > MAX_SAFE_REDIS_INTEGER
    ):
        anomalies.append(
            _anomaly(
                "budget.period_cost_out_of_bounds",
                "durable.period_management_cost",
                "exact_redis_integer",
                "oversized",
            )
        )
    return BudgetCostAuthorityAudit(
        eligible_usage_count=eligible_count,
        current_management_total_microusd=current_total,
        applied_settlement_total_microusd=applied_total,
        late_child_total_microusd=durable_late or 0,
        anomalies=tuple(anomalies),
    )


def _safe_exact(value: Any, *, signed: bool = False) -> int | None:
    if value is None:
        return None
    decimal = Decimal(value)
    if decimal != decimal.to_integral_value():
        return None
    parsed = int(decimal)
    lower = -MAX_SAFE_REDIS_INTEGER if signed else 0
    if parsed < lower or parsed > MAX_SAFE_REDIS_INTEGER:
        return None
    return parsed


def _evidence_value(value: Any) -> str | int | bool | None:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, tuple):
        return ",".join(str(item) for item in value)
    return str(value)


def _anomaly(code, path, expected, observed):
    return BudgetCostAuthorityAnomaly(
        code=code,
        path=path,
        expected=expected,
        observed=observed,
    )
