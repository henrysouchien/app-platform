"""Named-operator weekly report for the immutable initial commercial pilot."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, JsonValue, StrictInt

from .authority import CommercialRole
from .authority_store import load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags, get_commercial_flags
from .models import StableCode, StrictCommercialModel


class PilotReportFinding(StrictCommercialModel):
    suite_code: StableCode
    scope_type: Literal["account", "environment"]
    scope_id: str
    code: StableCode
    severity: Literal["warning", "error", "critical"]
    owner: StableCode
    subject_type: StableCode
    subject_id: str
    suggested_repair: StableCode
    repair_kind: Literal["automatic", "operator", "investigate", "none"]
    resolution_state: Literal["open", "resolved", "accepted_risk", "false_positive"]
    last_seen_at: AwareDatetime
    resolution_reason_code: StableCode | None = None
    resolution_actor_user_id: Annotated[StrictInt, Field(gt=0)] | None = None
    resolved_at: AwareDatetime | None = None


class PilotReconciliationStatus(StrictCommercialModel):
    status: Literal["missing", "green", "drift", "blocked", "stale"]
    source_status: Literal["green", "drift", "blocked"] | None = None
    snapshot_at: AwareDatetime | None = None
    finding_count: Annotated[StrictInt, Field(ge=0)]
    age_seconds: Annotated[StrictInt, Field(ge=0)] | None = None
    max_age_seconds: Literal[90000] = 90000
    freshness_policy: Literal["pilot-reconciliation-daily.v1"] = (
        "pilot-reconciliation-daily.v1"
    )
    owner: StableCode | None = None
    suggested_action: StableCode | None = None


class PilotWeeklyReport(StrictCommercialModel):
    schema_version: Literal["commercial.pilot-weekly-report.v2"] = (
        "commercial.pilot-weekly-report.v2"
    )
    snapshot_at: AwareDatetime
    environment: Literal["dev", "staging", "prod"]
    week_start: date
    week_end: date
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    agreement_terms_id: Annotated[StrictInt, Field(gt=0)]
    offer_code: StableCode
    surface_code: StableCode
    contracted_service_period_cents: Annotated[StrictInt, Field(ge=0)]
    economics: dict[str, JsonValue] | None
    economics_attribution: dict[str, JsonValue]
    usage: dict[str, JsonValue] | None
    workflow: dict[str, JsonValue] | None
    budget: dict[str, JsonValue] | None
    retry_count: Annotated[StrictInt, Field(ge=0)] | None = None
    retry_observability: Literal["available", "unavailable"] = "unavailable"
    account_reconciliation: PilotReconciliationStatus
    provider_reconciliation: PilotReconciliationStatus
    findings: tuple[PilotReportFinding, ...]


class PilotWeeklyReportService:
    """Render one report snapshot after resolving named viewer authority."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags | None = None,
    ) -> None:
        self._connection = connection
        self._flags = flags or get_commercial_flags()
        self._flags.validate()

    def render_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        week_start: date,
    ) -> PilotWeeklyReport:
        if week_start.isoweekday() != 1:
            raise ValueError("pilot report week_start must be a UTC Monday")
        if runtime_environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_reconciliation_enabled
        ):
            raise RuntimeError("commercial pilot reporting is disabled")
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=runtime_environment,
        )
        if not operator.roles.intersection(
            {CommercialRole.COMMERCIAL_VIEWER, CommercialRole.COMMERCIAL_ADMIN}
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                WITH snapshot AS (
                    SELECT commercial_pilot_report_clock() AS evaluated_at
                ), scope AS (
                    SELECT * FROM commercial_initial_pilot_scope
                     WHERE environment = %s
                       AND service_start_at < (
                           (%s::date + 7)::timestamp AT TIME ZONE 'UTC'
                       )
                       AND service_end_at > (
                           %s::date::timestamp AT TIME ZONE 'UTC'
                       )
                ), account_run AS (
                    SELECT CASE
                               WHEN run.snapshot_at < snapshot.evaluated_at
                                    - INTERVAL '25 hours' THEN 'stale'
                               ELSE run.status
                           END AS status,
                           run.status AS source_status,
                           run.snapshot_at, run.finding_count,
                           GREATEST(0, FLOOR(EXTRACT(EPOCH FROM
                               snapshot.evaluated_at - run.snapshot_at
                           )))::BIGINT AS age_seconds,
                           90000 AS max_age_seconds,
                           'pilot-reconciliation-daily.v1'::TEXT
                               AS freshness_policy,
                           CASE WHEN run.snapshot_at < snapshot.evaluated_at
                                          - INTERVAL '25 hours'
                                THEN 'commercial.platform' END AS owner,
                           CASE WHEN run.snapshot_at < snapshot.evaluated_at
                                          - INTERVAL '25 hours'
                                THEN 'reconciliation.run_account' END
                               AS suggested_action
                      FROM commercial_reconciliation_runs run
                      JOIN scope ON run.commercial_account_id = scope.commercial_account_id
                      CROSS JOIN snapshot
                     WHERE run.environment = scope.environment
                       AND run.suite_code = 'billing_revenue_economics.v1'
                       AND run.scope_type = 'account'
                       AND run.scope_id = scope.commercial_account_id::TEXT
                     ORDER BY run.snapshot_at DESC, run.run_id DESC LIMIT 1
                ), provider_run AS (
                    SELECT CASE
                               WHEN run.snapshot_at < snapshot.evaluated_at
                                    - INTERVAL '25 hours' THEN 'stale'
                               ELSE run.status
                           END AS status,
                           run.status AS source_status,
                           run.snapshot_at, run.finding_count,
                           GREATEST(0, FLOOR(EXTRACT(EPOCH FROM
                               snapshot.evaluated_at - run.snapshot_at
                           )))::BIGINT AS age_seconds,
                           90000 AS max_age_seconds,
                           'pilot-reconciliation-daily.v1'::TEXT
                               AS freshness_policy,
                           CASE WHEN run.snapshot_at < snapshot.evaluated_at
                                          - INTERVAL '25 hours'
                                THEN 'finance_operations' END AS owner,
                           CASE WHEN run.snapshot_at < snapshot.evaluated_at
                                          - INTERVAL '25 hours'
                                THEN 'reconciliation.run_provider_cost' END
                               AS suggested_action
                      FROM commercial_reconciliation_runs run
                      JOIN scope ON TRUE
                      CROSS JOIN snapshot
                     WHERE run.environment = scope.environment
                       AND run.suite_code = 'provider_cost_allocation.v1'
                       AND run.scope_type = 'environment'
                       AND run.scope_id = scope.environment
                     ORDER BY run.snapshot_at DESC, run.run_id DESC LIMIT 1
                ), current_findings AS (
                    SELECT finding.suite_code, finding.scope_type, finding.scope_id,
                           finding.code, finding.severity, finding.owner,
                           finding.subject_type, finding.subject_id,
                           finding.suggested_repair, finding.repair_kind,
                           finding.resolution_state, finding.last_seen_at,
                           finding.resolution_reason_code,
                           finding.resolution_actor_user_id,
                           finding.resolved_at
                      FROM commercial_reconciliation_current_findings finding
                      JOIN scope ON finding.environment = scope.environment
                     WHERE (
                         finding.suite_code = 'billing_revenue_economics.v1'
                         AND finding.scope_type = 'account'
                         AND finding.scope_id = scope.commercial_account_id::TEXT
                     ) OR (
                         finding.suite_code = 'provider_cost_allocation.v1'
                         AND finding.scope_type = 'environment'
                         AND finding.scope_id = scope.environment
                     )
                )
                SELECT snapshot.evaluated_at, scope.environment,
                       scope.commercial_account_id, scope.agreement_id,
                       scope.agreement_terms_id, scope.offer_code,
                       scope.surface_code, scope.contracted_service_period_cents,
                       (SELECT to_jsonb(economics) FROM
                            commercial_initial_pilot_week_economics economics
                         WHERE economics.week_start = %s
                           AND economics.terms_attribution_state = 'exact'),
                       COALESCE((
                           SELECT jsonb_build_object(
                               'state', economics.terms_attribution_state,
                               'incomplete_day_count',
                                   economics.terms_attribution_incomplete_day_count
                           )
                             FROM commercial_initial_pilot_week_economics economics
                            WHERE economics.week_start = %s
                       ), '{"state":"exact","incomplete_day_count":0}'::jsonb),
                       (SELECT to_jsonb(usage) FROM
                            commercial_initial_pilot_week_usage usage
                         WHERE usage.week_start = %s),
                       (SELECT to_jsonb(workflow) FROM
                            commercial_initial_pilot_week_workflow workflow
                         WHERE workflow.week_start = %s),
                       (SELECT to_jsonb(budget) FROM
                            commercial_initial_pilot_budget_economics budget
                         WHERE budget.period_start_at < %s::date + 7
                           AND budget.period_end_at > %s::date
                         ORDER BY budget.period_start_at DESC LIMIT 1),
                       (SELECT retry.retry_count FROM
                            commercial_initial_pilot_week_retry retry
                         WHERE retry.week_start = %s),
                       COALESCE((SELECT retry.retry_observability FROM
                            commercial_initial_pilot_week_retry retry
                         WHERE retry.week_start = %s), 'unavailable'),
                       COALESCE((SELECT to_jsonb(account_run) FROM account_run),
                                '{"status":"missing","source_status":null,"snapshot_at":null,"finding_count":0,"age_seconds":null,"max_age_seconds":90000,"freshness_policy":"pilot-reconciliation-daily.v1","owner":"commercial.platform","suggested_action":"reconciliation.run_account"}'::jsonb),
                       COALESCE((SELECT to_jsonb(provider_run) FROM provider_run),
                                '{"status":"missing","source_status":null,"snapshot_at":null,"finding_count":0,"age_seconds":null,"max_age_seconds":90000,"freshness_policy":"pilot-reconciliation-daily.v1","owner":"finance_operations","suggested_action":"reconciliation.run_provider_cost"}'::jsonb),
                       COALESCE((SELECT jsonb_agg(to_jsonb(current_findings)
                                                ORDER BY
                                                    CASE severity
                                                        WHEN 'critical' THEN 1
                                                        WHEN 'error' THEN 2
                                                        ELSE 3
                                                    END,
                                                    code, subject_id)
                                   FROM current_findings), '[]'::jsonb)
                  FROM scope CROSS JOIN snapshot
                """,
                (
                    runtime_environment,
                    week_start,
                    week_start,
                    week_start,
                    week_start,
                    week_start,
                    week_start,
                    week_start,
                    week_start,
                    week_start,
                    week_start,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT
            )

        account_status = dict(row[15])
        provider_status = dict(row[16])
        return PilotWeeklyReport(
            snapshot_at=row[0],
            environment=row[1],
            week_start=week_start,
            week_end=week_start + timedelta(days=7),
            commercial_account_id=int(row[2]),
            agreement_id=int(row[3]),
            agreement_terms_id=int(row[4]),
            offer_code=row[5],
            surface_code=row[6],
            contracted_service_period_cents=int(row[7]),
            economics=row[8],
            economics_attribution=row[9],
            usage=row[10],
            workflow=row[11],
            budget=row[12],
            retry_count=int(row[13]) if row[13] is not None else None,
            retry_observability=row[14],
            account_reconciliation=PilotReconciliationStatus.model_validate(
                account_status
            ),
            provider_reconciliation=PilotReconciliationStatus.model_validate(
                provider_status
            ),
            findings=tuple(PilotReportFinding.model_validate(item) for item in row[17]),
        )


__all__ = [
    "PilotReportFinding",
    "PilotReconciliationStatus",
    "PilotWeeklyReport",
    "PilotWeeklyReportService",
]
