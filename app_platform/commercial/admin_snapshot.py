"""One-statement, secret-safe commercial account snapshot for named operators."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any, Generic, Literal, Mapping, TypeVar
from uuid import UUID

from pydantic import StrictInt

from .errors import CommercialError
from .flags import CommercialFlags
from .models import StrictCommercialModel


class AccountRow(StrictCommercialModel):
    id: StrictInt
    public_id: UUID
    kind: str
    display_name: str
    status: str
    created_at: datetime


class MemberRow(StrictCommercialModel):
    user_id: StrictInt
    role: str
    status: str
    joined_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AgreementTermsRow(StrictCommercialModel):
    agreement_id: StrictInt
    agreement_public_id: UUID
    surface_code: str
    channel: str
    billing_provider: str
    agreement_state: str
    currency: str
    service_start_at: datetime | None
    service_end_at: datetime | None
    agreement_terms_id: StrictInt | None
    terms_revision: StrictInt | None
    offer_code: str | None
    price_code: str | None
    effective_from: datetime | None
    effective_until: datetime | None
    sealed_at: datetime | None


class AgreementItemRow(StrictCommercialModel):
    agreement_item_id: StrictInt
    agreement_terms_id: StrictInt
    item_code: str
    item_kind: str
    price_code: str | None
    quantity: Decimal
    unit_amount_cents: StrictInt
    billing_interval: str | None
    service_start_at: datetime | None
    service_end_at: datetime | None


class EntitlementRow(StrictCommercialModel):
    entitlement_fact_id: StrictInt | None
    revision: StrictInt
    fact_count: StrictInt
    revision_updated_at: datetime
    agreement_id: StrictInt | None
    agreement_terms_id: StrictInt | None
    surface_code: str | None
    subject_kind: str | None
    subject_user_id: StrictInt | None
    source_kind: str | None
    entitlement_key: str | None
    effect: str | None
    value: bool | StrictInt | None
    priority: StrictInt | None
    effective_from: datetime | None
    effective_until: datetime | None
    status: str | None
    reason_code: str | None


class BillingDocumentRow(StrictCommercialModel):
    document_id: StrictInt
    provider: str
    external_document_id: str
    document_kind: str
    currency: str
    issued_at: datetime
    status: str
    status_effective_at: datetime


class BillingLineRow(StrictCommercialModel):
    billing_line_id: StrictInt
    document_id: StrictInt
    external_line_id: str
    agreement_terms_id: StrictInt
    price_code: str | None
    net_consideration_ex_tax_cents: StrictInt
    tax_cents: StrictInt
    service_period_start_at: datetime
    service_period_end_at: datetime


class RevenueAllocationRow(StrictCommercialModel):
    allocation_run_id: StrictInt
    document_id: StrictInt
    run_version: StrictInt
    run_state: str
    finalized_at: datetime | None
    billing_line_id: StrictInt
    period_start_at: datetime
    period_end_at: datetime
    recognized_revenue_cents: StrictInt


class MoneyMovementRow(StrictCommercialModel):
    movement_id: StrictInt
    provider: str
    provider_environment: str
    agreement_id: StrictInt
    document_id: StrictInt | None
    external_object_type: str
    external_object_id: str
    movement_kind: str
    signed_amount_cents: StrictInt
    currency: str
    occurred_at: datetime
    received_at: datetime


class BudgetPeriodRow(StrictCommercialModel):
    budget_period_id: StrictInt
    agreement_terms_id: StrictInt
    period_start_at: datetime
    period_end_at: datetime
    state: str
    model_limit_microusd: StrictInt
    technical_limit_microusd: StrictInt
    max_period_overdraft_microusd: StrictInt
    settled_by_bucket: dict[str, StrictInt]
    current_hold_by_bucket: dict[str, StrictInt]
    overdraw_microusd: StrictInt


class BudgetReservationRow(StrictCommercialModel):
    reservation_id: UUID
    budget_period_id: StrictInt
    agreement_terms_id: StrictInt
    execution_context_id: UUID
    workflow_run_id: UUID | None
    request_id: str
    estimated_cost_microusd: StrictInt
    state: str
    authorized_work_start_deadline: datetime
    expires_at: datetime
    late_child_accept_until: datetime
    created_at: datetime
    reserved_at: datetime | None
    settled_at: datetime | None
    current_hold_by_bucket: dict[str, StrictInt]


class MonthEconomicsRow(StrictCommercialModel):
    agreement_id: StrictInt
    offer_code: str
    service_month: date
    recognized_revenue_usd: Decimal
    realized_revenue_usd: Decimal
    actual_model_provider_cogs_usd: Decimal
    actual_processor_fee_usd: Decimal
    actual_technical_cogs_usd: Decimal
    normalized_shadow_cost_usd: Decimal
    management_technical_cogs_usd: Decimal | None
    direct_service_labor_usd: Decimal
    actual_technical_gross_margin_usd: Decimal
    management_technical_gross_margin_usd: Decimal | None
    managed_contribution_margin_usd: Decimal | None
    unknown_management_cost_event_count: StrictInt
    unallocated_processor_fee_count: StrictInt


class ReconciliationRunRow(StrictCommercialModel):
    run_id: UUID
    suite_code: str
    mode: str
    status: Literal["green", "drift", "blocked", "stale"]
    source_status: Literal["green", "drift", "blocked"]
    finding_count: StrictInt
    snapshot_at: datetime
    created_at: datetime
    age_seconds: StrictInt
    max_age_seconds: Literal[90000]
    freshness_policy: Literal["pilot-reconciliation-daily.v1"]


class ReconciliationFindingRow(StrictCommercialModel):
    finding_id: UUID
    suite_code: str
    code: str
    category: str
    severity: str
    owner: str
    subject_type: str
    subject_id: str
    first_seen_at: datetime
    last_seen_at: datetime
    suggested_repair: str
    repair_kind: str
    resolution_state: str


class IntegrationState(StrictCommercialModel):
    status: Literal["not_installed", "safe_projection_pending"]


RowT = TypeVar("RowT", bound=StrictCommercialModel)


class BoundedSection(StrictCommercialModel, Generic[RowT]):
    rows: tuple[RowT, ...]
    truncated: bool


class CommercialAdminAccountSnapshot(StrictCommercialModel):
    schema_version: Literal["commercial.admin-account-snapshot.v1"]
    environment: Literal["dev", "staging", "prod"]
    commercial_account_id: StrictInt
    snapshot_at: datetime
    account: AccountRow
    members: BoundedSection[MemberRow]
    agreements: BoundedSection[AgreementTermsRow]
    agreement_items: BoundedSection[AgreementItemRow]
    entitlements: BoundedSection[EntitlementRow]
    billing_documents: BoundedSection[BillingDocumentRow]
    billing_lines: BoundedSection[BillingLineRow]
    revenue_allocations: BoundedSection[RevenueAllocationRow]
    money_movements: BoundedSection[MoneyMovementRow]
    budget_periods: BoundedSection[BudgetPeriodRow]
    budget_reservations: BoundedSection[BudgetReservationRow]
    monthly_economics: BoundedSection[MonthEconomicsRow]
    reconciliation_runs: BoundedSection[ReconciliationRunRow]
    reconciliation_findings: BoundedSection[ReconciliationFindingRow]
    external_tokens: IntegrationState
    stripe_sync: IntegrationState
    dlq_health: IntegrationState


_LIMIT = 200
def _section(model: type[RowT], values: list[dict[str, Any]]) -> BoundedSection[RowT]:
    return BoundedSection[RowT](
        rows=tuple(model.model_validate(row) for row in values[:_LIMIT]),
        truncated=len(values) > _LIMIT,
    )


_SNAPSHOT_SQL = r"""
WITH
clock AS MATERIALIZED (
    SELECT statement_timestamp() AS snapshot_at
),
deployment AS MATERIALIZED (
    SELECT environment
      FROM commercial_deployment_context
     WHERE singleton
     FOR SHARE
),
operator_roles AS MATERIALIZED (
    SELECT role
      FROM commercial_operator_role_grants, clock
     WHERE user_id = %(operator_user_id)s
       AND environment = %(environment)s
       AND state = 'active'
       AND granted_at <= clock.snapshot_at
       AND (expires_at IS NULL OR expires_at > clock.snapshot_at)
     FOR SHARE
),
authorized_scope AS MATERIALIZED (
    SELECT %(account_id)s::BIGINT AS account_id
     WHERE EXISTS (
               SELECT 1 FROM deployment WHERE environment = %(environment)s
           )
       AND EXISTS (
               SELECT 1 FROM operator_roles
                WHERE role IN ('commercial_viewer', 'commercial_admin')
           )
),
account AS MATERIALIZED (
    SELECT account.id, account.public_id, account.kind, account.display_name,
           account.status, account.created_at
      FROM commercial_accounts account
      JOIN authorized_scope scope ON scope.account_id = account.id
),
members AS MATERIALIZED (
    SELECT member.user_id, member.role, member.status, member.joined_at,
           member.created_at, member.updated_at
      FROM commercial_account_members member
      JOIN authorized_scope scope
        ON scope.account_id = member.commercial_account_id
     ORDER BY member.user_id LIMIT 201
),
agreements AS MATERIALIZED (
    SELECT agreement.id AS agreement_id,
           agreement.public_id AS agreement_public_id,
           agreement.surface_code, agreement.channel,
           agreement.billing_provider, agreement.state AS agreement_state,
           agreement.currency, agreement.service_start_at,
           agreement.service_end_at, terms.id AS agreement_terms_id,
           terms.revision AS terms_revision, terms.offer_code,
           terms.price_code, terms.effective_from, terms.effective_until,
           terms.sealed_at
      FROM commercial_agreements agreement
      LEFT JOIN commercial_agreement_terms terms
        ON terms.agreement_id = agreement.id
       AND terms.commercial_account_id = agreement.commercial_account_id
      JOIN authorized_scope scope
        ON scope.account_id = agreement.commercial_account_id
     ORDER BY agreement.id, terms.revision LIMIT 201
),
agreement_items AS MATERIALIZED (
    SELECT item.id AS agreement_item_id, item.agreement_terms_id,
           item.item_code, item.item_kind, item.price_code, item.quantity,
           item.unit_amount_cents, item.billing_interval,
           item.service_start_at, item.service_end_at
      FROM commercial_agreement_items item
      JOIN commercial_agreement_terms terms ON terms.id = item.agreement_terms_id
      JOIN authorized_scope scope
        ON scope.account_id = terms.commercial_account_id
     ORDER BY item.agreement_terms_id, item.id LIMIT 201
),
entitlements AS MATERIALIZED (
    SELECT fact.id AS entitlement_fact_id,
           revision.revision, revision.fact_count,
           revision.updated_at AS revision_updated_at,
           fact.agreement_id, fact.agreement_terms_id, fact.surface_code,
           fact.subject_kind, fact.subject_user_id, fact.source_kind,
           fact.entitlement_key, fact.effect, fact.value_json AS value, fact.priority,
           fact.effective_from, fact.effective_until, fact.status,
           fact.reason_code
      FROM commercial_entitlement_revisions revision
      LEFT JOIN commercial_entitlements fact
        ON fact.commercial_account_id = revision.commercial_account_id
       AND fact.entitlement_revision = revision.revision
      JOIN authorized_scope scope
        ON scope.account_id = revision.commercial_account_id
     ORDER BY revision.revision DESC, fact.priority DESC, fact.id
     LIMIT 201
),
billing_documents AS MATERIALIZED (
    SELECT document.id AS document_id, document.provider,
           document.external_document_id, document.document_kind,
           document.currency, document.issued_at,
           current.status, current.status_effective_at
      FROM commercial_billing_documents_current current
      JOIN commercial_billing_documents document ON document.id = current.id
      JOIN authorized_scope scope
        ON scope.account_id = document.commercial_account_id
     ORDER BY document.issued_at DESC, document.id DESC LIMIT 201
),
billing_lines AS MATERIALIZED (
    SELECT line.id AS billing_line_id, line.document_id,
           line.external_line_id, line.agreement_terms_id, line.price_code,
           line.net_consideration_ex_tax_cents, line.tax_cents,
           line.service_period_start_at, line.service_period_end_at
      FROM commercial_billing_lines line
      JOIN authorized_scope scope
        ON scope.account_id = line.commercial_account_id
     ORDER BY line.document_id DESC, line.id LIMIT 201
),
revenue_allocations AS MATERIALIZED (
    SELECT run.id AS allocation_run_id, run.document_id,
           run.version AS run_version, run.state AS run_state,
           run.finalized_at, allocation.billing_line_id,
           allocation.period_start_at, allocation.period_end_at,
           allocation.recognized_revenue_cents
      FROM commercial_revenue_allocation_runs run
      JOIN commercial_revenue_allocations allocation
        ON allocation.allocation_run_id = run.id
       AND allocation.document_id = run.document_id
      JOIN commercial_billing_documents document ON document.id = run.document_id
      JOIN authorized_scope scope
        ON scope.account_id = document.commercial_account_id
     ORDER BY run.document_id DESC, run.version DESC,
              allocation.billing_line_id, allocation.period_start_at
     LIMIT 201
),
money_movements AS MATERIALIZED (
    SELECT id AS movement_id, provider, environment AS provider_environment,
           agreement_id, document_id, external_object_type,
           external_object_id, movement_kind, signed_amount_cents, currency,
           occurred_at, received_at
      FROM commercial_money_movements
      JOIN authorized_scope scope
        ON scope.account_id = commercial_money_movements.commercial_account_id
     ORDER BY occurred_at DESC, id DESC LIMIT 201
),
period_ids AS MATERIALIZED (
    SELECT period.id
      FROM commercial_budget_periods period
      JOIN commercial_agreement_terms terms
        ON terms.id = period.agreement_terms_id
      JOIN authorized_scope scope
        ON scope.account_id = terms.commercial_account_id
),
settled AS MATERIALIZED (
    SELECT settlement.budget_period_id,
           jsonb_object_agg(settlement.budget_bucket, settlement.amount) AS by_bucket
      FROM (
          SELECT budget_period_id, budget_bucket,
                 SUM(amount_delta_microusd)::BIGINT AS amount
            FROM commercial_budget_settlements
           WHERE budget_period_id IN (SELECT id FROM period_ids)
           GROUP BY budget_period_id, budget_bucket
      ) settlement
     GROUP BY settlement.budget_period_id
),
holds AS MATERIALIZED (
    SELECT hold.budget_period_id,
           jsonb_object_agg(hold.budget_bucket, hold.amount) AS by_bucket
      FROM (
          SELECT budget_period_id, budget_bucket,
                 SUM(current_hold_microusd)::BIGINT AS amount
            FROM commercial_budget_current_holds
           WHERE budget_period_id IN (SELECT id FROM period_ids)
           GROUP BY budget_period_id, budget_bucket
      ) hold
     GROUP BY hold.budget_period_id
),
overdraw AS MATERIALIZED (
    SELECT budget_period_id, SUM(amount_microusd)::BIGINT AS amount
      FROM commercial_budget_events
     WHERE budget_period_id IN (SELECT id FROM period_ids)
       AND event_kind = 'overdraw'
     GROUP BY budget_period_id
),
budget_periods AS MATERIALIZED (
    SELECT period.id AS budget_period_id, period.agreement_terms_id,
           period.period_start_at, period.period_end_at, period.state,
           period.model_limit_microusd, period.technical_limit_microusd,
           period.max_period_overdraft_microusd,
           COALESCE(settled.by_bucket, '{}'::jsonb) AS settled_by_bucket,
           COALESCE(holds.by_bucket, '{}'::jsonb) AS current_hold_by_bucket,
           COALESCE(overdraw.amount, 0)::BIGINT AS overdraw_microusd
      FROM commercial_budget_periods period
      LEFT JOIN settled ON settled.budget_period_id = period.id
      LEFT JOIN holds ON holds.budget_period_id = period.id
      LEFT JOIN overdraw ON overdraw.budget_period_id = period.id
     WHERE period.id IN (SELECT id FROM period_ids)
     ORDER BY period.period_start_at DESC, period.id DESC LIMIT 201
),
budget_reservations AS MATERIALIZED (
    SELECT reservation.id AS reservation_id, reservation.budget_period_id,
           reservation.agreement_terms_id, reservation.execution_context_id,
           reservation.workflow_run_id, reservation.request_id,
           reservation.estimated_cost_microusd, reservation.state,
           reservation.authorized_work_start_deadline,
           reservation.expires_at, reservation.late_child_accept_until,
           reservation.created_at, reservation.reserved_at,
           reservation.settled_at,
           COALESCE(holds.by_bucket, '{}'::jsonb) AS current_hold_by_bucket
      FROM commercial_budget_reservations reservation
      LEFT JOIN (
          SELECT reservation_id,
                 jsonb_object_agg(budget_bucket, current_hold_microusd) AS by_bucket
            FROM commercial_budget_current_holds
           WHERE budget_period_id IN (SELECT id FROM period_ids)
           GROUP BY reservation_id
      ) holds ON holds.reservation_id = reservation.id
     WHERE reservation.budget_period_id IN (SELECT id FROM period_ids)
     ORDER BY reservation.created_at DESC, reservation.id LIMIT 201
),
monthly_economics AS MATERIALIZED (
    SELECT agreement_id, offer_code, service_month,
           recognized_revenue_usd, realized_revenue_usd,
           actual_model_provider_cogs_usd, actual_processor_fee_usd,
           actual_technical_cogs_usd, normalized_shadow_cost_usd,
           management_technical_cogs_usd, direct_service_labor_usd,
           actual_technical_gross_margin_usd,
           management_technical_gross_margin_usd,
           managed_contribution_margin_usd,
           unknown_management_cost_event_count,
           unallocated_processor_fee_count
      FROM commercial_account_month_economics
      JOIN authorized_scope scope
        ON scope.account_id = commercial_account_month_economics.commercial_account_id
     ORDER BY service_month DESC, agreement_id, offer_code LIMIT 201
),
reconciliation_runs AS MATERIALIZED (
    SELECT DISTINCT ON (run.suite_code)
           run.run_id, run.suite_code, run.mode,
           CASE WHEN run.snapshot_at < clock.snapshot_at - INTERVAL '25 hours'
                THEN 'stale' ELSE run.status END AS status,
           run.status AS source_status,
           run.finding_count, run.snapshot_at, run.created_at,
           GREATEST(
               0, EXTRACT(EPOCH FROM (clock.snapshot_at - run.snapshot_at))::BIGINT
           ) AS age_seconds,
           90000::BIGINT AS max_age_seconds,
           'pilot-reconciliation-daily.v1'::TEXT AS freshness_policy
      FROM commercial_reconciliation_runs run CROSS JOIN clock
      JOIN authorized_scope scope
        ON scope.account_id = run.commercial_account_id
     WHERE run.environment = %(environment)s
       AND run.scope_type = 'account'
     ORDER BY run.suite_code, run.snapshot_at DESC, run.run_id DESC LIMIT 201
),
reconciliation_findings AS MATERIALIZED (
    SELECT finding.finding_id, finding.suite_code, finding.code,
           finding.category, finding.severity,
           finding.owner, finding.subject_type, finding.subject_id,
           finding.first_seen_at, finding.last_seen_at,
           suggested_repair, repair_kind, resolution_state
      FROM commercial_reconciliation_current_findings finding
      JOIN authorized_scope scope
        ON scope.account_id = finding.commercial_account_id
     WHERE finding.environment = %(environment)s
     ORDER BY CASE finding.severity
                  WHEN 'critical' THEN 0 WHEN 'error' THEN 1 ELSE 2
              END,
              finding.last_seen_at DESC, finding.suite_code, finding.code,
              finding.subject_type, finding.subject_id, finding.finding_id
     LIMIT 201
)
SELECT clock.snapshot_at,
       EXISTS (
           SELECT 1 FROM deployment WHERE environment = %(environment)s
       ) AS deployment_matches,
       EXISTS (
           SELECT 1 FROM operator_roles
            WHERE role IN ('commercial_viewer', 'commercial_admin')
       ) AS authorized,
       (SELECT to_jsonb(account) FROM account) AS account,
       (SELECT COALESCE(jsonb_agg(to_jsonb(members) ORDER BY members.user_id),
                        '[]'::jsonb) FROM members)
           AS members,
       (SELECT COALESCE(jsonb_agg(to_jsonb(agreements)
                                 ORDER BY agreements.agreement_id,
                                          agreements.terms_revision),
                        '[]'::jsonb) FROM agreements)
           AS agreements,
       (SELECT COALESCE(jsonb_agg(to_jsonb(agreement_items)
                                 ORDER BY agreement_items.agreement_terms_id,
                                          agreement_items.agreement_item_id),
                        '[]'::jsonb)
          FROM agreement_items) AS agreement_items,
       (SELECT COALESCE(jsonb_agg(to_jsonb(entitlements)
                                 ORDER BY entitlements.revision DESC,
                                          entitlements.priority DESC,
                                          entitlements.entitlement_fact_id),
                        '[]'::jsonb)
          FROM entitlements) AS entitlements,
       (SELECT COALESCE(jsonb_agg(to_jsonb(billing_documents)
                                 ORDER BY billing_documents.issued_at DESC,
                                          billing_documents.document_id DESC),
                        '[]'::jsonb)
          FROM billing_documents) AS billing_documents,
       (SELECT COALESCE(jsonb_agg(to_jsonb(billing_lines)
                                 ORDER BY billing_lines.document_id DESC,
                                          billing_lines.billing_line_id),
                        '[]'::jsonb)
          FROM billing_lines) AS billing_lines,
       (SELECT COALESCE(jsonb_agg(to_jsonb(revenue_allocations)
                                 ORDER BY revenue_allocations.document_id DESC,
                                          revenue_allocations.run_version DESC,
                                          revenue_allocations.billing_line_id,
                                          revenue_allocations.period_start_at),
                        '[]'::jsonb)
          FROM revenue_allocations) AS revenue_allocations,
       (SELECT COALESCE(jsonb_agg(to_jsonb(money_movements)
                                 ORDER BY money_movements.occurred_at DESC,
                                          money_movements.movement_id DESC),
                        '[]'::jsonb)
          FROM money_movements) AS money_movements,
       (SELECT COALESCE(jsonb_agg(to_jsonb(budget_periods)
                                 ORDER BY budget_periods.period_start_at DESC,
                                          budget_periods.budget_period_id DESC),
                        '[]'::jsonb)
          FROM budget_periods) AS budget_periods,
       (SELECT COALESCE(jsonb_agg(to_jsonb(budget_reservations)
                                 ORDER BY budget_reservations.created_at DESC,
                                          budget_reservations.reservation_id),
                        '[]'::jsonb)
          FROM budget_reservations) AS budget_reservations,
       (SELECT COALESCE(jsonb_agg(to_jsonb(monthly_economics)
                                 ORDER BY monthly_economics.service_month DESC,
                                          monthly_economics.agreement_id,
                                          monthly_economics.offer_code),
                        '[]'::jsonb)
          FROM monthly_economics) AS monthly_economics,
       (SELECT COALESCE(jsonb_agg(to_jsonb(reconciliation_runs)
                                 ORDER BY reconciliation_runs.suite_code),
                        '[]'::jsonb)
          FROM reconciliation_runs) AS reconciliation_runs,
       (SELECT COALESCE(jsonb_agg(to_jsonb(reconciliation_findings)
                                 ORDER BY CASE reconciliation_findings.severity
                                              WHEN 'critical' THEN 0
                                              WHEN 'error' THEN 1 ELSE 2
                                          END,
                                          reconciliation_findings.last_seen_at DESC,
                                          reconciliation_findings.suite_code,
                                          reconciliation_findings.code,
                                          reconciliation_findings.subject_type,
                                          reconciliation_findings.subject_id,
                                          reconciliation_findings.finding_id),
                        '[]'::jsonb)
          FROM reconciliation_findings) AS reconciliation_findings,
       to_regclass('mcp_tokens') IS NOT NULL AS tokens_installed,
       to_regclass('billing_provider_customers') IS NOT NULL AS stripe_installed
  FROM clock
"""


_RESULT_COLUMNS = (
    "snapshot_at",
    "deployment_matches",
    "authorized",
    "account",
    "members",
    "agreements",
    "agreement_items",
    "entitlements",
    "billing_documents",
    "billing_lines",
    "revenue_allocations",
    "money_movements",
    "budget_periods",
    "budget_reservations",
    "monthly_economics",
    "reconciliation_runs",
    "reconciliation_findings",
    "tokens_installed",
    "stripe_installed",
)


class CommercialAdminSnapshotService:
    def __init__(self, connection: object, *, flags: CommercialFlags) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags

    def render_account_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        commercial_account_id: int,
    ) -> CommercialAdminAccountSnapshot:
        if not self._flags.commercial_control_enabled:
            raise ValueError("commercial control is disabled")
        if runtime_environment != self._flags.environment:
            raise ValueError("commercial admin environment mismatch")
        if commercial_account_id <= 0:
            raise ValueError("commercial account id must be positive")
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                _SNAPSHOT_SQL,
                {
                    "operator_user_id": operator_user_id,
                    "environment": runtime_environment,
                    "account_id": commercial_account_id,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError("commercial admin snapshot returned no result")
        values = (
            {column: row[column] for column in _RESULT_COLUMNS}
            if isinstance(row, Mapping)
            else dict(zip(_RESULT_COLUMNS, row, strict=True))
        )
        if not values["deployment_matches"]:
            raise CommercialError("commercial_account_access_denied")
        if not values["authorized"]:
            raise CommercialError("commercial_role_required")
        if values["account"] is None:
            raise CommercialError("commercial_account_not_found")
        token_status = (
            "safe_projection_pending" if values["tokens_installed"] else "not_installed"
        )
        stripe_status = (
            "safe_projection_pending" if values["stripe_installed"] else "not_installed"
        )
        return CommercialAdminAccountSnapshot(
            schema_version="commercial.admin-account-snapshot.v1",
            environment=runtime_environment,
            commercial_account_id=commercial_account_id,
            snapshot_at=values["snapshot_at"],
            account=AccountRow.model_validate(values["account"]),
            members=_section(MemberRow, values["members"]),
            agreements=_section(AgreementTermsRow, values["agreements"]),
            agreement_items=_section(AgreementItemRow, values["agreement_items"]),
            entitlements=_section(EntitlementRow, values["entitlements"]),
            billing_documents=_section(
                BillingDocumentRow, values["billing_documents"]
            ),
            billing_lines=_section(BillingLineRow, values["billing_lines"]),
            revenue_allocations=_section(
                RevenueAllocationRow, values["revenue_allocations"]
            ),
            money_movements=_section(MoneyMovementRow, values["money_movements"]),
            budget_periods=_section(BudgetPeriodRow, values["budget_periods"]),
            budget_reservations=_section(
                BudgetReservationRow, values["budget_reservations"]
            ),
            monthly_economics=_section(
                MonthEconomicsRow, values["monthly_economics"]
            ),
            reconciliation_runs=_section(
                ReconciliationRunRow, values["reconciliation_runs"]
            ),
            reconciliation_findings=_section(
                ReconciliationFindingRow,
                values["reconciliation_findings"],
            ),
            external_tokens=IntegrationState(status=token_status),
            stripe_sync=IntegrationState(status=stripe_status),
            dlq_health=IntegrationState(status="not_installed"),
        )


__all__ = ["CommercialAdminAccountSnapshot", "CommercialAdminSnapshotService"]
