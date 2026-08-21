"""Append-only commercial reconciliation evidence and billing/economics checks."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from functools import wraps
import json
from typing import Annotated, Literal, TypeVar
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, JsonValue, StrictBool, StrictInt, StrictStr

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import CommercialRole
from .authority_store import load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags, get_commercial_flags
from .models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .billing.stripe_reconciliation import (
    StripeAccountObservation,
    StripeMonetaryObservation,
)


BILLING_REVENUE_ECONOMICS_SUITE = "billing_revenue_economics.v1"
PROVIDER_COST_ALLOCATION_SUITE = "provider_cost_allocation.v1"
STRIPE_PROVIDER_RECONCILIATION_SUITE = "stripe_provider.v1"
STRIPE_MONETARY_RECONCILIATION_SUITE = "stripe_monetary.v1"
STRIPE_WEBHOOK_INBOX_RECONCILIATION_SUITE = "stripe_webhook_inbox.v1"
RuntimeEnvironment = Literal["dev", "staging", "prod"]
FindingSeverity = Literal["warning", "error", "critical"]
RepairKind = Literal["automatic", "operator", "investigate", "none"]
ResolutionKind = Literal["resolved", "accepted_risk", "false_positive"]


class ReconciliationFinding(StrictCommercialModel):
    finding_id: UUID
    fingerprint_sha256: Sha256Digest
    code: StableCode
    category: StableCode
    severity: FindingSeverity
    owner: StableCode
    subject_type: StableCode
    subject_id: Annotated[StrictStr, Field(min_length=1, max_length=512)]
    expected: dict[str, JsonValue]
    observed: dict[str, JsonValue]
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    suggested_repair: StableCode
    repair_kind: RepairKind


class BillingReconciliationCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    reason_code: StableCode


class BillingReconciliationResult(StrictCommercialModel):
    run_id: UUID
    environment: RuntimeEnvironment
    suite_code: Literal["billing_revenue_economics.v1"] = (
        BILLING_REVENUE_ECONOMICS_SUITE
    )
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    billing_environments: tuple[Literal["internal", "test", "live"], ...]
    idempotency_key: IdempotencyKey
    status: Literal["green", "drift", "blocked"]
    snapshot_at: AwareDatetime
    findings: tuple[ReconciliationFinding, ...]
    durable_replayed: StrictBool = False


class StripeProviderReconciliationCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    reason_code: StableCode


class StripeProviderReconciliationResult(StrictCommercialModel):
    run_id: UUID
    environment: RuntimeEnvironment
    suite_code: Literal["stripe_provider.v1"] = STRIPE_PROVIDER_RECONCILIATION_SUITE
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    billing_environment: Literal["test", "live"]
    idempotency_key: IdempotencyKey
    status: Literal["green", "drift", "blocked"]
    snapshot_at: AwareDatetime
    findings: tuple[ReconciliationFinding, ...]
    durable_replayed: StrictBool = False


class StripeMonetaryReconciliationCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    reason_code: StableCode


class StripeMonetaryReconciliationResult(StrictCommercialModel):
    run_id: UUID
    environment: RuntimeEnvironment
    suite_code: Literal["stripe_monetary.v1"] = STRIPE_MONETARY_RECONCILIATION_SUITE
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    billing_environment: Literal["test", "live"]
    idempotency_key: IdempotencyKey
    status: Literal["green", "drift", "blocked"]
    snapshot_at: AwareDatetime
    findings: tuple[ReconciliationFinding, ...]
    durable_replayed: StrictBool = False


class StripeWebhookInboxReconciliationCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    reason_code: StableCode


class StripeWebhookInboxReconciliationResult(StrictCommercialModel):
    run_id: UUID
    environment: RuntimeEnvironment
    suite_code: Literal["stripe_webhook_inbox.v1"] = (
        STRIPE_WEBHOOK_INBOX_RECONCILIATION_SUITE
    )
    billing_environment: Literal["test", "live"]
    idempotency_key: IdempotencyKey
    status: Literal["green", "drift", "blocked"]
    snapshot_at: AwareDatetime
    findings: tuple[ReconciliationFinding, ...]
    durable_replayed: StrictBool = False


class ProviderCostReconciliationCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    reason_code: StableCode


class ProviderCostReconciliationResult(StrictCommercialModel):
    run_id: UUID
    environment: RuntimeEnvironment
    suite_code: Literal["provider_cost_allocation.v1"] = (
        PROVIDER_COST_ALLOCATION_SUITE
    )
    idempotency_key: IdempotencyKey
    status: Literal["green", "drift", "blocked"]
    snapshot_at: AwareDatetime
    findings: tuple[ReconciliationFinding, ...]
    durable_replayed: StrictBool = False


class ReconciliationResolutionCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    source_finding_id: UUID
    resolution_kind: ResolutionKind
    reason_code: StableCode
    note_redacted: Annotated[StrictStr, Field(min_length=1, max_length=2000)] | None = (
        None
    )


class ReconciliationResolutionResult(StrictCommercialModel):
    resolution_id: UUID
    source_finding_id: UUID
    fingerprint_sha256: Sha256Digest
    environment: RuntimeEnvironment
    suite_code: Literal["billing_revenue_economics.v1"] = (
        BILLING_REVENUE_ECONOMICS_SUITE
    )
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    resolution_kind: ResolutionKind
    reason_code: StableCode
    actor_user_id: Annotated[StrictInt, Field(gt=0)]
    audit_event_id: UUID
    resolved_at: AwareDatetime
    durable_replayed: StrictBool = False


class ProviderCostResolutionCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    source_finding_id: UUID
    resolution_kind: ResolutionKind
    reason_code: StableCode
    note_redacted: Annotated[StrictStr, Field(min_length=1, max_length=2000)] | None = (
        None
    )


class ProviderCostResolutionResult(StrictCommercialModel):
    resolution_id: UUID
    source_finding_id: UUID
    fingerprint_sha256: Sha256Digest
    environment: RuntimeEnvironment
    suite_code: Literal["provider_cost_allocation.v1"] = (
        PROVIDER_COST_ALLOCATION_SUITE
    )
    resolution_kind: ResolutionKind
    reason_code: StableCode
    actor_user_id: Annotated[StrictInt, Field(gt=0)]
    audit_event_id: UUID
    resolved_at: AwareDatetime
    durable_replayed: StrictBool = False


_ResultT = TypeVar("_ResultT")


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class CommercialReconciliationService:
    """Run dry-run reports and explicitly resolve their latest observations."""

    def __init__(
        self, connection: object, *, flags: CommercialFlags | None = None
    ) -> None:
        self._connection = connection
        self._flags = flags or get_commercial_flags()
        self._flags.validate()

    @_atomic
    def reconcile_billing_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: BillingReconciliationCommand,
    ) -> BillingReconciliationResult:
        """Persist one account audit from a single PostgreSQL statement snapshot."""

        self._require_operator(
            operator_user_id,
            runtime_environment,
            required_role=CommercialRole.COMMERCIAL_VIEWER,
        )
        billing_environment = self._billing_environment()
        command_sha256 = canonical_sha256(
            {
                "schema": "commercial.reconciliation.billing-command.v1",
                "environment": runtime_environment,
                "suite_code": BILLING_REVENUE_ECONOMICS_SUITE,
                "billing_environments": ["internal", billing_environment],
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
            }
        )
        self._advisory_lock(runtime_environment, command.commercial_account_id)
        replay = self._load_run(
            runtime_environment, command, command_sha256=command_sha256
        )
        if replay is not None:
            return replay
        self._require_account(command.commercial_account_id)

        run_id = uuid4()
        snapshot_at, status, raw_findings = self._billing_snapshot(
            runtime_environment,
            command.commercial_account_id,
            billing_environment=billing_environment,
            run_id=run_id,
            idempotency_key=command.idempotency_key,
            command_sha256=command_sha256,
            reason_code=command.reason_code,
            actor_user_id=operator_user_id,
        )
        findings = tuple(
            self._finding_from_snapshot(
                runtime_environment,
                command.commercial_account_id,
                snapshot_at,
                raw,
            )
            for raw in raw_findings
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            for finding in findings:
                cursor.execute(
                    """
                    INSERT INTO commercial_reconciliation_findings (
                        finding_id, run_id, fingerprint_sha256, code, category,
                        severity, owner, subject_type, subject_id,
                        expected, observed, first_seen_at, last_seen_at,
                        suggested_repair, repair_kind
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s, %s, %s, %s
                    )
                    """,
                    (
                        str(finding.finding_id),
                        str(run_id),
                        finding.fingerprint_sha256,
                        finding.code,
                        finding.category,
                        finding.severity,
                        finding.owner,
                        finding.subject_type,
                        finding.subject_id,
                        json.dumps(
                            finding.expected, sort_keys=True, separators=(",", ":")
                        ),
                        json.dumps(
                            finding.observed, sort_keys=True, separators=(",", ":")
                        ),
                        finding.first_seen_at,
                        finding.last_seen_at,
                        finding.suggested_repair,
                        finding.repair_kind,
                    ),
                )
        finally:
            cursor.close()
        return BillingReconciliationResult(
            run_id=run_id,
            environment=runtime_environment,
            commercial_account_id=command.commercial_account_id,
            billing_environments=("internal", billing_environment),
            idempotency_key=command.idempotency_key,
            status=status,
            snapshot_at=snapshot_at,
            findings=findings,
        )

    @_atomic
    def reconcile_stripe_provider_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: StripeProviderReconciliationCommand,
        observation: StripeAccountObservation,
    ) -> StripeProviderReconciliationResult:
        """Compare normalized Stripe customer/subscription evidence without repairs."""

        self._require_operator(
            operator_user_id, runtime_environment,
            required_role=CommercialRole.COMMERCIAL_VIEWER,
        )
        billing_environment = self._billing_environment()
        if observation.environment != billing_environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        observation_body = observation.model_dump(
            mode="json", exclude={"content_sha256", "observed_at"}
        )
        if canonical_sha256(observation_body) != observation.content_sha256:
            raise ValueError("Stripe reconciliation observation digest mismatch")
        command_sha256 = canonical_sha256({
            "schema": "commercial.reconciliation.stripe-provider-command.v1",
            "environment": runtime_environment,
            "billing_environment": billing_environment,
            "command": command.model_dump(mode="python", exclude={"idempotency_key"}),
            "observation_sha256": observation.content_sha256,
        })
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (
                    "commercial_reconciliation_account",
                    f"{runtime_environment}:{STRIPE_PROVIDER_RECONCILIATION_SUITE}:"
                    f"{command.commercial_account_id}",
                ),
            )
            cursor.execute(
                """SELECT run_id, status, snapshot_at, command_sha256
                     FROM commercial_reconciliation_runs
                    WHERE environment = %s AND suite_code = %s
                      AND scope_type = 'account' AND scope_id = %s
                      AND idempotency_key = %s""",
                (
                    runtime_environment, STRIPE_PROVIDER_RECONCILIATION_SUITE,
                    str(command.commercial_account_id), command.idempotency_key,
                ),
            )
            replay = cursor.fetchone()
            if replay is not None:
                if replay[3] != command_sha256:
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT
                    )
                cursor.execute(
                    """SELECT finding_id, fingerprint_sha256, code, category,
                              severity, owner, subject_type, subject_id,
                              expected, observed, first_seen_at, last_seen_at,
                              suggested_repair, repair_kind
                         FROM commercial_reconciliation_findings
                        WHERE run_id = %s ORDER BY code, subject_type, subject_id""",
                    (str(replay[0]),),
                )
                return StripeProviderReconciliationResult(
                    run_id=UUID(str(replay[0])), environment=runtime_environment,
                    commercial_account_id=command.commercial_account_id,
                    billing_environment=billing_environment,
                    idempotency_key=command.idempotency_key, status=replay[1],
                    snapshot_at=replay[2],
                    findings=tuple(
                        self._finding_from_row(row) for row in cursor.fetchall()
                    ), durable_replayed=True,
                )
            expected = self._stripe_local_expectation(
                cursor, command.commercial_account_id,
                billing_environment=billing_environment,
            )
            raw_findings = self._stripe_provider_findings(expected, observation)
            cursor.execute("SELECT statement_timestamp()")
            snapshot_at = cursor.fetchone()[0]
            findings = tuple(sorted((
                self._stripe_finding(
                    runtime_environment, command.commercial_account_id,
                    snapshot_at, raw,
                ) for raw in raw_findings
            ), key=lambda item: (item.code, item.subject_type, item.subject_id)))
            status = (
                "blocked" if any(item.severity == "critical" for item in findings)
                else "drift" if findings else "green"
            )
            run_id = uuid4()
            cursor.execute(
                """INSERT INTO commercial_reconciliation_runs (
                       run_id, environment, suite_code, scope_type, scope_id,
                       commercial_account_id, idempotency_key, command_sha256,
                       mode, status, finding_count, actor_user_id, snapshot_at, metadata
                   ) VALUES (%s,%s,%s,'account',%s,%s,%s,%s,'dry_run',%s,%s,%s,%s,%s::jsonb)""",
                (
                    str(run_id), runtime_environment,
                    STRIPE_PROVIDER_RECONCILIATION_SUITE,
                    str(command.commercial_account_id), command.commercial_account_id,
                    command.idempotency_key, command_sha256, status, len(findings),
                    operator_user_id, snapshot_at,
                    json.dumps({
                        "billing_environment": billing_environment,
                        "observation_sha256": observation.content_sha256,
                        "reason_code": command.reason_code,
                    }, sort_keys=True, separators=(",", ":")),
                ),
            )
        finally:
            cursor.close()
        self._insert_findings(run_id, findings)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT status, snapshot_at FROM commercial_reconciliation_runs
                    WHERE run_id = %s""",
                (str(run_id),),
            )
            persisted_run = cursor.fetchone()
            cursor.execute(
                """SELECT finding_id, fingerprint_sha256, code, category,
                          severity, owner, subject_type, subject_id,
                          expected, observed, first_seen_at, last_seen_at,
                          suggested_repair, repair_kind
                     FROM commercial_reconciliation_findings
                    WHERE run_id = %s ORDER BY code, subject_type, subject_id""",
                (str(run_id),),
            )
            persisted_findings = tuple(
                self._finding_from_row(row) for row in cursor.fetchall()
            )
        finally:
            cursor.close()
        return StripeProviderReconciliationResult(
            run_id=run_id, environment=runtime_environment,
            commercial_account_id=command.commercial_account_id,
            billing_environment=billing_environment,
            idempotency_key=command.idempotency_key, status=persisted_run[0],
            snapshot_at=persisted_run[1], findings=persisted_findings,
        )

    @_atomic
    def reconcile_stripe_monetary_as_operator(
        self,
        *, operator_user_id: int, runtime_environment: RuntimeEnvironment,
        command: StripeMonetaryReconciliationCommand,
        observation: StripeMonetaryObservation,
    ) -> StripeMonetaryReconciliationResult:
        """Compare normalized Stripe money evidence without mutating billing facts."""

        self._require_operator(
            operator_user_id, runtime_environment,
            required_role=CommercialRole.COMMERCIAL_VIEWER,
        )
        billing_environment = self._billing_environment()
        if observation.environment != billing_environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        if (
            observation.evidence_completeness == "complete"
            and not observation.has_provider_attestation()
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        if observation.evidence_completeness == "complete":
            admission_at = datetime.now(observation.observed_at.tzinfo)
            if (
                observation.observed_at < admission_at - timedelta(hours=36)
                or observation.observed_at > admission_at + timedelta(minutes=5)
            ):
                raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        observation_body = observation.model_dump(
            mode="json", exclude={"content_sha256", "observed_at"}
        )
        if canonical_sha256(observation_body) != observation.content_sha256:
            raise ValueError("Stripe monetary observation digest mismatch")
        command_sha256 = canonical_sha256({
            "schema": "commercial.reconciliation.stripe-monetary-command.v1",
            "environment": runtime_environment,
            "billing_environment": billing_environment,
            "command": command.model_dump(mode="python", exclude={"idempotency_key"}),
            "observation_sha256": observation.content_sha256,
        })
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (
                    "commercial_reconciliation_account",
                    f"{runtime_environment}:{STRIPE_MONETARY_RECONCILIATION_SUITE}:"
                    f"{command.commercial_account_id}",
                ),
            )
            cursor.execute(
                """SELECT run_id, status, snapshot_at, command_sha256
                     FROM commercial_reconciliation_runs
                    WHERE environment = %s AND suite_code = %s
                      AND scope_type = 'account' AND scope_id = %s
                      AND idempotency_key = %s""",
                (
                    runtime_environment, STRIPE_MONETARY_RECONCILIATION_SUITE,
                    str(command.commercial_account_id), command.idempotency_key,
                ),
            )
            replay = cursor.fetchone()
            if replay is not None:
                if replay[3] != command_sha256:
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT
                    )
                cursor.execute(
                    """SELECT finding_id, fingerprint_sha256, code, category,
                              severity, owner, subject_type, subject_id,
                              expected, observed, first_seen_at, last_seen_at,
                              suggested_repair, repair_kind
                         FROM commercial_reconciliation_findings
                        WHERE run_id = %s ORDER BY code, subject_type, subject_id""",
                    (str(replay[0]),),
                )
                return StripeMonetaryReconciliationResult(
                    run_id=UUID(str(replay[0])), environment=runtime_environment,
                    commercial_account_id=command.commercial_account_id,
                    billing_environment=billing_environment,
                    idempotency_key=command.idempotency_key, status=replay[1],
                    snapshot_at=replay[2], findings=tuple(
                        self._finding_from_row(row) for row in cursor.fetchall()
                    ), durable_replayed=True,
                )
            expected = self._stripe_local_monetary_expectation(
                cursor, command.commercial_account_id,
                billing_environment=billing_environment,
            )
            raw_findings = self._stripe_monetary_findings(expected, observation)
            cursor.execute("SELECT statement_timestamp()")
            snapshot_at = cursor.fetchone()[0]
            findings = tuple(sorted((
                self._external_finding(
                    runtime_environment, command.commercial_account_id,
                    snapshot_at, raw, suite_code=STRIPE_MONETARY_RECONCILIATION_SUITE,
                ) for raw in raw_findings
            ), key=lambda item: (item.code, item.subject_type, item.subject_id)))
            status = (
                "blocked" if any(item.severity == "critical" for item in findings)
                else "drift" if findings else "green"
            )
            run_id = uuid4()
            cursor.execute(
                """INSERT INTO commercial_reconciliation_runs (
                       run_id, environment, suite_code, scope_type, scope_id,
                       commercial_account_id, idempotency_key, command_sha256,
                       mode, status, finding_count, actor_user_id, snapshot_at, metadata
                   ) VALUES (%s,%s,%s,'account',%s,%s,%s,%s,'dry_run',%s,%s,%s,%s,%s::jsonb)""",
                (
                    str(run_id), runtime_environment,
                    STRIPE_MONETARY_RECONCILIATION_SUITE,
                    str(command.commercial_account_id), command.commercial_account_id,
                    command.idempotency_key, command_sha256, status, len(findings),
                    operator_user_id, snapshot_at,
                    json.dumps({
                        "billing_environment": billing_environment,
                        "observation_sha256": observation.content_sha256,
                        "provider_observed_at": observation.observed_at.isoformat(),
                        "reason_code": command.reason_code,
                    }, sort_keys=True, separators=(",", ":")),
                ),
            )
        finally:
            cursor.close()
        self._insert_findings(run_id, findings)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT status, snapshot_at FROM commercial_reconciliation_runs WHERE run_id = %s",
                (str(run_id),),
            )
            persisted_run = cursor.fetchone()
            cursor.execute(
                """SELECT finding_id, fingerprint_sha256, code, category,
                          severity, owner, subject_type, subject_id,
                          expected, observed, first_seen_at, last_seen_at,
                          suggested_repair, repair_kind
                     FROM commercial_reconciliation_findings
                    WHERE run_id = %s ORDER BY code, subject_type, subject_id""",
                (str(run_id),),
            )
            persisted_findings = tuple(
                self._finding_from_row(row) for row in cursor.fetchall()
            )
        finally:
            cursor.close()
        return StripeMonetaryReconciliationResult(
            run_id=run_id, environment=runtime_environment,
            commercial_account_id=command.commercial_account_id,
            billing_environment=billing_environment,
            idempotency_key=command.idempotency_key, status=persisted_run[0],
            snapshot_at=persisted_run[1], findings=persisted_findings,
        )

    @_atomic
    def reconcile_stripe_webhook_inbox_as_operator(
        self, *, operator_user_id: int, runtime_environment: RuntimeEnvironment,
        command: StripeWebhookInboxReconciliationCommand,
    ) -> StripeWebhookInboxReconciliationResult:
        """Persist bounded environment-wide non-applied Stripe inbox evidence."""

        self._require_operator(
            operator_user_id, runtime_environment,
            required_role=CommercialRole.COMMERCIAL_VIEWER,
        )
        billing_environment = self._billing_environment()
        command_sha256 = canonical_sha256({
            "schema": "commercial.reconciliation.stripe-webhook-inbox-command.v1",
            "environment": runtime_environment,
            "billing_environment": billing_environment,
            "command": command.model_dump(mode="python", exclude={"idempotency_key"}),
        })
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                ("commercial_reconciliation_environment",
                 f"{runtime_environment}:{STRIPE_WEBHOOK_INBOX_RECONCILIATION_SUITE}"),
            )
            cursor.execute(
                """SELECT run_id, status, snapshot_at, command_sha256
                     FROM commercial_reconciliation_runs
                    WHERE environment = %s AND suite_code = %s
                      AND scope_type = 'environment' AND scope_id = %s
                      AND idempotency_key = %s""",
                (runtime_environment, STRIPE_WEBHOOK_INBOX_RECONCILIATION_SUITE,
                 runtime_environment, command.idempotency_key),
            )
            replay = cursor.fetchone()
            if replay is not None:
                if replay[3] != command_sha256:
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT
                    )
                cursor.execute(
                    """SELECT finding_id, fingerprint_sha256, code, category,
                              severity, owner, subject_type, subject_id,
                              expected, observed, first_seen_at, last_seen_at,
                              suggested_repair, repair_kind
                         FROM commercial_reconciliation_findings
                        WHERE run_id = %s ORDER BY code, subject_type, subject_id""",
                    (str(replay[0]),),
                )
                return StripeWebhookInboxReconciliationResult(
                    run_id=UUID(str(replay[0])), environment=runtime_environment,
                    billing_environment=billing_environment,
                    idempotency_key=command.idempotency_key, status=replay[1],
                    snapshot_at=replay[2], findings=tuple(
                        self._finding_from_row(row) for row in cursor.fetchall()
                    ), durable_replayed=True,
                )
            cursor.execute(
                """SELECT external_event_id, event_type, processing_state,
                          attempt_count, last_error_code,
                          payload_json #>> '{data,object,customer}' AS customer_id
                     FROM commercial_webhook_events
                    WHERE provider = 'stripe' AND environment = %s
                      AND processing_state NOT IN ('applied', 'ignored')
                 ORDER BY external_event_id LIMIT 101""",
                (billing_environment,),
            )
            rows = tuple(cursor.fetchall())
            cursor.execute("SELECT statement_timestamp()")
            snapshot_at = cursor.fetchone()[0]
            raw_findings = []
            for row in rows[:100]:
                assigned = row[5] is not None
                raw_findings.append({
                    "code": (
                        "stripe.webhook_not_applied" if assigned
                        else "stripe.webhook_unassigned_not_applied"
                    ),
                    "category": "webhook", "severity": (
                        "critical" if row[2] == "dead" or not assigned else "error"
                    ),
                    "owner": "billing_operations", "subject_type": "stripe_webhook",
                    "subject_id": str(row[0]),
                    "expected": {"processing_state": "applied_or_ignored"},
                    "observed": {
                        "event_type": row[1], "processing_state": row[2],
                        "attempt_count": int(row[3]), "last_error_code": row[4],
                        "customer_id": row[5],
                    },
                    "suggested_repair": "stripe.webhook_replay_review",
                    "repair_kind": "investigate",
                })
            if len(rows) > 100:
                raw_findings.append({
                    "code": "stripe.webhook_backlog_overflow", "category": "webhook",
                    "severity": "critical", "owner": "billing_operations",
                    "subject_type": "stripe_webhook_inbox",
                    "subject_id": billing_environment,
                    "expected": {"bounded_unapplied_event_count_lte": 100},
                    "observed": {"bounded_unapplied_event_count_gte": 101},
                    "suggested_repair": "stripe.webhook_backlog_review",
                    "repair_kind": "investigate",
                })
            findings = tuple(sorted((
                self._environment_finding_from_snapshot(
                    runtime_environment, STRIPE_WEBHOOK_INBOX_RECONCILIATION_SUITE,
                    snapshot_at, raw,
                ) for raw in raw_findings
            ), key=lambda item: (item.code, item.subject_type, item.subject_id)))
            status = (
                "blocked" if any(item.severity == "critical" for item in findings)
                else "drift" if findings else "green"
            )
            run_id = uuid4()
            cursor.execute(
                """INSERT INTO commercial_reconciliation_runs (
                       run_id, environment, suite_code, scope_type, scope_id,
                       commercial_account_id, idempotency_key, command_sha256,
                       mode, status, finding_count, actor_user_id, snapshot_at, metadata
                   ) VALUES (%s,%s,%s,'environment',%s,NULL,%s,%s,'dry_run',
                             %s,%s,%s,%s,%s::jsonb)""",
                (str(run_id), runtime_environment,
                 STRIPE_WEBHOOK_INBOX_RECONCILIATION_SUITE, runtime_environment,
                 command.idempotency_key, command_sha256, status, len(findings),
                 operator_user_id, snapshot_at, json.dumps({
                     "billing_environment": billing_environment,
                     "reason_code": command.reason_code,
                     "bounded_limit": 100,
                 }, sort_keys=True, separators=(",", ":"))),
            )
        finally:
            cursor.close()
        self._insert_findings(run_id, findings)
        return StripeWebhookInboxReconciliationResult(
            run_id=run_id, environment=runtime_environment,
            billing_environment=billing_environment,
            idempotency_key=command.idempotency_key, status=status,
            snapshot_at=snapshot_at, findings=findings,
        )

    @_atomic
    def reconcile_provider_costs_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ProviderCostReconciliationCommand,
    ) -> ProviderCostReconciliationResult:
        """Persist one environment-wide provider-cost audit from one snapshot."""

        self._require_operator(
            operator_user_id,
            runtime_environment,
            required_role=CommercialRole.COMMERCIAL_VIEWER,
        )
        command_sha256 = canonical_sha256(
            {
                "schema": "commercial.reconciliation.provider-cost-command.v1",
                "environment": runtime_environment,
                "suite_code": PROVIDER_COST_ALLOCATION_SUITE,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
            }
        )
        self._environment_advisory_lock(
            runtime_environment, PROVIDER_COST_ALLOCATION_SUITE
        )
        replay = self._load_provider_cost_run(
            runtime_environment, command, command_sha256=command_sha256
        )
        if replay is not None:
            return replay

        run_id = uuid4()
        snapshot_at, status, raw_findings = self._provider_cost_snapshot(
            runtime_environment,
            run_id=run_id,
            idempotency_key=command.idempotency_key,
            command_sha256=command_sha256,
            reason_code=command.reason_code,
            actor_user_id=operator_user_id,
        )
        findings = tuple(
            self._environment_finding_from_snapshot(
                runtime_environment,
                PROVIDER_COST_ALLOCATION_SUITE,
                snapshot_at,
                raw,
            )
            for raw in raw_findings
        )
        self._insert_findings(run_id, findings)
        return ProviderCostReconciliationResult(
            run_id=run_id,
            environment=runtime_environment,
            idempotency_key=command.idempotency_key,
            status=status,
            snapshot_at=snapshot_at,
            findings=findings,
        )

    @_atomic
    def resolve_provider_cost_finding_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ProviderCostResolutionCommand,
    ) -> ProviderCostResolutionResult:
        """Append a named disposition for the latest environment-wide finding."""

        self._require_operator(
            operator_user_id,
            runtime_environment,
            required_role=CommercialRole.COMMERCIAL_ADMIN,
        )
        command_sha256 = canonical_sha256(
            {
                "schema": "commercial.reconciliation.provider-cost-resolution.v1",
                "environment": runtime_environment,
                "suite_code": PROVIDER_COST_ALLOCATION_SUITE,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
            }
        )
        self._environment_advisory_lock(
            runtime_environment, PROVIDER_COST_ALLOCATION_SUITE
        )
        replay = self._load_provider_cost_resolution(
            runtime_environment, command, command_sha256=command_sha256
        )
        if replay is not None:
            return replay

        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT finding_id, fingerprint_sha256
                  FROM commercial_reconciliation_current_findings
                 WHERE environment = %s
                   AND suite_code = %s
                   AND scope_type = 'environment'
                   AND scope_id = %s
                   AND finding_id = %s
                   AND resolution_state = 'open'
                """,
                (
                    runtime_environment,
                    PROVIDER_COST_ALLOCATION_SUITE,
                    runtime_environment,
                    str(command.source_finding_id),
                ),
            )
            source = cursor.fetchone()
            if source is None:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT,
                    internal_detail=(
                        "provider-cost resolution source is not the latest open finding"
                    ),
                )
            fingerprint_sha256 = str(source[1])
        finally:
            cursor.close()

        resolution_id = uuid4()
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action=(
                    "commercial.reconciliation.resolve."
                    f"{command.resolution_kind}"
                ),
                target_type="commercial_reconciliation_finding",
                target_id=str(command.source_finding_id),
                reason_code=command.reason_code,
                after={
                    "content_sha256": command_sha256,
                    "environment": runtime_environment,
                    "role": "commercial_admin",
                    "result_code": "applied",
                },
            ),
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_reconciliation_resolutions (
                    resolution_id, source_finding_id, environment, suite_code,
                    scope_type, scope_id, fingerprint_sha256,
                    idempotency_key, command_sha256, resolution_kind,
                    reason_code, note_redacted, actor_user_id,
                    audit_event_id, resolved_at
                ) VALUES (
                    %s, %s, %s, %s, 'environment', %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, statement_timestamp()
                ) RETURNING resolved_at
                """,
                (
                    str(resolution_id),
                    str(command.source_finding_id),
                    runtime_environment,
                    PROVIDER_COST_ALLOCATION_SUITE,
                    runtime_environment,
                    fingerprint_sha256,
                    command.idempotency_key,
                    command_sha256,
                    command.resolution_kind,
                    command.reason_code,
                    command.note_redacted,
                    operator_user_id,
                    str(audit_event_id),
                ),
            )
            resolved_at: datetime = cursor.fetchone()[0]
        finally:
            cursor.close()
        return ProviderCostResolutionResult(
            resolution_id=resolution_id,
            source_finding_id=command.source_finding_id,
            fingerprint_sha256=fingerprint_sha256,
            environment=runtime_environment,
            resolution_kind=command.resolution_kind,
            reason_code=command.reason_code,
            actor_user_id=operator_user_id,
            audit_event_id=audit_event_id,
            resolved_at=resolved_at,
        )

    @_atomic
    def resolve_finding_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ReconciliationResolutionCommand,
    ) -> ReconciliationResolutionResult:
        """Append an explicit disposition for the latest observation of a finding."""

        self._require_operator(
            operator_user_id,
            runtime_environment,
            required_role=CommercialRole.COMMERCIAL_ADMIN,
        )
        command_sha256 = canonical_sha256(
            {
                "schema": "commercial.reconciliation.resolution-command.v1",
                "environment": runtime_environment,
                "suite_code": BILLING_REVENUE_ECONOMICS_SUITE,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
            }
        )
        self._advisory_lock(runtime_environment, command.commercial_account_id)
        replay = self._load_resolution(
            runtime_environment, command, command_sha256=command_sha256
        )
        if replay is not None:
            return replay

        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT finding_id, fingerprint_sha256
                  FROM commercial_reconciliation_current_findings
                 WHERE environment = %s
                   AND suite_code = %s
                   AND scope_type = 'account'
                   AND scope_id = %s
                   AND finding_id = %s
                   AND resolution_state = 'open'
                """,
                (
                    runtime_environment,
                    BILLING_REVENUE_ECONOMICS_SUITE,
                    str(command.commercial_account_id),
                    str(command.source_finding_id),
                ),
            )
            source = cursor.fetchone()
            if source is None:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT,
                    internal_detail="resolution source is not the latest open finding",
                )
            fingerprint_sha256 = str(source[1])
        finally:
            cursor.close()

        resolution_id = uuid4()
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=command.commercial_account_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action=(
                    "commercial.reconciliation.resolve."
                    f"{command.resolution_kind}"
                ),
                target_type="commercial_reconciliation_finding",
                target_id=str(command.source_finding_id),
                reason_code=command.reason_code,
                after={
                    "account_id": command.commercial_account_id,
                    "content_sha256": command_sha256,
                    "environment": runtime_environment,
                    "role": "commercial_admin",
                    "result_code": "applied",
                },
            ),
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_reconciliation_resolutions (
                    resolution_id, source_finding_id, environment, suite_code,
                    scope_type, scope_id, fingerprint_sha256,
                    idempotency_key, command_sha256, resolution_kind,
                    reason_code, note_redacted, actor_user_id,
                    audit_event_id, resolved_at
                ) VALUES (
                    %s, %s, %s, %s, 'account', %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, statement_timestamp()
                ) RETURNING resolved_at
                """,
                (
                    str(resolution_id),
                    str(command.source_finding_id),
                    runtime_environment,
                    BILLING_REVENUE_ECONOMICS_SUITE,
                    str(command.commercial_account_id),
                    fingerprint_sha256,
                    command.idempotency_key,
                    command_sha256,
                    command.resolution_kind,
                    command.reason_code,
                    command.note_redacted,
                    operator_user_id,
                    str(audit_event_id),
                ),
            )
            resolved_at: datetime = cursor.fetchone()[0]
        finally:
            cursor.close()
        return ReconciliationResolutionResult(
            resolution_id=resolution_id,
            source_finding_id=command.source_finding_id,
            fingerprint_sha256=fingerprint_sha256,
            environment=runtime_environment,
            commercial_account_id=command.commercial_account_id,
            resolution_kind=command.resolution_kind,
            reason_code=command.reason_code,
            actor_user_id=operator_user_id,
            audit_event_id=audit_event_id,
            resolved_at=resolved_at,
        )

    @staticmethod
    def _stripe_local_expectation(cursor, account_id: int, *, billing_environment: str) -> dict:
        cursor.execute(
            """SELECT account.public_id, customer.external_customer_id
                 FROM commercial_accounts account
            LEFT JOIN billing_provider_customers customer
                   ON customer.commercial_account_id = account.id
                  AND customer.provider = 'stripe' AND customer.environment = %s
                WHERE account.id = %s""",
            (billing_environment, account_id),
        )
        account = cursor.fetchone()
        if account is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
        cursor.execute(
            """SELECT agreement.external_subscription_id, agreement.state,
                      agreement.cancel_at_period_end,
                      agreement.current_period_start_at, agreement.current_period_end_at,
                      terms.price_code
                 FROM commercial_agreements agreement
            LEFT JOIN commercial_agreement_terms terms
                   ON terms.agreement_id = agreement.id AND terms.effective_until IS NULL
                WHERE agreement.commercial_account_id = %s
                  AND agreement.billing_provider = 'stripe'
                  AND agreement.billing_environment = %s
                  AND agreement.external_subscription_id IS NOT NULL
             ORDER BY agreement.external_subscription_id""",
            (account_id, billing_environment),
        )
        subscriptions = {
            str(row[0]): {
                "state": row[1], "cancel_at_period_end": bool(row[2]),
                "current_period_start_at": row[3],
                "current_period_end_at": row[4], "price_code": row[5],
            }
            for row in cursor.fetchall()
        }
        cursor.execute(
            """SELECT code, category, severity, owner, subject_type, subject_id,
                      expected, observed, suggested_repair, repair_kind
                 FROM commercial_account_control_reconciliation_candidates
                WHERE commercial_account_id = %s AND category = 'entitlement'
             ORDER BY code, subject_type, subject_id""",
            (account_id,),
        )
        local_findings = tuple({
            "code": row[0], "category": row[1], "severity": row[2],
            "owner": row[3], "subject_type": row[4], "subject_id": row[5],
            "expected": row[6], "observed": row[7],
            "suggested_repair": row[8], "repair_kind": row[9],
        } for row in cursor.fetchall())
        return {
            "account_public_id": str(account[0]),
            "customer_id": account[1],
            "subscriptions": subscriptions,
            "local_findings": local_findings,
        }

    @staticmethod
    def _stripe_provider_findings(expected: dict, observation: StripeAccountObservation) -> list[dict]:
        findings: list[dict] = list(expected.get("local_findings", ()))

        def add(code, severity, subject_type, subject_id, expected_value, observed_value, repair):
            findings.append({
                "code": code, "category": "provider_reconciliation",
                "severity": severity, "owner": "billing_operations",
                "subject_type": subject_type, "subject_id": subject_id,
                "expected": expected_value, "observed": observed_value,
                "suggested_repair": repair, "repair_kind": "operator",
            })

        expected_customer = expected["customer_id"]
        if observation.expected_external_customer_id != expected_customer:
            add(
                "stripe.customer_mapping_drift", "critical", "commercial_account",
                expected["account_public_id"],
                {"external_customer_id": expected_customer},
                {"external_customer_id": observation.expected_external_customer_id},
                "stripe.customer_identity_repair",
            )
        if observation.commercial_account_public_id.hex != UUID(
            expected["account_public_id"]
        ).hex:
            add(
                "stripe.customer_account_mismatch", "critical", "commercial_account",
                expected["account_public_id"],
                {"commercial_account_public_id": expected["account_public_id"]},
                {"commercial_account_public_id": str(observation.commercial_account_public_id)},
                "stripe.customer_metadata_review",
            )
        matches = observation.matching_external_customer_ids
        if expected_customer is None or matches != (expected_customer,):
            add(
                "stripe.customer_uniqueness_drift", "critical", "commercial_account",
                expected["account_public_id"],
                {"external_customer_ids": [expected_customer] if expected_customer else []},
                {"external_customer_ids": list(matches)},
                "stripe.customer_identity_repair",
            )
        local = expected["subscriptions"]
        remote = {
            item.external_subscription_id: item for item in observation.subscriptions
        }
        for subscription_id in sorted(set(local) - set(remote)):
            add(
                "stripe.subscription_missing_remote", "critical", "stripe_subscription",
                subscription_id, {"present": True}, {"present": False},
                "stripe.subscription_identity_review",
            )
        for subscription_id in sorted(set(remote) - set(local)):
            add(
                "stripe.subscription_missing_local", "critical", "stripe_subscription",
                subscription_id, {"present": False}, {"present": True},
                "stripe.subscription_projection_repair",
            )
        compatible_states = {
            "pending_payment": {"incomplete"}, "trialing": {"trialing"},
            "active": {"active"}, "past_due": {"past_due"},
            "grace": {"past_due", "unpaid"}, "paused": {"paused"},
            "canceled": {"canceled"}, "expired": {"canceled", "incomplete_expired"},
        }
        for subscription_id in sorted(set(local) & set(remote)):
            local_item, remote_item = local[subscription_id], remote[subscription_id]
            if remote_item.status not in compatible_states.get(local_item["state"], set()):
                add(
                    "stripe.subscription_state_drift", "error", "stripe_subscription",
                    subscription_id, {"agreement_state": local_item["state"]},
                    {"subscription_status": remote_item.status},
                    "stripe.subscription_projection_repair",
                )
            if local_item["price_code"] != remote_item.price_code:
                add(
                    "stripe.subscription_price_drift", "critical", "stripe_subscription",
                    subscription_id, {"price_code": local_item["price_code"]},
                    {"price_code": remote_item.price_code},
                    "stripe.subscription_price_review",
                )
            if local_item["cancel_at_period_end"] != remote_item.cancel_at_period_end:
                add(
                    "stripe.subscription_cancellation_drift", "error", "stripe_subscription",
                    subscription_id,
                    {"cancel_at_period_end": local_item["cancel_at_period_end"]},
                    {"cancel_at_period_end": remote_item.cancel_at_period_end},
                    "stripe.subscription_projection_repair",
                )
            if (
                local_item["current_period_start_at"] != remote_item.current_period_start_at
                or local_item["current_period_end_at"] != remote_item.current_period_end_at
            ):
                add(
                    "stripe.subscription_period_drift", "error", "stripe_subscription",
                    subscription_id,
                    {
                        "current_period_start_at": local_item["current_period_start_at"].isoformat()
                        if local_item["current_period_start_at"] else None,
                        "current_period_end_at": local_item["current_period_end_at"].isoformat()
                        if local_item["current_period_end_at"] else None,
                    },
                    {
                        "current_period_start_at": remote_item.current_period_start_at.isoformat(),
                        "current_period_end_at": remote_item.current_period_end_at.isoformat(),
                    }, "stripe.subscription_projection_repair",
                )
        return findings

    @staticmethod
    def _stripe_local_monetary_expectation(
        cursor, account_id: int, *, billing_environment: str
    ) -> dict:
        cursor.execute(
            "SELECT public_id FROM commercial_accounts WHERE id = %s",
            (account_id,),
        )
        account = cursor.fetchone()
        if account is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
        cursor.execute(
            """SELECT document.id, document.external_document_id, document.status,
                      document.currency, customer.external_customer_id,
                      agreement.external_subscription_id,
                      COALESCE((SELECT SUM(line.net_consideration_ex_tax_cents)
                                  FROM commercial_billing_lines line
                                 WHERE line.document_id = document.id), 0),
                      COALESCE((SELECT SUM(line.tax_cents)
                                  FROM commercial_billing_lines line
                                 WHERE line.document_id = document.id), 0),
                      COALESCE((SELECT SUM(movement.signed_amount_cents)
                                  FROM commercial_money_movements movement
                                 WHERE movement.document_id = document.id
                                   AND movement.movement_kind = 'cash_receipt'), 0),
                      COALESCE((SELECT SUM(allocation.recognized_revenue_cents)
                                  FROM commercial_revenue_allocation_runs run
                                  JOIN commercial_revenue_allocations allocation
                                    ON allocation.allocation_run_id = run.id
                                 WHERE run.document_id = document.id
                                   AND run.state = 'final'), 0)
                 FROM commercial_billing_documents_current document
                 JOIN commercial_agreements agreement ON agreement.id = document.agreement_id
                 JOIN billing_provider_customers customer
                   ON customer.commercial_account_id = document.commercial_account_id
                  AND customer.provider = 'stripe' AND customer.environment = %s
                WHERE document.commercial_account_id = %s
                  AND document.provider = 'stripe' AND document.environment = %s
                  AND document.document_kind = 'invoice'
             ORDER BY document.external_document_id""",
            (billing_environment, account_id, billing_environment),
        )
        documents = {}
        for row in cursor.fetchall():
            cursor.execute(
                """SELECT external_line_id, price_code,
                          net_consideration_ex_tax_cents, tax_cents,
                          service_period_start_at, service_period_end_at
                     FROM commercial_billing_lines
                    WHERE document_id = %s ORDER BY external_line_id""",
                (int(row[0]),),
            )
            documents[str(row[1])] = {
                "status": row[2], "currency": row[3],
                "external_customer_id": row[4], "external_subscription_id": row[5],
                "net_consideration_ex_tax_cents": int(row[6]),
                "tax_cents": int(row[7]), "cash_receipt_cents": int(row[8]),
                "recognized_revenue_cents": int(row[9]),
                "lines": {
                    str(line[0]): {
                        "price_code": line[1],
                        "net_consideration_ex_tax_cents": int(line[2]),
                        "tax_cents": int(line[3]),
                        "service_period_start_at": line[4],
                        "service_period_end_at": line[5],
                    }
                    for line in cursor.fetchall()
                },
            }
        cursor.execute(
            """SELECT document.external_document_id, movement.external_object_type,
                      movement.external_object_id, movement.movement_kind,
                      movement.signed_amount_cents, movement.currency,
                      movement.occurred_at
                 FROM commercial_money_movements movement
                 JOIN commercial_billing_documents document
                   ON document.id = movement.document_id
                WHERE movement.commercial_account_id = %s
                  AND movement.provider = 'stripe' AND movement.environment = %s
                  AND movement.movement_kind IN (
                      'cash_receipt','refund','dispute_hold','dispute_release','processor_fee'
                  )
             ORDER BY movement.external_object_type, movement.external_object_id,
                      movement.movement_kind""",
            (account_id, billing_environment),
        )
        movements = {
            (str(row[1]), str(row[2]), str(row[3])): {
                "external_invoice_id": str(row[0]),
                "signed_amount_cents": int(row[4]), "currency": row[5],
                "occurred_at": row[6],
            }
            for row in cursor.fetchall()
        }
        return {
            "account_public_id": str(account[0]),
            "documents": documents, "movements": movements,
        }

    @staticmethod
    def _stripe_monetary_findings(
        expected: dict, observation: StripeMonetaryObservation
    ) -> list[dict]:
        findings: list[dict] = []

        def add(code, severity, subject_type, subject_id, expected_value, observed_value, repair):
            findings.append({
                "code": code, "category": "money_reconciliation",
                "severity": severity, "owner": "billing_operations",
                "subject_type": subject_type, "subject_id": subject_id,
                "expected": expected_value, "observed": observed_value,
                "suggested_repair": repair, "repair_kind": "operator",
            })

        if observation.evidence_completeness == "partial":
            add(
                "stripe.monetary_evidence_incomplete", "critical", "commercial_account",
                expected["account_public_id"],
                {"evidence_completeness": "complete"},
                {"evidence_completeness": observation.evidence_completeness},
                "stripe.monetary_provider_enumeration_required",
            )

        if str(observation.commercial_account_public_id) != expected["account_public_id"]:
            add(
                "stripe.monetary_account_mismatch", "critical", "commercial_account",
                expected["account_public_id"],
                {"commercial_account_public_id": expected["account_public_id"]},
                {"commercial_account_public_id": str(observation.commercial_account_public_id)},
                "stripe.monetary_identity_review",
            )
        local_documents = expected["documents"]
        remote_documents = {
            item.external_invoice_id: item
            for item in observation.invoices if item.status != "draft"
        }
        for invoice_id in sorted(set(local_documents) - set(remote_documents)):
            add(
                "stripe.invoice_missing_remote", "critical", "stripe_invoice", invoice_id,
                {"present": True}, {"present": False}, "stripe.invoice_identity_review",
            )
        for invoice_id in sorted(set(remote_documents) - set(local_documents)):
            remote = remote_documents[invoice_id]
            add(
                "stripe.invoice_missing_local", "critical", "stripe_invoice", invoice_id,
                {"present": False, "digest": None},
                {"present": True, "digest": remote.snapshot_sha256},
                "stripe.invoice_projection_repair",
            )
        for invoice_id in sorted(set(local_documents) & set(remote_documents)):
            local, remote = local_documents[invoice_id], remote_documents[invoice_id]
            if (
                local["external_customer_id"] != remote.external_customer_id
                or local["external_subscription_id"] != remote.external_subscription_id
            ):
                add(
                    "stripe.invoice_authority_drift", "critical", "stripe_invoice", invoice_id,
                    {
                        "external_customer_id": local["external_customer_id"],
                        "external_subscription_id": local["external_subscription_id"],
                    },
                    {
                        "external_customer_id": remote.external_customer_id,
                        "external_subscription_id": remote.external_subscription_id,
                    },
                    "stripe.invoice_identity_review",
                )
            allowed_status = {remote.status}
            if remote.status == "paid":
                allowed_status.add("credited")
            if local["status"] not in allowed_status:
                add(
                    "stripe.invoice_status_drift", "error", "stripe_invoice", invoice_id,
                    {"status": local["status"]}, {"status": remote.status},
                    "stripe.invoice_projection_repair",
                )
            remote_lines = {
                line.external_line_id: {
                    "price_code": line.price_code,
                    "net_consideration_ex_tax_cents": line.net_consideration_ex_tax_cents,
                    "tax_cents": line.tax_cents,
                    "service_period_start_at": line.service_period_start_at,
                    "service_period_end_at": line.service_period_end_at,
                } for line in remote.lines
            }
            if local["lines"] != remote_lines:
                add(
                    "stripe.invoice_line_drift", "critical", "stripe_invoice", invoice_id,
                    {"line_count": len(local["lines"]), "line_digest": canonical_sha256(local["lines"])},
                    {"line_count": len(remote_lines), "line_digest": canonical_sha256(remote_lines)},
                    "stripe.invoice_projection_repair",
                )
            expected_amounts = {
                "currency": local["currency"],
                "net_consideration_ex_tax_cents": local["net_consideration_ex_tax_cents"],
                "tax_cents": local["tax_cents"],
                "cash_receipt_cents": local["cash_receipt_cents"],
                "recognized_revenue_cents": local["recognized_revenue_cents"],
            }
            observed_amounts = {
                "currency": remote.currency,
                "net_consideration_ex_tax_cents": remote.net_consideration_ex_tax_cents,
                "tax_cents": remote.tax_cents,
                "cash_receipt_cents": remote.amount_paid_cents,
                "recognized_revenue_cents": remote.net_consideration_ex_tax_cents,
            }
            if expected_amounts != observed_amounts:
                add(
                    "stripe.invoice_amount_drift", "critical", "stripe_invoice", invoice_id,
                    expected_amounts, observed_amounts,
                    "stripe.invoice_money_revenue_repair",
                )
        local_movements, remote_movements = expected["movements"], {
            (item.external_object_type, item.external_object_id, item.movement_kind): {
                "external_invoice_id": item.external_invoice_id,
                "signed_amount_cents": item.signed_amount_cents,
                "currency": item.currency, "occurred_at": item.occurred_at,
            } for item in observation.movements
        }
        for key in sorted(set(local_movements) | set(remote_movements)):
            local, remote = local_movements.get(key), remote_movements.get(key)
            if local != remote:
                add(
                    "stripe.money_movement_drift", "critical", "stripe_movement",
                    ":".join(key),
                    {"present": local is not None, "digest": canonical_sha256(local) if local else None},
                    {"present": remote is not None, "digest": canonical_sha256(remote) if remote else None},
                    "stripe.money_movement_projection_repair",
                )
        return findings

    @staticmethod
    def _external_finding(
        environment: RuntimeEnvironment, account_id: int, snapshot_at: datetime,
        raw: dict, *, suite_code: str,
    ) -> ReconciliationFinding:
        identity = {
            "environment": environment, "suite_code": suite_code,
            "scope_type": "account", "scope_id": str(account_id),
            "code": raw["code"], "subject_type": raw["subject_type"],
            "subject_id": raw["subject_id"],
        }
        return ReconciliationFinding(
            finding_id=uuid4(), fingerprint_sha256=canonical_sha256(identity),
            code=raw["code"], category=raw["category"], severity=raw["severity"],
            owner=raw["owner"], subject_type=raw["subject_type"],
            subject_id=raw["subject_id"], expected=raw["expected"],
            observed=raw["observed"], first_seen_at=snapshot_at,
            last_seen_at=snapshot_at, suggested_repair=raw["suggested_repair"],
            repair_kind=raw["repair_kind"],
        )

    @staticmethod
    def _stripe_finding(
        environment: RuntimeEnvironment, account_id: int,
        snapshot_at: datetime, raw: dict,
    ) -> ReconciliationFinding:
        identity = {
            "environment": environment,
            "suite_code": STRIPE_PROVIDER_RECONCILIATION_SUITE,
            "scope_type": "account", "scope_id": str(account_id),
            "code": raw["code"], "subject_type": raw["subject_type"],
            "subject_id": raw["subject_id"],
        }
        return ReconciliationFinding(
            finding_id=uuid4(), fingerprint_sha256=canonical_sha256(identity),
            code=raw["code"], category=raw["category"], severity=raw["severity"],
            owner=raw["owner"], subject_type=raw["subject_type"],
            subject_id=raw["subject_id"], expected=raw["expected"],
            observed=raw["observed"], first_seen_at=snapshot_at,
            last_seen_at=snapshot_at, suggested_repair=raw["suggested_repair"],
            repair_kind=raw["repair_kind"],
        )

    def _require_operator(
        self,
        user_id: int,
        environment: RuntimeEnvironment,
        *,
        required_role: CommercialRole,
    ) -> None:
        self._require_transaction()
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_reconciliation_enabled
        ):
            raise RuntimeError("commercial reconciliation is disabled")
        if environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            deployment = cursor.fetchone()
        finally:
            cursor.close()
        operator = load_named_operator(
            self._connection, user_id=user_id, environment=environment
        )
        if (
            deployment is None
            or deployment[0] != environment
            or required_role not in operator.roles
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _require_account(self, account_id: int) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT id FROM commercial_accounts WHERE id = %s FOR KEY SHARE",
                (account_id,),
            )
            if cursor.fetchone() is None:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND
                )
        finally:
            cursor.close()

    def _billing_environment(self) -> Literal["test", "live"]:
        return "live" if self._flags.stripe_live_mode_enabled else "test"

    def _insert_findings(
        self, run_id: UUID, findings: tuple[ReconciliationFinding, ...]
    ) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            for finding in findings:
                cursor.execute(
                    """
                    INSERT INTO commercial_reconciliation_findings (
                        finding_id, run_id, fingerprint_sha256, code, category,
                        severity, owner, subject_type, subject_id,
                        expected, observed, first_seen_at, last_seen_at,
                        suggested_repair, repair_kind
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s, %s, %s, %s
                    )
                    """,
                    (
                        str(finding.finding_id),
                        str(run_id),
                        finding.fingerprint_sha256,
                        finding.code,
                        finding.category,
                        finding.severity,
                        finding.owner,
                        finding.subject_type,
                        finding.subject_id,
                        json.dumps(
                            finding.expected, sort_keys=True, separators=(",", ":")
                        ),
                        json.dumps(
                            finding.observed, sort_keys=True, separators=(",", ":")
                        ),
                        finding.first_seen_at,
                        finding.last_seen_at,
                        finding.suggested_repair,
                        finding.repair_kind,
                    ),
                )
        finally:
            cursor.close()

    def _provider_cost_snapshot(
        self,
        environment: RuntimeEnvironment,
        *,
        run_id: UUID,
        idempotency_key: str,
        command_sha256: str,
        reason_code: str,
        actor_user_id: int,
    ) -> tuple[datetime, Literal["green", "drift"], tuple[dict, ...]]:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                WITH snapshot AS (
                    SELECT statement_timestamp() AS snapshot_at
                ), candidates AS (
                    SELECT code, category, severity, owner, subject_type,
                           subject_id, expected, observed,
                           suggested_repair, repair_kind
                      FROM (
                          SELECT *
                            FROM commercial_provider_cost_reconciliation_candidates
                           WHERE environment = %s
                          UNION ALL
                          SELECT *
                            FROM commercial_provider_cost_receipt_reconciliation_candidates
                           WHERE environment = %s
                      ) candidate
                ), payload AS (
                    SELECT snapshot.snapshot_at,
                           COALESCE(
                               jsonb_agg(
                                   jsonb_build_object(
                                       'code', candidate.code,
                                       'category', candidate.category,
                                       'severity', candidate.severity,
                                       'owner', candidate.owner,
                                       'subject_type', candidate.subject_type,
                                       'subject_id', candidate.subject_id,
                                       'expected', candidate.expected,
                                       'observed', candidate.observed,
                                       'first_seen_at', prior.first_seen_at,
                                       'suggested_repair', candidate.suggested_repair,
                                       'repair_kind', candidate.repair_kind
                                   ) ORDER BY candidate.code,
                                              candidate.subject_type,
                                              candidate.subject_id
                               ) FILTER (WHERE candidate.code IS NOT NULL),
                               '[]'::jsonb
                           ) AS findings
                      FROM snapshot
                      LEFT JOIN candidates candidate ON TRUE
                      LEFT JOIN LATERAL (
                          SELECT MIN(finding.first_seen_at) AS first_seen_at
                            FROM commercial_reconciliation_findings finding
                            JOIN commercial_reconciliation_runs run
                              ON run.run_id = finding.run_id
                           WHERE run.environment = %s
                             AND run.suite_code = %s
                             AND run.scope_type = 'environment'
                             AND run.scope_id = %s
                             AND finding.code = candidate.code
                             AND finding.category = candidate.category
                             AND finding.subject_type = candidate.subject_type
                             AND finding.subject_id = candidate.subject_id
                      ) prior ON TRUE
                     GROUP BY snapshot.snapshot_at
                ), inserted_run AS (
                    INSERT INTO commercial_reconciliation_runs (
                        run_id, environment, suite_code, scope_type, scope_id,
                        commercial_account_id, idempotency_key, command_sha256,
                        mode, status, finding_count, actor_user_id,
                        snapshot_at, metadata
                    )
                    SELECT %s, %s, %s, 'environment', %s,
                           NULL, %s, %s, 'dry_run',
                           CASE WHEN jsonb_array_length(payload.findings) = 0
                                THEN 'green' ELSE 'drift' END,
                           jsonb_array_length(payload.findings), %s,
                           payload.snapshot_at, %s::jsonb
                      FROM payload
                    RETURNING snapshot_at, status
                )
                SELECT inserted_run.snapshot_at, inserted_run.status,
                       payload.findings
                  FROM inserted_run CROSS JOIN payload
                """,
                (
                    environment,
                    environment,
                    environment,
                    PROVIDER_COST_ALLOCATION_SUITE,
                    environment,
                    str(run_id),
                    environment,
                    PROVIDER_COST_ALLOCATION_SUITE,
                    environment,
                    idempotency_key,
                    command_sha256,
                    actor_user_id,
                    json.dumps(
                        {
                            "reason_code": reason_code,
                            "snapshot_contract": "statement_snapshot.v1",
                            "source_contract": "provider_cost_receipt_ledger.v1",
                            "receipt_import_contract": "normalized_artifact_digest.v1",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return row[0], row[1], tuple(row[2])

    @staticmethod
    def _environment_finding_from_snapshot(
        environment: RuntimeEnvironment,
        suite_code: str,
        snapshot_at: datetime,
        raw: dict,
    ) -> ReconciliationFinding:
        identity = {
            "environment": environment,
            "suite_code": suite_code,
            "scope_type": "environment",
            "scope_id": environment,
            "code": raw["code"],
            "category": raw["category"],
            "subject_type": raw["subject_type"],
            "subject_id": raw["subject_id"],
        }
        return ReconciliationFinding(
            finding_id=uuid4(),
            fingerprint_sha256=canonical_sha256(identity),
            code=raw["code"],
            category=raw["category"],
            severity=raw["severity"],
            owner=raw["owner"],
            subject_type=raw["subject_type"],
            subject_id=raw["subject_id"],
            expected=raw["expected"],
            observed=raw["observed"],
            first_seen_at=raw.get("first_seen_at") or snapshot_at,
            last_seen_at=snapshot_at,
            suggested_repair=raw["suggested_repair"],
            repair_kind=raw["repair_kind"],
        )

    def _billing_snapshot(
        self,
        environment: RuntimeEnvironment,
        account_id: int,
        *,
        billing_environment: Literal["test", "live"],
        run_id: UUID,
        idempotency_key: str,
        command_sha256: str,
        reason_code: str,
        actor_user_id: int,
    ) -> tuple[datetime, Literal["green", "drift"], tuple[dict, ...]]:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                WITH snapshot AS (
                    SELECT statement_timestamp() AS snapshot_at
                ), in_scope_documents AS (
                    SELECT document.*
                      FROM commercial_billing_documents document
                     WHERE document.commercial_account_id = %s
                       AND document.environment IN ('internal', %s)
                ), document_totals AS (
                    SELECT document.id AS document_id, document.provider,
                           document.document_kind,
                           COUNT(line.id) AS line_count,
                           COALESCE(SUM(line.net_consideration_ex_tax_cents), 0)
                               AS net_consideration_cents,
                           COALESCE(SUM(line.net_consideration_ex_tax_cents
                                        + line.tax_cents), 0) AS gross_due_cents
                      FROM in_scope_documents document
                      LEFT JOIN commercial_billing_lines line
                        ON line.document_id = document.id
                     GROUP BY document.id, document.provider, document.document_kind
                ), final_allocations AS (
                    SELECT run.document_id, run.id AS allocation_run_id,
                           COUNT(allocation.billing_line_id) AS allocation_count,
                           COALESCE(SUM(allocation.recognized_revenue_cents), 0)
                               AS recognized_revenue_cents
                      FROM commercial_revenue_allocation_runs run
                      LEFT JOIN commercial_revenue_allocations allocation
                        ON allocation.allocation_run_id = run.id
                     WHERE run.state = 'final'
                     GROUP BY run.document_id, run.id
                ), receipts AS (
                    SELECT movement.document_id,
                           COALESCE(SUM(movement.signed_amount_cents) FILTER (
                               WHERE movement.movement_kind = 'cash_receipt'
                           ), 0) AS cash_receipt_cents
                      FROM commercial_money_movements movement
                      JOIN in_scope_documents document
                        ON document.id = movement.document_id
                     GROUP BY movement.document_id
                ), offer_counts AS (
                    SELECT line.document_id,
                           COUNT(DISTINCT terms.offer_code) AS offer_count
                      FROM commercial_billing_lines line
                      JOIN commercial_agreement_terms terms
                        ON terms.id = line.agreement_terms_id
                      JOIN document_totals document
                        ON document.document_id = line.document_id
                     GROUP BY line.document_id
                ), candidates AS (
                    SELECT 'billing.revenue_allocation_missing'::TEXT AS code,
                           'billing'::TEXT AS category,
                           'critical'::TEXT AS severity,
                           'billing_operations'::TEXT AS owner,
                           'billing_document'::TEXT AS subject_type,
                           document.document_id::TEXT AS subject_id,
                           jsonb_build_object('required_state', 'final') AS expected,
                           jsonb_build_object(
                               'allocation_state', 'missing',
                               'provider', document.provider,
                               'line_count', document.line_count
                           ) AS observed,
                           'billing.revenue_allocate'::TEXT AS suggested_repair,
                           'operator'::TEXT AS repair_kind
                      FROM document_totals document
                      LEFT JOIN final_allocations allocation
                        ON allocation.document_id = document.document_id
                     WHERE allocation.allocation_run_id IS NULL
                    UNION ALL
                    SELECT 'billing.revenue_total_mismatch', 'billing', 'critical',
                           'finance_operations', 'billing_document',
                           document.document_id::TEXT,
                           jsonb_build_object(
                               'net_consideration_cents',
                               document.net_consideration_cents
                           ),
                           jsonb_build_object(
                               'recognized_revenue_cents',
                               allocation.recognized_revenue_cents,
                               'allocation_count', allocation.allocation_count
                           ),
                           'billing.revenue_rebuild', 'operator'
                      FROM document_totals document
                      JOIN final_allocations allocation
                        ON allocation.document_id = document.document_id
                     WHERE allocation.recognized_revenue_cents
                           <> document.net_consideration_cents
                    UNION ALL
                    SELECT 'billing.paid_receipt_shortfall', 'billing', 'error',
                           'billing_operations', 'billing_document',
                           document.document_id::TEXT,
                           jsonb_build_object(
                               'minimum_cash_receipt_cents', document.gross_due_cents
                           ),
                           jsonb_build_object(
                               'cash_receipt_cents',
                               COALESCE(receipt.cash_receipt_cents, 0),
                               'provider', document.provider
                           ),
                           'billing.money_movement_reconcile', 'investigate'
                      FROM document_totals document
                      JOIN commercial_billing_current_document_status status
                        ON status.document_id = document.document_id
                      LEFT JOIN receipts receipt
                        ON receipt.document_id = document.document_id
                     WHERE status.status = 'paid'
                       AND document.document_kind IN ('invoice', 'manual_invoice')
                       AND COALESCE(receipt.cash_receipt_cents, 0)
                           < document.gross_due_cents
                    UNION ALL
                    SELECT 'billing.noncollectible_revenue_present', 'billing',
                           'critical', 'finance_operations', 'billing_document',
                           document.document_id::TEXT,
                           jsonb_build_object('recognized_revenue_cents', 0),
                           jsonb_build_object(
                               'recognized_revenue_cents',
                               allocation.recognized_revenue_cents,
                               'status', status.status
                           ),
                           'billing.revenue_reversal_review', 'investigate'
                      FROM document_totals document
                      JOIN commercial_billing_current_document_status status
                        ON status.document_id = document.document_id
                      JOIN final_allocations allocation
                        ON allocation.document_id = document.document_id
                     WHERE status.status IN ('void', 'uncollectible')
                       AND document.document_kind IN ('invoice', 'manual_invoice')
                       AND allocation.recognized_revenue_cents > 0
                    UNION ALL
                    SELECT 'billing.offer_attribution_ambiguous', 'economics', 'error',
                           'finance_operations', 'billing_document',
                           document.document_id::TEXT,
                           jsonb_build_object('offer_count', 1),
                           jsonb_build_object(
                               'offer_count', COALESCE(offer.offer_count, 0),
                               'line_count', document.line_count
                           ),
                           'billing.offer_attribution_review', 'investigate'
                      FROM document_totals document
                      LEFT JOIN offer_counts offer
                        ON offer.document_id = document.document_id
                     WHERE COALESCE(offer.offer_count, 0) <> 1
                    UNION ALL
                    SELECT 'billing.processor_fee_allocation_missing', 'economics',
                           'error', 'finance_operations', 'money_movement',
                           movement.id::TEXT,
                           jsonb_build_object('required_state', 'final'),
                           jsonb_build_object(
                               'allocation_state', 'missing',
                               'signed_amount_cents', movement.signed_amount_cents,
                               'document_id', movement.document_id
                           ),
                           'billing.processor_fee_allocate', 'operator'
                      FROM commercial_money_movements movement
                      JOIN in_scope_documents document
                        ON document.id = movement.document_id
                     WHERE movement.movement_kind = 'processor_fee'
                       AND movement.signed_amount_cents < 0
                       AND NOT EXISTS (
                           SELECT 1
                             FROM commercial_processor_fee_allocation_runs fee_run
                            WHERE fee_run.money_movement_id = movement.id
                              AND fee_run.state = 'final'
                       )
                    UNION ALL
                    SELECT 'billing.processor_fee_source_stale', 'economics',
                           'critical', 'finance_operations',
                           'processor_fee_allocation_run', fee_run.id::TEXT,
                           jsonb_build_object(
                               'source_revenue_allocation_run_id', current_run.id
                           ),
                           jsonb_build_object(
                               'source_revenue_allocation_run_id',
                               fee_run.source_revenue_allocation_run_id,
                               'money_movement_id', fee_run.money_movement_id,
                               'document_id', fee_run.document_id
                           ),
                           'billing.processor_fee_reallocation_review', 'investigate'
                      FROM commercial_processor_fee_allocation_runs fee_run
                      JOIN in_scope_documents document
                        ON document.id = fee_run.document_id
                      JOIN commercial_revenue_allocation_runs current_run
                        ON current_run.document_id = fee_run.document_id
                       AND current_run.state = 'final'
                     WHERE fee_run.state = 'final'
                       AND fee_run.source_revenue_allocation_run_id <> current_run.id
                    UNION ALL
                    SELECT 'billing.processor_fee_unattributed', 'economics',
                           'critical', 'finance_operations', 'money_movement',
                           movement.id::TEXT,
                           jsonb_build_object('document_attribution', 'required'),
                           jsonb_build_object(
                               'document_id', NULL,
                               'signed_amount_cents', movement.signed_amount_cents
                           ),
                           'billing.processor_fee_attribution_review', 'investigate'
                      FROM commercial_money_movements movement
                     WHERE movement.commercial_account_id = %s
                       AND movement.movement_kind = 'processor_fee'
                       AND movement.document_id IS NULL
                       AND movement.environment IN ('internal', %s)
                    UNION ALL
                    SELECT 'economics.unknown_rate', 'economics', 'critical',
                           'pricing_operations', 'commercial_account', %s::TEXT,
                           jsonb_build_object('unknown_rate_event_count', 0),
                           jsonb_build_object(
                               'unknown_rate_event_count', COUNT(*),
                               'environment', %s
                           ),
                           'pricing.rate_resolve', 'investigate'
                      FROM commercial_usage_events usage
                      JOIN commercial_execution_contexts context
                        ON context.id = usage.execution_context_id
                     WHERE context.commercial_account_id = %s
                       AND context.environment = %s
                       AND usage.pricing_state = 'unknown_rate'
                    HAVING COUNT(*) > 0
                    UNION ALL
                    SELECT candidate.code, candidate.category,
                           candidate.severity, candidate.owner,
                           candidate.subject_type, candidate.subject_id,
                           candidate.expected, candidate.observed,
                           candidate.suggested_repair, candidate.repair_kind
                      FROM commercial_account_control_reconciliation_candidates candidate
                     WHERE candidate.commercial_account_id = %s
                       AND candidate.environment = %s
                    UNION ALL
                    SELECT candidate.code, candidate.category,
                           candidate.severity, candidate.owner,
                           candidate.subject_type, candidate.subject_id,
                           candidate.expected, candidate.observed,
                           candidate.suggested_repair, candidate.repair_kind
                      FROM commercial_direct_usage_reconciliation_candidates candidate
                     WHERE candidate.commercial_account_id = %s
                       AND candidate.environment = %s
                    UNION ALL
                    SELECT candidate.code, candidate.category,
                           candidate.severity, candidate.owner,
                           candidate.subject_type, candidate.subject_id,
                           candidate.expected, candidate.observed,
                           candidate.suggested_repair, candidate.repair_kind
                      FROM commercial_budget_reconciliation_candidates candidate
                     WHERE candidate.commercial_account_id = %s
                       AND candidate.environment = %s
                    UNION ALL
                    SELECT candidate.code, candidate.category,
                           candidate.severity, candidate.owner,
                           candidate.subject_type, candidate.subject_id,
                           candidate.expected, candidate.observed,
                           candidate.suggested_repair, candidate.repair_kind
                      FROM commercial_account_exception_reconciliation_candidates candidate
                     WHERE candidate.commercial_account_id = %s
                       AND candidate.environment = %s
                ), payload AS (
                    SELECT snapshot.snapshot_at,
                           COALESCE(
                           jsonb_agg(
                               jsonb_build_object(
                                   'code', candidate.code,
                                   'category', candidate.category,
                                   'severity', candidate.severity,
                                   'owner', candidate.owner,
                                   'subject_type', candidate.subject_type,
                                   'subject_id', candidate.subject_id,
                                   'expected', candidate.expected,
                                   'observed', candidate.observed,
                                   'first_seen_at', prior.first_seen_at,
                                   'suggested_repair', candidate.suggested_repair,
                                   'repair_kind', candidate.repair_kind
                               ) ORDER BY candidate.code, candidate.subject_type,
                                          candidate.subject_id
                           ) FILTER (WHERE candidate.code IS NOT NULL),
                           '[]'::jsonb
                           ) AS findings
                      FROM snapshot
                      LEFT JOIN candidates candidate ON TRUE
                      LEFT JOIN LATERAL (
                          SELECT MIN(finding.first_seen_at) AS first_seen_at
                            FROM commercial_reconciliation_findings finding
                            JOIN commercial_reconciliation_runs run
                              ON run.run_id = finding.run_id
                           WHERE run.environment = %s
                             AND run.suite_code = %s
                             AND run.scope_type = 'account'
                             AND run.scope_id = %s
                             AND finding.code = candidate.code
                             AND finding.category = candidate.category
                             AND finding.subject_type = candidate.subject_type
                             AND finding.subject_id = candidate.subject_id
                      ) prior ON TRUE
                     GROUP BY snapshot.snapshot_at
                ), inserted_run AS (
                    INSERT INTO commercial_reconciliation_runs (
                        run_id, environment, suite_code, scope_type, scope_id,
                        commercial_account_id, idempotency_key, command_sha256,
                        mode, status, finding_count, actor_user_id,
                        snapshot_at, metadata
                    )
                    SELECT %s, %s, %s, 'account', %s, %s, %s, %s,
                           'dry_run',
                           CASE WHEN jsonb_array_length(payload.findings) = 0
                                THEN 'green' ELSE 'drift' END,
                           jsonb_array_length(payload.findings), %s,
                           payload.snapshot_at, %s::jsonb
                      FROM payload
                    RETURNING snapshot_at, status
                )
                SELECT inserted_run.snapshot_at, inserted_run.status,
                       payload.findings
                  FROM inserted_run CROSS JOIN payload
                """,
                (
                    account_id,
                    billing_environment,
                    account_id,
                    billing_environment,
                    account_id,
                    environment,
                    account_id,
                    environment,
                    account_id,
                    environment,
                    account_id,
                    environment,
                    account_id,
                    environment,
                    account_id,
                    environment,
                    environment,
                    BILLING_REVENUE_ECONOMICS_SUITE,
                    str(account_id),
                    str(run_id),
                    environment,
                    BILLING_REVENUE_ECONOMICS_SUITE,
                    str(account_id),
                    account_id,
                    idempotency_key,
                    command_sha256,
                    actor_user_id,
                    json.dumps(
                        {
                            "billing_environments": [
                                "internal",
                                billing_environment,
                            ],
                            "reason_code": reason_code,
                            "snapshot_contract": "statement_snapshot.v1",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return row[0], row[1], tuple(row[2])

    @staticmethod
    def _finding_from_snapshot(
        environment: RuntimeEnvironment,
        account_id: int,
        snapshot_at: datetime,
        raw: dict,
    ) -> ReconciliationFinding:
        identity = {
            "environment": environment,
            "suite_code": BILLING_REVENUE_ECONOMICS_SUITE,
            "scope_type": "account",
            "scope_id": str(account_id),
            "code": raw["code"],
            "category": raw["category"],
            "subject_type": raw["subject_type"],
            "subject_id": raw["subject_id"],
        }
        return ReconciliationFinding(
            finding_id=uuid4(),
            fingerprint_sha256=canonical_sha256(identity),
            code=raw["code"],
            category=raw["category"],
            severity=raw["severity"],
            owner=raw["owner"],
            subject_type=raw["subject_type"],
            subject_id=raw["subject_id"],
            expected=raw["expected"],
            observed=raw["observed"],
            first_seen_at=raw["first_seen_at"] or snapshot_at,
            last_seen_at=snapshot_at,
            suggested_repair=raw["suggested_repair"],
            repair_kind=raw["repair_kind"],
        )

    def _load_provider_cost_run(
        self,
        environment: RuntimeEnvironment,
        command: ProviderCostReconciliationCommand,
        *,
        command_sha256: str,
    ) -> ProviderCostReconciliationResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT run_id, status, snapshot_at, command_sha256
                  FROM commercial_reconciliation_runs
                 WHERE environment = %s AND suite_code = %s
                   AND scope_type = 'environment' AND scope_id = %s
                   AND idempotency_key = %s
                """,
                (
                    environment,
                    PROVIDER_COST_ALLOCATION_SUITE,
                    environment,
                    command.idempotency_key,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if row[3] != command_sha256:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT
                )
            cursor.execute(
                """
                SELECT finding_id, fingerprint_sha256, code, category, severity,
                       owner, subject_type, subject_id, expected, observed,
                       first_seen_at, last_seen_at, suggested_repair, repair_kind
                  FROM commercial_reconciliation_findings
                 WHERE run_id = %s
                 ORDER BY code, subject_type, subject_id
                """,
                (str(row[0]),),
            )
            findings = tuple(self._finding_from_row(item) for item in cursor.fetchall())
        finally:
            cursor.close()
        return ProviderCostReconciliationResult(
            run_id=UUID(str(row[0])),
            environment=environment,
            idempotency_key=command.idempotency_key,
            status=row[1],
            snapshot_at=row[2],
            findings=findings,
            durable_replayed=True,
        )

    def _load_provider_cost_resolution(
        self,
        environment: RuntimeEnvironment,
        command: ProviderCostResolutionCommand,
        *,
        command_sha256: str,
    ) -> ProviderCostResolutionResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT resolution_id, source_finding_id, fingerprint_sha256,
                       resolution_kind, reason_code, actor_user_id,
                       audit_event_id, resolved_at, command_sha256
                  FROM commercial_reconciliation_resolutions
                 WHERE environment = %s AND suite_code = %s
                   AND scope_type = 'environment' AND scope_id = %s
                   AND idempotency_key = %s
                """,
                (
                    environment,
                    PROVIDER_COST_ALLOCATION_SUITE,
                    environment,
                    command.idempotency_key,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[8] != command_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return ProviderCostResolutionResult(
            resolution_id=UUID(str(row[0])),
            source_finding_id=UUID(str(row[1])),
            fingerprint_sha256=row[2],
            environment=environment,
            resolution_kind=row[3],
            reason_code=row[4],
            actor_user_id=int(row[5]),
            audit_event_id=UUID(str(row[6])),
            resolved_at=row[7],
            durable_replayed=True,
        )

    def _load_run(
        self,
        environment: RuntimeEnvironment,
        command: BillingReconciliationCommand,
        *,
        command_sha256: str,
    ) -> BillingReconciliationResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT run_id, status, snapshot_at, command_sha256
                  FROM commercial_reconciliation_runs
                 WHERE environment = %s AND suite_code = %s
                   AND scope_type = 'account' AND scope_id = %s
                   AND idempotency_key = %s
                """,
                (
                    environment,
                    BILLING_REVENUE_ECONOMICS_SUITE,
                    str(command.commercial_account_id),
                    command.idempotency_key,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if row[3] != command_sha256:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT
                )
            cursor.execute(
                """
                SELECT finding_id, fingerprint_sha256, code, category, severity,
                       owner, subject_type, subject_id, expected, observed,
                       first_seen_at, last_seen_at, suggested_repair, repair_kind
                  FROM commercial_reconciliation_findings
                 WHERE run_id = %s
                 ORDER BY code, subject_type, subject_id
                """,
                (str(row[0]),),
            )
            findings = tuple(self._finding_from_row(item) for item in cursor.fetchall())
        finally:
            cursor.close()
        return BillingReconciliationResult(
            run_id=UUID(str(row[0])),
            environment=environment,
            commercial_account_id=command.commercial_account_id,
            billing_environments=("internal", self._billing_environment()),
            idempotency_key=command.idempotency_key,
            status=row[1],
            snapshot_at=row[2],
            findings=findings,
            durable_replayed=True,
        )

    def _load_resolution(
        self,
        environment: RuntimeEnvironment,
        command: ReconciliationResolutionCommand,
        *,
        command_sha256: str,
    ) -> ReconciliationResolutionResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT resolution_id, source_finding_id, fingerprint_sha256,
                       resolution_kind, reason_code, actor_user_id,
                       audit_event_id, resolved_at, command_sha256
                  FROM commercial_reconciliation_resolutions
                 WHERE environment = %s AND suite_code = %s
                   AND scope_type = 'account' AND scope_id = %s
                   AND idempotency_key = %s
                """,
                (
                    environment,
                    BILLING_REVENUE_ECONOMICS_SUITE,
                    str(command.commercial_account_id),
                    command.idempotency_key,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[8] != command_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return ReconciliationResolutionResult(
            resolution_id=UUID(str(row[0])),
            source_finding_id=UUID(str(row[1])),
            fingerprint_sha256=row[2],
            environment=environment,
            commercial_account_id=command.commercial_account_id,
            resolution_kind=row[3],
            reason_code=row[4],
            actor_user_id=int(row[5]),
            audit_event_id=UUID(str(row[6])),
            resolved_at=row[7],
            durable_replayed=True,
        )

    @staticmethod
    def _finding_from_row(row: tuple) -> ReconciliationFinding:
        return ReconciliationFinding(
            finding_id=UUID(str(row[0])),
            fingerprint_sha256=row[1],
            code=row[2],
            category=row[3],
            severity=row[4],
            owner=row[5],
            subject_type=row[6],
            subject_id=row[7],
            expected=row[8],
            observed=row[9],
            first_seen_at=row[10],
            last_seen_at=row[11],
            suggested_repair=row[12],
            repair_kind=row[13],
        )

    def _advisory_lock(self, environment: str, account_id: int) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (
                    "commercial_reconciliation_account",
                    f"{environment}:{BILLING_REVENUE_ECONOMICS_SUITE}:{account_id}",
                ),
            )
        finally:
            cursor.close()

    def _environment_advisory_lock(self, environment: str, suite_code: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (
                    "commercial_reconciliation_environment",
                    f"{environment}:{suite_code}",
                ),
            )
        finally:
            cursor.close()

    def _run_atomic(self, operation: Callable[[], _ResultT]) -> _ResultT:
        self._require_transaction()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_reconciliation_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_reconciliation_command")
                cursor.execute("RELEASE SAVEPOINT commercial_reconciliation_command")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_reconciliation_command")
            return result
        finally:
            cursor.close()

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("commercial reconciliation requires a transaction")


__all__ = [
    "BILLING_REVENUE_ECONOMICS_SUITE",
    "PROVIDER_COST_ALLOCATION_SUITE",
    "STRIPE_PROVIDER_RECONCILIATION_SUITE",
    "STRIPE_MONETARY_RECONCILIATION_SUITE",
    "STRIPE_WEBHOOK_INBOX_RECONCILIATION_SUITE",
    "BillingReconciliationCommand",
    "BillingReconciliationResult",
    "CommercialReconciliationService",
    "ProviderCostReconciliationCommand",
    "ProviderCostReconciliationResult",
    "StripeProviderReconciliationCommand",
    "StripeProviderReconciliationResult",
    "StripeMonetaryReconciliationCommand",
    "StripeMonetaryReconciliationResult",
    "StripeWebhookInboxReconciliationCommand",
    "StripeWebhookInboxReconciliationResult",
    "ProviderCostResolutionCommand",
    "ProviderCostResolutionResult",
    "ReconciliationFinding",
    "ReconciliationResolutionCommand",
    "ReconciliationResolutionResult",
]
