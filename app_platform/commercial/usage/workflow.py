"""Durable lifecycle and binding for direct commercial workflows."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import re
from typing import Callable, Iterator, Literal, Mapping, Protocol
from uuid import UUID

from ..flags import CommercialFlags
from .direct import (
    DirectCommercialUsageContext,
    DirectCommercialUsageEmitter,
    bind_direct_commercial_usage,
)
from .workflow_attempts import (
    PostgresWorkflowAttemptService,
    WorkflowAttemptKind,
    WorkflowAttemptStartCommand,
)


_SAFE_CODE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_SUCCESS_EVIDENCE_VALUES = {
    "artifact_type": frozenset(
        {
            "none",
            "portfolio_report",
            "risk_analysis",
            "scenario_analysis",
            "optimization_result",
            "research_document",
            "presentation",
            "spreadsheet",
            "trade_receipt",
        }
    ),
    "completion_kind": frozenset(
        {
            "artifact_created",
            "action_completed",
            "provider_call_completed",
            "no_artifact",
        }
    ),
    "result_code": frozenset({"succeeded", "partial", "no_change"}),
}


class DirectWorkflowLifecycleError(RuntimeError):
    pass


class DirectReservationStartAuthorizer(Protocol):
    def authorize_start(
        self,
        connection,
        *,
        reservation_id: UUID,
        execution_context_id: UUID,
        funding_route_id: UUID,
        workflow_run_id: UUID,
        started_at: datetime,
    ) -> None: ...


def _safe_success_evidence(value: Mapping[str, object] | None) -> dict[str, object]:
    evidence = dict(value or {})
    if set(evidence) - set(_SUCCESS_EVIDENCE_VALUES):
        raise ValueError("workflow success evidence key is not allowlisted")
    for key, item in evidence.items():
        if not isinstance(item, str) or item not in _SUCCESS_EVIDENCE_VALUES[key]:
            raise ValueError("workflow success evidence value is not allowlisted")
    if len(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()) > 4096:
        raise ValueError("workflow success evidence exceeds size limit")
    return evidence


class DirectWorkflowHandle:
    __slots__ = ("_context", "artifact_count", "success_evidence", "_completed")

    def __init__(self, context: DirectCommercialUsageContext) -> None:
        self._context = context
        self.artifact_count = 0
        self.success_evidence: dict[str, object] = {}
        self._completed = False

    @property
    def context(self) -> DirectCommercialUsageContext:
        return self._context

    def mark_success(
        self,
        *,
        artifact_count: int = 0,
        success_evidence: Mapping[str, object] | None = None,
    ) -> None:
        if self._completed:
            raise DirectWorkflowLifecycleError("completed workflow handle is immutable")
        if artifact_count < 0:
            raise ValueError("workflow artifact count cannot be negative")
        self.artifact_count = artifact_count
        self.success_evidence = _safe_success_evidence(success_evidence)

    def _mark_completed(self) -> None:
        if self._completed:
            raise DirectWorkflowLifecycleError("workflow handle was already completed")
        self._completed = True


class DirectCommercialWorkflowService:
    def __init__(
        self,
        *,
        connection_factory: Callable[[], object],
        flags: CommercialFlags,
        emitter: DirectCommercialUsageEmitter,
        reservation_authorizer: DirectReservationStartAuthorizer | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        flags.validate()
        self._connection_factory = connection_factory
        self._flags = flags
        self._emitter = emitter
        self._reservation_authorizer = reservation_authorizer
        self._clock = clock

    def start(
        self,
        *,
        workflow_run_id: UUID,
        attempt_idempotency_key: str,
        execution_context_id: UUID,
        funding_route_id: UUID,
        workflow_code: str,
        primary_inference_observability: Literal[
            "hank_metered", "hank_byok_observed", "external_unobserved", "none"
        ],
        request_id: str,
        session_id: str,
        channel: str,
        capability_id: str | None = None,
        parent_turn_id: str | None = None,
        reservation_id: UUID | None = None,
        attempt_kind: WorkflowAttemptKind = "initial",
        retry_of_workflow_run_id: UUID | None = None,
    ) -> DirectWorkflowHandle:
        if not self._flags.commercial_usage_ingest_enabled:
            raise DirectWorkflowLifecycleError("commercial direct workflow is disabled")
        for value in (workflow_code, channel):
            if not _SAFE_CODE.fullmatch(value):
                raise ValueError("commercial direct workflow codes are invalid")
        if capability_id is not None and not _SAFE_CODE.fullmatch(capability_id):
            raise ValueError("commercial direct capability is invalid")
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("commercial workflow clock must be timezone-aware")
        connection = self._connection_factory()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT context.authorized_work_start_deadline, context.status,
                           context.revoked_at, rate.version AS shadow_rate_version,
                           route.billing_mode, route.provider, route.effective_from,
                           route.effective_until, route.revoked_at AS route_revoked_at
                      FROM commercial_execution_contexts context
                      JOIN commercial_policy_versions rate
                        ON rate.id = context.shadow_rate_policy_id
                       AND rate.policy_kind = 'rate' AND rate.state IN ('active', 'retired')
                      JOIN commercial_funding_routes route
                        ON route.id = %s
                       AND route.environment = context.environment
                       AND route.commercial_account_id = context.commercial_account_id
                       AND route.agreement_id = context.agreement_id
                       AND route.agreement_terms_id = context.agreement_terms_id
                       AND route.classification_state = 'active'
                     WHERE context.id = %s AND context.environment = %s
                     FOR SHARE OF context, route
                    """,
                    (
                        str(funding_route_id),
                        str(execution_context_id),
                        self._flags.environment,
                    ),
                )
                row = cursor.fetchone()
                if row is None:
                    raise DirectWorkflowLifecycleError(
                        "commercial direct lineage not found"
                    )
                values = self._row_values(row)
                (
                    start_deadline,
                    context_status,
                    context_revoked_at,
                    shadow_rate_version,
                    billing_mode,
                    provider,
                    route_from,
                    route_until,
                    route_revoked_at,
                ) = values
                if (
                    context_status != "active"
                    or context_revoked_at is not None
                    or now > start_deadline
                    or now < route_from
                    or (route_until is not None and now >= route_until)
                    or (route_revoked_at is not None and now >= route_revoked_at)
                ):
                    raise DirectWorkflowLifecycleError(
                        "commercial direct lineage is outside its authorized start window"
                    )
                if (billing_mode == "metered") != (reservation_id is not None):
                    raise DirectWorkflowLifecycleError(
                        "commercial direct reservation does not match billing mode"
                    )
                if billing_mode == "metered":
                    if self._reservation_authorizer is None:
                        raise DirectWorkflowLifecycleError(
                            "metered direct workflow reservation authorization is unavailable"
                        )
                if (
                    billing_mode == "metered"
                    and primary_inference_observability == "hank_byok_observed"
                ) or (
                    billing_mode == "byok"
                    and primary_inference_observability == "hank_metered"
                ):
                    raise DirectWorkflowLifecycleError(
                        "commercial direct observability does not match billing mode"
                    )
                attempt = PostgresWorkflowAttemptService(connection).start(
                    WorkflowAttemptStartCommand(
                        idempotency_key=attempt_idempotency_key,
                        workflow_run_id=workflow_run_id,
                        execution_context_id=execution_context_id,
                        source_product="risk-module-direct",
                        workflow_code=workflow_code,
                        primary_inference_observability=(
                            primary_inference_observability
                        ),
                        started_at=now,
                        attempt_kind=attempt_kind,
                        retry_of_workflow_run_id=retry_of_workflow_run_id,
                    )
                )
                if attempt.replayed:
                    raise DirectWorkflowLifecycleError(
                        "commercial workflow start already exists and requires reconciliation"
                    )
                direct_context = DirectCommercialUsageContext(
                    execution_context_id=execution_context_id,
                    workflow_run_id=workflow_run_id,
                    workflow_attempt_group_id=attempt.attempt_group_id,
                    workflow_attempt_number=attempt.attempt_number,
                    retry_of_workflow_run_id=attempt.retry_of_workflow_run_id,
                    workflow_attempt_kind=attempt.attempt_kind,
                    funding_route_id=funding_route_id,
                    provider=provider,
                    reservation_id=reservation_id,
                    request_id=request_id,
                    session_id=session_id,
                    parent_turn_id=parent_turn_id,
                    channel=channel,
                    capability_id=capability_id,
                    shadow_rate_version=shadow_rate_version,
                    raw_billing_mode=billing_mode,
                )
                if billing_mode == "metered":
                    self._reservation_authorizer.authorize_start(
                        connection,
                        reservation_id=reservation_id,
                        execution_context_id=execution_context_id,
                        funding_route_id=funding_route_id,
                        workflow_run_id=workflow_run_id,
                        started_at=now,
                    )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return DirectWorkflowHandle(context=direct_context)

    def complete(
        self,
        handle: DirectWorkflowHandle,
        *,
        state: Literal["succeeded", "failed", "canceled", "abandoned"],
    ) -> None:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("commercial workflow clock must be timezone-aware")
        evidence = (
            _safe_success_evidence(handle.success_evidence)
            if state == "succeeded"
            else {}
        )
        artifact_count = handle.artifact_count if state == "succeeded" else 0
        connection = self._connection_factory()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE commercial_workflow_runs
                       SET state = %s, completed_at = %s, artifact_count = %s,
                           success_evidence = %s::jsonb
                     WHERE id = %s AND execution_context_id = %s AND state = 'started'
                    """,
                    (
                        state,
                        now,
                        artifact_count,
                        json.dumps(evidence),
                        str(handle.context.workflow_run_id),
                        str(handle.context.execution_context_id),
                    ),
                )
                if cursor.rowcount != 1:
                    raise DirectWorkflowLifecycleError(
                        "commercial direct workflow completion was not applied"
                    )
            connection.commit()
            handle._mark_completed()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def workflow(self, **start_facts) -> Iterator[DirectWorkflowHandle]:
        handle = self.start(**start_facts)
        try:
            with bind_direct_commercial_usage(
                context=handle.context,
                emitter=self._emitter,
            ):
                yield handle
        except BaseException as work_error:
            try:
                self.complete(handle, state="failed")
            except BaseException as completion_error:
                raise BaseExceptionGroup(
                    "commercial workflow work and failure finalization both failed",
                    [work_error, completion_error],
                ) from None
            raise
        else:
            self.complete(handle, state="succeeded")

    @staticmethod
    def _row_values(row) -> tuple[object, ...]:
        if isinstance(row, Mapping):
            return (
                row["authorized_work_start_deadline"],
                row["status"],
                row["revoked_at"],
                row["shadow_rate_version"],
                row["billing_mode"],
                row["provider"],
                row["effective_from"],
                row["effective_until"],
                row["route_revoked_at"],
            )
        return tuple(row)


__all__ = [
    "DirectCommercialWorkflowService",
    "DirectReservationStartAuthorizer",
    "DirectWorkflowHandle",
    "DirectWorkflowLifecycleError",
]
