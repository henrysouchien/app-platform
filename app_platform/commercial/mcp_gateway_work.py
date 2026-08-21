"""Produce the two-token gateway package for one funded external MCP request."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, Protocol
from uuid import UUID

from pydantic import Field, StrictInt

from .mcp_funded_claim import (
    McpFundedClaimRequest,
    McpFundedClaimResult,
    PostgresMcpFundedClaimCoordinator,
)
from .agreement_lifecycle import IdempotencyKey
from .models import StableCode, StrictCommercialModel
from .work_authorization import (
    IssuedCommercialWorkAuthorization,
    WorkAuthorizationIssueCommand,
)


class _WorkAuthorizationIssuer(Protocol):
    @property
    def connection(self): ...

    def issue(
        self, command: WorkAuthorizationIssueCommand
    ) -> IssuedCommercialWorkAuthorization: ...


class McpGatewayWorkIntent(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    authorization_id: UUID
    workflow_run_id: UUID
    request_id: str = Field(min_length=1, max_length=255)
    session_id: str = Field(min_length=1, max_length=255)
    lifetime_seconds: StrictInt = Field(gt=0, le=300)


class McpGatewayDispatchFacts(StrictCommercialModel):
    workflow_code: StableCode
    funding_route_id: UUID
    provider: StableCode
    billing_mode: Literal["byok", "metered"]
    operation: StableCode
    capability_id: StableCode | None = None


TrustedDispatchResolver = Callable[
    [McpFundedClaimRequest, McpFundedClaimResult, McpGatewayWorkIntent],
    McpGatewayDispatchFacts,
]


class McpGatewayWorkPackageRequest(StrictCommercialModel):
    funded_claim: McpFundedClaimRequest
    intent: McpGatewayWorkIntent


class McpGatewayWorkPackage(StrictCommercialModel):
    funded_claim: McpFundedClaimResult
    work_authorization: IssuedCommercialWorkAuthorization


class PostgresMcpGatewayWorkCoordinator:
    """Return claim and one-time work authority only after both commit safely."""

    def __init__(
        self,
        *,
        funded_claims: PostgresMcpFundedClaimCoordinator,
        work_authorizations: _WorkAuthorizationIssuer,
        resolve_dispatch: TrustedDispatchResolver,
    ) -> None:
        if funded_claims.connection is not work_authorizations.connection:
            raise ValueError(
                "MCP funded claims and work authorizations must share one connection"
            )
        self._funded = funded_claims
        self._work = work_authorizations
        self._resolve_dispatch = resolve_dispatch

    def issue(self, request: McpGatewayWorkPackageRequest) -> McpGatewayWorkPackage:
        funded = self._funded.issue(request.funded_claim)
        try:
            facts = self._resolve_dispatch(request.funded_claim, funded, request.intent)
            if not isinstance(facts, McpGatewayDispatchFacts):
                raise TypeError("trusted MCP gateway dispatch facts are invalid")
            reservation = request.funded_claim.reservation
            reservation_id = None
            if facts.billing_mode == "metered":
                if reservation is None or (
                    reservation.workflow_run_id != request.intent.workflow_run_id
                    or reservation.request_id != request.intent.request_id
                ):
                    raise ValueError(
                        "metered gateway dispatch differs from reservation lineage"
                    )
                reservation_id = reservation.reservation_id
            elif reservation is not None:
                raise ValueError("BYOK gateway dispatch cannot use a reservation")
            authorization = self._work.issue(
                WorkAuthorizationIssueCommand(
                    idempotency_key=request.intent.idempotency_key,
                    authorization_id=request.intent.authorization_id,
                    environment=request.funded_claim.claim.environment,
                    execution_context_id=funded.claim.execution_context.id,
                    workflow_run_id=request.intent.workflow_run_id,
                    expected_workflow_code=facts.workflow_code,
                    funding_route_id=facts.funding_route_id,
                    expected_provider=facts.provider,
                    expected_billing_mode=facts.billing_mode,
                    reservation_id=reservation_id,
                    operation=facts.operation,
                    capability_id=facts.capability_id,
                    request_id=request.intent.request_id,
                    session_id=request.intent.session_id,
                    lifetime_seconds=request.intent.lifetime_seconds,
                )
            )
        except Exception as issue_error:
            cleanup_errors: list[Exception] = []
            if request.funded_claim.reservation is None:
                try:
                    self._abandon_byok_workflow(
                        request.intent.workflow_run_id,
                        funded.claim.execution_context.id,
                    )
                except Exception as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            try:
                self._funded.compensate(
                    request.funded_claim,
                    reason="work_authorization.issue_failed",
                )
            except Exception as cleanup_error:
                cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                raise RuntimeError(
                    "MCP gateway work issuance requires compensation repair"
                ) from cleanup_errors[0]
            raise issue_error
        return McpGatewayWorkPackage(
            funded_claim=funded,
            work_authorization=authorization,
        )

    def _abandon_byok_workflow(
        self,
        workflow_run_id: UUID,
        execution_context_id: UUID,
    ) -> None:
        connection = self._work.connection
        status = getattr(connection, "get_transaction_status", None)
        if status is None or status() != 0:
            connection.rollback()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"commercial.gateway_workflow:{workflow_run_id}",),
                )
                cursor.execute(
                    """
                    SELECT workflow.state, lineage.source_product,
                           workflow.execution_context_id, context.status
                      FROM commercial_workflow_runs workflow
                      JOIN commercial_workflow_attempt_lineage lineage
                        ON lineage.workflow_run_id = workflow.id
                       AND lineage.execution_context_id = workflow.execution_context_id
                      JOIN commercial_execution_contexts context
                        ON context.id = workflow.execution_context_id
                     WHERE workflow.id = %s
                     FOR UPDATE OF workflow, lineage, context
                    """,
                    (str(workflow_run_id),),
                )
                row = cursor.fetchone()
                if row is None or (
                    row[0] != "started"
                    or row[1] != "hank-agent-gateway"
                    or UUID(str(row[2])) != execution_context_id
                    or row[3] != "active"
                ):
                    raise RuntimeError("BYOK gateway workflow cannot be abandoned safely")
                cursor.execute(
                    """
                    SELECT 1 FROM commercial_work_start_authorizations
                     WHERE workflow_run_id = %s LIMIT 1
                    """,
                    (str(workflow_run_id),),
                )
                if cursor.fetchone() is not None:
                    raise RuntimeError("work-authorized BYOK workflow cannot be abandoned")
                cursor.execute(
                    """
                    SELECT 1 FROM commercial_usage_events
                     WHERE workflow_run_id = %s LIMIT 1
                    """,
                    (str(workflow_run_id),),
                )
                if cursor.fetchone() is not None:
                    raise RuntimeError("usage-bearing BYOK workflow cannot be abandoned")
                cursor.execute(
                    """
                    UPDATE commercial_workflow_runs
                       SET state = 'abandoned', completed_at = clock_timestamp(),
                           artifact_count = 0, success_evidence = '{}'::jsonb
                     WHERE id = %s AND state = 'started'
                    """,
                    (str(workflow_run_id),),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("BYOK workflow abandonment lost its fence")
            connection.commit()
        except Exception:
            connection.rollback()
            raise


__all__ = [
    "McpGatewayWorkPackage",
    "McpGatewayWorkPackageRequest",
    "McpGatewayWorkIntent",
    "McpGatewayDispatchFacts",
    "PostgresMcpGatewayWorkCoordinator",
]
