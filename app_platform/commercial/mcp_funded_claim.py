"""Budget-gated exposure of an already authorized external MCP claim."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import model_validator

from .budget.protocol import BudgetReservationCommand, BudgetReservationResult
from .claims import IssuedCommercialClaim
from .errors import CommercialError, CommercialErrorCode
from .execution_contexts import (
    ExecutionContextRevokeCommand,
    ExecutionContextService,
)
from .flags import CommercialFlags
from .mcp_claim_authorization import (
    McpClaimAuthorizationRequest,
    PostgresMcpClaimAuthorizationCoordinator,
)
from .models import StrictCommercialModel


ReservationRunner = Callable[
    [Any, BudgetReservationCommand], BudgetReservationResult
]
AbandonRunner = Callable[
    [Any, BudgetReservationCommand, str], BudgetReservationResult
]


class McpFundedClaimRequest(StrictCommercialModel):
    claim: McpClaimAuthorizationRequest
    reservation: BudgetReservationCommand | None = None

    @model_validator(mode="after")
    def _linked_context(self) -> "McpFundedClaimRequest":
        if (
            self.reservation is not None
            and self.reservation.execution_context_id != self.claim.context_id
        ):
            raise ValueError("MCP reservation must use the claim execution context")
        return self


class McpFundedClaimResult(StrictCommercialModel):
    claim: IssuedCommercialClaim
    reservation: BudgetReservationResult | None = None


class PostgresMcpFundedClaimCoordinator:
    """Withhold cost-bearing claims until durable budget authority is green."""

    def __init__(
        self,
        *,
        flags: CommercialFlags,
        claim_coordinator: PostgresMcpClaimAuthorizationCoordinator,
        reserve: ReservationRunner,
        abandon: AbandonRunner,
    ) -> None:
        flags.validate()
        self._flags = flags
        self._claims = claim_coordinator
        self._reserve = reserve
        self._abandon = abandon

    def issue(self, request: McpFundedClaimRequest) -> McpFundedClaimResult:
        exposure = request.claim.exposure_manifest.tools.get(request.claim.tool_key)
        if exposure is None:
            # The claim coordinator owns the stable fail-closed tool error.
            self._claims.issue(request.claim)
            raise RuntimeError("unmanifested MCP tool unexpectedly issued a claim")
        requires_reservation = exposure.cost_class != "none"
        if requires_reservation != (request.reservation is not None):
            raise ValueError(
                "cost-bearing MCP tools require exactly one budget reservation"
            )

        hidden_claim = self._claims.issue(request.claim)
        if request.reservation is None:
            return McpFundedClaimResult(claim=hidden_claim)
        context = hidden_claim.execution_context
        reservation = request.reservation
        if (
            reservation.agreement_terms_id != context.agreement_terms_id
            or reservation.authorized_work_start_deadline
            != context.authorized_work_start_deadline
            or reservation.late_child_accept_until != context.usage_accept_until
        ):
            self._revoke_hidden_context(request, reason="budget.context_mismatch")
            raise ValueError("MCP reservation authority differs from execution context")
        try:
            reserved = self._reserve(self._claims.connection, reservation)
        except Exception:
            self._compensate(
                request,
                reason="budget.reserve_failed",
            )
            raise
        if reserved.reservation_id != reservation.reservation_id:
            self._compensate(
                request,
                reason="budget.result_identity_mismatch",
            )
            raise RuntimeError("reservation result identity mismatch")
        if reserved.decision != "allow" or reserved.state != "reserved":
            self._revoke_hidden_context(request, reason="budget.reserve_blocked")
            raise CommercialError(CommercialErrorCode.BUDGET_HARD_LIMIT)
        if (
            reserved.lease_version != reservation.lease_version + 1
            or reserved.redis_generation != reservation.redis_generation
        ):
            self._compensate(
                request,
                reason="budget.result_fence_mismatch",
            )
            raise RuntimeError("reservation result fence mismatch")

        # Re-run current token, tenant, entitlement, emergency-deny, and manifest
        # checks after reservation. Exact JTI replay returns the committed claim only
        # when every immutable context fact still agrees.
        try:
            final_claim = self._claims.issue(request.claim)
        except Exception:
            self._compensate(
                request,
                reason="budget.final_recheck_failed",
            )
            raise
        return McpFundedClaimResult(claim=final_claim, reservation=reserved)

    @property
    def connection(self):
        return self._claims.connection

    def compensate(self, request: McpFundedClaimRequest, *, reason: str) -> None:
        """Release hidden funded authority after a downstream pre-work failure."""

        self._compensate(request, reason=reason)

    def _compensate(
        self,
        request: McpFundedClaimRequest,
        *,
        reason: str,
    ) -> None:
        reservation = request.reservation
        if reservation is None:
            self._revoke_hidden_context(request, reason=reason)
            return
        abandon_error: Exception | None = None
        try:
            abandoned = self._abandon(
                self._claims.connection,
                reservation,
                reason,
            )
            if (
                abandoned.reservation_id != reservation.reservation_id
                or abandoned.decision != "block"
                or abandoned.state != "released"
                or abandoned.lease_version
                not in {
                    reservation.lease_version,
                    reservation.lease_version + 1,
                    reservation.lease_version + 2,
                }
            ):
                raise RuntimeError("reservation abandonment result is invalid")
        except Exception as error:
            abandon_error = error
        try:
            self._revoke_hidden_context(request, reason=reason)
        except Exception as revoke_error:
            if abandon_error is not None:
                raise RuntimeError(
                    "MCP claim reservation and context compensation both require repair"
                ) from revoke_error
            raise
        if abandon_error is not None:
            raise RuntimeError(
                "MCP claim reservation compensation requires repair"
            ) from abandon_error

    def _revoke_hidden_context(
        self,
        request: McpFundedClaimRequest,
        *,
        reason: str,
    ) -> None:
        connection = self._claims.connection
        if bool(getattr(connection, "autocommit", False)):
            raise RuntimeError("MCP context compensation requires a transaction")
        transaction_status = getattr(connection, "get_transaction_status", None)
        if transaction_status is None or transaction_status() != 0:
            connection.rollback()
        try:
            ExecutionContextService(
                connection,
                flags=self._flags,
                clock=lambda: request.claim.issued_at,
            ).revoke(
                ExecutionContextRevokeCommand(
                    environment=request.claim.environment,
                    execution_context_id=request.claim.context_id,
                    reason_code=reason,
                    revoked_at=request.claim.issued_at,
                )
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise


__all__ = [
    "McpFundedClaimRequest",
    "McpFundedClaimResult",
    "PostgresMcpFundedClaimCoordinator",
]
