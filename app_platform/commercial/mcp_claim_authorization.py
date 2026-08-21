"""Atomic verified MCP authority, dynamic scope, context, and claim composition."""

from __future__ import annotations

from typing import Literal, Protocol
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictInt

from .authorization import CommercialDenialReason
from .claims import (
    ExecutionClaimIssueCommand,
    IssuedCommercialClaim,
)
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .mcp_commercial_authorization import (
    VerifiedMcpAuthorizationRequest,
    resolve_verified_mcp_authorization,
)
from .mcp_exposure import McpExposureManifest
from .mcp_scope_authority import (
    McpDynamicScopeRequest,
    resolve_mcp_dynamic_scopes,
)
from .mcp_token_verification import McpTokenVerificationResult
from .models import StableCode, StrictCommercialModel


class _ResolvedClaimIssuer(Protocol):
    @property
    def connection(self): ...

    def issue_resolved(self, resolve_command) -> IssuedCommercialClaim: ...


class McpClaimAuthorizationRequest(StrictCommercialModel):
    context_id: UUID
    environment: Literal["dev", "staging", "prod"]
    verification: McpTokenVerificationResult
    tool_key: str = Field(pattern=r"^[a-z][a-z0-9-]*:[a-z][a-z0-9_]*$")
    exposure_manifest: McpExposureManifest
    emergency_denied_scopes: tuple[StableCode, ...] = ()
    shadow_rate_policy_id: StrictInt = Field(gt=0)
    manifest_policy_id: StrictInt = Field(gt=0)
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorized_work_start_deadline: AwareDatetime
    usage_accept_until: AwareDatetime


class PostgresMcpClaimAuthorizationCoordinator:
    """Expose a signed claim only after current authority and context commit together."""

    def __init__(
        self,
        *,
        flags: CommercialFlags,
        claim_issuer: _ResolvedClaimIssuer,
    ) -> None:
        flags.validate()
        self._flags = flags
        self._claim_issuer = claim_issuer

    @property
    def connection(self):
        return self._claim_issuer.connection

    def issue(
        self, request: McpClaimAuthorizationRequest
    ) -> IssuedCommercialClaim:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_entitlement_projection_enabled
            and self._flags.commercial_usage_ingest_enabled
            and self._flags.commercial_budget_enforcement_enabled
            and self._flags.mcp_external_auth_enabled
        ):
            raise ValueError("external MCP claim authorization is disabled")
        if request.environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.TOKEN_INVALID)

        def resolve_command(connection) -> ExecutionClaimIssueCommand:
            commercial = resolve_verified_mcp_authorization(
                connection,
                flags=self._flags,
                request=VerifiedMcpAuthorizationRequest(
                    verification=request.verification,
                    evaluated_at=request.issued_at,
                ),
            )
            if not commercial.allowed or commercial.context is None:
                raise CommercialError(
                    _commercial_denial_code(commercial.denial_reason)
                )
            scope = resolve_mcp_dynamic_scopes(
                request.exposure_manifest,
                McpDynamicScopeRequest(
                    tool_key=request.tool_key,
                    user_id=request.verification.user_id,
                    token_id=request.verification.token_id,
                    authorized_at=request.issued_at,
                    token_requested_scopes=request.verification.requested_scopes,
                    applicable_entitlements=commercial.context.effective_entitlements,
                    emergency_denied_scopes=request.emergency_denied_scopes,
                ),
            )
            if not scope.allowed:
                if scope.denial_code is None:
                    raise RuntimeError("dynamic MCP scope denial has no stable code")
                raise CommercialError(scope.denial_code)
            return ExecutionClaimIssueCommand(
                context_id=request.context_id,
                environment=request.environment,
                authorization=commercial.context,
                mcp_token_id=request.verification.token_id,
                effective_scopes=scope.effective_scopes,
                shadow_rate_policy_id=request.shadow_rate_policy_id,
                manifest_policy_id=request.manifest_policy_id,
                expected_manifest_version=scope.manifest_version,
                expected_manifest_sha256=scope.manifest_sha256,
                issued_at=request.issued_at,
                expires_at=request.expires_at,
                authorized_work_start_deadline=request.authorized_work_start_deadline,
                usage_accept_until=request.usage_accept_until,
            )

        return self._claim_issuer.issue_resolved(resolve_command)


def _commercial_denial_code(
    reason: CommercialDenialReason | None,
) -> CommercialErrorCode:
    token_codes = {
        CommercialDenialReason.TOKEN_INVALID: CommercialErrorCode.TOKEN_INVALID,
        CommercialDenialReason.TOKEN_EXPIRED: CommercialErrorCode.TOKEN_EXPIRED,
        CommercialDenialReason.TOKEN_REVOKED: CommercialErrorCode.TOKEN_REVOKED,
    }
    if reason in token_codes:
        return token_codes[reason]
    if reason == CommercialDenialReason.AGREEMENT_STATE_DENIED:
        return CommercialErrorCode.COMMERCIAL_AGREEMENT_INACTIVE
    if reason in {
        CommercialDenialReason.ENTITLEMENT_MISSING,
        CommercialDenialReason.ENTITLEMENT_DENIED,
    }:
        return CommercialErrorCode.ENTITLEMENT_REQUIRED
    if reason in {
        CommercialDenialReason.ACCOUNT_NOT_FOUND,
        CommercialDenialReason.MEMBERSHIP_INACTIVE,
        CommercialDenialReason.AGREEMENT_MISSING,
        CommercialDenialReason.TERMS_MISSING,
        CommercialDenialReason.ENTITLEMENT_REVISION_MISSING,
    }:
        return CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED
    return CommercialErrorCode.BILLING_SYNC_PENDING


__all__ = [
    "McpClaimAuthorizationRequest",
    "PostgresMcpClaimAuthorizationCoordinator",
]
