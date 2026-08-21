"""Fresh transactional authority check at an irreversible provider boundary."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from .authorization import (
    CommercialAuthorizationRequest,
    CommercialDenialReason,
    resolve_commercial_authorization,
)
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .mcp_exposure import McpExposureManifest
from .mcp_scope_authority import McpDynamicScopeRequest, resolve_mcp_dynamic_scopes
from .models import StableCode, StrictCommercialModel


class IrreversibleAuthorityRequest(StrictCommercialModel):
    execution_context_id: UUID
    work_authorization_id: UUID
    workflow_run_id: UUID
    expected_entitlement_revision: int = Field(gt=0)
    environment: Literal["dev", "staging", "prod"]
    tool_key: str
    request_id: str
    session_id: str
    operation: StableCode
    capability_id: StableCode | None = None
    provider: StableCode
    billing_mode: Literal["byok", "metered"]
    exposure_manifest: McpExposureManifest
    emergency_denied_scopes: tuple[StableCode, ...] = ()


class IrreversibleAuthorityResult(StrictCommercialModel):
    execution_context_id: UUID
    tool_key: str
    commercial_account_id: int
    agreement_id: int
    user_id: int
    mcp_token_id: UUID
    entitlement_revision: int
    evaluated_at: AwareDatetime


def authorize_irreversible_submission(
    connection: Any,
    *,
    flags: CommercialFlags,
    request: IrreversibleAuthorityRequest,
) -> IrreversibleAuthorityResult:
    """Hold current commercial authority locks through provider submission.

    The caller owns the transaction and must invoke the provider mutation before
    releasing it. This prevents a concurrent revoke or entitlement projection
    from completing between this check and submission.
    """

    flags.validate()
    if not (
        flags.commercial_control_enabled
        and flags.commercial_entitlement_projection_enabled
        and flags.mcp_external_auth_enabled
    ):
        raise ValueError("irreversible commercial authorization is disabled")
    if request.environment != flags.environment:
        raise CommercialError(CommercialErrorCode.TOKEN_INVALID)
    if bool(getattr(connection, "autocommit", False)):
        raise ValueError("irreversible authorization requires autocommit disabled")
    exposure = request.exposure_manifest.tools.get(request.tool_key)
    if exposure is None or exposure.safety_class != "irreversible":
        raise CommercialError(CommercialErrorCode.TOOL_NOT_EXPOSED)

    with connection.cursor() as cursor:
        cursor.execute("SELECT clock_timestamp()", ())
        evaluated_at = cursor.fetchone()[0]
        cursor.execute(
            """
            SELECT context.environment, context.audience, context.surface_code,
                   context.commercial_account_id, account.public_id,
                   context.agreement_id, context.agreement_terms_id,
                   context.user_id, context.mcp_token_id,
                   context.entitlement_revision, context.effective_scopes,
                   context.manifest_policy_id,
                   context.status, context.revoked_at
              FROM commercial_execution_contexts context
              JOIN commercial_accounts account
                ON account.id = context.commercial_account_id
             WHERE context.id = %s
            """,
            (str(request.execution_context_id),),
        )
        initial = cursor.fetchone()
    if initial is None or initial[0] != request.environment or initial[1] != "hank-agent-gateway":
        raise CommercialError(CommercialErrorCode.TOKEN_INVALID)
    if int(initial[9]) != request.expected_entitlement_revision:
        raise CommercialError(CommercialErrorCode.TOKEN_INVALID)
    if initial[12] != "active" or initial[13] is not None:
        raise CommercialError(CommercialErrorCode.TOKEN_REVOKED)
    if initial[8] is None:
        raise CommercialError(CommercialErrorCode.TOKEN_INVALID)

    token_id = UUID(str(initial[8]))
    decision = resolve_commercial_authorization(
        connection,
        flags=flags,
        request=CommercialAuthorizationRequest(
            user_id=int(initial[7]),
            commercial_account_public_id=UUID(str(initial[4])),
            surface_code=str(initial[2]),
            mcp_token_id=token_id,
            evaluated_at=evaluated_at,
        ),
    )
    if not decision.allowed or decision.context is None:
        raise CommercialError(_denial_code(decision.denial_reason))
    authority = decision.context
    if (
        authority.commercial_account_id != int(initial[3])
        or authority.agreement_id != int(initial[5])
        or authority.agreement_terms_id != int(initial[6])
        or authority.user_id != int(initial[7])
        or authority.entitlement_revision != int(initial[9])
    ):
        raise CommercialError(CommercialErrorCode.ENTITLEMENT_REQUIRED)

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT status, revoked_at, expired_at, expires_at, requested_scopes,
                   commercial_account_id, agreement_id, user_id, surface_code
              FROM mcp_tokens WHERE id = %s FOR SHARE
            """,
            (str(token_id),),
        )
        token = cursor.fetchone()
        cursor.execute(
            """
            SELECT status, revoked_at, entitlement_revision, manifest_policy_id,
                   audience, effective_scopes
              FROM commercial_execution_contexts
             WHERE id = %s FOR SHARE
            """,
            (str(request.execution_context_id),),
        )
        current = cursor.fetchone()
        cursor.execute(
            """
            SELECT content_sha256, body_json->>'manifest_version'
              FROM commercial_policy_versions
             WHERE id = %s AND policy_kind = 'manifest' FOR SHARE
            """,
            (int(initial[11]),),
        )
        manifest_policy = cursor.fetchone()
        cursor.execute(
            """
            SELECT execution_context_id, workflow_run_id, request_id, session_id,
                   operation, capability_id, provider, billing_mode, expires_at
              FROM commercial_work_start_authorizations
             WHERE authorization_id = %s FOR SHARE
            """,
            (str(request.work_authorization_id),),
        )
        work_authority = cursor.fetchone()
        cursor.execute("SELECT clock_timestamp()", ())
        evaluated_at = cursor.fetchone()[0]
    if (
        token is None
        or current is None
        or manifest_policy is None
        or work_authority is None
    ):
        raise CommercialError(CommercialErrorCode.TOKEN_INVALID)
    if token[0] == "revoked" or token[1] is not None:
        raise CommercialError(CommercialErrorCode.TOKEN_REVOKED)
    if token[0] == "expired" or token[2] is not None or token[3] <= evaluated_at:
        raise CommercialError(CommercialErrorCode.TOKEN_EXPIRED)
    if (
        token[0] != "active"
        or int(token[5]) != authority.commercial_account_id
        or int(token[6]) != authority.agreement_id
        or int(token[7]) != authority.user_id
        or token[8] != authority.surface_code
        or current[0] != "active"
        or current[1] is not None
        or int(current[2]) != authority.entitlement_revision
        or int(current[3]) != int(initial[11])
        or current[4] != "hank-agent-gateway"
        or tuple(current[5]) != tuple(initial[10])
        or manifest_policy[0] != request.exposure_manifest.content_sha256
        or manifest_policy[1] != request.exposure_manifest.manifest_version
        or UUID(str(work_authority[0])) != request.execution_context_id
        or UUID(str(work_authority[1])) != request.workflow_run_id
        or work_authority[2] != request.request_id
        or work_authority[3] != request.session_id
        or work_authority[4] != request.operation
        or work_authority[5] != request.capability_id
        or work_authority[6] != request.provider
        or work_authority[7] != request.billing_mode
        or work_authority[8] <= evaluated_at
    ):
        raise CommercialError(CommercialErrorCode.TOKEN_INVALID)

    final_decision = resolve_commercial_authorization(
        connection,
        flags=flags,
        request=CommercialAuthorizationRequest(
            user_id=int(initial[7]),
            commercial_account_public_id=UUID(str(initial[4])),
            surface_code=str(initial[2]),
            mcp_token_id=token_id,
            evaluated_at=evaluated_at,
        ),
    )
    if not final_decision.allowed or final_decision.context is None:
        raise CommercialError(_denial_code(final_decision.denial_reason))
    if final_decision.context != authority.model_copy(update={"evaluated_at": evaluated_at}):
        raise CommercialError(CommercialErrorCode.ENTITLEMENT_REQUIRED)
    authority = final_decision.context

    scope = resolve_mcp_dynamic_scopes(
        request.exposure_manifest,
        McpDynamicScopeRequest(
            tool_key=request.tool_key,
            user_id=authority.user_id,
            token_id=token_id,
            authorized_at=evaluated_at,
            token_requested_scopes=tuple(token[4]),
            applicable_entitlements=authority.effective_entitlements,
            emergency_denied_scopes=request.emergency_denied_scopes,
        ),
    )
    if not scope.allowed:
        raise CommercialError(scope.denial_code or CommercialErrorCode.TOKEN_SCOPE_DENIED)
    if not set(scope.effective_scopes).issubset(set(initial[10])):
        raise CommercialError(CommercialErrorCode.TOKEN_SCOPE_DENIED)
    return IrreversibleAuthorityResult(
        execution_context_id=request.execution_context_id,
        tool_key=request.tool_key,
        commercial_account_id=authority.commercial_account_id,
        agreement_id=authority.agreement_id,
        user_id=authority.user_id,
        mcp_token_id=token_id,
        entitlement_revision=authority.entitlement_revision,
        evaluated_at=evaluated_at,
    )


def _denial_code(reason: CommercialDenialReason | None) -> CommercialErrorCode:
    if reason == CommercialDenialReason.AGREEMENT_STATE_DENIED:
        return CommercialErrorCode.COMMERCIAL_AGREEMENT_INACTIVE
    if reason in {
        CommercialDenialReason.ENTITLEMENT_MISSING,
        CommercialDenialReason.ENTITLEMENT_DENIED,
    }:
        return CommercialErrorCode.ENTITLEMENT_REQUIRED
    return CommercialErrorCode.BILLING_SYNC_PENDING


__all__ = [
    "IrreversibleAuthorityRequest",
    "IrreversibleAuthorityResult",
    "authorize_irreversible_submission",
]
