"""Revalidated commercial authority for a previously verified MCP bearer."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from pydantic import AwareDatetime

from .authorization import (
    CommercialAuthorizationDecision,
    CommercialAuthorizationRequest,
    CommercialDenialReason,
    resolve_commercial_authorization,
)
from .flags import CommercialFlags
from .mcp_token_verification import McpTokenVerificationResult
from .models import StrictCommercialModel


_MAX_VERIFICATION_AGE = timedelta(seconds=30)


class VerifiedMcpAuthorizationRequest(StrictCommercialModel):
    verification: McpTokenVerificationResult
    evaluated_at: AwareDatetime


def _denied(reason: CommercialDenialReason) -> CommercialAuthorizationDecision:
    return CommercialAuthorizationDecision(allowed=False, denial_reason=reason)


def resolve_verified_mcp_authorization(
    connection: Any,
    *,
    flags: CommercialFlags,
    request: VerifiedMcpAuthorizationRequest,
) -> CommercialAuthorizationDecision:
    """Re-lock the verified token tuple and load its current entitlement revision."""

    if bool(getattr(connection, "autocommit", False)):
        raise ValueError("verified MCP authorization requires autocommit disabled")
    verification = request.verification
    if (
        request.evaluated_at < verification.verified_at
        or request.evaluated_at - verification.verified_at > _MAX_VERIFICATION_AGE
    ):
        return _denied(CommercialDenialReason.TOKEN_INVALID)

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT public_id
              FROM commercial_accounts
             WHERE id = %s
             FOR SHARE
            """,
            (verification.commercial_account_id,),
        )
        account = cursor.fetchone()
    if account is None:
        return _denied(CommercialDenialReason.TOKEN_INVALID)

    decision = resolve_commercial_authorization(
        connection,
        flags=flags,
        request=CommercialAuthorizationRequest(
            user_id=verification.user_id,
            commercial_account_public_id=account[0],
            surface_code=verification.surface_code,
            mcp_token_id=verification.token_id,
            evaluated_at=request.evaluated_at,
        ),
    )
    if not decision.allowed:
        return decision
    context = decision.context
    if context is None or (
        context.commercial_account_id != verification.commercial_account_id
        or context.agreement_id != verification.agreement_id
        or context.user_id != verification.user_id
        or context.surface_code != verification.surface_code
    ):
        return _denied(CommercialDenialReason.TOKEN_INVALID)

    # Token lifecycle commands acquire account/agreement/revision authority first and
    # the token row last. Preserve that order here, then close the post-verification
    # revoke/rotate/expiry window while all authority locks remain held.
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT commercial_account_id, user_id, agreement_id, surface_code,
                   requested_scopes, status, expires_at, revoked_at, expired_at
              FROM mcp_tokens
             WHERE id = %s
             FOR SHARE
            """,
            (str(verification.token_id),),
        )
        token = cursor.fetchone()
    if token is None:
        return _denied(CommercialDenialReason.TOKEN_INVALID)
    if str(token[5]) == "revoked" or token[7] is not None:
        return _denied(CommercialDenialReason.TOKEN_REVOKED)
    if str(token[5]) == "expired" or token[8] is not None or token[6] <= request.evaluated_at:
        return _denied(CommercialDenialReason.TOKEN_EXPIRED)
    if (
        int(token[0]) != verification.commercial_account_id
        or int(token[1]) != verification.user_id
        or int(token[2]) != verification.agreement_id
        or str(token[3]) != verification.surface_code
        or tuple(token[4]) != verification.requested_scopes
        or str(token[5]) != "active"
    ):
        return _denied(CommercialDenialReason.TOKEN_INVALID)
    return decision


__all__ = [
    "VerifiedMcpAuthorizationRequest",
    "resolve_verified_mcp_authorization",
]
