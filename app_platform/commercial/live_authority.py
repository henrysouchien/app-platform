"""Current token/account/agreement state for gateway live commercial checks."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import Field

from .authorization import CommercialAuthorizationRequest, resolve_commercial_authorization
from .flags import CommercialFlags
from .models import StrictCommercialModel


class CommercialLiveContextState(StrictCommercialModel):
    context_id: UUID
    active: bool
    entitlement_revision: int = Field(ge=0)
    commercial_account_id: int | None = Field(default=None, gt=0)
    agreement_id: int | None = Field(default=None, gt=0)
    mcp_token_id: UUID | None = None


class CommercialLiveAgreementTermsState(StrictCommercialModel):
    agreement_id: UUID
    current_terms_revision: int | None = Field(default=None, gt=0)


def resolve_current_agreement_terms_revision(
    connection: Any,
    *,
    flags: CommercialFlags,
    agreement_id: UUID,
) -> CommercialLiveAgreementTermsState:
    """Resolve the effective terms revision without granting the gateway DB access."""
    flags.validate()
    if bool(getattr(connection, "autocommit", False)):
        raise ValueError("live commercial terms require autocommit disabled")
    if not flags.commercial_control_enabled:
        return CommercialLiveAgreementTermsState(agreement_id=agreement_id)
    with connection.cursor() as cursor:
        cursor.execute("SELECT clock_timestamp()")
        now = cursor.fetchone()[0]
        cursor.execute(
            """
            SELECT terms.revision
              FROM commercial_deployment_context deployment
              JOIN commercial_agreements agreement ON TRUE
              JOIN commercial_agreement_terms terms
                ON terms.agreement_id = agreement.id
             WHERE deployment.singleton = TRUE
               AND deployment.environment = %s
               AND agreement.public_id = %s
               AND terms.effective_from <= %s
               AND (terms.effective_until IS NULL OR terms.effective_until > %s)
               AND (to_jsonb(terms)->>'voided_at') IS NULL
             ORDER BY terms.revision DESC
             LIMIT 2
            """,
            (flags.environment, str(agreement_id), now, now),
        )
        rows = cursor.fetchall()
    if len(rows) > 1:
        raise RuntimeError("multiple effective commercial agreement terms")
    return CommercialLiveAgreementTermsState(
        agreement_id=agreement_id,
        current_terms_revision=int(rows[0][0]) if rows else None,
    )


def resolve_commercial_live_context_state(
    connection: Any,
    *,
    flags: CommercialFlags,
    context_id: UUID,
) -> CommercialLiveContextState:
    """Resolve live state without trusting the historical claim snapshot."""
    flags.validate()
    if bool(getattr(connection, "autocommit", False)):
        raise ValueError("live commercial state requires autocommit disabled")
    with connection.cursor() as cursor:
        cursor.execute("SELECT clock_timestamp()")
        now = cursor.fetchone()[0]
        cursor.execute(
            """
            SELECT context.environment, context.surface_code,
                   context.commercial_account_id, account.public_id,
                   context.agreement_id, context.agreement_terms_id,
                   context.user_id, context.mcp_token_id,
                   context.entitlement_revision, context.status, context.revoked_at
              FROM commercial_execution_contexts context
              JOIN commercial_accounts account ON account.id = context.commercial_account_id
             WHERE context.id = %s
            """,
            (str(context_id),),
        )
        row = cursor.fetchone()
    if row is None:
        return CommercialLiveContextState(
            context_id=context_id, active=False, entitlement_revision=0
        )
    account_id, agreement_id = int(row[2]), int(row[4])
    token_id = UUID(str(row[7])) if row[7] is not None else None
    stored_revision = int(row[8])
    def state(*, active: bool, revision: int) -> CommercialLiveContextState:
        return CommercialLiveContextState(
            context_id=context_id,
            active=active,
            entitlement_revision=revision,
            commercial_account_id=account_id,
            agreement_id=agreement_id,
            mcp_token_id=token_id,
        )
    if (
        row[0] != flags.environment
        or row[9] != "active"
        or row[10] is not None
        or token_id is None
    ):
        return state(active=False, revision=stored_revision)
    decision = resolve_commercial_authorization(
        connection,
        flags=flags,
        request=CommercialAuthorizationRequest(
            user_id=int(row[6]),
            commercial_account_public_id=UUID(str(row[3])),
            surface_code=str(row[1]),
            mcp_token_id=token_id,
            evaluated_at=now,
        ),
    )
    authority = decision.context if decision.allowed else None
    current_revision = authority.entitlement_revision if authority else stored_revision
    active = authority is not None and (
        authority.commercial_account_id == account_id
        and authority.agreement_id == agreement_id
        and authority.agreement_terms_id == int(row[5])
        and authority.user_id == int(row[6])
        and authority.entitlement_revision == stored_revision
    )
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT status, expires_at, revoked_at, expired_at,
                   commercial_account_id, agreement_id, user_id, surface_code
              FROM mcp_tokens WHERE id = %s
            """,
            (str(token_id),),
        )
        token = cursor.fetchone()
    active = active and token is not None and (
        token[0] == "active"
        and token[1] > now
        and token[2] is None
        and token[3] is None
        and int(token[4]) == account_id
        and int(token[5]) == agreement_id
        and int(token[6]) == int(row[6])
        and token[7] == row[1]
    )
    return state(active=bool(active), revision=current_revision)


__all__ = [
    "CommercialLiveAgreementTermsState",
    "CommercialLiveContextState",
    "resolve_commercial_live_context_state",
    "resolve_current_agreement_terms_revision",
]
