"""Revision-aware commercial authorization beside identity authentication."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, ContextManager, Literal
from uuid import UUID

from fastapi import Depends, HTTPException, Request
from pydantic import AwareDatetime, Field, model_validator

from .entitlements import CanonicalEntitlementFact, resolve_effective_entitlements
from .flags import CommercialFlags
from .models import StableCode, StrictCommercialModel


class CommercialDenialReason(StrEnum):
    COMMERCIAL_DISABLED = "commercial_disabled"
    ACCOUNT_NOT_FOUND = "account_not_found"
    MEMBERSHIP_INACTIVE = "membership_inactive"
    AGREEMENT_MISSING = "agreement_missing"
    AGREEMENT_STATE_DENIED = "agreement_state_denied"
    TERMS_MISSING = "terms_missing"
    ENTITLEMENT_REVISION_MISSING = "entitlement_revision_missing"
    ENTITLEMENT_MISSING = "entitlement_missing"
    ENTITLEMENT_DENIED = "entitlement_denied"
    ENTITLEMENT_DATA_INVALID = "entitlement_data_invalid"
    TOKEN_INVALID = "token_invalid"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"


class CommercialAuthorizationRequest(StrictCommercialModel):
    user_id: int = Field(gt=0)
    commercial_account_public_id: UUID
    surface_code: StableCode
    mcp_token_id: UUID | None = None
    required_allow_keys: tuple[StableCode, ...] = ()
    evaluated_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @model_validator(mode="after")
    def _unique_required_keys(self) -> "CommercialAuthorizationRequest":
        if len(set(self.required_allow_keys)) != len(self.required_allow_keys):
            raise ValueError("required commercial entitlement keys must be unique")
        return self


class CommercialAuthorizationContext(StrictCommercialModel):
    user_id: int = Field(gt=0)
    commercial_account_id: int = Field(gt=0)
    commercial_account_public_id: UUID
    account_kind: Literal["individual", "firm"]
    agreement_id: int = Field(gt=0)
    agreement_terms_id: int = Field(gt=0)
    agreement_terms_revision: int = Field(gt=0)
    offer_code: StableCode
    surface_code: StableCode
    entitlement_revision: int = Field(gt=0)
    effective_entitlements: tuple[CanonicalEntitlementFact, ...]
    evaluated_at: AwareDatetime


class CommercialAuthorizationDecision(StrictCommercialModel):
    allowed: bool
    denial_reason: CommercialDenialReason | None = None
    denied_entitlement_key: StableCode | None = None
    context: CommercialAuthorizationContext | None = None

    @model_validator(mode="after")
    def _shape(self) -> "CommercialAuthorizationDecision":
        if self.allowed != (self.context is not None):
            raise ValueError("allowed decisions require exactly one authorization context")
        if self.allowed == (self.denial_reason is not None):
            raise ValueError("denied decisions require exactly one denial reason")
        if self.denied_entitlement_key is not None and self.denial_reason not in {
            CommercialDenialReason.ENTITLEMENT_MISSING,
            CommercialDenialReason.ENTITLEMENT_DENIED,
        }:
            raise ValueError("denied entitlement key requires an entitlement denial")
        return self


class CommercialAuthorizationPublicError(StrictCommercialModel):
    code: StableCode
    message: str
    retryable: bool = False


def commercial_public_error(
    decision: CommercialAuthorizationDecision,
) -> CommercialAuthorizationPublicError:
    """Map internal diagnostics to the deliberately coarse public contract."""

    reason = decision.denial_reason
    if reason in {
        CommercialDenialReason.ACCOUNT_NOT_FOUND,
        CommercialDenialReason.MEMBERSHIP_INACTIVE,
        CommercialDenialReason.AGREEMENT_MISSING,
        CommercialDenialReason.TERMS_MISSING,
        CommercialDenialReason.ENTITLEMENT_REVISION_MISSING,
    }:
        return CommercialAuthorizationPublicError(
            code="commercial_agreement_required",
            message="A qualifying commercial agreement is required.",
        )
    if reason == CommercialDenialReason.AGREEMENT_STATE_DENIED:
        return CommercialAuthorizationPublicError(
            code="commercial_agreement_inactive",
            message="The commercial agreement is not currently active.",
        )
    if reason in {
        CommercialDenialReason.ENTITLEMENT_MISSING,
        CommercialDenialReason.ENTITLEMENT_DENIED,
    }:
        return CommercialAuthorizationPublicError(
            code="entitlement_required",
            message="The requested capability is not included.",
        )
    if reason in {
        CommercialDenialReason.TOKEN_INVALID,
        CommercialDenialReason.TOKEN_EXPIRED,
        CommercialDenialReason.TOKEN_REVOKED,
    }:
        return CommercialAuthorizationPublicError(
            code=reason.value,
            message="The access token is not valid for this request.",
        )
    return CommercialAuthorizationPublicError(
        code="billing_sync_pending",
        message="Commercial authorization is temporarily unavailable.",
        retryable=True,
    )


def _denied(
    reason: CommercialDenialReason,
    *,
    key: str | None = None,
) -> CommercialAuthorizationDecision:
    return CommercialAuthorizationDecision(
        allowed=False,
        denial_reason=reason,
        denied_entitlement_key=key,
    )


def resolve_commercial_authorization(
    connection: Any,
    *,
    flags: CommercialFlags,
    request: CommercialAuthorizationRequest,
) -> CommercialAuthorizationDecision:
    """Resolve current commercial authority without replacing user authentication."""

    if not flags.commercial_entitlement_projection_enabled:
        return _denied(CommercialDenialReason.COMMERCIAL_DISABLED)
    if getattr(connection, "autocommit", False):
        raise ValueError("commercial authorization requires autocommit disabled")
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT id, status, kind FROM commercial_accounts
             WHERE public_id = %s FOR SHARE
            """,
            (str(request.commercial_account_public_id),),
        )
        account = cursor.fetchone()
        if account is None or account[1] != "active":
            return _denied(CommercialDenialReason.ACCOUNT_NOT_FOUND)
        account_id = int(account[0])
        account_kind = account[2]
        cursor.execute(
            """
            SELECT status FROM commercial_account_members
             WHERE commercial_account_id = %s AND user_id = %s FOR SHARE
            """,
            (account_id, request.user_id),
        )
        member = cursor.fetchone()
        if member is None or member[0] != "active":
            return _denied(CommercialDenialReason.MEMBERSHIP_INACTIVE)

        cursor.execute(
            """
            SELECT id, state, service_start_at, service_end_at,
                   grace_end_at, current_period_end_at
              FROM commercial_agreements
             WHERE commercial_account_id = %s AND surface_code = %s
               AND (service_start_at IS NULL OR service_start_at <= %s)
               AND (service_end_at IS NULL OR service_end_at > %s)
             ORDER BY id
             FOR SHARE
            """,
            (
                account_id,
                request.surface_code,
                request.evaluated_at,
                request.evaluated_at,
            ),
        )
        agreement_rows = cursor.fetchall()
        primary = []
        canceled = []
        for row in agreement_rows:
            state = row[1]
            if state in {"trialing", "active", "past_due"}:
                primary.append(row)
            elif state == "grace" and row[4] is not None and row[4] > request.evaluated_at:
                primary.append(row)
            elif state == "canceled":
                access_until = row[5] or row[3]
                if access_until is not None and access_until > request.evaluated_at:
                    canceled.append(row)
        if not agreement_rows:
            return _denied(CommercialDenialReason.AGREEMENT_MISSING)
        eligible = primary or canceled
        if len(eligible) != 1:
            return _denied(CommercialDenialReason.AGREEMENT_STATE_DENIED)
        agreement_id = int(eligible[0][0])

        cursor.execute(
            """
            SELECT id, revision, offer_code
              FROM commercial_agreement_terms
             WHERE commercial_account_id = %s AND agreement_id = %s
               AND effective_from <= %s
               AND (effective_until IS NULL OR effective_until > %s)
               AND (to_jsonb(commercial_agreement_terms)->>'voided_at') IS NULL
             ORDER BY revision DESC
             FOR SHARE
            """,
            (
                account_id,
                agreement_id,
                request.evaluated_at,
                request.evaluated_at,
            ),
        )
        terms_rows = cursor.fetchall()
        if len(terms_rows) != 1:
            return _denied(CommercialDenialReason.TERMS_MISSING)
        terms_id, terms_revision, offer_code = terms_rows[0]

        cursor.execute(
            """
            SELECT revision, fact_count
              FROM commercial_entitlement_revisions
             WHERE commercial_account_id = %s
             FOR SHARE
            """,
            (account_id,),
        )
        revision_row = cursor.fetchone()
        if revision_row is None:
            return _denied(CommercialDenialReason.ENTITLEMENT_REVISION_MISSING)
        entitlement_revision, expected_fact_count = map(int, revision_row)

        cursor.execute(
            """
            SELECT subject_kind, subject_user_id, subject_mcp_token_id,
                   source_kind, entitlement_key, effect, value_json, priority,
                   effective_from, effective_until, reason_code
              FROM commercial_entitlements
             WHERE commercial_account_id = %s
               AND agreement_id = %s AND agreement_terms_id = %s
               AND surface_code = %s AND entitlement_revision = %s
               AND status = 'active' AND effective_from <= %s
               AND (effective_until IS NULL OR effective_until > %s)
               AND (subject_kind = 'account'
                    OR (subject_kind = 'user' AND subject_user_id = %s)
                    OR (subject_kind = 'mcp_token' AND subject_mcp_token_id = %s))
             ORDER BY id
            """,
            (
                account_id,
                agreement_id,
                terms_id,
                request.surface_code,
                entitlement_revision,
                request.evaluated_at,
                request.evaluated_at,
                request.user_id,
                str(request.mcp_token_id) if request.mcp_token_id else None,
            ),
        )
        facts = tuple(
            CanonicalEntitlementFact(
                subject_kind=row[0],
                subject_user_id=row[1],
                subject_mcp_token_id=row[2],
                source_kind=row[3],
                entitlement_key=row[4],
                effect=row[5],
                value=row[6],
                priority=row[7],
                effective_from=row[8],
                effective_until=row[9],
                reason_code=row[10],
            )
            for row in cursor.fetchall()
        )
        cursor.execute(
            """
            SELECT COUNT(*) FROM commercial_entitlements
             WHERE commercial_account_id = %s AND entitlement_revision = %s
               AND status = 'active'
            """,
            (account_id, entitlement_revision),
        )
        if int(cursor.fetchone()[0]) != expected_fact_count:
            return _denied(CommercialDenialReason.ENTITLEMENT_DATA_INVALID)
    finally:
        cursor.close()

    effective = resolve_effective_entitlements(
        facts,
        user_id=request.user_id,
        token_id=request.mcp_token_id,
    )
    by_key = {fact.entitlement_key: fact for fact in effective}
    for key in request.required_allow_keys:
        fact = by_key.get(key)
        if fact is None or fact.effect != "allow":
            reason = (
                CommercialDenialReason.ENTITLEMENT_DENIED
                if fact is not None and fact.effect == "deny"
                else CommercialDenialReason.ENTITLEMENT_MISSING
            )
            return _denied(reason, key=key)
    return CommercialAuthorizationDecision(
        allowed=True,
        context=CommercialAuthorizationContext(
            user_id=request.user_id,
            commercial_account_id=account_id,
            commercial_account_public_id=request.commercial_account_public_id,
            account_kind=account_kind,
            agreement_id=agreement_id,
            agreement_terms_id=int(terms_id),
            agreement_terms_revision=int(terms_revision),
            offer_code=offer_code,
            surface_code=request.surface_code,
            entitlement_revision=entitlement_revision,
            effective_entitlements=effective,
            evaluated_at=request.evaluated_at,
        ),
    )


def create_commercial_authorization_dependency(
    *,
    current_user_dependency: Callable[..., dict[str, Any]],
    connection_factory: Callable[[], ContextManager[Any]],
    flags: CommercialFlags,
    surface_code: StableCode,
    required_allow_keys: tuple[StableCode, ...] = (),
) -> Callable[..., CommercialAuthorizationContext]:
    """Compose cookie identity with explicit account-scoped commercial authority."""

    if not required_allow_keys:
        raise ValueError("commercial route dependencies require an entitlement key")

    def require_commercial_authority(
        request: Request,
        user: dict[str, Any] = Depends(current_user_dependency),
    ) -> CommercialAuthorizationContext:
        raw_account_id = request.headers.get("X-Commercial-Account-ID")
        try:
            account_public_id = UUID(raw_account_id or "")
            user_id = int(user["id"])
        except (KeyError, TypeError, ValueError) as exc:
            public_error = commercial_public_error(
                _denied(CommercialDenialReason.ACCOUNT_NOT_FOUND)
            )
            raise HTTPException(
                status_code=503 if public_error.retryable else 403,
                detail=public_error.model_dump(mode="json"),
            ) from exc
        with connection_factory() as connection:
            try:
                decision = resolve_commercial_authorization(
                    connection,
                    flags=flags,
                    request=CommercialAuthorizationRequest(
                        user_id=user_id,
                        commercial_account_public_id=account_public_id,
                        surface_code=surface_code,
                        required_allow_keys=required_allow_keys,
                    ),
                )
            finally:
                rollback = getattr(connection, "rollback", None)
                if callable(rollback) and not getattr(connection, "autocommit", False):
                    rollback()
        if not decision.allowed:
            public_error = commercial_public_error(decision)
            raise HTTPException(
                status_code=503 if public_error.retryable else 403,
                detail=public_error.model_dump(mode="json"),
            )
        assert decision.context is not None
        return decision.context

    return require_commercial_authority


__all__ = [
    "CommercialAuthorizationContext",
    "CommercialAuthorizationDecision",
    "CommercialAuthorizationRequest",
    "CommercialAuthorizationPublicError",
    "CommercialDenialReason",
    "commercial_public_error",
    "create_commercial_authorization_dependency",
    "resolve_commercial_authorization",
]
