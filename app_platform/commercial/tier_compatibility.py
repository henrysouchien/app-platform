"""Single migration bridge between canonical commerce and legacy access classes."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
import json
import logging
from typing import Literal

from .models import StableCode, StrictCommercialModel


logger = logging.getLogger(__name__)
LegacyTier = Literal["public", "registered", "paid", "business"]
_TIER_ORDER: dict[str, int] = {
    "public": 0,
    "registered": 1,
    "paid": 2,
    "business": 3,
}


class TierCompatibilityMode(StrEnum):
    LEGACY = "legacy"
    SHADOW = "shadow"
    CANONICAL = "canonical"


class TierParityOutcome(StrEnum):
    MATCH = "match"
    CANONICAL_ALLOW_LEGACY_DENY = "canonical_allow_legacy_deny"
    CANONICAL_DENY_LEGACY_ALLOW = "canonical_deny_legacy_allow"
    CANONICAL_UNAVAILABLE = "canonical_unavailable"


class TierParityEvent(StrictCommercialModel):
    route_code: StableCode
    mode: TierCompatibilityMode
    outcome: TierParityOutcome
    canonical_allowed: bool | None
    legacy_allowed: bool
    effective_allowed: bool
    legacy_tier: LegacyTier
    projected_tier: LegacyTier | None


class TierCompatibilityDecision(StrictCommercialModel):
    allowed: bool
    mode: TierCompatibilityMode
    legacy_allowed: bool
    canonical_allowed: bool | None
    projected_tier: LegacyTier | None
    parity_outcome: TierParityOutcome


class CanonicalTierProjection(StrictCommercialModel):
    allowed: bool
    projected_tier: LegacyTier


def _normalize_tier(value: str | None) -> LegacyTier:
    normalized = str(value or "registered").strip().lower()
    if normalized not in _TIER_ORDER:
        return "registered"
    return normalized  # type: ignore[return-value]


def _projected_tier(
    projection: CanonicalTierProjection | None,
) -> LegacyTier | None:
    if projection is None:
        return None
    return projection.projected_tier


def resolve_canonical_tier_projection(
    connection: object,
    *,
    user_id: int,
    evaluated_at: datetime,
) -> CanonicalTierProjection:
    """Project a coarse legacy class from authoritative eligible agreements."""

    if getattr(connection, "autocommit", False):
        raise ValueError("canonical tier projection requires autocommit disabled")
    cursor = connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute(
            """
            SELECT commercial_account_id FROM commercial_account_members
             WHERE user_id = %s AND status = 'active'
             ORDER BY commercial_account_id
            """,
            (user_id,),
        )
        account_ids = [int(row[0]) for row in cursor.fetchall()]
        if not account_ids:
            return CanonicalTierProjection(allowed=False, projected_tier="registered")
        cursor.execute(
            """
            SELECT id FROM commercial_accounts
             WHERE id = ANY(%s) ORDER BY id FOR SHARE
            """,
            (account_ids,),
        )
        locked_account_ids = [int(row[0]) for row in cursor.fetchall()]
        cursor.execute(
            """
            SELECT account.kind, agreement.state, agreement.grace_end_at,
                   agreement.current_period_end_at, agreement.service_end_at
              FROM commercial_account_members AS member
              JOIN commercial_accounts AS account
                ON account.id = member.commercial_account_id
              JOIN commercial_agreements AS agreement
                ON agreement.commercial_account_id = account.id
              JOIN commercial_agreement_terms AS terms
                ON terms.agreement_id = agreement.id
               AND terms.commercial_account_id = account.id
              JOIN commercial_entitlement_revisions AS revision
                ON revision.commercial_account_id = account.id
              JOIN commercial_entitlements AS entitlement
                ON entitlement.commercial_account_id = account.id
               AND entitlement.entitlement_revision = revision.revision
               AND entitlement.agreement_id = agreement.id
               AND entitlement.agreement_terms_id = terms.id
               AND entitlement.surface_code = agreement.surface_code
             WHERE member.user_id = %s AND member.status = 'active'
               AND account.id = ANY(%s)
               AND account.status = 'active'
               AND (agreement.service_start_at IS NULL OR agreement.service_start_at <= %s)
               AND (agreement.service_end_at IS NULL OR agreement.service_end_at > %s)
               AND terms.effective_from <= %s
               AND (terms.effective_until IS NULL OR terms.effective_until > %s)
               AND (to_jsonb(terms)->>'voided_at') IS NULL
               AND entitlement.status = 'active'
               AND entitlement.effect IN ('allow', 'limit')
               AND entitlement.effective_from <= %s
               AND (entitlement.effective_until IS NULL OR entitlement.effective_until > %s)
               AND (entitlement.subject_kind = 'account'
                    OR (entitlement.subject_kind = 'user'
                        AND entitlement.subject_user_id = member.user_id))
             FOR SHARE OF member, agreement, terms, revision, entitlement
            """,
            (
                user_id,
                locked_account_ids,
                evaluated_at,
                evaluated_at,
                evaluated_at,
                evaluated_at,
                evaluated_at,
                evaluated_at,
            ),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
    eligible_kinds = []
    for kind, state, grace_end, period_end, service_end in rows:
        if state in {"trialing", "active", "past_due"}:
            eligible_kinds.append(kind)
        elif state == "grace" and grace_end is not None and grace_end > evaluated_at:
            eligible_kinds.append(kind)
        elif state == "canceled":
            boundary = period_end or service_end
            if boundary is not None and boundary > evaluated_at:
                eligible_kinds.append(kind)
    if not eligible_kinds:
        return CanonicalTierProjection(allowed=False, projected_tier="registered")
    return CanonicalTierProjection(
        allowed=True,
        projected_tier="business" if "firm" in eligible_kinds else "paid",
    )


def _outcome(
    canonical_allowed: bool | None, legacy_allowed: bool
) -> TierParityOutcome:
    if canonical_allowed is None:
        return TierParityOutcome.CANONICAL_UNAVAILABLE
    if canonical_allowed == legacy_allowed:
        return TierParityOutcome.MATCH
    if canonical_allowed:
        return TierParityOutcome.CANONICAL_ALLOW_LEGACY_DENY
    return TierParityOutcome.CANONICAL_DENY_LEGACY_ALLOW


def log_tier_parity(event: TierParityEvent) -> None:
    """Emit only stable decision facts; never log user/account identifiers."""

    logger.info(
        "commercial_tier_parity %s",
        json.dumps(event.model_dump(mode="json"), separators=(",", ":"), sort_keys=True),
    )


def evaluate_tier_compatibility(
    *,
    route_code: StableCode,
    mode: TierCompatibilityMode,
    legacy_tier: str | None,
    canonical_projection: CanonicalTierProjection | None,
    minimum_legacy_tier: Literal["paid", "business"] = "paid",
    parity_sink: Callable[[TierParityEvent], None] = log_tier_parity,
) -> TierCompatibilityDecision:
    """Evaluate canonical-first data while preserving the selected rollout behavior."""

    normalized_tier = _normalize_tier(legacy_tier)
    legacy_allowed = _TIER_ORDER[normalized_tier] >= _TIER_ORDER[minimum_legacy_tier]
    canonical_allowed = (
        canonical_projection.allowed if canonical_projection is not None else None
    )
    if mode == TierCompatibilityMode.CANONICAL:
        if canonical_allowed is None:
            raise ValueError("canonical compatibility mode requires a canonical decision")
        allowed = canonical_allowed
    else:
        allowed = legacy_allowed
    projected_tier = _projected_tier(canonical_projection)
    outcome = _outcome(canonical_allowed, legacy_allowed)
    event = TierParityEvent(
        route_code=route_code,
        mode=mode,
        outcome=outcome,
        canonical_allowed=canonical_allowed,
        legacy_allowed=legacy_allowed,
        effective_allowed=allowed,
        legacy_tier=normalized_tier,
        projected_tier=projected_tier,
    )
    parity_sink(event)
    return TierCompatibilityDecision(
        allowed=allowed,
        mode=mode,
        legacy_allowed=legacy_allowed,
        canonical_allowed=canonical_allowed,
        projected_tier=projected_tier,
        parity_outcome=outcome,
    )


__all__ = [
    "LegacyTier",
    "CanonicalTierProjection",
    "TierCompatibilityDecision",
    "TierCompatibilityMode",
    "TierParityEvent",
    "TierParityOutcome",
    "evaluate_tier_compatibility",
    "log_tier_parity",
    "resolve_canonical_tier_projection",
]
