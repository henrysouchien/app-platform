"""Explicit classification of legacy tiers and credentials during cutover."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import CommercialRole
from .authority_store import load_named_operator
from .models import StableCode, StrictCommercialModel


class LegacyUserClassification(StrEnum):
    TEST = "test"
    INTERNAL = "internal"
    GRANDFATHERED_CUSTOMER = "grandfathered_customer"
    ORPHAN = "orphan"


class LegacyCredentialKind(StrEnum):
    MCP_TOKEN = "mcp_token"


class LegacyTierInventoryEntry(StrictCommercialModel):
    user_id: Annotated[int, Field(gt=0)]
    observed_tier: Literal["paid", "business"]
    classification: LegacyUserClassification | None
    agreement_id: Annotated[int, Field(gt=0)] | None
    reason_code: StableCode | None

    @model_validator(mode="after")
    def _coherent_review(self) -> "LegacyTierInventoryEntry":
        if self.classification is None:
            if self.agreement_id is not None or self.reason_code is not None:
                raise ValueError("unreviewed legacy user cannot carry review evidence")
            return self
        if self.reason_code is None:
            raise ValueError("reviewed legacy user requires a reason code")
        linked = self.agreement_id is not None
        if linked != (
            self.classification is LegacyUserClassification.GRANDFATHERED_CUSTOMER
        ):
            raise ValueError("only grandfathered customers link an agreement")
        return self

    @property
    def requires_operator_resolution(self) -> bool:
        return self.classification is None or self.classification is LegacyUserClassification.ORPHAN

    @property
    def is_payment_evidence(self) -> bool:
        return (
            self.classification is LegacyUserClassification.GRANDFATHERED_CUSTOMER
            and self.agreement_id is not None
        )


def require_mcp_external_bearer(
    *, legacy_api_key_match: bool, mcp_token_match: bool
) -> LegacyCredentialKind:
    """Fail closed unless only the authoritative external-token store matched."""

    if legacy_api_key_match or not mcp_token_match:
        raise ValueError("credential is not an unambiguous MCP external token")
    return LegacyCredentialKind.MCP_TOKEN


class PostgresLegacyCutoverStore:
    """Transaction-scoped inventory and append-only operator classification store."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def inventory(self) -> tuple[LegacyTierInventoryEntry, ...]:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT u.id, lower(u.tier), review.classification,
                       review.agreement_id, review.reason_code
                  FROM users u
                  LEFT JOIN LATERAL (
                    SELECT classification, agreement_id, reason_code
                      FROM commercial_legacy_user_reviews r
                     WHERE r.user_id = u.id AND r.observed_tier = lower(u.tier)
                     ORDER BY r.revision DESC
                     LIMIT 1
                  ) review ON TRUE
                 WHERE lower(u.tier) IN ('paid', 'business')
                 ORDER BY u.id
                """
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        return tuple(
            LegacyTierInventoryEntry(
                user_id=int(row[0]),
                observed_tier=str(row[1]),
                classification=(
                    LegacyUserClassification(str(row[2])) if row[2] else None
                ),
                agreement_id=int(row[3]) if row[3] is not None else None,
                reason_code=str(row[4]) if row[4] else None,
            )
            for row in rows
        )

    def record_review(
        self,
        *,
        user_id: int,
        observed_tier: str,
        classification: LegacyUserClassification,
        reason_code: str,
        operator_user_id: int,
        agreement_id: int | None = None,
    ) -> LegacyTierInventoryEntry:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("legacy cutover review requires a transaction")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SELECT tier FROM users WHERE id = %s FOR UPDATE", (user_id,))
            row = cursor.fetchone()
            actual_tier = str(row[0]).lower() if row else None
            if actual_tier != observed_tier or observed_tier not in {"paid", "business"}:
                raise ValueError("legacy tier changed before review")
            cursor.execute(
                """
                INSERT INTO commercial_legacy_user_reviews (
                    user_id, revision, observed_tier, classification, reason_code,
                    operator_user_id, agreement_id, manual_command_id
                )
                SELECT %s, COALESCE(max(r.revision), 0) + 1, %s, %s, %s, %s, %s,
                       CASE WHEN %s = 'grandfathered_customer' THEN (
                           SELECT command_id
                             FROM commercial_manual_agreement_commands
                            WHERE agreement_id = %s AND command_kind = 'activate'
                            ORDER BY created_at DESC LIMIT 1
                       ) END
                  FROM commercial_legacy_user_reviews r
                 WHERE r.user_id = %s
                RETURNING classification, agreement_id, reason_code
                """,
                (
                    user_id,
                    observed_tier,
                    classification.value,
                    reason_code,
                    operator_user_id,
                    agreement_id,
                    classification.value,
                    agreement_id,
                    user_id,
                ),
            )
            inserted = cursor.fetchone()
        finally:
            cursor.close()
        return LegacyTierInventoryEntry(
            user_id=user_id,
            observed_tier=observed_tier,
            classification=LegacyUserClassification(str(inserted[0])),
            agreement_id=int(inserted[1]) if inserted[1] is not None else None,
            reason_code=str(inserted[2]),
        )


class LegacyCutoverService:
    """Named-operator boundary for durable legacy-user review decisions."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self._store = PostgresLegacyCutoverStore(connection)

    def inventory_as_operator(
        self, *, operator_user_id: int, environment: str
    ) -> tuple[LegacyTierInventoryEntry, ...]:
        self._require_operator(operator_user_id, environment, read_only=True)
        return self._store.inventory()

    def record_review_as_operator(
        self,
        *,
        operator_user_id: int,
        environment: str,
        user_id: int,
        observed_tier: str,
        classification: LegacyUserClassification,
        reason_code: str,
        agreement_id: int | None = None,
    ) -> LegacyTierInventoryEntry:
        self._require_operator(operator_user_id, environment, read_only=False)
        result = self._store.record_review(
            user_id=user_id,
            observed_tier=observed_tier,
            classification=classification,
            reason_code=reason_code,
            operator_user_id=operator_user_id,
            agreement_id=agreement_id,
        )
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=uuid4(),
                commercial_account_id=self._agreement_account_id(agreement_id),
                agreement_id=agreement_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.legacy_user.review",
                target_type="user",
                target_id=str(user_id),
                reason_code=reason_code,
                after={
                    "user_id": user_id,
                    **({"agreement_id": agreement_id} if agreement_id else {}),
                    "observed_tier": observed_tier,
                    "classification": classification.value,
                    "result_code": "applied",
                },
            ),
        )
        return result

    def _require_operator(
        self, operator_user_id: int, environment: str, *, read_only: bool
    ) -> None:
        if environment not in {"dev", "staging", "prod"}:
            raise ValueError("invalid commercial environment")
        operator = load_named_operator(
            self._connection, user_id=operator_user_id, environment=environment
        )
        allowed = {CommercialRole.COMMERCIAL_ADMIN}
        if read_only:
            allowed.add(CommercialRole.COMMERCIAL_VIEWER)
        if not operator.roles.intersection(allowed):
            raise PermissionError("commercial role required")

    def _agreement_account_id(self, agreement_id: int | None) -> int | None:
        if agreement_id is None:
            return None
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT commercial_account_id FROM commercial_agreements WHERE id = %s",
                (agreement_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise ValueError("commercial agreement does not exist")
        return int(row[0])


__all__ = [
    "LegacyCredentialKind",
    "LegacyCutoverService",
    "LegacyTierInventoryEntry",
    "LegacyUserClassification",
    "PostgresLegacyCutoverStore",
    "require_mcp_external_bearer",
]
