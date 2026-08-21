"""Default-off customer portal read model for MCP token eligibility and scope preview."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from collections.abc import Mapping
from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, StrictInt
from .catalog import CatalogBody
from .entitlement_store import (
    McpTokenEntitlementPreviewRequest,
    preview_mcp_token_entitlements,
)
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .mcp_tokens import McpTokenLifetimePolicy
from .models import StableCode, StrictCommercialModel
from .postgres_tuple_connection import PostgresTupleCursorConnection


class McpTokenPortalDisabledError(RuntimeError):
    """The portal is intentionally unavailable at the current rollout gate."""


class McpTokenPortalRuntimeError(RuntimeError):
    """The portal could not establish a safe runtime boundary."""


class McpTokenPortalAgreement(StrictCommercialModel):
    commercial_account_public_id: UUID
    commercial_account_display_name: str = Field(min_length=1, max_length=200)
    agreement_public_id: UUID
    surface_code: StableCode
    agreement_state: Literal["trialing", "active"]
    channel: Literal["self_serve", "managed", "pilot"]
    entitlement_revision: StrictInt = Field(gt=0)
    maximum_requestable_scopes: tuple[StableCode, ...]
    minimum_expires_at: AwareDatetime
    maximum_expires_at: AwareDatetime


@dataclass(frozen=True, slots=True)
class _AgreementCandidate:
    commercial_account_id: int
    commercial_account_public_id: UUID
    commercial_account_display_name: str
    agreement_id: int
    agreement_public_id: UUID
    surface_code: str
    agreement_state: str
    channel: str
    service_end_at: datetime | None
    entitlement_revision: int
    catalog: CatalogBody


def _value(row: object, index: int, name: str) -> Any:
    if isinstance(row, Mapping):
        return row[name]
    return row[index]  # type: ignore[index]


def _json_object(value: object) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError("commercial catalog body must be an object")
    return value


class PostgresMcpTokenPortalService:
    """List only token-eligible agreements administered by the authenticated user."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        lifetime_policy: McpTokenLifetimePolicy,
    ) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._lifetime_policy = lifetime_policy

    def list_eligible_agreements(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        limit: int = 100,
    ) -> tuple[McpTokenPortalAgreement, ...]:
        self._require_clean_transaction()
        try:
            if (
                isinstance(actor_user_id, bool)
                or not isinstance(actor_user_id, int)
                or actor_user_id <= 0
            ):
                raise ValueError("actor user identity must be a positive integer")
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or not 1 <= limit <= 100
            ):
                raise ValueError(
                    "MCP token portal agreement limit must be between 1 and 100"
                )
            self._require_enabled(runtime_environment)
            now = self._now()
            results: list[McpTokenPortalAgreement] = []
            after_account_public_id: UUID | None = None
            after_agreement_public_id: UUID | None = None
            while len(results) < limit:
                page_size = min(100, limit - len(results))
                candidates = self._load_candidates(
                    actor_user_id,
                    now,
                    page_size,
                    after_account_public_id=after_account_public_id,
                    after_agreement_public_id=after_agreement_public_id,
                )
                if not candidates:
                    break
                for candidate in candidates:
                    preview = self._preview_candidate(candidate, actor_user_id, now)
                    if preview is not None:
                        results.append(preview)
                        if len(results) == limit:
                            break
                last_candidate = candidates[-1]
                after_account_public_id = last_candidate.commercial_account_public_id
                after_agreement_public_id = last_candidate.agreement_public_id
                if len(candidates) < page_size:
                    break
            return tuple(results)
        finally:
            self._connection.rollback()  # type: ignore[attr-defined]

    def preview_agreement(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        commercial_account_public_id: UUID,
        agreement_public_id: UUID,
    ) -> McpTokenPortalAgreement:
        self._require_clean_transaction()
        try:
            if (
                isinstance(actor_user_id, bool)
                or not isinstance(actor_user_id, int)
                or actor_user_id <= 0
            ):
                raise ValueError("actor user identity must be a positive integer")
            self._require_enabled(runtime_environment)
            now = self._now()
            matches = tuple(
                preview
                for candidate in self._load_candidates(
                    actor_user_id,
                    now,
                    limit=1,
                    commercial_account_public_id=commercial_account_public_id,
                    agreement_public_id=agreement_public_id,
                )
                if (preview := self._preview_candidate(candidate, actor_user_id, now))
                is not None
            )
            if len(matches) != 1:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED
                )
            return matches[0]
        finally:
            self._connection.rollback()  # type: ignore[attr-defined]

    def _require_enabled(self, runtime_environment: str) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_entitlement_projection_enabled
            and self._flags.commercial_usage_ingest_enabled
            and self._flags.commercial_budget_enforcement_enabled
            and self._flags.mcp_external_auth_enabled
        ):
            raise McpTokenPortalDisabledError("external MCP token portal is disabled")
        if runtime_environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        if row is None or _value(row, 0, "environment") != runtime_environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)

    def _load_candidates(
        self,
        actor_user_id: int,
        now: datetime,
        limit: int,
        *,
        commercial_account_public_id: UUID | None = None,
        agreement_public_id: UUID | None = None,
        after_account_public_id: UUID | None = None,
        after_agreement_public_id: UUID | None = None,
    ) -> tuple[_AgreementCandidate, ...]:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT account.id AS commercial_account_id,
                       account.public_id AS commercial_account_public_id,
                       account.display_name AS commercial_account_display_name,
                       agreement.id AS agreement_id,
                       agreement.public_id AS agreement_public_id,
                       agreement.surface_code, agreement.state AS agreement_state,
                       agreement.channel, agreement.service_end_at,
                       revision.revision AS entitlement_revision,
                       catalog.body_json AS catalog_body
                  FROM commercial_account_members member
                  JOIN commercial_accounts account
                    ON account.id = member.commercial_account_id
                  JOIN commercial_agreements agreement
                    ON agreement.commercial_account_id = account.id
                  JOIN commercial_entitlement_revisions revision
                    ON revision.commercial_account_id = account.id
                  JOIN commercial_agreement_terms terms
                    ON terms.agreement_id = agreement.id
                   AND terms.commercial_account_id = account.id
                   AND terms.effective_from <= %s
                   AND (terms.effective_until IS NULL OR terms.effective_until > %s)
                   AND (to_jsonb(terms)->>'voided_at') IS NULL
                  JOIN commercial_policy_versions catalog
                    ON catalog.id = terms.catalog_policy_id
                   AND catalog.policy_kind = 'catalog'
                 WHERE member.user_id = %s AND member.status = 'active'
                   AND member.role IN ('owner', 'admin')
                   AND account.status = 'active'
                   AND agreement.state IN ('trialing', 'active')
                   AND agreement.service_start_at IS NOT NULL
                   AND agreement.service_start_at <= %s
                   AND (agreement.service_end_at IS NULL OR agreement.service_end_at > %s)
                   AND (agreement.channel = 'self_serve'
                        OR agreement.service_end_at IS NOT NULL)
                   AND (%s::uuid IS NULL OR account.public_id = %s::uuid)
                   AND (%s::uuid IS NULL OR agreement.public_id = %s::uuid)
                   AND (
                        %s::uuid IS NULL
                        OR account.public_id > %s::uuid
                        OR (account.public_id = %s::uuid
                            AND agreement.public_id > %s::uuid)
                   )
                 ORDER BY account.public_id, agreement.public_id
                 LIMIT %s
                """,
                (
                    now,
                    now,
                    actor_user_id,
                    now,
                    now,
                    str(commercial_account_public_id)
                    if commercial_account_public_id is not None
                    else None,
                    str(commercial_account_public_id)
                    if commercial_account_public_id is not None
                    else None,
                    str(agreement_public_id)
                    if agreement_public_id is not None
                    else None,
                    str(agreement_public_id)
                    if agreement_public_id is not None
                    else None,
                    str(after_account_public_id)
                    if after_account_public_id is not None
                    else None,
                    str(after_account_public_id)
                    if after_account_public_id is not None
                    else None,
                    str(after_account_public_id)
                    if after_account_public_id is not None
                    else None,
                    str(after_agreement_public_id)
                    if after_agreement_public_id is not None
                    else None,
                    limit,
                ),
            )
            rows = cursor.fetchall()
        return tuple(
            _AgreementCandidate(
                commercial_account_id=int(_value(row, 0, "commercial_account_id")),
                commercial_account_public_id=UUID(
                    str(_value(row, 1, "commercial_account_public_id"))
                ),
                commercial_account_display_name=str(
                    _value(row, 2, "commercial_account_display_name")
                ),
                agreement_id=int(_value(row, 3, "agreement_id")),
                agreement_public_id=UUID(str(_value(row, 4, "agreement_public_id"))),
                surface_code=str(_value(row, 5, "surface_code")),
                agreement_state=str(_value(row, 6, "agreement_state")),
                channel=str(_value(row, 7, "channel")),
                service_end_at=_value(row, 8, "service_end_at"),
                entitlement_revision=int(_value(row, 9, "entitlement_revision")),
                catalog=CatalogBody.model_validate(
                    _json_object(_value(row, 10, "catalog_body"))
                ),
            )
            for row in rows
        )

    def _preview_candidate(
        self,
        candidate: _AgreementCandidate,
        actor_user_id: int,
        now: datetime,
    ) -> McpTokenPortalAgreement | None:
        candidate_token_id = uuid5(
            NAMESPACE_URL,
            "commercial-mcp-token-preview:"
            f"{self._flags.environment}:{actor_user_id}:"
            f"{candidate.commercial_account_id}:{candidate.agreement_id}:"
            f"{candidate.entitlement_revision}",
        )
        preview = preview_mcp_token_entitlements(
            PostgresTupleCursorConnection(self._connection),
            flags=self._flags,
            request=McpTokenEntitlementPreviewRequest(
                commercial_account_id=candidate.commercial_account_id,
                agreement_id=candidate.agreement_id,
                user_id=actor_user_id,
                candidate_token_id=candidate_token_id,
                projected_at=now,
            ),
        )
        current = self._load_candidates(
            actor_user_id,
            now,
            limit=1,
            commercial_account_public_id=candidate.commercial_account_public_id,
            agreement_public_id=candidate.agreement_public_id,
        )
        if len(current) != 1:
            return None
        candidate = current[0]
        current_scopes = {
            definition.key
            for definition in candidate.catalog.scope_registry
            if definition.availability == "current"
        }
        maximum_scopes = tuple(
            sorted(
                fact.entitlement_key
                for fact in preview.effective_facts
                if fact.entitlement_key in current_scopes
                and fact.entitlement_key.startswith("scope:")
                and fact.effect == "allow"
                and fact.value is True
            )
        )
        if not maximum_scopes:
            return None
        maximum_lifetime = (
            self._lifetime_policy.maximum_self_serve_lifetime_seconds
            if candidate.channel == "self_serve"
            else self._lifetime_policy.maximum_contract_lifetime_seconds
        )
        minimum_expires_at = now + timedelta(
            seconds=self._lifetime_policy.minimum_lifetime_seconds
        )
        maximum_expires_at = now + timedelta(seconds=maximum_lifetime)
        if candidate.service_end_at is not None:
            maximum_expires_at = min(maximum_expires_at, candidate.service_end_at)
        if maximum_expires_at < minimum_expires_at:
            return None
        return McpTokenPortalAgreement(
            commercial_account_public_id=candidate.commercial_account_public_id,
            commercial_account_display_name=candidate.commercial_account_display_name,
            agreement_public_id=candidate.agreement_public_id,
            surface_code=candidate.surface_code,
            agreement_state=candidate.agreement_state,  # type: ignore[arg-type]
            channel=candidate.channel,  # type: ignore[arg-type]
            entitlement_revision=candidate.entitlement_revision,
            maximum_requestable_scopes=maximum_scopes,
            minimum_expires_at=minimum_expires_at,
            maximum_expires_at=maximum_expires_at,
        )

    def _require_clean_transaction(self) -> None:
        if getattr(self._connection, "autocommit", False):
            raise McpTokenPortalRuntimeError(
                "MCP token portal requires autocommit disabled"
            )
        transaction_status = getattr(self._connection, "get_transaction_status", None)
        if transaction_status is not None and transaction_status() != 0:
            raise McpTokenPortalRuntimeError(
                "MCP token portal requires a clean transaction boundary"
            )

    def _now(self) -> datetime:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute("SELECT transaction_timestamp() AS now_at")
            row = cursor.fetchone()
        now = _value(row, 0, "now_at")
        if now.tzinfo is None or now.utcoffset() is None:
            raise McpTokenPortalRuntimeError(
                "database transaction time must be timezone-aware"
            )
        return now


__all__ = [
    "McpTokenPortalDisabledError",
    "McpTokenPortalAgreement",
    "McpTokenPortalRuntimeError",
    "PostgresMcpTokenPortalService",
]
