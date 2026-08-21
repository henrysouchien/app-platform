"""Durable server-resolved identities for commercial execution claims."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Callable, Literal
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authorization import CommercialAuthorizationContext
from .flags import CommercialFlags, get_commercial_flags
from .models import Sha256Digest, StableCode, StrictCommercialModel
from .authority_invalidation import (
    CommercialAuthorityInvalidationCommand,
    publish_authority_invalidation,
)


_RECORD_COLUMNS = (
    "id",
    "environment",
    "audience",
    "surface_code",
    "commercial_account_id",
    "agreement_id",
    "agreement_terms_id",
    "user_id",
    "mcp_token_id",
    "offer_code",
    "effective_scopes",
    "entitlement_revision",
    "payer_policy_id",
    "budget_policy_id",
    "shadow_rate_policy_id",
    "manifest_policy_id",
    "schema_version",
    "claim_sha256",
    "issued_at",
    "expires_at",
    "authorized_work_start_deadline",
    "usage_accept_until",
    "status",
    "revoked_at",
    "revoke_reason",
    "creation_audit_event_id",
    "revocation_audit_event_id",
)
_MAX_AUTHORIZATION_AGE = timedelta(seconds=30)


class ExecutionContextCreateCommand(StrictCommercialModel):
    id: UUID
    environment: Literal["dev", "staging", "prod"]
    audience: StableCode
    authorization: CommercialAuthorizationContext
    mcp_token_id: UUID | None = None
    effective_scopes: tuple[StableCode, ...]
    shadow_rate_policy_id: Annotated[StrictInt, Field(gt=0)]
    manifest_policy_id: Annotated[StrictInt, Field(gt=0)]
    schema_version: Literal[1] = 1
    claim_sha256: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorized_work_start_deadline: AwareDatetime
    usage_accept_until: AwareDatetime

    @field_validator("effective_scopes")
    @classmethod
    def _scopes_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("execution context requires effective scopes")
        if tuple(sorted(set(value))) != value:
            raise ValueError("effective scopes must be sorted and unique")
        return value

    @model_validator(mode="after")
    def _valid_time_window(self) -> "ExecutionContextCreateCommand":
        allowed_scopes = {
            fact.entitlement_key
            for fact in self.authorization.effective_entitlements
            if fact.effect == "allow"
            and fact.entitlement_key.startswith("scope:")
            and fact.effective_from <= self.issued_at
            and (fact.effective_until is None or fact.effective_until > self.issued_at)
        }
        if not set(self.effective_scopes).issubset(allowed_scopes):
            raise ValueError(
                "execution scopes exceed resolved commercial authorization"
            )
        if self.issued_at < self.authorization.evaluated_at:
            raise ValueError("claim issuance cannot precede authorization evaluation")
        if self.issued_at - self.authorization.evaluated_at > _MAX_AUTHORIZATION_AGE:
            raise ValueError("commercial authorization result is stale")
        if self.expires_at <= self.issued_at:
            raise ValueError("claim expiry must follow issuance")
        if self.expires_at > self.issued_at + timedelta(minutes=5):
            raise ValueError("commercial claim lifetime cannot exceed five minutes")
        if not (
            self.issued_at
            <= self.authorized_work_start_deadline
            <= self.expires_at
            <= self.usage_accept_until
        ):
            raise ValueError("execution context authorization windows are invalid")
        return self


class ExecutionContextRecord(StrictCommercialModel):
    id: UUID
    environment: Literal["dev", "staging", "prod"]
    audience: StableCode
    surface_code: StableCode
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    agreement_terms_id: Annotated[StrictInt, Field(gt=0)]
    user_id: Annotated[StrictInt, Field(gt=0)]
    mcp_token_id: UUID | None
    offer_code: StableCode
    effective_scopes: tuple[StableCode, ...]
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    payer_policy_id: Annotated[StrictInt, Field(gt=0)]
    budget_policy_id: Annotated[StrictInt, Field(gt=0)]
    shadow_rate_policy_id: Annotated[StrictInt, Field(gt=0)]
    manifest_policy_id: Annotated[StrictInt, Field(gt=0)]
    schema_version: Literal[1]
    claim_sha256: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorized_work_start_deadline: AwareDatetime
    usage_accept_until: AwareDatetime
    status: Literal["active", "revoked"]
    revoked_at: AwareDatetime | None
    revoke_reason: StableCode | None
    creation_audit_event_id: UUID
    revocation_audit_event_id: UUID | None
    replayed: StrictBool = False


class ExecutionContextRevokeCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    execution_context_id: UUID
    reason_code: StableCode
    revoked_at: AwareDatetime


class ExecutionContextService:
    def __init__(
        self,
        connection: Any,
        *,
        flags: CommercialFlags | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._flags = flags or get_commercial_flags()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def create(self, command: ExecutionContextCreateCommand) -> ExecutionContextRecord:
        self._assert_enabled(command.environment)
        self._lock(command.id)
        replay = self._load(command.id)
        if replay is not None:
            if not self._matches_command(replay, command):
                raise ValueError("execution context JTI has conflicting claim facts")
            return replay.model_copy(update={"replayed": True})
        if command.issued_at > self._clock():
            raise ValueError("execution context cannot be future-issued")
        authority = command.authorization
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT terms.commercial_account_id, terms.agreement_id,
                       agreement.surface_code, terms.offer_code,
                       terms.payer_policy_id, terms.budget_policy_id
                  FROM commercial_agreement_terms terms
                  JOIN commercial_agreements agreement ON agreement.id = terms.agreement_id
                 WHERE terms.id = %s
                 FOR SHARE OF terms, agreement
                """,
                (authority.agreement_terms_id,),
            )
            row = cursor.fetchone()
        if row is None:
            raise ValueError("execution context agreement terms do not exist")
        account_id, agreement_id, surface, offer, payer_policy, budget_policy = row
        if (
            int(account_id) != authority.commercial_account_id
            or int(agreement_id) != authority.agreement_id
            or surface != authority.surface_code
            or offer != authority.offer_code
        ):
            raise ValueError(
                "authorization result differs from durable agreement identity"
            )
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id,
                commercial_account_id=int(account_id),
                agreement_id=int(agreement_id),
                actor_type="service",
                actor_id="commercial-control",
                action="commercial.execution_context.issue",
                target_type="commercial_execution_context",
                target_id=str(command.id),
                reason_code="claim.issued",
                after={
                    "account_id": int(account_id),
                    "agreement_id": int(agreement_id),
                    "result_code": "applied",
                },
            ),
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO commercial_execution_contexts (
                    id, environment, audience, surface_code, commercial_account_id,
                    agreement_id, agreement_terms_id, user_id, mcp_token_id,
                    offer_code, effective_scopes, entitlement_revision,
                    payer_policy_id, budget_policy_id, shadow_rate_policy_id,
                    manifest_policy_id, schema_version, claim_sha256, issued_at,
                    expires_at, authorized_work_start_deadline, usage_accept_until,
                    creation_audit_event_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(command.id),
                    command.environment,
                    command.audience,
                    surface,
                    account_id,
                    agreement_id,
                    authority.agreement_terms_id,
                    authority.user_id,
                    str(command.mcp_token_id) if command.mcp_token_id else None,
                    offer,
                    list(command.effective_scopes),
                    authority.entitlement_revision,
                    payer_policy,
                    budget_policy,
                    command.shadow_rate_policy_id,
                    command.manifest_policy_id,
                    command.schema_version,
                    command.claim_sha256,
                    command.issued_at,
                    command.expires_at,
                    command.authorized_work_start_deadline,
                    command.usage_accept_until,
                    str(audit_id),
                ),
            )
        record = self._load(command.id)
        if record is None:
            raise RuntimeError("execution context insert did not persist")
        return record

    def revoke(self, command: ExecutionContextRevokeCommand) -> ExecutionContextRecord:
        self._assert_enabled(command.environment)
        if command.revoked_at > self._clock():
            raise ValueError("execution context revocation cannot be future-dated")
        self._lock(command.execution_context_id)
        existing = self._load(command.execution_context_id)
        if existing is None or existing.environment != command.environment:
            raise ValueError(
                "execution context does not exist in deployment environment"
            )
        if existing.status == "revoked":
            if (
                existing.revoked_at == command.revoked_at
                and existing.revoke_reason == command.reason_code
            ):
                return existing.model_copy(update={"replayed": True})
            raise ValueError("execution context already has different revocation facts")
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id,
                commercial_account_id=existing.commercial_account_id,
                agreement_id=existing.agreement_id,
                actor_type="service",
                actor_id="commercial-control",
                action="commercial.execution_context.revoke",
                target_type="commercial_execution_context",
                target_id=str(existing.id),
                reason_code=command.reason_code,
                after={
                    "account_id": existing.commercial_account_id,
                    "agreement_id": existing.agreement_id,
                    "result_code": "revoked",
                },
            ),
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE commercial_execution_contexts
                   SET status = 'revoked', revoked_at = %s, revoke_reason = %s,
                       revocation_audit_event_id = %s
                 WHERE id = %s AND status = 'active'
                """,
                (
                    command.revoked_at,
                    command.reason_code,
                    str(audit_id),
                    str(existing.id),
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("execution context revocation lost its locked row")
        publish_authority_invalidation(
            self._connection,
            CommercialAuthorityInvalidationCommand(
                environment=existing.environment,
                kind="context",
                commercial_account_id=existing.commercial_account_id,
                entitlement_revision=existing.entitlement_revision,
                context_id=existing.id,
                token_id=existing.mcp_token_id,
            ),
        )
        record = self._load(existing.id)
        if record is None:
            raise RuntimeError("execution context revocation did not persist")
        return record

    def _assert_enabled(self, environment: str) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("execution context changes require a transaction")
        if not self._flags.commercial_control_enabled:
            raise RuntimeError("commercial control is disabled")
        if environment != self._flags.environment:
            raise ValueError("execution context environment does not match deployment")

    def _lock(self, context_id: UUID) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (str(context_id),),
            )

    def _load(self, context_id: UUID) -> ExecutionContextRecord | None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, environment, audience, surface_code, commercial_account_id,
                       agreement_id, agreement_terms_id, user_id, mcp_token_id,
                       offer_code, effective_scopes, entitlement_revision,
                       payer_policy_id, budget_policy_id, shadow_rate_policy_id,
                       manifest_policy_id, schema_version, claim_sha256, issued_at,
                       expires_at, authorized_work_start_deadline, usage_accept_until,
                       status, revoked_at, revoke_reason, creation_audit_event_id,
                       revocation_audit_event_id
                  FROM commercial_execution_contexts WHERE id = %s
                """,
                (str(context_id),),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return ExecutionContextRecord.model_validate(
            dict(zip(_RECORD_COLUMNS, row, strict=True))
        )

    @staticmethod
    def _matches_command(
        record: ExecutionContextRecord, command: ExecutionContextCreateCommand
    ) -> bool:
        return (
            record.environment == command.environment
            and record.audience == command.audience
            and record.commercial_account_id
            == command.authorization.commercial_account_id
            and record.agreement_id == command.authorization.agreement_id
            and record.agreement_terms_id == command.authorization.agreement_terms_id
            and record.user_id == command.authorization.user_id
            and record.surface_code == command.authorization.surface_code
            and record.offer_code == command.authorization.offer_code
            and record.mcp_token_id == command.mcp_token_id
            and record.effective_scopes == command.effective_scopes
            and record.entitlement_revision
            == command.authorization.entitlement_revision
            and record.shadow_rate_policy_id == command.shadow_rate_policy_id
            and record.manifest_policy_id == command.manifest_policy_id
            and record.schema_version == command.schema_version
            and record.claim_sha256 == command.claim_sha256
            and record.issued_at == command.issued_at
            and record.expires_at == command.expires_at
            and record.authorized_work_start_deadline
            == command.authorized_work_start_deadline
            and record.usage_accept_until == command.usage_accept_until
        )
