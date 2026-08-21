"""Replay-safe rotation, revocation, and deterministic MCP token expiration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
import json
import secrets
from typing import Annotated, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority_invalidation import (
    CommercialAuthorityInvalidationCommand,
    publish_authority_invalidation,
)
from .entitlement_store import AccountProjectionRequest, persist_account_entitlements
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .mcp_token_codec import McpTokenPepperRing
from .mcp_tokens import (
    MCP_TOKEN_INVALIDATION_CHANNEL,
    McpTokenMetadata,
    McpTokenRequestError,
)
from .models import StableCode, StrictCommercialModel, canonical_sha256


MCP_TOKEN_EXPIRER_ACTOR_ID = "mcp-token-expirer"


class McpTokenLifecycleCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    surface_code: StableCode
    token_id: UUID
    expected_lifecycle_version: Annotated[StrictInt, Field(gt=0)]
    expected_entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    reason_code: StableCode

    def command_sha256(self) -> str:
        return canonical_sha256(
            self.model_dump(mode="python", exclude={"idempotency_key"})
        )


class McpTokenRotateCommand(McpTokenLifecycleCommand):
    overlap_seconds: Annotated[StrictInt, Field(ge=1, le=900)]


class McpTokenRevokeCommand(McpTokenLifecycleCommand):
    pass


class McpTokenExpirationRequest(StrictCommercialModel):
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)] | None = None
    limit: Annotated[StrictInt, Field(ge=1, le=100)] = 100


class McpTokenExpireCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    surface_code: StableCode
    token_id: UUID
    expected_lifecycle_version: Annotated[StrictInt, Field(gt=0)]
    expires_at: AwareDatetime
    reason_code: Literal["token.expired"] = "token.expired"

    def command_sha256(self) -> str:
        return canonical_sha256(
            self.model_dump(mode="python", exclude={"idempotency_key"})
        )


class McpTokenRotateResult(StrictCommercialModel):
    predecessor_token_id: UUID
    token_metadata: McpTokenMetadata
    token: str | None = Field(default=None, repr=False)
    secret_available: StrictBool
    successor_audit_event_id: UUID
    predecessor_audit_event_id: UUID
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    projection_changed: StrictBool
    replayed: StrictBool = False

    @model_validator(mode="after")
    def _secret_shape(self) -> "McpTokenRotateResult":
        if self.secret_available is not (self.token is not None):
            raise ValueError("MCP rotation secret availability is inconsistent")
        if self.replayed and self.secret_available:
            raise ValueError("replayed MCP rotation cannot return a secret")
        return self


class McpTokenRevokeResult(StrictCommercialModel):
    token_metadata: McpTokenMetadata
    audit_event_id: UUID
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    projection_changed: StrictBool
    replayed: StrictBool = False


class McpTokenPreparedRevoke(StrictCommercialModel):
    """A revoked token awaiting one combined entitlement projection."""

    command: McpTokenRevokeCommand
    command_identity: UUID
    audit_event_id: UUID
    actor_user_id: Annotated[StrictInt, Field(gt=0)]


class McpTokenPreparedExpirationItem(StrictCommercialModel):
    command: McpTokenExpireCommand
    command_identity: UUID
    audit_event_id: UUID


class McpTokenPreparedExpiration(StrictCommercialModel):
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    prepared_at: AwareDatetime
    items: tuple[McpTokenPreparedExpirationItem, ...]


class McpTokenExpireResult(StrictCommercialModel):
    token_metadata: McpTokenMetadata
    audit_event_id: UUID
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    projection_changed: StrictBool


class McpTokenLifecycleService:
    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        pepper_ring: McpTokenPepperRing | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._pepper_ring = pepper_ring
        self._random_bytes = random_bytes

    def rotate_as_customer(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: McpTokenRotateCommand,
    ) -> McpTokenRotateResult:
        self._require_positive_int(actor_user_id, label="actor user identity")
        return self._run_committed(
            lambda: self._rotate_customer(
                actor_user_id=actor_user_id,
                runtime_environment=runtime_environment,
                command=command,
            )
        )

    def revoke_as_customer(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: McpTokenRevokeCommand,
    ) -> McpTokenRevokeResult:
        self._require_positive_int(actor_user_id, label="actor user identity")
        return self._run_committed(
            lambda: self._revoke(
                actor_type="user",
                actor_id=str(actor_user_id),
                actor_user_id=actor_user_id,
                runtime_environment=runtime_environment,
                command=command,
                incident=False,
            )
        )

    def prepare_revoke_as_customer_for_replacement(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: McpTokenRevokeCommand,
    ) -> McpTokenPreparedRevoke:
        """Revoke now and let an atomic successor mint perform the projection."""

        self._require_positive_int(actor_user_id, label="actor user identity")
        self._require_enabled(runtime_environment)
        identity = self._command_identity(
            environment=runtime_environment,
            operation="revoke",
            actor_type="user",
            actor_id=str(actor_user_id),
            command=command,
        )
        self._lock_command(identity)
        authority, token = self._lock_customer_scope(
            actor_user_id=actor_user_id,
            command=command,
        )
        self._require_expected_versions(command, authority, token)
        if token["status"] == "revoked":
            raise CommercialError(CommercialErrorCode.TOKEN_REVOKED)
        if token["status"] != "active":
            raise CommercialError(CommercialErrorCode.TOKEN_EXPIRED)
        now = self._wall_now()
        audit_id = uuid5(identity, "revoke-audit")
        self._insert_lifecycle_audit(
            audit_event_id=audit_id,
            actor_type="user",
            actor_id=str(actor_user_id),
            action="commercial.mcp_token.revoke",
            token_id=command.token_id,
            command=command,
            user_id=int(token["user_id"]),
            state="revoked",
            result_code="revoked",
            command_sha256=command.command_sha256(),
        )
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                UPDATE mcp_tokens
                   SET status = 'revoked', revoked_at = %s,
                       revoked_reason_code = %s, revocation_audit_event_id = %s,
                       version = version + 1,
                       updated_at = GREATEST(
                           clock_timestamp(), updated_at + INTERVAL '1 microsecond'
                       )
                 WHERE id = %s
                """,
                (now, command.reason_code, str(audit_id), str(command.token_id)),
            )
        return McpTokenPreparedRevoke(
            command=command,
            command_identity=identity,
            audit_event_id=audit_id,
            actor_user_id=actor_user_id,
        )

    def finalize_revoke_replacement(
        self,
        prepared: McpTokenPreparedRevoke,
        *,
        entitlement_revision: int,
        projection_changed: bool,
        runtime_environment: Literal["dev", "staging", "prod"],
    ) -> None:
        """Bind a prepared revoke to the successor's combined projection result."""

        self._insert_command(
            identity=prepared.command_identity,
            environment=runtime_environment,
            operation="revoke",
            actor_type="user",
            actor_id=str(prepared.actor_user_id),
            command=prepared.command,
            result_token_id=prepared.command.token_id,
            result_audit_event_id=prepared.audit_event_id,
            entitlement_revision=entitlement_revision,
            projection_changed=projection_changed,
        )
        self._notify(
            prepared.command.commercial_account_id,
            prepared.command.token_id,
            entitlement_revision,
        )

    def revoke_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: McpTokenRevokeCommand,
    ) -> McpTokenRevokeResult:
        self._require_positive_int(operator_user_id, label="operator user identity")
        return self._run_committed(
            lambda: self._revoke(
                actor_type="admin",
                actor_id=str(operator_user_id),
                actor_user_id=operator_user_id,
                runtime_environment=runtime_environment,
                command=command,
                incident=True,
            )
        )

    def expire_due_for_account(
        self,
        *,
        runtime_environment: Literal["dev", "staging", "prod"],
        commercial_account_id: int,
        limit: int = 100,
    ) -> tuple[McpTokenExpireResult, ...]:
        request = McpTokenExpirationRequest(
            commercial_account_id=commercial_account_id,
            limit=limit,
        )
        return self._run_committed(
            lambda: self._expire_due(
                runtime_environment=runtime_environment,
                request=request,
            )
        )

    def prepare_expire_due_for_account(
        self,
        *,
        runtime_environment: Literal["dev", "staging", "prod"],
        commercial_account_id: int,
        agreement_id: int | None = None,
        limit: int = 100,
    ) -> McpTokenPreparedExpiration:
        """Expire due token rows inside a caller-owned transaction."""

        if getattr(self._connection, "autocommit", False):
            raise ValueError("prepared token expiration requires a transaction")
        request = McpTokenExpirationRequest(
            commercial_account_id=commercial_account_id,
            agreement_id=agreement_id,
            limit=limit,
        )
        return self._prepare_expire_due(
            runtime_environment=runtime_environment,
            request=request,
        )

    def finalize_prepared_expiration(
        self,
        prepared: McpTokenPreparedExpiration,
        *,
        runtime_environment: Literal["dev", "staging", "prod"],
        entitlement_revision: int,
        projection_changed: bool,
    ) -> tuple[McpTokenExpireResult, ...]:
        """Bind prepared expirations to one combined entitlement projection."""

        return self._finalize_prepared_expiration(
            prepared=prepared,
            runtime_environment=runtime_environment,
            entitlement_revision=entitlement_revision,
            projection_changed=projection_changed,
        )

    def lock_expiration_scope_for_transaction(
        self,
        *,
        commercial_account_id: int,
    ) -> None:
        """Acquire the canonical token-expiration advisory lock first."""

        self._require_positive_int(
            commercial_account_id,
            label="commercial account identity",
        )
        if getattr(self._connection, "autocommit", False):
            raise ValueError("token expiration scope requires a transaction")
        self._lock_expiration_account(commercial_account_id)

    def _rotate_customer(
        self,
        *,
        actor_user_id: int,
        runtime_environment: str,
        command: McpTokenRotateCommand,
    ) -> McpTokenRotateResult:
        self._require_enabled(runtime_environment)
        identity = self._command_identity(
            environment=runtime_environment,
            operation="rotate",
            actor_type="user",
            actor_id=str(actor_user_id),
            command=command,
        )
        self._lock_command(identity)
        authority, token = self._lock_customer_scope(
            actor_user_id=actor_user_id,
            command=command,
        )
        replay = self._load_rotate_replay(
            identity=identity,
            actor_type="user",
            actor_id=str(actor_user_id),
            command=command,
        )
        if replay is not None:
            return replay
        self._require_expected_versions(command, authority, token)
        now = self._wall_now()
        if token["user_id"] != actor_user_id:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        if token["status"] == "revoked":
            raise CommercialError(CommercialErrorCode.TOKEN_REVOKED)
        if token["status"] != "active" or token["expires_at"] <= now:
            raise CommercialError(CommercialErrorCode.TOKEN_EXPIRED)
        if token["rotation_successor_token_id"] is not None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_TOKEN_VERSION_CONFLICT)
        if not self._eligible_rotation_agreement(authority, command.surface_code, now):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_INACTIVE)
        successor_id = uuid5(identity, "successor-token")
        successor_audit_id = uuid5(identity, "successor-audit")
        predecessor_audit_id = uuid5(identity, "predecessor-audit")
        if self._pepper_ring is None:
            raise ValueError("MCP token rotation requires a pepper ring")
        material = self._pepper_ring.issue(random_bytes=self._random_bytes)
        digest = command.command_sha256()
        self._insert_lifecycle_audit(
            audit_event_id=successor_audit_id,
            actor_type="user",
            actor_id=str(actor_user_id),
            action="commercial.mcp_token.rotate_successor",
            token_id=successor_id,
            command=command,
            user_id=actor_user_id,
            state="active",
            result_code="applied",
            command_sha256=digest,
        )
        self._insert_lifecycle_audit(
            audit_event_id=predecessor_audit_id,
            actor_type="user",
            actor_id=str(actor_user_id),
            action="commercial.mcp_token.rotate_predecessor",
            token_id=command.token_id,
            command=command,
            user_id=actor_user_id,
            state="active",
            result_code="applied",
            command_sha256=digest,
        )
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                INSERT INTO mcp_tokens (
                    id, commercial_account_id, user_id, agreement_id, surface_code,
                    token_prefix, secret_digest, token_salt, digest_version,
                    pepper_version, label, requested_scopes, expires_at,
                    rotated_from_token_id, creation_audit_event_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(successor_id),
                    command.commercial_account_id,
                    actor_user_id,
                    command.agreement_id,
                    command.surface_code,
                    material.prefix,
                    material.digest,
                    material.salt,
                    material.digest_version,
                    material.pepper_version,
                    token["label"],
                    list(token["requested_scopes"]),
                    token["expires_at"],
                    str(command.token_id),
                    str(successor_audit_id),
                ),
            )
            rotation_at = self._wall_now()
            overlap_until = rotation_at + timedelta(seconds=command.overlap_seconds)
            if overlap_until >= token["expires_at"]:
                raise McpTokenRequestError(
                    "MCP token rotation overlap must end before original expiry"
                )
            cursor.execute(
                """
                UPDATE mcp_tokens
                   SET rotation_successor_token_id = %s,
                       rotation_overlap_until = %s, rotation_audit_event_id = %s,
                       expires_at = %s, version = version + 1,
                       updated_at = GREATEST(
                           clock_timestamp(), updated_at + INTERVAL '1 microsecond'
                       )
                 WHERE id = %s
                """,
                (
                    str(successor_id),
                    overlap_until,
                    str(predecessor_audit_id),
                    overlap_until,
                    str(command.token_id),
                ),
            )
        projection = self._project(command.commercial_account_id, rotation_at)
        self._insert_command(
            identity=identity,
            environment=runtime_environment,
            operation="rotate",
            actor_type="user",
            actor_id=str(actor_user_id),
            command=command,
            result_token_id=successor_id,
            result_audit_event_id=successor_audit_id,
            entitlement_revision=projection.revision,
            projection_changed=projection.changed,
        )
        self._notify(
            command.commercial_account_id, command.token_id, projection.revision
        )
        self._notify(command.commercial_account_id, successor_id, projection.revision)
        return McpTokenRotateResult(
            predecessor_token_id=command.token_id,
            token_metadata=self._load_metadata(successor_id),
            token=material.token,
            secret_available=True,
            successor_audit_event_id=successor_audit_id,
            predecessor_audit_event_id=predecessor_audit_id,
            entitlement_revision=projection.revision,
            projection_changed=projection.changed,
        )

    def _revoke(
        self,
        *,
        actor_type: Literal["user", "admin"],
        actor_id: str,
        actor_user_id: int,
        runtime_environment: str,
        command: McpTokenRevokeCommand,
        incident: bool,
    ) -> McpTokenRevokeResult:
        if incident:
            self._require_expiration_enabled(runtime_environment)
        else:
            self._require_enabled(runtime_environment)
        incident_grant = None
        if incident:
            incident_grant = self._lock_incident_grant(
                user_id=actor_user_id,
                environment=runtime_environment,
            )
        identity = self._command_identity(
            environment=runtime_environment,
            operation="revoke",
            actor_type=actor_type,
            actor_id=actor_id,
            command=command,
        )
        self._lock_command(identity)
        if incident:
            authority, token = self._lock_incident_scope(command)
        else:
            authority, token = self._lock_customer_scope(
                actor_user_id=actor_user_id,
                command=command,
            )
        now = self._wall_now()
        if incident:
            self._require_incident_grant_current(incident_grant, now)
        replay = self._load_revoke_replay(
            identity=identity,
            actor_type=actor_type,
            actor_id=actor_id,
            command=command,
        )
        if replay is not None:
            return replay
        self._require_expected_versions(command, authority, token)
        if token["status"] == "revoked":
            raise CommercialError(CommercialErrorCode.TOKEN_REVOKED)
        if token["status"] != "active":
            raise CommercialError(CommercialErrorCode.TOKEN_EXPIRED)
        audit_id = uuid5(identity, "revoke-audit")
        self._insert_lifecycle_audit(
            audit_event_id=audit_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action="commercial.mcp_token.revoke",
            token_id=command.token_id,
            command=command,
            user_id=int(token["user_id"]),
            state="revoked",
            result_code="revoked",
            command_sha256=command.command_sha256(),
        )
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                UPDATE mcp_tokens
                   SET status = 'revoked', revoked_at = %s,
                       revoked_reason_code = %s, revocation_audit_event_id = %s,
                       version = version + 1,
                       updated_at = GREATEST(
                           clock_timestamp(), updated_at + INTERVAL '1 microsecond'
                       )
                 WHERE id = %s
                """,
                (now, command.reason_code, str(audit_id), str(command.token_id)),
            )
        projection = self._project(command.commercial_account_id, now)
        self._insert_command(
            identity=identity,
            environment=runtime_environment,
            operation="revoke",
            actor_type=actor_type,
            actor_id=actor_id,
            command=command,
            result_token_id=command.token_id,
            result_audit_event_id=audit_id,
            entitlement_revision=projection.revision,
            projection_changed=projection.changed,
        )
        self._notify(
            command.commercial_account_id, command.token_id, projection.revision
        )
        return McpTokenRevokeResult(
            token_metadata=self._load_metadata(command.token_id),
            audit_event_id=audit_id,
            entitlement_revision=projection.revision,
            projection_changed=projection.changed,
        )

    def _expire_due(
        self,
        *,
        runtime_environment: str,
        request: McpTokenExpirationRequest,
    ) -> tuple[McpTokenExpireResult, ...]:
        self._require_enabled(runtime_environment)
        prepared = self._prepare_expire_due(
            runtime_environment=runtime_environment,
            request=request,
        )
        if not prepared.items:
            return ()
        projection = self._project(
            request.commercial_account_id,
            prepared.prepared_at,
        )
        return self._finalize_prepared_expiration(
            prepared=prepared,
            runtime_environment=runtime_environment,
            entitlement_revision=projection.revision,
            projection_changed=projection.changed,
        )

    def _prepare_expire_due(
        self,
        *,
        runtime_environment: str,
        request: McpTokenExpirationRequest,
    ) -> McpTokenPreparedExpiration:
        self._require_expiration_enabled(runtime_environment)
        self._lock_expiration_account(request.commercial_account_id)
        self._lock_account(request.commercial_account_id)
        self._lock_entitlement_revision(request.commercial_account_id)
        now = self._wall_now()
        due = self._lock_due_tokens(
            account_id=request.commercial_account_id,
            agreement_id=request.agreement_id,
            now=now,
            limit=request.limit,
        )
        if not due:
            return McpTokenPreparedExpiration(
                commercial_account_id=request.commercial_account_id,
                prepared_at=now,
                items=(),
            )

        pending: list[McpTokenPreparedExpirationItem] = []
        for token in due:
            command = self._expiration_command(
                environment=runtime_environment,
                account_id=request.commercial_account_id,
                token=token,
            )
            identity = self._expiration_identity(runtime_environment, command)
            audit_id = uuid5(identity, "expire-audit")
            self._insert_lifecycle_audit(
                audit_event_id=audit_id,
                actor_type="service",
                actor_id=MCP_TOKEN_EXPIRER_ACTOR_ID,
                action="commercial.mcp_token.expire",
                token_id=command.token_id,
                command=command,
                user_id=token["user_id"],
                state="expired",
                result_code="applied",
                command_sha256=command.command_sha256(),
            )
            with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
                cursor.execute(
                    """
                    UPDATE mcp_tokens
                       SET status = 'expired', expired_at = %s,
                           expiration_audit_event_id = %s, version = version + 1,
                           updated_at = GREATEST(
                               clock_timestamp(), updated_at + INTERVAL '1 microsecond'
                           )
                     WHERE id = %s AND commercial_account_id = %s
                       AND status = 'active' AND version = %s
                    """,
                    (
                        now,
                        str(audit_id),
                        str(command.token_id),
                        request.commercial_account_id,
                        command.expected_lifecycle_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_TOKEN_VERSION_CONFLICT
                    )
            pending.append(
                McpTokenPreparedExpirationItem(
                    command=command,
                    command_identity=identity,
                    audit_event_id=audit_id,
                )
            )
        return McpTokenPreparedExpiration(
            commercial_account_id=request.commercial_account_id,
            prepared_at=now,
            items=tuple(pending),
        )

    def _finalize_prepared_expiration(
        self,
        *,
        prepared: McpTokenPreparedExpiration,
        runtime_environment: str,
        entitlement_revision: int,
        projection_changed: bool,
    ) -> tuple[McpTokenExpireResult, ...]:
        results = []
        for item in prepared.items:
            command = item.command
            self._insert_command(
                identity=item.command_identity,
                environment=runtime_environment,
                operation="expire",
                actor_type="service",
                actor_id=MCP_TOKEN_EXPIRER_ACTOR_ID,
                command=command,
                result_token_id=command.token_id,
                result_audit_event_id=item.audit_event_id,
                entitlement_revision=entitlement_revision,
                projection_changed=projection_changed,
            )
            self._notify(
                prepared.commercial_account_id,
                command.token_id,
                entitlement_revision,
            )
            results.append(
                McpTokenExpireResult(
                    token_metadata=self._load_metadata(command.token_id),
                    audit_event_id=item.audit_event_id,
                    entitlement_revision=entitlement_revision,
                    projection_changed=projection_changed,
                )
            )
        return tuple(results)

    def _lock_customer_scope(self, *, actor_user_id: int, command):
        account_status = self._lock_account(command.commercial_account_id)
        member = self._lock_member(command.commercial_account_id, actor_user_id)
        authority = self._lock_agreement_revision(command, account_status)
        if account_status != "active":
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_INACTIVE)
        if (
            member is None
            or member[1] != "active"
            or member[0] not in {"owner", "admin"}
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        return authority, self._lock_token(command)

    def _lock_incident_scope(self, command):
        account_status = self._lock_account(command.commercial_account_id)
        authority = self._lock_agreement_revision(command, account_status)
        return authority, self._lock_token(command)

    def _lock_expiration_account(self, account_id: int) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"commercial-mcp-token-expiration:{account_id}",),
            )

    def _lock_entitlement_revision(self, account_id: int) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT revision FROM commercial_entitlement_revisions
                 WHERE commercial_account_id = %s FOR UPDATE
                """,
                (account_id,),
            )
            cursor.fetchone()

    def _lock_due_tokens(
        self,
        *,
        account_id: int,
        agreement_id: int | None,
        now: datetime,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT id, user_id, agreement_id, surface_code, version, expires_at
                 FROM mcp_tokens
                 WHERE commercial_account_id = %s AND status = 'active'
                   AND (%s IS NULL OR agreement_id = %s)
                   AND expires_at <= %s
                 ORDER BY expires_at, id
                 LIMIT %s
                 FOR UPDATE
                """,
                (account_id, agreement_id, agreement_id, now, limit),
            )
            rows = cursor.fetchall()
        return tuple(
            {
                "id": UUID(str(row[0])),
                "user_id": int(row[1]),
                "agreement_id": int(row[2]),
                "surface_code": str(row[3]),
                "version": int(row[4]),
                "expires_at": row[5],
            }
            for row in rows
        )

    @staticmethod
    def _expiration_command(
        *, environment: str, account_id: int, token: dict[str, object]
    ) -> McpTokenExpireCommand:
        expires_at = token["expires_at"].astimezone(timezone.utc)
        identity = McpTokenLifecycleService._expiration_identity_values(
            environment=environment,
            token_id=token["id"],
            lifecycle_version=token["version"],
            expires_at=expires_at,
        )
        return McpTokenExpireCommand(
            idempotency_key=f"expire-{identity}",
            commercial_account_id=account_id,
            agreement_id=token["agreement_id"],
            surface_code=token["surface_code"],
            token_id=token["id"],
            expected_lifecycle_version=token["version"],
            expires_at=expires_at,
        )

    @staticmethod
    def _expiration_identity(environment: str, command: McpTokenExpireCommand) -> UUID:
        return McpTokenLifecycleService._expiration_identity_values(
            environment=environment,
            token_id=command.token_id,
            lifecycle_version=command.expected_lifecycle_version,
            expires_at=command.expires_at,
        )

    @staticmethod
    def _expiration_identity_values(
        *,
        environment: str,
        token_id: UUID,
        lifecycle_version: int,
        expires_at: datetime,
    ) -> UUID:
        canonical_expiry = expires_at.astimezone(timezone.utc)
        return uuid5(
            NAMESPACE_URL,
            "commercial-mcp-token-expiration:"
            f"{environment}:{token_id}:{lifecycle_version}:"
            f"{canonical_expiry.isoformat(timespec='microseconds')}",
        )

    def _lock_incident_grant(
        self, *, user_id: int, environment: str
    ) -> tuple[datetime, datetime | None]:
        observed_at = self._wall_now()
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT granted_at, expires_at
                  FROM commercial_operator_role_grants
                 WHERE user_id = %s AND environment = %s
                   AND role = 'entitlement_operator' AND state = 'active'
                   AND granted_at <= %s
                   AND (expires_at IS NULL OR expires_at > %s)
                 FOR SHARE
                """,
                (user_id, environment, observed_at, observed_at),
            )
            row = cursor.fetchone()
        if row is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        return row[0], row[1]

    @staticmethod
    def _require_incident_grant_current(
        grant: tuple[datetime, datetime | None] | None, now: datetime
    ) -> None:
        if (
            grant is None
            or grant[0] > now
            or (grant[1] is not None and grant[1] <= now)
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _lock_account(self, account_id: int) -> str:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT status FROM commercial_accounts WHERE id = %s FOR UPDATE",
                (account_id,),
            )
            account = cursor.fetchone()
        if account is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
        return str(account[0])

    def _lock_agreement_revision(
        self, command, account_status: str
    ) -> dict[str, object]:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT surface_code, state, service_start_at, service_end_at
                  FROM commercial_agreements
                 WHERE id = %s AND commercial_account_id = %s FOR UPDATE
                """,
                (command.agreement_id, command.commercial_account_id),
            )
            agreement = cursor.fetchone()
            cursor.execute(
                """
                SELECT revision FROM commercial_entitlement_revisions
                 WHERE commercial_account_id = %s FOR UPDATE
                """,
                (command.commercial_account_id,),
            )
            revision = cursor.fetchone()
        if agreement is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED)
        return {
            "account_status": account_status,
            "surface_code": str(agreement[0]),
            "agreement_state": str(agreement[1]),
            "service_start_at": agreement[2],
            "service_end_at": agreement[3],
            "entitlement_revision": int(revision[0]) if revision else None,
        }

    def _lock_member(self, account_id: int, user_id: int):
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT role, status FROM commercial_account_members
                 WHERE commercial_account_id = %s AND user_id = %s FOR SHARE
                """,
                (account_id, user_id),
            )
            return cursor.fetchone()

    def _lock_token(self, command) -> dict[str, object]:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT user_id, status, version, label, requested_scopes,
                       expires_at, rotation_successor_token_id
                  FROM mcp_tokens
                 WHERE id = %s AND commercial_account_id = %s
                   AND agreement_id = %s AND surface_code = %s
                 FOR UPDATE
                """,
                (
                    str(command.token_id),
                    command.commercial_account_id,
                    command.agreement_id,
                    command.surface_code,
                ),
            )
            row = cursor.fetchone()
        if row is None:
            raise CommercialError(CommercialErrorCode.TOKEN_INVALID)
        return {
            "user_id": int(row[0]),
            "status": str(row[1]),
            "version": int(row[2]),
            "label": str(row[3]),
            "requested_scopes": tuple(row[4]),
            "expires_at": row[5],
            "rotation_successor_token_id": row[6],
        }

    def _require_expected_versions(self, command, authority, token) -> None:
        if authority["surface_code"] != command.surface_code:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        if token["version"] != command.expected_lifecycle_version:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_TOKEN_VERSION_CONFLICT)
        if authority["entitlement_revision"] != command.expected_entitlement_revision:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_ENTITLEMENT_VERSION_CONFLICT
            )

    @staticmethod
    def _eligible_rotation_agreement(
        authority, surface_code: str, now: datetime
    ) -> bool:
        return bool(
            authority["surface_code"] == surface_code
            and authority["agreement_state"] in {"trialing", "active"}
            and authority["service_start_at"] is not None
            and authority["service_start_at"] <= now
            and (
                authority["service_end_at"] is None or authority["service_end_at"] > now
            )
        )

    def _insert_lifecycle_audit(
        self,
        *,
        audit_event_id: UUID,
        actor_type: Literal["user", "admin", "service"],
        actor_id: str,
        action: str,
        token_id: UUID,
        command: McpTokenLifecycleCommand | McpTokenExpireCommand,
        user_id: int,
        state: Literal["active", "revoked", "expired"],
        result_code: Literal["applied", "revoked"],
        command_sha256: str,
    ) -> None:
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=command.commercial_account_id,
                agreement_id=command.agreement_id,
                actor_type=actor_type,
                actor_id=actor_id,
                action=action,
                target_type="mcp_token",
                target_id=str(token_id),
                reason_code=command.reason_code,
                after={
                    "account_id": command.commercial_account_id,
                    "agreement_id": command.agreement_id,
                    "user_id": user_id,
                    "state": state,
                    "content_sha256": command_sha256,
                    "result_code": result_code,
                },
            ),
        )

    def _insert_command(
        self,
        *,
        identity: UUID,
        environment: str,
        operation: Literal["rotate", "revoke", "expire"],
        actor_type: Literal["user", "admin", "service"],
        actor_id: str,
        command: McpTokenLifecycleCommand | McpTokenExpireCommand,
        result_token_id: UUID,
        result_audit_event_id: UUID,
        entitlement_revision: int,
        projection_changed: bool,
    ) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                INSERT INTO commercial_mcp_token_commands (
                    command_id, environment, operation, idempotency_scope,
                    idempotency_key, command_sha256, actor_type, actor_id,
                    commercial_account_id, agreement_id, result_token_id,
                    result_audit_event_id, entitlement_revision, projection_changed
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(uuid5(identity, "command")),
                    environment,
                    operation,
                    self._idempotency_scope(actor_type, actor_id, command),
                    command.idempotency_key,
                    command.command_sha256(),
                    actor_type,
                    actor_id,
                    command.commercial_account_id,
                    command.agreement_id,
                    str(result_token_id),
                    str(result_audit_event_id),
                    entitlement_revision,
                    projection_changed,
                ),
            )

    def _load_rotate_replay(self, *, identity, actor_type, actor_id, command):
        row = self._load_command(uuid5(identity, "command"))
        if row is None:
            return None
        self._validate_replay(row, "rotate", actor_type, actor_id, command)
        metadata = self._load_metadata(UUID(str(row[8])))
        if metadata.rotated_from_token_id != command.token_id:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT rotation_audit_event_id FROM mcp_tokens WHERE id = %s",
                (str(command.token_id),),
            )
            predecessor_audit = cursor.fetchone()
        if predecessor_audit is None or predecessor_audit[0] is None:
            raise RuntimeError("rotated predecessor audit evidence is missing")
        return McpTokenRotateResult(
            predecessor_token_id=command.token_id,
            token_metadata=metadata,
            token=None,
            secret_available=False,
            successor_audit_event_id=UUID(str(row[9])),
            predecessor_audit_event_id=UUID(str(predecessor_audit[0])),
            entitlement_revision=int(row[10]),
            projection_changed=bool(row[11]),
            replayed=True,
        )

    def _load_revoke_replay(self, *, identity, actor_type, actor_id, command):
        row = self._load_command(uuid5(identity, "command"))
        if row is None:
            return None
        self._validate_replay(row, "revoke", actor_type, actor_id, command)
        return McpTokenRevokeResult(
            token_metadata=self._load_metadata(command.token_id),
            audit_event_id=UUID(str(row[9])),
            entitlement_revision=int(row[10]),
            projection_changed=bool(row[11]),
            replayed=True,
        )

    def _load_command(self, command_id: UUID):
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT operation, idempotency_scope, idempotency_key,
                       command_sha256, actor_type, actor_id,
                       commercial_account_id, agreement_id, result_token_id,
                       result_audit_event_id, entitlement_revision,
                       projection_changed
                  FROM commercial_mcp_token_commands WHERE command_id = %s
                """,
                (str(command_id),),
            )
            return cursor.fetchone()

    def _validate_replay(self, row, operation, actor_type, actor_id, command):
        expected = (
            operation,
            self._idempotency_scope(actor_type, actor_id, command),
            command.idempotency_key,
            command.command_sha256(),
            actor_type,
            actor_id,
            command.commercial_account_id,
            command.agreement_id,
        )
        if tuple(row[:8]) != expected:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)

    @staticmethod
    def _idempotency_scope(actor_type: str, actor_id: str, command) -> str:
        return f"token:{command.token_id}:actor:{actor_type}:{actor_id}"

    @classmethod
    def _command_identity(
        cls, *, environment, operation, actor_type, actor_id, command
    ) -> UUID:
        return uuid5(
            NAMESPACE_URL,
            "commercial-mcp-token-lifecycle:"
            f"{environment}:{operation}:"
            f"{cls._idempotency_scope(actor_type, actor_id, command)}:"
            f"{command.idempotency_key}",
        )

    def _project(self, account_id: int, now: datetime):
        return persist_account_entitlements(
            self._connection,
            flags=self._flags,
            request=AccountProjectionRequest(
                commercial_account_id=account_id,
                projected_at=now,
            ),
        )

    def _notify(self, account_id: int, token_id: UUID, revision: int) -> None:
        payload = json.dumps(
            {
                "commercial_account_id": account_id,
                "token_id": str(token_id),
                "entitlement_revision": revision,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT pg_notify(%s, %s)", (MCP_TOKEN_INVALIDATION_CHANNEL, payload)
            )
        publish_authority_invalidation(
            self._connection,
            CommercialAuthorityInvalidationCommand(
                environment=self._flags.environment,
                kind="token",
                commercial_account_id=account_id,
                entitlement_revision=revision,
                token_id=token_id,
            ),
        )

    @staticmethod
    def _metadata_columns() -> str:
        return """
            id, commercial_account_id, user_id, agreement_id, surface_code,
            token_prefix, label, requested_scopes, status, version, created_at,
            expires_at, rotated_from_token_id, rotation_successor_token_id,
            rotation_overlap_until, revoked_at, revoked_reason_code, expired_at,
            last_used_at
        """

    def _load_metadata(self, token_id: UUID) -> McpTokenMetadata:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                f"SELECT {self._metadata_columns()} FROM mcp_tokens WHERE id = %s",
                (str(token_id),),
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError("durable MCP token result is missing")
        values = tuple(row)
        return McpTokenMetadata(
            id=UUID(str(values[0])),
            commercial_account_id=int(values[1]),
            user_id=int(values[2]),
            agreement_id=int(values[3]),
            surface_code=values[4],
            token_prefix=values[5],
            label=values[6],
            requested_scopes=tuple(values[7]),
            status=values[8],
            version=int(values[9]),
            created_at=values[10],
            expires_at=values[11],
            rotated_from_token_id=(UUID(str(values[12])) if values[12] else None),
            rotation_successor_token_id=(UUID(str(values[13])) if values[13] else None),
            rotation_overlap_until=values[14],
            revoked_at=values[15],
            revoked_reason_code=values[16],
            expired_at=values[17],
            last_used_at=values[18],
        )

    def _require_enabled(self, environment: str) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_entitlement_projection_enabled
            and self._flags.commercial_usage_ingest_enabled
            and self._flags.commercial_budget_enforcement_enabled
            and self._flags.mcp_external_auth_enabled
        ):
            raise ValueError("external MCP token lifecycle is disabled")
        if environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        if row is None or row[0] != environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)

    def _require_expiration_enabled(self, environment: str) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_entitlement_projection_enabled
        ):
            raise ValueError("MCP token expiration is disabled")
        if environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        if row is None or row[0] != environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)

    def _lock_command(self, identity: UUID) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"commercial-mcp-token-lifecycle:{identity}",),
            )

    def _wall_now(self) -> datetime:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute("SELECT clock_timestamp()")
            value = cursor.fetchone()[0]
        return value

    def _run_committed(self, operation):
        self._require_clean_transaction()
        try:
            result = operation()
            self._connection.commit()  # type: ignore[attr-defined]
        except BaseException:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        return result

    def _require_clean_transaction(self) -> None:
        if getattr(self._connection, "autocommit", False):
            raise ValueError("MCP token lifecycle requires autocommit disabled")
        status = getattr(self._connection, "get_transaction_status", None)
        if status is not None and status() != 0:
            raise ValueError(
                "MCP token lifecycle requires a clean transaction boundary"
            )

    @staticmethod
    def _require_positive_int(value: object, *, label: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{label} must be a positive integer")


__all__ = [
    "MCP_TOKEN_EXPIRER_ACTOR_ID",
    "McpTokenExpirationRequest",
    "McpTokenExpireCommand",
    "McpTokenExpireResult",
    "McpTokenLifecycleCommand",
    "McpTokenLifecycleService",
    "McpTokenPreparedExpiration",
    "McpTokenPreparedExpirationItem",
    "McpTokenRevokeCommand",
    "McpTokenRevokeResult",
    "McpTokenRotateCommand",
    "McpTokenRotateResult",
]
