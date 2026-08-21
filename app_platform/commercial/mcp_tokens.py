"""Default-off, replay-safe MCP token issuance and metadata listing."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
import json
import secrets
from typing import Annotated, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority_invalidation import (
    CommercialAuthorityInvalidationCommand,
    publish_authority_invalidation,
)
from .entitlement_store import AccountProjectionRequest, persist_account_entitlements
from .entitlements import CanonicalEntitlementFact, resolve_effective_entitlements
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .mcp_token_codec import McpTokenPepperRing
from .models import StableCode, StrictCommercialModel, canonical_sha256


MCP_TOKEN_INVALIDATION_CHANNEL = "commercial_mcp_token_invalidation"
_MAX_SELF_SERVE_LIFETIME_SECONDS = 90 * 24 * 60 * 60


class McpTokenRequestError(ValueError):
    """A customer token request violates a bounded product constraint."""


class McpTokenLifetimePolicy(StrictCommercialModel):
    """Product-selected lifetimes inside the database's hard safety ceilings."""

    minimum_lifetime_seconds: Annotated[StrictInt, Field(ge=60)]
    maximum_self_serve_lifetime_seconds: Annotated[
        StrictInt, Field(ge=60, le=_MAX_SELF_SERVE_LIFETIME_SECONDS)
    ]
    maximum_contract_lifetime_seconds: Annotated[StrictInt, Field(ge=60)]

    @model_validator(mode="after")
    def _ordered(self) -> "McpTokenLifetimePolicy":
        if self.minimum_lifetime_seconds > min(
            self.maximum_self_serve_lifetime_seconds,
            self.maximum_contract_lifetime_seconds,
        ):
            raise ValueError("minimum MCP token lifetime exceeds a configured maximum")
        return self


class McpTokenMintCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    surface_code: StableCode
    expected_entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    label: Annotated[str, Field(min_length=1, max_length=120)]
    requested_scopes: tuple[StableCode, ...] = Field(min_length=1, max_length=64)
    expires_at: AwareDatetime
    reason_code: StableCode

    @field_validator("requested_scopes")
    @classmethod
    def _canonical_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("requested MCP token scopes must be sorted and unique")
        if any(not scope.startswith("scope:") for scope in value):
            raise ValueError("MCP tokens may request only scope entitlements")
        return value

    def command_sha256(self) -> str:
        return canonical_sha256(
            self.model_dump(mode="python", exclude={"idempotency_key"})
        )


class McpTokenMetadata(StrictCommercialModel):
    id: UUID
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    user_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    surface_code: StableCode
    token_prefix: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{22}$")]
    label: Annotated[str, Field(min_length=1, max_length=120)]
    requested_scopes: tuple[StableCode, ...]
    status: Literal["active", "revoked", "expired"]
    version: Annotated[StrictInt, Field(gt=0)]
    created_at: AwareDatetime
    expires_at: AwareDatetime
    rotated_from_token_id: UUID | None = None
    rotation_successor_token_id: UUID | None = None
    rotation_overlap_until: AwareDatetime | None = None
    revoked_at: AwareDatetime | None = None
    revoked_reason_code: StableCode | None = None
    expired_at: AwareDatetime | None = None
    last_used_at: AwareDatetime | None = None


class McpTokenMintResult(StrictCommercialModel):
    token_metadata: McpTokenMetadata
    token: str | None = Field(default=None, repr=False)
    secret_available: StrictBool
    audit_event_id: UUID
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    projection_changed: StrictBool
    replayed: StrictBool = False

    @model_validator(mode="after")
    def _secret_shape(self) -> "McpTokenMintResult":
        if self.secret_available is not (self.token is not None):
            raise ValueError("MCP token secret availability is inconsistent")
        if self.replayed and self.secret_available:
            raise ValueError("replayed MCP token commands cannot return a secret")
        return self


class McpTokenService:
    """Issue one-time bearer material and expose only safe token metadata."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        pepper_ring: McpTokenPepperRing,
        lifetime_policy: McpTokenLifetimePolicy,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._pepper_ring = pepper_ring
        self._lifetime_policy = lifetime_policy
        self._random_bytes = random_bytes

    def mint(
        self,
        *,
        actor_user_id: Annotated[int, Field(gt=0)],
        runtime_environment: Literal["dev", "staging", "prod"],
        command: McpTokenMintCommand,
    ) -> McpTokenMintResult:
        self._require_clean_transaction()
        try:
            result = self.prepare_mint_in_transaction(
                actor_user_id=actor_user_id,
                runtime_environment=runtime_environment,
                command=command,
            )
            self._connection.commit()  # type: ignore[attr-defined]
        except BaseException:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        return result

    def prepare_mint_in_transaction(
        self,
        *,
        actor_user_id: Annotated[int, Field(gt=0)],
        runtime_environment: Literal["dev", "staging", "prod"],
        command: McpTokenMintCommand,
    ) -> McpTokenMintResult:
        """Prepare a mint without commit for a larger caller-owned atomic workflow."""

        return self._prepare_mint(
            actor_user_id=actor_user_id,
            runtime_environment=runtime_environment,
            command=command,
        )

    def _prepare_mint(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: McpTokenMintCommand,
    ) -> McpTokenMintResult:
        self._require_positive_int(actor_user_id, label="actor user identity")
        now = self._now()
        self._require_enabled(runtime_environment)
        identity = self.command_identity(runtime_environment, actor_user_id, command)
        self._lock_command(identity)
        authority = self._load_authority(actor_user_id, command)
        replay = self._load_replay(
            identity=identity,
            actor_user_id=actor_user_id,
            command=command,
        )
        if replay is not None:
            return replay
        self._validate_new_command(command, authority, now)

        token_id = uuid5(identity, "token")
        audit_event_id = uuid5(identity, "audit")
        material = self._pepper_ring.issue(random_bytes=self._random_bytes)
        audit = CommercialAuditEvent(
            event_id=audit_event_id,
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
            actor_type="user",
            actor_id=str(actor_user_id),
            action="commercial.mcp_token.mint",
            target_type="mcp_token",
            target_id=str(token_id),
            reason_code=command.reason_code,
            after={
                "account_id": command.commercial_account_id,
                "agreement_id": command.agreement_id,
                "user_id": actor_user_id,
                "state": "active",
                "content_sha256": command.command_sha256(),
                "result_code": "applied",
            },
        )
        insert_commercial_audit_event(self._connection, audit)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                INSERT INTO mcp_tokens (
                    id, commercial_account_id, user_id, agreement_id, surface_code,
                    token_prefix, secret_digest, token_salt, digest_version,
                    pepper_version, label, requested_scopes, expires_at,
                    creation_audit_event_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(token_id),
                    command.commercial_account_id,
                    actor_user_id,
                    command.agreement_id,
                    command.surface_code,
                    material.prefix,
                    material.digest,
                    material.salt,
                    material.digest_version,
                    material.pepper_version,
                    command.label,
                    list(command.requested_scopes),
                    command.expires_at,
                    str(audit_event_id),
                ),
            )
        projection = persist_account_entitlements(
            self._connection,
            flags=self._flags,
            request=AccountProjectionRequest(
                commercial_account_id=command.commercial_account_id,
                projected_at=now,
            ),
        )
        self._require_effective_token_scopes(
            command,
            actor_user_id=actor_user_id,
            token_id=token_id,
            entitlement_revision=projection.revision,
            now=now,
        )
        self._insert_command(
            identity=identity,
            environment=runtime_environment,
            actor_user_id=actor_user_id,
            command=command,
            token_id=token_id,
            audit_event_id=audit_event_id,
            entitlement_revision=projection.revision,
            projection_changed=projection.changed,
        )
        self._notify(
            account_id=command.commercial_account_id,
            token_id=token_id,
            entitlement_revision=projection.revision,
        )
        metadata = self._load_metadata(token_id)
        return McpTokenMintResult(
            token_metadata=metadata,
            token=material.token,
            secret_available=True,
            audit_event_id=audit_event_id,
            entitlement_revision=projection.revision,
            projection_changed=projection.changed,
        )

    def list_tokens(
        self,
        *,
        actor_user_id: Annotated[int, Field(gt=0)],
        runtime_environment: Literal["dev", "staging", "prod"],
        commercial_account_id: Annotated[int, Field(gt=0)],
        limit: Annotated[int, Field(ge=1, le=200)] = 100,
    ) -> tuple[McpTokenMetadata, ...]:
        self._require_positive_int(actor_user_id, label="actor user identity")
        self._require_positive_int(
            commercial_account_id, label="commercial account identity"
        )
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 200
        ):
            raise ValueError("MCP token list limit must be between 1 and 200")
        self._require_enabled(runtime_environment)
        self._require_account_admin(actor_user_id, commercial_account_id, lock=False)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                f"""
                SELECT {self._metadata_columns()}
                  FROM mcp_tokens
                 WHERE commercial_account_id = %s
                 ORDER BY created_at DESC, id DESC
                 LIMIT %s
                """,
                (commercial_account_id, limit),
            )
            rows = cursor.fetchall()
        return tuple(self._metadata_from_row(row) for row in rows)

    @staticmethod
    def command_identity(
        environment: str, actor_user_id: int, command: McpTokenMintCommand
    ) -> UUID:
        scope = McpTokenService.idempotency_scope(command, actor_user_id)
        return uuid5(
            NAMESPACE_URL,
            "commercial-mcp-token:"
            f"{environment}:mint:{scope}:{command.idempotency_key}",
        )

    @staticmethod
    def idempotency_scope(command: McpTokenMintCommand, actor_user_id: int) -> str:
        return f"account:{command.commercial_account_id}:user:{actor_user_id}"

    def _require_enabled(self, environment: str) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_entitlement_projection_enabled
            and self._flags.commercial_usage_ingest_enabled
            and self._flags.commercial_budget_enforcement_enabled
            and self._flags.mcp_external_auth_enabled
        ):
            raise ValueError("external MCP token issuance is disabled")
        if environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        if row is None or row[0] != environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)

    def _load_authority(
        self, actor_user_id: int, command: McpTokenMintCommand
    ) -> dict[str, object]:
        self._require_account_admin(
            actor_user_id, command.commercial_account_id, lock=True
        )
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT surface_code, state, channel, service_start_at, service_end_at
                  FROM commercial_agreements
                 WHERE id = %s AND commercial_account_id = %s
                 FOR UPDATE
                """,
                (command.agreement_id, command.commercial_account_id),
            )
            agreement = cursor.fetchone()
            cursor.execute(
                """
                SELECT revision
                  FROM commercial_entitlement_revisions
                 WHERE commercial_account_id = %s
                 FOR UPDATE
                """,
                (command.commercial_account_id,),
            )
            revision = cursor.fetchone()
        if agreement is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED)
        return {
            "surface_code": agreement[0],
            "state": agreement[1],
            "channel": agreement[2],
            "service_start_at": agreement[3],
            "service_end_at": agreement[4],
            "entitlement_revision": int(revision[0]) if revision else None,
        }

    def _require_account_admin(
        self, actor_user_id: int, account_id: int, *, lock: bool
    ) -> None:
        account_lock = "FOR UPDATE" if lock else "FOR SHARE"
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                f"SELECT status FROM commercial_accounts WHERE id = %s {account_lock}",
                (account_id,),
            )
            account = cursor.fetchone()
            cursor.execute(
                """
                SELECT role, status
                  FROM commercial_account_members
                 WHERE commercial_account_id = %s AND user_id = %s
                 FOR SHARE
                """,
                (account_id, actor_user_id),
            )
            member = cursor.fetchone()
        if account is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
        if account[0] != "active":
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_INACTIVE)
        if (
            member is None
            or member[1] != "active"
            or member[0] not in {"owner", "admin"}
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)

    def _validate_new_command(
        self,
        command: McpTokenMintCommand,
        authority: dict[str, object],
        now: datetime,
    ) -> None:
        if authority["entitlement_revision"] != command.expected_entitlement_revision:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_ENTITLEMENT_VERSION_CONFLICT
            )
        if authority["surface_code"] != command.surface_code:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        if authority["state"] not in {"trialing", "active"}:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_INACTIVE)
        service_start_at = authority["service_start_at"]
        service_end_at = authority["service_end_at"]
        if service_start_at is None or service_start_at > now:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_INACTIVE)
        maximum = (
            self._lifetime_policy.maximum_self_serve_lifetime_seconds
            if authority["channel"] == "self_serve"
            else self._lifetime_policy.maximum_contract_lifetime_seconds
        )
        lifetime = command.expires_at - now
        if lifetime < timedelta(seconds=self._lifetime_policy.minimum_lifetime_seconds):
            raise McpTokenRequestError(
                "MCP token expiry is below the configured minimum"
            )
        if lifetime > timedelta(seconds=maximum):
            raise McpTokenRequestError(
                "MCP token expiry exceeds the configured maximum"
            )
        if service_end_at is not None and command.expires_at > service_end_at:
            raise McpTokenRequestError(
                "MCP token expiry exceeds the agreement service window"
            )
        if authority["channel"] != "self_serve" and service_end_at is None:
            raise ValueError("contract MCP tokens require a finite service window")

    def _require_effective_token_scopes(
        self,
        command: McpTokenMintCommand,
        *,
        actor_user_id: int,
        token_id: UUID,
        entitlement_revision: int,
        now: datetime,
    ) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT subject_kind, subject_user_id, subject_mcp_token_id,
                       source_kind, entitlement_key, effect, value_json, priority,
                       effective_from, effective_until, reason_code
                  FROM commercial_entitlements
                 WHERE commercial_account_id = %s
                   AND agreement_id = %s
                   AND surface_code = %s
                   AND entitlement_revision = %s
                   AND status = 'active'
                   AND effective_from <= %s
                   AND (effective_until IS NULL OR effective_until > %s)
                   AND (subject_kind = 'account'
                        OR (subject_kind = 'user' AND subject_user_id = %s)
                        OR (subject_kind = 'mcp_token'
                            AND subject_mcp_token_id = %s))
                   AND entitlement_key = ANY(%s)
                """,
                (
                    command.commercial_account_id,
                    command.agreement_id,
                    command.surface_code,
                    entitlement_revision,
                    now,
                    now,
                    actor_user_id,
                    str(token_id),
                    list(command.requested_scopes),
                ),
            )
            rows = cursor.fetchall()
        facts = tuple(
            CanonicalEntitlementFact(
                subject_kind=row[0],
                subject_user_id=int(row[1]) if row[1] is not None else None,
                subject_mcp_token_id=(
                    UUID(str(row[2])) if row[2] is not None else None
                ),
                source_kind=row[3],
                entitlement_key=row[4],
                effect=row[5],
                value=(json.loads(row[6]) if isinstance(row[6], str) else row[6]),
                priority=int(row[7]),
                effective_from=row[8],
                effective_until=row[9],
                reason_code=row[10],
            )
            for row in rows
        )
        effective = resolve_effective_entitlements(
            facts, user_id=actor_user_id, token_id=token_id
        )
        allowed = {
            fact.entitlement_key
            for fact in effective
            if fact.effect == "allow" and fact.value is True
        }
        if not set(command.requested_scopes).issubset(allowed):
            raise CommercialError(CommercialErrorCode.TOKEN_SCOPE_DENIED)

    def _load_replay(
        self,
        *,
        identity: UUID,
        actor_user_id: int,
        command: McpTokenMintCommand,
    ) -> McpTokenMintResult | None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT operation, idempotency_scope, idempotency_key,
                       command_sha256, actor_type, actor_id,
                       commercial_account_id, agreement_id, result_token_id,
                       result_audit_event_id, entitlement_revision,
                       projection_changed
                  FROM commercial_mcp_token_commands
                 WHERE command_id = %s
                """,
                (str(uuid5(identity, "command")),),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        expected = (
            "mint",
            self.idempotency_scope(command, actor_user_id),
            command.idempotency_key,
            command.command_sha256(),
            "user",
            str(actor_user_id),
            command.commercial_account_id,
            command.agreement_id,
        )
        if tuple(row[:8]) != expected:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return McpTokenMintResult(
            token_metadata=self._load_metadata(UUID(str(row[8]))),
            token=None,
            secret_available=False,
            audit_event_id=UUID(str(row[9])),
            entitlement_revision=int(row[10]),
            projection_changed=bool(row[11]),
            replayed=True,
        )

    def _insert_command(
        self,
        *,
        identity: UUID,
        environment: str,
        actor_user_id: int,
        command: McpTokenMintCommand,
        token_id: UUID,
        audit_event_id: UUID,
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
                    %s, %s, 'mint', %s, %s, %s, 'user', %s,
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(uuid5(identity, "command")),
                    environment,
                    self.idempotency_scope(command, actor_user_id),
                    command.idempotency_key,
                    command.command_sha256(),
                    str(actor_user_id),
                    command.commercial_account_id,
                    command.agreement_id,
                    str(token_id),
                    str(audit_event_id),
                    entitlement_revision,
                    projection_changed,
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
        return self._metadata_from_row(row)

    @staticmethod
    def _metadata_from_row(row: object) -> McpTokenMetadata:
        values = tuple(row)  # type: ignore[arg-type]
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

    def _notify(
        self, *, account_id: int, token_id: UUID, entitlement_revision: int
    ) -> None:
        payload = json.dumps(
            {
                "commercial_account_id": account_id,
                "token_id": str(token_id),
                "entitlement_revision": entitlement_revision,
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
                entitlement_revision=entitlement_revision,
                token_id=token_id,
            ),
        )

    def _lock_command(self, identity: UUID) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"commercial-mcp-token:{identity}",),
            )

    def _require_clean_transaction(self) -> None:
        if getattr(self._connection, "autocommit", False):
            raise ValueError("MCP token commands require autocommit disabled")
        transaction_status = getattr(self._connection, "get_transaction_status", None)
        if transaction_status is not None and transaction_status() != 0:
            raise ValueError("MCP token mint requires a clean transaction boundary")

    @staticmethod
    def _require_positive_int(value: object, *, label: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{label} must be a positive integer")

    def _now(self) -> datetime:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute("SELECT transaction_timestamp()")
            value = cursor.fetchone()[0]
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("database transaction time must be timezone-aware")
        return value


__all__ = [
    "MCP_TOKEN_INVALIDATION_CHANNEL",
    "McpTokenLifetimePolicy",
    "McpTokenMetadata",
    "McpTokenMintCommand",
    "McpTokenMintResult",
    "McpTokenRequestError",
    "McpTokenService",
]
