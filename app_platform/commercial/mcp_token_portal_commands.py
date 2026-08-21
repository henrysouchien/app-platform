"""Public-identity application service for customer MCP token commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from .agreement_lifecycle import IdempotencyKey
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .mcp_token_codec import McpTokenPepperRing
from .mcp_token_lifecycle import (
    McpTokenLifecycleService,
    McpTokenRevokeCommand,
    McpTokenRotateCommand,
)
from .mcp_token_portal import McpTokenPortalDisabledError, McpTokenPortalRuntimeError
from .mcp_tokens import (
    McpTokenLifetimePolicy,
    McpTokenMetadata,
    McpTokenMintCommand,
    McpTokenService,
)
from .models import StableCode, StrictCommercialModel
from .postgres_tuple_connection import PostgresTupleCursorConnection


DEFAULT_CUSTOMER_ROTATION_OVERLAP_SECONDS = 60


class McpTokenPortalMintRequest(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_public_id: UUID
    agreement_public_id: UUID
    expected_entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    label: Annotated[str, Field(min_length=1, max_length=120)]
    requested_scopes: tuple[StableCode, ...] = Field(min_length=1, max_length=64)
    expires_at: AwareDatetime

    @field_validator("requested_scopes")
    @classmethod
    def _canonical_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("requested MCP token scopes must be sorted and unique")
        if any(not scope.startswith("scope:") for scope in value):
            raise ValueError("requested MCP token scopes must use the scope namespace")
        return value


class McpTokenPortalLifecycleRequest(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_public_id: UUID
    agreement_public_id: UUID
    token_id: UUID
    expected_lifecycle_version: Annotated[StrictInt, Field(gt=0)]
    expected_entitlement_revision: Annotated[StrictInt, Field(gt=0)]


class McpTokenPortalTokenMetadata(StrictCommercialModel):
    id: UUID
    commercial_account_public_id: UUID
    agreement_public_id: UUID
    owner_kind: Literal["self", "other_member"]
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


class McpTokenPortalSecretResult(StrictCommercialModel):
    token_metadata: McpTokenPortalTokenMetadata
    token: str | None = Field(default=None, repr=False)
    secret_available: StrictBool
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    replayed: StrictBool = False

    @model_validator(mode="after")
    def _secret_shape(self) -> "McpTokenPortalSecretResult":
        if self.secret_available is not (self.token is not None):
            raise ValueError("MCP token secret availability is inconsistent")
        if self.replayed and self.secret_available:
            raise ValueError("replayed MCP token commands cannot return a secret")
        return self


class McpTokenPortalRevokeResult(StrictCommercialModel):
    token_metadata: McpTokenPortalTokenMetadata
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    replayed: StrictBool = False


@dataclass(frozen=True, slots=True)
class _PortalAuthority:
    commercial_account_id: int
    agreement_id: int
    surface_code: str


class PostgresMcpTokenPortalCommandService:
    """Resolve public tenant identities, then delegate to token authorities."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        pepper_ring: McpTokenPepperRing,
        lifetime_policy: McpTokenLifetimePolicy,
        rotation_overlap_seconds: int = DEFAULT_CUSTOMER_ROTATION_OVERLAP_SECONDS,
    ) -> None:
        flags.validate()
        if (
            isinstance(rotation_overlap_seconds, bool)
            or not isinstance(rotation_overlap_seconds, int)
            or not 1 <= rotation_overlap_seconds <= 900
        ):
            raise ValueError(
                "customer MCP token rotation overlap must be 1-900 seconds"
            )
        self._connection = PostgresTupleCursorConnection(connection)
        self._flags = flags
        self._pepper_ring = pepper_ring
        self._lifetime_policy = lifetime_policy
        self._rotation_overlap_seconds = rotation_overlap_seconds

    def mint(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        request: McpTokenPortalMintRequest,
    ) -> McpTokenPortalSecretResult:
        authority = self._resolve_authority(
            actor_user_id,
            runtime_environment,
            request.commercial_account_public_id,
            request.agreement_public_id,
        )
        issued = McpTokenService(
            self._connection,
            flags=self._flags,
            pepper_ring=self._pepper_ring,
            lifetime_policy=self._lifetime_policy,
        ).mint(
            actor_user_id=actor_user_id,
            runtime_environment=runtime_environment,
            command=McpTokenMintCommand(
                idempotency_key=request.idempotency_key,
                commercial_account_id=authority.commercial_account_id,
                agreement_id=authority.agreement_id,
                surface_code=authority.surface_code,
                expected_entitlement_revision=request.expected_entitlement_revision,
                label=request.label,
                requested_scopes=request.requested_scopes,
                expires_at=request.expires_at,
                reason_code="token.customer_mint",
            ),
        )
        return McpTokenPortalSecretResult(
            token_metadata=self._public_metadata(
                issued.token_metadata,
                request.commercial_account_public_id,
                request.agreement_public_id,
                actor_user_id,
            ),
            token=issued.token,
            secret_available=issued.secret_available,
            entitlement_revision=issued.entitlement_revision,
            replayed=issued.replayed,
        )

    def rotate(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        request: McpTokenPortalLifecycleRequest,
    ) -> McpTokenPortalSecretResult:
        authority = self._resolve_authority(
            actor_user_id,
            runtime_environment,
            request.commercial_account_public_id,
            request.agreement_public_id,
        )
        rotated = McpTokenLifecycleService(
            self._connection, flags=self._flags, pepper_ring=self._pepper_ring
        ).rotate_as_customer(
            actor_user_id=actor_user_id,
            runtime_environment=runtime_environment,
            command=McpTokenRotateCommand(
                idempotency_key=request.idempotency_key,
                commercial_account_id=authority.commercial_account_id,
                agreement_id=authority.agreement_id,
                surface_code=authority.surface_code,
                token_id=request.token_id,
                expected_lifecycle_version=request.expected_lifecycle_version,
                expected_entitlement_revision=request.expected_entitlement_revision,
                overlap_seconds=self._rotation_overlap_seconds,
                reason_code="token.customer_rotate",
            ),
        )
        return McpTokenPortalSecretResult(
            token_metadata=self._public_metadata(
                rotated.token_metadata,
                request.commercial_account_public_id,
                request.agreement_public_id,
                actor_user_id,
            ),
            token=rotated.token,
            secret_available=rotated.secret_available,
            entitlement_revision=rotated.entitlement_revision,
            replayed=rotated.replayed,
        )

    def revoke(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        request: McpTokenPortalLifecycleRequest,
    ) -> McpTokenPortalRevokeResult:
        authority = self._resolve_authority(
            actor_user_id,
            runtime_environment,
            request.commercial_account_public_id,
            request.agreement_public_id,
        )
        revoked = McpTokenLifecycleService(
            self._connection, flags=self._flags, pepper_ring=self._pepper_ring
        ).revoke_as_customer(
            actor_user_id=actor_user_id,
            runtime_environment=runtime_environment,
            command=McpTokenRevokeCommand(
                idempotency_key=request.idempotency_key,
                commercial_account_id=authority.commercial_account_id,
                agreement_id=authority.agreement_id,
                surface_code=authority.surface_code,
                token_id=request.token_id,
                expected_lifecycle_version=request.expected_lifecycle_version,
                expected_entitlement_revision=request.expected_entitlement_revision,
                reason_code="token.customer_revoke",
            ),
        )
        return McpTokenPortalRevokeResult(
            token_metadata=self._public_metadata(
                revoked.token_metadata,
                request.commercial_account_public_id,
                request.agreement_public_id,
                actor_user_id,
            ),
            entitlement_revision=revoked.entitlement_revision,
            replayed=revoked.replayed,
        )

    def list_tokens(
        self,
        *,
        actor_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        commercial_account_public_id: UUID,
        agreement_public_id: UUID,
        limit: int = 100,
    ) -> tuple[McpTokenPortalTokenMetadata, ...]:
        self._require_actor(actor_user_id)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 200
        ):
            raise ValueError("MCP token list limit must be between 1 and 200")
        self._require_clean_transaction()
        try:
            self._require_enabled(runtime_environment)
            authority = self._query_authority(
                actor_user_id,
                commercial_account_public_id,
                agreement_public_id,
            )
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT token.id, token.user_id, token.surface_code,
                           token.token_prefix, token.label, token.requested_scopes,
                           token.status, token.version, token.created_at,
                           token.expires_at, token.rotated_from_token_id,
                           token.rotation_successor_token_id,
                           token.rotation_overlap_until, token.revoked_at,
                           token.revoked_reason_code, token.expired_at,
                           token.last_used_at
                      FROM mcp_tokens token
                     WHERE token.commercial_account_id = %s
                       AND token.agreement_id = %s
                       AND token.surface_code = %s
                     ORDER BY token.created_at DESC, token.id DESC
                     LIMIT %s
                     FOR SHARE OF token
                    """,
                    (
                        authority.commercial_account_id,
                        authority.agreement_id,
                        authority.surface_code,
                        limit,
                    ),
                )
                rows = cursor.fetchall()
            return tuple(
                self._metadata_from_row(
                    row,
                    commercial_account_public_id,
                    agreement_public_id,
                    actor_user_id,
                )
                for row in rows
            )
        finally:
            self._connection.rollback()

    def _resolve_authority(
        self,
        actor_user_id: int,
        runtime_environment: str,
        account_public_id: UUID,
        agreement_public_id: UUID,
    ) -> _PortalAuthority:
        self._require_actor(actor_user_id)
        self._require_clean_transaction()
        try:
            self._require_enabled(runtime_environment)
            return self._query_authority(
                actor_user_id,
                account_public_id,
                agreement_public_id,
            )
        finally:
            self._connection.rollback()

    def _query_authority(
        self,
        actor_user_id: int,
        account_public_id: UUID,
        agreement_public_id: UUID,
    ) -> _PortalAuthority:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT account.id, agreement.id, agreement.surface_code
                  FROM commercial_account_members member
                  JOIN commercial_accounts account
                    ON account.id = member.commercial_account_id
                  JOIN commercial_agreements agreement
                    ON agreement.commercial_account_id = account.id
                 WHERE member.user_id = %s AND member.status = 'active'
                   AND member.role IN ('owner', 'admin')
                   AND account.public_id = %s
                   AND agreement.public_id = %s
                 FOR SHARE OF member, account, agreement
                """,
                (actor_user_id, str(account_public_id), str(agreement_public_id)),
            )
            rows = cursor.fetchall()
        if len(rows) != 1:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        return _PortalAuthority(
            commercial_account_id=int(rows[0][0]),
            agreement_id=int(rows[0][1]),
            surface_code=str(rows[0][2]),
        )

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
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        if row is None or row[0] != runtime_environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)

    def _require_clean_transaction(self) -> None:
        if getattr(self._connection, "autocommit", False):
            raise McpTokenPortalRuntimeError(
                "MCP token portal requires autocommit disabled"
            )
        status = getattr(self._connection, "get_transaction_status", None)
        if status is not None and status() != 0:
            raise McpTokenPortalRuntimeError(
                "MCP token portal requires a clean transaction boundary"
            )

    @staticmethod
    def _require_actor(actor_user_id: object) -> None:
        if (
            isinstance(actor_user_id, bool)
            or not isinstance(actor_user_id, int)
            or actor_user_id <= 0
        ):
            raise ValueError("actor user identity must be a positive integer")

    @staticmethod
    def _public_metadata(
        metadata: McpTokenMetadata,
        account_public_id: UUID,
        agreement_public_id: UUID,
        actor_user_id: int,
    ) -> McpTokenPortalTokenMetadata:
        return McpTokenPortalTokenMetadata(
            id=metadata.id,
            commercial_account_public_id=account_public_id,
            agreement_public_id=agreement_public_id,
            owner_kind=(
                "self" if metadata.user_id == actor_user_id else "other_member"
            ),
            surface_code=metadata.surface_code,
            token_prefix=metadata.token_prefix,
            label=metadata.label,
            requested_scopes=metadata.requested_scopes,
            status=metadata.status,
            version=metadata.version,
            created_at=metadata.created_at,
            expires_at=metadata.expires_at,
            rotated_from_token_id=metadata.rotated_from_token_id,
            rotation_successor_token_id=metadata.rotation_successor_token_id,
            rotation_overlap_until=metadata.rotation_overlap_until,
            revoked_at=metadata.revoked_at,
            revoked_reason_code=metadata.revoked_reason_code,
            expired_at=metadata.expired_at,
            last_used_at=metadata.last_used_at,
        )

    @staticmethod
    def _metadata_from_row(
        row: tuple[object, ...],
        account_public_id: UUID,
        agreement_public_id: UUID,
        actor_user_id: int,
    ) -> McpTokenPortalTokenMetadata:
        return McpTokenPortalTokenMetadata(
            id=UUID(str(row[0])),
            owner_kind=("self" if int(row[1]) == actor_user_id else "other_member"),
            commercial_account_public_id=account_public_id,
            agreement_public_id=agreement_public_id,
            surface_code=str(row[2]),
            token_prefix=str(row[3]),
            label=str(row[4]),
            requested_scopes=tuple(row[5]),
            status=row[6],  # type: ignore[arg-type]
            version=int(row[7]),
            created_at=row[8],  # type: ignore[arg-type]
            expires_at=row[9],  # type: ignore[arg-type]
            rotated_from_token_id=UUID(str(row[10])) if row[10] else None,
            rotation_successor_token_id=UUID(str(row[11])) if row[11] else None,
            rotation_overlap_until=row[12],  # type: ignore[arg-type]
            revoked_at=row[13],  # type: ignore[arg-type]
            revoked_reason_code=row[14],  # type: ignore[arg-type]
            expired_at=row[15],  # type: ignore[arg-type]
            last_used_at=row[16],  # type: ignore[arg-type]
        )


__all__ = [
    "DEFAULT_CUSTOMER_ROTATION_OVERLAP_SECONDS",
    "McpTokenPortalLifecycleRequest",
    "McpTokenPortalMintRequest",
    "McpTokenPortalRevokeResult",
    "McpTokenPortalSecretResult",
    "McpTokenPortalTokenMetadata",
    "PostgresMcpTokenPortalCommandService",
]
