"""Audience-bound asymmetric commercial claims backed by durable contexts."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Annotated, Any, Final, Literal
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import jwt
from pydantic import AwareDatetime, Field, StrictInt, model_validator

from .authorization import CommercialAuthorizationContext
from .execution_contexts import (
    ExecutionContextCreateCommand,
    ExecutionContextRecord,
    ExecutionContextService,
)
from .flags import CommercialFlags
from .models import (
    CommercialClaimV1,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)


COMMERCIAL_CLAIM_ALGORITHM = "EdDSA"
COMMERCIAL_CLAIM_ISSUER: Final[Literal["risk-module-commercial-control"]] = (
    "risk-module-commercial-control"
)
COMMERCIAL_CLAIM_AUDIENCE: Final[Literal["hank-agent-gateway"]] = (
    "hank-agent-gateway"
)


CommercialClaimPayload = CommercialClaimV1


class ExecutionClaimIssueCommand(StrictCommercialModel):
    context_id: UUID
    environment: Literal["dev", "staging", "prod"]
    authorization: CommercialAuthorizationContext
    mcp_token_id: UUID | None = None
    effective_scopes: tuple[StableCode, ...]
    shadow_rate_policy_id: Annotated[StrictInt, Field(gt=0)]
    manifest_policy_id: Annotated[StrictInt, Field(gt=0)]
    expected_manifest_version: StableCode
    expected_manifest_sha256: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    authorized_work_start_deadline: AwareDatetime
    usage_accept_until: AwareDatetime

    @model_validator(mode="after")
    def _whole_second_times(self) -> "ExecutionClaimIssueCommand":
        values = (
            self.issued_at,
            self.expires_at,
            self.authorized_work_start_deadline,
            self.usage_accept_until,
        )
        if any(value.microsecond for value in values):
            raise ValueError("commercial claim timestamps must use whole seconds")
        return self


class IssuedCommercialClaim(StrictCommercialModel):
    token: Annotated[str, Field(min_length=1, max_length=4096, repr=False)]
    payload: CommercialClaimPayload
    execution_context: ExecutionContextRecord


class CommercialClaimSigningKey:
    def __init__(self, *, key_id: StableCode, private_key_pem: bytes) -> None:
        key = load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("commercial signing key must be Ed25519")
        self.key_id = key_id
        self.private_key = key


class PostgresCommercialClaimIssuer:
    """Own the issuance transaction and expose a token only after commit."""

    def __init__(
        self,
        connection: Any,
        *,
        signing_key: CommercialClaimSigningKey,
        flags: CommercialFlags,
    ) -> None:
        self._connection = connection
        self._key = signing_key
        self._flags = flags

    @property
    def connection(self) -> Any:
        """Return the transaction owner for same-connection orchestration."""

        return self._connection

    def issue(self, command: ExecutionClaimIssueCommand) -> IssuedCommercialClaim:
        return self.issue_resolved(lambda _connection: command)

    def issue_resolved(
        self,
        resolve_command: Callable[[Any], ExecutionClaimIssueCommand],
    ) -> IssuedCommercialClaim:
        """Resolve locked authority, persist context, and expose a claim after commit."""

        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("commercial claim issuance requires a transaction")
        transaction_status = getattr(self._connection, "get_transaction_status", None)
        if transaction_status is None or transaction_status() != 0:
            raise RuntimeError("commercial claim issuer requires a clean transaction boundary")
        try:
            command = resolve_command(self._connection)
            issued = self._prepare(command)
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return issued

    def _prepare(self, command: ExecutionClaimIssueCommand) -> IssuedCommercialClaim:
        identities = self._load_identities(command)
        payload = CommercialClaimPayload(
            schema_version=1,
            kid=self._key.key_id,
            iss=COMMERCIAL_CLAIM_ISSUER,
            aud=COMMERCIAL_CLAIM_AUDIENCE,
            sub=f"user:{command.authorization.user_id}",
            environment=command.environment,
            surface=command.authorization.surface_code,
            commercial_account_id=identities["account_public_id"],
            agreement_id=identities["agreement_public_id"],
            agreement_terms_revision=identities["terms_revision"],
            offer_code=command.authorization.offer_code,
            effective_scopes=tuple(
                scope.removeprefix("scope:") for scope in command.effective_scopes
            ),
            entitlement_revision=command.authorization.entitlement_revision,
            payer_policy_version=identities["payer_policy_version"],
            budget_policy_version=identities["budget_policy_version"],
            shadow_rate_version=identities["shadow_rate_version"],
            manifest_version=identities["manifest_version"],
            authorized_work_start_deadline=int(
                command.authorized_work_start_deadline.timestamp()
            ),
            usage_accept_until=int(command.usage_accept_until.timestamp()),
            iat=int(command.issued_at.timestamp()),
            exp=int(command.expires_at.timestamp()),
            jti=command.context_id,
        )
        token = jwt.encode(
            payload.model_dump(mode="json"),
            self._key.private_key,
            algorithm=COMMERCIAL_CLAIM_ALGORITHM,
            headers={"kid": self._key.key_id, "typ": "JWT"},
        )
        claim_sha256 = "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()
        context = ExecutionContextService(
            self._connection,
            flags=self._flags,
            clock=lambda: command.issued_at,
        ).create(
            ExecutionContextCreateCommand(
                id=command.context_id,
                environment=command.environment,
                audience=COMMERCIAL_CLAIM_AUDIENCE,
                authorization=command.authorization,
                mcp_token_id=command.mcp_token_id,
                effective_scopes=command.effective_scopes,
                shadow_rate_policy_id=command.shadow_rate_policy_id,
                manifest_policy_id=command.manifest_policy_id,
                claim_sha256=claim_sha256,
                issued_at=command.issued_at,
                expires_at=command.expires_at,
                authorized_work_start_deadline=command.authorized_work_start_deadline,
                usage_accept_until=command.usage_accept_until,
            )
        )
        if context.status != "active":
            raise ValueError("commercial claim execution context is revoked")
        return IssuedCommercialClaim(
            token=token, payload=payload, execution_context=context
        )

    def _load_identities(self, command: ExecutionClaimIssueCommand) -> dict[str, Any]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT account.public_id, agreement.public_id, terms.revision,
                       payer.policy_code || '@' || payer.version,
                       budget.policy_code || '@' || budget.version,
                       rate.policy_code || '@' || rate.version,
                       manifest.body_json->>'manifest_version',
                       manifest.policy_kind, manifest.content_sha256,
                       manifest.body_json
                  FROM commercial_agreement_terms terms
                  JOIN commercial_agreements agreement ON agreement.id = terms.agreement_id
                  JOIN commercial_accounts account ON account.id = terms.commercial_account_id
                  JOIN commercial_policy_versions payer ON payer.id = terms.payer_policy_id
                  JOIN commercial_policy_versions budget ON budget.id = terms.budget_policy_id
                  JOIN commercial_policy_versions rate ON rate.id = %s
                  JOIN commercial_policy_versions manifest ON manifest.id = %s
                 WHERE terms.id = %s
                 FOR SHARE OF account, agreement, terms, payer, budget, rate, manifest
                """,
                (
                    command.shadow_rate_policy_id,
                    command.manifest_policy_id,
                    command.authorization.agreement_terms_id,
                ),
            )
            row = cursor.fetchone()
        if row is None:
            raise ValueError("commercial claim identities are unavailable")
        names = (
            "account_public_id", "agreement_public_id", "terms_revision",
            "payer_policy_version", "budget_policy_version", "shadow_rate_version",
            "manifest_version",
            "manifest_policy_kind",
            "manifest_content_sha256",
            "manifest_body",
        )
        identities = dict(zip(names, row, strict=True))
        if identities["manifest_policy_kind"] != "manifest":
            raise ValueError("commercial claim manifest policy kind does not match")
        if identities["manifest_version"] != command.expected_manifest_version:
            raise ValueError("commercial claim exposure manifest version does not match")
        if identities["manifest_content_sha256"] != command.expected_manifest_sha256:
            raise ValueError("commercial claim exposure manifest digest does not match")
        if canonical_sha256(identities["manifest_body"]) != command.expected_manifest_sha256:
            raise ValueError("commercial claim exposure manifest policy integrity failed")
        return identities
