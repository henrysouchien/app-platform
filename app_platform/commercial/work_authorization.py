"""Signed, digest-only gateway authority for one commercial workflow attempt."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Annotated, Any, Callable, Literal, Mapping
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import jwt
from pydantic import Field, StrictBool, StrictInt, model_validator

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .flags import CommercialFlags
from .models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .usage.workflow_attempts import (
    WorkflowAttemptKind,
    WorkflowObservability,
)


WORK_AUTHORIZATION_ALGORITHM = "EdDSA"
WORK_AUTHORIZATION_ISSUER = "risk-module-commercial-work-control"
WORK_AUTHORIZATION_AUDIENCE = "hank-agent-gateway-work-start"
WORK_AUTHORIZATION_SOURCE_PRODUCT = "hank-agent-gateway"
_MAX_AUTHORIZATION_LIFETIME_SECONDS = 300
OpaqueIdentifier = Annotated[
    str,
    Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$",
    ),
]


class CommercialWorkAuthorizationV1(StrictCommercialModel):
    schema_version: Literal[1]
    kid: StableCode
    iss: Literal["risk-module-commercial-work-control"]
    aud: Literal["hank-agent-gateway-work-start"]
    jti: UUID
    environment: Literal["dev", "staging", "prod"]
    execution_claim_jti: UUID
    workflow_run_id: UUID
    workflow_attempt_group_id: UUID
    workflow_attempt_number: Annotated[StrictInt, Field(gt=0)]
    retry_of_workflow_run_id: UUID | None
    workflow_attempt_kind: WorkflowAttemptKind
    primary_inference_observability: WorkflowObservability
    funding_route_id: UUID
    provider: StableCode
    billing_mode: Literal["byok", "metered"]
    reservation_id: UUID | None
    operation: StableCode
    capability_id: StableCode | None
    request_id: OpaqueIdentifier
    session_id: OpaqueIdentifier
    iat: Annotated[StrictInt, Field(gt=0)]
    exp: Annotated[StrictInt, Field(gt=0)]

    @model_validator(mode="after")
    def _valid_authority(self) -> "CommercialWorkAuthorizationV1":
        if self.exp <= self.iat or (
            self.exp - self.iat > _MAX_AUTHORIZATION_LIFETIME_SECONDS
        ):
            raise ValueError("work authorization lifetime must be within five minutes")
        if (self.billing_mode == "metered") != (self.reservation_id is not None):
            raise ValueError("work authorization reservation differs from billing mode")
        if (
            self.billing_mode == "metered"
            and self.primary_inference_observability != "hank_metered"
        ) or (
            self.billing_mode == "byok"
            and self.primary_inference_observability != "hank_byok_observed"
        ):
            raise ValueError(
                "work authorization observability differs from billing mode"
            )
        return self


class WorkAuthorizationIssueCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    authorization_id: UUID
    environment: Literal["dev", "staging", "prod"]
    execution_context_id: UUID
    workflow_run_id: UUID
    expected_workflow_code: StableCode
    funding_route_id: UUID
    expected_provider: StableCode
    expected_billing_mode: Literal["byok", "metered"]
    reservation_id: UUID | None = None
    operation: StableCode
    capability_id: StableCode | None = None
    request_id: OpaqueIdentifier
    session_id: OpaqueIdentifier
    lifetime_seconds: Annotated[
        StrictInt, Field(gt=0, le=_MAX_AUTHORIZATION_LIFETIME_SECONDS)
    ] = _MAX_AUTHORIZATION_LIFETIME_SECONDS


class IssuedCommercialWorkAuthorization(StrictCommercialModel):
    token: Annotated[
        str,
        Field(min_length=1, max_length=4096, repr=False, exclude=True),
    ]
    payload: CommercialWorkAuthorizationV1
    token_sha256: Sha256Digest
    replayed: StrictBool = False


class WorkAuthorizationIssueError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CommercialWorkAuthorizationSigningKey:
    def __init__(self, *, key_id: StableCode, private_key_pem: bytes) -> None:
        key = load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("work authorization signing key must be Ed25519")
        self.key_id = key_id
        self.private_key = key


class RetainedWorkAuthorizationSigningKey:
    def __init__(
        self,
        *,
        signing_key: CommercialWorkAuthorizationSigningKey,
        retired_at: datetime,
        retained_until: datetime,
    ) -> None:
        if (
            retired_at.tzinfo is None
            or retired_at.utcoffset() is None
            or retained_until.tzinfo is None
            or retained_until.utcoffset() is None
        ):
            raise ValueError("retained signing-key window must be timezone-aware")
        retired_at = retired_at.astimezone(timezone.utc)
        retained_until = retained_until.astimezone(timezone.utc)
        if retained_until < retired_at + timedelta(
            seconds=_MAX_AUTHORIZATION_LIFETIME_SECONDS
        ):
            raise ValueError(
                "retained signing key must cover the maximum token lifetime"
            )
        self.signing_key = signing_key
        self.retired_at = retired_at
        self.retained_until = retained_until


class CommercialWorkAuthorizationSigningKeyRing:
    """One active key plus explicitly time-bounded replay-only private keys."""

    def __init__(
        self,
        *,
        current: CommercialWorkAuthorizationSigningKey,
        retained: tuple[RetainedWorkAuthorizationSigningKey, ...] = (),
    ) -> None:
        keys = {current.key_id: current}
        deadlines: dict[str, datetime] = {}
        retirements: dict[str, datetime] = {}
        for entry in retained:
            key_id = entry.signing_key.key_id
            if key_id in keys:
                raise ValueError("work authorization key IDs must be unique")
            keys[key_id] = entry.signing_key
            deadlines[key_id] = entry.retained_until
            retirements[key_id] = entry.retired_at
        self.current = current
        self._keys = keys
        self._retained_until = deadlines
        self._retired_at = retirements

    def for_replay(
        self, key_id: str, *, now: datetime, issued_at: datetime
    ) -> CommercialWorkAuthorizationSigningKey | None:
        if key_id == self.current.key_id:
            return self.current
        retained_until = self._retained_until.get(key_id)
        if retained_until is None or now > retained_until:
            return None
        if issued_at > self._retired_at[key_id]:
            raise WorkAuthorizationIssueError("work_authorization.replay_key_retired")
        return self._keys[key_id]


class PostgresCommercialWorkAuthorizationIssuer:
    """Own issuance and return a token only after digest evidence commits."""

    def __init__(
        self,
        connection: Any,
        *,
        signing_key: (
            CommercialWorkAuthorizationSigningKey
            | CommercialWorkAuthorizationSigningKeyRing
        ),
        flags: CommercialFlags,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        flags.validate()
        self._connection = connection
        self._keys = (
            signing_key
            if isinstance(signing_key, CommercialWorkAuthorizationSigningKeyRing)
            else CommercialWorkAuthorizationSigningKeyRing(current=signing_key)
        )
        self._flags = flags
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def connection(self) -> Any:
        """Return the transaction owner for same-connection orchestration."""

        return self._connection

    def issue(
        self, command: WorkAuthorizationIssueCommand
    ) -> IssuedCommercialWorkAuthorization:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("work authorization issuance requires a transaction")
        status = getattr(self._connection, "get_transaction_status", None)
        if status is None or status() != 0:
            raise RuntimeError("work authorization issuer requires a clean boundary")
        if not self._flags.commercial_work_authorization_enabled:
            raise WorkAuthorizationIssueError("work_authorization.disabled")
        if command.environment != self._flags.environment:
            raise WorkAuthorizationIssueError("work_authorization.environment_mismatch")
        try:
            issued = self._prepare(command)
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return issued

    def _prepare(
        self, command: WorkAuthorizationIssueCommand
    ) -> IssuedCommercialWorkAuthorization:
        command_sha256 = canonical_sha256(
            command.model_dump(mode="python", exclude={"idempotency_key"})
        )
        scope = self._load_attempt_scope(command.workflow_run_id)
        if UUID(str(scope["execution_context_id"])) != command.execution_context_id:
            raise WorkAuthorizationIssueError("work_authorization.context_mismatch")
        if scope["workflow_code"] != command.expected_workflow_code:
            raise WorkAuthorizationIssueError("work_authorization.workflow_mismatch")
        if scope["environment"] != command.environment:
            raise WorkAuthorizationIssueError("work_authorization.environment_mismatch")
        lock_key = (
            f"commercial.work_authorization:{scope['environment']}:"
            f"{scope['commercial_account_id']}:{command.idempotency_key}"
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,)
            )
            cursor.execute(
                """
                SELECT authorization_id, environment, execution_context_id,
                       workflow_run_id, attempt_group_id, attempt_number,
                       retry_of_workflow_run_id, attempt_kind,
                       primary_inference_observability, funding_route_id,
                       provider, billing_mode, reservation_id, operation,
                       capability_id, request_id, session_id, key_id,
                       token_sha256, issued_at, expires_at, command_sha256
                  FROM commercial_work_start_authorizations
                 WHERE environment = %s AND commercial_account_id = %s
                   AND source_product = %s AND idempotency_key = %s
                 FOR SHARE
                """,
                (
                    scope["environment"],
                    scope["commercial_account_id"],
                    WORK_AUTHORIZATION_SOURCE_PRODUCT,
                    command.idempotency_key,
                ),
            )
            existing = cursor.fetchone()
        if existing is not None:
            return self._replay(command, command_sha256, existing)

        now = self._server_now()
        authority = self._load_initial_authority(command, scope, now)
        expires_at = self._bounded_expiry(command, authority, now)
        payload = self._payload(
            key_id=self._keys.current.key_id,
            authorization_id=command.authorization_id,
            environment=str(scope["environment"]),
            execution_context_id=UUID(str(scope["execution_context_id"])),
            workflow_run_id=command.workflow_run_id,
            attempt_group_id=UUID(str(scope["attempt_group_id"])),
            attempt_number=int(scope["attempt_number"]),
            retry_of_workflow_run_id=(
                UUID(str(scope["retry_of_workflow_run_id"]))
                if scope["retry_of_workflow_run_id"] is not None
                else None
            ),
            attempt_kind=str(scope["attempt_kind"]),
            primary_inference_observability=str(
                scope["primary_inference_observability"]
            ),
            funding_route_id=command.funding_route_id,
            provider=str(authority["provider"]),
            billing_mode=str(authority["billing_mode"]),
            reservation_id=command.reservation_id,
            operation=command.operation,
            capability_id=command.capability_id,
            request_id=command.request_id,
            session_id=command.session_id,
            issued_at=now,
            expires_at=expires_at,
        )
        token, token_sha256 = self._signed(payload)
        audit_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_id,
                commercial_account_id=int(scope["commercial_account_id"]),
                agreement_id=int(scope["agreement_id"]),
                actor_type="service",
                actor_id="commercial-work-control",
                action="commercial.work_authorization.issue",
                target_type="commercial_work_start_authorization",
                target_id=str(command.authorization_id),
                reason_code="work_authorization.issued",
                after={
                    "account_id": int(scope["commercial_account_id"]),
                    "agreement_id": int(scope["agreement_id"]),
                    "result_code": "applied",
                },
            ),
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO commercial_work_start_authorizations (
                    authorization_id, environment, commercial_account_id,
                    source_product, execution_context_id, workflow_run_id,
                    attempt_group_id, attempt_number, retry_of_workflow_run_id,
                    attempt_kind, primary_inference_observability,
                    funding_route_id, provider, billing_mode,
                    reservation_id, operation, capability_id, request_id,
                    session_id, key_id, token_sha256, issued_at, expires_at,
                    idempotency_key, command_sha256, audit_event_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(command.authorization_id),
                    scope["environment"],
                    scope["commercial_account_id"],
                    WORK_AUTHORIZATION_SOURCE_PRODUCT,
                    str(scope["execution_context_id"]),
                    str(command.workflow_run_id),
                    str(scope["attempt_group_id"]),
                    scope["attempt_number"],
                    (
                        str(scope["retry_of_workflow_run_id"])
                        if scope["retry_of_workflow_run_id"] is not None
                        else None
                    ),
                    scope["attempt_kind"],
                    scope["primary_inference_observability"],
                    str(command.funding_route_id),
                    authority["provider"],
                    authority["billing_mode"],
                    str(command.reservation_id) if command.reservation_id else None,
                    command.operation,
                    command.capability_id,
                    command.request_id,
                    command.session_id,
                    self._keys.current.key_id,
                    token_sha256,
                    now,
                    expires_at,
                    command.idempotency_key,
                    command_sha256,
                    str(audit_id),
                ),
            )
        return IssuedCommercialWorkAuthorization(
            token=token,
            payload=payload,
            token_sha256=token_sha256,
        )

    def _load_attempt_scope(self, workflow_run_id: UUID) -> dict[str, object]:
        names = (
            "execution_context_id",
            "attempt_group_id",
            "attempt_number",
            "retry_of_workflow_run_id",
            "attempt_kind",
            "primary_inference_observability",
            "workflow_code",
            "source_product",
            "environment",
            "commercial_account_id",
            "agreement_id",
            "agreement_terms_id",
            "context_status",
            "context_revoked_at",
            "context_start_deadline",
            "workflow_state",
            "workflow_started_at",
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT lineage.execution_context_id, lineage.attempt_group_id,
                       lineage.attempt_number, lineage.retry_of_workflow_run_id,
                       lineage.attempt_kind,
                       workflow.primary_inference_observability,
                       workflow.workflow_code,
                       lineage.source_product,
                       context.environment, context.commercial_account_id,
                       context.agreement_id, context.agreement_terms_id,
                       context.status, context.revoked_at,
                       context.authorized_work_start_deadline,
                       workflow.state, workflow.started_at
                  FROM commercial_workflow_attempt_lineage lineage
                  JOIN commercial_workflow_runs workflow
                    ON workflow.id = lineage.workflow_run_id
                   AND workflow.execution_context_id = lineage.execution_context_id
                  JOIN commercial_execution_contexts context
                    ON context.id = lineage.execution_context_id
                 WHERE lineage.workflow_run_id = %s
                 FOR SHARE OF lineage, workflow, context
                """,
                (str(workflow_run_id),),
            )
            row = cursor.fetchone()
        if row is None:
            raise WorkAuthorizationIssueError("work_authorization.attempt_unavailable")
        scope = dict(zip(names, self._values(row, names), strict=True))
        if scope["source_product"] != WORK_AUTHORIZATION_SOURCE_PRODUCT:
            raise WorkAuthorizationIssueError(
                "work_authorization.source_product_mismatch"
            )
        return scope

    def _load_initial_authority(
        self,
        command: WorkAuthorizationIssueCommand,
        scope: Mapping[str, object],
        now: datetime,
    ) -> dict[str, object]:
        if (
            scope["context_status"] != "active"
            or scope["context_revoked_at"] is not None
            or scope["workflow_state"] != "started"
            or now < scope["workflow_started_at"]
            or now >= scope["context_start_deadline"]
        ):
            raise WorkAuthorizationIssueError("work_authorization.context_inactive")
        route_names = (
            "provider",
            "billing_mode",
            "environment",
            "commercial_account_id",
            "agreement_id",
            "agreement_terms_id",
            "classification_state",
            "effective_from",
            "effective_until",
            "revoked_at",
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT provider, billing_mode, environment, commercial_account_id,
                       agreement_id, agreement_terms_id, classification_state,
                       effective_from, effective_until, revoked_at
                  FROM commercial_funding_routes
                 WHERE id = %s
                 FOR SHARE
                """,
                (str(command.funding_route_id),),
            )
            row = cursor.fetchone()
        if row is None:
            raise WorkAuthorizationIssueError(
                "work_authorization.funding_route_unavailable"
            )
        route = dict(zip(route_names, self._values(row, route_names), strict=True))
        if (
            route["environment"] != scope["environment"]
            or int(route["commercial_account_id"])
            != int(scope["commercial_account_id"])
            or int(route["agreement_id"]) != int(scope["agreement_id"])
            or int(route["agreement_terms_id"]) != int(scope["agreement_terms_id"])
            or route["classification_state"] != "active"
            or now < route["effective_from"]
            or (
                route["effective_until"] is not None and now >= route["effective_until"]
            )
            or (route["revoked_at"] is not None and now >= route["revoked_at"])
        ):
            raise WorkAuthorizationIssueError(
                "work_authorization.funding_route_inactive"
            )
        if (
            route["provider"] != command.expected_provider
            or route["billing_mode"] != command.expected_billing_mode
        ):
            raise WorkAuthorizationIssueError(
                "work_authorization.dispatch_route_mismatch"
            )
        is_metered = route["billing_mode"] == "metered"
        if is_metered != (command.reservation_id is not None):
            raise WorkAuthorizationIssueError("work_authorization.reservation_mismatch")
        if is_metered and not self._flags.commercial_budget_enforcement_enabled:
            raise WorkAuthorizationIssueError(
                "work_authorization.budget_enforcement_disabled"
            )
        observability = scope["primary_inference_observability"]
        if (is_metered and observability != "hank_metered") or (
            not is_metered and observability != "hank_byok_observed"
        ):
            raise WorkAuthorizationIssueError(
                "work_authorization.observability_mismatch"
            )

        route["context_start_deadline"] = scope["context_start_deadline"]
        route["route_effective_until"] = route["effective_until"]
        route["route_revoked_at"] = route["revoked_at"]
        route["reservation_start_deadline"] = None
        if command.reservation_id is None:
            return route
        reservation_names = (
            "execution_context_id",
            "workflow_run_id",
            "state",
            "authorized_work_start_deadline",
            "request_id",
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_context_id, workflow_run_id, state,
                       authorized_work_start_deadline, request_id
                  FROM commercial_budget_reservations
                 WHERE id = %s
                 FOR SHARE
                """,
                (str(command.reservation_id),),
            )
            row = cursor.fetchone()
        if row is None:
            raise WorkAuthorizationIssueError(
                "work_authorization.reservation_unavailable"
            )
        reservation = dict(
            zip(reservation_names, self._values(row, reservation_names), strict=True)
        )
        if (
            UUID(str(reservation["execution_context_id"]))
            != UUID(str(scope["execution_context_id"]))
            or reservation["workflow_run_id"] is None
            or UUID(str(reservation["workflow_run_id"])) != command.workflow_run_id
            or reservation["state"] != "reserved"
            or now >= reservation["authorized_work_start_deadline"]
            or reservation["request_id"] != command.request_id
        ):
            raise WorkAuthorizationIssueError("work_authorization.reservation_inactive")
        route["reservation_start_deadline"] = reservation[
            "authorized_work_start_deadline"
        ]
        return route

    def _bounded_expiry(
        self,
        command: WorkAuthorizationIssueCommand,
        authority: Mapping[str, object],
        now: datetime,
    ) -> datetime:
        deadlines = [
            now + timedelta(seconds=command.lifetime_seconds),
            authority["context_start_deadline"],
        ]
        for name in (
            "route_effective_until",
            "route_revoked_at",
            "reservation_start_deadline",
        ):
            if authority.get(name) is not None:
                deadlines.append(authority[name])
        expires_at = min(deadlines)
        if expires_at <= now:
            raise WorkAuthorizationIssueError("work_authorization.window_expired")
        return expires_at

    def _replay(
        self,
        command: WorkAuthorizationIssueCommand,
        command_sha256: str,
        row: object,
    ) -> IssuedCommercialWorkAuthorization:
        names = (
            "authorization_id",
            "environment",
            "execution_context_id",
            "workflow_run_id",
            "attempt_group_id",
            "attempt_number",
            "retry_of_workflow_run_id",
            "attempt_kind",
            "primary_inference_observability",
            "funding_route_id",
            "provider",
            "billing_mode",
            "reservation_id",
            "operation",
            "capability_id",
            "request_id",
            "session_id",
            "key_id",
            "token_sha256",
            "issued_at",
            "expires_at",
            "command_sha256",
        )
        values = dict(zip(names, self._values(row, names), strict=True))
        if (
            UUID(str(values["authorization_id"])) != command.authorization_id
            or values["command_sha256"] != command_sha256
        ):
            raise WorkAuthorizationIssueError("work_authorization.idempotency_conflict")
        signing_key = self._keys.for_replay(
            str(values["key_id"]),
            now=self._server_now(),
            issued_at=values["issued_at"],
        )
        if signing_key is None:
            raise WorkAuthorizationIssueError(
                "work_authorization.replay_key_unavailable"
            )
        payload = self._payload(
            key_id=signing_key.key_id,
            authorization_id=UUID(str(values["authorization_id"])),
            environment=str(values["environment"]),
            execution_context_id=UUID(str(values["execution_context_id"])),
            workflow_run_id=UUID(str(values["workflow_run_id"])),
            attempt_group_id=UUID(str(values["attempt_group_id"])),
            attempt_number=int(values["attempt_number"]),
            retry_of_workflow_run_id=(
                UUID(str(values["retry_of_workflow_run_id"]))
                if values["retry_of_workflow_run_id"] is not None
                else None
            ),
            attempt_kind=str(values["attempt_kind"]),
            primary_inference_observability=str(
                values["primary_inference_observability"]
            ),
            funding_route_id=UUID(str(values["funding_route_id"])),
            provider=str(values["provider"]),
            billing_mode=str(values["billing_mode"]),
            reservation_id=(
                UUID(str(values["reservation_id"]))
                if values["reservation_id"] is not None
                else None
            ),
            operation=str(values["operation"]),
            capability_id=(
                str(values["capability_id"])
                if values["capability_id"] is not None
                else None
            ),
            request_id=str(values["request_id"]),
            session_id=str(values["session_id"]),
            issued_at=values["issued_at"],
            expires_at=values["expires_at"],
        )
        token, token_sha256 = self._signed(payload, signing_key=signing_key)
        if not hmac.compare_digest(token_sha256, str(values["token_sha256"])):
            raise WorkAuthorizationIssueError(
                "work_authorization.replay_digest_mismatch"
            )
        return IssuedCommercialWorkAuthorization(
            token=token,
            payload=payload,
            token_sha256=token_sha256,
            replayed=True,
        )

    def _payload(
        self,
        *,
        key_id: str,
        authorization_id: UUID,
        environment: str,
        execution_context_id: UUID,
        workflow_run_id: UUID,
        attempt_group_id: UUID,
        attempt_number: int,
        retry_of_workflow_run_id: UUID | None,
        attempt_kind: str,
        primary_inference_observability: str,
        funding_route_id: UUID,
        provider: str,
        billing_mode: str,
        reservation_id: UUID | None,
        operation: str,
        capability_id: str | None,
        request_id: str,
        session_id: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> CommercialWorkAuthorizationV1:
        return CommercialWorkAuthorizationV1(
            schema_version=1,
            kid=key_id,
            iss=WORK_AUTHORIZATION_ISSUER,
            aud=WORK_AUTHORIZATION_AUDIENCE,
            jti=authorization_id,
            environment=environment,
            execution_claim_jti=execution_context_id,
            workflow_run_id=workflow_run_id,
            workflow_attempt_group_id=attempt_group_id,
            workflow_attempt_number=attempt_number,
            retry_of_workflow_run_id=retry_of_workflow_run_id,
            workflow_attempt_kind=attempt_kind,
            primary_inference_observability=primary_inference_observability,
            funding_route_id=funding_route_id,
            provider=provider,
            billing_mode=billing_mode,
            reservation_id=reservation_id,
            operation=operation,
            capability_id=capability_id,
            request_id=request_id,
            session_id=session_id,
            iat=int(issued_at.timestamp()),
            exp=int(expires_at.timestamp()),
        )

    def _signed(
        self,
        payload: CommercialWorkAuthorizationV1,
        *,
        signing_key: CommercialWorkAuthorizationSigningKey | None = None,
    ) -> tuple[str, str]:
        key = signing_key or self._keys.current
        if payload.kid != key.key_id:
            raise WorkAuthorizationIssueError("work_authorization.signing_key_mismatch")
        token = jwt.encode(
            payload.model_dump(mode="json"),
            key.private_key,
            algorithm=WORK_AUTHORIZATION_ALGORITHM,
            headers={"kid": key.key_id, "typ": "JWT"},
        )
        return token, "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()

    def _server_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("work authorization clock must be timezone-aware")
        return now.astimezone(timezone.utc).replace(microsecond=0)

    @staticmethod
    def _values(row: object, names: tuple[str, ...]) -> tuple[object, ...]:
        if isinstance(row, Mapping):
            return tuple(row[name] for name in names)
        return tuple(row)  # type: ignore[arg-type]


__all__ = [
    "CommercialWorkAuthorizationSigningKey",
    "CommercialWorkAuthorizationSigningKeyRing",
    "CommercialWorkAuthorizationV1",
    "IssuedCommercialWorkAuthorization",
    "PostgresCommercialWorkAuthorizationIssuer",
    "RetainedWorkAuthorizationSigningKey",
    "WORK_AUTHORIZATION_ALGORITHM",
    "WORK_AUTHORIZATION_AUDIENCE",
    "WORK_AUTHORIZATION_ISSUER",
    "WORK_AUTHORIZATION_SOURCE_PRODUCT",
    "WorkAuthorizationIssueCommand",
    "WorkAuthorizationIssueError",
]
