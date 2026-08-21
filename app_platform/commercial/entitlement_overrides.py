"""Audited, replay-safe operator lifecycle for bounded entitlement overrides."""

from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
import json
from typing import Annotated, Callable, Literal, TypeVar
from uuid import UUID, NAMESPACE_URL, uuid5

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority_invalidation import (
    CommercialAuthorityInvalidationCommand,
    publish_authority_invalidation,
)
from .authority import CommercialAction, CommercialRole, record_change_execution
from .authority_store import PostgresChangeRequestStore, load_named_operator
from .change_request_commands import (
    ChangeRequestCommandResult,
    ChangeRequestCommandService,
)
from .entitlement_store import AccountProjectionRequest, persist_account_entitlements
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .models import StableCode, StrictCommercialModel, canonical_sha256


OverrideOperation = Literal["create", "revoke"]
OverrideEffect = Literal["allow", "deny", "limit"]
_ResultT = TypeVar("_ResultT")


class EntitlementOverrideCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    operation: OverrideOperation
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    expected_entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    override_id: UUID | None = None
    surface_code: StableCode | None = None
    subject_kind: Literal["account", "user"] | None = None
    subject_user_id: Annotated[StrictInt, Field(gt=0)] | None = None
    entitlement_key: StableCode | None = None
    effect: OverrideEffect | None = None
    value: StrictBool | Annotated[StrictInt, Field(ge=0)] | None = None
    priority: Annotated[StrictInt, Field(ge=0)] = 0
    effective_from: AwareDatetime | None = None
    effective_until: AwareDatetime | None = None
    reason_code: StableCode

    @model_validator(mode="after")
    def _valid_shape(self) -> "EntitlementOverrideCommand":
        create_fields = (
            self.surface_code,
            self.subject_kind,
            self.entitlement_key,
            self.effect,
            self.value,
            self.effective_from,
            self.effective_until,
        )
        if self.operation == "revoke":
            if self.override_id is None or any(
                value is not None for value in create_fields
            ):
                raise ValueError("revoke requires only override identity and reason")
            if self.subject_user_id is not None or self.priority != 0:
                raise ValueError("revoke cannot replace immutable override facts")
            return self
        if self.override_id is not None or any(
            value is None for value in create_fields
        ):
            raise ValueError("create requires complete override facts")
        if (self.subject_kind == "user") is not (self.subject_user_id is not None):
            raise ValueError("user overrides require exactly one subject user")
        if self.effective_until <= self.effective_from:  # type: ignore[operator]
            raise ValueError("override expiry must follow its effective time")
        if self.effect in {"allow", "deny"} and self.value is not True:
            raise ValueError("allow and deny overrides require boolean true")
        if self.effect == "limit" and (
            isinstance(self.value, bool) or not isinstance(self.value, int)
        ):
            raise ValueError("limit overrides require a non-negative integer")
        if (
            self.effect == "allow"
            and self.entitlement_key == "scope:trade-execute"
            and self.subject_kind != "user"
        ):
            raise ValueError("trade execution allows must be user-scoped")
        return self

    @property
    def expands_access(self) -> bool:
        return self.operation == "create" and self.effect == "allow"

    def authority_sha256(self) -> str:
        return canonical_sha256(
            self.model_dump(mode="python", exclude={"idempotency_key"})
        )


class EntitlementOverrideResult(StrictCommercialModel):
    override_id: UUID
    operation: OverrideOperation
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    audit_event_id: UUID
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    projection_changed: StrictBool
    replayed: StrictBool = False


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class EntitlementOverrideService:
    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        clock: Callable[[], datetime],
    ) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._clock = clock
        self._requests = PostgresChangeRequestStore(connection)

    @_atomic
    def request_high_risk_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        request_idempotency_key: IdempotencyKey,
        command: EntitlementOverrideCommand,
        expires_in_seconds: Annotated[int, Field(ge=60, le=86400)],
    ) -> ChangeRequestCommandResult:
        now = self._clock()
        self._require_flags(runtime_environment)
        self._require_high_risk(command)
        self._validate_scope(command)
        return ChangeRequestCommandService(
            self._connection
        ).request_execution_scope_override(
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            step_up_event_id=step_up_event_id,
            idempotency_key=request_idempotency_key,
            target_type="commercial_entitlement_override",
            target_id=self.authority_target(runtime_environment, command),
            authority_sha256=command.authority_sha256(),
            reason_code=command.reason_code,
            expires_in_seconds=expires_in_seconds,
            now=now,
        )

    @_atomic
    def approve_high_risk_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        approval_idempotency_key: IdempotencyKey,
        request_id: UUID,
    ) -> ChangeRequestCommandResult:
        self._require_flags(runtime_environment)
        request = self._requests.get(request_id)
        if (
            request is None
            or request.environment != runtime_environment
            or request.action != CommercialAction.EXECUTION_SCOPE_OVERRIDE
            or request.target_type != "commercial_entitlement_override"
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        return ChangeRequestCommandService(
            self._connection
        ).approve_execution_scope_override(
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            step_up_event_id=step_up_event_id,
            idempotency_key=approval_idempotency_key,
            request_id=request_id,
            now=self._clock(),
        )

    @_atomic
    def execute_safe_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: EntitlementOverrideCommand,
    ) -> EntitlementOverrideResult:
        now = self._clock()
        self._require_safe_authority(operator_user_id, runtime_environment)
        if command.expands_access:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        identity = self.command_identity(runtime_environment, command)
        self._lock_command(str(identity))
        command_id = uuid5(identity, "command")
        replay = self._load_command(command_id, command)
        if replay is not None:
            return replay
        audit_id = uuid5(identity, "audit")
        if command.operation == "revoke":
            assert command.override_id is not None
            current = self._load_override(command)
            if current["effect"] != "allow":
                raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        return self._apply(
            command=command,
            override_id=(
                uuid5(identity, "override")
                if command.operation == "create"
                else command.override_id
            ),
            audit_event_id=audit_id,
            audit_role="entitlement_operator",
            operator_user_id=operator_user_id,
            now=now,
            runtime_environment=runtime_environment,
            command_id=command_id,
        )

    @_atomic
    def execute_approved_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        request_id: UUID,
        command: EntitlementOverrideCommand,
    ) -> EntitlementOverrideResult:
        now = self._clock()
        self._require_flags(runtime_environment)
        identity = self.command_identity(runtime_environment, command)
        self._lock_command(str(identity))
        request = self._requests.get(request_id)
        target_id = self.authority_target(runtime_environment, command)
        if (
            request is None
            or request.environment != runtime_environment
            or request.action != CommercialAction.EXECUTION_SCOPE_OVERRIDE
            or request.target_type != "commercial_entitlement_override"
            or request.target_id != target_id
            or request.payload_sha256 != command.authority_sha256()
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        operator = self._require_admin_step_up(
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            step_up_event_id=step_up_event_id,
            now=now,
        )
        if request.state == "executed":
            return self._replay_executed(request, command)
        if request.state != "approved":
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        command_id = uuid5(identity, "command")
        replay = self._load_command(command_id, command)
        if replay is not None:
            record_change_execution(
                request_id,
                store=self._requests,
                operator=operator,
                succeeded=True,
                result_code="applied",
                audit_event_id=replay.audit_event_id,
                now=now,
            )
            return replay
        if command.operation == "create":
            if not command.expands_access:
                raise ValueError(
                    "bounded deny/limit creation uses the safe override path"
                )
        elif self._load_override(command)["effect"] == "allow":
            raise ValueError("allow revocation uses the safe override path")
        override_id = (
            uuid5(identity, "override")
            if command.operation == "create"
            else command.override_id
        )
        audit_id = uuid5(identity, "audit")
        result = self._apply(
            command=command,
            override_id=override_id,
            audit_event_id=audit_id,
            audit_role="commercial_admin",
            operator_user_id=operator_user_id,
            now=now,
            change_request_id=request_id,
            runtime_environment=runtime_environment,
            command_id=command_id,
        )
        record_change_execution(
            request_id,
            store=self._requests,
            operator=operator,
            succeeded=True,
            result_code="applied",
            audit_event_id=result.audit_event_id,
            now=now,
        )
        return result

    @classmethod
    def authority_target(
        cls, environment: str, command: EntitlementOverrideCommand
    ) -> str:
        identity = cls.command_identity(environment, command)
        override_id = (
            uuid5(identity, "override")
            if command.operation == "create"
            else command.override_id
        )
        return f"{command.operation}:{override_id}"

    @staticmethod
    def idempotency_scope(command: EntitlementOverrideCommand) -> str:
        if command.operation == "revoke":
            return f"override:{command.override_id}"
        return (
            f"account:{command.commercial_account_id}:agreement:{command.agreement_id}"
        )

    @classmethod
    def command_identity(
        cls, environment: str, command: EntitlementOverrideCommand
    ) -> UUID:
        return uuid5(
            NAMESPACE_URL,
            "commercial-entitlement-override:"
            f"{environment}:{command.operation}:{cls.idempotency_scope(command)}:"
            f"{command.idempotency_key}",
        )

    def _apply(
        self,
        *,
        command: EntitlementOverrideCommand,
        override_id: UUID | None,
        audit_event_id: UUID,
        audit_role: Literal["entitlement_operator", "commercial_admin"],
        operator_user_id: int,
        now: datetime,
        change_request_id: UUID | None = None,
        runtime_environment: str,
        command_id: UUID,
    ) -> EntitlementOverrideResult:
        if override_id is None:
            raise ValueError("override identity is required")
        replay = self._load_command(command_id, command)
        if replay is not None:
            return replay
        self._validate_scope(command)
        audit = CommercialAuditEvent(
            event_id=audit_event_id,
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
            actor_type="admin",
            actor_id=str(operator_user_id),
            action=f"commercial.entitlement.override.{command.operation}",
            target_type="commercial_entitlement_override",
            target_id=str(override_id),
            reason_code=command.reason_code,
            after={
                "account_id": command.commercial_account_id,
                "agreement_id": command.agreement_id,
                "content_sha256": command.authority_sha256(),
                "role": audit_role,
                "result_code": "applied"
                if command.operation == "create"
                else "revoked",
            },
        )
        insert_commercial_audit_event(self._connection, audit)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            if command.operation == "create":
                cursor.execute(
                    """
                    INSERT INTO commercial_entitlement_overrides (
                        id, commercial_account_id, agreement_id, surface_code,
                        subject_kind, subject_user_id, source_kind,
                        entitlement_key, effect, value_json, priority,
                        effective_from, effective_until, reason_code, audit_event_id,
                        create_change_request_id, create_authority_sha256
                    ) VALUES (%s, %s, %s, %s, %s, %s, 'admin_override',
                              %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(override_id),
                        command.commercial_account_id,
                        command.agreement_id,
                        command.surface_code,
                        command.subject_kind,
                        command.subject_user_id,
                        command.entitlement_key,
                        command.effect,
                        json.dumps(command.value),
                        command.priority,
                        command.effective_from,
                        command.effective_until,
                        command.reason_code,
                        str(audit_event_id),
                        str(change_request_id) if change_request_id else None,
                        command.authority_sha256() if change_request_id else None,
                    ),
                )
            else:
                cursor.execute(
                    """
                    UPDATE commercial_entitlement_overrides
                       SET revoked_at = %s, revoke_reason_code = %s,
                           revoked_audit_event_id = %s,
                           revoke_change_request_id = %s,
                           revoke_authority_sha256 = %s
                     WHERE id = %s AND revoked_at IS NULL
                    RETURNING id
                    """,
                    (
                        now,
                        command.reason_code,
                        str(audit_event_id),
                        str(change_request_id) if change_request_id else None,
                        command.authority_sha256() if change_request_id else None,
                        str(override_id),
                    ),
                )
                if cursor.fetchone() is None:
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT
                    )
        projection = self._project(command.commercial_account_id, now)
        publish_authority_invalidation(
            self._connection,
            CommercialAuthorityInvalidationCommand(
                environment=self._flags.environment,
                kind="emergency",
                commercial_account_id=command.commercial_account_id,
                entitlement_revision=projection.revision,
            ),
        )
        result = EntitlementOverrideResult(
            override_id=override_id,
            operation=command.operation,
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
            audit_event_id=audit_event_id,
            entitlement_revision=projection.revision,
            projection_changed=projection.changed,
        )
        self._insert_command(
            command_id=command_id,
            environment=runtime_environment,
            command=command,
            result=result,
            actor_user_id=operator_user_id,
            change_request_id=change_request_id,
        )
        return result

    def _require_flags(self, environment: str) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_entitlement_projection_enabled
        ):
            raise ValueError("commercial entitlement override control is disabled")
        if environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        if row is None or row[0] != environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _require_safe_authority(self, user_id: int, environment: str) -> None:
        self._require_flags(environment)
        operator = load_named_operator(
            self._connection, user_id=user_id, environment=environment
        )
        if CommercialRole.ENTITLEMENT_OPERATOR not in operator.roles:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _validate_scope(self, command: EntitlementOverrideCommand) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT status
                  FROM commercial_accounts
                 WHERE id = %s
                 FOR UPDATE
                """,
                (command.commercial_account_id,),
            )
            account = cursor.fetchone()
            cursor.execute(
                """
                SELECT surface_code
                  FROM commercial_agreements
                 WHERE id = %s AND commercial_account_id = %s
                 FOR UPDATE
                """,
                (command.agreement_id, command.commercial_account_id),
            )
            agreement = cursor.fetchone()
        if account is None or account[0] != "active" or agreement is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
        if command.operation == "create" and agreement[0] != command.surface_code:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
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
        if (
            revision is None
            or int(revision[0]) != command.expected_entitlement_revision
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_ENTITLEMENT_VERSION_CONFLICT
            )

    def _require_high_risk(self, command: EntitlementOverrideCommand) -> None:
        if command.operation == "create":
            if not command.expands_access:
                raise ValueError(
                    "bounded deny/limit creation uses the safe override path"
                )
            return
        if self._load_override(command)["effect"] == "allow":
            raise ValueError("allow revocation uses the safe override path")

    def _load_override(self, command: EntitlementOverrideCommand) -> dict[str, object]:
        if command.override_id is None:
            raise ValueError("override identity is required")
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT commercial_account_id, agreement_id, effect, revoked_at
                  FROM commercial_entitlement_overrides WHERE id = %s FOR SHARE
                """,
                (str(command.override_id),),
            )
            row = cursor.fetchone()
        if (
            row is None
            or int(row[0]) != command.commercial_account_id
            or int(row[1]) != command.agreement_id
            or row[3] is not None
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
        return {"effect": row[2]}

    def _load_command(
        self, command_id: UUID, command: EntitlementOverrideCommand
    ) -> EntitlementOverrideResult | None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                SELECT operation, idempotency_scope, idempotency_key,
                       command_sha256, commercial_account_id, agreement_id,
                       override_id, audit_event_id, entitlement_revision,
                       projection_changed
                  FROM commercial_entitlement_override_commands
                 WHERE command_id = %s
                """,
                (str(command_id),),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        expected = (
            command.operation,
            self.idempotency_scope(command),
            command.idempotency_key,
            command.authority_sha256(),
            command.commercial_account_id,
            command.agreement_id,
        )
        if tuple(row[:6]) != expected:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return EntitlementOverrideResult(
            override_id=UUID(str(row[6])),
            operation=command.operation,
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
            audit_event_id=UUID(str(row[7])),
            entitlement_revision=int(row[8]),
            projection_changed=bool(row[9]),
            replayed=True,
        )

    def _insert_command(
        self,
        *,
        command_id: UUID,
        environment: str,
        command: EntitlementOverrideCommand,
        result: EntitlementOverrideResult,
        actor_user_id: int,
        change_request_id: UUID | None,
    ) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                """
                INSERT INTO commercial_entitlement_override_commands (
                    command_id, environment, operation, idempotency_scope,
                    idempotency_key, command_sha256, commercial_account_id,
                    agreement_id, override_id, audit_event_id, change_request_id,
                    actor_user_id, entitlement_revision, projection_changed
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(command_id),
                    environment,
                    command.operation,
                    self.idempotency_scope(command),
                    command.idempotency_key,
                    command.authority_sha256(),
                    command.commercial_account_id,
                    command.agreement_id,
                    str(result.override_id),
                    str(result.audit_event_id),
                    str(change_request_id) if change_request_id else None,
                    actor_user_id,
                    result.entitlement_revision,
                    result.projection_changed,
                ),
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

    def _replay_executed(self, request, command):
        if not request.execution_succeeded or request.audit_event_id is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        identity = self.command_identity(request.environment, command)
        result = self._load_command(
            uuid5(identity, "command"),
            command,
        )
        if result is None or result.audit_event_id != request.audit_event_id:
            raise RuntimeError("executed override request lost its audit evidence")
        return result

    def _run_atomic(self, operation: Callable[[], _ResultT]) -> _ResultT:
        if getattr(self._connection, "autocommit", False):
            raise ValueError(
                "entitlement override commands require autocommit disabled"
            )
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute("SAVEPOINT commercial_entitlement_override")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_entitlement_override")
                cursor.execute("RELEASE SAVEPOINT commercial_entitlement_override")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_entitlement_override")
        return result

    def _lock_command(self, identity: str) -> None:
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"commercial-entitlement-override:{identity}",),
            )

    def _require_admin_step_up(
        self,
        *,
        operator_user_id: int,
        environment: str,
        step_up_event_id: UUID,
        now: datetime,
    ):
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        if CommercialRole.COMMERCIAL_ADMIN not in operator.roles:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        if (
            operator.step_up_verified_at is None
            or operator.step_up_event_id is None
            or not now - timedelta(minutes=15) <= operator.step_up_verified_at <= now
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_STEP_UP_REQUIRED)
        return operator


__all__ = [
    "EntitlementOverrideCommand",
    "EntitlementOverrideResult",
    "EntitlementOverrideService",
]
