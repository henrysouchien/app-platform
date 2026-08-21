"""Durably idempotent named-operator commercial account creation."""

from __future__ import annotations

from functools import wraps
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import Field, StrictBool

from .account_service import CommercialAccountService
from .accounts import CommercialAccountKind, CommercialAccountState
from .agreement_lifecycle import IdempotencyKey
from .errors import CommercialError, CommercialErrorCode
from .authority import CommercialRole
from .authority_store import load_named_operator
from .models import NonEmptyStr, StableCode, StrictCommercialModel, canonical_sha256


class AccountCreateCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    owner_user_id: Annotated[int, Field(gt=0)]
    kind: CommercialAccountKind
    display_name: NonEmptyStr
    reason_code: StableCode


class AccountCommandResult(StrictCommercialModel):
    command_id: UUID
    commercial_account_id: Annotated[int, Field(gt=0)]
    public_id: UUID
    owner_user_id: Annotated[int, Field(gt=0)]
    kind: CommercialAccountKind
    display_name: NonEmptyStr
    state: CommercialAccountState
    billing_currency: str
    display_timezone: NonEmptyStr
    audit_event_id: UUID
    replayed: StrictBool = False


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class AccountCommandService:
    def __init__(self, connection) -> None:
        self._connection = connection

    @_atomic
    def create_account(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        command: AccountCreateCommand,
    ) -> AccountCommandResult:
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "create_account",
                "environment": environment,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
            }
        )
        self._require_operator(operator_user_id, environment)
        self._lock(command.owner_user_id, environment, command.idempotency_key)
        replay = self._load(
            command.owner_user_id,
            environment,
            command.idempotency_key,
            payload_sha256,
        )
        if replay is not None:
            return replay
        visible = CommercialAccountService(self._connection).create_account_for_user(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            owner_user_id=command.owner_user_id,
            kind=command.kind,
            display_name=command.display_name,
            reason_code=command.reason_code,
            command_content_sha256=payload_sha256,
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT event_id FROM commercial_audit_log
                 WHERE commercial_account_id = %s
                   AND actor_type = 'admin' AND actor_id = %s
                   AND action = 'commercial.account.create'
                   AND target_id = %s
                 ORDER BY id DESC LIMIT 1
                """,
                (
                    visible.account.id,
                    str(operator_user_id),
                    str(visible.account.public_id),
                ),
            )
            audit_row = cursor.fetchone()
        finally:
            cursor.close()
        if audit_row is None:
            raise RuntimeError("account creation did not produce audit evidence")
        result = AccountCommandResult(
            command_id=uuid4(),
            commercial_account_id=visible.account.id,
            public_id=visible.account.public_id,
            owner_user_id=visible.membership.user_id,
            kind=visible.account.kind,
            display_name=visible.account.display_name,
            state=visible.account.state,
            billing_currency=visible.account.billing_currency,
            display_timezone=visible.account.display_timezone,
            audit_event_id=UUID(str(audit_row[0])),
        )
        self._insert(
            result=result,
            operator_user_id=operator_user_id,
            environment=environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        return result

    def _require_operator(self, operator_user_id, environment):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            deployment = cursor.fetchone()
        finally:
            cursor.close()
        operator = load_named_operator(
            self._connection, user_id=operator_user_id, environment=environment
        )
        if (
            deployment is None
            or deployment[0] != environment
            or CommercialRole.COMMERCIAL_ADMIN not in operator.roles
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _lock(self, owner_user_id, environment, key):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                (owner_user_id, f"{environment}:create_account:{key}"),
            )
        finally:
            cursor.close()

    def _load(self, owner_user_id, environment, key, payload):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT command_id, payload_sha256, commercial_account_id,
                       result_public_id, owner_user_id, result_kind,
                       result_display_name, result_state, result_billing_currency,
                       result_display_timezone, audit_event_id
                  FROM commercial_account_commands
                 WHERE owner_user_id = %s AND environment = %s
                   AND idempotency_key = %s
                """,
                (owner_user_id, environment, key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[1] != payload:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return AccountCommandResult(
            command_id=UUID(str(row[0])),
            commercial_account_id=row[2],
            public_id=UUID(str(row[3])),
            owner_user_id=row[4],
            kind=row[5],
            display_name=row[6],
            state=row[7],
            billing_currency=row[8],
            display_timezone=row[9],
            audit_event_id=UUID(str(row[10])),
            replayed=True,
        )

    def _insert(self, *, result, operator_user_id, environment, idempotency_key, payload_sha256):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO commercial_account_commands (
                    command_id, environment, idempotency_key, payload_sha256,
                    actor_user_id, owner_user_id, commercial_account_id,
                    result_public_id, result_kind, result_display_name,
                    result_state, result_billing_currency, result_display_timezone,
                    audit_event_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(result.command_id), environment, idempotency_key,
                    payload_sha256, operator_user_id, result.owner_user_id,
                    result.commercial_account_id, str(result.public_id),
                    result.kind.value, result.display_name, result.state.value,
                    result.billing_currency, result.display_timezone,
                    str(result.audit_event_id),
                ),
            )
        finally:
            cursor.close()

    def _run_atomic(self, operation):
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("account commands require a transaction")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_account_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_account_command")
                cursor.execute("RELEASE SAVEPOINT commercial_account_command")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_account_command")
            return result
        finally:
            cursor.close()


__all__ = ["AccountCommandResult", "AccountCommandService", "AccountCreateCommand"]
