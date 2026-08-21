"""Transaction-scoped commercial account and membership operations."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import TypeAdapter

from .accounts import (
    CommercialAccountKind,
    CommercialAccountRecord,
    CommercialAccountState,
    CommercialMemberRole,
    CommercialMembershipRecord,
    CommercialMemberState,
    VisibleCommercialAccount,
)
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import CommercialRole
from .authority_store import load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .models import NonEmptyStr, StableCode


_ACCOUNT_COLUMNS = (
    "id, public_id, kind, display_name, status, billing_currency, display_timezone, "
    "metadata, created_at, updated_at"
)
_MEMBER_COLUMNS = (
    "commercial_account_id, user_id, role, status, joined_at, created_at, updated_at"
)
_DISPLAY_NAME_ADAPTER = TypeAdapter(NonEmptyStr)
_REASON_CODE_ADAPTER = TypeAdapter(StableCode)


def _qualified(columns: str, alias: str) -> str:
    return ", ".join(f"{alias}.{name.strip()}" for name in columns.split(","))


def _mapping(columns: str, row: tuple[Any, ...]) -> dict[str, Any]:
    return dict(zip((name.strip() for name in columns.split(",")), row, strict=True))


def _account(row: tuple[Any, ...]) -> CommercialAccountRecord:
    payload = _mapping(_ACCOUNT_COLUMNS, row)
    payload["public_id"] = UUID(str(payload["public_id"]))
    payload["kind"] = CommercialAccountKind(payload["kind"])
    payload["state"] = CommercialAccountState(payload.pop("status"))
    return CommercialAccountRecord.model_validate(payload)


def _member(row: tuple[Any, ...]) -> CommercialMembershipRecord:
    payload = _mapping(_MEMBER_COLUMNS, row)
    payload["role"] = CommercialMemberRole(payload["role"])
    payload["state"] = CommercialMemberState(payload.pop("status"))
    return CommercialMembershipRecord.model_validate(payload)


class CommercialAccountService:
    """Mutate account facts and audit them in one caller-owned transaction."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def create_account(
        self,
        *,
        authenticated_user_id: int,
        kind: CommercialAccountKind,
        display_name: str,
        reason_code: StableCode,
    ) -> VisibleCommercialAccount:
        return self._create_account(
            owner_user_id=authenticated_user_id,
            actor_type="user",
            actor_id=str(authenticated_user_id),
            kind=kind,
            display_name=display_name,
            reason_code=reason_code,
            command_content_sha256=None,
        )

    def create_account_for_user(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        owner_user_id: int,
        kind: CommercialAccountKind,
        display_name: str,
        reason_code: StableCode,
        command_content_sha256: str | None = None,
    ) -> VisibleCommercialAccount:
        operator = self._resolve_operator(
            operator_user_id=operator_user_id,
            runtime_environment=runtime_environment,
        )
        if CommercialRole.COMMERCIAL_ADMIN not in operator.roles:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        return self._create_account(
            owner_user_id=owner_user_id,
            actor_type="admin",
            actor_id=str(operator.user_id),
            kind=kind,
            display_name=display_name,
            reason_code=reason_code,
            command_content_sha256=command_content_sha256,
        )

    def _create_account(
        self,
        *,
        owner_user_id: int,
        actor_type: str,
        actor_id: str,
        kind: CommercialAccountKind,
        display_name: str,
        reason_code: StableCode,
        command_content_sha256: str | None,
    ) -> VisibleCommercialAccount:
        self._require_transaction()
        display_name = _DISPLAY_NAME_ADAPTER.validate_python(display_name)
        reason_code = _REASON_CODE_ADAPTER.validate_python(reason_code)
        public_id = uuid4()
        cursor = self._connection.cursor()
        try:
            if kind == CommercialAccountKind.INDIVIDUAL:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtext('commercial_individual_account'), %s)",
                    (owner_user_id,),
                )
                cursor.execute(
                    """
                    SELECT 1
                    FROM commercial_accounts AS account
                    JOIN commercial_account_members AS member
                      ON member.commercial_account_id = account.id
                    WHERE account.kind = 'individual' AND account.status <> 'closed'
                      AND member.user_id = %s AND member.role = 'owner'
                      AND member.status = 'active'
                    """,
                    (owner_user_id,),
                )
                if cursor.fetchone() is not None:
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_ACCOUNT_ALREADY_EXISTS
                    )
            cursor.execute(
                f"""
                INSERT INTO commercial_accounts (
                    public_id, kind, display_name, status
                ) VALUES (%s, %s, %s, 'active')
                RETURNING {_ACCOUNT_COLUMNS}
                """,
                (str(public_id), kind.value, display_name),
            )
            account_row = cursor.fetchone()
            cursor.execute(
                f"""
                INSERT INTO commercial_account_members (
                    commercial_account_id, user_id, role, status, joined_at
                ) VALUES (%s, %s, 'owner', 'active', NOW())
                RETURNING {_MEMBER_COLUMNS}
                """,
                (account_row[0], owner_user_id),
            )
            member_row = cursor.fetchone()
        finally:
            cursor.close()
        stored_account = _account(account_row)
        stored_member = _member(member_row)
        after = {
            "account_id": stored_account.id,
            "user_id": owner_user_id,
            "state": "active",
            "account_kind": stored_account.kind.value,
            "member_role": stored_member.role.value,
            "member_state": stored_member.state.value,
            "result_code": "applied",
        }
        if command_content_sha256 is not None:
            after["content_sha256"] = command_content_sha256
        self._audit_as(
            actor_type=actor_type,
            actor_id=actor_id,
            account=stored_account,
            action="commercial.account.create",
            target_type="commercial_account",
            target_id=str(stored_account.public_id),
            reason_code=reason_code,
            after=after,
        )
        return VisibleCommercialAccount(
            account=stored_account,
            membership=stored_member,
        )

    def invite_member(
        self,
        *,
        commercial_account_id: int,
        actor_user_id: int,
        user_id: int,
        role: CommercialMemberRole,
        reason_code: StableCode,
    ) -> CommercialMembershipRecord:
        reason_code = _REASON_CODE_ADAPTER.validate_python(reason_code)
        if role == CommercialMemberRole.OWNER:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE)
        account = self._require_admin(
            commercial_account_id=commercial_account_id,
            actor_user_id=actor_user_id,
        )
        if account.kind != CommercialAccountKind.FIRM:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE)
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                INSERT INTO commercial_account_members (
                    commercial_account_id, user_id, role, status
                ) VALUES (%s, %s, %s, 'invited')
                ON CONFLICT (commercial_account_id, user_id) DO NOTHING
                RETURNING {_MEMBER_COLUMNS}
                """,
                (commercial_account_id, user_id, role.value),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_MEMBER_ALREADY_EXISTS)
        member = _member(row)
        self._audit_membership(
            account=account,
            actor_user_id=actor_user_id,
            user_id=user_id,
            action="commercial.member.invite",
            reason_code=reason_code,
            after={
                "account_id": account.id,
                "user_id": user_id,
                "member_role": member.role.value,
                "member_state": member.state.value,
                "result_code": "applied",
            },
        )
        return member

    def activate_member(
        self,
        *,
        commercial_account_id: int,
        actor_user_id: int,
        user_id: int,
        reason_code: StableCode,
    ) -> CommercialMembershipRecord:
        return self._change_member_state(
            commercial_account_id=commercial_account_id,
            actor_user_id=actor_user_id,
            user_id=user_id,
            reason_code=reason_code,
            expected=CommercialMemberState.INVITED,
            target=CommercialMemberState.ACTIVE,
            action="commercial.member.activate",
            set_joined=True,
        )

    def suspend_member(
        self,
        *,
        commercial_account_id: int,
        actor_user_id: int,
        user_id: int,
        reason_code: StableCode,
    ) -> CommercialMembershipRecord:
        return self._change_member_state(
            commercial_account_id=commercial_account_id,
            actor_user_id=actor_user_id,
            user_id=user_id,
            reason_code=reason_code,
            expected=CommercialMemberState.ACTIVE,
            target=CommercialMemberState.SUSPENDED,
            action="commercial.member.suspend",
            set_joined=False,
        )

    def remove_member(
        self,
        *,
        commercial_account_id: int,
        actor_user_id: int,
        user_id: int,
        reason_code: StableCode,
    ) -> CommercialMembershipRecord:
        return self._change_member_state(
            commercial_account_id=commercial_account_id,
            actor_user_id=actor_user_id,
            user_id=user_id,
            expected=None,
            target=CommercialMemberState.REMOVED,
            action="commercial.member.remove",
            reason_code=reason_code,
            set_joined=False,
        )

    def transfer_ownership(
        self,
        *,
        commercial_account_id: int,
        actor_user_id: int,
        new_owner_user_id: int,
        reason_code: StableCode,
    ) -> tuple[CommercialMembershipRecord, CommercialMembershipRecord]:
        self._require_transaction()
        reason_code = _REASON_CODE_ADAPTER.validate_python(reason_code)
        account, actor = self._load_account_and_actor(
            commercial_account_id, actor_user_id
        )
        if (
            account.state != CommercialAccountState.ACTIVE
            or actor.role != CommercialMemberRole.OWNER
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        if actor_user_id == new_owner_user_id:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE)
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                SELECT {_MEMBER_COLUMNS}
                FROM commercial_account_members
                WHERE commercial_account_id = %s AND user_id IN (%s, %s)
                ORDER BY user_id FOR UPDATE
                """,
                (commercial_account_id, actor_user_id, new_owner_user_id),
            )
            loaded_members = tuple(_member(row) for row in cursor.fetchall())
            members = {member.user_id: member for member in loaded_members}
            target = members.get(new_owner_user_id)
            if target is None or target.state != CommercialMemberState.ACTIVE:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE
                )
            cursor.execute(
                f"""
                UPDATE commercial_account_members
                SET role = 'admin', updated_at = NOW()
                WHERE commercial_account_id = %s AND user_id = %s AND role = 'owner'
                RETURNING {_MEMBER_COLUMNS}
                """,
                (commercial_account_id, actor_user_id),
            )
            previous_owner = _member(cursor.fetchone())
            cursor.execute(
                f"""
                UPDATE commercial_account_members
                SET role = 'owner', updated_at = NOW()
                WHERE commercial_account_id = %s AND user_id = %s
                  AND status = 'active' AND role <> 'owner'
                RETURNING {_MEMBER_COLUMNS}
                """,
                (commercial_account_id, new_owner_user_id),
            )
            new_owner_row = cursor.fetchone()
        finally:
            cursor.close()
        if new_owner_row is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE)
        new_owner = _member(new_owner_row)
        self._audit_membership(
            account=account,
            actor_user_id=actor_user_id,
            user_id=new_owner_user_id,
            action="commercial.account.transfer_ownership",
            reason_code=reason_code,
            before={
                "account_id": account.id,
                "previous_owner_user_id": actor_user_id,
                "new_owner_user_id": new_owner_user_id,
                "previous_owner_role": "owner",
                "new_owner_role": target.role.value,
            },
            after={
                "account_id": account.id,
                "previous_owner_user_id": actor_user_id,
                "new_owner_user_id": new_owner_user_id,
                "previous_owner_role": previous_owner.role.value,
                "new_owner_role": new_owner.role.value,
                "result_code": "applied",
            },
        )
        return previous_owner, new_owner

    def set_account_state(
        self,
        *,
        commercial_account_id: int,
        actor_user_id: int,
        state: CommercialAccountState,
        reason_code: StableCode,
    ) -> CommercialAccountRecord:
        reason_code = _REASON_CODE_ADAPTER.validate_python(reason_code)
        if state == CommercialAccountState.ACTIVE:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE)
        account, actor = self._load_account_and_actor(
            commercial_account_id, actor_user_id
        )
        if (
            actor.role != CommercialMemberRole.OWNER
            or actor.state != CommercialMemberState.ACTIVE
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        allowed = (
            account.state == CommercialAccountState.ACTIVE
            and state
            in {CommercialAccountState.SUSPENDED, CommercialAccountState.CLOSED}
        ) or (
            account.state == CommercialAccountState.SUSPENDED
            and state == CommercialAccountState.CLOSED
        )
        if not allowed:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_INACTIVE)
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                UPDATE commercial_accounts
                SET status = %s, updated_at = NOW()
                WHERE id = %s AND status = %s
                RETURNING {_ACCOUNT_COLUMNS}
                """,
                (state.value, commercial_account_id, account.state.value),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_INACTIVE)
        updated = _account(row)
        self._audit(
            actor_user_id=actor_user_id,
            account=updated,
            action=f"commercial.account.{state.value}",
            target_type="commercial_account",
            target_id=str(updated.public_id),
            reason_code=reason_code,
            before={"account_id": account.id, "state": account.state.value},
            after={"account_id": updated.id, "state": state.value},
        )
        return updated

    def list_visible_accounts(
        self, *, user_id: int
    ) -> tuple[VisibleCommercialAccount, ...]:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                SELECT {_qualified(_ACCOUNT_COLUMNS, "account")},
                       {_qualified(_MEMBER_COLUMNS, "member")}
                FROM commercial_accounts AS account
                JOIN commercial_account_members AS member
                  ON member.commercial_account_id = account.id
                WHERE member.user_id = %s AND member.status <> 'removed'
                ORDER BY account.id
                """,
                (user_id,),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        account_count = len(_ACCOUNT_COLUMNS.split(","))
        return tuple(
            VisibleCommercialAccount(
                account=_account(row[:account_count]),
                membership=_member(row[account_count:]),
            )
            for row in rows
        )

    def list_accounts_for_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
    ) -> tuple[CommercialAccountRecord, ...]:
        operator = self._resolve_operator(
            operator_user_id=operator_user_id,
            runtime_environment=runtime_environment,
        )
        if not operator.roles.intersection(
            {CommercialRole.COMMERCIAL_VIEWER, CommercialRole.COMMERCIAL_ADMIN}
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"SELECT {_ACCOUNT_COLUMNS} FROM commercial_accounts ORDER BY id"
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        return tuple(_account(row) for row in rows)

    def _change_member_state(
        self,
        *,
        commercial_account_id: int,
        actor_user_id: int,
        user_id: int,
        expected: CommercialMemberState | None,
        target: CommercialMemberState,
        action: str,
        reason_code: StableCode,
        set_joined: bool,
    ) -> CommercialMembershipRecord:
        reason_code = _REASON_CODE_ADAPTER.validate_python(reason_code)
        account = self._require_admin(
            commercial_account_id=commercial_account_id,
            actor_user_id=actor_user_id,
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"SELECT {_MEMBER_COLUMNS} FROM commercial_account_members "
                "WHERE commercial_account_id = %s AND user_id = %s FOR UPDATE",
                (commercial_account_id, user_id),
            )
            current_row = cursor.fetchone()
            if current_row is None:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE
                )
            current = _member(current_row)
            if current.role == CommercialMemberRole.OWNER:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE
                )
            if expected is not None and current.state != expected:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE
                )
            if expected is None and current.state == CommercialMemberState.REMOVED:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE
                )
            cursor.execute(
                f"""
                UPDATE commercial_account_members
                SET status = %s,
                    joined_at = CASE WHEN %s THEN NOW() ELSE joined_at END,
                    updated_at = NOW()
                WHERE commercial_account_id = %s AND user_id = %s AND status = %s
                RETURNING {_MEMBER_COLUMNS}
                """,
                (
                    target.value,
                    set_joined,
                    commercial_account_id,
                    user_id,
                    current.state.value,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE)
        updated = _member(row)
        before = {
            "account_id": account.id,
            "user_id": user_id,
            "member_role": current.role.value,
            "member_state": current.state.value,
        }
        facts: dict[str, Any] = {
            "account_id": account.id,
            "user_id": user_id,
            "member_role": updated.role.value,
            "member_state": updated.state.value,
            "result_code": "revoked"
            if target == CommercialMemberState.REMOVED
            else "applied",
        }
        self._audit_membership(
            account=account,
            actor_user_id=actor_user_id,
            user_id=user_id,
            action=action,
            reason_code=reason_code,
            before=before,
            after=facts,
        )
        return updated

    def _require_admin(
        self, *, commercial_account_id: int, actor_user_id: int
    ) -> CommercialAccountRecord:
        account, actor = self._load_account_and_actor(
            commercial_account_id, actor_user_id
        )
        if account.state != CommercialAccountState.ACTIVE:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_INACTIVE)
        if actor.state != CommercialMemberState.ACTIVE or actor.role not in {
            CommercialMemberRole.OWNER,
            CommercialMemberRole.ADMIN,
        }:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        return account

    def _load_account_and_actor(
        self, commercial_account_id: int, actor_user_id: int
    ) -> tuple[CommercialAccountRecord, CommercialMembershipRecord]:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"SELECT {_ACCOUNT_COLUMNS} FROM commercial_accounts WHERE id = %s FOR UPDATE",
                (commercial_account_id,),
            )
            account_row = cursor.fetchone()
            if account_row is None:
                raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
            cursor.execute(
                f"SELECT {_MEMBER_COLUMNS} FROM commercial_account_members "
                "WHERE commercial_account_id = %s AND user_id = %s FOR UPDATE",
                (commercial_account_id, actor_user_id),
            )
            actor_row = cursor.fetchone()
        finally:
            cursor.close()
        if actor_row is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED)
        return _account(account_row), _member(actor_row)

    def _audit_membership(
        self,
        *,
        account: CommercialAccountRecord,
        actor_user_id: int,
        user_id: int,
        action: str,
        reason_code: StableCode,
        after: dict[str, Any],
        before: dict[str, Any] | None = None,
    ) -> None:
        self._audit(
            actor_user_id=actor_user_id,
            account=account,
            action=action,
            target_type="commercial_account_member",
            target_id=f"{account.id}:{user_id}",
            reason_code=reason_code,
            before=before,
            after=after,
        )

    def _audit(
        self,
        *,
        actor_user_id: int,
        account: CommercialAccountRecord,
        action: str,
        target_type: str,
        target_id: str,
        reason_code: StableCode,
        after: dict[str, Any],
        before: dict[str, Any] | None = None,
    ) -> None:
        self._audit_as(
            actor_type="user",
            actor_id=str(actor_user_id),
            account=account,
            action=action,
            target_type=target_type,
            target_id=target_id,
            reason_code=reason_code,
            before=before,
            after=after,
        )

    def _audit_as(
        self,
        *,
        actor_type: str,
        actor_id: str,
        account: CommercialAccountRecord,
        action: str,
        target_type: str,
        target_id: str,
        reason_code: StableCode,
        after: dict[str, Any],
        before: dict[str, Any] | None = None,
    ) -> None:
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                commercial_account_id=account.id,
                actor_type=actor_type,
                actor_id=actor_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                reason_code=reason_code,
                before=before,
                after=after,
            ),
        )

    def _resolve_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
    ):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None or row[0] != runtime_environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        return load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=runtime_environment,
        )

    def _require_transaction(self) -> None:
        if getattr(self._connection, "autocommit", False):
            raise ValueError("commercial account mutations require autocommit disabled")


__all__ = ["CommercialAccountService"]
