"""PostgreSQL compare-and-swap adapter for commercial change requests."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from .authority import (
    CommercialAction,
    CommercialChangeRequestV1,
    CommercialRole,
    NamedOperator,
)


_COLUMNS = (
    "request_id, schema_version, version, action, environment, target_type, "
    "target_id, payload_sha256, reason_code, requester_user_id, required_role, "
    "requester_step_up_at, requester_step_up_event_id, requested_at, expires_at, "
    "state, approver_user_id, approved_at, approver_step_up_at, "
    "approver_step_up_event_id, execution_succeeded, execution_result_code, "
    "executed_at, executor_user_id, executor_step_up_at, executor_step_up_event_id, "
    "audit_event_id"
)


def _row_to_request(row: tuple[Any, ...]) -> CommercialChangeRequestV1:
    names = [item.strip() for item in _COLUMNS.split(",")]
    payload = dict(zip(names, row, strict=True))
    payload["request_id"] = UUID(str(payload["request_id"]))
    payload["action"] = CommercialAction(payload["action"])
    payload["required_role"] = CommercialRole(payload["required_role"])
    for field in (
        "requester_step_up_event_id",
        "approver_step_up_event_id",
        "executor_step_up_event_id",
        "audit_event_id",
    ):
        if payload[field] is not None:
            payload[field] = UUID(str(payload[field]))
    return CommercialChangeRequestV1.model_validate(payload)


class PostgresChangeRequestStore:
    """Transaction-scoped store; the caller owns commit and rollback."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def create_pending(self, request: CommercialChangeRequestV1) -> None:
        if request.state != "pending" or request.version != 1:
            raise ValueError("PostgreSQL store accepts only new pending requests")
        cursor = self._connection.cursor()
        try:
            placeholders = ", ".join("%s" for _column in _COLUMNS.split(","))
            cursor.execute(
                f"INSERT INTO commercial_change_requests ({_COLUMNS}) "
                f"VALUES ({placeholders})",
                self._params(request),
            )
        finally:
            cursor.close()

    def get(self, request_id: UUID) -> CommercialChangeRequestV1 | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"SELECT {_COLUMNS} FROM commercial_change_requests WHERE request_id = %s",
                (str(request_id),),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else _row_to_request(row)

    def compare_and_swap(
        self,
        *,
        expected: CommercialChangeRequestV1,
        updated: CommercialChangeRequestV1,
    ) -> bool:
        if updated.request_id != expected.request_id:
            raise ValueError("CAS cannot change request identity")
        if updated.version != expected.version + 1:
            raise ValueError("CAS version must advance by one")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE commercial_change_requests
                SET version = %s, state = %s,
                    approver_user_id = %s, approved_at = %s,
                    approver_step_up_at = %s, approver_step_up_event_id = %s,
                    execution_succeeded = %s, execution_result_code = %s,
                    executed_at = %s, executor_user_id = %s,
                    executor_step_up_at = %s, executor_step_up_event_id = %s,
                    audit_event_id = %s
                WHERE request_id = %s AND version = %s AND state = %s
                RETURNING request_id
                """,
                (
                    updated.version,
                    updated.state,
                    updated.approver_user_id,
                    updated.approved_at,
                    updated.approver_step_up_at,
                    str(updated.approver_step_up_event_id)
                    if updated.approver_step_up_event_id
                    else None,
                    updated.execution_succeeded,
                    updated.execution_result_code,
                    updated.executed_at,
                    updated.executor_user_id,
                    updated.executor_step_up_at,
                    str(updated.executor_step_up_event_id)
                    if updated.executor_step_up_event_id
                    else None,
                    str(updated.audit_event_id) if updated.audit_event_id else None,
                    str(expected.request_id),
                    expected.version,
                    expected.state,
                ),
            )
            return cursor.fetchone() is not None
        finally:
            cursor.close()

    @staticmethod
    def _params(request: CommercialChangeRequestV1) -> tuple[Any, ...]:
        return (
            str(request.request_id),
            request.schema_version,
            request.version,
            request.action.value,
            request.environment,
            request.target_type,
            request.target_id,
            request.payload_sha256,
            request.reason_code,
            request.requester_user_id,
            request.required_role.value,
            request.requester_step_up_at,
            str(request.requester_step_up_event_id)
            if request.requester_step_up_event_id
            else None,
            request.requested_at,
            request.expires_at,
            request.state,
            request.approver_user_id,
            request.approved_at,
            request.approver_step_up_at,
            str(request.approver_step_up_event_id)
            if request.approver_step_up_event_id
            else None,
            request.execution_succeeded,
            request.execution_result_code,
            request.executed_at,
            request.executor_user_id,
            request.executor_step_up_at,
            str(request.executor_step_up_event_id)
            if request.executor_step_up_event_id
            else None,
            str(request.audit_event_id) if request.audit_event_id else None,
        )


def load_named_operator(
    connection: Any,
    *,
    user_id: int,
    environment: str,
    step_up_event_id: UUID | None = None,
) -> NamedOperator:
    """Resolve current roles for an already-authenticated named user; never read tier."""

    cursor = connection.cursor()
    try:
        step_up_verified_at = None
        if step_up_event_id is not None:
            cursor.execute(
                """
                SELECT verified_at
                FROM commercial_operator_step_up_events
                WHERE event_id = %s AND user_id = %s
                  AND verified_at <= NOW() AND expires_at > NOW()
                FOR SHARE
                """,
                (str(step_up_event_id), user_id),
            )
            evidence = cursor.fetchone()
            if evidence is not None:
                step_up_verified_at = evidence[0]
        cursor.execute(
            """
            SELECT role
            FROM commercial_operator_role_grants
            WHERE user_id = %s AND environment = %s AND state = 'active'
              AND granted_at <= NOW()
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY role
            FOR SHARE
            """,
            (user_id, environment),
        )
        roles = frozenset(CommercialRole(row[0]) for row in cursor.fetchall())
    finally:
        cursor.close()
    return NamedOperator(
        user_id=user_id,
        roles=roles,
        step_up_verified_at=step_up_verified_at,
        step_up_event_id=step_up_event_id if step_up_verified_at is not None else None,
    )


__all__ = ["PostgresChangeRequestStore", "load_named_operator"]
