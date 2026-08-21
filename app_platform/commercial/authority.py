"""Named-operator authority and maker-checker change-request semantics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import StrEnum
from threading import Lock
from types import MappingProxyType
from typing import Annotated, Literal, Mapping, Protocol
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    model_validator,
)

from .errors import CommercialError, CommercialErrorCode
from .models import (
    NonEmptyStr,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
)


class CommercialRole(StrEnum):
    COMMERCIAL_VIEWER = "commercial_viewer"
    BILLING_OPERATOR = "billing_operator"
    ENTITLEMENT_OPERATOR = "entitlement_operator"
    COMMERCIAL_ADMIN = "commercial_admin"


class CommercialAction(StrEnum):
    VIEW = "commercial_view"
    MANUAL_BILLING_FACT = "manual_billing_fact"
    REFUND_CREDIT_PROPOSAL = "refund_credit_proposal"
    SAFE_ENTITLEMENT_CHANGE = "safe_entitlement_change"
    TOKEN_INCIDENT_RESPONSE = "token_incident_response"
    ACCOUNT_AGREEMENT_ADMIN = "account_agreement_admin"
    MANUAL_AGREEMENT_ACTIVATION = "manual_agreement_activation"
    BUDGET_INCREASE = "budget_increase"
    PAYER_SWITCH = "payer_switch"
    EXECUTION_SCOPE_OVERRIDE = "execution_scope_override"
    LIVE_POLICY_ACTIVATION = "live_policy_activation"
    LIVE_STRIPE_REPAIR = "live_stripe_repair"


class ActionAuthority(StrictCommercialModel):
    required_role: CommercialRole
    step_up_required: StrictBool
    maker_checker_in_production: StrictBool


ACTION_AUTHORITY: Mapping[CommercialAction, ActionAuthority] = MappingProxyType(
    {
        CommercialAction.VIEW: ActionAuthority(
            required_role=CommercialRole.COMMERCIAL_VIEWER,
            step_up_required=False,
            maker_checker_in_production=False,
        ),
        CommercialAction.MANUAL_BILLING_FACT: ActionAuthority(
            required_role=CommercialRole.BILLING_OPERATOR,
            step_up_required=False,
            maker_checker_in_production=False,
        ),
        CommercialAction.REFUND_CREDIT_PROPOSAL: ActionAuthority(
            required_role=CommercialRole.BILLING_OPERATOR,
            step_up_required=False,
            maker_checker_in_production=False,
        ),
        CommercialAction.SAFE_ENTITLEMENT_CHANGE: ActionAuthority(
            required_role=CommercialRole.ENTITLEMENT_OPERATOR,
            step_up_required=False,
            maker_checker_in_production=False,
        ),
        CommercialAction.TOKEN_INCIDENT_RESPONSE: ActionAuthority(
            required_role=CommercialRole.ENTITLEMENT_OPERATOR,
            step_up_required=False,
            maker_checker_in_production=False,
        ),
        CommercialAction.ACCOUNT_AGREEMENT_ADMIN: ActionAuthority(
            required_role=CommercialRole.COMMERCIAL_ADMIN,
            step_up_required=False,
            maker_checker_in_production=False,
        ),
        CommercialAction.MANUAL_AGREEMENT_ACTIVATION: ActionAuthority(
            required_role=CommercialRole.COMMERCIAL_ADMIN,
            step_up_required=True,
            maker_checker_in_production=True,
        ),
        CommercialAction.BUDGET_INCREASE: ActionAuthority(
            required_role=CommercialRole.COMMERCIAL_ADMIN,
            step_up_required=True,
            maker_checker_in_production=True,
        ),
        CommercialAction.PAYER_SWITCH: ActionAuthority(
            required_role=CommercialRole.COMMERCIAL_ADMIN,
            step_up_required=True,
            maker_checker_in_production=True,
        ),
        CommercialAction.EXECUTION_SCOPE_OVERRIDE: ActionAuthority(
            required_role=CommercialRole.COMMERCIAL_ADMIN,
            step_up_required=True,
            maker_checker_in_production=True,
        ),
        CommercialAction.LIVE_POLICY_ACTIVATION: ActionAuthority(
            required_role=CommercialRole.COMMERCIAL_ADMIN,
            step_up_required=True,
            maker_checker_in_production=True,
        ),
        CommercialAction.LIVE_STRIPE_REPAIR: ActionAuthority(
            required_role=CommercialRole.BILLING_OPERATOR,
            step_up_required=True,
            maker_checker_in_production=True,
        ),
    }
)


class NamedOperator(StrictCommercialModel):
    user_id: Annotated[int, Field(gt=0)]
    roles: frozenset[CommercialRole]
    step_up_verified_at: AwareDatetime | None = None
    step_up_event_id: UUID | None = None


class CommercialChangeRequestV1(StrictCommercialModel):
    schema_version: Literal[1] = 1
    version: Annotated[int, Field(gt=0)] = 1
    request_id: UUID
    action: CommercialAction
    environment: Literal["dev", "staging", "prod"]
    target_type: StableCode
    target_id: NonEmptyStr
    payload_sha256: Sha256Digest
    reason_code: StableCode
    requester_user_id: Annotated[int, Field(gt=0)]
    required_role: CommercialRole
    requester_step_up_at: AwareDatetime | None = None
    requester_step_up_event_id: UUID | None = None
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    state: Literal["pending", "approved", "executed"] = "pending"
    approver_user_id: Annotated[int, Field(gt=0)] | None = None
    approved_at: AwareDatetime | None = None
    approver_step_up_at: AwareDatetime | None = None
    approver_step_up_event_id: UUID | None = None
    execution_succeeded: StrictBool | None = None
    execution_result_code: StableCode | None = None
    executed_at: AwareDatetime | None = None
    executor_user_id: Annotated[int, Field(gt=0)] | None = None
    executor_step_up_at: AwareDatetime | None = None
    executor_step_up_event_id: UUID | None = None
    audit_event_id: UUID | None = None

    @model_validator(mode="after")
    def _validate_state(self) -> "CommercialChangeRequestV1":
        authority = ACTION_AUTHORITY[self.action]
        if self.required_role != authority.required_role:
            raise ValueError("required role must match the action authority policy")
        if self.expires_at <= self.requested_at:
            raise ValueError("change request expiry must follow request time")
        approval = (self.approver_user_id, self.approved_at)
        execution = (
            self.execution_succeeded,
            self.execution_result_code,
            self.executed_at,
            self.executor_user_id,
            self.audit_event_id,
        )
        if authority.step_up_required and (
            self.requester_step_up_at is None or self.requester_step_up_event_id is None
        ):
            raise ValueError("high-risk requests require requester step-up evidence")
        if authority.step_up_required and not (
            self.requested_at - timedelta(minutes=15)
            <= self.requester_step_up_at
            <= self.requested_at
        ):
            raise ValueError("requester step-up evidence is outside the allowed window")
        if self.state == "pending" and any(
            value is not None for value in (*approval, *execution)
        ):
            raise ValueError(
                "pending requests cannot contain approval or execution facts"
            )
        if self.state == "pending" and (
            self.approver_step_up_at is not None
            or self.approver_step_up_event_id is not None
            or self.executor_step_up_at is not None
            or self.executor_step_up_event_id is not None
        ):
            raise ValueError("pending requests cannot contain later step-up evidence")
        if self.state in {"approved", "executed"} and any(
            value is None for value in approval
        ):
            raise ValueError("approved requests require approver and approval time")
        if self.approved_at is not None and not (
            self.requested_at <= self.approved_at < self.expires_at
        ):
            raise ValueError("approval time must follow request and precede expiry")
        if authority.step_up_required and self.state in {"approved", "executed"}:
            if (
                self.approver_step_up_at is None
                or self.approver_step_up_event_id is None
            ):
                raise ValueError("high-risk approval requires step-up evidence")
            if not (
                self.approved_at - timedelta(minutes=15)
                <= self.approver_step_up_at
                <= self.approved_at
            ):
                raise ValueError(
                    "approver step-up evidence is outside the allowed window"
                )
        if (
            self.state in {"approved", "executed"}
            and authority.maker_checker_in_production
            and self.environment == "prod"
            and self.approver_user_id == self.requester_user_id
        ):
            raise ValueError("production maker and checker must be different users")
        if self.state == "approved" and any(value is not None for value in execution):
            raise ValueError("approved requests cannot contain execution facts")
        if self.state == "approved" and self.executor_step_up_at is not None:
            raise ValueError(
                "approved requests cannot contain executor step-up evidence"
            )
        if self.state == "approved" and self.executor_step_up_event_id is not None:
            raise ValueError(
                "approved requests cannot contain executor step-up evidence"
            )
        if self.state == "executed" and any(value is None for value in execution):
            raise ValueError("executed requests require result and audit facts")
        if authority.step_up_required and self.state == "executed":
            if (
                self.executor_step_up_at is None
                or self.executor_step_up_event_id is None
            ):
                raise ValueError("high-risk execution requires step-up evidence")
            if not (
                self.executed_at - timedelta(minutes=15)
                <= self.executor_step_up_at
                <= self.executed_at
            ):
                raise ValueError(
                    "executor step-up evidence is outside the allowed window"
                )
        if self.executed_at is not None and (
            self.approved_at is None
            or not (self.approved_at <= self.executed_at < self.expires_at)
        ):
            raise ValueError("execution time must follow approval and precede expiry")
        return self


class ChangeRequestStore(Protocol):
    def create_pending(self, request: CommercialChangeRequestV1) -> None: ...

    def get(self, request_id: UUID) -> CommercialChangeRequestV1 | None: ...

    def compare_and_swap(
        self,
        *,
        expected: CommercialChangeRequestV1,
        updated: CommercialChangeRequestV1,
    ) -> bool: ...


class InMemoryChangeRequestStore:
    """Thread-safe C0 proof adapter; C1 supplies the durable PostgreSQL store."""

    def __init__(self) -> None:
        self._records: dict[UUID, CommercialChangeRequestV1] = {}
        self._lock = Lock()

    def create_pending(self, request: CommercialChangeRequestV1) -> None:
        if request.state != "pending" or request.version != 1:
            raise ValueError("store accepts only new pending change requests")
        with self._lock:
            if request.request_id in self._records:
                raise ValueError("duplicate commercial change request")
            self._records[request.request_id] = request

    def get(self, request_id: UUID) -> CommercialChangeRequestV1 | None:
        with self._lock:
            return self._records.get(request_id)

    def compare_and_swap(
        self,
        *,
        expected: CommercialChangeRequestV1,
        updated: CommercialChangeRequestV1,
    ) -> bool:
        with self._lock:
            current = self._records.get(expected.request_id)
            if current != expected or updated.version != expected.version + 1:
                return False
            self._records[expected.request_id] = updated
            return True


def _require_authority(
    operator: NamedOperator, action: CommercialAction, now: datetime
) -> ActionAuthority:
    authority = ACTION_AUTHORITY[action]
    if authority.required_role not in operator.roles:
        raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
    if authority.step_up_required and (
        operator.step_up_verified_at is None
        or operator.step_up_event_id is None
        or operator.step_up_verified_at < now - timedelta(minutes=15)
        or operator.step_up_verified_at > now
    ):
        raise CommercialError(CommercialErrorCode.COMMERCIAL_STEP_UP_REQUIRED)
    return authority


def create_change_request(
    *,
    store: ChangeRequestStore,
    operator: NamedOperator,
    action: CommercialAction,
    environment: Literal["dev", "staging", "prod"],
    target_type: StableCode,
    target_id: str,
    payload_sha256: Sha256Digest,
    reason_code: StableCode,
    expires_at: datetime,
    now: datetime | None = None,
) -> CommercialChangeRequestV1:
    checked_at = now or datetime.now(timezone.utc)
    authority = _require_authority(operator, action, checked_at)
    if expires_at <= checked_at:
        raise ValueError("change request expiry must be in the future")
    request = CommercialChangeRequestV1(
        request_id=uuid4(),
        action=action,
        environment=environment,
        target_type=target_type,
        target_id=target_id,
        payload_sha256=payload_sha256,
        reason_code=reason_code,
        requester_user_id=operator.user_id,
        required_role=authority.required_role,
        requester_step_up_at=operator.step_up_verified_at,
        requester_step_up_event_id=operator.step_up_event_id,
        requested_at=checked_at,
        expires_at=expires_at,
    )
    store.create_pending(request)
    return request


def approve_change_request(
    request_id: UUID,
    *,
    store: ChangeRequestStore,
    operator: NamedOperator,
    now: datetime | None = None,
) -> CommercialChangeRequestV1:
    checked_at = now or datetime.now(timezone.utc)
    request = store.get(request_id)
    if request is None:
        raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
    if request.state != "pending":
        raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
    if request.expires_at <= checked_at:
        raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_EXPIRED)
    authority = _require_authority(operator, request.action, checked_at)
    if (
        authority.maker_checker_in_production
        and request.environment == "prod"
        and operator.user_id == request.requester_user_id
    ):
        raise CommercialError(CommercialErrorCode.COMMERCIAL_MAKER_CHECKER_REQUIRED)
    approved = CommercialChangeRequestV1.model_validate(
        {
            **request.model_dump(mode="python"),
            "version": request.version + 1,
            "state": "approved",
            "approver_user_id": operator.user_id,
            "approved_at": checked_at,
            "approver_step_up_at": operator.step_up_verified_at,
            "approver_step_up_event_id": operator.step_up_event_id,
        }
    )
    if not store.compare_and_swap(expected=request, updated=approved):
        raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
    return approved


def record_change_execution(
    request_id: UUID,
    *,
    store: ChangeRequestStore,
    operator: NamedOperator,
    succeeded: bool,
    result_code: StableCode,
    audit_event_id: UUID,
    now: datetime | None = None,
) -> CommercialChangeRequestV1:
    checked_at = now or datetime.now(timezone.utc)
    request = store.get(request_id)
    if request is None:
        raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
    if request.state != "approved":
        raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
    if request.expires_at <= checked_at:
        raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_EXPIRED)
    _require_authority(operator, request.action, checked_at)
    executed = CommercialChangeRequestV1.model_validate(
        {
            **request.model_dump(mode="python"),
            "version": request.version + 1,
            "state": "executed",
            "execution_succeeded": succeeded,
            "execution_result_code": result_code,
            "executed_at": checked_at,
            "executor_user_id": operator.user_id,
            "executor_step_up_at": operator.step_up_verified_at,
            "executor_step_up_event_id": operator.step_up_event_id,
            "audit_event_id": audit_event_id,
        }
    )
    if not store.compare_and_swap(expected=request, updated=executed):
        raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
    return executed


__all__ = [
    "ACTION_AUTHORITY",
    "ActionAuthority",
    "CommercialAction",
    "CommercialChangeRequestV1",
    "CommercialRole",
    "ChangeRequestStore",
    "InMemoryChangeRequestStore",
    "NamedOperator",
    "approve_change_request",
    "create_change_request",
    "record_change_execution",
]
