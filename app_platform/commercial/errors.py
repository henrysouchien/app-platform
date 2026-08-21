"""Stable, safe error contracts for the commercial control plane."""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class CommercialErrorCode(StrEnum):
    """Machine-readable codes shared with customer and service clients."""

    COMMERCIAL_AGREEMENT_REQUIRED = "commercial_agreement_required"
    COMMERCIAL_AGREEMENT_INACTIVE = "commercial_agreement_inactive"
    ENTITLEMENT_REQUIRED = "entitlement_required"
    TOKEN_INVALID = "token_invalid"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_SCOPE_DENIED = "token_scope_denied"
    TOOL_NOT_EXPOSED = "tool_not_exposed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    BUDGET_SOFT_LIMIT = "budget_soft_limit"
    BUDGET_HARD_LIMIT = "budget_hard_limit"
    BUDGET_SERVICE_UNAVAILABLE = "budget_service_unavailable"
    UNKNOWN_RATE_VERSION = "unknown_rate_version"
    PROVIDER_COST_IDENTITY_MISSING = "provider_cost_identity_missing"
    FUNDING_ROUTE_MISMATCH = "funding_route_mismatch"
    USAGE_EVENT_CONFLICT = "usage_event_conflict"
    RESERVATION_LINEAGE_MISSING = "reservation_lineage_missing"
    BILLING_SYNC_PENDING = "billing_sync_pending"
    COMMERCIAL_ROLE_REQUIRED = "commercial_role_required"
    COMMERCIAL_STEP_UP_REQUIRED = "commercial_step_up_required"
    COMMERCIAL_APPROVAL_REQUIRED = "commercial_approval_required"
    COMMERCIAL_APPROVAL_EXPIRED = "commercial_approval_expired"
    COMMERCIAL_MAKER_CHECKER_REQUIRED = "commercial_maker_checker_required"
    COMMERCIAL_ACCOUNT_NOT_FOUND = "commercial_account_not_found"
    COMMERCIAL_ACCOUNT_ACCESS_DENIED = "commercial_account_access_denied"
    COMMERCIAL_ACCOUNT_INACTIVE = "commercial_account_inactive"
    COMMERCIAL_ACCOUNT_ALREADY_EXISTS = "commercial_account_already_exists"
    COMMERCIAL_MEMBER_INVALID_STATE = "commercial_member_invalid_state"
    COMMERCIAL_MEMBER_ALREADY_EXISTS = "commercial_member_already_exists"
    COMMERCIAL_AGREEMENT_INVALID_TRANSITION = "commercial_agreement_invalid_transition"
    COMMERCIAL_AGREEMENT_VERSION_CONFLICT = "commercial_agreement_version_conflict"
    COMMERCIAL_ENTITLEMENT_VERSION_CONFLICT = "commercial_entitlement_version_conflict"
    COMMERCIAL_TOKEN_VERSION_CONFLICT = "commercial_token_version_conflict"
    COMMERCIAL_ACTIVATION_NOT_DUE = "commercial_activation_not_due"
    COMMERCIAL_IDEMPOTENCY_CONFLICT = "commercial_idempotency_conflict"
    COMMERCIAL_BILLING_FACT_INVALID = "commercial_billing_fact_invalid"
    COMMERCIAL_BILLING_SOURCE_CONFLICT = "commercial_billing_source_conflict"


_DEFAULT_PUBLIC_MESSAGES: dict[CommercialErrorCode, str] = {
    CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED: "An active commercial agreement is required.",
    CommercialErrorCode.COMMERCIAL_AGREEMENT_INACTIVE: "The commercial agreement is not active.",
    CommercialErrorCode.ENTITLEMENT_REQUIRED: "This capability is not available for the current account.",
    CommercialErrorCode.TOKEN_INVALID: "The access token is invalid.",
    CommercialErrorCode.TOKEN_EXPIRED: "The access token has expired.",
    CommercialErrorCode.TOKEN_REVOKED: "The access token has been revoked.",
    CommercialErrorCode.TOKEN_SCOPE_DENIED: "The access token does not allow this operation.",
    CommercialErrorCode.TOOL_NOT_EXPOSED: "This tool is not available on the external surface.",
    CommercialErrorCode.RATE_LIMIT_EXCEEDED: "The request limit has been reached. Try again later.",
    CommercialErrorCode.BUDGET_SOFT_LIMIT: "The current usage policy requires a lower-cost path.",
    CommercialErrorCode.BUDGET_HARD_LIMIT: "The current usage policy does not allow more funded work.",
    CommercialErrorCode.BUDGET_SERVICE_UNAVAILABLE: "Usage controls are temporarily unavailable.",
    CommercialErrorCode.UNKNOWN_RATE_VERSION: "The requested funded operation cannot be priced safely.",
    CommercialErrorCode.PROVIDER_COST_IDENTITY_MISSING: "Provider cost identity is incomplete.",
    CommercialErrorCode.FUNDING_ROUTE_MISMATCH: "The provider funding route could not be verified.",
    CommercialErrorCode.USAGE_EVENT_CONFLICT: "The usage event conflicts with an existing event.",
    CommercialErrorCode.RESERVATION_LINEAGE_MISSING: "The funded operation is missing reservation lineage.",
    CommercialErrorCode.BILLING_SYNC_PENDING: "Billing is still synchronizing. Try again shortly.",
    CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED: "The named operator lacks the required commercial role.",
    CommercialErrorCode.COMMERCIAL_STEP_UP_REQUIRED: "Recent step-up authentication is required.",
    CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED: "An approved commercial change request is required.",
    CommercialErrorCode.COMMERCIAL_APPROVAL_EXPIRED: "The commercial change request has expired.",
    CommercialErrorCode.COMMERCIAL_MAKER_CHECKER_REQUIRED: "A different named operator must approve this change.",
    CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND: "The commercial account was not found.",
    CommercialErrorCode.COMMERCIAL_ACCOUNT_ACCESS_DENIED: "You cannot administer this commercial account.",
    CommercialErrorCode.COMMERCIAL_ACCOUNT_INACTIVE: "The commercial account is not active.",
    CommercialErrorCode.COMMERCIAL_ACCOUNT_ALREADY_EXISTS: "A matching commercial account already exists.",
    CommercialErrorCode.COMMERCIAL_MEMBER_INVALID_STATE: "The commercial account member is not in a valid state for this operation.",
    CommercialErrorCode.COMMERCIAL_MEMBER_ALREADY_EXISTS: "The user is already associated with this commercial account.",
    CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION: "The commercial agreement cannot make that transition.",
    CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT: "The commercial agreement changed before this command completed.",
    CommercialErrorCode.COMMERCIAL_ENTITLEMENT_VERSION_CONFLICT: "The account entitlements changed before this command completed.",
    CommercialErrorCode.COMMERCIAL_TOKEN_VERSION_CONFLICT: "The access token changed before this command completed.",
    CommercialErrorCode.COMMERCIAL_ACTIVATION_NOT_DUE: "The approved commercial activation window has not started.",
    CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT: "The idempotency key was already used for a different command.",
    CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID: "The billing fact does not match the commercial agreement.",
    CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT: "The billing source identity conflicts with an existing fact.",
}


class CommercialError(Exception):
    """Typed exception whose serialized form contains only safe public fields."""

    def __init__(
        self,
        code: CommercialErrorCode | str,
        *,
        retryable: bool = False,
        retry_at: str | None = None,
        internal_detail: str | None = None,
    ) -> None:
        self.code = CommercialErrorCode(code)
        self.public_message = _DEFAULT_PUBLIC_MESSAGES[self.code]
        self.retryable = bool(retryable)
        self.retry_at = retry_at
        self.internal_detail = internal_detail
        super().__init__(self.public_message)

    def to_public_payload(self, *, request_id: str | None = None) -> dict[str, Any]:
        """Return the stable external payload without internal diagnostic detail."""

        payload: dict[str, Any] = {
            "code": self.code.value,
            "message": self.public_message,
            "retryable": self.retryable,
        }
        if self.retry_at is not None:
            payload["retry_at"] = self.retry_at
        if request_id is not None:
            payload["request_id"] = request_id
        return payload


__all__ = ["CommercialError", "CommercialErrorCode"]
