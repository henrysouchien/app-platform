"""Allowlisted, append-only commercial audit writer."""

from __future__ import annotations

import json
import re
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, field_validator, model_validator

from .models import NonEmptyStr, StableCode, StrictCommercialModel


SAFE_AUDIT_FACT_KEYS = frozenset(
    {
        "policy_identities",
        "policy_count",
        "state",
        "version",
        "role",
        "environment",
        "user_id",
        "account_id",
        "agreement_id",
        "offer_code",
        "price_code",
        "content_sha256",
        "request_id",
        "step_up_event_id",
        "result_code",
        "succeeded",
        "account_kind",
        "member_role",
        "member_state",
        "previous_owner_user_id",
        "new_owner_user_id",
        "previous_owner_role",
        "new_owner_role",
        "cancel_at_period_end",
        "classification",
        "observed_tier",
    }
)
AuditFacts = dict[StableCode, JsonValue]
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_SAFE_IDENTITY = re.compile(r"^[A-Za-z0-9._:@-]{1,256}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_ROLES = {
    "commercial_viewer",
    "billing_operator",
    "entitlement_operator",
    "commercial_admin",
}
_MEMBER_ROLES = {"owner", "admin", "billing", "member"}
_MEMBER_STATES = {"invited", "active", "suspended", "removed"}
_STATES = {
    "draft",
    "pending",
    "approved",
    "executed",
    "active",
    "suspended",
    "closed",
    "revoked",
    "retired",
    "failed",
    "pending_payment",
    "trialing",
    "past_due",
    "grace",
    "paused",
    "canceled",
    "expired",
}
_RESULT_CODES = {"activated", "applied", "rejected", "revoked", "failed"}
_SENSITIVE_TEXT = re.compile(
    r"secret|password|credential|prompt|api[_-]?key|authorization|cookie|signature|token_value",
    re.IGNORECASE,
)


def validate_audit_facts(value: AuditFacts | None) -> AuditFacts | None:
    if value is None:
        return None
    unknown = set(value) - SAFE_AUDIT_FACT_KEYS
    if unknown:
        raise ValueError(f"unapproved commercial audit fact keys: {sorted(unknown)}")
    for key, item in value.items():
        string_values = item if isinstance(item, list) else [item]
        if any(
            isinstance(child, str) and _SENSITIVE_TEXT.search(child)
            for child in string_values
        ):
            raise ValueError(f"commercial audit fact {key} contains forbidden content")
        if key == "policy_identities":
            if (
                not isinstance(item, list)
                or not 1 <= len(item) <= 100
                or not all(
                    isinstance(child, str) and _SAFE_IDENTITY.fullmatch(child)
                    for child in item
                )
            ):
                raise ValueError(f"commercial audit fact {key} has an unsafe value")
        elif key in {
            "policy_count",
            "version",
            "user_id",
            "account_id",
            "agreement_id",
            "previous_owner_user_id",
            "new_owner_user_id",
        }:
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise ValueError(
                    f"commercial audit fact {key} must be a non-negative integer"
                )
        elif key in {"succeeded", "cancel_at_period_end"}:
            if not isinstance(item, bool):
                raise ValueError(f"commercial audit fact {key} must be boolean")
        elif key == "content_sha256":
            if not isinstance(item, str) or not _SHA256.fullmatch(item):
                raise ValueError("commercial audit content hash is invalid")
        elif key in {"request_id", "step_up_event_id"}:
            if not isinstance(item, str) or not _UUID.fullmatch(item):
                raise ValueError(f"commercial audit fact {key} must be a UUID")
        elif key == "role":
            if not isinstance(item, str) or item not in _ROLES:
                raise ValueError("commercial audit role is invalid")
        elif key in {"member_role", "previous_owner_role", "new_owner_role"}:
            if not isinstance(item, str) or item not in _MEMBER_ROLES:
                raise ValueError("commercial audit member role is invalid")
        elif key == "member_state":
            if not isinstance(item, str) or item not in _MEMBER_STATES:
                raise ValueError("commercial audit member state is invalid")
        elif key == "account_kind":
            if not isinstance(item, str) or item not in {"individual", "firm"}:
                raise ValueError("commercial audit account kind is invalid")
        elif key == "environment":
            if not isinstance(item, str) or item not in {"dev", "staging", "prod"}:
                raise ValueError("commercial audit environment is invalid")
        elif key == "state":
            if not isinstance(item, str) or item not in _STATES:
                raise ValueError("commercial audit state is invalid")
        elif key == "result_code":
            if not isinstance(item, str) or item not in _RESULT_CODES:
                raise ValueError("commercial audit result code is invalid")
        elif key == "classification":
            if item not in {"test", "internal", "grandfathered_customer", "orphan"}:
                raise ValueError("commercial audit classification is invalid")
        elif key == "observed_tier":
            if item not in {"paid", "business"}:
                raise ValueError("commercial audit observed tier is invalid")
        elif not isinstance(item, str) or not _SAFE_CODE.fullmatch(item):
            raise ValueError(f"commercial audit fact {key} must be a stable code")
    rendered = json.dumps(value, separators=(",", ":"), sort_keys=True)
    if len(rendered.encode("utf-8")) > 32_768:
        raise ValueError("commercial audit facts exceed the size limit")
    return value


class CommercialAuditEvent(StrictCommercialModel):
    event_id: UUID = Field(default_factory=uuid4)
    commercial_account_id: Annotated[int, Field(gt=0)] | None = None
    agreement_id: Annotated[int, Field(gt=0)] | None = None
    actor_type: Literal["user", "admin", "service", "stripe", "reconciler"]
    actor_id: NonEmptyStr | None = None
    action: StableCode
    target_type: StableCode
    target_id: NonEmptyStr
    reason_code: StableCode | None = None
    before: AuditFacts | None = None
    after: AuditFacts | None = None
    request_id: NonEmptyStr | None = None

    @field_validator("before", "after")
    @classmethod
    def _safe_facts(cls, value: AuditFacts | None) -> AuditFacts | None:
        return validate_audit_facts(value)

    @model_validator(mode="after")
    def _named_human(self) -> "CommercialAuditEvent":
        if self.actor_type in {"user", "admin"} and self.actor_id is None:
            raise ValueError("human commercial audit actors must be named")
        return self


def insert_commercial_audit_event(
    connection: object, event: CommercialAuditEvent
) -> None:
    """Insert one safe event without committing the caller-owned transaction."""

    cursor = connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute(
            """
            INSERT INTO commercial_audit_log (
                event_id, commercial_account_id, agreement_id,
                actor_type, actor_id, action, target_type, target_id,
                reason_code, before_json, after_json, request_id
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s::jsonb, %s::jsonb, %s
            )
            """,
            (
                str(event.event_id),
                event.commercial_account_id,
                event.agreement_id,
                event.actor_type,
                event.actor_id,
                event.action,
                event.target_type,
                event.target_id,
                event.reason_code,
                json.dumps(event.before, separators=(",", ":"))
                if event.before is not None
                else None,
                json.dumps(event.after, separators=(",", ":"))
                if event.after is not None
                else None,
                event.request_id,
            ),
        )
    finally:
        cursor.close()


__all__ = [
    "CommercialAuditEvent",
    "SAFE_AUDIT_FACT_KEYS",
    "insert_commercial_audit_event",
    "validate_audit_facts",
]
