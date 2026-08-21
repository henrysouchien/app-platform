"""Versioned commercial contracts shared across routes and repositories."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
import hashlib
import json
import math
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)


NonEmptyStr = Annotated[
    StrictStr,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=512),
]
StableCode = Annotated[
    StrictStr,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9._:-]*$",
    ),
]
Sha256Digest = Annotated[
    StrictStr,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$"),
]
MIN_SIGNED_BIGINT = -(2**63)
MAX_SIGNED_BIGINT = 2**63 - 1
SignedBigInt = Annotated[
    StrictInt, Field(ge=MIN_SIGNED_BIGINT, le=MAX_SIGNED_BIGINT)
]
NonNegativeBigInt = Annotated[StrictInt, Field(ge=0, le=MAX_SIGNED_BIGINT)]
NonNegativeMicrousd = Annotated[StrictInt, Field(ge=0)]
Environment = Literal["dev", "staging", "prod"]


class StrictCommercialModel(BaseModel):
    """Security-sensitive V1 contract base."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class AdditiveResponseCommercialModel(StrictCommercialModel):
    """Response-only contract that retains safe future additive fields."""

    __pydantic_extra__: dict[str, JsonValue] = Field(init=False)
    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


def _canonical_number_text(value: int | float | Decimal) -> str:
    if isinstance(value, bool):
        raise TypeError("booleans are not canonical JSON numbers")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON numbers must be finite")
        decimal_value = Decimal(str(value))
    else:
        decimal_value = value
    if not decimal_value.is_finite():
        raise ValueError("canonical JSON numbers must be finite")
    if decimal_value == 0:
        return "0"
    rendered = format(decimal_value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _canonical_json_text(value: Any) -> str:
    if isinstance(value, BaseModel):
        return _canonical_json_text(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        members = (
            json.dumps(key, ensure_ascii=False, separators=(",", ":"))
            + ":"
            + _canonical_json_text(value[key])
            for key in sorted(value)
        )
        return "{" + ",".join(members) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json_text(item) for item in value) + "]"
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical commercial timestamps must be timezone-aware")
        rendered = value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return _canonical_json_text(rendered)
    if isinstance(value, UUID):
        return _canonical_json_text(str(value))
    if isinstance(value, Enum):
        return _canonical_json_text(value.value)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, Decimal)):
        return _canonical_number_text(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    raise TypeError(f"unsupported canonical commercial value: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode normalized JSON deterministically for digests and signatures."""

    return _canonical_json_text(value).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class CommercialClaimV1(StrictCommercialModel):
    """Short-lived, audience-bound commercial authority issued by risk_module."""

    schema_version: Literal[1]
    iss: Literal["risk-module-commercial-control"]
    aud: Literal["hank-agent-gateway"]
    kid: StableCode
    sub: Annotated[StrictStr, Field(pattern=r"^user:[1-9][0-9]*$")]
    environment: Environment
    surface: StableCode
    commercial_account_id: UUID
    agreement_id: UUID
    agreement_terms_revision: Annotated[StrictInt, Field(gt=0)]
    offer_code: StableCode
    effective_scopes: tuple[StableCode, ...]
    entitlement_revision: Annotated[StrictInt, Field(gt=0)]
    payer_policy_version: NonEmptyStr
    budget_policy_version: NonEmptyStr
    shadow_rate_version: NonEmptyStr
    manifest_version: NonEmptyStr
    authorized_work_start_deadline: Annotated[StrictInt, Field(gt=0)]
    usage_accept_until: Annotated[StrictInt, Field(gt=0)]
    iat: Annotated[StrictInt, Field(gt=0)]
    exp: Annotated[StrictInt, Field(gt=0)]
    jti: UUID

    @field_validator("effective_scopes")
    @classmethod
    def _validate_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or tuple(sorted(set(value))) != value:
            raise ValueError("effective_scopes must be non-empty, sorted, and unique")
        return value

    @model_validator(mode="after")
    def _validate_time_window(self) -> "CommercialClaimV1":
        if self.exp <= self.iat:
            raise ValueError("exp must be after iat")
        if self.exp - self.iat > 300:
            raise ValueError("commercial claim lifetime must not exceed five minutes")
        if not (self.iat <= self.authorized_work_start_deadline <= self.exp):
            raise ValueError("authorized_work_start_deadline must fall within the claim lifetime")
        if self.usage_accept_until < self.exp:
            raise ValueError("usage_accept_until must not precede claim expiry")
        return self


class UsageAcceptanceV1(AdditiveResponseCommercialModel):
    """Per-event result returned by canonical usage ingestion."""

    schema_version: Literal[1] = 1
    environment: Environment
    source_event_id: NonEmptyStr
    status: Literal[
        "accepted",
        "duplicate",
        "conflict",
        "rejected_retryable",
        "rejected_terminal",
    ]
    canonical_event_id: NonEmptyStr | None = None
    reason_code: StableCode | None = None

    @model_validator(mode="after")
    def _validate_result_identity(self) -> "UsageAcceptanceV1":
        if self.status in {"accepted", "duplicate"} and self.canonical_event_id is None:
            raise ValueError("accepted and duplicate results require canonical_event_id")
        if self.status not in {"accepted", "duplicate"} and self.reason_code is None:
            raise ValueError("non-accepted results require reason_code")
        return self


class BudgetDecisionV1(AdditiveResponseCommercialModel):
    """Stable reserve/preflight decision returned to an execution point."""

    schema_version: Literal[1] = 1
    decision: Literal["allow", "warn", "block", "degrade"]
    reservation_id: NonEmptyStr | None = None
    lease_version: Annotated[StrictInt, Field(gt=0)] | None = None
    holds_by_bucket_microusd: dict[StableCode, NonNegativeMicrousd] = Field(
        default_factory=dict
    )
    remaining_microusd: NonNegativeMicrousd
    reason_code: StableCode
    retry_at: AwareDatetime | None = None
    allowed_fallbacks: tuple[StableCode, ...] = ()

    @field_validator("allowed_fallbacks")
    @classmethod
    def _validate_fallbacks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("allowed_fallbacks must not contain duplicates")
        return value

    @model_validator(mode="after")
    def _validate_reservation(self) -> "BudgetDecisionV1":
        if self.decision in {"allow", "warn", "degrade"}:
            if self.reservation_id is None or self.lease_version is None:
                raise ValueError("non-block decisions require a reservation and lease version")
            if not self.holds_by_bucket_microusd:
                raise ValueError("non-block decisions require at least one budget hold")
        if (self.reservation_id is None) != (self.lease_version is None):
            raise ValueError("reservation_id and lease_version must be provided together")
        if self.decision == "block" and (
            self.reservation_id is not None or self.holds_by_bucket_microusd
        ):
            raise ValueError("block decisions must not create a reservation or budget hold")
        return self


class CommercialPolicySnapshotV1(StrictCommercialModel):
    """Content-addressed deployment envelope for an immutable policy body."""

    schema_version: Literal[1] = 1
    policy_kind: Literal["catalog", "entitlement", "payer", "budget", "rate", "manifest"]
    policy_code: StableCode
    version: NonEmptyStr
    content_sha256: Sha256Digest
    body: dict[str, JsonValue]

    @model_validator(mode="after")
    def _validate_content_digest(self) -> "CommercialPolicySnapshotV1":
        expected = canonical_sha256(self.body)
        if self.content_sha256 != expected:
            raise ValueError(
                f"content_sha256 does not match canonical body digest: expected {expected}"
            )
        return self


__all__ = [
    "BudgetDecisionV1",
    "CommercialClaimV1",
    "CommercialPolicySnapshotV1",
    "Environment",
    "NonEmptyStr",
    "Sha256Digest",
    "StableCode",
    "StrictCommercialModel",
    "UsageAcceptanceV1",
    "canonical_json_bytes",
    "canonical_sha256",
]
