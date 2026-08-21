"""Producer contract for one canonical economic usage delta."""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Any, Literal, Mapping
from uuid import UUID

from agent_gateway import CapabilityBind
from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from ..models import (
    Environment,
    MAX_SIGNED_BIGINT,
    NonEmptyStr,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)


NonNegativeInt = Annotated[StrictInt, Field(ge=0, le=MAX_SIGNED_BIGINT)]
NonNegativeDecimal = Annotated[Decimal, Field(ge=0, max_digits=18, decimal_places=8)]
NonNegativeProviderUnits = Annotated[Decimal, Field(ge=0, max_digits=20, decimal_places=6)]
SourceEventId = Annotated[str, Field(min_length=1, max_length=255)]


class _CommercialUsageEventBodyV1(StrictCommercialModel):
    schema_version: Literal[1] = 1
    source_product: StableCode
    source_event_id: SourceEventId
    environment: Environment
    occurred_at: AwareDatetime
    execution_context_id: NonEmptyStr
    request_id: NonEmptyStr
    session_id: NonEmptyStr
    parent_turn_id: NonEmptyStr | None = None
    workflow_run_id: NonEmptyStr
    reservation_id: NonEmptyStr | None = None
    funding_route_id: NonEmptyStr
    channel: StableCode
    provider: StableCode
    operation: StableCode
    model: NonEmptyStr | None = None
    capability_id: StableCode | None = None
    usage_state: Literal["succeeded", "failed_billable", "failed_unbilled", "canceled"]
    uncached_input_tokens: NonNegativeInt = 0
    billable_output_tokens: NonNegativeInt = 0
    reasoning_tokens_observed: NonNegativeInt | None = None
    cache_write_tokens: NonNegativeInt = 0
    cache_read_tokens: NonNegativeInt = 0
    is_batch: StrictBool = False
    provider_units: NonNegativeProviderUnits | None = None
    separately_billed_tool_cost_usd: NonNegativeDecimal = Decimal("0")
    producer_estimated_cost_usd: NonNegativeDecimal | None = None
    provider_reported_cost_usd: NonNegativeDecimal | None = None
    cost_observation_kind: Literal["producer_estimate", "provider_response", "unknown"]
    producer_rate_version: NonEmptyStr | None = None
    shadow_rate_version: NonEmptyStr
    raw_billing_mode: Literal["byok", "metered"]

    @model_validator(mode="after")
    def _validate_usage_semantics(self) -> "_CommercialUsageEventBodyV1":
        if (
            self.reasoning_tokens_observed is not None
            and self.reasoning_tokens_observed > self.billable_output_tokens
        ):
            raise ValueError(
                "reasoning_tokens_observed is an informational subset of billable_output_tokens"
            )
        if self.cost_observation_kind == "producer_estimate":
            if self.producer_estimated_cost_usd is None:
                raise ValueError(
                    "producer_estimate observation requires producer_estimated_cost_usd"
                )
            if self.producer_rate_version is None:
                raise ValueError("producer estimates require producer_rate_version")
        elif self.cost_observation_kind == "provider_response":
            if self.provider_reported_cost_usd is None:
                raise ValueError(
                    "provider_response observation requires provider_reported_cost_usd"
                )
        elif (
            self.producer_estimated_cost_usd is not None
            or self.provider_reported_cost_usd is not None
        ):
            raise ValueError("unknown cost observation must not assert a monetary observation")

        if self.raw_billing_mode == "metered" and self.reservation_id is None:
            raise ValueError("metered usage requires reservation_id")
        if self.usage_state == "failed_unbilled" and (
            self.separately_billed_tool_cost_usd != 0
            or (self.producer_estimated_cost_usd or 0) != 0
            or (self.provider_reported_cost_usd or 0) != 0
        ):
            raise ValueError("failed-unbilled usage cannot assert monetary cost")
        return self


class CommercialUsageEventV1(_CommercialUsageEventBodyV1):
    """One provider/model/tool economic delta from a trusted producer.

    Account, agreement, offer, payer class, and budget identity are deliberately
    absent.  The ingest service derives those trusted fields from the durable
    execution context, reservation, and funding route.
    """

    source_payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_source_digest(self) -> "CommercialUsageEventV1":
        expected = usage_payload_sha256(self)
        if self.source_payload_sha256 != expected:
            raise ValueError(
                f"source_payload_sha256 does not match canonical event digest: expected {expected}"
            )
        return self


class _CommercialUsageEventBodyV2(_CommercialUsageEventBodyV1):
    """Attempt-authoritative usage body; V1 remains byte- and schema-immutable."""

    schema_version: Literal[2]
    source_product: Literal["hank-agent-gateway", "risk-module-direct"]
    execution_context_id: UUID
    workflow_run_id: UUID
    reservation_id: UUID | None = None
    funding_route_id: UUID
    provider_units: Annotated[
        Decimal, Field(gt=0, max_digits=20, decimal_places=6)
    ] | None = None
    workflow_attempt_group_id: UUID
    workflow_attempt_number: Annotated[StrictInt, Field(gt=0, le=MAX_SIGNED_BIGINT)]
    retry_of_workflow_run_id: UUID | None
    workflow_attempt_kind: Literal["initial", "user_retry", "automatic_retry"]
    work_authorization_id: UUID | None

    @model_validator(mode="after")
    def _validate_attempt_semantics(self) -> "_CommercialUsageEventBodyV2":
        if self.provider_units is not None and self.provider_units <= 0:
            raise ValueError("Usage V2 provider_units must be positive when present")
        if self.workflow_attempt_kind == "initial":
            if (
                self.workflow_attempt_number != 1
                or self.retry_of_workflow_run_id is not None
                or self.workflow_attempt_group_id != self.workflow_run_id
            ):
                raise ValueError("initial usage must self-root attempt lineage")
        elif (
            self.workflow_attempt_number <= 1
            or self.retry_of_workflow_run_id is None
            or self.workflow_attempt_group_id == self.workflow_run_id
            or self.retry_of_workflow_run_id == self.workflow_run_id
        ):
            raise ValueError("retry usage must identify its predecessor and ordinal")
        if self.source_product == "hank-agent-gateway":
            if self.work_authorization_id is None:
                raise ValueError("gateway Usage V2 requires work_authorization_id")
        elif self.work_authorization_id is not None:
            raise ValueError("direct Usage V2 cannot assert gateway work authorization")
        return self


class CommercialUsageEventV2(_CommercialUsageEventBodyV2):
    """One economic delta with central logical-attempt lineage."""

    source_payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_source_digest(self) -> "CommercialUsageEventV2":
        expected = usage_payload_sha256_v2(self)
        if self.source_payload_sha256 != expected:
            raise ValueError(
                f"source_payload_sha256 does not match canonical V2 event digest: expected {expected}"
            )
        return self


class _CommercialUsageEventBodyV3(_CommercialUsageEventBodyV1):
    """Model-authoritative successor for both V1 and V2 lineage modes."""

    schema_version: Literal[3]
    source_product: Literal["hank-agent-gateway", "risk-module-direct"]
    provider: StableCode
    model: NonEmptyStr
    capability_id: StableCode
    capability_bind: CapabilityBind
    provider_reported_model: NonEmptyStr | None
    workflow_attempt_group_id: UUID | None
    workflow_attempt_number: Annotated[
        StrictInt, Field(gt=0, le=MAX_SIGNED_BIGINT)
    ] | None
    retry_of_workflow_run_id: UUID | None
    workflow_attempt_kind: (
        Literal["initial", "user_retry", "automatic_retry"] | None
    )
    work_authorization_id: UUID | None

    @model_validator(mode="after")
    def _validate_model_identity_projections(self) -> "_CommercialUsageEventBodyV3":
        bind = self.capability_bind
        if self.provider != bind.provider:
            raise ValueError("provider projection differs from capability_bind.provider")
        if self.model != bind.upstream_model:
            raise ValueError(
                "model projection differs from capability_bind.upstream_model"
            )
        if self.capability_id != bind.capability_id:
            raise ValueError(
                "capability_id projection differs from capability_bind.capability_id"
            )
        return self

    @model_validator(mode="after")
    def _validate_attempt_mode(self) -> "_CommercialUsageEventBodyV3":
        attempt_values = (
            self.workflow_attempt_group_id,
            self.workflow_attempt_number,
            self.retry_of_workflow_run_id,
            self.workflow_attempt_kind,
            self.work_authorization_id,
        )
        if all(value is None for value in attempt_values):
            return self
        if (
            self.workflow_attempt_group_id is None
            or self.workflow_attempt_number is None
            or self.workflow_attempt_kind is None
        ):
            raise ValueError("Usage V3 attempt lineage must be complete or all-null")
        try:
            UUID(str(self.execution_context_id))
            workflow_run_id = UUID(str(self.workflow_run_id))
            UUID(str(self.funding_route_id))
            if self.reservation_id is not None:
                UUID(str(self.reservation_id))
        except (TypeError, ValueError):
            raise ValueError("Usage V3 attempt mode requires UUID lineage") from None
        if self.provider_units is not None and self.provider_units <= 0:
            raise ValueError("Usage V3 attempt provider_units must be positive")
        if self.workflow_attempt_kind == "initial":
            if (
                self.workflow_attempt_number != 1
                or self.retry_of_workflow_run_id is not None
                or self.workflow_attempt_group_id != workflow_run_id
            ):
                raise ValueError("initial usage must self-root attempt lineage")
        elif (
            self.workflow_attempt_number <= 1
            or self.retry_of_workflow_run_id is None
            or self.workflow_attempt_group_id == workflow_run_id
            or self.retry_of_workflow_run_id == workflow_run_id
        ):
            raise ValueError("retry usage must identify its predecessor and ordinal")
        if self.source_product == "hank-agent-gateway":
            if self.work_authorization_id is None:
                raise ValueError("gateway Usage V3 attempt requires work_authorization_id")
        elif self.work_authorization_id is not None:
            raise ValueError("direct Usage V3 cannot assert gateway work authorization")
        return self


class CommercialUsageEventV3(_CommercialUsageEventBodyV3):
    """One economic delta with exact model bind and reported identity."""

    source_payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_source_digest(self) -> "CommercialUsageEventV3":
        expected = usage_payload_sha256_v3(self)
        if self.source_payload_sha256 != expected:
            raise ValueError(
                f"source_payload_sha256 does not match canonical V3 event digest: expected {expected}"
            )
        return self


def usage_payload_sha256(
    value: CommercialUsageEventV1 | _CommercialUsageEventBodyV1 | Mapping[str, Any],
) -> str:
    """Hash the normalized V1 body, excluding its digest field."""

    if isinstance(value, CommercialUsageEventV1):
        body_payload = value.model_dump(
            mode="python",
            exclude={"source_payload_sha256"},
        )
        body = _CommercialUsageEventBodyV1.model_validate(body_payload)
    elif isinstance(value, _CommercialUsageEventBodyV1):
        body = value
    else:
        raw = dict(value)
        raw.pop("source_payload_sha256", None)
        body = _CommercialUsageEventBodyV1.model_validate(raw)
    return canonical_sha256(body)


def usage_payload_sha256_v2(
    value: CommercialUsageEventV2 | _CommercialUsageEventBodyV2 | Mapping[str, Any],
) -> str:
    """Hash the normalized V2 body, excluding its digest field."""

    if isinstance(value, CommercialUsageEventV2):
        body_payload = value.model_dump(
            mode="python",
            exclude={"source_payload_sha256"},
        )
        body = _CommercialUsageEventBodyV2.model_validate(body_payload)
    elif isinstance(value, _CommercialUsageEventBodyV2):
        body = value
    else:
        raw = dict(value)
        raw.pop("source_payload_sha256", None)
        body = _CommercialUsageEventBodyV2.model_validate(raw)
    return canonical_sha256(body)


def usage_payload_sha256_v3(
    value: CommercialUsageEventV3 | _CommercialUsageEventBodyV3 | Mapping[str, Any],
) -> str:
    """Hash the normalized V3 body, excluding its digest field."""

    if isinstance(value, CommercialUsageEventV3):
        body_payload = value.model_dump(
            mode="python",
            exclude={"source_payload_sha256"},
        )
        body = _CommercialUsageEventBodyV3.model_validate(body_payload)
    elif isinstance(value, _CommercialUsageEventBodyV3):
        body = value
    else:
        raw = dict(value)
        raw.pop("source_payload_sha256", None)
        body = _CommercialUsageEventBodyV3.model_validate(raw)
    return canonical_sha256(body)


def build_usage_event_v1(value: Mapping[str, Any]) -> CommercialUsageEventV1:
    """Normalize a producer body, attach its digest, and return the strict event."""

    raw = dict(value)
    raw.pop("source_payload_sha256", None)
    body = _CommercialUsageEventBodyV1.model_validate(raw)
    payload = body.model_dump(mode="python")
    payload["source_payload_sha256"] = canonical_sha256(body)
    return CommercialUsageEventV1.model_validate(payload)


def build_usage_event_v2(value: Mapping[str, Any]) -> CommercialUsageEventV2:
    """Normalize an attempt-authoritative producer body and attach its digest."""

    raw = dict(value)
    raw.pop("source_payload_sha256", None)
    body = _CommercialUsageEventBodyV2.model_validate(raw)
    payload = body.model_dump(mode="python")
    payload["source_payload_sha256"] = canonical_sha256(body)
    return CommercialUsageEventV2.model_validate(payload)


def build_usage_event_v3(value: Mapping[str, Any]) -> CommercialUsageEventV3:
    """Normalize a model-authoritative producer body and attach its digest."""

    raw = dict(value)
    raw.pop("source_payload_sha256", None)
    body = _CommercialUsageEventBodyV3.model_validate(raw)
    payload = body.model_dump(mode="python")
    payload["source_payload_sha256"] = canonical_sha256(body)
    return CommercialUsageEventV3.model_validate(payload)


CommercialUsageEvent = (
    CommercialUsageEventV1 | CommercialUsageEventV2 | CommercialUsageEventV3
)


def validate_usage_event(value: object) -> CommercialUsageEvent:
    """Discriminate immutable V1 from attempt-authoritative V2."""

    if isinstance(
        value,
        (CommercialUsageEventV1, CommercialUsageEventV2, CommercialUsageEventV3),
    ):
        return value
    if not isinstance(value, Mapping):
        raise ValueError("commercial usage event must be an object")
    if value.get("schema_version") == 3:
        return CommercialUsageEventV3.model_validate(value)
    if value.get("schema_version") == 2:
        return CommercialUsageEventV2.model_validate(value)
    return CommercialUsageEventV1.model_validate(value)


__all__ = [
    "CommercialUsageEventV1",
    "CommercialUsageEventV2",
    "CommercialUsageEventV3",
    "CommercialUsageEvent",
    "build_usage_event_v1",
    "build_usage_event_v2",
    "build_usage_event_v3",
    "usage_payload_sha256",
    "usage_payload_sha256_v2",
    "usage_payload_sha256_v3",
    "validate_usage_event",
]
