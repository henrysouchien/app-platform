"""Canonical direct-call usage emission for risk_module provider paths."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from decimal import Decimal
from typing import Iterator, Literal
from uuid import UUID

from agent_gateway import CapabilityBind
from pydantic import AwareDatetime, Field, model_validator

from ..models import NonEmptyStr, StableCode, StrictCommercialModel
from .auth import AuthenticatedUsageProducer
from .contract import (
    CommercialUsageEvent,
    CommercialUsageEventV2,
    CommercialUsageEventV3,
    build_usage_event_v2,
    build_usage_event_v3,
)
from .ingest import CommercialUsageIngestService
from .workflow_attempts import WorkflowAttemptKind


class DirectCommercialUsageContext(StrictCommercialModel):
    """Server-issued commercial lineage bound around one direct workflow."""

    execution_context_id: UUID
    workflow_run_id: UUID
    workflow_attempt_group_id: UUID
    workflow_attempt_number: int = Field(gt=0)
    retry_of_workflow_run_id: UUID | None = None
    workflow_attempt_kind: WorkflowAttemptKind
    funding_route_id: UUID
    provider: StableCode
    reservation_id: UUID | None = None
    request_id: NonEmptyStr
    session_id: NonEmptyStr
    parent_turn_id: NonEmptyStr | None = None
    channel: StableCode
    capability_id: StableCode | None = None
    shadow_rate_version: NonEmptyStr
    raw_billing_mode: Literal["byok", "metered"]

    @model_validator(mode="after")
    def _reservation_matches_billing_mode(self) -> "DirectCommercialUsageContext":
        if self.raw_billing_mode == "metered" and self.reservation_id is None:
            raise ValueError("metered direct usage requires reservation lineage")
        if self.raw_billing_mode == "byok" and self.reservation_id is not None:
            raise ValueError("BYOK direct usage cannot carry a Hank-funded reservation")
        return self


class DirectUsageObservation(StrictCommercialModel):
    """One completed provider/model/tool economic delta."""

    source_event_id: NonEmptyStr
    occurred_at: AwareDatetime
    provider: StableCode
    operation: StableCode
    model: NonEmptyStr | None = None
    capability_bind: CapabilityBind | None = None
    provider_reported_model: NonEmptyStr | None = None
    usage_state: Literal["succeeded", "failed_billable", "failed_unbilled", "canceled"]
    uncached_input_tokens: int = Field(default=0, ge=0, le=2**63 - 1)
    billable_output_tokens: int = Field(default=0, ge=0, le=2**63 - 1)
    reasoning_tokens_observed: int | None = Field(default=None, ge=0, le=2**63 - 1)
    cache_write_tokens: int = Field(default=0, ge=0, le=2**63 - 1)
    cache_read_tokens: int = Field(default=0, ge=0, le=2**63 - 1)
    is_batch: bool = False
    provider_units: Decimal | None = Field(
        default=None, ge=0, max_digits=20, decimal_places=6
    )
    separately_billed_tool_cost_usd: Decimal = Field(
        default=Decimal("0"), ge=0, max_digits=18, decimal_places=8
    )
    producer_estimated_cost_usd: Decimal | None = Field(
        default=None, ge=0, max_digits=18, decimal_places=8
    )
    provider_reported_cost_usd: Decimal | None = Field(
        default=None, ge=0, max_digits=18, decimal_places=8
    )
    cost_observation_kind: Literal["producer_estimate", "provider_response", "unknown"]
    producer_rate_version: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _validate_model_identity(self) -> "DirectUsageObservation":
        bind = self.capability_bind
        if bind is None:
            if self.provider_reported_model is not None:
                raise ValueError(
                    "provider_reported_model requires an exact capability_bind"
                )
            return self
        if self.provider != bind.provider:
            raise ValueError("direct usage provider differs from capability bind")
        if self.model != bind.upstream_model:
            raise ValueError("direct usage model differs from capability bind")
        return self


class DirectUsageEmissionError(RuntimeError):
    def __init__(
        self,
        *,
        status: str,
        reason_code: str | None,
        event: CommercialUsageEvent,
        attempts: int,
    ) -> None:
        super().__init__(
            f"direct commercial usage was not accepted: {status}/{reason_code}"
        )
        self.status = status
        self.reason_code = reason_code
        self.event = event
        self.attempts = attempts


class DirectCommercialUsageEmitter:
    def __init__(
        self,
        *,
        ingest_service: CommercialUsageIngestService,
        producer: AuthenticatedUsageProducer,
        max_persist_attempts: int = 3,
    ) -> None:
        if "risk-module-direct" not in producer.source_products:
            raise ValueError(
                "direct usage producer is not authorized for risk-module-direct"
            )
        self._ingest_service = ingest_service
        self._producer = producer
        if max_persist_attempts <= 0 or max_persist_attempts > 10:
            raise ValueError(
                "direct usage persistence attempts must be between one and ten"
            )
        self._max_persist_attempts = max_persist_attempts

    def emit(
        self,
        context: DirectCommercialUsageContext,
        observation: DirectUsageObservation,
    ) -> CommercialUsageEventV2 | CommercialUsageEventV3:
        if observation.provider != context.provider:
            raise ValueError("direct usage provider does not match bound funding route")
        bind = observation.capability_bind
        if (
            bind is not None
            and context.capability_id is not None
            and bind.capability_id != context.capability_id
        ):
            raise ValueError("direct usage capability differs from bound workflow")
        body: dict[str, object] = {
            "schema_version": 3 if bind is not None else 2,
            "source_product": "risk-module-direct",
            "source_event_id": observation.source_event_id,
            "environment": self._producer.environment,
            "occurred_at": observation.occurred_at,
            "execution_context_id": str(context.execution_context_id),
            "request_id": context.request_id,
            "session_id": context.session_id,
            "parent_turn_id": context.parent_turn_id,
            "workflow_run_id": str(context.workflow_run_id),
            "workflow_attempt_group_id": str(context.workflow_attempt_group_id),
            "workflow_attempt_number": context.workflow_attempt_number,
            "retry_of_workflow_run_id": (
                str(context.retry_of_workflow_run_id)
                if context.retry_of_workflow_run_id is not None
                else None
            ),
            "workflow_attempt_kind": context.workflow_attempt_kind,
            "work_authorization_id": None,
            "reservation_id": (
                str(context.reservation_id)
                if context.reservation_id is not None
                else None
            ),
            "funding_route_id": str(context.funding_route_id),
            "channel": context.channel,
            "provider": bind.provider if bind is not None else observation.provider,
            "operation": observation.operation,
            "model": bind.upstream_model if bind is not None else observation.model,
            "capability_id": (
                bind.capability_id if bind is not None else context.capability_id
            ),
            "usage_state": observation.usage_state,
            "uncached_input_tokens": observation.uncached_input_tokens,
            "billable_output_tokens": observation.billable_output_tokens,
            "reasoning_tokens_observed": observation.reasoning_tokens_observed,
            "cache_write_tokens": observation.cache_write_tokens,
            "cache_read_tokens": observation.cache_read_tokens,
            "is_batch": observation.is_batch,
            "provider_units": observation.provider_units,
            "separately_billed_tool_cost_usd": (
                observation.separately_billed_tool_cost_usd
            ),
            "producer_estimated_cost_usd": observation.producer_estimated_cost_usd,
            "provider_reported_cost_usd": observation.provider_reported_cost_usd,
            "cost_observation_kind": observation.cost_observation_kind,
            "producer_rate_version": observation.producer_rate_version,
            "shadow_rate_version": context.shadow_rate_version,
            "raw_billing_mode": context.raw_billing_mode,
        }
        if bind is not None:
            body["capability_bind"] = bind.model_dump(mode="json")
            body["provider_reported_model"] = observation.provider_reported_model
            event = build_usage_event_v3(body)
        else:
            event = build_usage_event_v2(body)
        return self.emit_event(event)

    def emit_event(self, event: CommercialUsageEvent) -> CommercialUsageEvent:
        if (
            event.source_product != "risk-module-direct"
            or event.environment != self._producer.environment
        ):
            raise ValueError(
                "direct usage event producer identity does not match emitter"
            )
        result = None
        for attempt in range(1, self._max_persist_attempts + 1):
            try:
                result = self._ingest_service.ingest_batch(
                    [event.model_dump(mode="json")], producer=self._producer
                )[0]
            except Exception:
                if attempt < self._max_persist_attempts:
                    continue
                raise DirectUsageEmissionError(
                    status="rejected_retryable",
                    reason_code="usage.ingest_unavailable",
                    event=event,
                    attempts=attempt,
                ) from None
            if result.status in {"accepted", "duplicate"}:
                return event
            if (
                result.status != "rejected_retryable"
                or attempt == self._max_persist_attempts
            ):
                raise DirectUsageEmissionError(
                    status=result.status,
                    reason_code=result.reason_code,
                    event=event,
                    attempts=attempt,
                )
        raise AssertionError("unreachable direct usage persistence state")


class DirectUsageBinding(StrictCommercialModel):
    context: DirectCommercialUsageContext
    emitter: DirectCommercialUsageEmitter

    model_config = {"arbitrary_types_allowed": True, "frozen": True, "extra": "forbid"}


_CURRENT_DIRECT_USAGE: ContextVar[DirectUsageBinding | None] = ContextVar(
    "current_direct_commercial_usage", default=None
)


@contextmanager
def bind_direct_commercial_usage(
    *,
    context: DirectCommercialUsageContext,
    emitter: DirectCommercialUsageEmitter,
) -> Iterator[DirectUsageBinding]:
    binding = DirectUsageBinding(context=context, emitter=emitter)
    token: Token[DirectUsageBinding | None] = _CURRENT_DIRECT_USAGE.set(binding)
    try:
        yield binding
    finally:
        _CURRENT_DIRECT_USAGE.reset(token)


def get_direct_commercial_usage_binding() -> DirectUsageBinding | None:
    return _CURRENT_DIRECT_USAGE.get()


def assert_bound_direct_provider(provider: str) -> None:
    binding = get_direct_commercial_usage_binding()
    if binding is not None and binding.context.provider != provider:
        raise ValueError("provider call does not match bound commercial funding route")


def emit_bound_direct_usage(
    observation: DirectUsageObservation,
) -> CommercialUsageEvent | None:
    binding = get_direct_commercial_usage_binding()
    if binding is None:
        return None
    return binding.emitter.emit(binding.context, observation)


__all__ = [
    "DirectCommercialUsageContext",
    "DirectCommercialUsageEmitter",
    "DirectUsageBinding",
    "DirectUsageEmissionError",
    "DirectUsageObservation",
    "bind_direct_commercial_usage",
    "assert_bound_direct_provider",
    "emit_bound_direct_usage",
    "get_direct_commercial_usage_binding",
]
