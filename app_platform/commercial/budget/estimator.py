"""Versioned, fail-closed reservation estimates for commercial workflows."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Annotated

from pydantic import Field, StrictInt, TypeAdapter, ValidationError, model_validator

from ..models import MAX_SIGNED_BIGINT, StableCode, StrictCommercialModel


PositiveBigInt = Annotated[StrictInt, Field(gt=0, le=MAX_SIGNED_BIGINT)]
NonNegativeBigInt = Annotated[StrictInt, Field(ge=0, le=MAX_SIGNED_BIGINT)]
_STABLE_CODE_ADAPTER = TypeAdapter(StableCode)


class ReservationEstimatorError(ValueError):
    """Raised when no safe reservation can be produced."""


class ReservationFallback(StrEnum):
    LOWER_COST_MODEL = "lower_cost_model"
    CUSTOMER_BYOK = "customer_byok"


class WorkflowCostObservation(StrictCommercialModel):
    """Reviewed workflow-level cost distribution used to create a profile."""

    successful_workflow_count: PositiveBigInt
    p50_microusd: PositiveBigInt
    p90_microusd: PositiveBigInt
    observed_max_microusd: PositiveBigInt

    @model_validator(mode="after")
    def _ordered_quantiles(self) -> "WorkflowCostObservation":
        if not self.p50_microusd <= self.p90_microusd <= self.observed_max_microusd:
            raise ValueError(
                "workflow cost observations must satisfy p50 <= p90 <= max"
            )
        return self


class ReservationProfile(StrictCommercialModel):
    """Immutable estimator policy for one workflow or the explicit conservative default."""

    profile_version: StableCode
    workflow_code: StableCode | None
    primary_bucket: StableCode
    observation: WorkflowCostObservation
    safety_factor_bps: Annotated[StrictInt, Field(ge=10_000, le=100_000)]
    safe_max_microusd: PositiveBigInt
    top_up_threshold_microusd: PositiveBigInt
    max_unreserved_delta_microusd: NonNegativeBigInt
    allowed_fallbacks: tuple[ReservationFallback, ...] = ()

    @model_validator(mode="after")
    def _safe_policy(self) -> "ReservationProfile":
        if self.safe_max_microusd < self.observation.p90_microusd:
            raise ValueError("safe maximum cannot be below observed p90")
        if self.top_up_threshold_microusd > self.safe_max_microusd:
            raise ValueError("top-up threshold cannot exceed safe maximum")
        if self.max_unreserved_delta_microusd > self.top_up_threshold_microusd:
            raise ValueError("max unreserved delta cannot exceed top-up threshold")
        if len(set(self.allowed_fallbacks)) != len(self.allowed_fallbacks):
            raise ValueError("allowed fallbacks must be unique")
        return self


class ReservationBucketHold(StrictCommercialModel):
    budget_bucket: StableCode
    amount_microusd: PositiveBigInt


class ReservationEstimate(StrictCommercialModel):
    profile_version: StableCode
    workflow_code: StableCode
    used_conservative_default: bool
    holds_by_bucket_microusd: tuple[ReservationBucketHold, ...]
    top_up_threshold_microusd: PositiveBigInt
    max_unreserved_delta_microusd: NonNegativeBigInt
    allowed_fallbacks: tuple[ReservationFallback, ...]


class ReservationEstimator:
    """Resolve an immutable profile and return a conservative multi-bucket hold."""

    def __init__(self, profiles: Iterable[ReservationProfile]) -> None:
        by_workflow: dict[str, ReservationProfile] = {}
        conservative_default: ReservationProfile | None = None
        for profile in profiles:
            if profile.workflow_code is None:
                if conservative_default is not None:
                    raise ValueError("only one conservative default profile is allowed")
                conservative_default = profile
            elif profile.workflow_code in by_workflow:
                raise ValueError(
                    f"duplicate reservation profile: {profile.workflow_code}"
                )
            else:
                by_workflow[profile.workflow_code] = profile
        self._profiles = by_workflow
        self._conservative_default = conservative_default

    def estimate(self, workflow_code: str) -> ReservationEstimate:
        if not isinstance(workflow_code, str):
            raise ReservationEstimatorError(
                "workflow code must be a canonical stable code"
            )
        try:
            canonical_workflow_code = _STABLE_CODE_ADAPTER.validate_python(
                workflow_code
            )
        except (TypeError, ValidationError) as error:
            raise ReservationEstimatorError(
                "workflow code must be a canonical stable code"
            ) from error
        if canonical_workflow_code != workflow_code:
            raise ReservationEstimatorError("workflow code must be canonical")

        profile = self._profiles.get(canonical_workflow_code)
        used_default = profile is None
        if profile is None:
            profile = self._conservative_default
        if profile is None:
            raise ReservationEstimatorError(
                "unknown workflow has no conservative profile: "
                f"{canonical_workflow_code}"
            )

        scaled_p90 = (
            profile.observation.p90_microusd * profile.safety_factor_bps + 9_999
        ) // 10_000
        estimate = min(profile.safe_max_microusd, scaled_p90)
        if (
            estimate <= 0
        ):  # Defensive: profiles reject zero, but never emit a zero hold.
            raise ReservationEstimatorError("reservation estimate must be positive")

        holds = [
            ReservationBucketHold(
                budget_bucket=profile.primary_bucket, amount_microusd=estimate
            )
        ]
        if profile.primary_bucket != "technical":
            holds.append(
                ReservationBucketHold(
                    budget_bucket="technical", amount_microusd=estimate
                )
            )
        return ReservationEstimate(
            profile_version=profile.profile_version,
            workflow_code=canonical_workflow_code,
            used_conservative_default=used_default,
            holds_by_bucket_microusd=tuple(holds),
            top_up_threshold_microusd=profile.top_up_threshold_microusd,
            max_unreserved_delta_microusd=profile.max_unreserved_delta_microusd,
            allowed_fallbacks=profile.allowed_fallbacks,
        )
