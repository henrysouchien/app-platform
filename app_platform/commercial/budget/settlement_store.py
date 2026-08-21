"""Atomic Redis settlement primitives for commercial reservations."""

from __future__ import annotations

from importlib import resources
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from ..flags import CommercialFlags
from ..models import (
    NonEmptyStr,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)
from .redis_store import (
    MAX_SAFE_REDIS_INTEGER,
    BucketLimit,
    CommercialReservationRedisError,
    RedisBucketHold,
)


NonNegativeSafeInt = Annotated[StrictInt, Field(ge=0, le=MAX_SAFE_REDIS_INTEGER)]
SignedSafeInt = Annotated[
    StrictInt, Field(ge=-MAX_SAFE_REDIS_INTEGER, le=MAX_SAFE_REDIS_INTEGER)
]
PositiveSafeInt = Annotated[StrictInt, Field(gt=0, le=MAX_SAFE_REDIS_INTEGER)]


class SettlementBucketAmount(StrictCommercialModel):
    budget_bucket: StableCode
    amount_microusd: SignedSafeInt


class BudgetSettlementRedisCommand(StrictCommercialModel):
    reservation_id: UUID
    source_product: StableCode
    source_event_id: Annotated[NonEmptyStr, Field(max_length=255)]
    cost_revision: NonNegativeSafeInt
    actor_type: Literal["service", "provider", "admin", "reconciler"] = "service"
    actor_id: NonEmptyStr | None = None
    cost_adjustment_id: UUID | None = None
    reason_code: StableCode = "budget.settled"
    payload_sha256: Sha256Digest
    lease_token: UUID
    lease_version: PositiveSafeInt
    generation: PositiveSafeInt
    budget_policy_id: PositiveSafeInt
    ttl_seconds: Annotated[StrictInt, Field(gt=0, le=31_536_000)]
    is_late_child: StrictBool
    finalize_reservation: StrictBool
    late_child_allowance_microusd: NonNegativeSafeInt
    actuals: tuple[SettlementBucketAmount, ...]
    limits: tuple[BucketLimit, ...]

    @model_validator(mode="after")
    def _bucket_invariants(self) -> "BudgetSettlementRedisCommand":
        actual_buckets = [item.budget_bucket for item in self.actuals]
        limit_buckets = [item.budget_bucket for item in self.limits]
        if not actual_buckets or len(set(actual_buckets)) != len(actual_buckets):
            raise ValueError("settlement buckets must be non-empty and unique")
        if set(actual_buckets) != set(limit_buckets):
            raise ValueError(
                "settlement actuals and limits must cover identical buckets"
            )
        if "technical" not in actual_buckets:
            raise ValueError("settlement requires the canonical technical total")
        amounts = {item.budget_bucket: item.amount_microusd for item in self.actuals}
        has_negative = any(amount < 0 for amount in amounts.values())
        component_total = sum(
            amount for bucket, amount in amounts.items() if bucket != "technical"
        )
        if not has_negative and amounts["technical"] < component_total:
            raise ValueError(
                "canonical technical total cannot be below component costs"
            )
        if self.cost_revision == 0 and has_negative:
            raise ValueError("revision zero settlement amounts cannot be negative")
        if has_negative and not (
            self.cost_revision > 0
            and self.actor_type in {"admin", "reconciler"}
            and self.actor_id is not None
            and self.cost_adjustment_id is not None
        ):
            raise ValueError(
                "negative settlement revision requires canonical adjustment authority"
            )
        return self


class BudgetSettlementRedisDecision(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: StableCode
    reservation_id: UUID
    lease_version: PositiveSafeInt
    generation: PositiveSafeInt
    state: Literal[
        "reserved",
        "partially_settled",
        "settled",
        "overdrawn",
        "released",
        "expired",
        "missing",
    ]
    replayed: StrictBool
    overdrawn: StrictBool
    holds_by_bucket_microusd: tuple[RedisBucketHold, ...]
    settled_by_bucket_microusd: tuple[RedisBucketHold, ...]
    late_child_consumed_microusd: NonNegativeSafeInt

    @field_validator(
        "holds_by_bucket_microusd", "settled_by_bucket_microusd", mode="before"
    )
    @classmethod
    def _freeze_bucket_map(cls, value):
        if isinstance(value, dict):
            return tuple(
                {
                    "budget_bucket": bucket,
                    "amount_microusd": (
                        int(amount)
                        if isinstance(amount, str) and amount.isdigit()
                        else amount
                    ),
                }
                for bucket, amount in sorted(value.items())
            )
        return value

    @field_validator(
        "lease_version",
        "generation",
        "late_child_consumed_microusd",
        mode="before",
    )
    @classmethod
    def _parse_exact_integer(cls, value):
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return value


class CommercialBudgetSettlementRedisStore:
    def __init__(self, client, *, flags: CommercialFlags) -> None:
        flags.validate()
        if not (
            flags.commercial_control_enabled
            and (
                flags.commercial_budget_shadow_mode
                or flags.commercial_budget_enforcement_enabled
            )
        ):
            raise CommercialReservationRedisError(
                "commercial budget settlement controls are disabled"
            )
        self._client = client
        self._mode = (
            "enforce" if flags.commercial_budget_enforcement_enabled else "shadow"
        )
        self._script = (
            resources.files(__package__)
            .joinpath("lua/settlement.lua")
            .read_text(encoding="utf-8")
        )
        self._readiness_script = (
            resources.files(__package__)
            .joinpath("lua/generation_ready.lua")
            .read_text(encoding="utf-8")
        )
        self._sha: str | None = None
        self._readiness_sha: str | None = None

    def generation_ready(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        generation: int,
        reservation_id: UUID,
        buckets: tuple[str, ...],
    ) -> bool:
        if min(agreement_terms_id, period_id, generation) <= 0 or not buckets:
            raise ValueError("settlement generation readiness identity is invalid")
        tag = f"commercial:{self._mode}:{agreement_terms_id}:{period_id}"
        base = f"budget:spend:v2:{{{tag}}}"
        prefix = f"{base}:g{generation}"
        keys = [
            f"{prefix}:generation",
            f"{base}:generation",
            f"{prefix}:policy",
            f"{prefix}:active",
            f"{prefix}:reservation:{reservation_id}",
            *(f"{prefix}:bucket:{bucket}" for bucket in buckets),
        ]
        argv = [str(generation), str(len(buckets)), *buckets]
        try:
            if self._readiness_sha is None:
                self._readiness_sha = self._client.script_load(self._readiness_script)
            try:
                raw = self._client.evalsha(self._readiness_sha, len(keys), *keys, *argv)
            except Exception as error:
                if error.__class__.__name__ != "NoScriptError":
                    raise
                raw = self._client.eval(self._readiness_script, len(keys), *keys, *argv)
        except Exception as error:
            raise CommercialReservationRedisError(
                "commercial budget generation readiness is unavailable"
            ) from error
        return raw in {1, "1", b"1"}

    def settle(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        command: BudgetSettlementRedisCommand,
    ) -> BudgetSettlementRedisDecision:
        command = BudgetSettlementRedisCommand.model_validate(command.model_dump())
        if min(agreement_terms_id, period_id) <= 0:
            raise ValueError("settlement agreement and period IDs must be positive")
        tag = f"commercial:{self._mode}:{agreement_terms_id}:{period_id}"
        base = f"budget:spend:v2:{{{tag}}}"
        prefix = f"{base}:g{command.generation}"
        identity = canonical_sha256(
            {
                "reservation_id": str(command.reservation_id),
                "source_event_id": command.source_event_id,
                "cost_revision": command.cost_revision,
            }
        ).split(":", 1)[1]
        operation_digest = canonical_sha256(
            {
                "operation": "settle",
                "reservation_id": str(command.reservation_id),
                "source_product": command.source_product,
                "source_event_id": command.source_event_id,
                "cost_revision": command.cost_revision,
                "actor_type": command.actor_type,
                "actor_id": command.actor_id,
                "cost_adjustment_id": (
                    str(command.cost_adjustment_id)
                    if command.cost_adjustment_id is not None
                    else None
                ),
                "reason_code": command.reason_code,
                "payload_sha256": command.payload_sha256,
                "lease_token": str(command.lease_token),
                "lease_version": command.lease_version,
                "generation": command.generation,
                "budget_policy_id": command.budget_policy_id,
                "is_late_child": command.is_late_child,
                "finalize_reservation": command.finalize_reservation,
                "late_child_allowance_microusd": (
                    command.late_child_allowance_microusd
                ),
                "actuals": sorted(
                    (item.budget_bucket, item.amount_microusd)
                    for item in command.actuals
                ),
                "limits": sorted(
                    (item.budget_bucket, item.limit_microusd) for item in command.limits
                ),
            }
        )
        actuals = sorted(command.actuals, key=lambda item: item.budget_bucket)
        limits = {item.budget_bucket: item.limit_microusd for item in command.limits}
        keys = [
            f"{prefix}:reservation:{command.reservation_id}",
            f"{prefix}:idempotency:settle.{identity}",
            f"{prefix}:active",
            f"{prefix}:policy",
            f"{prefix}:late-child-used",
            *(f"{prefix}:bucket:{item.budget_bucket}" for item in actuals),
            f"{prefix}:generation",
            f"{base}:generation",
        ]
        argv = [
            str(command.reservation_id),
            operation_digest,
            str(command.lease_token),
            str(command.lease_version),
            str(command.generation),
            str(command.budget_policy_id),
            str(command.ttl_seconds),
            command.source_product,
            command.source_event_id,
            str(command.cost_revision),
            command.actor_type,
            command.actor_id or "",
            str(command.cost_adjustment_id) if command.cost_adjustment_id else "",
            "1" if command.is_late_child else "0",
            "1" if command.finalize_reservation else "0",
            str(command.late_child_allowance_microusd),
            str(len(actuals)),
        ]
        for item in actuals:
            argv.extend(
                [
                    item.budget_bucket,
                    str(item.amount_microusd),
                    str(limits[item.budget_bucket]),
                ]
            )
        argv.append(command.reason_code)
        try:
            if self._sha is None:
                self._sha = self._client.script_load(self._script)
            try:
                raw = self._client.evalsha(self._sha, len(keys), *keys, *argv)
            except Exception as error:
                if error.__class__.__name__ != "NoScriptError":
                    raise
                raw = self._client.eval(self._script, len(keys), *keys, *argv)
        except Exception as error:
            raise CommercialReservationRedisError(
                f"commercial budget settlement Redis unavailable: {error}"
            ) from error
        return BudgetSettlementRedisDecision.model_validate(json.loads(raw))
