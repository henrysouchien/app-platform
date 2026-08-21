"""Atomic Redis primitives for agreement-level commercial reservations."""

from __future__ import annotations

import hashlib
from importlib import resources
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from app_platform.api_budget.exceptions import BudgetGuardUnavailable

from ..flags import CommercialFlags
from ..models import MAX_SIGNED_BIGINT, Sha256Digest, StableCode, StrictCommercialModel
from .estimator import ReservationBucketHold


PositiveBigInt = Annotated[StrictInt, Field(gt=0, le=MAX_SIGNED_BIGINT)]
NonNegativeBigInt = Annotated[StrictInt, Field(ge=0, le=MAX_SIGNED_BIGINT)]
MAX_SAFE_REDIS_INTEGER = 2**52 - 1


class CommercialReservationRedisError(BudgetGuardUnavailable):
    """Commercial Redis control is unavailable or misconfigured."""


class BucketLimit(StrictCommercialModel):
    budget_bucket: StableCode
    limit_microusd: PositiveBigInt


class ReservationRedisCommand(StrictCommercialModel):
    reservation_id: UUID
    idempotency_key: StableCode
    payload_sha256: Sha256Digest
    lease_token: UUID
    lease_version: PositiveBigInt
    generation: PositiveBigInt
    budget_policy_id: PositiveBigInt
    ttl_seconds: Annotated[StrictInt, Field(gt=0, le=31_536_000)]
    max_concurrent_reservations: PositiveBigInt
    max_unreserved_delta_microusd: NonNegativeBigInt
    late_child_allowance_microusd: NonNegativeBigInt
    max_period_overdraft_microusd: NonNegativeBigInt
    allow_generation_bootstrap: StrictBool = False
    holds: tuple[ReservationBucketHold, ...]
    limits: tuple[BucketLimit, ...]

    @model_validator(mode="after")
    def _matching_buckets(self) -> "ReservationRedisCommand":
        hold_buckets = [hold.budget_bucket for hold in self.holds]
        limit_buckets = [limit.budget_bucket for limit in self.limits]
        if not hold_buckets or len(set(hold_buckets)) != len(hold_buckets):
            raise ValueError("reservation holds must be non-empty and unique")
        if not limit_buckets or len(set(limit_buckets)) != len(limit_buckets):
            raise ValueError("reservation limits must be non-empty and unique")
        if not set(hold_buckets).issubset(limit_buckets):
            raise ValueError("reservation holds must be covered by period limits")
        if (
            any(bucket != "technical" for bucket in hold_buckets)
            and "technical" not in hold_buckets
        ):
            raise ValueError("non-technical holds require the overall technical bucket")
        if (
            any(bucket != "technical" for bucket in limit_buckets)
            and "technical" not in limit_buckets
        ):
            raise ValueError(
                "non-technical limits require the overall technical bucket"
            )
        holds = {hold.budget_bucket: hold.amount_microusd for hold in self.holds}
        limits = {limit.budget_bucket: limit.limit_microusd for limit in self.limits}
        if holds.get("technical", 0) < sum(
            amount for bucket, amount in holds.items() if bucket != "technical"
        ):
            raise ValueError("technical hold must cover all non-technical holds")
        if limits.get("technical", 0) < sum(
            amount for bucket, amount in limits.items() if bucket != "technical"
        ):
            raise ValueError("technical limit must cover all non-technical limits")
        if any(
            hold.amount_microusd > MAX_SAFE_REDIS_INTEGER for hold in self.holds
        ) or any(
            limit.limit_microusd > MAX_SAFE_REDIS_INTEGER for limit in self.limits
        ):
            raise ValueError("Redis monetary values must be exact IEEE-754 integers")
        if any(
            value > MAX_SAFE_REDIS_INTEGER
            for value in (
                self.lease_version,
                self.generation,
                self.max_concurrent_reservations,
                self.max_unreserved_delta_microusd,
                self.late_child_allowance_microusd,
                self.max_period_overdraft_microusd,
            )
        ):
            raise ValueError("Redis control values must be exact IEEE-754 integers")
        worst_case_overdraft = (
            self.max_concurrent_reservations * self.max_unreserved_delta_microusd
            + self.late_child_allowance_microusd
        )
        if worst_case_overdraft > self.max_period_overdraft_microusd:
            raise ValueError("commercial budget policy exceeds its overdraft bound")
        return self


class RedisBucketHold(StrictCommercialModel):
    budget_bucket: StableCode
    amount_microusd: NonNegativeBigInt


class ReservationRedisDecision(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: StableCode
    reservation_id: UUID
    lease_version: PositiveBigInt
    generation: PositiveBigInt
    replayed: bool
    holds_by_bucket_microusd: tuple[RedisBucketHold, ...]
    active_reservations: NonNegativeBigInt

    @field_validator("holds_by_bucket_microusd", mode="before")
    @classmethod
    def _freeze_holds(cls, value):
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
        "lease_version", "generation", "active_reservations", mode="before"
    )
    @classmethod
    def _parse_exact_integer(cls, value):
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return value


class CommercialReservationRedisStore:
    """Execute one-slot Lua operations without touching legacy API budget keys."""

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
                "commercial budget controls are disabled"
            )
        self._client = client
        self._mode = (
            "enforce" if flags.commercial_budget_enforcement_enabled else "shadow"
        )
        self._script = (
            resources.files(__package__)
            .joinpath("lua/reservation.lua")
            .read_text(encoding="utf-8")
        )
        self._sha: str | None = None

    def reserve(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        command: ReservationRedisCommand,
    ) -> ReservationRedisDecision:
        return self._execute("reserve", agreement_terms_id, period_id, command)

    def top_up(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        command: ReservationRedisCommand,
    ) -> ReservationRedisDecision:
        return self._execute("top_up", agreement_terms_id, period_id, command)

    def release(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        command: ReservationRedisCommand,
    ) -> ReservationRedisDecision:
        return self._execute("release", agreement_terms_id, period_id, command)

    def _execute(self, operation, agreement_terms_id, period_id, command):
        if agreement_terms_id <= 0 or period_id <= 0:
            raise ValueError("agreement terms and period IDs must be positive")
        command = ReservationRedisCommand.model_validate(command.model_dump())
        ordered_holds = sorted(command.holds, key=lambda item: item.budget_bucket)
        ordered_limits = sorted(command.limits, key=lambda item: item.budget_bucket)
        hold_amounts = {
            item.budget_bucket: item.amount_microusd for item in ordered_holds
        }
        keys = build_commercial_reservation_keys(
            mode=self._mode,
            agreement_terms_id=agreement_terms_id,
            period_id=period_id,
            generation=command.generation,
            reservation_id=command.reservation_id,
            idempotency_key=command.idempotency_key,
            buckets=tuple(limit.budget_bucket for limit in ordered_limits),
        )
        operation_digest = _operation_digest(operation, command)
        argv = [
            operation,
            str(command.reservation_id),
            operation_digest,
            str(command.lease_token),
            str(command.lease_version),
            str(command.generation),
            str(command.ttl_seconds),
            str(command.max_concurrent_reservations),
            str(len(ordered_limits)),
            str(command.budget_policy_id),
            str(command.max_unreserved_delta_microusd),
            str(command.late_child_allowance_microusd),
            str(command.max_period_overdraft_microusd),
        ]
        for limit in ordered_limits:
            argv.extend(
                [
                    limit.budget_bucket,
                    str(hold_amounts.get(limit.budget_bucket, 0)),
                    str(limit.limit_microusd),
                ]
            )
        argv.append("1" if command.allow_generation_bootstrap else "0")
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
                f"commercial budget Redis unavailable: {error}"
            ) from error
        return ReservationRedisDecision.model_validate(json.loads(raw))


def _operation_digest(operation: str, command: ReservationRedisCommand) -> str:
    payload = {
        "operation": operation,
        "reservation_id": str(command.reservation_id),
        "payload_sha256": command.payload_sha256,
        "lease_token": str(command.lease_token),
        "lease_version": command.lease_version,
        "generation": command.generation,
        "budget_policy_id": command.budget_policy_id,
        "max_concurrent_reservations": command.max_concurrent_reservations,
        "max_unreserved_delta_microusd": command.max_unreserved_delta_microusd,
        "late_child_allowance_microusd": command.late_child_allowance_microusd,
        "max_period_overdraft_microusd": command.max_period_overdraft_microusd,
        "holds": sorted(
            (hold.budget_bucket, hold.amount_microusd) for hold in command.holds
        ),
        "limits": sorted(
            (limit.budget_bucket, limit.limit_microusd) for limit in command.limits
        ),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_commercial_reservation_keys(
    *,
    mode: Literal["shadow", "enforce"],
    agreement_terms_id: int,
    period_id: int,
    generation: int,
    reservation_id: UUID,
    idempotency_key: str,
    buckets: tuple[str, ...],
) -> list[str]:
    """Build one-generation keys sharing exactly one Redis Cluster hash slot."""

    if mode not in {"shadow", "enforce"}:
        raise ValueError("commercial budget Redis mode is invalid")
    if min(agreement_terms_id, period_id, generation) <= 0:
        raise ValueError("commercial budget Redis key identities must be positive")
    tag = f"commercial:{mode}:{agreement_terms_id}:{period_id}"
    base = f"budget:spend:v2:{{{tag}}}"
    prefix = f"{base}:g{generation}"
    return [
        f"{prefix}:reservation:{reservation_id}",
        f"{prefix}:idempotency:{idempotency_key}",
        f"{prefix}:active",
        f"{prefix}:policy",
        *(f"{prefix}:bucket:{bucket}" for bucket in buckets),
        f"{prefix}:generation",
        f"{base}:generation",
    ]
