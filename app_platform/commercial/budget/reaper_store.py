"""Atomic Redis expiry primitive for abandoned commercial reservations."""

from __future__ import annotations

from importlib import resources
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator
from redis.exceptions import NoScriptError

from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel
from .redis_store import (
    MAX_SAFE_REDIS_INTEGER,
    CommercialReservationRedisError,
    RedisBucketHold,
    build_commercial_reservation_keys,
)


PositiveSafeInt = Annotated[
    StrictInt, Field(gt=0, le=MAX_SAFE_REDIS_INTEGER)
]


class BudgetReaperRedisCommand(StrictCommercialModel):
    reservation_id: UUID
    idempotency_key: StableCode
    payload_sha256: Sha256Digest
    lease_token: UUID
    lease_version: PositiveSafeInt
    generation: PositiveSafeInt
    ttl_seconds: Annotated[StrictInt, Field(gt=0, le=31_536_000)]
    reason_code: StableCode = "budget.expired"
    buckets: tuple[StableCode, ...]
    expected_holds_by_bucket_microusd: tuple[RedisBucketHold, ...]

    @model_validator(mode="after")
    def _bucket_invariants(self) -> "BudgetReaperRedisCommand":
        if self.buckets != ("model", "technical"):
            raise ValueError("reaper requires the complete budget policy buckets")
        expected = {
            item.budget_bucket: item.amount_microusd
            for item in self.expected_holds_by_bucket_microusd
        }
        if (
            len(expected) != len(self.expected_holds_by_bucket_microusd)
            or set(expected) != set(self.buckets)
        ):
            raise ValueError("reaper expected holds must exactly match buckets")
        return self


class BudgetReaperRedisDecision(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: StableCode
    reservation_id: UUID
    lease_version: PositiveSafeInt
    generation: PositiveSafeInt
    replayed: StrictBool
    holds_by_bucket_microusd: tuple[RedisBucketHold, ...]

    @field_validator("holds_by_bucket_microusd", mode="before")
    @classmethod
    def _freeze_holds(cls, value):
        if isinstance(value, dict):
            return tuple(
                {
                    "budget_bucket": bucket,
                    "amount_microusd": int(amount),
                }
                for bucket, amount in sorted(value.items())
            )
        return value

    @field_validator("lease_version", "generation", mode="before")
    @classmethod
    def _parse_exact_integer(cls, value):
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return value


class CommercialBudgetReaperRedisStore:
    def __init__(self, client, *, flags: CommercialFlags) -> None:
        flags.validate()
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
        ):
            raise CommercialReservationRedisError(
                "budget reaper requires enforcement mode"
            )
        self._client = client
        self._script = (
            resources.files(__package__)
            .joinpath("lua/reaper.lua")
            .read_text(encoding="utf-8")
        )
        self._sha: str | None = None

    def expire(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        command: BudgetReaperRedisCommand,
    ) -> BudgetReaperRedisDecision:
        if min(agreement_terms_id, period_id) <= 0:
            raise ValueError("reaper agreement and period IDs must be positive")
        command = BudgetReaperRedisCommand.model_validate(command.model_dump())
        buckets = tuple(sorted(command.buckets))
        keys = build_commercial_reservation_keys(
            mode="enforce",
            agreement_terms_id=agreement_terms_id,
            period_id=period_id,
            generation=command.generation,
            reservation_id=command.reservation_id,
            idempotency_key=command.idempotency_key,
            buckets=buckets,
        )
        expected = {
            item.budget_bucket: item.amount_microusd
            for item in command.expected_holds_by_bucket_microusd
        }
        argv = [
            str(command.reservation_id),
            command.payload_sha256,
            str(command.lease_token),
            str(command.lease_version),
            str(command.generation),
            str(command.ttl_seconds),
            str(len(buckets)),
            command.reason_code,
            *(value for bucket in buckets for value in (bucket, str(expected[bucket]))),
        ]
        try:
            if self._sha is None:
                self._sha = self._client.script_load(self._script)
            try:
                raw = self._client.evalsha(self._sha, len(keys), *keys, *argv)
            except NoScriptError:
                raw = self._client.eval(self._script, len(keys), *keys, *argv)
        except Exception as error:
            raise CommercialReservationRedisError(
                f"commercial budget reaper Redis unavailable: {error}"
            ) from error
        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return BudgetReaperRedisDecision.model_validate(json.loads(raw))
        except Exception as error:
            raise CommercialReservationRedisError(
                "commercial budget reaper Redis response is malformed"
            ) from error
