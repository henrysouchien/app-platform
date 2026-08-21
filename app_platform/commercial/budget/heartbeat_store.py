"""Atomic Redis heartbeat store for commercial budget reservations."""

from __future__ import annotations

from importlib import resources
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator
from redis.exceptions import NoScriptError

from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel
from .redis_store import (
    CommercialReservationRedisError,
    build_commercial_reservation_keys,
)


PositiveInt = Annotated[StrictInt, Field(gt=0, le=2**52 - 1)]


class BudgetHeartbeatRedisCommand(StrictCommercialModel):
    reservation_id: UUID
    idempotency_key: str
    payload_sha256: Sha256Digest
    lease_token: UUID
    lease_version: PositiveInt
    generation: PositiveInt
    ttl_seconds: Annotated[StrictInt, Field(gt=0, le=31_536_000)]
    heartbeat_at: AwareDatetime
    recovery_only: StrictBool = False
    buckets: tuple[StableCode, ...]

    @model_validator(mode="after")
    def _full_policy(self) -> "BudgetHeartbeatRedisCommand":
        if self.buckets != ("model", "technical"):
            raise ValueError("heartbeat requires the complete budget policy buckets")
        return self


class BudgetHeartbeatRedisDecision(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: StableCode
    reservation_id: UUID
    lease_version: PositiveInt
    generation: PositiveInt
    replayed: StrictBool
    heartbeat_at: AwareDatetime


class CommercialBudgetHeartbeatRedisStore:
    def __init__(self, client, *, flags: CommercialFlags) -> None:
        flags.validate()
        if not (flags.commercial_control_enabled and flags.commercial_budget_enforcement_enabled):
            raise CommercialReservationRedisError("budget heartbeat requires enforcement mode")
        self._client = client
        self._mode = "enforce"
        self._script = (
            resources.files(__package__)
            .joinpath("lua/heartbeat.lua")
            .read_text(encoding="utf-8")
        )
        self._sha: str | None = None

    def heartbeat(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        command: BudgetHeartbeatRedisCommand,
    ) -> BudgetHeartbeatRedisDecision:
        keys = build_commercial_reservation_keys(
            mode=self._mode,
            agreement_terms_id=agreement_terms_id,
            period_id=period_id,
            generation=command.generation,
            reservation_id=command.reservation_id,
            idempotency_key=command.idempotency_key,
            buckets=command.buckets,
        )
        argv = [
            str(command.reservation_id), command.payload_sha256,
            str(command.lease_token), str(command.lease_version),
            str(command.generation), str(command.ttl_seconds),
            str(len(command.buckets)), command.heartbeat_at.isoformat(),
            "1" if command.recovery_only else "0", *command.buckets,
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
                "budget heartbeat Redis operation failed"
            ) from error
        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return BudgetHeartbeatRedisDecision.model_validate(json.loads(raw))
        except Exception as error:
            raise CommercialReservationRedisError(
                "budget heartbeat Redis response is malformed"
            ) from error
