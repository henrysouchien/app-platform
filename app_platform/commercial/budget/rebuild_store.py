"""Atomic Redis generation staging and compare-and-set cutover."""

from __future__ import annotations

from importlib import resources
import json
import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictBool, StrictInt, model_validator
from redis.exceptions import NoScriptError

from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel
from .redis_store import MAX_SAFE_REDIS_INTEGER, CommercialReservationRedisError


SafeNonnegativeInt = Annotated[StrictInt, Field(ge=0, le=MAX_SAFE_REDIS_INTEGER)]
SafePositiveInt = Annotated[StrictInt, Field(gt=0, le=MAX_SAFE_REDIS_INTEGER)]
_POLICY_BUCKETS = ("model", "technical")


class RebuildBucket(StrictCommercialModel):
    budget_bucket: StableCode
    amount_microusd: SafeNonnegativeInt
    limit_microusd: SafeNonnegativeInt


class RebuildReservation(StrictCommercialModel):
    reservation_id: UUID
    payload_sha256: Sha256Digest
    lease_token: UUID
    lease_version: SafePositiveInt
    state: Literal[
        "reserved",
        "partially_settled",
        "settled",
        "released",
        "expired",
        "overdrawn",
    ]
    active: StrictBool
    ttl_seconds: Annotated[StrictInt, Field(gt=0, le=31_536_000)]
    holds_by_bucket_microusd: tuple[RebuildBucket, ...]

    @model_validator(mode="after")
    def _buckets(self) -> "RebuildReservation":
        if tuple(item.budget_bucket for item in self.holds_by_bucket_microusd) != (
            "model",
            "technical",
        ):
            raise ValueError("rebuild reservation requires full policy buckets")
        if not self.active and any(
            item.amount_microusd != 0 for item in self.holds_by_bucket_microusd
        ):
            raise ValueError("terminal rebuild reservation cannot retain holds")
        active_state = self.state in {"reserved", "partially_settled", "overdrawn"}
        terminal_state = self.state in {"settled", "released", "expired", "overdrawn"}
        if (self.active and not active_state) or (
            not self.active and not terminal_state
        ):
            raise ValueError("rebuild reservation state conflicts with activity")
        return self


class BudgetGenerationBuildCommand(StrictCommercialModel):
    agreement_terms_id: SafePositiveInt
    budget_period_id: SafePositiveInt
    expected_generation: SafePositiveInt
    target_generation: SafePositiveInt
    snapshot_sha256: Sha256Digest
    budget_policy_id: SafePositiveInt
    max_concurrent_reservations: SafePositiveInt
    max_unreserved_delta_microusd: SafeNonnegativeInt
    late_child_allowance_microusd: SafeNonnegativeInt
    late_child_consumed_microusd: SafeNonnegativeInt
    max_period_overdraft_microusd: SafeNonnegativeInt
    active_reservations: SafeNonnegativeInt
    buckets: tuple[RebuildBucket, ...]
    reservations: tuple[RebuildReservation, ...]

    @model_validator(mode="after")
    def _invariants(self) -> "BudgetGenerationBuildCommand":
        if self.target_generation <= self.expected_generation:
            raise ValueError("rebuild target generation must advance")
        if tuple(item.budget_bucket for item in self.buckets) != _POLICY_BUCKETS:
            raise ValueError("rebuild requires full policy buckets")
        if self.active_reservations != sum(
            1 for reservation in self.reservations if reservation.active
        ):
            raise ValueError("rebuild active reservation count conflicts")
        if self.active_reservations > self.max_concurrent_reservations:
            raise ValueError("rebuild active reservations exceed policy")
        if self.late_child_consumed_microusd > min(
            self.late_child_allowance_microusd,
            self.max_period_overdraft_microusd,
        ):
            raise ValueError("rebuild late-child consumption exceeds policy")
        identities = [item.reservation_id for item in self.reservations]
        if len(identities) != len(set(identities)):
            raise ValueError("rebuild reservation identities must be unique")
        return self


class BudgetGenerationDecision(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: StableCode
    generation: SafePositiveInt
    snapshot_sha256: Sha256Digest
    replayed: StrictBool


class CommercialBudgetRebuildRedisStore:
    def __init__(self, client, *, flags: CommercialFlags) -> None:
        flags.validate()
        if not (
            flags.commercial_control_enabled
            and flags.commercial_budget_enforcement_enabled
        ):
            raise CommercialReservationRedisError(
                "budget rebuild requires enforcement mode"
            )
        self._client = client
        package = resources.files(__package__).joinpath("lua")
        self._build_script = package.joinpath("rebuild.lua").read_text(encoding="utf-8")
        self._cas_script = package.joinpath("generation_cas.lua").read_text(
            encoding="utf-8"
        )
        self._build_sha: str | None = None
        self._cas_sha: str | None = None

    def current_generation(
        self, *, agreement_terms_id: int, period_id: int
    ) -> tuple[int | None, str | None]:
        try:
            values = self._client.hmget(
                self._pointer_key(agreement_terms_id, period_id),
                "generation",
                "snapshot_sha256",
            )
        except Exception as error:
            raise CommercialReservationRedisError(
                "budget generation pointer is unavailable"
            ) from error
        generation_raw, digest = values
        if generation_raw is None:
            return None, None
        if isinstance(generation_raw, bytes):
            generation_raw = generation_raw.decode("utf-8")
        if isinstance(digest, bytes):
            digest = digest.decode("utf-8")
        if (
            not isinstance(generation_raw, str)
            or not generation_raw.isdigit()
            or generation_raw.startswith("0")
            or not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise CommercialReservationRedisError(
                "budget generation pointer is malformed"
            )
        generation = int(generation_raw)
        if not 0 < generation <= MAX_SAFE_REDIS_INTEGER:
            raise CommercialReservationRedisError(
                "budget generation pointer is malformed"
            )
        return generation, digest

    def build(self, command: BudgetGenerationBuildCommand) -> BudgetGenerationDecision:
        command = BudgetGenerationBuildCommand.model_validate(command.model_dump())
        keys = self._generation_keys(command)
        payload = json.dumps(
            _redis_wire_value(command.model_dump(mode="json")),
            sort_keys=True,
            separators=(",", ":"),
        )
        raw = self._eval("_build_sha", self._build_script, keys, [payload])
        return self._decision(raw, "budget generation build response is malformed")

    def compare_and_set(
        self,
        *,
        agreement_terms_id: int,
        period_id: int,
        expected_generation: int,
        target_generation: int,
        snapshot_sha256: str,
        reservation_ids: tuple[UUID, ...],
    ) -> BudgetGenerationDecision:
        if (
            not 0 < expected_generation <= MAX_SAFE_REDIS_INTEGER
            or not expected_generation < target_generation <= MAX_SAFE_REDIS_INTEGER
            or re.fullmatch(r"sha256:[0-9a-f]{64}", snapshot_sha256) is None
            or len(reservation_ids) != len(set(reservation_ids))
        ):
            raise ValueError("budget generation CAS command is invalid")
        raw = self._eval(
            "_cas_sha",
            self._cas_script,
            [
                self._pointer_key(agreement_terms_id, period_id),
                *self._target_manifest_keys(
                    agreement_terms_id,
                    period_id,
                    target_generation,
                    reservation_ids,
                ),
            ],
            [
                str(expected_generation),
                str(target_generation),
                snapshot_sha256,
                str(len(reservation_ids)),
            ],
        )
        return self._decision(raw, "budget generation CAS response is malformed")

    def _eval(self, sha_name, script, keys, argv):
        try:
            sha = getattr(self, sha_name)
            if sha is None:
                sha = self._client.script_load(script)
                setattr(self, sha_name, sha)
            try:
                return self._client.evalsha(sha, len(keys), *keys, *argv)
            except NoScriptError:
                return self._client.eval(script, len(keys), *keys, *argv)
        except Exception as error:
            raise CommercialReservationRedisError(
                "budget generation Redis operation failed"
            ) from error

    @staticmethod
    def _decision(raw, message):
        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return BudgetGenerationDecision.model_validate(json.loads(raw))
        except Exception as error:
            raise CommercialReservationRedisError(message) from error

    @staticmethod
    def _pointer_key(agreement_terms_id: int, period_id: int) -> str:
        if min(agreement_terms_id, period_id) <= 0:
            raise ValueError("budget generation identity must be positive")
        tag = f"commercial:enforce:{agreement_terms_id}:{period_id}"
        return f"budget:spend:v2:{{{tag}}}:generation"

    @staticmethod
    def _generation_metadata_key(
        agreement_terms_id: int, period_id: int, generation: int
    ) -> str:
        if min(agreement_terms_id, period_id, generation) <= 0:
            raise ValueError("budget generation identity must be positive")
        tag = f"commercial:enforce:{agreement_terms_id}:{period_id}"
        return f"budget:spend:v2:{{{tag}}}:g{generation}:generation"

    @staticmethod
    def _target_manifest_keys(
        agreement_terms_id: int,
        period_id: int,
        generation: int,
        reservation_ids: tuple[UUID, ...],
    ) -> list[str]:
        if min(agreement_terms_id, period_id, generation) <= 0:
            raise ValueError("budget generation identity must be positive")
        tag = f"commercial:enforce:{agreement_terms_id}:{period_id}"
        prefix = f"budget:spend:v2:{{{tag}}}:g{generation}"
        return [
            f"{prefix}:generation",
            f"{prefix}:active",
            f"{prefix}:late-child-used",
            f"{prefix}:policy",
            f"{prefix}:bucket:model",
            f"{prefix}:bucket:technical",
            *(f"{prefix}:reservation:{identity}" for identity in reservation_ids),
        ]

    @staticmethod
    def _generation_keys(command: BudgetGenerationBuildCommand) -> list[str]:
        tag = (
            f"commercial:enforce:{command.agreement_terms_id}:"
            f"{command.budget_period_id}"
        )
        base = f"budget:spend:v2:{{{tag}}}"
        prefix = f"{base}:g{command.target_generation}"
        return [
            f"{prefix}:generation",
            f"{prefix}:active",
            f"{prefix}:late-child-used",
            f"{prefix}:policy",
            *(f"{prefix}:bucket:{item.budget_bucket}" for item in command.buckets),
            *(
                f"{prefix}:reservation:{reservation.reservation_id}"
                for reservation in command.reservations
            ),
        ]


def _redis_wire_value(value):
    """Encode integers as canonical decimals for exact Lua validation."""

    if type(value) is int:
        return str(value)
    if isinstance(value, list):
        return [_redis_wire_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redis_wire_value(item) for key, item in value.items()}
    return value
