"""Atomic staging and CAS cutover for token-limit Redis generations."""

from __future__ import annotations

from importlib import resources
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictInt, model_validator

from ..flags import CommercialFlags
from ..models import Sha256Digest, StrictCommercialModel
from .redis_store import CommercialTokenLimitRedisError


SafeInt = Annotated[StrictInt, Field(ge=0, le=2**52 - 1)]
PositiveSafeInt = Annotated[StrictInt, Field(gt=0, le=2**52 - 1)]


class TokenLimitRebuildLease(StrictCommercialModel):
    lease_id: UUID
    workflow_run_id: UUID
    request_id: str = Field(min_length=1, max_length=128, pattern=r"^\S+$")
    lease_token: UUID
    lease_version: PositiveSafeInt
    entitlement_revision: PositiveSafeInt
    expires_at_epoch: PositiveSafeInt
    admission_digest: Sha256Digest


class TokenLimitGenerationBuildCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    mode: Literal["shadow", "enforce"]
    token_id: UUID
    expected_generation: PositiveSafeInt
    target_generation: PositiveSafeInt
    snapshot_sha256: Sha256Digest
    entitlement_revision: PositiveSafeInt
    policy_sha256: Sha256Digest
    requests_per_minute: PositiveSafeInt
    requests_per_day: PositiveSafeInt
    concurrent_workflows: PositiveSafeInt
    minute_start_epoch: SafeInt
    minute_count: SafeInt
    day_start_epoch: SafeInt
    day_count: SafeInt
    leases: tuple[TokenLimitRebuildLease, ...]

    @model_validator(mode="after")
    def _invariants(self):
        if self.target_generation <= self.expected_generation:
            raise ValueError("target generation must advance")
        if len({item.lease_id for item in self.leases}) != len(self.leases):
            raise ValueError("rebuild lease identities must be unique")
        return self


class TokenLimitGenerationDecision(StrictCommercialModel):
    decision: Literal["allow", "block"]
    reason_code: Literal[
        "limit.rebuild_staged", "limit.rebuild_replayed", "limit.rebuild_conflict",
        "limit.generation_swapped", "limit.generation_cas_conflict",
    ]
    generation: PositiveSafeInt
    snapshot_sha256: Sha256Digest
    replayed: bool


class CommercialTokenLimitRebuildRedisStore:
    def __init__(self, client, *, flags: CommercialFlags) -> None:
        flags.validate()
        if not flags.commercial_token_limit_enforcement_enabled:
            raise CommercialTokenLimitRedisError("token rebuild requires enforcement")
        self._client = client
        package = resources.files(__package__).joinpath("lua")
        self._build_script = package.joinpath("generation_build.lua").read_text(encoding="utf-8")
        self._cas_script = package.joinpath("generation_cas.lua").read_text(encoding="utf-8")
        self._build_sha = self._cas_sha = None

    def current_generation(self, *, environment, mode, token_id):
        raw = self._client.hmget(self.pointer_key(environment, mode, token_id), "generation", "snapshot_sha256")
        if raw[0] is None:
            return None, None
        try:
            digest = raw[1].decode() if isinstance(raw[1], bytes) else raw[1]
            return int(raw[0]), digest
        except Exception as error:
            raise CommercialTokenLimitRedisError("token generation pointer is malformed") from error

    def build(self, command):
        command = TokenLimitGenerationBuildCommand.model_validate(command.model_dump())
        payload = json.dumps(command.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        keys = self.generation_keys(command)
        return self._eval("_build_sha", self._build_script, keys, (payload,))

    def compare_and_set(self, command):
        command = TokenLimitGenerationBuildCommand.model_validate(command.model_dump())
        payload = json.dumps(
            command.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        keys = [self.pointer_key(command.environment, command.mode, command.token_id), *self.generation_keys(command)]
        return self._eval("_cas_sha", self._cas_script, keys, (
            str(command.expected_generation), str(command.target_generation),
            command.snapshot_sha256, str(len(command.leases)),
            payload,
        ))

    def _eval(self, attr, script, keys, argv):
        try:
            sha = getattr(self, attr)
            if sha is None:
                sha = self._client.script_load(script)
                setattr(self, attr, sha)
            try:
                raw = self._client.evalsha(sha, len(keys), *keys, *argv)
            except Exception as error:
                if error.__class__.__name__ != "NoScriptError":
                    raise
                raw = self._client.eval(script, len(keys), *keys, *argv)
            if isinstance(raw, bytes):
                raw = raw.decode()
            return TokenLimitGenerationDecision.model_validate(json.loads(raw))
        except Exception as error:
            raise CommercialTokenLimitRedisError("token generation operation failed") from error

    @staticmethod
    def pointer_key(environment, mode, token_id):
        return f"commercial:limit:v1:{mode}:{{{environment}:{token_id}}}:generation"

    @classmethod
    def generation_keys(cls, command):
        base = cls.pointer_key(command.environment, command.mode, command.token_id).rsplit(":generation", 1)[0]
        prefix = f"{base}:g{command.target_generation}"
        return [f"{prefix}:counters", f"{prefix}:leases", f"{prefix}:manifest",
                *(f"{prefix}:lease:{item.lease_id}" for item in command.leases)]
